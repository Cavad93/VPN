package com.cavadvpn.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import com.cavadvpn.config.RouteInfo
import com.cavadvpn.config.VpnConfig
import kotlinx.coroutines.*
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException

/** Starts the VPN tunnel. Required extras: EXTRA_SERVER_HOST, EXTRA_PRIVATE_KEY. */
const val ACTION_CONNECT    = "com.cavadvpn.CONNECT"
/** Stops the VPN tunnel. */
const val ACTION_DISCONNECT = "com.cavadvpn.DISCONNECT"

const val EXTRA_SERVER_HOST       = "server_host"
const val EXTRA_SERVER_PORT       = "server_port"
const val EXTRA_PRIVATE_KEY       = "private_key_hex"
const val EXTRA_SERVER_PUBLIC_KEY = "server_public_key_hex"

private const val TAG = "CavadVpnService"
private const val NOTIFICATION_CHANNEL_ID = "cavadvpn_channel"
private const val NOTIFICATION_ID = 1

/**
 * Android VPN service that creates a TUN interface and forwards traffic
 * to the CavadVPN server.
 *
 * The service runs a foreground notification while connected.  Packet
 * forwarding is performed on coroutine IO dispatchers to avoid blocking
 * the main thread.
 */
class CavadVpnService : VpnService() {

    private var vpnClient: VpnClient? = null
    private var tunFd: ParcelFileDescriptor? = null
    private var serviceScope: CoroutineScope? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_CONNECT -> {
                val host = intent.getStringExtra(EXTRA_SERVER_HOST)
                    ?: run { Log.e(TAG, "No server host in intent"); return START_NOT_STICKY }

                val config = VpnConfig(
                    serverHost        = host,
                    serverPort        = intent.getIntExtra(EXTRA_SERVER_PORT, 443),
                    privateKeyHex     = intent.getStringExtra(EXTRA_PRIVATE_KEY) ?: "",
                    serverPublicKeyHex = intent.getStringExtra(EXTRA_SERVER_PUBLIC_KEY) ?: ""
                )
                startVpn(config)
            }
            ACTION_DISCONNECT -> stopVpn()
        }
        return START_STICKY
    }

    override fun onRevoke() {
        Log.i(TAG, "VPN revoked by system")
        stopVpn()
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }

    // -----------------------------------------------------------------------
    // VPN lifecycle
    // -----------------------------------------------------------------------

    private fun startVpn(config: VpnConfig) {
        stopVpn() // clean up any existing session

        createNotificationChannel()
        startForeground(NOTIFICATION_ID, buildNotification("Connecting…"))

        val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
        serviceScope = scope

        scope.launch {
            try {
                val client = VpnClient(config)
                vpnClient = client

                Log.i(TAG, "Connecting to ${config.serverHost}:${config.serverPort}")
                val route = client.connect()
                Log.i(TAG, "Connected — assigned IP ${route.assignedIp}/${route.prefixLen}")

                val fd = setupTunnel(route, config)
                tunFd = fd

                updateNotification("Connected — ${route.assignedIp}")
                runTunnel(fd, client)
            } catch (e: Exception) {
                Log.e(TAG, "VPN connection failed: ${e.message}", e)
                stopVpn()
            }
        }
    }

    private fun stopVpn() {
        serviceScope?.cancel()
        serviceScope = null

        try { vpnClient?.disconnect() } catch (_: Exception) {}
        vpnClient = null

        try { tunFd?.close() } catch (_: Exception) {}
        tunFd = null

        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
        Log.i(TAG, "VPN stopped")
    }

    // -----------------------------------------------------------------------
    // TUN interface setup
    // -----------------------------------------------------------------------

    /**
     * Builds the VPN interface using [VpnService.Builder] and returns the
     * [ParcelFileDescriptor] for reading/writing raw IP packets.
     */
    fun setupTunnel(route: RouteInfo, config: VpnConfig): ParcelFileDescriptor {
        val builder = Builder()
            .setSession("CavadVPN")
            .addAddress(route.assignedIp, route.prefixLen)
            .addRoute("0.0.0.0", 0)           // route all IPv4 traffic
            .addDnsServer(config.dnsServer)
            .setMtu(config.mtu)
            .setBlocking(true)

        return builder.establish()
            ?: throw IOException("VpnService.Builder.establish() returned null — user may have denied VPN permission")
    }

    // -----------------------------------------------------------------------
    // Packet forwarding
    // -----------------------------------------------------------------------

    /**
     * Runs two coroutines that forward packets bidirectionally between the TUN
     * interface and the VPN data stream.  Blocks until either coroutine fails.
     */
    suspend fun runTunnel(tunFd: ParcelFileDescriptor, client: VpnClient) {
        val tunIn  = FileInputStream(tunFd.fileDescriptor)
        val tunOut = FileOutputStream(tunFd.fileDescriptor)

        coroutineScope {
            // TUN → server
            val tunToServer = launch(Dispatchers.IO) {
                val buf = ByteArray(client.routeInfo?.let { 1500 } ?: 1500)
                try {
                    while (isActive) {
                        val len = tunIn.read(buf)
                        if (len <= 0) break
                        client.sendPacket(buf.copyOf(len))
                    }
                } catch (e: Exception) {
                    if (isActive) Log.e(TAG, "TUN→server error: ${e.message}")
                }
            }

            // Server → TUN
            val serverToTun = launch(Dispatchers.IO) {
                try {
                    while (isActive) {
                        val pkt = client.recvPacket()
                        if (pkt.isEmpty()) break
                        tunOut.write(pkt)
                    }
                } catch (e: Exception) {
                    if (isActive) Log.e(TAG, "server→TUN error: ${e.message}")
                }
            }

            // If either direction fails, cancel the other
            tunToServer.invokeOnCompletion  { serverToTun.cancel() }
            serverToTun.invokeOnCompletion  { tunToServer.cancel() }
        }
    }

    // -----------------------------------------------------------------------
    // Notification helpers
    // -----------------------------------------------------------------------

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                NOTIFICATION_CHANNEL_ID,
                "CavadVPN Status",
                NotificationManager.IMPORTANCE_LOW
            )
            getSystemService(NotificationManager::class.java)
                .createNotificationChannel(channel)
        }
    }

    private fun buildNotification(text: String): Notification {
        val disconnectIntent = Intent(this, CavadVpnService::class.java).apply {
            action = ACTION_DISCONNECT
        }
        val pendingFlags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M)
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        else PendingIntent.FLAG_UPDATE_CURRENT

        val disconnectPi = PendingIntent.getService(this, 0, disconnectIntent, pendingFlags)

        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, NOTIFICATION_CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }

        return builder
            .setContentTitle("CavadVPN")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, "Disconnect", disconnectPi)
            .build()
    }

    private fun updateNotification(text: String) {
        getSystemService(NotificationManager::class.java)
            .notify(NOTIFICATION_ID, buildNotification(text))
    }
}
