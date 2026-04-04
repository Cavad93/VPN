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
import com.cavadvpn.ui.MainActivity
import kotlinx.coroutines.*
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/** Starts the VPN tunnel. Required extras: EXTRA_SERVER_HOST, EXTRA_PRIVATE_KEY. */
const val ACTION_CONNECT    = "com.cavadvpn.CONNECT"
/** Stops the VPN tunnel. */
const val ACTION_DISCONNECT = "com.cavadvpn.DISCONNECT"
/** Broadcast: periodic stats update. */
const val ACTION_STATS_UPDATE = "com.cavadvpn.STATS_UPDATE"
/** Broadcast: VPN connection state changed. */
const val ACTION_VPN_STATE_CHANGED = "com.cavadvpn.VPN_STATE_CHANGED"

const val EXTRA_SERVER_HOST       = "server_host"
const val EXTRA_SERVER_PORT       = "server_port"
const val EXTRA_PRIVATE_KEY       = "private_key_hex"
const val EXTRA_SERVER_PUBLIC_KEY = "server_public_key_hex"

const val EXTRA_STATE               = "state"
const val EXTRA_ERROR_MSG           = "error_msg"
const val EXTRA_STATS_BYTES_IN      = "bytes_in"
const val EXTRA_STATS_BYTES_OUT     = "bytes_out"
const val EXTRA_STATS_CONNECTED_SINCE = "connected_since_ms"
const val EXTRA_STATS_ASSIGNED_IP   = "assigned_ip"

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
    private var telemetry: TelemetryCollector? = null

    private val bytesIn  = AtomicLong(0L)
    private val bytesOut = AtomicLong(0L)
    private var connectedSinceMs = 0L
    private var assignedIp = ""
    private var currentServerAddr = ""

    /** Prevents re-entrant startVpn while a connection attempt is in progress. */
    private val connecting = AtomicBoolean(false)

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
            else -> {
                // No action (e.g. system restart without intent) — do not reconnect.
                stopSelf()
                return START_NOT_STICKY
            }
        }
        // START_NOT_STICKY: do NOT auto-restart the service. The user must
        // explicitly reconnect. This prevents the infinite reconnection loop
        // where Android restarts the service after stopVpn().
        return START_NOT_STICKY
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
        // Prevent re-entrant connection attempts.
        if (!connecting.compareAndSet(false, true)) {
            Log.w(TAG, "startVpn called while already connecting — ignoring")
            return
        }

        cleanupResources() // clean up any existing session (NOT stopVpn — stopSelf would kill us)

        createNotificationChannel()
        startForeground(NOTIFICATION_ID, buildNotification("Connecting…"))
        broadcastState("CONNECTING")

        bytesIn.set(0L)
        bytesOut.set(0L)
        connectedSinceMs = 0L
        assignedIp = ""
        currentServerAddr = "${config.serverHost}:${config.serverPort}"

        // Initialize telemetry collector.
        // API server URL: same host as VPN server, port 8080.
        val telemetryUrl = "http://${config.serverHost}:8080"
        telemetry = TelemetryCollector(
            serverUrl = telemetryUrl,
            context = this,
            getVpnState = {
                TelemetryCollector.VpnState(
                    state = if (connectedSinceMs > 0) "connected" else "disconnected",
                    serverAddr = currentServerAddr,
                )
            },
        )

        val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
        serviceScope = scope

        scope.launch {
            try {
                val client = VpnClient(config)
                vpnClient = client

                Log.i(TAG, "Connecting to ${config.serverHost}:${config.serverPort}")
                val hsStart = System.nanoTime()
                val route = client.connect()
                val hsMs = (System.nanoTime() - hsStart) / 1_000_000.0
                telemetry?.handshakeMs = hsMs
                Log.i(TAG, "Connected — assigned IP ${route.assignedIp}/${route.prefixLen}")

                // CRITICAL: Protect the VPN tunnel socket BEFORE setting up the
                // TUN interface. setupTunnel() calls addRoute("0.0.0.0", 0) which
                // would route the VPN socket's own traffic back through the TUN
                // interface, creating a routing loop.
                client.protectSocket(this@CavadVpnService)

                val fd = setupTunnel(route, config)
                tunFd = fd

                connectedSinceMs = System.currentTimeMillis()
                assignedIp = route.assignedIp
                connecting.set(false) // connection established

                updateNotification("Connected — ${route.assignedIp}")
                broadcastState("CONNECTED")

                // Start telemetry collection.
                telemetry?.recordConnect()
                telemetry?.start()

                // Start stats broadcast coroutine
                launch {
                    while (isActive) {
                        delay(1000L)
                        // Update telemetry byte counters.
                        telemetry?.updateBytes(bytesIn.get(), bytesOut.get())
                        broadcastStats()
                        val statsText = "↓ ${formatBytes(bytesIn.get())}  ↑ ${formatBytes(bytesOut.get())}"
                        updateNotification("${route.assignedIp}  $statsText")
                    }
                }

                runTunnel(fd, client)
                // Tunnel ended normally (server closed connection).
                Log.i(TAG, "Tunnel ended normally")
                broadcastState("DISCONNECTED")
                stopVpn()
            } catch (e: CancellationException) {
                // Coroutine was cancelled (e.g. by stopVpn) — not an error.
                Log.d(TAG, "VPN coroutine cancelled")
            } catch (e: Exception) {
                Log.e(TAG, "VPN connection failed: ${e.message}", e)
                broadcastState("ERROR", e.message ?: e.javaClass.simpleName)
                // Clean up but do NOT call stopVpn() → stopSelf() here.
                // That would cause Android to potentially restart the service.
                // Instead, just clean up resources and let the user manually reconnect.
                cleanupResources()
            } finally {
                connecting.set(false)
            }
        }
    }

    /** Releases all resources without stopping the service. */
    private fun cleanupResources() {
        serviceScope?.cancel()
        serviceScope = null

        // Stop telemetry collection.
        telemetry?.recordDisconnect()
        telemetry?.stop()
        telemetry = null

        try { vpnClient?.disconnect() } catch (_: Exception) {}
        vpnClient = null

        try { tunFd?.close() } catch (_: Exception) {}
        tunFd = null

        bytesIn.set(0L)
        bytesOut.set(0L)
        connectedSinceMs = 0L
        assignedIp = ""

        stopForeground(STOP_FOREGROUND_REMOVE)
    }

    private fun stopVpn() {
        cleanupResources()
        stopSelf()
        broadcastState("DISCONNECTED")
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
                // 65536 covers any IPv4 packet (max 65535 bytes); buffer is reused each iteration
                val buf = ByteArray(65536)
                try {
                    while (isActive) {
                        val len = tunIn.read(buf)
                        if (len <= 0) break
                        client.sendPacket(buf, len) // zero-copy: no buf.copyOf(len)
                        bytesOut.addAndGet(len.toLong())
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
                        if (pkt.isEmpty()) {
                            // Empty packet = timeout or stream closed. If the
                            // client is still connected, this is an idle timeout
                            // — just retry. If the mux is closed, the next read
                            // will throw EOFException.
                            if (!client.isConnected) break
                            continue
                        }
                        tunOut.write(pkt)
                        bytesIn.addAndGet(pkt.size.toLong())
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
    // Broadcast helpers
    // -----------------------------------------------------------------------

    private fun broadcastStats() {
        val intent = Intent(ACTION_STATS_UPDATE).apply {
            putExtra(EXTRA_STATS_BYTES_IN,        bytesIn.get())
            putExtra(EXTRA_STATS_BYTES_OUT,       bytesOut.get())
            putExtra(EXTRA_STATS_CONNECTED_SINCE, connectedSinceMs)
            putExtra(EXTRA_STATS_ASSIGNED_IP,     assignedIp)
            setPackage(packageName)
        }
        sendBroadcast(intent)
    }

    private fun broadcastState(state: String, errorMsg: String? = null) {
        val intent = Intent(ACTION_VPN_STATE_CHANGED).apply {
            putExtra(EXTRA_STATE, state)
            if (errorMsg != null) putExtra(EXTRA_ERROR_MSG, errorMsg)
            setPackage(packageName)
        }
        sendBroadcast(intent)
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
        val pendingFlags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M)
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        else PendingIntent.FLAG_UPDATE_CURRENT

        // Tap notification → open MainActivity
        val mainIntent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP
        }
        val mainPi = PendingIntent.getActivity(this, 1, mainIntent, pendingFlags)

        val disconnectIntent = Intent(this, CavadVpnService::class.java).apply {
            action = ACTION_DISCONNECT
        }
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
            .setContentIntent(mainPi)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, "Disconnect", disconnectPi)
            .build()
    }

    private fun updateNotification(text: String) {
        getSystemService(NotificationManager::class.java)
            .notify(NOTIFICATION_ID, buildNotification(text))
    }
}
