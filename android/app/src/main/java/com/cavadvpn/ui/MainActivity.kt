package com.cavadvpn.ui

import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import com.cavadvpn.R
import com.cavadvpn.config.ConfigStore
import com.cavadvpn.vpn.ACTION_CONNECT
import com.cavadvpn.vpn.ACTION_DISCONNECT
import com.cavadvpn.vpn.ACTION_STATS_UPDATE
import com.cavadvpn.vpn.ACTION_VPN_STATE_CHANGED
import com.cavadvpn.vpn.CavadVpnService
import com.cavadvpn.vpn.EXTRA_PRIVATE_KEY
import com.cavadvpn.vpn.EXTRA_SERVER_HOST
import com.cavadvpn.vpn.EXTRA_SERVER_PORT
import com.cavadvpn.vpn.EXTRA_SERVER_PUBLIC_KEY
import com.cavadvpn.vpn.EXTRA_STATE
import com.cavadvpn.vpn.EXTRA_STATS_ASSIGNED_IP
import com.cavadvpn.vpn.EXTRA_STATS_BYTES_IN
import com.cavadvpn.vpn.EXTRA_STATS_BYTES_OUT
import com.cavadvpn.vpn.EXTRA_STATS_CONNECTED_SINCE
import com.cavadvpn.vpn.VpnConnectionState
import com.cavadvpn.vpn.VpnStats
import com.cavadvpn.vpn.formatBytes

/**
 * Main screen: shows VPN connection status, stats, and connect/disconnect controls.
 */
class MainActivity : AppCompatActivity() {

    // Views
    private lateinit var tvStatus: TextView
    private lateinit var tvAssignedIp: TextView
    private lateinit var tvBytesIn: TextView
    private lateinit var tvBytesOut: TextView
    private lateinit var tvUptime: TextView
    private lateinit var btnConnectDisconnect: Button
    private lateinit var btnSettings: Button
    private lateinit var btnScanQr: Button

    private var isConnected = false

    // -----------------------------------------------------------------------
    // VPN permission launcher
    // -----------------------------------------------------------------------

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            doConnect()
        }
    }

    // -----------------------------------------------------------------------
    // QR scan result launcher
    // -----------------------------------------------------------------------

    private val qrScanLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            // Config already saved by QrScanActivity; just update UI
            updateConnectButtonState()
        }
    }

    // -----------------------------------------------------------------------
    // Broadcast receiver for stats and state updates from the service
    // -----------------------------------------------------------------------

    private val statsReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            when (intent.action) {
                ACTION_STATS_UPDATE -> {
                    val bytesIn    = intent.getLongExtra(EXTRA_STATS_BYTES_IN, 0L)
                    val bytesOut   = intent.getLongExtra(EXTRA_STATS_BYTES_OUT, 0L)
                    val since      = intent.getLongExtra(EXTRA_STATS_CONNECTED_SINCE, 0L)
                    val assignedIp = intent.getStringExtra(EXTRA_STATS_ASSIGNED_IP) ?: ""
                    val stats = VpnStats(bytesIn, bytesOut, since, assignedIp)
                    updateStats(stats)
                }
                ACTION_VPN_STATE_CHANGED -> {
                    val state = intent.getStringExtra(EXTRA_STATE) ?: return
                    handleStateChange(state)
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Lifecycle
    // -----------------------------------------------------------------------

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        tvStatus              = findViewById(R.id.tvStatus)
        tvAssignedIp          = findViewById(R.id.tvAssignedIp)
        tvBytesIn             = findViewById(R.id.tvBytesIn)
        tvBytesOut            = findViewById(R.id.tvBytesOut)
        tvUptime              = findViewById(R.id.tvUptime)
        btnConnectDisconnect  = findViewById(R.id.btnConnectDisconnect)
        btnSettings           = findViewById(R.id.btnSettings)
        btnScanQr             = findViewById(R.id.btnScanQr)

        btnConnectDisconnect.setOnClickListener {
            if (isConnected) disconnect() else requestVpnPermissionAndConnect()
        }

        btnSettings.setOnClickListener {
            startActivity(Intent(this, SettingsActivity::class.java))
        }

        btnScanQr.setOnClickListener {
            qrScanLauncher.launch(Intent(this, QrScanActivity::class.java))
        }

        updateConnectButtonState()
    }

    override fun onResume() {
        super.onResume()
        val filter = IntentFilter().apply {
            addAction(ACTION_STATS_UPDATE)
            addAction(ACTION_VPN_STATE_CHANGED)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(statsReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("UnspecifiedRegisterReceiverFlag")
            registerReceiver(statsReceiver, filter)
        }
    }

    override fun onPause() {
        super.onPause()
        try { unregisterReceiver(statsReceiver) } catch (_: Exception) {}
    }

    // -----------------------------------------------------------------------
    // VPN connection helpers
    // -----------------------------------------------------------------------

    private fun requestVpnPermissionAndConnect() {
        val intent = VpnService.prepare(this)
        if (intent != null) {
            vpnPermissionLauncher.launch(intent)
        } else {
            // Permission already granted
            doConnect()
        }
    }

    private fun doConnect() {
        val prefs  = getSharedPreferences("vpn_config", Context.MODE_PRIVATE)
        val config = ConfigStore.load(prefs)
        if (config == null) {
            tvStatus.text = getString(R.string.status_no_config)
            return
        }

        val intent = Intent(this, CavadVpnService::class.java).apply {
            action = ACTION_CONNECT
            putExtra(EXTRA_SERVER_HOST,       config.serverHost)
            putExtra(EXTRA_SERVER_PORT,       config.serverPort)
            putExtra(EXTRA_PRIVATE_KEY,       config.privateKeyHex)
            putExtra(EXTRA_SERVER_PUBLIC_KEY, config.serverPublicKeyHex)
        }
        startService(intent)

        isConnected = false
        tvStatus.text = getString(R.string.status_connecting)
        btnConnectDisconnect.text = getString(R.string.action_disconnect)
    }

    private fun disconnect() {
        val intent = Intent(this, CavadVpnService::class.java).apply {
            action = ACTION_DISCONNECT
        }
        startService(intent)

        isConnected = false
        tvStatus.text = getString(R.string.status_disconnected)
        tvAssignedIp.text = ""
        tvBytesIn.text    = "↓ 0 B"
        tvBytesOut.text   = "↑ 0 B"
        tvUptime.text     = "00:00:00"
        btnConnectDisconnect.text = getString(R.string.action_connect)
    }

    // -----------------------------------------------------------------------
    // UI update helpers
    // -----------------------------------------------------------------------

    private fun updateStats(stats: VpnStats) {
        isConnected = true
        tvStatus.text     = getString(R.string.status_connected)
        tvAssignedIp.text = stats.assignedIp
        tvBytesIn.text    = "↓ ${formatBytes(stats.bytesIn)}"
        tvBytesOut.text   = "↑ ${formatBytes(stats.bytesOut)}"
        tvUptime.text     = stats.formatUptime()
        btnConnectDisconnect.text = getString(R.string.action_disconnect)
    }

    private fun handleStateChange(state: String) {
        when (state) {
            "CONNECTED" -> {
                isConnected = true
                tvStatus.text = getString(R.string.status_connected)
                btnConnectDisconnect.text = getString(R.string.action_disconnect)
            }
            "DISCONNECTED" -> {
                isConnected = false
                tvStatus.text = getString(R.string.status_disconnected)
                btnConnectDisconnect.text = getString(R.string.action_connect)
            }
            "CONNECTING" -> {
                tvStatus.text = getString(R.string.status_connecting)
            }
            "ERROR" -> {
                isConnected = false
                tvStatus.text = getString(R.string.status_error)
                btnConnectDisconnect.text = getString(R.string.action_connect)
            }
        }
    }

    private fun updateConnectButtonState() {
        btnConnectDisconnect.text = if (isConnected)
            getString(R.string.action_disconnect)
        else
            getString(R.string.action_connect)
    }
}
