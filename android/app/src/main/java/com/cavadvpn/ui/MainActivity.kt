package com.cavadvpn.ui

import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.graphics.drawable.GradientDrawable
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.view.View
import android.view.animation.AccelerateDecelerateInterpolator
import android.widget.ImageButton
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import com.cavadvpn.R
import com.cavadvpn.config.ConfigStore
import com.cavadvpn.crypto.generateKeyPair
import com.cavadvpn.vpn.ACTION_CONNECT
import com.cavadvpn.vpn.ACTION_DISCONNECT
import com.cavadvpn.vpn.ACTION_STATS_UPDATE
import com.cavadvpn.vpn.ACTION_VPN_STATE_CHANGED
import com.cavadvpn.vpn.CavadVpnService
import com.cavadvpn.vpn.EXTRA_KNOCK_KEY
import com.cavadvpn.vpn.EXTRA_PRIVATE_KEY
import com.cavadvpn.vpn.EXTRA_SERVER_HOST
import com.cavadvpn.vpn.EXTRA_SERVER_PORT
import com.cavadvpn.vpn.EXTRA_SERVER_PUBLIC_KEY
import com.cavadvpn.vpn.EXTRA_ERROR_MSG
import com.cavadvpn.vpn.EXTRA_STATE
import com.cavadvpn.vpn.EXTRA_STATS_ASSIGNED_IP
import com.cavadvpn.vpn.EXTRA_STATS_BYTES_IN
import com.cavadvpn.vpn.EXTRA_STATS_BYTES_OUT
import com.cavadvpn.vpn.EXTRA_STATS_CONNECTED_SINCE
import com.cavadvpn.vpn.VpnStats
import com.cavadvpn.vpn.formatBytes

class MainActivity : AppCompatActivity() {

    private lateinit var tvStatus: TextView
    private lateinit var statusDot: View
    private lateinit var powerRing: View
    private lateinit var btnConnect: ImageButton
    private lateinit var tvConnectionAction: TextView
    private lateinit var tvAssignedIp: TextView
    private lateinit var tvBytesIn: TextView
    private lateinit var tvBytesOut: TextView
    private lateinit var tvUptime: TextView
    private lateinit var tvServerAddr: TextView
    private lateinit var btnSettings: ImageButton
    private lateinit var btnScanQr: ImageButton

    private var isConnected = false

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) doConnect()
    }

    private val qrScanLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) refreshServerLabel()
    }

    private val statsReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            when (intent.action) {
                ACTION_STATS_UPDATE -> {
                    val stats = VpnStats(
                        intent.getLongExtra(EXTRA_STATS_BYTES_IN, 0L),
                        intent.getLongExtra(EXTRA_STATS_BYTES_OUT, 0L),
                        intent.getLongExtra(EXTRA_STATS_CONNECTED_SINCE, 0L),
                        intent.getStringExtra(EXTRA_STATS_ASSIGNED_IP) ?: ""
                    )
                    updateStats(stats)
                }
                ACTION_VPN_STATE_CHANGED -> {
                    handleStateChange(
                        intent.getStringExtra(EXTRA_STATE) ?: return,
                        intent.getStringExtra(EXTRA_ERROR_MSG)
                    )
                }
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        tvStatus           = findViewById(R.id.tvStatus)
        statusDot          = findViewById(R.id.statusDot)
        powerRing          = findViewById(R.id.powerRing)
        btnConnect         = findViewById(R.id.btnConnectDisconnect)
        tvConnectionAction = findViewById(R.id.tvConnectionAction)
        tvAssignedIp       = findViewById(R.id.tvAssignedIp)
        tvBytesIn          = findViewById(R.id.tvBytesIn)
        tvBytesOut         = findViewById(R.id.tvBytesOut)
        tvUptime           = findViewById(R.id.tvUptime)
        tvServerAddr       = findViewById(R.id.tvServerAddr)
        btnSettings        = findViewById(R.id.btnSettings)
        btnScanQr          = findViewById(R.id.btnScanQr)

        btnConnect.setOnClickListener {
            if (isConnected) disconnect() else requestVpnPermissionAndConnect()
        }
        btnSettings.setOnClickListener {
            startActivity(Intent(this, SettingsActivity::class.java))
        }
        btnScanQr.setOnClickListener {
            qrScanLauncher.launch(Intent(this, QrScanActivity::class.java))
        }

        refreshServerLabel()
        applyDisconnectedUI()
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
        refreshServerLabel()
    }

    override fun onPause() {
        super.onPause()
        try { unregisterReceiver(statsReceiver) } catch (_: Exception) {}
    }

    // --- VPN connection ---

    private fun requestVpnPermissionAndConnect() {
        val intent = VpnService.prepare(this)
        if (intent != null) vpnPermissionLauncher.launch(intent) else doConnect()
    }

    private fun doConnect() {
        val prefs  = getSharedPreferences("vpn_config", Context.MODE_PRIVATE)
        val config = ConfigStore.load(prefs)
        if (config == null) {
            tvStatus.text = getString(R.string.status_no_config)
            return
        }

        val privateKeyHex = if (config.privateKeyHex.isBlank()) {
            val kp = generateKeyPair()
            val hex = kp.privateKey.joinToString("") { "%02x".format(it) }
            prefs.edit().putString(ConfigStore.KEY_PRIVATE_KEY, hex).apply()
            hex
        } else {
            config.privateKeyHex
        }

        val intent = Intent(this, CavadVpnService::class.java).apply {
            action = ACTION_CONNECT
            putExtra(EXTRA_SERVER_HOST,       config.serverHost)
            putExtra(EXTRA_SERVER_PORT,       config.serverPort)
            putExtra(EXTRA_PRIVATE_KEY,       privateKeyHex)
            putExtra(EXTRA_SERVER_PUBLIC_KEY, config.serverPublicKeyHex)
            putExtra(EXTRA_KNOCK_KEY,         config.knockKeyHex)
        }
        startService(intent)
        applyConnectingUI()
    }

    private fun disconnect() {
        startService(Intent(this, CavadVpnService::class.java).apply {
            action = ACTION_DISCONNECT
        })
        applyDisconnectedUI()
    }

    // --- UI state ---

    private fun updateStats(stats: VpnStats) {
        if (!isConnected) applyConnectedUI()
        tvAssignedIp.text = stats.assignedIp
        tvAssignedIp.visibility = if (stats.assignedIp.isNotBlank()) View.VISIBLE else View.GONE
        tvBytesIn.text  = formatBytes(stats.bytesIn)
        tvBytesOut.text = formatBytes(stats.bytesOut)
        tvUptime.text   = stats.formatUptime()
    }

    private fun handleStateChange(state: String, errorMsg: String? = null) {
        when (state) {
            "CONNECTED"    -> applyConnectedUI()
            "DISCONNECTED" -> applyDisconnectedUI()
            "CONNECTING"   -> applyConnectingUI()
            "ERROR"        -> {
                applyDisconnectedUI()
                tvStatus.text = errorMsg?.let { "${getString(R.string.status_error)}: $it" }
                    ?: getString(R.string.status_error)
                setDotColor(R.color.status_error)
            }
        }
    }

    private fun applyConnectedUI() {
        isConnected = true
        tvStatus.text = getString(R.string.status_connected)
        tvConnectionAction.text = getString(R.string.tap_to_disconnect)
        setDotColor(R.color.status_connected)
        powerRing.setBackgroundResource(R.drawable.bg_power_ring_connected)
        animatePowerRing()
    }

    private fun applyDisconnectedUI() {
        isConnected = false
        tvStatus.text = getString(R.string.status_disconnected)
        tvConnectionAction.text = getString(R.string.tap_to_connect)
        tvAssignedIp.visibility = View.GONE
        tvBytesIn.text  = "0 B"
        tvBytesOut.text = "0 B"
        tvUptime.text   = "00:00"
        setDotColor(R.color.status_disconnected)
        powerRing.setBackgroundResource(R.drawable.bg_power_ring)
        powerRing.scaleX = 1f
        powerRing.scaleY = 1f
    }

    private fun applyConnectingUI() {
        tvStatus.text = getString(R.string.status_connecting)
        tvConnectionAction.text = getString(R.string.securing_connection)
        setDotColor(R.color.status_connecting)
    }

    private fun setDotColor(colorRes: Int) {
        val bg = statusDot.background
        if (bg is GradientDrawable) {
            bg.setColor(ContextCompat.getColor(this, colorRes))
        }
    }

    private fun animatePowerRing() {
        powerRing.animate()
            .scaleX(1.08f).scaleY(1.08f)
            .setDuration(600)
            .setInterpolator(AccelerateDecelerateInterpolator())
            .withEndAction {
                powerRing.animate()
                    .scaleX(1f).scaleY(1f)
                    .setDuration(600)
                    .setInterpolator(AccelerateDecelerateInterpolator())
                    .start()
            }
            .start()
    }

    private fun refreshServerLabel() {
        val prefs = getSharedPreferences("vpn_config", Context.MODE_PRIVATE)
        val config = ConfigStore.load(prefs)
        tvServerAddr.text = if (config != null) {
            "${config.serverHost}:${config.serverPort}"
        } else {
            getString(R.string.label_not_configured)
        }
    }
}
