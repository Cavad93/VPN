package com.cavadvpn.ui

import android.content.Context
import android.os.Bundle
import android.widget.EditText
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.cavadvpn.R
import com.cavadvpn.config.ConfigStore
import com.cavadvpn.config.VpnConfig
import com.cavadvpn.crypto.generateKeyPair
import com.google.android.material.button.MaterialButton

class SettingsActivity : AppCompatActivity() {

    private lateinit var etServerHost: EditText
    private lateinit var etServerPort: EditText
    private lateinit var etPrivateKey: EditText
    private lateinit var etServerPublicKey: EditText
    private lateinit var etKnockKey: EditText
    private lateinit var etDnsServer: EditText
    private lateinit var btnGenerateKey: MaterialButton
    private lateinit var btnSave: MaterialButton

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_settings)

        etServerHost      = findViewById(R.id.etServerHost)
        etServerPort      = findViewById(R.id.etServerPort)
        etPrivateKey      = findViewById(R.id.etPrivateKey)
        etServerPublicKey = findViewById(R.id.etServerPublicKey)
        etKnockKey        = findViewById(R.id.etKnockKey)
        etDnsServer       = findViewById(R.id.etDnsServer)
        btnGenerateKey    = findViewById(R.id.btnGenerateKey)
        btnSave           = findViewById(R.id.btnSave)

        val prefs  = getSharedPreferences("vpn_config", Context.MODE_PRIVATE)
        val config = ConfigStore.load(prefs)
        if (config != null) {
            etServerHost.setText(config.serverHost)
            etServerPort.setText(config.serverPort.toString())
            etPrivateKey.setText(config.privateKeyHex)
            etServerPublicKey.setText(config.serverPublicKeyHex)
            etKnockKey.setText(config.knockKeyHex)
            etDnsServer.setText(config.dnsServer)
        } else {
            etServerPort.setText("443")
            etDnsServer.setText("8.8.8.8")
        }

        btnGenerateKey.setOnClickListener {
            val kp = generateKeyPair()
            val privHex = kp.privateKey.joinToString("") { "%02x".format(it) }
            etPrivateKey.setText(privHex)
        }

        btnSave.setOnClickListener { saveConfig(prefs) }
    }

    private fun saveConfig(prefs: android.content.SharedPreferences) {
        val host = etServerHost.text.toString().trim()
        if (host.isBlank()) {
            etServerHost.error = getString(R.string.error_host_required)
            return
        }

        val portStr = etServerPort.text.toString().trim()
        val port = portStr.toIntOrNull()
        if (port == null || port !in 1..65535) {
            etServerPort.error = getString(R.string.error_invalid_port)
            return
        }

        val privKey = etPrivateKey.text.toString().trim()
        if (privKey.isNotBlank() && (privKey.length != 64 || !privKey.all { it.isHex() })) {
            etPrivateKey.error = getString(R.string.error_invalid_key)
            return
        }

        val serverPubKey = etServerPublicKey.text.toString().trim()
        if (serverPubKey.isNotBlank() && (serverPubKey.length != 64 || !serverPubKey.all { it.isHex() })) {
            etServerPublicKey.error = getString(R.string.error_invalid_key)
            return
        }

        val knockKey = etKnockKey.text.toString().trim()
        if (knockKey.isNotBlank() && (knockKey.length != 64 || !knockKey.all { it.isHex() })) {
            etKnockKey.error = getString(R.string.error_invalid_key)
            return
        }

        val dns = etDnsServer.text.toString().trim().ifBlank { "8.8.8.8" }

        val config = VpnConfig(
            serverHost         = host,
            serverPort         = port,
            privateKeyHex      = privKey,
            serverPublicKeyHex = serverPubKey,
            knockKeyHex        = knockKey,
            dnsServer          = dns
        )
        ConfigStore.save(prefs, config)
        Toast.makeText(this, getString(R.string.settings_saved), Toast.LENGTH_SHORT).show()
        finish()
    }

    private fun Char.isHex() = this in '0'..'9' || this in 'a'..'f' || this in 'A'..'F'
}
