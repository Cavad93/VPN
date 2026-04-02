package com.cavadvpn.config

import android.content.SharedPreferences

/**
 * Persists [VpnConfig] to [SharedPreferences].
 */
object ConfigStore {

    const val KEY_SERVER_HOST       = "server_host"
    const val KEY_SERVER_PORT       = "server_port"
    const val KEY_PRIVATE_KEY       = "private_key_hex"
    const val KEY_SERVER_PUBLIC_KEY = "server_public_key_hex"
    const val KEY_DNS_SERVER        = "dns_server"
    const val KEY_MTU               = "mtu"

    fun save(prefs: SharedPreferences, config: VpnConfig) {
        prefs.edit()
            .putString(KEY_SERVER_HOST,       config.serverHost)
            .putInt   (KEY_SERVER_PORT,       config.serverPort)
            .putString(KEY_PRIVATE_KEY,       config.privateKeyHex)
            .putString(KEY_SERVER_PUBLIC_KEY, config.serverPublicKeyHex)
            .putString(KEY_DNS_SERVER,        config.dnsServer)
            .putInt   (KEY_MTU,               config.mtu)
            .apply()
    }

    fun load(prefs: SharedPreferences): VpnConfig? {
        val host = prefs.getString(KEY_SERVER_HOST, null) ?: return null
        return VpnConfig(
            serverHost        = host,
            serverPort        = prefs.getInt   (KEY_SERVER_PORT,       443),
            privateKeyHex     = prefs.getString(KEY_PRIVATE_KEY,       "") ?: "",
            serverPublicKeyHex = prefs.getString(KEY_SERVER_PUBLIC_KEY, "") ?: "",
            dnsServer         = prefs.getString(KEY_DNS_SERVER,        "8.8.8.8") ?: "8.8.8.8",
            mtu               = prefs.getInt   (KEY_MTU,               1400)
        )
    }

    fun clear(prefs: SharedPreferences) {
        prefs.edit()
            .remove(KEY_SERVER_HOST)
            .remove(KEY_SERVER_PORT)
            .remove(KEY_PRIVATE_KEY)
            .remove(KEY_SERVER_PUBLIC_KEY)
            .remove(KEY_DNS_SERVER)
            .remove(KEY_MTU)
            .apply()
    }
}
