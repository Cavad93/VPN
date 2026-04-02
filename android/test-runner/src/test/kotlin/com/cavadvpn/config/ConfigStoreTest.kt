package com.cavadvpn.config

import android.content.SharedPreferences
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

/**
 * Unit tests for [ConfigStore] using an in-memory [SharedPreferences] fake.
 */
class ConfigStoreTest {

    private lateinit var prefs: SharedPreferences

    @Before
    fun setUp() {
        prefs = FakeSharedPreferences()
    }

    @Test
    fun `load on empty prefs returns null`() {
        assertNull(ConfigStore.load(prefs))
    }

    @Test
    fun `save and load round-trip preserves serverHost`() {
        val config = makeConfig()
        ConfigStore.save(prefs, config)
        val loaded = ConfigStore.load(prefs)
        assertNotNull(loaded)
        assertEquals("vpn.example.com", loaded!!.serverHost)
    }

    @Test
    fun `save and load round-trip preserves serverPort`() {
        val config = makeConfig(port = 8443)
        ConfigStore.save(prefs, config)
        val loaded = ConfigStore.load(prefs)!!
        assertEquals(8443, loaded.serverPort)
    }

    @Test
    fun `save and load round-trip preserves privateKeyHex`() {
        val key = "b".repeat(64)
        val config = makeConfig(privateKey = key)
        ConfigStore.save(prefs, config)
        val loaded = ConfigStore.load(prefs)!!
        assertEquals(key, loaded.privateKeyHex)
    }

    @Test
    fun `save and load round-trip preserves dnsServer`() {
        val config = makeConfig(dns = "1.1.1.1")
        ConfigStore.save(prefs, config)
        val loaded = ConfigStore.load(prefs)!!
        assertEquals("1.1.1.1", loaded.dnsServer)
    }

    @Test
    fun `save and load round-trip preserves mtu`() {
        val config = makeConfig(mtu = 1280)
        ConfigStore.save(prefs, config)
        val loaded = ConfigStore.load(prefs)!!
        assertEquals(1280, loaded.mtu)
    }

    @Test
    fun `clear removes config so load returns null`() {
        ConfigStore.save(prefs, makeConfig())
        assertNotNull(ConfigStore.load(prefs))
        ConfigStore.clear(prefs)
        assertNull(ConfigStore.load(prefs))
    }

    @Test
    fun `load uses default port 443 when not set`() {
        // Manually store only the host key to simulate missing port
        val fake = FakeSharedPreferences()
        fake.edit().putString(ConfigStore.KEY_SERVER_HOST, "host").apply()
        val loaded = ConfigStore.load(fake)!!
        assertEquals(443, loaded.serverPort)
    }

    @Test
    fun `load uses default dns 8_8_8_8 when not set`() {
        val fake = FakeSharedPreferences()
        fake.edit().putString(ConfigStore.KEY_SERVER_HOST, "host").apply()
        val loaded = ConfigStore.load(fake)!!
        assertEquals("8.8.8.8", loaded.dnsServer)
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private fun makeConfig(
        host: String = "vpn.example.com",
        port: Int = 443,
        privateKey: String = "a".repeat(64),
        serverPublicKey: String = "",
        dns: String = "8.8.8.8",
        mtu: Int = 1400
    ) = VpnConfig(
        serverHost         = host,
        serverPort         = port,
        privateKeyHex      = privateKey,
        serverPublicKeyHex = serverPublicKey,
        dnsServer          = dns,
        mtu                = mtu
    )
}

// -----------------------------------------------------------------------
// In-memory SharedPreferences fake
// -----------------------------------------------------------------------

/**
 * A simple HashMap-backed [SharedPreferences] implementation for unit tests.
 * No Android framework code required.
 */
class FakeSharedPreferences : SharedPreferences {

    private val map = HashMap<String, Any?>()
    private val listeners = mutableListOf<SharedPreferences.OnSharedPreferenceChangeListener>()

    override fun getAll(): Map<String, *> = HashMap(map)

    override fun getString(key: String, defValue: String?): String? =
        (map[key] as? String) ?: defValue

    override fun getStringSet(key: String, defValues: Set<String>?): Set<String>? =
        @Suppress("UNCHECKED_CAST")
        (map[key] as? Set<String>) ?: defValues

    override fun getInt(key: String, defValue: Int): Int =
        (map[key] as? Int) ?: defValue

    override fun getLong(key: String, defValue: Long): Long =
        (map[key] as? Long) ?: defValue

    override fun getFloat(key: String, defValue: Float): Float =
        (map[key] as? Float) ?: defValue

    override fun getBoolean(key: String, defValue: Boolean): Boolean =
        (map[key] as? Boolean) ?: defValue

    override fun contains(key: String): Boolean = map.containsKey(key)

    override fun edit(): SharedPreferences.Editor = FakeEditor(map, listeners, this)

    override fun registerOnSharedPreferenceChangeListener(
        listener: SharedPreferences.OnSharedPreferenceChangeListener
    ) { listeners.add(listener) }

    override fun unregisterOnSharedPreferenceChangeListener(
        listener: SharedPreferences.OnSharedPreferenceChangeListener
    ) { listeners.remove(listener) }
}

private class FakeEditor(
    private val map: HashMap<String, Any?>,
    private val listeners: List<SharedPreferences.OnSharedPreferenceChangeListener>,
    private val prefs: SharedPreferences
) : SharedPreferences.Editor {

    private val pending = HashMap<String, Any?>()
    private val removals = mutableSetOf<String>()
    private var clearAll = false

    override fun putString(key: String, value: String?): SharedPreferences.Editor {
        pending[key] = value; return this
    }
    override fun putStringSet(key: String, values: Set<String>?): SharedPreferences.Editor {
        pending[key] = values; return this
    }
    override fun putInt(key: String, value: Int): SharedPreferences.Editor {
        pending[key] = value; return this
    }
    override fun putLong(key: String, value: Long): SharedPreferences.Editor {
        pending[key] = value; return this
    }
    override fun putFloat(key: String, value: Float): SharedPreferences.Editor {
        pending[key] = value; return this
    }
    override fun putBoolean(key: String, value: Boolean): SharedPreferences.Editor {
        pending[key] = value; return this
    }
    override fun remove(key: String): SharedPreferences.Editor {
        removals.add(key); return this
    }
    override fun clear(): SharedPreferences.Editor {
        clearAll = true; return this
    }

    override fun commit(): Boolean {
        applyChanges(); return true
    }

    override fun apply() {
        applyChanges()
    }

    private fun applyChanges() {
        if (clearAll) map.clear()
        removals.forEach { map.remove(it) }
        map.putAll(pending)
        pending.clear()
        removals.clear()
        clearAll = false
    }
}
