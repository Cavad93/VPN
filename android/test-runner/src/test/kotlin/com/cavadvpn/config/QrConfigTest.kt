package com.cavadvpn.config

import org.junit.Assert.*
import org.junit.Test

class QrConfigTest {

    private val validKey = "a".repeat(64)

    // -----------------------------------------------------------------------
    // parseQrCode — JSON format
    // -----------------------------------------------------------------------

    @Test
    fun `parseQrCode valid JSON returns correct config`() {
        val json = """{"server":"vpn.example.com:443","key":"$validKey"}"""
        val config = QrConfig.parseQrCode(json)
        assertEquals("vpn.example.com", config.serverHost)
        assertEquals(443, config.serverPort)
        assertEquals(validKey, config.privateKeyHex)
    }

    @Test
    fun `parseQrCode JSON with dns field uses it`() {
        val json = """{"server":"10.0.0.1:1194","key":"$validKey","dns":"1.1.1.1"}"""
        val config = QrConfig.parseQrCode(json)
        assertEquals("1.1.1.1", config.dnsServer)
    }

    @Test
    fun `parseQrCode JSON without dns defaults to 8_8_8_8`() {
        val json = """{"server":"host:443","key":"$validKey"}"""
        val config = QrConfig.parseQrCode(json)
        assertEquals("8.8.8.8", config.dnsServer)
    }

    @Test(expected = IllegalArgumentException::class)
    fun `parseQrCode JSON missing server throws`() {
        QrConfig.parseQrCode("""{"key":"$validKey"}""")
    }

    @Test(expected = IllegalArgumentException::class)
    fun `parseQrCode JSON missing key throws`() {
        QrConfig.parseQrCode("""{"server":"host:443"}""")
    }

    @Test(expected = IllegalArgumentException::class)
    fun `parseQrCode JSON key too short throws`() {
        QrConfig.parseQrCode("""{"server":"host:443","key":"abc123"}""")
    }

    @Test(expected = IllegalArgumentException::class)
    fun `parseQrCode JSON invalid port throws`() {
        QrConfig.parseQrCode("""{"server":"host:99999","key":"$validKey"}""")
    }

    // -----------------------------------------------------------------------
    // parseQrCode — URI format
    // -----------------------------------------------------------------------

    @Test
    fun `parseQrCode URI format returns correct config`() {
        val uri = "cavadvpn://config?server=vpn.example.com:443&key=$validKey&dns=1.1.1.1"
        val config = QrConfig.parseQrCode(uri)
        assertEquals("vpn.example.com", config.serverHost)
        assertEquals(443, config.serverPort)
        assertEquals(validKey, config.privateKeyHex)
        assertEquals("1.1.1.1", config.dnsServer)
    }

    @Test(expected = IllegalArgumentException::class)
    fun `parseQrCode URI missing server throws`() {
        QrConfig.parseQrCode("cavadvpn://config?key=$validKey")
    }

    // -----------------------------------------------------------------------
    // parseQrCode — server-generated URI format (host+port+private_key)
    // -----------------------------------------------------------------------

    @Test
    fun `parseQrCode server URI format with host+port+private_key`() {
        val uri = "cavadvpn://config?host=vpn.example.com&port=443&private_key=$validKey&dns=8.8.8.8"
        val config = QrConfig.parseQrCode(uri)
        assertEquals("vpn.example.com", config.serverHost)
        assertEquals(443, config.serverPort)
        assertEquals(validKey, config.privateKeyHex)
    }

    @Test
    fun `parseQrCode server URI format with server_key`() {
        val serverKey = "b".repeat(64)
        val uri = "cavadvpn://config?host=10.0.0.1&port=443&private_key=$validKey&server_key=$serverKey&dns=1.1.1.1"
        val config = QrConfig.parseQrCode(uri)
        assertEquals("10.0.0.1", config.serverHost)
        assertEquals(443, config.serverPort)
        assertEquals(validKey, config.privateKeyHex)
        assertEquals(serverKey, config.serverPublicKeyHex)
        assertEquals("1.1.1.1", config.dnsServer)
    }

    @Test(expected = IllegalArgumentException::class)
    fun `parseQrCode server URI missing both server and host throws`() {
        QrConfig.parseQrCode("cavadvpn://config?port=443&private_key=$validKey")
    }

    @Test(expected = IllegalArgumentException::class)
    fun `parseQrCode server URI missing both key and private_key throws`() {
        QrConfig.parseQrCode("cavadvpn://config?host=example.com&port=443")
    }

    // -----------------------------------------------------------------------
    // parseQrCode — server-generated JSON format (host+port+private_key)
    // -----------------------------------------------------------------------

    @Test
    fun `parseQrCode server JSON format with host+port+private_key`() {
        val json = """{"host":"vpn.example.com","port":"443","private_key":"$validKey","dns":"1.1.1.1"}"""
        val config = QrConfig.parseQrCode(json)
        assertEquals("vpn.example.com", config.serverHost)
        assertEquals(443, config.serverPort)
        assertEquals(validKey, config.privateKeyHex)
        assertEquals("1.1.1.1", config.dnsServer)
    }

    @Test
    fun `parseQrCode server JSON format with server_key`() {
        val serverKey = "b".repeat(64)
        val json = """{"host":"10.8.0.1","port":"443","private_key":"$validKey","server_key":"$serverKey"}"""
        val config = QrConfig.parseQrCode(json)
        assertEquals("10.8.0.1", config.serverHost)
        assertEquals(validKey, config.privateKeyHex)
        assertEquals(serverKey, config.serverPublicKeyHex)
    }

    @Test(expected = IllegalArgumentException::class)
    fun `parseQrCode server JSON missing both server and host throws`() {
        QrConfig.parseQrCode("""{"port":"443","private_key":"$validKey"}""")
    }

    @Test(expected = IllegalArgumentException::class)
    fun `parseQrCode server JSON missing both key and private_key throws`() {
        QrConfig.parseQrCode("""{"host":"example.com","port":"443"}""")
    }

    // -----------------------------------------------------------------------
    // toQrJson round-trip
    // -----------------------------------------------------------------------

    @Test
    fun `toQrJson round-trip preserves host port and key`() {
        val original = VpnConfig(
            serverHost    = "vpn.example.com",
            serverPort    = 8443,
            privateKeyHex = validKey,
            dnsServer     = "8.8.8.8"
        )
        val json   = QrConfig.toQrJson(original)
        val parsed = QrConfig.parseQrCode(json)
        assertEquals(original.serverHost, parsed.serverHost)
        assertEquals(original.serverPort, parsed.serverPort)
        assertEquals(original.privateKeyHex, parsed.privateKeyHex)
    }

    @Test
    fun `toQrJson output is valid JSON with server field`() {
        val config = VpnConfig(
            serverHost    = "host.example.com",
            serverPort    = 443,
            privateKeyHex = validKey
        )
        val json = QrConfig.toQrJson(config)
        assertTrue(json.contains("\"server\""))
        assertTrue(json.contains("host.example.com:443"))
    }
}
