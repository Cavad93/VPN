package com.cavadvpn.vpn

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class TelemetryCollectorTest {

    private fun createCollector(
        serverUrl: String = "http://127.0.0.1:1",
        getState: (() -> TelemetryCollector.VpnState)? = null,
        onConfigUpdate: ((TelemetryCollector.AiConfig) -> Unit)? = null,
    ): TelemetryCollector {
        return TelemetryCollector(
            serverUrl     = serverUrl,
            context       = null,
            collectIntervalMs = 60_000,
            appVersion    = "1.0.0-test",
            getVpnState   = getState,
            onConfigUpdate = onConfigUpdate,
        )
    }

    // ── Core fields ────────────────────────────────────────────────────────────

    @Test fun testCollectBasicReport() {
        val tc = createCollector()
        tc.updateBytes(5000, 3000)
        tc.handshakeMs = 120.5

        val r = tc.collectNow()
        assertEquals("android",    r.getString("platform"))
        assertEquals(5000L,        r.getLong("bytes_in"))
        assertEquals(3000L,        r.getLong("bytes_out"))
        assertEquals(120.5,        r.getDouble("handshake_ms"), 0.01)
        assertEquals("1.0.0-test", r.getString("app_version"))
        assertTrue(r.getString("device_id").isNotEmpty())
        assertTrue(r.getString("timestamp").contains("T"))
    }

    @Test fun testUpdateBytes() {
        val tc = createCollector()
        tc.updateBytes(100, 50)
        assertEquals(100L, tc.collectNow().getLong("bytes_in"))
        tc.updateBytes(200, 100)
        assertEquals(200L, tc.collectNow().getLong("bytes_in"))
    }

    @Test fun testReconnectCounter() {
        val tc = createCollector()
        repeat(3) { tc.recordReconnect() }
        assertEquals(3, tc.collectNow().getInt("reconnect_count"))
    }

    @Test fun testTlsErrorCounter() {
        val tc = createCollector()
        tc.recordTlsError()
        assertEquals(1, tc.collectNow().getInt("tls_errors"))
    }

    @Test fun testDpiDetection() {
        val tc = createCollector()
        assertFalse(tc.collectNow().getBoolean("dpi_detected"))
        tc.recordDpiDetection()
        assertTrue(tc.collectNow().getBoolean("dpi_detected"))
    }

    @Test fun testConnectDisconnect() {
        val tc = createCollector()
        assertEquals(0.0, tc.collectNow().getDouble("uptime_sec"), 0.01)
        tc.recordConnect()
        Thread.sleep(50)
        assertTrue(tc.collectNow().getDouble("uptime_sec") > 0)
        tc.recordDisconnect()
        assertEquals(0.0, tc.collectNow().getDouble("uptime_sec"), 0.01)
    }

    @Test fun testConnectionStateCallback() {
        val tc = createCollector(
            getState = { TelemetryCollector.VpnState("connected", "1.2.3.4:8443") }
        )
        val r = tc.collectNow()
        assertEquals("connected",    r.getString("connection_state"))
        assertEquals("1.2.3.4:8443", r.getString("server_addr"))
    }

    @Test fun testDefaultConnectionState() {
        assertEquals("disconnected", createCollector().collectNow().getString("connection_state"))
    }

    @Test fun testDeviceIdStable() {
        assertEquals(
            createCollector().collectNow().getString("device_id"),
            createCollector().collectNow().getString("device_id"),
        )
    }

    @Test fun testDeviceIdLength() {
        assertEquals(16, createCollector().collectNow().getString("device_id").length)
    }

    // ── New transport fields (Step 1 of AI autonomy) ───────────────────────────

    @Test fun testTransportInfoFields() {
        val tc = createCollector()
        tc.setTransportInfo(transport = "udp", bonds = 128, padding = "balanced", sni = "google.com")

        val r = tc.collectNow()
        assertEquals("udp",        r.getString("transport_mode"))
        assertEquals(128,          r.getInt("bond_count"))
        assertEquals("balanced",   r.getString("padding_mode"))
        assertEquals("google.com", r.getString("sni_host"))
    }

    @Test fun testTransportInfoDefaultsEmpty() {
        val r = createCollector().collectNow()
        assertEquals("", r.getString("transport_mode"))
        assertEquals(0,  r.getInt("bond_count"))
        assertEquals("", r.getString("padding_mode"))
        assertEquals("", r.getString("sni_host"))
    }

    @Test fun testHandshakeAttempts() {
        val tc = createCollector()
        assertEquals(0, tc.collectNow().getInt("handshake_attempts"))
        tc.recordHandshakeAttempt()
        tc.recordHandshakeAttempt()
        assertEquals(2, tc.collectNow().getInt("handshake_attempts"))
        tc.resetHandshakeAttempts()
        assertEquals(0, tc.collectNow().getInt("handshake_attempts"))
    }

    @Test fun testTransportInfoOverwrite() {
        val tc = createCollector()
        tc.setTransportInfo(transport = "tcp", bonds = 64)
        assertEquals("tcp", tc.collectNow().getString("transport_mode"))
        tc.setTransportInfo(transport = "udp", bonds = 128)
        assertEquals("udp", tc.collectNow().getString("transport_mode"))
        assertEquals(128,   tc.collectNow().getInt("bond_count"))
    }

    // ── AiConfig JSON parsing ──────────────────────────────────────────────────

    @Test fun testAiConfigFromJsonFlat() {
        val j = JSONObject().apply {
            put("transport_mode",  "udp")
            put("bond_count",      64)
            put("mtu",             1300)
            put("padding_mode",    "light")
            put("padding_enabled", true)
            put("jitter_ms",       10)
        }
        val cfg = TelemetryCollector.AiConfig.fromJson(j)
        assertEquals("udp",   cfg.transportMode)
        assertEquals(64,      cfg.bondCount)
        assertEquals(1300,    cfg.mtu)
        assertEquals("light", cfg.paddingMode)
        assertTrue(cfg.paddingEnabled)
        assertEquals(10,      cfg.jitterMs)
    }

    @Test fun testAiConfigFromJsonWrapped() {
        // Server wraps applied config in {config:{…}, applied_at:…}
        val inner = JSONObject().apply {
            put("transport_mode", "tcp")
            put("bond_count",     32)
        }
        val j = JSONObject().apply {
            put("config",     inner)
            put("applied_at", "2026-04-08T03:00:00Z")
            put("reason",     "test")
        }
        val cfg = TelemetryCollector.AiConfig.fromJson(j)
        assertEquals("tcp", cfg.transportMode)
        assertEquals(32,    cfg.bondCount)
    }

    @Test fun testAiConfigFromJsonEmpty() {
        val cfg = TelemetryCollector.AiConfig.fromJson(JSONObject())
        assertEquals("", cfg.transportMode)
        assertEquals(0,  cfg.bondCount)
        assertEquals(0,  cfg.mtu)
    }

    @Test fun testAiConfigFromJsonSniHosts() {
        val arr = org.json.JSONArray().apply {
            put("youtube.com"); put("google.com")
        }
        val j = JSONObject().apply { put("sni_hosts", arr) }
        val cfg = TelemetryCollector.AiConfig.fromJson(j)
        assertEquals(listOf("youtube.com", "google.com"), cfg.sniHosts)
    }

    @Test fun testAiConfigHashChange() {
        val cfg1 = TelemetryCollector.AiConfig(transportMode = "tcp", bondCount = 64)
        val cfg2 = TelemetryCollector.AiConfig(transportMode = "udp", bondCount = 64)
        val cfg3 = TelemetryCollector.AiConfig(transportMode = "tcp", bondCount = 64)
        assertNotEquals(cfg1.hashCode(), cfg2.hashCode())
        assertEquals(cfg1.hashCode(), cfg3.hashCode())
    }

    // ── Config update callback ─────────────────────────────────────────────────

    @Test fun testOnConfigUpdateCallbackRegistered() {
        var called = false
        val tc = createCollector(onConfigUpdate = { called = true })
        assertNotNull(tc.onConfigUpdate)
        tc.onConfigUpdate!!.invoke(TelemetryCollector.AiConfig(transportMode = "udp"))
        assertTrue(called)
    }

    @Test fun testOnConfigUpdateNullByDefault() {
        assertNull(createCollector().onConfigUpdate)
    }

    @Test fun testOnConfigUpdateReceivesFields() {
        var received: TelemetryCollector.AiConfig? = null
        val tc = createCollector(onConfigUpdate = { received = it })
        val expected = TelemetryCollector.AiConfig(
            transportMode  = "tcp",
            bondCount      = 128,
            mtu            = 1400,
            paddingMode    = "paranoid",
            paddingEnabled = true,
            jitterMs       = 20,
        )
        tc.onConfigUpdate!!.invoke(expected)
        assertEquals("tcp",      received?.transportMode)
        assertEquals(128,        received?.bondCount)
        assertEquals(1400,       received?.mtu)
        assertEquals("paranoid", received?.paddingMode)
        assertTrue(received?.paddingEnabled == true)
        assertEquals(20,         received?.jitterMs)
    }

    // ── Network / battery (no context) ────────────────────────────────────────

    @Test fun testNetworkTypeWithoutContext() {
        assertEquals("unknown", createCollector().collectNow().getString("network_type"))
    }

    @Test fun testBatteryWithoutContext() {
        assertEquals(0, createCollector().collectNow().getInt("battery_percent"))
    }

    // ── TCP ping ───────────────────────────────────────────────────────────────

    @Test fun testTcpPingUnreachable() {
        assertEquals(0.0, TelemetryCollector.measureTcpPing("192.0.2.1:1", 500), 0.01)
    }

    @Test fun testTcpPingInvalidAddr() {
        assertEquals(0.0, TelemetryCollector.measureTcpPing("invalid", 500), 0.01)
    }

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    @Test fun testSendFailure() {
        assertFalse(createCollector(serverUrl = "http://127.0.0.1:1").sendNow())
    }

    @Test fun testStartStop() {
        val tc = createCollector()
        tc.start()
        Thread.sleep(50)
        tc.stop()
        // No crash = pass
    }
}
