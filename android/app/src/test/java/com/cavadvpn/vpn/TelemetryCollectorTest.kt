package com.cavadvpn.vpn

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class TelemetryCollectorTest {

    private fun createCollector(
        serverUrl: String = "http://127.0.0.1:1",
        getState: (() -> TelemetryCollector.VpnState)? = null,
    ): TelemetryCollector {
        return TelemetryCollector(
            serverUrl = serverUrl,
            context = null,  // no Android context in unit tests
            collectIntervalMs = 60_000,
            appVersion = "1.0.0-test",
            getVpnState = getState,
        )
    }

    @Test
    fun testCollectBasicReport() {
        val tc = createCollector()
        tc.updateBytes(5000, 3000)
        tc.handshakeMs = 120.5

        val report = tc.collectNow()
        assertEquals("android", report.getString("platform"))
        assertEquals(5000L, report.getLong("bytes_in"))
        assertEquals(3000L, report.getLong("bytes_out"))
        assertEquals(120.5, report.getDouble("handshake_ms"), 0.01)
        assertEquals("1.0.0-test", report.getString("app_version"))
        assertTrue(report.getString("device_id").isNotEmpty())
        assertTrue(report.getString("timestamp").contains("T"))
    }

    @Test
    fun testUpdateBytes() {
        val tc = createCollector()
        tc.updateBytes(100, 50)
        val r1 = tc.collectNow()
        assertEquals(100L, r1.getLong("bytes_in"))
        assertEquals(50L, r1.getLong("bytes_out"))

        tc.updateBytes(200, 100)
        val r2 = tc.collectNow()
        assertEquals(200L, r2.getLong("bytes_in"))
    }

    @Test
    fun testReconnectCounter() {
        val tc = createCollector()
        tc.recordReconnect()
        tc.recordReconnect()
        tc.recordReconnect()
        val report = tc.collectNow()
        assertEquals(3, report.getInt("reconnect_count"))
    }

    @Test
    fun testTlsErrorCounter() {
        val tc = createCollector()
        tc.recordTlsError()
        val report = tc.collectNow()
        assertEquals(1, report.getInt("tls_errors"))
    }

    @Test
    fun testDpiDetection() {
        val tc = createCollector()
        assertFalse(tc.collectNow().getBoolean("dpi_detected"))
        tc.recordDpiDetection()
        assertTrue(tc.collectNow().getBoolean("dpi_detected"))
    }

    @Test
    fun testConnectDisconnect() {
        val tc = createCollector()
        assertEquals(0.0, tc.collectNow().getDouble("uptime_sec"), 0.01)

        tc.recordConnect()
        Thread.sleep(50)
        val report = tc.collectNow()
        assertTrue("uptime should be > 0", report.getDouble("uptime_sec") > 0)

        tc.recordDisconnect()
        assertEquals(0.0, tc.collectNow().getDouble("uptime_sec"), 0.01)
    }

    @Test
    fun testConnectionStateCallback() {
        val tc = createCollector(
            getState = { TelemetryCollector.VpnState("connected", "1.2.3.4:8443") }
        )
        val report = tc.collectNow()
        assertEquals("connected", report.getString("connection_state"))
        assertEquals("1.2.3.4:8443", report.getString("server_addr"))
    }

    @Test
    fun testDefaultConnectionState() {
        val tc = createCollector()
        val report = tc.collectNow()
        assertEquals("disconnected", report.getString("connection_state"))
    }

    @Test
    fun testDeviceIdStable() {
        val tc1 = createCollector()
        val tc2 = createCollector()
        assertEquals(
            tc1.collectNow().getString("device_id"),
            tc2.collectNow().getString("device_id")
        )
    }

    @Test
    fun testDeviceIdLength() {
        val tc = createCollector()
        val id = tc.collectNow().getString("device_id")
        assertEquals(16, id.length)
    }

    @Test
    fun testTcpPingUnreachable() {
        val ms = TelemetryCollector.measureTcpPing("192.0.2.1:1", timeoutMs = 500)
        assertEquals(0.0, ms, 0.01)
    }

    @Test
    fun testTcpPingInvalidAddr() {
        val ms = TelemetryCollector.measureTcpPing("invalid", timeoutMs = 500)
        assertEquals(0.0, ms, 0.01)
    }

    @Test
    fun testNetworkTypeWithoutContext() {
        val tc = createCollector()
        val report = tc.collectNow()
        assertEquals("unknown", report.getString("network_type"))
    }

    @Test
    fun testBatteryWithoutContext() {
        val tc = createCollector()
        val report = tc.collectNow()
        assertEquals(0, report.getInt("battery_percent"))
    }

    @Test
    fun testSendFailure() {
        val tc = createCollector(serverUrl = "http://127.0.0.1:1")
        assertFalse(tc.sendNow())
    }

    @Test
    fun testStartStop() {
        val tc = createCollector()
        tc.start()
        // Should not crash.
        Thread.sleep(50)
        tc.stop()
    }
}
