package com.cavadvpn.vpn

import org.junit.Assert.*
import org.junit.Test

class VpnStatsTest {

    // -----------------------------------------------------------------------
    // formatBytes
    // -----------------------------------------------------------------------

    @Test
    fun `formatBytes zero returns 0 B`() {
        assertEquals("0 B", formatBytes(0L))
    }

    @Test
    fun `formatBytes 500 returns 500 B`() {
        assertEquals("500 B", formatBytes(500L))
    }

    @Test
    fun `formatBytes 1023 returns bytes`() {
        assertEquals("1023 B", formatBytes(1023L))
    }

    @Test
    fun `formatBytes 1024 returns 1_0 KB`() {
        assertEquals("1.0 KB", formatBytes(1024L))
    }

    @Test
    fun `formatBytes 1500 returns 1_5 KB`() {
        assertEquals("1.5 KB", formatBytes(1500L))
    }

    @Test
    fun `formatBytes 1 MB returns 1_0 MB`() {
        assertEquals("1.0 MB", formatBytes(1_048_576L))
    }

    @Test
    fun `formatBytes 1 GB returns 1_0 GB`() {
        assertEquals("1.0 GB", formatBytes(1_073_741_824L))
    }

    // -----------------------------------------------------------------------
    // VpnStats.formatUptime
    // -----------------------------------------------------------------------

    @Test
    fun `formatUptime zero connectedSince returns 00_00_00`() {
        val stats = VpnStats(0L, 0L, 0L, "")
        assertEquals("00:00:00", stats.formatUptime())
    }

    @Test
    fun `formatUptime connectedSince in past is correct`() {
        val now = System.currentTimeMillis()
        val stats = VpnStats(0L, 0L, now - 65_000L, "")
        // uptime should be ~65 seconds = 00:01:05
        val formatted = stats.formatUptime()
        // Allow ±2 seconds of timing slack
        assertTrue(
            "Expected ~00:01:05, got $formatted",
            formatted in listOf("00:01:03", "00:01:04", "00:01:05", "00:01:06", "00:01:07")
        )
    }

    @Test
    fun `formatUptime 1 hour 1 minute 1 second`() {
        val now = System.currentTimeMillis()
        val elapsed = (3661L * 1000L)
        val stats = VpnStats(0L, 0L, now - elapsed, "")
        val formatted = stats.formatUptime()
        assertTrue("Expected ~01:01:01, got $formatted",
            formatted.startsWith("01:01:0"))
    }

    // -----------------------------------------------------------------------
    // VpnStats.EMPTY
    // -----------------------------------------------------------------------

    @Test
    fun `EMPTY has all zeros`() {
        val e = VpnStats.EMPTY
        assertEquals(0L, e.bytesIn)
        assertEquals(0L, e.bytesOut)
        assertEquals(0L, e.connectedSinceMs)
        assertEquals("", e.assignedIp)
    }

    @Test
    fun `EMPTY uptimeMs is 0`() {
        assertEquals(0L, VpnStats.EMPTY.uptimeMs)
    }
}
