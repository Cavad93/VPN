package com.cavadvpn.config

import org.junit.Assert.*
import org.junit.Test

/**
 * Tests for RouteInfo — focusing on the IPv6 fields added in the
 * CTL_ASSIGN_DUAL session (android client dual-stack support).
 */
class RouteInfoTest {

    // ── IPv4-only (CTL_ASSIGN) ────────────────────────────────────────────────

    @Test
    fun `ipv4-only RouteInfo has correct cidr`() {
        val ri = RouteInfo("10.8.0.2", 24, "10.8.0.1")
        assertEquals("10.8.0.2/24", ri.cidr)
    }

    @Test
    fun `ipv4-only RouteInfo has correct network`() {
        val ri = RouteInfo("10.8.0.2", 24, "10.8.0.1")
        assertEquals("10.8.0.0", ri.network)
    }

    @Test
    fun `ipv4-only RouteInfo isDualStack is false`() {
        val ri = RouteInfo("10.8.0.2", 24, "10.8.0.1")
        assertFalse(ri.isDualStack)
    }

    @Test
    fun `ipv4-only RouteInfo has null ipv6 fields`() {
        val ri = RouteInfo("10.8.0.2", 24, "10.8.0.1")
        assertNull(ri.assignedIp6)
        assertNull(ri.prefixLen6)
        assertNull(ri.gateway6)
    }

    // ── Dual-stack (CTL_ASSIGN_DUAL) ─────────────────────────────────────────

    @Test
    fun `dual-stack RouteInfo isDualStack is true`() {
        val ri = RouteInfo("10.8.0.2", 24, "10.8.0.1",
            assignedIp6 = "fc00::2", prefixLen6 = 120, gateway6 = "fc00::1")
        assertTrue(ri.isDualStack)
    }

    @Test
    fun `dual-stack RouteInfo preserves ipv4 cidr`() {
        val ri = RouteInfo("10.8.0.2", 24, "10.8.0.1",
            assignedIp6 = "fc00::2", prefixLen6 = 120, gateway6 = "fc00::1")
        assertEquals("10.8.0.2/24", ri.cidr)
    }

    @Test
    fun `dual-stack RouteInfo preserves ipv4 network`() {
        val ri = RouteInfo("10.8.0.2", 24, "10.8.0.1",
            assignedIp6 = "fc00::2", prefixLen6 = 120, gateway6 = "fc00::1")
        assertEquals("10.8.0.0", ri.network)
    }

    @Test
    fun `dual-stack RouteInfo exposes ipv6 fields`() {
        val ri = RouteInfo("10.8.0.2", 24, "10.8.0.1",
            assignedIp6 = "fc00::2", prefixLen6 = 120, gateway6 = "fc00::1")
        assertEquals("fc00::2", ri.assignedIp6)
        assertEquals(120, ri.prefixLen6)
        assertEquals("fc00::1", ri.gateway6)
    }

    @Test
    fun `dual-stack RouteInfo equality includes ipv6 fields`() {
        val a = RouteInfo("10.8.0.2", 24, "10.8.0.1", "fc00::2", 120, "fc00::1")
        val b = RouteInfo("10.8.0.2", 24, "10.8.0.1", "fc00::2", 120, "fc00::1")
        assertEquals(a, b)
    }

    @Test
    fun `RouteInfo ipv4-only differs from dual-stack despite same ipv4`() {
        val v4only = RouteInfo("10.8.0.2", 24, "10.8.0.1")
        val dual   = RouteInfo("10.8.0.2", 24, "10.8.0.1", "fc00::2", 120, "fc00::1")
        assertNotEquals(v4only, dual)
    }

    // ── Network calculation edge cases ────────────────────────────────────────

    @Test
    fun `network for slash-32 is same as assigned ip`() {
        val ri = RouteInfo("192.168.1.1", 32, "192.168.1.1")
        assertEquals("192.168.1.1", ri.network)
    }

    @Test
    fun `network for slash-0 is 0-0-0-0`() {
        val ri = RouteInfo("10.8.0.2", 0, "0.0.0.0")
        assertEquals("0.0.0.0", ri.network)
    }
}
