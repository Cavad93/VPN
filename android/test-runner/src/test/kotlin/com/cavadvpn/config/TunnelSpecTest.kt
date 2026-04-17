package com.cavadvpn.config

import org.junit.Assert.*
import org.junit.Test

/**
 * Tests for [buildTunnelSpec] — the pure function that derives TUN builder
 * parameters from RouteInfo + VpnConfig.  No Android runtime required.
 */
class TunnelSpecTest {

    private val defaultConfig = VpnConfig(
        serverHost = "1.2.3.4",
        dnsServer  = "8.8.8.8",
        mtu        = 1400
    )

    // ── IPv4-only server (CTL_ASSIGN) ────────────────────────────────────────

    @Test
    fun `ipv4-only spec has correct ipv4 address`() {
        val route = RouteInfo("10.8.0.2", 24, "10.8.0.1")
        val spec = buildTunnelSpec(route, defaultConfig)
        assertEquals("10.8.0.2", spec.ipv4Address)
    }

    @Test
    fun `ipv4-only spec has correct ipv4 prefix length`() {
        val route = RouteInfo("10.8.0.2", 24, "10.8.0.1")
        val spec = buildTunnelSpec(route, defaultConfig)
        assertEquals(24, spec.ipv4PrefixLen)
    }

    @Test
    fun `ipv4-only spec has null ipv6 address`() {
        val route = RouteInfo("10.8.0.2", 24, "10.8.0.1")
        val spec = buildTunnelSpec(route, defaultConfig)
        assertNull(spec.ipv6Address)
    }

    @Test
    fun `ipv4-only spec has null ipv6 prefix length`() {
        val route = RouteInfo("10.8.0.2", 24, "10.8.0.1")
        val spec = buildTunnelSpec(route, defaultConfig)
        assertNull(spec.ipv6PrefixLen)
    }

    @Test
    fun `ipv4-only spec does not route ipv6`() {
        val route = RouteInfo("10.8.0.2", 24, "10.8.0.1")
        val spec = buildTunnelSpec(route, defaultConfig)
        assertFalse(spec.routeAllIpv6)
    }

    @Test
    fun `ipv4-only spec carries dns server from config`() {
        val route = RouteInfo("10.8.0.2", 24, "10.8.0.1")
        val spec = buildTunnelSpec(route, defaultConfig)
        assertEquals("8.8.8.8", spec.dnsServer)
    }

    @Test
    fun `ipv4-only spec carries mtu from config`() {
        val route = RouteInfo("10.8.0.2", 24, "10.8.0.1")
        val spec = buildTunnelSpec(route, defaultConfig)
        assertEquals(1400, spec.mtu)
    }

    // ── Dual-stack server (CTL_ASSIGN_DUAL) ──────────────────────────────────

    @Test
    fun `dual-stack spec has correct ipv6 address`() {
        val route = RouteInfo("10.8.0.2", 24, "10.8.0.1",
            assignedIp6 = "fc00::2", prefixLen6 = 120, gateway6 = "fc00::1")
        val spec = buildTunnelSpec(route, defaultConfig)
        assertEquals("fc00::2", spec.ipv6Address)
    }

    @Test
    fun `dual-stack spec has correct ipv6 prefix length`() {
        val route = RouteInfo("10.8.0.2", 24, "10.8.0.1",
            assignedIp6 = "fc00::2", prefixLen6 = 120, gateway6 = "fc00::1")
        val spec = buildTunnelSpec(route, defaultConfig)
        assertEquals(120, spec.ipv6PrefixLen)
    }

    @Test
    fun `dual-stack spec enables ipv6 default route`() {
        val route = RouteInfo("10.8.0.2", 24, "10.8.0.1",
            assignedIp6 = "fc00::2", prefixLen6 = 120, gateway6 = "fc00::1")
        val spec = buildTunnelSpec(route, defaultConfig)
        assertTrue(spec.routeAllIpv6)
    }

    @Test
    fun `dual-stack spec preserves ipv4 address`() {
        val route = RouteInfo("10.8.0.2", 24, "10.8.0.1",
            assignedIp6 = "fc00::2", prefixLen6 = 120, gateway6 = "fc00::1")
        val spec = buildTunnelSpec(route, defaultConfig)
        assertEquals("10.8.0.2", spec.ipv4Address)
        assertEquals(24, spec.ipv4PrefixLen)
    }

    @Test
    fun `dual-stack spec carries dns server from config`() {
        val route = RouteInfo("10.8.0.2", 24, "10.8.0.1",
            assignedIp6 = "fc00::2", prefixLen6 = 120, gateway6 = "fc00::1")
        val cfg = defaultConfig.copy(dnsServer = "1.1.1.1")
        val spec = buildTunnelSpec(route, cfg)
        assertEquals("1.1.1.1", spec.dnsServer)
    }

    @Test
    fun `dual-stack spec carries mtu from config`() {
        val route = RouteInfo("10.8.0.2", 24, "10.8.0.1",
            assignedIp6 = "fc00::2", prefixLen6 = 120, gateway6 = "fc00::1")
        val cfg = defaultConfig.copy(mtu = 1350)
        val spec = buildTunnelSpec(route, cfg)
        assertEquals(1350, spec.mtu)
    }

    // ── Various IPv6 prefix lengths ──────────────────────────────────────────

    @Test
    fun `dual-stack spec handles slash-64 prefix`() {
        val route = RouteInfo("10.8.0.2", 24, "10.8.0.1",
            assignedIp6 = "fd00::2", prefixLen6 = 64, gateway6 = "fd00::1")
        val spec = buildTunnelSpec(route, defaultConfig)
        assertEquals(64, spec.ipv6PrefixLen)
    }

    @Test
    fun `dual-stack spec handles slash-126 prefix`() {
        val route = RouteInfo("10.8.0.2", 24, "10.8.0.1",
            assignedIp6 = "fd12::2", prefixLen6 = 126, gateway6 = "fd12::1")
        val spec = buildTunnelSpec(route, defaultConfig)
        assertEquals(126, spec.ipv6PrefixLen)
    }
}
