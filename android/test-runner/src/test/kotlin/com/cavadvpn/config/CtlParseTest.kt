package com.cavadvpn.config

import org.junit.Assert.*
import org.junit.Test
import java.net.InetAddress

/**
 * Tests for CTL_ASSIGN and CTL_ASSIGN_DUAL wire-format parsing.
 *
 * These tests verify the byte-level parsing that VpnClient.doControlStream
 * performs when reading the server's IP assignment response.  The parsing
 * helpers are reproduced here (without Android dependencies) to allow them
 * to run in the Maven test-runner on any JVM.
 *
 * Wire format (server/main.go):
 *   CTL_ASSIGN (0x02):     1 + 9  = 10 bytes total
 *     payload: ip4(4) + pfxLen4(1) + gw4(4)
 *
 *   CTL_ASSIGN_DUAL (0x05): 1 + 42 = 43 bytes total
 *     payload: ip4(4) + pfxLen4(1) + gw4(4) + ip6(16) + pfxLen6(1) + gw6(16)
 */
class CtlParseTest {

    // ── Helpers (mirrors of VpnClient companion object methods) ──────────────

    private fun formatIPv4(buf: ByteArray, offset: Int): String =
        "%d.%d.%d.%d".format(
            buf[offset].toInt()     and 0xFF,
            buf[offset + 1].toInt() and 0xFF,
            buf[offset + 2].toInt() and 0xFF,
            buf[offset + 3].toInt() and 0xFF
        )

    private fun formatIPv6(bytes: ByteArray): String {
        require(bytes.size == 16) { "IPv6 address must be 16 bytes, got ${bytes.size}" }
        return InetAddress.getByAddress(bytes).hostAddress
            ?: throw IllegalArgumentException("invalid IPv6 bytes")
    }

    private fun parseCtlAssign(payload: ByteArray): RouteInfo {
        require(payload.size == 9)
        return RouteInfo(
            assignedIp = formatIPv4(payload, 0),
            prefixLen  = payload[4].toInt() and 0xFF,
            gateway    = formatIPv4(payload, 5)
        )
    }

    private fun parseCtlAssignDual(payload: ByteArray): RouteInfo {
        require(payload.size == 42)
        return RouteInfo(
            assignedIp  = formatIPv4(payload, 0),
            prefixLen   = payload[4].toInt() and 0xFF,
            gateway     = formatIPv4(payload, 5),
            assignedIp6 = formatIPv6(payload.copyOfRange(9, 25)),
            prefixLen6  = payload[25].toInt() and 0xFF,
            gateway6    = formatIPv6(payload.copyOfRange(26, 42))
        )
    }

    // ── Helpers to build test payloads ────────────────────────────────────────

    private fun ipv4Bytes(vararg octets: Int): ByteArray =
        ByteArray(4) { octets[it].toByte() }

    /** Build a 9-byte CTL_ASSIGN payload. */
    private fun buildCtlAssignPayload(
        ip: IntArray, pfxLen: Int, gw: IntArray
    ): ByteArray = ByteArray(9).also { buf ->
        ip.forEachIndexed { i, b -> buf[i] = b.toByte() }
        buf[4] = pfxLen.toByte()
        gw.forEachIndexed { i, b -> buf[5 + i] = b.toByte() }
    }

    /** Build a 42-byte CTL_ASSIGN_DUAL payload. */
    private fun buildCtlAssignDualPayload(
        ip4: IntArray, pfxLen4: Int, gw4: IntArray,
        ip6: ByteArray, pfxLen6: Int, gw6: ByteArray
    ): ByteArray = ByteArray(42).also { buf ->
        ip4.forEachIndexed { i, b -> buf[i] = b.toByte() }
        buf[4] = pfxLen4.toByte()
        gw4.forEachIndexed { i, b -> buf[5 + i] = b.toByte() }
        ip6.copyInto(buf, destinationOffset = 9)
        buf[25] = pfxLen6.toByte()
        gw6.copyInto(buf, destinationOffset = 26)
    }

    // ── CTL_ASSIGN tests ──────────────────────────────────────────────────────

    @Test
    fun `parseCtlAssign returns correct ipv4 address`() {
        val payload = buildCtlAssignPayload(intArrayOf(10, 8, 0, 2), 24, intArrayOf(10, 8, 0, 1))
        val ri = parseCtlAssign(payload)
        assertEquals("10.8.0.2", ri.assignedIp)
    }

    @Test
    fun `parseCtlAssign returns correct prefix length`() {
        val payload = buildCtlAssignPayload(intArrayOf(10, 8, 0, 2), 24, intArrayOf(10, 8, 0, 1))
        val ri = parseCtlAssign(payload)
        assertEquals(24, ri.prefixLen)
    }

    @Test
    fun `parseCtlAssign returns correct gateway`() {
        val payload = buildCtlAssignPayload(intArrayOf(10, 8, 0, 2), 24, intArrayOf(10, 8, 0, 1))
        val ri = parseCtlAssign(payload)
        assertEquals("10.8.0.1", ri.gateway)
    }

    @Test
    fun `parseCtlAssign produces ipv4-only RouteInfo`() {
        val payload = buildCtlAssignPayload(intArrayOf(10, 8, 0, 5), 24, intArrayOf(10, 8, 0, 1))
        val ri = parseCtlAssign(payload)
        assertFalse(ri.isDualStack)
        assertNull(ri.assignedIp6)
        assertNull(ri.prefixLen6)
        assertNull(ri.gateway6)
    }

    @Test
    fun `parseCtlAssign handles high-octet addresses`() {
        // 192.168.100.200/16, gw=192.168.0.1
        val payload = buildCtlAssignPayload(
            intArrayOf(192, 168, 100, 200), 16, intArrayOf(192, 168, 0, 1))
        val ri = parseCtlAssign(payload)
        assertEquals("192.168.100.200", ri.assignedIp)
        assertEquals(16, ri.prefixLen)
        assertEquals("192.168.0.1", ri.gateway)
    }

    // ── CTL_ASSIGN_DUAL tests ─────────────────────────────────────────────────

    private val ip6Bytes  = ByteArray(16).apply { this[0] = 0xfc.toByte(); this[15] = 0x02 } // fc00::2
    private val gw6Bytes  = ByteArray(16).apply { this[0] = 0xfc.toByte(); this[15] = 0x01 } // fc00::1

    @Test
    fun `parseCtlAssignDual returns correct ipv4 fields`() {
        val payload = buildCtlAssignDualPayload(
            intArrayOf(10, 8, 0, 2), 24, intArrayOf(10, 8, 0, 1),
            ip6Bytes, 120, gw6Bytes
        )
        val ri = parseCtlAssignDual(payload)
        assertEquals("10.8.0.2", ri.assignedIp)
        assertEquals(24, ri.prefixLen)
        assertEquals("10.8.0.1", ri.gateway)
    }

    @Test
    fun `parseCtlAssignDual produces dual-stack RouteInfo`() {
        val payload = buildCtlAssignDualPayload(
            intArrayOf(10, 8, 0, 2), 24, intArrayOf(10, 8, 0, 1),
            ip6Bytes, 120, gw6Bytes
        )
        val ri = parseCtlAssignDual(payload)
        assertTrue(ri.isDualStack)
        assertNotNull(ri.assignedIp6)
        assertNotNull(ri.prefixLen6)
        assertNotNull(ri.gateway6)
    }

    @Test
    fun `parseCtlAssignDual returns correct ipv6 prefix length`() {
        val payload = buildCtlAssignDualPayload(
            intArrayOf(10, 8, 0, 2), 24, intArrayOf(10, 8, 0, 1),
            ip6Bytes, 120, gw6Bytes
        )
        val ri = parseCtlAssignDual(payload)
        assertEquals(120, ri.prefixLen6)
    }

    @Test
    fun `parseCtlAssignDual ipv6 address contains expected prefix`() {
        val payload = buildCtlAssignDualPayload(
            intArrayOf(10, 8, 0, 2), 24, intArrayOf(10, 8, 0, 1),
            ip6Bytes, 120, gw6Bytes
        )
        val ri = parseCtlAssignDual(payload)
        // fc00::/7 ULA prefix — address must start with "fc"
        assertTrue(
            "Expected IPv6 starting with 'fc', got: ${ri.assignedIp6}",
            ri.assignedIp6!!.startsWith("fc")
        )
    }

    @Test
    fun `parseCtlAssignDual ipv6 gateway contains expected prefix`() {
        val payload = buildCtlAssignDualPayload(
            intArrayOf(10, 8, 0, 2), 24, intArrayOf(10, 8, 0, 1),
            ip6Bytes, 120, gw6Bytes
        )
        val ri = parseCtlAssignDual(payload)
        assertTrue(
            "Expected IPv6 gateway starting with 'fc', got: ${ri.gateway6}",
            ri.gateway6!!.startsWith("fc")
        )
    }

    // ── formatIPv4 unit tests ─────────────────────────────────────────────────

    @Test
    fun `formatIPv4 handles all-zero address`() {
        val buf = ByteArray(4) { 0 }
        assertEquals("0.0.0.0", formatIPv4(buf, 0))
    }

    @Test
    fun `formatIPv4 handles all-255 address`() {
        val buf = ByteArray(4) { 0xFF.toByte() }
        assertEquals("255.255.255.255", formatIPv4(buf, 0))
    }

    @Test
    fun `formatIPv4 handles offset within larger buffer`() {
        // buf = [0, 0, 10, 8, 0, 2, 0] — offset 2
        val buf = byteArrayOf(0, 0, 10, 8, 0, 2, 0)
        assertEquals("10.8.0.2", formatIPv4(buf, 2))
    }

    // ── formatIPv6 unit tests ─────────────────────────────────────────────────

    @Test
    fun `formatIPv6 handles loopback address`() {
        val loopback = ByteArray(16).apply { this[15] = 1 } // ::1
        val result = formatIPv6(loopback)
        assertEquals("0:0:0:0:0:0:0:1", result)
    }

    @Test
    fun `formatIPv6 handles all-zero address`() {
        val allZero = ByteArray(16) { 0 } // ::
        // JVM InetAddress renders :: as "0:0:0:0:0:0:0:0"
        val result = formatIPv6(allZero)
        assertTrue("Expected all-zero IPv6, got: $result",
            result.contains("0"))
    }

    @Test
    fun `formatIPv6 rejects wrong size`() {
        try {
            formatIPv6(ByteArray(4))
            fail("Expected exception for 4-byte input")
        } catch (_: Exception) { /* expected */ }
    }
}
