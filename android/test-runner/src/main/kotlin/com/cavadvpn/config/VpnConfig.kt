package com.cavadvpn.config

/**
 * Configuration for a CavadVPN connection.
 *
 * @property serverHost      VPN server hostname or IP address
 * @property serverPort      VPN server port (default 443)
 * @property privateKeyHex   hex-encoded 32-byte X25519 private key for this client
 * @property serverPublicKeyHex optional hex-encoded 32-byte server public key to pin;
 *                           if empty the server key is accepted on first use
 * @property dnsServer       DNS server to push to the TUN interface
 * @property mtu             MTU for the virtual network interface
 * @property connectTimeoutMs TCP connect timeout in milliseconds
 * @property readTimeoutMs   socket read timeout in milliseconds
 */
data class VpnConfig(
    val serverHost: String,
    val serverPort: Int = 443,
    val privateKeyHex: String = "",
    val serverPublicKeyHex: String = "",
    val dnsServer: String = "8.8.8.8",
    val mtu: Int = 1400,
    val connectTimeoutMs: Int = 15_000,
    val readTimeoutMs: Int = 60_000
) {
    /** Decodes [privateKeyHex] to raw bytes. Returns null if empty (key will be generated). */
    fun privateKeyBytes(): ByteArray? {
        if (privateKeyHex.isBlank()) return null
        require(privateKeyHex.length == 64) {
            "privateKeyHex must be 64 hex characters, got ${privateKeyHex.length}"
        }
        return hexToBytes(privateKeyHex)
    }

    /** Decodes [serverPublicKeyHex] to raw bytes. Returns null if empty (no pinning). */
    fun serverPublicKeyBytes(): ByteArray? {
        if (serverPublicKeyHex.isBlank()) return null
        require(serverPublicKeyHex.length == 64) {
            "serverPublicKeyHex must be 64 hex characters, got ${serverPublicKeyHex.length}"
        }
        return hexToBytes(serverPublicKeyHex)
    }

    private fun hexToBytes(hex: String): ByteArray {
        check(hex.length % 2 == 0) { "odd hex string length" }
        return ByteArray(hex.length / 2) { i ->
            hex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
    }
}

/** IP routing information assigned by the VPN server. */
data class RouteInfo(
    val assignedIp: String,        // e.g. "10.8.0.2"
    val prefixLen: Int,            // e.g. 24
    val gateway: String,           // e.g. "10.8.0.1"
    val assignedIp6: String? = null,  // e.g. "fc00::2" — null for IPv4-only servers
    val prefixLen6: Int?    = null,   // e.g. 120 — null for IPv4-only servers
    val gateway6: String?   = null    // e.g. "fc00::1" — null for IPv4-only servers
) {
    /** CIDR notation for the assigned IPv4 address, e.g. "10.8.0.2/24". */
    val cidr: String get() = "$assignedIp/$prefixLen"

    /** True if the server assigned both IPv4 and IPv6 addresses (CTL_ASSIGN_DUAL). */
    val isDualStack: Boolean get() = assignedIp6 != null

    /** Network address for the IPv4 CIDR, e.g. "10.8.0.0". */
    val network: String get() {
        val parts = assignedIp.split(".").map { it.toInt() }
        val mask = if (prefixLen == 0) 0 else (-1 shl (32 - prefixLen))
        val ip = (parts[0] shl 24) or (parts[1] shl 16) or (parts[2] shl 8) or parts[3]
        val net = ip and mask
        return "%d.%d.%d.%d".format(net shr 24 and 0xFF, net shr 16 and 0xFF, net shr 8 and 0xFF, net and 0xFF)
    }
}
