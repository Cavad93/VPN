package com.cavadvpn.vpn

import com.cavadvpn.config.RouteInfo
import com.cavadvpn.config.VpnConfig
import com.cavadvpn.crypto.KeyPair
import com.cavadvpn.crypto.NoiseHandshake
import com.cavadvpn.crypto.generateKeyPair
import com.cavadvpn.transport.ClientMux
import com.cavadvpn.transport.MuxStream
import com.cavadvpn.transport.NoiseConn
import com.cavadvpn.transport.ObfsConn
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer

// Control stream message types (must match Go server main.go)
private const val CTL_HELLO             : Byte = 0x01
private const val CTL_ASSIGN            : Byte = 0x02  // IPv4-only assignment (10 bytes total)
private const val CTL_ASSIGN_DUAL       : Byte = 0x05  // IPv4+IPv6 dual-stack (43 bytes total)
private const val CTL_ERROR             : Byte = 0xFF.toByte()
private const val CTL_ASSIGN_PAYLOAD_LEN      = 9   // ip4(4) + pfxLen4(1) + gw4(4)
// Wire format CTL_ASSIGN_DUAL payload after type byte:
//   ip4(4) + pfxLen4(1) + gw4(4) + ip6(16) + pfxLen6(1) + gw6(16) = 42 bytes
private const val CTL_ASSIGN_DUAL_PAYLOAD_LEN = 42

/**
 * Manages a full VPN connection to the CavadVPN server.
 *
 * Connection sequence:
 *   TCP → TLS obfuscation (ObfsConn) → Noise_XX handshake → NoiseConn → ClientMux
 *   → control stream (IP assignment) → data stream (raw IP packets)
 */
class VpnClient(private val config: VpnConfig) {
    private var socket: Socket? = null
    private var obfs: ObfsConn? = null
    private var noiseConn: NoiseConn? = null
    private var mux: ClientMux? = null
    private var dataStream: MuxStream? = null

    @Volatile var isConnected: Boolean = false
        private set

    /** Exposes the underlying socket so [CavadVpnService] can call protect() on it. */
    fun protectSocket(service: android.net.VpnService) {
        socket?.let { service.protect(it) }
    }

    /** The route info assigned by the server after [connect]. */
    var routeInfo: RouteInfo? = null
        private set

    /** The server's verified public key after [connect]. */
    var serverPublicKey: ByteArray? = null
        private set

    /**
     * Performs the full connection sequence.
     * @return [RouteInfo] with the assigned IP, prefix length, and gateway
     * @throws Exception on any connection or handshake failure
     */
    fun connect(): RouteInfo {
        val kp = loadOrGenerateKeyPair()

        // 1. TCP connect with socket tuning.
        val sock = Socket()
        sock.connect(InetSocketAddress(config.serverHost, config.serverPort), config.connectTimeoutMs)
        // TCP_NODELAY: VPN forwards inner TCP ACKs as small frames; Nagle would
        // buffer them for up to one RTT (~80-120 ms), killing download throughput.
        sock.tcpNoDelay = true
        // 4 MB send/receive buffers: BDP for 30 Mbps × 100 ms ≈ 375 KB.
        sock.sendBufferSize    = 4 * 1024 * 1024
        sock.receiveBufferSize = 4 * 1024 * 1024
        sock.soTimeout = config.readTimeoutMs
        socket = sock

        // 2. TLS obfuscation (with optional port-knock HMAC in session_id)
        val obfsConn = ObfsConn(sock.getInputStream(), sock.getOutputStream(), config.knockKeyBytes())
        obfsConn.clientHandshake()
        obfs = obfsConn

        // 3. Noise_XX handshake
        val session = performNoiseHandshake(kp, obfsConn)
        serverPublicKey = session.remoteStatic.copyOf()

        // Optionally verify pinned server key
        config.serverPublicKeyBytes()?.let { pinned ->
            if (!pinned.contentEquals(session.remoteStatic)) {
                disconnect()
                throw SecurityException("server public key does not match pinned key")
            }
        }

        // 4. NoiseConn (encrypted transport)
        val nc = NoiseConn(obfsConn, session)
        noiseConn = nc

        // 5. ClientMux
        val muxConn = ClientMux(nc)
        mux = muxConn

        // 6. Control stream: request IP assignment
        val route = doControlStream(muxConn)
        routeInfo = route

        // 7. Open data stream for IP packets
        dataStream = muxConn.openStream()
        isConnected = true

        return route
    }

    /**
     * Sends a raw IPv4 packet over the data stream.
     */
    fun sendPacket(packet: ByteArray) {
        checkNotNull(dataStream) { "not connected" }
        dataStream!!.write(packet)
    }

    /**
     * Sends [len] bytes from [buf] starting at offset 0 — avoids copying a partially-filled
     * TUN read buffer.
     */
    fun sendPacket(buf: ByteArray, len: Int) {
        checkNotNull(dataStream) { "not connected" }
        dataStream!!.write(buf, 0, len)
    }

    /**
     * Receives a raw IPv4 packet from the data stream.
     * Blocks until a packet arrives, the stream closes, or the read times out.
     * Returns an empty array on timeout or stream close so the caller can
     * decide whether to retry or shut down.
     */
    fun recvPacket(): ByteArray {
        checkNotNull(dataStream) { "not connected" }
        return dataStream!!.read(30_000L) // 30s timeout — long enough for idle connections
    }

    /**
     * Opens an additional data stream (for concurrent traffic forwarding).
     */
    fun openDataStream(): MuxStream {
        return checkNotNull(mux) { "not connected" }.openStream()
    }

    /** Closes all layers gracefully. */
    fun disconnect() {
        isConnected = false
        try { dataStream?.close() } catch (_: Exception) {}
        try { mux?.close() }        catch (_: Exception) {}
        try { socket?.close() }     catch (_: Exception) {}
        dataStream = null
        mux = null
        noiseConn = null
        obfs = null
        socket = null
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    private fun loadOrGenerateKeyPair(): KeyPair {
        val keyBytes = config.privateKeyBytes()
        return if (keyBytes != null) {
            // Reconstruct key pair from stored private key bytes
            // We re-derive the public key from the private key via BouncyCastle
            val priv = org.bouncycastle.crypto.params.X25519PrivateKeyParameters(keyBytes)
            val pub = priv.generatePublicKey()
            KeyPair(keyBytes, pub.encoded.copyOf(32))
        } else {
            generateKeyPair()
        }
    }

    private fun performNoiseHandshake(
        kp: KeyPair,
        obfsConn: ObfsConn
    ): com.cavadvpn.crypto.NoiseSession {
        val hs = NoiseHandshake(kp)

        // -> e (32 bytes), sent with 2-byte BE length prefix
        val msg1 = hs.writeMessage1()
        sendHandshakeMsg(obfsConn, msg1)

        // <- e, ee, s, es (80 bytes)
        val msg2 = recvHandshakeMsg(obfsConn)
        hs.readMessage2(msg2)

        // -> s, se (48 bytes)
        val (msg3, session) = hs.writeMessage3()
        sendHandshakeMsg(obfsConn, msg3)

        return session
    }

    private fun sendHandshakeMsg(obfs: ObfsConn, msg: ByteArray) {
        val prefix = ByteArray(2)
        prefix[0] = (msg.size shr 8).toByte()
        prefix[1] =  msg.size.toByte()
        obfs.write(prefix + msg)
    }

    private fun recvHandshakeMsg(obfs: ObfsConn): ByteArray {
        val lenBytes = obfs.read(2)
        val length = ((lenBytes[0].toInt() and 0xFF) shl 8) or (lenBytes[1].toInt() and 0xFF)
        return obfs.read(length)
    }

    private fun doControlStream(muxConn: ClientMux): RouteInfo {
        val ctl = muxConn.openStream()
        try {
            ctl.write(byteArrayOf(CTL_HELLO))

            // Read the type byte first, then read the appropriate payload length.
            val typeBuf = ctl.readExactly(1)
            return when (typeBuf[0]) {
                CTL_ASSIGN -> {
                    val payload = ctl.readExactly(CTL_ASSIGN_PAYLOAD_LEN)
                    parseCtlAssign(payload)
                }
                CTL_ASSIGN_DUAL -> {
                    val payload = ctl.readExactly(CTL_ASSIGN_DUAL_PAYLOAD_LEN)
                    parseCtlAssignDual(payload)
                }
                CTL_ERROR -> throw IllegalStateException("server returned CTL_ERROR")
                else -> throw IllegalStateException(
                    "unexpected control response 0x%02x".format(typeBuf[0].toInt() and 0xFF)
                )
            }
        } finally {
            ctl.close()
        }
    }

    companion object {
        /** Parse a CTL_ASSIGN payload (9 bytes): ip4(4) + pfxLen4(1) + gw4(4). */
        internal fun parseCtlAssign(payload: ByteArray): RouteInfo {
            require(payload.size == CTL_ASSIGN_PAYLOAD_LEN) {
                "CTL_ASSIGN payload must be $CTL_ASSIGN_PAYLOAD_LEN bytes, got ${payload.size}"
            }
            val ip = formatIPv4(payload, 0)
            val pfxLen = payload[4].toInt() and 0xFF
            val gateway = formatIPv4(payload, 5)
            return RouteInfo(ip, pfxLen, gateway)
        }

        /**
         * Parse a CTL_ASSIGN_DUAL payload (42 bytes):
         *   ip4(4) + pfxLen4(1) + gw4(4) + ip6(16) + pfxLen6(1) + gw6(16)
         *
         * Returns a dual-stack RouteInfo with both IPv4 and IPv6 fields populated.
         */
        internal fun parseCtlAssignDual(payload: ByteArray): RouteInfo {
            require(payload.size == CTL_ASSIGN_DUAL_PAYLOAD_LEN) {
                "CTL_ASSIGN_DUAL payload must be $CTL_ASSIGN_DUAL_PAYLOAD_LEN bytes, got ${payload.size}"
            }
            val ip4     = formatIPv4(payload, 0)
            val pfxLen4 = payload[4].toInt() and 0xFF
            val gw4     = formatIPv4(payload, 5)
            val ip6     = formatIPv6(payload.copyOfRange(9, 25))
            val pfxLen6 = payload[25].toInt() and 0xFF
            val gw6     = formatIPv6(payload.copyOfRange(26, 42))
            return RouteInfo(ip4, pfxLen4, gw4, ip6, pfxLen6, gw6)
        }

        /** Format 4 bytes starting at [offset] as dotted-decimal IPv4. */
        internal fun formatIPv4(buf: ByteArray, offset: Int): String =
            "%d.%d.%d.%d".format(
                buf[offset].toInt()     and 0xFF,
                buf[offset + 1].toInt() and 0xFF,
                buf[offset + 2].toInt() and 0xFF,
                buf[offset + 3].toInt() and 0xFF
            )

        /**
         * Format a 16-byte big-endian IPv6 address using standard RFC 5952 notation
         * (e.g. "fc00::1" rather than "fc00:0:0:0:0:0:0:1").
         *
         * Uses InetAddress.getByAddress so the JVM handles :: compression correctly.
         */
        internal fun formatIPv6(bytes: ByteArray): String {
            require(bytes.size == 16) { "IPv6 address must be 16 bytes" }
            return InetAddress.getByAddress(bytes).hostAddress ?: throw IllegalArgumentException("invalid IPv6 bytes")
        }
    }
}
