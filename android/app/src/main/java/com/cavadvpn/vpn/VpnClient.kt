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
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer

// Control stream message types (must match Go server)
private const val CTL_HELLO  : Byte = 0x01
private const val CTL_ASSIGN : Byte = 0x02
private const val CTL_ERROR  : Byte = 0x03
private const val CTL_ASSIGN_PAYLOAD_LEN = 9  // ip(4) + prefixLen(1) + gateway(4)

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

        // 2. TLS obfuscation
        val obfsConn = ObfsConn(sock.getInputStream(), sock.getOutputStream())
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
     * Receives a raw IPv4 packet from the data stream.
     * Blocks until a packet arrives or the stream closes.
     */
    fun recvPacket(): ByteArray {
        checkNotNull(dataStream) { "not connected" }
        return dataStream!!.read()
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
            // Send ctlHello
            ctl.write(byteArrayOf(CTL_HELLO))

            // Receive ctlAssign: [0x02, ip(4), prefixLen(1), gateway(4)] = 10 bytes
            val resp = ctl.readExactly(1 + CTL_ASSIGN_PAYLOAD_LEN)
            when (resp[0]) {
                CTL_ERROR  -> throw IllegalStateException("server returned CTL_ERROR")
                CTL_ASSIGN -> { /* fall through */ }
                else -> throw IllegalStateException("unexpected control response 0x%02x".format(resp[0].toInt() and 0xFF))
            }

            val ip      = "%d.%d.%d.%d".format(
                resp[1].toInt() and 0xFF, resp[2].toInt() and 0xFF,
                resp[3].toInt() and 0xFF, resp[4].toInt() and 0xFF
            )
            val pfxLen  = resp[5].toInt() and 0xFF
            val gateway = "%d.%d.%d.%d".format(
                resp[6].toInt() and 0xFF, resp[7].toInt() and 0xFF,
                resp[8].toInt() and 0xFF, resp[9].toInt() and 0xFF
            )

            return RouteInfo(ip, pfxLen, gateway)
        } finally {
            ctl.close()
        }
    }
}
