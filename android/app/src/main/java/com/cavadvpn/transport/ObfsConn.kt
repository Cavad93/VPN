package com.cavadvpn.transport

import java.io.BufferedInputStream
import java.io.InputStream
import java.io.OutputStream
import java.security.SecureRandom

// TLS record content type bytes
private const val TLS_HANDSHAKE : Byte = 0x16
private const val TLS_APP_DATA  : Byte = 0x17

// TLS handshake message type bytes
private const val TLS_HELLO_CLIENT : Byte = 0x01
private const val TLS_HELLO_SERVER : Byte = 0x02

// TLS version field (legacy TLS 1.2 value required by RFC 8446)
private const val TLS_VERSION_MAJOR : Byte = 0x03
private const val TLS_VERSION_MINOR : Byte = 0x03

private const val OBFS_HEADER_SIZE = 5
private const val MAX_OBFS_PAYLOAD = 16383  // 2^14 - 1

/**
 * TLS-obfuscation layer that wraps a byte stream inside synthetic TLS records so that
 * DPI systems classify the traffic as ordinary HTTPS.
 *
 * The layer does NOT provide cryptographic security — that is handled by the Noise
 * handshake above it.  This layer only mimics TLS wire format.
 *
 * Wire format of one data record:
 *   byte 0      — content_type (0x17 = application_data)
 *   bytes 1-2   — version (0x03 0x03)
 *   bytes 3-4   — payload length (big-endian uint16)
 *   bytes 5..N  — payload
 */
class ObfsConn(
    inputStream: InputStream,
    private val outputStream: OutputStream
) {
    // 64 KB kernel-side buffer: one socket read typically delivers ~45 TLS records,
    // eliminating per-record syscalls on the hot receive path.
    private val inputStream = BufferedInputStream(inputStream, 65536)
    private var readBuf = ByteArray(0)
    private var readBufPos = 0

    /** Client side: send synthetic ClientHello, receive ServerHello. */
    fun clientHandshake() {
        outputStream.write(buildClientHello())
        outputStream.flush()
        readHandshakeRecord(TLS_HELLO_SERVER.toInt() and 0xFF)
    }

    /** Server side: receive ClientHello, send synthetic ServerHello. */
    fun serverHandshake() {
        readHandshakeRecord(TLS_HELLO_CLIENT.toInt() and 0xFF)
        outputStream.write(buildServerHello())
        outputStream.flush()
    }

    /**
     * Sends [data] as one or more TLS application_data records (max 16383 bytes each).
     * Writes the 5-byte header and payload in a single allocation to avoid an extra copy.
     */
    fun write(data: ByteArray) {
        var offset = 0
        while (offset < data.size) {
            val length = minOf(MAX_OBFS_PAYLOAD, data.size - offset)
            val rec = ByteArray(OBFS_HEADER_SIZE + length)
            rec[0] = TLS_APP_DATA
            rec[1] = TLS_VERSION_MAJOR
            rec[2] = TLS_VERSION_MINOR
            rec[3] = (length shr 8).toByte()
            rec[4] =  length.toByte()
            System.arraycopy(data, offset, rec, OBFS_HEADER_SIZE, length)
            outputStream.write(rec)
            offset += length
        }
        outputStream.flush()
    }

    /**
     * Reads exactly [n] bytes, buffering across TLS application_data records as needed.
     */
    fun read(n: Int): ByteArray {
        val result = ByteArray(n)
        var filled = 0
        while (filled < n) {
            if (readBufPos < readBuf.size) {
                val take = minOf(n - filled, readBuf.size - readBufPos)
                System.arraycopy(readBuf, readBufPos, result, filled, take)
                readBufPos += take
                filled += take
            } else {
                // Fetch next record
                val payload = readRecord(TLS_APP_DATA.toInt() and 0xFF)
                readBuf = payload
                readBufPos = 0
            }
        }
        return result
    }

    /** Synonym for [read] to match the Python API. */
    fun readExactly(n: Int): ByteArray = read(n)

    fun close() {
        try { inputStream.close() } catch (_: Exception) {}
        try { outputStream.close() } catch (_: Exception) {}
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    private fun readRecord(wantType: Int): ByteArray {
        val hdr = readFully(OBFS_HEADER_SIZE)
        val gotType = hdr[0].toInt() and 0xFF
        if (gotType != wantType) {
            throw IllegalStateException("obfs: unexpected record type 0x%02x (want 0x%02x)".format(gotType, wantType))
        }
        val length = ((hdr[3].toInt() and 0xFF) shl 8) or (hdr[4].toInt() and 0xFF)
        if (length == 0 || length > MAX_OBFS_PAYLOAD) {
            throw IllegalStateException("obfs: invalid record length $length")
        }
        return readFully(length)
    }

    private fun readHandshakeRecord(wantMsgType: Int) {
        val payload = readRecord(TLS_HANDSHAKE.toInt() and 0xFF)
        if (payload.size < 4) throw IllegalStateException("obfs: handshake record too short")
        val gotType = payload[0].toInt() and 0xFF
        if (gotType != wantMsgType) {
            throw IllegalStateException("obfs: unexpected handshake type 0x%02x".format(gotType))
        }
    }

    private fun readFully(n: Int): ByteArray {
        val buf = ByteArray(n)
        var pos = 0
        while (pos < n) {
            val r = inputStream.read(buf, pos, n - pos)
            if (r < 0) throw java.io.EOFException("obfs: connection closed after $pos/$n bytes")
            pos += r
        }
        return buf
    }

    // -----------------------------------------------------------------------
    // TLS record builders
    // -----------------------------------------------------------------------

    private fun buildClientHello(): ByteArray {
        val rng = SecureRandom()
        val random    = ByteArray(32).also { rng.nextBytes(it) }
        val sessionId = ByteArray(32).also { rng.nextBytes(it) }
        // Build body directly as ByteArray — avoids boxing every byte into a Byte object.
        // Layout: version(2) + random(32) + sessionIdLen(1) + sessionId(32) + cipherSuites(8) + compression(2)
        val body = ByteArray(2 + 32 + 1 + 32 + 8 + 2)
        var i = 0
        body[i++] = 0x03; body[i++] = 0x03            // legacy_version = TLS 1.2
        System.arraycopy(random, 0, body, i, 32); i += 32
        body[i++] = 0x20                               // session_id length = 32
        System.arraycopy(sessionId, 0, body, i, 32); i += 32
        // cipher suites: length(2) + TLS_AES_128_GCM_SHA256 + TLS_AES_256_GCM_SHA384 + TLS_CHACHA20_POLY1305_SHA256
        body[i++] = 0x00; body[i++] = 0x06
        body[i++] = 0x13; body[i++] = 0x01
        body[i++] = 0x13; body[i++] = 0x02
        body[i++] = 0x13; body[i++] = 0x03
        body[i++] = 0x01; body[i]   = 0x00            // compression_methods: length=1, null
        return wrapHandshakeRecord(TLS_HELLO_CLIENT.toInt() and 0xFF, body)
    }

    private fun buildServerHello(): ByteArray {
        val random = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val body = ByteArray(2 + 32 + 1 + 2 + 1)
        var i = 0
        body[i++] = 0x03; body[i++] = 0x03            // legacy_version
        System.arraycopy(random, 0, body, i, 32); i += 32
        body[i++] = 0x00                               // session_id_echo length = 0
        body[i++] = 0x13; body[i++] = 0x01            // cipher_suite
        body[i]   = 0x00                               // compression_method: null
        return wrapHandshakeRecord(TLS_HELLO_SERVER.toInt() and 0xFF, body)
    }

    private fun wrapHandshakeRecord(msgType: Int, body: ByteArray): ByteArray {
        val hsLen = body.size
        // Handshake message: type(1) + length(3) + body
        val hs = ByteArray(4 + hsLen)
        hs[0] = msgType.toByte()
        hs[1] = (hsLen shr 16).toByte()
        hs[2] = (hsLen shr  8).toByte()
        hs[3] =  hsLen.toByte()
        System.arraycopy(body, 0, hs, 4, hsLen)

        // TLS record: content_type(1) + version(2) + length(2) + hs
        val rec = ByteArray(OBFS_HEADER_SIZE + hs.size)
        rec[0] = TLS_HANDSHAKE
        rec[1] = TLS_VERSION_MAJOR
        rec[2] = TLS_VERSION_MINOR
        rec[3] = (hs.size shr 8).toByte()
        rec[4] =  hs.size.toByte()
        System.arraycopy(hs, 0, rec, OBFS_HEADER_SIZE, hs.size)
        return rec
    }

}
