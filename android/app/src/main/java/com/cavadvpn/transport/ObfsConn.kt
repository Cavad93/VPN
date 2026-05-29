package com.cavadvpn.transport

import java.io.BufferedInputStream
import java.io.InputStream
import java.io.OutputStream
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

// TLS record content type bytes
private const val TLS_CCS       : Byte = 0x14  // ChangeCipherSpec (middlebox compat, RFC 8446 §5.1)
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
    private val outputStream: OutputStream,
    private val knockKey: ByteArray? = null
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

    // -----------------------------------------------------------------------
    // GREASE (RFC 8701)
    // -----------------------------------------------------------------------

    private val greaseTable = intArrayOf(
        0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A,
        0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
        0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
        0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
    )

    private fun pickGrease(): Int {
        val b = ByteArray(1).also { SecureRandom().nextBytes(it) }
        return greaseTable[b[0].toInt() and 0x0F]
    }

    private fun u16(v: Int): ByteArray = byteArrayOf((v shr 8).toByte(), v.toByte())

    private fun buildExt(type: Int, data: ByteArray = ByteArray(0)): ByteArray =
        u16(type) + u16(data.size) + data

    private fun buildSupportedGroupsExt(grease: Int): ByteArray =
        buildExt(0x000A, u16(8) + u16(grease) + byteArrayOf(0x00, 0x1D, 0x00, 0x17, 0x00, 0x18))

    private fun buildALPNExt(): ByteArray = buildExt(0x0010, byteArrayOf(
        0x00, 0x0E,
        0x00, 0x02, 0x68, 0x32,
        0x00, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2F, 0x31, 0x2E, 0x31,
    ))

    private fun buildSigAlgsExt(): ByteArray = buildExt(0x000D, byteArrayOf(
        0x00, 0x10,
        0x04, 0x03, 0x08.toByte(), 0x04, 0x04, 0x01,
        0x05, 0x03, 0x08.toByte(), 0x05, 0x05, 0x01,
        0x08.toByte(), 0x06, 0x06, 0x01,
    ))

    private fun buildKeyShareExt(grease: Int): ByteArray {
        val x25519Key = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val entries = u16(grease) + byteArrayOf(0x00, 0x01, 0x00) +
                      byteArrayOf(0x00, 0x1D, 0x00, 0x20) + x25519Key
        return buildExt(0x0033, u16(entries.size) + entries)
    }

    private fun buildSupportedVersionsClientExt(grease: Int): ByteArray =
        buildExt(0x002B, byteArrayOf(0x06) + u16(grease) + byteArrayOf(0x03, 0x04, 0x03, 0x03))

    private fun buildCompressCertExt(): ByteArray =
        buildExt(0x001B, byteArrayOf(0x02, 0x00, 0x02, 0x00, 0x01))

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
        while (true) {
            val hdr = readFully(OBFS_HEADER_SIZE)
            val gotType = hdr[0].toInt() and 0xFF
            // Skip ChangeCipherSpec (TLS 1.3 middlebox compat, RFC 8446 §5.1).
            if (gotType == 0x14) {
                val length = ((hdr[3].toInt() and 0xFF) shl 8) or (hdr[4].toInt() and 0xFF)
                if (length in 1..MAX_OBFS_PAYLOAD) readFully(length)
                continue
            }
            if (gotType != wantType) {
                throw IllegalStateException("obfs: unexpected record type 0x%02x (want 0x%02x)".format(gotType, wantType))
            }
            val length = ((hdr[3].toInt() and 0xFF) shl 8) or (hdr[4].toInt() and 0xFF)
            if (length == 0 || length > MAX_OBFS_PAYLOAD) {
                throw IllegalStateException("obfs: invalid record length $length")
            }
            return readFully(length)
        }
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

    /** Chrome-120-equivalent ClientHello. Record header uses 0x0301 (legacy TLS 1.0),
     *  not 0x0303 — Chrome/Firefox/Safari behavior per RFC 8446 §5.1. */
    private fun buildClientHello(): ByteArray {
        val rng = SecureRandom()
        val random = ByteArray(32).also { rng.nextBytes(it) }
        val sessionId = if (knockKey != null) {
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(knockKey, "HmacSHA256"))
            mac.doFinal(random)
        } else ByteArray(32).also { rng.nextBytes(it) }

        val greaseCS  = pickGrease()
        val greaseE1  = pickGrease()
        val greaseE2  = pickGrease()
        val greaseGrp = pickGrease()
        val greaseVer = pickGrease()
        val greaseKS  = pickGrease()

        val cipherSuites = u16(greaseCS) + byteArrayOf(
            0x13, 0x01, 0x13, 0x02, 0x13, 0x03,
            0xC0.toByte(), 0x2B, 0xC0.toByte(), 0x2F,
            0xC0.toByte(), 0x2C, 0xC0.toByte(), 0x30,
            0xCC.toByte(), 0xA9.toByte(), 0xCC.toByte(), 0xA8.toByte(),
            0xC0.toByte(), 0x13, 0xC0.toByte(), 0x14,
            0x00, 0x9C.toByte(), 0x00, 0x9D.toByte(),
            0x00, 0x2F, 0x00, 0x35,
        )

        var exts = ByteArray(0)
        exts += buildExt(greaseE1, byteArrayOf(0x00, 0x00))
        exts += buildExt(0x0017)
        exts += buildExt(0xFF01, byteArrayOf(0x00))
        exts += buildSupportedGroupsExt(greaseGrp)
        exts += buildExt(0x000B, byteArrayOf(0x01, 0x00))
        exts += buildExt(0x0023)
        exts += buildALPNExt()
        exts += buildExt(0x0005, byteArrayOf(0x01, 0x00, 0x00, 0x00, 0x00))
        exts += buildSigAlgsExt()
        exts += buildExt(0x0012)
        exts += buildKeyShareExt(greaseKS)
        exts += buildExt(0x002D, byteArrayOf(0x01, 0x01))
        exts += buildSupportedVersionsClientExt(greaseVer)
        exts += buildCompressCertExt()
        exts += buildExt(greaseE2, byteArrayOf(0x00, 0x00))

        var body = byteArrayOf(0x03, 0x03) + random +
                   byteArrayOf(0x20) + sessionId +
                   u16(cipherSuites.size) + cipherSuites +
                   byteArrayOf(0x01, 0x00) +
                   u16(exts.size) + exts

        // Handshake header
        val hsLen = body.size
        val hs = byteArrayOf(
            TLS_HELLO_CLIENT,
            (hsLen shr 16).toByte(), (hsLen shr 8).toByte(), hsLen.toByte()
        ) + body

        // TLS record: 0x0301 (legacy TLS 1.0) in ClientHello record header
        val rec = ByteArray(OBFS_HEADER_SIZE + hs.size)
        rec[0] = TLS_HANDSHAKE
        rec[1] = 0x03
        rec[2] = 0x01  // legacy TLS 1.0 — Chrome/Firefox/Safari behavior
        rec[3] = (hs.size shr 8).toByte()
        rec[4] = hs.size.toByte()
        System.arraycopy(hs, 0, rec, OBFS_HEADER_SIZE, hs.size)
        return rec
    }

    private fun buildServerHello(): ByteArray {
        val rng = SecureRandom()
        val random      = ByteArray(32).also { rng.nextBytes(it) }
        val sessionEcho = ByteArray(32).also { rng.nextBytes(it) }
        val verExt = buildExt(0x002B, byteArrayOf(0x03, 0x04))
        val body = byteArrayOf(0x03, 0x03) + random +
                   byteArrayOf(0x20) + sessionEcho +
                   byteArrayOf(0x13, 0x01, 0x00) +
                   u16(verExt.size) + verExt
        return wrapHandshakeRecord(TLS_HELLO_SERVER.toInt() and 0xFF, body)
    }

    private fun wrapHandshakeRecord(msgType: Int, body: ByteArray): ByteArray {
        val hsLen = body.size
        val hs = ByteArray(4 + hsLen)
        hs[0] = msgType.toByte()
        hs[1] = (hsLen shr 16).toByte()
        hs[2] = (hsLen shr  8).toByte()
        hs[3] =  hsLen.toByte()
        System.arraycopy(body, 0, hs, 4, hsLen)
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
