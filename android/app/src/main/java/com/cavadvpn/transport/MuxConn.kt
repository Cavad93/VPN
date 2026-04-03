package com.cavadvpn.transport

import com.cavadvpn.crypto.NoiseCipherState
import com.cavadvpn.crypto.NoiseSession
import java.io.EOFException
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.BlockingQueue
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger


// Mux frame types
private const val FRAME_SYN  : Byte = 0x01
private const val FRAME_DATA : Byte = 0x02
private const val FRAME_FIN  : Byte = 0x03

private const val MUX_HEADER_SIZE = 7   // streamID(4) + type(1) + payloadLen(2)
private const val MAX_MUX_PAYLOAD = 0xFFFF

/**
 * Noise-encrypted transport layer over [ObfsConn].
 *
 * Each message is encrypted with the session's send cipher and prefixed with a
 * 2-byte big-endian length (the length of the ciphertext).
 */
class NoiseConn(private val obfs: ObfsConn, private val session: NoiseSession) {

    /** Encrypts [plaintext] and writes it with a 2-byte BE length prefix.
     *  Length prefix and ciphertext are combined into one allocation so that
     *  ObfsConn sends them as a single TLS record (avoids extra array copy). */
    fun writeMessage(plaintext: ByteArray) {
        val ct = session.sendCipher.encrypt(plaintext)
        val frame = ByteArray(2 + ct.size)
        frame[0] = (ct.size shr 8).toByte()
        frame[1] =  ct.size.toByte()
        System.arraycopy(ct, 0, frame, 2, ct.size)
        obfs.write(frame)
    }

    /** Reads one length-prefixed ciphertext frame and decrypts it. */
    fun readMessage(): ByteArray {
        val lenBytes = obfs.read(2)
        val frameLen = ((lenBytes[0].toInt() and 0xFF) shl 8) or (lenBytes[1].toInt() and 0xFF)
        val ct = obfs.read(frameLen)
        return session.recvCipher.decrypt(ct)
    }

    fun close() = obfs.close()
}

/**
 * A virtual bidirectional stream within a [ClientMux].
 *
 * Data is queued by the mux read-loop and delivered via [read] / [readExactly].
 */
class MuxStream(
    val streamId: Int,
    private val mux: ClientMux
) {
    private val queue: BlockingQueue<ByteArray> = ArrayBlockingQueue(4096)
    private val closed     = AtomicBoolean(false)
    private val remoteFin  = AtomicBoolean(false)
    private var readBuf    = ByteArray(0)
    private var readBufPos = 0

    /**
     * Sends [data] as one or more DATA frames.
     */
    fun write(data: ByteArray) {
        check(!closed.get()) { "stream $streamId is closed" }
        write(data, 0, data.size)
    }

    /**
     * Sends [length] bytes from [data] starting at [dataOffset] as one or more DATA frames.
     * Avoids a copy in the caller (e.g. TUN read buffer partial fill).
     */
    fun write(data: ByteArray, dataOffset: Int, length: Int) {
        check(!closed.get()) { "stream $streamId is closed" }
        var offset = dataOffset
        val end0 = dataOffset + length
        while (offset < end0) {
            val end = minOf(offset + MAX_MUX_PAYLOAD, end0)
            mux.writeFrame(streamId, FRAME_DATA, data, offset, end - offset)
            offset = end
        }
    }

    /**
     * Reads the next available data chunk. Returns an empty array on remote FIN / close.
     * Blocks up to [timeoutMs] milliseconds.
     */
    fun read(timeoutMs: Long = 5_000L): ByteArray {
        if (readBufPos < readBuf.size) {
            val chunk = readBuf.copyOfRange(readBufPos, readBuf.size)
            readBufPos = readBuf.size
            return chunk
        }
        return try {
            queue.poll(timeoutMs, TimeUnit.MILLISECONDS) ?: ByteArray(0)
        } catch (_: InterruptedException) {
            ByteArray(0)
        }
    }

    /**
     * Reads exactly [n] bytes, blocking and buffering across multiple chunks.
     */
    fun readExactly(n: Int, timeoutMs: Long = 5_000L): ByteArray {
        val buf = ByteArray(n)
        var filled = 0
        while (filled < n) {
            if (readBufPos < readBuf.size) {
                val take = minOf(n - filled, readBuf.size - readBufPos)
                System.arraycopy(readBuf, readBufPos, buf, filled, take)
                readBufPos += take
                filled += take
            } else {
                val chunk = try {
                    queue.poll(timeoutMs, TimeUnit.MILLISECONDS)
                } catch (_: InterruptedException) {
                    null
                }
                if (chunk == null || chunk.isEmpty()) {
                    throw EOFException("stream $streamId closed after $filled/$n bytes")
                }
                readBuf = chunk
                readBufPos = 0
            }
        }
        return buf
    }

    /** Sends FIN and removes this stream from the mux. */
    fun close() {
        if (closed.compareAndSet(false, true)) {
            try { mux.writeFrame(streamId, FRAME_FIN, ByteArray(0), 0, 0) } catch (_: Exception) {}
            mux.removeStream(streamId)
            queue.offer(ByteArray(0)) // unblock any waiting read
        }
    }

    // Called by the read-loop to deliver incoming data (slice of decrypted frame — no copy)
    internal fun deliver(data: ByteArray, offset: Int, length: Int) {
        if (length <= 0) return
        // Extract the slice so the full decrypted frame buffer can be GC'd independently
        val slice = data.copyOfRange(offset, offset + length)
        queue.offer(slice)
    }

    // Called by the read-loop when the remote sends FIN
    internal fun signalFin() {
        remoteFin.set(true)
        queue.offer(ByteArray(0))
    }
}

/**
 * Client-side stream multiplexer over a [NoiseConn].
 *
 * The client uses even stream IDs (2, 4, 6, …).  A background thread continuously
 * reads Noise messages and dispatches mux frames to the appropriate [MuxStream].
 */
class ClientMux(private val conn: NoiseConn) {
    // ConcurrentHashMap: lock-free reads on the dispatch hot path
    private val streams   = ConcurrentHashMap<Int, MuxStream>()
    private val writeLock = Any()
    private val nextId    = AtomicInteger(2) // even IDs for client; CAS increments
    private val closed    = AtomicBoolean(false)

    private val reader = Thread(::readLoop, "cavadvpn-mux-reader").also {
        it.isDaemon = true
        it.start()
    }

    /**
     * Opens a new outbound stream, sends a SYN frame, and returns the stream.
     */
    fun openStream(): MuxStream {
        check(!closed.get()) { "mux is closed" }
        val sid = nextId.getAndAdd(2) // atomic; no lock needed
        val stream = MuxStream(sid, this)
        streams[sid] = stream
        writeFrame(sid, FRAME_SYN, ByteArray(0), 0, 0)
        return stream
    }

    /** Closes all streams and the underlying connection. */
    fun close() {
        if (closed.compareAndSet(false, true)) {
            streams.values.forEach { it.signalFin() }
            streams.clear()
            try { conn.close() } catch (_: Exception) {}
            reader.interrupt()
        }
    }

    // -----------------------------------------------------------------------
    // Internal frame I/O
    // -----------------------------------------------------------------------

    internal fun writeFrame(streamId: Int, type: Byte, payload: ByteArray, offset: Int, length: Int) {
        val frame = ByteArray(MUX_HEADER_SIZE + length)
        frame[0] = (streamId ushr 24).toByte()
        frame[1] = (streamId ushr 16).toByte()
        frame[2] = (streamId ushr  8).toByte()
        frame[3] =  streamId.toByte()
        frame[4] = type
        frame[5] = (length shr 8).toByte()
        frame[6] =  length.toByte()
        if (length > 0) System.arraycopy(payload, offset, frame, MUX_HEADER_SIZE, length)
        synchronized(writeLock) { conn.writeMessage(frame) }
    }

    internal fun removeStream(streamId: Int) {
        streams.remove(streamId) // ConcurrentHashMap — no lock needed
    }

    private fun readLoop() {
        while (!closed.get()) {
            val frameData = try {
                conn.readMessage()
            } catch (e: Exception) {
                if (!closed.get()) {
                    closed.set(true)
                    streams.values.forEach { it.signalFin() }
                    streams.clear()
                }
                break
            }

            if (frameData.size < MUX_HEADER_SIZE) continue

            // Decode 7-byte header without ByteBuffer allocation
            val sid = ((frameData[0].toInt() and 0xFF) shl 24) or
                      ((frameData[1].toInt() and 0xFF) shl 16) or
                      ((frameData[2].toInt() and 0xFF) shl  8) or
                       (frameData[3].toInt() and 0xFF)
            val frameType = frameData[4]
            val payloadLen = ((frameData[5].toInt() and 0xFF) shl 8) or (frameData[6].toInt() and 0xFF)
            // Reuse the decrypted frame buffer — deliver the slice instead of copying
            val payloadStart = MUX_HEADER_SIZE
            val hasPayload = payloadLen > 0 && frameData.size >= payloadStart + payloadLen

            val stream = streams[sid] // lock-free read from ConcurrentHashMap

            when (frameType) {
                FRAME_SYN -> {
                    if (stream == null) {
                        // Server opened a stream — register it (putIfAbsent is atomic)
                        streams.putIfAbsent(sid, MuxStream(sid, this))
                    }
                }
                FRAME_DATA -> {
                    if (stream != null && hasPayload) stream.deliver(frameData, payloadStart, payloadLen)
                }
                FRAME_FIN -> {
                    stream?.signalFin()
                    removeStream(sid)
                }
            }
        }
    }
}
