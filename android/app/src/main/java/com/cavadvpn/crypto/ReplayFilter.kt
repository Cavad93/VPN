package com.cavadvpn.crypto

import java.nio.ByteBuffer
import java.security.SecureRandom

/** Size in bytes of an encoded PacketHeader. */
const val PACKET_HEADER_SIZE = 20

/** Sliding window radius in seconds for replay detection. */
const val REPLAY_WINDOW_SECS = 90L

/**
 * PacketHeader carries per-packet timestamp and nonce for replay protection.
 * Encoded as 8-byte big-endian timestamp + 12-byte nonce = 20 bytes.
 */
data class PacketHeader(val timestamp: Long, val nonce: ByteArray) {
    init { require(nonce.size == NONCE_SIZE) { "nonce must be $NONCE_SIZE bytes" } }

    fun encode(): ByteArray {
        val buf = ByteBuffer.allocate(PACKET_HEADER_SIZE)
        buf.putLong(timestamp)
        buf.put(nonce)
        return buf.array()
    }

    override fun equals(other: Any?) = other is PacketHeader &&
        timestamp == other.timestamp && nonce.contentEquals(other.nonce)
    override fun hashCode() = 31 * timestamp.hashCode() + nonce.contentHashCode()
}

/** Creates a PacketHeader with the current Unix second and a random nonce. */
fun newPacketHeader(): PacketHeader {
    val nonce = ByteArray(NONCE_SIZE)
    SecureRandom().nextBytes(nonce)
    return PacketHeader(System.currentTimeMillis() / 1000L, nonce)
}

/** Deserialises a PacketHeader from [data] (must be at least 20 bytes). */
fun decodePacketHeader(data: ByteArray): PacketHeader {
    require(data.size >= PACKET_HEADER_SIZE) {
        "data too short: ${data.size} < $PACKET_HEADER_SIZE"
    }
    val buf = ByteBuffer.wrap(data)
    val ts = buf.long
    val nonce = ByteArray(NONCE_SIZE)
    buf.get(nonce)
    return PacketHeader(ts, nonce)
}

/**
 * Thread-safe replay filter with a ±REPLAY_WINDOW_SECS sliding time window.
 * Packets outside the window or with a previously seen (timestamp, nonce) pair are rejected.
 */
class ReplayFilter {
    // second → set of hex-encoded nonces seen in that second
    private val buckets = HashMap<Long, HashSet<String>>()

    /**
     * Returns true if [header] is a fresh packet and records it.
     * Returns false if the packet is a replay or outside the time window.
     */
    @Synchronized
    fun check(header: PacketHeader): Boolean {
        val nowSec = System.currentTimeMillis() / 1000L
        val windowStart = nowSec - REPLAY_WINDOW_SECS
        val windowEnd   = nowSec + REPLAY_WINDOW_SECS

        if (header.timestamp < windowStart || header.timestamp > windowEnd) return false

        // Evict stale buckets
        val iter = buckets.entries.iterator()
        while (iter.hasNext()) {
            if (iter.next().key < windowStart) iter.remove()
        }

        val nonceHex = header.nonce.joinToString("") { "%02x".format(it) }
        val bucket = buckets.getOrPut(header.timestamp) { HashSet() }
        if (bucket.contains(nonceHex)) return false
        bucket.add(nonceHex)
        return true
    }
}
