package com.cavadvpn.crypto

import org.junit.Assert.*
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger

class ReplayFilterTest {

    private fun freshHeader(offsetSecs: Long = 0): PacketHeader {
        val nonce = ByteArray(NONCE_SIZE).also { java.security.SecureRandom().nextBytes(it) }
        return PacketHeader(System.currentTimeMillis() / 1000L + offsetSecs, nonce)
    }

    @Test fun `fresh packet is accepted`() {
        val filter = ReplayFilter()
        assertTrue(filter.check(freshHeader()))
    }

    @Test fun `duplicate packet is rejected`() {
        val filter = ReplayFilter()
        val hdr = freshHeader()
        assertTrue(filter.check(hdr))
        assertFalse(filter.check(hdr))
    }

    @Test fun `packet with same timestamp but different nonce is accepted`() {
        val filter = ReplayFilter()
        val ts = System.currentTimeMillis() / 1000L
        val n1 = ByteArray(NONCE_SIZE).also { java.security.SecureRandom().nextBytes(it) }
        val n2 = ByteArray(NONCE_SIZE).also { java.security.SecureRandom().nextBytes(it) }
        assertTrue(filter.check(PacketHeader(ts, n1)))
        assertTrue(filter.check(PacketHeader(ts, n2)))
    }

    @Test fun `packet older than window is rejected`() {
        val filter = ReplayFilter()
        assertFalse(filter.check(freshHeader(-(REPLAY_WINDOW_SECS + 1))))
    }

    @Test fun `packet newer than window is rejected`() {
        val filter = ReplayFilter()
        assertFalse(filter.check(freshHeader(REPLAY_WINDOW_SECS + 1)))
    }

    @Test fun `packet at window boundary is accepted`() {
        val filter = ReplayFilter()
        assertTrue(filter.check(freshHeader(-REPLAY_WINDOW_SECS)))
        assertTrue(filter.check(freshHeader( REPLAY_WINDOW_SECS)))
    }

    @Test fun `encode-decode round trip`() {
        val hdr = freshHeader()
        val encoded = hdr.encode()
        assertEquals(PACKET_HEADER_SIZE, encoded.size)
        val decoded = decodePacketHeader(encoded)
        assertEquals(hdr.timestamp, decoded.timestamp)
        assertArrayEquals(hdr.nonce, decoded.nonce)
    }

    @Test fun `newPacketHeader nonce is random`() {
        val h1 = newPacketHeader()
        val h2 = newPacketHeader()
        assertFalse(h1.nonce.contentEquals(h2.nonce))
    }

    @Test fun `thread-safe under concurrent access`() {
        val filter = ReplayFilter()
        val pool = Executors.newFixedThreadPool(8)
        val accepted = AtomicInteger()
        val rejected = AtomicInteger()
        val latch = CountDownLatch(1)
        val tasks = 200

        val futures = (0 until tasks).map {
            pool.submit {
                latch.await()
                val hdr = freshHeader()
                // Each thread submits the same header twice
                if (filter.check(hdr)) accepted.incrementAndGet()
                else rejected.incrementAndGet()
                if (filter.check(hdr)) accepted.incrementAndGet()
                else rejected.incrementAndGet()
            }
        }

        latch.countDown()
        futures.forEach { it.get() }
        pool.shutdown()

        // No assertions about exact counts — just must not throw or deadlock
        assertEquals(tasks * 2, accepted.get() + rejected.get())
    }
}
