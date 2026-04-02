package com.cavadvpn.crypto

import org.junit.Assert.*
import org.junit.Test

/**
 * Tests the Noise_XX handshake by running both initiator and a manual responder
 * side-by-side (since CavadVPN only ships the initiator side in the client).
 */
class NoiseHandshakeTest {

    /** Minimal Noise_XX responder for testing purposes only. */
    private class NoiseResponder(private val staticKP: KeyPair) {
        private val ss = NoiseSymmetricState()
        private var e: KeyPair? = null
        private var re: ByteArray? = null
        private var rs: ByteArray? = null
        private var step = 0

        init { ss.mixHash(ByteArray(0)) }

        // <- e (reads initiator ephemeral)
        fun readMessage1(msg: ByteArray) {
            require(step == 0)
            require(msg.size >= KEY_SIZE)
            re = msg.copyOf(KEY_SIZE)
            ss.mixHash(re!!)
            step = 1
        }

        // -> e, ee, s, es
        fun writeMessage2(): ByteArray {
            require(step == 1)
            val eph = generateKeyPair()
            e = eph
            ss.mixHash(eph.publicKey)

            val ee = diffieHellman(eph.privateKey, re!!)
            ss.mixKey(ee)

            val encStatic = ss.encryptAndHash(staticKP.publicKey)

            val es = diffieHellman(staticKP.privateKey, re!!)
            ss.mixKey(es)

            step = 2
            return eph.publicKey + encStatic
        }

        // <- s, se  →  split into session ciphers
        fun readMessage3(msg: ByteArray): NoiseSession {
            require(step == 2)
            require(msg.size >= KEY_SIZE + AEAD_OVERHEAD)

            val encStatic = msg.copyOf(KEY_SIZE + AEAD_OVERHEAD)
            rs = ss.decryptAndHash(encStatic)

            val se = diffieHellman(e!!.privateKey, rs!!)
            ss.mixKey(se)

            // Responder: send = k2, recv = k1
            val (k1, k2) = ss.split()
            step = 3
            return NoiseSession(k2, k1, rs!!.copyOf())
        }
    }

    @Test fun `full Noise_XX handshake succeeds`() {
        val clientKP = generateKeyPair()
        val serverKP = generateKeyPair()

        val initiator = NoiseHandshake(clientKP)
        val responder = NoiseResponder(serverKP)

        val msg1 = initiator.writeMessage1()
        assertEquals(KEY_SIZE, msg1.size)

        responder.readMessage1(msg1)
        val msg2 = responder.writeMessage2()

        initiator.readMessage2(msg2)
        val (msg3, clientSession) = initiator.writeMessage3()

        val serverSession = responder.readMessage3(msg3)

        // Verify mutual static key authentication
        assertArrayEquals(serverKP.publicKey, clientSession.remoteStatic)
        assertArrayEquals(clientKP.publicKey, serverSession.remoteStatic)
    }

    @Test fun `session ciphers are cross-compatible`() {
        val clientKP = generateKeyPair()
        val serverKP = generateKeyPair()

        val initiator = NoiseHandshake(clientKP)
        val responder = NoiseResponder(serverKP)

        val msg1 = initiator.writeMessage1()
        responder.readMessage1(msg1)
        val msg2 = responder.writeMessage2()
        initiator.readMessage2(msg2)
        val (msg3, clientSession) = initiator.writeMessage3()
        val serverSession = responder.readMessage3(msg3)

        val plain = "test message".toByteArray()

        // Client → Server
        val ct1 = clientSession.sendCipher.encrypt(plain)
        val pt1 = serverSession.recvCipher.decrypt(ct1)
        assertArrayEquals(plain, pt1)

        // Server → Client
        val ct2 = serverSession.sendCipher.encrypt(plain)
        val pt2 = clientSession.recvCipher.decrypt(ct2)
        assertArrayEquals(plain, pt2)
    }

    @Test fun `nonce counter increments correctly`() {
        val key = ByteArray(KEY_SIZE).also { java.security.SecureRandom().nextBytes(it) }
        val cs = NoiseCipherState(key)
        val plain = "msg".toByteArray()
        val ct0 = cs.encrypt(plain)
        val ct1 = cs.encrypt(plain)
        // Different nonces produce different ciphertexts
        assertFalse(ct0.contentEquals(ct1))
    }

    @Test fun `noiseHKDF produces deterministic output`() {
        val ck  = ByteArray(32) { it.toByte() }
        val ikm = ByteArray(32) { (it + 100).toByte() }
        val (o1a, o2a) = noiseHKDF(ck, ikm, 2)
        val (o1b, o2b) = noiseHKDF(ck, ikm, 2)
        assertArrayEquals(o1a, o1b)
        assertArrayEquals(o2a, o2b)
    }

    @Test fun `noiseHKDF outputs are distinct`() {
        val ck  = ByteArray(32) { it.toByte() }
        val ikm = ByteArray(32) { (it + 50).toByte() }
        val (o1, o2, o3) = noiseHKDF(ck, ikm, 3)
        assertFalse(o1.contentEquals(o2))
        assertFalse(o2.contentEquals(o3))
        assertFalse(o1.contentEquals(o3))
    }

    @Test(expected = IllegalStateException::class)
    fun `writeMessage1 can only be called once`() {
        val hs = NoiseHandshake(generateKeyPair())
        hs.writeMessage1()
        hs.writeMessage1()
    }

    @Test(expected = IllegalStateException::class)
    fun `readMessage2 requires writeMessage1 first`() {
        val hs = NoiseHandshake(generateKeyPair())
        hs.readMessage2(ByteArray(80))
    }

    @Test(expected = IllegalStateException::class)
    fun `writeMessage3 requires readMessage2 first`() {
        val hs = NoiseHandshake(generateKeyPair())
        hs.writeMessage1()
        hs.writeMessage3()
    }
}
