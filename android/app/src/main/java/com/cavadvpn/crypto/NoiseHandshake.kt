package com.cavadvpn.crypto

import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** Noise protocol identifier. */
const val PROTOCOL_NAME = "Noise_XX_25519_ChaChaPoly_SHA256"

/**
 * Post-handshake cipher state using ChaCha20-Poly1305 with incrementing nonce counter.
 * Nonce: 4 zero bytes + 8-byte little-endian counter.
 *
 * The ChaCha20Poly1305 cipher is created ONCE and re-initialized per packet
 * (avoids object allocation on every encrypt/decrypt — same fix as Go/Python).
 */
class NoiseCipherState(key: ByteArray) {
    private val key: ByteArray = key.copyOf(KEY_SIZE)
    private var counter: Long = 0L
    // Cipher created once; re-initialized with new nonce on each call.
    private val cipher = org.bouncycastle.crypto.modes.ChaCha20Poly1305()
    private val nonceBuf = ByteArray(NONCE_SIZE) // reused, avoids allocation per packet

    fun encrypt(plaintext: ByteArray, aad: ByteArray = ByteArray(0)): ByteArray {
        buildNonce(counter++, nonceBuf)
        return encryptWithCipher(cipher, key, nonceBuf, plaintext, aad)
    }

    fun decrypt(ciphertext: ByteArray, aad: ByteArray = ByteArray(0)): ByteArray {
        buildNonce(counter++, nonceBuf)
        return decryptWithCipher(cipher, key, nonceBuf, ciphertext, aad)
    }

    private fun buildNonce(n: Long, buf: ByteArray) {
        // 4 zero bytes + 8-byte little-endian counter
        buf[0] = 0; buf[1] = 0; buf[2] = 0; buf[3] = 0
        buf[4]  = (n         ).toByte()
        buf[5]  = (n ushr  8 ).toByte()
        buf[6]  = (n ushr 16 ).toByte()
        buf[7]  = (n ushr 24 ).toByte()
        buf[8]  = (n ushr 32 ).toByte()
        buf[9]  = (n ushr 40 ).toByte()
        buf[10] = (n ushr 48 ).toByte()
        buf[11] = (n ushr 56 ).toByte()
    }
}

/** Noise HKDF using HMAC-SHA256. Returns n (2 or 3) 32-byte outputs. */
internal fun noiseHKDF(ck: ByteArray, ikm: ByteArray, n: Int): List<ByteArray> {
    require(n in 2..3) { "noiseHKDF: n must be 2 or 3" }
    fun hmac(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }
    val tempKey = hmac(ck, ikm)
    val o1 = hmac(tempKey, byteArrayOf(0x01))
    val o2 = hmac(tempKey, o1 + byteArrayOf(0x02))
    if (n == 2) return listOf(o1, o2)
    val o3 = hmac(tempKey, o2 + byteArrayOf(0x03))
    return listOf(o1, o2, o3)
}

/** Symmetric state tracking transcript hash and chaining key. */
internal class NoiseSymmetricState {
    private var ck: ByteArray
    private var h: ByteArray
    private var cs: NoiseCipherState? = null

    init {
        // Per Noise spec: if len(protocol_name) <= HASHLEN use raw bytes, else hash it.
        // PROTOCOL_NAME is exactly 32 bytes so we copy directly.
        val nameBytes = PROTOCOL_NAME.toByteArray(Charsets.UTF_8)
        val initial = if (nameBytes.size <= KEY_SIZE) {
            ByteArray(KEY_SIZE).also { System.arraycopy(nameBytes, 0, it, 0, nameBytes.size) }
        } else {
            MessageDigest.getInstance("SHA-256").digest(nameBytes)
        }
        ck = initial.copyOf()
        h  = initial.copyOf()
    }

    fun mixHash(data: ByteArray) {
        val d = MessageDigest.getInstance("SHA-256")
        d.update(h)
        d.update(data)
        h = d.digest()
    }

    fun mixKey(ikm: ByteArray) {
        val (newCk, k) = noiseHKDF(ck, ikm, 2)
        ck = newCk
        cs = NoiseCipherState(k)
    }

    fun encryptAndHash(plaintext: ByteArray): ByteArray {
        val ct = cs?.encrypt(plaintext, h) ?: plaintext
        mixHash(ct)
        return ct
    }

    fun decryptAndHash(ciphertext: ByteArray): ByteArray {
        val pt = cs?.decrypt(ciphertext, h) ?: ciphertext
        mixHash(ciphertext)
        return pt
    }

    fun split(): Pair<NoiseCipherState, NoiseCipherState> {
        val (k1, k2) = noiseHKDF(ck, ByteArray(0), 2)
        return Pair(NoiseCipherState(k1), NoiseCipherState(k2))
    }
}

/**
 * Result of a completed Noise_XX handshake.
 *
 * @property sendCipher for encrypting outgoing messages
 * @property recvCipher for decrypting incoming messages
 * @property remoteStatic 32-byte public key of the authenticated peer
 */
data class NoiseSession(
    val sendCipher: NoiseCipherState,
    val recvCipher: NoiseCipherState,
    val remoteStatic: ByteArray
) {
    override fun equals(other: Any?) = other is NoiseSession &&
        remoteStatic.contentEquals(other.remoteStatic)
    override fun hashCode() = remoteStatic.contentHashCode()
}

/**
 * Noise_XX initiator handshake (client side).
 *
 * Pattern:  -> e  |  <- e, ee, s, es  |  -> s, se
 */
class NoiseHandshake(private val staticKP: KeyPair) {
    private val ss = NoiseSymmetricState()
    private var e: KeyPair? = null
    private var re: ByteArray? = null
    private var rs: ByteArray? = null
    private var step = 0

    init { ss.mixHash(ByteArray(0)) } // empty prologue

    /** -> e: generate ephemeral key, returns 32-byte public key. */
    fun writeMessage1(): ByteArray {
        require(step == 0) { "writeMessage1: invalid step $step" }
        val eph = generateKeyPair()
        e = eph
        ss.mixHash(eph.publicKey)
        step = 1
        return eph.publicKey.copyOf()
    }

    /**
     * <- e, ee, s, es: process 80-byte server message.
     * @param msg re_pub(32) + EncryptAndHash(s)(48)
     */
    fun readMessage2(msg: ByteArray) {
        require(step == 1) { "readMessage2: invalid step $step" }
        val minLen = KEY_SIZE + KEY_SIZE + AEAD_OVERHEAD
        require(msg.size >= minLen) { "readMessage2: too short ${msg.size} < $minLen" }

        val re_ = msg.copyOf(KEY_SIZE)
        re = re_
        ss.mixHash(re_)

        val ee = diffieHellman(e!!.privateKey, re_)
        ss.mixKey(ee)

        val encStatic = msg.copyOfRange(KEY_SIZE, KEY_SIZE + KEY_SIZE + AEAD_OVERHEAD)
        rs = ss.decryptAndHash(encStatic)

        val es = diffieHellman(e!!.privateKey, rs!!)
        ss.mixKey(es)
        step = 2
    }

    /**
     * -> s, se: encrypt our static key, DH mix, split.
     * @return Pair(48-byte message, NoiseSession with send/recv ciphers)
     */
    fun writeMessage3(): Pair<ByteArray, NoiseSession> {
        require(step == 2) { "writeMessage3: invalid step $step" }

        val encStatic = ss.encryptAndHash(staticKP.publicKey)

        val se = diffieHellman(staticKP.privateKey, re!!)
        ss.mixKey(se)

        val (sendCs, recvCs) = ss.split()
        step = 3
        return Pair(encStatic, NoiseSession(sendCs, recvCs, rs!!.copyOf()))
    }
}
