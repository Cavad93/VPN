package com.cavadvpn.crypto

import org.junit.Assert.*
import org.junit.Test

class CryptoCoreTest {

    @Test fun `generateKeyPair returns 32-byte keys`() {
        val kp = generateKeyPair()
        assertEquals(KEY_SIZE, kp.privateKey.size)
        assertEquals(KEY_SIZE, kp.publicKey.size)
    }

    @Test fun `generateKeyPair RFC7748 clamping`() {
        val kp = generateKeyPair()
        // Low 3 bits of byte 0 must be 0
        assertEquals(0, kp.privateKey[0].toInt() and 0x07)
        // Bit 7 of byte 31 must be 0, bit 6 must be 1
        assertEquals(0, kp.privateKey[31].toInt() and 0x80)
        assertNotEquals(0, kp.privateKey[31].toInt() and 0x40)
    }

    @Test fun `generateKeyPair produces unique keys`() {
        val kp1 = generateKeyPair()
        val kp2 = generateKeyPair()
        assertFalse(kp1.privateKey.contentEquals(kp2.privateKey))
        assertFalse(kp1.publicKey.contentEquals(kp2.publicKey))
    }

    @Test fun `diffieHellman is commutative`() {
        val a = generateKeyPair()
        val b = generateKeyPair()
        val ab = diffieHellman(a.privateKey, b.publicKey)
        val ba = diffieHellman(b.privateKey, a.publicKey)
        assertArrayEquals(ab, ba)
    }

    @Test fun `diffieHellman returns 32-byte secret`() {
        val a = generateKeyPair()
        val b = generateKeyPair()
        assertEquals(KEY_SIZE, diffieHellman(a.privateKey, b.publicKey).size)
    }

    @Test(expected = IllegalArgumentException::class)
    fun `diffieHellman rejects short private key`() {
        diffieHellman(ByteArray(16), generateKeyPair().publicKey)
    }

    @Test(expected = IllegalArgumentException::class)
    fun `diffieHellman rejects short public key`() {
        diffieHellman(generateKeyPair().privateKey, ByteArray(16))
    }

    @Test fun `encrypt-decrypt round trip`() {
        val key   = ByteArray(KEY_SIZE).also { java.security.SecureRandom().nextBytes(it) }
        val nonce = generateNonce()
        val plain = "hello world".toByteArray()
        val ct = encrypt(key, nonce, plain)
        val pt = decrypt(key, nonce, ct)
        assertArrayEquals(plain, pt)
    }

    @Test fun `encrypt-decrypt with AAD`() {
        val key   = ByteArray(KEY_SIZE).also { java.security.SecureRandom().nextBytes(it) }
        val nonce = generateNonce()
        val plain = "secret data".toByteArray()
        val aad   = "additional auth".toByteArray()
        val ct = encrypt(key, nonce, plain, aad)
        val pt = decrypt(key, nonce, ct, aad)
        assertArrayEquals(plain, pt)
    }

    @Test(expected = SecurityException::class)
    fun `decrypt fails with wrong key`() {
        val key1  = ByteArray(KEY_SIZE).also { java.security.SecureRandom().nextBytes(it) }
        val key2  = ByteArray(KEY_SIZE).also { java.security.SecureRandom().nextBytes(it) }
        val nonce = generateNonce()
        val ct    = encrypt(key1, nonce, "data".toByteArray())
        decrypt(key2, nonce, ct)
    }

    @Test(expected = SecurityException::class)
    fun `decrypt fails with wrong nonce`() {
        val key   = ByteArray(KEY_SIZE).also { java.security.SecureRandom().nextBytes(it) }
        val ct    = encrypt(key, generateNonce(), "data".toByteArray())
        decrypt(key, generateNonce(), ct)
    }

    @Test(expected = SecurityException::class)
    fun `decrypt fails with wrong AAD`() {
        val key   = ByteArray(KEY_SIZE).also { java.security.SecureRandom().nextBytes(it) }
        val nonce = generateNonce()
        val ct    = encrypt(key, nonce, "data".toByteArray(), "aad1".toByteArray())
        decrypt(key, nonce, ct, "aad2".toByteArray())
    }

    @Test fun `encrypt adds AEAD overhead`() {
        val key   = ByteArray(KEY_SIZE).also { java.security.SecureRandom().nextBytes(it) }
        val plain = ByteArray(100)
        val ct    = encrypt(key, generateNonce(), plain)
        assertEquals(100 + AEAD_OVERHEAD, ct.size)
    }

    @Test fun `generateNonce returns 12 unique bytes`() {
        val n1 = generateNonce()
        val n2 = generateNonce()
        assertEquals(NONCE_SIZE, n1.size)
        assertFalse(n1.contentEquals(n2))
    }
}
