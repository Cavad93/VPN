package com.cavadvpn.crypto

import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.bouncycastle.crypto.engines.ChaCha7539Engine
import org.bouncycastle.crypto.modes.ChaChaPolyCipherMode
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey
import java.security.SecureRandom

/** Size in bytes of an X25519 key and ChaCha20-Poly1305 key. */
const val KEY_SIZE = 32

/** Size in bytes of a ChaCha20-Poly1305 nonce. */
const val NONCE_SIZE = 12

/** Authentication tag overhead in bytes for ChaCha20-Poly1305. */
const val AEAD_OVERHEAD = 16

/**
 * An X25519 key pair holding both the private and public key as raw 32-byte arrays.
 *
 * @property privateKey 32-byte X25519 private key (RFC 7748 clamped)
 * @property publicKey  32-byte X25519 public key derived from privateKey
 */
data class KeyPair(
    val privateKey: ByteArray,
    val publicKey: ByteArray
) {
    init {
        require(privateKey.size == KEY_SIZE) { "privateKey must be $KEY_SIZE bytes" }
        require(publicKey.size == KEY_SIZE) { "publicKey must be $KEY_SIZE bytes" }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is KeyPair) return false
        return privateKey.contentEquals(other.privateKey) && publicKey.contentEquals(other.publicKey)
    }

    override fun hashCode(): Int = 31 * privateKey.contentHashCode() + publicKey.contentHashCode()
}

/**
 * Generates a fresh X25519 key pair with RFC 7748 clamping applied to the private key.
 *
 * @return a new [KeyPair] backed by cryptographically random material
 */
fun generateKeyPair(): KeyPair {
    val random = SecureRandom()
    val gen = X25519KeyPairGenerator()
    gen.init(X25519KeyGenerationParameters(random))
    val keyPair = gen.generateKeyPair()

    val privateParams = keyPair.private as X25519PrivateKeyParameters
    val publicParams = keyPair.public as X25519PublicKeyParameters

    val privateBytes = privateParams.encoded.copyOf(KEY_SIZE)
    // RFC 7748 clamp
    privateBytes[0] = (privateBytes[0].toInt() and 0xF8).toByte()
    privateBytes[31] = (privateBytes[31].toInt() and 0x7F).toByte()
    privateBytes[31] = (privateBytes[31].toInt() or 0x40).toByte()

    // Recompute public key from clamped private key
    val clampedPriv = X25519PrivateKeyParameters(privateBytes)
    val clampedPub = clampedPriv.generatePublicKey()

    return KeyPair(
        privateKey = privateBytes,
        publicKey = clampedPub.encoded.copyOf(KEY_SIZE)
    )
}

/**
 * Performs an X25519 Diffie-Hellman operation.
 *
 * @param privateKey our 32-byte private key
 * @param publicKey  the remote party's 32-byte public key
 * @return 32-byte shared secret
 * @throws IllegalArgumentException if either key is the wrong size
 * @throws SecurityException if the resulting shared secret is the all-zero weak point
 */
fun diffieHellman(privateKey: ByteArray, publicKey: ByteArray): ByteArray {
    require(privateKey.size == KEY_SIZE) { "privateKey must be $KEY_SIZE bytes" }
    require(publicKey.size == KEY_SIZE) { "publicKey must be $KEY_SIZE bytes" }

    val privParams = X25519PrivateKeyParameters(privateKey)
    val pubParams = X25519PublicKeyParameters(publicKey)

    val agreement = X25519Agreement()
    agreement.init(privParams)

    val secret = ByteArray(KEY_SIZE)
    agreement.calculateAgreement(pubParams, secret, 0)

    // Guard against weak (all-zero) keys
    if (secret.all { it == 0.toByte() }) {
        throw SecurityException("DH result is the all-zero weak point")
    }
    return secret
}

/**
 * Encrypts [plaintext] using ChaCha20-Poly1305 AEAD.
 *
 * @param key       32-byte symmetric key
 * @param nonce     12-byte nonce (must be unique per (key, plaintext) pair)
 * @param plaintext data to encrypt
 * @param aad       additional authenticated data (may be empty)
 * @return ciphertext + 16-byte authentication tag
 */
fun encrypt(
    key: ByteArray,
    nonce: ByteArray,
    plaintext: ByteArray,
    aad: ByteArray = ByteArray(0)
): ByteArray {
    require(key.size == KEY_SIZE) { "key must be $KEY_SIZE bytes" }
    require(nonce.size == NONCE_SIZE) { "nonce must be $NONCE_SIZE bytes" }

    return chaCha20Poly1305(encrypt = true, key = key, nonce = nonce, input = plaintext, aad = aad)
}

/**
 * Decrypts [ciphertext] using ChaCha20-Poly1305 AEAD, verifying the authentication tag.
 *
 * @param key        32-byte symmetric key
 * @param nonce      12-byte nonce (must match the nonce used during encryption)
 * @param ciphertext ciphertext + 16-byte authentication tag
 * @param aad        additional authenticated data (must match what was used during encryption)
 * @return decrypted plaintext
 * @throws SecurityException if the authentication tag is invalid
 */
fun decrypt(
    key: ByteArray,
    nonce: ByteArray,
    ciphertext: ByteArray,
    aad: ByteArray = ByteArray(0)
): ByteArray {
    require(key.size == KEY_SIZE) { "key must be $KEY_SIZE bytes" }
    require(nonce.size == NONCE_SIZE) { "nonce must be $NONCE_SIZE bytes" }
    require(ciphertext.size >= AEAD_OVERHEAD) { "ciphertext too short (missing auth tag)" }

    return chaCha20Poly1305(encrypt = false, key = key, nonce = nonce, input = ciphertext, aad = aad)
}

/**
 * Generates 12 cryptographically random bytes suitable for use as a nonce.
 *
 * @return a fresh 12-byte nonce
 */
fun generateNonce(): ByteArray {
    val nonce = ByteArray(NONCE_SIZE)
    SecureRandom().nextBytes(nonce)
    return nonce
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Low-level ChaCha20-Poly1305 encrypt/decrypt using BouncyCastle.
 */
private fun chaCha20Poly1305(
    encrypt: Boolean,
    key: ByteArray,
    nonce: ByteArray,
    input: ByteArray,
    aad: ByteArray
): ByteArray {
    // Use BouncyCastle's ChaCha20-Poly1305 AEAD mode
    val cipher = org.bouncycastle.crypto.modes.ChaCha20Poly1305()
    val keyParam = KeyParameter(key)
    val params = AEADParameters(keyParam, 128 /* tag bits */, nonce, aad)
    cipher.init(encrypt, params)

    val outputSize = cipher.getOutputSize(input.size)
    val output = ByteArray(outputSize)
    val len = cipher.processBytes(input, 0, input.size, output, 0)
    try {
        cipher.doFinal(output, len)
    } catch (e: org.bouncycastle.crypto.InvalidCipherTextException) {
        throw SecurityException("ChaCha20-Poly1305 authentication failed: ${e.message}", e)
    }
    return output
}
