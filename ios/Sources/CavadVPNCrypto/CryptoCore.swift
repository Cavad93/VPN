/// CryptoCore.swift — X25519 key exchange + ChaCha20-Poly1305 AEAD + HMAC-SHA256
///
/// Wire-compatible with the Go server (server/crypto/crypto.go) and Python client (client/core.py).

import Foundation
import Crypto

// MARK: - Constants

public let KEY_SIZE = 32
public let AEAD_OVERHEAD = 16  // ChaCha20-Poly1305 tag size
public let NONCE_SIZE = 12

// MARK: - Key Pair

/// An X25519 key pair used for Diffie-Hellman and Noise handshake.
public struct KeyPair {
    public let privateKey: Curve25519.KeyAgreement.PrivateKey
    public let publicKeyBytes: [UInt8]  // 32 raw bytes

    public var publicKey: [UInt8] { publicKeyBytes }

    public init(privateKey: Curve25519.KeyAgreement.PrivateKey) {
        self.privateKey = privateKey
        self.publicKeyBytes = Array(privateKey.publicKey.rawRepresentation)
    }

    /// Initialize from raw 32-byte private key bytes.
    public init(privateKeyBytes: [UInt8]) throws {
        guard privateKeyBytes.count == KEY_SIZE else {
            throw CryptoError.invalidKeySize(privateKeyBytes.count)
        }
        let priv = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: Data(privateKeyBytes))
        self.privateKey = priv
        self.publicKeyBytes = Array(priv.publicKey.rawRepresentation)
    }
}

// MARK: - Errors

public enum CryptoError: Error {
    case invalidKeySize(Int)
    case dhWeakKey
    case decryptionFailed
    case invalidNonceSize(Int)
}

// MARK: - Key Generation

/// Generate a new X25519 key pair. RFC 7748 clamping is applied automatically by swift-crypto.
public func generateKeyPair() -> KeyPair {
    let priv = Curve25519.KeyAgreement.PrivateKey()
    return KeyPair(privateKey: priv)
}

// MARK: - Diffie-Hellman

/// Perform X25519 Diffie-Hellman. Returns 32-byte shared secret.
/// Throws if result is the all-zero weak key.
public func diffieHellman(privateKey: Curve25519.KeyAgreement.PrivateKey, publicKeyBytes: [UInt8]) throws -> [UInt8] {
    let pubKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: Data(publicKeyBytes))
    let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: pubKey)
    // Extract raw bytes from SharedSecret via withUnsafeBytes
    let bytes: [UInt8] = sharedSecret.withUnsafeBytes { Array($0) }
    if bytes.allSatisfy({ $0 == 0 }) {
        throw CryptoError.dhWeakKey
    }
    return bytes
}

// MARK: - Random Bytes

/// Generate cryptographically random bytes.
public func generateRandomBytes(count: Int) -> [UInt8] {
    var bytes = [UInt8](repeating: 0, count: count)
    for i in bytes.indices {
        bytes[i] = UInt8.random(in: 0...255)
    }
    return bytes
}

/// Generate a cryptographically random 12-byte nonce.
public func generateNonce() -> [UInt8] {
    return generateRandomBytes(count: NONCE_SIZE)
}

// MARK: - ChaCha20-Poly1305 AEAD

/// Encrypt plaintext with ChaCha20-Poly1305. Returns ciphertext + 16-byte auth tag.
public func chaCha20Poly1305Encrypt(
    key: [UInt8],
    nonce: [UInt8],
    plaintext: [UInt8],
    aad: [UInt8] = []
) throws -> [UInt8] {
    guard key.count == KEY_SIZE else { throw CryptoError.invalidKeySize(key.count) }
    guard nonce.count == NONCE_SIZE else { throw CryptoError.invalidNonceSize(nonce.count) }

    let symmetricKey = SymmetricKey(data: Data(key))
    let nonceData = try ChaChaPoly.Nonce(data: Data(nonce))
    let sealedBox = try ChaChaPoly.seal(Data(plaintext), using: symmetricKey, nonce: nonceData, authenticating: Data(aad))
    // ChaChaPoly.seal returns ciphertext + tag concatenated
    return Array(sealedBox.ciphertext) + Array(sealedBox.tag)
}

/// Decrypt ciphertext (with appended 16-byte tag) using ChaCha20-Poly1305.
public func chaCha20Poly1305Decrypt(
    key: [UInt8],
    nonce: [UInt8],
    ciphertext: [UInt8],
    aad: [UInt8] = []
) throws -> [UInt8] {
    guard key.count == KEY_SIZE else { throw CryptoError.invalidKeySize(key.count) }
    guard nonce.count == NONCE_SIZE else { throw CryptoError.invalidNonceSize(nonce.count) }
    guard ciphertext.count >= AEAD_OVERHEAD else { throw CryptoError.decryptionFailed }

    let symmetricKey = SymmetricKey(data: Data(key))
    let nonceData = try ChaChaPoly.Nonce(data: Data(nonce))

    let ct = Data(ciphertext.prefix(ciphertext.count - AEAD_OVERHEAD))
    let tag = Data(ciphertext.suffix(AEAD_OVERHEAD))
    let sealedBox = try ChaChaPoly.SealedBox(nonce: nonceData, ciphertext: ct, tag: tag)
    let plaintext = try ChaChaPoly.open(sealedBox, using: symmetricKey, authenticating: Data(aad))
    return Array(plaintext)
}

// MARK: - HMAC-SHA256

/// Compute HMAC-SHA256(key, data).
public func hmacSHA256(key: [UInt8], data: [UInt8]) -> [UInt8] {
    let symKey = SymmetricKey(data: Data(key))
    let mac = HMAC<SHA256>.authenticationCode(for: Data(data), using: symKey)
    return Array(mac)
}

// MARK: - Noise HKDF

/// Noise protocol HKDF using HMAC-SHA256.
/// Returns n (2 or 3) 32-byte outputs.
///
/// ```
/// TEMP = HMAC-SHA256(key=ck, data=ikm)
/// k1   = HMAC-SHA256(key=TEMP, data=[0x01])
/// k2   = HMAC-SHA256(key=k1,   data=[0x02])
/// k3   = HMAC-SHA256(key=k2,   data=[0x03])   // only if n == 3
/// ```
public func noiseHKDF(ck: [UInt8], ikm: [UInt8], n: Int) -> [[UInt8]] {
    precondition(n == 2 || n == 3, "noiseHKDF: n must be 2 or 3")
    let temp = hmacSHA256(key: ck, data: ikm)
    let k1 = hmacSHA256(key: temp, data: [0x01])
    let k2 = hmacSHA256(key: temp, data: k1 + [0x02])
    if n == 2 { return [k1, k2] }
    let k3 = hmacSHA256(key: temp, data: k2 + [0x03])
    return [k1, k2, k3]
}
