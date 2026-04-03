// CryptoCore.swift — X25519 DH + ChaCha20-Poly1305 + HMAC-SHA256
// Wire-compatible with Go server crypto package and Python/Kotlin clients.

import Foundation
import Crypto

// MARK: - Constants

/// Size in bytes of an X25519 key and ChaCha20-Poly1305 key.
public let keySize = 32

/// Size in bytes of a ChaCha20-Poly1305 nonce.
public let nonceSize = 12

/// Authentication tag overhead in bytes for ChaCha20-Poly1305.
public let aeadOverhead = 16

// MARK: - KeyPair

/// An X25519 key pair holding both the private and public key as raw 32-byte Data.
public struct KeyPair {
    public let privateKey: Data   // 32 bytes, RFC 7748 clamped
    public let publicKey: Data    // 32 bytes

    public init(privateKey: Data, publicKey: Data) {
        precondition(privateKey.count == keySize, "privateKey must be \(keySize) bytes")
        precondition(publicKey.count == keySize,  "publicKey must be \(keySize) bytes")
        self.privateKey = privateKey
        self.publicKey  = publicKey
    }
}

/// Generates a fresh X25519 key pair. RFC 7748 clamping is applied by swift-crypto.
public func generateKeyPair() -> KeyPair {
    let privKey = Curve25519.KeyAgreement.PrivateKey()
    let privBytes = Data(privKey.rawRepresentation)
    let pubBytes  = Data(privKey.publicKey.rawRepresentation)
    return KeyPair(privateKey: privBytes, publicKey: pubBytes)
}

/// Performs X25519 Diffie-Hellman.
/// - Returns: 32-byte shared secret.
/// - Throws: `CryptoError.weakKey` if result is the all-zero point.
public func diffieHellman(privateKey: Data, publicKey: Data) throws -> Data {
    guard privateKey.count == keySize, publicKey.count == keySize else {
        throw CryptoError.invalidKeySize
    }
    let priv = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKey)
    let pub  = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: publicKey)
    let sharedSecret = try priv.sharedSecretFromKeyAgreement(with: pub)
    let secret = sharedSecret.withUnsafeBytes { Data($0) }
    if secret == Data(repeating: 0, count: keySize) {
        throw CryptoError.weakKey
    }
    return secret
}

// MARK: - Noise HKDF

/// Noise protocol HKDF using HMAC-SHA256.
/// Returns n (2 or 3) 32-byte outputs.
public func noiseHKDF(ck: Data, ikm: Data, n: Int) -> [Data] {
    precondition(n == 2 || n == 3, "noiseHKDF: n must be 2 or 3")
    let temp = hmacSHA256(key: ck, data: ikm)
    let o1 = hmacSHA256(key: temp, data: Data([0x01]))
    let o2 = hmacSHA256(key: temp, data: o1 + Data([0x02]))
    if n == 2 { return [o1, o2] }
    let o3 = hmacSHA256(key: temp, data: o2 + Data([0x03]))
    return [o1, o2, o3]
}

/// Computes HMAC-SHA256.
public func hmacSHA256(key: Data, data: Data) -> Data {
    let mac = HMAC<SHA256>.authenticationCode(for: data, using: SymmetricKey(data: key))
    return Data(mac)
}

// MARK: - ChaCha20-Poly1305 low-level helpers

/// Encrypts plaintext with ChaCha20-Poly1305.
public func chaChaEncrypt(key: Data, nonce: Data, plaintext: Data, aad: Data = Data()) throws -> Data {
    guard key.count == keySize else { throw CryptoError.invalidKeySize }
    guard nonce.count == nonceSize else { throw CryptoError.invalidNonceSize }
    let symKey = SymmetricKey(data: key)
    let nonceObj = try ChaChaPoly.Nonce(data: nonce)
    let box = try ChaChaPoly.seal(plaintext, using: symKey, nonce: nonceObj, authenticating: aad)
    // ciphertext + tag (no nonce prefix in box.combined; combined = nonce(12)+ct+tag)
    return box.ciphertext + box.tag
}

/// Decrypts ciphertext (ciphertext+tag) with ChaCha20-Poly1305.
public func chaChaDecrypt(key: Data, nonce: Data, ciphertext: Data, aad: Data = Data()) throws -> Data {
    guard key.count == keySize else { throw CryptoError.invalidKeySize }
    guard nonce.count == nonceSize else { throw CryptoError.invalidNonceSize }
    guard ciphertext.count >= aeadOverhead else { throw CryptoError.ciphertextTooShort }
    let symKey = SymmetricKey(data: key)
    let nonceObj = try ChaChaPoly.Nonce(data: nonce)
    let ct  = ciphertext.prefix(ciphertext.count - aeadOverhead)
    let tag = ciphertext.suffix(aeadOverhead)
    let box = try ChaChaPoly.SealedBox(nonce: nonceObj, ciphertext: ct, tag: tag)
    return try ChaChaPoly.open(box, using: symKey, authenticating: aad)
}

/// Generates 12 cryptographically random bytes for use as a nonce.
public func generateNonce() -> Data {
    return generateRandomData(count: nonceSize)
}

/// Generates `count` cryptographically random bytes.
public func generateRandomData(count: Int) -> Data {
    var bytes = [UInt8](repeating: 0, count: count)
    for i in bytes.indices { bytes[i] = UInt8.random(in: 0...255) }
    return Data(bytes)
}

// MARK: - NoiseCipherState

/// Manages a ChaCha20-Poly1305 cipher with an auto-incrementing nonce counter.
/// Nonce = 4 zero bytes + 8-byte little-endian counter (12 bytes total).
public final class NoiseCipherState {
    private var key: Data?
    private var counter: UInt64 = 0

    public init() {}

    public func initializeKey(_ key: Data) {
        precondition(key.count == keySize)
        self.key = key
        self.counter = 0
    }

    public var hasKey: Bool { key != nil }

    public func encrypt(plaintext: Data, aad: Data = Data()) throws -> Data {
        guard let k = key else { return plaintext }
        let nonce = buildNonce(counter)
        counter += 1
        return try chaChaEncrypt(key: k, nonce: nonce, plaintext: plaintext, aad: aad)
    }

    public func decrypt(ciphertext: Data, aad: Data = Data()) throws -> Data {
        guard let k = key else { return ciphertext }
        let nonce = buildNonce(counter)
        counter += 1
        return try chaChaDecrypt(key: k, nonce: nonce, ciphertext: ciphertext, aad: aad)
    }

    private func buildNonce(_ n: UInt64) -> Data {
        var buf = Data(repeating: 0, count: nonceSize)
        // 4 zero bytes, then 8-byte LE counter
        var le = n.littleEndian
        withUnsafeBytes(of: &le) { leBytes in
            buf.replaceSubrange(4..<12, with: leBytes)
        }
        return buf
    }
}

// MARK: - Errors

public enum CryptoError: Error, Equatable {
    case invalidKeySize
    case invalidNonceSize
    case ciphertextTooShort
    case weakKey
    case authenticationFailure
    case invalidData(String)
}
