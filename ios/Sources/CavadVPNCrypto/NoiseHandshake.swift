/// NoiseHandshake.swift — Noise_XX handshake (initiator/client side)
///
/// Pattern:  -> e  |  <- e, ee, s, es  |  -> s, se
///
/// Wire-compatible with:
///   - Go server (server/crypto/handshake.go)
///   - Python client (client/core.py — NoiseHandshake class)
///   - Kotlin Android (NoiseHandshake.kt)

import Foundation
import Crypto

// MARK: - Protocol name

private let PROTOCOL_NAME = "Noise_XX_25519_ChaChaPoly_SHA256"

// MARK: - NoiseCipherState

/// Manages a ChaCha20-Poly1305 cipher with an auto-incrementing nonce counter.
///
/// Nonce format: 4 zero bytes + 8-byte little-endian counter (12 bytes total).
/// This matches the Python and Kotlin implementations.
public class NoiseCipherState {
    private var key: [UInt8]
    private var counter: UInt64 = 0

    public init(key: [UInt8]) {
        precondition(key.count == KEY_SIZE, "NoiseCipherState: key must be \(KEY_SIZE) bytes")
        self.key = key
    }

    public func encrypt(_ plaintext: [UInt8], aad: [UInt8] = []) throws -> [UInt8] {
        let nonce = buildNonce(counter)
        counter += 1
        return try chaCha20Poly1305Encrypt(key: key, nonce: nonce, plaintext: plaintext, aad: aad)
    }

    public func decrypt(_ ciphertext: [UInt8], aad: [UInt8] = []) throws -> [UInt8] {
        let nonce = buildNonce(counter)
        counter += 1
        return try chaCha20Poly1305Decrypt(key: key, nonce: nonce, ciphertext: ciphertext, aad: aad)
    }

    /// Build 12-byte nonce: 4 zero bytes + 8-byte little-endian counter.
    private func buildNonce(_ n: UInt64) -> [UInt8] {
        var nonce = [UInt8](repeating: 0, count: NONCE_SIZE)
        // bytes 0..3 are already zero
        // bytes 4..11: little-endian uint64
        var val = n
        for i in 4..<12 {
            nonce[i] = UInt8(val & 0xFF)
            val >>= 8
        }
        return nonce
    }
}

// MARK: - NoiseSymmetricState

/// Tracks the chaining key and transcript hash during a Noise handshake.
internal class NoiseSymmetricState {
    var ck: [UInt8]
    var h: [UInt8]
    var cs: NoiseCipherState?

    init() {
        let nameBytes = Array(PROTOCOL_NAME.utf8)
        // Noise spec: if len(name) <= HASHLEN, pad with zeros; else SHA-256
        let initial: [UInt8]
        if nameBytes.count <= KEY_SIZE {
            var padded = [UInt8](repeating: 0, count: KEY_SIZE)
            padded.replaceSubrange(0..<nameBytes.count, with: nameBytes)
            initial = padded
        } else {
            initial = Array(SHA256.hash(data: Data(nameBytes)))
        }
        self.ck = initial
        self.h = initial
    }

    func mixHash(_ data: [UInt8]) {
        var hasher = SHA256()
        hasher.update(data: Data(h))
        hasher.update(data: Data(data))
        h = Array(hasher.finalize())
    }

    func mixKey(_ ikm: [UInt8]) {
        let outputs = noiseHKDF(ck: ck, ikm: ikm, n: 2)
        ck = outputs[0]
        cs = NoiseCipherState(key: outputs[1])
    }

    func encryptAndHash(_ plaintext: [UInt8]) throws -> [UInt8] {
        let ciphertext: [UInt8]
        if let cs = cs {
            ciphertext = try cs.encrypt(plaintext, aad: h)
        } else {
            ciphertext = plaintext
        }
        mixHash(ciphertext)
        return ciphertext
    }

    func decryptAndHash(_ ciphertext: [UInt8]) throws -> [UInt8] {
        let plaintext: [UInt8]
        if let cs = cs {
            plaintext = try cs.decrypt(ciphertext, aad: h)
        } else {
            plaintext = ciphertext
        }
        mixHash(ciphertext)
        return plaintext
    }

    func split() -> (NoiseCipherState, NoiseCipherState) {
        let outputs = noiseHKDF(ck: ck, ikm: [], n: 2)
        return (NoiseCipherState(key: outputs[0]), NoiseCipherState(key: outputs[1]))
    }
}

// MARK: - NoiseSession

/// Result of a completed Noise_XX handshake.
public struct NoiseSession {
    /// Cipher for encrypting outgoing messages (initiator → responder).
    public let sendCipher: NoiseCipherState
    /// Cipher for decrypting incoming messages (responder → initiator).
    public let recvCipher: NoiseCipherState
    /// 32-byte public key of the authenticated remote peer.
    public let remoteStatic: [UInt8]

    public init(sendCipher: NoiseCipherState, recvCipher: NoiseCipherState, remoteStatic: [UInt8]) {
        self.sendCipher = sendCipher
        self.recvCipher = recvCipher
        self.remoteStatic = remoteStatic
    }
}

// MARK: - Noise errors

public enum NoiseError: Error {
    case invalidStep(Int)
    case messageTooShort(Int, Int)
}

// MARK: - NoiseHandshake (initiator)

/// Noise_XX handshake for the initiator (client) role.
///
/// Pattern:
/// ```
/// -> e              (message 1: send ephemeral public key)
/// <- e, ee, s, es   (message 2: recv responder's ephemeral + encrypted static)
/// -> s, se          (message 3: send encrypted initiator static)
/// ```
public class NoiseHandshake {
    private let staticKP: KeyPair
    private let ss = NoiseSymmetricState()
    private var e: KeyPair?        // our ephemeral key pair
    private var re: [UInt8]?       // remote ephemeral public key
    private var rs: [UInt8]?       // remote static public key
    private var step = 0

    public init(staticKeyPair: KeyPair) {
        self.staticKP = staticKeyPair
        // Empty prologue: mix hash of empty bytes
        ss.mixHash([])
    }

    /// Message 1 (-> e): generate ephemeral key pair, mix hash, return 32-byte public key.
    public func writeMessage1() throws -> [UInt8] {
        guard step == 0 else { throw NoiseError.invalidStep(step) }
        let eph = generateKeyPair()
        e = eph
        ss.mixHash(eph.publicKeyBytes)
        step = 1
        return eph.publicKeyBytes
    }

    /// Message 2 (<- e, ee, s, es): process 80-byte server message.
    /// Expected format: re_pub(32) + EncryptAndHash(s)(48)
    public func readMessage2(_ msg: [UInt8]) throws {
        guard step == 1 else { throw NoiseError.invalidStep(step) }
        let minLen = KEY_SIZE + KEY_SIZE + AEAD_OVERHEAD  // 80 bytes
        guard msg.count >= minLen else {
            throw NoiseError.messageTooShort(msg.count, minLen)
        }

        // <- e: remote ephemeral
        let re_ = Array(msg[0..<KEY_SIZE])
        re = re_
        ss.mixHash(re_)

        // ee: DH(e_init, e_resp)
        guard let e = e else { throw NoiseError.invalidStep(step) }
        let ee = try diffieHellman(privateKey: e.privateKey, publicKeyBytes: re_)
        ss.mixKey(ee)

        // s: decrypt remote static public key
        let encS = Array(msg[KEY_SIZE..<(KEY_SIZE + KEY_SIZE + AEAD_OVERHEAD)])
        let plainS = try ss.decryptAndHash(encS)
        rs = plainS

        // es: DH(e_init, s_resp)
        guard let rs = rs else { throw NoiseError.invalidStep(step) }
        let es = try diffieHellman(privateKey: e.privateKey, publicKeyBytes: rs)
        ss.mixKey(es)

        step = 2
    }

    /// Message 3 (-> s, se): encrypt static key, perform se DH, split into session ciphers.
    /// Returns (48-byte message, NoiseSession).
    public func writeMessage3() throws -> ([UInt8], NoiseSession) {
        guard step == 2 else { throw NoiseError.invalidStep(step) }

        // s: encrypt our static public key
        let encS = try ss.encryptAndHash(staticKP.publicKeyBytes)

        // se: DH(s_init, e_resp)
        guard let re = re else { throw NoiseError.invalidStep(step) }
        let se = try diffieHellman(privateKey: staticKP.privateKey, publicKeyBytes: re)
        ss.mixKey(se)

        // split into send/recv ciphers
        let (sendCipher, recvCipher) = ss.split()

        guard let rs = rs else { throw NoiseError.invalidStep(step) }
        let session = NoiseSession(
            sendCipher: sendCipher,
            recvCipher: recvCipher,
            remoteStatic: rs
        )

        step = 3
        return (encS, session)
    }
}
