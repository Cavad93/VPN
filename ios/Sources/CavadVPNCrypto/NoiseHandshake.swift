// NoiseHandshake.swift — Noise_XX initiator handshake (wire-compatible with Go server)
//
// Pattern:
//   -> e              (Message 1: 32 bytes)
//   <- e, ee, s, es   (Message 2: 80 bytes)
//   -> s, se          (Message 3: 48 bytes)

import Foundation
import Crypto

// MARK: - Protocol constants

private let protocolName = "Noise_XX_25519_ChaChaPoly_SHA256"

// MARK: - NoiseSymmetricState

/// Tracks the chaining key and transcript hash during a Noise handshake.
final class NoiseSymmetricState {
    private(set) var h: Data    // transcript hash
    private(set) var ck: Data   // chaining key
    private var cs: NoiseCipherState

    init() {
        let nameBytes = Data(protocolName.utf8)
        // Per Noise spec: if len(name) <= HASHLEN, pad with zeros; else SHA-256.
        let initial: Data
        if nameBytes.count <= keySize {
            var padded = Data(repeating: 0, count: keySize)
            padded.replaceSubrange(0..<nameBytes.count, with: nameBytes)
            initial = padded
        } else {
            initial = Data(SHA256.hash(data: nameBytes))
        }
        h  = initial
        ck = initial
        cs = NoiseCipherState()
    }

    func mixHash(_ data: Data) {
        var hasher = SHA256()
        hasher.update(data: h)
        hasher.update(data: data)
        h = Data(hasher.finalize())
    }

    func mixKey(_ ikm: Data) {
        let outputs = noiseHKDF(ck: ck, ikm: ikm, n: 2)
        ck = outputs[0]
        cs = NoiseCipherState()
        cs.initializeKey(outputs[1])
    }

    func encryptAndHash(_ plaintext: Data) throws -> Data {
        let ciphertext = try cs.hasKey
            ? cs.encrypt(plaintext: plaintext, aad: h)
            : plaintext
        mixHash(ciphertext)
        return ciphertext
    }

    func decryptAndHash(_ ciphertext: Data) throws -> Data {
        let plaintext = try cs.hasKey
            ? cs.decrypt(ciphertext: ciphertext, aad: h)
            : ciphertext
        mixHash(ciphertext)
        return plaintext
    }

    func split() -> (NoiseCipherState, NoiseCipherState) {
        let outputs = noiseHKDF(ck: ck, ikm: Data(), n: 2)
        let c1 = NoiseCipherState()
        c1.initializeKey(outputs[0])
        let c2 = NoiseCipherState()
        c2.initializeKey(outputs[1])
        return (c1, c2)
    }
}

// MARK: - NoiseSession

/// Result of a completed Noise_XX handshake.
public struct NoiseSession {
    public let sendCipher: NoiseCipherState
    public let recvCipher: NoiseCipherState
    public let remoteStatic: Data  // 32-byte peer public key

    init(sendCipher: NoiseCipherState, recvCipher: NoiseCipherState, remoteStatic: Data) {
        self.sendCipher   = sendCipher
        self.recvCipher   = recvCipher
        self.remoteStatic = remoteStatic
    }
}

// MARK: - NoiseHandshake

/// Noise_XX initiator (client-side) handshake.
public final class NoiseHandshake {
    private let staticKP: KeyPair
    private let ss = NoiseSymmetricState()
    private var ephemeralKP: KeyPair?
    private var remoteEphemeral: Data?
    private var remoteStatic: Data?
    private var step = 0

    public init(staticKP: KeyPair) {
        self.staticKP = staticKP
        ss.mixHash(Data()) // empty prologue
    }

    // MARK: Message 1: -> e

    /// Generates an ephemeral key pair, mixes the public key into h, and returns the 32-byte public key.
    public func writeMessage1() throws -> Data {
        guard step == 0 else { throw NoiseError.invalidStep(step) }
        let eph = generateKeyPair()
        ephemeralKP = eph
        ss.mixHash(eph.publicKey)
        step = 1
        return eph.publicKey
    }

    // MARK: Message 2: <- e, ee, s, es

    /// Processes the 80-byte server message: re.pub(32) + EncryptAndHash(s)(48).
    public func readMessage2(_ msg: Data) throws {
        guard step == 1 else { throw NoiseError.invalidStep(step) }
        let minLen = keySize + keySize + aeadOverhead   // 32 + 32 + 16 = 80
        guard msg.count >= minLen else { throw NoiseError.messageTooShort(msg.count, minLen) }
        guard let eph = ephemeralKP else { throw NoiseError.internalError("no ephemeral key") }

        // <- e
        let re = msg.prefix(keySize)
        remoteEphemeral = re
        ss.mixHash(re)

        // ee = DH(e_init, e_resp)
        let ee = try diffieHellman(privateKey: eph.privateKey, publicKey: Data(re))
        ss.mixKey(ee)

        // s: decrypt remote static
        let encS = msg[keySize ..< keySize + keySize + aeadOverhead]
        let rs = try ss.decryptAndHash(Data(encS))
        remoteStatic = rs

        // es = DH(e_init, s_resp)
        let es = try diffieHellman(privateKey: eph.privateKey, publicKey: rs)
        ss.mixKey(es)

        step = 2
    }

    // MARK: Message 3: -> s, se

    /// Encrypts our static public key, does se DH mix, splits into send/recv ciphers.
    /// - Returns: `(48-byte message, NoiseSession)`
    public func writeMessage3() throws -> (Data, NoiseSession) {
        guard step == 2 else { throw NoiseError.invalidStep(step) }
        guard let re = remoteEphemeral else { throw NoiseError.internalError("no remote ephemeral") }
        guard let rs = remoteStatic    else { throw NoiseError.internalError("no remote static") }

        // s: encrypt our static public key
        let encS = try ss.encryptAndHash(staticKP.publicKey)

        // se = DH(s_init, e_resp)
        let se = try diffieHellman(privateKey: staticKP.privateKey, publicKey: re)
        ss.mixKey(se)

        // split
        let (sendCs, recvCs) = ss.split()
        step = 3
        return (encS, NoiseSession(sendCipher: sendCs, recvCipher: recvCs, remoteStatic: rs))
    }
}

// MARK: - Errors

public enum NoiseError: Error {
    case invalidStep(Int)
    case messageTooShort(Int, Int)
    case internalError(String)
}
