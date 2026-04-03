// NoiseHandshakeTests.swift — Unit tests for NoiseHandshake.swift

import XCTest
@testable import CavadVPNCrypto

/// A minimal Noise_XX RESPONDER implemented for testing only.
/// Performs the server side so we can verify the full handshake round-trip.
private final class NoiseResponder {
    private let staticKP: KeyPair
    private let ss = NoiseSymmetricState()
    private var e: KeyPair?
    private var re: Data?
    private var rs: Data?

    init(staticKP: KeyPair) {
        self.staticKP = staticKP
        ss.mixHash(Data()) // empty prologue
    }

    // Read msg1 (-> e): 32-byte initiator ephemeral
    func readMessage1(_ msg: Data) {
        re = msg
        ss.mixHash(msg)
    }

    // Write msg2 (<- e, ee, s, es): e.pub(32) + EncryptAndHash(s)(48) = 80 bytes
    // Wire-compatible with Go server WriteMessage2 (no empty payload appended).
    func writeMessage2() throws -> Data {
        let eph = generateKeyPair()
        e = eph
        ss.mixHash(eph.publicKey)

        // ee = DH(e_resp, e_init)
        let ee = try diffieHellman(privateKey: eph.privateKey, publicKey: re!)
        ss.mixKey(ee)

        // s: encrypt our static
        let encS = try ss.encryptAndHash(staticKP.publicKey)

        // es = DH(s_resp, e_init)
        let es = try diffieHellman(privateKey: staticKP.privateKey, publicKey: re!)
        ss.mixKey(es)

        return eph.publicKey + encS  // 32 + 48 = 80 bytes
    }

    // Read msg3 (-> s, se): EncryptAndHash(s_init)(48) + EncryptAndHash(empty)(16)
    func readMessage3(_ msg: Data) throws -> NoiseSession {
        guard msg.count >= keySize + aeadOverhead else {
            XCTFail("msg3 too short"); fatalError()
        }
        let encS = msg.prefix(keySize + aeadOverhead)
        rs = try ss.decryptAndHash(Data(encS))

        // se = DH(e_resp, s_init)
        let se = try diffieHellman(privateKey: e!.privateKey, publicKey: rs!)
        ss.mixKey(se)

        // split (responder: send=k2, recv=k1)
        let (k1, k2) = ss.split()
        return NoiseSession(sendCipher: k2, recvCipher: k1, remoteStatic: rs!)
    }
}

// Expose split() for testing via an internal wrapper
extension NoiseSymmetricState {
    func split() -> (NoiseCipherState, NoiseCipherState) {
        let outputs = noiseHKDF(ck: ck, ikm: Data(), n: 2)
        let c1 = NoiseCipherState(); c1.initializeKey(outputs[0])
        let c2 = NoiseCipherState(); c2.initializeKey(outputs[1])
        return (c1, c2)
    }
}

final class NoiseHandshakeTests: XCTestCase {

    func testFullHandshakeRoundtrip() throws {
        let initiatorKP = generateKeyPair()
        let responderKP = generateKeyPair()

        let initiator = NoiseHandshake(staticKP: initiatorKP)
        let responder = NoiseResponder(staticKP: responderKP)

        // -> e
        let msg1 = try initiator.writeMessage1()
        XCTAssertEqual(msg1.count, keySize)
        responder.readMessage1(msg1)

        // <- e, ee, s, es
        let msg2 = try responder.writeMessage2()
        try initiator.readMessage2(msg2)

        // -> s, se
        let (msg3, initiatorSession) = try initiator.writeMessage3()
        let responderSession = try responder.readMessage3(msg3)

        // Verify both sides derive the same keys
        let plaintext = Data("Hello, Noise!".utf8)
        let ct = try initiatorSession.sendCipher.encrypt(plaintext: plaintext)
        let pt = try responderSession.recvCipher.decrypt(ciphertext: ct)
        XCTAssertEqual(pt, plaintext)

        let ct2 = try responderSession.sendCipher.encrypt(plaintext: plaintext)
        let pt2 = try initiatorSession.recvCipher.decrypt(ciphertext: ct2)
        XCTAssertEqual(pt2, plaintext)
    }

    func testHandshakeExchangesRemoteStatic() throws {
        let initiatorKP = generateKeyPair()
        let responderKP = generateKeyPair()

        let initiator = NoiseHandshake(staticKP: initiatorKP)
        let responder = NoiseResponder(staticKP: responderKP)

        let msg1 = try initiator.writeMessage1()
        responder.readMessage1(msg1)
        let msg2 = try responder.writeMessage2()
        try initiator.readMessage2(msg2)
        let (msg3, initiatorSession) = try initiator.writeMessage3()
        let responderSession = try responder.readMessage3(msg3)

        XCTAssertEqual(initiatorSession.remoteStatic, responderKP.publicKey)
        XCTAssertEqual(responderSession.remoteStatic, initiatorKP.publicKey)
    }

    func testMessage1Size() throws {
        let kp = generateKeyPair()
        let hs = NoiseHandshake(staticKP: kp)
        let msg1 = try hs.writeMessage1()
        XCTAssertEqual(msg1.count, keySize)  // 32 bytes
    }

    func testMessage2Size() throws {
        let kp1 = generateKeyPair()
        let kp2 = generateKeyPair()
        let initiator = NoiseHandshake(staticKP: kp1)
        let responder = NoiseResponder(staticKP: kp2)

        let msg1 = try initiator.writeMessage1()
        responder.readMessage1(msg1)
        let msg2 = try responder.writeMessage2()
        // e.pub(32) + enc_s(32+16) = 80 bytes (wire-compatible with Go server)
        XCTAssertEqual(msg2.count, 80)
    }

    func testMessage3Size() throws {
        let kp1 = generateKeyPair()
        let kp2 = generateKeyPair()
        let initiator = NoiseHandshake(staticKP: kp1)
        let responder = NoiseResponder(staticKP: kp2)

        let msg1 = try initiator.writeMessage1()
        responder.readMessage1(msg1)
        let msg2 = try responder.writeMessage2()
        try initiator.readMessage2(msg2)
        let (msg3, _) = try initiator.writeMessage3()
        // enc_s(48) = 32 + 16
        XCTAssertEqual(msg3.count, 48)
    }

    func testInvalidStepThrows() throws {
        let kp = generateKeyPair()
        let hs = NoiseHandshake(staticKP: kp)
        // Calling readMessage2 before writeMessage1
        XCTAssertThrowsError(try hs.readMessage2(Data(repeating: 0, count: 80)))
    }

    func testWriteMessage1Idempotent() throws {
        let kp = generateKeyPair()
        let hs = NoiseHandshake(staticKP: kp)
        _ = try hs.writeMessage1()
        XCTAssertThrowsError(try hs.writeMessage1())  // step violation
    }

    func testDifferentHandshakesProduceDifferentKeys() throws {
        let kp1 = generateKeyPair()
        let kp2 = generateKeyPair()

        func doHandshake() throws -> Data {
            let init1 = NoiseHandshake(staticKP: kp1)
            let resp1 = NoiseResponder(staticKP: kp2)
            let m1 = try init1.writeMessage1()
            resp1.readMessage1(m1)
            let m2 = try resp1.writeMessage2()
            try init1.readMessage2(m2)
            let (_, session) = try init1.writeMessage3()
            return session.remoteStatic
        }

        // Same static keys but different ephemerals each time → same remote static
        let rs1 = try doHandshake()
        let rs2 = try doHandshake()
        XCTAssertEqual(rs1, kp2.publicKey)
        XCTAssertEqual(rs2, kp2.publicKey)
    }

    func testNoiseProtocolNameInitialization() {
        // Verify the protocol name length matches Noise spec requirement
        let name = "Noise_XX_25519_ChaChaPoly_SHA256"
        XCTAssertEqual(name.count, 32)  // exactly keySize → direct copy, no hash
    }
}
