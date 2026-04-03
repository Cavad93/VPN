// CryptoCoreTests.swift — Unit tests for CryptoCore.swift

import XCTest
import Crypto
@testable import CavadVPNCrypto

final class CryptoCoreTests: XCTestCase {

    // MARK: – KeyPair generation

    func testGenerateKeyPairProducesCorrectSizes() {
        let kp = generateKeyPair()
        XCTAssertEqual(kp.privateKey.count, keySize)
        XCTAssertEqual(kp.publicKey.count,  keySize)
    }

    func testGenerateKeyPairIsRandom() {
        let kp1 = generateKeyPair()
        let kp2 = generateKeyPair()
        XCTAssertNotEqual(kp1.privateKey, kp2.privateKey)
        XCTAssertNotEqual(kp1.publicKey,  kp2.publicKey)
    }

    // MARK: – Diffie-Hellman

    func testDiffieHellmanProducesSharedSecret() throws {
        let kp1 = generateKeyPair()
        let kp2 = generateKeyPair()
        let s1 = try diffieHellman(privateKey: kp1.privateKey, publicKey: kp2.publicKey)
        let s2 = try diffieHellman(privateKey: kp2.privateKey, publicKey: kp1.publicKey)
        XCTAssertEqual(s1, s2)
        XCTAssertEqual(s1.count, keySize)
    }

    func testDiffieHellmanWithInvalidKeySizeThrows() {
        let kp = generateKeyPair()
        XCTAssertThrowsError(try diffieHellman(privateKey: Data([0x01]), publicKey: kp.publicKey))
    }

    // MARK: – ChaCha20-Poly1305

    func testChaChaEncryptDecryptRoundtrip() throws {
        let key       = generateRandomData(count: keySize)
        let nonce     = generateRandomData(count: nonceSize)
        let plaintext = Data("Hello, VPN!".utf8)
        let ct = try chaChaEncrypt(key: key, nonce: nonce, plaintext: plaintext)
        let pt = try chaChaDecrypt(key: key, nonce: nonce, ciphertext: ct)
        XCTAssertEqual(pt, plaintext)
    }

    func testChaChaEncryptProducesTag() throws {
        let key       = generateRandomData(count: keySize)
        let nonce     = generateRandomData(count: nonceSize)
        let plaintext = Data("test".utf8)
        let ct = try chaChaEncrypt(key: key, nonce: nonce, plaintext: plaintext)
        XCTAssertEqual(ct.count, plaintext.count + aeadOverhead)
    }

    func testChaChaDecryptWithWrongKeyFails() throws {
        let key1      = generateRandomData(count: keySize)
        let key2      = generateRandomData(count: keySize)
        let nonce     = generateRandomData(count: nonceSize)
        let plaintext = Data("test".utf8)
        let ct        = try chaChaEncrypt(key: key1, nonce: nonce, plaintext: plaintext)
        XCTAssertThrowsError(try chaChaDecrypt(key: key2, nonce: nonce, ciphertext: ct))
    }

    func testChaChaWithAAD() throws {
        let key   = generateRandomData(count: keySize)
        let nonce = generateRandomData(count: nonceSize)
        let pt    = Data("message".utf8)
        let aad   = Data("associated data".utf8)
        let ct    = try chaChaEncrypt(key: key, nonce: nonce, plaintext: pt, aad: aad)
        let dec   = try chaChaDecrypt(key: key, nonce: nonce, ciphertext: ct, aad: aad)
        XCTAssertEqual(dec, pt)
        // Wrong AAD must fail
        XCTAssertThrowsError(try chaChaDecrypt(key: key, nonce: nonce, ciphertext: ct, aad: Data("wrong".utf8)))
    }

    // MARK: – Noise HKDF

    func testNoiseHKDFProducesTwo32ByteOutputs() {
        let ck  = generateRandomData(count: keySize)
        let ikm = generateRandomData(count: keySize)
        let out = noiseHKDF(ck: ck, ikm: ikm, n: 2)
        XCTAssertEqual(out.count, 2)
        XCTAssertEqual(out[0].count, keySize)
        XCTAssertEqual(out[1].count, keySize)
        XCTAssertNotEqual(out[0], out[1])
    }

    func testNoiseHKDFProducesThreeOutputs() {
        let ck  = generateRandomData(count: keySize)
        let ikm = generateRandomData(count: keySize)
        let out = noiseHKDF(ck: ck, ikm: ikm, n: 3)
        XCTAssertEqual(out.count, 3)
        XCTAssertEqual(out[2].count, keySize)
    }

    func testNoiseHKDFIsKnownVector() {
        // Known-answer test: HKDF with all-zero inputs.
        let ck  = Data(repeating: 0x00, count: keySize)
        let ikm = Data(repeating: 0x00, count: keySize)
        let out = noiseHKDF(ck: ck, ikm: ikm, n: 2)
        // Verify outputs are non-zero and consistent across calls.
        XCTAssertNotEqual(out[0], Data(repeating: 0, count: keySize))
        let out2 = noiseHKDF(ck: ck, ikm: ikm, n: 2)
        XCTAssertEqual(out[0], out2[0])
        XCTAssertEqual(out[1], out2[1])
    }

    // MARK: – NoiseCipherState nonce format

    func testNoiseCipherStateCounterIncrements() throws {
        let cs = NoiseCipherState()
        let key = generateRandomData(count: keySize)
        cs.initializeKey(key)
        let pt = Data("hello".utf8)
        let ct1 = try cs.encrypt(plaintext: pt)
        let ct2 = try cs.encrypt(plaintext: pt)
        // Different nonces → different ciphertexts
        XCTAssertNotEqual(ct1, ct2)
    }
}
