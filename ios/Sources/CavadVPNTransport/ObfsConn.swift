// ObfsConn.swift — TLS obfuscation wrapper (wire-compatible with Go server transport/obfs.go)
//
// Wraps a byte-stream connection inside synthetic TLS records so DPI systems
// classify the traffic as ordinary HTTPS. Does NOT provide cryptographic security —
// that is handled by the Noise layer above it.
//
// Wire format (data record):
//   byte 0      — content_type (0x17 = application_data)
//   bytes 1-2   — version (0x03 0x03)
//   bytes 3-4   — payload length (big-endian uint16)
//   bytes 5..N  — payload

import Foundation
import Security
import Crypto
import CavadVPNCrypto

// MARK: - TLS constants

private let tlsHandshake: UInt8 = 0x16
private let tlsAppData:   UInt8 = 0x17
private let tlsHelloClient: UInt8 = 0x01
private let tlsHelloServer: UInt8 = 0x02
private let tlsVersionMajor: UInt8 = 0x03
private let tlsVersionMinor: UInt8 = 0x03
private let obfsHeaderSize = 5
private let maxObfsPayload = 16383  // 2^14 - 1

// MARK: - ObfsConn

/// TLS-obfuscation layer over a raw TCP socket.
public final class ObfsConn {
    private let inputStream:  InputStream
    private let outputStream: OutputStream
    /// Optional 32-byte port-knock PSK. When non-nil, the synthetic
    /// ClientHello carries `session_id = HMAC-SHA256(knockKey, random)`
    /// so the relay can authenticate the VPN client before forwarding.
    /// Wire-compatible with the Android `ObfsConn(knockKey)` constructor
    /// and the Go relay verifier in `server/transport/knock_test.go`.
    private let knockKey: Data?
    private var readBuf = Data()

    public init(
        inputStream: InputStream,
        outputStream: OutputStream,
        knockKey: Data? = nil
    ) {
        self.inputStream  = inputStream
        self.outputStream = outputStream
        // Reject malformed knock keys silently so a partial/empty hex
        // string in the user config falls back to the regular random
        // session_id rather than producing an invalid HMAC the server
        // would reject.
        self.knockKey = (knockKey?.count == 32) ? knockKey : nil
    }

    // MARK: Handshake

    /// Client side: send synthetic ClientHello, receive ServerHello.
    public func clientHandshake() throws {
        let hello = buildClientHello()
        try writeRaw(hello)
        try readHandshakeRecord(wantMsgType: tlsHelloServer)
    }

    /// Server side: read ClientHello, send synthetic ServerHello.
    public func serverHandshake() throws {
        try readHandshakeRecord(wantMsgType: tlsHelloClient)
        let hello = buildServerHello()
        try writeRaw(hello)
    }

    // MARK: Data I/O

    /// Sends data as one or more TLS application_data records (max 16383 bytes each).
    public func write(_ data: Data) throws {
        var offset = data.startIndex
        while offset < data.endIndex {
            let end = data.index(offset, offsetBy: min(maxObfsPayload, data.distance(from: offset, to: data.endIndex)))
            let chunk = data[offset..<end]
            try writeRaw(buildAppDataRecord(Data(chunk)))
            offset = end
        }
    }

    /// Reads exactly `n` bytes, buffering across TLS records as needed.
    public func read(_ n: Int) throws -> Data {
        while readBuf.count < n {
            let payload = try readRecord(wantType: tlsAppData)
            readBuf.append(payload)
        }
        let result = readBuf.prefix(n)
        readBuf.removeFirst(n)
        return Data(result)
    }

    /// Synonym for `read(_:)`.
    public func readExactly(_ n: Int) throws -> Data { try read(n) }

    /// Closes both streams.
    public func close() {
        inputStream.close()
        outputStream.close()
    }

    // MARK: Internal helpers

    private func writeRaw(_ data: Data) throws {
        var remaining = data
        while !remaining.isEmpty {
            let written = remaining.withUnsafeBytes { ptr -> Int in
                guard let base = ptr.baseAddress else { return 0 }
                return outputStream.write(base.assumingMemoryBound(to: UInt8.self), maxLength: remaining.count)
            }
            if written <= 0 {
                throw ObfsError.writeFailed
            }
            remaining = remaining.dropFirst(written)
        }
    }

    private func readFully(_ n: Int) throws -> Data {
        var buf = Data(count: n)
        var filled = 0
        while filled < n {
            let r = buf.withUnsafeMutableBytes { ptr -> Int in
                guard let base = ptr.baseAddress else { return 0 }
                return inputStream.read(
                    base.advanced(by: filled).assumingMemoryBound(to: UInt8.self),
                    maxLength: n - filled
                )
            }
            if r <= 0 { throw ObfsError.connectionClosed }
            filled += r
        }
        return buf
    }

    private func readRecord(wantType: UInt8) throws -> Data {
        while true {
            let hdr = try readFully(obfsHeaderSize)
            let gotType = hdr[0]
            // Skip ChangeCipherSpec records (TLS 1.3 middlebox compat, RFC 8446 §5.1).
            // The Go server sends CCS immediately after ServerHello in one write;
            // without this skip the first read() after handshake would throw.
            if gotType == 0x14 {
                let length = Int(hdr[3]) << 8 | Int(hdr[4])
                if length > 0, length <= maxObfsPayload {
                    _ = try readFully(length)
                }
                continue
            }
            guard gotType == wantType else {
                throw ObfsError.unexpectedRecordType(got: gotType, want: wantType)
            }
            let length = Int(hdr[3]) << 8 | Int(hdr[4])
            guard length > 0, length <= maxObfsPayload else {
                throw ObfsError.invalidRecordLength(length)
            }
            return try readFully(length)
        }
    }

    private func readHandshakeRecord(wantMsgType: UInt8) throws {
        let payload = try readRecord(wantType: tlsHandshake)
        guard payload.count >= 4 else { throw ObfsError.handshakeTooShort }
        guard payload[0] == wantMsgType else {
            throw ObfsError.unexpectedHandshakeType(got: payload[0], want: wantMsgType)
        }
    }

    // MARK: - Chrome-120 ClientHello builder

    // 16 GREASE pseudo-values (RFC 8701). Browsers insert these into cipher
    // suite lists, extension type fields, and named group lists to prevent
    // protocol ossification. TSPU uses JA3/JA4 fingerprinting to detect VPN
    // clients; matching Chrome's GREASE pattern defeats it.
    private let greaseTable: [UInt16] = [
        0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A,
        0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
        0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
        0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
    ]

    private func pickGrease() -> UInt16 {
        var b: UInt8 = 0
        SecRandomCopyBytes(kSecRandomDefault, 1, &b)
        return greaseTable[Int(b & 0x0F)]
    }

    private func u16(_ v: UInt16) -> [UInt8] { [UInt8(v >> 8), UInt8(v & 0xFF)] }

    private func buildExt(_ type: UInt16, _ data: [UInt8] = []) -> [UInt8] {
        u16(type) + u16(UInt16(data.count)) + data
    }

    private func buildSupportedGroupsExt(_ grease: UInt16) -> [UInt8] {
        buildExt(0x000A, [0x00, 0x08] + u16(grease) + [0x00, 0x1D, 0x00, 0x17, 0x00, 0x18])
    }

    private func buildALPNExt() -> [UInt8] {
        buildExt(0x0010, [
            0x00, 0x0E,
            0x00, 0x02, 0x68, 0x32,
            0x00, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2F, 0x31, 0x2E, 0x31,
        ])
    }

    private func buildSigAlgsExt() -> [UInt8] {
        buildExt(0x000D, [
            0x00, 0x10,
            0x04, 0x03, 0x08, 0x04, 0x04, 0x01,
            0x05, 0x03, 0x08, 0x05, 0x05, 0x01,
            0x08, 0x06, 0x06, 0x01,
        ])
    }

    private func buildKeyShareExt(_ grease: UInt16) -> [UInt8] {
        let x25519Key = Array(generateRandomData(count: 32))
        var entries = u16(grease) + [0x00, 0x01, 0x00]
        entries += [0x00, 0x1D, 0x00, 0x20] + x25519Key
        return buildExt(0x0033, u16(UInt16(entries.count)) + entries)
    }

    private func buildSupportedVersionsClientExt(_ grease: UInt16) -> [UInt8] {
        buildExt(0x002B, [0x06] + u16(grease) + [0x03, 0x04, 0x03, 0x03])
    }

    private func buildCompressCertExt() -> [UInt8] {
        buildExt(0x001B, [0x02, 0x00, 0x02, 0x00, 0x01])
    }

    // MARK: TLS record builders

    /// Builds a Chrome-120-equivalent ClientHello.
    ///
    /// Record header uses 0x0301 (legacy TLS 1.0) — Chrome/Firefox/Safari behavior
    /// per RFC 8446 §5.1. Using 0x0303 here is a known non-browser JA3 signal.
    private func buildClientHello() -> Data {
        let random = generateRandomData(count: 32)
        let sessionId: Data
        if let key = knockKey {
            let mac = HMAC<SHA256>.authenticationCode(for: random, using: SymmetricKey(data: key))
            sessionId = Data(mac)
        } else {
            sessionId = generateRandomData(count: 32)
        }

        let greaseCS  = pickGrease()
        let greaseE1  = pickGrease()
        let greaseE2  = pickGrease()
        let greaseGrp = pickGrease()
        let greaseVer = pickGrease()
        let greaseKS  = pickGrease()

        var cipherSuites: [UInt8] = u16(greaseCS) + [
            0x13, 0x01, 0x13, 0x02, 0x13, 0x03,
            0xC0, 0x2B, 0xC0, 0x2F, 0xC0, 0x2C, 0xC0, 0x30,
            0xCC, 0xA9, 0xCC, 0xA8,
            0xC0, 0x13, 0xC0, 0x14,
            0x00, 0x9C, 0x00, 0x9D,
            0x00, 0x2F, 0x00, 0x35,
        ]

        var exts: [UInt8] = []
        exts += buildExt(greaseE1, [0x00, 0x00])
        exts += buildExt(0x0017)
        exts += buildExt(0xFF01, [0x00])
        exts += buildSupportedGroupsExt(greaseGrp)
        exts += buildExt(0x000B, [0x01, 0x00])
        exts += buildExt(0x0023)
        exts += buildALPNExt()
        exts += buildExt(0x0005, [0x01, 0x00, 0x00, 0x00, 0x00])
        exts += buildSigAlgsExt()
        exts += buildExt(0x0012)
        exts += buildKeyShareExt(greaseKS)
        exts += buildExt(0x002D, [0x01, 0x01])
        exts += buildSupportedVersionsClientExt(greaseVer)
        exts += buildCompressCertExt()
        exts += buildExt(greaseE2, [0x00, 0x00])

        var body = Data()
        body.append(contentsOf: [0x03, 0x03])
        body.append(random)
        body.append(0x20)
        body.append(sessionId)
        body.append(contentsOf: u16(UInt16(cipherSuites.count)))
        body.append(contentsOf: cipherSuites)
        body.append(contentsOf: [0x01, 0x00])
        body.append(contentsOf: u16(UInt16(exts.count)))
        body.append(contentsOf: exts)

        return wrapClientHelloRecord(body: body)
    }

    private func buildServerHello() -> Data {
        let random      = generateRandomData(count: 32)
        let sessionEcho = generateRandomData(count: 32)
        let verExt: [UInt8] = buildExt(0x002B, [0x03, 0x04])

        var body = Data()
        body.append(contentsOf: [0x03, 0x03])
        body.append(random)
        body.append(0x20)
        body.append(sessionEcho)
        body.append(contentsOf: [0x13, 0x01])
        body.append(0x00)
        body.append(contentsOf: u16(UInt16(verExt.count)))
        body.append(contentsOf: verExt)

        return wrapHandshakeRecord(msgType: tlsHelloServer, body: body)
    }

    /// ClientHello record uses legacy version 0x0301 (TLS 1.0), not 0x0303.
    private func wrapClientHelloRecord(body: Data) -> Data {
        let hsLen = body.count
        var hs = Data()
        hs.append(tlsHelloClient)
        hs.append(UInt8((hsLen >> 16) & 0xFF))
        hs.append(UInt8((hsLen >>  8) & 0xFF))
        hs.append(UInt8( hsLen        & 0xFF))
        hs.append(body)

        var rec = Data()
        rec.append(tlsHandshake)
        rec.append(0x03)
        rec.append(0x01)  // legacy TLS 1.0 record version (Chrome/Firefox/Safari)
        rec.append(UInt8((hs.count >> 8) & 0xFF))
        rec.append(UInt8( hs.count       & 0xFF))
        rec.append(hs)
        return rec
    }

    private func wrapHandshakeRecord(msgType: UInt8, body: Data) -> Data {
        let hsLen = body.count
        var hs = Data()
        hs.append(msgType)
        hs.append(UInt8((hsLen >> 16) & 0xFF))
        hs.append(UInt8((hsLen >>  8) & 0xFF))
        hs.append(UInt8( hsLen        & 0xFF))
        hs.append(body)

        var rec = Data()
        rec.append(tlsHandshake)
        rec.append(tlsVersionMajor)
        rec.append(tlsVersionMinor)
        rec.append(UInt8((hs.count >> 8) & 0xFF))
        rec.append(UInt8( hs.count       & 0xFF))
        rec.append(hs)
        return rec
    }

    private func buildAppDataRecord(_ payload: Data) -> Data {
        var rec = Data()
        rec.append(tlsAppData)
        rec.append(tlsVersionMajor)
        rec.append(tlsVersionMinor)
        rec.append(UInt8((payload.count >> 8) & 0xFF))
        rec.append(UInt8( payload.count       & 0xFF))
        rec.append(payload)
        return rec
    }
}

// MARK: - Errors

public enum ObfsError: Error {
    case connectionClosed
    case writeFailed
    case unexpectedRecordType(got: UInt8, want: UInt8)
    case invalidRecordLength(Int)
    case handshakeTooShort
    case unexpectedHandshakeType(got: UInt8, want: UInt8)
}
