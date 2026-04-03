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
    private var readBuf = Data()

    public init(inputStream: InputStream, outputStream: OutputStream) {
        self.inputStream  = inputStream
        self.outputStream = outputStream
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
        let hdr = try readFully(obfsHeaderSize)
        guard hdr[0] == wantType else {
            throw ObfsError.unexpectedRecordType(got: hdr[0], want: wantType)
        }
        let length = Int(hdr[3]) << 8 | Int(hdr[4])
        guard length > 0, length <= maxObfsPayload else {
            throw ObfsError.invalidRecordLength(length)
        }
        return try readFully(length)
    }

    private func readHandshakeRecord(wantMsgType: UInt8) throws {
        let payload = try readRecord(wantType: tlsHandshake)
        guard payload.count >= 4 else { throw ObfsError.handshakeTooShort }
        guard payload[0] == wantMsgType else {
            throw ObfsError.unexpectedHandshakeType(got: payload[0], want: wantMsgType)
        }
    }

    // MARK: TLS record builders

    private func buildClientHello() -> Data {
        let random    = generateRandomData(count: 32)
        let sessionId = generateRandomData(count: 32)

        var body = Data()
        body.append(contentsOf: [0x03, 0x03])  // legacy_version = TLS 1.2
        body.append(random)
        body.append(0x20)                       // session_id length = 32
        body.append(sessionId)
        // cipher suites: TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256
        body.append(contentsOf: [0x00, 0x06, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03])
        body.append(contentsOf: [0x01, 0x00])  // compression_methods: length=1, null

        return wrapHandshakeRecord(msgType: tlsHelloClient, body: body)
    }

    private func buildServerHello() -> Data {
        let random = generateRandomData(count: 32)

        var body = Data()
        body.append(contentsOf: [0x03, 0x03])  // legacy_version = TLS 1.2
        body.append(random)
        body.append(0x00)                       // session_id length = 0
        body.append(contentsOf: [0x13, 0x01])  // cipher_suite: TLS_AES_128_GCM_SHA256
        body.append(0x00)                       // compression_method: null

        return wrapHandshakeRecord(msgType: tlsHelloServer, body: body)
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
