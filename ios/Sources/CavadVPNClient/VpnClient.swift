// VpnClient.swift — Full VPN client stack
// TCP → TLS obfuscation → Noise_XX → NoiseConn → ClientMux → control/data streams

import Foundation
#if canImport(Darwin)
import Darwin
#endif
import Crypto
import CavadVPNCrypto
import CavadVPNTransport

// MARK: - Control protocol constants (must match Go server main.go)

private let ctlHello:      UInt8 = 0x01
private let ctlAssign:     UInt8 = 0x02  // IPv4-only assignment (10 bytes total)
private let ctlAssignDual: UInt8 = 0x05  // IPv4+IPv6 dual-stack (43 bytes total)
private let ctlError:      UInt8 = 0xFF
private let ctlAssignPayloadLen = 9       // ip4(4) + pfxLen4(1) + gw4(4)
// CTL_ASSIGN_DUAL payload after the type byte:
//   ip4(4) + pfxLen4(1) + gw4(4) + ip6(16) + pfxLen6(1) + gw6(16) = 42 bytes
private let ctlAssignDualPayloadLen = 42

// MARK: - VpnClient

/// Manages a full VPN connection to the CavadVPN server.
///
/// Connection sequence:
///   TCP → ObfsConn (TLS obfuscation) → Noise_XX handshake → NoiseConn → ClientMux
///   → control stream (IP assignment) → data stream (raw IPv4 packets)
public final class VpnClient {
    public let config: VpnConfig

    private var inputStream:  InputStream?
    private var outputStream: OutputStream?
    private var socketFD: Int32 = -1    // raw BSD socket for TCP tuning
    private var obfs: ObfsConn?
    private var noiseConn: NoiseConn?
    private var mux: ClientMux?
    private var dataStream: MuxStream?

    public private(set) var isConnected = false
    public private(set) var routeInfo: RouteInfo?
    public private(set) var serverPublicKey: Data?

    public init(config: VpnConfig) {
        self.config = config
    }

    // MARK: Connect

    /// Performs the full connection sequence.
    /// - Returns: RouteInfo with the assigned IP, prefix length, and gateway.
    @discardableResult
    public func connect() throws -> RouteInfo {
        let kp = loadOrGenerateKeyPair()

        // 1. TCP connect
        var iStream: InputStream?
        var oStream: OutputStream?
        Stream.getStreamsToHost(
            withName: config.serverHost,
            port: config.serverPort,
            inputStream: &iStream,
            outputStream: &oStream
        )
        guard let ins = iStream, let outs = oStream else {
            throw VpnClientError.connectionFailed("failed to create streams")
        }
        ins.open()
        outs.open()
        // Wait for connection (simple busy wait with timeout)
        let deadline = Date().addingTimeInterval(config.connectTimeout)
        while ins.streamStatus == .opening || outs.streamStatus == .opening {
            if Date() > deadline { throw VpnClientError.connectionTimeout }
            Thread.sleep(forTimeInterval: 0.01)
        }
        if ins.streamError  != nil { throw VpnClientError.connectionFailed(ins.streamError!.localizedDescription) }
        if outs.streamError != nil { throw VpnClientError.connectionFailed(outs.streamError!.localizedDescription) }
        inputStream  = ins
        outputStream = outs

        // TCP socket tuning (matches Android VpnClient):
        // - TCP_NODELAY: VPN forwards inner TCP ACKs as small frames; Nagle would
        //   buffer them for up to one RTT (~80-120 ms), killing download throughput.
        // - 4 MB send/receive buffers: BDP for 30 Mbps × 100 ms ≈ 375 KB.
        if let rawSocket = extractSocketFD(from: ins) {
            socketFD = rawSocket
            var flag: Int32 = 1
            setsockopt(rawSocket, IPPROTO_TCP, TCP_NODELAY, &flag, socklen_t(MemoryLayout<Int32>.size))
            var bufSize: Int32 = 4 * 1024 * 1024
            setsockopt(rawSocket, SOL_SOCKET, SO_SNDBUF, &bufSize, socklen_t(MemoryLayout<Int32>.size))
            setsockopt(rawSocket, SOL_SOCKET, SO_RCVBUF, &bufSize, socklen_t(MemoryLayout<Int32>.size))
        }

        // 2. TLS obfuscation. Pass the knock key (when configured) so the
        // synthetic ClientHello carries HMAC-SHA256(key, random) in the
        // session_id field — the relay rejects connections without it,
        // proxying probes to a cover site instead.
        let obfsConn = ObfsConn(
            inputStream: ins,
            outputStream: outs,
            knockKey: config.knockKeyBytes()
        )
        try obfsConn.clientHandshake()
        obfs = obfsConn

        // 3. Noise_XX handshake
        let session = try performNoiseHandshake(kp: kp, obfsConn: obfsConn)
        serverPublicKey = session.remoteStatic

        // Optionally verify pinned server key
        if let pinned = config.serverPublicKeyBytes(), pinned != session.remoteStatic {
            disconnect()
            throw VpnClientError.serverKeyMismatch
        }

        // 4. NoiseConn (encrypted transport)
        let nc = NoiseConn(obfs: obfsConn, session: session)
        noiseConn = nc

        // 5. ClientMux
        let muxConn = ClientMux(conn: nc)
        mux = muxConn

        // 6. Control stream: request IP assignment
        let route = try doControlStream(muxConn)
        routeInfo = route

        // 7. Open data stream for IP packets
        dataStream = try muxConn.openStream()
        isConnected = true

        return route
    }

    // MARK: Data I/O

    /// Sends a raw IPv4 packet over the data stream.
    public func sendPacket(_ packet: Data) throws {
        guard let ds = dataStream else { throw VpnClientError.notConnected }
        try ds.write(packet)
    }

    /// Receives a raw IPv4 packet from the data stream. Blocks until a packet arrives.
    public func recvPacket(timeout: TimeInterval = 30) -> Data {
        return dataStream?.read(timeout: timeout) ?? Data()
    }

    // MARK: Disconnect

    /// Closes all layers gracefully.
    public func disconnect() {
        isConnected = false
        dataStream?.close()
        mux?.close()
        inputStream?.close()
        outputStream?.close()
        dataStream   = nil
        mux          = nil
        noiseConn    = nil
        obfs         = nil
        inputStream  = nil
        outputStream = nil
        socketFD     = -1
    }

    // MARK: Private helpers

    private func loadOrGenerateKeyPair() -> KeyPair {
        if let keyBytes = config.privateKeyBytes(), keyBytes.count == keySize {
            // Reconstruct key pair from stored private key bytes.
            // swift-crypto derives the public key automatically.
            if let priv = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: keyBytes) {
                return KeyPair(privateKey: keyBytes, publicKey: Data(priv.publicKey.rawRepresentation))
            }
        }
        return generateKeyPair()
    }

    private func performNoiseHandshake(kp: KeyPair, obfsConn: ObfsConn) throws -> NoiseSession {
        let hs = NoiseHandshake(staticKP: kp)

        // -> e (32 bytes) with 2-byte BE length prefix
        let msg1 = try hs.writeMessage1()
        try sendHandshakeMsg(obfsConn: obfsConn, msg: msg1)

        // <- e, ee, s, es (80 bytes)
        let msg2 = try recvHandshakeMsg(obfsConn: obfsConn)
        try hs.readMessage2(msg2)

        // -> s, se (48 bytes)
        let (msg3, session) = try hs.writeMessage3()
        try sendHandshakeMsg(obfsConn: obfsConn, msg: msg3)

        return session
    }

    private func sendHandshakeMsg(obfsConn: ObfsConn, msg: Data) throws {
        var prefix = Data(count: 2)
        prefix[0] = UInt8((msg.count >> 8) & 0xFF)
        prefix[1] = UInt8( msg.count       & 0xFF)
        try obfsConn.write(prefix + msg)
    }

    private func recvHandshakeMsg(obfsConn: ObfsConn) throws -> Data {
        let lenBytes = try obfsConn.read(2)
        let length = Int(lenBytes[0]) << 8 | Int(lenBytes[1])
        return try obfsConn.read(length)
    }

    /// Extracts the underlying BSD socket file descriptor from an InputStream
    /// using CFReadStream's kCFStreamPropertySocketNativeHandle.
    private func extractSocketFD(from stream: InputStream) -> Int32? {
        let cfStream = stream as CFReadStream
        guard let handle = CFReadStreamCopyProperty(cfStream, .socketNativeHandle) else { return nil }
        guard CFGetTypeID(handle) == CFNumberGetTypeID() else { return nil }
        var fd: CFSocketNativeHandle = -1
        if CFNumberGetValue((handle as! CFNumber), .intType, &fd), fd >= 0 {
            return fd
        }
        return nil
    }

    private func doControlStream(_ muxConn: ClientMux) throws -> RouteInfo {
        let ctl = try muxConn.openStream()
        defer { ctl.close() }

        // Send ctlHello: single byte 0x01 (must match server protocol).
        try ctl.write(Data([ctlHello]))

        // Read the 1-byte type first; payload length depends on which
        // assignment variant the server picked. Modern servers respond
        // with ctlAssignDual (0x05, 43 bytes total) when dual-stack is
        // configured, otherwise the legacy ctlAssign (0x02, 10 bytes).
        let typeByte = try ctl.readExactly(1)[0]
        switch typeByte {
        case ctlAssign:
            let payload = try ctl.readExactly(ctlAssignPayloadLen)
            return Self.parseCtlAssign(payload)
        case ctlAssignDual:
            let payload = try ctl.readExactly(ctlAssignDualPayloadLen)
            return try Self.parseCtlAssignDual(payload)
        case ctlError:
            throw VpnClientError.serverReturnedError
        default:
            throw VpnClientError.unexpectedControlResponse(typeByte)
        }
    }

    // MARK: Control payload parsers (internal so tests can verify wire format)

    /// Parse a CTL_ASSIGN payload (9 bytes): ip4(4) + pfxLen4(1) + gw4(4).
    static func parseCtlAssign(_ payload: Data) -> RouteInfo {
        precondition(payload.count == ctlAssignPayloadLen,
                     "ctlAssign payload must be \(ctlAssignPayloadLen) bytes")
        let p = Array(payload)
        let ip = "\(p[0]).\(p[1]).\(p[2]).\(p[3])"
        let prefixLen = Int(p[4])
        let gateway = "\(p[5]).\(p[6]).\(p[7]).\(p[8])"
        return RouteInfo(assignedIP: ip, prefixLen: prefixLen, gateway: gateway)
    }

    /// Parse a CTL_ASSIGN_DUAL payload (42 bytes):
    ///   ip4(4) + pfxLen4(1) + gw4(4) + ip6(16) + pfxLen6(1) + gw6(16)
    static func parseCtlAssignDual(_ payload: Data) throws -> RouteInfo {
        guard payload.count == ctlAssignDualPayloadLen else {
            throw VpnClientError.unexpectedControlResponse(ctlAssignDual)
        }
        let p = Array(payload)
        let ip4 = "\(p[0]).\(p[1]).\(p[2]).\(p[3])"
        let pfx4 = Int(p[4])
        let gw4 = "\(p[5]).\(p[6]).\(p[7]).\(p[8])"
        let ip6 = formatIPv6(Data(p[9..<25]))
        let pfx6 = Int(p[25])
        let gw6 = formatIPv6(Data(p[26..<42]))
        return RouteInfo(
            assignedIP:  ip4, prefixLen:  pfx4, gateway:  gw4,
            assignedIP6: ip6, prefixLen6: pfx6, gateway6: gw6
        )
    }
}

// MARK: - IPv6 formatting

/// Format a 16-byte big-endian IPv6 address using RFC 5952 notation
/// (e.g. "fc00::1" rather than "fc00:0:0:0:0:0:0:1"). Falls back to a
/// raw colon-separated form when inet_ntop is unavailable.
func formatIPv6(_ bytes: Data) -> String {
    precondition(bytes.count == 16, "IPv6 address must be 16 bytes")
    #if canImport(Darwin)
    var addr = in6_addr()
    _ = withUnsafeMutableBytes(of: &addr) { buf in
        bytes.copyBytes(to: buf)
    }
    var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
    let result = inet_ntop(AF_INET6, &addr, &buffer, socklen_t(INET6_ADDRSTRLEN))
    if result != nil { return String(cString: buffer) }
    #endif
    // Fallback: pure-Swift formatter (also keeps Linux test runners working).
    var groups: [String] = []
    for i in stride(from: 0, to: 16, by: 2) {
        let v = (UInt16(bytes[i]) << 8) | UInt16(bytes[i + 1])
        groups.append(String(format: "%x", v))
    }
    return groups.joined(separator: ":")
}

// MARK: - Errors

public enum VpnClientError: Error {
    case connectionFailed(String)
    case connectionTimeout
    case serverKeyMismatch
    case serverReturnedError
    case unexpectedControlResponse(UInt8)
    case notConnected
}
