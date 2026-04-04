// VpnClient.swift — Full VPN client stack
// TCP → TLS obfuscation → Noise_XX → NoiseConn → ClientMux → control/data streams

import Foundation
#if canImport(Darwin)
import Darwin
#endif
import Crypto
import CavadVPNCrypto
import CavadVPNTransport

// MARK: - Control protocol constants (must match Go server)

private let ctlHello:  UInt8 = 0x01
private let ctlAssign: UInt8 = 0x02
private let ctlError:  UInt8 = 0xFF
private let ctlAssignPayloadLen = 9  // ip(4) + prefixLen(1) + gateway(4)

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

        // 2. TLS obfuscation
        let obfsConn = ObfsConn(inputStream: ins, outputStream: outs)
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

        // Send ctlHello: single byte 0x01 (must match server protocol)
        try ctl.write(Data([ctlHello]))

        // Receive ctlAssign: [0x02, ip(4), prefixLen(1), gateway(4)] = 10 bytes
        let resp = try ctl.readExactly(1 + ctlAssignPayloadLen)
        switch resp[0] {
        case ctlError:
            throw VpnClientError.serverReturnedError
        case ctlAssign:
            break
        default:
            throw VpnClientError.unexpectedControlResponse(resp[0])
        }

        let ip = "\(resp[1]).\(resp[2]).\(resp[3]).\(resp[4])"
        let prefixLen = Int(resp[5])
        let gateway = "\(resp[6]).\(resp[7]).\(resp[8]).\(resp[9])"

        return RouteInfo(assignedIP: ip, prefixLen: prefixLen, gateway: gateway)
    }
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
