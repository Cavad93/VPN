// MuxConn.swift — NoiseConn + ClientMux + MuxStream
// Wire-compatible with Go server transport/mux.go

import Foundation
import CavadVPNCrypto

// MARK: - Mux frame constants

private let frameSYN:  UInt8 = 0x01
private let frameDATA: UInt8 = 0x02
private let frameFIN:  UInt8 = 0x03
private let muxHeaderSize = 7   // streamID(4) + type(1) + payloadLen(2)
private let maxMuxPayload = 0xFFFF

// MARK: - NoiseConn

/// Noise-encrypted transport layer over ObfsConn.
/// Each message is encrypted with the session's send cipher and prefixed with
/// a 2-byte big-endian length.
public final class NoiseConn {
    private let obfs: ObfsConn
    private let session: NoiseSession

    public init(obfs: ObfsConn, session: NoiseSession) {
        self.obfs    = obfs
        self.session = session
    }

    /// Encrypts plaintext and writes it with a 2-byte BE length prefix.
    public func writeMessage(_ plaintext: Data) throws {
        let ct = try session.sendCipher.encrypt(plaintext: plaintext)
        var frame = Data(capacity: 2 + ct.count)
        frame.append(UInt8((ct.count >> 8) & 0xFF))
        frame.append(UInt8( ct.count       & 0xFF))
        frame.append(ct)
        try obfs.write(frame)
    }

    /// Reads one length-prefixed ciphertext frame and decrypts it.
    public func readMessage() throws -> Data {
        let lenBytes = try obfs.read(2)
        let frameLen = Int(lenBytes[0]) << 8 | Int(lenBytes[1])
        let ct = try obfs.read(frameLen)
        return try session.recvCipher.decrypt(ciphertext: ct)
    }

    public func close() { obfs.close() }
}

// MARK: - MuxStream

/// A virtual bidirectional stream within a ClientMux.
public final class MuxStream {
    public let streamId: Int
    private weak var mux: ClientMux?

    private let queue = DispatchSemaphore(value: 0)
    private var chunks: [Data] = []
    private let chunksLock = NSLock()
    private var readBuf = Data()
    private var isClosed = false
    private var remoteFin = false

    init(streamId: Int, mux: ClientMux) {
        self.streamId = streamId
        self.mux = mux
    }

    /// Sends data as one or more DATA frames.
    public func write(_ data: Data) throws {
        guard !isClosed else { throw MuxError.streamClosed(streamId) }
        var offset = data.startIndex
        while offset < data.endIndex {
            let end = data.index(offset, offsetBy: min(maxMuxPayload, data.distance(from: offset, to: data.endIndex)))
            let chunk = Data(data[offset..<end])
            try mux?.writeFrame(streamId: streamId, type: frameDATA, payload: chunk)
            offset = end
        }
    }

    /// Reads the next available data chunk. Returns empty Data on FIN / close.
    /// Blocks for up to `timeout` seconds.
    public func read(timeout: TimeInterval = 30) -> Data {
        if !readBuf.isEmpty {
            let result = readBuf
            readBuf = Data()
            return result
        }
        let deadline = DispatchTime.now() + timeout
        guard queue.wait(timeout: deadline) == .success else { return Data() }
        chunksLock.lock()
        let chunk = chunks.isEmpty ? Data() : chunks.removeFirst()
        chunksLock.unlock()
        return chunk
    }

    /// Reads exactly `n` bytes, blocking and buffering across multiple chunks.
    public func readExactly(_ n: Int, timeout: TimeInterval = 30) throws -> Data {
        var result = Data(capacity: n)
        let deadline = Date().addingTimeInterval(timeout)
        while result.count < n {
            if !readBuf.isEmpty {
                let take = min(n - result.count, readBuf.count)
                result.append(readBuf.prefix(take))
                readBuf.removeFirst(take)
            } else {
                let remaining = deadline.timeIntervalSinceNow
                guard remaining > 0 else { throw MuxError.timeout }
                let semResult = queue.wait(timeout: .now() + remaining)
                guard semResult == .success else { throw MuxError.timeout }
                chunksLock.lock()
                let chunk = chunks.isEmpty ? Data() : chunks.removeFirst()
                chunksLock.unlock()
                if chunk.isEmpty { throw MuxError.streamEOF(streamId) }
                readBuf.append(chunk)
            }
        }
        return result
    }

    /// Sends FIN and removes this stream from the mux.
    public func close() {
        guard !isClosed else { return }
        isClosed = true
        try? mux?.writeFrame(streamId: streamId, type: frameFIN, payload: Data())
        mux?.removeStream(streamId: streamId)
        signalFin()
    }

    // Called by the read-loop to deliver incoming data.
    func deliver(_ data: Data) {
        chunksLock.lock()
        chunks.append(data)
        chunksLock.unlock()
        queue.signal()
    }

    // Called by the read-loop when the remote sends FIN.
    func signalFin() {
        remoteFin = true
        chunksLock.lock()
        chunks.append(Data())
        chunksLock.unlock()
        queue.signal()
    }
}

// MARK: - ClientMux

/// Client-side stream multiplexer over a NoiseConn.
/// The client uses even stream IDs (2, 4, 6, …).
/// A background thread continuously reads Noise messages and dispatches frames.
public final class ClientMux {
    private let conn: NoiseConn
    private var streams:   [Int: MuxStream] = [:]
    private let streamsLock = NSLock()
    private let writeLock   = NSLock()
    private var nextId = 2   // even IDs for client
    private var closed = false

    private var readerThread: Thread?

    public init(conn: NoiseConn) {
        self.conn = conn
        let t = Thread(target: self, selector: #selector(readLoop), object: nil)
        t.name = "cavadvpn-mux-reader"
        t.qualityOfService = .utility
        t.start()
        readerThread = t
    }

    // MARK: Public API

    /// Opens a new outbound stream, sends a SYN frame, and returns the stream.
    public func openStream() throws -> MuxStream {
        guard !closed else { throw MuxError.muxClosed }
        streamsLock.lock()
        let sid = nextId
        nextId += 2
        let stream = MuxStream(streamId: sid, mux: self)
        streams[sid] = stream
        streamsLock.unlock()
        try writeFrame(streamId: sid, type: frameSYN, payload: Data())
        return stream
    }

    /// Closes all streams and the underlying connection.
    public func close() {
        guard !closed else { return }
        closed = true
        streamsLock.lock()
        let allStreams = streams.values
        streams.removeAll()
        streamsLock.unlock()
        allStreams.forEach { $0.signalFin() }
        conn.close()
        readerThread?.cancel()
    }

    // MARK: Internal frame I/O

    func writeFrame(streamId: Int, type: UInt8, payload: Data) throws {
        var frame = Data(capacity: muxHeaderSize + payload.count)
        // streamID: uint32 big-endian
        frame.append(UInt8((streamId >> 24) & 0xFF))
        frame.append(UInt8((streamId >> 16) & 0xFF))
        frame.append(UInt8((streamId >>  8) & 0xFF))
        frame.append(UInt8( streamId        & 0xFF))
        frame.append(type)
        frame.append(UInt8((payload.count >> 8) & 0xFF))
        frame.append(UInt8( payload.count       & 0xFF))
        frame.append(payload)
        writeLock.lock()
        defer { writeLock.unlock() }
        try conn.writeMessage(frame)
    }

    func removeStream(streamId: Int) {
        streamsLock.lock()
        streams.removeValue(forKey: streamId)
        streamsLock.unlock()
    }

    // MARK: Read loop

    @objc private func readLoop() {
        while !closed {
            let frameData: Data
            do {
                frameData = try conn.readMessage()
            } catch {
                if !closed {
                    closed = true
                    streamsLock.lock()
                    let all = streams.values
                    streams.removeAll()
                    streamsLock.unlock()
                    all.forEach { $0.signalFin() }
                }
                return
            }

            guard frameData.count >= muxHeaderSize else { continue }

            let sid = Int(frameData[0]) << 24
                    | Int(frameData[1]) << 16
                    | Int(frameData[2]) <<  8
                    | Int(frameData[3])
            let ftype = frameData[4]
            let payloadLen = Int(frameData[5]) << 8 | Int(frameData[6])
            let payload: Data
            if payloadLen > 0, frameData.count >= muxHeaderSize + payloadLen {
                payload = Data(frameData[muxHeaderSize ..< muxHeaderSize + payloadLen])
            } else {
                payload = Data()
            }

            streamsLock.lock()
            let stream = streams[sid]
            streamsLock.unlock()

            switch ftype {
            case frameSYN:
                if stream == nil {
                    // Server opened a stream — register it
                    let newStream = MuxStream(streamId: sid, mux: self)
                    streamsLock.lock()
                    streams[sid] = newStream
                    streamsLock.unlock()
                }
            case frameDATA:
                if let s = stream, !payload.isEmpty {
                    s.deliver(payload)
                }
            case frameFIN:
                stream?.signalFin()
                removeStream(streamId: sid)
            default:
                break
            }
        }
    }
}

// MARK: - Errors

public enum MuxError: Error {
    case muxClosed
    case streamClosed(Int)
    case streamEOF(Int)
    case timeout
    case frameTooShort(Int)
}
