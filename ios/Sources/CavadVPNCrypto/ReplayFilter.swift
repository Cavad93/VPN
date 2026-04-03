// ReplayFilter.swift — Sliding window replay protection (±90 seconds)
// Wire-compatible with Go server crypto/replay.go

import Foundation

// MARK: - Constants

/// Size in bytes of an encoded PacketHeader.
public let packetHeaderSize = 20

/// Sliding window half-width in seconds.
public let replayWindowSecs: Int64 = 90

// MARK: - PacketHeader

/// Per-packet timestamp + nonce used for replay protection.
/// Encoding: 8-byte big-endian timestamp + 12-byte nonce = 20 bytes.
public struct PacketHeader: Equatable {
    public let timestamp: Int64  // Unix seconds
    public let nonce: Data       // 12 bytes

    public init(timestamp: Int64, nonce: Data) {
        precondition(nonce.count == nonceSize, "nonce must be \(nonceSize) bytes")
        self.timestamp = timestamp
        self.nonce     = nonce
    }

    /// Encodes the header as 20 bytes (big-endian timestamp + nonce).
    public func encode() -> Data {
        var buf = Data(capacity: packetHeaderSize)
        var ts = timestamp.bigEndian
        withUnsafeBytes(of: &ts) { buf.append(contentsOf: $0) }
        buf.append(nonce)
        return buf
    }
}

/// Creates a PacketHeader with the current Unix second and a random nonce.
public func newPacketHeader() -> PacketHeader {
    let nonce = generateRandomData(count: nonceSize)
    return PacketHeader(timestamp: Int64(Date().timeIntervalSince1970), nonce: nonce)
}

/// Deserialises a PacketHeader from data (must be at least 20 bytes).
public func decodePacketHeader(_ data: Data) throws -> PacketHeader {
    guard data.count >= packetHeaderSize else {
        throw ReplayError.dataTooShort(data.count)
    }
    let tsBytes = data.prefix(8)
    let ts = tsBytes.withUnsafeBytes { $0.load(as: Int64.self).bigEndian }
    let nonce = data[8 ..< 20]
    return PacketHeader(timestamp: ts, nonce: Data(nonce))
}

// MARK: - ReplayFilter

/// Thread-safe replay filter with a ±REPLAY_WINDOW_SECS sliding time window.
/// Packets outside the window or with a previously seen (timestamp, nonce) pair
/// are rejected.
public final class ReplayFilter {
    // second → set of hex-encoded nonces seen in that second
    private var buckets: [Int64: Set<String>] = [:]
    private let lock = NSLock()

    public init() {}

    /// Returns `true` if `header` is a fresh packet (and records it).
    /// Returns `false` if the packet is a replay or outside the time window.
    @discardableResult
    public func check(_ header: PacketHeader) -> Bool {
        lock.lock()
        defer { lock.unlock() }

        let nowSec = Int64(Date().timeIntervalSince1970)
        let windowStart = nowSec - replayWindowSecs
        let windowEnd   = nowSec + replayWindowSecs

        guard header.timestamp >= windowStart, header.timestamp <= windowEnd else {
            return false
        }

        // Evict stale buckets
        buckets = buckets.filter { $0.key >= windowStart }

        let nonceHex = header.nonce.map { String(format: "%02x", $0) }.joined()
        if buckets[header.timestamp]?.contains(nonceHex) == true {
            return false
        }
        buckets[header.timestamp, default: []].insert(nonceHex)
        return true
    }
}

// MARK: - Errors

public enum ReplayError: Error {
    case dataTooShort(Int)
}
