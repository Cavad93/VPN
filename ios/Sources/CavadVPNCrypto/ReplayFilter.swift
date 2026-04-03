/// ReplayFilter.swift — Sliding window replay protection
///
/// Wire-compatible with Go server (server/crypto/replay.go) and Python/Kotlin implementations.
///
/// Each packet carries a 20-byte header:
///   - 8 bytes: timestamp (seconds since Unix epoch, big-endian uint64)
///   - 12 bytes: random nonce
///
/// The filter rejects packets that are:
///   - More than 90 seconds in the past
///   - More than 90 seconds in the future
///   - Previously seen (replay)

import Foundation

// MARK: - Constants

private let PACKET_HEADER_SIZE = 20  // 8 (timestamp) + 12 (nonce)
private let WINDOW_SECONDS: Int64 = 90

// MARK: - PacketHeader

/// 20-byte packet header: timestamp (8 bytes) + nonce (12 bytes).
public struct PacketHeader {
    public let timestamp: UInt64  // Unix seconds
    public let nonce: [UInt8]     // 12 random bytes

    public init(timestamp: UInt64, nonce: [UInt8]) {
        precondition(nonce.count == 12, "PacketHeader: nonce must be 12 bytes")
        self.timestamp = timestamp
        self.nonce = nonce
    }

    /// Create a new header with current time and random nonce.
    public static func create() -> PacketHeader {
        let ts = UInt64(Date().timeIntervalSince1970)
        let nonce = generateRandomBytes(count: 12)
        return PacketHeader(timestamp: ts, nonce: nonce)
    }

    /// Serialize to 20 bytes: timestamp (8, big-endian) + nonce (12).
    public func encode() -> [UInt8] {
        var buf = [UInt8](repeating: 0, count: PACKET_HEADER_SIZE)
        var ts = timestamp
        for i in stride(from: 7, through: 0, by: -1) {
            buf[i] = UInt8(ts & 0xFF)
            ts >>= 8
        }
        buf.replaceSubrange(8..<20, with: nonce)
        return buf
    }

    /// Deserialize from 20 bytes.
    public static func decode(_ data: [UInt8]) throws -> PacketHeader {
        guard data.count >= PACKET_HEADER_SIZE else {
            throw ReplayError.headerTooShort(data.count)
        }
        var ts: UInt64 = 0
        for i in 0..<8 {
            ts = (ts << 8) | UInt64(data[i])
        }
        let nonce = Array(data[8..<20])
        return PacketHeader(timestamp: ts, nonce: nonce)
    }
}

// MARK: - ReplayError

public enum ReplayError: Error {
    case headerTooShort(Int)
    case tooOld
    case tooFuture
    case duplicate
}

// MARK: - ReplayFilter

/// Thread-safe sliding window replay filter.
///
/// Stores seen nonces grouped by second-granularity timestamp bucket.
/// Automatically cleans up old buckets during Check().
public class ReplayFilter {
    // Map from timestamp (seconds) to set of nonce strings seen in that second
    private var buckets: [Int64: Set<String>] = [:]
    private let lock = NSLock()

    public init() {}

    /// Check if a packet header is valid (not replayed, not stale, not from the future).
    /// On success, records the nonce so future duplicates are rejected.
    ///
    /// - Throws: ReplayError if packet is rejected
    public func check(_ header: PacketHeader) throws {
        let now = Int64(Date().timeIntervalSince1970)
        let pktTime = Int64(header.timestamp)

        if pktTime < now - WINDOW_SECONDS {
            throw ReplayError.tooOld
        }
        if pktTime > now + WINDOW_SECONDS {
            throw ReplayError.tooFuture
        }

        let nonceKey = header.nonce.map { String(format: "%02x", $0) }.joined()

        lock.lock()
        defer { lock.unlock() }

        // Check for duplicate
        if buckets[pktTime]?.contains(nonceKey) == true {
            throw ReplayError.duplicate
        }

        // Record nonce
        if buckets[pktTime] == nil {
            buckets[pktTime] = Set<String>()
        }
        buckets[pktTime]!.insert(nonceKey)

        // Cleanup old buckets
        let cutoff = now - WINDOW_SECONDS - 1
        buckets = buckets.filter { $0.key > cutoff }
    }
}
