// VpnStats.swift — Traffic statistics model for the iOS VPN UI

import Foundation

/// Traffic and connection statistics for a live VPN session.
public struct VpnStats: Equatable {
    /// Bytes received through the VPN tunnel.
    public var bytesIn: Int64
    /// Bytes sent through the VPN tunnel.
    public var bytesOut: Int64
    /// Unix timestamp (milliseconds) when the session started.
    public var connectedSinceMs: Int64
    /// IP address assigned to the client by the VPN server.
    public var assignedIP: String

    public static let empty = VpnStats(
        bytesIn: 0, bytesOut: 0,
        connectedSinceMs: Int64(Date().timeIntervalSince1970 * 1000),
        assignedIP: ""
    )

    public init(bytesIn: Int64, bytesOut: Int64, connectedSinceMs: Int64, assignedIP: String) {
        self.bytesIn = bytesIn
        self.bytesOut = bytesOut
        self.connectedSinceMs = connectedSinceMs
        self.assignedIP = assignedIP
    }

    /// Uptime in seconds.
    public var uptimeSeconds: Int64 {
        let nowMs = Int64(Date().timeIntervalSince1970 * 1000)
        return max(0, (nowMs - connectedSinceMs) / 1000)
    }

    /// Uptime formatted as HH:MM:SS.
    public var uptimeFormatted: String {
        let s = uptimeSeconds
        let h = s / 3600
        let m = (s % 3600) / 60
        let sec = s % 60
        return String(format: "%02d:%02d:%02d", h, m, sec)
    }

    /// Format a byte count as a human-readable string.
    public static func formatBytes(_ bytes: Int64) -> String {
        if bytes < 1024 {
            return "\(bytes) B"
        } else if bytes < 1024 * 1024 {
            return String(format: "%.1f KB", Double(bytes) / 1024)
        } else if bytes < 1024 * 1024 * 1024 {
            return String(format: "%.1f MB", Double(bytes) / (1024 * 1024))
        } else {
            return String(format: "%.1f GB", Double(bytes) / (1024 * 1024 * 1024))
        }
    }

    /// Formatted download label.
    public var downloadLabel: String { "↓ \(VpnStats.formatBytes(bytesIn))" }

    /// Formatted upload label.
    public var uploadLabel: String { "↑ \(VpnStats.formatBytes(bytesOut))" }
}
