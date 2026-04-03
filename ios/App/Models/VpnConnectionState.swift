// VpnConnectionState.swift — Connection state enum for the iOS VPN UI

import Foundation

/// Represents the current VPN connection state.
public enum VpnConnectionState: Equatable {
    case disconnected
    case connecting
    case connected(stats: VpnStats)
    case disconnecting
    case error(message: String)

    /// Human-readable description of the state.
    public var label: String {
        switch self {
        case .disconnected:   return "Disconnected"
        case .connecting:     return "Connecting…"
        case .connected:      return "Connected"
        case .disconnecting:  return "Disconnecting…"
        case .error(let msg): return "Error: \(msg)"
        }
    }

    /// Returns true when the VPN is active.
    public var isConnected: Bool {
        if case .connected = self { return true }
        return false
    }

    /// Returns true when a transition is in progress.
    public var isTransitioning: Bool {
        switch self {
        case .connecting, .disconnecting: return true
        default: return false
        }
    }

    /// Returns true when the Connect button should be enabled.
    public var canConnect: Bool {
        if case .disconnected = self { return true }
        if case .error = self { return true }
        return false
    }

    /// Returns true when the Disconnect button should be enabled.
    public var canDisconnect: Bool {
        if case .connected = self { return true }
        return false
    }

    /// Symbol name for the status icon.
    public var symbolName: String {
        switch self {
        case .disconnected:   return "lock.open.fill"
        case .connecting:     return "arrow.triangle.2.circlepath"
        case .connected:      return "lock.fill"
        case .disconnecting:  return "arrow.triangle.2.circlepath"
        case .error:          return "exclamationmark.triangle.fill"
        }
    }

    public static func == (lhs: VpnConnectionState, rhs: VpnConnectionState) -> Bool {
        switch (lhs, rhs) {
        case (.disconnected, .disconnected): return true
        case (.connecting, .connecting):     return true
        case (.disconnecting, .disconnecting): return true
        case (.connected(let a), .connected(let b)): return a == b
        case (.error(let a), .error(let b)): return a == b
        default: return false
        }
    }
}
