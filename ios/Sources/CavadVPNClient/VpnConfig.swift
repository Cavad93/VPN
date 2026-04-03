// VpnConfig.swift — VPN client configuration and route info

import Foundation

// MARK: - VpnConfig

/// Configuration for the VPN client.
public struct VpnConfig {
    public let serverHost: String
    public let serverPort: Int
    /// Hex-encoded 32-byte private key (optional; generated if nil).
    public let privateKeyHex: String?
    /// Hex-encoded 32-byte server public key for pinning (optional).
    public let serverPublicKeyHex: String?
    /// DNS server to use on the tunnel (defaults to "1.1.1.1").
    public let dnsServer: String
    /// Maximum transmission unit for the tunnel interface.
    public let mtu: Int
    /// TCP connect timeout in seconds.
    public let connectTimeout: TimeInterval
    /// TCP read timeout in seconds.
    public let readTimeout: TimeInterval

    public init(
        serverHost: String,
        serverPort: Int,
        privateKeyHex: String? = nil,
        serverPublicKeyHex: String? = nil,
        dnsServer: String = "1.1.1.1",
        mtu: Int = 1420,
        connectTimeout: TimeInterval = 15,
        readTimeout: TimeInterval = 30
    ) {
        self.serverHost = serverHost
        self.serverPort = serverPort
        self.privateKeyHex = privateKeyHex
        self.serverPublicKeyHex = serverPublicKeyHex
        self.dnsServer = dnsServer
        self.mtu = mtu
        self.connectTimeout = connectTimeout
        self.readTimeout = readTimeout
    }

    /// Decodes `privateKeyHex` to raw bytes, or nil if not set.
    public func privateKeyBytes() -> Data? {
        guard let hex = privateKeyHex else { return nil }
        return Data(hexString: hex)
    }

    /// Decodes `serverPublicKeyHex` to raw bytes, or nil if not set.
    public func serverPublicKeyBytes() -> Data? {
        guard let hex = serverPublicKeyHex else { return nil }
        return Data(hexString: hex)
    }
}

// MARK: - RouteInfo

/// IP routing information assigned by the VPN server after a successful handshake.
public struct RouteInfo {
    /// Assigned VPN IP address (e.g. "10.8.0.2").
    public let assignedIP: String
    /// Prefix length (e.g. 24 for /24).
    public let prefixLen: Int
    /// Gateway address (e.g. "10.8.0.1").
    public let gateway: String

    public init(assignedIP: String, prefixLen: Int, gateway: String) {
        self.assignedIP = assignedIP
        self.prefixLen  = prefixLen
        self.gateway    = gateway
    }

    /// CIDR notation, e.g. "10.8.0.2/24".
    public var cidr: String { "\(assignedIP)/\(prefixLen)" }

    /// Network address derived from assignedIP + prefixLen.
    public var network: String {
        guard let ip = ipv4ToUInt32(assignedIP) else { return assignedIP }
        let mask: UInt32 = prefixLen > 0 ? ~UInt32(0) << (32 - prefixLen) : 0
        let net = ip & mask
        return uint32ToIPv4(net)
    }
}

// MARK: - Data hex helpers

public extension Data {
    init?(hexString: String) {
        let hex = hexString.trimmingCharacters(in: .whitespaces)
        guard hex.count % 2 == 0 else { return nil }
        var data = Data(capacity: hex.count / 2)
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<next], radix: 16) else { return nil }
            data.append(byte)
            index = next
        }
        self = data
    }

    var hexString: String {
        map { String(format: "%02x", $0) }.joined()
    }
}

// MARK: - IPv4 helpers

private func ipv4ToUInt32(_ ip: String) -> UInt32? {
    let parts = ip.split(separator: ".").compactMap { UInt32($0) }
    guard parts.count == 4 else { return nil }
    return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]
}

private func uint32ToIPv4(_ n: UInt32) -> String {
    "\((n >> 24) & 0xFF).\((n >> 16) & 0xFF).\((n >> 8) & 0xFF).\(n & 0xFF)"
}
