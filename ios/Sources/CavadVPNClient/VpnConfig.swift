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
    /// Hex-encoded 32-byte port-knock PSK (optional).
    /// When set, the client embeds HMAC-SHA256(knockKey, clientHelloRandom)
    /// into the TLS session_id field. The relay/server uses this as a
    /// Reality-style port-knock to authenticate VPN clients before
    /// forwarding traffic; without the right key the server transparently
    /// proxies the connection to a cover site, so unauthorized probes
    /// cannot detect that a VPN endpoint is running.
    public let knockKeyHex: String?
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
        knockKeyHex: String? = nil,
        dnsServer: String = "1.1.1.1",
        mtu: Int = 1420,
        connectTimeout: TimeInterval = 15,
        readTimeout: TimeInterval = 30
    ) {
        self.serverHost = serverHost
        self.serverPort = serverPort
        self.privateKeyHex = privateKeyHex
        self.serverPublicKeyHex = serverPublicKeyHex
        self.knockKeyHex = knockKeyHex
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

    /// Decodes `knockKeyHex` to raw bytes, or nil if not set / malformed.
    /// A valid knock key is exactly 32 bytes; anything else returns nil so
    /// the client falls back to a random session_id (compatible with
    /// non-knock servers).
    public func knockKeyBytes() -> Data? {
        guard let hex = knockKeyHex,
              let bytes = Data(hexString: hex),
              bytes.count == 32 else { return nil }
        return bytes
    }
}

// MARK: - RouteInfo

/// IP routing information assigned by the VPN server after a successful handshake.
///
/// Supports both IPv4-only (CTL_ASSIGN, 0x02) and dual-stack IPv4+IPv6
/// (CTL_ASSIGN_DUAL, 0x05) responses. IPv6 fields are nil when the server
/// returned an IPv4-only assignment, so callers must `if let` them before
/// configuring an IPv6 tunnel.
public struct RouteInfo {
    /// Assigned VPN IPv4 address (e.g. "10.8.0.2").
    public let assignedIP: String
    /// IPv4 prefix length (e.g. 24 for /24).
    public let prefixLen: Int
    /// IPv4 gateway address (e.g. "10.8.0.1").
    public let gateway: String
    /// Assigned VPN IPv6 address, present when the server returned a
    /// dual-stack assignment (CTL_ASSIGN_DUAL).
    public let assignedIP6: String?
    /// IPv6 prefix length (e.g. 120 for /120), present alongside `assignedIP6`.
    public let prefixLen6: Int?
    /// IPv6 gateway address (e.g. "fc00::1"), present alongside `assignedIP6`.
    public let gateway6: String?

    public init(
        assignedIP: String,
        prefixLen: Int,
        gateway: String,
        assignedIP6: String? = nil,
        prefixLen6: Int? = nil,
        gateway6: String? = nil
    ) {
        self.assignedIP = assignedIP
        self.prefixLen  = prefixLen
        self.gateway    = gateway
        self.assignedIP6 = assignedIP6
        self.prefixLen6  = prefixLen6
        self.gateway6    = gateway6
    }

    /// IPv4 CIDR notation, e.g. "10.8.0.2/24".
    public var cidr: String { "\(assignedIP)/\(prefixLen)" }

    /// IPv6 CIDR notation if dual-stack, else nil.
    public var cidr6: String? {
        guard let ip = assignedIP6, let pfx = prefixLen6 else { return nil }
        return "\(ip)/\(pfx)"
    }

    /// True when both an IPv4 and an IPv6 address were assigned.
    public var isDualStack: Bool { assignedIP6 != nil && prefixLen6 != nil && gateway6 != nil }

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
