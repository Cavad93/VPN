// QRConfig.swift — QR code configuration parser for CavadVPN iOS

import Foundation

/// Errors that can occur while parsing a QR code config.
public enum QRConfigError: Error, Equatable {
    case emptyInput
    case invalidFormat(String)
    case missingField(String)
    case invalidValue(String)
}

/// Parses VPN configuration from a QR code string.
///
/// Supported formats:
/// 1. JSON:  `{"host":"1.2.3.4","port":443,"private_key":"aabb…","server_key":"ccdd…"}`
/// 2. URI:   `cavadvpn://config?host=1.2.3.4&port=443&private_key=aabb…&server_key=ccdd…`
public struct QRConfig {

    // MARK: - Parse

    /// Parse QR code text into a VpnConfig-compatible struct.
    public static func parse(_ text: String) throws -> ParsedConfig {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { throw QRConfigError.emptyInput }

        if trimmed.hasPrefix("cavadvpn://") {
            return try parseURI(trimmed)
        } else if trimmed.hasPrefix("{") {
            return try parseJSON(trimmed)
        } else {
            throw QRConfigError.invalidFormat("Expected JSON object or cavadvpn:// URI")
        }
    }

    // MARK: - JSON parser

    private static func parseJSON(_ text: String) throws -> ParsedConfig {
        guard let data = text.data(using: .utf8),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else {
            throw QRConfigError.invalidFormat("Malformed JSON")
        }

        let host = try requireString(obj, key: "host")
        let port = try requireInt(obj, key: "port")
        let privateKey = obj["private_key"] as? String
        let serverKey  = obj["server_key"]  as? String
        let dns        = obj["dns"]         as? String ?? "1.1.1.1"
        let mtu        = obj["mtu"]         as? Int    ?? 1420

        try validateHost(host)
        try validatePort(port)
        if let pk = privateKey { try validateHexKey(pk, field: "private_key") }
        if let sk = serverKey  { try validateHexKey(sk, field: "server_key")  }

        return ParsedConfig(
            host: host, port: port,
            privateKey: privateKey, serverKey: serverKey,
            dns: dns, mtu: mtu
        )
    }

    // MARK: - URI parser

    private static func parseURI(_ text: String) throws -> ParsedConfig {
        // Replace scheme so URLComponents can parse it
        let normalized = text.replacingOccurrences(of: "cavadvpn://config", with: "https://x")
        guard let comps = URLComponents(string: normalized),
              let items = comps.queryItems
        else {
            throw QRConfigError.invalidFormat("Malformed cavadvpn:// URI")
        }

        func q(_ name: String) -> String? {
            items.first(where: { $0.name == name })?.value
        }

        guard let host = q("host"), !host.isEmpty else {
            throw QRConfigError.missingField("host")
        }
        guard let portStr = q("port"), let port = Int(portStr) else {
            throw QRConfigError.missingField("port")
        }

        let privateKey = q("private_key")
        let serverKey  = q("server_key")
        let dns        = q("dns") ?? "1.1.1.1"
        let mtu        = q("mtu").flatMap(Int.init) ?? 1420

        try validateHost(host)
        try validatePort(port)
        if let pk = privateKey { try validateHexKey(pk, field: "private_key") }
        if let sk = serverKey  { try validateHexKey(sk, field: "server_key")  }

        return ParsedConfig(
            host: host, port: port,
            privateKey: privateKey, serverKey: serverKey,
            dns: dns, mtu: mtu
        )
    }

    // MARK: - Encode to JSON

    /// Serialise a config back to QR JSON.
    public static func toQRJson(
        host: String, port: Int,
        privateKey: String? = nil, serverKey: String? = nil,
        dns: String = "1.1.1.1", mtu: Int = 1420
    ) -> String {
        var obj: [String: Any] = ["host": host, "port": port, "dns": dns, "mtu": mtu]
        if let pk = privateKey { obj["private_key"] = pk }
        if let sk = serverKey  { obj["server_key"]  = sk }
        guard let data = try? JSONSerialization.data(withJSONObject: obj, options: [.sortedKeys]),
              let str  = String(data: data, encoding: .utf8)
        else { return "{}" }
        return str
    }

    /// Serialise a config to cavadvpn:// URI.
    public static func toQRUri(
        host: String, port: Int,
        privateKey: String? = nil, serverKey: String? = nil,
        dns: String = "1.1.1.1", mtu: Int = 1420
    ) -> String {
        var items = [URLQueryItem]()
        items.append(URLQueryItem(name: "host", value: host))
        items.append(URLQueryItem(name: "port", value: "\(port)"))
        if let pk = privateKey { items.append(URLQueryItem(name: "private_key", value: pk)) }
        if let sk = serverKey  { items.append(URLQueryItem(name: "server_key",  value: sk)) }
        items.append(URLQueryItem(name: "dns", value: dns))
        items.append(URLQueryItem(name: "mtu", value: "\(mtu)"))
        var comps = URLComponents()
        comps.queryItems = items
        return "cavadvpn://config\(comps.url?.absoluteString.dropFirst() ?? "")"
    }

    // MARK: - Validation helpers

    private static func requireString(_ obj: [String: Any], key: String) throws -> String {
        guard let v = obj[key] as? String, !v.isEmpty else {
            throw QRConfigError.missingField(key)
        }
        return v
    }

    private static func requireInt(_ obj: [String: Any], key: String) throws -> Int {
        if let v = obj[key] as? Int { return v }
        if let v = obj[key] as? String, let i = Int(v) { return i }
        throw QRConfigError.missingField(key)
    }

    private static func validateHost(_ host: String) throws {
        guard !host.isEmpty else { throw QRConfigError.invalidValue("host cannot be empty") }
    }

    private static func validatePort(_ port: Int) throws {
        guard port > 0 && port <= 65535 else {
            throw QRConfigError.invalidValue("port \(port) out of range 1–65535")
        }
    }

    private static func validateHexKey(_ key: String, field: String) throws {
        guard key.count == 64,
              key.allSatisfy({ $0.isHexDigit })
        else {
            throw QRConfigError.invalidValue("\(field) must be 64 hex characters")
        }
    }
}

// MARK: - ParsedConfig

/// Result of a successful QR code parse.
public struct ParsedConfig: Equatable {
    public let host: String
    public let port: Int
    public let privateKey: String?
    public let serverKey: String?
    public let dns: String
    public let mtu: Int

    public init(
        host: String, port: Int,
        privateKey: String?, serverKey: String?,
        dns: String, mtu: Int
    ) {
        self.host = host
        self.port = port
        self.privateKey = privateKey
        self.serverKey  = serverKey
        self.dns = dns
        self.mtu = mtu
    }
}
