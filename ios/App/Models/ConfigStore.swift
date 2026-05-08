// ConfigStore.swift — Persistent VPN configuration storage (UserDefaults)

import Foundation

/// Persists VPN connection configuration using UserDefaults.
///
/// Keys are namespaced under `com.cavadvpn.` to avoid collisions.
public struct ConfigStore {

    // MARK: - Key constants

    private enum Key {
        static let serverHost       = "com.cavadvpn.serverHost"
        static let serverPort       = "com.cavadvpn.serverPort"
        static let privateKeyHex    = "com.cavadvpn.privateKeyHex"
        static let serverPublicKey  = "com.cavadvpn.serverPublicKey"
        static let knockKey         = "com.cavadvpn.knockKey"
        static let dnsServer        = "com.cavadvpn.dnsServer"
        static let mtu              = "com.cavadvpn.mtu"
    }

    // MARK: - Save

    /// Persist configuration fields to UserDefaults.
    public static func save(
        to defaults: UserDefaults = .standard,
        host: String,
        port: Int,
        privateKeyHex: String?,
        serverPublicKeyHex: String?,
        knockKeyHex: String? = nil,
        dnsServer: String,
        mtu: Int
    ) {
        defaults.set(host,             forKey: Key.serverHost)
        defaults.set(port,             forKey: Key.serverPort)
        defaults.set(privateKeyHex,    forKey: Key.privateKeyHex)
        defaults.set(serverPublicKeyHex, forKey: Key.serverPublicKey)
        defaults.set(knockKeyHex,      forKey: Key.knockKey)
        defaults.set(dnsServer,        forKey: Key.dnsServer)
        defaults.set(mtu,              forKey: Key.mtu)
    }

    // MARK: - Load

    /// Load configuration from UserDefaults; returns nil if the host is missing.
    public static func load(from defaults: UserDefaults = .standard) -> StoredConfig? {
        guard let host = defaults.string(forKey: Key.serverHost), !host.isEmpty else {
            return nil
        }
        let port = defaults.integer(forKey: Key.serverPort)
        let effectivePort = port > 0 ? port : 443
        return StoredConfig(
            host: host,
            port: effectivePort,
            privateKeyHex: defaults.string(forKey: Key.privateKeyHex),
            serverPublicKeyHex: defaults.string(forKey: Key.serverPublicKey),
            knockKeyHex: defaults.string(forKey: Key.knockKey),
            dnsServer: defaults.string(forKey: Key.dnsServer) ?? "1.1.1.1",
            mtu: {
                let v = defaults.integer(forKey: Key.mtu)
                return v > 0 ? v : 1420
            }()
        )
    }

    // MARK: - Clear

    /// Remove all stored configuration from UserDefaults.
    public static func clear(from defaults: UserDefaults = .standard) {
        [Key.serverHost, Key.serverPort, Key.privateKeyHex,
         Key.serverPublicKey, Key.knockKey, Key.dnsServer, Key.mtu].forEach {
            defaults.removeObject(forKey: $0)
        }
    }

    // MARK: - Apply QR

    /// Save configuration from a parsed QR code.
    public static func apply(_ config: ParsedConfig, to defaults: UserDefaults = .standard) {
        save(
            to: defaults,
            host: config.host,
            port: config.port,
            privateKeyHex: config.privateKey,
            serverPublicKeyHex: config.serverKey,
            knockKeyHex: config.knockKey,
            dnsServer: config.dns,
            mtu: config.mtu
        )
    }
}

// MARK: - StoredConfig

/// A fully-loaded configuration retrieved from UserDefaults.
public struct StoredConfig: Equatable {
    public let host: String
    public let port: Int
    public let privateKeyHex: String?
    public let serverPublicKeyHex: String?
    /// Hex-encoded 32-byte port-knock PSK; nil for non-knock servers.
    public let knockKeyHex: String?
    public let dnsServer: String
    public let mtu: Int
}
