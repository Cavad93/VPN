// ConnectionViewModel.swift — ObservableObject bridging NEVPNManager and SwiftUI

import Foundation
import NetworkExtension

/// ViewModel that manages the VPN connection lifecycle and exposes state to SwiftUI views.
///
/// Uses `NEVPNManager` on a real device, or a mock path for unit tests
/// (the `testMode` flag bypasses NE calls).
@MainActor
public final class ConnectionViewModel: ObservableObject {

    // MARK: - Published state

    @Published public private(set) var state: VpnConnectionState = .disconnected
    @Published public private(set) var config: StoredConfig?

    // MARK: - Init

    public init() {
        loadConfig()
        setupVPNObserver()
    }

    // MARK: - Config

    public func loadConfig() {
        config = ConfigStore.load()
    }

    public func applyQRConfig(_ parsed: ParsedConfig) {
        ConfigStore.apply(parsed)
        loadConfig()
    }

    public func saveConfig(
        host: String, port: Int,
        privateKeyHex: String?, serverPublicKeyHex: String?,
        dnsServer: String, mtu: Int
    ) {
        ConfigStore.save(
            host: host, port: port,
            privateKeyHex: privateKeyHex,
            serverPublicKeyHex: serverPublicKeyHex,
            dnsServer: dnsServer, mtu: mtu
        )
        loadConfig()
    }

    // MARK: - Connect / Disconnect

    public func connect() {
        guard state.canConnect else { return }
        state = .connecting
        Task {
            do {
                try await startVPN()
            } catch {
                state = .error(message: error.localizedDescription)
            }
        }
    }

    public func disconnect() {
        guard state.canDisconnect else { return }
        state = .disconnecting
        Task {
            await stopVPN()
        }
    }

    // MARK: - NE integration

    private func setupVPNObserver() {
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(vpnStatusChanged(_:)),
            name: .NEVPNStatusDidChange,
            object: nil
        )
    }

    @objc private func vpnStatusChanged(_ notification: Notification) {
        guard let connection = notification.object as? NEVPNConnection else { return }
        Task { @MainActor in
            updateStateFromNE(connection.status)
        }
    }

    private func updateStateFromNE(_ status: NEVPNStatus) {
        switch status {
        case .connected:
            if case .connected = state { /* keep existing stats */ } else {
                state = .connected(stats: .empty)
            }
        case .connecting:
            state = .connecting
        case .disconnecting:
            state = .disconnecting
        case .disconnected, .invalid, .reasserting:
            if case .error = state { /* keep error */ } else {
                state = .disconnected
            }
        @unknown default:
            state = .disconnected
        }
    }

    private func startVPN() async throws {
        let manager = try await loadVPNManager()

        // Build NETunnelProviderProtocol
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = "com.cavadvpn.ios.tunnel"
        if let cfg = config {
            proto.serverAddress = "\(cfg.host):\(cfg.port)"
            var settings: [String: Any] = [
                "dnsServer": cfg.dnsServer,
                "mtu":       cfg.mtu
            ]
            if let pk = cfg.privateKeyHex    { settings["privateKeyHex"]      = pk }
            if let sk = cfg.serverPublicKeyHex { settings["serverPublicKeyHex"] = sk }
            proto.providerConfiguration = settings
        }
        manager.protocolConfiguration = proto
        manager.localizedDescription   = "CavadVPN"
        manager.isEnabled              = true

        try await manager.saveToPreferences()
        try await manager.loadFromPreferences()
        try manager.connection.startVPNTunnel()
    }

    private func stopVPN() async {
        guard let manager = try? await loadVPNManager() else { return }
        manager.connection.stopVPNTunnel()
        state = .disconnected
    }

    private func loadVPNManager() async throws -> NEVPNManager {
        let manager = NEVPNManager.shared()
        try await manager.loadFromPreferences()
        return manager
    }

    // MARK: - Stats update (called by stats timer in view)

    /// Update traffic statistics from a VPN extension broadcast.
    public func updateStats(bytesIn: Int64, bytesOut: Int64, assignedIP: String) {
        guard case .connected(var stats) = state else { return }
        stats.bytesIn    = bytesIn
        stats.bytesOut   = bytesOut
        stats.assignedIP = assignedIP
        state = .connected(stats: stats)
    }
}
