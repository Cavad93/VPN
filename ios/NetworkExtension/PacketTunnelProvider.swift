// PacketTunnelProvider.swift — iOS Network Extension
// Requires the "Network Extensions" capability and the
// com.apple.developer.networking.networkextension entitlement in the host app.

import NetworkExtension
import CavadVPNClient
import CavadVPNTransport
import CavadVPNCrypto

/// The main Network Extension entry point for iOS VPN.
///
/// The system instantiates this class when the VPN is started and calls
/// `startTunnel(options:completionHandler:)`.  All packet I/O is then driven
/// by the bidirectional forwarding loops.
class PacketTunnelProvider: NEPacketTunnelProvider {

    private var vpnClient: VpnClient?
    private var tunnelQueue = DispatchQueue(label: "com.cavadvpn.tunnel", qos: .userInitiated)

    // MARK: – Lifecycle

    override func startTunnel(
        options: [String: NSObject]? = nil,
        completionHandler: @escaping (Error?) -> Void
    ) {
        guard let proto = protocolConfiguration as? NETunnelProviderProtocol,
              let serverAddr = proto.serverAddress,
              !serverAddr.isEmpty
        else {
            completionHandler(TunnelError.missingConfiguration)
            return
        }

        // Parse host:port from serverAddress
        let (host, port) = parseHostPort(serverAddr, defaultPort: 443)

        let config = VpnConfig(
            serverHost: host,
            serverPort: port,
            privateKeyHex:      proto.providerConfiguration?["privateKeyHex"] as? String,
            serverPublicKeyHex: proto.providerConfiguration?["serverPublicKeyHex"] as? String,
            dnsServer:          proto.providerConfiguration?["dnsServer"]     as? String ?? "1.1.1.1",
            mtu:               (proto.providerConfiguration?["mtu"]           as? Int)    ?? 1420
        )

        let client = VpnClient(config: config)
        vpnClient = client

        tunnelQueue.async {
            do {
                let route = try client.connect()
                self.configureTunnel(route: route, config: config) { error in
                    if let error = error {
                        completionHandler(error)
                        return
                    }
                    // Start bidirectional forwarding
                    self.startForwarding()
                    completionHandler(nil)
                }
            } catch {
                completionHandler(error)
            }
        }
    }

    override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        vpnClient?.disconnect()
        vpnClient = nil
        completionHandler()
    }

    override func handleAppMessage(
        _ messageData: Data,
        completionHandler: ((Data?) -> Void)?
    ) {
        // Not used in this implementation.
        completionHandler?(nil)
    }

    // MARK: – Tunnel configuration

    private func configureTunnel(
        route: RouteInfo,
        config: VpnConfig,
        completionHandler: @escaping (Error?) -> Void
    ) {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: config.serverHost)

        // IPv4 configuration
        let ipv4 = NEIPv4Settings(addresses: [route.assignedIP], subnetMasks: [prefixLenToMask(route.prefixLen)])
        // Route all IPv4 traffic through the tunnel
        ipv4.includedRoutes = [NEIPv4Route.default()]
        // Exclude the VPN server itself to avoid routing loops
        let serverExclusion = NEIPv4Route(destinationAddress: config.serverHost, subnetMask: "255.255.255.255")
        ipv4.excludedRoutes = [serverExclusion]
        settings.ipv4Settings = ipv4

        // DNS — use the VPN gateway to prevent DNS leaks
        let dns = NEDNSSettings(servers: [config.dnsServer])
        dns.matchDomains = [""]   // intercept all DNS queries
        settings.dnsSettings = dns

        // MTU
        settings.mtu = NSNumber(value: config.mtu)

        setTunnelNetworkSettings(settings) { error in
            completionHandler(error)
        }
    }

    // MARK: – Packet forwarding

    private func startForwarding() {
        // Device → VPN server
        tunnelQueue.async { [weak self] in
            self?.forwardFromDevice()
        }
        // VPN server → Device
        tunnelQueue.async { [weak self] in
            self?.forwardFromServer()
        }
    }

    /// Reads packets from the TUN interface and sends them to the VPN server.
    private func forwardFromDevice() {
        while let client = vpnClient, client.isConnected {
            packetFlow.readPackets { [weak self] packets, _ in
                guard let self = self, let client = self.vpnClient else { return }
                for packet in packets {
                    try? client.sendPacket(packet)
                }
            }
        }
    }

    /// Reads packets from the VPN server and injects them into the TUN interface.
    private func forwardFromServer() {
        while let client = vpnClient, client.isConnected {
            let packet = client.recvPacket()
            guard !packet.isEmpty else { continue }
            // AF_INET = 2
            packetFlow.writePackets([packet], withProtocols: [NSNumber(value: AF_INET)])
        }
    }

    // MARK: – Helpers

    private func parseHostPort(_ addr: String, defaultPort: Int) -> (String, Int) {
        if let lastColon = addr.lastIndex(of: ":"),
           let port = Int(addr[addr.index(after: lastColon)...]) {
            let host = String(addr[..<lastColon])
            return (host, port)
        }
        return (addr, defaultPort)
    }

    private func prefixLenToMask(_ len: Int) -> String {
        let bits: UInt32 = len > 0 ? ~UInt32(0) << (32 - len) : 0
        return "\((bits >> 24) & 0xFF).\((bits >> 16) & 0xFF).\((bits >> 8) & 0xFF).\(bits & 0xFF)"
    }
}

// MARK: – Errors

enum TunnelError: Error {
    case missingConfiguration
    case connectionFailed(String)
}
