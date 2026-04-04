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
    /// Dedicated queue for server→device forwarding so it runs concurrently
    /// with device→server (which uses the readPackets callback on tunnelQueue).
    private var serverReadQueue = DispatchQueue(label: "com.cavadvpn.serverRead", qos: .userInitiated)

    /// SideStore compatibility: bypass Apple servers + pause support.
    private let sideStore = SideStoreController(pauseDuration: 30, pauseCooldown: 300)

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
        guard let command = String(data: messageData, encoding: .utf8) else {
            completionHandler?(nil)
            return
        }

        switch command {
        case "pause":
            // SideStore refresh: pause tunnel for 30 seconds
            let ok = sideStore.pause()
            let response = ok ? "paused" : "cooldown"
            completionHandler?(response.data(using: .utf8))
        case "resume":
            sideStore.resume()
            completionHandler?("resumed".data(using: .utf8))
        case "status":
            let status = sideStore.isPaused ? "paused:\(Int(sideStore.remainingPauseTime))" : "active"
            completionHandler?(status.data(using: .utf8))
        default:
            completionHandler?(nil)
        }
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
        var excluded = [NEIPv4Route(destinationAddress: config.serverHost, subnetMask: "255.255.255.255")]
        // Exclude Apple subnets so SideStore can re-sign the app
        for route in SideStoreController.excludedRoutePairs {
            excluded.append(NEIPv4Route(destinationAddress: route.destination, subnetMask: route.mask))
        }
        ipv4.excludedRoutes = excluded
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
        // Device → VPN server: uses readPackets' async callback pattern.
        // Each callback re-registers for the next batch — no blocking loop needed.
        readPacketsFromDevice()

        // VPN server → Device: runs on a SEPARATE concurrent queue because
        // recvPacket() blocks until data arrives. If this ran on the same
        // serial queue as device→server, one direction would starve the other.
        serverReadQueue.async { [weak self] in
            self?.forwardFromServer()
        }
    }

    /// Reads packets from the TUN interface and sends them to the VPN server.
    /// Uses the recursive callback pattern required by NEPacketTunnelProvider:
    /// readPackets calls the completion handler once when packets are available,
    /// then we re-register for the next batch.
    private func readPacketsFromDevice() {
        packetFlow.readPackets { [weak self] packets, _ in
            guard let self = self, let client = self.vpnClient, client.isConnected else { return }
            // Skip forwarding while paused (SideStore refresh)
            if !self.sideStore.isPaused {
                for packet in packets {
                    try? client.sendPacket(packet)
                }
            }
            // Re-register for the next batch of packets
            self.readPacketsFromDevice()
        }
    }

    /// Reads packets from the VPN server and injects them into the TUN interface.
    /// Runs on serverReadQueue — blocks on recvPacket() without starving device→server.
    private func forwardFromServer() {
        while let client = vpnClient, client.isConnected {
            let packet = client.recvPacket()
            guard !packet.isEmpty else { continue }
            // Skip forwarding while paused (SideStore refresh)
            if sideStore.isPaused { continue }
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
