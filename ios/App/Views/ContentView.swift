// ContentView.swift — Main screen: connect/disconnect button, status, traffic stats

import SwiftUI
import NetworkExtension

/// The root view of the CavadVPN iOS app.
struct ContentView: View {

    @StateObject private var vm = ConnectionViewModel()
    @State private var showSettings = false
    @State private var showQRScanner = false
    @State private var showQRError   = false
    @State private var qrErrorMsg    = ""

    // Stats refresh timer
    private let statsTimer = Timer.publish(every: 1, on: .main, in: .common).autoconnect()

    var body: some View {
        NavigationStack {
            VStack(spacing: 32) {
                Spacer()

                // — Status icon —
                statusIcon

                // — Status label —
                Text(vm.state.label)
                    .font(.title2.weight(.semibold))
                    .foregroundStyle(statusColor)
                    .animation(.easeInOut, value: vm.state.label)

                // — Connect / Disconnect button —
                connectButton

                // — Traffic stats card (visible only when connected) —
                if case .connected(let stats) = vm.state {
                    statsCard(stats)
                        .transition(.opacity.combined(with: .move(edge: .bottom)))
                }

                Spacer()

                // — No config warning —
                if vm.config == nil {
                    Label("No server configured. Tap ⚙ to set up.", systemImage: "exclamationmark.circle")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal)
                }
            }
            .padding()
            .animation(.spring(response: 0.4), value: vm.state.isConnected)
            .navigationTitle("CavadVPN")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button(action: { showQRScanner = true }) {
                        Label("Scan QR", systemImage: "qrcode.viewfinder")
                    }
                }
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button(action: { showSettings = true }) {
                        Label("Settings", systemImage: "gearshape.fill")
                    }
                }
            }
            .sheet(isPresented: $showSettings, onDismiss: { vm.loadConfig() }) {
                SettingsView(vm: vm)
            }
            .sheet(isPresented: $showQRScanner) {
                QRScanView { result in
                    showQRScanner = false
                    handleQRResult(result)
                }
            }
            .alert("QR Error", isPresented: $showQRError) {
                Button("OK") {}
            } message: {
                Text(qrErrorMsg)
            }
            .onReceive(statsTimer) { _ in
                refreshStats()
            }
        }
    }

    // MARK: - Subviews

    @ViewBuilder
    private var statusIcon: some View {
        ZStack {
            Circle()
                .fill(statusColor.opacity(0.15))
                .frame(width: 140, height: 140)

            Circle()
                .stroke(statusColor, lineWidth: 3)
                .frame(width: 140, height: 140)

            if vm.state.isTransitioning {
                ProgressView()
                    .scaleEffect(2)
                    .tint(statusColor)
            } else {
                Image(systemName: vm.state.symbolName)
                    .font(.system(size: 56, weight: .semibold))
                    .foregroundStyle(statusColor)
            }
        }
    }

    @ViewBuilder
    private var connectButton: some View {
        if vm.state.canConnect {
            Button(action: { vm.connect() }) {
                Text("Connect")
                    .font(.headline)
                    .frame(maxWidth: .infinity)
                    .padding()
                    .background(Color.accentColor)
                    .foregroundStyle(.white)
                    .clipShape(RoundedRectangle(cornerRadius: 14))
            }
            .disabled(vm.config == nil)
            .padding(.horizontal, 32)
        } else if vm.state.canDisconnect {
            Button(action: { vm.disconnect() }) {
                Text("Disconnect")
                    .font(.headline)
                    .frame(maxWidth: .infinity)
                    .padding()
                    .background(Color.red.opacity(0.9))
                    .foregroundStyle(.white)
                    .clipShape(RoundedRectangle(cornerRadius: 14))
            }
            .padding(.horizontal, 32)
        } else {
            // Transitioning — show disabled button
            Button(action: {}) {
                Text(vm.state.isTransitioning ? "Please wait…" : "Connect")
                    .font(.headline)
                    .frame(maxWidth: .infinity)
                    .padding()
            }
            .disabled(true)
            .padding(.horizontal, 32)
        }
    }

    @ViewBuilder
    private func statsCard(_ stats: VpnStats) -> some View {
        VStack(spacing: 0) {
            Divider()
            LazyVGrid(columns: [.init(.flexible()), .init(.flexible())], spacing: 16) {
                statItem(label: "Download", value: stats.downloadLabel, icon: "arrow.down.circle.fill")
                statItem(label: "Upload",   value: stats.uploadLabel,   icon: "arrow.up.circle.fill")
                statItem(label: "Uptime",   value: stats.uptimeFormatted, icon: "clock.fill")
                statItem(label: "IP",       value: stats.assignedIP.isEmpty ? "—" : stats.assignedIP,
                         icon: "network")
            }
            .padding()
            .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 16))
        }
        .padding(.horizontal)
    }

    @ViewBuilder
    private func statItem(label: String, value: String, icon: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Label(label, systemImage: icon)
                .font(.caption)
                .foregroundStyle(.secondary)
            Text(value)
                .font(.subheadline.monospacedDigit())
                .fontWeight(.medium)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    // MARK: - Helpers

    private var statusColor: Color {
        switch vm.state {
        case .connected:     return .green
        case .connecting,
             .disconnecting: return .orange
        case .error:         return .red
        default:             return .secondary
        }
    }

    private func handleQRResult(_ text: String) {
        do {
            let parsed = try QRConfig.parse(text)
            vm.applyQRConfig(parsed)
        } catch {
            qrErrorMsg  = error.localizedDescription
            showQRError = true
        }
    }

    private func refreshStats() {
        // Stats are pushed by the tunnel extension via Darwin notifications.
        // In a real implementation query NEVPNManager.shared().connection.
        // This timer tick is the hook point for integration.
    }
}

#Preview {
    ContentView()
}
