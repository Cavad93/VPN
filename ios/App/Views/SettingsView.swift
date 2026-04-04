// SettingsView.swift — Server configuration form

import SwiftUI

/// Settings sheet where the user configures the VPN server parameters.
struct SettingsView: View {

    @ObservedObject var vm: ConnectionViewModel
    @Environment(\.dismiss) private var dismiss

    // Form fields
    @State private var host       = ""
    @State private var portStr    = "443"
    @State private var privateKey = ""
    @State private var serverKey  = ""
    @State private var dnsServer  = "1.1.1.1"
    @State private var mtuStr     = "1420"

    @State private var showKeyAlert = false
    @State private var generatedKey = ""

    var body: some View {
        NavigationStack {
            Form {
                Section("Server") {
                    LabeledContent("Host") {
                        TextField("IP or hostname", text: $host)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                            .multilineTextAlignment(.trailing)
                            .keyboardType(.URL)
                    }
                    LabeledContent("Port") {
                        TextField("443", text: $portStr)
                            .keyboardType(.numberPad)
                            .multilineTextAlignment(.trailing)
                    }
                }

                Section("Encryption Keys") {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Private Key (hex)").font(.caption).foregroundStyle(.secondary)
                        TextField("64 hex characters", text: $privateKey)
                            .font(.caption.monospaced())
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                    }
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Server Public Key (hex, optional)").font(.caption).foregroundStyle(.secondary)
                        TextField("64 hex characters", text: $serverKey)
                            .font(.caption.monospaced())
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                    }
                    Button("Generate New Private Key") {
                        generateKey()
                    }
                    .foregroundStyle(.accentColor)
                }

                Section("Network") {
                    LabeledContent("DNS Server") {
                        TextField("1.1.1.1", text: $dnsServer)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                            .multilineTextAlignment(.trailing)
                            .keyboardType(.decimalPad)
                    }
                    LabeledContent("MTU") {
                        TextField("1420", text: $mtuStr)
                            .keyboardType(.numberPad)
                            .multilineTextAlignment(.trailing)
                    }
                }

                Section {
                    Button("Clear Configuration", role: .destructive) {
                        clearAndDismiss()
                    }
                }
            }
            .navigationTitle("Settings")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") { save() }
                        .disabled(host.trimmingCharacters(in: .whitespaces).isEmpty)
                }
            }
            .alert("Generated Key", isPresented: $showKeyAlert) {
                Button("Copy") { UIPasteboard.general.string = generatedKey }
                Button("OK") {}
            } message: {
                Text(generatedKey)
                    .font(.system(.caption, design: .monospaced))
            }
            .onAppear { populateFields() }
        }
    }

    // MARK: - Actions

    private func populateFields() {
        guard let cfg = vm.config else { return }
        host      = cfg.host
        portStr   = "\(cfg.port)"
        privateKey = cfg.privateKeyHex         ?? ""
        serverKey  = cfg.serverPublicKeyHex    ?? ""
        dnsServer  = cfg.dnsServer
        mtuStr     = "\(cfg.mtu)"
    }

    private func save() {
        let port = Int(portStr) ?? 443
        let mtu  = Int(mtuStr)  ?? 1420
        vm.saveConfig(
            host: host.trimmingCharacters(in: .whitespaces),
            port: port,
            privateKeyHex: privateKey.isEmpty ? nil : privateKey,
            serverPublicKeyHex: serverKey.isEmpty ? nil : serverKey,
            dnsServer: dnsServer.isEmpty ? "1.1.1.1" : dnsServer,
            mtu: mtu
        )
        dismiss()
    }

    private func clearAndDismiss() {
        ConfigStore.clear()
        vm.loadConfig()
        dismiss()
    }

    private func generateKey() {
        // Generate a random 32-byte X25519 private key (RFC 7748 clamp)
        var bytes = [UInt8](repeating: 0, count: 32)
        _ = SecRandomCopyBytes(kSecRandomDefault, 32, &bytes)
        // RFC 7748 clamp
        bytes[0]  &= 248
        bytes[31] &= 127
        bytes[31] |= 64
        let hex = bytes.map { String(format: "%02x", $0) }.joined()
        privateKey   = hex
        generatedKey = hex
        showKeyAlert = true
    }
}

#Preview {
    SettingsView(vm: ConnectionViewModel())
}
