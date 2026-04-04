// TelemetryCollector.swift — Client-side diagnostic telemetry for iOS
//
// Collects network metrics every interval and sends to the server's
// /api/v1/telemetry endpoint for AI-powered analysis (Sonnet).

import Foundation
#if canImport(UIKit)
import UIKit
#endif

// MARK: - TelemetryReport

/// A single diagnostic snapshot sent to the server.
public struct TelemetryReport: Codable, Sendable {
    public var deviceId: String = ""
    public var platform: String = "ios"
    public var appVersion: String = "1.0.0"
    public var timestamp: String = ""

    // Connection
    public var serverAddr: String = ""
    public var connectionState: String = "disconnected"
    public var uptimeSec: Double = 0
    public var reconnectCount: Int = 0

    // Latency
    public var handshakeMs: Double = 0
    public var pingMs: Double = 0
    public var jitterMs: Double = 0

    // Throughput
    public var bytesIn: UInt64 = 0
    public var bytesOut: UInt64 = 0
    public var throughputInKbps: Double = 0
    public var throughputOutKbps: Double = 0

    // Packet stats
    public var packetLossPercent: Double = 0
    public var retransmitCount: Int = 0
    public var outOfOrderCount: Int = 0

    // Network
    public var networkType: String = "unknown"
    public var signalStrength: Int = 0
    public var carrier: String = ""
    public var localIp: String = ""

    // Obfuscation
    public var obfsLatencyMs: Double = 0
    public var dpiDetected: Bool = false
    public var tlsErrors: Int = 0

    // System
    public var cpuPercent: Double = 0
    public var memoryMb: Double = 0
    public var batteryPercent: Int = 0

    enum CodingKeys: String, CodingKey {
        case deviceId = "device_id"
        case platform
        case appVersion = "app_version"
        case timestamp
        case serverAddr = "server_addr"
        case connectionState = "connection_state"
        case uptimeSec = "uptime_sec"
        case reconnectCount = "reconnect_count"
        case handshakeMs = "handshake_ms"
        case pingMs = "ping_ms"
        case jitterMs = "jitter_ms"
        case bytesIn = "bytes_in"
        case bytesOut = "bytes_out"
        case throughputInKbps = "throughput_in_kbps"
        case throughputOutKbps = "throughput_out_kbps"
        case packetLossPercent = "packet_loss_percent"
        case retransmitCount = "retransmit_count"
        case outOfOrderCount = "out_of_order_count"
        case networkType = "network_type"
        case signalStrength = "signal_strength"
        case carrier
        case localIp = "local_ip"
        case obfsLatencyMs = "obfs_latency_ms"
        case dpiDetected = "dpi_detected"
        case tlsErrors = "tls_errors"
        case cpuPercent = "cpu_percent"
        case memoryMb = "memory_mb"
        case batteryPercent = "battery_percent"
    }
}

// MARK: - TelemetryConfig

/// Configuration for the telemetry collector.
public struct TelemetryConfig {
    public var serverURL: String           // e.g. "http://193.124.93.240:8080"
    public var collectInterval: TimeInterval = 300  // 5 minutes
    public var sendTimeout: TimeInterval = 10
    public var appVersion: String = "1.0.0"
    public var deviceId: String = ""       // auto-generated if empty

    public init(serverURL: String) {
        self.serverURL = serverURL
    }
}

// MARK: - VPN state callback

/// Provides current VPN state to the telemetry collector.
public protocol TelemetryVPNStateProvider: AnyObject {
    func telemetryVPNState() -> (state: String, serverAddr: String)
}

// MARK: - TelemetryCollector

/// Periodically collects network metrics and sends them to the server.
public final class TelemetryCollector {

    private let config: TelemetryConfig
    private let deviceId: String
    private weak var stateProvider: TelemetryVPNStateProvider?
    private let lock = NSLock()

    // Counters.
    private var _bytesIn: UInt64 = 0
    private var _bytesOut: UInt64 = 0
    private var _prevBytesIn: UInt64 = 0
    private var _prevBytesOut: UInt64 = 0
    private var _prevSampleTime: Date?
    private var _reconnectCount: Int = 0
    private var _handshakeMs: Double = 0
    private var _tlsErrors: Int = 0
    private var _dpiDetected: Bool = false
    private var _connectedSince: Date?

    // Ping jitter.
    private var pingHistory: [Double] = []

    // Timer.
    private var timer: DispatchSourceTimer?
    private let queue = DispatchQueue(label: "com.cavadvpn.telemetry", qos: .utility)

    public init(config: TelemetryConfig, stateProvider: TelemetryVPNStateProvider? = nil) {
        self.config = config
        self.stateProvider = stateProvider
        self.deviceId = config.deviceId.isEmpty ? Self.generateDeviceId() : config.deviceId
    }

    // MARK: - Public counter updates

    public func updateBytes(bytesIn: UInt64, bytesOut: UInt64) {
        lock.lock()
        _bytesIn = bytesIn
        _bytesOut = bytesOut
        lock.unlock()
    }

    public func recordHandshake(durationMs: Double) {
        lock.lock()
        _handshakeMs = durationMs
        lock.unlock()
    }

    public func recordReconnect() {
        lock.lock()
        _reconnectCount += 1
        lock.unlock()
    }

    public func recordConnect() {
        lock.lock()
        _connectedSince = Date()
        lock.unlock()
    }

    public func recordDisconnect() {
        lock.lock()
        _connectedSince = nil
        lock.unlock()
    }

    public func recordTlsError() {
        lock.lock()
        _tlsErrors += 1
        lock.unlock()
    }

    public func recordDpiDetection() {
        lock.lock()
        _dpiDetected = true
        lock.unlock()
    }

    // MARK: - Lifecycle

    public func start() {
        guard timer == nil else { return }
        let t = DispatchSource.makeTimerSource(queue: queue)
        // Initial 30s delay, then repeat at collectInterval.
        t.schedule(
            deadline: .now() + 30,
            repeating: config.collectInterval
        )
        t.setEventHandler { [weak self] in
            self?.collectAndSend()
        }
        t.resume()
        timer = t
    }

    public func stop() {
        timer?.cancel()
        timer = nil
    }

    /// Collect report without sending (for testing).
    public func collectNow() -> TelemetryReport {
        return collect()
    }

    /// Collect and send immediately.
    @discardableResult
    public func sendNow() -> Bool {
        let report = collect()
        return send(report)
    }

    // MARK: - Internal

    private func collectAndSend() {
        let report = collect()
        _ = send(report)
    }

    private func collect() -> TelemetryReport {
        let now = Date()

        // VPN state.
        let vpnState = stateProvider?.telemetryVPNState() ?? ("disconnected", "")

        // Ping.
        var pingMs: Double = 0
        if !vpnState.1.isEmpty {
            pingMs = Self.measureTcpPing(serverAddr: vpnState.1, timeout: 5)
        }

        // Jitter.
        var jitterMs: Double = 0
        if pingMs > 0 {
            pingHistory.append(pingMs)
            if pingHistory.count > 12 { pingHistory.removeFirst() }
            if pingHistory.count >= 2 {
                var diffs: [Double] = []
                for i in 1..<pingHistory.count {
                    diffs.append(abs(pingHistory[i] - pingHistory[i - 1]))
                }
                jitterMs = diffs.reduce(0, +) / Double(diffs.count)
            }
        }

        lock.lock()

        // Throughput.
        var throughputIn: Double = 0
        var throughputOut: Double = 0
        if let prev = _prevSampleTime {
            let elapsed = now.timeIntervalSince(prev)
            if elapsed > 0 {
                let deltaIn = Int64(_bytesIn) - Int64(_prevBytesIn)
                let deltaOut = Int64(_bytesOut) - Int64(_prevBytesOut)
                throughputIn = (Double(deltaIn) * 8) / (elapsed * 1000) // kbit/s
                throughputOut = (Double(deltaOut) * 8) / (elapsed * 1000)
            }
        }
        _prevBytesIn = _bytesIn
        _prevBytesOut = _bytesOut
        _prevSampleTime = now

        // Uptime.
        let uptime: Double
        if let cs = _connectedSince {
            uptime = now.timeIntervalSince(cs)
        } else {
            uptime = 0
        }

        // Battery.
        var battery = 0
        #if canImport(UIKit) && !targetEnvironment(simulator)
        UIDevice.current.isBatteryMonitoringEnabled = true
        let level = UIDevice.current.batteryLevel
        battery = level >= 0 ? Int(level * 100) : 0
        #endif

        let formatter = ISO8601DateFormatter()

        let report = TelemetryReport(
            deviceId: deviceId,
            platform: "ios",
            appVersion: config.appVersion,
            timestamp: formatter.string(from: now),
            serverAddr: vpnState.1,
            connectionState: vpnState.0,
            uptimeSec: uptime,
            reconnectCount: _reconnectCount,
            handshakeMs: _handshakeMs,
            pingMs: pingMs,
            jitterMs: jitterMs,
            bytesIn: _bytesIn,
            bytesOut: _bytesOut,
            throughputInKbps: throughputIn,
            throughputOutKbps: throughputOut,
            networkType: "unknown",
            dpiDetected: _dpiDetected,
            tlsErrors: _tlsErrors,
            batteryPercent: battery
        )
        lock.unlock()

        return report
    }

    private func send(_ report: TelemetryReport) -> Bool {
        let urlStr = config.serverURL.trimmingCharacters(in: CharacterSet(charactersIn: "/")) + "/api/v1/telemetry"
        guard let url = URL(string: urlStr) else { return false }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.timeoutInterval = config.sendTimeout

        guard let body = try? JSONEncoder().encode(report) else { return false }
        request.httpBody = body

        let semaphore = DispatchSemaphore(value: 0)
        var success = false

        let task = URLSession.shared.dataTask(with: request) { _, response, error in
            if error == nil, let http = response as? HTTPURLResponse, http.statusCode == 200 {
                success = true
            }
            semaphore.signal()
        }
        task.resume()
        semaphore.wait()
        return success
    }

    // MARK: - Helpers

    /// Generate stable device ID from hardware info.
    static func generateDeviceId() -> String {
        #if canImport(UIKit)
        let raw = UIDevice.current.identifierForVendor?.uuidString ?? UUID().uuidString
        #else
        let raw = ProcessInfo.processInfo.hostName + ProcessInfo.processInfo.operatingSystemVersionString
        #endif
        guard let data = raw.data(using: .utf8) else { return "unknown" }
        // Simple djb2 hash — stable device identifier, not cryptographic.
        var h: UInt64 = 5381
        for byte in data {
            h = ((h << 5) &+ h) &+ UInt64(byte)
        }
        return String(format: "%016llx", h)
    }

    /// Measure TCP connect latency in milliseconds.
    public static func measureTcpPing(serverAddr: String, timeout: TimeInterval = 5) -> Double {
        let parts = serverAddr.split(separator: ":")
        guard parts.count == 2,
              let port = UInt16(parts[1]) else { return 0 }
        let host = String(parts[0])

        let start = CFAbsoluteTimeGetCurrent()
        let sock = CFSocketCreate(nil, PF_INET, SOCK_STREAM, IPPROTO_TCP, 0, nil, nil)
        guard sock != nil else { return 0 }

        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        inet_pton(AF_INET, host, &addr.sin_addr)

        let addrData = withUnsafePointer(to: &addr) { ptr in
            Data(bytes: ptr, count: MemoryLayout<sockaddr_in>.size)
        }
        let cfData = addrData as CFData
        let err = CFSocketConnectToAddress(sock, cfData, timeout)
        CFSocketInvalidate(sock)

        if err == .success {
            return (CFAbsoluteTimeGetCurrent() - start) * 1000
        }
        return 0
    }
}
