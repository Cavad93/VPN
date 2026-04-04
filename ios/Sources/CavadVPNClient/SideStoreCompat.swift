// SideStoreCompat.swift — SideStore compatibility for CavadVPN
//
// SideStore re-signs apps every 7 days using a free Apple ID.
// During refresh, SideStore must reach Apple's signing servers directly
// (not through the VPN tunnel). This module provides:
//
// 1. A list of Apple domains/IPs that must bypass the VPN
// 2. A tunnel pause mechanism (30-second freeze on demand)
//
// Usage in PacketTunnelProvider:
//   let compat = SideStoreCompat()
//   let excludedRoutes = compat.excludedRoutes()  // add to NEIPv4Settings
//   compat.pauseIfNeeded { resumed in ... }       // call periodically

import Foundation

/// Apple server subnets used by SideStore for app signing and refresh.
/// These must be routed directly (not through VPN) so SideStore can
/// re-sign the VPN app itself without a chicken-and-egg problem.
public struct SideStoreCompat {

    /// How long the tunnel pauses during SideStore refresh (seconds).
    public let pauseDuration: TimeInterval

    /// Whether the tunnel is currently paused.
    public private(set) var isPaused: Bool = false

    /// Timestamp of last pause (for cooldown logic).
    public private(set) var lastPauseTime: Date?

    /// Minimum interval between pauses to prevent abuse (seconds).
    public let pauseCooldown: TimeInterval

    /// Callback invoked when pause state changes.
    public var onPauseStateChanged: ((Bool) -> Void)?

    private var pauseTimer: DispatchSourceTimer?
    private let lock = NSLock()

    public init(pauseDuration: TimeInterval = 30, pauseCooldown: TimeInterval = 300) {
        self.pauseDuration = pauseDuration
        self.pauseCooldown = pauseCooldown
    }

    // MARK: - Apple bypass subnets

    /// Apple IP subnets that SideStore needs to reach directly.
    /// Covers: Apple ID auth, app signing (ppq), push, and iTunes services.
    public static let appleSubnets: [(network: String, mask: String)] = [
        // Apple ID / auth / signing (17.0.0.0/8 covers most Apple infra)
        ("17.0.0.0",   "255.0.0.0"),
        // Apple CloudKit / iCloud (additional range)
        ("104.248.0.0", "255.255.0.0"),
    ]

    /// Apple domains used by SideStore (for DNS bypass / split-tunnel reference).
    public static let appleDomains: [String] = [
        "ppq.apple.com",                   // provisioning / signing
        "developerservices2.apple.com",     // developer services
        "idmsa.apple.com",                  // Apple ID auth
        "appleid.apple.com",               // Apple ID
        "gsa.apple.com",                   // Grand Slam auth (Anisette)
        "play.itunes.apple.com",           // iTunes
        "apps.mzstatic.com",              // app metadata
        "init.itunes.apple.com",          // iTunes init
        "xp.apple.com",                   // provisioning profiles
        "identity.apple.com",             // identity services
        "bag.itunes.apple.com",           // config bag
    ]

    // MARK: - Route generation

    /// Generates IPv4 excluded routes for NEIPv4Settings.
    /// Call this in configureTunnel() and add to ipv4.excludedRoutes.
    ///
    /// Returns tuples of (destination, subnetMask) suitable for NEIPv4Route.
    public static func excludedRoutePairs() -> [(destination: String, mask: String)] {
        return appleSubnets
    }

    // MARK: - Pause / resume

    /// Pause the tunnel for `pauseDuration` seconds.
    /// Returns false if cooldown hasn't elapsed since last pause.
    @discardableResult
    public mutating func pause() -> Bool {
        lock.lock()
        defer { lock.unlock() }

        guard !isPaused else { return false }

        // Check cooldown
        if let last = lastPauseTime {
            let elapsed = Date().timeIntervalSince(last)
            if elapsed < pauseCooldown {
                return false
            }
        }

        isPaused = true
        lastPauseTime = Date()

        onPauseStateChanged?(true)

        // Schedule auto-resume
        let timer = DispatchSource.makeTimerSource(queue: .global(qos: .utility))
        timer.schedule(deadline: .now() + pauseDuration)
        timer.setEventHandler { [self] in
            // Note: self is captured as struct copy here; the caller must
            // use the resume() method via reference (class wrapper or inout).
        }
        pauseTimer = timer
        timer.resume()

        return true
    }

    /// Resume the tunnel immediately (before pauseDuration elapses).
    public mutating func resume() {
        lock.lock()
        defer { lock.unlock() }

        guard isPaused else { return }

        pauseTimer?.cancel()
        pauseTimer = nil
        isPaused = false

        onPauseStateChanged?(false)
    }

    /// Time remaining until auto-resume, or 0 if not paused.
    public var remainingPauseTime: TimeInterval {
        guard isPaused, let last = lastPauseTime else { return 0 }
        let elapsed = Date().timeIntervalSince(last)
        return max(0, pauseDuration - elapsed)
    }

    /// Whether a pause is allowed right now (cooldown elapsed).
    public var canPause: Bool {
        if isPaused { return false }
        guard let last = lastPauseTime else { return true }
        return Date().timeIntervalSince(last) >= pauseCooldown
    }
}

/// Class wrapper for SideStoreCompat that can be used in async contexts
/// (PacketTunnelProvider) where struct mutation is awkward.
public final class SideStoreController {

    private var compat: SideStoreCompat
    private let lock = NSLock()

    public var isPaused: Bool {
        lock.lock()
        defer { lock.unlock() }
        return compat.isPaused
    }

    public var canPause: Bool {
        lock.lock()
        defer { lock.unlock() }
        return compat.canPause
    }

    public var remainingPauseTime: TimeInterval {
        lock.lock()
        defer { lock.unlock() }
        return compat.remainingPauseTime
    }

    /// Called when pause state changes. Set before calling pause().
    public var onPauseStateChanged: ((Bool) -> Void)? {
        get { compat.onPauseStateChanged }
        set { compat.onPauseStateChanged = newValue }
    }

    public init(pauseDuration: TimeInterval = 30, pauseCooldown: TimeInterval = 300) {
        self.compat = SideStoreCompat(pauseDuration: pauseDuration, pauseCooldown: pauseCooldown)
    }

    /// Pause the tunnel. Returns false if on cooldown.
    @discardableResult
    public func pause() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        let ok = compat.pause()
        if ok {
            // Schedule resume on this class instance
            DispatchQueue.global(qos: .utility).asyncAfter(
                deadline: .now() + compat.pauseDuration
            ) { [weak self] in
                self?.resume()
            }
        }
        return ok
    }

    /// Resume the tunnel immediately.
    public func resume() {
        lock.lock()
        defer { lock.unlock() }
        compat.resume()
    }

    /// Excluded route pairs for NEIPv4Settings.
    public static var excludedRoutePairs: [(destination: String, mask: String)] {
        SideStoreCompat.excludedRoutePairs()
    }

    /// Apple domains for DNS reference.
    public static var appleDomains: [String] {
        SideStoreCompat.appleDomains
    }
}
