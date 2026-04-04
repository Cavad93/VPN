import XCTest
@testable import CavadVPNClient

final class SideStoreCompatTests: XCTestCase {

    // MARK: - Apple subnets

    func testAppleSubnetsNotEmpty() {
        XCTAssertFalse(SideStoreCompat.appleSubnets.isEmpty)
    }

    func testAppleSubnetsHaveValidFormat() {
        for subnet in SideStoreCompat.appleSubnets {
            // Each component should have 4 octets
            let netParts = subnet.network.split(separator: ".")
            let maskParts = subnet.mask.split(separator: ".")
            XCTAssertEqual(netParts.count, 4, "Invalid network: \(subnet.network)")
            XCTAssertEqual(maskParts.count, 4, "Invalid mask: \(subnet.mask)")
        }
    }

    func testAppleDomainsNotEmpty() {
        XCTAssertFalse(SideStoreCompat.appleDomains.isEmpty)
    }

    func testAppleDomainsContainPPQ() {
        XCTAssertTrue(SideStoreCompat.appleDomains.contains("ppq.apple.com"),
                      "Must include ppq.apple.com for app signing")
    }

    func testAppleDomainsContainGSA() {
        XCTAssertTrue(SideStoreCompat.appleDomains.contains("gsa.apple.com"),
                      "Must include gsa.apple.com for Anisette/Grand Slam auth")
    }

    // MARK: - Excluded routes

    func testExcludedRoutePairsMatchSubnets() {
        let pairs = SideStoreCompat.excludedRoutePairs()
        XCTAssertEqual(pairs.count, SideStoreCompat.appleSubnets.count)
        for (i, pair) in pairs.enumerated() {
            XCTAssertEqual(pair.destination, SideStoreCompat.appleSubnets[i].network)
            XCTAssertEqual(pair.mask, SideStoreCompat.appleSubnets[i].mask)
        }
    }

    // MARK: - SideStoreCompat struct pause/resume

    func testInitialStateNotPaused() {
        let compat = SideStoreCompat()
        XCTAssertFalse(compat.isPaused)
        XCTAssertNil(compat.lastPauseTime)
        XCTAssertTrue(compat.canPause)
        XCTAssertEqual(compat.remainingPauseTime, 0)
    }

    func testPauseSetsState() {
        var compat = SideStoreCompat(pauseDuration: 5, pauseCooldown: 1)
        let ok = compat.pause()
        XCTAssertTrue(ok)
        XCTAssertTrue(compat.isPaused)
        XCTAssertNotNil(compat.lastPauseTime)
        XCTAssertFalse(compat.canPause) // paused, can't pause again
    }

    func testDoublePauseReturnsFalse() {
        var compat = SideStoreCompat(pauseDuration: 5, pauseCooldown: 1)
        XCTAssertTrue(compat.pause())
        XCTAssertFalse(compat.pause()) // already paused
    }

    func testResumeResetsState() {
        var compat = SideStoreCompat(pauseDuration: 5, pauseCooldown: 0)
        compat.pause()
        XCTAssertTrue(compat.isPaused)
        compat.resume()
        XCTAssertFalse(compat.isPaused)
    }

    func testResumeWhenNotPausedIsNoop() {
        var compat = SideStoreCompat()
        compat.resume() // should not crash
        XCTAssertFalse(compat.isPaused)
    }

    func testRemainingTimeWhilePaused() {
        var compat = SideStoreCompat(pauseDuration: 30, pauseCooldown: 0)
        compat.pause()
        let remaining = compat.remainingPauseTime
        // Should be close to 30 seconds (within 1 second of starting)
        XCTAssertGreaterThan(remaining, 28)
        XCTAssertLessThanOrEqual(remaining, 30)
    }

    func testRemainingTimeWhenNotPaused() {
        let compat = SideStoreCompat()
        XCTAssertEqual(compat.remainingPauseTime, 0)
    }

    func testCooldownPreventsImmediateRepause() {
        var compat = SideStoreCompat(pauseDuration: 1, pauseCooldown: 60)
        compat.pause()
        compat.resume()
        // Cooldown is 60s, should not allow immediate repause
        XCTAssertFalse(compat.canPause)
        XCTAssertFalse(compat.pause())
    }

    func testCallbackOnPause() {
        var compat = SideStoreCompat(pauseDuration: 5, pauseCooldown: 0)
        var callbackValues: [Bool] = []
        compat.onPauseStateChanged = { isPaused in
            callbackValues.append(isPaused)
        }
        compat.pause()
        compat.resume()
        XCTAssertEqual(callbackValues, [true, false])
    }

    // MARK: - SideStoreController (class wrapper)

    func testControllerInitialState() {
        let ctrl = SideStoreController(pauseDuration: 5, pauseCooldown: 0)
        XCTAssertFalse(ctrl.isPaused)
        XCTAssertTrue(ctrl.canPause)
        XCTAssertEqual(ctrl.remainingPauseTime, 0)
    }

    func testControllerPauseResume() {
        let ctrl = SideStoreController(pauseDuration: 30, pauseCooldown: 0)
        XCTAssertTrue(ctrl.pause())
        XCTAssertTrue(ctrl.isPaused)
        XCTAssertFalse(ctrl.canPause)

        ctrl.resume()
        XCTAssertFalse(ctrl.isPaused)
    }

    func testControllerAutoResume() {
        let ctrl = SideStoreController(pauseDuration: 1, pauseCooldown: 0)
        ctrl.pause()
        XCTAssertTrue(ctrl.isPaused)

        // Wait for auto-resume (1 second + margin)
        let expectation = XCTestExpectation(description: "auto-resume")
        DispatchQueue.global().asyncAfter(deadline: .now() + 1.5) {
            expectation.fulfill()
        }
        wait(for: [expectation], timeout: 3)
        XCTAssertFalse(ctrl.isPaused)
    }

    func testControllerCallback() {
        let ctrl = SideStoreController(pauseDuration: 5, pauseCooldown: 0)
        var states: [Bool] = []
        let lock = NSLock()
        ctrl.onPauseStateChanged = { isPaused in
            lock.lock()
            states.append(isPaused)
            lock.unlock()
        }
        ctrl.pause()
        ctrl.resume()
        lock.lock()
        XCTAssertEqual(states, [true, false])
        lock.unlock()
    }

    func testControllerExcludedRoutes() {
        let routes = SideStoreController.excludedRoutePairs
        XCTAssertFalse(routes.isEmpty)
        // Should include Apple's 17.0.0.0/8
        XCTAssertTrue(routes.contains(where: { $0.destination == "17.0.0.0" }))
    }

    func testControllerAppleDomains() {
        let domains = SideStoreController.appleDomains
        XCTAssertTrue(domains.contains("ppq.apple.com"))
        XCTAssertTrue(domains.contains("gsa.apple.com"))
    }

    func testDefaultPauseDuration() {
        let compat = SideStoreCompat()
        XCTAssertEqual(compat.pauseDuration, 30)
    }

    func testDefaultPauseCooldown() {
        let compat = SideStoreCompat()
        XCTAssertEqual(compat.pauseCooldown, 300) // 5 minutes
    }
}
