// VpnConfigTests.swift — Unit tests for VpnConfig.swift + RouteInfo

import XCTest
@testable import CavadVPNClient

final class VpnConfigTests: XCTestCase {

    // MARK: – VpnConfig basics

    func testDefaultValues() {
        let cfg = VpnConfig(serverHost: "vpn.example.com", serverPort: 443)
        XCTAssertEqual(cfg.serverHost,  "vpn.example.com")
        XCTAssertEqual(cfg.serverPort,  443)
        XCTAssertNil(cfg.privateKeyHex)
        XCTAssertNil(cfg.serverPublicKeyHex)
        XCTAssertEqual(cfg.dnsServer,   "1.1.1.1")
        XCTAssertEqual(cfg.mtu,          1420)
    }

    func testPrivateKeyBytesDecoding() {
        let hex = "aabbccdd" + String(repeating: "00", count: 28)
        let cfg = VpnConfig(serverHost: "h", serverPort: 1, privateKeyHex: hex)
        let bytes = cfg.privateKeyBytes()
        XCTAssertNotNil(bytes)
        XCTAssertEqual(bytes!.count, 32)
        XCTAssertEqual(bytes![0], 0xAA)
        XCTAssertEqual(bytes![1], 0xBB)
    }

    func testServerPublicKeyBytesDecoding() {
        let hex = String(repeating: "ff", count: 32)
        let cfg = VpnConfig(serverHost: "h", serverPort: 1, serverPublicKeyHex: hex)
        let bytes = cfg.serverPublicKeyBytes()
        XCTAssertNotNil(bytes)
        XCTAssertEqual(bytes!.count, 32)
        XCTAssertTrue(bytes!.allSatisfy { $0 == 0xFF })
    }

    func testNilPrivateKeyReturnsNil() {
        let cfg = VpnConfig(serverHost: "h", serverPort: 1)
        XCTAssertNil(cfg.privateKeyBytes())
    }

    // MARK: – Data hex helpers

    func testDataHexStringRoundtrip() {
        let original = Data([0x01, 0xAB, 0xFF, 0x00, 0x42])
        let hex = original.hexString
        XCTAssertEqual(hex, "01abff0042")
        let decoded = Data(hexString: hex)
        XCTAssertEqual(decoded, original)
    }

    func testDataHexStringWithOddLengthReturnsNil() {
        XCTAssertNil(Data(hexString: "abc"))  // odd length
    }

    func testDataHexStringWithInvalidCharsReturnsNil() {
        XCTAssertNil(Data(hexString: "zz"))
    }

    // MARK: – RouteInfo

    func testRouteInfoCIDR() {
        let route = RouteInfo(assignedIP: "10.8.0.2", prefixLen: 24, gateway: "10.8.0.1")
        XCTAssertEqual(route.cidr, "10.8.0.2/24")
    }

    func testRouteInfoNetwork() {
        let route = RouteInfo(assignedIP: "10.8.0.42", prefixLen: 24, gateway: "10.8.0.1")
        XCTAssertEqual(route.network, "10.8.0.0")
    }

    func testRouteInfoGateway() {
        let route = RouteInfo(assignedIP: "192.168.100.5", prefixLen: 16, gateway: "192.168.0.1")
        XCTAssertEqual(route.gateway, "192.168.0.1")
    }

    // MARK: – Knock key (Reality-style port knocking)

    func testKnockKeyBytesValid() {
        let hex = String(repeating: "ab", count: 32)
        let cfg = VpnConfig(serverHost: "h", serverPort: 1, knockKeyHex: hex)
        XCTAssertEqual(cfg.knockKeyBytes()?.count, 32)
    }

    func testKnockKeyNilWhenAbsent() {
        let cfg = VpnConfig(serverHost: "h", serverPort: 1)
        XCTAssertNil(cfg.knockKeyBytes())
    }

    func testKnockKeyRejectsWrongLength() {
        // 8-byte hex → must be rejected so the client falls back to a
        // random session_id rather than sending an invalid HMAC.
        let cfg = VpnConfig(serverHost: "h", serverPort: 1, knockKeyHex: "deadbeefdeadbeef")
        XCTAssertNil(cfg.knockKeyBytes())
    }

    // MARK: – Dual-stack RouteInfo (CTL_ASSIGN_DUAL)

    func testRouteInfoDualStack() {
        let route = RouteInfo(
            assignedIP:  "10.8.0.2", prefixLen:  24, gateway:  "10.8.0.1",
            assignedIP6: "fc00::2",  prefixLen6: 120, gateway6: "fc00::1"
        )
        XCTAssertTrue(route.isDualStack)
        XCTAssertEqual(route.cidr,  "10.8.0.2/24")
        XCTAssertEqual(route.cidr6, "fc00::2/120")
    }

    func testRouteInfoIPv4OnlyNotDualStack() {
        let route = RouteInfo(assignedIP: "10.8.0.2", prefixLen: 24, gateway: "10.8.0.1")
        XCTAssertFalse(route.isDualStack)
        XCTAssertNil(route.cidr6)
    }

    /// The CTL_ASSIGN_DUAL wire format is locked to 42 bytes
    /// (ip4(4) + pfxLen4(1) + gw4(4) + ip6(16) + pfxLen6(1) + gw6(16)).
    /// Verify the parser handles this exact layout end-to-end.
    func testParseCtlAssignDualWireFormat() throws {
        // Build the same 42-byte payload the Go server sends.
        var p = Data()
        p.append(contentsOf: [10, 8, 0, 2])           // ip4
        p.append(24)                                  // pfx4
        p.append(contentsOf: [10, 8, 0, 1])           // gw4
        // fc00::2 = fc 00 00 00 00 00 00 00 00 00 00 00 00 00 00 02
        p.append(contentsOf: [0xFC, 0x00] + Array(repeating: UInt8(0), count: 13) + [0x02])
        p.append(120)                                 // pfx6
        // fc00::1
        p.append(contentsOf: [0xFC, 0x00] + Array(repeating: UInt8(0), count: 13) + [0x01])
        XCTAssertEqual(p.count, 42)

        let route = try VpnClient.parseCtlAssignDual(p)
        XCTAssertEqual(route.assignedIP,  "10.8.0.2")
        XCTAssertEqual(route.prefixLen,    24)
        XCTAssertEqual(route.gateway,     "10.8.0.1")
        XCTAssertEqual(route.assignedIP6, "fc00::2")
        XCTAssertEqual(route.prefixLen6,   120)
        XCTAssertEqual(route.gateway6,    "fc00::1")
    }

    func testParseCtlAssignWireFormat() {
        // Legacy 9-byte IPv4-only payload still works.
        let p = Data([10, 8, 0, 2, 24, 10, 8, 0, 1])
        let route = VpnClient.parseCtlAssign(p)
        XCTAssertEqual(route.assignedIP, "10.8.0.2")
        XCTAssertEqual(route.prefixLen,  24)
        XCTAssertEqual(route.gateway,    "10.8.0.1")
        XCTAssertFalse(route.isDualStack)
    }
}
