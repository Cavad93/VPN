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
}
