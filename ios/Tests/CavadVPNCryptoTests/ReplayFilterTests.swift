// ReplayFilterTests.swift — Unit tests for ReplayFilter.swift

import XCTest
@testable import CavadVPNCrypto

final class ReplayFilterTests: XCTestCase {

    // MARK: – PacketHeader encoding/decoding

    func testPacketHeaderEncodeDecodeRoundtrip() throws {
        let ts    = Int64(Date().timeIntervalSince1970)
        let nonce = generateRandomData(count: nonceSize)
        let hdr   = PacketHeader(timestamp: ts, nonce: nonce)
        let data  = hdr.encode()
        XCTAssertEqual(data.count, packetHeaderSize)
        let decoded = try decodePacketHeader(data)
        XCTAssertEqual(decoded.timestamp, ts)
        XCTAssertEqual(decoded.nonce,     nonce)
    }

    func testPacketHeaderEncodesBigEndianTimestamp() {
        let ts  = Int64(0x0102030405060708)
        let hdr = PacketHeader(timestamp: ts, nonce: Data(repeating: 0, count: nonceSize))
        let enc = hdr.encode()
        XCTAssertEqual(enc[0], 0x01)
        XCTAssertEqual(enc[1], 0x02)
        XCTAssertEqual(enc[2], 0x03)
        XCTAssertEqual(enc[3], 0x04)
    }

    func testDecodePacketHeaderTooShortThrows() {
        XCTAssertThrowsError(try decodePacketHeader(Data([0x01, 0x02])))
    }

    func testNewPacketHeaderHasCurrentTimestamp() {
        let before = Int64(Date().timeIntervalSince1970)
        let hdr    = newPacketHeader()
        let after  = Int64(Date().timeIntervalSince1970)
        XCTAssertGreaterThanOrEqual(hdr.timestamp, before)
        XCTAssertLessThanOrEqual   (hdr.timestamp, after)
        XCTAssertEqual(hdr.nonce.count, nonceSize)
    }

    // MARK: – ReplayFilter

    func testFreshPacketIsAccepted() {
        let filter = ReplayFilter()
        let hdr = newPacketHeader()
        XCTAssertTrue(filter.check(hdr))
    }

    func testReplayIsRejected() {
        let filter = ReplayFilter()
        let hdr = newPacketHeader()
        XCTAssertTrue(filter.check(hdr))
        XCTAssertFalse(filter.check(hdr))  // replay
    }

    func testOutdatedPacketIsRejected() {
        let filter = ReplayFilter()
        let oldTs  = Int64(Date().timeIntervalSince1970) - replayWindowSecs - 1
        let hdr    = PacketHeader(timestamp: oldTs, nonce: generateRandomData(count: nonceSize))
        XCTAssertFalse(filter.check(hdr))
    }

    func testFuturePacketIsRejected() {
        let filter = ReplayFilter()
        let futTs  = Int64(Date().timeIntervalSince1970) + replayWindowSecs + 1
        let hdr    = PacketHeader(timestamp: futTs, nonce: generateRandomData(count: nonceSize))
        XCTAssertFalse(filter.check(hdr))
    }

    func testDifferentNonceSameTimestampAccepted() {
        let filter = ReplayFilter()
        let ts     = Int64(Date().timeIntervalSince1970)
        let hdr1   = PacketHeader(timestamp: ts, nonce: generateRandomData(count: nonceSize))
        let hdr2   = PacketHeader(timestamp: ts, nonce: generateRandomData(count: nonceSize))
        XCTAssertTrue(filter.check(hdr1))
        XCTAssertTrue(filter.check(hdr2))
    }

    func testWindowBoundaryExactlyWindowStart() {
        let filter = ReplayFilter()
        let ts  = Int64(Date().timeIntervalSince1970) - replayWindowSecs
        let hdr = PacketHeader(timestamp: ts, nonce: generateRandomData(count: nonceSize))
        // Exactly at window start — should be accepted
        XCTAssertTrue(filter.check(hdr))
    }

    func testWindowBoundaryExactlyWindowEnd() {
        let filter = ReplayFilter()
        let ts  = Int64(Date().timeIntervalSince1970) + replayWindowSecs
        let hdr = PacketHeader(timestamp: ts, nonce: generateRandomData(count: nonceSize))
        XCTAssertTrue(filter.check(hdr))
    }

    func testManyUniquePacketsAccepted() {
        let filter = ReplayFilter()
        let ts = Int64(Date().timeIntervalSince1970)
        for _ in 0..<100 {
            let hdr = PacketHeader(timestamp: ts, nonce: generateRandomData(count: nonceSize))
            XCTAssertTrue(filter.check(hdr))
        }
    }
}
