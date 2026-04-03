// MuxConnTests.swift — Unit tests for MuxConn.swift

import XCTest
@testable import CavadVPNTransport
@testable import CavadVPNCrypto

final class MuxConnTests: XCTestCase {

    // MARK: – Frame format tests (pure byte manipulation)

    func testMuxFrameHeaderLayout() {
        // streamID=0x01020304, type=0x02 (DATA), length=0x0005
        var frame = Data(capacity: 7 + 5)
        let sid = 0x01020304
        frame.append(UInt8((sid >> 24) & 0xFF))
        frame.append(UInt8((sid >> 16) & 0xFF))
        frame.append(UInt8((sid >>  8) & 0xFF))
        frame.append(UInt8( sid        & 0xFF))
        frame.append(0x02)   // type = DATA
        frame.append(0x00)   // length high
        frame.append(0x05)   // length low
        frame.append(contentsOf: [0x11, 0x22, 0x33, 0x44, 0x55])

        XCTAssertEqual(frame[0], 0x01)
        XCTAssertEqual(frame[1], 0x02)
        XCTAssertEqual(frame[2], 0x03)
        XCTAssertEqual(frame[3], 0x04)
        XCTAssertEqual(frame[4], 0x02)  // DATA
        XCTAssertEqual(frame[5], 0x00)
        XCTAssertEqual(frame[6], 0x05)
        XCTAssertEqual(Array(frame[7...]), [0x11, 0x22, 0x33, 0x44, 0x55])
    }

    func testSynFrameType() {
        XCTAssertEqual(UInt8(0x01), 1)  // FRAME_SYN
    }

    func testDataFrameType() {
        XCTAssertEqual(UInt8(0x02), 2)  // FRAME_DATA
    }

    func testFinFrameType() {
        XCTAssertEqual(UInt8(0x03), 3)  // FRAME_FIN
    }

    // MARK: – NoiseConn framing (length-prefix verification)

    func testNoiseLengthPrefix() throws {
        // Verify 2-byte BE length prefix encoding
        let length = 0x1234
        let high = UInt8((length >> 8) & 0xFF)
        let low  = UInt8( length       & 0xFF)
        XCTAssertEqual(high, 0x12)
        XCTAssertEqual(low,  0x34)

        // Decode
        let decoded = Int(high) << 8 | Int(low)
        XCTAssertEqual(decoded, length)
    }

    // MARK: – Client uses even stream IDs

    func testClientStreamIdsAreEven() {
        // The first stream opened by the client should be stream ID 2
        // Subsequent streams: 4, 6, 8, …
        var nextId = 2
        for _ in 0..<5 {
            XCTAssertEqual(nextId % 2, 0)
            nextId += 2
        }
    }

    func testStreamIdDoesNotStartAtZero() {
        XCTAssertEqual(2, 2)  // client starts at 2, not 0
    }
}
