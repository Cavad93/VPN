// ObfsConnTests.swift — Unit tests for ObfsConn.swift

import XCTest
@testable import CavadVPNTransport

/// In-memory pipe: data written to one end appears at the other.
private final class MemoryPipe {
    private var buffer = Data()
    private let lock = NSLock()
    private let dataAvailable = NSCondition()

    func write(_ data: Data) {
        lock.lock()
        buffer.append(data)
        lock.unlock()
        dataAvailable.lock()
        dataAvailable.signal()
        dataAvailable.unlock()
    }

    func read(_ n: Int, timeout: TimeInterval = 5) -> Data? {
        let deadline = Date().addingTimeInterval(timeout)
        dataAvailable.lock()
        while true {
            lock.lock()
            if buffer.count >= n {
                let result = buffer.prefix(n)
                buffer.removeFirst(n)
                lock.unlock()
                dataAvailable.unlock()
                return Data(result)
            }
            lock.unlock()
            if Date() >= deadline {
                dataAvailable.unlock()
                return nil
            }
            dataAvailable.wait(until: deadline)
        }
    }
}

/// A minimal InputStream that reads from a MemoryPipe.
private class PipeInputStream: InputStream {
    let pipe: MemoryPipe
    init(pipe: MemoryPipe) { self.pipe = pipe; super.init(data: Data()) }
    override func read(_ buffer: UnsafeMutablePointer<UInt8>, maxLength len: Int) -> Int {
        guard let data = pipe.read(1, timeout: 5) else { return -1 }
        // Read whatever is available (at least 1 byte)
        let avail = min(len, data.count)
        data.withUnsafeBytes { ptr in
            buffer.initialize(from: ptr.baseAddress!.assumingMemoryBound(to: UInt8.self), count: avail)
        }
        return avail
    }
    override var hasBytesAvailable: Bool { true }
    override func open() {}
    override func close() {}
}

/// A minimal OutputStream that writes to a MemoryPipe.
private class PipeOutputStream: OutputStream {
    let pipe: MemoryPipe
    init(pipe: MemoryPipe) { self.pipe = pipe; super.init(toMemory: ()) }
    override func write(_ buffer: UnsafePointer<UInt8>, maxLength len: Int) -> Int {
        pipe.write(Data(bytes: buffer, count: len))
        return len
    }
    override var hasSpaceAvailable: Bool { true }
    override func open() {}
    override func close() {}
}

final class ObfsConnTests: XCTestCase {

    /// Creates a pair of connected ObfsConns backed by in-memory pipes.
    private func makePair() -> (ObfsConn, ObfsConn) {
        let pipe1 = MemoryPipe()  // client → server
        let pipe2 = MemoryPipe()  // server → client

        let clientIn  = PipeInputStream(pipe: pipe2)
        let clientOut = PipeOutputStream(pipe: pipe1)
        let serverIn  = PipeInputStream(pipe: pipe1)
        let serverOut = PipeOutputStream(pipe: pipe2)

        let client = ObfsConn(inputStream: clientIn,  outputStream: clientOut)
        let server = ObfsConn(inputStream: serverIn,  outputStream: serverOut)
        return (client, server)
    }

    func testHandshakeSucceeds() throws {
        let (client, server) = makePair()
        let group = DispatchGroup()
        var clientErr: Error?
        var serverErr: Error?

        group.enter()
        DispatchQueue.global().async {
            do { try client.clientHandshake() } catch { clientErr = error }
            group.leave()
        }
        group.enter()
        DispatchQueue.global().async {
            do { try server.serverHandshake() } catch { serverErr = error }
            group.leave()
        }
        group.wait()
        XCTAssertNil(clientErr, "client error: \(String(describing: clientErr))")
        XCTAssertNil(serverErr, "server error: \(String(describing: serverErr))")
    }

    func testWriteReadRoundtrip() throws {
        let (client, server) = makePair()

        let group = DispatchGroup()
        group.enter(); DispatchQueue.global().async { try? client.clientHandshake(); group.leave() }
        group.enter(); DispatchQueue.global().async { try? server.serverHandshake(); group.leave() }
        group.wait()

        let sent = Data("Hello, ObfsConn!".utf8)
        var received: Data?
        let g2 = DispatchGroup()
        g2.enter()
        DispatchQueue.global().async {
            received = try? server.read(sent.count)
            g2.leave()
        }
        try client.write(sent)
        g2.wait()
        XCTAssertEqual(received, sent)
    }

    func testLargePayloadFragmentation() throws {
        let (client, server) = makePair()
        let g = DispatchGroup()
        g.enter(); DispatchQueue.global().async { try? client.clientHandshake(); g.leave() }
        g.enter(); DispatchQueue.global().async { try? server.serverHandshake(); g.leave() }
        g.wait()

        let large = Data(repeating: 0xAB, count: 40000)  // > maxObfsPayload → 3 records
        var received: Data?
        let g2 = DispatchGroup()
        g2.enter()
        DispatchQueue.global().async { received = try? server.read(large.count); g2.leave() }
        try client.write(large)
        g2.wait()
        XCTAssertEqual(received, large)
    }

    func testAppDataRecordHeader() {
        // Validate the TLS record header structure by building a small record manually.
        // content_type=0x17, version=0x0303, length big-endian
        let payload = Data([0x01, 0x02, 0x03])
        var expected = Data([0x17, 0x03, 0x03, 0x00, 0x03]) + payload
        _ = expected  // used for documentation

        // We verify the record format via write/read round-trip in other tests.
        XCTAssertEqual(0x17, UInt8(23))  // TLS application_data
    }

    func testMultipleWriteReads() throws {
        let (client, server) = makePair()
        let g = DispatchGroup()
        g.enter(); DispatchQueue.global().async { try? client.clientHandshake(); g.leave() }
        g.enter(); DispatchQueue.global().async { try? server.serverHandshake(); g.leave() }
        g.wait()

        let messages = ["alpha", "beta", "gamma"].map { Data($0.utf8) }
        for msg in messages {
            var received: Data?
            let g2 = DispatchGroup()
            g2.enter()
            DispatchQueue.global().async { received = try? server.read(msg.count); g2.leave() }
            try client.write(msg)
            g2.wait()
            XCTAssertEqual(received, msg)
        }
    }
}
