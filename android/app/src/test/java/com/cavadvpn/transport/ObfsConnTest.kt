package com.cavadvpn.transport

import org.junit.Assert.*
import org.junit.Test
import java.io.PipedInputStream
import java.io.PipedOutputStream

/** Creates a connected pair of ObfsConn (client, server) using in-memory pipes. */
private fun connectedPair(): Pair<ObfsConn, ObfsConn> {
    val clientToServer = PipedOutputStream()
    val serverToClient = PipedOutputStream()

    val clientIn  = PipedInputStream(serverToClient, 65536)
    val serverIn  = PipedInputStream(clientToServer, 65536)

    val client = ObfsConn(clientIn,  clientToServer)
    val server = ObfsConn(serverIn,  serverToClient)
    return Pair(client, server)
}

class ObfsConnTest {

    @Test fun `client-server handshake succeeds`() {
        val (client, server) = connectedPair()
        var serverError: Exception? = null

        val serverThread = Thread {
            try { server.serverHandshake() }
            catch (e: Exception) { serverError = e }
        }
        serverThread.start()
        client.clientHandshake()
        serverThread.join(2000)

        assertNull("server handshake failed: $serverError", serverError)
    }

    @Test fun `write and read round trip`() {
        val (client, server) = connectedPair()

        Thread { server.serverHandshake() }.also { it.isDaemon = true; it.start() }
        client.clientHandshake()

        val payload = "hello from client".toByteArray()
        var received: ByteArray? = null

        val readThread = Thread { received = server.read(payload.size) }
        readThread.isDaemon = true
        readThread.start()

        client.write(payload)
        readThread.join(2000)

        assertArrayEquals(payload, received)
    }

    @Test fun `fragmentation of large payload`() {
        val (client, server) = connectedPair()

        Thread { server.serverHandshake() }.also { it.isDaemon = true; it.start() }
        client.clientHandshake()

        // 40 KB — forces multiple TLS records (max 16383 bytes each)
        val large = ByteArray(40_000) { (it % 256).toByte() }
        var received: ByteArray? = null

        val readThread = Thread { received = server.read(large.size) }
        readThread.isDaemon = true
        readThread.start()

        client.write(large)
        readThread.join(3000)

        assertArrayEquals(large, received)
    }

    @Test fun `bidirectional communication`() {
        val (client, server) = connectedPair()

        Thread { server.serverHandshake() }.also { it.isDaemon = true; it.start() }
        client.clientHandshake()

        val msg1 = "client → server".toByteArray()
        val msg2 = "server → client".toByteArray()

        var fromClient: ByteArray? = null
        var fromServer: ByteArray? = null

        val t1 = Thread { fromClient = server.read(msg1.size); server.write(msg2) }
        t1.isDaemon = true; t1.start()

        client.write(msg1)
        fromServer = client.read(msg2.size)
        t1.join(2000)

        assertArrayEquals(msg1, fromClient)
        assertArrayEquals(msg2, fromServer)
    }

    @Test fun `read buffers across TLS records`() {
        val (client, server) = connectedPair()
        Thread { server.serverHandshake() }.also { it.isDaemon = true; it.start() }
        client.clientHandshake()

        // Send two separate writes — receiver reads with a single large read()
        val part1 = "AAAA".toByteArray()
        val part2 = "BBBB".toByteArray()
        var received: ByteArray? = null

        val readThread = Thread { received = server.read(part1.size + part2.size) }
        readThread.isDaemon = true; readThread.start()

        client.write(part1)
        Thread.sleep(50)
        client.write(part2)
        readThread.join(2000)

        assertArrayEquals(part1 + part2, received)
    }
}
