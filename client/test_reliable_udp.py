"""Tests for reliable_udp.py — reliable ordered UDP transport."""

import socket
import struct
import threading
import time

import pytest

from reliable_udp import (
    HEADER_SIZE,
    MAX_PAYLOAD_SIZE,
    PACKET_TYPE_ACK,
    PACKET_TYPE_DATA,
    ReliableUDP,
    decode_packet,
    encode_packet,
)


# ---------------------------------------------------------------------------
# Encode / Decode
# ---------------------------------------------------------------------------

class TestEncodeDecodePacket:
    def test_encode_data_packet(self):
        raw = encode_packet(PACKET_TYPE_DATA, 42, 7, b"hello")
        assert len(raw) == HEADER_SIZE + 5

    def test_decode_data_packet(self):
        raw = encode_packet(PACKET_TYPE_DATA, 42, 7, b"hello")
        ptype, seq, ack, payload = decode_packet(raw)
        assert ptype == PACKET_TYPE_DATA
        assert seq == 42
        assert ack == 7
        assert payload == b"hello"

    def test_encode_ack_packet(self):
        raw = encode_packet(PACKET_TYPE_ACK, 0, 99)
        assert len(raw) == HEADER_SIZE

    def test_decode_ack_packet(self):
        raw = encode_packet(PACKET_TYPE_ACK, 0, 99)
        ptype, seq, ack, payload = decode_packet(raw)
        assert ptype == PACKET_TYPE_ACK
        assert ack == 99
        assert payload == b""

    def test_decode_too_short(self):
        with pytest.raises(ValueError, match="too short"):
            decode_packet(b"\x01\x00")

    def test_decode_truncated(self):
        # Header says 100 bytes payload but provides none.
        hdr = struct.pack("!BIIH", PACKET_TYPE_DATA, 0, 0, 100)
        with pytest.raises(ValueError, match="truncated"):
            decode_packet(hdr)

    def test_roundtrip_empty_payload(self):
        raw = encode_packet(PACKET_TYPE_DATA, 1, 0, b"")
        ptype, seq, ack, payload = decode_packet(raw)
        assert ptype == PACKET_TYPE_DATA
        assert seq == 1
        assert payload == b""

    def test_roundtrip_large_payload(self):
        data = bytes(range(256)) * 5  # 1280 bytes
        raw = encode_packet(PACKET_TYPE_DATA, 100, 50, data)
        ptype, seq, ack, payload = decode_packet(raw)
        assert payload == data


# ---------------------------------------------------------------------------
# ReliableUDP loopback tests
# ---------------------------------------------------------------------------

def _make_pair():
    """Create a client/server ReliableUDP pair over loopback UDP sockets."""
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_sock.bind(("127.0.0.1", 0))
    server_addr = server_sock.getsockname()

    client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_sock.bind(("127.0.0.1", 0))
    client_addr = client_sock.getsockname()

    client = ReliableUDP(client_sock, server_addr)
    server = ReliableUDP(server_sock, client_addr)

    return client, server


class TestReliableUDP:
    def test_write_read(self):
        client, server = _make_pair()
        try:
            client.write(b"hello")
            data = server.read()
            assert data == b"hello"
        finally:
            client.close()
            server.close()

    def test_multiple_messages(self):
        client, server = _make_pair()
        try:
            for i in range(5):
                msg = f"msg-{i}".encode()
                client.write(msg)

            for i in range(5):
                data = server.read()
                assert data == f"msg-{i}".encode()
        finally:
            client.close()
            server.close()

    def test_bidirectional(self):
        client, server = _make_pair()
        try:
            client.write(b"ping")
            assert server.read() == b"ping"

            server.write(b"pong")
            assert client.read() == b"pong"
        finally:
            client.close()
            server.close()

    def test_large_payload_fragmentation(self):
        """Data > MAX_PAYLOAD_SIZE should be fragmented and reassembled."""
        client, server = _make_pair()
        try:
            data = bytes(range(256)) * 20  # 5120 bytes > MAX_PAYLOAD_SIZE
            client.write(data)

            received = bytearray()
            while len(received) < len(data):
                chunk = server.read()
                received.extend(chunk)

            assert bytes(received) == data
        finally:
            client.close()
            server.close()

    def test_close(self):
        client, server = _make_pair()
        client.close()
        assert client._closed

        with pytest.raises(ConnectionError):
            client.write(b"after close")

        server.close()

    def test_sendall_alias(self):
        client, server = _make_pair()
        try:
            client.sendall(b"test")
            assert server.read() == b"test"
        finally:
            client.close()
            server.close()

    def test_recv_alias(self):
        client, server = _make_pair()
        try:
            client.write(b"abc")
            assert server.recv(1024) == b"abc"
        finally:
            client.close()
            server.close()

    def test_concurrent_writes(self):
        client, server = _make_pair()
        errors = []

        def writer(prefix, count):
            try:
                for i in range(count):
                    client.write(f"{prefix}-{i}".encode())
            except Exception as e:
                errors.append(e)

        try:
            threads = [
                threading.Thread(target=writer, args=("A", 10)),
                threading.Thread(target=writer, args=("B", 10)),
            ]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=5)

            # Read all 20 messages.
            received = set()
            for _ in range(20):
                data = server.read()
                received.add(data.decode())

            assert len(received) == 20
            assert not errors
        finally:
            client.close()
            server.close()

    def test_socket_interface_compat(self):
        """ReliableUDP should have settimeout and setsockopt (no-ops)."""
        client, server = _make_pair()
        try:
            client.settimeout(5)
            client.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)
            assert client.getpeername() is not None
            assert client.getsockname() is not None
        finally:
            client.close()
            server.close()
