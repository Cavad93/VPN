"""Tests for reliable_udp.py — reliable ordered UDP transport."""

import socket
import struct
import threading
import time

import pytest

from reliable_udp import (
    HEADER_SIZE,
    MAX_PAYLOAD_SIZE,
    MAX_WINDOW_SIZE,
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

    def test_fast_retransmit_triggers_on_3rd_dup_ack(self):
        """3 duplicate ACKs trigger fast retransmit and enter fast recovery.

        RFC 5681 §3.2:
          - ssthresh = max(in_flight / 2, 2)
          - cwnd = ssthresh + 3
          - _in_fast_recovery = True
          - The missing packet (ack_num) is retransmitted immediately.
        """
        client, server = _make_pair()
        try:
            client._cwnd = 16
            client._ssthresh = 64
            client._high_ack = 5

            # Inject 8 fake in-flight packets (seq 5..12).
            from reliable_udp import _PendingPacket
            fake_raw = encode_packet(PACKET_TYPE_DATA, 0, 0, b"x")
            for seq in range(5, 13):
                pp = _PendingPacket(fake_raw)
                pp.sent_at = time.monotonic()
                client._pending[seq] = pp

            in_flight = len(client._pending)          # 8
            expected_ssthresh = max(in_flight // 2, 2)  # 4

            # First two dup ACKs: no fast retransmit yet.
            client._process_ack(5)
            assert client._dup_ack_count == 1
            assert not client._in_fast_recovery

            client._process_ack(5)
            assert client._dup_ack_count == 2
            assert not client._in_fast_recovery

            # Third dup ACK: fast retransmit fires.
            client._process_ack(5)
            assert client._dup_ack_count == 3
            assert client._in_fast_recovery
            assert client._ssthresh == expected_ssthresh
            assert client._cwnd == expected_ssthresh + 3
        finally:
            client.close()
            server.close()

    def test_fast_recovery_cwnd_inflates_on_additional_dup_acks(self):
        """During fast recovery, each additional dup ACK inflates cwnd by 1."""
        client, server = _make_pair()
        try:
            client._cwnd = 7
            client._ssthresh = 4
            client._high_ack = 5
            client._in_fast_recovery = True
            client._dup_ack_count = 3

            from reliable_udp import _PendingPacket
            fake_raw = encode_packet(PACKET_TYPE_DATA, 0, 0, b"x")
            for seq in range(5, 10):
                pp = _PendingPacket(fake_raw)
                pp.sent_at = time.monotonic()
                client._pending[seq] = pp

            # 4th dup ACK → cwnd += 1 (7→8).
            client._process_ack(5)
            assert client._cwnd == 8
            assert client._in_fast_recovery

            # 5th dup ACK → cwnd += 1 (8→9).
            client._process_ack(5)
            assert client._cwnd == 9
            assert client._in_fast_recovery
        finally:
            client.close()
            server.close()

    def test_fast_recovery_exit_on_full_ack(self):
        """A new cumulative ACK exits fast recovery and deflates cwnd to ssthresh."""
        client, server = _make_pair()
        try:
            client._cwnd = 10      # inflated during recovery
            client._ssthresh = 4
            client._high_ack = 5
            client._dup_ack_count = 5
            client._in_fast_recovery = True

            # Full ACK advances past all outstanding data.
            client._process_ack(13)

            assert not client._in_fast_recovery
            assert client._dup_ack_count == 0
            assert client._cwnd == 4   # deflated to ssthresh
        finally:
            client.close()
            server.close()

    def test_retransmit_resets_fast_recovery(self):
        """RTO timeout resets fast recovery state before multiplicative decrease."""
        client, server = _make_pair()
        try:
            client._cwnd = 10
            client._ssthresh = 8
            client._in_fast_recovery = True
            client._dup_ack_count = 4
            client._rto = 0.001

            from reliable_udp import _PendingPacket
            fake_raw = encode_packet(PACKET_TYPE_DATA, 0, 0, b"x")
            pp = _PendingPacket(fake_raw)
            pp.sent_at = 0.0   # always expired
            client._pending[0] = pp

            client._do_retransmit()

            assert not client._in_fast_recovery
            assert client._dup_ack_count == 0
        finally:
            client.close()
            server.close()

    def test_initial_congestion_window_rfc6928(self):
        """Initial cwnd MUST be 10 (RFC 6928) and ssthresh MUST be MAX_WINDOW_SIZE (RFC 5681 §3.1).

        RFC 6928 §1: IW = min(10*SMSS, max(2*SMSS, 14600)).  For SMSS=1460 this
        equals 10 segments.  Linux uses this as default since kernel 2.6.39 (2011).

        RFC 5681 §3.1: initial ssthresh SHOULD be arbitrarily high so slow start
        continues until the network signals congestion — not until an artificial
        host-side limit.  Setting ssthresh=32 would prematurely cap slow start well
        below the BDP (≈47 segments at 7.64 Mbps, RTT=72ms), adding ~1.2 seconds
        of sub-optimal throughput at connection start and after each reconnect.
        """
        client, server = _make_pair()
        try:
            assert client._cwnd == 10, (
                f"Initial cwnd={client._cwnd}, want 10 (RFC 6928)"
            )
            assert client._ssthresh == MAX_WINDOW_SIZE, (
                f"Initial ssthresh={client._ssthresh}, want MAX_WINDOW_SIZE={MAX_WINDOW_SIZE} (RFC 5681 §3.1)"
            )
        finally:
            client.close()
            server.close()

    def test_retransmit_md_once_per_event(self):
        """Multiplicative decrease must apply at most once per _do_retransmit() call.

        RFC 6298 §5.4: MD is applied per retransmit EVENT, not per packet.
        Calling _do_retransmit() with N timed-out packets should halve cwnd
        exactly once, not N times.
        """
        client, server = _make_pair()
        try:
            initial_cwnd = 32
            client._cwnd = initial_cwnd
            client._ssthresh = 64
            client._rto = 0.001  # very short so packets are "timed out"

            # Inject 4 fake pending packets all past their RTO.
            from reliable_udp import _PendingPacket
            fake_raw = encode_packet(PACKET_TYPE_DATA, 0, 0, b"x")
            for seq in range(4):
                pp = _PendingPacket(fake_raw)
                pp.sent_at = 0.0  # epoch — always < rto
                client._pending[seq] = pp

            initial_rto = client._rto
            client._do_retransmit()

            # cwnd should be halved ONCE (32→16), not 4 times (32→2).
            assert client._cwnd == max(initial_cwnd // 2, 2), (
                f"cwnd={client._cwnd}, expected {initial_cwnd // 2} — MD applied multiple times"
            )
            # RTO should be doubled ONCE, not 4 times.
            assert client._rto == pytest.approx(initial_rto * 2, rel=0.01), (
                f"rto={client._rto}, expected {initial_rto * 2} — RTO backoff applied multiple times"
            )
        finally:
            client.close()
            server.close()
