"""
Reliable UDP transport for the Python VPN client.

Provides ordered, ACKed delivery over UDP with simple congestion control.
The server runs user-space BBR; the client uses a simpler Reno-like scheme
since the bottleneck is the server→client direction (download).

Wire format is identical to the Go server's transport/udp.go:
  type(1) | seqNum(4) | ackNum(4) | payloadLen(2) | payload(n)
"""

import socket
import struct
import threading
import time
from collections import deque
from typing import Optional

import structlog

logger = structlog.get_logger()

# Packet types — must match server/transport/udp.go constants.
PACKET_TYPE_DATA = 0x01
PACKET_TYPE_ACK = 0x02
PACKET_TYPE_SYN = 0x03
PACKET_TYPE_FIN = 0x04

# Protocol constants — match server values.
HEADER_SIZE = 11
MAX_PAYLOAD_SIZE = 1400
MAX_WINDOW_SIZE = 64
RETRANSMIT_TIMEOUT = 0.2  # 200ms
MAX_RETRANSMITS = 10
ACK_DELAY = 0.001  # 1ms delayed ACK


def encode_packet(pkt_type: int, seq_num: int, ack_num: int, payload: bytes = b"") -> bytes:
    """Encode a packet to wire format."""
    hdr = struct.pack("!BIIH", pkt_type, seq_num, ack_num, len(payload))
    return hdr + payload


def decode_packet(data: bytes):
    """Decode a packet from wire format. Returns (type, seq_num, ack_num, payload)."""
    if len(data) < HEADER_SIZE:
        raise ValueError("packet too short")
    pkt_type, seq_num, ack_num, payload_len = struct.unpack("!BIIH", data[:HEADER_SIZE])
    if len(data) < HEADER_SIZE + payload_len:
        raise ValueError("packet truncated")
    payload = data[HEADER_SIZE : HEADER_SIZE + payload_len]
    return pkt_type, seq_num, ack_num, payload


class _PendingPacket:
    __slots__ = ("raw", "sent_at", "retransmits")

    def __init__(self, raw: bytes):
        self.raw = raw
        self.sent_at = time.monotonic()
        self.retransmits = 0


class ReliableUDP:
    """
    Reliable, ordered UDP transport with congestion control.

    Provides a stream-like interface (read/write) compatible with ObfsConn.
    """

    def __init__(self, sock: socket.socket, addr: tuple):
        self._sock = sock
        self._addr = addr
        self._closed = False

        # Send state.
        self._send_lock = threading.Lock()
        self._send_seq = 0
        self._pending: dict[int, _PendingPacket] = {}
        self._cwnd = 4
        self._ssthresh = 32
        self._window_open = threading.Event()
        self._window_open.set()

        # Receive state.
        self._recv_lock = threading.Lock()
        self._recv_seq = 0
        self._recv_buf: dict[int, bytes] = {}  # out-of-order buffer
        self._read_queue: deque[bytes] = deque()
        self._read_event = threading.Event()

        # Delayed ACK state.
        self._ack_lock = threading.Lock()
        self._ack_pending = False
        self._ack_timer: Optional[threading.Timer] = None

        # Background threads.
        self._read_thread = threading.Thread(target=self._recv_loop, daemon=True)
        self._retransmit_thread = threading.Thread(target=self._retransmit_loop, daemon=True)
        self._read_thread.start()
        self._retransmit_thread.start()

    def write(self, data: bytes) -> None:
        """Send data reliably, fragmenting into MAX_PAYLOAD_SIZE chunks."""
        offset = 0
        while offset < len(data):
            end = min(offset + MAX_PAYLOAD_SIZE, len(data))
            self._write_packet(data[offset:end])
            offset = end

    def _write_packet(self, payload: bytes) -> None:
        """Send one packet with congestion window control."""
        # Wait for window to open.
        while True:
            with self._send_lock:
                if self._closed:
                    raise ConnectionError("connection closed")
                if len(self._pending) < self._cwnd:
                    break
            self._window_open.clear()
            self._window_open.wait(timeout=1.0)

        with self._send_lock:
            seq = self._send_seq
            self._send_seq += 1

            with self._recv_lock:
                ack_num = self._recv_seq

            raw = encode_packet(PACKET_TYPE_DATA, seq, ack_num, payload)
            self._sock.sendto(raw, self._addr)
            self._pending[seq] = _PendingPacket(raw)

    def read(self, max_size: int = 65536) -> bytes:
        """Read the next in-order payload. Blocks until data is available."""
        while True:
            if self._closed:
                raise ConnectionError("connection closed")
            if self._read_queue:
                return self._read_queue.popleft()
            self._read_event.clear()
            self._read_event.wait(timeout=1.0)

    def read_exactly(self, n: int) -> bytes:
        """Read exactly n bytes, buffering partial reads."""
        buf = bytearray()
        while len(buf) < n:
            chunk = self.read(n - len(buf))
            buf.extend(chunk)
        return bytes(buf)

    def sendall(self, data: bytes) -> None:
        """Alias for write() — compatibility with socket interface."""
        self.write(data)

    def recv(self, bufsize: int) -> bytes:
        """Alias for read() — compatibility with socket interface."""
        return self.read(bufsize)

    def close(self) -> None:
        """Close the connection."""
        self._closed = True
        self._window_open.set()
        self._read_event.set()
        with self._ack_lock:
            if self._ack_timer:
                self._ack_timer.cancel()

    # --- Private methods ---

    def _recv_loop(self) -> None:
        """Background thread: receive and dispatch incoming packets."""
        while not self._closed:
            try:
                self._sock.settimeout(0.5)
                data, _ = self._sock.recvfrom(65536)
            except socket.timeout:
                continue
            except OSError:
                break

            try:
                pkt_type, seq_num, ack_num, payload = decode_packet(data)
            except ValueError:
                continue

            if pkt_type == PACKET_TYPE_ACK:
                self._process_ack(ack_num)
            elif pkt_type in (PACKET_TYPE_DATA, PACKET_TYPE_SYN, PACKET_TYPE_FIN):
                self._process_data(seq_num, payload)

    def _process_ack(self, ack_num: int) -> None:
        """Handle incoming ACK — release pending packets, grow window."""
        with self._send_lock:
            cleared = 0
            for seq in list(self._pending.keys()):
                if seq < ack_num:
                    del self._pending[seq]
                    cleared += 1
                    # Simple window growth (client doesn't need BBR).
                    if self._cwnd < self._ssthresh:
                        self._cwnd += 1
                    elif self._cwnd < MAX_WINDOW_SIZE:
                        self._cwnd += 1
        if cleared > 0:
            self._window_open.set()

    def _process_data(self, seq_num: int, payload: bytes) -> None:
        """Handle incoming data — buffer, deliver in order, schedule ACK."""
        with self._recv_lock:
            if seq_num == self._recv_seq:
                if payload:
                    self._read_queue.append(payload)
                    self._read_event.set()
                self._recv_seq += 1
                # Drain consecutive buffered packets.
                while self._recv_seq in self._recv_buf:
                    buf_payload = self._recv_buf.pop(self._recv_seq)
                    if buf_payload:
                        self._read_queue.append(buf_payload)
                        self._read_event.set()
                    self._recv_seq += 1
            elif seq_num > self._recv_seq:
                self._recv_buf[seq_num] = payload
            # Duplicate (seq < recv_seq): silently discard.

        # Schedule delayed ACK.
        with self._ack_lock:
            self._ack_pending = True
            if self._ack_timer is None:
                self._ack_timer = threading.Timer(ACK_DELAY, self._flush_ack)
                self._ack_timer.daemon = True
                self._ack_timer.start()

    def _flush_ack(self) -> None:
        """Send a cumulative ACK."""
        with self._ack_lock:
            self._ack_pending = False
            self._ack_timer = None

        with self._recv_lock:
            ack_num = self._recv_seq

        raw = encode_packet(PACKET_TYPE_ACK, 0, ack_num)
        try:
            self._sock.sendto(raw, self._addr)
        except OSError:
            pass

    def _retransmit_loop(self) -> None:
        """Background thread: retransmit timed-out packets."""
        tick = RETRANSMIT_TIMEOUT / 4
        while not self._closed:
            time.sleep(tick)
            self._do_retransmit()

    def _do_retransmit(self) -> None:
        """Retransmit expired packets, apply multiplicative decrease."""
        now = time.monotonic()
        dropped = 0
        with self._send_lock:
            for seq in list(self._pending.keys()):
                pp = self._pending[seq]
                if now - pp.sent_at < RETRANSMIT_TIMEOUT:
                    continue
                if pp.retransmits >= MAX_RETRANSMITS:
                    del self._pending[seq]
                    dropped += 1
                    continue
                try:
                    self._sock.sendto(pp.raw, self._addr)
                except OSError:
                    pass
                pp.sent_at = now
                pp.retransmits += 1
                # Multiplicative decrease (simple Reno for client side).
                self._ssthresh = max(self._cwnd // 2, 2)
                self._cwnd = self._ssthresh
        if dropped > 0:
            self._window_open.set()

    # --- Socket-like interface for compatibility ---

    @property
    def fileno_unavailable(self):
        """ReliableUDP doesn't expose a fileno (it's not a raw socket)."""
        return True

    def getpeername(self):
        return self._addr

    def getsockname(self):
        return self._sock.getsockname()

    def settimeout(self, timeout):
        pass  # timeouts handled internally

    def setsockopt(self, *args):
        pass  # no-op for compatibility


def connect_udp(host: str, port: int, timeout: float = 30.0) -> ReliableUDP:
    """
    Create a ReliableUDP connection to the server.

    Returns a ReliableUDP object that can be used in place of a TCP socket
    with ObfsConn → NoiseConn → ClientMux.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    addr = (host, port)

    # Send a trigger packet so the server's listener detects this client.
    trigger = encode_packet(PACKET_TYPE_DATA, 0, 0, b"init")
    sock.sendto(trigger, addr)

    conn = ReliableUDP(sock, addr)

    # Wait briefly for the server to register the connection and ACK.
    time.sleep(0.05)

    return conn
