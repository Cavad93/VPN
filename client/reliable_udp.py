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
# MAX_PAYLOAD_SIZE is the max bytes carried in one UDP packet's payload field.
# The complete on-wire size is: HEADER(11) + payload, which must fit in one
# IP datagram without IP-level fragmentation (path MTU ≈ 1500 bytes including
# IP+UDP headers of ~28 bytes → effective MTU for UDP payload = 1472 bytes).
#
#   Ethernet MTU        : 1500 bytes
#   outer IP header     :  -20 bytes
#   outer UDP header    :   -8 bytes
#   reliable UDP header :  -11 bytes  (HEADER_SIZE)
#   ────────────────────────────────
#   Max UDP payload     : 1461 bytes  → round down to 1460 for alignment
#
# The VPN adds protocol overhead PER IP PACKET on top of the UDP payload:
#   ObfsConn TLS record header :  5 bytes
#   Noise length prefix        :  2 bytes
#   ChaCha20-Poly1305 AEAD tag : 16 bytes
#   Mux frame header           :  7 bytes
#   ─────────────────────────────────────
#   Total inner overhead       : 30 bytes
#
# Max inner IP packet = MAX_PAYLOAD_SIZE − 30 = 1460 − 30 = 1430 bytes.
# tun_macos.py sets DEFAULT_MTU = 1430, ensuring that every inner IP packet
# produces EXACTLY ONE UDP datagram — matching the Go server's MaxPayloadSize
# (transport/udp.go) and halving the UDP packet count vs a 1350-byte payload
# (which split every 1430-byte inner-IP+overhead into two datagrams, effectively
# halving cwnd utilisation and upload throughput).
#
# Wire check: HEADER(11) + MAX_PAYLOAD_SIZE(1460) = 1471 ≤ 1472 max UDP payload. ✓
MAX_PAYLOAD_SIZE = 1460
MAX_WINDOW_SIZE = 512    # was 64 — old cap hit at ~5 Mbps @ 136ms RTT
INITIAL_RTO = 0.5        # initial RTO; replaced by adaptive RTT-based RTO (RFC 6298)
MAX_RETRANSMITS = 10


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
        # Set recv timeout ONCE here instead of on every _recv_loop iteration.
        # Calling settimeout() in the loop triggers fcntl(F_GETFL) per packet
        # (~1364 syscalls/s at 7 Mbps) even though the value never changes.
        self._sock.settimeout(0.5)

        # Send state.
        self._send_lock = threading.Lock()
        self._send_seq = 0
        self._pending: dict[int, _PendingPacket] = {}
        self._cwnd = 4
        self._ssthresh = 32
        self._cwnd_remainder: float = 0.0   # fractional accumulator for CA phase
        self._window_open = threading.Event()
        self._window_open.set()

        # RTT estimation (RFC 6298).
        self._srtt: Optional[float] = None
        self._rttvar: float = 0.0
        self._rto: float = INITIAL_RTO

        # Receive state.
        self._recv_lock = threading.Lock()
        self._recv_seq = 0
        self._recv_buf: dict[int, bytes] = {}  # out-of-order buffer
        self._read_queue: deque[bytes] = deque()
        self._read_event = threading.Event()

        # ACK lock — protects sendto from concurrent callers.
        self._ack_lock = threading.Lock()

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

    # --- Private methods ---

    def _recv_loop(self) -> None:
        """Background thread: receive and dispatch incoming packets."""
        while not self._closed:
            try:
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

    def _update_rto(self, rtt: float) -> None:
        """Update RTO using RFC 6298 algorithm (SRTT + 4×RTTVAR)."""
        if self._srtt is None:
            self._srtt = rtt
            self._rttvar = rtt / 2
        else:
            self._rttvar = 0.75 * self._rttvar + 0.25 * abs(self._srtt - rtt)
            self._srtt = 0.875 * self._srtt + 0.125 * rtt
        self._rto = max(0.2, self._srtt + 4 * self._rttvar)

    def _process_ack(self, ack_num: int) -> None:
        """Handle incoming ACK — release pending packets, grow window, update RTT."""
        now = time.monotonic()
        with self._send_lock:
            cleared = 0
            for seq in list(self._pending.keys()):
                if seq < ack_num:
                    pp = self._pending.pop(seq)
                    cleared += 1
                    # RTT sample only from un-retransmitted packets (Karn's algorithm).
                    if pp.retransmits == 0:
                        self._update_rto(now - pp.sent_at)
                    # Congestion window growth.
                    if self._cwnd < self._ssthresh:
                        # Slow start: +1 per ACK.
                        self._cwnd = min(self._cwnd + 1, MAX_WINDOW_SIZE)
                    elif self._cwnd < MAX_WINDOW_SIZE:
                        # Congestion avoidance (Reno): +1/cwnd per ACK → +1 per RTT.
                        self._cwnd_remainder += 1.0 / self._cwnd
                        if self._cwnd_remainder >= 1.0:
                            self._cwnd += 1
                            self._cwnd_remainder -= 1.0
        if cleared > 0:
            self._window_open.set()

    def _process_data(self, seq_num: int, payload: bytes) -> None:
        """Handle incoming data — buffer, deliver in order, send immediate ACK."""
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

        # Send ACK immediately — no threading.Timer avoids GIL-induced 50-100ms
        # jitter that triggers BBR's "near-zero delivery rate → cwnd collapse" spiral.
        self._flush_ack()

    def _flush_ack(self) -> None:
        """Send a cumulative ACK immediately."""
        with self._recv_lock:
            ack_num = self._recv_seq

        raw = encode_packet(PACKET_TYPE_ACK, 0, ack_num)
        with self._ack_lock:
            try:
                self._sock.sendto(raw, self._addr)
            except OSError:
                pass

    def _retransmit_loop(self) -> None:
        """Background thread: retransmit timed-out packets."""
        while not self._closed:
            time.sleep(max(0.05, self._rto / 4))
            self._do_retransmit()

    def _do_retransmit(self) -> None:
        """Retransmit expired packets, apply multiplicative decrease.

        RFC 6298 §5.4 / Reno: multiplicative decrease and RTO doubling must be
        applied AT MOST ONCE per retransmit event (i.e. per call), not once per
        retransmitted packet.  Applying it per-packet causes cwnd to collapse
        from N to N/2^k for k simultaneous timeouts — even a single burst of 4
        timed-out packets drives cwnd from 32 → 2, stalling the connection for
        seconds.  The fix: track whether MD has already been applied this round
        and skip it for subsequent packets in the same call.
        """
        now = time.monotonic()
        dropped = 0
        did_reduce = False   # MD/RTO-backoff applied at most once per event
        with self._send_lock:
            for seq in list(self._pending.keys()):
                pp = self._pending[seq]
                if now - pp.sent_at < self._rto:
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
                if not did_reduce:
                    # Multiplicative decrease (Reno) — once per retransmit event.
                    self._ssthresh = max(self._cwnd // 2, 2)
                    self._cwnd = self._ssthresh
                    self._cwnd_remainder = 0.0
                    # Exponential backoff on RTO (cap at 60s).
                    self._rto = min(self._rto * 2, 60.0)
                    did_reduce = True
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

    def recv_into(self, buffer) -> int:
        """Fill *buffer* with the next available reassembled payload.

        Implements the socket.recv_into() interface so that ObfsConn (which
        calls recv_into on whatever transport it wraps) works over UDP.

        ReliableUDP delivers one reassembled packet at a time (up to
        MAX_PAYLOAD_SIZE=1400 bytes).  The staging buffer that ObfsConn passes
        is 262 144 bytes — we only use as many bytes as the payload needs.
        The ObfsConn._recv_exactly loop accumulates chunks in its sock_buf, so
        partial fills are perfectly fine.
        """
        data = self.read()
        n = min(len(data), len(buffer))
        buffer[:n] = data[:n]
        return n


def connect_udp(host: str, port: int, timeout: float = 30.0) -> ReliableUDP:
    """
    Create a ReliableUDP connection to the server.

    Returns a ReliableUDP object that can be used in place of a TCP socket
    with ObfsConn → NoiseConn → ClientMux.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    # Match the server's udpSocketBufSize (transport/udp.go: 4 MB).
    # Default UDP socket buffers are very small on macOS (~42 KB recv) and
    # Linux (~212 KB recv, capped by net.core.rmem_max).  At 7.64 Mbps
    # download, the receive buffer fills in ~44 ms on macOS.  When it
    # overflows, the kernel silently drops incoming packets.  Each drop
    # triggers a Reno multiplicative-decrease (cwnd → ssthresh = cwnd/2),
    # causing a throughput collapse cascade that limits download to 3-4 Mbps
    # despite the server having 7+ Mbps available.  4 MB matches the server
    # and gives ≈4 s of headroom at 7.64 Mbps — enough for any GIL pause.
    _UDP_BUF = 4 * 1024 * 1024  # 4 MB — matches server udpSocketBufSize
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, _UDP_BUF)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, _UDP_BUF)
    except OSError:
        pass  # OS may cap at kern.ipc.maxsockbuf — silently accept the cap
    addr = (host, port)

    # Send a trigger packet so the server's listener detects this client.
    trigger = encode_packet(PACKET_TYPE_DATA, 0, 0, b"init")
    sock.sendto(trigger, addr)

    conn = ReliableUDP(sock, addr)

    # Wait briefly for the server to register the connection and ACK.
    time.sleep(0.05)

    return conn
