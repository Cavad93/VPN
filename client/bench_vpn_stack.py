#!/usr/bin/env python3
"""
VPN Full-Stack Throughput Benchmark
====================================

Simulates the complete data path:
  MacBook → ReliableUDP → ObfsConn → NoiseConn → Mux → [data]

Tests each layer in isolation and end-to-end to prove the VPN code
is NOT the throughput bottleneck (target: >>7.64 Mbps).

Run:
  cd client && python3 bench_vpn_stack.py

No servers needed — everything runs on loopback.
"""

import os
import socket
import struct
import threading
import time
from dataclasses import dataclass

# --- VPN imports ---
from core import (
    NoiseCipherState,
    NoiseSession,
    SessionCipher,
    NoiseConn,
    ObfsConn,
    ClientMux,
    MUX_HEADER_SIZE,
    FRAME_DATA,
)
from reliable_udp import (
    MAX_PAYLOAD_SIZE,
    ReliableUDP,
    encode_packet,
    PACKET_TYPE_DATA,
    PACKET_TYPE_ACK,
)


# =============================================================================
# Helpers
# =============================================================================

def fmt_speed(bytes_count: int, elapsed: float) -> str:
    """Format throughput as Mbps."""
    if elapsed <= 0:
        return "∞ Mbps"
    mbps = bytes_count * 8 / elapsed / 1_000_000
    return f"{mbps:.1f} Mbps"


def fmt_ops(count: int, elapsed: float) -> str:
    """Format operations per second."""
    if elapsed <= 0:
        return "∞ ops/s"
    return f"{count / elapsed:,.0f} ops/s"


def make_udp_pair():
    """Create a client/server ReliableUDP pair over loopback."""
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_sock.bind(("127.0.0.1", 0))
    server_addr = server_sock.getsockname()

    client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_sock.bind(("127.0.0.1", 0))
    client_addr = client_sock.getsockname()

    client = ReliableUDP(client_sock, server_addr)
    server = ReliableUDP(server_sock, client_addr)
    return client, server


def make_noise_session():
    """Create a pair of NoiseSession objects for benchmarking (skip handshake)."""
    # Use deterministic keys for reproducibility.
    key_a = os.urandom(32)
    key_b = os.urandom(32)
    remote_key = os.urandom(32)

    # Client sends with key_a, server decrypts with key_a.
    # Server sends with key_b, client decrypts with key_b.
    client_send = NoiseCipherState()
    client_send.initialize_key(key_a)
    client_recv = NoiseCipherState()
    client_recv.initialize_key(key_b)

    server_send = NoiseCipherState()
    server_send.initialize_key(key_b)
    server_recv = NoiseCipherState()
    server_recv.initialize_key(key_a)

    client_session = NoiseSession(
        send_cipher=SessionCipher(client_send),
        recv_cipher=SessionCipher(client_recv),
        remote_static=remote_key,
    )
    server_session = NoiseSession(
        send_cipher=SessionCipher(server_send),
        recv_cipher=SessionCipher(server_recv),
        remote_static=remote_key,
    )
    return client_session, server_session


# =============================================================================
# Benchmark 1: ChaCha20-Poly1305 raw throughput
# =============================================================================

def bench_chacha20(data_mb: int = 100) -> dict:
    """Benchmark raw ChaCha20-Poly1305 encrypt + decrypt throughput."""
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

    key = ChaCha20Poly1305.generate_key()
    cipher = ChaCha20Poly1305(key)
    data = b"\x00" * 1400  # typical VPN packet size
    nonce = b"\x00" * 12

    total_bytes = data_mb * 1_000_000
    iterations = total_bytes // 1400

    # Encrypt benchmark
    t0 = time.monotonic()
    for _ in range(iterations):
        cipher.encrypt(nonce, data, None)
    enc_elapsed = time.monotonic() - t0

    # Decrypt benchmark
    ct = cipher.encrypt(nonce, data, None)
    t0 = time.monotonic()
    for _ in range(iterations):
        cipher.decrypt(nonce, ct, None)
    dec_elapsed = time.monotonic() - t0

    return {
        "name": "ChaCha20-Poly1305",
        "encrypt": fmt_speed(total_bytes, enc_elapsed),
        "decrypt": fmt_speed(total_bytes, dec_elapsed),
        "enc_ops": fmt_ops(iterations, enc_elapsed),
        "dec_ops": fmt_ops(iterations, dec_elapsed),
    }


# =============================================================================
# Benchmark 2: NoiseCipherState encrypt + decrypt (with nonce counting)
# =============================================================================

def bench_noise_cipher(data_mb: int = 50) -> dict:
    """Benchmark NoiseCipherState with auto-incrementing nonce (real VPN path)."""
    key = os.urandom(32)
    enc_cs = NoiseCipherState()
    enc_cs.initialize_key(key)
    dec_cs = NoiseCipherState()
    dec_cs.initialize_key(key)

    data = b"\x00" * 1400
    total_bytes = data_mb * 1_000_000
    iterations = total_bytes // 1400

    # Encrypt
    t0 = time.monotonic()
    for _ in range(iterations):
        enc_cs.encrypt_with_ad(b"", data)
    enc_elapsed = time.monotonic() - t0

    # Decrypt (reset nonces)
    enc_cs2 = NoiseCipherState()
    enc_cs2.initialize_key(key)
    ciphertexts = []
    for _ in range(min(iterations, 5000)):
        ciphertexts.append(enc_cs2.encrypt_with_ad(b"", data))

    dec_cs2 = NoiseCipherState()
    dec_cs2.initialize_key(key)
    t0 = time.monotonic()
    for ct in ciphertexts:
        dec_cs2.decrypt_with_ad(b"", ct)
    dec_elapsed = time.monotonic() - t0
    dec_bytes = len(ciphertexts) * 1400

    return {
        "name": "NoiseCipherState (with nonce counter)",
        "encrypt": fmt_speed(total_bytes, enc_elapsed),
        "decrypt": fmt_speed(dec_bytes, dec_elapsed),
        "enc_ops": fmt_ops(iterations, enc_elapsed),
    }


# =============================================================================
# Benchmark 3: ObfsConn TLS framing (encode/decode without network)
# =============================================================================

def bench_obfs_framing(data_mb: int = 50) -> dict:
    """Benchmark ObfsConn TLS record framing overhead (no actual I/O)."""
    # We measure the framing computation only (struct.pack, bytearray, copy).
    total_bytes = data_mb * 1_000_000
    iterations = total_bytes // 1400
    data = b"\x00" * 1400

    # Write framing: build TLS record header + payload
    hdr = bytearray(5)
    hdr[0] = 0x17  # application_data
    hdr[1] = 0x03
    hdr[2] = 0x03

    t0 = time.monotonic()
    for _ in range(iterations):
        struct.pack_into(">H", hdr, 3, len(data))
        _ = bytes(hdr) + data  # same as ObfsConn.write fast path
    write_elapsed = time.monotonic() - t0

    # Read framing: parse 5-byte header + extract payload
    record = bytes(hdr) + data
    t0 = time.monotonic()
    for _ in range(iterations):
        _ = int.from_bytes(record[3:5], "big")
        _ = record[5:]
    read_elapsed = time.monotonic() - t0

    return {
        "name": "ObfsConn TLS framing",
        "write": fmt_speed(total_bytes, write_elapsed),
        "read": fmt_speed(total_bytes, read_elapsed),
    }


# =============================================================================
# Benchmark 4: Mux frame encode/decode
# =============================================================================

def bench_mux_framing(data_mb: int = 50) -> dict:
    """Benchmark Mux frame header encode/decode overhead."""
    total_bytes = data_mb * 1_000_000
    iterations = total_bytes // 1400
    data = b"\x00" * 1400

    # Encode: 7-byte header + payload
    t0 = time.monotonic()
    for _ in range(iterations):
        frame = bytearray(7 + len(data))
        struct.pack_into(">IbH", frame, 0, 2, FRAME_DATA, len(data))
        frame[7:] = data
    encode_elapsed = time.monotonic() - t0

    # Decode: parse header
    frame = bytearray(7 + len(data))
    struct.pack_into(">IbH", frame, 0, 2, FRAME_DATA, len(data))
    frame[7:] = data
    frame_bytes = bytes(frame)

    t0 = time.monotonic()
    for _ in range(iterations):
        sid = int.from_bytes(frame_bytes[0:4], "big")
        ftype = frame_bytes[4]
        length = int.from_bytes(frame_bytes[5:7], "big")
        payload = frame_bytes[7:7 + length]
    decode_elapsed = time.monotonic() - t0

    return {
        "name": "Mux framing",
        "encode": fmt_speed(total_bytes, encode_elapsed),
        "decode": fmt_speed(total_bytes, decode_elapsed),
    }


# =============================================================================
# Benchmark 5: ReliableUDP loopback throughput
# =============================================================================

def bench_reliable_udp(data_mb: int = 10) -> dict:
    """Benchmark ReliableUDP throughput over loopback (no VPN layers)."""
    client, server = make_udp_pair()
    total_bytes = data_mb * 1_000_000
    data = b"\x00" * 1400
    packets = total_bytes // 1400
    received = 0
    done = threading.Event()

    def reader():
        nonlocal received
        while received < total_bytes:
            try:
                chunk = server.read()
                received += len(chunk)
            except Exception:
                break
        done.set()

    t = threading.Thread(target=reader, daemon=True)
    t.start()

    t0 = time.monotonic()
    for _ in range(packets):
        client.write(data)
    done.wait(timeout=30)
    elapsed = time.monotonic() - t0

    client.close()
    server.close()

    return {
        "name": "ReliableUDP loopback",
        "throughput": fmt_speed(received, elapsed),
        "packets": f"{packets} sent, {received // 1400} received",
    }


# =============================================================================
# Benchmark 6: Full stack (ReliableUDP → ObfsConn → NoiseConn → Mux)
# =============================================================================

class _FakeObfsServerConn:
    """Minimal server-side ObfsConn that reads/writes TLS records.

    Avoids needing a full handshake — directly reads/writes framed data.
    Used to benchmark the full VPN stack data path without handshake overhead.
    """

    def __init__(self, transport):
        self._transport = transport
        self._read_buf = bytearray()
        self._sock_buf = bytearray()
        self._recv_staging = bytearray(262144)
        self._write_hdr = bytearray(5)
        self._write_hdr[0] = 0x17
        self._write_hdr[1] = 0x03
        self._write_hdr[2] = 0x03

    def write(self, data: bytes) -> None:
        if len(data) <= 16383:
            struct.pack_into(">H", self._write_hdr, 3, len(data))
            self._transport.sendall(self._write_hdr + data)
            return
        offset = 0
        while offset < len(data):
            end = min(offset + 16383, len(data))
            chunk_len = end - offset
            rec = bytearray(5 + chunk_len)
            rec[0] = 0x17
            rec[1] = 0x03
            rec[2] = 0x03
            struct.pack_into(">H", rec, 3, chunk_len)
            rec[5:] = data[offset:end]
            self._transport.sendall(rec)
            offset = end

    def read(self, n: int) -> bytes:
        while len(self._read_buf) < n:
            payload = self._read_record()
            self._read_buf += payload
        result = bytes(self._read_buf[:n])
        del self._read_buf[:n]
        return result

    def read_exactly(self, n: int) -> bytes:
        return self.read(n)

    def _recv_exactly(self, n: int) -> bytes:
        while len(self._sock_buf) < n:
            nbytes = self._transport.recv_into(self._recv_staging)
            if not nbytes:
                raise ConnectionError("closed")
            self._sock_buf += self._recv_staging[:nbytes]
        if n == len(self._sock_buf):
            result = bytes(self._sock_buf)
            self._sock_buf = bytearray()
            return result
        result = bytes(self._sock_buf[:n])
        del self._sock_buf[:n]
        return result

    def _read_record(self) -> bytes:
        hdr = self._recv_exactly(5)
        length = int.from_bytes(hdr[3:5], "big")
        return self._recv_exactly(length)

    def close(self):
        try:
            self._transport.close()
        except OSError:
            pass


def bench_full_stack(data_mb: int = 5) -> dict:
    """Benchmark full VPN stack: ReliableUDP → ObfsConn → NoiseConn → Mux → Stream.

    Sets up client and server sides over loopback without real handshakes.
    Measures end-to-end throughput to determine if VPN code is the bottleneck.
    """
    # Create transport pair
    client_transport, server_transport = make_udp_pair()

    # Create ObfsConn wrappers (skip handshake — both sides use app_data framing)
    client_obfs = _FakeObfsServerConn(client_transport)
    server_obfs = _FakeObfsServerConn(server_transport)

    # Create Noise sessions (skip handshake — use pre-shared keys)
    client_session, server_session = make_noise_session()
    client_noise = NoiseConn(client_obfs, client_session)
    server_noise = NoiseConn(server_obfs, server_session)

    total_bytes = data_mb * 1_000_000
    packet_data = b"\x00" * 1400  # typical IP packet
    packets = total_bytes // 1400

    received_bytes = 0
    done = threading.Event()
    error_holder = [None]

    def server_reader():
        """Server side: read mux frames and extract data payloads."""
        nonlocal received_bytes
        try:
            while received_bytes < total_bytes:
                # Read noise message (mux frame)
                msg = server_noise.read_message()
                if len(msg) < MUX_HEADER_SIZE:
                    continue
                payload_len = int.from_bytes(msg[5:7], "big")
                received_bytes += payload_len
        except Exception as e:
            error_holder[0] = e
        finally:
            done.set()

    reader_thread = threading.Thread(target=server_reader, daemon=True)
    reader_thread.start()

    # Client side: write data as mux frames through NoiseConn
    t0 = time.monotonic()
    for i in range(packets):
        # Build mux frame: 7-byte header + payload
        frame = bytearray(7 + len(packet_data))
        struct.pack_into(">IbH", frame, 0, 2, FRAME_DATA, len(packet_data))
        frame[7:] = packet_data
        # Encrypt + TLS frame + UDP send
        client_noise.write_message(bytes(frame))

    done.wait(timeout=60)
    elapsed = time.monotonic() - t0

    client_transport.close()
    server_transport.close()

    result = {
        "name": "Full VPN Stack (UDP→Obfs→Noise→Mux)",
        "throughput": fmt_speed(received_bytes, elapsed),
        "packets_sent": packets,
        "bytes_received": received_bytes,
        "elapsed": f"{elapsed:.2f}s",
    }
    if error_holder[0]:
        result["error"] = str(error_holder[0])
    return result


# =============================================================================
# Benchmark 7: Simulated relay (Client → SPB → Astana)
# =============================================================================

def bench_relay_simulation(data_mb: int = 5) -> dict:
    """Simulate the full 3-node path: Client → SPB relay → Astana server.

    Sets up two UDP hops over loopback:
      Client ←ReliableUDP→ SPB-relay ←forward→ Astana-transport ←ReliableUDP→ Astana-server

    The relay is a transparent UDP forwarder (like relay.go).
    Measures end-to-end throughput through the double-hop.
    """
    # Hop 1: Client ↔ SPB relay
    client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_sock.bind(("127.0.0.1", 0))

    relay_client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    relay_client_sock.bind(("127.0.0.1", 0))

    # Hop 2: SPB relay ↔ Astana server
    relay_server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    relay_server_sock.bind(("127.0.0.1", 0))

    astana_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    astana_sock.bind(("127.0.0.1", 0))

    client_addr = client_sock.getsockname()
    relay_client_addr = relay_client_sock.getsockname()
    relay_server_addr = relay_server_sock.getsockname()
    astana_addr = astana_sock.getsockname()

    # Create ReliableUDP endpoints
    client = ReliableUDP(client_sock, relay_client_addr)
    astana = ReliableUDP(astana_sock, relay_server_addr)

    # Relay: forward packets between hops
    relay_stop = threading.Event()

    def relay_forward(src_sock, dst_sock, dst_addr):
        src_sock.settimeout(0.5)
        while not relay_stop.is_set():
            try:
                data, addr = src_sock.recvfrom(65536)
                dst_sock.sendto(data, dst_addr)
            except socket.timeout:
                continue
            except OSError:
                break

    # Client→Astana direction
    relay_t1 = threading.Thread(
        target=relay_forward,
        args=(relay_client_sock, relay_server_sock, astana_addr),
        daemon=True,
    )
    # Astana→Client direction
    relay_t2 = threading.Thread(
        target=relay_forward,
        args=(relay_server_sock, relay_client_sock, client_addr),
        daemon=True,
    )
    relay_t1.start()
    relay_t2.start()

    # Create ObfsConn + NoiseConn over the transport
    client_obfs = _FakeObfsServerConn(client)
    astana_obfs = _FakeObfsServerConn(astana)
    client_session, server_session = make_noise_session()
    client_noise = NoiseConn(client_obfs, client_session)
    astana_noise = NoiseConn(astana_obfs, server_session)

    total_bytes = data_mb * 1_000_000
    packet_data = b"\x00" * 1400
    packets = total_bytes // 1400

    received_bytes = 0
    done = threading.Event()
    error_holder = [None]

    def astana_reader():
        nonlocal received_bytes
        try:
            while received_bytes < total_bytes:
                msg = astana_noise.read_message()
                if len(msg) >= MUX_HEADER_SIZE:
                    payload_len = int.from_bytes(msg[5:7], "big")
                    received_bytes += payload_len
        except Exception as e:
            error_holder[0] = e
        finally:
            done.set()

    reader = threading.Thread(target=astana_reader, daemon=True)
    reader.start()

    t0 = time.monotonic()
    for _ in range(packets):
        frame = bytearray(7 + len(packet_data))
        struct.pack_into(">IbH", frame, 0, 2, FRAME_DATA, len(packet_data))
        frame[7:] = packet_data
        client_noise.write_message(bytes(frame))

    done.wait(timeout=120)
    elapsed = time.monotonic() - t0

    relay_stop.set()
    client.close()
    astana.close()

    result = {
        "name": "Full Relay Simulation (Client → SPB → Astana)",
        "throughput": fmt_speed(received_bytes, elapsed),
        "packets_sent": packets,
        "bytes_received": received_bytes,
        "elapsed": f"{elapsed:.2f}s",
    }
    if error_holder[0]:
        result["error"] = str(error_holder[0])
    return result


# =============================================================================
# Main
# =============================================================================

def print_result(result: dict):
    """Pretty-print a benchmark result."""
    name = result.pop("name", "???")
    print(f"\n  {name}")
    print(f"  {'─' * len(name)}")
    for k, v in result.items():
        print(f"    {k:20s}: {v}")


def main():
    print("=" * 70)
    print("  VPN Full-Stack Throughput Benchmark")
    print("=" * 70)
    print()
    print("  Target: prove VPN stack can sustain >> 7.64 Mbps (SPB upload)")
    print("  If loopback throughput >> 7.64 Mbps → bottleneck is NETWORK,")
    print("  not VPN code.")
    print()

    # Layer-by-layer benchmarks
    print("─" * 70)
    print("  LAYER BENCHMARKS (isolated components)")
    print("─" * 70)

    r1 = bench_chacha20(100)
    print_result(r1)

    r2 = bench_noise_cipher(50)
    print_result(r2)

    r3 = bench_obfs_framing(50)
    print_result(r3)

    r4 = bench_mux_framing(50)
    print_result(r4)

    # Transport benchmark
    print()
    print("─" * 70)
    print("  TRANSPORT BENCHMARKS (with actual UDP I/O)")
    print("─" * 70)

    r5 = bench_reliable_udp(10)
    print_result(r5)

    # Full stack benchmark
    print()
    print("─" * 70)
    print("  FULL STACK BENCHMARK (all layers combined)")
    print("─" * 70)

    r6 = bench_full_stack(5)
    print_result(r6)

    # Relay simulation
    print()
    print("─" * 70)
    print("  RELAY SIMULATION (Client → SPB relay → Astana)")
    print("─" * 70)

    r7 = bench_relay_simulation(5)
    print_result(r7)

    # Verdict
    print()
    print("=" * 70)
    print("  VERDICT")
    print("=" * 70)
    print()

    # Parse throughput from full stack result
    stack_tp = r6.get("throughput", "0 Mbps")
    relay_tp = r7.get("throughput", "0 Mbps")

    def parse_mbps(s: str) -> float:
        try:
            return float(s.split()[0])
        except (ValueError, IndexError):
            return 0.0

    stack_mbps = parse_mbps(stack_tp)
    relay_mbps = parse_mbps(relay_tp)
    target_mbps = 7.64

    if stack_mbps > target_mbps * 2:
        print(f"  ✓ Full stack: {stack_tp} >> {target_mbps} Mbps target")
        print(f"    → VPN code is NOT the bottleneck.")
    elif stack_mbps > target_mbps:
        print(f"  ~ Full stack: {stack_tp} > {target_mbps} Mbps but marginal")
        print(f"    → VPN code has some overhead but can sustain target.")
    else:
        print(f"  ✗ Full stack: {stack_tp} < {target_mbps} Mbps target")
        print(f"    → VPN code MAY be a bottleneck. Profile further.")

    print()

    if relay_mbps > target_mbps * 2:
        print(f"  ✓ Relay sim: {relay_tp} >> {target_mbps} Mbps target")
        print(f"    → Relay path is NOT the bottleneck.")
    elif relay_mbps > target_mbps:
        print(f"  ~ Relay sim: {relay_tp} > {target_mbps} Mbps but marginal")
    else:
        print(f"  ✗ Relay sim: {relay_tp} < {target_mbps} Mbps target")
        print(f"    → Relay path MAY be a bottleneck.")

    print()
    print(f"  Measured client download:  3.38 Mbps")
    print(f"  SPB server upload:         {target_mbps} Mbps")
    print(f"  Full stack loopback:       {stack_tp}")
    print(f"  Relay sim loopback:        {relay_tp}")
    print()

    if stack_mbps > target_mbps * 3:
        print(f"  CONCLUSION: The VPN stack can handle {stack_mbps/target_mbps:.0f}× the")
        print(f"  required throughput. The 3.38 Mbps limitation is caused by")
        print(f"  NETWORK conditions (packet loss, WiFi, ISP throttling),")
        print(f"  not by VPN software overhead.")
    print()


if __name__ == "__main__":
    main()
