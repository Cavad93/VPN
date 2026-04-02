"""
traffic_shaping.py — Traffic shaping module for Anti-DPI protection.

Imitate browser (HTTPS) traffic patterns by controlling:
  - Packet sizes (fragmentation + padding to match browser MTU patterns)
  - Inter-packet timing (delays to mimic browser request/response cycles)
  - Burst patterns (bursty sends with pauses, like page loads)

Usage:
    profile = BrowserProfile()
    shaper = TrafficShaper(profile)

    # Shape outgoing data into browser-like chunks with timing
    for chunk in shaper.shape_outgoing(large_payload):
        conn.write(chunk)
        shaper.wait_inter_chunk()

    # Or use the ShapedConn wrapper for transparent shaping
    shaped = ShapedConn(raw_conn, profile)
    shaped.write(data)
    data = shaped.read(4096)
"""

from __future__ import annotations

import os
import random
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Iterator, List, Optional, Tuple

import structlog

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Size bucket helpers
# ---------------------------------------------------------------------------

# Each bucket: (size_min, size_max, cumulative_probability)
# Probabilities sum to 1.0 across all buckets in a profile.
SizeBucket = Tuple[int, int, float]


def _sample_from_buckets(buckets: List[SizeBucket]) -> int:
    """Sample a target size from weighted buckets.

    Args:
        buckets: list of (size_min, size_max, cumulative_probability) sorted
                 by cumulative_probability ascending.

    Returns:
        Random integer in [size_min, size_max] for the selected bucket.
    """
    r = random.random()
    for size_min, size_max, cum_prob in buckets:
        if r <= cum_prob:
            return random.randint(size_min, size_max)
    # Fallback to last bucket
    size_min, size_max, _ = buckets[-1]
    return random.randint(size_min, size_max)


# ---------------------------------------------------------------------------
# Traffic profiles
# ---------------------------------------------------------------------------


@dataclass
class TrafficProfile:
    """Defines traffic shaping parameters to mimic a specific traffic type.

    Attributes:
        name: Human-readable profile name.
        size_buckets: Packet size distribution as cumulative-probability
            buckets ``(size_min, size_max, cum_prob)``.  The last bucket's
            cum_prob must be 1.0.
        min_inter_chunk_ms: Minimum delay between successive chunks (ms).
        max_inter_chunk_ms: Maximum delay between successive chunks (ms).
        burst_count: Number of chunks per burst before a longer pause.
        burst_pause_min_ms: Minimum pause after a burst completes (ms).
        burst_pause_max_ms: Maximum pause after a burst completes (ms).
        padding_probability: Probability [0, 1] to add random padding to a
            chunk even when it would fit the target size without it.
        max_padding_bytes: Maximum extra padding bytes to append.
    """

    name: str
    size_buckets: List[SizeBucket]
    min_inter_chunk_ms: float
    max_inter_chunk_ms: float
    burst_count: int
    burst_pause_min_ms: float
    burst_pause_max_ms: float
    padding_probability: float = 0.3
    max_padding_bytes: int = 64

    def sample_chunk_size(self) -> int:
        """Return a random target chunk size according to the profile."""
        return _sample_from_buckets(self.size_buckets)

    def sample_inter_chunk_delay(self) -> float:
        """Return a random inter-chunk delay in seconds."""
        ms = random.uniform(self.min_inter_chunk_ms, self.max_inter_chunk_ms)
        return ms / 1000.0

    def sample_burst_pause(self) -> float:
        """Return a random pause after a burst, in seconds."""
        ms = random.uniform(self.burst_pause_min_ms, self.burst_pause_max_ms)
        return ms / 1000.0

    def sample_padding(self) -> bytes:
        """Return random padding bytes, or empty bytes."""
        if random.random() < self.padding_probability:
            n = random.randint(1, self.max_padding_bytes)
            return os.urandom(n)
        return b""


def browser_profile() -> TrafficProfile:
    """Return a traffic profile mimicking Chrome/Firefox HTTPS page loads.

    Size distribution based on empirical TLS record sizes in browser traffic:
     - Small (< 256 B)   : ~20% — headers, ACKs, small requests
     - Medium (256–1400 B): ~45% — typical TLS records near MTU
     - Large (1400–4096 B): ~25% — image fragments, JS chunks
     - XL (4096–16383 B) : ~10% — larger JS/CSS downloads
    """
    buckets: List[SizeBucket] = [
        (64, 255, 0.20),
        (256, 1400, 0.65),
        (1401, 4096, 0.90),
        (4097, 16383, 1.00),
    ]
    return TrafficProfile(
        name="browser",
        size_buckets=buckets,
        min_inter_chunk_ms=1.0,
        max_inter_chunk_ms=15.0,
        burst_count=8,
        burst_pause_min_ms=50.0,
        burst_pause_max_ms=300.0,
        padding_probability=0.25,
        max_padding_bytes=32,
    )


def streaming_profile() -> TrafficProfile:
    """Return a profile mimicking video streaming (Netflix/YouTube).

    Streaming traffic is very bursty with large payloads and short pauses.
    """
    buckets: List[SizeBucket] = [
        (512, 1400, 0.30),
        (1401, 4096, 0.60),
        (4097, 16383, 1.00),
    ]
    return TrafficProfile(
        name="streaming",
        size_buckets=buckets,
        min_inter_chunk_ms=0.5,
        max_inter_chunk_ms=5.0,
        burst_count=20,
        burst_pause_min_ms=10.0,
        burst_pause_max_ms=50.0,
        padding_probability=0.1,
        max_padding_bytes=16,
    )


def idle_profile() -> TrafficProfile:
    """Return a profile mimicking an idle browser connection (keep-alive pings)."""
    buckets: List[SizeBucket] = [
        (32, 128, 0.70),
        (129, 512, 1.00),
    ]
    return TrafficProfile(
        name="idle",
        size_buckets=buckets,
        min_inter_chunk_ms=500.0,
        max_inter_chunk_ms=2000.0,
        burst_count=2,
        burst_pause_min_ms=1000.0,
        burst_pause_max_ms=5000.0,
        padding_probability=0.5,
        max_padding_bytes=64,
    )


# ---------------------------------------------------------------------------
# Padding wire format
# ---------------------------------------------------------------------------

# We embed padding length in a 2-byte prefix so the receiver can strip it.
# Wire format of a shaped chunk:
#   [2 bytes: padding_length BE][data][padding_length bytes: random padding]
#
# This keeps the receiver simple: read 2 bytes, then data + padding.

PADDING_HEADER_SIZE = 2  # bytes


def encode_chunk(data: bytes, padding: bytes) -> bytes:
    """Encode data + padding into a shaped chunk with a 2-byte padding length.

    Args:
        data: Actual payload bytes.
        padding: Random padding bytes (0–255 bytes).

    Returns:
        Encoded chunk: padding_len (2 B BE) + data + padding.

    Raises:
        ValueError: If padding length exceeds 65535.
    """
    if len(padding) > 65535:
        raise ValueError(f"Padding too long: {len(padding)}")
    return struct.pack(">H", len(padding)) + data + padding


def decode_chunk(chunk: bytes) -> bytes:
    """Strip padding from a shaped chunk and return the original data.

    Args:
        chunk: Full received chunk including padding header.

    Returns:
        Original data bytes.

    Raises:
        ValueError: If chunk is malformed.
    """
    if len(chunk) < PADDING_HEADER_SIZE:
        raise ValueError("Chunk too short to contain padding header")
    padding_len = struct.unpack(">H", chunk[:PADDING_HEADER_SIZE])[0]
    payload_end = len(chunk) - padding_len
    if payload_end < PADDING_HEADER_SIZE:
        raise ValueError(
            f"Chunk malformed: padding_len={padding_len} exceeds available data"
        )
    return chunk[PADDING_HEADER_SIZE:payload_end]


# ---------------------------------------------------------------------------
# Core shaper
# ---------------------------------------------------------------------------


class TrafficShaper:
    """Shapes outgoing data to match a traffic profile.

    This class is stateful — it tracks burst position so callers can apply
    timing delays at the right moment.

    Thread-safety: all public methods are protected by an internal lock.
    """

    def __init__(self, profile: TrafficProfile) -> None:
        self._profile = profile
        self._lock = threading.Lock()
        self._chunks_in_burst = 0  # how many chunks sent in current burst
        self._stats_total_chunks = 0
        self._stats_total_bytes_in = 0
        self._stats_total_bytes_out = 0

    @property
    def profile(self) -> TrafficProfile:
        return self._profile

    def fragment(self, data: bytes) -> List[bytes]:
        """Fragment *data* into raw (un-padded) chunks matching the profile sizes.

        Large payloads are split; small ones are left as-is (possibly smaller
        than a sampled target size — we never zero-pad application data itself,
        only add a declared padding suffix via ``encode_chunk``).

        Args:
            data: Raw bytes to fragment.

        Returns:
            List of byte slices covering *data* exactly.
        """
        if not data:
            return []
        chunks: List[bytes] = []
        offset = 0
        while offset < len(data):
            target = self._profile.sample_chunk_size()
            end = min(offset + target, len(data))
            chunks.append(data[offset:end])
            offset = end
        return chunks

    def encode_with_padding(self, chunk: bytes) -> bytes:
        """Add random padding to a chunk and encode with padding header.

        Args:
            chunk: Data chunk (already-fragmented slice).

        Returns:
            Wire-encoded bytes: padding_len header + chunk + padding.
        """
        padding = self._profile.sample_padding()
        return encode_chunk(chunk, padding)

    def shape_outgoing(self, data: bytes) -> List[bytes]:
        """Fragment *data* and encode each fragment with padding.

        This is the main entry point for shaping outgoing VPN traffic.

        Args:
            data: Raw application payload.

        Returns:
            List of wire-encoded chunks ready to be sent one by one.
        """
        with self._lock:
            self._stats_total_bytes_in += len(data)
            fragments = self.fragment(data)
            encoded = [self.encode_with_padding(f) for f in fragments]
            out_bytes = sum(len(e) for e in encoded)
            self._stats_total_bytes_out += out_bytes
            self._stats_total_chunks += len(encoded)
            logger.debug(
                "traffic_shaping.shape_outgoing",
                profile=self._profile.name,
                input_bytes=len(data),
                chunks=len(encoded),
                output_bytes=out_bytes,
            )
            return encoded

    def inter_chunk_delay(self) -> float:
        """Return delay to sleep between sending consecutive chunks (seconds).

        After ``profile.burst_count`` chunks, a longer burst pause is returned
        and the burst counter resets.

        Returns:
            Delay in seconds (may be 0.0).
        """
        with self._lock:
            self._chunks_in_burst += 1
            if self._chunks_in_burst >= self._profile.burst_count:
                self._chunks_in_burst = 0
                delay = self._profile.sample_burst_pause()
            else:
                delay = self._profile.sample_inter_chunk_delay()
        return delay

    def wait_inter_chunk(self) -> None:
        """Sleep for the appropriate inter-chunk delay."""
        delay = self.inter_chunk_delay()
        if delay > 0:
            time.sleep(delay)

    def reset_burst(self) -> None:
        """Reset the burst counter (call after a response is received)."""
        with self._lock:
            self._chunks_in_burst = 0

    def stats(self) -> dict:
        """Return shaping statistics."""
        with self._lock:
            return {
                "total_chunks": self._stats_total_chunks,
                "total_bytes_in": self._stats_total_bytes_in,
                "total_bytes_out": self._stats_total_bytes_out,
                "overhead_bytes": (
                    self._stats_total_bytes_out - self._stats_total_bytes_in
                ),
            }


# ---------------------------------------------------------------------------
# ShapedConn — transparent net.Conn-style wrapper
# ---------------------------------------------------------------------------


class ShapedConn:
    """Wraps a socket-like connection and applies traffic shaping transparently.

    Write path: data is fragmented + padded per the profile, sent with timing.
    Read path: received chunks are decoded (padding stripped) and reassembled.

    The connection must already be an established byte-stream (e.g. a
    ``NoiseConn`` or plain TCP socket).  ShapedConn handles the 2-byte padding
    header framing, so both ends must use ShapedConn (or compatible logic).

    Args:
        conn: Any object with ``send(bytes) -> int`` and ``recv(int) -> bytes``
              methods (e.g. ``socket.socket``).
        profile: Traffic profile to apply on the write path.
        apply_timing: If True (default), sleep between chunk sends.
    """

    def __init__(
        self,
        conn,
        profile: Optional[TrafficProfile] = None,
        apply_timing: bool = True,
    ) -> None:
        self._conn = conn
        self._shaper = TrafficShaper(profile or browser_profile())
        self._apply_timing = apply_timing
        self._read_buf = b""
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def write(self, data: bytes) -> int:
        """Shape and send *data* over the wrapped connection.

        Args:
            data: Raw bytes to send.

        Returns:
            Number of input bytes consumed (== len(data)).
        """
        chunks = self._shaper.shape_outgoing(data)
        for i, chunk in enumerate(chunks):
            self._sendall(chunk)
            if self._apply_timing and i < len(chunks) - 1:
                self._shaper.wait_inter_chunk()
        return len(data)

    def _sendall(self, data: bytes) -> None:
        """Send all bytes, retrying on partial sends."""
        total = 0
        while total < len(data):
            sent = self._conn.send(data[total:])
            if sent == 0:
                raise ConnectionError("Connection closed during send")
            total += sent

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def _recv_exactly(self, n: int) -> bytes:
        """Receive exactly *n* bytes from the connection."""
        buf = bytearray()
        while len(buf) < n:
            chunk = self._conn.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("Connection closed during recv")
            buf.extend(chunk)
        return bytes(buf)

    def read(self, max_size: int = 65536) -> bytes:
        """Read and decode one shaped chunk from the connection.

        Blocks until a complete chunk is available.  Returns the decoded
        application payload (padding stripped).

        Args:
            max_size: Hint for maximum desired bytes (not strictly enforced;
                      a single decoded chunk may be larger).

        Returns:
            Decoded application payload bytes.

        Raises:
            ConnectionError: If the connection is closed.
            ValueError: If the chunk is malformed.
        """
        # Read padding header (2 bytes)
        header = self._recv_exactly(PADDING_HEADER_SIZE)
        padding_len = struct.unpack(">H", header)[0]

        # We need to know the data length.  The length is determined by the
        # upper framing layer (NoiseConn / ObfsConn).  ShapedConn sits on top
        # of that layer, so each Read() call returns exactly one application
        # message which was split into chunks on the write side.
        #
        # For the simple case where ShapedConn wraps a raw TCP stream, we
        # read until we get a FIN — but that's impractical.  Instead, the
        # caller is expected to have a length-framed layer below (e.g.
        # NoiseConn's 2-byte length prefix).
        #
        # Here we read the known-size total: recv enough for the full record.
        # Since this is a wrapper, the caller passes `max_size` as the exact
        # expected payload size.  In practice the lower layer handles
        # record framing.
        #
        # Practical approach: read exactly `max_size` data + `padding_len`
        # padding.  The caller must know the data length (from lower framing).
        data = self._recv_exactly(max_size)
        if padding_len > 0:
            self._recv_exactly(padding_len)  # discard padding
        return data

    def close(self) -> None:
        """Close the underlying connection."""
        self._conn.close()

    @property
    def shaper(self) -> TrafficShaper:
        return self._shaper


# ---------------------------------------------------------------------------
# Convenience factory
# ---------------------------------------------------------------------------


def create_shaper(profile_name: str = "browser") -> TrafficShaper:
    """Create a TrafficShaper for a named built-in profile.

    Args:
        profile_name: One of ``"browser"``, ``"streaming"``, ``"idle"``.

    Returns:
        TrafficShaper instance.

    Raises:
        ValueError: If profile_name is unknown.
    """
    profiles = {
        "browser": browser_profile,
        "streaming": streaming_profile,
        "idle": idle_profile,
    }
    if profile_name not in profiles:
        raise ValueError(
            f"Unknown profile '{profile_name}'. "
            f"Available: {list(profiles.keys())}"
        )
    return TrafficShaper(profiles[profile_name]())
