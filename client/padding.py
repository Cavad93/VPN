"""
padding.py — Advanced padding and timing randomization for statistical traffic analysis resistance.

This module implements techniques to defeat network traffic analysis attacks that use
statistical methods to identify and classify VPN/encrypted traffic:

1. **Fixed-bucket padding**: Every outgoing frame is padded to the nearest
   pre-defined "bucket" size.  This collapses the continuous packet-size
   distribution to a small discrete set, defeating size-based fingerprinting
   and machine-learning classifiers that rely on exact packet lengths.

2. **Timing jitter**: A configurable random delay (uniform, Gaussian, or
   exponential distribution) is added before each send.  This blurs
   inter-packet timing (IAT) statistics used by traffic classifiers.

3. **Cover traffic**: A background thread injects random-sized dummy
   (FLAG_COVER) frames during idle periods.  This prevents correlation
   attacks that exploit silence patterns and traffic-volume fingerprints.

Wire format (sits on top of any byte-stream transport with a length-framing layer):
    [4 B: frame_len uint32 BE]  — total body bytes (excludes these 4 bytes)
    [1 B: flags]                — FLAG_DATA / FLAG_COVER / FLAG_KEEPALIVE
    [2 B: padding_len uint16 BE]— bytes of random padding appended after data
    [N B: data]                 — actual payload (empty for cover/keepalive)
    [padding_len B: random]     — cryptographically random padding bytes

Receiver: read 4 B → frame_len → read frame_len bytes → decode → check flags.
If FLAG_COVER or FLAG_KEEPALIVE: discard and read next frame.

Usage::

    import socket
    from padding import create_obfuscator

    a, b = socket.socketpair()
    sender   = create_obfuscator(a, mode="balanced")
    receiver = create_obfuscator(b, mode="balanced")

    sender.write(b"secret payload")
    data = receiver.read()   # b"secret payload"

    sender.close()
    receiver.close()
"""

from __future__ import annotations

import math
import os
import random
import struct
import threading
import time
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional

import structlog

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Wire format constants
# ---------------------------------------------------------------------------

FRAME_LEN_SIZE: int = 4   # uint32 BE: byte count of the frame body
FLAGS_SIZE: int = 1        # uint8: packet-type flag
PADDING_LEN_SIZE: int = 2  # uint16 BE: bytes of trailing random padding
FRAME_HEADER_SIZE: int = FLAGS_SIZE + PADDING_LEN_SIZE  # 3 bytes (excl. length prefix)

# Flag values stored in the flags byte of every frame
FLAG_DATA: int = 0x00       # Real application payload — pass to caller
FLAG_COVER: int = 0x01      # Cover-traffic dummy — receiver must discard
FLAG_KEEPALIVE: int = 0x02  # Keepalive heartbeat — receiver must discard

# Bucket sizes (bytes) matching common TLS record sizes and power-of-2 boundaries.
# All packet bodies are padded to the nearest bucket to normalise size distribution.
DEFAULT_BUCKETS: List[int] = [
    64, 128, 256, 512, 1024, 1448, 2896, 4096, 8192, 16384,
]


# ---------------------------------------------------------------------------
# Wire-format helpers
# ---------------------------------------------------------------------------


def encode_frame(data: bytes, flag: int, padding_len: int) -> bytes:
    """Build a complete length-prefixed wire frame.

    Layout::

        [4 B: frame_len uint32 BE]
        [1 B: flag]
        [2 B: padding_len uint16 BE]
        [len(data) B: data]
        [padding_len B: random padding]

    Args:
        data: Payload bytes (may be empty for cover/keepalive frames).
        flag: One of FLAG_DATA, FLAG_COVER, FLAG_KEEPALIVE.
        padding_len: Number of random bytes appended after *data*.

    Returns:
        Complete wire frame including the 4-byte length prefix.

    Raises:
        ValueError: If *padding_len* > 65535.
    """
    if padding_len > 65535:
        raise ValueError(f"padding_len {padding_len} exceeds maximum 65535")
    padding = os.urandom(padding_len)
    body = struct.pack(">BH", flag, padding_len) + data + padding
    return struct.pack(">I", len(body)) + body


def decode_frame(body: bytes) -> tuple:
    """Decode a frame body (the bytes after the 4-byte length prefix).

    Args:
        body: Raw frame body bytes.

    Returns:
        Tuple ``(flag: int, data: bytes)``.

    Raises:
        ValueError: If the frame is too short or its padding field is invalid.
    """
    if len(body) < FRAME_HEADER_SIZE:
        raise ValueError(
            f"Frame body too short: {len(body)} < {FRAME_HEADER_SIZE}"
        )
    flag, padding_len = struct.unpack(">BH", body[:FRAME_HEADER_SIZE])
    if padding_len > len(body) - FRAME_HEADER_SIZE:
        raise ValueError(
            f"Frame malformed: padding_len={padding_len} exceeds available body bytes"
        )
    data_end = len(body) - padding_len
    data = body[FRAME_HEADER_SIZE:data_end]
    return flag, data


# ---------------------------------------------------------------------------
# Fixed-bucket padder
# ---------------------------------------------------------------------------


class FixedBucketPadder:
    """Pad every frame to the nearest fixed-size bucket.

    Collapsing the continuous packet-size distribution to a small set of
    discrete values makes size-based statistical analysis and ML classifiers
    significantly less effective.

    Args:
        buckets: Sorted list of allowed total frame-body sizes (header +
                 data + padding).  Defaults to ``DEFAULT_BUCKETS``.
    """

    def __init__(self, buckets: Optional[List[int]] = None) -> None:
        effective = DEFAULT_BUCKETS if buckets is None else buckets
        self._buckets: List[int] = sorted(set(effective))
        if not self._buckets:
            raise ValueError("Bucket list must not be empty")

    @property
    def buckets(self) -> List[int]:
        """Return a copy of the bucket list."""
        return list(self._buckets)

    def target_frame_size(self, data_len: int) -> int:
        """Return the smallest bucket that accommodates *data_len* data bytes.

        The bucket must be >= FRAME_HEADER_SIZE + data_len.

        Args:
            data_len: Number of application data bytes (not counting headers
                      or padding).

        Returns:
            Target frame-body size in bytes (header + data + padding).
        """
        needed = FRAME_HEADER_SIZE + data_len
        for b in self._buckets:
            if b >= needed:
                return b
        # data_len exceeds every bucket: align to next multiple of max bucket
        max_b = self._buckets[-1]
        return math.ceil(needed / max_b) * max_b

    def compute_padding(self, data_len: int) -> int:
        """Return the number of padding bytes needed for *data_len* data bytes.

        The result satisfies::

            FRAME_HEADER_SIZE + data_len + compute_padding(data_len) == target_frame_size(data_len)

        Args:
            data_len: Number of application data bytes.

        Returns:
            Non-negative number of padding bytes.
        """
        target = self.target_frame_size(data_len)
        return max(0, target - FRAME_HEADER_SIZE - data_len)


# ---------------------------------------------------------------------------
# Timing jitter
# ---------------------------------------------------------------------------


class JitterDistribution(Enum):
    """Probability distribution for sampling timing jitter."""

    UNIFORM = "uniform"          # Uniform random in [min_ms, max_ms]
    GAUSSIAN = "gaussian"        # Normal(mean_ms, std_ms), clamped to [min, max]
    EXPONENTIAL = "exponential"  # Exponential(1/mean_ms), clamped to [min, max]


@dataclass
class JitterConfig:
    """Configuration for per-packet timing jitter.

    Jitter is added as a ``time.sleep()`` *before* each send, blurring the
    inter-arrival time (IAT) distribution seen by a passive observer.

    Attributes:
        distribution: Which probability distribution to sample from.
        min_ms: Minimum jitter in milliseconds (floor clamp).
        max_ms: Maximum jitter in milliseconds (ceiling clamp).
        mean_ms: Mean jitter used by GAUSSIAN and EXPONENTIAL distributions.
        std_ms: Standard deviation used by the GAUSSIAN distribution only.
    """

    distribution: JitterDistribution = JitterDistribution.UNIFORM
    min_ms: float = 0.0
    max_ms: float = 20.0
    mean_ms: float = 8.0
    std_ms: float = 4.0

    def sample_ms(self) -> float:
        """Sample a jitter value in milliseconds, clamped to [min_ms, max_ms]."""
        if self.distribution == JitterDistribution.UNIFORM:
            return random.uniform(self.min_ms, self.max_ms)
        elif self.distribution == JitterDistribution.GAUSSIAN:
            v = random.gauss(self.mean_ms, self.std_ms)
        elif self.distribution == JitterDistribution.EXPONENTIAL:
            rate = 1.0 / max(self.mean_ms, 1e-9)
            v = random.expovariate(rate)
        else:
            return 0.0
        return max(self.min_ms, min(self.max_ms, v))

    def sample_seconds(self) -> float:
        """Sample jitter in seconds."""
        return self.sample_ms() / 1000.0

    def wait(self) -> None:
        """Sleep for a sampled jitter duration."""
        delay = self.sample_seconds()
        if delay > 0.0:
            time.sleep(delay)


# ---------------------------------------------------------------------------
# Cover traffic configuration
# ---------------------------------------------------------------------------


@dataclass
class CoverTrafficConfig:
    """Configuration for background cover traffic injection.

    A daemon thread sends random FLAG_COVER frames during idle periods.
    The receiver silently discards them.  This prevents an observer from
    inferring communication patterns from silence gaps.

    Attributes:
        enabled: If False, no cover-traffic thread is started.
        idle_threshold_ms: Milliseconds of silence before the first cover
            packet is injected.
        interval_ms: How often the cover thread checks and potentially sends
            (milliseconds).
        min_size: Minimum simulated payload size for cover frames (bytes).
        max_size: Maximum simulated payload size for cover frames (bytes).
    """

    enabled: bool = True
    idle_threshold_ms: float = 200.0
    interval_ms: float = 500.0
    min_size: int = 64
    max_size: int = 512


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------


class _Stats:
    """Mutable statistics counters (not exported directly)."""

    __slots__ = (
        "data_packets_sent",
        "cover_packets_sent",
        "keepalive_packets_sent",
        "data_bytes_in",
        "data_bytes_out",
        "cover_bytes_out",
        "data_packets_recv",
        "cover_packets_recv",
    )

    def __init__(self) -> None:
        self.data_packets_sent: int = 0
        self.cover_packets_sent: int = 0
        self.keepalive_packets_sent: int = 0
        self.data_bytes_in: int = 0
        self.data_bytes_out: int = 0
        self.cover_bytes_out: int = 0
        self.data_packets_recv: int = 0
        self.cover_packets_recv: int = 0


# ---------------------------------------------------------------------------
# Core obfuscator
# ---------------------------------------------------------------------------


class StatisticalObfuscator:
    """Combines fixed-bucket padding, timing jitter, and cover traffic.

    Sits on top of any byte-stream connection and applies three layers of
    statistical obfuscation to defeat passive traffic analysis:

    * **Fixed-bucket padding** — all outgoing frames padded to discrete sizes.
    * **Timing jitter** — configurable random delay before every send.
    * **Cover traffic** — daemon thread fills silence with dummy frames.

    Thread-safety: ``write()`` and ``close()`` are thread-safe.
    ``read()`` should be called from a single reader thread.

    Args:
        conn: Underlying connection exposing ``send(bytes) -> int`` and
              ``recv(int) -> bytes``.  Any ``socket.socket`` or compatible
              object works.
        padder: Fixed-bucket padder instance.  Defaults to DEFAULT_BUCKETS.
        jitter: Timing jitter configuration.  Defaults to light uniform jitter.
        cover_config: Cover traffic parameters.  Defaults to enabled with
            200 ms idle threshold.
    """

    def __init__(
        self,
        conn,
        padder: Optional[FixedBucketPadder] = None,
        jitter: Optional[JitterConfig] = None,
        cover_config: Optional[CoverTrafficConfig] = None,
    ) -> None:
        self._conn = conn
        self._padder = padder or FixedBucketPadder()
        self._jitter = jitter or JitterConfig(
            distribution=JitterDistribution.UNIFORM,
            min_ms=0.0,
            max_ms=5.0,
        )
        self._cover_config = cover_config or CoverTrafficConfig()
        self._write_lock = threading.Lock()
        self._last_send_time: float = time.monotonic()
        self._stats = _Stats()
        self._closed = False
        self._stop_event = threading.Event()

        if self._cover_config.enabled:
            self._cover_thread: Optional[threading.Thread] = threading.Thread(
                target=self._cover_traffic_loop,
                daemon=True,
                name="padding.CoverTraffic",
            )
            self._cover_thread.start()
        else:
            self._cover_thread = None

    # ------------------------------------------------------------------
    # Write path
    # ------------------------------------------------------------------

    def write(self, data: bytes) -> None:
        """Obfuscate *data* and send it over the connection.

        Steps:
        1. Sleep for a sampled jitter delay.
        2. Compute fixed-bucket padding for ``len(data)``.
        3. Encode as a FLAG_DATA frame.
        4. Send atomically under the write lock.

        Args:
            data: Raw application payload bytes.

        Raises:
            ConnectionError: If the connection has been closed.
        """
        self._jitter.wait()
        padding_len = self._padder.compute_padding(len(data))
        frame = encode_frame(data, FLAG_DATA, padding_len)

        with self._write_lock:
            if self._closed:
                raise ConnectionError("StatisticalObfuscator is closed")
            self._sendall(frame)
            self._last_send_time = time.monotonic()
            self._stats.data_packets_sent += 1
            self._stats.data_bytes_in += len(data)
            self._stats.data_bytes_out += len(frame)
            logger.debug(
                "padding.write",
                data_len=len(data),
                frame_len=len(frame),
                padding_len=padding_len,
            )

    def _build_cover_frame(self) -> bytes:
        """Build a cover frame whose wire size matches a real data frame.

        The cover frame is padded to the same bucket that a real packet of
        a randomly chosen size in [min_size, max_size] would occupy.
        This makes cover frames statistically indistinguishable from real
        data frames by size alone.
        """
        simulated_data_len = random.randint(
            self._cover_config.min_size,
            self._cover_config.max_size,
        )
        # Total body size that a real packet with simulated_data_len would occupy
        target_body = self._padder.target_frame_size(simulated_data_len)
        # Cover frame has 0 real data bytes; all remaining space is padding
        padding_len = target_body - FRAME_HEADER_SIZE
        return encode_frame(b"", FLAG_COVER, max(0, padding_len))

    def _send_cover_packet(self) -> None:
        """Attempt to inject one cover packet (called from cover thread)."""
        try:
            frame = self._build_cover_frame()
        except Exception as exc:
            logger.warning("padding.cover: failed to build frame", error=str(exc))
            return

        with self._write_lock:
            if self._closed:
                return
            try:
                self._sendall(frame)
                self._last_send_time = time.monotonic()
                self._stats.cover_packets_sent += 1
                self._stats.cover_bytes_out += len(frame)
                logger.debug("padding.cover: injected", frame_len=len(frame))
            except (OSError, ConnectionError):
                pass  # Underlying connection died; cover thread will exit soon

    def _sendall(self, data: bytes) -> None:
        """Send all bytes, retrying on partial writes."""
        total = 0
        while total < len(data):
            sent = self._conn.send(data[total:])
            if sent == 0:
                raise ConnectionError("send() returned 0 — connection closed")
            total += sent

    # ------------------------------------------------------------------
    # Read path
    # ------------------------------------------------------------------

    def read(self) -> bytes:
        """Receive the next real data packet, silently discarding cover/keepalive.

        Blocks until a FLAG_DATA frame arrives.  FLAG_COVER and
        FLAG_KEEPALIVE frames are consumed and discarded transparently.

        Returns:
            Decoded application payload bytes (padding stripped).

        Raises:
            ConnectionError: If the connection is closed mid-read.
            ValueError: If a frame has an unrecognised flag or is malformed.
        """
        while True:
            length_raw = self._recv_exactly(FRAME_LEN_SIZE)
            frame_len = struct.unpack(">I", length_raw)[0]
            if frame_len == 0:
                raise ValueError("Received frame with zero-length body")
            body = self._recv_exactly(frame_len)
            flag, data = decode_frame(body)

            if flag == FLAG_DATA:
                self._stats.data_packets_recv += 1
                return data
            elif flag in (FLAG_COVER, FLAG_KEEPALIVE):
                self._stats.cover_packets_recv += 1
                logger.debug(
                    "padding.read: discarding non-data frame",
                    flag=hex(flag),
                    body_len=frame_len,
                )
            else:
                raise ValueError(f"Unknown frame flag: {hex(flag)}")

    def _recv_exactly(self, n: int) -> bytes:
        """Receive exactly *n* bytes, blocking until available."""
        buf = bytearray()
        while len(buf) < n:
            chunk = self._conn.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("Connection closed during recv")
            buf.extend(chunk)
        return bytes(buf)

    # ------------------------------------------------------------------
    # Cover traffic background loop
    # ------------------------------------------------------------------

    def _cover_traffic_loop(self) -> None:
        """Daemon thread: inject cover packets when the connection is idle."""
        interval = self._cover_config.interval_ms / 1000.0
        threshold = self._cover_config.idle_threshold_ms / 1000.0

        while not self._stop_event.wait(timeout=interval):
            if self._closed:
                break
            elapsed = time.monotonic() - self._last_send_time
            if elapsed >= threshold:
                self._send_cover_packet()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Stop the cover thread and close the underlying connection."""
        self._stop_event.set()
        with self._write_lock:
            self._closed = True
        if self._cover_thread is not None and self._cover_thread.is_alive():
            self._cover_thread.join(timeout=2.0)
        try:
            self._conn.close()
        except Exception:
            pass

    def stats(self) -> dict:
        """Return a snapshot of obfuscation statistics.

        Returns:
            Dictionary with keys:

            * ``data_packets_sent`` — real data packets sent
            * ``cover_packets_sent`` — cover frames injected
            * ``keepalive_packets_sent`` — keepalive frames sent
            * ``data_bytes_in`` — application bytes passed to :meth:`write`
            * ``data_bytes_out`` — wire bytes sent for data frames
            * ``cover_bytes_out`` — wire bytes sent for cover frames
            * ``data_packets_recv`` — real data packets received
            * ``cover_packets_recv`` — cover/keepalive frames discarded on read
            * ``overhead_ratio`` — padding + cover overhead relative to data bytes
        """
        s = self._stats
        overhead = (s.data_bytes_out + s.cover_bytes_out) - s.data_bytes_in
        return {
            "data_packets_sent": s.data_packets_sent,
            "cover_packets_sent": s.cover_packets_sent,
            "keepalive_packets_sent": s.keepalive_packets_sent,
            "data_bytes_in": s.data_bytes_in,
            "data_bytes_out": s.data_bytes_out,
            "cover_bytes_out": s.cover_bytes_out,
            "data_packets_recv": s.data_packets_recv,
            "cover_packets_recv": s.cover_packets_recv,
            "overhead_ratio": overhead / max(s.data_bytes_in, 1),
        }


# ---------------------------------------------------------------------------
# Preset factory
# ---------------------------------------------------------------------------


def create_obfuscator(conn, mode: str = "balanced") -> StatisticalObfuscator:
    """Create a :class:`StatisticalObfuscator` with a preset configuration.

    Three presets are available, trading overhead for protection strength:

    * ``"light"`` — minimal overhead (~5–15 %): uniform jitter 0–5 ms,
      fixed-bucket padding, no cover traffic.  Suitable when bandwidth is
      scarce or latency is critical.

    * ``"balanced"`` — moderate overhead (~20–40 %): Gaussian jitter
      (mean 10 ms, σ 5 ms), fixed-bucket padding, cover traffic every 500 ms
      after 200 ms of silence.  Good default for typical usage.

    * ``"paranoid"`` — high overhead (~50–100 %): exponential jitter
      (mean 20 ms), fine-grained bucket sizes (power-of-2), cover traffic
      every 100 ms after 50 ms of silence.  Maximises resistance to
      advanced traffic-analysis attacks.

    Args:
        conn: Underlying connection with ``send`` / ``recv`` interface.
        mode: One of ``"light"``, ``"balanced"``, ``"paranoid"``.

    Returns:
        Configured :class:`StatisticalObfuscator`.

    Raises:
        ValueError: If *mode* is not recognised.
    """
    if mode == "light":
        return StatisticalObfuscator(
            conn,
            padder=FixedBucketPadder(),
            jitter=JitterConfig(
                distribution=JitterDistribution.UNIFORM,
                min_ms=0.0,
                max_ms=5.0,
            ),
            cover_config=CoverTrafficConfig(enabled=False),
        )

    if mode == "balanced":
        return StatisticalObfuscator(
            conn,
            padder=FixedBucketPadder(),
            jitter=JitterConfig(
                distribution=JitterDistribution.GAUSSIAN,
                min_ms=0.0,
                max_ms=30.0,
                mean_ms=10.0,
                std_ms=5.0,
            ),
            cover_config=CoverTrafficConfig(
                enabled=True,
                idle_threshold_ms=200.0,
                interval_ms=500.0,
                min_size=64,
                max_size=256,
            ),
        )

    if mode == "paranoid":
        fine_buckets = [32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384]
        return StatisticalObfuscator(
            conn,
            padder=FixedBucketPadder(fine_buckets),
            jitter=JitterConfig(
                distribution=JitterDistribution.EXPONENTIAL,
                min_ms=0.0,
                max_ms=100.0,
                mean_ms=20.0,
            ),
            cover_config=CoverTrafficConfig(
                enabled=True,
                idle_threshold_ms=50.0,
                interval_ms=100.0,
                min_size=128,
                max_size=512,
            ),
        )

    raise ValueError(
        f"Unknown obfuscation mode '{mode}'. "
        "Available modes: 'light', 'balanced', 'paranoid'"
    )
