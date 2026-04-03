"""Lightweight performance metrics collector for the VPN client.

Mirrors the server-side perf.Collector but in Python. All public methods
are thread-safe. Designed for minimal overhead on the data path.

Usage::

    from perf_collector import PerfCollector, Stage

    pc = PerfCollector()
    with pc.timer(Stage.NOISE_ENCRYPT):
        ciphertext = cipher.encrypt(data)

    pc.track_packet(Stage.TUN_WRITE, len(data))
    snap = pc.snapshot()
"""

from __future__ import annotations

import enum
import json
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field, asdict
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Dict, List, Optional


class Stage(str, enum.Enum):
    """Data-path stages where latency is measured."""
    OBFS_WRITE = "obfs_write"
    OBFS_READ = "obfs_read"
    NOISE_ENCRYPT = "noise_encrypt"
    NOISE_DECRYPT = "noise_decrypt"
    MUX_WRITE = "mux_write"
    MUX_READ = "mux_read"
    TUN_WRITE = "tun_write"
    TUN_READ = "tun_read"
    HANDSHAKE = "handshake"
    SHAPING_DELAY = "shaping_delay"
    PADDING_OVERHEAD = "padding_overhead"
    FULL_RTT = "full_rtt"


# ---------------------------------------------------------------------------
# Lock-free-ish histogram (uses a single lock for simplicity in Python;
# the GIL makes atomic-like patterns less critical than in Go).
# ---------------------------------------------------------------------------

_HIST_BUCKETS = 20  # log2 buckets: <1µs, <2µs, <4µs, … <~1s


@dataclass
class HistogramSnapshot:
    count: int = 0
    mean_us: float = 0.0
    max_us: float = 0.0
    p50_us: float = 0.0
    p95_us: float = 0.0
    p99_us: float = 0.0


class _Histogram:
    __slots__ = ("_buckets", "_count", "_sum_ns", "_max_ns", "_lock")

    def __init__(self):
        self._buckets = [0] * _HIST_BUCKETS
        self._count = 0
        self._sum_ns = 0
        self._max_ns = 0
        self._lock = threading.Lock()

    def record(self, duration_s: float) -> None:
        ns = int(duration_s * 1_000_000_000)
        if ns <= 0:
            ns = 1
        usec = max(ns // 1000, 1)
        idx = 0
        v = usec
        while v > 1 and idx < _HIST_BUCKETS - 1:
            v >>= 1
            idx += 1
        with self._lock:
            self._buckets[idx] += 1
            self._count += 1
            self._sum_ns += ns
            if ns > self._max_ns:
                self._max_ns = ns

    def snapshot(self) -> HistogramSnapshot:
        with self._lock:
            count = self._count
            sum_ns = self._sum_ns
            max_ns = self._max_ns
            buckets = list(self._buckets)

        if count == 0:
            return HistogramSnapshot()

        mean_us = sum_ns / count / 1000.0
        max_us = max_ns / 1000.0
        p50 = _percentile(buckets, count, 0.50)
        p95 = _percentile(buckets, count, 0.95)
        p99 = _percentile(buckets, count, 0.99)
        return HistogramSnapshot(
            count=count, mean_us=mean_us, max_us=max_us,
            p50_us=p50, p95_us=p95, p99_us=p99,
        )

    def reset(self) -> None:
        with self._lock:
            self._buckets = [0] * _HIST_BUCKETS
            self._count = 0
            self._sum_ns = 0
            self._max_ns = 0


def _percentile(buckets: List[int], total: int, p: float) -> float:
    target = int(total * p + 0.5) or 1
    cumulative = 0
    for i, c in enumerate(buckets):
        cumulative += c
        if cumulative >= target:
            return 1.0 if i == 0 else float(1 << i)
    return float(1 << (_HIST_BUCKETS - 1))


# ---------------------------------------------------------------------------
# Stage metrics
# ---------------------------------------------------------------------------

class _StageMetrics:
    __slots__ = ("hist", "packets", "bytes_total", "_lock")

    def __init__(self):
        self.hist = _Histogram()
        self.packets = 0
        self.bytes_total = 0
        self._lock = threading.Lock()

    def track_packet(self, size: int) -> None:
        with self._lock:
            self.packets += 1
            self.bytes_total += size

    def snapshot(self) -> dict:
        with self._lock:
            packets = self.packets
            bytes_total = self.bytes_total
        return {
            "latency": asdict(self.hist.snapshot()),
            "packets": packets,
            "bytes": bytes_total,
        }

    def reset(self) -> None:
        self.hist.reset()
        with self._lock:
            self.packets = 0
            self.bytes_total = 0


# ---------------------------------------------------------------------------
# PerfCollector
# ---------------------------------------------------------------------------

@dataclass
class Snapshot:
    timestamp: str
    stages: Dict[str, dict]
    shaping_delay_total_ms: float = 0.0
    padding_overhead_pct: float = 0.0
    cover_traffic_bytes: int = 0
    reconnect_count: int = 0


class PerfCollector:
    """Central performance metrics collector for the VPN client."""

    def __init__(self):
        self._stages: Dict[Stage, _StageMetrics] = {
            s: _StageMetrics() for s in Stage
        }
        self._lock = threading.Lock()
        self.shaping_delay_total_ms: float = 0.0
        self.padding_overhead_pct: float = 0.0
        self.cover_traffic_bytes: int = 0
        self.reconnect_count: int = 0

    def track_latency(self, stage: Stage, duration_s: float) -> None:
        """Record a latency observation (in seconds)."""
        m = self._stages.get(stage)
        if m:
            m.hist.record(duration_s)

    def track_packet(self, stage: Stage, size: int) -> None:
        """Record one packet of given size passing through a stage."""
        m = self._stages.get(stage)
        if m:
            m.track_packet(size)

    @contextmanager
    def timer(self, stage: Stage):
        """Context manager that records elapsed time for a stage."""
        t0 = time.monotonic()
        try:
            yield
        finally:
            self.track_latency(stage, time.monotonic() - t0)

    def track_shaping_delay(self, delay_ms: float) -> None:
        with self._lock:
            self.shaping_delay_total_ms += delay_ms

    def track_padding(self, real_bytes: int, padded_bytes: int) -> None:
        if real_bytes > 0:
            with self._lock:
                self.padding_overhead_pct = (
                    (padded_bytes - real_bytes) / real_bytes * 100.0
                )

    def track_cover_traffic(self, nbytes: int) -> None:
        with self._lock:
            self.cover_traffic_bytes += nbytes

    def track_reconnect(self) -> None:
        with self._lock:
            self.reconnect_count += 1

    def snapshot(self) -> dict:
        """Return a JSON-serializable snapshot of all metrics."""
        stages = {}
        for s in Stage:
            stages[s.value] = self._stages[s].snapshot()
        with self._lock:
            return {
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "stages": stages,
                "shaping_delay_total_ms": self.shaping_delay_total_ms,
                "padding_overhead_pct": self.padding_overhead_pct,
                "cover_traffic_bytes": self.cover_traffic_bytes,
                "reconnect_count": self.reconnect_count,
            }

    def reset(self) -> None:
        """Zero all counters and histograms."""
        for m in self._stages.values():
            m.reset()
        with self._lock:
            self.shaping_delay_total_ms = 0.0
            self.padding_overhead_pct = 0.0
            self.cover_traffic_bytes = 0
            self.reconnect_count = 0


# ---------------------------------------------------------------------------
# Local HTTP server for exposing client metrics to the diagnostics tool.
# ---------------------------------------------------------------------------

class _PerfHandler(BaseHTTPRequestHandler):
    collector: Optional[PerfCollector] = None

    def do_GET(self):
        if self.path == "/perf":
            snap = self.collector.snapshot() if self.collector else {}
            body = json.dumps(snap, indent=2).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_error(404)

    def do_POST(self):
        if self.path == "/perf/reset":
            if self.collector:
                self.collector.reset()
            body = b'{"status":"reset"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_error(404)

    def log_message(self, format, *args):
        pass  # suppress default stderr logging


def start_perf_server(
    collector: PerfCollector,
    host: str = "127.0.0.1",
    port: int = 9091,
) -> HTTPServer:
    """Start a background HTTP server exposing /perf and /perf/reset.

    Returns the HTTPServer instance (call .shutdown() to stop).
    """
    handler_class = type("PerfHandler", (_PerfHandler,), {"collector": collector})
    server = HTTPServer((host, port), handler_class)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server
