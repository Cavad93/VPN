"""
telemetry.py — Client-side diagnostic telemetry collection and reporting.

Collects network performance metrics every interval and sends them to the
VPN server's telemetry API endpoint for AI-powered analysis.
"""

from __future__ import annotations

import hashlib
import json
import platform
import socket
import struct
import threading
import time
import urllib.request
import urllib.error
from dataclasses import dataclass, field, asdict
from typing import Optional, Callable

import structlog

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Device ID
# ---------------------------------------------------------------------------

def _generate_device_id() -> str:
    """Generate a stable device ID based on machine characteristics."""
    parts = [
        platform.node(),
        platform.machine(),
        platform.system(),
    ]
    raw = "|".join(parts).encode()
    return hashlib.sha256(raw).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class TelemetryReport:
    """Single diagnostic snapshot."""
    device_id: str = ""
    platform: str = ""
    app_version: str = "1.0.0"
    timestamp: str = ""  # ISO 8601

    # Connection metrics
    server_addr: str = ""
    connection_state: str = "disconnected"
    uptime_sec: float = 0.0
    reconnect_count: int = 0

    # Latency
    handshake_ms: float = 0.0
    ping_ms: float = 0.0
    jitter_ms: float = 0.0

    # Throughput
    bytes_in: int = 0
    bytes_out: int = 0
    throughput_in_kbps: float = 0.0
    throughput_out_kbps: float = 0.0

    # Packet stats
    packet_loss_percent: float = 0.0
    retransmit_count: int = 0
    out_of_order_count: int = 0

    # Network
    network_type: str = "unknown"
    signal_strength: int = 0
    carrier: str = ""
    local_ip: str = ""

    # Obfuscation
    obfs_latency_ms: float = 0.0
    dpi_detected: bool = False
    tls_errors: int = 0

    # DNS
    dns_resolve_ms: float = 0.0

    # Speed test
    download_speed_kbps: float = 0.0
    upload_speed_kbps: float = 0.0

    # System
    cpu_percent: float = 0.0
    memory_mb: float = 0.0
    battery_percent: int = 0


def _detect_platform() -> str:
    """Return normalized platform name."""
    s = platform.system().lower()
    if s == "darwin":
        return "macos"
    return s  # "linux", "windows"


def _detect_network_type() -> str:
    """Best-effort network type detection."""
    # On macOS we could parse scutil/networksetup, but for simplicity:
    return "wifi"  # default assumption; overridden by mobile clients


def _get_local_ip() -> str:
    """Get local IP address (masked for privacy)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        # Mask last octet for privacy.
        parts = ip.split(".")
        if len(parts) == 4:
            parts[3] = "x"
            return ".".join(parts)
        return ip
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Ping measurement
# ---------------------------------------------------------------------------

def measure_tcp_ping(host: str, port: int, timeout: float = 5.0) -> float:
    """Measure TCP connect latency to server in milliseconds."""
    try:
        start = time.monotonic()
        s = socket.create_connection((host, port), timeout=timeout)
        elapsed = (time.monotonic() - start) * 1000
        s.close()
        return round(elapsed, 2)
    except Exception:
        return 0.0


def measure_dns_resolve(hostname: str = "google.com") -> float:
    """Measure DNS resolution time in milliseconds."""
    try:
        start = time.monotonic()
        socket.getaddrinfo(hostname, 443, socket.AF_INET)
        return round((time.monotonic() - start) * 1000, 2)
    except Exception:
        return 0.0


def measure_download_speed(url: str, timeout: float = 10.0) -> float:
    """Measure download speed from a URL in kbit/s."""
    try:
        req = urllib.request.Request(url)
        start = time.monotonic()
        resp = urllib.request.urlopen(req, timeout=timeout)
        data = resp.read()
        elapsed = time.monotonic() - start
        resp.close()
        if elapsed > 0:
            return round((len(data) * 8) / (elapsed * 1000), 2)
        return 0.0
    except Exception:
        return 0.0


def measure_upload_speed(url: str, size: int = 524288, timeout: float = 10.0) -> float:
    """Measure upload speed to a URL in kbit/s. Sends `size` random bytes."""
    try:
        data = os.urandom(size)
        req = urllib.request.Request(
            url, data=data,
            headers={"Content-Type": "application/octet-stream"},
            method="POST",
        )
        start = time.monotonic()
        resp = urllib.request.urlopen(req, timeout=timeout)
        resp.read()
        resp.close()
        elapsed = time.monotonic() - start
        if elapsed > 0:
            return round((size * 8) / (elapsed * 1000), 2)
        return 0.0
    except Exception:
        return 0.0


def estimate_packet_loss(host: str, port: int, count: int = 5, timeout: float = 2.0) -> float:
    """Estimate packet loss by attempting multiple TCP connections."""
    if count <= 0:
        return 0.0
    successes = 0
    for _ in range(count):
        try:
            s = socket.create_connection((host, port), timeout=timeout)
            s.close()
            successes += 1
        except Exception:
            pass
    loss = ((count - successes) / count) * 100
    return round(loss, 1)


# ---------------------------------------------------------------------------
# Telemetry collector
# ---------------------------------------------------------------------------

@dataclass
class TelemetryConfig:
    """Configuration for telemetry collection."""
    server_url: str  # e.g. "http://193.124.93.240:8080"
    collect_interval: float = 300.0  # 5 minutes
    send_timeout: float = 10.0
    app_version: str = "1.0.0"
    device_id: str = ""  # auto-generated if empty


class TelemetryCollector:
    """
    Background telemetry collector.

    Periodically gathers metrics from the VPN client and sends
    them to the server's telemetry API.
    """

    def __init__(
        self,
        config: TelemetryConfig,
        get_vpn_state: Optional[Callable] = None,
    ) -> None:
        self._config = config
        self._device_id = config.device_id or _generate_device_id()
        self._platform = _detect_platform()
        self._get_vpn_state = get_vpn_state
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._log = logger.bind(component="telemetry")

        # Cumulative counters (set externally).
        self._bytes_in = 0
        self._bytes_out = 0
        self._prev_bytes_in = 0
        self._prev_bytes_out = 0
        self._prev_sample_time = 0.0
        self._reconnect_count = 0
        self._handshake_ms = 0.0
        self._tls_errors = 0
        self._dpi_detected = False
        self._connected_since: Optional[float] = None

        # Ping jitter tracking.
        self._ping_history: list[float] = []

        # Lock for counters.
        self._lock = threading.Lock()

    # -- Public API: update counters from VPN client -----------------------

    def update_bytes(self, bytes_in: int, bytes_out: int) -> None:
        """Update cumulative byte counters."""
        with self._lock:
            self._bytes_in = bytes_in
            self._bytes_out = bytes_out

    def record_handshake(self, duration_ms: float) -> None:
        """Record latest handshake duration."""
        with self._lock:
            self._handshake_ms = duration_ms

    def record_reconnect(self) -> None:
        """Increment reconnect counter."""
        with self._lock:
            self._reconnect_count += 1

    def record_connect(self) -> None:
        """Record connection start time."""
        with self._lock:
            self._connected_since = time.monotonic()

    def record_disconnect(self) -> None:
        """Clear connection time."""
        with self._lock:
            self._connected_since = None

    def record_tls_error(self) -> None:
        """Increment TLS error counter."""
        with self._lock:
            self._tls_errors += 1

    def record_dpi_detection(self) -> None:
        """Flag DPI detection."""
        with self._lock:
            self._dpi_detected = True

    # -- Lifecycle ---------------------------------------------------------

    def start(self) -> None:
        """Start background collection thread."""
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_loop, daemon=True, name="telemetry"
        )
        self._thread.start()
        self._log.info("telemetry_started",
                       interval=self._config.collect_interval)

    def stop(self) -> None:
        """Stop background collection."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None
        self._log.info("telemetry_stopped")

    def collect_now(self) -> TelemetryReport:
        """Collect a telemetry report immediately (for testing)."""
        return self._collect()

    def send_now(self) -> bool:
        """Collect and send immediately. Returns True on success."""
        report = self._collect()
        return self._send(report)

    # -- Internal ----------------------------------------------------------

    def _run_loop(self) -> None:
        """Background loop: collect and send at interval."""
        # Initial delay: let VPN connect first.
        self._stop_event.wait(30)

        while not self._stop_event.is_set():
            try:
                report = self._collect()
                self._send(report)
            except Exception as e:
                self._log.warning("telemetry_error", error=str(e))
            self._stop_event.wait(self._config.collect_interval)

    def _collect(self) -> TelemetryReport:
        """Gather all metrics into a report."""
        now = time.time()

        # Measure ping to VPN server.
        server_addr = ""
        ping_ms = 0.0
        if self._get_vpn_state:
            try:
                state = self._get_vpn_state()
                server_addr = state.get("server_addr", "")
            except Exception:
                pass

        host = ""
        port = 0
        if server_addr:
            try:
                host, port_str = server_addr.rsplit(":", 1)
                port = int(port_str)
                ping_ms = measure_tcp_ping(host, port)
            except Exception:
                pass

        # DNS resolution time.
        dns_ms = measure_dns_resolve()

        # Packet loss estimation (3 probes to minimize overhead).
        packet_loss = 0.0
        if host and port:
            packet_loss = estimate_packet_loss(host, port, count=3, timeout=2.0)

        # Speed test (only every 6th collection ~30 min to avoid overhead).
        download_kbps = 0.0
        upload_kbps = 0.0
        if hasattr(self, '_speed_test_counter'):
            self._speed_test_counter += 1
        else:
            self._speed_test_counter = 0
        if self._speed_test_counter % 6 == 0 and self._config.server_url:
            base = self._config.server_url.rstrip("/")
            download_kbps = measure_download_speed(
                base + "/api/v1/speedtest/download?size=524288", timeout=10.0
            )
            upload_kbps = measure_upload_speed(
                base + "/api/v1/speedtest/upload", size=262144, timeout=10.0
            )

        # Calculate jitter from ping history.
        jitter_ms = 0.0
        if ping_ms > 0:
            self._ping_history.append(ping_ms)
            if len(self._ping_history) > 12:
                self._ping_history = self._ping_history[-12:]
            if len(self._ping_history) >= 2:
                diffs = [
                    abs(self._ping_history[i] - self._ping_history[i - 1])
                    for i in range(1, len(self._ping_history))
                ]
                jitter_ms = round(sum(diffs) / len(diffs), 2)

        with self._lock:
            # Throughput calculation.
            elapsed = now - self._prev_sample_time if self._prev_sample_time > 0 else 0
            throughput_in = 0.0
            throughput_out = 0.0
            if elapsed > 0:
                delta_in = self._bytes_in - self._prev_bytes_in
                delta_out = self._bytes_out - self._prev_bytes_out
                throughput_in = round((delta_in * 8) / (elapsed * 1000), 2)  # kbit/s
                throughput_out = round((delta_out * 8) / (elapsed * 1000), 2)

            self._prev_bytes_in = self._bytes_in
            self._prev_bytes_out = self._bytes_out
            self._prev_sample_time = now

            uptime = 0.0
            if self._connected_since:
                uptime = time.monotonic() - self._connected_since

            connection_state = "disconnected"
            if self._get_vpn_state:
                try:
                    state = self._get_vpn_state()
                    connection_state = state.get("state", "disconnected")
                except Exception:
                    pass

            report = TelemetryReport(
                device_id=self._device_id,
                platform=self._platform,
                app_version=self._config.app_version,
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
                server_addr=server_addr,
                connection_state=connection_state,
                uptime_sec=round(uptime, 1),
                reconnect_count=self._reconnect_count,
                handshake_ms=self._handshake_ms,
                ping_ms=ping_ms,
                jitter_ms=jitter_ms,
                bytes_in=self._bytes_in,
                bytes_out=self._bytes_out,
                throughput_in_kbps=throughput_in,
                throughput_out_kbps=throughput_out,
                packet_loss_percent=packet_loss,
                network_type=_detect_network_type(),
                local_ip=_get_local_ip(),
                obfs_latency_ms=0.0,
                dpi_detected=self._dpi_detected,
                tls_errors=self._tls_errors,
                dns_resolve_ms=dns_ms,
                download_speed_kbps=download_kbps,
                upload_speed_kbps=upload_kbps,
            )

        return report

    def _send(self, report: TelemetryReport) -> bool:
        """Send report to server. Returns True on success."""
        url = self._config.server_url.rstrip("/") + "/api/v1/telemetry"
        data = json.dumps(asdict(report)).encode()

        try:
            req = urllib.request.Request(
                url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            resp = urllib.request.urlopen(req, timeout=self._config.send_timeout)
            status = resp.getcode()
            resp.close()
            if status == 200:
                self._log.debug("telemetry_sent", device=self._device_id)
                return True
            self._log.warning("telemetry_send_failed", status=status)
            return False
        except Exception as e:
            self._log.warning("telemetry_send_error", error=str(e))
            return False


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def create_telemetry_collector(
    server_url: str,
    get_vpn_state: Optional[Callable] = None,
    interval: float = 300.0,
    app_version: str = "1.0.0",
) -> TelemetryCollector:
    """Create a TelemetryCollector with sensible defaults."""
    config = TelemetryConfig(
        server_url=server_url,
        collect_interval=interval,
        app_version=app_version,
    )
    return TelemetryCollector(config, get_vpn_state=get_vpn_state)
