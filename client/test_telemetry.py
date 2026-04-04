"""Tests for telemetry.py — client-side diagnostic telemetry."""

import json
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from unittest.mock import patch, MagicMock

import pytest

from telemetry import (
    TelemetryReport,
    TelemetryConfig,
    TelemetryCollector,
    _generate_device_id,
    _detect_platform,
    _get_local_ip,
    measure_tcp_ping,
    create_telemetry_collector,
)


# ---------------------------------------------------------------------------
# Device ID tests
# ---------------------------------------------------------------------------

class TestDeviceID:
    def test_generate_device_id_stable(self):
        """Same machine should produce same ID."""
        id1 = _generate_device_id()
        id2 = _generate_device_id()
        assert id1 == id2
        assert len(id1) == 16

    def test_device_id_is_hex(self):
        id1 = _generate_device_id()
        int(id1, 16)  # should not raise


# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------

class TestPlatform:
    def test_detect_platform(self):
        result = _detect_platform()
        assert result in ("macos", "linux", "windows")

    @patch("telemetry.platform.system", return_value="Darwin")
    def test_detect_macos(self, mock_sys):
        assert _detect_platform() == "macos"

    @patch("telemetry.platform.system", return_value="Linux")
    def test_detect_linux(self, mock_sys):
        assert _detect_platform() == "linux"


# ---------------------------------------------------------------------------
# Local IP
# ---------------------------------------------------------------------------

class TestLocalIP:
    def test_get_local_ip_masked(self):
        ip = _get_local_ip()
        if ip:
            assert ip.endswith(".x"), f"Expected masked IP, got {ip}"

    @patch("telemetry.socket.socket")
    def test_get_local_ip_failure(self, mock_socket):
        mock_socket.side_effect = OSError("no network")
        assert _get_local_ip() == ""


# ---------------------------------------------------------------------------
# TCP ping
# ---------------------------------------------------------------------------

class TestTCPPing:
    def test_ping_unreachable(self):
        """Unreachable host should return 0."""
        ms = measure_tcp_ping("192.0.2.1", 1, timeout=0.5)
        assert ms == 0.0

    def test_ping_localhost(self):
        """Ping a local listener."""
        import socket
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        port = s.getsockname()[1]

        ms = measure_tcp_ping("127.0.0.1", port, timeout=2.0)
        s.close()
        assert ms > 0
        assert ms < 1000  # should be < 1s for localhost


# ---------------------------------------------------------------------------
# TelemetryReport
# ---------------------------------------------------------------------------

class TestTelemetryReport:
    def test_default_values(self):
        r = TelemetryReport()
        assert r.device_id == ""
        assert r.bytes_in == 0
        assert r.dpi_detected is False

    def test_custom_values(self):
        r = TelemetryReport(
            device_id="abc",
            platform="android",
            ping_ms=42.5,
            throughput_in_kbps=1500.0,
        )
        assert r.device_id == "abc"
        assert r.ping_ms == 42.5

    def test_serializable(self):
        r = TelemetryReport(device_id="x", platform="ios")
        from dataclasses import asdict
        d = asdict(r)
        s = json.dumps(d)
        parsed = json.loads(s)
        assert parsed["device_id"] == "x"
        assert parsed["platform"] == "ios"


# ---------------------------------------------------------------------------
# TelemetryCollector
# ---------------------------------------------------------------------------

class TestCollector:
    def test_create(self):
        cfg = TelemetryConfig(server_url="http://localhost:8080")
        tc = TelemetryCollector(cfg)
        assert tc._device_id  # auto-generated
        assert tc._platform in ("macos", "linux", "windows")

    def test_update_bytes(self):
        cfg = TelemetryConfig(server_url="http://localhost:8080")
        tc = TelemetryCollector(cfg)
        tc.update_bytes(1000, 500)
        assert tc._bytes_in == 1000
        assert tc._bytes_out == 500

    def test_record_handshake(self):
        cfg = TelemetryConfig(server_url="http://localhost:8080")
        tc = TelemetryCollector(cfg)
        tc.record_handshake(150.5)
        assert tc._handshake_ms == 150.5

    def test_record_reconnect(self):
        cfg = TelemetryConfig(server_url="http://localhost:8080")
        tc = TelemetryCollector(cfg)
        tc.record_reconnect()
        tc.record_reconnect()
        assert tc._reconnect_count == 2

    def test_record_connect_disconnect(self):
        cfg = TelemetryConfig(server_url="http://localhost:8080")
        tc = TelemetryCollector(cfg)
        tc.record_connect()
        assert tc._connected_since is not None
        tc.record_disconnect()
        assert tc._connected_since is None

    def test_record_tls_error(self):
        cfg = TelemetryConfig(server_url="http://localhost:8080")
        tc = TelemetryCollector(cfg)
        tc.record_tls_error()
        assert tc._tls_errors == 1

    def test_record_dpi(self):
        cfg = TelemetryConfig(server_url="http://localhost:8080")
        tc = TelemetryCollector(cfg)
        tc.record_dpi_detection()
        assert tc._dpi_detected is True


class TestCollectorCollect:
    def test_collect_basic(self):
        cfg = TelemetryConfig(
            server_url="http://localhost:8080",
            app_version="2.0.0",
            device_id="testdev",
        )
        tc = TelemetryCollector(cfg)
        tc.update_bytes(5000, 3000)
        tc.record_handshake(100.0)
        tc.record_connect()
        time.sleep(0.05)  # ensure measurable uptime

        report = tc.collect_now()
        assert report.device_id == "testdev"
        assert report.bytes_in == 5000
        assert report.bytes_out == 3000
        assert report.handshake_ms == 100.0
        assert report.uptime_sec > 0
        assert report.app_version == "2.0.0"
        assert report.timestamp  # non-empty

    def test_collect_with_state_callback(self):
        def get_state():
            return {
                "state": "connected",
                "server_addr": "127.0.0.1:9999",
            }

        cfg = TelemetryConfig(
            server_url="http://localhost:8080",
            device_id="dev1",
        )
        tc = TelemetryCollector(cfg, get_vpn_state=get_state)
        report = tc.collect_now()
        assert report.connection_state == "connected"
        assert report.server_addr == "127.0.0.1:9999"

    def test_throughput_calculation(self):
        cfg = TelemetryConfig(
            server_url="http://localhost:8080",
            device_id="dev1",
        )
        tc = TelemetryCollector(cfg)
        tc.update_bytes(0, 0)
        tc._prev_sample_time = time.time() - 5  # 5 seconds ago
        tc._prev_bytes_in = 0
        tc._prev_bytes_out = 0
        tc.update_bytes(62500, 12500)  # 500kbit in, 100kbit out over 5s

        report = tc.collect_now()
        assert report.throughput_in_kbps > 0
        assert report.throughput_out_kbps > 0

    def test_jitter_calculation(self):
        cfg = TelemetryConfig(
            server_url="http://localhost:8080",
            device_id="dev1",
        )
        tc = TelemetryCollector(cfg)
        tc._ping_history = [10.0, 20.0, 15.0, 25.0]

        # Mock ping to return a value.
        with patch("telemetry.measure_tcp_ping", return_value=30.0):
            tc._get_vpn_state = lambda: {"server_addr": "1.2.3.4:443"}
            report = tc.collect_now()
            assert report.jitter_ms > 0


# ---------------------------------------------------------------------------
# Send tests (with local HTTP server)
# ---------------------------------------------------------------------------

class _TelemetryHandler(BaseHTTPRequestHandler):
    received = []

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        _TelemetryHandler.received.append(json.loads(body))
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status":"ok"}')

    def log_message(self, *args):
        pass  # suppress output


class TestCollectorSend:
    def test_send_to_server(self):
        _TelemetryHandler.received = []
        server = HTTPServer(("127.0.0.1", 0), _TelemetryHandler)
        port = server.server_address[1]
        t = threading.Thread(target=server.handle_request, daemon=True)
        t.start()

        cfg = TelemetryConfig(
            server_url=f"http://127.0.0.1:{port}",
            device_id="sendtest",
        )
        tc = TelemetryCollector(cfg)
        tc.update_bytes(100, 50)

        ok = tc.send_now()
        assert ok is True
        t.join(timeout=2)
        server.server_close()

        assert len(_TelemetryHandler.received) == 1
        data = _TelemetryHandler.received[0]
        assert data["device_id"] == "sendtest"
        assert data["bytes_in"] == 100

    def test_send_failure(self):
        cfg = TelemetryConfig(
            server_url="http://127.0.0.1:1",  # unreachable
            device_id="fail",
            send_timeout=0.5,
        )
        tc = TelemetryCollector(cfg)
        ok = tc.send_now()
        assert ok is False


# ---------------------------------------------------------------------------
# Start/stop lifecycle
# ---------------------------------------------------------------------------

class TestCollectorLifecycle:
    def test_start_stop(self):
        cfg = TelemetryConfig(
            server_url="http://127.0.0.1:1",
            collect_interval=0.1,
            device_id="lifecycle",
        )
        tc = TelemetryCollector(cfg)
        tc.start()
        assert tc._thread is not None
        assert tc._thread.is_alive()
        tc.stop()
        assert not tc._thread.is_alive() if tc._thread else True

    def test_double_start(self):
        cfg = TelemetryConfig(
            server_url="http://127.0.0.1:1",
            collect_interval=60,
            device_id="double",
        )
        tc = TelemetryCollector(cfg)
        tc.start()
        thread1 = tc._thread
        tc.start()  # should not create a second thread
        assert tc._thread is thread1
        tc.stop()


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

class TestFactory:
    def test_create_telemetry_collector(self):
        tc = create_telemetry_collector(
            server_url="http://localhost:8080",
            interval=60,
            app_version="3.0.0",
        )
        assert isinstance(tc, TelemetryCollector)
        assert tc._config.collect_interval == 60
        assert tc._config.app_version == "3.0.0"
