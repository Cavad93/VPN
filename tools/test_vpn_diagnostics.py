#!/usr/bin/env python3
"""Tests for vpn_diagnostics.py — no real API calls."""

import json
import os
import sys
import tempfile
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
import unittest

# Add tools dir to path
sys.path.insert(0, os.path.dirname(__file__))

from vpn_diagnostics import (
    collect_server_metrics,
    collect_client_metrics,
    save_report,
    load_last_report,
    RateLimiter,
    fetch_json,
)


# ---------------------------------------------------------------------------
# Mock HTTP server
# ---------------------------------------------------------------------------

MOCK_PERF = {
    "timestamp": "2026-04-03T12:00:00Z",
    "stages": {
        "noise_encrypt": {"latency": {"count": 100, "mean_us": 5.2, "p50_us": 4.0, "p95_us": 8.0, "p99_us": 12.0, "max_us": 50.0}, "packets": 100, "bytes": 150000},
        "tun_read": {"latency": {"count": 100, "mean_us": 80.0, "p50_us": 60.0, "p95_us": 150.0, "p99_us": 300.0, "max_us": 1000.0}, "packets": 100, "bytes": 150000},
    },
    "active_sessions": 2,
    "total_sessions": 10,
    "retransmit_count": 5,
    "congestion_window": 32,
    "ssthresh": 16,
}

MOCK_SESSIONS = [
    {"id": 1, "assigned_ip": "10.8.0.2", "bytes_in": 1000000, "bytes_out": 2000000}
]

MOCK_HEALTH = {"status": "ok"}


class MockAPIHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/api/v1/perf":
            self._json_response(MOCK_PERF)
        elif self.path == "/api/v1/sessions":
            self._json_response(MOCK_SESSIONS)
        elif self.path == "/api/v1/health":
            self._json_response(MOCK_HEALTH)
        elif self.path == "/api/v1/stats":
            self._json_response({"total_bytes_in": 5000000, "total_bytes_out": 10000000})
        elif self.path == "/perf":
            self._json_response({"stages": {"noise_encrypt": {"latency": {"count": 50}}}})
        else:
            self.send_error(404)

    def _json_response(self, data):
        body = json.dumps(data).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def start_mock_server():
    server = HTTPServer(("127.0.0.1", 0), MockAPIHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestFetchJson(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = start_mock_server()
        cls.port = cls.server.server_address[1]
        cls.base = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def test_fetch_health(self):
        data = fetch_json(f"{self.base}/api/v1/health")
        self.assertEqual(data["status"], "ok")

    def test_fetch_perf(self):
        data = fetch_json(f"{self.base}/api/v1/perf")
        self.assertIn("stages", data)
        self.assertEqual(data["active_sessions"], 2)

    def test_fetch_404(self):
        data = fetch_json(f"{self.base}/nonexistent")
        self.assertIsNone(data)

    def test_fetch_unreachable(self):
        data = fetch_json("http://127.0.0.1:1/nope")
        self.assertIsNone(data)


class TestCollectMetrics(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = start_mock_server()
        cls.port = cls.server.server_address[1]
        cls.base = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def test_collect_server_metrics(self):
        metrics = collect_server_metrics(self.base)
        self.assertIn("perf", metrics)
        self.assertIn("sessions", metrics)
        self.assertIn("health", metrics)
        self.assertEqual(metrics["perf"]["active_sessions"], 2)

    def test_collect_client_metrics(self):
        metrics = collect_client_metrics(self.base)
        self.assertIsNotNone(metrics)
        self.assertIn("stages", metrics)

    def test_collect_client_metrics_unreachable(self):
        metrics = collect_client_metrics("http://127.0.0.1:1")
        self.assertIsNone(metrics)


class TestReportIO(unittest.TestCase):
    def test_save_and_load(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            path = f.name

        try:
            report1 = {"timestamp": "t1", "analysis": "first"}
            report2 = {"timestamp": "t2", "analysis": "second"}
            save_report(report1, path)
            save_report(report2, path)

            last = load_last_report(path)
            self.assertIsNotNone(last)
            self.assertEqual(last["analysis"], "second")
        finally:
            os.unlink(path)

    def test_load_nonexistent(self):
        last = load_last_report("/tmp/nonexistent_vpn_report_xyz.jsonl")
        self.assertIsNone(last)

    def test_load_empty_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            path = f.name
        try:
            last = load_last_report(path)
            self.assertIsNone(last)
        finally:
            os.unlink(path)


class TestRateLimiter(unittest.TestCase):
    def test_first_call_immediate(self):
        rl = RateLimiter(3600)  # 1 per second
        t0 = __import__("time").monotonic()
        rl.wait()
        elapsed = __import__("time").monotonic() - t0
        self.assertLess(elapsed, 1.0)

    def test_rate_limiting(self):
        rl = RateLimiter(3600)  # 1 per second
        rl.wait()  # first call — immediate
        t0 = __import__("time").monotonic()
        rl.wait()  # second call — should wait ~1s
        elapsed = __import__("time").monotonic() - t0
        self.assertGreater(elapsed, 0.8)


if __name__ == "__main__":
    unittest.main()
