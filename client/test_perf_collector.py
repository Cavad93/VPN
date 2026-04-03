"""Tests for perf_collector module."""
import json
import threading
import time
import urllib.request

import pytest

from perf_collector import (
    PerfCollector, Stage, _Histogram, _percentile, start_perf_server,
    _HIST_BUCKETS, HistogramSnapshot,
)


class TestHistogram:
    def test_empty_snapshot(self):
        h = _Histogram()
        s = h.snapshot()
        assert s.count == 0
        assert s.mean_us == 0.0

    def test_record_and_snapshot(self):
        h = _Histogram()
        h.record(0.000100)  # 100µs
        h.record(0.000200)  # 200µs
        h.record(0.000300)  # 300µs
        s = h.snapshot()
        assert s.count == 3
        assert 100 <= s.mean_us <= 400
        assert s.max_us >= 200

    def test_reset(self):
        h = _Histogram()
        h.record(0.001)
        h.reset()
        s = h.snapshot()
        assert s.count == 0

    def test_percentiles(self):
        h = _Histogram()
        for _ in range(500):
            h.record(0.000100)  # 100µs
        for _ in range(450):
            h.record(0.001)  # 1ms
        for _ in range(50):
            h.record(0.050)  # 50ms
        s = h.snapshot()
        assert s.count == 1000
        assert s.p50_us < 2000
        assert s.p99_us > 100


class TestPerfCollector:
    def test_track_latency(self):
        pc = PerfCollector()
        pc.track_latency(Stage.NOISE_ENCRYPT, 0.0001)
        snap = pc.snapshot()
        assert snap["stages"]["noise_encrypt"]["latency"]["count"] == 1

    def test_track_packet(self):
        pc = PerfCollector()
        pc.track_packet(Stage.TUN_READ, 1500)
        pc.track_packet(Stage.TUN_READ, 500)
        snap = pc.snapshot()
        assert snap["stages"]["tun_read"]["packets"] == 2
        assert snap["stages"]["tun_read"]["bytes"] == 2000

    def test_timer_context_manager(self):
        pc = PerfCollector()
        with pc.timer(Stage.OBFS_WRITE):
            time.sleep(0.001)
        snap = pc.snapshot()
        assert snap["stages"]["obfs_write"]["latency"]["count"] == 1
        assert snap["stages"]["obfs_write"]["latency"]["mean_us"] > 500

    def test_track_shaping_delay(self):
        pc = PerfCollector()
        pc.track_shaping_delay(10.5)
        pc.track_shaping_delay(5.0)
        snap = pc.snapshot()
        assert snap["shaping_delay_total_ms"] == pytest.approx(15.5)

    def test_track_padding(self):
        pc = PerfCollector()
        pc.track_padding(1000, 1200)
        snap = pc.snapshot()
        assert snap["padding_overhead_pct"] == pytest.approx(20.0)

    def test_track_cover_traffic(self):
        pc = PerfCollector()
        pc.track_cover_traffic(100)
        pc.track_cover_traffic(200)
        snap = pc.snapshot()
        assert snap["cover_traffic_bytes"] == 300

    def test_track_reconnect(self):
        pc = PerfCollector()
        pc.track_reconnect()
        pc.track_reconnect()
        snap = pc.snapshot()
        assert snap["reconnect_count"] == 2

    def test_reset(self):
        pc = PerfCollector()
        pc.track_latency(Stage.NOISE_ENCRYPT, 0.001)
        pc.track_packet(Stage.TUN_READ, 1000)
        pc.track_shaping_delay(10.0)
        pc.track_cover_traffic(500)
        pc.track_reconnect()
        pc.reset()
        snap = pc.snapshot()
        assert snap["stages"]["noise_encrypt"]["latency"]["count"] == 0
        assert snap["stages"]["tun_read"]["packets"] == 0
        assert snap["shaping_delay_total_ms"] == 0.0
        assert snap["cover_traffic_bytes"] == 0
        assert snap["reconnect_count"] == 0

    def test_snapshot_json_serializable(self):
        pc = PerfCollector()
        pc.track_latency(Stage.NOISE_ENCRYPT, 0.0001)
        snap = pc.snapshot()
        data = json.dumps(snap)
        assert len(data) > 0
        decoded = json.loads(data)
        assert "stages" in decoded
        assert "timestamp" in decoded

    def test_unknown_stage_ignored(self):
        pc = PerfCollector()
        # Should not raise.
        pc.track_latency("nonexistent", 0.001)
        pc.track_packet("nonexistent", 100)

    def test_concurrent_access(self):
        pc = PerfCollector()
        errors = []

        def worker():
            try:
                for _ in range(1000):
                    pc.track_latency(Stage.NOISE_ENCRYPT, 0.0001)
                    pc.track_packet(Stage.TUN_READ, 100)
                    pc.track_shaping_delay(0.1)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        snap = pc.snapshot()
        assert snap["stages"]["noise_encrypt"]["latency"]["count"] == 10000
        assert snap["stages"]["tun_read"]["packets"] == 10000

    def test_all_stages_present(self):
        pc = PerfCollector()
        snap = pc.snapshot()
        for s in Stage:
            assert s.value in snap["stages"]


class TestPerfServer:
    def test_get_perf(self):
        pc = PerfCollector()
        pc.track_latency(Stage.NOISE_ENCRYPT, 0.001)
        srv = start_perf_server(pc, port=0)
        port = srv.server_address[1]
        try:
            resp = urllib.request.urlopen(f"http://127.0.0.1:{port}/perf")
            data = json.loads(resp.read())
            assert data["stages"]["noise_encrypt"]["latency"]["count"] == 1
        finally:
            srv.shutdown()

    def test_post_reset(self):
        pc = PerfCollector()
        pc.track_latency(Stage.NOISE_ENCRYPT, 0.001)
        srv = start_perf_server(pc, port=0)
        port = srv.server_address[1]
        try:
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/perf/reset", method="POST", data=b""
            )
            resp = urllib.request.urlopen(req)
            data = json.loads(resp.read())
            assert data["status"] == "reset"
            assert pc.snapshot()["stages"]["noise_encrypt"]["latency"]["count"] == 0
        finally:
            srv.shutdown()

    def test_404(self):
        pc = PerfCollector()
        srv = start_perf_server(pc, port=0)
        port = srv.server_address[1]
        try:
            with pytest.raises(urllib.error.HTTPError) as exc_info:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/nonexistent")
            assert exc_info.value.code == 404
        finally:
            srv.shutdown()
