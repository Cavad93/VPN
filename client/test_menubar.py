"""
test_menubar.py — Unit tests for menubar.py (pure-Python domain model).

All tests run without macOS / PyObjC by testing VPNStatusModel, TrafficStats,
and VPNStatus directly.  The PyObjC NSObject subclasses are exercised only in
manual integration tests on a macOS machine.
"""

from __future__ import annotations

import threading
import time
from dataclasses import replace
from unittest.mock import MagicMock, patch

import pytest

from menubar import TrafficStats, VPNStatus, VPNStatusModel


# ---------------------------------------------------------------------------
# TrafficStats
# ---------------------------------------------------------------------------


class TestTrafficStatsFormatBytes:
    def test_bytes(self):
        assert TrafficStats.format_bytes(0) == "0.0 B"
        assert TrafficStats.format_bytes(1023) == "1023.0 B"

    def test_kilobytes(self):
        assert TrafficStats.format_bytes(1024) == "1.0 KB"
        assert TrafficStats.format_bytes(1536) == "1.5 KB"

    def test_megabytes(self):
        assert TrafficStats.format_bytes(1024 * 1024) == "1.0 MB"
        assert TrafficStats.format_bytes(int(1.5 * 1024 * 1024)) == "1.5 MB"

    def test_gigabytes(self):
        assert TrafficStats.format_bytes(1024 ** 3) == "1.0 GB"

    def test_terabytes(self):
        assert TrafficStats.format_bytes(1024 ** 4) == "1.0 TB"

    def test_large_value(self):
        result = TrafficStats.format_bytes(5 * 1024 * 1024 * 1024)
        assert result == "5.0 GB"


class TestTrafficStatsLabels:
    def test_ingress_label(self):
        s = TrafficStats(bytes_in=2048)
        assert "↓" in s.ingress_label
        assert "2.0 KB" in s.ingress_label

    def test_egress_label(self):
        s = TrafficStats(bytes_out=512)
        assert "↑" in s.egress_label
        assert "512.0 B" in s.egress_label

    def test_labels_zero(self):
        s = TrafficStats()
        assert "0.0 B" in s.ingress_label
        assert "0.0 B" in s.egress_label


class TestTrafficStatsUptime:
    def test_uptime_none_when_not_connected(self):
        s = TrafficStats()
        assert s.uptime == ""

    def test_uptime_seconds(self):
        s = TrafficStats()
        s.connected_since = time.monotonic() - 45
        assert s.uptime == "00:45"

    def test_uptime_minutes(self):
        s = TrafficStats()
        s.connected_since = time.monotonic() - 125  # 2m 5s
        assert s.uptime == "02:05"

    def test_uptime_hours(self):
        s = TrafficStats()
        s.connected_since = time.monotonic() - 3665  # 1h 1m 5s
        assert s.uptime == "01:01:05"

    def test_uptime_monotonically_increases(self):
        s = TrafficStats()
        s.connected_since = time.monotonic() - 10
        first = s.uptime
        time.sleep(0.05)
        second = s.uptime
        # Both should be parseable; second >= first
        assert second >= first


class TestTrafficStatsReset:
    def test_reset_clears_all_fields(self):
        s = TrafficStats(
            bytes_in=999,
            bytes_out=888,
            connected_since=time.monotonic() - 100,
            server_ip="1.2.3.4",
            assigned_ip="10.8.0.2",
        )
        s.reset()
        assert s.bytes_in == 0
        assert s.bytes_out == 0
        assert s.connected_since is None
        assert s.server_ip == ""
        assert s.assigned_ip == ""


# ---------------------------------------------------------------------------
# VPNStatusModel — status transitions
# ---------------------------------------------------------------------------


class TestVPNStatusModelInitial:
    def test_initial_status_is_disconnected(self):
        m = VPNStatusModel()
        assert m.status == VPNStatus.DISCONNECTED

    def test_initial_can_connect(self):
        m = VPNStatusModel()
        assert m.can_connect() is True

    def test_initial_cannot_disconnect(self):
        m = VPNStatusModel()
        assert m.can_disconnect() is False


class TestVPNStatusModelTransitions:
    def test_set_status_connecting(self):
        m = VPNStatusModel()
        m.set_status(VPNStatus.CONNECTING)
        assert m.status == VPNStatus.CONNECTING

    def test_set_status_connected(self):
        m = VPNStatusModel()
        m.set_status(VPNStatus.CONNECTED)
        assert m.status == VPNStatus.CONNECTED
        assert m.can_disconnect() is True
        assert m.can_connect() is False

    def test_set_status_disconnected(self):
        m = VPNStatusModel()
        m.set_status(VPNStatus.CONNECTED)
        m.set_status(VPNStatus.DISCONNECTED)
        assert m.status == VPNStatus.DISCONNECTED
        assert m.can_connect() is True

    def test_set_status_error(self):
        m = VPNStatusModel()
        m.set_status(VPNStatus.ERROR)
        assert m.status == VPNStatus.ERROR
        assert m.can_connect() is True

    def test_set_status_disconnecting(self):
        m = VPNStatusModel()
        m.set_status(VPNStatus.CONNECTED)
        m.set_status(VPNStatus.DISCONNECTING)
        assert m.can_connect() is False
        assert m.can_disconnect() is False

    def test_full_lifecycle(self):
        m = VPNStatusModel()
        states = [
            VPNStatus.CONNECTING,
            VPNStatus.CONNECTED,
            VPNStatus.DISCONNECTING,
            VPNStatus.DISCONNECTED,
        ]
        for s in states:
            m.set_status(s)
            assert m.status == s


class TestVPNStatusModelCallbacks:
    def test_status_callback_called_on_change(self):
        m = VPNStatusModel()
        received: list[VPNStatus] = []
        m.on_status_change(received.append)

        m.set_status(VPNStatus.CONNECTING)
        m.set_status(VPNStatus.CONNECTED)

        assert received == [VPNStatus.CONNECTING, VPNStatus.CONNECTED]

    def test_multiple_status_callbacks(self):
        m = VPNStatusModel()
        cb1_results: list[VPNStatus] = []
        cb2_results: list[VPNStatus] = []
        m.on_status_change(cb1_results.append)
        m.on_status_change(cb2_results.append)

        m.set_status(VPNStatus.CONNECTED)
        assert cb1_results == [VPNStatus.CONNECTED]
        assert cb2_results == [VPNStatus.CONNECTED]

    def test_stats_callback_called_on_update(self):
        m = VPNStatusModel()
        received: list[TrafficStats] = []
        m.on_stats_update(received.append)

        m.update_traffic(1024, 512)
        assert len(received) == 1
        assert received[0].bytes_in == 1024
        assert received[0].bytes_out == 512

    def test_status_callback_exception_is_swallowed(self):
        """A callback that raises must not break subsequent callbacks."""
        m = VPNStatusModel()
        second_called: list[bool] = []

        def bad_cb(s: VPNStatus) -> None:
            raise RuntimeError("deliberate error")

        m.on_status_change(bad_cb)
        m.on_status_change(lambda _: second_called.append(True))

        # Should not raise despite bad_cb
        m.set_status(VPNStatus.CONNECTED)
        assert second_called == [True]

    def test_stats_callback_exception_is_swallowed(self):
        m = VPNStatusModel()
        second_called: list[bool] = []

        def bad_cb(s: TrafficStats) -> None:
            raise RuntimeError("boom")

        m.on_stats_update(bad_cb)
        m.on_stats_update(lambda _: second_called.append(True))

        m.update_traffic(0, 0)
        assert second_called == [True]


class TestVPNStatusModelTraffic:
    def test_update_traffic(self):
        m = VPNStatusModel()
        m.update_traffic(2048, 1024)
        s = m.stats
        assert s.bytes_in == 2048
        assert s.bytes_out == 1024

    def test_update_traffic_cumulative(self):
        m = VPNStatusModel()
        m.update_traffic(100, 50)
        m.update_traffic(200, 100)
        s = m.stats
        assert s.bytes_in == 200
        assert s.bytes_out == 100

    def test_stats_returns_snapshot(self):
        m = VPNStatusModel()
        m.update_traffic(10, 5)
        snap1 = m.stats
        m.update_traffic(20, 10)
        snap2 = m.stats
        # snap1 should be independent of snap2
        assert snap1.bytes_in == 10
        assert snap2.bytes_in == 20


class TestVPNStatusModelServerInfo:
    def test_set_server_info(self):
        m = VPNStatusModel()
        m.set_server_info("1.2.3.4", "10.8.0.5")
        s = m.stats
        assert s.server_ip == "1.2.3.4"
        assert s.assigned_ip == "10.8.0.5"
        assert s.connected_since is not None

    def test_clear_server_info(self):
        m = VPNStatusModel()
        m.set_server_info("1.2.3.4", "10.8.0.5")
        m.update_traffic(999, 777)
        m.clear_server_info()
        s = m.stats
        assert s.bytes_in == 0
        assert s.bytes_out == 0
        assert s.server_ip == ""
        assert s.assigned_ip == ""
        assert s.connected_since is None


# ---------------------------------------------------------------------------
# VPNStatusModel — UI helpers
# ---------------------------------------------------------------------------


class TestVPNStatusModelUIHelpers:
    @pytest.mark.parametrize(
        "status,expected",
        [
            (VPNStatus.DISCONNECTED, "Disconnected"),
            (VPNStatus.CONNECTING, "Connecting\u2026"),
            (VPNStatus.CONNECTED, "Connected"),
            (VPNStatus.DISCONNECTING, "Disconnecting\u2026"),
            (VPNStatus.ERROR, "Error"),
        ],
    )
    def test_status_label(self, status: VPNStatus, expected: str):
        m = VPNStatusModel()
        m.set_status(status)
        assert m.status_label() == expected

    @pytest.mark.parametrize(
        "status,symbol",
        [
            (VPNStatus.CONNECTED, "\U0001f512"),      # 🔒
            (VPNStatus.CONNECTING, "\u23f3"),         # ⏳
            (VPNStatus.DISCONNECTING, "\u23f3"),      # ⏳
            (VPNStatus.ERROR, "\u26a0\ufe0f"),        # ⚠️
            (VPNStatus.DISCONNECTED, "\U0001f513"),   # 🔓
        ],
    )
    def test_menu_bar_title(self, status: VPNStatus, symbol: str):
        m = VPNStatusModel()
        m.set_status(status)
        assert m.menu_bar_title() == symbol


# ---------------------------------------------------------------------------
# Thread-safety smoke test
# ---------------------------------------------------------------------------


class TestVPNStatusModelThreadSafety:
    def test_concurrent_status_updates(self):
        """Many threads updating status should not corrupt state."""
        m = VPNStatusModel()
        errors: list[Exception] = []

        def worker(s: VPNStatus) -> None:
            try:
                for _ in range(50):
                    m.set_status(s)
                    _ = m.status
                    _ = m.status_label()
                    _ = m.menu_bar_title()
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=worker, args=(s,))
            for s in VPNStatus
            for _ in range(3)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        assert errors == [], f"Thread errors: {errors}"

    def test_concurrent_traffic_updates(self):
        m = VPNStatusModel()
        errors: list[Exception] = []

        def updater() -> None:
            try:
                for i in range(100):
                    m.update_traffic(i * 1024, i * 512)
                    _ = m.stats
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=updater) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        assert errors == []


# ---------------------------------------------------------------------------
# run_menubar_app raises on non-macOS
# ---------------------------------------------------------------------------


class TestRunMenubarAppGuard:
    def test_raises_when_pyobjc_unavailable(self):
        """run_menubar_app must raise RuntimeError when PyObjC is not available."""
        import menubar

        original = menubar._PYOBJC_AVAILABLE
        try:
            menubar._PYOBJC_AVAILABLE = False
            with pytest.raises(RuntimeError, match="PyObjC"):
                menubar.run_menubar_app(VPNStatusModel())
        finally:
            menubar._PYOBJC_AVAILABLE = original
