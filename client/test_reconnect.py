"""
test_reconnect.py — Unit tests for reconnect.py.

All network I/O (VPNClient.connect / disconnect) is mocked so tests run
without a real VPN server.
"""

from __future__ import annotations

import threading
import time
from typing import Optional
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

import reconnect as rc_mod
from reconnect import (
    AutoReconnect,
    ConnectionState,
    ExponentialBackoff,
    HealthChecker,
    ReconnectConfig,
    create_auto_reconnect,
)
from core import RouteInfo, VPNConfig


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_route() -> RouteInfo:
    return RouteInfo(
        assigned_ip="10.8.0.2",
        prefix_len=24,
        gateway="10.8.0.1",
        server_public_key=b"\x00" * 32,
    )


def _make_vpn_config() -> VPNConfig:
    return VPNConfig(server_addr="127.0.0.1:4443")


def _make_mock_client(route: Optional[RouteInfo] = None, connect_exc=None):
    """Return a MagicMock that mimics VPNClient."""
    client = MagicMock()
    if connect_exc is not None:
        client.connect.side_effect = connect_exc
    else:
        client.connect.return_value = route or _make_route()

    # Make _connected behave like a threading.Event
    connected_evt = threading.Event()
    connected_evt.set()
    client._connected = connected_evt

    # Mux mock — not closed by default
    mux = MagicMock()
    mux._closed = threading.Event()  # not set = alive
    client._mux = mux

    # Data stream mock
    stream = MagicMock()
    stream._closed = threading.Event()
    client._data_stream = stream

    return client


# ---------------------------------------------------------------------------
# ExponentialBackoff
# ---------------------------------------------------------------------------


class TestExponentialBackoff:
    def test_initial_delay(self):
        bo = ExponentialBackoff(initial_delay=1.0, factor=2.0, jitter=0.0)
        assert bo.next_delay() == pytest.approx(1.0)

    def test_doubles_each_attempt(self):
        bo = ExponentialBackoff(initial_delay=1.0, max_delay=100.0, factor=2.0, jitter=0.0)
        delays = [bo.next_delay() for _ in range(5)]
        assert delays == pytest.approx([1.0, 2.0, 4.0, 8.0, 16.0])

    def test_capped_at_max(self):
        bo = ExponentialBackoff(initial_delay=10.0, max_delay=30.0, factor=2.0, jitter=0.0)
        delays = [bo.next_delay() for _ in range(4)]
        assert delays == pytest.approx([10.0, 20.0, 30.0, 30.0])

    def test_reset_restarts_from_initial(self):
        bo = ExponentialBackoff(initial_delay=1.0, max_delay=100.0, factor=2.0, jitter=0.0)
        bo.next_delay()
        bo.next_delay()
        bo.reset()
        assert bo.next_delay() == pytest.approx(1.0)

    def test_jitter_within_bounds(self):
        bo = ExponentialBackoff(initial_delay=10.0, max_delay=100.0, factor=1.0, jitter=0.2)
        for _ in range(20):
            d = bo.next_delay()
            assert 8.0 <= d <= 12.0, d

    def test_attempt_counter(self):
        bo = ExponentialBackoff(initial_delay=1.0)
        assert bo.attempt == 0
        bo.next_delay()
        assert bo.attempt == 1
        bo.reset()
        assert bo.attempt == 0

    def test_invalid_initial_delay(self):
        with pytest.raises(ValueError):
            ExponentialBackoff(initial_delay=0)

    def test_invalid_max_delay(self):
        with pytest.raises(ValueError):
            ExponentialBackoff(initial_delay=10.0, max_delay=5.0)

    def test_invalid_factor(self):
        with pytest.raises(ValueError):
            ExponentialBackoff(factor=0.5)

    def test_invalid_jitter(self):
        with pytest.raises(ValueError):
            ExponentialBackoff(jitter=1.5)

    def test_zero_jitter(self):
        bo = ExponentialBackoff(initial_delay=5.0, jitter=0.0, factor=1.0)
        assert bo.next_delay() == pytest.approx(5.0)


# ---------------------------------------------------------------------------
# HealthChecker
# ---------------------------------------------------------------------------


class TestHealthChecker:
    def _make_checker(self, client, interval=0.05, timeout=1.0):
        fail_exc: list[Exception] = []
        fail_event = threading.Event()

        def on_failure(exc):
            fail_exc.append(exc)
            fail_event.set()

        checker = HealthChecker(client, interval=interval, timeout=timeout, on_failure=on_failure)
        return checker, fail_exc, fail_event

    def test_healthy_client_no_callback(self):
        client = _make_mock_client()
        checker, fail_exc, fail_event = self._make_checker(client, interval=0.05)
        checker.start()
        triggered = fail_event.wait(timeout=0.3)
        checker.stop()
        assert not triggered
        assert fail_exc == []

    def test_disconnected_client_triggers_failure(self):
        client = _make_mock_client()
        client._connected.clear()  # simulate disconnect
        checker, fail_exc, fail_event = self._make_checker(client, interval=0.05)
        checker.start()
        triggered = fail_event.wait(timeout=0.5)
        checker.stop()
        assert triggered
        assert len(fail_exc) >= 1
        assert isinstance(fail_exc[0], ConnectionError)

    def test_closed_mux_triggers_failure(self):
        client = _make_mock_client()
        client._mux._closed.set()  # simulate mux closing
        checker, fail_exc, fail_event = self._make_checker(client, interval=0.05)
        checker.start()
        triggered = fail_event.wait(timeout=0.5)
        checker.stop()
        assert triggered

    def test_closed_data_stream_triggers_failure(self):
        client = _make_mock_client()
        client._data_stream._closed.set()  # simulate stream closing
        checker, fail_exc, fail_event = self._make_checker(client, interval=0.05)
        checker.start()
        triggered = fail_event.wait(timeout=0.5)
        checker.stop()
        assert triggered

    def test_stop_terminates_loop(self):
        client = _make_mock_client()
        checker, _, _ = self._make_checker(client, interval=0.1)
        checker.start()
        checker.stop()
        # After stop, the thread should no longer be running
        assert checker._thread is None

    def test_null_mux_triggers_failure(self):
        client = _make_mock_client()
        client._mux = None
        checker, fail_exc, fail_event = self._make_checker(client, interval=0.05)
        checker.start()
        triggered = fail_event.wait(timeout=0.5)
        checker.stop()
        assert triggered


# ---------------------------------------------------------------------------
# AutoReconnect — state machine
# ---------------------------------------------------------------------------


class TestAutoReconnectState:
    def _manager(self, connect_side_effect=None, rc_cfg=None):
        cfg = _make_vpn_config()
        if rc_cfg is None:
            rc_cfg = ReconnectConfig(
                initial_delay=0.01,
                max_delay=0.05,
                backoff_factor=2.0,
                jitter=0.0,
                health_check_interval=999.0,  # don't trigger during tests
                max_attempts=0,
            )
        mgr = AutoReconnect(cfg, rc_cfg)
        return mgr

    def test_initial_state_disconnected(self):
        mgr = self._manager()
        assert mgr.state == ConnectionState.DISCONNECTED

    def test_connects_successfully(self):
        mgr = self._manager()
        route = _make_route()
        mock_client = _make_mock_client(route=route)

        with patch("reconnect.VPNClient", return_value=mock_client):
            mgr.start()
            connected = mgr.wait_connected(timeout=3.0)

        assert connected
        assert mgr.state == ConnectionState.CONNECTED
        assert mgr.route_info is not None
        assert mgr.route_info.assigned_ip == "10.8.0.2"
        mgr.stop()

    def test_on_connected_callback(self):
        mgr = self._manager()
        received: list[RouteInfo] = []

        def cb(r):
            received.append(r)

        mgr.on_connected = cb
        mock_client = _make_mock_client()

        with patch("reconnect.VPNClient", return_value=mock_client):
            mgr.start()
            mgr.wait_connected(timeout=3.0)

        assert len(received) == 1
        mgr.stop()

    def test_stop_sets_state_stopped(self):
        mgr = self._manager()
        mock_client = _make_mock_client()

        with patch("reconnect.VPNClient", return_value=mock_client):
            mgr.start()
            mgr.wait_connected(timeout=3.0)
            mgr.stop()

        assert mgr.state == ConnectionState.STOPPED

    def test_stop_before_start(self):
        """stop() on a never-started manager should not raise."""
        mgr = self._manager()
        mgr.stop()  # no exception

    def test_double_start_raises(self):
        mgr = self._manager()
        mock_client = _make_mock_client()

        with patch("reconnect.VPNClient", return_value=mock_client):
            mgr.start()
            mgr.wait_connected(timeout=3.0)
            with pytest.raises(RuntimeError):
                mgr.start()
        mgr.stop()


# ---------------------------------------------------------------------------
# AutoReconnect — retry on failure
# ---------------------------------------------------------------------------


class TestAutoReconnectRetry:
    def _manager(self, rc_cfg=None):
        cfg = _make_vpn_config()
        if rc_cfg is None:
            rc_cfg = ReconnectConfig(
                initial_delay=0.01,
                max_delay=0.05,
                backoff_factor=1.0,
                jitter=0.0,
                health_check_interval=999.0,
                max_attempts=0,
            )
        return AutoReconnect(cfg, rc_cfg)

    def test_retries_after_connection_failure(self):
        """First 2 attempts fail; 3rd succeeds."""
        mgr = self._manager()
        attempt_count = [0]
        route = _make_route()

        def factory(*args, **kwargs):
            attempt_count[0] += 1
            client = _make_mock_client()
            if attempt_count[0] < 3:
                client.connect.side_effect = ConnectionRefusedError("refused")
            else:
                client.connect.return_value = route
                client.connect.side_effect = None
            return client

        with patch("reconnect.VPNClient", side_effect=factory):
            mgr.start()
            connected = mgr.wait_connected(timeout=5.0)

        assert connected
        assert attempt_count[0] >= 3
        mgr.stop()

    def test_on_reconnecting_callback(self):
        mgr = self._manager()
        reconnecting_calls: list[tuple] = []
        attempt_count = [0]

        def factory(*args, **kwargs):
            attempt_count[0] += 1
            client = _make_mock_client()
            if attempt_count[0] == 1:
                client.connect.side_effect = ConnectionRefusedError("refused")
            else:
                client.connect.side_effect = None
                client.connect.return_value = _make_route()
            return client

        mgr.on_reconnecting = lambda a, d: reconnecting_calls.append((a, d))

        with patch("reconnect.VPNClient", side_effect=factory):
            mgr.start()
            mgr.wait_connected(timeout=5.0)

        assert len(reconnecting_calls) >= 1
        mgr.stop()

    def test_max_attempts_stops_manager(self):
        rc_cfg = ReconnectConfig(
            initial_delay=0.01,
            max_delay=0.05,
            backoff_factor=1.0,
            jitter=0.0,
            health_check_interval=999.0,
            max_attempts=3,
        )
        mgr = AutoReconnect(_make_vpn_config(), rc_cfg)
        failed_client = _make_mock_client(
            connect_exc=ConnectionRefusedError("refused")
        )

        with patch("reconnect.VPNClient", return_value=failed_client):
            mgr.start()
            # wait for manager to give up
            for _ in range(50):
                if mgr.state == ConnectionState.STOPPED:
                    break
                time.sleep(0.1)

        assert mgr.state == ConnectionState.STOPPED
        assert failed_client.connect.call_count == 3

    def test_on_disconnected_callback_after_mux_close(self):
        """Simulate mux closing after a successful connection."""
        mgr = self._manager()
        disconnected_calls: list[Optional[Exception]] = []
        stop_event = threading.Event()

        mock_client = _make_mock_client()

        def factory(*args, **kwargs):
            return mock_client

        mgr.on_disconnected = lambda exc: (disconnected_calls.append(exc), stop_event.set())

        with patch("reconnect.VPNClient", side_effect=factory):
            mgr.start()
            mgr.wait_connected(timeout=3.0)
            # Simulate the mux closing
            mock_client._mux._closed.set()
            stop_event.wait(timeout=3.0)

        assert len(disconnected_calls) >= 1
        mgr.stop()

    def test_reconnects_after_mux_close(self):
        """After mux closes, manager should reconnect automatically."""
        mgr = self._manager()
        connected_calls: list[RouteInfo] = []
        first_connected = threading.Event()
        second_connected = threading.Event()

        clients: list[MagicMock] = []

        def factory(*args, **kwargs):
            c = _make_mock_client()
            clients.append(c)
            return c

        def on_connected(route):
            connected_calls.append(route)
            if len(connected_calls) == 1:
                first_connected.set()
            elif len(connected_calls) == 2:
                second_connected.set()

        mgr.on_connected = on_connected

        with patch("reconnect.VPNClient", side_effect=factory):
            mgr.start()
            first_connected.wait(timeout=3.0)
            # Trigger disconnect
            clients[0]._mux._closed.set()
            second_connected.wait(timeout=5.0)

        assert len(connected_calls) >= 2
        mgr.stop()


# ---------------------------------------------------------------------------
# AutoReconnect — health check integration
# ---------------------------------------------------------------------------


class TestAutoReconnectHealthCheck:
    def test_health_check_failure_triggers_reconnect(self):
        rc_cfg = ReconnectConfig(
            initial_delay=0.01,
            max_delay=0.05,
            backoff_factor=1.0,
            jitter=0.0,
            health_check_interval=0.05,  # rapid health checks
            health_check_timeout=1.0,
            max_attempts=0,
        )
        mgr = AutoReconnect(_make_vpn_config(), rc_cfg)
        connected_count = [0]
        second_connected = threading.Event()
        clients: list[MagicMock] = []

        def factory(*args, **kwargs):
            c = _make_mock_client()
            clients.append(c)
            return c

        def on_connected(route):
            connected_count[0] += 1
            if connected_count[0] == 2:
                second_connected.set()

        mgr.on_connected = on_connected

        with patch("reconnect.VPNClient", side_effect=factory):
            mgr.start()
            mgr.wait_connected(timeout=3.0)
            # Disconnect the first client so health check fails
            clients[0]._connected.clear()
            second_connected.wait(timeout=5.0)

        assert connected_count[0] >= 2
        mgr.stop()


# ---------------------------------------------------------------------------
# create_auto_reconnect factory
# ---------------------------------------------------------------------------


class TestCreateAutoReconnect:
    def test_factory_creates_manager(self):
        mgr = create_auto_reconnect("1.2.3.4:443")
        assert isinstance(mgr, AutoReconnect)
        assert mgr.state == ConnectionState.DISCONNECTED

    def test_factory_with_key_file(self):
        mgr = create_auto_reconnect("1.2.3.4:443", private_key_file="/tmp/key.hex")
        assert mgr._vpn_config.private_key_file == "/tmp/key.hex"

    def test_factory_with_custom_rc_config(self):
        rc = ReconnectConfig(max_attempts=5)
        mgr = create_auto_reconnect("1.2.3.4:443", reconnect_config=rc)
        assert mgr._rc_cfg.max_attempts == 5

    def test_factory_custom_timeouts(self):
        mgr = create_auto_reconnect(
            "1.2.3.4:443",
            connect_timeout=15.0,
            read_timeout=45.0,
        )
        assert mgr._vpn_config.connect_timeout == 15.0
        assert mgr._vpn_config.read_timeout == 45.0


# ---------------------------------------------------------------------------
# ReconnectConfig defaults
# ---------------------------------------------------------------------------


class TestReconnectConfig:
    def test_defaults(self):
        cfg = ReconnectConfig()
        assert cfg.initial_delay == 1.0
        assert cfg.max_delay == 60.0
        assert cfg.backoff_factor == 2.0
        assert cfg.jitter == 0.1
        assert cfg.max_attempts == 0
        assert cfg.health_check_interval == 30.0
        assert cfg.health_check_timeout == 10.0

    def test_custom_values(self):
        cfg = ReconnectConfig(
            initial_delay=5.0,
            max_delay=120.0,
            backoff_factor=3.0,
            jitter=0.2,
            max_attempts=10,
            health_check_interval=15.0,
            health_check_timeout=5.0,
        )
        assert cfg.initial_delay == 5.0
        assert cfg.max_attempts == 10


# ---------------------------------------------------------------------------
# wait_connected behaviour
# ---------------------------------------------------------------------------


class TestWaitConnected:
    def test_wait_connected_timeout_returns_false(self):
        mgr = AutoReconnect(
            _make_vpn_config(),
            ReconnectConfig(initial_delay=10.0),
        )
        # Don't start the manager — so it will never connect
        result = mgr.wait_connected(timeout=0.1)
        assert result is False

    def test_wait_connected_returns_true_when_already_connected(self):
        mgr = AutoReconnect(
            _make_vpn_config(),
            ReconnectConfig(
                initial_delay=0.01, health_check_interval=999.0
            ),
        )
        mock_client = _make_mock_client()

        with patch("reconnect.VPNClient", return_value=mock_client):
            mgr.start()
            result = mgr.wait_connected(timeout=3.0)

        assert result is True
        mgr.stop()
