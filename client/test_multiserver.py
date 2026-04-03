"""
test_multiserver.py — Unit tests for multiserver.py.

All network I/O is mocked — tests run without a real VPN server.
"""

from __future__ import annotations

import threading
import time
from typing import Optional
from unittest.mock import MagicMock, patch

import pytest

import multiserver as ms
from multiserver import (
    MultiServerConfig,
    MultiServerManager,
    MultiServerState,
    SelectionPolicy,
    ServerEndpoint,
    ServerSelector,
    _probe_all,
    _probe_latency,
    create_multi_server_manager,
)
from core import RouteInfo, VPNConfig


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_route(ip: str = "10.8.0.2") -> RouteInfo:
    return RouteInfo(
        assigned_ip=ip,
        prefix_len=24,
        gateway="10.8.0.1",
        server_public_key=b"\x00" * 32,
    )


def _make_endpoint(addr: str = "1.2.3.4:443", name: str = "") -> ServerEndpoint:
    return ServerEndpoint(addr=addr, name=name or addr)


def _make_mock_client(route: Optional[RouteInfo] = None, connect_exc=None):
    """Return a MagicMock that mimics VPNClient."""
    client = MagicMock()
    if connect_exc is not None:
        client.connect.side_effect = connect_exc
    else:
        client.connect.return_value = route or _make_route()

    connected_evt = threading.Event()
    connected_evt.set()
    client._connected = connected_evt

    mux = MagicMock()
    mux._closed = threading.Event()
    client._mux = mux

    stream = MagicMock()
    stream._closed = threading.Event()
    client._data_stream = stream

    return client


# ---------------------------------------------------------------------------
# ServerEndpoint
# ---------------------------------------------------------------------------


class TestServerEndpoint:
    def test_name_defaults_to_addr(self):
        ep = ServerEndpoint(addr="1.2.3.4:443")
        assert ep.name == "1.2.3.4:443"

    def test_explicit_name(self):
        ep = ServerEndpoint(addr="1.2.3.4:443", name="primary")
        assert ep.name == "primary"

    def test_to_vpn_config_no_keypair(self):
        ep = ServerEndpoint(addr="1.2.3.4:443", connect_timeout=15.0)
        cfg = ep.to_vpn_config()
        assert cfg.server_addr == "1.2.3.4:443"
        assert cfg.connect_timeout == 15.0
        assert cfg.key_pair is None

    def test_to_vpn_config_with_keypair(self):
        from core import generate_key_pair
        kp = generate_key_pair()
        ep = ServerEndpoint(addr="1.2.3.4:443")
        cfg = ep.to_vpn_config(key_pair=kp)
        assert cfg.key_pair is kp


# ---------------------------------------------------------------------------
# MultiServerConfig
# ---------------------------------------------------------------------------


class TestMultiServerConfig:
    def test_empty_servers_raises(self):
        with pytest.raises(ValueError, match="at least one"):
            MultiServerConfig(servers=[])

    def test_default_policy(self):
        cfg = MultiServerConfig(servers=[_make_endpoint()])
        assert cfg.policy is SelectionPolicy.PRIORITY

    def test_custom_policy(self):
        cfg = MultiServerConfig(
            servers=[_make_endpoint()],
            policy=SelectionPolicy.ROUND_ROBIN,
        )
        assert cfg.policy is SelectionPolicy.ROUND_ROBIN


# ---------------------------------------------------------------------------
# ServerSelector — PRIORITY
# ---------------------------------------------------------------------------


class TestServerSelectorPriority:
    def _cfg(self, n: int = 3, max_per_server: int = 2) -> MultiServerConfig:
        servers = [ServerEndpoint(addr=f"10.0.0.{i}:443") for i in range(n)]
        return MultiServerConfig(
            servers=servers,
            policy=SelectionPolicy.PRIORITY,
            max_attempts_per_server=max_per_server,
        )

    def test_first_attempt_uses_primary(self):
        sel = ServerSelector(self._cfg())
        ep = sel.get(failure_count=0)
        assert ep.addr == "10.0.0.0:443"

    def test_switches_after_max_per_server_failures(self):
        sel = ServerSelector(self._cfg(max_per_server=2))
        assert sel.get(0).addr == "10.0.0.0:443"
        assert sel.get(1).addr == "10.0.0.0:443"
        assert sel.get(2).addr == "10.0.0.1:443"
        assert sel.get(3).addr == "10.0.0.1:443"
        assert sel.get(4).addr == "10.0.0.2:443"

    def test_clamps_at_last_server(self):
        sel = ServerSelector(self._cfg(n=2, max_per_server=1))
        # failure_count=99 → steps=99 → clamped to index 1
        ep = sel.get(failure_count=99)
        assert ep.addr == "10.0.0.1:443"

    def test_current_index(self):
        sel = ServerSelector(self._cfg(max_per_server=1))
        assert sel.current_index(0) == 0
        assert sel.current_index(1) == 1
        assert sel.current_index(2) == 2


# ---------------------------------------------------------------------------
# ServerSelector — ROUND_ROBIN
# ---------------------------------------------------------------------------


class TestServerSelectorRoundRobin:
    def _cfg(self, n: int = 3) -> MultiServerConfig:
        servers = [ServerEndpoint(addr=f"10.0.0.{i}:443") for i in range(n)]
        return MultiServerConfig(
            servers=servers,
            policy=SelectionPolicy.ROUND_ROBIN,
            max_attempts_per_server=1,
        )

    def test_cycles_through_servers(self):
        sel = ServerSelector(self._cfg())
        addrs = [sel.get(i).addr for i in range(6)]
        assert addrs == [
            "10.0.0.0:443", "10.0.0.1:443", "10.0.0.2:443",
            "10.0.0.0:443", "10.0.0.1:443", "10.0.0.2:443",
        ]

    def test_single_server_always_same(self):
        sel = ServerSelector(self._cfg(n=1))
        for i in range(5):
            assert sel.get(i).addr == "10.0.0.0:443"


# ---------------------------------------------------------------------------
# ServerSelector — FASTEST
# ---------------------------------------------------------------------------


class TestServerSelectorFastest:
    def _cfg(self, n: int = 3) -> MultiServerConfig:
        servers = [ServerEndpoint(addr=f"10.0.0.{i}:443") for i in range(n)]
        return MultiServerConfig(
            servers=servers,
            policy=SelectionPolicy.FASTEST,
            max_attempts_per_server=1,
        )

    def test_prime_sets_probed(self):
        cfg = self._cfg()
        sel = ServerSelector(cfg)
        # Patch _probe_all to return a fixed order
        with patch.object(ms, "_probe_all", return_value=[(0.05, 2), (0.10, 0), (0.20, 1)]):
            sel.prime()
        assert sel._probed.is_set()
        assert sel._sorted_by_latency == [2, 0, 1]

    def test_prime_idempotent(self):
        cfg = self._cfg()
        sel = ServerSelector(cfg)
        call_count = {"n": 0}

        def fake_probe(*args, **kwargs):
            call_count["n"] += 1
            return [(0.01, 0), (0.02, 1), (0.03, 2)]

        with patch.object(ms, "_probe_all", side_effect=fake_probe):
            sel.prime()
            sel.prime()  # should be no-op
        assert call_count["n"] == 1

    def test_reprobe_allows_re_prime(self):
        cfg = self._cfg()
        sel = ServerSelector(cfg)
        call_count = {"n": 0}

        def fake_probe(*args, **kwargs):
            call_count["n"] += 1
            return [(0.01, 0), (0.02, 1), (0.03, 2)]

        with patch.object(ms, "_probe_all", side_effect=fake_probe):
            sel.prime()
            sel.reprobe()
            sel.prime()
        assert call_count["n"] == 2

    def test_uses_latency_order(self):
        cfg = self._cfg()
        sel = ServerSelector(cfg)
        with patch.object(ms, "_probe_all", return_value=[(0.05, 2), (0.10, 0), (0.20, 1)]):
            sel.prime()
        # failure_count=0 → fastest = index 2
        assert sel.get(0).addr == "10.0.0.2:443"
        # failure_count=1 → second fastest = index 0
        assert sel.get(1).addr == "10.0.0.0:443"

    def test_falls_back_to_natural_order_when_not_primed(self):
        cfg = self._cfg()
        sel = ServerSelector(cfg)
        # Without prime(), sorted_by_latency is None → natural order
        assert sel.get(0).addr == "10.0.0.0:443"


# ---------------------------------------------------------------------------
# _probe_latency
# ---------------------------------------------------------------------------


class TestProbeLatency:
    def test_returns_inf_on_unreachable(self):
        # Nothing listening on port 1 — should fail fast and return inf
        lat = _probe_latency("127.0.0.1:1", timeout=0.5)
        assert lat == float("inf")

    def test_measures_loopback_connect(self):
        """Open a server socket on loopback and probe it."""
        import socket as _socket
        srv = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        srv.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        try:
            lat = _probe_latency(f"127.0.0.1:{port}", timeout=2.0)
            assert 0.0 <= lat < 1.0
        finally:
            srv.close()

    def test_invalid_addr_returns_inf(self):
        lat = _probe_latency("not-a-host:99999", timeout=0.5)
        assert lat == float("inf")


# ---------------------------------------------------------------------------
# _probe_all
# ---------------------------------------------------------------------------


class TestProbeAll:
    def test_returns_sorted_by_latency(self):
        def fake_probe(addr, timeout):
            # "fast" server gets 0.01s, "slow" gets 0.5s
            return 0.01 if "fast" in addr else 0.5

        servers = [
            ServerEndpoint(addr="slow:443"),
            ServerEndpoint(addr="fast:443"),
        ]
        with patch.object(ms, "_probe_latency", side_effect=fake_probe):
            results = _probe_all(servers, timeout=1.0)

        assert results[0] == (0.01, 1)  # fast first
        assert results[1] == (0.5, 0)

    def test_handles_unreachable(self):
        servers = [ServerEndpoint(addr="unreachable:443")]
        with patch.object(ms, "_probe_latency", return_value=float("inf")):
            results = _probe_all(servers, timeout=0.1)
        assert results[0][0] == float("inf")


# ---------------------------------------------------------------------------
# MultiServerManager — basic lifecycle
# ---------------------------------------------------------------------------


class TestMultiServerManagerLifecycle:
    def _manager(self, connect_exc=None, n_servers=2):
        servers = [
            ServerEndpoint(addr=f"10.0.0.{i}:443") for i in range(n_servers)
        ]
        cfg = MultiServerConfig(
            servers=servers,
            policy=SelectionPolicy.PRIORITY,
            initial_delay=0.05,
            max_delay=0.1,
            max_attempts_per_server=1,
            health_check_interval=30.0,
        )
        mock_client = _make_mock_client(connect_exc=connect_exc)
        manager = MultiServerManager(cfg)
        return manager, mock_client

    def test_initial_state_is_idle(self):
        manager, _ = self._manager()
        assert manager.state is MultiServerState.IDLE

    def test_start_stop_no_connection(self):
        """Manager starts and stops cleanly even if connect always fails."""
        servers = [ServerEndpoint(addr="10.0.0.1:443")]
        cfg = MultiServerConfig(
            servers=servers,
            initial_delay=0.05,
            max_delay=0.1,
        )
        manager = MultiServerManager(cfg)
        with patch("multiserver.VPNClient") as MockClient:
            MockClient.return_value.connect.side_effect = ConnectionRefusedError("refused")
            manager.start()
            time.sleep(0.2)
            manager.stop()
        assert manager.state is MultiServerState.STOPPED

    def test_connects_successfully(self):
        servers = [ServerEndpoint(addr="10.0.0.1:443")]
        cfg = MultiServerConfig(servers=servers, health_check_interval=60.0)
        route = _make_route()
        connected = threading.Event()
        connected_ep = []

        manager = MultiServerManager(cfg)
        manager.on_connected = lambda ep, r: (connected_ep.append(ep), connected.set())

        mock_client = _make_mock_client(route=route)
        with patch("multiserver.VPNClient", return_value=mock_client):
            manager.start()
            assert connected.wait(timeout=3.0), "did not connect in time"
            assert manager.state is MultiServerState.CONNECTED
            assert manager.route_info is route
            assert connected_ep[0].addr == "10.0.0.1:443"
            manager.stop()

    def test_wait_connected_returns_true(self):
        servers = [ServerEndpoint(addr="10.0.0.1:443")]
        cfg = MultiServerConfig(servers=servers, health_check_interval=60.0)
        mock_client = _make_mock_client()
        manager = MultiServerManager(cfg)
        with patch("multiserver.VPNClient", return_value=mock_client):
            manager.start()
            result = manager.wait_connected(timeout=3.0)
        assert result is True
        manager.stop()

    def test_wait_connected_timeout_returns_false(self):
        servers = [ServerEndpoint(addr="10.0.0.1:443")]
        cfg = MultiServerConfig(servers=servers, initial_delay=10.0)
        manager = MultiServerManager(cfg)
        with patch("multiserver.VPNClient") as MockClient:
            MockClient.return_value.connect.side_effect = ConnectionRefusedError
            manager.start()
            result = manager.wait_connected(timeout=0.2)
        assert result is False
        manager.stop()

    def test_double_start_raises(self):
        servers = [ServerEndpoint(addr="10.0.0.1:443")]
        cfg = MultiServerConfig(servers=servers, health_check_interval=60.0)
        mock_client = _make_mock_client()
        manager = MultiServerManager(cfg)
        with patch("multiserver.VPNClient", return_value=mock_client):
            manager.start()
            manager.wait_connected(timeout=2.0)
            with pytest.raises(RuntimeError, match="already running"):
                manager.start()
            manager.stop()


# ---------------------------------------------------------------------------
# MultiServerManager — failover
# ---------------------------------------------------------------------------


class TestMultiServerManagerFailover:
    def test_switches_server_on_failure(self):
        """First server always fails, second succeeds — manager uses second."""
        servers = [
            ServerEndpoint(addr="10.0.0.0:443", name="bad"),
            ServerEndpoint(addr="10.0.0.1:443", name="good"),
        ]
        cfg = MultiServerConfig(
            servers=servers,
            policy=SelectionPolicy.PRIORITY,
            initial_delay=0.05,
            max_delay=0.1,
            max_attempts_per_server=1,
            health_check_interval=60.0,
        )

        connected_eps: list = []
        connected_evt = threading.Event()

        def fake_client(vpn_cfg):
            client = _make_mock_client()
            if "10.0.0.0" in vpn_cfg.server_addr:
                client.connect.side_effect = ConnectionRefusedError("bad server")
            else:
                client.connect.return_value = _make_route()
            return client

        manager = MultiServerManager(cfg)
        manager.on_connected = lambda ep, r: (connected_eps.append(ep.name),
                                              connected_evt.set())

        with patch("multiserver.VPNClient", side_effect=fake_client):
            manager.start()
            assert connected_evt.wait(timeout=3.0), "failover did not happen"

        assert connected_eps[0] == "good"
        assert manager.active_endpoint.name == "good"
        manager.stop()

    def test_on_switching_callback_fired(self):
        """on_switching should fire when manager moves to a new server."""
        servers = [
            ServerEndpoint(addr="10.0.0.0:443", name="bad"),
            ServerEndpoint(addr="10.0.0.1:443", name="good"),
        ]
        cfg = MultiServerConfig(
            servers=servers,
            initial_delay=0.01,
            max_delay=0.05,
            max_attempts_per_server=1,
            health_check_interval=60.0,
        )

        switching_calls: list = []
        switched_evt = threading.Event()

        def on_switch(old, new, attempt):
            switching_calls.append((old.name, new.name))
            switched_evt.set()

        def fake_client(vpn_cfg):
            client = _make_mock_client()
            if "10.0.0.0" in vpn_cfg.server_addr:
                client.connect.side_effect = ConnectionRefusedError
            return client

        manager = MultiServerManager(cfg)
        manager.on_switching = on_switch

        with patch("multiserver.VPNClient", side_effect=fake_client):
            manager.start()
            switched_evt.wait(timeout=3.0)
            manager.stop()

        assert any(c[0] == "bad" and c[1] == "good" for c in switching_calls)

    def test_health_failure_triggers_failover(self):
        """When health check detects a dead connection, manager reconnects."""
        servers = [ServerEndpoint(addr="10.0.0.1:443")]
        cfg = MultiServerConfig(
            servers=servers,
            initial_delay=0.05,
            max_delay=0.1,
            health_check_interval=0.1,  # fast health check
        )

        connect_count = {"n": 0}
        reconnected = threading.Event()

        def fake_client(vpn_cfg):
            connect_count["n"] += 1
            client = _make_mock_client(route=_make_route())
            if connect_count["n"] == 2:
                reconnected.set()
            return client

        first_client = None

        original_factory = fake_client

        def factory_with_kill(vpn_cfg):
            c = original_factory(vpn_cfg)
            nonlocal first_client
            if connect_count["n"] == 1:
                first_client = c
            return c

        manager = MultiServerManager(cfg)
        with patch("multiserver.VPNClient", side_effect=factory_with_kill):
            manager.start()
            manager.wait_connected(timeout=3.0)

            # Simulate connection drop
            assert first_client is not None
            first_client._mux._closed.set()

            assert reconnected.wait(timeout=3.0), "did not reconnect after health failure"
            manager.stop()

    def test_on_disconnected_callback_fired(self):
        """on_disconnected fires when an active connection is lost."""
        servers = [ServerEndpoint(addr="10.0.0.1:443")]
        cfg = MultiServerConfig(
            servers=servers,
            initial_delay=0.05,
            health_check_interval=0.1,
        )

        disconnected = threading.Event()
        disconnected_eps: list = []

        manager = MultiServerManager(cfg)
        manager.on_disconnected = lambda ep, exc: (
            disconnected_eps.append(ep.name), disconnected.set()
        )

        client_holder = [None]

        def fake_client(vpn_cfg):
            c = _make_mock_client(route=_make_route())
            client_holder[0] = c
            return c

        with patch("multiserver.VPNClient", side_effect=fake_client):
            manager.start()
            manager.wait_connected(timeout=3.0)
            # Kill connection
            client_holder[0]._mux._closed.set()
            disconnected.wait(timeout=3.0)
            manager.stop()

        assert disconnected_eps[0] == "10.0.0.1:443"


# ---------------------------------------------------------------------------
# MultiServerManager — state transitions
# ---------------------------------------------------------------------------


class TestMultiServerManagerState:
    def test_state_connecting_on_start(self):
        servers = [ServerEndpoint(addr="10.0.0.1:443")]
        cfg = MultiServerConfig(servers=servers, initial_delay=10.0)
        manager = MultiServerManager(cfg)
        barrier = threading.Event()

        def slow_connect():
            barrier.wait(timeout=2.0)
            raise ConnectionRefusedError

        with patch("multiserver.VPNClient") as MockClient:
            MockClient.return_value.connect.side_effect = slow_connect
            manager.start()
            time.sleep(0.05)
            state = manager.state
            barrier.set()
            manager.stop()

        assert state is MultiServerState.CONNECTING

    def test_state_connected_after_success(self):
        servers = [ServerEndpoint(addr="10.0.0.1:443")]
        cfg = MultiServerConfig(servers=servers, health_check_interval=60.0)
        mock_client = _make_mock_client()
        manager = MultiServerManager(cfg)
        with patch("multiserver.VPNClient", return_value=mock_client):
            manager.start()
            manager.wait_connected(timeout=3.0)
            assert manager.state is MultiServerState.CONNECTED
            manager.stop()

    def test_state_stopped_after_stop(self):
        servers = [ServerEndpoint(addr="10.0.0.1:443")]
        cfg = MultiServerConfig(servers=servers, health_check_interval=60.0)
        mock_client = _make_mock_client()
        manager = MultiServerManager(cfg)
        with patch("multiserver.VPNClient", return_value=mock_client):
            manager.start()
            manager.wait_connected(timeout=3.0)
            manager.stop()
        assert manager.state is MultiServerState.STOPPED


# ---------------------------------------------------------------------------
# create_multi_server_manager factory
# ---------------------------------------------------------------------------


class TestFactory:
    def test_basic_creation(self):
        manager = create_multi_server_manager(["1.2.3.4:443", "5.6.7.8:443"])
        assert len(manager._cfg.servers) == 2
        assert manager._cfg.servers[0].addr == "1.2.3.4:443"
        assert manager._cfg.policy is SelectionPolicy.PRIORITY

    def test_custom_policy(self):
        manager = create_multi_server_manager(
            ["1.2.3.4:443"], policy=SelectionPolicy.ROUND_ROBIN
        )
        assert manager._cfg.policy is SelectionPolicy.ROUND_ROBIN

    def test_empty_addrs_raises(self):
        with pytest.raises(ValueError, match="at least one"):
            create_multi_server_manager([])

    def test_generates_keypair_if_none(self):
        manager = create_multi_server_manager(["1.2.3.4:443"])
        assert manager._key_pair is not None

    def test_uses_provided_keypair(self):
        from core import generate_key_pair
        kp = generate_key_pair()
        manager = create_multi_server_manager(["1.2.3.4:443"], key_pair=kp)
        assert manager._key_pair is kp

    def test_get_server_list(self):
        manager = create_multi_server_manager(["1.1.1.1:443", "2.2.2.2:443"])
        lst = manager.get_server_list()
        assert len(lst) == 2
        assert lst is not manager._cfg.servers  # copy, not the same list
