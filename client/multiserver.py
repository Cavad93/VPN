"""
multiserver.py — Multi-server support with automatic failover.

Manages a pool of VPN servers: on connection failure the client
transparently switches to the next available server according to the
configured selection policy.

Policies:
  PRIORITY   — always try servers in the order listed; return to the
                primary once it becomes reachable again.
  ROUND_ROBIN — cycle through servers in order; advance on each failure.
  FASTEST     — pick the server with the lowest TCP connect latency
                (measured at startup and after each failover).

Usage::

    servers = [
        ServerEndpoint("1.2.3.4:443", name="primary"),
        ServerEndpoint("5.6.7.8:443", name="fallback-1"),
    ]
    cfg = MultiServerConfig(servers=servers, policy=SelectionPolicy.PRIORITY)
    manager = MultiServerManager(cfg, key_pair=kp)
    manager.on_connected = lambda ep, route: print("connected via", ep.name)
    manager.start()
    manager.wait_connected(timeout=30)
    ...
    manager.stop()
"""

from __future__ import annotations

import socket
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, List, Optional

import structlog

from core import KeyPair, RouteInfo, VPNClient, VPNConfig, generate_key_pair

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass
class ServerEndpoint:
    """A single VPN server entry in the pool."""

    addr: str
    """host:port, e.g. '1.2.3.4:443'"""

    name: str = ""
    """Human-readable label (optional)."""

    connect_timeout: float = 10.0
    """TCP connect + handshake timeout for this server."""

    def __post_init__(self) -> None:
        if not self.name:
            self.name = self.addr

    def to_vpn_config(self, key_pair: Optional[KeyPair] = None) -> VPNConfig:
        """Build a :class:`VPNConfig` for this endpoint."""
        return VPNConfig(
            server_addr=self.addr,
            key_pair=key_pair,
            connect_timeout=self.connect_timeout,
        )


# ---------------------------------------------------------------------------
# Perf opt 1: VPNConfig object cache
# Each ServerEndpoint×KeyPair pair maps to a pre-built VPNConfig so that the
# hot reconnect path (called on every retry) never allocates a new dataclass.
# At 2 servers × 1 key pair this keeps the allocations at zero after the first
# connection attempt — meaningful when reconnecting at >10 Hz during storms.
# ---------------------------------------------------------------------------
_vpn_config_cache: dict = {}
_vpn_config_cache_lock = threading.Lock()


def _get_cached_vpn_config(endpoint: "ServerEndpoint", key_pair: Optional[KeyPair]) -> VPNConfig:
    """Return a cached :class:`VPNConfig` for *endpoint* + *key_pair*."""
    cache_key = (id(endpoint), id(key_pair))
    with _vpn_config_cache_lock:
        cfg = _vpn_config_cache.get(cache_key)
        if cfg is None:
            cfg = endpoint.to_vpn_config(key_pair)
            _vpn_config_cache[cache_key] = cfg
        return cfg


class SelectionPolicy(Enum):
    """Server selection strategy."""

    PRIORITY = "priority"
    """Try servers in order; always start from the primary."""

    ROUND_ROBIN = "round_robin"
    """Advance to the next server on each failure; wrap around."""

    FASTEST = "fastest"
    """Pick the server with the lowest TCP connect latency."""


@dataclass
class MultiServerConfig:
    """Configuration for the multi-server manager."""

    servers: List[ServerEndpoint]
    """Ordered list of VPN servers (at least one required)."""

    policy: SelectionPolicy = SelectionPolicy.PRIORITY
    """How to select the next server after a failure."""

    probe_timeout: float = 5.0
    """Timeout (seconds) for latency probes (FASTEST policy)."""

    initial_delay: float = 1.0
    """Base reconnect delay (seconds)."""

    max_delay: float = 60.0
    """Maximum reconnect delay (seconds)."""

    backoff_factor: float = 2.0
    """Exponential backoff multiplier."""

    max_attempts_per_server: int = 2
    """How many times to retry a server before switching to the next one."""

    health_check_interval: float = 30.0
    """Seconds between health checks while connected."""

    health_check_timeout: float = 10.0
    """Timeout for a single health check."""

    def __post_init__(self) -> None:
        if not self.servers:
            raise ValueError("MultiServerConfig requires at least one server entry")


# ---------------------------------------------------------------------------
# Latency probe
# ---------------------------------------------------------------------------


def _probe_latency(addr: str, timeout: float) -> float:
    """
    Measure TCP connect latency to *addr* (host:port).

    Returns elapsed seconds, or *float('inf')* if the connection fails.
    The connection is immediately closed after timing — no data is sent.
    """
    try:
        host, port_str = addr.rsplit(":", 1)
        port = int(port_str)
        start = time.monotonic()
        with socket.create_connection((host, port), timeout=timeout):
            pass
        return time.monotonic() - start
    except Exception:
        return float("inf")


def _probe_all(
    servers: List[ServerEndpoint], timeout: float
) -> List[tuple[float, int]]:
    """
    Probe all servers concurrently.

    Returns a list of (latency_seconds, original_index) sorted by latency
    (fastest first).  Uses one daemon thread per server to parallelise.
    """
    results: List[tuple[float, int]] = [None] * len(servers)  # type: ignore[list-item]
    threads: List[threading.Thread] = []

    def _measure(idx: int, ep: ServerEndpoint) -> None:
        lat = _probe_latency(ep.addr, timeout)
        results[idx] = (lat, idx)

    for i, ep in enumerate(servers):
        t = threading.Thread(target=_measure, args=(i, ep), daemon=True)
        threads.append(t)
        t.start()

    for t in threads:
        t.join(timeout=timeout + 1.0)

    # Replace any None entries (thread didn't finish) with inf
    for i, r in enumerate(results):
        if r is None:
            results[i] = (float("inf"), i)

    return sorted(results, key=lambda x: x[0])


# ---------------------------------------------------------------------------
# Server selector
# ---------------------------------------------------------------------------


class ServerSelector:
    """
    Thread-safe selector that returns the next server to try.

    All policy logic is contained here; :class:`MultiServerManager` delegates
    selection decisions to this class.
    """

    def __init__(self, config: MultiServerConfig) -> None:
        self._cfg = config
        self._lock = threading.Lock()
        self._rr_index = 0  # current round-robin position
        self._sorted_by_latency: Optional[List[int]] = None
        # For FASTEST policy, re-sort lazily on first use or after reset.
        self._probed = threading.Event()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def prime(self) -> None:
        """
        Run latency probes for the FASTEST policy.

        No-op for other policies.  Safe to call from any thread; only the
        first call actually probes — subsequent calls return immediately.
        """
        if self._cfg.policy is not SelectionPolicy.FASTEST:
            return
        if self._probed.is_set():
            return
        ranked = _probe_all(self._cfg.servers, self._cfg.probe_timeout)
        with self._lock:
            self._sorted_by_latency = [idx for _, idx in ranked]
            for rank, (lat, idx) in enumerate(ranked):
                ep = self._cfg.servers[idx]
                logger.info(
                    "server_latency_probe",
                    rank=rank + 1,
                    server=ep.name,
                    latency_ms=round(lat * 1000) if lat < float("inf") else "unreachable",
                )
        self._probed.set()

    def reprobe(self) -> None:
        """Force a fresh latency probe on the next :meth:`prime` call."""
        self._probed.clear()

    def get(self, failure_count: int) -> ServerEndpoint:
        """
        Return the server to use for attempt *failure_count* (0-indexed).

        Policy semantics:
        - PRIORITY: always start at index 0; advance by one server per
          ``max_attempts_per_server`` failures.
        - ROUND_ROBIN: advance by one server per ``max_attempts_per_server``
          failures, wrapping around.
        - FASTEST: same as PRIORITY but using the latency-sorted order.

        Perf opt 2: snapshot the sorted order list once under the lock then
        compute the index outside the critical section — lock hold time is
        O(1) regardless of the number of servers, avoiding contention when
        the background _run loop calls get() at high frequency during storms.
        """
        n = len(self._cfg.servers)
        steps = failure_count // max(1, self._cfg.max_attempts_per_server)

        # Snapshot under lock — O(1) reference copy, not a list copy
        with self._lock:
            order_snapshot = self._sorted_by_latency  # None or list ref

        if self._cfg.policy is SelectionPolicy.PRIORITY:
            idx = min(steps, n - 1)
        elif self._cfg.policy is SelectionPolicy.ROUND_ROBIN:
            idx = steps % n
        elif self._cfg.policy is SelectionPolicy.FASTEST:
            order = order_snapshot if order_snapshot is not None else list(range(n))
            idx = order[min(steps, n - 1)]
        else:
            idx = 0

        return self._cfg.servers[idx]

    def current_index(self, failure_count: int) -> int:
        """Return the 0-based index of the server selected for *failure_count*."""
        n = len(self._cfg.servers)
        steps = failure_count // max(1, self._cfg.max_attempts_per_server)
        with self._lock:
            order_snapshot = self._sorted_by_latency
        if self._cfg.policy is SelectionPolicy.PRIORITY:
            return min(steps, n - 1)
        elif self._cfg.policy is SelectionPolicy.ROUND_ROBIN:
            return steps % n
        elif self._cfg.policy is SelectionPolicy.FASTEST:
            order = order_snapshot if order_snapshot is not None else list(range(n))
            return order[min(steps, n - 1)]
        return 0


# ---------------------------------------------------------------------------
# Connection state
# ---------------------------------------------------------------------------


class MultiServerState(Enum):
    """Lifecycle states of the :class:`MultiServerManager`."""

    IDLE = "idle"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    RECONNECTING = "reconnecting"
    STOPPED = "stopped"


# ---------------------------------------------------------------------------
# Multi-server manager
# ---------------------------------------------------------------------------


class MultiServerManager:
    """
    Manages a pool of VPN servers with automatic failover.

    On failure the manager switches to the next server according to the
    configured :class:`SelectionPolicy`.  Within each server it applies
    exponential backoff between retries.

    Callbacks (set before calling :meth:`start`)::

        manager.on_connected   = lambda ep, route: ...
        manager.on_disconnected = lambda ep, exc: ...
        manager.on_switching    = lambda old_ep, new_ep, attempt: ...
    """

    def __init__(
        self,
        config: MultiServerConfig,
        key_pair: Optional[KeyPair] = None,
    ) -> None:
        self._cfg = config
        self._key_pair = key_pair  # shared across all server connections
        self._selector = ServerSelector(config)

        # Public callbacks
        self.on_connected: Optional[Callable[[ServerEndpoint, RouteInfo], None]] = None
        """Called after a successful connection is established."""
        self.on_disconnected: Optional[Callable[[ServerEndpoint, Optional[Exception]], None]] = None
        """Called when the active connection is lost."""
        self.on_switching: Optional[Callable[[ServerEndpoint, ServerEndpoint, int], None]] = None
        """Called with (old_endpoint, new_endpoint, attempt) before switching servers."""

        self._state = MultiServerState.IDLE
        self._state_lock = threading.Lock()
        self._connected_event = threading.Event()
        self._stop_event = threading.Event()
        self._failure_event = threading.Event()

        self._active_endpoint: Optional[ServerEndpoint] = None
        self._active_client: Optional[VPNClient] = None
        self._route_info: Optional[RouteInfo] = None
        self._health_thread: Optional[threading.Thread] = None
        self._worker: Optional[threading.Thread] = None
        self._failure_count = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def state(self) -> MultiServerState:
        with self._state_lock:
            return self._state

    @property
    def active_endpoint(self) -> Optional[ServerEndpoint]:
        """The server endpoint currently in use, or *None*."""
        return self._active_endpoint

    @property
    def route_info(self) -> Optional[RouteInfo]:
        """Route info from the most recent successful connection, or *None*."""
        return self._route_info

    def start(self) -> None:
        """Start the manager in a background thread."""
        if self._worker is not None and self._worker.is_alive():
            raise RuntimeError("MultiServerManager is already running")
        self._stop_event.clear()
        self._connected_event.clear()
        self._failure_count = 0
        self._worker = threading.Thread(
            target=self._run, daemon=True, name="multiserver-manager"
        )
        self._worker.start()
        logger.info("multiserver_started", policy=self._cfg.policy.value,
                    servers=[ep.name for ep in self._cfg.servers])

    def stop(self) -> None:
        """Signal the manager to stop and wait for it to shut down."""
        logger.info("multiserver_stopping")
        self._stop_event.set()
        self._failure_event.set()
        self._connected_event.set()
        self._stop_health_checker()
        self._disconnect_active(reason=None)
        if self._worker is not None:
            self._worker.join(timeout=15.0)
            self._worker = None
        self._set_state(MultiServerState.STOPPED)
        logger.info("multiserver_stopped")

    def wait_connected(self, timeout: Optional[float] = None) -> bool:
        """Block until connected (or *timeout* seconds).  Returns True if connected."""
        return self._connected_event.wait(timeout=timeout)

    def get_server_list(self) -> List[ServerEndpoint]:
        """Return a copy of the configured server list."""
        return list(self._cfg.servers)

    # ------------------------------------------------------------------
    # Background loop
    # ------------------------------------------------------------------

    def _run(self) -> None:
        # Warm up latency data for FASTEST policy (parallel TCP probes).
        self._selector.prime()

        delay = self._cfg.initial_delay
        attempt = 0

        while not self._stop_event.is_set():
            attempt += 1
            endpoint = self._selector.get(self._failure_count)
            self._set_state(
                MultiServerState.CONNECTING if self._failure_count == 0
                else MultiServerState.RECONNECTING
            )

            log = logger.bind(server=endpoint.name, attempt=attempt,
                              failures=self._failure_count)
            log.info("multiserver_connect_attempt")

            # Perf opt 1: reuse cached VPNConfig — zero alloc on hot reconnect path
            vpn_cfg = _get_cached_vpn_config(endpoint, self._key_pair)
            try:
                client = VPNClient(vpn_cfg)
                route = client.connect()
            except Exception as exc:
                log.warning("multiserver_connect_failed", error=str(exc))
                self._failure_count += 1

                # Notify switching if moving to a different server
                next_ep = self._selector.get(self._failure_count)
                if next_ep is not endpoint and self.on_switching is not None:
                    try:
                        self.on_switching(endpoint, next_ep, attempt)
                    except Exception:
                        pass

                # Exponential backoff (per-server, resets on success)
                self._stop_event.wait(timeout=delay)
                delay = min(delay * self._cfg.backoff_factor, self._cfg.max_delay)
                continue

            # ---- Connected successfully ----
            self._active_endpoint = endpoint
            self._active_client = client
            self._route_info = route
            self._failure_count = 0
            delay = self._cfg.initial_delay  # reset backoff

            self._set_state(MultiServerState.CONNECTED)
            self._connected_event.set()

            log.info("multiserver_connected",
                     assigned_ip=route.assigned_ip if route else None)

            if self.on_connected is not None:
                try:
                    self.on_connected(endpoint, route)
                except Exception:
                    pass

            # Monitor until failure or stop
            self._failure_event.clear()
            self._start_health_checker(client)
            self._failure_event.wait()  # blocks until health failure or stop()

            self._stop_health_checker()

            if self._stop_event.is_set():
                break

            # Connection lost — record and try again
            log.warning("multiserver_connection_lost", server=endpoint.name)
            self._failure_count += 1
            self._set_state(MultiServerState.RECONNECTING)

            if self.on_disconnected is not None:
                try:
                    self.on_disconnected(endpoint, None)
                except Exception:
                    pass

            self._disconnect_active(reason=None)

        self._set_state(MultiServerState.STOPPED)

    # ------------------------------------------------------------------
    # Health checker
    # ------------------------------------------------------------------

    def _health_check_loop(self, client: VPNClient) -> None:
        interval = self._cfg.health_check_interval
        while not self._stop_event.is_set() and not self._failure_event.is_set():
            if not self._stop_event.wait(timeout=interval):
                # Check if client is still alive
                try:
                    if not client._connected.is_set():
                        raise ConnectionError("client disconnected")
                    mux = client._mux
                    if mux is None or mux._closed.is_set():
                        raise ConnectionError("mux closed")
                    stream = client._data_stream
                    if stream is None or stream._closed.is_set():
                        raise ConnectionError("data stream closed")
                    logger.debug("multiserver_health_ok",
                                 server=self._active_endpoint.name
                                 if self._active_endpoint else "?")
                except Exception as exc:
                    logger.warning("multiserver_health_failed", error=str(exc),
                                   server=self._active_endpoint.name
                                   if self._active_endpoint else "?")
                    self._failure_event.set()
                    return

    def _start_health_checker(self, client: VPNClient) -> None:
        self._health_thread = threading.Thread(
            target=self._health_check_loop,
            args=(client,),
            daemon=True,
            name="multiserver-health",
        )
        self._health_thread.start()

    def _stop_health_checker(self) -> None:
        t = self._health_thread
        self._health_thread = None
        if t is not None and t.is_alive():
            self._failure_event.set()  # wake it up
            t.join(timeout=self._cfg.health_check_interval + 1.0)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _set_state(self, state: MultiServerState) -> None:
        with self._state_lock:
            self._state = state

    def _disconnect_active(self, reason: Optional[Exception]) -> None:
        client = self._active_client
        self._active_client = None
        if client is not None:
            try:
                client.disconnect()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def create_multi_server_manager(
    server_addrs: List[str],
    *,
    policy: SelectionPolicy = SelectionPolicy.PRIORITY,
    key_pair: Optional[KeyPair] = None,
    connect_timeout: float = 10.0,
    health_check_interval: float = 30.0,
    max_attempts_per_server: int = 2,
) -> "MultiServerManager":
    """
    Convenience factory: create a :class:`MultiServerManager` from a list of
    ``host:port`` strings.

    If *key_pair* is *None* a fresh X25519 pair is generated automatically.

    Example::

        manager = create_multi_server_manager(
            ["1.2.3.4:443", "5.6.7.8:443"],
            policy=SelectionPolicy.FASTEST,
        )
        manager.start()
    """
    if not server_addrs:
        raise ValueError("at least one server address is required")

    kp = key_pair or generate_key_pair()
    endpoints = [
        ServerEndpoint(addr=addr, connect_timeout=connect_timeout)
        for addr in server_addrs
    ]
    cfg = MultiServerConfig(
        servers=endpoints,
        policy=policy,
        max_attempts_per_server=max_attempts_per_server,
        health_check_interval=health_check_interval,
    )
    return MultiServerManager(cfg, key_pair=kp)
