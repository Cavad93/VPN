"""
reconnect.py — Auto-reconnect manager with exponential backoff and health check.

Wraps VPNClient and transparently reconnects on connection loss.
Periodic health checks detect silent connection failures.
"""

from __future__ import annotations

import random
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional

import structlog

from core import RouteInfo, VPNClient, VPNConfig

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass
class ReconnectConfig:
    """Configuration for auto-reconnect behaviour."""

    initial_delay: float = 1.0
    """Delay (seconds) before the first retry attempt."""

    max_delay: float = 60.0
    """Maximum delay (seconds) between consecutive retries."""

    backoff_factor: float = 2.0
    """Multiplier applied to the delay after each failed attempt."""

    jitter: float = 0.1
    """Fraction of the current delay added as random ±jitter.
    E.g. jitter=0.1 means ±10% of the current delay is added randomly."""

    max_attempts: int = 0
    """Maximum number of connection attempts. 0 means unlimited."""

    health_check_interval: float = 30.0
    """Seconds between periodic health checks while connected."""

    health_check_timeout: float = 10.0
    """Timeout (seconds) for a single health check probe."""


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------


class ConnectionState(Enum):
    """Lifecycle states of the AutoReconnect manager."""

    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    RECONNECTING = "reconnecting"
    STOPPED = "stopped"


# ---------------------------------------------------------------------------
# Backoff calculator
# ---------------------------------------------------------------------------


class ExponentialBackoff:
    """
    Computes successive delays using exponential backoff with optional jitter.

    Delay after attempt n (1-indexed):
        base = min(initial * factor^(n-1), max_delay)
        delay = base * uniform(1 - jitter, 1 + jitter)
    """

    def __init__(
        self,
        initial_delay: float = 1.0,
        max_delay: float = 60.0,
        factor: float = 2.0,
        jitter: float = 0.1,
    ) -> None:
        if initial_delay <= 0:
            raise ValueError("initial_delay must be positive")
        if max_delay < initial_delay:
            raise ValueError("max_delay must be >= initial_delay")
        if factor < 1.0:
            raise ValueError("factor must be >= 1.0")
        if not (0.0 <= jitter <= 1.0):
            raise ValueError("jitter must be in [0, 1]")

        self._initial = initial_delay
        self._max = max_delay
        self._factor = factor
        self._jitter = jitter
        self._attempt = 0

    @property
    def attempt(self) -> int:
        """Number of calls to :meth:`next_delay` so far."""
        return self._attempt

    def next_delay(self) -> float:
        """Return the delay for the current attempt and advance the counter."""
        base = min(self._initial * (self._factor ** self._attempt), self._max)
        if self._jitter > 0:
            lo = base * (1.0 - self._jitter)
            hi = base * (1.0 + self._jitter)
            delay = random.uniform(lo, hi)
        else:
            delay = base
        self._attempt += 1
        return max(0.0, delay)

    def reset(self) -> None:
        """Reset the attempt counter (call after a successful connection)."""
        self._attempt = 0


# ---------------------------------------------------------------------------
# Health checker
# ---------------------------------------------------------------------------


class HealthChecker:
    """
    Runs periodic health checks against the connected VPN client.

    Health is assessed by confirming that the VPN data stream is still alive
    (the mux read loop has not stopped) and that the underlying socket has not
    been reset. A failed check fires the provided *on_failure* callback.
    """

    def __init__(
        self,
        client: VPNClient,
        interval: float,
        timeout: float,
        on_failure: Callable[[Exception], None],
    ) -> None:
        self._client = client
        self._interval = interval
        self._timeout = timeout
        self._on_failure = on_failure
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        """Start the background health-check loop."""
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="vpn-health-check"
        )
        self._thread.start()

    def stop(self) -> None:
        """Signal the loop to stop and wait for it to finish."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=self._interval + 1.0)
            self._thread = None

    def _loop(self) -> None:
        while not self._stop_event.wait(timeout=self._interval):
            try:
                self._check()
            except Exception as exc:
                logger.warning("health_check_failed", error=str(exc))
                self._on_failure(exc)
                return  # stop checking; reconnect will restart us

    def _check(self) -> None:
        """
        Perform a single health check.

        Verifies that:
        1. The VPN client reports as connected.
        2. The underlying mux has not closed (its closed event is unset).
        3. The data stream is still open.
        """
        if not self._client._connected.is_set():
            raise ConnectionError("VPN client is not connected")

        mux = self._client._mux
        if mux is None or mux._closed.is_set():
            raise ConnectionError("VPN mux has been closed")

        data_stream = self._client._data_stream
        if data_stream is None or data_stream._closed.is_set():
            raise ConnectionError("VPN data stream has been closed")

        logger.debug("health_check_ok")


# ---------------------------------------------------------------------------
# Auto-reconnect manager
# ---------------------------------------------------------------------------


class AutoReconnect:
    """
    Wraps a :class:`VPNClient` and transparently reconnects on failure.

    Usage::

        cfg = VPNConfig(server_addr="1.2.3.4:443")
        rc_cfg = ReconnectConfig(initial_delay=2.0, max_attempts=10)
        manager = AutoReconnect(cfg, rc_cfg)
        manager.on_connected = lambda route: print("connected", route.cidr)
        manager.on_disconnected = lambda err: print("lost connection", err)
        manager.start()

        # ... later ...
        manager.stop()

    Callbacks are invoked from the background thread — keep them short.
    """

    def __init__(
        self,
        vpn_config: VPNConfig,
        reconnect_config: Optional[ReconnectConfig] = None,
    ) -> None:
        self._vpn_config = vpn_config
        self._rc_cfg = reconnect_config or ReconnectConfig()

        # Public callbacks — set before calling start()
        self.on_connected: Optional[Callable[[RouteInfo], None]] = None
        self.on_disconnected: Optional[Callable[[Optional[Exception]], None]] = None
        self.on_reconnecting: Optional[Callable[[int, float], None]] = None
        """Called with (attempt_number, delay_seconds) just before each retry."""

        self._state = ConnectionState.DISCONNECTED
        self._state_lock = threading.Lock()
        self._connected_event = threading.Event()
        self._stop_event = threading.Event()

        self._route_info: Optional[RouteInfo] = None
        self._client: Optional[VPNClient] = None
        self._health_checker: Optional[HealthChecker] = None
        self._backoff = ExponentialBackoff(
            initial_delay=self._rc_cfg.initial_delay,
            max_delay=self._rc_cfg.max_delay,
            factor=self._rc_cfg.backoff_factor,
            jitter=self._rc_cfg.jitter,
        )

        self._worker: Optional[threading.Thread] = None
        self._log = logger.bind(server=vpn_config.server_addr)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def state(self) -> ConnectionState:
        """Current connection state (thread-safe read)."""
        with self._state_lock:
            return self._state

    @property
    def route_info(self) -> Optional[RouteInfo]:
        """Route info from the most recent successful connection, or *None*."""
        return self._route_info

    def start(self) -> None:
        """
        Start the connection manager in a background thread.

        Returns immediately. Use :meth:`wait_connected` to block until the
        first successful connection is established.
        """
        if self._worker is not None and self._worker.is_alive():
            raise RuntimeError("AutoReconnect is already running")
        self._stop_event.clear()
        self._connected_event.clear()
        self._worker = threading.Thread(
            target=self._run_loop, daemon=True, name="vpn-reconnect"
        )
        self._worker.start()
        self._log.info("auto_reconnect_started")

    def stop(self) -> None:
        """
        Signal the manager to stop and wait for it to shut down.

        This method blocks until the background thread has exited.
        """
        self._log.info("auto_reconnect_stopping")
        self._stop_event.set()
        self._connected_event.set()  # unblock wait_connected callers
        self._stop_health_checker()
        self._disconnect_client(reason=None)
        if self._worker is not None:
            self._worker.join(timeout=15.0)
            self._worker = None
        self._set_state(ConnectionState.STOPPED)
        self._log.info("auto_reconnect_stopped")

    def wait_connected(self, timeout: Optional[float] = None) -> bool:
        """
        Block until the VPN is connected (or *timeout* seconds elapse).

        Returns *True* if connected, *False* on timeout.
        """
        return self._connected_event.wait(timeout=timeout)

    # ------------------------------------------------------------------
    # Background loop
    # ------------------------------------------------------------------

    def _run_loop(self) -> None:
        """Main reconnect loop executed in the worker thread."""
        attempt = 0
        self._backoff.reset()

        while not self._stop_event.is_set():
            attempt += 1
            self._set_state(
                ConnectionState.CONNECTING if attempt == 1
                else ConnectionState.RECONNECTING
            )

            self._log.info("vpn_connect_attempt", attempt=attempt)

            try:
                client = VPNClient(self._vpn_config)
                route = client.connect()
            except Exception as exc:
                self._log.warning(
                    "vpn_connect_failed", attempt=attempt, error=str(exc)
                )
                self._set_state(ConnectionState.DISCONNECTED)

                if self._rc_cfg.max_attempts > 0 and attempt >= self._rc_cfg.max_attempts:
                    self._log.error(
                        "vpn_max_attempts_reached", max_attempts=self._rc_cfg.max_attempts
                    )
                    self._set_state(ConnectionState.STOPPED)
                    return

                delay = self._backoff.next_delay()
                self._log.info("vpn_reconnect_wait", delay=delay, next_attempt=attempt + 1)
                if self.on_reconnecting is not None:
                    try:
                        self.on_reconnecting(attempt + 1, delay)
                    except Exception:
                        pass

                # Interruptible sleep
                self._stop_event.wait(timeout=delay)
                continue

            # --- Successfully connected ---
            self._client = client
            self._route_info = route
            self._backoff.reset()
            self._set_state(ConnectionState.CONNECTED)
            self._connected_event.set()

            if self.on_connected is not None:
                try:
                    self.on_connected(route)
                except Exception:
                    pass

            # Start health checker
            self._start_health_checker(client)

            # Wait until the connection is lost or stop is requested
            failure_exc = self._wait_for_failure()

            # --- Connection lost ---
            self._stop_health_checker()
            self._disconnect_client(reason=failure_exc)
            self._connected_event.clear()
            self._set_state(ConnectionState.DISCONNECTED)

            if self.on_disconnected is not None:
                try:
                    self.on_disconnected(failure_exc)
                except Exception:
                    pass

            if self._stop_event.is_set():
                break

            # Reset attempt counter for the next reconnect series
            attempt = 0
            self._backoff.reset()

        self._set_state(ConnectionState.STOPPED)

    # ------------------------------------------------------------------
    # Health checker helpers
    # ------------------------------------------------------------------

    def _start_health_checker(self, client: VPNClient) -> None:
        self._health_fail_event = threading.Event()
        self._health_fail_exc: Optional[Exception] = None

        def _on_failure(exc: Exception) -> None:
            self._health_fail_exc = exc
            self._health_fail_event.set()

        checker = HealthChecker(
            client=client,
            interval=self._rc_cfg.health_check_interval,
            timeout=self._rc_cfg.health_check_timeout,
            on_failure=_on_failure,
        )
        checker.start()
        self._health_checker = checker

    def _stop_health_checker(self) -> None:
        if self._health_checker is not None:
            self._health_checker.stop()
            self._health_checker = None

    def _wait_for_failure(self) -> Optional[Exception]:
        """
        Block until either:
        - The health checker signals a failure, or
        - The mux/data stream closes on its own, or
        - stop() is called.

        Returns the failure exception, or *None* if stop() was requested.
        """
        poll_interval = 1.0
        while not self._stop_event.is_set():
            # Health checker raised an alarm
            if self._health_fail_event.is_set():
                return self._health_fail_exc

            # Mux closed externally (e.g. server restarted)
            client = self._client
            if client is not None:
                mux = client._mux
                if mux is not None and mux._closed.is_set():
                    return ConnectionError("mux closed unexpectedly")
                if not client._connected.is_set():
                    return ConnectionError("client disconnected unexpectedly")

            self._stop_event.wait(timeout=poll_interval)

        return None

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    def _disconnect_client(self, reason: Optional[Exception]) -> None:
        client = self._client
        if client is not None:
            self._client = None
            try:
                client.disconnect()
            except Exception as exc:
                self._log.debug("disconnect_error", error=str(exc))

    def _set_state(self, new_state: ConnectionState) -> None:
        with self._state_lock:
            old = self._state
            self._state = new_state
        if old != new_state:
            self._log.debug("state_change", old=old.value, new=new_state.value)


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def create_auto_reconnect(
    server_addr: str,
    *,
    private_key_file: Optional[str] = None,
    reconnect_config: Optional[ReconnectConfig] = None,
    connect_timeout: float = 30.0,
    read_timeout: float = 60.0,
) -> AutoReconnect:
    """
    Convenience factory for the most common use case.

    Example::

        manager = create_auto_reconnect(
            "vpn.example.com:443",
            private_key_file="/etc/vpn/client.key",
        )
        manager.start()
        manager.wait_connected()
    """
    vpn_cfg = VPNConfig(
        server_addr=server_addr,
        private_key_file=private_key_file,
        connect_timeout=connect_timeout,
        read_timeout=read_timeout,
    )
    return AutoReconnect(vpn_cfg, reconnect_config)
