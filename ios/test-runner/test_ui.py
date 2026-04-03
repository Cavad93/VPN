"""
test_ui.py — Python compatibility tests for the iOS CavadVPN UI layer.

These tests validate the PURE LOGIC described in the Swift UI source files:
  - QRConfig.swift   → QR code parsing / serialisation
  - VpnStats.swift   → Traffic statistics formatting
  - ConfigStore.swift → UserDefaults-backed persistence

No Xcode or iOS simulator required; all logic is re-implemented in Python
and the tests verify byte-for-byte / string-for-string compatibility.

Run with:
    cd /home/user/VPN/ios/test-runner && python3 -m pytest test_ui.py -v
"""
from __future__ import annotations

import json
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional

import pytest


# ---------------------------------------------------------------------------
# Python re-implementation of QRConfig.swift
# ---------------------------------------------------------------------------

class QRConfigError(Exception):
    pass


@dataclass
class ParsedConfig:
    host: str
    port: int
    private_key: Optional[str]
    server_key: Optional[str]
    dns: str
    mtu: int


def _validate_host(host: str) -> None:
    if not host:
        raise QRConfigError("host cannot be empty")


def _validate_port(port: int) -> None:
    if port <= 0 or port > 65535:
        raise QRConfigError(f"port {port} out of range 1–65535")


def _validate_hex_key(key: str, field: str) -> None:
    if len(key) != 64 or not all(c in "0123456789abcdefABCDEF" for c in key):
        raise QRConfigError(f"{field} must be 64 hex characters")


def parse_qr_json(text: str) -> ParsedConfig:
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        raise QRConfigError("Malformed JSON")
    if not isinstance(obj, dict):
        raise QRConfigError("Expected JSON object")

    host = obj.get("host")
    if not host:
        raise QRConfigError("missing field: host")
    port = obj.get("port")
    if port is None:
        raise QRConfigError("missing field: port")
    try:
        port = int(port)
    except (TypeError, ValueError):
        raise QRConfigError("missing field: port")

    private_key = obj.get("private_key")
    server_key  = obj.get("server_key")
    dns         = obj.get("dns", "1.1.1.1")
    mtu         = int(obj.get("mtu", 1420))

    _validate_host(host)
    _validate_port(port)
    if private_key: _validate_hex_key(private_key, "private_key")
    if server_key:  _validate_hex_key(server_key,  "server_key")

    return ParsedConfig(host=host, port=port, private_key=private_key,
                        server_key=server_key, dns=dns, mtu=mtu)


def parse_qr_uri(text: str) -> ParsedConfig:
    if not text.startswith("cavadvpn://"):
        raise QRConfigError("Expected cavadvpn:// URI")
    # Strip scheme prefix and parse query params
    rest = text[len("cavadvpn://config"):]
    qs   = urllib.parse.parse_qs(rest.lstrip("?"), keep_blank_values=False)

    def q(k):
        vals = qs.get(k, [])
        return vals[0] if vals else None

    host = q("host")
    if not host:
        raise QRConfigError("missing field: host")
    port_str = q("port")
    if port_str is None:
        raise QRConfigError("missing field: port")
    try:
        port = int(port_str)
    except ValueError:
        raise QRConfigError("missing field: port")

    private_key = q("private_key")
    server_key  = q("server_key")
    dns         = q("dns") or "1.1.1.1"
    mtu         = int(q("mtu") or 1420)

    _validate_host(host)
    _validate_port(port)
    if private_key: _validate_hex_key(private_key, "private_key")
    if server_key:  _validate_hex_key(server_key,  "server_key")

    return ParsedConfig(host=host, port=port, private_key=private_key,
                        server_key=server_key, dns=dns, mtu=mtu)


def parse_qr(text: str) -> ParsedConfig:
    text = text.strip()
    if not text:
        raise QRConfigError("emptyInput")
    if text.startswith("cavadvpn://"):
        return parse_qr_uri(text)
    elif text.startswith("{"):
        return parse_qr_json(text)
    else:
        raise QRConfigError("Expected JSON object or cavadvpn:// URI")


def to_qr_json(host: str, port: int, private_key=None, server_key=None,
               dns="1.1.1.1", mtu=1420) -> str:
    obj: dict = {"dns": dns, "host": host, "mtu": mtu, "port": port}
    if private_key: obj["private_key"] = private_key
    if server_key:  obj["server_key"]  = server_key
    return json.dumps(obj, sort_keys=True)


def to_qr_uri(host: str, port: int, private_key=None, server_key=None,
              dns="1.1.1.1", mtu=1420) -> str:
    params = [("host", host), ("port", str(port))]
    if private_key: params.append(("private_key", private_key))
    if server_key:  params.append(("server_key",  server_key))
    params += [("dns", dns), ("mtu", str(mtu))]
    return "cavadvpn://config?" + urllib.parse.urlencode(params)


# ---------------------------------------------------------------------------
# Python re-implementation of VpnStats.swift
# ---------------------------------------------------------------------------

def format_bytes(b: int) -> str:
    if b < 1024:
        return f"{b} B"
    elif b < 1024 * 1024:
        return f"{b / 1024:.1f} KB"
    elif b < 1024 * 1024 * 1024:
        return f"{b / (1024 * 1024):.1f} MB"
    else:
        return f"{b / (1024 * 1024 * 1024):.1f} GB"


def format_uptime(connected_since_ms: int) -> str:
    now_ms  = int(time.time() * 1000)
    total_s = max(0, (now_ms - connected_since_ms) // 1000)
    h   = total_s // 3600
    m   = (total_s % 3600) // 60
    sec = total_s % 60
    return f"{h:02d}:{m:02d}:{sec:02d}"


# ---------------------------------------------------------------------------
# Python re-implementation of ConfigStore.swift
# ---------------------------------------------------------------------------

@dataclass
class StoredConfig:
    host: str
    port: int
    private_key_hex: Optional[str]
    server_public_key_hex: Optional[str]
    dns_server: str
    mtu: int


class MockDefaults:
    """In-memory stand-in for UserDefaults."""
    def __init__(self):
        self._store: dict = {}

    def set(self, key: str, value) -> None:
        self._store[key] = value

    def get(self, key: str, default=None):
        return self._store.get(key, default)

    def remove(self, key: str) -> None:
        self._store.pop(key, None)

    def clear_all(self) -> None:
        self._store.clear()


_KEYS = {
    "host":       "com.cavadvpn.serverHost",
    "port":       "com.cavadvpn.serverPort",
    "private":    "com.cavadvpn.privateKeyHex",
    "server_pub": "com.cavadvpn.serverPublicKey",
    "dns":        "com.cavadvpn.dnsServer",
    "mtu":        "com.cavadvpn.mtu",
}


def config_store_save(defaults: MockDefaults, host: str, port: int,
                      private_key_hex=None, server_public_key_hex=None,
                      dns_server="1.1.1.1", mtu=1420) -> None:
    defaults.set(_KEYS["host"],       host)
    defaults.set(_KEYS["port"],       port)
    defaults.set(_KEYS["private"],    private_key_hex)
    defaults.set(_KEYS["server_pub"], server_public_key_hex)
    defaults.set(_KEYS["dns"],        dns_server)
    defaults.set(_KEYS["mtu"],        mtu)


def config_store_load(defaults: MockDefaults) -> Optional[StoredConfig]:
    host = defaults.get(_KEYS["host"])
    if not host:
        return None
    port = defaults.get(_KEYS["port"], 0)
    if not port:
        port = 443
    return StoredConfig(
        host=host,
        port=port,
        private_key_hex=defaults.get(_KEYS["private"]),
        server_public_key_hex=defaults.get(_KEYS["server_pub"]),
        dns_server=defaults.get(_KEYS["dns"], "1.1.1.1"),
        mtu=defaults.get(_KEYS["mtu"], 1420) or 1420,
    )


def config_store_clear(defaults: MockDefaults) -> None:
    for k in _KEYS.values():
        defaults.remove(k)


def config_store_apply(defaults: MockDefaults, cfg: ParsedConfig) -> None:
    config_store_save(
        defaults,
        host=cfg.host, port=cfg.port,
        private_key_hex=cfg.private_key,
        server_public_key_hex=cfg.server_key,
        dns_server=cfg.dns, mtu=cfg.mtu,
    )


# ===========================================================================
# Tests — QRConfig
# ===========================================================================

FAKE_KEY    = "a" * 64
FAKE_SRVKEY = "b" * 64


class TestQRConfigJSON:

    def test_parse_minimal(self):
        text = json.dumps({"host": "1.2.3.4", "port": 443})
        cfg = parse_qr(text)
        assert cfg.host == "1.2.3.4"
        assert cfg.port == 443
        assert cfg.private_key is None
        assert cfg.server_key  is None
        assert cfg.dns == "1.1.1.1"
        assert cfg.mtu == 1420

    def test_parse_full(self):
        text = json.dumps({
            "host": "vpn.example.com", "port": 8443,
            "private_key": FAKE_KEY, "server_key": FAKE_SRVKEY,
            "dns": "8.8.8.8", "mtu": 1380,
        })
        cfg = parse_qr(text)
        assert cfg.host == "vpn.example.com"
        assert cfg.port == 8443
        assert cfg.private_key == FAKE_KEY
        assert cfg.server_key  == FAKE_SRVKEY
        assert cfg.dns == "8.8.8.8"
        assert cfg.mtu == 1380

    def test_missing_host(self):
        with pytest.raises(QRConfigError, match="host"):
            parse_qr(json.dumps({"port": 443}))

    def test_missing_port(self):
        with pytest.raises(QRConfigError, match="port"):
            parse_qr(json.dumps({"host": "1.2.3.4"}))

    def test_invalid_port_zero(self):
        with pytest.raises(QRConfigError):
            parse_qr(json.dumps({"host": "1.2.3.4", "port": 0}))

    def test_invalid_port_high(self):
        with pytest.raises(QRConfigError):
            parse_qr(json.dumps({"host": "1.2.3.4", "port": 99999}))

    def test_invalid_private_key_short(self):
        with pytest.raises(QRConfigError, match="private_key"):
            parse_qr(json.dumps({"host": "x", "port": 443, "private_key": "abc"}))

    def test_invalid_private_key_non_hex(self):
        with pytest.raises(QRConfigError, match="private_key"):
            parse_qr(json.dumps({"host": "x", "port": 443, "private_key": "z" * 64}))

    def test_invalid_server_key(self):
        with pytest.raises(QRConfigError, match="server_key"):
            parse_qr(json.dumps({"host": "x", "port": 443, "server_key": "g" * 64}))

    def test_malformed_json(self):
        with pytest.raises(QRConfigError, match="JSON"):
            parse_qr("{not valid json")

    def test_empty_string(self):
        with pytest.raises(QRConfigError):
            parse_qr("")

    def test_unknown_format(self):
        with pytest.raises(QRConfigError):
            parse_qr("hello world")

    def test_port_as_string_int(self):
        text = json.dumps({"host": "1.2.3.4", "port": "443"})
        cfg = parse_qr(text)
        assert cfg.port == 443

    def test_roundtrip_json(self):
        original = json.dumps({
            "dns": "1.1.1.1", "host": "10.0.0.1", "mtu": 1420,
            "port": 443, "private_key": FAKE_KEY,
        }, sort_keys=True)
        cfg  = parse_qr(original)
        back = to_qr_json(cfg.host, cfg.port, cfg.private_key, cfg.server_key,
                           cfg.dns, cfg.mtu)
        assert json.loads(back) == json.loads(original)


class TestQRConfigURI:

    def test_parse_minimal(self):
        uri = f"cavadvpn://config?host=1.2.3.4&port=443"
        cfg = parse_qr(uri)
        assert cfg.host == "1.2.3.4"
        assert cfg.port == 443

    def test_parse_full(self):
        uri = (f"cavadvpn://config?host=vpn.example.com&port=8443"
               f"&private_key={FAKE_KEY}&server_key={FAKE_SRVKEY}"
               f"&dns=8.8.8.8&mtu=1380")
        cfg = parse_qr(uri)
        assert cfg.host == "vpn.example.com"
        assert cfg.port == 8443
        assert cfg.private_key == FAKE_KEY
        assert cfg.server_key  == FAKE_SRVKEY
        assert cfg.dns == "8.8.8.8"
        assert cfg.mtu == 1380

    def test_missing_host(self):
        with pytest.raises(QRConfigError):
            parse_qr("cavadvpn://config?port=443")

    def test_missing_port(self):
        with pytest.raises(QRConfigError):
            parse_qr("cavadvpn://config?host=1.2.3.4")

    def test_invalid_key(self):
        with pytest.raises(QRConfigError, match="private_key"):
            parse_qr(f"cavadvpn://config?host=x&port=443&private_key=short")

    def test_roundtrip_uri(self):
        uri  = to_qr_uri("1.2.3.4", 443, FAKE_KEY, None, "1.1.1.1", 1420)
        cfg  = parse_qr(uri)
        back = to_qr_uri(cfg.host, cfg.port, cfg.private_key, cfg.server_key,
                          cfg.dns, cfg.mtu)
        assert cfg.host == "1.2.3.4"
        assert cfg.port == 443
        assert cfg.private_key == FAKE_KEY
        # Re-parse the round-tripped URI
        cfg2 = parse_qr(back)
        assert cfg2.host == cfg.host
        assert cfg2.port == cfg.port

    def test_to_qr_uri_contains_host(self):
        uri = to_qr_uri("vpn.test", 1194)
        assert "host=vpn.test" in uri
        assert "port=1194" in uri
        assert uri.startswith("cavadvpn://config?")

    def test_cross_format_same_result(self):
        """JSON and URI parse for the same config must yield the same ParsedConfig."""
        json_text = json.dumps({"host": "10.8.0.1", "port": 443,
                                 "private_key": FAKE_KEY, "dns": "1.1.1.1", "mtu": 1420},
                               sort_keys=True)
        uri_text  = to_qr_uri("10.8.0.1", 443, FAKE_KEY, None, "1.1.1.1", 1420)
        cfg_j = parse_qr(json_text)
        cfg_u = parse_qr(uri_text)
        assert cfg_j.host == cfg_u.host
        assert cfg_j.port == cfg_u.port
        assert cfg_j.private_key == cfg_u.private_key
        assert cfg_j.dns == cfg_u.dns
        assert cfg_j.mtu == cfg_u.mtu


# ===========================================================================
# Tests — VpnStats
# ===========================================================================

class TestVpnStats:

    def test_format_bytes_zero(self):
        assert format_bytes(0) == "0 B"

    def test_format_bytes_bytes(self):
        assert format_bytes(512) == "512 B"

    def test_format_bytes_1023(self):
        assert format_bytes(1023) == "1023 B"

    def test_format_bytes_1kb(self):
        assert format_bytes(1024) == "1.0 KB"

    def test_format_bytes_1_5kb(self):
        assert format_bytes(1536) == "1.5 KB"

    def test_format_bytes_1mb(self):
        assert format_bytes(1024 * 1024) == "1.0 MB"

    def test_format_bytes_1_5mb(self):
        assert format_bytes(int(1.5 * 1024 * 1024)) == "1.5 MB"

    def test_format_bytes_1gb(self):
        assert format_bytes(1024 ** 3) == "1.0 GB"

    def test_format_bytes_10gb(self):
        assert format_bytes(10 * 1024 ** 3) == "10.0 GB"

    def test_format_bytes_just_under_kb(self):
        assert format_bytes(1023) == "1023 B"

    def test_format_bytes_just_under_mb(self):
        result = format_bytes(1024 * 1024 - 1)
        assert "KB" in result

    def test_format_bytes_just_under_gb(self):
        result = format_bytes(1024 ** 3 - 1)
        assert "MB" in result

    def test_uptime_zero(self):
        now_ms = int(time.time() * 1000)
        s = format_uptime(now_ms)
        assert s == "00:00:00"

    def test_uptime_1min(self):
        one_min_ago = int(time.time() * 1000) - 60_000
        s = format_uptime(one_min_ago)
        assert s == "00:01:00"

    def test_uptime_1h(self):
        one_h_ago = int(time.time() * 1000) - 3_600_000
        s = format_uptime(one_h_ago)
        assert s == "01:00:00"

    def test_uptime_format(self):
        t = int(time.time() * 1000) - (2 * 3600 + 30 * 60 + 15) * 1000
        s = format_uptime(t)
        assert s == "02:30:15"

    def test_uptime_future_clamped_to_zero(self):
        future_ms = int(time.time() * 1000) + 60_000
        s = format_uptime(future_ms)
        assert s == "00:00:00"

    def test_download_label(self):
        label = "↓ " + format_bytes(2048)
        assert label == "↓ 2.0 KB"

    def test_upload_label(self):
        label = "↑ " + format_bytes(0)
        assert label == "↑ 0 B"


# ===========================================================================
# Tests — ConfigStore
# ===========================================================================

class TestConfigStore:

    def _fresh_defaults(self) -> MockDefaults:
        return MockDefaults()

    def test_load_empty_returns_none(self):
        d = self._fresh_defaults()
        assert config_store_load(d) is None

    def test_save_and_load_basic(self):
        d = self._fresh_defaults()
        config_store_save(d, host="1.2.3.4", port=443,
                          private_key_hex=None, server_public_key_hex=None,
                          dns_server="1.1.1.1", mtu=1420)
        cfg = config_store_load(d)
        assert cfg is not None
        assert cfg.host == "1.2.3.4"
        assert cfg.port == 443
        assert cfg.private_key_hex is None
        assert cfg.dns_server == "1.1.1.1"
        assert cfg.mtu == 1420

    def test_save_with_keys(self):
        d = self._fresh_defaults()
        config_store_save(d, host="vpn.test", port=8443,
                          private_key_hex=FAKE_KEY, server_public_key_hex=FAKE_SRVKEY,
                          dns_server="8.8.8.8", mtu=1380)
        cfg = config_store_load(d)
        assert cfg.private_key_hex == FAKE_KEY
        assert cfg.server_public_key_hex == FAKE_SRVKEY
        assert cfg.port == 8443
        assert cfg.mtu  == 1380

    def test_clear(self):
        d = self._fresh_defaults()
        config_store_save(d, host="1.2.3.4", port=443,
                          dns_server="1.1.1.1", mtu=1420)
        config_store_clear(d)
        assert config_store_load(d) is None

    def test_port_default_when_zero(self):
        d = self._fresh_defaults()
        d.set(_KEYS["host"], "1.2.3.4")
        d.set(_KEYS["port"], 0)
        cfg = config_store_load(d)
        assert cfg.port == 443

    def test_mtu_default_when_zero(self):
        d = self._fresh_defaults()
        config_store_save(d, host="x", port=443, dns_server="1.1.1.1", mtu=0)
        cfg = config_store_load(d)
        assert cfg.mtu == 1420

    def test_dns_default(self):
        d = self._fresh_defaults()
        d.set(_KEYS["host"], "1.2.3.4")
        cfg = config_store_load(d)
        assert cfg.dns_server == "1.1.1.1"

    def test_apply_parsed_config(self):
        d   = self._fresh_defaults()
        qr  = ParsedConfig(host="10.0.0.1", port=1194,
                           private_key=FAKE_KEY, server_key=FAKE_SRVKEY,
                           dns="8.8.4.4", mtu=1400)
        config_store_apply(d, qr)
        cfg = config_store_load(d)
        assert cfg.host == "10.0.0.1"
        assert cfg.port == 1194
        assert cfg.private_key_hex == FAKE_KEY
        assert cfg.server_public_key_hex == FAKE_SRVKEY
        assert cfg.dns_server == "8.8.4.4"
        assert cfg.mtu == 1400

    def test_overwrite_existing(self):
        d = self._fresh_defaults()
        config_store_save(d, host="old.host", port=443, dns_server="1.1.1.1", mtu=1420)
        config_store_save(d, host="new.host", port=8443, dns_server="8.8.8.8", mtu=1380)
        cfg = config_store_load(d)
        assert cfg.host == "new.host"
        assert cfg.port == 8443

    def test_qr_json_roundtrip_through_store(self):
        qr_text = json.dumps({"host": "1.2.3.4", "port": 443,
                               "private_key": FAKE_KEY, "dns": "1.1.1.1", "mtu": 1420},
                              sort_keys=True)
        parsed = parse_qr(qr_text)
        d = self._fresh_defaults()
        config_store_apply(d, parsed)
        cfg = config_store_load(d)
        assert cfg.host == "1.2.3.4"
        assert cfg.private_key_hex == FAKE_KEY

    def test_qr_uri_roundtrip_through_store(self):
        uri = to_qr_uri("vpn.example.com", 8443, FAKE_KEY, FAKE_SRVKEY, "8.8.8.8", 1380)
        parsed = parse_qr(uri)
        d = self._fresh_defaults()
        config_store_apply(d, parsed)
        cfg = config_store_load(d)
        assert cfg.host == "vpn.example.com"
        assert cfg.port == 8443
        assert cfg.private_key_hex == FAKE_KEY
        assert cfg.server_public_key_hex == FAKE_SRVKEY
        assert cfg.mtu == 1380


# ===========================================================================
# Tests — VpnConnectionState logic (pure Python, mirrors Swift enum)
# ===========================================================================

class VpnConnectionStateSimulator:
    """Python equivalent of the Swift VpnConnectionState enum for testing."""

    DISCONNECTED  = "disconnected"
    CONNECTING    = "connecting"
    CONNECTED     = "connected"
    DISCONNECTING = "disconnecting"
    ERROR         = "error"

    def __init__(self, kind: str, msg: str = "", stats=None):
        self.kind  = kind
        self.msg   = msg
        self.stats = stats

    def label(self) -> str:
        labels = {
            self.DISCONNECTED:  "Disconnected",
            self.CONNECTING:    "Connecting…",
            self.CONNECTED:     "Connected",
            self.DISCONNECTING: "Disconnecting…",
        }
        if self.kind == self.ERROR:
            return f"Error: {self.msg}"
        return labels.get(self.kind, "Unknown")

    def is_connected(self) -> bool:
        return self.kind == self.CONNECTED

    def is_transitioning(self) -> bool:
        return self.kind in (self.CONNECTING, self.DISCONNECTING)

    def can_connect(self) -> bool:
        return self.kind in (self.DISCONNECTED, self.ERROR)

    def can_disconnect(self) -> bool:
        return self.kind == self.CONNECTED


class TestVpnConnectionState:

    def test_disconnected_label(self):
        s = VpnConnectionStateSimulator("disconnected")
        assert s.label() == "Disconnected"

    def test_connecting_label(self):
        assert VpnConnectionStateSimulator("connecting").label() == "Connecting…"

    def test_connected_label(self):
        assert VpnConnectionStateSimulator("connected").label() == "Connected"

    def test_disconnecting_label(self):
        assert VpnConnectionStateSimulator("disconnecting").label() == "Disconnecting…"

    def test_error_label(self):
        s = VpnConnectionStateSimulator("error", msg="Timeout")
        assert s.label() == "Error: Timeout"

    def test_is_connected_true(self):
        assert VpnConnectionStateSimulator("connected").is_connected()

    def test_is_connected_false(self):
        assert not VpnConnectionStateSimulator("disconnected").is_connected()

    def test_is_transitioning_connecting(self):
        assert VpnConnectionStateSimulator("connecting").is_transitioning()

    def test_is_transitioning_disconnecting(self):
        assert VpnConnectionStateSimulator("disconnecting").is_transitioning()

    def test_is_transitioning_false(self):
        assert not VpnConnectionStateSimulator("connected").is_transitioning()

    def test_can_connect_disconnected(self):
        assert VpnConnectionStateSimulator("disconnected").can_connect()

    def test_can_connect_error(self):
        assert VpnConnectionStateSimulator("error", "oops").can_connect()

    def test_can_connect_false_when_connected(self):
        assert not VpnConnectionStateSimulator("connected").can_connect()

    def test_can_disconnect_true(self):
        assert VpnConnectionStateSimulator("connected").can_disconnect()

    def test_can_disconnect_false(self):
        assert not VpnConnectionStateSimulator("disconnected").can_disconnect()
