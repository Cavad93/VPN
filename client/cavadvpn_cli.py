#!/usr/bin/env python3
"""
cavadvpn_cli.py — CavadVPN command-line interface.

Provides connect/disconnect/status/config commands for the CavadVPN client.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

# Allow running from installed location as well as from source
_HERE = Path(__file__).parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

DEFAULT_CONFIG = Path.home() / ".config" / "cavadvpn" / "config.yaml"


def _load_config(path: Path) -> dict:
    """Load YAML config; return empty dict if file doesn't exist."""
    try:
        import yaml  # type: ignore
        with open(path) as fh:
            return yaml.safe_load(fh) or {}
    except FileNotFoundError:
        return {}
    except ImportError:
        # yaml not installed — return empty
        return {}


def _save_config(path: Path, cfg: dict) -> None:
    """Save config dict to YAML file, creating parent dirs as needed."""
    try:
        import yaml  # type: ignore
    except ImportError:
        print("ERROR: pyyaml not installed. Run: pip install pyyaml", file=sys.stderr)
        sys.exit(1)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as fh:
        yaml.safe_dump(cfg, fh, default_flow_style=False)


# ── Subcommands ───────────────────────────────────────────────────────────────

def cmd_status(_args: argparse.Namespace) -> int:
    """Show current VPN connection status."""
    # Attempt to read pid file written by connect command
    pid_file = Path.home() / ".config" / "cavadvpn" / "cavadvpn.pid"
    if pid_file.exists():
        pid = pid_file.read_text().strip()
        try:
            os.kill(int(pid), 0)  # signal 0 = existence check
            print(f"Status: CONNECTED (pid={pid})")
            return 0
        except (ProcessLookupError, ValueError):
            pass
    print("Status: DISCONNECTED")
    return 0


def _ensure_client_key(key_file: str) -> str:
    """Return path to client key file, generating a key pair if it doesn't exist."""
    path = Path(key_file)
    if path.exists():
        return key_file
    # Auto-generate a new X25519 key pair and save the private key as hex.
    try:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    except ImportError:
        print("ERROR: cryptography package not installed. Run: pip install cryptography", file=sys.stderr)
        sys.exit(1)
    priv = X25519PrivateKey.generate()
    priv_bytes = priv.private_bytes_raw()
    # RFC 7748 clamp
    b = bytearray(priv_bytes)
    b[0] &= 0xF8
    b[31] &= 0x7F
    b[31] |= 0x40
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(b.hex())
    path.chmod(0o600)
    print(f"Generated new client key → {path}")
    return key_file


def cmd_connect(args: argparse.Namespace) -> int:
    """Connect to VPN server."""
    config_path = Path(args.config)
    cfg = _load_config(config_path)

    server = args.server or cfg.get("server")
    if not server:
        print(
            "ERROR: Server address required. Use --server HOST:PORT or set 'server' in config.",
            file=sys.stderr,
        )
        return 1

    key_file = _ensure_client_key(
        args.key or cfg.get("private_key_file") or str(
            Path.home() / ".config" / "cavadvpn" / "client.key"
        )
    )

    server_key_hex = args.server_key or cfg.get("server_key") or ""

    # Telemetry: server URL for sending metrics (API port, not VPN port).
    # Defaults to http://<server_host>:8080, overridable via config or --telemetry-url.
    server_host = server.split(":")[0]
    telemetry_url = (
        args.telemetry_url
        or cfg.get("telemetry_url")
        or f"http://{server_host}:8080"
    )

    # Smart routing: probe blocklist BEFORE VPN connects if --auto-detect is on,
    # so probes go through the direct connection (not yet tunnelled).
    smart_router = None
    if getattr(args, "smart_route", False):
        try:
            from smart_route import create_smart_router  # type: ignore
            auto_detect = getattr(args, "auto_detect", False)
            if auto_detect:
                print("Smart route: probing blocked sites (this takes ~10 seconds)…")
            smart_router = create_smart_router(
                vpn_interface=cfg.get("tun_interface", ""),
                use_default_blocklist=True,
                auto_detect=auto_detect,
                probe_cache_file=str(
                    Path.home() / ".config" / "cavadvpn" / "probe_cache.json"
                ),
            )
            if auto_detect:
                # Run the probe NOW, before VPN changes the default route.
                smart_router._run_auto_detect()  # noqa: SLF001 — intentional pre-start probe
                auto_detect_done = True
            else:
                auto_detect_done = False
        except ImportError as exc:
            print(f"Warning: smart_route not available: {exc}", file=sys.stderr)
            smart_router = None
            auto_detect_done = False

    print(f"Connecting to {server} ...")
    if server_key_hex:
        print(f"Server key pinned: {server_key_hex[:16]}…")

    try:
        from core import VPNConfig, VPNClient  # type: ignore

        # server is already in "host:port" format — pass directly.
        vpn_cfg = VPNConfig(
            server_addr=server,
            private_key_file=key_file,
        )
        client = VPNClient(vpn_cfg)
        route = client.connect()
        print(f"Connected. Assigned IP: {route.assigned_ip}/{route.prefix_len}  Gateway: {route.gateway}")

        # Activate smart routing after VPN is up (routes now go through the tunnel).
        if smart_router is not None:
            try:
                # If auto_detect already ran, skip re-running it inside start().
                if auto_detect_done:
                    smart_router._config.auto_detect = False  # noqa: SLF001
                smart_router.start(vpn_gateway=route.gateway)
                st = smart_router.stats()
                print(
                    f"Smart route active: {st.blocked_domains} blocked domains, "
                    f"{st.blocked_ips} IPs → VPN, "
                    f"{st.direct_domains} direct"
                )
            except Exception as exc:  # noqa: BLE001
                print(f"Warning: smart route failed to start: {exc}", file=sys.stderr)
                smart_router = None

        # Start telemetry collector — sends metrics every 5 minutes.
        telemetry = None
        try:
            from telemetry import create_telemetry_collector  # type: ignore

            def _get_vpn_state():
                return {"server_addr": server, "state": "connected"}

            def _on_config_update(cfg: dict) -> None:
                """Автоматически применяет рекомендации AI агента."""
                # Обновляем транспортную информацию в следующем отчёте.
                transport = cfg.get("transport_mode", "")
                bonds = cfg.get("bond_count", 0)
                padding = cfg.get("padding_mode", "")
                sni_list = cfg.get("sni_hosts") or []
                sni = sni_list[0] if sni_list else ""
                if transport or bonds or padding or sni:
                    telemetry.set_transport_info(
                        transport_mode=transport,
                        bond_count=bonds,
                        sni_host=sni,
                        padding_mode=padding,
                    )
                print(f"[AI] Новый конфиг от сервера: transport={transport or '—'}, "
                      f"padding={padding or '—'}, sni={sni or '—'}")

            from telemetry import TelemetryConfig, TelemetryCollector  # type: ignore
            from telemetry import _generate_device_id, _detect_platform  # type: ignore

            tel_cfg = TelemetryConfig(
                server_url=telemetry_url,
                collect_interval=300.0,
                on_config_update=_on_config_update,
            )
            telemetry = TelemetryCollector(tel_cfg, get_vpn_state=_get_vpn_state)
            # Сообщаем текущий транспортный режим (UDP по умолчанию).
            telemetry.set_transport_info(transport_mode="udp", bond_count=0)
            telemetry.record_connect()
            telemetry.start()
            print(f"Telemetry active → {telemetry_url}")
        except Exception as exc:  # noqa: BLE001
            print(f"Warning: telemetry not started: {exc}", file=sys.stderr)

        # Write pid file
        pid_file = Path.home() / ".config" / "cavadvpn" / "cavadvpn.pid"
        pid_file.parent.mkdir(parents=True, exist_ok=True)
        pid_file.write_text(str(os.getpid()))

        # Block until interrupted
        import signal
        import time

        def _handle_signal(_sig, _frame):
            print("\nDisconnecting ...")
            if smart_router is not None:
                try:
                    smart_router.stop()
                    print("Smart route: routes removed.")
                except Exception:  # noqa: BLE001
                    pass
            if telemetry:
                telemetry.record_disconnect()
                telemetry.stop()
            client.disconnect()
            pid_file.unlink(missing_ok=True)
            sys.exit(0)

        signal.signal(signal.SIGINT, _handle_signal)
        signal.signal(signal.SIGTERM, _handle_signal)

        if smart_router is not None:
            print("Smart route ON: заблокированные сайты → VPN, российские → напрямую.")
        print("Press Ctrl+C to disconnect.")
        while True:
            time.sleep(1)

    except ImportError as exc:
        print(f"ERROR: Failed to import VPN core: {exc}", file=sys.stderr)
        print("Ensure the client library is installed in the virtualenv.", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


def cmd_disconnect(_args: argparse.Namespace) -> int:
    """Disconnect from VPN (sends SIGTERM to running process)."""
    pid_file = Path.home() / ".config" / "cavadvpn" / "cavadvpn.pid"
    if not pid_file.exists():
        print("No active VPN connection found.")
        return 0
    pid = pid_file.read_text().strip()
    try:
        os.kill(int(pid), 15)  # SIGTERM
        pid_file.unlink(missing_ok=True)
        print("Disconnected.")
    except ProcessLookupError:
        print("Process not found — cleaning up pid file.")
        pid_file.unlink(missing_ok=True)
    return 0


def cmd_config(args: argparse.Namespace) -> int:
    """Get or set configuration values."""
    config_path = Path(args.config)
    cfg = _load_config(config_path)

    if args.set:
        for pair in args.set:
            if "=" not in pair:
                print(f"ERROR: expected KEY=VALUE, got: {pair}", file=sys.stderr)
                return 1
            key, _, value = pair.partition("=")
            cfg[key.strip()] = value.strip()
        _save_config(config_path, cfg)
        print(f"Config saved to {config_path}")
    else:
        if cfg:
            for k, v in cfg.items():
                print(f"{k} = {v}")
        else:
            print(f"No config at {config_path}")
    return 0


def cmd_version(_args: argparse.Namespace) -> int:
    """Print version."""
    print("CavadVPN 1.0.0")
    return 0


# ── Argument parser ───────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cavadvpn",
        description="CavadVPN — secure VPN client",
    )
    parser.add_argument(
        "--config",
        default=str(DEFAULT_CONFIG),
        metavar="PATH",
        help="path to config file (default: %(default)s)",
    )

    subs = parser.add_subparsers(dest="command", metavar="COMMAND")

    subs.add_parser("status", help="show connection status")

    conn = subs.add_parser("connect", help="connect to VPN server")
    conn.add_argument("--server", metavar="HOST:PORT", help="server address")
    conn.add_argument("--key", metavar="FILE", help="private key file")
    conn.add_argument("--server-key", metavar="HEX",
                      help="server public key (64 hex chars); from GET /api/v1/qr/shared")
    conn.add_argument("--telemetry-url", metavar="URL",
                       help="telemetry endpoint (default: http://<server>:8080)")
    conn.add_argument(
        "--smart-route",
        action="store_true",
        default=True,
        help="умная маршрутизация (по умолчанию включена)",
    )
    conn.add_argument(
        "--no-smart-route",
        dest="smart_route",
        action="store_false",
        help="отключить умную маршрутизацию (весь трафик через VPN)",
    )
    conn.add_argument(
        "--auto-detect",
        action="store_true",
        default=False,
        help=(
            "с --smart-route: автоопределить заблокированные сайты TCP-пробой "
            "перед подключением (~10 с). Без этого флага используется встроенный список РКН."
        ),
    )

    subs.add_parser("disconnect", help="disconnect from VPN")

    cfg = subs.add_parser("config", help="get or set configuration")
    cfg.add_argument("--set", nargs="+", metavar="KEY=VALUE", help="set config values")

    subs.add_parser("version", help="print version")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    dispatch = {
        "status": cmd_status,
        "connect": cmd_connect,
        "disconnect": cmd_disconnect,
        "config": cmd_config,
        "version": cmd_version,
    }

    if args.command is None:
        parser.print_help()
        return 0

    handler = dispatch.get(args.command)
    if handler is None:
        parser.print_help()
        return 1

    return handler(args)


if __name__ == "__main__":
    sys.exit(main())
