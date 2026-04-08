#!/usr/bin/env python3
"""
VPN Performance Diagnostics Tool

Collects metrics from the VPN server, relay (if present), and client perf
endpoints, then sends them to Claude Sonnet 4.6 for analysis.  The key
improvement over the previous version is that it can automatically identify
WHICH network segment is the bottleneck:

    MacBook ──[segment A]──► SPb relay ──[segment B]──► Astana VPN server
                                    ▲
                         relay-metrics endpoint (:9092)

When --relay-url is provided, the tool fetches per-segment byte-rate data
from the relay's /relay-metrics endpoint and feeds it to Claude so that
the analysis can pinpoint:

    ✗ Segment A bottleneck  (MacBook → SPb upload < expected)
    ✗ Segment B bottleneck  (SPb → Astana upload < segment A)
    ✗ SPb upload ceiling    (SPb → MacBook < Astana → SPb)
    ✗ BBR congestion window too small (both segments fine, but cwnd limits BDP)
    ✗ Protocol overhead     (drop rate > 0 → queue full → retransmit storms)

Usage:
    # One-shot analysis (no relay)
    python3 vpn_diagnostics.py --server-url http://astana:8080

    # With relay metrics (recommended for SPb→Astana topology)
    python3 vpn_diagnostics.py \\
        --server-url  http://astana:8080 \\
        --relay-url   http://spb:9092 \\
        --client-url  http://127.0.0.1:9091

    # Continuous monitoring every 5 minutes
    python3 vpn_diagnostics.py \\
        --server-url http://astana:8080 --relay-url http://spb:9092 \\
        --interval 300

Environment:
    ANTHROPIC_API_KEY  — required; your Anthropic API key
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MODEL_ID = "claude-sonnet-4-6"
API_URL = "https://api.anthropic.com/v1/messages"
DEFAULT_REPORT_FILE = "vpn_perf_report.jsonl"
DEFAULT_MAX_REQUESTS_PER_HOUR = 12  # one every 5 min
DEFAULT_INTERVAL_SECONDS = 300      # 5 min
MAX_TOKENS = 4096

# ---------------------------------------------------------------------------
# Metrics collection
# ---------------------------------------------------------------------------


def fetch_json(url: str, token: str = "") -> Optional[dict]:
    """GET a JSON endpoint. Returns None on failure."""
    req = urllib.request.Request(url)
    req.add_header("Accept", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except (urllib.error.URLError, OSError, json.JSONDecodeError) as e:
        print(f"[warn] Failed to fetch {url}: {e}", file=sys.stderr)
        return None


def collect_server_metrics(base_url: str, token: str = "") -> dict:
    """Collect all available metrics from the VPN server API."""
    metrics: dict = {}
    perf = fetch_json(f"{base_url}/api/v1/perf", token)
    if perf:
        metrics["perf"] = perf
    sessions = fetch_json(f"{base_url}/api/v1/sessions", token)
    if sessions is not None:
        metrics["sessions"] = sessions
    stats = fetch_json(f"{base_url}/api/v1/stats", token)
    if stats:
        metrics["stats"] = stats
    health = fetch_json(f"{base_url}/api/v1/health")
    if health:
        metrics["health"] = health
    return metrics


def collect_relay_metrics(base_url: str) -> Optional[dict]:
    """Collect per-segment throughput metrics from the relay's /relay-metrics endpoint.

    Returns a dict with keys like client_rx_mbps, upstream_tx_mbps, etc.
    Returns None if the relay metrics endpoint is unavailable.
    """
    return fetch_json(f"{base_url}/relay-metrics")


def collect_client_metrics(base_url: str) -> Optional[dict]:
    """Collect metrics from the client's local perf HTTP endpoint."""
    return fetch_json(f"{base_url}/perf")


# ---------------------------------------------------------------------------
# Bottleneck pre-analysis (deterministic, runs before Claude)
# ---------------------------------------------------------------------------


def _mbps(bps: float) -> str:
    """Format bytes/s as Mbit/s string."""
    return f"{bps * 8 / 1_000_000:.2f} Mbit/s"


def pre_analyze_relay(relay: dict) -> list[str]:
    """Compute deterministic bottleneck hints from relay metrics.

    Returns a list of human-readable observations that are prepended to the
    Claude prompt.  This gives Claude concrete numbers to reason about instead
    of asking it to infer from raw bytes.
    """
    hints: list[str] = []

    client_rx   = relay.get("client_rx_bps", 0)    # MacBook → SPb
    client_tx   = relay.get("client_tx_bps", 0)    # SPb → MacBook
    upstream_tx = relay.get("upstream_tx_bps", 0)  # SPb → Astana
    upstream_rx = relay.get("upstream_rx_bps", 0)  # Astana → SPb
    drops       = relay.get("client_drops", 0)
    sessions    = relay.get("active_sessions", 0)
    fwd_eff     = relay.get("forward_efficiency")
    dl_eff      = relay.get("downlink_efficiency")

    if sessions == 0:
        hints.append("⚠ No active relay sessions — relay may be idle or clients disconnected.")
        return hints

    # Upload path: MacBook → SPb → Astana
    if client_rx > 0 and upstream_tx > 0:
        ratio = upstream_tx / client_rx
        if ratio < 0.90:
            hints.append(
                f"🔴 UPLOAD BOTTLENECK (MacBook→SPb→Astana): relay receives {_mbps(client_rx)} "
                f"from client but only forwards {_mbps(upstream_tx)} to Astana "
                f"(efficiency {ratio*100:.0f}%). Likely cause: SPb→Astana link saturation or "
                f"send-queue drops (drops={drops})."
            )
        else:
            hints.append(
                f"✅ Upload path healthy: MacBook→SPb {_mbps(client_rx)}, "
                f"SPb→Astana {_mbps(upstream_tx)} (efficiency {ratio*100:.0f}%)."
            )

    # Download path: Astana → SPb → MacBook
    if upstream_rx > 0 and client_tx > 0:
        ratio = client_tx / upstream_rx
        if ratio < 0.90:
            hints.append(
                f"🔴 DOWNLOAD BOTTLENECK (Astana→SPb→MacBook): Astana sends {_mbps(upstream_rx)} "
                f"to relay but relay delivers only {_mbps(client_tx)} to MacBook "
                f"(efficiency {ratio*100:.0f}%). "
                f"Likely cause: SPb upload bandwidth ceiling (SPb upload ≤ {_mbps(client_tx)})."
            )
        else:
            hints.append(
                f"✅ Download path healthy: Astana→SPb {_mbps(upstream_rx)}, "
                f"SPb→MacBook {_mbps(client_tx)} (efficiency {ratio*100:.0f}%)."
            )

    # Segment A vs B comparison (to identify which segment is slower)
    if client_rx > 0 and upstream_rx > 0:
        if client_rx < upstream_rx * 0.5:
            hints.append(
                f"🔴 SEGMENT A SLOWER THAN B: MacBook→SPb {_mbps(client_rx)} vs "
                f"Astana→SPb {_mbps(upstream_rx)} — segment A (MacBook upload or SPb download) "
                f"is less than 50% of segment B. Client may have bandwidth asymmetry or "
                f"ISP throttling on upload."
            )
        if upstream_rx < client_rx * 0.5:
            hints.append(
                f"🔴 SEGMENT B SLOWER THAN A: Astana→SPb {_mbps(upstream_rx)} vs "
                f"MacBook→SPb {_mbps(client_rx)} — segment B (Astana upload) is the bottleneck. "
                f"Consider increasing Astana server upload capacity."
            )

    # Drop pressure
    if drops > 100:
        hints.append(
            f"🔴 HIGH DROP COUNT: {drops} packets dropped (send queue full). "
            f"This causes retransmits and spikes RTO. Increase sendCh buffer or reduce offered load."
        )
    elif drops > 0:
        hints.append(f"⚠ Minor drops: {drops} packets (send queue briefly full).")

    return hints


# ---------------------------------------------------------------------------
# Claude API interaction
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """\
You are a VPN performance diagnostics expert. You analyze performance metrics
from a custom VPN implementation running in Russia and identify bottlenecks.

## VPN Architecture

    MacBook ──[segment A: UDP/BBR]──► SPb relay (Windows) ──[segment B: UDP]──► Astana server (Windows)
                                            ▲
                                   relay-metrics endpoint

The relay is a transparent UDP forwarder.  It does NOT decrypt traffic.
Noise_XX handshake and all encryption happen end-to-end: MacBook ↔ Astana.

Known bandwidth ceilings (from ISP speed tests):
- SPb server upload   ≈ 7.6 Mbit/s  → this is the MAXIMUM download speed for MacBook
- Astana server upload ≈ 14 Mbit/s  → this is the MAXIMUM upload speed for MacBook

## Per-Segment Relay Metrics (if provided)

    client_rx_bps    = bytes/s MacBook → SPb       (segment A upload)
    upstream_tx_bps  = bytes/s SPb → Astana        (segment A→B)
    upstream_rx_bps  = bytes/s Astana → SPb        (segment B download)
    client_tx_bps    = bytes/s SPb → MacBook       (segment A download)

    forward_efficiency  = upstream_tx / client_rx  (should be ≥ 0.95)
    downlink_efficiency = client_tx / upstream_rx  (should be ≥ 0.95)

## Bottleneck Identification Rules

1. If client_tx_mbps < SPb_upload_ceiling × 0.80:
   → SPb upload is NOT the ceiling; bottleneck is elsewhere.

2. If client_tx_mbps ≈ SPb_upload_ceiling (7.6 Mbit/s):
   → SPb upload IS the bottleneck.  Recommend: second relay / different exit node.

3. If client_rx_mbps >> client_tx_mbps (client downloads little, uploads fine):
   → Asymmetric congestion; BBR cwnd may be too small for BDP.
   → Check: BDP = bandwidth × RTT.  Seed BBR with correct RTT.

4. If forward_efficiency < 0.95:
   → Relay dropping packets; send-queue too small or upstream link saturated.

5. If both segments look fine but VPN speed is low:
   → Protocol overhead (AEAD 16B + Mux 7B + Noise 2B + TLS 5B = 30B per packet)
   → MTU mismatch (inner packets > 1350B get split into 2 UDP datagrams)
   → BBR seed RTT wrong (too conservative initial cwnd)

## Your Task

Analyze the provided metrics and produce ONE JSON response with:
1. The PRIMARY bottleneck with SEGMENT identification (A, B, or protocol layer).
2. Concrete fix with expected impact.
3. Overall health rating.

Be concise. Use exact numbers from the data. Identify the segment.
"""


def build_user_message(
    server_metrics: dict,
    relay_metrics: Optional[dict],
    client_metrics: Optional[dict],
    relay_hints: list[str],
    previous_report: Optional[dict],
) -> str:
    """Build the user message for Claude from collected metrics."""
    parts: list[str] = []

    # Pre-computed bottleneck hints (deterministic analysis).
    if relay_hints:
        parts.append("## Pre-Analysis: Relay Segment Observations\n")
        for hint in relay_hints:
            parts.append(f"  {hint}\n")
        parts.append("")

    # Relay metrics (most important for bottleneck identification).
    if relay_metrics:
        parts.append("## Relay Metrics (per-segment throughput)\n```json")
        parts.append(json.dumps(relay_metrics, indent=2, default=str))
        parts.append("```\n")

    # Server metrics.
    parts.append("## Astana VPN Server Metrics\n```json")
    parts.append(json.dumps(server_metrics, indent=2, default=str))
    parts.append("```\n")

    # Client metrics.
    if client_metrics:
        parts.append("## MacBook Client Metrics\n```json")
        parts.append(json.dumps(client_metrics, indent=2, default=str))
        parts.append("```\n")

    # Trend comparison.
    if previous_report:
        prev_analysis = previous_report.get("analysis", "")
        if prev_analysis:
            parts.append("## Previous Analysis (for trend comparison)\n```")
            parts.append(prev_analysis[:800])  # cap to save tokens
            parts.append("```\n")

    parts.append(
        "Analyze these metrics. Identify the PRIMARY bottleneck by segment "
        "(A=MacBook↔SPb, B=SPb↔Astana, or protocol layer). "
        "Give ONE concrete fix with expected throughput gain.\n\n"
        "Respond with EXACTLY this JSON (no markdown, no extra text):\n"
        "{\n"
        '  "bottleneck_segment": "A|B|protocol|unknown",\n'
        '  "bottleneck_cause": "one-line root cause with numbers",\n'
        '  "primary_fix": "concrete action",\n'
        '  "expected_gain": "e.g. +2 Mbit/s download",\n'
        '  "health": "GOOD|DEGRADED|CRITICAL",\n'
        '  "issues": [\n'
        '    {"severity": "critical|warning|info", "description": "...with numbers"}\n'
        "  ],\n"
        '  "summary": "2-3 sentence overall assessment"\n'
        "}"
    )

    return "\n".join(parts)


def analyze_with_claude(
    api_key: str,
    server_metrics: dict,
    relay_metrics: Optional[dict],
    client_metrics: Optional[dict],
    relay_hints: list[str],
    previous_report: Optional[dict] = None,
) -> dict:
    """Send metrics to Claude Sonnet 4.6 and get analysis."""

    user_content = build_user_message(
        server_metrics, relay_metrics, client_metrics, relay_hints, previous_report
    )

    payload = {
        "model": MODEL_ID,
        "max_tokens": MAX_TOKENS,
        "system": SYSTEM_PROMPT,
        "messages": [{"role": "user", "content": user_content}],
    }

    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        API_URL,
        data=data,
        headers={
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            result = json.loads(resp.read())
        text = ""
        for block in result.get("content", []):
            if block.get("type") == "text":
                text += block["text"]
        usage = result.get("usage", {})
        # Try to parse structured JSON response.
        parsed_analysis = None
        try:
            parsed_analysis = json.loads(text)
        except json.JSONDecodeError:
            pass
        return {
            "analysis": text,
            "parsed": parsed_analysis,
            "input_tokens": usage.get("input_tokens", 0),
            "output_tokens": usage.get("output_tokens", 0),
            "model": MODEL_ID,
        }
    except urllib.error.HTTPError as e:
        body = e.read().decode() if e.fp else ""
        return {"error": f"HTTP {e.code}: {body}", "analysis": ""}
    except Exception as e:
        return {"error": str(e), "analysis": ""}


# ---------------------------------------------------------------------------
# Report management
# ---------------------------------------------------------------------------


def save_report(report: dict, filepath: str) -> None:
    """Append a report as one JSON line to the report file."""
    with open(filepath, "a") as f:
        f.write(json.dumps(report, default=str) + "\n")


def load_last_report(filepath: str) -> Optional[dict]:
    """Load the most recent report from the JSONL file."""
    path = Path(filepath)
    if not path.exists():
        return None
    try:
        lines = path.read_text().strip().split("\n")
        if lines and lines[-1]:
            return json.loads(lines[-1])
    except (json.JSONDecodeError, IndexError):
        pass
    return None


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------


class RateLimiter:
    """Simple token-bucket rate limiter."""

    def __init__(self, max_per_hour: int):
        self._interval = 3600.0 / max(max_per_hour, 1)
        self._last_call = 0.0

    def wait(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_call
        if elapsed < self._interval:
            wait_time = self._interval - elapsed
            print(f"[rate-limit] Waiting {wait_time:.0f}s before next API call...")
            time.sleep(wait_time)
        self._last_call = time.monotonic()


# ---------------------------------------------------------------------------
# Pretty-print structured analysis result
# ---------------------------------------------------------------------------


def print_analysis(result: dict) -> None:
    """Print analysis result in a readable format."""
    parsed = result.get("parsed")
    if parsed:
        seg = parsed.get("bottleneck_segment", "unknown")
        seg_label = {
            "A": "Segment A (MacBook ↔ SPb relay)",
            "B": "Segment B (SPb relay ↔ Astana)",
            "protocol": "Protocol/congestion layer",
            "unknown": "Unknown",
        }.get(seg, seg)

        health = parsed.get("health", "?")
        health_icon = {"GOOD": "✅", "DEGRADED": "⚠️ ", "CRITICAL": "🔴"}.get(health, "❓")

        print(f"\n{'─'*60}")
        print(f" {health_icon} Health: {health}")
        print(f" 🎯 Bottleneck: {seg_label}")
        print(f"    Cause:  {parsed.get('bottleneck_cause', '')}")
        print(f"    Fix:    {parsed.get('primary_fix', '')}")
        print(f"    Gain:   {parsed.get('expected_gain', '')}")
        issues = parsed.get("issues", [])
        if issues:
            print(f"\n Issues ({len(issues)}):")
            for iss in issues:
                sev_icon = {"critical": "🔴", "warning": "⚠️ ", "info": "ℹ️ "}.get(
                    iss.get("severity", ""), "•"
                )
                print(f"   {sev_icon} {iss.get('description', '')}")
        print(f"\n {parsed.get('summary', '')}")
        print(f"{'─'*60}")
    else:
        # Fall back to raw text.
        print(f"\n{'─'*60}")
        print("ANALYSIS:")
        print(f"{'─'*60}")
        raw = result.get("analysis", "")
        print(raw[:3000] if len(raw) > 3000 else raw)
        print(f"{'─'*60}")

    tokens_in  = result.get("input_tokens", 0)
    tokens_out = result.get("output_tokens", 0)
    print(f"[tokens] in={tokens_in} out={tokens_out} total={tokens_in + tokens_out}")


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------


def run_once(
    args: argparse.Namespace,
    api_key: str,
    rate_limiter: RateLimiter,
    report_file: str,
) -> dict:
    """Collect metrics, analyze, save report. Returns the report dict."""
    print(f"\n{'='*60}")
    print(f"[{datetime.now(timezone.utc).isoformat()}] Collecting metrics...")

    server_metrics = collect_server_metrics(args.server_url, args.api_token or "")
    if not server_metrics:
        print("[error] No server metrics available. Is the server running?")
        return {"error": "no server metrics"}

    relay_metrics = None
    relay_hints: list[str] = []
    if args.relay_url:
        relay_metrics = collect_relay_metrics(args.relay_url)
        if relay_metrics:
            relay_hints = pre_analyze_relay(relay_metrics)
            print(f"[info] Relay metrics: {relay_metrics.get('active_sessions', 0)} sessions, "
                  f"↓{relay_metrics.get('client_tx_mbps', 0):.2f} Mbit/s to client, "
                  f"↑{relay_metrics.get('upstream_tx_mbps', 0):.2f} Mbit/s to upstream")
            if relay_hints:
                print("[relay pre-analysis]")
                for h in relay_hints:
                    print(f"  {h}")
        else:
            print("[warn] Relay metrics unavailable — bottleneck identification will be limited.")

    client_metrics = None
    if args.client_url:
        client_metrics = collect_client_metrics(args.client_url)
        if not client_metrics:
            print("[warn] No client metrics available.")

    previous = load_last_report(report_file)

    if args.dry_run:
        print("\n[dry-run] Metrics collected (no Claude API call).")
        if relay_hints:
            print("\nRelay bottleneck hints:")
            for h in relay_hints:
                print(f"  {h}")
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "server_metrics": server_metrics,
            "relay_metrics": relay_metrics,
            "client_metrics": client_metrics,
            "relay_hints": relay_hints,
        }

    print(f"[info] Sending to Claude {MODEL_ID} for analysis...")
    rate_limiter.wait()

    result = analyze_with_claude(
        api_key, server_metrics, relay_metrics, client_metrics, relay_hints, previous
    )

    if result.get("error"):
        print(f"[error] Claude API: {result['error']}", file=sys.stderr)

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "server_metrics": server_metrics,
        "relay_metrics": relay_metrics,
        "client_metrics": client_metrics,
        "relay_hints": relay_hints,
        **result,
    }

    save_report(report, report_file)
    print(f"[info] Report saved to {report_file}")
    print_analysis(result)

    return report


def main():
    parser = argparse.ArgumentParser(
        description="VPN Performance Diagnostics with Claude Sonnet 4.6 — per-segment bottleneck analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--server-url",
        required=True,
        help="Astana VPN server API base URL (e.g. http://astana-ip:8080)",
    )
    parser.add_argument(
        "--relay-url",
        default=None,
        help="SPb relay metrics endpoint (e.g. http://spb-ip:9092); enables per-segment analysis",
    )
    parser.add_argument(
        "--client-url",
        default=None,
        help="MacBook client perf HTTP endpoint (e.g. http://127.0.0.1:9091)",
    )
    parser.add_argument(
        "--api-token",
        default=os.environ.get("VPN_API_TOKEN", ""),
        help="VPN server API Bearer token (or VPN_API_TOKEN env var)",
    )
    parser.add_argument(
        "--report-file",
        default=DEFAULT_REPORT_FILE,
        help=f"Path to JSONL report file (default: {DEFAULT_REPORT_FILE})",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=0,
        help="Seconds between checks (0 = one-shot, default: 0)",
    )
    parser.add_argument(
        "--max-requests-per-hour",
        type=int,
        default=DEFAULT_MAX_REQUESTS_PER_HOUR,
        help=f"Max Claude API requests per hour (default: {DEFAULT_MAX_REQUESTS_PER_HOUR})",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Collect and print metrics without calling Claude API",
    )

    args = parser.parse_args()

    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key and not args.dry_run:
        print("[error] ANTHROPIC_API_KEY environment variable is required.", file=sys.stderr)
        sys.exit(1)

    report_file = args.report_file
    rate_limiter = RateLimiter(args.max_requests_per_hour)

    print(f"VPN Diagnostics — Claude {MODEL_ID}")
    print(f"  Astana server: {args.server_url}")
    print(f"  SPb relay:     {args.relay_url or '(not configured — bottleneck identification limited)'}")
    print(f"  Client:        {args.client_url or '(not configured)'}")
    print(f"  Report file:   {report_file}")
    print(f"  Rate limit:    {args.max_requests_per_hour} req/hour")
    print(f"  Interval:      {'one-shot' if args.interval == 0 else f'{args.interval}s'}")

    stop = False

    def on_signal(signum, frame):
        nonlocal stop
        stop = True
        print("\n[info] Shutting down...")

    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)

    if args.interval == 0:
        run_once(args, api_key, rate_limiter, report_file)
    else:
        print(f"\n[info] Starting continuous monitoring (Ctrl+C to stop)...")
        while not stop:
            run_once(args, api_key, rate_limiter, report_file)
            if stop:
                break
            for _ in range(args.interval):
                if stop:
                    break
                time.sleep(1)

    print("[info] Done.")


if __name__ == "__main__":
    main()
