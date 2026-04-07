#!/usr/bin/env python3
"""
ai_dashboard.py — Интерактивный дашборд AI агента VPN.

Запуск:
    python3 ai_dashboard.py --server http://10.8.0.1:8080 --token ТОКЕН

Управление (клавиши):
    a  — включить / выключить AI анализ
    t  — запустить анализ прямо сейчас (не ждать час)
    r  — обновить экран вручную
    q  — выход

Телеметрия собирается и отправляется автоматически каждые 5 минут.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import socket
import sys
import threading
import time
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path


# ── ANSI цвета ────────────────────────────────────────────────────────────────

ESC     = "\033"
RESET   = ESC + "[0m"
BOLD    = ESC + "[1m"
RED     = ESC + "[91m"
YELLOW  = ESC + "[93m"
GREEN   = ESC + "[92m"
CYAN    = ESC + "[96m"
GRAY    = ESC + "[90m"
WHITE   = ESC + "[97m"

def hide_cursor() -> str: return ESC + "[?25l"
def show_cursor() -> str: return ESC + "[?25h"


# ── HTTP ──────────────────────────────────────────────────────────────────────

class APIError(Exception):
    pass

def _req(method: str, url: str, token: str, body: dict | None = None) -> dict | None:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        resp = urllib.request.urlopen(req, timeout=8)
        raw = resp.read()
        return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        raise APIError(f"HTTP {e.code}: {e.read().decode(errors='replace')[:80]}")
    except urllib.error.URLError as e:
        raise APIError(f"Нет соединения: {e.reason}")
    except Exception as e:
        raise APIError(str(e))


# ── Встроенная телеметрия ─────────────────────────────────────────────────────

def _device_id() -> str:
    raw = "|".join([platform.node(), platform.machine(), platform.system()]).encode()
    return hashlib.sha256(raw).hexdigest()[:16]

def _tcp_ping(host: str, port: int) -> float:
    try:
        start = time.monotonic()
        s = socket.create_connection((host, port), timeout=5)
        ms = (time.monotonic() - start) * 1000
        s.close()
        return round(ms, 1)
    except Exception:
        return 0.0

def _dns_ms() -> float:
    try:
        start = time.monotonic()
        socket.getaddrinfo("google.com", 443, socket.AF_INET)
        return round((time.monotonic() - start) * 1000, 1)
    except Exception:
        return 0.0

def _packet_loss(host: str, port: int, count: int = 5) -> float:
    ok = 0
    for _ in range(count):
        try:
            s = socket.create_connection((host, port), timeout=2)
            s.close()
            ok += 1
        except Exception:
            pass
    return round(((count - ok) / count) * 100, 1)

def _send_telemetry(base: str, token: str, vpn_host: str, vpn_port: int,
                    bonds: int, tel_state: "TelState") -> None:
    """Собирает метрики и отправляет один отчёт на сервер."""
    ping = _tcp_ping(vpn_host, vpn_port)
    dns  = _dns_ms()
    loss = _packet_loss(vpn_host, vpn_port, count=4)

    report = {
        "device_id":            _device_id(),
        "platform":             platform.system().lower().replace("darwin", "macos"),
        "app_version":          "1.0.0",
        "timestamp":            time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "server_addr":          f"{vpn_host}:{vpn_port}",
        "connection_state":     "connected",
        "ping_ms":              ping,
        "packet_loss_percent":  loss,
        "dns_resolve_ms":       dns,
        "transport_mode":       "tcp" if bonds > 0 else "udp",
        "bond_count":           bonds,
        "dpi_detected":         False,
        "tls_errors":           0,
    }

    url  = base.rstrip("/") + "/api/v1/telemetry"
    data = json.dumps(report).encode()
    req  = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        urllib.request.urlopen(req, timeout=10).close()
        tel_state.last_sent = time.strftime("%H:%M:%S")
        tel_state.last_ping = ping
        tel_state.last_loss = loss
        tel_state.sent_count += 1
    except Exception:
        pass

class TelState:
    """Состояние телеметрии для отображения в UI."""
    def __init__(self):
        self.last_sent  = "—"
        self.last_ping  = 0.0
        self.last_loss  = 0.0
        self.sent_count = 0
        self.next_in    = 300  # секунд до следующей отправки

def telemetry_loop(base: str, token: str, vpn_host: str, vpn_port: int,
                   bonds: int, tel_state: TelState, stop: threading.Event) -> None:
    """Фоновый поток: отправляет телеметрию каждые 5 минут."""
    # Первая отправка через 30 секунд (VPN успевает подняться)
    for i in range(30, 0, -1):
        if stop.is_set():
            return
        tel_state.next_in = i
        time.sleep(1)

    while not stop.is_set():
        _send_telemetry(base, token, vpn_host, vpn_port, bonds, tel_state)
        for i in range(300, 0, -1):
            if stop.is_set():
                return
            tel_state.next_in = i
            time.sleep(1)


# ── Состояние дашборда ────────────────────────────────────────────────────────

class State:
    def __init__(self):
        self.lock          = threading.Lock()
        self.server_ok     = False
        self.ai_enabled: bool | None = None
        self.report_count  = 0
        self.last_report_time = ""
        self.analysis: dict = {}
        self.error         = ""
        self.status_msg    = ""
        self.status_time   = 0.0

    def set_status(self, msg: str):
        self.status_msg  = msg
        self.status_time = time.monotonic()


# ── Рендер ────────────────────────────────────────────────────────────────────

SEV_COLOR = {"critical": RED, "warning": YELLOW, "info": CYAN}
PRI_ICON  = {1: "●", 2: "◆", 3: "○"}

def _fmt_ts(iso: str) -> str:
    if not iso:
        return "—"
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return dt.astimezone().strftime("%d.%m %H:%M:%S")
    except Exception:
        return iso[:16]

def _wrap(text: str, width: int, indent: int = 5) -> list[str]:
    words, lines, line = text.split(), [], " " * indent
    for w in words:
        if len(line) + len(w) + 1 > width:
            lines.append(line)
            line = " " * indent + w + " "
        else:
            line += w + " "
    if line.strip():
        lines.append(line)
    return lines or [""]

def render(state: State, tel: TelState, base: str) -> None:
    now_str = datetime.now().strftime("%H:%M:%S")
    try:
        ts = os.get_terminal_size()
        width  = max(ts.columns, 70)
        height = ts.lines
    except Exception:
        width, height = 80, 24
    out: list[str] = []

    # ── Заголовок ──
    out.append(BOLD + WHITE + "─" * width + RESET)
    title = f"  🤖  CavadVPN AI Дашборд  ──  {base}  ──  {now_str}  "
    out.append(BOLD + WHITE + title + RESET)
    out.append(BOLD + WHITE + "─" * width + RESET)

    # ── Строка статуса ──
    srv   = (GREEN + "● Сервер OK" if state.server_ok else RED + "● Недоступен") + RESET
    if state.ai_enabled is None:
        ai_s = GRAY + "AI: ?" + RESET
    elif state.ai_enabled:
        ai_s = GREEN + "AI: ВКЛ ✓" + RESET
    else:
        ai_s = YELLOW + "AI: ВЫКЛ ✗" + RESET
    out.append(f"  {srv}   {ai_s}   {CYAN}Отчётов: {state.report_count}{RESET}")

    # ── Строка телеметрии ──
    ping_s = f"{tel.last_ping:.0f} ms" if tel.last_ping else "—"
    loss_s = f"{tel.last_loss:.0f}%" if tel.last_loss else "—"
    next_s = f"{tel.next_in}s" if tel.next_in > 0 else "сейчас"
    out.append(
        f"  {CYAN}Телеметрия:{RESET} отправлено {tel.sent_count}×   "
        f"последняя: {tel.last_sent}   "
        f"след. через {next_s}   "
        f"{GRAY}ping {ping_s}  loss {loss_s}{RESET}"
    )
    out.append("")

    # ── Статусное сообщение ──
    if state.status_msg and time.monotonic() - state.status_time < 5:
        out.append(f"  {YELLOW}▶ {state.status_msg}{RESET}")
        out.append("")

    if state.error:
        out.append(f"  {RED}Ошибка: {state.error}{RESET}")
        out.append("")

    # ── Анализ ──
    a = state.analysis
    if not a:
        out.append(f"  {GRAY}Анализ ещё не проводился.{RESET}")
        out.append(f"  Нажми {BOLD}t{RESET} — запустить сейчас.")
    else:
        ts = _fmt_ts(a.get("timestamp", ""))
        out.append(f"  {BOLD}Последний анализ:{RESET} {ts}  "
                   f"{GRAY}({a.get('report_count',0)} отчётов){RESET}")
        out.append("")

        summary = a.get("summary", "")
        if summary:
            out.append(f"  {BOLD}📊 Резюме:{RESET}")
            out += _wrap(summary, width - 6)
            out.append("")

        bypass = a.get("bypass_recommendations") or []
        if bypass:
            out.append(f"  {BOLD}{RED}🛡  Bypass ({len(bypass)}):{RESET}")
            for rec in sorted(bypass, key=lambda r: r.get("priority", 9)):
                icon = PRI_ICON.get(rec.get("priority", 3), "○")
                cfg  = rec.get("config") or {}
                out.append(f"   {RED}{icon}{RESET} {BOLD}{rec.get('action','')}{RESET}")
                out += _wrap(rec.get("description", ""), width - 8, 6)
                if cfg:
                    out.append(f"      {GRAY}{json.dumps(cfg, ensure_ascii=False)}{RESET}")
            out.append("")

        speed = a.get("speed_recommendations") or []
        if speed:
            out.append(f"  {BOLD}{GREEN}⚡ Speed ({len(speed)}):{RESET}")
            for rec in sorted(speed, key=lambda r: r.get("priority", 9)):
                icon = PRI_ICON.get(rec.get("priority", 3), "○")
                gain = rec.get("expected_gain", "")
                cfg  = rec.get("config") or {}
                gain_s = f"  {GREEN}+{gain}{RESET}" if gain else ""
                out.append(f"   {GREEN}{icon}{RESET} {BOLD}{rec.get('action','')}{RESET}{gain_s}")
                out += _wrap(rec.get("description", ""), width - 8, 6)
                if cfg:
                    out.append(f"      {GRAY}{json.dumps(cfg, ensure_ascii=False)}{RESET}")
            out.append("")

        acfg = a.get("actionable_config")
        if acfg:
            out.append(f"  {BOLD}{CYAN}🤖 Автоконфиг:{RESET}")
            for k, v in acfg.items():
                if v not in (None, "", 0, False, []):
                    out.append(f"    {CYAN}{k}:{RESET} {v}")
            out.append("")

        issues = a.get("issues") or []
        if issues:
            out.append(f"  {BOLD}⚠️  Проблемы:{RESET}")
            for iss in issues[:4]:
                col = SEV_COLOR.get(iss.get("severity", "info"), CYAN)
                out.append(f"   {col}[{iss.get('severity','').upper()}] "
                           f"{iss.get('category','')}{RESET}: "
                           f"{iss.get('description','')[:width-22]}")
            out.append("")

    # ── Нижняя панель ──
    out.append(BOLD + WHITE + "─" * width + RESET)
    ai_key = f"{GREEN}a: ВЫКЛ AI" if state.ai_enabled else f"{YELLOW}a: ВКЛ AI"
    out.append(f"  {ai_key}{RESET}   {CYAN}t: анализ сейчас{RESET}   "
               f"{GRAY}r: обновить   q: выход{RESET}")
    out.append(BOLD + WHITE + "─" * width + RESET)

    # Нижняя панель (3 строки) всегда приклеена к низу экрана.
    # Контент (всё кроме footer) обрезается по оставшемуся месту.
    FOOTER = 3
    footer  = out[-FOOTER:]          # separator + nav + separator
    body    = out[:-FOOTER]          # всё остальное
    body_rows = max(0, height - FOOTER - 1)
    visible = body[:body_rows]

    buf = hide_cursor() + ESC + "[?7l"   # отключаем перенос строк

    # Тело
    for i, line in enumerate(visible):
        buf += ESC + f"[{i + 1};1H" + line + ESC + "[K"

    # Зазор между телом и футером — очищаем строки
    for row in range(len(visible) + 1, height - FOOTER + 1):
        buf += ESC + f"[{row};1H" + ESC + "[K"

    # Футер — всегда на последних 3 строках
    for j, line in enumerate(footer):
        buf += ESC + f"[{height - FOOTER + j};1H" + line + ESC + "[K"

    buf += ESC + "[?7h"                   # восстанавливаем перенос строк
    sys.stdout.write(buf)
    sys.stdout.flush()


# ── Фон: обновления с сервера ─────────────────────────────────────────────────

def fetch_loop(base: str, token: str, state: State, interval: int) -> None:
    while True:
        try:
            _req("GET", f"{base}/api/v1/health", "")
            state.server_ok = True
            state.error = ""
        except APIError as e:
            state.server_ok = False
            state.error = str(e)

        try:
            ai = _req("GET", f"{base}/api/v1/telemetry/ai", token)
            state.ai_enabled = bool(ai.get("enabled")) if ai else False
        except APIError:
            pass

        try:
            reps = _req("GET", f"{base}/api/v1/telemetry?limit=1", token)
            if isinstance(reps, list) and reps:
                state.last_report_time = _fmt_ts(reps[-1].get("received_at", ""))
        except APIError:
            pass

        try:
            data = _req("GET", f"{base}/api/v1/telemetry/analysis", token)
            if data and "timestamp" in data:
                state.analysis = data
                state.report_count = data.get("report_count", state.report_count)
        except APIError:
            pass

        time.sleep(interval)


# ── Клавиатура ────────────────────────────────────────────────────────────────

def _read_key_unix() -> str:
    import tty, termios, select
    fd  = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        r, _, _ = select.select([sys.stdin], [], [], 0.2)
        if r:
            return sys.stdin.read(1)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)
    return ""

def _read_key_win() -> str:
    import msvcrt
    if msvcrt.kbhit():
        return msvcrt.getwch()
    time.sleep(0.1)
    return ""

read_key = _read_key_win if os.name == "nt" else _read_key_unix


# ── Действия ──────────────────────────────────────────────────────────────────

def toggle_ai(base: str, token: str, state: State) -> None:
    new_val = not state.ai_enabled if state.ai_enabled is not None else True
    try:
        r = _req("POST", f"{base}/api/v1/telemetry/ai", token, {"enabled": new_val})
        if r is not None:
            state.ai_enabled = r.get("enabled", new_val)
        state.set_status("AI " + ("включён ✓" if new_val else "выключен ✗"))
    except APIError as e:
        state.set_status(f"Ошибка: {e}")

def trigger_analysis(base: str, token: str, state: State) -> None:
    state.set_status("Запускаю анализ... (~15 сек)")
    try:
        data = _req("POST", f"{base}/api/v1/telemetry/analyze", token, {})
        if data and "timestamp" in data:
            state.analysis = data
            state.report_count = data.get("report_count", state.report_count)
            state.set_status("Анализ завершён ✓")
        else:
            state.set_status("Нет данных (сначала нужна телеметрия)")
    except APIError as e:
        state.set_status(f"Ошибка анализа: {e}")


# ── main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="CavadVPN AI Дашборд — мониторинг + телеметрия",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Пример (VPN уже подключён):
  python3 ai_dashboard.py \\
    --server http://10.8.0.1:8080 \\
    --token 8eb1b59111a447d3160127aa2c8a5322c00e69c6a1a3a84f6326a51c957fab2d \\
    --vpn-server 45.8.228.67:443 \\
    --bonds 64
        """,
    )
    parser.add_argument("--server", required=True, metavar="URL",
                        help="API сервера через VPN, напр. http://10.8.0.1:8080")
    parser.add_argument("--token", default="", metavar="TOKEN",
                        help="API токен из config.yaml")
    parser.add_argument("--vpn-server", default="", metavar="HOST:PORT",
                        help="адрес VPN сервера для измерения ping/loss (напр. 45.8.228.67:443)")
    parser.add_argument("--bonds", type=int, default=0, metavar="N",
                        help="число bonds (64 если запускаешь с -bonds 64)")
    parser.add_argument("--refresh", type=int, default=10, metavar="SEC",
                        help="интервал обновления дашборда в секундах (default: 10)")
    args = parser.parse_args()

    base = args.server.rstrip("/")

    # Определяем VPN хост/порт для ping
    vpn_host, vpn_port = "", 443
    if args.vpn_server:
        try:
            h, p = args.vpn_server.rsplit(":", 1)
            vpn_host, vpn_port = h, int(p)
        except ValueError:
            vpn_host = args.vpn_server
    else:
        # Пробуем достать хост из --server URL
        try:
            vpn_host = base.split("//")[1].split(":")[0]
        except Exception:
            pass

    state = State()
    tel   = TelState()
    stop  = threading.Event()

    # Фоновый поток: обновления с сервера
    threading.Thread(
        target=fetch_loop, args=(base, args.token, state, args.refresh),
        daemon=True,
    ).start()

    # Фоновый поток: сбор и отправка телеметрии
    if vpn_host:
        threading.Thread(
            target=telemetry_loop,
            args=(base, args.token, vpn_host, vpn_port, args.bonds, tel, stop),
            daemon=True,
        ).start()
    else:
        state.set_status("--vpn-server не указан, телеметрия не отправляется")

    time.sleep(1.5)  # ждём первого обновления

    # Очищаем экран один раз при старте
    if os.name != "nt":
        sys.stdout.write(ESC + "[2J" + ESC + "[H")
        sys.stdout.flush()
    else:
        os.system("cls")

    try:
        while True:
            render(state, tel, base)
            key = read_key().lower()
            if key == "q":
                break
            elif key == "a":
                threading.Thread(
                    target=toggle_ai, args=(base, args.token, state), daemon=True
                ).start()
            elif key == "t":
                threading.Thread(
                    target=trigger_analysis, args=(base, args.token, state), daemon=True
                ).start()
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        sys.stdout.write(ESC + "[2J" + ESC + "[H" + show_cursor())
        sys.stdout.flush()
        print("До свидания.")


if __name__ == "__main__":
    main()
