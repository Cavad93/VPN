#!/usr/bin/env python3
"""
ai_dashboard.py — Интерактивный дашборд AI агента VPN.

Запуск:
    python3 ai_dashboard.py --server http://АСТАНА:8080 --token ТОКЕН

Управление (клавиши):
    a  — включить / выключить AI анализ
    t  — запустить анализ прямо сейчас (не ждать час)
    r  — обновить экран вручную
    q  — выход
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path


# ── ANSI цвета ────────────────────────────────────────────────────────────────

ESC = "\033"
RESET  = ESC + "[0m"
BOLD   = ESC + "[1m"
RED    = ESC + "[91m"
YELLOW = ESC + "[93m"
GREEN  = ESC + "[92m"
CYAN   = ESC + "[96m"
BLUE   = ESC + "[94m"
GRAY   = ESC + "[90m"
WHITE  = ESC + "[97m"
MAGENTA = ESC + "[95m"

def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")

def move_to(row: int, col: int = 1) -> str:
    return f"{ESC}[{row};{col}H"

def hide_cursor() -> str:  return ESC + "[?25l"
def show_cursor() -> str:  return ESC + "[?25h"


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


# ── Модель состояния ──────────────────────────────────────────────────────────

class State:
    def __init__(self):
        self.lock = threading.Lock()
        self.server_ok = False
        self.ai_enabled: bool | None = None   # None = неизвестно
        self.report_count = 0
        self.last_report_time = ""
        self.analysis: dict = {}
        self.error = ""
        self.status_msg = ""          # однострочное сообщение о последнем действии
        self.status_time = 0.0
        self.refreshing = False

    def set_status(self, msg: str):
        with self.lock:
            self.status_msg = msg
            self.status_time = time.monotonic()


# ── Рендер дашборда ───────────────────────────────────────────────────────────

SEV_COLOR = {"critical": RED, "warning": YELLOW, "info": CYAN}
PRI_ICON  = {1: "●", 2: "◆", 3: "○"}

def _fmt_ts(iso: str) -> str:
    if not iso:
        return "—"
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        local = dt.astimezone()
        return local.strftime("%d.%m %H:%M:%S")
    except Exception:
        return iso[:16]

def _wrap(text: str, width: int, indent: int = 5) -> list[str]:
    words = text.split()
    lines, line = [], " " * indent
    for w in words:
        if len(line) + len(w) + 1 > width:
            lines.append(line)
            line = " " * indent + w + " "
        else:
            line += w + " "
    if line.strip():
        lines.append(line)
    return lines or [""]

def render(state: State, server: str) -> None:
    now_str = datetime.now().strftime("%H:%M:%S")
    width = max(os.get_terminal_size().columns, 60)

    lines: list[str] = []

    # Заголовок
    title = f" 🤖  CavadVPN AI Дашборд  ──  {server}  ──  {now_str} "
    pad = (width - len(title)) // 2
    lines.append(BOLD + WHITE + "─" * width + RESET)
    lines.append(" " * pad + BOLD + WHITE + title + RESET)
    lines.append(BOLD + WHITE + "─" * width + RESET)

    # Статус соединения и AI
    if state.server_ok:
        srv_str = GREEN + "● Сервер OK" + RESET
    else:
        srv_str = RED + "● Сервер недоступен" + RESET

    if state.ai_enabled is None:
        ai_str = GRAY + "AI: неизвестно" + RESET
    elif state.ai_enabled:
        ai_str = GREEN + "AI: ВКЛ ✓" + RESET
    else:
        ai_str = YELLOW + "AI: ВЫКЛ ✗" + RESET

    reports_str = CYAN + f"Отчётов: {state.report_count}" + RESET
    last_str = GRAY + f"Последний: {state.last_report_time}" + RESET

    lines.append(f"  {srv_str}   {ai_str}   {reports_str}   {last_str}")
    lines.append("")

    # Сообщение о последнем действии (исчезает через 5 сек)
    if state.status_msg and time.monotonic() - state.status_time < 5:
        lines.append(f"  {YELLOW}▶ {state.status_msg}{RESET}")
        lines.append("")

    if state.error:
        lines.append(f"  {RED}Ошибка: {state.error}{RESET}")
        lines.append("")

    analysis = state.analysis
    if not analysis:
        lines.append(f"  {GRAY}Анализ ещё не проводился.{RESET}")
        lines.append(f"  Нажми {BOLD}t{RESET} чтобы запустить немедленно.")
    else:
        # Время и количество
        ts = _fmt_ts(analysis.get("timestamp", ""))
        rc = analysis.get("report_count", 0)
        dc = analysis.get("device_count", 0)
        lines.append(f"  {BOLD}Последний анализ:{RESET} {ts}  {GRAY}({rc} отчётов, {dc} устройств){RESET}")
        lines.append("")

        # Резюме
        summary = analysis.get("summary", "")
        if summary:
            lines.append(f"  {BOLD}📊 Резюме:{RESET}")
            lines += _wrap(summary, width - 6)
            lines.append("")

        # DPI bypass рекомендации
        bypass = analysis.get("bypass_recommendations") or []
        if bypass:
            lines.append(f"  {BOLD}{RED}🛡  Bypass ({len(bypass)}):{RESET}")
            for rec in sorted(bypass, key=lambda r: r.get("priority", 9)):
                p = rec.get("priority", 3)
                icon = PRI_ICON.get(p, "○")
                action = rec.get("action", "")
                desc = rec.get("description", "")
                cfg = rec.get("config") or {}
                lines.append(f"   {RED}{icon}{RESET} {BOLD}{action}{RESET}")
                for l in _wrap(desc, width - 8, 6):
                    lines.append(l)
                if cfg:
                    lines.append(f"      {GRAY}{json.dumps(cfg, ensure_ascii=False)}{RESET}")
            lines.append("")

        # Speed рекомендации
        speed = analysis.get("speed_recommendations") or []
        if speed:
            lines.append(f"  {BOLD}{GREEN}⚡ Speed ({len(speed)}):{RESET}")
            for rec in sorted(speed, key=lambda r: r.get("priority", 9)):
                p = rec.get("priority", 3)
                icon = PRI_ICON.get(p, "○")
                action = rec.get("action", "")
                gain = rec.get("expected_gain", "")
                desc = rec.get("description", "")
                cfg = rec.get("config") or {}
                gain_s = f"  {GREEN}+{gain}{RESET}" if gain else ""
                lines.append(f"   {GREEN}{icon}{RESET} {BOLD}{action}{RESET}{gain_s}")
                for l in _wrap(desc, width - 8, 6):
                    lines.append(l)
                if cfg:
                    lines.append(f"      {GRAY}{json.dumps(cfg, ensure_ascii=False)}{RESET}")
            lines.append("")

        # Actionable config
        acfg = analysis.get("actionable_config")
        if acfg:
            lines.append(f"  {BOLD}{CYAN}🤖 Автоконфиг для клиентов:{RESET}")
            for k, v in acfg.items():
                if v not in (None, "", 0, False, []):
                    lines.append(f"    {CYAN}{k}:{RESET} {v}")
            lines.append("")

        # Проблемы
        issues = analysis.get("issues") or []
        if issues:
            lines.append(f"  {BOLD}⚠️  Проблемы:{RESET}")
            for issue in issues[:5]:  # максимум 5
                col = SEV_COLOR.get(issue.get("severity", "info"), CYAN)
                sev = issue.get("severity", "").upper()
                cat = issue.get("category", "")
                desc = issue.get("description", "")
                lines.append(f"   {col}[{sev}] {cat}{RESET}: {desc[:width - 20]}")
            lines.append("")

    # Нижняя панель управления
    lines.append(BOLD + WHITE + "─" * width + RESET)
    ai_toggle = f"{GREEN}a: ВЫКЛ AI{RESET}" if state.ai_enabled else f"{YELLOW}a: ВКЛ AI{RESET}"
    lines.append(
        f"  {ai_toggle}   "
        f"{CYAN}t: запустить анализ{RESET}   "
        f"{GRAY}r: обновить   q: выход{RESET}"
    )
    lines.append(BOLD + WHITE + "─" * width + RESET)

    # Рисуем весь экран за один раз
    sys.stdout.write(hide_cursor())
    sys.stdout.write(ESC + "[H")  # курсор в начало
    for line in lines:
        sys.stdout.write(line + ESC + "[K" + "\n")   # [K = очистить до конца строки
    # Очистить оставшиеся строки
    sys.stdout.write(ESC + "[J")
    sys.stdout.flush()


# ── Фоновые обновления ────────────────────────────────────────────────────────

def fetch_loop(base: str, token: str, state: State, interval: int) -> None:
    """Каждые interval секунд обновляет state с сервера."""
    while True:
        try:
            # health
            _req("GET", f"{base}/api/v1/health", "")
            with state.lock:
                state.server_ok = True
                state.error = ""
        except APIError as e:
            with state.lock:
                state.server_ok = False
                state.error = str(e)

        try:
            # AI статус
            ai = _req("GET", f"{base}/api/v1/telemetry/ai", token)
            with state.lock:
                state.ai_enabled = ai.get("enabled", False) if ai else False
        except APIError:
            pass

        try:
            # Число отчётов
            reports = _req("GET", f"{base}/api/v1/telemetry?limit=1", token)
            if isinstance(reports, list) and reports:
                with state.lock:
                    state.last_report_time = _fmt_ts(reports[-1].get("received_at", ""))
            # Общее количество через ?limit=0 не поддерживается — используем заголовок
        except APIError:
            pass

        try:
            # Последний анализ
            data = _req("GET", f"{base}/api/v1/telemetry/analysis", token)
            if data and "timestamp" in data:
                with state.lock:
                    state.analysis = data
                    state.report_count = data.get("report_count", state.report_count)
        except APIError:
            pass

        time.sleep(interval)


# ── Клавиатура (неблокирующая) ────────────────────────────────────────────────

def _read_key_unix() -> str:
    import tty, termios, select
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        r, _, _ = select.select([sys.stdin], [], [], 0.2)
        if r:
            ch = sys.stdin.read(1)
            return ch
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)
    return ""

def _read_key_win() -> str:
    import msvcrt
    if msvcrt.kbhit():
        return msvcrt.getwch()
    time.sleep(0.1)
    return ""

if os.name == "nt":
    read_key = _read_key_win
else:
    read_key = _read_key_unix


# ── Действия ──────────────────────────────────────────────────────────────────

def toggle_ai(base: str, token: str, state: State) -> None:
    current = state.ai_enabled
    new_val = not current if current is not None else True
    try:
        result = _req("POST", f"{base}/api/v1/telemetry/ai", token, {"enabled": new_val})
        if result is not None:
            with state.lock:
                state.ai_enabled = result.get("enabled", new_val)
            verb = "включён" if new_val else "выключен"
            state.set_status(f"AI {verb}")
    except APIError as e:
        state.set_status(f"Ошибка: {e}")

def trigger_analysis(base: str, token: str, state: State) -> None:
    state.set_status("Запускаю анализ...")
    try:
        data = _req("POST", f"{base}/api/v1/telemetry/analyze", token, {})
        if data:
            with state.lock:
                state.analysis = data
                state.report_count = data.get("report_count", state.report_count)
            state.set_status("Анализ завершён ✓")
        else:
            state.set_status("Нет данных для анализа")
    except APIError as e:
        state.set_status(f"Ошибка анализа: {e}")


# ── main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="AI дашборд CavadVPN")
    parser.add_argument("--server", required=True, metavar="URL",
                        help="адрес сервера, напр. http://1.2.3.4:8080")
    parser.add_argument("--token", default="", metavar="TOKEN",
                        help="API токен (из config.yaml → api.token)")
    parser.add_argument("--refresh", type=int, default=10, metavar="SEC",
                        help="интервал автообновления в секундах (default: 10)")
    args = parser.parse_args()
    base = args.server.rstrip("/")

    state = State()

    # Запускаем фоновый поток обновлений
    t = threading.Thread(
        target=fetch_loop,
        args=(base, args.token, state, args.refresh),
        daemon=True,
    )
    t.start()

    # Ждём первого обновления
    time.sleep(1.5)

    clear_screen()
    print(hide_cursor(), end="")

    try:
        while True:
            with state.lock:
                s = state  # безопасно читать без lock (GIL + атомарные чтения)
            render(s, base)

            # Читаем клавишу (таймаут ~0.2 сек)
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
            # 'r' или таймаут — просто перерисовываем

    except KeyboardInterrupt:
        pass
    finally:
        print(show_cursor())
        clear_screen()
        print("До свидания.")


if __name__ == "__main__":
    main()
