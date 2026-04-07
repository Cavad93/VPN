#!/usr/bin/env python3
"""
ai_monitor.py — Мониторинг AI анализа VPN в реальном времени.

Запуск:
    python3 ai_monitor.py --server http://АСТАНА:8080 --token ВАШ_API_TOKEN

Что делает:
    - Показывает последний AI анализ (bypass + speed рекомендации)
    - Опционально запускает немедленный анализ (-–trigger)
    - Следит за изменениями каждые N секунд (--watch)
"""

import argparse
import json
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime


# ── Цвета для терминала ───────────────────────────────────────────────────────

class C:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    GREEN  = "\033[92m"
    CYAN   = "\033[96m"
    BLUE   = "\033[94m"
    GRAY   = "\033[90m"
    WHITE  = "\033[97m"

def _no_color():
    for attr in vars(C):
        if not attr.startswith("_"):
            setattr(C, attr, "")

if not sys.stdout.isatty():
    _no_color()


# ── HTTP helpers ──────────────────────────────────────────────────────────────

def _request(method: str, url: str, token: str, body: bytes | None = None) -> dict:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        resp = urllib.request.urlopen(req, timeout=15)
        return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        raw = e.read().decode(errors="replace")
        print(f"{C.RED}HTTP {e.code}: {raw}{C.RESET}", file=sys.stderr)
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"{C.RED}Не удалось подключиться: {e.reason}{C.RESET}", file=sys.stderr)
        sys.exit(1)


# ── Форматирование ────────────────────────────────────────────────────────────

SEVERITY_COLOR = {
    "critical": C.RED,
    "warning":  C.YELLOW,
    "info":     C.CYAN,
}

PRIORITY_ICON = {1: "🔴", 2: "🟡", 3: "🟢"}


def _fmt_time(iso: str) -> str:
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return dt.strftime("%d.%m.%Y %H:%M:%S UTC")
    except Exception:
        return iso


def print_analysis(data: dict) -> None:
    if data.get("error"):
        print(f"\n{C.RED}Ошибка анализа: {data['error']}{C.RESET}")
        return

    ts = _fmt_time(data.get("timestamp", ""))
    reports = data.get("report_count", 0)
    devices = data.get("device_count", 0)

    print(f"\n{C.BOLD}{C.WHITE}{'─'*60}{C.RESET}")
    print(f"{C.BOLD}  AI Анализ VPN  {C.GRAY}({ts}){C.RESET}")
    print(f"{C.GRAY}  Отчётов: {reports}  |  Устройств: {devices}{C.RESET}")
    print(f"{C.BOLD}{C.WHITE}{'─'*60}{C.RESET}")

    # Краткое резюме
    summary = data.get("summary", "")
    if summary:
        print(f"\n{C.BOLD}📊 Резюме:{C.RESET}")
        # Переносим длинные строки
        words = summary.split()
        line = "  "
        for word in words:
            if len(line) + len(word) > 75:
                print(line)
                line = "  " + word + " "
            else:
                line += word + " "
        if line.strip():
            print(line)

    # Проблемы
    issues = data.get("issues") or []
    if issues:
        print(f"\n{C.BOLD}⚠️  Проблемы ({len(issues)}):{C.RESET}")
        for issue in issues:
            col = SEVERITY_COLOR.get(issue.get("severity", "info"), C.CYAN)
            sev = issue.get("severity", "info").upper()
            cat = issue.get("category", "")
            desc = issue.get("description", "")
            devs = issue.get("affected_devices") or []
            dev_str = f" [{', '.join(devs)}]" if devs else ""
            print(f"  {col}[{sev}]{C.RESET} {C.BOLD}{cat}{C.RESET}{dev_str}")
            print(f"    {desc}")

    # DPI Bypass рекомендации
    bypass = data.get("bypass_recommendations") or []
    if bypass:
        print(f"\n{C.BOLD}{C.RED}🛡  DPI Bypass рекомендации:{C.RESET}")
        for rec in sorted(bypass, key=lambda r: r.get("priority", 9)):
            p = rec.get("priority", 3)
            icon = PRIORITY_ICON.get(p, "⚪")
            action = rec.get("action", "")
            desc = rec.get("description", "")
            cfg = rec.get("config") or {}
            print(f"  {icon} {C.BOLD}{action}{C.RESET}")
            print(f"     {desc}")
            if cfg:
                print(f"     {C.GRAY}Параметры: {json.dumps(cfg, ensure_ascii=False)}{C.RESET}")

    # Speed рекомендации
    speed = data.get("speed_recommendations") or []
    if speed:
        print(f"\n{C.BOLD}{C.GREEN}⚡ Speed рекомендации:{C.RESET}")
        for rec in sorted(speed, key=lambda r: r.get("priority", 9)):
            p = rec.get("priority", 3)
            icon = PRIORITY_ICON.get(p, "⚪")
            action = rec.get("action", "")
            gain = rec.get("expected_gain", "")
            desc = rec.get("description", "")
            cfg = rec.get("config") or {}
            gain_str = f" {C.GREEN}(+{gain}){C.RESET}" if gain else ""
            print(f"  {icon} {C.BOLD}{action}{C.RESET}{gain_str}")
            print(f"     {desc}")
            if cfg:
                print(f"     {C.GRAY}Параметры: {json.dumps(cfg, ensure_ascii=False)}{C.RESET}")

    # Actionable config — что применится на клиенте автоматически
    acfg = data.get("actionable_config")
    if acfg:
        print(f"\n{C.BOLD}{C.CYAN}🤖 Автоприменяемый конфиг:{C.RESET}")
        lines = json.dumps(acfg, indent=4, ensure_ascii=False).splitlines()
        for line in lines:
            print(f"  {C.CYAN}{line}{C.RESET}")

    # Общие рекомендации (старый формат)
    recs = data.get("recommendations") or []
    if recs and not bypass and not speed:
        print(f"\n{C.BOLD}💡 Рекомендации:{C.RESET}")
        for r in recs:
            print(f"  • {r}")

    print(f"\n{C.BOLD}{C.WHITE}{'─'*60}{C.RESET}\n")


def print_config(data: dict) -> None:
    if not data:
        print(f"{C.GRAY}Конфиг пока не сгенерирован (AI ещё не запускался){C.RESET}")
        return
    print(f"\n{C.BOLD}{C.CYAN}Текущий конфиг для клиентов:{C.RESET}")
    print(json.dumps(data, indent=2, ensure_ascii=False))


# ── Команды ───────────────────────────────────────────────────────────────────

def cmd_show(base: str, token: str) -> None:
    """Показать последний анализ."""
    data = _request("GET", f"{base}/api/v1/telemetry/analysis", token)
    if "status" in data and data.get("status") == "no analysis yet":
        print(f"\n{C.YELLOW}Анализ ещё не проводился.{C.RESET}")
        print(f"Запусти {C.BOLD}python3 ai_monitor.py --trigger{C.RESET} чтобы запустить немедленно.")
        return
    print_analysis(data)


def cmd_trigger(base: str, token: str) -> None:
    """Запустить анализ прямо сейчас."""
    print(f"{C.YELLOW}Запускаю AI анализ... (может занять 10–30 секунд){C.RESET}")
    data = _request("POST", f"{base}/api/v1/telemetry/analyze", token, body=b"{}")
    print_analysis(data)


def cmd_config(base: str, _token: str) -> None:
    """Показать actionable_config для клиентов."""
    data = _request("GET", f"{base}/api/v1/telemetry/config", "")
    print_config(data)


def cmd_watch(base: str, token: str, interval: int) -> None:
    """Следить за анализом, обновлять каждые N секунд."""
    print(f"{C.CYAN}Слежу за анализом (обновление каждые {interval} сек, Ctrl+C для выхода){C.RESET}")
    last_ts = None
    while True:
        try:
            data = _request("GET", f"{base}/api/v1/telemetry/analysis", token)
            ts = data.get("timestamp", "")
            if ts != last_ts:
                last_ts = ts
                print_analysis(data)
            else:
                now = datetime.now().strftime("%H:%M:%S")
                print(f"\r{C.GRAY}[{now}] Нет новых данных...{C.RESET}", end="", flush=True)
            time.sleep(interval)
        except KeyboardInterrupt:
            print(f"\n{C.GRAY}Выход.{C.RESET}")
            break


# ── main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Мониторинг AI анализа VPN",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры:
  # Показать последний анализ:
  python3 ai_monitor.py --server http://1.2.3.4:8080 --token МОЙ_ТОКЕН

  # Запустить анализ прямо сейчас:
  python3 ai_monitor.py --server http://1.2.3.4:8080 --token МОЙ_ТОКЕН --trigger

  # Следить за обновлениями каждые 5 минут:
  python3 ai_monitor.py --server http://1.2.3.4:8080 --token МОЙ_ТОКЕН --watch 300

  # Показать конфиг который применится на клиентах:
  python3 ai_monitor.py --server http://1.2.3.4:8080 --config
        """,
    )
    parser.add_argument("--server", required=True,
                        metavar="URL", help="адрес сервера, напр. http://1.2.3.4:8080")
    parser.add_argument("--token", default="",
                        metavar="TOKEN", help="API токен (из config.yaml → api.token)")
    parser.add_argument("--trigger", action="store_true",
                        help="запустить анализ немедленно (не ждать следующего часа)")
    parser.add_argument("--watch", type=int, metavar="SEC", nargs="?", const=60,
                        help="следить за обновлениями каждые SEC секунд (default: 60)")
    parser.add_argument("--config", action="store_true",
                        help="показать actionable_config для клиентов")

    args = parser.parse_args()
    base = args.server.rstrip("/")

    if args.trigger:
        cmd_trigger(base, args.token)
    elif args.config:
        cmd_config(base, args.token)
    elif args.watch is not None:
        cmd_watch(base, args.token, args.watch)
    else:
        cmd_show(base, args.token)


if __name__ == "__main__":
    main()
