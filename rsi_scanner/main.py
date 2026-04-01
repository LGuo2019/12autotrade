from __future__ import annotations

import argparse
import atexit
import json
import logging
import os
from pathlib import Path
import signal
import sys
import time

from .budget import CreditBudget
from .config import load_config, resolve_secret
from .logging_utils import setup_logging
from .ig_watchlist import IGWatchlistSync
from .scanner import Scanner
from .scheduler import run_every_2h
from .sim import SimClient, SimDataSource, SimJSONSource
from .storage import Storage
from .telegram import TelegramClient, TelegramSendError
from .twelvedata import TwelveDataClient

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
STATE_FILE = DATA_DIR / "bot.state.json"


def _write_runtime_state(state: str, **extra: object) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    payload: dict[str, object] = {
        "state": state,
        "pid": os.getpid(),
        "updated_at": int(time.time()),
    }
    payload.update(extra)
    STATE_FILE.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")


def _register_process_logging() -> None:
    logger = logging.getLogger("rsi_scanner")

    def _on_exit() -> None:
        _write_runtime_state("stopped", exit_reason="atexit")
        logger.info("process_atexit pid=%d", os.getpid())

    atexit.register(_on_exit)

    def _handle_signal(signum: int, _frame: object) -> None:
        try:
            signame = signal.Signals(signum).name
        except ValueError:
            signame = str(signum)
        _write_runtime_state("stopping", signal=signame)
        logger.warning("process_signal pid=%d signal=%s", os.getpid(), signame)
        raise SystemExit(128 + int(signum))

    for sig_name in ("SIGINT", "SIGTERM", "SIGBREAK"):
        sig = getattr(signal, sig_name, None)
        if sig is not None:
            signal.signal(sig, _handle_signal)


def _symbol_aliases(symbol: str) -> list[str]:
    base = str(symbol).strip()
    if not base:
        return []
    upper = base.upper().replace(" ", "")
    aliases = [base, upper]

    if ":" in upper:
        aliases.append(upper.split(":", 1)[0])
    if "/" in upper:
        aliases.append(upper.replace("/", ""))
    if "." in upper:
        aliases.append(upper.replace(".", ""))
    if "-" in upper:
        aliases.append(upper.replace("-", ""))

    deduped: list[str] = []
    seen: set[str] = set()
    for alias in aliases:
        value = alias.strip()
        if not value or value in seen:
            continue
        seen.add(value)
        deduped.append(value)
    return deduped


def load_symbols(path: str) -> list[str]:
    symbols: list[str] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            symbol = line.strip()
            if not symbol or symbol.startswith("#"):
                continue
            symbols.append(symbol)
    return symbols


def load_symbol_mapping(path: str) -> dict[str, str]:
    p = Path(path)
    if not p.exists():
        return {}
    with p.open("r", encoding="utf-8") as f:
        raw = json.load(f)
    if not isinstance(raw, dict):
        return {}
    out: dict[str, str] = {}
    for k, v in raw.items():
        key = str(k).strip()
        if not key:
            continue
        out[key] = str(v).strip() if v is not None else key
    return out


def load_symbol_to_epic_map(path: str) -> dict[str, str]:
    p = Path(path)
    if not p.exists():
        return {}
    try:
        with p.open("r", encoding="utf-8") as f:
            payload = json.load(f)
    except Exception:
        return {}
    epic_to_symbol = payload.get("epic_to_twelvedata_symbol", payload) if isinstance(payload, dict) else {}
    if not isinstance(epic_to_symbol, dict):
        return {}
    out: dict[str, str] = {}
    for epic, symbol in epic_to_symbol.items():
        e = str(epic).strip()
        s = str(symbol).strip()
        if not e or not s:
            continue
        for alias in _symbol_aliases(s):
            out.setdefault(alias, e)
    return out


def load_symbols_set(path: str) -> set[str]:
    p = Path(path)
    if not p.exists():
        return set()
    out: set[str] = set()
    with p.open("r", encoding="utf-8") as f:
        for line in f:
            value = line.strip()
            if not value or value.startswith("#"):
                continue
            out.add(value)
    return out


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="TwelveData RSI scanner")
    parser.add_argument("--config", default="config.yaml")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--sim-csv", default="")
    parser.add_argument("--sim-json", default="")
    parser.add_argument("--db-path", default="")
    parser.add_argument("--send-telegram", action="store_true")
    parser.add_argument("--log-level", default="INFO")
    parser.add_argument("--json-logs", action="store_true")
    return parser


def run_once(args: argparse.Namespace) -> None:
    setup_logging(level=args.log_level, json_logs=args.json_logs)
    logger = logging.getLogger("rsi_scanner")
    _write_runtime_state("scan_starting")

    cfg = load_config(args.config)
    if args.dry_run:
        cfg.dry_run = True
    sim_mode = bool(args.sim_csv or args.sim_json)

    symbol_display_map: dict[str, str] = {}
    if cfg.mapping_file:
        symbol_display_map = load_symbol_mapping(cfg.mapping_file)
    if symbol_display_map:
        symbols = list(symbol_display_map.keys())
        logger.info(
            "startup symbols_loaded=%d mapping_file=%s",
            len(symbols),
            cfg.mapping_file,
        )
    else:
        symbols = load_symbols(cfg.symbols_file)
        logger.info("startup symbols_loaded=%d symbols_file=%s", len(symbols), cfg.symbols_file)
    if args.db_path:
        db_path = args.db_path
    elif sim_mode:
        db_path = ":memory:"
    else:
        db_path = "rsi_scanner.db"
    logger.info("storage_open path=%s", db_path)
    storage = Storage(db_path)

    budget = CreditBudget(
        storage=storage,
        per_min_limit=cfg.limits_per_min,
        per_day_limit=cfg.limits_per_day,
        reserve_pct=cfg.reserve_pct,
    )

    if args.sim_csv:
        data = SimDataSource(args.sim_csv)
        data_client = SimClient(data)
        cfg.dry_run = True
        logger.info("mode sim_csv path=%s", args.sim_csv)
    elif args.sim_json:
        data = SimJSONSource(args.sim_json)
        data_client = SimClient(data)
        cfg.dry_run = True
        logger.info("mode sim_json path=%s", args.sim_json)
    else:
        api_key = resolve_secret(cfg.twelvedata_api_key_env, cfg.twelvedata_api_key)
        if not api_key and not cfg.dry_run:
            raise SystemExit("Missing TwelveData API key (env or config)")
        data_client = TwelveDataClient(api_key=api_key, budget=budget, dry_run=cfg.dry_run)
        logger.info("mode live dry_run=%s", str(cfg.dry_run).lower())

    token = resolve_secret(cfg.telegram_token_env, cfg.telegram_token)
    chat_id = resolve_secret(cfg.telegram_chat_id_env, cfg.telegram_chat_id)
    telegram_dry_run = cfg.dry_run and not args.send_telegram
    if not (token and chat_id) and not telegram_dry_run:
        raise SystemExit("Missing Telegram token/chat (env or config)")

    logger.info("telegram_mode dry_run=%s", str(telegram_dry_run).lower())
    telegram = TelegramClient(token=token, chat_id=chat_id, dry_run=telegram_dry_run)

    ig_watchlist_sync = None
    symbol_to_epic_map = load_symbol_to_epic_map(cfg.ig_symbol_epic_map_file)
    if cfg.ig_auto_add_watchlist_on_alert:
        ig_api_key = resolve_secret(cfg.ig_api_key_env, cfg.ig_api_key)
        ig_identifier = resolve_secret(cfg.ig_identifier_env, cfg.ig_identifier)
        ig_password = resolve_secret(cfg.ig_password_env, cfg.ig_password)
        if ig_api_key and ig_identifier and ig_password:
            ig_watchlist_sync = IGWatchlistSync(
                api_key=ig_api_key,
                identifier=ig_identifier,
                password=ig_password,
                base_url=cfg.ig_base_url,
                watchlist_name=cfg.ig_watchlist_name,
                account_id=cfg.ig_account_id,
                cache_file=cfg.ig_watchlist_cache_file,
                dry_run=cfg.dry_run,
            )
            logger.info(
                "ig_watchlist_sync enabled=true watchlist=%s epic_map_size=%d",
                cfg.ig_watchlist_name,
                len(symbol_to_epic_map),
            )
        else:
            logger.warning("ig_watchlist_sync enabled=false reason=missing_ig_credentials")
    else:
        logger.info("ig_watchlist_sync enabled=false")

    scanner = Scanner(
        storage=storage,
        budget=budget,
        data_client=data_client,
        telegram=telegram,
        timeframe=cfg.timeframe,
        active_band=cfg.active_band,
        max_calls_per_run=cfg.max_calls_per_run,
        sticky_runs=cfg.sticky_runs,
        alert_on_first_seen_extreme=cfg.alert_on_first_seen_extreme,
        us_stocks_restrict_hours=cfg.us_stocks_restrict_hours,
        us_stocks_tz=cfg.us_stocks_tz,
        us_stocks_start=cfg.us_stocks_start,
        us_stocks_end=cfg.us_stocks_end,
        us_stock_symbols=load_symbols_set(cfg.us_stock_symbols_file),
        symbols=symbols,
        symbol_to_epic_map=symbol_to_epic_map,
        ig_watchlist_sync=ig_watchlist_sync,
        symbol_display_map=symbol_display_map,
        enforce_candle_dedup=not sim_mode,
    )

    logger.info(
        "run_begin timeframe=%s max_calls=%d sticky_runs=%d",
        cfg.timeframe,
        cfg.max_calls_per_run,
        cfg.sticky_runs,
    )
    result = scanner.run_once()
    _write_runtime_state(
        "scan_complete",
        planned=result.planned,
        scanned=result.scanned,
        alerts=result.alerts,
        no_data=result.no_data,
        budget_halted=result.budget_halted,
    )
    logger.info(
        "scan_complete planned=%d scanned=%d alerts=%d skipped=%d no_data=%d window_skipped=%d budget_halted=%s",
        result.planned,
        result.scanned,
        result.alerts,
        result.skipped,
        result.no_data,
        result.window_skipped,
        str(result.budget_halted).lower(),
    )
    try:
        telegram.send_scan_summary(
            timeframe=cfg.timeframe,
            symbols_total=len(symbols),
            planned=result.planned,
            scanned=result.scanned,
            alerts=result.alerts,
            skipped=result.skipped,
            no_data=result.no_data,
            budget_halted=result.budget_halted,
            remaining_day=budget.remaining_day(),
        )
    except TelegramSendError as exc:
        logger.error("scan_summary_send_failed error=%s", str(exc))
    if not args.json_logs:
        print(f"Scanned={result.scanned} Alerts={result.alerts} Skipped={result.skipped}")


def main() -> None:
    args = build_arg_parser().parse_args()
    setup_logging(level=args.log_level, json_logs=args.json_logs)
    logger = logging.getLogger("rsi_scanner")
    _register_process_logging()
    _write_runtime_state("starting", argv=sys.argv[1:])
    logger.info("process_start pid=%d argv=%s", os.getpid(), sys.argv[1:])
    if args.once:
        run_once(args)
        return

    logger.info("service_start once=false dry_run_flag=%s", str(args.dry_run).lower())
    def task() -> None:
        _write_runtime_state("scan_running")
        logger.info("scheduler_task_begin pid=%d", os.getpid())
        run_once(args)
        _write_runtime_state("scan_idle")
        logger.info("scheduler_task_end pid=%d", os.getpid())

    def on_wait(state: str, target: object, wait_seconds: int) -> None:
        run_at = target.strftime("%Y-%m-%d %H:%M:%S") if hasattr(target, "strftime") else str(target)
        _write_runtime_state("waiting", next_run_utc=run_at, wait_seconds=wait_seconds)

    run_every_2h(task, on_wait=on_wait)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        _write_runtime_state("stopped", exit_reason="keyboard_interrupt")
        logging.getLogger("rsi_scanner").warning("process_keyboard_interrupt pid=%d", os.getpid())
        sys.exit(0)
    except SystemExit as exc:
        _write_runtime_state("stopped", exit_reason="system_exit", code=exc.code)
        logging.getLogger("rsi_scanner").warning("process_system_exit pid=%d code=%s", os.getpid(), exc.code)
        raise
    except Exception:
        _write_runtime_state("stopped", exit_reason="unhandled_exception")
        logging.getLogger("rsi_scanner").exception("process_unhandled_exception pid=%d", os.getpid())
        raise
