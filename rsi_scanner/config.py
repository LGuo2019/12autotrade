from __future__ import annotations

import os
import re
from dataclasses import asdict
from typing import Any

import yaml

from .models import Config
from .constants import DEFAULT_TIMEFRAME


def load_config(path: str) -> Config:
    with open(path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}

    limits = raw.get("limits", {})
    twelvedata = raw.get("twelvedata", {})
    telegram = raw.get("telegram", {})
    scanner = raw.get("scanner", {})
    ig = raw.get("ig", {})

    cfg = Config(
        safe_mode=bool(raw.get("safe_mode", True)),
        dry_run=bool(raw.get("dry_run", True)),
        limits_per_min=int(limits.get("per_min", 8)),
        limits_per_day=int(limits.get("per_day", 800)),
        reserve_pct=float(limits.get("reserve_pct", 0.05)),
        twelvedata_api_key_env=str(twelvedata.get("api_key_env", "TWELVEDATA_API_KEY")),
        twelvedata_api_key=str(twelvedata.get("api_key", "")),
        telegram_token_env=str(telegram.get("token_env", "TELEGRAM_TOKEN")),
        telegram_token=str(telegram.get("token", "")),
        telegram_chat_id_env=str(telegram.get("chat_id_env", "TELEGRAM_CHAT_ID")),
        telegram_chat_id=str(telegram.get("chat_id", "")),
        timeframe=str(scanner.get("timeframe", DEFAULT_TIMEFRAME)),
        active_band=float(scanner.get("active_band", 6)),
        max_calls_per_run=int(scanner.get("max_calls_per_run", 63)),
        sticky_runs=int(scanner.get("sticky_runs", 2)),
        alert_on_first_seen_extreme=bool(scanner.get("alert_on_first_seen_extreme", False)),
        us_stocks_restrict_hours=bool(scanner.get("us_stocks_restrict_hours", False)),
        us_stocks_tz=str(scanner.get("us_stocks_tz", "America/New_York")),
        us_stocks_start=str(scanner.get("us_stocks_start", "07:30")),
        us_stocks_end=str(scanner.get("us_stocks_end", "18:00")),
        us_stock_symbols_file=str(scanner.get("us_stock_symbols_file", "data/us_stock_symbols.txt")),
        ig_auto_add_watchlist_on_alert=bool(scanner.get("ig_auto_add_watchlist_on_alert", False)),
        ig_watchlist_name=str(scanner.get("ig_watchlist_name", "My Watchlist")),
        ig_watchlist_cache_file=str(scanner.get("ig_watchlist_cache_file", "data/ig_watchlist_cache.json")),
        ig_symbol_epic_map_file=str(scanner.get("ig_symbol_epic_map_file", "rsi_universe_epic_to_twelvedata_symbol.json")),
        ig_api_key_env=str(ig.get("api_key_env", "IG_API_KEY")),
        ig_api_key=str(ig.get("api_key", "")),
        ig_identifier_env=str(ig.get("identifier_env", "IG_IDENTIFIER")),
        ig_identifier=str(ig.get("identifier", "")),
        ig_password_env=str(ig.get("password_env", "IG_PASSWORD")),
        ig_password=str(ig.get("password", "")),
        ig_base_url=str(ig.get("base_url", "https://api.ig.com/gateway/deal")),
        ig_account_id=str(ig.get("account_id", "")),
        symbols_file=str(raw.get("symbols_file", "symbols/markets.txt")),
        mapping_file=str(raw.get("mapping_file", "")),
    )

    return cfg


def env_or_empty(name: str) -> str:
    return os.environ.get(name, "")


def resolve_secret(env_name: str, literal: str) -> str:
    # Prefer environment variable value when present.
    if env_name and env_name in os.environ:
        return os.environ[env_name]
    # Fallback to literal config value (supports direct secrets in config.yaml).
    if literal:
        return literal
    # Backward compatibility: some configs store direct values in *_env keys.
    if env_name and not _looks_like_env_name(env_name):
        return env_name
    return ""


def _looks_like_env_name(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Z_][A-Z0-9_]*", value))


def to_dict(cfg: Config) -> dict[str, Any]:
    return asdict(cfg)
