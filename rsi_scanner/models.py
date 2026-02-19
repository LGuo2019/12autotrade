from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class RSIPoint:
    ts: int
    rsi: float


@dataclass(frozen=True)
class Alert:
    symbol: str
    timeframe: str
    value: float
    state: str
    ts: int


@dataclass(frozen=True)
class BudgetStatus:
    ok: bool
    wait_seconds: int
    reason: str


@dataclass
class AlertState:
    last_state: str
    last_ts: int
    last_alert_ts: int


@dataclass
class WatchTier:
    tier: str
    sticky_until_run: int


@dataclass
class Config:
    safe_mode: bool
    dry_run: bool
    limits_per_min: int
    limits_per_day: int
    reserve_pct: float
    twelvedata_api_key_env: str
    twelvedata_api_key: str
    telegram_token_env: str
    telegram_token: str
    telegram_chat_id_env: str
    telegram_chat_id: str
    timeframe: str
    active_band: float
    max_calls_per_run: int
    sticky_runs: int
    alert_on_first_seen_extreme: bool
    us_stocks_restrict_hours: bool
    us_stocks_tz: str
    us_stocks_start: str
    us_stocks_end: str
    us_stock_symbols_file: str
    ig_auto_add_watchlist_on_alert: bool
    ig_watchlist_name: str
    ig_watchlist_cache_file: str
    ig_symbol_epic_map_file: str
    ig_api_key_env: str
    ig_api_key: str
    ig_identifier_env: str
    ig_identifier: str
    ig_password_env: str
    ig_password: str
    ig_base_url: str
    ig_account_id: str
    symbols_file: str
    mapping_file: str
