from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from datetime import datetime
from zoneinfo import ZoneInfo
from typing import Dict, Iterable, List, Optional, Sequence

from .budget import CreditBudget
from .constants import (
    ACTIVE_TIER,
    REST_TIER,
    RSI_OVERBOUGHT,
    RSI_OVERSOLD,
    SECONDS_PER_2H,
    STATE_NEUTRAL,
    STATE_OVERBOUGHT,
    STATE_OVERSOLD,
)
from .models import Alert, AlertState, RSIPoint, WatchTier
from .signals import detect_cross, rsi_state
from .storage import Storage
from .telegram import TelegramClient, TelegramSendError
from .twelvedata import BudgetExceeded, TwelveDataClient
from .ig_watchlist import IGWatchlistSync


COOLDOWN_SECONDS = 3600
logger = logging.getLogger("rsi_scanner.scanner")


@dataclass
class ScanResult:
    planned: int
    scanned: int
    alerts: int
    skipped: int
    no_data: int
    window_skipped: int
    budget_halted: bool


class Scanner:
    def __init__(
        self,
        storage: Storage,
        budget: CreditBudget,
        data_client: TwelveDataClient,
        telegram: TelegramClient,
        timeframe: str,
        active_band: float,
        max_calls_per_run: int,
        sticky_runs: int,
        alert_on_first_seen_extreme: bool,
        us_stocks_restrict_hours: bool,
        us_stocks_tz: str,
        us_stocks_start: str,
        us_stocks_end: str,
        us_stock_symbols: Sequence[str] | None,
        symbols: Sequence[str],
        symbol_to_epic_map: Dict[str, str] | None = None,
        ig_watchlist_sync: IGWatchlistSync | None = None,
        symbol_display_map: Dict[str, str] | None = None,
        enforce_candle_dedup: bool = True,
    ) -> None:
        self.storage = storage
        self.budget = budget
        self.data_client = data_client
        self.telegram = telegram
        self.timeframe = timeframe
        self.active_band = active_band
        self.max_calls_per_run = max_calls_per_run
        self.sticky_runs = sticky_runs
        self.alert_on_first_seen_extreme = alert_on_first_seen_extreme
        self.us_stocks_restrict_hours = us_stocks_restrict_hours
        self.us_stocks_tz = us_stocks_tz
        self.us_stocks_start = us_stocks_start
        self.us_stocks_end = us_stocks_end
        self.us_stock_symbols = set(us_stock_symbols or [])
        self.symbols = list(symbols)
        self.symbol_to_epic_map = symbol_to_epic_map or {}
        self.ig_watchlist_sync = ig_watchlist_sync
        self.symbol_display_map = symbol_display_map or {}
        self.enforce_candle_dedup = enforce_candle_dedup

    def _display_symbol(self, symbol: str) -> str:
        return self.symbol_display_map.get(symbol, symbol)

    def run_once(self) -> ScanResult:
        now_ts = int(time.time())
        run_id = now_ts // SECONDS_PER_2H
        current_candle_ts = (now_ts // SECONDS_PER_2H) * SECONDS_PER_2H

        active, rest = self._partition_symbols(run_id)
        logger.info(
            "scan_start symbols=%d active=%d rest=%d timeframe=%s",
            len(self.symbols),
            len(active),
            len(rest),
            self.timeframe,
        )

        remaining_day = self.budget.remaining_day()
        if remaining_day <= 0:
            logger.warning("scan_skipped reason=day_budget_exhausted")
            return ScanResult(
                planned=0,
                scanned=0,
                alerts=0,
                skipped=len(self.symbols),
                no_data=0,
                window_skipped=0,
                budget_halted=True,
            )

        low_budget = remaining_day < self.max_calls_per_run
        to_scan: List[str] = []

        cursor = self.storage.get_rr_cursor(self.timeframe)

        if active:
            limit = min(len(active), self.max_calls_per_run)
            selected, cursor = _select_round_robin(active, cursor, limit)
            to_scan.extend(selected)

        if not low_budget and len(to_scan) < self.max_calls_per_run:
            rest_limit = self.max_calls_per_run - len(to_scan)
            selected, cursor = _select_round_robin(rest, cursor, rest_limit)
            to_scan.extend(selected)

        self.storage.set_rr_cursor(self.timeframe, cursor)
        logger.info(
            "scan_plan selected=%d max_calls=%d low_budget=%s remaining_day=%d",
            len(to_scan),
            self.max_calls_per_run,
            str(low_budget).lower(),
            remaining_day,
        )

        scanned = 0
        alerts = 0
        skipped = 0
        no_data = 0
        window_skipped = 0
        budget_halted = False
        stop_scan = False

        for symbol in to_scan:
            d_symbol = self._display_symbol(symbol)
            if self._skip_for_us_stock_window(symbol, d_symbol):
                window_skipped += 1
                continue
            logger.info("scan_symbol symbol=%s action=start", d_symbol)
            last_cached = self.storage.get_last_rsi(symbol, self.timeframe)
            if self.enforce_candle_dedup and last_cached and last_cached.ts >= current_candle_ts:
                skipped += 1
                logger.info("scan_symbol symbol=%s action=skip_cached ts=%d", d_symbol, last_cached.ts)
                continue
            while True:
                try:
                    points = self.data_client.fetch_rsi(symbol, self.timeframe)
                    break
                except BudgetExceeded as exc:
                    if exc.reason == "minute_limit":
                        wait_seconds = max(1, int(exc.wait_seconds))
                        logger.info(
                            "scan_symbol symbol=%s action=wait_budget reason=minute_limit wait_seconds=%d",
                            d_symbol,
                            wait_seconds,
                        )
                        time.sleep(wait_seconds)
                        continue
                    logger.warning("scan_halted reason=budget_exceeded scope=%s", exc.reason)
                    budget_halted = True
                    stop_scan = True
                    points = None
                    break
            if stop_scan:
                break

            if not points or len(points) < 2:
                reason = getattr(self.data_client, "last_error", "") or "unknown"
                logger.info("scan_symbol symbol=%s action=no_data reason=%s", d_symbol, reason)
                no_data += 1
                continue

            self.storage.insert_rsi(symbol, self.timeframe, points)

            prev, curr = points[-2], points[-1]
            logger.info(
                "scan_symbol symbol=%s action=queried prev_rsi=%.2f curr_rsi=%.2f prev_ts=%d curr_ts=%d",
                d_symbol,
                prev.rsi,
                curr.rsi,
                prev.ts,
                curr.ts,
            )
            cross_state = detect_cross(prev, curr)
            current_state = rsi_state(curr.rsi)

            alert_state = self.storage.get_alert_state(symbol, self.timeframe)
            if not alert_state:
                alert_state = AlertState(last_state=STATE_NEUTRAL, last_ts=0, last_alert_ts=0)

            should_alert = False
            alert_state_to_send = cross_state
            alert_reason = "cross"

            if cross_state and (curr.ts - alert_state.last_alert_ts) >= COOLDOWN_SECONDS:
                should_alert = True
            elif (
                self.alert_on_first_seen_extreme
                and current_state in (STATE_OVERBOUGHT, STATE_OVERSOLD)
                and alert_state.last_state != current_state
                and (curr.ts - alert_state.last_alert_ts) >= COOLDOWN_SECONDS
            ):
                should_alert = True
                alert_state_to_send = current_state
                alert_reason = "first_seen_extreme"

            if should_alert:
                alert = Alert(
                    symbol=self.symbol_display_map.get(symbol, symbol),
                    timeframe=self.timeframe,
                    value=curr.rsi,
                    state=alert_state_to_send or current_state,
                    ts=curr.ts,
                )
                try:
                    self.telegram.send_alert(alert)
                    alert_state.last_alert_ts = curr.ts
                    alerts += 1
                    epic = self.symbol_to_epic_map.get(symbol, "")
                    if self.ig_watchlist_sync and epic:
                        self.ig_watchlist_sync.add_epic_if_missing(epic)
                    logger.info(
                        "scan_symbol symbol=%s action=alert reason=%s state=%s rsi=%.2f",
                        d_symbol,
                        alert_reason,
                        alert_state_to_send or current_state,
                        curr.rsi,
                    )
                except TelegramSendError as exc:
                    logger.error("scan_symbol symbol=%s action=alert_failed error=%s", d_symbol, str(exc))
            else:
                logger.info(
                    "scan_symbol symbol=%s action=state_update state=%s rsi=%.2f",
                    d_symbol,
                    current_state,
                    curr.rsi,
                )

            alert_state.last_state = current_state
            alert_state.last_ts = curr.ts
            self.storage.upsert_alert_state(symbol, self.timeframe, alert_state)
            scanned += 1

        logger.info(
            "scan_end planned=%d scanned=%d alerts=%d skipped=%d no_data=%d window_skipped=%d budget_halted=%s",
            len(to_scan),
            scanned,
            alerts,
            skipped,
            no_data,
            window_skipped,
            str(budget_halted).lower(),
        )
        return ScanResult(
            planned=len(to_scan),
            scanned=scanned,
            alerts=alerts,
            skipped=skipped,
            no_data=no_data,
            window_skipped=window_skipped,
            budget_halted=budget_halted,
        )

    def _skip_for_us_stock_window(self, symbol: str, d_symbol: str) -> bool:
        if not self.us_stocks_restrict_hours:
            return False
        if symbol not in self.us_stock_symbols:
            return False
        try:
            tz = ZoneInfo(self.us_stocks_tz)
            now_local = datetime.now(tz)
            start_h, start_m = [int(x) for x in self.us_stocks_start.split(":", 1)]
            end_h, end_m = [int(x) for x in self.us_stocks_end.split(":", 1)]
            now_mins = now_local.hour * 60 + now_local.minute
            start_mins = start_h * 60 + start_m
            end_mins = end_h * 60 + end_m
        except Exception:
            return False

        if now_local.weekday() >= 5:
            logger.info(
                "scan_symbol symbol=%s action=skip_window reason=us_stock_weekend local=%s",
                d_symbol,
                now_local.strftime("%Y-%m-%d %H:%M %Z"),
            )
            return True

        if start_mins <= now_mins <= end_mins:
            return False

        logger.info(
            "scan_symbol symbol=%s action=skip_window reason=outside_us_stock_window local=%s window=%s-%s",
            d_symbol,
            now_local.strftime("%Y-%m-%d %H:%M %Z"),
            self.us_stocks_start,
            self.us_stocks_end,
        )
        return True

    def _partition_symbols(self, run_id: int) -> tuple[List[str], List[str]]:
        active: List[str] = []
        rest: List[str] = []

        high_band = RSI_OVERBOUGHT - self.active_band
        low_band = RSI_OVERSOLD + self.active_band

        for symbol in self.symbols:
            d_symbol = self._display_symbol(symbol)
            last = self.storage.get_last_rsi(symbol, self.timeframe)
            tier = self.storage.get_watch_tier(symbol, self.timeframe)

            is_near = False
            if last:
                is_near = last.rsi >= high_band or last.rsi <= low_band

            if is_near:
                sticky_until = run_id + self.sticky_runs
                self.storage.upsert_watch_tier(
                    symbol, self.timeframe, WatchTier(tier=ACTIVE_TIER, sticky_until_run=sticky_until)
                )
                logger.info(
                    "tier_update symbol=%s tier=ACTIVE reason=near_threshold rsi=%.2f sticky_until_run=%d",
                    d_symbol,
                    last.rsi if last else -1.0,
                    sticky_until,
                )
                active.append(symbol)
                continue

            if tier and tier.tier == ACTIVE_TIER and tier.sticky_until_run >= run_id:
                logger.info(
                    "tier_update symbol=%s tier=ACTIVE reason=sticky sticky_until_run=%d current_run=%d",
                    d_symbol,
                    tier.sticky_until_run,
                    run_id,
                )
                active.append(symbol)
                continue

            self.storage.upsert_watch_tier(
                symbol, self.timeframe, WatchTier(tier=REST_TIER, sticky_until_run=run_id)
            )
            logger.info("tier_update symbol=%s tier=REST", d_symbol)
            rest.append(symbol)

        return active, rest


def _select_round_robin(symbols: Sequence[str], cursor: int, limit: int) -> tuple[List[str], int]:
    if not symbols or limit <= 0:
        return [], cursor

    count = len(symbols)
    cursor = cursor % count

    ordered = list(symbols[cursor:]) + list(symbols[:cursor])
    selected = ordered[:limit]

    new_cursor = (cursor + len(selected)) % count
    return selected, new_cursor
