from __future__ import annotations

import math
import time
from dataclasses import dataclass
from datetime import datetime, timezone

from .models import BudgetStatus
from .storage import Storage
from .constants import SECONDS_PER_MINUTE


@dataclass
class CreditBudget:
    storage: Storage
    per_min_limit: int
    per_day_limit: int
    reserve_pct: float

    def __post_init__(self) -> None:
        self._min_window_start = 0
        self._min_used = 0

    def _effective_limit(self, limit: int) -> int:
        return max(0, int(math.floor(limit * (1.0 - self.reserve_pct))))

    def _current_day_key(self) -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d")

    def _reset_minute_if_needed(self, now_ts: int) -> None:
        current_min = now_ts // SECONDS_PER_MINUTE
        if current_min != self._min_window_start:
            self._min_window_start = current_min
            self._min_used = 0

    def remaining_day(self) -> int:
        day_key = self._current_day_key()
        used = self.storage.get_day_usage(day_key)
        return self._effective_limit(self.per_day_limit) - used

    def check(self, credits: int) -> BudgetStatus:
        now_ts = int(time.time())
        self._reset_minute_if_needed(now_ts)

        eff_min = self._effective_limit(self.per_min_limit)
        eff_day = self._effective_limit(self.per_day_limit)

        day_key = self._current_day_key()
        used_day = self.storage.get_day_usage(day_key)

        if used_day + credits > eff_day:
            return BudgetStatus(False, self._seconds_until_next_day(now_ts), "day_limit")

        if self._min_used + credits > eff_min:
            return BudgetStatus(False, self._seconds_until_next_minute(now_ts), "minute_limit")

        return BudgetStatus(True, 0, "ok")

    def consume(self, credits: int) -> BudgetStatus:
        status = self.check(credits)
        if not status.ok:
            return status

        now_ts = int(time.time())
        self._reset_minute_if_needed(now_ts)

        self._min_used += credits
        day_key = self._current_day_key()
        used_day = self.storage.get_day_usage(day_key)
        self.storage.set_day_usage(day_key, used_day + credits)
        return status

    @staticmethod
    def _seconds_until_next_minute(now_ts: int) -> int:
        return SECONDS_PER_MINUTE - (now_ts % SECONDS_PER_MINUTE)

    @staticmethod
    def _seconds_until_next_day(now_ts: int) -> int:
        next_day = datetime.fromtimestamp(now_ts, tz=timezone.utc).replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        next_day = next_day.timestamp() + 86400
        return max(0, int(next_day - now_ts))
