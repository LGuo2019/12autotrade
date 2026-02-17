from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import List, Optional

import requests

from .budget import CreditBudget
from .constants import RSI_PERIOD
from .models import RSIPoint


class BudgetExceeded(Exception):
    def __init__(self, wait_seconds: int, reason: str) -> None:
        super().__init__(f"Budget exceeded: {reason}. Wait {wait_seconds}s")
        self.wait_seconds = wait_seconds
        self.reason = reason


class TwelveDataClient:
    def __init__(self, api_key: str, budget: CreditBudget, dry_run: bool = False) -> None:
        self.api_key = api_key
        self.budget = budget
        self.dry_run = dry_run
        self._session = requests.Session()
        self.last_error = ""

    @staticmethod
    def _parse_datetime(dt_str: str) -> int:
        dt = datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        return int(dt.timestamp())

    def fetch_rsi(self, symbol: str, interval: str) -> Optional[List[RSIPoint]]:
        self.last_error = ""
        if self.dry_run:
            self.last_error = "dry_run_enabled"
            return None

        status = self.budget.consume(1)
        if not status.ok:
            raise BudgetExceeded(status.wait_seconds, status.reason)

        params = {
            "symbol": symbol,
            "interval": interval,
            "time_period": RSI_PERIOD,
            "outputsize": 2,
            "apikey": self.api_key,
        }
        try:
            resp = self._session.get(
                "https://api.twelvedata.com/rsi",
                params=params,
                timeout=15,
            )
            resp.raise_for_status()
            payload = resp.json()
        except requests.RequestException as exc:
            self.last_error = f"http_error:{exc}"
            return None
        except ValueError:
            self.last_error = "invalid_json"
            return None

        if payload.get("status") != "ok":
            code = payload.get("code")
            message = payload.get("message")
            details = []
            if code:
                details.append(str(code))
            if message:
                details.append(str(message))
            self.last_error = "api_error:" + (" | ".join(details) if details else "status_not_ok")
            return None

        values = payload.get("values") or []
        points: List[RSIPoint] = []
        for item in values:
            try:
                ts = self._parse_datetime(str(item["datetime"]))
                rsi = float(item["rsi"])
            except (KeyError, ValueError):
                continue
            points.append(RSIPoint(ts=ts, rsi=rsi))

        if len(points) < 2:
            self.last_error = "insufficient_values"
            return None

        return list(reversed(points))
