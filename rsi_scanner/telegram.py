from __future__ import annotations

import logging
import time
from datetime import datetime, timezone

import requests

from .models import Alert

logger = logging.getLogger("rsi_scanner.telegram")


class TelegramSendError(Exception):
    pass


class TelegramClient:
    def __init__(self, token: str, chat_id: str, dry_run: bool = False) -> None:
        self.token = token
        self.chat_id = chat_id
        self.dry_run = dry_run
        self._session = requests.Session()

    def send_alert(self, alert: Alert) -> None:
        message = (
            "RSI ALERT\n"
            f"Symbol: {alert.symbol}\n"
            f"TF: {alert.timeframe}\n"
            f"Value: {alert.value:.1f}\n"
            f"State: {alert.state}\n"
            f"Time: {self._format_ts(alert.ts)}"
        )

        if self.dry_run:
            print(message)
            return

        self._send_message(message)

    def send_scan_summary(
        self,
        *,
        timeframe: str,
        symbols_total: int,
        planned: int,
        scanned: int,
        alerts: int,
        skipped: int,
        no_data: int,
        budget_halted: bool,
        remaining_day: int,
    ) -> None:
        status = "BUDGET_HALTED" if budget_halted else "OK"
        message = (
            "RSI SCAN SUMMARY\n"
            f"TF: {timeframe}\n"
            f"Universe: {symbols_total}\n"
            f"Planned: {planned}\n"
            f"Scanned: {scanned}\n"
            f"No Data: {no_data}\n"
            f"Skipped: {skipped}\n"
            f"Alerts: {alerts}\n"
            f"Remaining Day Credits: {remaining_day}\n"
            f"Status: {status}\n"
            f"Time: {self._format_ts(int(time.time()))}"
        )

        if self.dry_run:
            print(message)
            return

        self._send_message(message)

    def _send_message(self, message: str) -> None:
        url = f"https://api.telegram.org/bot{self.token}/sendMessage"
        payload = {"chat_id": self.chat_id, "text": message}

        resp = self._session.post(url, json=payload, timeout=15)
        if resp.status_code == 429:
            try:
                retry_after = int(resp.json().get("parameters", {}).get("retry_after", 1))
            except ValueError:
                retry_after = 1
            time.sleep(retry_after)
            resp = self._session.post(url, json=payload, timeout=15)

        if resp.status_code >= 400:
            detail = _telegram_error_detail(resp)
            raise TelegramSendError(
                f"telegram_send_failed status={resp.status_code} detail={detail}"
            )

    @staticmethod
    def _format_ts(ts: int) -> str:
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M UTC")


def _telegram_error_detail(resp: requests.Response) -> str:
    try:
        payload = resp.json()
        description = payload.get("description")
        if isinstance(description, str) and description:
            return description
    except ValueError:
        pass
    text = (resp.text or "").strip()
    if text:
        return text
    return "unknown_error"
