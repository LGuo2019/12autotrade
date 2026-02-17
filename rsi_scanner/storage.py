from __future__ import annotations

import sqlite3
from typing import Iterable, Optional

from .constants import DEFAULT_TIMEFRAME
from .models import AlertState, RSIPoint, WatchTier


class Storage:
    def __init__(self, path: str = "rsi_scanner.db") -> None:
        self.path = path
        self._conn = sqlite3.connect(self.path)
        self._conn.row_factory = sqlite3.Row
        self._init_db()

    def _init_db(self) -> None:
        cur = self._conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS rsi_cache(
                symbol TEXT NOT NULL,
                timeframe TEXT NOT NULL,
                ts INTEGER NOT NULL,
                rsi REAL NOT NULL,
                PRIMARY KEY(symbol, timeframe, ts)
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS alert_state(
                symbol TEXT NOT NULL,
                timeframe TEXT NOT NULL,
                last_state TEXT NOT NULL,
                last_ts INTEGER NOT NULL,
                last_alert_ts INTEGER NOT NULL,
                PRIMARY KEY(symbol, timeframe)
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS watch_tier(
                symbol TEXT NOT NULL,
                timeframe TEXT NOT NULL,
                tier TEXT NOT NULL,
                sticky_until_run INTEGER NOT NULL,
                PRIMARY KEY(symbol, timeframe)
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS rr_cursor(
                timeframe TEXT NOT NULL PRIMARY KEY,
                cursor_index INTEGER NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS api_usage(
                day TEXT NOT NULL PRIMARY KEY,
                credits_used INTEGER NOT NULL
            )
            """
        )
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def get_last_rsi(self, symbol: str, timeframe: str = DEFAULT_TIMEFRAME) -> Optional[RSIPoint]:
        cur = self._conn.cursor()
        row = cur.execute(
            """
            SELECT ts, rsi FROM rsi_cache
            WHERE symbol = ? AND timeframe = ?
            ORDER BY ts DESC LIMIT 1
            """,
            (symbol, timeframe),
        ).fetchone()
        if not row:
            return None
        return RSIPoint(ts=int(row["ts"]), rsi=float(row["rsi"]))

    def insert_rsi(self, symbol: str, timeframe: str, points: Iterable[RSIPoint]) -> None:
        cur = self._conn.cursor()
        cur.executemany(
            """
            INSERT OR REPLACE INTO rsi_cache(symbol, timeframe, ts, rsi)
            VALUES (?, ?, ?, ?)
            """,
            [(symbol, timeframe, p.ts, p.rsi) for p in points],
        )
        cur.execute(
            """
            DELETE FROM rsi_cache
            WHERE symbol = ? AND timeframe = ?
            AND ts NOT IN (
                SELECT ts FROM rsi_cache
                WHERE symbol = ? AND timeframe = ?
                ORDER BY ts DESC LIMIT 200
            )
            """,
            (symbol, timeframe, symbol, timeframe),
        )
        self._conn.commit()

    def get_alert_state(self, symbol: str, timeframe: str) -> Optional[AlertState]:
        cur = self._conn.cursor()
        row = cur.execute(
            """
            SELECT last_state, last_ts, last_alert_ts
            FROM alert_state
            WHERE symbol = ? AND timeframe = ?
            """,
            (symbol, timeframe),
        ).fetchone()
        if not row:
            return None
        return AlertState(
            last_state=str(row["last_state"]),
            last_ts=int(row["last_ts"]),
            last_alert_ts=int(row["last_alert_ts"]),
        )

    def upsert_alert_state(self, symbol: str, timeframe: str, state: AlertState) -> None:
        cur = self._conn.cursor()
        cur.execute(
            """
            INSERT INTO alert_state(symbol, timeframe, last_state, last_ts, last_alert_ts)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(symbol, timeframe) DO UPDATE SET
                last_state=excluded.last_state,
                last_ts=excluded.last_ts,
                last_alert_ts=excluded.last_alert_ts
            """,
            (symbol, timeframe, state.last_state, state.last_ts, state.last_alert_ts),
        )
        self._conn.commit()

    def get_watch_tier(self, symbol: str, timeframe: str) -> Optional[WatchTier]:
        cur = self._conn.cursor()
        row = cur.execute(
            """
            SELECT tier, sticky_until_run
            FROM watch_tier
            WHERE symbol = ? AND timeframe = ?
            """,
            (symbol, timeframe),
        ).fetchone()
        if not row:
            return None
        return WatchTier(tier=str(row["tier"]), sticky_until_run=int(row["sticky_until_run"]))

    def upsert_watch_tier(self, symbol: str, timeframe: str, tier: WatchTier) -> None:
        cur = self._conn.cursor()
        cur.execute(
            """
            INSERT INTO watch_tier(symbol, timeframe, tier, sticky_until_run)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(symbol, timeframe) DO UPDATE SET
                tier=excluded.tier,
                sticky_until_run=excluded.sticky_until_run
            """,
            (symbol, timeframe, tier.tier, tier.sticky_until_run),
        )
        self._conn.commit()

    def get_rr_cursor(self, timeframe: str) -> int:
        cur = self._conn.cursor()
        row = cur.execute(
            "SELECT cursor_index FROM rr_cursor WHERE timeframe = ?",
            (timeframe,),
        ).fetchone()
        if not row:
            return 0
        return int(row["cursor_index"])

    def set_rr_cursor(self, timeframe: str, cursor_index: int) -> None:
        cur = self._conn.cursor()
        cur.execute(
            """
            INSERT INTO rr_cursor(timeframe, cursor_index)
            VALUES (?, ?)
            ON CONFLICT(timeframe) DO UPDATE SET cursor_index=excluded.cursor_index
            """,
            (timeframe, cursor_index),
        )
        self._conn.commit()

    def get_day_usage(self, day: str) -> int:
        cur = self._conn.cursor()
        row = cur.execute(
            "SELECT credits_used FROM api_usage WHERE day = ?",
            (day,),
        ).fetchone()
        if not row:
            return 0
        return int(row["credits_used"])

    def set_day_usage(self, day: str, credits_used: int) -> None:
        cur = self._conn.cursor()
        cur.execute(
            """
            INSERT INTO api_usage(day, credits_used)
            VALUES (?, ?)
            ON CONFLICT(day) DO UPDATE SET credits_used=excluded.credits_used
            """,
            (day, credits_used),
        )
        self._conn.commit()
