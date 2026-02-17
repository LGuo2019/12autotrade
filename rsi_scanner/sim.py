from __future__ import annotations

import csv
import json
import logging
import os
import re
from datetime import datetime, timezone
from typing import Dict, List, Optional

from .models import RSIPoint

logger = logging.getLogger("rsi_scanner.sim")


class SimDataSource:
    def __init__(self, csv_path: str) -> None:
        self.csv_path = csv_path
        self._data: Dict[str, List[RSIPoint]] = {}
        self._index: Dict[str, int] = {}
        self._load()

    def _load(self) -> None:
        with open(self.csv_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                symbol = row.get("symbol") or ""
                dt_str = row.get("datetime") or ""
                rsi_str = row.get("rsi") or ""
                if not symbol or not dt_str or not rsi_str:
                    continue
                ts = int(
                    datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc).timestamp()
                )
                point = RSIPoint(ts=ts, rsi=float(rsi_str))
                self._data.setdefault(symbol, []).append(point)

        for symbol, points in self._data.items():
            points.sort(key=lambda p: p.ts)
            self._index[symbol] = 0

    def next_two(self, symbol: str) -> Optional[List[RSIPoint]]:
        points = self._data.get(symbol)
        if not points:
            return None
        idx = self._index.get(symbol, 0)
        if idx + 1 >= len(points):
            return None
        self._index[symbol] = idx + 1
        return [points[idx], points[idx + 1]]


class SimJSONSource:
    def __init__(self, path: str) -> None:
        self.path = path
        self._data: Dict[str, List[RSIPoint]] = {}
        self._index: Dict[str, int] = {}
        self._default_streams: List[List[RSIPoint]] = []
        self._assigned_default_stream: Dict[str, int] = {}
        self._missing_logged: set[str] = set()
        self._load()

    def _load(self) -> None:
        if os.path.isdir(self.path):
            for filename in os.listdir(self.path):
                if not filename.endswith(".json"):
                    continue
                path = os.path.join(self.path, filename)
                symbol, points = self._load_one(path, filename[:-5])
                if not points:
                    continue
                if symbol:
                    self._data[symbol] = points
                else:
                    self._default_streams.append(points)
        else:
            with open(self.path, "r", encoding="utf-8") as f:
                payload = json.load(f)
            for symbol, values in payload.items():
                self._data[str(symbol)] = self._parse_values(values)

        for symbol, points in self._data.items():
            points.sort(key=lambda p: p.ts)
            self._index[symbol] = 0
        for points in self._default_streams:
            points.sort(key=lambda p: p.ts)

        logger.info(
            "sim_json_loaded symbol_streams=%d default_streams=%d path=%s",
            len(self._data),
            len(self._default_streams),
            self.path,
        )

    def _load_one(self, path: str, stem: str) -> tuple[str | None, List[RSIPoint]]:
        with open(path, "r", encoding="utf-8") as f:
            payload = json.load(f)
        values = payload.get("values") or []
        symbol = payload.get("symbol")
        if isinstance(symbol, str) and symbol.strip():
            return symbol.strip(), self._parse_values(values)
        inferred = self._infer_symbol_from_stem(stem)
        return inferred, self._parse_values(values)

    @staticmethod
    def _parse_values(values: List[dict]) -> List[RSIPoint]:
        points: List[RSIPoint] = []
        for item in values:
            dt_str = item.get("datetime")
            rsi_str = item.get("rsi")
            if not dt_str or rsi_str is None:
                continue
            ts = int(
                datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc).timestamp()
            )
            points.append(RSIPoint(ts=ts, rsi=float(rsi_str)))
        return points

    @staticmethod
    def _infer_symbol_from_stem(stem: str) -> str | None:
        # Supports common sim fixture naming such as EUR_USD.json and AAPL.json.
        if re.fullmatch(r"[A-Za-z0-9]+", stem):
            return stem.upper()
        if re.fullmatch(r"[A-Za-z0-9]+_[A-Za-z0-9]+", stem):
            left, right = stem.split("_", 1)
            return f"{left.upper()}/{right.upper()}"
        return None

    def next_two(self, symbol: str) -> Optional[List[RSIPoint]]:
        if symbol not in self._data and self._default_streams:
            stream_idx = self._assigned_default_stream.get(symbol)
            if stream_idx is None:
                stream_idx = len(self._assigned_default_stream) % len(self._default_streams)
                self._assigned_default_stream[symbol] = stream_idx
                self._data[symbol] = list(self._default_streams[stream_idx])
                self._index[symbol] = 0
                logger.info("sim_json_assign_default symbol=%s stream=%d", symbol, stream_idx)

        points = self._data.get(symbol)
        if not points:
            if symbol not in self._missing_logged:
                logger.warning("sim_json_missing_symbol symbol=%s", symbol)
                self._missing_logged.add(symbol)
            return None
        idx = self._index.get(symbol, 0)
        if idx + 1 >= len(points):
            return None
        self._index[symbol] = idx + 1
        return [points[idx], points[idx + 1]]


class SimClient:
    def __init__(self, data: SimDataSource | SimJSONSource) -> None:
        self.data = data

    def fetch_rsi(self, symbol: str, interval: str) -> Optional[List[RSIPoint]]:
        _ = interval
        return self.data.next_two(symbol)
