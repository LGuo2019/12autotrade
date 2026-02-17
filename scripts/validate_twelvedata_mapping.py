#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import math
import sys
import time
from collections import deque
from pathlib import Path
from typing import Any

import requests

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from rsi_scanner.config import load_config, resolve_secret


def _load_mapping(path: Path) -> dict[str, str]:
    with path.open("r", encoding="utf-8") as f:
        payload = json.load(f)
    if isinstance(payload, dict) and "epic_to_twelvedata_symbol" in payload:
        mapping = payload["epic_to_twelvedata_symbol"]
    else:
        mapping = payload
    if not isinstance(mapping, dict):
        raise ValueError("mapping JSON must be an object or contain epic_to_twelvedata_symbol")
    return {str(k): str(v) for k, v in mapping.items()}


def _classify_error(message: str) -> str:
    msg = (message or "").lower()
    if "grow plan" in msg or "consider upgrading" in msg:
        return "plan_restricted"
    if "symbol" in msg and "invalid" in msg:
        return "invalid_symbol"
    if "figi" in msg and "invalid" in msg:
        return "invalid_symbol"
    if "api key" in msg:
        return "auth_error"
    if "too many requests" in msg:
        return "rate_limited"
    return "api_error"


def _rate_limit(history: deque[float], per_minute: int) -> None:
    if per_minute <= 0:
        raise ValueError("effective per-minute budget is zero; check limits/reserve in config")
    now = time.time()
    while history and now - history[0] >= 60.0:
        history.popleft()
    if len(history) < per_minute:
        return
    wait_s = 60.0 - (now - history[0]) + 0.05
    if wait_s > 0:
        time.sleep(wait_s)
    now = time.time()
    while history and now - history[0] >= 60.0:
        history.popleft()


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate IG->TwelveData mapped symbols via /rsi")
    parser.add_argument("--config", default="config.yaml")
    parser.add_argument("--mapping-in", default="rsi_universe_epic_to_twelvedata_symbol.json")
    parser.add_argument("--out", default="rsi_universe_twelvedata_validation.json")
    parser.add_argument("--interval", default="2h")
    parser.add_argument("--time-period", type=int, default=14)
    parser.add_argument("--outputsize", type=int, default=2)
    parser.add_argument("--limit", type=int, default=0, help="Validate only first N mappings (0 = all)")
    args = parser.parse_args()

    cfg = load_config(args.config)
    api_key = resolve_secret(cfg.twelvedata_api_key_env, cfg.twelvedata_api_key)
    if not api_key:
        raise SystemExit(
            f"Missing TwelveData API key. Set {cfg.twelvedata_api_key_env} or twelvedata.api_key in {args.config}"
        )

    mapping_path = Path(args.mapping_in)
    mapping = _load_mapping(mapping_path)
    if args.limit and args.limit > 0:
        mapping = dict(list(mapping.items())[: args.limit])
    total = len(mapping)

    effective_per_min = max(0, int(math.floor(cfg.limits_per_min * (1.0 - cfg.reserve_pct))))
    effective_per_day = max(0, int(math.floor(cfg.limits_per_day * (1.0 - cfg.reserve_pct))))
    daily_remaining = effective_per_day

    session = requests.Session()
    history: deque[float] = deque()
    rows: list[dict[str, Any]] = []

    counts = {
        "valid": 0,
        "invalid_symbol": 0,
        "plan_restricted": 0,
        "auth_error": 0,
        "rate_limited": 0,
        "api_error": 0,
        "http_error": 0,
        "network_error": 0,
        "budget_skipped": 0,
    }

    for i, (epic, symbol) in enumerate(mapping.items(), start=1):
        if daily_remaining <= 0:
            counts["budget_skipped"] += 1
            rows.append(
                {
                    "epic": epic,
                    "symbol": symbol,
                    "status": "budget_skipped",
                    "message": "daily effective limit reached",
                }
            )
            continue

        _rate_limit(history, effective_per_min)
        params = {
            "symbol": symbol,
            "interval": args.interval,
            "time_period": args.time_period,
            "outputsize": args.outputsize,
            "apikey": api_key,
        }
        history.append(time.time())
        daily_remaining -= 1

        try:
            resp = session.get("https://api.twelvedata.com/rsi", params=params, timeout=20)
            status_code = resp.status_code
            payload = resp.json()
        except requests.RequestException as exc:
            counts["network_error"] += 1
            rows.append(
                {
                    "epic": epic,
                    "symbol": symbol,
                    "status": "network_error",
                    "message": str(exc),
                }
            )
            print(f"[{i}/{total}] {epic} -> {symbol}: network_error", flush=True)
            continue
        except ValueError:
            counts["http_error"] += 1
            rows.append(
                {
                    "epic": epic,
                    "symbol": symbol,
                    "status": "http_error",
                    "message": f"non_json_response status={status_code}",
                }
            )
            print(f"[{i}/{total}] {epic} -> {symbol}: http_error non_json", flush=True)
            continue

        if status_code != 200:
            counts["http_error"] += 1
            rows.append(
                {
                    "epic": epic,
                    "symbol": symbol,
                    "status": "http_error",
                    "message": f"http_status={status_code}",
                }
            )
            print(f"[{i}/{total}] {epic} -> {symbol}: http_error status={status_code}", flush=True)
            continue

        if payload.get("status") == "ok" and isinstance(payload.get("values"), list) and payload.get("values"):
            counts["valid"] += 1
            rows.append(
                {
                    "epic": epic,
                    "symbol": symbol,
                    "status": "valid",
                    "message": "",
                }
            )
            print(f"[{i}/{total}] {epic} -> {symbol}: valid", flush=True)
            continue

        message = str(payload.get("message") or payload)
        status = _classify_error(message)
        counts[status] = counts.get(status, 0) + 1
        rows.append(
            {
                "epic": epic,
                "symbol": symbol,
                "status": status,
                "message": message,
            }
        )
        print(f"[{i}/{total}] {epic} -> {symbol}: {status}", flush=True)

    output = {
        "summary": {
            "total": total,
            "effective_per_minute": effective_per_min,
            "effective_per_day": effective_per_day,
            "daily_remaining_after_run": daily_remaining,
            "counts": counts,
        },
        "results": rows,
    }

    out_path = Path(args.out)
    out_path.write_text(json.dumps(output, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nWrote validation report: {out_path}", flush=True)
    print(f"Summary: {json.dumps(output['summary']['counts'], ensure_ascii=False)}", flush=True)


if __name__ == "__main__":
    main()
