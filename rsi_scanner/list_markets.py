from __future__ import annotations

import argparse
import csv
from pathlib import Path
from typing import Any

import requests

from .config import load_config, resolve_secret


ENDPOINTS: dict[str, str] = {
    "exchanges": "https://api.twelvedata.com/exchanges",
    "stocks": "https://api.twelvedata.com/stocks",
    "forex_pairs": "https://api.twelvedata.com/forex_pairs",
    "cryptocurrencies": "https://api.twelvedata.com/cryptocurrencies",
    "etfs": "https://api.twelvedata.com/etfs/list",
    "indices": "https://api.twelvedata.com/indices",
    "funds": "https://api.twelvedata.com/funds",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Export TwelveData supported markets")
    parser.add_argument("--config", default="config.yaml")
    parser.add_argument("--output", default="markets.csv")
    parser.add_argument("--format", choices=["csv", "tsv"], default="csv")
    parser.add_argument(
        "--only",
        default=",".join(ENDPOINTS.keys()),
        help="Comma-separated endpoint keys: exchanges,stocks,forex_pairs,cryptocurrencies,etfs,indices,funds",
    )
    parser.add_argument("--timeout", type=int, default=30)
    return parser


def _fetch_data(session: requests.Session, url: str, api_key: str, timeout: int) -> list[dict[str, Any]]:
    response = session.get(url, params={"apikey": api_key}, timeout=timeout)
    response.raise_for_status()
    payload = response.json()
    if payload.get("status") == "error":
        message = payload.get("message", "unknown error")
        raise RuntimeError(f"TwelveData error from {url}: {message}")
    data = payload.get("data")
    if not isinstance(data, list):
        return []
    return data


def _row_for(kind: str, item: dict[str, Any]) -> dict[str, str]:
    return {
        "type": kind,
        "id": str(item.get("code") or item.get("mic_code") or item.get("symbol") or ""),
        "symbol": str(item.get("symbol") or ""),
        "name": str(item.get("name") or item.get("currency_group") or item.get("currency_base") or ""),
        "country": str(item.get("country") or ""),
        "exchange": str(item.get("exchange") or ""),
        "currency": str(item.get("currency") or ""),
    }


def main() -> None:
    args = build_parser().parse_args()
    cfg = load_config(args.config)
    api_key = resolve_secret(cfg.twelvedata_api_key_env, cfg.twelvedata_api_key)
    if not api_key:
        raise SystemExit("Missing TwelveData API key (env or config)")

    requested = [part.strip() for part in args.only.split(",") if part.strip()]
    invalid = [name for name in requested if name not in ENDPOINTS]
    if invalid:
        raise SystemExit(f"Invalid --only values: {','.join(invalid)}")

    rows: list[dict[str, str]] = []
    session = requests.Session()
    for kind in requested:
        url = ENDPOINTS[kind]
        items = _fetch_data(session, url, api_key, args.timeout)
        rows.extend(_row_for(kind, item) for item in items)

    fields = ["type", "id", "symbol", "name", "country", "exchange", "currency"]
    delimiter = "\t" if args.format == "tsv" else ","

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields, delimiter=delimiter)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Wrote {len(rows)} rows to {output_path}")


if __name__ == "__main__":
    main()
