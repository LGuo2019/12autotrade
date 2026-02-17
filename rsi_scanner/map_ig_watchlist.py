from __future__ import annotations

import argparse
import csv
import difflib
import re
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class MarketRow:
    type: str
    id: str
    symbol: str
    name: str
    country: str
    exchange: str
    currency: str
    norm_name: str
    norm_symbol: str
    compact_name: str
    compact_symbol: str


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Map IG watchlist names to TwelveData symbols")
    parser.add_argument("--ig-file", required=True, help="IG watchlist file (txt/csv)")
    parser.add_argument("--markets", default="markets.csv", help="TwelveData markets CSV")
    parser.add_argument("--output", default="ig_to_twelvedata.csv", help="Output mapping CSV")
    parser.add_argument(
        "--types",
        default="stocks,etfs,indices,forex_pairs,cryptocurrencies,funds",
        help="Comma-separated market types to include",
    )
    parser.add_argument("--min-score", type=float, default=0.72, help="Minimum fuzzy score to accept")
    return parser


def normalize(text: str) -> str:
    t = text.upper().strip()
    t = t.replace("&", " AND ")
    t = t.replace("/", " ")
    t = re.sub(r"\b(PLC|INC|LTD|LIMITED|CORP|CORPORATION|HOLDINGS|HOLDING|SA|NV|AG|ADR|ETF)\b", " ", t)
    t = re.sub(r"[^A-Z0-9 ]+", " ", t)
    t = re.sub(r"\s+", " ", t).strip()
    return t


def compact(text: str) -> str:
    return re.sub(r"[^A-Z0-9]+", "", text.upper())


def rank_bonus(row: MarketRow) -> float:
    ex = row.exchange.upper()
    country = row.country.upper()
    bonus = 0.0
    if ex in {"NASDAQ", "NYSE", "AMEX"}:
        bonus += 0.06
    if country in {"UNITED STATES", "USA", "US"}:
        bonus += 0.04
    return bonus


def load_markets(path: str, allowed_types: set[str]) -> list[MarketRow]:
    rows: list[MarketRow] = []
    with open(path, "r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for r in reader:
            r_type = (r.get("type") or "").strip()
            if r_type not in allowed_types:
                continue
            symbol = (r.get("symbol") or "").strip()
            name = (r.get("name") or "").strip()
            if not symbol and not name:
                continue
            rows.append(
                MarketRow(
                    type=r_type,
                    id=(r.get("id") or "").strip(),
                    symbol=symbol,
                    name=name,
                    country=(r.get("country") or "").strip(),
                    exchange=(r.get("exchange") or "").strip(),
                    currency=(r.get("currency") or "").strip(),
                    norm_name=normalize(name),
                    norm_symbol=normalize(symbol),
                    compact_name=compact(name),
                    compact_symbol=compact(symbol),
                )
            )
    return rows


def load_ig_names(path: str) -> list[str]:
    p = Path(path)
    if p.suffix.lower() in {".txt", ".list"}:
        with p.open("r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]

    with p.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        headers = [h for h in (reader.fieldnames or []) if h]
        preferred = ["name", "market", "market_name", "epic", "instrument"]
        chosen = ""
        lowered = {h.lower(): h for h in headers}
        for key in preferred:
            if key in lowered:
                chosen = lowered[key]
                break
        if not chosen and headers:
            chosen = headers[0]
        if not chosen:
            return []
        names = []
        for row in reader:
            value = (row.get(chosen) or "").strip()
            if value:
                names.append(value)
        return names


def best_match(name: str, markets: list[MarketRow], min_score: float) -> tuple[str, float, MarketRow | None]:
    norm = normalize(name)
    comp = compact(name)
    if not norm:
        return "none", 0.0, None

    pair = re.fullmatch(r"([A-Z]{3})/([A-Z]{3})", name.strip().upper())
    if pair:
        pair_comp = f"{pair.group(1)}{pair.group(2)}"
        direct = [
            row
            for row in markets
            if row.compact_symbol == pair_comp or row.compact_name == pair_comp
        ]
        if direct:
            best = max(direct, key=rank_bonus)
            return "symbol_exact", 1.0, best

    symbol_exact = [
        row
        for row in markets
        if (row.norm_symbol and norm == row.norm_symbol) or (row.compact_symbol and comp == row.compact_symbol)
    ]
    if symbol_exact:
        best = max(symbol_exact, key=rank_bonus)
        return "symbol_exact", 1.0, best

    name_exact = [
        row
        for row in markets
        if (row.norm_name and norm == row.norm_name) or (row.compact_name and comp == row.compact_name)
    ]
    if name_exact:
        best = max(name_exact, key=rank_bonus)
        return "name_exact", 1.0, best

    contains: list[tuple[float, MarketRow]] = []
    for row in markets:
        if row.norm_name and (norm in row.norm_name or row.norm_name in norm):
            score = difflib.SequenceMatcher(None, norm, row.norm_name).ratio() + rank_bonus(row)
            contains.append((score, row))
        elif row.compact_name and comp and (comp in row.compact_name or row.compact_name in comp):
            score = difflib.SequenceMatcher(None, comp, row.compact_name).ratio() + rank_bonus(row)
            contains.append((score, row))
    if contains:
        score, row = max(contains, key=lambda x: x[0])
        if score >= min_score:
            return "contains", score, row

    best_score = 0.0
    best_row: MarketRow | None = None
    for row in markets:
        target = row.norm_name or row.norm_symbol
        if not target:
            continue
        score = difflib.SequenceMatcher(None, norm, target).ratio() + rank_bonus(row)
        if row.compact_name and comp:
            score = max(score, difflib.SequenceMatcher(None, comp, row.compact_name).ratio() + rank_bonus(row))
        if row.compact_symbol and comp:
            score = max(score, difflib.SequenceMatcher(None, comp, row.compact_symbol).ratio() + rank_bonus(row))
        if score > best_score:
            best_score = score
            best_row = row
    if best_row and best_score >= min_score:
        return "fuzzy", best_score, best_row

    return "none", best_score, None


def main() -> None:
    args = build_parser().parse_args()
    allowed = {x.strip() for x in args.types.split(",") if x.strip()}
    markets = load_markets(args.markets, allowed)
    ig_names = load_ig_names(args.ig_file)

    out_fields = [
        "ig_name",
        "match_kind",
        "score",
        "td_type",
        "td_id",
        "td_symbol",
        "td_name",
        "td_country",
        "td_exchange",
        "td_currency",
    ]

    matched = 0
    with open(args.output, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=out_fields)
        writer.writeheader()
        for name in ig_names:
            kind, score, row = best_match(name, markets, args.min_score)
            if row:
                matched += 1
                writer.writerow(
                    {
                        "ig_name": name,
                        "match_kind": kind,
                        "score": f"{score:.3f}",
                        "td_type": row.type,
                        "td_id": row.id,
                        "td_symbol": row.symbol,
                        "td_name": row.name,
                        "td_country": row.country,
                        "td_exchange": row.exchange,
                        "td_currency": row.currency,
                    }
                )
            else:
                writer.writerow(
                    {
                        "ig_name": name,
                        "match_kind": "unmapped",
                        "score": f"{score:.3f}",
                        "td_type": "",
                        "td_id": "",
                        "td_symbol": "",
                        "td_name": "",
                        "td_country": "",
                        "td_exchange": "",
                        "td_currency": "",
                    }
                )

    print(f"IG rows={len(ig_names)} matched={matched} unmapped={len(ig_names)-matched} output={args.output}")


if __name__ == "__main__":
    main()
