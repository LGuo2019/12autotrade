#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from dataclasses import dataclass
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any
from urllib.parse import quote

import requests

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from rsi_scanner.config import load_config, resolve_secret
from rsi_scanner.main import (
    load_symbol_mapping,
    load_symbol_to_epic_map,
    load_symbols,
)


def _norm(s: str) -> str:
    return "".join(ch.lower() for ch in s if ch.isalnum())


def _norm_watchlist_name(name: str) -> str:
    n = str(name or "").lower().strip()
    n = n.replace("hours", "hour")
    n = n.replace("hrs", "hour")
    n = n.replace("hr", "hour")
    n = re.sub(r"[^a-z0-9]+", "", n)
    return n


def _symbol_key(symbol: str) -> str:
    value = str(symbol).strip().upper()
    if not value:
        return ""
    return re.sub(r"\s+", "", value)


def _http_error_detail(resp: requests.Response) -> str:
    try:
        payload = resp.json()
        msg = payload.get("errorCode") or payload.get("message") or payload.get("error")
        if msg:
            return str(msg)
    except ValueError:
        pass
    text = (resp.text or "").strip()
    return text[:200] if text else "unknown_error"


def _extract_epic_and_name(row: dict[str, Any]) -> tuple[str, str]:
    instrument = row.get("instrument", {}) if isinstance(row.get("instrument"), dict) else {}
    epic = str(row.get("epic") or instrument.get("epic") or "").strip()
    name = str(
        row.get("instrumentName")
        or row.get("marketName")
        or row.get("name")
        or instrument.get("name")
        or instrument.get("marketName")
        or ""
    ).strip()
    return epic, _clean_match_text(name)


def _clean_match_text(value: str) -> str:
    text = str(value or "").strip()
    # Remove IG session suffixes like "(24 Hours)" and other parenthetical tags.
    text = re.sub(r"\((?:[^)]*24\s*hours?[^)]*|[^)]*)\)", " ", text, flags=re.IGNORECASE)
    text = re.sub(r"\b(24\s*hours?|all\s*sessions?)\b", " ", text, flags=re.IGNORECASE)
    text = re.sub(r"[^A-Za-z0-9]+", " ", text)
    text = re.sub(r"\s+", " ", text).strip().lower()
    return text


def _score_market_candidate(symbol: str, display_name: str, candidate_name: str, row: dict[str, Any]) -> float:
    name_l = _clean_match_text(candidate_name)
    display_l = _clean_match_text(display_name)
    symbol_u = str(symbol or "").strip().upper()
    epic = str(
        row.get("epic")
        or (row.get("instrument", {}) if isinstance(row.get("instrument"), dict) else {}).get("epic")
        or ""
    ).strip().upper()
    if not display_l and not symbol_u:
        return 0.0

    score = 0.0

    # Strong signal: ticker embedded in IG epic (e.g. ... .VZ. ...).
    if symbol_u and epic:
        if f".{symbol_u}." in epic:
            score += 0.75
        elif symbol_u in epic:
            score += 0.45

    market = row.get("market", {}) if isinstance(row.get("market"), dict) else {}
    instrument = row.get("instrument", {}) if isinstance(row.get("instrument"), dict) else {}
    type_text = " ".join(
        str(x)
        for x in (
            row.get("instrumentType"),
            row.get("type"),
            market.get("instrumentType"),
            instrument.get("type"),
        )
        if x is not None
    ).upper()
    if any(token in type_text for token in ("SHARE", "EQUITY", "STOCK")):
        score += 0.10

    if display_l and name_l:
        if display_l == name_l:
            score += 0.80
        elif display_l in name_l or name_l in display_l:
            score += 0.65
        score += 0.35 * SequenceMatcher(None, display_l, name_l).ratio()

    return max(0.0, min(score, 1.0))


@dataclass
class IGClient:
    base_url: str
    api_key: str
    identifier: str
    password: str
    account_id: str = ""

    def __post_init__(self) -> None:
        self.base_url = self.base_url.rstrip("/")
        self.session = requests.Session()
        self.oauth_access_token = ""
        self.oauth_account_id = self.account_id.strip()
        self.cst = ""
        self.xst = ""

    def login(self) -> None:
        errors: list[str] = []
        # Match AutoTrade behavior first: v2 session tokens + IG-ACCOUNT-ID context.
        for version in ("2", "3"):
            headers = {
                "X-IG-API-KEY": self.api_key,
                "Content-Type": "application/json; charset=UTF-8",
                "Accept": "application/json; charset=UTF-8",
                "Version": version,
            }
            payload = {"identifier": self.identifier, "password": self.password, "encryptedPassword": False}
            resp = self.session.post(f"{self.base_url}/session", headers=headers, json=payload, timeout=30)
            if resp.status_code >= 400:
                errors.append(f"v{version}:{resp.status_code}:{_http_error_detail(resp)}")
                continue
            if version == "2":
                self.cst = resp.headers.get("CST", "")
                self.xst = resp.headers.get("X-SECURITY-TOKEN", "")
                if self.cst and self.xst:
                    return
                errors.append("v2:missing_session_tokens")
                continue

            body = resp.json() if resp.content else {}
            oauth = body.get("oauthToken", {}) if isinstance(body, dict) else {}
            token = str(oauth.get("access_token", "")).strip()
            if token:
                self.oauth_access_token = token
                # Keep configured account context if provided; only fallback to currentAccountId when empty.
                if not self.oauth_account_id:
                    account_id = str(body.get("currentAccountId", "")).strip()
                    if account_id:
                        self.oauth_account_id = account_id
                return
            errors.append("v3:missing_oauth_token")
        raise RuntimeError("IG login failed: " + " | ".join(errors))

    def _headers(self, version: str = "1") -> dict[str, str]:
        headers = {
            "X-IG-API-KEY": self.api_key,
            "Content-Type": "application/json; charset=UTF-8",
            "Accept": "application/json; charset=UTF-8",
            "Version": version,
        }
        if self.oauth_access_token:
            headers["Authorization"] = f"Bearer {self.oauth_access_token}"
            if self.oauth_account_id:
                headers["IG-ACCOUNT-ID"] = self.oauth_account_id
        else:
            headers["CST"] = self.cst
            headers["X-SECURITY-TOKEN"] = self.xst
            if self.oauth_account_id:
                headers["IG-ACCOUNT-ID"] = self.oauth_account_id
        return headers

    def get_watchlists(self) -> list[dict[str, Any]]:
        resp = self.session.get(f"{self.base_url}/watchlists", headers=self._headers("1"), timeout=30)
        if resp.status_code >= 400:
            raise RuntimeError(f"IG get_watchlists failed: {resp.status_code} {_http_error_detail(resp)}")
        payload = resp.json()
        return payload.get("watchlists", []) or []

    def get_watchlist(self, watchlist_id: str) -> dict[str, Any]:
        resp = self.session.get(
            f"{self.base_url}/watchlists/{requests.utils.quote(str(watchlist_id), safe='')}",
            headers=self._headers("1"),
            timeout=30,
        )
        if resp.status_code >= 400:
            raise RuntimeError(f"IG get_watchlist failed: {resp.status_code} {_http_error_detail(resp)}")
        return resp.json()

    def fetch_accounts(self) -> list[dict[str, Any]]:
        resp = self.session.get(f"{self.base_url}/accounts", headers=self._headers("1"), timeout=30)
        if resp.status_code >= 400:
            raise RuntimeError(f"IG fetch_accounts failed: {resp.status_code} {_http_error_detail(resp)}")
        payload = resp.json()
        rows = payload.get("accounts")
        return rows if isinstance(rows, list) else []

    def switch_account(self, account_id: str) -> None:
        if not account_id:
            return
        payload = {"accountId": account_id, "defaultAccount": False}
        resp = self.session.put(f"{self.base_url}/session", headers=self._headers("1"), json=payload, timeout=30)
        if resp.status_code >= 400:
            raise RuntimeError(f"IG switch_account failed: {resp.status_code} {_http_error_detail(resp)}")
        self.oauth_account_id = account_id

    def fetch_root_navigation(self) -> dict[str, Any]:
        return self._fetch_navigation(None)

    def fetch_navigation_node(self, node_id: str) -> dict[str, Any]:
        return self._fetch_navigation(node_id)

    def _fetch_navigation(self, node_id: str | None) -> dict[str, Any]:
        paths = ["/market-navigation", "/marketnavigation"] if node_id is None else [
            f"/market-navigation/{quote(str(node_id))}",
            f"/marketnavigation/{quote(str(node_id))}",
        ]
        last_error = ""
        for p in paths:
            resp = self.session.get(f"{self.base_url}{p}", headers=self._headers("1"), timeout=30)
            if resp.status_code < 400:
                return resp.json()
            last_error = f"{resp.status_code} {_http_error_detail(resp)}"
        raise RuntimeError(f"IG navigation fetch failed: {last_error}")

    def search_markets(self, term: str) -> list[dict[str, Any]]:
        if not term:
            return []
        resp = self.session.get(
            f"{self.base_url}/markets?searchTerm={quote(term)}",
            headers=self._headers("1"),
            timeout=30,
        )
        if resp.status_code >= 400:
            return []
        payload = resp.json()
        out: list[dict[str, Any]] = []
        for key in ("markets", "marketDetails", "instruments"):
            rows = payload.get(key)
            if isinstance(rows, list):
                out.extend([r for r in rows if isinstance(r, dict)])
        return out


def _find_watchlist_entry(watchlists: list[dict[str, Any]], watchlist_name: str) -> dict[str, Any] | None:
    wanted = _norm_watchlist_name(watchlist_name)
    for w in watchlists:
        name = str(w.get("name") or w.get("watchlistName") or "").strip()
        if _norm_watchlist_name(name) == wanted:
            return w
    for w in watchlists:
        name = str(w.get("name") or w.get("watchlistName") or "").strip()
        n = _norm_watchlist_name(name)
        if wanted in n or n in wanted:
            return w
    return None


def _recover_watchlist_markets_across_accounts(
    ig: IGClient,
    watchlist_name: str,
) -> tuple[str, list[dict[str, Any]]] | None:
    target = _norm_watchlist_name(watchlist_name)
    try:
        accounts = ig.fetch_accounts()
    except Exception:
        return None

    for acc in accounts:
        account_id = str(acc.get("accountId") or "").strip()
        if not account_id:
            continue
        try:
            ig.switch_account(account_id)
            watchlists = ig.get_watchlists()
            wid = _find_watchlist_id(watchlists, watchlist_name)
            if not wid:
                continue
            details = ig.get_watchlist(wid)
            markets = details.get("markets") or []
            if isinstance(markets, list) and markets:
                return wid, markets
        except Exception:
            continue
    return None


def _recover_watchlist_markets_navigation(
    ig: IGClient,
    watchlist_name: str,
) -> list[dict[str, Any]]:
    wanted = _norm_watchlist_name(watchlist_name)
    try:
        root = ig.fetch_root_navigation()
    except Exception:
        return []
    queue: list[tuple[str, str]] = []
    for node in root.get("nodes", []):
        if not isinstance(node, dict):
            continue
        nid = str(node.get("id") or "").strip()
        nname = str(node.get("name") or "").strip()
        if nid:
            queue.append((nid, nname))

    seen: set[str] = set()
    while queue:
        node_id, node_name = queue.pop(0)
        if node_id in seen:
            continue
        seen.add(node_id)
        norm = _norm_watchlist_name(node_name)
        try:
            payload = ig.fetch_navigation_node(node_id)
        except Exception:
            continue
        if norm == wanted or wanted in norm or norm in wanted:
            markets = payload.get("markets") or []
            if isinstance(markets, list) and markets:
                return [m for m in markets if isinstance(m, dict)]
        for child in payload.get("nodes", []):
            if not isinstance(child, dict):
                continue
            cid = str(child.get("id") or "").strip()
            cname = str(child.get("name") or "").strip()
            if cid and cid not in seen:
                queue.append((cid, cname))
    return []


def _lookup_epic(symbol: str, symbol_to_epic_map: dict[str, str]) -> str:
    key = symbol.strip()
    if not key:
        return ""
    upper = key.upper()
    compact = upper.replace("/", "").replace(".", "").replace("-", "").replace(" ", "")
    candidates = [key, upper, compact]
    if ":" in upper:
        candidates.append(upper.split(":", 1)[0])
    for cand in candidates:
        epic = symbol_to_epic_map.get(cand, "")
        if epic:
            return epic
    return ""


def _resolve_symbol_epic(
    ig: IGClient,
    symbol: str,
    display_name: str,
    watchlist_markets: list[dict[str, Any]],
    min_score: float,
    delay_seconds: float,
) -> tuple[str, float, str, str, str]:
    # First, resolve from already-fetched watchlist markets.
    best_epic = ""
    best_score = -1.0
    best_name = ""
    best_source = ""
    for row in watchlist_markets:
        epic, name = _extract_epic_and_name(row)
        if not epic:
            continue
        score = _score_market_candidate(symbol, display_name, name, row)
        if score > best_score:
            best_epic = epic
            best_score = score
            best_name = name
            best_source = "watchlist"
    if best_score >= min_score:
        return best_epic, best_score, best_name, best_source, symbol

    # Second, fallback to IG /markets search.
    terms: list[str] = [symbol]
    base_symbol = symbol.split(":", 1)[0]
    if base_symbol and base_symbol != symbol:
        terms.append(base_symbol)
    if display_name.strip():
        terms.append(display_name.strip())

    dedup_terms: list[str] = []
    seen_terms: set[str] = set()
    for term in terms:
        t = term.strip()
        if not t:
            continue
        k = t.lower()
        if k in seen_terms:
            continue
        seen_terms.add(k)
        dedup_terms.append(t)

    best_epic = best_epic if best_score >= 0 else ""
    best_score = max(best_score, -1.0)
    seen_epics: set[str] = set()
    for term in dedup_terms:
        rows = ig.search_markets(term)
        if delay_seconds > 0:
            time.sleep(delay_seconds)
        for row in rows:
            epic, name = _extract_epic_and_name(row)
            if not epic or epic in seen_epics:
                continue
            seen_epics.add(epic)
            score = _score_market_candidate(symbol, display_name, name, row)
            if score > best_score:
                best_epic = epic
                best_score = score
                best_name = name
                best_source = f"search:{term}"
    if best_score < min_score:
        return "", max(best_score, 0.0), best_name, best_source, symbol
    return best_epic, best_score, best_name, best_source, symbol


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Populate IG watchlist cache for cache-only scan mode")
    p.add_argument("--config", default="config.yaml")
    p.add_argument("--cache-out", default="", help="Override scanner.ig_watchlist_cache_file")
    p.add_argument("--watchlist-name", default="", help="Override scanner.ig_watchlist_name")
    p.add_argument("--min-score", type=float, default=0.74, help="Min score for IG market search fallback")
    p.add_argument("--delay-seconds", type=float, default=0.2, help="Delay between IG market search calls")
    return p


def main() -> None:
    args = build_parser().parse_args()
    cfg = load_config(args.config)

    ig_api_key = resolve_secret(cfg.ig_api_key_env, cfg.ig_api_key)
    ig_identifier = resolve_secret(cfg.ig_identifier_env, cfg.ig_identifier)
    ig_password = resolve_secret(cfg.ig_password_env, cfg.ig_password)
    if not (ig_api_key and ig_identifier and ig_password):
        raise SystemExit("Missing IG credentials in config")

    watchlist_name = args.watchlist_name.strip() or cfg.ig_watchlist_name
    cache_file = args.cache_out.strip() or cfg.ig_watchlist_cache_file
    if not cache_file:
        raise SystemExit("Missing cache output path (scanner.ig_watchlist_cache_file)")

    symbol_display_map: dict[str, str] = {}
    if cfg.mapping_file:
        symbol_display_map = load_symbol_mapping(cfg.mapping_file)
    if symbol_display_map:
        symbols = list(symbol_display_map.keys())
    else:
        symbols = load_symbols(cfg.symbols_file)
        symbol_display_map = {s: s for s in symbols}

    symbol_to_epic_map = load_symbol_to_epic_map(cfg.ig_symbol_epic_map_file)

    ig = IGClient(
        base_url=cfg.ig_base_url,
        api_key=ig_api_key,
        identifier=ig_identifier,
        password=ig_password,
        account_id=cfg.ig_account_id,
    )
    ig.login()

    watchlists = ig.get_watchlists()
    watchlist_entry = _find_watchlist_entry(watchlists, watchlist_name)
    if not watchlist_entry:
        available = sorted(
            {
                str(w.get("name") or w.get("watchlistName") or "").strip()
                for w in watchlists
                if str(w.get("name") or w.get("watchlistName") or "").strip()
            }
        )
        raise SystemExit(f"Watchlist not found: {watchlist_name}. Available: {available}")
    name_fields = [
        str(watchlist_entry.get("id") or "").strip(),
        str(watchlist_entry.get("watchlistId") or "").strip(),
        str(watchlist_entry.get("name") or "").strip(),
        str(watchlist_entry.get("watchlistName") or "").strip(),
    ]
    candidate_ids: list[str] = []
    for cid in name_fields:
        if cid and cid not in candidate_ids:
            candidate_ids.append(cid)

    watchlist_id = candidate_ids[0] if candidate_ids else ""
    watchlist_markets: list[dict[str, Any]] = []
    for cid in candidate_ids:
        try:
            details = ig.get_watchlist(cid)
            rows = [m for m in (details.get("markets") or []) if isinstance(m, dict)]
            if rows:
                watchlist_id = cid
                watchlist_markets = rows
                break
            if not watchlist_markets:
                watchlist_id = cid
        except Exception:
            continue

    watchlist_epics = {
        str(m.get("epic") or "").strip()
        for m in watchlist_markets
        if str(m.get("epic") or "").strip()
    }
    if not watchlist_markets:
        print(
            "WARNING watchlist_markets_empty "
            f"watchlist_name={watchlist_name!r} watchlist_id={watchlist_id!r} "
            "source=IG /watchlists/{id} returned 0 markets"
        )
        recovered = _recover_watchlist_markets_across_accounts(ig, watchlist_name)
        if recovered:
            watchlist_id, watchlist_markets = recovered
            print(
                "RECOVERED watchlist_markets "
                f"source=cross_account watchlist_id={watchlist_id!r} markets={len(watchlist_markets)}"
            )
        else:
            nav_rows = _recover_watchlist_markets_navigation(ig, watchlist_name)
            if nav_rows:
                watchlist_markets = nav_rows
                print(
                    "RECOVERED watchlist_markets "
                    f"source=navigation markets={len(watchlist_markets)}"
                )

    symbol_epic_cache: dict[str, str] = {}
    resolved_by_static = 0
    resolved_by_search = 0
    unresolved = 0

    for symbol in symbols:
        key = _symbol_key(symbol)
        if not key:
            continue
        epic = _lookup_epic(symbol, symbol_to_epic_map)
        if epic:
            symbol_epic_cache[key] = epic
            resolved_by_static += 1
            continue

        display_name = symbol_display_map.get(symbol, symbol)
        epic, score, ig_name, source, _ = _resolve_symbol_epic(
            ig=ig,
            symbol=symbol,
            display_name=display_name,
            watchlist_markets=watchlist_markets,
            min_score=args.min_score,
            delay_seconds=max(0.0, args.delay_seconds),
        )
        if epic:
            symbol_epic_cache[key] = epic
            resolved_by_search += 1
            continue
        unresolved += 1
        print(
            "UNRESOLVED "
            f"symbol={symbol} "
            f"display_name={display_name!r} "
            f"best_ig_name={ig_name!r} "
            f"best_epic={epic or '<none>'} "
            f"source={source or '<none>'} "
            f"score={score:.3f}"
        )

    payload = {
        "identity": {
            "base_url": cfg.ig_base_url.rstrip("/").lower(),
            "watchlist_name": _norm(watchlist_name),
            "account_id": cfg.ig_account_id.strip(),
        },
        "watchlist_id": watchlist_id,
        "watchlist_epics": sorted(watchlist_epics),
        "symbol_epic_cache": dict(sorted(symbol_epic_cache.items())),
        "updated_at": int(time.time()),
    }

    out = Path(cache_file)
    if out.parent and str(out.parent) != ".":
        out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")

    print(f"Wrote cache: {cache_file}")
    print(
        "Summary: "
        f"symbols={len(symbols)} static={resolved_by_static} search={resolved_by_search} "
        f"unresolved={unresolved} watchlist_epics={len(watchlist_epics)}"
    )


if __name__ == "__main__":
    main()
