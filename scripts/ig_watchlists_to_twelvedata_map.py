#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import urllib.parse
from dataclasses import dataclass
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any

import requests
import yaml

IG_DEFAULT_WATCHLISTS = ["My watchlist", "24 Hours Shares"]


@dataclass(frozen=True)
class IGInstrument:
    watchlist: str
    ig_name: str
    epic: str


@dataclass(frozen=True)
class TwelveCandidate:
    symbol: str
    instrument_name: str
    exchange: str
    instrument_type: str
    country: str
    currency: str


def _ig_kind_from_epic(epic: str) -> str:
    e = epic.upper()
    if e.startswith("IX."):
        return "index"
    if e.startswith("CC."):
        return "commodity"
    if e.startswith("CS."):
        return "fx_or_spot"
    return "other"


def _load_yaml(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _resolve(secret_cfg: dict[str, Any], base_cfg: dict[str, Any], key: str, env_key: str) -> str:
    if key in secret_cfg and secret_cfg.get(key):
        return str(secret_cfg[key]).strip()
    env_name = secret_cfg.get(env_key) or base_cfg.get(env_key)
    if env_name and str(env_name).strip() in __import__("os").environ:
        return __import__("os").environ[str(env_name).strip()]
    if env_name:
        candidate = str(env_name).strip()
        # Backward compatibility: many local configs store direct values in *_env.
        # If token does not contain "_" (e.g. GY9V9), treat it as a literal value.
        if "_" not in candidate:
            return candidate
        if not re.fullmatch(r"[A-Z_][A-Z0-9_]*", candidate):
            return candidate
    return ""


class IGClient:
    def __init__(
        self,
        base_url: str,
        api_key: str,
        identifier: str,
        password: str,
        account_id: str = "",
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.identifier = identifier
        self.password = password
        self.session = requests.Session()
        self.cst = ""
        self.xst = ""
        self.oauth_access_token = ""
        self.oauth_account_id = account_id.strip()

    def login(self, versions: tuple[str, ...] = ("3", "2")) -> None:
        url = f"{self.base_url}/session"
        payload = {
            "identifier": self.identifier,
            "password": self.password,
            "encryptedPassword": False,
        }
        last_error = ""
        errors: list[str] = []
        for version in versions:
            headers = {
                "X-IG-API-KEY": self.api_key,
                "Content-Type": "application/json; charset=UTF-8",
                "Accept": "application/json; charset=UTF-8",
                "Version": version,
            }
            resp = self.session.post(url, headers=headers, json=payload, timeout=30)
            if resp.status_code < 400:
                payload_json = resp.json() if resp.content else {}
                if version == "3":
                    oauth = payload_json.get("oauthToken", {}) if isinstance(payload_json, dict) else {}
                    token = str(oauth.get("access_token", "")).strip()
                    account_id = str(
                        payload_json.get("currentAccountId", "")
                        or oauth.get("accountId", "")
                    ).strip()
                    if not account_id and isinstance(payload_json, dict):
                        accounts = payload_json.get("accounts") or []
                        if accounts and isinstance(accounts, list):
                            first = accounts[0]
                            if isinstance(first, dict):
                                account_id = str(first.get("accountId", "")).strip()
                    if token:
                        self.oauth_access_token = token
                        self.oauth_account_id = account_id
                        return

                self.cst = resp.headers.get("CST", "")
                self.xst = resp.headers.get("X-SECURITY-TOKEN", "")
                if self.cst and self.xst:
                    return
                raise RuntimeError(
                    f"IG login succeeded (v{version}) but missing usable auth tokens "
                    "(OAuth access_token or CST/X-SECURITY-TOKEN)"
                )
            last_error = (
                f"IG login failed status={resp.status_code} version={version} "
                f"base_url={self.base_url} detail={_http_error_detail(resp)}"
            )
            errors.append(last_error)
            # invalid-details may still succeed under another version, so continue trying.
        raise RuntimeError(" | ".join(errors) if errors else last_error)

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

    def _headers_for(self, version: str = "1", include_account_id: bool = True) -> dict[str, str]:
        headers = self._headers(version)
        if not include_account_id:
            headers.pop("IG-ACCOUNT-ID", None)
        return headers

    def get_watchlists(self) -> list[dict[str, Any]]:
        url = f"{self.base_url}/watchlists"
        resp = self.session.get(url, headers=self._headers("1"), timeout=30)
        if resp.status_code >= 400:
            raise RuntimeError(
                f"IG get_watchlists failed status={resp.status_code} detail={_http_error_detail(resp)} "
                f"oauth_account_id={self.oauth_account_id or '<empty>'}"
            )
        payload = resp.json()
        return payload.get("watchlists", [])

    def get_watchlist(self, watchlist_id: str) -> dict[str, Any]:
        encoded_id = urllib.parse.quote(str(watchlist_id), safe="")
        url = f"{self.base_url}/watchlists/{encoded_id}"
        resp = self.session.get(url, headers=self._headers("1"), timeout=30)
        if resp.status_code >= 400:
            raise RuntimeError(
                f"IG get_watchlist failed status={resp.status_code} watchlist_id={watchlist_id} "
                f"detail={_http_error_detail(resp)} oauth_account_id={self.oauth_account_id or '<empty>'}"
            )
        return resp.json()

    def fetch_root_navigation(self) -> dict[str, Any]:
        return self._fetch_navigation_payload(None)

    def fetch_navigation_node(self, node_id: str) -> dict[str, Any]:
        return self._fetch_navigation_payload(node_id)

    def _fetch_navigation_payload(self, node_id: str | None) -> dict[str, Any]:
        paths: list[str]
        if node_id is None:
            paths = ["/market-navigation", "/marketnavigation"]
        else:
            encoded = urllib.parse.quote(str(node_id), safe="")
            paths = [f"/market-navigation/{encoded}", f"/marketnavigation/{encoded}"]

        last_error = ""
        for path in paths:
            url = f"{self.base_url}{path}"
            resp = self.session.get(url, headers=self._headers_for("1", include_account_id=False), timeout=30)
            if resp.status_code < 400:
                return resp.json()
            last_error = f"status={resp.status_code} path={path} detail={_http_error_detail(resp)}"
        raise RuntimeError(f"IG navigation fetch failed: {last_error}")

    def fetch_session(self) -> dict[str, Any]:
        url = f"{self.base_url}/session"
        resp = self.session.get(url, headers=self._headers_for("1", include_account_id=False), timeout=30)
        if resp.status_code >= 400:
            return {}
        return resp.json()

    def switch_account(self, account_id: str) -> None:
        if not account_id:
            return
        if self.oauth_access_token:
            # OAuth calls use IG-ACCOUNT-ID directly; no session switch required.
            self.oauth_account_id = account_id
            return
        url = f"{self.base_url}/session"
        payload = {"accountId": account_id, "defaultAccount": False}
        resp = self.session.put(url, headers=self._headers("1"), json=payload, timeout=30)
        if resp.status_code >= 400:
            raise RuntimeError(
                f"IG switch_account failed status={resp.status_code} detail={_http_error_detail(resp)}"
            )
        self.oauth_account_id = account_id

    def discover_account_id(self) -> str:
        if self.oauth_account_id:
            return self.oauth_account_id
        if not self.oauth_access_token:
            return ""
        url = f"{self.base_url}/accounts"
        headers = self._headers_for("1", include_account_id=False)
        resp = self.session.get(url, headers=headers, timeout=30)
        if resp.status_code >= 400:
            return ""
        payload = resp.json()
        accounts = payload.get("accounts") or []
        if not isinstance(accounts, list) or not accounts:
            return ""
        preferred = [a for a in accounts if isinstance(a, dict) and a.get("preferred")]
        picked = preferred[0] if preferred else accounts[0]
        if isinstance(picked, dict):
            account_id = str(picked.get("accountId", "")).strip()
            if account_id:
                self.oauth_account_id = account_id
                return account_id
        return ""

    def fetch_accounts(self) -> list[dict[str, Any]]:
        url = f"{self.base_url}/accounts"
        resp = self.session.get(url, headers=self._headers_for("1", include_account_id=False), timeout=30)
        if resp.status_code >= 400:
            raise RuntimeError(
                f"IG fetch_accounts failed status={resp.status_code} detail={_http_error_detail(resp)}"
            )
        payload = resp.json()
        rows = payload.get("accounts")
        return rows if isinstance(rows, list) else []


class TwelveDataClient:
    def __init__(self, api_key: str) -> None:
        self.api_key = api_key
        self.session = requests.Session()

    def symbol_search(self, query: str, outputsize: int = 30) -> list[TwelveCandidate]:
        url = "https://api.twelvedata.com/symbol_search"
        params = {
            "symbol": query,
            "outputsize": outputsize,
            "apikey": self.api_key,
        }
        resp = self.session.get(url, params=params, timeout=30)
        resp.raise_for_status()
        payload = resp.json()
        if payload.get("status") == "error":
            return []
        data = payload.get("data") or []
        out: list[TwelveCandidate] = []
        for row in data:
            out.append(
                TwelveCandidate(
                    symbol=str(row.get("symbol", "")),
                    instrument_name=str(row.get("instrument_name", "")),
                    exchange=str(row.get("exchange", "")),
                    instrument_type=str(row.get("instrument_type", "")),
                    country=str(row.get("country", "")),
                    currency=str(row.get("currency", "")),
                )
            )
        return out

    def fetch_catalog(self, td_types: list[str]) -> list[TwelveCandidate]:
        endpoint_map = {
            "indices": "https://api.twelvedata.com/indices",
            "commodities": "https://api.twelvedata.com/commodities",
        }
        out: list[TwelveCandidate] = []
        seen: set[tuple[str, str]] = set()
        for td_type in td_types:
            key = td_type.strip().lower()
            if key not in endpoint_map:
                continue
            url = endpoint_map[key]
            resp = self.session.get(url, params={"apikey": self.api_key}, timeout=30)
            resp.raise_for_status()
            payload = resp.json()
            if payload.get("status") == "error":
                continue
            for row in payload.get("data") or []:
                symbol = str(row.get("symbol", "")).strip()
                name = str(row.get("name", "")).strip()
                exchange = str(row.get("exchange", "")).strip()
                country = str(row.get("country", "")).strip()
                currency = str(row.get("currency", "")).strip()
                if not symbol and not name:
                    continue
                dedupe_key = (symbol.upper(), key)
                if dedupe_key in seen:
                    continue
                seen.add(dedupe_key)
                out.append(
                    TwelveCandidate(
                        symbol=symbol,
                        instrument_name=name,
                        exchange=exchange,
                        instrument_type=key.upper(),
                        country=country,
                        currency=currency,
                    )
                )
        return out


def _catalog_cache_path(td_cfg: dict[str, Any], cli_path: str, td_types: list[str]) -> str:
    if cli_path.strip():
        return cli_path.strip()
    cfg_path = str(td_cfg.get("catalog_cache_file", "")).strip()
    if cfg_path:
        return cfg_path
    suffix = "_".join(td_types) if td_types else "catalog"
    return f"twelvedata_{suffix}.json"


def _load_catalog_cache(path: str, td_types: list[str]) -> list[TwelveCandidate] | None:
    p = Path(path)
    if not p.exists():
        return None
    try:
        payload = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None
    cached_types = payload.get("types", [])
    if sorted([str(x).lower() for x in cached_types]) != sorted(td_types):
        return None
    rows = payload.get("data", [])
    if not isinstance(rows, list):
        return None
    out: list[TwelveCandidate] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        out.append(
            TwelveCandidate(
                symbol=str(row.get("symbol", "")),
                instrument_name=str(row.get("instrument_name", "")),
                exchange=str(row.get("exchange", "")),
                instrument_type=str(row.get("instrument_type", "")),
                country=str(row.get("country", "")),
                currency=str(row.get("currency", "")),
            )
        )
    return out


def _save_catalog_cache(path: str, td_types: list[str], rows: list[TwelveCandidate]) -> None:
    p = Path(path)
    if p.parent and str(p.parent) != ".":
        p.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "types": td_types,
        "count": len(rows),
        "data": [
            {
                "symbol": r.symbol,
                "instrument_name": r.instrument_name,
                "exchange": r.exchange,
                "instrument_type": r.instrument_type,
                "country": r.country,
                "currency": r.currency,
            }
            for r in rows
        ],
    }
    p.write_text(json.dumps(payload, indent=2, ensure_ascii=True), encoding="utf-8")


def _clean_name(name: str) -> str:
    n = name.upper()
    n = re.sub(r"\(.*?\)", " ", n)
    n = n.replace("&", " AND ")
    n = re.sub(r"[^A-Z0-9 ]+", " ", n)
    n = re.sub(r"\s+", " ", n).strip()
    return n


def _query_tokens(inst: IGInstrument) -> list[str]:
    tokens: list[str] = []

    cleaned = _clean_name(inst.ig_name)
    if cleaned:
        tokens.append(cleaned)

    epic_parts = [p for p in re.split(r"[^A-Z0-9]+", inst.epic.upper()) if p]
    blacklist = {
        "D",
        "CASH",
        "IP",
        "CFD",
        "SPOT",
        "DAILY",
        "WEEKLY",
        "MONTHLY",
        "MINI",
        "MICRO",
    }

    for p in epic_parts:
        if p in blacklist:
            continue
        if re.fullmatch(r"[A-Z]{6}", p):
            tokens.append(f"{p[:3]}/{p[3:]}")
            tokens.append(p)
        elif re.fullmatch(r"[A-Z]{4,12}", p):
            tokens.append(p)

    # Use meaningful name chunks to avoid tiny ambiguous symbols (e.g. CC, NG).
    for part in cleaned.split():
        if len(part) >= 4:
            tokens.append(part)

    seen = set()
    deduped: list[str] = []
    for t in tokens:
        if t not in seen:
            seen.add(t)
            deduped.append(t)
    return deduped[:8]


def _score_candidate(inst: IGInstrument, cand: TwelveCandidate) -> float:
    n1 = _clean_name(inst.ig_name)
    n2 = _clean_name(cand.instrument_name)
    sym = cand.symbol.upper()

    score = 0.0
    name_ratio = 0.0
    if n1 and n2:
        name_ratio = SequenceMatcher(None, n1, n2).ratio()
        score += name_ratio * 0.72

    epic = inst.epic.upper()
    if sym and sym in epic:
        score += 0.25

    compact_pair = re.sub(r"[^A-Z]", "", n1)
    if re.fullmatch(r"[A-Z]{6}", compact_pair) and sym.replace("/", "") == compact_pair:
        score += 0.3

    # Penalize short ticker matches unless name is also close.
    if len(sym.replace("/", "")) <= 3 and name_ratio < 0.70:
        score -= 0.35

    # Enforce broad instrument-type compatibility from IG epic prefix.
    ig_kind = _ig_kind_from_epic(epic)
    td_type = cand.instrument_type.upper()
    if ig_kind == "index":
        if "INDEX" in td_type:
            score += 0.18
        else:
            score -= 0.30
    elif ig_kind == "commodity":
        if "COMMODITY" in td_type or "FUTURE" in td_type:
            score += 0.18
        else:
            score -= 0.30
    elif ig_kind == "fx_or_spot":
        if "CURRENCY" in td_type or "FOREX" in td_type or "/" in sym:
            score += 0.16

    if cand.country.upper() in {"UNITED STATES", "USA", "US"}:
        score += 0.04
    if cand.exchange.upper() in {"NASDAQ", "NYSE", "AMEX"}:
        score += 0.03

    return max(0.0, min(score, 1.0))


def map_instrument(inst: IGInstrument, td: TwelveDataClient) -> tuple[TwelveCandidate | None, float, str]:
    best: TwelveCandidate | None = None
    best_score = -1.0
    best_query = ""

    for query in _query_tokens(inst):
        candidates = td.symbol_search(query)
        for cand in candidates:
            s = _score_candidate(inst, cand)
            if s > best_score:
                best_score = s
                best = cand
                best_query = query

    if best is None:
        return None, 0.0, ""

    return best, best_score, best_query


def map_instrument_from_catalog(
    inst: IGInstrument, catalog: list[TwelveCandidate]
) -> tuple[TwelveCandidate | None, float, str]:
    tokens = _query_tokens(inst)
    token_compact = {re.sub(r"[^A-Z0-9]", "", t.upper()) for t in tokens}
    token_compact = {t for t in token_compact if t}

    best: TwelveCandidate | None = None
    best_score = -1.0
    best_query = ""
    for cand in catalog:
        cand_sym = re.sub(r"[^A-Z0-9]", "", cand.symbol.upper())
        cand_name = re.sub(r"[^A-Z0-9]", "", cand.instrument_name.upper())
        # Fast prefilter: require some overlap before expensive scoring.
        if token_compact:
            overlap = any(t in cand_sym or cand_sym in t or t in cand_name for t in token_compact)
            if not overlap:
                continue
        score = _score_candidate(inst, cand)
        if score > best_score:
            best_score = score
            best = cand
            best_query = next(iter(tokens), "")

    if best is None:
        return None, 0.0, ""
    return best, best_score, best_query


def _extract_ig_instruments(ig: IGClient, wanted_names: set[str]) -> list[IGInstrument]:
    all_watchlists = ig.get_watchlists()
    wanted_by_name = {_norm_watchlist_name(w): w for w in wanted_names}
    selected: list[tuple[str, str]] = []

    available_names: list[str] = []
    for w in all_watchlists:
        name = str(w.get("name", "")).strip()
        wid = str(w.get("id", "")).strip()
        if not wid or not name:
            continue
        available_names.append(name)
        name_norm = _norm_watchlist_name(name)
        if name_norm in wanted_by_name:
            selected.append((wid, name))

    if not selected:
        # Fallback to contains matching (handles variants like "24hr Shares").
        wanted_norms = list(wanted_by_name.keys())
        for w in all_watchlists:
            name = str(w.get("name", "")).strip()
            wid = str(w.get("id", "")).strip()
            if not wid or not name:
                continue
            name_norm = _norm_watchlist_name(name)
            for wn in wanted_norms:
                if wn in name_norm or name_norm in wn:
                    selected.append((wid, name))
                    break

    selected_names_norm = {_norm_watchlist_name(name) for _, name in selected}
    missing_norms = [wn for wn in wanted_by_name.keys() if wn not in selected_names_norm]

    nav_selected: list[tuple[str, str]] = []
    if missing_norms:
        nav_selected = _find_navigation_nodes_by_name(ig, set(missing_norms))

    if not selected and not nav_selected:
        raise RuntimeError(f"Could not find requested watchlists. Available: {available_names}")


    out: list[IGInstrument] = []
    seen = set()

    for wid, wname in selected:
        details = ig.get_watchlist(wid)
        markets = details.get("markets", [])
        market_count = len(markets) if isinstance(markets, list) else 0
        if market_count == 0 and "24hourshare" in _norm_watchlist_name(wname):
            recovered = _recover_watchlist_markets_across_accounts(ig, wname)
            if recovered is not None:
                wid, markets = recovered
                market_count = len(markets)
            if market_count == 0:
                try:
                    nav_nodes = _find_navigation_nodes_by_name(ig, {_norm_watchlist_name(wname)})
                    if nav_nodes:
                        node_id, node_name = nav_nodes[0]
                        payload = ig.fetch_navigation_node(node_id)
                        nav_markets = payload.get("markets", [])
                        if isinstance(nav_markets, list) and nav_markets:
                            markets = nav_markets
                            market_count = len(markets)
                except RuntimeError as exc:
                    _ = exc
        for m in markets:
            ig_name = str(
                m.get("instrumentName")
                or m.get("epicDescription")
                or m.get("name")
                or m.get("marketName")
                or ""
            ).strip()
            epic = str(m.get("epic") or "").strip()
            if not ig_name and not epic:
                continue
            key = (wname, ig_name, epic)
            if key in seen:
                continue
            seen.add(key)
            out.append(IGInstrument(watchlist=wname, ig_name=ig_name or epic, epic=epic))

    for node_id, node_name in nav_selected:
        payload = ig.fetch_navigation_node(node_id)
        markets = payload.get("markets", [])
        for m in markets:
            instrument = m.get("instrument", {}) if isinstance(m.get("instrument"), dict) else {}
            ig_name = str(
                m.get("instrumentName")
                or m.get("name")
                or instrument.get("name")
                or ""
            ).strip()
            epic = str(m.get("epic") or instrument.get("epic") or "").strip()
            if not ig_name and not epic:
                continue
            key = (node_name, ig_name, epic)
            if key in seen:
                continue
            seen.add(key)
            out.append(IGInstrument(watchlist=node_name, ig_name=ig_name or epic, epic=epic))

    return out


def _recover_watchlist_markets_across_accounts(
    ig: IGClient, watchlist_name: str
) -> tuple[str, list[dict[str, Any]]] | None:
    try:
        accounts = ig.fetch_accounts()
    except Exception as exc:
        _ = exc
        return None

    target = _norm_watchlist_name(watchlist_name)
    for account in accounts:
        account_id = str(account.get("accountId") or "").strip()
        if not account_id:
            continue
        try:
            ig.switch_account(account_id)
            watchlists = ig.get_watchlists()
        except Exception:
            continue

        selected_id = ""
        for w in watchlists:
            name = str(w.get("name") or w.get("watchlistName") or "").strip()
            wid = str(w.get("id") or w.get("watchlistId") or "").strip()
            if not name or not wid:
                continue
            norm = _norm_watchlist_name(name)
            if norm == target or target in norm or norm in target:
                selected_id = wid
                break
        if not selected_id:
            continue
        try:
            details = ig.get_watchlist(selected_id)
            markets = details.get("markets", [])
        except Exception:
            continue
        if isinstance(markets, list) and markets:
            return selected_id, markets
    return None


def _find_navigation_nodes_by_name(ig: IGClient, wanted_norms: set[str]) -> list[tuple[str, str]]:
    root = ig.fetch_root_navigation()
    queue: list[tuple[str, str]] = []
    for node in root.get("nodes", []):
        nid = str(node.get("id") or "").strip()
        nname = str(node.get("name") or "").strip()
        if nid:
            queue.append((nid, nname))

    found: list[tuple[str, str]] = []
    seen_nodes: set[str] = set()

    while queue and wanted_norms:
        node_id, node_name = queue.pop(0)
        if node_id in seen_nodes:
            continue
        seen_nodes.add(node_id)

        norm = _norm_watchlist_name(node_name)
        matches = [w for w in wanted_norms if w == norm or w in norm or norm in w]
        if matches:
            found.append((node_id, node_name))
            for m in matches:
                wanted_norms.discard(m)

        try:
            payload = ig.fetch_navigation_node(node_id)
        except RuntimeError:
            continue
        for child in payload.get("nodes", []):
            cid = str(child.get("id") or "").strip()
            cname = str(child.get("name") or "").strip()
            if cid and cid not in seen_nodes:
                queue.append((cid, cname))

    return found


def _norm_watchlist_name(name: str) -> str:
    n = name.lower().strip()
    n = n.replace("hours", "hour")
    n = n.replace("hrs", "hour")
    n = n.replace("hr", "hour")
    n = re.sub(r"[^a-z0-9]+", "", n)
    return n


def write_outputs(
    mapped: list[dict[str, Any]],
    mapping_json_path: str,
) -> None:
    mapping: dict[str, str] = {}
    collisions: list[tuple[str, str, str]] = []

    for row in mapped:
        td_symbol = row.get("td_symbol", "")
        ig_name = row.get("ig_name", "")
        if not td_symbol:
            continue
        if td_symbol in mapping and mapping[td_symbol] != ig_name:
            collisions.append((td_symbol, mapping[td_symbol], ig_name))
            continue
        mapping[td_symbol] = ig_name

    with open(mapping_json_path, "w", encoding="utf-8") as f:
        json.dump(mapping, f, indent=2, ensure_ascii=True, sort_keys=True)

    print(f"Wrote mapping JSON: {mapping_json_path} ({len(mapping)} keys)")
    print(f"Processed rows: {len(mapped)}")
    if collisions:
        print(f"Symbol collisions skipped: {len(collisions)}")
        for sym, old, new in collisions[:20]:
            print(f"  {sym}: '{old}' vs '{new}'")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="One-off IG watchlist -> TwelveData mapping")
    p.add_argument("--config", default="config.yaml", help="Config with API key env names or direct keys")
    p.add_argument("--ig-base-url", default="", help="IG API base URL")
    p.add_argument("--ig-account-id", default="", help="Optional IG account id for OAuth calls")
    p.add_argument(
        "--ig-account-type",
        default="",
        help="Optional account type preference (e.g. SPREADBET, CFD).",
    )
    p.add_argument(
        "--ig-login-version",
        choices=["auto", "3", "2"],
        default="auto",
        help="IG /session version strategy. Use '3' for migrated client-account model.",
    )
    p.add_argument(
        "--watchlists",
        default=",".join(IG_DEFAULT_WATCHLISTS),
        help="Comma-separated IG watchlist names to fetch",
    )
    p.add_argument("--min-score", type=float, default=0.72, help="Score threshold to treat mapping as matched")
    p.add_argument("--mapping-out", default="ig_to_twelvedata_mapping.json")
    p.add_argument(
        "--td-types",
        default="",
        help="Comma-separated TwelveData catalog types to load (currently supports: indices,commodities).",
    )
    p.add_argument("--catalog-cache", default="", help="JSON cache path for TwelveData catalog")
    p.add_argument("--refresh-catalog", action="store_true", help="Force refresh TwelveData catalog cache")
    p.add_argument("--print-ig-list", action="store_true", help="Print fetched IG instruments to stdout")
    p.add_argument("--ig-list-out", default="ig_fetched_instruments.txt", help="Write fetched IG instruments list")
    return p


def main() -> None:
    args = build_parser().parse_args()
    cfg = _load_yaml(args.config)
    ig_cfg = cfg.get("ig", {}) if isinstance(cfg.get("ig"), dict) else {}
    td_cfg = cfg.get("twelvedata", {}) if isinstance(cfg.get("twelvedata"), dict) else {}
    ig_base_url = (
        args.ig_base_url
        or str(ig_cfg.get("base_url", "")).strip()
        or "https://demo-api.ig.com/gateway/deal"
    )

    ig_api_key = _resolve(ig_cfg, {}, "api_key", "api_key_env")
    ig_identifier = _resolve(ig_cfg, {}, "identifier", "identifier_env")
    ig_password = _resolve(ig_cfg, {}, "password", "password_env")
    ig_account_id = args.ig_account_id or _resolve(ig_cfg, {}, "account_id", "account_id_env")
    ig_account_type = args.ig_account_type or _resolve(ig_cfg, {}, "account_type", "account_type_env")
    td_api_key = _resolve(td_cfg, {}, "api_key", "api_key_env")

    missing = []
    if not ig_api_key:
        missing.append("ig.api_key or ig.api_key_env")
    if not ig_identifier:
        missing.append("ig.identifier or ig.identifier_env")
    if not ig_password:
        missing.append("ig.password or ig.password_env")
    if not td_api_key:
        missing.append("twelvedata.api_key or twelvedata.api_key_env")
    if missing:
        raise SystemExit("Missing required credentials: " + ", ".join(missing))
    print(f"Using IG base URL: {ig_base_url}")

    wanted_watchlists = {x.strip() for x in args.watchlists.split(",") if x.strip()}
    if args.td_types.strip():
        td_types = [x.strip().lower() for x in args.td_types.split(",") if x.strip()]
    else:
        cfg_types = td_cfg.get("map_types", [])
        if isinstance(cfg_types, list):
            td_types = [str(x).strip().lower() for x in cfg_types if str(x).strip()]
        elif isinstance(cfg_types, str) and cfg_types.strip():
            td_types = [x.strip().lower() for x in cfg_types.split(",") if x.strip()]
        else:
            td_types = ["indices", "commodities"]

    ig = IGClient(
        base_url=ig_base_url,
        api_key=ig_api_key,
        identifier=ig_identifier,
        password=ig_password,
        account_id=ig_account_id,
    )
    td = TwelveDataClient(td_api_key)

    login_versions = ("3", "2") if args.ig_login_version == "auto" else (args.ig_login_version,)
    try:
        ig.login(login_versions)
        if ig_account_type:
            accounts = ig.fetch_accounts()
            wanted = ig_account_type.strip().upper()
            matching = [a for a in accounts if str(a.get("accountType", "")).upper() == wanted]
            if matching:
                preferred = next((a for a in matching if a.get("preferred")), matching[0])
                picked_id = str(preferred.get("accountId", "")).strip()
                if picked_id:
                    ig.switch_account(picked_id)
        if ig_account_id:
            ig.switch_account(ig_account_id)
        discovered = ig.discover_account_id()
        _ = discovered
        session_data = ig.fetch_session()
        _ = session_data
    except RuntimeError as exc:
        msg = str(exc)
        if "error.security.invalid-details" in msg:
            msg += (
                "\nHint: IG identifier must be your IG login username/email, not account number "
                "(e.g. ABC123)."
            )
        if "error.security.account-migrated" in msg:
            msg += "\nHint: account-migrated typically requires v3 login. Re-run with --ig-login-version 3."
        raise SystemExit(
            f"{msg}\nHint: try --ig-base-url https://api.ig.com/gateway/deal for live accounts, "
            "or --ig-base-url https://demo-api.ig.com/gateway/deal for demo accounts."
        )
    try:
        instruments = _extract_ig_instruments(ig, wanted_watchlists)
    except RuntimeError as exc:
        raise SystemExit(
            f"{exc}\nHint: Verify IG account context (ig.account_id / --ig-account-id) and optionally "
            "set ig.account_type (SPREADBET or CFD)."
        )
    print(f"Fetched IG instruments: {len(instruments)} from watchlists={sorted(wanted_watchlists)}")
    _write_ig_instrument_list(instruments, args.ig_list_out, args.print_ig_list)
    cache_path = _catalog_cache_path(td_cfg, args.catalog_cache, td_types)
    catalog: list[TwelveCandidate] | None = None
    if not args.refresh_catalog:
        catalog = _load_catalog_cache(cache_path, td_types)
        if catalog is not None:
            print(f"Loaded TwelveData catalog rows from cache: {len(catalog)} path={cache_path}")
    if catalog is None:
        catalog = td.fetch_catalog(td_types)
        _save_catalog_cache(cache_path, td_types, catalog)
        print(f"Fetched TwelveData catalog rows: {len(catalog)} types={td_types}")
        print(f"Saved TwelveData catalog cache: {cache_path}")

    mapped_rows: list[dict[str, Any]] = []
    matched = 0

    for inst in instruments:
        cand, score, query = map_instrument_from_catalog(inst, catalog)
        status = "unmapped"
        td_symbol = ""
        td_name = ""
        td_exchange = ""
        td_type = ""
        td_country = ""

        if cand and score >= args.min_score:
            matched += 1
            status = "matched"
            td_symbol = cand.symbol
            td_name = cand.instrument_name
            td_exchange = cand.exchange
            td_type = cand.instrument_type
            td_country = cand.country

        mapped_rows.append(
            {
                "watchlist": inst.watchlist,
                "ig_name": inst.ig_name,
                "ig_epic": inst.epic,
                "td_symbol": td_symbol,
                "td_name": td_name,
                "td_exchange": td_exchange,
                "td_type": td_type,
                "td_country": td_country,
                "score": f"{score:.3f}",
                "matched_by_query": query,
                "status": status,
            }
        )

    write_outputs(mapped_rows, args.mapping_out)
    print(f"Matched {matched}/{len(instruments)} with min_score={args.min_score:.2f}")


def _http_error_detail(resp: requests.Response) -> str:
    try:
        payload = resp.json()
        if isinstance(payload, dict):
            error_code = payload.get("errorCode")
            if error_code:
                return str(error_code)
            message = payload.get("message")
            if message:
                return str(message)
            return json.dumps(payload, ensure_ascii=True)
    except ValueError:
        pass
    text = (resp.text or "").strip()
    return text if text else "unknown_error"


def _write_ig_instrument_list(
    instruments: list[IGInstrument], out_path: str, print_to_stdout: bool
) -> None:
    lines: list[str] = []
    for i, inst in enumerate(instruments, 1):
        lines.append(f"{i:03d}. {inst.watchlist} | {inst.ig_name} | {inst.epic}")
    p = Path(out_path)
    if p.parent and str(p.parent) != ".":
        p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    print(f"Wrote IG fetched instruments list: {out_path} ({len(instruments)} rows)")
    if print_to_stdout:
        for line in lines:
            print(line)


if __name__ == "__main__":
    main()
