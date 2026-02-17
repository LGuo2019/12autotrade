#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import time
from dataclasses import dataclass
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any
from urllib.parse import quote

import requests
import yaml


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
        if "_" not in candidate:
            return candidate
        if not re.fullmatch(r"[A-Z_][A-Z0-9_]*", candidate):
            return candidate
    return ""


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


@dataclass
class Candidate:
    epic: str
    name: str
    score: float
    raw: dict[str, Any]


class IGClient:
    def __init__(self, base_url: str, api_key: str, identifier: str, password: str, account_id: str = "") -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.identifier = identifier
        self.password = password
        self.account_id = account_id
        self.session = requests.Session()
        self.oauth_access_token = ""
        self.oauth_account_id = account_id
        self.cst = ""
        self.xst = ""

    def login(self) -> None:
        errors: list[str] = []
        for version in ("3", "2"):
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
            body = resp.json() if resp.content else {}
            if version == "3":
                oauth = body.get("oauthToken", {}) if isinstance(body, dict) else {}
                token = str(oauth.get("access_token", "")).strip()
                account_id = str(body.get("currentAccountId", "")).strip()
                if token:
                    self.oauth_access_token = token
                    if account_id:
                        self.oauth_account_id = account_id
                    return
            self.cst = resp.headers.get("CST", "")
            self.xst = resp.headers.get("X-SECURITY-TOKEN", "")
            if self.cst and self.xst:
                return
            errors.append(f"v{version}:missing_tokens")
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

    def search_markets(self, term: str) -> list[dict[str, Any]]:
        url = f"{self.base_url}/markets?searchTerm={quote(term)}"
        resp = self.session.get(url, headers=self._headers("1"), timeout=30)
        if resp.status_code >= 400:
            raise RuntimeError(f"IG search failed term={term} status={resp.status_code} detail={_http_error_detail(resp)}")
        payload = resp.json()
        out: list[dict[str, Any]] = []
        for key in ("markets", "marketDetails", "instruments"):
            rows = payload.get(key)
            if isinstance(rows, list):
                out.extend([r for r in rows if isinstance(r, dict)])
        return out


def _extract_epic_name(row: dict[str, Any]) -> tuple[str, str]:
    epic = str(row.get("epic") or row.get("instrument", {}).get("epic") or "").strip()
    name = str(
        row.get("instrumentName")
        or row.get("marketName")
        or row.get("instrument", {}).get("name")
        or row.get("instrument", {}).get("marketName")
        or ""
    ).strip()
    return epic, name


def _score_candidate(symbol: str, ig_name: str, epic: str, candidate_name: str) -> float:
    sym = symbol.upper().strip()
    e = epic.upper().strip()
    name_ratio = SequenceMatcher(None, ig_name.lower(), candidate_name.lower()).ratio()
    score = 0.0
    if f".{sym}." in e:
        score += 0.55
    elif sym in e:
        score += 0.30
    if e.endswith(".DAILY.IP"):
        score += 0.25
    if e.startswith(("UA.", "UB.", "UC.", "UD.", "SA.", "SB.", "SC.", "SD.", "SE.", "SG.", "SH.")):
        score += 0.10
    score += 0.10 * name_ratio
    return score


def _choose_best(symbol: str, ig_name: str, rows: list[dict[str, Any]]) -> Candidate | None:
    cands: list[Candidate] = []
    for row in rows:
        epic, cname = _extract_epic_name(row)
        if not epic:
            continue
        score = _score_candidate(symbol, ig_name, epic, cname)
        cands.append(Candidate(epic=epic, name=cname, score=score, raw=row))
    if not cands:
        return None
    cands.sort(key=lambda x: x.score, reverse=True)
    return cands[0]


def main() -> None:
    ap = argparse.ArgumentParser(description="Find IG EPICs for TwelveData symbols via IG market search API")
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--mapping", default="12_IG_mapping_universe.json", help="symbol -> ig_name")
    ap.add_argument("--epic-map", default="rsi_universe_epic_to_twelvedata_symbol.json")
    ap.add_argument("--min-score", type=float, default=0.72)
    ap.add_argument("--out", default="data/ig_epic_candidates.json")
    ap.add_argument("--apply", action="store_true", help="Apply high-confidence matches into epic-map file")
    ap.add_argument("--delay-seconds", type=float, default=0.35, help="Delay between IG search calls")
    args = ap.parse_args()

    cfg = _load_yaml(args.config)
    ig_cfg = cfg.get("ig", {}) if isinstance(cfg, dict) else {}

    api_key = _resolve(ig_cfg, ig_cfg, "api_key", "api_key_env")
    identifier = _resolve(ig_cfg, ig_cfg, "identifier", "identifier_env")
    password = _resolve(ig_cfg, ig_cfg, "password", "password_env")
    base_url = str(ig_cfg.get("base_url") or "https://api.ig.com/gateway/deal").strip()
    account_id = str(ig_cfg.get("account_id") or "").strip()
    if not api_key or not identifier or not password:
        raise SystemExit("Missing IG credentials in config.yaml ig.* (or env names/values)")

    mapping: dict[str, str] = json.loads(Path(args.mapping).read_text())
    epic_payload = json.loads(Path(args.epic_map).read_text())
    epic_to_symbol: dict[str, str] = epic_payload.get("epic_to_twelvedata_symbol", {})
    symbol_to_epic: dict[str, str] = {}
    for epic, sym in epic_to_symbol.items():
        symbol_to_epic.setdefault(sym, epic)

    targets = [(sym, name) for sym, name in mapping.items() if sym not in symbol_to_epic]
    print(f"Targets missing epics: {len(targets)}")
    if not targets:
        return

    ig = IGClient(base_url=base_url, api_key=api_key, identifier=identifier, password=password, account_id=account_id)
    ig.login()

    results: dict[str, Any] = {}
    applied = 0
    for sym, name in targets:
        rows: list[dict[str, Any]] = []
        search_terms = [sym]
        # Only fallback to full name when ticker search found nothing.
        for term in search_terms:
            try:
                rows.extend(ig.search_markets(term))
                time.sleep(max(0.0, args.delay_seconds))
            except Exception as exc:
                print(f"{sym}: search_error term={term} error={exc}")
        if not rows:
            try:
                rows.extend(ig.search_markets(name))
                time.sleep(max(0.0, args.delay_seconds))
            except Exception as exc:
                print(f"{sym}: search_error term={name} error={exc}")
        best = _choose_best(sym, name, rows)
        if best is None:
            results[sym] = {"ig_name": name, "status": "unmatched", "candidate_count": len(rows)}
            print(f"{sym}: unmatched")
            continue
        status = "matched" if best.score >= args.min_score else "low_confidence"
        results[sym] = {
            "ig_name": name,
            "status": status,
            "best_epic": best.epic,
            "best_name": best.name,
            "score": round(best.score, 4),
            "candidate_count": len(rows),
        }
        print(f"{sym}: {status} epic={best.epic} score={best.score:.3f}")
        if args.apply and status == "matched":
            epic_to_symbol[best.epic] = sym
            if "details" in epic_payload and isinstance(epic_payload["details"], dict):
                epic_payload["details"][best.epic] = {"ig_name": name, "symbol": sym, "via": "ig_markets_search"}
            applied += 1

    out = {
        "targets": len(targets),
        "matched": sum(1 for r in results.values() if r["status"] == "matched"),
        "low_confidence": sum(1 for r in results.values() if r["status"] == "low_confidence"),
        "unmatched": sum(1 for r in results.values() if r["status"] == "unmatched"),
        "results": results,
    }
    Path(args.out).write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Wrote {args.out}")

    if args.apply and applied:
        epic_payload["epic_to_twelvedata_symbol"] = dict(sorted(epic_to_symbol.items()))
        epic_payload["mapped_count"] = len(epic_payload["epic_to_twelvedata_symbol"])
        epic_payload["total_input"] = epic_payload.get("total_input", len(epic_payload["epic_to_twelvedata_symbol"]))
        epic_payload["unmapped"] = epic_payload.get("unmapped", {})
        epic_payload["unmapped_count"] = len(epic_payload["unmapped"])
        Path(args.epic_map).write_text(json.dumps(epic_payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"Applied {applied} matches into {args.epic_map}")


if __name__ == "__main__":
    main()
