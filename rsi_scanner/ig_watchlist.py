from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import requests

logger = logging.getLogger("rsi_scanner.ig_watchlist")


class IGWatchlistError(Exception):
    pass


@dataclass
class IGWatchlistSync:
    api_key: str
    identifier: str
    password: str
    base_url: str
    watchlist_name: str
    account_id: str = ""
    cache_file: str = "data/ig_watchlist_cache.json"
    dry_run: bool = False

    def __post_init__(self) -> None:
        self._session = requests.Session()
        self._oauth_token = ""
        self._cst = ""
        self._xst = ""
        self._watchlist_id = ""
        self._watchlist_epics: set[str] = set()
        self._symbol_epic_cache: dict[str, str] = {}
        self._initialized = False
        self._cache_loaded = False
        self._load_cache()

    def add_epic_if_missing(self, epic: str) -> None:
        if not epic:
            return
        try:
            self._ensure_initialized()
        except Exception as exc:
            logger.error("ig_watchlist init_failed error=%s", str(exc))
            return

        if epic in self._watchlist_epics:
            logger.info("ig_watchlist epic=%s action=exists watchlist=%s", epic, self.watchlist_name)
            return

        if self.dry_run:
            logger.info("ig_watchlist epic=%s action=dry_run_add watchlist=%s", epic, self.watchlist_name)
            return

        try:
            self._add_market_to_watchlist(self._watchlist_id, epic)
            self._watchlist_epics.add(epic)
            self._save_cache()
            logger.info("ig_watchlist epic=%s action=added watchlist=%s", epic, self.watchlist_name)
        except Exception as exc:
            logger.error("ig_watchlist epic=%s action=add_failed error=%s", epic, str(exc))

    def add_symbol_if_missing(self, symbol: str, display_name: str = "") -> None:
        symbol_key = _symbol_key(symbol)
        if not symbol_key:
            return

        try:
            self._ensure_initialized()
        except Exception as exc:
            logger.error(
                "ig_watchlist symbol=%s action=resolve_failed error=%s",
                symbol_key,
                str(exc),
            )
            return

        epic = self._symbol_epic_cache.get(symbol_key, "")

        if not epic:
            logger.warning(
                "ig_watchlist symbol=%s action=cache_miss display_name=%s hint=refresh_ig_watchlist_cache",
                symbol_key,
                display_name,
            )
            return

        self._symbol_epic_cache[symbol_key] = epic
        self._save_cache()
        self.add_epic_if_missing(epic)

    def _ensure_initialized(self) -> None:
        if self._initialized:
            return
        self._login()
        if self._cache_loaded and self._watchlist_id:
            self._initialized = True
            logger.info(
                "ig_watchlist init_cached watchlist=%s watchlist_id=%s markets=%d account_id=%s",
                self.watchlist_name,
                self._watchlist_id,
                len(self._watchlist_epics),
                self.account_id or "",
            )
            return
        raise IGWatchlistError(
            "cache_missing_or_invalid "
            f"watchlist={self.watchlist_name} cache_file={self.cache_file} "
            "hint=run_scripts/populate_ig_watchlist_cache.py"
        )

    def _login(self) -> None:
        if self.dry_run:
            return
        # Try v3 (OAuth) first, then v2 session tokens fallback.
        errors: list[str] = []
        for version in ("3", "2"):
            headers = {
                "X-IG-API-KEY": self.api_key,
                "Content-Type": "application/json; charset=UTF-8",
                "Accept": "application/json; charset=UTF-8",
                "Version": version,
            }
            payload = {"identifier": self.identifier, "password": self.password}
            try:
                resp = self._session.post(f"{self.base_url}/session", json=payload, headers=headers, timeout=20)
            except requests.RequestException as exc:
                errors.append(f"v{version}: {exc}")
                continue
            if resp.status_code >= 400:
                errors.append(f"v{version}: {resp.status_code} {_http_error_detail(resp)}")
                continue
            body = resp.json()
            oauth = body.get("oauthToken") or {}
            self._oauth_token = str(oauth.get("access_token") or "")
            if not self._oauth_token:
                self._cst = resp.headers.get("CST", "")
                self._xst = resp.headers.get("X-SECURITY-TOKEN", "")
            if not (self._oauth_token or (self._cst and self._xst)):
                errors.append(f"v{version}: missing auth tokens")
                continue
            return
        raise IGWatchlistError("ig_login_failed: " + " | ".join(errors))

    def _auth_headers(self, version: str = "1") -> dict[str, str]:
        headers = {
            "X-IG-API-KEY": self.api_key,
            "Accept": "application/json; charset=UTF-8",
            "Content-Type": "application/json; charset=UTF-8",
            "Version": version,
        }
        if self._oauth_token:
            headers["Authorization"] = f"Bearer {self._oauth_token}"
            if self.account_id:
                headers["IG-ACCOUNT-ID"] = self.account_id
        elif self._cst and self._xst:
            headers["CST"] = self._cst
            headers["X-SECURITY-TOKEN"] = self._xst
            if self.account_id:
                headers["IG-ACCOUNT-ID"] = self.account_id
        return headers

    def _get_watchlists(self) -> list[dict[str, Any]]:
        resp = self._session.get(f"{self.base_url}/watchlists", headers=self._auth_headers("1"), timeout=20)
        if resp.status_code == 401 and self._is_auth_error(resp):
            self._relogin()
            resp = self._session.get(f"{self.base_url}/watchlists", headers=self._auth_headers("1"), timeout=20)
        if resp.status_code >= 400:
            raise IGWatchlistError(f"get_watchlists_failed {resp.status_code} {_http_error_detail(resp)}")
        payload = resp.json()
        return payload.get("watchlists", []) or []

    def _get_watchlist(self, watchlist_id: str) -> dict[str, Any]:
        resp = self._session.get(
            f"{self.base_url}/watchlists/{requests.utils.quote(str(watchlist_id), safe='')}",
            headers=self._auth_headers("1"),
            timeout=20,
        )
        if resp.status_code == 401 and self._is_auth_error(resp):
            self._relogin()
            resp = self._session.get(
                f"{self.base_url}/watchlists/{requests.utils.quote(str(watchlist_id), safe='')}",
                headers=self._auth_headers("1"),
                timeout=20,
            )
        if resp.status_code >= 400:
            raise IGWatchlistError(f"get_watchlist_failed {resp.status_code} {_http_error_detail(resp)}")
        return resp.json()

    def _add_market_to_watchlist(self, watchlist_id: str, epic: str) -> None:
        url = f"{self.base_url}/watchlists/{requests.utils.quote(str(watchlist_id), safe='')}"
        payload = {"epic": epic}
        # IG docs usually use PUT for add-to-watchlist; keep POST fallback.
        resp = self._session.put(url, json=payload, headers=self._auth_headers("1"), timeout=20)
        if resp.status_code == 401 and self._is_auth_error(resp):
            self._relogin()
            resp = self._session.put(url, json=payload, headers=self._auth_headers("1"), timeout=20)
        if resp.status_code < 400:
            return
        resp_post = self._session.post(url, json=payload, headers=self._auth_headers("1"), timeout=20)
        if resp_post.status_code == 401 and self._is_auth_error(resp_post):
            self._relogin()
            resp_post = self._session.post(url, json=payload, headers=self._auth_headers("1"), timeout=20)
        if resp_post.status_code < 400:
            return
        raise IGWatchlistError(
            f"add_market_failed put={resp.status_code}:{_http_error_detail(resp)} "
            f"post={resp_post.status_code}:{_http_error_detail(resp_post)}"
        )

    def _relogin(self) -> None:
        self._oauth_token = ""
        self._cst = ""
        self._xst = ""
        self._login()

    def _cache_identity(self) -> dict[str, str]:
        return {
            "base_url": self.base_url.rstrip("/").lower(),
            "watchlist_name": _norm(self.watchlist_name),
            "account_id": self.account_id.strip(),
        }

    def _load_cache(self) -> None:
        cache_path = str(self.cache_file or "").strip()
        if not cache_path:
            return
        p = Path(cache_path)
        if not p.exists():
            return
        try:
            payload = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            return
        if not isinstance(payload, dict):
            return
        identity = payload.get("identity")
        if not isinstance(identity, dict):
            return
        if identity != self._cache_identity():
            return

        watchlist_id = str(payload.get("watchlist_id") or "").strip()
        if not watchlist_id:
            return
        raw_epics = payload.get("watchlist_epics") or []
        if not isinstance(raw_epics, list):
            raw_epics = []
        raw_symbol_cache = payload.get("symbol_epic_cache") or {}
        if not isinstance(raw_symbol_cache, dict):
            raw_symbol_cache = {}

        self._watchlist_id = watchlist_id
        self._watchlist_epics = {str(x).strip() for x in raw_epics if str(x).strip()}
        self._symbol_epic_cache = {
            _symbol_key(k): str(v).strip()
            for k, v in raw_symbol_cache.items()
            if _symbol_key(k) and str(v).strip()
        }
        self._cache_loaded = True
        logger.info(
            "ig_watchlist cache_loaded watchlist=%s watchlist_id=%s markets=%d symbols=%d",
            self.watchlist_name,
            self._watchlist_id,
            len(self._watchlist_epics),
            len(self._symbol_epic_cache),
        )

    def _save_cache(self) -> None:
        cache_path = str(self.cache_file or "").strip()
        if not cache_path or not self._watchlist_id:
            return
        p = Path(cache_path)
        if p.parent and str(p.parent) != ".":
            p.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "identity": self._cache_identity(),
            "watchlist_id": self._watchlist_id,
            "watchlist_epics": sorted(self._watchlist_epics),
            "symbol_epic_cache": dict(sorted(self._symbol_epic_cache.items())),
            "updated_at": int(time.time()),
        }
        p.write_text(json.dumps(payload, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")

    @staticmethod
    def _is_auth_error(resp: requests.Response) -> bool:
        detail = _http_error_detail(resp).lower()
        return "oauth-token-invalid" in detail or "unauthorized" in detail or "invalid" in detail

    @staticmethod
    def _find_watchlist_id(watchlists: list[dict[str, Any]], name: str) -> str:
        want = _norm(name)
        for w in watchlists:
            wname = str(w.get("name") or w.get("watchlistName") or "").strip()
            wid = str(w.get("id") or w.get("watchlistId") or "").strip()
            if _norm(wname) == want and wid:
                return wid
        return ""


def _norm(s: str) -> str:
    return "".join(ch.lower() for ch in s if ch.isalnum())


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
