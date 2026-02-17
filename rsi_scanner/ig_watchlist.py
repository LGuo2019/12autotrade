from __future__ import annotations

import logging
from dataclasses import dataclass
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
    dry_run: bool = False

    def __post_init__(self) -> None:
        self._session = requests.Session()
        self._oauth_token = ""
        self._cst = ""
        self._xst = ""
        self._watchlist_id = ""
        self._watchlist_epics: set[str] = set()
        self._initialized = False

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
            logger.info("ig_watchlist epic=%s action=added watchlist=%s", epic, self.watchlist_name)
        except Exception as exc:
            logger.error("ig_watchlist epic=%s action=add_failed error=%s", epic, str(exc))

    def _ensure_initialized(self) -> None:
        if self._initialized:
            return
        self._login()
        watchlists = self._get_watchlists()
        self._watchlist_id = self._find_watchlist_id(watchlists, self.watchlist_name)
        if not self._watchlist_id:
            raise IGWatchlistError(f"watchlist_not_found name={self.watchlist_name}")
        details = self._get_watchlist(self._watchlist_id)
        self._watchlist_epics = {
            str(m.get("epic") or "").strip()
            for m in (details.get("markets") or [])
            if str(m.get("epic") or "").strip()
        }
        self._initialized = True
        logger.info(
            "ig_watchlist init_ok watchlist=%s watchlist_id=%s markets=%d account_id=%s",
            self.watchlist_name,
            self._watchlist_id,
            len(self._watchlist_epics),
            self.account_id or "",
        )
        if len(self._watchlist_epics) == 0:
            logger.warning(
                "ig_watchlist watchlist_empty watchlist=%s watchlist_id=%s account_id=%s "
                "hint=check_ig_account_id_or_duplicate_watchlist_name",
                self.watchlist_name,
                self._watchlist_id,
                self.account_id or "",
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
