from __future__ import annotations

import json

from rsi_scanner.ig_watchlist import IGWatchlistSync


def test_ig_watchlist_cache_roundtrip(tmp_path):
    cache_file = tmp_path / "ig_watchlist_cache.json"

    sync = IGWatchlistSync(
        api_key="k",
        identifier="u",
        password="p",
        base_url="https://api.ig.com/gateway/deal",
        watchlist_name="My Watchlist",
        account_id="ACC1",
        cache_file=str(cache_file),
        dry_run=True,
    )
    sync._watchlist_id = "WL123"
    sync._watchlist_epics = {"UA.D.AAPL.DAILY.IP"}
    sync._symbol_epic_cache = {"AAPL": "UA.D.AAPL.DAILY.IP"}
    sync._save_cache()

    payload = json.loads(cache_file.read_text(encoding="utf-8"))
    assert payload["watchlist_id"] == "WL123"
    assert payload["watchlist_epics"] == ["UA.D.AAPL.DAILY.IP"]

    loaded = IGWatchlistSync(
        api_key="k",
        identifier="u",
        password="p",
        base_url="https://api.ig.com/gateway/deal",
        watchlist_name="My Watchlist",
        account_id="ACC1",
        cache_file=str(cache_file),
        dry_run=True,
    )
    assert loaded._cache_loaded is True
    assert loaded._watchlist_id == "WL123"
    assert "UA.D.AAPL.DAILY.IP" in loaded._watchlist_epics
    assert loaded._symbol_epic_cache.get("AAPL") == "UA.D.AAPL.DAILY.IP"
