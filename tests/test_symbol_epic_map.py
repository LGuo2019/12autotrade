from __future__ import annotations

import json

from rsi_scanner.main import load_symbol_to_epic_map


def test_load_symbol_to_epic_map_builds_aliases(tmp_path):
    payload = {
        "epic_to_twelvedata_symbol": {
            "UA.D.AAPL.DAILY.IP": "AAPL:NASDAQ",
            "CS.D.EURUSD.TODAY.IP": "EUR/USD",
        }
    }
    path = tmp_path / "map.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    out = load_symbol_to_epic_map(str(path))

    assert out["AAPL:NASDAQ"] == "UA.D.AAPL.DAILY.IP"
    assert out["AAPL"] == "UA.D.AAPL.DAILY.IP"
    assert out["EUR/USD"] == "CS.D.EURUSD.TODAY.IP"
    assert out["EURUSD"] == "CS.D.EURUSD.TODAY.IP"
