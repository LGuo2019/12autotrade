from __future__ import annotations

from rsi_scanner.budget import CreditBudget
from rsi_scanner.storage import Storage
from rsi_scanner.twelvedata import TwelveDataClient


def test_budget_blocks_when_exceeded():
    storage = Storage(":memory:")
    budget = CreditBudget(storage=storage, per_min_limit=1, per_day_limit=1, reserve_pct=0)
    ok = budget.consume(1)
    assert ok.ok is True

    blocked = budget.consume(1)
    assert blocked.ok is False


def test_dry_run_no_http_calls():
    storage = Storage(":memory:")
    budget = CreditBudget(storage=storage, per_min_limit=8, per_day_limit=800, reserve_pct=0.05)
    client = TwelveDataClient(api_key="", budget=budget, dry_run=True)

    def _boom(*args, **kwargs):
        raise AssertionError("HTTP call should not happen in dry_run")

    client._session.get = _boom  # type: ignore[attr-defined]
    assert client.fetch_rsi("EUR/USD", "2h") is None
