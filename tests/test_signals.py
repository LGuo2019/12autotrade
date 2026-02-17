from __future__ import annotations

from rsi_scanner.models import RSIPoint
from rsi_scanner.signals import detect_cross


def test_cross_up():
    prev = RSIPoint(ts=1, rsi=68.21)
    curr = RSIPoint(ts=2, rsi=72.40)
    assert detect_cross(prev, curr) == "OVERBOUGHT"


def test_cross_down():
    prev = RSIPoint(ts=1, rsi=34.00)
    curr = RSIPoint(ts=2, rsi=28.50)
    assert detect_cross(prev, curr) == "OVERSOLD"


def test_repeated_state_no_alert():
    prev = RSIPoint(ts=1, rsi=72.00)
    curr = RSIPoint(ts=2, rsi=74.00)
    assert detect_cross(prev, curr) is None
