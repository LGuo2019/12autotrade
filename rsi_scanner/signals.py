from __future__ import annotations

from typing import Optional

from .constants import (
    RSI_OVERBOUGHT,
    RSI_OVERSOLD,
    STATE_NEUTRAL,
    STATE_OVERBOUGHT,
    STATE_OVERSOLD,
)
from .models import RSIPoint


def rsi_state(value: float) -> str:
    if value >= RSI_OVERBOUGHT:
        return STATE_OVERBOUGHT
    if value <= RSI_OVERSOLD:
        return STATE_OVERSOLD
    return STATE_NEUTRAL


def detect_cross(prev: RSIPoint, curr: RSIPoint) -> Optional[str]:
    prev_state = rsi_state(prev.rsi)
    curr_state = rsi_state(curr.rsi)
    if prev_state == STATE_NEUTRAL and curr_state in (STATE_OVERBOUGHT, STATE_OVERSOLD):
        return curr_state
    return None
