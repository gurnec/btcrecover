"""Trading strategies.

A strategy consumes candles one at a time and emits a :class:`Signal`.  Keeping
the interface tiny (``update(candle) -> Signal``) means the bot loop, backtester,
and any future live runner can all share the same strategy objects.
"""

from __future__ import annotations

import enum
from collections import deque
from typing import Deque, Optional

from .market_data import Candle


class Signal(enum.Enum):
    """A trading decision for the current candle."""

    BUY = "BUY"
    SELL = "SELL"
    HOLD = "HOLD"


class Strategy:
    """Base class for strategies."""

    def update(self, candle: Candle) -> Signal:  # pragma: no cover - interface
        raise NotImplementedError


class MovingAverageCrossStrategy(Strategy):
    """Classic dual moving-average crossover.

    Emits ``BUY`` when the fast SMA crosses above the slow SMA and ``SELL`` when
    it crosses below.  Between crossovers it returns ``HOLD``.  Signals are only
    produced once the slow window is fully populated, avoiding noisy decisions
    during warm-up.
    """

    def __init__(self, fast_period: int = 10, slow_period: int = 30) -> None:
        if fast_period <= 0 or slow_period <= 0:
            raise ValueError("periods must be positive")
        if fast_period >= slow_period:
            raise ValueError("fast_period must be smaller than slow_period")
        self.fast_period = fast_period
        self.slow_period = slow_period
        self._fast: Deque[float] = deque(maxlen=fast_period)
        self._slow: Deque[float] = deque(maxlen=slow_period)
        self._prev_fast_above: Optional[bool] = None

    @staticmethod
    def _sma(window: Deque[float]) -> float:
        return sum(window) / len(window)

    def update(self, candle: Candle) -> Signal:
        self._fast.append(candle.close)
        self._slow.append(candle.close)

        # Wait until we have enough data for a meaningful slow average.
        if len(self._slow) < self.slow_period:
            return Signal.HOLD

        fast_above = self._sma(self._fast) > self._sma(self._slow)

        signal = Signal.HOLD
        if self._prev_fast_above is not None and fast_above != self._prev_fast_above:
            signal = Signal.BUY if fast_above else Signal.SELL

        self._prev_fast_above = fast_above
        return signal
