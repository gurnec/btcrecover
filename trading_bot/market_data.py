"""Market data sources for the trading bot.

A ``MarketDataFeed`` yields :class:`Candle` objects (OHLCV bars).  The bot only
depends on this small interface, so new sources -- a live exchange REST/WebSocket
feed, a CSV backtest file, or the deterministic :class:`SyntheticFeed` used in
tests -- can be dropped in without touching strategy or execution code.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Iterable, Iterator, List, Sequence


@dataclass(frozen=True)
class Candle:
    """A single OHLCV market data point.

    ``timestamp`` is a Unix epoch time in seconds.  Prices are quote-currency
    (e.g. USD) per one unit of the base asset (e.g. BTC).
    """

    timestamp: float
    open: float
    high: float
    low: float
    close: float
    volume: float = 0.0

    def __post_init__(self) -> None:
        for name in ("open", "high", "low", "close"):
            value = getattr(self, name)
            if value <= 0 or not math.isfinite(value):
                raise ValueError(f"{name} must be a positive, finite price (got {value!r})")
        if self.high < self.low:
            raise ValueError(f"high ({self.high}) must be >= low ({self.low})")
        if self.volume < 0 or not math.isfinite(self.volume):
            raise ValueError(f"volume must be non-negative and finite (got {self.volume!r})")


class MarketDataFeed:
    """Base class for market data sources.

    Subclasses implement :meth:`candles`, returning an iterable of
    :class:`Candle` objects ordered oldest-first.
    """

    def candles(self) -> Iterable[Candle]:  # pragma: no cover - interface
        raise NotImplementedError

    def __iter__(self) -> Iterator[Candle]:
        return iter(self.candles())


class ListFeed(MarketDataFeed):
    """A feed backed by an in-memory list of candles (handy for backtests)."""

    def __init__(self, candles: Sequence[Candle]) -> None:
        self._candles: List[Candle] = list(candles)

    def candles(self) -> Iterable[Candle]:
        return list(self._candles)


class SyntheticFeed(MarketDataFeed):
    """A deterministic synthetic price series.

    Produces a smooth sine wave around ``base_price`` so strategies can be
    exercised (including crossovers) without any network access.  Being
    deterministic makes it ideal for reproducible tests and demos.
    """

    def __init__(
        self,
        length: int = 200,
        base_price: float = 30_000.0,
        amplitude: float = 4_000.0,
        period: int = 40,
        start_time: float = 0.0,
        interval_seconds: float = 3600.0,
    ) -> None:
        if length <= 0:
            raise ValueError("length must be positive")
        if period <= 0:
            raise ValueError("period must be positive")
        self.length = length
        self.base_price = base_price
        self.amplitude = amplitude
        self.period = period
        self.start_time = start_time
        self.interval_seconds = interval_seconds

    def candles(self) -> Iterable[Candle]:
        for i in range(self.length):
            angle = 2 * math.pi * (i / self.period)
            close = self.base_price + self.amplitude * math.sin(angle)
            prev = self.base_price + self.amplitude * math.sin(
                2 * math.pi * ((i - 1) / self.period)
            )
            open_ = prev if i > 0 else close
            high = max(open_, close) * 1.001
            low = min(open_, close) * 0.999
            yield Candle(
                timestamp=self.start_time + i * self.interval_seconds,
                open=open_,
                high=high,
                low=low,
                close=close,
                volume=1.0,
            )
