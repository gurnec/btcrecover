"""A small, safety-first BTC trading bot.

The long-term goal of this package is a fully automated BTC trader.  It is
built incrementally, with an emphasis on being *safe to run by default*:

* All trading is simulated (paper trading) unless a live broker is wired in
  explicitly.  There is no code path that spends real money without a
  deliberate, separate integration.
* Every component is small, typed, and unit-tested without needing network
  access or exchange credentials.

Public building blocks:

    Candle          -- a single OHLCV market data point
    MarketDataFeed  -- source of price data (synthetic feed included)
    Strategy        -- turns candles into BUY/SELL/HOLD signals
    Portfolio       -- tracks cash/position and executes paper trades
    TradingBot      -- glues a feed, strategy, and portfolio together
"""

from .config import BotConfig
from .market_data import Candle, MarketDataFeed, SyntheticFeed
from .portfolio import Portfolio, Trade
from .strategy import Signal, MovingAverageCrossStrategy
from .bot import TradingBot

__all__ = [
    "BotConfig",
    "Candle",
    "MarketDataFeed",
    "SyntheticFeed",
    "Portfolio",
    "Trade",
    "Signal",
    "MovingAverageCrossStrategy",
    "TradingBot",
]
