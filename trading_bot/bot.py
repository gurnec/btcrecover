"""The trading bot: glue between a data feed, a strategy, and a portfolio."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, List, Optional

from .config import BotConfig
from .market_data import Candle, MarketDataFeed
from .portfolio import Portfolio, Trade
from .strategy import MovingAverageCrossStrategy, Signal, Strategy


@dataclass
class BotResult:
    """Summary of a completed bot run."""

    trades: List[Trade]
    final_equity: float
    starting_equity: float
    candles_processed: int

    @property
    def pnl(self) -> float:
        return self.final_equity - self.starting_equity

    @property
    def return_pct(self) -> float:
        if self.starting_equity == 0:
            return 0.0
        return 100.0 * self.pnl / self.starting_equity


class TradingBot:
    """Runs a strategy over a feed against a (paper) portfolio.

    By design this only ever paper-trades.  ``config.live_trading`` is honoured
    as a hard guard: enabling it without supplying a live broker raises, so the
    bot cannot silently move real funds.
    """

    def __init__(
        self,
        config: Optional[BotConfig] = None,
        feed: Optional[MarketDataFeed] = None,
        strategy: Optional[Strategy] = None,
        portfolio: Optional[Portfolio] = None,
        on_trade: Optional[Callable[[Trade], None]] = None,
    ) -> None:
        self.config = (config or BotConfig()).validate()
        if self.config.live_trading:
            raise NotImplementedError(
                "Live trading is not implemented. Run in paper-trading mode "
                "(the default) until a reviewed live broker is wired in."
            )
        self.feed = feed
        self.strategy = strategy or MovingAverageCrossStrategy(
            fast_period=self.config.fast_period,
            slow_period=self.config.slow_period,
        )
        self.portfolio = portfolio or Portfolio(
            cash=self.config.starting_cash,
            fee_rate=self.config.fee_rate,
            trade_fraction=self.config.trade_fraction,
        )
        self.on_trade = on_trade

    def step(self, candle: Candle) -> Optional[Trade]:
        """Process a single candle and return any resulting trade."""
        signal = self.strategy.update(candle)
        if signal is Signal.HOLD:
            return None
        trade = self.portfolio.execute(signal, candle.close, candle.timestamp)
        if trade is not None and self.on_trade is not None:
            self.on_trade(trade)
        return trade

    def run(self, feed: Optional[MarketDataFeed] = None) -> BotResult:
        """Run over an entire feed and return a :class:`BotResult`."""
        feed = feed or self.feed
        if feed is None:
            raise ValueError("no market data feed provided")

        starting_equity = self.portfolio.cash + self.portfolio.position * 0.0
        last_close = 0.0
        count = 0
        for candle in feed:
            if count == 0:
                # Mark starting equity against the first observed price so a
                # pre-existing position is valued fairly.
                starting_equity = self.portfolio.equity(candle.close)
            self.step(candle)
            last_close = candle.close
            count += 1

        final_equity = self.portfolio.equity(last_close) if count else starting_equity
        return BotResult(
            trades=list(self.portfolio.trades),
            final_equity=final_equity,
            starting_equity=starting_equity,
            candles_processed=count,
        )
