"""Paper-trading portfolio and execution engine.

:class:`Portfolio` simulates order execution against a known price, tracking
cash and base-asset holdings and applying a configurable fee.  It deliberately
never touches a real exchange -- it is the "dry run" backend that lets the rest
of the bot be developed and tested safely.  A live broker would implement the
same ``buy``/``sell`` surface.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from .strategy import Signal


@dataclass(frozen=True)
class Trade:
    """A record of a single executed paper trade."""

    timestamp: float
    side: Signal  # BUY or SELL
    price: float
    quantity: float
    fee: float
    cash_after: float
    position_after: float


class Portfolio:
    """Tracks cash and a single base-asset position with fees.

    All buys spend a fixed fraction of available cash; all sells liquidate the
    entire position.  This keeps sizing simple and predictable for a first
    automated trader -- position sizing can be made smarter later behind the
    same interface.
    """

    def __init__(
        self,
        cash: float = 10_000.0,
        fee_rate: float = 0.001,
        position: float = 0.0,
        trade_fraction: float = 1.0,
    ) -> None:
        if cash < 0:
            raise ValueError("starting cash must be non-negative")
        if not 0.0 <= fee_rate < 1.0:
            raise ValueError("fee_rate must be in [0, 1)")
        if not 0.0 < trade_fraction <= 1.0:
            raise ValueError("trade_fraction must be in (0, 1]")
        self.cash = cash
        self.position = position
        self.fee_rate = fee_rate
        self.trade_fraction = trade_fraction
        self.trades: List[Trade] = []

    # -- valuation ---------------------------------------------------------
    def equity(self, price: float) -> float:
        """Total portfolio value (cash + position marked at ``price``)."""
        return self.cash + self.position * price

    # -- execution ---------------------------------------------------------
    def buy(self, price: float, timestamp: float = 0.0) -> Optional[Trade]:
        """Spend ``trade_fraction`` of cash to buy the base asset.

        Returns the resulting :class:`Trade`, or ``None`` if there was no cash
        to deploy.
        """
        if price <= 0:
            raise ValueError("price must be positive")
        spend = self.cash * self.trade_fraction
        if spend <= 0:
            return None
        fee = spend * self.fee_rate
        quantity = (spend - fee) / price
        if quantity <= 0:
            return None
        self.cash -= spend
        self.position += quantity
        trade = Trade(
            timestamp=timestamp,
            side=Signal.BUY,
            price=price,
            quantity=quantity,
            fee=fee,
            cash_after=self.cash,
            position_after=self.position,
        )
        self.trades.append(trade)
        return trade

    def sell(self, price: float, timestamp: float = 0.0) -> Optional[Trade]:
        """Liquidate the entire position.

        Returns the resulting :class:`Trade`, or ``None`` if flat.
        """
        if price <= 0:
            raise ValueError("price must be positive")
        if self.position <= 0:
            return None
        quantity = self.position
        proceeds = quantity * price
        fee = proceeds * self.fee_rate
        self.cash += proceeds - fee
        self.position = 0.0
        trade = Trade(
            timestamp=timestamp,
            side=Signal.SELL,
            price=price,
            quantity=quantity,
            fee=fee,
            cash_after=self.cash,
            position_after=self.position,
        )
        self.trades.append(trade)
        return trade

    def execute(self, signal: Signal, price: float, timestamp: float = 0.0) -> Optional[Trade]:
        """Apply a strategy signal, returning any trade that resulted."""
        if signal is Signal.BUY:
            return self.buy(price, timestamp)
        if signal is Signal.SELL:
            return self.sell(price, timestamp)
        return None
