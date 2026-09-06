"""Command-line entry point for the trading bot.

Runs a paper-trading backtest over the deterministic synthetic feed by default,
so ``python -m trading_bot`` works with no network access, no credentials, and
no risk of spending real funds.
"""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from .config import BotConfig
from .bot import TradingBot
from .market_data import SyntheticFeed
from .strategy import Signal


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="trading_bot",
        description="Safety-first BTC paper-trading bot (backtest demo).",
    )
    parser.add_argument("--config", help="Path to a JSON config file", default=None)
    parser.add_argument("--fast", type=int, help="Fast SMA period", default=None)
    parser.add_argument("--slow", type=int, help="Slow SMA period", default=None)
    parser.add_argument("--cash", type=float, help="Starting cash", default=None)
    parser.add_argument(
        "--candles",
        type=int,
        default=200,
        help="Number of synthetic candles to simulate",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print each executed trade",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    config = BotConfig.load(args.config)
    if args.fast is not None:
        config.fast_period = args.fast
    if args.slow is not None:
        config.slow_period = args.slow
    if args.cash is not None:
        config.starting_cash = args.cash
    config.validate()

    feed = SyntheticFeed(length=args.candles)

    def report(trade) -> None:
        side = "BUY " if trade.side is Signal.BUY else "SELL"
        print(
            f"  {side} {trade.quantity:.6f} @ {trade.price:,.2f} "
            f"(fee {trade.fee:,.2f}) -> cash {trade.cash_after:,.2f}"
        )

    bot = TradingBot(config=config, feed=feed, on_trade=report if args.verbose else None)

    print(f"Paper-trading {config.symbol} over {args.candles} synthetic candles")
    print(f"Strategy: SMA cross fast={config.fast_period} slow={config.slow_period}")
    if args.verbose:
        print("Trades:")
    result = bot.run()

    print("-" * 48)
    print(f"Trades executed : {len(result.trades)}")
    print(f"Starting equity : {result.starting_equity:,.2f}")
    print(f"Final equity    : {result.final_equity:,.2f}")
    print(f"P&L             : {result.pnl:,.2f} ({result.return_pct:+.2f}%)")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
