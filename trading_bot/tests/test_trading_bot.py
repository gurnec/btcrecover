"""Unit tests for the trading bot. No network or credentials required."""

import os
import unittest

from trading_bot import (
    BotConfig,
    Candle,
    MovingAverageCrossStrategy,
    Portfolio,
    Signal,
    SyntheticFeed,
    TradingBot,
)
from trading_bot.market_data import ListFeed


class CandleTests(unittest.TestCase):
    def test_rejects_non_positive_price(self):
        with self.assertRaises(ValueError):
            Candle(timestamp=0, open=0, high=1, low=1, close=1)

    def test_rejects_high_below_low(self):
        with self.assertRaises(ValueError):
            Candle(timestamp=0, open=1, high=1, low=2, close=1)

    def test_rejects_negative_volume(self):
        with self.assertRaises(ValueError):
            Candle(timestamp=0, open=1, high=1, low=1, close=1, volume=-1)


class StrategyTests(unittest.TestCase):
    def test_rejects_bad_periods(self):
        with self.assertRaises(ValueError):
            MovingAverageCrossStrategy(fast_period=30, slow_period=10)

    def test_holds_during_warmup(self):
        strat = MovingAverageCrossStrategy(fast_period=2, slow_period=4)
        signals = [strat.update(_c(p)) for p in [10, 11, 12]]
        self.assertTrue(all(s is Signal.HOLD for s in signals))

    def test_detects_buy_and_sell_crossovers(self):
        strat = MovingAverageCrossStrategy(fast_period=2, slow_period=3)
        # Rising then falling prices should yield a BUY then later a SELL.
        prices = [10, 10, 10, 20, 30, 40, 5, 4, 3, 2]
        signals = [strat.update(_c(p)) for p in prices]
        self.assertIn(Signal.BUY, signals)
        self.assertIn(Signal.SELL, signals)
        # BUY must occur before SELL.
        self.assertLess(signals.index(Signal.BUY), signals.index(Signal.SELL))


class PortfolioTests(unittest.TestCase):
    def test_buy_then_sell_flow(self):
        pf = Portfolio(cash=1000.0, fee_rate=0.0)
        buy = pf.buy(price=100.0)
        self.assertIsNotNone(buy)
        self.assertAlmostEqual(pf.cash, 0.0)
        self.assertAlmostEqual(pf.position, 10.0)

        sell = pf.sell(price=110.0)
        self.assertIsNotNone(sell)
        self.assertAlmostEqual(pf.position, 0.0)
        self.assertAlmostEqual(pf.cash, 1100.0)
        self.assertEqual(len(pf.trades), 2)

    def test_fees_reduce_proceeds(self):
        pf = Portfolio(cash=1000.0, fee_rate=0.01)
        pf.buy(price=100.0)
        # 1% fee on the 1000 spend -> 990 worth of asset at 100 = 9.9 units.
        self.assertAlmostEqual(pf.position, 9.9)

    def test_sell_when_flat_is_noop(self):
        pf = Portfolio(cash=1000.0)
        self.assertIsNone(pf.sell(price=100.0))

    def test_buy_with_no_cash_is_noop(self):
        pf = Portfolio(cash=0.0)
        self.assertIsNone(pf.buy(price=100.0))

    def test_rejects_bad_price(self):
        pf = Portfolio()
        with self.assertRaises(ValueError):
            pf.buy(price=0.0)

    def test_equity_marks_position(self):
        pf = Portfolio(cash=0.0, position=2.0)
        self.assertAlmostEqual(pf.equity(price=50.0), 100.0)


class ConfigTests(unittest.TestCase):
    def test_env_overrides(self):
        env = {
            "TRADING_BOT_FAST_PERIOD": "5",
            "TRADING_BOT_SLOW_PERIOD": "20",
            "TRADING_BOT_STARTING_CASH": "5000",
        }
        cfg = BotConfig.load(env=env)
        self.assertEqual(cfg.fast_period, 5)
        self.assertEqual(cfg.slow_period, 20)
        self.assertAlmostEqual(cfg.starting_cash, 5000.0)

    def test_live_trading_env_is_parsed(self):
        cfg = BotConfig.load(env={"TRADING_BOT_LIVE_TRADING": "true"})
        self.assertTrue(cfg.live_trading)

    def test_invalid_periods_rejected(self):
        with self.assertRaises(ValueError):
            BotConfig(fast_period=30, slow_period=10).validate()

    def test_json_file_loading(self):
        import json
        import tempfile

        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump({"symbol": "BTC-EUR", "fast_period": 7}, f)
            path = f.name
        try:
            cfg = BotConfig.load(path=path)
            self.assertEqual(cfg.symbol, "BTC-EUR")
            self.assertEqual(cfg.fast_period, 7)
        finally:
            os.unlink(path)


class BotTests(unittest.TestCase):
    def test_live_trading_is_guarded(self):
        with self.assertRaises(NotImplementedError):
            TradingBot(config=BotConfig(live_trading=True))

    def test_run_over_synthetic_feed(self):
        feed = SyntheticFeed(length=200)
        bot = TradingBot(config=BotConfig(fast_period=5, slow_period=20), feed=feed)
        result = bot.run()
        self.assertEqual(result.candles_processed, 200)
        self.assertGreater(len(result.trades), 0)
        self.assertIsInstance(result.pnl, float)

    def test_run_requires_feed(self):
        bot = TradingBot()
        with self.assertRaises(ValueError):
            bot.run()

    def test_on_trade_callback_fires(self):
        seen = []
        feed = ListFeed(list(SyntheticFeed(length=120)))
        bot = TradingBot(
            config=BotConfig(fast_period=3, slow_period=10),
            feed=feed,
            on_trade=seen.append,
        )
        result = bot.run()
        self.assertEqual(len(seen), len(result.trades))


def _c(close, ts=0):
    """Build a minimal valid candle with a given close price."""
    return Candle(timestamp=ts, open=close, high=close, low=close, close=close)


if __name__ == "__main__":
    unittest.main()
