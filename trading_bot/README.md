# trading_bot

A small, **safety-first** BTC trading bot. The long-term goal is a fully
automated BTC trader; this package is the foundation, built so that it is safe
to run and easy to extend.

## Design principles

- **Paper trading by default.** Nothing here spends real money. `Portfolio`
  simulates fills against a known price. Enabling `live_trading` without a
  reviewed live broker raises immediately, so real funds can never move by
  accident.
- **Small, typed, testable interfaces.** A `MarketDataFeed` produces `Candle`s,
  a `Strategy` turns candles into `Signal`s, and a `Portfolio` executes them.
  Each piece is unit-tested with no network access or credentials.
- **Pluggable everything.** Swap the synthetic feed for a live exchange feed, or
  the moving-average strategy for something smarter, without touching the rest.

## Quick start

```bash
# Backtest the SMA-crossover strategy over a deterministic synthetic feed:
python -m trading_bot --verbose

# Or via the launcher script:
./trading-bot.py --fast 5 --slow 20 --cash 5000 --candles 300
```

## Configuration

Config is resolved from defaults, then an optional JSON file, then
`TRADING_BOT_*` environment variables (later wins):

```bash
TRADING_BOT_FAST_PERIOD=5 TRADING_BOT_SLOW_PERIOD=20 python -m trading_bot
```

| Field           | Env var                        | Default   |
| --------------- | ------------------------------ | --------- |
| `symbol`        | `TRADING_BOT_SYMBOL`           | `BTC-USD` |
| `fast_period`   | `TRADING_BOT_FAST_PERIOD`      | `10`      |
| `slow_period`   | `TRADING_BOT_SLOW_PERIOD`      | `30`      |
| `starting_cash` | `TRADING_BOT_STARTING_CASH`    | `10000`   |
| `fee_rate`      | `TRADING_BOT_FEE_RATE`         | `0.001`   |
| `trade_fraction`| `TRADING_BOT_TRADE_FRACTION`   | `1.0`     |
| `live_trading`  | `TRADING_BOT_LIVE_TRADING`     | `false`   |

## Tests

```bash
python -m unittest discover -s trading_bot/tests -v
```

## Roadmap toward full automation

1. **Live market data** — implement a `MarketDataFeed` backed by a real
   exchange REST/WebSocket API (read-only; no keys needed for public data).
2. **Live broker** — implement the `Portfolio.buy`/`sell` surface against an
   exchange, gated behind `live_trading` plus explicit credentials.
3. **Scheduling** — a long-running loop that polls new candles on an interval
   and persists state between runs.
4. **Risk controls** — position limits, stop-loss / take-profit, max drawdown
   kill-switch, and notifications.
5. **More strategies & backtest metrics** — Sharpe, max drawdown, win rate.
