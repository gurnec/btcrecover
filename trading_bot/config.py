"""Configuration for the trading bot.

Loading order (later overrides earlier):

1. Built-in defaults on :class:`BotConfig`.
2. A JSON file, if one is passed to :meth:`BotConfig.load`.
3. ``TRADING_BOT_*`` environment variables.

Keeping config in one typed place makes it easy to reason about what the bot
will do before running it -- which matters a lot once real money is involved.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from typing import Any, Dict, Optional


@dataclass
class BotConfig:
    """All tunables for a bot run."""

    symbol: str = "BTC-USD"
    fast_period: int = 10
    slow_period: int = 30
    starting_cash: float = 10_000.0
    fee_rate: float = 0.001
    trade_fraction: float = 1.0
    # Safety switch: live trading requires this to be explicitly True *and* a
    # live broker to be supplied.  Paper trading is always the default.
    live_trading: bool = False

    _ENV_PREFIX = "TRADING_BOT_"
    _CASTS = {
        "symbol": str,
        "fast_period": int,
        "slow_period": int,
        "starting_cash": float,
        "fee_rate": float,
        "trade_fraction": float,
    }

    def validate(self) -> "BotConfig":
        if self.fast_period <= 0 or self.slow_period <= 0:
            raise ValueError("periods must be positive")
        if self.fast_period >= self.slow_period:
            raise ValueError("fast_period must be smaller than slow_period")
        if self.starting_cash < 0:
            raise ValueError("starting_cash must be non-negative")
        if not 0.0 <= self.fee_rate < 1.0:
            raise ValueError("fee_rate must be in [0, 1)")
        if not 0.0 < self.trade_fraction <= 1.0:
            raise ValueError("trade_fraction must be in (0, 1]")
        return self

    @classmethod
    def _coerce_bool(cls, value: Any) -> bool:
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in {"1", "true", "yes", "on"}

    @classmethod
    def load(
        cls,
        path: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
    ) -> "BotConfig":
        """Build a config from defaults, an optional JSON file, and env vars."""
        data: Dict[str, Any] = {}
        if path:
            with open(path, "r", encoding="utf-8") as f:
                data.update(json.load(f))

        environ = os.environ if env is None else env
        for field_name, cast in cls._CASTS.items():
            env_key = cls._ENV_PREFIX + field_name.upper()
            if env_key in environ:
                data[field_name] = cast(environ[env_key])
        live_key = cls._ENV_PREFIX + "LIVE_TRADING"
        if live_key in environ:
            data["live_trading"] = cls._coerce_bool(environ[live_key])
        if "live_trading" in data:
            data["live_trading"] = cls._coerce_bool(data["live_trading"])

        known = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        return cls(**known).validate()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
