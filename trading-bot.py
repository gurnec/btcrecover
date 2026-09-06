#!/usr/bin/env python

# trading-bot.py -- safety-first BTC paper-trading bot entry point
#
# This is a convenience launcher equivalent to `python -m trading_bot`.
# It paper-trades only; it never spends real funds.

import sys

from trading_bot.__main__ import main

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
