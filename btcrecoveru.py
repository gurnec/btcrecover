#!/usr/bin/env python
# for backwards compatibility
import sys, os
print >> sys.stderr, "notice: you can also run 'btcrecover.py --utf8' instead of 'btcrecoveru.py'"
sys.argv.append("--utf8")
execfile(os.path.join(os.path.dirname(__file__), "btcrecover.py"))
