#!/usr/bin/env python

# create-address-db.py -- Bitcoin address database creator for seedrecover
# Copyright (C) 2017 Christopher Gurnee
#
# This file is part of btcrecover.
#
# btcrecover is free software: you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version
# 2 of the License, or (at your option) any later version.
#
# btcrecover is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see http://www.gnu.org/licenses/

# If you find this program helpful, please consider a small
# donation to the developer at the following Bitcoin address:
#
#           3Au8ZodNHPei7MQiSVAWb7NB2yqsb48GW4
#
#                      Thank You!

from __future__ import print_function

from btcrecover import addressset
import argparse, sys, atexit
from os import path

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("--datadir",    metavar="DIRECTORY", help="the Bitcoin data directory (default: auto)")
    parser.add_argument("--update",     action="store_true", help="update an existing address database")
    parser.add_argument("--force",      action="store_true", help="overwrite any existing address database")
    parser.add_argument("--no-pause",   action="store_true", default=len(sys.argv)>1, help="never pause before exiting (default: auto)")
    parser.add_argument("--no-progress",action="store_true", default=not sys.stdout.isatty(), help="disable the progress bar (shows cur. blockfile instead)")
    parser.add_argument("--version", "-v", action="version", version="%(prog)s " + addressset.__version__)
    parser.add_argument("dbfilename",   nargs="?", default="addresses.db", help="the name of the database file (default: addresses.db)")

    # Optional bash tab completion support
    try:
        import argcomplete
        argcomplete.autocomplete(parser)
    except ImportError:
        pass

    args = parser.parse_args()

    if not args.no_pause:
        atexit.register(lambda: raw_input("\nPress Enter to exit ..."))

    if not args.update and not args.force and path.exists(args.dbfilename):
        sys.exit("Address database file already exists (use --update to update or --force to overwrite)")

    if args.datadir:
        blockdir = args.datadir
    elif sys.platform == "win32":
        blockdir = path.expandvars(r"%APPDATA%\Bitcoin")
    elif sys.platform.startswith("linux"):
        blockdir = path.expanduser("~/.bitcoin")
    elif sys.platform == "darwin":
        blockdir = path.expanduser("~/Library/Application Support/Bitcoin")
    else:
        sys.exit("Can't automatically determine Bitcoin data directory (use --datadir)")
    blockdir = path.join(blockdir, "blocks")

    addressset.create_address_db(args.dbfilename, blockdir, args.update, progress_bar=not args.no_progress)
