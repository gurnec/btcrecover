#!/usr/bin/python

# btcrecover.py -- Bitcoin wallet password recovery tool
# Copyright (C) 2014-2016 Christopher Gurnee
#
# This program is free software: you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version
# 2 of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see http://www.gnu.org/licenses/

# If you find this program helpful, please consider a small
# donation to the developer at the following Bitcoin address:
#
#           17LGpN2z62zp7RS825jXwYtE7zZ19Mxxu8
#
#                      Thank You!

# PYTHON_ARGCOMPLETE_OK - enables optional bash tab completion

from __future__ import print_function

from btcrecover import btcrpass
import sys

if __name__ == "__main__":

    btcrpass.parse_arguments(sys.argv[1:])
    (password_found, not_found_msg) = btcrpass.main()

    if password_found:
        btcrpass.safe_print("Password found: '" + password_found + "'")
        if any(ord(c) < 32 or ord(c) > 126 for c in password_found):
            print("HTML encoded:   '" + password_found.encode("ascii", "xmlcharrefreplace") + "'")

    elif not_found_msg:
        print(not_found_msg, file=sys.stderr if btcrpass.args.listpass else sys.stdout)

    else:
        sys.exit(1)  # An error occurred or Ctrl-C was pressed
