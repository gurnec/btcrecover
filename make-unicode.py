#!/usr/bin/python

# make-unicode.py -- build the Unicode version of btcrecover from the ASCII version
# Copyright (C) 2014, 2015 Christopher Gurnee
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
#           17LGpN2z62zp7RS825jXwYtE7zZ19Mxxu8
#
#                      Thank You!

from __future__ import print_function
import os, os.path as path


install_dir = path.dirname(__file__)

# This is a bit fragile, but it's probably good enough. It simply looks
# for certain strings, and comments or uncomments code between them.
def make_unicode_version(ascii_name, unicode_name):
    ascii_version_path   = path.join(install_dir, ascii_name)
    unicode_version_path = path.join(install_dir, unicode_name)

    if not path.isfile(ascii_version_path):
        exit("can't find " + ascii_version_path)

    if path.isfile  (unicode_version_path) and \
       path.getmtime(unicode_version_path) >= path.getmtime(ascii_version_path):
        print("existing Unicode version "+unicode_name+" is up-to-date")
        return False

    print("making "+unicode_name)
    key_strings = 0
    with open(ascii_version_path, "rb") as ascii_version:
        with open(unicode_version_path, "wb") as unicode_version:

            # Search for the first "key" string
            for line in ascii_version:
                unicode_version.write(line)
                if line.startswith("# Uncomment for Unicode support"):
                    key_strings += 1
                    break

            # Uncomment the block of code up until the next "key" string
            for line in ascii_version:
                if line.startswith("# Uncomment for ASCII-only support"):
                    key_strings += 1
                    unicode_version.write(line)
                    break
                unicode_version.write(line[1:] if line.startswith("#") else line)

            # Comment out the next block of code up until the first empty line
            for line in ascii_version:
                if line.strip() == "":
                    unicode_version.write(line)
                    break
                unicode_version.write("#")
                unicode_version.write(line)

            # Copy the rest of the file
            for line in ascii_version:
                unicode_version.write(line)

    assert key_strings == 2, "expected 2 key strings in {} (found {})".format(ascii_name, key_strings)

    # chmod +x unicode_version_path
    mode = os.stat(unicode_version_path).st_mode
    mode |= (mode & 0o444) >> 2           # "copy" any read bits to corresponding executable bits
    os.chmod(unicode_version_path, mode)  # (harmless NOOP on Windows)

    return True


if __name__ == '__main__':

    import argparse, atexit, unittest

    parser = argparse.ArgumentParser()
    parser.add_argument("--no-quicktests", action="store_true", help="don't run the QuickTests suite")
    parser.add_argument("--no-pause",      action="store_true", help="don't prompt 'Press Enter to exit'")
    args = parser.parse_args()

    # By default, pause before exiting
    if not args.no_pause:
        atexit.register(lambda: raw_input("\nPress Enter to exit ..."))

    # Build the Unicode versions of btcrecover and the test-btcr test suite
    modified1 = make_unicode_version("btcrecover.py", "btcrecoveru.py")
    modified2 = make_unicode_version("test-btcr.py",  "test-btcru.py")
    if not modified1 and not modified2:
        print("nothing left to do, exiting")

    # If at least one of the files were updated, by default run the QuickTests suite
    elif not args.no_quicktests:
        print("\nRunning quick tests\n")

        test_btcr = __import__("test-btcru")
        if unittest.TextTestRunner(buffer=True).run(test_btcr.QuickTests()).wasSuccessful():
            print("\nStart test-btcru.py to run the full test suite.")
        else:
            exit(1)
