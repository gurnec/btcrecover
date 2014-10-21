#!/usr/bin/python

# make-unicode.py -- build the Unicode version of btcrecover from the ASCII version
# Copyright (C) 2014 Christopher Gurnee
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# version 2 as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License version 2 for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

# If you find this program helpful, please consider a small donation
# donation to the developer at the following Bitcoin address:
#
#           17LGpN2z62zp7RS825jXwYtE7zZ19Mxxu8
#
#                      Thank You!

from __future__ import print_function
import os.path as path, sys, unittest


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
        print("existing Unicode version "+unicode_name+" is up-to-date", file=sys.stderr)
        return False

    print("making "+unicode_name, file=sys.stderr)
    with open(ascii_version_path, "rb") as ascii_version:
        with open(unicode_version_path, "wb") as unicode_version:

            # Search for the first "key" string
            for line in ascii_version:
                unicode_version.write(line)
                if line.startswith("# Uncomment for Unicode support"):
                    break

            # Uncomment the block of code up until the next "key" string
            for line in ascii_version:
                if line.startswith("# Uncomment for ASCII-only support"):
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

    return True


if __name__ == '__main__':

    # Build the Unicode versions of btcrecover and the test-btcr test suite
    modified1 = make_unicode_version("btcrecover.py", "btcrecoveru.py")
    modified2 = make_unicode_version("test-btcr.py",  "test-btcru.py")
    if not modified1 and not modified2:
        exit("nothing left to do, exiting")

    # If at least one of the files were updated, run the QuickTests suite
    print("\nRunning quick tests\n")

    test_btcr = __import__("test-btcru")
    if unittest.TextTestRunner(buffer=True).run(test_btcr.QuickTests()).wasSuccessful():
        print("\nuse 'python test-btcru.py' to run the full test suite.\n")
    else:
        exit(1)
