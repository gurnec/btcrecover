#!/usr/bin/python

# run-all-tests.py -- runs *all* btcrecover tests
# Copyright (C) 2016 Christopher Gurnee
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

if __name__ == b'__main__':

    import argparse, sys, atexit, timeit, unittest
    from btcrecover.test import test_passwords, test_seeds

    # Add two new arguments to those already provided by unittest.main()
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--no-buffer", action="store_true")
    parser.add_argument("--no-pause",  action="store_true")
    args, unittest_args = parser.parse_known_args()
    sys.argv[1:] = unittest_args

    # By default, pause before exiting
    if not args.no_pause:
        atexit.register(lambda: raw_input("\nPress Enter to exit ..."))

    total_tests = total_skipped = total_failures = total_errors = 0
    def accumulate_results(r):
        global total_tests, total_skipped, total_failures, total_errors
        total_tests    += r.testsRun
        total_skipped  += len(r.skipped)
        total_failures += len(r.failures)
        total_errors   += len(r.errors)

    timer = timeit.default_timer
    start_time = timer()

    print("** Running ANSI password tests **")
    test_passwords.tstr = str
    results = unittest.main(test_passwords, exit=False, buffer= not args.no_buffer).result
    accumulate_results(results)

    print("\n** Running Unicode password tests **")
    test_passwords.tstr = unicode
    results = unittest.main(test_passwords, exit=False, buffer= not args.no_buffer).result
    accumulate_results(results)

    print("\n** Running seed tests **")
    results = unittest.main(test_seeds,     exit=False, buffer= not args.no_buffer).result
    accumulate_results(results)

    elapsed_time = timer() - start_time

    print("\n\n*** Full Results ***\n")
    print("Ran {} tests in {:.3f}s\n".format(total_tests, elapsed_time))
    print("OK" if total_failures == total_errors == 0 else "FAILED", end="")

    details = [
        name + "=" + str(val)
        for name,val in (("failures", total_failures), ("errors", total_errors), ("skipped", total_skipped))
            if val
    ]
    if details:
        print(" (" + ", ".join(details) + ")", end="")
    print("\n")

    sys.exit(0 if total_failures == total_errors == 0 else 1)
