#!/usr/bin/env python

# run-all-tests.py -- runs *all* btcrecover tests
# Copyright (C) 2016, 2017 Christopher Gurnee
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

# Use the green test runner if available
try:
    import green.config, green.suite, green.output, collections
    has_green = True

    # Adapter which uses green, but is similar in signature to unittest.main()
    def main(test_module, exit = None, buffer = None):
        import green.loader, green.runner
        if buffer:
            green_args.quiet_stdout = True
        try:
            suite = green.loader.GreenTestLoader().loadTestsFromModule(test_module)  # new API (v2.9+)
        except AttributeError:
            suite = green.loader.loadFromModule(test_module)                         # legacy API
        results = green.runner.run(suite, sys.stdout, green_args)
        # Return the results in an object with a "result" attribute, same as unittest.main()
        return collections.namedtuple("Tuple", "result")(results)

# If green isn't available, use the unittest test runner
except ImportError:
    from unittest import main
    has_green = False


if __name__ == b'__main__':

    import argparse, sys, atexit, time, timeit, os, multiprocessing

    from btcrecover.test import test_passwords

    is_coincurve_loadable = test_passwords.can_load_coincurve()
    if is_coincurve_loadable:
        from btcrecover.test     import test_seeds
        from btcrecover.btcrseed import full_version
    else:
        from btcrecover.btcrpass import full_version

    # Add two new arguments to those already provided by main()
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--no-buffer", action="store_true")
    parser.add_argument("--no-pause",  action="store_true")
    args, unparsed_args = parser.parse_known_args()
    sys.argv[1:] = unparsed_args

    # By default, pause before exiting
    if not args.no_pause:
        atexit.register(lambda: not multiprocessing.current_process().name.startswith("PoolWorker-") and
                                raw_input("Press Enter to exit ..."))

    print("Testing", full_version() + "\n")

    # Additional setup normally done by green.cmdline.main()
    if has_green:
        green_args = green.config.parseArguments()
        green_args = green.config.mergeConfig(green_args)
        if green_args.shouldExit:
            sys.exit(green_args.exitCode)
        green.suite.GreenTestSuite.args = green_args
        if green_args.debug:
            green.output.debug_level = green_args.debug

    total_tests = total_skipped = total_failures = total_errors = total_passing = 0
    def accumulate_results(r):
        global total_tests, total_skipped, total_failures, total_errors, total_passing
        total_tests    += r.testsRun
        total_skipped  += len(r.skipped)
        total_failures += len(r.failures)
        total_errors   += len(r.errors)
        if has_green:
            total_passing += len(r.passing)

    timer = timeit.default_timer
    start_time = time.time() if has_green else timer()

    if not has_green:
        print("** Testing in ASCII character mode **")
    os.environ["BTCR_CHAR_MODE"] = "ascii"
    results = main(test_passwords, exit=False, buffer= not args.no_buffer).result
    accumulate_results(results)

    print()
    if not has_green:
        print("** Testing in Unicode character mode **")
    os.environ["BTCR_CHAR_MODE"] = "unicode"
    results = main(test_passwords, exit=False, buffer= not args.no_buffer).result
    accumulate_results(results)

    if is_coincurve_loadable:
        print("\n** Testing seed recovery **")
        results = main(test_seeds, exit=False, buffer= not args.no_buffer).result
        accumulate_results(results)
    else:
        print("\nwarning: skipping seed recovery tests (can't find prerequisite coincurve)")

    print("\n\n*** Full Results ***")
    if has_green:
        # Print the results in color using green
        results.startTime  = start_time
        results.testsRun   = total_tests
        results.passing    = (None,) * total_passing
        results.skipped    = (None,) * total_skipped
        results.failures   = (None,) * total_failures
        results.errors     = (None,) * total_errors
        results.all_errors = ()
        green_args.no_skip_report = True
        results.stopTestRun()
    else:
        print("\nRan {} tests in {:.3f}s\n".format(total_tests, timer() - start_time))
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
