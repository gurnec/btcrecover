#!/usr/bin/python

# test-btcr.py -- unit tests for btcrecovery.py
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

# (all futures as of 2.6 and 2.7 except unicode_literals)
from __future__ import print_function, absolute_import, division, \
                       generators, nested_scopes, with_statement

import btcrecover, unittest, cStringIO, StringIO, os, os.path, \
       cPickle, tempfile, shutil, filecmp, argparse, sys

wallet_dir = os.path.join(os.path.dirname(__file__), "test-wallets")


class StringIONonClosing(StringIO.StringIO):
    def close(self): pass


class GeneratorTester(unittest.TestCase):

    # tokenlist == a list of lines (w/o "\n") which will become the tokenlist file
    # expected_passwords == a list of passwords which should be produced from the tokenlist
    # extra_cmd_line == a single string of additional command-line options
    # test_passwordlist == whether or not to also test --passwordlist
    # chunksize == the password generator chunksize
    # expected_skipped == the expected # of skipped passwords, if any
    # extra_kwds == additional StringIO objects to act as file stand-ins
    def do_generator_test(self, tokenlist, expected_passwords, extra_cmd_line = "", test_passwordlist = False,
                          chunksize = sys.maxint, expected_skipped = None, **extra_kwds):
        assert isinstance(tokenlist, list)
        assert isinstance(expected_passwords, list)
        tokenlist_str = "\n".join(tokenlist)
        args          = (" __funccall --listpass "+extra_cmd_line).split()

        btcrecover.parse_arguments(["--tokenlist"] + args,
            tokenlist = cStringIO.StringIO(tokenlist_str), **extra_kwds)
        tok_it, skipped = btcrecover.password_generator_factory(chunksize)
        if expected_skipped is not None:
            self.assertEqual(skipped, expected_skipped)
        try:
            self.assertEqual(tok_it.next(), expected_passwords)
        except StopIteration:
            self.assertEqual([], expected_passwords)
        if not test_passwordlist: return (tok_it,)

        # Reset any files passed in as extra parameters
        for sio in filter(lambda s: isinstance(s, StringIONonClosing), extra_kwds.values()):
            sio.seek(0)

        btcrecover.parse_arguments(["--passwordlist"] + args,
            passwordlist = cStringIO.StringIO(tokenlist_str), **extra_kwds)
        pwl_it, skipped = btcrecover.password_generator_factory(chunksize)
        if expected_skipped is not None:
            self.assertEqual(skipped, expected_skipped)
        try:
            self.assertEqual(pwl_it.next(), expected_passwords)
        except StopIteration:
            self.assertEqual([], expected_passwords)
        return (tok_it, pwl_it)

    # tokenlist == a list of lines (w/o "\n") which will become the tokenlist file
    # expected_error == a (partial) error message that should be produced from the tokenlist
    # extra_cmd_line == a single string of additional command-line options
    # extra_kwds == additional StringIO objects to act as file stand-ins
    def expect_syntax_failure(self, tokenlist, expected_error, extra_cmd_line = "", **extra_kwds):
        assert isinstance(tokenlist, list)
        with self.assertRaises(SystemExit) as cm:
            btcrecover.parse_arguments(
                ("--tokenlist __funccall --listpass "+extra_cmd_line).split(),
                tokenlist = cStringIO.StringIO("\n".join(tokenlist)),
                **extra_kwds)
        self.assertIn(expected_error, cm.exception.code)


class Test01Basics(GeneratorTester):

    def test_alternate(self):
        self.do_generator_test(["one", "two"], ["one", "two", "twoone", "onetwo"])

    def test_mutex(self):
        self.do_generator_test(["one two three"], ["one", "two", "three"])

    def test_require(self):
        self.do_generator_test(["one", "+ two", "+ three"],
            ["threetwo", "twothree", "threetwoone", "threeonetwo",
            "twothreeone", "twoonethree", "onethreetwo", "onetwothree"])

    def test_chunksize_divisible(self):
        tok_it, = self.do_generator_test(["one two three four five six"], ["one", "two", "three"], "", False, 3)
        self.assertEqual(tok_it.next(), ["four", "five", "six"])
        self.assertRaises(StopIteration, tok_it.next)
    def test_chunksize_indivisible(self):
        tok_it, = self.do_generator_test(["one two three four five"], ["one", "two", "three"], "", False, 3)
        self.assertEqual(tok_it.next(), ["four", "five"])
        self.assertRaises(StopIteration, tok_it.next)
    def test_chunksize_modified(self):
        tok_it, = self.do_generator_test(["one two three four five six"], ["one", "two"], "", False, 2)
        self.assertIsNone(tok_it.send( (3, False) ))
        self.assertEqual(tok_it.next(), ["three", "four", "five"])
        self.assertEqual(tok_it.next(), ["six"])
        self.assertRaises(StopIteration, tok_it.next)

    def test_only_yield_count(self):
        btcrecover.parse_arguments(("--tokenlist __funccall --listpass").split(),
            tokenlist = cStringIO.StringIO("one two three four five six"))
        tok_it = btcrecover.password_generator(2, True)
        self.assertEqual(tok_it.next(), 2)
        self.assertIsNone(tok_it.send( (3, True) ))
        self.assertEqual(tok_it.next(), 3)
        self.assertIsNone(tok_it.send( (3, False) ))
        self.assertEqual(tok_it.next(), ["six"])
        self.assertRaises(StopIteration, tok_it.next)

        btcrecover.parse_arguments(("--passwordlist __funccall --listpass").split(),
            passwordlist = cStringIO.StringIO("one two three four five six".replace(" ", "\n")))
        pwl_it = btcrecover.password_generator(2, True)
        self.assertEqual(pwl_it.next(), 2)
        self.assertIsNone(pwl_it.send( (3, True) ))
        self.assertEqual(pwl_it.next(), 3)
        self.assertIsNone(pwl_it.send( (3, False) ))
        self.assertEqual(pwl_it.next(), ["six"])
        self.assertRaises(StopIteration, pwl_it.next)

    def test_only_yield_count_all(self):
        btcrecover.parse_arguments(("--tokenlist __funccall --listpass").split(),
            tokenlist = cStringIO.StringIO("one two three"))
        tok_it = btcrecover.password_generator(4, True)
        self.assertEqual(tok_it.next(), 3)
        self.assertRaises(StopIteration, tok_it.next)

        btcrecover.parse_arguments(("--passwordlist __funccall --listpass").split(),
            passwordlist = cStringIO.StringIO("one two three".replace(" ", "\n")))
        pwl_it = btcrecover.password_generator(4, True)
        self.assertEqual(pwl_it.next(), 3)
        self.assertRaises(StopIteration, pwl_it.next)

    def test_count(self):
        btcrecover.parse_arguments(("--tokenlist __funccall --listpass").split(),
            tokenlist = cStringIO.StringIO("one two three"))
        self.assertEqual(btcrecover.count_and_check_eta(1.0), 3)
    def test_count_zero(self):
        btcrecover.parse_arguments(("--tokenlist __funccall --listpass").split(),
            tokenlist = cStringIO.StringIO(""))
        self.assertEqual(btcrecover.count_and_check_eta(1.0), 0)
    # the size of a "chunk" is == btcrecover.PASSWORDS_BETWEEN_UPDATES == 100000
    def test_count_one_chunk(self):
        btcrecover.parse_arguments(("--tokenlist __funccall --listpass").split(),
            tokenlist = cStringIO.StringIO("%5d"))
        self.assertEqual(btcrecover.count_and_check_eta(1.0), 100000)
    def test_count_two_chunks(self):
        btcrecover.parse_arguments(("--tokenlist __funccall --listpass").split(),
            tokenlist = cStringIO.StringIO("%5d 100000"))
        self.assertEqual(btcrecover.count_and_check_eta(1.0), 100001)

    def test_token_counts_min_0(self):
        self.do_generator_test(["one"], ["", "one"], "--min-tokens 0")
    def test_token_counts_min_2(self):
        self.do_generator_test(["one", "two", "three"],
            ["twoone", "onetwo", "threeone", "onethree", "threetwo", "twothree", "threetwoone",
            "threeonetwo", "twothreeone", "twoonethree", "onethreetwo", "onetwothree"],
            "--min-tokens 2")
    def test_token_counts_max_2(self):
        self.do_generator_test(["one", "two", "three"],
            ["one", "two", "twoone", "onetwo", "three", "threeone", "onethree", "threetwo", "twothree"],
            "--max-tokens 2")
    def test_token_counts_min_max_2(self):
        self.do_generator_test(["one", "two", "three"],
            ["twoone", "onetwo", "threeone", "onethree", "threetwo", "twothree"],
            "--min-tokens 2 --max-tokens 2")

    def test_empty_file(self):
        self.do_generator_test([], [], "", True)
    def test_one_char_file(self):
        self.do_generator_test(["a"], ["a"], "", True)

    def test_z_all(self):
        self.do_generator_test(["1", "2 3", "+ 4 5"], map(str, [
            4,41,14,42,24,421,412,241,214,142,124,43,34,431,413,341,314,143,134,
            5,51,15,52,25,521,512,251,215,152,125,53,35,531,513,351,315,153,135]))


class Test02Anchors(GeneratorTester):

    def test_begin(self):
        self.do_generator_test(["^one", "^two", "three"],
            ["one", "two", "three", "onethree", "twothree"])
    def test_begin_0len(self):
        self.do_generator_test(["^"], [""])

    def test_end(self):
        self.do_generator_test(["one$", "two$", "three"],
            ["one", "two", "three", "threeone", "threetwo"])
    def test_end_0len(self):
        self.do_generator_test(["$"], [""])

    def test_begin_and_end(self):
        self.expect_syntax_failure(["^one$"], "token on line 1 is anchored with both ^ at the beginning and $ at the end")

    def test_positional(self):
        self.do_generator_test(["one", "^2^two", "^3^three"], ["one", "onetwo", "onetwothree"])
    def test_positional_old(self):
        self.do_generator_test(["one", "^2$two", "^3$three"], ["one", "onetwo", "onetwothree"])
    def test_positional_0len(self):
        self.do_generator_test(["+ ^1^", "^2^two"], ["", "two"])

    def test_positional_invalid(self):
        self.expect_syntax_failure(["^0^zero"], "anchor position of token on line 1 must be 1 or greater")

    def test_middle(self):
        self.do_generator_test(["^one", "^2,2^two", "^,3^three", "^,^four", "five$"],
            ["one", "five", "onefive", "onetwofive", "onethreefive", "onetwothreefive", "onefourfive",
            "onetwofourfive", "onefourthreefive", "onethreefourfive", "onetwothreefourfive"])
    def test_middle_old(self):
        self.do_generator_test(["^one", "^2,2$two", "^,3$three", "^,$four", "five$"],
            ["one", "five", "onefive", "onetwofive", "onethreefive", "onetwothreefive", "onefourfive",
            "onetwofourfive", "onefourthreefive", "onethreefourfive", "onetwothreefourfive"])
    def test_middle_0len(self):
        self.do_generator_test(["one", "+ ^,^", "^3^three"], ["onethree"])

    def test_middle_invalid_begin(self):
        self.expect_syntax_failure(["^1,^one"],  "anchor range of token on line 1 must begin with 2 or greater")
    def test_middle_invalid_range(self):
        self.expect_syntax_failure(["^3,2^one"], "anchor range of token on line 1 is invalid")
    def test_not_middle(self):
        self.do_generator_test(["^2,3one"], ["2,3one"])

class Test03WildCards(GeneratorTester):

    def test_basics_1(self):
        self.do_generator_test(["%d"], map(str, xrange(10)))
    def test_basics_2(self):
        self.do_generator_test(["%dtest"], [str(i)+"test" for i in xrange(10)])
    def test_basics_3(self):
        self.do_generator_test(["te%dst"], ["te"+str(i)+"st" for i in xrange(10)])
    def test_basics_4(self):
        self.do_generator_test(["test%d"], ["test"+str(i) for i in xrange(10)])

    def test_invalid_nocust(self):
        self.expect_syntax_failure(["%c"],    "invalid wildcard")
    def test_invalid_nocust_cap(self):
        self.expect_syntax_failure(["%C"],    "invalid wildcard")
    def test_invalid_notype(self):
        self.expect_syntax_failure(["test%"], "invalid wildcard")

    def test_multiple(self):
        self.do_generator_test(["%d%d"], ["{:02}".format(i) for i in xrange(100)])

    def test_length_2(self):
        self.do_generator_test(["%2d"],  ["{:02}".format(i) for i in xrange(100)])
    def test_length_range(self):
        self.do_generator_test(["%0,2d"],
            [""] +
            map(str, xrange(10)) +
            ["{:02}".format(i) for i in xrange(100)])

    def test_length_invalid_range(self):
        self.expect_syntax_failure(["%2,1d"], "on line 1: min wildcard length (2) > max length (1)")
    def test_invalid_length_1(self):
        self.expect_syntax_failure(["%2,d"],  "invalid wildcard")
    def test_invalid_length_2(self):
        self.expect_syntax_failure(["%,2d"],  "invalid wildcard")

    def test_case_lower(self):
        self.do_generator_test(["%a"], map(chr, xrange(ord("a"), ord("z")+1)))
    def test_case_upper(self):
        self.do_generator_test(["%A"], map(chr, xrange(ord("A"), ord("Z")+1)))
    def test_case_insensitive_1(self):
        self.do_generator_test(["%ia"],
            map(chr, xrange(ord("a"), ord("z")+1)) + map(chr, xrange(ord("A"), ord("Z")+1)))
    def test_case_insensitive_2(self):
        self.do_generator_test(["%iA"],
            map(chr, xrange(ord("A"), ord("Z")+1)) + map(chr, xrange(ord("a"), ord("z")+1)))

    def test_custom(self):
        self.do_generator_test(["%c"],  ["a", "b", "c", "D", "2"], "--custom-wild a-cD2")
    def test_custom_upper(self):
        self.do_generator_test(["%C"],  ["A", "B", "C", "D", "2"], "--custom-wild a-cD2")
    def test_custom_insensitive_1(self):
        self.do_generator_test(["%ic"], ["a", "b", "c", "D", "2", "A", "B", "C", "d"],
            "--custom-wild a-cD2 -d")
    def test_custom_insensitive_2(self):
        self.do_generator_test(["%iC"], ["A", "B", "C", "d", "2", "a", "b", "c", "D"],
            "--custom-wild a-cD2 -d")

    def test_set(self):
        self.do_generator_test(["%[abcc-]"], ["a", "b", "c", "-"], "-d")
    def test_set_insensitive(self):
        self.do_generator_test(["%i[abcc-]"], ["a", "b", "c", "-", "A", "B", "C"], "-d")
    def test_noset(self):
        self.do_generator_test(["%%[not-a-range]"], ["%[not-a-range]"])

    def test_range_1(self):
        self.do_generator_test(["%[1dc-f]"],  ["1", "d", "c", "e", "f"], "-d")
    def test_range_2(self):
        self.do_generator_test(["%[a-c-e]"], ["a", "b", "c", "-", "e"])
    def test_range_insensitive(self):
        self.do_generator_test(["%i[1dc-f]"], ["1", "d", "c", "e", "f", "D", "C", "E", "F"], "-d")

    def test_range_invalid(self):
        self.expect_syntax_failure(["%[c-a]"],  "first character in wildcard range 'c' > last 'a'")

    def test_contracting_1(self):
        self.do_generator_test(["a%0,2-bcd"], ["abcd", "bcd", "acd", "cd", "ad"], "-d")
    def test_contracting_2(self):
        self.do_generator_test(["abcd%1,2-"], ["abc", "ab"], "-d")
    def test_contracting_right(self):
        self.do_generator_test(["ab%0,1>cd"], ["abcd", "abd"], "-d")
    def test_contracting_left(self):
        self.do_generator_test(["ab%0,3<cd"], ["abcd", "acd", "cd"], "-d")
    def test_contracting_multiple(self):
        self.do_generator_test(["%0,2-ab%[X]cd%0,2-"],
            ["abXcd", "abXc", "abX", "bXcd", "bXc", "bX", "Xcd", "Xc", "X"], "-d")


class Test04Typos(GeneratorTester):

    def test_capslock(self):
        self.do_generator_test(["One2Three"], ["One2Three", "oNE2tHREE"],
            "--typos-capslock --typos 2 -d", True)
    def test_capslock_nocaps(self):
        self.do_generator_test(["123"], ["123"],
            "--typos-capslock --typos 2 -d", True)

    def test_swap(self):
        self.do_generator_test(["abcdd"], ["abcdd", "bacdd", "acbdd", "abdcd", "badcd"],
            "--typos-swap --typos 2 -d", True)

    def test_repeat(self):
        self.do_generator_test(["abc"], ["abc", "aabc", "abbc", "abcc", "aabbc", "aabcc", "abbcc"],
            "--typos-repeat --typos 2 -d", True)

    def test_delete(self):
        self.do_generator_test(["abc"], ["abc", "bc", "ac", "ab", "c", "b", "a"],
            "--typos-delete --typos 2 -d", True)

    def test_case(self):
        self.do_generator_test(["abC1"], ["abC1", "AbC1", "aBC1", "abc1", "ABC1", "Abc1", "aBc1"],
            "--typos-case --typos 2 -d", True)

    def test_closecase(self):
        self.do_generator_test(["one2Three"],
            ["one2Three", "One2Three", "one2three", "one2THree", "one2ThreE", "One2three",
            "One2THree", "One2ThreE", "one2tHree", "one2threE", "one2THreE"],
            "--typos-closecase --typos 2 -d", True)

    def test_insert(self):
        self.do_generator_test(["abc"],
            ["abc", "Xabc", "aXbc", "abXc", "abcX", "XaXbc", "XabXc", "XabcX", "aXbXc", "aXbcX", "abXcX"],
            "--typos-insert X --typos 2 -d", True)
    def test_insert_adjacent_1(self):
        self.do_generator_test(["ab"], ["ab", "Xab", "aXb", "abX", "XXab", "XaXb", "XabX", "aXXb", "aXbX", "abXX"],
            "--typos-insert X --typos 2 --max-adjacent-inserts 2 -d", True)
    def test_insert_adjacent_2(self):
        self.do_generator_test(["a"], ["a", "Xa", "aX", "XXa", "XaX", "aXX", "XXaX", "XaXX" ],
            "--typos-insert X --typos 3 --max-adjacent-inserts 2 -d", True)
    def test_insert_wildcard(self):
        self.do_generator_test(["abc"], ["abc", "Xabc", "Yabc", "aXbc", "aYbc", "abXc", "abYc", "abcX", "abcY"],
            "--typos-insert %[XY] -d", True)
    def test_insert_wildcard_adjacent(self):
        self.do_generator_test(["a"],
            ["a", "Xa", "Ya", "aX", "aY", "XXa", "XYa", "YXa", "YYa",
            "XaX", "XaY", "YaX", "YaY", "aXX", "aXY", "aYX", "aYY"],
            "--typos-insert %[XY] --typos 2 --max-adjacent-inserts 2 -d", True)
    def test_insert_invalid(self):
        self.expect_syntax_failure(["abc"], "contracting wildcards are not permitted here",
            "--typos-insert %0,1-")

    def test_replace(self):
        self.do_generator_test(["abc"], ["abc", "Xbc", "aXc", "abX", "XXc", "XbX", "aXX"],
            "--typos-replace X --typos 2 -d", True)
    def test_replace_wildcard(self):
        self.do_generator_test(["abc"], ["abc", "Xbc", "Ybc", "aXc", "aYc", "abX", "abY"],
            "--typos-replace %[X-Y] -d", True)
    def test_replace_invalid(self):
        self.expect_syntax_failure(["abc"], "contracting wildcards are not permitted here",
            "--typos-replace %>")

    def test_map(self):
        self.do_generator_test(["axb"],
            ["axb", "Axb", "Bxb", "axA", "axB", "AxA", "AxB", "BxA", "BxB"],
            "--typos-map __funccall --typos 2 -d", True,
            typos_map=StringIONonClosing(" ab \t AB \n x x \n a aB "))

    def test_z_all(self):
        self.do_generator_test(["12"],
            map(str, [12,812,182,128,8812,8182,8128,1882,1828,1288,112,8112,1812,1182,
                1128,2,82,28,92,892,982,928,122,8122,1822,1282,1228,1,81,18,19,819,189,
                198,1122,11,119,22,"",9,922,9,99,21,821,281,218,221,1,91,211,2,29]),
            "--typos-swap --typos-repeat --typos-delete --typos-case --typos-insert 8 --typos-replace 9 --typos 2 --max-adjacent-inserts 2 -d",
            True)

    def test_z_min_typos_1(self):
        self.do_generator_test(["12"],
            map(str, [88182,88128,81882,81828,81288,18828,18288,88112,81812,81182,81128,
                18812,18182,18128,11882,11828,11288,882,828,288,8892,8982,8928,9882,9828,
                9288,88122,81822,81282,81228,18822,18282,18228,12882,12828,12288,881,818,
                188,8819,8189,8198,1889,1898,1988,81122,18122,11822,11282,11228,811,181,
                118,8119,1819,1189,1198,822,282,228,8,89,98,8922,9822,9282,9228,89,98,899,
                989,998,8821,8281,8218,2881,2818,2188,8221,2821,2281,2218,81,18,891,981,
                918,8211,2811,2181,2118,82,28,829,289,298,2211,22,229,11,"",9,911,9,99]),
            "--typos-swap --typos-repeat --typos-delete --typos-case --typos-insert 8 --typos-replace 9 --typos 3 --max-adjacent-inserts 2 --min-typos 3 -d",
            True)
    def test_z_min_typos_2(self):
        self.do_generator_test(["12"], [],
            "--typos-swap --typos-repeat --typos-delete --typos-case --typos-replace 8 --typos 4 -d --min-typos 4",
            True)


LARGE_TOKENLIST_LEN = btcrecover.PASSWORDS_BETWEEN_UPDATES
LARGE_TOKENLIST     = " ".join(str(i) for i in xrange(LARGE_TOKENLIST_LEN))
LARGE_LAST_TOKEN    = str(LARGE_TOKENLIST_LEN - 1)
class Test05CommandLine(GeneratorTester):

    def test_regex_only(self):
        self.do_generator_test(["one", "two"], ["one", "twoone", "onetwo"], "--regex-only o.e")

    def test_regex_never(self):
        self.do_generator_test(["one", "two"], ["two"], "--regex-never o.e", True)

    def test_delimiter_tokenlist(self):
        self.do_generator_test([" one ** two **** "], [" one ", " two ", "", " "], "--delimiter **")

    def test_delimiter_typosmap(self):
        self.do_generator_test(["axb"], ["axb", "Axb", " xb", "axA", "ax ", "AxA", "Ax ", " xA", " x " ],
            "--delimiter ** --typos-map __funccall --typos 2 -d",
            True, typos_map=StringIONonClosing(" ab **A \n x **x"))

    # Try to test the myriad of --skip related boundary conditions in password_generator_factory()
    def test_skip(self):
        self.do_generator_test(["one", "two"], ["twoone", "onetwo"], "--skip 2", False, sys.maxint, 2)
    def test_skip_all_exact(self):
        self.do_generator_test(["one"], [], "--skip 1", True, sys.maxint, 1)
    def test_skip_all_pastend_1(self):
        self.do_generator_test(["one"], [], "--skip 2", True, sys.maxint, 1)
    def test_skip_all_pastend_2(self):
        self.do_generator_test(["one"], [], "--skip 2000000", True, sys.maxint, 1)
    def test_skip_empty_1(self):
        self.do_generator_test([], [], "--skip 1", True, sys.maxint, 0)
    def test_skip_empty_2(self):
        self.do_generator_test([], [], "--skip 2000000", True, sys.maxint, 0)
    def test_skip_large_1(self):
        self.do_generator_test([LARGE_TOKENLIST], [LARGE_LAST_TOKEN], "-d --skip "+str(LARGE_TOKENLIST_LEN-1), False, sys.maxint, LARGE_TOKENLIST_LEN-1)
    def test_skip_large_1_all_exact(self):
        self.do_generator_test([LARGE_TOKENLIST], [],                 "-d --skip "+str(LARGE_TOKENLIST_LEN  ), False, sys.maxint, LARGE_TOKENLIST_LEN)
    def test_skip_large_1_all_pastend(self):
        self.do_generator_test([LARGE_TOKENLIST], [],                 "-d --skip "+str(LARGE_TOKENLIST_LEN+1), False, sys.maxint, LARGE_TOKENLIST_LEN)
    def test_skip_large_2(self):
        self.do_generator_test([LARGE_TOKENLIST + " last"], ["last"], "-d --skip "+str(LARGE_TOKENLIST_LEN  ), False, sys.maxint, LARGE_TOKENLIST_LEN)
    def test_skip_large_2_all_exact(self):
        self.do_generator_test([LARGE_TOKENLIST + " last"], [],       "-d --skip "+str(LARGE_TOKENLIST_LEN+1), False, sys.maxint, LARGE_TOKENLIST_LEN+1)
    def test_skip_large_2_all_pastend(self):
        self.do_generator_test([LARGE_TOKENLIST + " last"], [],       "-d --skip "+str(LARGE_TOKENLIST_LEN+2), False, sys.maxint, LARGE_TOKENLIST_LEN+1)
    def test_skip_end2end(self):
        btcrecover.parse_arguments(("--skip 2 --tokenlist __funccall --listpass").split(),
            tokenlist = cStringIO.StringIO("one \n two"))
        self.assertIn("2 password combinations (plus 2 skipped)", btcrecover.main())
    def test_skip_end2end_all_exact(self):
        btcrecover.parse_arguments(("--skip 4 --tokenlist __funccall --listpass").split(),
            tokenlist = cStringIO.StringIO("one \n two"))
        self.assertIn("0 password combinations (plus 4 skipped)", btcrecover.main())
    def test_skip_end2end_all_pastend(self):
        btcrecover.parse_arguments(("--skip 5 --tokenlist __funccall --listpass").split(),
            tokenlist = cStringIO.StringIO("one \n two"))
        self.assertIn("0 password combinations (plus 4 skipped)", btcrecover.main())
    def test_skip_end2end_all_noeta(self):
        btcrecover.parse_arguments(("--skip 5 --tokenlist __funccall --no-eta --privkey").split(),
            tokenlist = cStringIO.StringIO("one \n two"),
            privkey   = "bWI6oikebfNQTLk75CfI5X3svX6AC7NFeGsgTNXZfA==")  # dummy privkey not actually tested
        self.assertIn("Skipped all 4 passwords", btcrecover.main())

    def test_max_eta(self):
        btcrecover.parse_arguments(("--max-eta 1 --tokenlist __funccall --privkey").split(),
            tokenlist = cStringIO.StringIO("1 2 3 4 5 6 7 8 9 10 11"),
            privkey   = "bWI6oikebfNQTLk75CfI5X3svX6AC7NFeGsgTNXZfA==")  # dummy privkey not actually tested
        with self.assertRaises(SystemExit) as cm:
            btcrecover.count_and_check_eta(360.0)  # 360s * 11 passwords > 1 hour
        self.assertIn("at least 11 passwords to try, ETA > max_eta option (1 hours)", cm.exception.code)
    def test_max_eta_ok(self):
        btcrecover.parse_arguments(("--max-eta 1 --tokenlist __funccall --privkey").split(),
            tokenlist = cStringIO.StringIO("1 2 3 4 5 6 7 8 9 10"),
            privkey   = "bWI6oikebfNQTLk75CfI5X3svX6AC7NFeGsgTNXZfA==")  # dummy privkey not actually tested
        self.assertEqual(btcrecover.count_and_check_eta(360.0), 10)  # 360s * 10 passwords <= 1 hour
    def test_max_eta_skip(self):
        btcrecover.parse_arguments(("--max-eta 1 --skip 4 --tokenlist __funccall --privkey").split(),
            tokenlist = cStringIO.StringIO("1 2 3 4 5 6 7 8 9 10 11 12 13 14 15"),
            privkey   = "bWI6oikebfNQTLk75CfI5X3svX6AC7NFeGsgTNXZfA==")  # dummy privkey not actually tested
        with self.assertRaises(SystemExit) as cm:
            btcrecover.count_and_check_eta(360.0)  # 360s * 11 passwords > 1 hour
        self.assertIn("at least 11 passwords to try, ETA > max_eta option (1 hours)", cm.exception.code)
    def test_max_eta_skip_ok(self):
        btcrecover.parse_arguments(("--max-eta 1 --skip 5 --tokenlist __funccall --privkey").split(),
            tokenlist = cStringIO.StringIO("1 2 3 4 5 6 7 8 9 10 11 12 13 14 15"),
            privkey   = "bWI6oikebfNQTLk75CfI5X3svX6AC7NFeGsgTNXZfA==")  # dummy privkey not actually tested
        # 360s * 10 passwords <= 1 hour, but count_and_check_eta still returns the total count of 15
        self.assertEqual(btcrecover.count_and_check_eta(360.0), 15)

    def test_worker(self):
        self.do_generator_test(["one two three four five six seven eight"], ["one", "four", "seven"],
            "--worker 1/3")
        self.do_generator_test(["one two three four five six seven eight"], ["two", "five", "eight"],
            "--worker 2/3")
        self.do_generator_test(["one two three four five six seven eight"], ["three", "six"],
            "--worker 3/3")

    def test_no_dupchecks_1(self):
        self.do_generator_test(["one", "one"], ["one", "one", "oneone", "oneone"], "-ddd")
        self.do_generator_test(["one", "one"], ["one", "one", "oneone"], "-dd")

    def test_no_dupchecks_2(self):
        self.do_generator_test(["one", "one"], ["one", "oneone"], "-d")
        # Duplicate code works differently the second time around; test it also
        self.assertEqual(btcrecover.password_generator(3).next(), ["one", "oneone"])

    def test_no_dupchecks_3(self):
        self.do_generator_test(["%[ab] %[a-b]"], ["a", "b", "a", "b"], "-d")
        self.do_generator_test(["%[ab] %[a-b]"], ["a", "b"])
        # Duplicate code works differently the second time around; test it also
        self.assertEqual(btcrecover.password_generator(3).next(), ["a", "b"])

SAVESLOT_SIZE = 4096
AUTOSAVE_ARGS = ("--autosave __funccall --tokenlist __funccall --privkey --no-progress --threads 1").split()
AUTOSAVE_TOKENLIST = "^one \n two \n three \n"
AUTOSAVE_PRIVKEY   = "bWI6oikebfNQTLk75CfI5X3svX6AC7NFeGsgTNXZfA=="
class Test06AutosaveRestore(unittest.TestCase):

    autosave_file = StringIONonClosing()

    def run_autosave_parse_arguments(self, autosave_file):
        btcrecover.parse_arguments(AUTOSAVE_ARGS,
            autosave  = autosave_file,
            tokenlist = cStringIO.StringIO(AUTOSAVE_TOKENLIST),
            privkey   = AUTOSAVE_PRIVKEY)

    def run_restore_parse_arguments(self, restore_file):
        btcrecover.parse_arguments("--restore __funccall".split(),
            restore   = restore_file,
            tokenlist = cStringIO.StringIO(AUTOSAVE_TOKENLIST),
            privkey   = AUTOSAVE_PRIVKEY)

    # These test_ functions are in alphabetical order (the same order they're executed in)

    # Create the initial autosave data
    def test_autosave(self):
        autosave_file = self.__class__.autosave_file
        self.run_autosave_parse_arguments(autosave_file)
        self.assertIn("Password search exhausted", btcrecover.main())
        #
        # Load slot 0, and verify it was created before any passwords were tested
        autosave_file.seek(0)
        savestate = cPickle.load(autosave_file)
        self.assertEqual(savestate.get("skip"), 0)
        self.assertLessEqual(autosave_file.tell(), SAVESLOT_SIZE)
        #
        # Load slot 1, and verify it was created after all passwords were tested
        autosave_file.seek(SAVESLOT_SIZE)
        savestate = cPickle.load(autosave_file)
        self.assertEqual(savestate.get("skip"), 9)
        self.assertLessEqual(autosave_file.tell(), 2*SAVESLOT_SIZE)

    # Using --autosave, restore (a copy of) the autosave data created by test_autosave(),
    # and make sure all of the passwords have already been tested
    def test_autosave_restore(self):
        self.run_autosave_parse_arguments(StringIONonClosing(self.__class__.autosave_file.getvalue()))
        self.assertIn("Skipped all 9 passwords, exiting", btcrecover.main())

    # Using --restore, restore (a copy of) the autosave data created by test_autosave(),
    # and make sure all of the passwords have already been tested
    def test_restore(self):
        self.run_restore_parse_arguments(StringIONonClosing(self.__class__.autosave_file.getvalue()))
        self.assertIn("Skipped all 9 passwords, exiting", btcrecover.main())

    # Using --autosave, restore (a copy of) the autosave data created by test_autosave(),
    # but change the arguments to generate an error
    def test_restore_changed_args(self):
        with self.assertRaises(SystemExit) as cm:
            btcrecover.parse_arguments(AUTOSAVE_ARGS + ["--typos-capslock"],
                autosave  = StringIO.StringIO(self.__class__.autosave_file.getvalue()),
                tokenlist = cStringIO.StringIO(AUTOSAVE_TOKENLIST),
                privkey   = AUTOSAVE_PRIVKEY)
        self.assertIn("can't restore previous session: the command line options have changed", cm.exception.code)

    # Using --autosave, restore (a copy of) the autosave data created by test_autosave(),
    # but change the tokenlist file to generate an error
    def test_restore_changed_tokenlist(self):
        with self.assertRaises(SystemExit) as cm:
            btcrecover.parse_arguments(AUTOSAVE_ARGS,
                autosave  = StringIO.StringIO(self.__class__.autosave_file.getvalue()),
                tokenlist = cStringIO.StringIO(AUTOSAVE_TOKENLIST + "four"),
                privkey   = AUTOSAVE_PRIVKEY)
        self.assertIn("can't restore previous session: the tokenlist file has changed", cm.exception.code)

    # Using --restore, restore (a copy of) the autosave data created by test_autosave(),
    # but change the privkey data to generate an error
    def test_restore_changed_privkey(self):
        with self.assertRaises(SystemExit) as cm:
            btcrecover.parse_arguments(("--restore __funccall").split(),
                restore   = StringIO.StringIO(self.__class__.autosave_file.getvalue()),
                tokenlist = cStringIO.StringIO(AUTOSAVE_TOKENLIST),
                privkey   = "bWI6ACkebfNQTLk75CfI5X3svX6AC7NFeGsgUxKNFg==")  # has a valid CRC
        self.assertIn("can't restore previous session: the encrypted key entered is not the same", cm.exception.code)

    # Using --restore, restore the autosave data created by test_autosave(),
    # but remove the last byte from slot 1 to make it invalid
    def test_restore_truncated(self):
        autosave_file = self.__class__.autosave_file
        autosave_file.seek(-1, os.SEEK_END)
        autosave_file.truncate()
        self.run_restore_parse_arguments(autosave_file)
        #
        # Slot 1 had the final save, but since it is invalid, the loader should fall
        # back to slot 0 with the initial save, so the passwords should be tried again.
        self.assertIn("Password search exhausted", btcrecover.main())
        #
        # Because slot 1 was invalid, it is the first slot overwritten. Load it, and
        # verify it was written to before any passwords were tested
        autosave_file.seek(SAVESLOT_SIZE)
        savestate = cPickle.load(autosave_file)
        self.assertEqual(savestate.get("skip"), 0)
        #
        # Load slot 0 (the second slot overwritten), and verify it was written to
        # after all passwords were tested
        autosave_file.seek(0)
        savestate = cPickle.load(autosave_file)
        self.assertEqual(savestate.get("skip"), 9)


is_armory_loadable = None
def can_load_armory():
    global is_armory_loadable
    # Don't call the load function more than once
    # (calling more than once on success is OK though)
    if is_armory_loadable is None:
        try:
            btcrecover.load_armory_library()
            is_armory_loadable = True
        except ImportError:
            is_armory_loadable = False
    return is_armory_loadable

class Test07WalletDecryption(unittest.TestCase):

    # Checks a test wallet against the known password, and ensures
    # that the library doesn't make any changes to the wallet file
    def wallet_tester(self, wallet_basename, force_purepython = False):
        assert os.path.basename(wallet_basename) == wallet_basename
        wallet_filename = os.path.join(wallet_dir, wallet_basename)

        temp_dir = tempfile.mkdtemp("-test-btcr")
        temp_wallet_filename = os.path.join(temp_dir, wallet_basename)
        shutil.copyfile(wallet_filename, temp_wallet_filename)

        btcrecover.load_wallet(temp_wallet_filename)
        if force_purepython: btcrecover.load_aes256_library(True)

        self.assertEqual(btcrecover.return_verified_password_or_false(
            ["btcr-wrong-password-1", "btcr-wrong-password-2"]), (False, 2))
        self.assertEqual(btcrecover.return_verified_password_or_false(
            ["btcr-wrong-password-3", "btcr-test-password", "btcr-wrong-password-4"]), ("btcr-test-password", 2))

        btcrecover.unload_wallet()
        self.assertTrue(filecmp.cmp(wallet_filename, temp_wallet_filename, False))  # False == always compare file contents
        shutil.rmtree(temp_dir)

    @unittest.skipUnless(can_load_armory(), "requires Armory")
    def test_armory(self):
        self.wallet_tester("armory-wallet.wallet")

    @unittest.skipUnless(btcrecover.load_aes256_library().__name__ == "Crypto", "requires PyCrypto")
    def test_bitcoincore(self):
        self.wallet_tester("bitcoincore-wallet.dat")

    @unittest.skipUnless(btcrecover.load_aes256_library().__name__ == "Crypto", "requires PyCrypto")
    def test_electrum(self):
        self.wallet_tester("electrum-wallet")

    @unittest.skipUnless(btcrecover.load_aes256_library().__name__ == "Crypto", "requires PyCrypto")
    def test_multibit(self):
        self.wallet_tester("multibit-wallet.key")

    def test_bitcoincore_pp(self):
        self.wallet_tester("bitcoincore-wallet.dat", True)

    def test_electrum_pp(self):
        self.wallet_tester("electrum-wallet", True)

    def test_multibit_pp(self):
        self.wallet_tester("multibit-wallet.key", True)

    def test_invalid_wallet(self):
        with self.assertRaises(SystemExit) as cm:
            btcrecover.load_wallet(__file__)
        self.assertIn("unrecognized wallet format", cm.exception.code)


class Test08KeyDecryption(unittest.TestCase):

    def key_tester(self, key_crc_base64, force_purepython = False):
        btcrecover.load_from_base64_key(key_crc_base64)
        if force_purepython: btcrecover.load_aes256_library(True)

        self.assertEqual(btcrecover.return_verified_password_or_false(
            ["btcr-wrong-password-1", "btcr-wrong-password-2"]), (False, 2))
        self.assertEqual(btcrecover.return_verified_password_or_false(
            ["btcr-wrong-password-3", "btcr-test-password", "btcr-wrong-password-4"]), ("btcr-test-password", 2))

    @unittest.skipUnless(can_load_armory(), "requires Armory")
    def test_armory(self):
        self.key_tester("YXI6r7mks1qvph4G+rRT7WlIptdr9qDqyFTfXNJ3ciuWJ12BgWX5Il+y28hLNr/u4Wl49hUi4JBeq6Jz9dVBX3vAJ6476FEAACAABAAAAGGwnwXRpPbBzC5lCOBVVWDu7mUJetBOBvzVAv0IbrboDXqA8A==")

    @unittest.skipUnless(btcrecover.load_aes256_library().__name__ == "Crypto", "requires PyCrypto")
    def test_bitcoincore(self):
        self.key_tester("YmM6Liw7m1jpszyXmbRHLoPBNuYkYSDEXjkNqmpXR25/vk9X2D9511+bTB22gP5ahGy4RZOv9WORecdECQEA9h79LQ==")

    @unittest.skipUnless(btcrecover.load_aes256_library().__name__ == "Crypto", "requires PyCrypto")
    def test_multibit(self):
        self.key_tester("bWI6oikebfNQTLk75CfI5X3svX6AC7NFeGsgTNXZfA==")

    def test_bitcoincore_pp(self):
        self.key_tester("YmM6Liw7m1jpszyXmbRHLoPBNuYkYSDEXjkNqmpXR25/vk9X2D9511+bTB22gP5ahGy4RZOv9WORecdECQEA9h79LQ==", True)

    def test_multibit_pp(self):
        self.key_tester("bWI6oikebfNQTLk75CfI5X3svX6AC7NFeGsgTNXZfA==", True)

    @unittest.skipUnless(btcrecover.get_opencl_devices(), "requires OpenCL and a compatible device")
    def test_bitcoincore_cl(self):
        btcrecover.load_from_base64_key("YmM6Liw7m1jpszyXmbRHLoPBNuYkYSDEXjkNqmpXR25/vk9X2D9511+bTB22gP5ahGy4RZOv9WORecdECQEA9h79LQ==")

        dev_names_tested = set()
        for dev in btcrecover.get_opencl_devices():
            if dev.name in dev_names_tested: continue
            dev_names_tested.add(dev.name)
            btcrecover.init_bitcoincore_opencl_kernel([dev], [4], [None], 200)

            self.assertEqual(btcrecover.return_verified_password_or_false(
                ["btcr-wrong-password-1", "btcr-wrong-password-2"]), (False, 2))
            self.assertEqual(btcrecover.return_verified_password_or_false(
                ["btcr-wrong-password-3", "btcr-test-password", "btcr-wrong-password-4"]), ("btcr-test-password", 2))

    @unittest.skipUnless(btcrecover.get_opencl_devices(), "requires OpenCL and a compatible device")
    @unittest.skipIf(sys.platform == "win32", "windows kills and restarts drivers which take too long")
    def test_bitcoincore_cl_no_interrupts(self):
        btcrecover.load_from_base64_key("YmM6Liw7m1jpszyXmbRHLoPBNuYkYSDEXjkNqmpXR25/vk9X2D9511+bTB22gP5ahGy4RZOv9WORecdECQEA9h79LQ==")

        dev_names_tested = set()
        for dev in btcrecover.get_opencl_devices():
            if dev.name in dev_names_tested: continue
            dev_names_tested.add(dev.name)
            btcrecover.init_bitcoincore_opencl_kernel([dev], [4], [None], 1)

            self.assertEqual(btcrecover.return_verified_password_or_false(
                ["btcr-wrong-password-1", "btcr-wrong-password-2"]), (False, 2))
            self.assertEqual(btcrecover.return_verified_password_or_false(
                ["btcr-wrong-password-3", "btcr-test-password", "btcr-wrong-password-4"]), ("btcr-test-password", 2))

    @unittest.skipUnless(btcrecover.get_opencl_devices(), "requires OpenCL and a compatible device")
    def test_bitcoincore_cl_sli(self):
        devices_by_name = dict()
        for dev in btcrecover.get_opencl_devices():
            if dev.name in devices_by_name: break
            else: devices_by_name[dev.name] = dev
        else:
            self.skipTest("requires two identical OpenCL devices")

        btcrecover.load_from_base64_key("YmM6Liw7m1jpszyXmbRHLoPBNuYkYSDEXjkNqmpXR25/vk9X2D9511+bTB22gP5ahGy4RZOv9WORecdECQEA9h79LQ==")
        btcrecover.init_bitcoincore_opencl_kernel([devices_by_name[dev.name], dev], [2, 2], [None, None], 200)

        self.assertEqual(btcrecover.return_verified_password_or_false(
            ["btcr-wrong-password-1", "btcr-wrong-password-2", "btcr-wrong-password-3", "btcr-wrong-password-4"]), (False, 4))
        self.assertEqual(btcrecover.return_verified_password_or_false(
            ["btcr-wrong-password-5", "btcr-test-password", "btcr-wrong-password-6"]), ("btcr-test-password", 2))
        self.assertEqual(btcrecover.return_verified_password_or_false(
            ["btcr-wrong-password-5", "btcr-wrong-password-6", "btcr-test-password"]), ("btcr-test-password", 3))

    def test_invalid_crc(self):
        with self.assertRaises(SystemExit) as cm:
            self.key_tester("aWI6oikebfNQTLk75CfI5X3svX6AC7NFeGsgTNXZfA==")
        self.assertIn("encrypted key data is corrupted (failed CRC check)", cm.exception.code)


E2E_ARGS = "--tokenlist __funccall --privkey --autosave __funccall --typos 3 --typos-case --typos-repeat --typos-swap --no-progress".split()
E2E_TOKENLIST = "+ ^%0,1[b-c]tcr--  \n  + ^,$%0,1<Test-  \n  ^3$pas  \n  + wrod$"
E2E_PRIVKEY   = "bWI6oikebfNQTLk75CfI5X3svX6AC7NFeGsgTNXZfA=="
class Test09EndToEnd(unittest.TestCase):

    autosave_file = StringIONonClosing()

    # These test_ functions are in alphabetical order (the same order they're executed in)

    # A test of multiple features at once
    def test_end_to_end(self):
        autosave_file = self.__class__.autosave_file
        btcrecover.parse_arguments(E2E_ARGS,
            tokenlist = cStringIO.StringIO(E2E_TOKENLIST),
            privkey   = E2E_PRIVKEY,
            autosave  = autosave_file)
        self.assertIn("Password found: 'btcr-test-password'", btcrecover.main())

        # Verify the exact password number where it was found to ensure password ordering hasn't changed
        autosave_file.seek(SAVESLOT_SIZE)
        savestate = cPickle.load(autosave_file)
        self.assertEqual(savestate.get("skip"), 103764)

    # Repeat the test above using the same autosave file, starting off just before the password was found
    def test_restore(self):
        self.test_end_to_end()

        # Verify the password number where the search started
        autosave_file = self.__class__.autosave_file
        autosave_file.seek(0)
        savestate = cPickle.load(autosave_file)
        self.assertEqual(savestate.get("skip"), 103764)

    # Repeat the first test with a new autosave file, using --skip to start just after the password is located
    def test_skip(self):
        autosave_file = StringIONonClosing()
        btcrecover.parse_arguments(E2E_ARGS + ["--skip=103765"],
            tokenlist = cStringIO.StringIO(E2E_TOKENLIST),
            privkey   = E2E_PRIVKEY,
            autosave  = autosave_file)
        self.assertIn("Password search exhausted", btcrecover.main())

        # Verify the password number where the search started
        autosave_file.seek(0)
        savestate = cPickle.load(autosave_file)
        self.assertEqual(savestate.get("skip"), 103765)

        # Verify the total count of passwords
        autosave_file.seek(SAVESLOT_SIZE)
        savestate = cPickle.load(autosave_file)
        self.assertEqual(savestate.get("skip"), 139655)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--no-buffer", action="store_true")
    args, unittest_args = parser.parse_known_args()
    sys.argv[1:] = unittest_args

    unittest.main(buffer = not args.no_buffer)
