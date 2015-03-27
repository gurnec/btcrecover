#!/usr/bin/python
# -*- coding: utf-8 -*-

# test-seedrecover.py -- unit tests for seedrecover.py
# Copyright (C) 2015 Christopher Gurnee
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

# If you find this program helpful, please consider a small
# donation to the developer at the following Bitcoin address:
#
#           17LGpN2z62zp7RS825jXwYtE7zZ19Mxxu8
#
#                      Thank You!

# (all futures as of 2.6 and 2.7 except unicode_literals)
from __future__ import print_function, absolute_import, division, \
                       generators, nested_scopes, with_statement

import warnings
# Convert warnings to errors:
warnings.simplefilter("error")

import seedrecover, unittest, os, tempfile, shutil, filecmp

wallet_dir = os.path.join(os.path.dirname(__file__), "test-wallets")


class TestRecoveryFromWallet(unittest.TestCase):

    # Checks a test wallet against the known password, and ensures
    # that the library doesn't make any changes to the wallet file
    def wallet_tester(self, wallet_basename, correct_mnemonic):
        assert os.path.basename(wallet_basename) == wallet_basename
        wallet_filename = os.path.join(wallet_dir, wallet_basename)

        temp_dir = tempfile.mkdtemp("-test-btcr")
        temp_wallet_filename = os.path.join(temp_dir, wallet_basename)
        shutil.copyfile(wallet_filename, temp_wallet_filename)

        wallet = seedrecover.btcr.load_wallet(wallet_filename)

        # Convert the mnemonic string into a mnemonic_ids_guess
        wallet.config_mnemonic(correct_mnemonic)
        correct_mnemonic = seedrecover.mnemonic_ids_guess

        # Creates wrong mnemonic id guesses
        wrong_mnemonic_iter = wallet.performance_iterator()

        self.assertEqual(wallet.return_verified_password_or_false(
            (wrong_mnemonic_iter.next(), wrong_mnemonic_iter.next())), (False, 2))
        self.assertEqual(wallet.return_verified_password_or_false(
            (wrong_mnemonic_iter.next(), correct_mnemonic, wrong_mnemonic_iter.next())), (correct_mnemonic, 2))

        del wallet
        self.assertTrue(filecmp.cmp(wallet_filename, temp_wallet_filename, False))  # False == always compare file contents
        shutil.rmtree(temp_dir)

    def test_electrum1(self):
        self.wallet_tester("electrum-wallet", "straight subject wild ask clean possible age hurt squeeze cost stuck softly")

    def test_electrum2(self):
        self.wallet_tester("electrum2-wallet", "eagle pair eager human cage forget pony fall robot vague later bright acid")

    def test_electrum2_upgradedfrom_electrum1(self):
        self.wallet_tester("electrum1-upgradedto-electrum2-wallet", "straight subject wild ask clean possible age hurt squeeze cost stuck softly")


class TestRecoveryFromMPK(unittest.TestCase):

    def mpk_tester(self, wallet_type, the_mpk, correct_mnemonic):

        wallet = wallet_type.create_from_params(mpk=the_mpk)

        # Convert the mnemonic string into a mnemonic_ids_guess
        wallet.config_mnemonic(correct_mnemonic)
        correct_mnemonic = seedrecover.mnemonic_ids_guess

        # Creates wrong mnemonic id guesses
        wrong_mnemonic_iter = wallet.performance_iterator()

        self.assertEqual(wallet.return_verified_password_or_false(
            (wrong_mnemonic_iter.next(), wrong_mnemonic_iter.next())), (False, 2))
        self.assertEqual(wallet.return_verified_password_or_false(
            (wrong_mnemonic_iter.next(), correct_mnemonic, wrong_mnemonic_iter.next())), (correct_mnemonic, 2))

    def test_electrum1(self):
        self.mpk_tester(seedrecover.WalletElectrum1,
            "c79b02697b32d9af63f7d2bd882f4c8198d04f0e4dfc5c232ca0c18a87ccc64ae8829404fdc48eec7111b99bda72a7196f9eb8eb42e92514a758f5122b6b5fea",
            "straight subject wild ask clean possible age hurt squeeze cost stuck softly")

    def test_electrum2(self):
        self.mpk_tester(seedrecover.WalletElectrum2,
            "xpub661MyMwAqRbcGsUXkGBkytQkYZ6M16bFWwTocQDdPSm6eJ1wUsxG5qty1kTCUq7EztwMscUstHVo1XCJMxWyLn4PP1asLjt4gPt3HkA81qe",
            "eagle pair eager human cage forget pony fall robot vague later bright acid")

    def test_electrum2_ja(self):
        self.mpk_tester(seedrecover.WalletElectrum2,
            "xpub661MyMwAqRbcFAyy6MaWCK5uGHhgvMZNaFbKy1TbSrcEm8oCgD3N2AfzPC8ndmdvcQbY8EbU414X4xNrs9dcNgcntShiBFJYJ6HJy7zKnQV",
            u"すんぽう うけつけ ぬいくぎ きどう ごはん たかね いてざ よしゅう なにもの われる たんき さとる あじわう")

    def test_bitcoinj(self):
        # an xpub at path m/0', as Bitcoin Wallet for Android would export
        self.mpk_tester(seedrecover.WalletBitcoinj,
            "xpub67tjk7ug7iNivs1f1pmDswDDbk6kRCe4U1AXSiYLbtp6a2GaodSUovt3kNrDJ2q18TBX65aJZ7VqRBpnVJsaVQaBY2SANYw6kgZf4QLCpPu",
            "laundry foil reform disagree cotton hope loud mix wheel snow real board")

    def test_bip44(self):
        # an xpub at path m/44'/0'/0', as Mycelium for Android would export
        self.mpk_tester(seedrecover.WalletBIP39,
            "xpub6BgCDhMefYxRS1gbVbxyokYzQji65v1eGJXGEiGdoobvFBShcNeJt97zoJBkNtbASLyTPYXJHRvkb3ahxaVVGEtC1AD4LyuBXULZcfCjBZx",
            "certain come keen collect slab gauge photo inside mechanic deny leader drop")

    def test_bip44_ja(self):
        # an xpub at path m/44'/0'/0'
        self.mpk_tester(seedrecover.WalletBIP39,
            "xpub6BfYc7HCQuKNxRMfmUhtkJ8HQ5A4t4zTy8cAQWjD7x5SZAdUD2QM2WoymmGfAD84mgbXbxyWiR922dyRtZUK2JPtBr8YLTzcQod3orvGB3k",
            u"あんまり　おんがく　いとこ　ひくい　こくはく　あらゆる　てあし　げどく　はしる　げどく　そぼろ　はみがき")


class TestRecoveryFromAddress(unittest.TestCase):

    def address_tester(self, wallet_type, the_address, the_address_limit, correct_mnemonic):

        wallet = wallet_type.create_from_params(address=the_address, address_limit=the_address_limit)

        # Convert the mnemonic string into a mnemonic_ids_guess
        wallet.config_mnemonic(correct_mnemonic)
        correct_mnemonic_ids = seedrecover.mnemonic_ids_guess

        # Creates wrong mnemonic id guesses
        wrong_mnemonic_iter = wallet.performance_iterator()

        self.assertEqual(wallet.return_verified_password_or_false(
            (wrong_mnemonic_iter.next(), wrong_mnemonic_iter.next())), (False, 2))
        self.assertEqual(wallet.return_verified_password_or_false(
            (wrong_mnemonic_iter.next(), correct_mnemonic_ids, wrong_mnemonic_iter.next())), (correct_mnemonic_ids, 2))

        # Make sure the address_limit is respected (note the "the_address_limit-1" below)
        wallet = wallet_type.create_from_params(address=the_address, address_limit=the_address_limit-1)
        wallet.config_mnemonic(correct_mnemonic)
        self.assertEqual(wallet.return_verified_password_or_false(
            (correct_mnemonic_ids,)), (False, 1))

    def test_electrum1(self):
        self.address_tester(seedrecover.WalletElectrum1, "12zAz6pAB6LhzGSZFCc6g9uBSWzwESEsPT", 3,
            "straight subject wild ask clean possible age hurt squeeze cost stuck softly")

    def test_electrum2(self):
        self.address_tester(seedrecover.WalletElectrum2, "14dpd9nayyoyCTNki5UUsm1KnAZ1x7o83E", 5,
            "eagle pair eager human cage forget pony fall robot vague later bright acid")

    def test_bitcoinj(self):
        self.address_tester(seedrecover.WalletBitcoinj, "17Czu38CcLwWr8jFZrDJBHWiEDd2QWhPSU", 4,
            "skin join dog sponsor camera puppy ritual diagram arrow poverty boy elbow")

    def test_bip44(self):
        self.address_tester(seedrecover.WalletBIP39, "1AiAYaVJ7SCkDeNqgFz7UDecycgzb6LoT3", 2,
            "certain come keen collect slab gauge photo inside mechanic deny leader drop")


if __name__ == b'__main__':

    import argparse, sys, atexit

    # Add two new arguments to those already provided by unittest.main()
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--no-buffer", action="store_true")
    parser.add_argument("--no-pause",  action="store_true")
    args, unittest_args = parser.parse_known_args()
    sys.argv[1:] = unittest_args

    # By default, pause before exiting
    if not args.no_pause:
        atexit.register(lambda: raw_input("\nPress Enter to exit ..."))

    unittest.main(buffer = not args.no_buffer)
