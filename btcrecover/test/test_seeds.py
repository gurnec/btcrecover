#!/usr/bin/python
# -*- coding: utf-8 -*-

# test_seeds.py -- unit tests for seedrecover.py
# Copyright (C) 2014-2016 Christopher Gurnee
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

# (all optional futures for 2.7 except unicode_literals)
from __future__ import print_function, absolute_import, division

import warnings
# Convert warnings to errors:
warnings.simplefilter("error")
# except these from Armory:
warnings.filterwarnings("ignore", r"the sha module is deprecated; use the hashlib module instead", DeprecationWarning)
warnings.filterwarnings("ignore", r"import \* only allowed at module level", SyntaxWarning)

from .. import btcrseed
import unittest, os, tempfile, shutil, filecmp, sys

wallet_dir = os.path.join(os.path.dirname(__file__), "test-wallets")


class TestRecoveryFromWallet(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        btcrseed.register_autodetecting_wallets()

    # Checks a test wallet against the known mnemonic, and ensures
    # that the library doesn't make any changes to the wallet file
    def wallet_tester(self, wallet_basename, correct_mnemonic, **kwds):
        assert os.path.basename(wallet_basename) == wallet_basename
        wallet_filename = os.path.join(wallet_dir, wallet_basename)

        temp_dir = tempfile.mkdtemp("-test-btcr")
        try:
            temp_wallet_filename = os.path.join(temp_dir, wallet_basename)
            shutil.copyfile(wallet_filename, temp_wallet_filename)

            wallet = btcrseed.btcrpass.load_wallet(temp_wallet_filename)

            # Convert the mnemonic string into a mnemonic_ids_guess
            wallet.config_mnemonic(correct_mnemonic, **kwds)
            correct_mnemonic = btcrseed.mnemonic_ids_guess

            # Creates wrong mnemonic id guesses
            wrong_mnemonic_iter = wallet.performance_iterator()

            self.assertEqual(wallet.return_verified_password_or_false(
                (wrong_mnemonic_iter.next(), wrong_mnemonic_iter.next())), (False, 2))
            self.assertEqual(wallet.return_verified_password_or_false(
                (wrong_mnemonic_iter.next(), correct_mnemonic, wrong_mnemonic_iter.next())), (correct_mnemonic, 2))

            del wallet
            self.assertTrue(filecmp.cmp(wallet_filename, temp_wallet_filename, False))  # False == always compare file contents
        finally:
            shutil.rmtree(temp_dir)

    def test_electrum1(self):
        self.wallet_tester("electrum-wallet", "straight subject wild ask clean possible age hurt squeeze cost stuck softly")

    def test_electrum2(self):
        self.wallet_tester("electrum2-wallet", "eagle pair eager human cage forget pony fall robot vague later bright acid",
            expected_len=13)

    def test_electrum27(self):
        self.wallet_tester("electrum27-wallet", "spot deputy pencil nasty fire boss moral rubber bacon thumb thumb icon",
            expected_len=12)

    def test_electrum2_upgradedfrom_electrum1(self):
        self.wallet_tester("electrum1-upgradedto-electrum2-wallet", "straight subject wild ask clean possible age hurt squeeze cost stuck softly")

    def test_electrum27_upgradedfrom_electrum1(self):
        self.wallet_tester("electrum1-upgradedto-electrum27-wallet", "straight subject wild ask clean possible age hurt squeeze cost stuck softly")


class TestRecoveryFromMPK(unittest.TestCase):

    def mpk_tester(self, wallet_type, the_mpk, correct_mnemonic, **kwds):

        wallet = wallet_type.create_from_params(mpk=the_mpk)

        # Convert the mnemonic string into a mnemonic_ids_guess
        wallet.config_mnemonic(correct_mnemonic, **kwds)
        correct_mnemonic = btcrseed.mnemonic_ids_guess

        # Creates wrong mnemonic id guesses
        wrong_mnemonic_iter = wallet.performance_iterator()

        self.assertEqual(wallet.return_verified_password_or_false(
            (wrong_mnemonic_iter.next(), wrong_mnemonic_iter.next())), (False, 2))
        self.assertEqual(wallet.return_verified_password_or_false(
            (wrong_mnemonic_iter.next(), correct_mnemonic, wrong_mnemonic_iter.next())), (correct_mnemonic, 2))

    def test_electrum1(self):
        self.mpk_tester(btcrseed.WalletElectrum1,
            "c79b02697b32d9af63f7d2bd882f4c8198d04f0e4dfc5c232ca0c18a87ccc64ae8829404fdc48eec7111b99bda72a7196f9eb8eb42e92514a758f5122b6b5fea",
            "straight subject wild ask clean possible age hurt squeeze cost stuck softly")

    def test_electrum2(self):
        self.mpk_tester(btcrseed.WalletElectrum2,
            "xpub661MyMwAqRbcGsUXkGBkytQkYZ6M16bFWwTocQDdPSm6eJ1wUsxG5qty1kTCUq7EztwMscUstHVo1XCJMxWyLn4PP1asLjt4gPt3HkA81qe",
            "eagle pair eager human cage forget pony fall robot vague later bright acid",
            expected_len=13)

    def test_electrum27(self):
        self.mpk_tester(btcrseed.WalletElectrum2,
            "xpub661MyMwAqRbcGt6qtQ19Ttwvo5Dbf2cQdA2GMf9Xkjth8NqYXXordg3gLK1npATRm9Fr7d7fA5ziCwqEVMmzeRezofp8CEaru8pJ57zV8hN",
            "spot deputy pencil nasty fire boss moral rubber bacon thumb thumb icon",
            expected_len=12)

    def test_electrum2_ja(self):
        self.mpk_tester(btcrseed.WalletElectrum2,
            "xpub661MyMwAqRbcFAyy6MaWCK5uGHhgvMZNaFbKy1TbSrcEm8oCgD3N2AfzPC8ndmdvcQbY8EbU414X4xNrs9dcNgcntShiBFJYJ6HJy7zKnQV",
            u"すんぽう うけつけ ぬいくぎ きどう ごはん たかね いてざ よしゅう なにもの われる たんき さとる あじわう",
            expected_len=13)

    TEST_ELECTRUM2_PASS_XPUB = "xpub661MyMwAqRbcG4s8buUEpDeeBMZeXxnroY3i9jZJNQuDrWQaCyR5Mvk9pmRK5q5WrEKTwSuYwBiSjcp3ZkM2ujhngFQXxvrTyv2uFCryyii"
    def test_electrum2_pass(self):
        self.mpk_tester(btcrseed.WalletElectrum2,
            self.TEST_ELECTRUM2_PASS_XPUB,
            "eagle pair eager human cage forget pony fall robot vague later bright acid",
            expected_len=13, passphrase=u"btcr test password 测试密码")

    def test_electrum2_pass_normalize(self):
        p = u" btcr  TEST  ℙáⓢⓢᵂöṝⅆ  测试  密码 "
        assert p == u" btcr  TEST  \u2119\xe1\u24e2\u24e2\u1d42\xf6\u1e5d\u2146  \u6d4b\u8bd5  \u5bc6\u7801 "
        self.mpk_tester(btcrseed.WalletElectrum2,
            self.TEST_ELECTRUM2_PASS_XPUB,
            "eagle pair eager human cage forget pony fall robot vague later bright acid",
            expected_len=13, passphrase=p)

    def test_electrum2_pass_wide(self):
        p = u"𝔅tcr 𝔗est 𝔓assword 测试密码"
        assert p == u"\U0001d505tcr \U0001d517est \U0001d513assword \u6d4b\u8bd5\u5bc6\u7801"
        self.mpk_tester(btcrseed.WalletElectrum2,
            # for narrow Unicode builds, check that we reproduce the same Electrum 2.x bugs:
            "xpub661MyMwAqRbcGYwDPmhGppsmr2NxcoFNAzGy3qRcE9wrtQhF6tCjtitFnizWKHv684AfshexRAiByRFX3VHpugBcAMYpwQezeYroi53KEKM"
                if sys.maxunicode < 65536 else
            # for wide Unicode builds, there are no bugs:
            self.TEST_ELECTRUM2_PASS_XPUB,
            "eagle pair eager human cage forget pony fall robot vague later bright acid",
            expected_len=13, passphrase=p)

    def test_bitcoinj(self):
        # an xpub at path m/0', as Bitcoin Wallet for Android/BlackBerry would export
        self.mpk_tester(btcrseed.WalletBitcoinj,
            "xpub67tjk7ug7iNivs1f1pmDswDDbk6kRCe4U1AXSiYLbtp6a2GaodSUovt3kNrDJ2q18TBX65aJZ7VqRBpnVJsaVQaBY2SANYw6kgZf4QLCpPu",
            "laundry foil reform disagree cotton hope loud mix wheel snow real board")

    def test_bip44(self):
        # an xpub at path m/44'/0'/0', as Mycelium for Android would export
        self.mpk_tester(btcrseed.WalletBIP39,
            "xpub6BgCDhMefYxRS1gbVbxyokYzQji65v1eGJXGEiGdoobvFBShcNeJt97zoJBkNtbASLyTPYXJHRvkb3ahxaVVGEtC1AD4LyuBXULZcfCjBZx",
            "certain come keen collect slab gauge photo inside mechanic deny leader drop")

    def test_bip44_ja(self):
        # an xpub at path m/44'/0'/0'
        self.mpk_tester(btcrseed.WalletBIP39,
            "xpub6BfYc7HCQuKNxRMfmUhtkJ8HQ5A4t4zTy8cAQWjD7x5SZAdUD2QM2WoymmGfAD84mgbXbxyWiR922dyRtZUK2JPtBr8YLTzcQod3orvGB3k",
            u"あんまり　おんがく　いとこ　ひくい　こくはく　あらゆる　てあし　げどく　はしる　げどく　そぼろ　はみがき")

    def test_bip44_pass(self):
        # an xpub at path m/44'/0'/0', as Mycelium for Android would export
        self.mpk_tester(btcrseed.WalletBIP39,
            "xpub6D3uXJmdUg4xVnCUkNXJPCkk18gZAB8exGdQeb2rDwC5UJtraHHARSCc2Nz7rQ14godicjXiKxhUn39gbAw6Xb5eWb5srcbkhqPgAqoTMEY",
            "certain come keen collect slab gauge photo inside mechanic deny leader drop",
            passphrase=u"btcr-test-password")

    def test_bip44_pass_unicode(self):
        # an xpub at path m/44'/0'/0', as Mycelium for Android would export
        self.mpk_tester(btcrseed.WalletBIP39,
            "xpub6CZe1G1A1CaaSepbekLMSk1sBRNA9kHZzEQCedudHAQHHB21FW9fYpQWXBevrLVQfL8JFQVFWEw3aACdr6szksaGsLiHDKyRd1rPJ6ev5ig",
            "certain come keen collect slab gauge photo inside mechanic deny leader drop",
            passphrase=u"btcr-тест-пароль")


class TestRecoveryFromAddress(unittest.TestCase):

    def address_tester(self, wallet_type, the_address, the_address_limit, correct_mnemonic, **kwds):

        wallet = wallet_type.create_from_params(address=the_address, address_limit=the_address_limit)

        # Convert the mnemonic string into a mnemonic_ids_guess
        wallet.config_mnemonic(correct_mnemonic, **kwds)
        correct_mnemonic_ids = btcrseed.mnemonic_ids_guess

        # Creates wrong mnemonic id guesses
        wrong_mnemonic_iter = wallet.performance_iterator()

        self.assertEqual(wallet.return_verified_password_or_false(
            (wrong_mnemonic_iter.next(), wrong_mnemonic_iter.next())), (False, 2))
        self.assertEqual(wallet.return_verified_password_or_false(
            (wrong_mnemonic_iter.next(), correct_mnemonic_ids, wrong_mnemonic_iter.next())), (correct_mnemonic_ids, 2))

        # Make sure the address_limit is respected (note the "the_address_limit-1" below)
        wallet = wallet_type.create_from_params(address=the_address, address_limit=the_address_limit-1)
        wallet.config_mnemonic(correct_mnemonic, **kwds)
        self.assertEqual(wallet.return_verified_password_or_false(
            (correct_mnemonic_ids,)), (False, 1))

    def test_electrum1(self):
        self.address_tester(btcrseed.WalletElectrum1, "12zAz6pAB6LhzGSZFCc6g9uBSWzwESEsPT", 3,
            "straight subject wild ask clean possible age hurt squeeze cost stuck softly")

    def test_electrum2(self):
        self.address_tester(btcrseed.WalletElectrum2, "14dpd9nayyoyCTNki5UUsm1KnAZ1x7o83E", 5,
            "eagle pair eager human cage forget pony fall robot vague later bright acid",
            expected_len=13)

    def test_electrum27(self):
        self.address_tester(btcrseed.WalletElectrum2, "1HQrNUBEsEqwEaZZzMqqLqCHSVCGF7dTVS", 5,
            "spot deputy pencil nasty fire boss moral rubber bacon thumb thumb icon",
            expected_len=12)

    def test_bitcoinj(self):
        self.address_tester(btcrseed.WalletBitcoinj, "17Czu38CcLwWr8jFZrDJBHWiEDd2QWhPSU", 4,
            "skin join dog sponsor camera puppy ritual diagram arrow poverty boy elbow")

    def test_bip44(self):
        self.address_tester(btcrseed.WalletBIP39, "1AiAYaVJ7SCkDeNqgFz7UDecycgzb6LoT3", 2,
            "certain come keen collect slab gauge photo inside mechanic deny leader drop")


# All seed tests are quick
class QuickTests(unittest.TestSuite) :
    def __init__(self):
        super(QuickTests, self).__init__()
        self.addTests(unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__]))


if __name__ == b'__main__':

    import argparse

    # Add one new argument to those already provided by unittest.main()
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--no-buffer", action="store_true")
    args, unittest_args = parser.parse_known_args()
    sys.argv[1:] = unittest_args

    unittest.main(buffer = not args.no_buffer)
