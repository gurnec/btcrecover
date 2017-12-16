#!/usr/bin/env python
# -*- coding: utf-8 -*-

# test_seeds.py -- unit tests for seedrecover.py
# Copyright (C) 2014-2017 Christopher Gurnee
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

# (all optional futures for 2.7 except unicode_literals)
from __future__ import print_function, absolute_import, division

import warnings, unittest, os, tempfile, shutil, filecmp, sys, hashlib, random, mmap, pickle
if __name__ == b'__main__':
    sys.path.append(os.path.join(os.path.dirname(__file__), "..", ".."))
from btcrecover import btcrseed
from btcrecover.addressset import AddressSet

wallet_dir = os.path.join(os.path.dirname(__file__), "test-wallets")


def setUpModule():
    global orig_warnings
    orig_warnings = warnings.catch_warnings()
    orig_warnings.__enter__()  # save the current warnings settings (it's a context manager)
    # Convert warnings to errors:
    warnings.simplefilter("error")

def tearDownModule():
    orig_warnings.__exit__(None, None, None)  # restore the original warnings settings


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

    def test_bip44_firstfour(self):
        # an xpub at path m/44'/0'/0', as Mycelium for Android would export
        self.mpk_tester(btcrseed.WalletBIP39,
            "xpub6BgCDhMefYxRS1gbVbxyokYzQji65v1eGJXGEiGdoobvFBShcNeJt97zoJBkNtbASLyTPYXJHRvkb3ahxaVVGEtC1AD4LyuBXULZcfCjBZx",
            "cert come keen coll slab gaug phot insi mech deny lead drop")

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


is_sha3_loadable = None
def can_load_sha3():
    global is_sha3_loadable
    if is_sha3_loadable is None:
        try:
            import sha3
            is_sha3_loadable = True
        except ImportError:
            is_sha3_loadable = False
    return is_sha3_loadable


class TestRecoveryFromAddress(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        try:
            hashlib.new(b"ripemd160")
        except ValueError:
            raise unittest.SkipTest("requires that hashlib implements RIPEMD-160")

    def address_tester(self, wallet_type, the_address, the_address_limit, correct_mnemonic, **kwds):
        assert the_address_limit > 1

        wallet = wallet_type.create_from_params(addresses=[the_address], address_limit=the_address_limit)

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
        wallet = wallet_type.create_from_params(addresses=[the_address], address_limit=the_address_limit-1)
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

    @unittest.skipUnless(can_load_sha3(), "requires pysha3")
    def test_ethereum(self):
        self.address_tester(btcrseed.WalletEthereum, "0x9544a5BD7D9AACDc0A12c360C1ec6182C84bab11", 3,
            "cable top mango offer mule air lounge refuse stove text cattle opera")

    # tests for a bug affecting certain seeds/wallets in v0.7.1
    @unittest.skipUnless(can_load_sha3(), "requires pysha3")
    def test_padding_bug(self):
        self.address_tester(btcrseed.WalletEthereum, "0xaeaa91ba7235dc2d90e28875d3e466aaa27e076d", 2,
            "appear section card oak mercy output person grab rotate sort where rural")


class TestAddressSet(unittest.TestCase):
    HASH_BYTES     = 1
    TABLE_LEN      = 2 ** (8*HASH_BYTES)
    BYTES_PER_ADDR = AddressSet(1)._bytes_per_addr

    def test_add(self):
        aset = AddressSet(self.TABLE_LEN)
        addr = "".join(chr(b) for b in xrange(20))
        self.assertNotIn(addr, aset)
        aset.add(addr)
        self.assertIn   (addr, aset)
        self.assertEqual(len(aset), 1)

    def collision_tester(self, aset, addr1, addr2):
        aset.add(addr1)
        self.assertIn   (addr1, aset)
        self.assertNotIn(addr2, aset)
        self.assertEqual(len(aset), 1)
        aset.add(addr2)
        self.assertIn   (addr1, aset)
        self.assertIn   (addr2, aset)
        self.assertEqual(len(aset), 2)
        return aset
    #
    def test_collision(self):
        aset  = AddressSet(self.TABLE_LEN)
        # the last HASH_BYTES (1) bytes are the "hash", and only the next BYTES_PER_ADDR (8) rightmost bytes are stored
        addr1 = "".join(chr(b) for b in xrange(20))
        addr2 = addr1.replace(chr(20 - self.HASH_BYTES - self.BYTES_PER_ADDR), "\0")  # the leftmost byte that's stored
        self.collision_tester(aset, addr1, addr2)
    #
    def test_collision_fail(self):
        aset  = AddressSet(self.TABLE_LEN)
        # the last 1 (HASH_BYTES) bytes are the "hash", and only the next 8 (BYTES_PER_ADDR) rightmost bytes are stored
        addr1 = "".join(chr(b) for b in xrange(20))
        addr2 = addr1.replace(chr(20 - self.HASH_BYTES - self.BYTES_PER_ADDR - 1), "\0")  # the rightmost byte not stored
        self.assertRaises(unittest.TestCase.failureException, self.collision_tester, aset, addr1, addr2)
        self.assertEqual(len(aset), 1)

    def test_null(self):
        aset = AddressSet(self.TABLE_LEN)
        addr = 20 * "\0"
        aset.add(addr)
        self.assertNotIn(addr, aset)
        self.assertEqual(len(aset), 0)

    # very unlikely to fail; if it does, there's probably a significant problem
    def test_false_positives(self):
        aset = AddressSet(131072, bytes_per_addr=5)  # reduce bytes_per_addr to increase failure probability
        rand_byte_count = aset._hash_bytes + aset._bytes_per_addr
        nonrand_prefix  = (20 - rand_byte_count) * "\0"
        for i in xrange(aset._max_len):
            aset.add(nonrand_prefix + "".join(chr(random.randrange(256)) for i in xrange(rand_byte_count)))
        for i in xrange(524288):
            self.assertNotIn(
                nonrand_prefix + "".join(chr(random.randrange(256)) for i in xrange(rand_byte_count)),
                aset)

    def test_file(self):
        aset = AddressSet(self.TABLE_LEN)
        addr = "".join(chr(b) for b in xrange(20))
        aset.add(addr)
        dbfile = tempfile.TemporaryFile()
        aset.tofile(dbfile)
        dbfile.seek(0)
        aset = AddressSet.fromfile(dbfile)
        self.assertTrue(dbfile.closed)  # should be closed by AddressSet in read-only mode
        self.assertIn(addr, aset)
        self.assertEqual(len(aset), 1)

    def test_file_update(self):
        aset   = AddressSet(self.TABLE_LEN)
        dbfile = tempfile.NamedTemporaryFile(delete=False)
        try:
            aset.tofile(dbfile)
            dbfile.seek(0)
            aset = AddressSet.fromfile(dbfile, mmap_access=mmap.ACCESS_WRITE)
            addr = "".join(chr(b) for b in xrange(20))
            aset.add(addr)
            aset.close()
            self.assertTrue(dbfile.closed)
            dbfile = open(dbfile.name, "rb")
            aset = AddressSet.fromfile(dbfile)
            self.assertIn(addr, aset)
            self.assertEqual(len(aset), 1)
        finally:
            aset.close()
            dbfile.close()
            os.remove(dbfile.name)

    def test_pickle_mmap(self):
        aset = AddressSet(self.TABLE_LEN)
        addr = "".join(chr(b) for b in xrange(20))
        aset.add(addr)
        dbfile = tempfile.NamedTemporaryFile(delete=False)
        try:
            aset.tofile(dbfile)
            dbfile.seek(0)
            aset = AddressSet.fromfile(dbfile)  # now it's an mmap
            pickled = pickle.dumps(aset, protocol=pickle.HIGHEST_PROTOCOL)
            aset.close()  # also closes the file
            aset = pickle.loads(pickled)
            self.assertIn(addr, aset)
            self.assertEqual(len(aset), 1)
        finally:
            aset.close()
            dbfile.close()
            os.remove(dbfile.name)


class TestRecoveryFromAddressDB(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if not os.path.isfile(btcrseed.ADDRESSDB_DEF_FILENAME):
            raise unittest.SkipTest("requires '"+btcrseed.ADDRESSDB_DEF_FILENAME+"' file in the current directory")

    def addressdb_tester(self, wallet_type, the_address_limit, correct_mnemonic, **kwds):
        assert the_address_limit > 1

        addressdb = AddressSet.fromfile(open(btcrseed.ADDRESSDB_DEF_FILENAME, "rb"), preload=False)
        wallet = wallet_type.create_from_params(hash160s=addressdb, address_limit=the_address_limit)

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
        wallet = wallet_type.create_from_params(hash160s=addressdb, address_limit=the_address_limit-1)
        wallet.config_mnemonic(correct_mnemonic, **kwds)
        self.assertEqual(wallet.return_verified_password_or_false(
            (correct_mnemonic_ids,)), (False, 1))

    def test_bip44(self):
        # 1D5noXUg7za4W3zjhgCmn1cFewqRrXSM9B is in block 476446
        self.addressdb_tester(btcrseed.WalletBIP39, 5,
            "certain come keen collect slab gauge photo inside mechanic deny leader drop")


class TestSeedTypos(unittest.TestCase):
    XPUB = "xpub6BgCDhMefYxRS1gbVbxyokYzQji65v1eGJXGEiGdoobvFBShcNeJt97zoJBkNtbASLyTPYXJHRvkb3ahxaVVGEtC1AD4LyuBXULZcfCjBZx"

    def seed_tester(self, the_mpk, correct_mnemonic, mnemonic_guess, typos = None, big_typos = 0):
        correct_mnemonic = correct_mnemonic.split()
        assert mnemonic_guess.split() != correct_mnemonic
        assert typos or big_typos
        btcrseed.loaded_wallet = btcrseed.WalletBIP39.create_from_params(mpk=the_mpk)
        btcrseed.loaded_wallet.config_mnemonic(mnemonic_guess)
        self.assertEqual(
            btcrseed.run_btcrecover(typos or big_typos, big_typos, extra_args="--threads 1".split()),
            tuple(correct_mnemonic))

    def test_delete(self):
        self.seed_tester(self.XPUB,
            "certain      come keen collect slab gauge photo inside mechanic deny leader drop",  # correct
            "certain come come keen collect slab gauge photo inside mechanic deny leader drop",  # guess
            typos=1)

    def test_replacewrong(self):
        self.seed_tester(self.XPUB,
            "certain come keen collect slab gauge photo inside mechanic deny leader drop",  # correct
            "certain X    keen collect slab gauge photo inside mechanic deny leader drop",  # guess
            big_typos=1)

    def test_insert(self):
        self.seed_tester(self.XPUB,
            "certain come keen collect slab gauge photo inside mechanic deny leader drop",  # correct
            "        come keen collect slab gauge photo inside mechanic deny leader drop",  # guess
            big_typos=1)

    def test_swap(self):
        self.seed_tester(self.XPUB,
            "certain come keen collect slab gauge photo inside mechanic deny leader drop",  # correct
            "certain keen come collect slab gauge photo inside mechanic deny leader drop",  # guess
            typos=1)

    def test_replace(self):
        self.seed_tester(self.XPUB,
            "certain  come keen collect slab gauge photo inside mechanic deny leader drop",  # correct
            "disagree come keen collect slab gauge photo inside mechanic deny leader drop",  # guess
            big_typos=1)

    def test_replaceclose(self):
        self.seed_tester(self.XPUB,
            "certain come   keen collect slab gauge photo inside mechanic deny leader drop",  # correct
            "certain become keen collect slab gauge photo inside mechanic deny leader drop",  # guess
            typos=1)

    def test_replaceclose_firstfour(self):
        self.seed_tester(self.XPUB,
            "certain come keen collect slab gauge photo inside mechanic deny leader drop",  # correct
            "cere    come keen coll    slab gaug  phot  insi   mech     deny lead   drop",  # guess
            # "cere" is close to "cert" in the en-firstfour language, even though "cereal" is not close to "certain"
            typos=1)


# All seed tests except TestAddressSet.test_false_positives are quick
class QuickTests(unittest.TestSuite):
    def __init__(self):
        super(QuickTests, self).__init__()
        for suite in unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__]):
            if isinstance(suite._tests[0], TestAddressSet):
                for test_num in xrange(len(suite._tests)):
                    if suite._tests[test_num]._testMethodName == "test_false_positives":
                        del suite._tests[test_num]
                        break
            self.addTests(suite)


if __name__ == b'__main__':

    import argparse

    # Add one new argument to those already provided by unittest.main()
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--no-buffer", action="store_true")
    args, unittest_args = parser.parse_known_args()
    sys.argv[1:] = unittest_args

    unittest.main(buffer = not args.no_buffer)
