# btcrseed.py -- btcrecover mnemonic sentence library
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

# TODO: finish pythonizing comments/documentation

# (all optional futures for 2.7 except unicode_literals)
from __future__ import print_function, absolute_import, division

__version__ = "0.7.3"

from . import btcrpass
from .addressset import AddressSet
import sys, os, io, base64, hashlib, hmac, difflib, coincurve, itertools, \
       unicodedata, collections, struct, glob, atexit, re, random, multiprocessing


# Order of the base point generator, from SEC 2
GENERATOR_ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141L

ADDRESSDB_DEF_FILENAME = "addresses.db"

def full_version():
    return "seedrecover {}, {}".format(
        __version__,
        btcrpass.full_version()
    )


################################### Utility Functions ###################################


def bytes_to_int(bytes_rep):
    """convert a string of bytes (in big-endian order) to a long integer

    :param bytes_rep: the raw bytes
    :type bytes_rep: str
    :return: the unsigned integer
    :rtype: long
    """
    return long(base64.b16encode(bytes_rep), 16)

def int_to_bytes(int_rep, min_length):
    """convert an unsigned integer to a string of bytes (in big-endian order)

    :param int_rep: a non-negative integer
    :type int_rep: long or int
    :param min_length: the minimum output length
    :type min_length: int
    :return: the raw bytes, zero-padded (at the beginning) if necessary
    :rtype: str
    """
    assert int_rep >= 0
    hex_rep = "{:X}".format(int_rep)
    if len(hex_rep) % 2 == 1:    # The hex decoder below requires
        hex_rep = "0" + hex_rep  # exactly 2 chars per byte.
    return base64.b16decode(hex_rep).rjust(min_length, "\0")


dec_digit_to_base58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
base58_digit_to_dec = { b58:dec for dec,b58 in enumerate(dec_digit_to_base58) }


def base58check_to_bytes(base58_rep, expected_size):
    """decode a base58check string to its raw bytes

    :param base58_rep: check-code appended base58-encoded string
    :type base58_rep: str
    :param expected_size: the expected number of decoded bytes (excluding the check code)
    :type expected_size: int
    :return: the base58-decoded bytes
    :rtype: str
    """
    base58_stripped = base58_rep.lstrip("1")

    int_rep = 0
    for base58_digit in base58_stripped:
        int_rep *= 58
        int_rep += base58_digit_to_dec[base58_digit]

    # Convert int to raw bytes
    all_bytes  = int_to_bytes(int_rep, expected_size + 4)

    zero_count = next(zeros for zeros,byte in enumerate(all_bytes) if byte != "\0")
    if len(base58_rep) - len(base58_stripped) != zero_count:
        raise ValueError("prepended zeros mismatch")

    if hashlib.sha256(hashlib.sha256(all_bytes[:-4]).digest()).digest()[:4] != all_bytes[-4:]:
        raise ValueError("base58 check code mismatch")

    return all_bytes[:-4]

def base58check_to_hash160(base58_rep):
    """convert from a base58check address to its hash160 form

    :param base58_rep: check-code appended base58-encoded address
    :type base58_rep: str
    :return: the hash of the pubkey/redeemScript, then the version byte
    :rtype: (str, str)
    """
    decoded_bytes = base58check_to_bytes(base58_rep, 1 + 20)
    return decoded_bytes[1:], decoded_bytes[0]

BIP32ExtendedKey = collections.namedtuple("BIP32ExtendedKey",
    "version depth fingerprint child_number chaincode key")
#
def base58check_to_bip32(base58_rep):
    """decode a bip32-serialized extended key from its base58check form

    :param base58_rep: check-code appended base58-encoded bip32 extended key
    :type base58_rep: str
    :return: a namedtuple containing: version depth fingerprint child_number chaincode key
    :rtype: BIP32ExtendedKey
    """
    decoded_bytes = base58check_to_bytes(base58_rep, 4 + 1 + 4 + 4 + 32 + 33)
    return BIP32ExtendedKey(decoded_bytes[0:4],  ord(decoded_bytes[ 4:5]), decoded_bytes[ 5:9],
        struct.unpack(">I", decoded_bytes[9:13])[0], decoded_bytes[13:45], decoded_bytes[45:])

def compress_pubkey(uncompressed_pubkey):
    """convert an uncompressed public key into a compressed public key

    :param uncompressed_pubkey: the uncompressed public key
    :type uncompressed_pubkey: str
    :return: the compressed public key
    :rtype: str
    """
    assert len(uncompressed_pubkey) == 65 and uncompressed_pubkey[0] == "\x04"
    return chr((ord(uncompressed_pubkey[-1]) & 1) + 2) + uncompressed_pubkey[1:33]


print = btcrpass.safe_print  # use btcrpass's print which never dies from printing Unicode


################################### Wallets ###################################

# A class decorator which adds a wallet class to a registered
# list that can later be selected by a user in GUI mode
selectable_wallet_classes = []
def register_selectable_wallet_class(description):
    def _register_selectable_wallet_class(cls):
        selectable_wallet_classes.append((cls, description))
        return cls
    return _register_selectable_wallet_class


# Loads a wordlist from a file into a list of Python unicodes. Note that the
# unicodes are normalized in NFC format, which is not what BIP39 requires (NFKD).
wordlists_dir = os.path.join(os.path.dirname(__file__), "wordlists")
def load_wordlist(name, lang):
    filename = os.path.join(wordlists_dir, "{}-{}.txt".format(name, lang))
    with io.open(filename, encoding="utf_8_sig") as wordlist_file:
        wordlist = []
        for word in wordlist_file:
            word = word.strip()
            if word and not word.startswith(u"#"):
                wordlist.append(unicodedata.normalize("NFC", word))
    return wordlist


def calc_passwords_per_second(checksum_ratio, kdf_overhead, scalar_multiplies):
    """estimate the number of mnemonics that can be checked per second (per CPU core)

    :param checksum_ratio: chances that a random mnemonic has the correct checksum [0.0 - 1.0]
    :type checksum_ratio: float
    :param kdf_overhead: overhead in seconds imposed by the kdf per each guess
    :type kdf_overhead: float
    :param scalar_multiplies: count of EC scalar multiplications required per each guess
    :type scalar_multiplies: int
    :return: estimated mnemonic check rate in hertz (per CPU core)
    :rtype: float
    """
    return 1.0 / (checksum_ratio * (kdf_overhead + scalar_multiplies*0.0001) + 0.00001)


############### WalletBase ###############

# Methods common to most wallets, but overridden by WalletEthereum
class WalletBase(object):

    def __init__(self, loading = False):
        assert loading, "use load_from_filename or create_from_params to create a " + self.__class__.__name__

    @staticmethod
    def _addresses_to_hash160s(addresses):
        hash160s = set()
        for address in addresses:
            hash160, version_byte = base58check_to_hash160(address)
            if ord(version_byte) != 0:
                raise ValueError("not a Bitcoin P2PKH address; version byte is {:#04x}".format(ord(version_byte)))
            hash160s.add(hash160)
        return hash160s

    @staticmethod
    def pubkey_to_hash160(uncompressed_pubkey):
        """convert from an uncompressed public key to its Bitcoin compressed-pubkey hash160 form

        :param uncompressed_pubkey: SEC 1 EllipticCurvePoint OctetString
        :type uncompressed_pubkey: str
        :return: ripemd160(sha256(compressed_pubkey))
        :rtype: str
        """
        return hashlib.new("ripemd160", hashlib.sha256(compress_pubkey(uncompressed_pubkey)).digest()).digest()


############### Electrum1 ###############

@register_selectable_wallet_class("Electrum 1.x (including wallets later upgraded to 2.x)")
class WalletElectrum1(WalletBase):

    _words = None
    @classmethod
    def _load_wordlist(cls):
        if not cls._words:
            cls._words      = tuple(map(str, load_wordlist("electrum1", "en")))  # also converts to ASCII
            cls._word_to_id = { word:id for id,word in enumerate(cls._words) }

    @property
    def word_ids(self):      return xrange(len(self._words))
    @classmethod
    def id_to_word(cls, id): return cls._words[id]

    @staticmethod
    def is_wallet_file(wallet_file):
        wallet_file.seek(0)
        # returns "maybe yes" or "definitely no"
        return None if wallet_file.read(2) == b"{'" else False

    def __init__(self, loading = False):
        super(WalletElectrum1, self).__init__(loading)
        self._master_pubkey        = None
        self._passwords_per_second = None

        self._load_wordlist()
        self._num_words = len(self._words)  # needs to be an instance variable so it can be pickled

    def passwords_per_seconds(self, seconds):
        if not self._passwords_per_second:
            self._passwords_per_second = \
                calc_passwords_per_second(1, 0.12, 1 if self._master_pubkey else self._addrs_to_generate + 1)
        return max(int(round(self._passwords_per_second * seconds)), 1)

    # Load an Electrum1 wallet file (the part of it we need, just the master public key)
    @classmethod
    def load_from_filename(cls, wallet_filename):
        from ast import literal_eval
        with open(wallet_filename) as wallet_file:
            wallet = literal_eval(wallet_file.read(btcrpass.MAX_WALLET_FILE_SIZE))  # up to 64M, typical size is a few k
        return cls._load_from_dict(wallet)

    @classmethod
    def _load_from_dict(cls, wallet):
        seed_version = wallet.get("seed_version")
        if seed_version is None:             raise ValueError("Unrecognized wallet format (Electrum1 seed_version not found)")
        if seed_version != 4:                raise NotImplementedError("Unsupported Electrum1 seed version " + seed_version)
        if not wallet.get("use_encryption"): raise ValueError("Electrum1 wallet is not encrypted")
        master_pubkey = base64.b16decode(wallet["master_public_key"], casefold=True)
        if len(master_pubkey) != 64:         raise ValueError("Electrum1 master public key is not 64 bytes long")
        self = cls(loading=True)
        self._master_pubkey = "\x04" + master_pubkey  # prepend the uncompressed tag
        return self

    # Creates a wallet instance from either an mpk, an addresses container and address_limit,
    # or a hash160s container. If none of these were supplied, prompts the user for each.
    @classmethod
    def create_from_params(cls, mpk = None, addresses = None, address_limit = None, hash160s = None, is_performance = False):
        self = cls(loading=True)

        # Process the mpk (master public key) argument
        if mpk:
            if len(mpk) != 128:
                raise ValueError("an Electrum 1.x master public key must be exactly 128 hex digits long")
            try:
                mpk = base64.b16decode(mpk, casefold=True)
                # (it's assigned to the self._master_pubkey later)
            except TypeError as e:
                raise ValueError(e)  # consistently raise ValueError for any bad inputs

        # Process the hash160s argument
        if hash160s:
            if mpk:
                print("warning: addressdb is ignored when an mpk is provided", file=sys.stderr)
                hash160s = None
            else:
                self._known_hash160s = hash160s

        # Process the addresses argument
        if addresses:
            if mpk or hash160s:
                print("warning: addresses are ignored when an mpk or addressdb is provided", file=sys.stderr)
                addresses = None
            else:
                self._known_hash160s = self._addresses_to_hash160s(addresses)

        # Process the address_limit argument
        if address_limit:
            if mpk:
                print("warning: address limit is ignored when an mpk is provided", file=sys.stderr)
                address_limit = None
            else:
                address_limit = int(address_limit)
                if address_limit <= 0:
                    raise ValueError("the address limit must be > 0")
                # (it's assigned to self._addrs_to_generate later)

        # If mpk, addresses, and hash160s arguments were all not provided, prompt the user for an mpk first
        if not mpk and not addresses and not hash160s:
            init_gui()
            while True:
                mpk = tkSimpleDialog.askstring("Electrum 1.x master public key",
                    "Please enter your master public key if you have it, or click Cancel to search by an address instead:",
                    initialvalue="c79b02697b32d9af63f7d2bd882f4c8198d04f0e4dfc5c232ca0c18a87ccc64ae8829404fdc48eec7111b99bda72a7196f9eb8eb42e92514a758f5122b6b5fea"
                        if is_performance else None)
                if not mpk:
                    break  # if they pressed Cancel, stop prompting for an mpk
                mpk = mpk.strip()
                try:
                    if len(mpk) != 128:
                        raise TypeError()
                    mpk = base64.b16decode(mpk, casefold=True)  # raises TypeError() on failure
                    break
                except TypeError:
                    tkMessageBox.showerror("Master public key", "The entered Electrum 1.x key is not exactly 128 hex digits long")

        # If an mpk has been provided (in the function call or from a user), convert it to the needed format
        if mpk:
            assert len(mpk) == 64, "mpk is 64 bytes long (after decoding from hex)"
            self._master_pubkey = "\x04" + mpk  # prepend the uncompressed tag

        # If an mpk wasn't provided (at all), and addresses and hash160s arguments also
        # weren't provided (in the original function call), prompt the user for addresses.
        else:
            if not addresses and not hash160s:
                # init_gui() was already called above
                self._known_hash160s = None
                while True:
                    addresses = tkSimpleDialog.askstring("Addresses",
                        "Please enter at least one address from your wallet, "
                        "preferably some created early in your wallet's lifetime:",
                        initialvalue="17LGpN2z62zp7RS825jXwYtE7zZ19Mxxu8" if is_performance else None)
                    if not addresses: break
                    addresses.replace(",", " ")
                    addresses.replace(";", " ")
                    addresses = addresses.split()
                    if not addresses: break
                    try:
                        # (raises ValueError or TypeError on failure):
                        self._known_hash160s = self._addresses_to_hash160s(addresses)
                        break
                    except (ValueError, TypeError) as e:
                        tkMessageBox.showerror("Addresses", "An entered address is invalid ({})".format(e))

                # If there are still no hash160s available (and no mpk), check for an address database before giving up
                if not self._known_hash160s:
                    if os.path.isfile(ADDRESSDB_DEF_FILENAME):
                        print("Using address database file '"+ADDRESSDB_DEF_FILENAME+"' in the current directory.")
                    else:
                        print("notice: address database file '"+ADDRESSDB_DEF_FILENAME+"' does not exist in current directory", file=sys.stderr)
                        sys.exit("canceled")

            if not address_limit:
                init_gui()  # might not have been called yet
                before_the = "one(s) you just entered" if addresses else "first one in actual use"
                address_limit = tkSimpleDialog.askinteger("Address limit",
                    "Please enter the address generation limit. Smaller will\n"
                    "be faster, but it must be equal to at least the number\n"
                    "of addresses created before the "+before_the+":", minvalue=1)
                if not address_limit:
                    sys.exit("canceled")
            self._addrs_to_generate = address_limit

            if not self._known_hash160s:
                print("Loading address database ...")
                self._known_hash160s = AddressSet.fromfile(open(ADDRESSDB_DEF_FILENAME, "rb"))

        return self

    # Performs basic checks so that clearly invalid mnemonic_ids can be completely skipped
    @staticmethod
    def verify_mnemonic_syntax(mnemonic_ids):
        return len(mnemonic_ids) == 12 and None not in mnemonic_ids

    # This is the time-consuming function executed by worker thread(s). It returns a tuple: if a mnemonic
    # is correct return it, else return False for item 0; return a count of mnemonics checked for item 1
    def return_verified_password_or_false(self, mnemonic_ids_list):
        # Copy some vars into local for a small speed boost
        l_sha256     = hashlib.sha256
        hashlib_new  = hashlib.new
        num_words    = self._num_words
        num_words2   = num_words * num_words

        for count, mnemonic_ids in enumerate(mnemonic_ids_list, 1):
            # Compute the binary seed from the word list the Electrum1 way
            seed = ""
            for i in xrange(0, 12, 3):
                seed += "{:08x}".format( mnemonic_ids[i    ]
                     + num_words  * (   (mnemonic_ids[i + 1] - mnemonic_ids[i    ]) % num_words )
                     + num_words2 * (   (mnemonic_ids[i + 2] - mnemonic_ids[i + 1]) % num_words ))
            #
            unstretched_seed = seed
            for i in xrange(100000):  # Electrum1's seed stretching
                seed = l_sha256(seed + unstretched_seed).digest()

            # If a master public key was provided, check the pubkey derived from the seed against it
            if self._master_pubkey:
                try:
                    if coincurve.PublicKey.from_valid_secret(seed).format(compressed=False) == self._master_pubkey:
                        return mnemonic_ids, count  # found it
                except ValueError: continue

            # Else derive addrs_to_generate addresses from the seed, searching for a match with known_hash160s
            else:
                master_privkey = bytes_to_int(seed)

                try: master_pubkey_bytes = coincurve.PublicKey.from_valid_secret(seed).format(compressed=False)[1:]
                except ValueError: continue

                for seq_num in xrange(self._addrs_to_generate):
                    # Compute the next deterministic private/public key pair the Electrum1 way.
                    # FYI we derive a privkey first, and then a pubkey from that because it's
                    # likely faster than deriving a pubkey directly from the base point and
                    # seed -- it means doing a simple modular addition instead of a point
                    # addition (plus a scalar point multiplication which is needed for both).
                    d_offset  = bytes_to_int( l_sha256(l_sha256(
                            "{}:0:{}".format(seq_num, master_pubkey_bytes)  # 0 means: not a change address
                        ).digest()).digest() )
                    d_privkey = int_to_bytes((master_privkey + d_offset) % GENERATOR_ORDER, 32)

                    d_pubkey  = coincurve.PublicKey.from_valid_secret(d_privkey).format(compressed=False)
                    # Compute the hash160 of the *uncompressed* public key, and check for a match
                    if hashlib_new("ripemd160", l_sha256(d_pubkey).digest()).digest() in self._known_hash160s:
                        return mnemonic_ids, count  # found it

        return False, count

    # Configures the values of four globals used later in config_btcrecover():
    # mnemonic_ids_guess, close_mnemonic_ids, num_inserts, and num_deletes
    @classmethod
    def config_mnemonic(cls, mnemonic_guess = None, closematch_cutoff = 0.65):
        # If a mnemonic guess wasn't provided, prompt the user for one
        if not mnemonic_guess:
            init_gui()
            mnemonic_guess = tkSimpleDialog.askstring("Electrum seed",
                "Please enter your best guess for your Electrum seed:")
            if not mnemonic_guess:
                sys.exit("canceled")

        mnemonic_guess = str(mnemonic_guess)  # ensures it's ASCII

        # Convert the mnemonic words into numeric ids and pre-calculate similar mnemonic words
        global mnemonic_ids_guess, close_mnemonic_ids
        mnemonic_ids_guess = ()
        # close_mnemonic_ids is a dict; each dict key is a mnemonic_id (int), and each
        # dict value is a tuple containing length 1 tuples, and finally each of the
        # length 1 tuples contains a single mnemonic_id which is similar to the dict's key
        close_mnemonic_ids = {}
        for word in mnemonic_guess.lower().split():
            close_words = difflib.get_close_matches(word, cls._words, sys.maxint, closematch_cutoff)
            if close_words:
                if close_words[0] != word:
                    print("'{}' was in your guess, but it's not a valid Electrum seed word;\n"
                          "    trying '{}' instead.".format(word, close_words[0]))
                mnemonic_ids_guess += cls._word_to_id[close_words[0]],
                close_mnemonic_ids[mnemonic_ids_guess[-1]] = tuple( (cls._word_to_id[w],) for w in close_words[1:] )
            else:
                print("'{}' was in your guess, but there is no similar Electrum seed word;\n"
                      "    trying all possible seed words here instead.".format(word))
                mnemonic_ids_guess += None,

        global num_inserts, num_deletes
        num_inserts = max(12 - len(mnemonic_ids_guess), 0)
        num_deletes = max(len(mnemonic_ids_guess) - 12, 0)
        if num_inserts:
            print("Seed sentence was too short, inserting {} word{} into each guess."
                  .format(num_inserts, "s" if num_inserts > 1 else ""))
        if num_deletes:
            print("Seed sentence was too long, deleting {} word{} from each guess."
                  .format(num_deletes, "s" if num_deletes > 1 else ""))

    # Produces a long stream of differing and incorrect mnemonic_ids guesses (for testing)
    @staticmethod
    def performance_iterator():
        # See WalletBIP39.performance_iterator() for details
        prefix = tuple(random.randrange(len(WalletElectrum1._words)) for i in xrange(8))
        for guess in itertools.product(xrange(len(WalletElectrum1._words)), repeat = 4):
            yield prefix + guess


############### BIP32 ###############

class WalletBIP32(WalletBase):

    def __init__(self, path = None, loading = False):
        super(WalletBIP32, self).__init__(loading)
        self._chaincode            = None
        self._passwords_per_second = None

        # Split the BIP32 key derivation path into its constituent indexes
        if not path:  # Defaults to BIP44
            path = "m/44'/0'/0'/"
            # Append the internal/external (change) index to the path in create_from_params()
            self._append_last_index = True
        else:
            self._append_last_index = False
        path_indexes = path.split("/")
        if path_indexes[0] == "m" or path_indexes[0] == "":
            del path_indexes[0]   # the optional leading "m/"
        if path_indexes[-1] == "":
            del path_indexes[-1]  # the optional trailing "/"
        self._path_indexes = ()
        for path_index in path_indexes:
            if path_index.endswith("'"):
                self._path_indexes += int(path_index[:-1]) + 2**31,
            else:
                self._path_indexes += int(path_index),

    def passwords_per_seconds(self, seconds):
        if not self._passwords_per_second:
            scalar_multiplies = 0
            for i in self._path_indexes:
                if i < 2147483648:          # if it's a normal child key
                    scalar_multiplies += 1  # then it requires a scalar multiply
            if not self._chaincode:
                scalar_multiplies += self._addrs_to_generate + 1  # each addr. to generate req. a scalar multiply
            self._passwords_per_second = \
                calc_passwords_per_second(self._checksum_ratio, self._kdf_overhead, scalar_multiplies)
        return max(int(round(self._passwords_per_second * seconds)), 1)

    # Creates a wallet instance from either an mpk, an addresses container and address_limit,
    # or a hash160s container. If none of these were supplied, prompts the user for each.
    # (the BIP32 key derivation path is by default BIP44's account 0)
    @classmethod
    def create_from_params(cls, mpk = None, addresses = None, address_limit = None, hash160s = None, path = None, is_performance = False):
        self = cls(path, loading=True)

        # Process the mpk (master public key) argument
        if mpk:
            if not mpk.startswith("xpub"):
                raise ValueError("the BIP32 extended public key must begin with 'xpub'")
            mpk = base58check_to_bip32(mpk)
            # (it's processed more later)

        # Process the hash160s argument
        if hash160s:
            if mpk:
                print("warning: addressdb is ignored when an mpk is provided", file=sys.stderr)
                hash160s = None
            else:
                self._known_hash160s = hash160s

        # Process the addresses argument
        if addresses:
            if mpk or hash160s:
                print("warning: addresses are ignored when an mpk or addressdb is provided", file=sys.stderr)
                addresses = None
            else:
                self._known_hash160s = self._addresses_to_hash160s(addresses)

        # Process the address_limit argument
        if address_limit:
            if mpk:
                print("warning: address limit is ignored when an mpk is provided", file=sys.stderr)
                address_limit = None
            else:
                address_limit = int(address_limit)
                if address_limit <= 0:
                    raise ValueError("the address limit must be > 0")
                # (it's assigned to self._addrs_to_generate later)

        # If mpk, addresses, and hash160s arguments were all not provided, prompt the user for an mpk first
        if not mpk and not addresses and not hash160s:
            init_gui()
            while True:
                mpk = tkSimpleDialog.askstring("Master extended public key",
                    "Please enter your master extended public key (xpub) if you "
                    "have it, or click Cancel to search by an address instead:",
                    initialvalue=self._performance_xpub() if is_performance else None)
                if not mpk:
                    break  # if they pressed Cancel, stop prompting for an mpk
                mpk = mpk.strip()
                try:
                    if not mpk.startswith("xpub"):
                        raise ValueError("not a BIP32 extended public key (doesn't start with 'xpub')")
                    mpk = base58check_to_bip32(mpk)
                    break
                except ValueError as e:
                    tkMessageBox.showerror("Master extended public key", "The entered key is invalid ({})".format(e))

        # If an mpk has been provided (in the function call or from a user), extract the
        # required chaincode and adjust the path to match the mpk's depth and child number
        if mpk:
            if mpk.depth == 0:
                print("xpub depth: 0")
                assert mpk.child_number == 0, "child_number == 0 when depth == 0"
            else:
                if mpk.child_number < 2**31:
                    child_num = mpk.child_number
                else:
                    child_num = str(mpk.child_number - 2**31) + "'"
                print("xpub depth:       {}\n"
                      "xpub fingerprint: {}\n"
                      "xpub child #:     {}"
                      .format(mpk.depth, base64.b16encode(mpk.fingerprint), child_num))
            self._chaincode = mpk.chaincode
            if mpk.depth <= len(self._path_indexes):                  # if this, ensure the path
                self._path_indexes = self._path_indexes[:mpk.depth]   # length matches the depth
                if self._path_indexes and self._path_indexes[-1] != mpk.child_number:
                    raise ValueError("the extended public key's child # doesn't match "
                                     "the corresponding index of this wallet's path")
            elif mpk.depth == 1 + len(self._path_indexes) and self._append_last_index:
                self._path_indexes += mpk.child_number,
            else:
                raise ValueError(
                    "the extended public key's depth exceeds the length of this wallet's path ({})"
                    .format(len(self._path_indexes)))

        else:  # else if not mpk

            # If we don't have an mpk but need to append the last
            # index, assume it's the external (non-change) chain
            if self._append_last_index:
                self._path_indexes += 0,

            # If an mpk wasn't provided (at all), and addresses and hash160s arguments also
            # weren't provided (in the original function call), prompt the user for addresses.
            if not addresses and not hash160s:
                # init_gui() was already called above
                self._known_hash160s = None
                while True:
                    addresses = tkSimpleDialog.askstring("Addresses",
                        "Please enter at least one address from the first account in your wallet, "
                        "preferably some created early in the account's lifetime:",
                        initialvalue="17LGpN2z62zp7RS825jXwYtE7zZ19Mxxu8" if is_performance else None)
                    if not addresses: break
                    addresses.replace(",", " ")
                    addresses.replace(";", " ")
                    addresses = addresses.split()
                    if not addresses: break
                    try:
                        # (raises ValueError or TypeError on failure):
                        self._known_hash160s = self._addresses_to_hash160s(addresses)
                        break
                    except (ValueError, TypeError) as e:
                        tkMessageBox.showerror("Addresses", "An entered address is invalid ({})".format(e))

                # If there are still no hash160s available (and no mpk), check for an address database before giving up
                if not self._known_hash160s:
                    if os.path.isfile(ADDRESSDB_DEF_FILENAME):
                        print("Using address database file '"+ADDRESSDB_DEF_FILENAME+"' the in current directory.")
                    else:
                        print("notice: address database file '"+ADDRESSDB_DEF_FILENAME+"' does not exist in current directory", file=sys.stderr)
                        sys.exit("canceled")

            if not address_limit:
                init_gui()  # might not have been called yet
                before_the = "one(s) you just entered" if addresses else "first one in actual use"
                address_limit = tkSimpleDialog.askinteger("Address limit",
                    "Please enter the address generation limit. Smaller will\n"
                    "be faster, but it must be equal to at least the number\n"
                    "of addresses created before the "+before_the+":", minvalue=1)
                if not address_limit:
                    sys.exit("canceled")
            self._addrs_to_generate = address_limit

            if not self._known_hash160s:
                print("Loading address database ...")
                self._known_hash160s = AddressSet.fromfile(open(ADDRESSDB_DEF_FILENAME, "rb"))

        return self

    # Performs basic checks so that clearly invalid mnemonic_ids can be completely skipped
    @staticmethod
    def verify_mnemonic_syntax(mnemonic_ids):
        # Length must be divisible by 3 and all ids must be present
        return len(mnemonic_ids) % 3 == 0 and None not in mnemonic_ids

    # This is the time-consuming function executed by worker thread(s). It returns a tuple: if a mnemonic
    # is correct return it, else return False for item 0; return a count of mnemonics checked for item 1
    def return_verified_password_or_false(self, mnemonic_ids_list):
        for count, mnemonic_ids in enumerate(mnemonic_ids_list, 1):

            # Check the (BIP39 or Electrum2) checksum; most guesses will fail this test
            if not self._verify_checksum(mnemonic_ids):
                continue

            # Convert the mnemonic sentence to seed bytes (according to BIP39 or Electrum2)
            seed_bytes = hmac.new("Bitcoin seed", self._derive_seed(mnemonic_ids), hashlib.sha512).digest()

            if self._verify_seed(seed_bytes):
                return mnemonic_ids, count  # found it

        return False, count

    def _verify_seed(self, seed_bytes):
        # Derive the chain of private keys for the specified path as per BIP32
        privkey_bytes   = seed_bytes[:32]
        chaincode_bytes = seed_bytes[32:]
        for i in self._path_indexes:

            if i < 2147483648:  # if it's a normal child key, derive the compressed public key
                try: data_to_hmac = coincurve.PublicKey.from_valid_secret(privkey_bytes).format()
                except ValueError: return False
            else:               # else it's a hardened child key
                data_to_hmac = "\0" + privkey_bytes  # prepended "\0" as per BIP32
            data_to_hmac += struct.pack(">I", i)  # append the index (big-endian) as per BIP32

            seed_bytes = hmac.new(chaincode_bytes, data_to_hmac, hashlib.sha512).digest()

            # The child private key is the parent one + the first half of the seed_bytes (mod n)
            privkey_bytes   = int_to_bytes((bytes_to_int(seed_bytes[:32]) +
                                            bytes_to_int(privkey_bytes)) % GENERATOR_ORDER, 32)
            chaincode_bytes = seed_bytes[32:]

        # If an extended public key was provided, check the derived chain code against it
        if self._chaincode:
            if chaincode_bytes == self._chaincode:
                return True  # found it

        else:
            # (note: the rest assumes the address index isn't hardened)

            # Derive the final public keys, searching for a match with known_hash160s
            # (these first steps below are loop invariants)
            try: data_to_hmac = coincurve.PublicKey.from_valid_secret(privkey_bytes).format()
            except ValueError: return False
            privkey_int = bytes_to_int(privkey_bytes)
            #
            for i in xrange(self._addrs_to_generate):
                seed_bytes = hmac.new(chaincode_bytes,
                    data_to_hmac + struct.pack(">I", i), hashlib.sha512).digest()

                # The final derived private key is the parent one + the first half of the seed_bytes
                d_privkey_bytes = int_to_bytes((bytes_to_int(seed_bytes[:32]) +
                                                privkey_int) % GENERATOR_ORDER, 32)

                d_pubkey = coincurve.PublicKey.from_valid_secret(d_privkey_bytes).format(compressed=False)
                if self.pubkey_to_hash160(d_pubkey) in self._known_hash160s:
                    return True

        return False

    # Returns a dummy xpub for performance testing purposes
    @staticmethod
    def _performance_xpub():
        # an xpub at path m/44'/0'/0', as Mycelium for Android would export
        return "xpub6BgCDhMefYxRS1gbVbxyokYzQji65v1eGJXGEiGdoobvFBShcNeJt97zoJBkNtbASLyTPYXJHRvkb3ahxaVVGEtC1AD4LyuBXULZcfCjBZx"


############### BIP39 ###############

@register_selectable_wallet_class("Standard BIP39/BIP44 (Mycelium, TREZOR, Ledger, Bither, Blockchain.info, Jaxx)")
class WalletBIP39(WalletBIP32):
    FIRSTFOUR_TAG = "-firstfour"

    # Load the wordlists for all languages (actual one to use is selected in config_mnemonic() )
    _language_words = {}
    @classmethod
    def _load_wordlists(cls):
        assert not cls._language_words, "_load_wordlists() should only be called once from the first init()"
        cls._do_load_wordlists("bip39")
        for wordlist_lang in cls._language_words.keys():  # takes a copy of the keys so the dict can be safely changed
            wordlist = cls._language_words[wordlist_lang]
            assert len(wordlist) == 2048, "BIP39 wordlist has 2048 words"
            # Special case for the four languages whose words may be truncated to the first four letters
            if wordlist_lang in ("en", "es", "fr", "it"):
                cls._language_words[wordlist_lang + cls.FIRSTFOUR_TAG] = [ w[:4] for w in wordlist ]
    #
    @classmethod
    def _do_load_wordlists(cls, name, wordlist_langs = None):
        if not wordlist_langs:
            wordlist_langs = []
            for filename in glob.iglob(os.path.join(wordlists_dir, name + "-??*.txt")):
                wordlist_langs.append(os.path.basename(filename)[len(name)+1:-4])  # e.g. "en", or "zh-hant"
        for lang in wordlist_langs:
            assert lang not in cls._language_words, "wordlist not already loaded"
            cls._language_words[lang] = load_wordlist(name, lang)

    @property
    def word_ids(self): return self._words
    @staticmethod
    def id_to_word(id): return id  # returns a UTF-8 encoded bytestring

    def __init__(self, path = None, loading = False):
        super(WalletBIP39, self).__init__(path, loading)
        if not self._language_words:
            self._load_wordlists()
        pbkdf2_library_name = btcrpass.load_pbkdf2_library().__name__  # btcrpass's pbkdf2 library is used in _derive_seed()
        self._kdf_overhead = 0.0026 if pbkdf2_library_name == "hashlib" else 0.013

    def __setstate__(self, state):
        # (Re)load the pbkdf2 library if necessary
        btcrpass.load_pbkdf2_library()
        self.__dict__ = state

    # Converts a mnemonic word from a Python unicode (as produced by load_wordlist())
    # into a bytestring (of type str) in the format required by BIP39
    @staticmethod
    def _unicode_to_bytes(word):
        assert isinstance(word, unicode)
        return intern(unicodedata.normalize("NFKD", word).encode("utf_8"))

    # Configures the values of four globals used later in config_btcrecover():
    # mnemonic_ids_guess, close_mnemonic_ids, num_inserts, and num_deletes;
    # also selects the appropriate wordlist language to use
    def config_mnemonic(self, mnemonic_guess = None, lang = None, passphrase = u"", expected_len = None, closematch_cutoff = 0.65):
        if expected_len:
            if expected_len < 12:
                raise ValueError("minimum BIP39 sentence length is 12 words")
            if expected_len > 24:
                raise ValueError("maximum BIP39 sentence length is 24 words")
            if expected_len % 3 != 0:
                raise ValueError("BIP39 sentence length must be evenly divisible by 3")

        # Do most of the work in this function:
        passphrase = self._config_mnemonic(mnemonic_guess, lang, passphrase, expected_len, closematch_cutoff)

        # The pbkdf2-derived salt, based on the passphrase, as per BIP39 (needed by _derive_seed());
        # first ensure that this version of Python supports the characters present in the passphrase
        if sys.maxunicode < 65536:  # if this Python is a "narrow" Unicode build
            for c in passphrase:
                c = ord(c)
                if 0xD800 <= c <= 0xDBFF or 0xDC00 <= c <= 0xDFFF:
                    raise ValueError("this version of Python doesn't support passphrases with Unicode code points > "+str(sys.maxunicode))
        self._derivation_salt = "mnemonic" + self._unicode_to_bytes(passphrase)

        # Special case for wallets which tell users to record only the first four letters of each word;
        # convert all short words into long ones (intentionally done *after* the finding of close words).
        # Specifically, update self._words and the globals mnemonic_ids_guess and close_mnemonic_ids.
        if self._lang.endswith(self.FIRSTFOUR_TAG):
            long_lang_words = self._language_words[self._lang[:-len(self.FIRSTFOUR_TAG)]]
            assert isinstance(long_lang_words[0], unicode),  "long words haven't yet been converted into bytes"
            assert isinstance(self._words[0],     bytes),    "short words have already been converted into bytes"
            assert len(long_lang_words) == len(self._words), "long and short word lists have the same length"
            long_lang_words = [ self._unicode_to_bytes(l) for l in long_lang_words ]
            short_to_long   = { s:l for s,l in zip(self._words, long_lang_words) }
            self._words     = long_lang_words
            #
            global mnemonic_ids_guess  # the to-be-replaced short-words guess
            long_ids_guess = ()        # the new long-words guess
            for short_id in mnemonic_ids_guess:
                long_ids_guess += None if short_id is None else short_to_long[short_id],
            mnemonic_ids_guess = long_ids_guess
            #
            global close_mnemonic_ids
            if close_mnemonic_ids:
                assert isinstance(close_mnemonic_ids.iterkeys()  .next(),       bytes), "close word keys have already been converted into bytes"
                assert isinstance(close_mnemonic_ids.itervalues().next()[0][0], bytes), "close word values have already been converted into bytes"
                for key in close_mnemonic_ids.keys():  # takes a copy of the keys so the dict can be safely changed
                    vals = close_mnemonic_ids.pop(key)
                    # vals is a tuple containing length-1 tuples which in turn each contain one word in bytes-format
                    close_mnemonic_ids[short_to_long[key]] = tuple( (short_to_long[v[0]],) for v in vals )

        # Calculate each word's index in binary (needed by _verify_checksum())
        self._word_to_binary = { word : "{:011b}".format(i) for i,word in enumerate(self._words) }

        # Chances a checksum is valid, e.g. 1/16 for 12 words, 1/256 for 24 words
        self._checksum_ratio = 2.0**( -( len(mnemonic_ids_guess) + num_inserts - num_deletes )//3 )
    #
    def _config_mnemonic(self, mnemonic_guess, lang, passphrase, expected_len, closematch_cutoff):

        # If a mnemonic guess wasn't provided, prompt the user for one
        if not mnemonic_guess:
            init_gui()
            mnemonic_guess = tkSimpleDialog.askstring("Seed",
                "Please enter your best guess for your seed (mnemonic):")
            if not mnemonic_guess:
                sys.exit("canceled")

        # Note: this is not in BIP39's preferred encoded form yet, instead it's
        # in the same format as load_wordlist creates (NFC normalized Unicode)
        mnemonic_guess = unicodedata.normalize("NFC", unicode(mnemonic_guess).lower()).split()
        if len(mnemonic_guess) == 1:  # assume it's a logographic script (no spaces, e.g. Chinese)
            mnemonic_guess = tuple(mnemonic_guess)

        # Select the appropriate wordlist language to use
        if not lang:
            language_word_hits = {}  # maps a language id to the # of words found in that language
            for word in mnemonic_guess:
                for lang, one_languages_words in self._language_words.iteritems():
                    if word in one_languages_words:
                        language_word_hits.setdefault(lang, 0)
                        language_word_hits[lang] += 1
            if len(language_word_hits) == 0:
                raise ValueError("can't guess wordlist language: 0 valid words")
            if len(language_word_hits) == 1:
                best_guess = language_word_hits.popitem()
            else:
                sorted_hits = language_word_hits.items()
                sorted_hits.sort(key=lambda x: x[1])  # sort based on hit count
                best_guess   = sorted_hits[-1]
                second_guess = sorted_hits[-2]
                # at least 20% must be exclusive to the best_guess language
                if best_guess[1] - second_guess[1] < 0.2 * len(mnemonic_guess):
                    raise ValueError("can't guess wordlist language: top best guesses ({}, {}) are too close ({}, {})"
                                     .format(best_guess[0], second_guess[0], best_guess[1], second_guess[1]))
            # at least half must be valid words
            if best_guess[1] < 0.5 * len(mnemonic_guess):
                raise ValueError("can't guess wordlist language: best guess ({}) has only {} valid word(s)"
                                 .format(best_guess[0], best_guess[1]))
            lang = best_guess[0]
        #
        try:
            words = self._language_words[lang]
        except KeyError:  # consistently raise ValueError for any bad inputs
            raise ValueError("can't find wordlist for language code '{}'".format(lang))
        self._lang = lang
        print("Using the '{}' wordlist.".format(lang))

        # Build the mnemonic_ids_guess and pre-calculate similar mnemonic words
        global mnemonic_ids_guess, close_mnemonic_ids
        self._initial_words_valid = True  # start off by assuming they're all valid
        mnemonic_ids_guess        = ()    # the best initial guess (w/no invalid words)
        #
        # close_mnemonic_ids is a dict; each dict key is a mnemonic_id (a string), and
        # each dict value is a tuple containing length 1 tuples, and finally each of the
        # length 1 tuples contains a single mnemonic_id which is similar to the dict's key;
        # e.g.: { "a-word" : ( ("a-ward", ), ("a-work",) ), "other-word" : ... }
        close_mnemonic_ids = {}
        for word in mnemonic_guess:
            close_words = difflib.get_close_matches(word, words, sys.maxint, closematch_cutoff)
            if close_words:
                if close_words[0] != word:
                    print(u"'{}' was in your guess, but it's not a valid seed word;\n"
                          u"    trying '{}' instead.".format(word, close_words[0]))
                    self._initial_words_valid = False
                mnemonic_ids_guess += self._unicode_to_bytes(close_words[0]),  # *now* convert to BIP39's format
                close_mnemonic_ids[mnemonic_ids_guess[-1]] = \
                    tuple( (self._unicode_to_bytes(w),) for w in close_words[1:] )
            else:
                if __name__ == b"__main__":
                    print(u"'{}' was in your guess, but there is no similar seed word;\n"
                          u"    trying all possible seed words here instead.".format(word))
                else:
                    print(u"'{}' was in your seed, but there is no similar seed word.".format(word))
                self._initial_words_valid = False
                mnemonic_ids_guess += None,

        guess_len = len(mnemonic_ids_guess)
        if not expected_len:  # (this is always explicitly specified for Electrum 2 seeds)
            assert not isinstance(self, WalletElectrum2), "WalletBIP39._config_mnemonic: expected_len is specified for WalletElectrum2 objects"
            if guess_len < 12:
                expected_len = 12
            elif guess_len > 24:
                expected_len = 24
            else:
                off_by = guess_len % 3
                if off_by == 1:
                    expected_len = guess_len - 1
                elif off_by == 2:
                    expected_len = guess_len + 1
                else:
                    expected_len = guess_len

        global num_inserts, num_deletes
        num_inserts = max(expected_len - guess_len, 0)
        num_deletes = max(guess_len - expected_len, 0)
        if num_inserts and not isinstance(self, WalletElectrum2):
            print("Seed sentence was too short, inserting {} word{} into each guess."
                  .format(num_inserts, "s" if num_inserts > 1 else ""))
        if num_deletes:
            print("Seed sentence was too long, deleting {} word{} from each guess."
                  .format(num_deletes, "s" if num_deletes > 1 else ""))

        # Now that we're done with the words in Unicode format,
        # convert them to BIP39's encoding and save for future reference
        self._words = tuple(map(self._unicode_to_bytes, words))

        if passphrase is True:
            init_gui()
            while True:
                passphrase = tkSimpleDialog.askstring("Passphrase",
                    "Please enter the passphrase you added when the seed was first created:", show="*")
                if not passphrase:
                    sys.exit("canceled")
                if passphrase == tkSimpleDialog.askstring("Passphrase", "Please re-enter the passphrase:", show="*"):
                    break
                tkMessageBox.showerror("Passphrase", "The passphrases did not match, try again.")
        return passphrase

    # Called by WalletBIP32.return_verified_password_or_false() to verify a BIP39 checksum
    def _verify_checksum(self, mnemonic_words):
        # Convert from the mnemonic_words (ids) back to the entropy bytes + checksum
        bit_string        = "".join(self._word_to_binary[w] for w in mnemonic_words)
        cksum_len_in_bits = len(mnemonic_words) // 3  # as per BIP39
        entropy_bytes     = bytearray()
        for i in xrange(0, len(bit_string) - cksum_len_in_bits, 8):
            entropy_bytes.append(int(bit_string[i:i+8], 2))
        cksum_int = int(bit_string[-cksum_len_in_bits:], 2)
        #
        # Calculate and verify the checksum
        return ord(hashlib.sha256(entropy_bytes).digest()[:1]) >> 8-cksum_len_in_bits \
               == cksum_int

    # Called by WalletBIP32.return_verified_password_or_false() to create a binary seed
    def _derive_seed(self, mnemonic_words):
        # Note: the words are already in BIP39's normalized form
        return btcrpass.pbkdf2_hmac("sha512", b" ".join(mnemonic_words), self._derivation_salt, 2048)

    # Produces a long stream of differing and incorrect mnemonic_ids guesses (for testing)
    # (uses mnemonic_ids_guess, num_inserts, and num_deletes globals as set by config_mnemonic())
    def performance_iterator(self):
        # This used to just itereate through the entire space, starting at "abandon abandon abandon ..."
        # and "counting" up from there. However "abandon abandon ... abandon about" is actually in use
        # in the blockchain (buggy software or people just messing around), and in address-database
        # mode this creates an unwanted positive hit, so now we have to start with a random prefix.
        length = len(mnemonic_ids_guess) + num_inserts - num_deletes
        assert length >= 12
        prefix = tuple(random.choice(self._words) for i in xrange(length-4))
        for guess in itertools.product(self._words, repeat=4):
            yield prefix + guess


############### bitcoinj ###############

@register_selectable_wallet_class("Bitcoinj compatible (MultiBit HD (Beta 8+), Bitcoin Wallet for Android/BlackBerry, Hive, breadwallet)")
class WalletBitcoinj(WalletBIP39):

    def __init__(self, path = None, loading = False):
        # Just calls WalletBIP39.__init__() with a hardcoded path
        if path: raise ValueError("can't specify a BIP32 path with Bitcoinj wallets")
        super(WalletBitcoinj, self).__init__("m/0'/0/", loading)

    @staticmethod
    def is_wallet_file(wallet_file):
        wallet_file.seek(0)
        if wallet_file.read(1) == b"\x0a":  # protobuf field number 1 of type length-delimited
            network_identifier_len = ord(wallet_file.read(1))
            if 1 <= network_identifier_len < 128:
                wallet_file.seek(2 + network_identifier_len)
                if wallet_file.read(1) in b"\x12\x1a":   # field number 2 or 3 of type length-delimited
                    return True
        return False

    # Load a bitcoinj wallet file (the part of it we need, just the chaincode)
    @classmethod
    def load_from_filename(cls, wallet_filename):
        from . import wallet_pb2
        pb_wallet = wallet_pb2.Wallet()
        with open(wallet_filename, "rb") as wallet_file:
            pb_wallet.ParseFromString(wallet_file.read(btcrpass.MAX_WALLET_FILE_SIZE))  # up to 64M, typical size is a few k
        if pb_wallet.encryption_type == wallet_pb2.Wallet.UNENCRYPTED:
            raise ValueError("this bitcoinj wallet is not encrypted")

        # Search for the (one and only) master public extended key (whose path length is 0)
        self = None
        for key in pb_wallet.key:
            if  key.HasField("deterministic_key") and len(key.deterministic_key.path) == 0:
                assert not self, "only one master public extended key is in the wallet file"
                assert len(key.deterministic_key.chain_code) == 32, "chaincode length is 32 bytes"
                self = cls(loading=True)
                self._chaincode = key.deterministic_key.chain_code
                # Because it's the *master* xpub, it has an empty path
                self._path_indexes = ()

        if not self:
            raise ValueError("No master public extended key was found in this bitcoinj wallet file")
        return self

    # Returns a dummy xpub for performance testing purposes
    @staticmethod
    def _performance_xpub():
        # an xpub at path m/0', as Bitcoin Wallet for Android/BlackBerry would export
        return "xpub67tjk7ug7iNivs1f1pmDswDDbk6kRCe4U1AXSiYLbtp6a2GaodSUovt3kNrDJ2q18TBX65aJZ7VqRBpnVJsaVQaBY2SANYw6kgZf4QLCpPu"


############### Electrum2 ###############

@register_selectable_wallet_class('Electrum 2.x ("standard" wallets initially created with 2.x)')
class WalletElectrum2(WalletBIP39):

    # From Electrum 2.x's mnemonic.py (coalesced)
    CJK_INTERVALS = (
        ( 0x1100,  0x11ff),
        ( 0x2e80,  0x2fdf),
        ( 0x2ff0,  0x2fff),
        ( 0x3040,  0x31ff),
        ( 0x3400,  0x4dbf),
        ( 0x4e00,  0xa4ff),
        ( 0xa960,  0xa97f),
        ( 0xac00,  0xd7ff),
        ( 0xf900,  0xfaff),
        ( 0xff00,  0xffef),
        (0x16f00, 0x16f9f),
        (0x1b000, 0x1b0ff),
        (0x20000, 0x2a6df),
        (0x2a700, 0x2b81f),
        (0x2f800, 0x2fa1d),
        (0xe0100, 0xe01ef))

    # Load the wordlists for all languages (actual one to use is selected in config_mnemonic() )
    @classmethod
    def _load_wordlists(cls):
        assert not cls._language_words, "_load_wordlists() should only be called once from the first init()"
        cls._do_load_wordlists("electrum2")
        cls._do_load_wordlists("bip39", ("en", "es", "ja", "zh-hans"))  # only the four bip39 ones used by Electrum2
        assert all(len(w) >= 1411 for w in cls._language_words.values()), \
               "Electrum2 wordlists are at least 1411 words long" # because we assume a max mnemonic length of 13

    def __init__(self, path = None, loading = False):
        # Just calls WalletBIP39.__init__() with a hardcoded path
        if path: raise ValueError("can't specify a BIP32 path with Electrum 2.x wallets")
        super(WalletElectrum2, self).__init__("m/0/", loading)
        self._checksum_ratio   = 1.0 / 256.0  # 1 in 256 checksums are valid on average
        self._needs_passphrase = None

    @staticmethod
    def is_wallet_file(wallet_file):
        wallet_file.seek(0)
        data = wallet_file.read(8)
        if data[0] == b"{":
            return None  # "maybe yes"
        try:   data = base64.b64decode(data)
        except TypeError: return False  # "definitely no"
        if data.startswith(b"BIE1"):
            sys.exit("error: Electrum 2.8+ fully-encrypted wallet files cannot be read,\n"
                     "try to recover from your master extended public key or an address instead")
        return False  # "definitely no"

    # Load an Electrum2 wallet file (the part of it we need, just the master public key)
    @classmethod
    def load_from_filename(cls, wallet_filename):
        import json

        with open(wallet_filename) as wallet_file:
            wallet = json.load(wallet_file)
        wallet_type = wallet.get("wallet_type")
        if not wallet_type:
            raise ValueError("Unrecognized wallet format (Electrum2 wallet_type not found)")
        if wallet_type == "old":  # if it's been converted from 1.x to 2.y (y<7), return a WalletElectrum1 object
            return WalletElectrum1._load_from_dict(wallet)
        if not wallet.get("use_encryption"):
            raise ValueError("Electrum2 wallet is not encrypted")
        seed_version = wallet.get("seed_version", "(not found)")
        if wallet.get("seed_version") not in (11, 12, 13):  # all 2.x versions as of Oct 2016
            raise NotImplementedError("Unsupported Electrum2 seed version " + unicode(seed_version))
        if wallet_type != "standard":
            raise NotImplementedError("Unsupported Electrum2 wallet type: " + wallet_type)

        mpk = needs_passphrase = None
        while True:  # "loops" exactly once; only here so we've something to break out of

            # Electrum 2.7+ standard wallets have a keystore
            keystore = wallet.get("keystore")
            if keystore:
                keystore_type = keystore.get("type", "(not found)")

                # Wallets originally created by an Electrum 2.x version
                if keystore_type == "bip32":
                    mpk = keystore["xpub"]
                    if keystore.get("passphrase"):
                        needs_passphrase = True
                    break

                # Former Electrum 1.x wallet after conversion to Electrum 2.7+ standard-wallet format
                elif keystore_type == "old":
                    # Construct and return a WalletElectrum1 object
                    mpk = base64.b16decode(keystore["mpk"], casefold=True)
                    if len(mpk) != 64:
                        raise ValueError("Electrum1 master public key is not 64 bytes long")
                    self = WalletElectrum1(loading=True)
                    self._master_pubkey = "\x04" + mpk  # prepend the uncompressed tag
                    return self

                else:
                    print("warning: found unsupported keystore type " + keystore_type, file=sys.stderr)

            # Electrum 2.0 - 2.6.4 wallet (of any wallet type)
            mpks = wallet.get("master_public_keys")
            if mpks:
                mpk = mpks.values()[0]
                break

            raise RuntimeError("No master public keys found in Electrum2 wallet")

        assert mpk
        wallet = cls.create_from_params(mpk)
        wallet._needs_passphrase = needs_passphrase
        return wallet

    # Converts a mnemonic word from a Python unicode (as produced by load_wordlist())
    # into a bytestring (of type str) via the same method as Electrum 2.x
    @staticmethod
    def _unicode_to_bytes(word):
        assert isinstance(word, unicode)
        word = unicodedata.normalize("NFKD", word)
        word = filter(lambda c: not unicodedata.combining(c), word)  # Electrum 2.x removes combining marks
        return intern(word.encode("utf_8"))

    def config_mnemonic(self, mnemonic_guess = None, lang = None, passphrase = u"", expected_len = None, closematch_cutoff = 0.65):
        if expected_len is None:
            expected_len_specified = False
            if self._needs_passphrase:
                expected_len = 12
                print("notice: presence of a mnemonic passphrase implies a 12-word long Electrum 2.7+ mnemonic",
                      file=sys.stderr)
            else:
                init_gui()
                if tkMessageBox.askyesno("Electrum 2.x version",
                        "Did you CREATE your wallet with Electrum version 2.7 (released Oct 2 2016) or later?"
                        "\n\nPlease choose No if you're unsure.",
                        default=tkMessageBox.NO):
                    expected_len = 12
                else:
                    expected_len = 13
        else:
            expected_len_specified = True
            if expected_len > 13:
                raise ValueError("maximum mnemonic length for Electrum2 is 13 words")

        if self._needs_passphrase and not passphrase:
            passphrase = True  # tells self._config_mnemonic() to prompt for a passphrase below
            init_gui()
            tkMessageBox.showwarning("Passphrase",
                'This Electrum seed was extended with "custom words" (a seed passphrase) when it '
                "was first created. You will need to enter it to continue.\n\nNote that this seed "
                "passphrase is NOT the same as the wallet password that's entered to spend funds.")
        # Calls WalletBIP39's generic version (note the leading _) with the mnemonic
        # length (which for Electrum2 wallets alone is treated only as a maximum length)
        passphrase = self._config_mnemonic(mnemonic_guess, lang, passphrase, expected_len, closematch_cutoff)

        # Python 2.x running Electrum 2.x has a Unicode bug where if there are any code points > 65535,
        # they might be normalized differently between different Python 2 builds (narrow vs. wide Unicode)
        assert isinstance(passphrase, unicode)
        if sys.maxunicode < 65536:  # the check for narrow Unicode builds looks for UTF-16 surrogate pairs:
            maybe_buggy = any(0xD800 <= ord(c) <= 0xDBFF or 0xDC00 <= ord(c) <= 0xDFFF for c in passphrase)
        else:                       # the check for wide Unicode builds:
            maybe_buggy = any(ord(c) > 65535 for c in passphrase)
        if maybe_buggy:
            print("warning: due to Unicode incompatibilities, it's strongly recommended\n"
                  "         that you run seedrecover.py on the same computer (or at least\n"
                  "         the same OS) where you created your wallet", file=sys.stderr)

        if expected_len_specified and num_inserts:
            print("notice: for Electrum 2.x, --mnemonic-length is the max length tried, but not necessarily the min",
                  file=sys.stderr)

        # The pbkdf2-derived salt (needed by _derive_seed()); Electrum 2.x is similar to BIP39,
        # however it differs in the iffy(?) normalization procedure and the prepended string
        import string
        passphrase = unicodedata.normalize("NFKD", passphrase)  # problematic w/Python narrow Unicode builds, same as Electrum
        passphrase = passphrase.lower()  # (?)
        passphrase = filter(lambda c: not unicodedata.combining(c), passphrase)  # remove combining marks
        passphrase = u" ".join(passphrase.split())  # replace whitespace sequences with a single ASCII space
        # remove ASCII whitespace between CJK characters (?)
        passphrase = u"".join(c for i,c in enumerate(passphrase) if not (
                c in string.whitespace
            and any(intvl[0] <= ord(passphrase[i-1]) <= intvl[1] for intvl in self.CJK_INTERVALS)
            and any(intvl[0] <= ord(passphrase[i+1]) <= intvl[1] for intvl in self.CJK_INTERVALS)))
        self._derivation_salt = "electrum" + passphrase.encode("utf_8")

        # Electrum 2.x doesn't separate mnemonic words with spaces in sentences for any CJK
        # scripts when calculating the checksum or deriving a binary seed (even though this
        # seem inappropriate for some CJK scripts such as Hiragana as used by the ja wordlist)
        self._space = "" if self._lang in ("ja", "zh-hans", "zh-hant") else " "

    # Performs basic checks so that clearly invalid mnemonic_ids can be completely skipped
    @staticmethod
    def verify_mnemonic_syntax(mnemonic_ids):
        # As long as each wordlist has at least 1411 words (checked by _load_wordlists()),
        # a valid mnemonic is at most 13 words long (and all ids must be present)
        return len(mnemonic_ids) <= 13 and None not in mnemonic_ids

    # Called by WalletBIP32.return_verified_password_or_false() to verify an Electrum2 checksum
    def _verify_checksum(self, mnemonic_words):
        return hmac.new("Seed version", self._space.join(mnemonic_words), hashlib.sha512) \
               .digest()[0] == "\x01"

    # Called by WalletBIP32.return_verified_password_or_false() to create a binary seed
    def _derive_seed(self, mnemonic_words):
        # Note: the words are already in Electrum2's normalized form
        return btcrpass.pbkdf2_hmac("sha512", self._space.join(mnemonic_words), self._derivation_salt, 2048)

    # Returns a dummy xpub for performance testing purposes
    @staticmethod
    def _performance_xpub():
        # an xpub at path m, as Electrum would export
        return "xpub661MyMwAqRbcGsUXkGBkytQkYZ6M16bFWwTocQDdPSm6eJ1wUsxG5qty1kTCUq7EztwMscUstHVo1XCJMxWyLn4PP1asLjt4gPt3HkA81qe"


############### Ethereum ###############

@register_selectable_wallet_class('Ethereum Standard BIP39/BIP44 (Jaxx, MetaMask, MyEtherWallet, TREZOR, Exodus, NOT Ledger)')
class WalletEthereum(WalletBIP39):

    def __init__(self, path = None, loading = False):
        if not path: path = "m/44'/60'/0'/0/"
        super(WalletEthereum, self).__init__(path, loading)
        global sha3
        import sha3

    def __setstate__(self, state):
        super(WalletEthereum, self).__setstate__(state)
        # (re-)load the required libraries after being unpickled
        global sha3
        import sha3

    @classmethod
    def create_from_params(cls, *args, **kwargs):
        if isinstance(kwargs.get("hash160s"), AddressSet):
            raise ValueError("can't use an address database with Ethereum wallets")
        self = super(WalletEthereum, cls).create_from_params(*args, **kwargs)
        if hasattr(self, "_known_hash160s") and isinstance(self._known_hash160s, AddressSet):
            raise ValueError("can't use an address database with Ethereum wallets")
        return self

    @staticmethod
    def _addresses_to_hash160s(addresses):
        hash160s = set()
        for address in addresses:
            if address[:2].lower() == "0x":
                address = address[2:]
            if len(address) != 40:
                raise ValueError("length (excluding any '0x' prefix) of Ethereum addresses must be 40")
            cur_hash160 = base64.b16decode(address, casefold=True)
            if not address.islower():  # verify the EIP55 checksum unless all letters are lowercase
                checksum = sha3.keccak_256(base64.b16encode(cur_hash160).lower()).digest()
                for nibble, c in enumerate(address, 0):
                    if c.isalpha() and \
                       c.isupper() != bool(ord(checksum[nibble // 2]) & (0b1000 if nibble&1 else 0b10000000)):
                            raise ValueError("invalid EIP55 checksum")
            hash160s.add(cur_hash160)
        return hash160s

    @staticmethod
    def pubkey_to_hash160(uncompressed_pubkey):
        """convert from an uncompressed public key to its Ethereum hash160 form

        :param uncompressed_pubkey: SEC 1 EllipticCurvePoint OctetString
        :type uncompressed_pubkey: str
        :return: last 20 bytes of keccak256(raw_64_byte_pubkey)
        :rtype: str
        """
        assert len(uncompressed_pubkey) == 65 and uncompressed_pubkey[0] == "\x04"
        return sha3.keccak_256(uncompressed_pubkey[1:]).digest()[-20:]


################################### Main ###################################


tk_root = None
def init_gui():
    global tk_root, tk, tkFileDialog, tkSimpleDialog, tkMessageBox
    if not tk_root:

        if sys.platform == "win32":
            # Some py2exe .dll's, when registered as Windows shell extensions (e.g. SpiderOak), can interfere
            # with Python scripts which spawn a shell (e.g. a file selection dialog). The code below blocks
            # required modules from loading and prevents any such py2exe .dlls from causing too much trouble.
            sys.modules["win32api"] = None
            sys.modules["win32com"] = None

        import Tkinter as tk
        import tkFileDialog, tkSimpleDialog, tkMessageBox
        tk_root = tk.Tk(className="seedrecover.py")  # initialize library
        tk_root.withdraw()                           # but don't display a window (yet)


# seed.py uses routines from password.py to generate guesses, however instead
# of dealing with passwords (immutable sequences of characters), it deals with
# seeds (represented as immutable sequences of mnemonic_ids). More specifically,
# seeds are tuples of mnemonic_ids, and a mnemonic_id is just an int for Electrum1,
# or a UTF-8 bytestring id for most other wallet types.

# These are simple typo generators; see btcrpass.py for additional information.
# Instead of returning iterables of sequences of characters (iterables of strings),
# these return iterables of sequences of mnemonic_ids (iterables of partial seeds).
#
@btcrpass.register_simple_typo("deleteword")
def delete_word(mnemonic_ids, i):
    return (),
#
@btcrpass.register_simple_typo("replaceword")
def replace_word(mnemonic_ids, i):
    if mnemonic_ids[i] is None: return (),      # don't touch invalid words
    return ((new_id,) for new_id in loaded_wallet.word_ids if new_id != mnemonic_ids[i])
#
@btcrpass.register_simple_typo("replacecloseword")
def replace_close_word(mnemonic_ids, i):
    if mnemonic_ids[i] is None: return (),      # don't touch invalid words
    return close_mnemonic_ids[mnemonic_ids[i]]  # the pre-calculated similar words
#
@btcrpass.register_simple_typo("replacewrongword")
def replace_wrong_word(mnemonic_ids, i):
    if mnemonic_ids[i] is not None: return (),  # only replace invalid words
    return ((new_id,) for new_id in loaded_wallet.word_ids)


# Builds a command line and then runs btcrecover with it.
#   typos     - max number of mistakes to apply to each guess
#   big_typos - max number of "big" mistakes to apply to each guess;
#               a big mistake involves replacing or inserting a word using the
#               full word list, and significantly increases the search time
#   min_typos - min number of mistakes to apply to each guess
num_inserts = num_deletes = 0
def run_btcrecover(typos, big_typos = 0, min_typos = 0, is_performance = False, extra_args = []):
    if typos < 0:  # typos == 0 is silly, but causes no harm
        raise ValueError("typos must be >= 0")
    if big_typos < 0:
        raise ValueError("big-typos must be >= 0")
    if big_typos > typos:
        raise ValueError("typos includes big_typos, therefore it must be >= big_typos")
    # min_typos < 0 is silly, but causes no harm
    # typos < min_typos is an error; it's checked in btcrpass.parse_arguments()

    # Local copies of globals whose changes should only be visible locally
    l_num_inserts = num_inserts
    l_num_deletes = num_deletes

    # Number of words that were definitely wrong in the guess
    num_wrong = sum(map(lambda id: id is None, mnemonic_ids_guess))

    # Start building the command-line arguments
    btcr_args = "--typos " + str(typos)

    if is_performance:
        btcr_args += " --performance"
        # These typos are not supported by seedrecover with --performance testing:
        l_num_inserts = l_num_deletes = num_wrong = 0

    # First, check if there are any required typos (if there are missing or extra
    # words in the guess) and adjust the max number of other typos to later apply

    any_typos  = typos  # the max number of typos left after removing required typos
    #big_typos =        # the max number of "big" typos after removing required typos (an arg from above)

    if l_num_deletes:  # if the guess is too long (extra words need to be deleted)
        any_typos -= l_num_deletes
        btcr_args += " --typos-deleteword"
        if l_num_deletes < typos:
            btcr_args += " --max-typos-deleteword " + str(l_num_deletes)

    if num_wrong:      # if any of the words were invalid (and need to be replaced)
        any_typos -= num_wrong
        big_typos -= num_wrong
        btcr_args += " --typos-replacewrongword"
        if num_wrong < typos:
            btcr_args += " --max-typos-replacewrongword " + str(num_wrong)

    # For (only) Electrum2, num_inserts are not required, so we try several sub-phases with a
    # different number of inserts each time; for all others the total num_inserts are required
    if isinstance(loaded_wallet, WalletElectrum2):
        num_inserts_to_try = xrange(l_num_inserts + 1)  # try a range
    else:
        num_inserts_to_try = l_num_inserts,             # only try the required max
    for subphase_num, cur_num_inserts in enumerate(num_inserts_to_try, 1):

        # Create local copies of these which are reset at the beginning of each loop
        l_any_typos = any_typos
        l_big_typos = big_typos
        l_btcr_args = btcr_args

        ids_to_try_inserting = None
        if cur_num_inserts:  # if the guess is too short (words need to be inserted)
            l_any_typos -= cur_num_inserts
            l_big_typos -= cur_num_inserts
            # (instead of --typos-insert we'll set inserted_items=ids_to_try_inserting below)
            ids_to_try_inserting = ((id,) for id in loaded_wallet.word_ids)
            l_btcr_args += " --max-adjacent-inserts " + str(cur_num_inserts)
            if cur_num_inserts < typos:
                l_btcr_args += " --max-typos-insert " + str(cur_num_inserts)

        # For >1 subphases, print this out now or just after the skip-this-phase check below
        if len(num_inserts_to_try) > 1:
            subphase_msg = "  - subphase {}/{}: with {} inserted seed word{}".format(
                subphase_num, len(num_inserts_to_try),
                cur_num_inserts, "" if cur_num_inserts == 1 else "s")
        if subphase_num > 1:
            print(subphase_msg)
            maybe_skipping = "the remainder of this phase."
        else:
            maybe_skipping = "this phase."

        if l_any_typos < 0:  # if too many typos are required to generate valid mnemonics
            print("Not enough mistakes permitted to produce a valid seed; skipping", maybe_skipping)
            return False
        if l_big_typos < 0:  # if too many big typos are required to generate valid mnemonics
            print("Not enough entirely different seed words permitted; skipping", maybe_skipping)
            return False
        assert typos >= cur_num_inserts + l_num_deletes + num_wrong

        if subphase_num == 1 and len(num_inserts_to_try) > 1:
            print(subphase_msg)

        # Because btcrecover doesn't support --min-typos-* on a per-typo basis, it ends
        # up generating some invalid guesses. We can use --min-typos to filter out some
        # of them (the remainder is later filtered out by verify_mnemonic_syntax()).
        min_typos = max(min_typos, cur_num_inserts + l_num_deletes + num_wrong)
        if min_typos:
            l_btcr_args += " --min-typos " + str(min_typos)

        # Next, if the required typos above haven't consumed all available typos
        # (as specified by the function's args), add some "optional" typos

        if l_any_typos:
            l_btcr_args += " --typos-swap"
            if l_any_typos < typos:
                l_btcr_args += " --max-typos-swap " + str(l_any_typos)

            if l_big_typos:  # if there are any big typos left, add the replaceword typo
                l_btcr_args += " --typos-replaceword"
                if l_big_typos < typos:
                    l_btcr_args += " --max-typos-replaceword " + str(l_big_typos)

            # only add replacecloseword typos if they're not already covered by the
            # replaceword typos added above and there exists at least one close word
            num_replacecloseword = l_any_typos - l_big_typos
            if num_replacecloseword > 0 and any(len(ids) > 0 for ids in close_mnemonic_ids.itervalues()):
                l_btcr_args += " --typos-replacecloseword"
                if num_replacecloseword < typos:
                    l_btcr_args += " --max-typos-replacecloseword " + str(num_replacecloseword)

        btcrpass.parse_arguments(
            l_btcr_args.split() + extra_args,
            inserted_items= ids_to_try_inserting,
            wallet=         loaded_wallet,
            base_iterator=  (mnemonic_ids_guess,) if not is_performance else None, # the one guess to modify
            perf_iterator=  lambda: loaded_wallet.performance_iterator(),
            check_only=     loaded_wallet.verify_mnemonic_syntax
        )
        (mnemonic_found, not_found_msg) = btcrpass.main()

        if mnemonic_found:
            return mnemonic_found
        elif not_found_msg is None:
            return None  # An error occurred or Ctrl-C was pressed inside btcrpass.main()

    return False  # No error occurred; the mnemonic wasn't found


def register_autodetecting_wallets():
    """Registers wallets which can do file auto-detection with btcrecover's auto-detect mechanism

    :rtype: None
    """
    btcrpass.clear_registered_wallets()
    for wallet_cls, description in selectable_wallet_classes:
        if hasattr(wallet_cls, "is_wallet_file"):
            btcrpass.register_wallet_class(wallet_cls)


def main(argv):
    global loaded_wallet
    loaded_wallet = wallet_type = None
    create_from_params     = {}  # additional args to pass to wallet_type.create_from_params()
    config_mnemonic_params = {}  # additional args to pass to wallet.config_mnemonic()
    phase                  = {}  # if only one phase is requested, the args to pass to run_btcrecover()
    extra_args             = []  # additional args to pass to btcrpass.parse_arguments() (in run_btcrecover())

    if argv or "_ARGCOMPLETE" in os.environ:
        import argparse
        parser = argparse.ArgumentParser()
        parser.add_argument("--wallet",      metavar="FILE",        help="the wallet file")
        parser.add_argument("--wallet-type", metavar="TYPE",        help="if not using a wallet file, the wallet type")
        parser.add_argument("--mpk",         metavar="XPUB-OR-HEX", help="if not using a wallet file, the master public key")
        parser.add_argument("--addrs",       metavar="ADDRESS",     nargs="+", help="if not using an mpk, address(es) in the wallet")
        parser.add_argument("--addressdb",   metavar="FILE", nargs="?", help="if not using addrs, use a full address database (default: %(const)s)", const=ADDRESSDB_DEF_FILENAME)
        parser.add_argument("--addr-limit",  type=int, metavar="COUNT", help="if using addrs or addressdb, the generation limit")
        parser.add_argument("--typos",       type=int, metavar="COUNT", help="the max number of mistakes to try (default: auto)")
        parser.add_argument("--big-typos",   type=int, metavar="COUNT", help="the max number of big (entirely different word) mistakes to try (default: auto or 0)")
        parser.add_argument("--min-typos",   type=int, metavar="COUNT", help="enforce a min # of mistakes per guess")
        parser.add_argument("--close-match",type=float,metavar="CUTOFF",help="try words which are less/more similar for each mistake (0.0 to 1.0, default: 0.65)")
        parser.add_argument("--passphrase",  action="store_true",       help="the mnemonic is augmented with a known passphrase (BIP39 or Electrum 2.x only)")
        parser.add_argument("--passphrase-prompt", action="store_true", help="prompt for the mnemonic passphrase via the terminal (default: via the GUI)")
        parser.add_argument("--mnemonic-prompt",   action="store_true", help="prompt for the mnemonic guess via the terminal (default: via the GUI)")
        parser.add_argument("--mnemonic-length", type=int, metavar="WORD-COUNT", help="the length of the correct mnemonic (default: auto)")
        parser.add_argument("--language",    metavar="LANG-CODE",       help="the wordlist language to use (see wordlists/README.md, default: auto)")
        parser.add_argument("--bip32-path",  metavar="PATH",            help="path (e.g. m/0'/0/) excluding the final index (default: BIP44 account 0)")
        parser.add_argument("--skip",        type=int, metavar="COUNT", help="skip this many initial passwords for continuing an interrupted search")
        parser.add_argument("--threads", type=int, metavar="COUNT", help="number of worker threads (default: number of CPUs, {})".format(btcrpass.cpus))
        parser.add_argument("--worker",      metavar="ID#/TOTAL#",  help="divide the workload between TOTAL# servers, where each has a different ID# between 1 and TOTAL#")
        parser.add_argument("--max-eta",     type=int,              help="max estimated runtime before refusing to even start (default: 168 hours, i.e. 1 week)")
        parser.add_argument("--no-eta",      action="store_true",   help="disable calculating the estimated time to completion")
        parser.add_argument("--no-dupchecks",action="store_true",   help="disable duplicate guess checking to save memory")
        parser.add_argument("--no-progress", action="store_true",   help="disable the progress bar")
        parser.add_argument("--no-pause",    action="store_true",   help="never pause before exiting (default: auto)")
        parser.add_argument("--performance", action="store_true",   help="run a continuous performance test (Ctrl-C to exit)")
        parser.add_argument("--btcr-args",   action="store_true",   help=argparse.SUPPRESS)
        parser.add_argument("--version","-v",action="store_true",   help="show full version information and exit")

        # Optional bash tab completion support
        try:
            import argcomplete
            argcomplete.autocomplete(parser)
        except ImportError:
            pass
        assert argv

        # Parse the args; unknown args will be passed to btcrpass.parse_arguments() iff --btcr-args is specified
        args, extra_args = parser.parse_known_args(argv)
        if extra_args and not args.btcr_args:
            parser.parse_args(argv)  # re-parse them just to generate an error for the unknown args
            assert False

        # Version information is always printed by seedrecover.py, so just exit
        if args.version: sys.exit(0)

        if args.wallet:
            loaded_wallet = btcrpass.load_wallet(args.wallet)

        # Look up the --wallet-type arg in the list of selectable_wallet_classes
        if args.wallet_type:
            if args.wallet:
                print("warning: --wallet-type is ignored when a wallet is provided", file=sys.stderr)
            else:
                args.wallet_type  = args.wallet_type.lower()
                wallet_type_names = []
                for cls, desc in selectable_wallet_classes:
                    wallet_type_names.append(cls.__name__.replace("Wallet", "", 1).lower())
                    if wallet_type_names[-1] == args.wallet_type:
                        wallet_type = cls
                        break
                else:
                    wallet_type_names.sort()
                    sys.exit("--wallet-type must be one of: " + ", ".join(wallet_type_names))

        if args.mpk:
            if args.wallet:
                print("warning: --mpk is ignored when a wallet is provided", file=sys.stderr)
            else:
                create_from_params["mpk"] = args.mpk

        if args.addrs:
            if args.wallet:
                print("warning: --addrs is ignored when a wallet is provided", file=sys.stderr)
            else:
                create_from_params["addresses"] = args.addrs

        if args.addr_limit is not None:
            if args.wallet:
                print("warning: --addr-limit is ignored when a wallet is provided", file=sys.stderr)
            else:
                create_from_params["address_limit"] = args.addr_limit

        if args.addressdb and not os.path.isfile(args.addressdb):
            sys.exit("file '{}' does not exist".format(args.addressdb))

        if args.typos is not None:
            phase["typos"] = args.typos

        if args.big_typos is not None:
            phase["big_typos"] = args.big_typos
            if not args.typos:
                phase["typos"] = args.big_typos

        if args.min_typos is not None:
            if not phase.get("typos"):
                sys.exit("--typos must be specified when using --min_typos")
            phase["min_typos"] = args.min_typos

        if args.close_match is not None:
            config_mnemonic_params["closematch_cutoff"] = args.close_match

        if args.mnemonic_prompt:
            encoding = sys.stdin.encoding or "ASCII"
            if "utf" not in encoding.lower():
                print("terminal does not support UTF; mnemonics with non-ASCII chars might not work", file=sys.stderr)
            mnemonic_guess = raw_input("Please enter your best guess for your mnemonic (seed)\n> ")
            if not mnemonic_guess:
                sys.exit("canceled")
            if isinstance(mnemonic_guess, str):
                mnemonic_guess = mnemonic_guess.decode(encoding)  # convert from terminal's encoding to unicode
            config_mnemonic_params["mnemonic_guess"] = mnemonic_guess

        if args.passphrase_prompt:
            import getpass
            encoding = sys.stdin.encoding or "ASCII"
            if "utf" not in encoding.lower():
                print("warning: terminal does not support UTF; passwords with non-ASCII chars might not work", file=sys.stderr)
            print("(note your passphrase will not be displayed as you type)")
            while True:
                passphrase = getpass.getpass("Please enter the passphrase you added when the seed was first created: ")
                if not passphrase:
                    sys.exit("canceled")
                if passphrase == getpass.getpass("Please re-enter the passphrase: "):
                    break
                print("The passphrases did not match, try again.")
            if isinstance(passphrase, str):
                passphrase = passphrase.decode(encoding)  # convert from terminal's encoding to unicode
            config_mnemonic_params["passphrase"] = passphrase
        elif args.passphrase:
            config_mnemonic_params["passphrase"] = True  # config_mnemonic() will prompt for one

        if args.language:
            config_mnemonic_params["lang"] = args.language.lower()

        if args.mnemonic_length is not None:
            config_mnemonic_params["expected_len"] = args.mnemonic_length

        if args.bip32_path:
            if args.wallet:
                print("warning: --bip32-path is ignored when a wallet is provided", file=sys.stderr)
            else:
                create_from_params["path"] = args.bip32_path

        # These arguments and their values are passed on to btcrpass.parse_arguments()
        for argkey in "skip", "threads", "worker", "max_eta":
            if args.__dict__[argkey] is not None:
                extra_args.extend(("--"+argkey.replace("_", "-"), str(args.__dict__[argkey])))

        # These arguments (which have no values) are passed on to btcrpass.parse_arguments()
        for argkey in "no_eta", "no_dupchecks", "no_progress":
            if args.__dict__[argkey]:
                extra_args.append("--"+argkey.replace("_", "-"))

        if args.performance:
            create_from_params["is_performance"] = phase["is_performance"] = True
            phase.setdefault("typos", 0)
            if not args.mnemonic_prompt:
                # Create a dummy mnemonic; only its language and length are used for anything
                config_mnemonic_params["mnemonic_guess"] = " ".join("act" for i in xrange(args.mnemonic_length or 12))

        if args.addressdb:
            print("Loading address database ...")
            create_from_params["hash160s"] = AddressSet.fromfile(open(args.addressdb, "rb"))

    else:  # else if no command-line args are present
        global pause_at_exit
        pause_at_exit = True
        atexit.register(lambda: pause_at_exit and
                                not multiprocessing.current_process().name.startswith("PoolWorker-") and
                                raw_input("Press Enter to exit ..."))

    if not loaded_wallet and not wallet_type:  # neither --wallet nor --wallet-type were specified

        # Ask for a wallet file
        init_gui()
        wallet_filename = tkFileDialog.askopenfilename(title="Please select your wallet file if you have one")
        if wallet_filename:
            loaded_wallet = btcrpass.load_wallet(wallet_filename)  # raises on failure; no second chance

    if not loaded_wallet:    # if no wallet file was chosen

        if not wallet_type:  # if --wallet-type wasn't specified

            # Without a wallet file, we can't automatically determine the wallet type, so prompt the
            # user to select a wallet that's been registered with @register_selectable_wallet_class
            selectable_wallet_classes.sort(key=lambda x: x[1])  # sort by description
            class WalletTypeDialog(tkSimpleDialog.Dialog):
                def body(self, master):
                    self.wallet_type     = None
                    self._index_to_cls   = []
                    self._selected_index = tk.IntVar(value= -1)
                    for i, (cls, desc) in enumerate(selectable_wallet_classes):
                        self._index_to_cls.append(cls)
                        tk.Radiobutton(master, variable=self._selected_index, value=i, text=desc) \
                            .pack(anchor=tk.W)
                def validate(self):
                    if self._selected_index.get() < 0:
                        tkMessageBox.showwarning("Wallet Type", "Please select a wallet type")
                        return False
                    return True
                def apply(self):
                    self.wallet_type = self._index_to_cls[self._selected_index.get()]
            #
            wallet_type_dialog = WalletTypeDialog(tk_root, "Please select your wallet type")
            wallet_type = wallet_type_dialog.wallet_type
            if not wallet_type:
                sys.exit("canceled")

        try:
            loaded_wallet = wallet_type.create_from_params(**create_from_params)
        except TypeError as e:
            matched = re.match("create_from_params\(\) got an unexpected keyword argument '(.*)'", str(e))
            if matched:
                sys.exit("{} does not support the {} option".format(wallet_type.__name__, matched.group(1)))
            raise
        except ValueError as e:
            sys.exit(e)

    try:
        loaded_wallet.config_mnemonic(**config_mnemonic_params)
    except TypeError as e:
        matched = re.match("config_mnemonic\(\) got an unexpected keyword argument '(.*)'", str(e))
        if matched:
            sys.exit("{} does not support the {} option".format(loaded_wallet.__class__.__name__, matched.group(1)))
        raise
    except ValueError as e:
        sys.exit(e)

    # Seeds for some wallet types have a checksum which is unlikely to be correct
    # for the initial provided seed guess; if it is correct, let the user know
    try:
        if (  loaded_wallet._initial_words_valid
          and loaded_wallet.verify_mnemonic_syntax(mnemonic_ids_guess)
          and loaded_wallet._verify_checksum(mnemonic_ids_guess) ):
            print(u"Initial seed guess has a valid checksum ({:.2g}% chance).".format(loaded_wallet._checksum_ratio * 100.0))
    except AttributeError: pass

    # Now that most of the GUI code is done, undo any Windows shell extension workarounds from init_gui()
    if sys.platform == "win32" and tk_root:
        del sys.modules["win32api"]
        del sys.modules["win32com"]
        # Some py2exe-compiled .dll shell extensions set sys.frozen, which should only be set
        # for "frozen" py2exe .exe's; this causes problems with multiprocessing, so delete it
        try:
            del sys.frozen
        except AttributeError: pass

    if phase:
        phases = (phase,)
    # Set reasonable defaults for the search phases
    else:
        # If each guess is very slow, separate out the first two phases
        passwords_per_seconds = loaded_wallet.passwords_per_seconds(1)
        if passwords_per_seconds < 25:
            phases = [ dict(typos=1), dict(typos=2, min_typos=2) ]
        else:
            phases = [ dict(typos=2) ]
        #
        # These two phases are added to all searches
        phases.extend(( dict(typos=1, big_typos=1), dict(typos=2, big_typos=1, min_typos=2) ))
        #
        # Add a final more thorough phase if it's not likely to take more than a few hours
        if len(mnemonic_ids_guess) <= 13 and passwords_per_seconds >=  750 or \
           len(mnemonic_ids_guess) <= 19 and passwords_per_seconds >= 2500:
            phases.append(dict(typos=3, big_typos=1, min_typos=3, extra_args=["--no-dupchecks"]))

    for phase_num, phase_params in enumerate(phases, 1):

        # Print a friendly message describing this phase's search settings
        print("Phase {}/{}: ".format(phase_num, len(phases)), end="")
        if phase_params["typos"] == 1:
            print("1 mistake", end="")
        else:
            print("up to {} mistakes".format(phase_params["typos"]), end="")
        if phase_params.get("big_typos"):
            if phase_params["big_typos"] == phase_params["typos"] == 1:
                print(" which can be an entirely different seed word.")
            else:
                print(", {} of which can be an entirely different seed word.".format(phase_params["big_typos"]))
        else:
            print(", excluding entirely different seed words.")

        # Perform this phase's search
        phase_params.setdefault("extra_args", []).extend(extra_args)
        mnemonic_found = run_btcrecover(**phase_params)

        if mnemonic_found:
            return " ".join(loaded_wallet.id_to_word(i) for i in mnemonic_found).decode("utf_8")
        elif mnemonic_found is None:
            return None  # An error occurred or Ctrl-C was pressed inside btcrpass.main()
        else:
            print("Seed not found" + ( ", sorry..." if phase_num==len(phases) else "" ))

    return False  # No error occurred; the mnemonic wasn't found

def show_mnemonic_gui(mnemonic_sentence):
    """may be called *after* main() to display the successful result iff the GUI is in use

    :param mnemonic_sentence: the mnemonic sentence that was found
    :type mnemonic_sentence: unicode
    :rtype: None
    """
    assert tk_root
    global pause_at_exit
    padding = 6
    tk.Label(text="WARNING: seed information is sensitive, carefully protect it and do not share", fg="red") \
        .pack(padx=padding, pady=padding)
    tk.Label(text="Seed found:").pack(side=tk.LEFT, padx=padding, pady=padding)
    entry = tk.Entry(width=80, readonlybackground="white")
    entry.insert(0, mnemonic_sentence)
    entry.config(state="readonly")
    entry.select_range(0, tk.END)
    entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=padding, pady=padding)
    tk_root.deiconify()
    tk_root.lift()
    entry.focus_set()
    tk_root.mainloop()  # blocks until the user closes the window
    pause_at_exit = False
