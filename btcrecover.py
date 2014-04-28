#!/usr/bin/python

# btcrecover.py -- Bitcoin wallet password recovery tool
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

# TODO: Unicode support? just permit 8-bit characters?
# TODO: convert to a proper importable module; clean up globals
# TODO: unit tests
# TODO: pythonize comments/documentation

# (all futures as of 2.6 and 2.7 except unicode_literals)
from __future__ import print_function, absolute_import, division, \
                       generators, nested_scopes, with_statement

__version__          = "0.5.8"
__ordering_version__ = "0.5.0"  # must be updated whenever password ordering changes

import sys, argparse, itertools, string, re, multiprocessing, signal, os, os.path, \
       cPickle, gc, time, hashlib, collections, base64, struct, ast, atexit, zlib, functools

# The progressbar module is recommended but optional; it is typically
# distributed with btcrecover (it is loaded later on demand)

# The pywin32 module is also recommended on Windows but optional; it's only
# used to adjust the process priority to be more friendly and to catch more
# signals (other than just Ctrl-C) for better autosaves. When used with
# Armory, btcrecover will just load the version that ships with Armory.


############################## Configurables/Plugins ##############################
# wildcard sets, simple typo generators, and wallet support functions


# Recognized wildcard (e.g. %d, %a) types mapped to their associated sets
# of characters; used in expand_wildcards_generator()
# warning: don't use digits, 'i', '[', or ',' as the key for a wildcard set
wildcard_sets = {
    "d" : string.digits,
    "a" : string.lowercase,
    "A" : string.uppercase,
    "n" : string.lowercase + string.digits,
    "N" : string.uppercase + string.digits,
    # wildcards can be used to escape these special symbols
    "%" : "%",
    "^" : "^",
    "S" : "$"  # the key is intentionally a capital "S", the value is a dollar sign
}
wildcard_keys = "".join(wildcard_sets)
#
# case-insensitive versions (e.g. %ia) of wildcard_sets for those which have them
wildcard_nocase_sets = {
    "a" : string.lowercase + string.uppercase,
    "A" : string.uppercase + string.lowercase,
    "n" : string.lowercase + string.uppercase + string.digits,
    "N" : string.uppercase + string.lowercase + string.digits
}


# Simple typo generators produce (as an iterable, e.g. a tuple, generator, etc.)
# zero or more alternative typo strings which can replace a single character. If
# more than one string is produced, all combinations are tried. If zero strings are
# produced (e.g. an empty tuple), then the specified input character has no typo
# alternatives that can be tried (e.g. you can't change the case of a caseless char).
# They are called with the full password and an index into that password of the
# character which will be replaced.
#
def typo_repeat(p, i): return (2 * p[i],)  # a single replacement of len 2
def typo_delete(p, i): return ("",)        # s single replacement of len 0
def typo_case(p, i):
    swapped = p[i].swapcase()
    return (swapped,) if swapped != p[i] else ()
def typo_closecase(p, i):  # (case_id functions defined in the Password Generation section)
    cur_case_id = case_id_of(p[i])
    if cur_case_id == UNCASED_ID: return ()
    if i==0 or i+1==len(p) or \
       case_id_changed(case_id_of(p[i-1]), cur_case_id) or \
       case_id_changed(case_id_of(p[i+1]), cur_case_id):  return (p[i].swapcase(),)
    return ()
def typo_append_wildcard(p, i):  return [p[i]+e for e in typos_insert_expanded]
def typo_replace_wildcard(p, i): return [e      for e in typos_replace_expanded if e != p[i]]
def typo_map(p, i):              return typos_map.get(p[i], ())
# (typos_insert_expanded and typos_replace_expanded are initialized from
# args.typos_insert and args.typos_replace respectively in the Password
# Generation section. typos_map is initialized in the Argument Parsing section)
#
# Dict: command line argument name is: "typos-" + key_name; associated value is
# the generator function from above; this dict MUST BE ORDERED to prevent the
# breakage of --skip and --restore features (the order can be arbitrary, but it
# MUST be repeatable across runs and preferably across implementations)
simple_typos = collections.OrderedDict()
simple_typos["repeat"]    = typo_repeat
simple_typos["delete"]    = typo_delete
simple_typos["case"]      = typo_case
simple_typos["closecase"] = typo_closecase
simple_typos["insert"]    = typo_append_wildcard
simple_typos["replace"]   = typo_replace_wildcard
simple_typos["map"]       = typo_map
#
# Dict: typo name (matches typo names in the dict above) mapped to the options
# that are passed to add_argument; this dict is only ordered for cosmetic reasons
simple_typo_args = collections.OrderedDict()
simple_typo_args["repeat"]    = dict( action="store_true",       help="repeats (doubles) a character" )
simple_typo_args["delete"]    = dict( action="store_true",       help="deletes a character" )
simple_typo_args["case"]      = dict( action="store_true",       help="changes the case (upper/lower) of a letter" )
simple_typo_args["closecase"] = dict( action="store_true",       help="like --typos-case, but only changes letters next to one with a different case")
simple_typo_args["insert"]    = dict( metavar="WILDCARD-STRING", help="inserts a string or wildcard" )
simple_typo_args["replace"]   = dict( metavar="WILDCARD-STRING", help="replaces a character with another string or wildcard" )
simple_typo_args["map"]       = dict( metavar="FILE", type=argparse.FileType('r'), help="replaces specific characters based on a map file" )


# TODO: work on wallet "plugin" interface; via subclassing?
wallet = None

# Given a filename, determines the wallet type and calls a function to load
# a wallet library, the wallet, and set the measure_performance_iterations
# global to result in about 0.5 seconds worth of iterations. Also sets the
# return_verified_password_or_false global to point to the correct function
# for the discovered wallet type.
def load_wallet(wallet_filename):
    global return_verified_password_or_false

    with open(wallet_filename, "rb") as wallet_file:

        # Armory
        if wallet_file.read(8) == b"\xbaWALLET\x00":  # Armory magic
            wallet_file.close()
            load_armory_wallet(wallet_filename)  # passing in a filename
            return_verified_password_or_false = return_armory_verified_password_or_false
            return

        # Bitcoin Core
        wallet_file.seek(12)
        if wallet_file.read(8) == b"\x62\x31\x05\x00\x09\x00\x00\x00":  # BDB magic, Btree v9
            wallet_file.close()
            load_bitcoincore_wallet(wallet_filename)  # passing in a filename
            return_verified_password_or_false = return_bitcoincore_verified_password_or_false
            return

        # MultiBit private key backup file (not the wallet file)
        wallet_file.seek(0)
        try:    is_multibitpk = base64.b64decode(wallet_file.read(20).lstrip()[:12]).startswith(b"Salted__")
        except: is_multibitpk = False
        if is_multibitpk:
            load_multibit_privkey_file(wallet_file)  # passing in a file object
            return_verified_password_or_false = return_multibitpk_verified_password_or_false
            return

        # Electrum
        wallet_file.seek(0)
        if wallet_file.read(2) == b"{'":  # best we can easily do short of just trying to load it
            try:
                load_electrum_wallet(wallet_file)  # passing in a file object
                return_verified_password_or_false = return_electrum_verified_password_or_false
                return
            except SyntaxError: pass     # probably wasn't an electrum wallet
            except: raise

        print(parser.prog+": error: unrecognized wallet format", file=sys.stderr)
        sys.exit(2)


# Given a key_data blob that was extracted by one of the extract-* scripts,
# determines the wallet type and calls a function to load a wallet library,
# the key, and set the measure_performance_iterations global to result in
# about 0.5 seconds worth of iterations. Also sets the
# return_verified_password_or_false global to point to the correct function
# for the discovered key type. (This can be called instead of load_wallet() )
def load_from_key(key_data):
    global return_verified_password_or_false
    key_type = key_data[:3]

    if key_type == b"ar:":
        load_armory_from_privkey(key_data[3:])
        return_verified_password_or_false = return_armorypk_verified_password_or_false
        return

    if key_type == b"bc:":
        load_bitcoincore_from_mkey(key_data[3:])
        return_verified_password_or_false = return_bitcoincore_verified_password_or_false
        return

    if key_type == b"mb:":
        load_multibit_from_privkey(key_data[3:])
        return_verified_password_or_false = return_multibitpk_verified_password_or_false
        return

    # TODO: Electrum support (not sure if it's even possible?)

    print(parser.prog+": error: unrecognized encrypted key type", file=sys.stderr)
    sys.exit(2)


def load_armory_library():
    global measure_performance_iterations, armoryengine, SecureBinaryData, KdfRomix
    measure_performance_iterations = 2

    # Try to add the Armory libraries to the path for various platforms
    if sys.platform == "win32":
        win32_path = os.environ.get("ProgramFiles",  r"C:\Program Files (x86)") + r"\Armory"
        sys.path.extend((win32_path, win32_path + r"\library.zip"))
    elif sys.platform.startswith("linux"):
        sys.path.append("/usr/lib/armory")
    elif sys.platform == "darwin":  # untested
        sys.path.append("/Applications/Armory.app/Contents/MacOS/py/usr/lib/armory")

    # Temporarily blank out argv before importing the armoryengine, otherwise it attempts to process argv
    old_argv = sys.argv[1:]
    del sys.argv[1:]

    # Try up to 10 times to load Armory (there's a race condition on opening the log file in Windows multiprocessing)
    for i in xrange(10):
        try: import armoryengine.PyBtcWallet, armoryengine.PyBtcAddress
        except IOError as e:
            if i<9 and e.filename.endswith(r"\armorylog.txt"): time.sleep(0.1)
            else: raise  # unexpected failure
        else: break  # when it succeeds
    from CppBlockUtils import SecureBinaryData, KdfRomix  # (also a part of Armory)

    sys.argv[1:] = old_argv  # restore the command line

# Load the Armory wallet file given the filename
def load_armory_wallet(wallet_filename):
    global wallet
    load_armory_library()
    wallet = armoryengine.PyBtcWallet.PyBtcWallet().readWalletFile(wallet_filename)

# This is the time-consuming function executed by worker thread(s):
# if a password is correct, return it, else return false
def return_armory_verified_password_or_false(p):
    if wallet.verifyPassphrase(SecureBinaryData(p)): return p
    else: return False

# Import an Armory private key that was extracted by extract-armory-privkey.py
def load_armory_from_privkey(privkey_data):
    global wallet
    load_armory_library()
    address = armoryengine.PyBtcAddress.PyBtcAddress().createFromEncryptedKeyData(
        privkey_data[:20],                      # address (160 bit hash)
        SecureBinaryData(privkey_data[20:52]),  # encrypted private key
        SecureBinaryData(privkey_data[52:68])   # initialization vector
    )
    bytes_reqd, iter_count = struct.unpack("< I I", privkey_data[68:76])
    kdf = KdfRomix(bytes_reqd, iter_count, SecureBinaryData(privkey_data[76:]))  # kdf args and seed
    wallet = address, kdf

# This is the time-consuming function executed by worker thread(s):
# if a password is correct, return it, else return false
def return_armorypk_verified_password_or_false(p):
    address, kdf = wallet
    if address.verifyEncryptionKey(kdf.DeriveKey(SecureBinaryData(p))): return p
    else:
        address.binPublicKey65 = SecureBinaryData()  # work around bug in verifyEncryptionKey in Armory 0.91
        return False


# Load a Bitcoin Core BDB wallet file given the filename and extract the first encrypted master key
def load_bitcoincore_wallet(wallet_filename):
    global measure_performance_iterations, wallet
    load_aes256_library()
    measure_performance_iterations = 5  # load_aes256_library sets this, but it's changed here
    import bsddb.db
    db_env = bsddb.db.DBEnv()
    db_env.open(os.path.dirname(wallet_filename), bsddb.db.DB_CREATE | bsddb.db.DB_INIT_MPOOL)
    db = bsddb.db.DB(db_env)
    db.open(wallet_filename, b"main", bsddb.db.DB_BTREE, bsddb.db.DB_RDONLY)
    mkey = db.get(b"\x04mkey\x01\x00\x00\x00")
    db.close()
    db_env.close()
    if not mkey:
        raise ValueError("Encrypted master key #1 not found in the Bitcoin Core wallet file.\n"+
                         "(is this wallet encrypted? is this a standard Bitcoin Core wallet?)")
    # This is a little fragile because it assumes the encrypted key and salt sizes are
    # 48 and 8 bytes long respectively, which although currently true may not always be
    # (it will loudly fail if this isn't the case; if smarter it could gracefully succeed):
    encrypted_master_key, salt, method, iter_count = struct.unpack_from("< 49p 9p I I", mkey)
    if method != 0: raise NotImplementedError("Unsupported Bitcoin Core key derivation method " + str(method))
    wallet = encrypted_master_key, salt, iter_count

# Import a Bitcoin Core encrypted master key that was extracted by extract-mkey.py
def load_bitcoincore_from_mkey(mkey_data):
    global measure_performance_iterations, wallet
    load_aes256_library()
    measure_performance_iterations = 5  # load_aes256_library sets this, but it's overwritten here
    # These are the same encrypted_master_key, salt, iter_count retrieved by load_bitcoincore_wallet()
    wallet = struct.unpack("< 48s 8s I", mkey_data)

# This is the time-consuming function executed by worker thread(s):
# if a password is correct, return it, else return false
def return_bitcoincore_verified_password_or_false(p):
    encrypted_master_key, salt, iter_count = wallet
    derived_key_iv = p + salt
    for i in xrange(iter_count):
        derived_key_iv = hashlib.sha512(derived_key_iv).digest()
    master_key = aes256_cbc_decrypt(derived_key_iv[0:32], derived_key_iv[32:48], encrypted_master_key)
    # If the 48 byte encrypted_master_key decrypts to exactly 32 bytes long (padded with 16 16s), we've found it
    if master_key.endswith(b"\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10"): return p
    else: return False


# Load a Multibit private key backup file (the part of it we need) given an opened file object
def load_multibit_privkey_file(privkey_file):
    global wallet
    load_aes256_library()
    privkey_file.seek(0)
    # Multibit privkey files contain base64 text split into multiple lines;
    # we need the first 32 bytes after decoding, which translates to 44 before.
    wallet = "".join(privkey_file.read(50).split())  # join multiple lines into one
    if len(wallet) < 44: raise EOFError("Expected at least 44 bytes of text in the MultiBit private key file")
    wallet = base64.b64decode(wallet[:44])
    assert wallet.startswith(b"Salted__"), "loaded a Multibit privkey file"
    if len(wallet) < 32:  raise EOFError("Expected at least 32 bytes of decoded data in the MultiBit private key file")
    wallet = wallet[8:32]
    # wallet now consists of:
    #   8 bytes of salt, followed by
    #   1 16-byte encrypted aes block containing the first 16 base58 chars of a 52-char encoded private key

# Import a MultiBit private key that was extracted by extract-multibit-privkey.py
def load_multibit_from_privkey(privkey_data):
    global wallet
    load_aes256_library()
    wallet = privkey_data

# This is the function executed by worker thread(s):
# if a password is correct, return it, else return false
def return_multibitpk_verified_password_or_false(p):
    salted = p + wallet[:8]
    key1   = hashlib.md5(salted).digest()
    key2   = hashlib.md5(key1 + salted).digest()
    iv     = hashlib.md5(key2 + salted).digest()
    b58_privkey = aes256_cbc_decrypt(key1 + key2, iv, wallet[8:])
    # If it looks like a base58 private key, we've found it
    # (there's a 1 in 600 billion chance this hits but the password is wrong)
    # (may be fragile, e.g. what if comments or whitespace precede the first key in future MultiBit versions?)
    if (b58_privkey[0] == b"L" or b58_privkey[0] == b"K") and \
        re.match(r"[LK][1-9A-HJ-NP-Za-km-z]{15}", b58_privkey):
            return p
    return False


# Load an Electrum wallet file (the part of it we need) given an opened file object
def load_electrum_wallet(wallet_file):
    global wallet
    load_aes256_library()
    wallet_file.seek(0)
    wallet = ast.literal_eval(wallet_file.read(1048576))  # up to 1M, typical size is a few k
    seed_version = wallet.get("seed_version")
    if seed_version is None:             raise ValueError("Unrecognized wallet format (Electrum seed_version not found)")
    if seed_version != 4:                raise NotImplementedError("Unsupported Electrum seed version " + seed_version)
    if not wallet.get("use_encryption"): raise ValueError("Electrum wallet is not encrypted")
    wallet = base64.b64decode(wallet["seed"])
    if len(wallet) != 64:                raise ValueError("Electrum encrypted seed plus iv is not 64 bytes long")

# This is the function executed by worker thread(s):
# if a password is correct, return it, else return false
def return_electrum_verified_password_or_false(p):
    key  = hashlib.sha256( hashlib.sha256( p ).digest() ).digest()
    seed = aes256_cbc_decrypt(key, wallet[:16], wallet[16:])
    # If the 48 byte encrypted seed decrypts to exactly 32 bytes long (padded with 16 16s), we've found it
    if seed.endswith(b"\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10"): return p
    else: return False


# Loads PyCrypto if available, else falls back to the pure python version (30x slower)
def load_aes256_library():
    global Crypto, aespython, aes256_cbc_decrypt, aes256_key_expander, measure_performance_iterations
    try:
        import Crypto.Cipher.AES
        aes256_cbc_decrypt = aes256_cbc_decrypt_pycrypto
        measure_performance_iterations = 50000
    except ImportError:
        import aespython.key_expander, aespython.aes_cipher, aespython.cbc_mode
        aes256_cbc_decrypt = aes256_cbc_decrypt_pp
        aes256_key_expander = aespython.key_expander.KeyExpander(256)
        measure_performance_iterations = 2000

# Input must be a multiple of 16 bytes; does not strip any padding
def aes256_cbc_decrypt_pycrypto(key, iv, ciphertext):
    return Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_CBC, iv).decrypt(ciphertext)

# Input must be a multiple of 16 bytes; does not strip any padding.
# This version is attributed to GitHub user serprex; please see the aespython
# README.txt for more information. It measures over 30x faster than the more
# common "slowaes" package (although it's still 30x slower than the PyCrypto)
def aes256_cbc_decrypt_pp(key, iv, ciphertext):
    block_cipher  = aespython.aes_cipher.AESCipher( aes256_key_expander.expand(map(ord, key)) )
    stream_cipher = aespython.cbc_mode.CBCMode(block_cipher, 16)
    stream_cipher.set_iv(bytearray(iv))
    plaintext = bytearray()
    for i in xrange(0, len(ciphertext), 16):
        plaintext.extend( stream_cipher.decrypt_block(map(ord, ciphertext[i:i+16])) )  # input must be a list
    return str(plaintext)


############################## Argument Parsing ##############################


# Returns an (order preserved) list or string with duplicate elements removed
# (if input is a string, returns a string, otherwise returns a list)
# (N.B. not a generator function, so faster for small inputs, not for large)
def remove_duplicates(iterable):
    seen = set()
    unique = []
    for x in iterable:
        if x not in seen:
            unique.append(x)
            seen.add(x)
    if isinstance(iterable, str):
        return "".join(unique) if len(unique) < len(iterable) else iterable
    return unique

# Converts a wildcard set into a string, expanding ranges and removing duplicates,
# e.g.: "hexa-fA-F" -> "hexabcdfABCDEF"
def build_wildcard_set(set_string):
    return remove_duplicates(re.sub(r"(.)-(.)", expand_single_range, set_string))
#
def expand_single_range(m):
    char_first, char_last = map(ord, m.groups())
    if char_first > char_last: raise ValueError("first char > last char in wildcard range")
    return "".join(map(chr, xrange(char_first, char_last+1)))

# Returns a count of valid wildcards in the string, or -1 if any invalid wildcards are present
# (see expand_wildcards_generator() for more details on wildcards)
def count_valid_wildcards(str_with_wildcards):
    # Remove all valid wildcards; if any %'s are left they are invalid
    valid_wildcards_removed, count = re.subn(r"%(?:(?:\d+,)?\d+)?(?:i)?(?:["+wildcard_keys+"]|\[.+?\])", "", str_with_wildcards)
    if "%" in valid_wildcards_removed: return -1
    if count == 0:                     return  0
    # Expand any custom wildcard sets for the sole purpose of checking for exceptions (e.g. %[z-a])
    # We know all wildcards present have valid syntax, so we don't need to use the full regex, but
    # we do need to capture %% to avoid seeing this as a wildcard set (it isn't one): %%[not-a-set]
    for wildcard_set in re.findall(r"%[\d,i]*\[(.+?)\]|%%", str_with_wildcards):
        if wildcard_set:
            try:
                re.sub(r"(.)-(.)", expand_single_range, wildcard_set)
            except ValueError: return -1
            except: raise
    return count

pause_registered = None
def enable_pause():
    global pause_registered
    if pause_registered is None:
        if sys.stdin.isatty():
            atexit.register(lambda: raw_input("Press Enter to exit ..."))
            pause_registered = True
        else:
            print(parser.prog+": warning: ignoring --pause since stdin is not interactive (or was redirected)", file=sys.stderr)
            pause_registered = False


if __name__ == '__main__':

    # can raise exceptions on some platforms
    try:    cpus = multiprocessing.cpu_count()
    except: cpus = 1

    parser = argparse.ArgumentParser()
    parser.add_argument("--wallet",      metavar="FILE", help="the wallet file (this or --mkey or --listpass req'd)")
    parser.add_argument("--tokenlist",   metavar="FILE", help="the list of tokens/partial passwords (required)")
    parser.add_argument("--max-tokens",  type=int, default=sys.maxint, metavar="COUNT", help="enforce a max # of tokens included per guess")
    parser.add_argument("--min-tokens",  type=int, default=1, metavar="COUNT", help="enforce a min # of tokens included per guess")
    parser.add_argument("--typos",       type=int, default=0, metavar="COUNT", help="simulate up to this many typos; you must choose one or more typo types from the list below")
    parser.add_argument("--min-typos",   type=int, default=0, metavar="COUNT", help="enforce a min # of typos included per guess")
    typo_types_group = parser.add_argument_group("typo types")
    typo_types_group.add_argument("--typos-capslock", action="store_true", help="tries the password with caps lock turned on")
    typo_types_group.add_argument("--typos-swap",     action="store_true", help="swaps two adjacent characters")
    for typo_name, typo_args in simple_typo_args.items():
        typo_types_group.add_argument("--typos-"+typo_name, **typo_args)
    parser.add_argument("--custom-wild", metavar="STRING", help="a custom set of characters for the %%c wildcard")
    parser.add_argument("--regex-only",  metavar="STRING", help="only try passwords which match the given regular expr")
    parser.add_argument("--regex-never", metavar="STRING", help="never try passwords which match the given regular expr")
    parser.add_argument("--delimiter",   metavar="STRING", help="the delimiter for multiple alternative tokens on each line of the tokenlist (default: whitespace)")
    parser.add_argument("--skip",        type=int, default=0, metavar="COUNT", help="skip this many initial passwords for continuing an interrupted search")
    parser.add_argument("--autosave",    metavar="FILE",   help="autosaves (5 min) progress to/ restores it from a file")
    parser.add_argument("--restore",     type=argparse.FileType("r+b", 0), metavar="FILE", help="restores progress and options from an autosave file (must be the only option on the command line)")
    parser.add_argument("--threads",     type=int, default=cpus, metavar="COUNT", help="number of worker threads (default: number of CPUs, "+str(cpus)+")")
    parser.add_argument("--worker",      metavar="ID#/TOTAL#", help="divide the workload between TOTAL# servers, where each has a different ID# between 1 and TOTAL#")
    parser.add_argument("--max-eta",     type=int, default=168,  metavar="HOURS", help="max estimated runtime before refusing to even start (default: 168 hours, i.e. 1 week)")
    parser.add_argument("--no-dupchecks",action="store_true", help="disable duplicate guess checking to save memory")
    parser.add_argument("--no-progress", action="store_true", default=not sys.stdout.isatty(), help="disable the progress bar")
    parser.add_argument("--mkey",        action="store_true", help="prompt for a Bitcoin Core encrypted master key (from extract-mkey.py) instead of using a wallet file")
    parser.add_argument("--privkey",     action="store_true", help="prompt for an encrypted private key (from extract-*-privkey.py) instead of using a wallet file")
    parser.add_argument("--listpass",    action="store_true", help="just list all password combinations and exit")
    parser.add_argument("--pause",       action="store_true", help="pause before exiting")
    parser.add_argument("--version",     action="version",    version="%(prog)s " + __version__)

    # effective_argv is what we are effectively given, either via the command line, via embedded
    # options in the tokenlist file, or as a result of restoring a session, before any argument
    # processing or defaulting is done (unless it's is done by argparse). Each time effective_argv
    # is changed (due to reading a tokenlist or restore file), we redo parser.parse_args() which
    # overwrites args, so we only do this early on before any real args processing takes place.
    effective_argv = sys.argv[1:]
    args = parser.parse_args()

    # Do this as early as possible so user doesn't miss any error messages
    if args.pause: enable_pause()

    # If we're not --restoring, open the tokenlist_file now (if we are restoring,
    # we don't know what to open until after the restore data is loaded)
    tokenlist_file = None
    if not args.restore:
        if args.tokenlist:                                 tokenlist_file = open(args.tokenlist)
        elif os.path.isfile("btcrecover-tokens-auto.txt"): tokenlist_file = open("btcrecover-tokens-auto.txt")

    # If the first line of the tokenlist file starts with exactly "#--", parse it as additional arguments
    # (note that command line arguments can override arguments in this file)
    if tokenlist_file:
        if tokenlist_file.read(3) == "#--":  # TODO: Unicode BOM breaks this
            print("Reading additional options from tokenlist file '"+tokenlist_file.name+"'", file=sys.stderr)
            tokenlist_args = ("--"+tokenlist_file.readline()).split()  # TODO: support quoting / escaping?
            for arg in tokenlist_args:
                if arg.startswith("--to"):  # --tokenlist
                    print(parser.prog+": error: the --tokenlist option is not permitted inside a tokenlist file", file=sys.stderr)
                    sys.exit(2)
            effective_argv = tokenlist_args + effective_argv  # prepend them so that real argv takes precedence
            args = parser.parse_args(effective_argv)          # reparse the arguments
            # Check this again as early as possible so user doesn't miss any error messages
            if args.pause: enable_pause()
        tokenlist_file.seek(0)  # reset to beginning of file

    # There are two ways to restore from an autosave file: either specify --restore (alone)
    # on the command line in which case the saved arguments completely replace everything else,
    # or specify --autosave along with the exact same arguments as are in the autosave file.
    #
    if args.restore:  # Load and completely replace current arguments
        if len(effective_argv) > 2 or "=" in effective_argv[0] and len(effective_argv) > 1:
            print(parser.prog+": error: the --restore option must be the only option when used", file=sys.stderr)
            sys.exit(2)
        autosave_file = args.restore        # reuse the restore file as the new autosave file
        savestate = cPickle.load(autosave_file)
        effective_argv = savestate["argv"]  # argv is effectively being replaced; it's reparsed below
        print("Restoring session:", " ".join(effective_argv))
        print("Last session ended having finished password #", savestate["skip"])
        args = parser.parse_args(effective_argv)
        # Check this again as early as possible so user doesn't miss any error messages
        if args.pause: enable_pause()
        # If the order of passwords generated has changed since the last version, don't permit a restore
        if __ordering_version__ != savestate.get("ordering_version"):
            print(parser.prog+": error: autosave was created with an incompatible version of "+parser.prog, file=sys.stderr)
            sys.exit(2)
        assert args.autosave, "autosave option enabled in restored autosave file"
        #
        # We finally know the tokenlist filename; open it here
        if args.tokenlist:                                 tokenlist_file = open(args.tokenlist)
        elif os.path.isfile("btcrecover-tokens-auto.txt"): tokenlist_file = open("btcrecover-tokens-auto.txt")
        if tokenlist_file:
            if tokenlist_file.read(3) == "#--":
                print(parser.prog+": warning: all options loaded from restore file; ignoring options in tokenlist file '"+tokenlist_file.name+"'", file=sys.stderr)
            tokenlist_file.seek(0)
        print("Using autosave file '"+autosave_file.name+"'")
        args.skip = savestate["skip"]       # override this with the most recent value
        restored = True   # a global flag for future reference
    #
    elif args.autosave and os.path.isfile(args.autosave) and os.path.getsize(args.autosave) > 0:  # Load and compare to current arguments
        autosave_file = open(args.autosave, "r+b", 0)
        savestate = cPickle.load(autosave_file)
        restored_argv = savestate["argv"]
        print("Restoring session:", " ".join(restored_argv))
        print("Last session ended having finished password #", savestate["skip"])
        if restored_argv != effective_argv:  # TODO: be more lenient than an exact match?
            print(parser.prog+": error: can't restore previous session: the command line options have changed", file=sys.stderr)
            sys.exit(2)
        # If the order of passwords generated has changed since the last version, don't permit a restore
        if __ordering_version__ != savestate.get("ordering_version"):
            print(parser.prog+": error: autosave was created with an incompatible version of "+parser.prog, file=sys.stderr)
            sys.exit(2)
        print("Using autosave file '"+args.autosave+"'")
        args.skip = savestate["skip"]  # override this with the most recent value
        restored = True   # a global flag for future reference
    #
    else:
        restored = False  # a global flag for future reference

    argsdict = vars(args)  # only used to check for presence of typos_* arguments

    # Do a bunch of argument sanity checking

    # tokenlist_file should have been opened by now (possibly during the a session restore)
    if not tokenlist_file:
        print(parser.prog+": error: argument --tokenlist is required (or file btcrecover-tokens-auto.txt must be present)", file=sys.stderr)
        sys.exit(2)

    if args.max_tokens < args.min_tokens:
        print(parser.prog+": error: --max-tokens is less than --min-tokens", file=sys.stderr)
        sys.exit(2)

    # Have _any_ typo types been specified?
    simple_typo_types_specified = False
    for typo_name in simple_typos:
        if argsdict.get("typos_"+typo_name):
            simple_typo_types_specified = True
            break
    # also check other typo types which aren't "simple" typos
    any_typo_types_specified = simple_typo_types_specified or args.typos_capslock or args.typos_swap

    if args.typos and not any_typo_types_specified:
        print(parser.prog+": warning: --typos has no effect because no type of typo was chosen", file=sys.stderr)
    elif args.min_typos and not any_typo_types_specified:
        print(parser.prog+": warning: --min-typos has no effect because no type of typo was chosen", file=sys.stderr)

    if any_typo_types_specified and not args.typos:
        if args.min_typos:
            print(parser.prog+": warning: --typos COUNT not specified or 0; assuming same as --min_typos ("+str(args.min_typos)+")", file=sys.stderr)
            args.typos = args.min_typos
        else:
            print(parser.prog+": warning: --typos COUNT not specified or 0; assuming 1", file=sys.stderr)
            args.typos = 1

    if args.typos < args.min_typos:
        print(parser.prog+": error: --typos is less than --min_typos", file=sys.stderr)
        sys.exit(2)

    if args.typos_closecase and args.typos_case:
        print(parser.prog+": warning: disabling --typos-closecase because --typos-case was also specified", file=sys.stderr)
        args.typos_closecase = None

    # Parse the custom wildcard set option
    if args.custom_wild:
        for c in args.custom_wild:
            if ord(c) > 127:
                print(parser.prog+": error: --custom_wild has non-ASCII character '"+c+"'", file=sys.stderr)
                sys.exit(2)
        custom_set_built   = build_wildcard_set(args.custom_wild)
        wildcard_sets["c"] = custom_set_built  # (duplicates already removed by build_wildcard_set)
        wildcard_sets["C"] = remove_duplicates(custom_set_built.upper())
        # If there are any case-sensitive letters in the set, build the case-insensitive versions
        custom_set_caseswapped = custom_set_built.swapcase()
        if custom_set_caseswapped != custom_set_built:
            wildcard_nocase_sets["c"] = remove_duplicates(custom_set_built + custom_set_caseswapped)
            wildcard_nocase_sets["C"] = wildcard_nocase_sets["c"].swapcase()
        wildcard_keys += "cC"  # keep track of available wildcard types (this is used in regex's)

    regex_only  = re.compile(args.regex_only)  if args.regex_only  else None
    regex_never = re.compile(args.regex_never) if args.regex_never else None

    # Syntax check any --typos-insert wildcard (it's expanded later in the Password Generation section)
    if args.typos_insert:
        if count_valid_wildcards(args.typos_insert) == -1:
            print(parser.prog+": error: --typos-insert", args.typos_insert, "has an invalid wildcard (%) spec", file=sys.stderr)
            sys.exit(2)
    # Syntax check any --typos-replace wildcard (it's expanded later in the Password Generation section)
    if args.typos_replace:
        if count_valid_wildcards(args.typos_replace) == -1:
            print(parser.prog+": error: --typos-replace", args.typos_replace, "has an invalid wildcard (%) spec", file=sys.stderr)
            sys.exit(2)

    # Process any --typos-map file: build a dict (typos_map) mapping replaceable characters to their replacements
    typos_map_hash = None
    if args.typos_map:
        typos_map = dict()
        for line_num, line in enumerate(args.typos_map, 1):
            if line[0] == "#": continue  # ignore comments
            #
            # Remove the trailing newline, then split the line exactly
            # once on the specified delimiter (default: whitespace)
            split_line = line.rstrip("\r\n").split(args.delimiter, 1)
            if len(split_line) == 0: continue  # ignore empty lines
            if len(split_line) == 1:
                print("--typos-map file has an empty replacement list on line", line_num)
                sys.exit(2)
            if args.delimiter is None: split_line[1] = split_line[1].rstrip()  # ignore trailing whitespace by default
            for c in "".join(split_line):
                if ord(c) > 127:
                    print(parser.prog+": error: --typos-map file has non-ASCII character '"+c+"' on line", line_num, file=sys.stderr)
                    sys.exit(2)
            replacements = remove_duplicates(split_line[1])
            for c in split_line[0]:
                if c in replacements:
                    typos_map[c] = filter(lambda r: r != c, replacements)
                else:
                    typos_map[c] = replacements
        #
        # Take a hash of the typos_map and check it during a session restore
        # to make sure we're actually restoring the exact same session
        if args.autosave:
            sha1 = hashlib.sha1()
            for k in sorted(typos_map.keys()):  # must take the hash in a deterministic order (not in typos_map order)
                sha1.update(k + str(typos_map[k]))
            typos_map_hash = sha1.digest()
            sha1 = None
        if restored:
            if typos_map_hash != savestate["typos_map_hash"]:
                print(parser.prog+": error: can't restore previous session: the typos_map file has changed", file=sys.stderr)
                sys.exit(2)

    worker_threads = max(args.threads, 1)

    if args.worker:
        match = re.match(r"(\d+)/(\d+)$", args.worker)
        if not match:
            print(parser.prog+": error: --worker ID#/TOTAL# must be have the format uint/uint", file=sys.stderr)
            sys.exit(2)
        worker_id     = int(match.group(1))
        workers_total = int(match.group(2))
        if workers_total < 2:
            print(parser.prog+": error: in --worker ID#/TOTAL#, TOTAL# must be >= 2", file=sys.stderr)
            sys.exit(2)
        if worker_id < 1:
            print(parser.prog+": error: in --worker ID#/TOTAL#, ID# must be >= 1", file=sys.stderr)
            sys.exit(2)
        if worker_id > workers_total:
            print(parser.prog+": error: in --worker ID#/TOTAL#, ID# must be <= TOTAL#", file=sys.stderr)
            sys.exit(2)

    if args.no_progress: have_progress = False
    else:
        try:
            from progressbar import *
            have_progress = True
        except ImportError:
            have_progress = False

    # (move this into an argparse group?)
    required_args = 0
    if args.wallet:   required_args += 1
    if args.mkey:     required_args += 1
    if args.privkey:  required_args += 1
    if args.listpass: required_args += 1
    if required_args != 1:
        print(parser.prog+": error: argument --wallet (--listpass, --mkey, or --privkey, exactly one) is required", file=sys.stderr)
        sys.exit(2)

    # Load the wallet file
    if args.wallet:
        load_wallet(args.wallet)

    # Prompt for a Bitcoin Core encrypted master key or a private key instead of requiring
    # a wallet file (the only reason to treat these two differently is to emphasize that
    # privkeys once decrypted can "leak" Bitcoin, whereas mkeys without the wallet are safe)
    if args.mkey or args.privkey:
        # Make sure we don't have readline support (which could save keys in a history file)
        assert "readline" not in sys.modules, "readline not loaded during sensitive input"
        if args.privkey:
            # We could warn about wallet files too, but hopefully that's already obvious...
            print("WARNING: a complete private key, once decrypted, provides access to that key's Bitcoin", file=sys.stderr)
        if sys.stdin.isatty():
            prompt = "Please enter the encrypted key data from the extract script\n> "
        else:
            prompt = "Reading encrypted key data from stdin\n"
        key_crc_data = base64.b64decode(raw_input(prompt))
        # If stdin was redirected, close it so we don't keep the file alive while running
        if not sys.stdin.isatty():
            sys.stdin.close()    # this doesn't really close the fd
            try:    os.close(0)  # but this should, where supported
            except: pass
        # Need to save key_data (in a global) for reinitializing worker
        # processes on windows, and key_crc (another global) for do_autosave()
        key_data   = key_crc_data[:-4]
        (key_crc,) = struct.unpack("<I", key_crc_data[-4:])
        if zlib.crc32(key_data) & 0xffffffff != key_crc:
            print(parser.prog+": error: encrypted key data is corrupted (failed CRC check)", file=sys.stderr)
            sys.exit(2)
        is_mkey = key_data.startswith("bc:")  # Bitcoin Core
        if args.mkey and not is_mkey:
            print(parser.prog+": error: the --mkey data is not a Bitcoin Core encrypted master key (might be a privkey?)", file=sys.stderr)
            sys.exit(2)
        if args.privkey and is_mkey:
            print(parser.prog+": error: the --privkey data is a Bitcoin Core encrypted mkey, not a privkey", file=sys.stderr)
            sys.exit(2)
        # Emulates load_wallet, but using key_data instead
        load_from_key(key_data)
        if restored and key_crc != savestate["key_crc"]:
            print(parser.prog+": error: can't restore previous session: the encrypted master key entered is not the same", file=sys.stderr)
            sys.exit(2)
    else:
        key_data = key_crc = None

    # Open a new autosave file (if --restore was specified, the restore file
    # is still open and has already been assigned to autosave_file instead)
    if args.autosave and not restored:
        if args.listpass:
            print(parser.prog+": warning: --autosave is ignored with --listpass", file=sys.stderr)

        # Don't overwrite nonzero files or nonfile objects (e.g. directories)
        if os.path.exists(args.autosave) and (os.path.getsize(args.autosave) > 0 or not os.path.isfile(args.autosave)):
            print(parser.prog+": error: --autosave file '"+args.autosave+"' already exists, won't overwrite", file=sys.stderr)
            sys.exit(2)
        autosave_file = open(args.autosave, "wb", 0)  # (0 == buffering is disabled)
        print("Using autosave file '"+args.autosave+"'")


############################## Tokenfile Parsing ##############################


# Build up the token_lists structure, a list of lists, reflecting the tokenlist file.
# Each list in the token_lists list is preceded with a None element unless the
# corresponding line in the tokenlist file begins with a "+" (see example below).
# Each token is represented by a string if that token is not anchored, or by an
# AnchoredToken object used to store the begin and end fields
#
# EXAMPLE FILE:
#     #   Lines that begin with # are ignored comments
#     #
#     an_optional_token_exactly_one_per_line...
#     ...may_or_may_not_be_tried_per_guess
#     #
#     mutually_exclusive  token_list  on_one_line  at_most_one_is_tried
#     #
#     +  this_required_token_was_preceded_by_a_plus_in_the_file
#     +  exactly_one_of_these  tokens_are_required  and_were_preceded_by_a_plus
#     #
#     ^if_present_this_is_at_the_beginning  if_present_this_is_at_the_end$
#     #
#     ^2$if_present_this_is_second ^5$if_present_this_is_fifth
#     #
#     ^2,4$if_present_its_second_third_or_fourth_(but_never_last)
#     ^2,$if_present_this_is_second_or_greater_(but_never_last)
#     ^,$exactly_the_same_as_above
#     ^,3$if_present_this_is_third_or_less_(but_never_first_or_last)
#
# RESULTANT token_lists ==
# [
#     [ None,  'an_optional_token_exactly_one_per_line...' ],
#     [ None,  '...may_or_may_not_be_tried_per_guess' ],
#
#     [ None,  'mutually_exclusive',  'token_list',  'on_one_line',  'at_most_one_is_tried' ],
#
#     [ 'this_required_token_was_preceded_by_a_plus_in_the_file' ],
#     [ 'exactly_one_of_these',  'tokens_are_required',  'and_were_preceded_by_a_plus' ],
#
#     [ AnchoredToken(begin=0), AnchoredToken(begin="$") ],
#
#     [ AnchoredToken(begin=1), AnchoredToken(begin=4) ],
#
#     [ AnchoredToken(begin=1, end=3) ],
#     [ AnchoredToken(begin=1, end=sys.maxint) ],
#     [ AnchoredToken(begin=1, end=sys.maxint) ],
#     [ AnchoredToken(begin=1, end=2) ]
# ]

@functools.total_ordering
class AnchoredToken:
    def __init__(self, token, line_num = "?"):
        if token[0] == "^":
            if token[-1] == "$":
                print(parser.prog+": error: token on line", line_num, "is anchored with both ^ at the beginning and $ at the end", file=sys.stderr)
                sys.exit(2)
            #
            # If it looks like it might be a positional or middle anchor
            if token[1] in "0123456789," or "$" in token:
                #
                # If it actually is a syntactically correct positional or middle anchor
                match = re.match(r"\^(?:(?P<begin>\d+)?(?P<range>,)(?P<end>\d+)?|(?P<pos>\d+))\$(?=.)", token)
                if match:
                    # If it's a middle (range) anchor
                    if match.group("range"):
                        self.begin = match.group("begin")
                        self.end   = match.group("end")
                        self.begin = 1          if self.begin is None else int(self.begin) - 1
                        self.end   = sys.maxint if self.end   is None else int(self.end)   - 1
                        if self.begin > self.end:
                            print(parser.prog+": error: anchor range of token on line", line_num, "is invalid (begin > end)", file=sys.stderr)
                            sys.exit(2)
                        if self.begin < 1:
                            print(parser.prog+": error: anchor range of token on line", line_num, "must begin with 2 or greater", file=sys.stderr)
                            sys.exit(2)
                        self.text = token[match.end():]
                    # Else it's a positional anchor
                    else:
                        self.begin = int(match.group("pos")) - 1
                        self.end   = None
                        if self.begin < 0:
                            print(parser.prog+": error: anchor position of token on line", line_num, "must be 1 or greater", file=sys.stderr)
                            sys.exit(2)
                        self.text = token[match.end():]
                #
                # If it's a begin anchor that looks a bit like some other type
                else:
                    print(parser.prog+": warning: token on line", line_num, "looks like it might be a positional anchor,\n" +
                          "but it can't be parsed correctly, so it's assumed to be a simple beginning anchor instead", file=sys.stderr)
                    self.begin = 0
                    self.end   = None
                    self.text  = token[1:]
            # Else it's just a normal begin anchor
            else:
                self.begin = 0
                self.end   = None
                self.text  = token[1:]
        #
        # Parse end anchor if present
        elif token[-1] == "$":
            self.begin = "$"
            self.end   = None
            self.text  = token[:-1]
        #
        else: raise ValueError("token passed to AnchoredToken constructor is not an anchored token")

    def is_positional(self):  return True if self.end is     None else False
    def is_middle(self):      return True if self.end is not None else False
    # For sets
    def __hash__(self):
        return hash(self.text) ^ hash(self.begin) ^ hash(self.end)
    def __eq__(self, other):
        return self.text == other.text and self.begin == other.begin and self.end == other.end if isinstance(other, AnchoredToken) else False
    # For sort
    def __lt__(self, other):
        return self.text <  other.text or  self.begin <  other.begin or  self.end <  other.end if isinstance(other, AnchoredToken) else False
    # For hashlib
    def __str__(self):
        if self.begin == 0:   return "^" + self.text
        if self.begin == "$": return self.text + "$"
        strval = "^"
        if self.end is None or self.begin > 1: strval += str(self.begin + 1)
        if self.end:
            strval += ","
            if self.end < sys.maxint: strval += str(self.end + 1)
        return strval + "$" + self.text
    def __repr__(self): return self.__class__.__name__ + "(" + repr(str(self)) + ")"

if __name__ == '__main__':

    has_any_wildcards        = False
    has_any_duplicate_tokens = False
    token_set_for_dupchecks  = set()
    token_lists = []

    for line_num, line in enumerate(tokenlist_file, 1):

        # Ignore comments
        if line[0] == "#": continue

        # Start off assuming these tokens are optional (no preceding "+");
        # if it turns out there is a "+", we'll remove this None later
        new_list = [None]

        # Remove the trailing newline, then split the line on the
        # specified delimiter (default: whitespace) to get a list of tokens
        new_list.extend( line.rstrip("\r\n").split(args.delimiter) )

        # Ignore empty lines
        if len(new_list) == 1: continue

        # If a "+" is present at the beginning followed by at least one token,
        # then exactly one of the token(s) is required. This is noted in the structure
        # by removing the preceding None we added above (and also delete the "+")
        if new_list[1] == "+" and len(new_list) > 2:
            del new_list[0:2]

        # Check token syntax and convert any anchored tokens to an AnchoredToken object
        for i, token in enumerate(new_list):
            if token is None: continue

            for c in token:
                if ord(c) > 127:
                    print(parser.prog+": error: token on line", line_num, "has non-ASCII character '"+c+"'", file=sys.stderr)
                    sys.exit(2)

            # Syntax check any wildcards
            wildcard_count = count_valid_wildcards(token)
            if wildcard_count:
                if wildcard_count == -1:
                    print(parser.prog+": error: token on line", line_num, "has an invalid wildcard (%) spec (use %% to escape a %)", file=sys.stderr)
                    sys.exit(2)
                has_any_wildcards = True  # (a global)

            # Keep track of the existence of any duplicate tokens for future optimization
            if not has_any_duplicate_tokens:
                if token in token_set_for_dupchecks:
                    has_any_duplicate_tokens = True
                else:
                    token_set_for_dupchecks.add(token)

            # Parse anchor if present
            if token[0] == "^" or token[-1] == "$":
                new_list[i] = AnchoredToken(token, line_num)

        # Add the completed list for this one line to the token_lists list of lists
        token_lists.append(new_list)

    tokenlist_file.close()

    # Tokens at the end of the outer token_lists get tried first below;
    # reverse the list here so that tokens at the beginning of the file
    # appear at the end of the list and consequently get tried first
    token_lists.reverse()

    # Take a hash of the token_lists and check it during a session restore
    # to make sure we're actually restoring the exact same session
    if args.autosave:
        token_lists_hash = hashlib.sha1(str(token_lists)).digest()
    if restored:
        if token_lists_hash != savestate["token_lists_hash"]:
            print(parser.prog+": error: can't restore previous session: the tokenlist file has changed", file=sys.stderr)
            sys.exit(2)


############################## Password Generation ##############################


# Checks for duplicate hashable items in multiple identical runs
# (builds a cache in the first run to be memory efficient in future runs)
class DuplicateChecker:
    def __init__(self):
        self.seen_once  = set()
        self.duplicates = dict()
        self.run_number = 0

    def is_duplicate(self, x):
        # The duplicates cache is built during the first run
        if self.run_number == 0:
            if x in self.seen_once:       # If it's now the second time we've seen it:
                self.seen_once.remove(x)      # it's been seen *more* than once
                self.duplicates[x] = 1        # mark it as having duplicates
                return True
            elif x in self.duplicates:    # If it's the third+ time we've seen it
                return True
            else:                         # If it's the first time we've seen it
                self.seen_once.add(x)
                return False

        # The duplicates cache is available for lookup on second+ runs
        duplicate = self.duplicates.get(x)
        if duplicate:
            if duplicate <= self.run_number:          # First time we've seen it this run:
                self.duplicates[x] = self.run_number + 1  # mark it as having been seen this run
                return False
            else:                                     # Second+ time we've seen it this run
                return True
        else:   return False                          # Else it isn't a recorded duplicate

    def run_finished(self):
        if self.run_number == 0:
            self.seen_once = None  # No longer need this for second+ runs
        self.run_number += 1


# Used to communicate between typo generators the number of typos that have been
# created so far during each password generated so that later generators know how
# many additional typos, at most, they are permitted to add
typos_sofar = 0

# The main generator function produces all possible requested password permutations with
# no duplicates from the token_lists global as constructed above plus wildcard expansion
# and up to a certain number of requested typos
#
token_combination_dups = DuplicateChecker()
password_dups          = DuplicateChecker()
#
def password_generator():
    global typos_sofar, token_combination_dups, password_dups
    worker_count = 0  # only used if --worker is specified

    if has_any_duplicate_tokens:
        permutations_function = permutations_nodups
    else:
        permutations_function = itertools.permutations

    # Build up the modification_generators list; see the inner loop below for more details
    modification_generators = []
    if has_any_wildcards:           modification_generators.append( expand_wildcards_generator )
    if args.typos_capslock:         modification_generators.append( capslock_typos_generator   )
    if args.typos_swap:             modification_generators.append( swap_typos_generator       )
    if simple_typo_types_specified: modification_generators.append( simple_typos_generator     )

    # The outer loop iterates through all possible (unordered) combinations of tokens
    # taking into account the at-most-one-token-per-line rule. Note that lines which
    # were not required (no "+") have a None in their corresponding list; if this
    # None item is chosen for a tokens_combination, then this tokens_combination
    # corresponds to one without any token from that line, and we we simply remove
    # the None from this tokens_combination below.
    for tokens_combination in itertools.product(*token_lists):

        # Remove any None's, then check against token length constraints:
        tokens_combination = filter(lambda t: t is not None, tokens_combination)
        if not args.min_tokens <= len(tokens_combination) <= args.max_tokens: continue

        # There are two types of anchors, positional and middle/range. Positional anchors
        # only have a single possible position; middle anchors have a range, but are never
        # tried at the beginning or end. Below, build a tokens_combination_nopos list from
        # tokens_combination with all positional anchors removed. They will be inserted
        # back into the correct position later. Also search for invalid anchors of any
        # type: a positional anchor placed past the end of the current combination (based
        # on its length) or a middle anchor whose begin position is past *or at* the end.
        positional_anchors       = None  # (will contain strings, not AnchoredToken's)
        tokens_combination_nopos = []
        invalid_anchors          = False
        for token in tokens_combination:
            if isinstance(token, AnchoredToken):
                pos = token.begin
                if token.is_positional():       # a single-position anchor
                    if pos == "$":
                        pos = len(tokens_combination) - 1
                    elif pos >= len(tokens_combination):
                        invalid_anchors = True  # anchored past the end
                        break
                    if not positional_anchors:  # initialize it to a list of None's
                        positional_anchors = list(itertools.repeat(None, len(tokens_combination)))
                    if positional_anchors[pos]:
                        invalid_anchors = True  # two tokens anchored to the same place
                        break
                    positional_anchors[pos] = token.text    # save valid single-position anchor
                else:                           # else it's a middle anchor
                    if pos+1 >= len(tokens_combination):
                        invalid_anchors = True  # anchored past *or at* the end
                        break
                    tokens_combination_nopos.append(token)  # add this token (a middle anchor)
            else:                                           # else it's not an anchored token,
                tokens_combination_nopos.append(token)      # add this token (just a string)
        if invalid_anchors: continue
        #
        if len(tokens_combination_nopos) == 0:  # if all tokens have positional anchors,
            tokens_combination_nopos = ( "", )  # make this non-empty so a password can be created

        # Do some duplicate checking early on to avoid running through potentially a
        # lot of passwords all of which end up being duplicates. We check the current
        # combination (of all tokens), sorted because different orderings of token
        # combinations are equivalent at this point. This runs regardless of the
        # --no-dupchecks option because it probably doesn't take up much memory...
        # TODO:
        #   Allow --no-dupchecks, or something else, to disable this?
        #   Be smarter in deciding when to turn this on?
        #   Instead of dup checking, write a smarter product (seems hard)?
        if has_any_duplicate_tokens and \
           token_combination_dups.is_duplicate(tuple(sorted(tokens_combination))): continue

        # The middle loop iterates through all valid permutations (orderings) of one
        # combination of tokens and combines the tokens to create a password string.
        # Because positionally anchored tokens can only appear in one position, they
        # are not passed to the permutations_function.
        for ordered_token_guess in permutations_function(tokens_combination_nopos):

            # Insert the positional anchors we removed above back into the guess
            if positional_anchors:
                ordered_token_guess = list(ordered_token_guess)
                for i, token in enumerate(positional_anchors):
                    if token: ordered_token_guess.insert(i, token)  # (token here is just a string)

            # The second type of anchor has a range of possible positions for the anchored
            # token. If any anchored token is outside of its permissible range, we continue
            # on to the next guess. Otherwise, we remove the anchor information leaving
            # only the string behind.
            if isinstance(ordered_token_guess[0], AnchoredToken) or isinstance(ordered_token_guess[-1], AnchoredToken):
                continue  # middle anchors are never permitted at the beginning or end
            invalid_anchors = False
            for i, token in enumerate(ordered_token_guess[1:-1], 1):
                if isinstance(token, AnchoredToken):
                    assert token.is_middle(), "only middle/range anchors left"
                    if token.begin <= i <= token.end:
                        if (not isinstance(ordered_token_guess, list)):
                            ordered_token_guess = list(ordered_token_guess)
                        ordered_token_guess[i] = token.text  # now it's just a string
                    else:
                        invalid_anchors = True
                        break
            if invalid_anchors: continue

            password_base = "".join(ordered_token_guess)

            # The inner loop takes the password_base and applies zero or more modifications
            # to it to produce a number of different possible variations of password_base
            # (e.g. different wildcard expansions, typos, etc.)

            # Reset this for each new password_base
            typos_sofar = 0

            # modification_generators is a list of function generators each of which takes a
            # string and produces one or more password variations based on that string. It is
            # built at the beginning of this function, and is built differently depending on
            # the token_lists (are any wildcards present?) and the program options (were any
            # typos requested?).

            # If any modifications have been requested, create an iterator that will
            # loop through all combinations of the requested modifications
            if len(modification_generators):
                modification_iterator = generator_product(password_base, *modification_generators)
            #
            # Otherwise just produce the unmodified password itself
            else:
                modification_iterator = (password_base,)

            for password in modification_iterator:

                if typos_sofar < args.min_typos: continue

                # Check the password against the --regex-only and --regex-never options
                if regex_only  and not regex_only .search(password): continue
                if regex_never and     regex_never.search(password): continue

                # This duplicate check can be disabled via --no-dupchecks
                # because it can take up a lot memory, sometimes needlessly
                if not args.no_dupchecks and password_dups.is_duplicate(password): continue

                yield password

    token_combination_dups.run_finished()
    password_dups.run_finished()


# Like itertools.permutations, but avoids duplicates even if input contains some.
# Input must be a sequence of hashable elements.
# TODO: implement without recursion?
def permutations_nodups(sequence):
    if len(sequence) == 2:
        # Only two permutations to try:
        yield sequence if isinstance(sequence, tuple) else tuple(sequence)
        if sequence[0] != sequence[1]:
            yield (sequence[1], sequence[0])

    elif len(sequence) <= 1:
        # Only one permutation to try:
        yield sequence if isinstance(sequence, tuple) else tuple(sequence)
    else:

        # If the sequence contains no duplicates, use the faster itertools version
        seen = set(sequence)
        if len(seen) == len(sequence):
            for permutation in itertools.permutations(sequence):
                yield permutation
            return

        # If they're all the same, there's only one permutation:
        if len(seen) == 1:
            yield sequence if isinstance(sequence, tuple) else tuple(sequence)
            return

        # Else there's at least one duplicate and two+ permutations; use our version
        seen = set()
        for i, choice in enumerate(sequence):
            if i > 0 and choice in seen: continue          # don't need to check the first one
            if i+1 < len(sequence):      seen.add(choice)  # don't need to add the last one
            for rest in permutations_nodups(sequence[:i] + sequence[i+1:]):
                yield (choice,) + rest
        return


# This generator utility is a bit like itertools.product. It takes a list of iterators
# and invokes them in (the equivalent of) a nested for loop, except instead of a list
# of simple iterators it takes a list of generators each of which expects to be called
# with a single argument. generator_product calls the first generator with the passed
# initial_value, and then takes each value it produces and calls the second generator
# with each, and then takes each value the second generator produces and calls the
# third generator with each, etc., until there are no generators left, at which point
# it produces all the values generated by the last generator.
#
# This can be useful in the case you have a list of generators, each of which is
# designed to produce a number of variations of an initial value, and you'd like to
# string them together to get all possible (product-wise) variations.
#
# TODO: implement without recursion?
def generator_product(initial_value, generator, *other_generators):
    if len(other_generators) == 0:
        for final_value in generator(initial_value):
            yield final_value
    else:
        for intermediate_value in generator(initial_value):
            for final_value in generator_product(intermediate_value, *other_generators):
                yield final_value


# This generator function that expands all wildcards in the string passed to it,
# or if there are no wildcards it simply produces that single string
custom_wildcard_cache = dict()
def expand_wildcards_generator(password_with_wildcards):

    # Quick check to see if any wildcards are present
    if password_with_wildcards.find("%") == -1:
        # If none, just produce the string and end
        yield password_with_wildcards
        return

    # Find the first wildcard parameter in the format %[[min,]max][caseflag]type
    # where caseflag=="i" if present and type is one of the wildcard_keys
    # (e.g. "%d", "%2n", "%1,3ia", etc.) or type is of the form "[custom-wildcard-set]"
    match = re.search(r"%(?:(?:(?P<min>\d+),)?(?P<max>\d+))?(?P<nocase>i)?(?:(?P<type>["+wildcard_keys+"])|\[(?P<custom>.+?)\])", password_with_wildcards)
    assert match, "parsed valid wildcard spec"

    password_prefix = password_with_wildcards[0:match.start()]               # no wildcards present here;
    password_postfix_with_wildcards = password_with_wildcards[match.end():]  # might be other wildcards in here

    # Build the set of possible characters based on the wildcard type and caseflag
    m_custom, m_nocase = match.group("custom", "nocase")
    if m_custom:
        wildcard_set = custom_wildcard_cache.get((m_custom, m_nocase))
        if wildcard_set is None:
            wildcard_set = build_wildcard_set(m_custom)
            if m_nocase:
                # Build a case-insensitive version
                wildcard_set_caseswapped = wildcard_set.swapcase()
                if wildcard_set_caseswapped != wildcard_set:
                    wildcard_set = remove_duplicates(wildcard_set + wildcard_set_caseswapped)
            custom_wildcard_cache[(m_custom, m_nocase)] = wildcard_set
    else:
        m_type = match.group("type")
        if m_nocase and m_type in wildcard_nocase_sets:
            wildcard_set = wildcard_nocase_sets[m_type]
        else:
            wildcard_set = wildcard_sets[m_type]
    assert wildcard_set, "found wildcard type"

    # Extract or default the wildcard min and max length
    wildcard_maxlen = match.group("max")
    wildcard_maxlen = int(wildcard_maxlen) if wildcard_maxlen else 1
    wildcard_minlen = match.group("min")
    wildcard_minlen = int(wildcard_minlen) if wildcard_minlen else wildcard_maxlen

    # Iterate through specified wildcard lengths
    for wildcard_len in xrange(wildcard_minlen, wildcard_maxlen+1):

        # Expand the wildcard into a length of characters according to the wildcard type/caseflag
        for wildcard_expanded_list in itertools.product(wildcard_set, repeat=wildcard_len):
            password_prefix_expanded = password_prefix + "".join(wildcard_expanded_list)

            # If the wildcard was at the end of the string, we're done
            if len(password_postfix_with_wildcards) == 0:
                yield password_prefix_expanded
                continue

            # Recurse to expand any additional wildcards possibly in password_postfix_with_wildcards
            # TODO: isn't this a tail recursion that can be collapsed easily?
            for password_postfix_expanded in expand_wildcards_generator(password_postfix_with_wildcards):
                yield password_prefix_expanded + password_postfix_expanded


# capslock_typos_generator() is a generator function which tries swapping the case of
# the entire password (producing just one variation of the password_base in addition
# to the password_base itself)
def capslock_typos_generator(password_base):
    global typos_sofar

    # Start with the unmodified password itself, and end if there's nothing left to do
    yield password_base
    if typos_sofar >= args.typos: return

    password_swapped = password_base.swapcase()
    if password_swapped != password_base:
        typos_sofar += 1
        yield password_swapped
        typos_sofar -= 1


# swap_typos_generator() is a generator function which produces all possible combinations
# of the password_base where zero or more pairs of adjacent characters are swapped. Even
# when multiple swapping typos are requested, any single character is never swapped more
# than once per generated password.
def swap_typos_generator(password_base):
    global typos_sofar

    # Start with the unmodified password itself, and end if there's nothing left to do
    yield password_base
    max_swaps = args.typos - typos_sofar
    if max_swaps <= 0 or len(password_base) < 2: return

    # First swap one pair of characters, then all combinations of 2 pairs, then of 3,
    # up to the max requested or up to the max number swappable (whichever's less). The
    # max number swappable is len // 2 because we never swap any single character twice.
    max_swaps = min(max_swaps, len(password_base) // 2)
    for swap_count in xrange(1, max_swaps + 1):
        typos_sofar += swap_count

        # Generate all possible combinations of swapping exactly swap_count characters;
        # swap_indexes is a list of indexes of characters that will be swapped in a
        # single guess (swapped with the character at the next position in the string)
        for swap_indexes in itertools.combinations(xrange(len(password_base)-1), swap_count):

            # Look for adjacent indexes in  swap_indexes (which would cause a single
            # character to be swapped more than once in a single guess), and only
            # continue if no such adjacent indexes are found
            for i in xrange(1, swap_count):
                if swap_indexes[i] - swap_indexes[i-1] == 1:
                    break
            else:  # if we left the loop normally (didn't break)

                # Perform and the actual swaps
                password = password_base
                for i in swap_indexes:
                    if password[i] == password[i+1]:  # "swapping" these would result in generating a duplicate guess
                        break
                    password = password[:i] + password[i+1] + password[i] + password[i+2:]
                else:  # if we left the loop normally (didn't break)
                    yield password

        typos_sofar -= swap_count


# Convenience functions currently only used by typo_closecase()
#
UNCASED_ID   = 0
LOWERCASE_ID = 1
UPPERCASE_ID = 2
def case_id_of(letter):
    if   letter.islower(): return LOWERCASE_ID
    elif letter.isupper(): return UPPERCASE_ID
    else:                  return UNCASED_ID
#
# Note that  in order for a case to be considered changed, one of the two letters must be
# uppercase (i.e. lowercase to uncased isn't a case change, but uppercase to uncased is a
# case change, and of course lowercase to uppercase is too)
def case_id_changed(case_id1, case_id2):
    if case_id1 != case_id2 and (case_id1 == UPPERCASE_ID or case_id2 == UPPERCASE_ID):
          return True
    else: return False


# simple_typos_generator() is a generator function which, given a password_base, produces
# all possible combinations of typos of that password_base, of a count and of types specified
# at the command line. See the Configurables section for a list and description of the
# available simple typo generator types/functions. (The simple_typos_generator() function
# itself isn't very simple... it's called "simple" because the functions in the Configurables
# section which simple_typos_generator() calls are simple; they are collectively called
# simple typo generators)
#
if __name__ == '__main__':
    # Req'd by the typo_append_wildcard and typo_replace_wildcard simple generator functions:
    if args.typos_insert:
        typos_insert_expanded  = list(expand_wildcards_generator(args.typos_insert))
    if args.typos_replace:
        typos_replace_expanded = list(expand_wildcards_generator(args.typos_replace))
    #
    # A list of simple typo generator functions enabled via the command line:
    typo_generators = [generator for name,generator in simple_typos.items() if argsdict.get("typos_"+name)]
#
def simple_typos_generator(password_base):
    global typos_sofar
    assert len(typo_generators) > 0, "typo types specified"

    # Start with the unmodified password itself
    yield password_base

    # First change all single characters, then all combinations of 2 characters, then of 3, etc.
    max_typos = min(args.typos - typos_sofar, len(password_base))
    for typos_count in xrange(1, max_typos + 1):
        typos_sofar += typos_count

        # Select the indexes of exactly typos_count characters from the password_base
        # that will be the target of the typos (out of all possible combinations thereof)
        for typo_indexes in itertools.combinations(xrange(len(password_base)), typos_count):

            # Iterate through all possible permutations of the specified
            # typo_generators being applied to the selected typo targets
            for typo_generators_per_target in itertools.product(typo_generators, repeat=typos_count):

                # For each of the selected typo targets, call the generator selected above to
                # get the replacement(s) of said to-be-replaced typo targets. Each item in
                # typo_replacements is an iterable (tuple, list, generator, etc.) producing
                # zero or more replacements for a single target. If there are zero replacements
                # for any target, the for loop below intentionally produces no results at all.
                typo_replacements = [ generator(password_base, index) for index, generator in
                    zip(typo_indexes, typo_generators_per_target) ]

                # one_replacement_set is a tuple of exactly typos_count length, with one
                # replacement per selected typo target. If all of the selected generators
                # above each produce only one replacement, this loop will execute once with
                # that one replacement set. If one or more of the generators produce multiple
                # replacements (for a single target), this loop iterates accross all possible
                # combinations of those replacements. If any generator produces zero outputs
                # (therefore that the target has no typo), this loop iterates zero times.
                for one_replacement_set in itertools.product(*typo_replacements):

                    # Construct a new password, left-to-right, from password_base and the
                    # one_replacement_set.
                    # typo_indexes_ has a added sentinal at the end; it's the index of
                    # one-past-the-end of password_base.
                    typo_indexes_ = typo_indexes + (len(password_base),)
                    password = password_base[0:typo_indexes_[0]]
                    for i, replacement in enumerate(one_replacement_set):
                        password += replacement + password_base[typo_indexes_[i]+1:typo_indexes_[i+1]]
                    yield password

        typos_sofar -= typos_count


############################## Main ##############################


# Init function for the password verifying worker processes:
#   (re-)loads the wallet or key (should only be necessary on Windows),
#   tries to set the process priority to minimum, and
#   begins ignoring SIGINTs for a more graceful exit on Ctrl-C
def init_worker(wallet_filename, key_data):
    if not wallet:
        if wallet_filename: load_wallet(wallet_filename)
        elif key_data:      load_from_key(key_data)
        else: assert False, "wallet filename or key data passed to init_worker"
    set_process_priority_idle()
    signal.signal(signal.SIGINT, signal.SIG_IGN)
#
def set_process_priority_idle():
    try:
        if sys.platform == "win32":
            import win32process
            win32process.SetPriorityClass(win32process.GetCurrentProcess(), win32process.IDLE_PRIORITY_CLASS)
        else:
            os.nice(19)
    except: pass

# Once installed, performs cleanup prior to a requested process shutdown on Windows
def windows_ctrl_handler(signal):
    if signal == 0:   # if it's a Ctrl-C,
       return False   # defer to the native Python handler which works just fine
    #
    # Python on Windows is a bit touchy with signal handlers; it's safest to just
    # do all the cleanup code here (even though it's cleaner to throw an exception)
    if args.autosave:
        do_autosave(args.skip + passwords_tried, True)  # do this first, it's most important
        autosave_file.close()
    print("\nInterrupted after finishing password #", args.skip + passwords_tried, file=sys.stderr)
    if sys.stdout.isatty() ^ sys.stderr.isatty():  # if they're different, print to both to be safe
        print("\nInterrupted after finishing password #", args.skip + passwords_tried)
    sys.exit()

# TODO: implement a safer atomic autosave? fsync? (buffering is already disabled at file open)
def do_autosave(skip, inside_interrupt_handler = False):
    assert autosave_file and not autosave_file.closed,  "autosave_file is open"
    autosave_file.seek(0)
    if not inside_interrupt_handler:
        sigint_handler  = signal.signal(signal.SIGINT,  signal.SIG_IGN)  # ignore Ctrl-C and
        sigterm_handler = signal.signal(signal.SIGTERM, signal.SIG_IGN)  # SIGTERM while saving
    autosave_file.truncate()
    cPickle.dump(dict(
            argv             = effective_argv,   # combined options from command line and tokenlists file
            skip             = skip,             # passwords completed so far
            token_lists_hash = token_lists_hash, #\
            typos_map_hash   = typos_map_hash,   # > inputs which aren't permitted to change between runs
            key_crc          = key_crc,          #/
            ordering_version = __ordering_version__ # password ordering can't change between runs
        ), autosave_file, cPickle.HIGHEST_PROTOCOL)
    autosave_file.flush()  # buffering should already be disabled, but this doesn't hurt
    if not inside_interrupt_handler:
        signal.signal(signal.SIGINT, sigint_handler)
        signal.signal(signal.SIGTERM, sigterm_handler)


if __name__ == '__main__':

    # If --listpass was requested, just list out all the passwords and exit
    passwords_count = 0
    if args.listpass:
        for password in password_generator():
            print(password)
            passwords_count += 1
        print("\n", passwords_count, "password combinations", file=sys.stderr)
        sys.exit(0)

    # Measure the performance of the verification function
    # (measure_performance_iterations has been set such that this should take about 0.5 seconds)
    assert measure_performance_iterations, "measure_performance_iterations has been set"
    start = time.clock()
    for i in xrange(measure_performance_iterations):
        return_verified_password_or_false("measure performance passphrase "+str(i))
    est_secs_per_password = (time.clock() - start) / float(measure_performance_iterations)

    # If the time to verify a password is short enough, the time to generate the passwords in this thread
    # becomes comparable to verifying passwords, therefore this should count towards being a "worker" thread
    if est_secs_per_password < 1.0 / 20000.0:
        main_thread_is_worker = True
        spawned_threads   = worker_threads - 1       # spawn 1 fewer than requested (might be 0)
        verifying_threads = spawned_threads or 1
    else:
        main_thread_is_worker = False
        spawned_threads   = worker_threads if worker_threads > 1 else 0
        verifying_threads = worker_threads

    # The chunksize for multiprocessing.imap: enough passwords to last for about 1/200th of a second.
    # (this was determined experimentally to be about the best I could do, YMMV)
    if spawned_threads:
        imap_chunksize = int(1.0 / (200.0*est_secs_per_password)) or 1

    # Adjust estimate for the number of verifying threads (final estimate is probably an underestimate)
    est_secs_per_password /= min(verifying_threads, cpus)

    # If requested, subtract out skipped passwords from the count (calculated just below)
    if args.skip > 0:
        passwords_count = -args.skip

    # Count how many passwords there are so we can display and conform to ETAs
    max_seconds = args.max_eta * 3600  # max_eta is in hours
    start = time.clock()
    for password in password_generator():
        passwords_count += 1
        if passwords_count * est_secs_per_password > max_seconds:
            print(parser.prog+": error: at least {:,} passwords to try, ETA > max_eta option ({} hours), exiting" \
                  .format(passwords_count, args.max_eta), file=sys.stderr)
            sys.exit(2)
        if passwords_count == 5000000:  # takes about 5 seconds on my CPU, YMMV
            print("Counting passwords ...")
    iterate_time = time.clock() - start

    if passwords_count <= 0:
        print("Skipped all", passwords_count + args.skip, "passwords, exiting")
        sys.exit(0)

    # If additional ETA calculations are required
    if args.autosave or not have_progress:
        eta_seconds = passwords_count * est_secs_per_password
        if (spawned_threads == 0 or spawned_threads >= cpus):  # if the main thread is sharing CPU time with a verifying thread
            eta_seconds += iterate_time
        eta_seconds = int(round(eta_seconds)) or 1
        if args.autosave:
            est_passwords_per_5min = passwords_count / eta_seconds * 300

    # Create an iterator which produces the desired password permutations, skipping some if so instructed
    password_iterator = password_generator()
    if args.skip > 0:
        print("Starting with password #", args.skip + 1)
        for i in xrange(args.skip): password_iterator.next()

    print("Using", worker_threads, "worker", "threads" if worker_threads > 1 else "thread")  # (they're actually worker processes)

    if have_progress:
        progress = ProgressBar(maxval=passwords_count, widgets=[
            SimpleProgress(), " ", Bar(left="[", fill="-", right="]"), FormatLabel(" %(elapsed)s, "), ETA()
        ])

    else:
        # If progressbar is unavailable, print out a time estimate instead
        print("Will try {:,} passwords, ETA ".format(passwords_count), end="")
        eta_hours    = eta_seconds // 3600
        eta_seconds -= 3600 * eta_hours
        eta_minutes  = eta_seconds // 60
        eta_seconds -= 60 * eta_minutes
        if eta_hours   > 0: print(eta_hours,   "hours ",   end="")
        if eta_minutes > 0: print(eta_minutes, "minutes ", end="")
        if eta_hours  == 0: print(eta_seconds, "seconds ", end="")
        print("...")

    # If there aren't many passwords, give each of the N workers 1/Nth of the passwords
    if spawned_threads and spawned_threads * imap_chunksize > passwords_count:
        imap_chunksize = (passwords_count-1) // spawned_threads + 1

    # Autosave the starting state now that we're just about ready to start
    if args.autosave: do_autosave(args.skip)

    # Try to release as much memory as possible (before forking if multiple workers are being used)
    # (the initial counting process can be memory intensive)
    gc.collect(2)

    # Create an iterator which actually checks the (remaining) passwords produced by the password_iterator
    # by executing the return_verified_password_or_false worker function in possibly multiple threads
    if spawned_threads == 0:
        password_found_iterator = itertools.imap(return_verified_password_or_false, password_iterator)
        set_process_priority_idle()  # this, the only thread, should be nice
    else:
        pool = multiprocessing.Pool(spawned_threads, init_worker, [args.wallet, key_data])
        password_found_iterator = pool.imap(return_verified_password_or_false, password_iterator, imap_chunksize)
        if main_thread_is_worker: set_process_priority_idle()  # if this thread is cpu-intensive, be nice

    # Try to catch all types of intentional program shutdowns so we can
    # display password progress information and do a final autosave
    try:
        signal.signal(signal.SIGTERM, signal.getsignal(signal.SIGINT))
        if sys.platform == "win32":
            import win32api
            win32api.SetConsoleCtrlHandler(windows_ctrl_handler, True)
    except: pass

    # Iterate through password_found_iterator looking for a successful guess
    passwords_tried = 0
    if have_progress: progress.start()
    try:
        for password_found in password_found_iterator:
            if password_found:
                if have_progress: print()  # move down to the line below the progress bar
                print("Password found:", password_found)
                break
            passwords_tried += 1
            if have_progress: progress.update(passwords_tried)
            if args.autosave and passwords_tried % est_passwords_per_5min == 0:
                do_autosave(args.skip + passwords_tried)
        else:  # if the for loop exits normally (without breaking)
            if have_progress: progress.finish()
            print("Password search exhausted")

    # Gracefully handle Ctrl-C (and other intentional program shutdowns), printing the
    # count completed so far so that it can be skipped if the user restarts the same run
    except KeyboardInterrupt:
        print("\nInterrupted after finishing password #", args.skip + passwords_tried, file=sys.stderr)
        if sys.stdout.isatty() ^ sys.stderr.isatty():  # if they're different, print to both to be safe
            print("\nInterrupted after finishing password #", args.skip + passwords_tried)
        # (falls through to the autosave next)

    # For unexpected exceptions, still print the count, but re-raise (w/o a final autosave)
    except:
        print("\nUnexpected error after finishing password #", args.skip + passwords_tried, file=sys.stderr)
        if sys.stdout.isatty() ^ sys.stderr.isatty():  # if they're different, print to both to be safe
            print("\nUnexpected error after finishing password #", args.skip + passwords_tried)
        raise

    # Autosave the final state (for all non-error cases-- we're shutting down
    # (e.g. Ctrl-C or a reboot), the password was found, or the search was exhausted)
    if args.autosave:
        do_autosave(args.skip + passwords_tried)
        autosave_file.close()
