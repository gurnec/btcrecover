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

__version__ =  "0.3.2"

import sys, argparse, itertools, string, re, multiprocessing, signal, os, os.path, \
       cPickle, gc, time, hashlib, collections, base64, struct, ast, atexit

# The progressbar module is recommended but optional; it is typically
# distributed with btcrecover (it is loaded later on demand)

# The pywin32 module is also recommended on Windows but optional; it's only
# used to adjust the process priority to be more friendly. When used with
# Armory, btcrecover will just load the version that ships with Armory.


############################## Configurables/Plugins ##############################
# wildcard sets, simply typo generators, and wallet support functions


# Recognized wildcard (e.g. %d, %a) types mapped to their associated sets
# of characters; used in expand_wildcards_generator()
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
def typo_repeat(p, i): return (2 * p[i],)
def typo_delete(p, i): return ("",)
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
# (typos_insert_expanded and typos_replace_expanded are initalized from
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
# Given a filename, determines the wallet type and calls a function to load a
# wallet library and the wallet. Also configures the get_est_secs_per_password
# and return_verified_password_or_false globals to call the correct functions
# for the discovered wallet type.
def load_wallet(wallet_filename):
    global get_est_secs_per_password, return_verified_password_or_false
    with open(wallet_filename, "rb") as wallet_file:

        # Armory
        if wallet_file.read(8) == b"\xbaWALLET\x00":  # Armory magic
            wallet_file.close()
            load_armory_wallet(wallet_filename)  # passing in a filename
            get_est_secs_per_password         = get_armory_est_secs_per_password
            return_verified_password_or_false = return_armory_verified_password_or_false
            return

        # Bitcoin Core
        wallet_file.seek(12)
        if wallet_file.read(8) == "\x62\x31\x05\x00\x09\x00\x00\x00":  # BDB magic, Btree v9
            wallet_file.close()
            load_bitcoincore_wallet(wallet_filename)  # passing in a filename
            get_est_secs_per_password         = get_bitcoincore_est_secs_per_password
            return_verified_password_or_false = return_bitcoincore_verified_password_or_false
            return

        # Multibit private key backup file (not the wallet file)
        wallet_file.seek(0)
        try:    is_multibitpk = base64.b64decode(wallet_file.read(20).lstrip()[:12]).startswith("Salted__")
        except: is_multibitpk = False
        if is_multibitpk:
            load_multibit_privkey(wallet_file)  # passing in a file object
            get_est_secs_per_password         = get_multibitpk_est_secs_per_password
            return_verified_password_or_false = return_multibitpk_verified_password_or_false
            return

        # Electrum
        wallet_file.seek(0)
        if wallet_file.read(2) == "{'":  # best we can easily do short of just trying to load it
            try:
                load_electrum_wallet(wallet_file)  # passing in a file object
                get_est_secs_per_password         = get_electrum_est_secs_per_password
                return_verified_password_or_false = return_electrum_verified_password_or_false
                return
            except SyntaxError: pass     # probably wasn't an electrum wallet
            except: raise

        print(parser.prog+": error: unrecognized wallet format", file=sys.stderr)
        sys.exit(2)


# Load the Armory library and a wallet file given the filename
def load_armory_wallet(wallet_filename):
    global armoryengine, CppBlockUtils, wallet
    # Try to add the Armory libraries to the path on various platforms
    if sys.platform == "win32":
        win32_path = os.environ.get("ProgramFiles",  r"C:\Program Files (x86)") + r"\Armory"
        sys.path.extend((win32_path, win32_path + r"\library.zip"))
    elif sys.platform.startswith("linux"):
        sys.path.append("/usr/lib/armory")
    elif sys.platform == "darwin":
        sys.path.append("/Applications/Armory.app/Contents/MacOS/py/usr/lib/armory")
    # Temporarily blank out argv before importing the armoryengine, otherwise it attempts to process argv
    old_argv = sys.argv[1:]
    del sys.argv[1:]
    # Try up to 10 times to load Armory (there's a race condition on opening the log file in Windows multiprocessing)
    for i in xrange(10):
        try: import armoryengine.PyBtcWallet, CppBlockUtils
        except IOError as e:
            if i<9 and e.filename.endswith(r"\armorylog.txt"): time.sleep(0.1)
            else: raise
        else: break
    wallet = armoryengine.PyBtcWallet.PyBtcWallet().readWalletFile(wallet_filename)
    sys.argv[1:] = old_argv

# Estimate the time it takes to try a single password (on a single CPU) for Armory
def get_armory_est_secs_per_password():
    return ( wallet.testKdfComputeTime() + wallet.testKdfComputeTime() ) / 2.0  # about 0.5s by design

# This is the time-consuming function executed by worker thread(s):
# if a password is correct, return it, else return false
def return_armory_verified_password_or_false(p):
    if wallet.verifyPassphrase(CppBlockUtils.SecureBinaryData(p)): return p
    else: return False


# Load a Bitcoin Core BDB wallet file given the filename and extract the first encrypted master key
def load_bitcoincore_wallet(wallet_filename):
    global wallet, has_bsddb
    load_aes256_library()

    mkey = None
    try:
        import bsddb.db
        has_bsddb = True
    except: has_bsddb = False
    if has_bsddb:
        db_env = bsddb.db.DBEnv()
        db_env.open(os.path.dirname(wallet_filename), bsddb.db.DB_CREATE | bsddb.db.DB_INIT_MPOOL)
        db = bsddb.db.DB(db_env)
        db.open(wallet_filename, "main", bsddb.db.DB_BTREE, bsddb.db.DB_RDONLY)
        mkey = db.get("\x04mkey\x01\x00\x00\x00")
        db.close()
        db_env.close()

    else:
        def align_32bits(i):
            m = i % 4
            return i+4-m if m else i
        with open(wallet_filename, "rb") as wallet_file:
            wallet_file_size=os.path.getsize(wallet_filename)

            wallet_file.seek(12)
            assert wallet_file.read(8) == "\x62\x31\x05\x00\x09\x00\x00\x00", "is a Btree v9 file"
            wallet_file.seek(20)
            (page_size,) = struct.unpack("<I", wallet_file.read(4))

            # Don't actually try walking the btree, just look through every btree leaf page
            # for the value/key pair (yes they are in that order...) we're searching for
            for page_base in xrange(page_size, wallet_file_size, page_size):  # skip the header page
                wallet_file.seek(page_base+20)
                (item_count, first_item_pos, btree_level, page_type) = struct.unpack("< H H B B", wallet_file.read(6))
                if page_type != 5 or btree_level != 1: continue  # skip non-btree and non-leaf pages
                pos = align_32bits(page_base + first_item_pos)
                wallet_file.seek(pos)
                for i in xrange(item_count):
                    (item_len, item_type) = struct.unpack("< H B", wallet_file.read(3))
                    if item_type & ~0x80 == 1:  # it's a variable-length key or value
                        if item_type == 1:      # if it's not marked as deleted
                            if i % 2 == 0:      # if it's a value, save it's position
                                value_pos = pos+3
                                value_len = item_len
                            elif item_len == 9 and wallet_file.read(item_len) == "\x04mkey\x01\x00\x00\x00":
                                wallet_file.seek(value_pos)
                                mkey = wallet_file.read(value_len)  # found it!
                                break
                        pos = align_32bits(pos + 3 + item_len)  # calc the position of the next item
                    else:
                        pos += 12  # the two other item types have a fixed length
                    if i+1 < item_count:  # don't need to seek if this is the last item in the page
                        assert pos < page_base + page_size, "next item is located in current page"
                        wallet_file.seek(pos)
                else: continue  # if not found on this page, continue to next page
                break           # if we broke out of inner loop, break out of this one

    if not mkey:
        raise Exception("Encrypted master key #1 not found in the Bitcoin Core wallet file.\n"+
                        "(is this wallet encrypted? is this a standard Bitcoin Core wallet?)")
    # This is a little fragile because it assumes the encrypted key and salt sizes are
    # 48 and 8 bytes long respectively, which although currently true may not always be:
    (encrypted_master_key, salt, method, iter_count) = struct.unpack_from("< 49p 9p I I", mkey)
    if method != 0: raise NotImplementedError("Unsupported Bitcoin Core key derivation method " + str(method))
    wallet = (encrypted_master_key, salt, iter_count)

# Estimate the time it takes to try a single password (on a single CPU) for Bitcoin Core
def get_bitcoincore_est_secs_per_password():
    start = time.clock()
    for i in xrange(5):  # about 0.5s by design
        return_bitcoincore_verified_password_or_false("timing test passphrase")
    return (time.clock() - start) / 5.0

# This is the time-consuming function executed by worker thread(s):
# if a password is correct, return it, else return false
def return_bitcoincore_verified_password_or_false(p):
    (encrypted_master_key, salt, iter_count) = wallet
    derived_key_iv = p + salt
    for i in xrange(iter_count):
        derived_key_iv = hashlib.sha512(derived_key_iv).digest()
    master_key = aes256_cbc_decrypt(derived_key_iv[0:32], derived_key_iv[32:48], encrypted_master_key)
    # If the 48 byte encrypted_master_key decrypts to exactly 32 bytes long (padded with 16 16s), we've found it
    if master_key.endswith("\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10"): return p
    else: return False


# Load a Multibit private key backup file (the part of it we need) given an opened file object
def load_multibit_privkey(privkey_file):
    global wallet
    load_aes256_library()
    privkey_file.seek(0)
    # Multibit privkey files contain base64 text split into multiple lines;
    # we need the first 80 bytes after decoding, which translates to 108 before
    wallet = "".join(privkey_file.read(120).split())  # should only be one crlf, but allow more
    if len(wallet) < 108: raise EOFError("Expected at least 108 bytes of text in the MultiBit private key file")
    wallet = base64.b64decode(wallet[:108])
    assert wallet.startswith("Salted__"), "loaded a Multibit privkey file"

# Estimate the time it takes to try a single password (on a single CPU) for Multibit
def get_multibitpk_est_secs_per_password():
    start = time.clock()
    for i in xrange(test_iterations):
        return_multibitpk_verified_password_or_false("timing test passphrase")
    return (time.clock() - start) / test_iterations

# This is the function executed by worker thread(s):
# if a password is correct, return it, else return false
def return_multibitpk_verified_password_or_false(p):
    salted = p + wallet[8:16]
    key1   = hashlib.md5(salted).digest()
    key2   = hashlib.md5(key1 + salted).digest()
    iv     = hashlib.md5(key2 + salted).digest()
    b58_privkey = aes256_cbc_decrypt(key1 + key2, iv, wallet[16:80])
    # If it looks like a base58 private key, we've found it
    # (a bit fragile in the interest of speed, e.g. what if comments or whitespace precede the first key?)
    if (b58_privkey[0] == "L" or b58_privkey[0] == "K") and \
       re.match("[LK][123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{51}", b58_privkey):
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

# Estimate the time it takes to try a single password (on a single CPU) for Electrum
def get_electrum_est_secs_per_password():
    global test_iterations
    start = time.clock()
    for i in xrange(test_iterations):
        return_electrum_verified_password_or_false("timing test passphrase")
    return (time.clock() - start) / test_iterations

# This is the function executed by worker thread(s):
# if a password is correct, return it, else return false
def return_electrum_verified_password_or_false(p):
    key  = hashlib.sha256( hashlib.sha256( p ).digest() ).digest()
    seed = aes256_cbc_decrypt(key, wallet[:16], wallet[16:])
    # If the 48 byte encrypted seed decrypts to exactly 32 bytes long (padded with 16 16s), we've found it
    if seed.endswith("\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10"): return p
    else: return False


# Loads PyCrypto if available, else falls back to pure python version (30x slower)
def load_aes256_library():
    global Crypto, aespython, aes256_cbc_decrypt, aes256_key_expander, test_iterations
    try:
        import Crypto.Cipher.AES
        aes256_cbc_decrypt = aes256_cbc_decrypt_pycrypto
        test_iterations = 50000  # takes about 0.5 seconds on my CPU, YMMV
    except:
        import aespython.key_expander, aespython.aes_cipher, aespython.cbc_mode
        aes256_cbc_decrypt = aes256_cbc_decrypt_pp
        aes256_key_expander = aespython.key_expander.KeyExpander(256)
        test_iterations =  2000  # takes about 0.5 seconds on my CPU, YMMV

def aes256_cbc_decrypt_pycrypto(key, iv, ciphertext):
    return Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_CBC, iv).decrypt(ciphertext)

# Input must be a multiple of 16 bytes; does not strip any padding
def aes256_cbc_decrypt_pp(key, iv, ciphertext):
    block_cipher  = aespython.aes_cipher.AESCipher( aes256_key_expander.expand(bytearray(key)) )
    stream_cipher = aespython.cbc_mode.CBCMode(block_cipher, 16)
    stream_cipher.set_iv(bytearray(iv))
    plaintext = bytearray()
    i = 0
    while i < len(ciphertext):
        plaintext.extend( stream_cipher.decrypt_block(map(ord, ciphertext[i:i+16])) )
        i += 16
    return str(plaintext)


############################## Argument Parsing ##############################


if __name__ == '__main__':

    # can raise exceptions on some platforms
    try:    cpus = multiprocessing.cpu_count()
    except: cpus = 1

    parser = argparse.ArgumentParser()
    parser.add_argument("--wallet",      metavar="FILE", help="the wallet file (required unless using --listpass)")
    parser.add_argument("--tokenlist",   metavar="FILE", help="the list of tokens/partial passwords (required)")
    parser.add_argument("--max-tokens",  type=int, default=9999, metavar="COUNT", help="enforce a max # of tokens included per guess")
    parser.add_argument("--min-tokens",  type=int, default=1,    metavar="COUNT", help="enforce a min # of tokens included per guess")
    parser.add_argument("--typos",       type=int, default=0,    metavar="COUNT", help="simulate up to this many typos; you must choose one or more typo types from the list below")
    parser.add_argument("--min-typos",   type=int, default=0,    metavar="COUNT", help="enforce a min # of typos included per guess")
    typo_types_group = parser.add_argument_group("typo types")
    typo_types_group.add_argument("--typos-capslock", action="store_true", help="tries the password with caps lock turned on")
    typo_types_group.add_argument("--typos-swap",     action="store_true", help="swaps two adjacent characters")
    for typo_name, typo_args in simple_typo_args.items():
        typo_types_group.add_argument("--typos-"+typo_name, **typo_args)
    parser.add_argument("--custom-wild", metavar="STRING", help="a custom set of characters for the %%c wildcard")
    parser.add_argument("--delimiter",   metavar="STRING", help="the delimiter for multiple alternative tokens on each line of the tokenlist (default: whitespace)")
    parser.add_argument("--skip",        type=int, default=0, metavar="COUNT", help="skip this many initial passwords for continuing an interupted search")
    parser.add_argument("--autosave",    metavar="FILE",   help="autosaves (5 min) progress to/ restores it from a file")
    parser.add_argument("--restore",     type=argparse.FileType("r+b", 0), metavar="FILE", help="restores progress and options from an autosave file (must be the only option on the command line)")
    parser.add_argument("--threads",     type=int, default=cpus, metavar="COUNT", help="number of worker threads (default: number of CPUs, "+str(cpus)+")")
    parser.add_argument("--max-eta",     type=int, default=168,  metavar="HOURS", help="max estimated runtime before refusing to even start (default: 168 hours, i.e. 1 week)")
    parser.add_argument("--no-dupchecks",action="store_true", help="disable duplicate guess checking to save memory")
    parser.add_argument("--no-progress", action="store_true", help="disable the progress bar")
    parser.add_argument("--listpass",    action="store_true", help="just list all password combinations and exit")
    parser.add_argument("--pause",       action="store_true", help="pause before exiting")
    parser.add_argument("--version",     action="version",    version="%(prog)s " + __version__)

    # effective_argv is what we are effectively given, either via the command line, via embedded
    # optinos in the tokenlist file, or as a result of restoring a session, before any argument
    # processing or defaulting is done (unless it's is done by argparse). Each time effective_argv
    # is changed (due to reading a tokenlist or restore file, we redo parser.parse_args() which
    # overwrites args, so we only do this early on before any real args processing takes place.
    effective_argv = sys.argv[1:]
    args = parser.parse_args()

    # Do this as early as possible so user doesn't miss any error messages
    if args.pause:
        atexit.register(lambda: raw_input("Press Enter to exit ..."))
        pause_registered = True
    else:
        pause_registered = False

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
            print("Reading additional options from tokenlist file '"+tokenlist_file.name+"'")
            tokenlist_args = ("--"+tokenlist_file.readline()).split()  # TODO: support quoting / escaping?
            for arg in tokenlist_args:
                if arg.startswith("--to"):  # --tokenlist
                    print(parser.prog+": error: the --tokenlist option is not permitted inside a tokenlist file", file=sys.stderr)
                    sys.exit(2)
            effective_argv = tokenlist_args + effective_argv
            args = parser.parse_args(effective_argv)  # reparse the arguments
            # Check this again as early as possible so user doesn't miss any error messages
            if not pause_registered and args.pause:
                atexit.register(lambda: raw_input("Press Enter to exit ..."))
                pause_registered = True
        else:
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
        assert args.autosave, "autosave option enabled in restored autosave file"
        # Check this again as early as possible so user doesn't miss any error messages
        if not pause_registered and args.pause:
            atexit.register(lambda: raw_input("Press Enter to exit ..."))
            pause_registered = True
        #
        # We finally know the tokenlist filename; open it here
        if args.tokenlist:                                 tokenlist_file = open(args.tokenlist)
        elif os.path.isfile("btcrecover-tokens-auto.txt"): tokenlist_file = open("btcrecover-tokens-auto.txt")
        if tokenlist_file:
            if tokenlist_file.read(3) == "#--":
                print(parser.prog+": warning: all options loaded from restore file; ignoring options in tokenlist file '"+tokenlist_file.name+"'", file=sys.stderr)
                tokenlist_file.readline()
            else:
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
        print("Using autosave file '"+args.autosave+"'")
        args.skip = savestate["skip"]  # override this with the most recent value
        restored = True   # a global flag for future reference
    #
    else:
        restored = False  # a global flag for future reference

    argsdict = vars(args)  # only used to check for presence of typos_* arguments

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
        wildcard_sets["c"] = args.custom_wild
        wildcard_sets["C"] = args.custom_wild.upper()
        custom_wildset_caseswapped = "".join([c.swapcase() for c in args.custom_wild if c.swapcase() != c])
        if len(custom_wildset_caseswapped) > 0:
            wildcard_nocase_sets["c"] = wildcard_sets["c"] + custom_wildset_caseswapped
            wildcard_nocase_sets["C"] = wildcard_sets["C"] + custom_wildset_caseswapped.swapcase()
        wildcard_keys += "cC"

    # Syntax check any --typos-insert wildcard (it's expanded later in the Password Generation section)
    if args.typos_insert:
        # Remove all valid wildcard specs; if any %'s are left they are invalid
        valid_wildcards_removed = re.sub(r"%(?:(?:\d+,)?\d+)?(?:i)?["+wildcard_keys+"]", "", args.typos_insert)
        if "%" in valid_wildcards_removed:
            print(parser.prog+": error: --typos-insert", args.typos_insert, "has an invalid wildcard (%) spec", file=sys.stderr)
            sys.exit(2)
    #
    # Syntax check any --typos-replace wildcard (it's expanded later in the Password Generation section)
    if args.typos_replace:
        # Remove all valid wildcard specs; if any %'s are left they are invalid
        valid_wildcards_removed = re.sub(r"%(?:(?:\d+,)?\d+)?(?:i)?["+wildcard_keys+"]", "", args.typos_replace)
        if "%" in valid_wildcards_removed:
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
            #
            replacement_set = frozenset(split_line[1])  # removes duplicate replacements if any
            replacement_sorted_list = list(replacement_set)
            replacement_sorted_list.sort()  # otherwise the order could change between runs, which'd BREAK --skip and --restore
            for c in split_line[0]:
                if c in replacement_set:
                    typos_map[c] = [r for r in replacement_sorted_list if r != c]
                else:
                    typos_map[c] = replacement_sorted_list
        #
        # Take a hash of the typos_map and check it during a session restore
        # to make sure we're actually restoring the exact same session
        if args.autosave:
            sha1 = hashlib.sha1()
            sorted_keys = typos_map.keys()
            sorted_keys.sort()
            for k in sorted_keys:  # must take the hash in a deterministic order (not in typos_map order)
                sha1.update(k + str(typos_map[k]))
            typos_map_hash = sha1.digest()
            sha1 = None
        if restored:
            if typos_map_hash != savestate["typos_map_hash"]:
                print(parser.prog+": error: can't restore previous session: the typos_map file has changed", file=sys.stderr)
                sys.exit(1)

    worker_threads = max(args.threads, 1)

    if args.no_progress: have_progress = False
    else:
        try:
            from progressbar import *
            have_progress = True
        except:
            have_progress = False

    # Load the wallet file (unless only --listpass has been requested)
    if args.wallet:
        load_wallet(args.wallet)
    elif not args.listpass:
        print(parser.prog+": error: argument --wallet (or --listpass) is required", file=sys.stderr)
        sys.exit(2)

    if not has_bsddb:
        print(parser.prog+": warning: can't load bsddb, falling back to experimental Bitcoin Core wallet parsing mode", file=sys.stderr)

    # Open a new autosave file (if --restore was specified, the restore file
    # is still open and has already been assigned to autosave_file instead)
    if args.autosave and not restored:
        if args.listpass:
            print(parser.prog+": warning: --autosave is ignored with --listpass", file=sys.stderr)

        # Don't overwrite nonzero files or nonfile objects (e.g. directories)
        if os.path.exists(args.autosave) and (os.path.getsize(args.autosave) > 0 or not os.path.isfile(args.autosave)):
            print(parser.prog+": error: --autosave file '"+args.autosave+"' already exists, won't overwrite", file=sys.stderr)
            sys.exit(1)
        autosave_file = open(args.autosave, "wb", 0)  # (0 == buffering is disabled)
        print("Using autosave file '"+args.autosave+"'")


############################## Tokenfile Parsing ##############################


# Build up the token_lists structure, a list of lists, reflecting the tokenlist file.
# Each list in the token_lists list is preceded with a None element unless the
# corresponding line in the tokenlist file begins with a "+" (see example below).
#
# EXAMPLE FILE:
#     # lines that begin with # are ignored comments
#     an_optional_token_exactly_one_per_line...
#     ...may_or_may_not_be_tried_per_guess
#     mutually_exclusive  token_list  on_one_line  at_most_one_is_tried
#     +  this_required_token_was_preceded_by_a_plus_in_the_file
#     +  exactly_one_of_these  tokens_are_required  and_were_preceded_by_a_plus
# RESULTANT token_lists
# [
#     [ None, 'an_optional_token_exactly_one_per_line...' ],
#     [ None, '...may_or_may_not_be_tried_per_guess' ],
#     [ None, 'mutually_exclusive', 'token_list', 'on_one_line', 'at_most_one_is_tried' ],
#     [ 'this_required_token_was_preceded_by_a_plus_in_the_file' ],
#     [ 'exactly_one_of_these', 'tokens_are_required', 'and_were_preceded_by_a_plus' ]
# ]
#
has_any_wildcards = False
token_lists = []
if __name__ == '__main__':
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
            del new_list[0:2]\

        # Syntax checks
        for token in new_list:
            if token is None: continue

            for c in token:
                if ord(c) > 127:
                    print(parser.prog+": error: token on line", line_num, "has non-ASCII character '"+c+"'", file=sys.stderr)
                    sys.exit(1)

            # A token anchored at both beginning and end is probably a mistake
            if token[0] == "^" and token[-1] == "$":
                print(parser.prog+": error: token on line", line_num, "is anchored with both ^ (begins with) and $ (ends with)", file=sys.stderr)
                sys.exit(1)

            # Remove all valid wildcard specs; if any %'s are left they are invalid
            valid_wildcards_removed = re.sub(r"%(?:(?:\d+,)?\d+)?(?:i)?["+wildcard_keys+"]", "", token)
            if "%" in valid_wildcards_removed:
                print(parser.prog+": error: token on line", line_num, "has an invalid wildcard (%) spec (use %% to escape a %)", file=sys.stderr)
                sys.exit(1)
            if len(valid_wildcards_removed) != len(token):
                has_any_wildcards = True

        # Add the completed list to the token_lists list of lists
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
            sys.exit(1)


############################## Password Generation ##############################


# Used to communicate between typo generators the number of typos that have been
# created so far during each password generated so that later generators know how
# many additional typos, at most, they are permitted to add
typos_sofar = 0

# The main generator function produces all possible requested password permutations with
# no duplicates from the token_lists global as constructed above plus any requested typos
#
# Caches duplicate passwords for reducing memory usage during additional (identical) runs
duplicate_passwords = dict()
run_number = 0
#
def password_generator():
    global typos_sofar, duplicate_passwords, run_number
    passwords_seen_once = set()

    # Build up the modification_generators list; see the inner loop below for more details
    modification_generators = []
    if has_any_wildcards:           modification_generators.append( expand_wildcards_generator )
    if args.typos_capslock:         modification_generators.append( capslock_typos_generator   )
    if args.typos_swap:             modification_generators.append( swap_typos_generator       )
    if simple_typo_types_specified: modification_generators.append( simple_typos_generator     )

    # The outer loop iterates through all possible (unordered) combinations of tokens
    # taking into account the at-most-one-token-per-line rule. Note that lines which
    # were not required (no "+") have a None in their corresponding list; if this
    # None item is chosen for a tokens_combination we simply remove it below.
    for tokens_combination in itertools.product(*token_lists):

        # Remove any None's, then check against token length constraints:
        collapsed_tokens_combination = filter( lambda t: t is not None , tokens_combination)
        if len(collapsed_tokens_combination) not in xrange(args.min_tokens, args.max_tokens+1): continue

        # Look for anchors (^ or $) in each token to force the tokens into the specified position
        begin_anchor = ""
        end_anchor = ""
        duplicate_anchors = False
        unanchored_tokens_combination = []
        for token in collapsed_tokens_combination:
            if token[0] == "^":
                if begin_anchor: duplicate_anchors = True; break
                begin_anchor = token[1:]
            elif token[-1] == "$":
                if end_anchor:   duplicate_anchors = True; break
                end_anchor = token[0:-1]
            else:
                unanchored_tokens_combination.append(token)
        #
        # A combination that includes two tokens anchored to the same place is skipped
        if duplicate_anchors: continue
        #
        # Handle the case where all tokens in this combination are anchored ones
        if len(unanchored_tokens_combination) == 0:
            unanchored_tokens_combination = [ "" ]

        # The middle loop iterates through all possible permutations (orderings) of one
        # combination of tokens and combines the tokens to create a password string
        for ordered_token_guess in itertools.permutations(unanchored_tokens_combination):
            password_base = begin_anchor + "".join(ordered_token_guess) + end_anchor

            # The inner loop takes the password_base and applies zero or more modifications
            # to it to produce a number of different possible variations of password_base
            # (e.g. different wildcard expansions, typos, etc.)

            # Reset this for each new password_base
            typos_sofar = 0

            # modification_generators is a list of function generators each of which take a
            # string and produces one or more password variations based on that string. It is
            # built at the beginning of this function, and is built differently depending on
            # the token_lists (are any wildcards present?) and the program options (were any
            # typos requested?). It may contain:
            #     expand_wildcards_generator, swap_typos_generator, and/or simple_typos_generator

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

                # Skip producing this password if it's already been produced (unless dupchecks are disabled)
                if not args.no_dupchecks:

                    # duplicate_passwords cache is built during the first run
                    if run_number == 0:
                        if password in passwords_seen_once:               # second time we've seen it;
                            duplicate_passwords[password] = 1             # this passwords has dup(s)
                            passwords_seen_once.remove(password)          # (seen more than once - remove it)
                            continue
                        else:
                            if password in duplicate_passwords: continue  # third+ time we've seen it
                            else: passwords_seen_once.add(password)       # first time we've seen it

                    # duplicate_passwords cache is available for lookup on second+ runs
                    else:
                        dup = duplicate_passwords.get(password)
                        if dup:
                            if dup <= run_number:
                                duplicate_passwords[password] = run_number + 1  # first time we've seen it
                            else: continue                                      # second+ time we've seen it

                yield password

    run_number += 1

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
def expand_wildcards_generator(password_with_wildcards):

    # Quick check to see if any wildcards are present
    if password_with_wildcards.find("%") == -1:
        # If none, just produce the string and end
        yield password_with_wildcards
        return

    # Find the first wildcard parameter in the format %[[min,]max][caseflag]type
    # where caseflag=="i" if present and type is one of the wildcard_keys (e.g. "%d", "%2n", "%1,3ia", etc.)
    match = re.search(r"%(?:(?:(?P<min>\d+),)?(?P<max>\d+))?(?P<nocase>i)?(?P<type>["+wildcard_keys+"])", password_with_wildcards)
    assert match, "parsed valid wildcard spec"

    password_prefix = password_with_wildcards[0:match.start()]               # no wildcards present here;
    password_postfix_with_wildcards = password_with_wildcards[match.end():]  # might be other wildcards in here

    # Build the set of possible characters based on the wildcard type and caseflag
    if match.group("nocase") and match.group("type") in wildcard_nocase_sets:
        wildcard_set = wildcard_nocase_sets[match.group("type")]
    else:
        wildcard_set = wildcard_sets[match.group("type")]
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
    # up to the max requested or up to the max number swappable (whichever's less).
    # The max number swappable is len // 2 because we never any single character twice.
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
                    if password[i] == password[i+1]:
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
        typos_insert_expanded  = [s for s in expand_wildcards_generator(args.typos_insert)]
    if args.typos_replace:
        typos_replace_expanded = [s for s in expand_wildcards_generator(args.typos_replace)]
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

                # For each of the selected typo targets, call the selected generator to
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
                    # typo_indexes_ has a sentinal at the end; it's the index of
                    # one-past-the-end of password_base.
                    typo_indexes_ = typo_indexes + (len(password_base),)
                    password = password_base[0:typo_indexes_[0]]
                    for i, replacement in enumerate(one_replacement_set):
                        password += replacement + password_base[typo_indexes_[i]+1:typo_indexes_[i+1]]
                    yield password

        typos_sofar -= typos_count


############################## Main ##############################


# Init function for the password verifying worker threads:
#   (re-)loads the wallet file (should only be necessary on Windows),
#   tries to set the process priority to minimum, and
#   begins ignoring SIGINTs for a more graceful exit on Ctrl-C
def init_worker(wallet_filename):
    if not wallet: load_wallet(wallet_filename)
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

# TODO: implement a safer atomic autosave? fsync? (buffering is already disabled at file open)
def do_autosave(skip):
    assert autosave_file and not autosave_file.closed,  "autosave_file is open"
    autosave_file.seek(0)
    orig_handler = signal.signal(signal.SIGINT, signal.SIG_IGN)  # ignore Ctrl-C while saving
    autosave_file.truncate()
    cPickle.dump(dict(
            argv=effective_argv,
            skip=skip,
            token_lists_hash=token_lists_hash,
            typos_map_hash=typos_map_hash),
        autosave_file, cPickle.HIGHEST_PROTOCOL)
    autosave_file.flush()  # buffering should already be disabled, but this doesn't hurt
    signal.signal(signal.SIGINT, orig_handler)


if __name__ == '__main__':

    # If --listpass was requested, just list out all the passwords and exit
    passwords_count = 0
    if args.listpass:
        for password in password_generator():
            print(password)
            passwords_count += 1
        print("\n", passwords_count, "password combinations", file=sys.stderr)
        sys.exit(0)

    # If the time to verify a password is short enough, the time to generate the passwords in this thread
    # becomes comparable to verifying passwords, therefore this should count towards being a "worker" thread
    est_secs_per_password = get_est_secs_per_password()
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
            sys.exit(1)
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
        pool = multiprocessing.Pool(spawned_threads, init_worker, [args.wallet])
        password_found_iterator = pool.imap(return_verified_password_or_false, password_iterator, imap_chunksize)
        if main_thread_is_worker: set_process_priority_idle()  # if this thread is cpu-intensive, be nice

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

    # Gracefully handle Ctrl-C, printing the count completed so far
    # so that it can be skipped if the user restarts the same run
    except KeyboardInterrupt:
        print("\nInterrupted after finishing password #", args.skip + passwords_tried)

    # Autosave the final state (for all cases-- we were interrupted, password was found, or search exhausted)
    if args.autosave:
        do_autosave(args.skip + passwords_tried)
        autosave_file.close()
