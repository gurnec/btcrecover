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

# TODO: Unicode support? permit 8-bit characters (already done for passwordlist)?
# TODO: put everything in a class?
# TODO: pythonize comments/documentation

# (all futures as of 2.6 and 2.7 except unicode_literals)
from __future__ import print_function, absolute_import, division, \
                       generators, nested_scopes, with_statement

__version__          = "0.7.1"
__ordering_version__ = "0.6.4"  # must be updated whenever password ordering changes

import sys, argparse, itertools, string, re, multiprocessing, signal, os, os.path, \
       cPickle, gc, time, hashlib, collections, base64, struct, ast, atexit, zlib

# The progressbar module is recommended but optional; it is typically
# distributed with btcrecover (it is loaded later on demand)

# The pywin32 module is also recommended on Windows but optional; it's only
# used to adjust the process priority to be more friendly and to catch more
# signals (other than just Ctrl-C) for better autosaves. When used with
# Armory, btcrecover will just load the version that ships with Armory.


################################### Configurables/Plugins ###################################
# wildcard sets, simple typo generators, and wallet support functions


# Recognized wildcard (e.g. %d, %a) types mapped to their associated sets
# of characters; used in expand_wildcards_generator()
# warning: don't use digits, 'i', '[', ',', '-', '<', or '>' as the key for a wildcard set
def init_wildcards():
    global wildcard_sets, wildcard_keys, wildcard_nocase_sets, custom_wildcard_cache
    all_ascii_symbols = "".join(map(chr, range(33, 48)+range(58, 65)+range(91, 97)+range(123, 127)))
    wildcard_sets = {
        "d" : string.digits,
        "a" : string.lowercase,
        "A" : string.uppercase,
        "n" : string.lowercase + string.digits,
        "N" : string.uppercase + string.digits,
        "s" : " ",        # space
        "l" : "\n",       # line feed
        "r" : "\r",       # carriage return
        "R" : "\n\r",     # newline characters
        "t" : "\t",       # tab
        "T" : " \t",      # space and tab
        "w" : " \r\n",    # space and newline characters
        "W" : " \r\n\t",  # space, newline, and tab
        "y" : all_ascii_symbols,
        "Y" : string.digits + all_ascii_symbols,
        "p" : "".join(map(chr, xrange(33, 127))),  # all ASCII printable characters except whitespace
        "P" : "".join(map(chr, xrange(33, 127))) + " \r\n\t",  # as above, plus space, newline, and tab
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
    #
    custom_wildcard_cache = dict()


# Simple typo generators produce (as an iterable, e.g. a tuple, generator, etc.)
# zero or more alternative typo strings which can replace a single character. If
# more than one string is produced, all combinations are tried. If zero strings are
# produced (e.g. an empty tuple), then the specified input character has no typo
# alternatives that can be tried (e.g. you can't change the case of a caseless char).
# They are called with the full password and an index into that password of the
# character which will be replaced.
#
def typo_repeat(p, i): return 2 * p[i],  # a single replacement of len 2
def typo_delete(p, i): return "",        # s single replacement of len 0
def typo_case(p, i):
    swapped = p[i].swapcase()
    return (swapped,) if swapped != p[i] else ()
def typo_closecase(p, i):  # (case_id functions defined in the Password Generation section)
    cur_case_id = case_id_of(p[i])
    if cur_case_id == UNCASED_ID: return ()
    if i==0 or i+1==len(p) or \
            case_id_changed(case_id_of(p[i-1]), cur_case_id) or \
            case_id_changed(case_id_of(p[i+1]), cur_case_id):
        return p[i].swapcase(),
    return ()
def typo_replace_wildcard(p, i): return [e      for e in typos_replace_expanded if e != p[i]]
def typo_map(p, i):              return typos_map.get(p[i], ())
# (typos_replace_expanded and typos_map are initialized from args.typos_replace
# and args.typos_map respectively in parse_args() )
#
# a dict: command line argument name is: "typos-" + key_name; associated value is
# the generator function from above; this dict MUST BE ORDERED to prevent the
# breakage of --skip and --restore features (the order can be arbitrary, but it
# MUST be repeatable across runs and preferably across implementations)
simple_typos = collections.OrderedDict()
simple_typos["repeat"]    = typo_repeat
simple_typos["delete"]    = typo_delete
simple_typos["case"]      = typo_case
simple_typos["closecase"] = typo_closecase
simple_typos["replace"]   = typo_replace_wildcard
simple_typos["map"]       = typo_map
#
# a dict: typo name (matches typo names in the dict above) mapped to the options
# that are passed to add_argument; this dict is only ordered for cosmetic reasons
simple_typo_args = collections.OrderedDict()
simple_typo_args["repeat"]    = dict( action="store_true",       help="repeats (doubles) a character" )
simple_typo_args["delete"]    = dict( action="store_true",       help="deletes a character" )
simple_typo_args["case"]      = dict( action="store_true",       help="changes the case (upper/lower) of a letter" )
simple_typo_args["closecase"] = dict( action="store_true",       help="like --typos-case, but only changes letters next to one with a different case")
simple_typo_args["map"]       = dict( metavar="FILE",            help="replaces specific characters based on a map file" )
simple_typo_args["replace"]   = dict( metavar="WILDCARD-STRING", help="replaces a character with another string or wildcard" )


# TODO: work on wallet "plugin" interface; via subclassing?

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
        try:              is_multibitpk = base64.b64decode(wallet_file.read(20).lstrip()[:12]).startswith(b"Salted__")
        except TypeError: is_multibitpk = False
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

        error_exit("unrecognized wallet format")

# Clears out any wallet data (but doesn't "unload" any wallet libraries)
def unload_wallet():
    wallet = None


# Given a base64 string that was produced by one of the extract-* scripts,
# determines the wallet type and calls a function to load a wallet library,
# the key, and set the measure_performance_iterations global to result in
# about 0.5 seconds worth of iterations. Also sets the
# return_verified_password_or_false global to point to the correct function
# for the discovered key type. (This can be called instead of load_wallet() )
def load_from_base64_key(key_crc_base64):
    try:   key_crc_data = base64.b64decode(key_crc_base64)
    except TypeError: error_exit("encrypted key data is corrupted (invalid base64)")

    if len(key_crc_data) < 8:
        error_exit("encrypted key data is corrupted (too short)")
    l_key_data = key_crc_data[:-4]
    (key_crc,) = struct.unpack("<I", key_crc_data[-4:])
    if zlib.crc32(l_key_data) & 0xffffffff != key_crc:
        error_exit("encrypted key data is corrupted (failed CRC check)")

    load_from_raw_key(l_key_data)
    # Need to save key_data (in a global) for reinitializing worker processes on windows
    global key_data
    key_data = l_key_data

    return key_crc
#
def load_from_raw_key(key_data):
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

    error_exit("unrecognized encrypted key type")


armoryengine = None
def load_armory_library():
    global measure_performance_iterations, armoryengine, SecureBinaryData, KdfRomix
    measure_performance_iterations = 2
    if armoryengine: return

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
    try:

        # Try up to 10 times to load Armory (there's a race condition on opening the log file in Windows multiprocessing)
        for i in xrange(10):
            try: import armoryengine.PyBtcWallet, armoryengine.PyBtcAddress
            except IOError as e:
                if i<9 and e.filename.endswith(r"\armorylog.txt"): time.sleep(0.1)
                else: raise  # unexpected failure
            else: break  # when it succeeds
        from CppBlockUtils import SecureBinaryData, KdfRomix  # (also a part of Armory)

    finally:
        sys.argv[1:] = old_argv  # restore the command line

# Load the Armory wallet file given the filename
def load_armory_wallet(wallet_filename):
    global wallet
    load_armory_library()
    wallet = armoryengine.PyBtcWallet.PyBtcWallet().readWalletFile(wallet_filename)

# This is the time-consuming function executed by worker thread(s). It returns a tuple: if a password
# is correct return it, else return False for item 0; return a count of passwords checked for item 1
def return_armory_verified_password_or_false(passwords):
    for count, password in enumerate(passwords, 1):
        if wallet.verifyPassphrase(SecureBinaryData(password)):
            return password, count
    return False, count

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

# This is the time-consuming function executed by worker thread(s). It returns a tuple: if a password
# is correct return it, else return False for item 0; return a count of passwords checked for item 1
def return_armorypk_verified_password_or_false(passwords):
    address, kdf = wallet
    for count, password in enumerate(passwords, 1):
        if address.verifyEncryptionKey(kdf.DeriveKey(SecureBinaryData(password))):
            return password, count
        address.binPublicKey65 = SecureBinaryData()  # work around bug in verifyEncryptionKey in Armory 0.91
    else:
        return False, count


# Load a Bitcoin Core BDB wallet file given the filename and extract the first encrypted master key
def load_bitcoincore_wallet(wallet_filename):
    global measure_performance_iterations, wallet
    load_aes256_library()
    measure_performance_iterations = 5  # load_aes256_library sets this, but it's changed here
    wallet_filename = os.path.abspath(wallet_filename)
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

# This is the time-consuming function executed by worker thread(s). It returns a tuple: if a password
# is correct return it, else return False for item 0; return a count of passwords checked for item 1
def return_bitcoincore_verified_password_or_false(passwords):
    # Copy a global into local for a small speed boost
    l_sha512 = hashlib.sha512
    encrypted_master_key, salt, iter_count = wallet
    for count, password in enumerate(passwords, 1):
        derived_key_iv = password + salt
        for i in xrange(iter_count):
            derived_key_iv = l_sha512(derived_key_iv).digest()
        master_key = aes256_cbc_decrypt(derived_key_iv[0:32], derived_key_iv[32:48], encrypted_master_key)
        # If the 48 byte encrypted_master_key decrypts to exactly 32 bytes long (padded with 16 16s), we've found it
        if master_key.endswith(b"\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10"):
            return password, count
    return False, count

# Load the OpenCL libraries and return a list of available devices
cl_devices_avail = None
def get_opencl_devices():
    global pyopencl, numpy, cl_devices_avail
    if not cl_devices_avail:
        import pyopencl, numpy
        cl_devices_avail = filter(lambda d: d.available==1 and d.profile=="FULL_PROFILE" and d.endian_little==1,
            itertools.chain(*[p.get_devices() for p in pyopencl.get_platforms()]))
    return cl_devices_avail

# Load and initialize the OpenCL kernel for Bitcoin Core, given:
#   devices - a list of one or more of the devices returned by get_opencl_devices()
#   global_ws - a list of global work sizes, exactly one per device
#   local_ws  - a list of local work sizes (or Nones), exactly one per device
#   int_rate  - number of times to interrupt calculations to prevent hanging
#               the GPU driver per call to return_verified_password_or_false()
def init_bitcoincore_opencl_kernel(devices, global_ws, local_ws, int_rate):
    global cl_devices, cl_global_ws, cl_local_ws, cl_kernel, cl_queues, cl_hashes_buffers, \
           return_verified_password_or_false, iter_count_chunksize

    # Need to save these for return_bitcoincore_opencl_verified_password_or_false()
    assert devices, "init_bitcoincore_opencl_kernel: at least one device is selected in cl_devices"
    assert len(devices) == len(global_ws) == len(local_ws), "init_bitcoincore_opencl_kernel: one global_ws and one local_ws specified for each device"
    cl_devices   = devices
    cl_global_ws = global_ws
    cl_local_ws  = local_ws

    cl_context = cl_kernel = cl_queues = cl_hashes_buffers = None  # clear any previously loaded
    cl_context = pyopencl.Context(devices)
    #
    # Load and compile the OpenCL program
    cl_program = pyopencl.Program(cl_context,
        open(os.path.join(os.path.dirname(__file__), "sha512-ng-bc_kernel.cl")).read()).build("-w")
    #
    # Configure and store for later the OpenCL kernel (the entrance function)
    cl_kernel  = cl_program.kernel_sha512_bc
    cl_kernel.set_scalar_arg_dtypes([None, numpy.uint32])

    # Create one command queue and one I/O buffer per device
    cl_queues         = []
    cl_hashes_buffers = []
    for i, device in enumerate(devices):
        cl_queues.append(pyopencl.CommandQueue(cl_context, device))
        # Each buffer is of len --global-ws * (size-of-sha152-hash-in-bytes == 512 bits / 8 == 64)
        cl_hashes_buffers.append(pyopencl.Buffer(cl_context, pyopencl.mem_flags.READ_WRITE, global_ws[i] * 64))

    # Doing all iter_count iterations at once will hang the GPU, so instead calculate how
    # many iterations should be done at a time based on iter_count and the requested int_rate,
    # trying to maximize the number of iterations done in the last set to optimize performance
    assert isinstance(wallet, tuple) and len(wallet) == 3, "init_bitcoincore_opencl_kernel: bitcoin core wallet or mkey has been loaded"
    iter_count = wallet[2]
    iter_count_chunksize = iter_count // int_rate or 1
    if iter_count_chunksize % int_rate != 0:  # if not evenly divisible,
        iter_count_chunksize += 1             # then round up

    return_verified_password_or_false = return_bitcoincore_opencl_verified_password_or_false

def return_bitcoincore_opencl_verified_password_or_false(passwords):
    assert len(passwords) <= sum(cl_global_ws), "return_bitcoincore_opencl_verified_password_or_false: at most --global-ws passwords"
    encrypted_master_key, salt, iter_count = wallet

    # The first iter_count iteration is done by the CPU
    hashes = numpy.empty([sum(cl_global_ws), 64], numpy.uint8)
    for i, password in enumerate(passwords):
        hashes[i] = numpy.fromstring(hashlib.sha512(password + salt).digest(), numpy.uint8)

    # Divide up and copy the starting hashes into the OpenCL buffer(s) (one per device) in parallel
    done   = []  # a list of OpenCL event objects
    offset = 0
    for devnum, ws in enumerate(cl_global_ws):
        done.append(pyopencl.enqueue_copy(cl_queues[devnum], cl_hashes_buffers[devnum], hashes[offset : offset + ws], is_blocking=False))
        cl_queues[devnum].flush()  # Starts the copy operation
        offset += ws
    pyopencl.wait_for_events(done)

    # Doing all iter_count iterations at once will hang the GPU, so instead do iter_count_chunksize
    # iterations at a time, pausing briefly while waiting for them to complete, and then continuing.
    # Because iter_count is probably not evenly divisible by iter_count_chunksize, the loop below
    # performs all but the last of these iter_count_chunksize sets of iterations.

    i = 1 - iter_count_chunksize  # used if the loop below doesn't run (when --int-rate == 1)
    for i in xrange(1, iter_count - iter_count_chunksize, iter_count_chunksize):
        done = []  # a list of OpenCL event objects
        # Start up a kernel for each device to do one set of iter_count_chunksize iterations
        for devnum in xrange(len(cl_devices)):
            done.append(cl_kernel(cl_queues[devnum], (cl_global_ws[devnum],), None if cl_local_ws[devnum] is None else (cl_local_ws[devnum],),
                cl_hashes_buffers[devnum], iter_count_chunksize))
            cl_queues[devnum].flush()  # Starts the kernel
        pyopencl.wait_for_events(done)

    # Perform the last remaining set of iterations (usually fewer then iter_count_chunksize)
    done = []  # a list of OpenCL event objects
    for devnum in xrange(len(cl_devices)):
        done.append(cl_kernel(cl_queues[devnum], (cl_global_ws[devnum],), None if cl_local_ws[devnum] is None else (cl_local_ws[devnum],),
            cl_hashes_buffers[devnum], iter_count - iter_count_chunksize - i))
        cl_queues[devnum].flush()  # Starts the kernel
    pyopencl.wait_for_events(done)

    # Copy the resulting fully computed hashes back to RAM in parallel
    done   = []  # a list of OpenCL event objects
    offset = 0
    for devnum, ws in enumerate(cl_global_ws):
        done.append(pyopencl.enqueue_copy(cl_queues[devnum], hashes[offset : offset + ws], cl_hashes_buffers[devnum], is_blocking=False))
        offset += ws
        cl_queues[devnum].flush()  # Starts the copy operation
    pyopencl.wait_for_events(done)

    # Using the computed hashes, try to decrypt the master key (in CPU)
    for i, password in enumerate(passwords):
        derived_key_iv = hashes[i].tostring()
        master_key = aes256_cbc_decrypt(derived_key_iv[0:32], derived_key_iv[32:48], encrypted_master_key)
        # If the 48 byte encrypted_master_key decrypts to exactly 32 bytes long (padded with 16 16s), we've found it
        if master_key.endswith(b"\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10"):
            return password, i + 1
    return False, i + 1


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
    assert wallet.startswith(b"Salted__"), "load_multibit_privkey_file: file starts with base64 'Salted__'"
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

# This is the time-consuming function executed by worker thread(s). It returns a tuple: if a password
# is correct return it, else return False for item 0; return a count of passwords checked for item 1
def return_multibitpk_verified_password_or_false(passwords):
    # Copy a global into local for a small speed boost
    l_md5 = hashlib.md5
    for count, password in enumerate(passwords, 1):
        salted = password + wallet[:8]
        key1   = l_md5(salted).digest()
        key2   = l_md5(key1 + salted).digest()
        iv     = l_md5(key2 + salted).digest()
        b58_privkey = aes256_cbc_decrypt(key1 + key2, iv, wallet[8:])
        # If it looks like a base58 private key, we've found it
        # (there's a 1 in 600 billion chance this hits but the password is wrong)
        # (may be fragile, e.g. what if comments or whitespace precede the first key in future MultiBit versions?)
        if (b58_privkey[0] == b"L" or b58_privkey[0] == b"K") and \
            re.match(br".[1-9A-HJ-NP-Za-km-z]{15}", b58_privkey):
                return password, count
    return False, count


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

# This is the time-consuming function executed by worker thread(s). It returns a tuple: if a password
# is correct return it, else return False for item 0; return a count of passwords checked for item 1
def return_electrum_verified_password_or_false(passwords):
    # Copy a global into local for a small speed boost
    l_sha256 = hashlib.sha256
    for count, password in enumerate(passwords, 1):
        key  = l_sha256( l_sha256( password ).digest() ).digest()
        seed = aes256_cbc_decrypt(key, wallet[:16], wallet[16:])
        # If the 48 byte encrypted seed decrypts to exactly 32 bytes long (padded with 16 16s), we've found it
        if seed.endswith(b"\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10"):
            return password, count
    return False, count


# Loads PyCrypto if available, else falls back to the pure python version (30x slower)
missing_pycrypto_warned = False
def load_aes256_library(force_purepython = False):
    global Crypto, aespython, aes256_cbc_decrypt, aes256_key_expander, \
           measure_performance_iterations, missing_pycrypto_warned
    if not force_purepython:
        try:
            import Crypto.Cipher.AES
            aes256_cbc_decrypt = aes256_cbc_decrypt_pycrypto
            measure_performance_iterations = 50000
            return Crypto
        except ImportError:
            if not missing_pycrypto_warned:
                print(prog+": warning: can't find PyCrypto, using aespython instead", file=sys.stderr)
                missing_pycrypto_warned = True
    import aespython.key_expander, aespython.aes_cipher, aespython.cbc_mode
    aes256_cbc_decrypt  = aes256_cbc_decrypt_pp
    aes256_key_expander = aespython.key_expander.KeyExpander(256)
    measure_performance_iterations = 2000
    return aespython

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


################################### Argument Parsing ###################################


# Calls sys.exit with an error message, taking unnamed arguments like print()
def error_exit(*msgs): sys.exit(prog + ": error: " + " ".join(map(str, msgs)))

# Returns an (order preserved) list or string with duplicate elements removed
# (if input is a string, returns a string, otherwise returns a list)
# (N.B. not a generator function, so faster for small inputs, not for large)
def duplicates_removed(iterable):
    if args.no_dupchecks >= 4:
        if isinstance(iterable, basestring) or isinstance(iterable, list):
            return iterable
        return list(iterable)
    seen = set()
    unique = []
    for x in iterable:
        if x not in seen:
            unique.append(x)
            seen.add(x)
    if len(unique) == len(iterable) and (isinstance(iterable, basestring) or isinstance(iterable, list)):
        return iterable
    elif isinstance(iterable, str):
        return b"".join(unique)
    elif isinstance(iterable, Unicode):
        return u"".join(unique)
    return unique

# Converts a wildcard set into a string, expanding ranges and removing duplicates,
# e.g.: "hexa-fA-F" -> "hexabcdfABCDEF"
def build_wildcard_set(set_string):
    return duplicates_removed(re.sub(r"(.)-(.)", expand_single_range, set_string))
#
def expand_single_range(m):
    char_first, char_last = map(ord, m.groups())
    if char_first > char_last:
        raise ValueError("first character in wildcard range '"+chr(char_first)+"' > last '"+chr(char_last)+"'")
    return "".join(map(chr, xrange(char_first, char_last+1)))

# Returns an integer count of valid wildcards in the string, or
# a string error message if any invalid wildcards are present
# (see expand_wildcards_generator() for more details on wildcards)
def count_valid_wildcards(str_with_wildcards, permit_contracting_wildcards = False):
    contracting_wildcards = "<>-" if permit_contracting_wildcards else ""
    # Remove all valid wildcards, syntax checking the min to max ranges; if any %'s are left they are invalid
    try:
        valid_wildcards_removed, count = \
            re.subn(r"%(?:(?:(\d+),)?(\d+))?(?:i)?(?:["+wildcard_keys+contracting_wildcards+"]|\[.+?\])",
            syntax_check_range, str_with_wildcards)
    except ValueError as e: return str(e)
    if "%" in valid_wildcards_removed:
        invalid_wildcard_msg = "invalid wildcard (%) syntax (use %% to escape a %)"
        # If checking with permit_contracting_wildcards==True returns something different,
        # then the string must contain contracting wildcards (which were not permitted)
        if not permit_contracting_wildcards and \
                count_valid_wildcards(str_with_wildcards, True) != invalid_wildcard_msg:
            return "contracting wildcards are not permitted here"
        else:
            return invalid_wildcard_msg
    if count == 0: return 0
    # Expand any custom wildcard sets for the sole purpose of checking for exceptions (e.g. %[z-a])
    # We know all wildcards present have valid syntax, so we don't need to use the full regex, but
    # we do need to capture %% to avoid parsing this as a wildcard set (it isn't one): %%[not-a-set]
    for wildcard_set in re.findall(r"%[\d,i]*\[(.+?)\]|%%", str_with_wildcards):
        if wildcard_set:
            try:   re.sub(r"(.)-(.)", expand_single_range, wildcard_set)
            except ValueError as e: return str(e)
    return count
#
def syntax_check_range(m):
    minlen, maxlen = m.groups()
    if minlen and maxlen and int(minlen) > int(maxlen):
        raise ValueError("min wildcard length ("+minlen+") > max length ("+maxlen+")")
    if maxlen and int(maxlen) == 0:
        print(prog+": warning: %0 or %0,0 wildcards always expand to empty strings", file=sys.stderr)
    return ""

# Loads the savestate from the more recent save slot in an autosave_file (into a global)
SAVESLOT_SIZE = 4096
def load_savestate(autosave_file):
    global savestate, autosave_nextslot
    savestate0 = savestate1 = first_error = None
    # Try to load both save slots, ignoring pickle errors at first
    autosave_file.seek(0)
    try:
        savestate0 = cPickle.load(autosave_file)
    except Exception as e:
        first_error = e
    else:  assert autosave_file.tell() <= SAVESLOT_SIZE, "load_savestate: slot 0 data <= "+str(SAVESLOT_SIZE)+" bytes long"
    autosave_file.seek(0, os.SEEK_END)
    autosave_len = autosave_file.tell()
    if autosave_len > SAVESLOT_SIZE:  # if the second save slot is present
        autosave_file.seek(SAVESLOT_SIZE)
        try:
            savestate1 = cPickle.load(autosave_file)
        except Exception: pass
        else:  assert autosave_file.tell() <= 2*SAVESLOT_SIZE, "load_savestate: slot 1 data <= "+str(SAVESLOT_SIZE)+" bytes long"
    else:
        # Convert an old format file to a new one by making it at least SAVESLOT_SIZE bytes long
        autosave_file.write((SAVESLOT_SIZE - autosave_len) * b"\0")
    #
    # Determine which slot is more recent, and use it
    if savestate0 and savestate1:
        use_slot = 0 if savestate0["skip"] >= savestate1["skip"] else 1
    elif savestate0:
        if autosave_len > SAVESLOT_SIZE:
            print(prog+": warning: data in second autosave slot was corrupted, using first slot", file=sys.stderr)
        use_slot = 0
    elif savestate1:
        print(prog+": warning: data in first autosave slot was corrupted, using second slot", file=sys.stderr)
        use_slot = 1
    else:
        print(prog+": warning: data in both primary and backup autosave slots is corrupted", file=sys.stderr)
        raise first_error
    if use_slot == 0:
        savestate = savestate0
        autosave_nextslot =  1
    else:
        assert use_slot == 1
        savestate = savestate1
        autosave_nextslot =  0

# Opens a new or returns an already-opened file, if it passes the specified constraints.
# * Only examines one file: if filename == "__funccall" and funccall_file is not None,
#   use it. Otherwise if filename is not None, use it. Otherwise if default_filename
#   exists, use it. Otherwise, return None.
# * After deciding which one file to potentially use, check it against the require_data
#   or new_or_empty "no-exception" constraints and just return None if either fails.
#   (These are "soft" fails which don't raise exceptions.)
# * Tries to open (if not already opened) and return the file, letting any exception
#   raised by open (a "hard" fail) to pass up.
def open_or_use(filename, mode="r", funccall_file=None, **kwds):
    permit_stdin     = kwds.get("permit_stdin")      # filename of "-" opens stdin
    default_filename = kwds.get("default_filename")  # may open this if it exists
    require_data     = kwds.get("require_data")      # open only if non-empty
    new_or_empty     = kwds.get("new_or_empty")      # open only if new or empty
    assert not(permit_stdin and require_data), "open_or_use: stdin cannot require_data"
    assert not(permit_stdin and new_or_empty), "open_or_use: stdin is never new_or_empty"
    assert not(require_data and new_or_empty), "open_or_use: can require_data or be new_or_empty"
    #
    # If the already-opened file was requested
    if funccall_file and filename == "__funccall":
        if require_data or new_or_empty:
            funccall_file.seek(0, os.SEEK_END)
            if funccall_file.tell() == 0:
                # The file is empty; if it shouldn't be:
                if require_data: return None
            else:
                funccall_file.seek(0)
                # The file has contents; if it shouldn't:
                if new_or_empty: return None
        return funccall_file
    #
    if permit_stdin and filename == "-":
        return sys.stdin
    #
    # If there was no file specified, but a default exists
    if not filename and default_filename:
        if permit_stdin and default_filename == "-":
            return sys.stdin
        if os.path.isfile(default_filename):
            filename = default_filename
    if not filename:
        return None
    #
    if require_data and (not os.path.isfile(filename) or os.path.getsize(filename) == 0):
        return None
    if new_or_empty and os.path.exists(filename) and (os.path.getsize(filename) > 0 or not os.path.isfile(filename)):
        return None
    return open(filename, mode)

# Enables pause-before-exit (at most once per program run) if stdin is interactive (a tty)
pause_registered = None
def enable_pause():
    global pause_registered
    if pause_registered is None:
        if sys.stdin.isatty():
            atexit.register(lambda: raw_input("Press Enter to exit ..."))
            pause_registered = True
        else:
            print(prog+": warning: ignoring --pause since stdin is not interactive (or was redirected)", file=sys.stderr)
            pause_registered = False


# argparse type functions
def strings_list(argval):
    return argval.split(",")
#
def positive_ints_list(argval):
    try:   result = map(int, argval.split(","))
    except ValueError: raise argparse.ArgumentTypeError("items in this comma-separated list must be positive integers")
    for i in result:
        if i < 1: raise argparse.ArgumentTypeError("integers in this list must be > 0")
    return result

# can raise an exception on some platforms
try:                  cpus = multiprocessing.cpu_count()
except StandardError: cpus = 1

# Build the list of command-line options common to both tokenlist and passwordlist files
parser_common = argparse.ArgumentParser(add_help=False)
prog          = parser_common.prog
parser_common.add_argument("--wallet",      metavar="FILE", help="the wallet file (this, --mkey, --privkey, or --listpass is required)")
parser_common.add_argument("--typos",       type=int, metavar="COUNT", help="simulate up to this many typos; you must choose one or more typo types from the list below")
parser_common.add_argument("--min-typos",   type=int, default=0, metavar="COUNT", help="enforce a min # of typos included per guess")
typo_types_group = parser_common.add_argument_group("typo types")
typo_types_group.add_argument("--typos-capslock", action="store_true", help="tries the password with caps lock turned on")
typo_types_group.add_argument("--typos-swap",     action="store_true", help="swaps two adjacent characters")
for typo_name, typo_args in simple_typo_args.items():
    typo_types_group.add_argument("--typos-"+typo_name, **typo_args)
typo_types_group.add_argument("--typos-insert",   metavar="WILDCARD-STRING", help="inserts a string or wildcard")
typo_types_group.add_argument("--max-adjacent-inserts", type=int, default=1, metavar="COUNT", help="max # of --typos-insert strings that can be inserted between a single pair of characters (default: 1)")
parser_common.add_argument("--custom-wild", metavar="STRING", help="a custom set of characters for the %%c wildcard")
parser_common.add_argument("--regex-only",  metavar="STRING", help="only try passwords which match the given regular expr")
parser_common.add_argument("--regex-never", metavar="STRING", help="never try passwords which match the given regular expr")
parser_common.add_argument("--delimiter",   metavar="STRING", help="the delimiter between tokens in the tokenlist or columns in the typos-map (default: whitespace)")
parser_common.add_argument("--skip",        type=int, default=0,    metavar="COUNT", help="skip this many initial passwords for continuing an interrupted search")
parser_common.add_argument("--threads",     type=int, default=cpus, metavar="COUNT", help="number of worker threads (default: number of CPUs, "+str(cpus)+")")
parser_common.add_argument("--worker",      metavar="ID#/TOTAL#",   help="divide the workload between TOTAL# servers, where each has a different ID# between 1 and TOTAL#")
parser_common.add_argument("--max-eta",     type=int, default=168,  metavar="HOURS", help="max estimated runtime before refusing to even start (default: 168 hours, i.e. 1 week)")
parser_common.add_argument("--no-eta",      action="store_true",    help="disable calculating the estimated time to completion")
parser_common.add_argument("--no-dupchecks", "-d", action="count", default=0, help="disable duplicate guess checking to save memory; specify up to four times for additional effect")
parser_common.add_argument("--no-progress", action="store_true",   default=not sys.stdout.isatty(), help="disable the progress bar")
parser_common.add_argument("--mkey",        action="store_true", help="prompt for a Bitcoin Core encrypted master key (from extract-mkey.py) instead of using a wallet file")
parser_common.add_argument("--privkey",     action="store_true", help="prompt for an encrypted private key (from extract-*-privkey.py) instead of using a wallet file")
parser_common.add_argument("--listpass",    action="store_true", help="just list all password combinations to test and exit")
parser_common.add_argument("--performance", action="store_true", help="run a continuous performance test (Ctrl-C to exit)")
parser_common.add_argument("--pause",       action="store_true", help="pause before exiting")
parser_common.add_argument("--version","-v",action="version", version="%(prog)s " + __version__)
gpu_group = parser_common.add_argument_group("GPU acceleration")
gpu_group.add_argument("--enable-gpu", action="store_true",     help="enable experimental OpenCL-based GPU acceleration (only supports Bitcoin Core wallets and mkeys)")
gpu_group.add_argument("--global-ws",  type=positive_ints_list, default=[4096], metavar="PASSWORD-COUNT-1[,PASSWORD-COUNT-2...]", help="OpenCL global work size (default: 4096)")
gpu_group.add_argument("--local-ws",   type=positive_ints_list, default=[None], metavar="PASSWORD-COUNT-1[,PASSWORD-COUNT-2...]", help="OpenCL local work size; --global-ws must be evenly divisible by --local-ws (default: auto)")
gpu_group.add_argument("--gpu-names",  type=strings_list,       metavar="NAME-OR-ID-1[,NAME-OR-ID-2...]", help="Choose GPU(s) on multi-GPU systems (default: auto)")
gpu_group.add_argument("--list-gpus",  action="store_true",     help="List available GPU names and IDs, then exit")
gpu_group.add_argument("--int-rate",   type=int, default=200,   metavar="RATE", help="interrupt rate: raise to improve PC's responsiveness at the expense of search performance (default: 200)")

# Once parse_arguments() has completed, password_generator_factory() will return an iterator
# (actually a generator object) configured to generate all the passwords requested by the
# command-line options, and return_verified_password_or_false() will be configured to check
# passwords against the wallet or key if one was specified. (typically called with sys.argv[1:])
# TODO: document kwds usage (as used by unit tests)
def parse_arguments(effective_argv, **kwds):
    # Do some basic globals initialization; the rest are all done below
    init_wildcards()
    init_password_generator()

    # effective_argv is what we are effectively given, either via the command line, via embedded
    # options in the tokenlist file, or as a result of restoring a session, before any argument
    # processing or defaulting is done (unless it's is done by argparse). Each time effective_argv
    # is changed (due to reading a tokenlist or restore file), we redo parser.parse_args() which
    # changes args, so we only do this early on before most args processing takes place.

    # Create a parser which can parse any supported option, and run it
    global args
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-h", "--help",  action="store_true", help="show this help message and exit")
    parser.add_argument("--tokenlist",   metavar="FILE",      help="the list of tokens/partial passwords (required)")
    parser.add_argument("--max-tokens",  type=int, default=sys.maxint, metavar="COUNT", help="enforce a max # of tokens included per guess")
    parser.add_argument("--min-tokens",  type=int, default=1,          metavar="COUNT", help="enforce a min # of tokens included per guess")
    parser._add_container_actions(parser_common)
    parser.add_argument("--autosave",    metavar="FILE", help="autosaves (5 min) progress to/ restores it from a file")
    parser.add_argument("--restore",     metavar="FILE", help="restores progress and options from an autosave file (must be the only option on the command line)")
    parser.add_argument("--passwordlist",metavar="FILE", nargs="?", const="-", help="instead of using a tokenlist, read complete passwords (exactly one per line) from this file or from stdin")
    args = parser.parse_args(effective_argv)

    # Do this as early as possible so user doesn't miss any error messages
    if args.pause: enable_pause()

    # If a simple passwordlist is being provided, re-parse the command line with fewer options
    # (--help is handled by directly argparse in this case)
    if args.passwordlist:
        parser = argparse.ArgumentParser(add_help=True)
        parser.add_argument("--passwordlist", required=True, nargs="?", const="-", metavar="FILE", help="instead of using a tokenlist, read complete passwords (exactly one per line) from this file or from stdin")
        parser._add_container_actions(parser_common)
        # Add these in as non-options so that args gets a copy of their values
        parser.set_defaults(autosave=False, restore=False)
        args = parser.parse_args(effective_argv)

    # Manually handle the --help option, now that we know which help (tokenlist, not passwordlist) to print
    elif args.help:
        parser.print_help()
        sys.exit(0)


    if args.performance and (args.tokenlist or args.passwordlist):
        error_exit("--performance cannot be used with --tokenlist or --passwordlist")

    if args.list_gpus:
        for i, dev in enumerate(get_opencl_devices(), 1):
            print("#"+str(i), dev.name.strip())
        exit(0)

    # If we're not --restoring nor using a passwordlist, try to open the tokenlist_file now
    # (if we are restoring, we don't know what to open until after the restore data is loaded)
    if not args.restore and not args.passwordlist and not args.performance:
        tokenlist_file = open_or_use(args.tokenlist, "r", kwds.get("tokenlist"),
            default_filename="btcrecover-tokens-auto.txt", permit_stdin=True)
    else:
        tokenlist_file = None

    # If the first line of the tokenlist file starts with exactly "#--", parse it as additional arguments
    # (note that command line arguments can override arguments in this file)
    # TODO: handle Unicode BOM
    char1_of_tokenlist_file = ""
    if tokenlist_file:
        char1_of_tokenlist_file = tokenlist_file.read(1)  # need to save this in case it's not "#"
        if char1_of_tokenlist_file == "#":                # it's either a comment or additional args
            char1_of_tokenlist_file = ""
            first_line = tokenlist_file.readline()
            if first_line.startswith("--"):               # if it's additional args, not just a comment
                print("Reading additional options from tokenlist file '"+tokenlist_file.name+"'", file=sys.stderr)
                tokenlist_args = first_line.split()       # TODO: support quoting / escaping?
                for arg in tokenlist_args:
                    if arg.startswith("--to"):        # --tokenlist
                        error_exit("the --tokenlist option is not permitted inside a tokenlist file")
                    elif arg.startswith("--pas"):     # --passwordlist
                        error_exit("the --passwordlist option is not permitted inside a tokenlist file")
                    elif arg.startswith("--pe"):     # --performance
                        error_exit("the --performance option is not permitted inside a tokenlist file")
                effective_argv = tokenlist_args + effective_argv  # prepend them so that real argv takes precedence
                args = parser.parse_args(effective_argv)          # reparse the arguments
                # Check this again as early as possible so user doesn't miss any error messages
                if args.pause: enable_pause()


    # There are two ways to restore from an autosave file: either specify --restore (alone)
    # on the command line in which case the saved arguments completely replace everything else,
    # or specify --autosave along with the exact same arguments as are in the autosave file.
    #
    global savestate, restored, autosave_file
    savestate = None
    restored  = False
    # If args.restore was specified, load and completely replace current arguments
    autosave_file = open_or_use(args.restore, "r+b", kwds.get("restore"))
    if autosave_file:
        if len(effective_argv) > 2 or "=" in effective_argv[0] and len(effective_argv) > 1:
            error_exit("the --restore option must be the only option when used")
        load_savestate(autosave_file)
        effective_argv = savestate["argv"]  # argv is effectively being replaced; it's reparsed below
        print("Restoring session:", " ".join(effective_argv))
        print("Last session ended having finished password #", savestate["skip"])
        restore_filename = args.restore     # save this before it's overwritten below
        args = parser.parse_args(effective_argv)
        # Check this again as early as possible so user doesn't miss any error messages
        if args.pause: enable_pause()
        # If the order of passwords generated has changed since the last version, don't permit a restore
        if __ordering_version__ != savestate.get("ordering_version"):
            error_exit("autosave was created with an incompatible version of "+prog)
        assert args.autosave,         "parse_arguments: autosave option enabled in restored autosave file"
        assert not args.passwordlist, "parse_arguments: passwordlist option not specified in restored autosave file"
        #
        # We finally know the tokenlist filename; open it here
        tokenlist_file = open_or_use(args.tokenlist, "r", kwds.get("tokenlist"),
            default_filename="btcrecover-tokens-auto.txt", permit_stdin=True)
        # Display a warning if any options (all ignored) were specified in the tokenlist file
        if tokenlist_file:
            char1_of_tokenlist_file = tokenlist_file.read(1)  # need to save this in case it's not "#"
            if char1_of_tokenlist_file == "#":                # it's either a comment or additional args
                char1_of_tokenlist_file = ""
                first_line = tokenlist_file.readline()
                if first_line.startswith("--"):               # if it's additional args, not just a comment
                    print(prog+": warning: all options loaded from restore file; ignoring options in tokenlist file '"+tokenlist_file.name+"'", file=sys.stderr)
        print("Using autosave file '"+restore_filename+"'")
        args.skip = savestate["skip"]  # override this with the most recent value
        restored = True  # a global flag for future reference
    #
    elif args.autosave:
        # If there's anything in the specified file, assume it's autosave data and try to load it
        autosave_file = open_or_use(args.autosave, "r+b", kwds.get("autosave"), require_data=True)
        if autosave_file:
            # Load and compare to current arguments
            load_savestate(autosave_file)
            restored_argv = savestate["argv"]
            print("Restoring session:", " ".join(restored_argv))
            print("Last session ended having finished password #", savestate["skip"])
            if restored_argv != effective_argv:  # TODO: be more lenient than an exact match?
                error_exit("can't restore previous session: the command line options have changed")
            # If the order of passwords generated has changed since the last version, don't permit a restore
            if __ordering_version__ != savestate.get("ordering_version"):
                error_exit("autosave was created with an incompatible version of "+prog)
            print("Using autosave file '"+args.autosave+"'")
            args.skip = savestate["skip"]  # override this with the most recent value
            restored = True  # a global flag for future reference
        #
        # Else if the specified file is empty or doesn't exist:
        else:
            if args.listpass:
                print(prog+": warning: --autosave is ignored with --listpass", file=sys.stderr)
            elif args.performance:
                print(prog+": warning: --autosave is ignored with --performance", file=sys.stderr)
            else:
                # create an initial savestate that is populated throughout the rest of parse_arguments()
                savestate = dict(argv = effective_argv, ordering_version = __ordering_version__)


    # Do a bunch of argument sanity checking

    # Either we're using a passwordlist file (though it's not yet opened),
    # or we're using a tokenlist file it it should have been found and opened by now,
    # or we're running a performance test (and neither is open; already checked above).
    if not args.passwordlist and not tokenlist_file and not args.performance:
        error_exit("argument --tokenlist or --passwordlist is required (or file btcrecover-tokens-auto.txt must be present)")

    if tokenlist_file and args.max_tokens < args.min_tokens:
        error_exit("--max-tokens is less than --min-tokens")

    # Build an ordered list of enabled simple typo generators. This list MUST be in the same relative
    # order as the items in simple_typos to prevent the breakage of --skip and --restore features
    global enabled_simple_typos
    enabled_simple_typos = \
        [generator for name,generator in simple_typos.items() if args.__dict__.get("typos_"+name)]

    # Have _any_ (simple or otherwise) typo types been specified?
    any_typo_types_specified = enabled_simple_typos or \
        args.typos_capslock or args.typos_swap or args.typos_insert

    if not any_typo_types_specified:
        if args.min_typos > 0:
            error_exit("no passwords are produced when no type of typo is chosen, but --min-typos were required")
        if args.typos:
            print(prog+": warning: --typos has no effect because no type of typo was chosen", file=sys.stderr)

    else:
        if args.typos is None:
            if args.min_typos:
                print(prog+": warning: --typos COUNT not specified; assuming same as --min_typos ("+str(args.min_typos)+")", file=sys.stderr)
                args.typos = args.min_typos
            else:
                print(prog+": warning: --typos COUNT not specified; assuming 1", file=sys.stderr)
                args.typos = 1

        elif args.typos < args.min_typos:
            error_exit("--typos is less than --min_typos")

        elif args.typos <= 0:
            print(prog+": warning: --typos", args.typos, " disables all typos", file=sys.stderr)
            enabled_simple_typos = args.typos_capslock = args.typos_swap = args.typos_insert = None

        if args.typos_closecase and args.typos_case:
            print(prog+": warning: specifying --typos-case disables --typos-closecase", file=sys.stderr)
            args.typos_closecase = None

    if args.max_adjacent_inserts != 1:
        if not args.typos_insert:
            print(prog+": warning: --max-adjacent-inserts has no effect unless --typos-insert is used", file=sys.stderr)
        elif args.max_adjacent_inserts < 1:
            print(prog+": warning: --max-adjacent-inserts", args.max_adjacent_inserts, " disables --typos-insert", file=sys.stderr)
            args.typos_insert = None
        elif args.max_adjacent_inserts > args.typos:
            print(prog+": warning: --max-adjacent-inserts is limited by the number of --typos ("+str(args.typos)+")", file=sys.stderr)


    # Parse the custom wildcard set option
    if args.custom_wild:
        global wildcard_keys
        if args.passwordlist and not (args.typos_insert or args.typos_replace):
            print(prog+": warning: ignoring unused --custom-wild", file=sys.stderr)
        else:
            for c in args.custom_wild:
                if ord(c) > 127:
                    error_exit("--custom_wild has non-ASCII character '"+c+"'")
            custom_set_built   = build_wildcard_set(args.custom_wild)
            wildcard_sets["c"] = custom_set_built  # (duplicates already removed by build_wildcard_set)
            wildcard_sets["C"] = duplicates_removed(custom_set_built.upper())
            # If there are any case-sensitive letters in the set, build the case-insensitive versions
            custom_set_caseswapped = custom_set_built.swapcase()
            if custom_set_caseswapped != custom_set_built:
                wildcard_nocase_sets["c"] = duplicates_removed(custom_set_built + custom_set_caseswapped)
                wildcard_nocase_sets["C"] = wildcard_nocase_sets["c"].swapcase()
            wildcard_keys += "cC"  # keep track of available wildcard types (this is used in regex's)

    # Syntax check and expand --typos-insert/--typos-replace wildcards
    global typos_insert_expanded, typos_replace_expanded
    for arg_name, arg_val in ("--typos-insert", args.typos_insert), ("--typos-replace", args.typos_replace):
        if arg_val:
            error_msg = count_valid_wildcards(arg_val)
            if isinstance(error_msg, basestring):
                error_exit(arg_name, arg_val, ":", error_msg)
    if args.typos_insert:
        typos_insert_expanded  = list(expand_wildcards_generator(args.typos_insert))
    if args.typos_replace:
        typos_replace_expanded = list(expand_wildcards_generator(args.typos_replace))

    # Process any --typos-map file: build a dict (typos_map) mapping replaceable characters to their replacements
    global typos_map
    typos_map = None
    if args.typos_map:
        typos_map = dict()
        typos_map_file = open_or_use(args.typos_map, "r", kwds.get("typos_map"))
        for line_num, line in enumerate(typos_map_file, 1):
            if line.startswith("#"): continue  # ignore comments
            #
            # Remove the trailing newline, then split the line exactly
            # once on the specified delimiter (default: whitespace)
            split_line = line.rstrip("\r\n").split(args.delimiter, 1)
            if len(split_line) == 0: continue  # ignore empty lines
            if len(split_line) == 1:
                error_exit("--typos-map file has an empty replacement list on line", line_num)
            if args.delimiter is None: split_line[1] = split_line[1].rstrip()  # ignore trailing whitespace by default
            for c in "".join(split_line):
                if ord(c) > 127:
                    error_exit("--typos-map file has non-ASCII character '"+c+"' on line", line_num)
            for c in split_line[0]:  # (c is the character to be replaced)
                replacements = duplicates_removed(typos_map.get(c, "") + split_line[1])
                if c in replacements:
                    typos_map[c] = filter(lambda r: r != c, replacements)
                else:
                    typos_map[c] = replacements
        typos_map_file.close()
        #
        # If autosaving, take a hash of the typos_map and either check it
        # during a session restore to make sure we're actually restoring
        # the exact same session, or save it for future such checks
        if savestate:
            sha1 = hashlib.sha1()
            for k in sorted(typos_map.keys()):  # must take the hash in a deterministic order (not in typos_map order)
                sha1.update(k + str(typos_map[k]))
            typos_map_hash = sha1.digest()
            del sha1
            if restored:
                if typos_map_hash != savestate["typos_map_hash"]:
                    error_exit("can't restore previous session: the typos_map file has changed")
            else:
                savestate["typos_map_hash"] = typos_map_hash
    #
    # Else if not args.typos_map but these were specified:
    elif args.passwordlist and args.delimiter:
        # With --passwordlist, --delimiter is only used for a --typos-map
        print(prog+": warning: ignoring unused --delimiter", file=sys.stderr)

    # Compile the regex options
    global regex_only, regex_never
    try:   regex_only  = re.compile(args.regex_only)  if args.regex_only  else None
    except re.error as e: error_exit("invalid --regex-only",  args.regex_only, ":", e)
    try:   regex_never = re.compile(args.regex_never) if args.regex_never else None
    except re.error as e: error_exit("invalid --regex-never", args.regex_only, ":", e)

    if args.skip < 0:
        print(prog+": warning: --skip must be >= 0, assuming 0", file=sys.stderr)
        args.skip == 0

    if args.threads < 1:
        print(prog+": warning: --threads must be >= 1, assuming 1", file=sys.stderr)
        args.threads = 1

    if args.worker:  # worker servers
        global worker_id, workers_total
        match = re.match(r"(\d+)/(\d+)$", args.worker)
        if not match:
            error_exit("--worker ID#/TOTAL# must be have the format uint/uint")
        worker_id     = int(match.group(1))
        workers_total = int(match.group(2))
        if workers_total < 2:
            error_exit("in --worker ID#/TOTAL#, TOTAL# must be >= 2")
        if worker_id < 1:
            error_exit("in --worker ID#/TOTAL#, ID# must be >= 1")
        if worker_id > workers_total:
            error_exit("in --worker ID#/TOTAL#, ID# must be <= TOTAL#")
        worker_id -= 1  # now it's in the range [0, workers_total)

    global have_progress, progressbar
    if args.no_progress:
        have_progress = False
    else:
        try:
            import progressbar
            have_progress = True
        except ImportError:
            have_progress = False


    required_args = 0
    if args.wallet:   required_args += 1
    if args.mkey:     required_args += 1
    if args.privkey:  required_args += 1
    if args.listpass: required_args += 1
    if required_args != 1:
        error_exit("argument --wallet (--mkey, --privkey, or --listpass, exactly one) is required")

    # Load the wallet file
    global wallet
    if args.wallet:
        load_wallet(args.wallet)
    else:
        wallet = None

    # Prompt for a Bitcoin Core encrypted master key or a private key instead of requiring
    # a wallet file (the only reason to treat these two differently is to emphasize that
    # privkeys once decrypted can "leak" Bitcoin, whereas mkeys without the wallet are safe)
    global key_data
    key_data = None
    if args.mkey or args.privkey:
        key_crc_base64 = kwds.get("mkey") if args.mkey else kwds.get("privkey")  # for unittest
        if not key_crc_base64:
            if tokenlist_file == sys.stdin:
                print(prog+": warning: order of data on stdin is: optional extra command-line arguments, key data, rest of tokenlist", file=sys.stderr)
            elif args.passwordlist == "-" and not sys.stdin.isatty():  # if isatty, friendly prompts are provided instead
                print(prog+": warning: order of data on stdin is: key data, password list", file=sys.stderr)
            if args.privkey:
                # We could warn about wallet files too, but hopefully that's already obvious...
                print("WARNING: a complete private key, once decrypted, provides access to that key's Bitcoin", file=sys.stderr)
            #
            # Has the first character of the key data already been read in from stdin?
            need_to_prepend = tokenlist_file == sys.stdin and char1_of_tokenlist_file != ""
            if sys.stdin.isatty() and not need_to_prepend:
                print("Please enter the encrypted key data from the extract script\n> ", end="")
            else:
                print("Reading encrypted key data from stdin")
            key_crc_base64 = sys.stdin.readline().rstrip("\r\n")
            if need_to_prepend:
                key_crc_base64 = char1_of_tokenlist_file + key_crc_base64
                char1_of_tokenlist_file = ""
        #
        # Emulates load_wallet, but using the base64 key data instead of a wallet file
        # (this sets the key_data global, and returns the validated CRC)
        key_crc = load_from_base64_key(key_crc_base64)
        #
        is_mkey = key_data.startswith("bc:")  # Bitcoin Core
        if args.mkey and not is_mkey:
            error_exit("the --mkey data is not a Bitcoin Core encrypted master key (might be a privkey?)")
        if args.privkey and is_mkey:
            error_exit("the --privkey data is a Bitcoin Core encrypted mkey, not a privkey")
        #
        # If autosaving, either check the key_crc during a session restore to make sure we're
        # actually restoring the exact same session, or save it for future such checks
        if savestate:
            if restored:
                if key_crc != savestate["key_crc"]:
                    error_exit("can't restore previous session: the encrypted key entered is not the same")
            else:
                savestate["key_crc"] = key_crc


    # Parse and syntax check all of the GPU related options
    if args.enable_gpu:
        # TODO: fix this fragile check
        if not isinstance(wallet, tuple) or len(wallet) != 3:
            error_exit("GPU searching is only supported for Bitcoin Core wallets and mkeys")
        devices_avail = get_opencl_devices()  # all available OpenCL device objects
        if devices_avail == []:
            error_exit("no supported GPUs found")
        if args.int_rate <= 0:
            error_exit("--int-rate must be > 0")
        #
        # If specific devices were requested by name, build a list of devices from those available
        if args.gpu_names:
            # Create a list of names of available devices, exactly the same way as --list-gpus except all lower case
            avail_names = []  # will be the *names* of available devices
            for i, dev in enumerate(devices_avail, 1):
                avail_names.append("#"+str(i)+" "+dev.name.strip().lower())
            #
            devices = []  # will be the list of devices to actually use, taken from devices_avail
            for device_name in args.gpu_names:  # for each name specified at the command line
                if device_name == "":
                    error_exit("empty name in --gpus")
                device_name = device_name.lower()
                for i, avail_name in enumerate(avail_names):
                    if device_name in avail_name:  # if the name at the command line matches an available one
                        devices.append(devices_avail[i])
                        avail_names[i] = ""  # this device isn't available a second time
                        break
                else:  # if for loop exits normally, and not via the break above
                    error_exit("can't find GPU whose name contains '"+device_name+"' (use --list-gpus to display available GPUs)")
        #
        # Else if specific devices weren't requested, try to build a good default list
        else:
            best_score_sofar = -1
            for dev in devices_avail:
                cur_score = 0
                if   dev.type & pyopencl.device_type.ACCELERATOR: cur_score += 8  # always best
                elif dev.type & pyopencl.device_type.GPU:         cur_score += 4  # better than CPU
                if   "nvidia" in dev.vendor.lower():              cur_score += 2  # is never an IGP: very good
                elif "amd"    in dev.vendor.lower():              cur_score += 1  # sometimes an IGP: good
                if cur_score >= best_score_sofar:
                    if cur_score > best_score_sofar:
                        best_score_sofar = cur_score
                        devices = []
                    devices.append(dev)
            #
            # Multiple best devices are only permitted if they seem to be identical
            device_name = devices[0].name
            for dev in devices[1:]:
                if dev.name != device_name:
                    error_exit("can't automatically determine best GPU(s), please use the --gpus option")
        #
        # --global-ws and --local-ws lists must be the same length as the number of devices to use, unless
        # they are of length one in which case they are repeated until they are the correct length
        for argname, arglist in ("--global-ws", args.global_ws), ("--local-ws", args.local_ws):
            if len(arglist) == len(devices): continue
            if len(arglist) != 1:
                error_exit("number of", argname, "integers must be either one or be the number of GPUs utilized")
            arglist.extend(arglist * (len(devices) - 1))
        #
        # Check the values of --global-ws and --local-ws (already known to be positive ints)
        local_ws_warning = False
        if args.local_ws[0] is not None:  # if one is specified, they're all specified
            for i in xrange(len(args.local_ws)):
                if args.local_ws[i] > devices[i].max_work_group_size:
                    error_exit("--local-ws of", args.local_ws[i], "exceeds max of", devices[i].max_work_group_size, "for GPU '"+devices[i].name.strip()+"'")
                if args.global_ws[i] % args.local_ws[i] != 0:
                    error_exit("each --global-ws ("+str(args.global_ws[i])+") must be evenly divisible by its --local-ws ("+str(args.local_ws[i])+")")
                if args.local_ws[i] % 32 != 0 and not local_ws_warning:
                    print(prog+": warning: each --local-ws should probably be divisible by 32 for good performance", file=sys.stderr)
                    local_ws_warning = True
        for ws in args.global_ws:
            if ws % 32 != 0:
                print(prog+": warning: each --global-ws should probably be divisible by 32 for good performance", file=sys.stderr)
                break
        #
        init_bitcoincore_opencl_kernel(devices, args.global_ws, args.local_ws, args.int_rate)
        if args.threads != parser.get_default("threads"):
            print(prog+": warning: --threads is ignored with --enable-gpu", file=sys.stderr)
        args.threads = 1
    #
    # if not --enable-gpu: sanity checks
    else:
        for argname, argkey in ("--gpu-names", "gpu_names"), ("--global-ws", "global_ws"), ("--local-ws", "local_ws"), ("--int-rate", "int_rate"):
            if args.__dict__[argkey] != parser.get_default(argkey):
                print(prog+": warning:", argname, "is ignored without --enable-gpu", file=sys.stderr)


    global has_any_wildcards
    if args.performance:
        has_any_wildcards = False  # Need to initialize this to something
        if args.listpass:
            error_exit("--performance tests require a wallet or key")

    # ETAs are always disabled with --listpass or --performance
    if args.listpass or args.performance:
        args.no_eta = True

    # If we're using a passwordlist file, open it here. If we're opening stdin, read in at least an
    # initial portion. If we manage to read up until EOF, then we won't need to disable ETA features.
    global passwordlist_file, initial_passwordlist, passwordlist_allcached
    passwordlist_file = open_or_use(args.passwordlist, "r", kwds.get("passwordlist"), permit_stdin=True)
    if passwordlist_file:
        initial_passwordlist   = []
        passwordlist_allcached = False
        has_any_wildcards      = False  # currently not supported for passwordlists
        #
        if passwordlist_file == sys.stdin:
            passwordlist_isatty = sys.stdin.isatty()
            if passwordlist_isatty:  # be user friendly
                print("Please enter your password guesses, one per line (with no extra spaces)")
                print(exit)  # os-specific version of "Use exit() or Ctrl-D (i.e. EOF) to exit"
            else:
                print("Reading passwordlist from stdin")
            #
            for i in xrange(1000000):
                line = passwordlist_file.readline()
                if not line or passwordlist_isatty and line.rstrip("\r\n") == "exit()":
                    passwordlist_allcached = True
                    break
                initial_passwordlist.append(line)
            #
            if not passwordlist_allcached and not args.no_eta:
                # ETA calculations require that the passwordlist file is seekable or all in RAM
                print(prog+": warning: --no-eta has been enabled because --passwordlist is stdin and is large", file=sys.stderr)
                args.no_eta = True

    # Some final sanity checking, now that args.no_eta's value is known
    if args.no_eta:  # always true for --listpass and --performance
        if not args.no_dupchecks:
            if args.performance:
                print(prog+": warning: --performance without --no-dupchecks will eventually cause an out-of-memory error", file=sys.stderr)
            elif not args.listpass:
                print(prog+": warning: --no-eta without --no-dupchecks can cause out-of-memory failures while searching", file=sys.stderr)
        if args.max_eta != parser.get_default("max_eta"):
            print(prog+": warning: --max-eta is ignored with --no-eta, --listpass, or --performance", file=sys.stderr)


    # If we're using a tokenlist file, call parse_tokenlist() to parse it.
    if tokenlist_file:
        if tokenlist_file == sys.stdin:
            if sys.stdin.isatty() and char1_of_tokenlist_file == "":
                print("Please enter your tokenlist")   # be a little user friendly
            else:
                print("Reading tokenlist from stdin")  # unless we've already started reading it...
        parse_tokenlist(tokenlist_file, char1_of_tokenlist_file)

    # If something has been redirected to stdin and we've been reading from it, close
    # stdin now so we don't keep the redirected files alive while running, but only
    # if we're done with it (done reading the passwordlist_file and no --pause option)
    if (    not sys.stdin.isatty() and
            (args.mkey or args.privkey or tokenlist_file == sys.stdin or passwordlist_file == sys.stdin) and
            (passwordlist_file != sys.stdin or passwordlist_allcached) and not pause_registered):
        sys.stdin.close()   # this doesn't really close the fd
        try:   os.close(0)  # but this should, where supported
        except StandardError: pass

    if tokenlist_file: tokenlist_file.close()

    # Open a new autosave file (if --restore was specified, the restore file
    # is still open and has already been assigned to autosave_file instead)
    if savestate and not restored:
        global autosave_nextslot
        autosave_file = open_or_use(args.autosave, "wb", kwds.get("autosave"), new_or_empty=True)
        if not autosave_file:
            error_exit("--autosave file '"+args.autosave+"' already exists, won't overwrite")
        autosave_nextslot = 0
        print("Using autosave file '"+args.autosave+"'")


################################### Tokenfile Parsing ###################################


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

# After creation, AnchoredToken must not be changed: it creates and caches the return
# values for __str__ and __hash__ for speed on the assumption they don't change
class AnchoredToken:
    def __init__(self, token, line_num = "?"):
        if token.startswith("^"):
            # If it is a syntactically correct positional or middle anchor
            match = re.match(r"\^(?:(?P<begin>\d+)?(?P<middle>,)(?P<end>\d+)?|(?P<pos>\d+))(?:\^|\$)", token)
            if match:
                # If it's a middle (ranged) anchor
                if match.group("middle"):
                    begin = match.group("begin")
                    end   = match.group("end")
                    cached_str = "^"  # begin building the cached __str__
                    if begin is None:
                        begin = 2
                    else:
                        begin = int(begin)
                        if begin > 2:
                            cached_str += str(begin)
                    cached_str += ","
                    if end is None:
                        end = sys.maxint
                    else:
                        end = int(end)
                        cached_str += str(end)
                    cached_str += "^"
                    if begin > end:
                        error_exit("anchor range of token on line", line_num, "is invalid (begin > end)")
                    if begin < 2:
                        error_exit("anchor range of token on line", line_num, "must begin with 2 or greater")
                    self.begin = begin - 1
                    self.end   = end   - 1 if end != sys.maxint else end
                #
                # Else it's a positional anchor
                else:
                    pos = int(match.group("pos"))
                    cached_str = "^"  # begin building the cached __str__
                    if pos < 1:
                        error_exit("anchor position of token on line", line_num, "must be 1 or greater")
                    if pos > 1:
                        cached_str += str(pos) + "^"
                    self.begin = pos - 1
                    self.end   = None
                #
                self.text = token[match.end():]  # same for both middle and positional anchors
            #
            # Else it's a begin anchor
            else:
                if len(token) > 1 and token[1] in "0123456789,":
                    print(prog+": warning: token on line", line_num, "looks like it might be a positional anchor, " +
                          "but it can't be parsed correctly, so it's assumed to be a simple beginning anchor instead", file=sys.stderr)
                cached_str = "^"  # begin building the cached __str__
                self.begin = 0
                self.end   = None
                self.text  = token[1:]
            #
            if self.text.endswith("$"):
                error_exit("token on line", line_num, "is anchored with both ^ at the beginning and $ at the end")
            #
            self.cached_str = cached_str + self.text  # finish building the cached __str__
        #
        # Parse end anchor if present
        elif token.endswith("$"):
            self.begin = "$"
            self.end   = None
            self.text  = token[:-1]
            self.cached_str = self.text + "$"
        #
        else: raise ValueError("token passed to AnchoredToken constructor is not an anchored token")
        #
        self.cached_hash = hash(self.cached_str)
        if self.text == "":
            print(prog+": warning: token on line", line_num, "contains only an anchor (and zero password characters)", file=sys.stderr)

    def is_positional(self): return self.end is     None
    def is_middle(self):     return self.end is not None
    # For sets
    def __hash__(self):      return self.cached_hash
    def __eq__(self, other): return self.cached_str == str(other)
    def __ne__(self, other): return self.cached_str != str(other)
    # For sort (so that str() can be used as the key function)
    def __str__(self):       return self.cached_str
    # For hashlib
    def __repr__(self):      return self.__class__.__name__ + "(" + repr(self.cached_str) + ")"

def parse_tokenlist(tokenlist_file, prepend_to_line1 = ""):
    global token_lists
    global has_any_duplicate_tokens, has_any_wildcards, has_any_anchors, has_any_mid_anchors

    if args.no_dupchecks < 3:
        has_any_duplicate_tokens = False
        token_set_for_dupchecks  = set()
    has_any_wildcards   = False
    has_any_anchors     = False
    has_any_mid_anchors = False
    token_lists         = []

    # May need to restore the first character we read in the argument parsing
    # section while looking for command line arguments in the tokenlist file
    first_line = prepend_to_line1 + tokenlist_file.readline()
    for line_num, line in enumerate(itertools.chain((first_line,), tokenlist_file), 1):

        # Ignore comments
        if line.startswith("#"): continue

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
                    error_exit("token on line", line_num, "has non-ASCII character '"+c+"'")

            # Syntax check any wildcards
            count_or_error_msg = count_valid_wildcards(token, True)  # True == permit contracting wildcards
            if isinstance(count_or_error_msg, basestring):
                error_exit("on line", str(line_num)+":", count_or_error_msg)
            elif count_or_error_msg:
                has_any_wildcards = True  # (a global)

            # Parse anchor if present and convert to an AnchoredToken object
            if token.startswith("^") or token.endswith("$"):
                token = AnchoredToken(token, line_num)  # (the line_num is just for error messages)
                new_list[i] = token
                has_any_anchors = True
                if token.is_middle(): has_any_mid_anchors = True

            # Keep track of the existence of any duplicate tokens for future optimization
            if args.no_dupchecks < 3 and not has_any_duplicate_tokens:
                if token in token_set_for_dupchecks:
                    has_any_duplicate_tokens = True
                    del token_set_for_dupchecks
                else:
                    token_set_for_dupchecks.add(token)

        # Add the completed list for this one line to the token_lists list of lists
        token_lists.append(new_list)

    # Tokens at the end of the outer token_lists get tried first below;
    # reverse the list here so that tokens at the beginning of the file
    # appear at the end of the list and consequently get tried first
    token_lists.reverse()

    # If autosaving, take a hash of the token_lists and either check it
    # during a session restore to make sure we're actually restoring
    # the exact same session, or save it for future such checks
    if savestate:
        token_lists_hash = hashlib.sha1(str(token_lists)).digest()
        if restored:
            if token_lists_hash != savestate["token_lists_hash"]:
                error_exit("can't restore previous session: the tokenlist file has changed")
        else:
            savestate["token_lists_hash"] = token_lists_hash


################################### Password Generation ###################################


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
            if x in self.duplicates:      # If it's the third+ time we've seen it
                return True
            elif x in self.seen_once:     # If it's now the second time we've seen it:
                self.seen_once.remove(x)      # it's been seen *more* than once
                self.duplicates[x] = 1        # mark it as having duplicates
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
            del self.seen_once  # No longer need this for second+ runs
        self.run_number += 1


# The main generator function produces all possible requested password permutations with no
# duplicates from the token_lists global as constructed above plus wildcard expansion or from
# the passwordlist file, plus up to a certain number of requested typos. Results are produced
# in lists of length chunksize, which can be changed by calling iterator.send((new_chunksize,
# only_yield_count)) (which does not itself return any passwords). If only_yield_count, then
# instead of producing lists, for each iteration single integers <= chunksize are produced
# (only the last integer might be < than chunksize), useful for counting or skipping passwords.
def init_password_generator():
    global password_dups, token_combination_dups
    password_dups = token_combination_dups = None
#
def password_generator(chunksize = 1, only_yield_count = False):
    assert chunksize > 0, "password_generator: chunksize > 0"
    # Used to communicate between typo generators the number of typos that have been
    # created so far during each password generated so that later generators know how
    # many additional typos, at most, they are permitted to add
    global typos_sofar
    typos_sofar = 0

    passwords_gathered = []
    passwords_count    = 0  # == len(passwords_gathered)
    worker_count = 0  # Only used if --worker is specified
    new_args = None

    # Initialize this global if not already initialized but only
    # if they should be used; see its usage below for more details
    global password_dups
    if password_dups is None and args.no_dupchecks < 1:
        password_dups = DuplicateChecker()

    # Copy a few globals into local for a small speed boost
    l_generator_product = generator_product
    l_args_min_typos    = args.min_typos
    l_regex_only        = regex_only
    l_regex_never       = regex_never
    l_password_dups     = password_dups
    l_args_worker       = args.worker
    if l_args_worker:
        l_workers_total = workers_total
        l_worker_id     = worker_id

    # Build up the modification_generators list; see the inner loop below for more details
    modification_generators = []
    if has_any_wildcards:    modification_generators.append( expand_wildcards_generator )
    if args.typos_capslock:  modification_generators.append( capslock_typos_generator   )
    if args.typos_swap:      modification_generators.append( swap_typos_generator       )
    if enabled_simple_typos: modification_generators.append( simple_typos_generator     )
    if args.typos_insert:    modification_generators.append( insert_typos_generator     )
    modification_generators_len = len(modification_generators)

    # Select the base password generator which produces base passwords based
    # on either a tokenlist file (as parsed above) or a passwordlist file.
    if args.passwordlist:
        base_password_iterator = passwordlist_base_password_generator()
    elif args.performance:
        base_password_iterator = performance_base_password_generator()
    else:
        base_password_iterator = tokenlist_base_password_generator()
    for password_base in base_password_iterator:

        # The for loop below takes the password_base and applies zero or more modifications
        # to it to produce a number of different possible variations of password_base (e.g.
        # different wildcard expansions, typos, etc.)

        # modification_generators is a list of function generators each of which takes a
        # string and produces one or more password variations based on that string. It is
        # built just above, and is built differently depending on the token_lists (are any
        # wildcards present?) and the program options (were any typos requested?).
        #
        # If any modifications have been requested, create an iterator that will
        # loop through all combinations of the requested modifications
        if modification_generators_len:
            if modification_generators_len == 1:
                modification_iterator = modification_generators[0](password_base)
            else:
                modification_iterator = l_generator_product(password_base, *modification_generators)
        #
        # Otherwise just produce the unmodified password itself
        else:
            modification_iterator = (password_base,)

        for password in modification_iterator:

            if typos_sofar < l_args_min_typos: continue

            # Check the password against the --regex-only and --regex-never options
            if l_regex_only  and not l_regex_only .search(password): continue
            if l_regex_never and     l_regex_never.search(password): continue

            # This duplicate check can be disabled via --no-dupchecks
            # because it can take up a lot of memory, sometimes needlessly
            if l_password_dups and l_password_dups.is_duplicate(password): continue

            # Workers in a server pool ignore passwords not assigned to them
            if l_args_worker:
                if worker_count % l_workers_total != l_worker_id:
                    worker_count += 1
                    continue
                worker_count += 1

            # Produce the password(s) or the count once enough of them have been accumulated
            passwords_count += 1
            if only_yield_count:
                if passwords_count >= chunksize:
                    new_args = yield passwords_count
                    passwords_count = 0
            else:
                passwords_gathered.append(password)
                if passwords_count >= chunksize:
                    new_args = yield passwords_gathered
                    passwords_gathered = []
                    passwords_count    = 0

            # Process new arguments received from .send(), yielding nothing back to send()
            if new_args:
                chunksize, only_yield_count = new_args
                assert chunksize > 0, "password_generator.send: chunksize > 0"
                new_args = None
                yield

        assert typos_sofar == 0, "password_generator: typos_sofar == 0 after all typo generators have finished"

    if l_password_dups:          l_password_dups.run_finished()

    # Produce the remaining passwords that have been accumulated
    if passwords_count > 0:
        yield passwords_count if only_yield_count else passwords_gathered


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
    if other_generators == ():
        for final_value in generator(initial_value):
            yield final_value
    else:
        for intermediate_value in generator(initial_value):
            for final_value in generator_product(intermediate_value, *other_generators):
                yield final_value


# The tokenlist generator function produces all possible password permutations from the
# token_lists global as constructed by parse_tokenlist(). These passwords are then used
# by password_generator() as base passwords that can undergo further modifications.
def tokenlist_base_password_generator():
    # Initialize this global if not already initialized but only
    # if they should be used; see its usage below for more details
    global token_combination_dups
    if token_combination_dups is None and args.no_dupchecks < 2 and has_any_duplicate_tokens:
        token_combination_dups = DuplicateChecker()

    # Copy a few globals into local for a small speed boost
    l_len                    = len
    l_args_min_tokens        = args.min_tokens
    l_args_max_tokens        = args.max_tokens
    l_has_any_anchors        = has_any_anchors
    l_type                   = type
    l_token_combination_dups = token_combination_dups
    l_tuple                  = tuple
    l_sorted                 = sorted
    l_list                   = list

    # Choose between the custom duplicate-checking and the standard itertools permutation
    # functions for the outer loop unless the custom one has been specifically disabled
    # with three (or more) --no-dupcheck options.
    if args.no_dupchecks < 3 and has_any_duplicate_tokens:
        permutations_function = permutations_nodups
    else:
        permutations_function = itertools.permutations

    # The outer loop iterates through all possible (unordered) combinations of tokens
    # taking into account the at-most-one-token-per-line rule. Note that lines which
    # were not required (no "+") have a None in their corresponding list; if this
    # None item is chosen for a tokens_combination, then this tokens_combination
    # corresponds to one without any token from that line, and we we simply remove
    # the None from this tokens_combination (product_limitedlen does this on its own,
    # itertools.product does not so it's done below).
    #
    # First choose which product generator to use: the custom product_limitedlen
    # might be faster (possibly a lot) if a large --min-tokens or any --max-tokens
    # is specified at the command line, otherwise use the standard itertools version.
    using_product_limitedlen = l_args_min_tokens > 5 or l_args_max_tokens < sys.maxint
    if using_product_limitedlen:
        # Unfortunately, product_limitedlen is recursive; the recursion limit
        # must be at least as high as the number of lines in the tokenlist file
        if l_len(token_lists) + 20 > sys.getrecursionlimit():
            sys.setrecursionlimit(l_len(token_lists) + 20)
        product_generator = product_limitedlen(*token_lists, minlen=l_args_min_tokens, maxlen=l_args_max_tokens)
    else:
        product_generator = itertools.product(*token_lists)
    for tokens_combination in product_generator:

        # Remove any None's, then check against token length constraints:
        # (product_limitedlen, if used, has already done all this)
        if not using_product_limitedlen:
            tokens_combination = filter(lambda t: t is not None, tokens_combination)
            if not l_args_min_tokens <= l_len(tokens_combination) <= l_args_max_tokens: continue

        # There are two types of anchors, positional and middle/range. Positional anchors
        # only have a single possible position; middle anchors have a range, but are never
        # tried at the beginning or end. Below, build a tokens_combination_nopos list from
        # tokens_combination with all positional anchors removed. They will be inserted
        # back into the correct position later. Also search for invalid anchors of any
        # type: a positional anchor placed past the end of the current combination (based
        # on its length) or a middle anchor whose begin position is past *or at* the end.
        positional_anchors = None  # (will contain strings, not AnchoredToken's)
        if l_has_any_anchors:
            tokens_combination_len   = l_len(tokens_combination)
            tokens_combination_nopos = []
            invalid_anchors          = False
            for token in tokens_combination:
                if l_type(token) != str:        # If it's an AnchoredToken
                    pos = token.begin
                    if token.is_positional():       # a single-position anchor
                        if pos == "$":
                            pos = tokens_combination_len - 1
                        elif pos >= tokens_combination_len:
                            invalid_anchors = True  # anchored past the end
                            break
                        if not positional_anchors:  # initialize it to a list of None's
                            positional_anchors = [None for i in xrange(tokens_combination_len)]
                        if positional_anchors[pos] is not None:
                            invalid_anchors = True  # two tokens anchored to the same place
                            break
                        positional_anchors[pos] = token.text    # save valid single-position anchor
                    else:                           # else it's a middle anchor
                        if pos+1 >= tokens_combination_len:
                            invalid_anchors = True  # anchored past *or at* the end
                            break
                        tokens_combination_nopos.append(token)  # add this token (a middle anchor)
                else:                                           # else it's not an anchored token,
                    tokens_combination_nopos.append(token)      # add this token (just a string)
            if invalid_anchors: continue
            #
            if tokens_combination_nopos == []:      # if all tokens have positional anchors,
                tokens_combination_nopos = ( "", )  # make this non-empty so a password can be created
        else:
            tokens_combination_nopos = tokens_combination

        # Do some duplicate checking early on to avoid running through potentially a
        # lot of passwords all of which end up being duplicates. We check the current
        # combination (of all tokens), sorted because different orderings of token
        # combinations are equivalent at this point. This check can be disabled with two
        # (or more) --no-dupcheck options (one disables only the other duplicate check).
        # TODO:
        #   Be smarter in deciding when to enable this? (currently on if has_any_duplicate_tokens)
        #   Instead of dup checking, write a smarter product (seems hard)?
        if l_token_combination_dups and \
           l_token_combination_dups.is_duplicate(l_tuple(l_sorted(tokens_combination, None, str))): continue

        # The inner loop iterates through all valid permutations (orderings) of one
        # combination of tokens and combines the tokens to create a password string.
        # Because positionally anchored tokens can only appear in one position, they
        # are not passed to the permutations_function.
        for ordered_token_guess in permutations_function(tokens_combination_nopos):

            # Insert the positional anchors we removed above back into the guess
            if positional_anchors:
                ordered_token_guess = l_list(ordered_token_guess)
                for i, token in enumerate(positional_anchors):
                    if token is not None:
                        ordered_token_guess.insert(i, token)  # (token here is just a string)

            # The second type of anchor has a range of possible positions for the anchored
            # token. If any anchored token is outside of its permissible range, we continue
            # on to the next guess. Otherwise, we remove the anchor information leaving
            # only the string behind.
            if has_any_mid_anchors:
                if l_type(ordered_token_guess[0]) != str or l_type(ordered_token_guess[-1]) != str:
                    continue  # middle anchors are never permitted at the beginning or end
                invalid_anchors = False
                for i, token in enumerate(ordered_token_guess[1:-1], 1):
                    if l_type(token) != str:  # If it's an AnchoredToken
                        assert token.is_middle(), "only middle/range anchors left"
                        if token.begin <= i <= token.end:
                            if l_type(ordered_token_guess) != l_list:
                                ordered_token_guess = l_list(ordered_token_guess)
                            ordered_token_guess[i] = token.text  # now it's just a string
                        else:
                            invalid_anchors = True
                            break
                if invalid_anchors: continue

            yield "".join(ordered_token_guess)

    if l_token_combination_dups: l_token_combination_dups.run_finished()


# Like itertools.product, but only produces output tuples whose length is between
# minlen and maxlen. Normally, product always produces output of length len(sequences),
# but this version removes elements from each produced product which are == None
# (making their length variable) and only then applies the requested length constraint.
# (Does not accept the itertools "repeat" argument.)
# TODO: implement without recursion?
def product_limitedlen(*sequences, **kwds):
    minlen = kwds.get("minlen", 0)
    maxlen = kwds.get("maxlen", sys.maxint)

    sequences_len = len(sequences)
    if sequences_len == 0:
        if minlen <= 0 <= maxlen: yield ()
        return

    # Iterate through elements in the first sequence
    for choice in sequences[0]:

        # Adjust minlen and maxlen if this element affects the length (isn't None)
        if choice is None:
            new_minlen = minlen
            new_maxlen = maxlen
        else:
            new_minlen = minlen - 1
            new_maxlen = maxlen - 1

        # If (and only if) the total length after recursing could
        # possibly fall inside the requested range, continue
        if sequences_len > new_minlen and new_maxlen >= 0:

            # Special case (just so we can be non-recursive) when new_maxlen == 0:
            # this is only possible if each of the remaining sequences has a None
            # option, otherwise the result will be too long, so search for this
            # requirement and produce a single output if it's found
            if new_maxlen == 0:
                for seq in sequences:
                    if None not in seq: break
                else:  # if it didn't break, there was a None in every sequence
                    yield () if choice is None else (choice,)
                continue

            # Special case (to avoid one recursion) when this sequence is the last
            if sequences_len == 1:
                yield () if choice is None else (choice,)
                continue

            for rest in product_limitedlen(*sequences[1:], minlen=new_minlen, maxlen=new_maxlen):
                yield rest if choice is None else (choice,) + rest


# Like itertools.permutations, but avoids duplicates even if input contains some.
# Input must be a sequence of hashable elements. (Does not accept the itertools "r" argument.)
# TODO: implement without recursion?
def permutations_nodups(sequence):
    # Copy a global into local for a small speed boost
    l_len = len

    sequence_len = l_len(sequence)
    if sequence_len == 2:
        # Only two permutations to try:
        yield sequence if type(sequence) == tuple else tuple(sequence)
        if sequence[0] != sequence[1]:
            yield (sequence[1], sequence[0])

    elif sequence_len <= 1:
        # Only one permutation to try:
        yield sequence if type(sequence) == tuple else tuple(sequence)
    else:

        # If the sequence contains no duplicates, use the faster itertools version
        seen = set(sequence)
        if l_len(seen) == sequence_len:
            for permutation in itertools.permutations(sequence):
                yield permutation
            return

        # If they're all the same, there's only one permutation:
        if l_len(seen) == 1:
            yield sequence if type(sequence) == tuple else tuple(sequence)
            return

        # Else there's at least one duplicate and two+ permutations; use our version
        seen = set()
        for i, choice in enumerate(sequence):
            if i > 0 and choice in seen: continue          # don't need to check the first one
            if i+1 < sequence_len:       seen.add(choice)  # don't need to add the last one
            for rest in permutations_nodups(sequence[:i] + sequence[i+1:]):
                yield (choice,) + rest
        return


# Produces whole passwords from a file, exactly one per line, or from the file's cache
# (which is created by parse_arguments if the file is stdin). These passwords are then
# used by password_generator() as base passwords that can undergo further modifications.
def passwordlist_base_password_generator():
    global initial_passwordlist

    for password_base in initial_passwordlist:
        yield password_base.rstrip("\r\n")

    if not passwordlist_allcached:
        assert not passwordlist_file.closed
        for password_base in passwordlist_file:
            yield password_base.rstrip("\r\n")

    # Prepare for a potential future run
    if passwordlist_file != sys.stdin:
        passwordlist_file.seek(0)

    # Data from stdin can't be reused if it hasn't been fully cached
    elif not passwordlist_allcached:
        initial_passwordlist = ()
        passwordlist_file.close()


# Produces an infinite number of base passwords for performance measurements. These passwords
# are then used by password_generator() as base passwords that can undergo further modifications.
def performance_base_password_generator():
    for i in itertools.count(0):
        yield "Measure Performance " + str(i)


# This generator function expands (or contracts) all wildcards in the string passed
# to it, or if there are no wildcards it simply produces the string unchanged
# TODO: implement without recursion?
def expand_wildcards_generator(password_with_wildcards):

    # Quick check to see if any wildcards are present
    if password_with_wildcards.find("%") == -1:
        # If none, just produce the string and end
        yield password_with_wildcards
        return

    # Copy a few globals into local for a small speed boost
    l_xrange = xrange
    l_len    = len
    l_min    = min
    l_max    = max

    # Find the first wildcard parameter in the format %[[min,]max][caseflag]type
    # where caseflag=="i" if present and type is one of: wildcard_keys, <, >, or -
    # (e.g. "%d", "%-", "%2n", "%1,3ia", etc.) or type is of the form "[custom-wildcard-set]"
    match = re.search(r"%(?:(?:(?P<min>\d+),)?(?P<max>\d+))?(?P<nocase>i)?(?:(?P<type>["+wildcard_keys+"<>-])|\[(?P<custom>.+?)\])", password_with_wildcards)
    assert match, "expand_wildcards_generator: parsed valid wildcard spec"

    password_prefix = password_with_wildcards[0:match.start()]               # no wildcards present here;
    password_postfix_with_wildcards = password_with_wildcards[match.end():]  # might be other wildcards in here

    # For positive (expanding) wildcards, build the set of possible characters based on the wildcard type and caseflag
    m_custom, m_nocase = match.group("custom", "nocase")
    if m_custom:  # e.g. %[abcdef0-9]
        is_expanding = True
        wildcard_set = custom_wildcard_cache.get((m_custom, m_nocase))
        if wildcard_set is None:
            wildcard_set = build_wildcard_set(m_custom)
            if m_nocase:
                # Build a case-insensitive version
                wildcard_set_caseswapped = wildcard_set.swapcase()
                if wildcard_set_caseswapped != wildcard_set:
                    wildcard_set = duplicates_removed(wildcard_set + wildcard_set_caseswapped)
            custom_wildcard_cache[(m_custom, m_nocase)] = wildcard_set
    else:
        m_type = match.group("type")
        is_expanding = m_type not in "<>-"
        if is_expanding:
            if m_nocase and m_type in wildcard_nocase_sets:
                wildcard_set = wildcard_nocase_sets[m_type]
            else:
                wildcard_set = wildcard_sets[m_type]
    assert not is_expanding or wildcard_set, "expand_wildcards_generator: found expanding wildcard set"

    # Extract or default the wildcard min and max length
    wildcard_maxlen = match.group("max")
    wildcard_maxlen = int(wildcard_maxlen) if wildcard_maxlen else 1
    wildcard_minlen = match.group("min")
    wildcard_minlen = int(wildcard_minlen) if wildcard_minlen else wildcard_maxlen

    # If it's an expanding wildcard
    if is_expanding:
        # Iterate through specified wildcard lengths
        for wildcard_len in l_xrange(wildcard_minlen, wildcard_maxlen+1):

            # Expand the wildcard into a length of characters according to the wildcard type/caseflag
            for wildcard_expanded_list in itertools.product(wildcard_set, repeat=wildcard_len):
                password_prefix_expanded = password_prefix + "".join(wildcard_expanded_list)

                # If the wildcard was at the end of the string, we're done
                if password_postfix_with_wildcards == "":
                    yield password_prefix_expanded
                    continue

                # Recurse to expand any additional wildcards possibly in password_postfix_with_wildcards
                for password_postfix_expanded in expand_wildcards_generator(password_postfix_with_wildcards):
                    yield password_prefix_expanded + password_postfix_expanded

    # Otherwise it's a contracting wildcard
    else:
        # Determine the max # of characters that can be removed from either the left
        # or the right of the wildcard, not yet taking wildcard_maxlen into account
        max_from_left  = l_len(password_prefix) if m_type in "<-" else 0
        if m_type in ">-":
            max_from_right = password_postfix_with_wildcards.find("%")
            if max_from_right == -1: max_from_right = l_len(password_postfix_with_wildcards)
        else:
            max_from_right = 0

        # Iterate over the total number of characters to remove
        for remove_total in l_xrange(wildcard_minlen, l_min(wildcard_maxlen, max_from_left+max_from_right) + 1):

            # Iterate over the number of characters to remove from the right of the wildcard
            # (this loop runs just once for %#,#< or %#,#> ; or for %#,#- at the beginning or end)
            for remove_right in l_xrange(l_max(0, remove_total-max_from_left), l_min(remove_total, max_from_right) + 1):
                remove_left = remove_total-remove_right

                # If the wildcard was at the end or if there's nothing remaining on the right, we're done
                if l_len(password_postfix_with_wildcards) - remove_right == 0:
                    yield password_prefix[:-remove_left] if remove_left else password_prefix
                    continue

                # Recurse to expand any additional wildcards possibly in password_postfix_with_wildcards
                for password_postfix_expanded in expand_wildcards_generator(password_postfix_with_wildcards[remove_right:]):
                    yield (password_prefix[:-remove_left] if remove_left else password_prefix) + password_postfix_expanded


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
    # Copy a few globals into local for a small speed boost
    l_xrange                 = xrange
    l_itertools_combinations = itertools.combinations
    l_args_nodupchecks       = args.no_dupchecks

    # Start with the unmodified password itself, and end if there's nothing left to do
    yield password_base
    max_swaps         = args.typos - typos_sofar
    password_base_len = len(password_base)
    if max_swaps <= 0 or password_base_len < 2: return

    # First swap one pair of characters, then all combinations of 2 pairs, then of 3,
    # up to the max requested or up to the max number swappable (whichever's less). The
    # max number swappable is len // 2 because we never swap any single character twice.
    max_swaps = min(max_swaps, password_base_len // 2)
    for swap_count in l_xrange(1, max_swaps + 1):
        typos_sofar += swap_count

        # Generate all possible combinations of swapping exactly swap_count characters;
        # swap_indexes is a list of indexes of characters that will be swapped in a
        # single guess (swapped with the character at the next position in the string)
        for swap_indexes in l_itertools_combinations(l_xrange(password_base_len-1), swap_count):

            # Look for adjacent indexes in swap_indexes (which would cause a single
            # character to be swapped more than once in a single guess), and only
            # continue if no such adjacent indexes are found
            for i in l_xrange(1, swap_count):
                if swap_indexes[i] - swap_indexes[i-1] == 1:
                    break
            else:  # if we left the loop normally (didn't break)

                # Perform and the actual swaps
                password = password_base
                for i in swap_indexes:
                    if password[i] == password[i+1] and l_args_nodupchecks < 4:  # "swapping" these would result in generating a duplicate guess
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
def simple_typos_generator(password_base):
    global typos_sofar
    # Copy a few globals into local for a small speed boost
    l_xrange            = xrange
    l_itertools_product = itertools.product
    assert len(enabled_simple_typos) > 0, "simple_typos_generator: at least one simple typo enabled"

    # Start with the unmodified password itself
    yield password_base

    # First change all single characters, then all combinations of 2 characters, then of 3, etc.
    password_base_len = len(password_base)
    max_typos         = min(args.typos - typos_sofar, password_base_len)
    for typos_count in l_xrange(1, max_typos + 1):
        typos_sofar += typos_count

        # Select the indexes of exactly typos_count characters from the password_base
        # that will be the target of the typos (out of all possible combinations thereof)
        for typo_indexes in itertools.combinations(l_xrange(password_base_len), typos_count):
            # typo_indexes_ has an added sentinel at the end; it's the index of
            # one-past-the-end of password_base. This is used in the inner loop.
            typo_indexes_ = typo_indexes + (password_base_len,)

            # Iterate through all possible permutations of the specified
            # enabled_simple_typos being applied to the selected typo targets
            for typo_generators_per_target in l_itertools_product(enabled_simple_typos, repeat=typos_count):

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
                # replacements (for a single target), this loop iterates across all possible
                # combinations of those replacements. If any generator produces zero outputs
                # (therefore that the target has no typo), this loop iterates zero times.
                for one_replacement_set in l_itertools_product(*typo_replacements):

                    # Construct a new password, left-to-right, from password_base and the
                    # one_replacement_set. (Note the use of typo_indexes_, not typo_indexes.)
                    password = password_base[0:typo_indexes_[0]]
                    for i, replacement in enumerate(one_replacement_set):
                        password += replacement + password_base[typo_indexes_[i]+1:typo_indexes_[i+1]]
                    yield password

        typos_sofar -= typos_count


# insert_typos_generator() is a generator function which inserts one or more strings
# from the typos_insert_expanded list between every pair of characters in password_base,
# as well as at its beginning and its end.
def insert_typos_generator(password_base):
    global typos_sofar
    # Copy a few globals into local for a small speed boost
    l_max_adjacent_inserts = args.max_adjacent_inserts
    l_xrange               = xrange
    l_itertools_product    = itertools.product

    # Start with the unmodified password itself
    yield password_base

    password_base_len = len(password_base)
    assert l_max_adjacent_inserts > 0
    if l_max_adjacent_inserts > 1:
        # Can select for insertion the same index more than once in a single guess
        combinations_function = itertools.combinations_with_replacement
        max_inserts = args.typos - typos_sofar
    else:
        # Will select for insertion an index at most once in a single guess
        combinations_function = itertools.combinations
        max_inserts = min(args.typos - typos_sofar, password_base_len + 1)

    # First insert a single string, then all combinations of 2 strings, then of 3, etc.
    for inserts_count in l_xrange(1, max_inserts + 1):
        typos_sofar += inserts_count

        # Select the indexes (some possibly the same) of exactly inserts_count characters
        # from the password_base before which new string(s) will be inserted
        for insert_indexes in combinations_function(l_xrange(password_base_len + 1), inserts_count):

            # If multiple inserts are permitted at a single location, make sure they're
            # limited to args.max_adjacent_inserts. (If multiple inserts are not permitted,
            # they are never produced by the combinations_function selected earlier.)
            if l_max_adjacent_inserts > 1:
                too_many_adjacent = False
                last_index = -1
                for index in insert_indexes:
                    if index != last_index:
                        adjacent_count = 1
                        last_index = index
                    else:
                        adjacent_count += 1
                        too_many_adjacent = adjacent_count > l_max_adjacent_inserts
                        if too_many_adjacent: break
                if too_many_adjacent: continue

            # insert_indexes_ has an added sentinel at the end; it's the index of
            # one-past-the-end of password_base. This is used in the inner loop.
            insert_indexes_ = insert_indexes + (password_base_len,)

            # For each of the selected insert indexes, select a replacement from
            # typos_insert_expanded (which is created in parse_arguments() )
            for one_insertion_set in l_itertools_product(typos_insert_expanded, repeat = inserts_count):

                # Construct a new password, left-to-right, from password_base and the
                # one_insertion_set. (Note the use of insert_indexes_, not insert_indexes.)
                password = password_base[0:insert_indexes_[0]]
                for i, insertion in enumerate(one_insertion_set):
                    password += insertion + password_base[insert_indexes_[i]:insert_indexes_[i+1]]
                yield password

        typos_sofar -= inserts_count


################################### Main ###################################


# Init function for the password verifying worker processes:
#   (re-)loads the wallet or key (should only be necessary on Windows),
#   tries to set the process priority to minimum, and
#   begins ignoring SIGINTs for a more graceful exit on Ctrl-C
wallet = None  # initialized once at global scope for Windows
def init_worker(wallet_filename, key_data):
    if not wallet:
        if wallet_filename: load_wallet(wallet_filename)
        elif key_data:      load_from_raw_key(key_data)
        else: assert False, "init_worker: wallet filename or key data specified"
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
    except StandardError: pass

# If an out-of-memory error occurs which can be handled, free up some memory, display
# an informative error message, and then return, otherwise re-raise the exception
def handle_oom():
    global password_dups, token_combination_dups  # these are the memory-hogging culprits
    if password_dups and password_dups.run_number == 0:
        del password_dups, token_combination_dups
        gc.collect(2)
        print(prog+": error: out of memory", file=sys.stderr)
        print(prog+": notice: the --no-dupchecks option will reduce memory usage at the possible expense of speed", file=sys.stderr)
    elif token_combination_dups and token_combination_dups.run_number == 0:
        del token_combination_dups
        gc.collect(2)
        print(prog+": error: out of memory", file=sys.stderr)
        print(prog+": notice: the --no-dupchecks option can be specified twice to further reduce memory usage", file=sys.stderr)
    else: raise


# Saves progress by overwriting the older (of two) slots in the autosave file
# (autosave_nextslot is initialized in load_savestate() or parse_arguments() )
def do_autosave(skip, inside_interrupt_handler = False):
    global autosave_nextslot
    assert autosave_file and not autosave_file.closed,          "do_autosave: autosave_file is open"
    assert isinstance(savestate, dict) and "argv" in savestate, "do_autosave: savestate is initialized"
    if not inside_interrupt_handler:
        sigint_handler  = signal.signal(signal.SIGINT,  signal.SIG_IGN)    # ignore Ctrl-C,
        sigterm_handler = signal.signal(signal.SIGTERM, signal.SIG_IGN)    # SIGTERM, and
        if sys.platform != "win32":  # (windows has no SIGHUP)
            sighup_handler = signal.signal(signal.SIGHUP, signal.SIG_IGN)  # SIGHUP while saving
    # Erase the target save slot so that a partially written save will be recognized as such
    if autosave_nextslot == 0:
        start_pos = 0
        autosave_file.seek(start_pos)
        autosave_file.write(SAVESLOT_SIZE * b"\0")
        autosave_file.flush()
        try:   os.fsync(autosave_file.fileno())
        except StandardError: pass
        autosave_file.seek(start_pos)
    else:
        assert autosave_nextslot == 1
        start_pos = SAVESLOT_SIZE
        autosave_file.seek(start_pos)
        autosave_file.truncate()
        try:   os.fsync(autosave_file.fileno())
        except StandardError: pass
    savestate["skip"] = skip  # overwrite the one item which changes for each autosave
    cPickle.dump(savestate, autosave_file, cPickle.HIGHEST_PROTOCOL)
    assert autosave_file.tell() <= start_pos + SAVESLOT_SIZE, "do_autosave: data <= "+str(SAVESLOT_SIZE)+" bytes long"
    autosave_file.flush()
    try:   os.fsync(autosave_file.fileno())
    except StandardError: pass
    autosave_nextslot = 1 if autosave_nextslot==0 else 0
    if not inside_interrupt_handler:
        signal.signal(signal.SIGINT,  sigint_handler)
        signal.signal(signal.SIGTERM, sigterm_handler)
        if sys.platform != "win32":
            signal.signal(signal.SIGHUP, sighup_handler)


# Given an est_secs_per_password, counts the *total* number of passwords generated by password_generator()
# (including those skipped by args.skip), and returns the result, checking the --max-eta constraint along
# the way (and exiting if it's violated). Displays messages to the user if the process is taking a while.
def count_and_check_eta(est):
    assert est > 0.0, "count_and_check_eta: est_secs_per_password > 0.0"
    return password_generator_factory(est_secs_per_password = est)[1]

# Creates a password iterator from the chosen password_generator() and advances it past skipped passwords (as
# per args.skip), returning a tuple: new_iterator, #_of_passwords_skipped. Displays messages to the user if the
# process is taking a while. (Or does the work of count_and_check_eta() when passed est_secs_per_password.)
PASSWORDS_BEFORE_DISPLAY  = 3000000  # on my CPU takes between 2 and 15 seconds depending on complexity, YMMV
PASSWORDS_BETWEEN_UPDATES = 100000
def password_generator_factory(chunksize = 1, **kwds):
    est_secs_per_password = kwds.get("est_secs_per_password", 0)  # Also causes *all* passwords to be counted
    # If not counting all passwords (if only skipping)
    if not est_secs_per_password:
        # The simple case where there's nothing to skip, just return an unmodified password_generator()
        if args.skip <= 0:
            return password_generator(chunksize), 0
        # The still fairly simple case where there's not much to skip, just skip it all at once
        elif args.skip <= PASSWORDS_BETWEEN_UPDATES:
            passwords_count_iterator = password_generator(args.skip, True)  # only_yield_count==True
            passwords_counted = 0
            try:
                # Skip it all in a single iteration (or raise StopIteration if it's empty)
                passwords_counted = passwords_count_iterator.next()
                passwords_count_iterator.send( (chunksize, False) )  # change it into a "normal" iterator
            except StopIteration: pass
            return passwords_count_iterator, passwords_counted

    # If not counting all passwords (therefore the runtime is bounded by args.skip), don't bother
    # displaying any messages if they would only be displayed for a moment.
    if not est_secs_per_password and args.skip < 1.5 * PASSWORDS_BEFORE_DISPLAY:
        l_passwords_before_display = int(1.5 * PASSWORDS_BEFORE_DISPLAY)
    else:
        l_passwords_before_display = PASSWORDS_BEFORE_DISPLAY

    assert args.skip >= 0
    sys_stderr_isatty = sys.stderr.isatty()
    max_seconds = args.max_eta * 3600  # max_eta is in hours
    passwords_count_iterator = password_generator(PASSWORDS_BETWEEN_UPDATES, True)  # only_yield_count==True
    passwords_counted = 0
    try:
        # Iterate though the password counts in increments of size PASSWORDS_BETWEEN_UPDATES
        for passwords_counted_last in passwords_count_iterator:
            passwords_counted += passwords_counted_last
            unskipped_passwords_counted = passwords_counted - args.skip

            # If it's taking a while, display/update the on-screen message
            if passwords_counted >= l_passwords_before_display and sys_stderr_isatty:
                if passwords_counted == l_passwords_before_display:
                    print("Counting passwords ..." if est_secs_per_password else "Skipping passwords ...", file=sys.stderr)
                #
                # If ETAs were requested, calculate and possibly display one
                if est_secs_per_password:
                    # Only display an ETA once unskipped passwords are being counted
                    if unskipped_passwords_counted > 0:
                        eta = unskipped_passwords_counted * est_secs_per_password / 60
                        if eta < 90:     eta = str(int(eta)+1) + " minutes"  # round up
                        else:
                            eta /= 60
                            if eta < 48: eta = str(int(round(eta))) + " hours"
                            else:        eta = str(round(eta / 24, 1)) + " days"
                        msg = "\r  {:,}".format(passwords_counted)
                        if args.skip: msg += " (includes {:,} skipped)".format(args.skip)
                        msg += "  ETA: " + eta + " and counting   "
                        print(msg, end="", file=sys.stderr)
                    # Else just indicate that all the passwords counted so far are skipped
                    else:
                        print("\r  {:,} (all skipped)".format(passwords_counted), end="", file=sys.stderr)
                #
                # Else no ETAs were requested, just display the count ("Skipping passwords ..." was already printed)
                else:
                    print("\r  {:,}".format(passwords_counted), end="", file=sys.stderr)

            # If the ETA is past its max permitted limit, exit
            if unskipped_passwords_counted * est_secs_per_password > max_seconds:
                print("\r", file=sys.stderr)
                error_exit("at least {:,} passwords to try, ETA > max_eta option ({} hours), exiting" \
                    .format(passwords_counted - args.skip, args.max_eta))

            # If not counting all the passwords, then break out of this loop before it's gone past args.skip
            # (actually it must leave at least one password left to count before the args.skip limit)
            if not est_secs_per_password and passwords_counted >= args.skip - PASSWORDS_BETWEEN_UPDATES:
                break

        # Erase the on-screen counter if it was being displayed
        if passwords_counted >= l_passwords_before_display and sys_stderr_isatty:
            print("\rDone" + " "*74)

        # If all passwords were being/have been counted
        if est_secs_per_password:
            return None, passwords_counted

        # Else finish counting the final (probably partial) iteration of skipped passwords
        # (which will be in the range [1, PASSWORDS_BETWEEN_UPDATES] )
        else:
            try:
                passwords_count_iterator.send( (args.skip - passwords_counted, True) )  # the remaining count
                passwords_counted += passwords_count_iterator.next()
                passwords_count_iterator.send( (chunksize, False) )  # change it into a "normal" iterator
            except StopIteration: pass
            return passwords_count_iterator, passwords_counted

    except BaseException as e:
        if isinstance(e, SystemExit): raise  # happens when error_exit is called above
        counting_or_skipping = "counting" if est_secs_per_password else "skipping"
        including_skipped    = "(including skipped ones)" if est_secs_per_password and args.skip else ""
        print("\nInterrupted after", counting_or_skipping, passwords_counted, "passwords", including_skipped, file=sys.stderr)
        if isinstance(e, MemoryError) and passwords_counted > 0:
            handle_oom()  # will re-raise if not handled
            sys.exit(1)
        if isinstance(e, KeyboardInterrupt): sys.exit(0)
        raise


def main():

    # Once installed, performs cleanup prior to a requested process shutdown on Windows
    # (this is defined inside main so it can access the passwords_tried local)
    def windows_ctrl_handler(signal):
        if signal == 0:   # if it's a Ctrl-C,
           return False   # defer to the native Python handler which works just fine
        #
        # Python on Windows is a bit touchy with signal handlers; it's safest to just do
        # all the cleanup code here (even though it'd be cleaner to throw an exception)
        if savestate:
            do_autosave(args.skip + passwords_tried, True)  # do this first, it's most important
            autosave_file.close()
        print("\nInterrupted after finishing password #", args.skip + passwords_tried, file=sys.stderr)
        if sys.stdout.isatty() ^ sys.stderr.isatty():  # if they're different, print to both to be safe
            print("\nInterrupted after finishing password #", args.skip + passwords_tried)
        os._exit(1)

    # Copy a global into local for a small speed boost
    l_savestate = savestate

    # If --listpass was requested, just list out all the passwords and exit
    passwords_count = 0
    if args.listpass:
        password_iterator, skipped_count = password_generator_factory()
        plus_skipped = "(plus " + str(skipped_count) + " skipped)" if skipped_count else ""
        try:
            for password in password_iterator:
                passwords_count += 1
                print(password[0])
        except BaseException as e:
            print("\nInterrupted after generating", passwords_count, "passwords", plus_skipped, file=sys.stderr)
            if isinstance(e, MemoryError) and passwords_count > 0:
                handle_oom()  # will re-raise if not handled
                sys.exit(1)
            if isinstance(e, KeyboardInterrupt): sys.exit(0)
            raise
        msg = str(passwords_count) + " password combinations " + plus_skipped
        print("\n", msg, file=sys.stderr)
        return msg

    # Measure the performance of the verification function
    if args.enable_gpu:
        inner_iterations = sum(args.global_ws)
        outer_iterations = 1
    else:
        # Passwords are verified in "chunks" to reduce call overhead. One chunk includes enough passwords to
        # last for about 1/100th of a second (determined experimentally to be about the best I could do, YMMV)
        CHUNKSIZE_SECONDS = 1.0 / 100.0
        # (measure_performance_iterations has been set such that this should take about 0.5 seconds)
        assert measure_performance_iterations, "measure_performance_iterations has been set"
        inner_iterations = int(round(2*measure_performance_iterations * CHUNKSIZE_SECONDS)) or 1  # assumes 0.5 second's worth
        outer_iterations = int(round(measure_performance_iterations / inner_iterations))
    #
    start = time.clock()
    for o in xrange(outer_iterations):
        return_verified_password_or_false(["measure performance "+str(i) for i in xrange(inner_iterations)])
    est_secs_per_password = (time.clock() - start) / (outer_iterations * inner_iterations)
    assert isinstance(est_secs_per_password, float) and est_secs_per_password > 0.0

    if args.enable_gpu:
        chunksize = sum(args.global_ws)
    else:
        # (see CHUNKSIZE_SECONDS above)
        chunksize = int(round(CHUNKSIZE_SECONDS / est_secs_per_password)) or 1

    # If the time to verify a password is short enough, the time to generate the passwords in this thread
    # becomes comparable to verifying passwords, therefore this should count towards being a "worker" thread
    if est_secs_per_password < 1.0 / 20000.0:
        main_thread_is_worker = True
        spawned_threads   = args.threads - 1      # spawn 1 fewer than requested (might be 0)
        verifying_threads = spawned_threads or 1
    else:
        main_thread_is_worker = False
        spawned_threads   = args.threads if args.threads > 1 else 0
        verifying_threads = args.threads

    # Adjust estimate for the number of verifying threads (final estimate is probably an underestimate)
    est_secs_per_password /= min(verifying_threads, cpus)

    # Count how many passwords there are (excluding skipped ones) so we can display and conform to ETAs
    if not args.no_eta:

        assert args.skip >= 0
        start = time.clock()
        passwords_count = count_and_check_eta(est_secs_per_password) - args.skip
        iterate_time = time.clock() - start

        if passwords_count <= 0:
            msg = "Skipped all "+str(passwords_count + args.skip)+" passwords, exiting"
            print(msg)
            return msg

        # If additional ETA calculations are required
        if l_savestate or not have_progress:
            eta_seconds = passwords_count * est_secs_per_password
            # if the main thread is sharing CPU time with a verifying thread
            if (spawned_threads == 0 and not args.enable_gpu or spawned_threads >= cpus):
                eta_seconds += iterate_time
            eta_seconds = int(round(eta_seconds)) or 1
            if l_savestate:
                est_passwords_per_5min = passwords_count // eta_seconds * 300

    # else if args.no_eta and savestate, calculate a simple approximate of est_passwords_per_5min
    elif l_savestate:
        est_passwords_per_5min = int(round(300.0 / est_secs_per_password))
        assert est_passwords_per_5min > 0

    # If there aren't many passwords, give each of the N workers 1/Nth of the passwords
    # (rounding up) and also don't bother spawning more threads than there are passwords
    if not args.no_eta and spawned_threads * chunksize > passwords_count:
        if spawned_threads > passwords_count:
            spawned_threads = passwords_count
        chunksize = (passwords_count-1) // spawned_threads + 1

    # Create an iterator which produces the password permutations in chunks, skipping some if so instructed
    if args.skip > 0:
        print("Starting with password #", args.skip + 1)
    password_iterator, skipped_count = password_generator_factory(chunksize)
    if skipped_count < args.skip:
        assert args.no_eta, "discovering all passwords have been skipped this late only happens if --no-eta"
        msg = "Skipped all "+str(skipped_count)+" passwords, exiting"
        print(msg)
        return msg
    assert skipped_count == args.skip

    if args.enable_gpu:
        if len(cl_devices) == 1:
            print("Using OpenCL", pyopencl.device_type.to_string(cl_devices[0].type), cl_devices[0].name.strip())
        else:
            print("Using", len(cl_devices), "OpenCL devices:")
            for dev in cl_devices:
                print(" ", pyopencl.device_type.to_string(dev.type), dev.name.strip())
    else:
        print("Using", args.threads, "worker", "threads" if args.threads > 1 else "thread")  # (they're actually worker processes)

    if have_progress:
        if args.no_eta:
            progress = progressbar.ProgressBar(maxval=sys.maxint, widgets=[
                progressbar.AnimatedMarker(),
                progressbar.FormatLabel(" %(value)d  elapsed: %(elapsed)s  rate: "),
                progressbar.FileTransferSpeed(unit="P")
            ])
        else:
            progress = progressbar.ProgressBar(maxval=passwords_count, widgets=[
                progressbar.SimpleProgress(), " ",
                progressbar.Bar(left="[", fill="-", right="]"),
                progressbar.FormatLabel(" %(elapsed)s, "),
                progressbar.ETA()
            ])
    else:
        progress = None
        if args.no_eta:
            print("Searching for password ...")
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

    # Autosave the starting state now that we're just about ready to start
    if l_savestate: do_autosave(args.skip)

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
        password_found_iterator = pool.imap(return_verified_password_or_false, password_iterator)
        if main_thread_is_worker: set_process_priority_idle()  # if this thread is cpu-intensive, be nice

    # Try to catch all types of intentional program shutdowns so we can
    # display password progress information and do a final autosave
    try:
        sigint_handler = signal.getsignal(signal.SIGINT)
        signal.signal(signal.SIGTERM, sigint_handler)     # OK to call on any OS
        if sys.platform != "win32":
            signal.signal(signal.SIGHUP, sigint_handler)  # can't call this on windows
        else:
            import win32api
            win32api.SetConsoleCtrlHandler(windows_ctrl_handler, True)
    except StandardError: pass

    # Make est_passwords_per_5min evenly divisible by chunksize
    # (so that passwords_tried % est_passwords_per_5min will eventually == 0)
    if l_savestate:
        assert isinstance(est_passwords_per_5min, int)
        est_passwords_per_5min = int(round(est_passwords_per_5min / chunksize)) * chunksize

    # Iterate through password_found_iterator looking for a successful guess
    msg = ""
    passwords_tried = 0
    if progress: progress.start()
    try:
        for password_found, passwords_tried_last in password_found_iterator:
            passwords_tried += passwords_tried_last
            if progress: progress.update(passwords_tried)
            if password_found:
                if progress: print()  # move down to the line below the progress bar
                msg = "Password found: " + repr(password_found)
                print(msg)
                passwords_tried -= 1  # adjusted so it's autosaved just before this password
                break
            if l_savestate and passwords_tried % est_passwords_per_5min == 0:
                do_autosave(args.skip + passwords_tried)
        else:  # if the for loop exits normally (without breaking)
            if progress:
                if args.no_eta:
                    progress.maxval = passwords_tried
                progress.finish()
            msg = "Password search exhausted"
            print(msg)

    # Gracefully handle any exceptions, printing the count completed so far so that it can be
    # skipped if the user restarts the same run. If the exception was expected (Ctrl-C or some
    # other intentional shutdown, or an out-of-memory condition that can be handled), fall
    # through to the autosave, otherwise re-raise the exception.
    except BaseException as e:
        print("\nInterrupted after finishing password #", args.skip + passwords_tried, file=sys.stderr)
        if sys.stdout.isatty() ^ sys.stderr.isatty():  # if they're different, print to both to be safe
            print("\nInterrupted after finishing password #", args.skip + passwords_tried)
        if isinstance(e, MemoryError): handle_oom()    # will re-raise if not handled
        elif not isinstance(e, KeyboardInterrupt): raise

    # Autosave the final state (for all non-error cases -- we're shutting down (e.g. Ctrl-C or a
    # reboot), the password was found, or the search was exhausted -- or for handled out-of-memory)
    if l_savestate:
        do_autosave(args.skip + passwords_tried)
        autosave_file.close()

    if spawned_threads > 0: pool.terminate()
    if msg: return msg


if __name__ == '__main__':
    parse_arguments(sys.argv[1:])
    main()
