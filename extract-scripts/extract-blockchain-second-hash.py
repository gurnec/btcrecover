#!/usr/bin/python

# extract-blockchain-second-hash.py -- Blockchain second password hash extractor
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

from __future__ import print_function
import sys, os.path, base64, json, getpass, uuid, zlib, struct


################################### AES Libraries ###################################

# Loads PyCrypto if available, else falls back to the pure python version
def load_aes256_library():
    global aespython, aes256_cbc_decrypt, pbkdf2
    try:
        import Crypto.Cipher.AES, Crypto.Protocol.KDF
        aes256_cbc_decrypt = lambda key, iv, ciphertext: \
            Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_CBC, iv).decrypt(ciphertext)
        pbkdf2 = lambda password, salt, iter_count, len: \
            Crypto.Protocol.KDF.PBKDF2(password, salt, len, iter_count)
        return
    except ImportError: pass
    # Add the parent directory of this script's location to the library search path
    sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), ".."))
    import aespython.key_expander, aespython.aes_cipher, aespython.cbc_mode, passlib.utils.pbkdf2
    aes256_cbc_decrypt = aes256_cbc_decrypt_pp
    pbkdf2 = passlib.utils.pbkdf2.pbkdf2

# Input must be a multiple of 16 bytes; does not strip any padding.
# This version is attributed to GitHub user serprex; please see the
# aespython README.txt for more information.
def aes256_cbc_decrypt_pp(key, iv, ciphertext):
    aes256_key_expander = aespython.key_expander.KeyExpander(256)
    block_cipher  = aespython.aes_cipher.AESCipher( aes256_key_expander.expand(map(ord, key)) )
    stream_cipher = aespython.cbc_mode.CBCMode(block_cipher, 16)
    stream_cipher.set_iv(bytearray(iv))
    plaintext = bytearray()
    for i in xrange(0, len(ciphertext), 16):
        plaintext.extend( stream_cipher.decrypt_block(map(ord, ciphertext[i:i+16])) )  # input must be a list
    return str(plaintext)


################################### Main ###################################

prog = os.path.basename(sys.argv[0])

if len(sys.argv) != 2 or sys.argv[1].startswith("-"):
    print("usage:", prog, "BLOCKCHAIN_WALLET_FILE", file=sys.stderr)
    sys.exit(2)

wallet_filename = sys.argv[1]
data = open(wallet_filename, "rb").read(1048576)  # up to 1M, typical size is a few k

iter_count = None
try:
    # This will parse either an encrypted v2.0 wallet, or an unencrypted wallet
    if data[0] == "{":
        try:
            data = json.loads(data)
        except ValueError:
            # If it fails, then we must have an encrypted v0.0 wallet instead
            pass
        else:
            # This tries to sanity check an encrypted v2.0 wallet, it will fail if an unencrypted wallet is loaded
            if data["version"] != 2:
                raise NotImplementedError("Unsupported Blockchain wallet version " + str(data["version"]))
            iter_count = data["pbkdf2_iterations"]
            if not isinstance(iter_count, int) or iter_count < 1:
                raise ValueError("Invalid Blockchain pbkdf2_iterations " + str(iter_count))
            data = data["payload"]

    # At this point we've successfully loaded an encrypted wallet (either v0.0 o v2.0).
    # Either the encrypted data was extracted from the "payload" field above, or this
    # is a v0.0 wallet file whose entire contents consist of the encrypted data
    try:
        data = base64.b64decode(data)
    except TypeError as e:
        raise ValueError("Can't base64-decode Blockchain wallet: "+str(e))
    if len(data) < 32:
        raise ValueError("Encrypted Blockchain data is too short")
    if len(data) % 16 != 0:
        raise ValueError("Encrypted Blockchain data length not divisible by encryption blocksize (16)")

    if not iter_count:   # has already been set for v2.0 wallets
        iter_count = 10  # the default for v0.0 wallets

    # Now that data contains the encrypted binary data, prompt for a password and decrypt it
    load_aes256_library()
    password = getpass.getpass("Please enter the Blockchain wallet's main password: ")
    if not password:
        sys.exit("Encrypted Blockchain files must be decrypted to extract the second password hash")
    key  = pbkdf2(password, data[:16], iter_count, 32)    # data[:16] is the salt
    data = aes256_cbc_decrypt(key, data[:16], data[16:])  # key, iv, encrypted blocks
    padding = ord(data[-1:])  # ISO 10126 padding
    if padding > 16:
        sys.exit("Invalid padding (wrong main password?)")
    data = data[:-padding]

    # Parse the now decrypted wallet (if the wallet wasn't encrypted, it was already parsed above)
    try:
        data = json.loads(data)
    except ValueError as e:
        system.exit("can't parse JSON: "+str(e)+" (wrong main password?)")

except KeyError as e:
    # This is the one error to expect and ignore if the wallet wasn't encrypted
    if e.message == "version": pass
    else: raise


if not data["double_encryption"]:
    system.exit("double encryption with a second password is not enabled for this wallet")

# Extract the three items we need to perform checking on the second password

# The second password hash, converted from hex to binary
password_hash = base64.b16decode(data["dpasswordhash"], True)  # True means allow lowercase
if len(password_hash) != 32:
    raise ValueError("Blockchain second password hash is not 32 bytes long")

# The salt, converted from a GUID to binary
salt = data["sharedKey"].encode("ascii")
salt_uuid = uuid.UUID(salt)
if str(salt_uuid) != salt:
    raise ValueError("Unrecognized Blockchain salt format")

# The iteration count
iter_count = data["options"]["pbkdf2_iterations"]
if not isinstance(iter_count, int) or iter_count < 1:
    raise ValueError("Invalid Blockchain pbkdf2_iterations " + str(iter_count))

print("Blockchain second password hash, salt, and iter_count in base64:", file=sys.stderr)
bytes = b"bs:" + struct.pack("< 32s 16s I", password_hash, salt_uuid.bytes, iter_count)
crc_bytes = struct.pack("<I", zlib.crc32(bytes) & 0xffffffff)

print(base64.b64encode(bytes + crc_bytes))
