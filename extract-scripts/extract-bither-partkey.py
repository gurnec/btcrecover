#!/usr/bin/env python

# extract-bither-privkey.py -- Bither private key extractor
# Copyright (C) 2016 Christopher Gurnee
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
import sys, os.path, sqlite3, base64, zlib, struct

prog = os.path.basename(sys.argv[0])

if len(sys.argv) != 2 or sys.argv[1].startswith("-"):
    print("usage:", prog, "BITHER_WALLET_FILE (typically named address.db)", file=sys.stderr)
    sys.exit(2)

wallet_filename = sys.argv[1]

# Open the Bither wallet file (it's a SQLite 3 file)
wallet_conn = sqlite3.connect(wallet_filename)

# Try to find an encrypted loose key
wallet_cur = wallet_conn.execute("SELECT encrypt_private_key FROM addresses LIMIT 1")
key_data   = wallet_cur.fetchone()
if not key_data:
    sys.exit("This Bither wallet is incompatible with "+prog+" (no loose private keys found).\n" +
             "Please run btcrecover with the wallet file directly instead.")
key_data = key_data[0]
wallet_conn.close()

# key_data is forward-slash delimited; it contains an optional pubkey hash, an encrypted key, an IV, a salt
key_data = key_data.split("/")
if len(key_data) == 1:
    key_data = key_data.split(":")  # old Bither wallets used ":" as the delimiter
if len(key_data) == 4:
    key_data.pop(0)  # remove the optional pubkey hash
if len(key_data) != 3:
    sys.exit("unrecognized Bither encrypted key format (expected 3-4 slash-delimited elements, found {})"
             .format(len(key_data)))
privkey_ciphertext = base64.b16decode(key_data[0], casefold=True)
salt               = base64.b16decode(key_data[2], casefold=True)

if len(privkey_ciphertext) != 48:
    sys.exit("unexpected encrypted key length in Bither wallet (expected 48, found {})"
               .format(len(privkey_ciphertext)))

# The first salt byte is optionally a flags byte that's not needed
if len(salt) == 9:
    salt = salt[1:]
elif len(salt) != 8:
    sys.exit("unexpected salt length ({}) in Bither wallet".format(len(salt)))

print("Bither partial encrypted private key, salt, and crc in base64:", file=sys.stderr)

# We only need the last half of the encrypted private key and the encrypted
# padding (the last 32 bytes of the 48 bytes of ciphertext), plus the salt
bytes = "bt:" + privkey_ciphertext[16:48] + salt
crc_bytes = struct.pack("<I", zlib.crc32(bytes) & 0xffffffff)
print(base64.b64encode(bytes + crc_bytes))
