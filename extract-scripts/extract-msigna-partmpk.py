#!/usr/bin/env python

# extract-msigna-privkey.py -- mSIGNA private key extractor
# Copyright (C) 2014, 2015 Christopher Gurnee
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

if len(sys.argv) not in (2,3) or sys.argv[1].startswith("-"):
    print("usage:", prog, "MSIGNA_VAULT_FILE [KEYCHAIN-NAME]", file=sys.stderr)
    sys.exit(2)

vault_filename = sys.argv[1]
keychain_name  = sys.argv[2] if len(sys.argv) >= 3 else None

# Open the mSIGNA vault file (it's a SQLite 3 file)
wallet_conn = sqlite3.connect(vault_filename)

# Find the specified keychain, or if none was specified, find the first
wallet_conn.row_factory = sqlite3.Row
select = "SELECT * FROM Keychain"
if keychain_name:
    wallet_cur = wallet_conn.execute(select + " WHERE name LIKE '%' || ? || '%'", (keychain_name,))
else:
    wallet_cur = wallet_conn.execute(select)
keychain = wallet_cur.fetchone()
if not keychain:
    sys.exit("no such keychain found in the mSIGNA vault")

# If there are multiple matching keychains, give up
keychain_extra = wallet_cur.fetchone()
if keychain_extra:
    print("Multiple matching keychains found in the mSIGNA vault:", file=sys.stderr)
    print("  ", keychain["name"])
    print("  ", keychain_extra["name"])
    for keychain_extra in wallet_cur:
        print("  ", keychain_extra["name"])
    sys.exit("Please specify the keychain name as the second argument to " + prog)

wallet_conn.close()

# Extract the entire encrypted master private key for this keychain; it should
# contain 32 bytes of encrypted key data, followed by 16 bytes of encrypted padding
privkey_ciphertext = str(keychain["privkey_ciphertext"])
if len(privkey_ciphertext) == 32:
    sys.exit("mSIGNA keychain '"+keychain["name"]+"' is not encrypted")
if len(privkey_ciphertext) != 48:
    sys.exit("mSIGNA keychain '"+keychain["name"]+"' has an unexpected privkey length")

print("mSIGNA partial encrypted master private key, salt, and crc in base64:", file=sys.stderr)

# We only need the last half of the encrypted master private key and the encrypted
# padding (the last 32 bytes of the 48 bytes of ciphertext), plus the salt
bytes = "ms:" + privkey_ciphertext[16:48] + struct.pack("< q", keychain["privkey_salt"])
crc_bytes = struct.pack("<I", zlib.crc32(bytes) & 0xffffffff)
print(base64.b64encode(bytes + crc_bytes))
