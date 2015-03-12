#!/usr/bin/python

# extract-electrum-partmpk.py -- Electrum 2.x partial mpk extractor
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

from __future__ import print_function
import sys, os.path, json, base64, zlib, struct

prog = os.path.basename(sys.argv[0])

if len(sys.argv) != 2 or sys.argv[1].startswith("-"):
    print("usage:", prog, "ELECTRUM2_WALLET_FILE", file=sys.stderr)
    sys.exit(2)

wallet_filename = sys.argv[1]

with open(wallet_filename) as wallet_file:
    wallet = json.load(wallet_file)

if not wallet.get("use_encryption"): raise ValueError("Electrum2 wallet is not encrypted")

wallet_type = wallet.get("wallet_type")
if not wallet_type:                  raise ValueError("Electrum2 wallet_type not found")

if wallet_type == "old":  # if it's a converted Electrum 1.x wallet
    wallet_id = "el"
    seed_version = wallet.get("seed_version")
    if seed_version is None:         raise ValueError("Unrecognized wallet format (Electrum seed_version not found)")
    if seed_version != 4:            raise NotImplementedError("Unsupported Electrum seed version " + seed_version)

    data = base64.b64decode(wallet["seed"])
    if len(data) != 64:              raise ValueError("Electrum encrypted seed plus iv is not 64 bytes long")
    data = data[:32]  # only need the 16-byte IV plus the first 16-byte encrypted block of the seed

    print("First half of encrypted Electrum seed, iv, and crc in base64:", file=sys.stderr)

else:  # it's a wallet initially created by Electrum 2.x
    wallet_id = "e2"
    mpks = wallet.get("master_private_keys", ())
    if len(mpks) == 0:               raise ValueError("No master private keys found in Electrum2 wallet")
    data = base64.b64decode(mpks.values()[0])
    if len(data) != 128:             raise ValueError("Unexpected Electrum2 encrypted master private key length")
    data = data[:32]  # only need the 16-byte IV plus the first 16-byte encrypted block of the mpk

    print("Electrum2 partial encrypted master private key, iv, and crc in base64:", file=sys.stderr)

bytes = wallet_id + ":" + data
crc_bytes = struct.pack("<I", zlib.crc32(bytes) & 0xffffffff)

print(base64.b64encode(bytes + crc_bytes))
