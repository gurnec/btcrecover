#!/usr/bin/python

# extract-electrum2-partmpk.py -- Electrum 2.x partial mpk extractor
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

from __future__ import print_function
import sys, os.path, json, base64, zlib, itertools, struct

prog = os.path.basename(sys.argv[0])

if len(sys.argv) != 2 or sys.argv[1].startswith("-"):
    print("usage:", prog, "ELECTRUM2_WALLET_FILE", file=sys.stderr)
    sys.exit(2)

wallet_filename = sys.argv[1]

with open(wallet_filename) as wallet_file:
    wallet = json.load(wallet_file)

wallet_type = wallet.get("wallet_type")
if not wallet_type:                  raise ValueError("Electrum wallet_type not found")
if not wallet.get("use_encryption"): raise ValueError("Electrum wallet is not encrypted")
seed_version = wallet.get("seed_version", "(not found)")

# Former Electrum 1.x wallet after conversion to 2.y (y<7)
if wallet_type == "old":
    if seed_version != 4:            raise NotImplementedError("Unsupported Electrum1 seed version " + str(seed_version))
    data = base64.b64decode(wallet["seed"])
    if len(data) != 64:              raise ValueError("Electrum1 encrypted seed plus iv is not 64 bytes long")
    wallet_id = "el"
    data      = data[:32]  # only need the 16-byte IV plus the first 16-byte encrypted block of the seed
    desc      = "First half of encrypted Electrum 1.x seed"

else:
    if wallet.get("seed_version") not in (11, 12, 13):  # all 2.x versions as of Oct 2016
                                     raise NotImplementedError("Unsupported Electrum2 seed version " + str(seed_version))
    xprv = None
    while True:  # "loops" exactly once; only here so we've something to break out of

        # Electrum 2.7+ standard wallets have a keystore
        keystore = wallet.get("keystore")
        if keystore:
            keystore_type = keystore.get("type", "(not found)")

            # Wallets originally created by an Electrum 2.x version
            if keystore_type == "bip32":
                xprv = keystore["xprv"]
                break

            # Former Electrum 1.x wallet after conversion to Electrum 2.7+ standard-wallet format
            elif keystore_type == "old":
                data = base64.b64decode(keystore["seed"])
                if len(data) != 64:  raise RuntimeError("Electrum1 encrypted seed plus iv is not 64 bytes long")
                wallet_id = "el"
                data      = data[:32]  # only need the 16-byte IV plus the first 16-byte encrypted block of the seed
                desc      = "First half of encrypted Electrum 1.x seed"
                break

            else:
                print(prog+": warning: found unsupported keystore type " + keystore_type, file=sys.stderr)

        # Electrum 2.7+ multisig or 2fa wallet
        for i in itertools.count(1):
            x = wallet.get("x{}/".format(i))
            if not x: break
            x_type = x.get("type", "(not found)")
            if x_type == "bip32":
                xprv = x.get("xprv")
                if xprv: break
            else:
                print(prog + ": warning: found unsupported key type " + x_type, file=sys.stderr)
        if xprv: break

        # Electrum 2.0 - 2.6.4 wallet (of any wallet type)
        mpks = wallet.get("master_private_keys")
        if mpks:
            xprv = mpks.values()[0]
            break

        raise RuntimeError("No master private keys or seeds found in Electrum2 wallet")

    if xprv:
        data = base64.b64decode(xprv)
        if len(data) != 128: raise ValueError("Unexpected Electrum2 encrypted master private key length")
        wallet_id = "e2"
        data      = data[:32]  # only need the 16-byte IV plus the first 16-byte encrypted block of the mpk
        desc      = "Electrum 2.x partial encrypted master private key"

assert wallet_id and data and len(data) == 32

print(desc + ", iv, and crc in base64:", file=sys.stderr)

bytes = wallet_id + ":" + data
crc_bytes = struct.pack("<I", zlib.crc32(bytes) & 0xffffffff)

print(base64.b64encode(bytes + crc_bytes))
