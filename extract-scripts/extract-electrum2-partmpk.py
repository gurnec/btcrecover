#!/usr/bin/env python

# extract-electrum2-partmpk.py -- Electrum 2.x partial mpk extractor
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

from __future__ import print_function
import sys, os.path, json, base64, zlib, itertools, struct

prog = os.path.basename(sys.argv[0])

if len(sys.argv) != 2 or sys.argv[1].startswith("-"):
    print("usage:", prog, "ELECTRUM2_WALLET_FILE", file=sys.stderr)
    sys.exit(2)

wallet_filename = sys.argv[1]

with open(wallet_filename) as wallet_file:
    try:
        wallet = json.load(wallet_file)
    except ValueError as e:
        wallet_file.seek(0)
        try:
            data = base64.b64decode(wallet_file.read(8))
        except TypeError:
            raise e
        if data[:4] == "BIE1":  # Electrum 2.8+ magic
            raise NotImplementedError("Electrum 2.8+ fully encrypted wallets are supported by btcrecover, but not via data extracts")
        else:
            raise e

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
    if wallet.get("seed_version") not in (11, 12, 13) and wallet_type != "imported":  # all 2.x versions as of Oct 2016
                                     raise NotImplementedError("Unsupported Electrum2 seed version " + str(seed_version))
    xprv = None

    # A try block and an exception that's raised to exit the block once we've found the data to extract
    class FoundEncryptedData(BaseException): pass
    try:

        # Electrum 2.7+ standard wallets have a keystore
        keystore = wallet.get("keystore")
        if keystore:
            keystore_type = keystore.get("type", "(not found)")

            # Wallets originally created by an Electrum 2.x version
            if keystore_type == "bip32":
                xprv = keystore["xprv"]
                raise FoundEncryptedData()

            # Former Electrum 1.x wallet after conversion to Electrum 2.7+ standard-wallet format
            elif keystore_type == "old":
                data = base64.b64decode(keystore["seed"])
                if len(data) != 64:  raise RuntimeError("Electrum1 encrypted seed plus iv is not 64 bytes long")
                wallet_id = "el"
                data      = data[:32]  # only need the 16-byte IV plus the first 16-byte encrypted block of the seed
                desc      = "First half of encrypted Electrum 1.x seed"
                raise FoundEncryptedData()

            # Imported loose private keys
            elif keystore_type == "imported":
                for privkey in keystore["keypairs"].values():
                    if privkey:
                        privkey = base64.b64decode(privkey)
                        if len(privkey) != 80:
                            raise RuntimeError("Electrum2 private key plus iv is not 80 bytes long")
                        wallet_id = "ek"
                        data      = privkey[-32:]  # only need the 16-byte IV plus the last 16-byte encrypted block of the key
                        desc      = "Last 16 bytes of a private key"
                        raise FoundEncryptedData()

            else:
                print(prog+": warning: found unsupported keystore type " + keystore_type, file=sys.stderr)

        # Electrum 2.7+ multisig or 2fa wallet
        for i in itertools.count(1):
            x = wallet.get("x{}/".format(i))
            if not x: break
            x_type = x.get("type", "(not found)")
            if x_type == "bip32":
                xprv = x.get("xprv")
                if xprv: raise FoundEncryptedData()
            else:
                print(prog + ": warning: found unsupported key type " + x_type, file=sys.stderr)

        # Electrum 2.0 - 2.6.4 wallet with imported loose private keys
        if wallet_type == "imported":
            for imported in wallet["accounts"]["/x"]["imported"].values():
                privkey = imported[1] if len(imported) >= 2 else None
                if privkey:
                    # Construct and return a WalletElectrumLooseKey object
                    privkey = base64.b64decode(privkey)
                    if len(privkey) != 80:
                        raise RuntimeError("Electrum2 private key plus iv is not 80 bytes long")
                    wallet_id = "ek"
                    data      = privkey[-32:]  # only need the 16-byte IV plus the last 16-byte encrypted block of the key
                    desc      = "Last 16 bytes of a private key"
                    raise FoundEncryptedData()

        # Electrum 2.0 - 2.6.4 wallet (of any other wallet type)
        else:
            mpks = wallet.get("master_private_keys")
            if mpks:
                xprv = mpks.values()[0]
                raise FoundEncryptedData()

        raise RuntimeError("No master private keys or seeds found in Electrum2 wallet")

    except FoundEncryptedData: pass

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
