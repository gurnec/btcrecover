#!/usr/bin/env python

# extract-armory-privkey.py -- Armory private key extractor
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
import sys, os.path, struct, zlib, base64, time

prog = os.path.basename(sys.argv[0])

def print_usage():
    print("usage:", prog, "ARMORY_WALLET_FILE <option>\n" +
          "    <option> must either be:\n" +
          "    list                    - list addresses that have encrypted private keys\n" +
          "    extract BITCOIN_ADDRESS - extract the encrypted private key of the address")
    sys.exit(2)

# Parse command line arguments
if len(sys.argv) < 3: print_usage()
wallet_filename = sys.argv[1]
if sys.argv[2]   == "list":
    if len(sys.argv) != 3: print_usage()
    base58_bitcoin_address = None
elif sys.argv[2] == "extract":
    if len(sys.argv) != 4: print_usage()
    base58_bitcoin_address = sys.argv[3]
else: print_usage()

# Try to add the Armory libraries to the path on various platforms, and then load it
if sys.platform == "win32":
    win32_path = os.environ.get("ProgramFiles",  r"C:\Program Files (x86)") + r"\Armory"
    sys.path.extend((win32_path, win32_path + r"\library.zip"))
elif sys.platform.startswith("linux"):
    sys.path.append("/usr/lib/armory")
elif sys.platform == "darwin":
    sys.path.append("/Applications/Armory.app/Contents/MacOS/py/usr/lib/armory")
del sys.argv[1:]  # blank out argv before importing it, otherwise it attempts to process argv
import armoryengine.PyBtcWallet, armoryengine.ArmoryUtils

# Load the wallet file
wallet = armoryengine.PyBtcWallet.PyBtcWallet().readWalletFile(wallet_filename)

# Utility function to print out some useful details of an Armory address object
def print_address(address, file=sys.stdout):
    # The public address string
    desc = address.getAddrStr()
    desc += " " * (34 - len(desc))  # line them up nicely
    # The first date this address was used, if available
    if address.timeRange[0] != 2**32-1:
        desc += time.strftime(" First:%x", time.localtime(address.timeRange[0]))
    # The last date this address was used, if available
    if address.timeRange[1] != 0:
        desc += time.strftime(" Last:%x", time.localtime(address.timeRange[1]))
    # Was this address imported into Armory?
    if address.chainIndex == -2:
        desc += " [IMPORTED]"
    # The address comments, if any
    comment = wallet.commentsMap.get(address.addrStr20)
    if comment:
        desc += " " + comment
    print(desc, file=file)

# "list" mode- just list out all addresses that have an encrypted private key
# except the ROOT address
if base58_bitcoin_address is None:
    address_count = 0
    for i, address_hash, address in wallet.getAddrListSortedByChainIndex():
        if address.binPrivKey32_Encr.getSize() != 0 and not address.isAddrChainRoot():
            print_address(address)
            address_count += 1
    print("\n Found "+str(address_count)+" addresses with encrypted private keys")

# "extract" mode
else:
    # Lookup the address in the wallet and make sure it's suitable
    address = wallet.addrMap.get(armoryengine.ArmoryUtils.addrStr_to_hash160(base58_bitcoin_address)[1])
    if address is None:
        print(prog+": error: bitcoin address not found in this wallet", file=sys.stderr)
        sys.exit(1)

    print("\nWARNING: once decrypted, this will provide access to all Bitcoin\n" +
            "         funds available now and in the future of this one address\n", file=sys.stderr)
    print_address(address, file=sys.stderr)

    if address.binPrivKey32_Plain.getSize() != 0:
        print(prog+": error: private key is already decrypted", file=sys.stderr)
        sys.exit(1)
    if address.binPrivKey32_Encr.getSize() == 0:
        print(prog+": error: private key for this address is not stored in this wallet", file=sys.stderr)
        sys.exit(1)
    assert not address.isAddrChainRoot(),             "this isn't the ROOT address"
    assert len(address.addrStr20)              == 20, "public key hash is 20 bytes long"
    assert address.binPrivKey32_Encr.getSize() == 32, "encrypted private key is 32 bytes long"
    assert address.binInitVect16.getSize()     == 16, "aes initialization vector is 16 bytes long"

    print("\nArmory address, encrypted private key, iv, kdf parameters, and crc in base64:", file=sys.stderr)

    kdf   = wallet.kdf  # Contains the key derivation function parameters and salt
    assert kdf, "kdf is present"
    bytes = b"ar:"                           + \
        address.addrStr20                    + \
        address.binPrivKey32_Encr.toBinStr() + \
        address.binInitVect16.toBinStr()     + \
        struct.pack("< I I", kdf.getMemoryReqtBytes(), kdf.getNumIterations()) + \
        kdf.getSalt().toBinStr()
    crc_bytes = struct.pack("<I", zlib.crc32(bytes) & 0xffffffff)

    print(base64.b64encode(bytes + crc_bytes))
