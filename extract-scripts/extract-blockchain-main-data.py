#!/usr/bin/env python

# extract-blockchain-main-data.py -- Blockchain data extractor
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
#           3Au8ZodNHPei7MQiSVAWb7NB2yqsb48GW4
#
#                      Thank You!

from __future__ import print_function
import sys, os.path, base64, json, zlib, struct

prog = os.path.basename(sys.argv[0])

if len(sys.argv) != 2 or sys.argv[1].startswith("-"):
    print("usage:", prog, "BLOCKCHAIN_WALLET_FILE", file=sys.stderr)
    sys.exit(2)

wallet_filename = sys.argv[1]
data = open(wallet_filename, "rb").read(64 * 2**20)  # up to 64M, typical size is a few k

# The number of pbkdf2 iterations, or 0 for v0.0 wallet files which don't specify this
iter_count = 0

class MayBeBlockchainV0(BaseException): pass;  # an exception which jumps to the end of the try block below
try:

    # Most blockchain files (except v0.0 wallets) are JSON encoded; try to parse it as such
    try:
        data = json.loads(data)
    except ValueError:
        raise MayBeBlockchainV0()

    # Config files have no version attribute; they encapsulate the wallet file plus some detrius
    if u"version" not in data:
        try:
            data = data[u"payload"]  # extract the wallet file from the config
        except KeyError:
            raise ValueError("Can't find either version nor payload attributes in Blockchain file")
        try:
            data = json.loads(data)  # try again to parse a v2.0/v3.0 JSON-encoded wallet file
        except ValueError:
            raise MayBeBlockchainV0()

    # Extract what's needed from a v2.0/3.0 wallet file
    if data[u"version"] > 3:
        raise NotImplementedError("Unsupported Blockchain wallet version " + str(data[u"version"]))
    iter_count = data[u"pbkdf2_iterations"]
    if not isinstance(iter_count, int) or iter_count < 1:
        raise ValueError("Invalid Blockchain pbkdf2_iterations " + str(iter_count))
    data = data[u"payload"]

except MayBeBlockchainV0:
    pass

# Either the encrypted data was extracted from the "payload" field above, or this is 
# a v0.0 (a.k.a. v1) wallet file whose entire contents consist of the encrypted data
try:
    data = base64.b64decode(data)
except TypeError as e:
    raise ValueError("Can't base64-decode Blockchain wallet: "+str(e))
if len(data) < 32:
    raise ValueError("Encrypted Blockchain data is too short")
if len(data) % 16 != 0:
    raise ValueError("Encrypted Blockchain data length not divisible by encryption blocksize (16)")

print("Blockchain first 16 encrypted bytes, iv, and iter_count in base64:", file=sys.stderr)

bytes = b"bk:" + struct.pack("< 16s 16s I", data[16:32], data[0:16], iter_count)
crc_bytes = struct.pack("<I", zlib.crc32(bytes) & 0xffffffff)

print(base64.b64encode(bytes + crc_bytes))
