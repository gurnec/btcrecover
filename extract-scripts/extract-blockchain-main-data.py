#!/usr/bin/python

# extract-blockchain-main-data.py -- Blockchain data extractor
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

# If you find this program helpful, please consider a small
# donation to the developer at the following Bitcoin address:
#
#           17LGpN2z62zp7RS825jXwYtE7zZ19Mxxu8
#
#                      Thank You!

from __future__ import print_function
import sys, os.path, base64, json, zlib, struct

prog = os.path.basename(sys.argv[0])

if len(sys.argv) != 2 or sys.argv[1].startswith("-"):
    print("usage:", prog, "BLOCKCHAIN_WALLET_FILE", file=sys.stderr)
    sys.exit(2)

wallet_filename = sys.argv[1]
data = open(wallet_filename, "rb").read(1048576)  # up to 1M, typical size is a few k

# The number of pbkdf2 iterations, or 0 for v0.0 wallet files which don't specify this
iter_count = 0

# Try to load a v2.0 wallet file first
if data[0] == "{":
    try:
        data = json.loads(data)
    except ValueError: pass
    else:
        if data["version"] != 2:
            raise NotImplementedError("Unsupported Blockchain wallet version " + str(data["version"]))
        iter_count = data["pbkdf2_iterations"]
        if not isinstance(iter_count, int) or iter_count < 1:
            raise ValueError("Invalid Blockchain pbkdf2_iterations " + str(iter_count))
        data = data["payload"]

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
