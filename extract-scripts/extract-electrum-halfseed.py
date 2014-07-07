#!/usr/bin/python

# extract-electrum-halfseed.py -- Electrum partial seed extractor
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

# Special thanks to Bitcointalk.org user Wotan777 who discovered a better way
# to work with Electrum wallets, and who made this extract script possible.

from __future__ import print_function
import sys, os.path, ast, base64, zlib, struct

prog = os.path.basename(sys.argv[0])

if len(sys.argv) != 2 or sys.argv[1].startswith("-"):
    print("usage:", prog, "ELECTRUM_WALLET_FILE", file=sys.stderr)
    sys.exit(2)

wallet_filename = sys.argv[1]

wallet = ast.literal_eval(open(wallet_filename, "rb").read(1048576))  # up to 1M, typical size is a few k

seed_version = wallet.get("seed_version")
if seed_version is None: raise ValueError("Unrecognized wallet format (Electrum seed_version not found)")
if seed_version != 4:    raise NotImplementedError("Unsupported Electrum seed version " + seed_version)

if not wallet.get("use_encryption"): raise ValueError("Electrum wallet is not encrypted")

iv_and_encr_seed = base64.b64decode(wallet["seed"])
if len(iv_and_encr_seed) != 64:      raise ValueError("Electrum encrypted seed plus iv is not 64 bytes long")

print("First half of encrypted Electrum seed, iv, and crc in base64:", file=sys.stderr)

bytes = b"el:" + iv_and_encr_seed[:32]  # only need the 16-byte IV plus the first 16-byte encrypted block of the seed
crc_bytes = struct.pack("<I", zlib.crc32(bytes) & 0xffffffff)

print(base64.b64encode(bytes + crc_bytes))
