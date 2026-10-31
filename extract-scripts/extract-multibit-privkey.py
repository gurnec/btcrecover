#!/usr/bin/env python

# extract-multibit-privkey.py -- MultiBit private key extractor
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
import sys, os.path, base64, zlib, struct

prog = os.path.basename(sys.argv[0])

if len(sys.argv) != 2 or sys.argv[1].startswith("-"):
    print("usage:", prog, "MULTIBIT_PRIVATE_KEY_FILE", file=sys.stderr)
    sys.exit(2)

privkey_filename = sys.argv[1]

with open(privkey_filename, "rb") as privkey_file:

    # Multibit privkey files contain base64 text split into multiple lines;
    # we need the first 32 bytes after decoding, which translates to 44 before.
    base64_encoded = "".join(privkey_file.read(50).split())  # join multiple lines into one
    if len(base64_encoded) < 44:
        print(prog+": error: file is not a MultiBit private key file (too short)", file=sys.stderr)
        sys.exit(1)
    try: salt_privkey = base64.b64decode(base64_encoded[:44])
    except:
        print(prog+": error: file is not a MultiBit private key file (not base64 encoded)", file=sys.stderr)
        sys.exit(1)
    if not salt_privkey.startswith(b"Salted__"):
        print(prog+": error: file is not a MultiBit private key file", file=sys.stderr)
        sys.exit(1)
    if len(salt_privkey) < 32:
        print(prog+": error: file is not a MultiBit private key file (too short)", file=sys.stderr)
        sys.exit(1)

print("\nWARNING: please read the important warning in the Usage for MultiBit\n"
        "         Classic section of Extract_Scripts.md before proceeding.\n")

print("MultiBit partial first encrypted private key, salt, and crc in base64:", file=sys.stderr)

# salt_privkey[8:32] now consists of:
#   8 bytes of salt, followed by
#   1 16-byte encrypted aes block containing the first 16 base58 chars of a 52-char encoded private key

bytes = b"mb:" + salt_privkey[8:32]
crc_bytes = struct.pack("<I", zlib.crc32(bytes) & 0xffffffff)

print(base64.b64encode(bytes + crc_bytes))
