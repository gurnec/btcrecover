#!/usr/bin/python

# extract-multibit-privkey.py -- MultiBit private key extractor
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

import sys, os.path, base64, zlib, struct

prog = os.path.basename(sys.argv[0])

if len(sys.argv) != 2 or sys.argv[1].startswith("-"):
    print("usage: "+prog+" MULTIBIT_PRIVATE_KEY_FILE")
    sys.exit(2)

privkey_filename = sys.argv[1]

with open(privkey_filename, "rb") as privkey_file:

    # Multibit privkey files contain base64 text split into multiple lines;
    # we need the first 80 bytes after decoding, which translates to 108 before.
    base64_encoded = "".join(privkey_file.read(120).split())  # join multiple lines into one
    if len(base64_encoded) < 108:
        print(prog+": error: file is not a MultiBit private key file (too short)")
        sys.exit(1)
    try: salt_privkey = base64.b64decode(base64_encoded[:108])
    except:
        print(prog+": error: file is not a MultiBit private key file (not base64 encoded)")
        sys.exit(1)
    if not salt_privkey.startswith("Salted__"):
        print(prog+": error: file is not a MultiBit private key file")
        sys.exit(1)
    if len(salt_privkey) < 80:
        print(prog+": error: file is not a MultiBit private key file (too short)")
        sys.exit(1)


print("\n" +
      "WARNING: once decrypted, this will provide access to all Bitcoin\n"    +
      "         funds currently available in your first MultiBit address\n\n" +
      "MultiBit first encrypted private key, salt, and crc in base64:")

# salt_privkey[8:80] now consists of:
#   8 bytes of salt, followed by
#   4 16-byte encrypted aes blocks containing a 52-byte base58 encoded private key

bytes = "mb:" + salt_privkey[8:80]
crc_bytes = struct.pack("<I", zlib.crc32(bytes) & 0xffffffff)

print(base64.b64encode(bytes + crc_bytes))
