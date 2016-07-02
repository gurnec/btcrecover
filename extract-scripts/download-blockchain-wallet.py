#!/usr/bin/python

# download-blockchain-wallet.py -- Blockchain wallet file downloader
# Copyright (C) 2016 Christopher Gurnee
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
import sys, os.path, urllib2, json

# The base URL
URL = "https://blockchain.info/wallet"

prog = os.path.basename(sys.argv[0])

if len(sys.argv) < 2:
    filename = "wallet.aes.json"
elif len(sys.argv) == 2 and not sys.argv[1].startswith("-"):
    filename = sys.argv[1]
else:
    print("usage:", prog, "[NEW_BLOCKCHAIN_WALLET_FILE]", file=sys.stderr)
    sys.exit(2)

# Refuse to overwrite an existing file
assert not os.path.exists(filename), filename + " already exists, won't overwrite"

print("Please enter your wallet's ID (e.g. 9bb4c672-563e-4806-9012-a3e8f86a0eca)")
wallet_id = raw_input("> ")

# Create the cookie-saving web browser object
browser = urllib2.build_opener(urllib2.HTTPCookieProcessor())

# Keep trying to download the wallet until we pass
# the IP address / email verification step (if any)
wallet_data = 0
while wallet_data == 0:
    try:
        wallet_data = json.load(
            browser.open(URL + "/{}?format=json".format(wallet_id))
        ).get("payload")

    except urllib2.HTTPError as e:
        error_msg = e.read()
        try:
            error_msg = json.loads(error_msg)["initial_error"]
        except: pass
        raw_input(error_msg + "\n\nPress enter to try again...")

# If the loop above exits (there's no HTTP error),
# but there was no payload data, then 2FA is enabled
while not wallet_data:

    print("This wallet has two-factor authentication enabled, please enter your 2FA code")
    two_factor = raw_input("> ")

    try:
        # Send the 2FA to the server and download the wallet
        wallet_data = browser.open(
            URL, "method=get-wallet&guid={}&payload={}&length={}"
            .format(wallet_id, two_factor, len(two_factor))
        ).read()

    except urllib2.HTTPError as e:
        print(e.read() + "\n", file=sys.stderr)

# Save the wallet
with open(filename, "wb") as wallet_file:
    wallet_file.write(wallet_data)

print("Wallet file saved as " + filename)
