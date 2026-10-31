#!/usr/bin/env python

# download-blockchain-wallet.py -- Blockchain.info wallet file downloader
# Copyright (C) 2016, 2017 Christopher Gurnee
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
import sys, os.path, atexit, uuid, urllib2, json, time

# The base URL
BASE_URL = "https://blockchain.info/"
# The api_code (as of Feb 2 2017)
API_CODE = "1770d5d9-bcea-4d28-ad21-6cbd5be018a8"

prog = os.path.basename(sys.argv[0])

if len(sys.argv) < 2:
    atexit.register(lambda: raw_input("\nPress Enter to exit ..."))
    filename = "wallet.aes.json"
elif len(sys.argv) == 2 and not sys.argv[1].startswith("-"):
    filename = sys.argv[1]
else:
    print("usage:", prog, "[NEW_BLOCKCHAIN_WALLET_FILE]", file=sys.stderr)
    sys.exit(2)

# Refuse to overwrite an existing file
assert not os.path.exists(filename), filename + " already exists, won't overwrite"

print("Please enter your wallet's ID (e.g. 9bb4c672-563e-4806-9012-a3e8f86a0eca)")
wallet_id = str(uuid.UUID(raw_input("> ").strip()))


# Performs a web request, adding the api_code and (if available) auth_token
auth_token = None
def do_request(query, body = None):
    if body is None:
        assert "?" in query
        query += "&api_code=" + API_CODE
    req = urllib2.Request(BASE_URL + query)
    if body is not None:
        req.add_data((body+"&" if body else "") + "api_code=" + API_CODE)
    if auth_token:
        req.add_header("authorization", "Bearer " + auth_token)
    try:
        return urllib2.urlopen(req, cadefault=True)  # calls ssl.create_default_context() (despite what the docs say)
    except TypeError:
        return urllib2.urlopen(req)  # Python < 2.7.9 doesn't support the cadefault argument
#
# Performs a do_request(), decoding the result as json
def do_request_json(query, body = None):
    return json.load(do_request(query, body))


# Get an auth_token
auth_token = do_request_json("sessions", "")["token"]  # a POST request

# Try to download the wallet
try:
    wallet_data = do_request_json(
        "wallet/{}?format=json".format(wallet_id)
    ).get("payload")

# If IP address / email verification is required
except urllib2.HTTPError as e:
    error_msg = e.read()
    try:
        error_msg = json.loads(error_msg)["initial_error"]
    except: pass
    print(error_msg)
    if error_msg.lower().startswith("unknown wallet identifier"):
        sys.exit(1)

    # Wait for the user to complete the requested authorization
    time.sleep(5)
    print("Waiting for authorization (press Ctrl-C to give up)...")
    while True:
        poll_data = do_request_json("wallet/poll-for-session-guid?format=json")
        if "guid" in poll_data:
            break
        time.sleep(5)
    print()

    # Try again to download the wallet (this shouldn't fail)
    wallet_data = do_request_json(
        "wallet/{}?format=json".format(wallet_id)
    ).get("payload")

# If there was no payload data, then 2FA is enabled
while not wallet_data:

    print("This wallet has two-factor authentication enabled, please enter your 2FA code")
    two_factor = raw_input("> ").strip()

    try:
        # Send the 2FA to the server and download the wallet
        wallet_data = do_request("wallet",
            "method=get-wallet&guid={}&payload={}&length={}"
            .format(wallet_id, two_factor, len(two_factor))
        ).read()

    except urllib2.HTTPError as e:
        print(e.read() + "\n", file=sys.stderr)

# Save the wallet
with open(filename, "wb") as wallet_file:
    wallet_file.write(wallet_data)

print("Wallet file saved as " + filename)
