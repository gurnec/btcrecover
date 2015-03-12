#!/bin/bash

set -e

DOWNLOADS="`curl -fsS --retry 10 https://s3.amazonaws.com/bitcoinarmory-media/announce.txt | awk '/^downloads/{print $2}'`"
echo "$DOWNLOADS" | grep -q '^https://' || { echo "Can't find Armory downloads URL"; exit 1; }

uname -m | grep -q '64$' && BITS=64 || BITS=32
LATEST="`curl -fsS --retry 10 \"$DOWNLOADS\" | grep \"^Armory [0-9.]* Ubuntu [0-9.,]*\`lsb_release -rs\`[0-9.,]* $BITS \" | sort -k 2V | tail -1 | awk '{print $6}'`"
echo "$LATEST" | grep -q '^https://' || { echo "Can't find latest Armory download URL"; exit 1; }

curl -fsS --retry 10 -o '/tmp/armory.deb' "$LATEST"

sudo apt-get -q update
sudo apt-get -yq install dpkg-sig gdebi-core

gpg -q --keyserver keyserver.ubuntu.com --recv-keys 98832223
dpkg-sig --verify /tmp/armory.deb | grep -q 'GOODSIG.*821F122936BDD565366AC36A4AB16AEA98832223' || { echo "Signature verification failed"; exit 1; }

sudo gdebi -nq /tmp/armory.deb
rm /tmp/armory.deb
