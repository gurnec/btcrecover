#!/bin/bash

set -e

LATEST="https://github.com/goatpig/BitcoinArmory/releases/download/v0.94.1/armory_0.94.1_amd64.deb"

curl -LfsS --retry 10 -o '/tmp/armory.deb' "$LATEST"

sudo apt-get -q update
sudo apt-get -yq install gdebi-core

sudo gdebi -nq /tmp/armory.deb
rm /tmp/armory.deb
