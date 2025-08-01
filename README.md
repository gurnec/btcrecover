# *btcrecover* [![Build Status](https://travis-ci.org/gurnec/btcrecover.svg?branch=master)](https://travis-ci.org/gurnec/btcrecover) ![license](https://img.shields.io/badge/license-GPLv2-blue.svg) #

*btcrecover* is an open source Bitcoin wallet password and seed recovery tool. It is designed for the case where you already know most of your password or seed, but need assistance in trying different possible combinations.

If you find *btcrecover* helpful, please consider a small donation:
**[3Au8ZodNHPei7MQiSVAWb7NB2yqsb48GW4](bitcoin:3Au8ZodNHPei7MQiSVAWb7NB2yqsb48GW4?label=btcrecover)**

**Thank You!**

## Quick Start ##

This guide will help you get started with `btcrecover`.

### Installation ###

1.  Download the latest version from [here](https://github.com/gurnec/btcrecover/archive/master.zip).
2.  Unzip the downloaded file.
3.  Install the required Python libraries.

**Windows:**

Open a command prompt window, and type this to install the required Python libraries:

```
C:\Python27\Scripts\pip install coincurve==5.2.0 pysha3
```

**Linux:**

Most distributions include Python 2.7 pre-installed. Two additional Python libraries, coincurve and (for Ethereum wallets) pysha3 are required. For example on Debian-like distributions (including Ubuntu), open a terminal window and type this:

```
sudo apt-get install python-pip
sudo pip install coincurve==5.2.0 pysha3
```

**OS X:**

1.  Follow the instructions [here](docs/INSTALL.md#os-x) to download and install the latest version of Python 2.7.
2.  Open a terminal window (open the Launchpad and search for "terminal"). Type this and then choose `Install` to install the command line developer tools:

    ```
    xcode-select --install
    ```
3.  Type this to install the GNU Multiple Precision Arithmetic Library:

    ```
    curl -O https://gmplib.org/download/gmp/gmp-6.1.2.tar.xz
    tar xf gmp-6.1.2.tar.xz
    cd gmp-6.1.2
    ./configure --prefix=/usr/local/opt/gmp
    make && make check
    sudo make install
    cd ..
    rm -rf gmp-6.1.2 gmp-6.1.2.tar.xz
    ```
4.  Type this to install coincurve and (for Ethereum wallets) pysha3:

    ```
    sudo pip install coincurve==5.2.0 pysha3
    ```

### Running the GUI ###

The easiest way to use `btcrecover` is with the graphical user interface (GUI).

1.  Double-click the `main-gui.py` file to launch the main GUI.
2.  Click "Recover Password" to launch the password recovery GUI, or "Recover Seed" to launch the seed recovery GUI.

**Password Recovery:**

1.  Select your encrypted wallet file.
2.  Select a password list or a token list.
3.  (Optional) Adjust the typo and thread settings.
4.  Click "Start Recovery" to begin.

**Seed Recovery:**

1.  Select the wallet type.
2.  Fill in the required information for the selected wallet type.
3.  Enter your best guess for the mnemonic seed phrase.
4.  (Optional) Adjust the typo and thread settings.
5.  Click "Start Recovery" to begin.

## Features ##

 * Bitcoin wallet password recovery support for:
     * [Armory](https://btcarmory.com/)
     * [Bitcoin Unlimited](https://www.bitcoinunlimited.info/)/[Classic](https://bitcoinclassic.com/)/[XT](https://bitcoinxt.software/)/[Core](https://bitcoincore.org/)
     * [MultiBit HD](https://multibit.org/) and [MultiBit Classic](https://multibit.org/help/v0.5/help_contents.html)
     * [Electrum](https://electrum.org/) (1.x and 2.x)
     * Most wallets based on [bitcoinj](https://bitcoinj.github.io/), including [Hive for OS X](https://github.com/hivewallet/hive-mac/wiki/FAQ)
     * BIP-39 passphrases, Bitcoin & Ethereum supported (e.g. [TREZOR](https://www.bitcointrezor.com/) & [Ledger](https://www.ledgerwallet.com/) passphrases)
     * [mSIGNA (CoinVault)](https://ciphrex.com/products/)
     * [Blockchain.info](https://blockchain.info/wallet)
     * [pywallet --dumpwallet](https://github.com/jackjack-jj/pywallet) of Bitcoin Unlimited/Classic/XT/Core wallets
     * [Bitcoin Wallet for Android/BlackBerry](https://play.google.com/store/apps/details?id=de.schildbach.wallet) spending PINs and encrypted backups
     * [KnC Wallet for Android](https://github.com/kncgroup/bitcoin-wallet) encrypted backups
     * [Bither](https://bither.net/)
 * Altcoin password support for most wallets derived from one of those above, including:
     * [Litecoin Core](https://litecoin.org/)
     * [Electrum-LTC](https://electrum-ltc.org/)
     * [Litecoin Wallet for Android](https://litecoin.org/) encrypted backups
     * [Dogecoin Core](http://dogecoin.com/)
     * [MultiDoge](http://multidoge.org/)
     * [Dogecoin Wallet for Android](http://dogecoin.com/) encrypted backups
 * Bitcoin & Ethereum seed recovery support for:
     * [Electrum](https://electrum.org/) (1.x and 2.x, plus wallet file loading support)
     * BIP-32/39 compliant wallets ([bitcoinj](https://bitcoinj.github.io/)), including:
         * [MultiBit HD](https://multibit.org/)
         * [Bitcoin Wallet for Android/BlackBerry](https://play.google.com/store/apps/details?id=de.schildbach.wallet) (with seeds previously extracted by [decrypt\_bitcoinj\_seeds](https://github.com/gurnec/decrypt_bitcoinj_seed))
         * [Hive for Android](https://play.google.com/store/apps/details?id=com.hivewallet.hive.cordova), [for iOS](https://github.com/hivewallet/hive-ios), and [Hive Web](https://hivewallet.com/)
         * [breadwallet for iOS](https://breadwallet.com/)
     * BIP-32/39/44 Bitcoin & Ethereum compliant wallets, including:
         * [Mycelium for Android](https://wallet.mycelium.com/)
         * [TREZOR](https://www.bitcointrezor.com/)
         * [Ledger](https://www.ledgerwallet.com/)
         * [Jaxx](https://jaxx.io/)
         * [MyEtherWallet](https://www.myetherwallet.com/)
         * [Bither](https://bither.net/)
         * [Blockchain.info](https://blockchain.info/wallet)
 * [Free and Open Source](http://en.wikipedia.org/wiki/Free_and_open-source_software) - anyone can download, inspect, use, and redistribute this software
 * Supported on Windows, Linux, and OS X
 * Graphical User Interface for both password and seed recovery
 * Support for Unicode passwords and seeds
 * Multithreaded searches, with user-selectable thread count
 * Experimental [GPU acceleration](docs/GPU_Acceleration.md) for Bitcoin Unlimited/Classic/XT/Core, Armory, and derived altcoin wallets
 * Wildcard expansion for passwords
 * Typo simulation for passwords and seeds
 * Progress bar and ETA display (at the command line)
 * Optional autosave - interrupt and continue password recoveries without losing progress
 * “Offline” mode for nearly all supported wallets - use one of the [extract scripts (click for more information)](docs/Extract_Scripts.md) to extract just enough information to attempt password recovery, without giving *btcrecover* or whoever runs it access to *any* of the addresses or private keys in your Bitcoin wallet.
 * “Nearly offline” mode for Armory - use an [extract script (click for more information)](docs/Extract_Scripts.md) to extract a single private key for attempting password recovery. *btcrecover* and whoever runs it will only have access to this one address/private key from your Bitcoin wallet (read the link above for an important caveat).

## Advanced Usage ##

For more advanced usage, you can run `btcrecover` from the command line. This allows you to use more advanced features such as token files and typos.

### The Token File ###

*btcrecover* can accept as input a text file which has a list of what are called password “tokens”. A token is simply a portion of a password which you do remember, even if you don't remember where that portion appears in the actual password. It will combine these tokens in different ways to create different whole password guesses to try.

For more information on how to use token files, please see the [Token File Tutorial](TUTORIAL.md#the-token-file).

### Typos ###

*btcrecover* can generate different variations of passwords to find typos or mistakes you may have inadvertently made while typing a password in or writing one down. This feature is enabled by including one or more command-line options when you run *btcrecover*.

For more information on how to use typos, please see the [Typos Tutorial](T.md#typos).

## Limitations & Caveats ##

Please see the separate [Limitations and Caveats](docs/Limitations_and_Caveats.md) documentation for additional details on these topics:

 * Delimiters, Spaces, and Special Symbols in Passwords
 * Memory & CPU Usage
 * Security Issues
 * Typos Details

## Copyright and License ##

btcrecover -- Bitcoin wallet password and seed recovery tool

Copyright (C) 2014-2017 Christopher Gurnee

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program.  If not, see http://www.gnu.org/licenses/
