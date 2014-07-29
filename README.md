# *btcrecover* [![Build Status](https://travis-ci.org/gurnec/btcrecover.svg?branch=master)](https://travis-ci.org/gurnec/btcrecover) #

*btcrecover* is an open source Bitcoin wallet password recovery tool. It is designed for the case where you already know most of your password, but need assistance in trying different possible combinations.

## Features ##

 * Bitcoin wallet support for:
     * [Armory](https://bitcoinarmory.com/)
     * [Bitcoin Core (Bitcoin-Qt)](https://bitcoinarmory.com/download/)
     * [MultiBit](https://multibit.org/)
     * [Electrum](https://electrum.org/)
     * [Blockchain](https://blockchain.info/wallet)
     * [pywallet --dumpwallet](https://github.com/jackjack-jj/pywallet) of Bitcoin Core wallets
 * Litecoin wallet support for:
     * [Litecoin-Qt](https://litecoin.org/)
 * [Free and Open Source](http://en.wikipedia.org/wiki/Free_and_open-source_software) - anyone can download, inspect, use, and redistribute this software
 * Supported on Windows, Linux, and OS X
 * Options to help minimize the search space - the more you remember about your password, the less time it will take to find
 * Multithreaded searches, with user-selectable thread count
 * Experimental GPU acceleration for Bitcoin Core, Armory, and Litecoin-Qt wallets
 * Wildcard expansion
 * Typo simulation
 * Progress bar and ETA display (at the command line)
 * Interrupt and Continue searches without losing progress
 * Optional autosave - continue searches even after inadvertent interruptions or crashes
 * “Offline” mode for Bitcoin Core, MultiBit, Electrum, Blockchain, and Litecoin-Qt wallets - use one of the [extract scripts (click for more information)](extract-scripts/README.md) to extract just enough information to attempt password recovery, without giving *btcrecover* or whoever runs it access to *any* of the addresses or private keys in your Bitcoin wallet.
 * “Nearly offline” mode for Armory - use an [extract script (click for more information)](extract-scripts/README.md) to extract a single private key for attempting password recovery. *btcrecover* and whoever runs it will only have access to this one address/private key from your Bitcoin wallet.

----------

**Please see [TUTORIAL.md](TUTORIAL.md) for more information, including installation instructions and requirements.**

If you find *btcrecover* helpful, please consider a small donation:
**[17LGpN2z62zp7RS825jXwYtE7zZ19Mxxu8](bitcoin:17LGpN2z62zp7RS825jXwYtE7zZ19Mxxu8?label=btcrecover)**

#### Thank You! ####
