# BTCRecover
[![Build Status](https://travis-ci.org/3rdIteration/btcrecover.svg?branch=master)](https://travis-ci.org/3rdIteration/btcrecover) ![license](https://img.shields.io/badge/license-GPLv2-blue.svg)

> **Note:** You are viewing the `README` for an older, unmaintained version of BTCRecover. The project has been significantly updated and is actively maintained by the community. For the latest version, more features, and up-to-date documentation, please visit:
>
> - **Active GitHub Repository:** [github.com/3rdIteration/btcrecover](https://github.com/3rdIteration/btcrecover)
> - **Modern Documentation:** [btcrecover.readthedocs.io](https://btcrecover.readthedocs.io/en/latest/)

An open-source wallet password and seed recovery toolkit for Bitcoin and compatible wallets. BTCRecover is designed for scenarios where you know most of your password or mnemonic, but need assistance trying likely combinations, fixing typos, or filling in missing words. It supports a GUI for simplicity and a CLI for power users, with multithreading, optional autosave, and “offline” extraction modes to minimize risk to your wallet data. See also the documentation site for features and guides: [btcrecover.readthedocs.io](https://btcrecover.readthedocs.io/en/latest/).

If you find BTCRecover helpful, please consider a small donation:
3Au8ZodNHPei7MQiSVAWb7NB2yqsb48GW4

Thank you!

Highlights
- Password and seed recovery for many Bitcoin and Ethereum-compatible wallets
- GUI and CLI workflows
- Multithreaded search with ETA
- Typo simulation and wildcard/token-based generation
- Optional autosave and resumable sessions
- “Offline” and “nearly offline” extract modes to protect keys
- Experimental GPU acceleration for specific wallets

For an at-a-glance feature overview and GPU notes, see the docs at [btcrecover.readthedocs.io](https://btcrecover.readthedocs.io/en/latest/) and the active repository at [github.com/3rdIteration/btcrecover](https://github.com/3rdIteration/btcrecover).

Security First
- Always work on copies of wallet files, never the originals.
- Use “offline” extraction where available to avoid exposing private keys.
- Run locally on a trusted machine; do not share seeds/passwords.
- Review Limitations & Caveats before large runs.

Quick Start & Installation

For the most up-to-date and user-friendly installation instructions, please see the **[Installation Guide on btcrecover.readthedocs.io](https://btcrecover.readthedocs.io/en/latest/INSTALL/)**.

The documentation on the official site covers installation on Windows, Linux, and macOS, and includes details for setting up GPU acceleration. The instructions in this `README` are outdated and have been removed to avoid confusion.

Using the GUI

1) Double-click main-gui.py to launch the main interface.
2) Choose “Recover Password” or “Recover Seed”.

Password Recovery (GUI)
1) Select your encrypted wallet file.
2) Choose a password list or a token file (see Token Files below).
3) Optionally adjust typo settings and thread count.
4) Click “Start Recovery”.

Seed Recovery (GUI)
1) Select wallet type.
2) Provide required details for the chosen wallet.
3) Enter your best-guess mnemonic (you can leave blanks for unknown words if supported).
4) Optionally adjust typo settings and thread count.
5) Click “Start Recovery”.

Command Line (Advanced)

The CLI enables advanced composition strategies, token files, typos, and scripting. Refer to the tutorials for structured token files and typo generation. For a comprehensive guide, including GPU usage and extract scripts, see [btcrecover.readthedocs.io](https://btcrecover.readthedocs.io/en/latest/) and the active repo at [github.com/3rdIteration/btcrecover](https://github.com/3rdIteration/btcrecover).

Token Files

Token files list fragments (“tokens”) you remember—names, years, symbols—without knowing exact order or placement. BTCRecover systematically combines tokens with rules to generate candidates.

Start with the Token File Tutorial:
- Upstream tutorial: TUTORIAL.md#the-token-file (in this repository)
- Additional examples and hints: [btcrecover.readthedocs.io](https://btcrecover.readthedocs.io/en/latest/) and the active repo [github.com/3rdIteration/btcrecover](https://github.com/3rdIteration/btcrecover)

Typos

BTCRecover can simulate common mistakes: swapped characters, case shifts, adjacent-key errors, missing characters, and more. Enable via CLI options or GUI settings.

See the Typos Tutorial:
- Upstream tutorial: T.md#typos (in this repository)
- Extended notes: [btcrecover.readthedocs.io](https://btcrecover.readthedocs.io/en/latest/)

Features

Password recovery support for:
- Armory
- Bitcoin Core/Unlimited/Classic/XT
- MultiBit HD and MultiBit Classic
- Electrum (1.x, 2.x)
- bitcoinj-based wallets (e.g., Hive)
- BIP-39 passphrases (Bitcoin & Ethereum; e.g., Trezor, Ledger)
- mSIGNA (CoinVault)
- Blockchain.com (formerly blockchain.info) wallet
- pywallet --dumpwallet of Core/Unlimited/Classic/XT
- Bitcoin Wallet for Android/BlackBerry spending PINs and encrypted backups
- KnC Wallet for Android encrypted backups
- Bither
- Many altcoin derivatives (Litecoin Core, Electrum-LTC, Dogecoin Core, MultiDoge, Android variants)

Seed recovery support for:
- Electrum (1.x, 2.x; includes wallet file loading)
- BIP-32/39 compliant bitcoinj wallets:
  - MultiBit HD
  - Bitcoin Wallet for Android/BlackBerry (with seeds extracted by decrypt_bitcoinj_seed)
  - Hive (Android, iOS, Web)
  - breadwallet for iOS
- BIP-32/39/44 compliant wallets, including:
  - Mycelium (Android)
  - Trezor
  - Ledger
  - Jaxx
  - MyEtherWallet
  - Bither
  - Blockchain.com

Core capabilities:
- GUI for both password and seed recovery
- CLI with powerful token and typo frameworks
- Multithreaded search, user-selectable threads
- Typo simulation and wildcard expansion
- Progress bar and ETA on CLI
- Optional autosave for resumable sessions
- “Offline” mode: use extract scripts to limit data exposure
- “Nearly offline” mode for Armory (single-key extraction)
- Experimental GPU acceleration for specific wallets

For a current feature matrix, GPU support notes, and multi-device/GPU usage see [btcrecover.readthedocs.io](https://btcrecover.readthedocs.io/en/latest/) which highlights GPU acceleration options and distributed workloads.

Offline/Extract Scripts

Minimize risk by extracting only the data needed for recovery. Most supported wallets can use “offline” mode via extract scripts so BTCRecover never sees private keys or addresses. Armory supports a “nearly offline” mode with a single private key extraction.

See:
- Extract Scripts documentation in this repo (docs/Extract_Scripts.md)
- Additional guidance and “offline mode” overview at [github.com/3rdIteration/btcrecover](https://github.com/3rdIteration/btcrecover) and [btcrecover.readthedocs.io](https://btcrecover.readthedocs.io/en/latest/)

GPU Acceleration

BTCRecover offers experimental GPU acceleration for select wallets (e.g., Bitcoin Core family, Armory, and derivatives). GPU support, setup instructions, and caveats vary by platform. Consult:
- GPU Acceleration doc: docs/GPU_Acceleration.md
- Reference docs at [btcrecover.readthedocs.io](https://btcrecover.readthedocs.io/en/latest/)

Troubleshooting

- Dependencies fail to build: ensure compiler toolchain installed (Windows Build Tools, Xcode CLT on macOS, build-essential on Linux) and GMP as required for coincurve.
- Slow performance: reduce typo depth, refine tokens, use targeted masks, increase threads, or consider GPU where supported.
- Wallet not listed: many altcoins derived from Core/Electrum/bitcoinj may work. Check the docs and issues in the active fork: [github.com/3rdIteration/btcrecover](https://github.com/3rdIteration/btcrecover).
- Safety: always use copies of wallet files; prefer offline extraction.

Limitations & Caveats

Please review docs/Limitations_and_Caveats.md for important notes on:
- Delimiters, spaces, and special symbols
- Memory and CPU usage
- Security considerations
- Typo behavior details

For more detailed, continuously updated caveats and usage notes, see [btcrecover.readthedocs.io](https://btcrecover.readthedocs.io/en/latest/).

Contributing and Community

- Issues and PRs are welcome. Please include environment details, wallet type, and minimal repro steps.
- For broader community guidance, examples, and extended forks, explore:
  - Active fork and enhancements: [github.com/3rdIteration/btcrecover](https://github.com/3rdIteration/btcrecover)
  - Project docs: [btcrecover.readthedocs.io](https://btcrecover.readthedocs.io/en/latest/)

License

BTCRecover — Bitcoin wallet password and seed recovery tool

Copyright (C) 2014–2017 Christopher Gurnee

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License version 2 or (at your option) any later version, as published by the Free Software Foundation.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see http://www.gnu.org/licenses/

References and Further Reading
- Official docs and how-tos: [btcrecover.readthedocs.io](https://btcrecover.readthedocs.io/en/latest/)
- Maintained fork with additional features: [github.com/3rdIteration/btcrecover](https://github.com/3rdIteration/btcrecover)

------------------------------------------------------------

Notes on sources:
- The project overview, GPU acceleration mention, GUI, autosave/resume, and offline extract modes are documented at [btcrecover.readthedocs.io](https://btcrecover.readthedocs.io/en/latest/).
- The active fork and modern usage patterns are often referenced at [github.com/3rdIteration/btcrecover](https://github.com/3rdIteration/btcrecover).
