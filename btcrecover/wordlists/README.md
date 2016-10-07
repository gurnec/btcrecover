## *seedrecover* wordlists ##

All wordlists used by *seedrecover.py* are sourced from third parties. In particular:

 * BIP-39 wordlists can be found here: <https://github.com/bitcoin/bips/blob/master/bip-0039/bip-0039-wordlists.md>
 * Electrum 2 wordlists can be found here: <https://github.com/spesmilo/electrum/tree/master/lib/wordlist>

The wordlist files themselves were copied verbatim from the sources above, including any copyright notices. Only the filenames have been modified.


### Language Codes ###

*seedrecover.py* attempts to guess the correct language of the mnemonic it is trying to recover, however it may not always guess correctly (in particular when it comes to Chinese). You can instruct *seedrecover.py* to use a specific language via the `--language LANG-CODE` option.

The available `LANG-CODE`s are taken from the filenames in the same directory as this file; they follow the first `-` in their filenames. Specifically, in alphabetical order they are:

 * Chinese (simplified) (BIP-39 only) - `zh-hans`
 * Chinese (traditional) (BIP-39 only) - `zh-hant`
 * English - `en`
 * French (Electrum 2.x only) - `fr`
 * Japanese - `ja`
 * Portuguese (Electrum 2.x only) - `pt` 
 * Spanish - `es`
