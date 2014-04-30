# *btcrecover* #

## *extract-mkey.py* ##

Sometimes, it is not desirable to run *btcrecover* directly on the computer which stores the target wallet file. For example:

 * A computer or a cloud-based virtual machine with faster CPUs might be a better place to run *btcrecover*.
 * Configuring *btcrecover* to search for your password correctly can be tricky; you might be interested in finding someone who can configure and run *btcrecover* for you on their computer.
 * You may not trust that *btcrecover* is free from harmful bugs or other malicious behavior. *btcrecover* is open source, and requires no untrustworthy binaries be installed. However it's also a fairly long and complicated Python script, which makes it difficult even for other Python programmers to be certain that it doesn't contain any harmful code (either intentionally malicious or just by accident).

*extract-mkey.py* is a relatively short and simple script which extracts just enough information from a Bitcoin Core or Litecoin-Qt wallet file to be useful to *btcrecover* in a password search, but it doesn't extract enough information to put any of your funds at risk.

For more information regarding *btcrecover*, please see [TUTORIAL.md](../TUTORIAL.md).

### Download ###

You can download the entire *btcrecover* package from: <https://github.com/gurnec/btcrecover/archive/master.zip>

If you'd prefer to download only the *extract-mkey.py* script, please right click on the following link and choose “Save link as...” or “Save target as...”: <https://github.com/gurnec/btcrecover/raw/master/extract-mkey/extract-mkey.py>

If you're on Windows, you will also need to install the latest version of Python 2.7, either the 32-bit version or the 64-bit version. Currently this is the “Python 2.7.6 Windows Installer” for the 32-bit version, or “Python 2.7.6 Windows X86-64 Installer” for the 64-bit version (which is preferable if you have a 64-bit version of Windows), both available here: <https://www.python.org/download/>


### Usage ###

After downloading the script, **make a copy of your wallet.dat file into a different folder** (to make it easy, into the same folder as *extract-mkey.py*). As an example for Windows, click on the Start Menu, then click “Run...”, and then type this to open your Bitcoin folder which contains your wallet.dat file: `%appdata%\Bitcoin`. From here you can copy and paste your wallet.dat file into a separate folder. Next you'll need to open a Command Prompt window and type something like this (depending on where the downloaded script is, and assuming you've made a copy of your wallet.dat into the same folder):

    cd \Users\Chris\Downloads\btcrecover-master\extract-mkey
    C:\python27\python extract-mkey.py wallet.dat

You should get a message which looks like this as a result:

    Bitcoin Core encrypted master key, salt, iter_count, and crc in base64:
    lV/wGO5oAUM42KTfq5s3egX3Uhk6gc5gEf1R3TppgzWNW7NGZQF5t5U3Ik0qYs5/dprb+ifLDHuGNQIA+8oRWA==

When you (or someone else) runs *btcrecover* to search for passwords, you will not need your wallet file, only the output from *extract-mkey.py*. To continue the example:

    cd \Users\Chris\Downloads\btcrecover-master
    C:\python27\python btcrecover.py --mkey --tokenlist tokens.txt
    Please enter the Bitcoin Core encrypted master key from extract-mkey.py
    > lV/wGO5oAUM42KTfq5s3egX3Uhk6gc5gEf1R3TppgzWNW7NGZQF5t5U3Ik0qYs5/dprb+ifLDHuGNQIA+8oRWA==
    ...
    Password found: xxx

### Technical Details ###

The *extract-mkey.py* script is intentionally short and should be easy to read for any Python programmer. It opens a wallet.dat file using the Python bsddb.db library (the Berkeley DB library which comes with Python 2.7), and then extracts a single key/value pair with the key string of `\x04mkey\x01\x00\x00\x00`. This key/value pair contains an encrypted version of the Bitcoin Core “master key”, or mkey for short, along with some other information required to try decrypting the mkey, specifically the mkey salt and iteration count. This information is then converted to base64 format for easy copy/paste, and printed to the screen.

The encrypted mkey is useful to *btcrecover*, but it does not contain any of your Bitcoin address or private key information. *btcrecover* can attempt to decrypt the mkey by trying different password combinations. Should it succeed, it and whoever runs it will then know the password to your wallet file, but without the rest of your wallet file, the password and the decrypted mkey are of no use.


### Limitations ###

*extract-mkey.py* only works with Bitcoin Core (a.k.a. Bitcoin-QT) and Litecoin-Qt wallet files. For Armory and MultiBit wallets, please refer to the [extract-privkey scripts](../extract-privkey/README.md).
