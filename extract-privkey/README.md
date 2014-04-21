# *btcrecover* #

## extract-privkey scripts ##

Sometimes, it is not desirable to run *btcrecover* directly on the computer which stores the target wallet file. For example:

 * A computer or a cloud-based virtual machine with faster CPUs might be a better place to run *btcrecover*.
 * Configuring *btcrecover* to search for your password correctly can be tricky; you might be interested in finding someone who can configure and run *btcrecover* for you on their computer.
 * You may not trust that *btcrecover* is free from harmful bugs or other malicious behavior. *btcrecover* is open source, and requires no untrustworthy binaries be installed. However it's also a fairly long and complicated Python script, which makes it difficult even for other Python programmers to be certain that it doesn't contain any harmful code (either intentionally malicious or just by accident).

*extract-armory-privkey.py* and *extract-multibit-privkey.py* are relatively short and simple scripts which extract a single encrypted private key (or for MultiBit, just a fraction of a private key) associated with a single Bitcoin address from a wallet. *btcrecover* can then operate on this single key, and once decrypted, only the Bitcoin funds associated with this one address could ever be at risk. The rest of your keys remain safely in your wallet.

### Download ###

You can download the entire *btcrecover* package from: <https://github.com/gurnec/btcrecover/archive/master.zip>

If you'd prefer to download just a single extract script, please select the one for your wallet software from below, then right click and choose “Save link as...” or “Save target as...”:

 * Armory - <https://github.com/gurnec/btcrecover/blob/master/extract-privkey/extract-armory-privkey.py>
 * MultiBit - <https://github.com/gurnec/btcrecover/blob/master/extract-privkey/extract-multibit-privkey.py>

If you're on Windows, you will also need to install the latest version of Python 2.7. For Armory wallets, you must install the 32-bit version. For MultiBit, you may install either the 32-bit or the 64-bit version. Currently this is the “Python 2.7.6 Windows Installer” for the 32-bit version, or the “Python 2.7.6 Windows X86-64 Installer” for the 64-bit version, both available here: <https://www.python.org/download/>. For Armory wallets, you must also have Armory v0.91 or later installed.


### Usage for Armory ###

Open Armory (in offline mode if you like), and take note of the wallet ID whose password you've lost. Open this wallet, and click Receive Bitcoins to display a new Bitcoin address. Add a label to the address, such as "Recovery address - DO NOT USE", and copy the Bitcoin address to someplace temporary (a Notepad document, a Post-It, or wherever). Quit Armory.

If you've ever used this wallet on more than one computer, the address you just created might already exist. It's up to you to find an unused and unpublished address for this procedure, and to never use this address in the future. You can check if the address has been used in the past at <https://blockchain.info/>, but you're the only one who might know if you've given this address out to someone else before today.

After downloading the script, **make a copy of your wallet file into a different folder** (to make it easy, into the same folder as the extract script). As an example for Windows, click on the Start Menu, then click “Run...”, and then type this to open your Armory folder which contains your wallet files: `%appdata%\Armory`. From here you can copy and paste the wallet file that matches the wallet ID you noted earlier into a separate folder. Next you'll need to open a Command Prompt window and type something like this (depending on where the downloaded script is, and assuming you've made a copy of your wallet file into the same folder):

    cd \Users\Chris\Downloads\btcrecover-master\extract-privkey
    C:\python27\python extract-armory-privkey.py armory_2dRkxw76K_.wallet extract 1LhkzLtY5drbUxXvsk8LmU1aRFz13EDcp4

Of course, you need to replace the wallet filename with yours, and the Bitcoin address with the one you created earlier. You should get a message which looks like this as a result. You should double-check that the address matches the one you just created (along with the label which you gave to it):

    1LhkzLtY5drbUxXvsk8LmU1aRFz13EDcp4 First:04/19/14 Last:04/19/14 Recovery address - DO NOT USE

    WARNING: once decrypted, this will provide access to all Bitcoin
             funds available now and in the future of this one address

    Armory address, encrypted private key, iv, kdf parameters, and crc in base64:
    YXI62B+/jb1Pthvjsrh+LlW5PS87FpfdBR3d5G1yWPY0cEUl3D+U2382qq0YkqoBDfnHDda/a3bOay/OKq9UWy/nra5SGyMAAEAAAgAAABiymPHbLR+L8tKm+wpnzDioxV+lMgAwB2SH0hpYvez8w5aWGQ==

When you (or someone else) runs *btcrecover* to search for passwords, you will not need your wallet file, only the output from *extract-armory-privkey.py*. To continue the example:

    cd \Users\Chris\Downloads\btcrecover-master
    C:\python27\python btcrecover.py --privkey --tokenlist tokens.txt
    WARNING: a complete private key, once decrypted, provides access to that key's Bitcoin
    Please enter the encrypted key data from the extract script
    > YXI62B+/jb1Pthvjsrh+LlW5PS87FpfdBR3d5G1yWPY0cEUl3D+U2382qq0YkqoBDfnHDda/a3bOay/OKq9UWy/nra5SGyMAAEAAAgAAABiymPHbLR+L8tKm+wpnzDioxV+lMgAwB2SH0hpYvez8w5aWGQ==
    ...
    Password found: xxx


### Usage for MultiBit ###

*extract-multibit-privkey.py* doesn’t operate directly on MultiBit wallet files, instead it operates on MultiBit private key backup files. Each time you change your wallet password (including the first time you add a password), plus on certain other occasions, MultiBit creates an encrypted private key backup file in a `key-backup` directory (see the link below for more details). These private key backup files are much faster to try passwords against (by a factor of over 1,000), which is why *btcrecover* uses them. Unfortunately, it’s up to you to locate the correct private key backup file for the wallet whose password you need to recover. If you only have one MultiBit wallet, you can just choose the most recent private key backup file. Otherwise, you need to locate a private key backup file that has a date of when you either changed the password of, or added new addresses to the wallet you’d like to recover.

For more details on locating your MultiBit private key backup files, see: <https://www.multibit.org/en/help/v0.5/help_fileDescriptions.html>

Once you've located the correct MultiBit private key backup file, **make a copy of it into a different folder** (to make it easy, into the same folder as the extract script). As an example for Windows, click on the Start Menu, then click “Run...”, and then type this to open the private key backup folder for the first wallet which MultiBit creates (this might not be the one you want, though...): `%appdata%\MultiBit\multibit-data\key-backup`. From here you can copy and paste a private key backup file into a separate folder. Next you'll need to open a Command Prompt window and type something like this (depending on where the downloaded script is, and assuming you've made a copy of the private key file into the same folder):

    cd \Users\Chris\Downloads\btcrecover-master\extract-privkey
    C:\python27\python extract-multibit-privkey.py multibit-20140407200743.key

Of course, you need to replace the private key filename with yours. You should get a message which looks like this as a result:

    MultiBit partial first encrypted private key, salt, and crc in base64:
    bWI6sTaHldcBFFj9zlgNpO1szOwy8elpl20OWgj+lA==

When you (or someone else) runs *btcrecover* to search for passwords, you will not need your wallet file or the private key file, only the output from *extract-armory-privkey.py*. To continue the example:

    cd \Users\Chris\Downloads\btcrecover-master
    C:\python27\python btcrecover.py --privkey --tokenlist tokens.txt
    WARNING: a complete private key, once decrypted, provides access to that key's Bitcoin
    Please enter the encrypted key data from the extract script
    > bWI6sTaHldcBFFj9zlgNpO1szOwy8elpl20OWgj+lA==
    ...
    Password found: xxx

#### MultiBit Technical Details ####

The *extract-multibit-privkey.py* script extracts the first 16 encrypted base58-encoded characters (out of 52) from the first private key from a MultiBit private key backup file. Because less than 30% of a single private key is extracted, the private key itself cannot be feasibly reconstructed even after these first 16 characters are decrypted (assuming the password search succeeds). Because these 16 characters are base58 encoded, *btcrecover* can use them alone to check passwords. It tries decrypting the characters with each password, and once the result is a valid 16-character long base58-encoded private key prefix, it has found the correct password.

Without access to the rest of your private key backup file or your wallet file, these 16 characters alone do not put any of your Bitcoin funds at risk, even after a successful password guess and decryption.


### Limitations ###

An extract script is not available for Electrum wallets. For Bitcoin Core wallets, please refer to [*extract-mkey.py*](../extract-mkey/README.md).
