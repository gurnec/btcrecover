## *btcrecover* Installation ##

Just download the latest version from <https://github.com/gurnec/btcrecover/archive/master.zip> and unzip it to a location of your choice. There’s no installation procedure for *btcrecover* itself, however there are additional requirements below depending on your operating system and the wallet type you’re trying to recover.

### Wallet Installation Requirements ###

Locate your wallet type in the list below, and follow the instructions in the sections indicated for your wallet.

**Note** that for Armory wallets, you must have Armory 0.92.x or later installed on the computer where you run *btcrecover*.

 * Armory 0.91.x or earlier - unsupported, please upgrade Armory first
 * Armory 0.92.x on Windows - [Python 2.7](#python-27) **32-bit** (x86)
 * Armory 0.93+ on Windows - [Python 2.7](#python-27) **64-bit** (x86-64)
 * Armory 0.92+ on Linux - no additional requirements
 * Armory 0.92+ on OS X - some versions of Armory may not work correctly on OS X, if in doubt use version 0.95.1
 * Bitcoin Unlimited/Classic/XT/Core - [Python 2.7](#python-27),  optional: [PyCryptodome](#pycryptodome)
 * MultiBit Classic - [Python 2.7](#python-27), recommended: [PyCryptodome](#pycryptodome)
 * MultiBit HD - [Python 2.7](#python-27), [scrypt](#scrypt), optional: [PyCryptodome](#pycryptodome)
 * Electrum (1.x or 2.x) - [Python 2.7](#python-27), recommended: [PyCryptodome](#pycryptodome)
 * Electrum 2.8+ fully encrypted wallets - [Python 2.7](#python-27) (2.7.8+ recommended), [coincurve](Seedrecover_Quick_Start_Guide.md#installation), optional: [PyCryptodome](#pycryptodome)
 * BIP-39 Bitcoin passphrases (e.g. TREZOR) - [Python 2.7](#python-27) (2.7.8+ recommended), [coincurve](Seedrecover_Quick_Start_Guide.md#installation)
 * BIP-39 Ethereum passphrases (e.g. TREZOR) - [Python 2.7](#python-27) (2.7.8+ recommended), [coincurve and pysha3](Seedrecover_Quick_Start_Guide.md#installation)
 * Hive for OS X - [Python 2.7](#python-27), [scrypt](#scrypt), [Google protobuf](#google-protocol-buffers), optional: [PyCryptodome](#pycryptodome)
 * mSIGNA (CoinVault) - [Python 2.7](#python-27), recommended: [PyCryptodome](#pycryptodome)
 * Blockchain.info - [Python 2.7](#python-27) (2.7.8+ recommended), recommended: [PyCryptodome](#pycryptodome)
 * Bitcoin Wallet for Android/BlackBerry backup - [Python 2.7](#python-27), recommended: [PyCryptodome](#pycryptodome)
 * Bitcoin Wallet for Android/BlackBerry spending PIN - [Python 2.7](#python-27), [scrypt](#scrypt), [Google protobuf](#google-protocol-buffers), optional: [PyCryptodome](#pycryptodome)
 * KnC Wallet for Android backup - [Python 2.7](#python-27), recommended: [PyCryptodome](#pycryptodome)
 * Bither - [Python 2.7](#python-27), [scrypt](#scrypt), [coincurve](Seedrecover_Quick_Start_Guide.md#installation), optional: [PyCryptodome](#pycryptodome)
 * Litecoin-Qt - [Python 2.7](#python-27),  optional: [PyCryptodome](#pycryptodome)
 * Electrum-LTC - [Python 2.7](#python-27), recommended: [PyCryptodome](#pycryptodome)
 * Litecoin Wallet for Android - [Python 2.7](#python-27), recommended: [PyCryptodome](#pycryptodome)
 * Dogecoin Core - [Python 2.7](#python-27),  optional: [PyCryptodome](#pycryptodome)
 * MultiDoge - [Python 2.7](#python-27), recommended: [PyCryptodome](#pycryptodome)
 * Dogecoin Wallet for Android - [Python 2.7](#python-27), recommended: [PyCryptodome](#pycryptodome)


### Windows ###

***After*** installing the requirements for your wallet from above, if you'd like you may *optionally* install pywin32 which allows *btcrecover* to run as a low-priority process so it doesn’t hog your CPU, and slightly improves autosave safety.

Download and run the latest version of the pywin32 installer for Python 2.7, either the 32-bit version or the 64-bit version to match the version of Python you installed. Currently this is `pywin32-221.win32-py2.7.exe` for the 32-bit version or `pywin32-221.win-amd64-py2.7.exe` for the 64-bit version available in the `Build 221` folder here: <http://sourceforge.net/projects/pywin32/files/pywin32/>

----------


### Python 2.7 ###

##### Windows #####

Visit the Python download page here: <https://www.python.org/downloads/windows/>, and click the link for the latest **Python 2.7** release near the top of the page under the heading *Python Releases for Windows*. Download and run either the `Windows x86 MSI installer` for the 32-bit version of Python, or the `Windows x86-64 MSI installer` for the 64-bit one (for Armory wallets, be sure to choose the correct one as noted above). Modern PCs should use the 64-bit version, however if you're unsure which one is compatible with your PC, choose the 32-bit one.

##### Linux #####

Most distributions include Python 2.7 pre-installed.

Note that for Blockchain.info wallets, Python version 2.7.8 or greater is recommended, and will run approximately 5 times faster than earlier versions. You can determine which version of Python you have installed by running `python --version` in a terminal. If your version is earlier than 2.7.8, you may want to check if your distribution has a “backports” repository with a more up-to-date version.

Some Linux distributions do not include the bsddb (Berkeley DB) Python module. This is usually not a problem, however if you encounter a `master key #1 not found` error, it might be resolved by installing the bsddb module (or a version of Python which includes it).

##### OS X #####

Since OS X includes an older version of Python 2, it's strongly recommended that you install the latest version. Doing so will not affect the older OS X version, the new one will be installed in a different place from the existing one.

To install the latest version, visit the Python download page here: <https://www.python.org/downloads/mac-osx/>, and click the link for the latest **Python 2** release. Download and open either the `Mac OS X 64-bit/32-bit installer` for OS X 10.6 and later (most people will want this one), or the `Mac OS X 32-bit i386/PPC installer` for OS X 10.5.

If you have any Terminal windows open, close them after the installation completes to allow the new version to go into effect.

If (and only if) you decide *not* to install the latest version of Python 2, you will need to manually install `pip` if you need to install any of the other requirements below:

        curl https://bootstrap.pypa.io/get-pip.py | sudo python


### PyCryptodome ###

PyCryptodome is not strictly required for any wallet, however it offers a 20x speed improvement for wallets that tag it as recommended in the list above.

##### Windows #####

To install PyCryptodome on Windows, you can simply do it with:

    pip install pycryptodome

If you don't have pip installed, you can read the instructions here: <https://pip.pypa.io/en/stable/installing/>

**Note:** PyCryptodome is a forked and enhanced version of the now inactive PyCrypto package. So it is best to not have both installed at the same time. If you had installed PyCrypto earlier, you can uninstall it with:

    pip uninstall pycrypto

You can do this before installing PyCryptodome, so these do not interfere.

##### Linux #####

Many distributions include PyCryptodome pre-installed, check your distribution’s package management system to see if it is available (it is often called “python-crypto”). If not, try installing it from PyPI, for example on Debian-like distributions (including Ubuntu), if this doesn't work:

    sudo apt-get install python-crypto

then try this instead:

    sudo apt-get install python-pip
    sudo pip install pycryptodome

**Note:** PyCryptodome is a forked and enhanced version of the now inactive PyCrypto package. So it is best to not have both installed at the same time. If you had installed PyCrypto earlier, you can uninstall it with:

    sudo pip uninstall pycrypto

You can do this before installing PyCryptodome, so these do not interfere.

##### OS X #####

 1. Open a terminal window (open the Launchpad and search for "terminal"). Type this and then choose `Install` to install the command line developer tools:

        xcode-select --install

 2. Type this to install PyCryptodome:

        sudo pip install pycryptodome

**Note:** PyCryptodome is a forked and enhanced version of the now inactive PyCrypto package. So it is best to not have both installed at the same time. If you had installed PyCrypto earlier, you can uninstall it with:

    sudo pip uninstall pycrypto

You can do this before installing PyCryptodome, so these do not interfere.

##### Further information #####

If you have any issues in configuring PyCryptodome, you check out it's:
- Documentation: https://www.pycryptodome.org/en/latest/src/introduction.html
- GitHub repo: https://github.com/Legrandin/pycryptodome
- Package page: https://pypi.python.org/pypi/pycryptodome

### scrypt ###

##### Windows #####

 1. Open a command prompt window, and type this to install pylibscrypt:

        C:\Python27\Scripts\pip install pylibscrypt

 2. Download this libsodium zip file, and extract it to a temporary location: <https://download.libsodium.org/libsodium/releases/libsodium-1.0.13-msvc.zip>

 3. Find the correct `libsodium.dll` file from the extracted files, it will be located at one of these two paths:

        Win32\Release\v141\dynamic\libsodium.dll
        x64\Release\v141\dynamic\libsodium.dll

    Choose either the 32-bit version (the first one above) or the 64-bit version (the second), it **must** match the version of Python that you've installed. Note that the 64-bit version is recommended if it's supported by your computer (it is approximately 35% faster than the 32-bit version, so install the 64-bit versions of both libsodium *and* Python for best performance).

 4. Copy the chosen `libsodium.dll` file into your `C:\Python27` directory.

 5. Download and install one of the two update packages below from Microsoft, either the 32-bit version or the 64-bit version (the second) to match the version of Python that you've installed.

    * [Microsoft Visual C++ Redistributable for Visual Studio 2017 **32-bit**](https://go.microsoft.com/fwlink/?LinkId=746572)
    * [Microsoft Visual C++ Redistributable for Visual Studio 2017 **64-bit**](https://go.microsoft.com/fwlink/?LinkId=746571)

##### Linux #####

Install pylibscrypt and at least one scrypt library, for example on Debian-like distributions (including Ubuntu):

 1. Open a terminal window, and type this to install pylibscrypt:

        sudo apt-get install python-pip
        sudo pip install pylibscrypt

 2. Install *one* of the scrypt libraries listed under the Requirements section here: <https://pypi.python.org/pypi/pylibscrypt>, e.g. try each of these commands, stopping after the *first one* succeeds:

        sudo apt-get install libscrypt0
        sudo apt-get install python-scrypt
        sudo pip install scrypt
        sudo apt-get install libsodium18
        sudo apt-get install libsodium13

##### OS X #####

 1. Open a terminal window (open the Launchpad and search for "terminal"). Type this and then choose `Install` to install the command line developer tools:

        xcode-select --install

 2. Type this to install pylibscrypt and libscrypt:

        sudo pip install pylibscrypt

        curl -Lo libscrypt.zip https://github.com/technion/libscrypt/archive/master.zip
        unzip libscrypt.zip
        cd libscrypt-master
        make CFLAGS_EXTRA= LDFLAGS= LDFLAGS_EXTRA= && sudo make install-osx


### Google Protocol Buffers ###

##### Windows #####

Open a command prompt window, and type this to install Google Protocol Buffers:

    C:\Python27\Scripts\pip install protobuf

##### Linux #####

Install the Google's Python protobuf library, for example on Debian-like distributions (including Ubuntu), open a terminal window and type this:

    sudo apt-get install python-pip
    sudo pip install protobuf

##### OS X #####

 1. Open a terminal window (open the Launchpad and search for "terminal"). Type this and then choose `Install` to install the command line developer tools:

        xcode-select --install

 2. Type this to install Google Protocol Buffers:

        sudo pip install protobuf

----------


### Windows GPU acceleration for Bitcoin Unlimited/Classic/XT/Core, Armory, or Litecoin-Qt ###

 1. Download the latest version of PyOpenCL for OpenCL 1.2 / Python 2.7, either the 32-bit version or the 64-bit version to match the version of Python you installed, from here: <http://www.lfd.uci.edu/~gohlke/pythonlibs/#pyopencl>. For best compatibility, be sure to select a version for OpenCL 1.2 *and no later* (look for "cl12" in the file name, and also look for "27" to match Python 2.7).

    As of this writing, the 32-bit and 64-bit versions are named respectively:

        pyopencl-2017.1.1+cl12-cp27-cp27m-win32.whl
        pyopencl-2017.1.1+cl12-cp27-cp27m-win_amd64.whl

 2. Open a command prompt window, and type this to install PyOpenCL and its dependencies:

        cd %USERPROFILE%\Downloads
        C:\Python27\Scripts\pip install pyopencl-2017.1.1+cl12-cp27-cp27m-win_amd64.whl

    Note that you may need to change either the directory (on the first line) or the filename (on the second) depending on the filename you downloaded and its location.

[PyCryptodome](#pycryptodome) is also recommended for Bitcoin Unlimited/Classic/XT/Core or Litecoin-Qt wallets for a 2x speed improvement.
