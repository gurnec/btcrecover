## *btcrecover* Installation ##

Just download the latest version from <https://github.com/gurnec/btcrecover/archive/master.zip> and unzip it to a location of your choice. There’s no installation procedure for *btcrecover* itself, however there are additional requirements below depending on your operating system and the wallet type you’re trying to recover.

### Wallet Installation Requirements ###

Locate your wallet type in the list below, and follow the instructions in the sections indicated for your wallet.

Note that for Armory wallets, you must have Armory 0.92.x or later installed on the computer where you run *btcrecover*.

 * Armory 0.91.x or earlier - unsupported, please upgrade Armory first
 * Armory 0.92.x on Windows - [Python 2.7](#python-27) **32-bit**
 * Armory 0.93.x on Windows - [Python 2.7](#python-27) **64-bit** (X86-64)
 * Armory 0.92+ on Linux or OS X - no additional requirements
 * Bitcoin Core (Bitcoin-Qt) - [Python 2.7](#python-27),  optional: [PyCrypto](#pycrypto)
 * MultiBit Classic - [Python 2.7](#python-27), recommended: [PyCrypto](#pycrypto)
 * MultiBit HD - [Python 2.7](#python-27), [scrypt](#scrypt), optional: [PyCrypto](#pycrypto)
 * Electrum (1.x or 2.x) - [Python 2.7](#python-27), recommended: [PyCrypto](#pycrypto)
 * Hive for OS X - [Python 2.7](#python-27), [scrypt](#scrypt), [Google protobuf](#google-protocol-buffers), optional: [PyCrypto](#pycrypto)
 * mSIGNA (CoinVault) - [Python 2.7](#python-27), recommended: [PyCrypto](#pycrypto)
 * Blockchain.info - [Python 2.7](#python-27) (2.7.8+ recommended), recommended: [PyCrypto](#pycrypto)
 * Bitcoin Wallet for Android backup - [Python 2.7](#python-27), recommended: [PyCrypto](#pycrypto)
 * Bitcoin Wallet for Android spending PIN - [Python 2.7](#python-27), [scrypt](#scrypt), [Google protobuf](#google-protocol-buffers), optional: [PyCrypto](#pycrypto)
 * KnC Wallet for Android backup - [Python 2.7](#python-27), recommended: [PyCrypto](#pycrypto)
 * Bither - [Python 2.7](#python-27), [scrypt](#scrypt), optional: [PyCrypto](#pycrypto)
 * Litecoin-Qt - [Python 2.7](#python-27),  optional: [PyCrypto](#pycrypto)
 * Electrum-LTC - [Python 2.7](#python-27), recommended: [PyCrypto](#pycrypto)
 * Litecoin Wallet for Android - [Python 2.7](#python-27), recommended: [PyCrypto](#pycrypto)
 * Dogecoin Core - [Python 2.7](#python-27),  optional: [PyCrypto](#pycrypto)
 * MultiDoge - [Python 2.7](#python-27), recommended: [PyCrypto](#pycrypto)
 * Dogecoin Wallet for Android - [Python 2.7](#python-27), recommended: [PyCrypto](#pycrypto)


### Windows ###

***After*** installing the requirements for your wallet from above, if you'd like you may *optionally* install pywin32 which allows *btcrecover* to run as a low-priority process so it doesn’t hog your CPU, and slightly improves autosave safety.

Download and run the latest version of the pywin32 installer for Python 2.7, either the 32-bit version or the 64-bit version to match the version of Python you installed. Currently this is `pywin32-219.win32-py2.7.exe` for the 32-bit version or `pywin32-219.win-amd64-py2.7.exe` for the 64-bit version available in the `Build 219` folder here: <http://sourceforge.net/projects/pywin32/files/pywin32/>

----------


### Python 2.7 ###

##### Windows #####

Visit the Python download page here: <https://www.python.org/downloads/windows/>, and click the link for the latest **Python 2** release. Download and run either the `Windows x86 MSI installer` for the 32-bit version of Python, or the `Windows x86-64 MSI installer` for the 64-bit one (for Armory wallets, be sure to choose the correct one as noted above). If you're unsure which one is compatible with your PC, choose the 32-bit one.

##### Linux or OS X #####

Most distributions include Python 2.7 pre-installed.

Note that for Blockchain.info wallets, Python version 2.7.8 or greater is recommended, and will run approximately 5 times faster than earlier versions. You can determine which version of Python you have installed by running `python --version` in a terminal. If your version is earlier than 2.7.8, you may want to check if your distribution has a “backports” repository with a more up-to-date version.


### PyCrypto ###

PyCrypto is not strictly required for any wallet, however it offers a 20x speed improvement for wallets that tag it as recommended in the list above.

##### Windows #####

Download and run the PyCrypto 2.6 installer for Python 2.7, either the 32-bit version or the 64-bit version to match your version of Python. This is either `PyCrypto 2.6 for Python 2.7 32bit` or `PyCrypto 2.6 for Python 2.7 64bit` available here: <http://www.voidspace.org.uk/python/modules.shtml#pycrypto>

##### Linux #####

Many distributions include PyCrypto pre-installed, check your distribution’s package management system to see if it is available (it is often called “python-crypto”). If not, try installing it by using PyPI, for example on Debian-like distributions, if this doesn't work:

    sudo apt-get install python-crypto

then try this instead:

    sudo apt-get install python-pip
    sudo pip install pycrypto

##### OS X #####

On OS X, installing PyCrypto is unfortunately a bit more difficult:

 1. Download and install the “Command Line Tools for Xcode” for your version of OS X from Apple here: <https://developer.apple.com/downloads/>. This site requires that you register as an Apple Developer using your Apple ID.

2.  Open a Terminal window, and install Python pip and then PyCrypto:

        curl https://bootstrap.pypa.io/get-pip.py | sudo python
        sudo pip install pycrypto


### scrypt ###

##### Windows #####

 1. Open a command prompt window, and type this to install pylibscrypt:

        C:\Python27\Scripts\pip install pylibscrypt

 2. Download this libsodium zip file, and extract it to a temporary location: <https://download.libsodium.org/libsodium/releases/libsodium-1.0.2-msvc.zip>

 3. Find the correct `libsodium.dll` file from the extracted files, it will be located at one of these two paths:

        Win32\Release\v120\dynamic\libsodium.dll
        x64\Release\v120\dynamic\libsodium.dll

    Choose either the 32-bit version (the first one above) or the 64-bit version (the second) to match the version of Python that you've installed. Note that the 64-bit version is recommended if it's supported by your computer (it is approximately 35% faster than the 32-bit version).

 4. Copy the chosen `libsodium.dll` file into your `C:\Python27` directory, and rename it to `sodium.dll`

 5. Download and install the “Visual C++ Redistributable Packages for Visual Studio 2013” from Microsoft here: <http://www.microsoft.com/en-us/download/details.aspx?id=40784>. As above, you will need to choose either the 32-bit version or the 64-bit version to match the version of Python that you've installed.

##### Linux #####

 1. Open a terminal window, and type this to install pylibscrypt:

        sudo pip install pylibscrypt

 2. Install one of the scrypt libraries listed under the Requirements section here: <https://pypi.python.org/pypi/pylibscrypt>. For example on Debian-like distributions, try ***one*** of these commands:

        sudo apt-get install libscrypt0
        sudo apt-get install python-scrypt
        sudo pip install scrypt
        sudo apt-get install libsodium13

##### OS X #####

On OS X, installing scrypt is unfortunately a bit more difficult:

 1. Download and install the “Command Line Tools for Xcode” for your version of OS X from Apple here: <https://developer.apple.com/downloads/>. This site requires that you register as an Apple Developer using your Apple ID.

2.  Open a Terminal window, and install Python pip and then scrypt:

        curl https://bootstrap.pypa.io/get-pip.py | sudo python
        sudo pip install pylibscrypt scrypt


### Google Protocol Buffers ###

##### Windows #####

Open a command prompt window, and type this to install Google Protocol Buffers:

    C:\Python27\Scripts\pip install pyprotobuf

##### Linux #####

Open a terminal window, and type this to install Google Protocol Buffers:

    sudo pip install pyprotobuf

----------


### Windows GPU acceleration for Bitcoin Core, Armory, or Litecoin-Qt ###

To enable the experimental GPU acceleration feature in Windows, download and install the **32-bit** version of [Python 2.7](#python-27) (and optionally [pywin32](#windows)) as detailed above (and *only* this version, no other version of Python can be installed except for the 32-bit version of Python 2.7).

For Armory, you must install a 0.92.x version of Armory; 0.93.x versions are not supported (however wallets created or used by a any version of Armory are compatible with *btcrecover*).

You will also need to download and run the installers for:

 * The latest binary version of PyOpenCL for Python 2 & Python(x,y) available here: <https://code.google.com/p/pythonxy/wiki/AdditionalPlugins>. (The download link on that page is a button to the right of “pyopencl” which has an arrow pointing downwards.)

 * The latest binary version of NumPy for Python 2.7. Currently this is `numpy-1.9.2-win32-superpack-python2.7.exe`, available in the `1.9.2` folder here: <http://sourceforge.net/projects/numpy/files/NumPy/>

 * [PyCrypto](#pycrypto) is also recommended for Bitcoin Core or Litecoin-Qt wallets for a 2x speed improvement.

If you encounter the error `ImportError: DLL load failed` when running *btcrecover*, you will also need to copy the file named `boost_python-vc90-mt-1_54.dll` from the `C:\Python27\DLLs\` directory into the `C:\Python27\Lib\site-packages\pyopencl\` directory (this is apparently a bug in the PyOpenCL installer).
