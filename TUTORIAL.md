# *btcrecover* Tutorial #


*btcrecover* is a free and open source multithreaded wallet password recovery tool with support for Armory, Bitcoin Core (a.k.a. Bitcoin-Qt), MultiBit (a.k.a. MultiBit Classic, MultiBit HD is not supported), Electrum, and Litecoin-Qt. It is designed for the case where you already know most of your password, but need assistance in trying different possible combinations. This tutorial will guide you through the features it has to offer.

If you find *btcrecover* helpful, please consider a small donation to help support my efforts:
**[17LGpN2z62zp7RS825jXwYtE7zZ19Mxxu8](bitcoin:17LGpN2z62zp7RS825jXwYtE7zZ19Mxxu8?label=btcrecover)**

#### Thank You! ####


## Quick Start ##

This tutorial is pretty long... you don't have to read the whole thing. Here are some places to start.

 1. Read the [Installation](#installation) section for instructions and download links.
 2. If you already have a `btcrecover-tokens-auto.txt` file, skip straight to step 5.  If you need help creating passwords from different combinations of smaller pieces you remember, start with step 3. If you you think there's a typo in your password, or if you mostly know what your whole password is and only need to try different variations of it, read step 4.
 3. Read [The Token File](#the-token-file) section (at least the beginning), which describes how *btcrecover* builds up a whole password you don't remember from smaller pieces you do remember. Once you're done, you'll know how to create a `tokens.txt` file you'll need later.
 4. Read the [Typos](#typos) section, which describes how *btcrecover* can make variations to a whole password to create different password guesses. Once you're done, you'll have a list of command-line options which will create the variations you want to test.
     * If you didn't need step 3, read [The Passwordlist](#the-passwordlist) section instead.
 5. Read the [Running *btcrecover*](#running-btcrecover) section to see how to put these pieces together and how to run *btcrecover* in a Command Prompt window.
     * (optional) Read the [Testing your config](#testing-your-config) section to view the passwords that will be tested.
     * (optional) If you're testing a lot of combinations that will take a long time, use the [Autosave](#autosave) feature to safeguard against losing your progress.
 6. (optional, but highly recommended) Donate huge sums of Bitcoin to the donation address above once your password's been found.


## The Token File ##

*btcrecover* can accept as input a text file which has a list of what are called password “tokens”. A token is simply a portion of a password which you do remember, even if you don't remember where that portion appears in the actual password. It will combine these tokens in different ways to create different whole password guesses to try.

This plain text file, typically named `tokens.txt`, can be created in any basic text editor, such as Notepad on Windows or TextEdit on OS X, and should probably be saved into the same folder as the `btcrecover.py` script (just to keep things simple).

### Basics ###

Let’s say that you remember your password contains 3 parts, you just can’t remember in what order you used them. Here are the contents of a simple `tokens.txt` file:

    Cairo
    Beetlejuice
    Hotel_california

When used with these contents, *btcrecover* will try all possible combinations using one or more of these three tokens, e.g. `Hotel_california` (just one token), `BettlejuiceCairo` (two tokens pasted together), etc.

### Mutual Exclusion ###

Maybe you’re not sure about how you spelled or capitalized one of those words. Take this token file:

    Cairo
    Beetlejuice beetlejuice Betelgeuse betelgeuse
    Hotel_california

Tokens listed on the same line, separated by spaces, are mutually exclusive and will never be tried together in a password guess. *btcrecover* will try `Cairo` and `bettlejuiceCairoHotel_california`, but it will skip over `Betelgeusebetelgeuse`. Had all four Beetlejuice versions been listed out on separate lines, this would have resulted in trying thousands of additional passwords which we know to be incorrect. As is, this token file only needs to try 48 passwords to account for all possible combinations. Had they all been on separate lines, it would have had to try 1,956 different combinations.

In short, when you’re sure that certain tokens or variations of a token have no chance of appearing together in a password, placing them all on the same line can save a lot of time.

### Required Tokens ###

What if you’re certain that `Cairo` appears in the password, but you’re not so sure about the other tokens?

    + Cairo
    Beetlejuice beetlejuice Betelgeuse betelgeuse
    Hotel_california

Placing a `+` (and some space after it) at the beginning of a line tells *btcrecover* to only try passwords that include `Cairo` in them. You can also combine these two last features. Here’s a longer example:

    Cairo cairo Katmai katmai
    + Beetlejuice beetlejuice Betelgeuse betelgeuse
    Hotel_california hotel_california

In this example above, passwords will be constructed by taking at most one token from the first line, exactly one token from the second line (it’s required), and at most one token from the third line. So `Hotel_californiaBetelgeuse` would be tried, but `cairoKatmaiBetelgeuse` would be skipped (`cairo` and `Katmai` are on the same line, so they’re never tried together) and `katmaiHotel_california` is also skipped (because one token from the second line is required in every try).

This file will create a total of just 244 different combinations. Had all ten of those tokens been listed on separate lines, it would have produced 9,864,100 guesses, which could take days longer to test!

### Anchors ###

#### Beginning and Ending Anchors ####

Another way to save time is to use “anchors”. You can tell *btcrecover* that certain tokens, if they are present at all, are definitely at the beginning or end of the password:

    ^Cairo
    Beetlejuice beetlejuice Betelgeuse betelgeuse
    Hotel_california$

In this example above, the `^` symbol is considered special if it appears at the beginning of any token (it’s not actually a part of the password), and the `$` symbol is special if it appears at the end of any token. `Cairo`, if it is tried, is only tried at the beginning of a password, and `Hotel_california`, if it is tried, is only tried at the end. Note that neither is required to be tried in password guesses with the example above. As before, all of these options can be combined:

    Cairo
    Beetlejuice beetlejuice Betelgeuse betelgeuse
    + ^Hotel_california ^hotel_california

In this example above, either `Hotel_california` or `hotel_california` is *required* at the beginning of every password that is tried (and the other tokens are tried normally after that).

#### Positional Anchors ####

Tokens with positional anchors may only appear at one specific position in the password -- there are always a specific number of other tokens which precede the anchored one. In the example below you'll notice a number in between the two `^` symbols added to the very beginning to create positionally anchored tokens (with no spaces):

    ^2^Second_or_bust
    ^3^Third_or_bust
    Cairo
    Beetlejuice
    Hotel_california

As you can guess, `Second_or_bust`, if it is tried, is only tried as the second token in a password, and `Third_or_bust`, if it is tried, is only tried as the third. (Neither token is required because there is no `+` at the beginning these of these lines.)

#### Middle Anchors ####

Middle anchors are a bit like positional anchors, only more flexible: the anchored tokens may appear once throughout a specific *range* of positions in the password.

**Note** that placing a middle anchor on a token introduces a special restriction: it *forces* the token into the *middle* of a password. A token with a middle anchor (unlike any of the other anchors described above) will *never* be tried as the first or last token of a password.

You specify a middle anchor by adding a comma and two numbers (between the `^` symbols) at the very beginning of a token (all with no spaces):

    ^2,3^Second_or_third_(but_never_last)
    ^2,4^Second_to_fourth_(but_never_last)
    Cairo
    Beetlejuice
    Hotel_california

 As mentioned above, neither of those middle-anchored tokens will ever be tried as the last token in a password, so something (one or more of the non-anchored tokens) will appear after the middle-anchored ones in every guess in which they appear. Since tokens with middle anchors never appear at the beginning either, the smallest value you can use for that first number is 2. Finally, when you specify the range, you can leave out one (or even both) of the numbers, like this:

    ^3,^Third_or_after_(but_never_last)
    ^,3^Third_or_earlier((but_never_first_or_last)
    ^,^Anywhere_in_the_middle
    Cairo
    Beetlejuice
    Hotel_california

You can't leave out the comma (that's what makes it a middle anchor instead of a positional anchor). Leaving out a number doesn't change the “never at the beginning or the end” rule which always applies to middle anchors. If you do need a token with a middle anchor to also possibly appear at the beginning or end of a password, you can add second copy to the same line with a beginning or end anchor (because at most one token on a line can appear in any guess):

    ^,^Anywhere_in_the_middle_or_end        Anywhere_in_the_middle_or_end$
    ^,^Anywhere_in_the_middle_or_beginning ^Anywhere_in_the_middle_or_beginning

### Token Counts ###

There are a number of command-line options that affect the combinations tried. The `--max-tokens` option limits the number of tokens that are added together and tried. With `--max-tokens` set to 2, `Hotel_californiaCairo`, made from two tokens, would be tried from the earlier example, but `Hotel_californiaCairoBeetlejuice` would be skipped because it’s made from three tokens. You can still use *btcrecover* even if you have a large number of tokens, as long as `--max-tokens` is set to something reasonable. If you’d like to re-run *btcrecover* with a larger number of `--max-tokens` if at first it didn’t succeed, you can also specify `--min-tokens` to avoid trying combinations you’ve already tried.

### Expanding Wildcards ###

What if you think one of the tokens has a number in it, but you’re not sure what that number is? For example, if you think that Cairo is definitely followed by a single digit, you could do this:

    Cairo0 Cairo1 Cairo2 Cairo3 Cairo4 Cairo5 Cairo6 Cairo7 Cairo8 Cairo9
    Beetlejuice
    Hotel_california

While this definitely works, it’s not very convenient. This next token file has the same effect, but it’s easier to write:

    Cairo%d
    Beetlejuice
    Hotel_california

The `%d` is a wildcard which is replaced by all combinations of a single digit. Here are some examples of the different types of wildcards you can use:

 * `%d`    - a single digit
 * `%2d`   - exactly 2 digits
 * `%1,3d` - between 1 and 3 digits (all possible permutations thereof)
 * `%0,2d` - between 0 and 2 digits (in other words, the case where there are no digits is also tried)
 * `%a`    - a single lowercase letter
 * `%1,3a` - between 1 and 3 lowercase letters
 * `%A`    - a single uppercase letter
 * `%n`    - a single digit or lowercase letter
 * `%N`    - a single digit or uppercase letter
 * `%ia`   - a “case-insensitive” version of %a: a single lower or uppercase letter
 * `%in`   - a single digit, lower or uppercase letter
 * `%1,2in`- between 1 and 2 characters long of digits, lower or uppercase letters
 * `%[chars]` - exactly 1 of the characters between `[` and `]` (e.g. either a `c`, `h`, `a`, `r`, or `s`)
 * `%1,3[chars]` - between 1 and 3 of the characters between `[` and `]`
 * `%[0-9a-f]` - exactly 1 of these characters: `0123456789abcdef`
 * `%2i[0-9a-f]` - exactly 2 of these characters: `0123456789abcdefABCDEF`
 * `%s`    - a single space
 * `%l`    - a single line feed character
 * `%r`    - a single carriage return character
 * `%R`    - a single line feed or carriage return character
 * `%t`    - a single tab character
 * `%T`    - a single space or tab character
 * `%w`    - a single space, line feed, or carriage return character
 * `%W`    - a single space, line feed, carriage return, or tab character
 * `%y`    - any single ASCII symbol
 * `%Y`    - any single ASCII digit or symbol
 * `%p`    - any single ASCII letter, digit, or symbol
 * `%P`    - any single character from either `%p` or `%W` (pretty much everything)
 * `%c`    - a single character from a custom set specified at the command line with `--custom-wild characters`
 * `%C`    - an uppercased version of `%c` (the same as `%c` if `%c` has no lowercase letters)
 * `%ic`   - a case-insensitive version of `%c`
 * `%%`    - a single `%` (so that `%`’s in your password aren’t confused as wildcards)
 * `%^`    - a single `^` (so it’s not confused with an anchor if it’s at the beginning of a token)
 * `%S`    - a single `$` (yes, that’s `%` and a capital `S` that gets replaced by a dollar sign, sorry if that’s confusing)

Up until now, most of the features help by reducing the number of passwords that need to be tried by exploiting your knowledge of what’s probably in the password. Wildcards significantly expand the number of passwords that need to be tried, so they’re best used in moderation.

### Contracting Wildcards ###

Instead of adding new characters to a password guess, contracting wildcards remove one or more characters. Here's an example:

    Start%0,2-End

The `%0,2-` contracting wildcard will remove between 0 and 2 adjacent characters from either side, so that each of `StartEnd` (removes 0), `StarEnd` (removes 1 from left), `StaEnd` (removes 2 from left), `Starnd` (removes 1 from left and 1 from right), `Startnd` (removes 1 from right), and `Startd` (removes 2 from right) will be tried. This can be useful when considering copy-paste errors, for example:

    %0,20-A/Long/Password/with/symbols/that/maybe/was/partially/copy/pasted%0,20-

Different versions of this password will be tried removing up to 20 characters from either end.

Here are the three types of contracting wildcards:

 * `%0,5-` - removes between 0 and 5 adjacent characters (total) taken from either side of the wildcard
 * `%0,5<` - removes between 0 and 5 adjacent characters only from the wildcard's left
 * `%0,5>` - removes between 0 and 5 adjacent characters only from the wildcard's right

You may want to note that a contracting wildcard in one token can potentially remove characters from other tokens, but it will never remove or cross over another wildcard. Here's an example to fully illustrate this (feel free to skip to the next section if you're not interested in these specific details):

    AAAA%0,10>BBBB
    xxxx%dyyyy

These two tokens each have eight normal letters. The first token has a contracting wildcard which removes up to 10 characters from its right, and the second token has an expanding wildcard which expands to a single digit.

One of the passwords generated from these tokens is `AAAABBxxxx5yyyy`, which comes from selecting the first token followed by the second token, and then applying the wildcards with the contracting wildcard removing two characters. Another is `AAAAxx5yyyy` which comes from the same tokens, but the contracting wildcard now is removing six characters, two of which are from the second token.

The digit and the `yyyy` will never be removed by the contracting wildcard because other wildcards are never removed or crossed over. Even though the contracting wildcard is set to remove up to 10 characters, `AAAAyyy` will never be produced because the `%d` blocks it.


## The Passwordlist ##

If you already have a simple list of whole passwords you'd like to test, and you don't need any of the features described above, you can use the `--passwordlist` command-line option (instead of the `--tokenlist` option as described later in the [Running *btcrecover*](#running-btcrecover) section).

If you specify `--passwordlist` without a file, *btcrecover* will prompt you to type in a list of passwords, one per line, in the Command Prompt window. If you already have a text file with the passwords in it, you can use `--passwordlist FILE` instead (replacing `FILE` with the file name).

Be sure not to add any extra spaces, unless those spaces are actually a part of a password.

Each line is used verbatim as a single password when using the `--passwordlist` option (and none of the features from above are applied). You can however use any of the Typos features described below to try different variations of the passwords in the passwordlist.


## Typos ##

*btcrecover* can generate different variations of passwords to find typos or mistakes you may have inadvertently made while typing a password in or writing one down. This feature is enabled by including one or more command-line options when you run *btcrecover*.

With the `--typos #` command-line option (with `#` replaced with a count of typos), you tell *btcrecover* up to how many typos you’d like it to add to each password (that has been either generated from a token file or taken from a passwordlist as described above). You must also specify the types of typos you’d like it to generate, and it goes through all possible combinations for you (including the no-typos-present possibility). Here is a summary of the basic types of typos along with the command-line options which enable each:

 * `--typos-capslock` - tries the whole password with caps lock turned on
 * `--typos-swap`     - swaps two adjacent characters
 * `--typos-repeat`   - repeats (doubles) a character
 * `--typos-delete`   - deletes a character
 * `--typos-case`     - changes the case (upper/lower) of a single letter

For example, with `--typos 2 --typos-capslock --typos-repeat` options specified on the command line, all combinations containing up to two typos will be tried, e.g. `Cairo` (no typos), `cAIRO` (one typo: caps lock), `CCairoo` (two typos: both repeats), and `cAIROO` (two typos: one of each type) will be tried. Adding lots of typo types to the command line can significantly increase the number of combinations, and increasing the `--typos` count can be even more dramatic, so it’s best to tread lightly when using this feature unless you have a small token file or passwordlist.

Here are some additional types of typos that require a bit more explanation:

 * `--typos-closecase` - Like `--typos-case`, but it only tries changing the case of a letter if that letter is next to another letter with a different case, or if it's at the beginning or the end. This produces fewer combinations to try so it will run faster, and it will still catch the more likely instances of someone holding down shift for too long or for not long enough.

 * `--typos-replace s` - This tries replacing each single character with the specified string (in the example, an `s`). The string can be a single character, or some longer string (in which case each single character is replaced by the entire string), or even a string with one or more [expanding wildcards](#expanding-wildcards) in it. For example, `--typos 1 --typos-replace %a` would try replacing each character (one at a time) with a lower-case letter, working through all possible combinations. Using wildcards can drastically increase the total number of combinations.

 * `--typos-insert s`  - Just like `--typos-replace`, but instead of replacing a character, this tries inserting a single copy of the string (or the wildcard substitutions) in between each pair of characters, as well as at the beginning and the end.

    Even when `--typos` is greater than 1, `--typos-insert` will not normally try inserting multiple copies of the string at the same position. For example, with `--typos 2 --typos-insert Z` specified, guesses such as `CaiZro` and `CZairoZ` are tried, but `CaiZZro` is not. You can change this by using `--max-adjacent-inserts #` with a number greater than 1.

#### Typos Map ####

 * `--typos-map typos.txt`   - This is a relatively complicated, but also flexible type of typo. It tries replacing certain specific characters with certain other specific characters, using a separate file (in this example, named `typos.txt`) to spell out the details. For example, if you know that you often make mistakes with punctuation, you could create a typos-map file which has these two lines in it:

        .    ,/;
        ;    [‘/.


    In this example, *btcrecover* will try replacing each `.` with one of the three punctuation marks which follow the spaces on the same line, and it will try replacing each `;` with one of the four punctuation marks which follow it.

    This feature can be used for more than just typos. If for example you’re a fan of “1337” (leet) speak in your passwords, you could create a typos-map along these lines:

        aA    @
        sS    $5
        oO    0

    This would try replacing instances of `a` or `A` with `@`, instances of `s` or `S` with either a `$` or a `5`, etc., up to the maximum number of typos specified with the `--typos #` option. For example, if the token file contained the token `Passwords`, and if you specified `--typos 3`, `P@55words` and `Pa$sword5` would both be tried because they each have three or fewer typos/replacements, but `P@$$w0rd5` with its 5 typos would not be tried.


## Autosave ##

Depending on the number of passwords which need to be tried, running *btcrecover* might take a very long time. If it is interrupted in the middle of testing (with Ctrl-C (see below), due to a reboot, accidentally closing the Command Prompt, or for any other reason), you might lose your progress and have to start the search over from the beginning. To safeguard against this, you can add the `--autosave savefile` option when you first start *btcrecover*. It will automatically save its progress about every 5 minutes to the file that you specify (in this case, it was named `savefile` – you can just make up any file name, as long as it doesn’t already exist).

If interrupted, you can restart testing by either running it with the exact same options, or by providing this option and nothing else: `--restore savefile`. *btcrecover* will then begin testing exactly where it had left off. (Note that the token file, as well as the typos-map file, if used, must still be present and must be unmodified for this to work. If they are not present or if they’ve been changed, *btcrecover* will refuse to start.)

The autosave feature is not currently supported with passwordlists, only with token files.


### Interrupt and Continue ###

If you need to interrupt *btcrecover* in the middle of testing, you can do so with Ctrl-C (hold down the Ctrl key and press C) and it will respond with a message such this and then it will exit:

    Interrupted after finishing password # 357449

If you didn't have the autosave feature enabled, you can still manually start testing where you left off. You need to start *btcrecover* with the *exact same* token file or passwordlist, toypos-map file (if you were using one), and command-line options plus one extra option, `--skip 357449`, and it will start up right where it had left off.


## Installation ##

Just download the latest version from <https://github.com/gurnec/btcrecover/archive/master.zip> and unzip it to a location of your choice. There’s no installation procedure for *btcrecover* itself, however there are additional requirements below depending on your operating system and the wallet type you’re trying to recover.

### Armory (on any OS)###

You must have Armory installed if you’re trying to recover an Armory password. *btcrecover* has only been tested with Armory version 0.91; other versions may not work at all or may only work after some changes have been made. If *btcrecover* is unable to locate the Armory installation directory automatically, you may need to move the *btcrecover* files into the Armory `Program Files` or `lib` directory, or learn how to use the `PYTHONPATH` environment variable.

### Windows – Armory ###

In addition to requiring Armory 0.91, you will also need to download and install:

 * The latest version of Python 2.7, 32-bit (it must be the 32-bit version). Currently this is the “Python 2.7.6 Windows Installer” available here: <https://www.python.org/download/>

### Windows – Bitcoin Core, MultiBit Classic, Electrum, or Litecoin-Qt ###

With this combination, you will also need to download and install:

 * The latest version of Python 2.7, either the 32-bit version or the 64-bit version. Currently this is the “Python 2.7.6 Windows Installer” for the 32-bit version, or “Python 2.7.6 Windows X86-64 Installer” for the 64-bit version (which is preferable if you have a 64-bit version of Windows and don't plan on using GPU acceleration), both available here: <https://www.python.org/download/>

 * Optional, but highly recommended for MultiBit or Electrum (for a 30x speed improvement): The latest binary version of PyCrypto for Python 2.7, either the 32-bit version or the 64-bit version to match your version of Python. Currently this is “PyCrypto 2.6 for Python 2.7 32bit” or “PyCrypto 2.6 for Python 2.7 64bit” available here: <http://www.voidspace.org.uk/python/modules.shtml#pycrypto>

 * Optional, allows *btcrecover* to run as a low-priority process so it doesn’t hog your CPU and slightly improves autosave safety: The latest version of pywin32 for Python 2.7, either the 32-bit version or the 64-bit version to match your version of Python. Currently this is “pywin32-219.win32-py2.7.exe” for the 32-bit version or “pywin32-219.win-amd64-py2.7.exe” for the 64-bit version available in the “Build 219” folder here: <http://sourceforge.net/projects/pywin32/files/pywin32/>

#### Windows GPU acceleration for Bitcoin Core or Litecoin-Qt ####

To enable the experimental GPU acceleration features in Windows, you will need to download and install the 32-bit version of Python 2.7 plus the optional components you'd like as detailed above (and *only* this version, no other version of Python can be installed except the 32-bit version of Python 2.7 plus any optional libraries), and you will also need to download and install:

 * The latest binary version of PyOpenCL for Python 2 & Python(x,y) available here: <https://code.google.com/p/pythonxy/wiki/AdditionalPlugins>. (The download link on that page is a button to the right of “pyopencl” which has an arrow pointing downwards.)

 * The latest binary version of NumPy for Python 2.7. Currently this is “numpy-1.8.1-win32-superpack-python2.7.exe”, available next to “Looking for the latest version?” here: <http://sourceforge.net/projects/numpy/files/NumPy/>

If you encounter the error `ImportError: DLL load failed` when running *btcrecover*, you will also need to copy the file named `boost_python-vc90-mt-1_54.dll` from the `C:\Python27\DLLs\` directory into the `C:\Python27\Lib\site-packages\pyopencl\` directory (this is apparently a bug in the PyOpenCL installer).

### Linux or OS X – Bitcoin Core, MultiBit Classic, Electrum, or Litecoin-Qt ###

 * Python 2.7.x – Most distributions include this pre-installed.

 * Optional, but highly recommended for MultiBit or Electrum: PyCrypto for Python 2.7.x – Many distributions include this pre-installed, check your distribution’s package management system to see if this is available. It is often called “python2.7 crypto” or just “python-crypto”. If not, try installing it by using PyPI, for example on Debian-like distributions:

        sudo apt-get install python-pip
        sudo pip install pycrypto


## Running *btcrecover* ##

(Also see the [Quick Start](#quick-start) section.) After you've installed all of the requirements (above) and have downloaded the latest version:

 1. Unzip the `btcrecover-master.zip` file, it contains a single directory named "btcrecover-master". Inside the btcrecover-master directory is the Python script (program) file `btcrecover.py`.
 2. **Make a copy of your wallet file** into the directory which contains `btcrecover.py`. On Windows, you can usually find your wallet file by clicking on the Start Menu, then “Run...”, and then typing in one of the following paths and clicking OK. Some wallet software allows you to create multiple wallets, for example Armory wallets have an ID which you can view in the Armory interface, and the wallet file names contain this ID. Of course, you need to be sure to copy the correct wallet file.
     * Armory - `%appdata%\Armory`
     * Bitcoin Core - `%appdata%\Bitcoin`
     * Electrum - `%appdata%\Electrum\wallets`
     * Litecoin-Qt - `%appdata%\Litecoin`
     * MultiBit - Please see the [Finding MultiBit Wallet Files](#finding-multibit-wallet-files) section below
 3. If you have a `btcrecover-tokens-auto.txt` file, you're almost done. Copy it into the directory which contains `btcrecover.py`, and then simply double-click the `btcrecover.py` file, and *btcrecover* should begin testing passwords. (You may need to rename your wallet file if it doesn't match the file name listed insided the `btcrecover-tokens-auto.txt` file.) If you don't have a `btcrecover-tokens-auto.txt` file, continue reading below.
 4. Copy your `tokens.txt` file, or your passwordlist file if you're using one, into the directory which contains `btcrecover.py`.
 5. You will need to run `btcrecover.py` with at least two command-line options, `--wallet FILE` to identify the wallet file name and either `--tokenlist FILE` or `--passwordlist FILE` (the FILE is optional for `--passwordlist`), depending on whether you're using a [Token File](#the-token-file) or [Passwordlist](#the-passwordlist). If you're using [Typos](#typos) or [Autosave](#autosave), please refer the sections above for additional options you'll want to add.
 6. What follows is an example on windows. The details for your system will be different, for example the download location may be different, or the wallet file name may differ, so you'll need to make some changes. Any additional options are all placed on the same line.

        cd \Users\Chris\Downloads\btcrecover-master
        C:\python27\python btcrecover.py --wallet wallet.dat --tokenlist tokens.txt --other-options...

After a short delay, *btcrecover* should begin testing passwords and will display a progress bar and an ETA. If it appears to be stuck just counting upwards with the message `Counting passwords ...` and no progress bar, please read the [Memory limitations](#memory) section below. If that doesn't help, then you've probably chosen too many tokens or typos to test resulting in more combinations than your system can handle (although the [`--max-tokens`](#token-counts) option may be able to help).

Running `btcrecover.py` with the `--help` option will give you a summary of all of the available command-line options, most of which are described in the sections above.

### Testing your config ###

If you'd just like to test your token file and/or chosen typos, you can use the `--listpass` option in place of the `--wallet FILE` option as demonstrated below. *btcrecover* will then list out all the passwords to the screen instead of actually testing them against a wallet file. This can also be useful if you have another tool which can test some other type of wallet, and is capable of taking a list of passwords to test from *btcrecover*. Because this option can generate so much output, you may want only use it with short token files and few typo options.

        C:\python27\python btcrecover.py --listpass --tokenlist tokens.txt  | more

The `| more` at the end (the `|` symbol is a shifted `\` backslash) will introduce a pause after each screenful of passwords.

### Finding MultiBit Wallet Files ###

*btcrecover* doesn’t operate directly on MultiBit wallet files, instead it operates on MultiBit private key backup files. When you first add a password to your MultiBit wallet, and after that each time you add a new receiving address or change your wallet password, MultiBit creates an encrypted private key backup file in a `key-backup` directory that's near the wallet file. These private key backup files are much faster to try passwords against (by a factor of over 1,000), which is why *btcrecover* uses them. For the default wallet that is created when MultiBit is first installed, this directory is located here:

    %appdata%\MultiBit\multibit-data\key-backup

The key files have names which look like `walletname-20140407200743.key`. If you've created additional wallets, their `key-backup` directories will be located elsewhere and it's up to you to locate them. Once you have, choose the most recent `.key` file and copy it into the directory containing `btcrecover.py` for it to use.

For more details on locating your MultiBit private key backup files, see: <https://www.multibit.org/en/help/v0.5/help_fileDescriptions.html>

### GPU acceleration for Bitcoin Core and Litecoin-Qt wallets###

*btcrecover* includes experimental support for using one or more graphics cards or dedicated accelerator cards to increase search performance with Bitcoin Core and Litecoin-Qt wallets. This can offer on the order of *100x* better performance when enabled.

In order to use this feature, you must have a card and drivers which support OpenCL (most AMD and NVIDIA cards and drivers already support OpenCL on Windows), and you must install the required Python libraries as described in the [Windows GPU acceleration](#windows-gpu-acceleration-for-bitcoin-core-or-litecoin-qt) section. GPU acceleration should also work on Linux and OS X, however instruction for installing the required Python libraries are not currently included in this tutorial.

To enable GPU support, add the `--enable-gpu` option to the command line. There are two other options, `--global-ws` and `--local-ws`, which should also be provided along with specific values to improve the search speed. Unfortunately, the specific values for these options can only be determined by trial and error. A good starting point is:

    C:\python27\python btcrecover.py --wallet wallet.dat --performance --enable-gpu --global-ws 4096 --local-ws 512

The `--performance` option tells *btcrecover* to simply measure the performance until Ctrl-C is pressed, and not to try testing any particular passwords. You will still need a wallet file (or an `--mkey` if you'd prefer) for performance testing. After you you have a baseline from this initial test, you can try different values for `--global-ws` and `--local-ws` to see if they improve or worsen performance.

Finding the right values for `--global-ws` and `--local-ws` can make a 10x improvement, so it's usually worth the effort.

Generally when testing, you should increase or decrease these two values by powers of 2, for example you should increase or decrease them by 128 or 256 at a time. It's important to note that `--global-ws` must always be evenly divisible by `--local-ws`, otherwise *btcrecover* will exit with an error message.

Although this procedure can be tedious, with larger tokenlists or passwordlists they can make a significant difference.

### command-line options inside the tokens file ###

If you'd prefer, you can also place command-line options directly inside the `tokens.txt` file. In order to do this, the very first line of the tokens file must begin with exactly `#--`, and the rest of this line (and only this line) is interpreted as additional command-line options. For example, here's a tokens file which enables autosave, pause-before-exit, and one type of typo:

    #--autosave progress.sav --pause --typos 1 --typos-case
    Cairo
    Beetlejuice Betelgeuse
    Hotel_california

### btcrecover-tokens-auto.txt ###

Normally, when you run *btcrecover* it expects you to run it with at least a few options, such as the location of the tokens file and of the wallet file. If you run it without specifying `--tokenlist` or `--passwordlist`, it will check to see if there is a file named `btcrecover-tokens-auto.txt` in the current directory, and if found it will use that for the tokenlist. Because you can specify options inside the tokenlist file if you'd prefer (see above), this allows you to run *btcrecover* without using the command line at all. You may want to consider using the `--pause` option to prevent a Command Prompt window from immediately closing once it's done running if you decide to run it this way.


# Limitations / Caveats #

### Beta Software ###

Although this software is unlikely to harm any wallet files, **you are strongly encouraged to only run it with copies of your wallets**. In particular, this software is distributed **WITHOUT ANY WARRANTY**; please see the accompanying GPLv2 licensing terms for more details.

Because this software is beta software, and also because it interacts with other beta software, it’s entirely possible that it may fail to find a password which it’s been correctly configure by you to find.

#### OS X ####
Mac OS X support is completely untested.

### Delimiters, Spaces, and Special Symbols in Passwords###

By default, *btcrecover* uses one or more whitespaces to separate tokens in the tokenlist file, and to separated to-be-replaced characters from their replacements in the typos-map file. It also ignores any extra whitespace in these files. This makes it difficult to test passwords which include spaces and certain other symbols.

One way around this, which only works for the tokenlist file, is to use the `%s` wildcard which will be replaced by a single space. Another option, which works both for the tokenlist file and a typos-map file, is using the `--delimiter` which option allows you to change this behavior. If used, whitespace is no longer ignored, nor is extra whitespace stripped. Instead, the new `--delimiter` string must be used *exactly as specified* to separate tokens or typos-map columns. Any whitespace becomes a part of a token, so you must take care not to add any inadvertent whitespace to these files.

Additionally, *btcrecover* considers the following symbols special under certain specific circumstances in the tokenlist file (and for the `#` symbol, also in the typos-map file). A special symbol is part of the syntax, and not part of a password.

 * `%` - always considered special; `%%` in a token will be replaced by `%` during searches
 * `^` - only special if it's the first character of a token; `%^` will be replaced by `^` during searches
 * `$` - only special if it's the last character of a token; `%S` (note the capital `S`) will be replaced by `$` during searches
 * `#` - only special if it's the very first character on a line, the rest of the line is then ignored (a comment); note that if `#--` is at the very beginning of the tokenlist file, then the first line is parsed as additional command-line options
 * `+` - only special if it's the first token (after possibly stripping whitespace) on a line, followed by a delimiter, and then followed by other token(s) (see the [Mutual Exclusion](#mutual-exclusion) section); if you need  a `+` character in a token, make sure it's either not first on a line, or it's part of a larger token, or it's on a line all by itself

None of this applies to passwordlist files, which always treat spaces and symbols (except for carriage-returns and line-feeds) verbatim, treating them as parts of a password.

### Unicode Support ###

This one’s easy... there is none.

All input to *btcrecover* must be 7-bit ASCII. The current version of Armory (which is what *btcrecover* was originally developed for) has this same limitation, so there should be no problems with Armory wallets. Bitcoin Core, MultBit Classic, and Electrum support Unicode passwords. It would be theoretically possible to add Unicode support (at least for the Basic Multilingual Plane, which is what Python supports decently; the SMP would be harder, especially with support for the typos feature), however none of the software wallets normalize their Unicode strings before passing them along to their key derivation functions, and this could cause issues.

In short, Unicode support is something I’d like to add if there’s a significant demand for it, but it will never be perfect. In the mean time, as long as your password consists only of ASCII characters, it should work without any issues.

### Resource Usage ###

#### Memory ####

When *btcrecover* starts, it's first task is to count all the passwords it's about to try, looking for and recording duplicates for future reference (so that no password is tried twice) and also so it can display an ETA. This duplicate checking can take **a lot** of memory, depending on how many passwords need to be counted, but in some circumstances it can also save a lot of time. If *btcrecover* appears to hang after displaying the `Counting passwords ...` message, or if it outright crashes, try running it again with the `--no-dupchecks` option. After this initial counting phase, it doesn't use up much RAM as it searches through passwords.

Although this initial counting phase can be skipped by using the `--no-eta` option, it's not recommended. If you do use `--no-eta`, it's highly recommended that you also use `--no-dupchecks` at the same time.

You may want to always use a single `--no-dupchecks` option when working with MultiBit or Electrum wallets because the duplicate checking can actually decrease CPU efficiency (and always decreases memory efficiency) with these wallets in many cases.

If you specify `--no-dupchecks` more than once, it will disable even more of the duplicate checking logic:

 * 1 time - disables the most comprehensive and also the most memory intensive duplicate checking
 * 2 times - disables duplicate checking that rarely consumes much memory relative to the time it saves, although it may if the tokenlist file has a large number of tokens on relatively few lines with at least one but relatively few identical tokens
 * 3 times - disables duplicate checking which consumes very little memory relative to the duplicates it can potentially find; it's almost never useful to use this level
 * 4 times - disables duplicate checking which consumes no additional memory; it's never useful to use this level (and it's only available for debugging purposes)

#### CPU ####

By default, *btcrecover* tries to use as much CPU time as is available and spare. You can use the `--threads` option to decrease the number of worker threads (which defaults to the number of logical processors in your system) if you'd like to decrease CPU usage (but also the guess rate).

With MultiBit or Electrum wallets, *btcrecover* may not be able to effeciently use more than four or five CPU cores, sometimes even less depending on the contents of the tokenlist and the chosen typos. Specifying the `--no-dupchecks` option may help improve CPU usage and therefore the password guess rate in many cases with these two wallet types, and using slightly fewer or slightly greater `--threads` might also help. The only way to find out is to experiment.

*btcrecover* places itself in the lowest CPU priority class to minimize disruption to your PC while searching (but for Windows, it can only do this if you've installed the optional pywin32).

### Unsupported Wallet Types ###

As already mentioned, MultiBit HD is not supported. Electrum BIP32 wallets are also currently unsupported.

### Security Issues ###

Most Bitcoin wallet software goes to great lengths to protect your wallet password while it's stored unencrypted. *btcrecover* does not. This includes, but is not limited to:

 * you must create the tokenlist file which will probably have lots of sensitive password information in it, and save it to an unencrypted file;
 * no attempt is made to overwrite sensitive password information in RAM during or after running;
 * unless you use the `--no-dupchecks` option, a large amount of sensitive password information is stored in RAM temporarily, is not securely overwritten, and is very likely swapped out to the paging file where it could remain for a long time even after *btcrecover* has exited.

None of these issues are intentionally malicious, they should be considered security bugs. There are no workarounds for them, short of only running *btcrecover* inside a VM on a hard disk drive (not a solid-state drive) and securely deleting the VM once finished, all of which is far beyond the scope of this tutorial...

### Typos Gory Details ###

The intent of the typos features is to only apply at most one typo at a time to any single character, even when applying multiple typos to a single password guess. For example, when specifying `--typos 2 --typo-case --typo-repeat`, each password guess can have up to two typos applied (so two case changes, **or** two repeated characters, **or** one case change plus one repeated character, at most). No single character in a guess will have more than one typo applied to it in a single guess, e.g. a single character will never be both repeated and case-changed at the same time.

There are however some exceptions to this one-typo-per-character rule-- one intentional, and one due to limitations in the software.

The `--typos-capslock` typo simulates leaving the caps lock turned on during a guess. It can affect all the letters in a password at once even though it's a single typo. As in exception to the one-typo-per-character rule, a single letter *can* be affected by a caps lock typo plus another typo at the same time.

The `--typos-swap` typo also ignores the one-typo-per-character rule. Two adjacent characters can be swapped (which counts as one typo) and then a second typo can be applied to one (or both) of the swapped characters. This is more a software limitation than a design choice, but it's unlikely to change. You are however guaranteed that a single character will never be swapped more than once per guess.

Finally it should be noted that wildcard substitutions (expansions and contractions) occur before typos are applied, and that typos can be applied to the results of wildcard expansions. The exact order of password creation is:

 1. Create a "base" password from one or more tokens, following all the token rules (mutual exclusion, anchors, etc.).
 2. Apply all wildcard expansions and contractions.
 3. Apply up to a single caps lock typo.
 4. Apply zero or more swap typos.
 5. Apply zero or more character-changing typos (these typos *do* follow the one-typo-per-character rule).
 6. Apply zero or more typo insertions (from the `typos-insert` option).

At no time will the total number of typos in a single guess be more than requested with the `--typos #` option (nor will it be less than the `--min-typos` option if it's used).

# Copyright and License #

btcrecover.py -- Bitcoin wallet password recovery tool

Copyright (C) 2014 Christopher Gurnee

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License version 2 as published by the Free Software Foundation.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License version 2 for more details.

You should have received a copy of the GNU General Public License along with this program; if not, write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
