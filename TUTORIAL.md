# *btcrecover* Tutorial #

*btcrecover* is an open source, multithreaded Bitcoin wallet password recovery tool with support for Armory, Bitcoin Core (a.k.a. Bitcoin-QT), MultiBit (a.k.a. MultiBit Classic, MultiBit HD is not supported), and Electrum. It is designed for the case where you already know most of your password, but need assistance in trying different possible combinations. This tutorial will guide you through the features it has to offer.

If you find *btcrecover* helpful, please consider a small donation:
**[17LGpN2z62zp7RS825jXwYtE7zZ19Mxxu8](bitcoin:17LGpN2z62zp7RS825jXwYtE7zZ19Mxxu8?label=btcrecover)**

#### Thank You! ####

## The Token File ##

*btcrecover* accepts as input a file which has a list of what are called password “tokens”, which are parts of a password, and then it combines these tokens in different ways to create different passwords to try.

### Basics ###

Let’s say that you remember your password contains 3 parts, you just can’t remember in what order you used them. Here are the contents of an example token file:

    Cairo
    Beetlejuice
    Hotel_california

When used with these contents, *btcrecover* will try all possible combinations using one or more of these three tokens, e.g. `Hotel_california` (just one token), `BettlejuiceCairo` (two tokens pasted together), etc.

### Mutual Exclusion ###

Maybe you’re not sure about how you spelled or capitalized one of those words. Take this token file:

    Cairo
    Beetlejuice beetlejuice Betelgeuse betelgeuse
    Hotel_california

Tokens listed on the same line, separated by whitespace, are mutually exclusive. *btcrecover* will try `Cairo` and `bettlejuiceCairoHotel_california`, but it will skip over `Betelgeusebetelgeuse`. Had all four Beetlejuice versions been listed out on separate lines, this would have resulted in trying thousands of additional passwords which we know to be incorrect. As is, this token file only needs to try 48 passwords to account for all possible combinations. Had they all been on separate lines, it would have to try 1,956 different combinations. In short, when you’re sure that certain tokens or variations of a token have no chance of appearing together in a password, placing them all on the same line can save a lot of time.

### Required Tokens ###

What if you’re certain that `Cairo` appears in the password, but you’re not so sure about the other tokens?

    + Cairo
    Beetlejuice beetlejuice Betelgeuse betelgeuse
    Hotel_california

Placing a `+` (and some whitespace after it) at the beginning of a line tells *btcrecover* to only try passwords that include `Cairo` in them. You can also combine these two last features. Here’s a longer example:

    Cairo cairo Katmai katmai
    + Beetlejuice beetlejuice Betelgeuse betelgeuse
    Hotel_california hotel_california

In this example above, passwords will be constructed by taking at most one token from the first line, exactly one token from the second line (it’s required), and at most one token from the third line. So `Hotel_californiaBetelgeuse` would be tried, but `cairoKatmaiBetelgeuse` would be skipped (those first two tokens are on the same line, so they’re never tried together) and `katmaiHotel_california` is also skipped (because one token from the second line is required in every try). This file would try a total of 244 different combinations. Listing all ten of those tokens on separate lines and trying every single possible combination would take 9,864,100 tries... quite a bit more painful.

### Anchors ###

Another way to save time is to use “anchors”. You can tell *btcrecover* that certain tokens, if they are present at all, are definitely at the beginning or end of the password:

    ^Cairo
    Beetlejuice beetlejuice Betelgeuse betelgeuse
    Hotel_california$

In this example above, the `^` symbol is considered special if it appears at the beginning of any token (it’s not actually a part of the password), and the `$` symbol is special if it appears at the end of any token. `Cairo`, if it is present, is only tried at the beginning of a password, and `Hotel_california`, if it is present, is only tried at the end. As before, all of these can be combined:

    Cairo
    Beetlejuice
    + ^Hotel_california ^hotel_california

In this example above, either `Hotel_california` or `hotel_california` is required at the beginning of every password that is tried (and the other two tokens are tried normally after that).

### Token Counts ###

There are a number of command line options that affect the combinations tried. The `--max-tokens` option limits the number of tokens that are added together and tried. With `--max-tokens` set to 2, `Hotel_californiaCairo`, made from two tokens, would be tried from that last example, but `Hotel_californiaCairoBeetlejuice` would be skipped because it’s made from three tokens. You can still use *btcrecover* even if you have a large number of tokens, as long as `--max-tokens` is set to something reasonable. If you’d like to re-run *btcrecover* with a larger number of `--max-tokens` if at first it didn’t succeed, you can also specify `--min-tokens` to avoid trying combinations you’ve already tried.

### Wildcards ###

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
 * `%c`    - a single character from a custom set specified at the command line with `--custom-wild characters`
 * `%C`    - an uppercase version of `%c` (might be the same as `%c`, depending on how you set it)
 * `%ic`   - a case-insensitive version of `%c`
 * `%%`    - exactly one “%” (so that %’s in your password aren’t confused as wildcards)
 * `%^`    - exactly one “^” (so it’s not confused with an anchor if it’s at the beginning of a token)
 * `%S`    - exactly one “$” (yes, that’s % and a capital S that gets replaced by a dollar sign, sorry if	that’s confusing)

Up until now, most of the features help by reducing the number of passwords that need to be tried by exploiting your knowledge of what’s probably in the password. Wildcards significantly expand the number of passwords that need to be tried, so they’re best used in moderation.


## Typos ##

This next feature also expands the number of passwords that need to be tried. It’s an attempt to guess possible typos you may have inadvertently made while first typing in the password, although it can be useful for other purposes too. It’s enabled with the `--typos #` command line option (with `#` replaced with a count of typos). With this option, you tell *btcrecover* up to how many typos you’d like it to add to each password (that’s generated from the rules above), along with a list of different types of typos you’d like it to test, and it goes through all possible combinations for you (including the no-typos-present possibility). Here is a summary of the basic types of typos:

 * `--typos-capslock` - tries the whole password with caps lock turned on
 * `--typos-swap`     - swaps two adjacent characters
 * `--typos-repeat`   - repeats (doubles) a character
 * `--typos-delete`   - deletes a character
 * `--typos-case`     - changes the case (upper/lower) of a single letter

For example, with `--typos 2 --typos-capslock --typos-repeat` specified on the command line, all combinations containing up to two typos will be tried, e.g. `Cairo` (no typos), `cAIRO` (one typo: caps lock), `CCairoo` (two typos: both repeats), and `cAIROO` (two typos: one of each type) will be tried. Adding lots of typo types to the command line can significantly increase the number of combinations, and increasing the `--typos` count can be even more dramatic, so it’s best to tread lightly when using this feature unless you have a small token file.

Here are some additional types of typos that require a bit more explanation:

 * `--typos-closecase` - Like `--typos-case`, but it only tries changing the case of a letter if that letter is next to another letter with a different case. This produces fewer combinations to try so it will run faster, and it will still catch the more likely instances of someone holding down shift for too long or for not long enough.

 * `--typos-insert s`  - This tries inserting the specified string (in the example, an “s”) in between each pair of characters (and also at the end). The string can be a single letter, or some longer string (in which case the string is inserted in its entirety), or even a string with one or more wildcards in it. Of course, using wildcards can drastically increase the total number of combinations...

 * `--typos-replace s` - Just like `--typos-insert`, but instead of inserting the string, this removes a single character and puts the string (or the wildcard substitutions) in that character’s place.

#### Typos Map ####

 * `--typos-map file`   - This is a relatively complicated, but also flexible type of typo. It tries replacing certain specific characters with certain other specific characters, using a separate file to spell out the details. For example, if you know that you often make mistakes with punctuation, you could create a typos-map file which has these two lines in it:

        .    ,/;
        ;    [‘/.


    In this example, *btcrecover* will try replacing each `.` with one of the three punctuation marks which follow the spaces on the same line, and it will try replacing each `;` with one of the four punctuation marks which follow it. This feature can be used for more than just typos... for example, if you’re a fan of “1337” (leet) speak in your passwords, you could create a typos-map along these lines:

        aA    @
        sS    $5
        oO    0
    
    This would try replacing instances of `a` or `A` with `@`, instances of `s` or `S` with either a `$` or a `5`, etc., up to the maximum number of typos specified with the `--typos #` option. For example, if the token file contained the token `Passwords`, and if you specified `--typos 3`, `P@55words` and `Pa$$word5` would both be tried because they each have three typos/replacements, but `P@$$w0rd5` with its 5 typos would not be tried.

## Interrupt and Continue ##

Depending on the number of passwords which need to be tried, running *btcrecover* might take a very long time. If you need to cancel it in the middle of testing, you can do so with Ctrl-C (hold down the Ctrl key and press C) and it will respond with a message such as:

    Interrupted after finishing password # 357449

If you then restart it using the exact same options, and with the exact same token file (and typos-map file if you’re using one), you can add the `--skip 357449` option to the end and it will start up exactly where it had left off.

### Autosave ###

To make it even safer, you can add the `--autosave savefile` option when you first start *btcrecover*. It will automatically save its progress about every 5 minutes to the file that you specify (in this case, it was named `savefile` – you can just make up any file name, as long as it doesn’t already exist).

If you cancel in the middle of testing (with Ctrl-C, or due to a reboot, or for any other reason), you can restart testing by either running the exact same command with the exact same options, or by providing this option and nothing else: `--restore savefile`. *btcrecover* will check that the token file hasn’t changed, and it will begin testing with the same set of options exactly where it left off. (Note that the token file, as well as the typos-map file, if used, must still be present and must be unmodified for this to work. If they are not present or if they’ve been changed, *btcrecover* will refuse to start.)

## Testing your config ##

If you'd just like to test your token file and chosen typos, you can use the `--listpass` option (in which case you don't need to supply a wallet file). *btcrecover* will then list out all the passwords to the screen instead of actually testing them against a wallet file. This can also be useful if you have another tool which can test some other type of wallet, and is capable of taking a list of passwords to test from *btcrecover*.

## Installation ##

Just download the latest version from https://github.com/gurnec/btcrecover/archive/master.zip and unzip to a location of your choice. There’s no installation procedure for *btcrecover* itself, however there are additional requirements depending on your operating system and the wallet type you’re trying to recover.

### Armory (on any OS)###

You must have Armory installed if you’re trying to recover an Armory password. *btcrecover* has only been tested with Armory version 0.91; other versions may not work at all or may only work after some changes have been made. If *btcrecover* is unable to locate the Armory installation directory automatically, you may need to move the *btcrecover* files into the Armory `Program Files` or `lib` directory, or learn how to use the `PYTHONPATH` environment variable.

### Windows – Armory ###

In addition to requiring Armory 0.91, you will also need to download and install:

 * The latest version of Python 2.7, 32-bit (it must be the 32-bit version). Currently this is the “Python 2.7.6 Windows Installer” available here: https://www.python.org/download/

### Windows – Bitcoin Core, MultiBit Classic, or Electrum ###

With this combination, you will also need to download and install:

 * The latest version of Python 2.7, either the 32-bit version or the 64-bit version. Currently this is the “Python 2.7.6 Windows Installer” for the 32-bit version, or “Python 2.7.6 Windows X86-64 Installer” for the 64-bit version (which is preferable if you have a 64-bit version of Windows), both available here: https://www.python.org/download/

 * Optional, but highly recommended for MultiBit or Electrum: The latest binary version of PyCrypto for Python 2.7, either the 32-bit version or the 64-bit version to match your version of Python. Currently this is “PyCrypto 2.6 for Python 2.7 32bit” or “PyCrypto 2.6 for Python 2.7 64bit” available here: http://www.voidspace.org.uk/python/modules.shtml#pycrypto

 * Optional, allows *btcrecover* to run as a low-priority process so it doesn’t hog your CPU: The latest version of pywin32 for Python 2.7, either the 32-bit version or the 64-bit version to match your version of Python. Currently this is “pywin32-218.win32-py2.7.exe” for the 32-bit version or “pywin32-218.win-amd64-py2.7.exe” for the 64-bit version available in the “Build 218” folder here: http://sourceforge.net/projects/pywin32/files/pywin32/

### Linux or OS X – Bitcoin Core, MultiBit Classic, or Electrum###

 * Python 2.7.x – Most distributions include this pre-installed.

 * Optional, but highly recommended for MultiBit or Electrum: PyCrypto for Python 2.7.x – Many distributions include this pre-installed, check your distribution’s package management system to see if this is available. It is often called “python2.7 crypto”. If not, try installing it by using PyPI, for example on Debian-like distributions:

        sudo apt-get install python-pip
        sudo pip install pycrypto

## Running *btcrecover* ##

After installation, **make a copy of your wallet file into a different directory** (to make it easy, right into the *btcrecover* directory), create your token file (e.g. with Notepad), and run *btcrecover* with the options you’d like. It is a command-line tool which runs at a command prompt. As a simple example, running it on Windows would involve opening a Command Prompt and typing something like this:

    cd \Users\Chris\Downloads\btcrecover-master
    C:\python27\python btcrecover.py --wallet wallet.dat --tokenlist tokens.txt

Locating your wallet file is up to you... Google/Bing are your friends (but read below for a special note about MultiBit). If you insist on running it without making a separate copy of your wallet file (but don’t do that), please be sure to close your Bitcoin wallet software first.

Running with the `--help` option will give you a summary of the available options, most of which are described above, and can be placed after the required `--wallet wallet.dat --tokenlist tokens.txt` options in the command line in any order.

### Command Line Options inside the tokenlist file ###

If you'd prefer, you can also place command line options directly inside the tokenlist file. In order to do this, the very first line of the tokenlist file must begin with exactly `#--`, and the rest of this line (and only this line) is interpreted as additional command line options. For example, if you use the `%c` custom wildcard set, you can put the `--custom-wild` option inside the tokenlist file (along with other options) like this:

    #--custom-wild abcdABCD --autosave mysave --pause
    a_password_with_three_letters_from_above_appended_%3c

### btcrecover-tokens-auto.txt ###

Normally, when you run *btcrecover* it expects you to run it with at least a few options, such as the location of the token file and of the wallet file. If you run it without specifying the `--tokenlist`, it will check to see if there is a file named `btcrecover-tokens-auto.txt` in the current directory, and if found it will use that for the tokenlist. Because you can specify options inside the tokenlist file if you'd prefer, this allows you to run *btcrecover* without using the command line at all. You may want to consider using the `--pause` option to prevent a command window from immediately closing once it's done running if you decide to run it this way.

### Finding MultiBit Wallet Files ###

*btcrecover* doesn’t operate directly on MultiBit wallet files, instead it operates on MultiBit private key backup files. Each time you change your wallet password (including the first time you add a password), plus on certain other occasions, MultiBit creates an encrypted private key backup file in a `key-backup` directory (see the link below for more details). These private key backup files are much faster to try passwords against (by a factor of over 1,000), which is why *btcrecover* uses them. Unfortunately, it’s up to you to locate the correct private key backup file for the wallet whose password you need to recover. If you only have one MultiBit wallet, you can just choose the most recent private key backup file. Otherwise, you need to locate a private key backup file that has a date of when you either changed the password of, or added new addresses to the wallet you’d like to recover.

For more details on locating your MultiBit private key backup files, see: https://www.multibit.org/en/help/v0.5/help_fileDescriptions.html

# Limitations / Caveats #

### Beta Software ###

Although this software is unlikely to harm any wallet files, **you are strongly encouraged to only run it with copies of your wallets**. In particular, this software is distributed **WITHOUT ANY WARRANTY**; please see the accompanying GPLv2 licensing terms for more details.

Because this software is beta software, and also because it interacts with other beta software, it’s entirely possible that it may fail to find a password which it’s been correctly configure to find.

#### OS X ####
Mac OS X support is completely untested.

### Delimiters, Spaces, and Special Symbols in Passwords###

By default, *btcrecover* uses one or more whitespace to separate tokens in the tokenlist file, and to separated to-be-replaced characters from their replacements in the typos-map file. It also ignores any extra whitespace in these files. This makes it impossible to test passwords which include spaces.

The `--delimiter` option allows you to change this behavior. If used, whitespace is no longer ignored, nor is extra whitespace stripped. Instead, the new `--delimiter` string must be used *exactly as specified* to separate tokens. Any whitespace becomes a part of a token, so you must take care not to add any inadvertent whitespace to these files.

Additionally, *btcrecover* considers the following symbols special under certain specific circumstances in the tokenlist file. A special symbol is part of the tokenlist syntax, and not part of a password.

 * `%` - always considered special; `%%` in a token will be replaced by `%` during searches    
 * `^` - only special if it's the first character of a token; `%^` will be replaced by `^` during searches
 * `$` - only special if it's the last character of a token; `%S` (note the capital `S`) will be replaced by `$` during searches
 * `#` - only special if it's the first character on a line, the rest of the line is then ignored (a comment); note that if `#--` is at the very beginning of the file, then the first line is parsed as additional command line options
 * `+` - only special if it's the first token (after possibly stripping whitespace) on a line, followed by a delimiter, and then followed by other token(s) (see the *Mutual Exclusion* section); if you need  a `+` character in a token, make sure it's either not first on a line, or it's part of a larger token, or it's on a line all by itself

### Unicode Support ###

This one’s easy... there is none.

All input to *btcrecover* must be 7-bit ASCII. The current version of Armory (which is what *btcrecover* was originally developed for) has this same limitation, so there should be no problems with Armory wallets. Bitcoin Core, MultBit Classic, and Electrum support Unicode passwords. It would be theoretically possible to add Unicode support (at least for the Basic Multilingual Plane, which is what Python supports decently; the SMP would be harder, especially with support for the typos feature), however none of the software wallets normalize their Unicode strings before passing them along to their key derivation functions, and this could cause issues.

In short, Unicode support is something I’d like to add if there’s a significant demand for it, but it will never be perfect.

### Resource Usage ###

#### Memory ####

When *btcrecover* starts, it's first task is to count all the passwords it's about to try, looking for and recording duplicates for future reference (so that no password is tried twice). This duplicate checking can take **a lot** of memory, depending on how many passwords need to be counted. If *btcrecover* appears to hang after displaying the `Counting passwords ...` message, or if it outright crashes, try running it again with the `--no-dupchecks` option. After this initial counting phase, it doesn't use up much RAM as it searches through passwords.

You may want to always use the `--no-dupchecks` option when working with MultiBit key files or Electrum wallets because the duplicate checking saves very little time with these in most cases.

#### CPU ####

By default, *btcrecover* tries to use as much CPU time as is available and spare. You can use the `--threads` option to decrease the number of threads if you'd like to decrease CPU usage. Under some circumstances, increasing the `--threads` option a little may improve search performance (usually only with MultiBit or Electrum).

*btcrecover* places itself in the lowest CPU priority class to minimize disruption to your PC while searching (but for Windows, it can only do this if you've installed the optional pywin32).

### Unsupported Wallet Types ###

As already mentioned, MultiBit HD is not supported. Electrum BIP32 wallets are also currently unsupported.

### Security Issues ###

Most Bitcoin wallet software goes to great lengths to protect your wallet password. *btcrecover* does practically nothing. This includes, but is not limited to:

 * you must create the tokenlist file which probably will have lots of sensitive password information in it, and save it to a file unencrypted;
 * no attempt is made to overwrite sensitive password information in RAM during or after running;
 * unless you use the `--no-dupchecks` option, a large amount of sensitive password information is stored in RAM temporarily, is not overwritten, and is very likely swapped out to the paging file where it could remain for a long time even after *btcrecover* has exited.

There are no fixes to any of these issues, short of only running *btcrecover* inside a VM on a hard disk drive (not a solid-state drive) and securely deleting the VM once finished, all of which is far beyond the scope of this tutorial... 

### Typos Gory Details ###

TODO

# Copyright and License #

btcrecover.py -- Bitcoin wallet password recovery tool

Copyright (C) 2014 Christopher Gurnee

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License version 2 as published by the Free Software Foundation.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License version 2 for more details.

You should have received a copy of the GNU General Public License along with this program; if not, write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
