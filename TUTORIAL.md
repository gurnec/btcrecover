# *btcrecover* Tutorial #


*btcrecover* is a free and open source multithreaded wallet password recovery tool with support for Armory, Bitcoin Unlimited/Classic/XT/Core, MultiBit (Classic and HD), Electrum (1.x and 2.x), mSIGNA (CoinVault), Hive for OS X, Blockchain.info (v1-v3 wallet formats, both main and second passwords), Bither, and Bitcoin & KNC Wallets for Android. It is designed for the case where you already know most of your password, but need assistance in trying different possible combinations. This tutorial will guide you through the features it has to offer.

If you find *btcrecover* helpful, please consider a small donation to help support my efforts:
**[3Au8ZodNHPei7MQiSVAWb7NB2yqsb48GW4](bitcoin:3Au8ZodNHPei7MQiSVAWb7NB2yqsb48GW4?label=btcrecover)**

#### Thank You! ####


## Quick Start ##

This tutorial is pretty long... you don't have to read the whole thing. Here are some places to start.

 1. Read the [Installation Guide](docs/INSTALL.md) for instructions and download links.
 2. (optional) Run the unit tests by double-clicking on `run-all-tests.py`. If you encounter any failures, please [report them here](https://github.com/gurnec/btcrecover/issues).
 3. If you already have a `btcrecover-tokens-auto.txt` file, skip straight to step 6.  If not, and you need help creating passwords from different combinations of smaller pieces you remember, start with step 4. If you you think there's a typo in your password, or if you mostly know what your whole password is and only need to try different variations of it, read step 5.
 4. Read [The Token File](#the-token-file) section (at least the beginning), which describes how *btcrecover* builds up a whole password you don't remember from smaller pieces you do remember. Once you're done, you'll know how to create a `tokens.txt` file you'll need later.
 5. Read the [Typos](#typos) section, which describes how *btcrecover* can make variations to a whole password to create different password guesses. Once you're done, you'll have a list of command-line options which will create the variations you want to test.
     * If you skipped step 4 above, read the simple [Passwordlist](#the-passwordlist) section instead.
 6. Read the [Running *btcrecover*](#running-btcrecover) section to see how to put these pieces together and how to run *btcrecover* in a Command Prompt window.
     * (optional) Read the [Testing your config](#testing-your-config) section to view the passwords that will be tested.
     * (optional) If you're testing a lot of combinations that will take a long time, use the [Autosave](#autosave) feature to safeguard against losing your progress.
 7. (optional, but highly recommended) Donate huge sums of Bitcoin to the donation address above once your password's been found.


## The Token File ##

*btcrecover* can accept as input a text file which has a list of what are called password “tokens”. A token is simply a portion of a password which you do remember, even if you don't remember where that portion appears in the actual password. It will combine these tokens in different ways to create different whole password guesses to try.

This file, typically named `tokens.txt`, can be created in any basic text editor, such as Notepad on Windows or TextEdit on OS X, and should probably be saved into the same folder as the `btcrecover.py` script (just to keep things simple). Note that if your password contains any non-[ASCII](https://en.wikipedia.org/wiki/ASCII) (non-English) characters, you should read the section on [Unicode Support](#unicode-support) before continuing. 

### Basics ###

Let’s say that you remember your password contains 3 parts, you just can’t remember in what order you used them. Here are the contents of a simple `tokens.txt` file:

    Cairo
    Beetlejuice
    Hotel_california

When used with these contents, *btcrecover* will try all possible combinations using one or more of these three tokens, e.g. `Hotel_california` (just one token), `BettlejuiceCairo` (two tokens pasted together), etc.

Note that lines which start with a `#` are ignored as comments, but only if the `#` is at the *very beginning* of the line:

    # This line is a comment, it's ignored.
    # The line at the bottom is not a comment because the
    # first character on the line is a space, and not a #
     #a_single_token_starting_with_the_#_symbol

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
    ^,3^Third_or_earlier(but_never_first_or_last)
    ^,^Anywhere_in_the_middle
    Cairo
    Beetlejuice
    Hotel_california

You can't leave out the comma (that's what makes it a middle anchor instead of a positional anchor). Leaving out a number doesn't change the “never at the beginning or the end” rule which always applies to middle anchors. If you do need a token with a middle anchor to also possibly appear at the beginning or end of a password, you can add second copy to the same line with a beginning or end anchor (because at most one token on a line can appear in any guess):

    ^,^Anywhere_in_the_middle_or_end        Anywhere_in_the_middle_or_end$
    ^,^Anywhere_in_the_middle_or_beginning ^Anywhere_in_the_middle_or_beginning

#### Relative Anchors ####

Relative anchors restrict the position of tokens relative to one another. They are only affected by other tokens which also have relative anchors. They look like positional anchors, except they have a single `r` preceding the relative number value:

    ^r1^Earlier
    ^r2^Middlish_A
    ^r2^Middlish_B
    ^r3^Later
    Anywhere

In this example above, if two or more relative-anchored tokens appear together in a single password guess, they appear in their specified order. `Earlier Anywhere Later` and `Anywhere Middlish_A Later` would be tried, however `Later Earlier` would not. Note that `Middlish_A` and `Middlish_B` can appear in the same guess, and they can appear with either being first since they have a matching relative value, e.g. `Middlish_B Middlish_A Later` would be tried.

You cannot specify a single token with both a positional and relative anchor at the same time.

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
 * `%a`    - a single ASCII lowercase letter
 * `%1,3a` - between 1 and 3 lowercase letters
 * `%A`    - a single ASCII uppercase letter
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

### Backreference Wildcards ###

Backreference wildcards copy one or more characters which appear somewhere earlier in the password. In the simplest case, they're not very useful. For example, in the token `Z%b`, the `%b` simply copies the character which immediately precedes it, resulting in `ZZ`.

Consider the case where the password contains patterns such as `AA`, `BB`, up through `ZZ`, but would never contain `AZ`. You could use `%2A` to generate these patterns, but then you'd end up with `AZ` being tried. `%2A` generates 676 different combinations, but in this example we only want to try 26. Instead you can use two wildcards together: `%A%b`. The `%A` will expand into a single letter (from `A` to `Z`), and *after* this expansion happens, the `%b` will copy that letter, resulting in only the 26 patterns we want.

As with normal wildcards, backreference wildcards may contain a copy length, for example:

 * `Test%d%b`    - `Test00` through `Test99`, but never `Test12`
 * `Test%d%2b`   - `Test000` through `Test999`, but never `Test123`
 * `Test%d%0,3b` - `Test0` to `Test9` (the backreference length is 0), `Test00` to `Test99`, etc., `Test0000` to `Test9999`

In the examples so far, the copying starts with the character immediately to the left of the `%b`, but this can be changed by adding a `;#` just before the `b`, for example:

 * `Test%b`       - `Testt`
 * `Test%;1b`     - starts 1 back, same as above, `Testt`
 * `Test%;2b`     - starts 2 back, `Tests`
 * `Test%;4b`     - starts 4 back, `TestT`
 * `Test%2;4b`    - starts 4 back, with a copy length of 2: `TestTe`
 * `Test%8;4b`    - starts 4 back, with a copy length of 8: `TestTestTest`
 * `Test%0,2;4b`  - starts 4 back, with a copy length from 0 to 2: `Test`, `TestT`, and `TestTe`
 * `%2Atest%2;6b` - patterns such as `ABtestAB` and `XKtestXK` where the two capital letters before and after `test` match each other, but never `ABtestXK` where they don't match

To summarize, wildcards to the left of a `%b` are expanded first, and then the `%b` is replaced by copying one or more characters from the left, and then wildcards towards the right (if any) are examined.

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

### Keyboard Walking — Backreference Wildcards, revisited ###

This feature combines traits of both backreference wildcards and typos maps into a single function. If you haven't read about typos maps below (or about backreference wildcards above), you should probably skip this section for now and come back later.

Consider a complex password pattern such as this: `00test11`, `11test22`, etc. up through `88test99`. In other words, the pattern is generated by combining these 5 strings: `#` `#` `test` `#+1` `#+1`. Using simple backreference wildcards, we can almost produce such a pattern with this token: `%d%btest%d%b`. This produces everything from our list, but it also produced a lot more that we don't want, for example `33test55` is produced even though it doesn't match the pattern because 3+1 is not 5.

Instead a way is needed for a backreference wildcard to do more than simply copy a previous character, it must be able to create a *modified copy* of a previous character. It can do this the same way that a typos map replaces characters by using a separate map file to determine the replacement. So to continue this example, a new map file is needed, `nextdigit.txt`:

    0 1
    1 2
    2 3
    3 4
    4 5
    5 6
    6 7
    7 8
    8 9

Finally, here's a token that makes use of this map file to generate the pattern we're looking for: `%d%btest%2;nextdigit.txt;6b`. That's pretty complicated, so let's break it down:

 * `%d`   - expands to `0` through `9`
 * `%b`   - copies the previous character, so no we have `00` through `99`
 * `test` - now we have `00test` through `99test`
 * `%2;nextdigit.txt;6b` - a single backreference wildcard which is made up of:
     * `2` - the copy length (the length of the result after expansion)
     * `nextdigit.txt` - the map file used determine how to modify characters
     * `6` - how far to the left of the wildcard to start copying; 6 characters counting leftwards from the end of `00test` is the first `0`

    The result of expanding this wildcard when the token starts off with `00test` is `00test11`. It expands into *two* `1`'s because the copy length is 2, and it expands into modified `1`'s instead of just copying the `0`'s because the file maps a `0` (in its first column) to a `1` (in the second column). Likewise, a `77test` is expanded into `77test88`. `99test` is expanded into `99test99` because the the lookup character, a `9`, isn't present in (the first column of) the map file, and so it's copied unmodified.

Note that when you use a map file inside a backreference wildcard, the file name always has a semicolon (`;`) on either side. These are all valid backreference wildcards (but they're all different because the have different copy lengths and starting positions): `%;file.txt;b`, `%2;file.txt;b`, `%;file.txt;6b`, `%2;file.txt;6b`.

The final example involves something called keyboard walking. Consider a password pattern where a typist starts with any letter, and then chooses the next character by moving their finger using a particular pattern, for example by always going either diagonal up and right, or diagonal down and right, and then repeating until the result is a certain length. A single backreference wildcard that uses a map file can create this pattern.

Here's what the beginning of a map file for this pattern, `pattern.txt`, would look like:

    q 2a
    a wz
    z s
    2 w
    w 3s
    ...

So if the last letter is a `q`, the next letter in the pattern is either a `2` or an `a` (for going upper-right or lower-right). If the last letter is a `z`, there's only one direction available for the next letter, upper-right to `s`. With this map file, and the following token, all combinations which follow this pattern between 4 and 6 characters long would be tried: `%a%3,5;pattern.txt;b`


## The Passwordlist ##

If you already have a simple list of whole passwords you'd like to test, and you don't need any of the features described above, you can use the `--passwordlist` command-line option (instead of the `--tokenlist` option as described later in the [Running *btcrecover*](#running-btcrecover) section). If your password contains any non-[ASCII](https://en.wikipedia.org/wiki/ASCII) (non-English) characters, you should read the section on [Unicode Support](#unicode-support) before continuing.

If you specify `--passwordlist` without a file, *btcrecover* will prompt you to type in a list of passwords, one per line, in the Command Prompt window. If you already have a text file with the passwords in it, you can use `--passwordlist FILE` instead (replacing `FILE` with the file name).

Be sure not to add any extra spaces, unless those spaces are actually a part of a password.

Each line is used verbatim as a single password when using the `--passwordlist` option (and none of the features from above are applied). You can however use any of the Typos features described below to try different variations of the passwords in the passwordlist.


## Typos ##

*btcrecover* can generate different variations of passwords to find typos or mistakes you may have inadvertently made while typing a password in or writing one down. This feature is enabled by including one or more command-line options when you run *btcrecover*.

If you'd just like some specific examples of command-line options you can add, please see the [Typos Quick Start Guide](docs/Typos_Quick_Start_Guide.md).

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

    The *btcrecover* package includes a few typos-map example files in the `typos` directory. You can read more about them in the [Typos Quick Start Guide](docs/Typos_Quick_Start_Guide.md#typos-maps).

### Max Typos by Type ###

As described above, the `--typos #` command-line option limits the total number of typos, regardless of type, that will ever be applied to a single guess. You can also set limits which are only applied to specific types of typos. For each of the `--typos-xxxx` command-line options above there is a corresponding `--max-typos-xxxx #` option.

For example, with `--typos 3 --typos-delete --typos-insert %a --max-typos-insert 1`, up to three typos will be tried. All of them could be delete typos, but at most only one will ever be an insert typo (which would insert a single lowercase letter in this case). This is particularly useful when `--typos-insert` and `--typos-replace` are used with wildcards as in this example, because it can greatly decrease the total number of combinations that need to be tried, turning a total number that would take far too long to test into one that is much more reasonable.


## Autosave ##

Depending on the number of passwords which need to be tried, running *btcrecover* might take a very long time. If it is interrupted in the middle of testing (with Ctrl-C (see below), due to a reboot, accidentally closing the Command Prompt, or for any other reason), you might lose your progress and have to start the search over from the beginning. To safeguard against this, you can add the `--autosave savefile` option when you first start *btcrecover*. It will automatically save its progress about every 5 minutes to the file that you specify (in this case, it was named `savefile` – you can just make up any file name, as long as it doesn’t already exist).

If interrupted, you can restart testing by either running it with the exact same options, or by providing this option and nothing else: `--restore savefile`. *btcrecover* will then begin testing exactly where it had left off. (Note that the token file, as well as the typos-map file, if used, must still be present and must be unmodified for this to work. If they are not present or if they’ve been changed, *btcrecover* will refuse to start.)

The autosave feature is not currently supported with passwordlists, only with token files.


### Interrupt and Continue ###

If you need to interrupt *btcrecover* in the middle of testing, you can do so with Ctrl-C (hold down the Ctrl key and press C) and it will respond with a message such this and then it will exit:

    Interrupted after finishing password # 357449

If you didn't have the autosave feature enabled, you can still manually start testing where you left off. You need to start *btcrecover* with the *exact same* token file or passwordlist, typos-map file (if you were using one), and command-line options plus one extra option, `--skip 357449`, and it will start up right where it had left off.


## Unicode Support ##

If your password contains any non-[ASCII](https://en.wikipedia.org/wiki/ASCII#ASCII_printable_code_chart) (non-English) characters, you will need to add the `--utf8` command-line option to enable Unicode support.

Please note that all input to and output from *btcrecover* must be UTF-8 encoded (either with or without a Byte Order Mark, or "BOM"), so be sure to change the Encoding to UTF-8 when you save any text files. For example in Windows Notepad, the file *Encoding* setting is right next to the *Save* button in the *File* -> *Save As...* dialog.

On Windows (but usually not on Linux or OS X), you may have trouble if any of the command line options you need to use contain any non-ASCII characters. Usually, if it displays in the command prompt window correctly when you type it in, it will work correctly with `btcrecover.py`. If it doesn't display correctly, please read the section describing how to put [command-line options inside the tokens file](#command-line-options-inside-the-tokens-file).

Also on Windows (but usually not on Linux or OS X), if your password is found it may not be displayed correctly in the command prompt window. Here is an example of what an incorrect output might look like:

    Password found: 'btcr-????-??????'
    HTML encoded:   'btcr-&#1090;&#1077;&#1089;&#1090;-&#1087;&#1072;&#1088;&#1086;&#1083;&#1100;'

As you can see, the Windows command prompt was incapable of rendering some of the characters (and they were replaced with `?` characters). To view the password that was found, copy and paste the `HTML encoded` line into a text file, and save it with a name that ends with `.html` instead of the usual `.txt`. Double-click the new `.html` file and it will open in your web browser to display the correct password:

    HTML encoded: 'btcr-тест-пароль'


## Running *btcrecover* ##

(Also see the [Quick Start](#quick-start) section.) After you've installed all of the requirements (above) and have downloaded the latest version:

 1. Unzip the `btcrecover-master.zip` file, it contains a single directory named "btcrecover-master". Inside the btcrecover-master directory is the Python script (program) file `btcrecover.py`.
 2. **Make a copy of your wallet file** into the directory which contains `btcrecover.py`. On Windows, you can usually find your wallet file by clicking on the Start Menu, then “Run...” (or for Windows 8+ by holding down the *Windows* key and pressing `r`), and then typing in one of the following paths and clicking OK. Some wallet software allows you to create multiple wallets, for example Armory wallets have an ID which you can view in the Armory interface, and the wallet file names contain this ID. Of course, you need to be sure to copy the correct wallet file.
     * Armory - `%appdata%\Armory` (it's a `.wallet` file)
     * Bitcoin Unlimited/Classic/XT/Core - `%appdata%\Bitcoin` (it's named `wallet.dat`)
     * Bitcoin Wallet for Android/BlackBerry, lost spending PINs - Please see the [Bitcoin Wallet for Android/BlackBerry Spending PINs](#bitcoin-wallet-for-androidblackberry-spending-pins) section below.
     * MultiBit Classic - Please see the [Finding MultiBit Classic Wallet Files](#finding-multibit-classic-wallet-files) section below.
     * MultiBit HD - `%appdata%\MultiBitHD` (it's in one of the folders here, it's named `mbhd.wallet.aes`)
     * Electrum - `%appdata%\Electrum\wallets`
     * BIP-39 passphrases (e.g. TREZOR) - Please see the [BIP-39 Passphrases](#bip-39-passphrases) section below.
     * mSIGNA - `%homedrive%%homepath%` (it's a `.vault` file)
     * Bither - `%appdata%\Bither` (it's named `address.db`)
     * Blockchain.info - it's usually named `wallet.aes.json`; if you don't have a backup of your wallet file, you can download one by running the `download-blockchain-wallet.py` tool in the `extract-scripts` directory if you know your wallet ID (and 2FA if enabled)
     * Litecoin-Qt - `%appdata%\Litecoin` (it's named `wallet.dat`)
 3. If you have a `btcrecover-tokens-auto.txt` file, you're almost done. Copy it into the directory which contains `btcrecover.py`, and then simply double-click the `btcrecover.py` file, and *btcrecover* should begin testing passwords. (You may need to rename your wallet file if it doesn't match the file name listed insided the `btcrecover-tokens-auto.txt` file.) If you don't have a `btcrecover-tokens-auto.txt` file, continue reading below.
 4. Copy your `tokens.txt` file, or your passwordlist file if you're using one, into the directory which contains `btcrecover.py`.
 5. You will need to run `btcrecover.py` with at least two command-line options, `--wallet FILE` to identify the wallet file name and either `--tokenlist FILE` or `--passwordlist FILE` (the FILE is optional for `--passwordlist`), depending on whether you're using a [Token File](#the-token-file) or [Passwordlist](#the-passwordlist). If you're using [Typos](#typos) or [Autosave](#autosave), please refer the sections above for additional options you'll want to add.
 6. Here's an example for both Windows and OS X. The details for your system will be different, for example the download location may be different, or the wallet file name may differ, so you'll need to make some changes. Any additional options are all placed at the end of the *btcrecover* line.
    * *Windows*: Open a Command Prompt window (click the Start Menu and type "command"), and type in the two lines below. 

            cd Downloads\btcrecover-master
            C:\python27\python btcrecover.py --wallet wallet.dat --tokenlist tokens.txt [other-options...]

    * *OS X*: Open a terminal window (open the Launchpad and search for "terminal"), and type in the two lines below.

            cd Downloads/btcrecover-master
            python btcrecover.py --wallet wallet.dat --tokenlist tokens.txt [other-options...]

After a short delay, *btcrecover* should begin testing passwords and will display a progress bar and an ETA as shown below. If it appears to be stuck just counting upwards with the message `Counting passwords ...` and no progress bar, please read the [Memory limitations](docs/Limitations_and_Caveats.md#memory) section. If that doesn't help, then you've probably chosen too many tokens or typos to test resulting in more combinations than your system can handle (although the [`--max-tokens`](#token-counts) option may be able to help).

    Counting passwords ...
    Done
    Using 4 worker threads
    439 of 7661527 [-------------------------------] 0:00:10, ETA:  2 days, 0:25:56

If one of the combinations is the correct password for the wallet, the password will eventually be displayed and *btcrecover* will stop running:

    1298935 of 7661527 [####-----------------------] 8:12:42, ETA:  1 day, 16:13:24
    Password found: 'Passwd42'

If all of the password combinations are tried, and none of them were correct for the wallet, this message will be dislayed instead:

    7661527 of 7661527 [########################################] 2 days, 0:26:06,
    Password search exhausted

Running `btcrecover.py` with the `--help` option will give you a summary of all of the available command-line options, most of which are described in the sections above.

### Testing your config ###

If you'd just like to test your token file and/or chosen typos, you can use the `--listpass` option in place of the `--wallet FILE` option as demonstrated below. *btcrecover* will then list out all the passwords to the screen instead of actually testing them against a wallet file. This can also be useful if you have another tool which can test some other type of wallet, and is capable of taking a list of passwords to test from *btcrecover*. Because this option can generate so much output, you may want only use it with short token files and few typo options.

        C:\python27\python btcrecover.py --listpass --tokenlist tokens.txt  | more

The `| more` at the end (the `|` symbol is a shifted `\` backslash) will introduce a pause after each screenful of passwords.

### Finding MultiBit Classic Wallet Files ###

*btcrecover* doesn’t operate directly on MultiBit Classic wallet files, instead it operates on MultiBit private key backup files. When you first add a password to your MultiBit Classic wallet, and after that each time you add a new receiving address or change your wallet password, MultiBit creates an encrypted private key backup file in a `key-backup` directory that's near the wallet file. These private key backup files are much faster to try passwords against (by a factor of over 1,000), which is why *btcrecover* uses them. For the default wallet that is created when MultiBit is first installed, this directory is located here:

    %appdata%\MultiBit\multibit-data\key-backup

The key files have names which look like `walletname-20140407200743.key`. If you've created additional wallets, their `key-backup` directories will be located elsewhere and it's up to you to locate them. Once you have, choose the most recent `.key` file and copy it into the directory containing `btcrecover.py` for it to use.

For more details on locating your MultiBit private key backup files, see: <https://www.multibit.org/en/help/v0.5/help_fileDescriptions.html>

### Bitcoin Wallet for Android/BlackBerry Spending PINs ###

Bitcoin Wallet for Android/BlackBerry has a *spending PIN* feature which can optionally be enabled. If you lose your spending PIN, you can use *btcrecover* to try to recover it.

 1. Open the Bitcoin Wallet app, press the menu button, and choose Safety.
 2. Choose *Back up wallet*.
 3. Type in a password to protect your wallet backup file, and press OK. You'll need to remember this password for later.
 4. Press the Archive button in the lower-right corner.
 5. Select a method of sharing the wallet backup file with your PC, for example you might choose Gmail or perhaps Drive.

This wallet backup file, once saved to your PC, can be used just like any other wallet file in *btcrecover* with one important exception: when you run *btcrecover*, you **must** add the `--android-pin` option. When you do, *btcrecover* will ask you for your backup password (from step 3), and then it will try to recover the spending PIN.

Because PINs usually just contain digits, your token file will usually just contain something like this (for PINs of up to 6 digits for example): `%1,6d`. (See the section on [Wildcards](#expanding-wildcards) for more details.)

Note that if you don't include the `--android-pin` option, *btcrecover* will try to recover the backup password instead.

### BIP-39 Passphrases ###

Some [BIP-39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) compliant wallets offer a feature to add a “BIP-39” or “plausible deniability” passphrase to your seed (mnemonic), most notably the TREZOR hardware wallet. (Note that most hardware wallets also offer a PIN feature which is not supported by *btcrecover*.)

If you know your seed, but don't remember this passphrase, *btcrecover* may be able to help. You will also need to know either:

 1. Preferably your master public key / “xpub”  (for the *first* account in your wallet, if it supports multiple accounts), *or*
 2. a receiving address that was generated by your wallet (in its first account), along with a good estimate of how many addresses you created before the receiving address you'd like to use.

Once you have this information, run *btcrecover* normally, except that *instead* of providing a wallet file on the command line as described above with the `--wallet wallet.dat` option, use the `--bip39` option, e.g.:

    C:\python27\python btcrecover.py --bip39 --tokenlist tokens.txt [other-options...]

If you have an Ethereum seed, also add the `--wallet-type ethereum` option. When you run this, you will be prompted for your master public key (or your address), and your seed.

**Note** that *btcrecover* assumes your wallet software is using both the BIP-39 the BIP-44 standards. If your wallet is not strictly complaint with these standards, *btcrecover* will probably not work correctly to find your passphrase. It may be possible to use the `--bip32-path` option to work correctly with a wallet using different standards—feel free to open an [issue on GitHub](https://github.com/gurnec/btcrecover/issues/new) if you're unsure of your wallet's compatibility with *btcrecover*.

### GPU acceleration for Bitcoin Unlimited/Classic/XT/Core, Armory, and Litecoin-Qt wallets ###

*btcrecover* includes experimental support for using one or more graphics cards or dedicated accelerator cards to increase search performance. This can offer on the order of *100x* better performance with Bitcoin Unlimited/Classic/XT/Core or Litecoin-Qt wallets when enabled and correctly tuned. With Armory (which uses a GPU-resistant key derivation function), this can offer a modest improvement of 2x - 5x.

For more information, please see the [GPU Acceleration Guide](docs/GPU_Acceleration.md).

### command-line options inside the tokens file ###

If you'd prefer, you can also place command-line options directly inside the `tokens.txt` file. In order to do this, the very first line of the tokens file must begin with exactly `#--`, and the rest of this line (and only this line) is interpreted as additional command-line options. For example, here's a tokens file which enables autosave, pause-before-exit, and one type of typo:

    #--autosave progress.sav --pause --typos 1 --typos-case
    Cairo
    Beetlejuice Betelgeuse
    Hotel_california

### btcrecover-tokens-auto.txt ###

Normally, when you run *btcrecover* it expects you to run it with at least a few options, such as the location of the tokens file and of the wallet file. If you run it without specifying `--tokenlist` or `--passwordlist`, it will check to see if there is a file named `btcrecover-tokens-auto.txt` in the current directory, and if found it will use that for the tokenlist. Because you can specify options inside the tokenlist file if you'd prefer (see above), this allows you to run *btcrecover* without using the command line at all. You may want to consider using the `--pause` option to prevent a Command Prompt window from immediately closing once it's done running if you decide to run it this way.


# Limitations & Caveats #

### Beta Software ###

Although this software is unlikely to harm any wallet files, **you are strongly encouraged to only run it with copies of your wallets**. In particular, this software is distributed **WITHOUT ANY WARRANTY**; please see the accompanying GPLv2 licensing terms for more details.

Because this software is beta software, and also because it interacts with other beta software, it’s entirely possible that it may fail to find a password which it’s been correctly configure by you to find.

### Additional Limitations & Caveats ###

Please see the separate [Limitations and Caveats](docs/Limitations_and_Caveats.md) documentation for additional details on these topics:

 * Delimiters, Spaces, and Special Symbols in Passwords
 * Memory & CPU Usage
 * Security Issues
 * Typos Details


# Copyright and License #

btcrecover -- Bitcoin wallet password and seed recovery tool

Copyright (C) 2014-2017 Christopher Gurnee

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program.  If not, see http://www.gnu.org/licenses/
