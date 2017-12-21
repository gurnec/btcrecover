## *btcrecover* Limitations & Caveats ##

### Beta Software ###

Although this software is unlikely to harm any wallet files, **you are strongly encouraged to only run it with copies of your wallets**. In particular, this software is distributed **WITHOUT ANY WARRANTY**; please see the accompanying GPLv2 licensing terms for more details.

Because this software is beta software, and also because it interacts with other beta software, it’s entirely possible that it may fail to find a password which it’s been correctly configure by you to find.

### Delimiters, Spaces, and Special Symbols in Passwords ###

By default, *btcrecover* uses one or more whitespaces to separate tokens in the tokenlist file, and to separated to-be-replaced characters from their replacements in the typos-map file. It also ignores any extra whitespace in these files. This makes it difficult to test passwords which include spaces and certain other symbols.

One way around this that only works for the tokenlist file is to use the `%s` wildcard which will be replaced by a single space. Another option that works both for the tokenlist file and a typos-map file is using the `--delimiter` option which allows you to change this behavior. If used, whitespace is no longer ignored, nor is extra whitespace stripped. Instead, the new `--delimiter` string must be used *exactly as specified* to separate tokens or typos-map columns. Any whitespace becomes a part of a token, so you must take care not to add any inadvertent whitespace to these files.

Additionally, *btcrecover* considers the following symbols special under certain specific circumstances in the tokenlist file (and for the `#` symbol, also in the typos-map file). A special symbol is part of the syntax, and not part of a password.

 * `%` - always considered special (except when *inside* a `%[...]`-style wildcard, see the [Wildcards](../TUTORIAL.md#expanding-wildcards) section); `%%` in a token will be replaced by `%` during searches
 * `^` - only special if it's the first character of a token; `%^` will be replaced by `^` during searches
 * `$` - only special if it's the last character of a token; `%S` (note the capital `S`) will be replaced by `$` during searches
 * `#` - only special if it's the *very first* character on a line, see the [note about comments here](../TUTORIAL.md#basics)
 * `+` - only special if it's the first (not including any spaces) character on a line, immediately followed by a space (or delimiter) and then some tokens (see the [Mutual Exclusion](../TUTORIAL.md#mutual-exclusion) section); if you need  a single `+` character as a token, make sure it's not the first token on the line, or it's on a line all by itself
 * `]` - only special when it follows `%[` in a token to mark the end of a `%[...]`-style wildcard. If it appears *immediately after* the `%[`, it is part of the replacement set and the *next* `]` actually ends the wildcard, e.g. the wildcard `%[]x]` contains two replacement characters, `]` and `x`. 

None of this applies to passwordlist files, which always treat spaces and symbols (except for carriage-returns and line-feeds) verbatim, treating them as parts of a password.

### Resource Usage ###

#### Memory ####

When *btcrecover* starts, it's first task is to count all the passwords it's about to try, looking for and recording duplicates for future reference (so that no password is tried twice) and also so it can display an ETA. This duplicate checking can take **a lot** of memory, depending on how many passwords need to be counted, but in some circumstances it can also save a lot of time. If *btcrecover* appears to hang after displaying the `Counting passwords ...` message, or if it outright crashes, try running it again with the `--no-dupchecks` option. After this initial counting phase, it doesn't use up much RAM as it searches through passwords.

Although this initial counting phase can be skipped by using the `--no-eta` option, it's not recommended. If you do use `--no-eta`, it's highly recommended that you also use `--no-dupchecks` at the same time.

You may want to always use a single `--no-dupchecks` option when working with MultiBit Classic or Electrum wallets because the duplicate checking can actually decrease CPU efficiency (and always decreases memory efficiency) with these wallets in many cases.

If you specify `--no-dupchecks` more than once, it will disable even more of the duplicate checking logic:

 * 1 time - disables the most comprehensive and also the most memory intensive duplicate checking
 * 2 times - disables duplicate checking that rarely consumes much memory relative to the time it saves, although it may if the tokenlist file has a large number of tokens on relatively few lines with at least one but relatively few identical tokens
 * 3 times - disables duplicate checking which consumes very little memory relative to the duplicates it can potentially find; it's almost never useful to use this level
 * 4 times - disables duplicate checking which consumes no additional memory; it's never useful to use this level (and it's only available for debugging purposes)

#### CPU ####

By default, *btcrecover* tries to use as much CPU time as is available and spare. You can use the `--threads` option to decrease the number of worker threads (which defaults to the number of logical processors in your system) if you'd like to decrease CPU usage (but also the guess rate).

With MultiBit or Electrum wallets, *btcrecover* may not be able to efficiently use more than four or five CPU cores, sometimes even less depending on the contents of the tokenlist and the chosen typos. Specifying the `--no-dupchecks` option may help improve CPU usage and therefore the password guess rate in many cases with these two wallet types, and using slightly fewer or slightly greater `--threads` might also help. The only way to find out is to experiment.

*btcrecover* places itself in the lowest CPU priority class to minimize disruption to your PC while searching.

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
