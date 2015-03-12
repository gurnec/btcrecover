## *btcrecover* Typos Quick Start Guide ##

If you only have a single (or just a few) passwords that you'd like to apply some typos to, you can use the following table to pick a set of [typos command-line options](../TUTORIAL.md#typos) with which to run *btcrecover*.

The leftmost column contains the command-line options, with a full set of options on each row (if the options for a row is blank, they're the same as the row above). As a general rule, each successive row of options will try a larger set of typos than the preceding row. You should select a row which includes the same type of wallet you intend to test, along with a password length that's similar to your password(s). The columns on the right will give you a rough estimate of how many password variations there are and of how long *btcrecover* will take to check the variations (per input password to be tested).

| Typos command-line options                                                                                                                                                                          |          Wallet Type          | Password Length | Passwords Checked | Hours Taken |
|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------:|:---------------:|------------------:|:-----------:|
| --typos 2 --typos-capslock --typos-swap --typos-repeat --typos-delete --typos-case --typos-map typos\us-with-shifts-map.txt                                                                         |                        Armory |        20       |            15,000 |     0.2     |
| --typos 3 --typos-capslock --typos-swap --typos-repeat --typos-delete --typos-closecase --typos-map typos\us-with-shifts-map.txt --max-typos-map 1                                                  |                        Armory |        15       |           100,000 |     1.5     |
|                                                                                                                                                                                                     |                        Armory |        20       |           200,000 |     3.0     |
|                                                                                                                                                                                                     |                  Bitcoin Core |        20       |           200,000 |     2.0     |
| --typos 3 --typos-capslock --typos-swap --typos-repeat --typos-delete --typos-closecase --typos-map typos\us-with-shifts-map.txt --max-typos-map 2                                                  |                        Armory |        15       |           200,000 |     3.0     |
|                                                                                                                                                                                                     |                  Bitcoin Core |        15       |           200,000 |     2.0     |
| --typos 2 --typos-capslock --typos-swap --typos-repeat --typos-delete --typos-closecase --typos-map typos\us-with-shifts-map.txt --typos-insert %a                                                  |                        Armory |        15       |           230,000 |     3.5     |
|                                                                                                                                                                                                     |                  Bitcoin Core |        15       |           230,000 |     2.0     |
| --typos 3 --typos-capslock --typos-swap --typos-repeat --typos-delete --typos-closecase --typos-map typos\us-with-shifts-map.txt                                                                    |                  Bitcoin Core |        15       |           300,000 |     2.5     |
| --typos 3 --typos-capslock --typos-swap --typos-repeat --typos-delete --typos-closecase --typos-map typos\us-with-shifts-map.txt --max-typos-map 2 --typos-insert %a --max-typos-insert 1           | Bitcoin Core, GPU accelerated |        20       |        10,000,000 |     1.5     |
| --typos 4 --typos-capslock --typos-swap --typos-repeat --typos-delete --typos-closecase --typos-map typos\us-with-shifts-map.txt --max-typos-map 2                                                  | Bitcoin Core, GPU accelerated |        20       |        13,000,000 |     2.0     |
| --typos 4 --typos-capslock --typos-swap --typos-repeat --typos-delete --typos-case --typos-map typos\us-with-shifts-map.txt                                                                         | Bitcoin Core, GPU accelerated |        15       |        10,000,000 |     1.5     |
| --typos 3 --typos-capslock --typos-swap --typos-repeat --typos-delete --typos-closecase --typos-map typos\us-with-shifts-map.txt --max-typos-map 2 --typos-insert %a --max-typos-insert 2           | Bitcoin Core, GPU accelerated |        15       |        14,000,000 |     2.0     |
| --typos 4 --typos-capslock --typos-delete --typos-insert %P --max-typos-insert 2 --no-dupchecks                                                                                                     |          MultiBit or Electrum |        15       |       125,000,000 |     0.2     |
|                                                                                                                                                                                                     |          MultiBit or Electrum |        20       |       390,000,000 |     0.4     |
| --typos 4 --typos-capslock --typos-swap --typos-repeat --typos-delete --typos-case --typos-map typos\us-with-shifts-map.txt --max-typos-map 2 --typos-insert %a --max-typos-insert 2 --no-dupchecks |          MultiBit or Electrum |        15       |       900,000,000 |     1.2     |
| --typos 3 --typos-capslock --typos-delete --typos-insert %P --max-typos-insert 2 --typos-replace %P --max-typos-replace 1 --no-dupchecks                                                            |          MultiBit or Electrum |        15       |     1,700,000,000 |     2.3     |


### Typos Maps ###

The *btcrecover* package includes a few [typos-map](../TUTORIAL.md#typos-map) example files in this directory. One of them, `us-with-shifts-map.txt`, is used in the Quick Start suggestions above.

 * `us-map.txt` - For each key on a standard US ANSI ASCII keyboard, this typos-map file will try an adjacent key to test the case where your finger may have slipped one position while typing a password. This typos-map is only intended for testing passwords which do not contain any shifted letters or symbols.

 * `us-with-shifts-map.txt` - Just like `us-map.txt`, except that this typos-map is intended for testing passwords which do contain shifted letters or symbols. In most cases, this typos-map should be used in combination with either the `--typos-case` or the `--typos-closecase` option.

 * `leet-map.txt` - This typos-map tests passwords by replacing letters with their leetspeak version(s) (see <http://en.wikipedia.org/wiki/Leet> for more information).

 * `leet-uncommon-map.txt` - Just like `leet-map.txt`, except this typos-map contains additional less-common replacements.
