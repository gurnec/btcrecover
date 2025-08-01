## *btcrecover* Performance Benchmarking Guide ##

*btcrecover* includes a performance benchmarking tool to help you estimate the time it will take to recover your password and to compare the performance of different hardware and recovery strategies.

### Quick Start ###

To run a simple benchmark, use the `--benchmark` option along with a wallet file:

    python btcrecover.py --wallet wallet.dat --benchmark

To benchmark with GPU acceleration:

    python btcrecover.py --wallet wallet.dat --benchmark --enable-gpu

To benchmark a specific level of typo or tokenlist complexity:

    python btcrecover.py --wallet wallet.dat --benchmark --benchmark-typos-complexity 2
    python btcrecover.py --wallet wallet.dat --benchmark --benchmark-tokenlist-complexity 4

### Command-Line Options ###

*   `--benchmark`: Enables the detailed performance benchmarking mode. When this flag is used, *btcrecover* will run a 10-second test and print a detailed report.

*   `--benchmark-output FILE`: Saves the benchmark results to a JSON file. This is useful for sharing your results or for further analysis.

*   `--benchmark-typos-complexity INT`: Sets the complexity of typo generation for the benchmark. This is equivalent to using the `--typos` option with the same integer value. If no other typo types are specified, `--typos-swap` is used by default.

*   `--benchmark-tokenlist-complexity INT`: Sets the complexity of the tokenlist for the benchmark. *btcrecover* will generate a dummy tokenlist with the specified number of tokens.

### Interpreting the Results ###

The benchmark will produce a report similar to this:

    --- btcrecover Benchmark ---
    Device: CPU
    Wallet: WalletBitcoinCore
    Typos Complexity: 2
    Running benchmark for 10 seconds...

    --- Benchmark Results ---
    Passwords per second: 1234.56

    --- Estimating Recovery Time ---
    To estimate the time to recover your password, you need to know the size of your password space.
    Password Space Size: The total number of possible passwords.
    Estimated Time (seconds) = Password Space Size / Passwords per Second

The "Passwords per second" value is the most important metric. It tells you how many password candidates your system can check per second for the given wallet type and complexity.

To estimate the recovery time, you need to calculate the size of your password space. For example, if you are using a tokenlist with 3 tokens and no typos, the password space size is 3! (3 factorial) = 6. If you are using a password list, the password space size is the number of passwords in the list.

### JSON Output Format ###

If you use the `--benchmark-output` option, the results will be saved in a JSON file with the following structure:

```json
{
    "timestamp": 1678886400.0,
    "version": "0.17.10",
    "device": {
        "type": "CPU",
        "name": "Intel(R) Core(TM) i7-8750H CPU @ 2.20GHz"
    },
    "wallet": {
        "type": "WalletBitcoinCore",
        "difficulty": "25000 SHA-512 iterations"
    },
    "benchmark_parameters": {
        "duration_seconds": 10.0,
        "typos_complexity": 2,
        "tokenlist_complexity": null
    },
    "results": {
        "passwords_per_second": 1234.56
    }
}
```

### Community Benchmarks ###

You can contribute to a community-driven benchmark database by sharing your JSON output files. This will help other users to:

*   Compare the performance of different hardware.
*   Estimate recovery times more accurately.
*   Choose the most effective recovery strategies.

To contribute, please look for a relevant repository or forum where users are collecting and sharing benchmark data. (Note: a central repository for this data is not yet established).
