## *btcrecover* GPU Acceleration Guide ##

*btcrecover* includes experimental support for using one or more graphics cards or dedicated accelerator cards to increase search performance. This can offer on the order of *100x* better performance with Bitcoin Unlimited/Classic/XT/Core or altcoin wallets when enabled and correctly tuned. With Armory (which uses a GPU-resistant key derivation function), this can offer a modest improvement of 2x - 5x.

In order to use this feature, you must have a card and drivers which support OpenCL (most AMD and NVIDIA cards and drivers already support OpenCL on Windows), and you must install the required Python libraries as described in the [Windows GPU acceleration](INSTALL.md#windows-gpu-acceleration-for-bitcoin-unlimitedclassicxtcore-armory-or-litecoin-qt) section of the Installation Guide. GPU acceleration should also work on Linux and OS X, however instructions for installing the required Python libraries are not currently included in this tutorial.

Due to its experimental status, it's highly recommended that you run the GPU unit tests before running it with a wallet. The two commands below will run the relevant tests in ASCII and Unicode modes, respectively (or you can leave out `GPUTests` to run all of the unit tests if you'd prefer). Any skipped tests can be safely ignored, unless *all* the tests are skipped which probably means there was a problem loading OpenCL.

    C:\python27\python -m btcrecover.test.test_passwords -v GPUTests
    C:\python27\python -m btcrecover.test.test_passwords -v --utf8 GPUTests

Assuming the tests do not fail, GPU support can be enabled by adding the `--enable-gpu` option to the command line. There are other additional options, specifically `--global-ws` and `--local-ws`, which should also be provided along with particular values to improve the search performance.

### Understanding GPU Performance Tuning

To understand how to tune GPU performance, it's helpful to understand a little about how OpenCL works. OpenCL executes code on the GPU in parallel using "work-items". These work-items are grouped into "work-groups".

*   `--local-ws` (local work size) sets the number of work-items in a work-group. The optimal value for this parameter is highly dependent on the GPU architecture.
*   `--global-ws` (global work size) sets the total number of work-items to be executed. This should be a multiple of the local work size.

Finding the right values for `--global-ws` and `--local-ws` can make a 10x improvement, so it's usually worth the effort.

### A Systematic Approach to Tuning

Instead of simple trial and error, we recommend a more systematic approach to finding the optimal values for your GPU.

**Step 1: Find the Optimal Local Work Size (`--local-ws`)**

The local work size is the most important parameter to tune. A well-chosen local work size will allow the GPU to execute work-items efficiently. The best value is often a multiple of the "warp size" (for NVIDIA) or "wavefront size" (for AMD).

Here are some recommended starting points for `--local-ws` based on your GPU vendor:

| Vendor  | Recommended `--local-ws` |
|---------|--------------------------|
| NVIDIA  | 64, 128, 256             |
| AMD     | 64, 128, 256             |
| Intel   | 64, 128                  |

To find the best `--local-ws` for your GPU, start with one of the recommended values and a relatively small `--global-ws` (e.g., 4096).

    C:\python27\python btcrecover.py --wallet wallet.dat --performance --enable-gpu --global-ws 4096 --local-ws 128

Run the command and note the performance. Then, try other recommended values for `--local-ws` and see which one gives the best performance.

**Step 2: Find the Optimal Global Work Size (`--global-ws`)**

Once you have found the optimal `--local-ws`, you can tune the `--global-ws`. The goal is to find a value that is large enough to keep all the compute units of your GPU busy.

Start with a `--global-ws` that is a large multiple of your chosen `--local-ws`. For example, if your `--local-ws` is 128, you could start with a `--global-ws` of 4096, then try 8192, 16384, and so on.

    C:\python27\python btcrecover.py --wallet wallet.dat --performance --enable-gpu --global-ws 8192 --local-ws 128

Increase the `--global-ws` until you no longer see a performance improvement.

**Important Note:** `--global-ws` must always be evenly divisible by `--local-ws`.

### GPU performance tuning for Armory

Performance tuning for Armory is similar to tuning for other wallets, but it is more complex because Armory uses a memory-hard key derivation function. This means that the amount of memory your GPU has is a major limiting factor.

The `--mem-factor` option allows you to trade off memory usage for performance. A higher `--mem-factor` will use less memory, which allows you to use a larger `--global-ws`.

When tuning for Armory, we recommend the following process:

1.  **Use `--calc-memory` to estimate the maximum `--global-ws`:**

        C:\python27\python btcrecover.py --wallet armory_2dRkxw76K_.wallet --enable-gpu --calc-memory

2.  **Find the optimal `--local-ws`:** Use the systematic approach described above, but keep the `--global-ws` below the estimated maximum.
3.  **Find the optimal `--global-ws`:** Once you have found the optimal `--local-ws`, experiment with different values of `--global-ws` and `--mem-factor` to find the best combination for your GPU.

This procedure can be tedious, but with larger tokenlists or passwordlists it can make a significant difference.
