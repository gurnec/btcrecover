## *btcrecover* GPU Acceleration Guide ##

*btcrecover* includes experimental support for using one or more graphics cards or dedicated accelerator cards to increase search performance. This can offer on the order of *100x* better performance with Bitcoin Unlimited/Classic/XT/Core or altcoin wallets when enabled and correctly tuned. With Armory (which uses a GPU-resistant key derivation function), this can offer a modest improvement of 2x - 5x.

In order to use this feature, you must have a card and drivers which support OpenCL (most AMD and NVIDIA cards and drivers already support OpenCL on Windows), and you must install the required Python libraries as described in the [Windows GPU acceleration](INSTALL.md#windows-gpu-acceleration-for-bitcoin-unlimitedclassicxtcore-armory-or-litecoin-qt) section of the Installation Guide. GPU acceleration should also work on Linux and OS X, however instructions for installing the required Python libraries are not currently included in this tutorial.

Due to its experimental status, it's highly recommended that you run the GPU unit tests before running it with a wallet. The two commands below will run the relevant tests in ASCII and Unicode modes, respectively (or you can leave out `GPUTests` to run all of the unit tests if you'd prefer). Any skipped tests can be safely ignored, unless *all* the tests are skipped which probably means there was a problem loading OpenCL.

    C:\python27\python -m btcrecover.test.test_passwords -v GPUTests
    C:\python27\python -m btcrecover.test.test_passwords -v --utf8 GPUTests

Assuming the tests do not fail, GPU support can be enabled by adding the `--enable-gpu` option to the command line. There are other additional options, specifically `--global-ws` and `--local-ws`, which should also be provided along with particular values to improve the search performance. Unfortunately, the exact values for these options can only be determined by trial and error, as detailed below.

### GPU performance tuning for Bitcoin Unlimited/Classic/XT/Core and Litecoin-Qt ###

A good starting point for these wallets is:

    C:\python27\python btcrecover.py --wallet wallet.dat --performance --enable-gpu --global-ws 4096 --local-ws 512

The `--performance` option tells *btcrecover* to simply measure the performance until Ctrl-C is pressed, and not to try testing any particular passwords. You will still need a wallet file (or an `--extract-data` option) for performance testing. After you you have a baseline from this initial test, you can try different values for `--global-ws` and `--local-ws` to see if they improve or worsen performance.

Finding the right values for `--global-ws` and `--local-ws` can make a 10x improvement, so it's usually worth the effort.

Generally when testing, you should increase or decrease these two values by powers of 2, for example you should increase or decrease them by 128 or 256 at a time. It's important to note that `--global-ws` must always be evenly divisible by `--local-ws`, otherwise *btcrecover* will exit with an error message.

Although this procedure can be tedious, with larger tokenlists or passwordlists it can make a significant difference.

### GPU performance tuning for Armory ###

Performance tuning for Armory is similar to tuning for Bitcoin Unlimited/Classic/XT/Core, but unfortunately it's much more complex. Armory uses a memory-hard key derivation function called ROMix-SHA-512 which is specifically designed to resist GPU-based acceleration. You should start by reading the section above, which also applies to Armory. In addition to `--global-ws` and `--local-ws`, there is a third option, `--mem-factor`, which affects the GPU memory usage, and as a consequence overall performance.

GPU memory usage is directly proportional to `--global-ws`. The larger the `--global-ws`, the more GPU memory is used. With Armory wallets, a larger `--global-ws` usually improves performance, so you should start with a `--global-ws` that is as high as your GPU will allow. In order to help you locate this value, you can run *btcrecover* with the `--calc-memory` options, as seen below:

    C:\python27\python btcrecover.py --wallet armory_2dRkxw76K_.wallet --enable-gpu --calc-memory
    Details for this wallet
      ROMix V-table length:  32,768
      outer iteration count: 4
      with --mem-factor 1 (the default),
        memory per global worker: 2,048 KB

    Details for GeForce GTX 560 Ti
      global memory size:     1,024 MB
      with --mem-factor 1 (the default),
        est. max --global-ws: 480
        with --global-ws 4096 (the default),
          est. memory usage:  8,192 MB

So for this particular wallet and GPU, a `--global-ws` of around 480 is the maximum supported, and this would be a good starting point for performance searching:

    C:\python27\python btcrecover.py --wallet armory_2dRkxw76K_.wallet --enable-gpu --global-ws 480 --local-ws 32 --performance

If this generates a memory allocation error message (and it probably will), try decreasing `--global-ws` by 32 or 64 at a time until it succeeds. Once you've determined a good `--global-ws` (near its maximum) and a good `--local-ws` (through trial and error, unfortunately), you can move onto the next step.

The `--mem-factor #` option *decreases* memory usage by the factor specified, allowing you to use a larger `--global-ws`. Next, you should try the same procedure above, but use a higher `--mem-factor` (the default is 1) to see if performance can be further improved. In this example, I've determined that the best settings so far are `--global-ws 448 --local-ws 64`, and now I'm starting with these values and adding `--mem-factor 2`:

    C:\python27\python btcrecover.py --wallet armory_2dRkxw76K_.wallet --enable-gpu --global-ws 448 --local-ws 64 --mem-factor 2 --calc-memory

    Details for this wallet
      ROMix V-table length:  32,768
      outer iteration count: 4
      with --mem-factor 2,
        memory per global worker: 1,024 KB

    Details for GeForce GTX 560 Ti
      global memory size:     1,024 MB
      with --mem-factor 2,
        est. max --global-ws: 992
        with --global-ws 448,
          est. memory usage:  448 MB

So for the next round of testing, we should start somewhere around `--global-ws 992 --local-ws 64 --mem-factor 2`, except that 992 isn't evenly divisible by 64, so we reduce it until it is evenly divisible which results in starting values of `--global-ws 960 --local-ws 64 --mem-factor 2`.

For the next few rounds of testing, you can generally keep `--local-ws` at the same value, and just focus on determining the highest value of `--global-ws` which provides the best performance for each successively larger value of `--mem-factor`. Eventually you will reach a point where increasing `--mem-factor` and `--global-ws` will no longer provide any performance benefit, and may actually start hurting performance. This is generally the best you can get with this particular wallet and GPU combination. In this example, the best I could get was at these settings which resulted in a 3.5x improvement over my quad-core CPU, or a 6x improvement when using two GPUs:

    C:\python27\python btcrecover.py --wallet armory_2dRkxw76K_.wallet --enable-gpu --global-ws 2816 --local-ws 128 --mem-factor 6 --performance

This procedure is definitely tedious, so it's up to you to decide whether the improvement you might realize is worth it.
