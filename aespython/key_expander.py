#!/usr/bin/env python

"""
AES Key Expansion.

Expands 128, 192, or 256 bit key for use with AES

Running this file as __main__ will result in a self-test of the algorithm.

Algorithm per NIST FIPS-197 http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf

Copyright (c) 2010, Adam Newman http://www.caller9.com/
Licensed under the MIT license http://www.opensource.org/licenses/mit-license.php
"""
__author__ = "Adam Newman"

#Normally use relative import. In test mode use local import.
try:from .aes_tables import sbox,rcon
except ValueError:from aes_tables import sbox,rcon
from operator import xor
class KeyExpander:
    """Perform AES Key Expansion"""

    _expanded_key_length = {128 : 176, 192 : 208, 256 : 240}

    def __init__(self, key_length):
        self._key_length = key_length
        self._n = key_length>>3

        if key_length in self._expanded_key_length:
            self._b = self._expanded_key_length[key_length]
        else:
            raise LookupError('Invalid Key Size')

    def expand(self, new_key):
        """
            Expand the encryption key per AES key schedule specifications

            http://en.wikipedia.org/wiki/Rijndael_key_schedule#Key_schedule_description
        """
        #First n bytes are copied from key
        len_new_key = len(new_key)
        if len_new_key != self._n:
            raise RuntimeError('expand(): key size is invalid')
        rcon_iter = 1
        nex=new_key.extend

        #Grow the key until it is the correct length
        while 1:
            #Copy last 4 bytes of extended key, apply core, increment i(rcon_iter),
            #core Append the list of elements 1-3 and list comprised of element 0 (circular rotate left)
            #core For each element of this new list, put the result of sbox into output array.
            #xor with 4 bytes n bytes from end of extended key
            keyarr=[sbox[i] for i in new_key[-3:]+new_key[-4:-3]]
            #First byte of output array is XORed with rcon(iter)
            keyarr[0] ^= rcon[rcon_iter]
            nex(map(xor,keyarr, new_key[-self._n:4-self._n]))
            rcon_iter += 1
            len_new_key += 4

            #Run three passes of 4 byte expansion using copy of 4 byte tail of extended key
            #which is then xor'd with 4 bytes n bytes from end of extended key
            for j in 0,1,2:
                nex(map(xor,new_key[-4:], new_key[-self._n:4-self._n]))
                len_new_key += 4
            if len_new_key >= self._b:return new_key
            else:
                #If key length is 256 and key is not complete, add 4 bytes tail of extended key
                #run through sbox before xor with 4 bytes n bytes from end of extended key
                if self._key_length == 256:
                    nex(map(xor,[sbox[x] for x in new_key[-4:]], new_key[-self._n:4-self._n]))
                    len_new_key += 4
                    if len_new_key >= self._b:return new_key

                #If key length is 192 or 256 and key is not complete, run 2 or 3 passes respectively
                #of 4 byte tail of extended key xor with 4 bytes n bytes from end of extended key
                if self._key_length != 128:
                    for j in ((0,1) if self._key_length == 192 else (0,1,2)):
                        nex(map(xor,new_key[-4:], new_key[-self._n:4-self._n]))
                        len_new_key += 4
                    if len_new_key >= self._b:return new_key

import unittest
class TestKeyExpander(unittest.TestCase):
    def test_keys(self):
        """Test All Key Expansions"""
        import test_keys
        test_data = test_keys.TestKeys()
        for key_size in 128, 192, 256:
            test_expander = KeyExpander(key_size)
            test_expanded_key = test_expander.expand(test_data.test_key[key_size])
            self.assertEqual (len([i for i, j in zip(test_expanded_key, test_data.test_expanded_key_validated[key_size]) if i == j]),
                len(test_data.test_expanded_key_validated[key_size]),
                msg='Key expansion ' + str(key_size) + ' bit')

if __name__ == "__main__":
    unittest.main()