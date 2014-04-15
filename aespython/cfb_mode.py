#!/usr/bin/env python
"""
CFB Mode of operation

Running this file as __main__ will result in a self-test of the algorithm.

Algorithm per NIST SP 800-38A http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf

Copyright (c) 2010, Adam Newman http://www.caller9.com/
Licensed under the MIT license http://www.opensource.org/licenses/mit-license.php
"""
__author__ = "Adam Newman"

class CFBMode:
    """Perform CFB operation on a block and retain IV information for next operation"""
    def __init__(self, block_cipher, block_size):
        self._block_cipher = block_cipher
        self._block_size = block_size
        self._iv = [0] * block_size

    def set_iv(self, iv):
        if len(iv) == self._block_size:
            self._iv = iv

    def encrypt_block(self, plaintext):
        cipher_iv = self._block_cipher.cipher_block(self._iv)
        iv = self._iv = [i ^ j for i,j in zip (plaintext, cipher_iv)]
        return iv

    def decrypt_block(self, ciphertext):
        cipher_iv = self._block_cipher.cipher_block(self._iv)
        self._iv = ciphertext
        return [i ^ j for i,j in zip (cipher_iv, ciphertext)]

import unittest
class TestEncryptionMode(unittest.TestCase):
    def test_mode(self):
        #Self test
        import key_expander
        import aes_cipher
        import test_keys

        test_data = test_keys.TestKeys()

        test_expander = key_expander.KeyExpander(256)
        test_expanded_key = test_expander.expand(test_data.test_mode_key)

        test_cipher = aes_cipher.AESCipher(test_expanded_key)

        test_cfb = CFBMode(test_cipher, 16)

        test_cfb.set_iv(test_data.test_mode_iv)
        for k in range(4):
            self.assertEquals(len([i for i, j in zip(test_data.test_cfb_ciphertext[k],test_cfb.encrypt_block(test_data.test_mode_plaintext[k])) if i == j]),
                16,
                msg='CFB encrypt test block' + str(k))

        test_cfb.set_iv(test_data.test_mode_iv)
        for k in range(4):
            self.assertEquals(len([i for i, j in zip(test_data.test_mode_plaintext[k],test_cfb.decrypt_block(test_data.test_cfb_ciphertext[k])) if i == j]),
                16,
                msg='CFB decrypt test block' + str(k))

if __name__ == "__main__":
    unittest.main()
