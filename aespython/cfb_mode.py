#!/usr/bin/env python
"""
CFB Mode of operation

Algorithm per NIST SP 800-38A http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf

Copyright (c) 2010, Adam Newman http://www.caller9.com/
Licensed under the MIT license http://www.opensource.org/licenses/mit-license.php
"""
__all__ = "CFBMode",
from . import Mode

class CFBMode(Mode):
    """Perform CFB operation on a block and retain IV information for next operation"""

    def encrypt_block(self, plaintext):
        a0,a1,a2,a3,a4,a5,a6,a7,a8,a9,aa,ab,ac,ad,ae,af=self._block_cipher.cipher_block(self._iv)
        b0,b1,b2,b3,b4,b5,b6,b7,b8,b9,ba,bb,bc,bd,be,bf=plaintext
        a0=self._iv=a0^b0,a1^b1,a2^b2,a3^b3,a4^b4,a5^b5,a6^b6,a7^b7,a8^b8,a9^b9,aa^ba,ab^bb,ac^bc,ad^bd,ae^be,af^bf
        return a0

    def decrypt_block(self, ciphertext):
        a0,a1,a2,a3,a4,a5,a6,a7,a8,a9,aa,ab,ac,ad,ae,af=self._block_cipher.cipher_block(self._iv)
        self._iv=b0,b1,b2,b3,b4,b5,b6,b7,b8,b9,ba,bb,bc,bd,be,bf=ciphertext
        return a0^b0,a1^b1,a2^b2,a3^b3,a4^b4,a5^b5,a6^b6,a7^b7,a8^b8,a9^b9,aa^ba,ab^bb,ac^bc,ad^bd,ae^be,af^bf
