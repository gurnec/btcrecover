#!/usr/bin/env python
"""
AES Block Cipher.

Performs single block cipher decipher operations on a 16 element list of integers.
These integers represent 8 bit bytes in a 128 bit block.
The result of cipher or decipher operations is the transformed 16 element list of integers.

Running this file as __main__ will result in a self-test of the algorithm.

Algorithm per NIST FIPS-197 http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf

Copyright (c) 2010, Adam Newman http://www.caller9.com/
Licensed under the MIT license http://www.opensource.org/licenses/mit-license.php
"""
__author__ = "Adam Newman"

#Normally use relative import. In test mode use local import.
try:from .aes_tables import sbox,i_sbox,galI,galNI
except ValueError:from aes_tables import sbox,i_sbox,galI,galNI
ups=",".join("s%x"%x for x in range(16))
upr=ups.replace("s","r")
mix=",".join(",".join(("g{0}[s%x]^g{1}[s%x]^g{2}[s%x]^g{3}[s%x]^r%x"%(i+(i[0]+(0,3,2,1)[j],))).format(j&3,j+1&3,j+2&3,j+3&3) for j in (0,3,2,1)) for i in ((0,1,2,3),(4,5,6,7),(8,9,10,11),(12,13,14,15))).replace("g2","g").replace("g3","g")
i=mix.find("g[")
while i!=-1:
	mix=mix[:i]+mix[i+2:i+4]+mix[i+5:]
	i=mix.find("g[",i)
imix=",".join(",".join(("g{0}[s%x]^g{1}[s%x]^g{2}[s%x]^g{3}[s%x]"%i).format(j&3,j+1&3,j+2&3,j+3&3) for j in (0,3,2,1)) for i in ((0,1,2,3),(4,5,6,7),(8,9,10,11),(12,13,14,15)))
csl=["s%x"%(x*5&15) for x in range(16)]
csr=["s%x"%(x*-3&15) for x in range(16)]
box=",".join("s[%s]"%i for i in csl)
ibox=",".join("s[%s]^r%x"%i for i in zip(csr,range(16)))
xor=",".join("s[%s]^r%x"%i for i in zip(csl,range(16)))
xori=";".join("s%x^=r%x"%(i,i) for i in range(16))
ciph="""def decipher_block(f,s):
 g0,g1,g2,g3=galNI;ek=f._expanded_key;S=s+[0]*(16-len(s));s=sbox;R=ek[:16];X
 for f in range(!16):R=ek[f:f+16];S=B;S=M
 R=ek[f+16:]
 return """.replace("S",ups).replace("R",upr).replace("X",xori)
class AESCipher:
    def __init__(self,expanded_key):
        self._expanded_key=expanded_key
        self._Nr=len(expanded_key)-16
    exec(ciph.replace("g2,g3","").replace("dec","c").replace("!","16,f._Nr,").replace("B",box).replace("M",mix)+xor)
    exec(ciph.replace("NI","I").replace(":16","f._Nr:").replace("f+16:",":16").replace("!","f._Nr-16,0,-").replace("sbox","i_sbox").replace("B",ibox).replace("M",imix)+ibox)
import unittest
class TestCipher(unittest.TestCase):
    def test_cipher(self):
        """Test AES cipher with all key lengths"""
        import test_keys
        import key_expander
        test_data = test_keys.TestKeys()
        for key_size in 128, 192, 256:
            test_key_expander = key_expander.KeyExpander(key_size)
            test_expanded_key = test_key_expander.expand(test_data.test_key[key_size])
            test_cipher = AESCipher(test_expanded_key)
            test_result_ciphertext = test_cipher.cipher_block(test_data.test_block_plaintext)
            self.assertEquals(len([i for i, j in zip(test_result_ciphertext, test_data.test_block_ciphertext_validated[key_size]) if i == j]),
                16,msg='Test %d bit cipher'%key_size)
            test_result_plaintext = test_cipher.decipher_block(test_data.test_block_ciphertext_validated[key_size])
            self.assertEquals(len([i for i, j in zip(test_result_plaintext, test_data.test_block_plaintext) if i == j]),
                16,msg='Test %d bit decipher'%key_size)
if __name__ == "__main__":
    unittest.main()