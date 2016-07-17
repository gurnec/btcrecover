#!/usr/bin/env python
"""
AES Block Cipher.

Performs single block cipher decipher operations on a 16 element list of integers.
These integers represent 8 bit bytes in a 128 bit block.
The result of cipher or decipher operations is the transformed 16 element list of integers.

Algorithm per NIST FIPS-197 http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf

Copyright (c) 2010, Adam Newman http://www.caller9.com/
Licensed under the MIT license http://www.opensource.org/licenses/mit-license.php
"""
__all__ = "AESCipher",

from .aes_tables import sbox,i_sbox,galI,galNI
class AESCipher:
    __slots__ = "_Nr", "_Nrr", "_f16","_l16"
    def __init__(self,expanded_key):
        self._Nr=[expanded_key[i:i+16] for i in range(16,len(expanded_key)-16,16)]
        self._Nrr=self._Nr[::-1]
        self._f16=expanded_key[:16]
        self._l16=expanded_key[-16:]
    def cipher_block(z,s0,s=sbox,g0=galNI[0],g1=galNI[1]):
        s0,s1,s2,s3,s4,s5,s6,s7,s8,s9,sa,sb,sc,sd,se,sf=s0
        r0,r1,r2,r3,r4,r5,r6,r7,r8,r9,ra,rb,rc,rd,re,rf=z._f16
        s0^=r0;s1^=r1;s2^=r2;s3^=r3;s4^=r4;s5^=r5;s6^=r6;s7^=r7;s8^=r8;s9^=r9;sa^=ra;sb^=rb;sc^=rc;sd^=rd;se^=re;sf^=rf
        for r0,r1,r2,r3,r4,r5,r6,r7,r8,r9,ra,rb,rc,rd,re,rf in z._Nr:
            s0=s[s0];s4=s[s4];s8=s[s8];sc=s[sc]
            s1,s2,s3,s5,s6,s7,s9,sa,sb,sd,se,sf=s[s5],s[sa],s[sf],s[s9],s[se],s[s3],s[sd],s[s2],s[s7],s[s1],s[s6],s[sb]
            s0,s1,s2,s3,s4,s5,s6,s7,s8,s9,sa,sb,sc,sd,se,sf=g0[s0]^g1[s1]^s2^s3^r0,s0^g0[s1]^g1[s2]^s3^r1,s0^s1^g0[s2]^g1[s3]^r2,g1[s0]^s1^s2^g0[s3]^r3,g0[s4]^g1[s5]^s6^s7^r4,s4^g0[s5]^g1[s6]^s7^r5,s4^s5^g0[s6]^g1[s7]^r6,g1[s4]^s5^s6^g0[s7]^r7,g0[s8]^g1[s9]^sa^sb^r8,s8^g0[s9]^g1[sa]^sb^r9,s8^s9^g0[sa]^g1[sb]^ra,g1[s8]^s9^sa^g0[sb]^rb,g0[sc]^g1[sd]^se^sf^rc,sc^g0[sd]^g1[se]^sf^rd,sc^sd^g0[se]^g1[sf]^re,g1[sc]^sd^se^g0[sf]^rf
        r0,r1,r2,r3,r4,r5,r6,r7,r8,r9,ra,rb,rc,rd,re,rf=z._l16
        return s[s0]^r0,s[s5]^r1,s[sa]^r2,s[sf]^r3,s[s4]^r4,s[s9]^r5,s[se]^r6,s[s3]^r7,s[s8]^r8,s[sd]^r9,s[s2]^ra,s[s7]^rb,s[sc]^rc,s[s1]^rd,s[s6]^re,s[sb]^rf
    def decipher_block(z,s0,s=i_sbox,g0=galI[0],g1=galI[1],g2=galI[2],g3=galI[3]):
        s0,s1,s2,s3,s4,s5,s6,s7,s8,s9,sa,sb,sc,sd,se,sf=s0
        r0,r1,r2,r3,r4,r5,r6,r7,r8,r9,ra,rb,rc,rd,re,rf=z._l16
        s0^=r0;s1^=r1;s2^=r2;s3^=r3;s4^=r4;s5^=r5;s6^=r6;s7^=r7;s8^=r8;s9^=r9;sa^=ra;sb^=rb;sc^=rc;sd^=rd;se^=re;sf^=rf
        for r0,r1,r2,r3,r4,r5,r6,r7,r8,r9,ra,rb,rc,rd,re,rf in z._Nrr:
            s0=s[s0]^r0;s4=s[s4]^r4;s8=s[s8]^r8;sc=s[sc]^rc
            s1,s2,s3,s5,s6,s7,s9,sa,sb,sd,se,sf=s[sd]^r1,s[sa]^r2,s[s7]^r3,s[s1]^r5,s[se]^r6,s[sb]^r7,s[s5]^r9,s[s2]^ra,s[sf]^rb,s[s9]^rd,s[s6]^re,s[s3]^rf
            s0,s1,s2,s3,s4,s5,s6,s7,s8,s9,sa,sb,sc,sd,se,sf=g0[s0]^g1[s1]^g2[s2]^g3[s3],g3[s0]^g0[s1]^g1[s2]^g2[s3],g2[s0]^g3[s1]^g0[s2]^g1[s3],g1[s0]^g2[s1]^g3[s2]^g0[s3],g0[s4]^g1[s5]^g2[s6]^g3[s7],g3[s4]^g0[s5]^g1[s6]^g2[s7],g2[s4]^g3[s5]^g0[s6]^g1[s7],g1[s4]^g2[s5]^g3[s6]^g0[s7],g0[s8]^g1[s9]^g2[sa]^g3[sb],g3[s8]^g0[s9]^g1[sa]^g2[sb],g2[s8]^g3[s9]^g0[sa]^g1[sb],g1[s8]^g2[s9]^g3[sa]^g0[sb],g0[sc]^g1[sd]^g2[se]^g3[sf],g3[sc]^g0[sd]^g1[se]^g2[sf],g2[sc]^g3[sd]^g0[se]^g1[sf],g1[sc]^g2[sd]^g3[se]^g0[sf]
        r0,r1,r2,r3,r4,r5,r6,r7,r8,r9,ra,rb,rc,rd,re,rf=z._f16
        return s[s0]^r0,s[sd]^r1,s[sa]^r2,s[s7]^r3,s[s4]^r4,s[s1]^r5,s[se]^r6,s[sb]^r7,s[s8]^r8,s[s5]^r9,s[s2]^ra,s[sf]^rb,s[sc]^rc,s[s9]^rd,s[s6]^re,s[s3]^rf
