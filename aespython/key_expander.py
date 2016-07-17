"""
AES Key Expansion

Expands 128, 192, or 256 bit key for use with AES

Algorithm per NIST FIPS-197 http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf

Copyright (c) 2010, Adam Newman http://www.caller9.com
Licensed under the MIT license http://www.opensource.org/licenses/mit-license.php
"""
__all__ = "expandKey",
from .aes_tables import sbox,rcon
_expanded_key_length={16:176,24:208,32:240}
def expandKey(new_key):
    """Expand the encryption key per AES key schedule specifications
        http://en.wikipedia.org/wiki/Rijndael_key_schedule#Key_schedule_description"""
    _n=len(new_key)
    if _n not in (16,24,32):
        raise RuntimeError('expand(): key size is invalid')
    rcon_iter=1
    _nn16=_n!=16
    _n32=_n==32
    n0=new_key[-4]
    n1=new_key[-3]
    n2=new_key[-2]
    n3=new_key[-1]
    _n0=-_n
    _n1=1-_n
    _n2=2-_n
    _n3=3-_n
    _n=_expanded_key_length[_n]-_n
    nex=new_key.extend
    while 1:
        #Copy last 4 bytes of extended key, apply core, increment rcon_iter,
        #core Append the list of elements 1-3 and list comprised of element 0 (circular rotate left)
        #core For each element of this new list, put the result of sbox into output array.
        #xor with 4 bytes n bytes from end of extended key
        #First byte of output array is XORed with rcon(iter)
        nx=n0,n1,n2,n3=(sbox[n1]^rcon[rcon_iter]^new_key[_n0],
            sbox[n2]^new_key[_n1],
            sbox[n3]^new_key[_n2],
            sbox[n0]^new_key[_n3])
        nex(nx)
        rcon_iter += 1

        #Run three passes of 4 byte expansion using copy of 4 byte tail of extended key
        #which is then xor'd with 4 bytes n bytes from end of extended key
        nx=n0,n1,n2,n3=(n0^new_key[_n0],
            n1^new_key[_n1],
            n2^new_key[_n2],
            n3^new_key[_n3])
        nex(nx)
        nx=n0,n1,n2,n3=(n0^new_key[_n0],
            n1^new_key[_n1],
            n2^new_key[_n2],
            n3^new_key[_n3])
        nex(nx)
        nx=n0,n1,n2,n3=(n0^new_key[_n0],
            n1^new_key[_n1],
            n2^new_key[_n2],
            n3^new_key[_n3])
        nex(nx)
        _n -= 16
        if _n <= 0:return new_key
        elif _nn16:
            #If key length is 256 and key is not complete, add 4 bytes tail of extended key
            #run through sbox before xor with 4 bytes n bytes from end of extended key
            if _n32:
                nx=n0,n1,n2,n3=(sbox[n0]^new_key[_n0],
                    sbox[n1]^new_key[_n1],
                    sbox[n2]^new_key[_n2],
                    sbox[n3]^new_key[_n3])
                nex(nx)
                _n -= 4
                if _n <= 0:return new_key

            #If key length in (192, 256) and key is not complete, run 2 or 3 passes respectively
            #of 4 byte tail of extended key xor with 4 bytes n bytes from end of extended key
            nx=n0,n1,n2,n3=(n0^new_key[_n0],
                n1^new_key[_n1],
                n2^new_key[_n2],
                n3^new_key[_n3])
            nex(nx)
            nx=n0,n1,n2,n3=(n0^new_key[_n0],
                n1^new_key[_n1],
                n2^new_key[_n2],
                n3^new_key[_n3])
            nex(nx)
            if _n32:
                nx=n0,n1,n2,n3=(n0^new_key[_n0],
                    n1^new_key[_n1],
                    n2^new_key[_n2],
                    n3^new_key[_n3])
                nex(nx)
                _n -= 12
            else:_n -= 8
            if _n <= 0:return new_key