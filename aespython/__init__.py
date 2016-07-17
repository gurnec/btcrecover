__all__ = 'AESCipher','expandKey','Mode','CBCMode','CBCMode','CFBMode','OFBMode'
class Mode:
    __slots__ = "_iv", "_block_cipher"

    def __init__(self, block_cipher, block_size):
        self._block_cipher = block_cipher
        self._iv = bytearray(block_size)

    def set_iv(self, iv):
        if len(iv) == len(self._iv):
            self._iv = iv
from .aes_cipher import AESCipher
from .key_expander import expandKey
from .cbc_mode import CBCMode
from .cfb_mode import CFBMode
from .ofb_mode import OFBMode
