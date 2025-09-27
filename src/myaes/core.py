from Crypto.Util import Counter
from Crypto.Util.strxor import strxor

from Crypto.Cipher import AES
from Crypto import Random


def chunk(vec: bytes, size: int):
    assert len(vec) % size == 0   # exact size

    for i in range(0, len(vec), size):
        yield vec[i:i+size]


class MYAES:
    def __init__(self) -> None:
        self._iv = b"\x00"*8 + Random.get_random_bytes(8)

        # Panic on int overflow in counter
        self._counter_max_val = int.from_bytes(b"\xFF"*16, byteorder='big', signed=False) 

    def encrypt(self, msg: bytes, key: bytes):
        assert len(msg) % 16 == 0   # padless
        assert len(key) == 16

        ctr = self._iv
        enc = ctr
        for blk in chunk(msg, 16):
            enc += strxor(self._encrypt_block(key, ctr), blk)
            ctr = self._increment(ctr)
        
        return enc

    def decrypt(self, enc: bytes, key: bytes):
        assert len(enc) % 16 == 0   # consistent
        assert len(key) == 16

        ctr = enc[:16]
        msg = b""
        for blk in chunk(enc[16:], 16):
            msg += strxor(self._encrypt_block(key, ctr), blk)
            ctr = self._increment(ctr)
        
        return msg

    def _increment(self, ctr: bytes):
        assert len(ctr) == 16

        c = int.from_bytes(ctr, byteorder='big', signed=False)
        assert c != self._counter_max_val
        c += 1
        return c.to_bytes(16, byteorder='big', signed=False)

    def get_iv(self):
        return int.from_bytes(self._iv, byteorder='big', signed=False)
    
    def get_iv_bytes(self):
        return self._iv
    
    @staticmethod
    def keygen():
        return Random.get_random_bytes(16)

    @staticmethod
    def _encrypt_block(key: bytes, blk: bytes):
        assert len(key) == 16
        assert len(blk) == 16

        cip = AES.new(key, AES.MODE_ECB)
        return cip.encrypt(blk)
