from Crypto.Cipher import AES
from Crypto import Random


class AESCRT:
    def encrypt(self, msg: bytes, key: bytes):
        assert len(msg) % 16 == 0   # padless
        assert len(key) == 16

    def decrypt(self, enc: bytes, key: bytes):
        assert len(enc) % 16 == 0   # consistent
        assert len(key) == 16


    @staticmethod
    def keygen():
        return Random.get_random_bytes(16)

    @staticmethod
    def __encrypt_block(key: bytes, blk: bytes):
        assert len(key) == 16
        assert len(blk) == 16

        cip = AES.new(key, AES.MODE_ECB)
        return cip.encrypt(blk)

    @staticmethod
    def __decrypt_block(blk: bytes, msg: bytes):
        assert len(blk) == 16
        assert len(msg) == 16

        cip = AES.new(blk, AES.MODE_ECB)
        return cip.decrypt(msg)


def main():
    print("Hello from cryptography-fundamentals-hw28!")


if __name__ == "__main__":
    main()
