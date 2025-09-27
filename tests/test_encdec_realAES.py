from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Random import get_random_bytes

from myaes import MYAES

def test_encrypt_block():
    """Encrypt a block with MYAES and AES and ensure is they perform the same encryption"""
    myaes = MYAES()
    key = myaes.keygen()
    msg = myaes.keygen()
    iv = myaes.get_iv()

    aes = AES.new(key, AES.MODE_CTR, counter=Counter.new(128, initial_value=iv))

    # The slice removes the prepended IV
    assert myaes.encrypt(msg, key)[16:] == aes.encrypt(msg)

def test_decrypt_block():
    """Decrypt a block with MYAES and AES and ensure is they perform the same decryption"""
    myaes = MYAES()
    key = myaes.keygen()
    enc = myaes.keygen()
    iv = myaes.get_iv()

    aes = AES.new(key, AES.MODE_CTR, counter=Counter.new(128, initial_value=iv))

    # Need to prepend the IV
    assert myaes.decrypt(myaes.get_iv_bytes() + enc, key) == aes.decrypt(enc)

def test_encrypt_multiblock():
    """Encrypt a message with MYAES and AES and ensure is they perform the same encryption"""
    myaes = MYAES()
    key = myaes.keygen()
    msg = get_random_bytes(256)
    iv = myaes.get_iv()

    aes = AES.new(key, AES.MODE_CTR, counter=Counter.new(128, initial_value=iv))

    # The slice removes the prepended IV
    assert myaes.encrypt(msg, key)[16:] == aes.encrypt(msg)

def test_decrypt_multiblock():
    """Decrypt a message with MYAES and AES and ensure is they perform the same decryption"""
    myaes = MYAES()
    key = myaes.keygen()
    enc = get_random_bytes(256)
    iv = myaes.get_iv()

    aes = AES.new(key, AES.MODE_CTR, counter=Counter.new(128, initial_value=iv))

    # Need to prepend the IV
    assert myaes.decrypt(myaes.get_iv_bytes() + enc, key) == aes.decrypt(enc)


def test_cross_encdec_block_myaes_aes():
    """Encrypt block with myaes and decrypt with aes, compare the original block to the decrypted one"""
    myaes = MYAES()
    key = myaes.keygen()
    msg = myaes.keygen()
    iv = myaes.get_iv()
    iv_bytes = myaes.get_iv_bytes()

    aes = AES.new(key, AES.MODE_CTR, counter=Counter.new(128, initial_value=iv))

    enc = myaes.encrypt(msg, key)
    dec = aes.decrypt(enc[16:]) # slice out the IV

    assert msg == dec

def test_cross_encdec_multiblock_myaes_aes():
    """Encrypt block with myaes and decrypt with aes, compare the original block to the decrypted one"""
    myaes = MYAES()
    key = myaes.keygen()
    msg = get_random_bytes(256)
    iv = myaes.get_iv()
    iv_bytes = myaes.get_iv_bytes()

    aes = AES.new(key, AES.MODE_CTR, counter=Counter.new(128, initial_value=iv))

    enc = myaes.encrypt(msg, key)
    dec = aes.decrypt(enc[16:]) # slice out the IV

    assert msg == dec

def test_cross_encdec_block_aes_myaes():
    """Encrypt block with aes and decrypt with myaes, compare the original block to the decrypted one"""
    myaes = MYAES()
    key = myaes.keygen()
    msg = myaes.keygen()
    iv = myaes.get_iv()
    iv_bytes = myaes.get_iv_bytes()

    aes = AES.new(key, AES.MODE_CTR, counter=Counter.new(128, initial_value=iv))

    enc = aes.encrypt(msg)
    dec = myaes.decrypt(iv_bytes + enc, key) # slice out the IV

    assert msg == dec

def test_cross_encdec_multiblock_aes_myaes():
    """Encrypt multiblock with aes and decrypt with myaes, compare the original block to the decrypted one"""
    myaes = MYAES()
    key = myaes.keygen()
    msg = get_random_bytes(256)
    iv = myaes.get_iv()
    iv_bytes = myaes.get_iv_bytes()

    aes = AES.new(key, AES.MODE_CTR, counter=Counter.new(128, initial_value=iv))

    enc = aes.encrypt(msg)
    dec = myaes.decrypt(iv_bytes + enc, key) # slice out the IV

    assert msg == dec