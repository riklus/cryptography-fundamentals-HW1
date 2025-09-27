from myaes import MYAES

def test_encrypt_decrypt():
    """Encrypt a block and ensure decryption returns the same block"""
    myaes = MYAES()
    key = myaes.keygen()
    msg = myaes.keygen()
    
    enc = myaes.encrypt(msg, key)
    dec = myaes.decrypt(enc, key)

    assert msg == dec

def test_encrypt_decrypt_multiblock():
    """Encrypt a block and ensure decryption returns the same block"""
    myaes = MYAES()
    key = myaes.keygen()
    msg = myaes.keygen() * 256
    
    enc = myaes.encrypt(msg, key)
    dec = myaes.decrypt(enc, key)

    assert msg == dec