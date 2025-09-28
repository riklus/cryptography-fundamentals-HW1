import pytest
from Crypto.Random import get_random_bytes
from myaes import MYAES

def test_encrypt_block_boundaries_msg_lt():
    myaes = MYAES()
    key = myaes.keygen()
    msg = myaes.keygen()[:-1]
    
    with pytest.raises(Exception):
        myaes.encrypt(msg, key)

def test_encrypt_block_boundaries_msg_gt():
    myaes = MYAES()
    key = myaes.keygen()
    msg = myaes.keygen() + b"A"
    
    with pytest.raises(Exception):
        myaes.encrypt(msg, key)

def test_encrypt_block_boundaries_key_lt():
    myaes = MYAES()
    key = myaes.keygen()[:-1]
    msg = myaes.keygen()
    
    with pytest.raises(Exception):
        myaes.encrypt(msg, key)

def test_encrypt_block_boundaries_key_gt():
    myaes = MYAES()
    key = myaes.keygen() + b"A"
    msg = myaes.keygen() 
    
    with pytest.raises(Exception):
        myaes.encrypt(msg, key)



def test_encrypt_multiblock_boundaries_msg_lt():
    myaes = MYAES()
    key = myaes.keygen()
    msg = get_random_bytes(256)[:-1]
    
    with pytest.raises(Exception):
        myaes.encrypt(msg, key)

def test_encrypt_multiblock_boundaries_msg_gt():
    myaes = MYAES()
    key = myaes.keygen()
    msg = get_random_bytes(256) + b"A"
    
    with pytest.raises(Exception):
        myaes.encrypt(msg, key)

def test_encrypt_multiblock_boundaries_key_lt():
    myaes = MYAES()
    key = myaes.keygen()[:-1]
    msg = get_random_bytes(256)
    
    with pytest.raises(Exception):
        myaes.encrypt(msg, key)

def test_encrypt_multiblock_boundaries_key_gt():
    myaes = MYAES()
    key = myaes.keygen() + b"A"
    msg = get_random_bytes(256)
    
    with pytest.raises(Exception):
        myaes.encrypt(msg, key)