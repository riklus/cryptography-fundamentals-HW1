import pytest
from myaes import MYAES

def test_encrypt_block_boundaries_key_lt():
    myaes = MYAES()
    key = b"A"*15
    blk = myaes.keygen()
    
    with pytest.raises(Exception):
        myaes._encrypt_block(key, blk)

def test_encrypt_block_boundaries_key_gt():
    myaes = MYAES()
    key = b"A"*17
    blk = myaes.keygen()
    
    with pytest.raises(Exception):
        myaes._encrypt_block(key, blk)

def test_encrypt_block_boundaries_blk_lt():
    myaes = MYAES()
    key = myaes.keygen()
    blk = b"A"*15
    
    with pytest.raises(Exception):
        myaes._encrypt_block(key, blk)

def test_encrypt_block_boundaries_blk_gt():
    myaes = MYAES()
    key = myaes.keygen()
    blk = b"A"*17
    
    with pytest.raises(Exception):
        myaes._encrypt_block(key, blk)