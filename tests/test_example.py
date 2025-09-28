from myaes import MYAES

def test_example():
    myaes = MYAES()
    key = myaes.keygen()
    msg = b"Transfer 100 DKK to Starbucks LT"

    enc = myaes.encrypt(msg, key)
    dec = myaes.decrypt(enc, key)

    assert msg == dec