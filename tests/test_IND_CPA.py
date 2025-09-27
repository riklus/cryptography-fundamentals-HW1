from myaes import MYAES

def test_IND_CPA():
    myaes = MYAES()
    key = myaes.keygen()
    msg = b"Transfer 100 DKK to Starbucks LT"
    enc = bytearray(myaes.encrypt(msg, key))

    # Attack: Attacker knows the message's format
    pos = msg.find(b"1") + 16       # Find 100 DKK byte position, skipping the IV
    enc[pos] ^= 0x04                # Flip 100 DKK to 500 DKK

    # Victim decrypts the message
    dec = myaes.decrypt(bytes(enc), key)

    assert dec == b"Transfer 500 DKK to Starbucks LT"