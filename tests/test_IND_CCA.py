import secrets
from pytest import mark
from Crypto.Util.strxor import strxor
from myaes import MYAES


def test_malleability():
    myaes = MYAES()
    key = myaes.keygen()
    msg = b"Transfer 100 DKK to Starbucks LT"
    enc = bytearray(myaes.encrypt(msg, key))

    # Attack: Attacker knows the message's format
    pos = msg.find(b"1") + 16  # Find 100 DKK byte position, skipping the IV
    enc[pos] ^= 0x04  # Flip 100 DKK to 500 DKK

    # Victim decrypts the message
    dec = myaes.decrypt(bytes(enc), key)

    assert dec == b"Transfer 500 DKK to Starbucks LT"


@mark.parametrize("_", range(0, 1024))
def test_IND_CPA_a(_):
    myaes = MYAES()
    key = myaes.keygen()

    # Attacker can't access m1, m2, msg variable
    m1, m2 = (b"\x00" * 16 + b"\x00" * 16), (b"\xff" * 16 + b"\xff" * 16)
    msg = secrets.choice([m1, m2])
    enc = myaes.encrypt(msg, key)

    # Attacker drops last block from msg
    dec = myaes.decrypt(enc[:-16], key)

    if dec == b"\x00" * 16:
        assert msg == m1
    elif dec == b"\xff" * 16:
        assert msg == m2


@mark.parametrize("_", range(0, 1024))
def test_IND_CPA_b(_):
    myaes = MYAES()
    key = myaes.keygen()

    # Attacker can't access m1, m2, msg variable
    m1, m2 = (b"\x00" * 16 + b"\x00" * 16), (b"\xff" * 16 + b"\xff" * 16)
    msg = secrets.choice([m1, m2])
    enc = myaes.encrypt(msg, key)

    # Attacker flips every bit in last msg block
    dec = myaes.decrypt(enc[:-16] + strxor(enc[16:], b"\ff" * 16), key)

    if dec[:16] == b"\x00" * 16:
        assert msg == m1
    elif dec[:16] == b"\xff" * 16:
        assert msg == m2
