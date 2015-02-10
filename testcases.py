from Crypto.Util.strxor import strxor
from Crypto.Cipher import AES
from Matasano import *


def test1():
    test_str = ("49276d206b696c6c696e6720796f75722062726169" +
            "6e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
    decoded = test_str.decode("hex")
    base64 = encode_base64(decoded)
    if base64 == \
            "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t":
        print "Simple encoding and decoding works."


def test2():
    test_1 = "1c0111001f010100061a024b53535009181c"
    test_2 = "686974207468652062756c6c277320657965"
    if hex_xor(test_1, test_2) == "746865206b696420646f6e277420706c6179":
        print "Hex XOR works."


def test3():
    key = "YELLOW SUBMARINE"
    with open("7.txt", "r") as f:
        e = f.read()
        e = e.replace("\n", "")
    e = e.decode("base64")
    cipher = AES.new(key)
    if cipher.decrypt(e)[:15] == "I'm back and I'":
        print "Basic cipher decrypting works."

def test4():
    exp_1 = "YELLOW SUBMARINE" + chr(4) * 4
    exp_2 = "YELLOW SUBMARINEABCD" + chr(20) * 20
    if (padding("YELLOW SUBMARINE", 20) == exp_1 and
            padding("YELLOW SUBMARINEABCD", 20) == exp_2):
        print "Padding works."

def test5a():
    key = "YELLOW SUBMARINE"
    ecb_16 = AES.new(key)
    iv = chr(0) * 16

    test_message = "hello world"
    enc = cbc_encrypt(ecb_16, test_message, iv, 16)
    dec = cbc_decrypt(ecb_16, enc, iv, 16)
    if dec == padding(test_message, 16):
        print "CBC encode/decode is symmetrical."

def test5b():
    key = "YELLOW SUBMARINE"
    ecb_16 = AES.new(key)
    iv = chr(0) * 16

    with open("10.txt", "r") as f:
        e = f.read()
        e = e.replace("\n", "")
    e = e.decode("base64")
    decode = cbc_decrypt(ecb_16, e, iv, 16)
    if decode[:15] == "I'm back and I'":
        print "CBC cipher decrypting works."