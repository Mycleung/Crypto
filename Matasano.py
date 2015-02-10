from Crypto.Util.strxor import strxor
from Crypto.Cipher import AES
import testcases

def encode_base64(binary_str):
    return binary_str.encode("base64").rstrip()

def hex_xor(str_1, str_2):
    """
    Takes two hex strings and Xors them

    :param str_1: Hex string
    :param str_2: Hex string
    :return: Hex string
    """
    return strxor(str_1.decode("hex"), str_2.decode("hex")).encode("hex")

def padding(in_str, block_len):
    padding_required = block_len % len(in_str)
    if not padding_required:
        return in_str + chr(block_len) * block_len
    else:
        return in_str + chr(padding_required) * padding_required

def cbc_encrypt(cipher, input_bin_str, iv, block_len):
    # Function for encrypting a single block
    def encrypt_block(cipher, inp_str, iv):
        return cipher.encrypt(strxor(inp_str, iv))

    output_str = ""
    block_list = pad_and_blockify(input_bin_str, block_len)

    # Iteratively encrypt each block, passing the result to be the iv of
    # the next block's encryption
    next_iv = iv
    for block in block_list:
        next_iv = encrypt_block(cipher, block, next_iv)
        output_str += next_iv

    return output_str

def pad_and_blockify(input_bin_str, block_len):
    # Apply padding
    encode_str = padding(input_bin_str, block_len)
    # Pad and blockify
    return blockify(encode_str, block_len)

def blockify(input_bin_str, block_len):
    return [input_bin_str[i:i+block_len] for i in range(0,
                                              len(input_bin_str),
                                              block_len)]

def cbc_decrypt(cipher, input_bin_str, iv, block_len):
    # Function for decrypting a single block
    def decrypt_block(cipher, enc_str, iv):
        return strxor(cipher.decrypt(enc_str), iv)

    output_str = ""
    block_list = blockify(input_bin_str, block_len)

    next_iv = iv
    for block in block_list:
        output_str += decrypt_block(cipher, block, next_iv)
        next_iv = block

    return output_str

if __name__ == "__main__":
    testcases.test1()
    testcases.test2()
    testcases.test3()
    testcases.test4()
    testcases.test5a()
    testcases.test5b()