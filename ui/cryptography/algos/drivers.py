from typing import Union
from .AES.AES import *
from .ECIES.ecies import *
from .rsa.rsa import *
from .sha512 import *
from .sha256 import *
from django.conf import settings
import pathlib

'''
File/Text Writting related IO controls
'''

def rsa_encrypt(msg: str, is_file=True):
    rsa_obj = RSA()
    cipher = rsa_obj.encrypt(msg, is_file=is_file)
    return cipher, rsa_obj.private_key

def rsa_decrypt(cipher, private_key, to_file=False):
    result = ''
    rsa_obj = RSA()
    rsa_obj.private_key = private_key
    try:
        result = rsa_obj.decrypt(cipher)
    except Exception:
        return result

    if to_file:
        filepath = str(os.path.join(os.path.join(settings.BASE_DIR, 'temp'), 'rsa_decoded'))
        with open(filepath, 'w') as f: 
            f.write(result)
        return filepath
    else:
        return result

curve = EllipticCurve(
        'secp256k1',
        # Field characteristic.
        p=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f,
        # Curve coefficients.
        a=0,
        b=7,
        # Base point.
        g=(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
           0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8),
        # Subgroup order.
        n=0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141,
        # Subgroup cofactor.
        h=1,
    )

def ecies_encrypt(msg: str, is_file=False):

    data = {'prime': curve.p, 'a': curve.a, 'b': curve.b, 'generator': curve.g, 'subgroup_order': curve.n,
            'subgroup_cofactor': curve.h, 'public_key': None, 'private_key': None, 'random_number': None,
            'random_number_EC_point': None, 'shared_secret_point': None, 'shared_secret': None,
            'sym_enc_key': None, 'mac_key': None, 'mac_tag': None, 'ciphertext': None, 'plaintext': None,
            'is_filepath': is_file}
    priv_key = generate_key(curve)
    pub_key = double_and_add(priv_key, curve.g, curve)
    file_path = str(os.path.join(os.path.join(settings.BASE_DIR, 'temp'), 'encrypted'))
    cstring, data = encrypt(msg, curve, pub_key, 192, 32, data, is_filepath=is_file, file_name=file_path)

    return data['ciphertext'], data['private_key'], cstring

def ecies_decrypt(cstring: str, priv_key: int, is_file=False):
    data = {'prime': curve.p, 'a': curve.a, 'b': curve.b, 'generator': curve.g, 'subgroup_order': curve.n,
            'subgroup_cofactor': curve.h, 'public_key': None, 'private_key': None, 'random_number': None,
            'random_number_EC_point': None, 'shared_secret_point': None, 'shared_secret': None,
            'sym_enc_key': None, 'mac_key': None, 'mac_tag': None, 'ciphertext': None, 'plaintext': None,
            'is_filepath': is_file}
    file_path = str(os.path.join(os.path.join(settings.BASE_DIR, 'temp'), 'decrypted'))
    res, data = decrypt(cstring, curve, priv_key, 192, 32, data, is_filepath=is_file, file_name=file_path)
    return data['plaintext']

def aes_pad(msg: bytes):
    padding_len = 16 - (len(msg) % 16)
    padding = bytes([padding_len] * padding_len)
    return msg + padding

def aes_unpad(plaintext):
    """
    Removes a PKCS#7 padding, returning the unpadded text and ensuring the
    padding was correct.
    """
    padding_len = plaintext[-1]
    assert padding_len > 0
    message, padding = plaintext[:-padding_len], plaintext[-padding_len:]
    assert all(p == padding_len for p in padding)
    return message

def aes_encrypt(msg: str, key_int: int, is_file: bool=False):
    if is_file:
        input_data = open(msg, 'rb').read()
        input_data = aes_pad(input_data)
        msg_bytes = []
        for i in range(len(input_data)):
            msg_bytes.append(input_data[i])
    else:
        msg_bytes = msg.encode('utf-8')
    key = []
    for _ in range(6):
        key.append(key_int & 0xFFFFFFFF)
        key_int >> 32
    encoded_results = encode_byte_list(msg_bytes, key)
    output_string = ""
    for byte in encoded_results:
        output_string += str(byte) + " "
    with open('temp/aes_encoded', 'w') as f:
        f.write(output_string)
    return 'temp/aes_encoded'

def aes_decrypt(msg: str, key_int: int, is_file: bool=False):
    if is_file:
        string = open(msg, 'r').read()

        string_byte_array = string.split(" ")
        byte_array = []
        for string_byte in string_byte_array:
            if string_byte != "":
                byte_array.append(int(string_byte))
    else:
        string_byte_array = msg.split(" ")
        byte_array = []
        for string_byte in string_byte_array:
            if string_byte != "":
                byte_array.append(int(string_byte))
    key=[]
    for _ in range(6):
        key.append(key_int & 0xFFFFFFFF)
        key_int >> 32
    encoded_boi = decode_byte_list(byte_array, key)
    # print(output_string)
    with open('temp/aes_decoded', "wb") as f:
        f.write(aes_unpad(bytearray(encoded_boi)))
    return 'temp/aes_decoded'


    

