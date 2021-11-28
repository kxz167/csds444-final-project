import sys
import os
import collections
import hashlib
import random
import binascii
import secrets
import base64

from mod import Mod
from math import ceil

from algorithms.sha2.sha256 import *

# will be deleted when AES integrated
from cryptography.fernet import Fernet

EllipticCurve = collections.namedtuple('EllipticCurve', 'name p a b g n h')


class HMAC:

    def __init__(self, key):

        #book keeping
        self.block_size = 64
        self.output_size = 32
        self.ipad = b'\x36' * self.block_size
        self.opad = b'\x5c' * self.block_size

        self.key = key

        if len(self.key) > self.block_size:
            self.key = sha256(self.key)

        if len(self.key) < self.block_size:
            # pad with 0s until length is blockSize
            self.key = self.key + b'\x00' * (self.block_size - len(self.key))

        self.h1 = SHA256()
        self.h2 = SHA256()
        self.h1.update(xor(self.key, self.ipad))
        self.h2.update(xor(self.key, self.opad))
        self.finalized = False


    def update(self, message):
        self.h1.update(message)

    def digest(self):
        if self.finalized:
            raise ValueError("Already finalized.")
        h1_digest = self.h1.digest()
        self.h2.update(h1_digest)
        self.finalized = True
        return self.h2.digest()



def sha256(data):
    """
    :param data: bytes-like
    :returns: hash
    """
    h_sha256 = SHA256()
    h_sha256.update(data)
    return h_sha256.hexdigest()

# TEMPORARY: replace with group's AES once done
def fernet_encrypt(m, key):
    """
    :param m: message, bytes-like
    :param key: cryptographic key
    :returns: ciphertext
    """
    f = Fernet(key)
    return f.encrypt(m)

# TEMPORARY: replace with group's AES once done
def fernet_decrypt(c, key):
    """
    :param c: ciphertext, bytes-like
    :param key: cryptographic key
    :returns: plaintext
    """
    f = Fernet(key)
    return f.decrypt(c)


def generate_keys(curve):
    num = secrets.randbelow(curve.n - 1) + 1
    return double_and_add(num, curve.g, curve), num


def point_add(point_1, point_2, curve):
    if point_1 is None:
        return point_2
    if point_2 is None:
        return point_1
    point_1 = mod_ify(curve.p, point_1)
    point_2 = mod_ify(curve.p, point_2)
    if point_1 == point_2:
        lam = ((3 * (point_1[0] ** 2)) + curve.a) // (2 * point_1[1])
    else:
        lam = (point_2[1] - point_1[1]) // (point_2[0] - point_1[0])
    x3 = (lam ** 2) - point_1[0] - point_2[0]
    y3 = -(point_1[1] + lam * (x3 - point_1[0]))
    return x3._value, y3._value


def bits(n):
    """
    Generates the binary digits of n.
    """
    while n:
        yield n & 1
        n >>= 1


def double_and_add(n, P, curve):
    """
    :param n: number of times to add P to itself
    :param P: point on elliptic curve
    :param curve: elliptic curve
    :returns: result of n * P using double and add algorithm
    """
    result = None
    addend = P

    for bit in bits(n):
        if bit == 1:
            result = point_add(result, addend, curve)
        addend = point_add(addend, addend, curve)

    return result


def mod_ify(n, point):
    """
    :param n: modulus
    :param point: tuple of integers
    :returns: modular tuple
    """
    return tuple(Mod(i, n) for i in point)


def xor(x, y):
    return bytes(x[i] ^ y[i] for i in range(min(len(x), len(y))))


def hkdf(length: int, ikm) -> bytes:
    """Key derivation function"""
    hash_len = 32
    prk = HMAC(ikm).digest()
    t = b""
    okm = b""
    for i in range(ceil(length / hash_len)):
        h = HMAC(prk)
        h.update(t + bytes([1 + i]))
        t = h.digest()
        okm += t
    return okm[:length]


def parse_string(s, is_filePath=False):
    """
    :param s: string to be parsed
    :returns: (R, ciphertext, tag)
    """
    tokens = s.split('&')
    R = (int(tokens[0]), int(tokens[1]))
    if is_filePath:
        return R, tokens[2], eval(tokens[3])
    return R, eval(tokens[2]), eval(tokens[3])


def encrypt(m, curve, pub_key, sym_enc_key_size, mac_key_size, encrypt_func=fernet_encrypt, is_filepath=False, file_name=None):
    """
    :param m: message to encrypt
    :param curve: elliptic curve
    :param pub_key: public key of person to receive message (point on elliptic curve)
    :param sym_enc_key_size: size of key for symmetric encryption step
    :param mac_key_size: size of key for MAC verification step
    :param encrypt_func: function to perform encoding using generated key
    :returns: tuple: (point_on_curve, ciphertext, MAC)
    """
    R, r = generate_keys(curve)
    sym_enc_key, mac_key = keys_from_point(r, pub_key, curve, sym_enc_key_size, mac_key_size)
    sym_enc_key = base64.b64encode(sym_enc_key)
    hmac = HMAC(mac_key)

    if is_filepath:
        if file_name is None:
            raise ValueError("Must choose a name for the output file.")
        out = open(file_name, 'wb')
        with open(m, 'rb') as file:
            chunk = 0
            while chunk != b'':
                chunk = file.read(-1)
                c = encrypt_func(chunk, sym_enc_key)
                out.write(c)
                hmac.update(c)
            file.close()
        out.close()
        tag = base64.b64encode(hmac.digest())
        return str(R[0]) + '&' + str(R[1]) + '&' + file_name + '&' + str(tag)
    else:
        c = encrypt_func(m, sym_enc_key)
        hmac = HMAC(mac_key)
        hmac.update(c)
        tag = base64.b64encode(hmac.digest())
        return str(R[0]) + '&' + str(R[1]) + '&' + str(c) + '&' + str(tag)


def decrypt(cipherstring, curve, priv_key, sym_enc_key_size, mac_key_size, decrypt_func=fernet_decrypt, is_filepath=False, file_name=None):

    R, c, tag = parse_string(cipherstring, is_filepath)
    sym_enc_key, mac_key = keys_from_point(priv_key, R, curve, sym_enc_key_size, mac_key_size)
    sym_enc_key = base64.b64encode(sym_enc_key)
    hmac = HMAC(mac_key)

    if is_filepath:
        if file_name is None:
            raise ValueError("Must choose a name for the output file.")
        out = open(file_name, 'wb')
        try:
            with open(c, 'rb') as file:
                chunk = 0
                chunk = file.read(-1)
                while chunk != b'':
                    hmac.update(chunk)
                    m = decrypt_func(chunk, sym_enc_key)
                    out.write(m)
                    chunk = file.read(-1)
                file.close()
            out.close()
        finally:
            file.close()
            out.close()
        d = base64.b64encode(hmac.digest())
        if d != tag:
            raise AssertionError("Computed MAC and received MAC do not match.")
        return file_name
    else:
        hmac.update(c)
        d = base64.b64encode(hmac.digest())
        if d != tag:
            raise AssertionError("Computed MAC and received MAC do not match.")
        m = decrypt_func(c, sym_enc_key)
        return m


def keys_from_point(n, key, curve, sym_enc_key_size, mac_key_size):
    P = double_and_add(n, key, curve)
    S = P[0].to_bytes((P[0].bit_length() + 7) // 8, byteorder='big')
    key = hkdf(sym_enc_key_size + mac_key_size, S)
    # symmetric encryption key
    sym_enc_key = key[0:sym_enc_key_size]
    # MAC key
    mac_key = key[sym_enc_key_size:]
    return sym_enc_key, mac_key


def ecies(m, is_filepath=False):
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

    pub_key, priv_key = generate_keys(curve)
    print("Public Key: " + str(pub_key))
    print("Private Key: " + str(priv_key))

    if is_filepath:
        cstring = encrypt(m, curve, pub_key, 32, 32, is_filepath=True, file_name='encrypted')
        R, c, tag = parse_string(cstring, is_filePath=True)
        print("Point: " + str(R))
        print("Ciphertext filepath: " + str(c))
        print("MAC: " + str(tag))
        res = decrypt(cstring, curve, priv_key, 32, 32, is_filepath=True, file_name='decrypted')
        print("Plaintext filepath: " + res)

        return
        #TODO: make this work for large files
    else:
        cstring = encrypt(m, curve, pub_key, 32, 32)
        R, c, tag = parse_string(cstring)
        print("Point: " + str(R))
        print("Ciphertext: " + str(c))
        print("MAC: " + str(tag))
        res = decrypt(cstring, curve, priv_key, 32, 32)
        print("Plaintext: " + str(res.decode('utf-8')))




