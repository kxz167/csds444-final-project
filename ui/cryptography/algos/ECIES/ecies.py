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

from ..sha256 import *
from ..AES.AES import *

EllipticCurve = collections.namedtuple('EllipticCurve', 'name p a b g n h')


class HMAC:

    def __init__(self, key):

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


def encrypt(m, key):
    """
    :param m: message, bytes-like
    :param key: cryptographic key (assumed 192 bits)
    :returns: ciphertext
    """
    if len(key) != 192:
        raise ValueError("Key must be 192-bit for AES")
    return encode_byte_list(list(m), list(key))


def decrypt(c, key):
    """
    :param c: ciphertext, bytes-like
    :param key: cryptographic key (assumed 192 bits)
    :returns: plaintext
    """
    if len(key) != 192:
        raise ValueError("Key must be 192-bit for AES")
    return decode_byte_list(list(c), list(key))


def generate_key(curve):
    num = secrets.randbelow(curve.n - 1) + 1
    return num


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


def encrypt(m, curve, pub_key, sym_enc_key_size, mac_key_size, data, encrypt_func=encrypt, is_filepath=False,
            file_name=None):
    """
    :param m: message to encrypt
    :param curve: elliptic curve
    :param pub_key: public key of person to receive message (point on elliptic curve)
    :param sym_enc_key_size: size of key for symmetric encryption step
    :param mac_key_size: size of key for MAC verification step
    :param encrypt_func: function to perform encoding using generated key
    :returns: tuple: (point_on_curve, ciphertext, MAC)
    """
    r = generate_key(curve)
    R = double_and_add(r, curve.g, curve)
    data['random_number'] = r
    data['random_number_EC_point'] = R
    sym_enc_key, mac_key, data = keys_from_point(r, pub_key, curve, sym_enc_key_size, mac_key_size, data)
    hmac = HMAC(mac_key)

    if is_filepath:
        if file_name is None:
            raise ValueError("Must choose a name for the output file.")
        data['ciphertext'] = file_name
        out = open(file_name, 'wb')
        with open(m, 'rb') as file:
            chunk = 0
            while chunk != b'':
                chunk = file.read(-1)
                c = encrypt_func(chunk, sym_enc_key)
                out.write(bytes(c))
                hmac.update(bytes(c))
            file.close()
        out.close()
        tag = base64.b64encode(hmac.digest())
        data['mac_tag'] = tag
        return str(R[0]) + '&' + str(R[1]) + '&' + file_name + '&' + str(tag), data
    else:
        c = encrypt_func(bytes(m, 'utf-8'), sym_enc_key)
        hmac = HMAC(mac_key)
        hmac.update(bytes(c))
        data['ciphertext'] = bytes(c)
        tag = base64.b64encode(hmac.digest())
        data['mac_tag'] = tag
        return str(R[0]) + '&' + str(R[1]) + '&' + str(c) + '&' + str(tag), data


def decrypt(cipherstring, curve, priv_key, sym_enc_key_size, mac_key_size, data, decrypt_func=decrypt,
            is_filepath=False, file_name=None):
    R, c, tag = parse_string(cipherstring, is_filepath)
    sym_enc_key, mac_key, data = keys_from_point(priv_key, R, curve, sym_enc_key_size, mac_key_size, data)
    hmac = HMAC(mac_key)

    if is_filepath:
        if file_name is None:
            raise ValueError("Must choose a name for the output file.")
        data['plaintext'] = file_name
        out = open(file_name, 'wb')
        try:
            with open(c, 'rb') as file:
                chunk = 0
                chunk = file.read(-1)
                while chunk != b'':
                    hmac.update(chunk)
                    m = decrypt_func(chunk, sym_enc_key)
                    out.write(bytes(m))
                    chunk = file.read(-1)
                file.close()
            out.close()
        finally:
            file.close()
            out.close()
        d = base64.b64encode(hmac.digest())
        if d != tag:
            raise AssertionError("Computed MAC and received MAC do not match.")
        return file_name, data
    else:
        hmac.update(bytes(c))
        d = base64.b64encode(hmac.digest())
        if d != tag:
            raise AssertionError("Computed MAC and received MAC do not match.")
        m = decrypt_func(c, sym_enc_key)
        data['plaintext'] = bytes(m).decode('utf-8').rstrip('\x00')
        return m, data


def keys_from_point(n, key, curve, sym_enc_key_size, mac_key_size, data):
    P = double_and_add(n, key, curve)
    data['shared_secret_point'] = P
    S = P[0].to_bytes((P[0].bit_length() + 7) // 8, byteorder='big')
    data['shared_secret'] = S
    key = hkdf(sym_enc_key_size + mac_key_size, S)
    # symmetric encryption key
    sym_enc_key = key[0:sym_enc_key_size]
    data['sym_enc_key'] = sym_enc_key
    # MAC key
    mac_key = key[sym_enc_key_size:]
    data['mac_key'] = mac_key
    return sym_enc_key, mac_key, data


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

    data = {'prime': curve.p, 'a': curve.a, 'b': curve.b, 'generator': curve.g, 'subgroup_order': curve.n,
            'subgroup_cofactor': curve.h, 'public_key': None, 'private_key': None, 'random_number': None,
            'random_number_EC_point': None, 'shared_secret_point': None, 'shared_secret': None,
            'sym_enc_key': None, 'mac_key': None, 'mac_tag': None, 'ciphertext': None, 'plaintext': None,
            'is_filepath': is_filepath}

    priv_key = generate_key(curve)
    pub_key = double_and_add(priv_key, curve.g, curve)
    data['public_key'] = str(pub_key)
    data['private_key'] = str(priv_key)

    if is_filepath:
        cstring, data = encrypt(m, curve, pub_key, 192, 32, data, is_filepath=True, file_name='encrypted')
        R, c, tag = parse_string(cstring, is_filePath=True)
        res, data = decrypt(cstring, curve, priv_key, 192, 32, data, is_filepath=True, file_name='decrypted')
    else:
        cstring, data = encrypt(m, curve, pub_key, 192, 32, data)
        R, c, tag = parse_string(cstring)
        res, data = decrypt(cstring, curve, priv_key, 192, 32, data)
    return data


def to_string(data):
    """
    :param data: dictionary of all important info from encryption/decryption process
    :returns: (results, steps)
    """
    results = {
        'string_text': data['plaintext']
    }
    if data['is_filepath']:
        results['file'] = {
            'encrypted': 'encrypted',
            'decrypted': 'decrypted'
        }
    step1 = {
        'msg': 'Below are the details of the elliptic curve (y^3 = x^2 + ax + b (mod p)) used for encryption.',
        'substeps': ['prime: ' + str(data['prime']) + ', a: ' + str(data['a'] )+ ', b: ' + str(data['b']) +
                     ', generator point: ' + str(data['generator']) + ', order of subgroup: ' +
                     str(data['subgroup_order']) + ', cofactor of subgroup: ' + str(data['subgroup_cofactor'])]
    }

    step2 = {
        'msg': 'Let Alice be the sender, and Bob the receiver. Bob\'s private key is derived by picking a number ' +
               'uniformly at random between 1 and the subgroup order. Call this number \'kb\'. His public key, KB, is' +
               ' a point on the elliptic curve with rational coefficients, obtained by adding the generator point to' +
               'itself kb times. Note that the rational points on an elliptic curve form a group under addition:' +
               ' adding two points with rational coefficients on the curve produces a third on the curve. Alice reads' +
               ' KB from a public ledger.',
        'substeps': ['kb: ' + str(data['public_key']) + ', KB: ' + str(data['private_key'])]
    }

    step3 = {
        'msg': 'Alice generates a random number r and the associated point R, identically to how Bob derived his keys' +
               '. Then, Alice adds Bob\'s public key to itself r times, generating a point P on the curve. The x ' +
               'coordinate of this point is the shared secret, S. This shared secret is the input to the key ' +
               'derivation function (KDF), which computes both the symmetric encryption key and the message' +
               ' authentication code (MAC) key.',
        'substeps': ['r: ' + str(data['random_number']) + ', R: ' + str(data['random_number_EC_point']) + ', P: ' +
                     str(data['shared_secret_point']) + ', S: ' + str(data['shared_secret']) + ', symmetric encryption' +
                     ' key: ' + str(data['sym_enc_key']) + ', MAC key: ' + str(data['mac_key'])]
    }

    step4 = {
        'msg': 'The symmetric encryption key is used to encrypt the plaintext using AES, while the MAC key is used by' +
               ' the HMAC algorithm to compute the MAC tag, which verifies the authenticity of the message. Alice' +
               ' broadcasts her point R, the ciphertext (c), and the MAC to Bob: R||c||MAC',
        'substeps': [('ciphertext: ' + str(data['ciphertext']) + ', ' if not data['is_filepath'] else '') + 'MAC: ' +
                     str(data['mac_tag'])]
    }

    step5 = {
        'msg': 'Bob receives R||c||MAC from Alice and parses it. He derived the shared secret S = P_x, where ' +
               'P = (P_x, P_y) = r * KB. This is the same as the one Alice computed, since P = kb * R = kb * r * G =' +
               ' r * kb * G = r * KB. Using S, Bob can derive the symmetric encryption keys and MAC keys the same way' +
               ' Alice did. Bob computes the MAC using the MAC key, and checks to make sure they match. If they do, ' +
               'Bob uses AES to decrypt the ciphertext with the symmetric encryption key he derived.',
        'substeps': [('plaintext: ' + str(data['plaintext']) if not data['is_filepath'] else '')]
    }

    steps = [step1, step2, step3, step4, step5]

    return results, steps