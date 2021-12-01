import copy
import json
from bitstring import BitArray

byte_block = 128 # 1024 bits
bit_length = 2**64
F64 = 0xffffffffffffffff

# CONSTANTS:
word_constants=[0x428a2f98d728ae22,0x7137449123ef65cd,0xb5c0fbcfec4d3b2f,0xe9b5dba58189dbbc,0x3956c25bf348b538,0x59f111f1b605d019,0x923f82a4af194f9b,0xab1c5ed5da6d8118,0xd807aa98a3030242,0x12835b0145706fbe,0x243185be4ee4b28c,0x550c7dc3d5ffb4e2,0x72be5d74f27b896f,0x80deb1fe3b1696b1,0x9bdc06a725c71235,0xc19bf174cf692694,0xe49b69c19ef14ad2,0xefbe4786384f25e3,0x0fc19dc68b8cd5b5,0x240ca1cc77ac9c65,0x2de92c6f592b0275,0x4a7484aa6ea6e483,0x5cb0a9dcbd41fbd4,0x76f988da831153b5,0x983e5152ee66dfab,0xa831c66d2db43210,0xb00327c898fb213f,0xbf597fc7beef0ee4,0xc6e00bf33da88fc2,0xd5a79147930aa725,0x06ca6351e003826f,0x142929670a0e6e70,0x27b70a8546d22ffc,0x2e1b21385c26c926,0x4d2c6dfc5ac42aed,0x53380d139d95b3df,0x650a73548baf63de,0x766a0abb3c77b2a8,0x81c2c92e47edaee6,0x92722c851482353b,0xa2bfe8a14cf10364,0xa81a664bbc423001,0xc24b8b70d0f89791,0xc76c51a30654be30,0xd192e819d6ef5218,0xd69906245565a910,0xf40e35855771202a,0x106aa07032bbd1b8,0x19a4c116b8d2d0c8,0x1e376c085141ab53,0x2748774cdf8eeb99,0x34b0bcb5e19b48a8,0x391c0cb3c5c95a63,0x4ed8aa4ae3418acb,0x5b9cca4f7763e373,0x682e6ff3d6b2b8a3,0x748f82ee5defb2fc,0x78a5636f43172f60,0x84c87814a1f0ab72,0x8cc702081a6439ec,0x90befffa23631e28,0xa4506cebde82bde9,0xbef9a3f7b2c67915,0xc67178f2e372532b,0xca273eceea26619c,0xd186b8c721c0c207,0xeada7dd6cde0eb1e,0xf57d4f7fee6ed178,0x06f067aa72176fba,0x0a637dc5a2c898a6,0x113f9804bef90dae,0x1b710b35131c471b,0x28db77f523047d84,0x32caab7b40c72493,0x3c9ebe0a15c9bebc,0x431d67c49c100d4c,0x4cc5d4becb3e42b6,0x597f299cfc657e2a,0x5fcb6fab3ad6faec,0x6c44198c4a475817]
initial_vector_values = [0x6a09e667f3bcc908,0xbb67ae8584caa73b,0x3c6ef372fe94f82b,0xa54ff53a5f1d36f1,0x510e527fade682d1,0x9b05688c2b3e6c1f,0x1f83d9abfb41bd6b,0x5be0cd19137e2179]

import os

def sha_pad(value, pad):
    # print(((value << 1) | 1 ) << (pad-1))
    return ((value << 1) | 1 ) << (pad-1)

def left_rotate_64(number, shifts):
    return ((number << shifts) | (number >> (64 - shifts))) & 0xffffffffffffffff

def right_rotate_64(number, shifts):
    return (number >> shifts) | (number << (64 - shifts)) & 0xffffffffffffffff

def append_64(original, appended):
    return (original << 64) | appended

def concatenate(h0, h1, h2, h3, h4, h5, h6, h7):
    return append_64(append_64(append_64(append_64(append_64(append_64(append_64(h0, h1), h2), h3), h4), h5), h6), h7)

def sigma_0 (word):
    return (right_rotate_64(word, 1) ^ (right_rotate_64(word, 8)) ^ (word >> 7))

def sigma_1 (word):
    return  (right_rotate_64(word, 19) ^ (right_rotate_64(word, 61)) ^ (word >> 6))

def Sigma_0 (word):
    return (right_rotate_64(word, 28) ^ (right_rotate_64(word, 34) ^ (right_rotate_64(word, 39))))

def Sigma_1 (word):
    return (right_rotate_64(word, 14) ^ (right_rotate_64(word, 18)) ^ (right_rotate_64(word, 41)))

def ch(x,y,z):
    return (x & y) ^ ((~x) & z)

def maj(x, y, z):
    return (x & y) ^ (x & z) ^ (y & z)

def pad(msg_len: int):
    """
    Total padding for data
    <msg> + \x80 (first 32 bits with the first bit = 1) + \00 (mult)
    """
    # Message is stored as bytes, calculate bit-length requires multiplication by 8
    bit_len = (msg_len * 8)

    # 64 bit representation of bit length
    length = bit_len.to_bytes(16, 'big')

    # Appending blocks of bytes, blocks = K / 8
    blocks = 0

    while (bit_len + 8 + blocks * 8 + 128) % 1024 != 0:
        blocks += 1

    return b'\x80' + (b'\x00' * blocks) + length


class SHA512:

    def __init__(self, visual=False):

        # UI Mode?
        self.visual = visual
        self._steps = []

        self._cache = b''
        self._msg_len = 0
        self._H = copy.deepcopy(initial_vector_values)
        self._K = copy.deepcopy(word_constants)
        self.rounds = 0


    def __compress(self, chunk: bytes) -> None:
        """
        Main Compression algorithm
        """
        assert len(chunk) == byte_block, "All chunks to be compressed must be 128 bytes (1024 bits)"
        if self.visual:
            visual_dict = {
                'msg':  BitArray(chunk).hex,
                'substeps': []
            }
        w = [0] * 80

        w[:16] = [int.from_bytes(chunk[i * 8 : i * 8 + 8], 'big') for i in range(16)]

        for i in range(16, 80):
            w[i] = w[i-16] + sigma_0(w[i-15]) + w[i-7] + sigma_1(w[i-2]) & F64

        a, b, c, d, e, f, g, h = self._H

        for i in range(80):
            temp1 = (h + Sigma_1(e) + ch(e, f, g) + self._K[i] + w[i]) & F64
            # S0 := (a rightrotate 28) xor (a rightrotate 34) xor (a rightrotate 39)
            # S0 = Sigma_0(a)
            # maj := (a and b) xor (a and c) xor (b and c)
            # maj = (a & b) ^ (a & c) ^ (b & c)
            # temp2 := S0 + maj
            temp2 = (Sigma_0(a) + maj(a, b, c)) & F64
    
            h = g
            g = f
            f = e

            e = (d + temp1) & F64
            d = c
            c = b
            b = a

            a = (temp1 + temp2) & F64
            if self.visual:
                substep_dict = {
                    'round': i,
                    'a': a,
                    'b': b,
                    'c': c,
                    'd': d,
                    'e': e,
                    'f': f,
                    'g': g,
                    'h': h,
                    'temp1': temp1,
                    'temp2': temp2
                }
                visual_dict['substeps'].append(json.dumps(substep_dict, indent=4))
        for i, (h, x) in enumerate(zip(self._H, [a, b, c, d, e, f, g, h])):
            self._H[i] = (h + x) & F64
        if self.visual:
            self._steps.append(visual_dict)

    def update(self, msg: bytes) -> None:
        """
        Update the SHA hex with new data
        """
        if msg is None:
            return
        
        # Update msg length in bytes
        self._msg_len += len(msg)
        self._cache += msg

        while len(self._cache) >= 128:
            self.__compress(self._cache[:128])
            self._cache = self._cache[128:]
    
    def digest(self) -> bytes:
        sha_copy = copy.deepcopy(self)

        # Append additional padded bits
        sha_copy.update(pad(self._msg_len))
        hash_buffer = b''
        for h in sha_copy._H:
            hash_buffer += h.to_bytes(8, 'big')
        return hash_buffer

    @property
    def steps(self):
        sha_copy = copy.deepcopy(self)

        # Append additional padded bits
        sha_copy.update(pad(self._msg_len))
        return sha_copy._steps

    def hexdigest(self) -> str:
        return self.digest().hex()