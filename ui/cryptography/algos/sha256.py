import copy

F32 = 0xFFFFFFFF

# K constants
K32 = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
      0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
      0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
      0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
      0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
      0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
      0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
      0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
      0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]

# H constants
H32 = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]

# WORD size in bytes
WORD_SIZE = 4

def ch(x, y, z):
    return (x & y) ^ ((~x) & z)

def maj(x, y, z):
    return (x & y) ^ (x & z) ^ (y & z)

def right_rotate_32(x, y):
    return ((x >> y) | (x << (32 - y))) & F32

def sigma_0(m): 
    return right_rotate_32(m, 7) ^ right_rotate_32(m, 18) ^ (m >> 3)

def sigma_1(m): 
    return right_rotate_32(m, 17) ^ right_rotate_32(m, 19) ^ (m >> 10)

def Sigma_0(m):
    return right_rotate_32(m, 2) ^ right_rotate_32(m, 13) ^ right_rotate_32(m, 22)

def Sigma_1(m):
    return right_rotate_32(m, 6) ^ right_rotate_32(m, 11) ^ right_rotate_32(m, 25)

def pad(msg_len: int):
    """
    Total padding for data

    <msg> + \x80 (first 32 bits with the first bit = 1) + \00 (mult)
    """
    # Message is stored as bytes, calculate bit-length requires multiplication by 8
    bit_len = (msg_len * 8)

    # 64 bit representation of bit length
    length = bit_len.to_bytes(8, 'big')

    # Appending blocks of bytes, blocks = K / 8
    blocks = 0

    while (bit_len + 8 + blocks * 8 + 64) % 512 != 0:
        blocks += 1

    return b'\x80' + (b'\x00' * blocks) + length

class SHA256:

    def __init__(self, visual=False):

        # UI Mode?
        self.visual = visual
        self._steps = []

        self._cache = b''
        self._msg_len = 0
        self._H = copy.deepcopy(H32)
        self._K = copy.deepcopy(K32)
        self.rounds = 0


    def __compress(self, chunk: bytes) -> None:
        """
        Main Compression algorithm
        """
        assert len(chunk) == 64, "All chunks to be compressed must be 64 bytes (512 bits)"
        visual_dict = {
            'chunk': chunk
        }
        # 32 bit words
        w = [0] * 64

        # copy 512 bit chunk into the first 16 words of the w buffer
        w[:16] = [int.from_bytes(chunk[i * WORD_SIZE :i * WORD_SIZE + WORD_SIZE], 'big') for i in range(16)]

        for i in range(16, 64):
            w[i] = (w[i - 16] + sigma_0(w[i - 15]) + w[i - 7] + sigma_1(w[i - 2])) & F32

        a, b, c, d, e, f, g, h = self._H
        if self.visual:
            visual_dict['w'] = w
            visual_dict['rounds'] = []

        for i in range(64):
            temp1 = (h + Sigma_1(e) + ch(e, f, g) + self._K[i] + w[i]) & F32
            temp2 = (Sigma_0(a) + maj(a, b, c)) & F32
    
            h = g
            g = f
            f = e

            e = (d + temp1) & F32
            d = c
            c = b
            b = a

            a = (temp1 + temp2) & F32
            if self.visual:
                visual_dict['rounds'].append({
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
                })
        for i, (h, x) in enumerate(zip(self._H, [a, b, c, d, e, f, g, h])):
            self._H[i] = (h + x) & F32
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

        while len(self._cache) >= 64:
            self.__compress(self._cache[:64])
            self._cache = self._cache[64:]
    
    def digest(self) -> bytes:
        sha_copy = copy.deepcopy(self)

        # Append additional padded bits
        sha_copy.update(pad(self._msg_len))

        hash_buffer = b''
        for h in sha_copy._H:
            hash_buffer += h.to_bytes(WORD_SIZE, 'big')
        return hash_buffer
    
    @property
    def steps(self):
        if not self.visual:
            raise NotImplementedError("SHA-256 is not in visual mode")
        sha_copy = copy.deepcopy(self)

        # Append additional padded bits
        sha_copy.update(pad(self._msg_len))
        return sha_copy._steps

    def hexdigest(self) -> str:
        return self.digest().hex()