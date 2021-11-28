import random
import math
from struct import pack, unpack


def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a


def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, x, y = egcd(b % a, a)
        return g, y - (b // a) * x, x


def mult_inverse(e, n):
    g, x, y = egcd(e, n)
    if g != 1:
        raise Exception("No multiplicative inverse")
    else:
        return x % n


def is_prime(x):
    if x == 2:
        return True
    elif x < 2 or x % 2 == 0:
        return False
    for i in range(3, int(math.sqrt(x) + 2), 2):
        if x % i == 0:
            return False
    return True


def generate_prime(keysize=5):
    num = random.randint(2 ** (keysize - 1), 2 ** (keysize))
    while True:
        if is_prime(num):
            return num
        else:
            num = num + 1


def string_to_long(m):
    """Reference https://github.com/dlitz/pycrypto/blob/master/lib/Crypto/Util/number.py"""

    acc = 0
    length = len(m)
    if length % 4:
        extra = (4 - length % 4)
        m = bytes('\000', encoding='utf8') * extra + bytes(m, encoding='utf8')

    for i in range(0, length, 4):
        acc = (acc << 32) + unpack('>I', m[i:i + 4])[0]

    return acc


def long_to_bytes(num):
    """Reference https://github.com/dlitz/pycrypto/blob/master/lib/Crypto/Util/number.py"""

    s = bytes('', encoding='utf8')
    while num > 0:
        s = pack('>I', num & 0xffffffff) + s
        num = num >> 32

    i = 0
    while i < len(s):
        if s[i] != bytes('\000', encoding='utf8')[0]:
            break
        i += 1
    return s[i:]


def mod_exp(a, e, p):
    ans = 1
    a = a % p

    if a == 0:
        return 0

    while e > 0:
        if (e % 2) == 0:
            e = e / 2
            a = (a * a) % p

        else:
            ans = (ans * a) % p
            e = e - 1

    return ans


def int2bytes(number: int, fill_size: int = 0) -> bytes:
    """
    Convert an unsigned integer to bytes (big-endian)::
    Does not preserve leading zeros if you don't specify a fill size.
    :param number:
        Integer value
    :param fill_size:
        If the optional fill size is given the length of the resulting
        byte string is expected to be the fill size and will be padded
        with prefix zero bytes to satisfy that length.
    :returns:
        Raw bytes (base-256 representation).
    :raises:
        ``OverflowError`` when fill_size is given and the number takes up more
        bytes than fit into the block. This requires the ``overflow``
        argument to this function to be set to ``False`` otherwise, no
        error will be raised.
    """

    if number < 0:
        raise ValueError("Number must be an unsigned integer: %d" % number)

    bytes_required = max(1, math.ceil(number.bit_length() / 8))

    if fill_size > 0:
        return number.to_bytes(fill_size, "big")

    return number.to_bytes(bytes_required, "big")
