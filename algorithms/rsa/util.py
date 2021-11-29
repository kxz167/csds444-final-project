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


def is_prime_miller(n, k=4):
    if n == 2:
        return True

    if n == 1 or n % 2 == 0:
        return False

    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    for _ in range(k):
        a = random.randint(2, n - 1)
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(keysize):
    num = random.getrandbits(keysize)
    if not num & 1:  # make sure it's odd
        num += 1
    while True:
        if is_prime_miller(num):
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
