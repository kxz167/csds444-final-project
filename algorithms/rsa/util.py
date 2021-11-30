import random
from struct import pack, unpack


def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a


def egcd(a, b):
    """
    Source: https://en.wikibooks.org/wiki/Algorithm_Implementation/Mathematics/Extended_Euclidean_algorithm#Iterative_algorithm_3
    """
    x0, x1, y0, y1 = 0, 1, 1, 0
    while a != 0:
        (q, a), b = divmod(b, a), a
        y0, y1 = y1, y0 - q * y1
        x0, x1 = x1, x0 - q * x1
    return b, x0, y0


def mult_inverse(e, n):
    g, x, y = egcd(e, n)
    if g != 1:
        raise Exception("No multiplicative inverse")
    else:
        return x % n


def is_prime_miller(n, k=4):
    """
    Source: https://gist.github.com/Ayrx/5884790
    4 rounds justified by: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf#page=80
    """
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
    if not num & 1:
        num += 1
    while True:
        if is_prime_miller(num):
            return num
        else:
            num = num + 2


def x_to_int(m):
    """Reference https://github.com/dlitz/pycrypto/blob/master/lib/Crypto/Util/number.py"""

    acc = 0
    length = len(m)

    if length % 4:
        extra = (4 - length % 4)
        if isinstance(m, str):
            m = bytes('\000', encoding='utf8') * extra + bytes(m, encoding='utf8')
        elif isinstance(m, bytes):
            m = bytes('\000', encoding='utf8') * extra + m
    else:
        if isinstance(m, str):
            m = bytes(m, encoding='utf8')

    for i in range(0, length, 4):
        acc = (acc << 32) + unpack('>I', m[i:i + 4])[0]

    return acc


def int_to_bytes(num):
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
