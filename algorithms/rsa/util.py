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


def process_string(message):
    """Convert string to long integer

    Args:
        message: string

    REFERENCE
    =========
    https://github.com/dlitz/pycrypto/blob/master/lib/Crypto/Util/number.py
    """

    acc = 0
    length = len(message)
    if length % 4:
        extra = (4 - length % 4)
        message = bytes('\000', "utf-8") * extra + bytes(message, "utf-8")

    for i in range(0, length, 4):
        acc = (acc << 32) + unpack('>I', message[i:i+4])[0]

    return acc

def recover_string(number):
    """Convert long to byte string

    Args:
            number: long integer to convert to string

    REFERENCE
    =========
    https://github.com/dlitz/pycrypto/blob/master/lib/Crypto/Util/number.py
    """

    s = bytes('', "utf-8")
    while number > 0:
        s = pack('>I', number & 0xffffffff) + s
        number = number >> 32

    # remove padded zeros
    i = 0
    while i < len(s):
        if s[i] != bytes('\000', "utf-8")[0]:
            break
        i += 1
    return s[i:]
