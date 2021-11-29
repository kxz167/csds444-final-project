import random
import util


class RSA:

    def __init__(self, size=20):
        self.bit_size = size

        self.p = util.generate_prime(self.bit_size)
        self.q = util.generate_prime(self.bit_size)
        while self.p == self.q:
            self.q = util.generate_prime(self.bit_size)

        self.n = self.p * self.q

        self.phi = (self.p - 1) * (self.q - 1)

        self.public_key, self.private_key = self.generate_keys()

    def generate_keys(self):
        g = 0
        while g != 1:
            e = random.randint(2, self.phi - 1)
            g = util.gcd(self.phi, e)

        d = util.mult_inverse(e, self.n)

        public_key = (e, self.n)
        private_key = (d, self.n)

        return public_key, private_key

    def encrypt(self, m: int, key):
        e, n = key
        c = util.mod_exp(m, e, n)
        return c

    def decrypt(self, c: int):
        d, n = self.private_key
        p = util.mod_exp(c, d, n)
        return p


if __name__ == '__main__':

    Alice = RSA()
    Bob = RSA()
    mess = "h"
    m = util.string_to_long(mess)
    c = RSA.encrypt(Alice, m, Bob.public_key)
    p = RSA.decrypt(Bob, c)
    print("Message:", mess)
    print("Public key:", Bob.public_key)
    print("Private key:", Bob.private_key)
    print("Message int:", m)
    print("Ciphertext:", c)
    print("Plaintext int:", p)
    print("Plaintext bytes:", util.recover_string(p))
    print("Decrypted plaintext:", util.long_to_bytes(p).decode('utf8'))
