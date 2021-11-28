import random
import util


class RSA:

    def __init__(self, size=5):
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

        print("Public and private keys:", ((e, self.n), (d, self.n)))

        public_key = (e, self.n)
        private_key = (d, self.n)

        return public_key, private_key

    def encrypt(self, m, key):
        m = util.string_to_long(m)
        e, n = key
        c = util.mod_exp(m, e, n)

        return c


    def decrypt(self, c):
        d, n = self.private_key
        p = util.mod_exp(c, d, n)
        #ok now how to get a string genius
        return p

if __name__ == '__main__':
    rsa = RSA()
    c = RSA.encrypt(rsa, "hello world", rsa.private_key)
    RSA.decrypt(rsa, c)
