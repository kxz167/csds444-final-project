import random
import util
import Input


class RSA:

    def __init__(self, size=512):
        self.bit_size = size

        self.p = util.generate_prime(self.bit_size)
        self.q = util.generate_prime(self.bit_size)
        while self.p == self.q:
            self.q = util.generate_prime(self.bit_size)

        self.n = self.p * self.q

        self.phi = (self.p - 1) * (self.q - 1)

        self.public_key, self.private_key = self.generate_keys()

    def generate_keys(self):

        e = random.randint(2, self.phi - 1)
        while util.gcd(self.phi, e) != 1:
            e = random.randint(2, self.phi - 1)

        try:
            d = pow(e, -1, self.phi)
        except:
            d = util.mult_inverse(e, self.phi)

        public_key = (e, self.n)
        private_key = (d, self.n)

        return public_key, private_key

    def encrypt(self, input, is_file=False, show_steps=False):
        def preprocess(input):
            if isinstance(input, str):
                Input.input_type = "string"
                return util.x_to_int(input)
            elif isinstance(input, bytes):
                Input.input_type = "bytes"
                return util.x_to_int(input)
            elif isinstance(input, int):
                Input.input_type = "int"
                return input
            else:
                raise TypeError("Not allowed type")

        if is_file:
            with open(input, "r") as f:
                lines = f.readlines(256)

            text = ""
            for line in lines:
                text += line
                m = preprocess(text)

        else:
            m = preprocess(input)

        try:
            assert m.bit_length() <= self.n.bit_length()
        except AssertionError:
            raise AssertionError("Message is too long")

        e, n = self.public_key
        c = pow(m, e, n)
        return c

    def decrypt(self, c: int):
        d, n = self.private_key
        p = pow(c, d, n)

        def postprocess(output):
            if Input.input_type == "string":
                return util.int_to_bytes(output).decode()
            elif Input.input_type == "bytes":
                return util.int_to_bytes(output)
            elif Input.input_type == "int":
                return output

        return postprocess(p)


if __name__ == '__main__':
    A = RSA()
    B = RSA()

    m = "C:/Users/16507/Documents/ComputerSecurity/csds444-final-project/test.txt"

    ciphertext_B = B.encrypt(m, is_file=True)

    print("Message:", m)
    print("Public key:", B.public_key)
    print("Private key:", B.private_key)
    print("cipher:", ciphertext_B)
    print("Plaintext:", B.decrypt(ciphertext_B))
