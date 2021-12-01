import random
from . import util
from .Input import Input


class RSA:

    def __init__(self, size=1024):
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

        m_list = []

        if is_file:
            with open(input, "r") as f:
                while True:
                    chunk = f.read(128)
                    if not chunk:
                        break
                    m = preprocess(chunk)
                    m_list.append(m)

        else:
            m_list.append(preprocess(input))

        try:
            for m in m_list:
                assert m.bit_length() <= self.n.bit_length()
        except AssertionError:
            raise AssertionError("Message is too long")

        e, n = self.public_key
        c_list = []
        for m in m_list:
            c = pow(m, e, n)
            c_list.append(c)

        if is_file:
            with open("encrypted.txt", "a") as f:
                for c in c_list:
                    f.write(str(c))
        return m_list, c_list

    def decrypt(self, c_list: list, is_file = False):
        def postprocess(output):
            if Input.input_type == "string":
                return util.int_to_bytes(output).decode()
            elif Input.input_type == "bytes":
                return util.int_to_bytes(output)
            elif Input.input_type == "int":
                return output

        d, n = self.private_key

        p_list = []

        for c in c_list:
            p = pow(c, d, n)
            p_list.append(postprocess(p))

        val = ""
        for plaintext in p_list:
            val += plaintext

        if is_file:
            with open("decrypted.txt", "a") as f:
                f.write(val)
        return val

    def rsa(self, input, is_file=False, show_steps=False):
        results = {}
        mint_list, cipher = self.encrypt(input, is_file)
        plaintext = self.decrypt(cipher, is_file)
        results['string_text'] = 'Ciphertext: {}\n Plaintext: {}'.format(cipher, plaintext)
        if is_file:
            results['file'] = {'encrypted': 'encrypted.txt', 'decrypted': 'decrypted.txt'}
        step1 = {
            'msg': 'Below are the details of the keys and how they were generated',
            'substeps': ['p: {}\n'.format(self.p), 'q: {}\n'.format(self.q), 'n: {}\n'.format(self.n), 'phi: {}\n'.format(self.phi), 
                        'Public Key: {}\n'.format(self.public_key), 'Private Key: {}\n'.format(self.private_key)]
        }
        step2 = {
            'msg': 'Below are the details of encryption with RSA',
            'substeps': ['the message as integer:' + str(mint_list), 'the public key: ' + str(self.public_key), 'the ciphertext: {}'.format(cipher)]
        }
        step3 = {
            'msg': 'Below are the details of encryption with RSA',
            'substeps': ['the ciphertext: {}'.format(cipher), 'the private key: '+ str(self.private_key), 'the decrypted message: '+
                         plaintext]
        }
        steps = [step1, step2, step3]
        return results, steps