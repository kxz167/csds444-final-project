# lookup tables borrowed from https://medium.com/wearesinch/building-aes-128-from-the-ground-up-with-python-8122af44ebf9
# because there's no way in hell i'm typing them out myself :P
aes_sbox = [
    [int('63', 16), int('7c', 16), int('77', 16), int('7b', 16), int('f2', 16), int('6b', 16), int('6f', 16),
     int('c5', 16), int(
        '30', 16), int('01', 16), int('67', 16), int('2b', 16), int('fe', 16), int('d7', 16), int('ab', 16),
     int('76', 16)],
    [int('ca', 16), int('82', 16), int('c9', 16), int('7d', 16), int('fa', 16), int('59', 16), int('47', 16),
     int('f0', 16), int(
        'ad', 16), int('d4', 16), int('a2', 16), int('af', 16), int('9c', 16), int('a4', 16), int('72', 16),
     int('c0', 16)],
    [int('b7', 16), int('fd', 16), int('93', 16), int('26', 16), int('36', 16), int('3f', 16), int('f7', 16),
     int('cc', 16), int(
        '34', 16), int('a5', 16), int('e5', 16), int('f1', 16), int('71', 16), int('d8', 16), int('31', 16),
     int('15', 16)],
    [int('04', 16), int('c7', 16), int('23', 16), int('c3', 16), int('18', 16), int('96', 16), int('05', 16),
     int('9a', 16), int(
        '07', 16), int('12', 16), int('80', 16), int('e2', 16), int('eb', 16), int('27', 16), int('b2', 16),
     int('75', 16)],
    [int('09', 16), int('83', 16), int('2c', 16), int('1a', 16), int('1b', 16), int('6e', 16), int('5a', 16),
     int('a0', 16), int(
        '52', 16), int('3b', 16), int('d6', 16), int('b3', 16), int('29', 16), int('e3', 16), int('2f', 16),
     int('84', 16)],
    [int('53', 16), int('d1', 16), int('00', 16), int('ed', 16), int('20', 16), int('fc', 16), int('b1', 16),
     int('5b', 16), int(
        '6a', 16), int('cb', 16), int('be', 16), int('39', 16), int('4a', 16), int('4c', 16), int('58', 16),
     int('cf', 16)],
    [int('d0', 16), int('ef', 16), int('aa', 16), int('fb', 16), int('43', 16), int('4d', 16), int('33', 16),
     int('85', 16), int(
        '45', 16), int('f9', 16), int('02', 16), int('7f', 16), int('50', 16), int('3c', 16), int('9f', 16),
     int('a8', 16)],
    [int('51', 16), int('a3', 16), int('40', 16), int('8f', 16), int('92', 16), int('9d', 16), int('38', 16),
     int('f5', 16), int(
        'bc', 16), int('b6', 16), int('da', 16), int('21', 16), int('10', 16), int('ff', 16), int('f3', 16),
     int('d2', 16)],
    [int('cd', 16), int('0c', 16), int('13', 16), int('ec', 16), int('5f', 16), int('97', 16), int('44', 16),
     int('17', 16), int(
        'c4', 16), int('a7', 16), int('7e', 16), int('3d', 16), int('64', 16), int('5d', 16), int('19', 16),
     int('73', 16)],
    [int('60', 16), int('81', 16), int('4f', 16), int('dc', 16), int('22', 16), int('2a', 16), int('90', 16),
     int('88', 16), int(
        '46', 16), int('ee', 16), int('b8', 16), int('14', 16), int('de', 16), int('5e', 16), int('0b', 16),
     int('db', 16)],
    [int('e0', 16), int('32', 16), int('3a', 16), int('0a', 16), int('49', 16), int('06', 16), int('24', 16),
     int('5c', 16), int(
        'c2', 16), int('d3', 16), int('ac', 16), int('62', 16), int('91', 16), int('95', 16), int('e4', 16),
     int('79', 16)],
    [int('e7', 16), int('c8', 16), int('37', 16), int('6d', 16), int('8d', 16), int('d5', 16), int('4e', 16),
     int('a9', 16), int(
        '6c', 16), int('56', 16), int('f4', 16), int('ea', 16), int('65', 16), int('7a', 16), int('ae', 16),
     int('08', 16)],
    [int('ba', 16), int('78', 16), int('25', 16), int('2e', 16), int('1c', 16), int('a6', 16), int('b4', 16),
     int('c6', 16), int(
        'e8', 16), int('dd', 16), int('74', 16), int('1f', 16), int('4b', 16), int('bd', 16), int('8b', 16),
     int('8a', 16)],
    [int('70', 16), int('3e', 16), int('b5', 16), int('66', 16), int('48', 16), int('03', 16), int('f6', 16),
     int('0e', 16), int(
        '61', 16), int('35', 16), int('57', 16), int('b9', 16), int('86', 16), int('c1', 16), int('1d', 16),
     int('9e', 16)],
    [int('e1', 16), int('f8', 16), int('98', 16), int('11', 16), int('69', 16), int('d9', 16), int('8e', 16),
     int('94', 16), int(
        '9b', 16), int('1e', 16), int('87', 16), int('e9', 16), int('ce', 16), int('55', 16), int('28', 16),
     int('df', 16)],
    [int('8c', 16), int('a1', 16), int('89', 16), int('0d', 16), int('bf', 16), int('e6', 16), int('42', 16),
     int('68', 16), int(
        '41', 16), int('99', 16), int('2d', 16), int('0f', 16), int('b0', 16), int('54', 16), int('bb', 16),
     int('16', 16)]
]

reverse_aes_sbox = [
    [int('52', 16), int('09', 16), int('6a', 16), int('d5', 16), int('30', 16), int('36', 16), int('a5', 16),
     int('38', 16), int(
        'bf', 16), int('40', 16), int('a3', 16), int('9e', 16), int('81', 16), int('f3', 16), int('d7', 16),
     int('fb', 16)],
    [int('7c', 16), int('e3', 16), int('39', 16), int('82', 16), int('9b', 16), int('2f', 16), int('ff', 16),
     int('87', 16), int(
        '34', 16), int('8e', 16), int('43', 16), int('44', 16), int('c4', 16), int('de', 16), int('e9', 16),
     int('cb', 16)],
    [int('54', 16), int('7b', 16), int('94', 16), int('32', 16), int('a6', 16), int('c2', 16), int('23', 16),
     int('3d', 16), int(
        'ee', 16), int('4c', 16), int('95', 16), int('0b', 16), int('42', 16), int('fa', 16), int('c3', 16),
     int('4e', 16)],
    [int('08', 16), int('2e', 16), int('a1', 16), int('66', 16), int('28', 16), int('d9', 16), int('24', 16),
     int('b2', 16), int(
        '76', 16), int('5b', 16), int('a2', 16), int('49', 16), int('6d', 16), int('8b', 16), int('d1', 16),
     int('25', 16)],
    [int('72', 16), int('f8', 16), int('f6', 16), int('64', 16), int('86', 16), int('68', 16), int('98', 16),
     int('16', 16), int(
        'd4', 16), int('a4', 16), int('5c', 16), int('cc', 16), int('5d', 16), int('65', 16), int('b6', 16),
     int('92', 16)],
    [int('6c', 16), int('70', 16), int('48', 16), int('50', 16), int('fd', 16), int('ed', 16), int('b9', 16),
     int('da', 16), int(
        '5e', 16), int('15', 16), int('46', 16), int('57', 16), int('a7', 16), int('8d', 16), int('9d', 16),
     int('84', 16)],
    [int('90', 16), int('d8', 16), int('ab', 16), int('00', 16), int('8c', 16), int('bc', 16), int('d3', 16),
     int('0a', 16), int(
        'f7', 16), int('e4', 16), int('58', 16), int('05', 16), int('b8', 16), int('b3', 16), int('45', 16),
     int('06', 16)],
    [int('d0', 16), int('2c', 16), int('1e', 16), int('8f', 16), int('ca', 16), int('3f', 16), int('0f', 16),
     int('02', 16), int(
        'c1', 16), int('af', 16), int('bd', 16), int('03', 16), int('01', 16), int('13', 16), int('8a', 16),
     int('6b', 16)],
    [int('3a', 16), int('91', 16), int('11', 16), int('41', 16), int('4f', 16), int('67', 16), int('dc', 16),
     int('ea', 16), int(
        '97', 16), int('f2', 16), int('cf', 16), int('ce', 16), int('f0', 16), int('b4', 16), int('e6', 16),
     int('73', 16)],
    [int('96', 16), int('ac', 16), int('74', 16), int('22', 16), int('e7', 16), int('ad', 16), int('35', 16),
     int('85', 16), int(
        'e2', 16), int('f9', 16), int('37', 16), int('e8', 16), int('1c', 16), int('75', 16), int('df', 16),
     int('6e', 16)],
    [int('47', 16), int('f1', 16), int('1a', 16), int('71', 16), int('1d', 16), int('29', 16), int('c5', 16),
     int('89', 16), int(
        '6f', 16), int('b7', 16), int('62', 16), int('0e', 16), int('aa', 16), int('18', 16), int('be', 16),
     int('1b', 16)],
    [int('fc', 16), int('56', 16), int('3e', 16), int('4b', 16), int('c6', 16), int('d2', 16), int('79', 16),
     int('20', 16), int(
        '9a', 16), int('db', 16), int('c0', 16), int('fe', 16), int('78', 16), int('cd', 16), int('5a', 16),
     int('f4', 16)],
    [int('1f', 16), int('dd', 16), int('a8', 16), int('33', 16), int('88', 16), int('07', 16), int('c7', 16),
     int('31', 16), int(
        'b1', 16), int('12', 16), int('10', 16), int('59', 16), int('27', 16), int('80', 16), int('ec', 16),
     int('5f', 16)],
    [int('60', 16), int('51', 16), int('7f', 16), int('a9', 16), int('19', 16), int('b5', 16), int('4a', 16),
     int('0d', 16), int(
        '2d', 16), int('e5', 16), int('7a', 16), int('9f', 16), int('93', 16), int('c9', 16), int('9c', 16),
     int('ef', 16)],
    [int('a0', 16), int('e0', 16), int('3b', 16), int('4d', 16), int('ae', 16), int('2a', 16), int('f5', 16),
     int('b0', 16), int(
        'c8', 16), int('eb', 16), int('bb', 16), int('3c', 16), int('83', 16), int('53', 16), int('99', 16),
     int('61', 16)],
    [int('17', 16), int('2b', 16), int('04', 16), int('7e', 16), int('ba', 16), int('77', 16), int('d6', 16),
     int('26', 16), int(
        'e1', 16), int('69', 16), int('14', 16), int('63', 16), int('55', 16), int('21', 16), int('0c', 16),
     int('7d', 16)]
]


def sbox_lookup(byte):
    x = byte >> 4
    y = byte & 15
    return aes_sbox[x][y]


def sbox_inverse_lookup(byte):
    x = byte >> 4
    y = byte & 15
    return reverse_aes_sbox[x][y]


'''
def mul(a, b):

    Multiplies two bytes together as elements of the galois field (mod 2^n)
    :param a:
    :param b:
    :return:

    if (a >127 and b > 127):
        print(a, b)
    p = 0x00
    for i in range(8):
        if b % 2 != 0:
            p = p ^ a
        h = a > 128
        to_discard = a >> 7
        to_discard = to_discard << 8
        a = (a << 1) - to_discard

        if h:
            a = a ^ 0x1B
        b = b >> 1
    return p
'''


def byte(x, n=8):
    return format(x, f"0{n}b")


def mul(a, b):
    tmp = 0
    b_byte = bin(b)[2:]
    for i in range(len(b_byte)):
        tmp = tmp ^ (int(b_byte[-(i + 1)]) * (a << i))

    mod = int("100011011", 2)
    exp = len(bin(tmp)[2:])
    diff = exp - len(bin(mod)[2:]) + 1

    for i in range(diff):
        if byte(tmp, exp)[i] == "1":
            tmp = tmp ^ (mod << diff - i - 1)
    return tmp


def rotate(word):
    first_part = word << 8
    second_part = word >> (32 - 8)
    overshoot = second_part << 32
    return first_part + second_part - overshoot


# exponentiates two to some value (given)
def rcon(value):
    c = 0x01
    if value == 0:
        return 0
    while value != 1:
        c = mul(c, 2)
        value -= 1
    return c


def sub_word(word):
    '''
    :param word: 32 bit word to split into 8 bit segments
    :return: sbox applied to each byte in the word
    '''
    # divides the word into bytes: first, second, ..., fourth
    remainder = word
    first = word >> 24
    remainder -= first << 24

    second = remainder >> 16
    remainder -= second << 16

    third = remainder >> 8
    remainder -= third << 8

    fourth = remainder

    # now apply sbox function to each
    first = sbox_lookup(first)
    second = sbox_lookup(second)
    third = sbox_lookup(third)
    fourth = sbox_lookup(fourth)
    return (first << 24) + (second << 16) + (third << 8) + fourth


def sub_bytes(matrix):
    new_matrix = []
    for i in range(4):
        new_matrix.append([0, 0, 0, 0])

    for row in range(4):
        for col in range(4):
            new_matrix[row][col] = sbox_lookup(matrix[row][col])
    return new_matrix


def unsub_bytes(matrix):
    new_matrix = []
    for i in range(4):
        new_matrix.append([0, 0, 0, 0])

    for row in range(4):
        for col in range(4):
            new_matrix[row][col] = sbox_inverse_lookup(matrix[row][col])
    return new_matrix


def shift_rows(matrix):
    # initialize a new matrix to pop junk into
    new_matrix = []
    for i in range(4):
        new_matrix.append([0, 0, 0, 0])

    # now, pop elements into there based on row shift of magnitude determined by index
    for i in range(4):
        new_matrix[0][i] = matrix[0][i]
    for i in range(4):
        new_matrix[1][i] = matrix[1][(i + 1) % 4]
    for i in range(4):
        new_matrix[2][i] = matrix[2][(i + 2) % 4]
    for i in range(4):
        new_matrix[3][i] = matrix[3][(i + 3) % 4]
    return new_matrix


def unshift_rows(matrix):
    return shift_rows(shift_rows(shift_rows(matrix)))


def mix_columns(matrix):
    new_matrix = []
    for i in range(4):
        new_matrix.append([0, 0, 0, 0])

    for col in range(4):
        new_elements = mix_one_column(matrix[0][col], matrix[1][col], matrix[2][col], matrix[3][col])
        for row in range(len(new_elements)):
            new_matrix[row][col] = new_elements[row]
    return new_matrix


def mix_one_column(b0, b1, b2, b3):
    d0 = mul(2, b0) ^ mul(3, b1) ^ b2 ^ b3
    d1 = b0 ^ mul(2, b1) ^ mul(3, b2) ^ b3
    d2 = b0 ^ b1 ^ mul(2, b2) ^ mul(3, b3)
    d3 = mul(3, b0) ^ b1 ^ b2 ^ mul(2, b3)
    return [d0, d1, d2, d3]


# check to make sure this is actually hexadecimal uwu
def unmix_one_column(d0, d1, d2, d3):
    b0 = mul(14, d0) ^ mul(11, d1) ^ mul(13, d2) ^ mul(9, d3)
    b1 = mul(9, d0) ^ mul(14, d1) ^ mul(11, d2) ^ mul(13, d3)
    b2 = mul(13, d0) ^ mul(9, d1) ^ mul(14, d2) ^ mul(11, d3)
    b3 = mul(11, d0) ^ mul(13, d1) ^ mul(9, d2) ^ mul(14, d3)
    return [b0, b1, b2, b3]


def apply_key(matrix, round_keys, round):  # key will be a tuple of words?
    keys_for_this_round = []
    key_bytes = []
    keys_for_this_round.append(round_keys[round * 4])
    keys_for_this_round.append(round_keys[round * 4 + 1])
    keys_for_this_round.append(round_keys[round * 4 + 2])
    keys_for_this_round.append(round_keys[round * 4 + 3])

    for key in keys_for_this_round:
        remainder = key
        first = key >> 24
        remainder -= first << 24

        second = remainder >> 16
        remainder -= second << 16

        third = remainder >> 8
        remainder -= third << 8

        fourth = remainder
        key_bytes.append(first)
        key_bytes.append(second)
        key_bytes.append(third)
        key_bytes.append(fourth)

    # now we have a list key_bytes of 16 bytes, to correspond to our 4x4 matrix bytes. Apply via xor
    new_matrix = []
    for i in range(4):
        new_matrix.append([0, 0, 0, 0])

    for row in range(4):
        for col in range(4):
            new_matrix[row][col] = matrix[row][col] ^ key_bytes[row * 4 + col]

    return new_matrix


def unmix_columns(matrix):
    new_matrix = []
    for i in range(4):
        new_matrix.append([0, 0, 0, 0])

    for col in range(4):
        new_elements = unmix_one_column(matrix[0][col], matrix[1][col], matrix[2][col], matrix[3][col])
        for row in range(len(new_elements)):
            new_matrix[row][col] = new_elements[row]
    return new_matrix


def generate_keys(original_key_words, N, R):
    W = []
    for i in range(4 * R):
        W.append(0)
        if (0 <= i < N):
            W[i] = original_key_words[i]
        elif i >= N and i % N == 0:
            W[i] = W[i - N] ^ sub_word(rotate(W[i - 1])) ^ rcon(i / N)
        elif i >= N == 8 and i % N == 4:
            W[i] = W[i - N] ^ sub_word(W[i - 1])
        else:
            W[i] = W[i - N] ^ W[i - 1]

    return W


def encrypt_matrix(matrix, round_keys):
    # first round
    matrix = apply_key(matrix, round_keys, 0)

    # rounds 1 through 11
    for round in range(1, 11):
        matrix = sub_bytes(matrix)
        matrix = shift_rows(matrix)
        matrix = mix_columns(matrix)
        matrix = apply_key(matrix, round_keys, round)

    # round 12, final round
    matrix = sub_bytes(matrix)
    matrix = shift_rows(matrix)
    matrix = apply_key(matrix, round_keys, 11)
    return matrix


def decrypt_matrix(matrix, round_keys):
    # revert round 12 first
    matrix = apply_key(matrix, round_keys, 11)
    matrix = unshift_rows(matrix)
    matrix = unsub_bytes(matrix)

    # now go back through the rounds backwards
    for round in range(10, 0, -1):
        matrix = apply_key(matrix, round_keys, round)
        matrix = unmix_columns(matrix)
        matrix = unshift_rows(matrix)
        matrix = unsub_bytes(matrix)

    # now revert the very first round
    matrix = apply_key(matrix, round_keys, 0)
    return matrix


def main():
    # This implementation will use 6x32 bit key with 12 rounds
    # i'th element corresponds to i'th word of starting key
    K = []
    for i in range(6):
        K.append(0)
    W = generate_keys(K, 6, 12)

    # i'th element corresponds to i'th word of round keys
    # one round key is W[4n], W[4n+1], W[4n+2], W[4n+3]
    string = "\"Hello cat uwu\" said the person to the cat"
    data = string.encode("utf-8")
    new_data = [data[0], data[1]]
    print(bytes(new_data).decode("utf-8"))
    print(data.decode("utf-8"))

    data_matrix = [[1, 2, 3, 4], [5, 6, 7, 8], [9, 10, 11, 12], [13, 14, 15, 16]]
    print("start data: ", data_matrix)
    encrypted_data = encrypt_matrix(data_matrix, W)
    print("encrypted data =", encrypted_data)
    print("unencrypted data =", decrypt_matrix(encrypted_data, W))


if __name__ == "__main__":
    main()
