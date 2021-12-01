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


def byte(x, n=8):
    return format(x, f"0{n}b")


def mul(a, b):
    # this method for galois field of order 2^8 multiplication is not mine, abstract algebra is hard
    # credit to https://medium.com/wearesinch/building-aes-128-from-the-ground-up-with-python-8122af44ebf9
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
def two_power(value):
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
            W[i] = W[i - N] ^ sub_word(rotate(W[i - 1])) ^ two_power(i / N)
        elif i >= N == 8 and i % N == 4:
            W[i] = W[i - N] ^ sub_word(W[i - 1])
        else:
            W[i] = W[i - N] ^ W[i - 1]

    return W


def matrix_to_byte_list(matrix):
    byte_list = []
    for row in range(4):
        for col in range(4):
            byte_list.append(matrix[row][col])
    return byte_list


def matrix_to_string(matrix):
    string = "|"
    for row in range(4):
        for col in range(4):
            string += str(matrix[row][col]) + "  "
        if row != 3:
            string += "|\n|"
        else:
            string += "|\n"

    return string


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


def encrypt_matrix_with_steps(matrix, round_keys):
    message1 = "AES is a single key block cipher that generates many round keys to use in various 'rounds' of the algorithm" \
               "\nWe'll be showing what one round of the algorithm looks like on the first 16 bytes of the message" \
               "\nThe first 16 bytes of text encoded into utf-8 are put into the matrix shown below\n" + matrix_to_string(matrix)
    message2 = ""
    message3 = ""
    message4 = ""
    message5 = ""
    message6 = ""

    # first round
    matrix = apply_key(matrix, round_keys, 0)

    # rounds 1 through 11
    for round in range(1, 11):
        matrix = sub_bytes(matrix)
        if round == 1:
            message2 = "First, every byte in the matrix is put into a specific bijective function from the set of possible byte values" \
                   " to the set of possible byte values. The bijective property is very useful because it" \
                       " allows to undo this step by pluging a byte into the inverse of the function \n" + matrix_to_string(matrix)
        matrix = shift_rows(matrix)
        if round == 1:
            message3 = "Then, the rows of the matrix are shifted by an amount equal to the index of the row " \
                       "This can be easily undone with decrypting by shifting in the opposite direction " \
                       "\n" + matrix_to_string(matrix)
        matrix = mix_columns(matrix)
        if round == 1:
            message4 = "Then, the column vectors of the matrix are multiplied by a specific invertible matrix with elements " \
                       "and operations in the galois field of order 2^8. This is an abstract algebra structure that defines" \
                       " its own rules for multiplication and addition. This and the previous step both help to allow small changes" \
                       " in the input text to have huge changes in the encrypted text" \
                       " This can be undone during decryption by multiplying every column " \
                       "by the inverse matrix\n" + matrix_to_string(matrix)
        matrix = apply_key(matrix, round_keys, round)
        if round == 1:
            message5 = "Finally, the round key for this specific round is applied through an xor operation with the" \
                       " bytes of the matrix, and we're done with this round" \
                       " This can be undone during decryption by xoring with the key again, as the xor operation is its own" \
                       " inverse\n" + matrix_to_string(matrix)

    # round 12, final round
    matrix = sub_bytes(matrix)
    matrix = shift_rows(matrix)
    matrix = apply_key(matrix, round_keys, 11)
    message6 = "This process is repeated for 12 rounds total in our implementation, with small variations on the first and" \
               " last rounds. Decryption is done by doing the inverse of every step as mentioned previously." \
               " Here is the matrix at the end of all of the rounds, completely incomprehensible when compared to the originial" \
               " matrix\n" + matrix_to_string(matrix)

    steps = [{'msg':message1}, {'msg':message2}, {'msg':message3}, {'msg':message4}, {'msg':message5}, {'msg':message6}]
    return matrix, steps


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

def encode_byte_list(bytes, key=[0,0,0,0,0,0], return_explanation=False):
    '''
    takes in a list of bytes to encipher and a 6 character[byte] key
    returns an enciphered list of bytes
    and now also returns a (results, steps) tuple *eye roll*
    '''
    result_string = ""

    round_keys = generate_keys(key, 6, 12)

    byteroos = []
    for byte in bytes:
        byteroos.append(byte)

    bytes_left = len(bytes)
    new_bytes_list = []
    bytes_encoded = 0

    while bytes_left > 0:
        print(bytes_left)
        # make data matrix
        data_matrix = []
        for i in range(4):
            data_matrix.append([0, 0, 0, 0])

        for col in range(4):
            for row in range(4):
                if bytes_left > 0:
                    data_matrix[row][col] = bytes[bytes_encoded]
                bytes_encoded -= -1
                bytes_left -= 1
        if (bytes_encoded > 16):
            data_matrix = encrypt_matrix(data_matrix, round_keys)
        else:
            data_matrix, steps = encrypt_matrix_with_steps(data_matrix, round_keys)
        bytes_to_append = matrix_to_byte_list(data_matrix)
        for byte in bytes_to_append:
            new_bytes_list.append(byte)
    result_string = "We started with needing to encrypt:", str(byteroos), "\nAnd encrypting, we end up with encrypted byt" \
                                                                          "es:" + str(new_bytes_list)
    bullshit_to_appease_group_members = {'string_text': ''.join(result_string)}
    if return_explanation:
        return new_bytes_list, (bullshit_to_appease_group_members, steps)
    else:
        return new_bytes_list


def decode_byte_list(bytes, key=[0,0,0,0,0,0]):
    '''
    takes in a list of enciphered bytes to decode, returns the original list
    '''
    round_keys = generate_keys(key, 6, 12)

    bytes_left = len(bytes)
    new_bytes_list = []
    bytes_encoded = 0

    while bytes_left > 0:
        # make data matrix
        data_matrix = []
        for i in range(4):
            data_matrix.append([0, 0, 0, 0])

        for col in range(4):
            for row in range(4):
                if bytes_left > 0:
                    data_matrix[col][row] = bytes[bytes_encoded]
                bytes_encoded -= -1
                bytes_left -= 1
        data_matrix = decrypt_matrix(data_matrix, round_keys)

        bytes_to_append = []
        for col in range(4):
            for row in range(4):
                bytes_to_append.append(data_matrix[row][col])

        for byte in bytes_to_append:
            new_bytes_list.append(byte)
    '''
    for i in range(len(new_bytes_list) - 1, 0, -1):
        if new_bytes_list[i] == 0:
            new_bytes_list.pop(i)
        else:
            break
    '''
    return new_bytes_list

def main():
    print("Type 'encrypt' if you want to encrypt something\n"
          "Type 'decrypt' if you want to decrypt something")
    encrypt_or_decrypt = input()
    while encrypt_or_decrypt != 'encrypt' and encrypt_or_decrypt != 'decrypt':
        print("Type 'encrypt' if you want to encrypt something\n"
              "Type 'decrypt' if you want to decrypt something)")
        input_type = input()

    print("Type 'string' to",encrypt_or_decrypt, "a string that you will type or paste here\n"
          "Type 'file' to ", encrypt_or_decrypt, "that you will specify the path to\n")
    input_type = input()
    while input_type != 'string' and input_type != 'file':
        print("Type 'string' to", encrypt_or_decrypt, "a string that you will type or paste here\n"
                        "Type 'file' to ", encrypt_or_decrypt, "that you will specify the path to\n")
        input_type = input()

    print("please enter an integer from 0 to 2^196. This will be your key")
    key_int = int(input())
    print("Your key is", key_int)
    key = []
    for i in range(6):
        key.append(key_int & 0xFFFFFFFF)
        key_int >> 32

    print(key)

    #parse inputs
    if input_type == "string":
        output_file = open("output_file.txt", "w")
        print("Please enter the string you want to", encrypt_or_decrypt)
        string = input()
        if encrypt_or_decrypt == "encrypt":
            data = string.encode("utf-8")
            encoded_boi = encode_byte_list(data, key)
            output_string = ""
            for byte in encoded_boi:
                output_string += str(byte) + " "
            output_file.write(output_string)
            print("here's your encoded string. It is also stored in output_file.txt")
            print(output_string)
        if encrypt_or_decrypt == "decrypt":
            string_byte_array = string.split(" ")
            byte_array = []
            for string_byte in string_byte_array:
                if string_byte != "":
                    byte_array.append(int(string_byte))
            encoded_boi = decode_byte_list(byte_array, key)
            output_string = (bytes(encoded_boi).decode("utf-8"))
            output_file.write(output_string)
            print("here's your decoded string. It is also stored in output_file.txt")
            print(output_string)

    if input_type == "file":
        print("Please enter the file name you want to", encrypt_or_decrypt + ". eg. song.mp3")
        file_string = input()
        if encrypt_or_decrypt == "encrypt":
            input_file = open(file_string, 'rb')
            input_data = input_file.read()
            output_file = open("output_file.txt", "w")

            byte_list = []
            for i in range(len(input_data)):
                byte_list.append(input_data[i])

            encoded_boi = encode_byte_list(byte_list, key)
            output_string = ""
            for byte in encoded_boi:
                output_string += str(byte) + " "
            output_file.write(output_string)
            print("Your encrypted data is stored in output_file.txt\n"
                  "You can decrypt it by specifying the file name in this tool later")
        if encrypt_or_decrypt == "decrypt":
            print("type the name you want the file to have when output: (eg. song.mp3)")
            output_name = input()

            input_file = open(file_string, 'r')
            string = input_file.read()

            string_byte_array = string.split(" ")
            byte_array = []
            for string_byte in string_byte_array:
                if string_byte != "":
                    byte_array.append(int(string_byte))
            encoded_boi = decode_byte_list(byte_array, key)

            output_file = open(output_name, 'wb')
            newFileByteArray = bytearray(encoded_boi)
            output_file.write(newFileByteArray)

            print("your decrypted file has been saved at")




def run_the_algo(string_txt, is_filepath, show_steps):
    key_int = 0
    key = []
    for i in range(6):
        key.append(key_int & 0xFFFFFFFF)
        key_int >> 32

    #parse inputs
    if not is_filepath:
        output_file = open("encrypted_output_file.txt", "w")
        string = string_txt

        #encrypt
        data = string.encode("utf-8")
        encoded_boi, tuple_boi = encode_byte_list(data, key, True)
        output_string = ""
        for byte in encoded_boi:
            output_string += str(byte) + " "
        output_file.write(output_string)


        string_byte_array = output_string.split(" ")
        byte_array = []
        for string_byte in string_byte_array:
            if string_byte != "":
                byte_array.append(int(string_byte))
        encoded_boi = decode_byte_list(byte_array, key)
        output_string = (bytes(encoded_boi).decode("utf-8"))
        output_file.write(output_string)

    else:
        file_string = string_txt
        input_file = open(file_string, 'rb')
        input_data = input_file.read()
        output_file = open("output_file.txt", "w")

        byte_list = []
        for i in range(len(input_data)):
            byte_list.append(input_data[i])

        encoded_boi, tuple_boi = encode_byte_list(byte_list, key, True)
        output_string = ""
        for byte in encoded_boi:
            output_string += str(byte) + " "
        output_file.write(output_string)
        output_file.close()

        output_name = "decrypted" + file_string
        input_file = open("output_file.txt", 'r')
        string = input_file.read()

        string_byte_array = string.split(" ")
        byte_array = []
        for string_byte in string_byte_array:
            if string_byte != "":
                byte_array.append(int(string_byte))
        encoded_boi = decode_byte_list(byte_array, key)

        output_file = open(output_name, 'wb')
        newFileByteArray = bytearray(encoded_boi)
        output_file.write(newFileByteArray)

    print(tuple_boi)
    return tuple_boi