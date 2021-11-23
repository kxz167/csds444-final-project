# input formatting
    # Original message
    # Padding bits (required)-> (1) : (10000000....)
    # Size of original message

    # combined = whole multiple of 1024 bits.
        # Processed as blocks of 1024 bits each.
        # L bit message (L < 2^129-2) + P bits (P > 1) = N * 1024 - 128

    # Adding the size of the original message file represented in 128 bits (limited size but is like, ^25 TBs).

# hash buffer initialization: Intermediate stage block cipher
    # Initial Vectors (IV) first 64 bits of the fractional parts of the square roots of the first 8 prime numbers.
    # Hash buffer consists of 8 subparts for storing registers.

# message processing
    # Split each 1024 block into 80 words.
    # 80 Rounds takes (one word, output of previous round, and sha512 constant).
        # First round takes final round from previous block (Or IV for first block of first round)
        # SHA CONSTANTS: First 64 bits from fractional parts of the cube roots of the first 80 prime numbers.
    # Output is 512 bits, which is added to the previous message processing phase.

#output

input_file_path = "simple2"
byte_block = 128 # 1024 bits
bit_length = 2**64

# CONSTANTS:
word_constants=[0x428a2f98d728ae22,0x7137449123ef65cd,0xb5c0fbcfec4d3b2f,0xe9b5dba58189dbbc,0x3956c25bf348b538,0x59f111f1b605d019,0x923f82a4af194f9b,0xab1c5ed5da6d8118,0xd807aa98a3030242,0x12835b0145706fbe,0x243185be4ee4b28c,0x550c7dc3d5ffb4e2,0x72be5d74f27b896f,0x80deb1fe3b1696b1,0x9bdc06a725c71235,0xc19bf174cf692694,0xe49b69c19ef14ad2,0xefbe4786384f25e3,0x0fc19dc68b8cd5b5,0x240ca1cc77ac9c65,0x2de92c6f592b0275,0x4a7484aa6ea6e483,0x5cb0a9dcbd41fbd4,0x76f988da831153b5,0x983e5152ee66dfab,0xa831c66d2db43210,0xb00327c898fb213f,0xbf597fc7beef0ee4,0xc6e00bf33da88fc2,0xd5a79147930aa725,0x06ca6351e003826f,0x142929670a0e6e70,0x27b70a8546d22ffc,0x2e1b21385c26c926,0x4d2c6dfc5ac42aed,0x53380d139d95b3df,0x650a73548baf63de,0x766a0abb3c77b2a8,0x81c2c92e47edaee6,0x92722c851482353b,0xa2bfe8a14cf10364,0xa81a664bbc423001,0xc24b8b70d0f89791,0xc76c51a30654be30,0xd192e819d6ef5218,0xd69906245565a910,0xf40e35855771202a,0x106aa07032bbd1b8,0x19a4c116b8d2d0c8,0x1e376c085141ab53,0x2748774cdf8eeb99,0x34b0bcb5e19b48a8,0x391c0cb3c5c95a63,0x4ed8aa4ae3418acb,0x5b9cca4f7763e373,0x682e6ff3d6b2b8a3,0x748f82ee5defb2fc,0x78a5636f43172f60,0x84c87814a1f0ab72,0x8cc702081a6439ec,0x90befffa23631e28,0xa4506cebde82bde9,0xbef9a3f7b2c67915,0xc67178f2e372532b,0xca273eceea26619c,0xd186b8c721c0c207,0xeada7dd6cde0eb1e,0xf57d4f7fee6ed178,0x06f067aa72176fba,0x0a637dc5a2c898a6,0x113f9804bef90dae,0x1b710b35131c471b,0x28db77f523047d84,0x32caab7b40c72493,0x3c9ebe0a15c9bebc,0x431d67c49c100d4c,0x4cc5d4becb3e42b6,0x597f299cfc657e2a,0x5fcb6fab3ad6faec,0x6c44198c4a475817]
initial_vector_values = [0x6a09e667f3bcc908,0xbb67ae8584caa73b,0x3c6ef372fe94f82b,0xa54ff53a5f1d36f1,0x510e527fade682d1,0x9b05688c2b3e6c1f,0x1f83d9abfb41bd6b,0x5be0cd19137e2179]
print (word_constants)
print(initial_vector_values)

# File Size:
print("==============")
import os
file_size = os.path.getsize(input_file_path) * 8
padding = 1024 - ((file_size % 1024 + 128) % 1024)
print("The file size is:", file_size, "bits.")
print("That means we need a pad of:", padding)
print("And this then gives us a remainder of:", (padding + file_size + 128) % 1024)
print("==============")

def sha_pad(value, pad):
    # print(((value << 1) | 1 ) << (pad-1))
    return ((value << 1) | 1 ) << (pad-1)

def left_rotate_64(number, shifts):
    return ((number << shifts) | (number >> (64 - shifts))) & 0xffffffffffffffff

def right_rotate_64(number, shifts):
    return (number >> shifts) | (number << (64 - shifts)) & 0xffffffffffffffff

def append_64(original, appended):
    return (original << 64) | appended

def concatenate(h0, h1, h2, h3, h4, h5, h6, h7):
    return append_64(append_64(append_64(append_64(append_64(append_64(append_64(h0, h1), h2), h3), h4), h5), h6), h7)

def sigma_0 (word):
    return (right_rotate_64(word, 1) ^ (right_rotate_64(word, 8)) ^ (word >> 7))

def sigma_1 (word):
    return  (right_rotate_64(word, 19) ^ (right_rotate_64(word, 61)) ^ (word >> 6))

def Sigma_0 (word):
    return (right_rotate_64(word, 28) ^ (right_rotate_64(word, 34) ^ (right_rotate_64(word, 39))))

def Sigma_1 (word):
    return (right_rotate_64(e, 14) ^ (right_rotate_64(e, 18)) ^ (right_rotate_64(e, 41)))

def ch(x,y,z):
    return (x & y) ^ ((~x) & z)

def maj(x, y, z):
    return (x & y) ^ (x & z) ^ (y & z)

input_file = open(input_file_path, 'rb')
reading = True

# Initial Round Values / RESULTS
a = initial_vector_values[0]
b = initial_vector_values[1]
c = initial_vector_values[2]
d = initial_vector_values[3]
e = initial_vector_values[4]
f = initial_vector_values[5]
g = initial_vector_values[6]
h = initial_vector_values[7]

# Initial Hash Value:
h0 = initial_vector_values[0]
h1 = initial_vector_values[1]
h2 = initial_vector_values[2]
h3 = initial_vector_values[3]
h4 = initial_vector_values[4]
h5 = initial_vector_values[5]
h6 = initial_vector_values[6]
h7 = initial_vector_values[7]

# h0 = 0
# h1 = 0
# h2 = 0
# h3 = 0
# h4 = 0
# h5 = 0
# h6 = 0
# h7 = 0

i=0
while(reading):
    print("===============")
    i += 1
    # if(i == 1):
    #     reading = False

    # Read input file one block at a time
    read = input_file.read(byte_block)

    # If we are at the end, pad:
    if(len(read) < byte_block):
        print("Int of bytes read: ", int.from_bytes(read, 'big'))
        
        # Pad with the correct number of bits and then add the file size.
        read_int = (sha_pad(int.from_bytes(read, 'big'), padding) << 128 ) | file_size
        print("Int after padding + file size: ", read_int)
        print(bin(read_int))
        
        # Set th read input back into bits.
        read = int.to_bytes(read_int, byte_block, 'big')
        # End the while loop
        reading = False
    # sum = sum | read

    print("Raw output:",read)
    print("Binary output:", bin(int.from_bytes(read, 'big')))
    print("With length(bytes):",len(read))

    ## DO THE ENCODING HERE ASSUMING READ IS A 1024 BIT BLOCK
    print("--ENCODING--")

    words = []          # Each generated word
    word_string = []

    #GENERATE WORDS
    for x in range(0,16):
        # Get certain bits from the read input
        words.append(int.from_bytes(read[x*8: x*8+8], 'big'))
        word_string.append(read[x*8:x*8+8])

    for x in range(16, 80):
        # s0 := (w[i-15] rightrotate 1) xor (w[i-15] rightrotate 8) xor (w[i-15] rightshift 7)
        # s0 = sigma_0(words[x-15])
        # print(s0)
        # s1 := (w[i-2] rightrotate 19) xor (w[i-2] rightrotate 61) xor (w[i-2] rightshift 6)
        # s1 = sigma_1(words[x-2])
        # print(s1)
        # w[i] := w[i-16] + s0 + w[i-7] + s1
        words.append((words[x-16] + sigma_0(words[x-15]) + words[x-7] + sigma_1(words[x-2])) % (bit_length))
    print("Word Strings:", word_string)
    print("Message Schedule:", words)
    print(len(words))
    # for i from 0 to 63

    # Initialize working variables:
    a = h0
    b = h1
    c = h2
    d = h3
    e = h4
    f = h5
    g = h6
    h = h7

    #PERFORM ROUNDS: 
    for p in range(0, 80):
        # S1 := (e rightrotate 14) xor (e rightrotate 18) xor (e rightrotate 41)
        # S1 = Sigma_1(e)
        # ch := (e and f) xor ((not e) and g)
        # ch = (e & f) ^ ((~e) & g) 
        # temp1 := h + S1 + ch + k[i] + w[i]
        temp1 = (h + Sigma_1(e) + ch(e, f, g) + word_constants[p] + words[p]) % bit_length
        # S0 := (a rightrotate 28) xor (a rightrotate 34) xor (a rightrotate 39)
        # S0 = Sigma_0(a)
        # maj := (a and b) xor (a and c) xor (b and c)
        # maj = (a & b) ^ (a & c) ^ (b & c)
        # temp2 := S0 + maj
        temp2 = (Sigma_0(a) + maj(a, b, c))% bit_length

        # T1 = h + ch(e, f, g) sigma(e) + words[x] + word_constants[x]

        h = g
        g = f
        f = e
        e = (d + temp1) % bit_length
        d = c
        c = b
        b = a
        a = (temp1 + temp2) % bit_length

    # Add the compressed chunk to the current hash value:
    h0 = (h0 + a) % bit_length
    h1 = (h1 + b) % bit_length
    h2 = (h2 + c) % bit_length
    h3 = (h3 + d) % bit_length
    h4 = (h4 + e) % bit_length
    h5 = (h5 + f) % bit_length
    h6 = (h6 + g) % bit_length
    h7 = (h7 + h) % bit_length

    # a = (h0 + a) % bit_length
    # b = (h2 + b) % bit_length
    # c = (h3 + c) % bit_length
    # d = (h4 + d) % bit_length
    # e = (h1 + e) % bit_length
    # f = (h5 + f) % bit_length
    # g = (h6 + g) % bit_length
    # h = (h7 + h) % bit_length
    print("Hashes:", h0, h1, h2, h3, h4, h5, h6, h7)
    print("===============")
    
print("Final Results:")
appended_results = concatenate(h0, h1, h2, h3, h4, h5, h6, h7)
print(appended_results)
print(hex(appended_results))
print("With: ", i, " Rounds")
# print(right_rotate(864691128455136524, 2, 64))

# print(sum)

# print("===")
# print(file_size)
# byte_size = int.to_bytes(file_size, 128, 'big')
# print(len(byte_size))
# print(byte_size)

# from pathlib import Path
# binary_content = Path(input_file_path).read_bytes()
# print(binary_content)