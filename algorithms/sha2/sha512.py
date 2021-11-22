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

input_file_path = "wiki"

byte_block = 128 # 1024 bits

# DETERMINE SIZE:



import os

# 23576 * 1024 = 24 | + 128 = 152. Needs a pad of 872

file_size = os.path.getsize(input_file_path) * 8
padding = 1024 - ((file_size % 1024 + 128) % 1024)

print("The file size is: ", file_size, "bits.")
print("That means we need a pad of: ", padding)
print((padding + file_size + 128) % 1024)

def sha_pad(value, pad):
    return ((value << 1) | 1 ) << (pad-1)

# print(sha_pad(5, 5))

input_file = open(input_file_path, 'rb')
# sum = b'0'
reading = True

i=0
while(reading):
    print("===============")
    i += 1
    # Read input file as bytes
    read = input_file.read(byte_block)

    # If we are at the end:
    if(len(read) < byte_block):
        print(int.from_bytes(read, 'big'))
        
        # Pad with the correct number of bits and then add the file size.
        read_int = (sha_pad(int.from_bytes(read, 'big'), padding) << 128 ) | file_size
        # Set th read input back into bits.
        read = int.to_bytes(read_int, byte_block * 8, 'big')
        # End the while loop
        reading = False
    # sum = sum | read
    print(read)
    print(len(read))
    print(int.from_bytes(read, 'big'))
    # print(sha_pad(int.from_bytes(read, 'big'), 3))

# print(sum)

# print("===")
# print(file_size)
# byte_size = int.to_bytes(file_size, 128, 'big')
# print(len(byte_size))
# print(byte_size)

# from pathlib import Path
# binary_content = Path(input_file_path).read_bytes()
# print(binary_content)