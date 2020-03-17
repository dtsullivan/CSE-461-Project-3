# Daniel Sullivan
# CSE 461 Project 3
# AES encryption for TCP

keySize = 16
blockSize = 16
rounds = 10
rowSize = int(blockSize / 4)
rcon = bytes([ 0x01, 0x02, 0x04, 0x08, 0x10,
            0x20, 0x40, 0x80, 0x1B, 0x36 ])

def int_to_byte(x):
    return x & 0xFF

def ROTL8(x, shift):
    return int_to_byte(((x) << (shift)) | ((x) >> (8 - (shift))))

# Algorithm for genenrating s_box
# Derived from Advanced Encryption Standard 2001 specification
# https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.197.pdf
def InitializeSbox(s_box):
    p = 1
    q = 1

    # loop invariant: p * q == 1 in the Galois field
    while (True):
        # multiply p by 3
        p = (p ^ int_to_byte(p << 1) ^
                (0x1B if (p & 0x80) else 0x00))

        # divide q by 3 (equals multiplication by 0xf6)
        q ^= int_to_byte(q << 0x01)
        q ^= int_to_byte(q << 0x02)
        q ^= int_to_byte(q << 0x04)
        q ^= (0x09 if (q & 0x80) else 0x00)

        # compute the affine transformation
        xformed = int_to_byte(q ^ (ROTL8(q, 1)) ^ (ROTL8(q, 2))
                    ^ (ROTL8(q, 3)) ^ (ROTL8(q, 4)))

        s_box[p] = int_to_byte(xformed ^ 0x63)

        if (p == 1):
            break

    # 0 has no inverse
    s_box[0] = 0x63

# Algorithm for genenrating Galois matrix multiplication tables and
# modifying columns
# Derived from Advanced Encryption Standard 2001 specification
# https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.197.pdf
def MultiplyColumn(col, startIndex):
    #'ones' is a copy of input column
    # 'twos' is the elements multiplied by 2 in Rijndael's Galois field
    # ones[n] ^ twos[n] is element n multiplied by 3 in Rijndael's Galois field
    ones = bytearray(rowSize)
    twos = bytearray(rowSize)
    for i in range(rowSize):
        ones[i] = col[i + startIndex]
        # high_bit is 0xff if the high bit of col[n] is 1, 0 otherwise */
        # arithmetic right shift, shifting in zeros or ones
        high_bit = 0xFF if ((col[i + startIndex] >> 7) % 2 == 1) else 0x00
        # remove high bit because twos[i] is an 8-bit char
        # so we xor by 0x1b and not 0x11b
        twos[i] = int_to_byte(col[i + startIndex] << 1)
        twos[i] ^= (0x1B & high_bit)
    # Rijndael's Galois field
    # 2*x0 + 3*x1 + x3 + x2
    col[0 + startIndex] = twos[0] ^ ones[3] ^ ones[2] ^ twos[1] ^ ones[1]
    # x0 + 2*x1 + 3*x2 + x3
    col[1 + startIndex] = twos[1] ^ ones[0] ^ ones[3] ^ twos[2] ^ ones[2]
    # x0 + x1 + 2*x2 + 3*x3
    col[2 + startIndex] = twos[2] ^ ones[1] ^ ones[0] ^ twos[3] ^ ones[3]
    # 3*x0 + x1 + x2 + 2*x3
    col[3 + startIndex] = twos[3] ^ ones[2] ^ ones[1] ^ twos[0] ^ ones[0]

# Multiply columns of block by Galois matrix
def MixColumns(state):
    for i in range(0, blockSize, rowSize):
        MultiplyColumn(state, i)

# Perform key expansion
def ExpandKey(key, expanded_keys, s_box):
    # Copy first key
    for i in range(keySize):
        expanded_keys[i] = key[i]

    # Keep track of total bytes and rcon
    total_bytes = 16
    rcon_index = 1

    # temp word for xor
    temp = bytearray(rowSize)

    while (total_bytes < (keySize * (rounds + 1))):
        # Grab prev 4 bytes for core
        for i in range(rowSize):
            temp[i] = expanded_keys[total_bytes - rowSize + i]

        # Perform key schedule once every 16 bytes
        if (total_bytes % blockSize == 0):
            # Rotate left
            first = temp[0]
            for i in range(rowSize - 1):
                temp[i] = temp[i + 1]

            temp[rowSize - 1] = first

            # substitute bytes
            for i in range(rowSize):
                temp[i] = s_box[temp[i]]

            # XOR with rcon value
            temp[0] ^= rcon[rcon_index - 1]
            rcon_index += 1

        # XOR temp with first 4 bytes of previous key
        for i in range(rowSize):
            expanded_keys[total_bytes] = expanded_keys[total_bytes - 16] ^ temp[i]
            total_bytes += 1

# Substitute bytes from s box
def SubBytes(state, s_box):
    for i in range(blockSize):
        state[i] = s_box[state[i]]

# Shift rows left
def ShiftRows(state):
    # Loops are too confusing in 1D and it is only a 4x4 matrix so
    # we go manually

    # fill temp array
    temp = bytearray(blockSize)
    temp[0] = state[0]
    temp[1] = state[5]
    temp[2] = state[10]
    temp[3] = state[15]
    temp[4] = state[4]
    temp[5] = state[9]
    temp[6] = state[14]
    temp[7] = state[3]
    temp[8] = state[8]
    temp[9] = state[13]
    temp[10] = state[2]
    temp[11] = state[7]
    temp[12] = state[12]
    temp[13] = state[1]
    temp[14] = state[6]
    temp[15] = state[11]

    # copy back to state
    for i in range(blockSize):
        state[i] = temp[i]

def AddRoundKey(state, expanded_keys, key_index):
    for i in range(blockSize):
        state[i] ^= expanded_keys[i + key_index]

# Perform AES encryption on given block
def Encrypt(block, cipher_text, expanded_keys, s_box):
    # copy block to state
    state = bytearray(blockSize)
    for i in range(blockSize):
        state[i] = block[i]

    # inital round
    AddRoundKey(state, expanded_keys, 0)
    key_index = keySize

    # 9 main rounds
    for i in range(rounds - 1):
        SubBytes(state, s_box)
        ShiftRows(state)
        MixColumns(state)
        AddRoundKey(state, expanded_keys, key_index)
        key_index += keySize

    # final round
    SubBytes(state, s_box)
    ShiftRows(state)
    AddRoundKey(state, expanded_keys, key_index)

    # copy to cipher_text array
    for i in range(blockSize):
        cipher_text[i] = state[i]

def main():
    # Generate s-box
    s_box = bytearray(256)
    InitializeSbox(s_box)

    # Read key
    key = bytearray(keySize)
    key = bytes.fromhex(input("Encryption key in hex: "))
    assert(len(key) == keySize)

    # Expand key
    expanded_keys = bytearray((rounds + 1) * keySize)
    ExpandKey(key, expanded_keys, s_box)

    # Read blocks
    message = input("message: ").encode('utf-8')
    index = 0
    while index < len(message):
        # create block to encrypt
        block = bytearray(blockSize)
        blockIndex = 0

        # fill block with message. Remainder is padded with 0x00
        while (blockIndex < blockSize and index < len(message)):
            block[blockIndex] = message[index]
            index += 1
            blockIndex += 1

        # Encrypt blocks
        cipher_text = bytearray(blockSize)
        Encrypt(block, cipher_text, expanded_keys, s_box)

        # Print cipher text
        print(''.join(format(x, '02x') for x in cipher_text))

if __name__ == '__main__':
    main()
