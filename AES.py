# Daniel Sullivan
# CSE 461 Project 3
# 128-bit AES encryption for TCP

keySize = 16
blockSize = 16
rounds = 10
rowSize = int(blockSize / 4)
rcon = bytes([ 0x01, 0x02, 0x04, 0x08, 0x10,
            0x20, 0x40, 0x80, 0x1B, 0x36 ])

# Could compute s-box, but faster to hard code due to small key size
s_box = bytes([0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67,
        0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59,
        0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7,
        0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1,
        0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05,
        0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83,
        0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29,
        0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
        0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa,
        0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c,
        0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc,
        0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
        0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19,
        0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee,
        0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
        0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4,
        0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6,
        0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70,
        0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9,
        0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e,
        0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1,
        0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0,
        0x54, 0xbb, 0x16])

inv_s_box = bytes([0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3,
        0x9e, 0x81, 0xf3, 0xd7, 0xfb , 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f,
        0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb , 0x54,
        0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b,
        0x42, 0xfa, 0xc3, 0x4e , 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24,
        0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25 , 0x72, 0xf8,
        0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d,
        0x65, 0xb6, 0x92 , 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
        0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84 , 0x90, 0xd8, 0xab,
        0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3,
        0x45, 0x06 , 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1,
        0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b , 0x3a, 0x91, 0x11, 0x41,
        0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6,
        0x73 , 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9,
        0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e , 0x47, 0xf1, 0x1a, 0x71, 0x1d,
        0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b ,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0,
        0xfe, 0x78, 0xcd, 0x5a, 0xf4 , 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07,
        0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f , 0x60,
        0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f,
        0x93, 0xc9, 0x9c, 0xef , 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5,
        0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61 , 0x17, 0x2b,
        0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55,
        0x21, 0x0c, 0x7d])

def int_to_byte(x):
    return x & 0xFF

def ROTL8(x, shift):
    return int_to_byte(((x) << (shift)) | ((x) >> (8 - (shift))))

# galois multiplication of element a multiplied by b in the
# galois field for 8 bit item
def galois(a, b):
    p = 0
    for _ in range(8):
        if (b & 0x01):
            p = p ^ a
        high_bit = a & 0x80
        # remove high bit because it is an 8-bit char
        # so we xor by 0x1b and not 0x11b
        a = int_to_byte(a << 1)
        if high_bit:
            a = a ^ 0x1B
        # arithmetic right shift, shifting in zeros or ones
        b = b >> 1
    return p


# Generate Galois matrix multiplication tables and
# modifying columns
# Derived from Advanced Encryption Standard 2001 specification
# https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.197.pdf
def MultiplyColumn(col, startIndex):
    temp = bytes([col[0 + startIndex], col[1 + startIndex],
            col[2 + startIndex], col[3 + startIndex]])
    # Rijndael's Galois field
    # 2*x0 + 3*x1 + x2 + x3
    col[0 + startIndex] = galois(temp[0], 2) ^ galois(temp[3], 1) ^ galois(temp[2], 1) ^ galois(temp[1], 3)
    # x0 + 2*x1 + 3*x2 + x3
    col[1 + startIndex] = galois(temp[1], 2) ^ galois(temp[0], 1) ^ galois(temp[3], 1) ^ galois(temp[2], 3)
    # x0 + x1 + 2*x2 + 3*x3
    col[2 + startIndex] = galois(temp[2], 2) ^ galois(temp[1], 1) ^ galois(temp[0], 1) ^ galois(temp[3], 3)
    # 3*x0 + x1 + x2 + 2*x3
    col[3 + startIndex] = galois(temp[3], 2) ^ galois(temp[2], 1) ^ galois(temp[1], 1) ^ galois(temp[0], 3)

def InvMultiplyColumn(col, startIndex):
    temp = bytes([col[0 + startIndex], col[1 + startIndex],
            col[2 + startIndex], col[3 + startIndex]])
    # Inverse Rijndael's Galois field
    # 14*x0 + 11*x1 + 13*x2 + 9*x3
    col[0 + startIndex] = galois(temp[0], 14) ^ galois(temp[3], 9) ^ galois(temp[2], 13) ^ galois(temp[1], 11)
    # 9*x0 + 14*x1 + 11*x2 + 13*x3
    col[1 + startIndex] = galois(temp[1], 14) ^ galois(temp[0], 9) ^ galois(temp[3], 13) ^ galois(temp[2], 11)
    # 13*x0 + 9*x1 + 14*x2 + 11*x3
    col[2 + startIndex] = galois(temp[2], 14) ^ galois(temp[1], 9) ^ galois(temp[0], 13) ^ galois(temp[3], 11)
    # 11*x0 + 13*x1 + 9*x2 + 14*x3
    col[3 + startIndex] = galois(temp[3], 14) ^ galois(temp[2], 9) ^ galois(temp[1], 13) ^ galois(temp[0], 11)

# Multiply columns of block by Galois matrix
def MixColumns(state):
    for i in range(0, blockSize, rowSize):
        MultiplyColumn(state, i)

# Multiply columns of inverse block by Galois matrix
def InvMixColumns(state):
    for i in range(0, blockSize, rowSize):
        InvMultiplyColumn(state, i)

# Perform key expansion
def ExpandKey(key, expanded_keys):
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
def SubBytes(state):
    for i in range(blockSize):
        state[i] = s_box[state[i]]

# Substitute bytes from s box
def InvSubBytes(state):
    for i in range(blockSize):
        state[i] = inv_s_box[state[i]]

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

# Shift rows right
def InvShiftRows(state):
    # Loops are too confusing in 1D and it is only a 4x4 matrix so
    # we go manually

    # fill temp array
    temp = bytearray(blockSize)
    temp[0] = state[0]
    temp[1] = state[13]
    temp[2] = state[10]
    temp[3] = state[7]
    temp[4] = state[4]
    temp[5] = state[1]
    temp[6] = state[14]
    temp[7] = state[11]
    temp[8] = state[8]
    temp[9] = state[5]
    temp[10] = state[2]
    temp[11] = state[15]
    temp[12] = state[12]
    temp[13] = state[9]
    temp[14] = state[6]
    temp[15] = state[3]

    # copy back to state
    for i in range(blockSize):
        state[i] = temp[i]

def AddRoundKey(state, expanded_keys, key_index):
    for i in range(blockSize):
        state[i] ^= expanded_keys[i + key_index]

# Perform AES encryption on given block
def EncryptBlock(block, cipher_text, expanded_keys):
    # copy block to state
    state = bytearray(blockSize)
    for i in range(blockSize):
        state[i] = block[i]

    # inital round
    key_index = 0
    AddRoundKey(state, expanded_keys, key_index)
    key_index += keySize

    # 9 main rounds
    for i in range(rounds - 1):
        SubBytes(state)
        ShiftRows(state)
        MixColumns(state)
        AddRoundKey(state, expanded_keys, key_index)
        key_index += keySize

    # final round
    SubBytes(state)
    ShiftRows(state)
    AddRoundKey(state, expanded_keys, key_index)

    # copy to cipher_text array
    for i in range(blockSize):
        cipher_text[i] = state[i]

# Perform AES decryption on given block
def DecryptBlock(block, cipher_text, expanded_keys):
    # copy block to state
    state = bytearray(blockSize)
    for i in range(blockSize):
        state[i] = block[i]
    
    # inital round
    key_index = rounds * keySize
    AddRoundKey(state, expanded_keys, key_index)
    key_index -= keySize

    # 9 main rounds
    for i in range(rounds - 1):
        InvShiftRows(state)
        InvSubBytes(state)
        AddRoundKey(state, expanded_keys, key_index)
        InvMixColumns(state)
        key_index -= keySize

    # final round
    InvShiftRows(state)
    InvSubBytes(state)
    AddRoundKey(state, expanded_keys, key_index)

    # copy to cipher_text array
    for i in range(blockSize):
        cipher_text[i] = state[i]

# Encrypt hex message with key
def Encrypt(message, key):
    # Expand key
    expanded_keys = bytearray((rounds + 1) * keySize)
    ExpandKey(key, expanded_keys)

    # Read blocks
    index = 0
    encrypted_message = bytearray()
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
        encrypted_block = bytearray(blockSize)
        EncryptBlock(block, encrypted_block, expanded_keys)
        encrypted_message += encrypted_block

    return encrypted_message

# decrypt hex ciphertext
def Decrypt(encrypted_message, key):
    # Expand key
    expanded_keys = bytearray((rounds + 1) * keySize)
    ExpandKey(key, expanded_keys)

    # Read blocks
    index = 0
    decrypted_message = bytearray()
    while index < len(encrypted_message):
        # create block to decrypt
        block = bytearray(blockSize)
        blockIndex = 0

        # fill block with message. Remainder is padded with 0x00
        while (blockIndex < blockSize and index < len(encrypted_message)):
            block[blockIndex] = encrypted_message[index]
            index += 1
            blockIndex += 1

        # Decrypt blocks
        decrypted_block = bytearray(blockSize)
        DecryptBlock(block, decrypted_block, expanded_keys)
        decrypted_message += decrypted_block

    return decrypted_message

def main():
    # Read key
    key = bytearray(keySize)
    key = bytes.fromhex(input("Encryption key in hex: "))
    assert(len(key) == keySize)

    # read message
    message = bytes.fromhex(input("Message in hex: "))

    # encrypt
    encrypted_message = Encrypt(message, key)

    # Print cipher text
    print('Cipher text in hex: ' + ''.join(format(x, '02x') for x in encrypted_message))

    # decrypt
    decrypted_message = Decrypt(encrypted_message, key)

    # Print decoded text
    print('Decrypted text in hex: ' + ''.join(format(x, '02x') for x in decrypted_message))

if __name__ == '__main__':
    main()
