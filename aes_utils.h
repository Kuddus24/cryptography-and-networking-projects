#ifndef AES_UTILS_H
#define AES_UTILS_H

#include "custom_types.h"

#endif // AES_UTILS_H

// Define constants
#define Nb 4 // Number of columns (32-bit words) in the state
#define Nk 4 // Number of 32-bit words in the key
#define Nr 10 // Number of rounds for AES-128


// Rcon for key expansion
static const u8 Rcon[10] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

// Define the S-box
static const u8 sbox[16][16] = {
    {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
    {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
    {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
    {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
    {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
    {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
    {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
    {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
    {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
    {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
    {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
    {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
    {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
    {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
    {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
    {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}
};

// Function to get S-Box value
u8 getSBoxValue(u8 num) {
    return sbox[num >> 4][num & 0x0F];
}

// Define the inverse S-box
static const u8 inv_sbox[16][16] = {
    {0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},
    {0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},
    {0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},
    {0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},
    {0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},
    {0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},
    {0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06},
    {0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b},
    {0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
    {0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},
    {0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},
    {0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},
    {0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},
    {0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},
    {0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},
    {0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d}
};

// Function to get Inverse S-Box value
u8 getInvSBoxValue(u8 num) {
    return inv_sbox[num >> 4][num & 0x0f];
}

// RotWord function for key expansion
void RotWord(u8* word) {
    u8 temp = word[0];
    word[0] = word[1];
    word[1] = word[2];
    word[2] = word[3];
    word[3] = temp;
}

// SubWord function for key expansion
void SubWord(u8* word) {
    for (int i = 0; i < 4; i++) {
        word[i] = getSBoxValue(word[i]);
    }
}

// Key expansion function
void KeyExpansion(u8* RoundKey, const u8* Key) {
    unsigned i, k;
    u8 tempa[4]; // Used for the column/row operations

    // The first round key is the key itself.
    for (i = 0; i < Nk; ++i) {
        RoundKey[(i * 4) + 0] = Key[(i * 4) + 0];
        RoundKey[(i * 4) + 1] = Key[(i * 4) + 1];
        RoundKey[(i * 4) + 2] = Key[(i * 4) + 2];
        RoundKey[(i * 4) + 3] = Key[(i * 4) + 3];
    }

    // All other round keys are found from the previous round keys.
    for (i = Nk; i < Nb * (Nr + 1); ++i) {
        k = (i - 1) * 4;
        tempa[0] = RoundKey[k + 0];
        tempa[1] = RoundKey[k + 1];
        tempa[2] = RoundKey[k + 2];
        tempa[3] = RoundKey[k + 3];

        if (i % Nk == 0) {
            // RotWord() rotates the 4 bytes in a word to the left once
            // [a0, a1, a2, a3] becomes [a1, a2, a3, a0]
            RotWord(tempa);

            // SubWord() applies the S-box to each of the 4 bytes
            SubWord(tempa);

            // XOR with the round constant Rcon[i/Nk]
            tempa[0] = tempa[0] ^ Rcon[(i / Nk) - 1];
        }
        RoundKey[(i * 4) + 0] = RoundKey[(i - Nk) * 4 + 0] ^ tempa[0];
        RoundKey[(i * 4) + 1] = RoundKey[(i - Nk) * 4 + 1] ^ tempa[1];
        RoundKey[(i * 4) + 2] = RoundKey[(i - Nk) * 4 + 2] ^ tempa[2];
        RoundKey[(i * 4) + 3] = RoundKey[(i - Nk) * 4 + 3] ^ tempa[3];
    }
}


// AddRoundKey function XORs the state with the round key
void AddRoundKey(u8 state[4][4], const u8* RoundKey, int round) {
    for (int i = 0; i < 4; i++) {           //loop over columns
        for (int j = 0; j < 4; j++) {       //loop over rows
            state[j][i] ^= RoundKey[(round * Nb * 4) + (i * Nb) + j];
        }
    }
}

// SubBytes transformation replaces each byte in the state with its S-box value
void SubBytes(u8 state[4][4]) {
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[i][j] = getSBoxValue(state[i][j]);
        }
    }
}

// InvSubBytes transformation replaces each byte in the state with its inverse S-box value
void InvSubBytes(u8 state[4][4]) {
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[i][j] = getInvSBoxValue(state[i][j]);
        }
    }
}

// ShiftRows function 
void ShiftRows(u8 state[4][4]) {
    u8 temp;                                           // Temporary variable to hold a value during the rotation.

    // Row 0 is not shifted, rows 1, 2, and 3 are shifted left by increasing amounts.
    for (int row = 1; row < 4; ++row) {                // 'row' specifies how many positions to shift the row to the left.
        for (int shift = 0; shift < row; ++shift) {     
            temp = state[row][0];                      // Store the first element of the row in 'temp' to be placed at the end after shifting.
            for (int col = 0; col < 3; ++col) {
                state[row][col] = state[row][col + 1];
            }
            state[row][3] = temp;                    // Place the original first element (stored in 'temp') at the end of the row.
        }
    }
}

// InvShiftRows function
void InvShiftRows(u8 state[4][4]) {
    u8 temp;

    // Row 0 is not shifted, rows 1, 2, and 3 are shifted right by increasing amounts.
    for (int row = 1; row < 4; ++row) {
        for (int shift = 0; shift < row; ++shift) {
            temp = state[row][3];
            for (int col = 3; col > 0; --col) {
                state[row][col] = state[row][col - 1];
            }
            state[row][0] = temp;
        }
    }
}

// xtime function to perform multiplication by 2 in the GF(2^8) field
u8 xtime(u8 x) {
    return (x << 1) ^ ((x & 0x80) ? 0x1b : 0);          //guide: avoid ussing if..else condition in practice;

   /*  Shift 'x' one bit to the left.
       This is equivalent to multiplying by 2 in the GF(2^8) field.
       The result of (x << 1) is equivalent to x multiplied by 2.
       Check if the most significant bit (MSB) of 'x' was set (i.e., x & 0x80)
       If the MSB was set (i.e., x >= 0x80), then the result of (x << 1) needs to be reduced by XORing with 0x1b.
       If the MSB was not set (i.e., x < 0x80), no reduction is needed, so we just return (x << 1).*/
}

//function multiplies two bytes in the GF(2^8) field using the xtime function
u8 gf_mult(u8 a, u8 b) {
    u8 result = 0;             //initialize result to zero;
    while (b > 0) {            // Continue looping while there are still bits in 'b' to process.
        if (b & 1) {           // Check if the least significant bit of 'b' is set (i.e., if b is odd).
            result ^= a;       // If the bit is set, XOR the current value of 'a' with 'result'.
        }
        a = xtime(a);          // Perform multiplication by 2 in GF(2^8) using the xtime function." This is equivalent to shifting left".
        b >>= 1;               // Shift 'b' to the right by one bit. "This essentially moves to the next bit in 'b' for the next iteration".
    
    }
    return result;              // Return the final result of the multiplication.
}

//Function to perform mixed column  operations;
void mixColumns(u8 state[4][4]) {
    u8 temp[4];

    for (int c = 0; c < 4; ++c) {
        temp[0] = gf_mult(state[0][c], 0x02) ^ gf_mult(state[1][c], 0x03) ^ state[2][c] ^ state[3][c];
        temp[1] = state[0][c] ^ gf_mult(state[1][c], 0x02) ^ gf_mult(state[2][c], 0x03) ^ state[3][c];
        temp[2] = state[0][c] ^ state[1][c] ^ gf_mult(state[2][c], 0x02) ^ gf_mult(state[3][c], 0x03);
        temp[3] = gf_mult(state[0][c], 0x03) ^ state[1][c] ^ state[2][c] ^ gf_mult(state[3][c], 0x02);

        for (int i = 0; i < 4; ++i) {
            state[i][c] = temp[i];
        }
    }
}

// Function to perform inverse MixColumns operation
void invMixColumns(u8 state[4][4]) {
    u8 temp[4];

    for (int c = 0; c < 4; ++c) {
        temp[0] = gf_mult(state[0][c], 0x0e) ^ gf_mult(state[1][c], 0x0b) ^ gf_mult(state[2][c], 0x0d) ^ gf_mult(state[3][c], 0x09);
        temp[1] = gf_mult(state[0][c], 0x09) ^ gf_mult(state[1][c], 0x0e) ^ gf_mult(state[2][c], 0x0b) ^ gf_mult(state[3][c], 0x0d);
        temp[2] = gf_mult(state[0][c], 0x0d) ^ gf_mult(state[1][c], 0x09) ^ gf_mult(state[2][c], 0x0e) ^ gf_mult(state[3][c], 0x0b);
        temp[3] = gf_mult(state[0][c], 0x0b) ^ gf_mult(state[1][c], 0x0d) ^ gf_mult(state[2][c], 0x09) ^ gf_mult(state[3][c], 0x0e);

        for (int i = 0; i < 4; ++i) {
            state[i][c] = temp[i];
        }
    }
}

// AES cipher function
void cipher(u8* input, const u8* key, u8* output) {
    u8 state[4][4]; // 4x4 state array
    u8 RoundKey[Nb * (Nr + 1) * 4]; // Expanded key

    // Convert input to state array (column-major order)
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[j][i] = input[i * 4 + j];
        }
    }

    // Key expansion
    KeyExpansion(RoundKey, key);

    // Initial round key addition
    AddRoundKey(state, RoundKey, 0);

    // Main rounds
    for (int round = 1; round <= Nr - 1; round++) {
        SubBytes(state);
        ShiftRows(state);
        mixColumns(state);
        AddRoundKey(state, RoundKey, round);
    }

    // Final round (without MixColumns)
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, RoundKey, Nr);

    // Convert state back to output (row-major order)
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            output[i * 4 + j] = state[j][i];
        }
    }
}

// AES decryption function
void AES_decrypt(const u8* ciphertext, const u8* key, u8* plaintext) {
    u8 RoundKey[176];
    u8 state[4][4];

    // Expand the key
    KeyExpansion(RoundKey, key);

    // Copy ciphertext to state array
    for (int i = 0; i < 16; ++i) {
        state[i % 4][i / 4] = ciphertext[i];
    }

    // Initial round
    AddRoundKey(state, RoundKey, Nr);

    // Main rounds
    for (int round = Nr - 1; round >= 1; --round) {
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(state, RoundKey, round);
        invMixColumns(state);
    }

    // Final round
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, RoundKey, 0);

    // Copy state array to plaintext
    for (int i = 0; i < 16; ++i) {
        plaintext[i] = state[i % 4][i / 4];
    }
}

void printState(const u8 state[4][4]) {
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            printf("%02X ", state[i][j]);
        }
        printf("\n");
    }
    printf("\n");
}
