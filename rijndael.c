    
/*
 * Fintan Parsons D22127543
 *       This code describes the AES/Rijndael algorithm
 *  The code takes in a block of 128 bits and encrypts it.
 * First it adds a round key, I will describe how the roundkeys are generated later.
 * Then it changes the bytes in the block to different bytes according to 
 * a 'sub byte' or byte substitution lookup table. 
 * 
 * It then shiftrows the rows as if the block was organised into a square of rows and columns. 
 * the first row isn't shifted at all, the second row takes the first datum on the left and moves it to index 3 or the ourth ppoistion while shifting all others left one place in the row.
 * The third row moves two from the left to the end and shifts the rest two places left. so the byte at index 0 moves to index 2, 1 to 3 in this case.
 * The fourth row move three in a similar fashion
 * 
 * 
 * Then the columns are mixed also.
 * Mixed meaning each column is swapped with its dot product of a specified Galois Field
 * 
 *  And another round key is added. 
 * 'Added' meaning each column of the block is XOR bitwise with the corresponding column of the round key.
 * There is a different round key for each round.
 * 
 * Round keys are generated from the original cipher key.
 * First the fourth column is shifted downwards were the first item becomes the last and the rest are shifted up.
 * This new column is swapped with subbytes in the subbytes table and 
 * XOR bitwise with the first column of the ciper and Rcon column to generate the firs t column of the round key.
 * For the next 3 columns of the round key, each colmun of the last key is XOR'd with the last column generated in the round key.
 * Theses steps are repeated with the last roundkey generated geernating the next roundkey.
 * This is done 10 times
 * 
 * These steps: SubBytes, Shiftrows MixColumns and AddRoundKey are repeated nine times.
 * 
 * Finally, the subBytes, Shiftrows, and addition of a roundkey are done again but not the mixing of columns. 
 * This gives the encrypted message.
 * 
 * To retrieve the plaintext message, inverted versions of these steps are done in reverse with the same key because this is a symmetric encrytion method.
 */

#include <stdlib.h>
#include <stdio.h>
// TODO: Any other files you need to include should go here

#include "rijndael.h"

//S_block is the sub buytes conversion table where the index is used to looku[ the replacement byte
unsigned char S_block[256] = {0x63, 0x7c,   0x77,   0x7b,   0xf2,   0x6b,   0x6f,   0xc5,   0x30,   0x01,   0x67,   0x2b,   0xfe,   0xd7,   0xab,   0x76,0xca,  0x82,   0xc9,   0x7d,   0xfa,   0x59,   0x47,   0xf0,   0xad,   0xd4,   0xa2,   0xaf,   0x9c,   0xa4,   0x72,   0xc0,0xb7,  0xfd,   0x93,   0x26,   0x36,   0x3f,   0xf7,   0xcc,   0x34,   0xa5,   0xe5,   0xf1,   0x71,   0xd8,   0x31,   0x15,0x04,  0xc7,   0x23,   0xc3,   0x18,   0x96,   0x05,   0x9a,   0x07,   0x12,   0x80,   0xe2,   0xeb,   0x27,   0xb2,   0x75, 0x09, 0x83,   0x2c,   0x1a,   0x1b,   0x6e,   0x5a,   0xa0,   0x52,   0x3b,   0xd6,   0xb3,   0x29,   0xe3,   0x2f,   0x84, 0x53, 0xd1,   0x00,   0xed,   0x20,   0xfc,   0xb1,   0x5b,   0x6a,   0xcb,   0xbe,   0x39,   0x4a,   0x4c,   0x58,   0xcf,0xd0,  0xef,   0xaa,   0xfb,   0x43,   0x4d,   0x33,   0x85,   0x45,   0xf9,   0x02,   0x7f,   0x50,   0x3c,   0x9f,   0xa8,0x51,  0xa3,   0x40,   0x8f,   0x92,   0x9d,   0x38,   0xf5,   0xbc,   0xb6,   0xda,   0x21,   0x10,   0xff,   0xf3,   0xd2, 0xcd, 0x0c,   0x13,   0xec,   0x5f,   0x97,   0x44,   0x17,   0xc4,   0xa7,   0x7e,   0x3d,   0x64,   0x5d,   0x19,   0x73,0x60,  0x81,   0x4f,   0xdc,   0x22,   0x2a,   0x90,   0x88,   0x46,   0xee,   0xb8,   0x14,   0xde,   0x5e,   0x0b,   0xdb,0xe0,  0x32,   0x3a,   0x0a,   0x49,   0x06,   0x24,   0x5c,   0xc2,   0xd3,   0xac,   0x62,   0x91, 0x95, 0xe4,   0x79,0xe7,  0xc8,   0x37,   0x6d,   0x8d,   0xd5,   0x4e,   0xa9,   0x6c,   0x56,   0xf4,   0xea,   0x65,   0x7a,   0xae,   0x08,0xba,  0x78,   0x25,   0x2e,   0x1c,   0xa6,   0xb4,   0xc6,   0xe8,   0xdd,   0x74,   0x1f,   0x4b,   0xbd,   0x8b,   0x8a,0x70,  0x3e,   0xb5,   0x66,   0x48,   0x03,   0xf6,   0x0e,   0x61,   0x35,   0x57,   0xb9,   0x86,   0xc1,   0x1d,   0x9e,0xe1,  0xf8,   0x98,   0x11,   0x69,   0xd9,   0x8e,   0x94,   0x9b,   0x1e,   0x87,   0xe9,   0xce,   0x55,   0x28,   0xdf, 0x8c, 0xa1,   0x89,   0x0d,   0xbf,   0xe6,   0x42,   0x68,   0x41,   0x99,   0x2d,   0x0f,   0xb0,   0x54,   0xbb,   0x16 };

/*
 * Operations used when encrypting a block
 */
void sub_bytes(unsigned char *block) {

  /*
 * This uses the S_block lookup table to convert byte
 */
    for (int i = 0; i < 16; i++) {
        block[i] = S_block[block[i]]; // Substitute each byte
    }
}


void shift_rows(unsigned char *block) {
      unsigned char temp;

    // Second row shift left by 1
    temp = block[1]; 
    block[1] = block[5];
    block[5] = block[9];
    block[9] = block[13];
    block[13] = temp;

    // Third row shift left by 2
    temp = block[2]; // Store the first element of row 2
    block[2] = block[10];
    block[10] = temp;
    temp = block[6]; // Store the second element of row 2
    block[6] = block[14];
    block[14] = temp;

    // Fourth row shift left by 3 (or right by 1, same effect)
    temp = block[15]; // Store the last element of row 3
    block[15] = block[11];
    block[11] = block[7];
    block[7] = block[3];
    block[3] = temp;
}



unsigned char gmul(unsigned char a, unsigned char b) {
    unsigned char p = 0; // Result of the multiplication (initially 0, representing the zero polynomial).
    unsigned char hi_bit_set; // To check for the overflow bit (x^8 term).

    for (int counter = 0; counter < 8; counter++) {
        // If the current bit of b (representing the coefficient of x^counter in b(x)) is set...
        if (b & 1) {
            // Add a(x) to p(x) (in GF(2^8), addition is XOR).
            p ^= a; 
        }

        // Prepare for the next iteration:
        // Check if the x^7 term of a(x) is set before multiplication by x.
        hi_bit_set = a & 0x80; 
        // Multiply a(x) by x (equivalent to a left shift by 1).
        a <<= 1; 

        // If the multiplication resulted in x^8 term, reduce by the irreducible polynomial (x^8 + x^4 + x^3 + x + 1).
        if (hi_bit_set) {
            a ^= 0x1b; // 0x1b represents the polynomial x^8 + x^4 + x^3 + x + 1.
        }

        // Prepare b(x) for the next term (equivalent to dividing by x, or shifting right by 1).
        b >>= 1; 
    }

    return p; // Return the product p(x) = a(x) * b(x) mod (x^8 + x^4 + x^3 + x + 1).
}




void mix_columns(unsigned char *block) {
    unsigned char temp[4];
    for (int i = 0; i < 4; i++) { // Iterate over columns
        temp[0] = gmul(0x02, block[i*4]) ^ gmul(0x03, block[i*4+1]) ^ block[i*4+2] ^ block[i*4+3];
        temp[1] = block[i*4] ^ gmul(0x02, block[i*4+1]) ^ gmul(0x03, block[i*4+2]) ^ block[i*4+3];
        temp[2] = block[i*4] ^ block[i*4+1] ^ gmul(0x02, block[i*4+2]) ^ gmul(0x03, block[i*4+3]);
        temp[3] = gmul(0x03, block[i*4]) ^ block[i*4+1] ^ block[i*4+2] ^ gmul(0x02, block[i*4+3]);
        for (int j = 0; j < 4; j++) {
            block[i*4+j] = temp[j];
        }
    }
}

/*
 * Operations used when decrypting a block
 */
void invert_sub_bytes(unsigned char *block) {
   unsigned char inv_S_block[256] = {
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    };

    for (int i = 0; i < 16; i++) {
        block[i] = inv_S_block[block[i]]; // Replace each byte with its inverse from the S-box
    }
}



void invert_shift_rows(unsigned char *block) {
   unsigned char temp;

    // Invert shift for the second row - shift right by 1
    temp = block[13]; // Store the last element of row 1
    block[13] = block[9];
    block[9] = block[5];
    block[5] = block[1];
    block[1] = temp;

    // Invert shift for the third row - shift right by 2
    temp = block[2]; // Swap first and third elements
    block[2] = block[10];
    block[10] = temp;
    temp = block[6]; // Swap second and fourth elements
    block[6] = block[14];
    block[14] = temp;

    // Invert shift for the fourth row - shift right by 3 (or left by 1, same effect)
    temp = block[3]; // Store the first element of row 3
    block[3] = block[7];
    block[7] = block[11];
    block[11] = block[15];
    block[15] = temp;
}



void invert_mix_columns(unsigned char *block) {
    unsigned char temp[4];
    for (int i = 0; i < 4; i++) {
        temp[0] = gmul(0x0e, block[i*4]) ^ gmul(0x0b, block[i*4+1]) ^ gmul(0x0d, block[i*4+2]) ^ gmul(0x09, block[i*4+3]);
        temp[1] = gmul(0x09, block[i*4]) ^ gmul(0x0e, block[i*4+1]) ^ gmul(0x0b, block[i*4+2]) ^ gmul(0x0d, block[i*4+3]);
        temp[2] = gmul(0x0d, block[i*4]) ^ gmul(0x09, block[i*4+1]) ^ gmul(0x0e, block[i*4+2]) ^ gmul(0x0b, block[i*4+3]);
        temp[3] = gmul(0x0b, block[i*4]) ^ gmul(0x0d, block[i*4+1]) ^ gmul(0x09, block[i*4+2]) ^ gmul(0x0e, block[i*4+3]);
        for (int j = 0; j < 4; j++) {
            block[i*4+j] = temp[j];
        }
    }
}


/*
 * This operation is shared between encryption and decryption
 */
void add_round_key(unsigned char *block, unsigned char *round_key) {
    for (int i = 0; i < 16; i++) {
        block[i] ^= round_key[i]; // Perform XOR on each byte
    }
}

// Round constant
unsigned char rcon[10] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};
/*
 * This function should expand the round key. Given an input,
 * which is a single 128-bit key, it should return a 176-byte
 * vector, containing the 11 round keys one after the other
 */
void key_expansion(unsigned char* cipher_key, unsigned char* expanded_keys) {
    int bytes_generated = 16; // We start after the first 16 bytes
    int rcon_iteration = 0;
    unsigned char temp[4]; // Temporary storage for the core

    // The first 16 bytes of the expanded key are the cipher key
    for (int i = 0; i < 16; i++) {
        expanded_keys[i] = cipher_key[i];
    }

    // Generate the remaining bytes until we get a total of 176 bytes
    while (bytes_generated < 176) {
        // Read 4 bytes for the core operation
        for (int i = 0; i < 4; i++) {
            temp[i] = expanded_keys[i + bytes_generated - 4];
        }

        // Perform the core operation once for each 16 byte key
        if (bytes_generated % 16 == 0) {
            // Rotate the input 8 bits to the left
            unsigned char a = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = a;

            // Apply S-box substitution
            for (int i = 0; i < 4; i++) {
                temp[i] = S_block[temp[i]];
            }

            // XOR the first byte with the round constant
            temp[0] ^= rcon[rcon_iteration++];
        }

        // XOR temp with the four-byte block 16 bytes before the new expanded key. This step is done for all bytes.
        for (unsigned char a = 0; a < 4; a++) {
            expanded_keys[bytes_generated] = expanded_keys[bytes_generated - 16] ^ temp[a];
            bytes_generated++;
        }
    }
}



/*
 * The implementations of the functions declared in the
 * header file should go here
 */
unsigned char *aes_encrypt_block(unsigned char *plaintext, unsigned char *key) {
  printf("aes encrypt block");
  unsigned char* output = (unsigned char*)malloc(sizeof(unsigned char) * BLOCK_SIZE);
    if (!output) {
        return NULL; // Allocation failed
    }

    // With AES-128, we need 176 bytes of expanded keys
    unsigned char expandedKeys[176]; 
    key_expansion(key, expandedKeys);

    // Copy plaintext to output as the initial state
    for (int i = 0; i < BLOCK_SIZE; i++) {
        output[i] = plaintext[i];
    }

    // Initial round key addition
    add_round_key(output, expandedKeys);

    // 9 rounds of encryption
    for (int i = 1; i < 10; i++) {
        sub_bytes(output);
        shift_rows(output);
        mix_columns(output);
        add_round_key(output, expandedKeys + (BLOCK_SIZE * i));
    }

    // Final round (without mix columns)
    sub_bytes(output);
    shift_rows(output);
    add_round_key(output, expandedKeys + 160); // The final round key

  //unsigned char *output = (unsigned char *)malloc(sizeof(unsigned char) * BLOCK_SIZE);
  return output;
}

unsigned char* aes_decrypt_block(unsigned char* ciphertext, unsigned char* key) {
    unsigned char* output = (unsigned char*)malloc(sizeof(unsigned char) * BLOCK_SIZE);
    if (!output) {
        return NULL; // Allocation failed
    }

    unsigned char expandedKeys[176]; // For AES-128, we need 176 bytes of expanded keys
    key_expansion(key, expandedKeys);

    // Copy ciphertext to output as the initial state
    for (int i = 0; i < BLOCK_SIZE; i++) {
        output[i] = ciphertext[i];
    }

    // Initial round key addition (using the last round key)
    add_round_key(output, expandedKeys + 160); // The last round key

    // 9 rounds of decryption
    for (int round = 9; round > 0; round--) {
        invert_shift_rows(output);
        invert_sub_bytes(output);
        add_round_key(output, expandedKeys + (BLOCK_SIZE * round));
        invert_mix_columns(output);
    }

    // Final round (without invert mix columns)
    invert_shift_rows(output);
    invert_sub_bytes(output);
    add_round_key(output, expandedKeys); // The initial round key

    return output;
}
