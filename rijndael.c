    
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


void mix_columns(unsigned char *block) {
  // TODO: Implement me!
}

/*
 * Operations used when decrypting a block
 */
void invert_sub_bytes(unsigned char *block) {
  // TODO: Implement me!
}

void invert_shift_rows(unsigned char *block) {
  // TODO: Implement me!
}

void invert_mix_columns(unsigned char *block) {
  // TODO: Implement me!
}

/*
 * This operation is shared between encryption and decryption
 */
void add_round_key(unsigned char *block, unsigned char *round_key) {
  // TODO: Implement me!
}

/*
 * This function should expand the round key. Given an input,
 * which is a single 128-bit key, it should return a 176-byte
 * vector, containing the 11 round keys one after the other
 */
unsigned char *expand_key(unsigned char *cipher_key) {
  // TODO: Implement me!
  return 0;
}

/*
 * The implementations of the functions declared in the
 * header file should go here
 */
unsigned char *aes_encrypt_block(unsigned char *plaintext, unsigned char *key) {
  // TODO: Implement me!
  unsigned char *output =
      (unsigned char *)malloc(sizeof(unsigned char) * BLOCK_SIZE);
  return output;
}

unsigned char *aes_decrypt_block(unsigned char *ciphertext,
                                 unsigned char *key) {
  // TODO: Implement me!
  unsigned char *output =
      (unsigned char *)malloc(sizeof(unsigned char) * BLOCK_SIZE);
  return output;
}
