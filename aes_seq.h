#include <stddef.h>
#include <omp.h>
#define AES_BLOCK_SIZE 16              
#define NUM_THREADS 16
/**************************** DATA TYPES ****************************/
typedef unsigned char BYTE;            // 8-bit byte
typedef unsigned int WORD;             // 32-bit word

/*********************** FUNCTIONS **********************/

// Key setup must be done before any AES en/de-cryption functions can be used.
void keyExpansion(const BYTE key[],          // The key, must be 128, 192, or 256 bits
    WORD w[],                  // Output key schedule to be used later
    int keysize);              // Bit length of the key, 128, 192, or 256

void encrypt(const BYTE in[],             // 16 bytes of plaintext
    BYTE out[],                  // 16 bytes of ciphertext
    const WORD key[],            // all round kets, returned from keyExpansion
    int keysize);                // length of the key: 128, 192, or 256 bits

void decrypt(const BYTE in[],             // 16 bytes of ciphertext(text cryptee)
    BYTE out[],                  // 16 bytes of plaintext
    const WORD key[],            // From the key setup
    int keysize);                // Bit length of the key, 128, 192, or 256


///////////////////
// AES - CTR
///////////////////
void increment_ctr(BYTE ctr[],                  // Must be a multiple of AES_BLOCK_SIZE
    int counter_size,          // Bytes of the IV used for counting (low end)
    long long step);                 // Step to increment the IV by step
void aes_encrypt_ctr(const BYTE in[],         // Plaintext
    size_t in_len,           // Any byte length
    BYTE out[],              // Ciphertext, same length as plaintext
    const WORD key[],        // From the key setup
    int keysize,             // Bit length of the key, 128, 192, or 256
    const BYTE ctr[]);        // IV, must be AES_BLOCK_SIZE bytes long

void aes_encrypt_ctr_openmp(const BYTE in[],         // Plaintext
    size_t in_len,           // Any byte length
    BYTE out[],              // Ciphertext, same length as plaintext
    const WORD key[],        // From the key setup
    int keysize,             // Bit length of the key, 128, 192, or 256
    const BYTE ctr[]);        // IV, must be AES_BLOCK_SIZE bytes long
