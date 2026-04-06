/**
 * RC4 implementation for FuckProtect shell.
 *
 * Used to decrypt .so file sections at runtime.
 * The protector encrypts ELF sections (.bitcode, .rodata) with RC4,
 * embedding the key at a known ELF symbol offset.
 *
 * Based on dpt-shell's rc4/rc4.c implementation.
 */

#include <stdint.h>
#include <string.h>

/**
 * Initialize the RC4 state with the given key.
 *
 * @param state RC4 state array (256 bytes)
 * @param key Encryption key
 * @param keyLen Key length in bytes
 */
void rc4_init(uint8_t *state, const uint8_t *key, int keyLen) {
    for (int i = 0; i < 256; i++) {
        state[i] = (uint8_t)i;
    }

    uint8_t j = 0;
    for (int i = 0; i < 256; i++) {
        j = (uint8_t)(j + state[i] + key[i % keyLen]);
        uint8_t temp = state[i];
        state[i] = state[j];
        state[j] = temp;
    }
}

/**
 * Encrypt or decrypt data using RC4.
 *
 * RC4 is symmetric — the same function encrypts and decrypts.
 *
 * @param state RC4 state array (256 bytes, already initialized)
 * @param input Input data
 * @param output Output data (can be same as input for in-place)
 * @param len Data length in bytes
 */
void rc4_crypt(uint8_t *state, const uint8_t *input, uint8_t *output, int len) {
    uint8_t i = 0, j = 0;

    for (int n = 0; n < len; n++) {
        i = (uint8_t)(i + 1);
        j = (uint8_t)(j + state[i]);

        uint8_t temp = state[i];
        state[i] = state[j];
        state[j] = temp;

        uint8_t k = state[(uint8_t)(state[i] + state[j])];
        output[n] = input[n] ^ k;
    }
}

/**
 * Convenience function: RC4 encrypt/decrypt a buffer in-place.
 *
 * @param key RC4 key
 * @param keyLen Key length
 * @param data Data to encrypt/decrypt (modified in-place)
 * @param len Data length
 */
void rc4_inplace(const uint8_t *key, int keyLen, uint8_t *data, int len) {
    uint8_t state[256];
    rc4_init(state, key, keyLen);
    rc4_crypt(state, data, data, len);
}
