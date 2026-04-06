/**
 * Tiny AES-256-CBC implementation (public domain, based on tiny-aes-c).
 *
 * This is a minimal, self-contained AES implementation to avoid depending
 * on OpenSSL. It supports AES-256 with CBC mode and PKCS#7 padding.
 *
 * Source: adapted from https://github.com/kokke/tiny-AES-c
 */

#include <stdint.h>
#include <string.h>

/* ─── AES state and round keys ────────────────────────────────────── */

#define AES_BLOCKLEN 16
#define AES_KEYLEN_256 32
#define AES_keyExpSize 240  /* Expanded key size for AES-256 */

/* The S-box and round constants */
static const uint8_t sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0x1b,0x16,0x63,0x38,0x9f,0x6d,0x88,0x46,0xee,0xb8,
    0x14,0xde,0x5e,0x0b,0xdb,0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,
    0x62,0x91,0x95,0xe4,0x79,0xe7,0xc8,0x37,0x6d,0x33,0xd4,0x69,0x24,0x0f,0xae,0x67,
    0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,
    0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,0x53,0xd1,0x00,0xed,0x20,0xfc,0x1b,
    0x16,0x63,0x38,0x9f,0x6d,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,0xe0,0x32,
    0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,0xe7,0xc8,
    0x37,0x6d,0x33,0xd4,0x69,0x24,0x0f,0xae,0x67,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,
    0xb2,0x75,0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,
    0x2f,0x84,0x53,0xd1,0x00,0xed,0x20,0xfc,0x1b,0x16,0x63,0x38,0x9f,0x6d,0x88,0x46,
    0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,
};

static const uint8_t rsbox[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d,
};

/* Round constants for AES-256 */
static const uint8_t Rcon[15] = {
    0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,0x00,0x00,0x00,0x00
};

/* ─── Key expansion ───────────────────────────────────────────────── */

static void key_expansion_256(const uint8_t *key, uint8_t *round_key) {
    int i, j;

    /* Copy the original key */
    for (i = 0; i < AES_KEYLEN_256; i++) {
        round_key[i] = key[i];
    }

    i = AES_KEYLEN_256;
    while (i < AES_keyExpSize) {
        uint8_t t[4];
        for (j = 0; j < 4; j++) t[j] = round_key[i - 4 + j];

        if (i % AES_KEYLEN_256 == 0) {
            /* RotWord + SubWord + Rcon */
            uint8_t temp = t[0];
            t[0] = t[1]; t[1] = t[2]; t[2] = t[3]; t[3] = temp;
            for (j = 0; j < 4; j++) t[j] = sbox[t[j]];
            t[0] ^= Rcon[i / AES_KEYLEN_256];
        } else if (i % AES_KEYLEN_256 == 16) {
            for (j = 0; j < 4; j++) t[j] = sbox[t[j]];
        }

        for (j = 0; j < 4; j++) {
            round_key[i + j] = round_key[i - AES_KEYLEN_256 + j] ^ t[j];
        }
        i += 4;
    }
}

/* ─── AES core operations ─────────────────────────────────────────── */

#define Nb 4
#define Nk 8   /* AES-256 */
#define Nr 14  /* AES-256 rounds */

static void sub_bytes(uint8_t *state) {
    for (int i = 0; i < 16; i++) state[i] = sbox[state[i]];
}

static void inv_sub_bytes(uint8_t *state) {
    for (int i = 0; i < 16; i++) state[i] = rsbox[state[i]];
}

static void shift_rows(uint8_t *state) {
    uint8_t temp;
    /* Row 1: shift left by 1 */
    temp = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = temp;
    /* Row 2: shift left by 2 */
    temp = state[2]; state[2] = state[10]; state[10] = temp;
    temp = state[6]; state[6] = state[14]; state[14] = temp;
    /* Row 3: shift left by 3 (= right by 1) */
    temp = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = state[3]; state[3] = temp;
}

static void inv_shift_rows(uint8_t *state) {
    uint8_t temp;
    temp = state[13]; state[13] = state[9]; state[9] = state[5]; state[5] = state[1]; state[1] = temp;
    temp = state[10]; state[10] = state[2]; state[2] = temp;
    temp = state[14]; state[14] = state[6]; state[6] = temp;
    temp = state[3]; state[3] = state[7]; state[7] = state[11]; state[11] = state[15]; state[15] = temp;
}

static uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        uint8_t hi = a & 0x80;
        a <<= 1;
        if (hi) a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

static void mix_columns(uint8_t *state) {
    for (int i = 0; i < 4; i++) {
        uint8_t s0 = state[i * 4 + 0], s1 = state[i * 4 + 1];
        uint8_t s2 = state[i * 4 + 2], s3 = state[i * 4 + 3];
        state[i * 4 + 0] = gmul(2,s0) ^ gmul(3,s1) ^ s2 ^ s3;
        state[i * 4 + 1] = s0 ^ gmul(2,s1) ^ gmul(3,s2) ^ s3;
        state[i * 4 + 2] = s0 ^ s1 ^ gmul(2,s2) ^ gmul(3,s3);
        state[i * 4 + 3] = gmul(3,s0) ^ s1 ^ s2 ^ gmul(2,s3);
    }
}

static void inv_mix_columns(uint8_t *state) {
    for (int i = 0; i < 4; i++) {
        uint8_t s0 = state[i * 4 + 0], s1 = state[i * 4 + 1];
        uint8_t s2 = state[i * 4 + 2], s3 = state[i * 4 + 3];
        state[i * 4 + 0] = gmul(14,s0) ^ gmul(11,s1) ^ gmul(13,s2) ^ gmul(9,s3);
        state[i * 4 + 1] = gmul(9,s0) ^ gmul(14,s1) ^ gmul(11,s2) ^ gmul(13,s3);
        state[i * 4 + 2] = gmul(13,s0) ^ gmul(9,s1) ^ gmul(14,s2) ^ gmul(11,s3);
        state[i * 4 + 3] = gmul(11,s0) ^ gmul(13,s1) ^ gmul(9,s2) ^ gmul(14,s3);
    }
}

static void add_round_key(uint8_t *state, const uint8_t *round_key) {
    for (int i = 0; i < 16; i++) state[i] ^= round_key[i];
}

/* ─── AES-256 encrypt / decrypt single block ──────────────────────── */

static void aes_ecb_encrypt_block(const uint8_t *in, uint8_t *out, const uint8_t *round_key) {
    uint8_t state[16];
    memcpy(state, in, 16);

    add_round_key(state, round_key);

    for (int round = 1; round < Nr; round++) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, round_key + round * 16);
    }

    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, round_key + Nr * 16);

    memcpy(out, state, 16);
}

static void aes_ecb_decrypt_block(const uint8_t *in, uint8_t *out, const uint8_t *round_key) {
    uint8_t state[16];
    memcpy(state, in, 16);

    add_round_key(state, round_key + Nr * 16);

    for (int round = Nr - 1; round > 0; round--) {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, round_key + round * 16);
        inv_mix_columns(state);
    }

    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, round_key);

    memcpy(out, state, 16);
}

/* ─── AES-CBC mode ────────────────────────────────────────────────── */

/**
 * AES-256-CBC encrypt.
 *
 * @param key       32-byte AES key
 * @param iv        16-byte IV (will be modified)
 * @param in        Input plaintext
 * @param out       Output ciphertext (same size as in, must be PKCS#7 padded)
 * @param length    Input length (must be multiple of 16)
 */
void aes_cbc_encrypt(const uint8_t *key, uint8_t *iv, const uint8_t *in, uint8_t *out, int length) {
    uint8_t round_key[AES_keyExpSize];
    key_expansion_256(key, round_key);

    for (int i = 0; i < length; i += AES_BLOCKLEN) {
        /* XOR with previous block (or IV) */
        for (int j = 0; j < AES_BLOCKLEN; j++) {
            out[i + j] = in[i + j] ^ iv[j];
        }
        aes_ecb_encrypt_block(out + i, out + i, round_key);
        memcpy(iv, out + i, AES_BLOCKLEN); /* Update IV */
    }
}

/**
 * AES-256-CBC decrypt.
 *
 * @param key       32-byte AES key
 * @param iv        16-byte IV (will be modified)
 * @param in        Input ciphertext
 * @param out       Output plaintext
 * @param length    Input length (must be multiple of 16)
 */
void aes_cbc_decrypt(const uint8_t *key, uint8_t *iv, const uint8_t *in, uint8_t *out, int length) {
    uint8_t round_key[AES_keyExpSize];
    key_expansion_256(key, round_key);
    uint8_t prev_iv[16];

    for (int i = 0; i < length; i += AES_BLOCKLEN) {
        memcpy(prev_iv, in + i, AES_BLOCKLEN); /* Save before decrypt */
        aes_ecb_decrypt_block(in + i, out + i, round_key);
        /* XOR with previous block (or IV) */
        for (int j = 0; j < AES_BLOCKLEN; j++) {
            out[i + j] ^= iv[j];
        }
        memcpy(iv, prev_iv, AES_BLOCKLEN); /* Update IV */
    }
}

/* ─── PKCS#7 padding ──────────────────────────────────────────────── */

/**
 * Apply PKCS#7 padding.
 *
 * @param in        Input data
 * @param in_len    Input length
 * @param out       Output buffer (must be in_len + (1..16) bytes)
 * @return Padded length
 */
int pkcs7_pad(const uint8_t *in, int in_len, uint8_t *out) {
    int pad_len = AES_BLOCKLEN - (in_len % AES_BLOCKLEN);
    memcpy(out, in, in_len);
    for (int i = 0; i < pad_len; i++) {
        out[in_len + i] = (uint8_t)pad_len;
    }
    return in_len + pad_len;
}

/**
 * Remove PKCS#7 padding.
 *
 * @param in        Input data (padded)
 * @param in_len    Padded length
 * @return Unpadded length, or -1 if padding is invalid
 */
int pkcs7_unpad(uint8_t *in, int in_len) {
    if (in_len < 1) return -1;
    int pad_len = in[in_len - 1];
    if (pad_len < 1 || pad_len > AES_BLOCKLEN) return -1;
    for (int i = 0; i < pad_len; i++) {
        if (in[in_len - 1 - i] != pad_len) return -1;
    }
    return in_len - pad_len;
}
