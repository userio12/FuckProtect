/**
 * Key derivation for DEX decryption.
 *
 * The AES-256 key is computed at build time as SHA-256 of the APK signing
 * certificate. This hash is embedded into the native library by the
 * protector tool and replaced during the protection process.
 *
 * At runtime, the shell verifies that the APK's current signing certificate
 * matches the embedded hash before proceeding with DEX decryption.
 */

#include <stdint.h>
#include <string.h>

/* ─── Embedded certificate hash (replaced by protector at build time) ─── */
/*
 * The protector replaces these placeholder bytes with the actual SHA-256
 * hash of the APK signing certificate. The pattern "CERT_HASH_PLACEHOLDER"
 * (32 bytes, padded) is searched for and replaced.
 */
static const uint8_t EMBEDDED_CERT_HASH[32] = {
    0x43, 0x45, 0x52, 0x54, 0x5f, 0x48, 0x41, 0x53, /* "CERT_HAS" */
    0x48, 0x5f, 0x50, 0x4c, 0x41, 0x43, 0x45, 0x48, /* "H_PLACEH" */
    0x4f, 0x4c, 0x44, 0x45, 0x52, 0x00, 0x00, 0x00, /* "HOLDER\0" */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* "\0\0..." */
};

/**
 * Get the embedded certificate hash.
 *
 * @param out Output buffer (must be 32 bytes)
 */
void get_embedded_cert_hash(uint8_t *out) {
    memcpy(out, EMBEDDED_CERT_HASH, 32);
}

/**
 * Verify a certificate hash against the embedded one.
 *
 * @param current_hash 32-byte SHA-256 of current APK signing cert
 * @return 1 if match, 0 if mismatch
 */
int verify_cert_hash(const uint8_t *current_hash) {
    /* Constant-time comparison to prevent timing attacks */
    volatile uint8_t result = 0;
    for (int i = 0; i < 32; i++) {
        result |= current_hash[i] ^ EMBEDDED_CERT_HASH[i];
    }
    return result == 0;
}

/**
 * Derive the AES key from a certificate hash.
 *
 * The key IS the SHA-256 hash (32 bytes = 256 bits).
 *
 * @param cert_hash 32-byte SHA-256 of the signing certificate
 * @param key_out   Output buffer (must be 32 bytes) — same as input
 */
void derive_aes_key(const uint8_t *cert_hash, uint8_t *key_out) {
    memcpy(key_out, cert_hash, 32);
}
