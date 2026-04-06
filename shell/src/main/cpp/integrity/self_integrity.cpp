#pragma once
/**
 * Native self-integrity check for FuckProtect shell.
 *
 * Computes a hash of our own .text (code) section at runtime and
 * compares it with a hash value embedded at build time. If the
 * native library has been patched (e.g., to bypass anti-debugging),
 * the hash will differ.
 *
 * T9.3: Native self-integrity check
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <link.h>
#include <elf.h>
#include <android/log.h>

#define SELF_TAG "FP_SelfCheck"
#define SELF_LOG(fmt, ...) \
    __android_log_print(ANDROID_LOG_DEBUG, SELF_TAG, fmt, ##__VA_ARGS__)
#define SELF_ERR(fmt, ...) \
    __android_log_print(ANDROID_LOG_ERROR, SELF_TAG, fmt, ##__VA_ARGS__)

/* ─── Build-time hash (replaced by protector) ──────────────────────── */
/*
 * The protector computes SHA-256 of the .text section of libshell.so
 * at build time and replaces this placeholder with the actual hash.
 *
 * Placeholder: "SELF_TEXT_HASH_PLACEHOLDER_32_BYTES!!" (32 bytes)
 */
static const uint8_t EMBEDDED_TEXT_HASH[32] = {
    0x53, 0x45, 0x4c, 0x46, 0x5f, 0x54, 0x45, 0x58, /* "SELF_TEX" */
    0x54, 0x5f, 0x48, 0x41, 0x53, 0x48, 0x5f, 0x50, /* "T_HASH_P" */
    0x4c, 0x41, 0x43, 0x45, 0x48, 0x4f, 0x4c, 0x44, /* "LACEHOLD" */
    0x45, 0x52, 0x5f, 0x33, 0x32, 0x00, 0x00, 0x00, /* "ER_32\0" */
};

/* ─── Simple hash function (FNV-1a) ────────────────────────────────── */
/*
 * We use FNV-1a instead of SHA-256 to avoid pulling in a full crypto
 * library. The hash is computed at runtime and compared with a value
 * computed at build time using the same algorithm.
 *
 * For production, use SHA-256.
 */

#define FNV_OFFSET_BASIS_64 0xCBF29CE484222325ULL
#define FNV_PRIME_64        0x100000001B3ULL

static uint64_t fnv1a_hash(const uint8_t *data, size_t len) {
    uint64_t hash = FNV_OFFSET_BASIS_64;
    for (size_t i = 0; i < len; i++) {
        hash ^= data[i];
        hash *= FNV_PRIME_64;
    }
    return hash;
}

/**
 * Find the .text section of a loaded shared library.
 *
 * @param lib_base Base address of the library
 * @param out_text Output: pointer to .text section
 * @param out_size Output: size of .text section
 * @return 0 on success, -1 on error
 */
static int find_text_section(uintptr_t lib_base, void **out_text, size_t *out_size) {
    ElfW(Ehdr) *ehdr = (ElfW(Ehdr) *)lib_base;

    /* Verify ELF magic */
    if (memcmp(ehdr->e_ident, "\177ELF", 4) != 0) {
        return -1;
    }

    /* Get section header table */
    ElfW(Shdr) *shdr = (ElfW(Shdr) *)(lib_base + ehdr->e_shoff);
    const char *shstrtab = (const char *)(lib_base +
        shdr[ehdr->e_shstrndx].sh_offset);

    /* Iterate sections to find .text */
    for (int i = 0; i < ehdr->e_shnum; i++) {
        const char *name = shstrtab + shdr[i].sh_name;
        if (strcmp(name, ".text") == 0) {
            *out_text = (void *)(lib_base + shdr[i].sh_addr);
            *out_size = shdr[i].sh_size;
            return 0;
        }
    }

    return -1;
}

/**
 * Get the base address of libshell.so.
 */
static uintptr_t get_shell_lib_base(void) {
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return 0;

    char line[512];
    uintptr_t base = 0;

    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "libshell.so") && strstr(line, "r-xp")) {
            char *dash = strchr(line, '-');
            if (dash) {
                *dash = '\0';
                base = (uintptr_t)strtoul(line, NULL, 16);
            }
            break;
        }
    }

    fclose(fp);
    return base;
}

/**
 * Compute hash of our own .text section.
 *
 * @param hash_out Output buffer for 8-byte FNV-1a hash
 * @return 0 on success, -1 on error
 */
static int compute_text_hash(uint64_t *hash_out) {
    uintptr_t base = get_shell_lib_base();
    if (base == 0) {
        SELF_ERR("Cannot find libshell.so base address");
        return -1;
    }

    void *text_addr = NULL;
    size_t text_size = 0;

    if (find_text_section(base, &text_addr, &text_size) != 0) {
        SELF_ERR("Cannot find .text section in libshell.so");
        return -1;
    }

    *hash_out = fnv1a_hash((const uint8_t *)text_addr, text_size);
    SELF_LOG("Computed .text hash: 0x%016lx (size: %zu)",
             (unsigned long)*hash_out, text_size);

    return 0;
}

/**
 * Verify our own .text section hasn't been modified.
 *
 * @return 0 = integrity OK, 1 = tampering detected
 */
int verify_native_integrity(void) {
    uint64_t current_hash;

    if (compute_text_hash(&current_hash) != 0) {
        /* Can't compute hash — skip check rather than fail */
        SELF_LOG("Skipping self-integrity check (couldn't compute hash)");
        return 0;
    }

    /*
     * Compare with embedded hash. The embedded value is stored as 32 bytes
     * but our FNV-1a hash is 8 bytes. We only compare the first 8 bytes.
     */
    uint64_t expected_hash;
    memcpy(&expected_hash, EMBEDDED_TEXT_HASH, sizeof(uint64_t));

    if (current_hash != expected_hash) {
        SELF_ERR("Self-integrity check FAILED: hash mismatch");
        SELF_ERR("  Expected: 0x%016lx", (unsigned long)expected_hash);
        SELF_ERR("  Current:  0x%016lx", (unsigned long)current_hash);
        return 1;
    }

    SELF_LOG("Self-integrity check PASSED");
    return 0;
}

/**
 * Get the embedded text hash (for debugging).
 */
void get_embedded_text_hash_hex(char *out, int out_size) {
    /* Just use the first 8 bytes as hex */
    uint64_t hash;
    memcpy(&hash, EMBEDDED_TEXT_HASH, sizeof(uint64_t));
    snprintf(out, out_size, "%016lx", (unsigned long)hash);
}
