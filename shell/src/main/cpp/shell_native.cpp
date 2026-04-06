/**
 * JNI entry point for the FuckProtect shell native library.
 *
 * This file bridges the Java ShellApplication class with native
 * crypto, anti-debugging, and integrity functions.
 */

#include <jni.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <android/log.h>
#include <sys/mman.h>
#include <elf.h>
#include <link.h>
#include <sys/sysconf.h>

/* Section header type constants */
#ifndef SHT_SYMTAB
#define SHT_SYMTAB 2
#endif
#ifndef SHT_DYNSYM
#define SHT_DYNSYM 11
#endif
#ifndef SHF_ALLOC
#define SHF_ALLOC 0x2
#endif
#ifndef SHF_EXECINSTR
#define SHF_EXECINSTR 0x4
#endif

#include "crypto/aes.c"           /* AES-256-CBC + PKCS#7 */
#include "crypto/key_derive.c"    /* Key derivation + cert hash verification */
#include "rc4/rc4.c"              /* RC4 for .so section decryption */
#include "antidbg/anti_debug.cpp" /* Anti-debugging checks */
#include "antidbg/continuous_monitor.cpp" /* Continuous monitoring + emulator detect */
#include "antidbg/protect_process.cpp" /* Child process protection */
#include "integrity/self_check.cpp"   /* Signature / APK integrity */
#include "integrity/self_integrity.cpp" /* Native self-integrity */
#include "hook/anti_hook.cpp"     /* Anti-hooking measures */
#include "hook/plt_check.cpp"     /* PLT/GOT integrity */
#include "hook/art_hook.cpp"      /* ART method hooking for hollowed methods */
#include "utils/string_obfuscate.cpp" /* Encrypted strings */

/* Log macros using encrypted strings */
static char _log_tag_buf[32];
#define LOG_TAG str_get(STR_FP_LOG_TAG, _log_tag_buf, sizeof(_log_tag_buf))
#define LOGD(fmt, ...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, fmt, ##__VA_ARGS__)
#define LOGE(fmt, ...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, fmt, ##__VA_ARGS__)

/* Payload constants matching the Java PayloadFormat */
#define PAYLOAD_MAGIC_0 0x46  /* 'F' */
#define PAYLOAD_MAGIC_1 0x55  /* 'U' */
#define PAYLOAD_MAGIC_2 0x43  /* 'C' */
#define PAYLOAD_MAGIC_3 0x4B  /* 'K' */
#define PAYLOAD_HEADER_SIZE 18  /* Fixed header fields */
#define IV_SIZE 16

/* Flag bits (must match PayloadHeader.Flags in Kotlin) */
#define FLAG_SIGNATURE_VERIFICATION 0x04

/**
 * Decrypt RC4-encrypted sections of our own native library.
 *
 * The protector encrypts .bitcode/.rodata sections with RC4 and embeds
 * the key at a known location. This function:
 * 1. Finds our own library's base address
 * 2. Locates the RC4 key
 * 3. Decrypts the encrypted sections in-place
 */
static void decrypt_so_sections(void) {
    /* Get our own library's base address from /proc/self/maps */
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return;

    char line[512];
    uintptr_t our_base = 0;
    char our_path[512] = {0};

    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "libshell.so") && strstr(line, "r-xp")) {
            char *dash = strchr(line, '-');
            if (dash) {
                *dash = '\0';
                our_base = (uintptr_t)strtoul(line, NULL, 16);
                char *path_start = strchr(dash + 1, ' ');
                while (path_start && *path_start == ' ') path_start++;
                if (path_start) {
                    char *path_end = strchr(path_start, '\n');
                    if (path_end) *path_end = '\0';
                    strncpy(our_path, path_start, sizeof(our_path) - 1);
                }
            }
            break;
        }
    }
    fclose(fp);

    if (our_base == 0) return;

    /* Read the ELF header to find section headers */
    ElfW(Ehdr) *ehdr = (ElfW(Ehdr) *)our_base;
    if (ehdr->e_ident[0] != 0x7F || ehdr->e_ident[1] != 'E' ||
        ehdr->e_ident[2] != 'L' || ehdr->e_ident[3] != 'F') {
        return;
    }

    ElfW(Shdr) *shdr = (ElfW(Shdr) *)(our_base + ehdr->e_shoff);
    const char *shstrtab = (const char *)(our_base + shdr[ehdr->e_shstrndx].sh_offset);

    /* Find the RC4 key symbol */
    uint8_t rc4_key[16] = {0};
    int key_found = 0;

    for (int i = 0; i < ehdr->e_shnum; i++) {
        if (shdr[i].sh_type == SHT_SYMTAB || shdr[i].sh_type == SHT_DYNSYM) {
            ElfW(Sym) *symtab = (ElfW(Sym) *)(our_base + shdr[i].sh_offset);
            int num_syms = shdr[i].sh_size / shdr[i].sh_entsize;

            for (int j = 0; j < num_syms; j++) {
                const char *name = shstrtab + symtab[j].st_name;
                if (strstr(name, "g_dpt_rc4_key") || strstr(name, "rc4_key")) {
                    /* Found the key symbol — read the key from its location */
                    uint8_t *key_addr = (uint8_t *)(our_base + symtab[j].st_value);
                    memcpy(rc4_key, key_addr, 16);
                    key_found = 1;
                    break;
                }
            }
            if (key_found) break;
        }
    }

    if (!key_found) return;

    /* Decrypt encrypted sections */
    for (int i = 0; i < ehdr->e_shnum; i++) {
        const char *name = shstrtab + shdr[i].sh_name;

        if ((strcmp(name, ".bitcode") == 0 || strcmp(name, ".rodata") == 0) &&
            shdr[i].sh_flags & SHF_ALLOC &&
            shdr[i].sh_flags & SHF_EXECINSTR &&
            shdr[i].sh_size > 0) {

            uint8_t *section_addr = (uint8_t *)(our_base + shdr[i].sh_addr);

            /* Make section writable */
            uintptr_t page_start = section_addr & ~(sysconf(_SC_PAGE_SIZE) - 1);
            size_t page_size = sysconf(_SC_PAGE_SIZE);
            size_t num_pages = (shdr[i].sh_size / page_size) + 2;

            if (mprotect((void *)page_start, page_size * num_pages,
                         PROT_READ | PROT_WRITE | PROT_EXEC) == 0) {
                /* Decrypt in-place */
                rc4_inplace(rc4_key, 16, section_addr, shdr[i].sh_size);

                /* Restore permissions */
                mprotect((void *)page_start, page_size * num_pages,
                         PROT_READ | PROT_EXEC);
            }
        }
    }
}

/**
 * Read a 4-byte big-endian integer from the payload.
 */
static int read_int32_be(const uint8_t *buf) {
    return (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3];
}

/**
 * Parse the payload header and extract the encrypted DEX data.
 */
static int parse_payload(
    const uint8_t *payload, int payload_len,
    const uint8_t **out_dex, int *out_dex_len,
    int *out_flags
) {
    if (payload_len < PAYLOAD_HEADER_SIZE) {
        LOGE("Payload too small: %d bytes", payload_len);
        return -1;
    }

    if (payload[0] != PAYLOAD_MAGIC_0 || payload[1] != PAYLOAD_MAGIC_1 ||
        payload[2] != PAYLOAD_MAGIC_2 || payload[3] != PAYLOAD_MAGIC_3) {
        LOGE("Invalid payload magic: %02x%02x%02x%02x",
             payload[0], payload[1], payload[2], payload[3]);
        return -1;
    }

    int version = (payload[4] << 8) | payload[5];
    int flags = (payload[6] << 8) | payload[7];
    int dex_len = read_int32_be(payload + 8);
    int hollow_len = read_int32_be(payload + 12);
    int app_name_len = read_int32_be(payload + 16);

    LOGD("Payload v%d flags=0x%x dex_len=%d hollow=%d app_name=%d",
         version, flags, dex_len, hollow_len, app_name_len);

    if (dex_len <= 0 || payload_len < PAYLOAD_HEADER_SIZE + app_name_len + dex_len) {
        LOGE("Invalid payload lengths: app_name=%d dex_len=%d total=%d",
             app_name_len, dex_len, payload_len);
        return -1;
    }

    int dex_offset = PAYLOAD_HEADER_SIZE + app_name_len;
    *out_dex = payload + dex_offset;
    *out_dex_len = dex_len;
    *out_flags = flags;

    return 0;
}

/**
 * JNI: nativeInit(JNIEnv*, Context)
 *
 * Called from ShellApplication.attachBaseContext() BEFORE any decryption.
 * Performs: anti-debugging, signature verification, anti-hooking, integrity.
 */
JNIEXPORT void JNICALL
Java_com_fuckprotect_shell_ShellApplication_nativeInitWithContext(
    JNIEnv *env, jobject /*thiz*/, jobject context
) {
    LOGD("nativeInit: FuckProtect shell initializing...");

    /* ─── Step 1: Anti-debugging (T6.1-T6.5) ──────────────────────── */
    anti_debug_init();
    LOGD("nativeInit: anti-debugging checks passed");

    /* ─── Step 2: Signature verification (T7.3) ───────────────────── */
    jclass ctxClass = env->GetObjectClass(context);
    jmethodID getAssetsId = env->GetMethodID(
        ctxClass, "getAssets", "()Landroid/content/res/AssetManager;"
    );
    if (getAssetsId == NULL) { env->DeleteLocalRef(ctxClass); return; }

    jobject assetManager = env->CallObjectMethod(context, getAssetsId);
    if (assetManager == NULL) { env->DeleteLocalRef(ctxClass); return; }

    jclass amClass = env->GetObjectClass(assetManager);
    jmethodID openId = env->GetMethodID(
        amClass, "open", "(Ljava/lang/String;)Ljava/io/InputStream;"
    );
    jstring payloadName = env->NewStringUTF("fp_payload.dat");
    jobject inputStream = env->CallObjectMethod(assetManager, openId, payloadName);
    env->DeleteLocalRef(payloadName);
    env->DeleteLocalRef(amClass);
    env->DeleteLocalRef(assetManager);

    if (inputStream != NULL) {
        jclass isClass = env->GetObjectClass(inputStream);
        jmethodID availableId = env->GetMethodID(
            isClass, "available", "()I"
        );
        (void)env->CallIntMethod(inputStream, availableId);

        jbyteArray headerBuf = env->NewByteArray(18);
        jmethodID readId = env->GetMethodID(
            isClass, "read", "([BII)I"
        );
        env->CallIntMethod(inputStream, readId, headerBuf, 0, 18);
        jbyte *headerBytes = env->GetByteArrayElements(headerBuf, NULL);

        int flags = ((headerBytes[6] & 0xFF) << 8) | (headerBytes[7] & 0xFF);

        env->ReleaseByteArrayElements(headerBuf, headerBytes, JNI_ABORT);
        env->DeleteLocalRef(headerBuf);

        jmethodID closeId = env->GetMethodID(isClass, "close", "()V");
        env->CallVoidMethod(inputStream, closeId);
        env->DeleteLocalRef(isClass);
        env->DeleteLocalRef(inputStream);

        /* If signature verification flag is set, verify now */
        if (flags & FLAG_SIGNATURE_VERIFICATION) {
            LOGD("nativeInit: signature verification enabled, checking...");

            jclass svClass = env->FindClass(
                "com/fuckprotect/shell/integrity/SignatureVerifier"
            );
            if (svClass != NULL) {
                jmethodID getHashId = env->GetStaticMethodID(
                    svClass, "getCurrentCertHash",
                    "(Landroid/content/Context;)[B"
                );
                if (getHashId != NULL) {
                    jbyteArray currentHash = (jbyteArray)env->CallStaticObjectMethod(
                        svClass, getHashId, context
                    );
                    if (currentHash != NULL) {
                        jsize hashLen = env->GetArrayLength(currentHash);
                        if (hashLen == 32) {
                            jbyte *hashBytes = env->GetByteArrayElements(
                                currentHash, NULL
                            );
                            int result = verify_cert_hash((const uint8_t *)hashBytes);
                            env->ReleaseByteArrayElements(
                                currentHash, hashBytes, JNI_ABORT
                            );

                            if (!result) {
                                LOGE("nativeInit: SIGNATURE MISMATCH — exiting");
                                env->DeleteLocalRef(svClass);
                                _exit(1);
                            }
                            LOGD("nativeInit: signature verification passed");
                        }
                        env->DeleteLocalRef(currentHash);
                    }
                }
                env->DeleteLocalRef(svClass);
            }
        }
    }
    env->DeleteLocalRef(ctxClass);

    /* ─── Step 3: Anti-hooking (T9.1-T9.4) ────────────────────────── */
    anti_hook_init();
    LOGD("nativeInit: anti-hooking checks passed");

    /* ─── Step 4: PLT/GOT integrity (T9.1) ────────────────────────── */
    verify_plt_got_integrity();
    verify_function_not_hooked("dlopen");
    verify_function_not_hooked("dlsym");

    /* ─── Step 5: Native self-integrity (T9.3) ────────────────────── */
    verify_native_integrity();

    /* ─── Step 6: Start continuous monitoring (T11.1-T11.3) ───────── */
    response_action_t action = RESPONSE_EXIT;
    int enable_emulator = 0;
    monitor_start(action, enable_emulator);
    LOGD("nativeInit: continuous monitoring started");

    /* ─── Step 7: Create child monitor process ─────────────────────── */
    protect_process();
    LOGD("nativeInit: child process protection started");

    /* ─── Step 8: Decrypt native library sections ──────────────────── */
    decrypt_so_sections();
    LOGD("nativeInit: native library sections decrypted");

    /* ─── Step 9: Install ART method hooks ─────────────────────────── */
    hook_install_DefineClass();
    LOGD("nativeInit: ART method hooks installed");

    LOGD("nativeInit: all initialization checks passed");
}

/**
 * JNI: nativeInit() — legacy overload (anti-debugging only).
 */
JNIEXPORT void JNICALL
Java_com_fuckprotect_shell_ShellApplication_nativeInit(
    JNIEnv * /*env*/, jobject /*thiz*/
) {
    anti_debug_init();
}

/**
 * JNI: nativeDecryptDex(byte[] payload)
 *
 * Decrypts the DEX from the encrypted payload.
 */
JNIEXPORT jbyteArray JNICALL
Java_com_fuckprotect_shell_ShellApplication_nativeDecryptDex(
    JNIEnv *env, jobject /*thiz*/, jbyteArray payload
) {
    if (payload == NULL) {
        LOGE("nativeDecryptDex: null payload");
        return NULL;
    }

    jsize payload_len = env->GetArrayLength(payload);
    jbyte *payload_bytes = env->GetByteArrayElements(payload, NULL);
    if (payload_bytes == NULL) {
        LOGE("nativeDecryptDex: failed to get payload elements");
        return NULL;
    }

    const uint8_t *encrypted_dex = NULL;
    int encrypted_dex_len = 0;
    int flags = 0;

    if (parse_payload(
        (const uint8_t *)payload_bytes, payload_len,
        &encrypted_dex, &encrypted_dex_len, &flags
    ) != 0) {
        env->ReleaseByteArrayElements(payload, payload_bytes, JNI_ABORT);
        LOGE("nativeDecryptDex: payload parsing failed");
        return NULL;
    }

    if (encrypted_dex_len <= IV_SIZE) {
        env->ReleaseByteArrayElements(payload, payload_bytes, JNI_ABORT);
        LOGE("nativeDecryptDex: encrypted data too short: %d", encrypted_dex_len);
        return NULL;
    }

    const uint8_t *iv = encrypted_dex;
    const uint8_t *ciphertext = encrypted_dex + IV_SIZE;
    int ciphertext_len = encrypted_dex_len - IV_SIZE;

    uint8_t cert_hash[32];
    uint8_t aes_key[32];
    get_embedded_cert_hash(cert_hash);
    derive_aes_key(cert_hash, aes_key);

    uint8_t *decrypted = (uint8_t *)malloc(ciphertext_len);
    if (decrypted == NULL) {
        env->ReleaseByteArrayElements(payload, payload_bytes, JNI_ABORT);
        LOGE("nativeDecryptDex: malloc failed");
        return NULL;
    }

    uint8_t iv_copy[IV_SIZE];
    memcpy(iv_copy, iv, IV_SIZE);

    aes_cbc_decrypt(aes_key, iv_copy, ciphertext, decrypted, ciphertext_len);

    int plain_len = pkcs7_unpad(decrypted, ciphertext_len);
    if (plain_len < 0) {
        free(decrypted);
        env->ReleaseByteArrayElements(payload, payload_bytes, JNI_ABORT);
        LOGE("nativeDecryptDex: PKCS#7 unpadding failed");
        return NULL;
    }

    LOGD("nativeDecryptDex: decrypted %d bytes -> %d bytes (DEX)",
         ciphertext_len, plain_len);

    if (plain_len < 8 ||
        decrypted[0] != 'd' || decrypted[1] != 'e' ||
        decrypted[2] != 'x' || decrypted[3] != '\n') {
        LOGE("nativeDecryptDex: decrypted data doesn't look like DEX");
        memset(decrypted, 0, ciphertext_len);
        free(decrypted);
        env->ReleaseByteArrayElements(payload, payload_bytes, JNI_ABORT);
        return NULL;
    }

    jbyteArray result = env->NewByteArray(plain_len);
    if (result != NULL) {
        env->SetByteArrayRegion(result, 0, plain_len, (jbyte *)decrypted);
    }

    memset(decrypted, 0, ciphertext_len);
    free(decrypted);
    memset(aes_key, 0, sizeof(aes_key));
    memset(iv_copy, 0, sizeof(iv_copy));
    env->ReleaseByteArrayElements(payload, payload_bytes, JNI_ABORT);

    return result;
}

/* ─── Test helpers ──────────────────────────────────────────────────── */

JNIEXPORT void JNICALL
Java_com_fuckprotect_shell_antidbg_AntiDebugTestNative_nativeAntiDebugInit(
    JNIEnv * /*env*/, jobject /*thiz*/
) {
    anti_debug_init();
}

/* ─── ProxyComponentFactory native methods ─────────────────────────── */

/**
 * Get the original AppComponentFactory class name from payload metadata.
 * This is read from the payload's app class name field (same field as
 * Application class name — if it starts with a '.' it's an Application
 * class, otherwise it could be an AppComponentFactory).
 *
 * For now, we store this as a static variable set during nativeInit.
 */
static char g_originalComponentFactory[256] = {0};

JNIEXPORT jstring JNICALL
Java_com_fuckprotect_shell_factory_ProxyComponentFactory_getOriginalComponentFactory(
    JNIEnv *env, jclass /*clazz*/
) {
    if (g_originalComponentFactory[0] == '\0') {
        return NULL;
    }
    return env->NewStringUTF(g_originalComponentFactory);
}

JNIEXPORT jstring JNICALL
Java_com_fuckprotect_shell_factory_ProxyComponentFactory_getOriginalApplicationName(
    JNIEnv *env, jclass /*clazz*/
) {
    // Same as ShellApplication - read from stored value
    // For now, return NULL (the ProxyComponentFactory will use the className parameter)
    return NULL;
}

/**
 * Initialize the shell from ProxyComponentFactory.
 * This is the same as nativeInitWithContext but called from the factory.
 */
JNIEXPORT void JNICALL
Java_com_fuckprotect_shell_factory_ProxyComponentFactory_initShell(
    JNIEnv *env, jclass /*clazz*/
) {
    // Run anti-debugging and integrity checks
    anti_debug_init();
    anti_hook_init();
    verify_plt_got_integrity();
    verify_function_not_hooked("dlopen");
    verify_function_not_hooked("dlsym");
    verify_native_integrity();
}

/**
 * Replace the class loader — delegates to the same logic as ShellApplication.
 */
JNIEXPORT void JNICALL
Java_com_fuckprotect_shell_factory_ProxyComponentFactory_replaceClassLoader(
    JNIEnv * /*env*/, jclass /*clazz*/, jobject /*targetClassLoader*/
) {
    // This is handled by the existing ClassLoaderProxy Java class
    // The native side doesn't need to do anything here
}

/**
 * Set the original AppComponentFactory name (called from Java during initialization).
 */
JNIEXPORT void JNICALL
Java_com_fuckprotect_shell_factory_ProxyComponentFactory_nativeSetOriginalFactory(
    JNIEnv *env, jclass /*clazz*/, jstring factoryName
) {
    if (factoryName == NULL) {
        g_originalComponentFactory[0] = '\0';
        return;
    }

    const char *name = env->GetStringUTFChars(factoryName, NULL);
    if (name != NULL) {
        strncpy(g_originalComponentFactory, name, sizeof(g_originalComponentFactory) - 1);
        g_originalComponentFactory[sizeof(g_originalComponentFactory) - 1] = '\0';
        env->ReleaseStringUTFChars(factoryName, name);
    }
}
