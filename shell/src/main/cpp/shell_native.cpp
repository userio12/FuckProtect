/**
 * JNI entry point for the FuckProtect shell native library.
 *
 * This file bridges the Java ShellApplication class with native
 * crypto, anti-debugging, and integrity functions.
 */

#include <jni.h>
#include <string.h>
#include <stdlib.h>
#include <android/log.h>

#include "crypto/aes.c"           /* AES-256-CBC + PKCS#7 */
#include "crypto/key_derive.c"    /* Key derivation + cert hash verification */
#include "antidbg/anti_debug.cpp" /* Anti-debugging checks */
#include "antidbg/continuous_monitor.cpp" /* Continuous monitoring + emulator detect */
#include "integrity/self_check.cpp"   /* Signature / APK integrity */
#include "integrity/self_integrity.cpp" /* Native self-integrity */
#include "hook/anti_hook.cpp"     /* Anti-hooking measures */
#include "hook/plt_check.cpp"     /* PLT/GOT integrity */
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
 * Read a 4-byte big-endian integer from the payload.
 */
static int read_int32_be(const uint8_t *buf) {
    return (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3];
}

/**
 * Parse the payload header and extract the encrypted DEX data.
 *
 * Payload format:
 *   [Magic 4][Version 2][Flags 2][DexLen 4][HollowLen 4][AppNameLen 4]
 *   [AppName variable]
 *   [EncryptedDex variable (IV + ciphertext)]
 *
 * @param payload      Full payload bytes
 * @param payload_len  Payload length
 * @param out_dex      Output: pointer to encrypted DEX data (IV + ciphertext)
 * @param out_dex_len  Output: length of encrypted DEX data
 * @param out_flags    Output: payload flags
 * @return 0 on success, -1 on error
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

    /* Verify magic */
    if (payload[0] != PAYLOAD_MAGIC_0 || payload[1] != PAYLOAD_MAGIC_1 ||
        payload[2] != PAYLOAD_MAGIC_2 || payload[3] != PAYLOAD_MAGIC_3) {
        LOGE("Invalid payload magic: %02x%02x%02x%02x",
             payload[0], payload[1], payload[2], payload[3]);
        return -1;
    }

    /* Read header fields */
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

    /* Encrypted DEX starts after header + app name */
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
 * Performs:
 *  1. Anti-debugging checks (all 6 checks)
 *  2. APK signature verification (if flag is set)
 *
 * @param context Java Context object (for APK path resolution)
 */
JNIEXPORT void JNICALL
Java_com_fuckprotect_shell_ShellApplication_nativeInitWithContext(
    JNIEnv *env, jobject thiz, jobject context
) {
    LOGD("nativeInit: FuckProtect shell initializing...");

    /* ─── Step 1: Anti-debugging (T6.1-T6.5) ──────────────────────── */
    anti_debug_init();
    LOGD("nativeInit: anti-debugging checks passed");

    /* ─── Step 2: Signature verification (T7.3) ───────────────────── */
    /* Read the flags from the payload to check if signature verification
     * is enabled. We need to re-read the payload for this. */

    /* Read payload from assets */
    jclass ctxClass = (*env)->GetObjectClass(env, context);
    jmethodID getAssetsId = (*env)->GetMethodID(
        env, ctxClass, "getAssets", "()Landroid/content/res/AssetManager;"
    );
    if (getAssetsId == NULL) return;

    jobject assetManager = (*env)->CallObjectMethod(env, context, getAssetsId);
    if (assetManager == NULL) return;

    /* Open fp_payload.dat */
    jclass amClass = (*env)->GetObjectClass(env, assetManager);
    jmethodID openId = (*env)->GetMethodID(
        env, amClass, "open", "(Ljava/lang/String;)Ljava/io/InputStream;"
    );
    jstring payloadName = (*env)->NewStringUTF(env, "fp_payload.dat");
    jobject inputStream = (*env)->CallObjectMethod(env, assetManager, openId, payloadName);
    (*env)->DeleteLocalRef(env, payloadName);

    if (inputStream != NULL) {
        /* Read available bytes to get header */
        jclass isClass = (*env)->GetObjectClass(env, inputStream);
        jmethodID availableId = (*env)->GetMethodID(
            env, isClass, "available", "()I"
        );
        jint available = (*env)->CallIntMethod(env, inputStream, availableId);

        /* We only need the first 18 bytes for flags */
        jbyteArray headerBuf = (*env)->NewByteArray(env, 18);
        jbyte *headerBytes = (*env)->GetByteArrayElements(env, headerBuf, NULL);

        /* Read header bytes */
        jmethodID readId = (*env)->GetMethodID(
            env, isClass, "read", "([BII)I"
        );
        (*env)->CallIntMethod(env, inputStream, readId, headerBuf, 0, 18);
        headerBytes = (*env)->GetByteArrayElements(env, headerBuf, NULL);

        /* Extract flags (offset 6, 2 bytes big-endian) */
        int flags = ((headerBytes[6] & 0xFF) << 8) | (headerBytes[7] & 0xFF);

        (*env)->ReleaseByteArrayElements(env, headerBuf, headerBytes, JNI_ABORT);
        (*env)->DeleteLocalRef(env, headerBuf);

        /* Close stream */
        jmethodID closeId = (*env)->GetMethodID(env, isClass, "close", "()V");
        (*env)->CallVoidMethod(env, inputStream, closeId);

        /* If signature verification flag is set, verify now */
        if (flags & FLAG_SIGNATURE_VERIFICATION) {
            LOGD("nativeInit: signature verification enabled, checking...");

            /* Get current cert hash from Java */
            jclass svClass = (*env)->FindClass(
                env, "com/fuckprotect/shell/integrity/SignatureVerifier"
            );
            if (svClass != NULL) {
                jmethodID getHashId = (*env)->GetStaticMethodID(
                    env, svClass, "getCurrentCertHash",
                    "(Landroid/content/Context;)[B"
                );
                if (getHashId != NULL) {
                    jbyteArray currentHash = (jbyteArray)(*env)->CallStaticObjectMethod(
                        env, svClass, getHashId, context
                    );
                    if (currentHash != NULL) {
                        jsize hashLen = (*env)->GetArrayLength(env, currentHash);
                        if (hashLen == 32) {
                            jbyte *hashBytes = (*env)->GetByteArrayElements(
                                env, currentHash, NULL
                            );
                            int result = verify_cert_hash((const uint8_t *)hashBytes);
                            (*env)->ReleaseByteArrayElements(
                                env, currentHash, hashBytes, JNI_ABORT
                            );

                            if (!result) {
                                LOGE("nativeInit: SIGNATURE MISMATCH — exiting");
                                _exit(1);
                            }
                            LOGD("nativeInit: signature verification passed");
                        }
                    }
                }
                (*env)->DeleteLocalRef(env, svClass);
            }
        }
    }

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
    /* Default: exit on detection. In silent defense mode, use corrupt/delay. */
    response_action_t action = RESPONSE_EXIT;
    int enable_emulator = 0;  /* Set from config in production */

    /* Check payload flags for silent defense mode */
    /* In production: read from protector config embedded in payload */
    monitor_start(action, enable_emulator);
    LOGD("nativeInit: continuous monitoring started");

    LOGD("nativeInit: all initialization checks passed");
}

/**
 * JNI: nativeInit() — legacy overload (calls the context version with null).
 *
 * Anti-debugging only, no signature verification (requires context).
 */
JNIEXPORT void JNICALL
Java_com_fuckprotect_shell_ShellApplication_nativeInit(
    JNIEnv *env, jobject thiz
) {
    LOGD("nativeInit: FuckProtect shell initializing (no-context)...");
    anti_debug_init();
    LOGD("nativeInit: anti-debugging checks passed");
}

/**
 * JNI: nativeDecryptDex(byte[] payload)
 *
 * Decrypts the DEX from the encrypted payload.
 *
 * @param payload Full encrypted payload (header + app name + IV + ciphertext)
 * @return Decrypted DEX bytes
 */
JNIEXPORT jbyteArray JNICALL
Java_com_fuckprotect_shell_ShellApplication_nativeDecryptDex(
    JNIEnv *env, jobject thiz, jbyteArray payload
) {
    if (payload == NULL) {
        LOGE("nativeDecryptDex: null payload");
        return NULL;
    }

    /* Get payload bytes */
    jsize payload_len = (*env)->GetArrayLength(env, payload);
    jbyte *payload_bytes = (*env)->GetByteArrayElements(env, payload, NULL);
    if (payload_bytes == NULL) {
        LOGE("nativeDecryptDex: failed to get payload elements");
        return NULL;
    }

    const uint8_t *encrypted_dex = NULL;
    int encrypted_dex_len = 0;
    int flags = 0;

    /* Parse payload to extract encrypted DEX section */
    if (parse_payload(
        (const uint8_t *)payload_bytes, payload_len,
        &encrypted_dex, &encrypted_dex_len, &flags
    ) != 0) {
        (*env)->ReleaseByteArrayElements(env, payload, payload_bytes, JNI_ABORT);
        LOGE("nativeDecryptDex: payload parsing failed");
        return NULL;
    }

    /* The first 16 bytes of encrypted_dex are the IV */
    if (encrypted_dex_len <= IV_SIZE) {
        (*env)->ReleaseByteArrayElements(env, payload, payload_bytes, JNI_ABORT);
        LOGE("nativeDecryptDex: encrypted data too short: %d", encrypted_dex_len);
        return NULL;
    }

    const uint8_t *iv = encrypted_dex;
    const uint8_t *ciphertext = encrypted_dex + IV_SIZE;
    int ciphertext_len = encrypted_dex_len - IV_SIZE;

    /* Get the embedded cert hash to derive the AES key */
    uint8_t cert_hash[32];
    uint8_t aes_key[32];
    get_embedded_cert_hash(cert_hash);
    derive_aes_key(cert_hash, aes_key);

    /* Decrypt: allocate output buffer */
    uint8_t *decrypted = (uint8_t *)malloc(ciphertext_len);
    if (decrypted == NULL) {
        (*env)->ReleaseByteArrayElements(env, payload, payload_bytes, JNI_ABORT);
        LOGE("nativeDecryptDex: malloc failed");
        return NULL;
    }

    /* Copy IV so it can be modified by the decrypt function */
    uint8_t iv_copy[IV_SIZE];
    memcpy(iv_copy, iv, IV_SIZE);

    /* AES-256-CBC decrypt */
    aes_cbc_decrypt(aes_key, iv_copy, ciphertext, decrypted, ciphertext_len);

    /* Remove PKCS#7 padding */
    int plain_len = pkcs7_unpad(decrypted, ciphertext_len);
    if (plain_len < 0) {
        free(decrypted);
        (*env)->ReleaseByteArrayElements(env, payload, payload_bytes, JNI_ABORT);
        LOGE("nativeDecryptDex: PKCS#7 unpadding failed");
        return NULL;
    }

    LOGD("nativeDecryptDex: decrypted %d bytes -> %d bytes (DEX)",
         ciphertext_len, plain_len);

    /* Verify DEX magic */
    if (plain_len < 8 ||
        decrypted[0] != 'd' || decrypted[1] != 'e' ||
        decrypted[2] != 'x' || decrypted[3] != '\n') {
        LOGE("nativeDecryptDex: decrypted data doesn't look like DEX");
        /* Wipe and return NULL — wrong key or corrupted */
        memset(decrypted, 0, ciphertext_len);
        free(decrypted);
        (*env)->ReleaseByteArrayElements(env, payload, payload_bytes, JNI_ABORT);
        return NULL;
    }

    /* Create Java byte array with the decrypted DEX */
    jbyteArray result = (*env)->NewByteArray(env, plain_len);
    if (result != NULL) {
        (*env)->SetByteArrayRegion(env, result, 0, plain_len, (jbyte *)decrypted);
    }

    /* Clean up: wipe sensitive data */
    memset(decrypted, 0, ciphertext_len);
    free(decrypted);
    memset(aes_key, 0, sizeof(aes_key));
    memset(iv_copy, 0, sizeof(iv_copy));
    (*env)->ReleaseByteArrayElements(env, payload, payload_bytes, JNI_ABORT);

    return result;
}

/* ─── Test helpers ──────────────────────────────────────────────────── */

/**
 * JNI: AntiDebugTestNative.nativeAntiDebugInit()
 *
 * Exposes anti_debug_init() for instrumented testing.
 */
JNIEXPORT void JNICALL
Java_com_fuckprotect_shell_antidbg_AntiDebugTestNative_nativeAntiDebugInit(
    JNIEnv *env, jobject thiz
) {
    (void)env;
    (void)thiz;
    anti_debug_init();
}
