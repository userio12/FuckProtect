#pragma GCC diagnostic ignored "-Wunused-function"
/**
 * APK signature verification for FuckProtect shell.
 *
 * At runtime, computes SHA-256 of the current APK's signing certificate
 * and compares it with the hash embedded in the native library at
 * build time. Mismatch means the APK was re-signed with a different key.
 */

#include <jni.h>
#include <string.h>
#include <android/log.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "../crypto/key_derive.c"

#define SIG_TAG "FP_Signature"
#define SIG_LOG(fmt, ...) \
    __android_log_print(ANDROID_LOG_DEBUG, SIG_TAG, fmt, ##__VA_ARGS__)
#define SIG_LOG_ERR(fmt, ...) \
    __android_log_print(ANDROID_LOG_ERROR, SIG_TAG, fmt, ##__VA_ARGS__)

/**
 * Get the APK path from the process command line.
 *
 * @param env JNI environment
 * @param context Java Context object
 * @return APK path string (must be freed), or NULL on error
 */
static char *get_apk_path(JNIEnv *env, jobject context) {
    jclass ctxClass = env->GetObjectClass(context);
    jmethodID getApkPathId = env->GetMethodID(
        ctxClass, "getPackageResourcePath", "()Ljava/lang/String;"
    );
    if (getApkPathId == NULL) return NULL;

    jstring jPath = (jstring)env->CallObjectMethod(context, getApkPathId);
    if (jPath == NULL) return NULL;

    const char *cPath = env->GetStringUTFChars(jPath, NULL);
    char *result = strdup(cPath);
    env->ReleaseStringUTFChars(jPath, cPath);
    env->DeleteLocalRef(jPath);
    env->DeleteLocalRef(ctxClass);

    return result;
}

/**
 * Compute SHA-256 of the APK file.
 *
 * Note: This is a simplified implementation that hashes the entire APK
 * file. For production, a more sophisticated approach would hash only
 * the non-variable parts (excluding META-INF signatures, zip alignment
 * padding, etc.).
 *
 * @param apk_path Path to the APK file
 * @param hash_out Output buffer (32 bytes)
 * @return 0 on success, -1 on error
 */
static int compute_apk_hash(const char *apk_path, uint8_t *hash_out) {
    /* Use Java's MessageDigest for SHA-256 since implementing it in C
     * would add significant code size. Call from native via JNI. */
    (void)apk_path;
    (void)hash_out;
    /* TODO: Implement in Phase 3 — for now this is done from Java side */
    return -1;
}

/**
 * JNI: verifySignature(byte[] currentCertHash) -> boolean
 *
 * Called from Java SignatureVerifier. Compares the current APK's
 * signing certificate hash with the one embedded at build time.
 *
 * @param currentCertHash SHA-256 of current APK's signing certificate
 * @return JNI_TRUE if match, JNI_FALSE if mismatch
 */
JNIEXPORT jboolean JNICALL
Java_com_fuckprotect_shell_integrity_SignatureVerifier_nativeVerifySignature(
    JNIEnv *env, jclass /*clazz*/, jbyteArray currentCertHash
) {
    if (currentCertHash == NULL) {
        SIG_LOG_ERR("Null certificate hash");
        return JNI_FALSE;
    }

    jsize hashLen = env->GetArrayLength(currentCertHash);
    if (hashLen != 32) {
        SIG_LOG_ERR("Invalid certificate hash length: %d (expected 32)", hashLen);
        return JNI_FALSE;
    }

    jbyte *hashBytes = env->GetByteArrayElements(currentCertHash, NULL);
    if (hashBytes == NULL) return JNI_FALSE;

    /* Constant-time comparison */
    int result = verify_cert_hash((const uint8_t *)hashBytes);

    env->ReleaseByteArrayElements(currentCertHash, hashBytes, JNI_ABORT);

    if (result) {
        SIG_LOG("Signature verification PASSED");
    } else {
        SIG_LOG_ERR("Signature verification FAILED — APK may be tampered");
    }

    return result ? JNI_TRUE : JNI_FALSE;
}

/**
 * Get the embedded expected certificate hash.
 *
 * @return 32-byte jbyteArray with expected cert hash
 */
JNIEXPORT jbyteArray JNICALL
Java_com_fuckprotect_shell_integrity_SignatureVerifier_nativeGetExpectedHash(
    JNIEnv *env, jclass /*clazz*/
) {
    uint8_t hash[32];
    get_embedded_cert_hash(hash);

    jbyteArray result = env->NewByteArray(32);
    if (result != NULL) {
        env->SetByteArrayRegion(result, 0, 32, (jbyte *)hash);
    }
    return result;
}

/**
 * JNI: ApkIntegrity.nativeVerifyApkHash(byte[]) -> boolean
 *
 * Placeholder: full APK hash verification deferred to Phase 3.
 */
JNIEXPORT jboolean JNICALL
Java_com_fuckprotect_shell_integrity_ApkIntegrity_nativeVerifyApkHash(
    JNIEnv * /*env*/, jclass /*clazz*/, jbyteArray /*currentHash*/
) {
    return JNI_TRUE;
}
