package com.fuckprotect.protector.util

import com.fuckprotect.common.Constants
import java.io.File

/**
 * Embeds the APK signing certificate hash into the compiled native
 * library (libshell.so) before it is packaged into the protected APK.
 *
 * The native library contains a placeholder pattern:
 *   "CERT_HASH_PLACEHOLDER" (32 bytes, padded with zeros)
 *
 * This class findsss the placeholder in the compiled .so binary and
 * replaces it with the actual SHA-256 hash of the signing certificate.
 *
 * This way, the native code can verify at runtime that the APK hasn't
 * been re-signed with a different key.
 */
class SignatureEmbedder {

    companion object {
        /** Placeholder string embedded in key_derive.c */
        private const val PLACEHOLDER = "CERT_HASH_PLACEHOLDER"

        /** Size of the SHA-256 hash in bytes */
        private const val HASH_SIZE = 32
    }

    /**
     * Embed the certificate hash into a compiled native library.
     *
     * @param soFile The compiled libshell.so file
     * @param certHash 32-byte SHA-256 of the signing certificate
     * @return true if embedding succeeded
     */
    fun embed(soFile: File, certHash: ByteArray): Boolean {
        require(soFile.exists()) { "Native library not found: ${soFile.absolutePath}" }
        require(certHash.size == HASH_SIZE) {
            "Certificate hash must be $HASH_SIZE bytes, got ${certHash.size}"
        }

        val data = soFile.readBytes()
        val placeholderBytes = PLACEHOLDER.toByteArray(Charsets.US_ASCII)

        /* Build a search pattern: the placeholder text padded with zeros to 32 bytes */
        val searchPattern = ByteArray(HASH_SIZE)
        System.arraycopy(placeholderBytes, 0, searchPattern, 0,
            minOf(placeholderBytes.size, HASH_SIZE))

        /* Search for the placeholder in the binary */
        val offset = findPattern(data, searchPattern)
        if (offset < 0) {
            /* Try searching for just the text without padding */
            val textOffset = findPattern(data, placeholderBytes)
            if (textOffset < 0) {
                System.err.println(
                    "WARNING: Could not find certificate hash placeholder in ${soFile.name}. " +
                    "Signature verification will use the default placeholder."
                )
                return false
            }
            replaceAt(data, textOffset, certHash)
        } else {
            replaceAt(data, offset, certHash)
        }

        soFile.writeBytes(data)
        return true
    }

    /**
     * Embed the certificate hash into all ABI variants of libshell.so.
     *
     * @param nativeLibsDir Directory containing ABI subdirs
     *   (armeabi-v7a/, arm64-v8a/, x86/, x86_64/)
     * @param certHash 32-byte SHA-256 of the signing certificate
     */
    fun embedAll(nativeLibsDir: File, certHash: ByteArray) {
        require(nativeLibsDir.exists() && nativeLibsDir.isDirectory) {
            "Native libs directory not found"
        }

        nativeLibsDir.listFiles()?.filter { it.isDirectory }?.forEach { abiDir ->
            val soFile = File(abiDir, "libshell.so")
            if (soFile.exists()) {
                val success = embed(soFile, certHash)
                println("  ${abiDir.name}/libshell.so: ${if (success) "OK" else "FAILED"}")
            }
        }
    }

    // ─── Private helpers ─────────────────────────────────────────────

    private fun findPattern(data: ByteArray, pattern: ByteArray): Int {
        if (pattern.isEmpty() || pattern.size > data.size) return -1

        for (i in 0..(data.size - pattern.size)) {
            var found = true
            for (j in pattern.indices) {
                if (data[i + j] != pattern[j]) {
                    found = false
                    break
                }
            }
            if (found) return i
        }
        return -1
    }

    private fun replaceAt(data: ByteArray, offset: Int, replacement: ByteArray) {
        val len = minOf(replacement.size, data.size - offset)
        System.arraycopy(replacement, 0, data, offset, len)
    }
}
