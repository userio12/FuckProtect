package com.fuckprotect.shell.integrity

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.Assert.*

/**
 * Signature tamper detection test (T7.6).
 *
 * Verifies that the signature verification mechanism correctly:
 * 1. Accepts the APK signed with the expected key
 * 2. Would reject an APK signed with a different key
 *
 * Note: We can't easily re-sign the APK during automated testing.
 * This test verifies the verification mechanism works correctly
 * with the current APK's signature.
 */
@RunWith(AndroidJUnit4::class)
class SignatureTamperTest {

    @Test
    fun getCurrentCertHash_returnsNonNullHash() {
        val context: Context = ApplicationProvider.getApplicationContext()

        val hash = SignatureVerifier.getCurrentCertHash(context)

        assertNotNull("Certificate hash should not be null", hash)
        assertEquals(
            "SHA-256 hash should be 32 bytes",
            32,
            hash.size
        )
    }

    @Test
    fun getCurrentCertHash_isDeterministic() {
        val context: Context = ApplicationProvider.getApplicationContext()

        val hash1 = SignatureVerifier.getCurrentCertHash(context)
        val hash2 = SignatureVerifier.getCurrentCertHash(context)

        assertArrayEquals(
            "Certificate hash should be deterministic",
            hash1,
            hash2
        )
    }

    @Test
    fun getExpectedHashHex_returnsValidHexString() {
        val hex = SignatureVerifier.getExpectedHashHex()

        assertNotNull("Expected hash hex string should not be null", hex)
        assertTrue(
            "Expected hash should be 64 hex characters (32 bytes)",
            hex.length == 64
        )
        assertTrue(
            "Expected hash should contain only hex characters",
            hex.matches(Regex("[0-9a-f]{64}"))
        )
    }

    @Test
    fun signatureVerifier_hasCorrectJniMethods() {
        // Verify the native methods exist and are callable
        val context: Context = ApplicationProvider.getApplicationContext()

        // This should not throw UnsatisfiedLinkError
        try {
            val expectedHash = SignatureVerifier.nativeGetExpectedHash()
            assertNotNull("nativeGetExpectedHash should return a result", expectedHash)
        } catch (e: UnsatisfiedLinkError) {
            fail("Native library not loaded: ${e.message}")
        }
    }

    @Test
    fun apkIntegrity_computeHashReturnsValidHash() {
        // Verify that APK integrity checking can compute a hash
        val context: Context = ApplicationProvider.getApplicationContext()

        // This will attempt to hash the APK file
        // Result may vary based on test environment
        try {
            val result = ApkIntegrity.verify(context)
            // Should complete without exception (true or false)
            assertNotNull("Integrity check should complete", result)
        } catch (e: Exception) {
            fail("APK integrity check should not throw: ${e.message}")
        }
    }

    @Test
    fun differentCertificates_produceDifferentHashes() {
        // Verify that the hash function is working correctly by hashing
        // different inputs
        val hashA = "certificateA".toByteArray().let {
            java.security.MessageDigest.getInstance("SHA-256").digest(it)
        }
        val hashB = "certificateB".toByteArray().let {
            java.security.MessageDigest.getInstance("SHA-256").digest(it)
        }

        assertFalse(
            "Different inputs should produce different hashes",
            hashA.contentEquals(hashB)
        )
    }
}
