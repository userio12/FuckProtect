package com.fuckprotect.protector.embedder

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.io.TempDir
import java.io.File

/**
 * Unit tests for SignatureEmbedder (T7.1/T7.2 verification).
 */
class SignatureEmbedderTest {

    private val embedder = SignatureEmbedder()

    @TempDir
    lateinit var tempDir: File

    @Test
    fun `embed replaces placeholder with cert hash`() {
        val certHash = ByteArray(32) { 0x42 }
        val soFile = createFakeSoWithPlaceholder()

        val result = embedder.embed(soFile, certHash)

        assertTrue(result)
        val data = soFile.readBytes()
        // Verify the placeholder was replaced
        val placeholder = "CERT_HASH_PLACEHOLDER".toByteArray(Charsets.US_ASCII)
        assertFalse(containsPattern(data, placeholder))
        // Verify the cert hash is present
        assertTrue(containsPattern(data, certHash.copyOfRange(0, 16)))
    }

    @Test
    fun `embed returns false when placeholder not found`() {
        val certHash = ByteArray(32) { 0x42 }
        val soFile = File(tempDir, "libshell.so").apply {
            writeBytes(ByteArray(1000) { 0x00 }) // No placeholder
        }

        val result = embedder.embed(soFile, certHash)

        assertFalse(result)
    }

    @Test
    fun `embed rejects wrong hash size`() {
        val badHash = ByteArray(16) { 0x42 } // Wrong size (should be 32)
        val soFile = createFakeSoWithPlaceholder()

        val ex = assertThrows(IllegalArgumentException::class.java) {
            embedder.embed(soFile, badHash)
        }
        assertTrue(ex.message?.contains("32 bytes") == true)
    }

    @Test
    fun `embedAll processes multiple ABI variants`() {
        val certHash = ByteArray(32) { it.toByte() }
        val libsDir = File(tempDir, "libs").apply { mkdirs() }

        // Create ABI subdirs with fake .so files
        for (abi in listOf("armeabi-v7a", "arm64-v8a", "x86", "x86_64")) {
            val abiDir = File(libsDir, abi).apply { mkdirs() }
            createFakeSoWithPlaceholder(abiDir)
        }

        // This should not crash
        embedder.embedAll(libsDir, certHash)

        // Verify all were processed
        for (abi in listOf("armeabi-v7a", "arm64-v8a", "x86", "x86_64")) {
            val soFile = File(libsDir, "$abi/libshell.so")
            assertTrue(soFile.exists())
        }
    }

    // ─── Helpers ─────────────────────────────────────────────────────

    private fun createFakeSoWithPlaceholder(dir: File? = null): File {
        val soFile = dir?.let { File(it, "libshell.so") }
            ?: File(tempDir, "libshell.so")

        val placeholder = "CERT_HASH_PLACEHOLDER".toByteArray(Charsets.US_ASCII)
        val data = ByteArray(2000)
        // Place placeholder at offset 1000
        System.arraycopy(placeholder, 0, data, 1000, placeholder.size)
        // Add ELF magic at start
        data[0] = 0x7F; data[1] = 'E'.code.toByte()
        data[2] = 'L'.code.toByte(); data[3] = 'F'.code.toByte()

        soFile.writeBytes(data)
        return soFile
    }

    private fun containsPattern(data: ByteArray, pattern: ByteArray): Boolean {
        for (i in 0..(data.size - pattern.size)) {
            var found = true
            for (j in pattern.indices) {
                if (data[i + j] != pattern[j]) {
                    found = false
                    break
                }
            }
            if (found) return true
        }
        return false
    }
}
