package com.fuckprotect.common

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*

/**
 * Unit tests for Constants and CryptoParams (T1.6, T1.8 verification).
 */
class ConstantsTest {

    @Test
    fun `MAGIC is correct bytes`() {
        val expected = byteArrayOf(0x46, 0x55, 0x43, 0x4B) // "FUCK"
        assertArrayEquals(expected, Constants.MAGIC)
    }

    @Test
    fun `MAGIC decodes to readable string`() {
        assertEquals("FUCK", Constants.MAGIC.decodeToString())
    }

    @Test
    fun `VERSION is 1`() {
        assertEquals(1, Constants.VERSION.toInt())
    }

    @Test
    fun `ALGORITHM_AES is valid cipher string`() {
        assertEquals("AES/CBC/PKCS5Padding", Constants.ALGORITHM_AES)
    }

    @Test
    fun `KEY_SIZE is 256 bits (32 bytes)`() {
        assertEquals(256, Constants.KEY_SIZE_BITS)
        assertEquals(32, Constants.KEY_SIZE_BYTES)
    }

    @Test
    fun `IV_SIZE is 16 bytes`() {
        assertEquals(16, Constants.IV_SIZE_BYTES)
    }

    @Test
    fun `SHA256_SIZE is 32 bytes`() {
        assertEquals(32, Constants.SHA256_SIZE_BYTES)
    }

    @Test
    fun `CRC32_SIZE is 4 bytes`() {
        assertEquals(4, Constants.CRC32_SIZE_BYTES)
    }

    @Test
    fun `shell Application class name is valid`() {
        assertEquals(
            "com.fuckprotect.shell.ShellApplication",
            Constants.SHELL_APPLICATION_CLASS
        )
    }

    @Test
    fun `payload asset name is valid`() {
        assertEquals("fp_payload.dat", Constants.PAYLOAD_ASSET_NAME)
    }
}
