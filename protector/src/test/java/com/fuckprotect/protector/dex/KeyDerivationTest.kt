package com.fuckprotect.protector.dex

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*

/**
 * Unit tests for KeyDerivation (T2.5 verification).
 */
class KeyDerivationTest {

    @Test
    fun `deriveFromCertBytes produces 32-byte key`() {
        val certBytes = "fake certificate data".toByteArray()
        val key = KeyDerivation.deriveFromCertBytes(certBytes)

        assertEquals(32, key.size)
    }

    @Test
    fun `deriveFromCertBytes is deterministic`() {
        val certBytes = "same certificate".toByteArray()

        val key1 = KeyDerivation.deriveFromCertBytes(certBytes)
        val key2 = KeyDerivation.deriveFromCertBytes(certBytes)

        assertArrayEquals(key1, key2)
    }

    @Test
    fun `different certs produce different keys`() {
        val certA = "certificate A".toByteArray()
        val certB = "certificate B".toByteArray()

        val keyA = KeyDerivation.deriveFromCertBytes(certA)
        val keyB = KeyDerivation.deriveFromCertBytes(certB)

        assertFalse(keyA.contentEquals(keyB))
    }

    @Test
    fun `sha256 produces correct hash size`() {
        val data = "test data".toByteArray()
        val hash = KeyDerivation.sha256(data)

        assertEquals(32, hash.size)
    }

    @Test
    fun `sha256 is deterministic`() {
        val data = "test data".toByteArray()

        val hash1 = KeyDerivation.sha256(data)
        val hash2 = KeyDerivation.sha256(data)

        assertArrayEquals(hash1, hash2)
    }

    @Test
    fun `toHexString produces valid hex string`() {
        val hash = ByteArray(32) { 0x1A.toByte() }
        val hex = KeyDerivation.toHexString(hash)

        assertEquals(64, hex.length)
        assertTrue(hex.all { it in '0'..'9' || it in 'a'..'f' })
    }

    @Test
    fun `toHexString matches known value`() {
        val input = byteArrayOf(0x00, 0x01, 0x02, 0x0F, 0x10, 0xFF.toByte())
        val hex = KeyDerivation.toHexString(input)

        assertEquals("0001020f10ff", hex)
    }
}
