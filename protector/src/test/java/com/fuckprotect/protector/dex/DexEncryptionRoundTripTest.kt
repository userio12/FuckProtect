package com.fuckprotect.protector.dex

import com.fuckprotect.common.Constants
import com.fuckprotect.common.PayloadFormat
import com.fuckprotect.common.PayloadHeader
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream

/**
 * Integration tests for encryption round-trip (T2.7).
 *
 * Verifies: DEX bytes → encrypt → build payload → parse → decrypt →
 * result matches original DEX bytes.
 */
class DexEncryptionRoundTripTest {

    private val encryptor = DexEncryptor()

    @Test
    fun `encrypt then decrypt returns original data`() {
        val originalData = "This is fake DEX content for testing".toByteArray()
        val key = ByteArray(32) { (it % 256).toByte() } // Deterministic key for testing

        val encrypted = encryptor.encrypt(originalData, key)
        val decrypted = encryptor.decrypt(encrypted.data, key)

        assertArrayEquals(originalData, decrypted)
    }

    @Test
    fun `encrypt produces different ciphertext with different IV`() {
        val originalData = "Same data twice".toByteArray()
        val key = ByteArray(32) { 0x42 }

        val enc1 = encryptor.encrypt(originalData, key)
        val enc2 = encryptor.encrypt(originalData, key)

        // Same key, different random IV → different ciphertext
        assertFalse(enc1.data.contentEquals(enc2.data))

        // But both decrypt to the same plaintext
        val dec1 = encryptor.decrypt(enc1.data, key)
        val dec2 = encryptor.decrypt(enc2.data, key)
        assertArrayEquals(dec1, dec2)
    }

    @Test
    fun `decrypt with wrong key fails`() {
        val originalData = "Secret DEX data".toByteArray()
        val correctKey = ByteArray(32) { 0x55 }
        val wrongKey = ByteArray(32) { 0xAA }

        val encrypted = encryptor.encrypt(originalData, correctKey)

        // Decrypting with wrong key produces garbage (or throws on padding error)
        assertThrows(javax.crypto.BadPaddingException::class.java) {
            encryptor.decrypt(encrypted.data, wrongKey)
        }
    }

    @Test
    fun `payload roundtrip: build → parse → decrypt`() {
        val originalDex = createFakeDexBytes()
        val key = ByteArray(32) { it.toByte() }
        val appClassName = "com.example.TestApplication"

        // Step 1: Encrypt
        val encrypted = encryptor.encrypt(originalDex, key)

        // Step 2: Build payload
        val payload = PayloadBuilder()
            .setOriginalAppClass(appClassName)
            .setEncryptedDexData(encrypted.data)
            .enableNativeProtection()
            .build()

        // Step 3: Parse payload
        val bais = ByteArrayInputStream(payload)
        val dis = DataInputStream(bais)
        val header = PayloadFormat.readHeader(dis)

        assertEquals(PayloadHeader.MAGIC.copyOf(), header.magic)
        assertEquals(appClassName.length, header.originalAppClassNameLength)
        assertEquals(encrypted.data.size, header.encryptedDexLength)

        val appName = PayloadFormat.readString(dis)
        assertEquals(appClassName, appName)

        // Read encrypted DEX data
        val encryptedDexData = ByteArray(header.encryptedDexLength)
        dis.readFully(encryptedDexData)

        // Read CRC footer
        val crcFooter = ByteArray(Constants.CRC32_SIZE_BYTES)
        dis.readFully(crcFooter)

        // Step 4: Decrypt
        val decrypted = encryptor.decrypt(encryptedDexData, key)

        // Step 5: Verify
        assertArrayEquals(originalDex, decrypted)
    }

    @Test
    fun `encrypted payload has IV prepended`() {
        val data = "test".toByteArray()
        val key = ByteArray(32) { 0x11 }

        val encrypted = encryptor.encrypt(data, key)

        // Payload should be IV (16 bytes) + ciphertext
        assertTrue(encrypted.data.size > Constants.IV_SIZE_BYTES)
        assertEquals(Constants.IV_SIZE_BYTES + data.size + 16, encrypted.data.size)
        // +16 because PKCS#7 pads "test" (4 bytes) to 16 bytes
    }

    @Test
    fun `CryptoParams copy is independent`() {
        val key = ByteArray(32) { 0x42 }
        val iv = ByteArray(16) { 0x33 }
        val params = com.fuckprotect.common.CryptoParams(key, iv)

        val copy = params.copy()

        assertArrayEquals(params.key, copy.key)
        assertArrayEquals(params.iv, copy.iv)

        // Modifying copy doesn't affect original
        copy.key[0] = 0x00
        assertEquals(0x42.toByte(), params.key[0])
    }

    @Test
    fun `CryptoParams destroy zeros out key material`() {
        val key = ByteArray(32) { 0x42 }
        val iv = ByteArray(16) { 0x33 }
        val params = com.fuckprotect.common.CryptoParams(key, iv)

        params.destroy()

        assertTrue(params.key.all { it == 0.toByte() })
        assertTrue(params.iv.all { it == 0.toByte() })
    }

    @Test
    fun `PayloadFormat CRC32 roundtrip`() {
        val data = "test data for CRC".toByteArray()
        val crc = PayloadFormat.computeCrc32(data)

        assertTrue(PayloadFormat.verifyCrc32(data, crc))

        // Modified data should fail
        val modified = data.copyOf()
        modified[0] = (modified[0] + 1).toByte()
        assertFalse(PayloadFormat.verifyCrc32(modified, crc))
    }

    @Test
    fun `PayloadFormat string roundtrip`() {
        val baos = ByteArrayOutputStream()
        val dos = DataOutputStream(baos)

        val testStrings = listOf(
            "com.example.MyApp",
            "",
            "a",
            "Hello, 世界",  // Unicode
        )

        for (s in testStrings) {
            PayloadFormat.writeString(dos, s)
        }

        val bais = ByteArrayInputStream(baos.toByteArray())
        val dis = DataInputStream(bais)

        for (s in testStrings) {
            val read = PayloadFormat.readString(dis)
            assertEquals(s, read)
        }
    }

    // ─── Helpers ─────────────────────────────────────────────────────

    private fun createFakeDexBytes(): ByteArray {
        // Create a minimal fake DEX-like byte array
        val baos = ByteArrayOutputStream()
        val dos = DataOutputStream(baos)

        // DEX magic "dex\n037\0"
        dos.write(byteArrayOf(0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x37, 0x00))
        // Some fake DEX content
        dos.write("FAKE DEX CONTENT FOR ROUND-TRIP TESTING".toByteArray())
        // Pad to make it look somewhat realistic
        dos.write(ByteArray(200) { (it % 128).toByte() })

        return baos.toByteArray()
    }
}
