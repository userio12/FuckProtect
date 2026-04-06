package com.fuckprotect.protector.dex

import com.fuckprotect.common.Constants
import com.fuckprotect.common.PayloadFormat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*
import java.io.ByteArrayInputStream
import java.io.DataInputStream

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
        val key = ByteArray(32) { 0x42.toByte() }

        val encrypted = encryptor.encrypt(originalData, key)
        val decrypted = encryptor.decrypt(encrypted.data, key)

        assertArrayEquals(originalData, decrypted)
    }

    @Test
    fun `encrypt produces different ciphertext with different IV`() {
        val originalData = "Same data twice".toByteArray()
        val key = ByteArray(32) { 0x42.toByte() }

        val enc1 = encryptor.encrypt(originalData, key)
        val enc2 = encryptor.encrypt(originalData, key)

        assertFalse(enc1.data.contentEquals(enc2.data))

        val dec1 = encryptor.decrypt(enc1.data, key)
        val dec2 = encryptor.decrypt(enc2.data, key)
        assertArrayEquals(dec1, dec2)
    }

    @Test
    fun `decrypt with wrong key fails`() {
        val originalData = "Secret DEX data".toByteArray()
        val correctKey = ByteArray(32) { 0x55.toByte() }
        val wrongKey = ByteArray(32) { 0xAA.toByte() }

        val encrypted = encryptor.encrypt(originalData, correctKey)

        assertThrows(javax.crypto.BadPaddingException::class.java) {
            encryptor.decrypt(encrypted.data, wrongKey)
        }
    }

    @Test
    fun `payload roundtrip build parse decrypt`() {
        val originalDex = createFakeDexBytes()
        val key = ByteArray(32) { it.toByte() }
        val appClassName = "com.example.TestApplication"

        val encrypted = encryptor.encrypt(originalDex, key)

        val payload = PayloadBuilder()
            .setOriginalAppClass(appClassName)
            .setEncryptedDexData(encrypted.data)
            .enableNativeProtection()
            .build()

        val bais = ByteArrayInputStream(payload)
        val dis = DataInputStream(bais)
        val header = PayloadFormat.readHeader(dis)

        assertArrayEquals(Constants.MAGIC, header.magic)
        assertEquals(appClassName.length, header.originalAppClassNameLength)
        assertEquals(encrypted.data.size, header.encryptedDexLength)

        val appName = PayloadFormat.readString(dis)
        assertEquals(appClassName, appName)

        val encryptedDexData = ByteArray(header.encryptedDexLength)
        dis.readFully(encryptedDexData)

        val crcFooter = ByteArray(Constants.CRC32_SIZE_BYTES)
        dis.readFully(crcFooter)

        val decrypted = encryptor.decrypt(encryptedDexData, key)

        assertArrayEquals(originalDex, decrypted)
    }

    @Test
    fun `encrypted payload has IV prepended`() {
        val data = "test".toByteArray()
        val key = ByteArray(32) { 0x11.toByte() }

        val encrypted = encryptor.encrypt(data, key)

        // Payload = IV (16) + ciphertext (PKCS7 pads 4→16) = 32
        assertTrue(encrypted.data.size > Constants.IV_SIZE_BYTES)
        assertEquals(Constants.IV_SIZE_BYTES + 16, encrypted.data.size)
    }

    @Test
    fun `CryptoParams copy is independent`() {
        val key = ByteArray(32) { 0x42.toByte() }
        val iv = ByteArray(16) { 0x33.toByte() }
        val params = com.fuckprotect.common.CryptoParams(key, iv)

        val copy = params.copy()

        assertArrayEquals(params.key, copy.key)
        assertArrayEquals(params.iv, copy.iv)

        copy.key[0] = 0x00.toByte()
        assertEquals(0x42.toByte(), params.key[0])
    }

    @Test
    fun `CryptoParams destroy zeros out key material`() {
        val key = ByteArray(32) { 0x42.toByte() }
        val iv = ByteArray(16) { 0x33.toByte() }
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

        val modified = data.copyOf()
        modified[0] = (modified[0] + 1).toByte()
        assertFalse(PayloadFormat.verifyCrc32(modified, crc))
    }

    @Test
    fun `PayloadFormat string roundtrip`() {
        val baos = java.io.ByteArrayOutputStream()
        val dos = java.io.DataOutputStream(baos)

        val testStrings = listOf(
            "com.example.MyApp",
            "",
            "a",
            "Hello, 世界",
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

    private fun createFakeDexBytes(): ByteArray {
        val baos = java.io.ByteArrayOutputStream()
        val dos = java.io.DataOutputStream(baos)

        dos.write(byteArrayOf(0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x37, 0x00))
        dos.write("FAKE DEX CONTENT FOR ROUND-TRIP TESTING".toByteArray())
        dos.write(ByteArray(200) { (it % 128).toByte() })

        return baos.toByteArray()
    }
}
