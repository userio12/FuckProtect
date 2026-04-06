package com.fuckprotect.protector.dex

import com.fuckprotect.common.Constants
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Unit tests for DexParser (T2.3).
 *
 * Since we don't have a real DEX file in the test classpath,
 * these tests construct synthetic DEX byte arrays.
 */
class DexParserTest {

    private val parser = DexParser()

    @Test
    fun `isValidMagic accepts dex 035`() {
        val magic = byteArrayOf(0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x35, 0x00)
        assertTrue(DexHeader.isValidMagic(magic))
    }

    @Test
    fun `isValidMagic accepts dex 037`() {
        val magic = byteArrayOf(0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x37, 0x00)
        assertTrue(DexHeader.isValidMagic(magic))
    }

    @Test
    fun `isValidMagic accepts dex 038`() {
        val magic = byteArrayOf(0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x38, 0x00)
        assertTrue(DexHeader.isValidMagic(magic))
    }

    @Test
    fun `isValidMagic accepts dex 039`() {
        val magic = byteArrayOf(0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x39, 0x00)
        assertTrue(DexHeader.isValidMagic(magic))
    }

    @Test
    fun `isValidMagic rejects invalid magic`() {
        val magic = byteArrayOf(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
        assertFalse(DexHeader.isValidMagic(magic))
    }

    @Test
    fun `isValidMagic rejects short array`() {
        val magic = byteArrayOf(0x64, 0x65, 0x78)
        assertFalse(DexHeader.isValidMagic(magic))
    }

    @Test
    fun `parseHeaderOnly reads valid DEX header`() {
        val dexBytes = createMinimalDex037()
        val header = parser.parseHeaderOnly(dexBytes)

        assertEquals("037", header.version)
        assertEquals(0x70, header.headerSize)
        assertTrue(DexHeader.isValidMagic(header.magic))
        assertEquals(0x12345678, header.endianTag)
    }

    @Test
    fun `parseHeaderOnly detects invalid header`() {
        val badBytes = ByteArray(112) // All zeros
        val header = parser.parseHeaderOnly(badBytes)
        assertFalse(header.isValid)
    }

    @Test
    fun `parse rejects file too small`() {
        val smallBytes = ByteArray(50)
        val ex = assertThrows(IllegalArgumentException::class.java) {
            parser.parse(smallBytes)
        }
        assertTrue(ex.message?.contains("too small") == true)
    }

    @Test
    fun `parse reads method IDs count`() {
        val dexBytes = createDexWithMethods(5)
        val dexFile = parser.parse(dexBytes)

        assertEquals(5, dexFile.methodIds.size)
    }

    @Test
    fun `parse reads class defs count`() {
        val dexBytes = createDexWithClasses(3)
        val dexFile = parser.parse(dexBytes)

        assertEquals(3, dexFile.classDefs.size)
    }

    @Test
    fun `parse detects DEX version 035`() {
        val dexBytes = createMinimalDex035()
        val dexFile = parser.parse(dexBytes)

        assertEquals("035", dexFile.version)
        assertTrue(dexFile.isValid)
    }

    @Test
    fun `parse detects DEX version 037`() {
        val dexBytes = createMinimalDex037()
        val dexFile = parser.parse(dexBytes)

        assertEquals("037", dexFile.version)
        assertTrue(dexFile.isValid)
    }

    // ─── Helper: create minimal synthetic DEX ────────────────────────

    /**
     * Create a minimal valid DEX 037 file with the correct header structure.
     * This isn't a real executable DEX, but has a valid header that the
     * parser can read.
     */
    private fun createMinimalDex037(): ByteArray {
        val baos = ByteArrayOutputStream()
        val dos = DataOutputStream(baos)

        // Magic: "dex\n037\0"
        dos.write(byteArrayOf(0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x37, 0x00))
        // Checksum (placeholder adler32)
        dos.writeInt(0x12345678)
        // Signature (20 zeros)
        dos.write(ByteArray(20))
        // File size
        dos.writeInt(0x70) // header only
        // Header size
        dos.writeInt(0x70)
        // Endian tag
        dos.writeInt(0x12345678)
        // Link size, offset
        dos.writeInt(0)
        dos.writeInt(0)
        // Map offset
        dos.writeInt(0)
        // String IDs
        dos.writeInt(0)
        dos.writeInt(0)
        // Type IDs
        dos.writeInt(0)
        dos.writeInt(0)
        // Proto IDs
        dos.writeInt(0)
        dos.writeInt(0)
        // Field IDs
        dos.writeInt(0)
        dos.writeInt(0)
        // Method IDs
        dos.writeInt(0)
        dos.writeInt(0)
        // Class defs
        dos.writeInt(0)
        dos.writeInt(0)
        // Data
        dos.writeInt(0)
        dos.writeInt(0)

        return baos.toByteArray()
    }

    private fun createMinimalDex035(): ByteArray {
        val dex = createMinimalDex037()
        // Replace version
        dex[4] = 0x30
        dex[5] = 0x33
        dex[6] = 0x35
        return dex
    }

    private fun createDexWithMethods(count: Int): ByteArray {
        val dex = createMinimalDex037().toMutableList()

        // Add method IDs after the header
        val methodIdsOff = dex.size
        repeat(count) {
            // Each method ID: classIdx(2) + protoIdx(2) + nameIdx(4) = 8 bytes
            dex.add(0x00) // classIdx low
            dex.add(0x00) // classIdx high
            dex.add(0x00) // protoIdx low
            dex.add(0x00) // protoIdx high
            val nameIdx = 0x0100 + it // nameIdx (4 bytes, LE)
            dex.add((nameIdx and 0xFF).toByte())
            dex.add(((nameIdx shr 8) and 0xFF).toByte())
            dex.add(((nameIdx shr 16) and 0xFF).toByte())
            dex.add(((nameIdx shr 24) and 0xFF).toByte())
        }

        // Update header: methodIdsSize and methodIdsOff
        val buffer = ByteBuffer.wrap(dex.toByteArray().also {}).order(ByteOrder.LITTLE_ENDIAN)

        // We need to modify the byte array directly
        val result = dex.toByteArray()
        // methodIdsSize at offset 0x58
        result[0x58] = count.toByte()
        result[0x59] = 0
        result[0x5A] = 0
        result[0x5B] = 0
        // methodIdsOff at offset 0x5C
        result[0x5C] = (methodIdsOff and 0xFF).toByte()
        result[0x5D] = ((methodIdsOff shr 8) and 0xFF).toByte()
        result[0x5E] = ((methodIdsOff shr 16) and 0xFF).toByte()
        result[0x5F] = ((methodIdsOff shr 24) and 0xFF).toByte()
        // Update file size
        val fileSize = result.size
        result[0x20] = (fileSize and 0xFF).toByte()
        result[0x21] = ((fileSize shr 8) and 0xFF).toByte()
        result[0x22] = ((fileSize shr 16) and 0xFF).toByte()
        result[0x23] = ((fileSize shr 24) and 0xFF).toByte()

        return result
    }

    private fun createDexWithClasses(count: Int): ByteArray {
        val dex = createMinimalDex037().toMutableList()

        // Add class defs after the header
        val classDefsOff = dex.size
        repeat(count) {
            // Each class def: 8 ints * 4 bytes = 32 bytes
            repeat(32) { dex.add(0x00) }
        }

        val result = dex.toByteArray()
        // classDefsSize at offset 0x60
        result[0x60] = count.toByte()
        result[0x61] = 0
        result[0x62] = 0
        result[0x63] = 0
        // classDefsOff at offset 0x64
        result[0x64] = (classDefsOff and 0xFF).toByte()
        result[0x65] = ((classDefsOff shr 8) and 0xFF).toByte()
        result[0x66] = ((classDefsOff shr 16) and 0xFF).toByte()
        result[0x67] = ((classDefsOff shr 24) and 0xFF).toByte()
        // Update file size
        val fileSize = result.size
        result[0x20] = (fileSize and 0xFF).toByte()
        result[0x21] = ((fileSize shr 8) and 0xFF).toByte()
        result[0x22] = ((fileSize shr 16) and 0xFF).toByte()
        result[0x23] = ((fileSize shr 24) and 0xFF).toByte()

        return result
    }
}
