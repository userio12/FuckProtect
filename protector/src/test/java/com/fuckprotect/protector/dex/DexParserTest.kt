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
 * Tests header parsing, validation, and section parsing.
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
        val badBytes = ByteArray(112)
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
        val dexBytes = createDexWithMethods(0)
        // Override version to 035
        dexBytes[4] = 0x30
        dexBytes[5] = 0x33
        dexBytes[6] = 0x35

        val dexFile = parser.parse(dexBytes)
        assertEquals("035", dexFile.version)
    }

    @Test
    fun `parse detects DEX version 037`() {
        val dexBytes = createDexWithMethods(0)
        val dexFile = parser.parse(dexBytes)
        assertEquals("037", dexFile.version)
    }

    // ─── Helpers ─────────────────────────────────────────────────────

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
        dos.writeInt(0x70)
        // Header size
        dos.writeInt(0x70)
        // Endian tag
        dos.writeInt(0x12345678)
        // Rest of header (76 bytes to fill 0x70 total)
        dos.write(ByteArray(0x70 - 40))

        return baos.toByteArray()
    }

    private fun createDexWithMethods(count: Int): ByteArray {
        val headerSize = 0x70
        val methodIdsOff = headerSize + 100 // some padding
        val methodIdsSize = count * 8 // 8 bytes per method ID

        val baos = ByteArrayOutputStream()
        val dos = DataOutputStream(baos)

        // Magic: "dex\n037\0"
        dos.write(byteArrayOf(0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x37, 0x00))
        dos.writeInt(0) // checksum
        dos.write(ByteArray(20)) // signature
        val fileSize = headerSize + 100 + methodIdsSize
        dos.writeInt(fileSize)
        dos.writeInt(headerSize)
        dos.writeInt(0x12345678) // endian
        // Link
        dos.writeInt(0); dos.writeInt(0)
        // Map
        dos.writeInt(0)
        // String IDs
        dos.writeInt(0); dos.writeInt(0)
        // Type IDs
        dos.writeInt(0); dos.writeInt(0)
        // Proto IDs
        dos.writeInt(0); dos.writeInt(0)
        // Field IDs
        dos.writeInt(0); dos.writeInt(0)
        // Method IDs
        dos.writeInt(count)
        dos.writeInt(methodIdsOff)
        // Class defs
        dos.writeInt(0); dos.writeInt(0)
        // Data
        dos.writeInt(0); dos.writeInt(0)

        // Padding
        dos.write(ByteArray(100))

        // Method IDs
        repeat(count) {
            dos.writeShort(0) // classIdx
            dos.writeShort(0) // protoIdx
            dos.writeInt(1 + it) // nameIdx
        }

        return baos.toByteArray()
    }

    private fun createDexWithClasses(count: Int): ByteArray {
        val headerSize = 0x70
        val classDefsOff = headerSize + 100
        val classDefSize = count * 32 // 32 bytes per class def

        val baos = ByteArrayOutputStream()
        val dos = DataOutputStream(baos)

        // Magic
        dos.write(byteArrayOf(0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x37, 0x00))
        dos.writeInt(0)
        dos.write(ByteArray(20))
        val fileSize = headerSize + 100 + classDefSize
        dos.writeInt(fileSize)
        dos.writeInt(headerSize)
        dos.writeInt(0x12345678)
        // Link
        dos.writeInt(0); dos.writeInt(0)
        // Map
        dos.writeInt(0)
        // String IDs
        dos.writeInt(0); dos.writeInt(0)
        // Type IDs
        dos.writeInt(0); dos.writeInt(0)
        // Proto IDs
        dos.writeInt(0); dos.writeInt(0)
        // Field IDs
        dos.writeInt(0); dos.writeInt(0)
        // Method IDs
        dos.writeInt(0); dos.writeInt(0)
        // Class defs
        dos.writeInt(count)
        dos.writeInt(classDefsOff)
        // Data
        dos.writeInt(0); dos.writeInt(0)

        // Padding
        dos.write(ByteArray(100))

        // Class defs
        repeat(count) {
            dos.writeInt(0)  // classIdx
            dos.writeInt(1)  // accessFlags
            dos.writeInt(1)  // superclassIdx
            dos.writeInt(0)  // interfacesOff
            dos.writeInt(0)  // sourceFileIdx
            dos.writeInt(0)  // annotationsOff
            dos.writeInt(0)  // classDataOff
            dos.writeInt(0)  // staticValuesOff
        }

        return baos.toByteArray()
    }
}
