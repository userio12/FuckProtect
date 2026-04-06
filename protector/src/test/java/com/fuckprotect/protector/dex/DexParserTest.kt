package com.fuckprotect.protector.dex

import com.fuckprotect.common.Constants
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Unit tests for DexParser (T2.3).
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
        val dexBytes = createValidDexHeader()
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
        val dexBytes = createValidDexHeader()
        dexBytes[4] = 0x30
        dexBytes[5] = 0x33
        dexBytes[6] = 0x35

        val dexFile = parser.parse(dexBytes)
        assertEquals("035", dexFile.version)
    }

    @Test
    fun `parse detects DEX version 037`() {
        val dexBytes = createValidDexHeader()
        val dexFile = parser.parse(dexBytes)
        assertEquals("037", dexFile.version)
    }

    // ─── Helpers ─────────────────────────────────────────────────────

    /**
     * Creates a valid DEX header + padding (no actual sections).
     */
    private fun createValidDexHeader(): ByteArray {
        val baos = java.io.ByteArrayOutputStream()
        val buf = ByteBuffer.allocate(256).order(ByteOrder.LITTLE_ENDIAN)

        // Magic: "dex\n037\0"
        buf.put(byteArrayOf(0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x37, 0x00))
        buf.putInt(0) // checksum
        buf.put(ByteArray(20)) // signature
        val fileSize = 256
        buf.putInt(fileSize)
        buf.putInt(0x70) // headerSize
        buf.putInt(0x12345678) // endian
        // Rest of header fields (all zeros = no sections)
        repeat(18) { buf.putInt(0) }

        // Pad to 256 bytes
        buf.position(256)

        return buf.array()
    }

    /**
     * Creates a DEX file with method IDs.
     */
    private fun createDexWithMethods(count: Int): ByteArray {
        val headerSize = 0x70
        val methodIdsOff = 0x100 // 256
        val methodIdsSize = count * 8
        val fileSize = methodIdsOff + methodIdsSize

        val buf = ByteBuffer.allocate(fileSize).order(ByteOrder.LITTLE_ENDIAN)

        // Header
        buf.put(byteArrayOf(0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x37, 0x00))
        buf.putInt(0) // checksum
        buf.put(ByteArray(20)) // signature
        buf.putInt(fileSize)
        buf.putInt(0x70)
        buf.putInt(0x12345678)
        // 11 zeros (linkSize through fieldIdsOff)
        repeat(11) { buf.putInt(0) }
        buf.putInt(count) // methodIdsSize
        buf.putInt(methodIdsOff) // methodIdsOff
        // 4 zeros (classDefsSize through dataOff)
        repeat(4) { buf.putInt(0) }

        // Pad to methodIdsOff
        buf.position(methodIdsOff)

        // Method IDs
        repeat(count) {
            buf.putShort(0) // classIdx
            buf.putShort(0) // protoIdx
            buf.putInt(1 + it) // nameIdx
        }

        return buf.array()
    }

    /**
     * Creates a DEX file with class definitions.
     */
    private fun createDexWithClasses(count: Int): ByteArray {
        val headerSize = 0x70
        val classDefsOff = 0x100
        val classDefsSize = count * 32
        val fileSize = classDefsOff + classDefsSize

        val buf = ByteBuffer.allocate(fileSize).order(ByteOrder.LITTLE_ENDIAN)

        // Header
        buf.put(byteArrayOf(0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x37, 0x00))
        buf.putInt(0)
        buf.put(ByteArray(20))
        buf.putInt(fileSize)
        buf.putInt(0x70)
        buf.putInt(0x12345678)
        // 13 zeros (linkSize through methodIdsOff)
        repeat(13) { buf.putInt(0) }
        buf.putInt(count) // classDefsSize
        buf.putInt(classDefsOff) // classDefsOff
        // 2 zeros (dataSize, dataOff)
        repeat(2) { buf.putInt(0) }

        // Pad to classDefsOff
        buf.position(classDefsOff)

        // Class defs
        repeat(count) {
            buf.putInt(0) // classIdx
            buf.putInt(1) // accessFlags
            buf.putInt(1) // superclassIdx
            buf.putInt(0) // interfacesOff
            buf.putInt(0) // sourceFileIdx
            buf.putInt(0) // annotationsOff
            buf.putInt(0) // classDataOff
            buf.putInt(0) // staticValuesOff
        }

        return buf.array()
    }
}
