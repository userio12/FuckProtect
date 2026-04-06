package com.fuckprotect.protector.dex

import com.fuckprotect.common.Constants
import java.io.File
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Represents the 32-byte DEX file header.
 *
 * Reference: https://source.android.com/docs/core/runtime/dex-format
 */
data class DexHeader(
    val magic: ByteArray,                // 8 bytes: "dex\n035\0" or "dex\n037\0"
    val checksum: Int,                   // 4 bytes: adler32 non-header checksum
    val signature: ByteArray,            // 20 bytes: SHA-1 signature
    val fileSize: Int,                   // 4 bytes: size of entire DEX file
    val headerSize: Int,                 // 4 bytes: size of header (always 0x70)
    val endianTag: Int,                  // 4 bytes: endianness tag
    val linkSize: Int,                   // 4 bytes: link section size
    val linkOff: Int,                    // 4 bytes: offset to link data
    val mapOff: Int,                     // 4 bytes: offset to map data
    val stringIdsSize: Int,              // 4 bytes: number of string IDs
    val stringIdsOff: Int,              // 4 bytes: offset to string IDs
    val typeIdsSize: Int,               // 4 bytes: number of type IDs
    val typeIdsOff: Int,                // 4 bytes: offset to type IDs
    val protoIdsSize: Int,              // 4 bytes: number of prototype IDs
    val protoIdsOff: Int,               // 4 bytes: offset to prototype IDs
    val fieldIdsSize: Int,              // 4 bytes: number of field IDs
    val fieldIdsOff: Int,               // 4 bytes: offset to field IDs
    val methodIdsSize: Int,             // 4 bytes: number of method IDs
    val methodIdsOff: Int,              // 4 bytes: offset to method IDs
    val classDefsSize: Int,             // 4 bytes: number of class definitions
    val classDefsOff: Int,              // 4 bytes: offset to class definitions
    val dataSize: Int,                  // 4 bytes: size of data section
    val dataOff: Int,                   // 4 bytes: offset to data section
) {
    companion object {
        const val SIZE = 0x70 // 112 bytes
        val EXPECTED_ENDIAN: Int = 0x12345678
        val SUPPORTED_MAGICS: List<String> = listOf(
            "dex\n035\u0000",  // Android 4.0+
            "dex\n037\u0000",  // Android 8.0+
            "dex\n038\u0000",  // Android 10+
            "dex\n039\u0000",  // Android 12+
        )

        fun isValidMagic(magic: ByteArray): Boolean {
            if (magic.size < 8) return false
            val magicStr = magic.decodeToString()
            return SUPPORTED_MAGICS.any { magicStr.startsWith(it) }
        }
    }

    /** DEX version string extracted from magic (e.g. "035", "037"). */
    val version: String
        get() = magic.decodeToString().substring(4, 7)

    val isValid: Boolean
        get() = isValidMagic(magic) &&
                endianTag == EXPECTED_ENDIAN &&
                headerSize == SIZE &&
                fileSize > 0
}

/**
 * A parsed method ID entry from the DEX method_ids section.
 */
data class DexMethodId(
    val classIdx: Short,     // index into typeIds
    val protoIdx: Short,     // index into protoIds
    val nameIdx: Int,        // index into stringIds
)

/**
 * A parsed class definition entry from the DEX class_defs section.
 */
data class DexClassDef(
    val classIdx: Int,           // index into typeIds
    val accessFlags: Int,
    val superclassIdx: Int,
    val interfacesOff: Int,
    val sourceFileIdx: Int,
    val annotationsOff: Int,
    val classDataOff: Int,       // offset to class_data_item
    val staticValuesOff: Int,
)

/**
 * Parsed representation of a DEX file.
 */
data class DexFile(
    val header: DexHeader,
    val rawBytes: ByteArray,
    val methodIds: List<DexMethodId> = emptyList(),
    val classDefs: List<DexClassDef> = emptyList(),
) {
    /** DEX version string. */
    val version: String get() = header.version

    /** Whether this DEX file appears structurally valid. */
    val isValid: Boolean get() = header.isValid
}

/**
 * Parses DEX files from raw bytes or files.
 *
 * Supports DEX versions 035, 037, 038, 039.
 */
class DexParser {

    /**
     * Parse a DEX file from disk.
     */
    fun parse(file: File): DexFile {
        require(file.exists()) { "DEX file not found: ${file.absolutePath}" }
        require(file.length() > DexHeader.SIZE) {
            "File too small to be a valid DEX: ${file.length()} bytes"
        }

        val bytes = file.readBytes()
        return parse(bytes)
    }

    /**
     * Parse a DEX file from a byte array.
     */
    fun parse(bytes: ByteArray): DexFile {
        val buffer = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)

        val header = parseHeader(buffer)
        require(header.isValid) {
            "Invalid DEX header. magic=${header.magic.decodeToString().take(7)}, " +
                    "version=${header.version}, fileSize=${header.fileSize}"
        }

        val methodIds = parseMethodIds(buffer, header)
        val classDefs = parseClassDefs(buffer, header)

        return DexFile(
            header = header,
            rawBytes = bytes,
            methodIds = methodIds,
            classDefs = classDefs,
        )
    }

    /**
     * Parse just the header (lightweight, doesn't parse sections).
     */
    fun parseHeaderOnly(bytes: ByteArray): DexHeader {
        val buffer = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        return parseHeader(buffer)
    }

    // ─── Private: header parsing ─────────────────────────────────────

    private fun parseHeader(buffer: ByteBuffer): DexHeader {
        buffer.position(0)

        val magic = ByteArray(8).also { buffer.get(it) }
        val checksum = buffer.int
        val signature = ByteArray(20).also { buffer.get(it) }
        val fileSize = buffer.int
        val headerSize = buffer.int
        val endianTag = buffer.int
        val linkSize = buffer.int
        val linkOff = buffer.int
        val mapOff = buffer.int
        val stringIdsSize = buffer.int
        val stringIdsOff = buffer.int
        val typeIdsSize = buffer.int
        val typeIdsOff = buffer.int
        val protoIdsSize = buffer.int
        val protoIdsOff = buffer.int
        val fieldIdsSize = buffer.int
        val fieldIdsOff = buffer.int
        val methodIdsSize = buffer.int
        val methodIdsOff = buffer.int
        val classDefsSize = buffer.int
        val classDefsOff = buffer.int
        val dataSize = buffer.int
        val dataOff = buffer.int

        return DexHeader(
            magic = magic,
            checksum = checksum,
            signature = signature,
            fileSize = fileSize,
            headerSize = headerSize,
            endianTag = endianTag,
            linkSize = linkSize,
            linkOff = linkOff,
            mapOff = mapOff,
            stringIdsSize = stringIdsSize,
            stringIdsOff = stringIdsOff,
            typeIdsSize = typeIdsSize,
            typeIdsOff = typeIdsOff,
            protoIdsSize = protoIdsSize,
            protoIdsOff = protoIdsOff,
            fieldIdsSize = fieldIdsSize,
            fieldIdsOff = fieldIdsOff,
            methodIdsSize = methodIdsSize,
            methodIdsOff = methodIdsOff,
            classDefsSize = classDefsSize,
            classDefsOff = classDefsOff,
            dataSize = dataSize,
            dataOff = dataOff,
        )
    }

    // ─── Private: section parsing ────────────────────────────────────

    private fun parseMethodIds(
        buffer: ByteBuffer,
        header: DexHeader,
    ): List<DexMethodId> {
        if (header.methodIdsSize == 0 || header.methodIdsOff == 0) return emptyList()

        val methodIds = mutableListOf<DexMethodId>()
        buffer.position(header.methodIdsOff)

        repeat(header.methodIdsSize) {
            val classIdx = buffer.short
            val protoIdx = buffer.short
            val nameIdx = buffer.int
            methodIds.add(DexMethodId(classIdx, protoIdx, nameIdx))
        }

        return methodIds
    }

    private fun parseClassDefs(
        buffer: ByteBuffer,
        header: DexHeader,
    ): List<DexClassDef> {
        if (header.classDefsSize == 0 || header.classDefsOff == 0) return emptyList()

        val classDefs = mutableListOf<DexClassDef>()
        buffer.position(header.classDefsOff)

        repeat(header.classDefsSize) {
            val classIdx = buffer.int
            val accessFlags = buffer.int
            val superclassIdx = buffer.int
            val interfacesOff = buffer.int
            val sourceFileIdx = buffer.int
            val annotationsOff = buffer.int
            val classDataOff = buffer.int
            val staticValuesOff = buffer.int

            classDefs.add(
                DexClassDef(
                    classIdx = classIdx,
                    accessFlags = accessFlags,
                    superclassIdx = superclassIdx,
                    interfacesOff = interfacesOff,
                    sourceFileIdx = sourceFileIdx,
                    annotationsOff = annotationsOff,
                    classDataOff = classDataOff,
                    staticValuesOff = staticValuesOff,
                )
            )
        }

        return classDefs
    }
}
