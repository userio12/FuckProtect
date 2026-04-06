package com.fuckprotect.protector.dex.hollow

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * DEX method hollowing implementation.
 *
 * This extracts code_item data from DEX methods and replaces them with NOP instructions.
 * The extracted code is stored in a separate payload for runtime restoration.
 *
 * Based on dpt-shell's DexUtils.extractAllMethods() and DexUtils.injectInvokeMethod().
 *
 * DEX method hollowing process:
 * 1. Parse DEX file to find all methods with code_item
 * 2. Extract the code_item (instructions, tries, handlers)
 * 3. Replace the method body with a single "return-void" or "return" instruction
 * 4. Store the original code_item in a map keyed by method index
 * 5. Write the extracted code to a separate payload file
 *
 * At runtime:
 * 1. The shell loads the hollowed DEX
 * 2. When a class is loaded, the shell patches the method code_item back
 * 3. The method now has its original bytecode
 */
class DexMethodHollower {

    /**
     * Extract code_items from all methods in a DEX file.
     *
     * @param dexBytes Original DEX file bytes
     * @return Extraction result containing hollowed DEX and extracted code
     */
    fun hollowMethods(dexBytes: ByteArray): HollowResult {
        val buffer = ByteBuffer.wrap(dexBytes).order(ByteOrder.LITTLE_ENDIAN)

        // Parse DEX header
        buffer.position(0x58) // methodIdsSize offset
        val methodIdsSize = buffer.int
        val methodIdsOff = buffer.int
        val classDefsSize = buffer.int
        val classDefsOff = buffer.int

        // Parse method IDs
        val methodIds = mutableListOf<MethodId>()
        buffer.position(methodIdsOff)
        for (i in 0 until methodIdsSize) {
            val classIdx = buffer.short.toInt()
            val protoIdx = buffer.short.toInt()
            val nameIdx = buffer.int
            methodIds.add(MethodId(i, classIdx, protoIdx, nameIdx))
        }

        // Parse class definitions to find method code offsets
        val extractedMethods = mutableMapOf<Int, ByteArray>()
        val codeOffsetsToHollow = mutableMapOf<Int, Int>() // codeOff -> methodIdx

        buffer.position(classDefsOff)
        for (i in 0 until classDefsSize) {
            val classIdx = buffer.int
            buffer.position(buffer.position() + 12) // skip accessFlags, superclassIdx, interfacesOff
            val sourceFileIdx = buffer.int
            val annotationsOff = buffer.int
            val classDataOff = buffer.int
            val staticValuesOff = buffer.int

            if (classDataOff == 0) continue

            // Parse class_data_item
            buffer.position(classDataOff)
            val directMethodsSize = readUleb128(buffer)
            val virtualMethodsSize = readUleb128(buffer)

            var prevMethodIdx = 0
            val allMethods = directMethodsSize + virtualMethodsSize

            for (j in 0 until allMethodsSize) {
                val methodIdxDiff = readUleb128(buffer)
                val methodIdx = prevMethodIdx + methodIdxDiff
                prevMethodIdx = methodIdx
                val accessFlags = readUleb128(buffer)
                val codeOff = readUleb128(buffer)

                if (codeOff > 0 && methodIdx < methodIds.size) {
                    // Extract code_item at codeOff
                    val codeItemSize = extractCodeItem(dexBytes, codeOff, methodIds[methodIdx])
                    if (codeItemSize > 0) {
                        extractedMethods[methodIdx] = dexBytes.copyOfRange(codeOff, codeOff + codeItemSize)
                        codeOffsetsToHollow[codeOff] = methodIdx
                    }
                }
            }
        }

        // Hollow out the methods: replace code_item with NOP instructions
        val hollowedDex = dexBytes.copyOf()
        hollowOutMethods(hollowedDex, codeOffsetsToHollow)

        return HollowResult(
            hollowedDex = hollowedDex,
            extractedCode = extractedMethods,
            methodCount = extractedMethods.size,
        )
    }

    /**
     * Extract a code_item from the DEX at the given offset.
     *
     * code_item format:
     * - registers_size (2 bytes)
     * - ins_size (2 bytes)
     * - outs_size (2 bytes)
     * - tries_size (2 bytes)
     * - debug_info_off (4 bytes)
     * - insns_size (4 bytes)
     * - insns (2 bytes each)
     * - padding (if needed)
     * - try_item[] (if tries_size > 0)
     * - encoded_catch_handler_list (if tries_size > 0)
     *
     * @return Total size of code_item in bytes, or 0 on error
     */
    private fun extractCodeItem(dexBytes: ByteArray, codeOff: Int, methodId: MethodId): Int {
        if (codeOff + 16 > dexBytes.size) return 0

        val buffer = ByteBuffer.wrap(dexBytes).order(ByteOrder.LITTLE_ENDIAN)
        buffer.position(codeOff)

        val registersSize = buffer.short // 2 bytes
        val insSize = buffer.short       // 2 bytes
        val outsSize = buffer.short      // 2 bytes
        val triesSize = buffer.short     // 2 bytes
        val debugInfoOff = buffer.int    // 4 bytes
        val insnsSize = buffer.int       // 4 bytes (number of 2-byte instructions)

        if (insnsSize == 0) return 0

        // Calculate total code_item size
        val insnsBytes = insnsSize * 2
        var totalSize = 16 + insnsBytes // header + instructions

        // Add tries and handlers if present
        if (triesSize > 0) {
            // Padding to 4-byte alignment
            if (insnsSize % 2 != 0) {
                totalSize += 2 // padding
            }
            totalSize += triesSize * 8 // try_item: start_addr (2) + insn_count (2) + handler_off (4)
            // encoded_catch_handler_list size varies - we'll copy everything until the next code_item
        }

        return totalSize
    }

    /**
     * Hollow out methods by replacing their bytecode with NOP/return instructions.
     */
    private fun hollowOutMethods(dexBytes: ByteArray, codeOffsets: Map<Int, Int>) {
        for ((codeOff, methodIdx) in codeOffsets) {
            if (codeOff + 16 > dexBytes.size) continue

            val buffer = ByteBuffer.wrap(dexBytes).order(ByteOrder.LITTLE_ENDIAN)
            buffer.position(codeOff)

            val registersSize = buffer.short
            val insSize = buffer.short
            val outsSize = buffer.short
            val triesSize = buffer.short
            val debugInfoOff = buffer.int
            val insnsSize = buffer.int

            if (insnsSize == 0) continue

            val insnsOffset = codeOff + 16

            // Replace instructions with NOP/return
            for (i in 0 until insnsSize) {
                val insnOffset = insnsOffset + i * 2
                if (insnOffset + 1 < dexBytes.size) {
                    if (i == 0) {
                        // First instruction: return-void (0x0E) or return (0x0F)
                        dexBytes[insnOffset] = 0x0E // return-void
                        dexBytes[insnOffset + 1] = 0x00
                    } else {
                        // NOP (0x0000)
                        dexBytes[insnOffset] = 0x00
                        dexBytes[insnOffset + 1] = 0x00
                    }
                }
            }

            // Zero out tries if present
            if (triesSize > 0) {
                var triesOffset = insnsOffset + insnsSize * 2
                if (insnsSize % 2 != 0) triesOffset += 2 // skip padding

                for (i in 0 until triesSize.toInt()) {
                    val tryOffset = triesOffset + i * 8
                    if (tryOffset + 8 <= dexBytes.size) {
                        for (j in 0 until 8) {
                            dexBytes[tryOffset + j] = 0
                        }
                    }
                }
            }
        }
    }

    /**
     * Read an unsigned LEB128 value from the buffer.
     */
    private fun readUleb128(buffer: ByteBuffer): Int {
        var result = 0
        var shift = 0
        var byte: Int
        do {
            byte = buffer.get().toInt() and 0xFF
            result = result or ((byte and 0x7F) shl shift)
            shift += 7
        } while ((byte and 0x80) != 0)
        return result
    }

    /**
     * Write the extracted method code to a binary payload.
     *
     * Format:
     * - Magic: "HOLLOW" (6 bytes)
     * - Version: 1 (2 bytes)
     * - Method count: N (4 bytes)
     * - For each method:
     *   - methodIdx (4 bytes)
     *   - codeSize (4 bytes)
     *   - code (codeSize bytes)
     * - CRC32 footer (4 bytes)
     */
    fun writeExtractedCode(extractedCode: Map<Int, ByteArray>): ByteArray {
        val baos = ByteArrayOutputStream()
        val dos = DataOutputStream(baos)

        // Magic
        dos.write(byteArrayOf(0x48, 0x4F, 0x4C, 0x4C, 0x4F, 0x57)) // "HOLLOW"
        // Version
        dos.writeShort(1)
        // Method count
        dos.writeInt(extractedCode.size)

        // Methods
        for ((methodIdx, code) in extractedCode) {
            dos.writeInt(methodIdx)
            dos.writeInt(code.size)
            dos.write(code)
        }

        // CRC32 footer
        val data = baos.toByteArray()
        val crc = computeCrc32(data)
        dos.write(crc)

        return baos.toByteArray()
    }

    /**
     * Compute CRC32 checksum.
     */
    private fun computeCrc32(data: ByteArray): ByteArray {
        val crc = java.util.zip.CRC32()
        crc.update(data)
        val value = crc.value.toInt()
        return byteArrayOf(
            (value shr 24).toByte(),
            (value shr 16).toByte(),
            (value shr 8).toByte(),
            value.toByte(),
        )
    }
}

/**
 * Result of method hollowing.
 */
data class HollowResult(
    /** DEX file with hollowed methods (NOP instructions) */
    val hollowedDex: ByteArray,
    /** Extracted code_items keyed by method index */
    val extractedCode: Map<Int, ByteArray>,
    /** Number of methods hollowed */
    val methodCount: Int,
)

/**
 * DEX method ID entry.
 */
data class MethodId(
    val index: Int,
    val classIdx: Int,
    val protoIdx: Int,
    val nameIdx: Int,
)
