package com.fuckprotect.protector.native

import java.io.File
import java.io.RandomAccessFile

/**
 * Encrypts native library (.so) files using RC4.
 *
 * Similar to dpt-shell's soFiles encryption:
 * 1. Find the .bitcode section in the ELF file
 * 2. Encrypt it with RC4
 * 3. Embed the RC4 key at a known symbol offset
 *
 * At runtime, the shell decrypts the section before use.
 */
class SoFileEncryptor {

    companion object {
        /** ELF magic: \x7FELF */
        private val ELF_MAGIC = byteArrayOf(0x7F.toByte(), 0x45, 0x4C, 0x46)

        /** SHT_PROGBITS section type */
        private const val SHT_PROGBITS = 1

        /** SHF_ALLOC + SHF_WRITE + SHF_EXECINSTR flags */
        private const val SHF_ALLOC = 0x2
        private const val SHF_EXECINSTR = 0x4

        /** Default RC4 key size in bytes */
        const val RC4_KEY_SIZE = 16

        /** Symbol name where the RC4 key will be embedded */
        const val RC4_KEY_SYMBOL = "g_dpt_rc4_key"
    }

    /**
     * Encrypt the .bitcode section of a native library with RC4.
     *
     * @param soFile The .so file to encrypt
     * @param key RC4 encryption key
     * @return true if encryption succeeded
     */
    fun encryptSoFile(soFile: File, key: ByteArray): Boolean {
        if (!soFile.exists()) return false

        try {
            val data = soFile.readBytes()

            // Verify ELF magic
            if (data.size < 4 || !data.take(4).contentEquals(ELF_MAGIC)) {
                return false
            }

            // Parse ELF header to find section headers
            val is64Bit = data[4] == 2.toByte()
            val isLittleEndian = data[5] == 1.toByte()

            val e_shoff = readElfOffset(data, is64Bit, isLittleEndian)
            val e_shentsize = readElfShort(data, is64Bit, isLittleEndian, 58)
            val e_shnum = readElfShort(data, is64Bit, isLittleEndian, 60)
            val e_shstrndx = readElfShort(data, is64Bit, isLittleEndian, 62)

            if (e_shoff == 0L || e_shoff + e_shentsize * e_shnum > data.size) {
                return false
            }

            // Find the .bitcode section
            var bitcodeOffset = -1L
            var bitcodeSize = 0

            for (i in 0 until e_shnum) {
                val shOffset = e_shoff + i * e_shentsize

                val shType = readElfInt(data, is64Bit, isLittleEndian, shOffset + 4)
                val shFlags = if (is64Bit) readElfLong(data, isLittleEndian, shOffset + 8)
                    else readElfInt(data, is64Bit, isLittleEndian, shOffset + 8).toLong()
                val shAddr = if (is64Bit) readElfLong(data, isLittleEndian, shOffset + 16)
                    else readElfInt(data, is64Bit, isLittleEndian, shOffset + 12).toLong()
                val shOff = if (is64Bit) readElfLong(data, isLittleEndian, shOffset + 24)
                    else readElfInt(data, is64Bit, isLittleEndian, shOffset + 16).toLong()
                val shSize = if (is64Bit) readElfLong(data, isLittleEndian, shOffset + 32)
                    else readElfInt(data, is64Bit, isLittleEndian, shOffset + 20).toLong()

                if (shType == SHT_PROGBITS.toLong() &&
                    (shFlags and SHF_ALLOC.toLong()) != 0L &&
                    (shFlags and SHF_EXECINSTR.toLong()) != 0L &&
                    shOff > 0 && shSize > 0) {

                    // Check section name
                    val strTabOffset = e_shoff + e_shstrndx * e_shentsize
                    val nameOffset = readElfInt(data, is64Bit, isLittleEndian, shOffset)
                    val sectionName = readStringAt(data, strTabOffset + nameOffset)

                    if (sectionName == ".bitcode" || sectionName == ".rodata") {
                        bitcodeOffset = shOff
                        bitcodeSize = shSize.toInt()
                        break
                    }
                }
            }

            if (bitcodeOffset < 0) {
                // No .bitcode section found — skip encryption
                return true
            }

            // Encrypt the section
            val sectionData = data.copyOfRange(bitcodeOffset.toInt(), bitcodeOffset.toInt() + bitcodeSize)
            rc4Encrypt(key, sectionData)
            System.arraycopy(sectionData, 0, data, bitcodeOffset.toInt(), bitcodeSize)

            // Embed the RC4 key at the symbol location
            val keySymbolOffset = findSymbolOffset(data, is64Bit, isLittleEndian, e_shoff, e_shentsize, e_shnum)
            if (keySymbolOffset >= 0) {
                System.arraycopy(key, 0, data, keySymbolOffset, RC4_KEY_SIZE)
            }

            soFile.writeBytes(data)
            return true

        } catch (e: Exception) {
            return false
        }
    }

    /**
     * Encrypt all ABI variants of libshell.so.
     *
     * @param nativeLibsDir Directory containing ABI subdirs
     * @param key RC4 encryption key
     */
    fun encryptAllNativeLibs(nativeLibsDir: File, key: ByteArray) {
        nativeLibsDir.listFiles()?.filter { it.isDirectory }?.forEach { abiDir ->
            val soFile = File(abiDir, "libshell.so")
            if (soFile.exists()) {
                val success = encryptSoFile(soFile, key)
                println("  ${abiDir.name}/libshell.so: ${if (success) "encrypted" else "skipped"}")
            }
        }
    }

    // ─── RC4 Implementation ──────────────────────────────────────────

    private fun rc4Init(key: ByteArray): IntArray {
        val s = IntArray(256) { it }
        var j = 0
        for (i in 0 until 256) {
            j = (j + s[i] + key[i % key.size].toInt() and 0xFF) and 0xFF
            val temp = s[i]
            s[i] = s[j]
            s[j] = temp
        }
        return s
    }

    private fun rc4Crypt(key: ByteArray, data: ByteArray) {
        val s = rc4Init(key)
        var i = 0
        var j = 0
        for (n in data.indices) {
            i = (i + 1) and 0xFF
            j = (j + s[i]) and 0xFF
            val temp = s[i]
            s[i] = s[j]
            s[j] = temp
            val k = s[(s[i] + s[j]) and 0xFF]
            data[n] = (data[n].toInt() xor k).toByte()
        }
    }

    private fun rc4Encrypt(key: ByteArray, data: ByteArray) {
        rc4Crypt(key, data)
    }

    // ─── ELF Parsing Helpers ─────────────────────────────────────────

    private fun readElfShort(data: ByteArray, is64: Boolean, isLE: Boolean, offset: Int): Int {
        return if (isLE) {
            (data[offset].toInt() and 0xFF) or ((data[offset + 1].toInt() and 0xFF) shl 8)
        } else {
            ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)
        }
    }

    private fun readElfInt(data: ByteArray, is64: Boolean, isLE: Boolean, offset: Long): Int {
        val o = offset.toInt()
        return if (isLE) {
            (data[o].toInt() and 0xFF) or
                ((data[o + 1].toInt() and 0xFF) shl 8) or
                ((data[o + 2].toInt() and 0xFF) shl 16) or
                ((data[o + 3].toInt() and 0xFF) shl 24)
        } else {
            ((data[o].toInt() and 0xFF) shl 24) or
                ((data[o + 1].toInt() and 0xFF) shl 16) or
                ((data[o + 2].toInt() and 0xFF) shl 8) or
                (data[o + 3].toInt() and 0xFF)
        }
    }

    private fun readElfLong(data: ByteArray, isLE: Boolean, offset: Long): Long {
        val o = offset.toInt()
        return if (isLE) {
            (data[o].toLong() and 0xFF) or
                ((data[o + 1].toLong() and 0xFF) shl 8) or
                ((data[o + 2].toLong() and 0xFF) shl 16) or
                ((data[o + 3].toLong() and 0xFF) shl 24) or
                ((data[o + 4].toLong() and 0xFF) shl 32) or
                ((data[o + 5].toLong() and 0xFF) shl 40) or
                ((data[o + 6].toLong() and 0xFF) shl 48) or
                ((data[o + 7].toLong() and 0xFF) shl 56)
        } else {
            ((data[o].toLong() and 0xFF) shl 56) or
                ((data[o + 1].toLong() and 0xFF) shl 48) or
                ((data[o + 2].toLong() and 0xFF) shl 40) or
                ((data[o + 3].toLong() and 0xFF) shl 32) or
                ((data[o + 4].toLong() and 0xFF) shl 24) or
                ((data[o + 5].toLong() and 0xFF) shl 16) or
                ((data[o + 6].toLong() and 0xFF) shl 8) or
                (data[o + 7].toLong() and 0xFF)
        }
    }

    private fun readElfOffset(data: ByteArray, is64: Boolean, isLE: Boolean): Long {
        val offset = if (is64) 24 else 16
        return if (is64) readElfLong(data, isLE, offset.toLong())
        else readElfInt(data, is64, isLE, offset).toLong()
    }

    private fun readStringAt(data: ByteArray, offset: Long): String {
        val sb = StringBuilder()
        var i = offset.toInt()
        while (i < data.size && data[i] != 0.toByte()) {
            sb.append(data[i].toInt().toChar())
            i++
        }
        return sb.toString()
    }

    private fun findSymbolOffset(
        data: ByteArray,
        is64: Boolean,
        isLE: Boolean,
        e_shoff: Long,
        e_shentsize: Int,
        e_shnum: Int,
    ): Int {
        // Search for the RC4 key symbol in the .dynsym section
        // This is a simplified search — in production, parse the symbol table properly
        val symbolName = RC4_KEY_SYMBOL.toByteArray(Charsets.US_ASCII)

        for (i in 0 until data.size - symbolName.size) {
            var found = true
            for (j in symbolName.indices) {
                if (data[i + j] != symbolName[j]) {
                    found = false
                    break
                }
            }
            if (found) {
                // Found the symbol name — the key value is at a known offset after it
                return i + symbolName.size + 16
            }
        }

        return -1
    }
}
