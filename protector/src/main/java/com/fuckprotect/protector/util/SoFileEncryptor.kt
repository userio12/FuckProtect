package com.fuckprotect.protector.util

import java.io.File

/**
 * Encrypts native library (.so) files using RC4.
 */
class SoFileEncryptor {

    companion object {
        const val RC4_KEY_SIZE = 16
    }

    fun encryptAllNativeLibs(nativeLibsDir: File, key: ByteArray) {
        nativeLibsDir.listFiles()?.filter { it.isDirectory }?.forEach { abiDir ->
            val soFile = File(abiDir, "libshell.so")
            if (soFile.exists()) {
                val success = encryptSoFile(soFile, key)
                println("  ${abiDir.name}/libshell.so: ${if (success) "encrypted" else "skipped"}")
            }
        }
    }

    fun encryptSoFile(soFile: File, key: ByteArray): Boolean {
        if (!soFile.exists() || key.size < RC4_KEY_SIZE) return false

        val data = soFile.readBytes()
        if (data.size < 4 || !data.take(4).contentEquals(byteArrayOf(0x7F.toByte(), 0x45, 0x4C, 0x46))) {
            return false
        }

        // Simple RC4 encryption of the first section after header
        val sectionOffset = 0x1000 // Start after header
        if (data.size <= sectionOffset) return false

        val sectionData = data.copyOfRange(sectionOffset, data.size)
        rc4Crypt(key.copyOf(RC4_KEY_SIZE), sectionData)

        soFile.writeBytes(data.copyOf(sectionOffset) + sectionData)
        return true
    }

    private fun rc4Init(key: ByteArray): IntArray {
        val s = IntArray(256) { it }
        var j = 0
        for (i in 0 until 256) {
            j = (j + s[i] + key[i % key.size].toInt()) and 0xFF
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
}
