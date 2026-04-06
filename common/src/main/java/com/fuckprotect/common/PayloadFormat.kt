package com.fuckprotect.common

import java.io.DataInput
import java.io.DataOutput
import java.util.zip.CRC32

/**
 * Defines the binary payload format appended to protected APKs.
 *
 * Layout (big-endian):
 *   Offset  Size      Field
 *   0x00    4 bytes   Magic "FUCK"
 *   0x04    2 bytes   Version (uint16)
 *   0x06    2 bytes   Flags (uint16)
 *   0x08    4 bytes   Encrypted DEX length
 *   0x0C    4 bytes   Hollowed methods data length
 *   0x10    4 bytes   Original Application class name length
 *   0x14    variable  Original Application class name (UTF-8)
 *   0x14+N  variable  Encrypted DEX data (IV + ciphertext)
 *   ...     variable  Hollowed method bytecode (encrypted)
 *   ...     4 bytes   CRC32 footer
 *   ...     4 bytes   Total payload length
 */
data class PayloadHeader(
    val magic: ByteArray = Constants.MAGIC.copyOf(),
    val version: Short = Constants.VERSION,
    var flags: Short = 0,
    var encryptedDexLength: Int = 0,
    var hollowedMethodsLength: Int = 0,
    var originalAppClassNameLength: Int = 0,
) {

    /** Header size in bytes (fixed fields only, before variable data). */
    val headerSize: Int = HEADER_SIZE

    /** Flag bits. */
    object Flags {
        const val HAS_HOLLOWED_METHODS: Short = 0x01
        const val HAS_NATIVE_PROTECTION: Short = 0x02
        const val SIGNATURE_VERIFICATION: Short = 0x04
    }

    fun setFlag(flag: Short) {
        flags = (flags.toInt() or flag.toInt()).toShort()
    }

    fun hasFlag(flag: Short): Boolean = (flags.toInt() and flag.toInt()) != 0

    companion object {
        const val HEADER_SIZE = 14 // 4 + 2 + 2 + 4 + 2 (without app name length)
        const val FULL_FIXED_SIZE = 18 // includes app name length field
    }
}

/**
 * Serializes and deserializes the payload.
 */
object PayloadFormat {

    /**
     * Write the payload header (fixed fields) to the output.
     */
    fun writeHeader(out: DataOutput, header: PayloadHeader) {
        out.write(header.magic)
        out.writeShort(header.version.toInt())
        out.writeShort(header.flags.toInt())
        out.writeInt(header.encryptedDexLength)
        out.writeInt(header.hollowedMethodsLength)
        out.writeInt(header.originalAppClassNameLength)
    }

    /**
     * Read the payload header (fixed fields) from the input.
     */
    fun readHeader(input: DataInput): PayloadHeader {
        val magic = ByteArray(4).also { input.readFully(it) }
        val version = input.readShort()
        val flags = input.readShort()
        val encryptedDexLength = input.readInt()
        val hollowedMethodsLength = input.readInt()
        val originalAppClassNameLength = input.readInt()

        return PayloadHeader(
            magic = magic,
            version = version,
            flags = flags,
            encryptedDexLength = encryptedDexLength,
            hollowedMethodsLength = hollowedMethodsLength,
            originalAppClassNameLength = originalAppClassNameLength,
        )
    }

    /**
     * Write a UTF-8 string preceded by its 4-byte length.
     */
    fun writeString(out: DataOutput, str: String) {
        val bytes = str.toByteArray(Charsets.UTF_8)
        out.writeInt(bytes.size)
        out.write(bytes)
    }

    /**
     * Read a UTF-8 string preceded by its 4-byte length.
     */
    fun readString(input: DataInput): String {
        val length = input.readInt()
        val bytes = ByteArray(length)
        input.readFully(bytes)
        return bytes.decodeToString()
    }

    /**
     * Compute CRC32 of the given byte array (returned as 4 bytes, big-endian).
     */
    fun computeCrc32(data: ByteArray): ByteArray {
        val crc = CRC32()
        crc.update(data)
        val value = crc.value.toInt()
        return byteArrayOf(
            (value shr 24).toByte(),
            (value shr 16).toByte(),
            (value shr 8).toByte(),
            value.toByte(),
        )
    }

    /**
     * Verify a CRC32 checksum.
     */
    fun verifyCrc32(data: ByteArray, expected: ByteArray): Boolean {
        val actual = computeCrc32(data)
        return actual.contentEquals(expected)
    }
}
