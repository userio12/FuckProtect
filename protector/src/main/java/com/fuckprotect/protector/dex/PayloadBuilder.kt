package com.fuckprotect.protector.dex

import com.fuckprotect.common.Constants
import com.fuckprotect.common.PayloadFormat
import com.fuckprotect.common.PayloadHeader
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream

/**
 * Builds the binary payload that is appended to protected APKs.
 *
 * The payload follows the format defined in [PayloadFormat] and contains:
 * - Header (magic, version, flags, lengths)
 * - Original Application class name
 * - Encrypted DEX data (IV + ciphertext)
 * - Hollowed method bytecode (optional, encrypted)
 * - CRC32 footer
 * - Total payload length
 */
class PayloadBuilder {

    private val header = PayloadHeader()
    private var originalAppClassName: String = ""
    private var encryptedDexData: ByteArray = byteArrayOf()
    private var hollowedMethodsData: ByteArray = byteArrayOf()

    /**
     * Set the original Application class name (to be restored at runtime).
     */
    fun setOriginalAppClass(className: String): PayloadBuilder {
        this.originalAppClassName = className
        return this
    }

    /**
     * Set the encrypted DEX data (already encrypted, IV prepended).
     */
    fun setEncryptedDexData(data: ByteArray): PayloadBuilder {
        this.encryptedDexData = data.copyOf()
        header.encryptedDexLength = data.size
        return this
    }

    /**
     * Set the hollowed method bytecode (optional).
     */
    fun setHollowedMethodsData(data: ByteArray): PayloadBuilder {
        this.hollowedMethodsData = data.copyOf()
        header.hollowedMethodsLength = data.size
        if (data.isNotEmpty()) {
            header.setFlag(PayloadHeader.Flags.HAS_HOLLOWED_METHODS)
        }
        return this
    }

    /**
     * Enable signature verification flag.
     */
    fun enableSignatureVerification(): PayloadBuilder {
        header.setFlag(PayloadHeader.Flags.SIGNATURE_VERIFICATION)
        return this
    }

    /**
     * Enable native protection flag.
     */
    fun enableNativeProtection(): PayloadBuilder {
        header.setFlag(PayloadHeader.Flags.HAS_NATIVE_PROTECTION)
        return this
    }

    /**
     * Build the complete payload as a byte array.
     *
     * Output format:
     *   [Header fixed fields (18 bytes)]
     *   [Original Application class name (4-byte length + UTF-8)]
     *   [Encrypted DEX data]
     *   [Hollowed methods data]
     *   [CRC32 of all preceding data (4 bytes)]
     *   [Total payload length (4 bytes, big-endian)]
     */
    fun build(): ByteArray {
        val baos = ByteArrayOutputStream()
        val dos = DataOutputStream(baos)

        // Set app name length in header
        header.originalAppClassNameLength = originalAppClassName.toByteArray(Charsets.UTF_8).size

        // 1. Write header fixed fields
        PayloadFormat.writeHeader(dos, header)

        // 2. Write original Application class name
        PayloadFormat.writeString(dos, originalAppClassName)

        // 3. Write encrypted DEX data
        if (header.encryptedDexLength > 0) {
            dos.write(encryptedDexData)
        }

        // 4. Write hollowed methods data
        if (header.hollowedMethodsLength > 0) {
            dos.write(hollowedMethodsData)
        }

        dos.flush()

        // 5. Compute CRC32 of all data written so far
        val allData = baos.toByteArray()
        val crc = PayloadFormat.computeCrc32(allData)

        // 6. Write CRC32 footer
        dos.write(crc)

        // 7. Write total payload length (everything including this field)
        val totalLength = allData.size + Constants.CRC32_SIZE_BYTES + Constants.INT_SIZE_BYTES
        dos.writeInt(totalLength)

        dos.flush()
        val payload = baos.toByteArray()

        // Sanity check: the last 4 bytes should be the total length
        val checkLength = payload.size
        val writtenLength = payload.sliceArray(
            payload.size - Constants.INT_SIZE_BYTES until payload.size
        ).let {
            ((it[0].toInt() and 0xFF) shl 24) or
                    ((it[1].toInt() and 0xFF) shl 16) or
                    ((it[2].toInt() and 0xFF) shl 8) or
                    (it[3].toInt() and 0xFF)
        }
        require(checkLength == writtenLength) {
            "Payload length mismatch: wrote $writtenLength but actual is $checkLength"
        }

        return payload
    }

    /**
     * Build the payload and return both the raw bytes and a summary.
     */
    fun buildWithSummary(): Pair<ByteArray, String> {
        val payload = build()
        val summary = buildString {
            appendLine("=== Payload Summary ===")
            appendLine("  Magic:               ${header.magic.decodeToString()}")
            appendLine("  Version:             ${header.version}")
            appendLine("  Flags:               0x${header.flags.toInt().toString(16)}")
            appendLine("  App Class:           $originalAppClassName")
            appendLine("  Encrypted DEX size:  ${header.encryptedDexLength} bytes")
            appendLine("  Hollowed methods:    ${header.hollowedMethodsLength} bytes")
            appendLine("  Total payload size:  ${payload.size} bytes")
        }
        return payload to summary
    }
}
