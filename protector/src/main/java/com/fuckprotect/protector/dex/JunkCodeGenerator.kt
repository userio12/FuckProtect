package com.fuckprotect.protector.dex

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.security.MessageDigest
import java.util.Random

/**
 * Generates a junk code DEX file that serves as an anti-tamper mechanism.
 *
 * The junk DEX contains fake classes with meaningless methods.
 * At runtime, the shell checks if these classes still exist.
 * If they've been removed or modified, the APK was tampered with.
 *
 * This is similar to dpt-shell's JunkCodeGenerator.
 */
class JunkCodeGenerator {

    companion object {
        private const val JUNK_PACKAGE = "com.fuckprotect.shell.junk"
        private const val JUNK_CLASS_PREFIX = "J"
        private const val NUM_CLASSES = 10
        private const val NUM_METHODS_PER_CLASS = 5
    }

    private val random = Random(0xDEADBEEF) // Deterministic seed for reproducibility

    /**
     * Generate a junk DEX file as a byte array.
     *
     * The generated DEX contains fake classes with methods that do nothing
     * but return constants. The shell verifies these classes exist at runtime.
     *
     * @return DEX file bytes
     */
    fun generateDex(): ByteArray {
        val classes = generateJunkClasses()
        return buildDex(classes)
    }

    /**
     * Generate the expected hash of the junk DEX for runtime verification.
     *
     * @return SHA-256 hash of the junk DEX
     */
    fun generateExpectedHash(): ByteArray {
        val dex = generateDex()
        val md = MessageDigest.getInstance("SHA-256")
        return md.digest(dex)
    }

    /**
     * Generate fake class definitions.
     */
    private fun generateJunkClasses(): List<JunkClass> {
        return (0 until NUM_CLASSES).map { classIdx ->
            val className = "$JUNK_PACKAGE.${JUNK_CLASS_PREFIX}${classIdx}"
            val methods = (0 until NUM_METHODS_PER_CLASS).map { methodIdx ->
                JunkMethod(
                    name = "method${methodIdx}",
                    returnType = getRandomType(),
                    instructions = generateJunkInstructions(methodIdx),
                )
            }
            JunkClass(
                name = className,
                accessFlags = 0x0001, // public
                superName = "java.lang.Object",
                methods = methods,
            )
        }
    }

    /**
     * Generate meaningless DEX instructions for junk methods.
     */
    private fun generateJunkInstructions(seed: Int): List<ByteArray> {
        val instructions = mutableListOf<ByteArray>()

        // const v0, <random int>
        val constVal = random.nextInt(0xFFFF)
        instructions.add(byteArrayOf(
            0x12.toByte(), // const/4
            ((seed and 0xF) or (constVal and 0xF)).toByte(),
        ))

        // const-string v0, "junk"
        instructions.add(byteArrayOf(
            0x1A.toByte(), // const-string
            0x00, // vA=0, vB=string_idx (will be patched)
            0x00, 0x00,
        ))

        // return-object v0
        instructions.add(byteArrayOf(
            0x11.toByte(), // return-object
            0x00,
        ))

        return instructions
    }

    private fun getRandomType(): String {
        val types = listOf(
            "Ljava/lang/String;",
            "I",
            "Z",
            "Ljava/lang/Object;",
        )
        return types[random.nextInt(types.size)]
    }

    /**
     * Build a minimal valid DEX file from junk class definitions.
     *
     * This creates a simplified DEX structure:
     * - Header (112 bytes)
     * - String IDs
     * - Type IDs
     * - Proto IDs
     * - Field IDs (empty)
     * - Method IDs
     * - Class Definitions
     * - Data section (strings, encoded arrays, code items)
     *
     * For a complete implementation, use dexlib2 (com.android.tools.smali.dexlib2).
     * This is a simplified version for demonstration.
     */
    private fun buildDex(classes: List<JunkClass>): ByteArray {
        val baos = ByteArrayOutputStream()
        val dos = DataOutputStream(baos)

        // For a proper implementation, integrate dexlib2:
        // val dexBuilder = DexBuilder(Opcodes.getDefault())
        // classes.forEach { cls -> dexBuilder.internClass(cls) }
        // return dexBuilder.writeTo()

        // Placeholder: minimal DEX header + padding
        // In production, replace with full dexlib2 integration

        // DEX magic "dex\n035\0"
        dos.write(byteArrayOf(0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x35, 0x00))
        dos.writeInt(0) // checksum (placeholder)
        dos.write(ByteArray(20)) // signature (placeholder)

        val fileSize = 1024 // minimal size
        dos.writeInt(fileSize)
        dos.writeInt(0x70) // header size
        dos.writeInt(0x12345678) // endian tag

        // All zeros for remaining header fields
        dos.write(ByteArray(0x70 - 40))

        // Pad to file size
        dos.write(ByteArray(fileSize - 0x70))

        return baos.toByteArray()
    }

    /**
     * Write the junk DEX to a file.
     *
     * @param outputPath Where to write the junk DEX file
     */
    fun writeToFile(outputPath: java.io.File) {
        val dex = generateDex()
        outputPath.writeBytes(dex)
    }
}

/**
 * Represents a junk class definition.
 */
data class JunkClass(
    val name: String,
    val accessFlags: Int,
    val superName: String,
    val methods: List<JunkMethod>,
)

/**
 * Represents a junk method definition.
 */
data class JunkMethod(
    val name: String,
    val returnType: String,
    val instructions: List<ByteArray>,
)
