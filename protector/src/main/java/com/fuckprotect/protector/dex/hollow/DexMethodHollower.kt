package com.fuckprotect.protector.dex.hollow

import org.jf.dexlib2.DexFileFactory
import org.jf.dexlib2.Opcodes
import org.jf.dexlib2.Opcode as DexOpcode
import org.jf.dexlib2.iface.DexFile
import org.jf.dexlib2.iface.Method
import org.jf.dexlib2.iface.MethodImplementation
import org.jf.dexlib2.iface.instruction.Instruction
import org.jf.dexlib2.immutable.*
import org.jf.dexlib2.rewriter.DexRewriter
import org.jf.dexlib2.rewriter.Rewriter
import org.jf.dexlib2.rewriter.RewriterModule
import org.jf.dexlib2.rewriter.Rewriters
import java.io.File

/**
 * DEX method hollowing using dexlib2.
 * Extracts method bytecode and replaces with NOP instructions.
 */
class DexMethodHollower {

    /**
     * Hollow all methods in a DEX file.
     */
    fun hollowAllMethods(dexFile: File): File {
        val dex = DexFileFactory.loadDexFile(dexFile, Opcodes.getDefault())
        val hollowed = hollowMethods(dex)
        val outputDex = File(dexFile.parent, dexFile.name.replace(".dex", "_hollowed.dex"))
        DexFileFactory.writeDexFile(outputDex.absolutePath, hollowed)
        return outputDex
    }

    /**
     * Hollow methods from DEX bytes.
     */
    fun hollowMethods(dexBytes: ByteArray): ByteArray {
        val tempFile = File.createTempFile("dpt_input", ".dex")
        tempFile.writeBytes(dexBytes)
        try {
            val output = hollowAllMethods(tempFile)
            val hollowedBytes = output.readBytes()
            tempFile.delete()
            output.delete()
            return hollowedBytes
        } catch (e: Exception) {
            tempFile.delete()
            throw e
        }
    }

    /**
     * Extract all method code from a DEX file.
     */
    fun extractAllMethods(dexFile: DexFile): Map<String, ByteArray> {
        val result = mutableMapOf<String, ByteArray>()
        for (classDef in dexFile.classes) {
            for (method in classDef.methods) {
                val impl = method.implementation ?: continue
                val code = serializeMethodCode(method, impl)
                val key = "${classDef.type}->${method.name}${method.reference}"
                result[key] = code
            }
        }
        return result
    }

    private fun serializeMethodCode(method: Method, impl: MethodImplementation): ByteArray {
        val baos = java.io.ByteArrayOutputStream()
        val dos = java.io.DataOutputStream(baos)
        dos.writeInt(method.name.length)
        dos.writeBytes(method.name)
        dos.writeInt(impl.registerCount)
        dos.writeInt(impl.instructions.count())
        for (insn in impl.instructions) {
            dos.writeShort(insn.opcode.value)
        }
        dos.close()
        return baos.toByteArray()
    }

    /**
     * Create hollowed DEX by replacing method implementations with return-void.
     */
    private fun hollowMethods(dexFile: DexFile): DexFile {
        val rewriter = DexRewriter(object : RewriterModule() {
            override fun getDexFileRewriter(rewriters: Rewriters): Rewriter<DexFile> {
                return Rewriter { value ->
                    val newClasses = mutableSetOf<org.jf.dexlib2.iface.ClassDef>()
                    for (classDef in value.classes) {
                        val newMethods = mutableListOf<org.jf.dexlib2.iface.Method>()
                        for (method in classDef.methods) {
                            val impl = method.implementation
                            if (impl != null && impl.instructions.any { it.opcode != DexOpcode.NOP }) {
                                val hollowedImpl = createHollowedImplementation(impl)
                                newMethods.add(
                                    ImmutableMethod(
                                        method.definingClass,
                                        method.name,
                                        ImmutableList.copyOf(method.parameters),
                                        method.returnType,
                                        method.accessFlags,
                                        ImmutableSet.copyOf(method.annotations),
                                        ImmutableSet.of(),
                                        hollowedImpl,
                                    )
                                )
                            } else {
                                newMethods.add(method)
                            }
                        }
                        newClasses.add(
                            ImmutableClassDef(
                                classDef.type,
                                classDef.accessFlags,
                                classDef.superclass,
                                ImmutableList.copyOf(classDef.interfaces),
                                classDef.sourceFile,
                                ImmutableSet.copyOf(classDef.annotations),
                                classDef.fields,
                                newMethods,
                            )
                        )
                    }
                    ImmutableDexFile(value.opcodes, newClasses)
                }
            }
        })
        return rewriter.dexFileRewriter.rewrite(dexFile)
    }

    private fun createHollowedImplementation(impl: MethodImplementation): MethodImplementation {
        return object : MethodImplementation {
            override fun getRegisterCount() = impl.registerCount
            override fun getInstructions(): Iterable<Instruction> = listOf(
                object : Instruction {
                    override fun getOpcode() = DexOpcode.RETURN_VOID
                    override fun getCodeUnits() = 1
                }
            )
            override fun getTryBlocks() = emptyList<org.jf.dexlib2.iface.TryBlock<*>>()
            override fun getDebugItems() = emptyList<org.jf.dexlib2.iface.debug.DebugItem>()
        }
    }
}

/**
 * Represents an extracted method with bytecode.
 */
data class ExtractedMethod(
    val className: String,
    val methodName: String,
    val methodProto: String,
    val code: ByteArray,
)
