package com.fuckprotect.protector.apk

import net.lingala.zip4j.ZipFile
import net.lingala.zip4j.model.ZipParameters
import net.lingala.zip4j.model.enums.CompressionMethod
import java.io.File

/**
 * Repackages APK contents into a protected APK.
 *
 * Takes the extracted/modified contents and creates a new ZIP archive
 * with the correct APK structure.
 */
class ApkPackager {

    /**
     * Configuration for the repackaging process.
     */
    data class Config(
        /** Whether to store files (no compression) for alignment-sensitive entries. */
        val storeOnlyPatterns: List<String> = listOf("*.so", "*.dex", "*.arsc", "*.png", "*.jpg"),
        /** Compression level for deflate entries. */
        val compressionLevel: Int = 6,
    )

    private val config = Config()

    /**
     * Build a protected APK from the given working directory.
     *
     * @param workDir Directory containing the extracted/modified APK contents
     * @param outputApk The output APK file to create
     */
    fun buildApk(workDir: File, outputApk: File) {
        require(workDir.exists() && workDir.isDirectory) {
            "Work directory not found: ${workDir.absolutePath}"
        }

        outputApk.parentFile?.mkdirs()

        // Remove existing output
        if (outputApk.exists()) outputApk.delete()

        ZipFile(outputApk).use { zip ->
            val parameters = ZipParameters().apply {
                compressionMethod = CompressionMethod.DEFLATE
            }

            workDir.listFiles()?.forEach { entry ->
                addEntry(zip, entry, parameters, workDir)
            }
        }
    }

    /**
     * Build a protected APK, adding an extra payload file as an asset.
     *
     * @param workDir Directory containing the extracted/modified APK contents
     * @param outputApk The output APK file to create
     * @param payloadFile The encrypted payload file to add as an asset
     */
    fun buildApkWithPayload(workDir: File, outputApk: File, payloadFile: File) {
        // Ensure assets directory exists
        val assetsDir = File(workDir, "assets").apply { mkdirs() }

        // Copy payload into assets
        val payloadDest = File(assetsDir, Constants.PAYLOAD_ASSET_NAME)
        payloadFile.copyTo(payloadDest, overwrite = true)

        buildApk(workDir, outputApk)
    }

    /**
     * Add native .so files from a directory into the APK's lib/ directory.
     *
     * @param workDir The working directory (will have lib/ added)
     * @param nativeLibsDir Directory containing ABI subdirs (armeabi-v7a, arm64-v8a, etc.)
     */
    fun injectNativeLibs(workDir: File, nativeLibsDir: File) {
        require(nativeLibsDir.exists() && nativeLibsDir.isDirectory) {
            "Native libs directory not found: ${nativeLibsDir.absolutePath}"
        }

        val destLibDir = File(workDir, "lib").apply { mkdirs() }

        // Copy each ABI subdirectory
        nativeLibsDir.listFiles()?.filter { it.isDirectory }?.forEach { abiDir ->
            val destAbiDir = File(destLibDir, abiDir.name).apply { mkdirs() }
            abiDir.listFiles()?.filter { it.extension == "so" }?.forEach { soFile ->
                soFile.copyTo(File(destAbiDir, soFile.name), overwrite = true)
            }
        }
    }

    // ─── Private ─────────────────────────────────────────────────────

    private fun addEntry(
        zip: ZipFile,
        file: File,
        baseParams: ZipParameters,
        workDir: File,
    ) {
        if (file.isDirectory) {
            file.listFiles()?.forEach { child ->
                addEntry(zip, child, baseParams, workDir)
            }
            return
        }

        val params = ZipParameters().apply {
            compressionMethod = if (shouldStore(file)) {
                CompressionMethod.STORE
            } else {
                CompressionMethod.DEFLATE
            }
            fileNameInZip = file.relativeTo(workDir).path.replace(File.separatorChar, '/')
        }

        zip.addFile(file, params)
    }

    private fun shouldStore(file: File): Boolean {
        val name = file.name
        return config.storeOnlyPatterns.any { pattern ->
            when {
                pattern.startsWith("*.") -> name.endsWith(pattern.removePrefix("*."))
                pattern.endsWith("/") -> "$name/".endsWith(pattern)
                else -> name == pattern
            }
        }
    }
}
