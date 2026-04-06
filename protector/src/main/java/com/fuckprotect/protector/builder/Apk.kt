package com.fuckprotect.protector.builder

import com.fuckprotect.protector.res.ManifestEditor
import com.fuckprotect.protector.util.FileUtils
import com.fuckprotect.protector.util.LogUtils
import com.fuckprotect.protector.util.ZipUtils
import net.lingala.zip4j.ZipFile
import java.io.File

/**
 * Represents an Android APK being protected.
 * Matches dpt-shell's builder.Apk pattern.
 */
class Apk private constructor(private val builder: Builder) {

    val filePath: String = builder.filePath
    val workspaceDir: File = builder.workspaceDir ?: createTempDir("fp_apk_")
    var sign: Boolean = builder.sign
    var verifySign: Boolean = builder.verifySign

    var dexFiles: List<File> = emptyList()
    var applicationName: String = ""
    var packageName: String = ""
    var manifestFile: File? = null
    var primaryDex: File? = null

    /**
     * Extract APK to working directory and parse manifest.
     */
    fun extract() {
        LogUtils.debug("Extracting APK: %s", filePath)

        // Extract APK (except manifest)
        ZipFile(filePath).use { zip ->
            zip.fileHeaders.forEach { header ->
                if (header.fileName != "AndroidManifest.xml") {
                    zip.extractFile(header, workspaceDir.absolutePath)
                }
            }
        }

        // Read manifest directly from APK
        manifestFile = File(workspaceDir, "AndroidManifest.xml")
        ZipFile(filePath).use { zip ->
            val header = zip.fileHeaders.find { it.fileName == "AndroidManifest.xml" }
            if (header != null) {
                zip.getInputStream(header).use { input ->
                    manifestFile!!.writeBytes(input.readBytes())
                }
            }
        }

        // Discover DEX files
        dexFiles = workspaceDir.listFiles { f ->
            f.name.endsWith(".dex")
        }?.toList()?.sortedWith(
            compareBy { f ->
                val name = f.nameWithoutExtension
                if (name == "classes") 0 else name.removePrefix("classes").toIntOrNull() ?: Int.MAX_VALUE
            }
        ) ?: emptyList()

        primaryDex = dexFiles.firstOrNull()

        // Parse manifest
        parseManifest()

        LogUtils.info("Extracted APK: %s", workspaceDir.absolutePath)
    }

    /**
     * Parse the AndroidManifest.xml for application name and package.
     */
    private fun parseManifest() {
        val manifest = manifestFile ?: return
        val xml = manifest.readText()

        // Simple regex-based parsing
        val appMatch = Regex("""android:name\s*=\s*"([^"]+)"""", RegexOption.IGNORE_CASE)
            .findAll(xml)
            .firstOrNull { match ->
                val beforeMatch = xml.substring(0, match.range.first)
                beforeMatch.contains("<application", ignoreCase = true)
            }
        applicationName = appMatch?.groupValues?.get(1) ?: ""

        val pkgMatch = Regex("""package\s*=\s*"([^"]+)"""", RegexOption.IGNORE_CASE).find(xml)
        packageName = pkgMatch?.groupValues?.get(1) ?: ""

        if (applicationName.startsWith(".")) {
            applicationName = packageName + applicationName
        }

        LogUtils.debug("Application: %s, Package: %s", applicationName, packageName)
    }

    /**
     * Hijack the manifest to replace Application class with shell.
     */
    fun hijackManifest() {
        val manifest = manifestFile ?: return
        ManifestEditor.hijackApplicationInPlace(manifest, applicationName)
        LogUtils.info("Manifest hijacked: %s -> ShellApplication", applicationName)
    }

    /**
     * Build the protected APK.
     */
    fun buildPackage(originPackagePath: String, unpackFilePath: String, savePath: String) {
        LogUtils.info("Building protected package...")
        val outputDir = File(savePath)
        val resultFile = File(outputDir, "unsigned.apk")

        // Zip everything from unpacked directory
        ZipFile(resultFile).use { zip ->
            workspaceDir.listFiles()?.forEach { file ->
                if (file.isFile) {
                    zip.addFile(file)
                } else if (file.isDirectory) {
                    addDirectory(zip, file, file.name)
                }
            }
        }

        LogUtils.info("Package built: %s", resultFile.absolutePath)
    }

    /**
     * Sign the APK.
     */
    fun sign(keystoreFile: File, storePass: String, keyAlias: String, keyPass: String, outputFile: File) {
        // Signing is done by the caller via ApkSigner
    }

    private fun addDirectory(zip: ZipFile, dir: File, basePath: String) {
        dir.listFiles()?.forEach { file ->
            if (file.isFile) {
                zip.addFile(file)
            } else {
                addDirectory(zip, file, "$basePath/${file.name}")
            }
        }
    }

    private fun createTempDir(prefix: String): File {
        return File.createTempFile(prefix, "").apply { delete(); mkdir() }
    }

    /**
     * Builder pattern matching dpt-shell's Apk.Builder.
     */
    class Builder {
        var filePath: String = ""
        var workspaceDir: File? = null
        var sign: Boolean = true
        var verifySign: Boolean = false

        fun filePath(path: String) = apply { this.filePath = path }
        fun workspaceDir(dir: File?) = apply { this.workspaceDir = dir }
        fun sign(sign: Boolean) = apply { this.sign = sign }
        fun verifySign(verify: Boolean) = apply { this.verifySign = verify }

        fun build() = Apk(this)
    }
}
