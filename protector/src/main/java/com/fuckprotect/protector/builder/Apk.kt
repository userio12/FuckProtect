package com.fuckprotect.protector.builder

import com.fuckprotect.protector.res.ManifestEditor
import com.fuckprotect.protector.util.ApkSigner
import net.lingala.zip4j.ZipFile
import java.io.File

/**
 * Represents an Android APK being protected.
 *
 * Matches dpt-shell's builder.Apk pattern:
 * - Extract APK to working directory
 * - Parse manifest for application name
 * - Hollow methods
 * - Repackage and sign
 */
class Apk private constructor(private val builder: Builder) {

    val filePath: String = builder.filePath
    val outputPath: String? = builder.outputPath
    val shouldSign: Boolean = builder.sign
    val debuggable: Boolean = builder.debuggable
    val verifySign: Boolean = builder.verifySign

    private var workDir: File? = null
    var dexFiles: List<File> = emptyList()
    var originalApplication: String = ""
    var packageName: String = ""
    var manifestFile: File? = null
    var primaryDex: File? = null

    /**
     * Extract APK to working directory and parse manifest.
     */
    fun extract(): Apk {
        workDir = builder.workspaceDir ?: createTempDir("fp_apk_")

        // Extract APK
        ZipFile(filePath).use { zip ->
            zip.fileHeaders.forEach { header ->
                if (header.fileName != "AndroidManifest.xml") {
                    zip.extractFile(header, workDir!!.absolutePath)
                }
            }
        }

        // Read manifest directly from APK
        val manifestFile = File(workDir!!, "AndroidManifest.xml")
        ZipFile(filePath).use { zip ->
            val header = zip.fileHeaders.find { it.fileName == "AndroidManifest.xml" }
            if (header != null) {
                zip.getInputStream(header).use { input ->
                    manifestFile.writeBytes(input.readBytes())
                }
            }
        }
        this.manifestFile = manifestFile

        // Discover DEX files
        dexFiles = workDir!!.listFiles { f ->
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

        return this
    }

    /**
     * Parse the AndroidManifest.xml for application name and package.
     */
    private fun parseManifest() {
        val manifest = manifestFile ?: return
        val bytes = manifest.readBytes()

        // Check for AXML format
        if (bytes.size >= 8 &&
            bytes[0] == 0x03.toByte() && bytes[1] == 0x00.toByte() &&
            bytes[2] == 0x08.toByte() && bytes[3] == 0x00.toByte()) {
            // Binary AXML - parse with our AXML parser
            val parser = AxmlParser(bytes)
            originalApplication = parser.getApplicationName()
            packageName = parser.getPackageName()
        } else if (bytes.size >= 8 &&
            bytes[0] == 0x41.toByte() && bytes[1] == 0x58.toByte()) {
            // AXML with magic prefix
            val parser = AxmlParser(bytes.copyOfRange(8, bytes.size))
            originalApplication = parser.getApplicationName()
            packageName = parser.getPackageName()
        } else {
            // Plain XML
            val xml = bytes.decodeToString()
            val appMatch = Regex("""android:name\s*=\s*"([^"]+)"""", RegexOption.IGNORE_CASE)
                .findAll(xml).firstOrNull {
                    xml.indexOf("<application", it.range.first, ignoreCase = true) < it.range.first
                }
            originalApplication = appMatch?.groupValues?.get(1) ?: ""
            val pkgMatch = Regex("""package\s*=\s*"([^"]+)"""", RegexOption.IGNORE_CASE).find(xml)
            packageName = pkgMatch?.groupValues?.get(1) ?: ""
        }

        if (originalApplication.startsWith(".")) {
            originalApplication = packageName + originalApplication
        }
    }

    /**
     * Hijack the manifest to replace Application class.
     */
    fun hijackManifest() {
        val manifest = manifestFile ?: return
        val xml = manifest.readText()
        val modified = ManifestEditor.hijackApplication(xml, originalApplication)
        manifest.writeText(modified)
    }

    /**
     * Repackage the APK.
     */
    fun repackage(outputFile: File) {
        ZipFile(outputFile).use { zip ->
            workDir!!.listFiles()?.forEach { file ->
                if (file.isFile) {
                    zip.addFile(file)
                } else if (file.isDirectory) {
                    addDirectoryToZip(zip, file, file.name)
                }
            }
        }
    }

    /**
     * Sign the APK.
     */
    fun sign(keystoreFile: File, storePass: String, keyAlias: String, keyPass: String) {
        val signer = ApkSigner()
        val tempFile = File.createTempFile("fp_unsigned", ".apk")
        outputFile.copyTo(tempFile, overwrite = true)
        signer.signApkJar(
            tempFile, outputFile,
            ApkSigner.KeystoreConfig(keystoreFile, storePass, keyAlias, keyPass)
        )
        tempFile.delete()
    }

    private fun addDirectoryToZip(zip: ZipFile, dir: File, basePath: String) {
        dir.listFiles()?.forEach { file ->
            if (file.isFile) {
                zip.addFile(file)
            } else {
                addDirectoryToZip(zip, file, "$basePath/${file.name}")
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
        var outputPath: String? = null
        var workspaceDir: File? = null
        var sign: Boolean = true
        var debuggable: Boolean = false
        var verifySign: Boolean = false

        fun filePath(path: String) = apply { this.filePath = path }
        fun outputPath(path: String?) = apply { this.outputPath = path }
        fun workspaceDir(dir: File?) = apply { this.workspaceDir = dir }
        fun sign(sign: Boolean) = apply { this.sign = sign }
        fun debuggable(debuggable: Boolean) = apply { this.debuggable = debuggable }
        fun verifySign(verify: Boolean) = apply { this.verifySign = verify }

        fun build() = Apk(this)
    }
}
