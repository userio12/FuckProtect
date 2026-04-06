package com.fuckprotect.protector.apk

import net.lingala.zip4j.ZipFile
import net.lingala.zip4j.model.FileHeader
import java.io.File

/**
 * Represents the extracted contents of an APK relevant to protection.
 */
data class ExtractedApk(
    /** Temporary directory holding extracted contents. */
    val workDir: File,
    /** DEX files found in the APK (classes.dex, classes2.dex, ...). */
    val dexFiles: List<File>,
    /** AndroidManifest.xml (binary AXML format). */
    val manifest: File?,
    /** Native libraries directory (lib/). */
    val nativeLibDir: File?,
    /** Assets directory. */
    val assetsDir: File?,
    /** Resource table. */
    val resourcesArsc: File?,
    /** Other entries (META-INF, res/, etc.) preserved during repackaging. */
    val otherEntries: List<String>,
    /** Original Application class name from manifest (null if not found). */
    var originalApplicationClass: String? = null,
    /** Package name from manifest. */
    var packageName: String = "",
)

/**
 * Parses and extracts APK files for protection processing.
 */
class ApkParser {

    /**
     * Extract an APK and parse its structure.
     *
     * @param apkFile The input APK file
     * @param outputDir Directory to extract contents to
     * @return [ExtractedApk] with all discovered components
     */
    fun extract(apkFile: File, outputDir: File): ExtractedApk {
        require(apkFile.exists()) { "APK file not found: ${apkFile.absolutePath}" }
        outputDir.mkdirs()

        // Extract the APK
        ZipFile(apkFile).use { zip ->
            zip.extractAll(outputDir.absolutePath)
        }

        // Discover DEX files
        val dexFiles = outputDir.listFiles { f ->
            f.name.endsWith(".dex")
        }?.toList()?.sortedWith(
            compareBy { f ->
                val name = f.nameWithoutExtension
                if (name == "classes") 0 else name.removePrefix("classes").toIntOrNull() ?: Int.MAX_VALUE
            }
        ) ?: emptyList()

        // Discover manifest
        val manifest = File(outputDir, "AndroidManifest.xml").takeIf { it.exists() }

        // Discover native libs
        val nativeLibDir = File(outputDir, "lib").takeIf { it.exists() && it.isDirectory }

        // Discover assets
        val assetsDir = File(outputDir, "assets").takeIf { it.exists() && it.isDirectory }

        // Discover resources
        val resourcesArsc = File(outputDir, "resources.arsc").takeIf { it.exists() }

        // List other entries (entries that are not DEX, manifest, or native libs)
        val otherEntries = outputDir.listFiles()?.filter { f ->
            f.name != "AndroidManifest.xml" &&
                    f.name != "resources.arsc" &&
                    !f.name.endsWith(".dex") &&
                    !(f.name == "lib" && f.isDirectory) &&
                    !(f.name == "assets" && f.isDirectory)
        }?.map { f ->
            f.name
        } ?: emptyList()

        return ExtractedApk(
            workDir = outputDir,
            dexFiles = dexFiles,
            manifest = manifest,
            nativeLibDir = nativeLibDir,
            assetsDir = assetsDir,
            resourcesArsc = resourcesArsc,
            otherEntries = otherEntries,
        )
    }

    /**
     * Parse the Application class name from AndroidManifest.xml.
     *
     * This is a basic XML text search. For production use, a proper
     * AXML parser should be used since the manifest is in binary format.
     */
    fun parseApplicationClass(extracted: ExtractedApk): String? {
        val manifest = extracted.manifest ?: return null
        return parseApplicationClassFromXml(manifest.readText())
    }

    /**
     * Parse the package name from AndroidManifest.xml.
     */
    fun parsePackageName(extracted: ExtractedApk): String {
        val manifest = extracted.manifest ?: return ""
        return parsePackageNameFromXml(manifest.readText())
    }

    /**
     * Parse all relevant info from extracted APK.
     */
    fun parseAll(extracted: ExtractedApk): ExtractedApk {
        extracted.originalApplicationClass = parseApplicationClass(extracted)
        extracted.packageName = parsePackageName(extracted)
        return extracted
    }

    // ─── Private: XML parsing helpers ─────────────────────────────────

    /**
     * Extract the android:name value from the <application> tag.
     * Handles both binary AXML (decoded to text) and plain XML.
     */
    internal fun parseApplicationClassFromXml(xmlContent: String): String? {
        // Look for android:name="..." within <application ...>
        // Binary AXML decoded by zip4j may appear as plain text

        val appTagRegex = Regex(
            """<application[^>]*android:name\s*=\s*"([^"]+)"""",
            RegexOption.IGNORE_CASE,
        )
        val match = appTagRegex.find(xmlContent)
        return match?.groupValues?.get(1)
    }

    /**
     * Extract the package attribute from the <manifest> tag.
     */
    internal fun parsePackageNameFromXml(xmlContent: String): String {
        val pkgRegex = Regex(
            """<manifest[^>]*package\s*=\s*"([^"]+)"""",
            RegexOption.IGNORE_CASE,
        )
        val match = pkgRegex.find(xmlContent)
        return match?.groupValues?.get(1) ?: ""
    }

    /**
     * List all entries in an APK without extracting.
     */
    fun listEntries(apkFile: File): List<String> {
        require(apkFile.exists()) { "APK file not found: ${apkFile.absolutePath}" }
        return ZipFile(apkFile).use { zip ->
            zip.fileHeaders.map { it.fileName }
        }
    }

    /**
     * Extract a single entry from an APK to a file.
     */
    fun extractEntry(apkFile: File, entryName: String, destFile: File) {
        require(apkFile.exists()) { "APK file not found: ${apkFile.absolutePath}" }
        ZipFile(apkFile).use { zip ->
            val header = zip.fileHeaders.find { it.fileName == entryName }
                ?: error("Entry not found: $entryName")
            zip.extractFile(header, destFile.parent, destFile.name)
        }
    }
}
