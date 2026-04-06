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
     * Handles binary AXML format (the default) and falls back to plain XML.
     */
    fun parseApplicationClass(extracted: ExtractedApk): String? {
        val manifest = extracted.manifest ?: return null
        val bytes = manifest.readBytes()
        // Check if it's binary AXML (starts with AXML\x00\x00\x00\x00)
        return if (bytes.size >= 8 &&
            bytes[0] == 0x41.toByte() && bytes[1] == 0x58.toByte() &&
            bytes[2] == 0x4D.toByte() && bytes[3] == 0x4C.toByte()
        ) {
            parseApplicationClassFromAxml(bytes)
        } else {
            parseApplicationClassFromXml(bytes.decodeToString())
        }
    }

    /**
     * Parse the package name from AndroidManifest.xml.
     */
    fun parsePackageName(extracted: ExtractedApk): String {
        val manifest = extracted.manifest ?: return ""
        val bytes = manifest.readBytes()
        return if (bytes.size >= 8 &&
            bytes[0] == 0x41.toByte() && bytes[1] == 0x58.toByte() &&
            bytes[2] == 0x4D.toByte() && bytes[3] == 0x4C.toByte()
        ) {
            parsePackageNameFromAxml(bytes)
        } else {
            parsePackageNameFromXml(bytes.decodeToString())
        }
    }

    /**
     * Parse all relevant info from extracted APK.
     */
    fun parseAll(extracted: ExtractedApk): ExtractedApk {
        extracted.originalApplicationClass = parseApplicationClass(extracted)
        extracted.packageName = parsePackageName(extracted)
        return extracted
    }

    // ─── Private: Binary AXML parsing ────────────────────────────────

    /**
     * Minimal AXML parser that extracts string pool and finds attributes.
     *
     * AXML format:
     * - Header: "AXML\x00\x00\x00\x00" + size
     * - String pool: chunk header + string count + strings
     * - Resource IDs
     * - XML tree: StartTag, EndTag, Text, etc.
     *
     * This parser extracts the string pool then scans for android:name attributes
     * inside <application> tags.
     */
    private fun parseApplicationClassFromAxml(bytes: ByteArray): String? {
        try {
            val strings = extractStringPool(bytes)
            if (strings.isEmpty()) return null

            // Scan for application tag and android:name attribute
            // AXML chunk type: StartTag = 0x00100102
            // android:name resource ID = 0x01010003
            var inApplication = false
            var i = 0
            while (i < bytes.size - 8) {
                val chunkType = readInt32(bytes, i)
                val chunkSize = readInt32(bytes, i + 4)
                if (chunkSize <= 0 || i + chunkSize > bytes.size) {
                    i += 4
                    continue
                }

                if (chunkType == 0x00100102) {
                    // Start element tag
                    // +8: lineNumber, +12: comment string index (skip)
                    // +16: namespace URI index, +20: name index
                    val nameIdx = readInt32(bytes, i + 20)
                    if (nameIdx >= 0 && nameIdx < strings.size &&
                        strings[nameIdx] == "application") {
                        inApplication = true
                    }

                    // Parse attributes: +24: attribute start, +26: attribute size,
                    // +28: attribute count
                    if (i + 28 < bytes.size) {
                        val attrCount = readInt32(bytes, i + 28)
                        val attrStart = i + 36 // +28 + 8 (attributeStart + attributeSize)
                        for (a in 0 until attrCount) {
                            val off = attrStart + a * 20
                            if (off + 20 > i + chunkSize) break
                            val nsIdx = readInt32(bytes, off)      // namespace
                            val nameIdx2 = readInt32(bytes, off + 4) // name
                            val rawType = readInt32(bytes, off + 8) // rawValue
                            val typedVal = readInt32(bytes, off + 16) // typedData

                            // android namespace = 0x01010000 range
                            // android:name = 0x01010003
                            if (nsIdx == 0 && nameIdx2 == 3) { // android:name (resource ID 0x01010003)
                                // rawValue or data is the string index
                                val strIdx = if (rawType != -1) rawType else typedVal
                                if (strIdx >= 0 && strIdx < strings.size) {
                                    if (inApplication) {
                                        return strings[strIdx]
                                    }
                                }
                            }
                        }
                    }
                } else if (chunkType == 0x00100103) {
                    // End element tag
                    if (inApplication) {
                        val nameIdx = readInt32(bytes, i + 20)
                        if (nameIdx >= 0 && nameIdx < strings.size &&
                            strings[nameIdx] == "application") {
                            inApplication = false
                        }
                    }
                }

                i += chunkSize
            }
        } catch (_: Exception) {
            // Fall through
        }
        return null
    }

    private fun parsePackageNameFromAxml(bytes: ByteArray): String {
        try {
            val strings = extractStringPool(bytes)
            if (strings.isEmpty()) return ""

            // Package name is usually in the manifest's package attribute
            // Resource ID for package = 0x01010000 (android:package in <manifest>)
            // But actually the package is at a different location in AXML
            // For simplicity, try to find strings that look like package names
            for (s in strings) {
                if (s.contains(".") && s.all { it.isLetterOrDigit() || it == '.' || it == '_' } &&
                    s.length > 3 && s[0].isLetter()) {
                    // Heuristic: first plausible package-like string
                    if (s.startsWith("com.") || s.startsWith("org.") ||
                        s.startsWith("net.") || s.startsWith("io.")) {
                        return s
                    }
                }
            }
        } catch (_: Exception) {
            // Fall through
        }
        return ""
    }

    /**
     * Extract the string pool from AXML.
     */
    private fun extractStringPool(bytes: ByteArray): List<String> {
        // Find string pool chunk: starts with 0x001C0001 (RES_STRING_POOL_TYPE)
        var i = 8 // Skip AXML header
        while (i < bytes.size - 8) {
            val chunkType = readInt32(bytes, i)
            val chunkSize = readInt32(bytes, i + 4)
            if (chunkType == 0x001C0001 && chunkSize > 0 && i + chunkSize <= bytes.size) {
                return parseStringPoolChunk(bytes, i, chunkSize)
            }
            if (chunkSize <= 0) {
                i += 4
            } else {
                i += chunkSize
            }
        }
        return emptyList()
    }

    private fun parseStringPoolChunk(
        bytes: ByteArray,
        offset: Int,
        size: Int,
    ): List<String> {
        val stringCount = readInt32(bytes, offset + 8)
        val styleCount = readInt32(bytes, offset + 12)
        val flags = readInt32(bytes, offset + 16)
        val stringsStart = readInt32(bytes, offset + 20)
        val stylesStart = readInt32(bytes, offset + 24)

        val isUtf8 = (flags and 0x100) != 0
        val strings = mutableListOf<String>()

        val baseOffset = offset + stringsStart
        // Read string offsets
        val strOffsets = IntArray(stringCount) { j ->
            readInt32(bytes, offset + 28 + j * 4)
        }

        for (j in 0 until stringCount) {
            val strOffset = baseOffset + strOffsets[j]
            if (strOffset >= bytes.size) {
                strings.add("")
                continue
            }
            if (isUtf8) {
                // UTF-8: skip length encoding (1 or 2 bytes)
                var pos = strOffset
                val len = if (bytes[pos] >= 0) {
                    bytes[pos].toInt()
                } else {
                    ((bytes[pos].toInt() and 0x7F) shl 8) or (bytes[pos + 1].toInt() and 0xFF)
                }
                pos += if (bytes[strOffset] >= 0) 1 else 2
                // Skip UTF-8 length byte
                pos += if (bytes[pos] >= 0) 1 else 2
                if (pos + len > bytes.size) {
                    strings.add("")
                    continue
                }
                strings.add(bytes.copyOfRange(pos, pos + len).decodeToString())
            } else {
                // UTF-16
                val len = if (bytes[strOffset] >= 0) {
                    bytes[strOffset].toInt() or (bytes[strOffset + 1].toInt() shl 8)
                } else {
                    ((bytes[strOffset].toInt() and 0xFF) or (bytes[strOffset + 1].toInt() shl 8)) or
                        ((bytes[strOffset + 2].toInt() shl 16) or (bytes[strOffset + 3].toInt() shl 24))
                }
                val charCount = if (bytes[strOffset] >= 0) {
                    bytes[strOffset].toInt() or (bytes[strOffset + 1].toInt() shl 8)
                } else {
                    ((bytes[strOffset + 2].toInt() and 0xFF) or (bytes[strOffset + 3].toInt() shl 8))
                }
                val startPos = strOffset + if (len > 0x7FFF) 4 else 2
                if (startPos + charCount * 2 > bytes.size) {
                    strings.add("")
                    continue
                }
                val sb = StringBuilder(charCount)
                for (c in 0 until charCount) {
                    val lo = bytes[startPos + c * 2].toInt() and 0xFF
                    val hi = bytes[startPos + c * 2 + 1].toInt() and 0xFF
                    sb.append((hi shl 8 or lo).toChar())
                }
                strings.add(sb.toString())
            }
        }

        return strings
    }

    private fun readInt32(bytes: ByteArray, offset: Int): Int {
        if (offset + 4 > bytes.size) return 0
        return (bytes[offset].toInt() and 0xFF) or
                ((bytes[offset + 1].toInt() and 0xFF) shl 8) or
                ((bytes[offset + 2].toInt() and 0xFF) shl 16) or
                ((bytes[offset + 3].toInt() and 0xFF) shl 24)
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
