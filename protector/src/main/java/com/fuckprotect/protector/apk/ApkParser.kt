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

        // Extract all entries EXCEPT AndroidManifest.xml (we'll handle it specially)
        ZipFile(apkFile).use { zip ->
            zip.fileHeaders.forEach { header ->
                if (header.fileName != "AndroidManifest.xml") {
                    zip.extractFile(header, outputDir.absolutePath)
                }
            }
        }

        // Read AndroidManifest.xml directly from APK to preserve original format
        val manifest = readManifestDirectly(apkFile, outputDir)

        // Discover DEX files
        val dexFiles = outputDir.listFiles { f ->
            f.name.endsWith(".dex")
        }?.toList()?.sortedWith(
            compareBy { f ->
                val name = f.nameWithoutExtension
                if (name == "classes") 0 else name.removePrefix("classes").toIntOrNull() ?: Int.MAX_VALUE
            }
        ) ?: emptyList()

        // Discover native libs
        val nativeLibDir = File(outputDir, "lib").takeIf { it.exists() && it.isDirectory }

        // Discover assets
        val assetsDir = File(outputDir, "assets").takeIf { it.exists() && it.isDirectory }

        // Discover resources
        val resourcesArsc = File(outputDir, "resources.arsc").takeIf { it.exists() }

        // List other entries
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
     * Read AndroidManifest.xml directly from APK to avoid zip4j decompression issues.
     */
    private fun readManifestDirectly(apkFile: File, outputDir: File): File? {
        val manifestFile = File(outputDir, "AndroidManifest.xml")

        try {
            ZipFile(apkFile).use { zip ->
                val header = zip.fileHeaders.find { it.fileName == "AndroidManifest.xml" }
                    ?: return@use

                // Read raw bytes from the ZIP entry
                zip.getInputStream(header).use { inputStream ->
                    val bytes = inputStream.readBytes()
                    manifestFile.writeBytes(bytes)
                }
            }
        } catch (e: Exception) {
            System.err.println("DEBUG: Failed to read manifest directly: ${e.message}")
        }

        return manifestFile.takeIf { it.exists() && it.length() > 0 }
    }

    /**
     * Parse the Application class name from AndroidManifest.xml.
     *
     * Handles binary AXML format (with or without AXML magic prefix),
     * zlib-compressed manifest, and plain XML.
     */
    fun parseApplicationClass(extracted: ExtractedApk): String? {
        val manifest = extracted.manifest ?: return null
        var bytes = manifest.readBytes()
        System.err.println("DEBUG: Manifest size: ${bytes.size} bytes")
        System.err.println("DEBUG: First 16 bytes: ${bytes.take(16).joinToString(" ") { "%02x".format(it) }}")

        // Try to decompress if it looks like zlib/deflate compressed AXML
        if (bytes.size >= 2 && bytes[0] == 0x78.toByte() &&
            (bytes[1] == 0x9C.toByte() || bytes[1] == 0x01.toByte() || bytes[1] == 0xDA.toByte())) {
            try {
                bytes = java.util.zip.InflaterInputStream(bytes.inputStream()).use { it.readBytes() }
                System.err.println("DEBUG: Decompressed to ${bytes.size} bytes")
                System.err.println("DEBUG: First 8 bytes after decompress: ${bytes.take(8).joinToString(" ") { "%02x".format(it) }}")
            } catch (e: Exception) {
                System.err.println("DEBUG: Decompression failed: ${e.message}")
            }
        }

        // Check if it's binary AXML format:
        // 1. Starts with "AXML\x00\x00\x00\x00" magic
        // 2. Starts with RES_XML_TYPE header (0x0003 little-endian)
        val hasAxmlMagic = bytes.size >= 8 &&
            bytes[0] == 0x41.toByte() && bytes[1] == 0x58.toByte() &&
            bytes[2] == 0x4D.toByte() && bytes[3] == 0x4C.toByte()
        val hasXmlHeader = bytes.size >= 8 &&
            bytes[0] == 0x03.toByte() && bytes[1] == 0x00.toByte() && // RES_XML_TYPE
            bytes[2] == 0x08.toByte() && bytes[3] == 0x00.toByte()     // headerSize = 8
        val isAxml = hasAxmlMagic || hasXmlHeader

        System.err.println("DEBUG: Has AXML magic: $hasAxmlMagic, Has XML header: $hasXmlHeader, Is AXML: $isAxml")

        if (isAxml) {
            // If it has the AXML magic prefix, strip it to get the ResChunk header
            if (hasAxmlMagic && bytes.size > 8) {
                bytes = bytes.copyOfRange(8, bytes.size)
                System.err.println("DEBUG: Stripped AXML magic, remaining: ${bytes.size} bytes")
            }
            return parseApplicationClassFromAxml(bytes)
        }

        // Try to decode as text
        val xmlText = tryDecodeAsText(bytes)
        System.err.println("DEBUG: Decoded text length: ${xmlText.length}")
        System.err.println("DEBUG: First 100 chars: ${xmlText.take(100).map { if (it.isISOControl()) '?' else it }.joinToString("")}")

        return parseApplicationClassFromXml(xmlText)
    }

    /**
     * Try to decode bytes as UTF-8 or UTF-16 text.
     */
    private fun tryDecodeAsText(bytes: ByteArray): String {
        // Try UTF-8 first
        return try {
            bytes.decodeToString()
        } catch (_: Exception) {
            // Try UTF-16
            try {
                String(bytes, Charsets.UTF_16)
            } catch (_: Exception) {
                String(bytes, Charsets.ISO_8859_1)
            }
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
     */
    private fun parseApplicationClassFromAxml(bytes: ByteArray): String? {
        try {
            val strings = extractStringPool(bytes)
            if (strings.isEmpty()) return null

            // Find "application" string index
            val appStrIdx = strings.indexOfFirst { it == "application" }
            if (appStrIdx < 0) return null

            // Find "name" string index
            val nameStrIdx = strings.indexOfFirst { it == "name" }
            if (nameStrIdx < 0) return null

            // Scan XML tree for <application> start tag with name attribute
            var i = 8
            while (i < bytes.size - 8) {
                val chunkType = readInt32(bytes, i)
                val chunkSize = readInt32(bytes, i + 4)
                if (chunkSize <= 0 || i + chunkSize > bytes.size) {
                    i += 4
                    continue
                }

                if (chunkType == 0x00100102) {
                    // Start element tag
                    val elemNameIdx = readInt32(bytes, i + 20)
                    if (elemNameIdx == appStrIdx) {
                        // Found <application> tag - look for "name" attribute
                        val attrCount = readInt32(bytes, i + 28)
                        val attrStart = i + 36
                        for (a in 0 until attrCount) {
                            val off = attrStart + a * 20
                            if (off + 20 > i + chunkSize) break
                            val attrNameIdx = readInt32(bytes, off + 4)
                            if (attrNameIdx == nameStrIdx) {
                                val rawValue = readInt32(bytes, off + 8)
                                val dataVal = readInt32(bytes, off + 16)
                                val strIdx = if (rawValue != -1) rawValue else dataVal
                                if (strIdx >= 0 && strIdx < strings.size) {
                                    return strings[strIdx]
                                }
                            }
                        }
                        // No name attribute found - app uses default Application
                        // Find the main Activity class and use its package + default Application
                        return findDefaultApplicationFromAxml(bytes, strings)
                    }
                }

                i += chunkSize
            }
        } catch (_: Exception) {
        }
        return null
    }

    /**
     * When no custom Application is declared, find the main Activity's package
     * and return "android.app.Application" as the default.
     */
    private fun findDefaultApplicationFromAxml(
        bytes: ByteArray,
        strings: List<String>,
    ): String? {
        // Find "activity" string index
        val activityStrIdx = strings.indexOfFirst { it == "activity" }
        if (activityStrIdx < 0) return "android.app.Application"

        // Find main activity class (the one with LAUNCHER intent filter)
        var i = 8
        while (i < bytes.size - 8) {
            val chunkType = readInt32(bytes, i)
            val chunkSize = readInt32(bytes, i + 4)
            if (chunkSize <= 0 || i + chunkSize > bytes.size) {
                i += 4
                continue
            }
            if (chunkType == 0x00100102) {
                val elemNameIdx = readInt32(bytes, i + 20)
                if (elemNameIdx == activityStrIdx) {
                    // Found <activity> - look for name attribute
                    val attrCount = readInt32(bytes, i + 28)
                    val attrStart = i + 36
                    for (a in 0 until attrCount) {
                        val off = attrStart + a * 20
                        if (off + 20 > i + chunkSize) break
                        val attrNameIdx = readInt32(bytes, off + 4)
                        val nameStrIdx = strings.indexOfFirst { it == "name" }
                        if (attrNameIdx == nameStrIdx) {
                            val rawValue = readInt32(bytes, off + 8)
                            val dataVal = readInt32(bytes, off + 16)
                            val strIdx = if (rawValue != -1) rawValue else dataVal
                            if (strIdx >= 0 && strIdx < strings.size) {
                                val activityClass = strings[strIdx]
                                // Extract package from activity class
                                val pkg = activityClass.substringBeforeLast(".", "")
                                return if (activityClass.startsWith(".")) {
                                    "$pkg$activityClass"
                                } else {
                                    activityClass
                                }
                            }
                        }
                    }
                }
            }
            i += chunkSize
        }
        return "android.app.Application"
    }

    private fun parsePackageNameFromAxml(bytes: ByteArray): String {
        try {
            val strings = extractStringPool(bytes)
            if (strings.isEmpty()) return ""

            for (s in strings) {
                if (s.contains(".") && s.all { it.isLetterOrDigit() || it == '.' || it == '_' } &&
                    s.length > 3 && s[0].isLetter()) {
                    if (s.startsWith("com.") || s.startsWith("org.") ||
                        s.startsWith("net.") || s.startsWith("io.")) {
                        return s
                    }
                }
            }
        } catch (_: Exception) {
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
