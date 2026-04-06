package com.fuckprotect.protector.res

import com.fuckprotect.common.Constants
import java.io.File

/**
 * Edits AndroidManifest.xml to inject the shell Application class and
 * preserve the original Application class name as metadata.
 */
class ManifestEditor {

    /**
     * Modify the manifest to replace the Application class with the shell
     * Application and store the original class name as metadata.
     */
    fun hijackApplication(manifestXml: String, originalAppClass: String): String {
        val shellAppClass = Constants.SHELL_APPLICATION_CLASS
        var modified = manifestXml

        modified = modified.replaceFirst(
            Regex("""(android:name\s*=\s*")([^"]+)(")""", RegexOption.IGNORE_CASE),
            "$1$shellAppClass$3",
        )

        val metaDataTag =
            """<meta-data android:name="${Constants.META_ORIGINAL_APP_CLASS}" android:value="$originalAppClass" />"""

        modified = modified.replaceFirst(
            Regex("""(<application[^>]*>)""", RegexOption.IGNORE_CASE),
            "$1\n    $metaDataTag",
        )

        val versionTag =
            """<meta-data android:name="${Constants.META_PROTECTOR_VERSION}" android:value="1.0.0" />"""

        modified = modified.replaceFirst(
            Regex("""(<application[^>]*>)""", RegexOption.IGNORE_CASE),
            "$1\n    $versionTag",
        )

        return modified
    }

    /**
     * Modify the manifest file in place.
     */
    fun hijackApplicationInPlace(manifestFile: File, originalAppClass: String) {
        require(manifestFile.exists()) { "Manifest file not found: ${manifestFile.absolutePath}" }
        val content = manifestFile.readText()
        val modified = hijackApplication(content, originalAppClass)
        manifestFile.writeText(modified)
    }

    /**
     * Verify that the manifest has been hijacked correctly.
     */
    fun verifyHijack(manifestXml: String): HijackVerification {
        val hasShellApp = manifestXml.contains(Constants.SHELL_APPLICATION_CLASS, ignoreCase = true)
        val hasMetaData = manifestXml.contains(Constants.META_ORIGINAL_APP_CLASS, ignoreCase = true)
        val hasVersionMeta = manifestXml.contains(Constants.META_PROTECTOR_VERSION, ignoreCase = true)
        return HijackVerification(hasShellApp, hasMetaData, hasVersionMeta, hasShellApp && hasMetaData)
    }

    fun parseApplicationClassFromXml(xml: String): String? {
        val nameRegex = Regex("""android:name\s*=\s*"([^"]+)""", RegexOption.IGNORE_CASE)
        val appRegex = Regex("""<application[^>]*>""", RegexOption.IGNORE_CASE)
        val appMatches = appRegex.findAll(xml).toList()
        if (appMatches.isEmpty()) return null
        val appTag = appMatches.first().value
        val nameInTag = nameRegex.find(appTag)
        if (nameInTag != null) return nameInTag.groupValues[1]
        val appStart = appMatches.first().range.last
        return nameRegex.findAll(xml).firstOrNull { it.range.first > appStart }?.groupValues?.get(1)
    }

    fun parsePackageNameFromXml(xml: String): String {
        val regex = Regex("""package\s*=\s*"([^"]+)""", RegexOption.IGNORE_CASE)
        return regex.find(xml)?.groupValues?.get(1) ?: ""
    }

    companion object {
        @JvmStatic
        fun hijackApplicationInPlace(manifestFile: File, originalAppClass: String) {
            ManifestEditor().hijackApplicationInPlace(manifestFile, originalAppClass)
        }

        @JvmStatic
        fun hijackApplication(manifestXml: String, originalAppClass: String): String {
            return ManifestEditor().hijackApplication(manifestXml, originalAppClass)
        }
    }
}

data class HijackVerification(
    val hasShellApplication: Boolean,
    val hasMetaData: Boolean,
    val hasVersionMeta: Boolean,
    val isValid: Boolean,
)
