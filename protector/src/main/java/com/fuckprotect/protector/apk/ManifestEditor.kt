package com.fuckprotect.protector.apk

import com.fuckprotect.common.Constants
import java.io.File

/**
 * Edits AndroidManifest.xml to inject the shell Application class and
 * preserve the original Application class name as metadata.
 *
 * Since AndroidManifest.xml is in binary AXML format, this class uses
 * a text-based approach: it works on the decoded text representation
 * produced by zip4j extraction, then the repackager re-encodes it.
 *
 * For a more robust implementation, a proper AXML binary parser should
 * be used to avoid losing binary-specific metadata.
 */
class ManifestEditor {

    /**
     * Modify the manifest to replace the Application class with the shell
     * Application and store the original class name as metadata.
     *
     * @param manifestXml The manifest content (text or decoded AXML)
     * @param originalAppClass The original Application class name
     * @return Modified manifest content
     */
    fun hijackApplication(manifestXml: String, originalAppClass: String): String {
        val shellAppClass = Constants.SHELL_APPLICATION_CLASS

        var modified = manifestXml

        // Replace the original android:name in the <application> tag
        // Pattern 1: android:name="com.example.MyApp"
        modified = modified.replaceFirst(
            Regex("""(android:name\s*=\s*")([^"]+)(")""", RegexOption.IGNORE_CASE),
            "$1$shellAppClass$3",
        )

        // Add meta-data for original Application class inside <application>
        val metaDataTag =
            """<meta-data android:name="${Constants.META_ORIGINAL_APP_CLASS}" android:value="$originalAppClass" />"""

        // Insert after the opening <application ...> tag
        modified = modified.replaceFirst(
            Regex("""(<application[^>]*/>)""", RegexOption.IGNORE_CASE),
            "$1\n    $metaDataTag",
        ).replaceFirst(
            Regex("""(<application[^>]*>)""", RegexOption.IGNORE_CASE),
            "$1\n    $metaDataTag",
        )

        // Add protector version metadata
        val versionTag =
            """<meta-data android:name="${Constants.META_PROTECTOR_VERSION}" android:value="1.0.0" />"""

        modified = modified.replaceFirst(
            Regex("""(<application[^>]*>)""", RegexOption.IGNORE_CASE),
            "$1\n    $versionTag",
        )

        return modified
    }

    /**
     * Set the AppComponentFactory in the <application> tag.
     *
     * On Android 9+ (API 28+), the appComponentFactory attribute is used
     * to intercept all component creation. This is more reliable than
     * hijacking the Application class.
     *
     * @param manifestXml The manifest content
     * @param originalFactory The original AppComponentFactory class name (or empty if none)
     * @return Modified manifest content
     */
    fun hijackComponentFactory(manifestXml: String, originalFactory: String): String {
        val shellFactory = Constants.SHELL_COMPONENT_FACTORY

        var modified = manifestXml

        // If there's already an appComponentFactory attribute, replace it
        val hasFactory = modified.contains(
            Regex("""android:appComponentFactory\s*=""", RegexOption.IGNORE_CASE)
        )

        if (hasFactory) {
            modified = modified.replaceFirst(
                Regex("""(android:appComponentFactory\s*=\s*")([^"]+)(")""", RegexOption.IGNORE_CASE),
                "$1$shellFactory$3",
            )
        } else {
            // Add the attribute to the <application> tag
            modified = modified.replaceFirst(
                Regex("""(<application\s+)""", RegexOption.IGNORE_CASE),
                """$1android:appComponentFactory="$shellFactory" """,
            )
        }

        // Store the original factory name as metadata
        if (originalFactory.isNotEmpty()) {
            val factoryMetaTag =
                """<meta-data android:name="${Constants.META_ORIGINAL_FACTORY}" android:value="$originalFactory" />"""
            modified = modified.replaceFirst(
                Regex("""(<application[^>]*>)""", RegexOption.IGNORE_CASE),
                "$1\n    $factoryMetaTag",
            )
        }

        return modified
    }

    /**
     * Extract the appComponentFactory value from the manifest.
     */
    fun getAppComponentFactory(xml: String): String? {
        val regex = Regex(
            """android:appComponentFactory\s*=\s*"([^"]+)""",
            RegexOption.IGNORE_CASE,
        )
        return regex.find(xml)?.groupValues?.get(1)
    }

    /**
     * Modify the manifest file in place.
     *
     * @param manifestFile The AndroidManifest.xml file
     * @param originalAppClass The original Application class name
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
        val hasShellApp = manifestXml.contains(
            Constants.SHELL_APPLICATION_CLASS,
            ignoreCase = true,
        )
        val hasMetaData = manifestXml.contains(
            Constants.META_ORIGINAL_APP_CLASS,
            ignoreCase = true,
        )
        val hasVersionMeta = manifestXml.contains(
            Constants.META_PROTECTOR_VERSION,
            ignoreCase = true,
        )

        return HijackVerification(
            hasShellApplication = hasShellApp,
            hasMetaData = hasMetaData,
            hasVersionMeta = hasVersionMeta,
            isValid = hasShellApp && hasMetaData,
        )
    }

    /**
     * Extract the android:name value from the <application> tag.
     */
    fun parseApplicationClassFromXml(xml: String): String? {
        val nameRegex = Regex("""android:name\s*=\s*"([^"]+)""", RegexOption.IGNORE_CASE)
        val appRegex = Regex("""<application[^>]*>""", RegexOption.IGNORE_CASE)
        val appMatches = appRegex.findAll(xml).toList()
        if (appMatches.isEmpty()) return null

        // First try to find android:name INSIDE the opening <application> tag
        val appTag = appMatches.first().value
        val nameInTag = nameRegex.find(appTag)
        if (nameInTag != null) {
            return nameInTag.groupValues[1]
        }

        // Otherwise look for android:name after the opening tag
        val appStart = appMatches.first().range.last
        val nameMatch = nameRegex.findAll(xml).firstOrNull { it.range.first > appStart }
        return nameMatch?.groupValues?.get(1)
    }

    /**
     * Extract the package attribute from the <manifest> tag.
     */
    fun parsePackageNameFromXml(xml: String): String {
        val regex = Regex("""package\s*=\s*"([^"]+)""", RegexOption.IGNORE_CASE)
        return regex.find(xml)?.groupValues?.get(1) ?: ""
    }

    data class HijackVerification(
        val hasShellApplication: Boolean,
        val hasMetaData: Boolean,
        val hasVersionMeta: Boolean,
        val isValid: Boolean,
    )
}
