package com.fuckprotect.protector.apk

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*

/**
 * Unit tests for ManifestEditor (T3.3 verification).
 */
class ManifestEditorTest {

    private val editor = ManifestEditor()

    @Test
    fun `hijackApplication replaces Application class name`() {
        val originalManifest = """<?xml version="1.0"?>
            <manifest package="com.example">
                <application android:name="com.example.MyApp">
                </application>
            </manifest>
        """.trimIndent()

        val result = editor.hijackApplication(originalManifest, "com.example.MyApp")

        assertTrue(result.contains("com.fuckprotect.shell.ShellApplication"))
        assertFalse(result.contains("""android:name="com.example.MyApp""""))
    }

    @Test
    fun `hijackApplication adds metadata for original class`() {
        val originalManifest = """<?xml version="1.0"?>
            <manifest package="com.example">
                <application android:name="com.example.MyApp">
                </application>
            </manifest>
        """.trimIndent()

        val result = editor.hijackApplication(originalManifest, "com.example.MyApp")

        assertTrue(result.contains("FUCKPROTECT_APP_CLASS"))
        assertTrue(result.contains("com.example.MyApp"))
    }

    @Test
    fun `hijackApplication adds version metadata`() {
        val originalManifest = """<?xml version="1.0"?>
            <manifest package="com.example">
                <application android:name="com.example.MyApp">
                </application>
            </manifest>
        """.trimIndent()

        val result = editor.hijackApplication(originalManifest, "com.example.MyApp")

        assertTrue(result.contains("FUCKPROTECT_VERSION"))
        assertTrue(result.contains("1.0.0"))
    }

    @Test
    fun `verifyHijack detects proper hijack`() {
        val hijacked = """<?xml version="1.0"?>
            <manifest package="com.example">
                <application android:name="com.fuckprotect.shell.ShellApplication">
                    <meta-data android:name="FUCKPROTECT_APP_CLASS"
                               android:value="com.example.MyApp" />
                    <meta-data android:name="FUCKPROTECT_VERSION"
                               android:value="1.0.0" />
                </application>
            </manifest>
        """.trimIndent()

        val result = editor.verifyHijack(hijacked)

        assertTrue(result.isValid)
        assertTrue(result.hasShellApplication)
        assertTrue(result.hasMetaData)
        assertTrue(result.hasVersionMeta)
    }

    @Test
    fun `verifyHijack detects missing shell Application`() {
        val notHijacked = """<?xml version="1.0"?>
            <manifest package="com.example">
                <application android:name="com.example.MyApp">
                </application>
            </manifest>
        """.trimIndent()

        val result = editor.verifyHijack(notHijacked)

        assertFalse(result.isValid)
        assertFalse(result.hasShellApplication)
        assertFalse(result.hasMetaData)
    }

    @Test
    fun `parseApplicationClassFromXml extracts class name`() {
        val xml = """<manifest>
            <application android:name="com.example.MyApplication">
            </application>
        </manifest>"""

        val className = editor.parseApplicationClassFromXml(xml)
        assertEquals("com.example.MyApplication", className)
    }

    @Test
    fun `parsePackageNameFromXml extracts package name`() {
        val xml = """<manifest package="com.example.app"
            xmlns:android="http://schemas.android.com/apk/res/android">
        </manifest>"""

        val pkgName = editor.parsePackageNameFromXml(xml)
        assertEquals("com.example.app", pkgName)
    }

    @Test
    fun `parseApplicationClassFromXml handles missing Application`() {
        val xml = """<manifest>
            <application>
            </application>
        </manifest>"""

        val className = editor.parseApplicationClassFromXml(xml)
        assertNull(className)
    }
}
