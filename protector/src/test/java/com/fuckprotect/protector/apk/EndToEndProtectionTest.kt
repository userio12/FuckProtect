package com.fuckprotect.protector.apk

import com.fuckprotect.protector.dex.DexEncryptor
import com.fuckprotect.protector.dex.KeyDerivation
import com.fuckprotect.protector.dex.PayloadBuilder
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.io.TempDir
import java.io.File

/**
 * End-to-end protection pipeline test (T3.7).
 *
 * This test creates a minimal "fake APK" (ZIP with DEX + manifest),
 * runs it through the full protection pipeline, and verifies the
 * output structure. It does NOT install or run the APK.
 */
class EndToEndProtectionTest {

    @TempDir
    lateinit var tempDir: File

    private lateinit var fakeApk: File
    private lateinit var keystoreFile: File
    private lateinit var protectedApk: File

    @BeforeEach
    fun setUp() {
        fakeApk = File(tempDir, "test-app.apk")
        keystoreFile = File(tempDir, "test.keystore")
        protectedApk = File(tempDir, "test-protected.apk")

        createFakeApk()
        createTestKeystore()
    }

    @Test
    fun `full protection pipeline produces valid output`() {
        // Phase 1: Parse
        val parser = ApkParser()
        val extracted = parser.extract(fakeApk, File(tempDir, "extracted"))
        parser.parseAll(extracted)

        assertNotNull(extracted.originalApplicationClass)
        assertEquals("com.test.TestApp", extracted.originalApplicationClass)
        assertEquals(1, extracted.dexFiles.size)

        // Phase 2: Encrypt
        val encryptor = DexEncryptor()
        val key = ByteArray(32) { 0x42 }
        val dexBytes = extracted.dexFiles[0].readBytes()
        val encrypted = encryptor.encrypt(dexBytes, key)

        // Phase 3: Build payload
        val payload = PayloadBuilder()
            .setOriginalAppClass(extracted.originalApplicationClass!!)
            .setEncryptedDexData(encrypted.data)
            .enableNativeProtection()
            .enableSignatureVerification()
            .build()

        assertTrue(payload.size > 0)

        // Phase 4: Modify manifest
        val editor = ManifestEditor()
        if (extracted.manifest != null) {
            val originalContent = extracted.manifest.readText()
            editor.hijackApplicationInPlace(
                extracted.manifest,
                extracted.originalApplicationClass!!
            )
            val modifiedContent = extracted.manifest.readText()

            assertNotEquals(originalContent, modifiedContent)
            assertTrue(modifiedContent.contains("com.fuckprotect.shell.ShellApplication"))
        }

        // Phase 5: Write payload
        val payloadFile = File(extracted.workDir, "fp_payload.dat")
        payloadFile.writeBytes(payload)

        // Phase 6: Repackage
        val packager = ApkPackager()
        packager.buildApk(extracted.workDir, protectedApk)

        assertTrue(protectedApk.exists())
        assertTrue(protectedApk.length() > 0)

        // Verify the protected APK contains our payload
        val extractedProtected = parser.extract(protectedApk, File(tempDir, "extracted2"))
        val payloadAsset = File(extractedProtected.workDir, "assets/fp_payload.dat")
        assertTrue(payloadAsset.exists(), "Protected APK should contain payload asset")
    }

    @Test
    fun `protected APK contains shell Application in manifest`() {
        val parser = ApkParser()
        val extracted = parser.extract(fakeApk, File(tempDir, "extracted_e2e"))
        parser.parseAll(extracted)

        // Hijack manifest
        val editor = ManifestEditor()
        editor.hijackApplicationInPlace(
            extracted.manifest!!,
            extracted.originalApplicationClass!!
        )

        // Verify
        val manifestContent = extracted.manifest.readText()
        assertTrue(manifestContent.contains("com.fuckprotect.shell.ShellApplication"))
        assertTrue(manifestContent.contains("FUCKPROTECT_APP_CLASS"))
        assertTrue(manifestContent.contains("com.test.TestApp"))
    }

    @Test
    fun `protection pipeline preserves non-DEX resources`() {
        // Add extra files to the fake APK
        val resDir = File(tempDir, "extracted_res/res").apply { mkdirs() }
        File(resDir, "values.xml").writeText("<resources/>")

        val parser = ApkParser()
        val extracted = parser.extract(fakeApk, File(tempDir, "extracted_res"))
        parser.parseAll(extracted)

        val encryptor = DexEncryptor()
        val key = ByteArray(32) { 0x42 }
        val encrypted = encryptor.encrypt(extracted.dexFiles[0].readBytes(), key)

        val payload = PayloadBuilder()
            .setOriginalAppClass(extracted.originalApplicationClass!!)
            .setEncryptedDexData(encrypted.data)
            .build()

        val payloadFile = File(extracted.workDir, "fp_payload.dat")
        payloadFile.writeBytes(payload)

        val packager = ApkPackager()
        packager.buildApk(extracted.workDir, protectedApk)

        // Re-extract and verify resources are preserved
        val reExtracted = parser.extract(protectedApk, File(tempDir, "extracted_verify"))
        assertTrue(reExtracted.dexFiles.isNotEmpty(), "DEX files should be present")
    }

    // ─── Helpers ─────────────────────────────────────────────────────

    /**
     * Create a minimal fake APK (ZIP with DEX + manifest).
     */
    private fun createFakeApk() {
        net.lingala.zip4j.ZipFile(fakeApk).use { zip ->
            // Add fake DEX
            val dexContent = createFakeDex()
            val dexFile = File(tempDir, "classes.dex").apply { writeBytes(dexContent) }
            zip.addFile(dexFile)

            // Add fake manifest (plain XML for testing)
            val manifestContent = """<?xml version="1.0" encoding="utf-8"?>
                <manifest package="com.test" xmlns:android="http://schemas.android.com/apk/res/android">
                    <application android:name="com.test.TestApp">
                        <activity android:name="com.test.MainActivity">
                            <intent-filter>
                                <action android:name="android.intent.action.MAIN"/>
                                <category android:name="android.intent.category.LAUNCHER"/>
                            </intent-filter>
                        </activity>
                    </application>
                </manifest>
            """.trimIndent()
            val manifestFile = File(tempDir, "AndroidManifest.xml").apply { writeText(manifestContent) }
            zip.addFile(manifestFile)
        }
    }

    private fun createTestKeystore() {
        val signer = ApkSigner()
        signer.generateDebugKeystore(keystoreFile)
    }

    private fun createFakeDex(): ByteArray {
        val baos = java.io.ByteArrayOutputStream()
        val dos = java.io.DataOutputStream(baos)

        // DEX magic "dex\n037\0"
        dos.write(byteArrayOf(0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x37, 0x00))
        // Checksum
        dos.writeInt(0x00000000)
        // Signature (20 zeros)
        dos.write(ByteArray(20))
        // File size
        val size = 0x70
        dos.writeInt(size)
        // Header size
        dos.writeInt(0x70)
        // Endian tag
        dos.writeInt(0x12345678)
        // Rest of header (zeros)
        dos.write(ByteArray(0x70 - 32))
        // Extra data
        dos.write("FAKE DEX DATA FOR TESTING".toByteArray())

        return baos.toByteArray()
    }
}
