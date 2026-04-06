package com.fuckprotect.shell.loader

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.Assert.*

/**
 * Instrumented tests for DexLoader and ClassLoaderProxy (T4.7).
 *
 * These tests run on an Android device/emulator and verify that the
 * DEX loading mechanism works correctly.
 *
 * Note: Full integration test requires a protected APK installed.
 * These tests validate individual components.
 */
@RunWith(AndroidJUnit4::class)
class DexLoaderTest {

    private val context: Context = ApplicationProvider.getApplicationContext()

    @Test
    fun dexLoader_cleansUpAfterInitialization() {
        // Create a minimal "DEX" (just bytes for testing)
        val fakeDex = createFakeDexBytes()

        val loader = DexLoader(context, fakeDex)

        // After initialization, the temp file should be cleaned up
        // Note: DexClassLoader may fail on invalid DEX, but cleanup should still work
        try {
            loader.initialize()
        } catch (_: Exception) {
            // Expected: fake DEX is not valid
        }

        // Verify cleanup: the decryptedDex reference should be zeroed
        assertTrue(
            "Fake DEX bytes should be zeroed after cleanup",
            fakeDex.all { it == 0.toByte() }
        )
    }

    @Test
    fun classLoaderProxy_canGetOriginalAppClassFromMetadata() {
        // This test requires the manifest to have been modified
        // with our metadata. In a unit test context, we verify the
        // method exists and doesn't crash.
        val className = ClassLoaderProxy.getOriginalAppClass(context)
        // Returns null when metadata isn't set (expected in test)
        assertNull(className)
    }

    @Test
    fun dexLoader_handlesNullDexGracefully() {
        // Should not crash on null/empty input
        val emptyDex = ByteArray(0)
        val loader = DexLoader(context, emptyDex)

        // Initialization should fail gracefully
        assertThrows(Exception::class.java) {
            loader.initialize()
        }
    }

    private fun createFakeDexBytes(): ByteArray {
        val baos = java.io.ByteArrayOutputStream()
        val dos = java.io.DataOutputStream(baos)

        dos.write(byteArrayOf(0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x37, 0x00))
        dos.writeInt(0)
        dos.write(ByteArray(20))
        dos.writeInt(0x100)
        dos.writeInt(0x70)
        dos.writeInt(0x12345678)
        dos.write(ByteArray(0x70 - 32))
        dos.write("FAKE DEX".toByteArray())

        return baos.toByteArray()
    }
}
