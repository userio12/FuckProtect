package com.fuckprotect.shell

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.Assert.*

/**
 * JNI crypto round-trip test (T5.5).
 *
 * Verifies that the native JNI methods work correctly:
 * - nativeInit() doesn't crash when not debugged
 * - nativeDecryptDex() handles invalid input gracefully
 *
 * Full encrypt→decrypt round-trip requires the protector tool to
 * create a real payload. The Java-side encrypt → native decrypt
 * round-trip is tested in DexEncryptionRoundTripTest on the JVM side.
 */
@RunWith(AndroidJUnit4::class)
class JniCryptoRoundTripTest {

    @Test
    fun nativeInit_doesNotCrashWhenNotDebugged() {
        // When NOT being debugged, nativeInit should pass all checks
        // and return normally.
        val shellApp = TestShellApp()

        try {
            shellApp.runNativeInit()
            // If we reach here, anti-debugging checks passed
            assertTrue(true)
        } catch (e: UnsatisfiedLinkError) {
            fail("Native library not loaded: ${e.message}")
        }
    }

    @Test
    fun nativeDecryptDex_returnsNullForEmptyPayload() {
        val shellApp = TestShellApp()
        val result = shellApp.decryptDex(ByteArray(0))
        assertNull("Empty payload should return null", result)
    }

    @Test
    fun nativeDecryptDex_returnsNullForInvalidPayload() {
        val shellApp = TestShellApp()

        // Random bytes that don't form a valid payload
        val badPayload = ByteArray(100) { (it * 7).toByte() }
        val result = shellApp.decryptDex(badPayload)
        assertNull("Invalid payload should return null", result)
    }

    @Test
    fun nativeDecryptDex_returnsNullForShortPayload() {
        val shellApp = TestShellApp()

        // Payload too small (less than header size)
        val shortPayload = ByteArray(10)
        val result = shellApp.decryptDex(shortPayload)
        assertNull("Short payload should return null", result)
    }

    @Test
    fun nativeDecryptDex_returnsNullForWrongMagic() {
        val shellApp = TestShellApp()

        // Payload with wrong magic bytes
        val badMagic = ByteArray(200)
        badMagic[0] = 0x00  // Wrong: should be 0x46 ('F')
        badMagic[1] = 0x00  // Wrong: should be 0x55 ('U')
        badMagic[2] = 0x00  // Wrong: should be 0x43 ('C')
        badMagic[3] = 0x00  // Wrong: should be 0x4B ('K')

        val result = shellApp.decryptDex(badMagic)
        assertNull("Wrong magic payload should return null", result)
    }
}

/**
 * Minimal test wrapper that loads the native library and exposes methods.
 */
class TestShellApp {
    init {
        System.loadLibrary("shell")
    }

    fun runNativeInit() {
        nativeInit()
    }

    fun decryptDex(payload: ByteArray): ByteArray? {
        return nativeDecryptDex(payload)
    }

    private external fun nativeInit()
    private external fun nativeDecryptDex(payload: ByteArray): ByteArray?
}
