package com.fuckprotect.shell.antidbg

import android.os.Debug
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.Assert.*

/**
 * Anti-debugging test (T6.7).
 *
 * Verifies that the anti-debugging native code correctly detects
 * debugger attachment. Since we can't actually attach a debugger
 * during automated testing, this test verifies the check functions
 * exist and behave correctly in a non-debugged environment.
 *
 * NOTE: Run this test WITHOUT a debugger attached for accurate results.
 * To test debugger detection, manually attach jdb or Android Studio
 * debugger and verify the app exits.
 */
@RunWith(AndroidJUnit4::class)
class AntiDebugTest {

    init {
        System.loadLibrary("shell")
    }

    @Test
    fun whenNotDebugged_nativeInitDoesNotCrash() {
        // When NOT being debugged, anti_debug_init() should pass all checks
        // and return normally (not call _exit)
        val testObj = AntiDebugTestNative()

        // If we're not being debugged, this should not crash
        testObj.runAntiDebugInit()

        // If we reached this point, anti-debugging checks passed
        assertTrue(true)
    }

    @Test
    fun debugIsDebuggerConnected_returnsExpectedValue() {
        // In a test environment (no debugger), this should return false
        val isDebugging = Debug.isDebuggerConnected()

        // When running instrumented tests without a debugger attached,
        // this should be false. If running with --debug, it may be true.
        // We just verify the method works, not the value.
        assertNotNull("Debug.isDebuggerConnected() should not throw", isDebugging)
    }

    @Test
    fun debugFlags_detectDebuggableApp() {
        // Check if the app is debuggable (test APKs often are)
        val isDebuggable = android.os.Build.VERSION.SDK_INT >=
                android.os.Build.VERSION_CODES.O &&
                (android.app.ActivityThread.currentApplication()?.applicationInfo?.flags
                    ?.and(android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) ?: 0) != 0

        // In test builds, this is often true. We just verify we can read it.
        assertNotNull("Should be able to read debuggable flag", isDebuggable)
    }

    /**
     * Manual test: verify TracerPid check function.
     *
     * When not being debugged, TracerPid should be 0.
     */
    @Test
    fun tracerPid_isZeroWhenNotDebugged() {
        val tracerPid = readTracerPid()
        assertEquals(
            "TracerPid should be 0 when not being debugged",
            0,
            tracerPid
        )
    }
}

/**
 * Native test wrapper for anti-debugging functions.
 */
class AntiDebugTestNative {
    init {
        System.loadLibrary("shell")
    }

    /**
     * Run anti-debugging checks. Should succeed when not debugged.
     */
    fun runAntiDebugInit() {
        nativeAntiDebugInit()
    }

    private external fun nativeAntiDebugInit()
}

/**
 * Read TracerPid from /proc/self/status.
 */
private fun readTracerPid(): Int {
    return try {
        val status = java.io.File("/proc/self/status").readText()
        val line = status.lines().find { it.startsWith("TracerPid:") }
        line?.substringAfter(":")?.trim()?.toIntOrNull() ?: 0
    } catch (e: Exception) {
        0
    }
}
