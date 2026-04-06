package com.fuckprotect.shell;

import android.app.Application;
import android.content.Context;
import com.fuckprotect.shell.loader.ClassLoaderProxy;
import com.fuckprotect.shell.loader.DexLoader;
import com.fuckprotect.shell.integrity.SignatureVerifier;
import com.fuckprotect.shell.integrity.ApkIntegrity;

/**
 * Shell Application class — injected as the entry point of protected APKs.
 *
 * This class replaces the original Application in AndroidManifest.xml.
 * Its lifecycle:
 * 1. {@link #attachBaseContext(Context)} — decrypts DEX, replaces class loader,
 *    instantiates and forwards to the original Application.
 * 2. {@link #onCreate()} — forwards to the original Application's onCreate.
 *
 * All anti-debugging and integrity checks are performed in native code
 * BEFORE any DEX decryption occurs.
 */
public class ShellApplication extends Application {

    /** The real Application instance after forwarding. */
    private Application realApplication;

    static {
        // Load the shell native library (libshell.so)
        System.loadLibrary("shell");
    }

    @Override
    protected void attachBaseContext(Context base) {
        // Step 1: Run native anti-debugging and integrity checks
        // This MUST happen before any decryption
        nativeInitWithContext(base);

        // Step 1b: Additional Java-level integrity checks
        // (Native checks already ran in nativeInitWithContext)
        if (!SignatureVerifier.verify(base)) {
            throw new SecurityException("APK signature verification failed");
        }
        if (!ApkIntegrity.verify(base)) {
            throw new SecurityException("APK integrity check failed");
        }

        // Step 2: Read encrypted payload from assets
        byte[] payload = readPayloadFromAssets(base);
        if (payload == null || payload.length == 0) {
            throw new IllegalStateException("Failed to read encrypted payload");
        }

        // Step 3: Decrypt DEX via native code
        byte[] decryptedDex = nativeDecryptDex(payload);
        if (decryptedDex == null || decryptedDex.length == 0) {
            throw new IllegalStateException("Failed to decrypt DEX");
        }

        // Step 4: Load decrypted DEX using DexClassLoader
        DexLoader dexLoader = new DexLoader(base, decryptedDex);
        dexLoader.initialize();

        // Step 5: Replace PathClassLoader with our DexClassLoader
        ClassLoaderProxy.replaceClassLoader(base, dexLoader.getClassLoader());

        // Step 6: Get original Application class name from manifest metadata
        String originalAppClass = ClassLoaderProxy.getOriginalAppClass(base);
        if (originalAppClass == null || originalAppClass.isEmpty()) {
            throw new IllegalStateException(
                "Original Application class not found in manifest metadata"
            );
        }

        // Step 7: Create and attach the original Application
        try {
            realApplication = ClassLoaderProxy.createAndAttachApplication(
                originalAppClass, base
            );
        } catch (Exception e) {
            throw new RuntimeException(
                "Failed to create original Application: " + originalAppClass, e
            );
        }

        // Step 8: Clean up — wipe and delete decrypted DEX from memory/disk
        dexLoader.cleanup(decryptedDex);
    }

    @Override
    public void onCreate() {
        super.onCreate();

        // Forward onCreate to the real Application
        if (realApplication != null) {
            realApplication.onCreate();
        }
    }

    @Override
    public void onTerminate() {
        if (realApplication != null) {
            realApplication.onTerminate();
        }
        super.onTerminate();
    }

    @Override
    public void onTrimMemory(int level) {
        if (realApplication != null) {
            realApplication.onTrimMemory(level);
        } else {
            super.onTrimMemory(level);
        }
    }

    @Override
    public void onLowMemory() {
        if (realApplication != null) {
            realApplication.onLowMemory();
        } else {
            super.onLowMemory();
        }
    }

    /**
     * Read the encrypted payload from the app's assets.
     */
    private byte[] readPayloadFromAssets(Context context) {
        try (java.io.InputStream is = context.getAssets().open("fp_payload.dat")) {
            byte[] buffer = new byte[is.available()];
            int bytesRead = is.read(buffer);
            if (bytesRead != buffer.length) {
                java.util.Arrays.fill(buffer, (byte) 0);
                throw new IllegalStateException(
                    "Incomplete payload read: " + bytesRead + "/" + buffer.length
                );
            }
            return buffer;
        } catch (java.io.IOException e) {
            return null;
        }
    }

    // ─── Native methods ──────────────────────────────────────────────

    /**
     * Native initialization with Context. Performs:
     * - Anti-debugging checks (ptrace, TracerPid, timing)
     * - Signature verification (reads payload flags from assets)
     *
     * Should exit or corrupt state if tampering is detected.
     */
    private native void nativeInitWithContext(android.content.Context context);

    /**
     * Legacy native init without Context (anti-debugging only).
     */
    private native void nativeInit();

    /**
     * Decrypt the DEX from the encrypted payload.
     *
     * @param payload The full encrypted payload (header + IV + ciphertext)
     * @return Decrypted DEX bytes
     */
    private native byte[] nativeDecryptDex(byte[] payload);

    // ─── Test helpers (package-private, used by instrumented tests) ────

    /**
     * Test wrapper for nativeDecryptDex. Exposes the native method for testing.
     */
    byte[] testDecryptDex(byte[] payload) {
        return nativeDecryptDex(payload);
    }

    /**
     * Test wrapper for nativeInit. Exposes the native method for testing.
     */
    void testNativeInit() {
        nativeInit();
    }
}
