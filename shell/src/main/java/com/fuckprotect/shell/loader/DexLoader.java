package com.fuckprotect.shell.loader;

import android.content.Context;

import java.io.File;
import java.io.FileOutputStream;
import java.util.Arrays;

import dalvik.system.DexClassLoader;

/**
 * Handles DEX decryption, loading via DexClassLoader, and cleanup.
 *
 * For API 26+, InMemoryDexClassLoader would be preferred (no disk I/O),
 * but this implementation uses DexClassLoader with a temp file + immediate
 * deletion for compatibility with minSdk 21.
 */
public class DexLoader {

    private static final String DEX_PREFIX = "fp_decrypted_";
    private static final String DEX_SUFFIX = ".dex";

    private final Context context;
    private final byte[] decryptedDex;
    private DexClassLoader classLoader;
    private File tempDexFile;

    public DexLoader(Context context, byte[] decryptedDex) {
        this.context = context;
        this.decryptedDex = Arrays.copyOf(decryptedDex, decryptedDex.length);
    }

    /**
     * Initialize the DexClassLoader by writing the decrypted DEX to a
     * private temp file and creating the loader.
     *
     * The temp file is deleted immediately after the ClassLoader is created
     * (on some systems the file remains open by the loader).
     */
    public void initialize() {
        try {
            // Write decrypted DEX to private code cache directory
            tempDexFile = File.createTempFile(
                DEX_PREFIX, DEX_SUFFIX,
                context.getCodeCacheDir()
            );

            try (FileOutputStream fos = new FileOutputStream(tempDexFile)) {
                fos.write(decryptedDex);
            }

            // Create the DexClassLoader
            String optimizedDir = context.getDir("odex", Context.MODE_PRIVATE)
                .getAbsolutePath();
            String nativeLibDir = context.getApplicationInfo().nativeLibraryDir;

            classLoader = new DexClassLoader(
                tempDexFile.getAbsolutePath(),
                optimizedDir,
                nativeLibDir,
                context.getClassLoader()  // parent
            );

            // Delete the temp file — the OS may still hold a reference
            tempDexFile.delete();
            tempDexFile = null;

        } catch (Exception e) {
            // Clean up on failure
            cleanup(decryptedDex);
            throw new RuntimeException("Failed to initialize DexClassLoader", e);
        }
    }

    /**
     * Get the created DexClassLoader.
     * Must be called after {@link #initialize()}.
     */
    public DexClassLoader getClassLoader() {
        if (classLoader == null) {
            throw new IllegalStateException("DexLoader not initialized. Call initialize() first.");
        }
        return classLoader;
    }

    /**
     * Clean up all traces of decrypted DEX material.
     *
     * Wipes the decrypted bytes and deletes the temp file.
     *
     * @param dexRef Reference to the decrypted DEX byte array (will be zeroed)
     */
    public void cleanup(byte[] dexRef) {
        // Zero-fill the decrypted DEX bytes
        if (dexRef != null) {
            Arrays.fill(dexRef, (byte) 0);
        }
        Arrays.fill(decryptedDex, (byte) 0);

        // Delete temp file if it still exists
        if (tempDexFile != null && tempDexFile.exists()) {
            tempDexFile.delete();
            tempDexFile = null;
        }
    }
}
