package com.fuckprotect.shell.integrity;

import android.content.Context;
import android.content.pm.ApplicationInfo;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.security.MessageDigest;

/**
 * Verifies the APK file integrity at runtime.
 *
 * Computes SHA-256 of the installed APK file and compares it with
 * a hash value that was computed at build time and stored in the
 * native library. If the APK has been modified (even a single byte),
 * the hash will differ.
 *
 * Note: This hashes the entire APK including the META-INF signature
 * files. If the protector re-signs the APK after protection, the
 * hash must be computed AFTER signing and embedded before distribution.
 */
public class ApkIntegrity {

    /**
     * Verify the APK file integrity.
     *
     * @param context Application context
     * @return true if the APK hasn't been modified since protection
     */
    public static boolean verify(Context context) {
        try {
            String apkPath = getApkPath(context);
            if (apkPath == null) return false;

            byte[] currentHash = computeFileHash(apkPath);
            if (currentHash == null) return false;

            return nativeVerifyApkHash(currentHash);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Get the path to the installed APK file.
     */
    private static String getApkPath(Context context) {
        try {
            ApplicationInfo ai = context.getApplicationInfo();
            return ai.sourceDir;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Compute SHA-256 hash of a file.
     *
     * @param filePath Path to the file
     * @return SHA-256 hash bytes, or null on error
     */
    private static byte[] computeFileHash(String filePath) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] buffer = new byte[8192];

            try (BufferedInputStream bis = new BufferedInputStream(
                    new FileInputStream(filePath))) {
                int bytesRead;
                while ((bytesRead = bis.read(buffer)) != -1) {
                    md.update(buffer, 0, bytesRead);
                }
            }

            return md.digest();
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Native: verify APK hash against build-time value.
     */
    private static native boolean nativeVerifyApkHash(byte[] currentHash);
}
