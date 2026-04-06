package com.fuckprotect.shell.integrity;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;

import java.security.MessageDigest;

/**
 * Verifies the APK's signing certificate at runtime.
 *
 * The protector embeds the SHA-256 hash of the signing certificate
 * into the native library during the protection process. At runtime,
 * this class computes the SHA-256 of the current APK's signing
 * certificate and compares it with the embedded value via native code.
 *
 * A mismatch means the APK was re-packaged and re-signed with a
 * different key — a strong indicator of tampering.
 */
public class SignatureVerifier {

    static {
        System.loadLibrary("shell");
    }

    /**
     * Verify the current APK's signing certificate.
     *
     * @param context Application context
     * @return true if the certificate matches the one at build time
     */
    public static boolean verify(Context context) {
        try {
            byte[] currentHash = getCurrentCertHash(context);
            return nativeVerifySignature(currentHash);
        } catch (Exception e) {
            /* If we can't verify, assume tampered */
            return false;
        }
    }

    /**
     * Get the SHA-256 hash of the current APK's signing certificate.
     * Static version that takes Context (called from native code).
     */
    public static byte[] getCurrentCertHash(Context context) throws Exception {
        PackageInfo packageInfo = context.getPackageManager().getPackageInfo(
            context.getPackageName(),
            PackageManager.GET_SIGNING_CERTIFICATES
        );

        Signature[] signatures = packageInfo.signingInfo.getApkContentsSigners();
        if (signatures == null || signatures.length == 0) {
            throw new IllegalStateException("No signing certificates found");
        }

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(signatures[0].toByteArray());
    }

    /**
     * Native: verify certificate hash (constant-time comparison).
     */
    private static native boolean nativeVerifySignature(byte[] currentCertHash);

    /**
     * Native: get the expected certificate hash embedded at build time.
     */
    public static native byte[] nativeGetExpectedHash();

    /**
     * Get a hex representation of the expected hash (for logging).
     */
    public static String getExpectedHashHex() {
        try {
            byte[] hash = nativeGetExpectedHash();
            StringBuilder sb = new StringBuilder();
            for (byte b : hash) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (UnsatisfiedLinkError e) {
            return "<native lib not loaded>";
        }
    }
}
