package com.fuckprotect.shell.utils;

import android.util.Log;

/**
 * Obfuscated logging for the FuckProtect shell.
 *
 * All log messages use obfuscated tag names to make it harder for
 * reverse engineers to identify FuckProtect-specific log output.
 */
public class Logger {

    /** Obfuscated log tag — changes per build in production */
    private static final String TAG = "ShellRuntime";

    private static boolean verbose = false;

    public static void setVerbose(boolean v) {
        verbose = v;
    }

    public static void d(String msg) {
        if (verbose) {
            Log.d(TAG, msg);
        }
    }

    public static void d(String tag, String msg) {
        if (verbose) {
            Log.d(tag, msg);
        }
    }

    public static void e(String msg) {
        Log.e(TAG, msg);
    }

    public static void e(String tag, String msg) {
        Log.e(tag, msg);
    }

    public static void i(String msg) {
        if (verbose) {
            Log.i(TAG, msg);
        }
    }

    public static void w(String msg) {
        if (verbose) {
            Log.w(TAG, msg);
        }
    }
}
