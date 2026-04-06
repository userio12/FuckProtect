package com.fuckprotect.shell;

import android.content.Context;

public class JniBridge {
    static { System.loadLibrary("shell"); }

    public static native void initApp();
    public static native byte[] decryptDex(byte[] payload);
    public static native String getApplicationName();
    public static native void setOriginalFactory(String name);
    public static native String getOriginalFactory();
}
