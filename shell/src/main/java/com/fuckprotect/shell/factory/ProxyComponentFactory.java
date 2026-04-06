package com.fuckprotect.shell.factory;

import android.annotation.TargetApi;
import android.app.Activity;
import android.app.AppComponentFactory;
import android.app.Application;
import android.app.Service;
import android.content.BroadcastReceiver;
import android.content.ContentProvider;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.os.Build;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;

/**
 * Proxy AppComponentFactory for Android 9+ (API 28+).
 *
 * This class intercepts ALL Android component creation (Application, Activity,
 * Service, BroadcastReceiver, ContentProvider) and ensures the shell's class
 * loader is installed before any app code runs.
 *
 * Advantages over Application hijacking:
 * - Works on Android 9+ where AppComponentFactory is available
 * - Intercepts components before they're created (earlier than Application)
 * - Handles the original AppComponentFactory if the app has one
 * - More reliable - no race condition with component creation
 *
 * Usage: The protector replaces the manifest's android:appComponentFactory
 * attribute with this class name, and stores the original factory name
 * in the payload.
 */
@TargetApi(Build.VERSION_CODES.P)
@RequiresApi(Build.VERSION_CODES.P)
public class ProxyComponentFactory extends AppComponentFactory {

    private static final String TAG = "FP_ComponentFactory";
    private static AppComponentFactory originalFactory;
    private static volatile boolean initialized = false;

    /**
     * Get the original AppComponentFactory class name from the payload.
     * This is stored as a native variable at build time.
     */
    private static native String getOriginalComponentFactory();

    /**
     * Initialize the shell (native init, class loader replacement, etc.)
     */
    private static native void initShell();

    /**
     * Replace the class loader in the given ClassLoader with our DexClassLoader.
     */
    private static native void replaceClassLoader(ClassLoader target);

    /**
     * Get the original Application class name.
     */
    private static native String getOriginalApplicationName();

    /**
     * Instantiate or forward to the original AppComponentFactory.
     */
    private AppComponentFactory getOriginalFactory(ClassLoader cl) {
        if (originalFactory != null) {
            return originalFactory;
        }

        String factoryName = getOriginalComponentFactory();
        if (factoryName == null || factoryName.isEmpty()) {
            return null;
        }

        try {
            Class<?> factoryClass = Class.forName(factoryName, true, cl);
            originalFactory = (AppComponentFactory) factoryClass.newInstance();
            Log.d(TAG, "Original factory instantiated: " + factoryName);
        } catch (Exception e) {
            Log.w(TAG, "Failed to instantiate original factory: " + factoryName, e);
        }

        return originalFactory;
    }

    /**
     * Ensure shell is initialized (one-time).
     */
    private void ensureInitialized(ClassLoader cl) {
        if (initialized) return;

        synchronized (ProxyComponentFactory.class) {
            if (initialized) return;

            Log.d(TAG, "ProxyComponentFactory initializing...");
            initShell();
            replaceClassLoader(cl);
            initialized = true;
            Log.d(TAG, "ProxyComponentFactory initialization complete");
        }
    }

    @NonNull
    @Override
    public Application instantiateApplication(@NonNull ClassLoader cl,
                                              @NonNull String className)
            throws ClassNotFoundException, IllegalAccessException, InstantiationException {

        Log.d(TAG, "instantiateApplication: className=" + className);

        // Initialize shell BEFORE creating any component
        ensureInitialized(cl);

        AppComponentFactory factory = getOriginalFactory(cl);
        if (factory != null) {
            try {
                return factory.instantiateApplication(cl, className);
            } catch (Exception e) {
                Log.w(TAG, "Original factory failed, falling back", e);
            }
        }

        // Use the original application class name from our payload
        String appName = getOriginalApplicationName();
        if (appName != null && !appName.isEmpty()) {
            Log.d(TAG, "Instantiating original application: " + appName);
            return super.instantiateApplication(cl, appName);
        }

        // Fall back to default
        return super.instantiateApplication(cl, className);
    }

    @NonNull
    @Override
    public Activity instantiateActivity(@NonNull ClassLoader cl,
                                        @NonNull String className,
                                        Intent intent)
            throws ClassNotFoundException, IllegalAccessException, InstantiationException {

        Log.d(TAG, "instantiateActivity: className=" + className);
        ensureInitialized(cl);

        AppComponentFactory factory = getOriginalFactory(cl);
        if (factory != null) {
            try {
                return factory.instantiateActivity(cl, className, intent);
            } catch (Exception e) {
                Log.w(TAG, "Original factory activity creation failed", e);
            }
        }
        return super.instantiateActivity(cl, className, intent);
    }

    @NonNull
    @Override
    public BroadcastReceiver instantiateReceiver(@NonNull ClassLoader cl,
                                                  @NonNull String className,
                                                  Intent intent)
            throws ClassNotFoundException, IllegalAccessException, InstantiationException {

        Log.d(TAG, "instantiateReceiver: className=" + className);
        ensureInitialized(cl);

        AppComponentFactory factory = getOriginalFactory(cl);
        if (factory != null) {
            try {
                return factory.instantiateReceiver(cl, className, intent);
            } catch (Exception e) {
                Log.w(TAG, "Original factory receiver creation failed", e);
            }
        }
        return super.instantiateReceiver(cl, className, intent);
    }

    @NonNull
    @Override
    public Service instantiateService(@NonNull ClassLoader cl,
                                       @NonNull String className,
                                       Intent intent)
            throws ClassNotFoundException, IllegalAccessException, InstantiationException {

        Log.d(TAG, "instantiateService: className=" + className);
        ensureInitialized(cl);

        AppComponentFactory factory = getOriginalFactory(cl);
        if (factory != null) {
            try {
                return factory.instantiateService(cl, className, intent);
            } catch (Exception e) {
                Log.w(TAG, "Original factory service creation failed", e);
            }
        }
        return super.instantiateService(cl, className, intent);
    }

    @NonNull
    @Override
    public ContentProvider instantiateProvider(@NonNull ClassLoader cl,
                                                @NonNull String className)
            throws ClassNotFoundException, IllegalAccessException, InstantiationException {

        Log.d(TAG, "instantiateProvider: className=" + className);
        ensureInitialized(cl);

        AppComponentFactory factory = getOriginalFactory(cl);
        if (factory != null) {
            try {
                return factory.instantiateProvider(cl, className);
            } catch (Exception e) {
                Log.w(TAG, "Original factory provider creation failed", e);
            }
        }
        return super.instantiateProvider(cl, className);
    }

    @NonNull
    @Override
    public ClassLoader instantiateClassLoader(@NonNull ClassLoader cl,
                                               @NonNull ApplicationInfo aInfo) {

        Log.d(TAG, "instantiateClassLoader");
        ensureInitialized(cl);

        AppComponentFactory factory = getOriginalFactory(cl);
        if (factory != null) {
            try {
                return factory.instantiateClassLoader(cl, aInfo);
            } catch (Exception e) {
                Log.w(TAG, "Original factory classloader creation failed", e);
            }
        }
        return super.instantiateClassLoader(cl, aInfo);
    }
}
