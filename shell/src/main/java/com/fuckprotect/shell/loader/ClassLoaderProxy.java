package com.fuckprotect.shell.loader;

import android.app.Application;
import android.content.Context;
import android.content.ContextWrapper;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;

import com.fuckprotect.common.Constants;

import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

/**
 * Handles replacing the app's PathClassLoader with our DexClassLoader
 * and instantiating the original Application class.
 *
 * This class uses reflection to access internal Android framework classes
 * (ActivityThread, LoadedApk) which may vary across Android versions.
 */
public class ClassLoaderProxy {

    /**
     * Get the original Application class name from manifest metadata.
     */
    public static String getOriginalAppClass(Context context) {
        try {
            PackageManager pm = context.getPackageManager();
            String packageName = context.getPackageName();
            ApplicationInfo ai = pm.getApplicationInfo(
                packageName, PackageManager.GET_META_DATA
            );

            if (ai.metaData != null) {
                return ai.metaData.getString(Constants.META_ORIGINAL_APP_CLASS);
            }
        } catch (PackageManager.NameNotFoundException e) {
            // Fall through
        }

        return null;
    }

    /**
     * Replace the app's PathClassLoader with our DexClassLoader.
     *
     * This modifies the ActivityThread's internal mPackages map to swap
     * the class loader used for the current application.
     *
     * @param context The current Context
     * @param newClassLoader Our DexClassLoader containing the decrypted DEX
     */
    public static void replaceClassLoader(Context context, ClassLoader newClassLoader) {
        try {
            // Get the current ActivityThread instance
            Class<?> activityThreadClass = Class.forName("android.app.ActivityThread");
            Method currentActivityThreadMethod = activityThreadClass.getMethod(
                "currentActivityThread"
            );
            Object activityThread = currentActivityThreadMethod.invoke(null);

            if (activityThread == null) return;

            // Get mPackages field (Map<String, WeakReference<LoadedApk>>)
            Field mPackagesField = activityThreadClass.getDeclaredField("mPackages");
            mPackagesField.setAccessible(true);
            Object mPackages = mPackagesField.get(activityThread);

            // Iterate over the map and replace ClassLoaders in each LoadedApk
            Method keySetMethod = mPackages.getClass().getMethod("keySet");
            Object keySet = keySetMethod.invoke(mPackages);
            Method toArrayMethod = keySet.getClass().getMethod("toArray");
            Object[] keys = (Object[]) toArrayMethod.invoke(keySet);

            Method getMethod = mPackages.getClass().getMethod("get", Object.class);

            for (Object key : keys) {
                Object weakRef = getMethod.invoke(mPackages, key);
                if (weakRef == null) continue;

                Method getMethod2 = weakRef.getClass().getMethod("get");
                Object loadedApk = getMethod2.invoke(weakRef);
                if (loadedApk == null) continue;

                // Replace mClassLoader in LoadedApk
                try {
                    Field classLoaderField = loadedApk.getClass()
                        .getDeclaredField("mClassLoader");
                    classLoaderField.setAccessible(true);
                    classLoaderField.set(loadedApk, newClassLoader);
                } catch (NoSuchFieldException e) {
                    // Field may not exist on all versions
                }
            }

            // Also replace the context's class loader (for current context)
            replaceBaseContextClassLoader(context, newClassLoader);

        } catch (Exception e) {
            // If replacement fails, we still continue — the app may still work
            // with the parent class loader chain
        }
    }

    /**
     * Create and attach the original Application instance.
     *
     * @param appClassName Fully qualified class name of the original Application
     * @param base The base Context
     * @return The created Application instance
     */
    public static Application createAndAttachApplication(
        String appClassName, Context base
    ) throws Exception {
        // Load the class via our DexClassLoader
        ClassLoader cl = base.getClassLoader();
        Class<?> appClass = cl.loadClass(appClassName);

        // Create instance
        Application app = (Application) appClass.newInstance();

        // Get ActivityThread
        Class<?> activityThreadClass = Class.forName("android.app.ActivityThread");
        Method currentActivityThreadMethod = activityThreadClass.getMethod(
            "currentActivityThread"
        );
        Object activityThread = currentActivityThreadMethod.invoke(null);

        // Call attach() — this sets up the context
        Method attachMethod = Application.class.getDeclaredMethod(
            "attach", Context.class
        );
        attachMethod.setAccessible(true);
        attachMethod.invoke(app, base);

        // Set mLoadedApk field
        Field loadedApkField = ContextWrapper.class.getDeclaredField("mBase");
        // Actually we need to set mLoadedApk on the ActivityThread side
        // Get the LoadedApk for this package
        Field mLoadedApkField = ContextWrapper.class.getDeclaredField("mBase");

        // Call attachBaseContext on the real app
        Method attachBaseContext = Application.class.getDeclaredMethod(
            "attachBaseContext", Context.class
        );
        attachBaseContext.setAccessible(true);
        attachBaseContext.invoke(app, base);

        return app;
    }

    // ─── Private helpers ─────────────────────────────────────────────

    private static void replaceBaseContextClassLoader(
        Context context, ClassLoader newClassLoader
    ) {
        try {
            // ContextImpl has a mClassLoader field
            Field classLoaderField = context.getClass()
                .getDeclaredField("mClassLoader");
            classLoaderField.setAccessible(true);
            classLoaderField.set(context, newClassLoader);
        } catch (Exception e) {
            // Field may not exist on all versions
        }
    }
}
