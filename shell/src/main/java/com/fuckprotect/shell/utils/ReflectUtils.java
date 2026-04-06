package com.fuckprotect.shell.utils;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

/**
 * Reflection utility helpers for ClassLoaderProxy and Application forwarding.
 */
public class ReflectUtils {

    /**
     * Get a field value from an object, traversing class hierarchy if needed.
     */
    public static Object getField(Object obj, String fieldName) throws Exception {
        Class<?> clazz = obj.getClass();
        while (clazz != null) {
            try {
                Field field = clazz.getDeclaredField(fieldName);
                field.setAccessible(true);
                return field.get(obj);
            } catch (NoSuchFieldException e) {
                clazz = clazz.getSuperclass();
            }
        }
        throw new NoSuchFieldException("Field not found: " + fieldName);
    }

    /**
     * Set a field value on an object.
     */
    public static void setField(Object obj, String fieldName, Object value) throws Exception {
        Class<?> clazz = obj.getClass();
        while (clazz != null) {
            try {
                Field field = clazz.getDeclaredField(fieldName);
                field.setAccessible(true);
                field.set(obj, value);
                return;
            } catch (NoSuchFieldException e) {
                clazz = clazz.getSuperclass();
            }
        }
        throw new NoSuchFieldException("Field not found: " + fieldName);
    }

    /**
     * Invoke a method on an object.
     */
    public static Object invokeMethod(Object obj, String methodName, Object... args)
            throws Exception {
        Class<?> clazz = obj.getClass();
        Class<?>[] paramTypes = new Class[args.length];
        for (int i = 0; i < args.length; i++) {
            paramTypes[i] = args[i].getClass();
        }

        while (clazz != null) {
            try {
                Method method = clazz.getDeclaredMethod(methodName, paramTypes);
                method.setAccessible(true);
                return method.invoke(obj, args);
            } catch (NoSuchMethodException e) {
                clazz = clazz.getSuperclass();
            }
        }
        throw new NoSuchMethodException("Method not found: " + methodName);
    }

    /**
     * Call a static method.
     */
    public static Object invokeStaticMethod(Class<?> clazz, String methodName,
                                            Class<?>[] paramTypes, Object... args)
            throws Exception {
        Method method = clazz.getDeclaredMethod(methodName, paramTypes);
        method.setAccessible(true);
        return method.invoke(null, args);
    }

    /**
     * Get the current ActivityThread instance.
     */
    public static Object getCurrentActivityThread() throws Exception {
        Class<?> atClass = Class.forName("android.app.ActivityThread");
        Method method = atClass.getMethod("currentActivityThread");
        return method.invoke(null);
    }
}
