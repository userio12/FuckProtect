# ProGuard rules for FuckProtect shell module
# These rules protect the shell runtime classes from being obfuscated
# or removed, since they must work correctly at runtime.

# Keep the Shell Application class
-keep class com.fuckprotect.shell.ShellApplication { *; }

# Keep all shell loader classes
-keep class com.fuckprotect.shell.loader.** { *; }

# Keep integrity verification classes
-keep class com.fuckprotect.shell.integrity.** { *; }

# Keep utility classes
-keep class com.fuckprotect.shell.utils.** { *; }

# Keep native method signatures
-keepclasseswithmembernames class * {
    native <methods>;
}

# Keep reflection targets
-keep class com.fuckprotect.shell.** { *; }
