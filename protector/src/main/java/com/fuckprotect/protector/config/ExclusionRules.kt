package com.fuckprotect.protector.config

/**
 * Exclusion rules for the protector.
 *
 * Defines which classes, methods, or packages should NOT be protected.
 * Excluded classes remain in plaintext in the APK.
 */
data class ExclusionRules(
    /** Package patterns to exclude (supports wildcards: `com.example.**`). */
    val excludePackages: List<String> = listOf(
        "androidx.**",
        "android.**",
        "kotlin.**",
        "com.google.**",
        "org.jetbrains.**",
        "java.**",
        "javax.**",
    ),

    /** Specific class names to exclude (fully qualified). */
    val excludeClasses: List<String> = listOf(
        // BuildConfig is always excluded
        "*.BuildConfig",
    ),

    /** Specific methods to exclude from hollowing. */
    val excludeMethods: List<String> = listOf(
        // Lifecycle methods must not be hollowed
        "*.onCreate",
        "*.onDestroy",
        "*.onStart",
        "*.onStop",
        "*.onResume",
        "*.onPause",
    ),

    /** Native libraries to exclude from hooking. */
    val excludeNativeLibs: List<String> = listOf(
        "libart.so",
        "libc.so",
        "libm.so",
        "libdl.so",
    ),
) {
    /**
     * Check if a class should be excluded based on the rules.
     */
    fun isExcluded(className: String): Boolean {
        // Check exact class name
        if (className in excludeClasses) return true

        // Check wildcard patterns
        for (pattern in excludePackages) {
            if (matchesPattern(className, pattern)) return true
        }

        // Check BuildConfig pattern
        if (className.endsWith(".BuildConfig")) return true

        return false
    }

    /**
     * Check if a method should be excluded from hollowing.
     */
    fun isMethodExcluded(className: String, methodName: String): Boolean {
        val fullMethodName = "$className.$methodName"

        for (pattern in excludeMethods) {
            if (matchesPattern(fullMethodName, pattern)) return true
        }

        return false
    }

    /**
     * Simple wildcard pattern matching.
     * Supports `*` (single segment) and `**` (any depth).
     */
    private fun matchesPattern(value: String, pattern: String): Boolean {
        val regex = Regex(
            pattern
                .replace(".", "\\.")
                .replace("**", ".*")
                .replace("*", "[^.]*")
        )
        return regex.matches(value)
    }

    companion object {
        /** Default exclusion rules. */
        val DEFAULT = ExclusionRules()

        /** No exclusions — protect everything. */
        val NONE = ExclusionRules(
            excludePackages = emptyList(),
            excludeClasses = emptyList(),
            excludeMethods = emptyList(),
        )
    }
}
