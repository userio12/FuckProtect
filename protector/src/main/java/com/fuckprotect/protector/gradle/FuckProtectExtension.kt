package com.fuckprotect.protector.gradle

import org.gradle.api.Project
import org.gradle.api.provider.ListProperty
import org.gradle.api.provider.Property

/**
 * Gradle DSL extension for configuring FuckProtect.
 *
 * Usage in build.gradle.kts:
 * ```
 * fuckProtect {
 *     enabled = true
 *     antiDebug = true
 *     verifySignature = true
 *     methodHollowing = false
 *     silentDefense = false
 *     excludeClasses.set(listOf(
 *         "com.example.BuildConfig",
 *         "androidx.**",
 *     ))
 * }
 * ```
 *
 * T10.2: Configuration DSL
 */
abstract class FuckProtectExtension(project: Project) {

    /** Enable protection (default: true). Set to false to disable. */
    val enabled: Property<Boolean> = project.objects.property(Boolean::class.java)
        .convention(true)

    /** Encrypt DEX files (default: true). */
    val encryptDex: Property<Boolean> = project.objects.property(Boolean::class.java)
        .convention(true)

    /** Enable anti-debugging checks in the shell (default: true). */
    val antiDebug: Property<Boolean> = project.objects.property(Boolean::class.java)
        .convention(true)

    /** Enable APK signature verification (default: true). */
    val verifySignature: Property<Boolean> = project.objects.property(Boolean::class.java)
        .convention(true)

    /** Enable APK integrity verification (default: false). */
    val verifyApkIntegrity: Property<Boolean> = project.objects.property(Boolean::class.java)
        .convention(false)

    /** Enable method hollowing (default: false — Phase 3+). */
    val methodHollowing: Property<Boolean> = project.objects.property(Boolean::class.java)
        .convention(false)

    /** Enable continuous monitoring (default: false). */
    val continuousMonitoring: Property<Boolean> = project.objects.property(Boolean::class.java)
        .convention(false)

    /** Enable silent defense mode (default: false). */
    val silentDefense: Property<Boolean> = project.objects.property(Boolean::class.java)
        .convention(false)

    /** Enable emulator detection (default: false). */
    val emulatorDetection: Property<Boolean> = project.objects.property(Boolean::class.java)
        .convention(false)

    /** Enable anti-hooking (default: false). */
    val antiHooking: Property<Boolean> = project.objects.property(Boolean::class.java)
        .convention(false)

    /** Classes/packages to exclude from protection. */
    val excludeClasses: ListProperty<String> = project.objects.listProperty(String::class.java)
        .convention(
            listOf(
                "*.BuildConfig",
                "androidx.**",
                "android.**",
                "kotlin.**",
                "com.google.**",
            ),
        )

    /** Native ABI filters (default: all supported ABIs). */
    val abiFilters: ListProperty<String> = project.objects.listProperty(String::class.java)
        .convention(
            listOf("armeabi-v7a", "arm64-v8a"),
        )

    /** Log level (0=quiet, 1=normal, 2=verbose). */
    val logLevel: Property<Int> = project.objects.property(Int::class.java)
        .convention(1)

    /** Convenience: enable all protections at once. */
    fun maxProtection() {
        enabled.set(true)
        encryptDex.set(true)
        antiDebug.set(true)
        verifySignature.set(true)
        verifyApkIntegrity.set(true)
        methodHollowing.set(false)
        continuousMonitoring.set(false)
        silentDefense.set(false)
        emulatorDetection.set(false)
        antiHooking.set(true)
    }

    /** Convenience: disable all protections (for debugging). */
    fun disabled() {
        enabled.set(false)
    }
}
