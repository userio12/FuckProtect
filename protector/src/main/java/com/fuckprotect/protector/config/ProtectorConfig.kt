package com.fuckprotect.protector.config

/**
 * Configuration for the protector tool.
 *
 * Controls which protection features are enabled and how they behave.
 */
data class ProtectorConfig(
    /** Enable DEX encryption (default: true). */
    val encryptDex: Boolean = true,

    /** Enable anti-debugging checks in the shell (default: true). */
    val antiDebug: Boolean = true,

    /** Enable APK signature verification in the shell (default: true). */
    val verifySignature: Boolean = true,

    /** Enable APK integrity (checksum) verification (default: false — Phase 3). */
    val verifyApkIntegrity: Boolean = false,

    /** Enable method hollowing (default: false — Phase 3). */
    val methodHollowing: Boolean = false,

    /** Enable continuous monitoring thread (default: false — Phase 4). */
    val continuousMonitoring: Boolean = false,

    /** Enable silent defense mode (default: false — Phase 4). */
    val silentDefense: Boolean = false,

    /** Enable emulator detection (default: false — Phase 4). */
    val emulatorDetection: Boolean = false,

    /** Enable anti-hooking (default: false — Phase 3). */
    val antiHooking: Boolean = false,

    /** Classes to exclude from protection. */
    val excludeClasses: List<String> = emptyList(),

    /** Classes to force-protect even if they'd normally be excluded. */
    val forceProtectClasses: List<String> = emptyList(),

    /** ABI filters for native library inclusion. */
    val abiFilters: List<String> = listOf("armeabi-v7a", "arm64-v8a"),

    /** Log level for protector output (0=quiet, 1=normal, 2=verbose). */
    val logLevel: Int = 1,
) {
    companion object {
        /** Default configuration for maximum protection. */
        val MAX_PROTECTION = ProtectorConfig(
            encryptDex = true,
            antiDebug = true,
            verifySignature = true,
            verifyApkIntegrity = true,
            methodHollowing = false,
            continuousMonitoring = false,
            silentDefense = false,
            emulatorDetection = false,
            antiHooking = false,
        )

        /** Minimal configuration for debugging. */
        val DEBUG = ProtectorConfig(
            encryptDex = true,
            antiDebug = false,
            verifySignature = false,
            logLevel = 2,
        )
    }

    /** Merge with another config (this takes precedence). */
    fun merge(other: ProtectorConfig): ProtectorConfig = ProtectorConfig(
        encryptDex = encryptDex || other.encryptDex,
        antiDebug = antiDebug || other.antiDebug,
        verifySignature = verifySignature || other.verifySignature,
        verifyApkIntegrity = verifyApkIntegrity || other.verifyApkIntegrity,
        methodHollowing = methodHollowing || other.methodHollowing,
        continuousMonitoring = continuousMonitoring || other.continuousMonitoring,
        silentDefense = silentDefense || other.silentDefense,
        emulatorDetection = emulatorDetection || other.emulatorDetection,
        antiHooking = antiHooking || other.antiHooking,
        excludeClasses = excludeClasses + other.excludeClasses,
        forceProtectClasses = forceProtectClasses + other.forceProtectClasses,
        abiFilters = (abiFilters + other.abiFilters).distinct(),
        logLevel = maxOf(logLevel, other.logLevel),
    )
}
