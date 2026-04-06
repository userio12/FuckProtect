package com.fuckprotect.common

/**
 * Shared constants used by both the protector tool and the shell runtime.
 */
object Constants {

    /** Magic bytes written at the start of every protected payload: "FUCK" */
    val MAGIC: ByteArray = byteArrayOf(0x46, 0x55, 0x43, 0x4B)

    /** Current payload format version. */
    const val VERSION: Short = 1

    /** AES-256-CBC cipher transformation string. */
    const val ALGORITHM_AES: String = "AES/CBC/PKCS5Padding"

    /** AES key size in bits. */
    const val KEY_SIZE_BITS: Int = 256
    const val KEY_SIZE_BYTES: Int = 32

    /** AES block / IV size in bytes. */
    const val IV_SIZE_BYTES: Int = 16

    /** SHA-256 hash size in bytes. */
    const val SHA256_SIZE_BYTES: Int = 32

    /** CRC32 checksum size in bytes. */
    const val CRC32_SIZE_BYTES: Int = 4

    /** Int size in bytes (big-endian). */
    const val INT_SIZE: Int = 4

    /** Short size in bytes (big-endian). */
    const val SHORT_SIZE: Int = 2

    /** Name of the shell Application class injected into protected APKs. */
    const val SHELL_APPLICATION_CLASS = "com.fuckprotect.shell.ShellApplication"

    /** Name of the shell AppComponentFactory injected into protected APKs (Android 9+). */
    const val SHELL_COMPONENT_FACTORY = "com.fuckprotect.shell.factory.ProxyComponentFactory"

    /** Manifest meta-data key storing the original Application class name. */
    const val META_ORIGINAL_APP_CLASS = "FUCKPROTECT_APP_CLASS"

    /** Manifest meta-data key storing the original AppComponentFactory class name. */
    const val META_ORIGINAL_FACTORY = "FUCKPROTECT_APP_FACTORY"

    /** Manifest meta-data key storing the protector version. */
    const val META_PROTECTOR_VERSION = "FUCKPROTECT_VERSION"

    /** Default name for the protected native library. */
    const val NATIVE_LIB_NAME = "shell"

    /** File name for the encrypted payload inside the protected APK's assets. */
    const val PAYLOAD_ASSET_NAME = "fp_payload.dat"
}
