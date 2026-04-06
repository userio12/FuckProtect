package com.fuckprotect.protector.gradle

import com.fuckprotect.protector.Protector
import com.fuckprotect.protector.apk.ApkPackager
import com.fuckprotect.protector.apk.ApkParser
import com.fuckprotect.protector.apk.ApkSigner
import com.fuckprotect.protector.apk.ManifestEditor
import com.fuckprotect.protector.config.ExclusionRules
import com.fuckprotect.protector.config.ProtectorConfig
import com.fuckprotect.protector.dex.DexEncryptor
import com.fuckprotect.protector.dex.KeyDerivation
import com.fuckprotect.protector.dex.PayloadBuilder
import com.fuckprotect.protector.embedder.SignatureEmbedder
import org.gradle.api.DefaultTask
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputFile
import org.gradle.api.tasks.Optional
import org.gradle.api.tasks.OutputFile
import org.gradle.api.tasks.TaskAction
import java.io.File

/**
 * Gradle task that runs the FuckProtect protection pipeline on an APK.
 *
 * This task:
 * 1. Reads the unsigned/release APK
 * 2. Parses and extracts its contents
 * 3. Encrypts DEX files
 * 4. Modifies the manifest
 * 5. Embeds the signing certificate hash into native libs
 * 6. Repackages and signs the protected APK
 *
 * T10.3: Gradle task definition
 */
abstract class FuckProtectTask : DefaultTask() {

    @get:Input
    abstract val extension: Property<FuckProtectExtension>

    @get:Optional
    @get:InputFile
    abstract val inputApkFile: RegularFileProperty

    @get:Optional
    @get:OutputFile
    abstract val outputApkFile: RegularFileProperty

    @get:Optional
    @get:Input
    abstract val keystorePath: Property<String>

    @get:Optional
    @get:Input
    abstract val keystorePassword: Property<String>

    @get:Optional
    @get:Input
    abstract val keyAlias: Property<String>

    @get:Optional
    @get:Input
    abstract val keyPassword: Property<String>

    @get:Optional
    @get:Input
    abstract val storePassword: Property<String>

    /** Provider function for input APK (set by plugin). */
    var inputApkProvider: (() -> File?)? = null

    /** Provider function for output APK (set by plugin). */
    var outputApkProvider: (() -> File?)? = null

    @TaskAction
    fun execute() {
        val ext = extension.get()

        if (!ext.enabled.get()) {
            logger.info("FuckProtect: Protection disabled. Skipping.")
            return
        }

        logger.lifecycle("=== FuckProtect: Starting protection ===")

        // Resolve input/output APKs
        val inputApk = inputApkProvider?.invoke()
            ?: inputApkFile.orNull?.asFile
            ?: run {
                logger.error("FuckProtect: No input APK specified")
                return
            }

        val outputApk = outputApkProvider?.invoke()
            ?: outputApkFile.orNull?.asFile
            ?: run {
                logger.error("FuckProtect: No output APK specified")
                return
            }

        // Resolve keystore (use release signing config if available)
        val kStorePath = keystorePath.orNull
            ?: System.getenv("FP_KEYSTORE")
            ?: run {
                logger.warn("FuckProtect: No keystore configured. Using debug keystore.")
                val debugKeystore = File(
                    System.getenv("HOME"),
                    ".android/debug.keystore",
                )
                if (!debugKeystore.exists()) {
                    logger.error("FuckProtect: Debug keystore not found. Create one first.")
                    return
                }
                debugKeystore.absolutePath
            }

        val kStorePass = storePassword.orNull
            ?: System.getenv("FP_STORE_PASS")
            ?: "android"

        val kAlias = keyAlias.orNull
            ?: System.getenv("FP_KEY_ALIAS")
            ?: "androiddebugkey"

        val kPass = keyPassword.orNull
            ?: System.getenv("FP_KEY_PASS")
            ?: kStorePass

        logger.lifecycle("  Input:  $inputApk")
        logger.lifecycle("  Output: $outputApk")
        logger.lifecycle("  Config: antiDebug=${ext.antiDebug.get()}, " +
                "verifySignature=${ext.verifySignature.get()}")

        // Create temp working directory
        val workDir = File(project.buildDir, "fuckprotect-tmp").apply {
            mkdirs()
        }

        try {
            runProtection(
                inputApk = inputApk,
                outputApk = outputApk,
                workDir = workDir,
                keystorePath = kStorePath,
                keystorePassword = kStorePass,
                keyAlias = kAlias,
                keyPassword = kPass,
                storePassword = kStorePass,
                config = ext,
            )
        } finally {
            // Clean up temp directory
            workDir.deleteRecursively()
        }

        logger.lifecycle("=== FuckProtect: Protection complete ===")
        logger.lifecycle("  Protected APK: $outputApk")
    }

    private fun runProtection(
        inputApk: File,
        outputApk: File,
        workDir: File,
        keystorePath: String,
        keystorePassword: String,
        keyAlias: String,
        keyPassword: String,
        storePassword: String,
        config: FuckProtectExtension,
    ) {
        val verbose = config.logLevel.get() >= 2

        fun log(msg: String) {
            if (verbose) logger.lifecycle("  $msg")
        }

        // Phase 1: Parse
        log("Parsing input APK...")
        val parser = ApkParser()
        val extractDir = File(workDir, "extracted").apply { mkdirs() }
        val extracted = parser.extract(inputApk, extractDir)
        parser.parseAll(extracted)

        if (extracted.originalApplicationClass == null) {
            logger.error("FuckProtect: Could not determine Application class")
            return
        }

        log("  App: ${extracted.originalApplicationClass}")
        log("  Package: ${extracted.packageName}")
        log("  DEX files: ${extracted.dexFiles.size}")

        // Phase 2: Encrypt
        log("Encrypting DEX...")
        val encryptor = DexEncryptor()
        val signer = ApkSigner()
        val certHash = signer.getCertificateHash(
            ApkSigner.KeystoreConfig(
                File(keystorePath),
                storePassword,
                keyAlias,
                keyPassword,
            ),
        )
        val aesKey = KeyDerivation.deriveFromCertBytes(certHash)

        val primaryDex = extracted.dexFiles.firstOrNull()
        if (primaryDex == null) {
            logger.error("FuckProtect: No DEX files found")
            return
        }

        val encrypted = encryptor.encrypt(primaryDex.readBytes(), aesKey)
        log("  Encrypted: ${primaryDex.length()} -> ${encrypted.totalSize} bytes")

        // Phase 3: Build payload
        log("Building payload...")
        val payloadBuilder = PayloadBuilder()
            .setOriginalAppClass(extracted.originalApplicationClass!!)
            .setEncryptedDexData(encrypted.data)
            .enableNativeProtection()

        if (config.verifySignature.get()) {
            payloadBuilder.enableSignatureVerification()
        }

        val payload = payloadBuilder.build()
        val payloadFile = File(extractDir, "fp_payload.dat").apply { writeBytes(payload) }
        log("  Payload: ${payload.size} bytes")

        // Phase 4: Modify manifest
        log("Modifying manifest...")
        val editor = ManifestEditor()
        if (extracted.manifest != null) {
            editor.hijackApplicationInPlace(
                extracted.manifest,
                extracted.originalApplicationClass!!,
            )
            log("  Manifest hijacked")
        }

        // Phase 4b: Embed cert hash into native libs
        log("Embedding signature into native libs...")
        val embedder = SignatureEmbedder()
        val nativeLibDir = File(extractDir, "lib")
        if (nativeLibDir.exists()) {
            embedder.embedAll(nativeLibDir, certHash)
            log("  Hash embedded")
        }

        // Phase 5: Repackage
        log("Repackaging...")
        val packager = ApkPackager()
        val unsignedApk = File(workDir, "unsigned.apk")
        packager.buildApkWithPayload(extractDir, unsignedApk, payloadFile)
        log("  Unsigned APK: ${unsignedApk.length()} bytes")

        // Phase 6: Sign
        log("Signing...")
        signer.signApkJar(
            unsignedApk,
            outputApk,
            ApkSigner.KeystoreConfig(
                File(keystorePath),
                storePassword,
                keyAlias,
                keyPassword,
            ),
        )
        log("  Signed APK: ${outputApk.length()} bytes")
    }
}
