package com.fuckprotect.protector

import com.fuckprotect.protector.builder.Apk
import com.fuckprotect.protector.config.ShellConfig
import com.fuckprotect.protector.dex.DexEncryptor
import com.fuckprotect.protector.dex.KeyDerivation
import com.fuckprotect.protector.res.ManifestEditor
import com.fuckprotect.protector.task.ThreadPool
import com.fuckprotect.protector.util.ApkSigner
import com.fuckprotect.protector.util.LogUtils
import com.fuckprotect.protector.util.SignatureEmbedder
import picocli.CommandLine
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import java.io.File
import java.util.concurrent.Callable

@Command(
    name = "fuckprotect",
    mixinStandardHelpOptions = true,
    version = ["FuckProtect 1.0.0"],
    description = ["Protect Android APKs from reverse engineering"],
)
class Protector : Callable<Int> {

    @Option(names = ["-i", "--input"], description = ["Input APK file"], required = true)
    private lateinit var inputApk: File

    @Option(names = ["-o", "--output"], description = ["Output protected APK"], required = true)
    private lateinit var outputApk: File

    @Option(names = ["--keystore"], description = ["Keystore file"], required = true)
    private lateinit var keystoreFile: File

    @Option(names = ["--key-alias"], description = ["Key alias"], required = true)
    private lateinit var keyAlias: String

    @Option(names = ["--key-pass"], description = ["Key password"], required = true)
    private lateinit var keyPass: String

    @Option(names = ["--store-pass"], description = ["Keystore password"], required = true)
    private lateinit var storePass: String

    @Option(names = ["--work-dir"], description = ["Working directory"])
    private var workDir: File? = null

    @Option(names = ["-v", "--verbose"], description = ["Verbose output"])
    private var verbose: Boolean = false

    @Option(names = ["--verify-sign"], description = ["Enable signature verification"])
    private var verifySign: Boolean = false

    override fun call(): Int {
        try {
            println("=== FuckProtect 1.0.0 ===\n")

            val tempWork = workDir ?: File.createTempFile("fp_work_", "").apply { delete(); mkdir() }

            // Phase 1: Parse APK
            LogUtils.setOpenNoisyLog(verbose)
            LogUtils.info("Phase 1: Parsing input APK...")
            val apk = Apk.Builder()
                .filePath(inputApk.absolutePath)
                .workspaceDir(tempWork)
                .sign(true)
                .verifySign(verifySign)
                .build()
            apk.extract()
            LogUtils.info("  DEX files: %d", apk.dexFiles.size)
            LogUtils.info("  Application: %s", apk.applicationName)

            if (apk.applicationName.isNullOrEmpty()) {
                System.err.println("ERROR: Could not determine original Application class")
                return 1
            }

            // Phase 2: Encrypt DEX
            LogUtils.info("Phase 2: Encrypting DEX files...")
            val signer = ApkSigner()
            val certHash = signer.getCertificateHash(
                ApkSigner.KeystoreConfig(keystoreFile, storePass, keyAlias, keyPass)
            )
            val aesKey = KeyDerivation.deriveFromCertBytes(certHash)

            val primaryDex = apk.primaryDex
            if (primaryDex == null || !primaryDex.exists()) {
                System.err.println("ERROR: No DEX files found")
                return 1
            }

            val dexBytes = primaryDex.readBytes()
            val encrypted = DexEncryptor.encrypt(dexBytes, aesKey)
            LogUtils.info("  Encrypted: %d -> %d bytes", dexBytes.size, encrypted.size)

            // Phase 3: Build payload and write to assets
            LogUtils.info("Phase 3: Building payload...")
            val payloadDir = File(tempWork, "assets").apply { mkdirs() }
            val payloadFile = File(payloadDir, "fp_payload.dat")
            payloadFile.writeBytes(encrypted.data)

            // Phase 4: Hijack manifest
            LogUtils.info("Phase 4: Modifying manifest...")
            val manifestFile = apk.manifestFile
            if (manifestFile != null) {
                ManifestEditor.hijackApplicationInPlace(manifestFile, apk.applicationName)
                LogUtils.info("  Manifest hijacked")
            }

            // Phase 5: Embed cert hash into native libs
            LogUtils.info("Phase 5: Embedding certificate hash...")
            val nativeLibDir = File(tempWork, "lib")
            if (nativeLibDir.exists()) {
                SignatureEmbedder().embedAll(nativeLibDir, certHash)
                LogUtils.info("  Certificate hash embedded")
            }

            // Phase 6: Repackage
            LogUtils.info("Phase 6: Repackaging...")
            apk.buildPackage(inputApk.absolutePath, tempWork.absolutePath, tempWork.absolutePath)

            // Phase 7: Sign
            LogUtils.info("Phase 7: Signing...")
            val unsignedApk = File(tempWork, "unsigned.apk")
            if (unsignedApk.exists()) {
                signer.signApkJar(
                    unsignedApk, outputApk,
                    ApkSigner.KeystoreConfig(keystoreFile, storePass, keyAlias, keyPass)
                )
            }

            if (workDir == null) {
                Thread.sleep(1000) // Give filesystem time to settle
                tempWork.deleteRecursively()
            }

            println("\n=== Protection complete ===")
            println("  Output: ${outputApk.absolutePath}")
            return 0

        } catch (e: Exception) {
            System.err.println("ERROR: ${e.message}")
            if (verbose) e.printStackTrace(System.err)
            return 1
        }
    }

    companion object {
        @JvmStatic fun main(args: Array<String>) {
            System.exit(CommandLine(Protector()).execute(*args))
        }
    }
}
