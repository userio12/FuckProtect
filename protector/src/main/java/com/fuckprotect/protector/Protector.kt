package com.fuckprotect.protector

import com.fuckprotect.protector.builder.Apk
import com.fuckprotect.protector.dex.DexEncryptor
import com.fuckprotect.protector.dex.JunkCodeGenerator
import com.fuckprotect.protector.dex.KeyDerivation
import com.fuckprotect.protector.dex.PayloadBuilder
import com.fuckprotect.protector.dex.hollow.DexMethodHollower
import com.fuckprotect.protector.res.ManifestEditor
import com.fuckprotect.protector.util.ApkSigner
import com.fuckprotect.protector.util.SignatureEmbedder
import com.fuckprotect.protector.util.SoFileEncryptor
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

    override fun call(): Int {
        try {
            println("=== FuckProtect 1.0.0 ===\n")

            val tempWork = workDir ?: File.createTempFile("fp_work_", "").apply { delete(); mkdir() }

            // Phase 1: Parse
            log("Phase 1: Parsing input APK...")
            val apk = Apk(inputApk, tempWork)
            apk.extract()
            log("  DEX files: ${apk.dexFiles.size}")
            log("  Application: ${apk.originalApplication}")

            // Phase 2: Hollow methods
            log("Phase 2: Hollowing methods...")
            val hollower = DexMethodHollower()
            val hollowResult = hollower.hollowAllMethods(apk.primaryDex)
            log("  Hollowed: ${hollowResult.methodCount} methods")

            // Phase 3: Encrypt DEX
            log("Phase 3: Encrypting DEX...")
            val signer = ApkSigner()
            val certHash = signer.getCertificateHash(
                ApkSigner.KeystoreConfig(keystoreFile, storePass, keyAlias, keyPass)
            )
            val aesKey = KeyDerivation.deriveFromCertBytes(certHash)
            val encrypted = DexEncryptor.encrypt(apk.primaryDex.readBytes(), aesKey)
            log("  Encrypted: ${apk.primaryDex.length()} -> ${encrypted.size} bytes")

            // Phase 4: Build payload
            log("Phase 4: Building payload...")
            val payload = PayloadBuilder()
                .setAppClass(apk.originalApplication)
                .setEncryptedDex(encrypted)
                .enableSignatureVerification()
                .build()
            File(tempWork, "assets/fp_payload.dat").apply {
                parentFile?.mkdirs()
                writeBytes(payload)
            }

            // Phase 5: Modify manifest
            log("Phase 5: Modifying manifest...")
            ManifestEditor.hijackApplication(apk.manifestFile!!, apk.originalApplication)

            // Phase 6: Embed cert hash
            log("Phase 6: Embedding certificate hash...")
            val nativeLibDir = File(tempWork, "lib")
            if (nativeLibDir.exists()) {
                SignatureEmbedder().embedAll(nativeLibDir, certHash)
                SoFileEncryptor().encryptAll(nativeLibDir, certHash.copyOfRange(0, 16))
            }

            // Phase 7: Repackage
            log("Phase 7: Repackaging...")
            apk.repackage(outputApk)

            // Phase 8: Sign
            log("Phase 8: Signing...")
            signer.signApk(outputApk, ApkSigner.KeystoreConfig(keystoreFile, storePass, keyAlias, keyPass))

            if (workDir == null) tempWork.deleteRecursively()

            println("\n=== Protection complete ===")
            println("  Output: ${outputApk.absolutePath}")
            return 0
        } catch (e: Exception) {
            System.err.println("ERROR: ${e.message}")
            if (verbose) e.printStackTrace(System.err)
            return 1
        }
    }

    private fun log(msg: String) { if (verbose) println(msg) }

    companion object {
        @JvmStatic fun main(args: Array<String>) {
            System.exit(CommandLine(Protector()).execute(*args))
        }
    }
}
