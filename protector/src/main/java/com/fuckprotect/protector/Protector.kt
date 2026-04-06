package com.fuckprotect.protector

import com.fuckprotect.common.Constants
import com.fuckprotect.common.PayloadHeader
import com.fuckprotect.protector.apk.ApkPackager
import com.fuckprotect.protector.apk.ApkParser
import com.fuckprotect.protector.apk.ApkSigner
import com.fuckprotect.protector.apk.ManifestEditor
import com.fuckprotect.protector.dex.DexEncryptor
import com.fuckprotect.protector.dex.JunkCodeGenerator
import com.fuckprotect.protector.dex.KeyDerivation
import com.fuckprotect.protector.dex.PayloadBuilder
import com.fuckprotect.protector.embedder.SignatureEmbedder
import com.fuckprotect.protector.native.SoFileEncryptor
import picocli.CommandLine
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import java.io.File
import java.util.concurrent.Callable

/**
 * FuckProtect — Android APK protection tool.
 *
 * Takes an input APK, encrypts its DEX files, injects the shell runtime,
 * and outputs a protected APK that resists reverse engineering.
 *
 * Usage:
 *   java -jar protector.jar \
 *       --input app.apk \
 *       --output app-protected.apk \
 *       --keystore release.jks \
 *       --key-alias mykey \
 *       --key-pass mykeypass \
 *       --store-pass storepass
 */
@Command(
    name = "fuckprotect",
    mixinStandardHelpOptions = true,
    version = ["FuckProtect 1.0.0"],
    description = ["Protect Android APKs from reverse engineering"],
)
class Protector : Callable<Int> {

    @Option(
        names = ["-i", "--input"],
        description = ["Input APK file to protect"],
        required = true,
    )
    private lateinit var inputApk: File

    @Option(
        names = ["-o", "--output"],
        description = ["Output protected APK file"],
        required = true,
    )
    private lateinit var outputApk: File

    @Option(
        names = ["--keystore"],
        description = ["Keystore file for signing"],
        required = true,
    )
    private lateinit var keystoreFile: File

    @Option(
        names = ["--key-alias"],
        description = ["Keystore key alias"],
        required = true,
    )
    private lateinit var keyAlias: String

    @Option(
        names = ["--key-pass"],
        description = ["Key password"],
        required = true,
    )
    private lateinit var keyPass: String

    @Option(
        names = ["--store-pass"],
        description = ["Keystore password"],
        required = true,
    )
    private lateinit var storePass: String

    @Option(
        names = ["--work-dir"],
        description = ["Temporary working directory (default: auto-created)"],
    )
    private var workDir: File? = null

    @Option(
        names = ["--disable-sign-check"],
        description = ["Disable APK signature verification in the shell"],
    )
    private var disableSignCheck: Boolean = false

    @Option(
        names = ["-v", "--verbose"],
        description = ["Verbose output"],
    )
    private var verbose: Boolean = false

    override fun call(): Int {
        try {
            println("=== FuckProtect 1.0.0 ===")
            println()

            // Phase 1: Parse input APK
            log("Phase 1: Parsing input APK...")
            val apkParser = ApkParser()
            val tempWork = workDir ?: File.createTempFile("fp_work_", "").apply {
                delete()
                mkdir()
            }
            val extracted = apkParser.extract(inputApk, tempWork)
            apkParser.parseAll(extracted)

            log("  DEX files found: ${extracted.dexFiles.size}")
            log("  Original Application: ${extracted.originalApplicationClass}")
            log("  Package: ${extracted.packageName}")

            if (extracted.originalApplicationClass == null) {
                System.err.println("ERROR: Could not determine original Application class")
                return 1
            }

            // Phase 2: Encrypt DEX files
            log("Phase 2: Encrypting DEX files...")
            val dexEncryptor = DexEncryptor()

            // Derive AES key from signing certificate
            val signer = ApkSigner()
            val certHash = signer.getCertificateHash(
                ApkSigner.KeystoreConfig(
                    keystoreFile = keystoreFile,
                    keystorePassword = storePass,
                    keyAlias = keyAlias,
                    keyPassword = keyPass,
                )
            )
            val aesKey = KeyDerivation.deriveFromCertBytes(certHash)
            log("  AES key derived from signing certificate: ${KeyDerivation.toHexString(certHash).take(16)}...")

            // Encrypt the primary DEX (classes.dex)
            val primaryDex = extracted.dexFiles.firstOrNull()
            if (primaryDex == null) {
                System.err.println("ERROR: No DEX files found in APK")
                return 1
            }

            val dexBytes = primaryDex.readBytes()
            val encrypted = dexEncryptor.encrypt(dexBytes, aesKey)
            log("  Primary DEX encrypted: ${dexBytes.size} -> ${encrypted.totalSize} bytes (with IV)")

            // Build the payload
            log("Phase 3: Building payload...")
            val payloadBuilder = PayloadBuilder()
                .setOriginalAppClass(extracted.originalApplicationClass!!)
                .setEncryptedDexData(encrypted.data)
                .enableNativeProtection()

            if (!disableSignCheck) {
                payloadBuilder.enableSignatureVerification()
            }

            val (payload, summary) = payloadBuilder.buildWithSummary()
            log(summary)

            // Write payload to temp file
            val payloadFile = File(tempWork, "fp_payload.dat")
            payloadFile.writeBytes(payload)

            // Phase 4: Modify manifest
            log("Phase 4: Modifying manifest...")
            val manifestEditor = ManifestEditor()
            if (extracted.manifest != null) {
                manifestEditor.hijackApplicationInPlace(
                    extracted.manifest,
                    extracted.originalApplicationClass!!
                )
                val verification = manifestEditor.verifyHijack(extracted.manifest.readText())
                log("  Manifest hijack valid: ${verification.isValid}")
                if (!verification.isValid) {
                    System.err.println("WARNING: Manifest hijack may have failed")
                }
            } else {
                System.err.println("ERROR: AndroidManifest.xml not found")
                return 1
            }

            // Phase 4b: Embed cert hash into native library
            log("Phase 4b: Embedding signature hash into native library...")
            val embedder = SignatureEmbedder()
            val nativeLibDir = File(tempWork, "lib")
            if (nativeLibDir.exists()) {
                embedder.embedAll(nativeLibDir, certHash)
                log("  Certificate hash embedded into libshell.so")

                // Phase 4c: Encrypt native library sections with RC4
                log("Phase 4c: Encrypting native library sections...")
                val soEncryptor = SoFileEncryptor()
                val rc4Key = ByteArray(SoFileEncryptor.RC4_KEY_SIZE) {
                    (it * 0x37 and 0xFF).toByte()
                }
                soEncryptor.encryptAllNativeLibs(nativeLibDir, rc4Key)
                log("  Native library sections encrypted with RC4")
            } else {
                log("  WARNING: No native libs in APK — signature embedding skipped")
            }

            // Phase 4d: Generate junk code DEX
            log("Phase 4d: Generating junk code DEX...")
            val junkGen = JunkCodeGenerator()
            val junkDex = junkGen.generateDex()
            val junkDexFile = File(tempWork, "classes.dex").apply {
                // If classes.dex already exists, rename it first
                if (exists()) {
                    renameTo(File(tempWork, "classes_orig.dex"))
                }
            }
            junkDexFile.writeBytes(junkDex)
            log("  Junk code DEX generated: ${junkDex.size} bytes")

            // Phase 5: Repackage APK
            log("Phase 5: Repackaging...")
            val packager = ApkPackager()
            val unsignedApk = File.createTempFile("fp_unsigned_", ".apk").apply { deleteOnExit() }
            packager.buildApkWithPayload(tempWork, unsignedApk, payloadFile)
            log("  Unsigned APK created: ${unsignedApk.length()} bytes")

            // Phase 6: Sign APK
            log("Phase 6: Signing APK...")
            signer.signApkJar(
                unsignedApk,
                outputApk,
                ApkSigner.KeystoreConfig(
                    keystoreFile = keystoreFile,
                    keystorePassword = storePass,
                    keyAlias = keyAlias,
                    keyPassword = keyPass,
                )
            )
            log("  Signed APK: ${outputApk.length()} bytes")

            // Cleanup
            if (workDir == null) {
                tempWork.deleteRecursively()
            }

            println()
            println("=== Protection complete ===")
            println("  Output: ${outputApk.absolutePath}")
            println("  Original size: ${inputApk.length()} bytes")
            println("  Protected size: ${outputApk.length()} bytes")
            println()
            println("Next steps:")
            println("  1. Install: adb install -r ${outputApk.absolutePath}")
            println("  2. Verify: adb logcat | grep FuckProtectShell")

            return 0

        } catch (e: Exception) {
            System.err.println("ERROR: ${e.message}")
            if (verbose) e.printStackTrace(System.err)
            return 1
        }
    }

    private fun log(message: String) {
        if (verbose) println(message)
    }

    companion object {
        @JvmStatic
        fun main(args: Array<String>) {
            val exitCode = CommandLine(Protector()).execute(*args)
            System.exit(exitCode)
        }
    }
}
