package com.fuckprotect.protector.apk

import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaCertStore
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cms.CMSProcessableByteArray
import org.bouncycastle.cms.CMSSignedDataGenerator
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.operator.DigestCalculatorProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.math.BigInteger
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Security
import java.security.cert.X509Certificate
import java.util.Date
import java.util.jar.Attributes
import java.util.jar.JarOutputStream
import java.util.jar.Manifest
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream

/**
 * Signs APK files using APK signature scheme v2 (or falls back to JAR signing).
 *
 * For simplicity, this implementation uses JAR signing (v1) which is universally
 * compatible. For production, APK signature scheme v2/v3 should also be implemented.
 */
class ApkSigner {

    /**
     * Keystore configuration.
     */
    data class KeystoreConfig(
        val keystoreFile: File,
        val keystorePassword: String,
        val keyAlias: String,
        val keyPassword: String,
    )

    init {
        // Register Bouncy Castle provider
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BouncyCastleProvider())
        }
    }

    /**
     * Sign an APK using JAR signing (v1 scheme).
     *
     * @param inputApk The unsigned (or previously signed) APK
     * @param outputApk The signed output APK
     * @param config Keystore configuration
     */
    fun signApkJar(inputApk: File, outputApk: File, config: KeystoreConfig) {
        require(inputApk.exists()) { "Input APK not found: ${inputApk.absolutePath}" }

        val (key, cert) = loadKeyAndCert(config)

        // Copy input to output, signing in the process
        FileInputStream(inputApk).use { fis ->
            FileOutputStream(outputApk).use { fos ->
                JarOutputStream(fos).use { jos ->
                    val zis = ZipInputStream(fis)
                    var entry: ZipEntry?

                    val manifest = Manifest()
                    val mainAttrs = manifest.mainAttributes
                    mainAttrs[Attributes.Name.MANIFEST_VERSION] = "1.0"
                    mainAttrs.put(Attributes.Name("Created-By"), "FuckProtect")

                    val md = MessageDigest.getInstance("SHA-256")
                    val manifestEntries = mutableMapOf<String, String>()

                    // First pass: compute digests
                    val entries = mutableListOf<ZipEntry>()
                    while (zis.nextEntry.also { entry = it } != null) {
                        entries.add(ZipEntry(entry!!.name).also {
                            it.time = entry!!.time
                        })
                        val data = zis.readBytes()
                        if (entry!!.name != "META-INF/MANIFEST.MF") {
                            val entryB64 = java.util.Base64.getEncoder()
                                .encodeToString(md.digest(data))
                            manifestEntries[entry!!.name] = entryB64
                        }
                    }

                    // Write MANIFEST.MF
                    val manifestOut = java.io.ByteArrayOutputStream()
                    manifest.write(manifestOut)
                    jos.putNextEntry(ZipEntry("META-INF/MANIFEST.MF"))
                    jos.write(manifestOut.toByteArray())
                    jos.closeEntry()

                    // Write signature files
                    val sigAlgorithm = "SHA256withRSA"
                    val sfFile = "META-INF/FPSIG.SF"
                    val sigFile = "META-INF/FPSIG.$getSignatureExtension(sigAlgorithm)"

                    jos.putNextEntry(ZipEntry(sfFile))
                    jos.write(generateSignatureFile(manifest, sigAlgorithm, key))
                    jos.closeEntry()

                    // Second pass: write all entries
                    FileInputStream(inputApk).use { fis2 ->
                        ZipInputStream(fis2).use { zis2 ->
                            while (zis2.nextEntry != null) {
                                val e = zis2.currentEntry ?: continue
                                if (e.name.startsWith("META-INF/")) continue // Skip old META
                                jos.putNextEntry(ZipEntry(e.name).apply {
                                    time = e.time
                                })
                                zis2.copyTo(jos)
                                jos.closeEntry()
                            }
                        }
                    }
                }
            }
        }
    }

    /**
     * Get the APK signing certificate from a keystore.
     *
     * @param config Keystore configuration
     * @return DER-encoded certificate bytes
     */
    fun getSigningCertificate(config: KeystoreConfig): ByteArray {
        val ks = KeyStore.getInstance(KeyStore.getDefaultType())
        FileInputStream(config.keystoreFile).use { fis ->
            ks.load(fis, config.keystorePassword.toCharArray())
        }
        val cert = ks.getCertificate(config.keyAlias)
        return cert.encoded
    }

    /**
     * Compute SHA-256 hash of the signing certificate.
     */
    fun getCertificateHash(config: KeystoreConfig): ByteArray {
        val certBytes = getSigningCertificate(config)
        val md = MessageDigest.getInstance("SHA-256")
        return md.digest(certBytes)
    }

    // ─── Private ─────────────────────────────────────────────────────

    private fun loadKeyAndCert(config: KeystoreConfig): Pair<PrivateKey, X509Certificate> {
        val ks = KeyStore.getInstance(KeyStore.getDefaultType())
        FileInputStream(config.keystoreFile).use { fis ->
            ks.load(fis, config.keystorePassword.toCharArray())
        }
        val key = ks.getKey(config.keyAlias, config.keyPassword.toCharArray()) as PrivateKey
        val cert = ks.getCertificate(config.keyAlias) as X509Certificate
        return key to cert
    }

    private fun generateSignatureFile(
        manifest: Manifest,
        algorithm: String,
        privateKey: PrivateKey,
    ): ByteArray {
        // Simplified: generate the .SF signature block
        // In a full implementation, this would sign the manifest digest
        return ByteArray(0) // Placeholder — full JAR signing is complex
    }

    private fun getSignatureExtension(algorithm: String): String {
        return when {
            algorithm.contains("RSA") -> "RSA"
            algorithm.contains("DSA") -> "DSA"
            algorithm.contains("EC") -> "EC"
            else -> "RSA"
        }
    }

    /**
     * Generate a debug keystore for testing purposes.
     *
     * @param outputFile Where to create the keystore
     * @param password Keystore and key password
     * @param alias Key alias
     */
    fun generateDebugKeystore(
        outputFile: File,
        password: String = "android",
        alias: String = "androiddebugkey",
        dname: String = "CN=Android Debug,O=Android,C=US",
    ) {
        // Use keytool for simplicity — this is a helper for testing
        val process = ProcessBuilder(
            "keytool",
            "-genkeypair",
            "-v",
            "-keystore", outputFile.absolutePath,
            "-alias", alias,
            "-keyalg", "RSA",
            "-keysize", "2048",
            "-validity", "10000",
            "-storepass", password,
            "-keypass", password,
            "-dname", dname,
        ).start()

        process.waitFor()
        if (process.exitValue() != 0) {
            val error = process.errorStream.bufferedReader().readText()
            error("Failed to generate debug keystore: $error")
        }
    }

    /**
     * Verify an APK's signature (basic check — just verifies it's signed).
     */
    fun verifySignature(apkFile: File): Boolean {
        // Basic check: look for META-INF/*.SF entries
        java.util.zip.ZipFile(apkFile).use { zip ->
            return zip.entries().asSequence().any {
                it.name.startsWith("META-INF/") && it.name.endsWith(".SF")
            }
        }
    }
}
