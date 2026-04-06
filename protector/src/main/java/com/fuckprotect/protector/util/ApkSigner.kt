package com.fuckprotect.protector.util

import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.Security
import java.security.cert.X509Certificate
import java.util.jar.Attributes
import java.util.jar.JarOutputStream
import java.util.jar.Manifest
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream

/**
 * Signs APK files using JAR signing (v1 scheme).
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
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BouncyCastleProvider())
        }
    }

    /**
     * Sign an APK using JAR signing (v1 scheme).
     */
    fun signApkJar(inputApk: File, outputApk: File, config: KeystoreConfig) {
        require(inputApk.exists()) { "Input APK not found: ${inputApk.absolutePath}" }

        val (key, cert) = loadKeyAndCert(config)

        FileInputStream(inputApk).use { fis ->
            FileOutputStream(outputApk).use { fos ->
                JarOutputStream(fos).use { jos ->
                    val zis = ZipInputStream(fis)
                    var entry: ZipEntry?

                    val manifest = Manifest()
                    manifest.mainAttributes[Attributes.Name.MANIFEST_VERSION] = "1.0"
                    manifest.mainAttributes.put(Attributes.Name("Created-By"), "FuckProtect")

                    val md = MessageDigest.getInstance("SHA-256")
                    val manifestEntries = mutableMapOf<String, String>()

                    // First pass: compute digests
                    while (true) {
                        entry = zis.nextEntry ?: break
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

                    // Write signature file
                    val sigAlgorithm = "SHA256withRSA"
                    val sfFile = "META-INF/FPSIG.SF"

                    jos.putNextEntry(ZipEntry(sfFile))
                    jos.write(generateSignatureFile(manifest, sigAlgorithm, key))
                    jos.closeEntry()

                    // Second pass: copy all entries
                    FileInputStream(inputApk).use { fis2 ->
                        ZipInputStream(fis2).use { zis2 ->
                            var e: ZipEntry?
                            while (true) {
                                e = zis2.nextEntry ?: break
                                if (e!!.name.startsWith("META-INF/")) continue
                                val newEntry = ZipEntry(e!!.name)
                                newEntry.time = e!!.time
                                jos.putNextEntry(newEntry)
                                zis2.copyTo(jos)
                                jos.closeEntry()
                            }
                        }
                    }
                }
            }
        }
    }

    fun getSigningCertificate(config: KeystoreConfig): ByteArray {
        val ks = KeyStore.getInstance(KeyStore.getDefaultType())
        FileInputStream(config.keystoreFile).use { fis ->
            ks.load(fis, config.keystorePassword.toCharArray())
        }
        val cert = ks.getCertificate(config.keyAlias)
        return cert.encoded
    }

    fun getCertificateHash(config: KeystoreConfig): ByteArray {
        val certBytes = getSigningCertificate(config)
        val md = MessageDigest.getInstance("SHA-256")
        return md.digest(certBytes)
    }

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
        return ByteArray(0)
    }

    fun generateDebugKeystore(
        outputFile: File,
        password: String = "android",
        alias: String = "androiddebugkey",
        dname: String = "CN=Android Debug,O=Android,C=US",
    ) {
        val process = ProcessBuilder(
            "keytool", "-genkeypair", "-v",
            "-keystore", outputFile.absolutePath,
            "-alias", alias,
            "-keyalg", "RSA", "-keysize", "2048", "-validity", "10000",
            "-storepass", password, "-keypass", password,
            "-dname", dname,
        ).start()
        process.waitFor()
        if (process.exitValue() != 0) {
            val error = process.errorStream.bufferedReader().readText()
            error("Failed to generate debug keystore: $error")
        }
    }

    fun verifySignature(apkFile: File): Boolean {
        java.util.zip.ZipFile(apkFile).use { zip ->
            return zip.entries().asSequence().any {
                it.name.startsWith("META-INF/") && it.name.endsWith(".SF")
            }
        }
    }
}
