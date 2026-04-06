package com.fuckprotect.protector.dex

import com.fuckprotect.common.Constants
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.io.FileInputStream

/**
 * Derives a 32-byte AES-256 key from an APK signing certificate.
 *
 * The key is computed as SHA-256 of the DER-encoded signing certificate.
 * This ensures the key is unique per APK signing identity and is not
 * hardcoded anywhere in the protector or shell.
 */
object KeyDerivation {

    /**
     * Derive an AES key from a certificate file (X.509 DER-encoded).
     *
     * @param certPath Path to the .pem or .der certificate file
     * @return 32-byte AES key
     */
    fun deriveFromCertFile(certPath: String): ByteArray {
        val cf = CertificateFactory.getInstance("X.509")
        FileInputStream(certPath).use { fis ->
            val cert = cf.generateCertificate(fis)
            return deriveFromCertBytes(cert.encoded)
        }
    }

    /**
     * Derive an AES key from raw certificate bytes (DER-encoded).
     *
     * @param certBytes DER-encoded X.509 certificate
     * @return 32-byte AES key (SHA-256 hash of the certificate)
     */
    fun deriveFromCertBytes(certBytes: ByteArray): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(certBytes)
    }

    /**
     * Derive an AES key from a Base64-encoded certificate string.
     *
     * @param certBase64 Base64-encoded DER certificate
     * @return 32-byte AES key
     */
    fun deriveFromCertBase64(certBase64: String): ByteArray {
        val certBytes = java.util.Base64.getDecoder().decode(certBase64)
        return deriveFromCertBytes(certBytes)
    }

    /**
     * Compute SHA-256 hash of arbitrary data (used for signature embedding).
     */
    fun sha256(data: ByteArray): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(data)
    }

    /**
     * Format a hash as a hex string (for logging / embedding).
     */
    fun toHexString(hash: ByteArray): String {
        return hash.joinToString("") { "%02x".format(it) }
    }
}
