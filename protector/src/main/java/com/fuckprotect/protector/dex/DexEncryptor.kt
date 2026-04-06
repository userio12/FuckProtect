package com.fuckprotect.protector.dex

import com.fuckprotect.common.Constants
import com.fuckprotect.common.CryptoParams
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Result of DEX encryption: contains the ciphertext with IV prepended.
 */
data class EncryptedDex(
    /** IV (16 bytes) followed by AES-256-CBC ciphertext. */
    val data: ByteArray,
    /** The parameters used for encryption (key and IV). */
    val params: CryptoParams,
) {
    /** Total size of the encrypted payload (IV + ciphertext). */
    val totalSize: Int get() = data.size
}

/**
 * Encrypts DEX files using AES-256-CBC.
 *
 * The IV is randomly generated per encryption and prepended to the
 * ciphertext so the shell runtime can decrypt without any out-of-band
 * communication.
 */
class DexEncryptor {

    private val secureRandom = SecureRandom()

    /**
     * Encrypt a DEX file's raw bytes with the given key.
     *
     * If no key is provided, a random 32-byte key is generated (useful
     * for testing; in production the key should always be derived from
     * the APK signing certificate).
     */
    fun encrypt(dexBytes: ByteArray, key: ByteArray? = null): EncryptedDex {
        val actualKey = key ?: generateRandomKey()
        val iv = generateRandomIV()

        val cipher = Cipher.getInstance(Constants.ALGORITHM_AES)
        cipher.init(
            Cipher.ENCRYPT_MODE,
            SecretKeySpec(actualKey, "AES"),
            IvParameterSpec(iv),
        )

        val ciphertext = cipher.doFinal(dexBytes)

        // Prepend IV to ciphertext
        val payload = iv + ciphertext

        return EncryptedDex(
            data = payload,
            params = CryptoParams(key = actualKey, iv = iv),
        )
    }

    /**
     * Decrypt a previously encrypted DEX payload.
     *
     * The IV is read from the first 16 bytes of [encryptedData].
     */
    fun decrypt(encryptedData: ByteArray, key: ByteArray): ByteArray {
        require(encryptedData.size > Constants.IV_SIZE_BYTES) {
            "Encrypted data too short: ${encryptedData.size} bytes"
        }

        val iv = encryptedData.copyOfRange(0, Constants.IV_SIZE_BYTES)
        val ciphertext = encryptedData.copyOfRange(
            Constants.IV_SIZE_BYTES,
            encryptedData.size,
        )

        val cipher = Cipher.getInstance(Constants.ALGORITHM_AES)
        cipher.init(
            Cipher.DECRYPT_MODE,
            SecretKeySpec(key, "AES"),
            IvParameterSpec(iv),
        )

        return cipher.doFinal(ciphertext)
    }

    /**
     * Decrypt using a [CryptoParams] object.
     */
    fun decryptWithParams(encryptedData: ByteArray, params: CryptoParams): ByteArray {
        return decrypt(encryptedData, params.key)
    }

    private fun generateRandomKey(): ByteArray {
        val key = ByteArray(Constants.KEY_SIZE_BYTES)
        secureRandom.nextBytes(key)
        return key
    }

    private fun generateRandomIV(): ByteArray {
        val iv = ByteArray(Constants.IV_SIZE_BYTES)
        secureRandom.nextBytes(iv)
        return iv
    }
}
