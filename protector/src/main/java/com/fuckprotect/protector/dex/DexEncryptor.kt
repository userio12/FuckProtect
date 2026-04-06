package com.fuckprotect.protector.dex

import com.fuckprotect.common.Constants
import com.fuckprotect.common.CryptoParams
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Result of DEX encryption.
 */
data class EncryptedDex(
    val data: ByteArray,
    val params: CryptoParams,
) {
    val size: Int get() = data.size
}

/**
 * Encrypts DEX files using AES-256-CBC.
 */
class DexEncryptor {

    private val secureRandom = SecureRandom()

    fun encrypt(dexBytes: ByteArray, key: ByteArray? = null): EncryptedDex {
        val actualKey = key ?: generateRandomKey()
        val iv = generateRandomIV()
        val cipher = Cipher.getInstance(Constants.ALGORITHM_AES)
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(actualKey, "AES"), IvParameterSpec(iv))
        val ciphertext = cipher.doFinal(dexBytes)
        val payload = iv + ciphertext
        return EncryptedDex(data = payload, params = CryptoParams(key = actualKey, iv = iv))
    }

    fun decrypt(encryptedData: ByteArray, key: ByteArray): ByteArray {
        require(encryptedData.size > Constants.IV_SIZE_BYTES)
        val iv = encryptedData.copyOfRange(0, Constants.IV_SIZE_BYTES)
        val ciphertext = encryptedData.copyOfRange(Constants.IV_SIZE_BYTES, encryptedData.size)
        val cipher = Cipher.getInstance(Constants.ALGORITHM_AES)
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
        return cipher.doFinal(ciphertext)
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

    companion object {
        @JvmStatic
        fun encrypt(dexBytes: ByteArray, key: ByteArray): EncryptedDex {
            return DexEncryptor().encrypt(dexBytes, key)
        }
    }
}
