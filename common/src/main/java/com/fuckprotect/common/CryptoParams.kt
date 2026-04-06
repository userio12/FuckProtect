package com.fuckprotect.common

/**
 * Cryptographic parameters used for DEX encryption and decryption.
 *
 * The protector generates a random 32-byte AES key and a random 16-byte IV
 * per protection session. The IV is prepended to the encrypted payload so
 * the shell runtime can reconstruct the cipher without any out-of-band
 * key exchange.
 *
 * The AES key itself is derived at build time from the APK signing certificate:
 *   key = SHA-256(signingCertificate)
 *
 * This means the key is unique per APK signing identity and is embedded
 * in the native shell library at protection time.
 */
data class CryptoParams(
    /** AES-256 key (32 bytes). */
    val key: ByteArray,
    /** Initialization vector (16 bytes). */
    val iv: ByteArray,
) {
    init {
        require(key.size == Constants.KEY_SIZE_BYTES) {
            "AES key must be ${Constants.KEY_SIZE_BYTES} bytes, got ${key.size}"
        }
        require(iv.size == Constants.IV_SIZE_BYTES) {
            "IV must be ${Constants.IV_SIZE_BYTES} bytes, got ${iv.size}"
        }
    }

    /** Cipher transformation string (matches [Constants.ALGORITHM_AES]). */
    val algorithm: String = Constants.ALGORITHM_AES

    /**
     * Create a copy of this instance with defensively copied byte arrays.
     */
    fun copy(): CryptoParams = CryptoParams(
        key = key.copyOf(),
        iv = iv.copyOf(),
    )

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is CryptoParams) return false
        return key.contentEquals(other.key) && iv.contentEquals(other.iv)
    }

    override fun hashCode(): Int {
        var result = key.contentHashCode()
        result = 31 * result + iv.contentHashCode()
        return result
    }

    /**
     * Zero out key and IV material. Call this when the params are no longer
     * needed to reduce key material lifetime in memory.
     */
    fun destroy() {
        key.fill(0)
        iv.fill(0)
    }
}
