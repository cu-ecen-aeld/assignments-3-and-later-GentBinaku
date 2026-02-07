package com.ironvault.sdk

/**
 * IronVault Security SDK for Android
 * Provides high-assurance user authentication with hardware-backed security
 */
class IronVault private constructor(private val securityLevel: SecurityLevel) {

    /**
     * Hardware security levels
     */
    enum class SecurityLevel {
        /** Android StrongBox (discrete Secure Element, EAL 5+) */
        STRONGBOX,
        /** Trusted Execution Environment (TEE) */
        TEE,
        /** Software fallback (not recommended for production) */
        SOFTWARE
    }

    /**
     * Authentication state
     */
    enum class AuthState {
        UNINITIALIZED,
        INITIALIZED,
        AUTHENTICATING,
        AUTHENTICATED,
        LOCKED,
        ERROR
    }

    /**
     * Result wrapper for operations
     */
    sealed class Result<out T> {
        data class Success<T>(val data: T) : Result<T>()
        data class Error(val code: Int, val message: String) : Result<Nothing>()
    }

    private var nativeHandle: Long = 0

    init {
        // Load native library
        System.loadLibrary("ironvault_jni")
        nativeHandle = nativeInit(securityLevel.ordinal)
    }

    /**
     * Get current authentication state
     */
    fun getAuthState(): AuthState {
        val state = nativeGetAuthState(nativeHandle)
        return AuthState.values()[state]
    }

    /**
     * Generate hardware-backed ECC P-256 key pair
     */
    fun generateKeyPair(): Result<Unit> {
        val result = nativeGenerateKeyPair(nativeHandle)
        return if (result == 0) {
            Result.Success(Unit)
        } else {
            Result.Error(result, "Failed to generate key pair")
        }
    }

    /**
     * Request remote key attestation
     * Returns X.509 certificate chain proving hardware residency
     */
    fun requestAttestation(): Result<ByteArray> {
        val cert = nativeRequestAttestation(nativeHandle)
        return if (cert != null) {
            Result.Success(cert)
        } else {
            Result.Error(-1, "Failed to request attestation")
        }
    }

    /**
     * Sign data using hardware-backed key
     */
    fun signData(data: ByteArray): Result<ByteArray> {
        val signature = nativeSignData(nativeHandle, data)
        return if (signature != null) {
            Result.Success(signature)
        } else {
            Result.Error(-1, "Failed to sign data")
        }
    }

    /**
     * Verify signature using hardware-backed key
     */
    fun verifySignature(data: ByteArray, signature: ByteArray): Result<Boolean> {
        val result = nativeVerifySignature(nativeHandle, data, signature)
        return if (result == 0) {
            Result.Success(true)
        } else {
            Result.Success(false)
        }
    }

    /**
     * Generate Data Encryption Key (DEK) for high-speed operations
     * Protected by hardware master key
     */
    fun generateDEK(): Result<ByteArray> {
        val dek = nativeGenerateDEK(nativeHandle)
        return if (dek != null) {
            Result.Success(dek)
        } else {
            Result.Error(-1, "Failed to generate DEK")
        }
    }

    /**
     * Wrap DEK with hardware master key
     */
    fun wrapDEK(dek: ByteArray): Result<ByteArray> {
        val wrapped = nativeWrapDEK(nativeHandle, dek)
        return if (wrapped != null) {
            Result.Success(wrapped)
        } else {
            Result.Error(-1, "Failed to wrap DEK")
        }
    }

    /**
     * Unwrap DEK using hardware master key
     */
    fun unwrapDEK(wrappedDEK: ByteArray): Result<ByteArray> {
        val dek = nativeUnwrapDEK(nativeHandle, wrappedDEK)
        return if (dek != null) {
            Result.Success(dek)
        } else {
            Result.Error(-1, "Failed to unwrap DEK")
        }
    }

    /**
     * Cleanup and release resources
     */
    fun cleanup() {
        if (nativeHandle != 0L) {
            nativeCleanup(nativeHandle)
            nativeHandle = 0
        }
    }

    // Native methods
    private external fun nativeInit(securityLevel: Int): Long
    private external fun nativeCleanup(handle: Long)
    private external fun nativeGetAuthState(handle: Long): Int
    private external fun nativeGenerateKeyPair(handle: Long): Int
    private external fun nativeRequestAttestation(handle: Long): ByteArray?
    private external fun nativeSignData(handle: Long, data: ByteArray): ByteArray?
    private external fun nativeVerifySignature(handle: Long, data: ByteArray, signature: ByteArray): Int
    private external fun nativeGenerateDEK(handle: Long): ByteArray?
    private external fun nativeWrapDEK(handle: Long, dek: ByteArray): ByteArray?
    private external fun nativeUnwrapDEK(handle: Long, wrappedDEK: ByteArray): ByteArray?

    companion object {
        /**
         * Create IronVault instance with automatic hardware detection
         * Falls back from StrongBox -> TEE -> Software
         */
        fun create(): IronVault {
            val securityLevel = detectBestSecurityLevel()
            return IronVault(securityLevel)
        }

        /**
         * Create IronVault instance with specific security level
         */
        fun create(securityLevel: SecurityLevel): IronVault {
            return IronVault(securityLevel)
        }

        /**
         * Detect best available security level on device
         */
        private fun detectBestSecurityLevel(): SecurityLevel {
            // Check for StrongBox support
            if (hasStrongBoxSupport()) {
                return SecurityLevel.STRONGBOX
            }
            // Check for TEE support
            if (hasTEESupport()) {
                return SecurityLevel.TEE
            }
            // Fallback to software
            return SecurityLevel.SOFTWARE
        }

        private external fun hasStrongBoxSupport(): Boolean
        private external fun hasTEESupport(): Boolean
    }
}
