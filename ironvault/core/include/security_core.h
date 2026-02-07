#ifndef IRONVAULT_SECURITY_CORE_H
#define IRONVAULT_SECURITY_CORE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Hardware security module types
typedef enum {
    HSM_TYPE_NONE = 0,
    HSM_TYPE_STRONGBOX = 1,    // Android StrongBox (EAL 5+)
    HSM_TYPE_TEE = 2,           // Trusted Execution Environment
    HSM_TYPE_SECURE_ENCLAVE = 3 // iOS Secure Enclave
} hsm_type_t;

// Authentication states
typedef enum {
    AUTH_STATE_UNINITIALIZED = 0,
    AUTH_STATE_INITIALIZED = 1,
    AUTH_STATE_AUTHENTICATING = 2,
    AUTH_STATE_AUTHENTICATED = 3,
    AUTH_STATE_LOCKED = 4,
    AUTH_STATE_ERROR = 5
} auth_state_t;

// Error codes
typedef enum {
    IRONVAULT_SUCCESS = 0,
    IRONVAULT_ERROR_INVALID_PARAM = -1,
    IRONVAULT_ERROR_NOT_INITIALIZED = -2,
    IRONVAULT_ERROR_HSM_UNAVAILABLE = -3,
    IRONVAULT_ERROR_CRYPTO_FAILURE = -4,
    IRONVAULT_ERROR_ATTESTATION_FAILED = -5,
    IRONVAULT_ERROR_MEMORY = -6
} ironvault_error_t;

// Security context handle
typedef struct security_context security_context_t;

/**
 * Initialize the security core
 * @param hsm_type Hardware security module type
 * @return Context handle or NULL on failure
 */
security_context_t* ironvault_init(hsm_type_t hsm_type);

/**
 * Cleanup and destroy security context
 * @param ctx Security context
 */
void ironvault_cleanup(security_context_t* ctx);

/**
 * Get current authentication state
 * @param ctx Security context
 * @return Current authentication state
 */
auth_state_t ironvault_get_auth_state(security_context_t* ctx);

/**
 * Generate hardware-backed key pair (ECC P-256)
 * @param ctx Security context
 * @return Error code
 */
ironvault_error_t ironvault_generate_keypair(security_context_t* ctx);

/**
 * Request remote key attestation
 * @param ctx Security context
 * @param cert_chain_out Buffer for X.509 certificate chain
 * @param cert_chain_size Size of certificate chain buffer
 * @param actual_size Actual size of certificate chain
 * @return Error code
 */
ironvault_error_t ironvault_request_attestation(
    security_context_t* ctx,
    uint8_t* cert_chain_out,
    size_t cert_chain_size,
    size_t* actual_size
);

/**
 * Sign data using hardware-backed key
 * @param ctx Security context
 * @param data Data to sign
 * @param data_len Length of data
 * @param signature_out Buffer for signature
 * @param sig_len Length of signature buffer
 * @return Error code
 */
ironvault_error_t ironvault_sign_data(
    security_context_t* ctx,
    const uint8_t* data,
    size_t data_len,
    uint8_t* signature_out,
    size_t sig_len
);

/**
 * Verify signature using hardware-backed key
 * @param ctx Security context
 * @param data Data to verify
 * @param data_len Length of data
 * @param signature Signature to verify
 * @param sig_len Length of signature
 * @return Error code (SUCCESS if valid)
 */
ironvault_error_t ironvault_verify_signature(
    security_context_t* ctx,
    const uint8_t* data,
    size_t data_len,
    const uint8_t* signature,
    size_t sig_len
);

#ifdef __cplusplus
}
#endif

#endif // IRONVAULT_SECURITY_CORE_H
