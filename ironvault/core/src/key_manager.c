#include "../include/key_manager.h"
#include "../include/crypto.h"
#include "../include/internal.h"
#include <string.h>
#include <stdlib.h>

ironvault_error_t key_manager_init(security_context_t* ctx) {
    if (!ctx) {
        return IRONVAULT_ERROR_INVALID_PARAM;
    }
    // Key manager initialized with context
    return IRONVAULT_SUCCESS;
}

ironvault_error_t key_manager_generate_master_key(security_context_t* ctx) {
    if (!ctx) {
        return IRONVAULT_ERROR_INVALID_PARAM;
    }

    // Generate a unique master key ID in hardware
    // In real implementation, this would be created in StrongBox/Secure Enclave
    ironvault_error_t result = crypto_random_bytes(ctx->master_key_id, 32);
    if (result != IRONVAULT_SUCCESS) {
        return IRONVAULT_ERROR_CRYPTO_FAILURE;
    }

    return IRONVAULT_SUCCESS;
}

ironvault_error_t key_manager_generate_dek(
    security_context_t* ctx,
    uint8_t* dek_out,
    size_t dek_size
) {
    if (!ctx || !dek_out) {
        return IRONVAULT_ERROR_INVALID_PARAM;
    }

    if (dek_size != AES_256_KEY_SIZE) {
        return IRONVAULT_ERROR_INVALID_PARAM;
    }

    // Generate random DEK for symmetric encryption
    return crypto_random_bytes(dek_out, dek_size);
}

ironvault_error_t key_manager_wrap_dek(
    security_context_t* ctx,
    const uint8_t* dek,
    size_t dek_len,
    uint8_t* wrapped_out,
    size_t wrapped_size
) {
    if (!ctx || !dek || !wrapped_out) {
        return IRONVAULT_ERROR_INVALID_PARAM;
    }

    // Ensure wrapped buffer is large enough
    // wrapped = iv + ciphertext + tag
    size_t required_size = AES_GCM_IV_SIZE + dek_len + AES_GCM_TAG_SIZE;
    if (wrapped_size < required_size) {
        return IRONVAULT_ERROR_INVALID_PARAM;
    }

    // Generate random IV
    uint8_t iv[AES_GCM_IV_SIZE];
    ironvault_error_t result = crypto_random_bytes(iv, AES_GCM_IV_SIZE);
    if (result != IRONVAULT_SUCCESS) {
        return result;
    }

    // Use master key to wrap DEK
    // In real implementation, master key would be in hardware
    uint8_t* ciphertext = wrapped_out + AES_GCM_IV_SIZE;
    uint8_t* tag = ciphertext + dek_len;

    // Copy IV to output
    memcpy(wrapped_out, iv, AES_GCM_IV_SIZE);

    // Encrypt DEK with master key
    result = crypto_aes_gcm_encrypt(
        ctx->master_key_id,  // Using master_key_id as key for simulation
        iv,
        dek,
        dek_len,
        ciphertext,
        tag
    );

    return result;
}

ironvault_error_t key_manager_unwrap_dek(
    security_context_t* ctx,
    const uint8_t* wrapped,
    size_t wrapped_len,
    uint8_t* dek_out,
    size_t dek_size
) {
    if (!ctx || !wrapped || !dek_out) {
        return IRONVAULT_ERROR_INVALID_PARAM;
    }

    // Validate wrapped size
    size_t min_size = AES_GCM_IV_SIZE + dek_size + AES_GCM_TAG_SIZE;
    if (wrapped_len < min_size) {
        return IRONVAULT_ERROR_INVALID_PARAM;
    }

    // Extract components
    const uint8_t* iv = wrapped;
    const uint8_t* ciphertext = wrapped + AES_GCM_IV_SIZE;
    const uint8_t* tag = ciphertext + dek_size;

    // Decrypt DEK with master key
    return crypto_aes_gcm_decrypt(
        ctx->master_key_id,  // Using master_key_id as key for simulation
        iv,
        ciphertext,
        dek_size,
        tag,
        dek_out
    );
}

void key_manager_cleanup(security_context_t* ctx) {
    if (ctx) {
        // Zero out sensitive key material
        memset(ctx->master_key_id, 0, sizeof(ctx->master_key_id));
    }
}
