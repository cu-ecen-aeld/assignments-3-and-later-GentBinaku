#include "../include/security_core.h"
#include "../include/auth_state_machine.h"
#include "../include/key_manager.h"
#include "../include/crypto.h"
#include "../include/internal.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

security_context_t* ironvault_init(hsm_type_t hsm_type) {
    if (hsm_type == HSM_TYPE_NONE) {
        return NULL;
    }

    // Initialize crypto subsystem
    if (crypto_init() != IRONVAULT_SUCCESS) {
        return NULL;
    }

    security_context_t* ctx = (security_context_t*)malloc(sizeof(security_context_t));
    if (!ctx) {
        return NULL;
    }

    memset(ctx, 0, sizeof(security_context_t));
    ctx->hsm_type = hsm_type;
    ctx->auth_state = AUTH_STATE_UNINITIALIZED;
    ctx->initialized = 0;

    // Initialize authentication state machine
    if (auth_sm_init(ctx) != IRONVAULT_SUCCESS) {
        free(ctx);
        return NULL;
    }

    // Initialize key manager
    if (key_manager_init(ctx) != IRONVAULT_SUCCESS) {
        auth_sm_cleanup(ctx);
        free(ctx);
        return NULL;
    }

    ctx->initialized = 1;
    ctx->auth_state = AUTH_STATE_INITIALIZED;
    
    return ctx;
}

void ironvault_cleanup(security_context_t* ctx) {
    if (!ctx) {
        return;
    }

    // Cleanup subsystems
    auth_sm_cleanup(ctx);
    key_manager_cleanup(ctx);
    
    // Zero sensitive data
    memset(ctx->private_key, 0, sizeof(ctx->private_key));
    memset(ctx->master_key_id, 0, sizeof(ctx->master_key_id));
    
    free(ctx);
    crypto_cleanup();
}

auth_state_t ironvault_get_auth_state(security_context_t* ctx) {
    if (!ctx) {
        return AUTH_STATE_ERROR;
    }
    return ctx->auth_state;
}

ironvault_error_t ironvault_generate_keypair(security_context_t* ctx) {
    if (!ctx || !ctx->initialized) {
        return IRONVAULT_ERROR_NOT_INITIALIZED;
    }

    // Generate ECC P-256 keypair
    ironvault_error_t result = crypto_generate_ecc_keypair(
        ctx->private_key,
        ctx->public_key
    );

    if (result != IRONVAULT_SUCCESS) {
        return IRONVAULT_ERROR_CRYPTO_FAILURE;
    }

    return IRONVAULT_SUCCESS;
}

ironvault_error_t ironvault_request_attestation(
    security_context_t* ctx,
    uint8_t* cert_chain_out,
    size_t cert_chain_size,
    size_t* actual_size
) {
    if (!ctx || !ctx->initialized) {
        return IRONVAULT_ERROR_NOT_INITIALIZED;
    }

    if (!cert_chain_out || !actual_size) {
        return IRONVAULT_ERROR_INVALID_PARAM;
    }

    // Simulate attestation certificate chain generation
    // In real implementation, this would interact with hardware
    const char* mock_cert = "-----BEGIN CERTIFICATE-----\n"
                           "Mock X.509 Certificate Chain\n"
                           "Hardware Attestation (EAL 5+)\n"
                           "HSM Type: ";
    
    const char* hsm_name;
    switch (ctx->hsm_type) {
        case HSM_TYPE_STRONGBOX:
            hsm_name = "StrongBox";
            break;
        case HSM_TYPE_SECURE_ENCLAVE:
            hsm_name = "Secure Enclave";
            break;
        case HSM_TYPE_TEE:
            hsm_name = "TEE";
            break;
        default:
            hsm_name = "Unknown";
    }

    size_t total_size = strlen(mock_cert) + strlen(hsm_name) + 50;
    
    if (cert_chain_size < total_size) {
        *actual_size = total_size;
        return IRONVAULT_ERROR_INVALID_PARAM;
    }

    snprintf((char*)cert_chain_out, cert_chain_size, 
             "%s%s\n-----END CERTIFICATE-----\n", mock_cert, hsm_name);
    *actual_size = strlen((char*)cert_chain_out);

    return IRONVAULT_SUCCESS;
}

ironvault_error_t ironvault_sign_data(
    security_context_t* ctx,
    const uint8_t* data,
    size_t data_len,
    uint8_t* signature_out,
    size_t sig_len
) {
    if (!ctx || !ctx->initialized) {
        return IRONVAULT_ERROR_NOT_INITIALIZED;
    }

    if (!data || !signature_out) {
        return IRONVAULT_ERROR_INVALID_PARAM;
    }

    if (sig_len < ECC_P256_SIGNATURE_SIZE) {
        return IRONVAULT_ERROR_INVALID_PARAM;
    }

    // Sign using hardware-backed private key
    return crypto_ecc_sign(ctx->private_key, data, data_len, signature_out);
}

ironvault_error_t ironvault_verify_signature(
    security_context_t* ctx,
    const uint8_t* data,
    size_t data_len,
    const uint8_t* signature,
    size_t sig_len
) {
    if (!ctx || !ctx->initialized) {
        return IRONVAULT_ERROR_NOT_INITIALIZED;
    }

    if (!data || !signature) {
        return IRONVAULT_ERROR_INVALID_PARAM;
    }

    if (sig_len != ECC_P256_SIGNATURE_SIZE) {
        return IRONVAULT_ERROR_INVALID_PARAM;
    }

    // Verify using public key
    return crypto_ecc_verify(ctx->public_key, data, data_len, signature);
}
