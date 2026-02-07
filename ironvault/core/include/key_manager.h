#ifndef IRONVAULT_KEY_MANAGER_H
#define IRONVAULT_KEY_MANAGER_H

#include <stdint.h>
#include <stddef.h>
#include "security_core.h"

#ifdef __cplusplus
extern "C" {
#endif

// Key types for hybrid encryption model
typedef enum {
    KEY_TYPE_MASTER = 0,  // Hardware-protected master key
    KEY_TYPE_DEK = 1      // Data Encryption Key (symmetric)
} key_type_t;

// Key handle
typedef struct key_handle key_handle_t;

/**
 * Initialize key manager
 * @param ctx Security context
 * @return Error code
 */
ironvault_error_t key_manager_init(security_context_t* ctx);

/**
 * Generate master key in hardware
 * @param ctx Security context
 * @return Error code
 */
ironvault_error_t key_manager_generate_master_key(security_context_t* ctx);

/**
 * Generate Data Encryption Key (DEK)
 * Protected by master key
 * @param ctx Security context
 * @param dek_out Buffer for DEK
 * @param dek_size Size of DEK buffer (should be 32 bytes for AES-256)
 * @return Error code
 */
ironvault_error_t key_manager_generate_dek(
    security_context_t* ctx,
    uint8_t* dek_out,
    size_t dek_size
);

/**
 * Wrap DEK with master key
 * @param ctx Security context
 * @param dek Data Encryption Key to wrap
 * @param dek_len Length of DEK
 * @param wrapped_out Buffer for wrapped key
 * @param wrapped_size Size of wrapped buffer
 * @return Error code
 */
ironvault_error_t key_manager_wrap_dek(
    security_context_t* ctx,
    const uint8_t* dek,
    size_t dek_len,
    uint8_t* wrapped_out,
    size_t wrapped_size
);

/**
 * Unwrap DEK using master key
 * @param ctx Security context
 * @param wrapped Wrapped DEK
 * @param wrapped_len Length of wrapped data
 * @param dek_out Buffer for unwrapped DEK
 * @param dek_size Size of DEK buffer
 * @return Error code
 */
ironvault_error_t key_manager_unwrap_dek(
    security_context_t* ctx,
    const uint8_t* wrapped,
    size_t wrapped_len,
    uint8_t* dek_out,
    size_t dek_size
);

/**
 * Cleanup key manager
 * @param ctx Security context
 */
void key_manager_cleanup(security_context_t* ctx);

#ifdef __cplusplus
}
#endif

#endif // IRONVAULT_KEY_MANAGER_H
