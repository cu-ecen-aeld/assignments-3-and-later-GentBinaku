#ifndef IRONVAULT_INTERNAL_H
#define IRONVAULT_INTERNAL_H

#include "security_core.h"
#include "crypto.h"

// Internal security context structure
struct security_context {
    hsm_type_t hsm_type;
    auth_state_t auth_state;
    uint8_t master_key_id[32];
    uint8_t private_key[ECC_P256_KEY_SIZE];
    uint8_t public_key[ECC_P256_KEY_SIZE * 2];
    int initialized;
};

#endif // IRONVAULT_INTERNAL_H
