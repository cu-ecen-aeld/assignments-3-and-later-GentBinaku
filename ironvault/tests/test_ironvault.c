#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "../core/include/security_core.h"
#include "../core/include/auth_state_machine.h"
#include "../core/include/key_manager.h"
#include "../core/include/crypto.h"

// Test colors
#define GREEN "\033[0;32m"
#define RED "\033[0;31m"
#define NC "\033[0m" // No Color

static int tests_passed = 0;
static int tests_failed = 0;

void test_assert(const char* test_name, int condition) {
    if (condition) {
        printf(GREEN "✓" NC " %s\n", test_name);
        tests_passed++;
    } else {
        printf(RED "✗" NC " %s\n", test_name);
        tests_failed++;
    }
}

void test_initialization() {
    printf("\n=== Testing Initialization ===\n");
    
    // Test initialization with different HSM types
    security_context_t* ctx = ironvault_init(HSM_TYPE_TEE);
    test_assert("Initialize with TEE", ctx != NULL);
    
    if (ctx) {
        auth_state_t state = ironvault_get_auth_state(ctx);
        test_assert("Initial auth state is INITIALIZED", state == AUTH_STATE_INITIALIZED);
        
        ironvault_cleanup(ctx);
        test_assert("Cleanup successful", 1);
    }
    
    // Test invalid initialization
    security_context_t* invalid_ctx = ironvault_init(HSM_TYPE_NONE);
    test_assert("Reject NONE HSM type", invalid_ctx == NULL);
}

void test_key_generation() {
    printf("\n=== Testing Key Generation ===\n");
    
    security_context_t* ctx = ironvault_init(HSM_TYPE_TEE);
    test_assert("Initialize context", ctx != NULL);
    
    if (ctx) {
        // Test key pair generation
        ironvault_error_t result = ironvault_generate_keypair(ctx);
        test_assert("Generate ECC P-256 key pair", result == IRONVAULT_SUCCESS);
        
        // Test master key generation
        result = key_manager_generate_master_key(ctx);
        test_assert("Generate master key", result == IRONVAULT_SUCCESS);
        
        // Test DEK generation
        uint8_t dek[AES_256_KEY_SIZE];
        result = key_manager_generate_dek(ctx, dek, sizeof(dek));
        test_assert("Generate DEK", result == IRONVAULT_SUCCESS);
        
        ironvault_cleanup(ctx);
    }
}

void test_signing_verification() {
    printf("\n=== Testing Signing & Verification ===\n");
    
    security_context_t* ctx = ironvault_init(HSM_TYPE_STRONGBOX);
    test_assert("Initialize context", ctx != NULL);
    
    if (ctx) {
        // Generate key pair first
        ironvault_error_t result = ironvault_generate_keypair(ctx);
        test_assert("Generate key pair for signing", result == IRONVAULT_SUCCESS);
        
        // Sign data
        const char* test_data = "Hello, IronVault!";
        uint8_t signature[ECC_P256_SIGNATURE_SIZE];
        
        result = ironvault_sign_data(
            ctx,
            (const uint8_t*)test_data,
            strlen(test_data),
            signature,
            sizeof(signature)
        );
        test_assert("Sign data", result == IRONVAULT_SUCCESS);
        
        // Verify signature
        result = ironvault_verify_signature(
            ctx,
            (const uint8_t*)test_data,
            strlen(test_data),
            signature,
            sizeof(signature)
        );
        test_assert("Verify signature", result == IRONVAULT_SUCCESS);
        
        ironvault_cleanup(ctx);
    }
}

void test_attestation() {
    printf("\n=== Testing Attestation ===\n");
    
    security_context_t* ctx = ironvault_init(HSM_TYPE_STRONGBOX);
    test_assert("Initialize context", ctx != NULL);
    
    if (ctx) {
        uint8_t cert_chain[4096];
        size_t actual_size = 0;
        
        ironvault_error_t result = ironvault_request_attestation(
            ctx,
            cert_chain,
            sizeof(cert_chain),
            &actual_size
        );
        
        test_assert("Request attestation", result == IRONVAULT_SUCCESS);
        test_assert("Attestation returns data", actual_size > 0);
        
        // Check if attestation contains expected content
        if (actual_size > 0) {
            const char* cert_str = (const char*)cert_chain;
            test_assert("Certificate contains CERTIFICATE marker", 
                       strstr(cert_str, "CERTIFICATE") != NULL);
            test_assert("Certificate contains StrongBox identifier",
                       strstr(cert_str, "StrongBox") != NULL);
        }
        
        ironvault_cleanup(ctx);
    }
}

void test_hybrid_encryption() {
    printf("\n=== Testing Hybrid Encryption ===\n");
    
    security_context_t* ctx = ironvault_init(HSM_TYPE_SECURE_ENCLAVE);
    test_assert("Initialize context", ctx != NULL);
    
    if (ctx) {
        // Generate master key
        ironvault_error_t result = key_manager_generate_master_key(ctx);
        test_assert("Generate master key", result == IRONVAULT_SUCCESS);
        
        // Generate DEK
        uint8_t dek[AES_256_KEY_SIZE];
        result = key_manager_generate_dek(ctx, dek, sizeof(dek));
        test_assert("Generate DEK", result == IRONVAULT_SUCCESS);
        
        // Wrap DEK
        size_t wrapped_size = AES_GCM_IV_SIZE + sizeof(dek) + AES_GCM_TAG_SIZE;
        uint8_t wrapped_dek[wrapped_size];
        
        result = key_manager_wrap_dek(ctx, dek, sizeof(dek), wrapped_dek, wrapped_size);
        test_assert("Wrap DEK with master key", result == IRONVAULT_SUCCESS);
        
        // Unwrap DEK
        uint8_t unwrapped_dek[AES_256_KEY_SIZE];
        result = key_manager_unwrap_dek(ctx, wrapped_dek, wrapped_size, 
                                        unwrapped_dek, sizeof(unwrapped_dek));
        test_assert("Unwrap DEK", result == IRONVAULT_SUCCESS);
        
        // Verify DEK matches
        int match = memcmp(dek, unwrapped_dek, AES_256_KEY_SIZE) == 0;
        test_assert("Unwrapped DEK matches original", match);
        
        ironvault_cleanup(ctx);
    }
}

void test_auth_state_machine() {
    printf("\n=== Testing Authentication State Machine ===\n");
    
    security_context_t* ctx = ironvault_init(HSM_TYPE_TEE);
    test_assert("Initialize context", ctx != NULL);
    
    if (ctx) {
        // Test initial state
        auth_state_t state = auth_sm_get_state(ctx);
        test_assert("Initial state is INITIALIZED", state == AUTH_STATE_INITIALIZED);
        
        // Start authentication
        ironvault_error_t result = auth_sm_process_event(ctx, AUTH_EVENT_START_AUTH);
        test_assert("Process START_AUTH event", result == IRONVAULT_SUCCESS);
        
        state = auth_sm_get_state(ctx);
        test_assert("State changed to AUTHENTICATING", state == AUTH_STATE_AUTHENTICATING);
        
        // Successful authentication
        result = auth_sm_process_event(ctx, AUTH_EVENT_AUTH_SUCCESS);
        test_assert("Process AUTH_SUCCESS event", result == IRONVAULT_SUCCESS);
        
        state = auth_sm_get_state(ctx);
        test_assert("State changed to AUTHENTICATED", state == AUTH_STATE_AUTHENTICATED);
        
        int is_auth = auth_sm_is_authenticated(ctx);
        test_assert("Is authenticated", is_auth == 1);
        
        // Lock
        result = auth_sm_process_event(ctx, AUTH_EVENT_LOCK);
        test_assert("Process LOCK event", result == IRONVAULT_SUCCESS);
        
        state = auth_sm_get_state(ctx);
        test_assert("State changed to LOCKED", state == AUTH_STATE_LOCKED);
        
        ironvault_cleanup(ctx);
    }
}

void test_crypto_primitives() {
    printf("\n=== Testing Crypto Primitives ===\n");
    
    // Test ECC key generation
    uint8_t private_key[ECC_P256_KEY_SIZE];
    uint8_t public_key[ECC_P256_KEY_SIZE * 2];
    
    ironvault_error_t result = crypto_generate_ecc_keypair(private_key, public_key);
    test_assert("Generate ECC keypair", result == IRONVAULT_SUCCESS);
    
    // Test signing
    const char* data = "Test data";
    uint8_t signature[ECC_P256_SIGNATURE_SIZE];
    
    result = crypto_ecc_sign(private_key, (const uint8_t*)data, strlen(data), signature);
    test_assert("ECC sign", result == IRONVAULT_SUCCESS);
    
    // Test verification
    result = crypto_ecc_verify(public_key, (const uint8_t*)data, strlen(data), signature);
    test_assert("ECC verify", result == IRONVAULT_SUCCESS);
    
    // Test AES-GCM encryption
    uint8_t key[AES_256_KEY_SIZE];
    uint8_t iv[AES_GCM_IV_SIZE];
    crypto_random_bytes(key, sizeof(key));
    crypto_random_bytes(iv, sizeof(iv));
    
    const char* plaintext = "Secret message";
    size_t plaintext_len = strlen(plaintext);
    uint8_t ciphertext[plaintext_len];
    uint8_t tag[AES_GCM_TAG_SIZE];
    
    result = crypto_aes_gcm_encrypt(key, iv, (const uint8_t*)plaintext, 
                                    plaintext_len, ciphertext, tag);
    test_assert("AES-GCM encrypt", result == IRONVAULT_SUCCESS);
    
    // Test AES-GCM decryption
    uint8_t decrypted[plaintext_len];
    result = crypto_aes_gcm_decrypt(key, iv, ciphertext, plaintext_len, tag, decrypted);
    test_assert("AES-GCM decrypt", result == IRONVAULT_SUCCESS);
    
    int match = memcmp(plaintext, decrypted, plaintext_len) == 0;
    test_assert("Decrypted matches plaintext", match);
}

int main() {
    printf("\n");
    printf("╔═══════════════════════════════════════╗\n");
    printf("║   IronVault SDK Test Suite          ║\n");
    printf("╚═══════════════════════════════════════╝\n");
    
    test_initialization();
    test_key_generation();
    test_signing_verification();
    test_attestation();
    test_hybrid_encryption();
    test_auth_state_machine();
    test_crypto_primitives();
    
    printf("\n");
    printf("═════════════════════════════════════════\n");
    printf("  Test Results\n");
    printf("═════════════════════════════════════════\n");
    printf(GREEN "  Passed: %d\n" NC, tests_passed);
    if (tests_failed > 0) {
        printf(RED "  Failed: %d\n" NC, tests_failed);
    } else {
        printf("  Failed: %d\n", tests_failed);
    }
    printf("═════════════════════════════════════════\n");
    
    return tests_failed == 0 ? 0 : 1;
}
