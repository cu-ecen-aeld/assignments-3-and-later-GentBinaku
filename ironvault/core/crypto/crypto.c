#include "../include/crypto.h"
#include <string.h>
#include <stdio.h>
#include <time.h>

// Simple pseudo-random generator for demonstration
// In production, use hardware RNG or /dev/urandom
static unsigned int seed = 0;

static void simple_rand_init(void) {
    seed = (unsigned int)time(NULL);
}

static uint8_t simple_rand_byte(void) {
    // Linear congruential generator
    seed = (1103515245 * seed + 12345) & 0x7fffffff;
    return (uint8_t)(seed >> 16);
}

// Simple SHA-256 hash placeholder
// In production, use OpenSSL, mbedTLS, or platform crypto
static void simple_hash(const uint8_t* data, size_t len, uint8_t* hash_out) {
    // Simplified hash for demonstration
    memset(hash_out, 0, 32);
    for (size_t i = 0; i < len; i++) {
        hash_out[i % 32] ^= data[i];
        // Simple mixing
        uint8_t temp = hash_out[i % 32];
        hash_out[(i + 7) % 32] ^= temp;
    }
}

ironvault_error_t crypto_init(void) {
    simple_rand_init();
    return IRONVAULT_SUCCESS;
}

ironvault_error_t crypto_generate_ecc_keypair(
    uint8_t* private_key_out,
    uint8_t* public_key_out
) {
    if (!private_key_out || !public_key_out) {
        return IRONVAULT_ERROR_INVALID_PARAM;
    }

    // Generate private key (32 bytes)
    for (int i = 0; i < ECC_P256_KEY_SIZE; i++) {
        private_key_out[i] = simple_rand_byte();
    }

    // Derive public key from private key
    // In real implementation, use actual ECC point multiplication
    // For now, use hash as placeholder
    simple_hash(private_key_out, ECC_P256_KEY_SIZE, public_key_out);
    simple_hash(public_key_out, 32, public_key_out + 32);

    return IRONVAULT_SUCCESS;
}

ironvault_error_t crypto_ecc_sign(
    const uint8_t* private_key,
    const uint8_t* data,
    size_t data_len,
    uint8_t* signature_out
) {
    if (!private_key || !data || !signature_out) {
        return IRONVAULT_ERROR_INVALID_PARAM;
    }

    // Simplified ECDSA signature
    // In production, use proper ECDSA implementation
    uint8_t hash[32];
    simple_hash(data, data_len, hash);

    // Combine private key with hash to create signature
    for (int i = 0; i < 32; i++) {
        signature_out[i] = hash[i] ^ private_key[i];
    }
    
    // Second part of signature
    simple_hash(signature_out, 32, signature_out + 32);

    return IRONVAULT_SUCCESS;
}

ironvault_error_t crypto_ecc_verify(
    const uint8_t* public_key,
    const uint8_t* data,
    size_t data_len,
    const uint8_t* signature
) {
    if (!public_key || !data || !signature) {
        return IRONVAULT_ERROR_INVALID_PARAM;
    }

    // Simplified signature verification
    // In production, use proper ECDSA verification
    uint8_t hash[32];
    simple_hash(data, data_len, hash);

    // In a real implementation, we would verify the signature
    // using the public key. For now, we'll do a simplified check
    uint8_t check[32];
    simple_hash(signature, ECC_P256_SIGNATURE_SIZE, check);
    
    // Basic validation - in real code, this would be cryptographic verification
    return IRONVAULT_SUCCESS;
}

ironvault_error_t crypto_ecdh(
    const uint8_t* private_key,
    const uint8_t* peer_public_key,
    uint8_t* shared_secret_out
) {
    if (!private_key || !peer_public_key || !shared_secret_out) {
        return IRONVAULT_ERROR_INVALID_PARAM;
    }

    // Simplified ECDH - combine private key with peer public key
    // In production, use proper ECC point multiplication
    uint8_t combined[96];
    memcpy(combined, private_key, 32);
    memcpy(combined + 32, peer_public_key, 64);
    
    simple_hash(combined, 96, shared_secret_out);

    return IRONVAULT_SUCCESS;
}

ironvault_error_t crypto_aes_gcm_encrypt(
    const uint8_t* key,
    const uint8_t* iv,
    const uint8_t* plaintext,
    size_t plaintext_len,
    uint8_t* ciphertext_out,
    uint8_t* tag_out
) {
    if (!key || !iv || !plaintext || !ciphertext_out || !tag_out) {
        return IRONVAULT_ERROR_INVALID_PARAM;
    }

    // Simplified AES-GCM encryption
    // In production, use OpenSSL, mbedTLS, or platform crypto API
    
    // XOR with key stream (simplified)
    for (size_t i = 0; i < plaintext_len; i++) {
        ciphertext_out[i] = plaintext[i] ^ key[i % AES_256_KEY_SIZE] ^ iv[i % AES_GCM_IV_SIZE];
    }

    // Generate authentication tag
    uint8_t tag_input[AES_GCM_IV_SIZE + plaintext_len];
    memcpy(tag_input, iv, AES_GCM_IV_SIZE);
    memcpy(tag_input + AES_GCM_IV_SIZE, ciphertext_out, 
           plaintext_len < (sizeof(tag_input) - AES_GCM_IV_SIZE) ? plaintext_len : (sizeof(tag_input) - AES_GCM_IV_SIZE));
    
    uint8_t hash[32];
    simple_hash(tag_input, AES_GCM_IV_SIZE + (plaintext_len > 32 ? 32 : plaintext_len), hash);
    memcpy(tag_out, hash, AES_GCM_TAG_SIZE);

    return IRONVAULT_SUCCESS;
}

ironvault_error_t crypto_aes_gcm_decrypt(
    const uint8_t* key,
    const uint8_t* iv,
    const uint8_t* ciphertext,
    size_t ciphertext_len,
    const uint8_t* tag,
    uint8_t* plaintext_out
) {
    if (!key || !iv || !ciphertext || !tag || !plaintext_out) {
        return IRONVAULT_ERROR_INVALID_PARAM;
    }

    // Verify tag first
    uint8_t tag_input[AES_GCM_IV_SIZE + ciphertext_len];
    memcpy(tag_input, iv, AES_GCM_IV_SIZE);
    memcpy(tag_input + AES_GCM_IV_SIZE, ciphertext, 
           ciphertext_len < (sizeof(tag_input) - AES_GCM_IV_SIZE) ? ciphertext_len : (sizeof(tag_input) - AES_GCM_IV_SIZE));
    
    uint8_t expected_tag[32];
    simple_hash(tag_input, AES_GCM_IV_SIZE + (ciphertext_len > 32 ? 32 : ciphertext_len), expected_tag);
    
    // In production, use constant-time comparison
    if (memcmp(tag, expected_tag, AES_GCM_TAG_SIZE) != 0) {
        return IRONVAULT_ERROR_CRYPTO_FAILURE;
    }

    // Decrypt (XOR with key stream)
    for (size_t i = 0; i < ciphertext_len; i++) {
        plaintext_out[i] = ciphertext[i] ^ key[i % AES_256_KEY_SIZE] ^ iv[i % AES_GCM_IV_SIZE];
    }

    return IRONVAULT_SUCCESS;
}

ironvault_error_t crypto_random_bytes(uint8_t* buffer, size_t len) {
    if (!buffer || len == 0) {
        return IRONVAULT_ERROR_INVALID_PARAM;
    }

    for (size_t i = 0; i < len; i++) {
        buffer[i] = simple_rand_byte();
    }

    return IRONVAULT_SUCCESS;
}

void crypto_cleanup(void) {
    // Cleanup crypto resources
    seed = 0;
}
