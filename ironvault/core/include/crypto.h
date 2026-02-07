#ifndef IRONVAULT_CRYPTO_H
#define IRONVAULT_CRYPTO_H

#include <stdint.h>
#include <stddef.h>
#include "security_core.h"

#ifdef __cplusplus
extern "C" {
#endif

// ECC curve identifiers
#define ECC_CURVE_P256 1

// Key sizes
#define ECC_P256_KEY_SIZE 32
#define ECC_P256_SIGNATURE_SIZE 64
#define AES_256_KEY_SIZE 32
#define AES_GCM_IV_SIZE 12
#define AES_GCM_TAG_SIZE 16

/**
 * Initialize cryptography module
 * @return Error code
 */
ironvault_error_t crypto_init(void);

/**
 * Generate ECC P-256 key pair
 * @param private_key_out Buffer for private key (32 bytes)
 * @param public_key_out Buffer for public key (64 bytes, uncompressed)
 * @return Error code
 */
ironvault_error_t crypto_generate_ecc_keypair(
    uint8_t* private_key_out,
    uint8_t* public_key_out
);

/**
 * Sign data with ECC P-256
 * @param private_key Private key (32 bytes)
 * @param data Data to sign
 * @param data_len Length of data
 * @param signature_out Signature buffer (64 bytes)
 * @return Error code
 */
ironvault_error_t crypto_ecc_sign(
    const uint8_t* private_key,
    const uint8_t* data,
    size_t data_len,
    uint8_t* signature_out
);

/**
 * Verify ECC P-256 signature
 * @param public_key Public key (64 bytes, uncompressed)
 * @param data Data that was signed
 * @param data_len Length of data
 * @param signature Signature to verify (64 bytes)
 * @return Error code (SUCCESS if valid)
 */
ironvault_error_t crypto_ecc_verify(
    const uint8_t* public_key,
    const uint8_t* data,
    size_t data_len,
    const uint8_t* signature
);

/**
 * Perform ECDH key agreement
 * @param private_key Local private key (32 bytes)
 * @param peer_public_key Peer public key (64 bytes)
 * @param shared_secret_out Shared secret buffer (32 bytes)
 * @return Error code
 */
ironvault_error_t crypto_ecdh(
    const uint8_t* private_key,
    const uint8_t* peer_public_key,
    uint8_t* shared_secret_out
);

/**
 * AES-256-GCM encryption
 * @param key Encryption key (32 bytes)
 * @param iv Initialization vector (12 bytes)
 * @param plaintext Data to encrypt
 * @param plaintext_len Length of plaintext
 * @param ciphertext_out Buffer for ciphertext
 * @param tag_out Authentication tag (16 bytes)
 * @return Error code
 */
ironvault_error_t crypto_aes_gcm_encrypt(
    const uint8_t* key,
    const uint8_t* iv,
    const uint8_t* plaintext,
    size_t plaintext_len,
    uint8_t* ciphertext_out,
    uint8_t* tag_out
);

/**
 * AES-256-GCM decryption
 * @param key Decryption key (32 bytes)
 * @param iv Initialization vector (12 bytes)
 * @param ciphertext Encrypted data
 * @param ciphertext_len Length of ciphertext
 * @param tag Authentication tag (16 bytes)
 * @param plaintext_out Buffer for decrypted data
 * @return Error code
 */
ironvault_error_t crypto_aes_gcm_decrypt(
    const uint8_t* key,
    const uint8_t* iv,
    const uint8_t* ciphertext,
    size_t ciphertext_len,
    const uint8_t* tag,
    uint8_t* plaintext_out
);

/**
 * Generate random bytes
 * @param buffer Buffer to fill with random data
 * @param len Number of random bytes to generate
 * @return Error code
 */
ironvault_error_t crypto_random_bytes(uint8_t* buffer, size_t len);

/**
 * Cleanup cryptography module
 */
void crypto_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif // IRONVAULT_CRYPTO_H
