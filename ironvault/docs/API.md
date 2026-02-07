# IronVault SDK API Reference

## Core API (C)

### Initialization

#### `security_context_t* ironvault_init(hsm_type_t hsm_type)`

Initialize the IronVault security context.

**Parameters:**
- `hsm_type`: Hardware security module type
  - `HSM_TYPE_STRONGBOX` (1): Android StrongBox
  - `HSM_TYPE_TEE` (2): Trusted Execution Environment
  - `HSM_TYPE_SECURE_ENCLAVE` (3): iOS Secure Enclave

**Returns:** Security context handle, or NULL on failure

**Example:**
```c
security_context_t* ctx = ironvault_init(HSM_TYPE_STRONGBOX);
if (!ctx) {
    // Handle error
}
```

#### `void ironvault_cleanup(security_context_t* ctx)`

Cleanup and destroy security context. Zeros sensitive data.

### Authentication State

#### `auth_state_t ironvault_get_auth_state(security_context_t* ctx)`

Get current authentication state.

**Returns:**
- `AUTH_STATE_UNINITIALIZED` (0)
- `AUTH_STATE_INITIALIZED` (1)
- `AUTH_STATE_AUTHENTICATING` (2)
- `AUTH_STATE_AUTHENTICATED` (3)
- `AUTH_STATE_LOCKED` (4)
- `AUTH_STATE_ERROR` (5)

### Cryptographic Operations

#### `ironvault_error_t ironvault_generate_keypair(security_context_t* ctx)`

Generate hardware-backed ECC P-256 key pair.

**Returns:** `IRONVAULT_SUCCESS` (0) on success, error code otherwise

#### `ironvault_error_t ironvault_sign_data(...)`

Sign data using hardware-backed private key.

**Parameters:**
- `ctx`: Security context
- `data`: Data to sign
- `data_len`: Length of data
- `signature_out`: Buffer for signature (must be 64 bytes)
- `sig_len`: Length of signature buffer

**Returns:** Error code

#### `ironvault_error_t ironvault_verify_signature(...)`

Verify signature using hardware-backed public key.

**Parameters:**
- `ctx`: Security context
- `data`: Data that was signed
- `data_len`: Length of data
- `signature`: Signature to verify (64 bytes)
- `sig_len`: Length of signature

**Returns:** `IRONVAULT_SUCCESS` if signature is valid

### Attestation

#### `ironvault_error_t ironvault_request_attestation(...)`

Request remote key attestation. Returns X.509 certificate chain proving hardware residency.

**Parameters:**
- `ctx`: Security context
- `cert_chain_out`: Buffer for certificate chain
- `cert_chain_size`: Size of buffer
- `actual_size`: Pointer to receive actual certificate size

**Returns:** Error code

### Key Management

#### `ironvault_error_t key_manager_generate_master_key(security_context_t* ctx)`

Generate master key in hardware security module.

#### `ironvault_error_t key_manager_generate_dek(...)`

Generate Data Encryption Key (DEK) for symmetric encryption.

**Parameters:**
- `ctx`: Security context
- `dek_out`: Buffer for DEK (32 bytes for AES-256)
- `dek_size`: Size of DEK buffer

**Returns:** Error code

#### `ironvault_error_t key_manager_wrap_dek(...)`

Wrap DEK with hardware master key for secure storage.

**Parameters:**
- `ctx`: Security context
- `dek`: DEK to wrap (32 bytes)
- `dek_len`: Length of DEK
- `wrapped_out`: Buffer for wrapped key
- `wrapped_size`: Size of wrapped buffer (must be at least 60 bytes)

**Returns:** Error code

#### `ironvault_error_t key_manager_unwrap_dek(...)`

Unwrap DEK using hardware master key.

**Parameters:**
- `ctx`: Security context
- `wrapped`: Wrapped DEK
- `wrapped_len`: Length of wrapped data
- `dek_out`: Buffer for unwrapped DEK (32 bytes)
- `dek_size`: Size of DEK buffer

**Returns:** Error code

---

## Android API (Kotlin)

### Initialization

```kotlin
val sdk = IronVault.create()  // Automatic detection
val sdk = IronVault.create(SecurityLevel.STRONGBOX)  // Specific level
```

### Operations

All operations return `Result<T>` which is either `Success(data)` or `Error(code, message)`.

#### `fun generateKeyPair(): Result<Unit>`

Generate hardware-backed key pair.

#### `fun requestAttestation(): Result<ByteArray>`

Request attestation certificate chain.

#### `fun signData(data: ByteArray): Result<ByteArray>`

Sign data with hardware-backed key.

#### `fun verifySignature(data: ByteArray, signature: ByteArray): Result<Boolean>`

Verify signature.

#### `fun generateDEK(): Result<ByteArray>`

Generate Data Encryption Key.

#### `fun wrapDEK(dek: ByteArray): Result<ByteArray>`

Wrap DEK with master key.

#### `fun unwrapDEK(wrappedDEK: ByteArray): Result<ByteArray>`

Unwrap DEK.

#### `fun cleanup()`

Release resources.

### Example

```kotlin
when (val result = sdk.generateKeyPair()) {
    is IronVault.Result.Success -> {
        // Success
    }
    is IronVault.Result.Error -> {
        println("Error: ${result.code} - ${result.message}")
    }
}
```

---

## iOS API (Swift)

### Initialization

```swift
let result = IronVault.create()  // Automatic detection
let result = IronVault.create(securityLevel: .secureEnclave)  // Specific level
```

### Operations

All operations return `Result<T, Error>` which is either `.success(value)` or `.failure(error)`.

#### `func generateKeyPair() -> Result<Void, Error>`

Generate hardware-backed key pair.

#### `func requestAttestation() -> Result<Data, Error>`

Request attestation certificate chain.

#### `func signData(_ data: Data) -> Result<Data, Error>`

Sign data with hardware-backed key.

#### `func verifySignature(data: Data, signature: Data) -> Result<Bool, Error>`

Verify signature.

#### `func generateDEK() -> Result<Data, Error>`

Generate Data Encryption Key.

#### `func wrapDEK(_ dek: Data) -> Result<Data, Error>`

Wrap DEK with master key.

#### `func unwrapDEK(_ wrappedDEK: Data) -> Result<Data, Error>`

Unwrap DEK.

#### `func cleanup()`

Release resources.

### Example

```swift
switch sdk.generateKeyPair() {
case .success:
    // Success
case .failure(let error):
    print("Error: \(error)")
}
```

---

## Error Codes

| Code | Name | Description |
|------|------|-------------|
| 0 | `IRONVAULT_SUCCESS` | Operation successful |
| -1 | `IRONVAULT_ERROR_INVALID_PARAM` | Invalid parameter |
| -2 | `IRONVAULT_ERROR_NOT_INITIALIZED` | Context not initialized |
| -3 | `IRONVAULT_ERROR_HSM_UNAVAILABLE` | Hardware security module unavailable |
| -4 | `IRONVAULT_ERROR_CRYPTO_FAILURE` | Cryptographic operation failed |
| -5 | `IRONVAULT_ERROR_ATTESTATION_FAILED` | Attestation failed |
| -6 | `IRONVAULT_ERROR_MEMORY` | Memory allocation failed |

---

## Security Considerations

### Key Sizes
- ECC private key: 32 bytes (P-256)
- ECC public key: 64 bytes (uncompressed)
- ECC signature: 64 bytes
- AES key (DEK): 32 bytes (AES-256)
- AES-GCM IV: 12 bytes
- AES-GCM tag: 16 bytes

### Wrapped DEK Format
```
[IV (12 bytes)] [Encrypted DEK (32 bytes)] [Tag (16 bytes)]
Total: 60 bytes
```

### Thread Safety
The SDK is **not thread-safe**. Use external synchronization if accessing from multiple threads.

### Memory Management
- Always call `cleanup()` to zero sensitive data
- DEKs should be zeroed after use
- Wrapped DEKs can be stored persistently
