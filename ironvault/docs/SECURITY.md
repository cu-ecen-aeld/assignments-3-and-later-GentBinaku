# IronVault Security Design

## Threat Model

### Assets
1. **Master Key**: Hardware-protected cryptographic key
2. **Private Keys**: ECC P-256 private keys for signing
3. **DEKs**: Symmetric encryption keys for bulk data
4. **Authentication State**: User authentication status

### Threats
1. **Key Extraction**: Adversary attempting to extract keys from device
2. **Side Channel Attacks**: Timing, power analysis attacks
3. **Software Exploitation**: Memory corruption, code injection
4. **Physical Access**: Device theft, physical tampering
5. **Replay Attacks**: Reusing old authentication tokens
6. **Man-in-the-Middle**: Interception of attestation data

### Mitigations

#### Hardware Isolation
- **StrongBox/Secure Enclave**: Keys never exposed to application processor
- **EAL 5+ Certification**: Hardware-backed security guarantees
- **Side Channel Resistance**: Hardware implements countermeasures

#### Cryptographic Protections
- **ECC P-256**: NIST-approved curve for signing and key agreement
- **AES-256-GCM**: Authenticated encryption prevents tampering
- **Key Wrapping**: DEKs always encrypted by master key

#### Attestation
- **Certificate Chain**: Cryptographic proof of hardware residency
- **Nonce-based**: Backend includes nonce to prevent replay
- **Revocation**: Backend checks certificate revocation lists

## Architecture

### Layer Model

```
┌────────────────────────────────────────┐
│      Application (Untrusted)           │
├────────────────────────────────────────┤
│   Facade Layer (Kotlin/Swift)          │
│   - Input validation                   │
│   - Type safety                        │
├────────────────────────────────────────┤
│   Bridge Layer (JNI/C Interop)         │
│   - Marshalling                        │
│   - Error handling                     │
├────────────────────────────────────────┤
│   Security Core (C)                    │
│   - State machine                      │
│   - Key management                     │
│   - Crypto operations                  │
├────────────────────────────────────────┤
│   Hardware Security Module             │
│   StrongBox / Secure Enclave           │
│   - Key generation                     │
│   - Signing                            │
│   - Attestation                        │
└────────────────────────────────────────┘
     ↕ Hardware Isolation Boundary
```

### Trust Boundaries

1. **Application ↔ SDK**: Input validation, parameter checking
2. **SDK ↔ HSM**: Hardware-enforced isolation
3. **Device ↔ Backend**: TLS + Certificate pinning

## Cryptographic Specifications

### ECC P-256 (secp256r1)

**Key Generation:**
- Private key: 256-bit random number
- Public key: Point on P-256 curve

**Signing (ECDSA):**
1. Hash message with SHA-256
2. Generate signature (r, s) using private key
3. Signature size: 64 bytes (r: 32 bytes, s: 32 bytes)

**Verification:**
1. Hash message with SHA-256
2. Verify signature using public key
3. Accept if valid

### AES-256-GCM

**Encryption:**
1. Generate random 12-byte IV
2. Encrypt plaintext with AES-256 in GCM mode
3. Generate 16-byte authentication tag
4. Output: IV || Ciphertext || Tag

**Decryption:**
1. Extract IV, ciphertext, tag
2. Verify authentication tag
3. Decrypt if tag valid
4. Reject if tag invalid

### Hybrid Encryption Model

**Master Key:**
- Generated in hardware
- Never leaves HSM
- Used only for key wrapping

**DEK (Data Encryption Key):**
- Generated as random 256-bit value
- Used for bulk data encryption (AES-256-GCM)
- Wrapped by master key for storage
- Cached in application memory during use

**Rationale:**
- Hardware operations have high latency (10-100ms)
- Symmetric encryption is fast (GB/s)
- This balances security and performance

### Key Hierarchy

```
┌─────────────────────────────┐
│   Root of Trust (Hardware)  │
└──────────────┬──────────────┘
               │
               ▼
┌─────────────────────────────┐
│      Master Key (HSM)       │
│   - Generated in hardware   │
│   - Never exported          │
└──────────────┬──────────────┘
               │ Wraps
               ▼
┌─────────────────────────────┐
│      DEK (Symmetric)        │
│   - Random AES-256 key      │
│   - Used for data           │
└──────────────┬──────────────┘
               │ Encrypts
               ▼
┌─────────────────────────────┐
│      User Data              │
└─────────────────────────────┘
```

## Authentication State Machine

```
┌─────────────────┐
│  UNINITIALIZED  │
└────────┬────────┘
         │ INIT
         ▼
┌─────────────────┐
│   INITIALIZED   │◄──────────┐
└────────┬────────┘           │
         │ START_AUTH         │ UNLOCK
         ▼                    │
┌─────────────────┐           │
│ AUTHENTICATING  │           │
└────────┬────────┘           │
         │                    │
    ┌────┴────┐               │
    │         │               │
    │ SUCCESS │ FAILURE       │
    │         │               │
    ▼         ▼               │
┌────────┐ ┌────────┐         │
│  AUTH  │ │ LOCKED │─────────┘
│  -ED   │ └────────┘
└───┬────┘
    │ LOCK
    ▼
┌────────┐
│ LOCKED │
└────────┘
```

**State Transitions:**
- `UNINITIALIZED → INITIALIZED`: SDK initialization
- `INITIALIZED → AUTHENTICATING`: Begin authentication
- `AUTHENTICATING → AUTHENTICATED`: Successful auth
- `AUTHENTICATING → LOCKED`: Failed auth
- `AUTHENTICATED → LOCKED`: User lock
- `LOCKED → INITIALIZED`: Unlock

## Attestation Protocol

### Client Side (Device)

1. Generate key pair in hardware
2. Request attestation from HSM
3. HSM generates certificate chain:
   - Device certificate (signed by HSM)
   - Intermediate certificates
   - Root CA certificate
4. Send certificate chain to backend

### Server Side (Backend)

1. Receive certificate chain
2. Validate certificate chain
3. Check root CA is trusted
4. Verify device certificate signature
5. Extract hardware attestation claims:
   - Hardware type (StrongBox/Secure Enclave)
   - Security level (EAL rating)
   - Key residency proof
6. Accept or reject device

### Security Properties

- **Unforgeable**: Cannot create valid certificate without hardware
- **Verifiable**: Backend can cryptographically verify claims
- **Fresh**: Include nonce to prevent replay
- **Revocable**: Backend can revoke compromised devices

## Implementation Notes

### Current Status

⚠️ **This is a demonstration implementation**

**Implemented:**
- Core architecture and APIs
- State machine
- Key management abstraction
- Platform facades (Kotlin, Swift)

**Simplified (Not Production-Ready):**
- Cryptography: Uses simplified implementations
  - Real implementation needs OpenSSL/mbedTLS
- Random number generation: Uses pseudo-random
  - Real implementation needs hardware RNG
- Hardware integration: Stubs for demonstration
  - Real implementation needs KeyStore (Android) and SecKey (iOS) APIs

### Production Requirements

1. **Use Established Crypto Libraries**
   - OpenSSL, mbedTLS, or platform crypto APIs
   - Never implement crypto primitives yourself

2. **Hardware Integration**
   - Android: Use `android.security.keystore.KeyGenParameterSpec`
   - iOS: Use `SecKeyCreateRandomKey` with `kSecAttrTokenIDSecureEnclave`

3. **Secure Coding**
   - Constant-time comparisons for secrets
   - Secure memory wiping
   - Proper error handling
   - Bounds checking

4. **Testing**
   - Unit tests for all components
   - Integration tests with real hardware
   - Fuzzing for input validation
   - Security audit by third party

5. **Obfuscation** (Optional)
   - Code obfuscation for anti-reverse engineering
   - String encryption
   - Control flow flattening
   - Anti-debugging measures

## Compliance

### Standards
- **FIPS 140-2**: Federal crypto standard (if using approved crypto)
- **Common Criteria EAL 5+**: Hardware security evaluation
- **NIST SP 800-57**: Key management recommendations

### Best Practices
- **OWASP Mobile Top 10**: Mobile security risks
- **NIST Cybersecurity Framework**: Risk management
- **ISO/IEC 27001**: Information security management

## References

1. NIST FIPS 186-4: Digital Signature Standard (DSS)
2. NIST SP 800-38D: Recommendation for Block Cipher Modes (GCM)
3. NIST SP 800-57: Recommendation for Key Management
4. Android KeyStore Documentation
5. Apple Secure Enclave Documentation
6. Common Criteria Protection Profiles for Mobile Devices
