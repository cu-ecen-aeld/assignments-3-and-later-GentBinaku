# IronVault Mobile Security SDK

**IronVault** is a cross-platform mobile security SDK designed for high-assurance user authentication on Android and iOS platforms. It provides a unified API backed by hardware security modules for cryptographic operations and secure key management.

## Overview

IronVault leverages hardware-backed security features available on modern mobile devices:

- **Android**: StrongBox (discrete Secure Element, EAL 5+) and TEE (Trusted Execution Environment)
- **iOS**: Secure Enclave

The SDK implements a shared C security core that manages authentication state machines and sensitive data operations, with platform-specific facades in Kotlin (Android) and Swift (iOS).

## Key Features

### Hardware Isolation
- **Android StrongBox**: Interfaces with discrete Secure Element via Kotlin/JNI
- **iOS Secure Enclave**: Interfaces via Swift/C++ interop
- **Automatic Fallback**: Gracefully falls back from StrongBox → TEE → Software based on device capabilities

### Cryptography
- **ECC P-256**: Hardware-backed elliptic curve cryptography using NIST P-256 curve
- **ECDSA**: Digital signatures for authentication and data integrity
- **ECDH**: Key agreement for secure channel establishment
- **AES-256-GCM**: Symmetric encryption for bulk data operations

### Trust Model
- **Remote Key Attestation**: Hardware-generated X.509 certificate chains
- **Cryptographic Proof**: Verifiable proof of key residency in hardware (EAL 5+)
- **Certificate Chain**: Traceable chain of trust from device to root CA

### Performance Architecture
- **Hybrid Encryption Model**:
  - Master Key: Protected by hardware (StrongBox/Secure Enclave)
  - Data Encryption Keys (DEKs): High-speed symmetric keys for bulk operations
  - Key Wrapping: DEKs wrapped by master key for storage
- **Latency Mitigation**: Hardware operations limited to key protection, bulk encryption uses fast symmetric crypto

### Authentication State Machine
Manages authentication lifecycle with well-defined states:
- `UNINITIALIZED` → `INITIALIZED` → `AUTHENTICATING` → `AUTHENTICATED` → `LOCKED`

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Application Layer                         │
├─────────────────────────────────────────────────────────────┤
│  Kotlin Facade (Android)  │  Swift Facade (iOS)            │
│  - IronVault.kt           │  - IronVault.swift             │
│  - Simple, idiomatic API  │  - Type-safe Swift API         │
├─────────────────────────────────────────────────────────────┤
│  Platform Bridge Layer                                       │
│  - JNI (Android)          │  - C Interop (iOS)             │
├─────────────────────────────────────────────────────────────┤
│              C Security Core (Shared)                        │
│  - security_core.c        - Authentication state machine    │
│  - key_manager.c          - Hybrid encryption               │
│  - crypto.c               - ECC P-256, AES-256-GCM         │
├─────────────────────────────────────────────────────────────┤
│           Hardware Security Modules                          │
│  StrongBox/TEE (Android)  │  Secure Enclave (iOS)          │
└─────────────────────────────────────────────────────────────┘
```

## Project Structure

```
ironvault/
├── core/                      # Shared C security core
│   ├── include/              # Public headers
│   │   ├── security_core.h   # Main SDK API
│   │   ├── auth_state_machine.h
│   │   ├── key_manager.h
│   │   └── crypto.h
│   ├── src/                  # Core implementation
│   │   ├── security_core.c
│   │   ├── auth_state_machine.c
│   │   └── key_manager.c
│   └── crypto/               # Cryptography implementation
│       └── crypto.c
├── android/                   # Android platform layer
│   ├── src/
│   │   └── IronVault.kt      # Kotlin facade
│   └── jni/
│       └── ironvault_jni.c   # JNI bridge
├── ios/                       # iOS platform layer
│   └── src/
│       └── IronVault.swift   # Swift facade
├── docs/                      # Documentation
│   ├── API.md
│   ├── ARCHITECTURE.md
│   └── SECURITY.md
├── tests/                     # Unit tests
└── CMakeLists.txt            # Build configuration
```

## Building

### Core Library

```bash
cd ironvault
mkdir build && cd build
cmake ..
make
```

### Android

The Android library uses CMake with NDK:

```bash
cd ironvault
mkdir build-android && cd build-android
cmake .. -DANDROID=ON -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK/build/cmake/android.toolchain.cmake
make
```

### iOS

The iOS library can be built using Xcode or CMake with iOS toolchain.

## Usage Examples

### Android (Kotlin)

```kotlin
import com.ironvault.sdk.IronVault

// Initialize with automatic hardware detection
val sdk = IronVault.create()

// Generate hardware-backed key pair
when (val result = sdk.generateKeyPair()) {
    is IronVault.Result.Success -> println("Key pair generated")
    is IronVault.Result.Error -> println("Error: ${result.message}")
}

// Request attestation
when (val result = sdk.requestAttestation()) {
    is IronVault.Result.Success -> {
        val certChain = result.data
        // Send to backend for verification
    }
    is IronVault.Result.Error -> println("Attestation failed")
}

// Sign data
val data = "Hello, World!".toByteArray()
when (val result = sdk.signData(data)) {
    is IronVault.Result.Success -> {
        val signature = result.data
        // Use signature
    }
    is IronVault.Result.Error -> println("Signing failed")
}

// Hybrid encryption: Generate and wrap DEK
when (val dekResult = sdk.generateDEK()) {
    is IronVault.Result.Success -> {
        val dek = dekResult.data
        when (val wrapResult = sdk.wrapDEK(dek)) {
            is IronVault.Result.Success -> {
                val wrappedDEK = wrapResult.data
                // Store wrapped DEK, use plain DEK for encryption
            }
        }
    }
}

// Cleanup
sdk.cleanup()
```

### iOS (Swift)

```swift
import IronVault

// Initialize with automatic hardware detection
switch IronVault.create() {
case .success(let sdk):
    
    // Generate hardware-backed key pair
    switch sdk.generateKeyPair() {
    case .success:
        print("Key pair generated")
    case .failure(let error):
        print("Error: \(error)")
    }
    
    // Request attestation
    switch sdk.requestAttestation() {
    case .success(let certChain):
        // Send to backend for verification
        print("Certificate chain: \(certChain)")
    case .failure(let error):
        print("Attestation failed: \(error)")
    }
    
    // Sign data
    let data = "Hello, World!".data(using: .utf8)!
    switch sdk.signData(data) {
    case .success(let signature):
        print("Signature: \(signature)")
    case .failure(let error):
        print("Signing failed: \(error)")
    }
    
    // Hybrid encryption
    switch sdk.generateDEK() {
    case .success(let dek):
        switch sdk.wrapDEK(dek) {
        case .success(let wrappedDEK):
            // Store wrapped DEK
            print("DEK wrapped successfully")
        case .failure(let error):
            print("Wrap failed: \(error)")
        }
    case .failure(let error):
        print("DEK generation failed: \(error)")
    }
    
    // Cleanup
    sdk.cleanup()
    
case .failure(let error):
    print("Initialization failed: \(error)")
}
```

## Security Considerations

### Hardware Requirements
- **Android**: Minimum API level 28 for StrongBox, API level 23 for TEE
- **iOS**: Devices with Secure Enclave (iPhone 5s and later, iPad Air and later)

### Key Storage
- Master keys never leave hardware security module
- DEKs are always wrapped before storage
- Private keys are protected by hardware

### Attestation
- Certificate chains should be validated on backend
- Check for proper hardware attestation level (EAL 5+ for StrongBox)
- Verify certificate revocation status

### Production Considerations
⚠️ **Important**: This is a demonstration implementation. For production use:
- Replace simplified crypto with production libraries (OpenSSL, mbedTLS)
- Implement proper random number generation using hardware RNG
- Add comprehensive error handling and logging
- Implement certificate pinning for attestation backend
- Add obfuscation and anti-tampering measures
- Conduct security audit and penetration testing

## API Documentation

See [docs/API.md](docs/API.md) for complete API reference.

## License

See LICENSE file for details.

## Contributing

Contributions are welcome! Please read our contributing guidelines before submitting pull requests.

## Support

For questions and support, please open an issue on the project repository.
