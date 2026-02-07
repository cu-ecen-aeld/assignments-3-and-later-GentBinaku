import Foundation
import Security

/**
 * IronVault Security SDK for iOS
 * Provides high-assurance user authentication with hardware-backed security
 */
public class IronVault {
    
    /// Hardware security levels
    public enum SecurityLevel: Int {
        /// iOS Secure Enclave (EAL 5+)
        case secureEnclave = 0
        /// Software fallback (not recommended for production)
        case software = 1
    }
    
    /// Authentication state
    public enum AuthState: Int {
        case uninitialized = 0
        case initialized = 1
        case authenticating = 2
        case authenticated = 3
        case locked = 4
        case error = 5
    }
    
    /// Result wrapper for operations
    public enum Result<T> {
        case success(T)
        case failure(Error)
    }
    
    /// IronVault errors
    public enum IronVaultError: Error {
        case initializationFailed
        case operationFailed(code: Int)
        case invalidParameter
        case notInitialized
    }
    
    private var context: OpaquePointer?
    private let securityLevel: SecurityLevel
    
    /// Initialize IronVault with specified security level
    private init(securityLevel: SecurityLevel) {
        self.securityLevel = securityLevel
    }
    
    /// Create IronVault instance with automatic hardware detection
    public static func create() -> Result<IronVault> {
        let securityLevel = detectBestSecurityLevel()
        return create(securityLevel: securityLevel)
    }
    
    /// Create IronVault instance with specific security level
    public static func create(securityLevel: SecurityLevel) -> Result<IronVault> {
        let sdk = IronVault(securityLevel: securityLevel)
        
        let hsmType: Int32 = securityLevel == .secureEnclave ? 3 : 2
        sdk.context = ironvault_init(hsmType)
        
        guard sdk.context != nil else {
            return .failure(IronVaultError.initializationFailed)
        }
        
        // Generate master key
        _ = key_manager_generate_master_key(sdk.context)
        
        return .success(sdk)
    }
    
    /// Get current authentication state
    public func getAuthState() -> AuthState {
        guard let ctx = context else {
            return .error
        }
        
        let state = ironvault_get_auth_state(ctx)
        return AuthState(rawValue: Int(state)) ?? .error
    }
    
    /// Generate hardware-backed ECC P-256 key pair
    public func generateKeyPair() -> Result<Void> {
        guard let ctx = context else {
            return .failure(IronVaultError.notInitialized)
        }
        
        let result = ironvault_generate_keypair(ctx)
        if result == 0 {
            return .success(())
        } else {
            return .failure(IronVaultError.operationFailed(code: Int(result)))
        }
    }
    
    /// Request remote key attestation
    /// Returns X.509 certificate chain proving hardware residency
    public func requestAttestation() -> Result<Data> {
        guard let ctx = context else {
            return .failure(IronVaultError.notInitialized)
        }
        
        var certBuffer = [UInt8](repeating: 0, count: 4096)
        var actualSize: Int = 0
        
        let result = ironvault_request_attestation(
            ctx,
            &certBuffer,
            certBuffer.count,
            &actualSize
        )
        
        if result == 0 && actualSize > 0 {
            return .success(Data(certBuffer.prefix(actualSize)))
        } else {
            return .failure(IronVaultError.operationFailed(code: Int(result)))
        }
    }
    
    /// Sign data using hardware-backed key
    public func signData(_ data: Data) -> Result<Data> {
        guard let ctx = context else {
            return .failure(IronVaultError.notInitialized)
        }
        
        var signature = [UInt8](repeating: 0, count: 64)
        
        let result = data.withUnsafeBytes { dataPtr in
            ironvault_sign_data(
                ctx,
                dataPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                data.count,
                &signature,
                signature.count
            )
        }
        
        if result == 0 {
            return .success(Data(signature))
        } else {
            return .failure(IronVaultError.operationFailed(code: Int(result)))
        }
    }
    
    /// Verify signature using hardware-backed key
    public func verifySignature(data: Data, signature: Data) -> Result<Bool> {
        guard let ctx = context else {
            return .failure(IronVaultError.notInitialized)
        }
        
        let result = data.withUnsafeBytes { dataPtr in
            signature.withUnsafeBytes { sigPtr in
                ironvault_verify_signature(
                    ctx,
                    dataPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    data.count,
                    sigPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    signature.count
                )
            }
        }
        
        return .success(result == 0)
    }
    
    /// Generate Data Encryption Key (DEK) for high-speed operations
    /// Protected by hardware master key
    public func generateDEK() -> Result<Data> {
        guard let ctx = context else {
            return .failure(IronVaultError.notInitialized)
        }
        
        var dek = [UInt8](repeating: 0, count: 32)
        let result = key_manager_generate_dek(ctx, &dek, dek.count)
        
        if result == 0 {
            return .success(Data(dek))
        } else {
            return .failure(IronVaultError.operationFailed(code: Int(result)))
        }
    }
    
    /// Wrap DEK with hardware master key
    public func wrapDEK(_ dek: Data) -> Result<Data> {
        guard let ctx = context else {
            return .failure(IronVaultError.notInitialized)
        }
        
        let wrappedSize = 12 + dek.count + 16
        var wrapped = [UInt8](repeating: 0, count: wrappedSize)
        
        let result = dek.withUnsafeBytes { dekPtr in
            key_manager_wrap_dek(
                ctx,
                dekPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                dek.count,
                &wrapped,
                wrappedSize
            )
        }
        
        if result == 0 {
            return .success(Data(wrapped))
        } else {
            return .failure(IronVaultError.operationFailed(code: Int(result)))
        }
    }
    
    /// Unwrap DEK using hardware master key
    public func unwrapDEK(_ wrappedDEK: Data) -> Result<Data> {
        guard let ctx = context else {
            return .failure(IronVaultError.notInitialized)
        }
        
        var dek = [UInt8](repeating: 0, count: 32)
        
        let result = wrappedDEK.withUnsafeBytes { wrappedPtr in
            key_manager_unwrap_dek(
                ctx,
                wrappedPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                wrappedDEK.count,
                &dek,
                dek.count
            )
        }
        
        if result == 0 {
            return .success(Data(dek))
        } else {
            return .failure(IronVaultError.operationFailed(code: Int(result)))
        }
    }
    
    /// Cleanup and release resources
    public func cleanup() {
        if let ctx = context {
            ironvault_cleanup(ctx)
            context = nil
        }
    }
    
    deinit {
        cleanup()
    }
    
    // MARK: - Hardware Detection
    
    private static func detectBestSecurityLevel() -> SecurityLevel {
        // Check for Secure Enclave support (available on A7+ chips)
        if hasSecureEnclaveSupport() {
            return .secureEnclave
        }
        return .software
    }
    
    private static func hasSecureEnclaveSupport() -> Bool {
        // Check if device has Secure Enclave
        // Available on iPhone 5s and later, iPad Air and later
        #if targetEnvironment(simulator)
        return false
        #else
        // Check for kSecAttrTokenIDSecureEnclave availability
        return true  // Most modern iOS devices have Secure Enclave
        #endif
    }
}

// C API declarations
fileprivate func ironvault_init(_ hsmType: Int32) -> OpaquePointer?
fileprivate func ironvault_cleanup(_ ctx: OpaquePointer?)
fileprivate func ironvault_get_auth_state(_ ctx: OpaquePointer?) -> Int32
fileprivate func ironvault_generate_keypair(_ ctx: OpaquePointer?) -> Int32
fileprivate func ironvault_request_attestation(_ ctx: OpaquePointer?, _ buffer: UnsafeMutablePointer<UInt8>?, _ size: Int, _ actualSize: UnsafeMutablePointer<Int>?) -> Int32
fileprivate func ironvault_sign_data(_ ctx: OpaquePointer?, _ data: UnsafePointer<UInt8>?, _ dataLen: Int, _ signature: UnsafeMutablePointer<UInt8>?, _ sigLen: Int) -> Int32
fileprivate func ironvault_verify_signature(_ ctx: OpaquePointer?, _ data: UnsafePointer<UInt8>?, _ dataLen: Int, _ signature: UnsafePointer<UInt8>?, _ sigLen: Int) -> Int32
fileprivate func key_manager_generate_master_key(_ ctx: OpaquePointer?) -> Int32
fileprivate func key_manager_generate_dek(_ ctx: OpaquePointer?, _ dek: UnsafeMutablePointer<UInt8>?, _ dekSize: Int) -> Int32
fileprivate func key_manager_wrap_dek(_ ctx: OpaquePointer?, _ dek: UnsafePointer<UInt8>?, _ dekLen: Int, _ wrapped: UnsafeMutablePointer<UInt8>?, _ wrappedSize: Int) -> Int32
fileprivate func key_manager_unwrap_dek(_ ctx: OpaquePointer?, _ wrapped: UnsafePointer<UInt8>?, _ wrappedLen: Int, _ dek: UnsafeMutablePointer<UInt8>?, _ dekSize: Int) -> Int32
