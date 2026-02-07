#include <jni.h>
#include <string.h>
#include "../../core/include/security_core.h"
#include "../../core/include/key_manager.h"

// JNI helper to convert HSM type
static hsm_type_t jint_to_hsm_type(jint level) {
    switch (level) {
        case 0: return HSM_TYPE_STRONGBOX;
        case 1: return HSM_TYPE_TEE;
        default: return HSM_TYPE_TEE;
    }
}

// Initialize IronVault
JNIEXPORT jlong JNICALL
Java_com_ironvault_sdk_IronVault_nativeInit(JNIEnv* env, jobject obj, jint security_level) {
    hsm_type_t hsm_type = jint_to_hsm_type(security_level);
    security_context_t* ctx = ironvault_init(hsm_type);
    
    if (!ctx) {
        return 0;
    }
    
    // Generate master key
    key_manager_generate_master_key(ctx);
    
    return (jlong)(uintptr_t)ctx;
}

// Cleanup
JNIEXPORT void JNICALL
Java_com_ironvault_sdk_IronVault_nativeCleanup(JNIEnv* env, jobject obj, jlong handle) {
    if (handle != 0) {
        security_context_t* ctx = (security_context_t*)(uintptr_t)handle;
        ironvault_cleanup(ctx);
    }
}

// Get authentication state
JNIEXPORT jint JNICALL
Java_com_ironvault_sdk_IronVault_nativeGetAuthState(JNIEnv* env, jobject obj, jlong handle) {
    if (handle == 0) {
        return AUTH_STATE_ERROR;
    }
    
    security_context_t* ctx = (security_context_t*)(uintptr_t)handle;
    return (jint)ironvault_get_auth_state(ctx);
}

// Generate key pair
JNIEXPORT jint JNICALL
Java_com_ironvault_sdk_IronVault_nativeGenerateKeyPair(JNIEnv* env, jobject obj, jlong handle) {
    if (handle == 0) {
        return IRONVAULT_ERROR_NOT_INITIALIZED;
    }
    
    security_context_t* ctx = (security_context_t*)(uintptr_t)handle;
    return (jint)ironvault_generate_keypair(ctx);
}

// Request attestation
JNIEXPORT jbyteArray JNICALL
Java_com_ironvault_sdk_IronVault_nativeRequestAttestation(JNIEnv* env, jobject obj, jlong handle) {
    if (handle == 0) {
        return NULL;
    }
    
    security_context_t* ctx = (security_context_t*)(uintptr_t)handle;
    
    uint8_t cert_buffer[4096];
    size_t actual_size = 0;
    
    ironvault_error_t result = ironvault_request_attestation(
        ctx, cert_buffer, sizeof(cert_buffer), &actual_size
    );
    
    if (result != IRONVAULT_SUCCESS || actual_size == 0) {
        return NULL;
    }
    
    jbyteArray cert_array = (*env)->NewByteArray(env, actual_size);
    if (cert_array == NULL) {
        return NULL;
    }
    
    (*env)->SetByteArrayRegion(env, cert_array, 0, actual_size, (jbyte*)cert_buffer);
    return cert_array;
}

// Sign data
JNIEXPORT jbyteArray JNICALL
Java_com_ironvault_sdk_IronVault_nativeSignData(JNIEnv* env, jobject obj, jlong handle, jbyteArray data) {
    if (handle == 0 || data == NULL) {
        return NULL;
    }
    
    security_context_t* ctx = (security_context_t*)(uintptr_t)handle;
    
    jsize data_len = (*env)->GetArrayLength(env, data);
    jbyte* data_bytes = (*env)->GetByteArrayElements(env, data, NULL);
    
    uint8_t signature[ECC_P256_SIGNATURE_SIZE];
    ironvault_error_t result = ironvault_sign_data(
        ctx, (uint8_t*)data_bytes, data_len, signature, sizeof(signature)
    );
    
    (*env)->ReleaseByteArrayElements(env, data, data_bytes, JNI_ABORT);
    
    if (result != IRONVAULT_SUCCESS) {
        return NULL;
    }
    
    jbyteArray sig_array = (*env)->NewByteArray(env, ECC_P256_SIGNATURE_SIZE);
    if (sig_array == NULL) {
        return NULL;
    }
    
    (*env)->SetByteArrayRegion(env, sig_array, 0, ECC_P256_SIGNATURE_SIZE, (jbyte*)signature);
    return sig_array;
}

// Verify signature
JNIEXPORT jint JNICALL
Java_com_ironvault_sdk_IronVault_nativeVerifySignature(
    JNIEnv* env, jobject obj, jlong handle, jbyteArray data, jbyteArray signature
) {
    if (handle == 0 || data == NULL || signature == NULL) {
        return IRONVAULT_ERROR_INVALID_PARAM;
    }
    
    security_context_t* ctx = (security_context_t*)(uintptr_t)handle;
    
    jsize data_len = (*env)->GetArrayLength(env, data);
    jsize sig_len = (*env)->GetArrayLength(env, signature);
    
    jbyte* data_bytes = (*env)->GetByteArrayElements(env, data, NULL);
    jbyte* sig_bytes = (*env)->GetByteArrayElements(env, signature, NULL);
    
    ironvault_error_t result = ironvault_verify_signature(
        ctx, (uint8_t*)data_bytes, data_len, (uint8_t*)sig_bytes, sig_len
    );
    
    (*env)->ReleaseByteArrayElements(env, data, data_bytes, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, signature, sig_bytes, JNI_ABORT);
    
    return (jint)result;
}

// Generate DEK
JNIEXPORT jbyteArray JNICALL
Java_com_ironvault_sdk_IronVault_nativeGenerateDEK(JNIEnv* env, jobject obj, jlong handle) {
    if (handle == 0) {
        return NULL;
    }
    
    security_context_t* ctx = (security_context_t*)(uintptr_t)handle;
    
    uint8_t dek[AES_256_KEY_SIZE];
    ironvault_error_t result = key_manager_generate_dek(ctx, dek, sizeof(dek));
    
    if (result != IRONVAULT_SUCCESS) {
        return NULL;
    }
    
    jbyteArray dek_array = (*env)->NewByteArray(env, AES_256_KEY_SIZE);
    if (dek_array == NULL) {
        return NULL;
    }
    
    (*env)->SetByteArrayRegion(env, dek_array, 0, AES_256_KEY_SIZE, (jbyte*)dek);
    return dek_array;
}

// Wrap DEK
JNIEXPORT jbyteArray JNICALL
Java_com_ironvault_sdk_IronVault_nativeWrapDEK(JNIEnv* env, jobject obj, jlong handle, jbyteArray dek) {
    if (handle == 0 || dek == NULL) {
        return NULL;
    }
    
    security_context_t* ctx = (security_context_t*)(uintptr_t)handle;
    
    jsize dek_len = (*env)->GetArrayLength(env, dek);
    jbyte* dek_bytes = (*env)->GetByteArrayElements(env, dek, NULL);
    
    size_t wrapped_size = AES_GCM_IV_SIZE + dek_len + AES_GCM_TAG_SIZE;
    uint8_t* wrapped = (uint8_t*)malloc(wrapped_size);
    
    ironvault_error_t result = key_manager_wrap_dek(
        ctx, (uint8_t*)dek_bytes, dek_len, wrapped, wrapped_size
    );
    
    (*env)->ReleaseByteArrayElements(env, dek, dek_bytes, JNI_ABORT);
    
    if (result != IRONVAULT_SUCCESS) {
        free(wrapped);
        return NULL;
    }
    
    jbyteArray wrapped_array = (*env)->NewByteArray(env, wrapped_size);
    if (wrapped_array == NULL) {
        free(wrapped);
        return NULL;
    }
    
    (*env)->SetByteArrayRegion(env, wrapped_array, 0, wrapped_size, (jbyte*)wrapped);
    free(wrapped);
    
    return wrapped_array;
}

// Unwrap DEK
JNIEXPORT jbyteArray JNICALL
Java_com_ironvault_sdk_IronVault_nativeUnwrapDEK(
    JNIEnv* env, jobject obj, jlong handle, jbyteArray wrapped_dek
) {
    if (handle == 0 || wrapped_dek == NULL) {
        return NULL;
    }
    
    security_context_t* ctx = (security_context_t*)(uintptr_t)handle;
    
    jsize wrapped_len = (*env)->GetArrayLength(env, wrapped_dek);
    jbyte* wrapped_bytes = (*env)->GetByteArrayElements(env, wrapped_dek, NULL);
    
    uint8_t dek[AES_256_KEY_SIZE];
    ironvault_error_t result = key_manager_unwrap_dek(
        ctx, (uint8_t*)wrapped_bytes, wrapped_len, dek, sizeof(dek)
    );
    
    (*env)->ReleaseByteArrayElements(env, wrapped_dek, wrapped_bytes, JNI_ABORT);
    
    if (result != IRONVAULT_SUCCESS) {
        return NULL;
    }
    
    jbyteArray dek_array = (*env)->NewByteArray(env, AES_256_KEY_SIZE);
    if (dek_array == NULL) {
        return NULL;
    }
    
    (*env)->SetByteArrayRegion(env, dek_array, 0, AES_256_KEY_SIZE, (jbyte*)dek);
    return dek_array;
}

// Hardware detection stubs
JNIEXPORT jboolean JNICALL
Java_com_ironvault_sdk_IronVault_00024Companion_hasStrongBoxSupport(JNIEnv* env, jobject obj) {
    // In real implementation, check android.security.keystore features
    return JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_com_ironvault_sdk_IronVault_00024Companion_hasTEESupport(JNIEnv* env, jobject obj) {
    // In real implementation, check KeyStore features
    return JNI_TRUE;
}
