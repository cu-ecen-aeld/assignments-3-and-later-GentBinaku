#include "../include/auth_state_machine.h"
#include "../include/internal.h"
#include <string.h>

// State transition validation
static int is_valid_transition(auth_state_t current, auth_event_t event) {
    switch (current) {
        case AUTH_STATE_UNINITIALIZED:
            return (event == AUTH_EVENT_INIT);
        
        case AUTH_STATE_INITIALIZED:
            return (event == AUTH_EVENT_START_AUTH);
        
        case AUTH_STATE_AUTHENTICATING:
            return (event == AUTH_EVENT_AUTH_SUCCESS || 
                    event == AUTH_EVENT_AUTH_FAILURE);
        
        case AUTH_STATE_AUTHENTICATED:
            return (event == AUTH_EVENT_LOCK || event == AUTH_EVENT_RESET);
        
        case AUTH_STATE_LOCKED:
            return (event == AUTH_EVENT_UNLOCK || event == AUTH_EVENT_RESET);
        
        case AUTH_STATE_ERROR:
            return (event == AUTH_EVENT_RESET);
        
        default:
            return 0;
    }
}

ironvault_error_t auth_sm_init(security_context_t* ctx) {
    if (!ctx) {
        return IRONVAULT_ERROR_INVALID_PARAM;
    }
    // State machine is initialized with context
    return IRONVAULT_SUCCESS;
}

ironvault_error_t auth_sm_process_event(
    security_context_t* ctx,
    auth_event_t event
) {
    if (!ctx) {
        return IRONVAULT_ERROR_INVALID_PARAM;
    }

    auth_state_t current_state = ctx->auth_state;

    if (!is_valid_transition(current_state, event)) {
        return IRONVAULT_ERROR_INVALID_PARAM;
    }

    // Process state transitions
    switch (event) {
        case AUTH_EVENT_INIT:
            ctx->auth_state = AUTH_STATE_INITIALIZED;
            break;
        
        case AUTH_EVENT_START_AUTH:
            ctx->auth_state = AUTH_STATE_AUTHENTICATING;
            break;
        
        case AUTH_EVENT_AUTH_SUCCESS:
            ctx->auth_state = AUTH_STATE_AUTHENTICATED;
            break;
        
        case AUTH_EVENT_AUTH_FAILURE:
            ctx->auth_state = AUTH_STATE_LOCKED;
            break;
        
        case AUTH_EVENT_LOCK:
            ctx->auth_state = AUTH_STATE_LOCKED;
            break;
        
        case AUTH_EVENT_UNLOCK:
            ctx->auth_state = AUTH_STATE_INITIALIZED;
            break;
        
        case AUTH_EVENT_RESET:
            ctx->auth_state = AUTH_STATE_INITIALIZED;
            break;
        
        default:
            return IRONVAULT_ERROR_INVALID_PARAM;
    }

    return IRONVAULT_SUCCESS;
}

auth_state_t auth_sm_get_state(security_context_t* ctx) {
    if (!ctx) {
        return AUTH_STATE_ERROR;
    }
    return ctx->auth_state;
}

int auth_sm_is_authenticated(security_context_t* ctx) {
    if (!ctx) {
        return 0;
    }
    return (ctx->auth_state == AUTH_STATE_AUTHENTICATED) ? 1 : 0;
}

void auth_sm_cleanup(security_context_t* ctx) {
    if (ctx) {
        ctx->auth_state = AUTH_STATE_UNINITIALIZED;
    }
}
