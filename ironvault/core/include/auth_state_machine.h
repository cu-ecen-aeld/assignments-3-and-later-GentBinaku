#ifndef IRONVAULT_AUTH_STATE_MACHINE_H
#define IRONVAULT_AUTH_STATE_MACHINE_H

#include "security_core.h"

#ifdef __cplusplus
extern "C" {
#endif

// Authentication events
typedef enum {
    AUTH_EVENT_INIT = 0,
    AUTH_EVENT_START_AUTH = 1,
    AUTH_EVENT_AUTH_SUCCESS = 2,
    AUTH_EVENT_AUTH_FAILURE = 3,
    AUTH_EVENT_LOCK = 4,
    AUTH_EVENT_UNLOCK = 5,
    AUTH_EVENT_RESET = 6
} auth_event_t;

/**
 * Initialize authentication state machine
 * @param ctx Security context
 * @return Error code
 */
ironvault_error_t auth_sm_init(security_context_t* ctx);

/**
 * Process authentication event
 * @param ctx Security context
 * @param event Authentication event
 * @return Error code
 */
ironvault_error_t auth_sm_process_event(
    security_context_t* ctx,
    auth_event_t event
);

/**
 * Get current authentication state
 * @param ctx Security context
 * @return Current state
 */
auth_state_t auth_sm_get_state(security_context_t* ctx);

/**
 * Check if authenticated
 * @param ctx Security context
 * @return 1 if authenticated, 0 otherwise
 */
int auth_sm_is_authenticated(security_context_t* ctx);

/**
 * Cleanup authentication state machine
 * @param ctx Security context
 */
void auth_sm_cleanup(security_context_t* ctx);

#ifdef __cplusplus
}
#endif

#endif // IRONVAULT_AUTH_STATE_MACHINE_H
