#pragma once

/**
 * @brief Triggers Zygisk module hooks for system_server in late-injection scenarios.
 *
 * Dynamically reconstructs the JNI environment and process state parameters
 * (UID, GID, capabilities) required to fulfill the Zygisk API contract for
 * system_server_specialize.
 */
void trigger_system_server_hooks();
