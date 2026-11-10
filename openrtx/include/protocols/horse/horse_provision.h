/*
 * SPDX-FileCopyrightText: Copyright 2020-2026 OpenRTX Contributors
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Horse identity USB serial / Linux Unix-socket provisioning protocol.
 *
 * MSG_SEND_IDENTITY is accepted only while an explicit provisioning
 * window is open (menu entry). The radio shows the public fingerprint
 * and requires user confirmation before writing the keystore. The UI
 * never calls the radio API.
 */

#ifndef HORSE_PROVISION_H
#define HORSE_PROVISION_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Provisioning window length after enter or last activity (ms). */
#define HORSE_PROVISION_TIMEOUT_MS 120000U

/**
 * Initialise the provisioning transport (USB VCOM or Unix socket).
 */
void horse_provision_init(void);

/**
 * Poll for inbound bytes and enforce the provisioning timeout.
 */
void horse_provision_poll(void);

/**
 * Open the user-authorized provisioning window.
 *
 * Call from the UI when the operator enters the Horse provision menu.
 * Does not touch the radio API.
 */
void horse_provision_mode_enter(void);

/**
 * Close the provisioning window and discard any pending identity.
 */
void horse_provision_mode_leave(void);

/**
 * @return true while the provisioning window is open and not timed out.
 */
bool horse_provision_mode_active(void);

/**
 * @return true when an identity has arrived and awaits confirm.
 */
bool horse_provision_pending(void);

/**
 * Copy the pending identity public fingerprint.
 *
 * @param fp_out: 32-byte BLAKE2b fingerprint (HORSE-IDFP).
 * @return 0 on success, -ENOENT if nothing is pending.
 */
int horse_provision_pending_fingerprint(uint8_t fp_out[32]);

/**
 * Confirm and store the pending identity (user accepted the fingerprint).
 *
 * @return 0 on success, negative errno on failure.
 */
int horse_provision_confirm(void);

/**
 * Reject the pending identity without storing it.
 *
 * @return 0 on success, -ENOENT if nothing is pending.
 */
int horse_provision_reject(void);

#ifdef PLATFORM_LINUX
/**
 * Resolve the default Unix socket path into out.
 * Honours OPENRTX_HORSE_PROV_SOCK, else XDG_RUNTIME_DIR, else
 * XDG_STATE_HOME/OpenRTX or ~/.local/state/OpenRTX.
 *
 * @return 0 on success, -1 on failure.
 */
int horse_provision_default_sock_path(char *out, size_t out_len);

/**
 * Override the monotonic clock used for the provisioning timeout.
 * Pass 0 to resume using getTick(). Host tests only.
 *
 * @param ms: fake milliseconds, or 0 to clear the override.
 */
void horse_provision_test_set_now_ms(uint64_t ms);
#endif

#ifdef __cplusplus
}
#endif

#endif
