/*
 * SPDX-FileCopyrightText: Copyright 2020-2026 OpenRTX Contributors
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Horse peer public keys, indexed by horseInfo_t.contact_index.
 * Linux: XDG_STATE_HOME/OpenRTX/horse_peers.bin. Radio: a distinct NVM
 * region. Not part of contact_t.
 */

#ifndef HORSE_PEERS_H
#define HORSE_PEERS_H

#include "protocols/horse/horse_crypto.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HORSE_PEER_MAX 64

struct horse_peer {
    uint8_t address[6];
    uint8_t x25519_pk[HORSE_X25519_PUBLICKEY_BYTES];
    uint8_t ed25519_pk[HORSE_ED25519_PUBLICKEY_BYTES];
} __attribute__((packed));

bool horse_peer_read(uint16_t index, struct horse_peer *out);
bool horse_peer_write(uint16_t index, const struct horse_peer *in);
bool horse_peer_has_x25519(const struct horse_peer *peer);
bool horse_peer_has_ed25519(const struct horse_peer *peer);

#ifdef __cplusplus
}
#endif

#endif
