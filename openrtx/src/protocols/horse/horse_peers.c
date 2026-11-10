/*
 * SPDX-FileCopyrightText: Copyright 2020-2026 OpenRTX Contributors
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "protocols/horse/horse_peers.h"
#include <errno.h>
#include <string.h>

#ifdef PLATFORM_LINUX
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#else
#include "core/nvmem_access.h"
#endif

#ifndef HORSE_PEERS_NVM_OFFSET
#define HORSE_PEERS_NVM_OFFSET 0x00FE1000U
#endif

static bool peer_nonzero(const uint8_t *p, size_t n)
{
    size_t i;

    if (p == NULL)
        return false;
    for (i = 0; i < n; i++) {
        if (p[i] != 0)
            return true;
    }
    return false;
}

#ifdef PLATFORM_LINUX
static int horse_peers_path(char *path, size_t path_len)
{
    const char *env = getenv("XDG_STATE_HOME");
    const char *home = getenv("HOME");
    int n;

    if (env != NULL)
        n = snprintf(path, path_len, "%s/OpenRTX/horse_peers.bin", env);
    else if (home != NULL)
        n = snprintf(path, path_len, "%s/.local/state/OpenRTX/horse_peers.bin",
                     home);
    else
        return -1;
    if (n < 0 || (size_t)n >= path_len)
        return -1;
    return 0;
}

static int horse_peers_ensure_file(const char *path)
{
    int fd;
    struct horse_peer zero;
    uint16_t i;

    fd = open(path, O_RDWR);
    if (fd >= 0) {
        close(fd);
        return 0;
    }

    memset(&zero, 0, sizeof zero);
    fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0)
        return -1;
    for (i = 0; i < HORSE_PEER_MAX; i++) {
        if (write(fd, &zero, sizeof zero) != (ssize_t)sizeof zero) {
            close(fd);
            return -1;
        }
    }
    close(fd);
    return 0;
}
#endif

int horse_peers_read(uint16_t index, struct horse_peer *out)
{
    if (out == NULL || index == 0 || index > HORSE_PEER_MAX)
        return -EINVAL;

#ifdef PLATFORM_LINUX
    char path[512];
    int fd;
    off_t off;

    if (horse_peers_path(path, sizeof path) != 0)
        return -EIO;
    if (horse_peers_ensure_file(path) != 0)
        return -EIO;
    fd = open(path, O_RDONLY);
    if (fd < 0)
        return -EIO;
    off = (off_t)(index - 1) * (off_t)sizeof(struct horse_peer);
    if (lseek(fd, off, SEEK_SET) != off
        || read(fd, out, sizeof *out) != (ssize_t)sizeof *out) {
        close(fd);
        return -EIO;
    }
    close(fd);
    return 0;
#else
    {
        int rc =
            nvm_read(0, 0,
                     HORSE_PEERS_NVM_OFFSET
                         + (uint32_t)(index - 1) * sizeof(struct horse_peer),
                     out, sizeof *out);
        return rc == 0 ? 0 : -EIO;
    }
#endif
}

int horse_peers_write(uint16_t index, const struct horse_peer *in)
{
    if (in == NULL || index == 0 || index > HORSE_PEER_MAX)
        return -EINVAL;

#ifdef PLATFORM_LINUX
    char dir[512];
    char path[512];
    const char *env = getenv("XDG_STATE_HOME");
    const char *home = getenv("HOME");
    int fd;
    int n;
    off_t off;

    if (env != NULL)
        n = snprintf(dir, sizeof dir, "%s/OpenRTX", env);
    else if (home != NULL)
        n = snprintf(dir, sizeof dir, "%s/.local/state/OpenRTX", home);
    else
        return -EINVAL;
    if (n < 0 || (size_t)n >= sizeof dir)
        return -EIO;
    mkdir(dir, 0700);
    if (horse_peers_path(path, sizeof path) != 0)
        return -EIO;
    if (horse_peers_ensure_file(path) != 0)
        return -EIO;
    fd = open(path, O_RDWR);
    if (fd < 0)
        return -EIO;
    off = (off_t)(index - 1) * (off_t)sizeof(struct horse_peer);
    if (lseek(fd, off, SEEK_SET) != off
        || write(fd, in, sizeof *in) != (ssize_t)sizeof *in) {
        close(fd);
        return -EIO;
    }
    close(fd);
    return 0;
#else
    {
        int rc =
            nvm_write(0, 0,
                      HORSE_PEERS_NVM_OFFSET
                          + (uint32_t)(index - 1) * sizeof(struct horse_peer),
                      in, sizeof *in);
        return rc == 0 ? 0 : -EIO;
    }
#endif
}

bool horse_peers_has_x25519(const struct horse_peer *peer)
{
    if (peer == NULL)
        return false;
    return peer_nonzero(peer->x25519_pk, sizeof peer->x25519_pk);
}

bool horse_peers_has_ed25519(const struct horse_peer *peer)
{
    if (peer == NULL)
        return false;
    return peer_nonzero(peer->ed25519_pk, sizeof peer->ed25519_pk);
}
