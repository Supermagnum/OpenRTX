/*
 * SPDX-FileCopyrightText: Copyright 2020-2026 OpenRTX Contributors
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "protocols/horse/horse_heap.h"

static size_t horse_heap_live;
static size_t horse_heap_peak_bytes;

static void horse_heap_update_peak(void)
{
    if (horse_heap_live > horse_heap_peak_bytes)
        horse_heap_peak_bytes = horse_heap_live;
}

void horse_heap_reset_peak(void)
{
    horse_heap_live = 0;
    horse_heap_peak_bytes = 0;
}

void horse_heap_acquire(size_t bytes)
{
    horse_heap_live += bytes;
    horse_heap_update_peak();
}

void horse_heap_release(size_t bytes)
{
    if (bytes > horse_heap_live)
        horse_heap_live = 0;
    else
        horse_heap_live -= bytes;
}

void horse_heap_note(size_t bytes)
{
    horse_heap_acquire(bytes);
    horse_heap_release(bytes);
}

size_t horse_heap_peak(void)
{
    return horse_heap_peak_bytes;
}
