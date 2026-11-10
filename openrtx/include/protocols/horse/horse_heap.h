/*
 * SPDX-FileCopyrightText: Copyright 2020-2026 OpenRTX Contributors
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Horse-attributable heap peak tracker (C7).
 *
 * There is no state.heap_usage field in upstream or this fork. On device
 * the Info menu "Used heap" shows getHeapSize() - getCurrentFreeHeap()
 * from core/memory_profiling.h. This module records Horse-side live
 * bytes (Argon2id memlimit, worker/codec stack mallocs) for host tests
 * against the MD-3x0 heap budget of 89600 B.
 */

#ifndef HORSE_HEAP_H
#define HORSE_HEAP_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * MD-3x0 main-RAM heap size (_end .. _heap_end). Horse peak must stay
 * under HORSE_HEAP_BUDGET_BYTES of that.
 */
#define HORSE_MD3X0_HEAP_BYTES 89600u

/**
 * Budget for Horse-attributable peak: Argon2id 16 KiB + crypto worker
 * stack 16 KiB + codec stack 16 KiB + 4 KiB misc = 53248. Leaves ~36 KiB
 * of the 89600 B heap for framebuffer and other mallocs.
 */
#define HORSE_HEAP_BUDGET_BYTES 53248u

/**
 * Reset live and peak counters (host tests).
 */
void horse_heap_reset_peak(void);

/**
 * Add bytes to the live Horse working set and update the peak.
 *
 * @param bytes: size acquired (stack malloc, Argon2 buffer, ...).
 */
void horse_heap_acquire(size_t bytes);

/**
 * Remove bytes from the live Horse working set.
 *
 * @param bytes: size released.
 */
void horse_heap_release(size_t bytes);

/**
 * Convenience: note a one-shot claim without a matching release
 * (e.g. Argon2 temporary buffer sized by memlimit).
 *
 * @param bytes: size to fold into the peak.
 */
void horse_heap_note(size_t bytes);

/**
 * @return peak Horse-attributable live bytes since last reset.
 */
size_t horse_heap_peak(void);

#ifdef __cplusplus
}
#endif

#endif /* HORSE_HEAP_H */
