/*
 * openssl-rs — the ASan sensitivity canary.
 *
 * This is NOT product code and is not linked into anything the crate ships. It
 * exists for exactly one reason: a "zero findings" result from
 * AddressSanitizer is only trustworthy if the instrument is *known to fire*.
 * Before any layer's zero-findings result is recorded, this binary is built with
 * the same `clang -fsanitize=address -fno-omit-frame-pointer -g` flags the
 * probes use and run; it performs a deliberate heap use-after-free and a
 * deliberate heap-buffer-overflow. ASan MUST diagnose it with a nonzero exit.
 * If it does not, the harness records the canary as *not detected* and refuses
 * to trust any zero-findings layer result (forensics/tools/asan_closure.py).
 *
 * The accesses go through `volatile` sinks so the optimiser cannot delete them,
 * which would make the canary silently vacuous.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>

int main(void) {
    /* Heap use-after-free: read and write a freed block. */
    volatile char *p = (volatile char *)malloc(16);
    if (p == NULL)
        return 2;
    p[0] = 'A';
    free((void *)p);
    {
        volatile char c = p[3]; /* use-after-free read */
        p[4] = 'B';             /* use-after-free write */
        /* Keep the read alive. */
        if (c == 0x7f)
            fprintf(stderr, "canary: impossible\n");
    }

    /* Heap buffer overflow: write one past a small allocation. */
    {
        volatile char *q = (volatile char *)malloc(8);
        if (q == NULL)
            return 3;
        q[8] = 'C'; /* one past the end */
        free((void *)q);
    }

    /* If ASan did not fire, the canary reached here, which the harness reads as
     * "the instrument did not fire". */
    fprintf(stderr, "canary: NOT-DETECTED\n");
    return 0;
}
