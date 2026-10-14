/*
 * openssl-rs — the TSan sensitivity canary (independent C cross-check).
 *
 * This is NOT product code and is not linked into anything the crate ships. It
 * exists for exactly one reason: a "no data race" result from ThreadSanitizer
 * is only trustworthy if the instrument is *known to fire*. Before any layer's
 * no-race result is recorded, this binary is built with the same
 * `clang -fsanitize=thread -g` flags the probes use and run; it performs a
 * deliberate data race on a shared global and ThreadSanitizer MUST diagnose it
 * with a nonzero exit and a `data race` report. If it does not, the harness
 * records the canary as *not detected* and refuses to trust any no-race layer
 * result (forensics/tools/ms_tsan.py).
 *
 * The shared location is `volatile` so the optimiser cannot delete the loops and
 * make the canary silently vacuous; a volatile access is still a plain data race
 * that ThreadSanitizer instruments.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <pthread.h>
#include <stdio.h>

static volatile int shared = 0;

static void *writer(void *arg) {
    (void)arg;
    for (int i = 0; i < 4000000; i++)
        shared = i;
    return NULL;
}

static void *reader(void *arg) {
    (void)arg;
    long acc = 0;
    for (int i = 0; i < 4000000; i++)
        acc += shared;
    return (void *)acc;
}

int main(void) {
    pthread_t t1, t2;
    if (pthread_create(&t1, NULL, writer, NULL) != 0)
        return 2;
    if (pthread_create(&t2, NULL, reader, NULL) != 0)
        return 3;
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
    /* If TSan did not fire, the canary reached here, which the harness reads as
     * "the instrument did not fire". */
    fprintf(stderr, "canary: NOT-DETECTED\n");
    return 0;
}
