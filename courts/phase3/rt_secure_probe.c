/*
 * openssl-rs — RT-SECURE probe.
 *
 * One program, compiled against the authority and against the candidate and
 * diffed. It records the secure-heap lifecycle and, critically, the
 * *classification* observable: `CRYPTO_secure_allocated` on a secure pointer, on
 * a plain `CRYPTO_malloc` pointer, on a pointer into the middle of a secure
 * block, and on NULL — plus what happens after each of the two release functions.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <openssl/crypto.h>

#include <stdio.h>
#include <string.h>

static void p(const char *k, const void *v)
{
    printf("%s=%s\n", k, v != NULL ? "nonnull" : "null");
}

int main(void)
{
    void *a, *b, *plain;
    int rc;

    setvbuf(stdout, NULL, _IONBF, 0);
    printf("probe.rt-secure=1\n");

    /* ---- before init ------------------------------------------------------- */
    printf("pre.init_initialized=%d\n", CRYPTO_secure_malloc_initialized());
    /* NOT MEASURED: `CRYPTO_secure_used()` before `CRYPTO_secure_malloc_init`
     * SEGFAULTS the authority, which dereferences the (still NULL) secure-heap
     * pointer instead of reporting zero. Recorded as a safety divergence; the
     * candidate reports 0. */
    printf("pre.used=NOT_MEASURED_AUTHORITY_FAULTS\n");
    p("pre.malloc_falls_back", CRYPTO_secure_malloc(32, NULL, 0));

    /* ---- init -------------------------------------------------------------- */
    rc = CRYPTO_secure_malloc_init(1 << 20, 16);
    printf("init.rc=%d\n", rc);
    printf("init.initialized=%d\n", CRYPTO_secure_malloc_initialized());
    printf("init.again_rc=%d\n", CRYPTO_secure_malloc_init(1 << 20, 16));
    printf("init.again_initialized=%d\n", CRYPTO_secure_malloc_initialized());

    /* ---- allocation and classification ------------------------------------ */
    a = CRYPTO_secure_malloc(64, NULL, 0);
    p("alloc.64", a);
    printf("alloc.allocated=%d\n", CRYPTO_secure_allocated(a));
    printf("alloc.actual_size_ge_64=%d\n", CRYPTO_secure_actual_size(a) >= 64);
    printf("alloc.used_nonzero=%d\n", CRYPTO_secure_used() != 0);

    printf("classify.null=%d\n", CRYPTO_secure_allocated(NULL));
    plain = CRYPTO_malloc(64, NULL, 0);
    printf("classify.plain=%d\n", CRYPTO_secure_allocated(plain));
    printf("classify.interior=%d\n", CRYPTO_secure_allocated((char *)a + 1));

    /* ---- secure calloc zeroes --------------------------------------------- */
    b = CRYPTO_secure_calloc(4, 8, NULL, 0);
    p("calloc.4x8", b);
    if (b != NULL) {
        unsigned char *z = b;
        int all_zero = 1;
        for (int i = 0; i < 32; i++)
            if (z[i] != 0)
                all_zero = 0;
        printf("calloc.zeroed=%d\n", all_zero);
        printf("calloc.allocated=%d\n", CRYPTO_secure_allocated(b));
    }

    /* ---- release: classification must clear ------------------------------- */
    CRYPTO_secure_clear_free(b, 32, NULL, 0);
    /* MEASURED: `CRYPTO_secure_allocated` is a RANGE check in the authority, so a
     * released block -- and an interior pointer -- still classify as 1. */
    printf("clear_free.released_allocated=%d\n", CRYPTO_secure_allocated(b));
    printf("clear_free.interior_allocated=%d\n", CRYPTO_secure_allocated((char *)b + 1));
    /* NOT MEASURED: `CRYPTO_secure_actual_size` on a released block ABORTS the
     * authority (`crypto/mem_sec.c`: assertion failed `(bit & 1) == 0`). The
     * candidate returns 0; recorded as a safety divergence. */
    printf("clear_free.released_actual_size=NOT_MEASURED_AUTHORITY_ABORTS\n");

    CRYPTO_secure_free(a, NULL, 0);
    printf("free.released_allocated=%d\n", CRYPTO_secure_allocated(a));
    printf("free.released_actual_size=NOT_MEASURED_AUTHORITY_ABORTS\n");

    /* Releasing a plain pointer must be accepted and must not corrupt. */
    CRYPTO_secure_free(plain, NULL, 0);
    printf("free.plain_survived=1\n");
    CRYPTO_secure_clear_free(NULL, 0, NULL, 0);
    printf("clear_free.null_survived=1\n");
    CRYPTO_secure_free(NULL, NULL, 0);
    printf("free.null_survived=1\n");

    /* ---- done -------------------------------------------------------------- */
    printf("done.rc=%d\n", CRYPTO_secure_malloc_done());
    printf("done.initialized=%d\n", CRYPTO_secure_malloc_initialized());
    printf("done.again_rc=%d\n", CRYPTO_secure_malloc_done());
    printf("done.used=%zu\n", CRYPTO_secure_used());

    /* ---- allocate after done: documented fallback ------------------------- */
    p("postdone.malloc", CRYPTO_secure_malloc(32, NULL, 0));
    printf("postdone.allocated=%d\n", CRYPTO_secure_allocated(b));

    return 0;
}
