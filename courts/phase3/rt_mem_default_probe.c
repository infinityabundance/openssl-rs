/*
 * RT-MEM-DEFAULT -- the allocation family in the configuration a plain consumer
 * has: **no custom allocator installed**.
 *
 * Why this court exists
 * ---------------------
 * `RT-MEM` measures the allocation family, and every one of its size
 * observations is taken *after* the probe has installed a counting allocator,
 * because the counts are how it observes the free/realloc asymmetry. Installing
 * an allocator is not a neutral act: it selects the other branch of the
 * authority's allocator dispatch.
 *
 *     void *CRYPTO_malloc(size_t num, const char *file, int line)
 *     {
 *         if (malloc_impl != CRYPTO_malloc) {          <-- RT-MEM measures HERE
 *             ptr = malloc_impl(num, file, line);
 *             if (ptr != NULL || num == 0)
 *                 return ptr;
 *             goto err;
 *         }
 *         if (ossl_unlikely(num == 0))
 *             return NULL;                             <-- this court measures HERE
 *         ...
 *     }
 *
 * The two branches do not agree about a zero-length request, and the default
 * branch -- the one a consumer who never calls `CRYPTO_set_mem_functions` gets,
 * and the one whose behaviour `src/runtime/mem.rs` had recorded as "a zero-length
 * request is a real allocation, matching the authority" -- is the one no probe
 * had measured. `crypto/mem.c` raises no error on either zero-length arm, so the
 * only witness is the return value.
 *
 * This probe therefore never installs anything, and every observation below is
 * the default path.
 *
 * The effect witness
 * ------------------
 * `CRYPTO_realloc(p, 0)` returns NULL whether or not it released `p`, so its
 * return value cannot answer whether it did. The authority's default branch does
 * release:
 *
 *     if (num == 0) {
 *         CRYPTO_free(str, file, line);
 *         return NULL;
 *     }
 *
 * `RT-MEM` cannot see that either: under an installed allocator the authority
 * delegates the decision to the caller's `realloc_fn`, so this probe interposes
 * the four libc entry points and reports the *change* in the number of libc
 * `free` calls across the one operation. That is not the "internal allocation
 * count" `phase3_courts.py` excludes from diffing -- it is the observable effect
 * of a single call, and the delta is reported with its operand so a reader can
 * see exactly what was measured.
 *
 * The interposed functions forward to glibc's own `__libc_*`, which are in
 * `libc.so.6`'s dynamic symbol table at GLIBC_2.2.5. `dlsym(RTLD_NEXT, ...)`
 * would recurse through `malloc` before the real symbols are resolved; `__libc_*`
 * cannot. The probe is compiled with `-rdynamic` so that the executable's
 * definitions are visible to `libcrypto.so.3`. Both make this instrument
 * glibc-specific, which is correct for a court whose venue is the pinned
 * profile.
 *
 * Every observation is `key=value` on stdout, one per line, as in every other
 * probe. No addresses are printed.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ witness */

extern void *__libc_malloc(size_t);
extern void *__libc_calloc(size_t, size_t);
extern void *__libc_realloc(void *, size_t);
extern void __libc_free(void *);

static unsigned long libc_free_calls;

void *malloc(size_t n)
{
    return __libc_malloc(n);
}

void *calloc(size_t a, size_t b)
{
    return __libc_calloc(a, b);
}

void *realloc(void *p, size_t n)
{
    return __libc_realloc(p, n);
}

void free(void *p)
{
    libc_free_calls++;
    __libc_free(p);
}

/* ------------------------------------------------------------------ helpers */

static void sayp(const char *key, void *p)
{
    unsigned long e = ERR_peek_error();

    printf("%s=%s err=%lu\n", key, p == NULL ? "NULL" : "nonnull", e);
    ERR_clear_error();
}

static void sayn(const char *key, long v)
{
    unsigned long e = ERR_peek_error();

    printf("%s=%ld err=%lu\n", key, v, e);
    ERR_clear_error();
}

static void says(const char *key, const char *s)
{
    unsigned long e = ERR_peek_error();

    printf("%s=%s err=%lu\n", key, s == NULL ? "NULL" : s, e);
    ERR_clear_error();
}

/*
 * Run one operation and report both its result and how many libc `free` calls it
 * made. `guard` is released afterwards when the operation did not release it, so
 * that a leaking implementation does not also leak across observations.
 */
static void free_delta(const char *key, void *(*op)(void *), void *guard)
{
    unsigned long before = libc_free_calls;
    void *ret = op(guard);
    unsigned long delta = libc_free_calls - before;
    unsigned long e = ERR_peek_error();

    printf("%s=%s frees=%lu err=%lu\n", key,
           ret == NULL ? "NULL" : "nonnull", delta, e);
    ERR_clear_error();
    if (ret == NULL && delta == 0 && guard != NULL)
        CRYPTO_free(guard, __FILE__, __LINE__);
}

static void *op_realloc_zero(void *p)
{
    return CRYPTO_realloc(p, 0, __FILE__, __LINE__);
}

static void *op_clear_realloc_zero(void *p)
{
    return CRYPTO_clear_realloc(p, 16, 0, __FILE__, __LINE__);
}

static void *op_free(void *p)
{
    CRYPTO_free(p, __FILE__, __LINE__);
    return NULL;
}

/* A valid allocator the latch observation offers and must be refused. */
static void *shim_malloc(size_t n, const char *file, int line)
{
    (void)file;
    (void)line;
    return __libc_malloc(n);
}

static void *shim_realloc(void *p, size_t n, const char *file, int line)
{
    (void)file;
    (void)line;
    return __libc_realloc(p, n);
}

static void shim_free(void *p, const char *file, int line)
{
    (void)file;
    (void)line;
    __libc_free(p);
}

/* --------------------------------------------------------------------- main */

int main(void)
{
    void *p;

    setvbuf(stdout, NULL, _IOLBF, 0);

    /* ---- zero-length requests, default allocator ------------------------- */
    sayp("malloc.0", CRYPTO_malloc(0, __FILE__, __LINE__));
    sayp("malloc.1", CRYPTO_malloc(1, __FILE__, __LINE__));
    sayp("zalloc.0", CRYPTO_zalloc(0, __FILE__, __LINE__));
    sayp("zalloc.1", CRYPTO_zalloc(1, __FILE__, __LINE__));
    sayp("calloc.0x16", CRYPTO_calloc(0, 16, __FILE__, __LINE__));
    sayp("calloc.16x0", CRYPTO_calloc(16, 0, __FILE__, __LINE__));
    sayp("calloc.1x16", CRYPTO_calloc(1, 16, __FILE__, __LINE__));
    sayp("malloc_array.0x4", CRYPTO_malloc_array(0, 4, __FILE__, __LINE__));
    sayp("malloc_array.4x0", CRYPTO_malloc_array(4, 0, __FILE__, __LINE__));
    sayp("malloc_array.1x4", CRYPTO_malloc_array(1, 4, __FILE__, __LINE__));

    /* `realloc` with a NULL block is an allocation, so it inherits the
     * zero-length arm; with a live block it takes the owner's contract. */
    sayp("realloc.null.0", CRYPTO_realloc(NULL, 0, __FILE__, __LINE__));
    sayp("realloc.null.8", CRYPTO_realloc(NULL, 8, __FILE__, __LINE__));
    sayp("realloc_array.null.0x4", CRYPTO_realloc_array(NULL, 0, 4, __FILE__, __LINE__));
    sayp("clear_realloc.null.0_0", CRYPTO_clear_realloc(NULL, 0, 0, __FILE__, __LINE__));
    sayp("clear_realloc.null.0_8", CRYPTO_clear_realloc(NULL, 0, 8, __FILE__, __LINE__));
    sayp("clear_realloc_array.null.0x4_0x4",
         CRYPTO_clear_realloc_array(NULL, 0, 4, 0, __FILE__, __LINE__));

    /* ---- the secure heap before it is initialised ------------------------ */
    /* `CRYPTO_secure_malloc` forwards to `CRYPTO_malloc` while the secure heap
     * is uninitialised, and forwards *without* passing through its own error
     * arm, so these follow the default arms exactly. */
    sayp("secure_malloc.0", CRYPTO_secure_malloc(0, __FILE__, __LINE__));
    sayp("secure_malloc.1", CRYPTO_secure_malloc(1, __FILE__, __LINE__));
    sayp("secure_zalloc.0", CRYPTO_secure_zalloc(0, __FILE__, __LINE__));
    sayp("secure_malloc_array.0x4", CRYPTO_secure_malloc_array(0, 4, __FILE__, __LINE__));
    sayp("secure_calloc.0x16", CRYPTO_secure_calloc(0, 16, __FILE__, __LINE__));
    sayn("secure_initialized", CRYPTO_secure_malloc_initialized());

    /* ---- the effect witness ---------------------------------------------- */
    /* The control first: a call that certainly releases, so the witness is
     * shown to report a change it can see before it is trusted on the case
     * whose return value hides the same change. */
    p = CRYPTO_malloc(16, __FILE__, __LINE__);
    free_delta("realloc.live_to_zero", op_realloc_zero, p);
    p = CRYPTO_malloc(16, __FILE__, __LINE__);
    free_delta("clear_realloc.live_to_zero", op_clear_realloc_zero, p);
    p = CRYPTO_malloc(16, __FILE__, __LINE__);
    free_delta("free.live", op_free, p);

    /* ---- the duplication family ------------------------------------------ */
    /* `CRYPTO_memdup` refuses an `siz` at or above `INT_MAX` outright, before
     * allocating, and raises nothing. `CRYPTO_malloc_array` has no such rule,
     * which is why the two are measured side by side.
     *
     * Only the *refused* side of that boundary is measured. The accepted side is
     * `siz == INT_MAX - 1`, and probing it would ask the authority to copy two
     * gigabytes out of the probe's own buffer, which is an out-of-bounds read by
     * construction: an earlier revision of this probe did exactly that and the
     * authority died on it, taking the rest of the transcript with it. The
     * boundary is pinned instead by `memdup.intmax` refused, `memdup.sizemax`
     * refused and `memdup.16` accepted. */
    {
        static char small[32];

        memset(small, 'x', sizeof small);
        sayp("memdup.null.0", CRYPTO_memdup(NULL, 0, __FILE__, __LINE__));
        sayp("memdup.16", CRYPTO_memdup(small, 16, __FILE__, __LINE__));
        sayp("memdup.intmax", CRYPTO_memdup(small, (size_t)INT_MAX, __FILE__, __LINE__));
        sayp("memdup.sizemax", CRYPTO_memdup(small, SIZE_MAX, __FILE__, __LINE__));
    }
    says("strdup.null", CRYPTO_strdup(NULL, __FILE__, __LINE__));
    says("strdup.abc", CRYPTO_strdup("abc", __FILE__, __LINE__));
    says("strndup.null", CRYPTO_strndup(NULL, 4, __FILE__, __LINE__));
    says("strndup.abc_0", CRYPTO_strndup("abc", 0, __FILE__, __LINE__));
    says("strndup.abc_2", CRYPTO_strndup("abc", 2, __FILE__, __LINE__));
    says("strndup.abc_99", CRYPTO_strndup("abc", 99, __FILE__, __LINE__));

    /* ---- faults the authority takes and the candidate does not ---------- */
    /* Both `CRYPTO_aligned_alloc` and its `*_array` sibling write through
     * `*freeptr` unconditionally, so a NULL `freeptr` segfaults the authority
     * (measured: exit 139 on both, in a process of their own). Reproducing a
     * fault is not a compatibility goal, so the candidate answers NULL and the
     * divergence is recorded rather than compared:
     * `docs/SECURITY_DIVERGENCE_POLICY.md`, D-MEM-ALIGNED-1. The marker is
     * printed on both sides so the transcript records that the case was
     * considered and why it is not an observation. */
    printf("aligned_alloc.null_freeptr=NOT_MEASURED_AUTHORITY_FAULTS\n");
    printf("aligned_alloc_array.null_freeptr=NOT_MEASURED_AUTHORITY_FAULTS\n");

    /* ---- the latch ------------------------------------------------------- */
    /* Every observation above went through the default path, so
     * `allow_customize` is clear by now and an installation must be refused
     * with 0. This is the only order in which that answer is reachable: offered
     * before the first allocation, the same call is accepted. `RT-MEM-INSTALL`
     * measures that other order, in a process that chooses it. */
    printf("set_mem_functions_after_default_allocations=%d\n",
           CRYPTO_set_mem_functions(shim_malloc, shim_realloc, shim_free));

    printf("done=1\n");
    return 0;
}
