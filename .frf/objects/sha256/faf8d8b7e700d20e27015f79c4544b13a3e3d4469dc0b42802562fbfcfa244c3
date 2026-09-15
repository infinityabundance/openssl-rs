/*
 * RT-MEM-INSTALL -- `CRYPTO_set_mem_functions` and `CRYPTO_get_mem_functions`:
 * the allocator *dispatch* itself, rather than any one allocation.
 *
 * Why this is a separate court from RT-MEM-DEFAULT
 * ------------------------------------------------
 * The branch a process is in is chosen once and is then permanent. The first
 * non-zero request through the default path clears `allow_customize`
 * (`crypto/mem.c:205`), so an embedder that allocates before it installs an
 * allocator can never install one; and nothing installs the default back, so a
 * process that has installed one stays in the installed branch for its lifetime.
 * A single probe cannot therefore measure both branches, and this one measures the
 * installation state machine:
 *
 *   * the reported default *is the exported `CRYPTO_malloc`*, by identity, not a
 *     private shim -- the authority's `malloc_impl` is initialised to
 *     `CRYPTO_malloc` itself (`crypto/mem.c:23`), and a caller may compare the
 *     pointer it is handed against `&CRYPTO_malloc` or hand it straight back;
 *   * an installation may be **partial**: each non-NULL argument replaces its own
 *     slot and a NULL leaves it alone, and the call still answers 1;
 *   * an installation of the default identity back is the same as not installing.
 *
 * `RT-MEM-DEFAULT` measures the other branch (nothing installed) and closes with
 * the latch observation, which is the only way to see `CRYPTO_set_mem_functions`
 * answer 0: it must already have allocated through the default path, which is
 * exactly what that probe has done by the time it asks.
 *
 * Every observation is `key=value` on stdout, one per line, as in every other
 * probe. No addresses are printed; the identity observations report a comparison,
 * not a pointer.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>

static int malloc_calls;
static int realloc_calls;
static int free_calls;

static void *my_malloc(size_t n, const char *file, int line)
{
    (void)file;
    (void)line;
    malloc_calls++;
    return malloc(n);
}

static void *my_realloc(void *p, size_t n, const char *file, int line)
{
    (void)file;
    (void)line;
    realloc_calls++;
    return realloc(p, n);
}

static void my_free(void *p, const char *file, int line)
{
    (void)file;
    (void)line;
    free_calls++;
    free(p);
}

/* Which slots hold the probe's own functions, and which hold the authority's
 * exported defaults. Reported as comparisons so nothing address-shaped is
 * printed. */
static void report(const char *key)
{
    CRYPTO_malloc_fn m = NULL;
    CRYPTO_realloc_fn r = NULL;
    CRYPTO_free_fn f = NULL;

    CRYPTO_get_mem_functions(&m, &r, &f);
    printf("%s.malloc_mine=%d malloc_default=%d realloc_mine=%d realloc_default=%d"
           " free_mine=%d free_default=%d\n",
           key,
           m == my_malloc, m == CRYPTO_malloc,
           r == my_realloc, r == CRYPTO_realloc,
           f == my_free, f == CRYPTO_free);
}

int main(void)
{
    void *p;

    setvbuf(stdout, NULL, _IOLBF, 0);

    /* The state before anything is installed. */
    report("get.initial");

    /* A call that supplies none of the three: accepted, changes nothing. */
    printf("set.none=%d\n", CRYPTO_set_mem_functions(NULL, NULL, NULL));
    report("get.after_none");

    /* Partial installations, one slot at a time. */
    printf("set.malloc_only=%d\n", CRYPTO_set_mem_functions(my_malloc, NULL, NULL));
    report("get.after_malloc_only");
    printf("set.realloc_only=%d\n", CRYPTO_set_mem_functions(NULL, my_realloc, NULL));
    report("get.after_realloc_only");
    printf("set.free_only=%d\n", CRYPTO_set_mem_functions(NULL, NULL, my_free));
    report("get.after_free_only");

    /* All three, then again: reinstallation before any default-path allocation is
     * accepted. `allow_customize` is still set here because the default branch of
     * `CRYPTO_malloc` has never run -- every allocation below goes through the
     * probe's own shims. */
    printf("set.all=%d\n", CRYPTO_set_mem_functions(my_malloc, my_realloc, my_free));
    printf("set.all_again=%d\n", CRYPTO_set_mem_functions(my_malloc, my_realloc, my_free));

    /* The shims are actually used, and the installed branch answers a zero-length
     * request with an allocation -- the opposite of the default branch, which
     * `RT-MEM-DEFAULT` measures. */
    malloc_calls = 0;
    p = CRYPTO_malloc(0, __FILE__, __LINE__);
    printf("installed.malloc.0=%s shim_calls=%d err=%lu\n",
           p == NULL ? "NULL" : "nonnull", malloc_calls, ERR_peek_error());
    ERR_clear_error();
    if (p != NULL)
        CRYPTO_free(p, __FILE__, __LINE__);
    ERR_clear_error();

    /* Handing the default identity back is the same as not installing it, and is
     * accepted while customization is still allowed. */
    printf("set.default_back=%d\n",
           CRYPTO_set_mem_functions(CRYPTO_malloc, CRYPTO_realloc, CRYPTO_free));
    report("get.after_default_back");

    printf("done=1\n");
    return 0;
}
