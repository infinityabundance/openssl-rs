/*
 * RT-THREADDATA -- the per-context thread slot and its two accessors, differentially.
 *
 * What this court has to establish
 * --------------------------------
 * `OSSL_get_max_threads` and `OSSL_set_max_threads` are two locks and a field, so
 * the interesting part is not the arithmetic -- it is *which object* the field
 * lives in, and what happens when there is no object. Measured against the
 * admitted authority, that is three things:
 *
 *   * the counter is per **context**. `OSSL_set_max_threads(ctx_a, n)` must not
 *     move `OSSL_get_max_threads(ctx_b)`, and the default context is one of the
 *     contexts rather than a special case.
 *   * a NULL context resolves through the library context default chain, so the
 *     answer follows whatever this thread currently defaults to -- which the
 *     probe observes by installing a default and reading through NULL.
 *   * `OSSL_set_max_threads` answers **1** and the value is stored verbatim: no
 *     range check, so `UINT64_MAX` is legal to set and to read back. A
 *     `uint64_t` counter that is clipped, or a `set` that refuses a large value,
 *     would be a plausible implementation and a wrong one.
 *
 * The slot itself is observed by `RT-LIBCTX`, which sweeps the library context's
 * index table; this probe never touches `OSSL_LIB_CTX_get_data`, because the
 * index numbers are internal and this court's subject is the two accessors.
 *
 * Every value is printed as an unsigned decimal, so a truncation or a sign
 * mistake is visible rather than hidden behind a truthy comparison.
 *
 * Every observation is `key=value` on stdout, one line each, with unique keys. The
 * `err=` field is the packed `ERR_peek_error()` read immediately after the call and
 * cleared before the next, so it belongs to its own call.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/thread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static void sayu(const char *key, uint64_t v)
{
    printf("%s=%llu err=%lu\n", key, (unsigned long long) v, ERR_peek_error());
    ERR_clear_error();
}

static void sayn(const char *key, long long v)
{
    printf("%s=%lld err=%lu\n", key, v, ERR_peek_error());
    ERR_clear_error();
}

static void sayp(const char *key, const void *p)
{
    printf("%s=%s err=%lu\n", key, p == NULL ? "NULL" : "nonnull",
           ERR_peek_error());
    ERR_clear_error();
}

int main(void)
{
    OSSL_LIB_CTX *gd, *a, *b, *prev;

    setvbuf(stdout, NULL, _IOLBF, 0);

    /* The two functions do not need the context to exist first, but a context is
     * what they read, so this establishes that the global default is there. */
    gd = OSSL_LIB_CTX_get0_global_default();
    sayp("gd.nonnull", gd);

    /* ------------------------------------------------ a fresh, non-default context */

    a = OSSL_LIB_CTX_new();
    b = OSSL_LIB_CTX_new();
    sayp("new.a", a);
    sayp("new.b", b);
    sayn("new.distinct", a != b);

    /* A fresh context's counter is zero, and it is zero for each of them. */
    sayu("get.a.initial", OSSL_get_max_threads(a));
    sayu("get.b.initial", OSSL_get_max_threads(b));

    sayn("set.a.7", OSSL_set_max_threads(a, 7));
    sayu("get.a.7", OSSL_get_max_threads(a));
    /* Per-context: `b` did not move. */
    sayu("get.b.after.a.7", OSSL_get_max_threads(b));

    /* Stored verbatim, with no range check. */
    sayn("set.b.max", OSSL_set_max_threads(b, UINT64_MAX));
    sayu("get.b.max", OSSL_get_max_threads(b));
    sayu("get.a.after.b.max", OSSL_get_max_threads(a));

    /* Zero is a value, not "unset". */
    sayn("set.a.zero", OSSL_set_max_threads(a, 0));
    sayu("get.a.zero", OSSL_get_max_threads(a));
    sayu("get.b.still.max", OSSL_get_max_threads(b));
    sayn("set.b.zero", OSSL_set_max_threads(b, 0));

    /* ------------------------------------------------------ the NULL context */

    /* No thread-local default is installed, so NULL is the global default, whose
     * counter starts at zero and is the same object `gd` names. */
    sayu("get.null.initial", OSSL_get_max_threads(NULL));
    sayn("set.gd.9", OSSL_set_max_threads(gd, 9));
    sayu("get.null.after.gd.9", OSSL_get_max_threads(NULL));
    sayu("get.gd.9", OSSL_get_max_threads(gd));
    sayn("set.null.5", OSSL_set_max_threads(NULL, 5));
    sayu("get.null.5", OSSL_get_max_threads(NULL));
    sayu("get.gd.after.null.5", OSSL_get_max_threads(gd));
    /* The non-default contexts were not touched by any of that. */
    sayu("get.a.after.null", OSSL_get_max_threads(a));
    sayn("set.gd.zero", OSSL_set_max_threads(gd, 0));

    /* ------------------------------------------------- installing a default */

    /* Once this thread defaults to `a`, the NULL context is `a`, so the same
     * accessor answers `a`'s value. That is the whole reason the accessor takes a
     * context it is allowed to be given as NULL. */
    sayn("set.a.11", OSSL_set_max_threads(a, 11));
    sayu("null.before.default", OSSL_get_max_threads(NULL));
    prev = OSSL_LIB_CTX_set0_default(a);
    sayn("default.installed", prev == gd);
    sayu("null.after.default", OSSL_get_max_threads(NULL));
    sayu("explicit.a.after.default", OSSL_get_max_threads(a));
    /* `b` is still `b`. */
    sayu("explicit.b.after.default", OSSL_get_max_threads(b));

    /* Restoring the global default restores the NULL answer, and it must restore
     * it as *the global object*, not as a copy of it. */
    sayn("default.restore", OSSL_LIB_CTX_set0_default(gd) == a);
    sayu("null.after.restore", OSSL_get_max_threads(NULL));
    sayn("set.null.13", OSSL_set_max_threads(NULL, 13));
    sayu("get.gd.13", OSSL_get_max_threads(gd));
    sayn("set.gd.zero2", OSSL_set_max_threads(gd, 0));

    /* ------------------------------------------------------------------ cleanup */

    /* `a` and `b` are not the default, so these really release them. */
    OSSL_LIB_CTX_free(a);
    OSSL_LIB_CTX_free(b);
    sayp("free.gd.alive", OSSL_LIB_CTX_get0_global_default());

    sayn("err.empty", ERR_peek_error() == 0);
    printf("done=rt-threaddata err=%lu\n", ERR_peek_error());
    return 0;
}
