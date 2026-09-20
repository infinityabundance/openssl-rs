/*
 * RT-DH -- the differential court for `crypto/dh/dh_meth.c` (Phase 8.5's first slice).
 *
 * This program is compiled **twice**, once against the admitted authority and once against the
 * candidate distribution shell, and the two `key=value` transcripts are diffed. It never decides
 * anything: a residual is a difference between two executions, so the expectation cannot drift
 * with the crate. `forensics/tools/phase8_courts.py` owns the comparison.
 *
 * What this court covers, and what it does not
 * --------------------------------------------
 * This slice is the twenty-one `DH_meth_*` labels, and **every one of the twenty-one is called
 * below**. Nothing here does any cryptography: each function allocates a table, stores a pointer
 * in one, duplicates one, releases one, or reads one back. The transcript is therefore about
 * *identity, ownership and structure* rather than arithmetic, and that is the whole observable
 * contract of these entry points.
 *
 * The rest of 8.5 -- the `DH` object, `dh_key.c`'s generation and agreement, `dh_gen.c`,
 * `dh_check.c`, the FFC primitives and the named-group tables -- is **not** exercised here,
 * because it is not landed. This court's arms say so by their absence rather than by a transcribed
 * expectation, and `docs/DECISIONS.md` D329 names the dependency that keeps them open.
 *
 * The allocator-attribution plane
 * -------------------------------
 * `CRYPTO_set_mem_functions`'s callbacks take `(size_t num, const char *file, int line)`, and all
 * three are part of the published contract: an embedder that installs an allocator receives them.
 * `dh_meth.c` is a **source-tree** file, so `OPENSSL_FILE` in its bodies is
 * `../../src/openssl-3.6.4/crypto/dh/dh_meth.c` -- the prefix is present, unlike the `.c.in`
 * instances D279 and D280 had to distinguish. So the first thing this probe does is install an
 * allocator and record, for each arm, the **ordered sequence of `(kind, size, file)`** the library
 * requests inside a window that starts before the call and ends after it. That is how the claim
 * "this unit's allocation is attributed to this unit's translation unit" becomes a diff instead of
 * a constant in the crate.
 *
 * **The sequence, not just the set, is deliberate.** The order is load-bearing in three arms:
 * `DH_meth_new` stores `flags` *before* duplicating the name, so a failed duplicate can release
 * the table; `DH_meth_set1_name` duplicates *first* and releases second, so a failed duplicate
 * leaves the old name in place; `DH_meth_free` releases the name *before* the table. A set of
 * `file` strings would make all three orders invisible.
 *
 * The window is a window and not a whole-program trace for the same reason `RT-CIPHER-MEM`'s is:
 * `CRYPTO_set_mem_functions` latches, and the *rest* of the process -- the error queue, stdio, the
 * warm-up -- is not what this court is about. The warm-up call before the first window is what
 * keeps the first window from containing lazy library state.
 *
 * No address is ever printed: every function pointer is compared for equality with a local
 * sentinel and the *result* is printed, and the two name pointers are compared for *inequality*
 * rather than for their values. stdout is line-buffered, and no NULL-dereferencing entry point is
 * called -- a probe that aborts the harness compares nothing.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
/* `DH_meth_*` are `OSSL_DEPRECATEDIN_3_0`. The deprecation is the authority's own policy statement
 * about application code, not about a court that must exercise the entry points it declares;
 * suppressing the diagnostic keeps `-Wall` output readable without changing a single symbol this
 * probe links. */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/dh.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ the recorder */

#define EV_MAX 32
#define EV_NAME 512

/* Each event owns a copy of its `file` string rather than a pointer into the library, so a
 * release that happens before the window closes cannot leave the transcript reading freed
 * memory. A NULL `file` is recorded as the literal `<null>` for the same reason: the argument is
 * itself part of the contract, and dropping the event would hide exactly that. */
static char ev_file[EV_MAX][EV_NAME];
static unsigned long ev_size[EV_MAX];
static char ev_kind[EV_MAX];
static int nev;
static int recording;

static void record(char kind, size_t size, const char *file, int line)
{
    size_t n;

    if (!recording)
        return;
    if (file == NULL) {
        strcpy(ev_file[nev], "<null>");
    } else {
        n = strlen(file);
        if (n >= EV_NAME)
            n = EV_NAME - 1;
        memcpy(ev_file[nev], file, n);
        ev_file[nev][n] = '\0';
    }
    ev_kind[nev] = kind;
    ev_size[nev] = (unsigned long)size;
    if (nev < EV_MAX - 1)
        nev++;
    else
        ev_kind[nev] = kind; /* keep the count honest when the ring saturates */
    (void)line;
}

static void *my_malloc(size_t n, const char *file, int line)
{
    record('M', n, file, line);
    return malloc(n);
}

static void *my_realloc(void *p, size_t n, const char *file, int line)
{
    record('R', n, file, line);
    return realloc(p, n);
}

static void my_free(void *p, const char *file, int line)
{
    record('F', 0, file, line);
    free(p);
}

static void begin(void)
{
    nev = 0;
    recording = 1;
}

static void end(const char *arm)
{
    int i;

    recording = 0;
    printf("dh.%s.ev=%d\n", arm, nev);
    for (i = 0; i < nev; i++)
        printf("dh.%s.ev.%d=%c:%lu:%s\n", arm, i, ev_kind[i], ev_size[i], ev_file[i]);
}

/* ------------------------------------------------------------------ sentinels */

/* One per distinct function-pointer signature in `DH_METHOD`. They are stored and compared,
 * never called: each returns its own constant so that a transcription which *did* call one would
 * be visible in the transcript rather than merely wrong. */
static int sentinel_generate_key(DH *dh)
{
    (void)dh;
    return 0;
}

static int sentinel_compute_key(unsigned char *key, const BIGNUM *pub_key, DH *dh)
{
    (void)key; (void)pub_key; (void)dh;
    return 0;
}

static int sentinel_bn_mod_exp(const DH *dh, BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
    const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx)
{
    (void)dh; (void)r; (void)a; (void)p; (void)m; (void)ctx; (void)m_ctx;
    return 0;
}

static int sentinel_life(DH *dh)
{
    (void)dh;
    return 0;
}

static int sentinel_generate_params(DH *dh, int prime_len, int generator, BN_GENCB *cb)
{
    (void)dh; (void)prime_len; (void)generator; (void)cb;
    return 0;
}

/* The six function-pointer pairs, each observed five ways: the member of a fresh table is NULL;
 * the setter answers 1; the getter then answers the *sentinel* rather than merely non-NULL; the
 * setter accepts NULL and still answers 1; and the getter is back to NULL. The round trip leaves
 * the member NULL, which is what lets one table serve all six without order dependence. */
#define ROUNDTRIP(tag, GET, SET, SENT)                                  \
    do {                                                                \
        printf("dh.%s.get_default_is_null=%d\n", tag,                  \
            (const void *)(GET)(m) == NULL);                            \
        printf("dh.%s.set_ret=%d\n", tag, (SET)(m, (SENT)));           \
        printf("dh.%s.get_is_sentinel=%d\n", tag,                      \
            (const void *)(GET)(m) == (const void *)(SENT));           \
        printf("dh.%s.set_null_ret=%d\n", tag, (SET)(m, NULL));        \
        printf("dh.%s.get_after_null_is_null=%d\n", tag,               \
            (const void *)(GET)(m) == NULL);                            \
    } while (0)

int main(void)
{
    DH_METHOD *m;
    DH_METHOD *dup;
    void *marker = (void *)0x1234;

    /* The install latches, so it is the first act of the process. `my_malloc` records only while a
     * window is open, so the warm-up below attributes nothing. */
    if (!CRYPTO_set_mem_functions(my_malloc, my_realloc, my_free)) {
        printf("dh.set_mem_functions=0\n");
        return 1;
    }
    printf("dh.set_mem_functions=1\n");

    /* Warm-up, outside every window: the first `DH_meth_new` runs whatever lazy library state the
     * allocation path has, and a window around it would record that rather than this unit. */
    m = DH_meth_new("warmup", 0);
    if (m == NULL) {
        printf("dh.warmup=0\n");
        return 1;
    }
    DH_meth_free(m);

    /* ---- the window arms, in the order the functions run */

    begin();
    m = DH_meth_new("court-dh-method", 0x1234);
    end("new");
    printf("dh.new.not_null=%d\n", m != NULL);

    begin();
    dup = DH_meth_dup(m);
    end("dup");
    printf("dh.dup.not_null=%d\n", dup != NULL);

    begin();
    printf("dh.set1_name.ret=%d\n", DH_meth_set1_name(m, "court-dh-renamed"));
    end("set1_name");

    /* A refusal window: a NULL name is refused without an allocation on either side. */
    begin();
    printf("dh.set1_name_null.ret=%d\n", DH_meth_set1_name(m, NULL));
    end("set1_name_null");

    /* ---- the structural observations, none of which is an address */

    printf("dh.new.name=%s\n", DH_meth_get0_name(m));
    printf("dh.new.flags=%d\n", DH_meth_get_flags(m));
    printf("dh.new.app_data_is_null=%d\n", DH_meth_get0_app_data(m) == NULL);
    printf("dh.dup.name=%s\n", DH_meth_get0_name(dup));
    printf("dh.dup.flags=%d\n", DH_meth_get_flags(dup));
    printf("dh.dup.app_data_is_null=%d\n", DH_meth_get0_app_data(dup) == NULL);
    /* The duplicate's name is a second allocation, so the two pointers differ. */
    printf("dh.dup.name_ptr_differs=%d\n",
        DH_meth_get0_name(dup) != DH_meth_get0_name(m));
    /* A NULL `set1_name` leaves the old name in place. */
    printf("dh.set1_name_null.name_unchanged=%d",
        strcmp(DH_meth_get0_name(m), "court-dh-renamed") == 0);
    printf("\n");

    ROUNDTRIP("generate_key", DH_meth_get_generate_key, DH_meth_set_generate_key,
        sentinel_generate_key);
    ROUNDTRIP("compute_key", DH_meth_get_compute_key, DH_meth_set_compute_key,
        sentinel_compute_key);
    ROUNDTRIP("bn_mod_exp", DH_meth_get_bn_mod_exp, DH_meth_set_bn_mod_exp,
        sentinel_bn_mod_exp);
    ROUNDTRIP("init", DH_meth_get_init, DH_meth_set_init, sentinel_life);
    ROUNDTRIP("finish", DH_meth_get_finish, DH_meth_set_finish, sentinel_life);
    ROUNDTRIP("generate_params", DH_meth_get_generate_params, DH_meth_set_generate_params,
        sentinel_generate_params);

    /* `app_data` is not a function pointer and its NULL is a value, not a refusal. */
    printf("dh.app_data.set_ret=%d\n", DH_meth_set0_app_data(m, marker));
    printf("dh.app_data.get_is_marker=%d\n", DH_meth_get0_app_data(m) == marker);
    printf("dh.app_data.set_null_ret=%d\n", DH_meth_set0_app_data(m, NULL));
    printf("dh.app_data.get_after_null_is_null=%d\n", DH_meth_get0_app_data(m) == NULL);

    /* `flags` is stored verbatim and answered unconditionally. */
    printf("dh.flags.set_ret=%d\n", DH_meth_set_flags(m, 0x0f0f));
    printf("dh.flags.get=%d\n", DH_meth_get_flags(m));

    /* ---- the release windows, in the order the two objects are released */

    begin();
    DH_meth_free(dup);
    end("free_dup");

    begin();
    DH_meth_free(m);
    end("free_new");

    /* The preloaded name is the one `set1_name` stored, so the release order and the string are
     * both observed above. A NULL free is a no-op and records nothing. */
    begin();
    DH_meth_free(NULL);
    end("free_null");

    return 0;
}
