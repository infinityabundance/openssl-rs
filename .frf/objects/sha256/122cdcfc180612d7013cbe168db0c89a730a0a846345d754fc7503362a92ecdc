/*
 * openssl-rs — RT-EXDATA probe.
 *
 * One program, compiled against the authority and against the candidate and
 * diffed. It records which callbacks fire, in what order, with which `(argl)`,
 * and what the entry points return for every documented invalid input. The
 * ordering and the "does this callback fire at all" questions are the ones that
 * are easy to get plausibly wrong: for example, it is not obvious from the API
 * whether `CRYPTO_dup_ex_data` invokes the dup callbacks when the source
 * structure has no slot stack yet.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <openssl/crypto.h>
#include <openssl/err.h>

#include <stdio.h>
#include <string.h>

/* A tiny ordered log of callback invocations. */
static char g_ev[64];
static int g_argl[64];
static int g_n;

static void rec(char kind, int idx, long argl)
{
    if (g_n < 64) {
        g_ev[g_n] = kind;
        g_argl[g_n] = (int)argl;
        g_n++;
    }
    (void)idx;
}

static void dump(const char *tag)
{
    int i;
    printf("%s.count=%d\n", tag, g_n);
    for (i = 0; i < g_n; i++)
        printf("%s.%d=%c/%d\n", tag, i, g_ev[i], g_argl[i]);
    g_n = 0;
}

static void my_new(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl, void *argp)
{
    (void)parent;
    (void)ptr;
    (void)ad;
    (void)argp;
    rec('N', idx, argl);
}

static int my_dup(CRYPTO_EX_DATA *to, const CRYPTO_EX_DATA *from, void **from_d, int idx,
                  long argl, void *argp)
{
    (void)to;
    (void)from;
    (void)from_d;
    (void)argp;
    rec('D', idx, argl);
    return 1;
}

static void my_free(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl, void *argp)
{
    (void)parent;
    (void)ptr;
    (void)ad;
    (void)argp;
    rec('F', idx, argl);
}

int main(void)
{
    CRYPTO_EX_DATA ad;
    CRYPTO_EX_DATA to;
    int i1, i2, rc;

    setvbuf(stdout, NULL, _IONBF, 0);
    printf("probe.rt-exdata=1\n");

    /* ---- index allocation ------------------------------------------------- */
    i1 = CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_APP, 11, NULL, my_new, my_dup, my_free);
    i2 = CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_APP, 22, NULL, NULL, NULL, NULL);
    printf("index.first_positive=%d\n", i1 > 0);
    printf("index.increments_by_one=%d\n", i2 == i1 + 1);
    printf("index.minus_one=%d\n",
           CRYPTO_get_ex_new_index(-1, 0, NULL, NULL, NULL, NULL));
    printf("index.at_count=%d\n",
           CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX__COUNT, 0, NULL, NULL, NULL, NULL));
    printf("index.err_raised=%d\n", ERR_peek_error() != 0);
    ERR_clear_error();

    /* ---- new_ex_data on an empty structure --------------------------------- */
    memset(&ad, 0, sizeof(ad));
    g_n = 0;
    rc = CRYPTO_new_ex_data(CRYPTO_EX_INDEX_APP, NULL, &ad);
    printf("new.rc=%d\n", rc);
    printf("new.sk_allocated=%d\n", ad.sk != NULL);
    dump("new");
    memset(&to, 0, sizeof(to));
    (void)to;

    /* ---- dup with a source that was never populated ------------------------ */
    memset(&to, 0, sizeof(to));
    g_n = 0;
    rc = CRYPTO_dup_ex_data(CRYPTO_EX_INDEX_APP, &to, &ad);
    printf("dup.empty_from.rc=%d\n", rc);
    printf("dup.empty_from.events=%d\n", g_n);
    g_n = 0;

    /* ---- populate, then dup ----------------------------------------------- */
    rc = CRYPTO_set_ex_data(&ad, i1, (void *)0x1000);
    printf("set.rc=%d\n", rc);
    rc = CRYPTO_set_ex_data(&ad, i2, (void *)0x2000);
    printf("set.second_rc=%d\n", rc);
    printf("get.round_trip=%d\n", CRYPTO_get_ex_data(&ad, i1) == (void *)0x1000);
    printf("get.absent_is_null=%d\n", CRYPTO_get_ex_data(&ad, 0) == NULL);
    printf("get.negative_is_null=%d\n", CRYPTO_get_ex_data(&ad, -1) == NULL);
    /* NOT MEASURED, and deliberately so.
     *
     * `CRYPTO_get_ex_data(NULL, 0)` SEGFAULTS the authority: it dereferences the
     * `CRYPTO_EX_DATA *` without a NULL check. A probe cannot compare a crash,
     * and the candidate must not reproduce undefined behaviour merely to match an
     * observed fault. The candidate returns NULL instead; that divergence is
     * recorded in docs/SECURITY_DIVERGENCE_POLICY.md and in the Phase 3 seal.
     * The line is kept as a marker so the boundary is visible in the transcript
     * rather than being silently absent. */
    printf("get.null_ad=NOT_MEASURED_AUTHORITY_FAULTS\n");

    memset(&to, 0, sizeof(to));
    g_n = 0;
    rc = CRYPTO_dup_ex_data(CRYPTO_EX_INDEX_APP, &to, &ad);
    printf("dup.populated.rc=%d\n", rc);
    dump("dup.populated");
    printf("dup.copied_value=%d\n", CRYPTO_get_ex_data(&to, i1) == (void *)0x1000);

    /* ---- dup with an invalid class ---------------------------------------- */
    {
        CRYPTO_EX_DATA bad_to;
        memset(&bad_to, 0, sizeof(bad_to));
        printf("dup.invalid_class.empty=%d\n",
               CRYPTO_dup_ex_data(-1, &bad_to, &to));
        printf("dup.invalid_class.populated=%d\n",
               CRYPTO_dup_ex_data(CRYPTO_EX_INDEX__COUNT, &bad_to, &ad));
        printf("dup.invalid_class.err=%d\n", ERR_peek_error() != 0);
        ERR_clear_error();
        /* A VALID class that simply has no callbacks registered, with a source
         * that does have a stack: does the copy succeed or fail? */
        printf("dup.valid_class_no_callbacks=%d\n",
               CRYPTO_dup_ex_data(CRYPTO_EX_INDEX_DSA, &bad_to, &ad));
        printf("dup.valid_class_no_callbacks.err=%d\n", ERR_peek_error() != 0);
        ERR_clear_error();
    }

    /* ---- new_ex_data with an invalid class -------------------------------- */
    {
        CRYPTO_EX_DATA bad;
        memset(&bad, 0, sizeof(bad));
        printf("new.invalid_class.neg=%d\n", CRYPTO_new_ex_data(-1, NULL, &bad));
        printf("new.invalid_class.count=%d\n", CRYPTO_new_ex_data(CRYPTO_EX_INDEX__COUNT, NULL, &bad));
        printf("new.invalid_class.err=%d\n", ERR_peek_error() != 0);
        ERR_clear_error();
    }

    /* ---- set/get with a NULL ad ------------------------------------------- */
    /* NOT MEASURED: `CRYPTO_set_ex_data(NULL, ...)` is the same unchecked
     * dereference as above and is not run here. See the note on
     * `get.null_ad` above. */
    printf("set.null_ad=NOT_MEASURED_AUTHORITY_FAULTS\n");

    /* ---- free: callback order and stack release --------------------------- */
    g_n = 0;
    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_APP, NULL, &to);
    dump("free.to");
    printf("free.to.sk_cleared=%d\n", to.sk == NULL);
    g_n = 0;
    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_APP, NULL, &ad);
    dump("free.ad");
    printf("free.ad.sk_cleared=%d\n", ad.sk == NULL);

    /* ---- free again: must be harmless -------------------------------------- */
    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_APP, NULL, &ad);
    printf("free.twice_survived=1\n");

    return 0;
}
