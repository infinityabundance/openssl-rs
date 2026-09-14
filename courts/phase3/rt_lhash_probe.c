/*
 * openssl-rs — RT-LHASH probe.
 *
 * One program, compiled against the authority and against the candidate and
 * diffed. `OPENSSL_LH_strhash` is the part that cannot be reasoned out: it is a
 * specific rotate-and-xor construction whose constants and shift widths are only
 * knowable by measurement, and a caller can observe its value directly. So the
 * probe prints it over a spread of inputs, and separately records the insertion,
 * retrieval, duplicate, deletion, iteration and load-factor behaviour.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <openssl/lhash.h>

#include <stdio.h>
#include <string.h>

static unsigned long hash_str(const void *p)
{
    return OPENSSL_LH_strhash(p);
}

static int cmp_str(const void *a, const void *b)
{
    return strcmp(a, b);
}

static int g_doall_calls;

static void doall_cb(void *p)
{
    g_doall_calls++;
    printf("doall.item=%s\n", (const char *)p);
}

static void doall_arg_cb(void *p, void *arg)
{
    int *n = arg;
    (*n)++;
}

int main(void)
{
    OPENSSL_LHASH *lh;
    char *prev;

    setvbuf(stdout, NULL, _IONBF, 0);
    printf("probe.rt-lhash=1\n");

    /* ---- strhash: the exact values, over a spread of inputs ---------------- */
    printf("strhash.null=%lu\n", OPENSSL_LH_strhash(NULL));
    printf("strhash.empty=%lu\n", OPENSSL_LH_strhash(""));
    {
        static const char *const inputs[] = {
            "a", "b", "z", "A", "Z", "0", "9", " ", "cn", "CN", "commonName",
            "subjectAltName", "2.5.4.3", "1.2.840.113549.1.1.11", "sha256",
            "a longer string with spaces and punctuation: !@#$%^&*()",
        };
        size_t i;
        for (i = 0; i < sizeof(inputs) / sizeof(inputs[0]); i++)
            printf("strhash.[%s]=%lu\n", inputs[i], OPENSSL_LH_strhash(inputs[i]));
    }

    /* ---- construction and defaults ---------------------------------------- */
    lh = OPENSSL_LH_new(hash_str, cmp_str);
    printf("new.nonnull=%d\n", lh != NULL);
    printf("new.num_items=%lu\n", OPENSSL_LH_num_items(lh));
    printf("new.error=%d\n", OPENSSL_LH_error(lh));
    printf("new.down_load=%lu\n", OPENSSL_LH_get_down_load(lh));
    printf("new.retrieve_missing_null=%d\n", OPENSSL_LH_retrieve(lh, "nope") == NULL);
    printf("new.delete_missing_null=%d\n", OPENSSL_LH_delete(lh, "nope") == NULL);

    /* ---- insert / retrieve / duplicate ------------------------------------ */
    prev = OPENSSL_LH_insert(lh, (void *)"alpha");
    printf("insert.first_prev_null=%d\n", prev == NULL);
    prev = OPENSSL_LH_insert(lh, (void *)"beta");
    printf("insert.second_prev_null=%d\n", prev == NULL);
    printf("num_items.after_two=%lu\n", OPENSSL_LH_num_items(lh));
    printf("retrieve.alpha=%d\n", OPENSSL_LH_retrieve(lh, "alpha") != NULL);
    printf("retrieve.beta=%d\n", OPENSSL_LH_retrieve(lh, "beta") != NULL);
    printf("retrieve.absent=%d\n", OPENSSL_LH_retrieve(lh, "gamma") == NULL);

    /* Inserting a DIFFERENT pointer with an EQUAL key: the authority returns the
     * previously stored pointer and keeps the original in the table. */
    prev = OPENSSL_LH_insert(lh, (void *)"alpha2");
    printf("insert.duplicate_returns_prev=%d\n", prev != NULL && strcmp(prev, "alpha") == 0);
    printf("insert.duplicate_num_items=%lu\n", OPENSSL_LH_num_items(lh));

    /* ---- more items, then iteration order ---------------------------------- */
    (void)OPENSSL_LH_insert(lh, (void *)"delta");
    (void)OPENSSL_LH_insert(lh, (void *)"epsilon");
    (void)OPENSSL_LH_insert(lh, (void *)"zeta");
    printf("num_items.six=%lu\n", OPENSSL_LH_num_items(lh));
    g_doall_calls = 0;
    OPENSSL_LH_doall(lh, doall_cb);
    printf("doall.calls=%d\n", g_doall_calls);
    {
        int n = 0;
        OPENSSL_LH_doall_arg(lh, doall_arg_cb, &n);
        printf("doall_arg.calls=%d\n", n);
    }

    /* ---- delete ------------------------------------------------------------ */
    prev = OPENSSL_LH_delete(lh, "beta");
    printf("delete.beta_returns_item=%d\n", prev != NULL && strcmp(prev, "beta") == 0);
    printf("delete.num_items=%lu\n", OPENSSL_LH_num_items(lh));
    printf("delete.absent_again=%d\n", OPENSSL_LH_delete(lh, "beta") == NULL);

    /* ---- down_load is settable and readable -------------------------------- */
    OPENSSL_LH_set_down_load(lh, 4);
    printf("down_load.after_set=%lu\n", OPENSSL_LH_get_down_load(lh));

    /* ---- flush empties without freeing the items --------------------------- */
    OPENSSL_LH_flush(lh);
    printf("flush.num_items=%lu\n", OPENSSL_LH_num_items(lh));
    printf("flush.retrieve_null=%d\n", OPENSSL_LH_retrieve(lh, "alpha") == NULL);
    (void)OPENSSL_LH_insert(lh, (void *)"post-flush");
    printf("flush.reuse_insert=%d\n", OPENSSL_LH_retrieve(lh, "post-flush") != NULL);

    OPENSSL_LH_free(lh);
    printf("free.survived=1\n");
    OPENSSL_LH_free(NULL);
    printf("free.null_survived=1\n");

    return 0;
}
