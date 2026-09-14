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
#include <openssl/bio.h>
#include <openssl/lhash.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned long hash_str(const void *p)
{
    return OPENSSL_LH_strhash(p);
}

/*
 * Both helpers emit a multi-line report as ONE observation, so the transcript
 * stays one `key=value` record per line. `emit_mem` drains a memory BIO;
 * `emit_lines` escapes a string captured from a `FILE *`.
 */
static void emit_lines(const char *key, const char *s)
{
    printf("%s=", key);
    for (; *s != '\0'; s++)
        putchar(*s == '\n' ? '|' : *s);
    putchar('\n');
}

static void emit_mem(const char *key, BIO *b)
{
    char buf[4096];
    int n = BIO_read(b, buf, (int)sizeof(buf) - 1);

    if (n < 0)
        n = 0;
    buf[n] = '\0';
    emit_lines(key, buf);
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
    (void)p;
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
    /* NOT MEASURED: `OPENSSL_LH_doall`, `OPENSSL_LH_doall_arg` and
     * `OPENSSL_LH_doall_arg_thunk` SEGFAULT the authority on a table created with
     * the bare `OPENSSL_LH_new`. Every generated `lh_TYPE_new` installs thunks via
     * `OPENSSL_LH_set_thunks`, and the iteration entry points dereference the
     * (here NULL) thunk rather than falling back to direct iteration. That is a
     * fault boundary, not a documented failure, so the candidate must not copy it:
     * it iterates directly and is recorded as a safety divergence in
     * docs/SECURITY_DIVERGENCE_POLICY.md. The line is kept as a visible marker so
     * the boundary is not silently absent from the transcript. */
    printf("doall.calls=NOT_MEASURED_AUTHORITY_FAULTS\n");
    printf("doall_arg.calls=NOT_MEASURED_AUTHORITY_FAULTS\n");

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

    /*
     * ---- the statistics report ---------------------------------------------
     *
     * `OPENSSL_LH_stats_bio` makes `num_nodes` and `num_alloc_nodes` observable,
     * and they are deliberately different numbers: the table is a linear-hashing
     * one, so only `num_nodes` buckets are in use while `num_alloc_nodes` are
     * allocated. The report is captured through a memory BIO and through an
     * in-memory `FILE *`, so both entry points are compared, and each line is
     * emitted with newlines escaped to keep the transcript one observation per
     * record.
     */
    {
        BIO *b = BIO_new(BIO_s_mem());
        char *filebuf = NULL;
        size_t filelen = 0;
        FILE *f;
        /*
         * One buffer per stored key: the table keeps the *pointer* it was given,
         * so reusing a buffer would silently change the contents of an entry
         * already in the table and make the bucket distribution a measurement of
         * the aliasing rather than of the hash.
         */
        static char k6[6][16];
        static char k64[64][16];
        int i;

        lh = OPENSSL_LH_new(NULL, NULL);

        /* Empty table: 8 nodes in use out of 16 allocated. */
        OPENSSL_LH_stats_bio(lh, b);
        emit_mem("stats.empty", b);

        for (i = 0; i < 6; i++) {
            snprintf(k6[i], sizeof(k6[i]), "stat-%02d", i);
            OPENSSL_LH_insert(lh, k6[i]);
        }
        OPENSSL_LH_stats_bio(lh, b);
        emit_mem("stats.six", b);
        OPENSSL_LH_node_stats_bio(lh, b);
        emit_mem("node_stats.six", b);
        OPENSSL_LH_node_usage_stats_bio(lh, b);
        emit_mem("node_usage.six", b);

        /*
         * Enough inserts to split buckets: 64 items take the table past several
         * expansions, so both counts move and the split path is exercised.
         */
        for (i = 0; i < 64; i++) {
            snprintf(k64[i], sizeof(k64[i]), "grown-%02d", i);
            OPENSSL_LH_insert(lh, k64[i]);
        }
        OPENSSL_LH_stats_bio(lh, b);
        emit_mem("stats.grown", b);
        OPENSSL_LH_node_usage_stats_bio(lh, b);
        emit_mem("node_usage.grown", b);

        /* Deleting back down exercises the merge path. */
        for (i = 63; i >= 0; i--)
            OPENSSL_LH_delete(lh, k64[i]);
        OPENSSL_LH_stats_bio(lh, b);
        emit_mem("stats.shrunk", b);

        /* Flush empties the buckets without changing the table's shape. */
        OPENSSL_LH_flush(lh);
        OPENSSL_LH_stats_bio(lh, b);
        emit_mem("stats.flushed", b);

        /* The `FILE *` entry points, captured with open_memstream. */
        f = open_memstream(&filebuf, &filelen);
        OPENSSL_LH_stats(lh, f);
        OPENSSL_LH_node_usage_stats(lh, f);
        fclose(f);
        emit_lines("stats.file", filebuf);
        free(filebuf);

        /* A NULL table and a NULL destination must not crash. */
        OPENSSL_LH_stats_bio(NULL, b);
        printf("stats.null_table=1\n");
        OPENSSL_LH_stats_bio(lh, NULL);
        printf("stats.null_bio=1\n");

        BIO_free(b);
        OPENSSL_LH_free(lh);
    }

    return 0;
}
