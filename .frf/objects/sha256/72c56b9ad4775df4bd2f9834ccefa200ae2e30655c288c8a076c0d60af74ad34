/*
 * rt_txtdb_probe.c -- RT-TXTDB: the Phase-13.5 TXT_DB text database, driven.
 *
 * One C program, compiled once against the admitted authority and once against the candidate
 * distribution shell; the two transcripts are diffed line by line, keyed on `key=value`. Every
 * observation is a small integer or a byte string printed as hex -- never an address, never a
 * clock, never the error queue.
 *
 * ## What this probe drives
 *
 * The whole of `include/openssl/txt_db.h`, over a fixed in-memory database:
 *
 *   * `TXT_DB_read` (`crypto/txt_db/txt_db.c:20-125`) parses a fixed file held in a
 *     `BIO_new_mem_buf` BIO: a leading `#` comment record is skipped, fields are separated by
 *     tabs, and an escaped tab (`\` + TAB) is a literal tab inside a field. Every field of
 *     every row is printed as hex. Two failure arms are driven: a record with too few fields
 *     and one with too many, each of which answers NULL;
 *   * `TXT_DB_write` (`:187-232`) re-emits the parsed database to a `BIO_s_mem` BIO; the bytes
 *     are printed as hex, and the output is read back through a second `TXT_DB_read` to show
 *     the writer emits only bytes the reader accepts (the dropped comment excepted, which is
 *     the codec's own documented loss);
 *   * `TXT_DB_create_index` (`:147-185`) builds an lhash over field 0 with the probe's own
 *     hash and comparison functions, and a second database with a duplicate key is used to
 *     drive the `DB_ERROR_INDEX_CLASH` arm, whose `arg1`/`arg2` coordinates are printed;
 *   * `TXT_DB_get_by_index` (`:127-145`) drives a hit, a miss, an out-of-range index and a
 *     field with no index, each by its return and the `DB_ERROR_*` the object records;
 *   * `TXT_DB_insert` (`:234-277`) accepts a fresh row (the object then owns it) and refuses a
 *     duplicate, printing the clash's `Error`, `arg1` and the identity of `arg_row` against
 *     the row the index already held;
 *   * `TXT_DB_free` (`:279-314`) releases every object; nothing is printed for it, but the
 *     program runs to completion only because no row or index is double-freed.
 *
 * ## Arms that are deliberately absent
 *
 * A negative `idx` or `field` is not driven: the authority's range checks do not catch it and
 * would index out of bounds, so the two sides would compare undefined behaviour rather than
 * answers (the crate refuses it; see `src/txt_db/txt_db.rs`'s module header). `TXT_DB_write`
 * and `TXT_DB_insert` are never handed a NULL object, because both dereference it. The error
 * queue is never read: the `DB_ERROR_*` values on `TXT_DB` itself are the coordinate the
 * codec publishes.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/txt_db.h>

static void out_int(const char *key, long v)
{
    printf("%s=%ld\n", key, v);
}

static void out_hex(const char *key, const char *p, size_t n)
{
    size_t i;
    printf("%s=", key);
    for (i = 0; i < n; i++)
        printf("%02x", (unsigned char)p[i]);
    printf("\n");
}

/* ---------------------------------------------------------------------------------------------
 * The index callbacks: field 0 is the key. A polynomial hash and a strcmp, both the probe's own,
 * so the index's behaviour is measured against a function the transcript can name.
 * ------------------------------------------------------------------------------------------- */

static unsigned long key_hash(const void *v)
{
    const unsigned char *s = (const unsigned char *)((char **)v)[0];
    unsigned long h = 0;

    while (*s != '\0') {
        h = h * 131u + *s;
        s++;
    }
    return h;
}

static int key_cmp(const void *a, const void *b)
{
    return strcmp(((char **)a)[0], ((char **)b)[0]);
}

/* ---------------------------------------------------------------------------------------------
 * A row builder that mirrors what TXT_DB_read allocates: one block holding (n + 1) field
 * pointers followed by the NUL-terminated fields, with row[n] the sentinel. TXT_DB_free can then
 * release an inserted row by the same path it releases a parsed one.
 * ------------------------------------------------------------------------------------------- */

static char **make_row(const char *f0, const char *f1, const char *f2)
{
    const char *f[3];
    size_t total = 0;
    char **row;
    char *p;
    int i;

    f[0] = f0;
    f[1] = f1;
    f[2] = f2;
    for (i = 0; i < 3; i++)
        total += strlen(f[i]) + 1;
    row = OPENSSL_malloc(4 * sizeof(char *) + total);
    if (row == NULL)
        return NULL;
    p = (char *)(row + 4);
    for (i = 0; i < 3; i++) {
        size_t l = strlen(f[i]);
        memcpy(p, f[i], l + 1);
        row[i] = p;
        p += l + 1;
    }
    row[3] = p;
    return row;
}

/* Print every field of every row, each as hex, under a fixed prefix. */
static void dump_db(const char *prefix, TXT_DB *db)
{
    int nf = db->num_fields;
    int rows = sk_OPENSSL_PSTRING_num(db->data);
    char key[64];
    int r, f;

    snprintf(key, sizeof key, "%s.rows", prefix);
    out_int(key, rows);
    for (r = 0; r < rows; r++) {
        char **row = sk_OPENSSL_PSTRING_value(db->data, r);
        for (f = 0; f < nf; f++) {
            const char *s = row[f];
            snprintf(key, sizeof key, "%s.r%d.f%d", prefix, r, f);
            out_hex(key, s, strlen(s));
        }
    }
}

int main(void)
{
    /* `# comment` is skipped; the backslash-tab in row 0 field 1 is a literal tab. */
    static const char FILE_A[] =
        "# comment\tignored\n"
        "alpha=1\tx\\\tyyy\tz\n"
        "beta=2\tp\tq\n"
        "gamma=3\tm\tn\n";
    /* Two records with the same key, for the create-index clash arm. */
    static const char FILE_DUP[] =
        "k=1\ta\tb\n"
        "k=1\tc\td\n";
    /* Two malformed single-record files: too few fields, and too many. */
    static const char FILE_FEW[] = "a\tb\n";
    static const char FILE_MANY[] = "a\tb\tc\td\n";

    BIO *in_a = BIO_new_mem_buf(FILE_A, -1);
    TXT_DB *db = TXT_DB_read(in_a, 3);
    TXT_DB *rt;
    TXT_DB *dup_db;
    TXT_DB *few_db;
    TXT_DB *many_db;
    BIO *mem;
    BIO *rt_in;
    BIO *dup_in;
    BIO *few_in;
    BIO *many_in;
    OPENSSL_STRING lookup[1];
    OPENSSL_STRING *hit;
    char wbuf[4096];
    int got;
    long w;

    /* ---- read: split, comment skip and escaped tab ---------------------------------------- */
    out_int("read.nonnull", db != NULL);
    out_int("read.nf", db != NULL ? db->num_fields : -1);
    if (db != NULL)
        dump_db("read", db);

    /* ---- write: round trip ----------------------------------------------------------------- */
    mem = BIO_new(BIO_s_mem());
    w = TXT_DB_write(mem, db);
    out_int("write.ret", w);
    got = BIO_read(mem, wbuf, (int)sizeof wbuf);
    out_int("write.len", got > 0 ? got : 0);
    out_hex("write.hex", wbuf, got > 0 ? (size_t)got : 0);
    BIO_free(mem);

    rt_in = BIO_new_mem_buf(wbuf, got);
    rt = TXT_DB_read(rt_in, 3);
    out_int("rt.nonnull", rt != NULL);
    if (rt != NULL) {
        out_int("rt.nf", rt->num_fields);
        dump_db("rt", rt);
    }

    /* ---- create_index + get_by_index: hit, miss, out of range, no index -------------------- */
    out_int("idx.create.ret", TXT_DB_create_index(db, 0, NULL, key_hash, key_cmp));
    lookup[0] = "beta=2";
    hit = TXT_DB_get_by_index(db, 0, lookup);
    out_int("idx.hit.nonnull", hit != NULL);
    out_int("idx.hit.error", db->error);
    if (hit != NULL)
        out_hex("idx.hit.f0", hit[0], strlen(hit[0]));
    lookup[0] = "zeta=9";
    out_int("idx.miss.nonnull", TXT_DB_get_by_index(db, 0, lookup) != NULL);
    out_int("idx.miss.error", db->error);
    out_int("idx.oor.nonnull", TXT_DB_get_by_index(db, 3, lookup) != NULL);
    out_int("idx.oor.error", db->error);
    out_int("idx.noindex.nonnull", TXT_DB_get_by_index(db, 1, lookup) != NULL);
    out_int("idx.noindex.error", db->error);

    /* ---- insert: accept, then a duplicate-key clash --------------------------------------- */
    {
        char **fresh = make_row("delta=4", "r", "s");
        out_int("ins.ret", TXT_DB_insert(db, fresh));
        out_int("ins.rows", sk_OPENSSL_PSTRING_num(db->data));
        lookup[0] = "delta=4";
        out_int("ins.find.nonnull", TXT_DB_get_by_index(db, 0, lookup) != NULL);
    }
    {
        char **dupe = make_row("beta=2", "X", "Y");
        out_int("ins.dup.ret", TXT_DB_insert(db, dupe));
        out_int("ins.dup.error", db->error);
        out_int("ins.dup.arg1", db->arg1);
        out_int("ins.dup.rows", sk_OPENSSL_PSTRING_num(db->data));
        out_int("ins.dup.arg_row.same", db->arg_row == hit);
        if (db->arg_row != NULL)
            out_hex("ins.dup.arg_row.f0", ((char **)db->arg_row)[0],
                    strlen(((char **)db->arg_row)[0]));
        OPENSSL_free(dupe); /* refused, so the object never took ownership */
    }

    /* The write after the insert shows the accepted row and the refused one absent. */
    mem = BIO_new(BIO_s_mem());
    w = TXT_DB_write(mem, db);
    out_int("write2.ret", w);
    got = BIO_read(mem, wbuf, (int)sizeof wbuf);
    out_hex("write2.hex", wbuf, got > 0 ? (size_t)got : 0);
    BIO_free(mem);

    /* ---- read failures: wrong field count answers NULL ------------------------------------- */
    few_in = BIO_new_mem_buf(FILE_FEW, -1);
    few_db = TXT_DB_read(few_in, 3);
    out_int("bad.few.nonnull", few_db != NULL);
    many_in = BIO_new_mem_buf(FILE_MANY, -1);
    many_db = TXT_DB_read(many_in, 3);
    out_int("bad.many.nonnull", many_db != NULL);

    /* ---- create_index clash, on a database with two equal keys ----------------------------- */
    dup_in = BIO_new_mem_buf(FILE_DUP, -1);
    dup_db = TXT_DB_read(dup_in, 3);
    out_int("dupdb.nonnull", dup_db != NULL);
    out_int("dupdb.rows", dup_db != NULL ? sk_OPENSSL_PSTRING_num(dup_db->data) : -1);
    out_int("idx.dup.create.ret", TXT_DB_create_index(dup_db, 0, NULL, key_hash, key_cmp));
    out_int("idx.dup.error", dup_db->error);
    out_int("idx.dup.arg1", dup_db->arg1);
    out_int("idx.dup.arg2", dup_db->arg2);

    /* ---- free ------------------------------------------------------------------------------ */
    TXT_DB_free(db);
    TXT_DB_free(rt);
    TXT_DB_free(dup_db);
    TXT_DB_free(few_db);
    TXT_DB_free(many_db);
    BIO_free(in_a);
    BIO_free(rt_in);
    BIO_free(dup_in);
    BIO_free(few_in);
    BIO_free(many_in);
    out_int("free.done", 1);
    return 0;
}
