/*
 * openssl-rs — RT-MEM probe.
 *
 * One program, compiled twice (against the authority and against the candidate)
 * and diffed. Everything it prints must therefore be deterministic and
 * address-free: it reports *classes* (null/non-null, equal/different, zeroed/
 * not) and exact return values, never pointers.
 *
 * The interesting part is the counting allocator installed through
 * CRYPTO_set_mem_functions. Ownership and cleansing are not observable through
 * return values alone, so the probe makes them observable: the custom free
 * snapshots the block it is handed, which is how "clear_free cleansed the
 * buffer before releasing it" stops being a claim and becomes a measurement.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <openssl/crypto.h>
#include <openssl/err.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SNAP_MAX 128

static unsigned long g_malloc_calls, g_realloc_calls, g_free_calls;
static unsigned long g_live;

struct record {
    void *p;
    size_t n;
    int used;
};
static struct record g_records[4096];

static unsigned char g_snap[SNAP_MAX];
static size_t g_snap_len;
static unsigned long g_snap_count;

static void record_set(void *p, size_t n)
{
    size_t i;
    if (p == NULL)
        return;
    for (i = 0; i < sizeof(g_records) / sizeof(g_records[0]); i++) {
        if (!g_records[i].used) {
            g_records[i].used = 1;
            g_records[i].p = p;
            g_records[i].n = n;
            return;
        }
    }
}

static struct record *record_get(void *p)
{
    size_t i;
    for (i = 0; i < sizeof(g_records) / sizeof(g_records[0]); i++)
        if (g_records[i].used && g_records[i].p == p)
            return &g_records[i];
    return NULL;
}

static void record_del(void *p)
{
    struct record *r = record_get(p);
    if (r != NULL)
        r->used = 0;
}

static void *counting_malloc(size_t num, const char *file, int line)
{
    void *p;
    (void)file;
    (void)line;
    g_malloc_calls++;
    p = malloc(num);
    if (p != NULL) {
        record_set(p, num);
        g_live++;
    }
    return p;
}

static void *counting_realloc(void *addr, size_t num, const char *file, int line)
{
    void *p;
    (void)file;
    (void)line;
    g_realloc_calls++;
    if (addr == NULL)
        g_live++;
    if (addr != NULL && num == 0) {
        /* libc semantics: realloc(p, 0) releases p and returns NULL. Model it
         * explicitly so the probe's own bookkeeping cannot go stale. */
        record_del(addr);
        g_live--;
        return realloc(addr, 0);
    }
    p = realloc(addr, num);
    if (p != NULL) {
        if (addr != NULL)
            record_del(addr);
        record_set(p, num);
    }
    return p;
}

static void counting_free(void *addr, const char *file, int line)
{
    struct record *r;
    (void)file;
    (void)line;
    g_free_calls++;
    if (addr == NULL)
        return;
    r = record_get(addr);
    if (r != NULL) {
        /* Snapshot BEFORE releasing: this is what makes cleansing observable. */
        g_snap_len = r->n < SNAP_MAX ? r->n : SNAP_MAX;
        memcpy(g_snap, addr, g_snap_len);
        g_snap_count++;
        record_del(addr);
    }
    g_live--;
    free(addr);
}

static void sayn(const char *k, long v)
{
    printf("%s=%ld\n", k, v);
}

static void sayp(const char *k, const void *v)
{
    printf("%s=%s\n", k, v != NULL ? "nonnull" : "null");
}

static int all_zero(const unsigned char *p, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++)
        if (p[i] != 0)
            return 0;
    return 1;
}

/* Did the last freed block start with `b`? */
static int snap_starts(unsigned char b)
{
    if (g_snap_len == 0)
        return 0;
    return g_snap[0] == b;
}

/* Report the exact fault location if a probe step dies: stdout is unbuffered so
 * the last printed key names the step that failed. */
static void unbuffered(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
}

int main(int argc, char **argv)
{
    void *p, *q, *freeptr = NULL;
    char *s;
    unsigned char *z;
    unsigned long before;
    int rc;
    /* Optional stop point, so a crash can be localised by bisection:
     * `./probe 2` runs sections 1..2 and stops. The default runs everything. */
    int section = argc > 1 ? atoi(argv[1]) : 99;

    printf("probe.rt-mem=1\n");
    unbuffered();

    /* ---- allocator installation ------------------------------------------ */
    rc = CRYPTO_set_mem_functions(counting_malloc, counting_realloc, counting_free);
    sayn("set_mem_functions.rc", rc);
    {
        CRYPTO_malloc_fn m = NULL;
        CRYPTO_realloc_fn r = NULL;
        CRYPTO_free_fn f = NULL;
        CRYPTO_get_mem_functions(&m, &r, &f);
        sayn("get_mem_functions.malloc_installed", m == counting_malloc);
        sayn("get_mem_functions.realloc_installed", r == counting_realloc);
        sayn("get_mem_functions.free_installed", f == counting_free);
    }
    /* Installing the allocator a second time: the authority refuses once it has
     * committed, and callers rely on that return value. */
    sayn("set_mem_functions.again",
         CRYPTO_set_mem_functions(counting_malloc, counting_realloc, counting_free));

    /* ---- allocation sizes ------------------------------------------------ */
    sayp("malloc.0", CRYPTO_malloc(0, __FILE__, __LINE__));
    p = CRYPTO_malloc(16, __FILE__, __LINE__);
    sayp("malloc.16", p);
    CRYPTO_free(p, __FILE__, __LINE__);
    CRYPTO_free(NULL, __FILE__, __LINE__);

    sayp("zalloc.0", CRYPTO_zalloc(0, __FILE__, __LINE__));
    z = CRYPTO_zalloc(32, __FILE__, __LINE__);
    sayp("zalloc.32", z);
    sayn("zalloc.32.zeroed", all_zero(z, 32));
    CRYPTO_free(z, __FILE__, __LINE__);

    sayp("calloc.0x16", CRYPTO_calloc(0, 16, __FILE__, __LINE__));
    sayp("calloc.16x0", CRYPTO_calloc(16, 0, __FILE__, __LINE__));
    z = CRYPTO_calloc(4, 8, __FILE__, __LINE__);
    sayp("calloc.4x8", z);
    sayn("calloc.4x8.zeroed", all_zero(z, 32));
    CRYPTO_free(z, __FILE__, __LINE__);

    sayp("malloc_array.4x4", CRYPTO_malloc_array(4, 4, __FILE__, __LINE__));
    sayp("malloc_array.4x0", CRYPTO_malloc_array(4, 0, __FILE__, __LINE__));
    sayp("malloc_array.overflow", CRYPTO_malloc_array((size_t)-1, 2, __FILE__, __LINE__));
    sayn("malloc_array.overflow.err", ERR_peek_error() != 0);
    {
        const char *efile = NULL, *efunc = NULL, *edata = NULL;
        int eline = 0, eflags = 0;
        unsigned long e = ERR_peek_error_all(&efile, &eline, &efunc, &edata, &eflags);
        printf("malloc_array.overflow.err.code=%08lX\n", e);
        printf("malloc_array.overflow.err.node=%lu\n", e >> 23);
        printf("malloc_array.overflow.err.reason=%lu\n", e & 0x7FFFFF);
        printf("malloc_array.overflow.err.func=%s\n", efunc != NULL ? efunc : "(null)");
        printf("malloc_array.overflow.err.file=%s\n", efile != NULL ? efile : "(null)");
        printf("malloc_array.overflow.err.line_nonzero=%d\n", eline != 0);
        printf("malloc_array.overflow.err.data=%s\n", edata != NULL ? edata : "(null)");
        printf("malloc_array.overflow.err.flags=%d\n", eflags);
    }
    ERR_clear_error();

    if (section < 1) { printf("stopped.after=1\n"); return 0; }

    sayp("realloc.null_addr", CRYPTO_realloc(NULL, 8, __FILE__, __LINE__));
    p = CRYPTO_malloc(16, __FILE__, __LINE__);
    memset(p, 0xAA, 16);
    before = g_free_calls;
    q = CRYPTO_realloc(p, 0, __FILE__, __LINE__);
    sayp("realloc.zero_num", q);
    sayn("realloc.zero_num.freed", g_free_calls - before);

    /* ---- clear_realloc: shrinking must NOT move and must cleanse the tail - */
    p = CRYPTO_malloc(32, __FILE__, __LINE__);
    memset(p, 0xAA, 32);
    before = g_snap_count;
    q = CRYPTO_clear_realloc(p, 32, 16, __FILE__, __LINE__);
    sayn("clear_realloc.shrink_same_ptr", q == p);
    sayn("clear_realloc.shrink.freed", g_snap_count - before);
    sayn("clear_realloc.shrink.content", ((unsigned char *)q)[0] == 0xAA);
    CRYPTO_free(q, __FILE__, __LINE__);

    p = CRYPTO_malloc(16, __FILE__, __LINE__);
    memset(p, 0xBB, 16);
    g_snap_len = 0;
    g_snap_count = 0;
    q = CRYPTO_clear_realloc(p, 16, 0, __FILE__, __LINE__);
    sayp("clear_realloc.zero_num", q);
    sayn("clear_realloc.zero_num.freed", g_snap_count);
    sayn("clear_realloc.zero_num.cleansed", all_zero(g_snap, g_snap_len));

    sayp("clear_realloc.null_addr", CRYPTO_clear_realloc(NULL, 0, 8, __FILE__, __LINE__));

    if (section < 2) { printf("stopped.after=2\n"); return 0; }

    /* ---- array realloc ---------------------------------------------------- */
    /* On an overflowing request the authority RELEASES addr and returns NULL.
     * That ownership transfer is part of the contract, so the probe must not
     * free again afterwards: doing so is a double free, which is how this
     * behaviour was discovered. */
    p = CRYPTO_malloc_array(4, 4, __FILE__, __LINE__);
    q = CRYPTO_realloc_array(p, 8, 4, __FILE__, __LINE__);
    if (section < 31) { printf("stopped.after=31\n"); return 0; }
    sayp("realloc_array.null_addr", CRYPTO_realloc_array(NULL, 2, 4, __FILE__, __LINE__));
    g_snap_count = 0;
    sayp("realloc_array.overflow", CRYPTO_realloc_array(q, (size_t)-1, 2, __FILE__, __LINE__));
    sayn("realloc_array.overflow.released_addr", g_snap_count);
    sayn("realloc_array.overflow.err", ERR_peek_error() != 0);
    printf("realloc_array.overflow.err.code=%08lX\n", ERR_peek_error());
    ERR_clear_error();
    if (section < 32) { printf("stopped.after=32\n"); return 0; }
    p = CRYPTO_malloc_array(4, 4, __FILE__, __LINE__);
    /* `old_num` here is the OLD ELEMENT COUNT, not a byte count: it is
     * multiplied by `size` internally (which is also how the element-count
     * parameter of CRYPTO_realloc_array is interpreted). Passing a byte count
     * makes the authority cleanse past the end of the block -- how this was
     * established, by observing heap corruption in an earlier probe revision. */
    memset(p, 0xEE, 16);
    q = CRYPTO_clear_realloc_array(p, 4, 8, 4, __FILE__, __LINE__);
    sayp("clear_realloc_array.grow", q);
    sayn("clear_realloc_array.grow.preserves", q != NULL && ((unsigned char *)q)[15] == 0xEE);
    CRYPTO_free(q, __FILE__, __LINE__);
    if (section < 33) { printf("stopped.after=33\n"); return 0; }
    if (section < 33) { printf("stopped.after=33\n"); return 0; }
    p = CRYPTO_malloc_array(4, 4, __FILE__, __LINE__);
    g_snap_count = 0;
    sayp("clear_realloc_array.overflow",
         CRYPTO_clear_realloc_array(p, 4, (size_t)-1, 2, __FILE__, __LINE__));
    sayn("clear_realloc_array.overflow.released_addr", g_snap_count);
    sayn("clear_realloc_array.overflow.err", ERR_peek_error() != 0);
    printf("clear_realloc_array.overflow.err.code=%08lX\n", ERR_peek_error());
    ERR_clear_error();

    if (section < 3) { printf("stopped.after=3\n"); return 0; }

    /* ---- aligned allocation ---------------------------------------------- */
    freeptr = NULL;
    p = CRYPTO_aligned_alloc(64, 64, &freeptr, __FILE__, __LINE__);
    sayp("aligned_alloc.64", p);
    sayn("aligned_alloc.aligned", p != NULL && ((uintptr_t)p % 64) == 0);
    /* NOT `freeptr == p`: whether the underlying allocation happens to be
     * aligned is a property of the process's heap layout, which legitimately
     * differs between the authority and a candidate that links a Rust runtime.
     * Comparing it would turn a heap-layout coincidence into a false residual.
     * What IS contractual is that `*freeptr` is the block base, that the returned
     * pointer lies at or after it, and that the offset is smaller than `align`. */
    sayn("aligned_alloc.freeptr_nonnull", freeptr != NULL);
    sayn("aligned_alloc.offset_within_align",
         p != NULL && freeptr != NULL && (uintptr_t)p >= (uintptr_t)freeptr
             && ((uintptr_t)p - (uintptr_t)freeptr) < 64);
    sayp("aligned_alloc.freeptr", freeptr);
    if (freeptr != NULL)
        CRYPTO_free(freeptr, __FILE__, __LINE__);
    else if (p != NULL)
        CRYPTO_free(p, __FILE__, __LINE__);

    freeptr = NULL;
    sayp("aligned_alloc.zero_num", CRYPTO_aligned_alloc(0, 64, &freeptr, __FILE__, __LINE__));
    freeptr = NULL;
    p = CRYPTO_aligned_alloc_array(4, 16, 32, &freeptr, __FILE__, __LINE__);
    sayp("aligned_alloc_array.4x16", p);
    if (freeptr != NULL)
        CRYPTO_free(freeptr, __FILE__, __LINE__);

    if (section < 4) { printf("stopped.after=4\n"); return 0; }

    /* ---- dup / strdup ------------------------------------------------------ */
    sayp("memdup.null", CRYPTO_memdup(NULL, 8, __FILE__, __LINE__));
    p = CRYPTO_memdup("abc", 3, __FILE__, __LINE__);
    sayn("memdup.3.content", p != NULL && memcmp(p, "abc", 3) == 0);
    sayp("memdup.zero_len", CRYPTO_memdup("abc", 0, __FILE__, __LINE__));
    CRYPTO_free(p, __FILE__, __LINE__);

    sayp("strdup.null", CRYPTO_strdup(NULL, __FILE__, __LINE__));
    s = CRYPTO_strdup("hello", __FILE__, __LINE__);
    sayn("strdup.content", s != NULL && strcmp(s, "hello") == 0);
    CRYPTO_free(s, __FILE__, __LINE__);

    sayp("strndup.null", CRYPTO_strndup(NULL, 3, __FILE__, __LINE__));
    s = CRYPTO_strndup("abcdef", 3, __FILE__, __LINE__);
    sayn("strndup.truncates", s != NULL && strcmp(s, "abc") == 0);
    CRYPTO_free(s, __FILE__, __LINE__);
    s = CRYPTO_strndup("abc", 8, __FILE__, __LINE__);
    sayn("strndup.stops_at_nul", s != NULL && strcmp(s, "abc") == 0);
    CRYPTO_free(s, __FILE__, __LINE__);
    s = CRYPTO_strndup("abc", 0, __FILE__, __LINE__);
    sayn("strndup.zero_len_empty", s != NULL && s[0] == '\0');
    CRYPTO_free(s, __FILE__, __LINE__);

    /* ---- memcmp: exact return value, not just zero/non-zero ---------------- */
    {
        unsigned char a[4] = { 0x01, 0x02, 0x03, 0x04 };
        unsigned char b[4] = { 0x01, 0x02, 0x03, 0x04 };
        unsigned char c[4] = { 0x01, 0x02, 0x03, 0x00 };
        unsigned char d[4] = { 0x00, 0x02, 0x03, 0x04 };
        sayn("memcmp.equal", CRYPTO_memcmp(a, b, 4));
        sayn("memcmp.diff.04", CRYPTO_memcmp(a, c, 4));
        sayn("memcmp.diff.01", CRYPTO_memcmp(a, d, 4));
        sayn("memcmp.len0", CRYPTO_memcmp(a, d, 0));
    }
    /* The exact return value for a single differing byte, across the range of
     * differences. "Non-zero on difference" and "the OR of the differences"
     * are different contracts and callers can observe which one holds. */
    {
        static const unsigned char diffs[] = { 0x01, 0x02, 0x04, 0x08, 0x10,
                                               0x40, 0x80, 0xFF };
        size_t i;
        for (i = 0; i < sizeof(diffs) / sizeof(diffs[0]); i++) {
            unsigned char x[1];
            unsigned char y[1];
            char key[32];
            x[0] = diffs[i];
            y[0] = 0x00;
            snprintf(key, sizeof(key), "memcmp.1byte.%02x", diffs[i]);
            sayn(key, CRYPTO_memcmp(x, y, 1));
        }
    }

    /* ---- cleansing --------------------------------------------------------- */
    z = CRYPTO_malloc(64, __FILE__, __LINE__);
    memset(z, 0x5A, 64);
    OPENSSL_cleanse(z, 64);
    sayn("cleanse.zeroed", all_zero(z, 64));
    CRYPTO_free(z, __FILE__, __LINE__);
    OPENSSL_cleanse(NULL, 0);
    sayn("cleanse.null_zero_len_survived", 1);

    /* ---- clear_free must cleanse before release --------------------------- */
    p = CRYPTO_malloc(48, __FILE__, __LINE__);
    memset(p, 0xCC, 48);
    g_snap_len = 0;
    g_snap_count = 0;
    CRYPTO_clear_free(p, 48, __FILE__, __LINE__);
    sayn("clear_free.freed", g_snap_count);
    sayn("clear_free.cleansed", all_zero(g_snap, g_snap_len));

    /* plain free must NOT cleanse: the contrast is the point */
    p = CRYPTO_malloc(48, __FILE__, __LINE__);
    memset(p, 0xCC, 48);
    g_snap_len = 0;
    g_snap_count = 0;
    CRYPTO_free(p, __FILE__, __LINE__);
    sayn("free.freed", g_snap_count);
    sayn("free.preserves_bytes", snap_starts(0xCC));

    /* Internal allocation counts are implementation detail, not contract, so
     * they go to stderr: the differential comparison reads stdout only, and
     * stderr stays available to a human debugging a failure. */
    fprintf(stderr, "counts.malloc=%lu realloc=%lu free=%lu live=%lu\n",
            g_malloc_calls, g_realloc_calls, g_free_calls, g_live);
    return 0;
}
