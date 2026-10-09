/*
 * openssl-rs — Phase 25.8 differential probe: the sparse array against the authority.
 *
 * Drives the admitted authority's `ossl_sa_*` (OpenSSL 3.6.4) through one deterministic
 * operation sequence under a **caller-installed allocator** (`CRYPTO_set_mem_functions`),
 * including an allocation-failure injection, and prints a machine-readable JSON transcript.
 * `forensics/tools/ms_sparse_array_court.py` compiles and runs this against the authority and
 * runs the crate's matching Rust harness, then compares the two transcripts.
 *
 * Nothing here is a symbol of the crate: it links the authority's internal `sparse_array.o`
 * out of `libcrypto.a` (they are global there) and observes the same behaviours the Rust
 * reconstruction must conserve -- insert / replace / remove / depth growth, the numeric
 * boundary, the walk order, the allocation-hook observations and the failure answer.
 *
 * Build (inside the court only):
 *   clang -std=c11 -O1 -I <authority>/include -o probe rt_sparse_array_probe.c \
 *       -L <authority>/lib -lcrypto -Wl,-rpath,<authority>/lib -lpthread -ldl -lm
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <openssl/crypto.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The internal sparse-array surface (`crypto/sparse_array.h`), declared here so the probe needs
 * no internal header on the include path. `ossl_uintmax_t` is `uint64_t` in this profile. */
typedef struct sparse_array_st OPENSSL_SA;
extern OPENSSL_SA *ossl_sa_new(void);
extern void ossl_sa_free(OPENSSL_SA *sa);
extern void ossl_sa_free_leaves(OPENSSL_SA *sa);
extern size_t ossl_sa_num(const OPENSSL_SA *sa);
extern void ossl_sa_doall(const OPENSSL_SA *sa, void (*leaf)(uint64_t, void *));
extern void ossl_sa_doall_arg(const OPENSSL_SA *sa, void (*leaf)(uint64_t, void *, void *), void *arg);
extern void *ossl_sa_get(const OPENSSL_SA *sa, uint64_t n);
extern int ossl_sa_set(OPENSSL_SA *sa, uint64_t n, void *val);

#define TAG_MAX 64
#define ORD_MAX 64

/* The caller's allocator. `fail_after` < 0 disables injection; otherwise the (fail_after+1)-th
 * allocation answers NULL, which is the exhaustion the authority's `alloc_node` must propagate. */
static long g_mallocs;
static long g_frees;
static long g_calls;
static long g_fail_after = -1;
static int g_fail_next;
static unsigned long long g_sizes[TAG_MAX];
static int g_nsizes;

static void *hook_malloc(size_t n, const char *file, int line)
{
    (void)file;
    (void)line;
    if (g_fail_next) {
        /* One-shot failure: the node request answers NULL, and the error-report state the
         * authority allocates in response is allowed through (it would otherwise recurse). */
        g_fail_next = 0;
        return NULL;
    }
    if (g_fail_after >= 0 && g_calls >= g_fail_after)
        return NULL;
    g_calls++;
    g_mallocs++;
    if (g_nsizes < TAG_MAX)
        g_sizes[g_nsizes] = (unsigned long long)n;
    g_nsizes++;
    return malloc(n);
}

static void *hook_realloc(void *p, size_t n, const char *file, int line)
{
    (void)file;
    (void)line;
    return realloc(p, n);
}

static void hook_free(void *p, const char *file, int line)
{
    (void)file;
    (void)line;
    g_frees++;
    free(p);
}

/* Value blocks: an 8-byte allocation whose first byte is the tag, so a `get` result can be
 * reported as the tag it holds rather than as a pointer (which differs run to run). */
static void *g_values[TAG_MAX];
static unsigned char g_tags[TAG_MAX];
static int g_nvalues;

static unsigned char alloc_tag(int tag)
{
    void *p = CRYPTO_malloc(8, "probe", 1);
    if (p == NULL)
        return 0xff;
    ((unsigned char *)p)[0] = (unsigned char)tag;
    g_values[g_nvalues] = p;
    g_tags[g_nvalues] = (unsigned char)tag;
    g_nvalues++;
    return (unsigned char)tag;
}

/* The tag a live value pointer holds, or -1 for NULL / not one of ours. */
static int tag_of(void *p)
{
    int i;
    if (p == NULL)
        return -1;
    for (i = 0; i < g_nvalues; i++)
        if (g_values[i] == p)
            return (int)g_tags[i];
    return -2;
}

static uint64_t g_order[ORD_MAX];
static int g_norder;

static void order_leaf_note(uint64_t idx, void *val, void *arg)
{
    (void)arg;
    if (g_norder < ORD_MAX)
        g_order[g_norder] = (uint64_t)tag_of(val) + 1; /* 0 => null, else tag+1 */
    g_norder++;
}

static void emit_sizes(void)
{
    int i;
    printf("\"sizes\":[");
    for (i = 0; i < g_nsizes && i < TAG_MAX; i++)
        printf("%s%llu", i ? "," : "", g_sizes[i]);
    printf("]");
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    int nv = 0;
    int setret[16];
    int nset = 0;
    int gettag[16];
    int nget = 0;
    size_t num0;
    OPENSSL_SA *sa;
    int i;

    int installed;

    printf("SPARSE_JSON {");

    /* Install the caller's allocator first: this is the only order in which the authority
     * accepts it (its `allow_customize` clears on the first default allocation). */
    installed = CRYPTO_set_mem_functions(hook_malloc, hook_realloc, hook_free);
    printf("\"impl\":\"openssl-3.6.4\",\"installed\":%d,", installed);

    /* Value tags 1..7, one 8-byte block each. */
    {
        int tags[8] = {1, 2, 3, 4, 5, 6, 7};
        for (i = 0; i < 7; i++)
            alloc_tag(tags[i]);
    }

    sa = ossl_sa_new();
    printf("\"new\":%s,", sa != NULL ? "true" : "false");

    /* Insert / replace / remove / depth growth / the numeric boundary. */
    {
        struct { uint64_t n; int tag; } ops[] = {
            {5ULL, 1},                    /* depth 1 */
            {0ULL, 2},                    /* depth 1 */
            {0x10ULL, 3},                 /* depth 2 */
            {0x100ULL, 4},                /* depth 3 */
            {5ULL, 5},                    /* replace an existing slot */
            {0x10ULL, 0},                 /* remove (NULL) */
            {~(uint64_t)0, 6},            /* u64::MAX: the deepest tree */
            {1ULL << 60, 7},              /* the first index needing all 16 levels */
        };
        for (i = 0; i < (int)(sizeof(ops) / sizeof(ops[0])); i++) {
            void *val = ops[i].tag == 0 ? NULL : g_values[ops[i].tag - 1];
            setret[nset++] = ossl_sa_set(sa, ops[i].n, val);
        }
    }

    printf("\"set_ret\":[");
    for (i = 0; i < nset; i++)
        printf("%s%d", i ? "," : "", setret[i]);
    printf("],");

    num0 = ossl_sa_num(sa);
    printf("\"num\":%zu,", num0);

    /* Lookups, reported by the tag they hold. */
    {
        uint64_t ns[] = {5ULL, 0ULL, 0x10ULL, 0x100ULL, 1ULL << 60, ~(uint64_t)0, 17ULL};
        for (i = 0; i < (int)(sizeof(ns) / sizeof(ns[0])); i++)
            gettag[nget++] = tag_of(ossl_sa_get(sa, ns[i]));
    }
    printf("\"get\":[");
    for (i = 0; i < nget; i++)
        printf("%s%d", i ? "," : "", gettag[i]);
    printf("],");

    /* The walk order, reported by tag+1 (0 => null). */
    g_norder = 0;
    ossl_sa_doall_arg(sa, order_leaf_note, NULL);
    printf("\"order\":[");
    for (i = 0; i < g_norder; i++)
        printf("%s%llu", i ? "," : "", (unsigned long long)g_order[i]);
    printf("],");

    /* Allocation observations over the whole sequence so far. */
    printf("\"alloc\":{\"malloc\":%ld,\"free\":%ld,", g_mallocs, g_frees);
    emit_sizes();
    printf("},");

    /* Release values, nodes and header. */
    ossl_sa_free_leaves(sa);

    /* Allocation-failure injection: a fresh array whose first growth node is refused. A fresh
     * header is allocation #1 and the refused node is #2, so `set` must answer 0 and leave the
     * array ungrown; a retry (no injection) must then succeed. */
    g_mallocs = 0;
    g_frees = 0;
    g_calls = 0;
    {
        OPENSSL_SA *f = ossl_sa_new();
        int r;
        size_t n;
        void *g;
        int levels_after_fail;
        int r2;
        g_fail_next = 1;
        r = ossl_sa_set(f, 0x100ULL, g_values[0]);
        n = ossl_sa_num(f);
        g = ossl_sa_get(f, 0x100ULL);
        levels_after_fail = f ? ((int *)f)[0] : -1; /* levels is the first field */
        g_fail_next = 0;
        r2 = ossl_sa_set(f, 0x100ULL, g_values[0]);
        printf("\"fail\":{\"set_ret\":%d,\"num\":%zu,\"get_null\":%s,\"levels\":%d,"
               "\"retry_ret\":%d,\"retry_num\":%zu},",
               r, n, g == NULL ? "true" : "false", levels_after_fail,
               r2, ossl_sa_num(f));
        ossl_sa_free(f);
    }

    printf("\"num\":%zu", num0);
    printf("}\n");
    return 0;
}
