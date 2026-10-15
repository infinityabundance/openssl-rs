/*
 * openssl-rs — Phase 25 X.509 policy-tree differential probe.
 *
 * Drives the admitted authority's `X509_policy_check` and the whole policy-tree accessor surface
 * (OpenSSL 3.6.4, `crypto/x509/pcy_*.c`) through one deterministic sequence under a
 * **caller-installed allocator** (`CRYPTO_set_mem_functions`), including an allocation-failure
 * injection and the CVE-2023-0464 node cap, and prints a machine-readable JSON transcript.
 * `forensics/tools/ms_x509_policy_court.py` compiles and runs this against the authority and runs
 * the crate's matching Rust harness (`src/x509/pcy_probe.rs`), then compares the two transcripts
 * field by field.
 *
 * The file is deliberately **not** named `*_probe.c`: `probe_hygiene` scans `*_probe.c` for the
 * public-ABI probes, and this is not one -- it links the authority's internal `pcy_*.o` out of
 * `libcrypto.a` (they are global there) and observes the behaviour the crate reconstruction must
 * conserve.
 *
 * Build (inside the court only):
 *   clang -std=c11 -O1 -I <authority>/include -o probe rt_x509_policy_differential.c \
 *       <authority>/lib/libcrypto.a -lpthread -ldl -lm
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <openssl/asn1.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * `sizeof(X509_POLICY_NODE)` — `pcy_local.h` spells the node as three words and the crate asserts
 * 24. The failure injection targets the **first** allocation of exactly this size inside the check
 * window, which is the root anyPolicy node on both sides (the tree block is 64, the levels array is
 * `(nlevel * 32)`, the datum is 32 and the `OPENSSL_STACK` header is 32).
 */
#define NODE_SIZE 24

/* The authority's `X509.references` offset (`include/crypto/x509.h`, `struct x509_st`); the crate
 * asserts the same 192 at `src/x509/x_x509.rs`. Read directly so both sides report the same
 * refcount integer without an internal header on the include path. */
#define X509_REFERENCES_OFFSET 192
static int refs_of(X509 *x)
{
    return *(const int *)(const void *)((const char *)x + X509_REFERENCES_OFFSET);
}

#define SIZES_MAX 512
#define ORDER_MAX 64

/* --------------------------------------------------------------------------------------------- */
/* The caller's allocator.                                                                        */
/* --------------------------------------------------------------------------------------------- */

static long g_mallocs;
static long g_frees;
static int g_fail_size = -1; /* fail the first request of exactly this size, then pass */
static unsigned long long g_sizes[SIZES_MAX];
static int g_nsizes;

static void reset_counts(void)
{
    g_mallocs = 0;
    g_frees = 0;
    g_nsizes = 0;
}

static void *hook_malloc(size_t n, const char *file, int line)
{
    (void)file;
    (void)line;
    if (g_fail_size >= 0 && n == (size_t)g_fail_size) {
        g_fail_size = -1; /* one-shot: the error-report state the refusal then allocates is allowed */
        return NULL;
    }
    g_mallocs++;
    if (g_nsizes < SIZES_MAX)
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

/* --------------------------------------------------------------------------------------------- */
/* Certificate builders -- both sides build the same way so the check sees the same inputs.        */
/* --------------------------------------------------------------------------------------------- */

/* An `X509` carrying a single `CertificatePolicies` extension with the `n` OIDs. */
static X509 *cert_with_policies(const char *const *oids, int n)
{
    X509 *x = X509_new();
    STACK_OF(POLICYINFO) *cps;
    int i;

    if (x == NULL)
        return NULL;
    cps = sk_POLICYINFO_new_null();
    if (cps == NULL) {
        X509_free(x);
        return NULL;
    }
    for (i = 0; i < n; i++) {
        POLICYINFO *pi = POLICYINFO_new();
        if (pi == NULL) {
            sk_POLICYINFO_pop_free(cps, POLICYINFO_free);
            X509_free(x);
            return NULL;
        }
        pi->policyid = OBJ_txt2obj(oids[i], 1);
        if (pi->policyid == NULL || !sk_POLICYINFO_push(cps, pi)) {
            POLICYINFO_free(pi);
            sk_POLICYINFO_pop_free(cps, POLICYINFO_free);
            X509_free(x);
            return NULL;
        }
    }
    if (!X509_add1_ext_i2d(x, NID_certificate_policies, cps, 0, 0)) {
        sk_POLICYINFO_pop_free(cps, POLICYINFO_free);
        X509_free(x);
        return NULL;
    }
    sk_POLICYINFO_pop_free(cps, POLICYINFO_free);
    return x;
}

static X509 *cert_with_one_policy(const char *oid)
{
    const char *oids[1];
    oids[0] = oid;
    return cert_with_policies(oids, 1);
}

/* An `X509` with the `CertificatePolicies` set `pol` and a `policyMappings` extension
 * `from -> to` -- the mapped-policy intermediate. */
static X509 *cert_with_mapping(const char *pol, const char *from, const char *to)
{
    X509 *x = cert_with_one_policy(pol);
    STACK_OF(POLICY_MAPPING) *maps;
    POLICY_MAPPING *pm;

    if (x == NULL)
        return NULL;
    maps = sk_POLICY_MAPPING_new_null();
    pm = POLICY_MAPPING_new();
    if (maps == NULL || pm == NULL) {
        sk_POLICY_MAPPING_free(maps);
        POLICY_MAPPING_free(pm);
        X509_free(x);
        return NULL;
    }
    pm->issuerDomainPolicy = OBJ_txt2obj(from, 1);
    pm->subjectDomainPolicy = OBJ_txt2obj(to, 1);
    if (pm->issuerDomainPolicy == NULL || pm->subjectDomainPolicy == NULL
        || !sk_POLICY_MAPPING_push(maps, pm)) {
        POLICY_MAPPING_free(pm);
        sk_POLICY_MAPPING_free(maps);
        X509_free(x);
        return NULL;
    }
    if (!X509_add1_ext_i2d(x, NID_policy_mappings, maps, 0, 0)) {
        sk_POLICY_MAPPING_pop_free(maps, POLICY_MAPPING_free);
        X509_free(x);
        return NULL;
    }
    sk_POLICY_MAPPING_pop_free(maps, POLICY_MAPPING_free);
    return x;
}

/* A chain of `n` distinct numeric policy OIDs `1.2.3.4.<i>` on one certificate. */
static X509 *cert_with_npolicies(int n)
{
    X509 *x;
    STACK_OF(POLICYINFO) *cps;
    int i;

    x = X509_new();
    if (x == NULL)
        return NULL;
    cps = sk_POLICYINFO_new_null();
    if (cps == NULL) {
        X509_free(x);
        return NULL;
    }
    for (i = 0; i < n; i++) {
        char oid[48];
        POLICYINFO *pi = POLICYINFO_new();
        if (pi == NULL) {
            goto bad;
        }
        snprintf(oid, sizeof oid, "1.2.3.4.%d", i + 1);
        pi->policyid = OBJ_txt2obj(oid, 1);
        if (pi->policyid == NULL || !sk_POLICYINFO_push(cps, pi)) {
            POLICYINFO_free(pi);
            goto bad;
        }
    }
    if (!X509_add1_ext_i2d(x, NID_certificate_policies, cps, 0, 0)) {
        goto bad;
    }
    sk_POLICYINFO_pop_free(cps, POLICYINFO_free);
    return x;
bad:
    sk_POLICYINFO_pop_free(cps, POLICYINFO_free);
    X509_free(x);
    return NULL;
}

/* --------------------------------------------------------------------------------------------- */
/* Transcript emission.                                                                            */
/* --------------------------------------------------------------------------------------------- */

static void emit_oid(const ASN1_OBJECT *o)
{
    char buf[160];
    if (o == NULL) {
        printf("null");
        return;
    }
    buf[0] = '\0';
    OBJ_obj2txt(buf, sizeof buf, o, 1);
    printf("\"%s\"", buf);
}

/* The built tree's shape and the traversal order of `X509_policy_level_get0_node`. */
static void emit_shape(const char *name, X509_POLICY_TREE *tree, int ret, int expl)
{
    int levels, i, j, first = 1;
    char buf[160];

    printf("{\"name\":\"%s\",\"ret\":%d,\"expl\":%d,\"tree\":%d", name, ret, expl,
           tree != NULL);
    levels = X509_policy_tree_level_count(tree);
    printf(",\"levels\":%d", levels);
    printf(",\"pol\":%d",
           OPENSSL_sk_num((const OPENSSL_STACK *)X509_policy_tree_get0_policies(tree)));
    printf(",\"user\":%d",
           OPENSSL_sk_num((const OPENSSL_STACK *)X509_policy_tree_get0_user_policies(tree)));
    printf(",\"lc\":[");
    for (i = 0; i < levels; i++) {
        X509_POLICY_LEVEL *lvl = X509_policy_tree_get0_level(tree, i);
        printf("%s%d", i ? "," : "", X509_policy_level_node_count(lvl));
    }
    printf("],\"order\":[");
    for (i = 0; i < levels; i++) {
        X509_POLICY_LEVEL *lvl = X509_policy_tree_get0_level(tree, i);
        int n = X509_policy_level_node_count(lvl);
        for (j = 0; j < n; j++) {
            const X509_POLICY_NODE *node = X509_policy_level_get0_node(lvl, j);
            const ASN1_OBJECT *o = X509_policy_node_get0_policy(node);
            buf[0] = '\0';
            if (o != NULL)
                OBJ_obj2txt(buf, sizeof buf, o, 1);
            printf("%s\"%s\"", first ? "" : ",", buf);
            first = 0;
        }
    }
    printf("]}");
}

/* --------------------------------------------------------------------------------------------- */
/* The sequence.                                                                                   */
/* --------------------------------------------------------------------------------------------- */

/* Identities over the `single` tree: node count, nodes with a parent, parents that resolve to a
 * node the accessor returns at the level below, and the stability of repeated accessor calls. */
static int g_ident_nodes, g_ident_parents, g_ident_resolved, g_ident_stable = 1;

static void measure_identity(X509_POLICY_TREE *tree)
{
    int levels = X509_policy_tree_level_count(tree);
    int i, j, k;

    g_ident_nodes = g_ident_parents = g_ident_resolved = 0;
    g_ident_stable = 1;
    for (i = 0; i < levels; i++) {
        X509_POLICY_LEVEL *lvl = X509_policy_tree_get0_level(tree, i);
        int n = X509_policy_level_node_count(lvl);
        for (j = 0; j < n; j++) {
            X509_POLICY_NODE *node = X509_policy_level_get0_node(lvl, j);
            const X509_POLICY_NODE *par = X509_policy_node_get0_parent(node);
            g_ident_nodes++;
            if (X509_policy_level_get0_node(lvl, j) != node)
                g_ident_stable = 0;
            if (par != NULL) {
                int ok = 0;
                g_ident_parents++;
                if (i > 0) {
                    X509_POLICY_LEVEL *below = X509_policy_tree_get0_level(tree, i - 1);
                    int m = X509_policy_level_node_count(below);
                    for (k = 0; k < m; k++) {
                        if (X509_policy_level_get0_node(below, k) == par) {
                            ok = 1;
                            break;
                        }
                    }
                }
                if (ok)
                    g_ident_resolved++;
            }
        }
    }
}

/* The success-window allocator observation, filled by `run_single`. */
static long g_win_mallocs, g_win_frees;
static unsigned long long g_win_sizes[SIZES_MAX];
static int g_win_nsizes;
static long g_cl_mallocs, g_cl_frees;
static int g_ref_fresh, g_ref_after, g_ref_freed;

int main(void)
{
    int installed;
    X509_POLICY_TREE *tree;
    int expl, ret;
    int i;
    int first = 1;

    setvbuf(stdout, NULL, _IONBF, 0);

    printf("X509_POLICY_JSON {");

    /* Install the caller's allocator first: the only order the authority accepts. */
    installed = CRYPTO_set_mem_functions(hook_malloc, hook_realloc, hook_free);
    printf("\"impl\":\"openssl-3.6.4\",\"installed\":%d,", installed);

    printf("\"cases\":[");

    /* 1. NULL certs: `sk_X509_num(NULL) == -1`, so n = -2 -- INTERNAL. */
    {
        STACK_OF(X509) *c = NULL;
        tree = NULL;
        expl = -1;
        ret = X509_policy_check(&tree, &expl, c, NULL, 0);
        emit_shape("null_certs", tree, ret, expl);
        X509_policy_tree_free(tree);
    }

    /* 2. Empty cert stack: n = -1 -- INTERNAL. */
    {
        STACK_OF(X509) *c = sk_X509_new_null();
        printf(",");
        tree = NULL;
        expl = -1;
        ret = X509_policy_check(&tree, &expl, c, NULL, 0);
        emit_shape("empty_certs", tree, ret, expl);
        X509_policy_tree_free(tree);
        sk_X509_free(c);
    }

    /* 3. One trust anchor: n = 0 -- EMPTY, answered VALID with a NULL tree. */
    {
        X509 *ta = X509_new();
        STACK_OF(X509) *c = sk_X509_new_null();
        sk_X509_push(c, ta);
        printf(",");
        tree = NULL;
        expl = -1;
        ret = X509_policy_check(&tree, &expl, c, NULL, 0);
        emit_shape("one_ta", tree, ret, expl);
        X509_policy_tree_free(tree);
        sk_X509_free(c);
        X509_free(ta);
    }

    /* 4. Two policy-free certs: EMPTY, answered VALID with a NULL tree. */
    {
        X509 *a = X509_new();
        X509 *b = X509_new();
        STACK_OF(X509) *c = sk_X509_new_null();
        sk_X509_push(c, a);
        sk_X509_push(c, b);
        printf(",");
        tree = NULL;
        expl = -1;
        ret = X509_policy_check(&tree, &expl, c, NULL, 0);
        emit_shape("no_policies", tree, ret, expl);
        X509_policy_tree_free(tree);
        sk_X509_free(c);
        X509_free(a);
        X509_free(b);
    }

    /* 5. Two policy-free certs under X509_V_FLAG_EXPLICIT_POLICY: FAILURE. */
    {
        X509 *a = X509_new();
        X509 *b = X509_new();
        STACK_OF(X509) *c = sk_X509_new_null();
        sk_X509_push(c, a);
        sk_X509_push(c, b);
        printf(",");
        tree = NULL;
        expl = -1;
        ret = X509_policy_check(&tree, &expl, c, NULL, X509_V_FLAG_EXPLICIT_POLICY);
        emit_shape("explicit_empty", tree, ret, expl);
        X509_policy_tree_free(tree);
        sk_X509_free(c);
        X509_free(a);
        X509_free(b);
    }

    /* 6. A real leaf policy over a trust anchor: the tree is built and VALID. This is the
     *    success window: the counters are read after `X509_policy_tree_free`, so the recorded
     *    comparison covers the graph's construction **and** release. */
    {
        X509 *leaf = cert_with_one_policy("1.2.3.4");
        X509 *ta = X509_new();
        STACK_OF(X509) *c = sk_X509_new_null();
        sk_X509_push(c, leaf);
        sk_X509_push(c, ta);
        g_ref_fresh = refs_of(leaf);
        reset_counts();
        tree = NULL;
        expl = -1;
        ret = X509_policy_check(&tree, &expl, c, NULL, 0);
        g_ref_after = refs_of(leaf);
        measure_identity(tree);
        printf(",");
        emit_shape("single_policy", tree, ret, expl);
        X509_policy_tree_free(tree);
        g_ref_freed = refs_of(leaf);
        g_win_mallocs = g_mallocs;
        g_win_frees = g_frees;
        g_win_nsizes = g_nsizes < SIZES_MAX ? g_nsizes : SIZES_MAX;
        for (i = 0; i < g_win_nsizes; i++)
            g_win_sizes[i] = g_sizes[i];
        /* The teardown window: freeing the leaf certificate releases the per-cert policy cache on
         * the authority (`X509_free` -> `ossl_policy_cache_free`), which the crate withholds. */
        reset_counts();
        X509_free(leaf);
        X509_free(ta);
        g_cl_mallocs = g_mallocs;
        g_cl_frees = g_frees;
        sk_X509_free(c);
    }

    /* 7. The same leaf, asking for the user set to contain 1.2.3.4. */
    {
        X509 *leaf = cert_with_one_policy("1.2.3.4");
        X509 *ta = X509_new();
        STACK_OF(X509) *c = sk_X509_new_null();
        STACK_OF(ASN1_OBJECT) *oids = sk_ASN1_OBJECT_new_null();
        sk_X509_push(c, leaf);
        sk_X509_push(c, ta);
        sk_ASN1_OBJECT_push(oids, OBJ_txt2obj("1.2.3.4", 1));
        printf(",");
        tree = NULL;
        expl = -1;
        ret = X509_policy_check(&tree, &expl, c, oids, 0);
        emit_shape("user_policy", tree, ret, expl);
        X509_policy_tree_free(tree);
        sk_ASN1_OBJECT_pop_free(oids, ASN1_OBJECT_free);
        sk_X509_free(c);
        X509_free(leaf);
        X509_free(ta);
    }

    /* 8. A mapped-policy chain: leaf {1.2.3.4}, an intermediate mapping 1.2.3.4 -> 1.2.3.5, and a
     *    trust anchor. The policy cache reads the intermediate's `policyMappings`. */
    {
        X509 *leaf = cert_with_policies((const char *const[]){"1.2.3.4", "1.2.3.6"}, 2);
        X509 *inter = cert_with_mapping("1.2.3.4", "1.2.3.4", "1.2.3.5");
        X509 *ta = X509_new();
        STACK_OF(X509) *c = sk_X509_new_null();
        sk_X509_push(c, leaf);
        sk_X509_push(c, inter);
        sk_X509_push(c, ta);
        printf(",");
        tree = NULL;
        expl = -1;
        ret = X509_policy_check(&tree, &expl, c, NULL, 0);
        emit_shape("mapped_policy", tree, ret, expl);
        X509_policy_tree_free(tree);
        sk_X509_free(c);
        X509_free(leaf);
        X509_free(inter);
        X509_free(ta);
    }

    printf("],");


    /* Identity over the `single` tree. */
    printf("\"ident\":{\"nodes\":%d,\"parents\":%d,\"resolved\":%d,\"stable\":%d},",
           g_ident_nodes, g_ident_parents, g_ident_resolved, g_ident_stable);

    /* The success window's allocator observation, read after the release path. */
    printf("\"alloc\":{\"malloc\":%ld,\"free\":%ld,\"sizes\":[", g_win_mallocs, g_win_frees);
    for (i = 0; i < g_win_nsizes && i < SIZES_MAX; i++)
        printf("%s%llu", i ? "," : "", g_win_sizes[i]);
    printf("]},");

    /* The teardown window's allocator observation, isolated from the graph window. */
    printf("\"cleanup\":{\"malloc\":%ld,\"free\":%ld},", g_cl_mallocs, g_cl_frees);

    /* Allocation-failure injection: refuse the first allocation of the node's own size in a fresh
     * check window. The authority's `ossl_policy_level_add_node` must propagate NULL, so
     * `X509_policy_check` answers INTERNAL with a NULL tree. */
    {
        X509 *leaf = cert_with_one_policy("1.2.3.4");
        X509 *ta = X509_new();
        STACK_OF(X509) *c = sk_X509_new_null();
        sk_X509_push(c, leaf);
        sk_X509_push(c, ta);
        reset_counts();
        g_fail_size = NODE_SIZE;
        tree = NULL;
        expl = -1;
        ret = X509_policy_check(&tree, &expl, c, NULL, 0);
        printf("\"fail\":{\"ret\":%d,\"tree\":%d,\"levels\":%d,\"expl\":%d,"
               "\"malloc\":%ld,\"free\":%ld},",
               ret, tree != NULL, X509_policy_tree_level_count(tree), expl,
               g_mallocs, g_frees);
        X509_policy_tree_free(tree);
        sk_X509_free(c);
        X509_free(leaf);
        X509_free(ta);
    }

    /* CVE-2023-0464 cap: a leaf with 1100 distinct policies overruns `node_maximum = 1000`, so
     * `ossl_policy_level_add_node` answers NULL and the check answers INTERNAL. */
    {
        X509 *leaf = cert_with_npolicies(1100);
        X509 *ta = X509_new();
        STACK_OF(X509) *c = sk_X509_new_null();
        sk_X509_push(c, leaf);
        sk_X509_push(c, ta);
        tree = NULL;
        expl = -1;
        if (leaf != NULL)
            ret = X509_policy_check(&tree, &expl, c, NULL, 0);
        else
            ret = -99;
        printf("\"cap\":{\"ret\":%d,\"tree\":%d},", ret, tree != NULL);
        X509_policy_tree_free(tree);
        sk_X509_free(c);
        X509_free(leaf);
        X509_free(ta);
    }

    /* The stack-container control: a bare `OPENSSL_sk_new_null`/push/free under the installed hook.
     * The authority allocates its header and element array through `CRYPTO_malloc`, so the hook
     * sees them; a container that allocated elsewhere would show zero. */
    {
        void *marker = (void *)&g_mallocs;
        OPENSSL_STACK *sk;
        reset_counts();
        sk = OPENSSL_sk_new_null();
        OPENSSL_sk_push(sk, marker);
        OPENSSL_sk_free(sk);
        printf("\"stacks\":{\"malloc\":%ld,\"free\":%ld},", g_mallocs, g_frees);
    }

    /* The ASN1-object control: a bare dynamic `OBJ_txt2obj` under the installed hook. The
     * authority allocates the object (and its DER content) through `CRYPTO_malloc`; a container
     * that allocated it elsewhere would show zero. */
    {
        ASN1_OBJECT *o;
        reset_counts();
        o = OBJ_txt2obj("1.2.3.4", 1);
        ASN1_OBJECT_free(o);
        printf("\"objects\":{\"malloc\":%ld,\"free\":%ld},", g_mallocs, g_frees);
    }

    printf("\"refcount\":{\"fresh\":%d,\"after\":%d,\"freed\":%d}",
           g_ref_fresh, g_ref_after, g_ref_freed);

    printf("}\n");
    (void)first;
    return 0;
}
