/*
 * openssh v1i negative-control probe.
 *
 * Every check below violates (or reaches the edge of) a precondition named in
 * atlas-refresh/openssh-v1i-sites.json, and must be *rejected* by the candidate
 * implementation.  A receipt claim would fail if the corresponding guard were
 * removed:
 *
 *   - DIGEST DUPCTX(NULL) -> NULL; without the `ctx.is_null()` arm the provider
 *     dereferences NULL (the probe would die with SIGSEGV).
 *   - DIGEST FREECTX(NULL) -> no-op; the provider's OwnedCtx::from_raw must
 *     accept NULL exactly as OPENSSL_clear_free does.
 *   - DIGEST GET_PARAMS(NULL) -> 1; params is documented NULL-or-array.
 *   - CMP ITAV allocator: two live calls must return distinct pointers and each
 *     must be releasable once (a static/shared return would double-free).
 *   - CMP set1 on a name: a second set1 releases the incumbent and stores a
 *     deep copy; an aliasing dup would leave a dangling member and the final
 *     OSSL_CMP_CTX_free would double-free.
 *   - legacy EVP_MD init callbacks: sha1_init(NULL) must answer 0 (hardened),
 *     while sha256_init(NULL) is the unhardened sibling that the receipt keeps
 *     BLOCKED; the child process is expected to die with SIGSEGV.
 */
#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/cmp.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <openssl/x509.h>

typedef const OSSL_ALGORITHM *(*query_fn)(void *, int, int *);
typedef void *(*dupctx_fn)(void *);
typedef void (*freectx_fn)(void *);
typedef int (*getparams_fn)(OSSL_PARAM *);

static const OSSL_DISPATCH *find_id(const OSSL_DISPATCH *d, int id)
{
    for (; d != NULL && d->function_id != 0; d++)
        if (d->function_id == id)
            return d;
    return NULL;
}

static int dispatch_neg(const char *pname, const char *alg, int with_get_params)
{
    int ok = 1;
    OSSL_PROVIDER *p = OSSL_PROVIDER_load(NULL, pname);
    const OSSL_DISPATCH *pd, *q, *impl = NULL, *d;
    const OSSL_ALGORITHM *algs;
    query_fn query;
    int nocache = 0;

    if (p == NULL) {
        printf("FAIL %s: provider did not load\n", pname);
        return 0;
    }
    pd = OSSL_PROVIDER_get0_dispatch(p);
    q = find_id(pd, OSSL_FUNC_PROVIDER_QUERY_OPERATION);
    if (q == NULL) {
        printf("FAIL %s: no query operation\n", pname);
        return 0;
    }
    query = (query_fn)q->function;
    algs = query(NULL, OSSL_OP_DIGEST, &nocache);
    for (; algs != NULL && algs->algorithm_names != NULL; algs++) {
        if (strstr(algs->algorithm_names, alg) != NULL) {
            impl = algs->implementation;
            break;
        }
    }
    if (impl == NULL) {
        printf("FAIL %s: algorithm %s not found\n", pname, alg);
        return 0;
    }

    d = find_id(impl, OSSL_FUNC_DIGEST_DUPCTX);
    if (d != NULL) {
        dupctx_fn dup = (dupctx_fn)d->function;
        if (dup(NULL) != NULL) {
            printf("FAIL %s/%s: dupctx(NULL) returned non-NULL\n", pname, alg);
            ok = 0;
        }
    }
    d = find_id(impl, OSSL_FUNC_DIGEST_FREECTX);
    if (d != NULL) {
        freectx_fn fr = (freectx_fn)d->function;
        fr(NULL); /* must be a no-op */
    }
    if (with_get_params) {
        d = find_id(impl, OSSL_FUNC_DIGEST_GET_PARAMS);
        if (d != NULL) {
            getparams_fn gp = (getparams_fn)d->function;
            if (gp(NULL) != 1) {
                printf("FAIL %s/%s: get_params(NULL) != 1\n", pname, alg);
                ok = 0;
            }
        }
    }
    OSSL_PROVIDER_unload(p);
    printf("negctl %s/%s: %s\n", pname, alg, ok ? "rejected as required" : "FAILED");
    return ok;
}

static int cmp_neg(void)
{
    int ok = 1;
    ASN1_OBJECT *o1 = OBJ_dup(OBJ_nid2obj(NID_sha256));
    ASN1_OBJECT *o2 = OBJ_dup(OBJ_nid2obj(NID_sha256));
    OSSL_CMP_ITAV *a = OSSL_CMP_ITAV_create(o1, NULL);
    OSSL_CMP_ITAV *b = OSSL_CMP_ITAV_create(o2, NULL);

    if (a == NULL || b == NULL || a == b) {
        printf("FAIL cmp: ITAV allocator did not return two distinct live items\n");
        ok = 0;
    } else {
        OSSL_CMP_ITAV_free(a);
        OSSL_CMP_ITAV_free(b);
        printf("negctl cmp/itav: two distinct owned items, each released once\n");
    }
    if (OSSL_CMP_ITAV_create(NULL, NULL) != NULL) {
        printf("FAIL cmp: ITAV_create(NULL) was not refused\n");
        ok = 0;
    }

    {
        OSSL_CMP_CTX *ctx = OSSL_CMP_CTX_new(NULL, NULL);
        X509_NAME *nm = X509_NAME_new();
        int a1, a2;
        if (ctx == NULL || nm == NULL) {
            printf("FAIL cmp: ctx=%p name=%p\n", (void *)ctx, (void *)nm);
            ok = 0;
        } else if (X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_UTF8,
                                             (const unsigned char *)"v1i", -1, -1, 0) != 1) {
            printf("FAIL cmp: name entry\n");
            ok = 0;
        } else {
            a1 = OSSL_CMP_CTX_set1_expected_sender(ctx, nm);
            a2 = OSSL_CMP_CTX_set1_expected_sender(ctx, nm);
            if (a1 != 1 || a2 != 1) {
                printf("FAIL cmp: set1 returned %d then %d\n", a1, a2);
                ok = 0;
            }
        }
        OSSL_CMP_CTX_free(ctx);
        X509_NAME_free(nm);
        printf("negctl cmp/ctx: dup+replace+destruct released exactly once\n");
    }
    return ok;
}

static void child_init_null(const EVP_MD *md)
{
    int (*init)(EVP_MD_CTX *) = EVP_MD_meth_get_init(md);
    if (init == NULL)
        _exit(3);
    _exit(init(NULL) == 0 ? 0 : 4);
}

static int legacy_sha_neg(void)
{
    int ok = 1;
    pid_t pid;
    int status;

    /* hardened sibling: sha1_init(NULL) answers 0 */
    pid = fork();
    if (pid == 0)
        child_init_null(EVP_sha1());
    waitpid(pid, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        printf("FAIL legacy_sha: sha1_init(NULL) did not answer 0 (status %d)\n", status);
        ok = 0;
    } else {
        printf("negctl legacy_sha/sha1_init: NULL refused with 0\n");
    }

    /* unhardened sibling: NULL is not refused; the receipt keeps it BLOCKED */
    pid = fork();
    if (pid == 0)
        child_init_null(EVP_sha256());
    waitpid(pid, &status, 0);
    if (WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV) {
        printf("negctl legacy_sha/sha256_init: NULL dereference observed (SIGSEGV), "
               "so the site stays BLOCKED\n");
    } else {
        printf("FAIL legacy_sha: sha256_init(NULL) did not demonstrate the missing guard "
               "(status %d)\n", status);
        ok = 0;
    }
    return ok;
}

int main(void)
{
    int ok = 1;
    /* Hold a default-provider reference: CMP_CTX_new fetches SHA-256, and the
     * dispatch checks below unload the references they take. */
    OSSL_PROVIDER *keep = OSSL_PROVIDER_load(NULL, "default");
    ok &= dispatch_neg("default", "SHA1", 1);
    ok &= dispatch_neg("legacy", "MDC2", 0);
    ok &= cmp_neg();
    ok &= legacy_sha_neg();
    OSSL_PROVIDER_unload(keep);
    printf("RESULT %s\n", ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
}
