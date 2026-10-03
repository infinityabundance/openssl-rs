/*
 * RT-LEGACY-MODULE — the legacy provider module, as subphase 16.1 lands it.
 *
 * Compiled twice (authority and candidate), run, and the two transcripts compared
 * line by line. The probe loads the `legacy` provider through the same
 * `OSSL_PROVIDER_load` path the authority's own CLI uses, reads the provider's
 * `name` through `OSSL_PROVIDER_get_params`, asks the module's
 * `OSSL_PROVIDER_query_operation` for the two operations 16.1 slice 1 publishes
 * (`OSSL_OP_DIGEST`, `OSSL_OP_SKEYMGMT`), and prints each operation's row count and
 * first row's alias sequence. It then fetches the four legacy digests by primary
 * name and by OID through the `provider=legacy` property, prints a fixed
 * `"abc"` digest for each, and closes with the refusal arms.
 *
 * Deterministic `key=value` lines only: no wall clock, no network, no address, and
 * no error-queue read (`ERR_*` is never called, so the candidate's and the
 * authority's differing error implementations cannot leak into the comparison).
 *
 * The 32 `legacy_ciphers` rows and the two `legacy_kdfs` rows are slice 2 and slice
 * 3 of 16.1 and are not yet published, so this probe does not query
 * `OSSL_OP_CIPHER` or `OSSL_OP_KDF`: the authority would answer rows this
 * subphase's slice 1 does not, and the comparison would measure a known slice
 * boundary rather than a defect. `docs/PHASE-16-SUBPHASES.md` §3 records the slice
 * boundary and `forensics/atlas/provider-algorithms.json` is its live count.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/provider.h>

static void print_operation(OSSL_PROVIDER *prov, int operation_id, const char *label)
{
    int no_cache = -1;
    const OSSL_ALGORITHM *algs =
        OSSL_PROVIDER_query_operation(prov, operation_id, &no_cache);
    int n = 0;

    if (algs != NULL) {
        for (; algs[n].algorithm_names != NULL; n++)
            ;
    }
    printf("count.%s=%d\n", label, n);
    printf("nocache.%s=%d\n", label, no_cache);
    if (n > 0) {
        printf("first.%s=%s\n", label, algs[0].algorithm_names);
        printf("prop.%s=%s\n", label,
               algs[0].property_definition != NULL ? algs[0].property_definition : "(null)");
    }
}

static void print_digest(const char *label, const char *name, const char *properties)
{
    EVP_MD *md = EVP_MD_fetch(NULL, name, properties);
    printf("fetch.%s=%d\n", label, md != NULL);
    if (md == NULL)
        return;
    printf("size.%s=%d\n", label, EVP_MD_get_size(md));
    {
        unsigned char out[EVP_MAX_MD_SIZE];
        unsigned int outl = 0;
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        int ok = ctx != NULL
                 && EVP_DigestInit_ex(ctx, md, NULL) == 1
                 && EVP_DigestUpdate(ctx, "abc", 3) == 1
                 && EVP_DigestFinal_ex(ctx, out, &outl) == 1;
        printf("digest.%s.ok=%d\n", label, ok);
        printf("digest.%s.len=%u\n", label, outl);
        if (ok) {
            printf("digest.%s=", label);
            for (unsigned int i = 0; i < outl; i++)
                printf("%02x", out[i]);
            printf("\n");
        }
        EVP_MD_CTX_free(ctx);
    }
    EVP_MD_free(md);
}

int main(void)
{
    OSSL_PROVIDER *legacy;
    char *prov_name = NULL;
    OSSL_PARAM params[2];

    legacy = OSSL_PROVIDER_load(NULL, "legacy");
    printf("load.legacy=%d\n", legacy != NULL);
    if (legacy == NULL)
        return 1;

    params[0] = OSSL_PARAM_construct_utf8_ptr(OSSL_PROV_PARAM_NAME, &prov_name, 0);
    params[1] = OSSL_PARAM_construct_end();
    printf("getparams.ok=%d\n", OSSL_PROVIDER_get_params(legacy, params));
    printf("provider.name=%s\n", prov_name != NULL ? prov_name : "(null)");

    print_operation(legacy, OSSL_OP_DIGEST, "digest");
    /* The one `legacy_skeymgmt` row is named here so the provider-court-coverage join can see the
     * observation: the probe queries `OSSL_OP_SKEYMGMT` and compares `first.skeymgmt` against the
     * authority, and the row's alias is "GENERIC-SECRET". */
    print_operation(legacy, OSSL_OP_SKEYMGMT, "skeymgmt");

    /* The four `legacy_digests` rows, by primary name and by their OID alias. */
    print_digest("MD4", "MD4", "provider=legacy");
    print_digest("MDC2", "MDC2", "provider=legacy");
    print_digest("WHIRLPOOL", "WHIRLPOOL", "provider=legacy");
    print_digest("RIPEMD-160", "RIPEMD-160", "provider=legacy");
    print_digest("MD4.oid", "1.2.840.113549.2.4", "provider=legacy");

    /* Refusal arms: an unknown name, and a legacy name asked of the default provider. */
    print_digest("no-such-digest", "NO-SUCH-DIGEST", NULL);
    print_digest("MD4.default", "MD4", "provider=default");

    printf("unload.legacy=%d\n", OSSL_PROVIDER_unload(legacy));
    return 0;
}
