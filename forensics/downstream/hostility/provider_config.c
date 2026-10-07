/*
 * 24.10 hostility probe: **provider registration / configuration** — loading the default provider,
 * testing availability, loading the legacy provider, and fetching an algorithm through the fetched
 * provider plumbing. The candidate's provider configuration surface differs from the authority's, so
 * the probe records what actually loaded rather than assuming the provider set.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "hostility_common.h"
#include <openssl/provider.h>

int main(void)
{
    hostility_banner("provider-config");

    OSSL_PROVIDER *def = OSSL_PROVIDER_load(NULL, "default");
    if (def == NULL)
        hostility_fail("OSSL_PROVIDER_load default");
    const char *name = OSSL_PROVIDER_get0_name(def);
    printf("default_provider=%s\n", name != NULL ? name : "(null)");
    printf("default_available=%d\n", OSSL_PROVIDER_available(NULL, "default"));

    OSSL_PROVIDER *leg = OSSL_PROVIDER_try_load(NULL, "legacy", 1);
    printf("legacy_loaded=%d\n", leg != NULL);
    printf("legacy_available=%d\n", OSSL_PROVIDER_available(NULL, "legacy"));

    EVP_MD *md = EVP_MD_fetch(NULL, "SHA2-256", NULL);
    if (md == NULL)
        hostility_fail("EVP_MD_fetch SHA2-256");
    printf("fetched_md=%s\n", EVP_MD_get0_name(md));
    EVP_MD_free(md);

    if (leg != NULL)
        OSSL_PROVIDER_unload(leg);
    OSSL_PROVIDER_unload(def);
    hostility_ok();
    return 0;
}
