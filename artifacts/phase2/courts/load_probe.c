
/* Demand-loads the candidate DSO and resolves versioned symbols by *version*,
 * which is the check that matters: an application expecting an
 * OPENSSL_3.x.y-versioned symbol must not bind to an unversioned substitute. */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

static const char *symbols[] = {
    "EVP_DigestInit_ex", "EVP_CipherInit_ex", "EVP_PKEY_new", "X509_new",
    "CRYPTO_secure_calloc", "OSSL_PROVIDER_load",
};

int main(int argc, char **argv) {
    if (argc < 4) { fprintf(stderr, "usage: probe <dso> <version> <fail-count>\n"); return 2; }
    void *h = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!h) { fprintf(stderr, "dlopen failed: %s\n", dlerror()); return 1; }
    unsigned ok = 0, bad = 0;
    for (unsigned i = 0; i < sizeof(symbols) / sizeof(symbols[0]); i++) {
        void *p = dlvsym(h, symbols[i], argv[2]);
        if (p) ok++; else { bad++; printf("  unresolved %s@%s\n", symbols[i], argv[2]); }
    }
    printf("load-probe: %u resolved, %u unresolved at version %s\n", ok, bad, argv[2]);
    dlclose(h);
    return bad == (unsigned)atoi(argv[3]) ? 0 : 3;
}
