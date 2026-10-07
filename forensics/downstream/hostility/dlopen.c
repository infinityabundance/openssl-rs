/*
 * 24.10 hostility probe: **dlopen** — the probe links *no* OpenSSL at build time; it takes the
 * subject library's path as `argv[1]`, `dlopen`s it at runtime, and resolves an algorithm fetch and
 * the version accessor through `dlsym`. The loaded path is read back with `dladdr`, which is the
 * enabled-path proof that the runtime loader — not the link line — bound this subject.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>

typedef const char *(*version_fn)(int);
typedef void *(*md_fetch_fn)(void *, const char *, const char *);
typedef const char *(*md_name_fn)(const void *);
typedef void (*md_free_fn)(void *);
typedef void *(*prov_load_ex_fn)(void *, const char *, void *);

int main(int argc, char **argv)
{
    if (argc < 2) {
        printf("surface=dlopen\nresult=failed\nreason=no-library-path\n");
        return 1;
    }
    const char *path = argv[1];
    printf("surface=dlopen\n");
    printf("dlopen_requested=%s\n", path);

    void *h = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (h == NULL) {
        printf("result=failed\n");
        printf("reason=%s\n", dlerror());
        return 1;
    }
    version_fn version = (version_fn)dlsym(h, "OpenSSL_version");
    md_fetch_fn fetch = (md_fetch_fn)dlsym(h, "EVP_MD_fetch");
    md_name_fn name_get = (md_name_fn)dlsym(h, "EVP_MD_get0_name");
    md_free_fn md_free = (md_free_fn)dlsym(h, "EVP_MD_free");
    prov_load_ex_fn prov_load = (prov_load_ex_fn)dlsym(h, "OSSL_PROVIDER_load_ex");
    if (version == NULL || fetch == NULL || name_get == NULL || md_free == NULL) {
        printf("result=failed\nreason=missing-symbol\n");
        return 1;
    }
    printf("openssl_runtime_version=%s\n", version(0));

    Dl_info info;
    if (dladdr((void *)version, &info) != 0 && info.dli_fname != NULL)
        printf("dlopen_lib=%s\n", info.dli_fname);

    void *md = fetch(NULL, "SHA2-256", NULL);
    if (md == NULL) {
        printf("result=failed\nreason=EVP_MD_fetch\n");
        return 1;
    }
    printf("fetched_md=%s\n", name_get(md));
    md_free(md);
    printf("provider_loaded=%d\n", prov_load != NULL && prov_load(NULL, "default", NULL) != NULL);
    dlclose(h);
    printf("result=ok\n");
    return 0;
}
