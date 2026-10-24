#include <stdio.h>
#include <openssl/crypto.h>
#include <openssl/opensslv.h>
#include <openssl/provider.h>
#include <openssl/evp.h>

int main(void)
{
    const char *dir = OPENSSL_info(OPENSSL_INFO_MODULES_DIR);
    OSSL_PROVIDER *def = OSSL_PROVIDER_load(NULL, "default");
    OSSL_PROVIDER *leg = OSSL_PROVIDER_load(NULL, "legacy");
    EVP_MD *md;
    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    unsigned int i;

    printf("version=%s\n", OpenSSL_version(OPENSSL_VERSION));
    printf("modulesdir=%s\n", dir ? dir : "(null)");
    printf("default=%s\n", def ? "loaded" : "NULL");
    printf("legacy=%s\n", leg ? "loaded" : "NULL");
    md = EVP_MD_fetch(NULL, "MD4", "provider=legacy");
    printf("fetch_md4=%s\n", md ? "ok" : "NULL");
    if (md == NULL)
        return 1;
    if (!EVP_Digest("abc", 3, out, &len, md, NULL)) {
        printf("digest=fail\n");
        return 1;
    }
    printf("md4_abc=");
    for (i = 0; i < len; i++)
        printf("%02x", out[i]);
    printf("\n");
    return 0;
}
