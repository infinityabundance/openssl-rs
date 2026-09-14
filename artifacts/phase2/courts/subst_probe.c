
/* Trivial external consumer: compiled against the header shell, linked against
 * the candidate DSO. It takes addresses of versioned symbols (forcing link-time
 * resolution) but CALLS none of them, because every shell symbol is scaffolded
 * and aborts on call. The point of Phase 2 is build+load, not execution. */
#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>

int main(void) {
    const void *probe[] = {
        (const void *)&EVP_DigestInit_ex,
        (const void *)&EVP_CipherInit_ex,
        (const void *)&EVP_PKEY_new,
        (const void *)&X509_new,
        (const void *)&SSL_CTX_new,
        (const void *)&SSL_new,
    };
    unsigned nonzero = 0;
    for (unsigned i = 0; i < sizeof(probe) / sizeof(probe[0]); i++)
        if (probe[i]) nonzero++;
    printf("link-probe: %u/%zu versioned symbols resolved by the dynamic linker\n",
           nonzero, sizeof(probe) / sizeof(probe[0]));
    return 0;
}
