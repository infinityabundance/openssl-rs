/*
 * l7_strongswan.c — the admitted strongSwan workload harness.
 *
 * strongSwan's `pki` binary links libstrongswan dynamically and reaches OpenSSL through
 * the `openssl` crypto plugin, which is itself a shared object.  The runtime atlas's
 * L5 load proof is taken over the admitted program's own ldd resolution, so the
 * workload is entered through this small harness: it links the subject's libcrypto
 * directly (giving the loader a libcrypto soname to resolve and the LD_DEBUG pass a
 * library to initialise) and then execs `pki`, whose transcript shows the `openssl`
 * plugin loaded.  No crypto operation is performed by the harness itself.
 */
#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    const char *version = OpenSSL_version(OPENSSL_VERSION);
    const char *pki = getenv("S36_PKI");

    if (argc == 1 || (argc == 2 && (strcmp(argv[1], "--version") == 0 ||
                                    strcmp(argv[1], "-v") == 0))) {
        printf("strongswan-l7-harness %s\n", version);
        return 0;
    }
    if (!pki) {
        fprintf(stderr, "strongswan-l7-harness: S36_PKI is not set\n");
        return 127;
    }
    execv(pki, argv);
    perror("strongswan-l7-harness: execv");
    return 127;
}
