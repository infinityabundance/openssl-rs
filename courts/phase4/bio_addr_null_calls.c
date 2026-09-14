/*
 * openssl-rs — court-only archaeology: which null-argument BIO_ADDR calls fault
 * in the authority? One call per process (selected by argv[1]) so a fault is
 * attributable to exactly one call. This is the evidence behind the recorded
 * safety divergences in docs/SECURITY_DIVERGENCE_POLICY.md.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <openssl/bio.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
    unsigned char buf[16];
    size_t len = 16;

    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc != 2) {
        fprintf(stderr, "usage: %s <case>\n", argv[0]);
        return 2;
    }

    printf("case=%s\n", argv[1]);
    if (strcmp(argv[1], "free") == 0)
        BIO_ADDR_free(NULL);
    else if (strcmp(argv[1], "clear") == 0)
        BIO_ADDR_clear(NULL);
    else if (strcmp(argv[1], "dup") == 0)
        printf("ret=%p\n", (void *)BIO_ADDR_dup(NULL));
    else if (strcmp(argv[1], "rawaddress") == 0)
        printf("ret=%d\n", BIO_ADDR_rawaddress(NULL, buf, &len));
    else if (strcmp(argv[1], "rawport") == 0)
        printf("ret=%u\n", (unsigned)BIO_ADDR_rawport(NULL));
    else if (strcmp(argv[1], "family") == 0)
        printf("ret=%d\n", BIO_ADDR_family(NULL));
    else if (strcmp(argv[1], "hostname") == 0)
        printf("ret=%p\n", (void *)BIO_ADDR_hostname_string(NULL, 1));
    else if (strcmp(argv[1], "service") == 0)
        printf("ret=%p\n", (void *)BIO_ADDR_service_string(NULL, 1));
    else if (strcmp(argv[1], "path") == 0)
        printf("ret=%p\n", (void *)BIO_ADDR_path_string(NULL));
    else if (strcmp(argv[1], "copy") == 0)
        printf("ret=%d\n", BIO_ADDR_copy(NULL, NULL));
    else if (strcmp(argv[1], "ainfo-next") == 0)
        printf("ret=%p\n", (void *)BIO_ADDRINFO_next(NULL));
    else
        return 2;

    printf("survived %s\n", argv[1]);
    return 0;
}
