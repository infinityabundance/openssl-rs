/*
 * openssl-rs — discovery probe 3: compare the ADDR built by BIO_ADDR_rawmake with
 * the ADDR inside a BIO_lookup result, byte for byte and string for string.
 *
 * A rawmake address with port 8080 reports service_string = "36895" (byte-swapped)
 * while a lookup address for port 80 reported "80" (not swapped). One of the two is
 * inconsistent with a single model, so this measures both the raw storage and every
 * accessor on both.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

static void dump_addr(const char *prefix, const BIO_ADDR *a)
{
    unsigned char raw[32];
    size_t len = sizeof(raw);
    char key[96];
    char hexbuf[80];
    char *s;
    size_t i;
    int r;

    if (a == NULL) {
        printf("%s=<NULL ADDR>\n", prefix);
        return;
    }
    printf("%s.family=%d\n", prefix, BIO_ADDR_family(a));
    printf("%s.rawport=%u\n", prefix, (unsigned)BIO_ADDR_rawport(a));

    memset(raw, 0, sizeof(raw));
    r = BIO_ADDR_rawaddress(a, raw, &len);
    hexbuf[0] = '\0';
    for (i = 0; i < len && i * 2 + 2 < sizeof(hexbuf); i++)
        sprintf(hexbuf + i * 2, "%02x", raw[i]);
    printf("%s.rawaddress.ret=%d\n", prefix, r);
    printf("%s.rawaddress.len=%zu\n", prefix, len);
    printf("%s.rawaddress.bytes=%s\n", prefix, hexbuf);

    sprintf(key, "%s.hostname", prefix);
    s = BIO_ADDR_hostname_string(a, 1);
    printf("%s=%s\n", key, s ? s : "<NULL>");
    OPENSSL_free(s);

    sprintf(key, "%s.service.numeric", prefix);
    s = BIO_ADDR_service_string(a, 1);
    printf("%s=%s\n", key, s ? s : "<NULL>");
    OPENSSL_free(s);

    sprintf(key, "%s.service.named", prefix);
    s = BIO_ADDR_service_string(a, 0);
    printf("%s=%s\n", key, s ? s : "<NULL>");
    OPENSSL_free(s);

    sprintf(key, "%s.path", prefix);
    s = BIO_ADDR_path_string(a);
    printf("%s=%s\n", key, s ? s : "<NULL>");
    OPENSSL_free(s);
}

int main(void)
{
    BIO_ADDRINFO *res = NULL;
    BIO_ADDR *made;
    struct in_addr in;

    setvbuf(stdout, NULL, _IONBF, 0);

    /* 1. An address built by rawmake. */
    made = BIO_ADDR_new();
    inet_pton(AF_INET, "127.0.0.1", &in);
    BIO_ADDR_rawmake(made, AF_INET, &in, sizeof(in), 8080);
    printf("--- rawmake(127.0.0.1, 8080) ---\n");
    dump_addr("made", made);
    BIO_ADDR_free(made);

    /* 2. An address built the same way but with port 80, for the comparison. */
    made = BIO_ADDR_new();
    BIO_ADDR_rawmake(made, AF_INET, &in, sizeof(in), 80);
    printf("--- rawmake(127.0.0.1, 80) ---\n");
    dump_addr("made80", made);
    BIO_ADDR_free(made);

    /* 3. The address inside a lookup result, same port as (1). */
    if (BIO_lookup("127.0.0.1", "8080", BIO_LOOKUP_CLIENT, AF_INET, SOCK_STREAM, &res) == 1) {
        printf("--- lookup(127.0.0.1, 8080) ---\n");
        printf("lookup8080.count.chain=%d\n", BIO_ADDRINFO_next(res) != NULL);
        dump_addr("lookup8080", BIO_ADDRINFO_address(res));
        printf("lookup8080.socktype=%d\n", BIO_ADDRINFO_socktype(res));
        printf("lookup8080.protocol=%d\n", BIO_ADDRINFO_protocol(res));
    } else {
        printf("lookup8080.ret=0\n");
    }
    BIO_ADDRINFO_free(res);
    res = NULL;

    /* 4. And the same port through a lookup, to confirm the model. */
    if (BIO_lookup("127.0.0.1", "80", BIO_LOOKUP_CLIENT, AF_INET, SOCK_STREAM, &res) == 1) {
        printf("--- lookup(127.0.0.1, 80) ---\n");
        dump_addr("lookup80", BIO_ADDRINFO_address(res));
    } else {
        printf("lookup80.ret=0\n");
    }
    BIO_ADDRINFO_free(res);
    res = NULL;

    /* 5. IPv6, to see whether the family changes anything. */
    if (BIO_lookup("::1", "443", BIO_LOOKUP_CLIENT, AF_INET6, SOCK_STREAM, &res) == 1) {
        printf("--- lookup(::1, 443) ---\n");
        dump_addr("lookup6", BIO_ADDRINFO_address(res));
    } else {
        printf("lookup6.ret=0\n");
    }
    BIO_ADDRINFO_free(res);

    return 0;
}
