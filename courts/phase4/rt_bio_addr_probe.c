/*
 * openssl-rs — RT-BIO-ADDR: differential probe for BIO_ADDR.
 *
 * Compiled twice, against the authority and against the candidate, and the two
 * transcripts are compared line by line (`forensics/tools/phase4_courts.py`).
 * Every observation is one `key=value` line.
 *
 * Deliberately NOT probed: the null-argument calls the authority faults on
 * (`BIO_ADDR_clear`, `BIO_ADDR_rawaddress`, `BIO_ADDR_rawport`, `BIO_ADDR_family`,
 * `BIO_ADDR_hostname_string`, `BIO_ADDR_service_string`, `BIO_ADDR_path_string`).
 * A probe cannot compare a crash, and the candidate's total behaviour there is a
 * recorded safety divergence, not parity. The evidence that those calls fault -- one
 * call per process -- is `courts/phase4/bio_addr_null_calls.c`.
 *
 * The null-argument calls the authority *does* define (`BIO_ADDR_free`,
 * `BIO_ADDR_dup`, `BIO_ADDR_copy`) are probed, because those must match exactly.
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
#include <sys/un.h>

static void hex(const unsigned char *p, size_t n, char *out, size_t outlen)
{
    size_t i;
    out[0] = '\0';
    for (i = 0; i < n && i * 2 + 2 < outlen; i++)
        sprintf(out + i * 2, "%02x", p[i]);
}

static void str(const char *key, const char *value)
{
    printf("%s=%s\n", key, value == NULL ? "<NULL>" : value);
}

/* Print a hostname/service/path triple for one address. */
static void strings(const char *prefix, const BIO_ADDR *a)
{
    char key[80];
    char *s;

    s = BIO_ADDR_hostname_string(a, 1);
    sprintf(key, "%s.hostname.numeric", prefix);
    str(key, s);
    OPENSSL_free(s);

    s = BIO_ADDR_hostname_string(a, 0);
    sprintf(key, "%s.hostname.named", prefix);
    str(key, s);
    OPENSSL_free(s);

    s = BIO_ADDR_service_string(a, 1);
    sprintf(key, "%s.service.numeric", prefix);
    str(key, s);
    OPENSSL_free(s);

    s = BIO_ADDR_service_string(a, 0);
    sprintf(key, "%s.service.named", prefix);
    str(key, s);
    OPENSSL_free(s);

    s = BIO_ADDR_path_string(a);
    sprintf(key, "%s.path", prefix);
    str(key, s);
    OPENSSL_free(s);
}

int main(void)
{
    char buf[512];
    unsigned char raw[32];
    size_t len;
    int r;

    setvbuf(stdout, NULL, _IONBF, 0);

    /* --- a fresh address is AF_UNSPEC and reports no address ------------ */
    {
        BIO_ADDR *a = BIO_ADDR_new();

        printf("new.nonnull=%d\n", a != NULL);
        printf("new.family=%d\n", BIO_ADDR_family(a));
        printf("new.rawport=%u\n", (unsigned)BIO_ADDR_rawport(a));
        /* Set *l to a sentinel: does a failing rawaddress leave it untouched? */
        len = 12345;
        r = BIO_ADDR_rawaddress(a, raw, &len);
        printf("new.rawaddress.ret=%d\n", r);
        printf("new.rawaddress.len=%zu\n", len);
        strings("new", a);
        BIO_ADDR_free(a);
    }

    /* --- IPv4 ---------------------------------------------------------- */
    {
        BIO_ADDR *a = BIO_ADDR_new();
        struct in_addr in;

        inet_pton(AF_INET, "127.0.0.1", &in);
        printf("v4.rawmake.ret=%d\n", BIO_ADDR_rawmake(a, AF_INET, &in, sizeof(in), 8080));
        printf("v4.family=%d\n", BIO_ADDR_family(a));
        printf("v4.rawport=%u\n", (unsigned)BIO_ADDR_rawport(a));
        memset(raw, 0, sizeof(raw));
        len = sizeof(raw);
        r = BIO_ADDR_rawaddress(a, raw, &len);
        hex(raw, len, buf, sizeof(buf));
        printf("v4.rawaddress.ret=%d\n", r);
        printf("v4.rawaddress.len=%zu\n", len);
        printf("v4.rawaddress.bytes=%s\n", buf);
        strings("v4", a);
        BIO_ADDR_free(a);
    }

    /* --- IPv6 ---------------------------------------------------------- */
    {
        BIO_ADDR *a = BIO_ADDR_new();
        struct in6_addr in6;

        inet_pton(AF_INET6, "::1", &in6);
        printf("v6.rawmake.ret=%d\n", BIO_ADDR_rawmake(a, AF_INET6, &in6, sizeof(in6), 443));
        printf("v6.family=%d\n", BIO_ADDR_family(a));
        printf("v6.rawport=%u\n", (unsigned)BIO_ADDR_rawport(a));
        memset(raw, 0, sizeof(raw));
        len = sizeof(raw);
        r = BIO_ADDR_rawaddress(a, raw, &len);
        hex(raw, len, buf, sizeof(buf));
        printf("v6.rawaddress.ret=%d\n", r);
        printf("v6.rawaddress.len=%zu\n", len);
        printf("v6.rawaddress.bytes=%s\n", buf);
        strings("v6", a);
        BIO_ADDR_free(a);
    }

    /* --- link-local IPv6 scope ----------------------------------------- */
    {
        BIO_ADDR *a = BIO_ADDR_new();
        struct in6_addr in6;

        inet_pton(AF_INET6, "fe80::1", &in6);
        BIO_ADDR_rawmake(a, AF_INET6, &in6, sizeof(in6), 0);
        strings("v6link", a);
        BIO_ADDR_free(a);
    }

    /* --- AF_UNIX ------------------------------------------------------- */
    {
        BIO_ADDR *a = BIO_ADDR_new();
        const char *path = "/tmp/openssl-rs.sock";

        r = BIO_ADDR_rawmake(a, AF_UNIX, path, strlen(path) + 1, 0);
        printf("unix.rawmake.ret=%d\n", r);
        printf("unix.family=%d\n", BIO_ADDR_family(a));
        printf("unix.rawport=%u\n", (unsigned)BIO_ADDR_rawport(a));
        memset(raw, 0, sizeof(raw));
        len = sizeof(raw);
        r = BIO_ADDR_rawaddress(a, raw, &len);
        printf("unix.rawaddress.ret=%d\n", r);
        printf("unix.rawaddress.len=%zu\n", len);
        strings("unix", a);

        /* the path is NUL-terminated in storage, so a shorter wherelen stops there */
        BIO_ADDR_clear(a);
        r = BIO_ADDR_rawmake(a, AF_UNIX, "/tmp/ab", 8, 0);
        printf("unix.partial.ret=%d\n", r);
        printf("unix.partial.len.expect8=%zu\n", len);
        strings("unix.partial", a);
        BIO_ADDR_free(a);
    }

    /* --- rawmake validation, and what a rejection leaves behind --------- */
    {
        BIO_ADDR *a = BIO_ADDR_new();
        struct in_addr in;
        const char *longer_than_sun_path =
            "/tmp/0123456789012345678901234567890123456789012345678901234567890123456789"
            "0123456789012345678901234567890123456789";

        inet_pton(AF_INET, "1.2.3.4", &in);
        printf("validate.short.len=%d\n", BIO_ADDR_rawmake(a, AF_INET, &in, 3, 0));
        printf("validate.long.len=%d\n", BIO_ADDR_rawmake(a, AF_INET, &in, 16, 0));
        printf("validate.unspec=%d\n", BIO_ADDR_rawmake(a, AF_UNSPEC, &in, 4, 0));
        printf("validate.badfamily=%d\n", BIO_ADDR_rawmake(a, 999, &in, 4, 0));
        /*
         * Not probed: BIO_ADDR_rawmake(ap, AF_INET, NULL, 4, 0). The authority
         * validates the length and then dereferences `where`, so it faults; the
         * candidate returns 0. Recorded as a safety divergence, and the fault was
         * measured in its own process by courts/phase4/bio_addr_null_calls.c.
         */
        printf("validate.unix.toolong=%d\n",
               BIO_ADDR_rawmake(a, AF_UNIX, longer_than_sun_path,
                                strlen(longer_than_sun_path) + 1, 0));

        /* a rejection must not disturb what was there */
        BIO_ADDR_rawmake(a, AF_INET, &in, sizeof(in), 1234);
        BIO_ADDR_rawmake(a, AF_UNSPEC, &in, sizeof(in), 4321);
        printf("reject.family=%d\n", BIO_ADDR_family(a));
        printf("reject.rawport=%u\n", (unsigned)BIO_ADDR_rawport(a));

        /* and a successful remaking replaces the family entirely */
        BIO_ADDR_rawmake(a, AF_INET6, &in, 16, 0);
        BIO_ADDR_rawmake(a, AF_INET, &in, sizeof(in), 99);
        printf("remake.family=%d\n", BIO_ADDR_family(a));
        printf("remake.rawport=%u\n", (unsigned)BIO_ADDR_rawport(a));

        BIO_ADDR_free(a);
    }

    /* --- rawaddress out-parameter contract ----------------------------- */
    {
        BIO_ADDR *a = BIO_ADDR_new();
        struct in_addr in;

        inet_pton(AF_INET, "10.0.0.255", &in);
        BIO_ADDR_rawmake(a, AF_INET, &in, sizeof(in), 7);

        len = 1;
        r = BIO_ADDR_rawaddress(a, raw, &len);
        printf("rawaddress.smallbuf.ret=%d\n", r);
        printf("rawaddress.smallbuf.len=%zu\n", len);

        len = 99;
        r = BIO_ADDR_rawaddress(a, NULL, &len);
        printf("rawaddress.nullbuf.ret=%d\n", r);
        printf("rawaddress.nullbuf.len=%zu\n", len);

        r = BIO_ADDR_rawaddress(a, raw, NULL);
        printf("rawaddress.nulllen.ret=%d\n", r);

        BIO_ADDR_free(a);
    }

    /* --- clear / dup / copy -------------------------------------------- */
    {
        BIO_ADDR *a = BIO_ADDR_new();
        BIO_ADDR *dup;
        BIO_ADDR *copy;
        struct in_addr in;

        inet_pton(AF_INET, "192.0.2.7", &in);
        BIO_ADDR_rawmake(a, AF_INET, &in, sizeof(in), 4660);

        dup = BIO_ADDR_dup(a);
        printf("dup.nonnull=%d\n", dup != NULL);
        printf("dup.distinct=%d\n", dup != a);
        printf("dup.family=%d\n", BIO_ADDR_family(dup));
        printf("dup.rawport=%u\n", (unsigned)BIO_ADDR_rawport(dup));

        BIO_ADDR_clear(dup);
        printf("clear.family=%d\n", BIO_ADDR_family(dup));
        printf("clear.rawport=%u\n", (unsigned)BIO_ADDR_rawport(dup));
        len = 99;
        printf("clear.rawaddress.ret=%d\n", BIO_ADDR_rawaddress(dup, raw, &len));

        printf("copy.ret=%d\n", BIO_ADDR_copy(dup, a));
        printf("copy.family=%d\n", BIO_ADDR_family(dup));
        printf("copy.rawport=%u\n", (unsigned)BIO_ADDR_rawport(dup));

        BIO_ADDR_free(dup);
        BIO_ADDR_free(a);

        copy = BIO_ADDR_new();
        printf("copy.nullsrc=%d\n", BIO_ADDR_copy(copy, NULL));
        printf("copy.nulldst=%d\n", BIO_ADDR_copy(NULL, copy));
        BIO_ADDR_free(copy);
    }

    /* --- the null-argument calls the authority defines ------------------ */
    BIO_ADDR_free(NULL);
    printf("null.dup=%p\n", (void *)BIO_ADDR_dup(NULL));
    printf("null.copy=%d\n", BIO_ADDR_copy(NULL, NULL));

    return 0;
}
