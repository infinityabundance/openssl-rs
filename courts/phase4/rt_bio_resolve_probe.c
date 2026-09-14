/*
 * openssl-rs — RT-BIO-RESOLVE: differential probe for the resolver-backed surface.
 *
 * Covers BIO_ADDRINFO, BIO_lookup/BIO_lookup_ex, BIO_parse_hostserv, BIO_get_port,
 * BIO_get_host_ip and BIO_gethostbyname.
 *
 * Two things this probe is careful about:
 *
 *   * The error queue is part of the contract here, not just the return value.
 *     Every failure raises `ERR_LIB_BIO`/`ERR_R_SYS_LIB` at a specific recorded
 *     coordinate with `gai_strerror` as data, and `ERR_get_error_line_data`
 *     exposes all of it. A probe that compared only return values would call two
 *     different behaviours identical.
 *   * `*res` is written only on success, so the failure case is probed with a
 *     sentinel pointer to tell "left alone" from "set to NULL".
 *
 * Deliberately NOT probed, because the authority faults and the candidate is total
 * by policy (docs/SECURITY_DIVERGENCE_POLICY.md): a NULL `res`, a NULL host with
 * AF_UNIX (the authority calls strlen on it), a NULL hostserv, a NULL `ip`, and a
 * NULL `port_ptr`.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

/* Print the error queue's full observable state and clear it. */
static void err_state(const char *key)
{
    unsigned long e = ERR_peek_error();

    printf("%s.err=%lu\n", key, e);
    if (e != 0) {
        const char *file = NULL, *data = NULL;
        int line = 0, flags = 0;

        (void)ERR_get_error_line_data(&file, &line, &data, &flags);
        printf("%s.err.file=%s\n", key, file ? file : "<NULL>");
        printf("%s.err.line=%d\n", key, line);
        printf("%s.err.data=%s\n", key, data ? data : "<NULL>");
        printf("%s.err.flags=%d\n", key, flags);
        printf("%s.err.emptyafter=%d\n", key, ERR_peek_error() == 0);
        ERR_clear_error();
    }
}

static const char *addr_host(const BIO_ADDR *a, int numeric)
{
    static char buf[256];
    char *s = a == NULL ? NULL : BIO_ADDR_hostname_string(a, numeric);
    snprintf(buf, sizeof(buf), "%s", s == NULL ? "<NULL>" : s);
    OPENSSL_free(s);
    return buf;
}

static void dump_chain(const char *key, const BIO_ADDRINFO *res, int max)
{
    const BIO_ADDRINFO *it;
    char k[128];
    int n = 0;

    for (it = res; it != NULL && n < max; it = BIO_ADDRINFO_next(it)) {
        const BIO_ADDR *ad = BIO_ADDRINFO_address(it);

        sprintf(k, "%s.%d.family", key, n);
        printf("%s=%d\n", k, BIO_ADDRINFO_family(it));
        sprintf(k, "%s.%d.socktype", key, n);
        printf("%s=%d\n", k, BIO_ADDRINFO_socktype(it));
        sprintf(k, "%s.%d.protocol", key, n);
        printf("%s=%d\n", k, BIO_ADDRINFO_protocol(it));
        sprintf(k, "%s.%d.addrfamily", key, n);
        printf("%s=%d\n", k, ad == NULL ? -1 : BIO_ADDR_family(ad));
        sprintf(k, "%s.%d.host", key, n);
        printf("%s=%s\n", k, addr_host(ad, 1));
        sprintf(k, "%s.%d.serv", key, n);
        {
            char *s = ad == NULL ? NULL : BIO_ADDR_service_string(ad, 1);
            printf("%s=%s\n", k, s == NULL ? "<NULL>" : s);
            OPENSSL_free(s);
        }
        sprintf(k, "%s.%d.rawport", key, n);
        printf("%s=%u\n", k, ad == NULL ? 0u : (unsigned)BIO_ADDR_rawport(ad));
        n++;
    }
    printf("%s.count=%d\n", key, n);
}

static void lookup_case(const char *key, const char *host, const char *service,
                        int lookup_type, int family, int socktype, int protocol)
{
    BIO_ADDRINFO *res = NULL;
    int r;

    ERR_clear_error();
    r = BIO_lookup_ex(host, service, lookup_type, family, socktype, protocol, &res);
    printf("%s.ret=%d\n", key, r);
    printf("%s.isnull=%d\n", key, res == NULL);
    dump_chain(key, res, 8);
    err_state(key);
    BIO_ADDRINFO_free(res);
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);

    /* --- the accessors are total on NULL, and free(NULL) is a no-op ------- */
    printf("null.next=%p\n", (void *)BIO_ADDRINFO_next(NULL));
    printf("null.family=%d\n", BIO_ADDRINFO_family(NULL));
    printf("null.socktype=%d\n", BIO_ADDRINFO_socktype(NULL));
    printf("null.protocol=%d\n", BIO_ADDRINFO_protocol(NULL));
    printf("null.address=%p\n", (void *)BIO_ADDRINFO_address(NULL));
    BIO_ADDRINFO_free(NULL);
    printf("null.survived=1\n");

    /* --- the resolver path ---------------------------------------------- */
    lookup_case("lk.v4", "localhost", "80", BIO_LOOKUP_CLIENT, AF_INET, SOCK_STREAM, 0);
    lookup_case("lk.numeric", "127.0.0.1", "8080", BIO_LOOKUP_CLIENT, AF_INET,
                SOCK_STREAM, 0);
    lookup_case("lk.v4ex.tcp", "localhost", "80", BIO_LOOKUP_CLIENT, AF_INET,
                SOCK_STREAM, IPPROTO_TCP);
    lookup_case("lk.dgram", "localhost", "80", BIO_LOOKUP_CLIENT, AF_INET, SOCK_DGRAM,
                0);
    lookup_case("lk.sock0", "127.0.0.1", "80", BIO_LOOKUP_CLIENT, AF_INET, 0, 0);
    lookup_case("lk.family0", "127.0.0.1", "80", BIO_LOOKUP_CLIENT, 0, SOCK_STREAM, 0);
    lookup_case("lk.server.v4", NULL, "80", BIO_LOOKUP_SERVER, AF_INET, SOCK_STREAM, 0);
    lookup_case("lk.server.v6", NULL, "80", BIO_LOOKUP_SERVER, AF_INET6, SOCK_STREAM, 0);
    lookup_case("lk.client.v6", NULL, "80", BIO_LOOKUP_CLIENT, AF_INET6, SOCK_STREAM, 0);
    lookup_case("lk.noservice", "127.0.0.1", NULL, BIO_LOOKUP_CLIENT, AF_INET,
                SOCK_STREAM, 0);

    /* --- and its failures, with the queue --------------------------------- */
    lookup_case("lk.badhost", "no-such-host.invalid", "80", BIO_LOOKUP_CLIENT, AF_INET,
                SOCK_STREAM, 0);
    lookup_case("lk.badservice", "localhost", "no-such-service-xyz", BIO_LOOKUP_CLIENT,
                AF_INET, SOCK_STREAM, 0);
    lookup_case("lk.mismatch", "localhost", "80", BIO_LOOKUP_CLIENT, AF_INET,
                SOCK_STREAM, IPPROTO_UDP);
    lookup_case("lk.badproto", "localhost", "80", BIO_LOOKUP_CLIENT, AF_INET,
                SOCK_STREAM, 999);
    lookup_case("lk.badfamily", "localhost", "80", BIO_LOOKUP_CLIENT, 999, SOCK_STREAM,
                0);
    lookup_case("lk.emptyhost", "", "80", BIO_LOOKUP_CLIENT, AF_INET, SOCK_STREAM, 0);

    /* --- AF_UNIX takes the host as the path, with no resolver ------------ */
    lookup_case("lk.unix", "/tmp/openssl-rs.sock", NULL, BIO_LOOKUP_CLIENT, AF_UNIX,
                SOCK_STREAM, 0);
    lookup_case("lk.unix.dgram", "/tmp/openssl-rs.sock", NULL, BIO_LOOKUP_CLIENT,
                AF_UNIX, SOCK_DGRAM, 0);

    /* --- BIO_lookup is BIO_lookup_ex with protocol 0 --------------------- */
    {
        BIO_ADDRINFO *res = NULL;
        int r = BIO_lookup("127.0.0.1", "8080", BIO_LOOKUP_CLIENT, AF_INET,
                           SOCK_STREAM, &res);
        printf("lookup.wrapper.ret=%d\n", r);
        printf("lookup.wrapper.isnull=%d\n", res == NULL);
        dump_chain("lookup.wrapper", res, 4);
        BIO_ADDRINFO_free(res);
        ERR_clear_error();
    }

    /* --- *res is written only on success --------------------------------- */
    {
        BIO_ADDRINFO *sentinel = (BIO_ADDRINFO *)0x1234;
        int r = BIO_lookup_ex("no-such-host.invalid", "80", BIO_LOOKUP_CLIENT, AF_INET,
                              SOCK_STREAM, 0, &sentinel);
        printf("res.fail.ret=%d\n", r);
        printf("res.fail.intact=%d\n", sentinel == (BIO_ADDRINFO *)0x1234);
        ERR_clear_error();
    }
    {
        BIO_ADDRINFO *sentinel = (BIO_ADDRINFO *)0x1234;
        int r = BIO_lookup_ex("127.0.0.1", "80", BIO_LOOKUP_CLIENT, AF_INET,
                              SOCK_STREAM, 0, &sentinel);
        printf("res.ok.ret=%d\n", r);
        printf("res.ok.replaced=%d\n", sentinel != (BIO_ADDRINFO *)0x1234);
        BIO_ADDRINFO_free(sentinel);
    }

    /* --- BIO_parse_hostserv --------------------------------------------- */
    {
        static const struct {
            const char *key;
            const char *in;
            int prio;
        } cases[] = {
            { "hs.hostport", "example.com:443", BIO_PARSE_PRIO_HOST },
            { "hs.hostonly", "example.com", BIO_PARSE_PRIO_HOST },
            { "hs.portonly", ":443", BIO_PARSE_PRIO_HOST },
            { "hs.v6bracket", "[::1]:443", BIO_PARSE_PRIO_HOST },
            { "hs.v6bracket.noport", "[::1]", BIO_PARSE_PRIO_HOST },
            { "hs.v6bracket.junk", "[::1]x", BIO_PARSE_PRIO_HOST },
            { "hs.unbracketed", "::1", BIO_PARSE_PRIO_HOST },
            { "hs.empty", "", BIO_PARSE_PRIO_HOST },
            { "hs.colon", ":", BIO_PARSE_PRIO_HOST },
            { "hs.two.colons", "a:b:c", BIO_PARSE_PRIO_HOST },
            { "hs.star.host", "*:443", BIO_PARSE_PRIO_HOST },
            { "hs.star.serv", "example.com:*", BIO_PARSE_PRIO_HOST },
            { "hs.star.both", "*:*", BIO_PARSE_PRIO_HOST },
            { "hs.portonly.servprio", ":443", BIO_PARSE_PRIO_SERV },
            { "hs.both.servprio", "host:443", BIO_PARSE_PRIO_SERV },
            { "hs.hostonly.servprio", "example.com", BIO_PARSE_PRIO_SERV },
            { "hs.bracketed.nested", "[a:b]:443", BIO_PARSE_PRIO_HOST },
            { "hs.serv.has.colon", "host:a:b", BIO_PARSE_PRIO_HOST },
            { "hs.long", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:443",
              BIO_PARSE_PRIO_HOST },
        };
        size_t i;

        for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
            char *host = NULL, *serv = NULL;
            int r;

            ERR_clear_error();
            r = BIO_parse_hostserv(cases[i].in, &host, &serv, cases[i].prio);
            printf("%s.ret=%d\n", cases[i].key, r);
            printf("%s.host=%s\n", cases[i].key, host == NULL ? "<NULL>" : host);
            printf("%s.serv=%s\n", cases[i].key, serv == NULL ? "<NULL>" : serv);
            err_state(cases[i].key);
            OPENSSL_free(host);
            OPENSSL_free(serv);
        }

        /* A host out-parameter of NULL means "do not write it". */
        {
            char *serv = NULL;
            int r = BIO_parse_hostserv("example.com:443", NULL, &serv, BIO_PARSE_PRIO_HOST);
            printf("hs.nullhost.ret=%d\n", r);
            printf("hs.nullhost.serv=%s\n", serv == NULL ? "<NULL>" : serv);
            OPENSSL_free(serv);
            ERR_clear_error();
        }
    }

    /* --- BIO_get_port --------------------------------------------------- */
    {
        static const char *const cases[] = { "80", "0", "65535", "65536", "70000",
                                             "2147483647", "-1", "+80", "0x50", " 80",
                                             "80x", "", "http", "https", "ftp", "*" };
        size_t i;

        for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
            unsigned short port = 0xA5A5;
            char key[64];
            int r;

            ERR_clear_error();
            r = BIO_get_port(cases[i], &port);
            snprintf(key, sizeof(key), "port.%zu", i);
            printf("%s.ret=%d\n", key, r);
            printf("%s.port=%u\n", key, (unsigned)port);
            err_state(key);
        }

        /* A NULL string is a defined failure with its own reason. */
        {
            int r = BIO_get_port(NULL, NULL);
            printf("port.null.ret=%d\n", r);
            err_state("port.null");
        }
    }

    /* --- BIO_get_host_ip ------------------------------------------------ */
    {
        static const char *const cases[] = { "1.2.3.4", "0.0.0.0", "255.255.255.255",
                                             "localhost", "1.2.3", "1.2", "1",
                                             "256.1.1.1", "::1", "",
                                             "no-such-host.invalid" };
        size_t i;

        for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
            unsigned char ip[4] = { 0xde, 0xad, 0xbe, 0xef };
            char key[64];
            int r;

            ERR_clear_error();
            r = BIO_get_host_ip(cases[i], ip);
            snprintf(key, sizeof(key), "ip.%zu", i);
            printf("%s.ret=%d\n", key, r);
            printf("%s.bytes=%02x%02x%02x%02x\n", key, ip[0], ip[1], ip[2], ip[3]);
            err_state(key);
        }

        /* A NULL host is legal here: the resolver treats it as the loopback. */
        {
            unsigned char ip[4] = { 0xde, 0xad, 0xbe, 0xef };
            int r = BIO_get_host_ip(NULL, ip);
            printf("ip.null.ret=%d\n", r);
            printf("ip.null.bytes=%02x%02x%02x%02x\n", ip[0], ip[1], ip[2], ip[3]);
            err_state("ip.null");
        }
    }

    /* --- BIO_gethostbyname ---------------------------------------------- */
    {
        struct hostent *he = BIO_gethostbyname("localhost");
        printf("ghbn.ok.nonnull=%d\n", he != NULL);
        if (he != NULL) {
            printf("ghbn.ok.name=%s\n", he->h_name ? he->h_name : "<NULL>");
            printf("ghbn.ok.addrtype=%d\n", he->h_addrtype);
            printf("ghbn.ok.length=%d\n", he->h_length);
            printf("ghbn.ok.first=%02x%02x%02x%02x\n",
                   (unsigned char)he->h_addr_list[0][0],
                   (unsigned char)he->h_addr_list[0][1],
                   (unsigned char)he->h_addr_list[0][2],
                   (unsigned char)he->h_addr_list[0][3]);
        }
        ERR_clear_error();
        he = BIO_gethostbyname("no-such-host.invalid");
        printf("ghbn.bad.nonnull=%d\n", he != NULL);
        /* Measured: no error is raised on failure. */
        printf("ghbn.bad.err=%lu\n", ERR_peek_error());
        ERR_clear_error();
    }

    /*
     * ERR_add_error_data is the function the host/port helpers append through, so
     * its own behaviour is observed here too rather than assumed.
     */
    {
        static char big[3000];

        ERR_clear_error();
        ERR_set_error(ERR_LIB_BIO, 1, "base");
        ERR_add_error_data(2, "host=", NULL);
        err_state("aed.null");

        ERR_set_error(ERR_LIB_BIO, 1, "base");
        ERR_add_error_data(2, NULL, NULL);
        err_state("aed.bothnull");

        memset(big, 'z', sizeof(big) - 1);
        big[sizeof(big) - 1] = '\0';
        ERR_set_error(ERR_LIB_BIO, 1, "base");
        ERR_add_error_data(1, big);
        err_state("aed.long");

        ERR_set_error(ERR_LIB_BIO, 1, NULL);
        ERR_add_error_data(0);
        err_state("aed.zero");
    }

    return 0;
}
