/*
 * openssl-rs — discovery probe 5: the deprecated host/port helpers, BIO_parse_hostserv,
 * and the one case that discriminates whether BIO_lookup passes protocol 0.
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

static void err_state(const char *key)
{
    unsigned long e = ERR_peek_error();
    char buf[256];

    printf("%s.err=%lu\n", key, e);
    if (e != 0) {
        const char *file = NULL, *data = NULL;
        int line = 0, flags = 0;
        ERR_error_string_n(e, buf, sizeof(buf));
        printf("%s.err.string=%s\n", key, buf);
        /* The source coordinates are observable and are part of the contract. */
        (void)ERR_get_error_line_data(&file, &line, &data, &flags);
        printf("%s.err.file=%s\n", key, file ? file : "<NULL>");
        printf("%s.err.line=%d\n", key, line);
        printf("%s.err.data=%s\n", key, data ? data : "<NULL>");
        printf("%s.err.dataflags=%d\n", key, flags);
        ERR_clear_error();
    }
}

static void show_hostserv(const char *key, const char *in, int prio)
{
    char *host = NULL, *serv = NULL;
    int r = BIO_parse_hostserv(in, &host, &serv, prio);

    printf("%s.ret=%d\n", key, r);
    printf("%s.host=%s\n", key, host ? host : "<NULL>");
    printf("%s.serv=%s\n", key, serv ? serv : "<NULL>");
    err_state(key);
    OPENSSL_free(host);
    OPENSSL_free(serv);
}

static void show_port(const char *key, const char *in)
{
    unsigned short port = 0xA5A5;
    int r = BIO_get_port(in, &port);

    printf("%s.ret=%d\n", key, r);
    printf("%s.port=%u\n", key, (unsigned)port);
    err_state(key);
}

static void show_ip(const char *key, const char *in)
{
    unsigned char ip[4] = {0xde, 0xad, 0xbe, 0xef};
    int r = BIO_get_host_ip(in, ip);

    printf("%s.ret=%d\n", key, r);
    printf("%s.bytes=%02x%02x%02x%02x\n", key, ip[0], ip[1], ip[2], ip[3]);
    err_state(key);
}

static int lookup_count(const char *host, const char *service, int lookup_type,
                        int family, int socktype, int protocol)
{
    BIO_ADDRINFO *res = NULL;
    const BIO_ADDRINFO *it;
    int n = 0;

    if (BIO_lookup_ex(host, service, lookup_type, family, socktype, protocol, &res) != 1)
        return -1;
    for (it = res; it != NULL && n < 32; it = BIO_ADDRINFO_next(it))
        n++;
    BIO_ADDRINFO_free(res);
    return n;
}

int main(void)
{
    BIO_ADDRINFO *res = NULL;

    setvbuf(stdout, NULL, _IONBF, 0);

    /*
     * Does BIO_lookup pass protocol 0, or does it pick a protocol from the
     * socktype? With SOCK_RAW and protocol 0 the resolver returns one entry per
     * protocol; with a fixed protocol it returns one. That is the discriminator.
     */
    printf("proto.bio_lookup_raw=%d\n",
           lookup_count("127.0.0.1", "80", BIO_LOOKUP_CLIENT, AF_INET, SOCK_RAW, 0));
    {
        BIO_ADDRINFO *r2 = NULL;
        const BIO_ADDRINFO *it;
        int n = 0;
        if (BIO_lookup("127.0.0.1", "80", BIO_LOOKUP_CLIENT, AF_INET, SOCK_RAW, &r2) == 1)
            for (it = r2; it != NULL && n < 32; it = BIO_ADDRINFO_next(it))
                n++;
        printf("proto.bio_lookup_plain_raw=%d\n", n);
        BIO_ADDRINFO_free(r2);
    }
    printf("proto.bio_lookup_ex_raw_tcp=%d\n",
           lookup_count("127.0.0.1", "80", BIO_LOOKUP_CLIENT, AF_INET, SOCK_RAW,
                        IPPROTO_TCP));
    printf("proto.bio_lookup_ex_stream_tcp=%d\n",
           lookup_count("127.0.0.1", "80", BIO_LOOKUP_CLIENT, AF_INET, SOCK_STREAM,
                        IPPROTO_TCP));
    printf("proto.bio_lookup_ex_stream_udp=%d\n",
           lookup_count("127.0.0.1", "80", BIO_LOOKUP_CLIENT, AF_INET, SOCK_STREAM,
                        IPPROTO_UDP));

    /* Does BIO_lookup_ex reject family 0 or socktype 0? */
    printf("valid.family0=%d\n",
           lookup_count("127.0.0.1", "80", BIO_LOOKUP_CLIENT, 0, SOCK_STREAM, 0));
    printf("valid.sock0=%d\n",
           lookup_count("127.0.0.1", "80", BIO_LOOKUP_CLIENT, AF_INET, 0, 0));
    printf("valid.family999=%d\n",
           lookup_count("127.0.0.1", "80", BIO_LOOKUP_CLIENT, 999, SOCK_STREAM, 0));
    err_state("valid");

    /*
     * Which recorded raise site fires for each lookup failure? The packed code is
     * the same, but the file/line is not, and the project records those.
     */
    {
        static const struct {
            const char *key;
            const char *host, *service;
            int ltype, family, socktype, protocol;
        } cases[] = {
            { "lk.badhost", "no-such-host.invalid", "80", BIO_LOOKUP_CLIENT, AF_INET, SOCK_STREAM, 0 },
            { "lk.badservice", "localhost", "no-such-service-xyz", BIO_LOOKUP_CLIENT, AF_INET, SOCK_STREAM, 0 },
            { "lk.mismatch", "localhost", "80", BIO_LOOKUP_CLIENT, AF_INET, SOCK_STREAM, IPPROTO_UDP },
            { "lk.badproto", "localhost", "80", BIO_LOOKUP_CLIENT, AF_INET, SOCK_STREAM, 999 },
            { "lk.badfamily", "localhost", "80", BIO_LOOKUP_CLIENT, 999, SOCK_STREAM, 0 },
            { "lk.emptyhost", "", "80", BIO_LOOKUP_CLIENT, AF_INET, SOCK_STREAM, 0 },
            { "lk.server.v6", NULL, "80", BIO_LOOKUP_SERVER, AF_INET6, SOCK_STREAM, 0 },
            { "lk.client.v6", NULL, "80", BIO_LOOKUP_CLIENT, AF_INET6, SOCK_STREAM, 0 },
            { "lk.noname", "no-such-host.invalid", "80", BIO_LOOKUP_SERVER, AF_INET, SOCK_STREAM, 0 },
        };
        size_t i;
        for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
            BIO_ADDRINFO *r = NULL;
            int rc = BIO_lookup_ex(cases[i].host, cases[i].service, cases[i].ltype,
                                   cases[i].family, cases[i].socktype,
                                   cases[i].protocol, &r);
            printf("%s.ret=%d\n", cases[i].key, rc);
            err_state(cases[i].key);
            BIO_ADDRINFO_free(r);
        }
    }

    /* --- BIO_parse_hostserv -------------------------------------------- */
    show_hostserv("hs.hostport", "example.com:443", BIO_PARSE_PRIO_HOST);
    show_hostserv("hs.hostonly", "example.com", BIO_PARSE_PRIO_HOST);
    show_hostserv("hs.portonly", ":443", BIO_PARSE_PRIO_HOST);
    show_hostserv("hs.v6bracket", "[::1]:443", BIO_PARSE_PRIO_HOST);
    show_hostserv("hs.v6bracket.noport", "[::1]", BIO_PARSE_PRIO_HOST);
    show_hostserv("hs.v6bracket.junk", "[::1]x", BIO_PARSE_PRIO_HOST);
    show_hostserv("hs.unbracketed", "::1", BIO_PARSE_PRIO_HOST);
    show_hostserv("hs.empty", "", BIO_PARSE_PRIO_HOST);
    show_hostserv("hs.colon", ":", BIO_PARSE_PRIO_HOST);
    show_hostserv("hs.portonly.servprio", ":443", BIO_PARSE_PRIO_SERV);
    show_hostserv("hs.both.servprio", "host:443", BIO_PARSE_PRIO_SERV);
    show_hostserv("hs.hostonly.servprio", "example.com", BIO_PARSE_PRIO_SERV);
    show_hostserv("hs.two.colons", "a:b:c", BIO_PARSE_PRIO_HOST);

    /* --- BIO_get_port --------------------------------------------------- */
    show_port("port.80", "80");
    show_port("port.0", "0");
    show_port("port.65535", "65535");
    show_port("port.65536", "65536");
    show_port("port.70000", "70000");
    show_port("port.2147483647", "2147483647");
    show_port("port.neg", "-1");
    show_port("port.plus", "+80");
    show_port("port.hex", "0x50");
    show_port("port.space", " 80");
    show_port("port.trailing", "80x");
    show_port("port.empty", "");
    show_port("port.name", "http");
    show_port("port.name2", "https");
    show_port("port.name3", "ftp");

    /* --- BIO_get_host_ip ------------------------------------------------ */
    show_ip("ip.literal", "1.2.3.4");
    show_ip("ip.zero", "0.0.0.0");
    show_ip("ip.bcast", "255.255.255.255");
    show_ip("ip.name", "localhost");
    show_ip("ip.badquad", "1.2.3");
    show_ip("ip.range", "256.1.1.1");
    show_ip("ip.v6", "::1");
    show_ip("ip.empty", "");
    show_ip("ip.badname", "no-such-host.invalid");

    /* --- BIO_gethostbyname ---------------------------------------------- */
    {
        struct hostent *he = BIO_gethostbyname("localhost");
        printf("ghbn.localhost.nonnull=%d\n", he != NULL);
        if (he != NULL) {
            printf("ghbn.localhost.name=%s\n", he->h_name ? he->h_name : "<NULL>");
            printf("ghbn.localhost.addrtype=%d\n", he->h_addrtype);
            printf("ghbn.localhost.length=%d\n", he->h_length);
            printf("ghbn.localhost.first=%02x%02x%02x%02x\n",
                   (unsigned char)he->h_addr_list[0][0],
                   (unsigned char)he->h_addr_list[0][1],
                   (unsigned char)he->h_addr_list[0][2],
                   (unsigned char)he->h_addr_list[0][3]);
        }
        he = BIO_gethostbyname("no-such-host.invalid");
        printf("ghbn.bad.nonnull=%d\n", he != NULL);
        err_state("ghbn");
    }

    /* --- BIO_accept / BIO_get_accept_socket are socket-layer; see RT-BIO-SOCK --- */

    /*
     * Is *res written on the failure path? Passing a sentinel distinguishes
     * "set to NULL" from "left alone", which is an ownership observable.
     */
    {
        BIO_ADDRINFO *sentinel = (BIO_ADDRINFO *)0x1234;
        int r = BIO_lookup_ex("no-such-host.invalid", "80", BIO_LOOKUP_CLIENT,
                             AF_INET, SOCK_STREAM, 0, &sentinel);
        printf("res.failure.ret=%d\n", r);
        printf("res.failure.sentinel_intact=%d\n", sentinel == (BIO_ADDRINFO *)0x1234);
        printf("res.failure.isnull=%d\n", sentinel == NULL);
        ERR_clear_error();
    }
    {
        BIO_ADDRINFO *sentinel = (BIO_ADDRINFO *)0x1234;
        int r = BIO_lookup_ex("127.0.0.1", "80", BIO_LOOKUP_CLIENT, AF_INET,
                             SOCK_STREAM, 0, &sentinel);
        printf("res.success.ret=%d\n", r);
        printf("res.success.replaced=%d\n", sentinel != (BIO_ADDRINFO *)0x1234);
        /* the second link of a two-entry chain, to pin the chain shape */
        printf("res.success.second.nonnull=%d\n", BIO_ADDRINFO_next(sentinel) != NULL);
        BIO_ADDRINFO_free(sentinel);
    }
    /* A two-entry chain's second node, for localhost. */
    {
        BIO_ADDRINFO *r2 = NULL;
        if (BIO_lookup("localhost", "80", BIO_LOOKUP_CLIENT, AF_INET, SOCK_STREAM,
                       &r2) == 1) {
            const BIO_ADDRINFO *second = BIO_ADDRINFO_next(r2);
            printf("chain.second.nonnull=%d\n", second != NULL);
            if (second != NULL) {
                const BIO_ADDR *ad = BIO_ADDRINFO_address(second);
                char *s = ad ? BIO_ADDR_hostname_string(ad, 1) : NULL;
                printf("chain.second.host=%s\n", s ? s : "<NULL>");
                OPENSSL_free(s);
                printf("chain.second.family=%d\n", BIO_ADDRINFO_family(second));
                printf("chain.second.socktype=%d\n", BIO_ADDRINFO_socktype(second));
                printf("chain.second.protocol=%d\n", BIO_ADDRINFO_protocol(second));
            }
            printf("chain.third.nonnull=%d\n",
                   second != NULL && BIO_ADDRINFO_next(second) != NULL);
        }
        BIO_ADDRINFO_free(r2);
    }

    BIO_ADDRINFO_free(res);
    (void)res;
    return 0;
}
