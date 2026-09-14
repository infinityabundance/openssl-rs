/*
 * openssl-rs — discovery probe for BIO_ADDR / BIO_ADDRINFO / host-service parsing.
 *
 * NOT a court. This is the archaeology step: run it against the authority, read
 * what the authority actually does, and only then implement. It stays because it
 * documents how the contract was established.
 *
 * Output is `key=value`, one observation per line, unbuffered, so a fault still
 * leaves the transcript up to the fault. Calls whose null-argument behaviour is
 * unknown are grouped at the very END: a crash there costs nothing before it.
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

int main(void)
{
    char buf[256];
    BIO_ADDR *a = BIO_ADDR_new();
    unsigned char raw[32];
    size_t len;
    int r;

    setvbuf(stdout, NULL, _IONBF, 0);

    /* --- fresh ADDR ---------------------------------------------------- */
    printf("new.nonnull=%d\n", a != NULL);
    printf("new.family=%d\n", BIO_ADDR_family(a));
    printf("new.rawport=%u\n", (unsigned)BIO_ADDR_rawport(a));
    r = BIO_ADDR_rawaddress(a, raw, &len);
    printf("new.rawaddress.ret=%d\n", r);
    printf("new.rawaddress.len=%zu\n", len);

    /* --- IPv4 ---------------------------------------------------------- */
    {
        struct in_addr in;
        inet_pton(AF_INET, "127.0.0.1", &in);
        r = BIO_ADDR_rawmake(a, AF_INET, &in, sizeof(in), 8080);
        printf("v4.rawmake.ret=%d\n", r);
        printf("v4.family=%d\n", BIO_ADDR_family(a));
        printf("v4.rawport=%u\n", (unsigned)BIO_ADDR_rawport(a));
        memset(raw, 0, sizeof(raw));
        len = sizeof(raw);
        r = BIO_ADDR_rawaddress(a, raw, &len);
        hex(raw, len, buf, sizeof(buf));
        printf("v4.rawaddress.ret=%d\n", r);
        printf("v4.rawaddress.len=%zu\n", len);
        str("v4.rawaddress.bytes", buf);
        str("v4.hostname.numeric", BIO_ADDR_hostname_string(a, 1));
        str("v4.hostname.named", BIO_ADDR_hostname_string(a, 0));
        str("v4.service.numeric", BIO_ADDR_service_string(a, 1));
        str("v4.service.named", BIO_ADDR_service_string(a, 0));
        str("v4.path", BIO_ADDR_path_string(a));
    }

    /* --- IPv6 ---------------------------------------------------------- */
    {
        struct in6_addr in6;
        inet_pton(AF_INET6, "::1", &in6);
        r = BIO_ADDR_rawmake(a, AF_INET6, &in6, sizeof(in6), 443);
        printf("v6.rawmake.ret=%d\n", r);
        printf("v6.family=%d\n", BIO_ADDR_family(a));
        printf("v6.rawport=%u\n", (unsigned)BIO_ADDR_rawport(a));
        memset(raw, 0, sizeof(raw));
        len = sizeof(raw);
        r = BIO_ADDR_rawaddress(a, raw, &len);
        hex(raw, len, buf, sizeof(buf));
        printf("v6.rawaddress.ret=%d\n", r);
        printf("v6.rawaddress.len=%zu\n", len);
        str("v6.rawaddress.bytes", buf);
        str("v6.hostname.numeric", BIO_ADDR_hostname_string(a, 1));
        str("v6.service.numeric", BIO_ADDR_service_string(a, 1));
        str("v6.path", BIO_ADDR_path_string(a));
    }

    /* --- IPv6 with a scope id, and the all-zero address ----------------- */
    {
        struct in6_addr in6;
        inet_pton(AF_INET6, "fe80::1", &in6);
        BIO_ADDR_rawmake(a, AF_INET6, &in6, sizeof(in6), 0);
        str("v6link.hostname.numeric", BIO_ADDR_hostname_string(a, 1));
    }

    /* --- rawmake argument validation ---------------------------------- */
    {
        struct in_addr in;
        inet_pton(AF_INET, "1.2.3.4", &in);
        printf("rawmake.short.len=%d\n", BIO_ADDR_rawmake(a, AF_INET, &in, 3, 0));
        printf("rawmake.long.len=%d\n", BIO_ADDR_rawmake(a, AF_INET, &in, 16, 0));
        printf("rawmake.unspec=%d\n", BIO_ADDR_rawmake(a, AF_UNSPEC, &in, 4, 0));
        printf("rawmake.badfamily=%d\n", BIO_ADDR_rawmake(a, 999, &in, 4, 0));
        /* does a rejected rawmake leave the previous value in place? */
        BIO_ADDR_rawmake(a, AF_INET, &in, sizeof(in), 1234);
        BIO_ADDR_rawmake(a, AF_UNSPEC, &in, sizeof(in), 4321);
        printf("rawmake.reject.keeps.family=%d\n", BIO_ADDR_family(a));
        printf("rawmake.reject.keeps.port=%u\n", (unsigned)BIO_ADDR_rawport(a));
    }

    /* --- AF_UNIX ------------------------------------------------------- */
    {
        r = BIO_ADDR_rawmake(a, AF_UNIX, "/tmp/x.sock", strlen("/tmp/x.sock") + 1, 0);
        printf("unix.rawmake.ret=%d\n", r);
        printf("unix.family=%d\n", BIO_ADDR_family(a));
        printf("unix.rawport=%u\n", (unsigned)BIO_ADDR_rawport(a));
        str("unix.path", BIO_ADDR_path_string(a));
        str("unix.hostname.numeric", BIO_ADDR_hostname_string(a, 1));
        str("unix.service.numeric", BIO_ADDR_service_string(a, 1));
    }

    /* --- rawaddress out-parameter contract ----------------------------- */
    {
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
    }

    /* --- dup / copy ---------------------------------------------------- */
    {
        BIO_ADDR *dup = BIO_ADDR_dup(a);
        printf("dup.nonnull=%d\n", dup != NULL);
        printf("dup.rawport=%u\n", (unsigned)BIO_ADDR_rawport(dup));
        printf("dup.distinct=%d\n", dup != a);
        BIO_ADDR_clear(dup);
        printf("clear.family=%d\n", BIO_ADDR_family(dup));
        printf("clear.rawport=%u\n", (unsigned)BIO_ADDR_rawport(dup));
        printf("copy.ret=%d\n", BIO_ADDR_copy(dup, a));
        printf("copy.rawport=%u\n", (unsigned)BIO_ADDR_rawport(dup));
        BIO_ADDR_free(dup);
    }

    /* --- ADDRINFO ------------------------------------------------------ */
    {
        BIO_ADDRINFO *res = NULL;
        const BIO_ADDRINFO *it;
        int n = 0;

        printf("ainfo.null.next=%p\n", (void *)BIO_ADDRINFO_next(NULL));
        printf("ainfo.null.family=%d\n", BIO_ADDRINFO_family(NULL));
        printf("ainfo.null.socktype=%d\n", BIO_ADDRINFO_socktype(NULL));
        printf("ainfo.null.protocol=%d\n", BIO_ADDRINFO_protocol(NULL));
        printf("ainfo.null.address=%p\n", (void *)BIO_ADDRINFO_address(NULL));
        BIO_ADDRINFO_free(NULL);

        r = BIO_lookup("localhost", "80", BIO_LOOKUP_CLIENT, AF_INET, SOCK_STREAM, &res);
        printf("lookup.localhost.ret=%d\n", r);
        printf("lookup.localhost.nonnull=%d\n", res != NULL);
        for (it = res; it != NULL && n < 6; it = BIO_ADDRINFO_next(it), n++) {
            const BIO_ADDR *ad = BIO_ADDRINFO_address(it);
            char key[64];
            sprintf(key, "lookup.localhost.%d.family", n);
            printf("%s=%d\n", key, BIO_ADDRINFO_family(it));
            sprintf(key, "lookup.localhost.%d.socktype", n);
            printf("%s=%d\n", key, BIO_ADDRINFO_socktype(it));
            sprintf(key, "lookup.localhost.%d.protocol", n);
            printf("%s=%d\n", key, BIO_ADDRINFO_protocol(it));
            sprintf(key, "lookup.localhost.%d.addrfamily", n);
            printf("%s=%d\n", key, ad == NULL ? -1 : BIO_ADDR_family(ad));
            sprintf(key, "lookup.localhost.%d.host", n);
            str(key, ad == NULL ? NULL : BIO_ADDR_hostname_string(ad, 1));
            sprintf(key, "lookup.localhost.%d.serv", n);
            str(key, ad == NULL ? NULL : BIO_ADDR_service_string(ad, 1));
        }
        printf("lookup.localhost.count=%d\n", n);
        BIO_ADDRINFO_free(res);

        res = NULL;
        r = BIO_lookup("localhost", "http", BIO_LOOKUP_CLIENT, AF_INET, SOCK_STREAM, &res);
        printf("lookup.service.ret=%d\n", r);
        if (res != NULL) {
            str("lookup.service.first.serv",
                BIO_ADDR_service_string(BIO_ADDRINFO_address(res), 1));
        }
        BIO_ADDRINFO_free(res);

        res = NULL;
        r = BIO_lookup(NULL, "80", BIO_LOOKUP_SERVER, AF_INET, SOCK_STREAM, &res);
        printf("lookup.server.nullhost.ret=%d\n", r);
        if (res != NULL) {
            str("lookup.server.nullhost.host",
                BIO_ADDR_hostname_string(BIO_ADDRINFO_address(res), 1));
        }
        BIO_ADDRINFO_free(res);

        res = NULL;
        r = BIO_lookup("no-such-host.invalid", "80", BIO_LOOKUP_CLIENT, AF_INET,
                       SOCK_STREAM, &res);
        printf("lookup.badhost.ret=%d\n", r);
        printf("lookup.badhost.res=%p\n", (void *)res);
        BIO_ADDRINFO_free(res);

        res = NULL;
        r = BIO_lookup_ex("127.0.0.1", "8080", BIO_LOOKUP_CLIENT, AF_INET,
                          SOCK_STREAM, IPPROTO_TCP, &res);
        printf("lookup_ex.ret=%d\n", r);
        if (res != NULL) {
            str("lookup_ex.host", BIO_ADDR_hostname_string(BIO_ADDRINFO_address(res), 1));
            str("lookup_ex.serv", BIO_ADDR_service_string(BIO_ADDRINFO_address(res), 1));
            printf("lookup_ex.protocol=%d\n", BIO_ADDRINFO_protocol(res));
        }
        BIO_ADDRINFO_free(res);
    }

    /* --- hostserv parsing --------------------------------------------- */
    {
        char *host = NULL, *serv = NULL;
        r = BIO_parse_hostserv("example.com:443", &host, &serv, BIO_PARSE_PRIO_HOST);
        printf("hostserv.hostport.ret=%d\n", r);
        str("hostserv.hostport.host", host);
        str("hostserv.hostport.serv", serv);
        OPENSSL_free(host);
        OPENSSL_free(serv);
        host = serv = NULL;

        r = BIO_parse_hostserv("example.com", &host, &serv, BIO_PARSE_PRIO_HOST);
        printf("hostserv.hostonly.ret=%d\n", r);
        str("hostserv.hostonly.host", host);
        str("hostserv.hostonly.serv", serv);
        OPENSSL_free(host);
        OPENSSL_free(serv);
        host = serv = NULL;

        r = BIO_parse_hostserv(":443", &host, &serv, BIO_PARSE_PRIO_HOST);
        printf("hostserv.portonly.ret=%d\n", r);
        str("hostserv.portonly.host", host);
        str("hostserv.portonly.serv", serv);
        OPENSSL_free(host);
        OPENSSL_free(serv);
        host = serv = NULL;

        r = BIO_parse_hostserv("[::1]:443", &host, &serv, BIO_PARSE_PRIO_HOST);
        printf("hostserv.v6bracket.ret=%d\n", r);
        str("hostserv.v6bracket.host", host);
        str("hostserv.v6bracket.serv", serv);
        OPENSSL_free(host);
        OPENSSL_free(serv);
        host = serv = NULL;

        r = BIO_parse_hostserv("::1", &host, &serv, BIO_PARSE_PRIO_HOST);
        printf("hostserv.v6bare.ret=%d\n", r);
        str("hostserv.v6bare.host", host);
        str("hostserv.v6bare.serv", serv);
        OPENSSL_free(host);
        OPENSSL_free(serv);
        host = serv = NULL;

        r = BIO_parse_hostserv(":443", &host, &serv, BIO_PARSE_PRIO_SERV);
        printf("hostserv.prio.serv.ret=%d\n", r);
        str("hostserv.prio.serv.host", host);
        str("hostserv.prio.serv.serv", serv);
        OPENSSL_free(host);
        OPENSSL_free(serv);
    }

    /* --- deprecated port / address helpers ----------------------------- */
    {
        unsigned short port = 0;
        printf("get_port.decimal=%d\n", BIO_get_port("80", &port));
        printf("get_port.decimal.value=%u\n", (unsigned)port);
        printf("get_port.service=%d\n", BIO_get_port("https", &port));
        printf("get_port.service.value=%u\n", (unsigned)port);
        printf("get_port.bad=%d\n", BIO_get_port("no-such-service-xyz", &port));
        printf("get_port.range=%d\n", BIO_get_port("70000", &port));

        {
            unsigned char ip[4] = {0, 0, 0, 0};
            printf("get_host_ip.literal=%d\n", BIO_get_host_ip("1.2.3.4", ip));
            hex(ip, 4, buf, sizeof(buf));
            str("get_host_ip.literal.bytes", buf);
            printf("get_host_ip.name=%d\n", BIO_get_host_ip("localhost", ip));
            hex(ip, 4, buf, sizeof(buf));
            str("get_host_ip.name.bytes", buf);
        }
    }

    /* --- BIO_sock_info -------------------------------------------------- */
    {
        int fd = BIO_socket(AF_INET, SOCK_STREAM, 0, 0);
        union BIO_sock_info_u info;
        struct in_addr in;
        BIO_ADDR *bound = BIO_ADDR_new();

        printf("socket.fd.ge0=%d\n", fd >= 0);
        info.addr = BIO_ADDR_new();
        r = BIO_sock_info(fd, BIO_SOCK_INFO_ADDRESS, &info);
        printf("sock_info.unbound.ret=%d\n", r);
        str("sock_info.unbound.family",
            info.addr == NULL ? NULL : NULL);
        printf("sock_info.unbound.familyval=%d\n",
               info.addr == NULL ? -1 : BIO_ADDR_family(info.addr));
        BIO_ADDR_free(info.addr);

        inet_pton(AF_INET, "127.0.0.1", &in);
        BIO_ADDR_rawmake(bound, AF_INET, &in, sizeof(in), 0);
        r = BIO_bind(fd, bound, BIO_SOCK_REUSEADDR);
        printf("bind.ret=%d\n", r);
        info.addr = BIO_ADDR_new();
        r = BIO_sock_info(fd, BIO_SOCK_INFO_ADDRESS, &info);
        printf("sock_info.bound.ret=%d\n", r);
        printf("sock_info.bound.family=%d\n",
               info.addr == NULL ? -1 : BIO_ADDR_family(info.addr));
        printf("sock_info.bound.port.nonzero=%d\n",
               info.addr == NULL ? -1 : BIO_ADDR_rawport(info.addr) != 0);
        BIO_ADDR_free(info.addr);

        r = BIO_listen(fd, bound, 0);
        printf("listen.ret=%d\n", r);
        info.addr = BIO_ADDR_new();
        r = BIO_sock_info(fd, BIO_SOCK_INFO_ADDRESS, &info);
        printf("sock_info.listen.ret=%d\n", r);
        printf("sock_info.listen.port.nonzero=%d\n",
               info.addr == NULL ? -1 : BIO_ADDR_rawport(info.addr) != 0);
        BIO_ADDR_free(info.addr);

        BIO_ADDR_free(bound);
        BIO_closesocket(fd);
    }

    /* --- null-argument behaviour (a fault here costs nothing above) ----- */
    BIO_ADDR_free(NULL);
    BIO_ADDR_clear(NULL);
    str("addr_dup_null.nonnull", BIO_ADDR_dup(NULL) == NULL ? "yes" : "no");
    printf("addr_rawaddress_null.ret=%d\n", BIO_ADDR_rawaddress(NULL, raw, &len));
    printf("addr_rawport_null=%u\n", (unsigned)BIO_ADDR_rawport(NULL));

    BIO_ADDR_free(a);
    return 0;
}
