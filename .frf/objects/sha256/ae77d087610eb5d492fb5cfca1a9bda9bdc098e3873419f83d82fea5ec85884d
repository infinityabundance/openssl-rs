/*
 * openssl-rs — RT-BIO-SOCK: differential probe for the socket-layer entry points.
 *
 * This is the court that can see what RT-BIO-ADDR structurally cannot: `BIO_ADDR`
 * stores its port verbatim, so a `BIO_ADDR_rawmake(…, 8080)` address carries 8080
 * in a network-order field and a *syscall* binds port 36895. Reading the address
 * back through `BIO_sock_info` therefore reports 8080 while the service string
 * reports 36895 — the two accessors disagree, and only the pair together
 * identifies which convention is implemented. That observation is
 * `sock.bound.rawport.after.rawmake8080` below.
 *
 * Determinism rules this probe follows, because the two sides are separate
 * processes:
 *
 *   * ephemeral ports differ between runs, so no raw port number is printed. What
 *     is printed is *relations* -- non-zero, equal to another descriptor's port,
 *     the same string prefix -- which are run-independent.
 *   * descriptor numbers are printed as predicates (`>= 0`), not as values.
 *   * `errno` values are printed, because they are Linux constants (EBADF 9,
 *     EAFNOSUPPORT 97) rather than per-run state.
 *   * slices of ephemeral data (an accepted port, an `ip_port` string) are printed
 *     as length-prefix predicates.
 *
 * Every failure here raises *two* errors -- `ERR_LIB_SYS` with `errno` and the text
 * "calling ...()", then `ERR_LIB_BIO` with its own reason -- so the whole queue is
 * drained and compared, not just the first entry.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

static const char *last_file;
static int last_line;

/* Drain and print the whole error queue in order, then clear it. */
static void err_all(const char *key)
{
    char k[96];
    int n = 0;

    for (;;) {
        const char *file = NULL, *data = NULL;
        int line = 0, flags = 0;
        unsigned long e = ERR_get_error_line_data(&file, &line, &data, &flags);

        if (e == 0)
            break;
        last_file = file;
        last_line = line;
        snprintf(k, sizeof(k), "%s.%d.code", key, n);
        printf("%s=%lu\n", k, e);
        snprintf(k, sizeof(k), "%s.%d.file", key, n);
        printf("%s=%s\n", k, file ? file : "<NULL>");
        snprintf(k, sizeof(k), "%s.%d.line", key, n);
        printf("%s=%d\n", k, line);
        snprintf(k, sizeof(k), "%s.%d.data", key, n);
        printf("%s=%s\n", k, data ? data : "<NULL>");
        snprintf(k, sizeof(k), "%s.%d.flags", key, n);
        printf("%s=%d\n", k, flags);
        if (++n > 8)
            break;
    }
    snprintf(k, sizeof(k), "%s.count", key);
    printf("%s=%d\n", k, n);
    ERR_clear_error();
}

/* A local address for loopback with a chosen port. */
static BIO_ADDR *make_loopback(unsigned short port)
{
    struct in_addr in;
    BIO_ADDR *a = BIO_ADDR_new();

    inet_pton(AF_INET, "127.0.0.1", &in);
    BIO_ADDR_rawmake(a, AF_INET, &in, sizeof(in), port);
    return a;
}

static void show_addr(const char *key, const BIO_ADDR *a)
{
    char k[96];
    char *s;

    snprintf(k, sizeof(k), "%s.family", key);
    printf("%s=%d\n", k, BIO_ADDR_family(a));
    snprintf(k, sizeof(k), "%s.rawport", key);
    printf("%s=%u\n", k, (unsigned)BIO_ADDR_rawport(a));
    s = BIO_ADDR_hostname_string(a, 1);
    snprintf(k, sizeof(k), "%s.host", key);
    printf("%s=%s\n", k, s ? s : "<NULL>");
    OPENSSL_free(s);
    s = BIO_ADDR_service_string(a, 1);
    snprintf(k, sizeof(k), "%s.service", key);
    printf("%s=%s\n", k, s ? s : "<NULL>");
    OPENSSL_free(s);
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);

    /* --- BIO_socket failures, and the error pairs they raise ------------- */
    ERR_clear_error();
    printf("socket.badfamily=%d\n", BIO_socket(999, SOCK_STREAM, 0, 0));
    err_all("socket.badfamily");
    printf("socket.badproto=%d\n", BIO_socket(AF_INET, SOCK_STREAM, 999, 0));
    err_all("socket.badproto");
    printf("socket.badtype=%d\n", BIO_socket(AF_INET, 999, 0, 0));
    err_all("socket.badtype");

    /* --- the invalid-socket checks, which raise a single error each ------ */
    {
        BIO_ADDR *a = make_loopback(0);

        ERR_clear_error();
        printf("invalid.bind=%d\n", BIO_bind(-1, a, 0));
        err_all("invalid.bind");
        ERR_clear_error();
        printf("invalid.listen=%d\n", BIO_listen(-1, a, 0));
        err_all("invalid.listen");
        ERR_clear_error();
        printf("invalid.connect=%d\n", BIO_connect(-1, a, 0));
        err_all("invalid.connect");

        /* --- the stored-port observation --------------------------------- */
        BIO_ADDR *p8080 = make_loopback(8080);
        int s = BIO_socket(AF_INET, SOCK_STREAM, 0, 0);
        union BIO_sock_info_u info;
        int r;

        printf("describe.rawmake8080.start\n");
        show_addr("describe.rawmake8080", p8080);

        ERR_clear_error();
        r = BIO_bind(s, p8080, BIO_SOCK_REUSEADDR);
        printf("sock.bind8080.ret=%d\n", r);
        err_all("sock.bind8080");

        info.addr = BIO_ADDR_new();
        r = BIO_sock_info(s, BIO_SOCK_INFO_ADDRESS, &info);
        printf("sock.bind8080.info.ret=%d\n", r);
        err_all("sock.bind8080.info");
        /*
         * `getsockname` writes a real sockaddr, so the *service* string here is the
         * port the kernel actually bound and the *raw* port is that field read
         * verbatim. Under the authority's convention the pair is (8080, "36895");
         * an implementation that stored `htons(port)` would produce (36895, "8080").
         */
        show_addr("sock.bind8080.readback", info.addr);
        printf("sock.bind8080.readback.rawport.is.passed=%d\n",
               BIO_ADDR_rawport(info.addr) == 8080);
        BIO_ADDR_free(info.addr);
        BIO_closesocket(s);

        BIO_ADDR_free(p8080);
        BIO_ADDR_free(a);
    }

    /* --- a real loopback handshake --------------------------------------- */
    {
        BIO_ADDR *listen_at = make_loopback(0);
        int srv = BIO_socket(AF_INET, SOCK_STREAM, 0, 0);
        union BIO_sock_info_u bound;
        int r;

        ERR_clear_error();
        r = BIO_listen(srv, listen_at, BIO_SOCK_REUSEADDR);
        printf("tcp.listen.ret=%d\n", r);
        err_all("tcp.listen");

        bound.addr = BIO_ADDR_new();
        r = BIO_sock_info(srv, BIO_SOCK_INFO_ADDRESS, &bound);
        printf("tcp.listen.info.ret=%d\n", r);
        printf("tcp.listen.info.port.nonzero=%d\n",
               BIO_ADDR_rawport(bound.addr) != 0);
        printf("tcp.listen.info.host.is.loopback=%d\n",
               strcmp(BIO_ADDR_hostname_string(bound.addr, 1), "127.0.0.1") == 0);
        {
            char *s = BIO_ADDR_service_string(bound.addr, 1);
            printf("tcp.listen.info.service.nonempty=%d\n", s != NULL && s[0] != '\0');
            OPENSSL_free(s);
        }

        {
            int cli = BIO_socket(AF_INET, SOCK_STREAM, 0, 0);
            union BIO_sock_info_u local;
            BIO_ADDR *peer = BIO_ADDR_new();
            int accepted;

            ERR_clear_error();
            r = BIO_connect(cli, bound.addr, 0);
            printf("tcp.connect.ret=%d\n", r);
            err_all("tcp.connect");

            /* The client's local port, for comparison with the accepted peer. */
            local.addr = BIO_ADDR_new();
            r = BIO_sock_info(cli, BIO_SOCK_INFO_ADDRESS, &local);
            printf("tcp.client.info.ret=%d\n", r);

            ERR_clear_error();
            accepted = BIO_accept_ex(srv, peer, 0);
            printf("tcp.accept.ret.ge0=%d\n", accepted >= 0);
            err_all("tcp.accept");
            printf("tcp.accept.peer.host=%s\n", BIO_ADDR_hostname_string(peer, 1));
            printf("tcp.accept.peer.port.matches.client=%d\n",
                   BIO_ADDR_rawport(peer) == BIO_ADDR_rawport(local.addr));

            BIO_ADDR_free(peer);
            BIO_ADDR_free(local.addr);
            BIO_closesocket(accepted);
            BIO_closesocket(cli);
        }

        BIO_ADDR_free(bound.addr);
        BIO_ADDR_free(listen_at);
        BIO_closesocket(srv);
    }

    /* --- accept that cannot succeed, and the deprecated wrapper ---------- */
    {
        BIO_ADDR *peer = BIO_ADDR_new();
        char *ip_port = NULL;
        int r;

        ERR_clear_error();
        r = BIO_accept_ex(-1, peer, 0);
        printf("accept_ex.badfd.ret=%d\n", r);
        err_all("accept_ex.badfd");
        BIO_ADDR_free(peer);

        ERR_clear_error();
        r = BIO_accept(-1, &ip_port);
        printf("accept.badfd.ret=%d\n", r);
        printf("accept.badfd.ip_port.null=%d\n", ip_port == NULL);
        err_all("accept.badfd");
    }

    /* --- BIO_sock_info's other paths ------------------------------------- */
    {
        union BIO_sock_info_u info;

        ERR_clear_error();
        info.addr = BIO_ADDR_new();
        printf("sock_info.badtype=%d\n", BIO_sock_info(0, 99, &info));
        err_all("sock_info.badtype");
        BIO_ADDR_free(info.addr);

        ERR_clear_error();
        info.addr = BIO_ADDR_new();
        printf("sock_info.badfd=%d\n", BIO_sock_info(-1, BIO_SOCK_INFO_ADDRESS, &info));
        err_all("sock_info.badfd");
        BIO_ADDR_free(info.addr);
    }

    /* --- BIO_set_tcp_ndelay raises nothing ------------------------------- */
    {
        int s = BIO_socket(AF_INET, SOCK_STREAM, 0, 0);

        ERR_clear_error();
        printf("ndelay.ok=%d\n", BIO_set_tcp_ndelay(s, 1));
        printf("ndelay.err.count=%lu\n", ERR_peek_error());
        ERR_clear_error();
        printf("ndelay.badfd=%d\n", BIO_set_tcp_ndelay(-1, 1));
        printf("ndelay.badfd.err.count=%lu\n", ERR_peek_error());
        ERR_clear_error();
        BIO_closesocket(s);
    }

    /* --- the deprecated BIO_get_accept_socket --------------------------- */
    {
        int s;

        ERR_clear_error();
        s = BIO_get_accept_socket("127.0.0.1:0", 1);
        printf("gas.ok.ge0=%d\n", s >= 0);
        err_all("gas.ok");
        if (s >= 0)
            BIO_closesocket(s);

        ERR_clear_error();
        printf("gas.ambiguous=%d\n", BIO_get_accept_socket("::1", 0));
        err_all("gas.ambiguous");

        ERR_clear_error();
        printf("gas.badservice=%d\n",
               BIO_get_accept_socket("127.0.0.1:no-such-service-xyz", 0));
        err_all("gas.badservice");
    }

    (void)last_file;
    (void)last_line;
    return 0;
}
