/*
 * openssl-rs — RT-BIO-CONN: differential probe for the connect and accept BIOs.
 *
 * The two are probed together because the accept BIO is the only peer this probe
 * needs, and because their state machines are the same shape with different
 * terminals.
 *
 * What only this court can see
 * ----------------------------
 *   * **The transition sequence.** An info callback is installed on the client
 *     and every `(state, ret)` pair the machine passes through is printed, so a
 *     candidate that reaches `OK` by a different route is caught even though the
 *     final connection succeeds.
 *   * **The terminal state raises, and it is not the state that failed.** A
 *     refused connection lands in `CONNECT_ERROR`, and the *next* pass through
 *     the machine raises `BIO_R_CONNECT_ERROR` — so the queue holds the connect
 *     text under `ERR_LIB_SYS` and then the BIO reason, and the control returns
 *     0 rather than -1.
 *   * **`LISTEN` reports success before accepting.** `BIO_do_accept` returns 1
 *     with nothing in the chain, which is what lets a caller learn the
 *     kernel-chosen port without blocking.
 *   * **`ACCEPT` with a chain already present is a successful no-op**; `OK` with
 *     no chain goes back to `ACCEPT`. Both are order-dependent and invisible to
 *     any single-call test.
 *   * **`BIO_C_SET_ACCEPT`'s two argument shapes.** `num` 2 and 5 act on `ptr`
 *     being non-NULL to *set* a mode bit and on NULL to *clear* it; the other
 *     sub-commands need `ptr` to do anything at all.
 *
 * Determinism rules, because the two sides are separate processes
 * --------------------------------------------------------------
 *   * no port number is printed. The accept BIO's own cached service string is
 *     what the client is told to connect to, so the ephemeral port cancels out,
 *     and every port observation is a relation.
 *   * descriptor numbers are printed as predicates.
 *   * `errno` values are Linux constants and are printed.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#define _GNU_SOURCE
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
static int cb_count;

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

/* The state-transition callback. Printing the pairs is the point. */
static int info_cb(BIO *b, int state, int ret)
{
    char k[96];
    int n = cb_count++;

    (void)b;
    snprintf(k, sizeof(k), "conn.cb.%d.state", n);
    printf("%s=%d\n", k, state);
    snprintf(k, sizeof(k), "conn.cb.%d.ret", n);
    printf("%s=%d\n", k, ret);
    return ret;
}

static long ctrl(BIO *b, int cmd, long num)
{
    return BIO_ctrl(b, cmd, num, NULL);
}

/* ------------------------------------------------------------------------- */
/* Section A — a fresh connect BIO.                                         */
/* ------------------------------------------------------------------------- */

static void section_fresh_connect(void)
{
    BIO *b = BIO_new(BIO_s_connect());
    const char *p = NULL;
    char *borrowed = NULL;
    BIO *inner = NULL;
    int v = 12345;

    printf("conn.method.name=%s\n", BIO_method_name(b));
    printf("conn.method.type=%d\n", BIO_method_type(b));

    /* A NULL `ptr` makes most sub-commands a no-op that still reports success. */
    printf("conn.get.null.ptr0=%ld\n", ctrl(b, BIO_C_GET_CONNECT, 0));
    printf("conn.get.null.ptr4=%ld\n", ctrl(b, BIO_C_GET_CONNECT, 4));
    printf("conn.set.null=%ld\n", ctrl(b, BIO_C_SET_CONNECT, 0));

    /* With a real slot: the hostname and service are absent, the address of an
     * empty iteration is NULL, and the family falls back to the requested one. */
    printf("conn.get.hostname.ret=%ld\n", BIO_ctrl(b, BIO_C_GET_CONNECT, 0, &p));
    printf("conn.get.hostname.isnull=%d\n", p == NULL);
    p = NULL;
    printf("conn.get.port.ret=%ld\n", BIO_ctrl(b, BIO_C_GET_CONNECT, 1, &p));
    printf("conn.get.port.isnull=%d\n", p == NULL);
    p = NULL;
    printf("conn.get.address.ret=%ld\n", BIO_ctrl(b, BIO_C_GET_CONNECT, 2, &p));
    printf("conn.get.address.isnull=%d\n", p == NULL);
    printf("conn.get.family=%ld\n", BIO_get_conn_ip_family(b));
    printf("conn.get.mode=%ld\n", BIO_get_conn_mode(b));
    printf("conn.get.sub5=%ld\n", ctrl(b, BIO_C_GET_CONNECT, 5));

    /* The socket type defaults to a stream, and there is no datagram BIO yet. */
    printf("conn.get.socktype=%ld\n", ctrl(b, BIO_C_GET_SOCK_TYPE, 0));
    printf("conn.get.dgrambio=%ld\n", BIO_ctrl(b, BIO_C_GET_DGRAM_BIO, 0, &inner));
    printf("conn.get.dgrambio.isnull=%d\n", inner == NULL);

    /* `BIO_new` sets `shutdown` to 1, and a fresh BIO has no descriptor. */
    printf("conn.get.fd=%ld\n", ctrl(b, BIO_C_GET_FD, 0));
    printf("conn.get.close=%ld\n", ctrl(b, BIO_CTRL_GET_CLOSE, 0));
    printf("conn.set.close0=%ld\n", ctrl(b, BIO_CTRL_SET_CLOSE, 0));
    printf("conn.get.close.after0=%ld\n", ctrl(b, BIO_CTRL_GET_CLOSE, 0));

    printf("conn.pending=%ld\n", ctrl(b, BIO_CTRL_PENDING, 0));
    printf("conn.wpending=%ld\n", ctrl(b, BIO_CTRL_WPENDING, 0));
    printf("conn.flush=%ld\n", ctrl(b, BIO_CTRL_FLUSH, 0));
    printf("conn.eof=%ld\n", ctrl(b, BIO_CTRL_EOF, 0));
    printf("conn.unknown=%ld\n", ctrl(b, 9999, 0));

    /* The callback is set through the callback control, and the ordinary
     * `SET_CALLBACK` control deliberately reports that it did nothing. */
    printf("conn.ctrl.setcallback=%ld\n", ctrl(b, BIO_CTRL_SET_CALLBACK, 0));
    printf("conn.ctrl.getcallback.ret=%ld\n", BIO_ctrl(b, BIO_CTRL_GET_CALLBACK, 0, &p));
    printf("conn.ctrl.getcallback.isnull=%d\n", p == NULL);

    /* `BIO_C_SET_NBIO` only records the mode on the data block, and there is no
     * datagram BIO to forward it to, so it still reports 1. */
    printf("conn.set.nbio1=%ld\n", ctrl(b, BIO_C_SET_NBIO, 1));
    printf("conn.set.nbio0=%ld\n", ctrl(b, BIO_C_SET_NBIO, 0));

    /* The fast-open and connect-mode controls. */
    printf("conn.set.tfo1=%ld\n", ctrl(b, BIO_C_SET_TFO, 1));
    printf("conn.set.tfo0=%ld\n", ctrl(b, BIO_C_SET_TFO, 0));
    printf("conn.set.mode3=%ld\n", BIO_ctrl(b, BIO_C_SET_CONNECT_MODE, 3, NULL));
    printf("conn.get.mode.after=%ld\n", BIO_get_conn_mode(b));

    /*
     * A state machine with no name at all: `BEFORE` raises and the control
     * answers -1, which is what `BIO_do_connect` reports.
     */
    printf("conn.do_connect.noname=%ld\n", BIO_do_connect(b));
    err_all("conn.do_connect.noname");

    /* An unknown family is refused before the resolver is consulted. */
    printf("conn.set.family999=%ld\n", BIO_int_ctrl(b, BIO_C_SET_CONNECT, 3, 999));
    printf("conn.get.family.after=%ld\n", BIO_get_conn_ip_family(b));
    printf("conn.do_connect.badfamily=%ld\n", BIO_do_connect(b));
    err_all("conn.do_connect.badfamily");

    /* A name with a `host:service` spec sets both halves; a name without one
     * touches only the hostname. */
    printf("conn.set.hostname.plain=%ld\n",
           BIO_ctrl(b, BIO_C_SET_CONNECT, 0, (void *)"127.0.0.1"));
    borrowed = (char *)BIO_get_conn_hostname(b);
    printf("conn.hostname.plain.eq=%d\n", borrowed != NULL && strcmp(borrowed, "127.0.0.1") == 0);
    printf("conn.port.after.plain=%ld\n",
           BIO_ctrl(b, BIO_C_GET_CONNECT, 1, &p));
    printf("conn.port.after.plain.isnull=%d\n", p == NULL);
    printf("conn.set.hostname.withport=%ld\n",
           BIO_ctrl(b, BIO_C_SET_CONNECT, 0, (void *)"127.0.0.1:9"));
    borrowed = (char *)BIO_get_conn_hostname(b);
    printf("conn.hostname.withport.eq=%d\n",
           borrowed != NULL && strcmp(borrowed, "127.0.0.1") == 0);
    borrowed = (char *)BIO_get_conn_port(b);
    printf("conn.port.withport.eq=%d\n", borrowed != NULL && strcmp(borrowed, "9") == 0);

    /* `BIO_set_conn_port` takes only the service half. */
    printf("conn.set.port80=%ld\n", BIO_ctrl(b, BIO_C_SET_CONNECT, 1, (void *)"80"));
    borrowed = (char *)BIO_get_conn_port(b);
    printf("conn.port80.eq=%d\n", borrowed != NULL && strcmp(borrowed, "80") == 0);

    /* A well-formed address becomes a name and a service. */
    {
        BIO_ADDR *a = BIO_ADDR_new();
        struct in_addr in;
        inet_pton(AF_INET, "127.0.0.1", &in);
        BIO_ADDR_rawmake(a, AF_INET, &in, sizeof(in), htons(8080));
        printf("conn.set.address=%ld\n", BIO_ctrl(b, BIO_C_SET_CONNECT, 2, a));
        borrowed = (char *)BIO_get_conn_hostname(b);
        printf("conn.address.host.eq=%d\n",
               borrowed != NULL && strcmp(borrowed, "127.0.0.1") == 0);
        borrowed = (char *)BIO_get_conn_port(b);
        printf("conn.address.port.eq=%d\n", borrowed != NULL && strcmp(borrowed, "8080") == 0);
        BIO_ADDR_free(a);
    }

    printf("conn.set.sub9=%ld\n", ctrl(b, BIO_C_SET_CONNECT, 9));
    printf("conn.free=%d\n", BIO_free(b));
    (void)v;
}

/* ------------------------------------------------------------------------- */
/* Section B — a real connection over loopback.                             */
/* ------------------------------------------------------------------------- */

static void section_connect(void)
{
    BIO *sbio = NULL;
    char *port = NULL;
    BIO *cbio;
    char buf[32];
    BIO_POLL_DESCRIPTOR pd;
    int n;

    sbio = BIO_new_accept("127.0.0.1:0");
    if (sbio == NULL) {
        printf("connect.setup=0\n");
        return;
    }
    printf("connect.setup=1\n");

    /* The first `BIO_do_accept` only binds and listens: it returns 1 with an
     * empty chain, which is what makes the kernel-chosen port observable. */
    printf("connect.accept.listen=%ld\n", BIO_do_accept(sbio));
    err_all("connect.accept.listen");
    port = (char *)BIO_get_accept_port(sbio);
    printf("connect.accept.port.nonempty=%d\n", port != NULL && port[0] != '\0');
    printf("connect.accept.name.eq=%d\n",
           (char *)BIO_get_accept_name(sbio) != NULL
               && strcmp((char *)BIO_get_accept_name(sbio), "127.0.0.1") == 0);
    printf("connect.accept.getfd.ge0=%d\n", ctrl(sbio, BIO_C_GET_FD, 0) >= 0);

    if (port == NULL) {
        printf("connect.noport=1\n");
        BIO_free(sbio);
        return;
    }

    /* A NULL name is refused by `BIO_new_connect`, which frees the BIO again. */
    printf("connect.new.null=%d\n", BIO_new_connect(NULL) == NULL);

    cbio = BIO_new_connect("127.0.0.1");
    printf("connect.client.nonnull=%d\n", cbio != NULL);
    printf("connect.client.set.port=%ld\n", BIO_ctrl(cbio, BIO_C_SET_CONNECT, 1, port));
    BIO_callback_ctrl(cbio, BIO_CTRL_SET_CALLBACK, (BIO_info_cb *)info_cb);
    cb_count = 0;
    printf("connect.client.do_connect=%ld\n", BIO_do_connect(cbio));
    err_all("connect.client.do_connect");
    printf("connect.client.cb.count=%d\n", cb_count);
    printf("connect.client.state.ok=%ld\n", ctrl(cbio, BIO_C_DO_STATE_MACHINE, 0));
    printf("connect.client.fd.ge0=%d\n", ctrl(cbio, BIO_C_GET_FD, 0) >= 0);
    printf("connect.client.port.eq=%d\n",
           (char *)BIO_get_conn_port(cbio) != NULL
               && strcmp((char *)BIO_get_conn_port(cbio), port) == 0);
    printf("connect.client.addr.nonnull=%d\n", BIO_get_conn_address(cbio) != NULL);
    printf("connect.client.family=%ld\n", BIO_get_conn_ip_family(cbio));
    printf("connect.client.eof=%ld\n", ctrl(cbio, BIO_CTRL_EOF, 0));
    memset(&pd, 0, sizeof(pd));
    printf("connect.client.rpoll.ret=%ld\n",
           BIO_ctrl(cbio, BIO_CTRL_GET_RPOLL_DESCRIPTOR, 0, &pd));
    printf("connect.client.rpoll.type=%u\n", (unsigned)pd.type);
    printf("connect.client.rpoll.fd.ge0=%d\n", pd.value.fd >= 0);

    /* A round trip: the client's write reaches the accepted socket. */
    printf("connect.client.write=%d\n", BIO_write(cbio, "ping", 4));
    printf("connect.accept.second=%ld\n", BIO_do_accept(sbio));
    err_all("connect.accept.second");
    n = BIO_read(sbio, buf, sizeof(buf));
    printf("connect.accept.read=%d\n", n);
    printf("connect.accept.bytes=%s\n", n == 4 && memcmp(buf, "ping", 4) == 0 ? "ping" : "<other>");
    printf("connect.accept.peer.name.eq=%d\n",
           (char *)BIO_get_peer_name(sbio) != NULL
               && strcmp((char *)BIO_get_peer_name(sbio), "127.0.0.1") == 0);
    printf("connect.accept.peer.port.nonempty=%d\n",
           (char *)BIO_get_peer_port(sbio) != NULL
               && ((char *)BIO_get_peer_port(sbio))[0] != '\0');
    printf("connect.accept.eof=%ld\n", ctrl(sbio, BIO_CTRL_EOF, 0));

    printf("connect.accept.write=%d\n", BIO_write(sbio, "pong", 4));
    n = BIO_read(cbio, buf, sizeof(buf));
    printf("connect.client.read=%d\n", n);
    printf("connect.client.bytes=%s\n", n == 4 && memcmp(buf, "pong", 4) == 0 ? "pong" : "<other>");

    /* Every further `BIO_do_accept` with a live chain is a no-op that succeeds. */
    printf("connect.accept.again=%ld\n", BIO_do_accept(sbio));
    printf("connect.accept.again.again=%ld\n", BIO_do_accept(sbio));
    err_all("connect.accept.again");

    BIO_free(cbio);
    BIO_free(sbio);
}

/* ------------------------------------------------------------------------- */
/* Section C — a refused connection, and the two-error terminal state.        */
/* ------------------------------------------------------------------------- */

/*
 * A refused connection. The port is **fixed at 1**, which nothing can be
 * listening on without privilege, because the failure text embeds the service
 * and an ephemeral port would make the observation run-dependent. That text is
 * part of the evidence: the error queue carries `calling connect(127.0.0.1, 1)`
 * from `bss_conn.c` *and*, before it, the pair `BIO_connect` raised from
 * `bio_sock2.c` — which only happens because a refused `connect(2)` is not
 * retryable for this method.
 */
static void section_refused(void)
{
    BIO *cbio;

    cbio = BIO_new_connect("127.0.0.1");
    printf("refused.client.nonnull=%d\n", cbio != NULL);
    BIO_callback_ctrl(cbio, BIO_CTRL_SET_CALLBACK, (BIO_info_cb *)info_cb);
    printf("refused.client.set.port=%ld\n", BIO_ctrl(cbio, BIO_C_SET_CONNECT, 1, (void *)"1"));
    cb_count = 0;
    printf("refused.client.do_connect=%ld\n", BIO_do_connect(cbio));
    printf("refused.client.cb.count=%d\n", cb_count);
    err_all("refused.client.do_connect");
    /* The terminal state raises again on the next pass. */
    printf("refused.client.again=%ld\n", ctrl(cbio, BIO_C_DO_STATE_MACHINE, 0));
    err_all("refused.client.again");
    printf("refused.client.eof=%ld\n", ctrl(cbio, BIO_CTRL_EOF, 0));
    BIO_free(cbio);

    /*
     * The same name with no service at all: the machine has a hostname but no
     * service, and the resolver refuses the pair rather than the family.
     */
    cbio = BIO_new_connect("127.0.0.1");
    printf("refused.noservice.nonnull=%d\n", cbio != NULL);
    printf("refused.noservice.do_connect=%ld\n", BIO_do_connect(cbio));
    err_all("refused.noservice.do_connect");
    BIO_free(cbio);
}

/* ------------------------------------------------------------------------- */
/* Section D — the datagram connect mode.                                   */
/* ------------------------------------------------------------------------- */

static void section_dgram_connect(void)
{
    BIO_ADDR *want = BIO_ADDR_new();
    BIO_ADDR *got = BIO_ADDR_new();
    union BIO_sock_info_u info;
    int fd = BIO_socket(AF_INET, SOCK_DGRAM, 0, 0);
    struct in_addr in;
    char port[16];
    BIO *cbio;
    BIO *inner = NULL;
    BIO_MSG m[1];
    char payload[8] = "abc";
    char rx[8];
    size_t done = 0;

    inet_pton(AF_INET, "127.0.0.1", &in);
    BIO_ADDR_rawmake(want, AF_INET, &in, sizeof(in), 0);
    if (fd < 0 || !BIO_bind(fd, want, 0)) {
        printf("dgram.setup=0\n");
        BIO_ADDR_free(want);
        BIO_ADDR_free(got);
        return;
    }
    info.addr = got;
    if (!BIO_sock_info(fd, BIO_SOCK_INFO_ADDRESS, &info)) {
        printf("dgram.setup=0\n");
        BIO_ADDR_free(want);
        BIO_ADDR_free(got);
        BIO_closesocket(fd);
        return;
    }
    {
        char *svc = BIO_ADDR_service_string(got, 1);
        if (svc == NULL) {
            printf("dgram.setup=0\n");
            BIO_ADDR_free(want);
            BIO_ADDR_free(got);
            BIO_closesocket(fd);
            return;
        }
        snprintf(port, sizeof(port), "%s", svc);
        OPENSSL_free(svc);
    }
    printf("dgram.setup=1\n");

    cbio = BIO_new_connect("127.0.0.1");
    printf("dgram.client.nonnull=%d\n", cbio != NULL);
    printf("dgram.set.socktype=%ld\n", BIO_ctrl(cbio, BIO_C_SET_SOCK_TYPE, SOCK_DGRAM, NULL));
    printf("dgram.get.socktype=%ld\n", ctrl(cbio, BIO_C_GET_SOCK_TYPE, 0));
    /* Once the machine has run, the socket type can no longer be changed. */
    printf("dgram.client.set.port=%ld\n",
           BIO_ctrl(cbio, BIO_C_SET_CONNECT, 1, (void *)port));
    printf("dgram.client.do_connect=%ld\n", BIO_do_connect(cbio));
    err_all("dgram.client.do_connect");
    printf("dgram.client.set.socktype.after=%ld\n",
           BIO_ctrl(cbio, BIO_C_SET_SOCK_TYPE, SOCK_STREAM, NULL));
    printf("dgram.get.socktype.after=%ld\n", ctrl(cbio, BIO_C_GET_SOCK_TYPE, 0));

    /* A datagram connect leaves an inner datagram BIO that the batch calls
     * forward to. */
    printf("dgram.get.dgrambio=%ld\n", BIO_ctrl(cbio, BIO_C_GET_DGRAM_BIO, 0, &inner));
    printf("dgram.get.dgrambio.nonnull=%d\n", inner != NULL);
    if (inner != NULL) {
        printf("dgram.inner.name=%s\n", BIO_method_name(inner));
        printf("dgram.inner.fd.ge0=%d\n", ctrl(inner, BIO_C_GET_FD, 0) >= 0);
    }

    /* One datagram through the connect BIO's batch path. */
    memset(m, 0, sizeof(m));
    memset(rx, 0, sizeof(rx));
    m[0].data = payload;
    m[0].data_len = 3;
    printf("dgram.sendmmsg=%d\n", BIO_sendmmsg(cbio, m, sizeof(BIO_MSG), 1, 0, &done));
    printf("dgram.sendmmsg.done=%zu\n", done);
    /* The payload arrives on the plain socket we bound. */
    {
        BIO *dbio = BIO_new_dgram(fd, 0);
        int n = BIO_read(dbio, rx, sizeof(rx));
        printf("dgram.recv=%d\n", n);
        printf("dgram.recv.bytes=%s\n",
               n == 3 && memcmp(rx, "abc", 3) == 0 ? "abc" : "<other>");
        BIO_free(dbio);
    }
    printf("dgram.client.write=%d\n", BIO_write(cbio, "xy", 2));
    printf("dgram.client.eof=%ld\n", ctrl(cbio, BIO_CTRL_EOF, 0));

    BIO_free(cbio);
    BIO_closesocket(fd);
    BIO_ADDR_free(want);
    BIO_ADDR_free(got);
}

/* ------------------------------------------------------------------------- */
/* Section E — the accept BIO's controls.                                   */
/* ------------------------------------------------------------------------- */

static void section_accept_ctrl(void)
{
    BIO *b;
    const char *p = NULL;
    char *borrowed;
    BIO *chain;

    b = BIO_new(BIO_s_accept());
    printf("acpt.method.name=%s\n", BIO_method_name(b));
    printf("acpt.method.type=%d\n", BIO_method_type(b));

    printf("acpt.new.null=%d\n", BIO_new_accept(NULL) == NULL);

    printf("acpt.fresh.nonnull=%d\n", b != NULL);
    /* Before `init` is set, every getter reports -1 rather than a value. */
    printf("acpt.fresh.getaccept.noninit=%ld\n", BIO_ctrl(b, BIO_C_GET_ACCEPT, 0, &p));
    printf("acpt.fresh.getfd=%ld\n", ctrl(b, BIO_C_GET_FD, 0));
    printf("acpt.fresh.close=%ld\n", ctrl(b, BIO_CTRL_GET_CLOSE, 0));
    printf("acpt.fresh.pending=%ld\n", ctrl(b, BIO_CTRL_PENDING, 0));
    printf("acpt.fresh.wpending=%ld\n", ctrl(b, BIO_CTRL_WPENDING, 0));
    printf("acpt.fresh.flush=%ld\n", ctrl(b, BIO_CTRL_FLUSH, 0));
    printf("acpt.fresh.eof=%ld\n", ctrl(b, BIO_CTRL_EOF, 0));
    printf("acpt.fresh.unknown=%ld\n", ctrl(b, 9999, 0));

    /* `BIO_C_SET_ACCEPT` sub-command 0 parses the spec and sets `init`. */
    printf("acpt.set.name=%ld\n", BIO_ctrl(b, BIO_C_SET_ACCEPT, 0, (void *)"127.0.0.1:0"));
    printf("acpt.init.getfd=%ld\n", ctrl(b, BIO_C_GET_FD, 0));
    printf("acpt.getaccept.0.ret=%ld\n", BIO_ctrl(b, BIO_C_GET_ACCEPT, 0, &p));
    printf("acpt.getaccept.0.isnull=%d\n", p == NULL);
    p = NULL;
    printf("acpt.getaccept.1.ret=%ld\n", BIO_ctrl(b, BIO_C_GET_ACCEPT, 1, &p));
    printf("acpt.getaccept.1.isnull=%d\n", p == NULL);
    p = NULL;
    printf("acpt.getaccept.2.ret=%ld\n", BIO_ctrl(b, BIO_C_GET_ACCEPT, 2, &p));
    printf("acpt.getaccept.2.isnull=%d\n", p == NULL);
    p = NULL;
    printf("acpt.getaccept.3.ret=%ld\n", BIO_ctrl(b, BIO_C_GET_ACCEPT, 3, &p));
    printf("acpt.getaccept.3.isnull=%d\n", p == NULL);
    /* Sub-command 4 reports the requested family; the iteration is empty, so the
     * family lookup answers 0 and the stored family is used. */
    printf("acpt.getaccept.4=%ld\n", ctrl(b, BIO_C_GET_ACCEPT, 4));
    printf("acpt.getaccept.5=%ld\n", ctrl(b, BIO_C_GET_ACCEPT, 5));
    borrowed = (char *)BIO_get_accept_name(b);
    printf("acpt.name.eq=%d\n", borrowed != NULL && strcmp(borrowed, "127.0.0.1") == 0);

    /* The bind mode: `0` for reading, and the two flag sub-commands are the only
     * ones that act on a NULL `ptr`. */
    printf("acpt.bindmode.initial=%ld\n", BIO_get_bind_mode(b));
    printf("acpt.set.bindmode.reuse=%ld\n", BIO_ctrl(b, BIO_C_SET_BIND_MODE, 1, NULL));
    printf("acpt.bindmode.after=%ld\n", BIO_get_bind_mode(b));
    printf("acpt.set.nbio.ptr=%ld\n", BIO_ctrl(b, BIO_C_SET_ACCEPT, 2, (void *)"a"));
    printf("acpt.set.nbio.ptr.again=%ld\n", BIO_ctrl(b, BIO_C_SET_ACCEPT, 2, (void *)"a"));
    printf("acpt.set.tfo.ptr=%ld\n", BIO_ctrl(b, BIO_C_SET_ACCEPT, 5, (void *)"a"));
    printf("acpt.set.sub9=%ld\n", BIO_ctrl(b, BIO_C_SET_ACCEPT, 9, (void *)"a"));
    /* A plain `SET_CLOSE` and the `NBIO` control, which sets the mode of the
     * socket that will be *accepted*. */
    printf("acpt.set.nbio.ctrl1=%ld\n", ctrl(b, BIO_C_SET_NBIO, 1));
    printf("acpt.set.nbio.ctrl0=%ld\n", ctrl(b, BIO_C_SET_NBIO, 0));

    /*
     * Bind and listen. `BIO_do_accept` returns 1 here with an empty chain, which
     * is what lets a caller learn the kernel-chosen port without blocking.
     */
    printf("acpt.do_accept=%ld\n", BIO_do_accept(b));
    err_all("acpt.do_accept");
    printf("acpt.do_accept.getfd.ge0=%d\n", ctrl(b, BIO_C_GET_FD, 0) >= 0);
    printf("acpt.do_accept.accepting.name.eq=%d\n",
           (char *)BIO_get_accept_name(b) != NULL
               && strcmp((char *)BIO_get_accept_name(b), "127.0.0.1") == 0);
    printf("acpt.do_accept.accepting.port.nonempty=%d\n",
           (char *)BIO_get_accept_port(b) != NULL
               && ((char *)BIO_get_accept_port(b))[0] != '\0');
    printf("acpt.do_accept.again=%ld\n", BIO_do_accept(b));
    err_all("acpt.do_accept.again");

    /* A chain is stored, not pushed: `BIO_CTRL_EOF` still looks at `next_bio`,
     * which is empty, so it reports "not at end of stream". */
    printf("acpt.set.chain.null=%ld\n", BIO_ctrl(b, BIO_C_SET_ACCEPT, 3, NULL));
    chain = BIO_new(BIO_s_null());
    printf("acpt.set.chain=%ld\n", BIO_ctrl(b, BIO_C_SET_ACCEPT, 3, chain));
    printf("acpt.eof.withchain=%ld\n", ctrl(b, BIO_CTRL_EOF, 0));

    /* Resetting closes the listening socket and returns the state to BEFORE. */
    printf("acpt.reset=%ld\n", ctrl(b, BIO_CTRL_RESET, 0));
    printf("acpt.reset.getfd=%ld\n", ctrl(b, BIO_C_GET_FD, 0));
    printf("acpt.reset.close=%ld\n", ctrl(b, BIO_CTRL_GET_CLOSE, 0));

    /* An unknown family is refused before the resolver is consulted. The state
     * is BEFORE again, so the machine reaches GET_ADDR and stops there. */
    printf("acpt.set.family999=%ld\n", BIO_int_ctrl(b, BIO_C_SET_ACCEPT, 4, 999));
    printf("acpt.get.family.after=%ld\n", ctrl(b, BIO_C_GET_ACCEPT, 4));
    printf("acpt.do_accept.badfamily=%ld\n", BIO_do_accept(b));
    err_all("acpt.do_accept.badfamily");

    printf("acpt.free=%d\n", BIO_free(b));
}

/* ------------------------------------------------------------------------- */
/* Section F — the errno classifiers, whose membership sets differ.          */
/* ------------------------------------------------------------------------- */

/*
 * `RT-BIO-CONN` is where the difference matters: a refused `connect(2)` is not
 * retryable for this method, because `BIO_sock_non_fatal_error` does **not**
 * accept `ECONNREFUSED`. That was a candidate defect until this section existed,
 * and the values below are the whole Linux set the three classifiers can see.
 */
static void section_classifiers(void)
{
    static const struct {
        const char *name;
        int err;
    } errs[] = {
        { "EAGAIN", 11 },
        { "EWOULDBLOCK", 11 },
        { "EINTR", 4 },
        { "ENOTCONN", 107 },
        { "EPROTO", 71 },
        { "EINPROGRESS", 115 },
        { "EALREADY", 114 },
        { "ECONNREFUSED", 111 },
        { "ECONNRESET", 104 },
        { "ENOBUFS", 105 },
        { "EPIPE", 32 },
        { "EBADF", 9 },
        { "EINVAL", 22 },
        { "EISCONN", 106 },
        { "ETIMEDOUT", 110 },
        { "0", 0 },
    };
    size_t i;

    for (i = 0; i < sizeof(errs) / sizeof(errs[0]); i++) {
        char k[96];

        snprintf(k, sizeof(k), "classify.%s.sock", errs[i].name);
        printf("%s=%d\n", k, BIO_sock_non_fatal_error(errs[i].err));
        snprintf(k, sizeof(k), "classify.%s.fd", errs[i].name);
        printf("%s=%d\n", k, BIO_fd_non_fatal_error(errs[i].err));
        snprintf(k, sizeof(k), "classify.%s.dgram", errs[i].name);
        printf("%s=%d\n", k, BIO_dgram_non_fatal_error(errs[i].err));
    }
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    ERR_clear_error();

    section_fresh_connect();
    section_accept_ctrl();
    section_classifiers();
    section_connect();
    section_refused();
    section_dgram_connect();

    printf("probe.done=1\n");
    return 0;
}
