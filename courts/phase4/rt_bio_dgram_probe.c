/*
 * openssl-rs — RT-BIO-DGRAM: differential probe for the kernel datagram BIO.
 *
 * What only this court can see
 * ----------------------------
 * `BIO_s_datagram` carries protocol *state*, so most of its contract is not in
 * the bytes that move but in what the controls answer about that state:
 *
 *   * a fresh BIO's peer is `AF_UNSPEC`, and `BIO_CTRL_DGRAM_GET_PEER` reports
 *     the peer's `BIO_ADDR` size for that family. That value is 112 — the size of
 *     the C union — and a candidate whose internal storage is larger would report
 *     a different number without any visible address differing. The observation is
 *     `fresh.getpeer.ret`.
 *   * `BIO_CTRL_DGRAM_MTU_DISCOVER` returns the *`setsockopt(2)` result*, which is
 *     0 on success, so a "success boolean" implementation returns 1 here.
 *   * `BIO_CTRL_DGRAM_SET_LOCAL_ADDR_ENABLE` returns 1 both when it changes the
 *     socket option and when the requested state is already set.
 *   * `BIO_CTRL_DGRAM_GET_MTU_OVERHEAD` and `GET_FALLBACK_MTU` branch on the peer
 *     family, including the IPv4-mapped IPv6 case, so the probe drives all four
 *     families through `BIO_CTRL_DGRAM_SET_CONNECTED`.
 *   * `BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT` is a *deadline*, not a duration, and the
 *     read bracket shortens `SO_RCVTIMEO` to it and then restores the socket's own
 *     timeout. The probe measures that by blocking a read until the deadline and
 *     then reading the socket timeout back.
 *   * the timer-expiry and MTU-exceeded controls read a stored `errno` that only a
 *     failed read or write sets, so the probe produces a real `EAGAIN` first.
 *
 * Determinism rules, because the two sides are separate processes
 * --------------------------------------------------------------
 *   * ephemeral ports differ between runs, so a port is only ever printed as a
 *     *relation* against another port learned in the same process.
 *   * file descriptors are printed as predicates, never as values.
 *   * `errno` values are printed, because they are Linux constants.
 *   * the one timing observation is a coarse predicate (the read returned before a
 *     much later bound), not a duration.
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
#include <sys/time.h>
#include <time.h>

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

/* A loopback address with a chosen port; port 0 asks the kernel to choose. */
static BIO_ADDR *make_loopback(unsigned short port)
{
    struct in_addr in;
    BIO_ADDR *a = BIO_ADDR_new();

    inet_pton(AF_INET, "127.0.0.1", &in);
    BIO_ADDR_rawmake(a, AF_INET, &in, sizeof(in), port);
    return a;
}

/* A bound IPv4 UDP socket, and the address it is bound to. */
static int bound_udp(BIO_ADDR **addr_out)
{
    int fd = BIO_socket(AF_INET, SOCK_DGRAM, 0, 0);
    BIO_ADDR *want = make_loopback(0);
    union BIO_sock_info_u info;
    BIO_ADDR *got = BIO_ADDR_new();

    if (fd < 0) {
        BIO_ADDR_free(want);
        BIO_ADDR_free(got);
        return -1;
    }
    if (!BIO_bind(fd, want, 0)) {
        BIO_ADDR_free(want);
        BIO_ADDR_free(got);
        BIO_closesocket(fd);
        return -1;
    }
    info.addr = got;
    if (!BIO_sock_info(fd, BIO_SOCK_INFO_ADDRESS, &info)) {
        BIO_ADDR_free(want);
        BIO_ADDR_free(got);
        BIO_closesocket(fd);
        return -1;
    }
    BIO_ADDR_free(want);
    *addr_out = got;
    return fd;
}

/* Print an address through the public accessors only, and drain whatever the
 * accessors raised (a hostname for an `AF_UNSPEC` address is a failure, and it
 * raises rather than only returning NULL). */
static void show_addr(const char *key, const BIO_ADDR *a)
{
    char k[96];
    char *s;

    snprintf(k, sizeof(k), "%s.family", key);
    printf("%s=%d\n", k, BIO_ADDR_family(a));
    snprintf(k, sizeof(k), "%s.rawport.nonzero", key);
    printf("%s=%d\n", k, BIO_ADDR_rawport(a) != 0);
    s = BIO_ADDR_hostname_string(a, 1);
    snprintf(k, sizeof(k), "%s.host", key);
    printf("%s=%s\n", k, s ? s : "<NULL>");
    OPENSSL_free(s);
    snprintf(k, sizeof(k), "%s.err", key);
    err_all(k);
}

/* The same address, compared against one learned earlier in this process. */
static void show_addr_eq(const char *key, const BIO_ADDR *a, const BIO_ADDR *b)
{
    char k[96];

    snprintf(k, sizeof(k), "%s.family.eq", key);
    printf("%s=%d\n", k, BIO_ADDR_family(a) == BIO_ADDR_family(b));
    snprintf(k, sizeof(k), "%s.rawport.eq", key);
    printf("%s=%d\n", k, BIO_ADDR_rawport(a) == BIO_ADDR_rawport(b));
    snprintf(k, sizeof(k), "%s.err", key);
    err_all(k);
}

static long ctrl_int(BIO *b, int cmd, long num)
{
    return BIO_ctrl(b, cmd, num, NULL);
}

/* ------------------------------------------------------------------------- */
/* Section A — the method table and a fresh BIO's controls.                  */
/* ------------------------------------------------------------------------- */

static void section_fresh(void)
{
    BIO *b = BIO_new(BIO_s_datagram());
    BIO_ADDR *got = BIO_ADDR_new();
    BIO_POLL_DESCRIPTOR pd;
    int v = 12345;
    struct timeval tv;

    printf("fresh.method.name=%s\n", BIO_method_name(b));
    printf("fresh.method.type=%d\n", BIO_method_type(b));

    printf("fresh.ctrl.reset=%ld\n", ctrl_int(b, BIO_CTRL_RESET, 0));
    printf("fresh.ctrl.info=%ld\n", ctrl_int(b, BIO_CTRL_INFO, 0));
    printf("fresh.ctrl.pending=%ld\n", ctrl_int(b, BIO_CTRL_PENDING, 0));
    printf("fresh.ctrl.wpending=%ld\n", ctrl_int(b, BIO_CTRL_WPENDING, 0));
    printf("fresh.ctrl.dup=%ld\n", ctrl_int(b, BIO_CTRL_DUP, 0));
    printf("fresh.ctrl.flush=%ld\n", ctrl_int(b, BIO_CTRL_FLUSH, 0));
    /* `init` is 0 until a descriptor is set, so the getter reports -1. */
    printf("fresh.ctrl.getfd=%ld\n", ctrl_int(b, BIO_C_GET_FD, 0));
    printf("fresh.ctrl.getclose=%ld\n", ctrl_int(b, BIO_CTRL_GET_CLOSE, 0));
    printf("fresh.ctrl.setclose7=%ld\n", ctrl_int(b, BIO_CTRL_SET_CLOSE, 7));
    printf("fresh.ctrl.getclose.after7=%ld\n", ctrl_int(b, BIO_CTRL_GET_CLOSE, 0));
    printf("fresh.ctrl.unknown=%ld\n", ctrl_int(b, 9999, 0));

    /* The local-address capability and the effective capability mask. */
    printf("fresh.locaddr.cap=%ld\n", ctrl_int(b, BIO_CTRL_DGRAM_GET_LOCAL_ADDR_CAP, 0));
    printf("fresh.effective.caps=%ld\n", ctrl_int(b, BIO_CTRL_DGRAM_GET_EFFECTIVE_CAPS, 0));
    v = 12345;
    printf("fresh.locaddr.get.enable.ret=%ld\n",
           BIO_ctrl(b, BIO_CTRL_DGRAM_GET_LOCAL_ADDR_ENABLE, 0, &v));
    printf("fresh.locaddr.get.enable.value=%d\n", v);

    /* The MTU controls: a fresh BIO has a zero cached MTU and an AF_UNSPEC peer. */
    printf("fresh.mtu.get=%ld\n", ctrl_int(b, BIO_CTRL_DGRAM_GET_MTU, 0));
    printf("fresh.mtu.set1500=%ld\n", ctrl_int(b, BIO_CTRL_DGRAM_SET_MTU, 1500));
    printf("fresh.mtu.get.after=%ld\n", ctrl_int(b, BIO_CTRL_DGRAM_GET_MTU, 0));
    printf("fresh.mtu.overhead.afunspec=%ld\n", ctrl_int(b, BIO_CTRL_DGRAM_GET_MTU_OVERHEAD, 0));
    printf("fresh.mtu.fallback.afunspec=%ld\n", ctrl_int(b, BIO_CTRL_DGRAM_GET_FALLBACK_MTU, 0));

    /*
     * The peer is AF_UNSPEC, so `BIO_ADDR_sockaddr_size` answers the size of the
     * BIO_ADDR union. This is the observation that pins the internal storage size.
     */
    printf("fresh.getpeer.ret=%ld\n", BIO_ctrl(b, BIO_CTRL_DGRAM_GET_PEER, 0, got));
    show_addr("fresh.getpeer", got);
    BIO_ADDR_clear(got);
    printf("fresh.getpeer.num16.ret=%ld\n", BIO_ctrl(b, BIO_CTRL_DGRAM_GET_PEER, 16, got));
    show_addr("fresh.getpeer.num16", got);
    BIO_ADDR_clear(got);
    /* A peer address is absent (AF_UNSPEC) and the socket is not connected. */
    printf("fresh.detectpeer.ret=%ld\n",
           BIO_ctrl(b, BIO_CTRL_DGRAM_DETECT_PEER_ADDR, 0, got));
    show_addr("fresh.detectpeer", got);

    /* The stored-errno controls, before any failing transfer. */
    printf("fresh.timer.exp.recv=%ld\n", ctrl_int(b, BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP, 0));
    printf("fresh.timer.exp.send=%ld\n", ctrl_int(b, BIO_CTRL_DGRAM_GET_SEND_TIMER_EXP, 0));
    printf("fresh.mtu.exceeded=%ld\n", ctrl_int(b, BIO_CTRL_DGRAM_MTU_EXCEEDED, 0));

    /* Peek mode, and the collision-preserving control value. */
    printf("fresh.peekmode.set1=%ld\n", ctrl_int(b, BIO_CTRL_DGRAM_SET_PEEK_MODE, 1));
    printf("fresh.peekmode.set0=%ld\n", ctrl_int(b, BIO_CTRL_DGRAM_SET_PEEK_MODE, 0));
    printf("fresh.sctp.inhandshake=%ld\n",
           ctrl_int(b, BIO_CTRL_DGRAM_SCTP_SET_IN_HANDSHAKE, 0));

    /* The poll descriptor reports the descriptor, which is 0 for a fresh BIO. */
    memset(&pd, 0, sizeof(pd));
    printf("fresh.rpoll.ret=%ld\n", BIO_ctrl(b, BIO_CTRL_GET_RPOLL_DESCRIPTOR, 0, &pd));
    printf("fresh.rpoll.type=%u\n", (unsigned)pd.type);
    printf("fresh.rpoll.fd=%d\n", (int)pd.value.fd);
    memset(&pd, 0, sizeof(pd));
    printf("fresh.wpoll.ret=%ld\n", BIO_ctrl(b, BIO_CTRL_GET_WPOLL_DESCRIPTOR, 0, &pd));
    printf("fresh.wpoll.type=%u\n", (unsigned)pd.type);

    /* A deadline on a BIO with no descriptor: stored, not applied. */
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    printf("fresh.nexttimeout.ret=%ld\n",
           BIO_ctrl(b, BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT, 0, &tv));

    BIO_ADDR_free(got);
    printf("fresh.free=%d\n", BIO_free(b));
}

/* ------------------------------------------------------------------------- */
/* Section B — an invalid descriptor: every syscall path fails, and raises.   */
/* ------------------------------------------------------------------------- */

static void section_badfd(void)
{
    BIO *b = BIO_new_dgram(-1, 0);
    BIO_ADDR *got = BIO_ADDR_new();
    struct timeval tv;
    int v = 0;

    printf("badfd.init.getfd=%ld\n", ctrl_int(b, BIO_C_GET_FD, 0));
    printf("badfd.getpeer.ret=%ld\n", BIO_ctrl(b, BIO_CTRL_DGRAM_GET_PEER, 0, got));
    show_addr("badfd.getpeer", got);
    /* The local address could not be learned, so the family stays AF_UNSPEC and
     * `enable_local_addr` cannot pick a socket option. */
    printf("badfd.locaddr.cap=%ld\n", ctrl_int(b, BIO_CTRL_DGRAM_GET_LOCAL_ADDR_CAP, 0));
    printf("badfd.locaddr.set1=%ld\n",
           ctrl_int(b, BIO_CTRL_DGRAM_SET_LOCAL_ADDR_ENABLE, 1));
    printf("badfd.locaddr.get.ret=%ld\n",
           BIO_ctrl(b, BIO_CTRL_DGRAM_GET_LOCAL_ADDR_ENABLE, 0, &v));
    printf("badfd.locaddr.get.value=%d\n", v);
    printf("badfd.discover=%ld\n", ctrl_int(b, BIO_CTRL_DGRAM_MTU_DISCOVER, 0));
    printf("badfd.querymtu=%ld\n", ctrl_int(b, BIO_CTRL_DGRAM_QUERY_MTU, 0));
    printf("badfd.dontfrag1=%ld\n", ctrl_int(b, BIO_CTRL_DGRAM_SET_DONT_FRAG, 1));
    printf("badfd.nbio1=%ld\n", ctrl_int(b, BIO_C_SET_NBIO, 1));
    /* `BIO_socket_nbio` goes through `BIO_socket_ioctl`, which raises. */
    err_all("badfd.nbio1");

    tv.tv_sec = 1;
    tv.tv_usec = 0;
    printf("badfd.setrecv=%ld\n", BIO_ctrl(b, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &tv));
    err_all("badfd.setrecv");
    printf("badfd.getrecv=%ld\n", BIO_ctrl(b, BIO_CTRL_DGRAM_GET_RECV_TIMEOUT, 0, &tv));
    err_all("badfd.getrecv");
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    printf("badfd.setsend=%ld\n", BIO_ctrl(b, BIO_CTRL_DGRAM_SET_SEND_TIMEOUT, 0, &tv));
    err_all("badfd.setsend");
    printf("badfd.getsend=%ld\n", BIO_ctrl(b, BIO_CTRL_DGRAM_GET_SEND_TIMEOUT, 0, &tv));
    err_all("badfd.getsend");
    printf("badfd.getrecv.tv.after=%ld.%ld\n", (long)tv.tv_sec, (long)tv.tv_usec);

    /* A read and a write on an invalid descriptor: no raise, only a return. */
    {
        char buf[8];
        printf("badfd.read=%d\n", BIO_read(b, buf, sizeof(buf)));
        err_all("badfd.read");
        printf("badfd.write=%d\n", BIO_write(b, "xy", 2));
        err_all("badfd.write");
        printf("badfd.retry.read=%d\n", BIO_should_retry(b));
    }

    BIO_ADDR_free(got);
    printf("badfd.free=%d\n", BIO_free(b));
}

/* ------------------------------------------------------------------------- */
/* Section C — a connected loopback pair: transfers, peer learning, timeouts. */
/* ------------------------------------------------------------------------- */

static void section_transfer(void)
{
    BIO_ADDR *srv_addr = NULL;
    int srv_fd = bound_udp(&srv_addr);
    int cli_fd = BIO_socket(AF_INET, SOCK_DGRAM, 0, 0);
    BIO_ADDR *cli_addr = BIO_ADDR_new();
    union BIO_sock_info_u info;
    BIO *sbio, *cbio;
    BIO_ADDR *got = BIO_ADDR_new();
    char buf[64];
    int n;

    if (srv_fd < 0 || cli_fd < 0) {
        printf("transfer.setup=0\n");
        BIO_ADDR_free(srv_addr);
        BIO_ADDR_free(cli_addr);
        BIO_ADDR_free(got);
        return;
    }
    printf("transfer.setup=1\n");

    info.addr = cli_addr;
    printf("transfer.client.bound=%d\n", BIO_sock_info(cli_fd, BIO_SOCK_INFO_ADDRESS, &info));
    printf("transfer.client.connect=%d\n", BIO_connect(cli_fd, srv_addr, 0));

    sbio = BIO_new_dgram(srv_fd, 0);
    cbio = BIO_new_dgram(cli_fd, 0);

    /*
     * The client socket was connected before the BIO was made, so `BIO_set_fd`
     * detected the peer through `getpeername(2)` and the client BIO is
     * "connected": its peer size is the IPv4 sockaddr. The server BIO is not, and
     * its peer is still AF_UNSPEC.
     */
    printf("transfer.client.getpeer.ret=%ld\n", BIO_ctrl(cbio, BIO_CTRL_DGRAM_GET_PEER, 0, got));
    show_addr("transfer.client.getpeer", got);
    show_addr_eq("transfer.client.peer", got, srv_addr);
    BIO_ADDR_clear(got);
    printf("transfer.server.getpeer.ret=%ld\n", BIO_ctrl(sbio, BIO_CTRL_DGRAM_GET_PEER, 0, got));
    show_addr("transfer.server.getpeer", got);
    BIO_ADDR_clear(got);

    /* A backend query for the descriptor. */
    printf("transfer.server.getfd=%ld\n", ctrl_int(sbio, BIO_C_GET_FD, 0));

    /* One datagram, client to server. */
    printf("transfer.write=%d\n", BIO_write(cbio, "hello", 5));
    n = BIO_read(sbio, buf, sizeof(buf));
    printf("transfer.read.ret=%d\n", n);
    printf("transfer.read.bytes=%s\n", n == 5 && memcmp(buf, "hello", 5) == 0 ? "hello" : "<other>");

    /* Reading learned the sender, so the server BIO now has a peer address. */
    printf("transfer.server.getpeer.after=%ld\n",
           BIO_ctrl(sbio, BIO_CTRL_DGRAM_GET_PEER, 0, got));
    show_addr("transfer.server.peer.after", got);
    show_addr_eq("transfer.server.peer.after", got, cli_addr);
    BIO_ADDR_clear(got);

    /* The MTU controls against a real IPv4 peer. */
    printf("transfer.mtu.overhead=%ld\n", ctrl_int(sbio, BIO_CTRL_DGRAM_GET_MTU_OVERHEAD, 0));
    printf("transfer.mtu.fallback=%ld\n", ctrl_int(sbio, BIO_CTRL_DGRAM_GET_FALLBACK_MTU, 0));
    printf("transfer.mtu.discover=%ld\n", ctrl_int(sbio, BIO_CTRL_DGRAM_MTU_DISCOVER, 0));
    /*
     * `IP_MTU` needs a route, which an unconnected socket may or may not have
     * cached. The value is therefore printed only as a relation: whether the
     * query answered zero, and whether the cache the control wrote agrees with
     * what it returned.
     */
    {
        long q = ctrl_int(sbio, BIO_CTRL_DGRAM_QUERY_MTU, 0);
        long cached = ctrl_int(sbio, BIO_CTRL_DGRAM_GET_MTU, 0);
        printf("transfer.mtu.query.zero=%d\n", q == 0);
        printf("transfer.mtu.cached.eq.query=%d\n", cached == (q > 0 ? q : 0));
    }
    printf("transfer.mtu.dontfrag1=%ld\n", ctrl_int(sbio, BIO_CTRL_DGRAM_SET_DONT_FRAG, 1));
    printf("transfer.mtu.dontfrag0=%ld\n", ctrl_int(sbio, BIO_CTRL_DGRAM_SET_DONT_FRAG, 0));
    err_all("transfer.mtu.dontfrag");

    /* A non-blocking read with an empty queue is a real EAGAIN. */
    printf("transfer.nbio=%ld\n", ctrl_int(sbio, BIO_C_SET_NBIO, 1));
    printf("transfer.empty.read=%d\n", BIO_read(sbio, buf, sizeof(buf)));
    printf("transfer.empty.retry=%d\n", BIO_should_retry(sbio));
    /* The stored errno is now EAGAIN, which the expiry control consumes once. */
    printf("transfer.timer.exp.recv=%ld\n", ctrl_int(sbio, BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP, 0));
    printf("transfer.timer.exp.recv.again=%ld\n",
           ctrl_int(sbio, BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP, 0));
    printf("transfer.timer.exp.send=%ld\n", ctrl_int(sbio, BIO_CTRL_DGRAM_GET_SEND_TIMER_EXP, 0));
    printf("transfer.mtu.exceeded=%ld\n", ctrl_int(sbio, BIO_CTRL_DGRAM_MTU_EXCEEDED, 0));

    /* The socket-timeout controls, which report the `setsockopt(2)` result. */
    {
        struct timeval tv = { 3, 250000 };
        struct timeval back = { 0, 0 };
        printf("transfer.setrecv=%ld\n", BIO_ctrl(sbio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &tv));
        printf("transfer.getrecv.ret=%ld\n",
               BIO_ctrl(sbio, BIO_CTRL_DGRAM_GET_RECV_TIMEOUT, 0, &back));
        printf("transfer.getrecv.tv=%ld.%ld\n", (long)back.tv_sec, (long)back.tv_usec);
        tv.tv_sec = 2;
        tv.tv_usec = 125000;
        printf("transfer.setsend=%ld\n", BIO_ctrl(sbio, BIO_CTRL_DGRAM_SET_SEND_TIMEOUT, 0, &tv));
        printf("transfer.getsend.ret=%ld\n",
               BIO_ctrl(sbio, BIO_CTRL_DGRAM_GET_SEND_TIMEOUT, 0, &back));
        printf("transfer.getsend.tv=%ld.%ld\n", (long)back.tv_sec, (long)back.tv_usec);
    }

    /* Disable the timeout so the next section's blocking read is controlled by
     * the deadline alone. */
    {
        struct timeval zero = { 0, 0 };
        printf("transfer.setrecv.zero=%ld\n",
               BIO_ctrl(sbio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &zero));
    }

    /* A local address can be set on the client, which identifies the sender. */
    printf("transfer.locaddr.set1=%ld\n",
           ctrl_int(cbio, BIO_CTRL_DGRAM_SET_LOCAL_ADDR_ENABLE, 1));
    printf("transfer.locaddr.set1.again=%ld\n",
           ctrl_int(cbio, BIO_CTRL_DGRAM_SET_LOCAL_ADDR_ENABLE, 1));
    {
        int v = -1;
        BIO_ctrl(cbio, BIO_CTRL_DGRAM_GET_LOCAL_ADDR_ENABLE, 0, &v);
        printf("transfer.locaddr.get=%d\n", v);
    }
    printf("transfer.locaddr.set0=%ld\n",
           ctrl_int(cbio, BIO_CTRL_DGRAM_SET_LOCAL_ADDR_ENABLE, 0));

    BIO_free(cbio);
    BIO_free(sbio);
    BIO_ADDR_free(got);
    BIO_ADDR_free(srv_addr);
    BIO_ADDR_free(cli_addr);
}

/* ------------------------------------------------------------------------- */
/* Section D — the receive-timeout bracket around a real deadline.            */
/* ------------------------------------------------------------------------- */

static void section_deadline(void)
{
    BIO_ADDR *srv_addr = NULL;
    int srv_fd = bound_udp(&srv_addr);
    BIO *sbio;
    struct timeval ten = { 10, 0 };
    struct timeval back = { 0, 0 };
    struct timeval now;
    struct timeval deadline;
    struct timespec t0, t1;
    char buf[16];
    int r;

    if (srv_fd < 0) {
        printf("deadline.setup=0\n");
        BIO_ADDR_free(srv_addr);
        return;
    }
    printf("deadline.setup=1\n");
    sbio = BIO_new_dgram(srv_fd, 0);

    printf("deadline.setrecv10=%ld\n", BIO_ctrl(sbio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &ten));
    printf("deadline.getrecv.ret=%ld\n",
           BIO_ctrl(sbio, BIO_CTRL_DGRAM_GET_RECV_TIMEOUT, 0, &back));
    printf("deadline.getrecv.tv=%ld.%ld\n", (long)back.tv_sec, (long)back.tv_usec);

    /*
     * Arm a deadline 400 ms away. The socket's own timeout is 10 s, so the
     * bracket must shorten `SO_RCVTIMEO` to the deadline, the read must return
     * with EAGAIN shortly after, and the socket timeout must be restored.
     */
    gettimeofday(&now, NULL);
    deadline.tv_sec = now.tv_sec;
    deadline.tv_usec = now.tv_usec + 400000;
    if (deadline.tv_usec >= 1000000) {
        deadline.tv_usec -= 1000000;
        deadline.tv_sec += 1;
    }
    printf("deadline.setnext=%ld\n",
           BIO_ctrl(sbio, BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT, 0, &deadline));

    clock_gettime(CLOCK_MONOTONIC, &t0);
    r = BIO_read(sbio, buf, sizeof(buf));
    clock_gettime(CLOCK_MONOTONIC, &t1);
    printf("deadline.read=%d\n", r);
    /* The deadline fired long before the 10-second socket timeout would have. */
    {
        long ms = (t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000;
        printf("deadline.elapsed.under5s=%d\n", ms < 5000);
    }
    err_all("deadline.read");
    printf("deadline.timer.exp=%ld\n", ctrl_int(sbio, BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP, 0));
    printf("deadline.timer.exp.again=%ld\n",
           ctrl_int(sbio, BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP, 0));

    /* The bracket restored the socket's own timeout, not the deadline. */
    printf("deadline.getrecv.after.ret=%ld\n",
           BIO_ctrl(sbio, BIO_CTRL_DGRAM_GET_RECV_TIMEOUT, 0, &back));
    printf("deadline.getrecv.after.tv=%ld.%ld\n", (long)back.tv_sec, (long)back.tv_usec);

    BIO_free(sbio);
    BIO_ADDR_free(srv_addr);
}

/* ------------------------------------------------------------------------- */
/* Section E — the message batches.                                          */
/* ------------------------------------------------------------------------- */

static void section_mmsg(void)
{
    BIO_ADDR *srv_addr = NULL;
    int srv_fd = bound_udp(&srv_addr);
    int cli_fd = BIO_socket(AF_INET, SOCK_DGRAM, 0, 0);
    BIO *sbio, *cbio;
    BIO_MSG m[2];
    BIO_ADDR *local = BIO_ADDR_new();
    char d0[8] = "abc";
    char d1[8] = "defgh";
    char r0[8], r1[8];
    size_t done = 77;
    int r;

    if (srv_fd < 0 || cli_fd < 0) {
        printf("mmsg.setup=0\n");
        BIO_ADDR_free(srv_addr);
        BIO_ADDR_free(local);
        return;
    }
    printf("mmsg.setup=1\n");
    printf("mmsg.client.connect=%d\n", BIO_connect(cli_fd, srv_addr, 0));
    sbio = BIO_new_dgram(srv_fd, 0);
    cbio = BIO_new_dgram(cli_fd, 0);

    /* An empty batch succeeds without touching the socket. */
    done = 77;
    printf("mmsg.send.num0.ret=%d\n", BIO_sendmmsg(cbio, m, sizeof(BIO_MSG), 0, 0, &done));
    printf("mmsg.send.num0.done=%zu\n", done);
    done = 77;
    printf("mmsg.recv.num0.ret=%d\n", BIO_recvmmsg(sbio, m, sizeof(BIO_MSG), 0, 0, &done));
    printf("mmsg.recv.num0.done=%zu\n", done);

    /* Two datagrams in one call. The client is connected, so no peer is needed. */
    memset(m, 0, sizeof(m));
    m[0].data = d0;
    m[0].data_len = 3;
    m[1].data = d1;
    m[1].data_len = 5;
    done = 0;
    printf("mmsg.send.ret=%d\n", BIO_sendmmsg(cbio, m, sizeof(BIO_MSG), 2, 0, &done));
    printf("mmsg.send.done=%zu\n", done);
    printf("mmsg.send.len0=%zu\n", m[0].data_len);
    printf("mmsg.send.len1=%zu\n", m[1].data_len);
    printf("mmsg.send.flags0=%llu\n", (unsigned long long)m[0].flags);

    memset(m, 0, sizeof(m));
    memset(r0, 0, sizeof(r0));
    memset(r1, 0, sizeof(r1));
    m[0].data = r0;
    m[0].data_len = sizeof(r0);
    m[1].data = r1;
    m[1].data_len = sizeof(r1);
    done = 0;
    printf("mmsg.recv.ret=%d\n", BIO_recvmmsg(sbio, m, sizeof(BIO_MSG), 2, 0, &done));
    printf("mmsg.recv.done=%zu\n", done);
    printf("mmsg.recv.len0=%zu\n", m[0].data_len);
    printf("mmsg.recv.len1=%zu\n", m[1].data_len);
    printf("mmsg.recv.bytes0=%s\n", r0);
    printf("mmsg.recv.bytes1=%s\n", r1);

    /* Asking for the local address without enabling it fails the whole batch. */
    memset(m, 0, sizeof(m));
    m[0].data = d0;
    m[0].data_len = 3;
    m[0].local = local;
    done = 77;
    printf("mmsg.send.local.disabled.ret=%d\n",
           BIO_sendmmsg(cbio, m, sizeof(BIO_MSG), 1, 0, &done));
    printf("mmsg.send.local.disabled.done=%zu\n", done);
    err_all("mmsg.send.local.disabled");

    {
        char rr[8];
        memset(m, 0, sizeof(m));
        memset(rr, 0, sizeof(rr));
        m[0].data = rr;
        m[0].data_len = sizeof(rr);
        m[0].local = local;
        done = 77;
        printf("mmsg.recv.local.disabled.ret=%d\n",
               BIO_recvmmsg(sbio, m, sizeof(BIO_MSG), 1, 0, &done));
        printf("mmsg.recv.local.disabled.done=%zu\n", done);
        err_all("mmsg.recv.local.disabled");
    }

    /* With it enabled, the batch carries the record and the receive fills it. */
    printf("mmsg.locaddr.enable=%ld\n",
           ctrl_int(cbio, BIO_CTRL_DGRAM_SET_LOCAL_ADDR_ENABLE, 1));
    printf("mmsg.locaddr.enable.server=%ld\n",
           ctrl_int(sbio, BIO_CTRL_DGRAM_SET_LOCAL_ADDR_ENABLE, 1));

    memset(m, 0, sizeof(m));
    m[0].data = d0;
    m[0].data_len = 3;
    m[0].local = local;
    done = 0;
    r = BIO_sendmmsg(cbio, m, sizeof(BIO_MSG), 1, 0, &done);
    printf("mmsg.send.local.ret=%d\n", r);
    printf("mmsg.send.local.done=%zu\n", done);

    {
        char rr[8];
        BIO_ADDR *seen = BIO_ADDR_new();
        BIO_ADDR *own = BIO_ADDR_new();
        union BIO_sock_info_u info;
        memset(m, 0, sizeof(m));
        memset(rr, 0, sizeof(rr));
        m[0].data = rr;
        m[0].data_len = sizeof(rr);
        m[0].local = seen;
        done = 0;
        printf("mmsg.recv.local.ret=%d\n",
               BIO_recvmmsg(sbio, m, sizeof(BIO_MSG), 1, 0, &done));
        printf("mmsg.recv.local.done=%zu\n", done);
        printf("mmsg.recv.local.bytes=%s\n", rr);
        show_addr("mmsg.recv.local", seen);
        printf("mmsg.recv.local.is.loopback=%d\n",
               BIO_ADDR_family(seen) == AF_INET);
        /* The port the kernel reported is the server's own bound port. */
        info.addr = own;
        if (BIO_sock_info(srv_fd, BIO_SOCK_INFO_ADDRESS, &info))
            show_addr_eq("mmsg.recv.local.vs.server", seen, own);
        BIO_ADDR_free(seen);
        BIO_ADDR_free(own);
    }

    BIO_free(cbio);
    BIO_free(sbio);
    BIO_ADDR_free(local);
    BIO_ADDR_free(srv_addr);
}

/* ------------------------------------------------------------------------- */
/* Section F — the address controls and the method-level raw I/O.             */
/* ------------------------------------------------------------------------- */

static void section_addr_ctrl(void)
{
    /*
     * A real IPv4 socket, so the fragmentation control reaches a kernel that can
     * accept it for an IPv4 peer and reject it for an IPv6 one; an unbound UDP
     * socket is enough for `setsockopt(2)`.
     */
    int fd = BIO_socket(AF_INET, SOCK_DGRAM, 0, 0);
    BIO *b;
    BIO_ADDR *v4 = make_loopback(0);
    BIO_ADDR *v6 = BIO_ADDR_new();
    BIO_ADDR *got = BIO_ADDR_new();
    size_t rawlen = 0;
    unsigned char mapped[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1 };
    unsigned char plain[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

    if (fd < 0) {
        printf("addr.setup=0\n");
        BIO_ADDR_free(got);
        BIO_ADDR_free(v6);
        BIO_ADDR_free(v4);
        return;
    }
    printf("addr.setup=1\n");
    b = BIO_new_dgram(fd, 0);

    /* An IPv4 peer. */
    printf("addr.setpeer.v4=%ld\n", BIO_ctrl(b, BIO_CTRL_DGRAM_SET_PEER, 0, v4));
    printf("addr.overhead.v4=%ld\n", ctrl_int(b, BIO_CTRL_DGRAM_GET_MTU_OVERHEAD, 0));
    printf("addr.fallback.v4=%ld\n", ctrl_int(b, BIO_CTRL_DGRAM_GET_FALLBACK_MTU, 0));
    printf("addr.getpeer.v4.ret=%ld\n", BIO_ctrl(b, BIO_CTRL_DGRAM_GET_PEER, 0, got));
    show_addr_eq("addr.getpeer.v4", got, v4);
    BIO_ADDR_clear(got);
    printf("addr.dontfrag.v4=%ld\n", ctrl_int(b, BIO_CTRL_DGRAM_SET_DONT_FRAG, 1));
    err_all("addr.dontfrag.v4");
    printf("addr.dontfrag.v4.off=%ld\n", ctrl_int(b, BIO_CTRL_DGRAM_SET_DONT_FRAG, 0));
    err_all("addr.dontfrag.v4.off");

    /* `BIO_CTRL_DGRAM_CONNECT` sets the same peer through a different door. */
    printf("addr.connect.v4=%ld\n", BIO_ctrl(b, BIO_CTRL_DGRAM_CONNECT, 0, v4));
    printf("addr.overhead.after.connect=%ld\n", ctrl_int(b, BIO_CTRL_DGRAM_GET_MTU_OVERHEAD, 0));
    printf("addr.setconnected.v4=%ld\n", BIO_ctrl(b, BIO_CTRL_DGRAM_SET_CONNECTED, 0, v4));
    printf("addr.getpeer.connected.ret=%ld\n", BIO_ctrl(b, BIO_CTRL_DGRAM_GET_PEER, 0, got));
    show_addr_eq("addr.getpeer.connected", got, v4);
    BIO_ADDR_clear(got);

    /* An IPv6 peer: 48 bytes of overhead, a 1280-byte fallback. */
    BIO_ADDR_rawmake(v6, AF_INET6, plain, sizeof(plain), 0);
    printf("addr.setpeer.v6=%ld\n", BIO_ctrl(b, BIO_CTRL_DGRAM_SET_PEER, 0, v6));
    printf("addr.overhead.v6=%ld\n", ctrl_int(b, BIO_CTRL_DGRAM_GET_MTU_OVERHEAD, 0));
    printf("addr.fallback.v6=%ld\n", ctrl_int(b, BIO_CTRL_DGRAM_GET_FALLBACK_MTU, 0));
    /* The socket is AF_INET, so an IPv6-level option is rejected. */
    printf("addr.dontfrag.v6=%ld\n", ctrl_int(b, BIO_CTRL_DGRAM_SET_DONT_FRAG, 1));
    err_all("addr.dontfrag.v6");
    rawlen = 0;
    printf("addr.v6.rawaddress=%d\n",
           BIO_ADDR_rawaddress(v6, NULL, &rawlen));
    printf("addr.v6.rawlen=%zu\n", rawlen);

    /* An IPv4-mapped IPv6 peer is charged the IPv4 overhead and fallback. */
    BIO_ADDR_rawmake(v6, AF_INET6, mapped, sizeof(mapped), 0);
    printf("addr.setpeer.mapped=%ld\n", BIO_ctrl(b, BIO_CTRL_DGRAM_SET_PEER, 0, v6));
    printf("addr.overhead.mapped=%ld\n", ctrl_int(b, BIO_CTRL_DGRAM_GET_MTU_OVERHEAD, 0));
    printf("addr.fallback.mapped=%ld\n", ctrl_int(b, BIO_CTRL_DGRAM_GET_FALLBACK_MTU, 0));

    /* `SET_CONNECTED` with NULL forgets the peer, and the overhead returns to
     * the historical default. */
    printf("addr.setconnected.null=%ld\n", ctrl_int(b, BIO_CTRL_DGRAM_SET_CONNECTED, 0));
    printf("addr.overhead.after.null=%ld\n", ctrl_int(b, BIO_CTRL_DGRAM_GET_MTU_OVERHEAD, 0));
    printf("addr.fallback.after.null=%ld\n", ctrl_int(b, BIO_CTRL_DGRAM_GET_FALLBACK_MTU, 0));
    /* With an `AF_UNSPEC` peer the fragmentation control makes no syscall. */
    printf("addr.dontfrag.unset=%ld\n", ctrl_int(b, BIO_CTRL_DGRAM_SET_DONT_FRAG, 1));
    err_all("addr.dontfrag.unset");
    /* `DETECT_PEER_ADDR` on an unconnected socket finds nothing. */
    BIO_ADDR_clear(got);
    printf("addr.detectpeer.ret=%ld\n",
           BIO_ctrl(b, BIO_CTRL_DGRAM_DETECT_PEER_ADDR, 0, got));
    show_addr("addr.detectpeer", got);

    BIO_free(b);
    BIO_closesocket(fd);
    BIO_ADDR_free(got);
    BIO_ADDR_free(v6);
    BIO_ADDR_free(v4);
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    ERR_clear_error();

    section_fresh();
    section_badfd();
    section_addr_ctrl();
    section_transfer();
    section_deadline();
    section_mmsg();

    printf("probe.done=1\n");
    return 0;
}
