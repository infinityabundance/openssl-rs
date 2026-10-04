/*
 * RT-STATEM-REMAINDER — the TLS message-layer units 16.5 lands, driven at the
 * boundary they expose.
 *
 * Compiled twice (authority and candidate), run, and the two transcripts compared
 * line by line, keyed on `key=value`. 16.5 transcribes the read/write *transition*
 * surface of `ssl/statem/statem_clnt.c` and `statem_srvr.c` — the parser's decision
 * that a message type can follow the current hand state, and the constructor's
 * decision what to build next. The message bodies those transitions select build
 * and parse bytes through the record layer, the extension units and the key
 * schedule, none of which is landed, so a full flight cannot be driven without a
 * shared engine. What *is* drivable, and what this probe drives, is the state the
 * landed transitions leave a fresh connection in: the `SSL_connect` client and the
 * `SSL_accept` server over an empty memory-BIO peer, their return class, hand
 * state, `SSL_want`, `SSL_in_init`/`SSL_in_before`/`SSL_is_init_finished`, and the
 * second `SSL_do_handshake` re-entry.
 *
 * The boundary is recorded rather than fabricated: the client reaches
 * `TLS_ST_CW_CLNT_HELLO` (13) and the server stays `TLS_ST_BEFORE` (0), both
 * `SSL_READING`, exactly as 14.5b observed. The message layer did not change the
 * fresh state, because it stops at the body selection; the peer BIO therefore
 * receives no ClientHello on either side, and no byte of a flight is compared.
 *
 * No wall clock, no network, no address, no error-queue read.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>

static void out_int(const char *key, long v)
{
    printf("%s=%ld\n", key, (long)v);
}

int main(void)
{
    SSL_CTX *ctx;
    SSL *client;
    SSL *server;
    BIO *cr;
    BIO *cw;
    BIO *sr;
    BIO *sw;

    setvbuf(stdout, NULL, _IOLBF, 0);

    ctx = SSL_CTX_new(TLS_method());
    out_int("ctx.nonnull", ctx != NULL);

    client = SSL_new(ctx);
    server = SSL_new(ctx);
    cr = BIO_new(BIO_s_mem());
    cw = BIO_new(BIO_s_mem());
    sr = BIO_new(BIO_s_mem());
    sw = BIO_new(BIO_s_mem());
    SSL_set_bio(client, cr, cw);
    SSL_set_bio(server, sr, sw);

    /* --- the client's first flight, over an empty peer BIO --- */
    out_int("client.connect.ret", SSL_connect(client));
    out_int("client.state", SSL_get_state(client));
    out_int("client.want", SSL_want(client));
    out_int("client.in_init", SSL_in_init(client));
    out_int("client.in_before", SSL_in_before(client));
    out_int("client.finished", SSL_is_init_finished(client));
    out_int("client.error", SSL_get_error(client, -1));

    /* --- the server's first read, over an empty peer BIO --- */
    out_int("server.accept.ret", SSL_accept(server));
    out_int("server.state", SSL_get_state(server));
    out_int("server.want", SSL_want(server));
    out_int("server.in_init", SSL_in_init(server));
    out_int("server.in_before", SSL_in_before(server));
    out_int("server.finished", SSL_is_init_finished(server));
    out_int("server.error", SSL_get_error(server, -1));

    /* --- re-entry, and the refusal arm on a missing connection --- */
    out_int("client.do_handshake2", SSL_do_handshake(client));
    out_int("server.do_handshake2", SSL_do_handshake(server));
    out_int("null.connect", SSL_connect(NULL));
    out_int("null.do_handshake", SSL_do_handshake(NULL));

    SSL_free(client);
    SSL_free(server);
    SSL_CTX_free(ctx);

    printf("probe.done=1\n");
    return 0;
}
