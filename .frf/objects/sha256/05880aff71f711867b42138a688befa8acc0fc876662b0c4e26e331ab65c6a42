/*
 * rt_record_probe.c -- RT-RECORD: the Phase-14.4 record-layer surface, driven.
 *
 * One C program, compiled once against the admitted authority and once against the candidate
 * distribution shell; the two transcripts are diffed line by line, keyed on `key=value`. Every
 * observation is a small integer, a fixed string or a fixed pointer-identity-free value -- never an
 * address, never a clock, never the error queue, never a socket, never a handshake.
 *
 * ## What this probe drives
 *
 *   * the default read-buffer length setters (`SSL_CTX_set_default_read_buffer_len`,
 *     `SSL_set_default_read_buffer_len`) on a fresh context/connection and on NULL, where no public
 *     reader exists on either side and the call itself is the observation;
 *   * the record-state strings `SSL_rstate_string`/`_long` over a fresh connection -- the
 *     authority's `"unknown"` -- and over NULL;
 *   * `SSL_poll` over in-memory `SSL_POLL_ITEM` arrays only: the zero-item arms, a NULL SSL
 *     descriptor, a non-QUIC SSL descriptor, a socket descriptor, an unknown descriptor type, a
 *     NULL-then-refused pair, a refused-first triple whose trailing `revents` must be zeroed, and
 *     the `SSL_POLL_FLAG_NO_HANDLE_EVENTS` flag. A fixed zero `struct timeval` keeps every arm from
 *     blocking; no socket and no wall clock move an answer.
 *
 * ## Arms that are deliberately absent
 *
 * No handshake, no socket and no real datagram move an answer. `SSL_poll`'s QUIC items and its
 * blocking path are not driven: this crate builds no QUIC object, and a real `SSL_poll` over a QUIC
 * object is Phase 15's. The record read state is not set: no public API sets it, and the authority
 * answers `"unknown"` for the fresh connection the probe holds.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/tls1.h>

static void out_int(const char *key, long v)
{
    printf("%s=%ld\n", key, v);
}

static void out_str(const char *key, const char *v)
{
    printf("%s=%s\n", key, v != NULL ? v : "<NULL>");
}

int main(void)
{
    SSL_CTX *ctx;
    SSL *ssl;
    SSL_POLL_ITEM items[3];
    struct timeval zero_tv;
    size_t count;
    size_t item_size = sizeof(SSL_POLL_ITEM);

    ctx = SSL_CTX_new(TLS_method());
    out_int("ctx.nonnull", ctx != NULL);
    ssl = SSL_new(ctx);
    out_int("ssl.nonnull", ssl != NULL);

    /* -----------------------------------------------------------------------------------------
     * A. The default read-buffer length setters.
     * --------------------------------------------------------------------------------------- */
    SSL_CTX_set_default_read_buffer_len(ctx, 512);
    out_int("rec.ctx.set_len", 1);
    SSL_set_default_read_buffer_len(ssl, 1024);
    out_int("rec.ssl.set_len", 1);
    /* The connection setter's refusal arm is a NULL connection (the authority answers without
     * dereferencing it); the context setter has no refusal arm and is not driven with NULL, where
     * the authority would dereference it. */
    SSL_set_default_read_buffer_len(NULL, 1024);
    out_int("rec.ssl.set_len.null.noop", 1);

    /* -----------------------------------------------------------------------------------------
     * B. The record-state strings.
     * --------------------------------------------------------------------------------------- */
    out_str("rec.rstate", SSL_rstate_string(ssl));
    out_str("rec.rstate_long", SSL_rstate_string_long(ssl));
    out_str("rec.rstate.null", SSL_rstate_string(NULL));
    out_str("rec.rstate_long.null", SSL_rstate_string_long(NULL));

    /* -----------------------------------------------------------------------------------------
     * C. SSL_poll: the trivial zero-item arms.
     * --------------------------------------------------------------------------------------- */
    count = 9;
    out_int("poll.zero.null_timeout",
            SSL_poll(NULL, 0, item_size, NULL, 0, &count));
    out_int("poll.zero.null_timeout.count", (long)count);
    zero_tv.tv_sec = 0;
    zero_tv.tv_usec = 0;
    count = 9;
    out_int("poll.zero.zero_timeout",
            SSL_poll(NULL, 0, item_size, &zero_tv, 0, &count));
    out_int("poll.zero.zero_timeout.count", (long)count);
    out_int("poll.zero.no_count",
            SSL_poll(NULL, 0, item_size, NULL, 0, NULL));

    /* -----------------------------------------------------------------------------------------
     * D. One NULL SSL descriptor: a no-op with zero revents and no result.
     * --------------------------------------------------------------------------------------- */
    memset(items, 0, sizeof(items));
    items[0].desc.type = BIO_POLL_DESCRIPTOR_TYPE_SSL;
    items[0].desc.value.ssl = NULL;
    items[0].events = SSL_POLL_EVENT_R;
    count = 9;
    out_int("poll.null_ssl", SSL_poll(items, 1, item_size, &zero_tv, 0, &count));
    out_int("poll.null_ssl.count", (long)count);
    out_int("poll.null_ssl.revents", (long)items[0].revents);

    /* -----------------------------------------------------------------------------------------
     * E. One non-QUIC SSL descriptor: refused.
     * --------------------------------------------------------------------------------------- */
    memset(items, 0, sizeof(items));
    items[0].desc.type = BIO_POLL_DESCRIPTOR_TYPE_SSL;
    items[0].desc.value.ssl = ssl;
    items[0].events = SSL_POLL_EVENT_R;
    count = 9;
    out_int("poll.ssl", SSL_poll(items, 1, item_size, &zero_tv, 0, &count));
    out_int("poll.ssl.count", (long)count);
    out_int("poll.ssl.revents", (long)items[0].revents);

    /* -----------------------------------------------------------------------------------------
     * F. One socket descriptor: refused.
     * --------------------------------------------------------------------------------------- */
    memset(items, 0, sizeof(items));
    items[0].desc.type = BIO_POLL_DESCRIPTOR_TYPE_SOCK_FD;
    items[0].desc.value.fd = -1;
    count = 9;
    out_int("poll.sock", SSL_poll(items, 1, item_size, &zero_tv, 0, &count));
    out_int("poll.sock.count", (long)count);
    out_int("poll.sock.revents", (long)items[0].revents);

    /* -----------------------------------------------------------------------------------------
     * G. One unknown descriptor type: refused.
     * --------------------------------------------------------------------------------------- */
    memset(items, 0, sizeof(items));
    items[0].desc.type = 99;
    count = 9;
    out_int("poll.unknown", SSL_poll(items, 1, item_size, &zero_tv, 0, &count));
    out_int("poll.unknown.count", (long)count);
    out_int("poll.unknown.revents", (long)items[0].revents);

    /* -----------------------------------------------------------------------------------------
     * H. A NULL item then a refused item: the NULL is a no-op, the refusal stops the readout.
     * --------------------------------------------------------------------------------------- */
    memset(items, 0, sizeof(items));
    items[0].desc.type = BIO_POLL_DESCRIPTOR_TYPE_SSL;
    items[0].desc.value.ssl = NULL;
    items[1].desc.type = BIO_POLL_DESCRIPTOR_TYPE_SSL;
    items[1].desc.value.ssl = ssl;
    items[1].events = SSL_POLL_EVENT_R;
    count = 9;
    out_int("poll.two", SSL_poll(items, 2, item_size, &zero_tv, 0, &count));
    out_int("poll.two.count", (long)count);
    out_int("poll.two.revents0", (long)items[0].revents);
    out_int("poll.two.revents1", (long)items[1].revents);

    /* -----------------------------------------------------------------------------------------
     * I. A refused item first of three: FAIL_FROM zeroes the trailing revents.
     * --------------------------------------------------------------------------------------- */
    memset(items, 0, sizeof(items));
    items[0].desc.type = BIO_POLL_DESCRIPTOR_TYPE_SSL;
    items[0].desc.value.ssl = ssl;
    items[0].events = SSL_POLL_EVENT_R;
    items[1].revents = 0xdead;
    items[2].revents = 0xbeef;
    count = 9;
    out_int("poll.three", SSL_poll(items, 3, item_size, &zero_tv, 0, &count));
    out_int("poll.three.count", (long)count);
    out_int("poll.three.revents0", (long)items[0].revents);
    out_int("poll.three.revents1", (long)items[1].revents);
    out_int("poll.three.revents2", (long)items[2].revents);

    /* -----------------------------------------------------------------------------------------
     * J. The NO_HANDLE_EVENTS flag is unobservable for a refused item.
     * --------------------------------------------------------------------------------------- */
    memset(items, 0, sizeof(items));
    items[0].desc.type = BIO_POLL_DESCRIPTOR_TYPE_SSL;
    items[0].desc.value.ssl = ssl;
    count = 9;
    out_int("poll.nohandle",
            SSL_poll(items, 1, item_size, &zero_tv, SSL_POLL_FLAG_NO_HANDLE_EVENTS, &count));
    out_int("poll.nohandle.count", (long)count);

    SSL_free(ssl);
    SSL_CTX_free(ctx);
    out_int("freed", 1);
    return 0;
}
