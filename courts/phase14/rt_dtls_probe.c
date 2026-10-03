/*
 * rt_dtls_probe.c -- RT-DTLS: the Phase-14.8 DTLS layer, driven.
 *
 * One C program, compiled once against the admitted authority and once against the candidate
 * distribution shell; the two transcripts are diffed line by line, keyed on `key=value`. Every
 * observation is a small integer or a fixed string -- never an address, never a clock, never the
 * error queue, never a real datagram socket.
 *
 * ## What this probe drives
 *
 *   * `DTLSv1_listen`'s refusal arms over a constructed `DTLS_method` connection and a fixed
 *     in-memory datagram BIO: the NULL-connection arm, the no-BIO arm, the TLS version-mismatch
 *     arm, the empty-BIO arm (the memory BIO's retry return), a record shorter than the DTLS
 *     header, a non-handshake record, a foreign record version, a nonzero epoch, a non-ClientHello
 *     message, an out-of-range message sequence, a fragmented ClientHello and a ClientHello whose
 *     version is below the method's. Every one of those leaves the parser before the cookie stage.
 *   * `DTLS_get_data_mtu` over NULL and over a fresh DTLS connection (the no-cipher answer);
 *   * `DTLS_set_timer_cb` over NULL, over a fresh DTLS connection with a callback and with NULL;
 *   * the SRTP profile surface: `SSL_CTX_set_tlsext_use_srtp` and `SSL_set_tlsext_use_srtp` over
 *     fixed profile strings (accept, two-profile accept, duplicate refuse, unknown refuse and the
 *     empty string), and `SSL_get_srtp_profiles`/`SSL_get_selected_srtp_profile` over NULL, a
 *     fresh connection and a connection with its own list.
 *
 * ## Arms that are deliberately absent
 *
 * No handshake and no socket move an answer. `DTLSv1_listen`'s cookie stage (a ClientHello without
 * a cookie, which the authority answers with a `HelloVerifyRequest`) is not driven: it reaches
 * `WPACKET` and the record layer, which 14.8 does not land, and `src/ssl/d1_lib.rs` records that
 * reduction. The timer callback has no public reader on either side, so its setter is driven for
 * crash-freedom and its arms are recorded rather than compared. `DTLS_get_data_mtu` is not driven
 * over a TLS connection, where the authority dereferences a NULL `d1`.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/srtp.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>

static SSL_CTX *dtls_ctx;

static void out_int(const char *key, long v)
{
    printf("%s=%ld\n", key, v);
}

static void out_str(const char *key, const char *v)
{
    printf("%s=%s\n", key, v != NULL ? v : "<NULL>");
}

/* Build a fresh DTLS connection over a memory BIO carrying `data`, run `DTLSv1_listen`, and
 * release everything. `data == NULL` leaves the BIO empty. */
static int listen_arm(const unsigned char *data, int len)
{
    SSL *s = SSL_new(dtls_ctx);
    BIO *bio = BIO_new(BIO_s_mem());
    int r;

    if (data != NULL && len > 0)
        BIO_write(bio, data, len);
    SSL_set_bio(s, bio, bio);
    r = DTLSv1_listen(s, NULL);
    SSL_free(s);
    return r;
}

static unsigned int timer_cb(SSL *s, unsigned int timer_us)
{
    (void)s;
    return timer_us;
}

int main(void)
{
    SSL_CTX *tls_ctx;
    SSL *ssl, *ssl2, *tls_ssl;
    STACK_OF(SRTP_PROTECTION_PROFILE) *prof;
    SRTP_PROTECTION_PROFILE *p;

    dtls_ctx = SSL_CTX_new(DTLS_method());
    tls_ctx = SSL_CTX_new(TLS_method());
    out_int("ctx.dtls.nonnull", dtls_ctx != NULL);
    out_int("ctx.tls.nonnull", tls_ctx != NULL);

    /* -----------------------------------------------------------------------------------------
     * A. DTLSv1_listen refusal arms.
     * --------------------------------------------------------------------------------------- */
    {
        static const unsigned char short_rec[5] = { 22, 0xFE, 0xFD, 0, 0 };
        static const unsigned char not_hs[13] = { 1, 0xFE, 0xFD, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        static const unsigned char bad_ver[13] = { 22, 0x03, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        static const unsigned char bad_epoch[13] = { 22, 0xFE, 0xFD, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        static const unsigned char msgtype[25] = {
            22, 0xFE, 0xFD, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12,
            2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        };
        static const unsigned char msgseq[25] = {
            22, 0xFE, 0xFD, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12,
            1, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0
        };
        static const unsigned char frag[25] = {
            22, 0xFE, 0xFD, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12,
            1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0
        };
        static const unsigned char wrongver[27] = {
            22, 0xFE, 0xFD, 0, 0, 0, 0, 0, 0, 0, 0, 0, 14,
            1, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 2, 0xFE, 0xFC
        };

        out_int("listen.null", DTLSv1_listen(NULL, NULL));

        ssl = SSL_new(dtls_ctx);
        out_int("listen.no_bio", DTLSv1_listen(ssl, NULL));
        SSL_free(ssl);

        tls_ssl = SSL_new(tls_ctx);
        out_int("listen.tls.no_bio", DTLSv1_listen(tls_ssl, NULL));
        SSL_free(tls_ssl);

        out_int("listen.empty", listen_arm(NULL, 0));
        out_int("listen.short", listen_arm(short_rec, (int)sizeof(short_rec)));
        out_int("listen.not_handshake", listen_arm(not_hs, (int)sizeof(not_hs)));
        out_int("listen.bad_ver", listen_arm(bad_ver, (int)sizeof(bad_ver)));
        out_int("listen.bad_epoch", listen_arm(bad_epoch, (int)sizeof(bad_epoch)));
        out_int("listen.msgtype", listen_arm(msgtype, (int)sizeof(msgtype)));
        out_int("listen.msgseq", listen_arm(msgseq, (int)sizeof(msgseq)));
        out_int("listen.frag", listen_arm(frag, (int)sizeof(frag)));
        out_int("listen.wrongver", listen_arm(wrongver, (int)sizeof(wrongver)));

        /* The TLS connection with a memory BIO fails the version gate. */
        {
            BIO *bio = BIO_new(BIO_s_mem());
            tls_ssl = SSL_new(tls_ctx);
            SSL_set_bio(tls_ssl, bio, bio);
            out_int("listen.tls.version", DTLSv1_listen(tls_ssl, NULL));
            SSL_free(tls_ssl);
        }
    }

    /* -----------------------------------------------------------------------------------------
     * B. DTLS_get_data_mtu and DTLS_set_timer_cb.
     * --------------------------------------------------------------------------------------- */
    ssl = SSL_new(dtls_ctx);
    out_int("get_data_mtu.null", (long)DTLS_get_data_mtu(NULL));
    out_int("get_data_mtu.fresh", (long)DTLS_get_data_mtu(ssl));
    DTLS_set_timer_cb(NULL, timer_cb);
    out_int("set_timer_cb.null.survived", 1);
    DTLS_set_timer_cb(ssl, timer_cb);
    out_int("set_timer_cb.fresh.survived", 1);
    DTLS_set_timer_cb(ssl, NULL);
    out_int("set_timer_cb.clear.survived", 1);

    /* -----------------------------------------------------------------------------------------
     * C. The SRTP profile surface.
     * --------------------------------------------------------------------------------------- */
    out_int("srtp.ctx.unknown",
            SSL_CTX_set_tlsext_use_srtp(dtls_ctx, "SRTP_BOGUS"));
    out_int("srtp.ctx.empty", SSL_CTX_set_tlsext_use_srtp(dtls_ctx, ""));
    out_int("srtp.ctx.two",
            SSL_CTX_set_tlsext_use_srtp(
                dtls_ctx, "SRTP_AES128_CM_SHA1_80:SRTP_AEAD_AES_128_GCM"));
    out_int("srtp.ctx.dup",
            SSL_CTX_set_tlsext_use_srtp(
                dtls_ctx, "SRTP_AES128_CM_SHA1_80:SRTP_AES128_CM_SHA1_80"));

    out_int("srtp.profiles.null", SSL_get_srtp_profiles(NULL) == NULL);
    out_int("srtp.selected.null", SSL_get_selected_srtp_profile(NULL) == NULL);

    prof = SSL_get_srtp_profiles(ssl);
    out_int("srtp.ssl.from_ctx.nonnull", prof != NULL);
    out_int("srtp.ssl.from_ctx.num", sk_SRTP_PROTECTION_PROFILE_num(prof));
    p = sk_SRTP_PROTECTION_PROFILE_value(prof, 0);
    out_str("srtp.ssl.from_ctx.name0", p != NULL ? p->name : NULL);
    out_int("srtp.ssl.from_ctx.id0", p != NULL ? (long)p->id : -1);
    p = sk_SRTP_PROTECTION_PROFILE_value(prof, 1);
    out_str("srtp.ssl.from_ctx.name1", p != NULL ? p->name : NULL);
    out_int("srtp.ssl.from_ctx.id1", p != NULL ? (long)p->id : -1);
    out_int("srtp.ssl.selected.fresh", SSL_get_selected_srtp_profile(ssl) == NULL);

    ssl2 = SSL_new(dtls_ctx);
    out_int("srtp.ssl.own.set",
            SSL_set_tlsext_use_srtp(ssl2, "SRTP_AEAD_AES_256_GCM"));
    prof = SSL_get_srtp_profiles(ssl2);
    out_int("srtp.ssl.own.nonnull", prof != NULL);
    out_int("srtp.ssl.own.num", sk_SRTP_PROTECTION_PROFILE_num(prof));
    p = sk_SRTP_PROTECTION_PROFILE_value(prof, 0);
    out_str("srtp.ssl.own.name0", p != NULL ? p->name : NULL);
    out_int("srtp.ssl.own.id0", p != NULL ? (long)p->id : -1);
    out_int("srtp.ssl.own.dup",
            SSL_set_tlsext_use_srtp(
                ssl2, "SRTP_AES128_CM_SHA1_80:SRTP_AES128_CM_SHA1_80"));
    out_int("srtp.ssl.own.unknown",
            SSL_set_tlsext_use_srtp(ssl2, "SRTP_BOGUS"));
    out_int("srtp.ssl.null", SSL_set_tlsext_use_srtp(NULL, "SRTP_AES128_CM_SHA1_80"));

    /* -----------------------------------------------------------------------------------------
     * D. Release.
     * --------------------------------------------------------------------------------------- */
    SSL_free(ssl);
    SSL_free(ssl2);
    SSL_CTX_free(tls_ctx);
    SSL_CTX_free(dtls_ctx);
    out_int("freed", 1);
    return 0;
}
