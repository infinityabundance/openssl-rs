/*
 * openssl-rs -- Phase 14, subphase 14.7's differential court: RT-SESSION-CERT.
 *
 * Compiled twice -- once against the admitted authority, once against the candidate
 * distribution shell -- and run; the two transcripts are compared line for line by
 * `forensics/tools/phase14_courts.py`. Every observation is a `key=value` line, so a
 * missing or extra line costs exactly one residual.
 *
 * What it establishes, and what it does not
 * -----------------------------------------
 * `docs/PHASE-14-SUBPHASES.md` section 3.7 gives 14.7 "a codec and a loader". This probe drives
 * the four units' exports:
 *
 *  * the session object (`ssl_sess.c`): `new`/`free`/`up_ref`/`dup`, the id/id-context/master-key/
 *    hostname/ALPN/ticket-appdata/time/timeout/protocol/cipher/early-data accessors, ex-data, the
 *    per-context internal cache (`add`/`remove`/`flush`), the callback setters and their getters,
 *    the connection's session selection and the four PEM entry points;
 *  * the session DER codec (`ssl_asn1.c`): `i2d_SSL_SESSION` and `d2i_SSL_SESSION[_ex]` over a
 *    fixed in-process session, compared as the exact bytes the encoder produces;
 *  * the session printers (`ssl_txt.c`): `SSL_SESSION_print`/`_fp`/`_keylog` over that fixed
 *    session, compared byte for byte;
 *  * the CA-list and certificate/private-key plumbing (`ssl_cert.c`, `ssl_rsa.c`,
 *    `ssl_rsa_legacy.c`) over a fixed matching RSA certificate/private-key pair decoded in memory,
 *    including the deprecated `use_RSAPrivateKey` spellings and the serverinfo installer;
 *  * certificate compression (`ssl_cert_comp.c`): the preference setters over the empty and
 *    unsupported lists and the refusal arms of the compress/get/set entries (the admitted build
 *    defines every compression algorithm away).
 *
 * Determinism
 * -----------
 * Every value printed is a literal, a `nonnull`/`null`, an int/long answer, or the escaped bytes
 * of a deterministic buffer. No pointer is ever printed, no wall-clock value enters an
 * observation (the fixed session's `time` and `timeout` are set explicitly before the codec and
 * the printers run), no network is touched and no handshake is driven.
 *
 * The fixtures
 * ------------
 * The certificate and its matching key are the fixed RSA pair embedded below; they are decoded
 * from memory with `PEM_read_bio_X509`/`PEM_read_bio_PrivateKey`, so no file is opened. The
 * `FILE *` PEM wrappers are driven over `fmemopen`/`open_memstream` streams, which are memory,
 * not filesystem.
 *
 * Arms the authority would crash on
 * ---------------------------------
 * The refusal arms are only those the authority itself answers (a NULL argument its own body
 * checks). No arm passes a NULL `SSL`/`SSL_CTX` or a NULL session to an accessor that would
 * dereference it.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

/* ---------------------------------------------------------------------------------------------
 * Output helpers
 * --------------------------------------------------------------------------------------------- */

static void out_int(const char *key, long v)
{
    printf("%s=%ld\n", key, v);
}

static void out_ptr(const char *key, const void *p)
{
    printf("%s=%s\n", key, p != NULL ? "nonnull" : "null");
}

/* The exact bytes of a buffer, one `key=...` line: newline/backslash escaped, every other byte
 * literal. A printable byte is emitted verbatim. */
static void out_bytes(const char *key, const unsigned char *buf, size_t len)
{
    size_t i;

    printf("%s=", key);
    if (buf == NULL) {
        printf("(null)");
    } else {
        for (i = 0; i < len; i++) {
            unsigned char c = buf[i];

            if (c == '\n')
                printf("\\n");
            else if (c == '\r')
                printf("\\r");
            else if (c == '\\')
                printf("\\\\");
            else if (c >= 0x20 && c < 0x7f)
                putchar(c);
            else
                printf("\\x%02x", c);
        }
    }
    putchar('\n');
}

static int eq_bytes(const unsigned char *a, const unsigned char *b, size_t n)
{
    return a != NULL && b != NULL && memcmp(a, b, n) == 0;
}

/* ---------------------------------------------------------------------------------------------
 * The fixed fixtures
 * --------------------------------------------------------------------------------------------- */

static const char cert_pem[] =
"-----BEGIN CERTIFICATE-----\n"
"MIIDBTCCAe2gAwIBAgIUai6zKVesbjbmumuBUT1EmR0LTSYwDQYJKoZIhvcNAQEL\n"
"BQAwHzEdMBsGA1UEAwwUb3BlbnNzbC1ycyBSVC1UUyBUU0EwHhcNMjYxMDAyMTQ1\n"
"MDMyWhcNMzYwOTI5MTQ1MDMyWjAfMR0wGwYDVQQDDBRvcGVuc3NsLXJzIFJULVRT\n"
"IFRTQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKbf9sygrBw5JAOl\n"
"mVzYEOdZpCxku+03NQvBKBgac1D4FBqMh+sbT5oJ5MKw6Z8EDNaMnoaznNStyNrX\n"
"Zip2Vt4gDoztoYKsqa2sSOipaEUAtJo+mVPxuKwykQDt0NdotpGeorlhggvtYm27\n"
"L1hBps5JwFsjvaAdNuulJxPwy7mGk5KilzKnBwa0gZ3qBL/kkumbGt32OnCeuc0Y\n"
"g9oxA7gRaXvOJMP7GaNr0yhXwRvzN4PrabmzUw5BtdJehJ0ZjvFnHeDVegC7o+QN\n"
"7YG8G5F9xyda+Ze/ZmWIza7qy926QQT9MMkLkRHkLcTGLYx/XaMoLUoHYsN0RzYa\n"
"tqRJ3GcCAwEAAaM5MDcwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwHQYDVR0OBBYE\n"
"FM00nZ1j6GwRnuM1Oh1f7clXTP9cMA0GCSqGSIb3DQEBCwUAA4IBAQAsbpTJW6mS\n"
"nv2Jrc3DaZ6QeLf/kSCASY5Y6ylLzE5M8KC3RHU7YCB/PD/nGyqoxMLgGMOH3Nn/\n"
"mwxLu05SiemBI9p6d59j+q8rhE8pKEZ8n9czpRUpKN8Wjf7Yny195n/+TU567+j5\n"
"KixrqitsAzRjsnj4EqFt3CdrfJmM7IDOPlnoec8bQz5u8vvZtyGEYnPm+1oI8EvP\n"
"Kl/zKGx7tUSjMvb/44m11dPvkZPoyLFCBKyJ+qAgTzZ0iJYL0O1k1Py8FL/FZnju\n"
"/NYYetkHhw/9j6LPCriy488A1qdY76vN0NSxfQEuQKg3M55OIo2q6qZ4TQtdkiUl\n"
"o/wkQUeccaED\n"
"-----END CERTIFICATE-----\n";

static const char key_pem[] =
"-----BEGIN PRIVATE KEY-----\n"
"MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCm3/bMoKwcOSQD\n"
"pZlc2BDnWaQsZLvtNzULwSgYGnNQ+BQajIfrG0+aCeTCsOmfBAzWjJ6Gs5zUrcja\n"
"12YqdlbeIA6M7aGCrKmtrEjoqWhFALSaPplT8bisMpEA7dDXaLaRnqK5YYIL7WJt\n"
"uy9YQabOScBbI72gHTbrpScT8Mu5hpOSopcypwcGtIGd6gS/5JLpmxrd9jpwnrnN\n"
"GIPaMQO4EWl7ziTD+xmja9MoV8Eb8zeD62m5s1MOQbXSXoSdGY7xZx3g1XoAu6Pk\n"
"De2BvBuRfccnWvmXv2ZliM2u6svdukEE/TDJC5ER5C3Exi2Mf12jKC1KB2LDdEc2\n"
"GrakSdxnAgMBAAECggEABVbwzbET7ZHL95T5GHg0xstnRamUK9Q5CUV8E/s7WutF\n"
"wjUvSjIYWzLS2GBfrRNoZrBrqkkl4l7QytxjY3lPLHhwl0jT8cHp4gNmKfg6AM0a\n"
"JPoFmtX+d4Z+0xtrGljlDDl3vsJ50F9J8CjcvUOVUsd+OX+MgazGK5vs4NDmPPxI\n"
"nj9AReYo/xjRmHGhJbuVI8shesuMtv/4CAZu+/sU5/c1v9eJPv2WSlKVv3LOMp6s\n"
"cL5ZwMlZZQjrLX//2IYgzf7IdvZpB/WVA2yiE3Cy6h+6eYGG/ESugboWvS0mMYUC\n"
"0uXgNF9f0DACSqCmHYzEfqFqo1uxh1qmupzbRJav2QKBgQDiyrKiC91tRpar6YbG\n"
"wh0wh2ldIXmcemx+Fn2XIZT8KJeXKpjnxheWa8Pc1IIEPNkyylGM1Zdv0kLhHtzD\n"
"taoDy/ioLecZUyNue5QfKSOSv3W+jdatGdh6+7OPXr9oFoPR1ReBSNsJsI74V7v2\n"
"bMV4OCq8xRFmheTyDPX6TRTFzwKBgQC8Xc+sg3XdQqTKxWXqraCeuJu0EZREKOOE\n"
"o46ptQZKjPedwKh48+xVO9rBB092pktiGYrop56QwcIEwr6wWwzTB9M/XngPqcnI\n"
"kDK4brHkLy7qVSD/h+JCYEhzrF0YW83ye+9h2o2/rLeGK+cXsG87fJaNd4t4cKny\n"
"k1caYii96QKBgQCrHZU6fwlK8f+tJj3yqXOssf7lreQ8FILXf9CyvzvSJi56eEF2\n"
"Xxhc/mKBtDWFTQP0NoLhaCciz9p2UPrxD5h/1N6AxmGf0gLh0YwpFrkoeB028X4Q\n"
"jXexE0if3DU/K/25zLY3bekWnojBCDFh9R/pXTehxm8ik9PybaUKfi42MQKBgQCz\n"
"bMCW2Rn6SrLiGym7YuvuhHZ8DYqnajNectU/vhliBekPsSZJID/r6Hm1CJuer0R7\n"
"C02P06psxMNk+YPeRLxwf7GvWPMQKHD2xLQrjfWRH4iW2cP2456YD1K0LGj4/Omt\n"
"onQhR6dh/slJ2qPjosIxbbmSw15suRSI5eRAU2PvkQKBgQCj4Rx/BqKcrELtX12N\n"
"1dzE1hwrQrtJt03BA2rI0B2rZjZi7YiJP3qZi5ixm4OUQvxZuLzEaldsxYzll4T7\n"
"uiwMrRemAtnqyzo+GfMGwGwq2Qqonz2vFQFZTyhqLcSL2AjW7UxAZACbwrwwOZDX\n"
"+RFovRfBb+SxNVsfGe04CvMTzQ==\n"
"-----END PRIVATE KEY-----\n";

/* A V1 serverinfo block: one private-use extension, type 0xff00, of two bytes. */
static const unsigned char serverinfo_v1[] = { 0xff, 0x00, 0x00, 0x02, 'a', 'b' };

/* ---------------------------------------------------------------------------------------------
 * Static callback targets (never invoked -- only installed and read back)
 * --------------------------------------------------------------------------------------------- */

static int cb_new_session(SSL *ssl, SSL_SESSION *sess) { (void)ssl; (void)sess; return 1; }
static void cb_remove_session(SSL_CTX *ctx, SSL_SESSION *sess) { (void)ctx; (void)sess; }
static SSL_SESSION *cb_get_session(SSL *ssl, const unsigned char *d, int len, int *copy)
{ (void)ssl; (void)d; (void)len; (void)copy; return NULL; }
static void cb_info(const SSL *ssl, int type, int val) { (void)ssl; (void)type; (void)val; }
static int cb_client_cert(SSL *ssl, X509 **x, EVP_PKEY **p)
{ (void)ssl; (void)x; (void)p; return 0; }
static int cb_gen_cookie(SSL *ssl, unsigned char *c, unsigned int *l)
{ (void)ssl; (void)c; (void)l; return 0; }
static int cb_verify_cookie(SSL *ssl, const unsigned char *c, unsigned int l)
{ (void)ssl; (void)c; (void)l; return 0; }
static int cb_gen_stateless(SSL *ssl, unsigned char *c, size_t *l)
{ (void)ssl; (void)c; (void)l; return 0; }
static int cb_verify_stateless(SSL *ssl, const unsigned char *c, size_t l)
{ (void)ssl; (void)c; (void)l; return 0; }

/* ---------------------------------------------------------------------------------------------
 * Session object
 * --------------------------------------------------------------------------------------------- */

static void drive_session_object(void)
{
    unsigned char id[16];
    unsigned char id_ctx[5];
    unsigned char mk[48];
    unsigned char out[64];
    unsigned char alpn_in[2] = { 'h', '2' };
    unsigned char ta_in[2] = { 't', 'a' };
    const unsigned char *p;
    unsigned int len = 0;
    SSL_SESSION *s;
    SSL_SESSION *d;
    int i;

    for (i = 0; i < 16; i++) id[i] = (unsigned char)(0x10 + i);
    for (i = 0; i < 5; i++) id_ctx[i] = (unsigned char)(0xa0 + i);
    for (i = 0; i < 48; i++) mk[i] = (unsigned char)(0x40 + i);

    s = SSL_SESSION_new();
    out_ptr("session.new", s);
    out_int("session.up_ref", SSL_SESSION_up_ref(s));
    SSL_SESSION_free(s);

    out_int("session.set1_id", SSL_SESSION_set1_id(s, id, 16));
    p = SSL_SESSION_get_id(s, &len);
    out_int("session.id.len", (long)len);
    out_int("session.id.eq", eq_bytes(p, id, 16));
    out_int("session.set1_id.too_long", SSL_SESSION_set1_id(s, id, 33));
    p = SSL_SESSION_get_id(s, &len);
    out_int("session.id.len.after_too_long", (long)len);
    out_int("session.set1_id.zero", SSL_SESSION_set1_id(s, id, 0));
    out_int("session.set1_id.again", SSL_SESSION_set1_id(s, id, 16));

    out_int("session.set1_id_context", SSL_SESSION_set1_id_context(s, id_ctx, 5));
    p = SSL_SESSION_get0_id_context(s, &len);
    out_int("session.id_ctx.len", (long)len);
    out_int("session.id_ctx.eq", eq_bytes(p, id_ctx, 5));
    out_int("session.set1_id_context.too_long", SSL_SESSION_set1_id_context(s, id_ctx, 40));

    out_int("session.set1_master_key", SSL_SESSION_set1_master_key(s, mk, 48));
    out_int("session.get_master_key.len", (long)SSL_SESSION_get_master_key(s, NULL, 0));
    memset(out, 0, sizeof(out));
    out_int("session.get_master_key.n", (long)SSL_SESSION_get_master_key(s, out, sizeof(out)));
    out_int("session.master_key.eq", eq_bytes(out, mk, 48));

    out_int("session.set_time_ex", (long)SSL_SESSION_set_time_ex(s, 1700000000));
    out_int("session.get_time_ex", (long)SSL_SESSION_get_time_ex(s));
    out_int("session.get_time", SSL_SESSION_get_time(s));
    out_int("session.set_time", SSL_SESSION_set_time(s, 1700000100));
    out_int("session.get_time_ex2", (long)SSL_SESSION_get_time_ex(s));
    out_int("session.set_time_ex2", (long)SSL_SESSION_set_time_ex(s, 1700000000));
    out_int("session.set_timeout", SSL_SESSION_set_timeout(s, 300));
    out_int("session.get_timeout", SSL_SESSION_get_timeout(s));
    out_int("session.set_timeout.neg", SSL_SESSION_set_timeout(s, -1));

    out_int("session.set_protocol", SSL_SESSION_set_protocol_version(s, TLS1_2_VERSION));
    out_int("session.get_protocol", SSL_SESSION_get_protocol_version(s));

    out_int("session.has_ticket", SSL_SESSION_has_ticket(s));
    out_int("session.ticket_hint", (long)SSL_SESSION_get_ticket_lifetime_hint(s));
    {
        const unsigned char *tick = (const unsigned char *)0x1;
        size_t tlen = 99;
        SSL_SESSION_get0_ticket(s, &tick, &tlen);
        out_ptr("session.ticket.ptr", tick);
        out_int("session.ticket.len", (long)tlen);
    }
    out_int("session.get_compress_id", (long)SSL_SESSION_get_compress_id(s));
    out_int("session.get_max_early_data", (long)SSL_SESSION_get_max_early_data(s));
    out_int("session.set_max_early_data", SSL_SESSION_set_max_early_data(s, 42));
    out_int("session.get_max_early_data2", (long)SSL_SESSION_get_max_early_data(s));

    out_int("session.set1_hostname", SSL_SESSION_set1_hostname(s, "example.com"));
    out_int("session.get0_hostname.eq", strcmp(SSL_SESSION_get0_hostname(s), "example.com") == 0);
    out_int("session.set1_hostname.null", SSL_SESSION_set1_hostname(s, NULL));
    out_ptr("session.get0_hostname.null", SSL_SESSION_get0_hostname(s));
    out_int("session.set1_hostname.again", SSL_SESSION_set1_hostname(s, "example.com"));

    out_int("session.set1_alpn", SSL_SESSION_set1_alpn_selected(s, alpn_in, 2));
    {
        const unsigned char *a = NULL;
        size_t alen = 0;
        SSL_SESSION_get0_alpn_selected(s, &a, &alen);
        out_int("session.alpn.len", (long)alen);
        out_int("session.alpn.eq", eq_bytes(a, alpn_in, 2));
    }
    out_int("session.set1_alpn.empty", SSL_SESSION_set1_alpn_selected(s, NULL, 0));
    out_int("session.set1_alpn.again", SSL_SESSION_set1_alpn_selected(s, alpn_in, 2));

    out_int("session.set1_ticket_appdata", SSL_SESSION_set1_ticket_appdata(s, ta_in, 2));
    {
        void *d2 = NULL;
        size_t dl = 0;
        SSL_SESSION_set1_ticket_appdata(s, ta_in, 2);
        out_int("session.get0_ticket_appdata", SSL_SESSION_get0_ticket_appdata(s, &d2, &dl));
        out_int("session.ticket_appdata.len", (long)dl);
        out_int("session.ticket_appdata.eq", eq_bytes(d2, ta_in, 2));
    }
    out_int("session.set1_ticket_appdata.null", SSL_SESSION_set1_ticket_appdata(s, NULL, 0));

    out_ptr("session.get0_peer", SSL_SESSION_get0_peer(s));
    out_ptr("session.get0_peer_rpk", SSL_SESSION_get0_peer_rpk(s));

    out_int("session.is_resumable", SSL_SESSION_is_resumable(s));

    /* The `dup` runs before any ex-data is set: the authority's `CRYPTO_dup_ex_data` refuses a
     * session with application ex-data and no registered session index, so a set-then-dup pair
     * is not a comparable arm. */
    d = SSL_SESSION_dup(s);
    out_ptr("session.dup", d);
    if (d != NULL) {
        unsigned int dlen = 0;
        const unsigned char *dp = SSL_SESSION_get_id(d, &dlen);
        out_int("session.dup.id.len", (long)dlen);
        out_int("session.dup.id.eq", eq_bytes(dp, id, 16));
        out_int("session.dup.protocol", SSL_SESSION_get_protocol_version(d));
        out_int("session.dup.hostname.eq", strcmp(SSL_SESSION_get0_hostname(d), "example.com") == 0);
        out_int("session.dup.master_key.len", (long)SSL_SESSION_get_master_key(d, NULL, 0));
        SSL_SESSION_free(d);
    }

    /* ex-data: index 0 is the sentinel slot, which `CRYPTO_set_ex_data` still accepts. */
    out_ptr("session.get_ex_data.before", SSL_SESSION_get_ex_data(s, 0));
    out_int("session.set_ex_data", SSL_SESSION_set_ex_data(s, 0, (void *)s));
    out_int("session.get_ex_data.after", SSL_SESSION_get_ex_data(s, 0) == (void *)s);

    SSL_SESSION_free(s);
}

/* ---------------------------------------------------------------------------------------------
 * The fixed session the codec and the printers run over
 * --------------------------------------------------------------------------------------------- */

static SSL_SESSION *make_fixed_session(SSL *ssl)
{
    SSL_SESSION *s = SSL_SESSION_new();
    unsigned char id[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    unsigned char mk[48];
    unsigned char sid[4] = { 9, 10, 11, 12 };
    unsigned char alpn[2] = { 'h', '2' };
    unsigned char ta[3] = { 'a', 'p', 'p' };
    const unsigned char wire[2] = { 0x00, 0x9c }; /* TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 */
    const SSL_CIPHER *cipher;
    int i;

    for (i = 0; i < 48; i++) mk[i] = (unsigned char)(i * 3 + 1);

    SSL_SESSION_set1_id(s, id, 8);
    SSL_SESSION_set1_id_context(s, sid, 4);
    SSL_SESSION_set1_master_key(s, mk, 48);
    SSL_SESSION_set1_hostname(s, "example.test");
    SSL_SESSION_set1_alpn_selected(s, alpn, 2);
    SSL_SESSION_set1_ticket_appdata(s, ta, 3);
    SSL_SESSION_set_max_early_data(s, 7);
    SSL_SESSION_set_protocol_version(s, TLS1_2_VERSION);
    SSL_SESSION_set_time_ex(s, 1700000000);
    SSL_SESSION_set_timeout(s, 300);

    cipher = SSL_CIPHER_find(ssl, wire);
    out_int("session.set_cipher", SSL_SESSION_set_cipher(s, cipher));
    out_int("session.set_cipher.null", SSL_SESSION_set_cipher(s, NULL));
    out_int("session.set_cipher.again", SSL_SESSION_set_cipher(s, cipher));

    return s;
}

static void drive_codec(SSL *ssl)
{
    SSL_SESSION *s = make_fixed_session(ssl);
    unsigned char *der = NULL;
    const unsigned char *p;
    int derlen;
    SSL_SESSION *s2;
    BIO *mem;
    const unsigned char *pembuf;
    long pemlen;
    SSL_SESSION *s3;

    out_int("session.get0_cipher.eq", SSL_SESSION_get0_cipher(s) != NULL);

    derlen = i2d_SSL_SESSION(s, &der);
    out_int("der.len", derlen);
    out_bytes("der.bytes", der, derlen > 0 ? (size_t)derlen : 0);

    p = der;
    s2 = d2i_SSL_SESSION(NULL, &p, derlen);
    out_ptr("der.reparse", s2);
    if (s2 != NULL) {
        unsigned int l = 0;
        const unsigned char *idp = SSL_SESSION_get_id(s2, &l);
        out_int("der.rp.protocol", SSL_SESSION_get_protocol_version(s2));
        out_int("der.rp.id.len", (long)l);
        out_int("der.rp.master_key.len", (long)SSL_SESSION_get_master_key(s2, NULL, 0));
        out_int("der.rp.hostname.eq", strcmp(SSL_SESSION_get0_hostname(s2), "example.test") == 0);
        out_int("der.rp.time", (long)SSL_SESSION_get_time_ex(s2));
        out_int("der.rp.timeout", SSL_SESSION_get_timeout(s2));
        out_int("der.rp.max_early_data", (long)SSL_SESSION_get_max_early_data(s2));
        out_int("der.rp.cipher.eq", SSL_SESSION_get0_cipher(s2) == SSL_SESSION_get0_cipher(s));
        (void)idp;
    }

    mem = BIO_new(BIO_s_mem());
    out_int("pem.write.bio", PEM_write_bio_SSL_SESSION(mem, s));
    pemlen = BIO_get_mem_data(mem, (char **)&pembuf);
    out_bytes("pem.bytes", pembuf, pemlen > 0 ? (size_t)pemlen : 0);

    /* Re-read the exact bytes this side wrote, over a memory BIO. */
    {
        BIO *rd = BIO_new_mem_buf(pembuf, (int)pemlen);
        s3 = PEM_read_bio_SSL_SESSION(rd, NULL, NULL, NULL);
        out_ptr("pem.reparse.bio", s3);
        if (s3 != NULL) {
            out_int("pem.rp.protocol", SSL_SESSION_get_protocol_version(s3));
            out_int("pem.rp.hostname.eq", strcmp(SSL_SESSION_get0_hostname(s3), "example.test") == 0);
            SSL_SESSION_free(s3);
        }
        BIO_free(rd);
    }

    /* The `FILE *` spellings over memory streams. */
    {
        char *fbuf = NULL;
        size_t flen = 0;
        FILE *f = open_memstream(&fbuf, &flen);
        SSL_SESSION *s4;

        out_int("pem.write.fp", PEM_write_SSL_SESSION(f, s));
        fclose(f);
        out_bytes("pem.fp.bytes", (const unsigned char *)fbuf, flen);
        f = fmemopen(fbuf, flen, "r");
        s4 = PEM_read_SSL_SESSION(f, NULL, NULL, NULL);
        out_ptr("pem.reparse.fp", s4);
        if (s4 != NULL) SSL_SESSION_free(s4);
        fclose(f);
        free(fbuf);
    }

    /* `d2i_SSL_SESSION_ex` with no library context is the same decoder. */
    {
        const unsigned char *q = der;
        SSL_SESSION *s5 = d2i_SSL_SESSION_ex(NULL, &q, derlen, NULL, NULL);
        out_ptr("der.reparse_ex", s5);
        if (s5 != NULL) {
            out_int("der.rp_ex.protocol", SSL_SESSION_get_protocol_version(s5));
            SSL_SESSION_free(s5);
        }
    }

    SSL_SESSION_free(s2);
    OPENSSL_free(der);
    BIO_free(mem);

    /* Printers over the same fixed session, byte for byte. */
    {
        BIO *pr = BIO_new(BIO_s_mem());
        unsigned char *pbuf;
        long plen;

        out_int("print.ok", SSL_SESSION_print(pr, s));
        plen = BIO_get_mem_data(pr, (char **)&pbuf);
        out_bytes("print.bytes", pbuf, plen > 0 ? (size_t)plen : 0);
        out_int("print.null", SSL_SESSION_print(pr, NULL));
        BIO_free(pr);

        pr = BIO_new(BIO_s_mem());
        out_int("keylog.ok", SSL_SESSION_print_keylog(pr, s));
        plen = BIO_get_mem_data(pr, (char **)&pbuf);
        out_bytes("keylog.bytes", pbuf, plen > 0 ? (size_t)plen : 0);
        out_int("keylog.null", SSL_SESSION_print_keylog(pr, NULL));
        BIO_free(pr);

        {
            char *fbuf = NULL;
            size_t flen = 0;
            FILE *f = open_memstream(&fbuf, &flen);
            out_int("print_fp.ok", SSL_SESSION_print_fp(f, s));
            fclose(f);
            out_bytes("print_fp.bytes", (const unsigned char *)fbuf, flen);
            free(fbuf);
        }
    }

    SSL_SESSION_free(s);
}

/* ---------------------------------------------------------------------------------------------
 * The session cache and the callback surface
 * --------------------------------------------------------------------------------------------- */

static void drive_cache(SSL *ssl)
{
    SSL_CTX *ctx = SSL_get_SSL_CTX(ssl);
    SSL_SESSION *s = make_fixed_session(ssl);
    SSL_SESSION *s2;

    out_int("ctx.set_timeout", SSL_CTX_set_timeout(ctx, 100));
    out_int("ctx.get_timeout", SSL_CTX_get_timeout(ctx));

    out_int("cache.add", SSL_CTX_add_session(ctx, s));
    out_int("cache.add.again", SSL_CTX_add_session(ctx, s));
    out_int("cache.remove", SSL_CTX_remove_session(ctx, s));
    out_int("cache.remove.again", SSL_CTX_remove_session(ctx, s));

    s2 = SSL_SESSION_dup(s);
    out_int("cache.add.dup", SSL_CTX_add_session(ctx, s2));
    SSL_CTX_flush_sessions_ex(ctx, 0);
    out_int("cache.remove.after_flush", SSL_CTX_remove_session(ctx, s2));
    SSL_CTX_flush_sessions(ctx, 0);
    SSL_SESSION_free(s2);

    /* The setters and their getters. */
    SSL_CTX_sess_set_new_cb(ctx, cb_new_session);
    out_int("cb.new.nonnull", SSL_CTX_sess_get_new_cb(ctx) != NULL);
    SSL_CTX_sess_set_remove_cb(ctx, cb_remove_session);
    out_int("cb.remove.nonnull", SSL_CTX_sess_get_remove_cb(ctx) != NULL);
    SSL_CTX_sess_set_get_cb(ctx, cb_get_session);
    out_int("cb.get.nonnull", SSL_CTX_sess_get_get_cb(ctx) != NULL);
    SSL_CTX_set_info_callback(ctx, cb_info);
    out_int("cb.info.nonnull", SSL_CTX_get_info_callback(ctx) != NULL);
    SSL_CTX_set_client_cert_cb(ctx, cb_client_cert);
    out_int("cb.client_cert.nonnull", SSL_CTX_get_client_cert_cb(ctx) != NULL);
    SSL_CTX_set_cookie_generate_cb(ctx, cb_gen_cookie);
    SSL_CTX_set_cookie_verify_cb(ctx, cb_verify_cookie);
    SSL_CTX_set_stateless_cookie_generate_cb(ctx, cb_gen_stateless);
    SSL_CTX_set_stateless_cookie_verify_cb(ctx, cb_verify_stateless);

    /* The connection's session selection. */
    out_ptr("ssl.get_session.fresh", SSL_get_session(ssl));
    out_ptr("ssl.get1_session.fresh", SSL_get1_session(ssl));
    out_int("ssl.set_session", SSL_set_session(ssl, s));
    out_ptr("ssl.get_session.set", SSL_get_session(ssl));
    {
        SSL_SESSION *g = SSL_get1_session(ssl);
        out_ptr("ssl.get1_session.set", g);
        if (g != NULL) SSL_SESSION_free(g);
    }
    out_int("ssl.set_session.null", SSL_set_session(ssl, NULL));
    out_ptr("ssl.get_session.after_null", SSL_get_session(ssl));

    out_int("ssl.set_secret_cb", SSL_set_session_secret_cb(ssl, NULL, NULL));
    out_int("ssl.set_ticket_ext_cb", SSL_set_session_ticket_ext_cb(ssl, NULL, NULL));
    {
        unsigned char ext[3] = { 1, 2, 3 };
        out_int("ssl.set_ticket_ext", SSL_set_session_ticket_ext(ssl, ext, 3));
        out_int("ssl.set_ticket_ext.empty", SSL_set_session_ticket_ext(ssl, NULL, 0));
    }

    SSL_SESSION_free(s);
}

/* ---------------------------------------------------------------------------------------------
 * CA lists and the certificate/private-key loaders
 * --------------------------------------------------------------------------------------------- */

static int drive_ca_lists(SSL_CTX *ctx, SSL *ssl, X509 *cert)
{
    STACK_OF(X509_NAME) *l1 = NULL;
    STACK_OF(X509_NAME) *l2 = NULL;

    out_int("ca.ctx.add1", SSL_CTX_add1_to_CA_list(ctx, cert));
    out_ptr("ca.ctx.get0", SSL_CTX_get0_CA_list(ctx));
    l1 = SSL_dup_CA_list(SSL_CTX_get0_CA_list(ctx));
    out_ptr("ca.dup", l1);
    out_int("ca.ctx.set0", l1 != NULL ? 1 : 0);
    SSL_CTX_set0_CA_list(ctx, l1);
    out_ptr("ca.ctx.get0.after_set", SSL_CTX_get0_CA_list(ctx));

    SSL_CTX_add1_to_CA_list(ctx, cert);
    l2 = SSL_dup_CA_list(SSL_CTX_get0_CA_list(ctx));
    out_int("ca.ctx.set_client", l2 != NULL ? 1 : 0);
    SSL_CTX_set_client_CA_list(ctx, l2);
    out_ptr("ca.ctx.get_client", SSL_CTX_get_client_CA_list(ctx));
    out_int("ca.ctx.add_client", SSL_CTX_add_client_CA(ctx, cert));

    /* The connection falls back to the context for its CA list. */
    out_ptr("ca.ssl.get0.fallback", SSL_get0_CA_list(ssl));
    out_int("ca.ssl.add1", SSL_add1_to_CA_list(ssl, cert));
    out_ptr("ca.ssl.get0", SSL_get0_CA_list(ssl));
    out_int("ca.ssl.add_client", SSL_add_client_CA(ssl, cert));
    out_int("ca.ssl.set_client", l2 != NULL ? 1 : 0);
    SSL_set_client_CA_list(ssl, SSL_dup_CA_list(l2));
    out_ptr("ca.ssl.peer", SSL_get0_peer_CA_list(ssl));
    out_ptr("ca.ssl.get_client", SSL_get_client_CA_list(ssl));

    /* The refusal arms. */
    out_int("ca.ctx.add1.null", SSL_CTX_add1_to_CA_list(ctx, NULL));
    out_int("ca.ssl.add1.null", SSL_add1_to_CA_list(ssl, NULL));
    out_int("ca.ctx.add_client.null", SSL_CTX_add_client_CA(ctx, NULL));
    out_int("ca.ssl.add_client.null", SSL_add_client_CA(ssl, NULL));
    out_ptr("ca.load.null", SSL_load_client_CA_file(NULL));
    out_ptr("ca.load_ex.null", SSL_load_client_CA_file_ex(NULL, NULL, NULL));
    {
        STACK_OF(X509_NAME) *sk = sk_X509_NAME_new_null();
        out_int("ca.add_file.null", SSL_add_file_cert_subjects_to_stack(sk, NULL));
        out_int("ca.add_dir.null", SSL_add_dir_cert_subjects_to_stack(sk, NULL));
        out_int("ca.add_store.null", SSL_add_store_cert_subjects_to_stack(sk, NULL));
        sk_X509_NAME_pop_free(sk, X509_NAME_free);
    }
    out_int("exdata.idx.valid", SSL_get_ex_data_X509_STORE_CTX_idx() >= 0);
    return 1;
}

static void drive_cert_key(void)
{
    BIO *bc = BIO_new_mem_buf(cert_pem, -1);
    BIO *bk = BIO_new_mem_buf(key_pem, -1);
    X509 *cert = PEM_read_bio_X509(bc, NULL, NULL, NULL);
    EVP_PKEY *key = PEM_read_bio_PrivateKey(bk, NULL, NULL, NULL);
    SSL_CTX *ctx2;
    SSL_CTX *ctx3;
    SSL_CTX *ctx4;
    SSL_CTX *ctx5;
    SSL *ssl2;
    SSL *ssl3;
    RSA *rsa;
    unsigned char *cder = NULL;
    unsigned char *rder = NULL;
    int cderlen;
    int rderlen;

    out_ptr("fixture.cert", cert);
    out_ptr("fixture.key", key);

    ctx2 = SSL_CTX_new(TLS_method());
    out_int("rsa.use_cert.ctx", SSL_CTX_use_certificate(ctx2, cert));
    out_ptr("rsa.get0_cert", SSL_CTX_get0_certificate(ctx2));
    out_int("rsa.use_key.ctx", SSL_CTX_use_PrivateKey(ctx2, key));
    out_int("rsa.check.ctx", SSL_CTX_check_private_key(ctx2));
    out_ptr("rsa.get0_key", SSL_CTX_get0_privatekey(ctx2));

    ssl2 = SSL_new(ctx2);
    out_ptr("rsa.get_cert.ssl", SSL_get_certificate(ssl2));
    out_ptr("rsa.get_key.ssl", SSL_get_privatekey(ssl2));
    out_int("rsa.use_cert.ssl", SSL_use_certificate(ssl2, cert));
    out_int("rsa.use_key.ssl", SSL_use_PrivateKey(ssl2, key));
    out_int("rsa.check.ssl", SSL_check_private_key(ssl2));

    /* The ASN1 (DER) loaders. */
    cderlen = i2d_X509(cert, &cder);
    out_int("fixture.cert.der.len", cderlen);
    ctx3 = SSL_CTX_new(TLS_method());
    out_int("rsa.use_cert_asn1", SSL_CTX_use_certificate_ASN1(ctx3, cderlen, cder));
    out_ptr("rsa.get0_cert_asn1", SSL_CTX_get0_certificate(ctx3));
    out_int("rsa.use_cert_asn1.ssl", SSL_use_certificate_ASN1(ssl2, cder, cderlen));
    {
        const unsigned char bad[4] = { 1, 2, 3, 4 };
        SSL_CTX *badctx = SSL_CTX_new(TLS_method());
        out_int("rsa.use_cert_asn1.bad", SSL_CTX_use_certificate_ASN1(badctx, 4, bad));
        out_int("rsa.use_key_asn1.bad", SSL_CTX_use_PrivateKey_ASN1(EVP_PKEY_RSA, badctx, bad, 4));
        SSL_CTX_free(badctx);
    }
    out_int("rsa.use_key_asn1", SSL_CTX_use_PrivateKey_ASN1(EVP_PKEY_RSA, ctx3, NULL, 0));

    /* use_cert_and_key, and its not-replacing refusal. */
    ctx4 = SSL_CTX_new(TLS_method());
    out_int("certkey.ctx.override", SSL_CTX_use_cert_and_key(ctx4, cert, key, NULL, 1));
    out_int("certkey.ctx.no_override", SSL_CTX_use_cert_and_key(ctx4, cert, key, NULL, 0));
    out_int("certkey.ssl.override", SSL_use_cert_and_key(ssl2, cert, key, NULL, 1));

    /* NULL refusals of the cert/key loaders. */
    out_int("rsa.use_cert.null", SSL_CTX_use_certificate(ctx3, NULL));
    out_int("rsa.use_key.null", SSL_CTX_use_PrivateKey(ctx3, NULL));
    out_int("rsa.use_cert.ssl.null", SSL_use_certificate(ssl2, NULL));
    out_int("rsa.use_key.ssl.null", SSL_use_PrivateKey(ssl2, NULL));

    /* The `_file` refusal arms: a NULL file is the reachable arm, no file is opened. */
    out_int("file.use_cert.ctx.null", SSL_CTX_use_certificate_file(ctx3, NULL, SSL_FILETYPE_PEM));
    out_int("file.use_key.ctx.null", SSL_CTX_use_PrivateKey_file(ctx3, NULL, SSL_FILETYPE_PEM));
    out_int("file.use_cert.ssl.null", SSL_use_certificate_file(ssl2, NULL, SSL_FILETYPE_PEM));
    out_int("file.use_key.ssl.null", SSL_use_PrivateKey_file(ssl2, NULL, SSL_FILETYPE_PEM));
    out_int("file.chain.ctx.null", SSL_CTX_use_certificate_chain_file(ctx3, NULL));
    out_int("file.chain.ssl.null", SSL_use_certificate_chain_file(ssl2, NULL));

    /* The deprecated `use_RSAPrivateKey` spellings. */
    rsa = EVP_PKEY_get1_RSA(key);
    out_ptr("fixture.rsa", rsa);
    ctx5 = SSL_CTX_new(TLS_method());
    out_int("legacy.ctx.use", SSL_CTX_use_RSAPrivateKey(ctx5, rsa));
    out_int("legacy.ctx.use.null", SSL_CTX_use_RSAPrivateKey(ctx5, NULL));
    ssl3 = SSL_new(ctx5);
    out_int("legacy.ssl.use", SSL_use_RSAPrivateKey(ssl3, rsa));
    rderlen = i2d_RSAPrivateKey(rsa, &rder);
    out_int("fixture.rsa.der.len", rderlen);
    {
        SSL_CTX *ctx6 = SSL_CTX_new(TLS_method());
        SSL *ssl6 = SSL_new(ctx6);
        out_int("legacy.ctx.asn1.use", SSL_CTX_use_RSAPrivateKey_ASN1(ctx6, rder, rderlen));
        out_int("legacy.ssl.asn1.use", SSL_use_RSAPrivateKey_ASN1(ssl6, rder, rderlen));
        out_int("legacy.ctx.asn1.bad", SSL_CTX_use_RSAPrivateKey_ASN1(ctx6, rder, 4));
        out_int("legacy.ssl.asn1.bad", SSL_use_RSAPrivateKey_ASN1(ssl6, rder, 4));
        out_int("legacy.file.ctx.null", SSL_CTX_use_RSAPrivateKey_file(ctx6, NULL, SSL_FILETYPE_PEM));
        out_int("legacy.file.ssl.null", SSL_use_RSAPrivateKey_file(ssl6, NULL, SSL_FILETYPE_PEM));
        SSL_free(ssl6);
        SSL_CTX_free(ctx6);
    }
    out_int("legacy.ssl.use.null", SSL_use_RSAPrivateKey(ssl3, NULL));

    /* The serverinfo installers. */
    out_int("serverinfo.null", SSL_CTX_use_serverinfo(ctx2, NULL, 0));
    out_int("serverinfo.ex.null", SSL_CTX_use_serverinfo_ex(ctx2, 1, NULL, 0));
    out_int("serverinfo.ex.badver", SSL_CTX_use_serverinfo_ex(ctx2, 99, serverinfo_v1, sizeof(serverinfo_v1)));
    out_int("serverinfo.v1", SSL_CTX_use_serverinfo(ctx2, serverinfo_v1, sizeof(serverinfo_v1)));
    out_int("serverinfo.v2", SSL_CTX_use_serverinfo_ex(ctx2, 2, serverinfo_v1, sizeof(serverinfo_v1)));
    out_int("serverinfo.file.null", SSL_CTX_use_serverinfo_file(ctx2, NULL));

    /* CA lists over the decoded certificate. */
    drive_ca_lists(ctx2, ssl2, cert);

    RSA_free(rsa);
    OPENSSL_free(cder);
    OPENSSL_free(rder);
    SSL_free(ssl3);
    SSL_free(ssl2);
    SSL_CTX_free(ctx5);
    SSL_CTX_free(ctx4);
    SSL_CTX_free(ctx3);
    SSL_CTX_free(ctx2);
    EVP_PKEY_free(key);
    X509_free(cert);
    BIO_free(bc);
    BIO_free(bk);
}

/* ---------------------------------------------------------------------------------------------
 * Certificate compression
 * --------------------------------------------------------------------------------------------- */

static void drive_cert_comp(SSL_CTX *ctx, SSL *ssl)
{
    unsigned char *data = NULL;
    size_t orig_len = 0;
    int algs[2] = { TLSEXT_comp_cert_zlib, TLSEXT_comp_cert_brotli };

    out_int("comp.ctx.pref.empty", SSL_CTX_set1_cert_comp_preference(ctx, NULL, 0));
    out_int("comp.ctx.pref.algs", SSL_CTX_set1_cert_comp_preference(ctx, algs, 2));
    out_int("comp.ssl.pref.empty", SSL_set1_cert_comp_preference(ssl, NULL, 0));
    out_int("comp.ssl.pref.algs", SSL_set1_cert_comp_preference(ssl, algs, 2));
    out_int("comp.ctx.compress", SSL_CTX_compress_certs(ctx, 0));
    out_int("comp.ssl.compress", SSL_compress_certs(ssl, TLSEXT_comp_cert_zlib));
    out_int("comp.ctx.get1", (long)SSL_CTX_get1_compressed_cert(ctx, TLSEXT_comp_cert_zlib, &data, &orig_len));
    out_int("comp.ssl.get1", (long)SSL_get1_compressed_cert(ssl, TLSEXT_comp_cert_zlib, &data, &orig_len));
    out_int("comp.ctx.set1", SSL_CTX_set1_compressed_cert(ctx, TLSEXT_comp_cert_zlib, NULL, 0, 0));
    out_int("comp.ssl.set1", SSL_set1_compressed_cert(ssl, TLSEXT_comp_cert_zlib, NULL, 0, 0));
}

/* ---------------------------------------------------------------------------------------------
 * main
 * --------------------------------------------------------------------------------------------- */

int main(void)
{
    SSL_CTX *ctx;
    SSL *ssl;

    setvbuf(stdout, NULL, _IONBF, 0);

    ctx = SSL_CTX_new(TLS_method());
    ssl = SSL_new(ctx);

    drive_session_object();
    drive_codec(ssl);
    drive_cache(ssl);
    drive_cert_key();
    drive_cert_comp(ctx, ssl);

    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return 0;
}
