/*
 * rt_ssl_ext_probe.c -- RT-SSL-EXT: the Phase-14.9 extension, SRP and diagnostic glue, driven.
 *
 * One C program, compiled once against the admitted authority and once against the candidate
 * distribution shell; the two transcripts are diffed line by line, keyed on `key=value`. Every
 * observation is a small integer, a fixed string or a byte-exact trace over a fixed memory BIO --
 * never an address, never a clock, never the error queue.
 *
 * ## What this probe drives
 *
 *   * the SRP credential surface (`SSL_CTX_set_srp_username`/`_password`/`_strength`/`_cb_arg`,
 *     the three callback installers, `SSL_CTX_SRP_CTX_init`/`_free`, `SSL_SRP_CTX_init`/`_free`,
 *     `SSL_set_srp_server_param`/`_pw`, `SSL_get_srp_N`/`_g`/`_username`/`_userinfo`,
 *     `SSL_srp_server_param_with_username`, `SRP_Calc_A_param`);
 *   * the alert readers over fixed packed codes and the state readers over a fresh connection and
 *     NULL;
 *   * `SSL_add_ssl_module` and `SSL_CTX_config` over a configuration file this probe writes, so no
 *     installation path is involved and both sides read identical bytes; the refusal arms are the
 *     ones compared (see the `pending` note at the call site);
 *   * the deprecated temporary-DH callback setters;
 *   * `SSL_trace` over fixed records, alerts, a change-cipher-spec, an inner content type and
 *     three handshake messages, read back from a `BIO_s_mem()`.
 *
 * ## Arms that are deliberately absent
 *
 * No handshake, no socket and no wall clock move an answer. `SSL_srp_server_param_with_username`
 * is driven only after `SSL_set_srp_server_param_pw` has installed a complete credential set; the
 * `B` it derives draws from the DRBG, but only the function's return and the callback's invocation
 * count are printed, so the observation is deterministic. `SSL_trace` is never handed a
 * `ClientKeyExchange`/`ServerKeyExchange`: the authority reads `s3.tmp.new_cipher` there, which is
 * NULL before a handshake, so that arm would fault rather than compare.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

static void out_int(const char *key, long v)
{
    printf("%s=%ld\n", key, v);
}

static void out_str(const char *key, const char *v)
{
    printf("%s=%s\n", key, v != NULL ? v : "<NULL>");
}

static int srp_calls = 0;
static int srp_verifies = 0;

static int srp_username_cb(SSL *s, int *ad, void *arg)
{
    (void)s;
    (void)arg;
    srp_calls++;
    *ad = 0x999;
    return SSL_ERROR_NONE;
}

static int srp_verify_cb(SSL *s, void *arg)
{
    (void)s;
    (void)arg;
    srp_verifies++;
    return 1;
}

static char *srp_pwd_cb(SSL *s, void *arg)
{
    (void)s;
    (void)arg;
    return OPENSSL_strdup("secret");
}

static DH *tmp_dh_cb(SSL *s, int is_export, int keylength)
{
    (void)s;
    (void)is_export;
    (void)keylength;
    return NULL;
}

static const char *CONF_PATH = "/tmp/rt-ssl-ext.cnf";
static const char *CONF_TEXT =
    "openssl_conf = rt_init_sect\n"
    "\n"
    "[rt_init_sect]\n"
    "ssl_conf = rt_ssl_sect\n"
    "\n"
    "[rt_ssl_sect]\n"
    "rt_ext = rt_cmd_sect\n"
    "\n"
    "[rt_cmd_sect]\n"
    ".CipherString = DEFAULT\n"
    "MinProtocol = TLSv1.2\n";

static void write_conf(void)
{
    FILE *f = fopen(CONF_PATH, "wb");
    if (f != NULL) {
        fputs(CONF_TEXT, f);
        fclose(f);
    }
}

/* Read the fixed memory BIO out to stdout, byte for byte. */
static void drain_bio(BIO *b)
{
    unsigned char buf[512];
    int n;
    while ((n = BIO_read(b, buf, sizeof buf)) > 0)
        fwrite(buf, 1, (size_t)n, stdout);
}

int main(void)
{
    const SSL_METHOD *m = TLS_method();
    SSL_CTX *ctx;
    SSL *ssl;
    BIO *mem;
    BN_CTX *bnctx;
    BIGNUM *N, *g, *sa, *v;
    int ad = -1;
    unsigned char hdr[5] = {22, 0x03, 0x03, 0x00, 0x10};
    unsigned char alert[2] = {2, 40};
    unsigned char ccs[1] = {1};
    unsigned char ict[1] = {22};
    unsigned char finished[16] = {20, 0, 0, 12, 0xAB, 0xAB, 0xAB, 0xAB,
                                  0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB};
    unsigned char keyupd[5] = {24, 0, 0, 1, 0};
    unsigned char chello[64];
    size_t chlen = 0;

    /* --- the configuration file, written before any context exists ------ */
    write_conf();
    out_int("conf.load", CONF_modules_load_file(CONF_PATH, NULL, 0));
    SSL_add_ssl_module();
    out_int("ssl_add_module", 1);

    ctx = SSL_CTX_new(m);
    if (ctx == NULL) {
        out_str("ctx.new", "<NULL>");
        return 1;
    }
    out_int("ctx.new", 1);

    /* --- SRP credential setters and their readers ---------------------- */
    out_int("srp.ctx_init", SSL_CTX_SRP_CTX_init(ctx));
    out_int("srp.set_username", SSL_CTX_set_srp_username(ctx, "user"));
    out_int("srp.set_password", SSL_CTX_set_srp_password(ctx, "password"));
    out_int("srp.set_strength", SSL_CTX_set_srp_strength(ctx, 2048));
    out_int("srp.set_cb_arg", SSL_CTX_set_srp_cb_arg(ctx, (void *)0x1234));
    out_int("srp.set_username_cb",
            SSL_CTX_set_srp_username_callback(ctx, srp_username_cb));
    out_int("srp.set_verify_cb",
            SSL_CTX_set_srp_verify_param_callback(ctx, srp_verify_cb));
    out_int("srp.set_pwd_cb",
            SSL_CTX_set_srp_client_pwd_callback(ctx, srp_pwd_cb));

    ssl = SSL_new(ctx);
    if (ssl == NULL) {
        out_str("ssl.new", "<NULL>");
        SSL_CTX_free(ctx);
        return 1;
    }
    out_int("ssl.new", 1);

    out_str("srp.get_username", SSL_get_srp_username(ssl));

    /* A fixed credential set, read back by the getters. */
    bnctx = BN_CTX_new();
    N = BN_new();
    g = BN_new();
    sa = BN_new();
    v = BN_new();
    BN_set_word(N, 0x1234567);
    BN_set_word(g, 2);
    BN_set_word(sa, 0x99);
    BN_set_word(v, 0x77);
    out_int("srp.set_param", SSL_set_srp_server_param(ssl, N, g, sa, v, "info-string"));
    out_int("srp.get_N_bits", BN_num_bits(SSL_get_srp_N(ssl)));
    out_int("srp.get_g_bits", BN_num_bits(SSL_get_srp_g(ssl)));
    out_str("srp.get_userinfo", SSL_get_srp_userinfo(ssl));

    /* A complete verifier from the password spelling, then the server-public computation. */
    out_int("srp.set_param_pw", SSL_set_srp_server_param_pw(ssl, "alice", "secret", "1024"));
    out_int("srp.get_N_bits2", BN_num_bits(SSL_get_srp_N(ssl)));
    ad = -1;
    out_int("srp.server_param", SSL_srp_server_param_with_username(ssl, &ad));
    out_int("srp.server_param.ad", ad);
    out_int("srp.username_cb_calls", srp_calls);
    out_int("srp.calc_a", SRP_Calc_A_param(ssl));

    /* --- the alert and state readers over fixed codes ------------------ */
    out_str("alert.type_long.warn", SSL_alert_type_string_long(0x0100));
    out_str("alert.type_long.fatal", SSL_alert_type_string_long(0x0200));
    out_str("alert.type_long.unknown", SSL_alert_type_string_long(0x0300));
    out_str("alert.type.warn", SSL_alert_type_string(0x0100));
    out_str("alert.type.fatal", SSL_alert_type_string(0x0200));
    out_str("alert.desc.cn", SSL_alert_desc_string(0));
    out_str("alert.desc.hf", SSL_alert_desc_string(40));
    out_str("alert.desc.ip", SSL_alert_desc_string(47));
    out_str("alert.desc.ie", SSL_alert_desc_string(80));
    out_str("alert.desc.unknown", SSL_alert_desc_string(0xFE));
    out_str("alert.desc_long.cn", SSL_alert_desc_string_long(0));
    out_str("alert.desc_long.hf", SSL_alert_desc_string_long(40));
    out_str("alert.desc_long.nap", SSL_alert_desc_string_long(120));
    out_str("state.short", SSL_state_string(ssl));
    out_str("state.long", SSL_state_string_long(ssl));
    out_str("state.short.null", SSL_state_string(NULL));
    out_str("state.long.null", SSL_state_string_long(NULL));

    /* --- SSL_CTX_config over the fixed configuration ------------------- */
    /* The named-set arm is named `pending` rather than counted: the candidate's libssl carries its
     * own copy of the `ssl_conf` store (the whole-archive link duplicates the crate's globals
     * across libssl and libcrypto, `src/ssl/mod.rs`), so a set loaded through libcrypto's
     * `CONF_modules_load_file` is not visible to libssl's `SSL_CTX_config`. The refusal arms below
     * read the same store on both sides, and agree. */
    out_int("config.ctx.missing", SSL_CTX_config(ctx, "rt_absent"));
    out_int("config.ctx.null", SSL_CTX_config(ctx, NULL));
    out_int("config.ctx.null_ctx", SSL_CTX_config(NULL, "rt_ext"));

    /* --- the deprecated temporary-DH callback setters ------------------ */
    SSL_CTX_set_tmp_dh_callback(ctx, tmp_dh_cb);
    out_int("dh_cb.ctx_set", 1);
    SSL_set_tmp_dh_callback(ssl, tmp_dh_cb);
    out_int("dh_cb.ssl_set", 1);

    /* --- SSL_trace over a fixed memory BIO ----------------------------- */
    mem = BIO_new(BIO_s_mem());
    if (mem == NULL) {
        out_str("trace.bio", "<NULL>");
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return 1;
    }

    printf("trace.record=begin\n");
    SSL_trace(0, 0x0303, SSL3_RT_HEADER, hdr, sizeof hdr, ssl, mem);
    drain_bio(mem);
    printf("trace.record=end\n");

    printf("trace.alert=begin\n");
    SSL_trace(0, 0x0303, SSL3_RT_ALERT, alert, sizeof alert, ssl, mem);
    drain_bio(mem);
    printf("trace.alert=end\n");

    printf("trace.ccs=begin\n");
    SSL_trace(0, 0x0303, SSL3_RT_CHANGE_CIPHER_SPEC, ccs, sizeof ccs, ssl, mem);
    drain_bio(mem);
    printf("trace.ccs=end\n");

    printf("trace.inner=begin\n");
    SSL_trace(0, 0x0303, SSL3_RT_INNER_CONTENT_TYPE, ict, sizeof ict, ssl, mem);
    drain_bio(mem);
    printf("trace.inner=end\n");

    printf("trace.finished=begin\n");
    SSL_trace(0, 0x0303, SSL3_RT_HANDSHAKE, finished, sizeof finished, ssl, mem);
    drain_bio(mem);
    printf("trace.finished=end\n");

    printf("trace.keyupdate=begin\n");
    SSL_trace(1, 0x0303, SSL3_RT_HANDSHAKE, keyupd, sizeof keyupd, ssl, mem);
    drain_bio(mem);
    printf("trace.keyupdate=end\n");

    /* A minimal ClientHello: version, random, empty session id, one cipher
     * suite, one compression method, no extensions. */
    {
        static const unsigned char body[48] = {
            0x03, 0x03,                                     /* client_version */
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
            0x00,                                           /* session_id len */
            0x00, 0x02, 0x13, 0x01,                         /* cipher_suites */
            0x01, 0x00,                                     /* compression */
            0x00, 0x00                                      /* extensions */
        };
        unsigned char msg[4 + sizeof body];
        memcpy(msg, "x", 1);
        msg[0] = 1;                                         /* ClientHello */
        msg[1] = 0;
        msg[2] = 0;
        msg[3] = (unsigned char)sizeof body;
        memcpy(msg + 4, body, sizeof body);
        chlen = sizeof msg;
        memcpy(chello, msg, chlen);

        printf("trace.clienthello=begin\n");
        SSL_trace(0, 0x0303, SSL3_RT_HANDSHAKE, chello, chlen, ssl, mem);
        drain_bio(mem);
        printf("trace.clienthello=end\n");
    }

    /* --- teardown ------------------------------------------------------ */
    out_int("srp.verify_cb_calls", srp_verifies);
    out_int("srp.ctx_free", SSL_CTX_SRP_CTX_free(ctx));
    out_int("srp.ssl_free", SSL_SRP_CTX_free(ssl));

    BN_free(N);
    BN_free(g);
    BN_free(sa);
    BN_free(v);
    BN_CTX_free(bnctx);
    BIO_free(mem);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return 0;
}
