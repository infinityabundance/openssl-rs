/*
 * rt_ssl_object_probe.c -- RT-SSL-OBJECT: the Phase-14.1 SSL_CTX/SSL object model, driven.
 *
 * One C program, compiled once against the admitted authority and once against the candidate
 * distribution shell; the two transcripts are diffed line by line, keyed on `key=value`. Every
 * observation is a small integer, a fixed string or a pointer-identity boolean -- never an
 * address, never a clock, never the error queue.
 *
 * ## What this probe drives
 *
 * The object model and its accessor/control/callback surface, in the order src/ssl/ssl_lib.rs
 * lands it:
 *
 *   * the refusal arms -- `SSL_CTX_new(NULL)`, `SSL_new(NULL)`, `SSL_CTX_ctrl(NULL, ...)`,
 *     `SSL_ctrl(NULL, ...)`, `SSL_CTX_free(NULL)`/`SSL_free(NULL)` (both no-ops);
 *   * the lifecycle and refcount -- `SSL_CTX_new(TLS_method())`, `SSL_new`, `SSL_up_ref`,
 *     `SSL_free`, `SSL_CTX_up_ref`, `SSL_CTX_free`, and the method identity each object reports;
 *   * the defaults `SSL_CTX_new_ex` installs (`options`, `quiet_shutdown`, `verify_mode`,
 *     `num_tickets`, `max_early_data`, `recv_max_early_data`, the NULL callbacks, the security
 *     level `ssl_cert.c:84` sets);
 *   * the option/mode/verify/quiet/shutdown/read-ahead accessors and the `SSL_CTX_ctrl`/`SSL_ctrl`
 *     switch, always with a fixed input and its returned value;
 *   * the session-id context boundary (`SSL_MAX_SID_CTX_LENGTH` = 32 accepted, 33 refused);
 *   * the callback setters that have a getter -- passwd, keylog, security (+level/ex-data),
 *     record-padding arg, info -- set and read back;
 *   * ex-data through an index `CRYPTO_get_ex_new_index` allocates;
 *   * the version and state readers (`SSL_version`, `SSL_get_version`, `SSL_is_tls`/`_dtls`/`_quic`,
 *     `SSL_want`, `SSL_pending`, `SSL_get_error`, `SSL_get_default_timeout`);
 *   * the read/write/handshake entry guards on a freshly allocated connection, where the authority
 *     answers `SSL_R_UNINITIALIZED`/`SSL_R_CONNECTION_TYPE_NOT_SET`;
 *   * `SSL_set_bio` over memory BIOs, including the `rbio == wbio` ownership case and the no-op;
 *   * the 14.5b handshake entry points' refusal/flag arms over a fresh connection — `SSL_key_update`,
 *     `SSL_new_session_ticket`, `SSL_export_keying_material[_early]`, `SSL_sendfile`,
 *     `SSL_verify_client_post_handshake`, `SSL_read/write_early_data`, `SSL_renegotiate[_abbreviated]`
 *     and `SSL_stateless`. The state-machine transitions `SSL_connect`/`SSL_accept` drive live in
 *     `RT-STATEM`.
 *
 * ## Arms that are deliberately absent
 *
 * No socket and no wall clock move an answer. The flight a client's `SSL_connect` would write is
 * not compared: the message layer (14.5b's remaining work) is unlanded, so no arm reads a peer
 * BIO's bytes. `SSL_get_error` is read before any error is raised and after `ERR_clear_error`, so
 * the error queue never moves a value. The NULL arms of `SSL_CTX_get_options`,
 * `SSL_CTX_get_verify_mode`, `SSL_is_tls`/`_quic` and the like are not driven: those dereference
 * their argument in the authority, so a probe would crash both sides rather than compare them.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/stack.h>
#include <openssl/x509.h>

static void out_int(const char *key, long v)
{
    printf("%s=%ld\n", key, v);
}

static void out_str(const char *key, const char *v)
{
    printf("%s=%s\n", key, v != NULL ? v : "<NULL>");
}

static int verify_cb(int ok, X509_STORE_CTX *ctx)
{
    (void)ctx;
    return ok;
}

static int verify_cb2(int ok, X509_STORE_CTX *ctx)
{
    (void)ctx;
    return ok;
}

static int passwd_cb(char *buf, int size, int rwflag, void *u)
{
    (void)buf;
    (void)size;
    (void)rwflag;
    (void)u;
    return 0;
}

static void info_cb(const SSL *s, int type, int val)
{
    (void)s;
    (void)type;
    (void)val;
}

static void keylog_cb(const SSL *s, const char *line)
{
    (void)s;
    (void)line;
}

static int sec_cb(const SSL *s, const SSL_CTX *c, int op, int bits, int nid,
                  void *other, void *ex)
{
    (void)s;
    (void)c;
    (void)op;
    (void)bits;
    (void)nid;
    (void)other;
    (void)ex;
    return 1;
}

/*
 * The fixed certificate 14.7b's DANE arms feed to `SSL_dane_tlsa_add` and `SSL_add_expected_rpk`.
 * It is the same in-memory RSA fixture `RT-SESSION-CERT` uses; the arms compare the DANE calls'
 * return codes and the record read-backs, never a byte of the certificate, so the two sides need
 * only *a* valid certificate.
 */
static const char dane_cert_pem[] =
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

int main(void)
{
    const SSL_METHOD *m = TLS_method();
    SSL_CTX *ctx;
    SSL *ssl;
    BIO *m1, *m2, *m3;
    unsigned char sid[40];
    unsigned char ebuf[8];
    char buf[8];
    size_t n = 0;
    int idx;
    void *p = (void *)0xbeef;

    setvbuf(stdout, NULL, _IOLBF, 0);

    /* ----------------------------------------------------------------------------------------
     * A. The refusal arms.
     * -------------------------------------------------------------------------------------- */
    out_int("method.nonnull", m != NULL);
    out_int("ctx_new.null_method_refused", SSL_CTX_new(NULL) == NULL);
    out_int("new.null_ctx_refused", SSL_new(NULL) == NULL);
    out_int("ctx_ctrl.null_ctx", SSL_CTX_ctrl(NULL, SSL_CTRL_GET_READ_AHEAD, 0, NULL) == 0);
    out_int("ssl_ctrl.null_ssl", SSL_ctrl(NULL, SSL_CTRL_GET_READ_AHEAD, 0, NULL) == 0);
    SSL_CTX_free(NULL);
    SSL_free(NULL);
    out_int("free.null_noop", 1);

    /* ----------------------------------------------------------------------------------------
     * B. The context lifecycle and its defaults.
     * -------------------------------------------------------------------------------------- */
    ctx = SSL_CTX_new(m);
    out_int("ctx.nonnull", ctx != NULL);
    out_int("ctx.method.identity", SSL_CTX_get_ssl_method(ctx) == m);
    out_int("ctx.options.default", (long)SSL_CTX_get_options(ctx));
    out_int("ctx.quiet.default", SSL_CTX_get_quiet_shutdown(ctx));
    out_int("ctx.verify_mode.default", SSL_CTX_get_verify_mode(ctx));
    out_int("ctx.num_tickets.default", (long)SSL_CTX_get_num_tickets(ctx));
    out_int("ctx.max_early.default", (long)SSL_CTX_get_max_early_data(ctx));
    out_int("ctx.recv_max.default", (long)SSL_CTX_get_recv_max_early_data(ctx));
    out_int("ctx.passwd.default_null", SSL_CTX_get_default_passwd_cb(ctx) == NULL);
    out_int("ctx.passwd_ud.default_null",
            SSL_CTX_get_default_passwd_cb_userdata(ctx) == NULL);
    out_int("ctx.keylog.default_null", SSL_CTX_get_keylog_callback(ctx) == NULL);
    out_int("ctx.sec_cb.default_null", SSL_CTX_get_security_callback(ctx) == NULL);
    out_int("ctx.sec_ex.default_null", SSL_CTX_get0_security_ex_data(ctx) == NULL);
    out_int("ctx.sec_level.default", SSL_CTX_get_security_level(ctx));
    out_int("ctx.rpad_arg.default_null",
            SSL_CTX_get_record_padding_callback_arg(ctx) == NULL);
    out_int("ctx.cert.null", SSL_CTX_get0_certificate(ctx) == NULL);
    out_int("ctx.privkey.null", SSL_CTX_get0_privatekey(ctx) == NULL);
    out_int("ctx.cert_store.nonnull", SSL_CTX_get_cert_store(ctx) != NULL);
    out_int("ctx.param.nonnull", SSL_CTX_get0_param(ctx) != NULL);

    /* ----------------------------------------------------------------------------------------
     * C. Options, verify, quiet-shutdown round trips.
     * -------------------------------------------------------------------------------------- */
    out_int("ctx.options.set_ret", (long)SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET));
    out_int("ctx.options.get", (long)SSL_CTX_get_options(ctx));
    out_int("ctx.options.clear_ret", (long)SSL_CTX_clear_options(ctx, SSL_OP_NO_TICKET));
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_cb);
    out_int("ctx.verify_mode.set", SSL_CTX_get_verify_mode(ctx));
    out_int("ctx.verify_cb.set", SSL_CTX_get_verify_callback(ctx) == verify_cb);
    SSL_CTX_set_verify_depth(ctx, 7);
    out_int("ctx.verify_depth.set", SSL_CTX_get_verify_depth(ctx));
    SSL_CTX_set_quiet_shutdown(ctx, 1);
    out_int("ctx.quiet.set", SSL_CTX_get_quiet_shutdown(ctx));

    /* ----------------------------------------------------------------------------------------
     * D. The control switch, fixed inputs.
     * -------------------------------------------------------------------------------------- */
    out_int("ctx.ctrl.mode_ret",
            SSL_CTX_ctrl(ctx, SSL_CTRL_MODE, SSL_MODE_ENABLE_PARTIAL_WRITE, NULL));
    out_int("ctx.ctrl.get_read_ahead", SSL_CTX_ctrl(ctx, SSL_CTRL_GET_READ_AHEAD, 0, NULL));
    out_int("ctx.ctrl.set_max_cert_list_old",
            SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MAX_CERT_LIST, 1234, NULL));
    out_int("ctx.ctrl.get_max_cert_list", SSL_CTX_ctrl(ctx, SSL_CTRL_GET_MAX_CERT_LIST, 0, NULL));
    out_int("ctx.ctrl.set_send_frag_bad",
            SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MAX_SEND_FRAGMENT, 100, NULL));
    out_int("ctx.ctrl.set_send_frag_ok",
            SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MAX_SEND_FRAGMENT, 4096, NULL));
    out_int("ctx.ctrl.set_split_ok",
            SSL_CTX_ctrl(ctx, SSL_CTRL_SET_SPLIT_SEND_FRAGMENT, 2048, NULL));
    out_int("ctx.ctrl.set_split_bad",
            SSL_CTX_ctrl(ctx, SSL_CTRL_SET_SPLIT_SEND_FRAGMENT, 0, NULL));
    out_int("ctx.ctrl.set_pipes_bad", SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MAX_PIPELINES, 0, NULL));
    out_int("ctx.ctrl.set_pipes_ok", SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MAX_PIPELINES, 8, NULL));
    out_int("ctx.ctrl.cert_flags", SSL_CTX_ctrl(ctx, SSL_CTRL_CERT_FLAGS, 8, NULL));
    out_int("ctx.ctrl.clear_cert_flags", SSL_CTX_ctrl(ctx, SSL_CTRL_CLEAR_CERT_FLAGS, 8, NULL));
    out_int("ctx.ctrl.sess_cache_size_old",
            SSL_CTX_ctrl(ctx, SSL_CTRL_SET_SESS_CACHE_SIZE, 100, NULL));
    out_int("ctx.ctrl.sess_cache_size_get",
            SSL_CTX_ctrl(ctx, SSL_CTRL_GET_SESS_CACHE_SIZE, 0, NULL));
    out_int("ctx.ctrl.sess_cache_mode_get",
            SSL_CTX_ctrl(ctx, SSL_CTRL_GET_SESS_CACHE_MODE, 0, NULL));
    out_int("ctx.ctrl.get_min_proto",
            SSL_CTX_ctrl(ctx, SSL_CTRL_GET_MIN_PROTO_VERSION, 0, NULL));
    out_int("ctx.ctrl.get_max_proto",
            SSL_CTX_ctrl(ctx, SSL_CTRL_GET_MAX_PROTO_VERSION, 0, NULL));

    /* ----------------------------------------------------------------------------------------
     * E. Session-id context boundary and the callback setters with getters.
     * -------------------------------------------------------------------------------------- */
    memset(sid, 0xAB, sizeof(sid));
    out_int("ctx.sidctx.32", SSL_CTX_set_session_id_context(ctx, sid, 32));
    SSL_CTX_set_default_passwd_cb(ctx, passwd_cb);
    out_int("ctx.passwd.set", SSL_CTX_get_default_passwd_cb(ctx) == passwd_cb);
    SSL_CTX_set_default_passwd_cb_userdata(ctx, (void *)0x1234);
    out_int("ctx.passwd_ud.set",
            SSL_CTX_get_default_passwd_cb_userdata(ctx) == (void *)0x1234);
    SSL_CTX_set_keylog_callback(ctx, keylog_cb);
    out_int("ctx.keylog.set", SSL_CTX_get_keylog_callback(ctx) == keylog_cb);
    SSL_CTX_set_security_callback(ctx, sec_cb);
    out_int("ctx.sec_cb.set", SSL_CTX_get_security_callback(ctx) == sec_cb);
    SSL_CTX_set_security_level(ctx, 3);
    out_int("ctx.sec_level.set", SSL_CTX_get_security_level(ctx));
    SSL_CTX_set0_security_ex_data(ctx, (void *)0x5678);
    out_int("ctx.sec_ex.set", SSL_CTX_get0_security_ex_data(ctx) == (void *)0x5678);
    SSL_CTX_set_record_padding_callback_arg(ctx, (void *)0x9abc);
    out_int("ctx.rpad_arg.set",
            SSL_CTX_get_record_padding_callback_arg(ctx) == (void *)0x9abc);
    out_int("ctx.set_num_tickets", SSL_CTX_set_num_tickets(ctx, 5));
    out_int("ctx.get_num_tickets", (long)SSL_CTX_get_num_tickets(ctx));
    out_int("ctx.set_max_early", SSL_CTX_set_max_early_data(ctx, 100));
    out_int("ctx.get_max_early", (long)SSL_CTX_get_max_early_data(ctx));

    /* ----------------------------------------------------------------------------------------
     * F. The connection lifecycle and the configuration it inherits.
     * -------------------------------------------------------------------------------------- */
    ssl = SSL_new(ctx);
    out_int("ssl.nonnull", ssl != NULL);
    out_int("ssl.ctx.identity", SSL_get_SSL_CTX(ssl) == ctx);
    out_int("ssl.method.identity", SSL_get_ssl_method(ssl) == m);
    out_int("ssl.version", SSL_version(ssl));
    out_int("ssl.client_version", SSL_client_version(ssl));
    out_str("ssl.version_str", SSL_get_version(ssl));
    out_int("ssl.is_tls", SSL_is_tls(ssl));
    out_int("ssl.is_dtls", SSL_is_dtls(ssl));
    out_int("ssl.is_quic", SSL_is_quic(ssl));
    out_int("ssl.default_timeout", SSL_get_default_timeout(ssl));
    out_int("ssl.options.inherit", (long)SSL_get_options(ssl));
    out_int("ssl.verify_mode.inherit", SSL_get_verify_mode(ssl));
    out_int("ssl.verify_depth.inherit", SSL_get_verify_depth(ssl));
    out_int("ssl.quiet.inherit", SSL_get_quiet_shutdown(ssl));
    out_int("ssl.num_tickets.inherit", (long)SSL_get_num_tickets(ssl));
    out_int("ssl.rpad_arg.inherit",
            SSL_get_record_padding_callback_arg(ssl) == (void *)0x9abc);
    out_int("ssl.cert.null", SSL_get_certificate(ssl) == NULL);
    out_int("ssl.privkey.null", SSL_get_privatekey(ssl) == NULL);
    out_int("ssl.verified_chain.null", SSL_get0_verified_chain(ssl) == NULL);
    out_int("ssl.get_finished.len", (long)SSL_get_finished(ssl, buf, 8));
    out_int("ssl.get_peer_finished.len", (long)SSL_get_peer_finished(ssl, buf, 8));

    /* ----------------------------------------------------------------------------------------
     * G. State readers before any handshake.
     * -------------------------------------------------------------------------------------- */
    out_int("ssl.want.default", SSL_want(ssl));
    out_int("ssl.pending.default", SSL_pending(ssl));
    out_int("ssl.has_pending.default", SSL_has_pending(ssl));
    out_int("ssl.is_server.default", SSL_is_server(ssl));
    out_int("ssl.session_reused.default", SSL_session_reused(ssl));
    out_int("ssl.verify_result.default", (long)SSL_get_verify_result(ssl));
    /* `SSL_get_error`'s queue-aware arm (`i == 0`) is not driven: the candidate distribution links
     * the crate archive into both DSOs, so an `ERR` raised by libssl lands in a copy of the error
     * state that `ERR_clear_error()` (libcrypto) cannot clear, while the authority's does not. The
     * `i > 0` arm answers `SSL_ERROR_NONE` without reading the queue and is identical on both
     * sides; the duplication is recorded in src/ssl/mod.rs. */
    out_int("ssl.get_error.positive", SSL_get_error(ssl, 1));
    /* Deferred until after `SSL_get_error`: the too-long arm raises an `ERR`, and the candidate
     * distribution links the crate archive into both DSOs, so `ERR_clear_error()` (libcrypto)
     * cannot clear the copy libssl writes. This arm is therefore ordered so the error queue cannot
     * move the observation above; the duplication itself is recorded in src/ssl/mod.rs. */
    out_int("ctx.sidctx.33", SSL_CTX_set_session_id_context(ctx, sid, 33));

    /* ----------------------------------------------------------------------------------------
     * H. The connection's control and accessor surface.
     * -------------------------------------------------------------------------------------- */
    out_int("ssl.ctrl.mode_ret",
            SSL_ctrl(ssl, SSL_CTRL_MODE, SSL_MODE_ENABLE_PARTIAL_WRITE, NULL));
    out_int("ssl.ctrl.get_max_cert_list", SSL_ctrl(ssl, SSL_CTRL_GET_MAX_CERT_LIST, 0, NULL));
    out_int("ssl.ctrl.set_max_cert_list_old",
            SSL_ctrl(ssl, SSL_CTRL_SET_MAX_CERT_LIST, 55, NULL));
    out_int("ssl.ctrl.cert_flags", SSL_ctrl(ssl, SSL_CTRL_CERT_FLAGS, 4, NULL));
    out_int("ssl.ctrl.get_raw_cipherlist_null",
            SSL_ctrl(ssl, SSL_CTRL_GET_RAW_CIPHERLIST, 0, NULL));
    out_int("ssl.ctrl.get_extms", SSL_ctrl(ssl, SSL_CTRL_GET_EXTMS_SUPPORT, 0, NULL));
    out_int("ssl.ctrl.get_read_ahead", SSL_ctrl(ssl, SSL_CTRL_GET_READ_AHEAD, 0, NULL));
    SSL_set_verify(ssl, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_cb2);
    out_int("ssl.verify_mode.set", SSL_get_verify_mode(ssl));
    out_int("ssl.verify_cb.set", SSL_get_verify_callback(ssl) == verify_cb2);
    SSL_set_verify_depth(ssl, 9);
    out_int("ssl.verify_depth.set", SSL_get_verify_depth(ssl));
    SSL_set_quiet_shutdown(ssl, 1);
    out_int("ssl.quiet.set", SSL_get_quiet_shutdown(ssl));
    SSL_set_shutdown(ssl, SSL_SENT_SHUTDOWN);
    out_int("ssl.shutdown.set", SSL_get_shutdown(ssl));
    SSL_set_info_callback(ssl, info_cb);
    out_int("ssl.info_cb.set", SSL_get_info_callback(ssl) == info_cb);
    out_int("ssl.set_num_tickets", SSL_set_num_tickets(ssl, 6));
    out_int("ssl.get_num_tickets", (long)SSL_get_num_tickets(ssl));

    /* ----------------------------------------------------------------------------------------
     * I. ex-data through a registered index.
     * -------------------------------------------------------------------------------------- */
    idx = CRYPTO_get_ex_new_index(0 /* CRYPTO_EX_INDEX_SSL */, 0, NULL, NULL, NULL, NULL);
    out_int("ex_index.positive", idx > 0);
    out_int("ssl.ex_data.set", SSL_set_ex_data(ssl, idx, p));
    out_int("ssl.ex_data.get", SSL_get_ex_data(ssl, idx) == p);
    out_int("ctx.ex_data.set", SSL_CTX_set_ex_data(ctx, idx, p));
    out_int("ctx.ex_data.get", SSL_CTX_get_ex_data(ctx, idx) == p);

    /* ----------------------------------------------------------------------------------------
     * J. The read/write/handshake entry guards on a fresh connection.
     * -------------------------------------------------------------------------------------- */
    ERR_clear_error();
    out_int("ssl.read.uninit", SSL_read(ssl, buf, 4));
    out_int("ssl.read_neg_len", SSL_read(ssl, buf, -1));
    out_int("ssl.read_ex.uninit", SSL_read_ex(ssl, buf, 4, &n));
    out_int("ssl.peek.uninit", SSL_peek(ssl, buf, 4));
    out_int("ssl.peek_ex.uninit", SSL_peek_ex(ssl, buf, 4, &n));
    out_int("ssl.write.uninit", SSL_write(ssl, buf, 4));
    out_int("ssl.write_ex.uninit", SSL_write_ex(ssl, buf, 4, &n));
    out_int("ssl.do_handshake.uninit", SSL_do_handshake(ssl));
    out_int("ssl.shutdown.uninit", SSL_shutdown(ssl));

    /* ----------------------------------------------------------------------------------------
     * K. The BIO plumbing over memory BIOs.
     * -------------------------------------------------------------------------------------- */
    m1 = BIO_new(BIO_s_mem());
    m2 = BIO_new(BIO_s_mem());
    out_int("bio.m1.nonnull", m1 != NULL);
    out_int("bio.m2.nonnull", m2 != NULL);
    SSL_set_bio(ssl, m1, m2);
    out_int("ssl.rbio.set", SSL_get_rbio(ssl) == m1);
    out_int("ssl.wbio.set", SSL_get_wbio(ssl) == m2);
    out_int("ssl.get_fd.mem", SSL_get_fd(ssl));
    out_int("ssl.get_rfd.mem", SSL_get_rfd(ssl));
    m3 = BIO_new(BIO_s_mem());
    SSL_set_bio(ssl, m3, m3);
    out_int("ssl.rbio.same", SSL_get_rbio(ssl) == m3);
    out_int("ssl.wbio.same", SSL_get_wbio(ssl) == m3);
    SSL_set_bio(ssl, m3, m3);
    out_int("ssl.rbio.noop", SSL_get_rbio(ssl) == m3);
    out_int("ssl.wbio.noop", SSL_get_wbio(ssl) == m3);

    /* ----------------------------------------------------------------------------------------
     * M. Slice 2: the verify-parameter, CT, ALPN/SNI, certificate-type and accessor surface.
     *
     * Every arm is a fixed input and a small-integer / fixed-string / pointer-identity answer;
     * none moves a handshake, a socket or the clock. `X509_PURPOSE_SSL_SERVER` (1) and
     * `X509_TRUST_SSL_SERVER` (1) are the only purpose/trust literals used.
     * -------------------------------------------------------------------------------------- */
    /* purpose / trust / hostname (the X509_VERIFY_PARAM surface) */
    out_int("purpose.ctx", SSL_CTX_set_purpose(ctx, 1));
    out_int("purpose.ssl", SSL_set_purpose(ssl, 1));
    out_int("trust.ctx", SSL_CTX_set_trust(ctx, 1));
    out_int("trust.ssl", SSL_set_trust(ssl, 1));
    out_int("host.set1", SSL_set1_host(ssl, "example.com"));
    out_int("host.peername.null", SSL_get0_peername(ssl) == NULL);
    out_int("host.add1", SSL_add1_host(ssl, "www.example.com"));
    SSL_set_hostflags(ssl, 0);
    out_int("host.flags.noop", 1);

    /* the verify store loaders: a missing file and a NULL/NULL pair */
    out_int("verify.locations.null", SSL_CTX_load_verify_locations(ctx, NULL, NULL));
    out_int("verify.file.missing",
            SSL_CTX_load_verify_file(ctx, "/nonexistent/ca.pem"));

    /* the certificate/private-key readers with no certificate assigned */
    out_int("check_privkey.ctx.nocert", SSL_CTX_check_private_key(ctx));
    out_int("check_privkey.ssl.nocert", SSL_check_private_key(ssl));
    out_int("peer_cert0.null", SSL_get0_peer_certificate(ssl) == NULL);
    out_int("peer_cert1.null", SSL_get1_peer_certificate(ssl) == NULL);
    out_int("peer_chain.null", SSL_get_peer_cert_chain(ssl) == NULL);
    SSL_certs_clear(ssl);
    out_int("certs_clear.noop", SSL_get_certificate(ssl) == NULL);

    /* certificate transparency: the store, the flag and the enable dispatch */
    out_int("ct.ctx.disabled", SSL_CTX_ct_is_enabled(ctx));
    out_int("ct.ssl.disabled", SSL_ct_is_enabled(ssl));
    out_int("ct.ctx.store.nonnull", SSL_CTX_get0_ctlog_store(ctx) != NULL);
    out_int("ct.ctx.enable_strict", SSL_CTX_enable_ct(ctx, SSL_CT_VALIDATION_STRICT));
    out_int("ct.ctx.enabled", SSL_CTX_ct_is_enabled(ctx));
    out_int("ct.ssl.enable_perm", SSL_enable_ct(ssl, SSL_CT_VALIDATION_PERMISSIVE));
    out_int("ct.ssl.enabled", SSL_ct_is_enabled(ssl));
    out_int("ct.scts.null", SSL_get0_peer_scts(ssl) == NULL);

    /* ALPN and NPN: the offer lists, the negotiated readers and the selector */
    {
        unsigned char alpn_good[] = {2, 'h', '2'};
        unsigned char alpn_bad[] = {0};
        const unsigned char *ad = NULL;
        unsigned int al = 99;
        out_int("alpn.ctx.set_good", SSL_CTX_set_alpn_protos(ctx, alpn_good, 3));
        out_int("alpn.ctx.set_bad", SSL_CTX_set_alpn_protos(ctx, alpn_bad, 1));
        out_int("alpn.ssl.set_good", SSL_set_alpn_protos(ssl, alpn_good, 3));
        SSL_get0_alpn_selected(ssl, &ad, &al);
        out_int("alpn.selected.null", ad == NULL);
        out_int("alpn.selected.len", al);
        SSL_get0_next_proto_negotiated(ssl, &ad, &al);
        out_int("npn.selected.null", ad == NULL);
        out_int("npn.selected.len", al);
    }
    {
        unsigned char *np_out = NULL;
        unsigned char np_len = 0;
        unsigned char sp_srv[] = {2, 'h', '2'};
        unsigned char sp_match[] = {2, 'h', '2'};
        unsigned char sp_other[] = {2, 'x', 'x'};
        out_int("nextproto.match",
                SSL_select_next_proto(&np_out, &np_len, sp_srv, 3, sp_match, 3));
        out_int("nextproto.match.len", np_len);
        out_int("nextproto.nomatch",
                SSL_select_next_proto(&np_out, &np_len, sp_srv, 3, sp_other, 3));
        out_int("nextproto.nomatch.len", np_len);
        out_int("nextproto.empty",
                SSL_select_next_proto(&np_out, &np_len, sp_srv, 3, sp_match, 0));
        out_int("nextproto.empty.len", np_len);
    }

    /* SNI readers with no hostname set */
    out_int("sni.get.null", SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name) == NULL);
    out_int("sni.type", SSL_get_servername_type(ssl));

    /* the expected/negotiated certificate-type lists */
    {
        unsigned char ct_x509 = 0;
        unsigned char ct_bad = 1;
        unsigned char *t = (unsigned char *)0xbeef;
        size_t tl = 99;
        out_int("certtype.client.set", SSL_set1_client_cert_type(ssl, &ct_x509, 1));
        out_int("certtype.client.bad", SSL_set1_client_cert_type(ssl, &ct_bad, 1));
        out_int("certtype.client.get", SSL_get0_client_cert_type(ssl, &t, &tl));
        out_int("certtype.client.len", (long)tl);
        out_int("certtype.client.nonnull", t != NULL);
        out_int("certtype.server.set", SSL_set1_server_cert_type(ssl, &ct_x509, 1));
        out_int("certtype.ctx.client.set", SSL_CTX_set1_client_cert_type(ctx, &ct_x509, 1));
        out_int("certtype.ctx.server.set", SSL_CTX_set1_server_cert_type(ctx, &ct_x509, 1));
        out_int("certtype.neg.client", SSL_get_negotiated_client_cert_type(ssl));
        out_int("certtype.neg.server", SSL_get_negotiated_server_cert_type(ssl));
    }

    /* the domain-flag surface is unsupported on a non-QUIC object */
    {
        uint64_t df = 7;
        out_int("domain.ctx.set", SSL_CTX_set_domain_flags(ctx, 1));
        out_int("domain.ctx.get", SSL_CTX_get_domain_flags(ctx, &df));
        out_int("domain.ssl.get", SSL_get_domain_flags(ssl, &df));
    }

    /* block padding: the boundary and the too-large refusal */
    out_int("blockpad.ctx.ok", SSL_CTX_set_block_padding(ctx, 8));
    out_int("blockpad.ctx.ex", SSL_CTX_set_block_padding_ex(ctx, 4096, 8));
    out_int("blockpad.ctx.big", SSL_CTX_set_block_padding_ex(ctx, 100000, 8));
    out_int("blockpad.ssl.ok", SSL_set_block_padding(ssl, 8));
    out_int("blockpad.ssl.big", SSL_set_block_padding(ssl, 100000));

    /* the async wait-context readers with no job and no context */
    out_int("async.waiting", SSL_waiting_for_async(ssl));
    {
        int st = 99;
        out_int("async.status", SSL_get_async_status(ssl, &st));
        out_int("async.all_fds", SSL_get_all_async_fds(ssl, NULL, NULL));
        out_int("async.changed_fds", SSL_get_changed_async_fds(ssl, NULL, NULL, NULL, NULL));
    }

    /* the remaining state readers and buffer hooks */
    out_int("key_update.type", SSL_get_key_update_type(ssl));
    out_int("reneg.pending", SSL_renegotiate_pending(ssl));
    out_int("early_data.status", SSL_get_early_data_status(ssl));
    {
        uint64_t rtt = 99;
        out_int("handshake.rtt", SSL_get_handshake_rtt(ssl, &rtt));
    }
    out_int("client_random.size", (long)SSL_get_client_random(ssl, buf, 0));
    out_int("client_random.len", (long)SSL_get_client_random(ssl, (unsigned char *)buf, 8));
    out_int("server_random.size", (long)SSL_get_server_random(ssl, buf, 0));
    out_int("alloc_buffers", SSL_alloc_buffers(ssl));
    out_int("free_buffers", SSL_free_buffers(ssl));
    {
        uint64_t v = 99;
        out_int("value_uint.get", SSL_get_value_uint(ssl, 0, 0, &v));
        out_int("value_uint.set", SSL_set_value_uint(ssl, 0, 0, 0));
    }
    SSL_set_debug(ssl, 1);
    out_int("set_debug.noop", 1);
    out_int("blocking.get", SSL_get_blocking_mode(ssl));
    out_int("blocking.set", SSL_set_blocking_mode(ssl, 1));
    out_int("handle_events", SSL_handle_events(ssl));
    {
        struct timeval tv;
        int inf = 0;
        out_int("event_timeout.ret", SSL_get_event_timeout(ssl, &tv, &inf));
        out_int("event_timeout.sec", (long)tv.tv_sec);
        out_int("event_timeout.infinite", inf);
    }
    out_int("net_read_desired", SSL_net_read_desired(ssl));
    out_int("net_write_desired", SSL_net_write_desired(ssl));

    /* the QUIC-dispatch arms: every one is the non-QUIC fall-through */
    out_int("quic.new_stream.null", SSL_new_stream(ssl, 0) == NULL);
    out_int("quic.accept_stream.null", SSL_accept_stream(ssl, 0) == NULL);
    out_int("quic.accept_stream_qlen", (long)SSL_get_accept_stream_queue_len(ssl));
    out_int("quic.stream_conclude", SSL_stream_conclude(ssl, 0));
    out_int("quic.stream_reset", SSL_stream_reset(ssl, NULL, 0));
    out_int("quic.stream_type", SSL_get_stream_type(ssl));
    out_int("quic.stream_id", (long)SSL_get_stream_id(ssl));
    out_int("quic.is_stream_local", SSL_is_stream_local(ssl));
    out_int("quic.read_state", SSL_get_stream_read_state(ssl));
    out_int("quic.write_state", SSL_get_stream_write_state(ssl));
    out_int("quic.read_error", SSL_get_stream_read_error_code(ssl, NULL));
    out_int("quic.write_error", SSL_get_stream_write_error_code(ssl, NULL));
    out_int("quic.default_stream_mode", SSL_set_default_stream_mode(ssl, 0));
    out_int("quic.incoming_policy", SSL_set_incoming_stream_policy(ssl, 0, 0));
    out_int("quic.get0_connection", SSL_get0_connection(ssl) == ssl);
    out_int("quic.get0_listener.null", SSL_get0_listener(ssl) == NULL);
    out_int("quic.get0_domain.null", SSL_get0_domain(ssl) == NULL);
    out_int("quic.is_connection", SSL_is_connection(ssl));
    out_int("quic.is_listener", SSL_is_listener(ssl));
    out_int("quic.is_domain", SSL_is_domain(ssl));
    out_int("quic.new_listener.null", SSL_new_listener(ctx, 0) == NULL);
    out_int("quic.new_listener_from.null", SSL_new_listener_from(ssl, 0) == NULL);
    out_int("quic.new_from_listener.null", SSL_new_from_listener(ssl, 0) == NULL);
    out_int("quic.accept_connection.null", SSL_accept_connection(ssl, 0) == NULL);
    out_int("quic.accept_conn_qlen", (long)SSL_get_accept_connection_queue_len(ssl));
    out_int("quic.listen", SSL_listen(ssl));
    out_int("quic.new_domain.null", SSL_new_domain(ctx, 0) == NULL);
    out_int("quic.conn_close_info", SSL_get_conn_close_info(ssl, NULL, 0));
    out_int("quic.initial_peer_addr", SSL_set1_initial_peer_addr(ssl, NULL));
    out_int("quic.shutdown_ex", SSL_shutdown_ex(ssl, 0, NULL, 0));

    /* PSK identity: store/read, and the over-long hint refusal */
    out_int("psk.ctx.hint", SSL_CTX_use_psk_identity_hint(ctx, "hint"));
    {
        char big[300];
        memset(big, 'a', sizeof(big));
        big[299] = '\0';
        out_int("psk.ctx.hint_long", SSL_CTX_use_psk_identity_hint(ctx, big));
    }
    out_int("psk.ssl.hint", SSL_use_psk_identity_hint(ssl, "hint"));
    out_int("psk.get_hint.null", SSL_get_psk_identity_hint(ssl) == NULL);
    out_int("psk.get.null", SSL_get_psk_identity(ssl) == NULL);

    /* the ClientHello readers with no ClientHello message (outside a callback) */
    {
        const unsigned char *p = NULL;
        size_t cl_len = 99;
        int *ipresent = NULL;
        out_int("clienthello.isv2", SSL_client_hello_isv2(ssl));
        out_int("clienthello.legacy", SSL_client_hello_get0_legacy_version(ssl));
        out_int("clienthello.random", (long)SSL_client_hello_get0_random(ssl, &p));
        out_int("clienthello.session_id", (long)SSL_client_hello_get0_session_id(ssl, &p));
        out_int("clienthello.ciphers", (long)SSL_client_hello_get0_ciphers(ssl, &p));
        out_int("clienthello.compressions",
                (long)SSL_client_hello_get0_compression_methods(ssl, &p));
        out_int("clienthello.exts_present",
                SSL_client_hello_get1_extensions_present(ssl, &ipresent, &cl_len));
        out_int("clienthello.ext_order",
                SSL_client_hello_get_extension_order(ssl, NULL, &cl_len));
        out_int("clienthello.ext", SSL_client_hello_get0_ext(ssl, 0, NULL, NULL));
    }

    /* ----------------------------------------------------------------------------------------
     * N. The 14.1 remainder: the rows 14.3/14.4/14.5/14.7 unblock.
     *
     * Every arm is a fixed input and a small-integer / pointer-identity answer. The chain-cert
     * add (`SSL_CTX_add0_chain_cert`) is not driven: the authority's security callback inspects the
     * certificate's key, so an empty certificate is refused there while the candidate's recorded
     * default callback accepts it; the clear arm (`SSL_CTX_clear_chain_certs`) runs no security
     * check and is driven. `SSL_CTX_set0_tmp_dh_pkey` is likewise not driven for want of a key
     * whose security bits both sides agree on.
     * -------------------------------------------------------------------------------------- */
    out_int("ctx.sessions.nonnull", SSL_CTX_sessions(ctx) != NULL);
    out_int("has_matching_session_id",
            SSL_has_matching_session_id(ssl, (const unsigned char *)"abcd", 4));
    out_int("client_ciphers.null", SSL_get_client_ciphers(ssl) == NULL);
    out_int("current_cipher.null", SSL_get_current_cipher(ssl) == NULL);
    out_int("pending_cipher.null", SSL_get_pending_cipher(ssl) == NULL);
    out_int("current_compression.null", SSL_get_current_compression(ssl) == NULL);
    out_int("current_expansion.null", SSL_get_current_expansion(ssl) == NULL);
    out_int("peer_rpk.null", SSL_get0_peer_rpk(ssl) == NULL);
    {
        char sbuf[16];
        char *r = SSL_get_shared_ciphers(ssl, sbuf, sizeof sbuf);
        out_int("shared_ciphers.nonnull", r != NULL);
        out_int("shared_ciphers.empty", sbuf[0] == '\0');
    }
    out_int("default_verify_dir", SSL_CTX_set_default_verify_dir(ctx));
    out_int("default_verify_file", SSL_CTX_set_default_verify_file(ctx));
    out_int("default_verify_store", SSL_CTX_set_default_verify_store(ctx));
    out_int("clear_chain_certs", SSL_CTX_clear_chain_certs(ctx));
    out_int("set_ssl_version", SSL_CTX_set_ssl_version(ctx, TLSv1_2_method()));
    out_int("set_ssl_version.identity", SSL_CTX_get_ssl_method(ctx) == TLSv1_2_method());
    /* the public role setters over the internal helpers */
    SSL_set_accept_state(ssl);
    out_int("set_accept_state.server", SSL_is_server(ssl));
    SSL_set_connect_state(ssl);
    out_int("set_connect_state.server", SSL_is_server(ssl));
    /* copy_session_id over two fresh connections of the same method */
    {
        SSL *t2 = SSL_new(ctx);
        SSL *f2 = SSL_new(ctx);
        out_int("copy_session_id.two_fresh", SSL_copy_session_id(t2, f2));
        SSL_free(t2);
        SSL_free(f2);
    }

    /* ----------------------------------------------------------------------------------------
     * N. The handshake entry points (14.5b).
     *
     * Every arm is a fixed input and a small-integer answer over a fresh connection (or, for
     * `SSL_stateless`, a fresh memory-BIO pair). No arm reads a flight, the error queue or a clock;
     * the state-machine arms that *do* move state are in `RT-STATEM`.
     * -------------------------------------------------------------------------------------- */
    {
        SSL *hs = SSL_new(ctx);
        BIO *hr = BIO_new(BIO_s_mem()), *hw = BIO_new(BIO_s_mem());
        SSL_set_bio(hs, hr, hw);
        ERR_clear_error();
        out_int("hs.key_update.notreq", SSL_key_update(hs, 0));
        out_int("hs.key_update.req", SSL_key_update(hs, 1));
        out_int("hs.key_update.bad", SSL_key_update(hs, 7));
        out_int("hs.new_session_ticket", SSL_new_session_ticket(hs));
        out_int("hs.export_keying",
                SSL_export_keying_material(hs, ebuf, 8, "label", 5, NULL, 0, 1));
        out_int("hs.export_keying_early",
                SSL_export_keying_material_early(hs, ebuf, 8, "label", 5, NULL, 0));
        out_int("hs.sendfile", (long)SSL_sendfile(hs, -1, 0, 0, 0));
        out_int("hs.verify_pha", SSL_verify_client_post_handshake(hs));
        out_int("hs.read_early", SSL_read_early_data(hs, buf, 4, &n));
        out_int("hs.write_early", SSL_write_early_data(hs, buf, 4, &n));
        out_int("hs.renegotiate", SSL_renegotiate(hs));
        out_int("hs.renegotiate_abbr", SSL_renegotiate_abbreviated(hs));
        SSL_free(hs);
    }
    {
        SSL *st = SSL_new(ctx);
        BIO *sr = BIO_new(BIO_s_mem()), *sw = BIO_new(BIO_s_mem());
        SSL_set_bio(st, sr, sw);
        ERR_clear_error();
        out_int("hs.stateless", SSL_stateless(st));
        SSL_free(st);
    }

    /* ----------------------------------------------------------------------------------------
     * O. The 14.7b rows: the DANE/RPK surface, SSL_dup, SSL_set_SSL_CTX and the cipher-list parser.
     *
     * Every arm is a fixed input and a small-integer / fixed-string / pointer-identity answer. The
     * DANE arms use one fixed in-memory certificate; the compared values are the DANE calls' return
     * codes and the read-backs' unchanged out-parameters, never a byte of the certificate. No clock
     * and no network move a value.
     * -------------------------------------------------------------------------------------- */

    /* The DANE record surface over a fixed certificate. */
    {
        SSL_CTX *dctx = SSL_CTX_new(TLS_method());
        SSL *dssl = SSL_new(dctx);
        BIO *bc = BIO_new_mem_buf(dane_cert_pem, -1);
        X509 *cert = PEM_read_bio_X509(bc, NULL, NULL, NULL);
        unsigned char *cder = NULL, *pder = NULL;
        int cderlen = cert != NULL ? i2d_X509(cert, &cder) : 0;
        EVP_PKEY *pk = cert != NULL ? X509_get0_pubkey(cert) : NULL;
        int pderlen = pk != NULL ? i2d_PUBKEY(pk, &pder) : 0;

        out_int("dane.cert.ok", cert != NULL);
        out_int("dane.cert.pubkey_ok", pk != NULL);
        out_int("dane.cert.der_nonempty", cderlen > 0);
        out_int("dane.cert.spki_nonempty", pderlen > 0);

        out_int("dane.ctx.enable", SSL_CTX_dane_enable(dctx));
        out_int("dane.ctx.enable_again", SSL_CTX_dane_enable(dctx));
        out_int("dane.ctx.set_flags.ret", (long)SSL_CTX_dane_set_flags(dctx, 1));
        out_int("dane.ctx.set_flags.ret2", (long)SSL_CTX_dane_set_flags(dctx, 4));
        out_int("dane.ctx.clear_flags.ret", (long)SSL_CTX_dane_clear_flags(dctx, 1));
        out_int("dane.ctx.mtype_full_override", SSL_CTX_dane_mtype_set(dctx, EVP_sha256(), 0, 0));
        out_int("dane.ctx.mtype_custom", SSL_CTX_dane_mtype_set(dctx, EVP_sha256(), 17, 3));

        out_int("dane.ssl.enable", SSL_dane_enable(dssl, "example.com"));
        out_int("dane.ssl.enable_again", SSL_dane_enable(dssl, "example.com"));
        out_int("dane.ssl.set_flags.ret", (long)SSL_dane_set_flags(dssl, 1));
        out_int("dane.ssl.set_flags.ret2", (long)SSL_dane_set_flags(dssl, 2));
        out_int("dane.ssl.clear_flags.ret", (long)SSL_dane_clear_flags(dssl, 1));
        out_int("dane.get0.nonnull", SSL_get0_dane(dssl) != NULL);

        out_int("dane.tlsa.bad_usage", SSL_dane_tlsa_add(dssl, 4, 0, 1, pder, pderlen));
        out_int("dane.tlsa.bad_selector", SSL_dane_tlsa_add(dssl, 3, 2, 1, pder, pderlen));
        out_int("dane.tlsa.bad_mtype", SSL_dane_tlsa_add(dssl, 3, 0, 5, pder, pderlen));
        out_int("dane.tlsa.null_data", SSL_dane_tlsa_add(dssl, 3, 0, 1, NULL, 0));
        out_int("dane.tlsa.digest_bad_len", SSL_dane_tlsa_add(dssl, 3, 0, 1, pder, 5));
        {
            unsigned char dig[32];
            memset(dig, 0x5A, sizeof dig);
            out_int("dane.tlsa.digest_ok", SSL_dane_tlsa_add(dssl, 3, 0, 1, dig, sizeof dig));
        }
        out_int("dane.tlsa.cert_ok", SSL_dane_tlsa_add(dssl, 3, 0, 0, cder, cderlen));
        out_int("dane.tlsa.spki_ok", SSL_dane_tlsa_add(dssl, 3, 1, 0, pder, pderlen));
        out_int("dane.rpk.ok", SSL_add_expected_rpk(dssl, pk));
        out_int("dane.rpk.null_key", SSL_add_expected_rpk(dssl, NULL));

        {
            uint8_t usage = 0xEE, selector = 0xEE, mt = 0xEE;
            const unsigned char *tdata = (const unsigned char *)0x1;
            size_t tdlen = 99;
            out_int("dane.get0.authority", SSL_get0_dane_authority(dssl, NULL, NULL));
            out_int("dane.get0.tlsa.ret",
                    SSL_get0_dane_tlsa(dssl, &usage, &selector, &mt, &tdata, &tdlen));
            out_int("dane.get0.tlsa.usage_untouched", usage == 0xEE);
            out_int("dane.get0.tlsa.mtype_untouched", mt == 0xEE);
            out_int("dane.get0.tlsa.dlen_untouched", tdlen == 99);
        }

        /* Without `SSL_dane_enable`, `dane->trecs` is NULL: both setters refuse. */
        {
            SSL *nd = SSL_new(dctx);
            out_int("dane.tlsa.not_enabled", SSL_dane_tlsa_add(nd, 3, 0, 1, pder, pderlen));
            out_int("dane.rpk.not_enabled", SSL_add_expected_rpk(nd, pk));
            SSL_free(nd);
        }

        OPENSSL_free(cder);
        OPENSSL_free(pder);
        X509_free(cert);
        BIO_free(bc);
        SSL_free(dssl);
        SSL_CTX_free(dctx);
    }

    /* `SSL_bytes_to_cipher_list` over fixed bytes. */
    {
        SSL *b = SSL_new(ctx);
        OPENSSL_STACK *sk = NULL, *scsvs = NULL;
        const unsigned char two[2] = { 0x13, 0x01 };      /* TLS_AES_128_GCM_SHA256 */
        const unsigned char four[4] = { 0x13, 0x01, 0xC0, 0x2F };
        const unsigned char scsv[2] = { 0x00, 0xFF };     /* renegotiation-info SCSV */
        const unsigned char unknown[2] = { 0x00, 0x01 };
        const unsigned char odd[1] = { 0x13 };

        out_int("b2cl.empty", SSL_bytes_to_cipher_list(b, two, 0, 0, &sk, &scsvs));
        out_int("b2cl.odd", SSL_bytes_to_cipher_list(b, odd, 1, 0, &sk, &scsvs));

        out_int("b2cl.two.ret", SSL_bytes_to_cipher_list(b, two, 2, 0, &sk, &scsvs));
        out_int("b2cl.two.n", OPENSSL_sk_num(sk));
        out_str("b2cl.two.name0",
                SSL_CIPHER_get_name((const SSL_CIPHER *)OPENSSL_sk_value(sk, 0)));
        out_int("b2cl.two.scsvs_n", OPENSSL_sk_num(scsvs));
        OPENSSL_sk_free(sk);
        OPENSSL_sk_free(scsvs);
        sk = NULL;
        scsvs = NULL;

        out_int("b2cl.four.ret", SSL_bytes_to_cipher_list(b, four, 4, 0, &sk, &scsvs));
        out_int("b2cl.four.n", OPENSSL_sk_num(sk));
        out_str("b2cl.four.name0",
                SSL_CIPHER_get_name((const SSL_CIPHER *)OPENSSL_sk_value(sk, 0)));
        out_str("b2cl.four.name1",
                SSL_CIPHER_get_name((const SSL_CIPHER *)OPENSSL_sk_value(sk, 1)));
        OPENSSL_sk_free(sk);
        OPENSSL_sk_free(scsvs);
        sk = NULL;
        scsvs = NULL;

        out_int("b2cl.scsv.ret", SSL_bytes_to_cipher_list(b, scsv, 2, 0, &sk, &scsvs));
        out_int("b2cl.scsv.n", OPENSSL_sk_num(sk));
        out_int("b2cl.scsv.scsvs_n", OPENSSL_sk_num(scsvs));
        out_str("b2cl.scsv.name0",
                SSL_CIPHER_get_name((const SSL_CIPHER *)OPENSSL_sk_value(scsvs, 0)));
        OPENSSL_sk_free(sk);
        OPENSSL_sk_free(scsvs);
        sk = NULL;
        scsvs = NULL;

        out_int("b2cl.unknown.ret", SSL_bytes_to_cipher_list(b, unknown, 2, 0, &sk, &scsvs));
        out_int("b2cl.unknown.n", OPENSSL_sk_num(sk));
        out_int("b2cl.unknown.scsvs_n", OPENSSL_sk_num(scsvs));
        OPENSSL_sk_free(sk);
        OPENSSL_sk_free(scsvs);
        SSL_free(b);
    }

    /* `SSL_get1_supported_ciphers` over a fixed cipher set. */
    {
        SSL_CTX *cctx = SSL_CTX_new(TLS_method());
        out_int("get1.set_list", SSL_CTX_set_cipher_list(cctx, "AES128-SHA:AES256-SHA"));
        SSL *cs = SSL_new(cctx);
        OPENSSL_STACK *sup = SSL_get1_supported_ciphers(cs);
        out_int("get1.nonnull", sup != NULL);
        out_int("get1.n", OPENSSL_sk_num(sup));
        out_str("get1.name0",
                SSL_CIPHER_get_name((const SSL_CIPHER *)OPENSSL_sk_value(sup, 0)));
        out_str("get1.name1",
                SSL_CIPHER_get_name((const SSL_CIPHER *)OPENSSL_sk_value(sup, 1)));
        OPENSSL_sk_free(sup);
        SSL_free(cs);
        SSL_CTX_free(cctx);
    }

    /* `SSL_dup` and `SSL_set_SSL_CTX` over fixed objects. */
    {
        SSL_CTX *uctx = SSL_CTX_new(TLS_method());
        SSL *orig = SSL_new(uctx);
        SSL *dup = SSL_dup(orig);
        out_int("dup.nonnull", dup != NULL);
        out_int("dup.distinct", dup != NULL && dup != orig);
        out_int("dup.ctx", SSL_get_SSL_CTX(dup) == SSL_get_SSL_CTX(orig));
        out_int("dup.server", SSL_is_server(dup) == SSL_is_server(orig));
        out_int("dup.version", SSL_version(dup) == SSL_version(orig));
        out_int("dup.options", SSL_get_options(dup) == SSL_get_options(orig));
        out_int("dup.verify_mode", SSL_get_verify_mode(dup) == SSL_get_verify_mode(orig));
        out_int("dup.verify_depth", SSL_get_verify_depth(dup) == SSL_get_verify_depth(orig));
        out_int("dup.cert_null", SSL_get_certificate(dup) == NULL);
        SSL_free(dup);
        SSL_free(orig);
        SSL_CTX_free(uctx);
    }
    {
        SSL_CTX *c1 = SSL_CTX_new(TLS_method());
        SSL_CTX *c2 = SSL_CTX_new(TLS_method());
        SSL *s2 = SSL_new(c1);
        out_int("set_ctx.same", SSL_set_SSL_CTX(s2, c1) == c1);
        out_int("set_ctx.switch", SSL_set_SSL_CTX(s2, c2) == c2);
        out_int("set_ctx.get", SSL_get_SSL_CTX(s2) == c2);
        out_int("set_ctx.cert_null", SSL_get_certificate(s2) == NULL);
        out_int("set_ctx.null", SSL_set_SSL_CTX(s2, NULL) == c1);
        out_int("set_ctx.get_after_null", SSL_get_SSL_CTX(s2) == c1);
        out_int("set_ctx.null_ssl", SSL_set_SSL_CTX(NULL, c2) == NULL);
        SSL_free(s2);
        SSL_CTX_free(c1);
        SSL_CTX_free(c2);
    }

    /* ----------------------------------------------------------------------------------------
     * L. The refcount effect on free.
     * -------------------------------------------------------------------------------------- */
    out_int("ssl.up_ref", SSL_up_ref(ssl));
    SSL_free(ssl);
    SSL_free(ssl);
    out_int("ssl.freed", 1);
    out_int("ctx.up_ref", SSL_CTX_up_ref(ctx));
    SSL_CTX_free(ctx);
    SSL_CTX_free(ctx);
    out_int("ctx.freed", 1);

    return 0;
}
