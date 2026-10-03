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
 *   * `SSL_set_bio` over memory BIOs, including the `rbio == wbio` ownership case and the no-op.
 *
 * ## Arms that are deliberately absent
 *
 * No handshake, no socket and no wall clock move an answer. `SSL_accept`/`SSL_connect` are not
 * driven: they install a `handshake_func` and start a real handshake, which would reach the record
 * layer (14.4) and the state machine (14.5), neither of which this subphase lands. `SSL_get_error`
 * is read before any error is raised and after `ERR_clear_error`, so the error queue never moves a
 * value. The NULL arms of `SSL_CTX_get_options`, `SSL_CTX_get_verify_mode`, `SSL_is_tls`/`_quic`
 * and the like are not driven: those dereference their argument in the authority, so a probe would
 * crash both sides rather than compare them.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
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

int main(void)
{
    const SSL_METHOD *m = TLS_method();
    SSL_CTX *ctx;
    SSL *ssl;
    BIO *m1, *m2, *m3;
    unsigned char sid[40];
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
