/*
 * rt_ssl_ciph_probe.c -- RT-SSL-CIPH: the Phase-14.3 cipher and configuration surface, driven.
 *
 * One C program, compiled once against the admitted authority and once against the candidate
 * distribution shell; the two transcripts are diffed line by line, keyed on `key=value`. Every
 * observation is an integer, a fixed string or a joined name sequence -- never an address, never a
 * clock, never the error queue -- and no handshake, socket or timer moves an answer.
 *
 * ## What this probe drives
 *
 * A. The two `OSSL_default_*` strings `src/ssl/ssl_ciph.rs` returns.
 * B. The `SSL_CIPHER_*` readers over fixed wire ids: `SSL_CIPHER_find` resolves a two-byte
 *    ciphersuite id into the built-in table (`AES128-SHA`, `ECDHE-RSA-AES128-GCM-SHA256`, the
 *    three default TLSv1.3 suites, and two unknown ids), and each is read through
 *    `_get_name`/`_standard_name`/`_get_id`/`_get_protocol_id`/`_get_bits`/`_get_version`/
 *    `_is_aead`/`_get_cipher_nid`/`_get_digest_nid`/`_get_kx_nid`/`_get_auth_nid`/
 *    `_get_handshake_digest`/`_description`, plus `OPENSSL_cipher_name` and the NULL arms.
 * C. The `SSL_CTX_set_cipher_list`/`SSL_CTX_set_ciphersuites`/`SSL_CTX_get_ciphers`/
 *    `SSL_get_ciphers`/`SSL_get_cipher_list` surface, over fixed rule strings, with the parsed
 *    list's names printed in order.
 * D. `SSL_CONF_CTX_new`/`SSL_CONF_cmd`/`SSL_CONF_cmd_value_type`/`SSL_CONF_CTX_finish` over fixed
 *    `cmd,arg` pairs, plus `SSL_CONF_CTX_set1_prefix`/`set_flags`/`clear_flags`/`set_ssl_ctx` and
 *    `SSL_CONF_cmd_argv`.
 *
 * ## Arms that are deliberately absent
 *
 * `SSL_CIPHER_get_id`/`_get_protocol_id`/`_is_aead`/`_get_handshake_digest`/`_get_digest_nid`/
 * `_get_kx_nid`/`_get_auth_nid` dereference their argument in the authority, so no NULL arm drives
 * them (only `_get_cipher_nid`, `_get_bits`, `_get_name`, `_standard_name` and `_get_version`
 * check for NULL). The certificate/key/signature-algorithm/
 * group-list `SSL_CONF` commands are recognised by the table (their value types are compared) but
 * their handlers are later subphases' and are not driven through `SSL_CONF_cmd`.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define OPENSSL_SUPPRESS_DEPRECATED

#include <stdio.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/objects.h>
#include <openssl/evp.h>

static void out_int(const char *key, long v)
{
    printf("%s=%ld\n", key, v);
}

static void out_str(const char *key, const char *v)
{
    printf("%s=%s\n", key, v != NULL ? v : "<NULL>");
}

/* Print a stack of ciphers as a comma-joined name sequence. */
static void out_ciphers(const char *key, STACK_OF(SSL_CIPHER) *sk)
{
    int i, n;
    char buf[4096];
    size_t off = 0;

    if (sk == NULL) {
        printf("%s=<NULL>\n", key);
        return;
    }
    n = sk_SSL_CIPHER_num(sk);
    buf[0] = '\0';
    for (i = 0; i < n; i++) {
        const SSL_CIPHER *c = sk_SSL_CIPHER_value(sk, i);
        const char *nm = SSL_CIPHER_get_name(c);
        int wrote = snprintf(buf + off, sizeof(buf) - off, "%s%s",
                             i == 0 ? "" : ",", nm != NULL ? nm : "<NULL>");
        if (wrote < 0)
            break;
        off += (size_t)wrote;
        if (off >= sizeof(buf))
            break;
    }
    printf("%s=%s\n", key, buf);
}

/* A. The default strings. */
static void probe_defaults(void)
{
    out_str("default.cipher_list", OSSL_default_cipher_list());
    out_str("default.ciphersuites", OSSL_default_ciphersuites());
}

/* B. The readers over one fixed id. */
static void probe_cipher(SSL *ssl, const char *label, unsigned char hi, unsigned char lo)
{
    unsigned char id[2];
    char key[128];
    char desc[256];

    id[0] = hi;
    id[1] = lo;

#define K(fmt) (snprintf(key, sizeof(key), "cipher.%s.%s", label, fmt), key)

    const SSL_CIPHER *c = SSL_CIPHER_find(ssl, id);
    out_int(K("nonnull"), c != NULL);
    if (c == NULL)
        return;
    out_str(K("name"), SSL_CIPHER_get_name(c));
    out_str(K("stdname"), SSL_CIPHER_standard_name(c));
    printf("%s=%08lx\n", K("id"), (unsigned long)SSL_CIPHER_get_id(c));
    printf("%s=%04x\n", K("protocol_id"), (unsigned)SSL_CIPHER_get_protocol_id(c));
    {
        int alg = -1;
        out_int(K("bits"), SSL_CIPHER_get_bits(c, &alg));
        out_int(K("alg_bits"), alg);
    }
    out_str(K("version"), SSL_CIPHER_get_version(c));
    out_int(K("is_aead"), SSL_CIPHER_is_aead(c));
    out_int(K("cipher_nid"), SSL_CIPHER_get_cipher_nid(c));
    out_int(K("digest_nid"), SSL_CIPHER_get_digest_nid(c));
    out_int(K("kx_nid"), SSL_CIPHER_get_kx_nid(c));
    out_int(K("auth_nid"), SSL_CIPHER_get_auth_nid(c));
    out_int(K("has_md"), SSL_CIPHER_get_handshake_digest(c) != NULL);
    desc[0] = '\0';
    if (SSL_CIPHER_description(c, desc, sizeof(desc)) != NULL) {
        char *nl = strchr(desc, '\n');
        if (nl != NULL)
            *nl = '\0';
        out_str(K("description"), desc);
    } else {
        out_str(K("description"), "<NULL>");
    }
#undef K
}

static void probe_readers(SSL *ssl)
{
    probe_cipher(ssl, "aes128sha", 0x00, 0x2f);
    probe_cipher(ssl, "ecdhe_rsa_aes128gcm", 0xc0, 0x2f);
    probe_cipher(ssl, "tls13_aes128gcm", 0x13, 0x01);
    probe_cipher(ssl, "tls13_aes256gcm", 0x13, 0x02);
    probe_cipher(ssl, "tls13_chacha", 0x13, 0x03);
    probe_cipher(ssl, "unknown_aa", 0xaa, 0xaa);
    probe_cipher(ssl, "unknown_1234", 0x12, 0x34);

    out_str("name.std", OPENSSL_cipher_name("TLS_RSA_WITH_AES_128_CBC_SHA"));
    out_str("name.unknown", OPENSSL_cipher_name("TLS_NOT_A_CIPHER"));
    out_str("name.null", OPENSSL_cipher_name(NULL));
    out_str("get_name.null", SSL_CIPHER_get_name(NULL));
    out_str("standard_name.null", SSL_CIPHER_standard_name(NULL));
    out_str("get_version.null", SSL_CIPHER_get_version(NULL));
    out_int("get_bits.null", SSL_CIPHER_get_bits(NULL, NULL));
    out_int("cipher_nid.null", SSL_CIPHER_get_cipher_nid(NULL));
}

/* C. The cipher-list surface over fixed rule strings. */
static void probe_lists(const SSL_METHOD *m)
{
    SSL_CTX *ctx;
    SSL *ssl;

    ctx = SSL_CTX_new(m);
    out_int("list.ctx.nonnull", ctx != NULL);
    out_ciphers("list.fresh.ctx_get_ciphers", SSL_CTX_get_ciphers(ctx));

    out_int("list.set.rc", SSL_CTX_set_cipher_list(ctx, "AES128-SHA"));
    out_ciphers("list.set.ctx_get_ciphers", SSL_CTX_get_ciphers(ctx));

    out_int("list.set_multi.rc",
            SSL_CTX_set_cipher_list(ctx, "ECDHE-RSA-AES128-GCM-SHA256:AES256-SHA"));
    out_ciphers("list.set_multi.ctx_get_ciphers", SSL_CTX_get_ciphers(ctx));

    out_int("list.set_default.rc", SSL_CTX_set_cipher_list(ctx, "DEFAULT"));
    out_ciphers("list.set_default.ctx_get_ciphers", SSL_CTX_get_ciphers(ctx));

    out_int("list.set_empty.rc", SSL_CTX_set_cipher_list(ctx, ""));
    out_ciphers("list.set_empty.ctx_get_ciphers", SSL_CTX_get_ciphers(ctx));

    out_int("list.set_bogus.rc", SSL_CTX_set_cipher_list(ctx, "NOT-A-CIPHER"));
    out_int("list.set_null.rc", SSL_CTX_set_cipher_list(ctx, NULL));

    out_int("suites.set.rc", SSL_CTX_set_ciphersuites(ctx, "TLS_AES_128_GCM_SHA256"));
    out_ciphers("suites.set.ctx_get_ciphers", SSL_CTX_get_ciphers(ctx));

    out_int("suites.set_bogus.rc", SSL_CTX_set_ciphersuites(ctx, "BOGUS"));
    out_int("suites.set_empty.rc", SSL_CTX_set_ciphersuites(ctx, ""));
    out_ciphers("suites.set_empty.ctx_get_ciphers", SSL_CTX_get_ciphers(ctx));

    ssl = SSL_new(ctx);
    out_int("list.ssl.nonnull", ssl != NULL);
    out_ciphers("list.ssl.get_ciphers", SSL_get_ciphers(ssl));
    out_str("list.ssl.get_cipher_list0", SSL_get_cipher_list(ssl, 0));
    out_str("list.ssl.get_cipher_list_neg", SSL_get_cipher_list(ssl, -1));
    out_str("list.ssl.get_cipher_list_big", SSL_get_cipher_list(ssl, 9999));
    out_int("list.set_ssl.rc", SSL_set_cipher_list(ssl, "AES128-SHA"));
    out_ciphers("list.set_ssl.get_ciphers", SSL_get_ciphers(ssl));
    out_int("suites.set_ssl.rc", SSL_set_ciphersuites(ssl, "TLS_AES_256_GCM_SHA384"));
    out_ciphers("suites.set_ssl.get_ciphers", SSL_get_ciphers(ssl));

    SSL_free(ssl);
    SSL_CTX_free(ctx);
}

/* D. The SSL_CONF parser. */
static void probe_conf(void)
{
    SSL_CONF_CTX *cctx;
    SSL_CTX *ctx;
    unsigned int flags;
    char cmd[] = "-cipher";
    char arg[] = "AES128-SHA";
    char *argv[3];
    char **pargv;
    int pargc;

    cctx = SSL_CONF_CTX_new();
    out_int("conf.nonnull", cctx != NULL);

    flags = SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_FILE | SSL_CONF_FLAG_SERVER
                                          | SSL_CONF_FLAG_CLIENT | SSL_CONF_FLAG_CERTIFICATE);
    printf("conf.flags.set=%u\n", flags);
    flags = SSL_CONF_CTX_clear_flags(cctx, SSL_CONF_FLAG_SHOW_ERRORS);
    printf("conf.flags.clear=%u\n", flags);
    out_int("conf.prefix.rc", SSL_CONF_CTX_set1_prefix(cctx, ""));

    ctx = SSL_CTX_new(TLS_method());
    SSL_CONF_CTX_set_ssl_ctx(cctx, ctx);

    /* value types, both name spellings */
    out_int("conf.vt.CipherString", SSL_CONF_cmd_value_type(cctx, "CipherString"));
    out_int("conf.vt.Certificate", SSL_CONF_cmd_value_type(cctx, "Certificate"));
    out_int("conf.vt.chainCApath", SSL_CONF_cmd_value_type(cctx, "chainCApath"));
    out_int("conf.vt.chainCAstore", SSL_CONF_cmd_value_type(cctx, "chainCAstore"));
    out_int("conf.vt.no_tls1_3", SSL_CONF_cmd_value_type(cctx, "no_tls1_3"));
    out_int("conf.vt.MinProtocol", SSL_CONF_cmd_value_type(cctx, "MinProtocol"));
    out_int("conf.vt.VerifyMode", SSL_CONF_cmd_value_type(cctx, "VerifyMode"));
    out_int("conf.vt.unknown", SSL_CONF_cmd_value_type(cctx, "Frobnicate"));

    /* command dispatch */
    out_int("conf.cmd.cipher", SSL_CONF_cmd(cctx, "CipherString", "AES128-SHA"));
    out_int("conf.cmd.ciphersuites",
            SSL_CONF_cmd(cctx, "Ciphersuites", "TLS_AES_128_GCM_SHA256"));
    out_int("conf.cmd.cipher.bad", SSL_CONF_cmd(cctx, "CipherString", "NOT-A-CIPHER"));
    out_int("conf.cmd.cipher.null", SSL_CONF_cmd(cctx, "CipherString", NULL));
    out_int("conf.cmd.null_cmd", SSL_CONF_cmd(cctx, NULL, "x"));
    out_int("conf.cmd.unknown", SSL_CONF_cmd(cctx, "Frobnicate", "x"));

    out_int("conf.cmd.options",
            SSL_CONF_cmd(cctx, "Options", "Compression,NoRenegotiation"));
    printf("conf.options.bits=%lx\n",
           (unsigned long)(SSL_CTX_get_options(ctx)
                           & (SSL_OP_NO_COMPRESSION | SSL_OP_NO_RENEGOTIATION
                              | SSL_OP_ENABLE_MIDDLEBOX_COMPAT)));

    out_int("conf.cmd.protocol", SSL_CONF_cmd(cctx, "Protocol", "TLSv1.2"));
    out_int("conf.cmd.verify", SSL_CONF_cmd(cctx, "VerifyMode", "Require"));
    out_int("conf.ctx.verify_mode", SSL_CTX_get_verify_mode(ctx));

    out_int("conf.cmd.min_proto", SSL_CONF_cmd(cctx, "MinProtocol", "TLSv1.2"));
    out_int("conf.ctx.min_proto", SSL_CTX_get_min_proto_version(ctx));
    out_int("conf.cmd.max_proto", SSL_CONF_cmd(cctx, "MaxProtocol", "None"));
    out_int("conf.ctx.max_proto", SSL_CTX_get_max_proto_version(ctx));
    out_int("conf.cmd.min_proto.bad", SSL_CONF_cmd(cctx, "MinProtocol", "TLSv9"));
    out_int("conf.cmd.max_proto.dtls", SSL_CONF_cmd(cctx, "MaxProtocol", "DTLSv1.2"));

    out_int("conf.cmd.num_tickets", SSL_CONF_cmd(cctx, "NumTickets", "5"));
    out_int("conf.ctx.num_tickets", SSL_CTX_get_num_tickets(ctx));
    out_int("conf.cmd.record_padding", SSL_CONF_cmd(cctx, "RecordPadding", "0"));

    out_int("conf.cmd.switch", SSL_CONF_cmd(cctx, "no_tls1_3", NULL));

    out_int("conf.finish", SSL_CONF_CTX_finish(cctx));

    /* prefix handling: file names are matched case-insensitively after the prefix */
    out_int("conf.prefix.set2", SSL_CONF_CTX_set1_prefix(cctx, "SSL_"));
    out_int("conf.cmd.prefixed", SSL_CONF_cmd(cctx, "SSL_CipherString", "AES128-SHA"));
    out_int("conf.cmd.prefixed.bad", SSL_CONF_cmd(cctx, "X_CipherString", "AES128-SHA"));
    out_int("conf.prefix.clear", SSL_CONF_CTX_set1_prefix(cctx, NULL));

    SSL_CTX_free(ctx);
    SSL_CONF_CTX_free(cctx);

    /* command-line dispatch through SSL_CONF_cmd_argv */
    cctx = SSL_CONF_CTX_new();
    SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_CMDLINE | SSL_CONF_FLAG_CLIENT);
    ctx = SSL_CTX_new(TLS_client_method());
    SSL_CONF_CTX_set_ssl_ctx(cctx, ctx);
    argv[0] = cmd;
    argv[1] = arg;
    argv[2] = NULL;
    pargv = argv;
    pargc = 2;
    out_int("conf.argv.rc", SSL_CONF_cmd_argv(cctx, &pargc, &pargv));
    out_int("conf.argv.pargc", pargc);
    out_int("conf.argv.remaining", pargv == NULL || *pargv == NULL);
    out_int("conf.argv.vt", SSL_CONF_cmd_value_type(cctx, "cipher"));
    out_int("conf.argv.vt_dash", SSL_CONF_cmd_value_type(cctx, "-cipher"));
    SSL_CTX_free(ctx);
    SSL_CONF_CTX_free(cctx);
}

int main(void)
{
    SSL_CTX *ctx;
    SSL *ssl;

    setvbuf(stdout, NULL, _IOLBF, 0);

    probe_defaults();

    ctx = SSL_CTX_new(TLS_method());
    ssl = SSL_new(ctx);
    probe_readers(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);

    probe_lists(TLS_method());
    probe_conf();

    return 0;
}
