/*
 * RT-DOWNSTREAM-CONSUMER — a real downstream consumer, built against the shipped shell.
 *
 * This probe is not compiled with the crate. It is a standalone program that links only the
 * *shipped distribution surface* an out-of-tree package sees: the installed `include/openssl`
 * headers and the installed `libssl`/`libcrypto` shared objects, resolved through `-I`, `-L`,
 * `-lssl -lcrypto` and an `-rpath`. The same source is compiled twice -- once against the
 * candidate shell under `artifacts/phase2/install/`, once against the admitted authority's prefix
 * under `forensics/authorities/prefix/openssl-3.6.4-production/` -- and the two transcripts are
 * compared line by line, keyed on `key=value`.
 *
 * The plan (docs/PHASE-17-SUBPHASES.md section 3.4) asks "does a real consumer work?", not for a
 * parity claim about any one symbol. So the probe exercises a representative slice of the exported
 * surface from the outside:
 *
 *   1. **EVP**: a SHA-256 digest over a fixed input string, through `EVP_MD_CTX_new` /
 *      `EVP_DigestInit_ex` / `EVP_DigestUpdate` / `EVP_DigestFinal_ex`. The digest is a fixed
 *      function of the input, so its bytes are directly comparable.
 *   2. **X.509**: a PEM parse of the fixed `fixtures/leaf.pem` through `PEM_read_bio_X509`,
 *      reporting the object's version, public key, subject-entry count and SHA-256 DER digest.
 *   3. **ERR**: a libcrypto round-trip -- `ERR_raise` a fixed reason, then read it back through
 *      `ERR_peek_error` / `ERR_get_error` / `ERR_error_string_n`, and confirm the queue drains.
 *   4. **TLS 1.3**: a client/server handshake over two pairs of memory BIOs, using the fixed
 *      `fixtures/signer.pem` certificate and `fixtures/rsa-key.pem` key, driven to
 *      `SSL_is_init_finished` and then exchanging one fixed 15-byte application record each way.
 *
 * Every observation is a deterministic function of the build: a return value, a length, a packed
 * error code, a digest, a handshake state, or a byte count. Nothing reads the clock, the network,
 * an address, a random or a host file. The probe's own output is ASCII `key=value` lines, one per
 * observation; `phase17_courts.py` captures bytes and decodes Latin-1 regardless.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

/* Fixed fixtures, read by absolute `/work` path so both sides' runs see identical inputs. */
#define FIXTURES "/work/courts/phase17/fixtures"
#define MAX_FLIGHT 3

static void out_int(const char *key, long v)
{
    printf("%s=%ld\n", key, v);
}

static void out_hex(const char *key, unsigned long v)
{
    printf("%s=0x%lx\n", key, v);
}

/* A digest/byte string, hex-encoded so the transcript stays ASCII regardless of the bytes. */
static void out_hexbytes(const char *key, const unsigned char *p, int n)
{
    int i;

    printf("%s=", key);
    for (i = 0; i < n; i++)
        printf("%02x", p[i]);
    printf("\n");
}

/* Drain every pending byte from a BIO into `buf` (bounded), returning the count. */
static int drain(BIO *b, unsigned char *buf, int cap)
{
    int total = 0;

    for (;;) {
        int pending = (int)BIO_ctrl(b, BIO_CTRL_PENDING, 0, NULL);
        int n;

        if (pending <= 0 || total >= cap)
            break;
        if (pending > cap - total)
            pending = cap - total;
        n = BIO_read(b, buf + total, pending);
        if (n <= 0)
            break;
        total += n;
    }
    return total;
}

static void show_state(const char *side, SSL *s)
{
    char key[64];

    snprintf(key, sizeof key, "tls.%s.state", side);
    out_int(key, SSL_get_state(s));
    snprintf(key, sizeof key, "tls.%s.want", side);
    out_int(key, SSL_want(s));
    snprintf(key, sizeof key, "tls.%s.in_init", side);
    out_int(key, SSL_in_init(s));
    snprintf(key, sizeof key, "tls.%s.finished", side);
    out_int(key, SSL_is_init_finished(s));
}

/* --- 1. EVP: a SHA-256 digest over a fixed input --- */
static void evp_slice(void)
{
    static const unsigned char input[] = "openssl-rs downstream consumer";
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int mdlen = 0;
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    int init = 0, upd = 0, fin = 0;

    memset(md, 0, sizeof md);
    out_int("evp.ctx.nonnull", mctx != NULL);
    if (mctx != NULL) {
        init = EVP_DigestInit_ex(mctx, EVP_sha256(), NULL);
        if (init == 1)
            upd = EVP_DigestUpdate(mctx, input, sizeof input - 1);
        if (upd == 1)
            fin = EVP_DigestFinal_ex(mctx, md, &mdlen);
    }
    out_int("evp.digest.init", init);
    out_int("evp.digest.update", upd);
    out_int("evp.digest.final", fin);
    out_int("evp.digest.len", (long)mdlen);
    out_hexbytes("evp.digest.hex", md, (int)mdlen);
    EVP_MD_CTX_free(mctx);
}

/* --- 2. X.509: a PEM parse of the fixed leaf certificate --- */
static void x509_slice(void)
{
    BIO *b = BIO_new_file(FIXTURES "/leaf.pem", "r");
    X509 *x = NULL;
    unsigned char dg[EVP_MAX_MD_SIZE];
    unsigned int dl = 0;
    EVP_PKEY *pk = NULL;
    X509_NAME *nm = NULL;
    int digest_ret = 0;

    memset(dg, 0, sizeof dg);
    out_int("x509.bio.nonnull", b != NULL);
    if (b != NULL)
        x = PEM_read_bio_X509(b, NULL, NULL, NULL);
    out_int("x509.load.nonnull", x != NULL);
    out_int("x509.version", x != NULL ? X509_get_version(x) : -1);
    if (x != NULL) {
        pk = X509_get_pubkey(x);
        nm = X509_get_subject_name(x);
        digest_ret = X509_digest(x, EVP_sha256(), dg, &dl);
    }
    out_int("x509.pubkey.nonnull", pk != NULL);
    out_int("x509.subject.entries", nm != NULL ? X509_NAME_entry_count(nm) : -1);
    out_int("x509.digest.ret", digest_ret);
    out_int("x509.digest.len", (long)dl);
    out_hexbytes("x509.digest.hex", dg, (int)dl);
    EVP_PKEY_free(pk);
    X509_free(x);
    BIO_free(b);
}

/* --- 3. ERR: a libcrypto round-trip --- */
static void err_slice(void)
{
    char text[256];
    unsigned long e;

    ERR_clear_error();
    ERR_raise(ERR_LIB_USER, 100);
    e = ERR_peek_error();
    out_hex("err.user.peek", e);
    out_int("err.user.lib", ERR_GET_LIB(e));
    out_int("err.user.reason", ERR_GET_REASON(e));
    ERR_error_string_n(e, text, sizeof text);
    printf("err.user.text=%s\n", text);
    out_hex("err.user.get", ERR_get_error());
    out_hex("err.user.after_get", ERR_peek_error());
    ERR_clear_error();
}

/* --- 4. TLS 1.3: a handshake over memory BIOs and a fixed application record --- */
static void tls_slice(void)
{
    SSL_CTX *cctx = SSL_CTX_new(TLS_method());
    SSL_CTX *sctx = SSL_CTX_new(TLS_method());
    SSL *client = NULL;
    SSL *server = NULL;
    BIO *cr, *cw, *sr, *sw;
    unsigned char buf[16384];
    int i, last_c = -2, last_s = -2;

    out_int("tls.ctx.client.nonnull", cctx != NULL);
    out_int("tls.ctx.server.nonnull", sctx != NULL);
    if (cctx == NULL || sctx == NULL) {
        SSL_CTX_free(cctx);
        SSL_CTX_free(sctx);
        return;
    }

    out_int("tls.server.cert.load",
            SSL_CTX_use_certificate_chain_file(
                sctx, FIXTURES "/signer.pem"));
    out_int("tls.server.key.load",
            SSL_CTX_use_PrivateKey_file(
                sctx, FIXTURES "/rsa-key.pem", SSL_FILETYPE_PEM));
    out_int("tls.server.key.check", SSL_CTX_check_private_key(sctx));
    SSL_CTX_set_verify(cctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_verify(sctx, SSL_VERIFY_NONE, NULL);

    client = SSL_new(cctx);
    server = SSL_new(sctx);
    out_int("tls.client.nonnull", client != NULL);
    out_int("tls.server.nonnull", server != NULL);
    out_int("tls.ciphers.count",
            SSL_get_ciphers(client) != NULL
                ? OPENSSL_sk_num((const OPENSSL_STACK *)SSL_get_ciphers(client))
                : -1);

    cr = BIO_new(BIO_s_mem());
    cw = BIO_new(BIO_s_mem());
    sr = BIO_new(BIO_s_mem());
    sw = BIO_new(BIO_s_mem());
    SSL_set_bio(client, cr, cw);
    SSL_set_bio(server, sr, sw);

    for (i = 0; i < MAX_FLIGHT; i++) {
        int cret, sret, clen, slen;
        char key[64];

        cret = SSL_connect(client);
        snprintf(key, sizeof key, "tls.flight.%d.client.ret", i);
        out_int(key, cret);
        clen = drain(cw, buf, sizeof buf);
        snprintf(key, sizeof key, "tls.flight.%d.client.out", i);
        out_int(key, clen);
        if (clen > 0)
            BIO_write(sr, buf, clen);

        sret = SSL_accept(server);
        snprintf(key, sizeof key, "tls.flight.%d.server.ret", i);
        out_int(key, sret);
        slen = drain(sw, buf, sizeof buf);
        snprintf(key, sizeof key, "tls.flight.%d.server.out", i);
        out_int(key, slen);
        if (slen > 0)
            BIO_write(cr, buf, slen);

        last_c = cret;
        last_s = sret;
    }

    out_int("tls.flights.used", i);
    show_state("client", client);
    show_state("server", server);

    {
        /* The fixed 15-byte application record, exchanged once in each direction. */
        unsigned char msg[16] = "downstream-ping";
        unsigned char got[32];
        int n;
        int done = last_c > 0 && last_s > 0
            && SSL_is_init_finished(client) && SSL_is_init_finished(server);

        out_int("app.skipped", !done);
        out_int("app.write.client",
                done ? SSL_write(client, msg, (int)strlen((char *)msg)) : -1);
        n = done ? drain(cw, buf, sizeof buf) : 0;
        out_int("app.client.bytes", done ? n : -1);
        if (done)
            BIO_write(sr, buf, n);
        memset(got, 0, sizeof got);
        out_int("app.read.server", done ? SSL_read(server, got, sizeof got) : -1);
        out_int("app.server.match",
                done ? (memcmp(got, msg, strlen((char *)msg)) == 0) : -1);

        out_int("app.write.server",
                done ? SSL_write(server, msg, (int)strlen((char *)msg)) : -1);
        n = done ? drain(sw, buf, sizeof buf) : 0;
        out_int("app.server.bytes", done ? n : -1);
        if (done)
            BIO_write(cr, buf, n);
        memset(got, 0, sizeof got);
        out_int("app.read.client", done ? SSL_read(client, got, sizeof got) : -1);
        out_int("app.client.match",
                done ? (memcmp(got, msg, strlen((char *)msg)) == 0) : -1);
    }

    /* `SSL_set_bio` took ownership of the four BIOs. */
    SSL_free(client);
    SSL_free(server);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

int main(void)
{
    setvbuf(stdout, NULL, _IOLBF, 0);

    evp_slice();
    x509_slice();
    err_slice();
    tls_slice();

    printf("probe.done=1\n");
    return 0;
}
