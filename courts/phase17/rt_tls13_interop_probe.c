/*
 * RT-TLS13-INTEROP — the TLS 1.3 client/server flight, driven over a pair of memory BIOs.
 *
 * Compiled twice (authority and candidate), run, and the two transcripts compared line
 * by line, keyed on `key=value`. The probe stands up one `SSL_CTX` per side — the
 * server's carrying the fixed `courts/phase17/fixtures/signer.pem` certificate and its
 * `rsa-key.pem` key, the client verifying nothing — connects them over two pairs of
 * memory BIOs, and pumps flight by flight until both report a finished handshake or the
 * bounded iteration budget runs out. It then exchanges one application-data record in
 * each direction.
 *
 * What is printed is a *structural transcript*, not the raw bytes: the handshake's
 * random fields (`ClientHello.random`, `key_share`) differ run to run on both sides, so
 * the probe reads lengths, message types, protocol versions, cipher-suite lists and the
 * ordered extension-type list instead. Every one of those is a deterministic function
 * of the build, so the authority's own two runs agree and a candidate that builds the
 * same message produces the same lines.
 *
 * The probe does not read the clock, the network or an address. It does read the `ERR`
 * queue, because the stop point is exactly what 17.2a must measure and a bare `-1`
 * would not name it.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#define MAX_FLIGHT 3

static void out_int(const char *key, long v)
{
    printf("%s=%ld\n", key, (long)v);
}

static void out_hex16(const char *key, unsigned v)
{
    printf("%s=0x%04x\n", key, (unsigned)(v & 0xffff));
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

/* Print the ordered extension-type list of a ClientHello body (TLS presentation). */
static void parse_extensions(const unsigned char *p, int len)
{
    int first = 1, off = 0;

    printf("ch.ext.types=");
    while (off + 4 <= len) {
        unsigned type = ((unsigned)p[off] << 8) | p[off + 1];
        unsigned elen = ((unsigned)p[off + 2] << 8) | p[off + 3];

        if (off + 4 + (int)elen > len)
            break;
        printf("%s%u", first ? "" : ",", type);
        first = 0;
        off += 4 + (int)elen;
    }
    printf("\n");

    /* A *fixed* schema: every run prints one line per type in this table, whether the extension
     * is present (its length, and its body for the small ones) or absent (`len=-1`). The
     * comparison is line-wise over both transcripts, so a fixed schema keeps the two sides'
     * observation counts equal even when the candidate emits fewer extensions. The large
     * random-bearing row (key_share, 51) is named by length only. */
    {
        static const unsigned kTypes[] = { 22, 23, 35, 43, 45, 51 };
        size_t ti;

        for (ti = 0; ti < sizeof kTypes / sizeof kTypes[0]; ti++) {
            unsigned want = kTypes[ti];
            unsigned elen = 0xffffffffu;
            const unsigned char *body = NULL;
            char key[64];
            int k, found = 0;

            off = 0;
            while (off + 4 <= len) {
                unsigned type = ((unsigned)p[off] << 8) | p[off + 1];
                unsigned l = ((unsigned)p[off + 2] << 8) | p[off + 3];

                if (off + 4 + (int)l > len)
                    break;
                if (type == want) {
                    elen = l;
                    body = p + off + 4;
                    found = 1;
                    break;
                }
                off += 4 + (int)l;
            }

            snprintf(key, sizeof key, "ch.ext.%u.len", want);
            out_int(key, found ? (long)elen : -1);
            if (found && elen <= 24) {
                printf("ch.ext.%u.data=", want);
                for (k = 0; k < (int)elen; k++)
                    printf("%s%02x", k ? "," : "", body[k]);
                printf("\n");
            }
        }
    }
}

/* Parse a handshake record carrying a ClientHello and print its structure. */
static void parse_client_hello(const unsigned char *b, int n)
{
    int rec_len, hs_len, sid_len, cip_len, comp_len, ext_len, p;

    if (n < 5) {
        out_int("ch.present", 0);
        return;
    }
    out_int("ch.present", 1);
    out_int("ch.rectype", b[0]);
    out_hex16("ch.recversion", ((unsigned)b[1] << 8) | b[2]);
    rec_len = ((int)b[3] << 8) | b[4];
    out_int("ch.reclen", rec_len);
    out_int("ch.recbytes", n);

    /* Body: handshake header (4) then ClientHello. */
    if (n < 9 || b[5] != 1) {
        out_int("ch.hs_type", n >= 6 ? b[5] : -1);
        return;
    }
    hs_len = ((int)b[6] << 16) | ((int)b[7] << 8) | b[8];
    out_int("ch.hs_type", 1);
    out_int("ch.hs_len", hs_len);

    p = 9;
    if (p + 2 > n)
        return;
    out_hex16("ch.legacy_version", ((unsigned)b[p] << 8) | b[p + 1]);
    p += 2;
    if (p + 32 > n)
        return;
    out_int("ch.random_len", 32);
    p += 32;
    if (p + 1 > n)
        return;
    sid_len = b[p];
    out_int("ch.session_id_len", sid_len);
    p += 1 + sid_len;
    if (p + 2 > n)
        return;
    cip_len = ((int)b[p] << 8) | b[p + 1];
    out_int("ch.cipher_len", cip_len);
    out_int("ch.cipher_count", cip_len / 2);
    p += 2 + cip_len;
    if (p + 1 > n)
        return;
    comp_len = b[p];
    out_int("ch.comp_len", comp_len);
    p += 1 + comp_len;
    if (p + 2 > n) {
        out_int("ch.ext_total_len", -1);
        return;
    }
    ext_len = ((int)b[p] << 8) | b[p + 1];
    out_int("ch.ext_total_len", ext_len);
    out_int("ch.ext_count.present", 1);
    p += 2;
    parse_extensions(b + p, n - p);
}

static void dump_errors(const char *prefix)
{
    int i = 0;
    unsigned long e;

    while ((e = ERR_get_error()) != 0 && i < 4) {
        char buf[256];

        ERR_error_string_n(e, buf, sizeof buf);
        printf("%s.%d=%s\n", prefix, i, buf);
        i++;
    }
    printf("%s.count=%d\n", prefix, i);
}

static void show_state(const char *side, SSL *s)
{
    char key[64];

    snprintf(key, sizeof key, "%s.state", side);
    out_int(key, SSL_get_state(s));
    snprintf(key, sizeof key, "%s.want", side);
    out_int(key, SSL_want(s));
    snprintf(key, sizeof key, "%s.in_init", side);
    out_int(key, SSL_in_init(s));
    snprintf(key, sizeof key, "%s.finished", side);
    out_int(key, SSL_is_init_finished(s));
}

int main(void)
{
    SSL_CTX *cctx = NULL;
    SSL_CTX *sctx = NULL;
    SSL *client = NULL;
    SSL *server = NULL;
    BIO *cr, *cw, *sr, *sw;
    unsigned char buf[16384];
    int i, last_c = -2, last_s = -2;

    setvbuf(stdout, NULL, _IOLBF, 0);

    cctx = SSL_CTX_new(TLS_method());
    sctx = SSL_CTX_new(TLS_method());
    out_int("ctx.client.nonnull", cctx != NULL);
    out_int("ctx.server.nonnull", sctx != NULL);
    if (cctx == NULL || sctx == NULL)
        return 0;

    out_int("server.cert.load",
            SSL_CTX_use_certificate_chain_file(
                sctx, "/work/courts/phase17/fixtures/signer.pem"));
    out_int("server.key.load",
            SSL_CTX_use_PrivateKey_file(
                sctx, "/work/courts/phase17/fixtures/rsa-key.pem",
                SSL_FILETYPE_PEM));
    out_int("server.key.check", SSL_CTX_check_private_key(sctx));
    dump_errors("server.cert.err");
    SSL_CTX_set_verify(cctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_verify(sctx, SSL_VERIFY_NONE, NULL);

    client = SSL_new(cctx);
    server = SSL_new(sctx);
    out_int("client.nonnull", client != NULL);
    out_int("server.nonnull", server != NULL);
    out_int("client.ciphers.count",
            SSL_get_ciphers(client) != NULL
                ? OPENSSL_sk_num((const OPENSSL_STACK *)SSL_get_ciphers(client))
                : -1);

    cr = BIO_new(BIO_s_mem());
    cw = BIO_new(BIO_s_mem());
    sr = BIO_new(BIO_s_mem());
    sw = BIO_new(BIO_s_mem());
    SSL_set_bio(client, cr, cw);
    SSL_set_bio(server, sr, sw);

    /* --- the client's first flight, then the server's, a fixed number of rounds --- */
    for (i = 0; i < MAX_FLIGHT; i++) {
        int cret, sret, clen, slen;
        char key[64];

        cret = SSL_connect(client);
        snprintf(key, sizeof key, "flight.%d.client.ret", i);
        out_int(key, cret);
        clen = drain(cw, buf, sizeof buf);
        snprintf(key, sizeof key, "flight.%d.client.out", i);
        out_int(key, clen);
        if (clen > 0) {
            BIO_write(sr, buf, clen);
            if (i == 0)
                parse_client_hello(buf, clen);
        }

        sret = SSL_accept(server);
        snprintf(key, sizeof key, "flight.%d.server.ret", i);
        out_int(key, sret);
        slen = drain(sw, buf, sizeof buf);
        snprintf(key, sizeof key, "flight.%d.server.out", i);
        out_int(key, slen);
        if (slen > 0)
            BIO_write(cr, buf, slen);

        last_c = cret;
        last_s = sret;
    }

    out_int("flights.used", i);
    show_state("client", client);
    show_state("server", server);

    /* --- the error queues, which name the stop point --- */
    dump_errors("client.err");
    dump_errors("server.err");

    /* --- application data. The block prints a fixed schema whether or not the handshake finished,
     * so the two sides' observation counts agree; an unfinished handshake answers -1 to each. --- */
    {
        unsigned char msg[16] = "ping-over-tls13";
        unsigned char got[32];
        int n;
        int done = last_c > 0 && last_s > 0
            && SSL_is_init_finished(client) && SSL_is_init_finished(server);

        out_int("app.skipped", !done);
        out_int("app.write.client", done ? SSL_write(client, msg, (int)strlen((char *)msg)) : -1);
        n = done ? drain(cw, buf, sizeof buf) : 0;
        out_int("app.client.bytes", done ? n : -1);
        if (done)
            BIO_write(sr, buf, n);
        memset(got, 0, sizeof got);
        out_int("app.read.server", done ? SSL_read(server, got, sizeof got) : -1);
        out_int("app.server.match", done ? (memcmp(got, msg, strlen((char *)msg)) == 0) : -1);

        out_int("app.write.server", done ? SSL_write(server, msg, (int)strlen((char *)msg)) : -1);
        n = done ? drain(sw, buf, sizeof buf) : 0;
        out_int("app.server.bytes", done ? n : -1);
        if (done)
            BIO_write(cr, buf, n);
        memset(got, 0, sizeof got);
        out_int("app.read.client", done ? SSL_read(client, got, sizeof got) : -1);
        out_int("app.client.match", done ? (memcmp(got, msg, strlen((char *)msg)) == 0) : -1);
    }

    /* `SSL_set_bio` took ownership of the four BIOs, so only the objects above are freed. */
    SSL_free(client);
    SSL_free(server);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);

    printf("probe.done=1\n");
    return 0;
}
