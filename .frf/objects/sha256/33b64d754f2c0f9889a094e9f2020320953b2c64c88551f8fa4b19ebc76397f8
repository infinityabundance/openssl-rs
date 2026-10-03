/*
 * RT-HTTP -- subphase 12.1's behavioural court: the `crypto/http/` surface, driven over
 * memory BIOs, with no socket and no wall clock.
 *
 * One C program, compiled once against the admitted authority and once against the candidate
 * distribution shell, whose two transcripts are diffed line by line. Every observation is a
 * small integer, a `nonnull`/`null`, a byte-for-byte equality or a short hex string -- never an
 * address and never a clock, so the transcript is a function of the library and not of the
 * probe's own frame (`probe_hygiene.py` compiles it at -O0/-O1/-O2 and requires that).
 *
 * What is driven, and the names the plan guessed
 * -----------------------------------------------
 * The request/response engine is driven through `OSSL_HTTP_REQ_CTX_new`/`_set_request_line`/
 * `_add1_header`/`_set_expected`/`_set1_req`/`_exchange`/`_nbio_d2i`/`_get0_mem_bio`/
 * `_get_resp_len`/`_set_max_response_length`/`_set_max_response_hdr_lines`/`_is_alive` over
 * memory BIOs, with canned `HTTP/1.1` responses covering a status line, `Content-Length`, a
 * `Transfer-Encoding: chunked` case and a `Content-Type` with a `charset` parameter; and the
 * high-level `OSSL_HTTP_open`/`_set1_request`/`_exchange`/`_close`/`_transfer` path is driven
 * with a caller-supplied memory BIO pair, which is the path that opens no socket.
 *
 * The subphase note named `OSSL_HTTP_REQ_CTX_set_request`, `_set1_request_header`,
 * `_get1_header`, `parse_response_line`, `_nbio_d2i_ex`, `_set_mem_buf`, `_get_mem_buf`,
 * `OSSL_HTTP_get_ex`, `OSSL_HTTP_get0_status`, `OSSL_HTTP_get_response_hdr`,
 * `OSSL_HTTP_set_response_hdr` and `OSSL_HTTP_is_adjusted_rlen`. **None of those names exists
 * in the authority** `openssl-3.6.4` (`include/openssl/http.h`, `crypto/http/http_client.c`);
 * they are not landed because there is nothing to land. Each corresponds to a real arm that is
 * driven here instead: `set_request` -> `_set_request_line`; `set1_request_header`/`_get1_header`
 * -> `_add1_header` and the `OSSL_HTTP_REQ_CTX_get0_mem_bio` read-back; `parse_response_line`
 * -> the `static parse_http_line1` through `_nbio`; `nbio_d2i_ex` -> `_nbio_d2i`;
 * `set_mem_buf`/`get_mem_buf` -> `_new` over the caller's BIOs and `_get0_mem_bio`; and the four
 * `get0_status`/`get_response_hdr`/`set_response_hdr`/`is_adjusted_rlen` readers have no
 * counterpart at all in 3.6.4, because that API only arrived after this authority.
 *
 * The court also drives the two `http_lib.c` names the ledger opens in this stratum:
 * `OSSL_HTTP_parse_url` (its scheme/port layer, together with `OSSL_parse_url`'s own arms) and
 * `OSSL_HTTP_adapt_proxy` (`no_proxy` matching, with the proxy environment variables cleared so
 * the arm is deterministic).
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/http.h>

/* ---------------------------------------------------------------------------------------------
 * Output helpers -- every line is `key=value`. No address is ever printed.
 * --------------------------------------------------------------------------------------------- */

static void out_int(const char *key, long v)
{
    printf("%s=%ld\n", key, v);
}

static void out_ptr(const char *key, const void *p)
{
    printf("%s=%s\n", key, p != NULL ? "nonnull" : "null");
}

/* The first error on the queue as `lib.reason`, then the queue is cleared. */
static void out_err(const char *key)
{
    unsigned long e = ERR_get_error();

    if (e == 0) {
        printf("%s=none\n", key);
        return;
    }
    printf("%s=%d.%d\n", key, ERR_GET_LIB(e), ERR_GET_REASON(e));
    ERR_clear_error();
}

/* A short hex rendering of the first `n` bytes, bounded so the line stays short. */
static void out_hex(const char *key, const unsigned char *p, size_t n)
{
    size_t i, m = n < 16 ? n : 16;

    printf("%s=", key);
    for (i = 0; i < m; i++)
        printf("%02x", p[i]);
    printf("\n");
}

static int eq(const char *a, const char *b)
{
    if (a == NULL || b == NULL)
        return a == b;
    return strcmp(a, b) == 0;
}

/* ---------------------------------------------------------------------------------------------
 * `crypto/http/http_lib.c`'s `OSSL_parse_url` and `OSSL_HTTP_parse_url`.
 * --------------------------------------------------------------------------------------------- */

static void drive_parse_url(void)
{
    char *sch = NULL, *usr = NULL, *hst = NULL, *prt = NULL, *pth = NULL, *qry = NULL;
    char *frg = NULL;
    int pn = -1, rv;

    rv = OSSL_parse_url("https://user@example.com:8443/path?q=1#frag",
                        &sch, &usr, &hst, &prt, &pn, &pth, &qry, &frg);
    out_int("parse.https.rv", rv);
    out_int("parse.https.ok", rv == 1 && eq(sch, "https") && eq(usr, "user")
            && eq(hst, "example.com") && eq(prt, "8443") && pn == 8443
            && eq(pth, "/path") && eq(qry, "q=1") && eq(frg, "frag"));
    OPENSSL_free(sch); OPENSSL_free(usr); OPENSSL_free(hst); OPENSSL_free(prt);
    OPENSSL_free(pth); OPENSSL_free(qry); OPENSSL_free(frg);
    sch = usr = hst = prt = pth = qry = frg = NULL; pn = -1;

    rv = OSSL_parse_url("example.com/path", &sch, &usr, &hst, &prt, &pn,
                        &pth, &qry, &frg);
    out_int("parse.noscheme.rv", rv);
    out_int("parse.noscheme.ok", rv == 1 && eq(sch, "") && eq(usr, "")
            && eq(hst, "example.com") && eq(prt, "0") && pn == 0
            && eq(pth, "/path") && eq(qry, "") && eq(frg, ""));
    OPENSSL_free(sch); OPENSSL_free(usr); OPENSSL_free(hst); OPENSSL_free(prt);
    OPENSSL_free(pth); OPENSSL_free(qry); OPENSSL_free(frg);
    sch = usr = hst = prt = pth = qry = frg = NULL; pn = -1;

    rv = OSSL_parse_url(NULL, &sch, &usr, &hst, &prt, &pn, &pth, &qry, &frg);
    out_int("parse.null.rv", rv);
    out_err("parse.null.err");

    rv = OSSL_parse_url("example.com:99999/p", &sch, &usr, &hst, &prt, &pn,
                        &pth, &qry, &frg);
    out_int("parse.badport.rv", rv);
    out_err("parse.badport.err");

    rv = OSSL_parse_url("example.com:x", &sch, &usr, &hst, &prt, &pn,
                        &pth, &qry, &frg);
    out_int("parse.badpath.rv", rv);
    out_err("parse.badpath.err");
}

static void drive_http_parse_url(void)
{
    int ssl = -1, pn = -1, rv;
    char *usr = NULL, *hst = NULL, *prt = NULL, *pth = NULL, *qry = NULL, *frg = NULL;

    rv = OSSL_HTTP_parse_url("http://example.com/path", &ssl, &usr, &hst, &prt, &pn,
                             &pth, &qry, &frg);
    out_int("hparse.http.rv", rv);
    out_int("hparse.http.ok", rv == 1 && ssl == 0 && eq(usr, "") && eq(hst, "example.com")
            && eq(prt, "80") && pn == 80 && eq(pth, "/path"));
    OPENSSL_free(usr); OPENSSL_free(hst); OPENSSL_free(prt); OPENSSL_free(pth);
    OPENSSL_free(qry); OPENSSL_free(frg);
    usr = hst = prt = pth = qry = frg = NULL; pn = -1; ssl = -1;

    rv = OSSL_HTTP_parse_url("https://example.com", &ssl, &usr, &hst, &prt, &pn,
                             &pth, &qry, &frg);
    out_int("hparse.https.rv", rv);
    out_int("hparse.https.ok", rv == 1 && ssl == 1 && eq(hst, "example.com")
            && eq(prt, "443") && pn == 443 && eq(pth, "/"));
    OPENSSL_free(usr); OPENSSL_free(hst); OPENSSL_free(prt); OPENSSL_free(pth);
    OPENSSL_free(qry); OPENSSL_free(frg);
    usr = hst = prt = pth = qry = frg = NULL; pn = -1; ssl = -1;

    rv = OSSL_HTTP_parse_url("http://example.com:8080/x", &ssl, &usr, &hst, &prt, &pn,
                             &pth, &qry, &frg);
    out_int("hparse.explicit.rv", rv);
    out_int("hparse.explicit.ok", rv == 1 && eq(prt, "8080") && pn == 8080);
    OPENSSL_free(usr); OPENSSL_free(hst); OPENSSL_free(prt); OPENSSL_free(pth);
    OPENSSL_free(qry); OPENSSL_free(frg);
    usr = hst = prt = pth = qry = frg = NULL; pn = -1; ssl = -1;

    rv = OSSL_HTTP_parse_url("ftp://example.com/", &ssl, &usr, &hst, &prt, &pn,
                             &pth, &qry, &frg);
    out_int("hparse.badscheme.rv", rv);
    out_err("hparse.badscheme.err");
}

/* ---------------------------------------------------------------------------------------------
 * `OSSL_HTTP_adapt_proxy` and its `static use_proxy`.
 * --------------------------------------------------------------------------------------------- */

static void drive_adapt_proxy(void)
{
    static const char *PROXY = "http://proxy.example:3128";

    out_int("adapt.match", OSSL_HTTP_adapt_proxy(PROXY, "example.org", "example.com", 0) == PROXY);
    out_int("adapt.nomatch", OSSL_HTTP_adapt_proxy(PROXY, "example.com", "example.com", 0) == NULL);
    out_int("adapt.empty", OSSL_HTTP_adapt_proxy("", "example.org", "example.com", 0) == NULL);
    out_int("adapt.ipv6", OSSL_HTTP_adapt_proxy(PROXY, "[2001:db8::1]", "[2001:db8::1]", 0) == NULL);
    out_int("adapt.env_unset", OSSL_HTTP_adapt_proxy(NULL, "example.org", "example.com", 0) == NULL);
    out_int("adapt.ssl", OSSL_HTTP_adapt_proxy(PROXY, NULL, "", 1) == PROXY);
}

/* ---------------------------------------------------------------------------------------------
 * The low-level request context over memory BIOs.
 * --------------------------------------------------------------------------------------------- */

static OSSL_HTTP_REQ_CTX *mk(const char *resp, BIO **wbio_out, BIO **rbio_out)
{
    BIO *wbio = BIO_new(BIO_s_mem());
    BIO *rbio = BIO_new_mem_buf(resp, (int)strlen(resp));
    OSSL_HTTP_REQ_CTX *rctx = OSSL_HTTP_REQ_CTX_new(wbio, rbio, 0);

    *wbio_out = wbio;
    *rbio_out = rbio;
    return rctx;
}

static void drive_low_refusals(void)
{
    BIO *w = BIO_new(BIO_s_mem());
    BIO *r = BIO_new_mem_buf("HTTP/1.0 200 OK\r\n\r\n", 19);
    OSSL_HTTP_REQ_CTX *rctx;

    out_ptr("reqctx.new.null_wbio", OSSL_HTTP_REQ_CTX_new(NULL, r, 0));
    out_err("reqctx.new.null_wbio.err");
    out_ptr("reqctx.new.null_rbio", OSSL_HTTP_REQ_CTX_new(w, NULL, 0));
    out_err("reqctx.new.null_rbio.err");

    rctx = OSSL_HTTP_REQ_CTX_new(w, r, 0);
    out_ptr("reqctx.new.ok", rctx);

    out_ptr("reqctx.get0_mem_bio.null", OSSL_HTTP_REQ_CTX_get0_mem_bio(NULL));
    out_err("reqctx.get0_mem_bio.null.err");
    out_int("reqctx.get_resp_len.null", (long)OSSL_HTTP_REQ_CTX_get_resp_len(NULL));
    out_err("reqctx.get_resp_len.null.err");
    OSSL_HTTP_REQ_CTX_set_max_response_length(NULL, 10);
    out_err("reqctx.set_max_response_length.null.err");
    OSSL_HTTP_REQ_CTX_set_max_response_hdr_lines(NULL, 10);
    out_err("reqctx.set_max_response_hdr_lines.null.err");
    out_int("reqctx.set_request_line.null",
            OSSL_HTTP_REQ_CTX_set_request_line(NULL, 0, NULL, NULL, "/"));
    out_err("reqctx.set_request_line.null.err");
    out_int("reqctx.add1_header.null_rctx",
            OSSL_HTTP_REQ_CTX_add1_header(NULL, "X", "1"));
    out_err("reqctx.add1_header.null_rctx.err");
    out_int("reqctx.add1_header.null_name",
            OSSL_HTTP_REQ_CTX_add1_header(rctx, NULL, "1"));
    out_err("reqctx.add1_header.null_name.err");
    out_int("reqctx.set_expected.null",
            OSSL_HTTP_REQ_CTX_set_expected(NULL, NULL, 0, 0, 0));
    out_err("reqctx.set_expected.null.err");
    out_int("reqctx.set1_req.null",
            OSSL_HTTP_REQ_CTX_set1_req(NULL, NULL, ASN1_ANY_it(), NULL));
    out_err("reqctx.set1_req.null.err");

    OSSL_HTTP_REQ_CTX_free(rctx);
    OSSL_HTTP_REQ_CTX_free(NULL);
    BIO_free(r);
    BIO_free(w);
}

static void drive_request_build(void)
{
    static const char LINE[] = "GET /path HTTP/1.0\r\n";
    static const char LINE_HDR[] = "GET /path HTTP/1.0\r\nX-Test: abc\r\n";
    BIO *w, *r;
    OSSL_HTTP_REQ_CTX *rctx = mk("HTTP/1.0 200 OK\r\n\r\n", &w, &r);
    BIO *mem = OSSL_HTTP_REQ_CTX_get0_mem_bio(rctx);
    const char *p;
    long n;

    out_int("build.set_request_line",
            OSSL_HTTP_REQ_CTX_set_request_line(rctx, 0, NULL, NULL, "/path"));
    n = BIO_get_mem_data(mem, &p);
    out_int("build.line_len", n);
    out_int("build.line_is", n == (long)strlen(LINE)
            && memcmp(p, LINE, (size_t)n) == 0);

    out_int("build.add1_header", OSSL_HTTP_REQ_CTX_add1_header(rctx, "X-Test", "abc"));
    n = BIO_get_mem_data(mem, &p);
    out_int("build.line_hdr_is", n == (long)strlen(LINE_HDR)
            && memcmp(p, LINE_HDR, (size_t)n) == 0);

    out_int("build.set_request_line.crlf",
            OSSL_HTTP_REQ_CTX_set_request_line(rctx, 0, "bad\r\nhost", NULL, "/"));
    out_err("build.set_request_line.crlf.err");
    out_int("build.set_request_line.absuri",
            OSSL_HTTP_REQ_CTX_set_request_line(rctx, 0, "host", NULL, "http://x/"));
    out_err("build.set_request_line.absuri.err");

    out_int("build.set_expected", OSSL_HTTP_REQ_CTX_set_expected(rctx, "text/plain", 0, 0, 0));
    out_err("build.set_expected.err");
    out_int("build.set_expected.ka", OSSL_HTTP_REQ_CTX_set_expected(rctx, NULL, 0, 0, 1));

    out_int("build.set1_req.null", OSSL_HTTP_REQ_CTX_set1_req(rctx, NULL, NULL, NULL));

    OSSL_HTTP_REQ_CTX_free(rctx);
    BIO_free(r);
    BIO_free(w);
}

/* A stream response: status line, `Content-Length` and a `Content-Type` with a `charset`. */
static void drive_exchange_stream(void)
{
    static const char RESP[] =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "Content-Length: 5\r\n"
        "\r\n"
        "hello";
    BIO *w, *r;
    OSSL_HTTP_REQ_CTX *rctx = mk(RESP, &w, &r);
    BIO *resp;
    char body[8] = { 0 };
    int n;

    out_int("ex.stream.set_line",
            OSSL_HTTP_REQ_CTX_set_request_line(rctx, 0, NULL, NULL, "/"));
    out_int("ex.stream.expect",
            OSSL_HTTP_REQ_CTX_set_expected(rctx, "text/plain", 0, 0, 0));
    resp = OSSL_HTTP_REQ_CTX_exchange(rctx);
    out_ptr("ex.stream.resp", resp);
    out_err("ex.stream.err");
    out_int("ex.stream.resp_len", (long)OSSL_HTTP_REQ_CTX_get_resp_len(rctx));
    n = resp != NULL ? BIO_read(resp, body, 5) : -1;
    out_int("ex.stream.body_n", n);
    out_int("ex.stream.body_is", n == 5 && memcmp(body, "hello", 5) == 0);
    out_int("ex.stream.is_alive", OSSL_HTTP_is_alive(rctx));

    OSSL_HTTP_REQ_CTX_free(rctx);
    BIO_free(r);
    BIO_free(w);
}

/* `OSSL_HTTP_REQ_CTX_nbio` driven directly (it is the engine `_exchange` wraps, and the one
 * export the linker would not otherwise import from a probe that only calls its wrappers). */
static void drive_nbio_direct(void)
{
    static const char RESP[] =
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";
    BIO *w, *r;
    OSSL_HTTP_REQ_CTX *rctx = mk(RESP, &w, &r);

    out_int("nbio.set_line",
            OSSL_HTTP_REQ_CTX_set_request_line(rctx, 0, NULL, NULL, "/"));
    out_int("nbio.rv", OSSL_HTTP_REQ_CTX_nbio(rctx));
    out_err("nbio.err");

    OSSL_HTTP_REQ_CTX_free(rctx);
    BIO_free(r);
    BIO_free(w);
}

/* A `Transfer-Encoding: chunked` response: the engine does not decode it, which is observable. */
static void drive_exchange_chunked(void)
{
    static const char RESP[] =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "5\r\nhello\r\n0\r\n\r\n";
    BIO *w, *r;
    OSSL_HTTP_REQ_CTX *rctx = mk(RESP, &w, &r);
    BIO *resp;
    unsigned char body[32] = { 0 };
    int n;

    out_int("ex.chunk.set_line",
            OSSL_HTTP_REQ_CTX_set_request_line(rctx, 0, NULL, NULL, "/"));
    resp = OSSL_HTTP_REQ_CTX_exchange(rctx);
    out_ptr("ex.chunk.resp", resp);
    out_err("ex.chunk.err");
    out_int("ex.chunk.resp_len", (long)OSSL_HTTP_REQ_CTX_get_resp_len(rctx));
    n = resp != NULL ? BIO_read(resp, body, (int)sizeof body) : -1;
    out_int("ex.chunk.body_n", n);
    out_hex("ex.chunk.body_hex", body, n > 0 ? (size_t)n : 0);

    OSSL_HTTP_REQ_CTX_free(rctx);
    BIO_free(r);
    BIO_free(w);
}

/* A malformed status line. */
static void drive_exchange_malformed(void)
{
    BIO *w, *r;
    OSSL_HTTP_REQ_CTX *rctx = mk("BOGUS\r\n\r\n", &w, &r);
    BIO *resp;

    out_int("ex.bad.set_line",
            OSSL_HTTP_REQ_CTX_set_request_line(rctx, 0, NULL, NULL, "/"));
    resp = OSSL_HTTP_REQ_CTX_exchange(rctx);
    out_ptr("ex.bad.resp", resp);
    out_err("ex.bad.err");

    OSSL_HTTP_REQ_CTX_free(rctx);
    BIO_free(r);
    BIO_free(w);
}

/* A `Content-Type` the request did not ask for. */
static void drive_exchange_wrong_ct(void)
{
    static const char RESP[] =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: 2\r\n"
        "\r\n"
        "{}";
    BIO *w, *r;
    OSSL_HTTP_REQ_CTX *rctx = mk(RESP, &w, &r);
    BIO *resp;

    out_int("ex.ct.set_line",
            OSSL_HTTP_REQ_CTX_set_request_line(rctx, 0, NULL, NULL, "/"));
    out_int("ex.ct.expect",
            OSSL_HTTP_REQ_CTX_set_expected(rctx, "text/plain", 0, 0, 0));
    resp = OSSL_HTTP_REQ_CTX_exchange(rctx);
    out_ptr("ex.ct.resp", resp);
    out_err("ex.ct.err");

    OSSL_HTTP_REQ_CTX_free(rctx);
    BIO_free(r);
    BIO_free(w);
}

/* A response missing the `Content-Type` the request asked for. */
static void drive_exchange_missing_ct(void)
{
    static const char RESP[] =
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: 2\r\n"
        "\r\n"
        "{}";
    BIO *w, *r;
    OSSL_HTTP_REQ_CTX *rctx = mk(RESP, &w, &r);
    BIO *resp;

    out_int("ex.mct.set_line",
            OSSL_HTTP_REQ_CTX_set_request_line(rctx, 0, NULL, NULL, "/"));
    out_int("ex.mct.expect",
            OSSL_HTTP_REQ_CTX_set_expected(rctx, "text/plain", 0, 0, 0));
    resp = OSSL_HTTP_REQ_CTX_exchange(rctx);
    out_ptr("ex.mct.resp", resp);
    out_err("ex.mct.err");

    OSSL_HTTP_REQ_CTX_free(rctx);
    BIO_free(r);
    BIO_free(w);
}

/* The response length limit, exceeded. */
static void drive_exchange_max_len(void)
{
    static const char RESP[] =
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: 5\r\n"
        "\r\n"
        "hello";
    BIO *w, *r;
    OSSL_HTTP_REQ_CTX *rctx = mk(RESP, &w, &r);
    BIO *resp;

    out_int("ex.max.set_line",
            OSSL_HTTP_REQ_CTX_set_request_line(rctx, 0, NULL, NULL, "/"));
    OSSL_HTTP_REQ_CTX_set_max_response_length(rctx, 1);
    resp = OSSL_HTTP_REQ_CTX_exchange(rctx);
    out_ptr("ex.max.resp", resp);
    out_err("ex.max.err");

    OSSL_HTTP_REQ_CTX_free(rctx);
    BIO_free(r);
    BIO_free(w);
}

/* An ASN.1 response boundary, decoded through `OSSL_HTTP_REQ_CTX_nbio_d2i`. */
static void drive_nbio_d2i(void)
{
    static const unsigned char DER[] = { 0x30, 0x03, 0x02, 0x01, 0x05 };
    static const char HDR[] = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n";
    char resp[128];
    int hlen = snprintf(resp, sizeof resp, "%s", HDR);
    BIO *w = BIO_new(BIO_s_mem());
    BIO *r;
    OSSL_HTTP_REQ_CTX *rctx;
    void *pval = NULL;
    int rv;

    memcpy(resp + hlen, DER, sizeof DER);
    r = BIO_new_mem_buf(resp, hlen + (int)sizeof DER);
    rctx = OSSL_HTTP_REQ_CTX_new(w, r, 0);
    out_int("ex.asn1.set_line",
            OSSL_HTTP_REQ_CTX_set_request_line(rctx, 0, NULL, NULL, "/"));
    out_int("ex.asn1.expect",
            OSSL_HTTP_REQ_CTX_set_expected(rctx, NULL, 1 /*asn1*/, 0, 0));
    rv = OSSL_HTTP_REQ_CTX_nbio_d2i(rctx, &pval, ASN1_ANY_it());
    out_int("ex.asn1.rv", rv);
    out_ptr("ex.asn1.pval", pval);
    out_err("ex.asn1.err");
    ASN1_item_free(pval, ASN1_ANY_it());

    OSSL_HTTP_REQ_CTX_free(rctx);
    BIO_free(r);
    BIO_free(w);
}

static void drive_is_alive(void)
{
    BIO *w, *r;
    OSSL_HTTP_REQ_CTX *rctx = mk("HTTP/1.1 200 OK\r\nConnection: keep-alive\r\n\r\n", &w, &r);

    out_int("alive.null", OSSL_HTTP_is_alive(NULL));
    out_int("alive.after_new", OSSL_HTTP_is_alive(rctx));
    out_int("alive.set_line",
            OSSL_HTTP_REQ_CTX_set_request_line(rctx, 0, NULL, NULL, "/"));
    out_int("alive.set_expected_ka",
            OSSL_HTTP_REQ_CTX_set_expected(rctx, NULL, 0, 0, 1));
    out_int("alive.after_ka", OSSL_HTTP_is_alive(rctx));

    OSSL_HTTP_REQ_CTX_free(rctx);
    BIO_free(r);
    BIO_free(w);
}

/* ---------------------------------------------------------------------------------------------
 * The high-level API, driven with a caller-supplied memory BIO pair (no socket).
 * --------------------------------------------------------------------------------------------- */

static void drive_high_level(void)
{
    static const char RESP[] =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: 2\r\n"
        "\r\n"
        "hi";
    BIO *w = BIO_new(BIO_s_mem());
    BIO *r = BIO_new_mem_buf(RESP, (int)strlen(RESP));
    OSSL_HTTP_REQ_CTX *rctx;
    BIO *resp;
    char body[4] = { 0 };
    char *redir = NULL;
    int n;

    rctx = OSSL_HTTP_open("example.com", NULL, NULL, NULL, 0, w, r, NULL, NULL, 0, 0);
    out_ptr("hl.open", rctx);
    out_err("hl.open.err");
    out_int("hl.set1_request", rctx != NULL
            ? OSSL_HTTP_set1_request(rctx, "/p", NULL, NULL, NULL, NULL, 0, 0, -1, 0)
            : -1);
    out_err("hl.set1_request.err");
    resp = rctx != NULL ? OSSL_HTTP_exchange(rctx, &redir) : NULL;
    out_ptr("hl.exchange", resp);
    out_err("hl.exchange.err");
    n = resp != NULL ? BIO_read(resp, body, 2) : -1;
    out_int("hl.body_n", n);
    out_int("hl.body_is", n == 2 && memcmp(body, "hi", 2) == 0);
    if (resp != NULL)
        BIO_free(resp);
    out_int("hl.close", OSSL_HTTP_close(rctx, 1));
    BIO_free(r);
    BIO_free(w);
}

static void drive_high_level_refusals(void)
{
    BIO *w = BIO_new(BIO_s_mem());
    BIO *r = BIO_new_mem_buf("HTTP/1.0 200 OK\r\n\r\n", 19);
    OSSL_HTTP_REQ_CTX *out;

    out = OSSL_HTTP_open("h", NULL, NULL, NULL, 1, NULL, NULL, NULL, NULL, 0, 0);
    out_ptr("open.tls_not_enabled", out);
    out_err("open.tls_not_enabled.err");

    out = OSSL_HTTP_open("h", NULL, NULL, NULL, 0, NULL, r, NULL, NULL, 0, 0);
    out_ptr("open.rbio_without_bio", out);
    out_err("open.rbio_without_bio.err");

    out = OSSL_HTTP_open("h", NULL, "http://proxy", NULL, 0, w, r, NULL, NULL, 0, 0);
    out_ptr("open.bio_with_proxy", out);
    out_err("open.bio_with_proxy.err");

    out = OSSL_HTTP_open(NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL, NULL, 0, 0);
    out_ptr("open.server_null", out);
    out_err("open.server_null.err");

    out_int("open.set1_request.null",
            OSSL_HTTP_set1_request(NULL, "/", NULL, NULL, NULL, NULL, 0, 0, 0, 0));
    out_err("open.set1_request.null.err");

    out_ptr("get.null_url",
            OSSL_HTTP_get(NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, 0, 0, 0));
    out_err("get.null_url.err");

    {
        OSSL_HTTP_REQ_CTX *tr = NULL;
        BIO *tresp = OSSL_HTTP_transfer(&tr, NULL, NULL, "/", 0, NULL, NULL, NULL, NULL,
                                        NULL, NULL, 0, NULL, NULL, NULL, NULL, 0, 0, 0, 0);
        out_ptr("transfer.null_server", tresp);
        out_err("transfer.null_server.err");
    }

    out_int("proxy_connect.null_bio",
            OSSL_HTTP_proxy_connect(NULL, "h", "443", NULL, NULL, 0, NULL, NULL));
    out_err("proxy_connect.null_bio.err");
    out_int("proxy_connect.null_server",
            OSSL_HTTP_proxy_connect(w, NULL, NULL, NULL, NULL, 0, NULL, NULL));
    out_err("proxy_connect.null_server.err");
    out_int("proxy_connect.null_prog",
            OSSL_HTTP_proxy_connect(w, "h", "443", NULL, NULL, 0, w, NULL));
    out_err("proxy_connect.null_prog.err");

    BIO_free(r);
    BIO_free(w);
}

int main(void)
{
    /* The proxy environment variables would otherwise leak the runner's environment into
     * `OSSL_HTTP_adapt_proxy` and make the transcript host-dependent. Cleared on both sides. */
    unsetenv("http_proxy");
    unsetenv("HTTP_PROXY");
    unsetenv("https_proxy");
    unsetenv("HTTPS_PROXY");
    unsetenv("no_proxy");
    unsetenv("NO_PROXY");

    setvbuf(stdout, NULL, _IOLBF, 0);
    ERR_clear_error();

    drive_parse_url();
    drive_http_parse_url();
    drive_adapt_proxy();
    drive_low_refusals();
    drive_request_build();
    drive_exchange_stream();
    drive_nbio_direct();
    drive_exchange_chunked();
    drive_exchange_malformed();
    drive_exchange_wrong_ct();
    drive_exchange_missing_ct();
    drive_exchange_max_len();
    drive_nbio_d2i();
    drive_is_alive();
    drive_high_level();
    drive_high_level_refusals();

    return 0;
}
