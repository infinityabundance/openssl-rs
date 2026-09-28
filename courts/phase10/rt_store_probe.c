/*
 * openssl-rs -- Phase 10, subphase 10.5's differential court: RT-STORE.
 *
 * Compiled twice -- once against the admitted authority, once against the candidate
 * distribution shell -- and run; the two transcripts are compared line for line by
 * `forensics/tools/phase10_courts.py`. Every observation is a `key=value` line, so a
 * missing or extra line costs exactly one residual.
 *
 * What it establishes, and what it does not
 * -----------------------------------------
 * STORE's identity is a fetch and a loader contract (docs/PHASE-10-SUBPHASES.md section 3.3).
 * This probe drives the part of 10.5 whose closure is landed, and after the second pass that is
 * every export of the four units except three:
 *
 *  * the `OSSL_STORE_LOADER` object and its process-global scheme registry (`store_register.c`,
 *    `store_meth.c`), driven by name and through `OSSL_STORE_do_all_loaders`;
 *  * the `OSSL_STORE_INFO` type-name table (`store_strings.c`);
 *  * the whole `OSSL_STORE_INFO` object model (`new`/`new_NAME`/`new_PARAMS`/`new_PUBKEY`/
 *    `new_PKEY`/`new_CERT`/`new_CRL`/`set0_NAME_description`, `get_type`, the `get0_*` and
 *    `get1_*` accessors, and `free`) and the whole `OSSL_STORE_SEARCH` object;
 *  * the `OSSL_STORE_CTX` state machine (`open`/`open_ex`/`attach`/`eof`/`error`/`expect`/
 *    `find`/`delete`/`close`/`supports_search`, plus the two deprecated control entry points
 *    `OSSL_STORE_ctrl`/`OSSL_STORE_vctrl`) over an **in-process registered legacy loader**, which
 *    is what makes the refusal arms reachable without either `file` provider row.
 *
 * The refusal arms are the ones section 3.3 names -- an unknown scheme, a NULL URI, a loader
 * whose registration omits `load` -- each with its error queue coordinate, plus the CTX state
 * transitions (`eof`, `error`, `expect`, `find`, `close`).
 *
 * What it cannot drive, and prints as `pending.`
 * ----------------------------------------------
 * The blockage is **per function** (docs/DECISIONS.md D448, corrected by the second 10.5 pass and
 * again by 10.8), and what this probe does not call is named below with its measured blocker:
 *
 *  * `OSSL_STORE_load` -- its fetched branch calls `store_result.c`'s
 *    `ossl_store_handle_load_result`, which needs `PKCS12_parse` (10.3-withheld) now that 10.12
 *    landed `d2i_X509_AUX`. 10.8 landed `d2i_X509`/`d2i_X509_CRL`, so only `PKCS12_parse`
 *    remains.
 *  * `OSSL_STORE_find`'s `BY_NAME`/`BY_ISSUER_SERIAL` arms -- 10.8 landed `i2d_X509_NAME`, but the
 *    arms sit in the **fetched** branch, which no candidate reaches while the `file`
 *    `OSSL_OP_STORE` row is unpublished. The blocker is the provider row, not the name encoder.
 *  * the two `OSSL_OP_STORE` provider rows (`file`) -- so `OSSL_STORE_LOADER_fetch` and
 *    `OSSL_STORE_LOADER_do_all_provided` stay **address-taken only**, and the refused paths are
 *    driven through the legacy registry instead.
 *
 * 10.8 lands the `X509`/`X509_CRL` object core, so `OSSL_STORE_INFO_get1_CERT`/`_get1_CRL`, the
 * `CERT`/`CRL` arms of `OSSL_STORE_INFO_free`, and a decode/re-encode/dup/free of a fixed
 * certificate and CRL are **driven** below rather than named pending.
 *
 * Everything printed is a literal, a string, or a `nonnull`/`null`/int answer; no pointer
 * address is ever printed (the two sides allocate differently, and `probe_hygiene.py` would
 * catch it).
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE

/* The whole `ENGINE_*` surface is `OSSL_DEPRECATEDIN_3_0`; the deprecation is the authority's
 * statement about application code, not about a court that must exercise the registry. */
#define OPENSSL_SUPPRESS_DEPRECATED

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/store.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>

#include "rt_x509_der.h"

/* ---------------------------------------------------------------------------------------------
 * Output helpers -- every line is `key=value`.
 * --------------------------------------------------------------------------------------------- */

static void out_int(const char *key, long v)
{
    printf("%s=%ld\n", key, v);
}

static void out_str(const char *key, const char *s)
{
    printf("%s=%s\n", key, s != NULL ? s : "null");
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

/* ---------------------------------------------------------------------------------------------
 * A minimal legacy loader.
 *
 * `OSSL_STORE_register_loader` requires `open`, `load`, `eof`, `error` and `close` to be present;
 * one registration below deliberately omits `load` to drive the `LOADER_INCOMPLETE` refusal. The
 * callbacks are matched against the authority's own signatures and are what the CTX state machine
 * calls once `OSSL_STORE_open` has resolved this loader.
 * --------------------------------------------------------------------------------------------- */

static OSSL_STORE_LOADER_CTX *probe_open(const OSSL_STORE_LOADER *loader, const char *uri,
                                         const UI_METHOD *ui_method, void *ui_data)
{
    (void)loader; (void)uri; (void)ui_method; (void)ui_data;
    return (OSSL_STORE_LOADER_CTX *)1;
}

static OSSL_STORE_LOADER_CTX *probe_open_ex(const OSSL_STORE_LOADER *loader, const char *uri,
                                            OSSL_LIB_CTX *libctx, const char *propq,
                                            const UI_METHOD *ui_method, void *ui_data)
{
    (void)loader; (void)uri; (void)libctx; (void)propq; (void)ui_method; (void)ui_data;
    return (OSSL_STORE_LOADER_CTX *)1;
}

static OSSL_STORE_LOADER_CTX *probe_attach(const OSSL_STORE_LOADER *loader, BIO *bio,
                                           OSSL_LIB_CTX *libctx, const char *propq,
                                           const UI_METHOD *ui_method, void *ui_data)
{
    (void)loader; (void)bio; (void)libctx; (void)propq; (void)ui_method; (void)ui_data;
    return (OSSL_STORE_LOADER_CTX *)1;
}

static int probe_control(OSSL_STORE_LOADER_CTX *ctx, int cmd, va_list args)
{
    (void)ctx; (void)cmd; (void)args;
    return 1;
}

static int probe_expect(OSSL_STORE_LOADER_CTX *ctx, int expected)
{
    (void)ctx; (void)expected;
    return 1;
}

static int probe_find(OSSL_STORE_LOADER_CTX *ctx, const OSSL_STORE_SEARCH *criteria)
{
    (void)ctx; (void)criteria;
    return 1;
}

static OSSL_STORE_INFO *probe_load(OSSL_STORE_LOADER_CTX *ctx, const UI_METHOD *ui_method,
                                   void *ui_data)
{
    (void)ctx; (void)ui_method; (void)ui_data;
    return NULL;
}

static int probe_eof(OSSL_STORE_LOADER_CTX *ctx)
{
    (void)ctx;
    return 1;
}

static int probe_error(OSSL_STORE_LOADER_CTX *ctx)
{
    (void)ctx;
    return 0;
}

static int probe_close(OSSL_STORE_LOADER_CTX *ctx)
{
    (void)ctx;
    return 1;
}

/* Fill a loader with the five required callbacks. `with_load` is 0 for the
 * `LOADER_INCOMPLETE` arm, where `load` stays NULL. */
static OSSL_STORE_LOADER *make_loader(const char *scheme, int with_load)
{
    OSSL_STORE_LOADER *loader = OSSL_STORE_LOADER_new(NULL, scheme);

    if (loader == NULL)
        return NULL;
    OSSL_STORE_LOADER_set_open(loader, probe_open);
    OSSL_STORE_LOADER_set_open_ex(loader, probe_open_ex);
    OSSL_STORE_LOADER_set_attach(loader, probe_attach);
    OSSL_STORE_LOADER_set_ctrl(loader, probe_control);
    OSSL_STORE_LOADER_set_expect(loader, probe_expect);
    OSSL_STORE_LOADER_set_find(loader, probe_find);
    if (with_load)
        OSSL_STORE_LOADER_set_load(loader, probe_load);
    OSSL_STORE_LOADER_set_eof(loader, probe_eof);
    OSSL_STORE_LOADER_set_error(loader, probe_error);
    OSSL_STORE_LOADER_set_close(loader, probe_close);
    return loader;
}

/* `OSSL_STORE_vctrl` takes a `va_list`, which a caller can only build from its own variadic
 * function; this is that caller. */
static int call_vctrl(OSSL_STORE_CTX *ctx, int cmd, ...)
{
    va_list args;
    int ret;

    va_start(args, cmd);
    ret = OSSL_STORE_vctrl(ctx, cmd, args);
    va_end(args);
    return ret;
}

/* ---------------------------------------------------------------------------------------------
 * The do-all callbacks. Each prints a per-name `key` so the observation is order-independent:
 * the authority walks an LHASH (hash order) and the candidate walks its own register, and the
 * public contract gives the callback no order (docs/PHASE-10-SUBPHASES.md section 3.3).
 * --------------------------------------------------------------------------------------------- */

static void do_all_names_cb(const char *name, void *arg)
{
    long *count = arg;

    (void)name;
    (*count)++;
}

static long g_do_all_count;

static void do_all_loaders_cb(const OSSL_STORE_LOADER *loader, void *arg)
{
    (void)arg;
    g_do_all_count++;
    printf("store.do_all.%s=1\n", OSSL_STORE_LOADER_get0_scheme(loader));
}

/* ---------------------------------------------------------------------------------------------
 * The `OSSL_STORE_INFO` object model, driven through its public constructors and accessors.
 * --------------------------------------------------------------------------------------------- */

static void drive_info_object_model(void)
{
    OSSL_STORE_INFO *name;
    OSSL_STORE_INFO *params;
    OSSL_STORE_INFO *pubkey;
    OSSL_STORE_INFO *pkey;
    OSSL_STORE_INFO *cert;
    OSSL_STORE_INFO *crl;
    EVP_PKEY *pk;
    char *copy;

    /* The generic constructor, and the NAME arm with its description. */
    name = OSSL_STORE_INFO_new_NAME(OPENSSL_strdup("a-name"));
    out_ptr("info.new_NAME", name);
    out_int("info.get_type.NAME", OSSL_STORE_INFO_get_type(name));
    out_str("info.get0_NAME", OSSL_STORE_INFO_get0_NAME(name));
    out_ptr("info.get0_data.NAME", OSSL_STORE_INFO_get0_data(OSSL_STORE_INFO_NAME, name));
    out_ptr("info.get0_data.NAME.mismatch",
            OSSL_STORE_INFO_get0_data(OSSL_STORE_INFO_PKEY, name));
    out_ptr("info.get0_NAME_description.before", OSSL_STORE_INFO_get0_NAME_description(name));

    copy = OSSL_STORE_INFO_get1_NAME(name);
    out_ptr("info.get1_NAME", copy);
    out_int("info.get1_NAME.is_copy", copy != OSSL_STORE_INFO_get0_NAME(name));
    OPENSSL_free(copy);

    out_int("info.set0_NAME_description", OSSL_STORE_INFO_set0_NAME_description(
                                               name, OPENSSL_strdup("a description")));
    out_str("info.get0_NAME_description.after", OSSL_STORE_INFO_get0_NAME_description(name));
    copy = OSSL_STORE_INFO_get1_NAME_description(name);
    out_str("info.get1_NAME_description", copy);
    OPENSSL_free(copy);

    /* Every other typed accessor refuses a NAME, with its own reason. */
    out_ptr("info.get0_PARAMS.on_name", OSSL_STORE_INFO_get0_PARAMS(name));
    out_ptr("info.get1_PARAMS.on_name", OSSL_STORE_INFO_get1_PARAMS(name));
    out_err("info.get1_PARAMS.on_name.err");
    out_ptr("info.get0_PUBKEY.on_name", OSSL_STORE_INFO_get0_PUBKEY(name));
    out_ptr("info.get1_PUBKEY.on_name", OSSL_STORE_INFO_get1_PUBKEY(name));
    out_err("info.get1_PUBKEY.on_name.err");
    out_ptr("info.get0_PKEY.on_name", OSSL_STORE_INFO_get0_PKEY(name));
    out_ptr("info.get1_PKEY.on_name", OSSL_STORE_INFO_get1_PKEY(name));
    out_err("info.get1_PKEY.on_name.err");
    out_ptr("info.get0_CERT.on_name", OSSL_STORE_INFO_get0_CERT(name));
    out_ptr("info.get0_CRL.on_name", OSSL_STORE_INFO_get0_CRL(name));
    OSSL_STORE_INFO_free(name);

    /* The three EVP_PKEY arms, driven with a live key so the `get1_*` up-ref is real. */
    pk = EVP_PKEY_new();
    params = OSSL_STORE_INFO_new_PARAMS(pk);
    out_ptr("info.new_PARAMS", params);
    out_int("info.get_type.PARAMS", OSSL_STORE_INFO_get_type(params));
    out_int("info.get0_PARAMS.is_key", OSSL_STORE_INFO_get0_PARAMS(params) == pk);
    out_int("info.get1_PARAMS.is_key", OSSL_STORE_INFO_get1_PARAMS(params) == pk);
    out_ptr("info.get0_PUBKEY.on_params", OSSL_STORE_INFO_get0_PUBKEY(params));
    OSSL_STORE_INFO_free(params);

    pk = EVP_PKEY_new();
    pubkey = OSSL_STORE_INFO_new_PUBKEY(pk);
    out_ptr("info.new_PUBKEY", pubkey);
    out_int("info.get_type.PUBKEY", OSSL_STORE_INFO_get_type(pubkey));
    out_int("info.get0_PUBKEY.is_key", OSSL_STORE_INFO_get0_PUBKEY(pubkey) == pk);
    out_int("info.get1_PUBKEY.is_key", OSSL_STORE_INFO_get1_PUBKEY(pubkey) == pk);
    OSSL_STORE_INFO_free(pubkey);

    pk = EVP_PKEY_new();
    pkey = OSSL_STORE_INFO_new_PKEY(pk);
    out_ptr("info.new_PKEY", pkey);
    out_int("info.get_type.PKEY", OSSL_STORE_INFO_get_type(pkey));
    out_int("info.get0_PKEY.is_key", OSSL_STORE_INFO_get0_PKEY(pkey) == pk);
    out_int("info.get1_PKEY.is_key", OSSL_STORE_INFO_get1_PKEY(pkey) == pk);
    out_ptr("info.get0_PARAMS.on_pkey", OSSL_STORE_INFO_get0_PARAMS(pkey));
    OSSL_STORE_INFO_free(pkey);

    /* The CERT/CRL constructors take an opaque pointer; with a NULL object their accessors
     * answer NULL and the carve in `OSSL_STORE_INFO_free` is unobservable. */
    cert = OSSL_STORE_INFO_new_CERT(NULL);
    out_ptr("info.new_CERT", cert);
    out_int("info.get_type.CERT", OSSL_STORE_INFO_get_type(cert));
    out_ptr("info.get0_CERT", OSSL_STORE_INFO_get0_CERT(cert));
    out_ptr("info.get0_CRL.on_cert", OSSL_STORE_INFO_get0_CRL(cert));
    OSSL_STORE_INFO_free(cert);

    crl = OSSL_STORE_INFO_new_CRL(NULL);
    out_ptr("info.new_CRL", crl);
    out_int("info.get_type.CRL", OSSL_STORE_INFO_get_type(crl));
    out_ptr("info.get0_CRL", OSSL_STORE_INFO_get0_CRL(crl));
    OSSL_STORE_INFO_free(crl);

    /* The generic constructor with an arbitrary type, and the NULL free. */
    cert = OSSL_STORE_INFO_new(OSSL_STORE_INFO_NAME, NULL);
    out_int("info.new.generic.type", OSSL_STORE_INFO_get_type(cert));
    OSSL_STORE_INFO_free(cert);
    OSSL_STORE_INFO_free(NULL);
    out_str("info.free.null", "ok");
}

/* ---------------------------------------------------------------------------------------------
 * The `OSSL_STORE_SEARCH` object.
 * --------------------------------------------------------------------------------------------- */

static void drive_search_object_model(void)
{
    OSSL_STORE_SEARCH *alias;
    OSSL_STORE_SEARCH *name;
    OSSL_STORE_SEARCH *issuer;
    OSSL_STORE_SEARCH *fp;
    const EVP_MD *md = EVP_sha256();
    const unsigned char bytes[32] = { 0 };
    size_t len = 0;
    const unsigned char *got;

    alias = OSSL_STORE_SEARCH_by_alias("an-alias");
    out_ptr("search.by_alias", alias);
    out_int("search.by_alias.type", OSSL_STORE_SEARCH_get_type(alias));
    out_str("search.by_alias.string", OSSL_STORE_SEARCH_get0_string(alias));
    got = OSSL_STORE_SEARCH_get0_bytes(alias, &len);
    out_int("search.by_alias.len", (long)len);
    out_ptr("search.by_alias.bytes", got);
    out_ptr("search.by_alias.name", OSSL_STORE_SEARCH_get0_name(alias));
    out_ptr("search.by_alias.digest", OSSL_STORE_SEARCH_get0_digest(alias));
    OSSL_STORE_SEARCH_free(alias);

    name = OSSL_STORE_SEARCH_by_name(NULL);
    out_ptr("search.by_name", name);
    out_int("search.by_name.type", OSSL_STORE_SEARCH_get_type(name));
    out_ptr("search.by_name.name", OSSL_STORE_SEARCH_get0_name(name));
    OSSL_STORE_SEARCH_free(name);

    issuer = OSSL_STORE_SEARCH_by_issuer_serial(NULL, NULL);
    out_ptr("search.by_issuer", issuer);
    out_int("search.by_issuer.type", OSSL_STORE_SEARCH_get_type(issuer));
    out_ptr("search.by_issuer.serial", OSSL_STORE_SEARCH_get0_serial(issuer));
    OSSL_STORE_SEARCH_free(issuer);

    fp = OSSL_STORE_SEARCH_by_key_fingerprint(md, bytes, sizeof(bytes));
    out_ptr("search.by_fp", fp);
    out_int("search.by_fp.type", OSSL_STORE_SEARCH_get_type(fp));
    out_int("search.by_fp.digest.is_sha256", OSSL_STORE_SEARCH_get0_digest(fp) == md);
    OSSL_STORE_SEARCH_free(fp);

    /* A fingerprint whose length does not match the digest is the refusal arm. */
    fp = OSSL_STORE_SEARCH_by_key_fingerprint(md, bytes, 3);
    out_ptr("search.by_fp.bad_length", fp);
    out_err("search.by_fp.bad_length.err");
}

/* ---------------------------------------------------------------------------------------------
 * The `OSSL_STORE_CTX` state machine over the registered legacy loader.
 * --------------------------------------------------------------------------------------------- */

static void drive_store_ctx(OSSL_STORE_LOADER *loader)
{
    OSSL_STORE_CTX *ctx;
    OSSL_STORE_CTX *actx;
    OSSL_STORE_SEARCH *search;
    int secmem = 0;

    (void)loader;

    ctx = OSSL_STORE_open("probe://object", NULL, NULL, NULL, NULL);
    out_ptr("store.open.legacy", ctx);
    out_err("store.open.legacy.err");
    out_int("store.eof", OSSL_STORE_eof(ctx));
    out_int("store.error", OSSL_STORE_error(ctx));
    out_int("store.expect.pkey", OSSL_STORE_expect(ctx, OSSL_STORE_INFO_PKEY));
    out_err("store.expect.pkey.err");
    out_int("store.expect.negative", OSSL_STORE_expect(ctx, -1));
    out_err("store.expect.negative.err");
    out_int("store.expect.too_big", OSSL_STORE_expect(ctx, 7));
    out_err("store.expect.too_big.err");
    out_int("store.supports_search.name",
            OSSL_STORE_supports_search(ctx, OSSL_STORE_SEARCH_BY_NAME));
    out_int("store.supports_search.alias",
            OSSL_STORE_supports_search(ctx, OSSL_STORE_SEARCH_BY_ALIAS));

    search = OSSL_STORE_SEARCH_by_alias("an-alias");
    out_int("store.find.alias", OSSL_STORE_find(ctx, search));
    out_err("store.find.alias.err");
    out_int("store.find.null", OSSL_STORE_find(ctx, NULL));
    out_err("store.find.null.err");
    OSSL_STORE_SEARCH_free(search);

    out_int("store.ctrl.secmem", OSSL_STORE_ctrl(ctx, OSSL_STORE_C_USE_SECMEM, &secmem));
    out_err("store.ctrl.secmem.err");
    out_int("store.vctrl.secmem", call_vctrl(ctx, OSSL_STORE_C_USE_SECMEM, &secmem));
    out_err("store.vctrl.secmem.err");
    out_int("store.close", OSSL_STORE_close(ctx));

    /* The same state machine over `OSSL_STORE_attach`, which takes the BIO form. */
    actx = OSSL_STORE_attach(NULL, "probe", NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    out_ptr("store.attach.legacy", actx);
    out_int("store.attach.eof", OSSL_STORE_eof(actx));
    out_int("store.attach.close", OSSL_STORE_close(actx));

    /* `close(NULL)` is the authority's own `ossl_store_close_it(NULL) == 1`. */
    out_int("store.close.null", OSSL_STORE_close(NULL));
}

/* ---------------------------------------------------------------------------------------------
 * Phase 10.8: the `X509`/`X509_CRL` object core, and the two `OSSL_STORE_INFO` arms it closes.
 *
 * The DER is fixed and embedded (`rt_x509_der.h`), so both sides decode the same bytes. Every
 * observation is a length, a byte-for-byte equality, a nonnull/null or an error coordinate.
 * --------------------------------------------------------------------------------------------- */

static void drive_x509_object_core(void)
{
    const unsigned char *p;
    X509 *cert = NULL;
    X509 *cert2;
    X509_CRL *crl = NULL;
    X509_CRL *crl2;
    unsigned char *der = NULL;
    int len;
    OSSL_STORE_INFO *info;

    /* ----- X509 ----- */
    p = RT_X509_CERT_DER;
    cert = d2i_X509(NULL, &p, (long)RT_X509_CERT_DER_LEN);
    out_ptr("x509.d2i", cert);
    out_err("x509.d2i.err");
    out_int("x509.d2i.consumed", (long)(p - RT_X509_CERT_DER));
    if (cert != NULL) {
        len = i2d_X509(cert, &der);
        out_int("x509.i2d.len", (long)len);
        out_int("x509.i2d.same_bytes",
                len == (int)RT_X509_CERT_DER_LEN
                    && memcmp(der, RT_X509_CERT_DER, (size_t)len) == 0);
        OPENSSL_free(der);
        der = NULL;

        cert2 = X509_dup(cert);
        out_ptr("x509.dup", cert2);
        out_int("x509.dup.distinct", cert2 != NULL && cert2 != cert);
        if (cert2 != NULL) {
            len = i2d_X509(cert2, &der);
            out_int("x509.dup.i2d.same_bytes",
                    len == (int)RT_X509_CERT_DER_LEN
                        && memcmp(der, RT_X509_CERT_DER, (size_t)len) == 0);
            OPENSSL_free(der);
            der = NULL;
            X509_free(cert2);
        }
    }

    /* A one-byte-short decode is the refusal arm, with its coordinate. */
    p = RT_X509_CERT_DER;
    out_ptr("x509.d2i.truncated", d2i_X509(NULL, &p, (long)RT_X509_CERT_DER_LEN - 1));
    out_err("x509.d2i.truncated.err");

    /* ----- X509_CRL ----- */
    p = RT_X509_CRL_DER;
    crl = d2i_X509_CRL(NULL, &p, (long)RT_X509_CRL_DER_LEN);
    out_ptr("crl.d2i", crl);
    out_err("crl.d2i.err");
    out_int("crl.d2i.consumed", (long)(p - RT_X509_CRL_DER));
    if (crl != NULL) {
        len = i2d_X509_CRL(crl, &der);
        out_int("crl.i2d.len", (long)len);
        out_int("crl.i2d.same_bytes",
                len == (int)RT_X509_CRL_DER_LEN
                    && memcmp(der, RT_X509_CRL_DER, (size_t)len) == 0);
        OPENSSL_free(der);
        der = NULL;

        crl2 = X509_CRL_dup(crl);
        out_ptr("crl.dup", crl2);
        out_int("crl.dup.distinct", crl2 != NULL && crl2 != crl);
        X509_CRL_free(crl2);
    }

    p = RT_X509_CRL_DER;
    out_ptr("crl.d2i.truncated", d2i_X509_CRL(NULL, &p, (long)RT_X509_CRL_DER_LEN - 1));
    out_err("crl.d2i.truncated.err");

    /* ----- the CERT/CRL arms of OSSL_STORE_INFO_free, and get1_CERT/get1_CRL ----- */
    if (cert != NULL) {
        X509 *got;

        info = OSSL_STORE_INFO_new_CERT(cert);
        out_ptr("info.new_CERT.real", info);
        out_int("info.get0_CERT.is_cert", OSSL_STORE_INFO_get0_CERT(info) == cert);
        got = OSSL_STORE_INFO_get1_CERT(info);
        out_int("info.get1_CERT.is_cert", got == cert);
        /* Release the copy get1 handed back, then the info's own reference. */
        X509_free(got);
        OSSL_STORE_INFO_free(info);
    }
    if (crl != NULL) {
        X509_CRL *got;

        info = OSSL_STORE_INFO_new_CRL(crl);
        out_ptr("info.new_CRL.real", info);
        out_int("info.get0_CRL.is_crl", OSSL_STORE_INFO_get0_CRL(info) == crl);
        got = OSSL_STORE_INFO_get1_CRL(info);
        out_int("info.get1_CRL.is_crl", got == crl);
        X509_CRL_free(got);
        OSSL_STORE_INFO_free(info);
    }
    out_str("info.free.CERT_CRL_arms", "driven");
}

/* ---------------------------------------------------------------------------------------------
 * Phase 10.10 -- `crypto/x509/x509_obj.c`'s `X509_NAME_oneline`.
 *
 * The DN printer is a byte-exact string producer, so the arms are: a populated name decoded from
 * the authority document's own `Name` bytes, printed into a caller buffer and through the
 * allocating spelling; an empty name; the NULL-name arm; and the zero-length-buffer refusal.
 * No address is printed -- only strings, lengths and `nonnull`/`null`.
 * --------------------------------------------------------------------------------------------- */

/* The `Name` (`RDNSequence`) that RT_X509_CERT_DER carries as both its issuer and its subject:
 *
 *   SEQUENCE { SET { SEQUENCE { OID 2.5.4.3 (commonName), UTF8String "Root CA" } } }
 *
 * It is the authority document's own bytes (certificate offsets 32 and 66), lifted out so this
 * subphase's arms can decode a populated name without an `X509` accessor -- `X509_get_subject_name`
 * is `x509_cmp.c`, which 10.10 does not land. `d2i_X509_NAME` (10.8) decodes it. */
static const unsigned char RT_X509_NAME_DER[] = {
    0x30, 0x12, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03,
    0x55, 0x04, 0x03, 0x0c, 0x07, 0x52, 0x6f, 0x6f,
    0x74, 0x20, 0x43, 0x41,
};
#define RT_X509_NAME_DER_LEN 20

static void drive_name_oneline(void)
{
    const unsigned char *p = RT_X509_NAME_DER;
    X509_NAME *name = d2i_X509_NAME(NULL, &p, (long)RT_X509_NAME_DER_LEN);
    X509_NAME *empty;
    char buf[256];
    char *alloc;

    out_ptr("name.d2i", name);
    out_err("name.d2i.err");
    out_int("name.d2i.consumed", (long)(p - RT_X509_NAME_DER));

    if (name != NULL) {
        memset(buf, 0, sizeof(buf));
        out_str("name.oneline.buf", X509_NAME_oneline(name, buf, (int)sizeof(buf)));
        out_int("name.oneline.buf.len", (long)strlen(buf));

        /* The allocating spelling returns the library's own block; the caller frees it. */
        alloc = X509_NAME_oneline(name, NULL, 0);
        out_ptr("name.oneline.alloc", alloc);
        out_str("name.oneline.alloc.value", alloc);
        OPENSSL_free(alloc);

        /* A non-NULL buffer with no room is a refusal, not a partial render. */
        out_ptr("name.oneline.bufzero", X509_NAME_oneline(name, buf, 0));
        out_err("name.oneline.bufzero.err");
    }

    /* The NULL-name arm. */
    memset(buf, 0, sizeof(buf));
    out_str("name.oneline.noname", X509_NAME_oneline(NULL, buf, (int)sizeof(buf)));
    out_int("name.oneline.noname.len", (long)strlen(buf));

    /* An empty name renders as the empty string through the allocating spelling. */
    empty = X509_NAME_new();
    alloc = X509_NAME_oneline(empty, NULL, 0);
    out_ptr("name.oneline.empty.alloc", alloc);
    out_str("name.oneline.empty.value", alloc);
    OPENSSL_free(alloc);
    X509_NAME_free(empty);

    X509_NAME_free(name);
}

/* ---------------------------------------------------------------------------------------------
 * Phase 10.11 -- `crypto/x509/x509name.c`'s accessors and `crypto/asn1/a_strex.c`'s DN printer.
 *
 * The same populated `Name` as 10.10's block, now read through the convenience accessors (the
 * count, the two index searches, the text lookup with its length-query spelling, the entry and
 * its object/data/set fields) and printed under eight flag sets. `X509_NAME_print_ex` is a
 * byte-exact printer, so each flag set's exact text is the observation; `XN_FLAG_COMPAT` routes
 * through 10.10's `X509_NAME_oneline` and the rest through 10.11's `do_name_ex`.
 * --------------------------------------------------------------------------------------------- */

static void drive_name_print_ex(void)
{
    const unsigned char *p = RT_X509_NAME_DER;
    X509_NAME *name = d2i_X509_NAME(NULL, &p, (long)RT_X509_NAME_DER_LEN);
    BIO *b;
    char text[256];
    int n, i;
    static const struct { const char *k; unsigned long f; } arms[] = {
        { "rfc2253",        XN_FLAG_RFC2253 },
        { "oneline",        XN_FLAG_ONELINE },
        { "multiline",      XN_FLAG_MULTILINE },
        { "compat",         XN_FLAG_COMPAT },
        { "fn_oid",         XN_FLAG_SEP_CPLUS_SPC | XN_FLAG_FN_OID },
        { "fn_none",        XN_FLAG_SEP_CPLUS_SPC | XN_FLAG_FN_NONE },
        { "sep_comma_plus", XN_FLAG_SEP_COMMA_PLUS | XN_FLAG_FN_SN },
        { "sep_splus_spc",  XN_FLAG_SEP_SPLUS_SPC | XN_FLAG_FN_SN },
    };

    out_ptr("name.access.d2i", name);
    if (name == NULL)
        return;

    /* `x509name.c`'s accessors over the populated name. */
    out_int("name.access.count", (long)X509_NAME_entry_count(name));
    out_int("name.access.index.cn", (long)X509_NAME_get_index_by_NID(name, NID_commonName, -1));
    out_int("name.access.index.miss",
            (long)X509_NAME_get_index_by_NID(name, NID_organizationName, -1));
    out_int("name.access.index.badnid", (long)X509_NAME_get_index_by_NID(name, 1000000, -1));
    {
        char buf[128];
        memset(buf, 0, sizeof(buf));
        out_int("name.access.text.len",
                (long)X509_NAME_get_text_by_NID(name, NID_commonName, buf, (int)sizeof(buf)));
        out_str("name.access.text", buf);
        out_int("name.access.text.query",
                (long)X509_NAME_get_text_by_NID(name, NID_commonName, NULL, 0));
        out_int("name.access.text.miss",
                (long)X509_NAME_get_text_by_NID(name, NID_organizationName, buf, (int)sizeof(buf)));
    }
    {
        X509_NAME_ENTRY *ent = X509_NAME_get_entry(name, 0);
        out_ptr("name.access.entry0", ent);
        out_int("name.access.entry0.set", (long)X509_NAME_ENTRY_set(ent));
        out_int("name.access.entry0.obj", (long)OBJ_obj2nid(X509_NAME_ENTRY_get_object(ent)));
        out_int("name.access.entry0.datalen", (long)ASN1_STRING_length(X509_NAME_ENTRY_get_data(ent)));
        out_ptr("name.access.entry1", X509_NAME_get_entry(name, 1));
    }

    /* The byte-exact printer, one memory BIO per flag set. */
    for (i = 0; i < (int)(sizeof(arms) / sizeof(arms[0])); i++) {
        int r;

        b = BIO_new(BIO_s_mem());
        if (b == NULL)
            continue;
        memset(text, 0, sizeof(text));
        n = X509_NAME_print_ex(b, name, 0, arms[i].f);
        r = BIO_read(b, text, (int)sizeof(text) - 1);
        text[r > 0 ? r : 0] = 0;
        printf("name.print.%s.ret=%d\n", arms[i].k, n);
        printf("name.print.%s.text=%s\n", arms[i].k, text);
        BIO_free(b);
    }

    /* The NULL-name arm: no entries, so the printer answers zero through the real sink. */
    b = BIO_new(BIO_s_mem());
    out_int("name.print.noname", (long)X509_NAME_print_ex(b, NULL, 0, XN_FLAG_RFC2253));
    BIO_free(b);

    X509_NAME_free(name);
}

/* ---------------------------------------------------------------------------------------------
 * Phase 10.11 -- `crypto/x509/x509_v3.c`'s extension surface.
 *
 * The X.509v3 extension add/get/count/delete layer is directly observable: create an extension
 * by NID and by OBJ, append duplicates into a caller slot, count, search by NID/OBJ/critical,
 * fetch by index, replace a batch of same-OID extensions, and delete -- printing the returned
 * `nonnull`/`null`, the counts and each refusal's error coordinate. The unknown-NID create and
 * both NULL-target calls are the refusal arms.
 * --------------------------------------------------------------------------------------------- */

static void drive_x509v3_extensions(void)
{
    STACK_OF(X509_EXTENSION) *sk = NULL, *sk2 = NULL;
    ASN1_OCTET_STRING *d1 = ASN1_OCTET_STRING_new();
    ASN1_OCTET_STRING *d2 = ASN1_OCTET_STRING_new();
    X509_EXTENSION *ex1, *ex2, *removed;
    X509_EXTENSION *got;

    if (d1 == NULL || d2 == NULL) {
        out_ptr("v3.setup", NULL);
        return;
    }
    ASN1_OCTET_STRING_set(d1, (const unsigned char *)"BC", 2);
    ASN1_OCTET_STRING_set(d2, (const unsigned char *)"KU", 2);

    /* Create by NID with the critical flag, and read the three fields back. */
    ex1 = X509_EXTENSION_create_by_NID(NULL, NID_basic_constraints, 1, d1);
    out_ptr("v3.create.by_nid", ex1);
    out_err("v3.create.by_nid.err");
    out_int("v3.create.by_nid.crit", (long)X509_EXTENSION_get_critical(ex1));
    out_int("v3.create.by_nid.obj", (long)OBJ_obj2nid(X509_EXTENSION_get_object(ex1)));
    out_int("v3.create.by_nid.datalen", (long)ASN1_STRING_length(X509_EXTENSION_get_data(ex1)));

    /* The unknown-NID refusal and its coordinate. */
    ERR_clear_error();
    out_ptr("v3.create.badnid", X509_EXTENSION_create_by_NID(NULL, 1000000, 0, d1));
    out_err("v3.create.badnid.err");
    ERR_clear_error();

    /* `X509v3_add_ext` builds the stack from a NULL slot and duplicates the caller's extension. */
    sk = X509v3_add_ext(&sk, ex1, -1);
    out_ptr("v3.add_ext.stack", sk);
    out_int("v3.count.one", (long)X509v3_get_ext_count(sk));
    out_int("v3.count.null", (long)X509v3_get_ext_count(NULL));

    /* Create by OBJ, append, and a second extension of a different OID. */
    ex2 = X509_EXTENSION_create_by_OBJ(NULL, OBJ_nid2obj(NID_key_usage), 0, d2);
    out_ptr("v3.create.by_obj", ex2);
    out_int("v3.create.by_obj.crit", (long)X509_EXTENSION_get_critical(ex2));
    sk = X509v3_add_ext(&sk, ex2, -1);
    out_int("v3.count.two", (long)X509v3_get_ext_count(sk));

    /* The three searches, present and absent. */
    out_int("v3.by_nid", (long)X509v3_get_ext_by_NID(sk, NID_basic_constraints, -1));
    out_int("v3.by_nid.miss", (long)X509v3_get_ext_by_NID(sk, NID_subject_key_identifier, -1));
    out_int("v3.by_nid.badnid", (long)X509v3_get_ext_by_NID(sk, 1000000, -1));
    out_int("v3.by_obj", (long)X509v3_get_ext_by_OBJ(sk, X509_EXTENSION_get_object(ex1), -1));
    out_int("v3.by_obj.miss", (long)X509v3_get_ext_by_OBJ(sk, OBJ_nid2obj(NID_authority_key_identifier), -1));
    out_int("v3.by_crit.1", (long)X509v3_get_ext_by_critical(sk, 1, -1));
    out_int("v3.by_crit.0", (long)X509v3_get_ext_by_critical(sk, 0, -1));
    out_int("v3.by_crit.null", (long)X509v3_get_ext_by_critical(NULL, 1, -1));
    out_int("v3.by_obj.null", (long)X509v3_get_ext_by_OBJ(NULL, X509_EXTENSION_get_object(ex1), -1));

    /* Fetch by index, in and out of range, and from a NULL stack. */
    got = X509v3_get_ext(sk, 0);
    out_ptr("v3.get.0", got);
    out_int("v3.get.0.obj", (long)OBJ_obj2nid(X509_EXTENSION_get_object(got)));
    out_ptr("v3.get.5", X509v3_get_ext(sk, 5));
    out_ptr("v3.get.null", X509v3_get_ext(NULL, 0));

    /* A NULL target slot is the refusal `X509v3_add_ext` and `X509v3_add_extensions` share. */
    ERR_clear_error();
    out_ptr("v3.add_ext.null_target", X509v3_add_ext(NULL, ex1, -1));
    out_err("v3.add_ext.null_target.err");
    ERR_clear_error();

    /* `X509v3_add_extensions` replaces same-OID entries: the batch stays at two. */
    sk2 = X509v3_add_extensions(&sk2, sk);
    out_ptr("v3.add_extensions", sk2);
    out_int("v3.add_extensions.count", (long)X509v3_get_ext_count(sk2));
    ERR_clear_error();
    out_ptr("v3.add_extensions.null_target", X509v3_add_extensions(NULL, sk));
    out_err("v3.add_extensions.null_target.err");
    ERR_clear_error();

    /* `X509v3_delete_ext` returns the removed element and drops the count. */
    removed = X509v3_delete_ext(sk, 0);
    out_ptr("v3.delete.0", removed);
    out_int("v3.count.after_delete", (long)X509v3_get_ext_count(sk));
    out_ptr("v3.delete.5", X509v3_delete_ext(sk, 5));
    out_ptr("v3.delete.null", X509v3_delete_ext(NULL, 0));

    X509_EXTENSION_free(removed);
    X509_EXTENSION_free(ex1);
    X509_EXTENSION_free(ex2);
    sk_X509_EXTENSION_free(sk);
    sk_X509_EXTENSION_free(sk2);
    ASN1_OCTET_STRING_free(d1);
    ASN1_OCTET_STRING_free(d2);
}

/* ---------------------------------------------------------------------------------------------
 * A whole block of what this pass withholds, printed identically on both sides.
 * --------------------------------------------------------------------------------------------- */

static void out_pending(void)
{
    printf("pending.OSSL_STORE_LOADER_fetch=file_store_provider_row_unpublished\n");
    printf("pending.OSSL_STORE_LOADER_do_all_provided=file_store_provider_row_unpublished\n");
    printf("pending.OSSL_STORE_load=store_result_ossl_store_handle_load_result\n");
    printf("pending.OSSL_STORE_find.by_name=file_store_provider_row_unpublished\n");
    printf("pending.OSSL_STORE_find.by_issuer_serial=file_store_provider_row_unpublished\n");
}

/* ---------------------------------------------------------------------------------------------
 * Phase 10.9 -- the engine registry (`crypto/engine/`), the digest substrate
 * `X509_digest` reaches through `ossl_asn1_item_digest_ex`.
 *
 * The fetch/lookup surface is driven directly: the object lifecycle (`ENGINE_new`/`_free`),
 * the element accessors, ex_data, the linked list (`ENGINE_add`/`_get_first`/`_get_next`/
 * `_remove`), the table flags, and the digest registration/select pair the digest path uses.
 * Every observation is a return code, a `nonnull`/`null`, or a string the library owns; no
 * pointer address is printed, and the whole `ENGINE` object is released before the probe ends.
 * --------------------------------------------------------------------------------------------- */

/* An engine `digests` callback over one made-up nid, so the table arm registers something that
 * collides with no real algorithm; `md != NULL` is the fetch form, `md == NULL` the list form. */
static const int g_engine_digest_nids[1] = { 0x7ffffff0 };

static int engine_digests_cb(ENGINE *e, const EVP_MD **md, const int **nids, int nid)
{
    (void)e;
    if (md == NULL) {
        if (nids != NULL)
            *nids = g_engine_digest_nids;
        return 1;
    }
    if (nid == g_engine_digest_nids[0]) {
        *md = EVP_sha256();
        return 1;
    }
    return 0;
}

static void drive_engine_registry(void)
{
    ENGINE *e, *g, *sel, *it;
    int found;
    int sentinel = 0;

    out_int("engine.table_flags.initial", (long)ENGINE_get_table_flags());
    ENGINE_set_table_flags(ENGINE_TABLE_FLAG_NOINIT);
    out_int("engine.table_flags.set", (long)ENGINE_get_table_flags());
    ENGINE_set_table_flags(0);

    out_ptr("engine.static_state", ENGINE_get_static_state());

    e = ENGINE_new();
    out_ptr("engine.new", e);
    out_str("engine.get_id.unset", ENGINE_get_id(e));
    out_int("engine.get_flags", ENGINE_get_flags(e));
    out_int("engine.set_id", ENGINE_set_id(e, "probe-engine"));
    out_str("engine.get_id", ENGINE_get_id(e));
    out_int("engine.set_name", ENGINE_set_name(e, "probe engine"));
    out_str("engine.get_name", ENGINE_get_name(e));
    out_int("engine.set_id.null", ENGINE_set_id(e, NULL));
    out_err("engine.set_id.null.err");

    out_int("engine.set_ex_data", ENGINE_set_ex_data(e, 0, &sentinel));
    out_int("engine.get_ex_data.same", ENGINE_get_ex_data(e, 0) == (void *)&sentinel);

    out_ptr("engine.get_digest_engine.unregistered",
            ENGINE_get_digest_engine(g_engine_digest_nids[0]));
    out_int("engine.set_digests", ENGINE_set_digests(e, engine_digests_cb));
    out_int("engine.get_digests.same", ENGINE_get_digests(e) == engine_digests_cb);
    out_int("engine.register_digests", ENGINE_register_digests(e));
    sel = ENGINE_get_digest_engine(g_engine_digest_nids[0]);
    out_ptr("engine.get_digest_engine.registered", sel);
    out_int("engine.get_digest_engine.is_same", sel == e);
    out_int("engine.finish", ENGINE_finish(sel));
    ENGINE_unregister_digests(e);
    out_int("engine.free", ENGINE_free(e));

    g = ENGINE_new();
    ENGINE_set_id(g, "probe-listed");
    ENGINE_set_name(g, "probe listed");
    out_int("engine.add", ENGINE_add(g));
    found = 0;
    for (it = ENGINE_get_first(); it != NULL; it = ENGINE_get_next(it)) {
        const char *id = ENGINE_get_id(it);
        if (id != NULL && strcmp(id, "probe-listed") == 0)
            found = 1;
    }
    out_int("engine.listed.found", found);
    out_int("engine.remove", ENGINE_remove(g));
    out_int("engine.free.listed", ENGINE_free(g));

    out_int("engine.finish.null", ENGINE_finish(NULL));
    out_int("engine.free.null", ENGINE_free(NULL));
}

/* ---------------------------------------------------------------------------------------------
 * Phase 10.12 -- the leaf extension items, the `X509_AUX` layer, the policy accessors and the
 * `X509_verify_cert_error_string` table.
 *
 * Every arm compares bytes or an integer/string against the same computation on the authority, so
 * the transcript is the authority's own answers. The certificate suffixes are byte-exact: the
 * `X509_AUX` round trip sets an alias and a key id, encodes, decodes and compares the re-encoded
 * bytes. The policy accessors have no live tree to read (building one needs `X509_policy_check`,
 * 10.14), so each is driven through its NULL-input guard, which the authority's own code makes
 * observable. The `v3_pcia`/`v3_ist` items and the `v3_ia5`/`v3_skid` string helpers are driven
 * through their public surfaces.
 *
 * What it cannot drive, and therefore does not print: the `v3_*` extension tables
 * (`ossl_v3_*`), the `v3_ist` callbacks, and `pcy_node.c`'s six `ossl_policy_*` operations -- all
 * internal symbols the admitted DSO does not export, so no differential arm can name them. Each is
 * recorded as a withhold in its module's doc, not as a `pending.` line here.
 * --------------------------------------------------------------------------------------------- */

static void drive_x509_leaf_units(void)
{
    static const unsigned char want_alias[11] = "probe-alias";
    static const unsigned char want_keyid[4] = { 0x01, 0x02, 0x03, 0x04 };
    const unsigned char *p;
    X509 *cert, *cert2, *plain;
    X509_CERT_AUX *aux, *aux2;
    X509_POLICY_TREE *tree = NULL;
    X509_POLICY_LEVEL *level = NULL;
    X509_POLICY_NODE *node = NULL;
    PROXY_POLICY *pp, *pp2;
    PROXY_CERT_INFO_EXTENSION *pcie, *pcie2;
    ISSUER_SIGN_TOOL *ist, *ist2;
    ASN1_OCTET_STRING *oct, *oct2;
    ASN1_IA5STRING *ia5;
    char *s;
    unsigned char *der = NULL, *der2 = NULL;
    int len, alen = -1, klen = -1;

    /* ----- X509_AUX: set, encode, decode, compare ----- */
    p = RT_X509_CERT_DER;
    cert = d2i_X509(NULL, &p, (long)RT_X509_CERT_DER_LEN);
    out_ptr("aux.cert", cert);
    if (cert != NULL) {
        out_int("aux.trusted.before", X509_trusted(cert));
        out_ptr("aux.alias.before", X509_alias_get0(cert, &alen));
        out_int("aux.alias.before.len", (long)alen);
        out_int("aux.alias.set", X509_alias_set1(cert, want_alias, 11));
        out_int("aux.keyid.set", X509_keyid_set1(cert, want_keyid, 4));
        out_int("aux.trusted.after", X509_trusted(cert));
        out_int("aux.alias.len", (long)(X509_alias_get0(cert, &alen), alen));
        out_int("aux.keyid.len", (long)(X509_keyid_get0(cert, &klen), klen));
        out_int("aux.keyid.byte0", (long)X509_keyid_get0(cert, NULL)[0]);

        len = i2d_X509_AUX(cert, &der);
        out_int("aux.i2d.len", (long)len);
        out_int("aux.i2d.gt_plain", len > i2d_X509(cert, NULL));

        p = der;
        cert2 = d2i_X509_AUX(NULL, &p, (long)len);
        out_ptr("aux.d2i", cert2);
        out_err("aux.d2i.err");
        out_int("aux.d2i.consumed", (long)(p - der));
        if (cert2 != NULL) {
            out_int("aux.d2i.trusted", X509_trusted(cert2));
            out_int("aux.d2i.alias.len", (long)(X509_alias_get0(cert2, &alen), alen));
            out_int("aux.d2i.alias.bytes",
                    alen == 11 && memcmp(X509_alias_get0(cert2, NULL), want_alias, 11) == 0);
            out_int("aux.d2i.keyid.len", (long)(X509_keyid_get0(cert2, &klen), klen));
            out_int("aux.d2i.keyid.bytes",
                    klen == 4 && memcmp(X509_keyid_get0(cert2, NULL), want_keyid, 4) == 0);
            out_int("aux.d2i.reequal",
                    i2d_X509_AUX(cert2, &der2) == len
                        && der2 != NULL && memcmp(der, der2, (size_t)len) == 0);
            out_err("aux.d2i.reequal.err");
            OPENSSL_free(der2); der2 = NULL;
            X509_free(cert2);
        }
        OPENSSL_free(der); der = NULL;

        /* The clear arms: both succeed on a certificate that has the field. */
        X509_trust_clear(cert);
        X509_reject_clear(cert);
        out_str("aux.cleared", "ok");
    }

    /* d2i_X509_AUX over a plain certificate: the suffix is absent, so the prefix is consumed. */
    p = RT_X509_CERT_DER;
    plain = d2i_X509_AUX(NULL, &p, (long)RT_X509_CERT_DER_LEN);
    out_ptr("aux.d2i.plain", plain);
    out_int("aux.d2i.plain.consumed", (long)(p - RT_X509_CERT_DER));
    X509_free(plain);

    /* The NULL-name clear arms answer 1 without a certificate. */
    out_int("aux.alias.set.null", X509_alias_set1(NULL, NULL, 0));
    out_int("aux.keyid.set.null", X509_keyid_set1(NULL, NULL, 0));

    /* The truncated decode refuses, with its coordinate. */
    p = RT_X509_CERT_DER;
    out_ptr("aux.d2i.truncated", d2i_X509_AUX(NULL, &p, (long)RT_X509_CERT_DER_LEN - 1));
    out_err("aux.d2i.truncated.err");

    /* ----- the X509_CERT_AUX item itself, over an empty value ----- */
    aux = X509_CERT_AUX_new();
    out_ptr("certaux.new", aux);
    if (aux != NULL) {
        len = i2d_X509_CERT_AUX(aux, &der);
        out_int("certaux.i2d.len", (long)len);
        p = der;
        aux2 = d2i_X509_CERT_AUX(NULL, &p, (long)len);
        out_ptr("certaux.d2i", aux2);
        out_int("certaux.d2i.consumed", (long)(p - der));
        out_int("certaux.reequal",
                i2d_X509_CERT_AUX(aux2, &der2) == len
                    && der2 != NULL && memcmp(der, der2, (size_t)len) == 0);
        OPENSSL_free(der2); der2 = NULL;
        OPENSSL_free(der); der = NULL;
        X509_CERT_AUX_free(aux2);
        X509_CERT_AUX_free(aux);
    }

    /* ----- X509_verify_cert_error_string (x509_txt.c) ----- */
    out_str("cert_err.ok", X509_verify_cert_error_string(0));
    out_str("cert_err.not_yet", X509_verify_cert_error_string(9));
    out_str("cert_err.expired", X509_verify_cert_error_string(10));
    out_str("cert_err.ca_bcons", X509_verify_cert_error_string(89));
    out_str("cert_err.rpk", X509_verify_cert_error_string(95));
    out_str("cert_err.crl_verify", X509_verify_cert_error_string(101));
    out_str("cert_err.unknown", X509_verify_cert_error_string(9999));

    /* ----- the policy accessors (pcy_lib.c), through their NULL guards ----- */
    out_int("pcy.tree.levels.null", X509_policy_tree_level_count(tree));
    out_ptr("pcy.tree.level0.null", X509_policy_tree_get0_level(tree, 0));
    out_ptr("pcy.tree.policies.null", X509_policy_tree_get0_policies(tree));
    out_ptr("pcy.tree.user_policies.null", X509_policy_tree_get0_user_policies(tree));
    out_int("pcy.level.nodes.null", X509_policy_level_node_count(level));
    out_ptr("pcy.level.node0.null", X509_policy_level_get0_node(level, 0));
    out_ptr("pcy.node.policy.null", X509_policy_node_get0_policy(node));
    out_ptr("pcy.node.qualifiers.null", X509_policy_node_get0_qualifiers(node));
    out_ptr("pcy.node.parent.null", X509_policy_node_get0_parent(node));

    /* ----- the RFC 3820 items (v3_pcia.c) ----- */
    pp = PROXY_POLICY_new();
    out_ptr("pcia.pp.new", pp);
    if (pp != NULL) {
        ASN1_OBJECT_free(pp->policyLanguage);
        pp->policyLanguage = OBJ_txt2obj("1.2.3.4", 1);
        pp->policy = ASN1_OCTET_STRING_new();
        ASN1_OCTET_STRING_set(pp->policy, (const unsigned char *)"pol", 3);
        len = i2d_PROXY_POLICY(pp, &der);
        out_int("pcia.pp.i2d.len", (long)len);
        p = der;
        pp2 = d2i_PROXY_POLICY(NULL, &p, (long)len);
        out_ptr("pcia.pp.d2i", pp2);
        out_int("pcia.pp.d2i.consumed", (long)(p - der));
        out_int("pcia.pp.reequal",
                i2d_PROXY_POLICY(pp2, &der2) == len
                    && der2 != NULL && memcmp(der, der2, (size_t)len) == 0);
        OPENSSL_free(der2); der2 = NULL;
        OPENSSL_free(der); der = NULL;
        PROXY_POLICY_free(pp2);
        PROXY_POLICY_free(pp);
    }

    pcie = PROXY_CERT_INFO_EXTENSION_new();
    out_ptr("pcia.pcie.new", pcie);
    if (pcie != NULL) {
        ASN1_OBJECT_free(pcie->proxyPolicy->policyLanguage);
        pcie->proxyPolicy->policyLanguage = OBJ_txt2obj("1.2.3.4", 1);
        len = i2d_PROXY_CERT_INFO_EXTENSION(pcie, &der);
        out_int("pcia.pcie.i2d.len", (long)len);
        p = der;
        pcie2 = d2i_PROXY_CERT_INFO_EXTENSION(NULL, &p, (long)len);
        out_ptr("pcia.pcie.d2i", pcie2);
        out_int("pcia.pcie.reequal",
                i2d_PROXY_CERT_INFO_EXTENSION(pcie2, &der2) == len
                    && der2 != NULL && memcmp(der, der2, (size_t)len) == 0);
        OPENSSL_free(der2); der2 = NULL;
        OPENSSL_free(der); der = NULL;
        PROXY_CERT_INFO_EXTENSION_free(pcie2);
        PROXY_CERT_INFO_EXTENSION_free(pcie);
    }

    /* ----- the octet-string helpers (v3_skid.c) ----- */
    oct = ASN1_OCTET_STRING_new();
    ASN1_OCTET_STRING_set(oct, want_keyid, 4);
    s = i2s_ASN1_OCTET_STRING(NULL, oct);
    out_str("skid.i2s.octet", s);
    OPENSSL_free(s);
    ASN1_OCTET_STRING_free(oct);

    oct2 = s2i_ASN1_OCTET_STRING(NULL, NULL, "01:02:03:04");
    out_ptr("skid.s2i.octet", oct2);
    s = i2s_ASN1_OCTET_STRING(NULL, oct2);
    out_str("skid.s2i.octet.hex", s);
    OPENSSL_free(s);
    ASN1_OCTET_STRING_free(oct2);

    out_ptr("skid.s2i.octet.bad", s2i_ASN1_OCTET_STRING(NULL, NULL, "nonsense"));
    out_err("skid.s2i.octet.bad.err");

    /* ----- the IA5 helpers (v3_ia5.c) ----- */
    ia5 = s2i_ASN1_IA5STRING(NULL, NULL, "probe.test");
    out_ptr("ia5.s2i", ia5);
    s = i2s_ASN1_IA5STRING(NULL, ia5);
    out_str("ia5.i2s", s);
    OPENSSL_free(s);
    ASN1_IA5STRING_free(ia5);

    ia5 = ASN1_IA5STRING_new();
    out_ptr("ia5.i2s.empty", i2s_ASN1_IA5STRING(NULL, ia5));
    ASN1_IA5STRING_free(ia5);
    out_ptr("ia5.s2i.null", s2i_ASN1_IA5STRING(NULL, NULL, NULL));
    out_err("ia5.s2i.null.err");

    /* ----- the Issuer Sign Tool item (v3_ist.c) ----- */
    ist = ISSUER_SIGN_TOOL_new();
    out_ptr("ist.new", ist);
    if (ist != NULL) {
        ASN1_STRING_set(ist->signTool, "tool", 4);
        ASN1_STRING_set(ist->cATool, "ca", 2);
        ASN1_STRING_set(ist->signToolCert, "toolcert", 8);
        ASN1_STRING_set(ist->cAToolCert, "cacert", 6);
        len = i2d_ISSUER_SIGN_TOOL(ist, &der);
        out_int("ist.i2d.len", (long)len);
        p = der;
        ist2 = d2i_ISSUER_SIGN_TOOL(NULL, &p, (long)len);
        out_ptr("ist.d2i", ist2);
        out_int("ist.reequal",
                i2d_ISSUER_SIGN_TOOL(ist2, &der2) == len
                    && der2 != NULL && memcmp(der, der2, (size_t)len) == 0);
        OPENSSL_free(der2); der2 = NULL;
        OPENSSL_free(der); der = NULL;
        ISSUER_SIGN_TOOL_free(ist2);
        ISSUER_SIGN_TOOL_free(ist);
    }
}

/* ---------------------------------------------------------------------------------------------
 * Phase 10.13 -- the remaining leaf extension items (`v3_timespec.c`, `v3_pku.c`, `v3_utf8.c`)
 * and the extension registration surface (`v3_lib.c`).
 *
 * Each item is built through its public `_new` and structure fields, encoded, decoded and
 * re-encoded; the byte comparison is the observation. Every arm pops the error queue first
 * (D455's lesson: an error-coordinate claim is only as good as the queue state it is read from).
 * The `v3_lib` lookup half (`X509V3_EXT_get_nid`/`_get`) is withheld, so no arm names it; only
 * the registration half is driven. Every `ASN1_CHOICE` here is driven through its non-`SET OF`
 * arm (bit strings and `ASN1_NULL`), so the arms need no stack construction.
 * --------------------------------------------------------------------------------------------- */

/* The two probe-declared methods the registration half is driven with. `ext_nid` is `NID_undef`
 * (0); the list is `-1`-terminated. Neither is dynamic, so `X509V3_EXT_cleanup` frees nothing but
 * the list itself, exactly as the authority's own static tables are handled. */
static X509V3_EXT_METHOD probe_method = { NID_undef, 0, NULL, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, NULL };
static X509V3_EXT_METHOD probe_method_list[] = {
    { NID_undef, 0, NULL, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, NULL },
    { -1, 0, NULL, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, NULL },
};

/* Encode `value`, decode the bytes, re-encode and compare. `T` is the value's type. */
#define RT_ROUNDTRIP(tag, T, value, i2dfn, d2ifn, freefn)                  \
    do {                                                                   \
        unsigned char *d1_ = NULL, *d2_ = NULL;                            \
        const unsigned char *pp_;                                          \
        int l1_, l2_;                                                      \
        T *v2_;                                                            \
        ERR_clear_error();                                                 \
        l1_ = i2dfn((value), &d1_);                                        \
        out_int(tag ".i2d.len", (long)l1_);                                \
        ERR_clear_error();                                                 \
        pp_ = d1_;                                                         \
        v2_ = (l1_ > 0) ? d2ifn(NULL, &pp_, (long)l1_) : NULL;             \
        out_ptr(tag ".d2i", v2_);                                          \
        out_int(tag ".consumed", (long)(pp_ - d1_));                       \
        ERR_clear_error();                                                 \
        l2_ = (v2_ != NULL) ? i2dfn(v2_, &d2_) : -1;                       \
        out_int(tag ".reequal",                                            \
                (l1_ > 0 && l2_ == l1_ && d2_ != NULL                         \
                 && memcmp(d1_, d2_, (size_t)l1_) == 0));                  \
        OPENSSL_free(d2_);                                                 \
        if (v2_ != NULL)                                                   \
            freefn(v2_);                                                   \
        OPENSSL_free(d1_);                                                 \
    } while (0)

static void drive_x509_10_13_items(void)
{
    PKEY_USAGE_PERIOD *pup;
    OSSL_DAY_TIME *dt;
    OSSL_DAY_TIME_BAND *band;
    OSSL_TIME_SPEC_ABSOLUTE *absolute;
    OSSL_NAMED_DAY *nd;
    OSSL_TIME_SPEC_X_DAY_OF *xdo;
    OSSL_TIME_SPEC_DAY *day;
    OSSL_TIME_SPEC_WEEKS *weeks;
    OSSL_TIME_SPEC_MONTH *months;
    OSSL_TIME_PERIOD *period;
    OSSL_TIME_SPEC_TIME *tst;
    OSSL_TIME_SPEC *ts;
    ASN1_UTF8STRING *u8;
    char *s;

    /* ----- PKEY_USAGE_PERIOD (v3_pku.c) ----- */
    pup = PKEY_USAGE_PERIOD_new();
    out_ptr("pku.new", pup);
    if (pup != NULL) {
        pup->notBefore = ASN1_GENERALIZEDTIME_new();
        ASN1_GENERALIZEDTIME_set_string(pup->notBefore, "20260102030405Z");
        pup->notAfter = ASN1_GENERALIZEDTIME_new();
        ASN1_GENERALIZEDTIME_set_string(pup->notAfter, "20270102030405Z");
        RT_ROUNDTRIP("pku", PKEY_USAGE_PERIOD, pup, i2d_PKEY_USAGE_PERIOD,
                     d2i_PKEY_USAGE_PERIOD, PKEY_USAGE_PERIOD_free);
        PKEY_USAGE_PERIOD_free(pup);
    }

    /* ----- OSSL_DAY_TIME (v3_timespec.c) ----- */
    dt = OSSL_DAY_TIME_new();
    out_ptr("timespec.day.new", dt);
    if (dt != NULL) {
        dt->hour = ASN1_INTEGER_new();
        ASN1_INTEGER_set(dt->hour, 12);
        dt->minute = ASN1_INTEGER_new();
        ASN1_INTEGER_set(dt->minute, 30);
        dt->second = ASN1_INTEGER_new();
        ASN1_INTEGER_set(dt->second, 45);
        RT_ROUNDTRIP("timespec.day", OSSL_DAY_TIME, dt, i2d_OSSL_DAY_TIME,
                     d2i_OSSL_DAY_TIME, OSSL_DAY_TIME_free);
        OSSL_DAY_TIME_free(dt);
    }

    /* ----- OSSL_DAY_TIME_BAND ----- */
    band = OSSL_DAY_TIME_BAND_new();
    out_ptr("timespec.band.new", band);
    if (band != NULL) {
        band->startDayTime = OSSL_DAY_TIME_new();
        band->startDayTime->hour = ASN1_INTEGER_new();
        ASN1_INTEGER_set(band->startDayTime->hour, 9);
        band->endDayTime = OSSL_DAY_TIME_new();
        band->endDayTime->hour = ASN1_INTEGER_new();
        ASN1_INTEGER_set(band->endDayTime->hour, 17);
        RT_ROUNDTRIP("timespec.band", OSSL_DAY_TIME_BAND, band,
                     i2d_OSSL_DAY_TIME_BAND, d2i_OSSL_DAY_TIME_BAND,
                     OSSL_DAY_TIME_BAND_free);
        OSSL_DAY_TIME_BAND_free(band);
    }

    /* ----- OSSL_TIME_SPEC_ABSOLUTE ----- */
    absolute = OSSL_TIME_SPEC_ABSOLUTE_new();
    out_ptr("timespec.absolute.new", absolute);
    if (absolute != NULL) {
        absolute->startTime = ASN1_GENERALIZEDTIME_new();
        ASN1_GENERALIZEDTIME_set_string(absolute->startTime, "20260101000000Z");
        absolute->endTime = ASN1_GENERALIZEDTIME_new();
        ASN1_GENERALIZEDTIME_set_string(absolute->endTime, "20261231235959Z");
        RT_ROUNDTRIP("timespec.absolute", OSSL_TIME_SPEC_ABSOLUTE, absolute,
                     i2d_OSSL_TIME_SPEC_ABSOLUTE, d2i_OSSL_TIME_SPEC_ABSOLUTE,
                     OSSL_TIME_SPEC_ABSOLUTE_free);
        OSSL_TIME_SPEC_ABSOLUTE_free(absolute);
    }

    /* ----- OSSL_NAMED_DAY, BIT arm ----- */
    nd = OSSL_NAMED_DAY_new();
    out_ptr("timespec.namedday.new", nd);
    if (nd != NULL) {
        nd->type = OSSL_NAMED_DAY_TYPE_BIT;
        nd->choice.bitNamedDays = ASN1_BIT_STRING_new();
        ASN1_BIT_STRING_set_bit(nd->choice.bitNamedDays, OSSL_NAMED_DAY_BIT_WED, 1);
        ASN1_BIT_STRING_set_bit(nd->choice.bitNamedDays, OSSL_NAMED_DAY_BIT_SAT, 1);
        RT_ROUNDTRIP("timespec.namedday", OSSL_NAMED_DAY, nd, i2d_OSSL_NAMED_DAY,
                     d2i_OSSL_NAMED_DAY, OSSL_NAMED_DAY_free);
        OSSL_NAMED_DAY_free(nd);
    }

    /* ----- OSSL_TIME_SPEC_X_DAY_OF, FIRST arm over a BIT-armed named day ----- */
    xdo = OSSL_TIME_SPEC_X_DAY_OF_new();
    out_ptr("timespec.xdayof.new", xdo);
    if (xdo != NULL) {
        xdo->type = OSSL_TIME_SPEC_X_DAY_OF_FIRST;
        xdo->choice.first = OSSL_NAMED_DAY_new();
        xdo->choice.first->type = OSSL_NAMED_DAY_TYPE_BIT;
        xdo->choice.first->choice.bitNamedDays = ASN1_BIT_STRING_new();
        ASN1_BIT_STRING_set_bit(xdo->choice.first->choice.bitNamedDays, OSSL_NAMED_DAY_BIT_SUN, 1);
        RT_ROUNDTRIP("timespec.xdayof", OSSL_TIME_SPEC_X_DAY_OF, xdo,
                     i2d_OSSL_TIME_SPEC_X_DAY_OF, d2i_OSSL_TIME_SPEC_X_DAY_OF,
                     OSSL_TIME_SPEC_X_DAY_OF_free);
        OSSL_TIME_SPEC_X_DAY_OF_free(xdo);
    }

    /* ----- OSSL_TIME_SPEC_DAY, BIT arm ----- */
    day = OSSL_TIME_SPEC_DAY_new();
    out_ptr("timespec.dayspec.new", day);
    if (day != NULL) {
        day->type = OSSL_TIME_SPEC_DAY_TYPE_BIT;
        day->choice.bitDay = ASN1_BIT_STRING_new();
        ASN1_BIT_STRING_set_bit(day->choice.bitDay, OSSL_TIME_SPEC_DAY_BIT_FRI, 1);
        RT_ROUNDTRIP("timespec.dayspec", OSSL_TIME_SPEC_DAY, day,
                     i2d_OSSL_TIME_SPEC_DAY, d2i_OSSL_TIME_SPEC_DAY,
                     OSSL_TIME_SPEC_DAY_free);
        OSSL_TIME_SPEC_DAY_free(day);
    }

    /* ----- OSSL_TIME_SPEC_WEEKS, ALL arm ----- */
    weeks = OSSL_TIME_SPEC_WEEKS_new();
    out_ptr("timespec.weeks.new", weeks);
    if (weeks != NULL) {
        weeks->type = OSSL_TIME_SPEC_WEEKS_TYPE_ALL;
        weeks->choice.allWeeks = ASN1_NULL_new();
        RT_ROUNDTRIP("timespec.weeks", OSSL_TIME_SPEC_WEEKS, weeks,
                     i2d_OSSL_TIME_SPEC_WEEKS, d2i_OSSL_TIME_SPEC_WEEKS,
                     OSSL_TIME_SPEC_WEEKS_free);
        OSSL_TIME_SPEC_WEEKS_free(weeks);
    }

    /* ----- OSSL_TIME_SPEC_MONTH, ALL arm ----- */
    months = OSSL_TIME_SPEC_MONTH_new();
    out_ptr("timespec.months.new", months);
    if (months != NULL) {
        months->type = OSSL_TIME_SPEC_MONTH_TYPE_ALL;
        months->choice.allMonths = ASN1_NULL_new();
        RT_ROUNDTRIP("timespec.months", OSSL_TIME_SPEC_MONTH, months,
                     i2d_OSSL_TIME_SPEC_MONTH, d2i_OSSL_TIME_SPEC_MONTH,
                     OSSL_TIME_SPEC_MONTH_free);
        OSSL_TIME_SPEC_MONTH_free(months);
    }

    /* ----- OSSL_TIME_PERIOD, with a BIT-armed day ----- */
    period = OSSL_TIME_PERIOD_new();
    out_ptr("timespec.period.new", period);
    if (period != NULL) {
        period->days = OSSL_TIME_SPEC_DAY_new();
        period->days->type = OSSL_TIME_SPEC_DAY_TYPE_BIT;
        period->days->choice.bitDay = ASN1_BIT_STRING_new();
        ASN1_BIT_STRING_set_bit(period->days->choice.bitDay, OSSL_TIME_SPEC_DAY_BIT_MON, 1);
        RT_ROUNDTRIP("timespec.period", OSSL_TIME_PERIOD, period,
                     i2d_OSSL_TIME_PERIOD, d2i_OSSL_TIME_PERIOD,
                     OSSL_TIME_PERIOD_free);
        OSSL_TIME_PERIOD_free(period);
    }

    /* ----- OSSL_TIME_SPEC_TIME, ABSOLUTE arm ----- */
    tst = OSSL_TIME_SPEC_TIME_new();
    out_ptr("timespec.tst.new", tst);
    if (tst != NULL) {
        tst->type = OSSL_TIME_SPEC_TIME_TYPE_ABSOLUTE;
        tst->choice.absolute = OSSL_TIME_SPEC_ABSOLUTE_new();
        tst->choice.absolute->startTime = ASN1_GENERALIZEDTIME_new();
        ASN1_GENERALIZEDTIME_set_string(tst->choice.absolute->startTime, "20260304050607Z");
        RT_ROUNDTRIP("timespec.tst", OSSL_TIME_SPEC_TIME, tst,
                     i2d_OSSL_TIME_SPEC_TIME, d2i_OSSL_TIME_SPEC_TIME,
                     OSSL_TIME_SPEC_TIME_free);
        OSSL_TIME_SPEC_TIME_free(tst);
    }

    /* ----- OSSL_TIME_SPEC, with a time-zone and notThisTime ----- */
    ts = OSSL_TIME_SPEC_new();
    out_ptr("timespec.ts.new", ts);
    if (ts != NULL) {
        ts->time = OSSL_TIME_SPEC_TIME_new();
        ts->time->type = OSSL_TIME_SPEC_TIME_TYPE_ABSOLUTE;
        ts->time->choice.absolute = OSSL_TIME_SPEC_ABSOLUTE_new();
        ts->time->choice.absolute->startTime = ASN1_GENERALIZEDTIME_new();
        ASN1_GENERALIZEDTIME_set_string(ts->time->choice.absolute->startTime,
                                        "20260708091011Z");
        ts->notThisTime = 0;
        ts->timeZone = ASN1_INTEGER_new();
        ASN1_INTEGER_set(ts->timeZone, 2);
        RT_ROUNDTRIP("timespec.ts", OSSL_TIME_SPEC, ts, i2d_OSSL_TIME_SPEC,
                     d2i_OSSL_TIME_SPEC, OSSL_TIME_SPEC_free);
        OSSL_TIME_SPEC_free(ts);
    }

    /* ----- the UTF-8 helpers (v3_utf8.c) ----- */
    ERR_clear_error();
    u8 = s2i_ASN1_UTF8STRING(NULL, NULL, "probe.utf8");
    out_ptr("utf8.s2i", u8);
    s = i2s_ASN1_UTF8STRING(NULL, u8);
    out_str("utf8.i2s", s);
    OPENSSL_free(s);
    ASN1_UTF8STRING_free(u8);

    ERR_clear_error();
    u8 = ASN1_UTF8STRING_new();
    out_ptr("utf8.i2s.empty", i2s_ASN1_UTF8STRING(NULL, u8));
    out_err("utf8.i2s.empty.err");
    ASN1_UTF8STRING_free(u8);

    ERR_clear_error();
    out_ptr("utf8.s2i.null", s2i_ASN1_UTF8STRING(NULL, NULL, NULL));
    out_err("utf8.s2i.null.err");

    /* ----- the registration half of v3_lib.c ----- */
    ERR_clear_error();
    out_int("v3lib.add_standard", (long)X509V3_add_standard_extensions());
    out_err("v3lib.add_standard.err");

    ERR_clear_error();
    out_int("v3lib.add", (long)X509V3_EXT_add(&probe_method));
    out_err("v3lib.add.err");
    ERR_clear_error();
    out_int("v3lib.add_again", (long)X509V3_EXT_add(&probe_method));
    out_err("v3lib.add_again.err");

    ERR_clear_error();
    out_int("v3lib.add_list", (long)X509V3_EXT_add_list(probe_method_list));
    out_err("v3lib.add_list.err");

    X509V3_EXT_cleanup();
    out_str("v3lib.cleanup", "ok");
}

/* ---------------------------------------------------------------------------------------------
 * Phase 10.14.1 -- `crypto/x509/x509_cmp.c`, `x509cset.c` and `x509type.c`.
 *
 * The certificate comparison and accessor surface. Both fixed documents are decoded twice, so
 * the comparisons have a distinct-but-equal object and a self-argument; the name block from
 * 10.10 supplies a second `X509_NAME`. The CRL carries fourteen revoked entries, so the
 * `X509_REVOKED` accessors are reachable. Every arm pops its own error queue first (D455's
 * lesson); the Suite-B arms pin the static `check_suite_b` through the two public entry points
 * with a NULL key (the RSA leaf) and a real one.
 * --------------------------------------------------------------------------------------------- */

static void drive_x509_cmp_surface(void)
{
    const unsigned char *p;
    X509 *cert = NULL, *cert2 = NULL, *fresh = NULL;
    X509_CRL *crl = NULL, *crl2 = NULL;
    X509_NAME *name = NULL, *name2 = NULL;
    EVP_PKEY *k0, *k1;
    unsigned char *der = NULL;
    int len, ok, depth;
    STACK_OF(X509) *sk;
    STACK_OF(X509) *up;
    X509_REVOKED *rev;

    p = RT_X509_CERT_DER;
    cert = d2i_X509(NULL, &p, (long)RT_X509_CERT_DER_LEN);
    p = RT_X509_CERT_DER;
    cert2 = d2i_X509(NULL, &p, (long)RT_X509_CERT_DER_LEN);
    out_ptr("cmp.cert", cert);
    out_ptr("cmp.cert2", cert2);

    if (cert != NULL && cert2 != NULL) {
        out_int("cmp.issuer_and_serial.self", (long)X509_issuer_and_serial_cmp(cert, cert));
        out_int("cmp.issuer_and_serial.copy", (long)X509_issuer_and_serial_cmp(cert, cert2));
        out_int("cmp.issuer_and_serial.null_b", (long)X509_issuer_and_serial_cmp(cert, NULL));
        out_int("cmp.issuer_and_serial.null_a", (long)X509_issuer_and_serial_cmp(NULL, cert));
        out_int("cmp.issuer_name.self", (long)X509_issuer_name_cmp(cert, cert));
        out_int("cmp.issuer_name.copy", (long)X509_issuer_name_cmp(cert, cert2));
        out_int("cmp.subject_name.self", (long)X509_subject_name_cmp(cert, cert));
        out_int("cmp.subject_name.copy", (long)X509_subject_name_cmp(cert, cert2));

        out_ptr("cmp.get_issuer_name", X509_get_issuer_name(cert));
        out_ptr("cmp.get_subject_name", X509_get_subject_name(cert));
        out_ptr("cmp.get_serialNumber", X509_get_serialNumber(cert));
        out_int("cmp.get0_serialNumber.len",
                (long)ASN1_STRING_length(X509_get0_serialNumber(cert)));
        out_int("cmp.get_version", (long)X509_get_version(cert));
        out_int("cmp.get_signature_nid", (long)X509_get_signature_nid(cert));
        out_int("cmp.certificate_type", (long)X509_certificate_type(cert, NULL));
        out_int("cmp.certificate_type.null_cert", (long)X509_certificate_type(NULL, NULL));

        k0 = X509_get0_pubkey(cert);
        k1 = X509_get_pubkey(cert);
        out_ptr("cmp.get0_pubkey", k0);
        out_ptr("cmp.get_pubkey", k1);
        out_int("cmp.pubkey.same", k0 == k1);
        EVP_PKEY_free(k1);
        out_ptr("cmp.get0_pubkey.null", X509_get0_pubkey(NULL));
        out_ptr("cmp.get_pubkey.null", X509_get_pubkey(NULL));

        /* `check_private_key` against a NULL key: the certificate's own key path and its
         * refusal coordinate. */
        ERR_clear_error();
        out_int("cmp.check_private_key.nullkey", (long)X509_check_private_key(cert, NULL));
        out_err("cmp.check_private_key.nullkey.err");

        /* The name hashes; `_old` is the pre-1.1.0 spelling. */
        out_int("cmp.issuer_name_hash", (long)X509_issuer_name_hash(cert));
        out_int("cmp.subject_name_hash", (long)X509_subject_name_hash(cert));
        out_int("cmp.issuer_name_hash_old", (long)X509_issuer_name_hash_old(cert));
        out_int("cmp.subject_name_hash_old", (long)X509_subject_name_hash_old(cert));
        out_int("cmp.issuer_and_serial_hash", (long)X509_issuer_and_serial_hash(cert));

        /* The find-by searches over a stack holding both copies. */
        sk = sk_X509_new_null();
        sk_X509_push(sk, cert);
        sk_X509_push(sk, cert2);
        out_ptr("cmp.find_by_subject",
                X509_find_by_subject(sk, X509_get_subject_name(cert)));
        out_int("cmp.find_by_subject.is_first",
                X509_find_by_subject(sk, X509_get_subject_name(cert)) == cert);
        out_ptr("cmp.find_by_issuer_and_serial",
                X509_find_by_issuer_and_serial(sk, X509_get_issuer_name(cert),
                                               X509_get0_serialNumber(cert)));
        out_int("cmp.find_by_issuer_and_serial.is_first",
                X509_find_by_issuer_and_serial(sk, X509_get_issuer_name(cert),
                                               X509_get0_serialNumber(cert)) == cert);
        out_ptr("cmp.find_by_subject.null_sk",
                X509_find_by_subject(NULL, X509_get_subject_name(cert)));

        /* The up-ref duplicates the stack and uppers every element. */
        up = X509_chain_up_ref(sk);
        out_ptr("cmp.chain_up_ref", up);
        out_int("cmp.chain_up_ref.count", up != NULL ? (long)sk_X509_num(up) : -1);
        out_int("cmp.chain_up_ref.same0", up != NULL && sk_X509_value(up, 0) == cert);
        out_int("cmp.chain_up_ref.distinct", up != NULL && up != sk);
        sk_X509_pop_free(up, X509_free);
        sk_X509_free(sk);
    }

    /* The populated name compared with itself, a copy and NULL. */
    p = RT_X509_NAME_DER;
    name = d2i_X509_NAME(NULL, &p, (long)RT_X509_NAME_DER_LEN);
    p = RT_X509_NAME_DER;
    name2 = d2i_X509_NAME(NULL, &p, (long)RT_X509_NAME_DER_LEN);
    out_ptr("cmp.name", name);
    out_ptr("cmp.name2", name2);
    if (name != NULL && name2 != NULL) {
        out_int("cmp.name.self", (long)X509_NAME_cmp(name, name));
        out_int("cmp.name.copy", (long)X509_NAME_cmp(name, name2));
        out_int("cmp.name.null_b", (long)X509_NAME_cmp(name, NULL));
        out_int("cmp.name.null_a", (long)X509_NAME_cmp(NULL, name));
        ok = -1;
        out_int("cmp.name_hash_ex", (long)X509_NAME_hash_ex(name, NULL, NULL, &ok));
        out_int("cmp.name_hash_ex.ok", (long)ok);
        out_int("cmp.name_hash_old", (long)X509_NAME_hash_old(name));
        /* The certificate's issuer name and the standalone block are the same DN. */
        out_int("cmp.name_vs_cert_issuer",
                cert != NULL ? (long)X509_NAME_cmp(name, X509_get_issuer_name(cert)) : -9);
    }

    /* `X509_set_version`/`X509_get_version` round trip on a blank certificate. */
    fresh = X509_new();
    out_ptr("cmp.fresh", fresh);
    if (fresh != NULL) {
        out_int("cmp.set_version.initial", (long)X509_get_version(fresh));
        out_int("cmp.set_version.to2", (long)X509_set_version(fresh, 2));
        out_int("cmp.set_version.get2", (long)X509_get_version(fresh));
        out_int("cmp.set_version.same", (long)X509_set_version(fresh, 2));
        out_int("cmp.set_version.to0", (long)X509_set_version(fresh, 0));
        out_int("cmp.set_version.get0", (long)X509_get_version(fresh));
        X509_free(fresh);
    }

    /* ----- the CRL surface ----- */
    p = RT_X509_CRL_DER;
    crl = d2i_X509_CRL(NULL, &p, (long)RT_X509_CRL_DER_LEN);
    p = RT_X509_CRL_DER;
    crl2 = d2i_X509_CRL(NULL, &p, (long)RT_X509_CRL_DER_LEN);
    out_ptr("cmp.crl", crl);
    out_ptr("cmp.crl2", crl2);
    if (crl != NULL && crl2 != NULL) {
        out_int("cmp.crl_cmp.self", (long)X509_CRL_cmp(crl, crl));
        out_int("cmp.crl_cmp.copy", (long)X509_CRL_cmp(crl, crl2));
        out_int("cmp.crl_match.copy", (long)X509_CRL_match(crl, crl2));
        out_int("cmp.crl.get_version", (long)X509_CRL_get_version(crl));
        out_ptr("cmp.crl.get_issuer", X509_CRL_get_issuer(crl));
        out_int("cmp.crl.get_signature_nid", (long)X509_CRL_get_signature_nid(crl));
        out_ptr("cmp.crl.get0_lastUpdate", X509_CRL_get0_lastUpdate(crl));
        out_ptr("cmp.crl.get0_nextUpdate", X509_CRL_get0_nextUpdate(crl));
        out_ptr("cmp.crl.get_lastUpdate", X509_CRL_get_lastUpdate(crl));
        out_ptr("cmp.crl.get_nextUpdate", X509_CRL_get_nextUpdate(crl));
        out_ptr("cmp.crl.get0_tbs_sigalg", X509_CRL_get0_tbs_sigalg(crl));
        out_ptr("cmp.crl.get0_extensions", X509_CRL_get0_extensions(crl));
        {
            const ASN1_BIT_STRING *psig = NULL;
            const X509_ALGOR *palg = NULL;
            X509_CRL_get0_signature(crl, &psig, &palg);
            out_ptr("cmp.crl.get0_signature.sig", psig);
            out_ptr("cmp.crl.get0_signature.alg", palg);
        }

        /* The revoked stack and its entries, all fourteen of them. */
        {
            STACK_OF(X509_REVOKED) *revoked = X509_CRL_get_REVOKED(crl);
            STACK_OF(X509_REVOKED) *revoked2 = X509_CRL_get_REVOKED(crl2);
            out_ptr("cmp.crl.revoked", revoked);
            out_int("cmp.crl.revoked.count", revoked != NULL ? (long)sk_X509_REVOKED_num(revoked) : -1);
            rev = revoked2 != NULL ? sk_X509_REVOKED_value(revoked2, 0) : NULL;
            out_ptr("cmp.revoked0", rev);
            if (rev != NULL) {
                out_int("cmp.revoked0.serial.len",
                        (long)ASN1_STRING_length(X509_REVOKED_get0_serialNumber(rev)));
                out_ptr("cmp.revoked0.revocationDate", X509_REVOKED_get0_revocationDate(rev));
                out_ptr("cmp.revoked0.extensions", X509_REVOKED_get0_extensions(rev));
                out_int("cmp.revoked0.set_revocationDate",
                        (long)X509_REVOKED_set_revocationDate(
                            rev, (ASN1_TIME *)X509_REVOKED_get0_revocationDate(rev)));
                out_int("cmp.revoked0.set_serialNumber",
                        (long)X509_REVOKED_set_serialNumber(
                            rev, (ASN1_INTEGER *)X509_REVOKED_get0_serialNumber(rev)));
            }
        }

        /* The mutations, on the second decode: version, issuer, lastUpdate, sort. */
        out_int("cmp.crl.set_version0", (long)X509_CRL_set_version(crl2, 0));
        out_int("cmp.crl.get_version.after0", (long)X509_CRL_get_version(crl2));
        out_int("cmp.crl.set_version1", (long)X509_CRL_set_version(crl2, 1));
        out_int("cmp.crl.set_issuer_name",
                (long)X509_CRL_set_issuer_name(crl2, name));
        out_int("cmp.crl.set1_lastUpdate",
                (long)X509_CRL_set1_lastUpdate(crl2, X509_CRL_get0_lastUpdate(crl2)));
        out_int("cmp.crl.set1_nextUpdate",
                (long)X509_CRL_set1_nextUpdate(crl2, X509_CRL_get0_nextUpdate(crl2)));
        out_int("cmp.crl.sort", (long)X509_CRL_sort(crl2));

        /* Re-encode the CRL body; both sides must agree on the length. */
        len = i2d_re_X509_CRL_tbs(crl, &der);
        out_int("cmp.i2d_re_crl_tbs.len", (long)len);
        OPENSSL_free(der);
        der = NULL;
    }

    /* The static `check_suite_b` through both public entry points. */
    if (cert != NULL) {
        depth = -999;
        out_int("cmp.suiteb.off",
                (long)X509_chain_check_suiteb(&depth, cert, NULL, 0));
        out_int("cmp.suiteb.off.depth", (long)depth);
        depth = -999;
        out_int("cmp.suiteb.rsa_leaf",
                (long)X509_chain_check_suiteb(&depth, cert, NULL,
                                              X509_V_FLAG_SUITEB_128_LOS));
        out_int("cmp.suiteb.rsa_leaf.depth", (long)depth);
    }
    if (crl != NULL) {
        out_int("cmp.crl_suiteb.off", (long)X509_CRL_check_suiteb(crl, NULL, 0));
        out_int("cmp.crl_suiteb.on",
                (long)X509_CRL_check_suiteb(crl, NULL, X509_V_FLAG_SUITEB_128_LOS));
    }

    X509_free(cert);
    X509_free(cert2);
    X509_CRL_free(crl);
    X509_CRL_free(crl2);
    X509_NAME_free(name);
    X509_NAME_free(name2);
}

int main(void)
{
    OSSL_STORE_LOADER *loader;
    OSSL_STORE_LOADER *bad;
    OSSL_STORE_LOADER *incomplete;
    OSSL_STORE_LOADER *removed;
    const char *scheme = "probe";
    /* The published row's scheme literal, which `provider_court_coverage.py`'s join reads if
     * and when the row lands; naming it here is required by the pass even while the row is
     * withheld. It is never passed to a fetch, because the two sides would answer differently. */
    const char *file_scheme = "file";
    long names = 0;
    /* The two provider-fetch exports are referenced through a volatile slot so the reference
     * survives every optimisation level: a bare `func != NULL` is folded to 1 by the compiler,
     * which drops the relocation and leaves the symbol out of the probe's `.dynsym` --
     * `court_coverage.py` then has no edge for it. `probe_hygiene.py` observes the same reference
     * at each level. */
    static void (*volatile g_ref_fetch)(void);
    static void (*volatile g_ref_do_all)(void);

    ERR_clear_error();

    /* ----- the OSSL_STORE_INFO type-name table (store_strings.c) ----- */
    out_str("info.type_string.1", OSSL_STORE_INFO_type_string(1));
    out_str("info.type_string.2", OSSL_STORE_INFO_type_string(2));
    out_str("info.type_string.3", OSSL_STORE_INFO_type_string(3));
    out_str("info.type_string.4", OSSL_STORE_INFO_type_string(4));
    out_str("info.type_string.5", OSSL_STORE_INFO_type_string(5));
    out_str("info.type_string.6", OSSL_STORE_INFO_type_string(6));
    out_ptr("info.type_string.0", OSSL_STORE_INFO_type_string(0));
    out_ptr("info.type_string.7", OSSL_STORE_INFO_type_string(7));

    /* ----- the OSSL_STORE_INFO and OSSL_STORE_SEARCH object models (store_lib.c) ----- */
    drive_info_object_model();
    drive_search_object_model();

    /* ----- Phase 10.8: the X.509 object core and the arms it closes ----- */
    drive_x509_object_core();

    /* ----- Phase 10.10: the DN printer ----- */
    drive_name_oneline();

    /* ----- Phase 10.11: the name accessors, the DN flags and the extension surface ----- */
    drive_name_print_ex();
    drive_x509v3_extensions();

    /* ----- Phase 10.12: the leaf extension items, the X509_AUX layer and the policy graph ----- */
    drive_x509_leaf_units();

    /* ----- Phase 10.13: the remaining leaf extension items and the v3_lib registration surface ----- */
    drive_x509_10_13_items();

    /* ----- Phase 10.14.1: the certificate comparison and accessor surface ----- */
    drive_x509_cmp_surface();

    /* ----- OSSL_STORE_LOADER_new, including the NULL-scheme refusal ----- */
    out_ptr("loader.new.null_scheme", OSSL_STORE_LOADER_new(NULL, NULL));
    out_err("loader.new.null_scheme.err");

    loader = make_loader(scheme, 1);
    out_ptr("loader.new", loader);
    out_str("loader.scheme", OSSL_STORE_LOADER_get0_scheme(loader));
    out_ptr("loader.engine", OSSL_STORE_LOADER_get0_engine(loader));

    /* ----- the ten setters, each answering 1 ----- */
    out_int("loader.set_open", OSSL_STORE_LOADER_set_open(loader, probe_open));
    out_int("loader.set_open_ex", OSSL_STORE_LOADER_set_open_ex(loader, probe_open_ex));
    out_int("loader.set_attach", OSSL_STORE_LOADER_set_attach(loader, probe_attach));
    out_int("loader.set_ctrl", OSSL_STORE_LOADER_set_ctrl(loader, probe_control));
    out_int("loader.set_expect", OSSL_STORE_LOADER_set_expect(loader, probe_expect));
    out_int("loader.set_find", OSSL_STORE_LOADER_set_find(loader, probe_find));
    out_int("loader.set_load", OSSL_STORE_LOADER_set_load(loader, probe_load));
    out_int("loader.set_eof", OSSL_STORE_LOADER_set_eof(loader, probe_eof));
    out_int("loader.set_error", OSSL_STORE_LOADER_set_error(loader, probe_error));
    out_int("loader.set_close", OSSL_STORE_LOADER_set_close(loader, probe_close));

    /* ----- the by-name accessors, on a legacy loader (no provider) ----- */
    out_ptr("loader.get0_provider", OSSL_STORE_LOADER_get0_provider(loader));
    out_ptr("loader.get0_properties", OSSL_STORE_LOADER_get0_properties(loader));
    out_ptr("loader.get0_description", OSSL_STORE_LOADER_get0_description(loader));
    out_int("loader.is_a.probe", OSSL_STORE_LOADER_is_a(loader, "probe"));
    out_int("loader.names_do_all", OSSL_STORE_LOADER_names_do_all(loader, do_all_names_cb, &names));
    out_int("loader.names_count", names);
    out_ptr("loader.settable_ctx_params", OSSL_STORE_LOADER_settable_ctx_params(loader));
    out_int("loader.up_ref", OSSL_STORE_LOADER_up_ref(loader));

    /* ----- the registry ----- */
    out_int("store.register", OSSL_STORE_register_loader(loader));
    out_err("store.register.err");

    /* ----- the CTX state machine over the registered loader (store_lib.c) ----- */
    drive_store_ctx(loader);

    g_do_all_count = 0;
    out_int("store.do_all_loaders", OSSL_STORE_do_all_loaders(do_all_loaders_cb, NULL));
    out_int("store.do_all.count", g_do_all_count);

    removed = OSSL_STORE_unregister_loader(scheme);
    out_ptr("store.unregister", removed);
    out_err("store.unregister.err");
    out_int("store.unregister.is_same", removed == loader);
    OSSL_STORE_LOADER_free(removed);

    g_do_all_count = 0;
    out_int("store.do_all_loaders.after", OSSL_STORE_do_all_loaders(do_all_loaders_cb, NULL));
    out_int("store.do_all.count.after", g_do_all_count);

    /* ----- the unregistered-scheme refusal ----- */
    out_ptr("store.unregister.missing", OSSL_STORE_unregister_loader("nosuch"));
    out_err("store.unregister.missing.err");

    /* ----- the invalid-scheme refusal (RFC 3986 syntax) ----- */
    bad = make_loader("1bad", 1);
    out_ptr("store.register.bad_scheme.loader", bad);
    out_int("store.register.bad_scheme", OSSL_STORE_register_loader(bad));
    out_err("store.register.bad_scheme.err");
    OSSL_STORE_LOADER_free(bad);

    /* ----- the loader-incomplete refusal (load == NULL) ----- */
    incomplete = make_loader("incomplete", 0);
    out_ptr("store.register.incomplete.loader", incomplete);
    out_int("store.register.incomplete", OSSL_STORE_register_loader(incomplete));
    out_err("store.register.incomplete.err");
    OSSL_STORE_LOADER_free(incomplete);

    /* ----- the open/delete refusal arms, none of which resolves a loader ----- */
    out_ptr("store.open.null", OSSL_STORE_open(NULL, NULL, NULL, NULL, NULL));
    out_err("store.open.null.err");
    out_ptr("store.open_ex.unknown",
            OSSL_STORE_open_ex("foo://object", NULL, NULL, NULL, NULL, NULL, NULL, NULL));
    out_err("store.open_ex.unknown.err");

    out_int("store.delete.probe",
            OSSL_STORE_delete("probe://object", NULL, NULL, NULL, NULL, NULL));
    out_err("store.delete.probe.err");
    out_int("store.delete.null", OSSL_STORE_delete(NULL, NULL, NULL, NULL, NULL, NULL));
    out_err("store.delete.null.err");
    out_int("store.delete.no_scheme",
            OSSL_STORE_delete("noscheme", NULL, NULL, NULL, NULL, NULL));
    out_err("store.delete.no_scheme.err");

    /* ----- the two provider-fetch exports: referenced, not called ----- */
    g_ref_fetch = (void (*)(void))OSSL_STORE_LOADER_fetch;
    g_ref_do_all = (void (*)(void))OSSL_STORE_LOADER_do_all_provided;
    printf("ref.OSSL_STORE_LOADER_fetch=%s\n", g_ref_fetch != NULL ? "nonnull" : "null");
    printf("ref.OSSL_STORE_LOADER_do_all_provided=%s\n", g_ref_do_all != NULL ? "nonnull" : "null");
    out_str("ref.file_scheme", file_scheme);

    drive_engine_registry();

    out_pending();
    return 0;
}
