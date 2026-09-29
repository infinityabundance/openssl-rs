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
 *  * the two `OSSL_OP_STORE` provider rows (`file`) were withheld through 10.15. **10.16 publishes
 *    them**, so `OSSL_STORE_LOADER_fetch`/`do_all_provided` and the fetched `OSSL_STORE_find`
 *    arms are now **driven** at the end of `main` rather than named pending.
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
#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <openssl/dsa.h>
#include <openssl/ec.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/obj_mac.h>
#include <openssl/provider.h>
#include <openssl/rsa.h>
#include <openssl/store.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>

#include "rt_keyformat_keys.h"
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

/* A byte string as lowercase hex, or `null` for a NULL pointer. */
static void out_hex(const char *key, const unsigned char *p, long n)
{
    long i;

    if (p == NULL) {
        printf("%s=null\n", key);
        return;
    }
    printf("%s=", key);
    for (i = 0; i < n; i++)
        printf("%02x", p[i]);
    printf("\n");
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

/* The provider walk's visitor. It counts only, because a *fetched* loader's `scheme` is NULL
 * (`loader_from_algorithm` sets `scheme_id` and `propdef`, not the legacy `scheme` field), so the
 * legacy visitor's `get0_scheme` would print `(null)` on both sides -- a true but empty
 * observation. The count is the observable that distinguishes a resolved row from an absent one. */
static long g_provider_do_all_count;

static void provider_do_all_cb(OSSL_STORE_LOADER *loader, void *arg)
{
    (void)loader;
    (void)arg;
    g_provider_do_all_count++;
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
    printf("pending.OSSL_STORE_load=store_result_ossl_store_handle_load_result\n");
    /* 10.14.2: the classical RSA verify path (`X509_verify`/`NETSCAPE_SPKI_verify` over an
     * RSA-signed object) resolves its digest by name through `EVP_get_digestbyname`, which this
     * crate answers NULL for every built-in name -- the Phase 13 legacy-`OBJ_NAME` divergence
     * D333/D343 record (`add_all_legacy_methods` is a no-op). That path is therefore not
     * comparable; the Ed25519 verify arms are what drive `X509_verify`/`NETSCAPE_SPKI_verify`. */
    printf("pending.X509_verify.rsa=classical_rsa_path_reads_EVP_get_digestbyname_Phase13_divergence\n");
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

/* ---------------------------------------------------------------------------------------------
 * Phase 10.14.2 -- `crypto/x509/x_all.c`, `x509_def.c` and `x509spki.c`/`crypto/asn1/x_spki.c`.
 *
 * The certificate encode/decode faces and the digest family, driven over the fixed certificate,
 * CRL and name; the PKCS#8/X509_PUBKEY/private-key/public-key and RSA/DSA/EC stream faces over
 * the shared fixed keys; the two environment-name defaults; and the Netscape SPKI object. Every
 * arm pops its own error queue first (D455's lesson). Signing arms re-encode the signed object,
 * which is deterministic because PKCS#1 v1.5 is.
 * --------------------------------------------------------------------------------------------- */
static void drive_x509_all_surface(void)
{
    const unsigned char *p;
    X509 *cert = NULL, *rtcert = NULL;
    X509_CRL *crl = NULL, *rtcrl = NULL, *rtcrl2 = NULL;
    X509_NAME *name = NULL;
    EVP_PKEY *certkey = NULL, *priv = NULL, *dec = NULL;
    RSA *rsa = NULL, *rsa2 = NULL;
    DSA *dsa = NULL, *dsa2 = NULL;
    EC_KEY *ec = NULL, *ec2 = NULL;
    X509_PUBKEY *xpk = NULL, *xpk2 = NULL;
    PKCS8_PRIV_KEY_INFO *p8 = NULL, *p82 = NULL;
    X509_SIG *sig = NULL, *sig2 = NULL;
    NETSCAPE_SPKI *spki = NULL, *spki2 = NULL;
    ASN1_OCTET_STRING *osig = NULL;
    EVP_MD *md_used = NULL;
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int mdlen = 0;
    unsigned char *der = NULL;
    int len, fallback = 0;
    char *b64 = NULL;
    BIO *b = NULL;
    FILE *fp = NULL;

    p = RT_X509_CERT_DER;
    cert = d2i_X509(NULL, &p, (long)RT_X509_CERT_DER_LEN);
    p = RT_X509_CRL_DER;
    crl = d2i_X509_CRL(NULL, &p, (long)RT_X509_CRL_DER_LEN);
    p = RT_X509_NAME_DER;
    name = d2i_X509_NAME(NULL, &p, (long)RT_X509_NAME_DER_LEN);
    certkey = cert != NULL ? X509_get_pubkey(cert) : NULL;
    out_ptr("xall.cert", cert);
    out_ptr("xall.crl", crl);
    out_ptr("xall.name", name);
    out_ptr("xall.certkey", certkey);

    /* ----- the certificate and CRL fp/bio faces ----- */
    fp = tmpfile();
    ERR_clear_error();
    out_int("xall.x509.i2d_fp", fp != NULL ? i2d_X509_fp(fp, cert) : -99);
    if (fp != NULL) {
        rewind(fp);
        rtcert = d2i_X509_fp(fp, NULL);
    }
    out_ptr("xall.x509.d2i_fp", rtcert);
    out_int("xall.x509.d2i_fp.len", rtcert != NULL ? i2d_X509(rtcert, &der) : -1);
    OPENSSL_free(der);
    der = NULL;
    X509_free(rtcert);
    rtcert = NULL;
    if (fp != NULL)
        fclose(fp);
    fp = NULL;

    b = BIO_new(BIO_s_mem());
    ERR_clear_error();
    out_int("xall.x509.i2d_bio", b != NULL ? i2d_X509_bio(b, cert) : -99);
    if (b != NULL)
        rtcert = d2i_X509_bio(b, NULL);
    out_ptr("xall.x509.d2i_bio", rtcert);
    out_int("xall.x509.d2i_bio.len", rtcert != NULL ? i2d_X509(rtcert, &der) : -1);
    OPENSSL_free(der);
    der = NULL;
    X509_free(rtcert);
    rtcert = NULL;
    BIO_free(b);
    b = NULL;

    fp = tmpfile();
    ERR_clear_error();
    out_int("xall.crl.i2d_fp", fp != NULL ? i2d_X509_CRL_fp(fp, crl) : -99);
    if (fp != NULL) {
        rewind(fp);
        rtcrl = d2i_X509_CRL_fp(fp, NULL);
    }
    out_ptr("xall.crl.d2i_fp", rtcrl);
    out_int("xall.crl.d2i_fp.len", rtcrl != NULL ? i2d_X509_CRL(rtcrl, &der) : -1);
    OPENSSL_free(der);
    der = NULL;
    X509_CRL_free(rtcrl);
    rtcrl = NULL;
    if (fp != NULL)
        fclose(fp);
    fp = NULL;

    b = BIO_new(BIO_s_mem());
    ERR_clear_error();
    out_int("xall.crl.i2d_bio", b != NULL ? i2d_X509_CRL_bio(b, crl) : -99);
    if (b != NULL)
        rtcrl = d2i_X509_CRL_bio(b, NULL);
    out_ptr("xall.crl.d2i_bio", rtcrl);
    out_int("xall.crl.d2i_bio.len", rtcrl != NULL ? i2d_X509_CRL(rtcrl, &der) : -1);
    OPENSSL_free(der);
    der = NULL;
    X509_CRL_free(rtcrl);
    rtcrl = NULL;
    BIO_free(b);
    b = NULL;

    /* ----- the digest family ----- */
    ERR_clear_error();
    out_int("xall.pubkey_digest", X509_pubkey_digest(cert, EVP_sha256(), md, &mdlen));
    out_int("xall.pubkey_digest.len", (long)mdlen);
    out_int("xall.pubkey_digest.b0", (long)md[0]);
    ERR_clear_error();
    out_int("xall.digest.sha256", X509_digest(cert, EVP_sha256(), md, &mdlen));
    out_int("xall.digest.sha256.len", (long)mdlen);
    out_int("xall.digest.sha256.b0", (long)md[0]);
    ERR_clear_error();
    out_int("xall.digest.sha1", X509_digest(cert, EVP_sha1(), md, &mdlen));
    out_int("xall.digest.sha1.len", (long)mdlen);
    ERR_clear_error();
    out_int("xall.crl_digest", X509_CRL_digest(crl, EVP_sha256(), md, &mdlen));
    out_int("xall.crl_digest.len", (long)mdlen);
    out_int("xall.crl_digest.b0", (long)md[0]);
    ERR_clear_error();
    out_int("xall.crl_digest.null", X509_CRL_digest(crl, NULL, md, &mdlen));
    out_err("xall.crl_digest.null.err");
    ERR_clear_error();
    out_int("xall.name_digest", X509_NAME_digest(name, EVP_sha256(), md, &mdlen));
    out_int("xall.name_digest.len", (long)mdlen);
    ERR_clear_error();
    osig = X509_digest_sig(cert, &md_used, &fallback);
    out_ptr("xall.digest_sig", osig);
    out_int("xall.digest_sig.fallback", (long)fallback);
    out_int("xall.digest_sig.len", osig != NULL ? ASN1_STRING_length(osig) : -1);
    out_int("xall.digest_sig.b0",
            osig != NULL ? (long)((const unsigned char *)ASN1_STRING_get0_data(osig))[0] : -1);
    EVP_MD_free(md_used);
    md_used = NULL;
    ASN1_OCTET_STRING_free(osig);
    osig = NULL;
    ERR_clear_error();
    out_ptr("xall.digest_sig.null", X509_digest_sig(NULL, NULL, NULL));
    out_err("xall.digest_sig.null.err");

    /* ----- sign with the fixed RSA key (deterministic PKCS#1 v1.5), and sign_ctx ----- */
    p = rsa_pkcs1_der;
    priv = d2i_AutoPrivateKey(NULL, &p, (long)sizeof(rsa_pkcs1_der));
    out_ptr("xall.priv", priv);

    p = RT_X509_CRL_DER;
    rtcrl = d2i_X509_CRL(NULL, &p, (long)RT_X509_CRL_DER_LEN);
    ERR_clear_error();
    out_int("xall.crl_sign", X509_CRL_sign(rtcrl, priv, EVP_sha256()));
    ERR_clear_error();
    out_int("xall.crl_sign.null", X509_CRL_sign(NULL, priv, EVP_sha256()));
    out_err("xall.crl_sign.null.err");
    len = i2d_X509_CRL(rtcrl, &der);
    out_int("xall.crl_sign.len", len);
    OPENSSL_free(der);
    der = NULL;
    {
        EVP_MD_CTX *sctx = EVP_MD_CTX_new();
        p = RT_X509_CRL_DER;
        rtcrl2 = d2i_X509_CRL(NULL, &p, (long)RT_X509_CRL_DER_LEN);
        ERR_clear_error();
        out_int("xall.crl_sign_ctx.init",
                EVP_DigestSignInit(sctx, NULL, EVP_sha256(), NULL, priv));
        out_int("xall.crl_sign_ctx", X509_CRL_sign_ctx(rtcrl2, sctx));
        out_int("xall.crl_sign_ctx.len", i2d_X509_CRL(rtcrl2, &der));
        OPENSSL_free(der);
        der = NULL;
        X509_CRL_free(rtcrl2);
        rtcrl2 = NULL;
        EVP_MD_CTX_free(sctx);
    }
    X509_CRL_free(rtcrl);
    rtcrl = NULL;

    p = RT_X509_CERT_DER;
    rtcert = d2i_X509(NULL, &p, (long)RT_X509_CERT_DER_LEN);
    ERR_clear_error();
    out_int("xall.cert_sign", X509_sign(rtcert, priv, EVP_sha256()));
    ERR_clear_error();
    out_int("xall.cert_sign.null", X509_sign(NULL, priv, EVP_sha256()));
    out_err("xall.cert_sign.null.err");
    len = i2d_X509(rtcert, &der);
    out_int("xall.cert_sign.len", len);
    OPENSSL_free(der);
    der = NULL;
    {
        EVP_MD_CTX *sctx = EVP_MD_CTX_new();
        X509 *vcert = NULL;
        p = RT_X509_CERT_DER;
        vcert = d2i_X509(NULL, &p, (long)RT_X509_CERT_DER_LEN);
        ERR_clear_error();
        out_int("xall.cert_sign_ctx.init",
                EVP_DigestSignInit(sctx, NULL, EVP_sha256(), NULL, priv));
        out_int("xall.cert_sign_ctx", X509_sign_ctx(vcert, sctx));
        out_int("xall.cert_sign_ctx.len", i2d_X509(vcert, &der));
        OPENSSL_free(der);
        der = NULL;
        X509_free(vcert);
        EVP_MD_CTX_free(sctx);
    }
    X509_free(rtcert);
    rtcert = NULL;

    /* ----- verify over an Ed25519 signature: no digest-name lookup (the Phase 13
     * `EVP_get_digestbyname` divergence D333/D343 records is deliberately not on this path), so
     * the arms are comparable. The key is keygen'd, so only its-answer observations are printed. */
    {
        EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
        EVP_PKEY *ed = NULL;
        if (kctx != NULL)
            EVP_PKEY_keygen_init(kctx);
        if (kctx != NULL && EVP_PKEY_keygen(kctx, &ed) <= 0)
            ed = NULL;
        EVP_PKEY_CTX_free(kctx);
        out_ptr("xall.ed", ed);
        p = RT_X509_CERT_DER;
        rtcert = d2i_X509(NULL, &p, (long)RT_X509_CERT_DER_LEN);
        ERR_clear_error();
        out_int("xall.verify.sign_ed", X509_sign(rtcert, ed, NULL));
        ERR_clear_error();
        out_int("xall.verify.self_ed", X509_verify(rtcert, ed));
        out_err("xall.verify.self_ed.err");
        ERR_clear_error();
        out_int("xall.verify.nullkey", X509_verify(rtcert, NULL));
        out_err("xall.verify.nullkey.err");
        ERR_clear_error();
        out_int("xall.verify.wrongkey", X509_verify(rtcert, certkey));
        X509_free(rtcert);
        rtcert = NULL;
        EVP_PKEY_free(ed);
    }

    /* ----- the RSA stream faces ----- */
    p = rsa_pkcs1_der;
    rsa = d2i_RSAPrivateKey(NULL, &p, (long)sizeof(rsa_pkcs1_der));
    out_ptr("xall.rsa", rsa);
    b = BIO_new(BIO_s_mem());
    ERR_clear_error();
    out_int("xall.rsa.priv_bio", b != NULL ? i2d_RSAPrivateKey_bio(b, rsa) : -99);
    if (b != NULL)
        rsa2 = d2i_RSAPrivateKey_bio(b, NULL);
    out_ptr("xall.rsa.priv_bio.rt", rsa2);
    RSA_free(rsa2);
    rsa2 = NULL;
    BIO_free(b);
    b = NULL;
    b = BIO_new(BIO_s_mem());
    ERR_clear_error();
    out_int("xall.rsa.pub_bio", b != NULL ? i2d_RSAPublicKey_bio(b, rsa) : -99);
    if (b != NULL)
        rsa2 = d2i_RSAPublicKey_bio(b, NULL);
    out_ptr("xall.rsa.pub_bio.rt", rsa2);
    RSA_free(rsa2);
    rsa2 = NULL;
    BIO_free(b);
    b = NULL;
    b = BIO_new(BIO_s_mem());
    ERR_clear_error();
    out_int("xall.rsa.pk_bio", b != NULL ? i2d_RSA_PUBKEY_bio(b, rsa) : -99);
    if (b != NULL)
        rsa2 = d2i_RSA_PUBKEY_bio(b, NULL);
    out_ptr("xall.rsa.pk_bio.rt", rsa2);
    RSA_free(rsa2);
    rsa2 = NULL;
    BIO_free(b);
    b = NULL;
    fp = tmpfile();
    ERR_clear_error();
    out_int("xall.rsa.priv_fp", fp != NULL ? i2d_RSAPrivateKey_fp(fp, rsa) : -99);
    if (fp != NULL) {
        rewind(fp);
        rsa2 = d2i_RSAPrivateKey_fp(fp, NULL);
        out_ptr("xall.rsa.priv_fp.rt", rsa2);
        RSA_free(rsa2);
        rsa2 = NULL;
        fclose(fp);
    }
    fp = NULL;
    fp = tmpfile();
    ERR_clear_error();
    out_int("xall.rsa.pub_fp", fp != NULL ? i2d_RSAPublicKey_fp(fp, rsa) : -99);
    if (fp != NULL) {
        rewind(fp);
        rsa2 = d2i_RSAPublicKey_fp(fp, NULL);
        out_ptr("xall.rsa.pub_fp.rt", rsa2);
        RSA_free(rsa2);
        rsa2 = NULL;
        fclose(fp);
    }
    fp = NULL;
    fp = tmpfile();
    ERR_clear_error();
    out_int("xall.rsa.pk_fp", fp != NULL ? i2d_RSA_PUBKEY_fp(fp, rsa) : -99);
    if (fp != NULL) {
        rewind(fp);
        rsa2 = d2i_RSA_PUBKEY_fp(fp, NULL);
        out_ptr("xall.rsa.pk_fp.rt", rsa2);
        RSA_free(rsa2);
        rsa2 = NULL;
        fclose(fp);
    }
    fp = NULL;
    RSA_free(rsa);
    rsa = NULL;

    /* ----- the DSA stream faces ----- */
    p = dsa_trad_der;
    dsa = d2i_DSAPrivateKey(NULL, &p, (long)sizeof(dsa_trad_der));
    out_ptr("xall.dsa", dsa);
    b = BIO_new(BIO_s_mem());
    ERR_clear_error();
    out_int("xall.dsa.priv_bio", b != NULL ? i2d_DSAPrivateKey_bio(b, dsa) : -99);
    if (b != NULL)
        dsa2 = d2i_DSAPrivateKey_bio(b, NULL);
    out_ptr("xall.dsa.priv_bio.rt", dsa2);
    DSA_free(dsa2);
    dsa2 = NULL;
    BIO_free(b);
    b = NULL;
    b = BIO_new(BIO_s_mem());
    ERR_clear_error();
    out_int("xall.dsa.pk_bio", b != NULL ? i2d_DSA_PUBKEY_bio(b, dsa) : -99);
    if (b != NULL)
        dsa2 = d2i_DSA_PUBKEY_bio(b, NULL);
    out_ptr("xall.dsa.pk_bio.rt", dsa2);
    DSA_free(dsa2);
    dsa2 = NULL;
    BIO_free(b);
    b = NULL;
    fp = tmpfile();
    ERR_clear_error();
    out_int("xall.dsa.priv_fp", fp != NULL ? i2d_DSAPrivateKey_fp(fp, dsa) : -99);
    if (fp != NULL) {
        rewind(fp);
        dsa2 = d2i_DSAPrivateKey_fp(fp, NULL);
        out_ptr("xall.dsa.priv_fp.rt", dsa2);
        DSA_free(dsa2);
        dsa2 = NULL;
        fclose(fp);
    }
    fp = NULL;
    fp = tmpfile();
    ERR_clear_error();
    out_int("xall.dsa.pk_fp", fp != NULL ? i2d_DSA_PUBKEY_fp(fp, dsa) : -99);
    if (fp != NULL) {
        rewind(fp);
        dsa2 = d2i_DSA_PUBKEY_fp(fp, NULL);
        out_ptr("xall.dsa.pk_fp.rt", dsa2);
        DSA_free(dsa2);
        dsa2 = NULL;
        fclose(fp);
    }
    fp = NULL;
    DSA_free(dsa);
    dsa = NULL;

    /* ----- the EC stream faces ----- */
    p = ec_sec1_der;
    ec = d2i_ECPrivateKey(NULL, &p, (long)sizeof(ec_sec1_der));
    out_ptr("xall.ec", ec);
    b = BIO_new(BIO_s_mem());
    ERR_clear_error();
    out_int("xall.ec.priv_bio", b != NULL ? i2d_ECPrivateKey_bio(b, ec) : -99);
    if (b != NULL)
        ec2 = d2i_ECPrivateKey_bio(b, NULL);
    out_ptr("xall.ec.priv_bio.rt", ec2);
    EC_KEY_free(ec2);
    ec2 = NULL;
    BIO_free(b);
    b = NULL;
    b = BIO_new(BIO_s_mem());
    ERR_clear_error();
    out_int("xall.ec.pk_bio", b != NULL ? i2d_EC_PUBKEY_bio(b, ec) : -99);
    if (b != NULL)
        ec2 = d2i_EC_PUBKEY_bio(b, NULL);
    out_ptr("xall.ec.pk_bio.rt", ec2);
    EC_KEY_free(ec2);
    ec2 = NULL;
    BIO_free(b);
    b = NULL;
    fp = tmpfile();
    ERR_clear_error();
    out_int("xall.ec.priv_fp", fp != NULL ? i2d_ECPrivateKey_fp(fp, ec) : -99);
    if (fp != NULL) {
        rewind(fp);
        ec2 = d2i_ECPrivateKey_fp(fp, NULL);
        out_ptr("xall.ec.priv_fp.rt", ec2);
        EC_KEY_free(ec2);
        ec2 = NULL;
        fclose(fp);
    }
    fp = NULL;
    fp = tmpfile();
    ERR_clear_error();
    out_int("xall.ec.pk_fp", fp != NULL ? i2d_EC_PUBKEY_fp(fp, ec) : -99);
    if (fp != NULL) {
        rewind(fp);
        ec2 = d2i_EC_PUBKEY_fp(fp, NULL);
        out_ptr("xall.ec.pk_fp.rt", ec2);
        EC_KEY_free(ec2);
        ec2 = NULL;
        fclose(fp);
    }
    fp = NULL;
    EC_KEY_free(ec);
    ec = NULL;

    /* ----- the private-key / public-key / PKCS#8 stream faces ----- */
    b = BIO_new(BIO_s_mem());
    ERR_clear_error();
    out_int("xall.privkey.bio", b != NULL ? i2d_PrivateKey_bio(b, priv) : -99);
    if (b != NULL)
        dec = d2i_PrivateKey_bio(b, NULL);
    out_ptr("xall.privkey.bio.rt", dec);
    EVP_PKEY_free(dec);
    dec = NULL;
    BIO_free(b);
    b = NULL;
    b = BIO_new(BIO_s_mem());
    ERR_clear_error();
    out_int("xall.privkey.ex_bio", b != NULL ? i2d_PrivateKey_bio(b, priv) : -99);
    if (b != NULL)
        dec = d2i_PrivateKey_ex_bio(b, NULL, NULL, NULL);
    out_ptr("xall.privkey.ex_bio.rt", dec);
    EVP_PKEY_free(dec);
    dec = NULL;
    BIO_free(b);
    b = NULL;
    fp = tmpfile();
    ERR_clear_error();
    out_int("xall.privkey.fp", fp != NULL ? i2d_PrivateKey_fp(fp, priv) : -99);
    if (fp != NULL) {
        rewind(fp);
        dec = d2i_PrivateKey_fp(fp, NULL);
        out_ptr("xall.privkey.fp.rt", dec);
        EVP_PKEY_free(dec);
        dec = NULL;
        rewind(fp);
        dec = d2i_PrivateKey_ex_fp(fp, NULL, NULL, NULL);
        out_ptr("xall.privkey.ex_fp.rt", dec);
        EVP_PKEY_free(dec);
        dec = NULL;
        fclose(fp);
    }
    fp = NULL;

    b = BIO_new(BIO_s_mem());
    ERR_clear_error();
    out_int("xall.pubkeyface.bio", b != NULL ? i2d_PUBKEY_bio(b, priv) : -99);
    if (b != NULL)
        dec = d2i_PUBKEY_bio(b, NULL);
    out_ptr("xall.pubkeyface.bio.rt", dec);
    EVP_PKEY_free(dec);
    dec = NULL;
    BIO_free(b);
    b = NULL;
    b = BIO_new(BIO_s_mem());
    ERR_clear_error();
    out_int("xall.pubkeyface.ex_bio", b != NULL ? i2d_PUBKEY_bio(b, priv) : -99);
    if (b != NULL)
        dec = d2i_PUBKEY_ex_bio(b, NULL, NULL, NULL);
    out_ptr("xall.pubkeyface.ex_bio.rt", dec);
    EVP_PKEY_free(dec);
    dec = NULL;
    BIO_free(b);
    b = NULL;
    fp = tmpfile();
    ERR_clear_error();
    out_int("xall.pubkeyface.fp", fp != NULL ? i2d_PUBKEY_fp(fp, priv) : -99);
    if (fp != NULL) {
        rewind(fp);
        dec = d2i_PUBKEY_fp(fp, NULL);
        out_ptr("xall.pubkeyface.fp.rt", dec);
        EVP_PKEY_free(dec);
        dec = NULL;
        rewind(fp);
        dec = d2i_PUBKEY_ex_fp(fp, NULL, NULL, NULL);
        out_ptr("xall.pubkeyface.ex_fp.rt", dec);
        EVP_PKEY_free(dec);
        dec = NULL;
        fclose(fp);
    }
    fp = NULL;

    /* `PKCS8_PRIV_KEY_INFO` and `i2d_PKCS8PrivateKeyInfo`, fp and bio. */
    p8 = EVP_PKEY2PKCS8(priv);
    out_ptr("xall.p8", p8);
    b = BIO_new(BIO_s_mem());
    ERR_clear_error();
    out_int("xall.p8.bio", b != NULL ? i2d_PKCS8_PRIV_KEY_INFO_bio(b, p8) : -99);
    if (b != NULL)
        p82 = d2i_PKCS8_PRIV_KEY_INFO_bio(b, NULL);
    out_ptr("xall.p8.bio.rt", p82);
    PKCS8_PRIV_KEY_INFO_free(p82);
    p82 = NULL;
    BIO_free(b);
    b = NULL;
    b = BIO_new(BIO_s_mem());
    ERR_clear_error();
    out_int("xall.p8info.bio", b != NULL ? i2d_PKCS8PrivateKeyInfo_bio(b, priv) : -99);
    if (b != NULL)
        p82 = d2i_PKCS8_PRIV_KEY_INFO_bio(b, NULL);
    out_ptr("xall.p8info.bio.rt", p82);
    PKCS8_PRIV_KEY_INFO_free(p82);
    p82 = NULL;
    BIO_free(b);
    b = NULL;
    fp = tmpfile();
    ERR_clear_error();
    out_int("xall.p8.fp", fp != NULL ? i2d_PKCS8_PRIV_KEY_INFO_fp(fp, p8) : -99);
    if (fp != NULL) {
        rewind(fp);
        p82 = d2i_PKCS8_PRIV_KEY_INFO_fp(fp, NULL);
        out_ptr("xall.p8.fp.rt", p82);
        PKCS8_PRIV_KEY_INFO_free(p82);
        p82 = NULL;
        rewind(fp);
        out_int("xall.p8info.fp", i2d_PKCS8PrivateKeyInfo_fp(fp, priv));
        fclose(fp);
    }
    fp = NULL;
    PKCS8_PRIV_KEY_INFO_free(p8);
    p8 = NULL;

    /* `X509_SIG` (EncryptedPrivateKeyInfo) fp/bio, over the fixed encrypted key. */
    p = rsa_enc_der;
    sig = d2i_X509_SIG(NULL, &p, (long)sizeof(rsa_enc_der));
    out_ptr("xall.sig", sig);
    b = BIO_new(BIO_s_mem());
    ERR_clear_error();
    out_int("xall.sig.bio", b != NULL ? i2d_PKCS8_bio(b, sig) : -99);
    if (b != NULL)
        sig2 = d2i_PKCS8_bio(b, NULL);
    out_ptr("xall.sig.bio.rt", sig2);
    X509_SIG_free(sig2);
    sig2 = NULL;
    BIO_free(b);
    b = NULL;
    fp = tmpfile();
    ERR_clear_error();
    out_int("xall.sig.fp", fp != NULL ? i2d_PKCS8_fp(fp, sig) : -99);
    if (fp != NULL) {
        rewind(fp);
        sig2 = d2i_PKCS8_fp(fp, NULL);
        out_ptr("xall.sig.fp.rt", sig2);
        X509_SIG_free(sig2);
        sig2 = NULL;
        fclose(fp);
    }
    fp = NULL;
    X509_SIG_free(sig);
    sig = NULL;

    /* `X509_PUBKEY` fp/bio from the certificate's key. */
    out_int("xall.xpk.set", X509_PUBKEY_set(&xpk, certkey));
    out_ptr("xall.xpk", xpk);
    b = BIO_new(BIO_s_mem());
    ERR_clear_error();
    out_int("xall.xpk.bio", b != NULL ? i2d_X509_PUBKEY_bio(b, xpk) : -99);
    if (b != NULL)
        xpk2 = d2i_X509_PUBKEY_bio(b, NULL);
    out_ptr("xall.xpk.bio.rt", xpk2);
    X509_PUBKEY_free(xpk2);
    xpk2 = NULL;
    BIO_free(b);
    b = NULL;
    fp = tmpfile();
    ERR_clear_error();
    out_int("xall.xpk.fp", fp != NULL ? i2d_X509_PUBKEY_fp(fp, xpk) : -99);
    if (fp != NULL) {
        rewind(fp);
        xpk2 = d2i_X509_PUBKEY_fp(fp, NULL);
        out_ptr("xall.xpk.fp.rt", xpk2);
        X509_PUBKEY_free(xpk2);
        xpk2 = NULL;
        fclose(fp);
    }
    fp = NULL;
    X509_PUBKEY_free(xpk);
    xpk = NULL;

    /* ----- the two environment-name defaults ----- */
    out_str("xall.default_cert_dir_env", X509_get_default_cert_dir_env());
    out_str("xall.default_cert_file_env", X509_get_default_cert_file_env());

    /* ----- the Netscape SPKI object ----- */
    spki = NETSCAPE_SPKI_new();
    out_ptr("xall.spki", spki);
    if (spki != NULL && spki->spkac == NULL)
        spki->spkac = NETSCAPE_SPKAC_new();
    out_ptr("xall.spki.spkac", spki != NULL ? spki->spkac : NULL);
    if (spki != NULL) {
        out_int("xall.spki.set_pubkey", NETSCAPE_SPKI_set_pubkey(spki, certkey));
        out_ptr("xall.spki.get_pubkey", NETSCAPE_SPKI_get_pubkey(spki));
        /* Fixed content, so the encoding needs no signature and is byte-deterministic. */
        if (spki->spkac != NULL && spki->spkac->challenge != NULL)
            ASN1_STRING_set(spki->spkac->challenge, "challenge", 9);
        if (spki->signature != NULL)
            ASN1_STRING_set(spki->signature, "sig", 3);
        X509_ALGOR_set0(&spki->sig_algor, OBJ_nid2obj(NID_sha256WithRSAEncryption), V_ASN1_NULL,
                        NULL);
        len = i2d_NETSCAPE_SPKI(spki, &der);
        out_int("xall.spki.der.len", len);
        OPENSSL_free(der);
        der = NULL;
        b64 = NETSCAPE_SPKI_b64_encode(spki);
        out_str("xall.spki.b64", b64 != NULL ? b64 : "<null>");
        if (b64 != NULL) {
            spki2 = NETSCAPE_SPKI_b64_decode(b64, -1);
            out_ptr("xall.spki.b64.rt", spki2);
            out_int("xall.spki.b64.rt.len", spki2 != NULL ? i2d_NETSCAPE_SPKI(spki2, &der) : -1);
            OPENSSL_free(der);
            der = NULL;
            NETSCAPE_SPKI_free(spki2);
            spki2 = NULL;
            OPENSSL_free(b64);
            b64 = NULL;
        }
    }
    NETSCAPE_SPKI_free(spki);
    spki = NULL;

    /* Ed25519 sign/verify over an SPKI: again no digest-name lookup, so comparable. */
    {
        EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
        EVP_PKEY *ed = NULL;
        if (kctx != NULL)
            EVP_PKEY_keygen_init(kctx);
        if (kctx != NULL && EVP_PKEY_keygen(kctx, &ed) <= 0)
            ed = NULL;
        EVP_PKEY_CTX_free(kctx);
        spki = NETSCAPE_SPKI_new();
        if (spki != NULL && ed != NULL) {
            if (spki->spkac == NULL)
                spki->spkac = NETSCAPE_SPKAC_new();
            if (spki->spkac != NULL && spki->spkac->challenge != NULL)
                ASN1_STRING_set(spki->spkac->challenge, "challenge", 9);
            NETSCAPE_SPKI_set_pubkey(spki, ed);
            ERR_clear_error();
            out_int("xall.spki.sign_ed", NETSCAPE_SPKI_sign(spki, ed, NULL));
            ERR_clear_error();
            out_int("xall.spki.verify_ed", NETSCAPE_SPKI_verify(spki, ed));
            out_err("xall.spki.verify_ed.err");
            ERR_clear_error();
            out_int("xall.spki.verify_wrong", NETSCAPE_SPKI_verify(spki, certkey));
        }
        NETSCAPE_SPKI_free(spki);
        spki = NULL;
        EVP_PKEY_free(ed);
    }
    ERR_clear_error();
    out_ptr("xall.spki.b64.bad", NETSCAPE_SPKI_b64_decode("not base64!", -1));
    out_err("xall.spki.b64.bad.err");

    EVP_PKEY_free(certkey);
    EVP_PKEY_free(priv);
    X509_free(cert);
    X509_CRL_free(crl);
    X509_NAME_free(name);
}

/* ---------------------------------------------------------------------------------------------
 * Phase 10.14.4: the `GENERAL_NAME` / `GENERAL_NAMES` items and accessors.
 *
 * Five fixed wire forms cover the context-implicit primitive arms the CHOICE names ([1]
 * rfc822Name, [2] dNSName, [6] URI, [7] iPAddress, [8] registeredID); each is decoded, its
 * selector and cursor read, and its bytes re-encoded. The `otherName` and `directoryName` arms
 * are exercised through the setters (`set0_othername`, `set1_X509_NAME`), and the refusal of a
 * NULL target carries its error coordinate.
 * --------------------------------------------------------------------------------------------- */

static void drive_x509_10_14_4_genn(void)
{
    static const unsigned char GN_DNS[] = { 0x82, 0x09, 'a', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e' };
    static const unsigned char GN_MAIL[] = { 0x81, 0x03, 'a', '@', 'b' };
    static const unsigned char GN_URI[] = { 0x86, 0x08, 'h', 't', 't', 'p', ':', '/', '/', 'x' };
    static const unsigned char GN_IP[] = { 0x87, 0x04, 0x7f, 0x00, 0x00, 0x01 };
    static const unsigned char GN_RID[] = { 0x88, 0x03, 0x55, 0x04, 0x03 };
    static const unsigned char GN_BOTH[] = {
        0x30, 0x11,
        0x82, 0x09, 'a', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        0x87, 0x04, 0x7f, 0x00, 0x00, 0x01
    };
    static const unsigned char FIX_ANY_OCT[] = { 0x04, 0x01, 0x00 };
    const unsigned char *p;
    unsigned char *der = NULL;
    long len;
    GENERAL_NAME *n1 = NULL, *n2 = NULL, *dup = NULL, *tgt = NULL;
    GENERAL_NAMES *names = NULL, *names2 = NULL;
    ASN1_OBJECT *oid = NULL;
    ASN1_TYPE *val = NULL;

    out_ptr("genn.it", (const void *)GENERAL_NAME_it());
    out_ptr("genn.it_names", (const void *)GENERAL_NAMES_it());
    out_int("genn.it_stable", GENERAL_NAME_it() == GENERAL_NAME_it());

    /* dNSName: decode the fixed wire form, read the selector and re-encode byte-exactly. */
    p = GN_DNS;
    n1 = d2i_GENERAL_NAME(NULL, &p, (long)sizeof(GN_DNS));
    out_ptr("genn.dns", n1);
    out_int("genn.dns.type", n1 != NULL ? n1->type : -1);
    out_int("genn.dns.consumed", (long)(p - GN_DNS));
    len = i2d_GENERAL_NAME(n1, &der);
    out_hex("genn.dns.der", der, len);
    OPENSSL_free(der);
    der = NULL;
    {
        int t = -1;
        out_ptr("genn.dns.get0", GENERAL_NAME_get0_value(n1, &t));
        out_int("genn.dns.get0.type", t);
    }

    /* cmp: equal decodes are 0, a different tag is -1, a NULL argument is -1. */
    p = GN_DNS;
    n2 = d2i_GENERAL_NAME(NULL, &p, (long)sizeof(GN_DNS));
    out_int("genn.dns.cmp_same", GENERAL_NAME_cmp(n1, n2));
    GENERAL_NAME_free(n2);
    n2 = NULL;
    p = GN_IP;
    n2 = d2i_GENERAL_NAME(NULL, &p, (long)sizeof(GN_IP));
    out_int("genn.dns.cmp_other", GENERAL_NAME_cmp(n1, n2));
    out_int("genn.dns.cmp_null", GENERAL_NAME_cmp(n1, NULL));
    GENERAL_NAME_free(n2);
    n2 = NULL;
    GENERAL_NAME_free(n1);
    n1 = NULL;

    /* The remaining simple wire forms decode with their own selector. */
    p = GN_MAIL;
    n1 = d2i_GENERAL_NAME(NULL, &p, (long)sizeof(GN_MAIL));
    out_int("genn.mail.type", n1 != NULL ? n1->type : -1);
    GENERAL_NAME_free(n1);
    n1 = NULL;
    p = GN_URI;
    n1 = d2i_GENERAL_NAME(NULL, &p, (long)sizeof(GN_URI));
    out_int("genn.uri.type", n1 != NULL ? n1->type : -1);
    GENERAL_NAME_free(n1);
    n1 = NULL;
    p = GN_IP;
    n1 = d2i_GENERAL_NAME(NULL, &p, (long)sizeof(GN_IP));
    out_int("genn.ip.type", n1 != NULL ? n1->type : -1);
    GENERAL_NAME_free(n1);
    n1 = NULL;
    p = GN_RID;
    n1 = d2i_GENERAL_NAME(NULL, &p, (long)sizeof(GN_RID));
    out_int("genn.rid.type", n1 != NULL ? n1->type : -1);
    len = i2d_GENERAL_NAME(n1, &der);
    out_hex("genn.rid.der", der, len);
    OPENSSL_free(der);
    der = NULL;
    GENERAL_NAME_free(n1);
    n1 = NULL;

    /* otherName: the setter adopts a real ANY value, then dup and get0_otherName. */
    n1 = GENERAL_NAME_new();
    p = FIX_ANY_OCT;
    val = d2i_ASN1_TYPE(NULL, &p, (long)sizeof(FIX_ANY_OCT));
    out_ptr("genn.othn.value_in", val);
    oid = OBJ_nid2obj(NID_commonName);
    out_int("genn.othn.set", GENERAL_NAME_set0_othername(n1, oid, val));
    out_int("genn.othn.type", n1 != NULL ? n1->type : -1);
    {
        ASN1_OBJECT *poid = NULL;
        ASN1_TYPE *pval = NULL;
        out_int("genn.othn.get0", GENERAL_NAME_get0_otherName(n1, &poid, &pval));
        out_int("genn.othn.oid_nid", poid != NULL ? OBJ_obj2nid(poid) : -1);
        out_ptr("genn.othn.value", pval);
    }
    dup = GENERAL_NAME_dup(n1);
    out_ptr("genn.othn.dup", dup);
    out_int("genn.othn.dup.cmp", dup != NULL ? GENERAL_NAME_cmp(n1, dup) : -2);
    len = i2d_GENERAL_NAME(n1, &der);
    out_hex("genn.othn.der", der, len);
    OPENSSL_free(der);
    der = NULL;
    GENERAL_NAME_free(dup);
    dup = NULL;
    GENERAL_NAME_free(n1);
    n1 = NULL;

    /* directoryName via set1_X509_NAME (the NULL-DN case), plus the NULL-slot refusal. */
    ERR_clear_error();
    out_int("genn.dirname.set_null_dn", GENERAL_NAME_set1_X509_NAME(&tgt, NULL));
    out_err("genn.dirname.set_null_dn.err");
    out_ptr("genn.dirname", tgt);
    out_int("genn.dirname.type", tgt != NULL ? tgt->type : -1);
    len = i2d_GENERAL_NAME(tgt, &der);
    out_hex("genn.dirname.der", der, len);
    OPENSSL_free(der);
    der = NULL;
    GENERAL_NAME_free(tgt);
    tgt = NULL;
    ERR_clear_error();
    out_int("genn.dirname.null_tgt", GENERAL_NAME_set1_X509_NAME(NULL, NULL));
    out_err("genn.dirname.null_tgt.err");

    /* GENERAL_NAMES: the SEQUENCE OF over the two fixed names, and a re-encode. */
    p = GN_BOTH;
    names = d2i_GENERAL_NAMES(NULL, &p, (long)sizeof(GN_BOTH));
    out_ptr("genn.names", names);
    out_int("genn.names.num", names != NULL ? sk_GENERAL_NAME_num(names) : -1);
    out_int("genn.names.consumed", (long)(p - GN_BOTH));
    len = i2d_GENERAL_NAMES(names, &der);
    out_hex("genn.names.der", der, len);
    OPENSSL_free(der);
    der = NULL;
    p = GN_BOTH;
    names2 = d2i_GENERAL_NAMES(NULL, &p, (long)sizeof(GN_BOTH));
    out_int("genn.names.first.cmp",
            names != NULL && names2 != NULL
                ? GENERAL_NAME_cmp(sk_GENERAL_NAME_value(names, 0),
                                   sk_GENERAL_NAME_value(names2, 0))
                : -2);
    GENERAL_NAMES_free(names2);
    names2 = NULL;
    GENERAL_NAMES_free(names);
    names = NULL;
}

/* ---------------------------------------------------------------------------------------------
 * Phase 10.14.3 -- `crypto/x509/v3_utl.c`: the X.509v3 extension string/value utilities.
 *
 * The landed value/string helpers are driven directly: the `X509V3_parse_list` state machine's
 * four entry shapes and its two refusals, `X509V3_add_value` and its `_uchar`/`_bool`/`_bool_nf`
 * siblings, `X509V3_get_value_bool`/`_int` over a stack-local `CONF_VALUE`, the
 * `i2s_`/`s2i_ASN1_INTEGER` pair (sign and radix order, and the consumption refusal),
 * `i2s_ASN1_ENUMERATED`, the two `a2i_IPADDRESS` forms and `X509V3_NAME_from_section`. The nine
 * withheld functions (`X509_get1_email`/`_ocsp`/`X509_REQ_get1_email`, `do_x509_check` and its
 * four callers, `OSSL_GENERAL_NAMES_print`) are named in the module doc, not here: a probe cannot
 * link a symbol the candidate does not define. Every arm pops the error queue first (D455's
 * lesson).
 * --------------------------------------------------------------------------------------------- */

static void drive_x509_10_14_3_utl(void)
{
    STACK_OF(CONF_VALUE) *cv;
    ASN1_INTEGER *aint;
    ASN1_ENUMERATED *aenum;
    ASN1_OCTET_STRING *oct;
    char *s;
    int i;

    /* X509V3_parse_list: `name:value`, a bare name, a stripped-empty value and a refusal. */
    cv = X509V3_parse_list("a:b, c : d ,e");
    out_ptr("utl.parselist", cv);
    out_int("utl.parselist.num", cv != NULL ? (long)sk_CONF_VALUE_num(cv) : -1);
    if (cv != NULL) {
        for (i = 0; i < sk_CONF_VALUE_num(cv); i++) {
            CONF_VALUE *v = sk_CONF_VALUE_value(cv, i);
            printf("utl.parselist.%d.name=%s\n", i, v->name != NULL ? v->name : "<null>");
            printf("utl.parselist.%d.value=%s\n", i, v->value != NULL ? v->value : "<null>");
        }
    }
    sk_CONF_VALUE_pop_free(cv, X509V3_conf_free);

    ERR_clear_error();
    cv = X509V3_parse_list(":emptyname");
    out_ptr("utl.parselist.empty_name", cv);
    out_err("utl.parselist.empty_name.err");
    sk_CONF_VALUE_pop_free(cv, X509V3_conf_free);

    ERR_clear_error();
    cv = X509V3_parse_list("name:");
    out_ptr("utl.parselist.empty_value", cv);
    out_err("utl.parselist.empty_value.err");
    sk_CONF_VALUE_pop_free(cv, X509V3_conf_free);

    /* X509V3_add_value and the three typed spellings, into one stack. */
    cv = NULL;
    out_int("utl.add.value", X509V3_add_value("k", "v", &cv));
    out_int("utl.add.value_uchar",
            X509V3_add_value_uchar("u", (const unsigned char *)"w", &cv));
    out_int("utl.add.value_bool.true", X509V3_add_value_bool("bt", 1, &cv));
    out_int("utl.add.value_bool.false", X509V3_add_value_bool("bf", 0, &cv));
    out_int("utl.add.value_bool_nf.false", X509V3_add_value_bool_nf("bnf", 0, &cv));
    out_int("utl.add.num", cv != NULL ? (long)sk_CONF_VALUE_num(cv) : -1);
    if (cv != NULL) {
        for (i = 0; i < sk_CONF_VALUE_num(cv); i++) {
            CONF_VALUE *v = sk_CONF_VALUE_value(cv, i);
            printf("utl.add.%d.name=%s\n", i, v->name != NULL ? v->name : "<null>");
            printf("utl.add.%d.value=%s\n", i, v->value != NULL ? v->value : "<null>");
        }
    }
    sk_CONF_VALUE_pop_free(cv, X509V3_conf_free);

    /* X509V3_get_value_bool / _int over a stack-local CONF_VALUE. */
    {
        CONF_VALUE tv = { NULL, (char *)"b", (char *)"yes" };
        CONF_VALUE fv = { NULL, (char *)"b", (char *)"no" };
        CONF_VALUE nv = { NULL, (char *)"b", (char *)"maybe" };
        CONF_VALUE iv = { NULL, (char *)"i", (char *)"0x1f" };
        int b = -1;
        ASN1_INTEGER *got = NULL;

        ERR_clear_error();
        out_int("utl.getval.bool.true", X509V3_get_value_bool(&tv, &b));
        out_int("utl.getval.bool.true.val", b);
        b = -1;
        out_int("utl.getval.bool.false", X509V3_get_value_bool(&fv, &b));
        out_int("utl.getval.bool.false.val", b);
        out_int("utl.getval.bool.bad", X509V3_get_value_bool(&nv, &b));
        out_err("utl.getval.bool.bad.err");

        ERR_clear_error();
        out_int("utl.getval.int", X509V3_get_value_int(&iv, &got));
        out_ptr("utl.getval.int.aint", got);
        s = i2s_ASN1_INTEGER(NULL, got);
        out_str("utl.getval.int.text", s);
        OPENSSL_free(s);
        ASN1_INTEGER_free(got);
    }

    /* i2s_/s2i_ASN1_INTEGER: the sign/radix order and the consumption refusal. */
    ERR_clear_error();
    aint = s2i_ASN1_INTEGER(NULL, "-0x10");
    out_ptr("utl.s2i.int", aint);
    out_err("utl.s2i.int.err");
    s = i2s_ASN1_INTEGER(NULL, aint);
    out_str("utl.i2s.int", s);
    OPENSSL_free(s);
    ASN1_INTEGER_free(aint);

    ERR_clear_error();
    out_ptr("utl.s2i.int.bad", s2i_ASN1_INTEGER(NULL, "12x"));
    out_err("utl.s2i.int.bad.err");
    ERR_clear_error();
    out_ptr("utl.s2i.int.null", s2i_ASN1_INTEGER(NULL, NULL));
    out_err("utl.s2i.int.null.err");

    aenum = ASN1_ENUMERATED_new();
    ASN1_ENUMERATED_set(aenum, 255);
    s = i2s_ASN1_ENUMERATED(NULL, aenum);
    out_str("utl.i2s.enum", s);
    OPENSSL_free(s);
    ASN1_ENUMERATED_free(aenum);

    /* i2s_ASN1_ENUMERATED_TABLE (Phase 10.14, `v3_enum.c`): the `usr_data` name-table hit and the
     * fallback miss. The row the machinery builds is `ossl_v3_crl_reason`, whose `usr_data` is the
     * static `crl_reasons[]`; that array is not nameable from here, so this drives the *function*
     * with a local table of the same shape (`bitnum`/`lname`/`sname`, terminated by a null
     * `lname`). The hit answers the long name; the miss falls through to `i2s_ASN1_ENUMERATED`. */
    {
        BIT_STRING_BITNAME names[] = {
            { 1, "One", "one" },
            { 2, "Two", "two" },
            { -1, NULL, NULL }
        };
        struct v3_ext_method meth;
        ASN1_ENUMERATED *e2 = ASN1_ENUMERATED_new();

        memset(&meth, 0, sizeof(meth));
        meth.usr_data = names;
        ASN1_ENUMERATED_set(e2, 2);
        ERR_clear_error();
        s = i2s_ASN1_ENUMERATED_TABLE(&meth, e2);
        out_str("utl.enum_table.hit", s);
        out_err("utl.enum_table.hit.err");
        OPENSSL_free(s);
        ASN1_ENUMERATED_set(e2, 7);
        ERR_clear_error();
        s = i2s_ASN1_ENUMERATED_TABLE(&meth, e2);
        out_str("utl.enum_table.miss", s);
        out_err("utl.enum_table.miss.err");
        OPENSSL_free(s);
        ASN1_ENUMERATED_free(e2);
    }

    /* The address conversions, both forms and the refusals. */
    oct = a2i_IPADDRESS("192.0.2.1");
    out_ptr("utl.a2i.v4", oct);
    if (oct != NULL)
        out_hex("utl.a2i.v4.der", ASN1_STRING_get0_data(oct), ASN1_STRING_length(oct));
    ASN1_OCTET_STRING_free(oct);

    oct = a2i_IPADDRESS("2001:db8::1");
    out_ptr("utl.a2i.v6", oct);
    if (oct != NULL)
        out_hex("utl.a2i.v6.der", ASN1_STRING_get0_data(oct), ASN1_STRING_length(oct));
    ASN1_OCTET_STRING_free(oct);

    ERR_clear_error();
    out_ptr("utl.a2i.bad", a2i_IPADDRESS("not-an-ip"));
    out_err("utl.a2i.bad.err");

    oct = a2i_IPADDRESS_NC("10.0.0.0/255.0.0.0");
    out_ptr("utl.a2i.nc", oct);
    if (oct != NULL)
        out_hex("utl.a2i.nc.der", ASN1_STRING_get0_data(oct), ASN1_STRING_length(oct));
    ASN1_OCTET_STRING_free(oct);

    ERR_clear_error();
    out_ptr("utl.a2i.nc.noslash", a2i_IPADDRESS_NC("10.0.0.0"));
    out_err("utl.a2i.nc.noslash.err");

    /* X509V3_NAME_from_section over a two-entry pair stack, printed one-line. */
    cv = NULL;
    X509V3_add_value("CN", "probe.example", &cv);
    X509V3_add_value("+O", "org", &cv);
    {
        X509_NAME *nm = X509_NAME_new();
        char text[256];
        memset(text, 0, sizeof(text));
        out_int("utl.name_from_section", X509V3_NAME_from_section(nm, cv, MBSTRING_ASC));
        out_ptr("utl.name_from_section.text", X509_NAME_oneline(nm, text, (int)sizeof(text)));
        printf("utl.name_from_section.oneline=%s\n", text);
        out_int("utl.name_from_section.count", (long)X509_NAME_entry_count(nm));
        X509_NAME_free(nm);
    }
    sk_CONF_VALUE_pop_free(cv, X509V3_conf_free);

    /* X509_email_free over a NULL stack, the pop-free no-op. */
    X509_email_free(NULL);
    out_int("utl.email_free.null", 1);
}

/* ---------------------------------------------------------------------------------------------
 * Phase 10.14.5 -- `crypto/x509/x509_ext.c`'s `X509`/`X509_CRL` extension accessors.
 *
 * The accessors are one-line delegations to `x509_v3.c`'s list primitives, driven over the fixed
 * certificate and CRL: the counts, the by-NID/by-OBJ/by-critical searches (present and absent),
 * the by-index fetch (in and out of range), and the add/delete pair including the empty-list
 * collapse `delete_ext` performs. Every arm pops the error queue first.
 * --------------------------------------------------------------------------------------------- */

static void drive_x509_10_14_5_ext(void)
{
    const unsigned char *p = RT_X509_CERT_DER;
    const unsigned char *q = RT_X509_CRL_DER;
    X509 *cert = d2i_X509(NULL, &p, (long)RT_X509_CERT_DER_LEN);
    X509_CRL *crl = d2i_X509_CRL(NULL, &q, (long)RT_X509_CRL_DER_LEN);
    X509_EXTENSION *ex, *made, *removed;
    ASN1_OCTET_STRING *d = ASN1_OCTET_STRING_new();
    int before;

    ERR_clear_error();
    out_int("ext.cert.count", (long)X509_get_ext_count(cert));
    out_int("ext.cert.by_nid.bcons",
            (long)X509_get_ext_by_NID(cert, NID_basic_constraints, -1));
    out_int("ext.cert.by_nid.miss",
            (long)X509_get_ext_by_NID(cert, NID_subject_alt_name, -1));
    out_int("ext.cert.by_crit.1", (long)X509_get_ext_by_critical(cert, 1, -1));
    out_int("ext.cert.by_crit.0", (long)X509_get_ext_by_critical(cert, 0, -1));
    ex = X509_get_ext(cert, 0);
    out_ptr("ext.cert.get.0", ex);
    out_int("ext.cert.get.0.nid", (long)OBJ_obj2nid(X509_EXTENSION_get_object(ex)));
    out_ptr("ext.cert.get.99", X509_get_ext(cert, 99));
    out_int("ext.cert.by_obj",
            (long)X509_get_ext_by_OBJ(cert, X509_EXTENSION_get_object(ex), -1));

    /* `X509_add_ext` appends a duplicate; `X509_delete_ext` removes the first and, on an
     * emptied list, drops the list itself (`delete_ext`'s collapse). */
    ASN1_OCTET_STRING_set(d, (const unsigned char *)"BC", 2);
    made = X509_EXTENSION_create_by_NID(NULL, NID_basic_constraints, 1, d);
    before = X509_get_ext_count(cert);
    out_int("ext.cert.add", X509_add_ext(cert, made, -1));
    out_int("ext.cert.add.delta", (long)(X509_get_ext_count(cert) - before));
    removed = X509_delete_ext(cert, 0);
    out_ptr("ext.cert.delete.0", removed);
    X509_EXTENSION_free(removed);
    while ((removed = X509_delete_ext(cert, 0)) != NULL)
        X509_EXTENSION_free(removed);
    out_int("ext.cert.count.empty", (long)X509_get_ext_count(cert));
    out_ptr("ext.cert.get.empty", X509_get_ext(cert, 0));
    X509_EXTENSION_free(made);

    out_int("ext.crl.count", (long)X509_CRL_get_ext_count(crl));
    out_int("ext.crl.by_nid", (long)X509_CRL_get_ext_by_NID(crl, NID_crl_number, -1));
    out_ptr("ext.crl.get.0", X509_CRL_get_ext(crl, 0));
    out_ptr("ext.crl.get.99", X509_CRL_get_ext(crl, 99));
    out_int("ext.crl.by_crit.0", (long)X509_CRL_get_ext_by_critical(crl, 0, -1));

    ASN1_OCTET_STRING_free(d);
    X509_free(cert);
    X509_CRL_free(crl);
}

/* ---------------------------------------------------------------------------------------------
 * Phase 10.14.6 -- `crypto/x509/v3_crld.c`'s `DIST_POINT_set_dpname`.
 *
 * The binder's three reachable shapes are driven over the fixed certificate's issuer name: a NULL
 * `DIST_POINT_NAME` and a `type != 1` both answer 1 and touch nothing; a `type == 1` with an empty
 * relative-name fragment duplicates the issuer and generates its encoding. Every arm pops the
 * error queue first, and no pointer address is printed -- only the `dpname` NULL/non-NULL fact.
 * --------------------------------------------------------------------------------------------- */

static void drive_x509_10_14_6_crld(void)
{
    const unsigned char *p = RT_X509_CERT_DER;
    X509 *cert = d2i_X509(NULL, &p, (long)RT_X509_CERT_DER_LEN);
    const X509_NAME *issuer = X509_get_issuer_name(cert);
    DIST_POINT_NAME dpn;

    ERR_clear_error();
    memset(&dpn, 0, sizeof(dpn));

    out_int("crld.set_dpname.null", DIST_POINT_set_dpname(NULL, issuer));
    dpn.type = 0;
    out_int("crld.set_dpname.type0", DIST_POINT_set_dpname(&dpn, issuer));
    out_ptr("crld.set_dpname.type0.dpname", dpn.dpname);

    dpn.type = 1;
    dpn.name.relativename = NULL;
    out_int("crld.set_dpname.type1", DIST_POINT_set_dpname(&dpn, issuer));
    out_ptr("crld.set_dpname.type1.dpname", dpn.dpname);
    out_int("crld.set_dpname.type1.count",
            (long)(dpn.dpname != NULL ? X509_NAME_entry_count(dpn.dpname) : -1));
    X509_NAME_free(dpn.dpname);
    X509_free(cert);

    /* The `BASIC_CONSTRAINTS` item group: build, set both fields, encode, decode the bytes back,
     * re-encode and compare, then free. `BASIC_CONSTRAINTS_free` is the seventh name
     * `ossl_x509v3_cache_extensions` needs, so driving it here is what makes it real. */
    {
        BASIC_CONSTRAINTS *bc = BASIC_CONSTRAINTS_new();
        unsigned char *der1 = NULL, *der2 = NULL;
        const unsigned char *q;
        BASIC_CONSTRAINTS *bc2;
        ASN1_INTEGER *pl;
        int len1, len2;

        ERR_clear_error();
        out_ptr("bcons.new", bc);
        out_ptr("bcons.it", (const void *)BASIC_CONSTRAINTS_it());
        bc->ca = 1;
        pl = ASN1_INTEGER_new();
        ASN1_INTEGER_set(pl, 3);
        bc->pathlen = pl;
        len1 = i2d_BASIC_CONSTRAINTS(bc, &der1);
        out_int("bcons.i2d.len", (long)len1);
        q = der1;
        bc2 = d2i_BASIC_CONSTRAINTS(NULL, &q, (long)len1);
        out_ptr("bcons.d2i", bc2);
        out_int("bcons.d2i.ca", (long)(bc2 != NULL ? bc2->ca : -2));
        out_int("bcons.d2i.pathlen",
                (long)(bc2 != NULL && bc2->pathlen != NULL ? ASN1_INTEGER_get(bc2->pathlen)
                                                           : -2));
        len2 = i2d_BASIC_CONSTRAINTS(bc2, &der2);
        out_int("bcons.reequal",
                (long)(len1 == len2 && len1 > 0 && der1 != NULL && der2 != NULL
                       && memcmp(der1, der2, (size_t)len1) == 0));
        BASIC_CONSTRAINTS_free(bc2);
        BASIC_CONSTRAINTS_free(bc);
        OPENSSL_free(der1);
        OPENSSL_free(der2);
    }
}

/* ---------------------------------------------------------------------------------------------
 * Phase 10.16 -- the `file` `OSSL_OP_STORE` provider row.
 *
 * `OSSL_STORE_LOADER_fetch(NULL, "file", NULL)` reaches `deflt_query`'s/`base_query`'s
 * `OSSL_OP_STORE` arm, runs `construct_loader` and resolves the row through its
 * open/attach/load/eof/close callbacks; `OSSL_STORE_LOADER_do_all_provided` then finds the row in
 * both the default (fallback) and the base provider. Both providers are loaded explicitly so the
 * sweep is deterministic, and every arm pops its own error queue first (D455's lesson).
 * --------------------------------------------------------------------------------------------- */

static void drive_file_store_row(void)
{
    OSSL_STORE_LOADER *file_loader;
    OSSL_STORE_CTX *ctx;
    OSSL_PROVIDER *d;
    OSSL_PROVIDER *b;

    ERR_clear_error();
    d = OSSL_PROVIDER_load(NULL, "default");
    b = OSSL_PROVIDER_load(NULL, "base");
    out_ptr("store.file.provider.default", d);
    out_ptr("store.file.provider.base", b);

    ERR_clear_error();
    file_loader = OSSL_STORE_LOADER_fetch(NULL, "file", NULL);
    out_ptr("store.file.fetch", file_loader);
    out_err("store.file.fetch.err");
    if (file_loader != NULL)
        OSSL_STORE_LOADER_free(file_loader);

    ERR_clear_error();
    g_provider_do_all_count = 0;
    OSSL_STORE_LOADER_do_all_provided(NULL, provider_do_all_cb, NULL);
    out_int("store.file.do_all.count", g_provider_do_all_count);

    /* The fetched `OSSL_STORE_find` arms, over a real `file:` context. `/dev/null` stat()s and
     * opens on the admitted profile and is not a directory, so the `subject`/`issuer` parameters
     * take file_store.c's `SEARCH_ONLY_SUPPORTED_FOR_DIRECTORIES` refusal -- the same answer on
     * both sides. This is what the pre-10.16 probe could only name pending. */
    ERR_clear_error();
    ctx = OSSL_STORE_open("file:/dev/null", NULL, NULL, NULL, NULL);
    out_ptr("store.file.find.open", ctx);
    out_err("store.file.find.open.err");
    if (ctx != NULL) {
        X509_NAME *nm = X509_NAME_new();
        OSSL_STORE_SEARCH *by_name = OSSL_STORE_SEARCH_by_name(nm);

        ERR_clear_error();
        out_int("store.file.find.by_name", OSSL_STORE_find(ctx, by_name));
        out_err("store.file.find.by_name.err");
        OSSL_STORE_SEARCH_free(by_name);
        X509_NAME_free(nm);

        out_int("store.file.find.close", OSSL_STORE_close(ctx));
        out_err("store.file.find.close.err");
    }
}

/* ---------------------------------------------------------------------------------------------
 * Phase 10.14's three hubs -- the general-name printers (`v3_san.c`), the extension-configuration
 * value/section layer (`v3_conf.c`) and, through them, the attribute-value printer
 * (`x_attrib.c`).
 *
 * `GENERAL_NAME_print`/`i2v_GENERAL_NAME`/`i2v_GENERAL_NAMES`/`OSSL_GENERAL_NAMES_print` are
 * driven over hand-built general names of every payload-free and payload-bearing kind; the
 * `X509V3_get_section`/`_get_string` layer is driven over a real `NCONF` loaded from a memory BIO,
 * with the no-database, `lhash`-NULL and `set_issuer_pkey` refusals as the refusal arms. Every arm
 * clears the error queue first (D455).
 * --------------------------------------------------------------------------------------------- */

/* A `STACK_OF(CONF_VALUE)` as `name|value` per element. */
static void out_conf_stack(const char *key, STACK_OF(CONF_VALUE) *st)
{
    int i, n = st != NULL ? sk_CONF_VALUE_num(st) : -1;

    out_int(key, (long)n);
    for (i = 0; i < n; i++) {
        const CONF_VALUE *v = sk_CONF_VALUE_value(st, i);
        printf("%s.%d=%s|%s\n", key, i, v->name != NULL ? v->name : "null",
               v->value != NULL ? v->value : "null");
    }
}

/* `GENERAL_NAME_print` into a memory BIO, printed as `key.ret` and `key.text`. */
static void out_gen_print(const char *key, GENERAL_NAME *g)
{
    BIO *b = BIO_new(BIO_s_mem());
    char text[256];
    int n, r;

    if (b == NULL)
        return;
    memset(text, 0, sizeof(text));
    n = GENERAL_NAME_print(b, g);
    r = BIO_read(b, text, (int)sizeof(text) - 1);
    text[r > 0 ? r : 0] = 0;
    printf("%s.ret=%d\n", key, n);
    printf("%s.text=%s\n", key, text);
    BIO_free(b);
}

static GENERAL_NAME *make_ia5_gen(int type, const char *value)
{
    GENERAL_NAME *g = GENERAL_NAME_new();

    if (g == NULL)
        return NULL;
    g->type = type;
    g->d.ia5 = ASN1_IA5STRING_new();
    if (g->d.ia5 == NULL || !ASN1_STRING_set(g->d.ia5, value, -1)) {
        GENERAL_NAME_free(g);
        return NULL;
    }
    return g;
}

static void drive_v3_hubs(void)
{
    static const unsigned char ip4[4] = { 10, 0, 0, 1 };
    static const char cfg[] = "[sec]\nkey=value\n";
    X509V3_CTX ctx;
    CONF *conf;
    BIO *cb, *b;
    long eline = 0;
    GENERAL_NAME *email, *dns, *uri, *ip, *rid, *dn, *x400, *edi;
    GENERAL_NAMES *gens;
    STACK_OF(CONF_VALUE) *st;
    char *s;
    const unsigned char *p;
    char text[256];
    int n, r;

    /* ----- the general-name printers over hand-built names ----- */
    email = make_ia5_gen(GEN_EMAIL, "probe@example.com");
    dns = make_ia5_gen(GEN_DNS, "www.example.com");
    uri = make_ia5_gen(GEN_URI, "http://example.com/");
    out_ptr("gen.email.new", email);
    out_gen_print("gen.email.print", email);
    out_gen_print("gen.dns.print", dns);
    out_gen_print("gen.uri.print", uri);

    ip = GENERAL_NAME_new();
    if (ip != NULL) {
        ip->type = GEN_IPADD;
        ip->d.iPAddress = ASN1_OCTET_STRING_new();
        ASN1_OCTET_STRING_set(ip->d.iPAddress, ip4, 4);
    }
    out_gen_print("gen.ip.print", ip);

    rid = GENERAL_NAME_new();
    if (rid != NULL) {
        rid->type = GEN_RID;
        rid->d.registeredID = OBJ_txt2obj("1.2.3.4", 0);
    }
    out_gen_print("gen.rid.print", rid);

    p = RT_X509_NAME_DER;
    dn = GENERAL_NAME_new();
    if (dn != NULL) {
        dn->type = GEN_DIRNAME;
        dn->d.directoryName = d2i_X509_NAME(NULL, &p, (long)RT_X509_NAME_DER_LEN);
    }
    out_gen_print("gen.dirname.print", dn);

    x400 = GENERAL_NAME_new();
    if (x400 != NULL)
        x400->type = GEN_X400;
    edi = GENERAL_NAME_new();
    if (edi != NULL)
        edi->type = GEN_EDIPARTY;
    out_gen_print("gen.x400.print", x400);
    out_gen_print("gen.edi.print", edi);

    /* ----- the `i2v` printers, each answering a fresh CONF_VALUE stack ----- */
    st = i2v_GENERAL_NAME(NULL, email, NULL);
    out_conf_stack("gen.email.i2v", st);
    sk_CONF_VALUE_pop_free(st, X509V3_conf_free);
    st = i2v_GENERAL_NAME(NULL, dns, NULL);
    out_conf_stack("gen.dns.i2v", st);
    sk_CONF_VALUE_pop_free(st, X509V3_conf_free);
    st = i2v_GENERAL_NAME(NULL, uri, NULL);
    out_conf_stack("gen.uri.i2v", st);
    sk_CONF_VALUE_pop_free(st, X509V3_conf_free);
    st = i2v_GENERAL_NAME(NULL, ip, NULL);
    out_conf_stack("gen.ip.i2v", st);
    sk_CONF_VALUE_pop_free(st, X509V3_conf_free);
    st = i2v_GENERAL_NAME(NULL, rid, NULL);
    out_conf_stack("gen.rid.i2v", st);
    sk_CONF_VALUE_pop_free(st, X509V3_conf_free);
    st = i2v_GENERAL_NAME(NULL, dn, NULL);
    out_conf_stack("gen.dirname.i2v", st);
    sk_CONF_VALUE_pop_free(st, X509V3_conf_free);
    st = i2v_GENERAL_NAME(NULL, x400, NULL);
    out_conf_stack("gen.x400.i2v", st);
    sk_CONF_VALUE_pop_free(st, X509V3_conf_free);
    st = i2v_GENERAL_NAME(NULL, edi, NULL);
    out_conf_stack("gen.edi.i2v", st);
    sk_CONF_VALUE_pop_free(st, X509V3_conf_free);

    /* ----- `i2v_GENERAL_NAMES` and `OSSL_GENERAL_NAMES_print` over a two-element stack ----- */
    gens = sk_GENERAL_NAME_new_null();
    sk_GENERAL_NAME_push(gens, email);
    sk_GENERAL_NAME_push(gens, dns);
    st = i2v_GENERAL_NAMES(NULL, gens, NULL);
    out_conf_stack("gen.multi.i2v", st);
    sk_CONF_VALUE_pop_free(st, X509V3_conf_free);
    b = BIO_new(BIO_s_mem());
    memset(text, 0, sizeof(text));
    n = OSSL_GENERAL_NAMES_print(b, gens, 0);
    r = BIO_read(b, text, (int)sizeof(text) - 1);
    text[r > 0 ? r : 0] = 0;
    out_int("gen.names.print.ret", (long)n);
    out_str("gen.names.print.text", text);
    BIO_free(b);

    /* ----- the `v3_conf.c` config-value layer ----- */
    ERR_clear_error();
    conf = NCONF_new(NULL);
    out_ptr("v3conf.conf", conf);
    cb = BIO_new_mem_buf(cfg, -1);
    out_int("v3conf.load", (long)NCONF_load_bio(conf, cb, &eline));
    out_err("v3conf.load.err");
    BIO_free(cb);

    /* No database: `X509V3_set_ctx` clears `db`/`db_meth`, so both accessors refuse. */
    X509V3_set_ctx(&ctx, NULL, NULL, NULL, NULL, 0);
    ERR_clear_error();
    out_ptr("v3conf.section.nodb", X509V3_get_section(&ctx, "sec"));
    out_err("v3conf.section.nodb.err");
    ERR_clear_error();
    out_ptr("v3conf.string.nodb", X509V3_get_string(&ctx, "sec", "key"));
    out_err("v3conf.string.nodb.err");

    /* The nconf method: a real section and a real string. */
    X509V3_set_nconf(&ctx, conf);
    ERR_clear_error();
    st = X509V3_get_section(&ctx, "sec");
    out_ptr("v3conf.section", st);
    out_err("v3conf.section.err");
    X509V3_section_free(&ctx, st);
    ERR_clear_error();
    s = X509V3_get_string(&ctx, "sec", "key");
    out_str("v3conf.string", s);
    out_err("v3conf.string.err");
    X509V3_string_free(&ctx, s);

    /* The lhash method with a NULL database refuses identically. */
    X509V3_set_conf_lhash(&ctx, NULL);
    ERR_clear_error();
    out_ptr("v3conf.section.lhashnull", X509V3_get_section(&ctx, "sec"));
    out_err("v3conf.section.lhashnull.err");

    /* `set_issuer_pkey`: a NULL key is accepted; a key with no subject refuses. */
    X509V3_set_ctx(&ctx, NULL, NULL, NULL, NULL, 0);
    ERR_clear_error();
    out_int("v3conf.issuer_pkey.null", (long)X509V3_set_issuer_pkey(&ctx, NULL));
    out_err("v3conf.issuer_pkey.null.err");
    ERR_clear_error();
    out_int("v3conf.issuer_pkey.nosubject",
            (long)X509V3_set_issuer_pkey(&ctx, (EVP_PKEY *)&eline));
    out_err("v3conf.issuer_pkey.nosubject.err");

    NCONF_free(conf);

    sk_GENERAL_NAME_pop_free(gens, GENERAL_NAME_free);
}

int main(void)
{
    OSSL_STORE_LOADER *loader;
    OSSL_STORE_LOADER *bad;
    OSSL_STORE_LOADER *incomplete;
    OSSL_STORE_LOADER *removed;
    const char *scheme = "probe";
    /* The published row's scheme literal. `provider_court_coverage.py`'s join reads it, and
     * `drive_file_store_row` below passes it to the fetch and the provider walk. */
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

    /* ----- Phase 10.14.2: the certificate faces, the defaults and the Netscape SPKI object ----- */
    drive_x509_all_surface();

    /* ----- Phase 10.14.4: the GENERAL_NAME / GENERAL_NAMES items and accessors ----- */
    drive_x509_10_14_4_genn();

    /* ----- Phase 10.14.3: the X.509v3 extension string/value utilities ----- */
    drive_x509_10_14_3_utl();

    /* ----- Phase 10.14.5: the certificate/CRL extension accessors ----- */
    drive_x509_10_14_5_ext();

    /* ----- Phase 10.14.6: the CRL distribution point name binder ----- */
    drive_x509_10_14_6_crld();

    drive_v3_hubs();

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

    drive_file_store_row();

    out_pending();
    return 0;
}
