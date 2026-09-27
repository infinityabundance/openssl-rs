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
 * The blockage is **per function** (docs/DECISIONS.md D448, corrected by the second 10.5 pass),
 * and the three exports this probe does not call are named below with their measured blockers:
 *
 *  * `OSSL_STORE_load` -- its fetched branch calls `store_result.c`'s
 *    `ossl_store_handle_load_result`, which needs `d2i_X509`/`d2i_X509_AUX`/`d2i_X509_CRL`
 *    (Phase 11) and `PKCS12_parse` (10.3-withheld).
 *  * `OSSL_STORE_INFO_get1_CERT`/`get1_CRL` -- they call `X509_up_ref`/`X509_CRL_up_ref` (Phase
 *    11). The carved arms of `OSSL_STORE_INFO_free` (CERT/CRL, `X509_free`/`X509_CRL_free`) and
 *    of `OSSL_STORE_find` (BY_NAME/BY_ISSUER_SERIAL, `i2d_X509_NAME`) are named too.
 *  * the two `OSSL_OP_STORE` provider rows (`file`) -- so `OSSL_STORE_LOADER_fetch` and
 *    `OSSL_STORE_LOADER_do_all_provided` stay **address-taken only**, and the refused paths are
 *    driven through the legacy registry instead.
 *
 * Everything printed is a literal, a string, or a `nonnull`/`null`/int answer; no pointer
 * address is ever printed (the two sides allocate differently, and `probe_hygiene.py` would
 * catch it).
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/store.h>

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
 * A whole block of what this pass withholds, printed identically on both sides.
 * --------------------------------------------------------------------------------------------- */

static void out_pending(void)
{
    printf("pending.OSSL_STORE_LOADER_fetch=file_store_provider_row_unpublished\n");
    printf("pending.OSSL_STORE_LOADER_do_all_provided=file_store_provider_row_unpublished\n");
    printf("pending.OSSL_STORE_load=store_result_ossl_store_handle_load_result\n");
    printf("pending.OSSL_STORE_INFO_get1_CERT=phase11_x509_up_ref\n");
    printf("pending.OSSL_STORE_INFO_get1_CRL=phase11_x509_crl_up_ref\n");
    printf("pending.OSSL_STORE_INFO_free.cert_arm=phase11_x509_free\n");
    printf("pending.OSSL_STORE_INFO_free.crl_arm=phase11_x509_crl_free\n");
    printf("pending.OSSL_STORE_find.by_name=phase11_i2d_X509_NAME\n");
    printf("pending.OSSL_STORE_find.by_issuer_serial=phase11_i2d_X509_NAME\n");
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

    out_pending();
    return 0;
}
