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
 * This probe drives the part of 10.5 whose closure is landed: the `OSSL_STORE_LOADER` object
 * (`OSSL_STORE_LOADER_new`, the ten setters, the by-name accessors and the refcount pair), the
 * process-global scheme registry (`OSSL_STORE_register_loader`/`_unregister_loader`/
 * `OSSL_STORE_do_all_loaders`) and the `OSSL_STORE_INFO` type-name table
 * (`OSSL_STORE_INFO_type_string`). It drives the refusal arms the authority refuses: a NULL
 * scheme to `OSSL_STORE_LOADER_new`, a scheme that fails RFC 3986's syntax, and a loader whose
 * `load` is NULL -- each with its error queue coordinate.
 *
 * What it cannot drive, and prints as `pending.`
 * ----------------------------------------------
 * Two things are outside this pass, and both are the same blocker one level up:
 *
 *  * the two `OSSL_OP_STORE` provider rows (`file`, `forensics/atlas/provider-algorithms.json`)
 *    are published by `providers/implementations/storemgmt/file_store.c`, whose decoder chain
 *    and result path reach `store_result.c` and Phase 11's `X509` object. They are
 *    `unimplemented`, so `OSSL_STORE_LOADER_fetch` and `OSSL_STORE_LOADER_do_all_provided`
 *    would behave differently on the two sides -- the authority answers a real `file` loader
 *    and the candidate answers NULL -- and are therefore **address-taken only**: the reference
 *    is what `court_coverage.py` reads (basis `referenced`), and the row's blocker is named
 *    here rather than papered over.
 *  * `store_lib.c`'s `OSSL_STORE_CTX` state machine and `OSSL_STORE_INFO`/`OSSL_STORE_SEARCH`
 *    object model, whose CERT/CRL arms and `OSSL_STORE_find` reach Phase 11's `X509` (`X509_free`,
 *    `X509_up_ref`, `d2i_X509`, `i2d_X509_NAME`), and whose `OSSL_STORE_load` reaches
 *    `store_result.c`. Section 3.5: a row that cannot be driven is named, not silently passed.
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
 * callbacks are never invoked by this probe: the state machine that would call them is
 * `store_lib.c`'s and is withheld.
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
    if (with_load)
        OSSL_STORE_LOADER_set_load(loader, probe_load);
    OSSL_STORE_LOADER_set_eof(loader, probe_eof);
    OSSL_STORE_LOADER_set_error(loader, probe_error);
    OSSL_STORE_LOADER_set_close(loader, probe_close);
    return loader;
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
 * A whole block of what this pass withholds, printed identically on both sides.
 * --------------------------------------------------------------------------------------------- */

static void out_pending(void)
{
    printf("pending.OSSL_STORE_LOADER_fetch=file_store_provider_row_unpublished\n");
    printf("pending.OSSL_STORE_LOADER_do_all_provided=file_store_provider_row_unpublished\n");
    printf("pending.OSSL_STORE_open=store_lib_state_machine_withheld\n");
    printf("pending.OSSL_STORE_load=store_result_needs_phase11_x509\n");
    printf("pending.OSSL_STORE_INFO_new_CERT=phase11_x509\n");
    printf("pending.OSSL_STORE_INFO_get1_PKEY=store_lib_object_model_withheld\n");
    printf("pending.OSSL_STORE_SEARCH_by_name=store_lib_object_model_withheld\n");
    printf("pending.OSSL_STORE_find=phase11_i2d_X509_NAME\n");
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

    /* ----- the two provider-fetch exports: referenced, not called ----- */
    g_ref_fetch = (void (*)(void))OSSL_STORE_LOADER_fetch;
    g_ref_do_all = (void (*)(void))OSSL_STORE_LOADER_do_all_provided;
    printf("ref.OSSL_STORE_LOADER_fetch=%s\n", g_ref_fetch != NULL ? "nonnull" : "null");
    printf("ref.OSSL_STORE_LOADER_do_all_provided=%s\n", g_ref_do_all != NULL ? "nonnull" : "null");
    out_str("ref.file_scheme", file_scheme);

    out_pending();
    return 0;
}
