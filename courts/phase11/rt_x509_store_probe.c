/*
 * RT-X509-STORE -- the Phase 11.1/11.4 X.509 store/lookup/object and mutator surface, driven.
 *
 * This is the first *behavioural* court of the X.509 stratum: one C program, compiled once
 * against the admitted authority and once against the candidate distribution shell, whose two
 * transcripts are diffed line by line. Every observation is a small integer, a byte-for-byte
 * equality, a `nonnull`/`null`, or an error coordinate (`lib.reason`) -- never an address and
 * never an allocator-dependent value, so the transcript is a function of the library and not of
 * the probe's own frame (`probe_hygiene.py` compiles it at -O0/-O1/-O2 and requires that).
 *
 * The fixtures are fixed and embedded (`rt_x509_der.h`): the `root-cert.pem` certificate, the
 * `testcrl.pem` CRL, and `test/certs/x509-check.csr` with its leading `X509_REQ_INFO` lifted
 * out. Both sides decode the same bytes; the error queue is popped at the start of every arm.
 *
 * What it drives, and what it deliberately does not
 * -------------------------------------------------
 * It **calls** the `X509_LOOKUP_METHOD` vtable (`x509_meth.c`), the `X509_LOOKUP` object and
 * its five `by_*` dispatch doors and three method-data/store accessors, the `X509_OBJECT`
 * accessors/updaters and its by-subject index/retrieve trio over a caller-built stack, the four
 * `X509_STORE_*` arms that reach their refusal without a store (`add_cert`/`add_crl` with a NULL
 * object and the two object-cache readers with a NULL store, each with its error coordinate),
 * the whole `X509_set_*`/`X509_get0_*`/`X509_getm_*` mutator layer over a fixed `X509`, and the
 * `X509_REQ` mutators, attribute accessors, the `X509_REQ_INFO`/`X509_REQ` item group and
 * lifecycle over the fixed request DER.
 *
 * It does **not** call anything that needs an `X509_STORE` or an `X509_STORE_CTX` it cannot
 * obtain. The stratum withholds `X509_STORE_new`/`X509_STORE_CTX_new` (their blocker is
 * `X509_VERIFY_PARAM`, 11.2's `x509_vpm.c`), and the candidate's shell answers a call to either
 * with `abort` (`artifacts/phase2/shell/libcrypto.shell.rs`) -- so the store's registry
 * (`X509_STORE_add_lookup`), its object-cache readers that dereference a store
 * (`X509_STORE_get0_objects`, `X509_STORE_get0_param`), their `up_ref`/locks, the twenty-six
 * callback `set_*`/`get_*` pairs and the whole `X509_STORE_CTX_*` read path are **not driven
 * here**; they are covered by `RT-X509-REF` at basis `referenced`, the weaker true statement,
 * as are `X509_SIG_INFO_get` (its argument type `X509_SIG_INFO` is opaque in `x509.h`, so
 * driving it means re-declaring the struct) and `X509_get_signature_info` (it runs
 * `X509_check_purpose` and then reads the cached `siginf`, whose digest-name lookup is the
 * crate's recorded `EVP_get_digestbyname` divergence D333/D343; driving it would compare that
 * divergence, not this unit's contract, so it is left to the reference basis and named here).
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include "rt_x509_der.h"

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

/* ---------------------------------------------------------------------------------------------
 * The test method's hooks. Each has a distinct return value so a transcript line says which door
 * of the `X509_LOOKUP_METHOD` vtable the call reached; the counters say which side-effect hooks
 * `X509_LOOKUP_new`/`_free` ran.
 * --------------------------------------------------------------------------------------------- */

static long g_new_item_calls;
static long g_free_calls;
static long g_ctrl_cmd = -1;
static long g_ctrl_argl = -1;

static int probe_new_item(X509_LOOKUP *ctx)
{
    (void)ctx;
    g_new_item_calls++;
    return 1;
}

static int probe_new_item_reject(X509_LOOKUP *ctx)
{
    (void)ctx;
    return 0;
}

static void probe_free(X509_LOOKUP *ctx)
{
    (void)ctx;
    g_free_calls++;
}

static int probe_init(X509_LOOKUP *ctx)
{
    (void)ctx;
    return 3;
}

static int probe_shutdown(X509_LOOKUP *ctx)
{
    (void)ctx;
    return 4;
}

static int probe_ctrl(X509_LOOKUP *ctx, int cmd, const char *argc, long argl, char **ret)
{
    (void)ctx;
    (void)argc;
    (void)ret;
    g_ctrl_cmd = cmd;
    g_ctrl_argl = argl;
    return 5;
}

static int probe_get_by_subject(X509_LOOKUP *ctx, X509_LOOKUP_TYPE type,
                                const X509_NAME *name, X509_OBJECT *ret)
{
    (void)ctx; (void)type; (void)name; (void)ret;
    return 6;
}

static int probe_get_by_issuer_serial(X509_LOOKUP *ctx, X509_LOOKUP_TYPE type,
                                      const X509_NAME *name, const ASN1_INTEGER *serial,
                                      X509_OBJECT *ret)
{
    (void)ctx; (void)type; (void)name; (void)serial; (void)ret;
    return 7;
}

static int probe_get_by_fingerprint(X509_LOOKUP *ctx, X509_LOOKUP_TYPE type,
                                    const unsigned char *bytes, int len, X509_OBJECT *ret)
{
    (void)ctx; (void)type; (void)bytes; (void)len; (void)ret;
    return 8;
}

static int probe_get_by_alias(X509_LOOKUP *ctx, X509_LOOKUP_TYPE type,
                              const char *str, int len, X509_OBJECT *ret)
{
    (void)ctx; (void)type; (void)str; (void)len; (void)ret;
    return 9;
}

/* ---------------------------------------------------------------------------------------------
 * Phase 11.1a -- `crypto/x509/x509_meth.c`'s `X509_LOOKUP_METHOD` vtable.
 *
 * The nine setters each answer 1; each getter is compared to the exact hook just installed, so a
 * getter that returned a different slot than its setter wrote is one `=0` line. `meth_new(NULL)`
 * is the unit's one refusal: `OPENSSL_strdup(NULL)` answers NULL, so it frees and answers NULL
 * and raises nothing (this unit has no raise coordinate at all).
 * --------------------------------------------------------------------------------------------- */

static void drive_method(void)
{
    X509_LOOKUP_METHOD *m = X509_LOOKUP_meth_new("probe");

    out_ptr("meth.new", m);
    out_ptr("meth.new.null_name", X509_LOOKUP_meth_new(NULL));
    out_err("meth.new.null_name.err");

    out_int("meth.set_new_item", X509_LOOKUP_meth_set_new_item(m, probe_new_item));
    out_int("meth.set_free", X509_LOOKUP_meth_set_free(m, probe_free));
    out_int("meth.set_init", X509_LOOKUP_meth_set_init(m, probe_init));
    out_int("meth.set_shutdown", X509_LOOKUP_meth_set_shutdown(m, probe_shutdown));
    out_int("meth.set_ctrl", X509_LOOKUP_meth_set_ctrl(m, probe_ctrl));
    out_int("meth.set_get_by_subject",
            X509_LOOKUP_meth_set_get_by_subject(m, probe_get_by_subject));
    out_int("meth.set_get_by_issuer_serial",
            X509_LOOKUP_meth_set_get_by_issuer_serial(m, probe_get_by_issuer_serial));
    out_int("meth.set_get_by_fingerprint",
            X509_LOOKUP_meth_set_get_by_fingerprint(m, probe_get_by_fingerprint));
    out_int("meth.set_get_by_alias",
            X509_LOOKUP_meth_set_get_by_alias(m, probe_get_by_alias));

    out_int("meth.get_new_item", X509_LOOKUP_meth_get_new_item(m) == probe_new_item);
    out_int("meth.get_free", X509_LOOKUP_meth_get_free(m) == probe_free);
    out_int("meth.get_init", X509_LOOKUP_meth_get_init(m) == probe_init);
    out_int("meth.get_shutdown", X509_LOOKUP_meth_get_shutdown(m) == probe_shutdown);
    out_int("meth.get_ctrl", X509_LOOKUP_meth_get_ctrl(m) == probe_ctrl);
    out_int("meth.get_get_by_subject",
            X509_LOOKUP_meth_get_get_by_subject(m) == probe_get_by_subject);
    out_int("meth.get_get_by_issuer_serial",
            X509_LOOKUP_meth_get_get_by_issuer_serial(m) == probe_get_by_issuer_serial);
    out_int("meth.get_get_by_fingerprint",
            X509_LOOKUP_meth_get_get_by_fingerprint(m) == probe_get_by_fingerprint);
    out_int("meth.get_get_by_alias",
            X509_LOOKUP_meth_get_get_by_alias(m) == probe_get_by_alias);

    X509_LOOKUP_meth_free(m);
    X509_LOOKUP_meth_free(NULL);
    out_int("meth.free", 1);
}

/* ---------------------------------------------------------------------------------------------
 * Phase 11.1a -- `crypto/x509/x509_lu.c`'s `X509_LOOKUP` object.
 *
 * Two instances: one bound to a method with no hooks (the defaults: `init`/`shutdown`/`ctrl`
 * answer 1, the five `by_*` doors answer 0), one bound to the hooks above (which answer their
 * distinct markers, so each dispatcher is shown reaching its door). `by_subject_ex` has no
 * public setter, so it must fall through to `get_by_subject` -- the transcript's `=6` is that
 * fallback. A method whose `new_item` answers 0 is `X509_LOOKUP_new`'s refusal.
 * --------------------------------------------------------------------------------------------- */

static void drive_lookup(void)
{
    X509_LOOKUP_METHOD *n = X509_LOOKUP_meth_new("nohooks");
    X509_LOOKUP_METHOD *h = X509_LOOKUP_meth_new("hooks");
    X509_LOOKUP_METHOD *r = X509_LOOKUP_meth_new("reject");
    X509_LOOKUP *ln;
    X509_LOOKUP *lh;
    int sentinel = 0;
    void *data = &sentinel;

    /* ----- the no-hook method: every door's default ----- */
    ln = X509_LOOKUP_new(n);
    out_ptr("lookup.new.nohooks", ln);
    out_ptr("lookup.get_store.nohooks", X509_LOOKUP_get_store(ln));
    out_int("lookup.get_method_data.initial", X509_LOOKUP_get_method_data(ln) == NULL);
    out_int("lookup.set_method_data", X509_LOOKUP_set_method_data(ln, data));
    out_int("lookup.get_method_data.roundtrip", X509_LOOKUP_get_method_data(ln) == data);
    out_int("lookup.init.nohook", X509_LOOKUP_init(ln));
    out_int("lookup.shutdown.nohook", X509_LOOKUP_shutdown(ln));
    out_int("lookup.ctrl.nohook", X509_LOOKUP_ctrl(ln, 11, "x", 3, NULL));
    out_int("lookup.ctrl_ex.nohook", X509_LOOKUP_ctrl_ex(ln, 11, "x", 3, NULL, NULL, NULL));
    out_int("lookup.by_subject.nodoor",
            X509_LOOKUP_by_subject(ln, X509_LU_X509, NULL, NULL));
    out_int("lookup.by_subject_ex.nodoor",
            X509_LOOKUP_by_subject_ex(ln, X509_LU_X509, NULL, NULL, NULL, NULL));
    out_int("lookup.by_issuer_serial.nodoor",
            X509_LOOKUP_by_issuer_serial(ln, X509_LU_X509, NULL, NULL, NULL));
    out_int("lookup.by_fingerprint.nodoor",
            X509_LOOKUP_by_fingerprint(ln, X509_LU_X509, NULL, 0, NULL));
    out_int("lookup.by_alias.nodoor", X509_LOOKUP_by_alias(ln, X509_LU_X509, NULL, 0, NULL));
    X509_LOOKUP_free(ln);

    /* ----- the hooked method: every door reached ----- */
    X509_LOOKUP_meth_set_new_item(h, probe_new_item);
    X509_LOOKUP_meth_set_free(h, probe_free);
    X509_LOOKUP_meth_set_init(h, probe_init);
    X509_LOOKUP_meth_set_shutdown(h, probe_shutdown);
    X509_LOOKUP_meth_set_ctrl(h, probe_ctrl);
    X509_LOOKUP_meth_set_get_by_subject(h, probe_get_by_subject);
    X509_LOOKUP_meth_set_get_by_issuer_serial(h, probe_get_by_issuer_serial);
    X509_LOOKUP_meth_set_get_by_fingerprint(h, probe_get_by_fingerprint);
    X509_LOOKUP_meth_set_get_by_alias(h, probe_get_by_alias);

    g_new_item_calls = 0;
    lh = X509_LOOKUP_new(h);
    out_ptr("lookup.new.hooks", lh);
    out_int("lookup.new.new_item_calls", g_new_item_calls);
    out_int("lookup.init.hook", X509_LOOKUP_init(lh));
    out_int("lookup.shutdown.hook", X509_LOOKUP_shutdown(lh));
    out_int("lookup.ctrl.hook", X509_LOOKUP_ctrl(lh, 9, "arg", 7, NULL));
    out_int("lookup.ctrl.hook.cmd", g_ctrl_cmd);
    out_int("lookup.ctrl.hook.argl", g_ctrl_argl);
    out_int("lookup.ctrl_ex.hook", X509_LOOKUP_ctrl_ex(lh, 10, "arg", 8, NULL, NULL, NULL));
    out_int("lookup.ctrl_ex.hook.cmd", g_ctrl_cmd);
    out_int("lookup.by_subject.hook",
            X509_LOOKUP_by_subject(lh, X509_LU_X509, NULL, NULL));
    out_int("lookup.by_subject_ex.hook",
            X509_LOOKUP_by_subject_ex(lh, X509_LU_X509, NULL, NULL, NULL, NULL));
    out_int("lookup.by_issuer_serial.hook",
            X509_LOOKUP_by_issuer_serial(lh, X509_LU_X509, NULL, NULL, NULL));
    out_int("lookup.by_fingerprint.hook",
            X509_LOOKUP_by_fingerprint(lh, X509_LU_X509, NULL, 0, NULL));
    out_int("lookup.by_alias.hook", X509_LOOKUP_by_alias(lh, X509_LU_X509, NULL, 0, NULL));

    g_free_calls = 0;
    X509_LOOKUP_free(lh);
    out_int("lookup.free.free_calls", g_free_calls);
    X509_LOOKUP_free(NULL);
    out_int("lookup.free.null", 1);

    /* ----- the refusal: `new_item` answers 0 ----- */
    X509_LOOKUP_meth_set_new_item(r, probe_new_item_reject);
    out_ptr("lookup.new.new_item_reject", X509_LOOKUP_new(r));
    out_err("lookup.new.new_item_reject.err");

    X509_LOOKUP_meth_free(n);
    X509_LOOKUP_meth_free(h);
    X509_LOOKUP_meth_free(r);
}

/* ---------------------------------------------------------------------------------------------
 * Phase 11.1a -- `crypto/x509/x509_lu.c`'s `X509_OBJECT`.
 *
 * The tags are read back through `X509_OBJECT_get_type` (0 `X509_LU_NONE`, 1 `X509_LU_X509`,
 * 2 `X509_LU_CRL`) and the union through the two `get0` accessors, so a `set1_` that retagged
 * without moving the union is one `=0`. The by-subject trio runs over a caller-built stack with
 * no comparator, which is the stack API's pointer-equality path (`OPENSSL_sk_find_all`'s
 * `comp == NULL` arm): the useful by-subject path needs a store's own comparator stack, which
 * 11.2's `X509_STORE_new` builds, so `X509_OBJECT_idx_by_subject` answers -1 and the two
 * retrievers answer NULL. `set1_` on a NULL object is the refusal.
 * --------------------------------------------------------------------------------------------- */

static void drive_object(X509 *cert, X509_CRL *crl)
{
    X509_OBJECT *obj = X509_OBJECT_new();
    X509_NAME *nm = X509_get_subject_name(cert);

    out_ptr("object.new", obj);
    out_int("object.new.type", X509_OBJECT_get_type(obj));
    out_ptr("object.new.get0_X509", X509_OBJECT_get0_X509(obj));
    out_ptr("object.new.get0_X509_CRL", X509_OBJECT_get0_X509_CRL(obj));
    out_int("object.new.up_ref", X509_OBJECT_up_ref_count(obj));

    out_int("object.set1_X509.null_obj", X509_OBJECT_set1_X509(NULL, cert));
    out_int("object.set1_X509_CRL.null_obj", X509_OBJECT_set1_X509_CRL(NULL, crl));

    out_int("object.set1_X509", X509_OBJECT_set1_X509(obj, cert));
    out_int("object.after_x509.type", X509_OBJECT_get_type(obj));
    out_int("object.after_x509.is_cert", X509_OBJECT_get0_X509(obj) == cert);
    out_ptr("object.after_x509.get0_X509_CRL", X509_OBJECT_get0_X509_CRL(obj));
    out_int("object.after_x509.up_ref", X509_OBJECT_up_ref_count(obj));

    out_int("object.set1_X509_CRL", X509_OBJECT_set1_X509_CRL(obj, crl));
    out_int("object.after_crl.type", X509_OBJECT_get_type(obj));
    out_int("object.after_crl.is_crl", X509_OBJECT_get0_X509_CRL(obj) == crl);
    out_ptr("object.after_crl.get0_X509", X509_OBJECT_get0_X509(obj));

    /* ----- the by-subject index/retrieve trio over a caller-built stack ----- */
    {
        STACK_OF(X509_OBJECT) *h = sk_X509_OBJECT_new_null();
        X509_OBJECT *a = X509_OBJECT_new();
        X509_OBJECT *b = X509_OBJECT_new();

        X509_OBJECT_set1_X509(a, cert);
        X509_OBJECT_set1_X509(b, cert);
        sk_X509_OBJECT_push(h, a);
        sk_X509_OBJECT_push(h, b);
        out_int("object.stack.count", sk_X509_OBJECT_num(h));
        out_int("object.idx_by_subject", X509_OBJECT_idx_by_subject(h, X509_LU_X509, nm));
        out_ptr("object.retrieve_by_subject",
                X509_OBJECT_retrieve_by_subject(h, X509_LU_X509, nm));
        out_ptr("object.retrieve_match", X509_OBJECT_retrieve_match(h, a));

        sk_X509_OBJECT_pop_free(h, X509_OBJECT_free);
    }

    X509_OBJECT_free(obj);
    X509_OBJECT_free(NULL);
    out_int("object.free", 1);
}

/* ---------------------------------------------------------------------------------------------
 * Phase 11.1a -- the four `X509_STORE` arms that refuse before dereferencing a store.
 *
 * `X509_STORE_add_cert`/`_add_crl` with a NULL object, and the two object-cache readers with a
 * NULL store, are the only `X509_STORE_*` calls this stratum can make without `X509_STORE_new`
 * (11.2's). Each reaches its raise coordinate, so the transcript carries `lib.reason`.
 * --------------------------------------------------------------------------------------------- */

static void drive_store_refusals(void)
{
    ERR_clear_error();
    out_int("store.add_cert.null", X509_STORE_add_cert(NULL, NULL));
    out_err("store.add_cert.null.err");

    ERR_clear_error();
    out_int("store.add_crl.null", X509_STORE_add_crl(NULL, NULL));
    out_err("store.add_crl.null.err");

    ERR_clear_error();
    out_ptr("store.get1_objects.null", X509_STORE_get1_objects(NULL));
    out_err("store.get1_objects.null.err");

    ERR_clear_error();
    out_ptr("store.get1_all_certs.null", X509_STORE_get1_all_certs(NULL));
    out_err("store.get1_all_certs.null.err");
}

/* ---------------------------------------------------------------------------------------------
 * Phase 11.4a -- `crypto/x509/x509_set.c`'s mutator layer over a fixed `X509`.
 *
 * The getters read the decoded certificate; the set/`getm` round trips run over a fresh
 * `X509_new()`. The NULL-`x` and NULL-`tm` arms are the unit's refusals; the unit raises
 * nothing, so each refusal's coordinate is `none`.
 * --------------------------------------------------------------------------------------------- */

static void drive_set(X509 *cert)
{
    X509 *x;
    X509_NAME *nm;
    ASN1_INTEGER *ser;
    EVP_PKEY *pk;
    const ASN1_BIT_STRING *iuid = NULL;
    const ASN1_BIT_STRING *suid = NULL;
    const X509_ALGOR *tbsalg;
    const ASN1_OBJECT *tbsalg_obj = NULL;
    const ASN1_TIME *tm;

    /* ----- the getters over the decoded certificate ----- */
    out_ptr("x509.get0_notBefore", X509_get0_notBefore(cert));
    out_ptr("x509.get0_notAfter", X509_get0_notAfter(cert));
    out_int("x509.getm_notBefore.is_get0",
            X509_getm_notBefore(cert) == X509_get0_notBefore(cert));
    out_int("x509.getm_notAfter.is_get0", X509_getm_notAfter(cert) == X509_get0_notAfter(cert));
    out_int("x509.get_signature_type", X509_get_signature_type(cert));
    out_ptr("x509.get_X509_PUBKEY", X509_get_X509_PUBKEY(cert));
    X509_get0_uids(cert, &iuid, &suid);
    out_int("x509.get0_uids.issuer", iuid != NULL);
    out_int("x509.get0_uids.subject", suid != NULL);
    tbsalg = X509_get0_tbs_sigalg(cert);
    out_ptr("x509.get0_tbs_sigalg", tbsalg);
    X509_ALGOR_get0(&tbsalg_obj, NULL, NULL, tbsalg);
    out_int("x509.get0_tbs_sigalg.nid", tbsalg_obj != NULL ? OBJ_obj2nid(tbsalg_obj) : -1);

    /* ----- the mutators over a fresh X509 ----- */
    x = X509_new();
    out_ptr("x509.new", x);

    ser = ASN1_INTEGER_new();
    ASN1_INTEGER_set(ser, 7);
    out_int("x509.set_serialNumber", X509_set_serialNumber(x, ser));
    out_int("x509.set_serialNumber.read", ASN1_INTEGER_get(X509_get0_serialNumber(x)));
    out_int("x509.set_serialNumber.null_x", X509_set_serialNumber(NULL, ser));

    nm = X509_NAME_new();
    out_int("x509.set_subject_name", X509_set_subject_name(x, nm));
    out_int("x509.set_subject_name.read",
            X509_NAME_cmp(X509_get_subject_name(x), nm) == 0);
    out_int("x509.set_issuer_name", X509_set_issuer_name(x, nm));
    out_int("x509.set_issuer_name.read", X509_NAME_cmp(X509_get_issuer_name(x), nm) == 0);
    out_int("x509.set_subject_name.null_x", X509_set_subject_name(NULL, nm));

    tm = X509_get0_notBefore(cert);
    out_int("x509.set1_notBefore", X509_set1_notBefore(x, tm));
    out_int("x509.get0_notBefore.is_set", X509_get0_notBefore(x) != NULL);
    out_int("x509.getm_notBefore.is_set", X509_getm_notBefore(x) != NULL);
    out_int("x509.set1_notBefore.null_tm", X509_set1_notBefore(x, NULL));
    out_int("x509.set1_notBefore.null_x", X509_set1_notBefore(NULL, tm));
    out_int("x509.set1_notAfter", X509_set1_notAfter(x, X509_get0_notAfter(cert)));
    out_int("x509.set1_notAfter.null_tm", X509_set1_notAfter(x, NULL));

    pk = X509_get_pubkey(cert);
    out_int("x509.set_pubkey", X509_set_pubkey(x, pk));
    out_int("x509.pubkey.roundtrip",
            X509_PUBKEY_eq(X509_get_X509_PUBKEY(x), X509_get_X509_PUBKEY(cert)));
    out_int("x509.set_pubkey.null_x", X509_set_pubkey(NULL, pk));
    EVP_PKEY_free(pk);

    X509_free(x);
    ASN1_INTEGER_free(ser);
    X509_NAME_free(nm);
    out_int("x509.set.arms", 1);
}

/* ---------------------------------------------------------------------------------------------
 * Phase 11.4a -- `crypto/x509/x509_req.c` and `crypto/x509/x_req.c`.
 *
 * `X509_REQ`'s lifecycle and item, the `X509_REQ_INFO` item's own d2i/i2d/new/free, the
 * attribute accessors and the four `add1_attr*` mutators, the extension-NID table, the
 * distinguishing ID and the signature setters, driven over the fixed request DER. The six
 * `NULL req` arms are the refusals; each raises `ERR_R_PASSED_NULL_PARAMETER`, so the transcript
 * carries `11.786690`.
 * --------------------------------------------------------------------------------------------- */

static void drive_req(void)
{
    const unsigned char *p;
    unsigned char *der = NULL;
    unsigned char *tbs = NULL;
    int len;
    X509_REQ *req;
    X509_REQ *dup;
    X509_REQ *blank;
    X509_REQ_INFO *info;
    X509_ATTRIBUTE *at;
    X509_ALGOR *alg;
    ASN1_OCTET_STRING *did;
    ASN1_BIT_STRING *sig;
    EVP_PKEY *rpk;
    const ASN1_BIT_STRING *gsig = NULL;
    const X509_ALGOR *galg = NULL;
    static int alt_nids[] = { NID_commonName, NID_undef };

    /* ----- the item group ----- */
    out_ptr("req.it", X509_REQ_it());
    out_ptr("reqinfo.it", X509_REQ_INFO_it());

    blank = X509_REQ_new();
    out_ptr("req.new", blank);
    out_int("req.new.version", X509_REQ_get_version(blank));
    out_ptr("req.new_ex.null", X509_REQ_new_ex(NULL, NULL));
    out_ptr("req.new_ex.propq", X509_REQ_new_ex(NULL, "provider=default"));
    out_err("req.new_ex.propq.err");

    info = X509_REQ_INFO_new();
    out_ptr("reqinfo.new", info);
    X509_REQ_INFO_free(info);
    X509_REQ_INFO_free(NULL);

    /* ----- d2i/i2d over the fixed request DER ----- */
    p = RT_X509_REQ_DER;
    req = d2i_X509_REQ(NULL, &p, (long)RT_X509_REQ_DER_LEN);
    out_ptr("req.d2i", req);
    out_err("req.d2i.err");
    out_int("req.d2i.consumed", (long)(p - RT_X509_REQ_DER));
    len = i2d_X509_REQ(req, &der);
    out_int("req.i2d.len", len);
    out_int("req.i2d.same_bytes",
            len == (int)RT_X509_REQ_DER_LEN
                && memcmp(der, RT_X509_REQ_DER, (size_t)len) == 0);
    OPENSSL_free(der);
    der = NULL;

    /* A one-byte-short decode is the refusal arm, with its coordinate. */
    p = RT_X509_REQ_DER;
    out_ptr("req.d2i.truncated", d2i_X509_REQ(NULL, &p, (long)RT_X509_REQ_DER_LEN - 1));
    out_err("req.d2i.truncated.err");

    /* ----- dup and the signature/name reads ----- */
    dup = X509_REQ_dup(req);
    out_ptr("req.dup", dup);
    out_int("req.dup.distinct", dup != NULL && dup != req);
    out_int("req.dup.subject_cmp",
            X509_NAME_cmp(X509_REQ_get_subject_name(dup),
                          X509_REQ_get_subject_name(req)) == 0);
    X509_REQ_get0_signature(req, &gsig, &galg);
    out_int("req.get0_signature.sig", gsig != NULL);
    out_int("req.get0_signature.alg", galg != NULL);
    out_int("req.get_signature_nid", X509_REQ_get_signature_nid(req));

    rpk = X509_REQ_get_pubkey(req);
    out_ptr("req.get_pubkey", rpk);
    out_ptr("req.get0_pubkey", X509_REQ_get0_pubkey(req));
    out_int("req.get_pubkey.same", rpk == X509_REQ_get0_pubkey(req));
    out_ptr("req.get_X509_PUBKEY", X509_REQ_get_X509_PUBKEY(req));
    ERR_clear_error();
    out_int("req.check_private_key.self", X509_REQ_check_private_key(req, rpk));
    out_err("req.check_private_key.self.err");
    EVP_PKEY_free(rpk);

    /* ----- the distinguishing ID ----- */
    out_ptr("req.get0_distinguishing_id.initial", X509_REQ_get0_distinguishing_id(req));
    did = ASN1_OCTET_STRING_new();
    ASN1_OCTET_STRING_set(did, (const unsigned char *)"id", 2);
    X509_REQ_set0_distinguishing_id(req, did);
    out_int("req.get0_distinguishing_id.set",
            X509_REQ_get0_distinguishing_id(req) == did);
    X509_REQ_set0_distinguishing_id(req, NULL);
    out_ptr("req.get0_distinguishing_id.cleared", X509_REQ_get0_distinguishing_id(req));

    /* ----- the extension-NID table ----- */
    out_int("req.extension_nid.ext_req", X509_REQ_extension_nid(NID_ext_req));
    out_int("req.extension_nid.ms_ext_req", X509_REQ_extension_nid(NID_ms_ext_req));
    out_int("req.extension_nid.commonName", X509_REQ_extension_nid(NID_commonName));
    {
        int *nids = X509_REQ_get_extension_nids();
        out_ptr("req.get_extension_nids", nids);
        out_int("req.get_extension_nids.0", nids[0]);
        out_int("req.get_extension_nids.1", nids[1]);
        out_int("req.get_extension_nids.2", nids[2]);
    }
    X509_REQ_set_extension_nids(alt_nids);
    out_int("req.set_extension_nids.is_same", X509_REQ_get_extension_nids() == alt_nids);
    out_int("req.extension_nid.after_set", X509_REQ_extension_nid(NID_commonName));

    /* ----- the attribute surface, over the blank request ----- */
    out_int("req.get_attr_count.blank", X509_REQ_get_attr_count(blank));
    out_int("req.get_attr_by_NID.blank",
            X509_REQ_get_attr_by_NID(blank, NID_pkcs9_challengePassword, -1));
    out_int("req.get_attr_by_OBJ.blank",
            X509_REQ_get_attr_by_OBJ(blank, OBJ_nid2obj(NID_pkcs9_challengePassword), -1));
    out_ptr("req.get_attr.blank", X509_REQ_get_attr(blank, 0));

    /* Each `add1_attr*` succeeds for a fresh OID and refuses the same OID twice (the
     * `duplicate attribute` path `x509_att.c` owns, reached through this unit's wrapper). */
    out_int("req.add1_attr_by_NID",
            X509_REQ_add1_attr_by_NID(blank, NID_pkcs9_challengePassword,
                                      V_ASN1_PRINTABLESTRING,
                                      (const unsigned char *)"s", 1));
    out_int("req.attr_count.after_nid", X509_REQ_get_attr_count(blank));
    out_int("req.get_attr_by_NID.after_nid",
            X509_REQ_get_attr_by_NID(blank, NID_pkcs9_challengePassword, -1));
    ERR_clear_error();
    out_int("req.add1_attr_by_NID.duplicate",
            X509_REQ_add1_attr_by_NID(blank, NID_pkcs9_challengePassword,
                                      V_ASN1_PRINTABLESTRING,
                                      (const unsigned char *)"s", 1));
    out_err("req.add1_attr_by_NID.duplicate.err");

    out_int("req.add1_attr_by_txt",
            X509_REQ_add1_attr_by_txt(blank, "friendlyName", V_ASN1_UTF8STRING,
                                      (const unsigned char *)"t", 1));
    ERR_clear_error();
    out_int("req.add1_attr_by_txt.duplicate",
            X509_REQ_add1_attr_by_txt(blank, "friendlyName", V_ASN1_UTF8STRING,
                                      (const unsigned char *)"t", 1));
    out_err("req.add1_attr_by_txt.duplicate.err");

    out_int("req.add1_attr_by_OBJ",
            X509_REQ_add1_attr_by_OBJ(blank, OBJ_nid2obj(NID_pkcs9_emailAddress),
                                      V_ASN1_IA5STRING,
                                      (const unsigned char *)"a@b", 3));
    ERR_clear_error();
    out_int("req.add1_attr_by_OBJ.duplicate",
            X509_REQ_add1_attr_by_OBJ(blank, OBJ_nid2obj(NID_pkcs9_emailAddress),
                                      V_ASN1_IA5STRING,
                                      (const unsigned char *)"a@b", 3));
    out_err("req.add1_attr_by_OBJ.duplicate.err");

    at = X509_ATTRIBUTE_create_by_NID(NULL, NID_pkcs9_unstructuredName,
                                      V_ASN1_UTF8STRING,
                                      (const unsigned char *)"w", 1);
    out_ptr("req.attr.create", at);
    out_int("req.add1_attr", X509_REQ_add1_attr(blank, at));
    ERR_clear_error();
    out_int("req.add1_attr.duplicate", X509_REQ_add1_attr(blank, at));
    out_err("req.add1_attr.duplicate.err");
    out_int("req.attr_count.after_four", X509_REQ_get_attr_count(blank));
    out_ptr("req.get_attr.0", X509_REQ_get_attr(blank, 0));
    X509_ATTRIBUTE_free(at);

    out_ptr("req.delete_attr.0", X509_REQ_delete_attr(blank, 0));
    out_ptr("req.delete_attr.99", X509_REQ_delete_attr(blank, 99));
    out_int("req.attr_count.after_delete", X509_REQ_get_attr_count(blank));

    /* ----- the signature setters ----- */
    sig = ASN1_BIT_STRING_new();
    {
        unsigned char sig_byte = 0;
        ASN1_BIT_STRING_set(sig, &sig_byte, 1);
    }
    X509_REQ_set0_signature(blank, sig);
    X509_REQ_get0_signature(blank, &gsig, NULL);
    out_int("req.set0_signature.applied", gsig == sig);
    X509_REQ_set0_signature(blank, NULL);
    X509_REQ_get0_signature(blank, &gsig, NULL);
    out_ptr("req.set0_signature.cleared", gsig);

    alg = X509_ALGOR_new();
    X509_ALGOR_set0(alg, OBJ_nid2obj(NID_sha256WithRSAEncryption), V_ASN1_NULL, NULL);
    out_int("req.set1_signature_algo", X509_REQ_set1_signature_algo(blank, alg));
    out_int("req.get_signature_nid.after_set", X509_REQ_get_signature_nid(blank));
    X509_ALGOR_free(alg);

    /* ----- the six NULL-request refusals, each with its coordinate ----- */
    ERR_clear_error();
    out_int("req.add1_attr.null", X509_REQ_add1_attr(NULL, NULL));
    out_err("req.add1_attr.null.err");
    ERR_clear_error();
    out_int("req.add1_attr_by_NID.null",
            X509_REQ_add1_attr_by_NID(NULL, NID_commonName, V_ASN1_UTF8STRING,
                                      (const unsigned char *)"x", 1));
    out_err("req.add1_attr_by_NID.null.err");
    ERR_clear_error();
    out_int("req.add1_attr_by_OBJ.null",
            X509_REQ_add1_attr_by_OBJ(NULL, OBJ_nid2obj(NID_commonName), V_ASN1_UTF8STRING,
                                      (const unsigned char *)"x", 1));
    out_err("req.add1_attr_by_OBJ.null.err");
    ERR_clear_error();
    out_int("req.add1_attr_by_txt.null",
            X509_REQ_add1_attr_by_txt(NULL, "challengePassword", V_ASN1_UTF8STRING,
                                      (const unsigned char *)"x", 1));
    out_err("req.add1_attr_by_txt.null.err");
    ERR_clear_error();
    out_ptr("req.delete_attr.null", X509_REQ_delete_attr(NULL, 0));
    out_err("req.delete_attr.null.err");
    ERR_clear_error();
    out_int("req.i2d_re_tbs.null", i2d_re_X509_REQ_tbs(NULL, NULL));
    out_err("req.i2d_re_tbs.null.err");

    /* ----- the X509_REQ_INFO item's own d2i/i2d pair, and i2d_re_X509_REQ_tbs ----- */
    p = RT_X509_REQ_INFO_DER;
    info = d2i_X509_REQ_INFO(NULL, &p, (long)RT_X509_REQ_INFO_DER_LEN);
    out_ptr("reqinfo.d2i", info);
    out_err("reqinfo.d2i.err");
    out_int("reqinfo.d2i.consumed", (long)(p - RT_X509_REQ_INFO_DER));
    len = i2d_X509_REQ_INFO(info, &der);
    out_int("reqinfo.i2d.len", len);
    out_int("reqinfo.i2d.same_bytes",
            len == (int)RT_X509_REQ_INFO_DER_LEN
                && memcmp(der, RT_X509_REQ_INFO_DER, (size_t)len) == 0);
    OPENSSL_free(der);
    der = NULL;
    X509_REQ_INFO_free(info);

    p = RT_X509_REQ_INFO_DER;
    out_ptr("reqinfo.d2i.truncated", d2i_X509_REQ_INFO(NULL, &p,
                                                       (long)RT_X509_REQ_INFO_DER_LEN - 1));
    out_err("reqinfo.d2i.truncated.err");

    len = i2d_re_X509_REQ_tbs(req, &tbs);
    out_int("req.i2d_re_tbs.len", len);
    out_int("req.i2d_re_tbs.same_bytes",
            len == (int)RT_X509_REQ_INFO_DER_LEN
                && memcmp(tbs, RT_X509_REQ_INFO_DER, (size_t)len) == 0);
    OPENSSL_free(tbs);
    tbs = NULL;

    X509_REQ_free(dup);
    X509_REQ_free(req);
    X509_REQ_free(blank);
    X509_REQ_free(NULL);
    out_int("req.free", 1);
}

/* ---------------------------------------------------------------------------------------------
 * main
 * --------------------------------------------------------------------------------------------- */

int main(void)
{
    const unsigned char *p;
    X509 *cert;
    X509_CRL *crl;

    ERR_clear_error();

    p = RT_X509_CERT_DER;
    cert = d2i_X509(NULL, &p, (long)RT_X509_CERT_DER_LEN);
    out_ptr("fixture.cert", cert);
    p = RT_X509_CRL_DER;
    crl = d2i_X509_CRL(NULL, &p, (long)RT_X509_CRL_DER_LEN);
    out_ptr("fixture.crl", crl);

    drive_method();
    drive_lookup();
    drive_object(cert, crl);
    drive_store_refusals();
    drive_set(cert);
    drive_req();

    X509_CRL_free(crl);
    X509_free(cert);
    return 0;
}
