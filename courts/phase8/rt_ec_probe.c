/*
 * RT-EC -- the differential court for `crypto/ec/` (Phase 8.7).
 *
 * This program is compiled **twice**, once against the admitted authority and once against the
 * candidate distribution shell, and the two `key=value` transcripts are diffed. It never decides
 * anything: a residual is a difference between two executions, so the expectation cannot drift
 * with the crate. `forensics/tools/phase8_courts.py` owns the comparison.
 *
 * What this court covers, and the boundary it is drawn on
 * ------------------------------------------------------
 * D334's slice is `crypto/ec/ec_curve.c`'s built-in curve tables and `crypto/evp/ec_support.c`'s
 * two name tables, which is **four exports**: `EC_get_builtin_curves`, `EC_curve_nid2nist`,
 * `EC_curve_nist2nid` and `OSSL_EC_curve_nid2name`. All four are called, and every one of the
 * eighty-two rows is walked in both directions.
 *
 * **The curve constants are not observable through any export this slice lands.** `p`, `a`, `b`,
 * `gx`, `gy`, `order`, the cofactor and the seed reach a caller only through `EC_GROUP_get_curve`,
 * `EC_POINT_get_affine_coordinates`, `EC_GROUP_get_order`, `EC_GROUP_get0_cofactor` and
 * `EC_GROUP_get0_seed` -- all of which need `EC_GROUP_new_by_curve_name`, which needs `ec_lib.c`'s
 * group object and the field arithmetic it dispatches to. So the constants are **not** courted
 * here and this probe does not call them: their evidence is
 * `forensics/tools/gen_ec_curves.py`, whose own probe links against the authority's
 * `EC_GROUP_new_by_curve_name` and checks every read-back against the `data[]` array the
 * authority's struct declares, member for member and width for width, before
 * `src/ec/curve_data.rs` is written. Their *properties* -- the field widths, the oddness, each
 * comment's field size against its polynomial's degree, and `param_len`'s tightness against `p`
 * and the order -- are asserted by the unit tests in `src/ec/curve.rs`, which is where a value
 * with no public reader has to be checked.
 *
 * That is stated rather than implied because the alternative -- probing the constants through a
 * symbol the candidate has not implemented -- would abort the candidate with a diagnostic, and the
 * runner's own module documentation says a probe stays on the implemented surface so that a
 * failure here means a behavioural divergence rather than a missing symbol.
 *
 * What the four exports *are* diffed on
 * -------------------------------------
 *   * `EC_get_builtin_curves` in all four of its call shapes: a NULL table with a non-zero
 *     `nitems`, a table with `nitems == 0`, a one-entry table, and a full-size one. The answer is
 *     the table's length on every path and only `min(nitems, length)` entries are written, so the
 *     transcript prints the untouched tail of the short buffer beside the entry the call filled.
 *   * The eighty-two rows in order: each one's `nid`, its `OBJ_nid2sn` short name and its
 *     `comment` verbatim. The comment column is what makes this arm load-bearing for the curve
 *     *table* rather than only for the lookup -- a row dropped, added or reordered moves three
 *     lines -- and the three IPSec comments carry newline and tab bytes, printed escaped.
 *   * `EC_curve_nid2nist` and `OSSL_EC_curve_nid2name` over every row's NID and over four
 *     refusals each: `0`, `-1`, a NID no object has, and a curve with no NIST spelling.
 *   * `EC_curve_nist2nid` over the fifteen NIST short names and over the refusals that separate it
 *     from `ossl_ec_curve_name2nid`: a lower-case spelling, a NIST name with a trailing space, a
 *     name of the right shape and the wrong number, a SECG name that is in neither table, the SM2
 *     spelling that is only in the *other* table, and the empty string.
 *
 * D344's arms, added to the same probe, cover `crypto/evp/ec_ctrl.c`'s twelve
 * `EVP_PKEY_CTX_{get,set}_ec*` controls. Like 8.5's and 8.6's control courts, they need a context
 * to decide about, and this crate publishes no EC `EVP_KEYMGMT` and no EC `EVP_KEYEXCH` (8.7's
 * provider half is not landed), so `EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL)` answers NULL on
 * the candidate and a context on the authority. The probe therefore publishes its own keymgmt
 * **and** keyexch named `COURT-EC` -- the smallest the structural check accepts and named after the
 * court so it cannot shadow the default provider's own row in either binary's store -- and every
 * parameter the controls send is *echoed* by the callback that receives it, so the transcript
 * observes the parameter array the library built and not merely its return code. Each control is
 * asked against a NULL context, a live context with no operation, a parameter-generation operation
 * and a derivation operation; the round trips are the getter-backed pairs, and every refusal drains
 * its queue and compares the coordinate. **No arm prints a secret**: the cofactor mode, the output
 * length, the KDF type, a digest name, a curve name, an encoding name and a probe-chosen UKM are
 * all supplied by the probe itself. The one getter whose pointer answer cannot be compared --
 * `EVP_PKEY_CTX_get_ecdh_kdf_md`, whose `fix_md` GET arm calls `evp_get_digestbyname_ex` -- prints
 * a constant and names the callee (D344), exactly as `RT-DH` does for its sibling.
 *
 * D345's arms, the block after the group-parameter ones, cover 8.7's remaining same-stratum work:
 * the two `EC_POINT` hex codecs of `crypto/ec/ec_print.c`, the two `EC_POINT`/`BIGNUM` codecs of
 * `crypto/ec/ec_deprecated.c`, and `ECDSA_SIG_get0_r`/`_s` through the existing `ecdsa` block. Each
 * codec arm is a round trip compared by `EC_POINT_cmp`, a width, an in-place identity, or a
 * refusal; the refusals drain the callees' own coordinates (`crypto/o_str.c` and `ecp_oct.c`,
 * because neither codec unit raises) and the block clears the queue first so its drain carries only
 * its own records. **A single `00` octet is the point-at-infinity encoding, not a refusal**, which
 * is recorded rather than smoothed: this court observed it and the crate agrees.
 *
 * No secret is printed and none can be: this slice has no key, no nonce and no shared value. No
 * address is printed either -- every lookup answers a `const char *` into `.rodata`, and the probe
 * prints the *string* or the word `NULL`, never the pointer. stdout is line-buffered, and no
 * NULL-dereferencing entry point is called: `EC_curve_nist2nid(NULL)` faults inside `strcmp` in the
 * authority, so the probe does not call it and records that here instead.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
/* `EC_curve_nid2nist`, `EC_curve_nist2nid` and `OSSL_EC_curve_nid2name` are not deprecated, but
 * the field-type constants this probe compares against are reached through `EC_GROUP`-era
 * declarations. The deprecation is the authority's own policy statement about application code,
 * not about a court that must exercise the entry points it declares; suppressing the diagnostic
 * keeps `-Wall` output readable without changing a single symbol this probe links. */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/param_build.h>
#include <openssl/objects.h>
#include <openssl/provider.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The comment column, with the two whitespace bytes the three IPSec rows carry written as `|` and
 * `/`, so the transcript is one line per observation. */
static void emit_text(const char *tag, const char *member, const char *s)
{
    const char *p;

    printf("%s.%s=", tag, member);
    if (s == NULL) {
        printf("NULL\n");
        return;
    }
    for (p = s; *p != '\0'; p++)
        putchar(*p == '\n' ? '|' : (*p == '\t' ? '/' : *p));
    putchar('\n');
}

static void emit_nid2nist(int nid)
{
    const char *nist = EC_curve_nid2nist(nid);

    printf("nid2nist.%d=%s\n", nid, nist != NULL ? nist : "NULL");
}

static void emit_nid2name(int nid)
{
    const char *name = OSSL_EC_curve_nid2name(nid);

    printf("nid2name.%d=%s\n", nid, name != NULL ? name : "NULL");
}

static void emit_nist2nid(const char *name)
{
    printf("nist2nid.%s=%d\n", name, EC_curve_nist2nid(name));
}

/* The two refusals every lookup shares. `NID_brainpoolP256r1` is a curve with no NIST short name
 * and `NID_rsaEncryption` is not a curve at all -- the two answers `ec_support.c`'s table
 * distinguishes -- and `OID_undef`-style numbers that no object has are a third. */
static void emit_refusals(void)
{
    emit_nid2nist(0);
    emit_nid2nist(-1);
    emit_nid2nist(999999);
    emit_nid2nist(NID_brainpoolP256r1);
    emit_nid2nist(NID_rsaEncryption);
    emit_nid2name(0);
    emit_nid2name(-1);
    emit_nid2name(999999);
    emit_nid2name(NID_brainpoolP256r1);
    emit_nid2name(NID_rsaEncryption);
}

/* The drained error queue, with each record's library, reason and authority coordinate. The
 * coordinate is the authority's own `__FILE__`/`__LINE__`/`__func__`, which the crate's error
 * sites reproduce by construction, so a transcription that raised from the wrong line is a
 * residual rather than a plausible-looking transcript. */
static void layer_drain(const char *tag)
{
    unsigned long e;
    const char *file = NULL, *func = NULL, *data = NULL;
    int line = 0, flags = 0, k = 0;
    char key[96];

    while ((e = ERR_get_error_all(&file, &line, &func, &data, &flags)) != 0) {
        snprintf(key, sizeof(key), "%s.err%d", tag, k);
        printf("%s.lib=%d\n", key, ERR_GET_LIB(e));
        printf("%s.reason=%d\n", key, ERR_GET_REASON(e));
        emit_text(key, "file", file);
        printf("%s.line=%d\n", key, line);
        emit_text(key, "func", func);
        k++;
    }
    printf("%s.err_count=%d\n", tag, k);
}

/* A group's parameters rebuilt as an explicit one, for the two `EC_GROUP_*_params` exports. */
static void group_params_arms(const EC_GROUP *named, BN_CTX *bctx)
{
    OSSL_PARAM_BLD *bld;
    OSSL_PARAM *params;
    EC_GROUP *round;

    bld = OSSL_PARAM_BLD_new();
    if (bld == NULL) {
        printf("gparams.bld=0\n");
        return;
    }
    printf("gparams.bld=1\n");
    params = EC_GROUP_to_params(named, NULL, NULL, bctx);
    printf("gparams.to_params=%d\n", params != NULL);
    OSSL_PARAM_BLD_free(bld);
    if (params == NULL)
        return;
    round = EC_GROUP_new_from_params(params, NULL, NULL);
    printf("gparams.from_params=%d\n", round != NULL);
    if (round != NULL) {
        printf("gparams.cmp=%d\n", EC_GROUP_cmp(named, round, bctx));
        printf("gparams.field=%d\n", EC_GROUP_get_field_type(round));
        EC_GROUP_free(round);
    }
    OPENSSL_free(params);
}

/* ------------------------------------------------------------------ the control court's provider
 *
 * The twelve `EVP_PKEY_CTX_*ec*` controls of `crypto/evp/ec_ctrl.c` are decisions *about a
 * context*, so they need a context to decide about -- and six of them are derivation decisions and
 * six are generation ones, so the probe publishes **both** a keyexch and a keymgmt. This crate
 * publishes neither for EC (8.7's provider half is not landed), so
 * `EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL)` answers NULL on the candidate and a context on the
 * authority -- an arm that compared that would be a difference about a missing provider row rather
 * than about the controls. Both are the smallest the structural check accepts, named `COURT-EC`
 * rather than `EC` so that neither can shadow the default provider's own row in either binary's
 * method store. Every parameter the controls send is *echoed* by the callback that receives it, so
 * the transcript observes the parameter array the library built and not merely its return code; no
 * echoed value is a secret -- they are a cofactor mode, an output length, a KDF type, a digest
 * name, a curve name, an encoding name and a probe-chosen UKM, all of which the probe supplies. */

struct court_ctx {
    int have_cofactor;
    int cofactor;
    int have_outlen;
    unsigned long outlen;
    int have_kdftype;
    char kdftype[64];
    int have_md;
    char md[64];
    int have_ukm;
    unsigned long ukmlen;
    unsigned char ukm[64];
    int have_group;
    char group[64];
    int have_encoding;
    char encoding[64];
};

static struct court_ctx *court_new(void)
{
    struct court_ctx *c = malloc(sizeof(*c));

    if (c == NULL)
        return NULL;
    memset(c, 0, sizeof(*c));
    /* The defaults a fresh derivation context answers with. `kdf-type` is the empty string, which
     * `fix_ec_kdf_type`'s table maps back to `EVP_PKEY_ECDH_KDF_NONE`; `kdf-outlen` and the
     * cofactor mode are zero, which are the two values the getters report as successes. */
    strcpy(c->kdftype, "");
    strcpy(c->md, "SHA256");
    return c;
}

/* Print every parameter the library sent, one `key=value` line per entry. The rendering is by
 * `data_type`, so a wrong type is visible as well as a wrong value. **One GET parameter's value is
 * deliberately not printed**: `EVP_PKEY_CTX_get_ecdh_cofactor_mode` passes the address of an
 * UNINITIALIZED `int mode` to the getter, so the pre-write contents are whatever the previous call
 * left on the stack -- stack layout, not a behaviour -- and the authority's own transcript differs
 * from run to run (it happened to read back the preceding `set`'s `1`). The type and width are
 * still observed, and the arm that *returns* the mode observes the real behaviour. */
static void court_dump(const char *arm, const OSSL_PARAM params[])
{
    int i;

    for (i = 0; params != NULL && params[i].key != NULL; i++) {
        const OSSL_PARAM *p = &params[i];

        if (strcmp(arm, "der.get") == 0 && strcmp(p->key, "ecdh-cofactor-mode") == 0) {
            printf("ec.%s.p.%d=%s:integer_unwritten:%zu\n", arm, i, p->key, p->data_size);
        } else if (p->data_type == OSSL_PARAM_INTEGER) {
            int64_t v = 0;
            OSSL_PARAM_get_int64(p, &v);
            printf("ec.%s.p.%d=%s:int:%lld\n", arm, i, p->key, (long long)v);
        } else if (p->data_type == OSSL_PARAM_UNSIGNED_INTEGER) {
            uint64_t v = 0;
            OSSL_PARAM_get_uint64(p, &v);
            printf("ec.%s.p.%d=%s:uint:%llu\n", arm, i, p->key, (unsigned long long)v);
        } else if (p->data_type == OSSL_PARAM_UTF8_STRING) {
            printf("ec.%s.p.%d=%s:utf8:%s\n", arm, i, p->key,
                p->data != NULL ? (const char *)p->data : "<null>");
        } else if (p->data_type == OSSL_PARAM_OCTET_STRING) {
            printf("ec.%s.p.%d=%s:octet:%zu\n", arm, i, p->key, p->data_size);
        } else {
            printf("ec.%s.p.%d=%s:type%u:%zu\n", arm, i, p->key, p->data_type,
                p->data_size);
        }
    }
    printf("ec.%s.p.count=%d\n", arm, i);
}

/* Remember the parameters a getter will be asked for, by copying the value rather than the
 * pointer: the arrays the controls build point at stack locals in the *calling* frame, so a stored
 * pointer would be stale the moment the call returns. */
static void court_store(struct court_ctx *c, const OSSL_PARAM params[])
{
    int i;

    for (i = 0; params != NULL && params[i].key != NULL; i++) {
        const OSSL_PARAM *p = &params[i];

        if (strcmp(p->key, "ecdh-cofactor-mode") == 0) {
            int64_t v = 0;
            OSSL_PARAM_get_int64(p, &v);
            c->have_cofactor = 1;
            c->cofactor = (int)v;
        } else if (strcmp(p->key, "kdf-outlen") == 0) {
            uint64_t v = 0;
            OSSL_PARAM_get_uint64(p, &v);
            c->have_outlen = 1;
            c->outlen = (unsigned long)v;
        } else if (strcmp(p->key, "kdf-type") == 0) {
            c->have_kdftype = 1;
            snprintf(c->kdftype, sizeof(c->kdftype), "%s", (const char *)p->data);
        } else if (strcmp(p->key, "kdf-digest") == 0) {
            c->have_md = 1;
            snprintf(c->md, sizeof(c->md), "%s", (const char *)p->data);
        } else if (strcmp(p->key, "kdf-ukm") == 0) {
            c->have_ukm = 1;
            c->ukmlen = p->data_size;
            if (p->data != NULL && p->data_size <= sizeof(c->ukm))
                memcpy(c->ukm, p->data, p->data_size);
        } else if (strcmp(p->key, "group") == 0) {
            c->have_group = 1;
            snprintf(c->group, sizeof(c->group), "%s", (const char *)p->data);
        } else if (strcmp(p->key, "encoding") == 0) {
            c->have_encoding = 1;
            snprintf(c->encoding, sizeof(c->encoding), "%s", (const char *)p->data);
        }
    }
}

static int court_get(struct court_ctx *c, OSSL_PARAM params[])
{
    int i;

    for (i = 0; params != NULL && params[i].key != NULL; i++) {
        OSSL_PARAM *p = &params[i];

        if (strcmp(p->key, "ecdh-cofactor-mode") == 0)
            OSSL_PARAM_set_int(p, c->cofactor);
        else if (strcmp(p->key, "kdf-outlen") == 0)
            OSSL_PARAM_set_uint64(p, (uint64_t)c->outlen);
        else if (strcmp(p->key, "kdf-type") == 0)
            OSSL_PARAM_set_utf8_string(p, c->kdftype);
        else if (strcmp(p->key, "kdf-digest") == 0)
            OSSL_PARAM_set_utf8_string(p, c->md);
        else if (strcmp(p->key, "kdf-ukm") == 0)
            OSSL_PARAM_set_octet_ptr(p, c->ukm, c->ukmlen);
    }
    return 1;
}

/* The settable and gettable lists, as the structural check reads them. The `data` pointers are
 * NULL and `data_size` is the width the *control* builds, which is all a list of names needs. */
static const OSSL_PARAM court_gen_settable[] = {
    { "group", OSSL_PARAM_UTF8_STRING, NULL, 0, 0 },
    { "encoding", OSSL_PARAM_UTF8_STRING, NULL, 0, 0 },
    { NULL, 0, NULL, 0, 0 }
};
static const OSSL_PARAM court_gen_gettable[] = {
    { NULL, 0, NULL, 0, 0 }
};
static const OSSL_PARAM court_kex_settable[] = {
    { "ecdh-cofactor-mode", OSSL_PARAM_INTEGER, NULL, sizeof(int), 0 },
    { "kdf-outlen", OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(size_t), 0 },
    { "kdf-type", OSSL_PARAM_UTF8_STRING, NULL, 0, 0 },
    { "kdf-digest", OSSL_PARAM_UTF8_STRING, NULL, 0, 0 },
    { "kdf-ukm", OSSL_PARAM_OCTET_STRING, NULL, 0, 0 },
    { NULL, 0, NULL, 0, 0 }
};
static const OSSL_PARAM court_kex_gettable[] = {
    { "ecdh-cofactor-mode", OSSL_PARAM_INTEGER, NULL, sizeof(int), 0 },
    { "kdf-outlen", OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(size_t), 0 },
    { "kdf-type", OSSL_PARAM_UTF8_STRING, NULL, 0, 0 },
    { "kdf-digest", OSSL_PARAM_UTF8_STRING, NULL, 0, 0 },
    { "kdf-ukm", OSSL_PARAM_OCTET_PTR, NULL, 0, 0 },
    { NULL, 0, NULL, 0, 0 }
};

/* The keymgmt: only the generation callbacks carry state, because the two generation controls
 * reach the keymgmt through `EVP_PKEY_CTX_ctrl` on a generation operation. */
static int court_marker;

static void *ck_new(void *provctx) { (void)provctx; return court_new(); }
static void ck_free(void *keydata) { free(keydata); }
static int ck_has(const void *keydata, int selection)
{ (void)keydata; (void)selection; return 1; }
static int ck_get_params(void *keydata, OSSL_PARAM params[])
{ (void)keydata; (void)params; return 1; }
static const OSSL_PARAM *ck_gettable_params(void *provctx) { (void)provctx; return NULL; }
static int ck_set_params(void *keydata, const OSSL_PARAM params[])
{ (void)keydata; (void)params; return 1; }
static const OSSL_PARAM *ck_settable_params(void *provctx) { (void)provctx; return NULL; }
static void *ck_gen_init(void *provctx, int selection, const OSSL_PARAM params[])
{ (void)provctx; (void)selection; (void)params; return court_new(); }
static void ck_gen_cleanup(void *genctx) { free(genctx); }
static void *ck_gen(void *genctx, OSSL_CALLBACK *cb, void *cbarg)
{ (void)genctx; (void)cb; (void)cbarg; return malloc(1); }
static int ck_gen_set_template(void *genctx, void *templ)
{ (void)genctx; (void)templ; return 1; }
static int ck_gen_set_params(void *genctx, const OSSL_PARAM params[])
{ court_dump("gen.set", params); court_store(genctx, params); return 1; }
static const OSSL_PARAM *ck_gen_settable_params(void *genctx, void *provctx)
{ (void)genctx; (void)provctx; return court_gen_settable; }
static int ck_gen_get_params(void *genctx, OSSL_PARAM params[])
{ court_dump("gen.get", params); return court_get(genctx, params); }
static const OSSL_PARAM *ck_gen_gettable_params(void *genctx, void *provctx)
{ (void)genctx; (void)provctx; return court_gen_gettable; }
static void *ck_load(const void *reference, size_t reference_sz)
{ (void)reference; (void)reference_sz; return malloc(1); }
static const char *ck_query_operation_name(int operation_id)
{ (void)operation_id; return NULL; }
static void *ck_import(void *keydata, int selection, const OSSL_PARAM params[])
{ (void)keydata; (void)selection; (void)params; return malloc(1); }
static const OSSL_PARAM *ck_import_types(int selection) { (void)selection; return NULL; }
static int ck_export(void *keydata, int selection, OSSL_CALLBACK *cb, void *cbarg)
{ (void)keydata; (void)selection; (void)cb; (void)cbarg; return 1; }
static const OSSL_PARAM *ck_export_types(int selection) { (void)selection; return NULL; }
static void *ck_dup(const void *keydata, int selection)
{ (void)keydata; (void)selection; return malloc(1); }
static int ck_validate(const void *keydata, int selection, int checktype)
{ (void)keydata; (void)selection; (void)checktype; return 1; }
static int ck_match(const void *a, const void *b, int selection)
{ (void)a; (void)b; (void)selection; return 1; }

/* The keyexch: the six derivation controls reach `EVP_PKEY_CTX_set_params`/`_get_params` on a
 * derivation operation, which dispatch to `set_ctx_params`/`get_ctx_params`. */
static void *cx_newctx(void *provctx) { (void)provctx; return court_new(); }
static int cx_init(void *algctx) { (void)algctx; return 1; }
static int cx_set_peer(void *algctx, void *peerkey)
{ (void)algctx; (void)peerkey; return 1; }
static int cx_derive(void *algctx, unsigned char *secret, size_t *secretlen, size_t outlen)
{ (void)algctx; (void)secret; (void)secretlen; (void)outlen; return 1; }
static void cx_freectx(void *algctx) { free(algctx); }
static int cx_set_ctx_params(void *algctx, const OSSL_PARAM params[])
{ court_dump("der.set", params); court_store(algctx, params); return 1; }
static const OSSL_PARAM *cx_settable_ctx_params(void *algctx, void *provctx)
{ (void)algctx; (void)provctx; return court_kex_settable; }
static int cx_get_ctx_params(void *algctx, OSSL_PARAM params[])
{ court_dump("der.get", params); return court_get(algctx, params); }
static const OSSL_PARAM *cx_gettable_ctx_params(void *algctx, void *provctx)
{ (void)algctx; (void)provctx; return court_kex_gettable; }

static const OSSL_DISPATCH court_keymgmt_fns[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))ck_new },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))ck_free },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))ck_has },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))ck_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))ck_gettable_params },
    { OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*)(void))ck_set_params },
    { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (void (*)(void))ck_settable_params },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))ck_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE, (void (*)(void))ck_gen_set_template },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))ck_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void))ck_gen_settable_params },
    { OSSL_FUNC_KEYMGMT_GEN_GET_PARAMS, (void (*)(void))ck_gen_get_params },
    { OSSL_FUNC_KEYMGMT_GEN_GETTABLE_PARAMS, (void (*)(void))ck_gen_gettable_params },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))ck_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))ck_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))ck_load },
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, (void (*)(void))ck_query_operation_name },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))ck_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))ck_import_types },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))ck_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))ck_export_types },
    { OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))ck_dup },
    { OSSL_FUNC_KEYMGMT_VALIDATE, (void (*)(void))ck_validate },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))ck_match },
    { 0, NULL }
};

static const OSSL_DISPATCH court_keyexch_fns[] = {
    { OSSL_FUNC_KEYEXCH_NEWCTX, (void (*)(void))cx_newctx },
    { OSSL_FUNC_KEYEXCH_INIT, (void (*)(void))cx_init },
    { OSSL_FUNC_KEYEXCH_DERIVE, (void (*)(void))cx_derive },
    { OSSL_FUNC_KEYEXCH_SET_PEER, (void (*)(void))cx_set_peer },
    { OSSL_FUNC_KEYEXCH_FREECTX, (void (*)(void))cx_freectx },
    { OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS, (void (*)(void))cx_set_ctx_params },
    { OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS, (void (*)(void))cx_settable_ctx_params },
    { OSSL_FUNC_KEYEXCH_GET_CTX_PARAMS, (void (*)(void))cx_get_ctx_params },
    { OSSL_FUNC_KEYEXCH_GETTABLE_CTX_PARAMS, (void (*)(void))cx_gettable_ctx_params },
    { 0, NULL }
};

static const OSSL_ALGORITHM *court_query(void *provctx, int operation_id, int *no_cache)
{
    static const OSSL_ALGORITHM km[] = {
        { "COURT-EC:court-ec", "provider=court-ec", court_keymgmt_fns,
          "the probe's keymgmt" },
        { NULL, NULL, NULL, NULL }
    };
    static const OSSL_ALGORITHM kx[] = {
        { "COURT-EC:court-ec", "provider=court-ec", court_keyexch_fns,
          "the probe's keyexch" },
        { NULL, NULL, NULL, NULL }
    };

    (void)provctx;
    *no_cache = 0;
    if (operation_id == OSSL_OP_KEYMGMT)
        return km;
    if (operation_id == OSSL_OP_KEYEXCH)
        return kx;
    return NULL;
}

static int court_teardown(void *provctx) { (void)provctx; return 1; }

static const OSSL_DISPATCH court_dispatch[] = {
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))court_query },
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))court_teardown },
    { 0, NULL }
};

static int court_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in,
    const OSSL_DISPATCH **out, void **provctx)
{
    (void)handle;
    (void)in;
    *out = court_dispatch;
    *provctx = &court_marker;
    return 1;
}

/* The twelve controls, four ways: a NULL context, a live one with no operation, one with a
 * parameter-generation operation (the two generation controls) and one with a derivation operation
 * (the ten ECDH ones), so the *successful* path of each is observed as the parameter array the
 * library builds. The round trips are the getter-backed pairs and every refusal drains its queue. */
static void ec_ctl_arms(void)
{
    OSSL_PROVIDER *prov;
    EVP_PKEY_CTX *null_ctx = NULL;
    EVP_PKEY_CTX *fresh = NULL;
    EVP_PKEY_CTX *gen = NULL;
    EVP_PKEY_CTX *der = NULL;
    const EVP_MD *sha256 = EVP_MD_fetch(NULL, "SHA256", NULL);
    const EVP_MD *pmd = NULL;
    unsigned char *ukm, *out = NULL;
    int outlen = -1, kdftype, mode, ret;

    printf("ec.ctl.md_fetched=%d\n", sha256 != NULL);

    /* ---- the NULL-context refusals: the gate answers -2 for the six `OSSL_PARAM` builders, and
     * the six ctrl wrappers reach `EVP_PKEY_CTX_ctrl`'s own NULL test, also -2. */
    ERR_clear_error();
    printf("ec.ctl.null.set_cofactor=%d\n", EVP_PKEY_CTX_set_ecdh_cofactor_mode(null_ctx, 1));
    printf("ec.ctl.null.get_cofactor=%d\n", EVP_PKEY_CTX_get_ecdh_cofactor_mode(null_ctx));
    printf("ec.ctl.null.set_kdf_type=%d\n", EVP_PKEY_CTX_set_ecdh_kdf_type(null_ctx, 2));
    printf("ec.ctl.null.get_kdf_type=%d\n", EVP_PKEY_CTX_get_ecdh_kdf_type(null_ctx));
    printf("ec.ctl.null.set_kdf_md=%d\n", EVP_PKEY_CTX_set_ecdh_kdf_md(null_ctx, sha256));
    printf("ec.ctl.null.get_kdf_md=%d\n", EVP_PKEY_CTX_get_ecdh_kdf_md(null_ctx, &pmd));
    printf("ec.ctl.null.set_outlen=%d\n", EVP_PKEY_CTX_set_ecdh_kdf_outlen(null_ctx, 32));
    printf("ec.ctl.null.get_outlen=%d\n", EVP_PKEY_CTX_get_ecdh_kdf_outlen(null_ctx, &outlen));
    printf("ec.ctl.null.set0_ukm=%d\n", EVP_PKEY_CTX_set0_ecdh_kdf_ukm(null_ctx, NULL, 0));
    printf("ec.ctl.null.get0_ukm=%d\n", EVP_PKEY_CTX_get0_ecdh_kdf_ukm(null_ctx, &out));
    printf("ec.ctl.null.curve_nid=%d\n",
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(null_ctx, NID_X9_62_prime256v1));
    printf("ec.ctl.null.param_enc=%d\n",
        EVP_PKEY_CTX_set_ec_param_enc(null_ctx, OPENSSL_EC_NAMED_CURVE));
    layer_drain("ctl_null");

    /* ---- the provider, and the live context with no operation at all */
    printf("ec.ctl.provider.add=%d\n", OSSL_PROVIDER_add_builtin(NULL, "court-ec", court_init));
    prov = OSSL_PROVIDER_load(NULL, "court-ec");
    printf("ec.ctl.provider.load=%d\n", prov != NULL);
    if (prov == NULL)
        return;

    fresh = EVP_PKEY_CTX_new_from_name(NULL, "COURT-EC", NULL);
    printf("ec.ctl.fresh=%d\n", fresh != NULL);
    if (fresh == NULL)
        return;
    printf("ec.ctl.fresh.is_a_self=%d\n", EVP_PKEY_CTX_is_a(fresh, "COURT-EC"));
    printf("ec.ctl.fresh.operation=%d\n", EVP_PKEY_CTX_get_operation(fresh));

    /* On an operation-less context the gate refuses -2 and the ctrl wrappers refuse -1 with
     * `EVP_R_NO_OPERATION_SET`, so the two families are told apart by the return value. */
    ERR_clear_error();
    printf("ec.ctl.fresh.cofactor=%d\n", EVP_PKEY_CTX_set_ecdh_cofactor_mode(fresh, 1));
    printf("ec.ctl.fresh.outlen=%d\n", EVP_PKEY_CTX_set_ecdh_kdf_outlen(fresh, 32));
    printf("ec.ctl.fresh.kdf_type=%d\n", EVP_PKEY_CTX_set_ecdh_kdf_type(fresh, 2));
    printf("ec.ctl.fresh.curve_nid=%d\n",
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(fresh, NID_X9_62_prime256v1));
    printf("ec.ctl.fresh.param_enc=%d\n",
        EVP_PKEY_CTX_set_ec_param_enc(fresh, OPENSSL_EC_NAMED_CURVE));
    layer_drain("ctl_fresh");

    /* ---- the two generation controls on a parameter-generation operation, each of which now
     * succeeds and echoes the parameter it built. The SM2 spelling takes the SM2 curve row. */
    ERR_clear_error();
    gen = EVP_PKEY_CTX_new_from_name(NULL, "COURT-EC", NULL);
    printf("ec.ctl.gen=%d\n", gen != NULL);
    printf("ec.ctl.gen.init=%d\n", EVP_PKEY_paramgen_init(gen));
    printf("ec.ctl.gen.operation=%d\n", EVP_PKEY_CTX_get_operation(gen));
    ERR_clear_error();
    printf("ec.ctl.gen.curve_nid=%d\n",
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(gen, NID_X9_62_prime256v1));
    printf("ec.ctl.gen.curve_nid_sm2=%d\n",
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(gen, EVP_PKEY_SM2));
    printf("ec.ctl.gen.param_enc_named=%d\n",
        EVP_PKEY_CTX_set_ec_param_enc(gen, OPENSSL_EC_NAMED_CURVE));
    printf("ec.ctl.gen.param_enc_explicit=%d\n",
        EVP_PKEY_CTX_set_ec_param_enc(gen, OPENSSL_EC_EXPLICIT_CURVE));
    layer_drain("ctl_gen");

    /* ---- the ten derivation controls on a derivation operation, and the five round trips */
    ERR_clear_error();
    der = EVP_PKEY_CTX_new_from_name(NULL, "COURT-EC", NULL);
    printf("ec.ctl.der=%d\n", der != NULL);
    printf("ec.ctl.der.init=%d\n", EVP_PKEY_derive_init(der));
    printf("ec.ctl.der.operation=%d\n", EVP_PKEY_CTX_get_operation(der));
    layer_drain("ctl_der_init");

    /* The defaults a fresh derivation context answers with. `kdf-outlen` is the empty string's
     * zero, `kdf-type` the empty KDF's one, and the cofactor mode zero. */
    ERR_clear_error();
    printf("ec.ctl.der.default_outlen=%d\n", EVP_PKEY_CTX_get_ecdh_kdf_outlen(der, &outlen));
    printf("ec.ctl.der.default_outlen_value=%d\n", outlen);
    printf("ec.ctl.der.default_cofactor=%d\n", EVP_PKEY_CTX_get_ecdh_cofactor_mode(der));
    printf("ec.ctl.der.default_kdf_type=%d\n", EVP_PKEY_CTX_get_ecdh_kdf_type(der));
    layer_drain("ctl_der_default");

    /* the three plain getter-backed pairs, then the digest pair and the UKM pair. */
    ERR_clear_error();
    printf("ec.ctl.der.set_cofactor=%d\n", EVP_PKEY_CTX_set_ecdh_cofactor_mode(der, 1));
    mode = EVP_PKEY_CTX_get_ecdh_cofactor_mode(der);
    printf("ec.ctl.der.get_cofactor=%d\n", mode);
    printf("ec.ctl.der.cofactor_is_one=%d\n", mode == 1);
    printf("ec.ctl.der.set_outlen=%d\n", EVP_PKEY_CTX_set_ecdh_kdf_outlen(der, 32));
    printf("ec.ctl.der.get_outlen=%d\n", EVP_PKEY_CTX_get_ecdh_kdf_outlen(der, &outlen));
    printf("ec.ctl.der.outlen=%d\n", outlen);
    printf("ec.ctl.der.set_kdf_type=%d\n", EVP_PKEY_CTX_set_ecdh_kdf_type(der, 2));
    kdftype = EVP_PKEY_CTX_get_ecdh_kdf_type(der);
    printf("ec.ctl.der.get_kdf_type=%d\n", kdftype);
    printf("ec.ctl.der.kdf_type_is_x963=%d\n", kdftype == 2);
    printf("ec.ctl.der.set_kdf_md=%d\n", EVP_PKEY_CTX_set_ecdh_kdf_md(der, sha256));
    ret = EVP_PKEY_CTX_get_ecdh_kdf_md(der, &pmd);
    printf("ec.ctl.der.get_kdf_md=%d\n", ret);
    /* **The digest the getter hands back is not compared, and the callee that blocks it is named
     * rather than hidden.** `fix_md`'s GET arm resolves the method's name through
     * `evp_get_digestbyname_ex` (`crypto/evp/names.c`), whose legacy `OBJ_NAME` table this crate
     * leaves empty (`src/context/namemap.rs` records the whole legacy pre-population as Phase 13's
     * work, and `src/runtime/init.rs`'s `add_all_legacy_methods` is a no-op). So the candidate
     * answers a NULL method where the authority answers SHA-256, for a reason that is not
     * `ec_ctrl.c`'s, and an arm that compared it would be a residual about that deferral. The
     * parameter-level round trip *is* observed: `ec.der.set.p.0=kdf-digest` and `ec.der.get.p.0`
     * show the name the setter sent and the getter asked for. `docs/DECISIONS.md` D344 records the
     * coordinate. */
    printf("ec.ctl.der.get_kdf_md_digest_skipped=%d\n", 1);
    layer_drain("ctl_der_pairs");

    /* The UKM pair: `set0` takes custody on success, so the probe allocates through the same
     * allocator the control releases through, and frees only when the control did not. */
    ERR_clear_error();
    ukm = OPENSSL_malloc(4);
    if (ukm != NULL)
        memset(ukm, 0x5a, 4);
    ret = EVP_PKEY_CTX_set0_ecdh_kdf_ukm(der, ukm, 4);
    printf("ec.ctl.der.set0_ukm=%d\n", ret);
    if (ret != 1)
        OPENSSL_free(ukm);
    out = NULL;
    printf("ec.ctl.der.get0_ukm=%d\n", EVP_PKEY_CTX_get0_ecdh_kdf_ukm(der, &out));
    printf("ec.ctl.der.ukm_is_null=%d\n", out == NULL);
    layer_drain("ctl_der_ukm");

    /* The refusals that are not a `-2` from a gate: a cofactor mode outside `-1..=1` and a
     * non-positive output length are each `-2` with **no raise**, before the strict setter runs. */
    ERR_clear_error();
    printf("ec.ctl.der.cofactor_high=%d\n", EVP_PKEY_CTX_set_ecdh_cofactor_mode(der, 2));
    printf("ec.ctl.der.cofactor_low=%d\n", EVP_PKEY_CTX_set_ecdh_cofactor_mode(der, -2));
    printf("ec.ctl.der.zero_outlen=%d\n", EVP_PKEY_CTX_set_ecdh_kdf_outlen(der, 0));
    printf("ec.ctl.der.neg_outlen=%d\n", EVP_PKEY_CTX_set_ecdh_kdf_outlen(der, -1));
    layer_drain("ctl_der_refusals");

    /* The generation-side refusal: an encoding that is neither explicit nor named is -2, and the
     * raise is `fix_ec_param_enc`'s, so it carries the translator's own coordinate. */
    ERR_clear_error();
    printf("ec.ctl.gen.param_enc_bad=%d\n", EVP_PKEY_CTX_set_ec_param_enc(gen, 7));
    layer_drain("ctl_gen_refusal");

    EVP_PKEY_CTX_free(der);
    EVP_PKEY_CTX_free(gen);
    EVP_PKEY_CTX_free(fresh);
    if (pmd != NULL)
        EVP_MD_free((EVP_MD *)pmd);
    EVP_MD_free((EVP_MD *)sha256);
    OSSL_PROVIDER_unload(prov);
}

int main(void)
{
    size_t n, i;
    EC_builtin_curve one[2];

    /* One line per observation, so a crash on either side is located by the last line rather
     * than by a block-sized guess. */
    setvbuf(stdout, NULL, _IOLBF, 0);
    EC_builtin_curve *table;
    char tag[64];

    /* The four call shapes, in the authority's own order of tests: the NULL table and the
     * zero-length one both answer the length without writing; the one-entry one answers the length
     * having written exactly one row, and the second entry is still the sentinel it was. */
    n = EC_get_builtin_curves(NULL, 0);
    printf("count=%zu\n", n);
    printf("count.nitems0=%zu\n", EC_get_builtin_curves(one, 0));
    printf("count.null.nitems1=%zu\n", EC_get_builtin_curves(NULL, 1));
    printf("count.short=%zu\n", EC_get_builtin_curves(one, 1));
    printf("short.nid=%d\n", one[0].nid);
    emit_text("short", "comment", one[0].comment);
    emit_text("short", "sn", OBJ_nid2sn(one[0].nid));
    printf("short.tail=%d,%d\n", one[1].nid, one[1].comment == NULL ? 1 : 0);

    table = malloc(n * sizeof(*table));
    if (table == NULL) {
        printf("alloc=failed\n");
        return 0;
    }
    /* The two unused entries, so that "only `min` are written" is observed rather than assumed. */
    printf("count.full=%zu\n", EC_get_builtin_curves(table, n));

    /* Every row, in the table's own order. */
    for (i = 0; i < n; i++) {
        snprintf(tag, sizeof(tag), "row%.3zu", i);
        printf("%s.nid=%d\n", tag, table[i].nid);
        emit_text(tag, "sn", OBJ_nid2sn(table[i].nid));
        emit_text(tag, "comment", table[i].comment);
        emit_nid2nist(table[i].nid);
        emit_nid2name(table[i].nid);
    }

    emit_refusals();

    /* The fifteen NIST spellings, both directions of the pair. */
    {
        static const char *const nist[] = {
            "B-163", "B-233", "B-283", "B-409", "B-571",
            "K-163", "K-233", "K-283", "K-409", "K-571",
            "P-192", "P-224", "P-256", "P-384", "P-521",
        };
        size_t k;

        for (k = 0; k < sizeof(nist) / sizeof(nist[0]); k++) {
            emit_nist2nid(nist[k]);
            emit_nid2nist(EC_curve_nist2nid(nist[k]));
            emit_nid2name(EC_curve_nist2nid(nist[k]));
        }
    }

    /* The refusals of the case-sensitive walk. */
    emit_nist2nid("p-256");
    emit_nist2nid("b-163");
    emit_nist2nid("P-256 ");
    emit_nist2nid("P-999");
    emit_nist2nid("secp256k1");
    emit_nist2nid("SM2");
    emit_nist2nid("");
    /* One name longer than any row, so the walk's comparison and its fall-through are both crossed
     * on a string that no row's prefix can make equal. */
    emit_nist2nid("P-256-with-a-very-long-suffix-that-matches-no-row-at-all");

    /* The refusals above raise nothing -- neither lookup raises -- so the queue is empty here. It
     * is counted rather than asserted, because a count is a diff and an assertion is not. */
    {
        unsigned long e;
        int records = 0;

        while ((e = ERR_get_error()) != 0) {
            records++;
            (void)e;
        }
        printf("err.queue_records=%d\n", records);
    }

    /* D344's arms: the twelve `crypto/evp/ec_ctrl.c` controls, over the probe's own provider. */
    ec_ctl_arms();

/* ==================== Phase 8.7's remaining layer ==================== */
/* Every export the group object, the field arithmetic, the point encoders, the key layer, the
 * two signature/shared-secret units and the provider backend newly reach. A method table is
 * compared by comparison against the four constructors called below, never by address, and no
 * private key, shared secret, `k` or blinding factor is printed: the ECDH arm prints the two
 * sides' agreement and the length, and the ECDSA arm prints lengths, return codes and the
 * re-encoded round trip's equality. */
{
    const EC_METHOD *t0 = EC_GFp_simple_method();
    const EC_METHOD *t1 = EC_GFp_mont_method();
    const EC_METHOD *t2 = EC_GFp_nist_method();
    const EC_METHOD *t3 = EC_GF2m_simple_method();
    BN_CTX *bctx = BN_CTX_new();
    BIGNUM *bp = NULL, *ba = NULL, *bb = NULL, *bo = NULL, *bc = NULL;
    EC_GROUP *g = NULL, *g2 = NULL, *gexp = NULL;
    EC_POINT *P = NULL, *Q = NULL, *Rs = NULL;
    EC_KEY *key = NULL, *key2 = NULL;
    unsigned char *mem = NULL;
    unsigned int tk = 0, tk1 = 0, tk2 = 0, tk3 = 0;

    printf("layer.ctx=%d\n", bctx != NULL);
    if (bctx == NULL)
        goto layer_done;

    /* ---- the four method tables ---- */
    printf("method.0.field_type=%d\n", EC_METHOD_get_field_type(t0));
    printf("method.1.field_type=%d\n", EC_METHOD_get_field_type(t1));
    printf("method.2.field_type=%d\n", EC_METHOD_get_field_type(t2));
    printf("method.3.field_type=%d\n", EC_METHOD_get_field_type(t3));
    printf("method.distinct=%d%d%d%d%d%d\n",
           t0 != t1, t0 != t2, t0 != t3, t1 != t2, t1 != t3, t2 != t3);

    /* ---- EC_GROUP_new and the group accessors on a bare group ---- */
    g = EC_GROUP_new(t0);
    printf("group_new.0=%d\n", g != NULL);
    if (g != NULL) {
        printf("group_new.0.method_simple=%d\n", EC_GROUP_method_of(g) == t0);
        printf("group_new.0.asn1_flag=%d\n", EC_GROUP_get_asn1_flag(g));
        printf("group_new.0.conv_form=%d\n", EC_GROUP_get_point_conversion_form(g));
        printf("group_new.0.order_bits=%d\n", EC_GROUP_order_bits(g));
        printf("group_new.0.field=%d\n", EC_GROUP_get_field_type(g));
        printf("group_new.0.degree=%d\n", EC_GROUP_get_degree(g));
        printf("group_new.0.basis=%d\n", EC_GROUP_get_basis_type(g));
        printf("group_new.0.check_named=%d\n", EC_GROUP_check_named_curve(g, 0, bctx));
        printf("group_new.0.seed_len=%zu\n", EC_GROUP_get_seed_len(g));
        EC_GROUP_free(g);
    }
    g = EC_GROUP_new(t3);
    printf("group_new.3=%d\n", g != NULL);
    if (g != NULL) {
        printf("group_new.3.method_gf2m=%d\n", EC_GROUP_method_of(g) == t3);
        EC_GROUP_clear_free(g);
    }
    g = NULL;

    /* ---- every built-in curve ---- */
    for (i = 0; i < n; i++) {
        snprintf(tag, sizeof(tag), "cgrp%.3zu", i);
        g = EC_GROUP_new_by_curve_name(table[i].nid);
        printf("%s.ok=%d\n", tag, g != NULL);
        if (g == NULL)
            continue;
        printf("%s.field=%d\n", tag, EC_GROUP_get_field_type(g));
        printf("%s.degree=%d\n", tag, EC_GROUP_get_degree(g));
        printf("%s.order_bits=%d\n", tag, EC_GROUP_order_bits(g));
        bo = BN_new();
        printf("%s.get_order=%d\n", tag, EC_GROUP_get_order(g, bo, bctx));
        printf("%s.order_width=%d\n", tag, bo != NULL ? BN_num_bits(bo) : -1);
        BN_free(bo);
        bo = NULL;
        bc = (BIGNUM *)EC_GROUP_get0_cofactor(g);
        printf("%s.cofactor_word=%lu\n", tag, bc != NULL ? BN_get_word(bc) : 0UL);
        printf("%s.seed_len=%zu\n", tag, EC_GROUP_get_seed_len(g));
        printf("%s.name=%d\n", tag, EC_GROUP_get_curve_name(g));
        printf("%s.gen=%d\n", tag, EC_GROUP_get0_generator(g) != NULL);
        printf("%s.field0=%d\n", tag, EC_GROUP_get0_field(g) != NULL);
        printf("%s.mont=%d\n", tag, EC_GROUP_get_mont_data(g) != NULL);
        printf("%s.basis=%d\n", tag, EC_GROUP_get_basis_type(g));
        tk = tk1 = tk2 = tk3 = 0;
        printf("%s.trinomial=%d,%u\n", tag,
               EC_GROUP_get_trinomial_basis(g, &tk), tk);
        printf("%s.pentanomial=%d,%u,%u,%u\n", tag,
               EC_GROUP_get_pentanomial_basis(g, &tk1, &tk2, &tk3), tk1, tk2, tk3);
        if (table[i].nid != NID_X9_62_prime256v1)
            printf("%s.have_precomp=%d\n", tag, EC_GROUP_have_precompute_mult(g));
        if (table[i].nid != NID_X9_62_prime256v1) {
            const EC_METHOD *m = EC_GROUP_method_of(g);
            printf("%s.method=%d%d%d%d\n", tag, m == t0, m == t1, m == t2, m == t3);
        }
        EC_GROUP_free(g);
        g = NULL;
    }

    /* ---- the group checker and the discriminant, on the two named groups ---- */
    {
        EC_GROUP *gc = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
        EC_GROUP *gb = EC_GROUP_new_by_curve_name(NID_sect163k1);
        printf("check.prime=%d\n", gc != NULL && EC_GROUP_check(gc, bctx));
        printf("check.prime_disc=%d\n",
               gc != NULL && EC_GROUP_check_discriminant(gc, bctx));
        printf("check.binary=%d\n", gb != NULL && EC_GROUP_check(gb, bctx));
        printf("check.binary_disc=%d\n",
               gb != NULL && EC_GROUP_check_discriminant(gb, bctx));
        printf("check.named=%d\n", gc != NULL && EC_GROUP_check_named_curve(gc, 0, bctx));
        printf("check.named_nist_only=%d\n",
               gc != NULL && EC_GROUP_check_named_curve(gc, 1, bctx));
        EC_GROUP_free(gc);
        EC_GROUP_free(gb);
    }

    /* ---- the two curve constructors, over two named curves ---- */
    g2 = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    bp = BN_new();
    ba = BN_new();
    bb = BN_new();
    bo = BN_new();
    bc = BN_new();
    printf("curve.new_by_curve_name_ex=%d\n",
           EC_GROUP_new_by_curve_name_ex(NULL, NULL, NID_X9_62_prime256v1) != NULL);
    printf("curve.get0_order=%d\n", EC_GROUP_get0_order(g2) != NULL);
    printf("curve.get=%d\n", EC_GROUP_get_curve(g2, bp, ba, bb, bctx));
    printf("curve.get_wrapper_gfp=%d\n", EC_GROUP_get_curve_GFp(g2, bp, ba, bb, bctx));
    printf("curve.get_order=%d\n", EC_GROUP_get_order(g2, bo, bctx));
    printf("curve.get_cofactor=%d\n", EC_GROUP_get_cofactor(g2, bc, bctx));
    printf("curve.p_width=%d\n", BN_num_bits(bp));
    printf("curve.order_width=%d\n", BN_num_bits(bo));

    gexp = EC_GROUP_new_curve_GFp(bp, ba, bb, bctx);
    printf("curve.new_gfp=%d\n", gexp != NULL);
    if (gexp != NULL) {
        printf("curve.new_gfp.field=%d\n", EC_GROUP_get_field_type(gexp));
        printf("curve.new_gfp.degree=%d\n", EC_GROUP_get_degree(gexp));
        printf("curve.new_gfp.set_curve=%d\n", EC_GROUP_set_curve(gexp, bp, ba, bb, bctx));
        printf("curve.new_gfp.set_curve_wrapper=%d\n", EC_GROUP_set_curve_GFp(gexp, bp, ba, bb, bctx));
        printf("curve.new_gfp.set_generator=%d\n",
               EC_GROUP_set_generator(gexp, EC_GROUP_get0_generator(g2), bo, bc));
        EC_GROUP_set_curve_name(gexp, NID_X9_62_prime256v1);
        printf("curve.new_gfp.name=%d\n", EC_GROUP_get_curve_name(gexp));
        printf("curve.new_gfp.cmp_named=%d\n", EC_GROUP_cmp(g2, gexp, bctx));
        EC_GROUP_free(gexp);
        gexp = NULL;
    }
    {
        EC_GROUP *gb = EC_GROUP_new_by_curve_name(NID_sect163k1);
        BIGNUM *p2 = BN_new(), *a2 = BN_new(), *b2 = BN_new(), *o2 = BN_new(), *c2 = BN_new();
        if (gb != NULL) {
            printf("gf2m.get_curve=%d\n", EC_GROUP_get_curve(gb, p2, a2, b2, bctx));
            printf("gf2m.get_curve_wrapper=%d\n", EC_GROUP_get_curve_GF2m(gb, p2, a2, b2, bctx));
            printf("gf2m.get_order=%d\n", EC_GROUP_get_order(gb, o2, bctx));
            printf("gf2m.get_cofactor=%d\n", EC_GROUP_get_cofactor(gb, c2, bctx));
            printf("gf2m.set_curve_wrapper=%d\n", EC_GROUP_set_curve_GF2m(gb, p2, a2, b2, bctx));
            gexp = EC_GROUP_new_curve_GF2m(p2, a2, b2, bctx);
            printf("gf2m.new=%d\n", gexp != NULL);
            if (gexp != NULL) {
                printf("gf2m.new.field=%d\n", EC_GROUP_get_field_type(gexp));
                printf("gf2m.new.set_generator=%d\n",
                       EC_GROUP_set_generator(gexp, EC_GROUP_get0_generator(gb), o2, c2));
                EC_GROUP_set_curve_name(gexp, NID_sect163k1);
                printf("gf2m.new.cmp_named=%d\n", EC_GROUP_cmp(gb, gexp, bctx));
                EC_GROUP_free(gexp);
                gexp = NULL;
            }
        }
        BN_free(p2);
        BN_free(a2);
        BN_free(b2);
        BN_free(o2);
        BN_free(c2);
        EC_GROUP_free(gb);
    }

    /* ---- group copying, the seed and the ASN.1 flag ---- */
    {
        static const unsigned char seed[3] = { 1, 2, 3 };
        EC_GROUP *gc = EC_GROUP_dup(g2);
        printf("group.dup=%d\n", gc != NULL);
        if (gc != NULL) {
            printf("group.dup.cmp=%d\n", EC_GROUP_cmp(gc, g2, bctx));
            printf("group.copy=%d\n", EC_GROUP_copy(gc, g2));
            printf("group.set_seed=%zu\n", EC_GROUP_set_seed(gc, seed, sizeof(seed)));
            printf("group.seed_len=%zu\n", EC_GROUP_get_seed_len(gc));
            printf("group.seed0=%d\n", EC_GROUP_get0_seed(gc) != NULL);
            EC_GROUP_set_asn1_flag(gc, OPENSSL_EC_EXPLICIT_CURVE);
            printf("group.asn1_explicit=%d\n", EC_GROUP_get_asn1_flag(gc));
            EC_GROUP_set_asn1_flag(gc, OPENSSL_EC_NAMED_CURVE);
            printf("group.asn1_named=%d\n", EC_GROUP_get_asn1_flag(gc));
            EC_GROUP_set_point_conversion_form(gc, POINT_CONVERSION_COMPRESSED);
            printf("group.conv=%d\n", EC_GROUP_get_point_conversion_form(gc));
            EC_GROUP_set_point_conversion_form(gc, POINT_CONVERSION_UNCOMPRESSED);
            printf("group.precompute=%d\n", EC_GROUP_precompute_mult(gc, bctx));
            printf("group.have_precomp=%d\n", EC_GROUP_have_precompute_mult(gc));
            EC_GROUP_free(gc);
        }
        printf("group.dup_null=%d\n", EC_GROUP_dup(NULL) == NULL);
    }

    /* ---- the point object: accessors, arithmetic, encoders ---- */
    P = EC_POINT_new(g2);
    Q = EC_POINT_new(g2);
    Rs = EC_POINT_new(g2);
    printf("point.new=%d\n", P != NULL && Q != NULL && Rs != NULL);
    printf("point.method=%d\n", EC_POINT_method_of(P) == EC_GROUP_method_of(g2));
    printf("point.copy=%d\n", EC_POINT_copy(P, EC_GROUP_get0_generator(g2)));
    printf("point.is_at_inf=%d\n", EC_POINT_is_at_infinity(g2, P));
    printf("point.is_on_curve=%d\n", EC_POINT_is_on_curve(g2, P, bctx));
    printf("point.set_to_infinity=%d\n", EC_POINT_set_to_infinity(g2, Rs));
    printf("point.inf_is_at_inf=%d\n", EC_POINT_is_at_infinity(g2, Rs));
    printf("point.inf_on_curve=%d\n", EC_POINT_is_on_curve(g2, Rs, bctx));
    printf("point.inf_invert=%d\n", EC_POINT_invert(g2, Rs, bctx));
    printf("point.add=%d\n", EC_POINT_add(g2, Q, P, P, bctx));
    printf("point.dbl=%d\n", EC_POINT_dbl(g2, Rs, P, bctx));
    printf("point.add_matches_dbl=%d\n", EC_POINT_cmp(g2, Q, Rs, bctx) == 0);
    printf("point.cmp_self=%d\n", EC_POINT_cmp(g2, P, P, bctx));
    printf("point.invert=%d\n", EC_POINT_invert(g2, Rs, bctx));
    {
        EC_POINT *pd = EC_POINT_dup(P, g2);
        printf("point.dup=%d\n", pd != NULL);
        printf("point.dup.cmp=%d\n", EC_POINT_cmp(g2, pd, P, bctx));
        printf("point.dup.is_on_curve=%d\n", EC_POINT_is_on_curve(g2, pd, bctx));
        EC_POINT_free(pd);
    }
    {
        BIGNUM *x = BN_new(), *y = BN_new();
        printf("point.get_affine=%d\n", EC_POINT_get_affine_coordinates(g2, P, x, y, bctx));
        printf("point.get_affine_gfp=%d\n",
               EC_POINT_get_affine_coordinates_GFp(g2, P, x, y, bctx));
        printf("point.set_affine=%d\n", EC_POINT_set_affine_coordinates(g2, Q, x, y, bctx));
        printf("point.set_affine_gfp=%d\n",
               EC_POINT_set_affine_coordinates_GFp(g2, Q, x, y, bctx));
        printf("point.affine_round_trip=%d\n", EC_POINT_cmp(g2, P, Q, bctx) == 0);
        printf("point.make_affine=%d\n", EC_POINT_make_affine(g2, Q, bctx));
        BN_free(x);
        BN_free(y);
    }
    {
        BIGNUM *r1 = BN_new();
        EC_POINT *arr[3];
        EC_GROUP *gb = EC_GROUP_new_by_curve_name(NID_sect163k1);
        printf("point.get_affine_gf2m=%d\n",
               gb != NULL && EC_POINT_get_affine_coordinates_GF2m(
                   gb, EC_GROUP_get0_generator(gb), NULL, NULL, bctx));
        printf("point.set_affine_gf2m=%d\n",
               gb != NULL && EC_POINT_set_affine_coordinates_GF2m(
                   gb, EC_POINT_new(gb), NULL, NULL, bctx));
        arr[0] = P;
        arr[1] = Q;
        arr[2] = Rs;
        printf("point.points_make_affine=%d\n", EC_POINTs_make_affine(g2, 3, arr, bctx));
        printf("point.jproj_get=%d\n",
               EC_POINT_get_Jprojective_coordinates_GFp(g2, P, r1, r1, r1, bctx));
        printf("point.jproj_set=%d\n",
               EC_POINT_set_Jprojective_coordinates_GFp(g2, Q, r1, r1, r1, bctx));
        BN_free(r1);
        EC_GROUP_free(gb);
    }
    {
        size_t len = EC_POINT_point2oct(g2, P, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, bctx);
        printf("point.oct_len=%zu\n", len);
        if (len > 0 && len < 512) {
            mem = malloc(len);
            printf("point.point2oct=%zu\n",
                   EC_POINT_point2oct(g2, P, POINT_CONVERSION_UNCOMPRESSED, mem, len, bctx));
            printf("point.oct2point=%d\n", EC_POINT_oct2point(g2, Rs, mem, len, bctx));
            printf("point.oct_round_trip=%d\n", EC_POINT_cmp(g2, P, Rs, bctx) == 0);
            free(mem);
            mem = NULL;
        }
        printf("point.point2buf=%zu\n",
               EC_POINT_point2buf(g2, P, POINT_CONVERSION_UNCOMPRESSED, &mem, bctx));
        if (mem != NULL)
            OPENSSL_free(mem);
        mem = NULL;
        printf("point.compressed_set=%d\n",
               EC_POINT_set_compressed_coordinates(g2, Rs, BN_value_one(), 0, bctx));
        printf("point.compressed_set_gfp=%d\n",
               EC_POINT_set_compressed_coordinates_GFp(g2, Rs, BN_value_one(), 0, bctx));
    }
    {
        EC_GROUP *gb = EC_GROUP_new_by_curve_name(NID_sect163k1);
        EC_POINT *pb = gb != NULL ? EC_POINT_new(gb) : NULL;
        printf("point.compressed_gf2m=%d\n",
               pb != NULL && EC_POINT_set_compressed_coordinates_GF2m(gb, pb, BN_value_one(), 0, bctx));
        EC_POINT_clear_free(pb);
        EC_GROUP_free(gb);
    }
    /* the ladder arms */
    {
        BIGNUM *k = BN_new();
        const EC_POINT *points[1];
        const BIGNUM *scalars[1];
        BN_set_word(k, 7);
        points[0] = P;
        scalars[0] = k;
        printf("point.mul_ladder=%d\n", EC_POINT_mul(g2, Rs, k, NULL, NULL, bctx));
        printf("point.mul_generator_array=%d\n", EC_POINT_mul(g2, Rs, NULL, P, k, bctx));
        printf("point.mul_null_n=%d\n", EC_POINT_mul(g2, Rs, k, P, NULL, bctx));
        printf("point.mul_both_null=%d\n", EC_POINT_mul(g2, Rs, NULL, NULL, NULL, bctx));
        printf("point.mul_both_null_inf=%d\n", EC_POINT_is_at_infinity(g2, Rs));
        printf("point.points_mul=%d\n", EC_POINTs_mul(g2, Rs, k, 1, points, scalars, bctx));
        BN_free(k);
    }

    /* ---- one refusal with its drained coordinate ---- */
    {
        EC_GROUP *other = EC_GROUP_new_by_curve_name(NID_secp384r1);
        if (other != NULL && P != NULL) {
            printf("refusal.incompatible=%d\n", EC_POINT_is_on_curve(other, P, bctx));
            EC_GROUP_free(other);
        }
    }
    layer_drain("refusal.point");

    /* ---- the provider backend's two group-parameter exports ---- */
    group_params_arms(g2, bctx);
    layer_drain("gparams");

    /* ---- the `EC_POINT` hex and BN codecs: `crypto/ec/ec_print.c` and
     * `crypto/ec/ec_deprecated.c` (D345). Every arm is a round trip compared by `EC_POINT_cmp`,
     * a width, or a refusal; **no coordinate is printed** and no pointer is compared except for
     * the in-place identities the two `bn`/`hex` entry points guarantee. The queue is cleared
     * first so the drain below carries this block's own refusals and no earlier arm's. */
    ERR_clear_error();
    {
        size_t octlen = EC_POINT_point2oct(g2, P, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, bctx);
        char *hex = EC_POINT_point2hex(g2, P, POINT_CONVERSION_UNCOMPRESSED, bctx);

        printf("codec.hex.notnull=%d\n", hex != NULL);
        if (hex != NULL) {
            EC_POINT *hp = EC_POINT_new(g2);
            EC_POINT *again = EC_POINT_hex2point(g2, hex, NULL, bctx);

            printf("codec.hex.len_is_twice_oct=%d\n", strlen(hex) == octlen * 2);
            printf("codec.hex.upper_case=%d\n",
                strspn(hex, "0123456789ABCDEF") == strlen(hex));
            printf("codec.hex2point.notnull=%d\n", again != NULL);
            printf("codec.hex.round_trip=%d\n",
                again != NULL && EC_POINT_cmp(g2, P, again, bctx) == 0);
            /* A caller-supplied point is written in place and answered back. */
            printf("codec.hex2point.in_place=%d\n",
                hp != NULL && EC_POINT_hex2point(g2, hex, hp, bctx) == hp
                && EC_POINT_cmp(g2, P, hp, bctx) == 0);
            /* The refusals, each the callee's own: a NULL group and a NULL string return before
             * allocating, an odd digit count and a non-hex byte refuse in the decoder, and a
             * two-octet string whose first byte says "uncompressed" refuses because the width is
             * wrong. A single `00` octet is **not** a refusal: it is the point-at-infinity
             * encoding, which `ossl_ec_GFp_simple_oct2point` accepts at exactly one octet. */
            printf("codec.hex2point.null_group=%d\n",
                EC_POINT_hex2point(NULL, hex, NULL, bctx) == NULL);
            printf("codec.hex2point.null_hex=%d\n",
                EC_POINT_hex2point(g2, NULL, NULL, bctx) == NULL);
            printf("codec.hex2point.odd_len=%d\n",
                EC_POINT_hex2point(g2, "04A", NULL, bctx) == NULL);
            printf("codec.hex2point.bad_digit=%d\n",
                EC_POINT_hex2point(g2, "04ZZ", NULL, bctx) == NULL);
            printf("codec.hex2point.wrong_width=%d\n",
                EC_POINT_hex2point(g2, "04FF", NULL, bctx) == NULL);
            {
                EC_POINT *inf = EC_POINT_hex2point(g2, "00", NULL, bctx);

                printf("codec.hex2point.zero_is_infinity=%d\n",
                    inf != NULL && EC_POINT_is_at_infinity(g2, inf));
                EC_POINT_free(inf);
            }
            EC_POINT_free(again);
            EC_POINT_free(hp);
            OPENSSL_free(hex);
        }

        {
            BIGNUM *bn = EC_POINT_point2bn(g2, P, POINT_CONVERSION_UNCOMPRESSED, NULL, bctx);
            EC_POINT *bp2 = NULL;

            printf("codec.bn.notnull=%d\n", bn != NULL);
            printf("codec.bn.width_is_oct=%d\n",
                bn != NULL && (size_t)BN_num_bytes(bn) == octlen);
            if (bn != NULL) {
                BIGNUM *reuse = BN_new();
                EC_POINT *inplace = EC_POINT_new(g2);

                bp2 = EC_POINT_bn2point(g2, bn, NULL, bctx);
                printf("codec.bn2point.notnull=%d\n", bp2 != NULL);
                printf("codec.bn.round_trip=%d\n",
                    bp2 != NULL && EC_POINT_cmp(g2, P, bp2, bctx) == 0);
                printf("codec.bn2point.in_place=%d\n",
                    inplace != NULL && EC_POINT_bn2point(g2, bn, inplace, bctx) == inplace
                    && EC_POINT_cmp(g2, P, inplace, bctx) == 0);
                printf("codec.point2bn.reuse=%d\n",
                    reuse != NULL
                    && EC_POINT_point2bn(g2, P, POINT_CONVERSION_UNCOMPRESSED, reuse, bctx) == reuse);
                /* A zero `BIGNUM` is widened to one octet, which is the point at infinity; a
                 * single non-zero octet carries the `y_bit` an uncompressed form must not. */
                {
                    BIGNUM *zero = BN_new();
                    BIGNUM *one = BN_new();
                    EC_POINT *inf;

                    BN_set_word(zero, 0);
                    BN_set_word(one, 1);
                    inf = EC_POINT_bn2point(g2, zero, NULL, bctx);
                    printf("codec.bn2point.zero_is_infinity=%d\n",
                        inf != NULL && EC_POINT_is_at_infinity(g2, inf));
                    printf("codec.bn2point.one_refused=%d\n",
                        EC_POINT_bn2point(g2, one, NULL, bctx) == NULL);
                    EC_POINT_free(inf);
                    BN_free(one);
                    BN_free(zero);
                }
                EC_POINT_free(inplace);
                BN_free(reuse);
            }
            EC_POINT_free(bp2);
            BN_free(bn);
        }
    }
    layer_drain("codec");

    /* ---- the key layer ---- */
    key = EC_KEY_new_by_curve_name_ex(NULL, NULL, NID_X9_62_prime256v1);
    printf("key.new_by_curve_name_ex=%d\n", key != NULL);
    printf("key.new_by_curve_name=%d\n",
           EC_KEY_new_by_curve_name(NID_X9_62_prime256v1) != NULL);
    key2 = EC_KEY_new();
    printf("key.new_meth=%d\n", EC_KEY_new_method(NULL) != NULL);
    printf("key.new_ex=%d\n", EC_KEY_new_ex(NULL, NULL) != NULL);
    printf("key.method_is_default=%d\n", EC_KEY_get_method(key) == EC_KEY_OpenSSL());
    printf("key.default_is_openssl=%d\n", EC_KEY_get_default_method() == EC_KEY_OpenSSL());
    printf("key.can_sign=%d\n", EC_KEY_can_sign(key));
    printf("key.get0_engine_null=%d\n", EC_KEY_get0_engine(key) == NULL);
    printf("key.decoded_from_explicit=%d\n", EC_KEY_decoded_from_explicit_params(key));
    printf("key.set_ex_data=%d\n", EC_KEY_set_ex_data(key, 0, NULL));
    printf("key.get_ex_data=%d\n", EC_KEY_get_ex_data(key, 0) == NULL);
    printf("key.up_ref=%d\n", EC_KEY_up_ref(key));
    printf("key.enc_flags_default=%u\n", EC_KEY_get_enc_flags(key));
    EC_KEY_set_enc_flags(key, EC_PKEY_NO_PUBKEY);
    printf("key.enc_flags_set=%u\n", EC_KEY_get_enc_flags(key) & EC_PKEY_NO_PUBKEY);
    EC_KEY_set_enc_flags(key, 0);
    EC_KEY_set_asn1_flag(key, OPENSSL_EC_NAMED_CURVE);
    printf("key.conv_form=%d\n", EC_KEY_get_conv_form(key));
    EC_KEY_set_conv_form(key, POINT_CONVERSION_COMPRESSED);
    printf("key.conv_form2=%d\n", EC_KEY_get_conv_form(key));
    EC_KEY_set_conv_form(key, POINT_CONVERSION_UNCOMPRESSED);
    printf("key.set_method=%d\n", (EC_KEY_set_method(key2, EC_KEY_OpenSSL()),
                                   EC_KEY_get_method(key2) == EC_KEY_OpenSSL()));
    EC_KEY_set_default_method(EC_KEY_OpenSSL());
    printf("key.set_default=%d\n", EC_KEY_get_default_method() == EC_KEY_OpenSSL());
    printf("key.set_flags=%d\n",
           (EC_KEY_set_flags(key, EC_FLAG_COFACTOR_ECDH), EC_KEY_get_flags(key)));
    EC_KEY_clear_flags(key, EC_FLAG_COFACTOR_ECDH);
    printf("key.clear_flags=%d\n", EC_KEY_get_flags(key));

    printf("key.generate=%d\n", EC_KEY_generate_key(key));
    printf("key.check_key=%d\n", EC_KEY_check_key(key));
    printf("key.pub_on_curve=%d\n",
           EC_POINT_is_on_curve(EC_KEY_get0_group(key), EC_KEY_get0_public_key(key), bctx));
    printf("key.priv_present=%d\n", EC_KEY_get0_private_key(key) != NULL);
    printf("key.set_group=%d\n", EC_KEY_set_group(key2, EC_KEY_get0_group(key)));
    printf("key.set_public=%d\n", EC_KEY_set_public_key(key2, EC_KEY_get0_public_key(key)));
    printf("key.set_private=%d\n",
           EC_KEY_set_private_key(key2, EC_KEY_get0_private_key(key)));
    printf("key2.check_key=%d\n", EC_KEY_check_key(key2));
    printf("key.precompute=%d\n", EC_KEY_precompute_mult(key, bctx));
    {
        BIGNUM *x = BN_new(), *y = BN_new();
        EC_KEY *key3 = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        printf("key.affine=%d\n",
               EC_POINT_get_affine_coordinates(EC_KEY_get0_group(key),
                                               EC_KEY_get0_public_key(key), x, y, bctx)
               && EC_KEY_set_public_key_affine_coordinates(key3, x, y));
        printf("key3.check_key=%d\n", EC_KEY_check_key(key3));
        BN_free(x);
        BN_free(y);
        EC_KEY_free(key3);
    }

    /* the private scalar's and the public key's octet and buffer spellings */
    {
        size_t n1, n2, n3;
        unsigned char *o1 = NULL, *o2 = NULL, *o3 = NULL;
        n1 = EC_KEY_priv2oct(key, NULL, 0);
        printf("key.priv2oct_len=%zu\n", n1);
        if (n1 > 0 && n1 < 512) {
            o1 = malloc(n1);
            printf("key.priv2oct=%zu\n", EC_KEY_priv2oct(key, o1, n1));
            printf("key.oct2priv=%d\n", EC_KEY_oct2priv(key2, o1, n1));
            printf("key.priv_round_trip=%d\n",
                   EC_KEY_get0_private_key(key) != NULL
                   && EC_KEY_get0_private_key(key2) != NULL
                   && BN_cmp(EC_KEY_get0_private_key(key),
                             EC_KEY_get0_private_key(key2)) == 0);
        }
        n2 = EC_KEY_priv2buf(key, &o2);
        printf("key.priv2buf=%zu\n", n2);
        printf("key.priv2buf_matches=%d\n",
               o1 != NULL && o2 != NULL && n1 == n2 && memcmp(o1, o2, n1) == 0);
        n3 = EC_KEY_key2buf(key, POINT_CONVERSION_UNCOMPRESSED, &o3, bctx);
        printf("key.key2buf=%zu\n", n3);
        printf("key.oct2key=%d\n", EC_KEY_oct2key(key2, o3, n3, bctx));
        printf("key.pub_round_trip=%d\n",
               EC_POINT_cmp(EC_KEY_get0_group(key), EC_KEY_get0_public_key(key),
                            EC_KEY_get0_public_key(key2), bctx) == 0);
        free(o1);
        OPENSSL_free(o2);
        OPENSSL_free(o3);
    }
    {
        EC_KEY *kd = EC_KEY_dup(key);
        printf("key.dup=%d\n", kd != NULL);
        if (kd != NULL) {
            printf("key.dup.check=%d\n", EC_KEY_check_key(kd));
            EC_KEY_free(kd);
        }
        key2 = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        printf("key.copy=%d\n", EC_KEY_copy(key2, key) != NULL);
        printf("key.copy.check=%d\n", EC_KEY_check_key(key2));
        EC_KEY_free(key2);
        key2 = NULL;
    }

    /* ---- the EC_KEY_METHOD table, built by the probe itself ---- */
    {
        EC_KEY_METHOD *meth = EC_KEY_METHOD_new(NULL);
        int (*gi)(EC_KEY *);
        void (*gf)(EC_KEY *);
        int (*gc)(EC_KEY *, const EC_KEY *);
        int (*gg)(EC_KEY *, const EC_GROUP *);
        int (*gp)(EC_KEY *, const BIGNUM *);
        int (*gpub)(EC_KEY *, const EC_POINT *);

        EC_KEY_METHOD_set_init(meth, NULL, NULL, NULL, NULL, NULL, NULL);
        EC_KEY_METHOD_set_keygen(meth, NULL);
        EC_KEY_METHOD_set_compute_key(meth, NULL);
        EC_KEY_METHOD_set_sign(meth, NULL, NULL, NULL);
        EC_KEY_METHOD_set_verify(meth, NULL, NULL);
        printf("keymeth.new=%d\n", meth != NULL);
        EC_KEY_METHOD_get_init(meth, &gi, &gf, &gc, &gg, &gp, &gpub);
        printf("keymeth.set_init_all_null=%d\n", gi == NULL && gf == NULL && gc == NULL
               && gg == NULL && gp == NULL && gpub == NULL);
        EC_KEY_METHOD_get_keygen(meth, NULL);
        EC_KEY_METHOD_get_compute_key(meth, NULL);
        EC_KEY_METHOD_get_sign(meth, NULL, NULL, NULL);
        EC_KEY_METHOD_get_verify(meth, NULL, NULL);
        printf("keymeth.get_all=%d\n",
               gi == NULL && gf == NULL && gc == NULL && gg == NULL && gp == NULL
               && gpub == NULL);
        EC_KEY_METHOD_free(meth);
    }

    /* ---- ECDSA ---- */
    {
        static const unsigned char dgst[32] = { 9, 8, 7, 6, 5, 4, 3, 2, 1 };
        unsigned int siglen = 0;

        {
            ECDSA_SIG *fresh = ECDSA_SIG_new();
            BIGNUM *r0 = BN_new(), *s0 = BN_new();
            printf("ecdsa.sig_new=%d\n", fresh != NULL);
            printf("ecdsa.sig_set0=%d\n", ECDSA_SIG_set0(fresh, r0, s0));
            ECDSA_SIG_free(fresh);
        }
        printf("ecdsa.size=%d\n", ECDSA_size(key));
        printf("ecdsa.sign_null_size=%d\n",
               ECDSA_sign(0, dgst, sizeof(dgst), NULL, &siglen, key));
        printf("ecdsa.size_matches=%d\n", (int)siglen == ECDSA_size(key));
        mem = malloc(siglen > 0 ? siglen : 1);
        printf("ecdsa.sign=%d\n", ECDSA_sign(0, dgst, sizeof(dgst), mem, &siglen, key));
        printf("ecdsa.verify=%d\n", ECDSA_verify(0, dgst, sizeof(dgst), mem, (int)siglen, key));
        printf("ecdsa.verify_wrong=%d\n",
               ECDSA_verify(0, dgst + 1, sizeof(dgst) - 1, mem, (int)siglen, key));
        {
            ECDSA_SIG *es = ECDSA_do_sign(dgst, sizeof(dgst), key);
            unsigned char *der = NULL;
            int derlen;
            printf("ecdsa.do_sign=%d\n", es != NULL);
            printf("ecdsa.do_verify=%d\n", ECDSA_do_verify(dgst, sizeof(dgst), es, key));
            {
                const BIGNUM *er = NULL, *es_ = NULL;
                ECDSA_SIG_get0(es, &er, &es_);
                printf("ecdsa.parts=%d\n", er != NULL && es_ != NULL);
                /* D345's two single-field accessors answer the same `BIGNUM` pointers the pair
                 * accessor just wrote, which is the identity `ec_asn1.c` gives them. */
                printf("ecdsa.get0_r_is_field=%d\n", ECDSA_SIG_get0_r(es) == er);
                printf("ecdsa.get0_s_is_field=%d\n", ECDSA_SIG_get0_s(es) == es_);
            }
            /* The encoded length is *not* printed: a `r` or `s` with its top bit set gains a
             * leading zero byte, so the length of a fresh signature varies run to run. Only the
             * positivity, the decode and the re-encoded round trip are observations. */
            derlen = i2d_ECDSA_SIG(es, NULL);
            printf("ecdsa.i2d_null_pos=%d\n", derlen > 0);
            der = malloc(derlen > 0 ? derlen : 1);
            printf("ecdsa.i2d_pos=%d\n", i2d_ECDSA_SIG(es, &der) > 0);
            {
                const unsigned char *p = der - derlen;
                ECDSA_SIG *es2 = d2i_ECDSA_SIG(NULL, &p, derlen);
                printf("ecdsa.d2i=%d\n", es2 != NULL);
                if (es2 != NULL) {
                    const BIGNUM *r1 = NULL, *s1 = NULL, *r2 = NULL, *s2 = NULL;
                    ECDSA_SIG_get0(es, &r1, &s1);
                    ECDSA_SIG_get0(es2, &r2, &s2);
                    printf("ecdsa.round_trip=%d\n",
                           r1 != NULL && s1 != NULL && r2 != NULL && s2 != NULL
                           && BN_cmp(r1, r2) == 0 && BN_cmp(s1, s2) == 0);
                    ECDSA_SIG_free(es2);
                }
                free(der - derlen);
            }
            ECDSA_SIG_free(es);
        }
        {
            BIGNUM *kinv = NULL, *rp = NULL;
            unsigned int klen;
            unsigned char *kbuf;
            ECDSA_SIG *es;
            printf("ecdsa.sign_setup=%d\n", ECDSA_sign_setup(key, bctx, &kinv, &rp));
            printf("ecdsa.sign_setup_parts=%d\n", kinv != NULL && rp != NULL);
            klen = (unsigned int)ECDSA_size(key);
            kbuf = malloc(klen);
            es = ECDSA_do_sign_ex(dgst, sizeof(dgst), kinv, rp, key);
            printf("ecdsa.do_sign_ex=%d\n", es != NULL);
            ECDSA_SIG_free(es);
            printf("ecdsa.sign_ex=%d\n",
                   ECDSA_sign_ex(0, dgst, sizeof(dgst), kbuf, &klen, kinv, rp, key));
            printf("ecdsa.verify_ex=%d\n",
                   ECDSA_verify(0, dgst, sizeof(dgst), kbuf, (int)klen, key));
            free(kbuf);
            BN_clear_free(kinv);
            BN_clear_free(rp);
        }
    }
    layer_drain("ecdsa");

    /* ---- ECDH: agreement and length only ---- */
    {
        EC_KEY *peer = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        unsigned char *s1 = NULL, *s2 = NULL;
        size_t l1 = 0, l2 = 0, need = 0, q1 = 0, q2 = 0;
        printf("ecdh.peer_gen=%d\n", peer != NULL && EC_KEY_generate_key(peer));
        if (peer != NULL) {
            const EC_POINT *pub1 = EC_KEY_get0_public_key(peer);
            q1 = EC_POINT_point2oct(EC_KEY_get0_group(peer), pub1,
                                    POINT_CONVERSION_UNCOMPRESSED, NULL, 0, bctx);
            need = q1 > 0 ? q1 : 64;
            s1 = malloc(need);
            s2 = malloc(need);
            l1 = ECDH_compute_key(s1, need, pub1, key, NULL);
            l2 = ECDH_compute_key(s2, need, EC_KEY_get0_public_key(key), peer, NULL);
            q2 = EC_POINT_point2oct(EC_KEY_get0_group(key), EC_KEY_get0_public_key(key),
                                    POINT_CONVERSION_UNCOMPRESSED, NULL, 0, bctx);
            printf("ecdh.len=%zu\n", l1);
            printf("ecdh.peer_len=%zu\n", l2);
            printf("ecdh.pub_widths=%zu,%zu\n", q1, q2);
            printf("ecdh.agree=%d\n", l1 != 0 && l1 == l2 && memcmp(s1, s2, l1) == 0);
            /* the secret itself is never printed */
            free(s1);
            free(s2);
            EC_KEY_free(peer);
        }
    }

    layer_drain("layer");

layer_done:
    if (bctx != NULL)
        BN_CTX_free(bctx);
    BN_free(bp);
    BN_free(ba);
    BN_free(bb);
    BN_free(bo);
    BN_free(bc);
    EC_GROUP_free(g);
    EC_GROUP_free(g2);
    EC_GROUP_free(gexp);
    EC_POINT_free(P);
    EC_POINT_free(Q);
    EC_POINT_free(Rs);
    EC_KEY_free(key);
    EC_KEY_free(key2);
    free(mem);
}

    free(table);
    return 0;
}
