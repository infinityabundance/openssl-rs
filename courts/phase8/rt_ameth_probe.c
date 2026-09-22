/*
 * RT-AMETH -- Phase 8.8's `EVP_PKEY_ASN1_METHOD` registry court.
 *
 * `docs/DECISIONS.md` D353 lands the eleven `standard_methods[]` rows the crate carries
 * (`src/evp/pkey_asn1.rs`) over the four `*_ameth.c` object units, and this probe is what observes
 * them. It is compiled twice -- once against the admitted authority, once against the candidate
 * distribution shell -- and the two `key=value` transcripts are diffed line by line. Every
 * observation is a **return code, a `pkey_id`, a flag word, a string the library owns, or the
 * drained `ERR` coordinate**; no method address, no key byte and no random-derived value is ever
 * printed. `EVP_PKEY_get0_asn1`'s pointer is reduced to `notnull` and its `pkey_id`, and the one
 * `pkey` pointer comparison (`get0.*.same_object`) is a boolean.
 *
 * ## What this court deliberately does not observe
 *
 * **The count, and the four rows it is short of.** `crypto/asn1/standard_methods.h` carries fifteen
 * rows under this profile's guards; the crate carries eleven. The four withheld rows are
 * `crypto/ec/ecx_meth.c`'s `ossl_ecx{25519,448}_asn1_meth` and `ossl_ed{25519,448}_asn1_meth`
 * (`EVP_PKEY_X25519` 1034, `_X448` 1035, `_ED25519` 1087, `_ED448` 1088), and their absence is the
 * narrowing D353 records: `EVP_PKEY_asn1_find`/`_find_str` answer NULL and `EVP_PKEY_type`
 * `NID_undef` for those four. An arm that compared `EVP_PKEY_asn1_get_count()` outright, or walked
 * the table by index and printed the `pkey_id` at each index, would therefore **have to differ**
 * between the two sides -- which a differential court cannot carry (`docs/SECURITY_DIVERGENCE_
 * POLICY.md` D-EC-2 states the rule: a residual is a failure, so an arm that must differ is a known
 * failure rather than an observation). So the table is observed through a **fixed list of the eleven
 * `pkey_id`s the crate carries**, resolved with `EVP_PKEY_asn1_find`, and `EVP_PKEY_asn1_get0` is
 * exercised by scanning the whole index space on each side and asking whether the object `_find`
 * answered is reachable there -- a boolean, which the two sides agree on because the eleven shared
 * rows are the same objects.
 *
 * **The eight `RSA_print`/`DSA_print`/`EC_KEY_print` family printers.** They call
 * `EVP_PKEY_print_private`/`_params`, which are `crypto/evp/p_lib.c`'s exports and **absent from this
 * crate's compiled surface** -- measured with `nm` on `target/release/libopenssl_rs.a`, not read from
 * a ledger. A probe cannot link, let alone call, a symbol that is not there, so the print arms the
 * integration plan's section 7 lists are withheld with the eight printers themselves.
 *
 * **`EVP_PKEY_meth_find`/`_get0`/`_get_count` are observed, not withheld.** The second
 * `standard_methods[]` — `crypto/evp/pmeth_lib.c`'s array of `pmeth_fn` accessors — landed with
 * `docs/DECISIONS.md` D355, and arm 8 exercises the three over the **six in-reach rows**
 * (`EVP_PKEY_RSA` 6, `_DH` 28, `_DSA` 116, `_EC` 408, `_RSA_PSS` 912, `_DHX` 920). The four
 * `crypto/ec/ecx_meth.c` rows are withheld under the same record as arm 7's,
 * `D-PKEY-AMETH-3`, so the arm observes no index and no count the two sides would answer
 * differently: `EVP_PKEY_meth_get0(6)` is never queried and `EVP_PKEY_meth_get_count()` is only
 * ever reduced to a boolean.
 *
 * **The `crypto/asn1/d2i_param.c`/`d2i_pu.c` readers are observed, not withheld.**
 * `d2i_KeyParams`/`d2i_KeyParams_bio`/`d2i_PublicKey` landed together (`docs/DECISIONS.md` D354),
 * and arm 7 exercises the two refusals that need no encoding at all: a type whose method carries no
 * `param_decode` (`EVP_PKEY_RSA` and the `EVP_PKEY_SM2` alias) and a type outside `d2i_PublicKey`'s
 * three-arm switch (`EVP_PKEY_DH`).
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE

/* The `EVP_PKEY_asn1_*` family is `OSSL_DEPRECATEDIN_3_6`. The deprecation is the authority's own
 * statement about application code, not about a court that must exercise the entry points the
 * registry declares; suppressing it changes no symbol this probe links. */
#define OPENSSL_SUPPRESS_DEPRECATED

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/dh.h>
#include <openssl/dsa.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/rsa.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* The eleven `pkey_id`s the crate's `standard_methods[]` carries, in ascending order -- the
 * authority's fifteen minus the four `crypto/ec/ecx_meth.c` rows D353 withholds. Symbolic, so the
 * probe reads them from the same `obj_mac.h` on both sides. */
static const int IDS[] = {
    NID_rsaEncryption,           /* EVP_PKEY_RSA            6    */
    NID_rsa,                     /* EVP_PKEY_RSA2          19    (alias) */
    NID_dhKeyAgreement,          /* EVP_PKEY_DH            28    */
    NID_dsa_2,                   /* EVP_PKEY_DSA1          67    (alias) */
    NID_dsaWithSHA1_2,           /* EVP_PKEY_DSA4          70    (alias) */
    NID_dsaWithSHA1,             /* EVP_PKEY_DSA3         113    (alias) */
    NID_dsa,                     /* EVP_PKEY_DSA          116    */
    NID_X9_62_id_ecPublicKey,    /* EVP_PKEY_EC           408    */
    NID_rsassaPss,               /* EVP_PKEY_RSA_PSS      912    */
    NID_dhpublicnumber,          /* EVP_PKEY_DHX          920    */
    NID_sm2                      /* EVP_PKEY_SM2         1172    (alias) */
};
#define NIDS ((int)(sizeof(IDS) / sizeof(IDS[0])))

/* ------------------------------------------------------------------ the error queue */

/* Drain the queue, printing each record's packed code and its coordinate. The coordinate is
 * `ERR_get_error_all`'s file/line/func, which `gen_err_raise_sites.py` derives and which a court
 * that compared only the return value could not see. Nothing here is a secret. */
static void drain(const char *arm)
{
    int n = 0;

    for (;;) {
        const char *file = NULL;
        const char *func = NULL;
        int line = 0;
        unsigned long e = ERR_get_error_all(&file, &line, &func, NULL, NULL);

        if (e == 0)
            break;
        printf("ameth.%s.err.%d=%lu:%s:%d:%s\n", arm, n, e,
            file != NULL ? file : "(null)", line,
            func != NULL ? func : "(null)");
        n++;
    }
    printf("ameth.%s.err.count=%d\n", arm, n);
}

/* ------------------------------------------------------------------ the five fields */

/* `EVP_PKEY_asn1_get0_info`'s whole output for one method, keyed by a caller-supplied `tag`. The
 * `info` and `pem_str` strings are the authority's own, and a NULL one prints as `(null)` rather
 * than being dropped -- the argument is part of the contract. */
static void info_of(const char *tag, const EVP_PKEY_ASN1_METHOD *m)
{
    int pid = -100000, bid = -100000, flags = -100000;
    const char *info = NULL;
    const char *pem = NULL;
    int r = EVP_PKEY_asn1_get0_info(&pid, &bid, &flags, &info, &pem, m);

    printf("ameth.%s.info_ret=%d\n", tag, r);
    printf("ameth.%s.pkey_id=%d\n", tag, pid);
    printf("ameth.%s.pkey_base_id=%d\n", tag, bid);
    printf("ameth.%s.pkey_flags=%d\n", tag, flags);
    printf("ameth.%s.info=%s\n", tag, info != NULL ? info : "(null)");
    printf("ameth.%s.pem=%s\n", tag, pem != NULL ? pem : "(null)");
}

/* ------------------------------------------------------------------ arm 1: the table */

/* `EVP_PKEY_asn1_get_count`/`_get0` are observed **through the eleven ids**, never by printing the
 * count or the row at an index: those must differ (see the header). For each id the arm prints the
 * object `find` answers and whether that same object is reachable by walking `get0` over the whole
 * index space -- `same_object` is a pointer equality reduced to a boolean, and `scan_finds` asks
 * whether any `get0` row carries the id at all. */
static void table_arms(void)
{
    char tag[48];
    int i, j;

    printf("ameth.count.positive=%d\n", EVP_PKEY_asn1_get_count() > 0);
    printf("ameth.get0.negative_is_null=%d\n", EVP_PKEY_asn1_get0(-1) == NULL);
    printf("ameth.find.none_is_null=%d\n", EVP_PKEY_asn1_find(NULL, 0) == NULL);

    for (i = 0; i < NIDS; i++) {
        int id = IDS[i];
        const EVP_PKEY_ASN1_METHOD *m = EVP_PKEY_asn1_find(NULL, id);
        int scan_finds = 0;
        int same_object = 0;

        printf("ameth.find.%d.notnull=%d\n", id, m != NULL);
        if (m != NULL) {
            snprintf(tag, sizeof(tag), "find.%d", id);
            info_of(tag, m);
        }

        for (j = 0; j < EVP_PKEY_asn1_get_count(); j++) {
            const EVP_PKEY_ASN1_METHOD *g = EVP_PKEY_asn1_get0(j);
            int pid = -100000;

            if (g == NULL)
                continue;
            if (m != NULL && g == m)
                same_object = 1;
            if (EVP_PKEY_asn1_get0_info(&pid, NULL, NULL, NULL, NULL, g) != 1)
                continue;
            if (pid == id)
                scan_finds = 1;
        }
        printf("ameth.get0.scan_finds.%d=%d\n", id, scan_finds);
        printf("ameth.get0.same_object.%d=%d\n", id, same_object);
    }
}

/* ------------------------------------------------------------------ arm 2: find_str */

/* The case-insensitive PEM-name walk and its refusals. The three refusals are the ones the plan
 * names: a wrong length, a string that is a prefix of a PEM name, and a name no row carries. No
 * query names a withheld ECX PEM spelling, because the authority would find one and the crate would
 * not -- the D353 narrowing, measured elsewhere rather than carried as an arm. */
static void find_str_arms(void)
{
    static const struct {
        const char *label;
        const char *s;
        int len;
    } q[] = {
        { "rsa_measured", "RSA", -1 },
        { "rsa_explicit", "RSA", 3 },
        { "rsa_lowercase", "rsa", 3 },
        { "rsa_prefix", "RSA", 2 },
        { "rsa_too_long", "RSAX", 4 },
        { "dsa", "DSA", -1 },
        { "dh", "DH", -1 },
        { "dhx", "DHX", -1 },
        { "ec", "EC", -1 },
        { "rsa_pss", "RSA-PSS", -1 },
        { "absent", "NOSUCH", -1 },
        { "empty", "", -1 }
    };
    char tag[48];
    int i;

    for (i = 0; i < (int)(sizeof(q) / sizeof(q[0])); i++) {
        const EVP_PKEY_ASN1_METHOD *m = EVP_PKEY_asn1_find_str(NULL, q[i].s, q[i].len);

        printf("ameth.find_str.%s.notnull=%d\n", q[i].label, m != NULL);
        if (m != NULL) {
            snprintf(tag, sizeof(tag), "find_str.%s", q[i].label);
            info_of(tag, m);
        }
    }
    /* A NULL `ameth` is refused before any field is read. */
    printf("ameth.find_str.null_ameth=%d\n",
        EVP_PKEY_asn1_get0_info(NULL, NULL, NULL, NULL, NULL, NULL));
}

/* ------------------------------------------------------------------ arm 3: EVP_PKEY_type */

/* `EVP_PKEY_type` is `EVP_PKEY_asn1_find`'s answer, unaliased: it follows `pkey_base_id` while the
 * row carries `ASN1_PKEY_ALIAS`, so an alias's own id is never returned. The four withheld ids are
 * not queried (they would differ); the two synthetic values are. */
static void type_arms(void)
{
    int i;

    for (i = 0; i < NIDS; i++)
        printf("ameth.type.%d=%d\n", IDS[i], EVP_PKEY_type(IDS[i]));

    printf("ameth.type.undef=%d\n", EVP_PKEY_type(NID_undef));
    printf("ameth.type.none=%d\n", EVP_PKEY_type(EVP_PKEY_NONE));
    printf("ameth.type.keymgmt=%d\n", EVP_PKEY_type(EVP_PKEY_KEYMGMT));
}

/* ------------------------------------------------------------------ arm 4: EVP_PKEY_assign */

/* `EVP_PKEY_assign` sets `pkey->ameth` from the table and stores the key, and `EVP_PKEY_get0_asn1`
 * is the field it set. The EC arm is the one whose **type is rewritten from the key's own curve**:
 * an SM2-curve key assigned as `EVP_PKEY_EC` becomes `EVP_PKEY_SM2`, which is what makes the
 * `EVP_PKEY_type` call inside the assignment observable. */
static void assign_arms(void)
{
    /* RSA: a bare object, assigned, then read back through the accessor. */
    {
        EVP_PKEY *pk = EVP_PKEY_new();
        RSA *rsa = RSA_new();
        const EVP_PKEY_ASN1_METHOD *m;

        printf("ameth.assign.rsa.built=%d\n", pk != NULL && rsa != NULL);
        if (pk != NULL && rsa != NULL) {
            printf("ameth.assign.rsa.ret=%d\n", EVP_PKEY_assign(pk, EVP_PKEY_RSA, rsa));
            printf("ameth.assign.rsa.id=%d\n", EVP_PKEY_get_id(pk));
            printf("ameth.assign.rsa.base_id=%d\n", EVP_PKEY_get_base_id(pk));
            m = EVP_PKEY_get0_asn1(pk);
            printf("ameth.assign.rsa.ameth_notnull=%d\n", m != NULL);
            if (m != NULL)
                info_of("assign.rsa", m);
        }
        EVP_PKEY_free(pk); /* owns the RSA on success */
        if (pk == NULL || rsa == NULL)
            RSA_free(rsa);
    }

    /* DH: a real FFDHE-2048 group, so the object has something to point at. */
    {
        EVP_PKEY *pk = EVP_PKEY_new();
        DH *dh = DH_new_by_nid(NID_ffdhe2048);
        const EVP_PKEY_ASN1_METHOD *m;

        printf("ameth.assign.dh.built=%d\n", pk != NULL && dh != NULL);
        if (pk != NULL && dh != NULL) {
            printf("ameth.assign.dh.ret=%d\n", EVP_PKEY_assign(pk, EVP_PKEY_DH, dh));
            printf("ameth.assign.dh.id=%d\n", EVP_PKEY_get_id(pk));
            printf("ameth.assign.dh.base_id=%d\n", EVP_PKEY_get_base_id(pk));
            m = EVP_PKEY_get0_asn1(pk);
            printf("ameth.assign.dh.ameth_notnull=%d\n", m != NULL);
            if (m != NULL)
                info_of("assign.dh", m);
            printf("ameth.assign.dh.get0_dh_is_key=%d\n",
                (const void *)EVP_PKEY_get0_DH(pk) == (const void *)dh);
        }
        EVP_PKEY_free(pk);
        if (pk == NULL || dh == NULL)
            DH_free(dh);
    }

    /* EC on the SM2 curve, assigned as `EVP_PKEY_EC`: the type must come back as SM2. */
    {
        EVP_PKEY *pk = EVP_PKEY_new();
        EC_KEY *ec = EC_KEY_new_by_curve_name(NID_sm2);
        const EVP_PKEY_ASN1_METHOD *m;

        printf("ameth.assign.sm2.built=%d\n", pk != NULL && ec != NULL);
        if (pk != NULL && ec != NULL) {
            printf("ameth.assign.sm2.ret=%d\n", EVP_PKEY_assign(pk, EVP_PKEY_EC, ec));
            printf("ameth.assign.sm2.id=%d\n", EVP_PKEY_get_id(pk));
            printf("ameth.assign.sm2.base_id=%d\n", EVP_PKEY_get_base_id(pk));
            m = EVP_PKEY_get0_asn1(pk);
            printf("ameth.assign.sm2.ameth_notnull=%d\n", m != NULL);
            if (m != NULL)
                info_of("assign.sm2", m);
        }
        EVP_PKEY_free(pk);
        if (pk == NULL || ec == NULL)
            EC_KEY_free(ec);
    }

    /* EC on a prime curve, assigned as `EVP_PKEY_EC`: the type stays EC. */
    {
        EVP_PKEY *pk = EVP_PKEY_new();
        EC_KEY *ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);

        printf("ameth.assign.ec.built=%d\n", pk != NULL && ec != NULL);
        if (pk != NULL && ec != NULL) {
            printf("ameth.assign.ec.ret=%d\n", EVP_PKEY_assign(pk, EVP_PKEY_EC, ec));
            printf("ameth.assign.ec.id=%d\n", EVP_PKEY_get_id(pk));
            printf("ameth.assign.ec.base_id=%d\n", EVP_PKEY_get_base_id(pk));
        }
        EVP_PKEY_free(pk);
        if (pk == NULL || ec == NULL)
            EC_KEY_free(ec);
    }
}

/* ------------------------------------------------------------------ arm 5: the parameter callbacks */

/* A buildable key's `param_missing`/`param_cmp`/`param_copy` columns, through the three
 * `EVP_PKEY_*` entry points that dispatch to them, plus the id/base-id pair they sit beside. Two
 * FFDHE-2048 objects have equal parameters; a blank key has no method, and an RSA with no `n` is
 * missing them. **No modulus, exponent or group constant is printed** -- every arm is a verdict. */
static void params_arms(void)
{
    EVP_PKEY *a = EVP_PKEY_new();
    EVP_PKEY *b = EVP_PKEY_new();
    DH *a_dh = DH_new_by_nid(NID_ffdhe2048);
    DH *b_dh = DH_new_by_nid(NID_ffdhe2048);

    printf("ameth.params.built=%d\n", a != NULL && b != NULL && a_dh != NULL && b_dh != NULL);
    if (a != NULL && b != NULL && a_dh != NULL && b_dh != NULL) {
        /* `EVP_PKEY_set1_DH` takes its own reference; ours is released below. */
        printf("ameth.params.set1_a=%d\n", EVP_PKEY_set1_DH(a, a_dh));
        printf("ameth.params.set1_b=%d\n", EVP_PKEY_set1_DH(b, b_dh));
        printf("ameth.params.id_a=%d\n", EVP_PKEY_get_id(a));
        printf("ameth.params.base_id_a=%d\n", EVP_PKEY_get_base_id(a));
        printf("ameth.params.missing_a=%d\n", EVP_PKEY_missing_parameters(a));
        printf("ameth.params.cmp_ab=%d\n", EVP_PKEY_cmp_parameters(a, b));
        printf("ameth.params.copy_ba=%d\n", EVP_PKEY_copy_parameters(b, a));
        printf("ameth.params.cmp_after_copy=%d\n", EVP_PKEY_cmp_parameters(a, b));
        printf("ameth.params.get0_dh_notnull=%d\n", EVP_PKEY_get0_DH(a) != NULL);
        printf("ameth.params.get1_dh_notnull=%d\n", EVP_PKEY_get1_DH(a) != NULL);
        printf("ameth.params.get1_dh_releases=%d\n", EVP_PKEY_get1_DH(a) != NULL);
    }
    EVP_PKEY_free(a);
    EVP_PKEY_free(b);
    DH_free(a_dh);
    DH_free(b_dh);

    /* A blank key has no method, so the authority's guard answers 0 rather than dispatching. */
    {
        EVP_PKEY *blank = EVP_PKEY_new();

        printf("ameth.params.blank.missing=%d\n", EVP_PKEY_missing_parameters(blank));
        EVP_PKEY_free(blank);
    }

    /* An RSA object with neither `n` nor `e` is missing its parameters on both sides. */
    {
        EVP_PKEY *pk = EVP_PKEY_new();
        RSA *rsa = RSA_new();

        printf("ameth.params.empty_rsa.built=%d\n", pk != NULL && rsa != NULL);
        if (pk != NULL && rsa != NULL) {
            printf("ameth.params.empty_rsa.assign=%d\n", EVP_PKEY_assign(pk, EVP_PKEY_RSA, rsa));
            printf("ameth.params.empty_rsa.missing=%d\n", EVP_PKEY_missing_parameters(pk));
        }
        EVP_PKEY_free(pk);
        if (pk == NULL || rsa == NULL)
            RSA_free(rsa);
    }
}

/* ------------------------------------------------------------------ arm 6: the refusals */

/* Each refusal through its return value **and** its drained `ERR` coordinate. The four accessors
 * raise `EVP_R_EXPECTING_AN_{RSA,DSA,DH,EC}_KEY` at their own `p_legacy.c`/`p_lib.c` lines, and the
 * two `find` refusals raise nothing -- which the `err.count=0` lines record rather than assume. */
static void refusal_arms(void)
{
    EVP_PKEY *pk = EVP_PKEY_new();
    DH *dh = DH_new_by_nid(NID_ffdhe2048);

    printf("ameth.refuse.dh.built=%d\n", pk != NULL && dh != NULL);
    if (pk != NULL && dh != NULL) {
        printf("ameth.refuse.dh.assign=%d\n", EVP_PKEY_assign(pk, EVP_PKEY_DH, dh));

        ERR_clear_error();
        printf("ameth.refuse.get0_rsa_is_null=%d\n", EVP_PKEY_get0_RSA(pk) == NULL);
        drain("get0_rsa_on_dh");

        ERR_clear_error();
        printf("ameth.refuse.get1_rsa_is_null=%d\n", EVP_PKEY_get1_RSA(pk) == NULL);
        drain("get1_rsa_on_dh");

        ERR_clear_error();
        printf("ameth.refuse.get0_dsa_is_null=%d\n", EVP_PKEY_get0_DSA(pk) == NULL);
        drain("get0_dsa_on_dh");

        ERR_clear_error();
        printf("ameth.refuse.get0_ec_is_null=%d\n", EVP_PKEY_get0_EC_KEY(pk) == NULL);
        drain("get0_ec_on_dh");
    }
    EVP_PKEY_free(pk);
    if (pk == NULL || dh == NULL)
        DH_free(dh);

    /* A type no row names answers NULL and raises nothing. */
    ERR_clear_error();
    printf("ameth.refuse.find_unknown_is_null=%d\n", EVP_PKEY_asn1_find(NULL, 999999) == NULL);
    drain("find_unknown");

    ERR_clear_error();
    printf("ameth.refuse.find_str_unknown_is_null=%d\n",
        EVP_PKEY_asn1_find_str(NULL, "NOSUCH", -1) == NULL);
    drain("find_str_unknown");

    /* `EVP_PKEY_get0_asn1` on a blank key is `pkey->ameth`, which the assignment never set. */
    {
        EVP_PKEY *blank = EVP_PKEY_new();

        printf("ameth.refuse.blank.ameth_is_null=%d\n", EVP_PKEY_get0_asn1(blank) == NULL);
        EVP_PKEY_free(blank);
    }
}

/* ------------------------------------------------------------------ arm 7: the d2i readers */

/* `d2i_KeyParams`'s third refusal is the one a probe can reach without an encoding: a type whose
 * method carries no `param_decode` -- `EVP_PKEY_RSA` (6) and the `EVP_PKEY_SM2` alias (1172) both do
 * not -- is refused with `ASN1_R_UNSUPPORTED_TYPE` at `d2i_param.c:33` before the callback is
 * reached. `d2i_PublicKey` refuses a type outside its three-arm `switch` with
 * `ASN1_R_UNKNOWN_PUBLIC_KEY_TYPE` at `d2i_pu.c:86`. `d2i_KeyParams_bio` is the same refusal reached
 * through a `BUF_MEM` read of a complete DER `NULL`. Every observation is a return code, a slot
 * test, or the drained coordinate. */
static void d2i_arms(void)
{
    /* A complete DER `NULL`, which `asn1_d2i_read_bio` reads whole before `d2i_KeyParams` sees it. */
    static const unsigned char der_null[] = { 0x05, 0x00 };

    /* RSA has no `param_decode`, so :33 is the refusal and nothing else is raised. */
    {
        const unsigned char *p = der_null;
        EVP_PKEY *pk = NULL;

        ERR_clear_error();
        printf("ameth.d2i_keyparams.rsa.notnull=%d\n",
            d2i_KeyParams(EVP_PKEY_RSA, &pk, &p, (long)sizeof(der_null)) != NULL);
        printf("ameth.d2i_keyparams.rsa.slot_null=%d\n", pk == NULL);
        drain("d2i_keyparams_rsa");
    }

    /* The SM2 alias is the same shape, and it is a row the crate carries. */
    {
        const unsigned char *p = der_null;
        EVP_PKEY *pk = NULL;

        ERR_clear_error();
        printf("ameth.d2i_keyparams.sm2.notnull=%d\n",
            d2i_KeyParams(EVP_PKEY_SM2, &pk, &p, (long)sizeof(der_null)) != NULL);
        printf("ameth.d2i_keyparams.sm2.slot_null=%d\n", pk == NULL);
        drain("d2i_keyparams_sm2");
    }

    /* `d2i_PublicKey`: DH is outside the RSA/DSA/EC switch, so the default arm refuses. */
    {
        const unsigned char *p = der_null;
        EVP_PKEY *pk = NULL;

        ERR_clear_error();
        printf("ameth.d2i_publickey.dh.notnull=%d\n",
            d2i_PublicKey(EVP_PKEY_DH, &pk, &p, (long)sizeof(der_null)) != NULL);
        printf("ameth.d2i_publickey.dh.slot_null=%d\n", pk == NULL);
        drain("d2i_publickey_dh");
    }

    /* `d2i_KeyParams_bio`: the same RSA refusal through the `BUF_MEM` reader, which releases the
     * buffer on both paths. */
    {
        BIO *b = BIO_new_mem_buf(der_null, (int)sizeof(der_null));
        EVP_PKEY *pk = NULL;

        ERR_clear_error();
        printf("ameth.d2i_keyparams_bio.built=%d\n", b != NULL);
        if (b != NULL) {
            printf("ameth.d2i_keyparams_bio.rsa.notnull=%d\n",
                d2i_KeyParams_bio(EVP_PKEY_RSA, &pk, b) != NULL);
            printf("ameth.d2i_keyparams_bio.rsa.slot_null=%d\n", pk == NULL);
            drain("d2i_keyparams_bio_rsa");
        }
        BIO_free(b);
    }
}

/* ---------------------------------------------------- arm 8: the EVP_PKEY_METHOD table */

/* `crypto/evp/pmeth_lib.c`'s **second** `standard_methods[]` — not the `EVP_PKEY_ASN1_METHOD`
 * table arm 1 walks, but the array of `pmeth_fn` accessors `EVP_PKEY_meth_find` binary-searches.
 * Six of its ten rows are in reach (`EVP_PKEY_RSA` 6, `_DH` 28, `_DSA` 116, `_EC` 408, `_RSA_PSS`
 * 912, `_DHX` 920) and the four `crypto/ec/ecx_meth.c` rows are withheld with `D-PKEY-AMETH-3`'s
 * observable, so the arms below observe the six shared rows and **never** an index or a count the
 * two sides would answer differently: no `EVP_PKEY_meth_get0(6)` (the authority answers the X25519
 * method there and the crate NULL) and no `EVP_PKEY_meth_get_count()` *value* (10 against 6), only
 * a boolean. */
static void pmeth_arms(void)
{
    static const int MIDS[] = {
        NID_rsaEncryption,           /* EVP_PKEY_RSA            6 */
        NID_dhKeyAgreement,          /* EVP_PKEY_DH            28 */
        NID_dsa,                     /* EVP_PKEY_DSA          116 */
        NID_X9_62_id_ecPublicKey,    /* EVP_PKEY_EC           408 */
        NID_rsassaPss,               /* EVP_PKEY_RSA_PSS      912 */
        NID_dhpublicnumber           /* EVP_PKEY_DHX          920 */
    };
    int i, j;

    printf("ameth.pmeth.count_at_least_six=%d\n", EVP_PKEY_meth_get_count() >= 6);
    printf("ameth.pmeth.find.none_is_null=%d\n", EVP_PKEY_meth_find(999999) == NULL);

    for (i = 0; i < (int)(sizeof(MIDS) / sizeof(MIDS[0])); i++) {
        const EVP_PKEY_METHOD *m = EVP_PKEY_meth_find(MIDS[i]);
        int pid = -100000, flags = -100000;

        printf("ameth.pmeth.find.%d.notnull=%d\n", MIDS[i], m != NULL);
        if (m == NULL)
            continue;
        EVP_PKEY_meth_get0_info(&pid, &flags, m);
        printf("ameth.pmeth.find.%d.pkey_id=%d\n", MIDS[i], pid);
        printf("ameth.pmeth.find.%d.flags=%d\n", MIDS[i], flags);

        /* The row is the same object `get0` answers at its index, and the six shared rows are in
         * the same ascending `pkey_id` order on both sides, so `same` is a boolean they agree on. */
        for (j = 0; j < 6; j++) {
            const EVP_PKEY_METHOD *g = EVP_PKEY_meth_get0((size_t)j);

            printf("ameth.pmeth.get0.%d.%d.notnull=%d\n", i, j, g != NULL);
            if (g == NULL)
                continue;
            pid = -100000;
            EVP_PKEY_meth_get0_info(&pid, NULL, g);
            printf("ameth.pmeth.get0.%d.%d.pkey_id=%d\n", i, j, pid);
            printf("ameth.pmeth.get0.%d.%d.same=%d\n", i, j, g == m);
        }
    }

    /* Out-of-range indices. Only one beyond **both** index spaces is observed, because the
     * authority's is ten long and the crate's six. */
    printf("ameth.pmeth.get0.far_is_null=%d\n",
        EVP_PKEY_meth_get0((size_t)-1) == NULL && EVP_PKEY_meth_get0(1000) == NULL);
}

/* ------------------------------------------------------------------ the accessor family */

/* `court_coverage.py` requires every implemented export of a begun stratum to be **called** by
 * some staged probe, so this arm exercises the twelve legacy accessors' remaining spellings and the
 * four other exports directly. Each key is built from a bare object (`RSA_new`, `DSA_new`,
 * `EC_KEY_new_by_curve_name`) or a named FFDHE group, and every observation is a return code, an id,
 * a pointer **equality reduced to a boolean**, or a drained `ERR` coordinate -- never key material. */
static void coverage_arms(void)
{
    EVP_PKEY *dh_pk = EVP_PKEY_new();
    DH *dh = DH_new_by_nid(NID_ffdhe2048);

    printf("ameth.cov.dh.built=%d\n", dh_pk != NULL && dh != NULL);
    if (dh_pk != NULL && dh != NULL)
        EVP_PKEY_assign(dh_pk, EVP_PKEY_DH, dh);

    /* RSA: `set1` takes its own reference and assigns; ours is released after. */
    {
        EVP_PKEY *pk = EVP_PKEY_new();
        RSA *rsa = RSA_new();
        RSA *got;

        printf("ameth.cov.rsa.built=%d\n", pk != NULL && rsa != NULL);
        if (pk != NULL && rsa != NULL) {
            printf("ameth.cov.set1_rsa.ret=%d\n", EVP_PKEY_set1_RSA(pk, rsa));
            printf("ameth.cov.set1_rsa.id=%d\n", EVP_PKEY_get_id(pk));
            printf("ameth.cov.set1_rsa.same=%d\n",
                (const void *)EVP_PKEY_get0_RSA(pk) == (const void *)rsa);
            got = EVP_PKEY_get1_RSA(pk);
            printf("ameth.cov.get1_rsa.notnull=%d\n", got != NULL);
            RSA_free(got);
        }
        EVP_PKEY_free(pk);
        RSA_free(rsa);
    }

    /* DSA. */
    {
        EVP_PKEY *pk = EVP_PKEY_new();
        DSA *dsa = DSA_new();
        DSA *got;

        printf("ameth.cov.dsa.built=%d\n", pk != NULL && dsa != NULL);
        if (pk != NULL && dsa != NULL) {
            printf("ameth.cov.set1_dsa.ret=%d\n", EVP_PKEY_set1_DSA(pk, dsa));
            printf("ameth.cov.set1_dsa.id=%d\n", EVP_PKEY_get_id(pk));
            printf("ameth.cov.set1_dsa.same=%d\n",
                (const void *)EVP_PKEY_get0_DSA(pk) == (const void *)dsa);
            got = EVP_PKEY_get1_DSA(pk);
            printf("ameth.cov.get1_dsa.notnull=%d\n", got != NULL);
            DSA_free(got);
        }
        EVP_PKEY_free(pk);
        DSA_free(dsa);
    }

    /* EC_KEY on `prime256v1`: the assignment keeps the type `EVP_PKEY_EC`, and the two EC readers
     * below take their legacy arm because the key is legacy. */
    {
        EVP_PKEY *pk = EVP_PKEY_new();
        EC_KEY *ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        EC_KEY *got;

        printf("ameth.cov.ec.built=%d\n", pk != NULL && ec != NULL);
        if (pk != NULL && ec != NULL) {
            printf("ameth.cov.set1_ec.ret=%d\n", EVP_PKEY_set1_EC_KEY(pk, ec));
            printf("ameth.cov.set1_ec.id=%d\n", EVP_PKEY_get_id(pk));
            printf("ameth.cov.set1_ec.base_id=%d\n", EVP_PKEY_get_base_id(pk));
            printf("ameth.cov.set1_ec.same=%d\n",
                (const void *)EVP_PKEY_get0_EC_KEY(pk) == (const void *)ec);
            got = EVP_PKEY_get1_EC_KEY(pk);
            printf("ameth.cov.get1_ec.notnull=%d\n", got != NULL);
            EC_KEY_free(got);

            printf("ameth.cov.conv_form=%d\n", EVP_PKEY_get_ec_point_conv_form(pk));
            printf("ameth.cov.field_type=%d\n", EVP_PKEY_get_field_type(pk));
        }
        EVP_PKEY_free(pk);
        EC_KEY_free(ec);
    }

    /* The same two readers on a DH key: the `EVP_PKEY_get0_EC_KEY` type test refuses with its own
     * coordinate and the reader answers 0 rather than reading a group that is not there. */
    if (dh_pk != NULL && dh != NULL) {
        ERR_clear_error();
        printf("ameth.cov.conv_form_dh=%d\n", EVP_PKEY_get_ec_point_conv_form(dh_pk));
        drain("conv_form_on_dh");

        ERR_clear_error();
        printf("ameth.cov.field_type_dh=%d\n", EVP_PKEY_get_field_type(dh_pk));
        drain("field_type_on_dh");
    }

    /* The three raw-key readers refuse every other type before touching `*len`. */
    if (dh_pk != NULL && dh != NULL) {
        size_t len = 12345;

        ERR_clear_error();
        printf("ameth.cov.hmac_is_null=%d\n", EVP_PKEY_get0_hmac(dh_pk, &len) == NULL);
        printf("ameth.cov.hmac.len_untouched=%d\n", len == 12345);
        drain("hmac_on_dh");

        ERR_clear_error();
        printf("ameth.cov.poly1305_is_null=%d\n", EVP_PKEY_get0_poly1305(dh_pk, &len) == NULL);
        printf("ameth.cov.poly1305.len_untouched=%d\n", len == 12345);
        drain("poly1305_on_dh");

        ERR_clear_error();
        printf("ameth.cov.siphash_is_null=%d\n", EVP_PKEY_get0_siphash(dh_pk, &len) == NULL);
        printf("ameth.cov.siphash.len_untouched=%d\n", len == 12345);
        drain("siphash_on_dh");
    }

    /* `EVP_PKEY_encrypt_old`/`_decrypt_old` refuse a non-RSA key with `EVP_R_PUBLIC_KEY_NOT_RSA`,
     * and their two `ret` initialisers differ: **0** for encrypt, **-1** for decrypt. */
    if (dh_pk != NULL && dh != NULL) {
        unsigned char ek[8] = { 0 };
        unsigned char key[8] = { 0 };

        ERR_clear_error();
        printf("ameth.cov.encrypt_old_dh=%d\n", EVP_PKEY_encrypt_old(ek, key, 1, dh_pk));
        drain("encrypt_old_on_dh");

        ERR_clear_error();
        printf("ameth.cov.decrypt_old_dh=%d\n", EVP_PKEY_decrypt_old(key, ek, 1, dh_pk));
        drain("decrypt_old_on_dh");
    }

    EVP_PKEY_free(dh_pk);
    if (dh_pk == NULL || dh == NULL)
        DH_free(dh);
}

int main(void)
{
    table_arms();
    find_str_arms();
    type_arms();
    assign_arms();
    params_arms();
    refusal_arms();
    d2i_arms();
    pmeth_arms();
    coverage_arms();
    return 0;
}
