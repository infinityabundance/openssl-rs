/*
 * rt_engine_ctrl_probe.c -- RT-ENGINE-CTRL: the Phase-13.3 ENGINE control and command surface,
 * driven.
 *
 * One C program, compiled once against the admitted authority and once against the candidate
 * distribution shell; the two transcripts are diffed line by line, keyed on `key=value`. Every
 * observation is a small integer or a fixed 0/1 -- never an address, never a clock, never the
 * error queue. Where a pointer's *identity* matters it is compared against a fixed engine this
 * probe owns and printed as 0/1, so no address reaches the transcript.
 *
 * ## What this probe drives
 *
 * The four exports 13.3 lands, over the 13.2 tables and the 10.9/13.1 registry they bind into:
 *
 *   * `ENGINE_set_default` (`eng_fat.c`): the `ENGINE_METHOD_*` bit dispatch, driven one bit at a
 *     time (`RSA`, `CIPHERS|DIGESTS`), with the composite `ENGINE_METHOD_ALL`, and with the
 *     empty mask `0`. The observable is the return value and, for each bit, whether the matching
 *     `ENGINE_get_default_*`/`ENGINE_get_*_engine` select answers the engine bound.
 *   * `ENGINE_set_default_string`: every spelling `int_def_cb` recognises -- `RSA`, `RSA,DSA`,
 *     `CIPHERS,DIGESTS`, `PKEY`, `PKEY_CRYPTO`, `PKEY_ASN1` and `ALL` -- plus the trimming of
 *     space around an element, and the four refusal arms: an unknown element, an unknown element
 *     *after* a known one (which must abort before any default is set), the NULL list and the
 *     empty list.
 *   * `ENGINE_register_complete`: the nine-arm registration, observed through each table's
 *     select.
 *   * `ENGINE_register_all_complete`: the registry walk, and its `ENGINE_FLAGS_NO_REGISTER_ALL`
 *     skip, observed through a flag-marked engine's own cipher NID.
 *
 * ## A synthetic ENGINE is the subject
 *
 * The engine is built with the landed `ENGINE_new`, named with `ENGINE_set_id`/`ENGINE_set_name`
 * and published with `ENGINE_add`; every method it carries is a fixed object this probe owns
 * (`dummy_cipher`, `dummy_rsa`, ...) and every callback is a fixed function. The observable is
 * therefore the identity the engine carries, not any behaviour of an algorithm. After each arm
 * the probe releases the functional reference a select hands back and unregisters the engine, so
 * the next arm observes a clean table.
 *
 * ## Arms that are deliberately absent
 *
 * `ENGINE_set_default`'s arm bodies dereference their engine in both the authority and the crate,
 * so a NULL-engine arm is **not driven** -- it would crash on both sides and compare nothing.
 * `ENGINE_register_all_complete`'s walk over the *built-in* registry is not observed either: the
 * authority registers `rdrand`/`dynamic` and this crate registers nothing (the divergence
 * `src/engine/eng_all.rs` records), but neither carries any of the method tables this probe
 * selects, so a select for the probe's own NIDs is unaffected by that difference. The error
 * queue is never read, so the `ENGINE_R_INVALID_STRING` and `CONF_R_LIST_CANNOT_BE_NULL` raises
 * on the refusal arms cannot leak into a comparison.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>

#include <openssl/engine.h>

/* Fixed method objects: only their addresses are ever observed. */
static int dummy_cipher, dummy_digest, dummy_rsa, dummy_dsa, dummy_dh, dummy_ec, dummy_rand;
static int dummy_pkmeth, dummy_asn1meth;

/* The one NID each callback implements. */
#define CIPHER_NID 919
#define DIGEST_NID 920
#define PKMETH_NID 4242
#define ASN1METH_NID 4243
/* The flag-marked engine's own cipher NID, deliberately distinct from `CIPHER_NID`. */
#define FLAG_NID 7001

static const int cipher_nids[] = { CIPHER_NID };
static int cipher_cb(ENGINE *e, const EVP_CIPHER **cipher, const int **nids, int nid)
{
    (void)e;
    if (cipher != NULL) {
        if (nid == CIPHER_NID) {
            *cipher = (const EVP_CIPHER *)&dummy_cipher;
            return 1;
        }
        return 0;
    }
    if (nids != NULL) {
        *nids = cipher_nids;
        return 1;
    }
    return 0;
}

static const int digest_nids[] = { DIGEST_NID };
static int digest_cb(ENGINE *e, const EVP_MD **digest, const int **nids, int nid)
{
    (void)e;
    if (digest != NULL) {
        if (nid == DIGEST_NID) {
            *digest = (const EVP_MD *)&dummy_digest;
            return 1;
        }
        return 0;
    }
    if (nids != NULL) {
        *nids = digest_nids;
        return 1;
    }
    return 0;
}

static const int pkmeth_nids[] = { PKMETH_NID };
static int pkmeth_cb(ENGINE *e, EVP_PKEY_METHOD **pmeth, const int **nids, int nid)
{
    (void)e;
    if (pmeth != NULL) {
        if (nid == PKMETH_NID) {
            *pmeth = (EVP_PKEY_METHOD *)&dummy_pkmeth;
            return 1;
        }
        return 0;
    }
    if (nids != NULL) {
        *nids = pkmeth_nids;
        return 1;
    }
    return 0;
}

static const int asn1meth_nids[] = { ASN1METH_NID };
static int asn1meth_cb(ENGINE *e, EVP_PKEY_ASN1_METHOD **ameth, const int **nids, int nid)
{
    (void)e;
    if (ameth != NULL) {
        if (nid == ASN1METH_NID) {
            *ameth = (EVP_PKEY_ASN1_METHOD *)&dummy_asn1meth;
            return 1;
        }
        return 0;
    }
    if (nids != NULL) {
        *nids = asn1meth_nids;
        return 1;
    }
    return 0;
}

/* The flag-marked engine's cipher callback: an engine the walk must skip carries a method. */
static const int flag_nids[] = { FLAG_NID };
static int flag_cipher_cb(ENGINE *e, const EVP_CIPHER **cipher, const int **nids, int nid)
{
    (void)e;
    if (cipher != NULL) {
        if (nid == FLAG_NID) {
            *cipher = (const EVP_CIPHER *)&dummy_cipher;
            return 1;
        }
        return 0;
    }
    if (nids != NULL) {
        *nids = flag_nids;
        return 1;
    }
    return 0;
}

static void out_int(const char *key, long v)
{
    printf("%s=%ld\n", key, v);
}

/* Select a table's default, print whether it is `e`, and release the functional reference. */
static void report_default(const char *key, ENGINE *got, ENGINE *e)
{
    out_int(key, got == e);
    if (got != NULL)
        ENGINE_finish(got);
}

int main(void)
{
    ENGINE *e, *n, *r;

    setvbuf(stdout, NULL, _IOLBF, 0);

    /* ----------------------------------------------------------------------------------------
     * A. A synthetic engine with every method bound, published.
     * -------------------------------------------------------------------------------------- */
    e = ENGINE_new();
    out_int("new.nonnull", e != NULL);
    out_int("set_id.ret", ENGINE_set_id(e, "rt13c") == 1);
    out_int("set_name.ret", ENGINE_set_name(e, "RT 13 ctrl") == 1);
    out_int("add.ret", ENGINE_add(e) == 1);
    ENGINE_free(e);

    ENGINE_set_ciphers(e, cipher_cb);
    ENGINE_set_digests(e, digest_cb);
    ENGINE_set_RSA(e, (const RSA_METHOD *)&dummy_rsa);
    ENGINE_set_DSA(e, (const DSA_METHOD *)&dummy_dsa);
    ENGINE_set_DH(e, (const DH_METHOD *)&dummy_dh);
    ENGINE_set_EC(e, (const EC_KEY_METHOD *)&dummy_ec);
    ENGINE_set_RAND(e, (const RAND_METHOD *)&dummy_rand);
    ENGINE_set_pkey_meths(e, pkmeth_cb);
    ENGINE_set_pkey_asn1_meths(e, asn1meth_cb);

    /* ----------------------------------------------------------------------------------------
     * B. `ENGINE_set_default`: the mask dispatch, one bit at a time and composites.
     * -------------------------------------------------------------------------------------- */
    out_int("set_default.zero_ret", ENGINE_set_default(e, 0) == 1);
    out_int("set_default.zero_rsa_null", ENGINE_get_default_RSA() == NULL);

    out_int("set_default.rsa_ret", ENGINE_set_default(e, ENGINE_METHOD_RSA) == 1);
    report_default("set_default.rsa_same", ENGINE_get_default_RSA(), e);
    ENGINE_unregister_RSA(e);
    out_int("set_default.rsa_cleared_null", ENGINE_get_default_RSA() == NULL);

    out_int("set_default.cipher_digest_ret",
            ENGINE_set_default(e, ENGINE_METHOD_CIPHERS | ENGINE_METHOD_DIGESTS) == 1);
    report_default("set_default.cipher_same", ENGINE_get_cipher_engine(CIPHER_NID), e);
    report_default("set_default.digest_same", ENGINE_get_digest_engine(DIGEST_NID), e);
    ENGINE_unregister_ciphers(e);
    ENGINE_unregister_digests(e);
    out_int("set_default.cipher_cleared_null", ENGINE_get_cipher_engine(CIPHER_NID) == NULL);
    out_int("set_default.digest_cleared_null", ENGINE_get_digest_engine(DIGEST_NID) == NULL);

    out_int("set_default.all_ret", ENGINE_set_default(e, ENGINE_METHOD_ALL) == 1);
    report_default("set_default.all_rsa", ENGINE_get_default_RSA(), e);
    report_default("set_default.all_dsa", ENGINE_get_default_DSA(), e);
    report_default("set_default.all_dh", ENGINE_get_default_DH(), e);
    report_default("set_default.all_ec", ENGINE_get_default_EC(), e);
    report_default("set_default.all_rand", ENGINE_get_default_RAND(), e);
    report_default("set_default.all_pkmeth", ENGINE_get_pkey_meth_engine(PKMETH_NID), e);
    report_default("set_default.all_asn1meth", ENGINE_get_pkey_asn1_meth_engine(ASN1METH_NID), e);
    report_default("set_default.all_cipher", ENGINE_get_cipher_engine(CIPHER_NID), e);
    report_default("set_default.all_digest", ENGINE_get_digest_engine(DIGEST_NID), e);
    ENGINE_unregister_RSA(e);
    ENGINE_unregister_DSA(e);
    ENGINE_unregister_DH(e);
    ENGINE_unregister_EC(e);
    ENGINE_unregister_RAND(e);
    ENGINE_unregister_pkey_meths(e);
    ENGINE_unregister_pkey_asn1_meths(e);
    ENGINE_unregister_ciphers(e);
    ENGINE_unregister_digests(e);

    /* ----------------------------------------------------------------------------------------
     * C. `ENGINE_set_default_string`: the spellings `int_def_cb` recognises.
     * -------------------------------------------------------------------------------------- */
    out_int("string.rsa_ret", ENGINE_set_default_string(e, "RSA") == 1);
    report_default("string.rsa_same", ENGINE_get_default_RSA(), e);
    ENGINE_unregister_RSA(e);

    out_int("string.rsa_dsa_ret", ENGINE_set_default_string(e, "RSA,DSA") == 1);
    report_default("string.rsa_dsa_rsa", ENGINE_get_default_RSA(), e);
    report_default("string.rsa_dsa_dsa", ENGINE_get_default_DSA(), e);
    ENGINE_unregister_RSA(e);
    ENGINE_unregister_DSA(e);

    /* nospc=1 trims the space around each element. */
    out_int("string.spaced_ret", ENGINE_set_default_string(e, " RSA , DSA ") == 1);
    report_default("string.spaced_rsa", ENGINE_get_default_RSA(), e);
    report_default("string.spaced_dsa", ENGINE_get_default_DSA(), e);
    ENGINE_unregister_RSA(e);
    ENGINE_unregister_DSA(e);

    out_int("string.cipher_digest_ret",
            ENGINE_set_default_string(e, "CIPHERS,DIGESTS") == 1);
    report_default("string.cipher_digest_cipher", ENGINE_get_cipher_engine(CIPHER_NID), e);
    report_default("string.cipher_digest_digest", ENGINE_get_digest_engine(DIGEST_NID), e);
    ENGINE_unregister_ciphers(e);
    ENGINE_unregister_digests(e);

    out_int("string.pkey_crypto_ret", ENGINE_set_default_string(e, "PKEY_CRYPTO") == 1);
    report_default("string.pkey_crypto_pkmeth", ENGINE_get_pkey_meth_engine(PKMETH_NID), e);
    out_int("string.pkey_crypto_asn1_null",
            ENGINE_get_pkey_asn1_meth_engine(ASN1METH_NID) == NULL);
    ENGINE_unregister_pkey_meths(e);

    out_int("string.pkey_asn1_ret", ENGINE_set_default_string(e, "PKEY_ASN1") == 1);
    report_default("string.pkey_asn1_asn1meth", ENGINE_get_pkey_asn1_meth_engine(ASN1METH_NID), e);
    out_int("string.pkey_asn1_pkmeth_null", ENGINE_get_pkey_meth_engine(PKMETH_NID) == NULL);
    ENGINE_unregister_pkey_asn1_meths(e);

    out_int("string.pkey_ret", ENGINE_set_default_string(e, "PKEY") == 1);
    report_default("string.pkey_pkmeth", ENGINE_get_pkey_meth_engine(PKMETH_NID), e);
    report_default("string.pkey_asn1meth", ENGINE_get_pkey_asn1_meth_engine(ASN1METH_NID), e);
    ENGINE_unregister_pkey_meths(e);
    ENGINE_unregister_pkey_asn1_meths(e);

    out_int("string.all_ret", ENGINE_set_default_string(e, "ALL") == 1);
    report_default("string.all_rsa", ENGINE_get_default_RSA(), e);
    report_default("string.all_ec", ENGINE_get_default_EC(), e);
    report_default("string.all_cipher", ENGINE_get_cipher_engine(CIPHER_NID), e);
    ENGINE_unregister_RSA(e);
    ENGINE_unregister_DSA(e);
    ENGINE_unregister_DH(e);
    ENGINE_unregister_EC(e);
    ENGINE_unregister_RAND(e);
    ENGINE_unregister_pkey_meths(e);
    ENGINE_unregister_pkey_asn1_meths(e);
    ENGINE_unregister_ciphers(e);
    ENGINE_unregister_digests(e);

    /* ----------------------------------------------------------------------------------------
     * D. The refusal arms: unknown, partial-then-unknown, NULL and empty.
     * -------------------------------------------------------------------------------------- */
    out_int("string.unknown_ret", ENGINE_set_default_string(e, "BOGUS") == 0);
    out_int("string.unknown_rsa_null", ENGINE_get_default_RSA() == NULL);

    /* A known element before the unknown one must not leave a partial default set. */
    out_int("string.partial_unknown_ret", ENGINE_set_default_string(e, "RSA,BOGUS") == 0);
    out_int("string.partial_unknown_rsa_null", ENGINE_get_default_RSA() == NULL);

    out_int("string.null_ret", ENGINE_set_default_string(e, NULL) == 0);
    out_int("string.empty_ret", ENGINE_set_default_string(e, "") == 0);

    /* ----------------------------------------------------------------------------------------
     * E. `ENGINE_register_complete`: the nine-arm registration, through each select.
     * -------------------------------------------------------------------------------------- */
    out_int("register_complete.ret", ENGINE_register_complete(e) == 1);
    report_default("register_complete.rsa", ENGINE_get_default_RSA(), e);
    report_default("register_complete.dsa", ENGINE_get_default_DSA(), e);
    report_default("register_complete.dh", ENGINE_get_default_DH(), e);
    report_default("register_complete.ec", ENGINE_get_default_EC(), e);
    report_default("register_complete.rand", ENGINE_get_default_RAND(), e);
    report_default("register_complete.pkmeth", ENGINE_get_pkey_meth_engine(PKMETH_NID), e);
    report_default("register_complete.asn1meth", ENGINE_get_pkey_asn1_meth_engine(ASN1METH_NID), e);
    report_default("register_complete.cipher", ENGINE_get_cipher_engine(CIPHER_NID), e);
    report_default("register_complete.digest", ENGINE_get_digest_engine(DIGEST_NID), e);
    ENGINE_unregister_RSA(e);
    ENGINE_unregister_DSA(e);
    ENGINE_unregister_DH(e);
    ENGINE_unregister_EC(e);
    ENGINE_unregister_RAND(e);
    ENGINE_unregister_pkey_meths(e);
    ENGINE_unregister_pkey_asn1_meths(e);
    ENGINE_unregister_ciphers(e);
    ENGINE_unregister_digests(e);

    /* ----------------------------------------------------------------------------------------
     * F. `ENGINE_register_all_complete`: the registry walk.
     * -------------------------------------------------------------------------------------- */
    out_int("register_all_complete.ret", ENGINE_register_all_complete() == 1);
    report_default("register_all_complete.rsa", ENGINE_get_default_RSA(), e);
    report_default("register_all_complete.cipher", ENGINE_get_cipher_engine(CIPHER_NID), e);
    ENGINE_unregister_RSA(e);
    ENGINE_unregister_ciphers(e);
    ENGINE_unregister_digests(e);
    ENGINE_unregister_DSA(e);
    ENGINE_unregister_DH(e);
    ENGINE_unregister_EC(e);
    ENGINE_unregister_RAND(e);
    ENGINE_unregister_pkey_meths(e);
    ENGINE_unregister_pkey_asn1_meths(e);

    /* ----------------------------------------------------------------------------------------
     * G. The `ENGINE_FLAGS_NO_REGISTER_ALL` skip: a flag-marked engine carrying a cipher is
     *    left unregistered, while its own NID is distinct from the walk's other engine.
     * -------------------------------------------------------------------------------------- */
    n = ENGINE_new();
    out_int("flag_engine.nonnull", n != NULL);
    ENGINE_set_id(n, "rt13c-flag");
    ENGINE_set_name(n, "RT 13 ctrl flag");
    out_int("flag_engine.set_flags_ret",
            ENGINE_set_flags(n, ENGINE_FLAGS_NO_REGISTER_ALL) == 1);
    out_int("flag_engine.get_flags",
            (ENGINE_get_flags(n) & ENGINE_FLAGS_NO_REGISTER_ALL) != 0);
    out_int("flag_engine.add_ret", ENGINE_add(n) == 1);
    ENGINE_free(n);
    ENGINE_set_ciphers(n, flag_cipher_cb);

    out_int("flag_walk.ret", ENGINE_register_all_complete() == 1);
    out_int("flag_walk.skipped_null", ENGINE_get_cipher_engine(FLAG_NID) == NULL);

    return 0;
}
