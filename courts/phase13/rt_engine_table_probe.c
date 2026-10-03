/*
 * rt_engine_table_probe.c -- RT-ENGINE-TABLE: the Phase-13.2 ENGINE table and method binding
 * surface, driven.
 *
 * One C program, compiled once against the admitted authority and once against the candidate
 * distribution shell; the two transcripts are diffed line by line, keyed on `key=value`. Every
 * observation is a small integer or a fixed string -- never an address, never a clock, never the
 * error queue. Where a pointer's *identity* matters it is compared against a fixed object this
 * probe owns and the result is printed as 0/1, so no address ever reaches the transcript.
 *
 * ## What this probe drives
 *
 * The 53 exports 13.2 lands, over the engine object and registry core 10.9/13.1 landed:
 *
 *   * the cipher table (`tb_cipher.c`): `ENGINE_register_ciphers`, the `ENGINE_get_cipher_engine`
 *     select, `ENGINE_get_cipher`, `ENGINE_register_all_ciphers`, `ENGINE_set_default_ciphers`,
 *     `ENGINE_unregister_ciphers` and the two callback accessors.
 *   * the RSA/DSA/DH/EC/RAND tables (`tb_rsa.c`/`tb_dsa.c`/`tb_dh.c`/`tb_eckey.c`/`tb_rand.c`):
 *     the register/register_all/set_default/unregister walk and the `dummy_nid` select, for each.
 *   * the `EVP_PKEY_METHOD` table's one 13.2 name, `ENGINE_get_pkey_meth`.
 *   * the key-loader binding surface (`eng_pkey.c`): the three setter/getter pairs and the
 *     `ENGINE_load_private_key`/`_public_key`/`_ssl_client_cert` entry points, including their
 *     NULL, uninitialised and no-loader refusals.
 *
 * ## A synthetic ENGINE is the subject
 *
 * The engine is built with the landed `ENGINE_new`, named with `ENGINE_set_id`/`ENGINE_set_name`
 * and published with `ENGINE_add`; every method it carries is a fixed object this probe owns
 * (`dummy_cipher`, `dummy_rsa`, ...) and every callback is a fixed function. The observable is
 * therefore the identity the engine carries, not any behaviour of an algorithm.
 *
 * ## Arms that are deliberately absent
 *
 * The method getters dereference their engine in the authority (`ENGINE_get_RSA` is `e->rsa_meth`
 * with no NULL guard), so a NULL-engine arm is **not driven** -- it would crash on both sides and
 * compare nothing. The only NULL arms driven are the three `eng_pkey.c` entry points, whose
 * authority bodies guard `e == NULL` explicitly. The reverse lookup's *absence* arm is driven
 * instead: a table that has never been populated answers NULL. The error queue is never read, so
 * the `ENGINE_R_UNIMPLEMENTED_CIPHER`/`_PUBLIC_KEY_METHOD` raises on the refusal arms cannot leak
 * into a comparison. No built-in engine is registered or looked up: `ENGINE_load_builtin_engines`
 * and `ENGINE_by_id` are RT-ENGINE's, and their `rdrand`/`dynamic` divergence is recorded in
 * `src/engine/eng_all.rs`.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>

#include <openssl/engine.h>

/* Fixed method objects: only their addresses are ever observed. */
static int dummy_cipher, dummy_rsa, dummy_dsa, dummy_dh, dummy_ec, dummy_rand;
static int dummy_pkmeth, dummy_pkey;

/* The one NID the cipher callback implements, and the one the pkey-meth callback implements. */
#define CIPHER_NID 919
#define CIPHER_NID_ABSENT 920
#define PKMETH_NID 4242
#define PKMETH_NID_ABSENT 4243

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

static EVP_PKEY *load_priv_cb(ENGINE *e, const char *key_id, UI_METHOD *ui, void *cb)
{
    (void)e;
    (void)key_id;
    (void)ui;
    (void)cb;
    return (EVP_PKEY *)&dummy_pkey;
}

static EVP_PKEY *load_pub_cb(ENGINE *e, const char *key_id, UI_METHOD *ui, void *cb)
{
    (void)e;
    (void)key_id;
    (void)ui;
    (void)cb;
    return (EVP_PKEY *)&dummy_pkey;
}

#define SSL_CERT_RET 7
static int load_ssl_cb(ENGINE *e, SSL *s, STACK_OF(X509_NAME) *ca_dn, X509 **pcert,
                       EVP_PKEY **ppkey, STACK_OF(X509) **pother, UI_METHOD *ui, void *cb)
{
    (void)e;
    (void)s;
    (void)ca_dn;
    (void)pcert;
    (void)ppkey;
    (void)pother;
    (void)ui;
    (void)cb;
    return SSL_CERT_RET;
}

static void out_int(const char *key, long v)
{
    printf("%s=%ld\n", key, v);
}

int main(void)
{
    ENGINE *e, *n, *k, *r;

    setvbuf(stdout, NULL, _IOLBF, 0);

    /* ----------------------------------------------------------------------------------------
     * A. A synthetic engine with every method bound, and the set/get identity.
     * -------------------------------------------------------------------------------------- */
    e = ENGINE_new();
    out_int("new.nonnull", e != NULL);
    out_int("set_id.ret", ENGINE_set_id(e, "rt13t") == 1);
    out_int("set_name.ret", ENGINE_set_name(e, "RT 13 table") == 1);
    out_int("add.ret", ENGINE_add(e) == 1);
    ENGINE_free(e);

    out_int("set_ciphers.ret", ENGINE_set_ciphers(e, cipher_cb) == 1);
    out_int("get_ciphers.same", ENGINE_get_ciphers(e) == cipher_cb);
    out_int("set_rsa.ret", ENGINE_set_RSA(e, (const RSA_METHOD *)&dummy_rsa) == 1);
    out_int("get_rsa.same", (const void *)ENGINE_get_RSA(e) == (const void *)&dummy_rsa);
    out_int("set_dsa.ret", ENGINE_set_DSA(e, (const DSA_METHOD *)&dummy_dsa) == 1);
    out_int("get_dsa.same", (const void *)ENGINE_get_DSA(e) == (const void *)&dummy_dsa);
    out_int("set_dh.ret", ENGINE_set_DH(e, (const DH_METHOD *)&dummy_dh) == 1);
    out_int("get_dh.same", (const void *)ENGINE_get_DH(e) == (const void *)&dummy_dh);
    out_int("set_ec.ret", ENGINE_set_EC(e, (const EC_KEY_METHOD *)&dummy_ec) == 1);
    out_int("get_ec.same", (const void *)ENGINE_get_EC(e) == (const void *)&dummy_ec);
    out_int("set_rand.ret", ENGINE_set_RAND(e, (const RAND_METHOD *)&dummy_rand) == 1);
    out_int("get_rand.same", (const void *)ENGINE_get_RAND(e) == (const void *)&dummy_rand);
    out_int("set_pkmeths.ret", ENGINE_set_pkey_meths(e, pkmeth_cb) == 1);
    out_int("get_pkmeths.same", ENGINE_get_pkey_meths(e) == pkmeth_cb);

    out_int("get_pkmeth.same",
            ENGINE_get_pkey_meth(e, PKMETH_NID) == (const EVP_PKEY_METHOD *)&dummy_pkmeth);
    out_int("get_pkmeth.absent_null", ENGINE_get_pkey_meth(e, PKMETH_NID_ABSENT) == NULL);
    out_int("get_pkmeth_engine.absent_null",
            ENGINE_get_pkey_meth_engine(PKMETH_NID_ABSENT) == NULL);

    /* ----------------------------------------------------------------------------------------
     * B. The cipher table: register, select, fetch, unregister, walk, default.
     * -------------------------------------------------------------------------------------- */
    out_int("register_ciphers.ret", ENGINE_register_ciphers(e) == 1);
    r = ENGINE_get_cipher_engine(CIPHER_NID);
    out_int("cipher_engine.nonnull", r != NULL);
    out_int("cipher_engine.same", r == e);
    if (r != NULL)
        ENGINE_finish(r);
    out_int("get_cipher.same",
            ENGINE_get_cipher(e, CIPHER_NID) == (const EVP_CIPHER *)&dummy_cipher);
    out_int("get_cipher.absent_null", ENGINE_get_cipher(e, CIPHER_NID_ABSENT) == NULL);

    ENGINE_unregister_ciphers(e);
    out_int("cipher_engine.after_unregister_null", ENGINE_get_cipher_engine(CIPHER_NID) == NULL);
    ENGINE_register_all_ciphers();
    r = ENGINE_get_cipher_engine(CIPHER_NID);
    out_int("register_all_ciphers.same", r == e);
    if (r != NULL)
        ENGINE_finish(r);
    out_int("set_default_ciphers.ret", ENGINE_set_default_ciphers(e) == 1);
    r = ENGINE_get_cipher_engine(CIPHER_NID);
    out_int("set_default_ciphers.same", r == e);
    if (r != NULL)
        ENGINE_finish(r);
    ENGINE_unregister_ciphers(e);
    out_int("cipher_engine.final_null", ENGINE_get_cipher_engine(CIPHER_NID) == NULL);

    /* ----------------------------------------------------------------------------------------
     * C. The four method tables and RAND: the direct register/default calls, the register_all
     *    walk, the dummy_nid select and the unregister cleanup.
     * -------------------------------------------------------------------------------------- */
    out_int("register_RSA.ret", ENGINE_register_RSA(e) == 1);
    out_int("register_DSA.ret", ENGINE_register_DSA(e) == 1);
    out_int("register_DH.ret", ENGINE_register_DH(e) == 1);
    out_int("register_EC.ret", ENGINE_register_EC(e) == 1);
    out_int("register_RAND.ret", ENGINE_register_RAND(e) == 1);
    out_int("set_default_RSA.ret", ENGINE_set_default_RSA(e) == 1);
    out_int("set_default_DSA.ret", ENGINE_set_default_DSA(e) == 1);
    out_int("set_default_DH.ret", ENGINE_set_default_DH(e) == 1);
    out_int("set_default_EC.ret", ENGINE_set_default_EC(e) == 1);
    out_int("set_default_RAND.ret", ENGINE_set_default_RAND(e) == 1);

    ENGINE_register_all_RSA();
    r = ENGINE_get_default_RSA();
    out_int("default_RSA.same", r == e);
    if (r != NULL)
        ENGINE_finish(r);
    ENGINE_unregister_RSA(e);
    out_int("default_RSA.after_unregister_null", ENGINE_get_default_RSA() == NULL);

    ENGINE_register_all_DSA();
    r = ENGINE_get_default_DSA();
    out_int("default_DSA.same", r == e);
    if (r != NULL)
        ENGINE_finish(r);
    ENGINE_unregister_DSA(e);
    out_int("default_DSA.after_unregister_null", ENGINE_get_default_DSA() == NULL);

    ENGINE_register_all_DH();
    r = ENGINE_get_default_DH();
    out_int("default_DH.same", r == e);
    if (r != NULL)
        ENGINE_finish(r);
    ENGINE_unregister_DH(e);
    out_int("default_DH.after_unregister_null", ENGINE_get_default_DH() == NULL);

    ENGINE_register_all_EC();
    r = ENGINE_get_default_EC();
    out_int("default_EC.same", r == e);
    if (r != NULL)
        ENGINE_finish(r);
    ENGINE_unregister_EC(e);
    out_int("default_EC.after_unregister_null", ENGINE_get_default_EC() == NULL);

    ENGINE_register_all_RAND();
    r = ENGINE_get_default_RAND();
    out_int("default_RAND.same", r == e);
    if (r != NULL)
        ENGINE_finish(r);
    ENGINE_unregister_RAND(e);
    out_int("default_RAND.after_unregister_null", ENGINE_get_default_RAND() == NULL);

    /* ----------------------------------------------------------------------------------------
     * D. The no-method refusal: an engine with no RSA method registers as a no-op.
     * -------------------------------------------------------------------------------------- */
    n = ENGINE_new();
    out_int("nomethod.nonnull", n != NULL);
    ENGINE_set_id(n, "rt13t-none");
    ENGINE_set_name(n, "RT 13 table no method");
    ENGINE_add(n);
    ENGINE_free(n);
    out_int("register_RSA.nomethod_ret", ENGINE_register_RSA(n) == 1);
    out_int("set_default_RSA.nomethod_ret", ENGINE_set_default_RSA(n) == 1);
    out_int("default_RSA.nomethod_null", ENGINE_get_default_RSA() == NULL);

    /* ----------------------------------------------------------------------------------------
     * E. The key-loader surface: the three setter/getter pairs.
     * -------------------------------------------------------------------------------------- */
    k = ENGINE_new();
    out_int("loader.nonnull", k != NULL);
    ENGINE_set_id(k, "rt13t-key");
    ENGINE_set_name(k, "RT 13 table key loader");
    ENGINE_add(k);
    ENGINE_free(k);

    out_int("set_load_priv.ret", ENGINE_set_load_privkey_function(k, load_priv_cb) == 1);
    out_int("get_load_priv.same", ENGINE_get_load_privkey_function(k) == load_priv_cb);
    out_int("set_load_pub.ret", ENGINE_set_load_pubkey_function(k, load_pub_cb) == 1);
    out_int("get_load_pub.same", ENGINE_get_load_pubkey_function(k) == load_pub_cb);
    out_int("set_load_ssl.ret",
            ENGINE_set_load_ssl_client_cert_function(k, load_ssl_cb) == 1);
    out_int("get_load_ssl.same", ENGINE_get_ssl_client_cert_function(k) == load_ssl_cb);

    /* The NULL-engine refusals, which the authority guards explicitly. */
    out_int("load_private.NULL_null", ENGINE_load_private_key(NULL, "id", NULL, NULL) == NULL);
    out_int("load_public.NULL_null", ENGINE_load_public_key(NULL, "id", NULL, NULL) == NULL);
    out_int("load_ssl.NULL_zero",
            ENGINE_load_ssl_client_cert(NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL) == 0);

    /* The uninitialised refusals: `k` carries all three loaders but `funct_ref == 0`. */
    out_int("load_private.uninit_null", ENGINE_load_private_key(k, "id", NULL, NULL) == NULL);
    out_int("load_public.uninit_null", ENGINE_load_public_key(k, "id", NULL, NULL) == NULL);
    out_int("load_ssl.uninit_zero",
            ENGINE_load_ssl_client_cert(k, NULL, NULL, NULL, NULL, NULL, NULL, NULL) == 0);

    /* After `ENGINE_init`, each entry point reaches its loader. */
    out_int("init_key.ret", ENGINE_init(k) == 1);
    out_int("load_private.same",
            ENGINE_load_private_key(k, "id", NULL, NULL) == (EVP_PKEY *)&dummy_pkey);
    out_int("load_public.same",
            ENGINE_load_public_key(k, "id", NULL, NULL) == (EVP_PKEY *)&dummy_pkey);
    out_int("load_ssl.ret",
            ENGINE_load_ssl_client_cert(k, NULL, NULL, NULL, NULL, NULL, NULL, NULL)
                == SSL_CERT_RET);

    /* The no-loader refusals: `n` is initialised but carries no loader. */
    out_int("init_none.ret", ENGINE_init(n) == 1);
    out_int("load_private.noloader_null", ENGINE_load_private_key(n, "id", NULL, NULL) == NULL);
    out_int("load_public.noloader_null", ENGINE_load_public_key(n, "id", NULL, NULL) == NULL);
    out_int("load_ssl.noloader_zero",
            ENGINE_load_ssl_client_cert(n, NULL, NULL, NULL, NULL, NULL, NULL, NULL) == 0);

    return 0;
}
