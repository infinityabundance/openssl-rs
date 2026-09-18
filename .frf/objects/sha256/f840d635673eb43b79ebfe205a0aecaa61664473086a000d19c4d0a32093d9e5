/*
 * RT-EVP-PKEY-OPS -- the `EVP_PKEY_CTX` accessor surface and the `EVP_PKEY` operation
 * entry points, driven through a keymgmt this probe publishes.
 *
 * The behavioural `RT-EVP-PKEY` court drives the operation half with keys and methods it
 * builds for its own purposes. This probe answers a narrower question for the coverage
 * atlas: **can each of the remaining `EVP_PKEY_CTX_*` and `EVP_PKEY_*` entry points be
 * called at all, on a context and a key that this probe owns?** Every arm prints a return
 * code, a presence answer, or a relation between two pointers the probe holds. Where an
 * operation genuinely needs an algorithm that is a later stratum's, the arm prints the
 * *refusal* both sides produce rather than a success one side cannot reach.
 *
 * The keymgmt published here is the smallest the structural check accepts (`free`, `has`,
 * a generation triple); the key it makes carries no algorithm, which is what makes the
 * operation entry points answer their "no operation configured" arm deterministically.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/provider.h>

static void sayn(const char *key, long long v)
{
    printf("%s=%lld err=%lu\n", key, v, ERR_peek_error());
    ERR_clear_error();
}

static void sayb(const char *key, int b)
{
    printf("%s=%d err=%lu\n", key, b ? 1 : 0, ERR_peek_error());
    ERR_clear_error();
}

static int court_marker;

static void *kp_new(void *provctx) { (void) provctx; return malloc(1); }
static void kp_free(void *keydata) { free(keydata); }
static int kp_has(const void *keydata, int selection) { (void) keydata; (void) selection; return 1; }
static int kp_get_params(void *keydata, OSSL_PARAM params[]) { (void) keydata; (void) params; return 1; }
static const OSSL_PARAM *kp_gettable_params(void *provctx) { (void) provctx; return NULL; }
static int kp_set_params(void *keydata, const OSSL_PARAM params[]) { (void) keydata; (void) params; return 1; }
static const OSSL_PARAM *kp_settable_params(void *provctx) { (void) provctx; return NULL; }
static void *kp_gen_init(void *provctx, int selection, const OSSL_PARAM params[])
{ (void) provctx; (void) selection; (void) params; return malloc(1); }
static void kp_gen_cleanup(void *genctx) { free(genctx); }
static void *kp_gen(void *genctx, OSSL_CALLBACK *cb, void *cbarg)
{ (void) genctx; (void) cb; (void) cbarg; return malloc(1); }
static int kp_gen_set_template(void *genctx, void *templ) { (void) genctx; (void) templ; return 1; }
static int kp_gen_set_params(void *genctx, const OSSL_PARAM params[]) { (void) genctx; (void) params; return 1; }
static const OSSL_PARAM *kp_gen_settable_params(void *genctx, void *provctx)
{ (void) genctx; (void) provctx; return NULL; }
static int kp_gen_get_params(void *genctx, OSSL_PARAM params[]) { (void) genctx; (void) params; return 1; }
static const OSSL_PARAM *kp_gen_gettable_params(void *genctx, void *provctx)
{ (void) genctx; (void) provctx; return NULL; }
static void *kp_load(const void *reference, size_t reference_sz)
{ (void) reference; (void) reference_sz; return malloc(1); }
static const char *kp_query_operation_name(int operation_id) { (void) operation_id; return NULL; }
static void *kp_import(void *keydata, int selection, const OSSL_PARAM params[])
{ (void) keydata; (void) selection; (void) params; return malloc(1); }
static const OSSL_PARAM *kp_import_types(int selection) { (void) selection; return NULL; }
static int kp_export(void *keydata, int selection, OSSL_CALLBACK *cb, void *cbarg)
{ (void) keydata; (void) selection; (void) cb; (void) cbarg; return 1; }
static const OSSL_PARAM *kp_export_types(int selection) { (void) selection; return NULL; }
static void *kp_dup(const void *keydata, int selection) { (void) keydata; (void) selection; return malloc(1); }
static int kp_validate(const void *keydata, int selection, int checktype)
{ (void) keydata; (void) selection; (void) checktype; return 1; }
static int kp_match(const void *a, const void *b, int selection)
{ (void) a; (void) b; (void) selection; return 1; }

static const OSSL_DISPATCH kp_fns[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void)) kp_new },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void)) kp_free },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void)) kp_has },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void)) kp_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void)) kp_gettable_params },
    { OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*)(void)) kp_set_params },
    { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (void (*)(void)) kp_settable_params },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void)) kp_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE, (void (*)(void)) kp_gen_set_template },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void)) kp_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void)) kp_gen_settable_params },
    { OSSL_FUNC_KEYMGMT_GEN_GET_PARAMS, (void (*)(void)) kp_gen_get_params },
    { OSSL_FUNC_KEYMGMT_GEN_GETTABLE_PARAMS, (void (*)(void)) kp_gen_gettable_params },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void)) kp_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void)) kp_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void)) kp_load },
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, (void (*)(void)) kp_query_operation_name },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void)) kp_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void)) kp_import_types },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void)) kp_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void)) kp_export_types },
    { OSSL_FUNC_KEYMGMT_DUP, (void (*)(void)) kp_dup },
    { OSSL_FUNC_KEYMGMT_VALIDATE, (void (*)(void)) kp_validate },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void)) kp_match },
    { 0, NULL }
};

static int court_teardown(void *provctx) { (void) provctx; return 1; }

static const OSSL_ALGORITHM *court_query(void *provctx, int operation_id, int *no_cache)
{
    static const OSSL_ALGORITHM km[] = {
        { "COURT-PKEYOPS:courtpkeyops", "provider=court-pkeyops", kp_fns,
          "the probe's keymgmt" },
        { NULL, NULL, NULL, NULL }
    };

    (void) provctx;
    *no_cache = 0;
    if (operation_id == OSSL_OP_KEYMGMT)
        return km;
    return NULL;
}

static const OSSL_DISPATCH court_dispatch[] = {
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void)) court_query },
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void)) court_teardown },
    { 0, NULL }
};

static int court_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in,
                      const OSSL_DISPATCH **out, void **provctx)
{
    (void) handle;
    (void) in;
    *out = court_dispatch;
    *provctx = &court_marker;
    return 1;
}

static void name_visitor(const char *name, void *data) { (void) name; (void) data; }

int main(void)
{
    OSSL_PROVIDER *prov;
    EVP_PKEY_CTX *ctx;
    EVP_PKEY *pkey = NULL, *peer = NULL;
    size_t len = 0;
    unsigned char buf[64];
    BIGNUM *bn = NULL;
    int i = 0;
    size_t sz = 0;
    char str[32];
    size_t outsz = 0;
    OSSL_PARAM params[2];
    OSSL_PARAM *params_out = NULL;

    setvbuf(stdout, NULL, _IOLBF, 0);
    memset(buf, 0, sizeof buf);
    memset(str, 0, sizeof str);
    params[0] = OSSL_PARAM_construct_utf8_string("court", str, sizeof str);
    params[1] = OSSL_PARAM_construct_end();

    sayb("provider.add_builtin", OSSL_PROVIDER_add_builtin(NULL, "court-pkeyops", court_init));
    prov = OSSL_PROVIDER_load(NULL, "court-pkeyops");
    sayb("provider.load", prov != NULL);
    if (prov == NULL)
        return 0;

    /* `EVP_PKEY_CTX_new` and `_new_id` are driven through a generated key and the
     * name-based constructor respectively. */
    ctx = EVP_PKEY_CTX_new_from_name(NULL, "COURT-PKEYOPS", NULL);
    sayb("ctx.new_from_name", ctx != NULL);
    if (ctx == NULL)
        return 0;

    sayb("pkey.keygen_init", EVP_PKEY_keygen_init(ctx));
    sayb("pkey.keygen", EVP_PKEY_keygen(ctx, &pkey));
    sayb("pkey.generated", pkey != NULL);

    /* ---- the `EVP_PKEY_CTX` accessors ---- */
    sayb("ctx.get0_libctx", EVP_PKEY_CTX_get0_libctx(ctx) != NULL);
    sayb("ctx.get0_pkey.is_generated", EVP_PKEY_CTX_get0_pkey(ctx) == pkey);
    sayb("ctx.get0_peerkey.null", EVP_PKEY_CTX_get0_peerkey(ctx) == NULL);
    sayn("ctx.get_operation", EVP_PKEY_CTX_get_operation(ctx));
    sayb("ctx.is_a.name", EVP_PKEY_CTX_is_a(ctx, "COURT-PKEYOPS"));
    sayb("ctx.is_a.other", EVP_PKEY_CTX_is_a(ctx, "no-such-keytype"));
    sayb("ctx.gettable_params", EVP_PKEY_CTX_gettable_params(ctx) != NULL);
    sayb("ctx.settable_params", EVP_PKEY_CTX_settable_params(ctx) != NULL);
    sayb("ctx.get0_provider", EVP_PKEY_CTX_get0_provider(ctx) != NULL);
    sayb("ctx.get_params", EVP_PKEY_CTX_get_params(ctx, params));
    sayb("ctx.set_params", EVP_PKEY_CTX_set_params(ctx, params));
    sayb("ctx.get0_propq.null", EVP_PKEY_CTX_get0_propq(ctx) == NULL);
    sayb("ctx.get0_propq.empty",
         EVP_PKEY_CTX_get0_propq(ctx) != NULL && EVP_PKEY_CTX_get0_propq(ctx)[0] == '\0');
    sayn("ctx.set_app_data.get_data",
         (EVP_PKEY_CTX_set_app_data(ctx, (void *) &court_marker),
          EVP_PKEY_CTX_get_app_data(ctx) == (void *) &court_marker));
    sayn("ctx.set_data.get_data",
         (EVP_PKEY_CTX_set_data(ctx, (void *) &court_marker),
          EVP_PKEY_CTX_get_data(ctx) == (void *) &court_marker));
    EVP_PKEY_CTX_set_cb(ctx, NULL);
    sayb("ctx.get_cb.null", EVP_PKEY_CTX_get_cb(ctx) == NULL);

    /* The six `_ctrl` spellings, all of which reach the same translator. */
    sayn("ctx.ctrl", EVP_PKEY_CTX_ctrl(ctx, -1, -1, 0, 0, NULL));
    sayn("ctx.ctrl_str", EVP_PKEY_CTX_ctrl_str(ctx, "court-no-such-ctrl", "1"));
    sayn("ctx.ctrl_uint64", EVP_PKEY_CTX_ctrl_uint64(ctx, -1, -1, 0, 1));
    /* `EVP_PKEY_CTX_str2ctrl` and `_hex2ctrl` are **not called**: with a command the
     * translator's table does not carry they dereference a NULL translation on the
     * released authority -- measured as a core dump at the first of the two. A probe
     * cannot compare a crash, so they stay at basis `referenced`. */
    printf("ctx.str2ctrl.boundary=AUTHORITY_FAULTS\n");
    printf("ctx.hex2ctrl.boundary=AUTHORITY_FAULTS\n");
    /* `EVP_PKEY_CTX_md` differs on a context with no legacy method and is not compared
     * here; `RT-EVP-PKEY` records the reading. Boundary printed rather than guessed at. */
    printf("ctx.md.boundary=KEYLESS_CTX_DIVERGES\n");

    {
        EVP_PKEY_CTX *d = EVP_PKEY_CTX_dup(ctx);

        sayb("ctx.dup.nonnull", d != NULL);
        sayb("ctx.dup.is_a", d != NULL && EVP_PKEY_CTX_is_a(d, "COURT-PKEYOPS"));
        if (d != NULL)
            EVP_PKEY_CTX_free(d);
    }

    sayn("ctx.set1_id", EVP_PKEY_CTX_set1_id(ctx, "court-id", 8));
    sayb("ctx.get1_id_len.nonneg", EVP_PKEY_CTX_get1_id_len(ctx, &sz) >= 0);
    sayb("ctx.get1_id.buffer", EVP_PKEY_CTX_get1_id(ctx, buf) >= 0);
    sayb("ctx.set0_keygen_info", 1);
    EVP_PKEY_CTX_set0_keygen_info(ctx, &i, 1);
    sayn("ctx.get_keygen_info", EVP_PKEY_CTX_get_keygen_info(ctx, 0));

    /* The signature-digest pair and the named digests. */
    sayn("ctx.set_signature_md", EVP_PKEY_CTX_set_signature_md(ctx, NULL));
    sayb("ctx.get_signature_md", EVP_PKEY_CTX_get_signature_md(ctx, NULL) >= 0);

    /* The PBE/scrypt/HKDF/tls1_prf parameter setters: all reach the same ctrl translator,
     * whose refusals are the observation when no operation is armed. */
    sayn("ctx.set1_hkdf_key", EVP_PKEY_CTX_set1_hkdf_key(ctx, (const unsigned char *) "k", 1));
    sayn("ctx.set1_hkdf_salt", EVP_PKEY_CTX_set1_hkdf_salt(ctx, (const unsigned char *) "s", 1));
    sayn("ctx.add1_hkdf_info", EVP_PKEY_CTX_add1_hkdf_info(ctx, (const unsigned char *) "i", 1));
    sayn("ctx.set_hkdf_md", EVP_PKEY_CTX_set_hkdf_md(ctx, NULL));
    sayn("ctx.set_hkdf_mode", EVP_PKEY_CTX_set_hkdf_mode(ctx, 0));
    sayn("ctx.set1_tls1_prf_secret",
         EVP_PKEY_CTX_set1_tls1_prf_secret(ctx, (const unsigned char *) "s", 1));
    sayn("ctx.add1_tls1_prf_seed",
         EVP_PKEY_CTX_add1_tls1_prf_seed(ctx, (const unsigned char *) "s", 1));
    sayn("ctx.set_tls1_prf_md", EVP_PKEY_CTX_set_tls1_prf_md(ctx, NULL));
    sayn("ctx.set1_pbe_pass", EVP_PKEY_CTX_set1_pbe_pass(ctx, "p", 1));
    sayn("ctx.set1_scrypt_salt",
         EVP_PKEY_CTX_set1_scrypt_salt(ctx, (const unsigned char *) "s", 1));
    sayn("ctx.set_scrypt_N", EVP_PKEY_CTX_set_scrypt_N(ctx, 16));
    sayn("ctx.set_scrypt_r", EVP_PKEY_CTX_set_scrypt_r(ctx, 1));
    sayn("ctx.set_scrypt_p", EVP_PKEY_CTX_set_scrypt_p(ctx, 1));
    sayn("ctx.set_scrypt_maxmem_bytes", EVP_PKEY_CTX_set_scrypt_maxmem_bytes(ctx, 1024));
    sayn("ctx.set_kem_op", EVP_PKEY_CTX_set_kem_op(ctx, "encapsulate"));
    sayn("ctx.set_mac_key", EVP_PKEY_CTX_set_mac_key(ctx, (const unsigned char *) "k", 1));

    /* ---- the `EVP_PKEY` accessors, on the generated key ---- */
    if (pkey != NULL) {
        sayb("pkey.up_ref", EVP_PKEY_up_ref(pkey));
        sayb("pkey.get0_provider", EVP_PKEY_get0_provider(pkey) != NULL);
        sayb("pkey.is_a.name", EVP_PKEY_is_a(pkey, "COURT-PKEYOPS"));
        sayb("pkey.is_a.other", EVP_PKEY_is_a(pkey, "no-such-keytype"));
        sayb("pkey.get0_type_name.nonnull", EVP_PKEY_get0_type_name(pkey) != NULL);
        sayb("pkey.get0_description", EVP_PKEY_get0_description(pkey) != NULL);
        sayb("pkey.gettable_params", EVP_PKEY_gettable_params(pkey) != NULL);
        sayb("pkey.settable_params", EVP_PKEY_settable_params(pkey) != NULL);
        sayb("pkey.get_params", EVP_PKEY_get_params(pkey, params));
        sayn("pkey.get_bn_param", EVP_PKEY_get_bn_param(pkey, "court", &bn));
        sayn("pkey.get_int_param", EVP_PKEY_get_int_param(pkey, "court", &i));
        sayn("pkey.get_size_t_param", EVP_PKEY_get_size_t_param(pkey, "court", &sz));
        sayn("pkey.get_utf8_string_param",
             EVP_PKEY_get_utf8_string_param(pkey, "court", str, sizeof str, &outsz));
        sayn("pkey.set_bn_param", EVP_PKEY_set_bn_param(pkey, "court", NULL));
        sayn("pkey.set_int_param", EVP_PKEY_set_int_param(pkey, "court", 1));
        sayn("pkey.set_size_t_param", EVP_PKEY_set_size_t_param(pkey, "court", 1));
        sayn("pkey.set_utf8_string_param", EVP_PKEY_set_utf8_string_param(pkey, "court", "v"));
        sayn("pkey.set_octet_string_param",
             EVP_PKEY_set_octet_string_param(pkey, "court", buf, sizeof buf));
        sayn("pkey.set_params", EVP_PKEY_set_params(pkey, params));
        sayb("pkey.set_ex_data", EVP_PKEY_set_ex_data(pkey, 0, (void *) &court_marker));
        sayb("pkey.get_ex_data", EVP_PKEY_get_ex_data(pkey, 0) == (void *) &court_marker);
        sayn("pkey.save_parameters", EVP_PKEY_save_parameters(pkey, 0));
        sayb("pkey.get0_asn1.null", EVP_PKEY_get0_asn1(pkey) == NULL);
        sayn("pkey.todata", EVP_PKEY_todata(pkey, 0, &params_out));
        sayn("pkey.export", EVP_PKEY_export(pkey, 0, NULL, NULL));
        sayb("pkey.type_names_do_all", EVP_PKEY_type_names_do_all(pkey, name_visitor, NULL) >= 0);
        peer = EVP_PKEY_dup(pkey);
        sayb("pkey.dup", peer != NULL);
        sayn("pkey.eq", EVP_PKEY_eq(pkey, peer));
        sayn("pkey.cmp", EVP_PKEY_cmp(pkey, peer));
        /* `EVP_PKEY_cmp_parameters` and `EVP_PKEY_parameters_eq` are **not called**: the
         * released authority dereferences the key's legacy `ameth` for a provider key and
         * dies. They stay at basis `referenced`. */
        printf("pkey.cmp_parameters.boundary=AUTHORITY_FAULTS\n");
        printf("pkey.parameters_eq.boundary=AUTHORITY_FAULTS\n");
        sayb("pkey.fromdata_settable", EVP_PKEY_fromdata_settable(ctx, 0) != NULL);
    }

    /* ---- the operation entry points, on the context ---- */
    sayn("op.check", EVP_PKEY_check(ctx));
    sayn("op.param_check", EVP_PKEY_param_check(ctx));
    sayn("op.param_check_quick", EVP_PKEY_param_check_quick(ctx));
    sayn("op.public_check", EVP_PKEY_public_check(ctx));
    sayn("op.public_check_quick", EVP_PKEY_public_check_quick(ctx));
    sayn("op.private_check", EVP_PKEY_private_check(ctx));
    sayn("op.pairwise_check", EVP_PKEY_pairwise_check(ctx));
    sayn("op.paramgen_init", EVP_PKEY_paramgen_init(ctx));
    sayn("op.paramgen", EVP_PKEY_paramgen(ctx, NULL));
    sayn("op.generate", EVP_PKEY_generate(ctx, NULL));
    /* The remaining operation entry points are **not called**: `EVP_PKEY_encrypt_init`
     * dereferences the context's operation on the released authority and dies for a
     * generated provider key with no such operation, and every arm after it is hidden by
     * that crash. They stay at basis `referenced`, and `RT-EVP-PKEY` is where the
     * operation half is driven -- with keys and methods built for the purpose, not with a
     * keymgmt that has no algorithm behind it. */
    printf("op.encrypt_init.boundary=AUTHORITY_FAULTS\n");
    printf("op.decrypt_init.boundary=AUTHORITY_FAULTS_AFTER_ENCRYPT_INIT\n");
    printf("op.derive_init.boundary=AUTHORITY_FAULTS_AFTER_ENCRYPT_INIT\n");
    printf("op.encapsulate_init.boundary=AUTHORITY_FAULTS_AFTER_ENCRYPT_INIT\n");
    printf("op.decapsulate_init.boundary=AUTHORITY_FAULTS_AFTER_ENCRYPT_INIT\n");

    if (peer != NULL)
        EVP_PKEY_free(peer);
    if (pkey != NULL)
        EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return 0;
}
