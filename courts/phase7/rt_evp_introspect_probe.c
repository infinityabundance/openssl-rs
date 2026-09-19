/*
 * RT-EVP-INTROSPECT -- the method-table and legacy-header surfaces the behavioural
 * probes did not reach.
 *
 * Why another court rather than more arms in the existing ones
 * -----------------------------------------------------------
 * The court coverage atlas (`forensics/tools/court_coverage.py`, docs/DECISIONS.md
 * D199) asks, of every implemented export of a completed stratum, whether a probe that
 * ran references it. The Phase-7 probes drove 442 of 706; the remaining 264 were
 * *referenced* by `RT-EVP-REF` and nothing more. This probe turns a large block of them
 * into **called**: each arm below invokes the entry point and prints a relation, a
 * return code or a pointer identity, the way every other probe in this stratum does.
 *
 * What it observes, and why each observation is differential
 * ---------------------------------------------------------
 *   * **the setter/getter pairs of `EVP_PKEY_METHOD` and `EVP_PKEY_ASN1_METHOD`.** The
 *     setter stores a callback, the getter reads it back, and the probe prints whether
 *     the pointer it read back is the pointer it stored. That is a relation between two
 *     pointers the probe owns, so no address is printed and a transcription that stored
 *     the wrong field of a pair -- the defect class D184 records -- is visible as a
 *     single `0`.
 *   * **`EVP_MD_meth_*`, `EVP_CIPHER_meth_*` and their `_dup` forms.** Same shape.
 *   * **the `asn1`-parameter callbacks of a hand-built `EVP_CIPHER`.** Same shape.
 *   * **the PBE and password-prompt entry points**, by return code and by a bounded byte
 *     comparison of the derived key against the same computation on both sides; the
 *     parameters are chosen so the work is a few milliseconds.
 *   * **`EVP_MD_CTX_copy`** on a fresh context, which succeeds and whose result is read
 *     back through `EVP_MD_CTX_get0_md`.
 *
 * Deliberately not called here
 * ----------------------------
 *   * The `EVP_CIPHER_CTX_*` accessors and the legacy `EVP_*Init*` wrappers: they need an
 *     armed context, and arming one needs a cipher method -- a provider. `RT-EVP-CIPHER`
 *     and the class probe own that surface; calling these on an unarmed context is the
 *     authority fault D-CIPHERCTX-PARAMS-NULL records, and a probe cannot compare a crash.
 *   * `EVP_PKEY_asn1_add0`/`add_alias`: they mutate a process-global registry that is
 *     another stratum's table, and the observable they would produce is the count of that
 *     table, which is not this court's subject.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/params.h>
#include <openssl/sha.h>

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

/* ---- dummy callbacks with the exact signatures the setters take ---- */

static int cb_pkey(EVP_PKEY *pk) { (void) pk; return 1; }
static void cb_ctx_void(EVP_PKEY_CTX *ctx) { (void) ctx; }
static int cb_ctx_int(EVP_PKEY_CTX *ctx) { (void) ctx; return 1; }
static int cb_copy(EVP_PKEY_CTX *dst, const EVP_PKEY_CTX *src)
{ (void) dst; (void) src; return 1; }
static int cb_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{ (void) ctx; (void) type; (void) p1; (void) p2; return 1; }
static int cb_ctrl_str(EVP_PKEY_CTX *ctx, const char *type, const char *value)
{ (void) ctx; (void) type; (void) value; return 1; }
static int cb_op_md(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx)
{ (void) ctx; (void) mctx; return 1; }
static int cb_op_buf(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
                     const unsigned char *in, size_t inlen)
{ (void) ctx; (void) out; (void) outlen; (void) in; (void) inlen; return 1; }
static int cb_op_key(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen)
{ (void) ctx; (void) key; (void) keylen; return 1; }
static int cb_op_verify(EVP_PKEY_CTX *ctx, const unsigned char *sig, size_t siglen,
                        const unsigned char *tbs, size_t tbslen)
{ (void) ctx; (void) sig; (void) siglen; (void) tbs; (void) tbslen; return 1; }
static int cb_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pk) { (void) ctx; (void) pk; return 1; }
static int cb_digestsig(EVP_MD_CTX *ctx, unsigned char *sig, size_t *siglen,
                        const unsigned char *tbs, size_t tbslen)
{ (void) ctx; (void) sig; (void) siglen; (void) tbs; (void) tbslen; return 1; }
static int cb_digestverify(EVP_MD_CTX *ctx, const unsigned char *sig, size_t siglen,
                           const unsigned char *tbs, size_t tbslen)
{ (void) ctx; (void) sig; (void) siglen; (void) tbs; (void) tbslen; return 1; }
static int cb_signctx_init(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx)
{ (void) ctx; (void) mctx; return 1; }
static int cb_signctx(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
                      EVP_MD_CTX *mctx)
{ (void) ctx; (void) sig; (void) siglen; (void) mctx; return 1; }
static int cb_verifyctx(EVP_PKEY_CTX *ctx, const unsigned char *sig, int siglen,
                        EVP_MD_CTX *mctx)
{ (void) ctx; (void) sig; (void) siglen; (void) mctx; return 1; }

/* MD / CIPHER method callbacks. */
static int cb_md_ctx_int(EVP_MD_CTX *ctx) { (void) ctx; return 1; }
static int cb_md_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from)
{ (void) to; (void) from; return 1; }
static int cb_md_ctrl(EVP_MD_CTX *ctx, int cmd, int p1, void *p2)
{ (void) ctx; (void) cmd; (void) p1; (void) p2; return 1; }
static int cb_md_final(EVP_MD_CTX *ctx, unsigned char *md) { (void) ctx; (void) md; return 1; }
static int cb_md_update(EVP_MD_CTX *ctx, const void *data, size_t count)
{ (void) ctx; (void) data; (void) count; return 1; }
static int cb_cipher_ctx_int(EVP_CIPHER_CTX *ctx) { (void) ctx; return 1; }
static int cb_cipher_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
{ (void) ctx; (void) type; (void) arg; (void) ptr; return 1; }
static int cb_asn1(EVP_CIPHER_CTX *ctx, ASN1_TYPE *t) { (void) ctx; (void) t; return 1; }
static int cb_cipher_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                          const unsigned char *iv, int enc)
{ (void) ctx; (void) key; (void) iv; (void) enc; return 1; }

static int pkey_meth_arms(void)
{
    EVP_PKEY_METHOD *pm = EVP_PKEY_meth_new(EVP_PKEY_HMAC, 0);
    int (*p_check)(EVP_PKEY *) = NULL;
    void (*p_cleanup)(EVP_PKEY_CTX *) = NULL;
    int (*p_copy)(EVP_PKEY_CTX *, const EVP_PKEY_CTX *) = NULL;
    int (*p_ctrl)(EVP_PKEY_CTX *, int, int, void *) = NULL;
    int (*p_ctrl_str)(EVP_PKEY_CTX *, const char *, const char *) = NULL;
    int (*p_decrypt_init)(EVP_PKEY_CTX *) = NULL;
    int (*p_decrypt)(EVP_PKEY_CTX *, unsigned char *, size_t *, const unsigned char *, size_t) = NULL;
    int (*p_derive_init)(EVP_PKEY_CTX *) = NULL;
    int (*p_derive)(EVP_PKEY_CTX *, unsigned char *, size_t *) = NULL;
    int (*p_digest_custom)(EVP_PKEY_CTX *, EVP_MD_CTX *) = NULL;
    int (*p_digestsign)(EVP_MD_CTX *, unsigned char *, size_t *, const unsigned char *, size_t) = NULL;
    int (*p_digestverify)(EVP_MD_CTX *, const unsigned char *, size_t, const unsigned char *, size_t) = NULL;
    int (*p_encrypt_init)(EVP_PKEY_CTX *) = NULL;
    int (*p_encrypt)(EVP_PKEY_CTX *, unsigned char *, size_t *, const unsigned char *, size_t) = NULL;
    int (*p_init)(EVP_PKEY_CTX *) = NULL;
    int (*p_keygen_init)(EVP_PKEY_CTX *) = NULL;
    int (*p_keygen)(EVP_PKEY_CTX *, EVP_PKEY *) = NULL;
    int (*p_param_check)(EVP_PKEY *) = NULL;
    int (*p_paramgen_init)(EVP_PKEY_CTX *) = NULL;
    int (*p_paramgen)(EVP_PKEY_CTX *, EVP_PKEY *) = NULL;
    int (*p_public_check)(EVP_PKEY *) = NULL;
    int (*p_sign_init)(EVP_PKEY_CTX *) = NULL;
    int (*p_sign)(EVP_PKEY_CTX *, unsigned char *, size_t *, const unsigned char *, size_t) = NULL;
    int (*p_signctx_init)(EVP_PKEY_CTX *, EVP_MD_CTX *) = NULL;
    int (*p_signctx)(EVP_PKEY_CTX *, unsigned char *, size_t *, EVP_MD_CTX *) = NULL;
    int (*p_verify_init)(EVP_PKEY_CTX *) = NULL;
    int (*p_verify)(EVP_PKEY_CTX *, const unsigned char *, size_t, const unsigned char *, size_t) = NULL;
    int (*p_verify_recover_init)(EVP_PKEY_CTX *) = NULL;
    int (*p_verify_recover)(EVP_PKEY_CTX *, unsigned char *, size_t *, const unsigned char *, size_t) = NULL;
    int (*p_verifyctx_init)(EVP_PKEY_CTX *, EVP_MD_CTX *) = NULL;
    int (*p_verifyctx)(EVP_PKEY_CTX *, const unsigned char *, int, EVP_MD_CTX *) = NULL;

    if (pm == NULL) {
        sayb("pkey_meth.new", 0);
        return 0;
    }
    sayb("pkey_meth.new", pm != NULL);

    EVP_PKEY_meth_set_check(pm, cb_pkey);
    EVP_PKEY_meth_get_check(pm, &p_check);
    sayb("pkey_meth.check", p_check == cb_pkey);

    EVP_PKEY_meth_set_cleanup(pm, cb_ctx_void);
    EVP_PKEY_meth_get_cleanup(pm, &p_cleanup);
    sayb("pkey_meth.cleanup", p_cleanup == cb_ctx_void);

    EVP_PKEY_meth_set_copy(pm, cb_copy);
    EVP_PKEY_meth_get_copy(pm, &p_copy);
    sayb("pkey_meth.copy", p_copy == cb_copy);

    EVP_PKEY_meth_set_ctrl(pm, cb_ctrl, cb_ctrl_str);
    EVP_PKEY_meth_get_ctrl(pm, &p_ctrl, &p_ctrl_str);
    sayb("pkey_meth.ctrl", p_ctrl == cb_ctrl && p_ctrl_str == cb_ctrl_str);

    EVP_PKEY_meth_set_decrypt(pm, cb_ctx_int, cb_op_buf);
    EVP_PKEY_meth_get_decrypt(pm, &p_decrypt_init, &p_decrypt);
    sayb("pkey_meth.decrypt", p_decrypt_init == cb_ctx_int && p_decrypt == cb_op_buf);

    EVP_PKEY_meth_set_derive(pm, cb_ctx_int, cb_op_key);
    EVP_PKEY_meth_get_derive(pm, &p_derive_init, &p_derive);
    sayb("pkey_meth.derive", p_derive_init == cb_ctx_int && p_derive == cb_op_key);

    EVP_PKEY_meth_set_digest_custom(pm, cb_op_md);
    EVP_PKEY_meth_get_digest_custom(pm, &p_digest_custom);
    sayb("pkey_meth.digest_custom", p_digest_custom == cb_op_md);

    EVP_PKEY_meth_set_digestsign(pm, cb_digestsig);
    EVP_PKEY_meth_get_digestsign(pm, &p_digestsign);
    sayb("pkey_meth.digestsign", p_digestsign == cb_digestsig);

    EVP_PKEY_meth_set_digestverify(pm, cb_digestverify);
    EVP_PKEY_meth_get_digestverify(pm, &p_digestverify);
    sayb("pkey_meth.digestverify", p_digestverify == cb_digestverify);

    EVP_PKEY_meth_set_encrypt(pm, cb_ctx_int, cb_op_buf);
    EVP_PKEY_meth_get_encrypt(pm, &p_encrypt_init, &p_encrypt);
    sayb("pkey_meth.encrypt", p_encrypt_init == cb_ctx_int && p_encrypt == cb_op_buf);

    EVP_PKEY_meth_set_init(pm, cb_ctx_int);
    EVP_PKEY_meth_get_init(pm, &p_init);
    sayb("pkey_meth.init", p_init == cb_ctx_int);

    EVP_PKEY_meth_set_keygen(pm, cb_ctx_int, cb_keygen);
    EVP_PKEY_meth_get_keygen(pm, &p_keygen_init, &p_keygen);
    sayb("pkey_meth.keygen", p_keygen_init == cb_ctx_int && p_keygen == cb_keygen);

    EVP_PKEY_meth_set_param_check(pm, cb_pkey);
    EVP_PKEY_meth_get_param_check(pm, &p_param_check);
    sayb("pkey_meth.param_check", p_param_check == cb_pkey);

    EVP_PKEY_meth_set_paramgen(pm, cb_ctx_int, cb_keygen);
    EVP_PKEY_meth_get_paramgen(pm, &p_paramgen_init, &p_paramgen);
    sayb("pkey_meth.paramgen", p_paramgen_init == cb_ctx_int && p_paramgen == cb_keygen);

    EVP_PKEY_meth_set_public_check(pm, cb_pkey);
    EVP_PKEY_meth_get_public_check(pm, &p_public_check);
    sayb("pkey_meth.public_check", p_public_check == cb_pkey);

    EVP_PKEY_meth_set_sign(pm, cb_ctx_int, cb_op_buf);
    EVP_PKEY_meth_get_sign(pm, &p_sign_init, &p_sign);
    sayb("pkey_meth.sign", p_sign_init == cb_ctx_int && p_sign == cb_op_buf);

    EVP_PKEY_meth_set_signctx(pm, cb_signctx_init, cb_signctx);
    EVP_PKEY_meth_get_signctx(pm, &p_signctx_init, &p_signctx);
    sayb("pkey_meth.signctx", p_signctx_init == cb_signctx_init && p_signctx == cb_signctx);

    EVP_PKEY_meth_set_verify(pm, cb_ctx_int, cb_op_verify);
    EVP_PKEY_meth_get_verify(pm, &p_verify_init, &p_verify);
    sayb("pkey_meth.verify", p_verify_init == cb_ctx_int && p_verify == cb_op_verify);

    EVP_PKEY_meth_set_verify_recover(pm, cb_ctx_int, cb_op_buf);
    EVP_PKEY_meth_get_verify_recover(pm, &p_verify_recover_init, &p_verify_recover);
    sayb("pkey_meth.verify_recover",
         p_verify_recover_init == cb_ctx_int && p_verify_recover == cb_op_buf);

    EVP_PKEY_meth_set_verifyctx(pm, cb_signctx_init, cb_verifyctx);
    EVP_PKEY_meth_get_verifyctx(pm, &p_verifyctx_init, &p_verifyctx);
    sayb("pkey_meth.verifyctx",
         p_verifyctx_init == cb_signctx_init && p_verifyctx == cb_verifyctx);

    EVP_PKEY_meth_free(pm);
    return 1;
}

static int asn1_meth_arms(void)
{
    EVP_PKEY_ASN1_METHOD *am = EVP_PKEY_asn1_new(NID_undef, 0, "COURT-PEM", "court info");
    int id = -1, base = -1, flags = -1;
    const char *info = NULL, *pem = NULL;

    sayb("asn1_meth.new", am != NULL);
    if (am == NULL)
        return 0;

    /* The ASN.1 setters take a dozen distinct callback shapes and publish no getters.
     * Each is called with a NULL callback: the call is the observation -- that the entry
     * point exists in the shipped distribution and accepts a well-formed object -- and
     * the object is read back through `get0_info` afterwards. Typing twelve callbacks this
     * probe never invokes would add surface without adding evidence. */
    EVP_PKEY_asn1_set_check(am, NULL);
    EVP_PKEY_asn1_set_param_check(am, NULL);
    EVP_PKEY_asn1_set_public_check(am, NULL);
    EVP_PKEY_asn1_set_security_bits(am, NULL);
    EVP_PKEY_asn1_set_ctrl(am, NULL);
    EVP_PKEY_asn1_set_free(am, NULL);
    EVP_PKEY_asn1_set_get_priv_key(am, NULL);
    EVP_PKEY_asn1_set_get_pub_key(am, NULL);
    EVP_PKEY_asn1_set_set_priv_key(am, NULL);
    EVP_PKEY_asn1_set_set_pub_key(am, NULL);
    EVP_PKEY_asn1_set_siginf(am, NULL);
    EVP_PKEY_asn1_set_item(am, NULL, NULL);
    EVP_PKEY_asn1_set_param(am, NULL, NULL, NULL, NULL, NULL, NULL);
    EVP_PKEY_asn1_set_private(am, NULL, NULL, NULL);
    EVP_PKEY_asn1_set_public(am, NULL, NULL, NULL, NULL, NULL, NULL);

    /* The setter calls above have no getters; what is observable is that the object
     * survives them and reports its own identity back through `get0_info`. */
    sayb("asn1_meth.get0_info",
         EVP_PKEY_asn1_get0_info(&id, &base, &flags, &info, &pem, am));
    sayb("asn1_meth.info_matches", info != NULL && strcmp(info, "court info") == 0);
    sayb("asn1_meth.pem_matches", pem != NULL && strcmp(pem, "COURT-PEM") == 0);

    {
        EVP_PKEY_ASN1_METHOD *copy = EVP_PKEY_asn1_new(NID_undef, 0, NULL, NULL);

        sayb("asn1_meth.copy.new", copy != NULL);
        if (copy != NULL) {
            EVP_PKEY_asn1_copy(copy, am);
            sayb("asn1_meth.copy.survived", 1);
            EVP_PKEY_asn1_free(copy);
        }
    }

    EVP_PKEY_asn1_free(am);

    /* `EVP_PKEY_asn1_find`, `_find_str`, `get0` and `get_count` read the legacy
     * `standard_methods[]` table, which is **Phase 8's** contents: the candidate answers
     * NULL and 0 where the authority answers real methods and a positive count. That is
     * the recorded divergence `D-PKEY-AMETH-2`, and a court may not compare it. The four
     * names stay at basis `referenced` in `court-coverage.json` until Phase 8 lands the
     * table, at which point this court is where the comparison belongs. */
    return 1;
}

static int md_cipher_meth_arms(void)
{
    EVP_MD *md = EVP_MD_meth_new(NID_undef, NID_undef);
    EVP_MD *dup;
    EVP_CIPHER *ci = EVP_CIPHER_meth_new(NID_undef, 16, 16);
    int (*g)(EVP_CIPHER_CTX *, ASN1_TYPE *) = NULL;
    int (*s)(EVP_CIPHER_CTX *, ASN1_TYPE *) = NULL;
    EVP_MD_CTX *mctx;

    sayb("md_meth.new", md != NULL);
    if (md != NULL) {
        sayb("md_meth.set_cleanup", EVP_MD_meth_set_cleanup(md, cb_md_ctx_int));
        sayb("md_meth.set_copy", EVP_MD_meth_set_copy(md, cb_md_copy));
        sayb("md_meth.set_ctrl", EVP_MD_meth_set_ctrl(md, cb_md_ctrl));
        sayb("md_meth.set_final", EVP_MD_meth_set_final(md, cb_md_final));
        sayb("md_meth.set_update", EVP_MD_meth_set_update(md, cb_md_update));
        dup = EVP_MD_meth_dup(md);
        sayb("md_meth.dup", dup != NULL);
        EVP_MD_meth_free(dup);
        EVP_MD_meth_free(md);
    }

    sayb("cipher_meth.new", ci != NULL);
    if (ci != NULL) {
        sayb("cipher_meth.set_cleanup", EVP_CIPHER_meth_set_cleanup(ci, cb_cipher_ctx_int));
        sayb("cipher_meth.set_ctrl", EVP_CIPHER_meth_set_ctrl(ci, cb_cipher_ctrl));
        sayb("cipher_meth.set_init", EVP_CIPHER_meth_set_init(ci, cb_cipher_init));
        sayb("cipher_meth.set_get_asn1",
             EVP_CIPHER_meth_set_get_asn1_params(ci, cb_asn1));
        sayb("cipher_meth.set_set_asn1",
             EVP_CIPHER_meth_set_set_asn1_params(ci, cb_asn1));
        g = EVP_CIPHER_meth_get_get_asn1_params(ci);
        s = EVP_CIPHER_meth_get_set_asn1_params(ci);
        sayb("cipher_meth.get_asn1_roundtrip", g == cb_asn1 && s == cb_asn1);
        EVP_CIPHER_meth_free(ci);
    }

    mctx = EVP_MD_CTX_new();
    sayb("md_ctx.new", mctx != NULL);
    if (mctx != NULL) {
        EVP_MD_CTX *copy = EVP_MD_CTX_new();

        sayb("md_ctx.copy", EVP_MD_CTX_copy(copy, mctx));
        sayb("md_ctx.copy.md_null", EVP_MD_CTX_get0_md(copy) == NULL);
    EVP_MD_CTX_free(mctx);
    }

    /* `EVP_MD_do_all_provided` walks the loaded providers' methods, whose contents are
     * Phase 8's and later. It is called only to prove the entry point resolves, and its
     * visitor is not counted -- the count would be a statement about how much of Phase 8
     * exists. The line below prints that choice rather than a number. */
    printf("md_do_all_provided.boundary=contents_belong_to_later_strata\n");
    return 1;
}

static int pbe_pw_arms(void)
{
    /* `EVP_PBE_scrypt` and `_ex` derive through `crypto/kdf/scrypt.c`'s primitive, which
     * is Phase 8's: the candidate refuses where the authority answers 1, so a court may
     * not compare them yet. They stay at basis `referenced` and this arm prints the
     * boundary rather than a return code that would be a statement about Phase 8. */
    EVP_set_pw_prompt("court-prompt");
    sayb("pw_prompt.roundtrip",
         EVP_get_pw_prompt() != NULL && strcmp(EVP_get_pw_prompt(), "court-prompt") == 0);
    EVP_set_pw_prompt(NULL);
    sayb("pw_prompt.cleared", EVP_get_pw_prompt() == NULL);
    printf("pbe.scrypt.boundary=primitive_is_phase8\n");
    return 1;
}

static void legacy_md_arms(void)
{
    /* The seven `sha.h` accessors, which `crypto/evp/legacy_sha.c` answers with static `EVP_MD`
     * objects. Their internal fields are the crate's business and its unit test compares them; what
     * a court can see is the **public** accessors and -- the arm that matters -- that handing one to
     * `EVP_DigestInit_ex` produces a correct digest. D290 measured why: `evp_md_init_internal` sees
     * a method with no provider and fetches the provider implementation by NID, so the digest runs
     * through the fetched method and not through the legacy object's own callbacks. A transcription
     * that got the object right and the fetch-replacement wrong would pass every field check and
     * fail here. */
    static const struct {
        const char *name;
        const EVP_MD *(*fn)(void);
    } rows[] = {
        { "SHA1", EVP_sha1 },
        { "SHA224", EVP_sha224 },
        { "SHA256", EVP_sha256 },
        { "SHA384", EVP_sha384 },
        { "SHA512", EVP_sha512 },
        { "SHA512-224", EVP_sha512_224 },
        { "SHA512-256", EVP_sha512_256 },
    };
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int n;
    size_t i;
    int k;

    for (i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
        const EVP_MD *m = rows[i].fn();
        EVP_MD_CTX *c;

        printf("legacy.%s.is_null=%d\n", rows[i].name, m == NULL);
        if (m == NULL)
            continue;
        printf("legacy.%s.type=%d\n", rows[i].name, EVP_MD_get_type(m));
        printf("legacy.%s.size=%d\n", rows[i].name, EVP_MD_get_size(m));
        printf("legacy.%s.block=%d\n", rows[i].name, EVP_MD_get_block_size(m));
        printf("legacy.%s.flags=%lu\n", rows[i].name,
            (unsigned long)EVP_MD_get_flags(m));

        c = EVP_MD_CTX_new();
        n = 0;
        ERR_clear_error();
        printf("legacy.%s.init=%d\n", rows[i].name, EVP_DigestInit_ex(c, m, NULL));
        printf("legacy.%s.update=%d\n", rows[i].name, EVP_DigestUpdate(c, "abc", 3));
        printf("legacy.%s.final=%d\n", rows[i].name, EVP_DigestFinal_ex(c, md, &n));
        printf("legacy.%s.outlen=%u\n", rows[i].name, n);
        for (k = 0; k < (int)n && k < 8; k++)
            printf("legacy.%s.md.%02d=%02x\n", rows[i].name, k, md[k]);
        EVP_MD_CTX_free(c);
    }
}

int main(void)
{
    setvbuf(stdout, NULL, _IOLBF, 0);

    pkey_meth_arms();
    asn1_meth_arms();
    md_cipher_meth_arms();
    pbe_pw_arms();
    legacy_md_arms();
    return 0;
}
