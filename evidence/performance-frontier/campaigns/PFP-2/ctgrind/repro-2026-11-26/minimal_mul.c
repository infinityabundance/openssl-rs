/* Minimal ctgrind population for the P-256 ladder.
 *
 * One EC_POINT_mul of the generator by a 253-bit scalar.  Only the scalar's
 * limb *values* are tainted; the four-limb width is established and checked
 * against the defined value first, matching the recorded sign test's
 * taint_magnitude (d.as_ptr(), d.len()*8) and leaving the length defined.
 *
 * usage: minimal_mul [defined|taint-value|taint-bytes]
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <valgrind/memcheck.h>
#include <dlfcn.h>

/* The crate's BigNum is repr(Rust); on this target the compiler lays it out as
 * neg, flags, then Vec<u64> whose element pointer is at byte offset 8.  The
 * harness does not trust the length field: it knows the scalar has four limbs
 * and verifies all four limbs against the defined big-endian input.  A layout
 * drift therefore aborts (exit 13) instead of tainting the wrong bytes. */
#define BN_D_PTR_OFFSET 8
#define LIMBS 4

/* Determine the number of live limbs from the defined big-endian value and
 * return the limb pointer only if every one of those limbs matches. */
static uint64_t *limbs_checked(const BIGNUM *bn, size_t *out_limbs)
{
    unsigned char be[32];
    uint64_t *p;
    size_t first = 0, lim, i;
    if (BN_bn2binpad(bn, be, 32) != 32)
        return NULL;
    while (first < 32 && be[first] == 0)
        first++;
    if (first == 32)
        return NULL;
    lim = (32 - first + 7) / 8;
    memcpy(&p, (const unsigned char *)bn + BN_D_PTR_OFFSET, sizeof p);
    if (p == NULL || lim > LIMBS)
        return NULL;
    for (i = 0; i < lim; i++) {
        uint64_t limb = p[i];
        for (int j = 0; j < 8; j++) {
            size_t k = 32 - 1 - (i * 8 + (size_t)j);
            if (be[k] != (unsigned char)((limb >> (8 * j)) & 0xff))
                return NULL;
        }
    }
    *out_limbs = lim;
    return p;
}

static uint64_t *limbs_of(const BIGNUM *bn, const unsigned char *be, size_t n)
{
    uint64_t *p;
    memcpy(&p, (const unsigned char *)bn + BN_D_PTR_OFFSET, sizeof p);
    if (p == NULL)
        return NULL;
    for (int i = 0; i < LIMBS; i++) {
        uint64_t limb = p[i];
        for (int j = 0; j < 8; j++) {
            size_t k = n - 1 - ((size_t)i * 8 + (size_t)j);
            unsigned char expect = (unsigned char)((limb >> (8 * j)) & 0xff);
            if (be[k] != expect)
                return NULL;
        }
    }
    return p;
}

int main(int argc, char **argv)
{
    const char *mode = (argc > 1) ? argv[1] : "taint-value";
    unsigned char buf[32];
    EC_GROUP *group;
    const EC_POINT *gen;
    EC_POINT *r;
    BN_CTX *ctx;
    BIGNUM *k;
    int i;

    buf[0] = 0x11;
    for (i = 1; i < 32; i++)
        buf[i] = (unsigned char)(0x20 + i);

    group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if (group == NULL) return 10;
    gen = EC_GROUP_get0_generator(group);
    r = EC_POINT_new(group);
    ctx = BN_CTX_new();
    if (gen == NULL || r == NULL || ctx == NULL) return 11;

    k = BN_bin2bn(buf, (int)sizeof buf, NULL);
    if (k == NULL) return 12;

    if (strcmp(mode, "taint-value") == 0) {
        uint64_t *p = limbs_of(k, buf, sizeof buf);
        if (p == NULL) return 13; /* layout drifted; do not guess */
        VALGRIND_MAKE_MEM_UNDEFINED(p, LIMBS * sizeof(uint64_t));
    } else if (strcmp(mode, "sign-defined") == 0 || strcmp(mode, "sign-taint") == 0) {
        unsigned char dgst[32];
        EC_KEY *ec;
        const BIGNUM *priv;
        size_t lim = 0;
        uint64_t *p;
        ECDSA_SIG *sig;
        memset(dgst, 0x5a, sizeof dgst);
        BN_free(k);
        BN_CTX_free(ctx);
        EC_POINT_free(r);
        EC_GROUP_free(group);
        ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        if (ec == NULL) return 14;
        if (EC_KEY_generate_key(ec) != 1) return 15;
        priv = EC_KEY_get0_private_key(ec);
        if (priv == NULL) return 16;
        p = limbs_checked(priv, &lim);
        if (p == NULL) return 17;
        if (strcmp(mode, "sign-taint") == 0)
            VALGRIND_MAKE_MEM_UNDEFINED(p, lim * sizeof(uint64_t));
        sig = ECDSA_do_sign(dgst, (int)sizeof dgst, ec);
        if (sig != NULL)
            ECDSA_SIG_free(sig);
        EC_KEY_free(ec);
        { Dl_info di; if (dladdr((void *)&EC_POINT_mul, &di)) fprintf(stderr, "dso_base=%p\n", di.dli_fbase); }
        return sig == NULL ? 18 : 0;
    } else if (strcmp(mode, "taint-bytes") == 0) {
        /* Comparison population: re-import from undefined bytes, which also
         * taints the limb count the importer derives. */
        BN_free(k);
        VALGRIND_MAKE_MEM_UNDEFINED(buf, sizeof buf);
        k = BN_bin2bn(buf, (int)sizeof buf, NULL);
        if (k == NULL) return 12;
    }

    (void)EC_POINT_mul(group, r, NULL, gen, k, ctx);

    BN_free(k);
    BN_CTX_free(ctx);
    EC_POINT_free(r);
    EC_GROUP_free(group);
    { Dl_info di; if (dladdr((void *)&EC_POINT_mul, &di)) fprintf(stderr, "dso_base=%p\n", di.dli_fbase); }
    return 0;
}
