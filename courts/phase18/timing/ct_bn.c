/*
 * ctgrind harness for BN_mod_exp_mont_consttime and BN_mod_inverse.
 *
 * Technique: build the operands normally, then mark the *secret* BIGNUM's limb
 * storage undefined (VALGRIND_MAKE_MEM_UNDEFINED) and call the primitive under
 * memcheck.  Any branch or address that depends on the secret is reported.
 *
 * Operands are exactly the Phase-18 probe's:
 *   p = 2^255 - 19, a = 5,
 *   e0 = 2^254 + 1 (Hamming weight 2), e1 = 2^255 - 1 (Hamming weight 255),
 *   inverse operands a0 = 2^200 + 1, a1 = 2^254 - 3.
 *
 * The BIGNUM layout used to reach the limbs is the one this build actually
 * exports: BN_num_bits reads the limb pointer at +0x8 and `top` at +0x10
 * (verified from the candidate disassembly), so the mirror below has the same
 * offsets.  We mark only d[0..top), leaving the pointer and top defined.
 *
 * Modes: modexp | inverse | cmpcmp | cmpnaive
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dlfcn.h>

#include <valgrind/memcheck.h>

#include <openssl/bn.h>
#include <openssl/crypto.h>

struct bn_mirror {
    char pad[8];
    BN_ULONG *d;
    int top;
};

static volatile int g_sink;

static void mark_secret(BIGNUM *b)
{
    struct bn_mirror *m = (struct bn_mirror *)b;

    VALGRIND_MAKE_MEM_UNDEFINED(m->d, (size_t)m->top * sizeof(BN_ULONG));
}

static void unmark_secret(BIGNUM *b)
{
    struct bn_mirror *m = (struct bn_mirror *)b;

    VALGRIND_MAKE_MEM_DEFINED(m->d, (size_t)m->top * sizeof(BN_ULONG));
}

static int setup_p(BIGNUM *p)
{
    /* p = 2^255 - 19 */
    return BN_one(p) && BN_lshift(p, p, 255) && BN_sub_word(p, 19);
}

static int do_modexp(void)
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *r = BN_new(), *a = BN_new(), *p = BN_new(), *e = BN_new();
    int ok = 0;

    if (ctx == NULL || r == NULL || a == NULL || p == NULL || e == NULL)
        goto out;
    if (!setup_p(p) || !BN_set_word(a, 5))
        goto out;
    /* e = 2^255 - 1 (a 255-bit exponent; value is the only secret) */
    if (!BN_one(e) || !BN_lshift(e, e, 255) || !BN_sub_word(e, 1))
        goto out;

    mark_secret(e);
    ok = BN_mod_exp_mont_consttime(r, a, e, p, ctx, NULL);
    unmark_secret(e);

out:
    BN_free(r);
    BN_free(a);
    BN_free(p);
    BN_free(e);
    BN_CTX_free(ctx);
    return ok;
}

static int do_inverse(void)
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *r = BN_new(), *p = BN_new(), *a = BN_new();
    int ok = 0;

    if (ctx == NULL || r == NULL || p == NULL || a == NULL)
        goto out;
    if (!setup_p(p))
        goto out;
    /* a = 2^254 - 3, coprime to p */
    if (!BN_one(a) || !BN_lshift(a, a, 254) || !BN_sub_word(a, 3))
        goto out;

    mark_secret(a);
    ok = BN_mod_inverse(r, a, p, ctx) != NULL;
    unmark_secret(a);

out:
    BN_free(r);
    BN_free(p);
    BN_free(a);
    BN_CTX_free(ctx);
    return ok;
}

/* Negative control: the library's constant-time comparison.  No branch or
 * address may depend on the undefined buffer. */
static int do_cmpcmp(void)
{
    unsigned char *a = NULL, *b = NULL;
    int r;

    if (posix_memalign((void **)&a, 64, 4096) != 0 ||
        posix_memalign((void **)&b, 64, 4096) != 0)
        return 0;
    memset(a, 0x5a, 4096);
    memset(b, 0x5a, 4096);
    b[4095] ^= 0x01;      /* mismatch at the last byte */
    VALGRIND_MAKE_MEM_UNDEFINED(a, 4096);
    r = CRYPTO_memcmp(a, b, 4096);
    VALGRIND_MAKE_MEM_DEFINED(a, 4096);
    g_sink = r;
    free(a);
    free(b);
    return 1;
}

/* Positive control: deliberately leaky comparison, early exit on the first
 * mismatching byte.  memcheck must report a conditional jump on the secret. */
static int do_cmpnaive(void)
{
    unsigned char *a = NULL, *b = NULL;
    volatile unsigned char acc = 0;
    int i, r = 0;

    if (posix_memalign((void **)&a, 64, 4096) != 0 ||
        posix_memalign((void **)&b, 64, 4096) != 0)
        return 0;
    memset(a, 0x5a, 4096);
    memset(b, 0x5a, 4096);
    b[4095] ^= 0x01;
    VALGRIND_MAKE_MEM_UNDEFINED(a, 4096);
    for (i = 0; i < 4096; i++) {
        if (a[i] != b[i]) {   /* branch on secret */
            r = 1;
            break;
        }
        acc = (unsigned char)(acc * 3u + b[i]);
    }
    VALGRIND_MAKE_MEM_DEFINED(a, 4096);
    g_sink = r + acc;
    free(a);
    free(b);
    return 1;
}

int main(int argc, char **argv)
{
    const char *mode = argc > 1 ? argv[1] : "";
    int ok;

    {
        Dl_info di;
        if (dladdr((void *)BN_mod_exp_mont_consttime, &di) != 0)
            fprintf(stderr, "ctgrind.base=%p consttime=%p off=%#lx\n",
                    di.dli_fbase, (void *)BN_mod_exp_mont_consttime,
                    (unsigned long)((char *)BN_mod_exp_mont_consttime -
                                    (char *)di.dli_fbase));
        if (dladdr((void *)BN_mod_inverse, &di) != 0)
            fprintf(stderr, "ctgrind.inverse=%p off=%#lx\n",
                    (void *)BN_mod_inverse,
                    (unsigned long)((char *)BN_mod_inverse -
                                    (char *)di.dli_fbase));
    }

    if (strcmp(mode, "modexp") == 0)
        ok = do_modexp();
    else if (strcmp(mode, "inverse") == 0)
        ok = do_inverse();
    else if (strcmp(mode, "cmpcmp") == 0)
        ok = do_cmpcmp();
    else if (strcmp(mode, "cmpnaive") == 0)
        ok = do_cmpnaive();
    else {
        fprintf(stderr, "usage: %s modexp|inverse|cmpcmp|cmpnaive\n", argv[0]);
        return 2;
    }
    fprintf(stderr, "ctgrind.%s.returned=%d\n", mode, ok);
    return ok ? 0 : 1;
}
