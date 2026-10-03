/*
 * RT-SRP -- the Phase 12.8 SRP surface (`srp.h`), driven.
 *
 * One C program, compiled once against the admitted authority and once against the candidate
 * distribution, whose transcripts are diffed line by line. Every observation is a small integer, a
 * `nonnull`/`null`, a short string or a deterministic BIGNUM hex -- never an address and never a
 * wall clock, so the transcript is a function of the library and not of the probe's own frame
 * (`probe_hygiene.py` compiles it at -O0/-O1/-O2 and requires that).
 *
 * Randomness is the trap, and the probe is written around it
 * ---------------------------------------------------------
 * `SRP_create_verifier*` and `SRP_VBASE_get1_by_user` generate a random salt. The probe never
 * prints a salt or a verifier that depends on one. It prints *invariants* instead:
 *
 *   * `SRP_create_verifier_BN` is given a fixed salt, so its salt and verifier hex are a fixed
 *     function of the arithmetic, and `v == g**x mod N` is checked and printed as a boolean;
 *   * `SRP_create_verifier`'s random salt is fed straight back into `SRP_create_verifier_ex`, whose
 *     caller-salt branch must reproduce the first verifier -- a boolean, not a byte string;
 *   * a *fixed* SRP-variant base64 salt is handed to `SRP_create_verifier`, so the base64 codec
 *     (`t_fromb64`/`t_tob64`) is exercised down a deterministic path and its verifier string is a
 *     stable observable;
 *   * `SRP_VBASE_get1_by_user`'s seeded path is driven but only its non-NULL/s-non-NULL shape is
 *     printed, never `s`/`v`.
 *
 * What it drives
 * --------------
 * The seven RFC 5054 groups through `SRP_get_default_gN` (by each id and NULL) and
 * `SRP_check_known_gN_param` (each group, a wrong pair, and the two NULL refusals); the whole
 * client/server arithmetic (`SRP_Calc_A`/`_B`/`_u`/`_x`/`_server_key`/`_client_key` and their `_ex`
 * forms, whose NULL-context answers must equal the non-`_ex` ones) over fixed small BIGNUMs and the
 * 1024-bit group, plus `SRP_Verify_{A,B}_mod_N`; the `SRP_user_pwd_*` object graph; the
 * `SRP_VBASE_*` store; and the `SRP_create_verifier[_BN][_ex]` creators with their refusal arms.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/srp.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>

/* ---------------------------------------------------------------------------------------------
 * Output helpers -- every line is `key=value`. No address is ever printed.
 * --------------------------------------------------------------------------------------------- */

static void out_int(const char *key, long v)
{
    printf("%s=%ld\n", key, v);
}

static void out_nonnull(const char *key, const void *p)
{
    printf("%s=%s\n", key, p != NULL ? "nonnull" : "null");
}

/* A short deterministic string; NULL prints as `null`. */
static void out_str(const char *key, const char *s)
{
    printf("%s=%s\n", key, s != NULL ? s : "null");
}

/* A deterministic BIGNUM as uppercase hex, or `null`; the string BN_bn2hex returns is freed. */
static void out_bn(const char *key, const BIGNUM *b)
{
    char *h = b == NULL ? NULL : BN_bn2hex(b);

    printf("%s=%s\n", key, h != NULL ? h : "null");
    OPENSSL_free(h);
}

/* ---------------------------------------------------------------------------------------------
 * Fixed inputs. The SRP-variant base64 literals below were produced by the same front-padding
 * transform `t_tob64` uses (pad with zero bytes to a multiple of three, encode in the SRP
 * alphabet `0-9 A-Z a-z . /`, strip the leading `leadz` characters), so both sides decode
 * identical bytes and every downstream value is fixed.
 * --------------------------------------------------------------------------------------------- */

static const char *const rt_gN_ids[] = {
    "8192", "6144", "4096", "3072", "2048", "1536", "1024"
};

static const unsigned char rt_a[]    = { 0x01, 0x23, 0x45 };
static const unsigned char rt_b[]    = { 0x0a, 0xbc };
static const unsigned char rt_s[]    = { 0x11, 0x22, 0x33, 0x44, 0x55 };
static const unsigned char rt_v[]    = { 0x03 };
static const unsigned char rt_salt[] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
    0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14
};
static const unsigned char rt_Nexp[] = {
    0xef, 0xef, 0xef, 0xef, 0xef, 0xef, 0xef, 0xef,
    0xef, 0xef, 0xef, 0xef, 0xef, 0xef, 0xef, 0xef
};
static const unsigned char rt_gexp[] = { 0x02 };

/* `t_tob64({0x01..0x14})`, `t_tob64({0x02})` and `t_tob64({0xef x16})`. */
#define RT_FIXED_SALT_B64 "0420mG51WS82GeB30qE3n0H4XCK"
#define RT_GEXP_B64       "02"
#define RT_NEXP_B64       "3lx./lx./lx./lx./lx./l"

static BIGNUM *bn(const unsigned char *bytes, int len)
{
    return BN_bin2bn(bytes, len, NULL);
}

/* ---------------------------------------------------------------------------------------------
 * main
 * --------------------------------------------------------------------------------------------- */

int main(void)
{
    SRP_gN *gN;
    BIGNUM *g1024 = NULL, *N1024 = NULL;
    BIGNUM *g8192 = NULL, *N8192 = NULL;
    BIGNUM *a = NULL, *b = NULL, *s = NULL, *v = NULL, *A = NULL, *B = NULL;
    BIGNUM *u = NULL, *x = NULL, *S = NULL, *K = NULL;
    size_t i;

    /* --- the group table: each id and NULL, and the two accessors over it --- */
    for (i = 0; i < sizeof(rt_gN_ids) / sizeof(rt_gN_ids[0]); i++) {
        char k[64];
        const char *id = rt_gN_ids[i];

        gN = SRP_get_default_gN(id);
        snprintf(k, sizeof(k), "srp.gN.%s", id);
        out_nonnull(k, gN);
        if (gN != NULL) {
            snprintf(k, sizeof(k), "srp.gN.%s.id", id);
            out_str(k, gN->id);
            snprintf(k, sizeof(k), "srp.gN.%s.g", id);
            out_bn(k, gN->g);
            snprintf(k, sizeof(k), "srp.gN.%s.N", id);
            out_bn(k, gN->N);
            snprintf(k, sizeof(k), "srp.gN.%s.check", id);
            out_str(k, SRP_check_known_gN_param(gN->g, gN->N));
        }
        if (strcmp(id, "1024") == 0) {
            g1024 = (BIGNUM *)gN->g;
            N1024 = (BIGNUM *)gN->N;
        }
        if (strcmp(id, "8192") == 0) {
            g8192 = (BIGNUM *)gN->g;
            N8192 = (BIGNUM *)gN->N;
        }
    }

    gN = SRP_get_default_gN(NULL);
    out_nonnull("srp.gN.null", gN);
    if (gN != NULL) {
        out_str("srp.gN.null.id", gN->id);
        out_bn("srp.gN.null.g", gN->g);
        out_bn("srp.gN.null.N", gN->N);
    }
    out_nonnull("srp.gN.unknown", SRP_get_default_gN("9999"));
    out_nonnull("srp.gN.empty", SRP_get_default_gN(""));
    out_str("srp.gN.nullidx.check", SRP_check_known_gN_param(g8192, N1024));
    out_nonnull("srp.check.gnull", SRP_check_known_gN_param(NULL, N1024));
    out_nonnull("srp.check.Nnull", SRP_check_known_gN_param(g1024, NULL));

    /* --- the arithmetic over fixed small BIGNUMs and the 1024-bit group --- */
    a = bn(rt_a, sizeof(rt_a));
    b = bn(rt_b, sizeof(rt_b));
    s = bn(rt_s, sizeof(rt_s));
    v = bn(rt_v, sizeof(rt_v));

    A = SRP_Calc_A(a, N1024, g1024);
    B = SRP_Calc_B(b, N1024, g1024, v);
    u = SRP_Calc_u(A, B, N1024);
    x = SRP_Calc_x(s, "user", "password");
    S = SRP_Calc_server_key(A, v, u, b, N1024);
    K = SRP_Calc_client_key(N1024, B, g1024, x, a, u);

    out_bn("srp.calc.A", A);
    out_bn("srp.calc.B", B);
    out_bn("srp.calc.u", u);
    out_bn("srp.calc.x", x);
    out_bn("srp.calc.server_key", S);
    out_bn("srp.calc.client_key", K);

    out_int("srp.verify.A_mod_N", SRP_Verify_A_mod_N(A, N1024));
    out_int("srp.verify.B_mod_N", SRP_Verify_B_mod_N(B, N1024));
    out_int("srp.verify.N_mod_N", SRP_Verify_A_mod_N(N1024, N1024));
    out_int("srp.verify.A_null", SRP_Verify_A_mod_N(NULL, N1024));
    out_int("srp.verify.N_null", SRP_Verify_B_mod_N(B, NULL));

    /* refusal arms: a NULL argument answers NULL / 0, never a dereference */
    out_nonnull("srp.calc.A.null_a", SRP_Calc_A(NULL, N1024, g1024));
    out_nonnull("srp.calc.A.null_N", SRP_Calc_A(a, NULL, g1024));
    out_nonnull("srp.calc.A.null_g", SRP_Calc_A(a, N1024, NULL));
    out_nonnull("srp.calc.B.null_b", SRP_Calc_B(NULL, N1024, g1024, v));
    out_nonnull("srp.calc.B.null_N", SRP_Calc_B(b, NULL, g1024, v));
    out_nonnull("srp.calc.B.null_g", SRP_Calc_B(b, N1024, NULL, v));
    out_nonnull("srp.calc.B.null_v", SRP_Calc_B(b, N1024, g1024, NULL));
    /*
     * `SRP_Calc_u` has no NULL guard in the authority: it forwards to `srp_Calc_xy`, whose
     * `BN_ucmp(x, N)` dereferences the pointer, so a NULL `A`/`B`/`N` crashes the authority
     * rather than answering NULL. Those arms are omitted: a probe that dies on both sides
     * compares nothing, so the refusal set is the four functions that do guard.
     */
    out_nonnull("srp.calc.x.null_s", SRP_Calc_x(NULL, "user", "password"));
    out_nonnull("srp.calc.x.null_user", SRP_Calc_x(s, NULL, "password"));
    out_nonnull("srp.calc.x.null_pass", SRP_Calc_x(s, "user", NULL));
    out_nonnull("srp.calc.server_key.null_A", SRP_Calc_server_key(NULL, v, u, b, N1024));
    out_nonnull("srp.calc.server_key.null_v", SRP_Calc_server_key(A, NULL, u, b, N1024));
    out_nonnull("srp.calc.server_key.null_u", SRP_Calc_server_key(A, v, NULL, b, N1024));
    out_nonnull("srp.calc.server_key.null_b", SRP_Calc_server_key(A, v, u, NULL, N1024));
    out_nonnull("srp.calc.server_key.null_N", SRP_Calc_server_key(A, v, u, b, NULL));
    out_nonnull("srp.calc.client_key.null_N", SRP_Calc_client_key(NULL, B, g1024, x, a, u));
    out_nonnull("srp.calc.client_key.null_B", SRP_Calc_client_key(N1024, NULL, g1024, x, a, u));
    out_nonnull("srp.calc.client_key.null_g", SRP_Calc_client_key(N1024, B, NULL, x, a, u));
    out_nonnull("srp.calc.client_key.null_x", SRP_Calc_client_key(N1024, B, g1024, NULL, a, u));
    out_nonnull("srp.calc.client_key.null_a", SRP_Calc_client_key(N1024, B, g1024, x, NULL, u));
    out_nonnull("srp.calc.client_key.null_u", SRP_Calc_client_key(N1024, B, g1024, x, a, NULL));

    /* the `_ex` forms with a NULL library context and property query equal the plain forms */
    {
        BIGNUM *ex;

        ex = SRP_Calc_B_ex(b, N1024, g1024, v, NULL, NULL);
        out_int("srp.calc.B.ex_eq", ex != NULL && B != NULL && BN_cmp(ex, B) == 0);
        BN_free(ex);
        ex = SRP_Calc_u_ex(A, B, N1024, NULL, NULL);
        out_int("srp.calc.u.ex_eq", ex != NULL && u != NULL && BN_cmp(ex, u) == 0);
        BN_free(ex);
        ex = SRP_Calc_x_ex(s, "user", "password", NULL, NULL);
        out_int("srp.calc.x.ex_eq", ex != NULL && x != NULL && BN_cmp(ex, x) == 0);
        BN_free(ex);
        ex = SRP_Calc_client_key_ex(N1024, B, g1024, x, a, u, NULL, NULL);
        out_int("srp.calc.client_key.ex_eq", ex != NULL && K != NULL && BN_cmp(ex, K) == 0);
        BN_free(ex);
    }

    /* --- the user object graph --- */
    {
        SRP_user_pwd *pwd = SRP_user_pwd_new();

        out_nonnull("srp.user_pwd.new", pwd);
        SRP_user_pwd_set_gN(pwd, g1024, N1024);
        out_int("srp.user_pwd.set_gN.g", pwd->g == g1024);
        out_int("srp.user_pwd.set_gN.N", pwd->N == N1024);
        out_int("srp.user_pwd.set1_ids", SRP_user_pwd_set1_ids(pwd, "alice", "info-alice"));
        out_str("srp.user_pwd.id", pwd->id);
        out_str("srp.user_pwd.info", pwd->info);
        out_int("srp.user_pwd.set1_ids.noinfo", SRP_user_pwd_set1_ids(pwd, "alice", NULL));
        out_str("srp.user_pwd.info.null", pwd->info);
        out_int("srp.user_pwd.set0_sv", SRP_user_pwd_set0_sv(pwd, bn(rt_s, sizeof(rt_s)),
                                                            bn(rt_v, sizeof(rt_v))));
        out_int("srp.user_pwd.s.nonnull", pwd->s != NULL);
        out_int("srp.user_pwd.v.nonnull", pwd->v != NULL);
        out_int("srp.user_pwd.set0_sv.null", SRP_user_pwd_set0_sv(pwd, NULL, NULL));
        out_int("srp.user_pwd.s.after_null", pwd->s != NULL);
        SRP_user_pwd_free(pwd);
        SRP_user_pwd_free(NULL);
        out_int("srp.user_pwd.free_null", 1);
    }

    /* --- the verifier store --- */
    {
        SRP_VBASE *vb = SRP_VBASE_new(NULL);
        SRP_user_pwd *u_pwd = SRP_user_pwd_new();
        SRP_user_pwd *hit, *dup;

        out_nonnull("srp.vbase.new.null", vb);
        out_int("srp.vbase.new.null.seed", vb->seed_key == NULL);
        out_int("srp.vbase.new.null.users", sk_SRP_user_pwd_num(vb->users_pwd));

        SRP_user_pwd_set_gN(u_pwd, g1024, N1024);
        SRP_user_pwd_set1_ids(u_pwd, "bob", NULL);
        SRP_user_pwd_set0_sv(u_pwd, bn(rt_s, sizeof(rt_s)), bn(rt_v, sizeof(rt_v)));
        out_int("srp.vbase.add0", SRP_VBASE_add0_user(vb, u_pwd));
        out_int("srp.vbase.users", sk_SRP_user_pwd_num(vb->users_pwd));

        hit = SRP_VBASE_get_by_user(vb, "bob");
        out_nonnull("srp.vbase.get_by_user.hit", hit);
        out_str("srp.vbase.get_by_user.hit.id", hit != NULL ? hit->id : NULL);
        out_int("srp.vbase.get_by_user.hit.sv", hit != NULL && hit->s != NULL && hit->v != NULL);
        out_nonnull("srp.vbase.get_by_user.miss", SRP_VBASE_get_by_user(vb, "nobody"));
        out_nonnull("srp.vbase.get_by_user.nullvb", SRP_VBASE_get_by_user(NULL, "bob"));

        dup = SRP_VBASE_get1_by_user(vb, "bob");
        out_nonnull("srp.vbase.get1.hit", dup);
        out_str("srp.vbase.get1.hit.id", dup != NULL ? dup->id : NULL);
        out_int("srp.vbase.get1.hit.sv", dup != NULL && dup->s != NULL && dup->v != NULL);
        out_int("srp.vbase.get1.hit.dup_s",
                dup != NULL && hit != NULL && hit->s != NULL
                    && dup->s != NULL && BN_cmp(dup->s, hit->s) == 0);
        out_int("srp.vbase.get1.hit.dup_v",
                dup != NULL && hit != NULL && hit->v != NULL
                    && dup->v != NULL && BN_cmp(dup->v, hit->v) == 0);
        SRP_user_pwd_free(dup);

        out_nonnull("srp.vbase.get1.miss", SRP_VBASE_get1_by_user(vb, "nobody"));
        out_nonnull("srp.vbase.get1.nullvb", SRP_VBASE_get1_by_user(NULL, "bob"));
        SRP_VBASE_free(vb);
        SRP_VBASE_free(NULL);
        out_int("srp.vbase.free_null", 1);
    }

    {
        SRP_VBASE *vs = SRP_VBASE_new("seed");
        SRP_user_pwd *gen;

        out_nonnull("srp.vbase.new.seed", vs);
        out_str("srp.vbase.new.seed.key", vs->seed_key);
        /* with no default group resolved yet, even a seed cannot answer an unknown user */
        out_nonnull("srp.vbase.seed.get1.miss", SRP_VBASE_get1_by_user(vs, "carol"));
        vs->default_g = g1024;
        vs->default_N = N1024;
        gen = SRP_VBASE_get1_by_user(vs, "carol");
        out_nonnull("srp.vbase.seed.generated", gen);
        out_str("srp.vbase.seed.generated.id", gen != NULL ? gen->id : NULL);
        out_int("srp.vbase.seed.generated.sv",
                gen != NULL && gen->s != NULL && gen->v != NULL);
        out_int("srp.vbase.seed.generated.g", gen != NULL && gen->g == g1024);
        out_int("srp.vbase.seed.generated.N", gen != NULL && gen->N == N1024);
        SRP_user_pwd_free(gen);
        SRP_VBASE_free(vs);
    }

    /* --- the verifier creators --- */
    {
        BIGNUM *fsalt = bn(rt_salt, sizeof(rt_salt));
        BIGNUM *fver = NULL;
        BIGNUM *xchk = NULL, *gxchk = NULL;

        out_int("srp.cvbn.ret", SRP_create_verifier_BN("user", "password", &fsalt, &fver,
                                                       N1024, g1024));
        out_bn("srp.cvbn.salt", fsalt);
        out_bn("srp.cvbn.verifier", fver);
        if (fver != NULL) {
            xchk = SRP_Calc_x(fsalt, "user", "password");
            gxchk = SRP_Calc_A(xchk, N1024, g1024);
            out_int("srp.cvbn.v_matches_gx",
                    xchk != NULL && gxchk != NULL && BN_cmp(gxchk, fver) == 0);
        }
        BN_free(xchk);
        BN_free(gxchk);

        /* the `_ex` form with a NULL context equals the plain form over the same fixed salt */
        {
            BIGNUM *es = bn(rt_salt, sizeof(rt_salt));
            BIGNUM *ev = NULL;
            int r = SRP_create_verifier_BN_ex("user", "password", &es, &ev,
                                              N1024, g1024, NULL, NULL);

            out_int("srp.cvbn_ex.ret", r);
            out_int("srp.cvbn_ex.salt_eq",
                    es != NULL && fsalt != NULL && BN_cmp(es, fsalt) == 0);
            out_int("srp.cvbn_ex.ver_eq",
                    ev != NULL && fver != NULL && BN_cmp(ev, fver) == 0);
            BN_free(es);
            BN_free(ev);
        }
        BN_free(fsalt);
        BN_free(fver);

        /* NULL-argument refusals: the guard runs before any random salt is drawn */
        {
            BIGNUM *rs = NULL, *rv = NULL;

            out_int("srp.cvbn.user_null",
                    SRP_create_verifier_BN(NULL, "p", &rs, &rv, N1024, g1024));
            out_int("srp.cvbn.pass_null",
                    SRP_create_verifier_BN("u", NULL, &rs, &rv, N1024, g1024));
            out_int("srp.cvbn.salt_null",
                    SRP_create_verifier_BN("u", "p", NULL, &rv, N1024, g1024));
            out_int("srp.cvbn.ver_null",
                    SRP_create_verifier_BN("u", "p", &rs, NULL, N1024, g1024));
            out_int("srp.cvbn.N_null",
                    SRP_create_verifier_BN("u", "p", &rs, &rv, NULL, g1024));
            out_int("srp.cvbn.g_null",
                    SRP_create_verifier_BN("u", "p", &rs, &rv, N1024, NULL));
        }
    }

    {
        char *salt = NULL, *ver = NULL;
        char *id = SRP_create_verifier("user", "password", &salt, &ver, NULL, "1024");

        out_str("srp.cv.id", id);
        out_nonnull("srp.cv.salt", salt);
        out_nonnull("srp.cv.ver", ver);

        /* the returned random salt, fed back, must reproduce the very same verifier */
        {
            char *ver2 = NULL;
            char *id2 = SRP_create_verifier_ex("user", "password", &salt, &ver2,
                                               NULL, "1024", NULL, NULL);

            out_str("srp.cv.ex.id", id2);
            out_int("srp.cv.ex.ver_eq", ver != NULL && ver2 != NULL && strcmp(ver, ver2) == 0);
            OPENSSL_free(ver2);
        }

        /* a fixed salt makes the base64 codec's output a stable string observable */
        {
            char *fsalt = RT_FIXED_SALT_B64;
            char *fver = NULL;
            char *fid = SRP_create_verifier("user", "password", &fsalt, &fver, NULL, "1024");

            out_str("srp.cv.fixed.id", fid);
            out_str("srp.cv.fixed.ver", fver);
            OPENSSL_free(fver);
        }

        /* an explicit N/g pair is decoded by the same codec and reports the "*" id */
        {
            char *esalt = RT_FIXED_SALT_B64;
            char *ever = NULL;
            char *eid = SRP_create_verifier("user", "password", &esalt, &ever,
                                            RT_NEXP_B64, RT_GEXP_B64);

            out_str("srp.cv.explicit.id", eid);
            out_str("srp.cv.explicit.ver", ever);
            OPENSSL_free(ever);
        }

        /* refusal arms */
        out_nonnull("srp.cv.user_null",
                    SRP_create_verifier(NULL, "p", &salt, &ver, NULL, "1024"));
        out_nonnull("srp.cv.pass_null",
                    SRP_create_verifier("u", NULL, &salt, &ver, NULL, "1024"));
        out_nonnull("srp.cv.salt_null",
                    SRP_create_verifier("u", "p", NULL, &ver, NULL, "1024"));
        out_nonnull("srp.cv.ver_null",
                    SRP_create_verifier("u", "p", &salt, NULL, NULL, "1024"));
        out_nonnull("srp.cv.gid_unknown",
                    SRP_create_verifier("u", "p", &salt, &ver, NULL, "9999"));
        out_nonnull("srp.cv.N_empty",
                    SRP_create_verifier("u", "p", &salt, &ver, "", "1024"));
        out_nonnull("srp.cv.g_empty",
                    SRP_create_verifier("u", "p", &salt, &ver, RT_NEXP_B64, ""));

        OPENSSL_free(salt);
        OPENSSL_free(ver);
    }

    BN_free(a);
    BN_free(b);
    BN_free(s);
    BN_free(v);
    BN_free(A);
    BN_free(B);
    BN_free(u);
    BN_free(x);
    BN_free(S);
    BN_free(K);
    return 0;
}
