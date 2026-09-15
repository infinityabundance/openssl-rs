/*
 * openssl-rs — discovery probe: what the authority's COMP surface actually is in
 * *this* build profile.
 *
 * The Phase 4 obligation ledger found fourteen `COMP_*` exports assigned to this
 * stratum by `comp.h` that no ledger had ever accounted for. Before deciding
 * whether they can be implemented here, the decisive question is what the
 * authority's own build does with them: `crypto/comp/c_zlib.c`,
 * `c_zstd.c` and `c_brotli.c` each guard their whole body with
 * `#ifndef OPENSSL_NO_ZLIB` / `_ZSTD` / `_BROTLI`, and the profile configure
 * options record `no-zlib no-brotli no-zstd`. If those guards are in force, the
 * three factory functions answer NULL and the remaining eleven symbols are pure
 * object handling with no compression library involved.
 *
 * This probe answers that from the binary rather than from reading the guards.
 * It is a *discovery* probe, not a court: its transcript is the evidence its
 * findings are recorded against. See docs/DECISIONS.md.
 *
 * Nothing here is a candidate test; run it with forensics/tools/run_probe.sh.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>
#include <openssl/comp.h>
#include <openssl/objects.h>

int main(void)
{
    setvbuf(stdout, NULL, _IOLBF, 0);

#ifdef OPENSSL_NO_ZLIB
    printf("macro OPENSSL_NO_ZLIB=1\n");
#else
    printf("macro OPENSSL_NO_ZLIB=0\n");
#endif
#ifdef OPENSSL_NO_ZSTD
    printf("macro OPENSSL_NO_ZSTD=1\n");
#else
    printf("macro OPENSSL_NO_ZSTD=0\n");
#endif
#ifdef OPENSSL_NO_BROTLI
    printf("macro OPENSSL_NO_BROTLI=1\n");
#else
    printf("macro OPENSSL_NO_BROTLI=0\n");
#endif

    {
        COMP_METHOD *zlib_m = COMP_zlib();
        COMP_METHOD *zlib_o = COMP_zlib_oneshot();
        COMP_METHOD *zstd_m = COMP_zstd();
        COMP_METHOD *zstd_o = COMP_zstd_oneshot();
        COMP_METHOD *br_m = COMP_brotli();
        COMP_METHOD *br_o = COMP_brotli_oneshot();

        printf("COMP_zlib=%p\n", (void *)zlib_m);
        printf("COMP_zlib_oneshot=%p\n", (void *)zlib_o);
        printf("COMP_zstd=%p\n", (void *)zstd_m);
        printf("COMP_zstd_oneshot=%p\n", (void *)zstd_o);
        printf("COMP_brotli=%p\n", (void *)br_m);
        printf("COMP_brotli_oneshot=%p\n", (void *)br_o);
    }

    /* The NULL-argument contract of every accessor, which is the surface a
     * court can compare without any compression library present. */
    printf("COMP_get_type(NULL)=%d (NID_undef=%d)\n",
           COMP_get_type(NULL), NID_undef);
    printf("COMP_get_name(NULL)=%s\n",
           COMP_get_name(NULL) == NULL ? "<NULL>" : COMP_get_name(NULL));
    printf("COMP_CTX_new(NULL)=%p\n", (void *)COMP_CTX_new(NULL));

    /* `COMP_CTX_get_type(NULL)` is **not called**. The authority dereferences
     * `comp->meth` with no NULL check:
     *
     *     int COMP_CTX_get_type(const COMP_CTX *comp)
     *     { return comp->meth ? comp->meth->type : NID_undef; }
     *
     * so a NULL argument faults. Measured: the first run of this probe reached
     * this line and died with SIGSEGV (exit 139) before printing `done=1`.
     * That is an authority memory fault, not behaviour: it is recorded in
     * docs/SECURITY_DIVERGENCE_POLICY.md and deliberately NOT reproduced.
     * The candidate answers NID_undef, which is the value the authority's own
     * expression yields for every non-NULL ctx whose method is NULL.
     */
    printf("COMP_CTX_get_type(NULL)=<authority faults: SIGSEGV; not called>\n");

    {
        COMP_METHOD *m = COMP_zlib();
        COMP_CTX *ctx = COMP_CTX_new(m);

        printf("COMP_CTX_new(COMP_zlib())=%p\n", (void *)ctx);
        if (ctx != NULL) {
            const COMP_METHOD *back = COMP_CTX_get_method(ctx);
            printf("COMP_CTX_get_method(ctx)=%p same=%d\n", (void *)back,
                   back == m);
            printf("COMP_CTX_get_type(ctx)=%d\n", COMP_CTX_get_type(ctx));
            {
                unsigned char out[64];
                unsigned char in[16] = "0123456789abcdef";
                int r = COMP_compress_block(ctx, out, (int)sizeof(out), in,
                                            (int)sizeof(in));
                printf("COMP_compress_block=%d\n", r);
                r = COMP_expand_block(ctx, out, (int)sizeof(out), in,
                                      (int)sizeof(in));
                printf("COMP_expand_block=%d\n", r);
            }
            COMP_CTX_free(ctx);
        }
    }

    COMP_CTX_free(NULL);
    printf("COMP_CTX_free(NULL)=ok\n");

    printf("done=1\n");
    return 0;
}
