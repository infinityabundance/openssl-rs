/*
 * RT-PERFORMANCE-SENSITIVITY — the Phase 19.4 sensitivity court.
 *
 * Why this exists
 * ---------------
 * 19.3 measures the deterministic work a primitive path performs with an instrument the stratum
 * introduces: a counting `CRYPTO` allocator plus the method-derived geometry. An instrument can be
 * dead — wired to nothing, reading a constant, or blind to the quantity it names — and a work court
 * that compared a candidate against the authority under a dead instrument would report
 * "no divergence" for every path while proving nothing. Section 3.2 states the rule this probe
 * makes mechanical: *a control that cannot fail is not evidence*. So this court drives a
 * **deliberately slowed** variant of a measured path and requires the same work instrument that
 * 19.3 uses to catch it. If the slowed variant is not caught, the court is `fail`, not `pass`.
 *
 * Candidate-only
 * --------------
 * The slowed variant is a construction of this harness, never product code, so there is no
 * authority counterpart to drive: it is candidate-only, in the shape Phase 8's `CT-*` courts and
 * Phase 18's `CT-PRIMITIVES` use for a sensitivity control (D13, D201). The *reference* arm,
 * however, is anchored to the authority: it re-measures `aes-128-cbc` with exactly the 19.3
 * instrument and the court checks the vector equals the authority's recorded 19.3 vector, so the
 * reference measurement is the real path and not a broken instrument's answer.
 *
 * The slowed variant, and what "caught" means
 * -------------------------------------------
 * The control (`control-extra-pass`) is the reference path with an **injected extra full pass over
 * the primitive**: the same one-shot `AES-128-CBC` operation is run twice inside the measured
 * region, so the library allocates and encrypts twice. That is extra library work, injected here
 * and never in the crate. The instrument catches it when the slowed work vector differs from the
 * reference on a *library-side* key. The counting allocator's keys (`allocs`/`reallocs`/`bytes`)
 * are the work counter the stratum introduces, so the court requires the counter to move — an
 * extra pass that changed only `calls` (the driver-side invocation count, excluded from 19.3's
 * findings) would *not* be caught, and recording that boundary honestly is the point. The
 * reference must match the authority and the slowed variant must be caught on the counter, or the
 * instrument is not sensitive and the verdict is `fail` rather than a vacuous `pass`.
 *
 * No address, clock or duration is printed, so this is a deterministic work measurement and not a
 * wall-clock claim; `forensics/tools/probe_hygiene.py` sees the same transcript at `-O0`, `-O1` and
 * `-O2`. It makes no throughput claim and no benchmark-parity claim: it is evidence about the
 * *instrument's resolution*, not about the candidate's speed.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/provider.h>

/* ------------------------------------------------------------------------------------------- */
/* The instrument: the same counting `CRYPTO` allocator `RT-PERFORMANCE-WORK` installs.         */

static unsigned long long g_allocs, g_reallocs, g_bytes;
static int g_counting;

static void *work_malloc(size_t n, const char *file, int line)
{
    (void)file; (void)line;
    if (g_counting) {
        g_allocs++;
        g_bytes += (unsigned long long)n;
    }
    return malloc(n);
}

static void *work_realloc(void *p, size_t n, const char *file, int line)
{
    (void)file; (void)line;
    if (g_counting) {
        g_reallocs++;
        g_bytes += (unsigned long long)n;
    }
    return realloc(p, n);
}

static void work_free(void *p, const char *file, int line)
{
    (void)file; (void)line;
    free(p);
}

struct work {
    unsigned long long allocs, reallocs, bytes;
};

static struct work work_since(struct work base)
{
    struct work w;

    w.allocs = g_allocs - base.allocs;
    w.reallocs = g_reallocs - base.reallocs;
    w.bytes = g_bytes - base.bytes;
    return w;
}

/* The deterministic work vector one arm produced, exactly the 19.3 shape. */
struct wvec {
    int ran;
    long long in;
    long long blocks;
    long long calls;
    long long out;
    long long tag;
    long long ret;
    struct work w;
};

static void kfield(const char *arm, const char *field, int ran, long long value)
{
    char k[160];

    snprintf(k, sizeof k, "sens.%s.%s", arm, field);
    if (ran)
        printf("%s=%lld\n", k, value);
    else
        printf("%s=n/a\n", k);
}

static void emit(const char *arm, const struct wvec *v)
{
    kfield(arm, "ran", 1, v->ran);
    kfield(arm, "in", v->ran, v->in);
    kfield(arm, "blocks", v->ran, v->blocks);
    kfield(arm, "calls", v->ran, v->calls);
    kfield(arm, "out", v->ran, v->out);
    kfield(arm, "tag", v->ran, v->tag);
    kfield(arm, "allocs", v->ran, (long long)v->w.allocs);
    kfield(arm, "reallocs", v->ran, (long long)v->w.reallocs);
    kfield(arm, "bytes", v->ran, (long long)v->w.bytes);
    kfield(arm, "ret", v->ran, v->ret);
}

/* The fixed inputs the reference path is driven over: the same key, IV and plaintext 19.3 fixes,
 * so the one variation between the two arms is the injected extra pass. */
static unsigned char KEY[16];
static unsigned char IV[16];
static unsigned char IN[64];

static void init_inputs(void)
{
    int i;

    for (i = 0; i < 16; i++) {
        KEY[i] = (unsigned char)(i + 1);
        IV[i] = (unsigned char)(0xa0 + i);
    }
    for (i = 0; i < 64; i++)
        IN[i] = (unsigned char)(i * 3 + 1);
}

/* ------------------------------------------------------------------------------------------- */
/* The measured path: one one-shot AES-128-CBC encrypt, identical to 19.3's `cipher_once`.        */

static void cipher_once(struct wvec *v)
{
    EVP_CIPHER *c = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char out[256];
    int ol = 0, tl = 0, fl = 0;
    long long calls = 0, outb = 0;
    int ok = 1;

    memset(out, 0, sizeof out);

    c = EVP_CIPHER_fetch(NULL, "AES-128-CBC", NULL);
    calls++;
    if (c == NULL) { v->ran = 0; return; }
    ctx = EVP_CIPHER_CTX_new();
    calls++;
    if (ctx == NULL) { EVP_CIPHER_free(c); v->ran = 0; return; }

    if (EVP_EncryptInit_ex2(ctx, c, KEY, IV, NULL) != 1)
        ok = 0;
    calls++;
    if (ok) {
        if (EVP_EncryptUpdate(ctx, out, &ol, IN, (int)sizeof IN) != 1)
            ok = 0;
        outb += ol;
        calls++;
    }
    if (ok) {
        if (EVP_EncryptFinal_ex(ctx, out + outb, &fl) != 1)
            ok = 0;
        outb += fl;
        calls++;
    }

    v->ran = ok;
    v->in = (long long)sizeof IN;
    v->blocks = (v->in + EVP_CIPHER_get_block_size(c) - 1) /
                (EVP_CIPHER_get_block_size(c) > 0 ? EVP_CIPHER_get_block_size(c) : 1);
    v->calls = calls;
    v->out = outb;
    v->tag = -1;
    v->ret = ok;

    EVP_CIPHER_CTX_free(ctx);
    calls++;
    EVP_CIPHER_free(c);
    calls++;
    v->calls = calls;
}

/* One arm: warm once with counting off, then measure `passes` copies of the path. `passes` is 1
 * for the reference and 2 for the deliberately slowed variant -- the injected extra full pass. The
 * summed `calls`/`out` and the allocator's totals are the arm's work vector. */
static void measure_arm(int passes, struct wvec *v)
{
    struct work base;
    struct wvec warm, tmp;
    int i;

    memset(v, 0, sizeof *v);
    memset(&warm, 0, sizeof warm);
    g_counting = 0;
    cipher_once(&warm);            /* warm every lazy allocation and cache */
    base.allocs = g_allocs; base.reallocs = g_reallocs; base.bytes = g_bytes;

    g_counting = 1;
    for (i = 0; i < passes; i++) {
        memset(&tmp, 0, sizeof tmp);
        cipher_once(&tmp);
        if (!tmp.ran) {
            v->ran = 0;
            break;
        }
        v->ran = 1;
        v->in = tmp.in;
        v->blocks = tmp.blocks;
        v->calls += tmp.calls;
        v->out += tmp.out;
        v->tag = tmp.tag;
        v->ret = tmp.ret;
    }
    g_counting = 0;
    v->w = work_since(base);
}

int main(void)
{
    struct wvec reference, slowed;
    int installed;

    printf("probe.kind=performance-sensitivity\n");

    /* The instrument is installed before the library's first allocation; the shims only observe. */
    installed = CRYPTO_set_mem_functions(work_malloc, work_realloc, work_free);
    printf("work.hook.install=%d\n", installed);

    if (OSSL_PROVIDER_load(NULL, "default") == NULL)
        printf("work.default_provider=0\n");
    else
        printf("work.default_provider=1\n");

    init_inputs();

    /* The reference arm: the real measured path, exactly as 19.3 drives it. */
    printf("sens.reference.id=aes-128-cbc\n");
    measure_arm(1, &reference);
    emit("reference", &reference);

    /* The deliberately slowed arm: the same path with an injected extra full pass. Never product
     * code -- the extra work is constructed here. */
    printf("sens.slowed.id=control-extra-pass\n");
    measure_arm(2, &slowed);
    emit("slowed", &slowed);

    printf("probe.done=1\n");
    return 0;
}
