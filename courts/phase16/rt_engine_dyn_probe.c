/*
 * RT-ENGINE-DYN — the dynamic ENGINE loader, as subphase 16.2 lands it.
 *
 * Compiled twice (authority and candidate), run, and the two transcripts compared
 * line by line. The probe drives `ENGINE_by_id` — 13.1's export — over the loader
 * 16.2 lands (`crypto/engine/eng_dyn.c`):
 *
 *   * the NULL-id refusal, before anything is registered;
 *   * `OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_DYNAMIC, NULL)`, the bit whose
 *     `ossl_init_engine_dynamic` step runs `engine_load_dynamic_int` and registers
 *     the `dynamic` engine. Both sides accept the bit and answer 1;
 *   * the `dynamic` engine id and name read back through `ENGINE_by_id`, and that a
 *     second lookup answers a second (non-NULL) object — the engine carries
 *     `ENGINE_FLAGS_BY_ID_COPY`, so `ENGINE_by_id` answers a *copy* each time;
 *   * the dynamic fallback itself: `ENGINE_by_id("<absent>")` misses the list, is
 *     not the id `"dynamic"`, recurses into `ENGINE_by_id("dynamic")` and drives it
 *     with `ENGINE_ctrl_cmd_string` (`ID`, `DIR_LOAD=2`, `DIR_ADD`, `LIST_ADD=1`,
 *     `LOAD`). `OPENSSL_ENGINES` is pointed at a fixed directory with no matching
 *     shared object, so the loader's `LOAD` refuses and the lookup answers NULL on
 *     both sides — the same `notfound` arm the authority takes;
 *   * the empty-id refusal.
 *
 * No wall clock, no network, no address, and no error-queue read (`ERR_*` is never
 * called, so the two sides' differing error implementations cannot leak into the
 * comparison).
 *
 * ## What this court does not drive, and why
 *
 * A *real* `.so` load is not driven. The candidate's distribution shell installs a
 * provider module (`ossl-modules/legacy.so`) but no *engine* module, and the
 * authority's `lib/engines-3/` (`capi`, `afalg`, `padlock`, `loader_attic`) has no
 * counterpart there; a load of any of them would compare the authority's module set
 * against an absent one. A purpose-built fixture engine `.so` (an
 * `IMPLEMENT_DYNAMIC_BIND_FN` library linked against each side's own `libcrypto`)
 * is reproducible in principle, but the distribution's *engine module* contract is
 * the `filesystem` unit the plan assigns to 16.4, so it is not fabricated here. What
 * the court does drive is the loader's whole control path down to the refusing
 * `DSO_load`, which is the same code a successful load runs to that point.
 *
 * The `rdrand` id is deliberately not observed: it is
 * `crypto/engine/eng_rdrand.c`'s `engine_load_rdrand_int`, a separate unit
 * `src/engine/mod.rs` still withholds, and `ENGINE_load_builtin_engines`'s
 * `ALL_BUILTIN` mask (which names it) still trips the refused engine bits. The plan
 * row names `rdrand` because that mask reaches it, not because `eng_dyn.c` registers
 * it.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/engine.h>

static void out_int(const char *key, int value)
{
    printf("%s=%d\n", key, value);
}

static void out_str(const char *key, const char *value)
{
    printf("%s=%s\n", key, value != NULL ? value : "(null)");
}

int main(void)
{
    ENGINE *d, *d2;

    setvbuf(stdout, NULL, _IOLBF, 0);

    /* A fixed, object-free directory, so the fallback's `LOAD` refuses on both sides. */
    setenv("OPENSSL_ENGINES", "/nonexistent/rt16-engines", 1);

    /* --- the NULL-id refusal, before any registration --- */
    out_int("by_id.null_nonnull", ENGINE_by_id(NULL) != NULL);

    /* --- the DYNAMIC bit registers the `dynamic` engine on both sides --- */
    printf("init.dynamic.ret=%ld\n",
           (long) OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_DYNAMIC, NULL));

    d = ENGINE_by_id("dynamic");
    out_int("by_id.dynamic_nonnull", d != NULL);
    out_str("by_id.dynamic_id", d != NULL ? ENGINE_get_id(d) : NULL);
    out_str("by_id.dynamic_name", d != NULL ? ENGINE_get_name(d) : NULL);
    d2 = ENGINE_by_id("dynamic");
    out_int("by_id.dynamic_second_nonnull", d2 != NULL);
    if (d != NULL)
        ENGINE_free(d);
    if (d2 != NULL)
        ENGINE_free(d2);

    /* --- the dynamic fallback: a miss that drives the loader to a refusing LOAD --- */
    out_int("fallback.absent_nonnull", ENGINE_by_id("rt16-absent") != NULL);
    out_int("fallback.absent2_nonnull", ENGINE_by_id("rt16-eng") != NULL);
    out_int("by_id.empty_nonnull", ENGINE_by_id("") != NULL);

    printf("done=1\n");
    return 0;
}
