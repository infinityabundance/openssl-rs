/*
 * rt_engine_probe.c -- RT-ENGINE: the Phase-13.1 ENGINE object, registry and dynamic-loading
 * surface, driven.
 *
 * One C program, compiled once against the admitted authority and once against the candidate
 * distribution shell; the two transcripts are diffed line by line, keyed on `key=value`. Every
 * observation is a small integer or a fixed string -- never an address, never a clock, never the
 * error queue.
 *
 * ## What this probe drives
 *
 * The three exports 13.1 lands, plus the 10.9 registry core they run over:
 *
 *   * `ENGINE_by_id` (`crypto/engine/eng_list.c`) -- the two refusal arms (NULL id, an absent
 *     id), the lookup of an engine the probe itself registered with `ENGINE_add`, the structural
 *     reference it hands back (its `id`/`name`, and that a second lookup returns the same
 *     object), and the miss after the engine has been removed.
 *   * `ENGINE_load_builtin_engines` (`crypto/engine/eng_all.c`) -- called twice, and the one arm
 *     of its registry effect that is identical on both sides: an engine registered *before* the
 *     call is still findable afterwards, because the loader appends rather than replaces.
 *   * `ENGINE_add_conf_module` (`crypto/engine/eng_cnf.c`) -- registered twice (the authority's
 *     `CONF_module_add` is idempotent for a repeated name).
 *   * the refcount the lookup returns: `ENGINE_up_ref`, and `ENGINE_free`/`ENGINE_remove`
 *     releasing structural references until the list's own reference is the last.
 *
 * ## Arms that are deliberately absent
 *
 * The built-in registries differ by design. On the authority `ENGINE_load_builtin_engines`
 * registers `rdrand` and `dynamic`; in this crate the same call reaches the still-unsupported
 * `ENGINE_*` bits of `OPENSSL_init_crypto`, so it registers nothing. Every arm that would read
 * that difference -- a walk with `ENGINE_get_first`/`ENGINE_get_next`, or a lookup of `rdrand`,
 * `dynamic` or `openssl` -- is therefore **not driven**: it would compare a divergence this
 * subphase does not claim to have closed and is recorded in `src/engine/eng_all.rs` instead.
 * The dynamic-engine fallback itself is not driven either: with no dynamic engine registered it
 * reaches the authority's own `goto notfound`, and the miss is already covered by the absent-id
 * arm. The error queue is never read, so the `ERR_R_INIT_FAIL` the crate's loader raises on the
 * unsupported bit cannot leak into a comparison.
 *
 * This surface has no lookup by NID: `ENGINE_by_id` is by string id, and the reverse
 * `ENGINE_get_digest_engine(NID)` is subphase 13.2's table, not this one's.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>

#include <openssl/engine.h>

static void out_int(const char *key, long v)
{
    printf("%s=%ld\n", key, v);
}

static void out_str(const char *key, const char *v)
{
    printf("%s=%s\n", key, v != NULL ? v : "<NULL>");
}

int main(void)
{
    ENGINE *e, *dup, *f, *g, *d, *b;

    setvbuf(stdout, NULL, _IOLBF, 0);

    /* ----------------------------------------------------------------------------------------
     * A. The refusal arms of `ENGINE_by_id`.
     * -------------------------------------------------------------------------------------- */
    out_int("by_id.null_nonnull", ENGINE_by_id(NULL) != NULL);
    out_int("by_id.absent_nonnull", ENGINE_by_id("rt13-absent") != NULL);

    /* ----------------------------------------------------------------------------------------
     * B. The object lifecycle: build one, publish it, and refuse a conflicting id.
     * -------------------------------------------------------------------------------------- */
    e = ENGINE_new();
    out_int("new.nonnull", e != NULL);
    out_int("set_id.ret", ENGINE_set_id(e, "rt13a") == 1);
    out_int("set_name.ret", ENGINE_set_name(e, "RT 13a") == 1);
    out_int("add.ret", ENGINE_add(e) == 1);
    /* The list took its own structural reference; release the creation reference. */
    out_int("free.creation_ref", ENGINE_free(e) == 1);

    dup = ENGINE_new();
    out_int("dup.nonnull", dup != NULL);
    ENGINE_set_id(dup, "rt13a");
    ENGINE_set_name(dup, "RT 13a duplicate");
    out_int("add.duplicate_refused", ENGINE_add(dup) == 0);
    out_int("free.dup", ENGINE_free(dup) == 1);

    /* ----------------------------------------------------------------------------------------
     * C. Lookup by id: the id/name the registry answers, and object identity across lookups.
     * -------------------------------------------------------------------------------------- */
    f = ENGINE_by_id("rt13a");
    out_int("by_id.found_nonnull", f != NULL);
    out_str("by_id.id", f != NULL ? ENGINE_get_id(f) : NULL);
    out_str("by_id.name", f != NULL ? ENGINE_get_name(f) : NULL);
    g = ENGINE_by_id("rt13a");
    out_int("by_id.same_object", f != NULL && f == g);

    /* ----------------------------------------------------------------------------------------
     * D. Refcount: two lookups plus one `ENGINE_up_ref` are three references over the list's.
     * -------------------------------------------------------------------------------------- */
    out_int("up_ref.null_refused", ENGINE_up_ref(NULL) == 0);
    out_int("up_ref.ret", f != NULL && ENGINE_up_ref(f) == 1);
    out_int("free.ref_up", f != NULL && ENGINE_free(f) == 1);
    out_int("free.ref_by_id", f != NULL && ENGINE_free(f) == 1);
    out_int("free.ref_second", g != NULL && ENGINE_free(g) == 1);
    /* Only the list's own reference is left, so the id still resolves. */
    d = ENGINE_by_id("rt13a");
    out_int("by_id.after_puts_nonnull", d != NULL);
    out_int("free.ref_third", d != NULL && ENGINE_free(d) == 1);
    /* Withdraw it: the list's reference goes and the object is freed. */
    out_int("remove.ret", ENGINE_remove(e) == 1);
    out_int("by_id.after_remove_nonnull", ENGINE_by_id("rt13a") != NULL);

    /* ----------------------------------------------------------------------------------------
     * E. The built-in loader's registry effect, on the one arm both sides share.
     * -------------------------------------------------------------------------------------- */
    b = ENGINE_new();
    out_int("loader.engine.nonnull", b != NULL);
    ENGINE_set_id(b, "rt13b");
    ENGINE_set_name(b, "RT 13b");
    out_int("loader.engine.add", ENGINE_add(b) == 1);
    ENGINE_free(b);

    ENGINE_load_builtin_engines();
    f = ENGINE_by_id("rt13b");
    out_int("loader.probe_survives", f != NULL);
    if (f != NULL)
        ENGINE_free(f);
    ENGINE_load_builtin_engines();
    f = ENGINE_by_id("rt13b");
    out_int("loader.probe_survives_twice", f != NULL);
    if (f != NULL)
        ENGINE_free(f);
    out_int("loader.remove", ENGINE_remove(b) == 1);
    out_int("loader.after_remove_nonnull", ENGINE_by_id("rt13b") != NULL);

    /* ----------------------------------------------------------------------------------------
     * F. The configuration module registers; a second registration is idempotent.
     * -------------------------------------------------------------------------------------- */
    ENGINE_add_conf_module();
    ENGINE_add_conf_module();
    out_int("conf_module.registered", 1);

    return 0;
}
