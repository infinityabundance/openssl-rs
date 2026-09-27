/*
 * openssl-rs -- Phase 10 (10.5): the C-variadic entry points OSSL_STORE_ctrl and
 * OSSL_STORE_vctrl.
 *
 * WHY THIS FILE EXISTS, AND WHAT IT DECIDES
 * -----------------------------------------
 * `OSSL_STORE_ctrl(OSSL_STORE_CTX *ctx, int cmd, ...)` is C-variadic, and stable
 * Rust cannot *define* a C-variadic function. `OSSL_STORE_vctrl(OSSL_STORE_CTX
 * *ctx, int cmd, va_list args)` is its `va_list` twin, and a `va_list` can cross
 * into Rust only as an opaque pointer. So both public symbols are defined here,
 * and every behavioural decision lives in `openssl_rs_store_vctrl` in
 * `src/store/store_lib.rs`, which this file calls.
 *
 * WHY THE ARGUMENT WALK IS NOT HERE
 * ---------------------------------
 * The authority reads exactly one argument, and only conditionally:
 *
 *     fetched_loader != NULL && fetched_loader->p_set_ctx_params != NULL
 *         && cmd == OSSL_STORE_C_USE_SECMEM  ->  va_arg(args, int *)
 *
 * Every other path forwards the untouched `va_list` to the legacy loader's `ctrl`
 * callback (or ignores it). So whether the walk happens at all depends on the
 * *context*, not on `cmd` alone, and only the Rust half can decide it. The Rust
 * half therefore calls the crate's own `openssl_rs_va_gp` (src/runtime/bio/bio_va.c)
 * to pull that one general-purpose argument; this file only starts the list.
 *
 * LICENSE: Apache-2.0, as the rest of the crate.
 */

#include <stdarg.h>

/*
 * Provided by src/store/store_lib.rs. It owns the whole body: the fetched-loader
 * `set_ctx_params` arm, the legacy `ctrl` forward, and the "ignored, answer 1"
 * fallthrough. `args` is the caller's live `va_list`, opaque to Rust.
 */
extern int openssl_rs_store_vctrl(void *ctx, int cmd, va_list args);

/*
 * int OSSL_STORE_vctrl(OSSL_STORE_CTX *ctx, int cmd, va_list args)
 */
int OSSL_STORE_vctrl(void *ctx, int cmd, va_list args)
{
    return openssl_rs_store_vctrl(ctx, cmd, args);
}

/*
 * int OSSL_STORE_ctrl(OSSL_STORE_CTX *ctx, int cmd, ...)
 *
 * The authority's own body is `va_start(args, cmd); ret = OSSL_STORE_vctrl(ctx,
 * cmd, args); va_end(args); return ret;`, and so is this.
 */
int OSSL_STORE_ctrl(void *ctx, int cmd, ...)
{
    va_list args;
    int ret;

    va_start(args, cmd);
    ret = openssl_rs_store_vctrl(ctx, cmd, args);
    va_end(args);

    return ret;
}
