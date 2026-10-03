/*
 * openssl-rs — the `ucontext_t` fibre primitives, kept on the C side of the ABI.
 *
 * Why this file exists
 * --------------------
 * `crypto/async/arch/async_posix.h` builds its `async_fibre` around the
 * platform's `ucontext_t`, reads and writes `uc_stack.ss_sp`, `uc_stack.ss_size`
 * and `uc_link`, and switches stacks with `getcontext`/`makecontext`/
 * `swapcontext`. The layout of `ucontext_t` is the platform's business — glibc
 * and musl disagree even on the field order — so, exactly as
 * `src/runtime/dir_posix.c` does for `struct dirent` and `struct stat`, the
 * struct is touched here, by the same header the authority compiled against, and
 * only the operations cross into Rust.
 *
 * No behaviour lives here. The stack size, the alloc/free functions the caller
 * may substitute through `ASYNC_set_mem_functions`, and the escalation policy on
 * a failed switch are decided in `src/async/arch/async_posix.rs`; this file only
 * attaches the stack the Rust side allocated and performs the lift calls.
 *
 * The authority's `async_fibre_swapcontext` has a `setjmp`/`longjmp` path and a
 * `swapcontext` path selected by `USE_SWAPCONTEXT`. This shim uses
 * `swapcontext` unconditionally, which is one of the authority's own two
 * configurations and preserves the same observable fibre state on the admitted
 * platforms.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stddef.h>
#include <ucontext.h>

/*
 * The opaque storage size and alignment. Rust allocates this many bytes from its
 * own allocator with `CRYPTO_zalloc` and passes the pointer back; the alignment
 * is reported rather than assumed so that no field offset or alignment is baked
 * into the Rust source.
 */
size_t openssl_rs_ucontext_size(void)
{
    return sizeof(ucontext_t);
}

size_t openssl_rs_ucontext_align(void)
{
    return _Alignof(ucontext_t);
}

/* `int getcontext(ucontext_t *ucp)` — zero on success, nonzero on failure. */
int openssl_rs_ucontext_getcontext(void *ctx)
{
    return getcontext((ucontext_t *)ctx);
}

/*
 * `async_fibre_makecontext`'s platform half, after the Rust side has captured the
 * context with `openssl_rs_ucontext_getcontext` and allocated the stack: attach
 * the caller's stack and set the entry point. No `getcontext` here, because the
 * authority's `async_fibre_makecontext` captures the context once, before the
 * stack allocator runs.
 */
int openssl_rs_ucontext_set_stack(void *ctx, void (*start)(void),
    void *stack, size_t size)
{
    ucontext_t *uc = (ucontext_t *)ctx;

    uc->uc_stack.ss_sp = stack;
    uc->uc_stack.ss_size = size;
    uc->uc_stack.ss_flags = 0;
    uc->uc_link = NULL;
    makecontext(uc, start, 0);
    return 1;
}

/*
 * `async_fibre_swapcontext`'s platform half on the `swapcontext` arm. Returns 1
 * on success and 0 on failure, matching the authority's helper.
 */
int openssl_rs_ucontext_swapcontext(void *old_ctx, void *new_ctx)
{
    return swapcontext((ucontext_t *)old_ctx, (ucontext_t *)new_ctx) == 0;
}

/* `fibre->fibre.uc_stack.ss_sp`, so Rust can hand it to its `stack_free_impl`. */
void *openssl_rs_ucontext_stack(void *ctx)
{
    return ((ucontext_t *)ctx)->uc_stack.ss_sp;
}

/* The `ASYNC_is_capable` probe: `getcontext(&ctx) == 0`. */
int openssl_rs_ucontext_capable(void)
{
    ucontext_t ctx;

    return getcontext(&ctx) == 0;
}
