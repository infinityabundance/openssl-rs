/*
 * openssl-rs — Phase 3 core runtime: C-variadic adapters for the ERR surface.
 *
 * WHY THIS FILE EXISTS AND WHY IT IS NOT AN IMPLEMENTATION BACKEND
 * ---------------------------------------------------------------
 * ERR_set_error, ERR_add_error_data and ERR_add_error_vdata are printf-style
 * variadic C functions. Rust cannot *define* a C-variadic function on stable
 * (the `c_variadic` feature is unstable), so the ABI entry points must be
 * written in something that can. That is the entire content of this file:
 * argument marshalling and vsnprintf.
 *
 * All behaviour lives in Rust. Each adapter formats its arguments and calls
 * back into the Rust core (`openssl_rs_err_set_error`, `openssl_rs_err_add_data`,
 * `openssl_rs_err_add_data_va`). Nothing here decides library codes, reasons,
 * queue state, marks, or formatting policy.
 *
 * This is an ABI-boundary necessity, in the same category as the unsafe Rust
 * the boundary rules permit, and it is not a cryptographic or compatibility
 * backend of any kind.
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Provided by src/runtime/err.rs. */
extern void openssl_rs_err_set_error(int lib, int reason, const char *msg);
extern void openssl_rs_err_add_data(const char *msg);

/*
 * Render up to `num` NUL-terminated strings, concatenated, into a freshly
 * allocated buffer sized exactly to fit. The caller frees it.
 *
 * Two details here are the authority's own and are observable through
 * `ERR_get_error_data` (`crypto/err/err.c`, `ERR_add_error_vdata`):
 *
 *   * a NULL argument becomes the literal `"<NULL>"` rather than being skipped;
 *   * the result is **not** truncated -- the authority grows its buffer to fit,
 *     so a long argument reaches the queue whole.
 *
 * Both were found by the Phase 4 `RT-BIO-RESOLVE` court, in the case where
 * `BIO_get_host_ip(NULL, ip)` appends a NULL host to the resolver's error.
 *
 * Returns NULL when there is nothing to allocate, or when allocation failed.
 */
static char *join_strings(int num, va_list ap)
{
    va_list ap2;
    size_t total = 1;
    int i;
    char *buf;
    size_t used = 0;

    va_copy(ap2, ap);
    for (i = 0; i < num; i++) {
        const char *s = va_arg(ap2, const char *);
        if (s == NULL)
            s = "<NULL>";
        total += strlen(s);
    }
    va_end(ap2);

    buf = malloc(total);
    if (buf == NULL)
        return NULL;

    for (i = 0; i < num; i++) {
        const char *s = va_arg(ap, const char *);
        size_t n;

        if (s == NULL)
            s = "<NULL>";
        n = strlen(s);
        memcpy(buf + used, s, n);
        used += n;
    }
    buf[used] = '\0';
    return buf;
}

/*
 * void ERR_vset_error(int lib, int reason, const char *fmt, va_list args)
 *
 * The va_list form of ERR_set_error. The authority declares it publicly, so it
 * is an entry point in its own right rather than only a helper, and ERR_set_error
 * routes through it there too.
 */
void ERR_vset_error(int lib, int reason, const char *fmt, va_list args)
{
    char buf[1024];

    if (fmt == NULL) {
        openssl_rs_err_set_error(lib, reason, NULL);
        return;
    }

    buf[0] = '\0';
    vsnprintf(buf, sizeof(buf), fmt, args);
    openssl_rs_err_set_error(lib, reason, buf);
}

/*
 * void ERR_set_error(int lib, int reason, const char *fmt, ...)
 *
 * `fmt == NULL` means "no message", which clears any data on the slot rather
 * than being treated as an empty format string.
 */
void ERR_set_error(int lib, int reason, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    ERR_vset_error(lib, reason, fmt, ap);
    va_end(ap);
}

/*
 * void ERR_add_error_data(int num, ...)
 *
 * Concatenates `num` strings onto the current error's data field, replacing a
 * NULL argument with `"<NULL>"` and growing as needed.
 */
void ERR_add_error_data(int num, ...)
{
    va_list ap;
    char *joined;

    if (num <= 0)
        return;

    va_start(ap, num);
    joined = join_strings(num, ap);
    va_end(ap);
    if (joined == NULL)
        return;

    openssl_rs_err_add_data(joined);
    free(joined);
}

/*
 * void ERR_add_error_vdata(int num, va_list args)
 *
 * The va_list form, used by callers that already hold one. Kept here for the
 * same reason as the others: a va_list cannot cross into Rust.
 */
void ERR_add_error_vdata(int num, va_list args)
{
    char *joined;

    if (num <= 0)
        return;

    joined = join_strings(num, args);
    if (joined == NULL)
        return;

    openssl_rs_err_add_data(joined);
    free(joined);
}
