/*
 * openssl-rs — Phase 3 core runtime: C-variadic adapters for the ERR surface.
 *
 * WHY THIS FILE EXISTS AND WHY IT IS NOT AN IMPLEMENTATION BACKEND
 * ---------------------------------------------------------------
 * ERR_set_error, ERR_add_error_data and ERR_add_error_vdata are printf-style
 * variadic C functions. Rust cannot *define* a C-variadic function on stable
 * (the `c_variadic` feature is unstable), so the ABI entry points must be
 * written in something that can. That is almost the entire content of this file:
 * argument marshalling, and the buffer dance `ERR_vset_error` performs around the
 * variadic call.
 *
 * The formatting engine is NOT chosen here. It is `BIO_vsnprintf` — this crate's
 * own `_dopr`, reached exactly as the authority reaches it. That matters for the
 * bytes a caller reads back through `ERR_get_error_all`: `_dopr` renders `%s` of
 * NULL as `<NULL>` and `%p` of NULL as `0`, and libc's `vsnprintf` renders neither.
 * An earlier revision of this file called libc's `vsnprintf` directly and would
 * have produced `(null)` for the `group=%s name=%s` message the CONF reader
 * raises when the *name* is NULL. Nothing here decides library codes, reasons,
 * queue state or marks.
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
extern void openssl_rs_err_add_data(const char *msg);
extern char *openssl_rs_err_take_data(size_t *size);
extern void openssl_rs_err_finish_data(int lib, int reason, char *data,
    size_t size, int flags);

/* Provided by src/runtime/bio/bio_variadic.c — the authority's own printf. */
extern int BIO_vsnprintf(char *buf, size_t n, const char *format, va_list ap);

/* Provided by src/runtime/mem.rs: the allocator the ERR queue owns data with. */
extern void *CRYPTO_realloc(void *addr, size_t num, const char *file, int line);
extern void CRYPTO_free(void *ptr, const char *file, int line);

/*
 * `ERR_MAX_DATA_SIZE` from openssl/err.h.in. It is written out here rather than
 * included: this file must not acquire a dependency on any installed OpenSSL
 * headers, which is both an implementation-backend risk and a source of
 * machine-dependent compilation.
 */
#define ERR_MAX_DATA_SIZE 1024

/* `ERR_TXT_MALLOCED | ERR_TXT_STRING`, the flags the queue stores data under. */
#define ERR_TXT_MALLOCED 0x01
#define ERR_TXT_STRING 0x02

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
 *
 * The body mirrors `crypto/err/err_blocks.c` step for step, because the steps are
 * observable:
 *
 *   1. the slot's existing buffer is *detached* (reserved for reuse) rather than
 *      cleared, so a slot that already carried data reuses its allocation;
 *   2. the buffer is grown to `ERR_MAX_DATA_SIZE` if it is smaller;
 *   3. the message is formatted by `BIO_vsnprintf` — this crate's `_dopr`, not
 *      libc — which is what makes `%s` of NULL render as `<NULL>`;
 *   4. a negative (truncated) length is coerced to 0, which is why an over-long
 *      message becomes an *empty* string rather than a truncated one;
 *   5. the buffer is shrunk to the printed length plus its terminator.
 *
 * Only the queue's state changes (steps 1, and the final store) live in Rust.
 */
void ERR_vset_error(int lib, int reason, const char *fmt, va_list args)
{
    char *buf = NULL;
    size_t buf_size = 0;
    char *rbuf = NULL;
    int printed_len = 0;
    int flags = 0;

    if (fmt != NULL) {
        buf = openssl_rs_err_take_data(&buf_size);

        if (buf_size < ERR_MAX_DATA_SIZE
            && (rbuf = CRYPTO_realloc(buf, ERR_MAX_DATA_SIZE, NULL, 0)) != NULL) {
            buf = rbuf;
            buf_size = ERR_MAX_DATA_SIZE;
        }

        if (buf != NULL)
            printed_len = BIO_vsnprintf(buf, buf_size, fmt, args);
        if (printed_len < 0)
            printed_len = 0;
        if (buf != NULL)
            buf[printed_len] = '\0';

        if ((rbuf = CRYPTO_realloc(buf, (size_t)printed_len + 1, NULL, 0)) != NULL) {
            buf = rbuf;
            buf_size = (size_t)printed_len + 1;
            buf[printed_len] = '\0';
        }

        if (buf != NULL)
            flags = ERR_TXT_MALLOCED | ERR_TXT_STRING;
    }

    openssl_rs_err_finish_data(lib, reason, buf, buf_size, flags);
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
