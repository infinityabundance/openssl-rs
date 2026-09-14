/*
 * openssl-rs — Phase 4 BIO: C-variadic adapters for the printf surface.
 *
 * WHY THIS FILE EXISTS AND WHY IT IS NOT AN IMPLEMENTATION BACKEND
 * ---------------------------------------------------------------
 * BIO_printf, BIO_vprintf, BIO_snprintf and BIO_vsnprintf are C-variadic
 * functions of the public ABI. Stable Rust cannot *define* a C-variadic
 * function, so the entry points must be written in something that can. That is
 * the entire content of this file: argument marshalling and vsnprintf.
 *
 * All behaviour lives in Rust. The formatted result is handed to the crate's own
 * BIO_write, so the callback protocol, the `init` gate, the byte accounting and
 * the error queue are all decided by src/runtime/bio/iolib.rs. Nothing here
 * decides BIO state or formatting policy beyond what vsnprintf provides.
 *
 * This is an ABI-boundary necessity, in the same category as src/runtime/
 * err_variadic.c, and it is not a cryptographic or compatibility backend.
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct bio_st BIO;

/* Provided by src/runtime/bio/iolib.rs. */
extern int BIO_write(BIO *b, const void *data, int dlen);

/*
 * int BIO_vprintf(BIO *bio, const char *format, va_list args)
 *
 * Formats into a heap buffer sized from a first (NULL, 0) pass, writes the whole
 * result in one BIO_write, and reports the number of characters written or -1.
 */
int BIO_vprintf(BIO *bio, const char *format, va_list args)
{
    va_list copy;
    int len, ret;
    char *buf;

    if (format == NULL)
        return -1;

    va_copy(copy, args);
    len = vsnprintf(NULL, 0, format, copy);
    va_end(copy);
    if (len < 0)
        return -1;

    buf = malloc((size_t)len + 1);
    if (buf == NULL)
        return -1;

    vsnprintf(buf, (size_t)len + 1, format, args);
    ret = BIO_write(bio, buf, len);
    free(buf);

    return ret <= 0 ? -1 : len;
}

/*
 * int BIO_printf(BIO *bio, const char *format, ...)
 */
int BIO_printf(BIO *bio, const char *format, ...)
{
    va_list args;
    int ret;

    va_start(args, format);
    ret = BIO_vprintf(bio, format, args);
    va_end(args);
    return ret;
}

/*
 * int BIO_vsnprintf(char *buf, size_t n, const char *format, va_list args)
 *
 * The authority formats into the caller's buffer with a bounded implementation.
 * vsnprintf(3) has the same observable contract for the conversions the public
 * documentation guarantees, and the RT-BIO probe compares both implementations
 * over the conversions it exercises, so a divergence would be a residual rather
 * than a silent difference.
 */
int BIO_vsnprintf(char *buf, size_t n, const char *format, va_list args)
{
    int ret;

    if (format == NULL)
        return -1;

    ret = vsnprintf(buf, n, format, args);
    if (ret < 0)
        return -1;
    return ret;
}

/*
 * int BIO_snprintf(char *buf, size_t n, const char *format, ...)
 */
int BIO_snprintf(char *buf, size_t n, const char *format, ...)
{
    va_list args;
    int ret;

    va_start(args, format);
    ret = BIO_vsnprintf(buf, n, format, args);
    va_end(args);
    return ret;
}
