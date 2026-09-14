/*
 * openssl-rs — Phase 4 BIO: the C-variadic entry points of the printf surface.
 *
 * WHY THIS FILE EXISTS AND WHY IT IS NOT AN IMPLEMENTATION BACKEND
 * ---------------------------------------------------------------
 * BIO_printf, BIO_vprintf, BIO_snprintf and BIO_vsnprintf are C-variadic
 * functions of the public ABI. Stable Rust cannot *define* a C-variadic
 * function, so the entry points must be written in something that can. That is
 * the entire content of this file: it starts a va_list and hands it, with the
 * format string, to the crate's own engine.
 *
 * Formatting lives in src/runtime/bio/print_engine.rs and va_arg extraction in
 * src/runtime/bio/bio_va.c. Nothing here decides a padding rule, a radix, a
 * floating-point normalisation or a truncation result. This is an ABI-boundary
 * necessity in the same category as src/runtime/err_variadic.c, not a
 * cryptographic or compatibility backend.
 *
 * The three-argument non-variadic forms (BIO_snprintf is the only one that is
 * not variadic in its format? it is) are all variadic here; there is no
 * non-variadic form to declare.
 *
 * LICENSE: Apache-2.0, as the rest of the crate.
 */

#include <stdarg.h>
#include <stddef.h>

typedef struct bio_st BIO;

/* Provided by src/runtime/bio/print_engine.rs. */
extern int openssl_rs_dopr_vprintf(BIO *bio, const char *format, va_list args);
extern int openssl_rs_dopr_snprintf(char *buf, size_t n, const char *format,
                                    va_list args);

/*
 * int BIO_printf(BIO *bio, const char *format, ...)
 */
int BIO_printf(BIO *bio, const char *format, ...)
{
    va_list args;
    int ret;

    va_start(args, format);
    ret = openssl_rs_dopr_vprintf(bio, format, args);
    va_end(args);
    return ret;
}

/*
 * int BIO_vprintf(BIO *bio, const char *format, va_list args)
 */
int BIO_vprintf(BIO *bio, const char *format, va_list args)
{
    return openssl_rs_dopr_vprintf(bio, format, args);
}

/*
 * int BIO_snprintf(char *buf, size_t n, const char *format, ...)
 */
int BIO_snprintf(char *buf, size_t n, const char *format, ...)
{
    va_list args;
    int ret;

    va_start(args, format);
    ret = openssl_rs_dopr_snprintf(buf, n, format, args);
    va_end(args);
    return ret;
}

/*
 * int BIO_vsnprintf(char *buf, size_t n, const char *format, va_list args)
 *
 * Note that the engine reports *truncation* as failure, which is the
 * authority's behaviour and not traditional snprintf's: a caller that treats the
 * result as a length would otherwise read a short buffer as a complete one.
 */
int BIO_vsnprintf(char *buf, size_t n, const char *format, va_list args)
{
    return openssl_rs_dopr_snprintf(buf, n, format, args);
}
