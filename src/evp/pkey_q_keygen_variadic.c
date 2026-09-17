/*
 * openssl-rs — Phase 7.4e: the C-variadic entry point `EVP_PKEY_Q_keygen`.
 *
 * WHY THIS FILE EXISTS, AND WHAT IT DECIDES
 * -----------------------------------------
 * `EVP_PKEY_Q_keygen(OSSL_LIB_CTX *libctx, const char *propq, const char *type, ...)`
 * is C-variadic, and stable Rust cannot *define* a C-variadic function. `va_arg`
 * cannot live there either, because it needs the un-erased argument list of the
 * function that owns it. So both halves are here: this file starts the list and
 * reads exactly the arguments the authority's walk reads, and nothing else.
 *
 * THE WALK IS THE AUTHORITY'S (`crypto/evp/evp_lib.c:1219`), and the whole of it
 * is which name reads what:
 *
 *     "RSA", case-insensitively   ->  one `size_t`, the modulus size
 *     "EC",  case-insensitively   ->  one `char *`, the group name
 *     anything else               ->  NOTHING is read
 *
 * That last line is the one a plausible transcription gets wrong: an `else` that
 * read a `char *` "just in case" would consume an argument the caller never
 * supplied, and the difference is observable from a caller that passes none.
 *
 * WHERE THE PARAMETER ARRAY IS BUILT
 * ----------------------------------
 * In Rust. This file cannot include `<openssl/params.h>`: `build.rs` compiles the
 * C adapters with no include path at all (see `src/runtime/bio/bio_variadic.c`,
 * which needs only `<stdarg.h>`), and a private copy of `struct ossl_param_st`
 * here would be a second definition of a public ABI type, free to drift from the
 * first. So the walk reports *which argument class it read* — `kind` — and
 * `openssl_rs_evp_pkey_q_keygen` in `src/evp/pkey.rs` builds
 * `OSSL_PKEY_PARAM_RSA_BITS` or `OSSL_PKEY_PARAM_GROUP_NAME` from it, under the
 * authority's own key. The two halves together are the authority's walk; neither
 * decides anything on its own.
 *
 * LICENSE: Apache-2.0, as the rest of the crate.
 */

#include <stdarg.h>
#include <stddef.h>

/* The crate's own implementation of the authority's case-insensitive comparison. */
extern int OPENSSL_strcasecmp(const char *a, const char *b);

/*
 * Provided by src/evp/pkey.rs. `kind` is 0 for "no argument", 1 for "one size_t of
 * bits" and 2 for "one char * group name"; `bits` and `name` are meaningful only
 * for the corresponding kind, exactly as in the authority.
 */
extern void *openssl_rs_evp_pkey_q_keygen(void *libctx, const char *propq,
                                          const char *type, int kind,
                                          size_t bits, const char *name);

/*
 * EVP_PKEY *EVP_PKEY_Q_keygen(OSSL_LIB_CTX *libctx, const char *propq,
 *                             const char *type, ...)
 */
void *EVP_PKEY_Q_keygen(void *libctx, const char *propq, const char *type, ...)
{
    va_list args;
    size_t bits = 0;
    const char *name = NULL;
    int kind = 0;
    void *ret;

    va_start(args, type);

    if (OPENSSL_strcasecmp(type, "RSA") == 0) {
        bits = va_arg(args, size_t);
        kind = 1;
    } else if (OPENSSL_strcasecmp(type, "EC") == 0) {
        name = va_arg(args, char *);
        kind = 2;
    }

    ret = openssl_rs_evp_pkey_q_keygen(libctx, propq, type, kind, bits, name);

    va_end(args);
    return ret;
}
