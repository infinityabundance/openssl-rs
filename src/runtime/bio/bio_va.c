/*
 * openssl-rs — Phase 4 BIO: `va_arg` extraction for the Rust format engine.
 *
 * WHY THIS FILE EXISTS AND NOTHING ELSE DOES
 * -----------------------------------------
 * `_dopr`'s behaviour lives entirely in Rust (`src/runtime/bio/print_engine.rs`).
 * What cannot live there is `va_arg`: a C-variadic function cannot be *defined*
 * in stable Rust, and `va_arg` needs the un-erased argument list of the function
 * that owns it. So this file exposes exactly two primitives — "give me the next
 * general-purpose argument" and "give me the next floating-point argument" — and
 * no formatting policy whatsoever.
 *
 * The Rust engine drives the parse and therefore decides *which* class to pull
 * for each conversion. Keeping that decision in one place is deliberate: a
 * second parser here could disagree with the engine's and silently desynchronise
 * the argument stream.
 *
 * WHY TWO CLASSES ARE ENOUGH
 * --------------------------
 * On x86-64 SysV, general-purpose and SSE arguments advance independent cursors
 * inside the `va_list`, and that is precisely the model these two accessors
 * express: pulling an integer-class argument advances only the general-purpose
 * cursor, and pulling a float advances only the floating-point cursor. An
 * argument narrower than a register is passed in a full register slot (with
 * unspecified high bits) and the engine narrows it after the fact, so reading
 * every integer-class argument at register width is exact rather than
 * approximate.
 *
 * `long double` needs no third primitive: `HAVE_LONG_DOUBLE` is undefined in the
 * admitted build, so `LDOUBLE` is `double` and `%Lf` reads the same class as
 * `%f`. If a profile with an 80-bit `long double` are ever admitted, this file
 * grows a third accessor and the engine a third modifier case — they are
 * deliberately not conflated now.
 *
 * LICENSE: Apache-2.0, as the rest of the crate.
 */

#include <stdarg.h>

/*
 * unsigned long openssl_rs_va_gp(va_list ap)
 *
 * Pulls one general-purpose argument. `va_list` as a parameter is a pointer to
 * the caller's argument tag, so `va_arg` here advances the caller's own cursor,
 * which is what makes successive pulls observe successive arguments.
 */
unsigned long openssl_rs_va_gp(va_list ap)
{
    return va_arg(ap, unsigned long);
}

/*
 * double openssl_rs_va_fp(va_list ap)
 *
 * Pulls one floating-point argument, advancing the SSE cursor.
 */
double openssl_rs_va_fp(va_list ap)
{
    return va_arg(ap, double);
}
