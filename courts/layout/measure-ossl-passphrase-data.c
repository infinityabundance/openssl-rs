// Layout measurement for `struct ossl_passphrase_data_st` — the passphrase bridge.
//
// Phase 10's encoder and decoder contexts each embed one of these at a fixed offset, so the
// struct's size and member offsets are part of the `OSSL_ENCODER_CTX` / `OSSL_DECODER_CTX` layout
// the crate must match. The struct is a C `enum` plus an anonymous-ish `union` plus a one-bit
// `unsigned int` bitfield, and the three together decide where `cached_passphrase` lands on
// x86-64 — so the offsets are asked for rather than read off the declaration.
//
// See `courts/layout/README.md` for the include set.
#include <stdio.h>
#include <stddef.h>

#include <openssl/ui.h>
#include "internal/passphrase.h"

#define SHOW(T) printf("sizeof(%-31s) = %zu\n", #T, sizeof(T))
#define ALIGN(T) printf("alignof(%-30s) = %zu\n", #T, _Alignof(T))
#define OFF(T, m) printf("offsetof(%-23s, %-24s) = %zu\n", #T, #m, offsetof(T, m))

int main(void)
{
    SHOW(struct ossl_passphrase_data_st);
    ALIGN(struct ossl_passphrase_data_st);
    OFF(struct ossl_passphrase_data_st, type);
    /* The union member has no name of its own (`_`), so `offsetof` cannot name it; it sits
     * immediately after the four-byte `type` and its sixteen-byte storage is what the next
     * pointer member proves. */
    OFF(struct ossl_passphrase_data_st, cached_passphrase);
    OFF(struct ossl_passphrase_data_st, cached_passphrase_len);
    SHOW(union { struct { char *p; size_t l; } e; struct { void *c; void *a; } q; });
    return 0;
}
