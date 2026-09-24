// Layout measurement for `struct evp_pkey_st` — the `EVP_PKEY` object.
//
// Phase 7.4a modelled only the provider block and `ameth`, and recorded the legacy block —
// `engine`, `pmeth_engine`, the `pkey` / `legacy_cache_pkey` union and `attributes` — as
// deliberately absent, because `EVP_PKEY_ASN1_METHOD` was Phase 8's and `ENGINE` is Phase 13's.
// 8.8 lands the eleven `EVP_PKEY_ASN1_METHOD` objects whose callbacks read `pkey->pkey.<alg>`, so
// the block is now modelled, and this program is what says where each member sits rather than the
// declaration being read by eye.
//
// The offsets that cannot be reasoned about from the declaration are the ones the omitted members
// would have moved: `references` is a four-byte `_Atomic int`, so `lock` is eight-aligned at 56 and
// the four bytes at 52..56 are padding; `save_parameters` at 72 is followed by the four-byte storage
// of the `unsigned int foreign : 1` bitfield at 76; and `CRYPTO_EX_DATA` is the two-pointer
// `struct crypto_ex_data_st` (16 bytes), so `keymgmt` is at 96. `#ifndef FIPS_MODULE` is compiled on
// this profile, so all of the block is present.
//
// See `courts/layout/README.md` for the include set.
#include <stdio.h>
#include <stddef.h>

#include <openssl/engine.h>
#include "crypto/evp.h"

#define SHOW(T) printf("sizeof(%-31s) = %zu\n", #T, sizeof(T))
#define ALIGN(T) printf("alignof(%-30s) = %zu\n", #T, _Alignof(T))
#define OFF(T, m) printf("offsetof(%-23s, %-24s) = %zu\n", #T, #m, offsetof(T, m))

int main(void)
{
    SHOW(struct evp_pkey_st);
    ALIGN(struct evp_pkey_st);
    OFF(struct evp_pkey_st, type);
    OFF(struct evp_pkey_st, save_type);
    OFF(struct evp_pkey_st, ameth);
    OFF(struct evp_pkey_st, engine);
    OFF(struct evp_pkey_st, pmeth_engine);
    OFF(struct evp_pkey_st, pkey);
    OFF(struct evp_pkey_st, legacy_cache_pkey);
    OFF(struct evp_pkey_st, references);
    OFF(struct evp_pkey_st, lock);
    OFF(struct evp_pkey_st, attributes);
    OFF(struct evp_pkey_st, save_parameters);
    /* `foreign` is an `unsigned int : 1` bitfield, so `offsetof` cannot name it; its four-byte
     * storage sits immediately after `save_parameters` and before `ex_data`, which the next line
     * measures. */
    OFF(struct evp_pkey_st, ex_data);
    OFF(struct evp_pkey_st, keymgmt);
    OFF(struct evp_pkey_st, keydata);
    OFF(struct evp_pkey_st, dirty_cnt);
    OFF(struct evp_pkey_st, operation_cache);
    OFF(struct evp_pkey_st, dirty_cnt_copy);
    OFF(struct evp_pkey_st, cache);
    SHOW(union legacy_pkey_st);
    ALIGN(union legacy_pkey_st);
    SHOW(CRYPTO_EX_DATA);
    return 0;
}
