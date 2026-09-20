// Layout measurement for the `DH` object and its method table.
//
// `struct dh_st` (`crypto/dh/dh_local.h:16-41`) is the allocation `DH_new` makes, so its size is
// what an application's `CRYPTO_set_mem_functions` allocator receives as `num` — and its `params`
// member embeds `FFC_PARAMS` **by value**, so its size is downstream of that object's 96 bytes
// (`measure-ffc-params.c`). The object is also read field-by-field across four translation units
// this stratum transcribes (`dh_lib.c`, `dh_key.c`, `dh_gen.c`, `dh_check.c`), so a member placed
// at the wrong offset is a wrong read in one of them rather than a compile error.
//
// The two offsets that cannot be reasoned about from the declaration are the two after the
// embedded `params`: `int32_t length` sits at 96 and `BIGNUM *pub_key` is eight-aligned, so the
// four bytes at 100..104 are padding; and `CRYPTO_REF_COUNT references` is a four-byte
// `_Atomic int` at 144, so `CRYPTO_EX_DATA ex_data` — a pointer-pair-bearing struct — is
// eight-aligned at 152 and `flags` at 128 is followed by four padding bytes before
// `BN_MONT_CTX *method_mont_p` at 136. The `#ifndef FIPS_MODULE` block is compiled on this
// profile, so `ex_data` and `engine` are present.
//
// `struct dh_method` is measured here too, beside `measure-dh-method.c`, because the two objects
// interact: `dh_new_intern` computes `ret->meth->flags` through the table, and a table whose
// `flags` moved would move every later member.
//
// See `courts/layout/README.md` for the include set.
#include <stdio.h>
#include <stddef.h>

#include <openssl/engine.h>
#include "dh_local.h"

#define SHOW(T) printf("sizeof(%-31s) = %zu\n", #T, sizeof(T))
#define ALIGN(T) printf("alignof(%-30s) = %zu\n", #T, _Alignof(T))
#define OFF(T, m) printf("offsetof(%-23s, %-24s) = %zu\n", #T, #m, offsetof(T, m))

int main(void)
{
    SHOW(struct dh_st);
    ALIGN(struct dh_st);
    OFF(struct dh_st, pad);
    OFF(struct dh_st, version);
    OFF(struct dh_st, params);
    OFF(struct dh_st, length);
    OFF(struct dh_st, pub_key);
    OFF(struct dh_st, priv_key);
    OFF(struct dh_st, flags);
    OFF(struct dh_st, method_mont_p);
    OFF(struct dh_st, references);
    OFF(struct dh_st, ex_data);
    OFF(struct dh_st, engine);
    OFF(struct dh_st, libctx);
    OFF(struct dh_st, meth);
    OFF(struct dh_st, lock);
    OFF(struct dh_st, dirty_cnt);
    printf("DH_MIN_MODULUS_BITS = %d\n", DH_MIN_MODULUS_BITS);
    return 0;
}
