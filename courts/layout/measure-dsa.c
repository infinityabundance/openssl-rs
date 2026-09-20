// Layout measurement for the `DSA` object and its method table.
//
// `dsa_new_intern` allocates `sizeof(struct dsa_st)` with `OPENSSL_zalloc`, so the size is what an
// application's `CRYPTO_set_mem_functions` allocator receives as `num`; and four of 8.6's units read
// the object field by field, including the embedded `FFC_PARAMS` whose own size
// `measure-ffc-params.c` reports. `DSA_meth_new` and `DSA_meth_dup` do the same for
// `sizeof(struct dsa_method)`, whose members each `DSA_meth_get_*`/`DSA_meth_set_*` pair reads or
// writes one at a time.
//
// Two offsets cannot be reasoned about from the declaration. In `struct dsa_st`, `flags` is a
// four-byte `int` at 120 and `method_mont_p` is a pointer, so the four bytes at 124..128 are
// padding; and `references` is a four-byte `_Atomic int`. In `struct dsa_method`, `flags` is a
// four-byte `int` after a pointer member, so the four bytes after it are padding before `app_data`.
// The width of `int` is the profile's, so only the compiler can say what follows it.
//
// See `courts/layout/README.md` for the include set.
#include <stdio.h>
#include <stddef.h>

#include "dsa_local.h"

#define SHOW(T) printf("sizeof(%-31s) = %zu\n", #T, sizeof(T))
#define ALIGN(T) printf("alignof(%-30s) = %zu\n", #T, _Alignof(T))
#define OFF(T, m) printf("offsetof(%-23s, %-24s) = %zu\n", #T, #m, offsetof(T, m))
#define VAL(x) printf("%-34s = %d\n", #x, (int)(x))

int main(void)
{
    SHOW(struct dsa_st);
    ALIGN(struct dsa_st);
    OFF(struct dsa_st, pad);
    OFF(struct dsa_st, version);
    OFF(struct dsa_st, params);
    OFF(struct dsa_st, pub_key);
    OFF(struct dsa_st, priv_key);
    OFF(struct dsa_st, flags);
    OFF(struct dsa_st, method_mont_p);
    OFF(struct dsa_st, references);
    OFF(struct dsa_st, ex_data);
    OFF(struct dsa_st, meth);
    OFF(struct dsa_st, engine);
    OFF(struct dsa_st, lock);
    OFF(struct dsa_st, libctx);
    OFF(struct dsa_st, dirty_cnt);

    SHOW(struct dsa_method);
    ALIGN(struct dsa_method);
    OFF(struct dsa_method, name);
    OFF(struct dsa_method, dsa_do_sign);
    OFF(struct dsa_method, dsa_sign_setup);
    OFF(struct dsa_method, dsa_do_verify);
    OFF(struct dsa_method, dsa_mod_exp);
    OFF(struct dsa_method, bn_mod_exp);
    OFF(struct dsa_method, init);
    OFF(struct dsa_method, finish);
    OFF(struct dsa_method, flags);
    OFF(struct dsa_method, app_data);
    OFF(struct dsa_method, dsa_paramgen);
    OFF(struct dsa_method, dsa_keygen);

    SHOW(struct DSA_SIG_st);
    ALIGN(struct DSA_SIG_st);
    OFF(struct DSA_SIG_st, r);
    OFF(struct DSA_SIG_st, s);

    VAL(DSA_FLAG_NO_EXP_CONSTTIME);
    VAL(DSA_FLAG_CACHE_MONT_P);
    VAL(DSA_FLAG_FIPS_METHOD);
    VAL(DSA_FLAG_NON_FIPS_ALLOW);
    VAL(DSA_FLAG_FIPS_CHECKED);
    VAL(OPENSSL_DSA_MAX_MODULUS_BITS);
    return 0;
}
