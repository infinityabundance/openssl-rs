// Layout measurement for `FFC_PARAMS`, the DH and DSA domain-parameter object.
//
// `struct dh_st` embeds `FFC_PARAMS` **by value** (`crypto/dh/dh_local.h:23`) and `struct dsa_st`
// does the same, so this size is downstream of both objects' allocation sizes — which is what an
// application's `CRYPTO_set_mem_functions` allocator receives as `num` when `DH_new` or
// `DSA_new` runs. `ossl_ffc_params_init` also `memset`s `sizeof(*params)`, so a struct one member
// too wide would write past its own object.
//
// The offset that cannot be reasoned about from the declaration is `mdname`: `flags` is a
// four-byte `unsigned int` at 64 and `mdname` is a pointer, so the four bytes at 68..72 are
// padding and `mdname` sits at 72 rather than at 68. The width of `int` is the profile's, so only
// the compiler can say it. `src/ffc/mod.rs`'s test
// `the_ffc_params_struct_is_the_authoritys_shape` asserts every number this prints.
//
// See `courts/layout/README.md` for the include set.
#include <stdio.h>
#include <stddef.h>

#include "internal/ffc.h"

#define SHOW(T) printf("sizeof(%-31s) = %zu\n", #T, sizeof(T))
#define ALIGN(T) printf("alignof(%-30s) = %zu\n", #T, _Alignof(T))
#define OFF(T, m) printf("offsetof(%-23s, %-24s) = %zu\n", #T, #m, offsetof(T, m))

int main(void)
{
    SHOW(FFC_PARAMS);
    ALIGN(FFC_PARAMS);
    OFF(FFC_PARAMS, p);
    OFF(FFC_PARAMS, q);
    OFF(FFC_PARAMS, g);
    OFF(FFC_PARAMS, j);
    OFF(FFC_PARAMS, seed);
    OFF(FFC_PARAMS, seedlen);
    OFF(FFC_PARAMS, pcounter);
    OFF(FFC_PARAMS, nid);
    OFF(FFC_PARAMS, gindex);
    OFF(FFC_PARAMS, h);
    OFF(FFC_PARAMS, flags);
    OFF(FFC_PARAMS, mdname);
    OFF(FFC_PARAMS, mdprops);
    OFF(FFC_PARAMS, keylength);
    return 0;
}
