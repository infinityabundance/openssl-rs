// Layout measurement for the `DH` method table.
//
// `DH_meth_new` and `DH_meth_dup` allocate `sizeof(DH_METHOD)` with `OPENSSL_zalloc` /
// `OPENSSL_malloc`, so the size is what an application's `CRYPTO_set_mem_functions` allocator
// receives as `num`. The member offsets are contract twice over as well: `DH_meth_dup` copies the
// whole table with one `memcpy`, and each `DH_meth_get_*`/`DH_meth_set_*` pair reads or writes
// exactly one member, so a transcription that moved a member changes which one an accessor acts on
// without changing the size of a single allocation.
//
// The offset that cannot be reasoned about from the declaration is `app_data`: `flags` is a
// four-byte `int`, so the four bytes after it are padding and `app_data` is at 56 rather than the
// 48 a pointer-sized reading of `flags` would produce. The width of `int` is the profile's, so only
// the compiler can say it.
//
// See `courts/layout/README.md` for the include set.
#include <stdio.h>
#include <stddef.h>

#include "dh_local.h"

#define SHOW(T) printf("sizeof(%-31s) = %zu\n", #T, sizeof(T))
#define ALIGN(T) printf("alignof(%-30s) = %zu\n", #T, _Alignof(T))
#define OFF(T, m) printf("offsetof(%-23s, %-24s) = %zu\n", #T, #m, offsetof(T, m))

int main(void)
{
    SHOW(struct dh_method);
    ALIGN(struct dh_method);
    OFF(struct dh_method, name);
    OFF(struct dh_method, generate_key);
    OFF(struct dh_method, compute_key);
    OFF(struct dh_method, bn_mod_exp);
    OFF(struct dh_method, init);
    OFF(struct dh_method, finish);
    OFF(struct dh_method, flags);
    OFF(struct dh_method, app_data);
    OFF(struct dh_method, generate_params);
    return 0;
}
