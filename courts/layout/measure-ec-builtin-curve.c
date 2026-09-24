// Layout measurement for `EC_builtin_curve`, the one ABI structure 8.7's first slice exposes.
//
// `EC_get_builtin_curves`'s whole contract is that it writes `min(nitems, 82)` of these into a
// **caller-allocated** array -- `EC_builtin_curve r[82]` on a caller's stack is the documented
// idiom -- so both its size and its member offsets are part of the ABI: a crate whose `nid` sat at
// 8 instead of 0 would leave a caller's first `int` untouched and write four bytes of padding
// before its `comment` pointer, which no value comparison in a probe can see because the probe
// would be reading the same wrong layout back.
//
// The declaration cannot settle it. `include/openssl/ec.h:537-540` is
//
//     typedef struct {
//         int nid;
//         const char *comment;
//     } EC_builtin_curve;
//
// and the four bytes at 4..8 are padding, whose presence is decided by the compiler and the
// profile's pointer width rather than by the text. So the only honest source is a program that
// asks the authority's own compiler, which is this one.
//
// See `courts/layout/README.md` for the include set and the build line.
#include <stdio.h>
#include <stddef.h>

#include <openssl/ec.h>

#define SHOW(T) printf("sizeof(%-24s) = %zu\n", #T, sizeof(T))
#define ALIGN(T) printf("alignof(%-23s) = %zu\n", #T, _Alignof(T))
#define OFF(T, m) printf("offsetof(%-16s, %-15s) = %zu\n", #T, #m, offsetof(T, m))

int main(void)
{
    SHOW(EC_builtin_curve);
    ALIGN(EC_builtin_curve);
    OFF(EC_builtin_curve, nid);
    OFF(EC_builtin_curve, comment);
    return 0;
}
