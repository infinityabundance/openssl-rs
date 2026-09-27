// Layout measurement for the ENGINE object and the control-command definition —
// `struct engine_st` and `ENGINE_CMD_DEFN`.
//
// Phase 10.9 transcribes the engine registry into `src/engine/{eng_lib,eng_list}.rs`,
// stacking `struct engine_st` in a `#[repr(C)]` struct whose field offsets are asserted
// with `core::mem::offset_of!`. The declaration alone is not enough: `CRYPTO_REF_COUNT`
// is a fallback `int` here and `CRYPTO_EX_DATA` is an embedded block whose size is fixed
// by `crypto/ex_data.c`, and both decide every offset after them. `ENGINE_CMD_DEFN` is
// the one engine structure a consumer supplies and the registry reads, so its stride is
// measured too. This program compiles against the pinned authority's own internal header
// and prints the numbers the Rust asserts carry.
//
// See `courts/layout/README.md` for the include set. This program needs `-I
// "$S/crypto/engine"` because the header includes itself as `"eng_local.h"`.
#include <stdio.h>
#include <stddef.h>

#include <openssl/engine.h>
#include "crypto/engine.h"
#include "eng_local.h"

#define SHOW(T) printf("sizeof(%-29s) = %zu\n", #T, sizeof(T))
#define ALIGN(T) printf("alignof(%-28s) = %zu\n", #T, _Alignof(T))
#define OFF(T, m) printf("offsetof(%-21s, %-22s) = %zu\n", #T, #m, offsetof(T, m))

int main(void)
{
    SHOW(CRYPTO_REF_COUNT);
    SHOW(CRYPTO_EX_DATA);
    SHOW(struct engine_st);
    SHOW(ENGINE_CMD_DEFN);
    SHOW(ENGINE_CLEANUP_ITEM);

    OFF(struct engine_st, id);
    OFF(struct engine_st, name);
    OFF(struct engine_st, rsa_meth);
    OFF(struct engine_st, dsa_meth);
    OFF(struct engine_st, dh_meth);
    OFF(struct engine_st, ec_meth);
    OFF(struct engine_st, rand_meth);
    OFF(struct engine_st, ciphers);
    OFF(struct engine_st, digests);
    OFF(struct engine_st, pkey_meths);
    OFF(struct engine_st, pkey_asn1_meths);
    OFF(struct engine_st, destroy);
    OFF(struct engine_st, init);
    OFF(struct engine_st, finish);
    OFF(struct engine_st, ctrl);
    OFF(struct engine_st, load_privkey);
    OFF(struct engine_st, load_pubkey);
    OFF(struct engine_st, load_ssl_client_cert);
    OFF(struct engine_st, cmd_defns);
    OFF(struct engine_st, flags);
    OFF(struct engine_st, struct_ref);
    OFF(struct engine_st, funct_ref);
    OFF(struct engine_st, ex_data);
    OFF(struct engine_st, prev);
    OFF(struct engine_st, next);
    OFF(struct engine_st, prev_dyn);
    OFF(struct engine_st, next_dyn);
    OFF(struct engine_st, dynamic_id);

    OFF(ENGINE_CMD_DEFN, cmd_num);
    OFF(ENGINE_CMD_DEFN, cmd_name);
    OFF(ENGINE_CMD_DEFN, cmd_desc);
    OFF(ENGINE_CMD_DEFN, cmd_flags);
    return 0;
}
