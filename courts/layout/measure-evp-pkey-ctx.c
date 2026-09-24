// Layout measurement for `struct evp_pkey_ctx_st` — the `EVP_PKEY_CTX` object.
//
// 7.4a modelled the provider half and the four legacy scalars (`legacy_keytype`, `pkey`, `peerkey`,
// `data`) and recorded `pmeth`, `engine` and the `flag_call_digest_custom` bit as deliberately
// absent, because `EVP_PKEY_METHOD` was Phase 8's and `ENGINE` is Phase 13's. 8.8's `EVP_PKEY_METHOD`
// slice lands them (`docs/DECISIONS.md` D355), because four callbacks read `ctx->pmeth->pkey_id` and
// `pkey_ctx_is_pss` is nothing but that read, so the block is now modelled and this program is what
// says where each member sits rather than the declaration being read by eye.
//
// **The crate's `EvpPkeyCtx` is wider than this structure on purpose**, and the difference is
// measured here rather than asserted away: the authority overlaps the five operation families in one
// `union op` and the crate flattens it (`src/evp/pkey_ctx.rs`'s module doc), so every offset below
// the union is larger in Rust by the union's width minus one pointer pair. What the crate pins
// instead is the **legacy block's internal layout** — the eight-byte deltas between
// `legacy_keytype`, `pmeth`, `engine`, `pkey`, `peerkey`, `data` and `rsa_pubexp` — and this program
// is where those numbers come from.
//
// `flag_call_digest_custom` is an `unsigned int : 1` bitfield, so `offsetof` cannot name it; its
// four-byte storage sits immediately after `data` and before `rsa_pubexp`, which the last two lines
// measure.
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
    SHOW(struct evp_pkey_ctx_st);
    ALIGN(struct evp_pkey_ctx_st);
    OFF(struct evp_pkey_ctx_st, operation);
    OFF(struct evp_pkey_ctx_st, libctx);
    OFF(struct evp_pkey_ctx_st, propquery);
    OFF(struct evp_pkey_ctx_st, keytype);
    OFF(struct evp_pkey_ctx_st, keymgmt);
    OFF(struct evp_pkey_ctx_st, op);
    OFF(struct evp_pkey_ctx_st, cached_parameters);
    OFF(struct evp_pkey_ctx_st, app_data);
    OFF(struct evp_pkey_ctx_st, pkey_gencb);
    OFF(struct evp_pkey_ctx_st, keygen_info);
    OFF(struct evp_pkey_ctx_st, keygen_info_count);
    OFF(struct evp_pkey_ctx_st, legacy_keytype);
    OFF(struct evp_pkey_ctx_st, pmeth);
    OFF(struct evp_pkey_ctx_st, engine);
    OFF(struct evp_pkey_ctx_st, pkey);
    OFF(struct evp_pkey_ctx_st, peerkey);
    OFF(struct evp_pkey_ctx_st, data);
    /* `flag_call_digest_custom` is a bitfield and cannot be named by `offsetof`; its storage sits
     * between `data` and `rsa_pubexp`. */
    OFF(struct evp_pkey_ctx_st, rsa_pubexp);
    return 0;
}
