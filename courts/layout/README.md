# Layout measurement programs

These are **not courts**. They are one-off measuring programs compiled against the pinned
authority's own internal headers, and they exist because a handful of things the crate must match
cannot be read off a declaration with any confidence:

* the size of an object the provider allocates, which is what an application's
  `CRYPTO_set_mem_functions` allocator receives as `num`;
* the offsets of the members a hw function casts a `PROV_CIPHER_CTX *` back onto;
* the *values* two functions return, where the observable is buried several layers below any API a
  court can reach; and
* the **`file` string** every provider row hands a caller-installed allocator — a documented part of
  `CRYPTO_set_mem_functions`'s contract that no earlier program here had ever asked about.

All four are contract, and all four are decided by the authority's compiler and its own table
initialisers rather than by its text, so the only honest source is to compile a program that asks and
print the answers. `src/provider/cipher.rs`'s size test carries the numbers these programs produced;
the programs are committed so a reviewer can reproduce them instead of trusting the prose.

## The oracle programs, and why they are not merely measurements

Three of the programs here are the same idea pointed at something other than a layout.

`oracle-polyval.c` asks for **values**. The authority's `ossl_polyval_ghash_init` and
`ossl_polyval_ghash_hash` have external linkage but are absent from the shared object's dynamic
symbol table, so they are reachable only by linking the **static** archive — which is what this
program does, and which is why its three answers are the only direct observation of the byte-order
bridging `src/provider/cipher.rs` makes for POLYVAL. Through the provider that bridge can only be
seen through a whole AES-GCM-SIV record, where a wrong byte order and a wrong multiply look
identical. `the_polyval_helpers_match_the_authority_oracle` pins the three values; two of the three
`gswap8` calls that bridge needs were found by running it.

`oracle-chacha20-poly1305-hw.c` asks what **the compiler actually built** from a brace-elided
initialiser. `cipher_chacha20_poly1305_hw.c` writes

```c
static const PROV_CIPHER_HW_CHACHA20_POLY1305 chacha20poly1305_hw = {
    { chacha20_poly1305_initkey, NULL },     /* { init, cipher, copyctx } */
    chacha20_poly1305_aead_cipher, ...
};
```

and the inner brace supplies `PROV_CIPHER_HW`'s first two members, so `base.cipher` is a **null
function pointer** — unlike every other cipher row this crate transcribes, whose `base.cipher` is
the mode's own entry point. The program links `ossl_prov_cipher_hw_chacha20_poly1305()` out of the
static archive and prints all three base members plus the extended vtable's four offsets and their
distinctness. The Rust type that carries the null is `Chacha20Poly1305HwBase`, and the unit test
`the_chacha20_poly1305_context_is_the_authoritys_size` asserts both nulls rather than describing
them.

`oracle-mem-file.c` asks an **observable** question rather than a value or a layout. This one links
the **shared** object, because its subject is the provider's own allocation traffic: it installs
`CRYPTO_set_mem_functions` before anything else runs and reports every distinct `file` string the
authority passes, per row. That is what settled which translation unit each row's allocations belong
to — `providers/implementations/ciphers/cipher_aes.c` and not the shared `ciphercommon.c` the crate's
single `FILE` constant named; `providers/implementations/ciphers/cipher_chacha20_poly1305.c` with
**no** `../../src/openssl-3.6.4/` prefix because it is a `.c.in` template the build generates into the
build tree, where its source-tree sibling `cipher_chacha20.c` carries the prefix. It is also the
program that shows `ciphercommon.c` **never appears at all**, which is what makes the crate's older
shared constant wrong for every one of its call sites rather than only for the generated rows.

They live here rather than in `court/` because `court/` is scratch material that `.gitignore`
excludes, and a `docs/DECISIONS.md` entry that cites a file a reviewer cannot open is not evidence.
`courts/layout/` is outside every probe glob — `probe_hygiene.py`'s subjects are
`courts/phase<N>/*_probe.c` and nothing else — so these are never mistaken for courts.

## Running them

The include set is the production build's generated headers plus the pinned source tree's internal
headers, and the `fips` include is needed because `prov/securitycheck.h` reaches
`fips/fipsindicator.h`:

```sh
B=forensics/authorities/build/openssl-3.6.4-production
S=forensics/authorities/src/openssl-3.6.4
clang -std=c11 \
  -I "$B/include" -I "$B" \
  -I "$B/providers/implementations/include" -I "$B/providers/common/include" \
  -I "$S" -I "$S/crypto" -I "$S/include" \
  -I "$S/providers/implementations/include" -I "$S/providers/common/include" \
  -I "$S/providers/implementations/ciphers" -I "$S/providers/fips/include" \
  -o /tmp/measure courts/layout/measure-provider-ctxs.c && /tmp/measure
```

The programs whose subject is a `crypto/<type>/<type>_local.h` header need one more `-I`, the
directory the header itself lives in, because the authority includes it as `"ec_local.h"`:

```sh
clang -std=c11 -I "$B/include" -I "$B" -I "$S" -I "$S/crypto" -I "$S/crypto/ec" \
  -o /tmp/measure-ec courts/layout/measure-ec.c && /tmp/measure-ec
```

`measure-dh.c` and `measure-dsa.c` are the same shape with `-I "$S/crypto/dh"` and
`-I "$S/crypto/dsa"` in place of the last one.

The two static-archive oracles add the archive in place of a `-l` flag, because their subjects are
internal functions with no dynamic symbol:

```sh
clang -std=c11 <the include set above> -o /tmp/oracle \
  courts/layout/oracle-chacha20-poly1305-hw.c "$B/libcrypto.a" -lpthread -ldl
```

`oracle-mem-file.c` goes the other way and needs only the **installed prefix**, since it drives the
provider through the public API:

```sh
P=forensics/authorities/prefix/openssl-3.6.4-production
clang -std=c11 -o /tmp/oracle courts/layout/oracle-mem-file.c \
  -I "$P/include" -L "$P/lib" -lcrypto -Wl,-rpath,"$P/lib"
```

`crypto/modes.h` is unguarded and is already pulled in by `prov/ciphercommon.h`, so a program must
not include it a second time.

## What each one answers

| program | question | answers recorded in |
| --- | --- | --- |
| `measure-chacha-ctx.c` | `PROV_CHACHA20_CTX` and `PROV_CIPHER_HW_CHACHA20` | D264 |
| `measure-chacha20-poly1305-ctx.c` | `PROV_CHACHA20_POLY1305_CTX` (848 bytes, twelve member offsets) and `PROV_CIPHER_HW_CHACHA20_POLY1305` | D279 |
| `measure-union-align.c` | the key structs (`AES_KEY`, `CAMELLIA_KEY`, `SM4_KEY`, `ARIA_KEY`) and the context each makes | D269 |
| `measure-provider-ctxs.c` | every landed cipher context's size and its `ks` offsets | D269 |
| `measure-mode-ctxs.c` | the embedded mode contexts (`XTS128_CONTEXT`, `OCB128_CONTEXT`, `PROV_CCM_CTX`, `siv128_context`) and the `PROV_AES_OCB_CTX`/`PROV_AES_CCM_CTX`/`PROV_AES_XTS_CTX` member offsets | D269 |
| `measure-sm4-xts-ctx.c` | `PROV_SM4_XTS_CTX` and its five member offsets. A **separate program** from `measure-provider-ctxs.c`, because `cipher_sm4_xts.h` and `cipher_aes_xts.h` each generate an `OSSL_xts_stream_fn` through `PROV_CIPHER_FUNC` with different key types under one name, so the two headers cannot be included in one translation unit | D273 |
| `measure-rsa-ctx.c` | `RSA` (**216** bytes, twenty-three member offsets), `RSA_METHOD` (**120**, fifteen offsets) and `RSA_PSS_PARAMS_30` (**20**). The object's layout is **profile-dependent** -- its `pss`/`prime_infos`/`ex_data` block is `#ifndef FIPS_MODULE` -- so only the compiler can say which this profile produces | D283 |
| `measure-ffc-params.c` | `FFC_PARAMS` (**96** bytes, fourteen member offsets), the object `struct dh_st` and `struct dsa_st` each embed **by value**, so its size is downstream of both constructors' allocation sizes. The offset that cannot be read off the declaration is `mdname` at **72**, not 68: `flags` is a four-byte `unsigned int` at 64 and `mdname` is a pointer | D330 |
| `measure-dh.c` | `struct dh_st` (**208** bytes, sixteen member offsets) — the allocation `DH_new` makes and the object four of 8.5's units read field by field — plus `struct dh_method` beside `measure-dh-method.c` and `DH_MIN_MODULUS_BITS` (**512**). The two offsets that cannot be read off the declaration are `length` at **104** (a four-byte `int32_t`, so 108..112 is padding before `pub_key`) and `ex_data` at **152** (`references` is a four-byte `_Atomic int` at 144) | D331 |
| `measure-ec-builtin-curve.c` | `EC_builtin_curve` (**16** bytes, alignment 8, `nid` at **0** and `comment` at **8**). It is the one ABI structure 8.7's first slice exposes — `EC_get_builtin_curves` writes these into a **caller-allocated** array, so the four bytes of padding at 4..8 are the caller's contract and not the crate's private business | D334 |
| `measure-ec.c` | the seven `crypto/ec/ec_local.h` shapes: `struct ec_method_st` (**448** bytes, fifty-five callbacks), `struct ec_group_st` (**184**, `poly` at **72** and the `pre_comp` union at **160**), `struct ec_point_st` (**48**), `struct ec_key_st` (**104**, `ex_data` at **64**), `struct ec_key_method_st` (**120**, `init` at **16**), `struct ECDSA_SIG_st` and `point_conversion_form_t` (**4**), plus the seven constants (`EC_FLAGS_*`, `EC_KEY_METHOD_DYNAMIC`, the three `POINT_CONVERSION_*` and the seven `PCT_*` discriminators). Four of the six sizes are `OPENSSL_zalloc` allocations a caller's `CRYPTO_set_mem_functions` receives as `num` | D335 |
| `measure-cbc-hmac-ctxs.c` | the three `PROV_AES_HMAC_SHA*_CTX` allocations, whose `SHA_CTX` members are the reason the 256-bit row is 840 bytes | D276 |
| `oracle-polyval.c` | the authority's own POLYVAL answers, through the static archive | D278 |
| `oracle-chacha20-poly1305-hw.c` | the hw vtable's three base members (**`cipher` and `copyctx` are NULL**) and its four extended offsets | D279 |
| `oracle-mem-file.c` | the `file` string each provider row hands a `CRYPTO_set_mem_functions` allocator | D279 |

## `oracle-legacy-sha.c` — what `EVP_sha1()` is, and how a contradiction was resolved

The legacy digest method objects (`crypto/evp/legacy_sha.c`'s seven static `EVP_MD` values, and
`EVP_md5`) are the unblock for the RSA OAEP and PSS default digests, and they look like the easiest
thing in the tree: `EVP_sha1()` is `return &sha1_md;`, one line, no allocation, no fetch.

They are not, because the initialiser contradicts itself. `LEGACY_EVP_MD_METH_TABLE` expands to
`init, update, final, NULL, NULL, blksz, 0, ctrl`, and against `struct evp_md_st` that puts
`SHA_CBLOCK` in `block_size` and **zero in `ctx_size`** — while `evp_md_init_internal` allocates the
context's `md_data` only when `ctx_size` is non-zero, and `EVP_MD_CTX_get0_md_data` is a bare
`return ctx->md_data;`. A zero `ctx_size` should therefore make `sha1_init` call `SHA1_Init(NULL)`
and fail. This oracle measures what actually happens.

Build and run against the installed prefix:

```
clang -std=c11 -O1 -DNDEBUG -I "$B/include" -o /tmp/oracle-legacy-sha \
  courts/layout/oracle-legacy-sha.c -L "$B/lib" -lcrypto -Wl,-rpath,"$B/lib"
/tmp/oracle-legacy-sha
```

It answers `init_ok=1`, `final_ok=1` and the published `SHA1("abc")` = `a9993e36 4706816a ba3e2571
7850c26c 9cd0d89d`, so the legacy method is fully functional and the reading above is wrong
*somewhere*. `EVP_MD_get_ctx_size` is not an exported symbol, so the field itself cannot be read
through the public surface; the field was read through a local replica of `struct evp_md_st` whose
offsets the oracle prints, and the contradiction was settled from the authority's source. See
`docs/DECISIONS.md` D289 for the measurements and D290 for the resolution.

**The resolution, so a reader of this file need not chase it: a legacy method is never used to
digest.** `evp_md_init_internal` (`crypto/evp/digest.c:258-280`) checks `type->prov == NULL` and, for
such a method, **fetches the provider implementation by `OBJ_nid2sn(type->type)` and rebinds `type`
to it** before `ctx->digest = type`. `EVP_sha1()` is therefore a carrier whose callbacks an ENGINE
may use and whose digest path the library replaces; the digest runs through the provider method's
`dinit`/`dupdate`/`dfinal` on `ctx->algctx`, so `ctx_size` 0 and a NULL `md_data` are correct and
irrelevant. The one fact that looked impossible — `SHA1_Init` called with a non-NULL argument — is
the **provider** method's own `sha1_init` calling it, which an interposer cannot distinguish from
the legacy callback's call. That ambiguity is the file's own lesson: measuring a symbol does not
measure which caller reached it.
