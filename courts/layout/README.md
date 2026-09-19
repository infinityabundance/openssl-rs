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
| `measure-cbc-hmac-ctxs.c` | the three `PROV_AES_HMAC_SHA*_CTX` allocations, whose `SHA_CTX` members are the reason the 256-bit row is 840 bytes | D276 |
| `oracle-polyval.c` | the authority's own POLYVAL answers, through the static archive | D278 |
| `oracle-chacha20-poly1305-hw.c` | the hw vtable's three base members (**`cipher` and `copyctx` are NULL**) and its four extended offsets | D279 |
| `oracle-mem-file.c` | the `file` string each provider row hands a `CRYPTO_set_mem_functions` allocator | D279 |
