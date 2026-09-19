# Layout measurement programs

These are **not courts**. They are one-off measuring programs compiled against the pinned
authority's own internal headers, and they exist because a handful of numbers the crate must match
cannot be read off a declaration:

* the size of an object the provider allocates, which is what an application's
  `CRYPTO_set_mem_functions` allocator receives as `num`, and
* the offsets of the members a hw function casts a `PROV_CIPHER_CTX *` back onto.

Both are contract, and both are decided by the authority's compiler rather than by its text, so the
only honest source is to compile a program that asks the compiler and print the answers.
`src/provider/cipher.rs`'s size test carries the numbers these programs produced; the programs are
committed so a reviewer can reproduce them instead of trusting the prose.

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

`crypto/modes.h` is unguarded and is already pulled in by `prov/ciphercommon.h`, so a program must
not include it a second time.

## What each one answers

| program | question | answers recorded in |
| --- | --- | --- |
| `measure-chacha-ctx.c` | `PROV_CHACHA20_CTX` and `PROV_CIPHER_HW_CHACHA20` | D264 |
| `measure-union-align.c` | the key structs (`AES_KEY`, `CAMELLIA_KEY`, `SM4_KEY`, `ARIA_KEY`) and the context each makes | D269 |
| `measure-provider-ctxs.c` | every landed cipher context's size and its `ks` offsets | D269 |
| `measure-mode-ctxs.c` | the embedded mode contexts (`XTS128_CONTEXT`, `OCB128_CONTEXT`, `PROV_CCM_CTX`, `siv128_context`) and the `PROV_AES_OCB_CTX`/`PROV_AES_CCM_CTX`/`PROV_AES_XTS_CTX` member offsets | D269 |
