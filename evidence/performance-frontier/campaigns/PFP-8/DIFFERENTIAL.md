# PFP-8 — differential and refusal tests

**Candidate:** DSO `88c0c7e0…` (`b2cca665…`, clean `src`).
**Authority:** OpenSSL 3.6.4 production `611e511d…`.
**Harness:** `courts/performance-frontier/pfp8/bench_pfp8.c`;
**driver:** `courts/performance-frontier/pfp8/differential.py`.
**Raw record:** `raw/differential.json` (45 rows).

Groups: **RFC 7919 FFDHE-2048** (NID 1126), **RFC 7919 FFDHE-3072** (1127),
**RFC 3526 MODP-2048** (1213). The fixture bytes are the tracked
`src/bn/dh_data.rs` arrays, extracted by
`courts/performance-frontier/baseline/extract_dh_fixtures.py`.

## Counts

| population | comparisons | mismatches |
|---|---:|---:|
| shared secret, named vs authority (2048-bit exponent) | 3 | 0 |
| shared secret, named vs authority (225-bit exponent) | 3 | 0 |
| shared secret, named vs explicitly-loaded group (both widths) | 6 | 0 |
| key generation, candidate pair verified by the authority | 3 | 0 |
| key generation, authority pair verified by the candidate | 3 | 0 |
| key generation, shape (both libraries produced a pair) | 3 | 0 |
| malformed-peer refusal return codes (7 values × 3 groups) | 21 | 0 |
| **subtotal** | **42** | **0** |
| keygen with a caller-supplied private key | 3 | **STOP** |

Key generation is cross-checked as `g^priv`: the candidate's real
`DH_generate_key` pair `(priv, pub)` is verified by the authority's
`DH_compute_key(g, priv)`, and the authority's pair by the candidate's; all 6
cross-checks agree byte for byte. Shared-secret outputs also agree between the
named and the explicitly-loaded path, so the object-construction route does not
change the result.

## STOP — `PFP8-KEYGEN-PRESET-PRIV`

`DH_generate_key` on an object whose private key the caller supplied returns 0
and produces no public key in the candidate; the authority computes it.

| group | candidate | authority |
|---|---|---|
| ffdhe2048 | rc=1, no public key | rc=0, 256-byte public key |
| ffdhe3072 | rc=1, no public key | rc=0, 384-byte public key |
| modp2048 | rc=1, no public key | rc=0, 256-byte public key |

Cause: `src/dh/key.rs`'s `generate_key` places
`ossl_dh_generate_public_key` **inside** the `'generate` block and executes
`break 'generate` when `generate_new_key == 0`; the authority calls the
public-key function **outside** `if (generate_new_key)`
(`crypto/dh/dh_key.c:265-387`). This is pre-existing and not caused by PFP-8;
it was not repaired in this refusal batch.

## Refusal tests — malformed peer values

`DH_compute_key` return codes, candidate vs authority, for peer values
`0, 1, p−2, p−1, p, p+1, 2` on each group:

| group | result |
|---|---|
| ffdhe2048 | all 7 codes identical (0 and 1 refused; `p−2`, `p−1`, `p`, `p+1` refused with −1; 2 accepted) |
| ffdhe3072 | all 7 identical |
| modp2048 | all 7 identical |

The subgroup/range admission itself lives in `ossl_dh_check_pub_key_partial`
and the provider import, which this batch does not touch; `cargo test --lib --
dh` (77 passed, 0 failed, 2 ignored) covers the existing validation and
subgroup paths. No validation check, subgroup check or error path was changed.
