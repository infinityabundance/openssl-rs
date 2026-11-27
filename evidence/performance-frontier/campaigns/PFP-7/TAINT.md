# PFP-7 — ctgrind at the digest

**Digest:** `6d002db2…`; test binary `openssl_rs-b4da7ea231465a25`, sha256
`5509e5cda453dc1b2fafa66ebd15d9980308b4ae2999589e8626354e0817b073`
(`CARGO_PROFILE_TEST_DEBUG=0`, debug profile with line debug info suppressed).
**Harness:** `harness/taint.sh` → `raw/taint/*.log`, `raw/taint/sites.txt`.

**ctgrind is source-bound, not DSO-bound** (PFP-21). It is a taint run, not a
constant-time proof, and it cannot distinguish a `cmov` from a branch.

## Cases

| case | tainted | errors | contexts |
|---|---|---:|---:|
| `rsa::ossl::tests::ctgrind_rsa_crt_secret_exponents` | `d`, `dmp1`, `dmq1`, `p`, `q` | 96,668 | **112** |
| `rsa::ossl::tests::ctgrind_rsa_crt_secret_moduli` | `p`, `q` | 97,546 | **106** |
| same, `CTGRIND_CONTROL=1` | as above + a branch on a marked limb | 97,479 | **113** |

The two test cases land inside the band PFP-1 and PFP-5 recorded at earlier
digests (96,541/106 … 96,836/112), which is the expected result of *not*
changing the code.

## Origins

Top frames of the reported contexts (`raw/taint/sites.txt`), exponents case:

| count | site |
|---:|---|
| 21 | `bn::limbs::cmp` — the tail's congruence decision on the secret result |
| 15 | `bn::limbs::mul_fallible` — inside the variable-time `BN_mod_exp_mont` result check |
| 15 | `bn::limbs::divide_fallible` — same |
| 14 | `bn::limbs::normalise` — the pre-existing write-back (`PFP2-WRITEBACK-NORMALISE`) |
| 4 | `bn::limbs::sub_fallible` |
| ≤ 3 each | `Vec`/`RawVec` growth, `Option::unwrap_or`, `BN_add`, … |

**No context has `run_mont_ladder`, `run_mont_ladder_window`,
`select_window_digit`, `mont_mul_ladder_into` or `mont_mul_sos_into` as its
site.** The CRT exponentiation carriers therefore contain no secret-derived
conditional transfer or address in this run. The contexts that do appear are on
the *result check* (which examines the secret result with a variable-time
`BN_mod_exp_mont`, as the authority does) and on the pre-existing normalise.

## The interleaved carrier

There is **no interleaved loop in this build** — `BN_mod_exp_mont_consttime_x2`
is two sequential calls — so the question "does the interleaved loop introduce a
secret-dependent transfer or address?" has the vacuous answer **none**, because
the carrier does not exist. A future interleaved implementation would have to be
re-tainted at its own digest; this record does not cover it.

## Negative control

`CTGRIND_CONTROL=1` adds a deliberate branch on a marked modulus limb in the
test. It fires at the test's own frame: the `Conditional jump …` block count
rises **102 → 109** and contexts **106 → 113**. The instrument is sensitive at
that site. The RSA baseline is noisy (~100 contexts), so the control's marginal
signal here is 7 contexts, not the clean 0 → 1 of the window-only test; that
limit is stated rather than hidden.
