# PFP-5 — correctness differential

A single mismatch is a STOP. There were none.

## 1. In-crate: window vs bit-at-a-time reference vs variable-time oracle

`mod_exp_core_consttime_width_with(…, window)` runs the same ladder with an
explicit window choice, so `None` is the reference and `Some(4..=6)` the window.
`mod_exp_core` (the variable-time ladder, `limbs::{mul,rem}`) is an independent
oracle.

| test | moduli | exponents | bases | comparisons | mismatches |
|---|---|---|---:|---:|---:|
| `pfp5_window_matches_the_bit_at_a_time_ladder` | odd, 1–4 limbs (≤256 bits), incl. P-256's `p` | 0, 1, 2, small, full-width pseudorandom, all-ones | 0, 1, 2, m−1, m−2, m/2, one-limb, top-limb-only, all-ones, plus 24 pseudorandom residues | **3,420** window-vs-reference (w = 4, 5, 6 over 1,140 cases) + **1,140** reference-vs-oracle | 0 |
| `pfp5_window_matches_on_large_moduli` | odd 1024, 2048, 3072 bits (non-zero top limb) | 1024: all six classes; 2048: 0/small/full/ones; 3072: 1/full/ones | 0, 1, 2, m−1, random | **65** window(w=5)-vs-reference | 0 |

Total in-crate comparisons: **4,625** (3,420 + 1,140 + 65).

The 8192-bit bit-at-a-time comparison is **not** in the routine debug suite: a
debug-profile 8192-bit ladder costs minutes per case. 8192 bits is covered
instead by the authority differential below, where the candidate is compared
byte-for-byte against an independent implementation (OpenSSL 3.6.4) over 30
cases. This is a recorded scope limit, not a pass.

## 2. At the C ABI: candidate DSO `842efa27` vs authority `611e511d`

Harness `courts/performance-frontier/pfp5/pfp5_diff.c`, compiled against the
authority headers, one `libcrypto` per process via `dlopen`. Transcripts are
161 lines each and **byte-identical** (`raw/diff/diff.txt` is empty):

| population | cases | result |
|---|---:|---|
| `BN_mod_exp_mont_consttime`, moduli 256/1024/2048/3072/8192 bits, bases {0,1,2,m−1,random}, exponents {0,1,2,small,full,ones} | **150** | identical |
| RSA 2048 CRT private_encrypt, blinding on | 1 | identical |
| RSA 2048 CRT private_encrypt, blinding off (`RSA_blinding_off`) | 1 | identical, and equal to the blinded result (`blinding-off-equal=1` on both subjects) |
| RSA 2048 non-CRT (key rebuilt from n, e, d) private_encrypt | 1 | identical, and equal to the CRT result (`crt-equals-noncrt=1` on both subjects) |
| RSA 2048 public_encrypt → private_decrypt round trip (CRT) | 1 | ciphertext identical; round trip = 1 |
| RSA 2048 private_decrypt (non-CRT) | 1 | round trip = 1 |
| DH shared secret, RFC 7919 `ffdhe2048` | 1 | identical |
| DH shared secret, RFC 3526 `modp2048` | 1 | identical |

The population is deterministic (`xorshift64`), no `BN_rand` and no random bytes.
The 8192-bit `BN_mod_exp_mont_consttime` cases are included in the 150.

## 3. Routine suite

`cargo test --lib -- bn` — 159 passed, 0 failed. The full library suite —
2,491 passed, 0 failed, 54 ignored (the same 54 as the PFP-1 record; no test was
removed and none was newly ignored). The four new tests (two differential, two
ctgrind) are part of that count.
