# PFP-8 — the bound, and the decision

**Item:** `docs/PERFORMANCE-FRONTIER-TODO.md`, PFP-8.
**Claim class:** `SCOPED_OBSERVATION` (one court venue, no PMU).
**Frozen source `S`:** `staging` `b2cca665bea652c2c821205d516b28f3277f4ed1`
(`src` tree `05a4a56b7a4b2db3cee76e8db37fa286f1cd89d9`,
`src/bn/arith.rs` sha256 `b548ee1533f527366099d95b907bd20237bbcc2e8208966eb9a15cf11f09809f`,
build-relevant tree clean).
**Candidate DSO:** `88c0c7e04d52a1bf84d665fdd691bddf2bbe700e35505d95bf145bfdc3774d87`
(archive `2ec133ca3fc74f4ca0c0b93a68a0d769679f8b63e9ddac3ca8383c7feb9dff93`),
two fresh `CARGO_TARGET_DIR` builds agree byte for byte.
**Authority:** OpenSSL 3.6.4 production DSO
`611e511db4273c4b6b522031fd171efce71b80661bb8310c2a21dfd18ec0efd2`.
**Decision: REFUSE. No source changed. The arithmetic is below the 10 % threshold.**

---

## 1. Profile — key generation and shared secret, separately

`courts/performance-frontier/pfp8/bench_pfp8.c` drives the exported DH surface.
One process per workload; callgrind records the `CHECK` call, one warm-up and one
timed call, so the totals below are per two operations. The measured workload is
`ffdhe2048` (NID 1126); `ffdhe3072` and `modp2048` behave the same way.

### 1.1 The exponentiation itself (identical for keygen and agreement)

The exponent is staged to the **modulus** width, so both operations run
`bits = 64 · n = 2048`, independent of the private key's 225-bit declared length.
The window is `w = 5`, `windows = 410`, `entries = 32`.

| component | calls | instructions | share of the exponentiation |
|---|---:|---:|---:|
| table build (`entries − 2`) | 30 | 635,580 | **1.19 %** |
| main-loop squarings | 2,050 | 43,431,300 | 81.43 % |
| main-loop multiplications | 410 | 8,686,260 | 16.29 % |
| final conversion | 1 | 21,186 | 0.04 % |
| masked scan + loop control (`run_mont_ladder`, inlined scan) | — | 415,270 | 0.78 % |
| base conversion (`mont_mul_fallible`, SOS) | 1 | 32,158 | 0.06 % |
| other (copy/drop/geometry) | — | 113,176 | 0.21 % |
| **total** | 2,491 CIOS + 1 SOS | **53,334,930** | 100 % |

Measured fixed-width kernel cost: `mont_mul_ladder_into` is 105,548,652
instructions for 4,982 calls = **21,186 Ir/call** (n = 32, CIOS, M-A1
specialisation). The PFP-5 model used the SOS figure 30,170; this bound uses the
fixed-width kernel's own measured cost as the task requires.

The masked scan is cheaper than the PFP-5 model: the measured `run_mont_ladder`
exclusive cost is 415,270 Ir / 410 windows = **1,013 Ir/window**. The model's
conservative upper bound (`3` Ir per limb-select × `2^w · n` = 3,072 Ir/window)
is used below, so the scan cost is not understated.

### 1.2 Key generation (real named-group path, fresh object per call)

| component | instructions/op | share |
|---|---:|---:|
| `dh_bn_mod_exp` (the table above) | 53,334,930 | 85.2 % |
| `BN_MONT_CTX_set` / `pow2_mod_consttime` (one per fresh object) | 2,818,502 | 4.5 % |
| `ossl_ffc_generate_private_key` (RNG + range loop) | 5,153,631 | 8.2 % |
| named-group lookup (`name_find`; one per process/group table) | 2,095,420 | 3.3 % |
| object/BN allocation, DRBG, entry | remainder | ~1 % |

The process total is 125,262,230 Ir for two keygens: the first pays the one-time
group lookup (2,095,420) and both pay the per-object MontCtx (2,818,502 each),
so the first keygen is ~63.4 M and the steady-state keygen ~59.1 M. The table-build
fraction below is taken from the exponentiation itself and is unaffected by
these one-time terms.

Timed operation (15 paired repetitions, §`TIMING.md`): candidate **2,628.7 µs**,
authority **177.7 µs**, ratio **14.82× [14.40, 14.97]**.

### 1.3 Shared secret, 2048-bit benchmark exponent

| component | instructions/op | share |
|---|---:|---:|
| `dh_bn_mod_exp` (the table above) | 53,334,930 | 97.5 % |
| post-checks (`BN_copy`/`BN_sub_word`/`BN_cmp`), `BN_bn2binpad`, unpadding | ~1.38 M | 2.5 % |

Timed operation: candidate **2,443.0 µs**, authority **1,225.2 µs**, ratio
**1.9876× [1.9514, 2.0940]** — the recorded 2.02× at a different digest is
inside this interval; no trend is claimed across digests.

### 1.4 Shared secret, the RFC 7919 225-bit key length

Candidate **2,450.9 µs**, authority **176.3 µs**, ratio **14.04× [13.75, 14.45]**.
The exponent is 225 bits on both sides, but the crate runs `64 · md.len()` = 2048
iterations while the authority runs `p->top · BN_BITS2` = 256
(`bn_exp.c:637`). This is the fixed-width ladder policy, not a table cost; see
§5.

---

## 2. Window-width arithmetic

`N = 2048`, `n = 32`, measured kernel cost `C = 21,186` Ir. For a left-to-right
fixed window:

* `windows = ceil(N/w)`;
* squarings `= windows · w`; main-loop multiplications `= windows`;
* precompute that can move out of the per-call path `= 2^w − 2`;
* scan per window `= 2^w · n · 3 / C` Montgomery-call equivalents, so the total
  scan is `windows` times that; it grows with the table;
* conversions `= 2`.

| w | windows | squarings | main mult | precompute | scan total | total (calls) | total − precompute | precompute share |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 5 | 410 | 2,050 | 410 | 30 | 59.45 | 2,551.45 | 2,521.45 | **1.18 %** |
| 6 | 342 | 2,052 | 342 | 62 | 99.18 | 2,557.18 | 2,495.18 | **2.42 %** |
| 7 | 293 | 2,051 | 293 | 126 | 169.94 | 2,641.94 | 2,515.94 | **4.77 %** |
| 8 | 256 | 2,048 | 256 | 254 | 296.96 | 2,856.96 | 2,602.96 | **8.89 %** |

The table is not free: at `w = 7` and `w = 8` the scan growth makes the total
larger than the admitted `w = 5` baseline. Per window the model scan is
`2^w · 32 · 3 / 21,186` = **0.145 / 0.290 / 0.580 / 1.161** kernel-call
equivalents for `w = 5 / 6 / 7 / 8`, so the total scan grows as
59.45 / 99.18 / 169.94 / 296.96. The measured `w = 5` scan is 1,013 Ir/window
(0.048 call) because the compiler vectorises the masked scan; the model is used
so the scan cost is never understated. Relative to the baseline
(2,551.45 calls):

| w | prepared total | change vs baseline |
|---:|---:|---:|
| 5 | 2,521.45 | **−1.18 %** |
| 6 | 2,495.18 | **−2.21 %** |
| 7 | 2,515.94 | −1.39 % |
| 8 | 2,602.96 | **+2.02 % (worse)** |

The best prepared configuration is `w = 6` at 2.21 % — still far below 10 %.

---

## 3. Amdahl bound

Group preparation can move **only** the table build `B(w) = 2^w − 2`, and only
when the base is the group generator:

* **Key generation**: `f(w) = B / T` = 1.18 % (`w = 5`), 2.42 % (`w = 6`),
  4.77 % (`w = 7`), 8.89 % (`w = 8`). Including the window choice, the best
  measured-work removal is **2.21 %**.
* **Shared secret**: the base is the peer's public value, which is not the
  generator and is not known before the call. There is no public generator table
  to reuse, so `f = 0 %`. The 1.99× row is structurally untouched.
* **One DH exchange** (keygen + agreement on the same group, both full-width):
  the keygen half contributes about half the work, so the exchange bound is
  about **0.6 %**.

Every figure is below the 10 % refusal threshold.

---

## 4. What a positional comb would do (and why it is not this change)

A comb table (`g^{d · 2^{i·w}}` per window) removes the squarings for **key
generation**:

* at `N = 2048`, `w = 6`: per call `342 + 99.18 + 1 = 442.2` calls versus
  2,551.45, an 82.7 % reduction — but the table build is
  `342 · 62 + 341 · 6 ≈ 23,250` calls (9.1× the current per-call work) and the
  table is 5.6 MiB for `ffdhe2048` and 89.5 MiB for `ffdhe8192`;
* bounded by the group's declared 225-bit key length (`N = 256`, `w = 6`): the
  table is 43 · 64 · 32 · 8 = 704 KiB, the build is ~2,918 calls (1.17× the
  current per-call), and the per-call path is 43 + 12.5 + 1 = 56.5 calls
  (97.8 % removal) — for key generation only.

The shared secret uses the peer's public value as the base, so a comb cannot be
reused across calls there; it leaves the 1.99× row unchanged. Using the declared
key length as the ladder width is a separate constant-time policy change (the
current ladder deliberately runs the modulus width), not a table optimisation.
The comb is therefore not implemented in this batch; it is a candidate for a
separate keygen-only item that also decides the width policy.

**Generator-2 doubling was not implemented**: with a generator table, the
per-call multiplications are by table entries, not by `g`; doubling would only
cheapen the table build, which is the 1.19 % item above, and the bound does not
support any prepared path.

---

## 5. Decision and findings

**REFUSE.** The table build is 1.19 % of the exponentiation; the best prepared
window is 2.21 % faster; the shared-secret workload cannot use a generator table
at all. No source change is justified. A measured refusal is the complete result.

Two findings are recorded and were **not** repaired in this batch:

* **`PFP8-KEYGEN-PRESET-PRIV` (STOP, pre-existing).** `src/dh/key.rs`'s
  `generate_key` places `ossl_dh_generate_public_key` inside the `'generate`
  block and `break 'generate` when `generate_new_key == 0`. A
  `DH_generate_key` on an object whose `priv_key` the caller supplied therefore
  returns 0 without computing the public key. The authority's call is *outside*
  the `if (generate_new_key)` block (`crypto/dh/dh_key.c:265-387`). Candidate:
  `rc=1`, no public key; authority: `rc=0`, 256/384-byte public key — for all
  three real groups. This blocks the deterministic key-generation differential on
  that path and is a separate compatibility repair.
* **`PFP8-WIDTH-POLICY` (recorded observation).** The 14× gap at the RFC 7919
  key length is the fixed-width ladder running 2032 extra iterations
  (`64 · md.len()` vs the authority's `p->top · 64`). It is not a table cost and
  is not fixed here; a future item could use the **public** `dh->length` bound
  rather than the exponent's limb count.

Evidence: `PROFILE.md`, `DIFFERENTIAL.md`, `REFUSAL.md`, `TAINT.md`, `AUDIT.md`,
`TIMING.md`, `RECEIPT.md`, `build/`, `profile/`, `raw/`, `timing/`, `ctgrind/`,
`audit/`.
