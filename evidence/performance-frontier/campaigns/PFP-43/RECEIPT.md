# PFP-43 receipt — widened constant-time ladder (2400-bit exponent admission)

```yaml
task_id:            PFP-43
title:              an exponent wider than the modulus is computed, not refused
phase:              performance frontier
stage_branch:       staging (this batch is forbidden to commit/push)
source_identity:
  source_sha:       57ec4e2740c851583abc125dda3fac57b9ca94a6
  src_tree:         90a8be89401d7d1efc13ee9b39fe436c5e9ffbf9
  worktree:         uncommitted: src/bn/arith.rs, src/bn/mont.rs, src/dh/key.rs
  arith_sha256:     42b7323eb3b8a37ab36cc7c7aa1c61af3892ce93c4b043f86841ef5dcf95132c
  mont_sha256:      0d5f6a7fcb32e1705162cf1a7a0bcb80db4fb1b4433b53848feb89f44d93763a
  dh_key_sha256:    43405a51a84378f2ac41363f3e8497bfa9e149746b52aaa5aec76c6274ac2123
  candidate_dso:    da47f6503b7ed87bc79d2722a09573aa5a39da5e067d1859b5041ee17ff65125
  candidate_archive: 705c4aa5f5a3047a07890fd1fbe4eea97959c4a0ac803821f2e80aa4d85d7c15
  candidate_build_id: 311d01dadaabd10b7725970a2c6d3af0950518ec
  build:            cargo build --release --lib --offline (CARGO_BUILD_JOBS=1)
authority:
  dso_sha256:       611e511db4273c4b6b522031fd171efce71b80661bb8310c2a21dfd18ec0efd2
  source:           forensics/authorities/src/openssl-3.6.4
  behaviour:        scans every exponent bit and computes g^x mod p
court:
  matrix_probe:     court/tmp/pfp8/keygen_matrix (dbba05f197706abf05a1695797d995cc7c8dd9ea201c24d96bfce1b6a62eb2c7)
  timing_bench:     court/tmp/pfp8/bench_pfp8 (7a03fdd9a87496c6b9c19d218cdd56417bd750fae879f61e8a8b99a57d654b15)
  venue:            docker/openssl-rs-court.sh, 8g/8g cap, taskset -c 1
decision:           IMPLEMENT A (widen) — compatibility repaired; the row is not won
```

## 1. Refusal site, before and after

**Before.** `src/bn/arith.rs:2486-2497`:

```rust
// The policy is public; the clamp to the modulus' limb count is public too.
let policy = policy_limbs.min(md.len());
let width = if pd.len() <= policy {
    policy
} else {
    // Outside the declared bound: the previous modulus-width ladder, which
    // is also the previous answer for an exponent wider than the modulus.
    md.len()
};
if pd.len() > width {
    return None;
}
```

With `md.len() == 32` (2048-bit modulus) and `pd.len() == 38` (2400-bit exponent),
`width = 32` and `38 > 32`, so the ladder refused. `ladder_geometry`
(`arith.rs:2279`) had the same `declared_limbs.max(md.len())` clamp, and
`mod_exp_core_consttime_from_parts_prepared` is still the modulus-width entry
point.

**After.** The width is resolved **once**, before the policy function, in safe
code at the C entry point `src/bn/mont.rs:970`:

```rust
match policy_limbs {
    Some(policy) => {
        let width = resolve_ladder_width(policy, md.len(), pd.len());
        mod_exp_core_consttime_policy(&ad, pd, &md, width, prepared.as_ref())
    }
    ...
}
```

`resolve_ladder_width` (`src/bn/arith.rs:2455`) is:

```rust
let base = if policy_limbs == 0 {
    modulus_limbs
} else {
    policy_limbs.min(modulus_limbs)
};
base.max(exponent_limbs)
```

`mod_exp_core_consttime_policy` (`src/bn/arith.rs:2494`) no longer reads
`pd.len()` to choose a width; its only remaining read is the defensive contract
check `if pd.len() > resolved_width { return None; }` (`:2517`), which the
resolver makes unreachable on every in-crate path.

`DH_set0_key`, `set_priv_key` and the decoders were **not** changed: `Dh` is
`#[repr(C)]` and its 208-byte layout is asserted member by member in
`src/dh/mod.rs` (`the_dh_object_is_the_authoritys_shape`), so it cannot take a
new field without an ABI change. No `dh_st` mirror exists under
`artifacts/phase2/shell/`. The binding site is therefore the bn operation
boundary, not the object.

## 2. Bound and arithmetic

| key | exponent limbs | ladder width | iterations | measured (one process) |
|---|---:|---:|---:|---:|
| conforming `ffdhe2048` (225-bit policy) | 4 | 4 | 256 | PFP-8 baseline |
| caller-supplied 2400-bit, 2048-bit modulus | 38 | 38 | 2432 | 2971–3046 µs |
| authority, same key | — (scans 2048 bits) | — | ~2048 bit steps | 1416–1448 µs |

`width = max(min(policy, md.len()), pd.len())`; the ladder runs `64 * width`
iterations (`run_mont_ladder`, `arith.rs`). In-policy
(`pd.len() <= policy <= md.len()`) gives `width == policy`, so the PFP-8
schedule is unchanged (proved by `policy_width_widens_to_cover_the_exponent_and_never_truncates`
and the existing `policy_width_matches_the_modulus_width_ladder`).

`BN_mod_exp_mont_consttime` (`src/bn/mont.rs:1050`) is **not** widened. Its
documented contract fixes the schedule to the modulus width; widening it would
make a public C entry point's iteration count depend on the caller's exponent
length with no key-object policy to anchor it, and the DH refusal is not on that
path (`dh_bn_mod_exp` reaches `BN_mod_exp_mont`, not
`BN_mod_exp_mont_consttime`). A wider exponent through that specific API still
answers 0; that is the named residual compatibility deviation.

## 3. Change

| file | change |
|---|---|
| `src/bn/arith.rs` | new `resolve_ladder_width`; policy function takes a resolved width and drops the modulus clamp; tests replaced/added |
| `src/bn/mont.rs` | bind the width once at `bn_mod_exp_mont_impl`; import the resolver |
| `src/dh/key.rs` | new test: wide keygen, `DH_compute_key`, `ossl_dh_check_pairwise` (no production change) |

Diffstat: `src/bn/arith.rs +313/-?`, `src/bn/mont.rs +19`, `src/dh/key.rs +59`
(see `git diff --stat`). No change to `Dh`, the method tables, or any exported
symbol.

## 4. Unsafe accounting

| category | content |
|---|---|
| eliminated | none (the change is in safe arithmetic and a width decision) |
| relocated | none |
| hidden | **0** |
| new unsafe ops in non-test code | **0** |
| test-only unsafe | one `unsafe { }` block in the new `dh::key` test, matching that module's existing tests; compiled only under `#[cfg(test)]` |

## 5. Compatibility

`keygen_matrix.py` over 3 groups × 4 key-state combinations × 4 presets = 30
rows, candidate vs the authority. Before (`PFP-8/raw/preset-priv-matrix.json`):

```
MATRIX rows=30 mismatches=4
['ffdhe2048/nid/priv_preset_pub_absent/long_2400bit',
 'ffdhe2048/nid/priv_preset_pub_present/long_2400bit',
 'modp2048/nid/priv_preset_pub_absent/long_2400bit',
 'modp2048/nid/priv_preset_pub_present/long_2400bit']
```

After (verbatim, `raw/preset-priv-matrix.json` / stdout):

```
OK  ffdhe2048/nid/priv_absent_pub_absent: rc=1 pub=True errs=[]
OK  ffdhe2048/nid/priv_preset_pub_absent/in_bound_225: rc=1 pub=True errs=[]
OK  ffdhe2048/nid/priv_preset_pub_absent/short_1bit: rc=1 pub=True errs=[]
OK  ffdhe2048/nid/priv_preset_pub_absent/long_modulus_2048: rc=1 pub=True errs=[]
OK  ffdhe2048/nid/priv_preset_pub_absent/long_2400bit: rc=1 pub=True errs=[]
OK  ffdhe2048/nid/priv_absent_pub_present: rc=1 pub=True errs=[]
OK  ffdhe2048/nid/priv_preset_pub_present/in_bound_225: rc=1 pub=True errs=[]
OK  ffdhe2048/nid/priv_preset_pub_present/short_1bit: rc=1 pub=True errs=[]
OK  ffdhe2048/nid/priv_preset_pub_present/long_modulus_2048: rc=1 pub=True errs=[]
OK  ffdhe2048/nid/priv_preset_pub_present/long_2400bit: rc=1 pub=True errs=[]
OK  ffdhe3072/nid/priv_absent_pub_absent: rc=1 pub=True errs=[]
OK  ffdhe3072/nid/priv_preset_pub_absent/in_bound_225: rc=1 pub=True errs=[]
OK  ffdhe3072/nid/priv_preset_pub_absent/short_1bit: rc=1 pub=True errs=[]
OK  ffdhe3072/nid/priv_preset_pub_absent/long_modulus_2048: rc=1 pub=True errs=[]
OK  ffdhe3072/nid/priv_preset_pub_absent/long_2400bit: rc=1 pub=True errs=[]
OK  ffdhe3072/nid/priv_absent_pub_present: rc=1 pub=True errs=[]
OK  ffdhe3072/nid/priv_preset_pub_present/in_bound_225: rc=1 pub=True errs=[]
OK  ffdhe3072/nid/priv_preset_pub_present/short_1bit: rc=1 pub=True errs=[]
OK  ffdhe3072/nid/priv_preset_pub_present/long_modulus_2048: rc=1 pub=True errs=[]
OK  ffdhe3072/nid/priv_preset_pub_present/long_2400bit: rc=1 pub=True errs=[]
OK  modp2048/nid/priv_absent_pub_absent: rc=1 pub=True errs=[]
OK  modp2048/nid/priv_preset_pub_absent/in_bound_225: rc=1 pub=True errs=[]
OK  modp2048/nid/priv_preset_pub_absent/short_1bit: rc=1 pub=True errs=[]
OK  modp2048/nid/priv_preset_pub_absent/long_modulus_2048: rc=1 pub=True errs=[]
OK  modp2048/nid/priv_preset_pub_absent/long_2400bit: rc=1 pub=True errs=[]
OK  modp2048/nid/priv_absent_pub_present: rc=1 pub=True errs=[]
OK  modp2048/nid/priv_preset_pub_present/in_bound_225: rc=1 pub=True errs=[]
OK  modp2048/nid/priv_preset_pub_present/short_1bit: rc=1 pub=True errs=[]
OK  modp2048/nid/priv_preset_pub_present/long_modulus_2048: rc=1 pub=True errs=[]
OK  modp2048/nid/priv_preset_pub_present/long_2400bit: rc=1 pub=True errs=[]
MATRIX rows=30 mismatches=0
```

Correctness before timing:

* `pfp43_widened_ladder_matches_independent_paths_and_the_authority_constant`
  computes `2^x mod p` for `x = int("ab"*300, 16)` over the ffdhe2048 prime and
  compares three ways: the widened policy ladder, `mod_exp_core` (variable-time),
  `mod_exp_core_consttime_width(..., e.len())`, and the independently computed
  `pow(g,x,p)` (little-endian limbs in the test).
  `python3 pow(2, int("ab"*300, 16), p)` =
  `55edb9a4c08fe9e7cc8f8e8477e03b11e576f6484550a3109db210dfd045e7132b382123f40d282fd665bc6f388f85e605b618376b885a6f8118673476acc7360143563a5a1e340dc571b22752302a57e197a27bbcc24421f8e846328414f28e8491630f18620a3079e731ebcb50c3293ce3c4512d9b79ab030984a1c594ae8c1ccdcbf728d45a4b5138d0b3f3cb0ea5011569890282d1a2675007b04bc6e6e046f7c29d7ba3b97dcab10f1a8ff7c6da6c8c79dbdcfdbe013eedd8584f16a7ec4ae5eafd53440a04c9318ee748c5424c80afad5b592841ccce2b0219b363cfbcc07b1e9c18616b3e2becf1d31e2826d8ffdb90ba1c1e9ace9f263779fc85e662`.
  The C-ABI `bench_pfp8 --op keygen-fixed` prints the same 512 hex digits for
  the candidate and the authority (`raw/timing.txt`, `CHECK` lines).
* `pfp43_widened_ladder_covers_the_size_boundaries`: exponents of exactly
  `64*md.len() = 2048` bits, 2049 bits and 4096 bits against the 2048-bit
  modulus all equal the variable-time ladder; none is refused.
* `an_out_of_policy_private_key_derives_and_agrees` (dh/key.rs): a 2400-bit
  preset key derives its public key, agrees with an ordinary peer through
  `DH_compute_key_padded`, and passes `ossl_dh_check_pairwise` — keygen,
  `compute_key` and the pairwise check, not only keygen.

No mismatch was observed; if one had, the batch would have stopped.

## 6. Safety — the width declassification and its threat model

**What is declassified.** The ladder width, and therefore the iteration count
`64 * width`, is a function of the private exponent's **normalised limb count**
when that count exceeds `min(policy, md.len())`. It is a length, never a limb
value: no branch, table index or loop bound inside the ladder reads the
exponent's contents.

**Where it lives.** The single classification point is `resolve_ladder_width`
(`src/bn/arith.rs:2455`), called once at `src/bn/mont.rs:970`. Before this
change the same length read existed inside the policy function as the
`pd.len() <= policy` admission decision; the change moves it to one place,
before the ladder, and makes the interior width-only.

**Threat model.** The only new observable is the private exponent's limb count
(when it exceeds the group's declared policy) through the operation's duration.
The party that observes that timing is the party that supplied the key, or a
co-resident/remote observer of a **local** private key used in a configuration
outside its group's declared policy. For every conforming key
(`pd.len() <= policy`) the width is exactly the policy, so there is no new
channel at all. No secret *value* influences the schedule. This is the
declassification PFP-43 records; it is not a claim of constant time.

**Not established.** No branch/disassembly audit and no ctgrind run were made in
this batch, so **no constant-time claim is made**. The schedule argument above
is a source-level statement. The court is virtualised: the compatibility and
timing results are `SCOPED_OBSERVATION`, not a physical-venue measurement.

## 7. Timing (measured)

`bench_pfp8 --op keygen-fixed --nid 1126 --priv "ab"*300`, candidate vs
authority, `taskset -c 1`, `--iters 20 --runs 5`, three alternating repetitions
(`raw/timing.txt`):

| rep | candidate median µs | authority median µs |
|---|---:|---:|
| 1 | 2998.464 | 1425.097 |
| 2 | 3005.994 | 1794.971 (preempted; spread 0.233) |
| 3 | 3046.230 | 1447.639 |

Using each run's minimum (least contaminated): candidate ≈ 2971 µs,
authority ≈ 1419 µs → **2.09×** the authority (median-of-medians 2.08×). The
second authority sample is kept in the raw file rather than deleted.

This is the predicted order of magnitude: 2432 iterations versus the
authority's 2048 exponent-bit scan is ×1.19, on a ladder that PFP-8 measured at
≈1.99× the authority per equal-length operation. **The change repairs
compatibility; it does not win the row.** The 256-iteration path is the only
competitive schedule, and it is proposed (not implemented) as PFP-45 in
`BOUNDS.md`.

## 8. Repository gates

| gate | result |
|---|---|
| `cargo fmt --all -- --check` | clean |
| `cargo clippy --all-targets -- -D warnings` | clean |
| full `cargo test --lib -- --test-threads=4` | **2510 passed, 0 failed, 56 ignored** |
| baseline 2507 / 0 / 56 | 3 new tests, no test newly ignored, none removed unexplained |
| `keygen_matrix.py` | **rows=30 mismatches=0** |

## 9. Residual obligations

| id | state | obligation |
|---|---|---|
| `PFP43-LENGTH-DECLASSIFICATION` | OPEN | the width leaks the private key's limb count for out-of-policy keys; accepted with the threat model above, not measured with ctgrind |
| `PFP43-CONSTTIME-NOT-CLAIMED` | NOT_RUN | branch audit and ctgrind on the widened schedule |
| `PFP43-CONSTTIME-API` | OPEN | `BN_mod_exp_mont_consttime` still refuses a wider-than-modulus exponent (retained, justified in §2) |
| `PFP43-DH-FIELD` | RESOLVED | a bound-width field on `Dh` rejected: `#[repr(C)]`, 208-byte asserted layout |
| `PFP-45` | PROPOSED | reduce the secret exponent mod the subgroup order (text only, `BOUNDS.md`) |

## 10. What this receipt does not establish

* It is not a frontier result and does not make the widened path competitive.
* It is not a constant-time result; no branch audit or ctgrind was run.
* It does not repair `PFP8-WIDTH-POLICY` (the in-policy ladder is still ≈2× the
  authority per bit).
* It does not establish `SAFE_COMPATIBLE`; compatibility is confirmed against
  the exact `da47f650` DSO only.

---

## CORRECTION — PFP-39 (2026-11-27): the "`Dh` cannot take a field" claim was FALSE

**This section supersedes §1's final paragraph, §1's "After" width snippet, and §9's
`PFP43-DH-FIELD` row. The earlier text is preserved above rather than rewritten.**

**The false claim.** §1 said:

> `DH_set0_key`, `set_priv_key` and the decoders were **not** changed: `Dh` is
> `#[repr(C)]` and its 208-byte layout is asserted member by member ... so it
> cannot take a new field without an ABI change. ... The binding site is therefore
> the bn operation boundary, not the object.

That is wrong. It conflated "the authority's asserted offsets must not move" with
"no byte may be used", and missed that `struct dh_st` contains four-byte padding.

**What the independent adjudication found.** The authority's layout is: `pad` 0,
`version` 4, `params` 8..104, `length` 104..108, `pub_key` 112, `priv_key` 120,
`flags` 128, `method_mont_p` 136, `references` 144, `ex_data` 152, `engine` 168,
`libctx` 176, `meth` 184, `lock` 192, `dirty_cnt` 200, total 208. The bytes
`108..112`, `132..136` and `148..152` are padding. A `u32` inserted immediately
after `length` lands at `108..112`, moves no asserted offset, and keeps
`size_of::<Dh>() == 208`.

**What replaced it (PFP-39).**

* `src/dh/mod.rs` now has `pub(crate) priv_limbs: u32` immediately after `length`.
  `the_dh_object_is_the_authoritys_shape` asserts `offset_of!(Dh, priv_limbs) == 108`
  and still asserts `size_of::<Dh>() == 208` and every authority offset unchanged.
* The private key's normalised limb count is captured once at ingestion —
  `DH_new` (0), `DH_set0_key`, `generate_key`, and `ossl_dh_dup` — and refreshed on
  replacement.
* `src/bn/mont.rs` resolves the width from the stored count:
  `resolve_ladder_width(policy, md.len(), stored_exponent_limbs)`. The §1 "After"
  snippet's third argument `pd.len()` is therefore superseded; the resolver's
  arithmetic (`base.max(exponent_limbs)`) is unchanged.
* The 30-row court still reports `rows=30 mismatches=0` against the new exact DSO.

**Consequence for §9.** `PFP43-DH-FIELD` is **superseded, not resolved-by-rejection**:
the field was never rejected; it is carried in the authority's padding. PFP-39 is
the binding-at-ingestion implementation. No constant-time claim is added or
withdrawn by this correction.
