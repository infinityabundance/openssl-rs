# Integration plan — Phase 8.7's remaining layer (`crypto/ec/` items 2–6)

This document integrates **the block D334 and D335 measured and left whole**: the group and point
objects (`crypto/ec/ec_lib.c`, sixty-nine exports), the field arithmetic they dispatch to
(`ecp_smpl.c`, `ecp_mont.c`, `ecp_nist.c`, `ec2_smpl.c`), the point-encoding units
(`ecp_oct.c`, `ec2_oct.c`, `ec_oct.c`), the multiplication ladder (`ec_mult.c`), the two group
constructors (`ec_curve.c`'s withheld pair), the curve-conversion unit (`ec_cvt.c`), the key layer
(`ec_key.c`, `ec_kmeth.c`), the two signature/shared-secret units (`ecdsa_ossl.c`, `ecdh_ossl.c`),
the provider group/key backend it reaches (`ec_backend.c`) and the two BN units that closure
reaches (`crypto/bn/bn_intern.c`, `crypto/bn/bn_exp.c`).

It is a plan, not a landing: **nothing under `src/`, `courts/`, `forensics/` or `docs/` is touched by
this file**, and the plan itself is not part of the build.

It is written against what the crate *already* has, read rather than assumed:

* `src/ec/mod.rs` (1069 lines) holds D335's seven shapes and seven constants — `EcMethod`
  (`:172`, 448 bytes, 55 pointers over `flags`/`field_type`), `EcGroup` (184), `EcPoint` (48),
  `EcKey` (104), `EcKeyMethod` (120), `EcdsaSig` (16), the `EcPreComp` union, and the forty-five
  `*Fn` aliases (`:301`–`:518`, `:560`, `:766`–`:785`) that its members are declared with.
* `src/ec/curve.rs` (498 lines) holds `ec_curve.c`'s constants and `curve_list[]`, and
  `src/ec/curve_data.rs` the generated parameters; `src/ec/support.rs` (324) holds
  `crypto/evp/ec_support.c`. Four exports are implemented and `RT-EC` is registered at **483
  observations**.
* `src/bn/` supplies the whole arithmetic a field implementation needs: `BigNum`, `BN_*`,
  `BnCtx`/`BN_CTX_*`, `MontCtx`/`BN_MONT_CTX_*`, `BN_mod_exp_mont`. The two exceptions this plan's
  closure reaches are named in §2e.
* `src/runtime/` supplies `CRYPTO_zalloc`/`CRYPTO_free`/`cleanse`, the thread lock, the ex-data
  machinery, `OPENSSL_sk_*`, `raise_site` and the EC `ErrSite`s D334 added — `err_sites.rs` moved to
  **2,498** sites for `ec_curve.c` and `ec_support.c`, and every remaining unit of this block raises
  the same way.
* The gate's own universes, read from `forensics/atlas/prerequisite-gate.json`:
  **288** crate modules over **216** authority units, **3,527** language-census names, **32**
  divergence-covered names over **7** rows, **19** blocking dependencies, and
  **17** names referenced and not built. D336's measurement is what decides how this plan is cut.

---

## 1. The order of operations

Each step names the file it edits or creates, and why it must precede the next. Steps 2–6 are **one
commit**; steps 1 and 7–9 are separate ones. The reason steps 2–6 cannot be split is §3, and it is a
measurement rather than a preference.

**1. `court/` — the nistz256 boundary, as a record** (§8). Nothing else. It is first because every
later step's closure table depends on whether `ecp_nistz256.c` is in the commit, and the answer is
that it is not.

**2. `src/bn/intern.rs` and `src/bn/exp.rs` (new) — the two BN units the closure reaches.**
`crypto/bn/bn_intern.c` defines eight internals, none of them implemented and none of them in a unit
the crate has a module for: `bn_compute_wNAF`, `bn_copy_words`, `bn_get_dmax`, `bn_get_top`,
`bn_get_words`, `bn_set_all_zero`, `bn_set_static_words`, `bn_set_words`.
`crypto/bn/bn_exp.c` defines one, `bn_mod_exp_mont_fixed_top`. They land **whole**, in the two
modules named for their units, before anything in `crypto/ec/` names them: `ec_mult.c` calls
`bn_compute_wNAF`, and `ecp_smpl.c`'s `field_inv` path reaches `bn_mod_exp_mont_fixed_top`.

Why first: they are the only callees of the closed set that belong to **another stratum's directory**
and are small enough to land alone. Landing them here keeps step 3's closure table honest.

**Two names this step deliberately does *not* land, and it is the one place the closure reaches
backwards.** `ec2_oct.c:69` and `:81` call `BN_GF2m_mod_sqrt_arr` and `BN_GF2m_mod_solve_quad_arr`,
which are `crypto/bn/bn_gf2m.c`'s and therefore `bn.h`'s — Phase 5's — and
`forensics/phase9-obligations.json` already carries all four of the `_arr`/non-`_arr` pair as **`open`
with `received_from_phase: 5` and `module: src/bn/gf2m.rs`** (that module exists; it holds
`BN_GF2m_mod_mul_arr` and its neighbours). They cannot be landed here without moving a *sealed*
stratum's ledger backwards, so they are recorded as two **deferral rows in
`forensics/prerequisites.json`** with `owner_phase: 9` — the same shape Phase 7's `d2i_X509_ALGOR ->
phase 11` and `OSSL_ENCODER_CTX_new_for_pkey -> phase 10` rows already have, where an earlier
stratum's module names a later stratum's function and the record is the coordinate rather than an
approximation. The gate's `deferral_target_not_ahead` check passes (9 > 8) and its `deferral_blocker_is_stale`
check is satisfied by naming that work.

**3. `docs/PHASE-8-EC-INTEGRATION-PLAN.md` (this file) and the nistz256 divergence record.** A plan that is
written after the commit it describes is a description, not a plan.

**4. `src/ec/lib.rs`, `src/ec/smpl.rs`, `src/ec/mult.rs`, `src/ec/oct.rs`, `src/ec/cvt.rs`
(new) — the closed set of §3.** `crypto/ec/ec_lib.c` (sixty-nine exports, six internals),
`ecp_smpl.c` (one export, thirty-two internals), `ec_mult.c` (no export, six internals),
`ecp_oct.c` (no export, three internals), `ec_oct.c` (six exports, no internals) and `ec_cvt.c`
(two exports, no internals), in six new modules. This is the keystone: `ec_lib.c` **defines** the
five `EC_POINT_*` calls that `ecp_oct.c`, `ec_mult.c` and `ec2_oct.c` make at their own call sites,
and `ecp_smpl.c` **defines** the `ossl_ec_GFp_simple_*` symbols that `ec_lib.c`'s two
`EC_POINT_set_Jprojective_coordinates_GFp`/`_get_…` exports call. Neither is optional and neither can
precede the other, which is the cycle §3 measures.

Why before step 5: `ecp_mont.c`, `ecp_nist.c` and `ec2_smpl.c` are `EC_METHOD` tables whose
non-field columns are `ecp_smpl.c`'s and `ec_lib.c`'s functions, so their initialisers cannot be
written before those functions exist and are named by their crate paths.

**5. `src/ec/mont.rs`, `src/ec/nist.rs`, `src/ec/smpl2.rs` (new)** — `crypto/ec/ecp_mont.c`
(one export, eleven internals), `crypto/ec/ecp_nist.c` (one export, four internals) and
`crypto/ec/ec2_smpl.c` (one export, twenty-six internals). Each is a `static const EC_METHOD` plus
the field functions it names, and each is the *whole* unit, because D327's rule applies to a unit's
**internals** and a partial method table would leave eight columns fabricated (§3).

`ecp_nistz256.c` is deliberately **not** in this step or any other: its method table is landable but
its field arithmetic is not, and §8 records the boundary.

**6. In the same commit: `src/ec/curve.rs` gains `ec_group_new_from_data` and the two withheld
constructors** (`EC_GROUP_new_by_curve_name_ex`, `EC_GROUP_new_by_curve_name`), and
`curve_list[]`'s fourth column is written. Why here and not earlier: `ec_group_new_from_data`
branches on `curve.meth` and falls back to `EC_GROUP_new_curve_GFp`/`_GF2m` for every NULL row
(`ec_curve.c:2917`, `:2926`), so it needs step 4's `ec_cvt.c`; and the one non-NULL row's method is
§8's divergence rather than a transcription. **This retires `docs/SECURITY_DIVERGENCE_POLICY.md`'s
D-EC-1 and replaces it with D-EC-2** (§8), and retires D334's seventh divergence row
(`ossl_ec_curve_nid_from_params`), which is `ec_curve.c`'s internal and becomes implementable the
moment `ec_lib.c`'s nine callers exist.

**7. `src/ec/key.rs`, `src/ec/kmeth.rs` (new) — `crypto/ec/ec_key.c` and `crypto/ec/ec_kmeth.c`.**
Thirty-three and nineteen exports. This is the step that closes D335's second measurement: the five
method tables of step 5 name eleven columns from these two units, and `ec_kmeth.c`'s own
`openssl_ec_key_method` (`ec_kmeth.c:24-38`) names seven — so steps 1–6 compile only if the seven
are defined, and they can only be defined here. **`EC_KEY_generate_key` retires the ledger's
`deferred` row** and `forensics/tools/phase8_obligations.py`'s `BLOCKED_HANDOFFS` row is retired with
it.

Why in one step: `EC_KEY_new_method` (`ec_kmeth.c`) is `ossl_ec_key_new_method_int` (`ec_kmeth.c`'s
one internal) and reads `EC_KEY_get_default_method()`, which is `&openssl_ec_key_method`; and
`openssl_ec_key_method` names `ossl_ec_key_gen` (`ec_key.c`). Splitting them is a cycle.

**8. `src/ec/ecdsa_ossl.rs`, `src/ec/ecdh_ossl.rs` (new) — the two signature/shared-secret units**
(nine and two internals, no exports of their own; `ecdsa_sign.c`/`ecdsa_vrf.c`/`ecdh_kdf.c` keep
their exports). They land *after* step 7 because `ossl_ecdsa_simple_sign_setup` and its siblings take
an `EC_KEY`, and because the four `*Fn` columns in the two tables of step 5 that name them are
already written by then — the initialisers take *addresses*, so these two modules must exist before
step 5's tables are written, which is why step 5's tables and these two land in one commit in
practice. The commit boundary is therefore not 5 | 8 but {5, 8} | 7, and this plan records the
measured reason rather than the tidier-looking order.

**9. `src/ec/backend.rs` (new) and the two `EC_GROUP_*_params` exports** — `crypto/ec/ec_backend.c`
(seventeen internals) plus `crypto/param_build_set.c`'s four `ossl_param_build_set_*`, which is the
unit D330 and D331 both recorded as having no crate module and no plan row. `ec_lib.c`'s
`EC_GROUP_to_params` and `EC_GROUP_new_from_params` reach `ossl_ec_group_todata`,
`ossl_ec_encoding_param2id` and `ossl_ec_pt_format_param2id` (`ec_lib.c:1540`, `:1767`), so those
two exports of `ec_lib.c` are **withheld from step 4 and land here**, or the unit is not whole.
Landing `ec_backend.c` whole is the cheaper of the two: it is the same shape as `ec_key.c` and its
closure is `param_build_set.c` alone, whose own callees (`OSSL_PARAM_BLD_*`, `OSSL_PARAM_set_*`) are
in the crate.

**10. `court/phase8/rt_ec_probe.c` gains §5's arms, in order, in the same commits as the code they
court.** An export landed without an arm fails `court_coverage.py` in the same commit, so the arms
are not a later tidying.

**11. Regenerate the evidence, in `forensics/tools/pipeline.sh`'s order** (§6), in every commit.

---

## 2. Every new crate symbol the integration needs

One line each: symbol — authority coordinate — file that must define it — what to reuse instead.
"reuse" is read out of `src/ec/mod.rs`, `src/bn/` and `src/runtime/`, not assumed. Counts are from
`forensics/atlas/internal-symbols.json` and `forensics/phase8-obligations.json`.

### 2a. The keystone (`src/ec/lib.rs`, `crypto/ec/ec_lib.c`)

| what | coordinate | file | reuse |
|---|---|---|---|
| 6 internals | `ossl_ec_group_new_ex`, `ossl_ec_group_set_params`, `ossl_ec_group_do_inverse_ord`, `ossl_ec_group_simple_order_bits`, `ossl_ec_point_blind_coordinates`, `EC_pre_comp_free` | `src/ec/lib.rs` | `EcGroup`/`EcPoint`/`EcPreComp` (`ec/mod.rs`); `ossl_ec_wNAF_*` and `EC_ec_pre_comp_free` (`ec/mult.rs`, same commit) |
| 67 of the 69 exports | the forty-one `EC_GROUP_*`, the twenty-three `EC_POINT_*` accessors, `EC_POINTs_make_affine`/`EC_POINTs_mul`, `EC_METHOD_get_field_type` and `EC_KEY_get_ex_data`/`EC_KEY_set_ex_data` | `src/ec/lib.rs` | none: authority exports. `EC_GROUP_to_params`/`EC_GROUP_new_from_params` are the two withheld to step 9 |
| the three `ossl_inline` ladder helpers | `ec_local.h:762-798` — `ec_point_ladder_pre`/`_step`/`_post` | `src/ec/mod.rs` (beside D335's shapes) | `EC_POINT_copy`/`_dbl`/`_add` (this module). D335 named them and left them for item 4 |

### 2b. The field arithmetic (`src/ec/smpl.rs`, `src/ec/mult.rs`, `src/ec/oct.rs`, `src/ec/cvt.rs`)

| unit | coordinate | file | reuse |
|---|---|---|---|
| `ecp_smpl.c` | 32 internals `ossl_ec_GFp_simple_*`, export `EC_GFp_simple_method` | `src/ec/smpl.rs` | `BN_*`/`BnCtx`/`MontCtx`; `EcMethod` and the 27 `Ec*Fn` types it names; `ossl_ec_group_simple_order_bits` (`lib.rs`) |
| `ec_mult.c` | 6 internals — `ossl_ec_wNAF_mul`, `_precompute_mult`, `_have_precompute_mult`, `ossl_ec_scalar_mul_ladder`, `EC_ec_pre_comp_free`, `_dup` | `src/ec/mult.rs` | `bn_compute_wNAF` (step 2); `EC_POINT_*` (`lib.rs`); `ossl_ec_point_blind_coordinates` (`lib.rs`) |
| `ecp_oct.c` | 3 internals `ossl_ec_GFp_simple_{oct2point,point2oct,set_compressed_coordinates}` | `src/ec/oct.rs` | `EC_POINT_*` (`lib.rs`); D334's `EC_R_*` raise sites |
| `ec_oct.c` | 6 exports | `src/ec/oct.rs` | none: authority exports |
| `ec_cvt.c` | 2 exports `EC_GROUP_new_curve_GFp`/`_GF2m` | `src/ec/cvt.rs` | `EC_GFp_mont_method` (`mont.rs`), `EC_GF2m_simple_method` (`smpl2.rs`), `EC_GROUP_free` (`lib.rs`) |

### 2c. The three method tables (`src/ec/mont.rs`, `src/ec/nist.rs`, `src/ec/smpl2.rs`, and `ec2_oct.c`)

**The binary layer's size, measured rather than taken from the brief.** `forensics/atlas/ec-curves.json`
resolves each of `curve_list[]`'s 82 rows to the `EC_CURVE_DATA` structure it names: **42 rows are
characteristic-two and 40 are prime-field**, over **75** distinct structures (7 pairs share one
structure — `_EC_SECG_PRIME_112R1`, `_EC_SECG_PRIME_160R2` and five of the binary ones), of which 38
are prime and 37 binary. So the 38/37 split D334 attaches to the eighty-two rows is the split of the
**75 structures**, and the brief's "37 of the 82 `curve_list[]` rows are characteristic-two" is 37
structures over **42** rows. Neither changes what lands; both are recorded because the binary layer
is the half of the method tables that has no export of its own to court and its size is the only
thing that says how large it is.

| unit | coordinate | file | reuse |
|---|---|---|---|
| `ecp_mont.c` | 11 internals `ossl_ec_GFp_mont_*`, export `EC_GFp_mont_method` | `src/ec/mont.rs` | `MontCtx`/`BN_MONT_CTX_set`; `ossl_ec_GFp_simple_*` (`smpl.rs`) |
| `ecp_nist.c` | 4 internals, export `EC_GFp_nist_method` | `src/ec/nist.rs` | `BN_nist_mod_192`..`_521`; `EcFieldModFn` (`ec/mod.rs:560`) |
| `ec2_smpl.c` | 26 internals `ossl_ec_GF2m_simple_*`, export `EC_GF2m_simple_method` | `src/ec/smpl2.rs` | `BN_GF2m_*`; `EcGroup`'s `poly` at **72** (D335) |
| `ec2_oct.c` | 3 internals `ossl_ec_GF2m_simple_*` | `src/ec/smpl2.rs` | `BN_GF2m_mod_solve_quad_arr`/`_sqrt_arr`; `EC_POINT_*` (`lib.rs`) |

### 2d. The key layer (`src/ec/key.rs`, `src/ec/kmeth.rs`) and its two callers

| unit | coordinate | file | reuse |
|---|---|---|---|
| `ec_key.c` | 14 internals, 33 exports (incl. `EC_KEY_generate_key`) | `src/ec/key.rs` | `EcKey` (`ec/mod.rs`); `lib.rs`'s `EC_GROUP_*`/`EC_POINT_*`; `ecdh_ossl.rs`/`ecdsa_ossl.rs` |
| `ec_kmeth.c` | 1 internal (`ossl_ec_key_new_method_int`), 19 exports | `src/ec/kmeth.rs` | `EcKeyMethod` (`ec/mod.rs`); the default table's seven entries from `key.rs`, `ecdh_ossl.rs`, `ecdsa_ossl.rs` |
| `ecdsa_ossl.c` | 9 internals | `src/ec/ecdsa_ossl.rs` | `EcdsaSig`, `BN_*`, `lib.rs` |
| `ecdh_ossl.c` | 2 internals | `src/ec/ecdh_ossl.rs` | `lib.rs`, `bn/mod.rs` |

### 2e. The two BN units the closure reaches, with their coordinates

| symbol | coordinate | file | reuse |
|---|---|---|---|
| `bn_compute_wNAF` | `crypto/bn/bn_intern.c` | `src/bn/intern.rs` | `BN_is_odd`, `BN_num_bits` |
| `BN_GF2m_mod_sqrt_arr`, `BN_GF2m_mod_solve_quad_arr` | `crypto/bn/bn_gf2m.c` (`bn.h`, Phase 5) | **not written** — two deferral rows, `owner_phase: 9` | `phase9-obligations.json` already carries both as `open`; the deferral is the coordinate, not the body |
| `bn_copy_words`, `bn_get_words`, `bn_set_words`, `bn_get_dmax`, `bn_get_top`, `bn_set_static_words`, `bn_set_all_zero` | `crypto/bn/bn_intern.c` | `src/bn/intern.rs` | `BigNum` limbs; the crate's `bn_` naming |
| `bn_mod_exp_mont_fixed_top` | `crypto/bn/bn_exp.c` | `src/bn/exp.rs` | `MontCtx`; the crate's `BN_mod_exp_mont` (`src/bn/mont.rs`) |

### 2f. Reused, not written

`EcMethod`/`EcGroup`/`EcPoint`/`EcKey`/`EcKeyMethod`/`EcdsaSig`/`EcPreComp` and the 45 `*Fn` aliases
(`src/ec/mod.rs`); `BigNum`, `BN_*`, `BnCtx`, `MontCtx` and the `BN_mod_exp_mont` path (`src/bn/`);
`OpenSslStack`/`OPENSSL_sk_*`, `CryptoExData`, `CryptoRwlock`, `CRYPTO_zalloc`/`CRYPTO_free`/
`cleanse`, `raise_site` and `err_sites::EC_LIB_*`/`EC_R_*` (`src/runtime/`). `crash!`/`guard_ffi` are
**not** used by this layer: every entry point here takes pointers the authority dereferences without
a guard, exactly as `src/dsa/object.rs` records for DSA.

---

## 3. The cycle, and how it is measured rather than argued

**The claim, as measured.** `ec_lib.c`'s external name set is short and it names four other units
(D335): `ossl_ec_GFp_simple_set_Jprojective_coordinates_GFp`/`_get_…` (`ecp_smpl.c`, from
`EC_POINT_set_Jprojective_coordinates_GFp`/`_get_…`), `EC_nistz256_pre_comp_free`/`_dup`
(`ecp_nistz256.c`, from `EC_pre_comp_free` and `EC_GROUP_copy` under `#ifdef ECP_NISTZ256_ASM`, which
**is** defined here), `EC_ec_pre_comp_free`/`_dup` + `ossl_ec_wNAF_*` + `ossl_ec_point_blind_coordinates`
(`ec_mult.c`, `ec_lib.c`), and three `ec_backend.c` names. And `ecp_smpl.c` calls **eight**
`ec_lib.c` exports directly (`EC_POINT_dbl`, `_copy`, `_is_at_infinity`, `_set_affine_coordinates`,
`_get_affine_coordinates`, `_invert`, `_set_to_infinity`,
`_set_Jprojective_coordinates_GFp`) at `:496`, `:510`, `:624`–`:628`, `:713`, `:808`, `:942`,
`:966`, `:1076`–`:1080`, `:1173`, `:1188`–`:1190`, `:1656`–`:1660`. So the pair is a genuine cycle in
the authority's own text, and no order of the two units exists.

**The refinement this plan adds, and it is the one that makes the cycle affordable.** D335's
conclusion — "the *next* landing is items 2–6 together" — is correct about items 5 and 6 and stronger
than it needs to be about 2–4, because the gate's rule is asymmetric between a unit's **internals**
and its **exports**, and that asymmetry is readable in `prerequisite_gate.py`'s direction B:

```python
if name not in symbol_tu and language.get(name) is None:
    census["language_surface_not_modelled_by_name"].append(f"{tu}:{name}")
    continue
owner_tu = symbol_tu.get(name)
if owner_tu is None:
    census["language_surface_not_modelled_by_name"].append(f"{tu}:{name}")
    continue
```

A name that is an **export** is never in `symbol_tu` (that universe is
`internal-symbols.json`'s) and is never a macro or typedef, so it falls into
`language_surface_not_modelled_by_name` — the census, "counted, never a failure" — and is skipped.
Only an **internal** whose defining unit has a crate module reaches the finding. `ec_curve.c`'s two
withheld constructors are exports and are censused today for exactly this reason; its one withheld
internal is a divergence row.

**What that buys.** A unit may be given a module with its exports partly withheld, provided every
internal it **defines** is either defined or referenced by that module — and provided no module
*references* an unbuilt name, which is direction A and has no unit-level escape at all (§4). So
`ec_lib.c` can land with 67 of its 69 exports and its six internals whole; `ec_curve.c` keeps its
withheld pair **inside `src/ec/curve.rs`**, which already exists; and the commit's real boundary is
the closure below rather than "sixty-nine exports".

**The closure of steps 4–6, measured with the gate's own universes** (every name the commit's units
call that is not built and is not defined by the commit itself):

| name | kind | defining unit | how it is discharged |
|---|---|---|---|
| `EC_GROUP_new_curve_GF2m`, `_GFp` | export | `ec_cvt.c` | **landed in the same commit** (`src/ec/cvt.rs`) |
| `EC_GROUP_new_by_curve_name_ex` | export | `ec_curve.c` | **landed in the same commit** (step 6) |
| `ossl_ec_curve_nid_from_params` | internal | `ec_curve.c` | **landed in the same commit**; D334's seventh divergence row is **retired** |
| `bn_compute_wNAF` | internal | `crypto/bn/bn_intern.c` | **landed first** (step 2) |
| `bn_mod_exp_mont_fixed_top` | internal | `crypto/bn/bn_exp.c` | **landed first** (step 2) |
| `EC_nistz256_pre_comp_dup`, `_free` | internal | `ecp_nistz256.c` | **§8's divergence** — the field construction is perlasm-only, so the unit is not given a module |
| `ossl_ec_GF2m_simple_{oct2point,point2oct,set_compressed_coordinates}` | internal | `ec2_oct.c` | **landed in step 5** (`src/ec/smpl2.rs`) |
| `ossl_ec_group_todata`, `ossl_ec_encoding_param2id`, `ossl_ec_pt_format_param2id` | internal | `ec_backend.c` | **landed in step 9**, with `crypto/param_build_set.c` |
| `BN_GF2m_mod_sqrt_arr`, `BN_GF2m_mod_solve_quad_arr` | export | `crypto/bn/bn_gf2m.c` (Phase 5's, Phase 9's ledger) | **two deferral rows, `owner_phase: 9`** — they cannot be landed here without moving a sealed stratum's ledger backwards |

Every row is a *named coordinate*; none is a stub, a `None` in a table, or an early return. The last
row was found by this closure table rather than by reading, and it is the reason the binary-curve
step carries a deferral rather than a second BN module: it is the one place in this plan where the
closure reaches *backwards* into an already-sealed stratum's ledger.

---

## 4. The gate and coverage consequence of each module boundary

`court_coverage.py` reads the **candidate probe binary's undefined dynamic symbols**, so every
implemented export must be *imported by a staged probe that ran*. The gate reads
`src/**/*.rs` twice — once with string literals blanked (a *reference*) and once with them kept (a
*definition*) — so a module's boundary has two distinct consequences, and this table is the reason
the plan's steps are safe to take one at a time.

| module added | gate consequence | coverage consequence |
|---|---|---|
| `src/bn/intern.rs`, `src/bn/exp.rs` | two new units (`crypto/bn/bn_intern.c`, `bn_exp.c`) enter `transcription-edges.json`: `crate_modules` 288 -> 290, `authority_units` 216 -> 218. Direction B now applies to **9** BN internals; all 9 are defined, so zero findings. No export, so `implemented-surface.json` and both ledger lists do not move. `crypto/bn/bn_gf2m.c` already has a module, so its two Phase-9 names are **census** entries today and become direction-A references the moment `ec2_oct.rs` calls them — which is what the deferral rows of step 2 are for | none: no export |
| `src/ec/lib.rs` | one unit (`ec_lib.c`, 69 exports / 6 internals) -> `crate_modules` 291, `authority_units` 219. Direction B sees the unit's **six** internals; all six are defined. `language_census` rises by the unit's macro surface (`BN_num_bytes`, `ERR_raise`, `OPENSSL_free`, …) — counted, never a failure — **unless the transcription names one**, which is why every C macro is *expanded* at its site (`ERR_raise` becomes `raise_site(&err_sites::EC_LIB_nnn)`) and never written as a Rust identifier | **67 exports land**, so 67 new rows must be `directly_courted`. `EC_GROUP_to_params`/`EC_GROUP_new_from_params` stay `open` and need no arm |
| `src/ec/smpl.rs` | `ossl_ec_GFp_simple_*` (32) become internals of a unit with a module: each must be defined or referenced. The module defines all 32. One export lands (`EC_GFp_simple_method`) | **1** new directly-courted row. It is callable with **no arguments** — `EC_METHOD *EC_GFp_simple_method(void)` — so the arm is a direct call and needs no `EC_GROUP`; the same is true of the other three |
| `src/ec/mult.rs`, `src/ec/oct.rs`, `src/ec/cvt.rs` | `ec_mult.c` (6 internals) and `ecp_oct.c` (3) enter; `ec_oct.c` (6 exports) and `ec_cvt.c` (2) add no internal. `EC_ec_pre_comp_dup`/`_free` (D334's named `ec_local.h` internals) remain the only EC names in `dispatch_court.py`'s new `EC_METHOD_VTABLE` family's neighbourhood and are **not** `*Fn` aliases, so `unlinked` stays 0 | **8** new exports across `ec_oct.c` and `ec_cvt.c`; each needs an arm |
| `src/ec/mont.rs`, `src/ec/nist.rs`, `src/ec/smpl2.rs` | three units with **41** internals and 3 exports. The `EC_METHOD` initialisers name eleven columns from `ec_key.c`, `ecdh_ossl.c` and `ecdsa_ossl.c` (§5 of D335) — those are **unbuilt names referenced**, which is direction A and has no unit-level escape: **the two signature/shared-secret modules and the key layer must be in the same commit, or this row is a finding**. That is the one place in this plan where a tidy-looking split is impossible | **3** new exports (`EC_GFp_mont_method`, `EC_GFp_nist_method`, `EC_GF2m_simple_method`), each a no-argument call |
| `src/ec/curve.rs` (edited) | no new module, no new unit; two exports move from the census to `built`, so `checked.names_referenced_and_not_built` **decreases** by 2 and the ledger's `open` shrinks by 2 | **2** new directly-courted rows, and D-EC-1's replacement arm (§8) |
| `src/ec/key.rs`, `src/ec/kmeth.rs` | 14 + 1 internals, 52 exports. `ossl_ec_key_new_method_int` is the unit's only internal and is referenced by `EC_KEY_new_method`. The unit's seven `EC_KEY_METHOD` columns name `ecdsa_ossl.c`'s and `ecdh_ossl.c`'s functions, so step 8 must already have landed | **52** new exports. `EC_KEY_generate_key` retires `forensics/phase8-obligations.json`'s `deferred` row, which moves `deferred` 2 -> 1 and `implemented` by the same amount |
| `src/ec/ecdsa_ossl.rs`, `src/ec/ecdh_ossl.rs` | 9 + 2 internals, no exports of their own: no ledger movement, but the two tables of step 5 cannot be *written* without them (§1 step 8) | none directly; their effect is observed through `EC_KEY_sign`/`_verify`/`_compute_key` |
| `src/ec/backend.rs` (+ `param_build_set.c`) | 17 + 4 internals. `ossl_ec_group_todata` is covered today by the same class of record D330 recorded for it; landing it retires that record. `ossl_x509_algor_is_sm2` is named only by the provider half and stays with it | **2** new exports (`EC_GROUP_to_params`, `EC_GROUP_new_from_params`) |

**The four `*Fn` families.** Steps 4–8 add no alias *family*: the 45 aliases are already declared in
`src/ec/mod.rs` and are already registered in `dispatch_court.py` under `EC_METHOD_VTABLE`,
`EC_KEY_METHOD_VTABLE` and `EcFieldModFn`, with `unlinked=0 exempted=182 problems=0`. What the steps
add is *users* of those aliases, which is what `dispatch_court.py` counts as linked; the plan
therefore asserts no new family and the check is that the report stays `unlinked=0`.

---

## 5. The court arms to add, and the ones that stay owed

`RT-EC` is one differential probe compiled twice; the arms below are ordered by the commit that
makes them pass. Every arm compares two executions, prints a verdict and never a secret.

**Step 4's arms — the group and point objects.** `EC_GROUP_new_curve_GFp` over `secp256r1`'s own
`p`, `a`, `b`; `EC_GROUP_get_curve`/`_get_order`/`_get0_cofactor`/`_get0_generator`/`_get0_seed`;
`EC_GROUP_get_degree`/`_get_field_type`/`_method_of`; `EC_GROUP_copy`/`_cmp`/`_dup`; every
`EC_POINT_*` accessor over a generator and its double; `EC_POINT_set/get_Jprojective_coordinates_GFp`;
`EC_POINTs_make_affine` over a three-point array; `EC_POINT_mul` with a NULL generator (the ladder),
with an explicit generator array, with a NULL `n` (the generator's order) and with **both** scalars
NULL, which answers the point at infinity without raising (`ec_lib.c:1132-1133`); and the refusals
the authority raises — `EC_R_INCOMPATIBLE_OBJECTS` for a point of another group,
`EC_R_INVALID_FIELD`/`EC_R_INVALID_A`/`_B`/`_P` from `EC_GROUP_set_curve_GFp`, and
`EC_R_INVALID_GROUP_ORDER`/`EC_R_INVALID_COFACTOR`/`EC_R_INVALID_GENERATOR`/
`EC_R_INVALID_NAMED_GROUP_CONVERSION` from `EC_GROUP_set_generator`.

**Step 5's arms — the four method tables.** Each of the four constructors is called directly and its
`EC_METHOD_get_field_type` answer printed (406 for the three prime tables, 407 for the GF(2^m) one).
That one line is what makes the *table* the subject rather than the group: a method table whose
`field_type` moved is a different curve family, and no `EC_GROUP` is needed to see it.

**Step 6's arms — the constructors and the method-column boundary.** `EC_GROUP_new_by_curve_name`
over all eighty-two NIDs, each group's `EC_GROUP_method_of` printed **by identity** — the probe
compares it against `EC_GFp_simple_method`/`EC_GFp_mont_method`/`EC_GF2m_simple_method`, which it
also calls, rather than printing a pointer. This arm is D-EC-2's observable consequence and is the
tripwire for it: `NID_X9_62_prime256v1` answers `EC_GFp_simple_method` here where the authority
answers `EC_GFp_nistz256_method` (§8).

**Step 7's arms — the key layer.** `EC_KEY_new_by_curve_name`, `EC_KEY_set_private_key`/
`set_public_key`, `EC_KEY_check_key`, `EC_KEY_priv2oct`/`oct2priv`/`key2buf` and their inverses,
`EC_KEY_dup`/`_copy`, and `EC_KEY_generate_key` — a *generated* key, so the arm asserts properties
(the public point is on the curve, `EC_KEY_check_key` agrees, two generations differ) and prints no
private value. `EC_KEY_get_default_method`/`EC_KEY_OpenSSL` identity, and the seven
`EC_KEY_METHOD_get_*`/`set_*` pairs over a table the probe builds itself.

**Step 8's arms.** One ECDSA sign/verify round trip over a generated key per prime family, an
`ECDSA_do_sign`/`_do_verify` pair, the `EC_KEY_check_key` refusal for a public key not on the curve,
and `ECDH_compute_key` on both sides of a generated pair — the shared secret is **not printed**: the
arm prints the two sides' *agreement* and the length, which is the whole of what the authority's
contract exposes to a differential court. Deterministic known answers come from the corpus, not from
that arm.

**The arms that stay owed, named rather than skipped.** `EC_GROUP_to_params`/
`EC_GROUP_new_from_params` are step 9's and stay `open` and uncalled until it lands;
`EC_GROUP_have_precompute_mult`/`_precompute_mult` and `EC_KEY_precompute_mult` are courted only
through `EC_POINT_mul`'s ladder arm, because a pre-computation table is a cache and its *effect* is
what `EC_POINT_mul` compares; and no arm calls any `ossl_ec_GFp_nistz256_*` symbol, because §8's
divergence says the crate does not have them.

**Court hygiene.** No arm prints a private key, a shared secret, a k value or a blinding factor. The
two arms that generate material print verdicts and lengths; the two that would otherwise be vacuous
(`EC_GROUP_get0_field`, `EC_METHOD_get_field_type` on a group the probe did not build) are not added,
because a symbol already directly courted by a *call* is not made better by a second import.

---

## 6. The evidence bookkeeping

**Generators.** `forensics/tools/gen_ec_curves.py` is already registered in
`evidence_determinism.py`'s `GENERATORS_BEFORE_LEDGERS`, in `pipeline.sh`'s Phase-8 table block and in
the `COMPARED` set. Step 6 changes its **input side** (`curve_list[]`'s fourth column resolves to a
method for every row) and not its schema: `forensics/atlas/ec-curves.json`'s
`method_column_has_one_non_null_row` check becomes `method_column_resolves_for_every_row` with the
divergence named, and the generator must fail if a row's method is absent from the commit's five
tables. That check is this slice's first fail-closed arm and §7 reconstructs its failure.

**Error sites.** `gen_err_raise_sites.py`'s `COVERED_FILES` gains the units of steps 2, 4, 5, 7, 8
and 9 — `crypto/ec/ec_lib.c`, `ecp_smpl.c`, `ecp_oct.c`, `ec_oct.c`, `ec_cvt.c`, `ecp_mont.c`,
`ecp_nist.c`, `ec2_smpl.c`, `ec2_oct.c`, `ec_mult.c`, `ec_key.c`, `ec_kmeth.c`, `ecdsa_ossl.c`,
`ecdh_ossl.c`, `ec_backend.c`, `crypto/bn/bn_intern.c`, `crypto/bn/bn_exp.c` — and
`src/runtime/err_sites.rs` moves by the count the lexical scan reports, as D334's sixteen coordinates
did. `<openssl/ecerr.h>` is already in the resolver's include set.

**Ledgers.** `forensics/phase8-obligations.json` moves by the number of exports landed. The block has
**194** ec-related `open` rows; **149** of them are this layer's, and the other 45 are
`ec_asn1.c`'s (27), `crypto/evp/ec_ctrl.c`'s (12), `eck_prn.c`'s (4) and `ec_ameth.c`'s (2), which
are 8.8's and slice E's. The 149 split as: 76 with step 4 (`ec_lib.c`'s 67, `ecp_smpl.c`'s 1,
`ec_oct.c`'s 6, `ec_cvt.c`'s 2), 3 with step 5, 2 with step 6, 52 with step 7, 8 with step 8
(`ecdsa_sign.c`'s 5, `ecdsa_vrf.c`'s 2, `ecdh_kdf.c`'s 1), 6 with the step that first gives them
their callees (`ec_check.c`'s 2, `ec_print.c`'s 2, `ec_deprecated.c`'s 2 — all of them wrappers over
the functions above) and 2 with step 9. `deferred` moves 2 -> 1 when step 7 retires
`EC_KEY_generate_key`, and `forensics/atlas/implemented-surface.json`'s `libcrypto` implemented moves
by the same total. `forensics/prerequisites.json` loses the row for `ossl_ec_curve_nid_from_params`
(step 6), gains two deferral rows for the GF(2^m) pair (step 2) and gains §8's row; a divergence row
is **retired only by the commit that makes the name buildable**, which is why step 6 owns that edit.

**Transitions.** `regression_guard.py` watches `prerequisites[sealed_census]` and
`blocking_dependencies`. Giving a unit a crate module can only **decrease** `sealed_census` (a name a
sealed stratum's module no longer needs to answer) and landing callees can only **decrease**
`blocking_dependencies`; a decrease needs no row. An *increase* in either would mean a step added a
module whose closure names a sealed stratum's internal, which by §3 cannot happen for these units —
so this plan expects **no** `forensics/ownership-transitions.json` row, and says so in advance rather
than after the guard reports.

**Docs.** `docs/PHASE-8-SUBPHASES.md`'s 8.7 row and its clause-anchored narrative move with each
commit, in both directions, because `docs_consistency.py`'s `phase8_active_status` compares every
backticked identifier in the two anchored paragraphs with the ledger **per symbol**: a landed export
left in the open clause, and an open one left in the landed clause, are each a failure. The two
paragraphs are therefore edited in the same commit as the ledger, never afterwards.

---

## 7. Falsification tests

Each of these is a check that must be able to *fail*, reconstructed rather than asserted. The
precedent is `blocker_liveness.py --self-test` and `gen_provider_algorithms.py --self-test`, both of
which the pipeline runs.

1. **The curve table's method column, at step 6 (`gen_ec_curves.py`).** *The check:* every
   `curve_list[]` row resolves to one of the commit's four `EC_METHOD`s, and the one row the
   authority gives `EC_GFp_nistz256_method` resolves to `EC_GFp_simple_method` **and is named in the
   divergence record**. *Falsified by:* deleting one row's method from the crate's table -> the
   generator must fail by NID; and by giving the prime256v1 row `EC_GFp_nistz256_method` ->
   the generator must fail because no crate module defines that symbol, which is §8's boundary
   stated as code.
2. **The gate's export/internal asymmetry, at step 4 (`prerequisite_gate.py`).** *The check:*
   `ec_curve.c`'s two withheld constructors are censused rather than failed. *Falsified by:* a
   temporary module defining any of the commit's 67 landed `EC_GROUP_*`/`EC_POINT_*` **internals** and
   referencing only half of them -> the gate must report `unwired_function_in_the_current_stratum`
   for each withheld internal, and must report *nothing* for a withheld export. D336's measurement is
   the same construction the other way round (a module referencing an unbuilt **export** produced
   `undefined_prerequisite`, five times), so both halves of the rule have a recorded run.
3. **The closure, at every step (`prerequisite_gate.py`).** *The check:* every name in §3's table is
   discharged by the step that names it. *Falsified by:* landing `src/ec/mont.rs` without
   `src/ec/key.rs` and `src/ec/ecdsa_ossl.rs`/`ecdh_ossl.rs` -> the gate must report
   `undefined_prerequisite` for the eleven `EC_METHOD` columns those units supply. This is the step
   that makes the "one commit" claim falsifiable rather than rhetorical.
4. **The nistz256 divergence, at step 1 (`courts/phase8/rt_ec_probe.c`).** *The check:* the probe
   compares `EC_GROUP_method_of(EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1))` against
   `EC_GFp_simple_method` on **both** sides' asserted identity, and the transcript carries the
   residual. *Falsified by:* making the probe compare pointers instead of identities -> the arm
   becomes incapable of reporting the divergence and must fail its own self-check.
5. **`court_coverage.py`, at every step.** *The check:* every landed export is an undefined dynamic
   symbol of a staged candidate probe. *Falsified by:* removing one arm from §5 -> the coverage atlas
   must name the export it lost, out of 176 new names, with no other movement.
6. **The ledger clauses, at every step (`docs_consistency.py`).** *The check:* the two anchored
   paragraphs agree with `forensics/phase8-obligations.json` in both directions. *Falsified by:*
   moving one landed export into the open clause -> `phase8_active_status` must fail naming it.
7. **The BN closure, at step 2.** *The check:* `bn_intern.c`'s eight internals are whole. *Falsified
   by:* landing `bn_compute_wNAF` alone in a module named for the unit -> the gate must report
   `unwired_function_in_the_current_stratum` for the other seven, which is the case D327's rule
   exists for and the reason this plan's step 2 has no smaller form.

---

## 8. The nistz256 boundary, and the divergence the landing records

**What is not transcribed, and the coordinate.** `crypto/ec/ecp_nistz256.c`'s method table
(`:1569-1630`) is ordinary C and its two pre-computation functions are ordinary C, but every field
operation it names — `ecp_nistz256_mul_mont`, `_sqr_mont`, `_point_add`, `_point_double`,
`_gather_w5`/`_scatter_w5` and the rest — is `crypto/ec/ecp_nistz256-x86_64.s`, generated by
perlasm from `asm/ecp_nistz256-x86_64.pl`, with **no `#else` arm** in
`crypto/ec/ecp_nistz256-x86_64.c` (D334 measured this). Inventing a construction for them would be
the fabricated value D334 refused for `curve_list[]`'s fourth column, one level down; and D274's
rule, which lets the crate supply a construction for a perlasm-only function and make `RT-EC` the
court that proves it is *this* implementation's behaviour, is not available either — a
Montgomery-domain representation is observable through every subsequent multiplication, so a
different construction is a different curve arithmetic rather than a different instruction schedule.

**The boundary, stated as a divergence.** `docs/SECURITY_DIVERGENCE_POLICY.md` gains **D-EC-2**:

- **Obligation:** the method identity `EC_GROUP_method_of` reports for
  `EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)`, and every point operation performed on that
  group's `EC_METHOD`.
- **Authority:** `EC_GFp_nistz256_method` — the one non-NULL value of `curve_list[]`'s fourth column
  on this profile.
- **Crate:** `NID_X9_62_prime256v1`'s row resolves to `EC_GFp_simple_method`, as every NULL row does
  through `EC_GROUP_new_curve_GFp`; `ec_group_new_from_data` is transcribed whole and its `curve.meth`
  branch is real, but the field it reads is the divergence.
- **Reason:** §8's first paragraph. The refusal is D334's, applied one level down: a perlasm-only
  function with no portable arm is not inventable, and this one's representation is observable.
- **Observable consequences, which are what make it a divergence rather than an omission:** (a)
  `EC_GROUP_method_of` answers `EC_GFp_simple_method` where the authority answers
  `EC_GFp_nistz256_method` — one comparison in `RT-EC`, printed by identity; (b) every
  `NID_X9_62_prime256v1` operation runs the generic Weierstrass ladder rather than the 4-limb
  Montgomery arithmetic, so a `secp256r1` signature is the same *value* on both sides (the arithmetic
  is the same group) but not the same *code path*; (c) `EC_nistz256_pre_comp_free`/`_dup` are not
  defined, so `EC_GROUP_copy` and `EC_pre_comp_free` do not transcribe their two `#ifdef
  ECP_NISTZ256_ASM` arms — an omission that is unreachable while no nistz256 group can be
  constructed, and is named here rather than left as an untaken branch.
- **Claim removed:** the method identity of the one curve, and the nistz256 pre-computation path.
  Nothing else: all eighty-two rows, both constructors, every field operation of the four landed
  methods and all three name lookups are claimed and courted.
- **Trigger:** the slice that supplies a construction for the perlasm unit — at which point the
  column is written, `EC_GFp_nistz256_method` is defined, and this entry is removed with the
  `RT-EC` arm that observes the identity.
- **Supersedes D-EC-1**, whose subject was the same column recorded as "not transcribed": D-EC-2 is
  the same boundary with the answer the landing actually gives, which is stronger than a NULL because
  it is a stated behaviour a court can compare.

**`EC_GFp_nist_method` is *not* affected** and is landed in step 5: `ecp_nist.c` is ordinary C over
`BN_nist_mod_192`..`_521`, which the crate has, and `EC_GROUP_method_of` reports it for the curves
whose rows name it.
