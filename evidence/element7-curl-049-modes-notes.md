# E7 modes composition-gap batch — checkpoint notes

Branch `staging`, HEAD `1f65b8544` (clean at start). No commit/push.
`src/`, `Cargo.toml`, `Cargo.lock` untouched. Tool under change:
`forensics/tools/consumer_closure.py`.

Scope: the 21 `modes` sites — 14 local copies of exported names
(`CRYPTO_cfb128_encrypt`, `ofb128`, `cbc128`, `ctr128`, `ctr128_encrypt_ctr32`,
`cfb128_1_encrypt`) refusing `caller-supplies-an-object-field`, and 7
`wrap128`/`wrap_pad` sites refusing `caller-value-escapes-into-an-object-field`.

(Header written first so a transport failure cannot lose the index.  Entries
appended per step below.)

## Step log

1. Read the E7-LCP/E7-LEW notes, the triage and the two adjacent note files.
   Confirmed the 21 pins in `E7LCP_SITES`.
2. Image reconnaissance (libssl `DsoGraph` + `PrecisionResolver`, read-only
   probes under `court/tmp/modes/probe_*.py`):
   - the 14 sites' callers are three shapes: a fixed `lea <block fn>`; a
     `move 0x30(%param),%reg` load of `ProvCipherCtx.block` (Option, guarded by
     `ctx_block!`); and a load of the legacy `EvpAesKey`/`EvpCamelliaKey`/
     `EvpSm4Key.block` through `(*ctx).cipher_data` at 0x78 (non-Option,
     unguarded, covered by the S7a init-before-use premise).
   - the 7 wrap sites' callers: `wrap128` has 4 direct callers
     (`CRYPTO_128_wrap`, `CRYPTO_128_wrap_pad`, legacy `e_aes::aes_wrap_cipher`
     passing `lea aes_encrypt_block`, `AES_wrap_key` passing
     `lea aes::aes_encrypt_block`).  The two wrappers are reached only through
     the `ProvAesWrapCtx.wrapfn` field, stored by `aes_wrap_init` at compiled
     offset 0x1B8 and dispatched once at `aes_wrap_cipher+0x15B`
     (`0x2009eb`, `call *%r11`), guard-dominated, with argument 6 = the
     `ProvCipherCtx.block` load at 0x30 (also guard-dominated).
   - every writer store is at the expected compiled displacement
     (0x30, 0x1B8, and 0x0 for the three legacy keys).
3. Implemented the composed witness (new `E7-CLS` section).
4. Python syntax OK (48643 lines).

## Final result (this candidate)

21 seeded, **17 bound / 4 refused**.  Full closure **NOT_RUN**.

| sub-group | sites | bound | refused |
|---|---|---|---|
| 14 exported-name copies | 14 | 10 | 4 |
| 7 `wrap128`/`CRYPTO_128_wrap_pad` | 7 | 7 | 0 |

- **cfb128_encrypt** 4 bound (19 targets: provider `block` 9, legacy
  `EvpAesKey`/`EvpCamelliaKey`/`EvpSm4Key.block` 2+2+4, direct
  `aes_encrypt_block`/`seed_block_encrypt`/`aria_encrypt_block` 5).
- **cbc128_encrypt** 2 bound (19, same union).
- **ctr128_encrypt** 2 bound (18: no SEED direct caller).
- **ctr128_encrypt_ctr32** 2 bound, **proved empty**: parameter 7 is
  `Evp*Key.stream_ctr`, written only with `None`; the `if let Some(f)` arm is
  dead.
- **wrap128** 6 sites bound (11 targets: 9 `ProvCipherCtx.block` values + the
  two `aes_encrypt_block` copies 0x335cd0/0x431620).
- **CRYPTO_128_wrap_pad** 1 bound (10: the same field values + 0x335cd0).

### Refusals (4), with the evidence that would close each

- **ofb128_encrypt ×3** — `caller-set-not-closed`.  The only open caller is
  `ossl_cipher_hw_chunked_ofb128` at 0x20e13d.  The field is guarded twice
  (0x20e0eb/0x20e0ee before the loop; 0x20e161/0x20e170 on the back edge), but
  `_e7cls_guard_cover` requires the covering test to precede the site in
  instruction order, so it cannot cover the loop-carried reload at 0x20e161.
  Closing evidence: a loop-aware dominance proof (the back-edge guard dominates
  the next iteration's store), not a widening of the guard rule.
- **cfb128_1_encrypt ×1** — `caller-set-not-closed`.  The first call site of
  `camellia_cfb1_cipher`/`aes_cfb1_cipher` now resolves (one-hop spill at
  `0x8(%rsp)` from `0x78(%ctx)`), but the two later sites reload the same slot
  across balanced `push`/`add $0x10,%rsp` sequences.  `_e7cls_ctx_loads`
  refuses any `%rsp` write between the spill and the reload.  Closing evidence:
  a frame-slot stability proof that tracks the net `rsp` delta (0 at the store
  and the reload) and excludes aliasing accesses at the shifted offset.

### Escape accounting (the withdrawal lesson)

The single code-materialised escape in this family is
`aes_wrap_init` 0x1ff062 (`lea CRYPTO_128_wrap_pad`).  It is accounted only
because the new `_e7cls_writer_lea_provenance` shows the `lea` reaches the
`wrapfn` store at 0x1ff093 through the `cmovne` at 0x1ff08f.  A `lea` merely
co-located in a writer now refuses (`e7cls-unconsumed-escape` is the rule, not a
switch).  `CRYPTO_128_wrap_pad` binds on that proof.

### Controls (all load-bearing)

- `e7cls-second-writer`: a synthetic production writer ->
  `field-writer-set-not-enumerated`; the positive witness restores exactly.
- `e7cls-new-target`: a new reachable target moves the reported set by exactly
  the pinned function start and loses none.
- `e7cls-field-base-any`: flips the wrong-base refusal at the attribution
  helper (`ossl_cipher_hw_chunked_ofb128`, `%r13`).
- `e7cls-no-field-guard`: admits the ofb site (the guardless arm flips to
  resolved).
- `_e7cls_self_test` is candidate-bound: `NOT_RUN` if `libssl.so.3` or
  `nm`/`objdump` is absent.  It also asserts the wrap set contains both an
  `address` and a `field` caller, and that `ctr32` is the empty set.

### Validation

- `python3 forensics/tools/consumer_closure.py --self-test` -> **rc=0**,
  `self-test ok`, 0 `FAIL` lines, the E7CLS line present.
- Targeted re-resolution: 21 seeded, 17 `CLOSED_TARGET_SET_COMPOSED_FIELD`,
  4 refused (`E7CLS_composed_field_refused=4`), 4 `E7LCP` refusals.
- Peak `memory.current`: self-test 2,514,989,056 B (~2.34 GiB); targeted
  re-resolution 2,049,716,224 B (~1.91 GiB).  `free -g` available 33 GiB
  immediately before each; `OPENSSL_RS_COURT_DATA=8388608`.  Both runs were
  repeated against the final source (after the `proved_empty` field and the
  accounting docstring).
- No Rust change, so no `fmt`/`clippy`/`cargo test` gate was run.
- Artifacts: `court/tmp/modes/{reresolve.json,reresolve.log,selftest.log,
  run_peak.py,probe_verify.py,probe_rows.py,probe_refuse.py}`.

### Residuals (plainly)

1. The writer scan is source-level (`src/`); a macro/include-emitted writer
   would not be scanned.
2. The legacy non-`Option` `Evp*Key.block` fields retain the S7a
   init-before-use ordering, an external obligation, not a guard.
3. A value name with several in-image copies contributes every copy (safe
   over-approximation).
4. Relocation-slot escapes (none in this family) still use the older
   co-location rule; only code-materialised escapes have the store-provenance
   check.
5. Legacy field attribution is textual (`cast::<T>()` / accessor return type);
   it does not tie the cast variable to the loaded pointer by dataflow.
6. `CLOSED_TARGET_SET_COMPOSED_FIELD` is reported as a closed set but is
   deliberately absent from the ABI->closed table; the registry cross-check is
   untouched.
7. The E7CLS controls are bound to this candidate's pins and image; a re-freeze
   must re-run them.

### Queue after

modes **4** (ofb 3, cfb1 1).  Then http 4, p12 1, and the 23 named rest
refusals: **32 named rows** by the running count.  Element 7 remains **FAIL**;
`safe_compatible_curl` is **NOT ESTABLISHED**; no consumer graduates.
