# PFP-54 — resolving the fully-inlined SOS kernel through detached DWARF

**State: DONE.** One release compilation produced a debug-stripped shipped DSO
and a detached DWARF companion bound to it by build-id. The branch audit resolves
all **31** targets, including `arith::mont_mul_sos_into`, whose only body is
inlined into `mont_mul_fallible`. The audit observed **no secret-derived
conditional transfer and no secret-derived memory address**. Release-gate item 11
changed from `RG_AUDIT_IDENTITY_MISMATCH` to **passing**; the gate went from
**36** to **35** refusals and no `RG_AUDIT_*` or `RG_DOCS` line remains.

## 1. Route and why

**objcopy** (`--only-keep-debug`, `--strip-debug`, `--add-gnu-debuglink`), not
`-C split-debuginfo`. The product is a **hand-linked DSO**: the crate's staticlib
`libopenssl_rs.a` is linked with `cc -shared`, so rustc's own link step (where
`split-debuginfo` acts) is not the step that produces the shipped file. objcopy
operates on the exact linked DSO, so the DWARF and the shipped bytes come from one
link, and `--add-gnu-debuglink` leaves the standard CRC fallback binding.

**One build-flag change is required and none other:** `CARGO_PROFILE_RELEASE_DEBUG=1`
(debuginfo level 1). Without it the crate emits no crate DWARF at all (PFP-54's
finding), so no `DW_TAG_inlined_subroutine` exists to resolve. Level 1 emits
function names, line structure and inlined-subroutine scope DIEs; it does **not**
add local variable names. No source file is changed; `#[inline(never)]` was not
added. The product `.text` is unchanged by the flag (below: the pre-split and
shipped `.text` hashes are identical, and the audit's codegen is the shipped
codegen).

## 2. Identity, artefacts, digests

| | |
|---|---|
| branch / `HEAD` | `staging` / `f536fd63913073bab76f839d41e89617da4fa74c` |
| tree | `4fef3b02666120f261bc00c43e2e6e04c50cd013` |
| `HEAD:src` | `3b3a9e5c66896c761370c3679c16fe3afb187518` |
| dirty build-relevant tree | empty |
| rustc / cc / binutils | `1.98.1 (48a229cea)` / Debian 12.2.0 / GNU 2.40 |
| target | `x86_64-unknown-linux-gnu`, release |

| artefact | sha256 | bytes |
|---|---|---:|
| archive `libopenssl_rs.a` | `0c8a178848ea8f4307612f7512bcc0b00e66176260134cb6a6076be8aca26081` | — |
| linked (pre-split) DSO | `cd741ea724417614b34ca8e702f74f49da4b8b19ed14093101bbaf9383ba1f98` | 36,687,088 |
| **shipped** `artefacts/libcrypto.so.3` | **`a535454753d8857e4c385689ea431b5a47a9686322e6f52b203971188a49359f`** | 12,342,512 |
| **debug** `artefacts/libcrypto.so.3.debug` | **`cd64dd590a597116f8475f6db0c81cc94602d74d540d4b45b4b1bae1a0b7ed9b`** | 27,318,296 |
| `.text` (linked **and** shipped) | `9bf370d46142f2de2c6f62a7ef028c1203ccc3f24d27de78d8750c76b9a842fa` | — |
| GNU build-id (both files) | `83eccb95e79216e5b53b46389df55fda6f9a9dee` | — |

The shipped DSO carries **0** `.debug_*` sections; the companion carries **8**
(`.debug_info`, `_abbrev`, `_line`, `_str`, `_ranges`, …). Both remain under
`evidence/performance-frontier/campaigns/PFP-54/raw/artefacts/`. `Cargo.toml`
excludes `evidence/**`, and `cargo package --list --allow-dirty` names neither
artefact (0 matching lines).

## 3. The three correspondence checks (measured, `raw/correspondence.json`)

1. **Shipped `.text` = audited `.text`.** The audit report records
   `` `.text` SHA-256: 9bf370d4… ``; an independent `objcopy --dump-section .text`
   over the shipped file gives the same `9bf370d4…`. PASS.
2. **Build-id present and identical.** `readelf -n` gives
   `83eccb95e79216e5b53b46389df55fda6f9a9dee` in **both** the shipped DSO and the
   debug file; the audit tool refuses (exit 3) if they differ. PASS.
3. **Debug file is evidence, not shipped.** It lives at
   `…/PFP-54/raw/artefacts/libcrypto.so.3.debug`; the shipped file has 0 debug
   sections; `cargo package --list` does not include it. PASS.

A fourth, derivative control is in the tests: a debug companion built from a
different binary is refused with exit 3 (`debug-identity-mismatch`).

## 4. Inlined-extent resolution (`raw/inlined-extent.json`)

Established from the detached DWARF, not asserted:

- abstract subprogram DIE `0x7c169b`, linkage
  `_RNvNtNtCsdvWjcJp1SsP_10openssl_rs2bn5arith17mont_mul_sos_into`, decl line 1916;
- **one** `DW_TAG_inlined_subroutine` (`0x7c18c0`, `DW_AT_ranges 0x22db90`, call
  line 2275) refers to it — the target is inlined into **one** concrete caller;
- caller `mont_mul_fallible`, DIE `0x7c16cf`, extent `0x1664a0..0x166bb7`, which
  equals the shipped symbol `…17mont_mul_fallible` at `0x1664a0` size `0x717`;
- the recorded extent is four ranges, all inside the caller and all audited:

| range | bytes |
|---|---:|
| `0x16657b..0x166592` | 23 |
| `0x166753..0x166852` | 255 |
| `0x1668c0..0x166aca` | 522 |
| `0x166b2d..0x166b76` | 73 |
| **total** | **873** |

Checks all true: abstract unique, every instance enumerated, single caller,
caller extent = shipped symbol extent, every recorded range audited, every range
non-empty and inside the caller. That is the whole extent the compiler recorded
for this body; the audit consumes all of it.

## 5. Full branch audit at `a5354547…` — exit 0

31 expected, 31 resolved, 0 refused (1 via `resolves_to`, 1 via LLVM-suffix, 1 via
detached DWARF). Totals over the 31 targets: **1,134 jcc, 6 div/idiv, 81 cmov,
179 setcc, 12 jo/jno, 0 loop**.

- Every `cmov` is **register-to-register with a fixed (non-memory) address**:
  81 register / 0 memory / 0 register-based.
- Every `jcc` carries its condition provenance and guarded window in the report;
  `setcc` counts per target are in the summary.
- **Mechanised secret-dependence** exists only for `key::decap`'s comparison
  contract: 15 jcc public-bound, **0 secret-derived jcc**, 0 undetermined; one
  secret-derived `setcc` (`0x1f8396 setne %al`) consumed **arithmetically**
  (verified: `mov %eax,0xa0(%rsp)`) and one `public-bound` register `cmov`.
- **No secret-derived conditional transfer and no secret-derived memory address.
  No STOP.** For the other 30 targets the instrument prints provenance and
  counts, not taint; the record labels them `inventory-and-source-review` and
  the register does not assert constant time.

## 6. Release gate

`python3 forensics/tools/release_gate.py`:

| before (record at `c34cfe62`/`43a23e9b`) | after (`f536fd63`/`a5354547`) |
|---|---|
| `REFUSED (36 item(s))`, incl. `RG_AUDIT_IDENTITY_MISMATCH` | `REFUSED (35 item(s))`, **no `RG_AUDIT_*`**, no `RG_DOCS` |

The allowlist now names exactly **one** new digest, `a5354547…`, together with a
fresh audit of it; the coverage requirement (`PFP-34/coverage.json`) is rebound
to the PFP-54 inventory, and no family or prefix was admitted. The remaining 35
refusals are the pre-existing package/claims/threshold/policy/instrument/
authorisation items.

## 7. Assurance entries (PFP-49 schema) — schema behaviour recorded

The `ARTEFACT_AUDITED` dimension was added at the audited digest to the five
carriers the audit actually covered:

| kernel | carriers covered by the audit |
|---|---|
| `bn-mont-sos` | `mont_mul_sos_into`, `mont_mul_fallible` |
| `bn-window-ladder` | `run_mont_ladder`, `mod_exp_core_consttime_from_parts`, `mod_inverse_consttime` |
| `p256-field-mont` | `p256::mont_reduce_into`, `p256::wide_mul_x86` |
| `p256-order-inverse` | `mod_inverse_consttime` |
| `dh-width-policy` | `ossl_dh_compute_key`, `run_mont_ladder`, `mont_mul_sos_into`, `mont_mul_fallible` |

Each entry carries subject `artefacts/libcrypto.so.3` = `a5354547…`, a
`PASS` audit verdict at that digest, and evidence path `raw/audit-a5354547.md`.
**Not upgraded, deliberately:** `p256-fixed-comb` (not in the 31-target
inventory), `bn-cias-mont`/`bn-cias-fixed` (`SOURCE_TAINT_TESTED`),
`bn-mont-sqr`/`p256-field-arch`/`rsa-crt` (`UNASSESSED`).

**The schema working:** replacing the historical `SOURCE_REVIEWED` entries in
place produced `KV_ASSURANCE_CLASS_ABSENT` on the register's `claims` layer
(claims 2/3/4/6 cite those entries by evidence index). Because PFP-49 says the
classes are *dimensions, not a ladder*, the upgrade is represented by adding the
`ARTEFACT_AUDITED` entry at the new artefact and retaining the historical
`SOURCE_REVIEWED` entries (and their claims). `kernel_verification.py check`
then accepts the register. Nothing was relaxed. A claimed `ARTEFACT_AUDITED` in
the `claims` layer would additionally require a differential court at this
artefact, which a branch audit is not; no such claim was made.

## 8. What the detached-DWARF mapping does **not** cover

- a target **inlined into more than one caller** — refused
  (`dwarf-inline-multiple-callers`), never partially audited;
- a body **duplicated under more than one abstract origin** — not resolved;
- a **partially inlined** function — the out-of-line remainder is audited as its
  own symbol, not folded into this extent;
- **optimised/duplicated/partially inlined** functions generally: the mapping
  consumes the compiler's recorded ranges, not a source-level definition of the
  body;
- **DWARF5 `.debug_rnglists`**: the resolver parses the DWARF4 `.debug_ranges`
  form the production toolchain emits; the compiled control fixture is pinned to
  `-gdwarf-4` for the same reason;
- **any other artefact** than DSO `a5354547…` and build-id `83eccb95…`, and any
  target outside the 31-target inventory;
- **taint/constant time**: only `key::decap`'s comparison contract is mechanised.
  The audit is a review aid, not a constant-time proof.

## 9. Memory / court receipt

`free -g` immediately before each command (GiB available / swap free); the court
`openssl-rs-court` is pinned at `memory.max = 6g`, `memory.swap.max = 6g`,
`memory.events oom 0 / oom_kill 0`. All commands satisfied the brief's
available ≥ 24 and swap-free ≥ 16 floor.

| command | available | swap free | cap |
|---|---:|---:|---|
| build (one compilation) | 34 | 29 | 6g |
| baseline audit | 34 | 29 | 6g |
| audit (parser debug) | 34 | 28 | 6g |
| audit (DWARF, fixed) | 34 | 29 | 6g |
| audit (cmov table) | 34 | 29 | 6g |
| gate before | 34 | 29 | 6g |
| kernel check + gate after | 34 | 29 | 6g |
| audit-tool tests (19) | 34 | 29 | 6g |
| correspondence + extent | 33 | 29 | 6g |
| correspondence rerun | 33 | 29 | 6g |

`CARGO_BUILD_JOBS=2`, `CARGO_PROFILE_TEST_DEBUG=0`; the build ran into
`/work/court/tmp/pfp54` on the host disk, not a tmpfs. `test_sigstore_bundle`
was not run.

## 10. Reproduction

```
OPENSSL_RS_COURT_MEM=6g OPENSSL_RS_COURT_MEMSWAP=6g CARGO_BUILD_JOBS=2 \
  CARGO_PROFILE_TEST_DEBUG=0 bash docker/openssl-rs-court.sh exec \
    sh evidence/performance-frontier/campaigns/PFP-54/build.sh
python3 …/PFP-54/correspondence.py
python3 …/PFP-54/resolve_extent.py
python3 courts/phase18/timing/binary_branch_audit.py --no-cpuid-scan \
  --debug-file …/raw/artefacts/libcrypto.so.3.debug \
  --targets-file …/PFP-54/targets-pfp54.json \
  --expect-sha256 a5354547… …/raw/artefacts/libcrypto.so.3
python3 …/PFP-54/make_record.py
python3 …/PFP-54/upgrade_assurance.py
python3 forensics/tools/kernel_verification.py check
python3 forensics/tools/release_gate.py
```
