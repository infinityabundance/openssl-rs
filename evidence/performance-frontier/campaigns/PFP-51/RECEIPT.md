# PFP-51 — the branch-audit record at the shipped digest, and why it does not admit

**State: STOP at step 4 (branch audit). The gate keeps refusing. No digest was
admitted and no assurance class was upgraded.**

PFP-51 set out to regenerate the branch-audit record at the digest the current
source actually builds, then let PFP-49's `ARTEFACT_AUDITED` dimension replace
the `SOURCE_REVIEWED` classes the migration had to use. The first half succeeds:
the release DSO is reproducible at HEAD and its digest is recorded. The second
half does not, and the constraint that matters most says not to force it: the
fresh audit at that digest is **not** clean. One of the 31 required targets,
`arith::mont_mul_sos_into`, has no out-of-line body in this DSO, so the audit's
fail-closed contract exits 1 and the record cannot honestly be re-issued as a
`PASS`. A gate that went green because the allowlist was widened would be worse
than this red gate.

## 1. Source and build identity

| | |
|---|---|
| branch | `staging` |
| `HEAD` | `3eed68fd988bf2ae05002864e83ce57e4bf716fe` (PFP-49) |
| candidate tree | `075b08b3f554c357ce8a46061b8d572a277df7ac` |
| `HEAD:src` | `eb5cf87f7aab4529463cc1eaed0a3b56f2fcc96d` |
| rustc / cargo | `1.98.1 (48a229cea 2026-09-01)` / `1.98.1 (797e8a9bc)` |
| cc | `Debian 12.2.0-14+deb12u1` |
| target | `x86_64-unknown-linux-gnu`, release |
| link recipe | PFP-46/PFP-48 distribution shell: whole-archive `libopenssl_rs.a` + `artifacts/phase2/shell/libcrypto.shell.rs` + `artifacts/phase2/libcrypto.ld`, `-lpthread -ldl -lm -lrt -lutil` |
| shell / version-script sha256 | `efa0fbce…` / `75fb6eff…` |
| dirty build-relevant tree | **empty** (`git status --porcelain -- src Cargo.toml Cargo.lock build.rs artifacts/phase2/shell artifacts/phase2/libcrypto.ld`) |

Script: `evidence/performance-frontier/campaigns/PFP-51/build.sh`; inputs:
`raw/build-inputs-A.txt`, `raw/build-inputs-B.txt`.

## 2. Reproducibility — two independent builds

Two separate `CARGO_TARGET_DIR`s, `CARGO_BUILD_JOBS=1`,
`CARGO_PROFILE_TEST_DEBUG=0`, no `RUSTFLAGS`, no release `--test` build.

| build | archive sha256 | DSO sha256 | bytes | GNU build-id |
|---|---|---|---|---|
| A | `e3a56529…` | **`dbf3d0a427ad9a63eb9b724f1434e2b48a3a005242e60e450cf49db922653e3a`** | 17,115,320 | `ec3c97cfe3a75d5c50ee64836593a2eeaabad8a2` |
| B | `e3a56529…` | **`dbf3d0a427ad9a63eb9b724f1434e2b48a3a005242e60e450cf49db922653e3a`** | 17,115,320 | `ec3c97cfe3a75d5c50ee64836593a2eeaabad8a2` |

**The two digests are byte-identical.** This is the digest the current source
ships (`dbf3d0a4…`). Note the tracked `artifacts/phase2/install/lib/libcrypto.so.3`
is the stale release-0.0.49 DSO `fd25cc9e…`; it is not this candidate and was not
used as the subject.

## 3. Branch audit at `dbf3d0a4…` — **FAIL (exit 1)**

```
python3 courts/phase18/timing/binary_branch_audit.py \
  --expect-sha256 dbf3d0a4… \
  --targets-file evidence/performance-frontier/campaigns/PFP-31/targets-pfp31.json \
  court/tmp/pfp51/B/libcrypto.so.3
```

Exit **1**. Verbatim stderr (`raw/audit-dbf3d0a4.stderr`):

```
REFUSED target="Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects)" symbol="arith::mont_mul_sos_into" reason=missing
binary_branch_audit: FAIL-CLOSED: 1 of 31 expected targets were refused; this report is not a gate result.
```

Full report: `raw/audit-dbf3d0a4.md` (sha256 `33c654f4…`).

- expected 31, resolved uniquely and disassembled **30**, failed **1**; one
  inline mapping and two LLVM-suffixed copies still verified.
- Totals over the 30 resolved functions: **1125 jcc, 88 cmov, 173 setcc,
  12 jo/jno, 0 loop** (per-column sums of the report table, `raw/`).
- `key::decap` comparison contract (the only target with a declared contract):
  **0 secret-derived conditional jumps**, 0 undetermined; one secret-derived
  `setcc` (`0x4a9845 setne %al`, consumed arithmetically) and one `cmov`
  (`0x4a9866 cmovne %rcx,%rdx`, public-bound / fixed stack address). No
  secret-derived memory address.
- The other 29 targets carry no declared taint contract; the tool prints branch
  provenance, not taint. For them the record's old `secret_derived_jcc: 0` is a
  source-review judgement that is **not re-established at this digest**.

### The refusal, precisely

`mont_mul_sos_into` is defined at `src/bn/arith.rs:1874` and called from
`mont_mul_ladder_into` (line 2186), `mont_mul_into` (2203) and
`mont_mul_fallible_with` (2233). `LADDER_SCHEDULE` is `MontSchedule::Cios`
(line 1674), so the ladder does not select SOS; the reference path does, and
the release optimiser inlined the only remaining body. `nm` finds **no** defined
symbol ending in `mont_mul_sos_into` (`raw/symbol-resolution.txt`); only
`mont_mul_fallible` and `mont_mul_ladder_into` remain. `run_mont_ladder` grew
51→97 jcc and `mont_mul_fallible` 17→31 jcc, consistent with the inlining, but
the tool has no *verified* mapping for a carrier whose name is not
`symbol + suffix`, and a count copied from a carrier would be a substitution,
not an audit.

Consequences the gate would apply to any truthful record at this digest:

- `region.audit_exit != 0` → `RG_AUDIT_RECORD_INVALID`;
- `mont_mul_sos_into` is required by 7 of the 8 coverage paths
  (`ecdsa-sign`, `ecdsa-sign-default`, `ecdh`, `rsa-crt`, `rsa-nocrt`,
  `rsa-crt-pkcs1`, `dh`) → `RG_AUDIT_UNCOVERED_PATH`.

So the audit does not pass, and step 6 is not entered.

## 4. Taint at `dbf3d0a4…` — reproduced, same profile as PFP-31

Venue: `openssl-rs-court-tools:1` (valgrind-3.19.0; the base court image has
neither valgrind nor its headers). Harness `PFP-31/pfp31_mlkem.c` (source
`7a0e664e…`) retargeted with `--lib court/tmp/pfp51/B/libcrypto.so.3`.

| param | control | taint | contexts | `key::decap` contexts |
|---|---|---|---:|---:|
| 512 | 0 errors | 1271 | 3 | 0 |
| 768 | 0 errors | 2895 | 3 | 0 |
| 1024 | 0 errors | 4990 | 3 | 0 |

Identical to the accepted PFP-31 reading at `43a23e9b` (same counts, same three
contexts: `ml_kem::arith::matrix_expand` ×2 and
`provider::ml_kem_kmgmt::ml_kem_pairwise_test` ×1; authority `611e511d` shows
4). This reproduces the measurement; it is **not** a zero-error run, it is not a
firing negative control, and it supports no `ARTEFACT_TAINT_TESTED` claim.
Evidence: `raw/taint/`, `raw/taint-summary.tsv`.

## 5. The gate — unchanged, still refusing

`python3 forensics/tools/release_gate.py`, at HEAD, before and after every step
above: **`release-gate: REFUSED (36 item(s))`**, exit 1. The branch-audit
refusal is the identical line in both runs (`raw/gate-before.txt`,
`raw/gate-after.txt`):

```
REFUSED RG_AUDIT_IDENTITY_MISMATCH c34cfe62f…: the record was measured at source
c34cfe62f… / DSO 43a23e9b…; the release candidate is 3eed68fd… / tree
075b08b3…; a result measured at another DSO cannot evidence this candidate; the
record names tree fee211d0…; the candidate has tree 075b08b3…
```

No file under `evidence/performance-frontier/campaigns/PFP-34/` was modified;
the allowlist holds exactly the one digest it held before. The other 35
refusals are the pre-existing ones (package, claims, thresholds, policy,
instrument, authorisation).

## 6. Assurance entries — **none added**

`forensics/performance/KERNELS.json` is unchanged. `ARTEFACT_AUDITED` requires
an `ARTEFACT`-bound evidence record with a structured `PASS` audit of the exact
subject digest (`forensics/tools/kernel_verification.py`). At `dbf3d0a4…` there
is no such audit, because the report above exits 1. The kernel carriers therefore
remain at their PFP-49 classes (`SOURCE_REVIEWED`, `SOURCE_TAINT_TESTED`,
`UNASSESSED`). Claiming `ARTEFACT_AUDITED` here would be the declared-digest
defect PFP-49 closed, in mirror image.

## 7. `expected_dso_sha256` — still an optional declaration (W2 stands)

`release_gate.py::check_branch_audit` never hashes a DSO artefact. It takes the
identity from `record["dso"]["sha256"]` and only *cross-checks* an optional
caller declaration, `--branch-audit-dso-sha256` (default `None`). An absent
declaration is not a refusal. Making the declaration mandatory would not derive
the digest; deriving it requires the gate to locate and hash a candidate DSO,
which contradicts its deliberate "read the record, do not build" design and is
more than a one-line strengthening. **Recorded as remaining W2, not changed in
this batch.**

## 8. What would unblock it (not done here)

One of these, each requiring its own review rather than a widened allowlist:

1. extend `binary_branch_audit.py` with a verified inlining witness for a
   *fully inlined* kernel (carrier + call-site + constant/consumer witness, in
   the style of `llvm_suffix`), then re-audit at `dbf3d0a4…`; or
2. keep the kernel out-of-line at the source (`#[inline(never)]` on the
   reference kernel) and rebuild — a codegen/performance decision; or
3. a reviewed coverage change that names the carrier(s) actually holding the
   body and *proves* the body is inside the audited extent (the tool cannot do
   this today).

## 9. Memory / court receipt

`free -g` immediately before each heavy command (GiB available / swap free):

| command | available | swap free | cap |
|---|---:|---:|---|
| build A | 18 | 17 | 4g |
| build B | 18 | 17 | 4g |
| branch audit | 18 | 17 | 4g |
| taint | 23 | 10 | 4g |
| gate before/after | 23–24 | 10–17 | 4g |

Both courts were created/pinned at `--memory=4g --memory-swap=4g`
(`OPENSSL_RS_COURT_MEM=4g`, `OPENSSL_RS_COURT_MEMSWAP=4g`), `CARGO_BUILD_JOBS=1`,
`CARGO_PROFILE_TEST_DEBUG=0`. `memory.events` shows `oom 0`, `oom_kill 0` in both.
A fresh release build directory is 99 MiB; no build ran into a tmpfs.

*Disclosure:* `AGENTS.md` §6.1 names a 24 GiB floor before a build; §24.4 gives
the operative `min(4g, available-8g)` cap. This batch ran at 16.0–18.7 GiB
available under the PFP-51 brief's explicit 16 GiB floor, with the tightened 4g
cap and the observed `oom 0`. The tension is recorded, not hidden.
