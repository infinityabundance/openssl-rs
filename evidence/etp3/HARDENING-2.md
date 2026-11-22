# ETP-3 hardening 2 — complete verdicts, byte coverage, explicit allowances

**Status:** findings, repairs and controls for the follow-up to ETP-3.
**Candidate:** `staging` = `342934733de0d2297db663eeb35bfe48371cb034`; the
worktree was clean at the start of the session.
**Venue:** `openssl-rs-court-tools:1`; host `free -g` reported `available`
26 GiB before the controls and 26 GiB before the full `check` (guard floor:
24 GiB). No crate build and no host compilation were performed.
**Scope:** `courts/phase18/timing/`, `forensics/tools/` and the ETP-3 evidence.
No `src/` and no `docker/` file was changed.

This document records three defects that survived the first ETP-3 pass, the
repairs, the controls that now fire, the prerequisite restoration, and what is
still open. Qualification remains a statement about an instrument's own
controls, not a security result about the crate.

## 1. Defect A — a mixed transcript could still be accepted as secure

### Mechanism

`binsec_checkct.sh` searched the transcript for the secure line first:

```sh
if grep -Fq '[checkct:result] Program status is : secure' "$tmp/out"; then
    if [ "$rc" -ne 0 ]; then refuse 6 "inconsistent output"; fi
    exit 0
fi
```

A transcript containing both a secure line and an insecure line, with BINSEC
exiting zero, was therefore accepted as secure before the insecure line was
examined. A line such as `Program status is : secure (0.030) but ...` also
matched as a prefix.

### Repair

The wrapper now classifies the **complete** status population before deciding.
The canonical line is

```
[checkct:result] Program status is : <secure|insecure|unknown>[ (<seconds>)]
```

where the optional parenthesised field is BINSEC's own elapsed time. The
grammar is anchored to the whole line; any other trailing text is refused.
Exactly one verdict is required:

| population | reason | exit |
|---|---|---:|
| zero well-formed verdicts | `no-verdict-line` (or `no-output`) | 3 |
| secure then insecure (or the reverse) | `mixed-verdicts` | 6 |
| two or more secure verdicts | `duplicate-secure` | 6 |
| any other two or more verdicts | `multiple-verdicts` | 6 |
| verdict followed by additional text | `verdict-trailing-text` | 3 |
| exactly one secure, tool exits 0 | — | 0 |
| exactly one insecure | — | 1 (or 8 under `--require-secure`) |
| exactly one unknown | — | 4 (or 8 under `--require-secure`) |

The identity (`BINSEC_EXPECT_SHA256`), format (ELF), timeout and
`--require-secure` contracts are unchanged. The added exit 6 reasons are
inconsistent-transcript refusals; exit 3 remains "no single well-formed verdict
line".

### Controls

The stand-in BINSEC tool in `instrument_qualify.py` gained the modes
`secure_timed`, `mixed`, `duplicate_secure`, `multiple_insecure` and
`trailing_text`. The live table is 19 cases; the five new cases are:

| case | exit |
|---|---:|
| a secure verdict carrying BINSEC's timing suffix is accepted | 0 |
| mixed secure and insecure verdicts are refused when the tool exits zero | 6 |
| two secure verdicts are refused as duplicated | 6 |
| two non-secure verdicts are refused as multiple | 6 |
| a verdict line with additional text is refused | 3 |

The mixed-transcript control is the exact defect: the tool prints both lines and
exits zero, and the wrapper now refuses with `reason=mixed-verdicts` instead of
returning 0. The timed-secure control is the positive case that keeps the real
BINSEC output (`secure (0.026)`) acceptable.

## 2. Defect B — an address gap is not byte coverage

### Mechanism

`binary_branch_audit.py` compared consecutive instruction addresses and rejected
only a step larger than 15 bytes (the maximum x86 instruction length), and it
allowed up to 15 undecoded trailing bytes. A one-byte instruction omitted from
the decoded stream leaves a step of 1 to 15 bytes, so the check accepted it.
The decoded lengths were never used.

### Repair

The audit now disassembles with `--insn-width=16`, parses each instruction's raw
byte field, and treats the number of byte pairs as the instruction length. The
invariant is byte coverage:

1. `end(Iᵢ) = start(Iᵢ₊₁)` for every consecutive pair;
2. the first instruction starts exactly at the symbol address;
3. the last instruction ends exactly at the symbol boundary;
4. the total decoded byte count equals the symbol extent.

A gap, an overlap, a disassembly ending before or past the boundary, and a
byte-count mismatch are distinct refusals:

| condition | reason |
|---|---|
| `start(Iᵢ₊₁) > end(Iᵢ)` | `disassembly-hole:gap=+0x…` |
| `start(Iᵢ₊₁) < end(Iᵢ)` | `disassembly-overlap:overlap=0x…` |
| last end `< boundary` | `disassembly-truncated:N-bytes-undecoded` |
| last end `> boundary` | `disassembly-overrun:N-bytes-past-boundary` |
| start off the symbol | `misaligned-start:+0x…` |

The pre-repair script accepted a transcript with a one-byte `nop` removed. The
same shim now refuses it. The demonstration used a fixture with a `nop` between
two other instructions and an `objdump` shim that deletes the `nop` line; every
remaining address step is 4 bytes or less.

```
OMISSION_DEMO old_exit=0 new_exit=1
old stderr: binary_branch_audit: 1 expected targets resolved uniquely with complete disassembly; candidate sha256=2b1431582cee482ca3a998f5d91bc3daef853370fca23dd613cb8a3f94a6f179
new stderr: REFUSED target="fixture core" symbol="mont_mul_into" reason=disassembly-hole detail=disassembly-hole:gap=+0x1@+0xe
binary_branch_audit: FAIL-CLOSED: 1 of 1 expected targets were refused; this report is not a gate result.
```

### Controls

The branch-audit control gained an omission shim, an overlap shim and an
overrun shim; the existing truncation, gap, empty, hang, non-ELF and
wrong-digest controls remain. The live table is 13 cases, including:

| case | exit |
|---|---:|
| resolves exact unique symbols and exits 0 | 0 |
| an omitted short instruction is refused (byte coverage, not address gaps) | 1 |
| an overlap in the decoded stream is refused | 1 |
| a disassembly ending past the declared boundary is refused | 1 |
| truncated disassembly is refused, not counted as resolved | 1 |
| a hole in the decoded stream is refused | 1 |

### Re-run on the recorded candidate

The recorded candidate is `court/tmp/p4/libcrypto.so.3`, SHA-256
`ee7fa27c79f5a679d5b229429d53dc7c3b510695db9c74d11b4b6783a735ebe9`. The
byte-coverage audit was re-run with `--expect-sha256`:

```
AUDIT_EXIT=0
- expected targets: 7
- resolved uniquely and disassembled: 7
- failed: 0
--- stderr ---
binary_branch_audit: 7 expected targets resolved uniquely with complete disassembly; candidate sha256=ee7fa27c79f5a679d5b229429d53dc7c3b510695db9c74d11b4b6783a735ebe9
```

The stricter invariant still yields 7/7 and exit 0. **No coverage defect was
found in the recorded run**, so `courts/phase18/timing/RECEIPT-timing-unified.json`
is not contradicted. The invariant was not relaxed to obtain this result: the
omission control above proves the new check refuses a population the old one
accepted.

The full report (`court/tmp/etp3-hardening2/audit-ee7f.out`) contains the same
per-function counts as the earlier receipt: `mont_mul_into` 24 jcc / 0 div / 0
cmov; `mont_mul_fallible` 13 / 0 / 0; `mod_exp_core_consttime_from_parts` 73 / 0
/ 3; `mod_inverse_consttime` 217 / 0 / 3; `ossl_ec_scalar_mul_ladder` 113 / 0 /
5; `ossl_ec_GFp_simple_ladder_step` 61 / 0 / 0; `rsa_ossl_mod_exp` 133 / 0 / 0.

### Single-decoder limit

The venue has no second instruction decoder: `llvm-objdump`, `ndisasm`, `gdb`
and Python `capstone` are absent. Byte coverage is therefore established with
GNU objdump 2.40 alone. A decoder defect that omitted an instruction while
preserving contiguity would not be cross-checked. This is recorded as an open
limit in the register and in `docs/INSTRUMENT-QUALIFICATION.md`, not as a
passed check. Installing a second decoder was outside the authorised network
use for this batch.

## 3. Defect C — the nonzero version-probe exception was the default

### Mechanism

`validate_instrument` accepted a version command whenever it exited zero **or**
printed the recorded string:

```python
require(rc == 0 or version["observed"] in text, "IQ_VERSION_COMMAND", ...)
```

A command that printed the expected version and then exited nonzero was accepted
as evidence of identity for every instrument, although that behaviour is
appropriate only for a tool that cannot be probed any other way.

### Repair

The allowance is now explicit per instrument:

- `version_validation.accept_nonzero_exit` must be a boolean (default false);
- when true, `version_validation.nonzero_exit_justification` must be a non-empty
  string (`IQ_VERSION_JUSTIFICATION` otherwise);
- a nonzero probe that prints the recorded string is refused as
  `IQ_VERSION_NONZERO` unless the entry declares the allowance;
- a nonzero probe that does not print the recorded string remains
  `IQ_VERSION_COMMAND`; a wrong string remains `IQ_VERSION_MISMATCH`.

No instrument in the current register needs the allowance: every version
command exits zero in this session. The allowance exists for a future tool and
must be justified in its entry.

### Controls

`forensics/tools/tests/test_instrument_qualify.py` gained three mutations of the
`binary-branch-audit` version probe (a command that prints the recorded objdump
string and exits 7):

| control | expected |
|---|---|
| undeclared nonzero probe | `IQ_VERSION_NONZERO`, nonzero |
| declared probe with a justification | `REGISTER ok`, exit 0 |
| declared probe with an empty justification | `IQ_VERSION_JUSTIFICATION`, nonzero |

The checker suite is now 16/16 (`Ran 16 tests ... OK`).

## 4. Prerequisite restoration

### 4.1 dudect header

The pinned header was copied from the session-local `/opt/dudect/src/dudect.h`
into the repository:

```
courts/phase18/timing/third_party/dudect/dudect.h
sha256 3fb3b2bd7f9e17ae34b7c92518c1311c67342c56facc80da925d85f121b649da
15227 bytes
```

The digest equals the value already recorded in the register for the pinned
`dc269651…` tree. The register now lists the vendored path in `paths`, uses it
in `invocation`, and binds the control prerequisite to it. The control checks
the digest again before invoking `cc`, so a clean checkout re-qualifies without
the external tree.

The sensitivity control re-ran from the vendored header:

```
MODE=cmpnaive EXIT=0
dudect.executed mode=cmpnaive per_batch=20000 batches_run=2 total_measurements=40000
dudect.done mode=cmpnaive batches=2 state=0
MODE=cmpcmp EXIT=1
dudect.executed mode=cmpcmp per_batch=20000 batches_run=3 total_measurements=60000
dudect.done mode=cmpcmp batches=3 state=1
```

State 0 is leakage found (the positive control fires); state 1 is no leakage
evidence at this geometry (the negative control). The inverted exit status is
the harness's own contract and is recorded, not reinterpreted.

### 4.2 Pinned z3

`forensics/tools/install_z3_pinned.sh` installs Z3 4.13.0 into
`/opt/z3-solver/z3-4.13.0-x64-glibc-2.35`. It refuses outside the court (via
`require_court.sh`), verifies the archive digest before extraction, verifies the
extracted `bin/z3` digest, and checks the version string. Digests observed in
this session:

| object | sha256 |
|---|---|
| `z3-4.13.0-x64-glibc-2.35.zip` | `884e3a411fa11b125522fc35eba3391b772517c047f8064fb4b656d92a73b38c` |
| `bin/z3` | `0be0492eb59745e31e77a510ce50c8b940617b87647757bdb1ba6c856301f712` |

Installation output:

```
install_z3_pinned: downloading https://github.com/Z3Prover/z3/releases/download/z3-4.13.0/z3-4.13.0-x64-glibc-2.35.zip
install_z3_pinned: archive sha256 verified: 884e3a411fa11b125522fc35eba3391b772517c047f8064fb4b656d92a73b38c
Z3_PINNED_OK path=/opt/z3-solver/z3-4.13.0-x64-glibc-2.35/bin/z3 version='Z3 version 4.13.0 - 64 bit' binary_sha256=0be0492eb59745e31e77a510ce50c8b940617b87647757bdb1ba6c856301f712
```

Fail-closed control: `--check --dest /tmp/absent-z3` exits 1 with
`REFUSED: solver not executable`. `--check` against the installed tree exits 0.

The tools image still carries Z3 4.8.12 at `/usr/bin/z3`; it is not the pinned
solver. The wrapper's documented resolution order (explicit `BINSEC_Z3`, then
PATH, then the pinned directory) means the pinned tree must be selected
explicitly. Every live run below used
`BINSEC_Z3=/opt/z3-solver/z3-4.13.0-x64-glibc-2.35/bin/z3`.

### 4.3 Live BINSEC verdicts

The wrapper was run on every T16 target present in the court with the pinned
solver, `BINSEC_WALL_TIMEOUT=400` and `BINSEC_SSE_TIMEOUT=240`:

| target | SSE script | verdict line | wrapper exit |
|---|---|---|---:|
| `court/tmp/t16/ka_ct` | `ka.cfg` | `secure (0.026)` | 0 |
| `court/tmp/t16/ka_leaky` | `ka.cfg` | `insecure (0.024)` | 1 |
| `court/tmp/t16/memcmp_probe` | `memcmp.cfg` | `secure (0.031)` | 0 |
| `court/tmp/t16/real_rs` | `real_rs.cfg` | `unknown (0.027)` | 4 |
| `court/tmp/t16/inv_rs` | `inv.cfg` | `unknown (240.016)` | 4 |

Each run printed `# z3: Z3 version 4.13.0 - 64 bit`. The known-answer pair is
correct (the leaky fixture is insecure, the constant-time fixture is secure).
`CRYPTO_memcmp` is secure. The ladder and constant-time inversion reach the
engine and return `unknown` at the exploration bound; that is a result, not a
failure of the repair, and `unknown` remains a non-pass. No verdict is claimed
for the two `unknown` targets.

## 5. Qualification gate output

`python3 forensics/tools/instrument_qualify.py check` (court, verbatim):

```
REGISTER ok: 11 instruments, schema openssl-rs/instrument-qualification/1
  - valgrind-ctgrind: version 'valgrind-3.19.0'
  - dudect: version '3fb3b2bd7f9e17ae34b7c92518c1311c67342c56facc80da925d85f121b649da'
  - binsec-checkct: version 'Binsec version 0.11.3'
  - timecop-supercop: version 'e4fe70eb2a24928a7bbd3fb133787f982f7fead959dd6521c2d42c52b69e96ac'
  - perf-pmu: version 'perf version 6.1.192'
  - tsc-smi-fallbacks: version 'cc (Debian 12.2.0-14+deb12u1) 12.2.0'
  - binary-branch-audit: version 'GNU objdump (GNU Binutils for Debian) 2.40'
  - differential-bench-court: version 'Python 3.11.2'
  - alloc-probe: version 'cc (Debian 12.2.0-14+deb12u1) 12.2.0'
  - build-reproducibility: version 'GNU ar (GNU Binutils for Debian) 2.40'
  - etp-claims: version 'Python 3.11.2'
PASS     valgrind-ctgrind (ctgrind-sensitivity): 2 cases
PASS     dudect (dudect-sensitivity): 2 cases
PASS     binsec-checkct (binsec-gate): 19 cases
RECORDED timecop-supercop: bound to courts/phase18/timing/run_timecop_supercop.sh
PASS     perf-pmu (pmu-venue-probe): 3 cases
RECORDED tsc-smi-fallbacks: bound to courts/phase18/timing/run_pmu_substitutes.sh
PASS     binary-branch-audit (branch-audit-gate): 13 cases
PASS     differential-bench-court (differential-analysis-controls): 1 cases
PASS     alloc-probe (alloc-probe-control): 2 cases
PASS     build-reproducibility (reproducibility-comparison-control): 1 cases
PASS     etp-claims (etp-claims-controls): 1 cases
QUALIFICATION ok: every requested control passed and matched the register
```

`python3 -m json.tool evidence/etp3/instruments.json` exits 0.
`python3 forensics/tools/tests/test_instrument_qualify.py` reports
`Ran 16 tests ... OK`.

## 6. What remains open

- **BINSEC ladder/inversion verdicts.** `real_rs` and `inv_rs` return `unknown`
  at the 240 s bound. The cause recorded at T16 (allocator dispatch and
  `rust_oom` indirects in a statically linked binary) is unchanged. `unknown` is
  not a pass.
- **Single-decoder coverage.** No second decoder is available, so byte coverage
  is not cross-checked. A contiguity-preserving decoder defect would be
  invisible.
- **The image's Z3 on PATH.** `/usr/bin/z3` is 4.8.12. The pinned 4.13.0 tree is
  installed by a script and selected with `BINSEC_Z3`; the image itself is not
  modified (the `docker/` scope boundary was preserved). A caller that omits
  `BINSEC_Z3` gets the image solver, and the wrapper prints whichever solver it
  used.
- **TIMECOP/SUPERCOP and TSC/SMI.** Both remain `RECORDED`, not re-executed, for
  the reasons already recorded. `RECORDED` is not `PASS`.
- **dudect and the venue.** The dudect result is a statistical observation at
  the stated geometry on a virtualised host without a PMU. State 1 is not
  constant time.
- **T14/T16 prose.** Their older gate descriptions ("hole over 15 bytes", "more
  than 15 undecoded trailing bytes") are superseded by the byte-coverage
  invariant recorded here and in the ETP-3 row; the authoritative contracts are
  in `docs/INSTRUMENT-QUALIFICATION.md` §5 and the instrument register.

## 7. Files changed

| file | change |
|---|---|
| `courts/phase18/timing/binsec_checkct.sh` | complete verdict population, anchored grammar, new refusal reasons |
| `courts/phase18/timing/binary_branch_audit.py` | raw-byte decoding, byte-coverage invariant, gap/overlap/truncation/overrun refusals |
| `courts/phase18/timing/third_party/dudect/dudect.h` | vendored pinned header |
| `forensics/tools/instrument_qualify.py` | declared nonzero version-probe allowance; vendored dudect prerequisite; new mutation controls |
| `forensics/tools/tests/test_instrument_qualify.py` | three version-probe controls (16 tests total) |
| `forensics/tools/install_z3_pinned.sh` | pinned, digest-verified Z3 4.13.0 installer |
| `evidence/etp3/instruments.json` | dudect/z3 prerequisites, new control tables, live solver verdicts, byte-coverage limits |
| `docs/INSTRUMENT-QUALIFICATION.md` | new contract, controls, verdicts and open limits |
| `docs/ETP-TODO.md` | ETP-3 row amended |

## 8. Reproduction

```sh
# refusal and sensitivity controls (court)
python3 forensics/tools/instrument_qualify.py check

# checker negative controls
python3 forensics/tools/tests/test_instrument_qualify.py

# pinned solver
bash forensics/tools/install_z3_pinned.sh --check

# recorded candidate, byte coverage
python3 courts/phase18/timing/binary_branch_audit.py \
  --expect-sha256 ee7fa27c79f5a679d5b229429d53dc7c3b510695db9c74d11b4b6783a735ebe9 \
  court/tmp/p4/libcrypto.so.3

# live verdicts
BINSEC_Z3=/opt/z3-solver/z3-4.13.0-x64-glibc-2.35/bin/z3 \
  bash courts/phase18/timing/binsec_checkct.sh court/tmp/t16/ka.cfg court/tmp/t16/ka_ct
```
