# Unsafe Rust Policy

Status: **constitution** (Phase 0). Referenced by `docs/CUSTODIAN_CONTRACT.md` §4.

## 1. When `unsafe` is permitted

Only where the contract requires it:

- C ABI boundaries;
- raw ownership compatibility (see `docs/OWNERSHIP_MODEL.md`);
- platform syscalls;
- dynamic loading (`dlopen`/`dlsym`/`dlvsym`, `LoadLibrary`);
- CPU intrinsics (see Phase 19);
- exact memory-layout requirements (public struct layout, `offsetof`-visible
  fields, version-script/ABI-visible objects).

## 2. Structure

`unsafe` is **measured, not asserted**. `forensics/tools/unsafe_footprint.py`
scans `src/**/*.rs` and records, per module, the `unsafe` sites, the
`extern "C" fn` declarations and the `SAFETY:` comments; it classifies each
module as **boundary** (the FFI/ABI translation layer: `ffi`, `runtime`, `dso`,
`engine`, `async`, `context`) or **core** (parsers and algorithms: `asn1`,
`x509`, `pem`, `cms`, `ssl`, `bn`, `rsa`, `ec`, `evp`, and — conservatively —
every module not named boundary). The exact definitions and the classification
list are in the generated table `forensics/atlas/unsafe-footprint.json`, whose
rendered form is the "Measured `unsafe` / FFI footprint" section of
`forensics/STATUS.md`. The `UNSAFE-FOOTPRINT` growth check inside the
`HOSTILE-BOUNDARY-REGISTER` court (`forensics/tools/phase18_courts.py`) fails if a
core module's count rises above the ceiling recorded in
`artifacts/phase18/unsafe-bounds.json`, while the boundary layer is allowed to
grow.

At the Phase 18 hostile-hardening revision the measurement is **58,767** unsafe
sites and **10,860** `extern "C" fn` over **801,094** lines: the **core**
parser/algorithm modules carry **52,943** unsafe sites (**90.1%**) and the
**boundary** layer **5,824** (9.9%). `src/ffi` — the boundary the earlier
revision of this document named as the example — carries **none**. The claim
that `unsafe` is concentrated in narrow boundary modules is therefore **false of
this implementation**: the unsafe surface is in the parser and algorithm modules,
because the `#[no_mangle]` exports and their pointer marshalling sit beside the
code they expose rather than in a separate shim. A C authority, by contrast, is
~100% unsafe by construction, which is the baseline this measurement is against.

**This measurement is not a memory-safety claim.** It establishes the size and
location of the unsafe surface, not that any `unsafe` block is correct, that any
`SAFETY:` comment is true, or that the memory-safety benefit has been realised; a
footprint is not a proof, and the crate has had memory-safety defects of exactly
the class Rust is meant to remove (see `docs/PHASE-8-CRYPTO-SEAL.md`, D301/D302).
See `docs/NON_CLAIMS.md`.

- Each module carries a `// SAFETY:` invariant catalogue at the top describing
  every precondition its `unsafe` blocks assume.
- Every `unsafe` block states, in a comment, *which* catalogue invariant it
  relies on and *why* it holds at that point.

## 3. Panic containment

- No Rust panic may unwind across a C ABI boundary.
- Every exported `extern "C"` function has an unwind boundary
  (`catch_unwind`) or is otherwise guaranteed non-unwinding.
- Panics on the FFI path are a **hard failure**, detected by tests, not merely
  reviewed.

## 4. Testing of invariants

The instrumented checks over the parser/algorithm cores are **measured and recorded** in
`artifacts/phase18/unsafe-instruments.json`, not asserted here:

- unit tests per invariant, including negative tests (the crate's test modules);
- `Miri` over the safe-testable subset — attempted (`cargo +nightly miri test --lib`, the
  `asn1::x_algor` subset). It compiled the crate and executed tests, then reported
  undefined behaviour at the allocator trampoline (`src/runtime/mem.rs:379`: both the
  default and any installed allocator are stored as a `usize` and recovered by
  `transmute`, and the default is the libc `malloc` FFI). The crate is therefore not
  Miri-tractable beyond non-allocating tests; the exact error is recorded;
- address/UB sanitizers — `AddressSanitizer` **could not run** under the court's hard
  4 GiB `RLIMIT_DATA` (its shadow reservation is ~15.4 TB, the same constraint
  `forensics/tools/probe_hygiene.py` documents), and the attempt and its exact error are
  recorded rather than skipped silently;
- a bounded, deterministic mutational fuzz
  (`forensics/tools/fuzz_hostile_corpus.py`) over the hostile X.509 corpus: 16,384
  mutants in a 300 s bound, recorded in `artifacts/phase18/fuzz-hostile-corpus.json`;
- canary allocators for lifetime/aliasing invariants.

None of these establishes that any `unsafe` block is correct; they observe specific
error classes under specific execution, and §2's non-claim stands.

## 5. Authority undefined behaviour

The authority is written in C and may contain undefined behaviour. The candidate
does **not** reproduce UB merely because one observed authority run yielded a
particular result. Such observations become recorded *compatibility boundaries*
(`docs/RELEASE_GATES.md` §6), not behaviours to imitate.
