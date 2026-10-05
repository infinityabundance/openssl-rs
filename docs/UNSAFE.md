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

At the Phase 18 hostile-hardening revision the measurement is **58,826** unsafe
sites and **10,866** `extern "C" fn` over **801,594** lines: the **core**
parser/algorithm modules carry **52,943** unsafe sites (**90.0%**) and the
**boundary** layer **5,883** (10.0%). `src/ffi` — the boundary the earlier
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
- `Miri` over the **Miri-admitted TCB suite** — `cargo +nightly miri test --lib miri_tcb`
  with `MIRIFLAGS="-Zmiri-strict-provenance"`, run under seeds 0, 1 and 2 (and ordinary
  mode, seed 0): **9 admitted tests, 9 passed, 0 unsupported tests ran**. The suite is
  `src/runtime/miri_tcb.rs` and installs a Rust-backed allocator shim through
  `CRYPTO_set_mem_functions` before its first allocation, so the `CRYPTO_*` ownership
  surface, the X.509 refcount/lifetime path, the `OPENSSL_STACK`/`OPENSSL_LHASH`
  containers, the `BUF_MEM` gateway and the object registry run without libc. The
  allocator-trampoline provenance blocker is **fixed** at its root: the callback slots
  in `src/runtime/mem.rs` (and the async stack slots in
  `src/async/arch/async_posix.rs`) are `AtomicPtr<()>`, installed `f as *const () as
  *mut ()` and recovered by a pointer->function-pointer `transmute` after a null check;
  `CRYPTO_get_mem_functions` reconstructs pointer-shaped values; `CRYPTO_aligned_alloc`
  uses `ptr.addr()` for its address-only alignment observation while keeping `base` for
  provenance. The class cannot silently return: `forensics/tools/provenance_court.py`
  is a regression guard inside the `HOSTILE-BOUNDARY-REGISTER` court, and it fails when
  an integer->callable-pointer reconstruction reappears. Miri also **found a real
  aliasing defect** the suite exists to catch — `object_free` (`src/runtime/obj.rs`)
  formed `&mut *p` on a static registry object reachable from `X509_free` — now fixed
  by reading the flags before any mutable reference is formed. What Miri executes, and
  the surface it refuses (libc FFI in `src/runtime/bio/sys.rs`, DSOs in
  `src/dso/dlfcn.rs`, the `ucontext` fibres, `getrandom`, `rdtsc`), is named with a
  reason in `forensics/miri-tcb-suite.json`; the recorded run is
  `artifacts/phase18/miri-tcb.json`;
- a **crate-wide pointer-provenance audit** (Phase 18, Commit A), classifying every
  occurrence of the pattern: an integer->callable-pointer reconstruction is a defect
  (fixed in `src/runtime/mem.rs` and `src/async/arch/async_posix.rs`, guarded by
  `forensics/tools/provenance_court.py`); an address-only `ptr as usize`/`ptr.addr()`
  observation is left as-is (the `CRYPTO_aligned_alloc` alignment decision, hash keys and
  test identity comparisons); a stored dereferenceable function pointer cast through
  `*mut c_void` is provenance-preserving and left as-is (`asn1::utl::call_item_exp`,
  `context::dispatch::entry_function`); and a dynamic-loader symbol address
  (`src/dso/dlfcn.rs`'s `dlsym`, `src/engine/eng_dyn.rs`'s `dlsym`-paired cast) is the
  explicit provenance TCB — the boundary §1 admits for dynamic loading, recorded here
  rather than mechanised, and the reason the DSO tests are excluded from the Miri set;
- `AtomicUsize` slots that hold genuine counters (the panic count, the object-registry
  size, the test counters) are **not** pointer storage and are left as integers;
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
