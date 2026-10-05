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
- `AddressSanitizer`, run in a **dedicated sanitizer venue** rather than the court. The
  court's hard 4 GiB `RLIMIT_DATA` (`docker/openssl-rs-court.sh`) is what keeps a runaway court
  off the host, and it is **kept**; ASan is given `docker/openssl-rs-asan.{Dockerfile,sh}`
  instead, which bounds every real resource (cgroup memory, `--pids-limit`, `--cpus`, a wall-clock
  timeout, `--security-opt no-new-privileges`, the court's network policy) and leaves only the
  per-process `RLIMIT_DATA` unset, because ASan's shadow is a `PROT_NONE`/`MAP_NORESERVE` virtual
  reservation the cgroup does not count against resident memory. The candidate is instrumented
  **closed** — the Rust staticlib (`-Zsanitizer=address -Zbuild-std`), the first-party C adapters
  (`build.rs` through a `CC` wrapper) and the test probes — and a sensitivity canary (a deliberate
  heap use-after-free) must be diagnosed before any zero-findings result is trusted. Five
  in-process layers ran: the allocator/unit tests, targeted ownership tests, the hostile TLS
  corpus, the hostile X.509 corpus, and the 16,384-case mutation corpus. A sixth layer, the six
  sealed Phase-17 downstream consumers, runs each admitted probe against ASan-instrumented
  distribution DSOs built into a dedicated prefix (`/asan/install`, by
  `forensics/tools/build_phase2_asan.sh`, an ASan sibling of `build_phase2.sh` that never touches
  the normal `artifacts/phase2/install`), loaded by the Phase-17 consumer builds through
  `LD_LIBRARY_PATH` plus a preloaded clang ASan runtime. Five consumers run clean: CPython's
  bounded `test_ssl` (172 pass, 0 fail), nginx TLS 1.3 with session resumption, curl
  200/verify-result-0 plus its unrelated-CA negative arm, Git's SHA-1/SHA-256 tests and Smart-HTTP
  push/clone/pull, and HAProxy TLS termination. OpenSSH is **envelope-limited**: its seccomp
  sandbox (`sandbox-seccomp-filter.c:193-203`) denies the `mmap` ASan uses to reserve its shadow
  in the sshd preauth child (`ReserveShadowMemoryRange failed ... errno: 22`), so only OpenSSH's
  libcrypto-only operations (key generation, sign/verify, fingerprints, algorithm enumeration)
  ran under ASan — and were clean — while the sshd handshake path could not. The venue, its
  execution envelope, its instrumentation-closure receipt, the canary and every layer's verbatim
  result are recorded in `artifacts/phase18/asan.json`, and the per-consumer downstream evidence
  in `artifacts/phase18/asan-downstream.json`. The venue has found **six** distinct first-party
  defects, each fixed at the root against the authority: five from the original layers (a test
  buffer in `src/modes/wrap.rs`, and real candidate bugs in `src/provider/rand.rs`,
  `src/evp/pem_bridge.rs`, `src/dso/dlfcn.rs` and the `src/evp/legacy_evp.rs` tests), and a sixth
  found by the CPython layer — `src/ssl/ssl_lib.rs`'s `SSL_new` took **one** initial-context
  reference but assigned it to both `ssl->ctx` and `session_ctx`, while the authority takes one
  for each (`ssl/ssl_lib.c:705` and `:828`) and releases both (`ssl_lib.c:1438`, `:1485`); an SNI
  callback that switches contexts (`SSL_set_SSL_CTX`, `ssl_lib.c:5535`) then freed the context
  `session_ctx` still aliased, and a TLS 1.3 session ticket read it (heap-use-after-free at
  `src/ssl/statem/statem_srvr.rs:2892`). `SSL_new` now takes, and `SSL_free` releases, the second
  reference. **It is still not a memory-safety proof**: a clean layer is a bounded observation
  under one instrument, and TSan/UBSan/MSan did not run;
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
