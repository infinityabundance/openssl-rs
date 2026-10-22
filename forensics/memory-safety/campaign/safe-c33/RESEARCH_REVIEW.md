# OpenSSL-rs: security engineering research review and AGENTS.md upgrade

**Reviewed:** 2026-10-17. **Repository:** infinityabundance/openssl-rs, branch `integrate/safe-c33`; observed tip when inspected: `b421cfecdb1026cfbd794e82b1e4eb7443a18558`. **Deliverable:** `AGENTS.vNext.patch` appends §§21–32 to the existing tracked root AGENTS.md. No change has been pushed to the repository. This review is not a formal code audit or a new safety graduation.

## Executive finding

Existing `AGENTS.md` §§0–20 is already unusual in its rigor: unsafe ownership-adoption contracts, separation of allocated storage from valid Rust values, explicit RustBelt-style safety goals, mechanisms `OWNERSHIP_RECONSTRUCTED` vs `SAFETY_DISCHARGED`, independent cryptographic evidence, negative controls, external FRF-Fuzz, receipt-driven stages, and a risk-based verification schedule. Existing repository documents also cover cross-header/DSO ABI (`docs/ABI_POLICY.md`), security divergence (`docs/SECURITY_DIVERGENCE_POLICY.md`), and CI anti-regression (`docs/CI.md`). The upgrade should **operationalize** those constitutions, not replace them.

The highest-value omission is evidence for the **entire unsafe-abstraction lifecycle under C callback reentrancy**. The next is **tracing real consumer dependency paths** instead of treating coarse directory mappings or token-seam coverage as proof. The third is a **mechanical, fail-closed transition from local reconstructed ownership to externally reproducible safety discharge**.

## Ranked engineering gaps

| Rank | Priority | Gap / evidence in existing repository | Concrete action / completion witness | Value to drop-in consumers |
|---|---|---|---|---|
| 1 | P0 | Member-buffer / `RawCtx` contracts document owner invariants; broad caller, FFI callback and reentrancy closure is not established for every unsafe boundary | Stable boundary ID and caller/escape/destructor/callback graph; refuse/reentry tests; independently reviewed establishing code for every precondition | Prevent a crash/UB during otherwise legitimate OpenSSL API usage, TLS callbacks, custom providers, and allocator hooks |
| 2 | P0 | Safe-33 state measured 33 historical passes (8 L7, 25 L4) at the Phase-24 freeze; the current atlas records 33/33 at `L7-functional`, and only six families have detailed symbol fingerprints | Per-consumer binary/loader identity, imported symbols and versions, executed paths, explicit functional workload and security failure behavior | Focus engineering on actual curl/nginx/HAProxy/Redis/OpenSSH production surfaces, not equal-weight packages |
| 3 | P0 | Current atlas classifies a file as seamed if it contains a token; seal-only discharge = 0 | Obligation-level state `UNKNOWN -> CONTRACTED -> ESTABLISHED -> INDEPENDENTLY_CHECKED -> DISCHARGED` with fail-closed source-linked witness | Strong claims can survive independent maintainer scrutiny |
| 4 | P0 | `guard_ffi` / `AssertUnwindSafe` risk already flagged in §4, but no general callback rollback protocol enforced | Table for each C callback ABI/reentry/ownership/failure/poisoning; reentrant negative controls; no Rust unwinding over incompatible FFI | Avoid hidden state corruption during application callbacks |
| 5 | P0 | Container isolation defect is acknowledged (host worktree RW bind mount) | Disposable least-privilege courts, no host checkout mutation, audited permissions, separation of untrusted input | Necessary before running third-party tests or inviting public pilots |
| 6 | P1 | FRF-Fuzz strong in conception, but current sample and full-library evidence coverage differ | Stateful sequence fuzzers, two oracles, measured code/reach coverage, separate authentic and bypass-enabled fuzzing | Finds high-value TLS/ASN.1/provider state bugs missed by leaf-level tests |
| 7 | P1 | ABI policy strong but symbol exports alone are insufficient for real binary replacement | Assert `SONAME`, symbol versions, `dlvsym`, loaded DSOs, env/config, provider module and allocator behavior in current consumer processes | Prevents false-positive drop-in passes against the system libcrypto |
| 8 | P1 | Cryptographic and secret-handling policy exists; its per-algorithm/consumer execution status is still bounded | Wycheproof + protocol negative vectors, side-channel tested per artifact/compiler/CPU, fork/reseed/DRBG, FIPS claim separation | Protects key material and real application authenticity requirements |
| 9 | P1 | Fast conversion gates are established, full seal deferred | Triggered tests only on touched danger classes; full evidence at subsystem and promotion, not each edit | Maintains iteration speed without trading off final assurance |
| 10 | P1 | External adoption needs documented release-response and rollback contract | Maintainer-trial bundle with exact binaries, replay scripts, support scope, reports, rollback and security channel | Converts technical promise into manageable maintainer trial |

## Representative source-to-practice mapping

- **RustBelt and Ralf Jung on the scope of unsafe**: proof extends through *all operations that may invalidate the abstraction*, not the lexically marked `unsafe` lines. Requires stable boundary ID plus caller, escapes, mutators and destructor inventory. https://plv.mpi-sws.org/rustbelt/popl18/ ; https://www.ralfj.de/blog/2016/01/09/the-scope-of-unsafe.html
- **Rust provenance and Miri**: a valid address is not sufficient provenance; `&mut` uniqueness persists for the whole borrow. Miri catches particular executions and has native FFI limits; separate model tests from native sanitizer tests. https://www.ralfj.de/blog/2022/04/11/provenance-exposed.html ; https://github.com/rust-lang/miri/blob/master/README.md
- **Rustls' documented threat model**: hostile inputs, denial of service, protocol state, core-vs-provider trust boundary, OSS-Fuzz coverage and release/advisory process. Adapt the separation without deleting OpenSSL compatibility semantics. https://github.com/rustls/rustls/security
- **BoringSSL FUZZING.md**: deterministic/crypto-bypass fuzz builds to reach deep TLS states, separate real-crypto paths; never admit bypass mode to release. https://github.com/google/boringssl/blob/main/FUZZING.md
- **OpenSSL 3.6 docs**: precise allocator installation phase and hook observables; `SSL_get_error`/thread queue; provider fetch properties; FIPS provider claims; async and callback semantics. https://docs.openssl.org/3.6/man3/OPENSSL_malloc/ ; https://docs.openssl.org/3.6/man7/OSSL_PROVIDER-FIPS/ ; https://docs.openssl.org/3.6/man7/openssl-threads/
- **TLSfuzzer / TLS-Attacker**: verify rejects and protocol alerts in TLS negative-state courts rather than counting only successful handshakes. https://github.com/tlsfuzzer/tlsfuzzer ; https://github.com/tls-attacker/TLS-Attacker
- **Kani**: bounded symbolic properties for small abstractions; report bound, assumptions and scope. https://model-checking.github.io/kani/
- **libcrux**: separation of verified functional correctness, panic freedom and unverified binary side-channel behavior. https://github.com/celabshq/libcrux
- **Wycheproof**: independent malformed/attack vector oracle alongside OpenSSL compatibility oracle. https://github.com/C2SP/wycheproof
- **GNU linker versioning**: symbol version nodes are part of a binary drop-in contract. https://sourceware.org/binutils/docs/ld/VERSION.html
- **SLSA**: build provenance supports external rebuild and artifact integrity rather than a bare workflow-green claim. https://slsa.dev/spec/v1.2/

## A small, high-impact first batch (not 12 new pipelines)

1. Pick `SslSession` member-buffer machinery and one representative `SslCtx` owner. Map raw-pointer alias escapes, C callback/reentrancy, ownership and failure state to stable `boundary_id`s. Prove or enumerate each precondition. Target at most six files.
2. Add one callback/reentrancy witness, one allocation-refusal event transcript and one intentionally defective negative control. Keep every pre-existing library and functionality gate unchanged.
3. For **curl and nginx**, record exact DSO loaded, ABI symbol/version imports, representative TLS+certificate failures, current-candidate replay ID and actual runtime-observed entry points. Do not mistake imported symbols for executed code.
4. Test the smallest contracts with available model tools only if technically supported; native sanitizer for actual mixed C/Rust boundaries. Distinguish `NOT_RUN`, `UNSUPPORTED` and `PASS`.
5. Preserve outputs as append-only receipts; run full Phase-25 seal at subsystem integration rather than after each ownership conversion.

### Acceptance gate for any claim of improvement

A result is **not** a graduated memory-safety improvement because `unsafe` count dropped, more files contain owner tokens, a test suite stayed green, or a destructor trait was marked `unsafe`. The release-worthy result is a **specific UB mechanism made inexpressible under documented external preconditions**, supported by a complete caller contract, negative-control-sensitive execution where applicable, a bounded independently checkable proof and unchanged or explicitly adjudicated OpenSSL behavior. That proof then has to compose across an actual downstream dependency closure.
