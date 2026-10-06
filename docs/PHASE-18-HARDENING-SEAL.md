# Phase 18 — the hostile hardening contract: seal

**STATUS: derived.** This status is not typed; it is the state `forensics/tools/phase_state.py`
derives from artefact existence. The stratum's obligation ledger is empty of open rows —
`forensics/phase18-obligations.json` reads `open_in_this_stratum: 0` — every earlier stratum is
`complete`, and the FRF/Gemel chain entry §8 records has landed, so `forensics/phase-state.json`
reports phase 18 **`complete`** with an empty blocking reason. That derived state is the
phase-exit predicate, and D529 records that a ledger's own `complete` is *not* it
(`docs/DECISIONS.md`). `seal_sha256` is derived too: this document is named in
`forensics/tools/atlas_common.py`'s `SEAL_DOCS` table at `18`, which
`forensics/tools/render_seal_census.py` and `phase_state.py` read, so the line is recomputed
whenever this document changes and is not restated here. Reaching `complete` means the stratum has
reached the state a seal *records* (D421); it is **not** a security claim, and this document is
where what the derivation does and does not cover is written down.

**For every count in this document, read `docs/SEAL-CENSUS.md`**, which
`forensics/tools/render_seal_census.py` generates from the ledgers and the court results. This seal
cites that document rather than restating its arithmetic, because a number typed here is a number
that can drift from the evidence it summarises (D97). The tables this document *does* carry — §3's
court list and §7's criterion tables — each name the artefact they were read from.

**This seal records hostile-hardening evidence over the finished implementation, and it is neither
a security proof nor a parity claim.** Its evidence shows that the malformed-input corpora the
stratum drives produced the dispositions it recorded, that a deliberately branch-on-secret control
was caught by the constant-time screen, that the fixed-buffer boundary cases were driven at, below
and above each capacity with an honest injected-failure control, and that the register cannot claim
more than the courts measured. It does **not** show that the crate's parsers are safe against every
input, that any `unsafe` block is sound, that the paths the screen reports `independent` are
constant-time, or that the sanitizer-and-Miri results prove memory safety. `docs/PARITY_MODEL.md`
is the authority on what the labels mean, and `docs/NON_CLAIMS.md`, `docs/SECURITY_DIVERGENCE_POLICY.md`
and `docs/UNSAFE.md` are the authorities on what may be said. `PARITY_VERIFIED` is not claimed for
any symbol here — indeed this stratum owns none — and `forensics/STATUS.md`'s non-claims are the
generated projection's.

- Authority: `openssl-3.6.4-production` (`forensics/authorities/AUTHORITIES.json`), named as the
  authority by `artifacts/phase18/COURTS.json`. The FRF chain binds the runtime authority identity
  `openssl-rt-3.6.4-r2`.
- Court results: `artifacts/phase18/COURTS.json` — five courts, `all_pass` true, `summary` `pass`
  5 of 5, `pending_courts` empty; the per-court table is §3. Three are **differential transcript
  courts** that declare an FRF court (`RT-HOSTILE-TLS`, `RT-HOSTILE-X509`, `RT-MEM-HARDENING`);
  `CT-PRIMITIVES` is **candidate-only** (no authority transcript exists for a secret-independence
  property) and `HOSTILE-BOUNDARY-REGISTER` is a **data-validation** court whose own row is marked
  `frf_declarable: false`, and §1, §3 and §5 state why neither is declared.
- Obligation ledger: `forensics/phase18-obligations.json` — `owned` 5, `implemented` 5,
  `deferred_to_later_phase` 0, `open_in_this_stratum` 0; its unit is `hostile hardening contract`,
  a non-export unit, and its `atlas_owned` count is 0. `contract_units` 5, `provider_rows_owned` 0,
  `provider_rows_open` 0, `deferrals_received` 0 and `unit_deferrals_received` 0: it receives and
  hands forward nothing.
- Court coverage: `forensics/atlas/court-coverage.json` records **no phase-18 row**, and that is
  the join's own definition rather than an omission: `court_coverage.py` skips a ledger whose unit
  is in `atlas_common.NON_EXPORT_UNITS` (the same rule Phase 16's `cli-config contract` and Phase
  17's `downstream replacement contract` meet), so a stratum with no export universe can have no
  row and no unmatched export. §1 and §3 state the reading; `docs/DECISIONS.md` D485 records the
  marker.
- Derived state: `forensics/phase-state.json`, phase 18, `complete` with empty blocking. It owns
  **no exported symbol**, so its `atlas_owned` count is 0 and it registers no provider row.
- FRF receipts and claim: **present, and the chain's objects are on disk.** `.frf` carries three
  receipts, one per declarable court; six adjudicated challenge records (both declared operators
  on every court); and the `sensitivity-backed` claim
  `505ceaf418cb458554c3c7ac23922a2835a847ddc6b79c1291086878460af575`, binding
  `openssl-rt-3.6.4-r2` to `openssl-rs 0.0.25` (`identity_hash e4f60d8b`) with zero blockers. Two
  of the three premises are narrowed to the exit class, and §8 states what that is.
- Gemel checkpoint: **present, and it is this stratum's.** `forensics/GEMEL_TRAJECTORY.md`'s
  `current:` is the checkpoint `K63`
  (`checkpoint.b64e46d7d62f37035f586a7bdeddfafc39751738649c804c31ab4f5ecb306cff`), whose summary
  names Phase 18 and the FRF chain; the change that closes it is `C110`
  (`change.4f91d4ccf5b9fa9acdca24ac4c464cd038f795ff6b2e91fbcbb24214c8baf28a`). §8 states what
  that is.
- Deciding record: `docs/DECISIONS.md` — **D485** is the non-export-unit marker Phase 16 and 17
  share, **D525** hands the legacy provider rows past Phase 16, **D530** fixes the Phase-17
  entrance criteria and the 52 command bodies, **D13** and **D201** are the rules under which a
  candidate-only `CT-*` court is not FRF-declarable, and `docs/PHASE-18-SUBPHASES.md` is the
  subphase plan this seal closes. §10 summarises the corrections this seal records.

## 1. What this phase owns, and how that was decided

Phase 18 is **the hostile hardening contract stratum**, and like Phases 16 and 17 it owns **no
exported symbol**. Reading `forensics/atlas/symbol-ownership.json` for `owner_phase == 18` yields
nothing (`docs/PHASE-18-SUBPHASES.md:42-45`), because the declaring-header rule assigns no installed
header to this stratum; its ledger's `atlas_owned` count is therefore `0` and the ledger fails
closed if that ever stops being true rather than counting a symbol through a non-export unit
(`forensics/tools/phase18_obligations.py`).

**Its working set is its five contract units, and it receives and hands forward nothing.** Unlike
Phases 16 and 17 it takes no unit or symbol deferral from an earlier stratum and defers none: the
implementation it hardens is the one Phases 3 through 15 completed. `forensics/phase18-obligations.json`'s
`rule` names the contract units and says the ledger types none of them; `main` fails closed if the
ownership atlas assigns this stratum an export, the provider census a row, or the prerequisite
plane a deferral or a unit.

**The contract is five units**, each derived from a court that measures it:
`hostile-tls` (`RT-HOSTILE-TLS`), `hostile-x509` (`RT-HOSTILE-X509`), `constant-time`
(`CT-PRIMITIVES`), `memory-hardening` (`RT-MEM-HARDENING`) and `hostile-boundary-register`
(`HOSTILE-BOUNDARY-REGISTER`). The ledger's `contract_units` reads 5 and all five are
`implemented`.

**The ledger's unit is not an exported symbol.** `forensics/phase18-obligations.json` publishes
`unit: "hostile hardening contract"`, its `implemented`/`open` *export* lists are empty by
measurement, and its working set is counted in `open_in_this_stratum` over the five contract units.
`atlas_common.NON_EXPORT_UNITS` names the unit, so the two tools that partition the export universe
(`court_coverage.py`, `ownership_audit.py`) skip this ledger rather than reconcile a symbol set that
does not exist (D485).

**The two axes are recorded separately, and that is the point of the ledger shape.** Each contract
unit carries `measurement_state` (the instrument ran and its control was honest) beside
`property_status` and `findings` (what, if anything, the unit claims about a security property).
`constant-time` is the unit where the two diverge: `CT-PRIMITIVES` passes while recording the two BN
paths (`bn-modexp`, `bn-inverse`) as `separated` findings, so the property reads `NOT_CLAIMED` with
`findings_present`. **A passing `CT-PRIMITIVES` must never be read as "constant-time achieved".**
The findings are read from the court row rather than typed, and the ledger carries both axes for
every unit.

**This stratum's evidence is adversarial in its subject rather than differential in its
instrument.** It emits no primitive and owns no symbol: the subject is a hostile input against a
finished implementation. Three of its five courts are differential transcript courts and are FRF
declarable; the fourth is candidate-only and the fifth validates data, so neither carries a
declaration (D13, D201) and §3 states why.

**It begins on nothing of its own.** No hardening court exists at activation, so
`open_in_this_stratum` opens at the whole working set (five) and moves to zero as 18.1 through 18.5
land their rows and units. The ledger's `counts` is the live record; §1's activation measurement is
the plan's. The activation was taken against `main` `abc8a1c0` (openssl-rs 0.0.22, Phase 17
released).

**This stratum is a non-export unit, and the export-partitioning tools say so by the document's own
field.** `forensics/phase18-obligations.json` publishes `unit: "hostile hardening contract"`, which
`atlas_common.NON_EXPORT_UNITS` contains, so `court_coverage.py` and `ownership_audit.py` skip the
ledger rather than reconcile a symbol set that does not exist — exactly as they skip Phase 16's
`cli-config contract` and Phase 17's `downstream replacement contract` (D485).

## 2. What has been built

**18.0, the plan and the ledger.** `docs/PHASE-18-SUBPHASES.md` and the measurement in its §1, the
ledger `forensics/phase18-obligations.json` and its generator, and the runner
`forensics/tools/phase18_courts.py` with the registry it writes. The runner could not be deferred
(`docs/PHASE-18-SUBPHASES.md` §4.2): `run_courts.py` refuses a stratum that is not `not-started`
and has no runner, and this stratum's obligations are not exports, so its first runnable court is a
later subphase's. It landed with `PENDING_COURTS` naming the five planned courts, which 18.1
through 18.5 emptied. The direction of the `phase18_courts.py` <-> `phase18_obligations.py` edge is
the reverse of Phase 16's: the ledger's contract-unit states are measured from the courts registry,
so the registry is generated first and `phase18_courts.py` does **not** bind the ledger as an input.

**18.1, the hostile TLS corpus.** `RT-HOSTILE-TLS` compiles `courts/phase18/rt_hostile_tls_probe.c`
twice (authority and candidate) and drives the fixed 87-entry corpus
`courts/phase18/fixtures/hostile-tls/` (5,072 bytes: 20 record, 29 extension, 14 clienthello, 9
serverhello, 9 handshake and 6 control entries) through the real record layer and the TLS 1.3 flight
— a `server` entry into `SSL_accept`, a `client` entry into `SSL_connect` over a read-only memory
BIO. Each entry runs in its own forked child, so a crash, an OOM (under the process `RLIMIT_DATA`)
or a timeout is a recorded finding. The corpus is generated by
`forensics/tools/gen_hostile_tls_corpus.py` and its manifest is
`courts/phase18/fixtures/hostile-tls/MANIFEST.json`; the authority differential control
(`ch-min-valid`, a real handshake-record parse) is honest. 1,046 observations.

**18.2, the hostile X.509 / malformed-input corpus.** `RT-HOSTILE-X509` compiles
`courts/phase18/rt_hostile_x509_probe.c` twice and drives the fixed 133-entry corpus
`courts/phase18/fixtures/hostile-x509/` (42,802 bytes: extensions, PEM, time, malformed-tbs,
truncated, length-bomb, req, CRL, oversized, sigalg, bit-string, malformed-asn1 and control arms)
through the X.509, ASN.1 and PEM readers the arm names. Each entry runs in its own forked child; the
authority differential control (`cert-valid`, a real v3 certificate parse) is honest; its four base
inputs are the Phase-17 fixtures with recorded provenance. 1,066 observations, zero residuals.

**18.3, the constant-time / secret-independence screen.** `CT-PRIMITIVES` is candidate-only and
compiles `courts/phase18/ct_primitives_probe.c` once against the candidate distribution shell. For
each measured path — `BN_mod_exp_mont_consttime` and `BN_mod_inverse` over a 255-bit prime;
`RSA_private_decrypt` over two keys whose CRT exponents differ in Hamming weight; `EC_POINT_mul` on
P-256 through the constant-time ladder; `CRYPTO_memcmp` over a 4 KiB tag; and `EVP_KDF` HKDF
extract+expand — it drives the operation under two secret classes, 320 samples per class after 32
warmups, and classifies `separated` when the ratio of the two minimum batch times exceeds 110
percent. The §3.2 sensitivity control (`control-branchy-tag`, a deliberate branch-on-secret tag
comparison) is `separated` exactly where the path it varies (`aead-tag-memcmp`) is `independent`, so
the instrument provably discriminates. `rsa-private`, `ec-scalar-mul`, `aead-tag-memcmp` and
`tls-key-schedule-hkdf` are `independent`; `bn-modexp` and `bn-inverse` are `separated` and are
recorded as findings, not failed.

**18.4, the memory-safety / resource-exhaustion court.** `RT-MEM-HARDENING` compiles
`courts/phase18/rt_mem_hardening_probe.c` twice and drives the reduced engine's fixed buffers at,
just below and just above each recorded capacity: the record write's `SSL3_RT_MAX_PLAIN_LENGTH`
(16384) inner buffer via a full TLS 1.3 `SSL_write` of the boundary length, the
`TLS13_HS_BUF_LEN` (16384) handshake-reassembly buffer and the `Ssl::rec_body` (17000) store, 14
cases each in its own forked child. The injected-failure control is explicit: `ctrl-rlimit` lowers
`RLIMIT_DATA` and observes `ERR_R_MALLOC_FAILURE`; `ctrl-d2i` drives an allocation over a DER that
declares a 64 MiB content and observes a NULL `d2i_X509`; `ctrl-hook` installs a wrapper allocator
through `CRYPTO_set_mem_functions`. `failure_driven` is true on both sides. 282 observations.

**18.5, the hostile-boundary register.** `HOSTILE-BOUNDARY-REGISTER` stages no probe: its subject is
`artifacts/phase18/hostile-boundary-register.json`, the authored register that records, per surface,
whether it is `hardened` (a change landed), `measured` (a passing court covers it) or `not-claimed`
(explicitly outside this stratum) — 1 `hardened`, 18 `measured` and 10 `not-claimed` of 29 surfaces.
The court re-reads the live courts registry and fails the stratum if any recorded classification,
surface key, capacity or count has drifted from what the courts show. It also runs the
`UNSAFE-FOOTPRINT` growth check and the provenance regression guard (§4).

**18.6, the seal.** This document, the FRF/Gemel chain §8 records, and the registry rows the chain
requires.

**The books that moved with the code.** Phase 18's own ledger reads `owned` 5, `implemented` 5,
`deferred_to_later_phase` 0 and `open_in_this_stratum` 0, with `contract_units` 5, no provider row
and no deferral either way. The split moved as the subphases landed their rows, so this note does
not restate counts the ledger is the live record of.

## 3. The evidence

Copied from `artifacts/phase18/COURTS.json`. Observation counts are the court's own
`authority_observations`, which `forensics/tools/atlas_common.py` requires to equal the candidate's
before a row may be called true. Three courts are differential transcript courts; `CT-PRIMITIVES` is
candidate-only and `HOSTILE-BOUNDARY-REGISTER` validates the registry and the footprint bounds, so
both observe nothing line-wise.

| court | plane | observations | instrument |
|---|---|---|---|
| `RT-HOSTILE-TLS` | differential (hostile TLS corpus) | 1046 | `courts/phase18/rt_hostile_tls_probe.c` |
| `RT-HOSTILE-X509` | differential (hostile X.509 corpus) | 1066 | `courts/phase18/rt_hostile_x509_probe.c` |
| `CT-PRIMITIVES` | candidate-only (secret-independence) | — (structural) | `courts/phase18/ct_primitives_probe.c` |
| `RT-MEM-HARDENING` | differential (fixed-buffer boundary) | 282 | `courts/phase18/rt_mem_hardening_probe.c` |
| `HOSTILE-BOUNDARY-REGISTER` | data-validation (register + footprint) | — (structural) | `artifacts/phase18/hostile-boundary-register.json` |

Every differential row carries `hostile_residual_count: 0` and `verdict: "pass"`, and the summary
reads `pass` 5 of `total` 5 with `pending_courts` empty. `RT-HOSTILE-TLS` records 283 divergences
and `RT-MEM-HARDENING` 21, each as a recorded disposition rather than a residual; the total over
the three transcript courts is `docs/SEAL-CENSUS.md`'s, and the per-court rows there are the same
computation.

**The differential control is what keeps the expectation honest.** Each `RT-HOSTILE-*` court is
`pass` only when the corpus was driven on both sides, every candidate disposition was recorded, and
the authority differential control held — the authority parsed the well-formed control entry into a
real structure and itself suffered no crash, OOM or timeout. A hostile corpus whose control the
authority cannot parse would make the court `fail` rather than pass on vacuous agreement
(`docs/PHASE-18-SUBPHASES.md` §3.2).

**The candidate-only and data-validation courts are not transcript courts, and their rows say so.**
`CT-PRIMITIVES` has no authority transcript to diff — a secret-independence property is not an
authority behaviour — so it is compiled once against the candidate and carries a sensitivity
control instead; it is not declared in `gen_frf_courts.py` (D13, D201), exactly as Phase 8's, 9's
and 10's `CT-*` courts are not. `HOSTILE-BOUNDARY-REGISTER` stages no probe pair and re-reads the
live courts registry and the authored register, so its own row is marked `frf_declarable: false`
and no declaration is generated for it; §5 and §7 record that the seal depends on it.

**The court coverage join does not have a phase-18 row, and that is the join's own definition.**
`docs/SEAL-CENSUS.md`'s coverage table lists no phase-18 row for the same reason it lists no
phase-16 or phase-17 row: all three are non-export units, so `court_coverage.py` skips their
ledgers and there is no export to partition. The provider-row join (D245) is likewise vacuous: this
stratum owns no provider row.

## 4. What the courts found

A court whose results never surprised anyone is a court that is not looking, and this stratum's
courts did look. They found real defects in the candidate, and one measurement record that is honest
about what each instrument can and cannot drive.

**The constant-time screen found the reduced engine's BN core separates its two secret classes.**
`CT-PRIMITIVES` records `bn-modexp` and `bn-inverse` as `separated` (`RSA`, `EC`, the AEAD tag
compare and the TLS key-schedule HKDF are `independent`), and the ledger, the courts registry and
the register all carry them with `property_status: NOT_CLAIMED`. The separation is expected rather
than a surprise — `src/bn/exp.rs` documents a square-and-multiply core — and the court's job is to
record it with a *proven-sensitive* instrument: the `control-branchy-tag` control is `separated`
exactly where the real tag-memcmp path is `independent`. **This is an instrument result, not a
constant-time claim**; a secret dependence below the screen's 50 percent floor reads `independent`
and is outside its resolution (`docs/PHASE-18-SUBPHASES.md` §3.2).

**The memory court found the read path's bounds are enforced, and one contract is only as strong as
its caller.** The write path `ssl3_write_bytes`/`tls13_encrypt_record` fragments at
`SSL3_RT_MAX_PLAIN_LENGTH`, so the below/at/above cases all round-trip N bytes on both sides — the
previous greater-than-16-KiB overflow is fixed, not merely bounded. The handshake-reassembly buffer
`TLS13_HS_BUF_LEN` (16384) rejects the below/at cases as malformed and rejects the above case; the
record-body store `Ssl::rec_body` (17000) reads the whole body then rejects on the handshake cap at
17000 and refuses at 17001, consuming 17005/5 bytes where the authority stops at 5 — a recorded
divergence, not a fix. `tls13_encrypt_record`'s inner buffer copies `len` bytes without checking
`len`: the fragmenting caller bounds it, but the function's own `# Safety` contract does not, so it
is recorded as **merely `unsafe` to call directly** rather than silently fixed (§3.4). The
injected-failure control is honest: the candidate's allocation-failure paths returned
`ERR_R_MALLOC_FAILURE` and a NULL `d2i_X509` rather than aborting.

**The unsafe footprint is measured, not asserted, and it is concentrated exactly where the
implementation is not.** `forensics/atlas/unsafe-footprint.json` and its rendered form in
`forensics/STATUS.md` record **58,826** `unsafe` sites and **10,866** `extern "C" fn` over 855 files
and 801,656 lines: the **core** parser/algorithm modules (69 modules) carry **52,943** unsafe sites
(**90.0%**) and the **boundary** layer (6 modules) **5,883** (10.0%). `src/ffi` carries none. The
claim that `unsafe` is concentrated in narrow boundary modules is therefore **false of this
implementation** — which is why the `UNSAFE-FOOTPRINT` growth check inside `HOSTILE-BOUNDARY-REGISTER`
fails if any core module's count rises above the ceiling recorded in
`artifacts/phase18/unsafe-bounds.json`, while the boundary layer is allowed to grow. The
measurement establishes the size and location of the surface, **not its correctness** (`docs/UNSAFE.md` §2).

**The provenance blocker is fixed at its root, and the fix is guarded.** The allocator-trampoline
class that stopped Miri — an integer reconstructed into a callable pointer — was removed: the
callback slots in `src/runtime/mem.rs` (and the async stack slots in `src/async/arch/async_posix.rs`)
are `AtomicPtr<()>`, installed `f as *const () as *mut ()` and recovered by a pointer->function-pointer
`transmute` after a null check; `CRYPTO_get_mem_functions` reconstructs pointer-shaped values and
`CRYPTO_aligned_alloc` uses `ptr.addr()` for its address-only alignment observation while keeping
`base` for provenance. The class cannot silently return: `forensics/tools/provenance_court.py` is a
regression guard inside `HOSTILE-BOUNDARY-REGISTER`, so a reappearing integer->callable-pointer
reconstruction fails the stratum.

**ASan found six distinct first-party defects, and every layer it covers is now clean.** The
dedicated sanitizer venue (`docker/openssl-rs-asan.*`) instruments the Rust staticlib, the
first-party C adapters and the probes, with libc runtime-intercepted, and its sensitivity canary (a
deliberate heap use-after-free) must be diagnosed before any zero-findings result is trusted. It
found, each fixed at the root against the authority: a test buffer in `src/modes/wrap.rs`; real
candidate bugs in `src/provider/rand.rs`, `src/evp/pem_bridge.rs`, `src/dso/dlfcn.rs` and the
`src/evp/legacy_evp.rs` tests; and a sixth found by the CPython layer — `SSL_new` in
`src/ssl/ssl_lib.rs` took **one** initial-context reference but assigned it to both `ssl->ctx` and
`session_ctx`, while the authority up-refs once for each (`ssl/ssl_lib.c:705`, `:828`) and releases
both (`:1438`, `:1485`); an SNI callback switching contexts (`SSL_set_SSL_CTX`, `ssl_lib.c:5535`)
then freed the context `session_ctx` still aliased, and a TLS 1.3 session ticket read it
(heap-use-after-free at `src/ssl/statem/statem_srvr.rs:2892`). `SSL_new` now takes, and `SSL_free`
releases, the second reference. Five in-process layers ran — the allocator/unit tests, targeted
ownership tests, the hostile TLS corpus, the hostile X.509 corpus and the 16,384-case mutation
corpus — and all six layers, including the downstream consumers layer, report zero findings
(`artifacts/phase18/asan.json`).

**The six sealed downstreams run clean under the ASan candidate, with OpenSSH envelope-limited by
its own sandbox.** The sixth layer runs each Phase-17 consumer against ASan-instrumented
distribution DSOs built into a dedicated prefix (`/asan/install`, by
`forensics/tools/build_phase2_asan.sh`, which never touches `artifacts/phase2/install`). Five run
clean at zero findings: curl's TLS 1.3 client with its unrelated-CA negative arm, nginx TLS 1.3 with
session resumption, HAProxy TLS termination, Git's Smart-HTTP push/clone/pull, and CPython's bounded
`test_ssl` (172 pass, 0 fail). **OpenSSH is envelope-limited, not clean:** its seccomp sandbox
(`sandbox-seccomp-filter.c:193-203`) denies the `mmap` ASan uses to reserve its shadow in the sshd
preauth child (`ReserveShadowMemoryRange failed ... errno: 22`), so only OpenSSH's libcrypto-only
operations (key generation, sign/verify, fingerprints, algorithm enumeration) ran under ASan — and
were clean — while the sshd handshake path could not. This is a consumer-sandbox-versus-sanitizer
incompatibility, the same class as the court's `RLIMIT_DATA` (D105), and it is recorded rather than
hidden (`artifacts/phase18/asan-downstream.json`).

**Miri executed the admitted TCB subset and found a real aliasing defect; it refuses the surface it
cannot model.** `cargo +nightly miri test --lib miri_tcb` under `-Zmiri-strict-provenance`, run
under seeds 0, 1 and 2 (and ordinary mode, seed 0): **9 admitted tests, 9 passed, 0 unsupported
tests ran** (`artifacts/phase18/miri-tcb.json`). The suite `src/runtime/miri_tcb.rs` installs a
Rust-backed allocator shim through `CRYPTO_set_mem_functions` before its first allocation, so the
`CRYPTO_*` ownership surface, the X.509 refcount/lifetime path, the `OPENSSL_STACK`/`OPENSSL_LHASH`
containers, the `BUF_MEM` gateway and the object registry run without libc. Miri **found a real
aliasing defect** the suite exists to catch — `object_free` (`src/runtime/obj.rs`) formed `&mut *p`
on a static registry object reachable from `X509_free`, now fixed by reading the flags before any
mutable reference is formed. What Miri **does not execute** is named with a reason in
`forensics/miri-tcb-suite.json`: the libc FFI in `src/runtime/bio/sys.rs`, the DSO boundary in
`src/dso/dlfcn.rs`, the `ucontext` fibres, `getrandom` and `rdtsc`.

**The bounded fuzz surfaced the PEM defect and is a screen, not a campaign.**
`forensics/tools/fuzz_hostile_corpus.py` drove 16,384 deterministic mutants over the committed
hostile X.509 corpus in a 300 s bound (34.7 s actual) with zero findings on the fixed corpus
(`artifacts/phase18/fuzz-hostile-corpus.json`); under ASan the same class of screen surfaced the
`src/evp/pem_bridge.rs` defect recorded above. It is neither coverage-guided nor a fuzzing campaign.

**The FRF venue found that the hostile transcripts legitimately differ, and the claim is honest
about it.** The FRF runtime harness's first stdout line is a digest of the whole transcript, and the
hostile courts record their divergences rather than diffing them (§5), so `rt-hostile-tls` and
`rt-mem-hardening` raise one `open` first-stdout-line residual each. Disposing it would have let the
claim assert a first stdout line it does not have; **leaving it open narrows those two premises to
the exit class** and the claim carries both axes on `rt-hostile-x509`. The claim
`505ceaf418cb458554c3c7ac23922a2835a847ddc6b79c1291086878460af575` compiles with zero blockers.

**The one instrument boundary: the register stages no probe, and the sanitizer venue is not the
court.** `HOSTILE-BOUNDARY-REGISTER` is a data-validation court that re-reads the live courts
registry and the authored register; its evidence is the register and the footprint bounds, not a
transcript. ASan runs in a dedicated venue (`docker/openssl-rs-asan.*`) with its own execution
envelope, not in the forensic court, because the court's hard 4 GiB `RLIMIT_DATA` is what keeps a
runaway court off the host. The seal records both distinctions rather than counting either as a
transcript court.

**No generator drift the stratum's own slices left went unreconciled, and the seal forced none.**
Unlike Phase 14 (D529), whose later slices left four artefacts that only surfaced when the stratum
was derived `complete`, this stratum's slices are one plan, one ledger, one runner and five courts,
and deriving `complete` surfaced no reconciliation the slices had not already made. §10 records the
corrections this seal does make.

## 5. Fault boundaries — recorded, not reproduced

Where the authority dereferences a NULL, relies on an unset field, or builds an object this crate
does not, the court does not call it and the divergence is recorded. **No divergence obligation
names Phase 18 as its `current_owner`.** `forensics/divergence-obligations.json` reads 10 rows and
**0 blocking** at seal time; no live obligation outran this stratum's evidence, so `phase_state.py`
derives `complete`. The boundaries this stratum actually met are recorded in the places below.

1. **`RT-HOSTILE-TLS` records 283 divergences rather than diffing them.** The reduced TLS 1.3
   engine legitimately disposes of malformed records, handshake messages and extension bodies
   differently from the full authority — a smaller extension set, a reduced security callback, a
   partial flight — so the court records each entry's authority/candidate dispositions and fails
   only if the corpus was not driven, a candidate disposition was not recorded, or the authority
   control did not hold (`docs/PHASE-18-SUBPHASES.md` §3.1). All 283 are class `value`.
2. **`RT-MEM-HARDENING` records 21 divergences rather than diffing them.** The record-body store
   consumes 17005/5 bytes where the authority stops at 5, and the handshake-reassembly dispositions
   differ; each is recorded, not failed. All 21 are class `value`.
3. **The `tls13_encrypt_record` inner buffer is merely `unsafe` to use and is recorded, not
   fixed.** Its `# Safety` contract does not check `len`; the fragmenting caller bounds it. The
   register records it `merely-unsafe-to-use-recorded` rather than claiming it hardened
   (`docs/PHASE-18-SUBPHASES.md` §3.4).
4. **`CT-PRIMITIVES` is candidate-only, and that is the instrument.** A secret-independence
   property has no authority transcript to diff, so the court compiles once against the candidate
   and carries a sensitivity control instead; it is not FRF-declarable (D13, D201). A path below the
   screen's 50 percent floor reads `independent` and is outside its resolution.
5. **`HOSTILE-BOUNDARY-REGISTER` stages no probe.** Its subject is the authored register and the
   live courts registry, so it carries no `artifacts/phase18/probes/` pair and no FRF declaration;
   `frf_declarable` is false.
6. **ASan is a dedicated venue, and its closure is named rather than assumed.** The Rust staticlib,
   the first-party C adapters and the probes are instrumented; libc is not statically instrumented
   (the probes are dynamically linked and ASan's interceptors cover it); and the
   `CRYPTO_set_mem_functions` custom-allocator path is recorded separately rather than claimed to be
   ASan-instrumented end to end. The authority is **not** rebuilt under ASan.
7. **TSan/UBSan/MSan did not run, and Miri refuses the surface it cannot model.** The instruments
   that could not run are named with a reason rather than silently skipped: TSan/UBSan/MSan are
   deferred, and Miri refuses the libc FFI, the DSO boundary, the `ucontext` fibres, `getrandom` and
   `rdtsc` (`forensics/miri-tcb-suite.json`).
8. **The FRF venue narrows two premises rather than disposing their residuals.** §4 records why
   leaving the first-line residual open is the honest reading; `rt-hostile-x509` carries both
   stdout and exit.
9. **The `pending.` set is empty, and that is a measurement.** Every court the plan names is
   registered in `artifacts/phase18/COURTS.json`, and `PENDING_COURTS` is empty; this stratum owns
   no exported symbol, so nothing is counted as pending rather than dropped (§3).

## 6. What is explicitly NOT claimed

1. **Not parity, and not a usable drop-in OpenSSL.** `implemented` in the ledgers means a symbol
   with that name is defined, and this stratum defines none. `docs/PARITY_MODEL.md` states what each
   label means; no symbol here is `PARITY_VERIFIED`, and `forensics/STATUS.md` carries the current
   non-claims. A passing hostile court is at most `SEMANTIC_PASS` over the corpus it drives — never
   `PARITY_VERIFIED`.
2. **This is not a security claim, and a fixed corpus is not a fuzzer.** `RT-HOSTILE-TLS` and
   `RT-HOSTILE-X509` drive a fixed enumeration of malformed inputs; they are bounded differential
   results over the corpus they drive, not coverage claims and not safety proofs. The one fuzz is a
   bounded, deterministic 16,384-case screen in a 300 s budget (`artifacts/phase18/fuzz-hostile-corpus.json`),
   explicitly **not** coverage-guided, **not** a campaign and **not** a security proof. A corpus
   that does not reach a surface is named `pending`, not counted as passing
   (`docs/PHASE-18-SUBPHASES.md` §3.1, §3.6).
3. **The constant-time screen has a 50 percent floor, and a pass is not constant-time achieved.**
   `CT-PRIMITIVES` reports a path `separated` only when the ratio of the two minimum batch times
   exceeds 150 percent; a smaller secret dependence is reported `independent` and is outside its
   resolution. A passing `CT-PRIMITIVES` is the instrument's proven sensitivity plus a bounded
   screen at that resolution — never a proof of constant-time behaviour, never a wall-clock claim
   and never an attack claim. The `bn-modexp`/`bn-inverse` findings read `NOT_CLAIMED`, not
   "independent" (`docs/PHASE-18-SUBPHASES.md` §3.2).
4. **ASan covers the candidate, not the authority, and not the other sanitizers.** The venue
   instruments one candidate build and runs its adversarially-driven probes and the six downstream
   consumers; it does **not** rebuild or run the authority under ASan, and **TSan, UBSan and MSan
   did not run** (`artifacts/phase18/asan.json`'s `not_reached`). OpenSSH is envelope-limited by its
   seccomp sandbox: only its libcrypto-only operations ran, so its sshd handshake path carries no
   ASan observation at all.
5. **Miri executes only the admitted subset.** `cargo +nightly miri test --lib miri_tcb` ran 9
   admitted tests under three seeds plus ordinary mode and passed; it does **not** execute the libc
   FFI, the DSO boundary, the `ucontext` fibres, `getrandom` or `rdtsc` (each refused with a reason
   in `forensics/miri-tcb-suite.json`). A green Miri run is evidence about the admitted subset under
   one model, not about the crate.
6. **No memory-safety guarantee.** The unsafe footprint is a measurement of size and location, not
   correctness; no `unsafe` block is proven sound and no `SAFETY:` comment is proven true. ASan
   found six real defects and the layers are now clean, but a clean layer is a bounded observation
   under one instrument, and TSan/UBSan/MSan did not run. `docs/UNSAFE.md` §2's non-claim stands:
   the memory-safety benefit remains unproven.
7. **The FRF and Gemel evidence is established, and §8 records what it is.**
   `docs/RELEASE_GATES.md` §2 items 6, 8 and 10 are met by the chain entry §8 records: three
   receipts, six adjudicated challenge records, the `sensitivity-backed` claim
   `505ceaf418cb458554c3c7ac23922a2835a847ddc6b79c1291086878460af575` with zero blockers, and the
   Gemel checkpoint `K63` whose summary names Phase 18 and the FRF chain. Phase 18's derived state
   is `complete`. Two premises are narrowed to the exit class (§4), and that is recorded rather
   than smoothed.

## 7. Exit criteria

The project's rule for every stratum is `docs/RELEASE_GATES.md` §2 (`docs/RELEASE_GATES.md:49-66`):
ten items, and any open residual intersecting the claim scope blocks the claim. The plan's own gates
are its §5 process — a subphase lands its code, its court and its regenerated artefacts in **one
commit**; every name a subphase lands carries a court edge where it has one; and an artefact a
source change moves is regenerated in the same commit — and its §4.2 precondition (the runner lands
**with** the ledger). Every clause below is checked against a generated artefact rather than
asserted.

| criterion | evidence |
|---|---|
| every row this stratum owns is implemented or handed on with the dependency named | `forensics/phase18-obligations.json`: `open_in_this_stratum` 0, `deferred_to_later_phase` 0, `contract_units` 5 all `implemented`, no deferral either way |
| the export-coverage join is vacuous here, and that is the marker's rule | no phase-18 row in `forensics/atlas/court-coverage.json`, because `phase18-obligations.json`'s `unit` is in `atlas_common.NON_EXPORT_UNITS` (D485); `phase_state.py` scopes the rule out for such a ledger |
| no authority fault is reproduced | §5, and the boundaries recorded in the probes and the register |
| no blocking divergence obligation names this stratum | `forensics/divergence-obligations.json`: 10 rows, 0 blocking; none names Phase 18 |
| `ABI-PROTOTYPE`, `ABI-SYMBOL` and `ABI-DYNAMIC` stay clean | `forensics/atlas/ownership-audit.json`: `problems` empty, `implemented_by_two_strata` empty |
| the prototype court clean | `forensics/atlas/prototype-court.json`: `mismatches` 0 |
| the dispatch court clean | `forensics/atlas/dispatch-court.json`: `problems` 0 |
| the prerequisite gate at zero findings | `forensics/atlas/prerequisite-gate.json`: `findings` empty |
| the plan reconciliation at zero findings | `forensics/atlas/plan-reconciliation.json`: `findings` empty |
| the earlier strata are complete, which the rule requires | `forensics/phase-state.json`'s rule line |
| the courts are re-derived on every push, not trusted from a committed file | the `courts` job in `.github/workflows/ci.yml` runs `court/pipeline.sh` |
| a commit may not undo an earlier commit's evidence | `forensics/tools/regression_guard.py` against the branch's previous head and against `origin/main` |

**`docs/RELEASE_GATES.md` §2's ten items, each checked rather than assumed.** The first column is
the authority's own list (`docs/RELEASE_GATES.md:54-63`); the second says what this stratum's
evidence for it is, and, where an item is **not met**, says so plainly rather than leaving the row
empty.

| # | item | this stratum's evidence |
|---|---|---|
| 1 | authority identity | `forensics/authorities/AUTHORITIES.json` pins `openssl-3.6.4-production`; `artifacts/phase18/COURTS.json` names it |
| 2 | obligation inventory | `forensics/phase18-obligations.json`; 5 contract units, 0 provider rows, 0 export rows |
| 3 | court manifests | `artifacts/phase18/COURTS.json` |
| 4 | raw captures | **met.** The three staged `artifacts/phase18/probes/<probe>.{authority,candidate}` pairs are the captures the court venue diffs, and `.frf/captures/` carries the FRF venue's captures for the three declarable courts, produced by §8's chain |
| 5 | residual set | **met in the court venue.** Every differential court's `hostile_residual_count` is 0, `summary` reads `pass` 5 of 5 and `pending_courts` is empty; the 283 TLS and 21 memory divergences are recorded dispositions, not residuals. In the FRF venue, two premises carry one `open` first-line residual each, narrowed around by the claim and recorded in §4 |
| 6 | mutation / sensitivity evidence | **met.** `.frf/challenges/` carries six adjudicated Phase-18 records — both declared axes (`stdout-first-line`, `exit-class`) on all three declarable courts, each `saw_defect` and `specificity_clean` — which is what makes the claim `sensitivity-backed` rather than merely green (D13) |
| 7 | resolution runs | **not applicable, and therefore not met.** `--resolution-run` is required only for a `fixed` disposition, and no Phase-18 FRF residual is disposed `fixed` |
| 8 | FRF receipts | **met.** `.frf/receipts/` carries three Phase-18 receipts, one per declarable court |
| 9 | generated parity projection | `forensics/STATUS.md`, rendered by `forensics/tools/render_status.py`; the seal-facing arithmetic is `docs/SEAL-CENSUS.md` |
| 10 | Gemel checkpoint | **met.** `forensics/GEMEL_TRAJECTORY.md`'s `current:` is `K63` (`checkpoint.b64e46d7d62f37035f586a7bdeddfafc39751738649c804c31ab4f5ecb306cff`), whose summary names Phase 18 and the FRF chain |

**Nine of the ten items are met — 1, 2, 3, 4, 5, 6, 8, 9 and 10 — and item 7 is not applicable
rather than wanting, because `--resolution-run` is required only for a `fixed` disposition and none
attaches to a Phase-18 FRF residual.** Items 6, 8 and 10 retired when §8's chain landed, and
`phase_state.py` now derives `complete` with an empty blocking reason.

**The seal depends on the register, and that dependency is mechanical.** `HOSTILE-BOUNDARY-REGISTER`
re-reads the live courts registry and the authored register and fails the stratum if a recorded
classification, surface key, capacity or count has drifted, and it runs the `UNSAFE-FOOTPRINT`
growth check and the provenance regression guard. `phase_state.py` blocks a stratum on any
non-`pass` court in `artifacts/phase18/COURTS.json`, so the seal cannot derive `complete` while the
register or a footprint ceiling has drifted; the register is the stratum's own non-claim, and it may
not claim more than the courts above measured.

## 8. FRF and Gemel

**The FRF chain entry this stratum needs has landed, and this section records what it is.**

- **Three declarations are on disk.** `forensics/tools/gen_frf_courts.py`'s `COURTS` table gained a
  Phase-18 block — `rt-hostile-tls`, `rt-hostile-x509` and `rt-mem-hardening` — and
  `gen_frf_courts.py` wrote the three declarations under
  `forensics/frf/courts/openssl-rs-rt-<court>`. `gen_frf_courts.py --check` reports
  `ok: 280 file(s) match the table (140 courts)`, and `forensics/frf/README.md` counts **140 runtime
  courts** — the three Phase-18 ones among them, which moves the manifest count
  `docs/RELEASE_GATES.md` names with it. `CT-PRIMITIVES` is candidate-only and
  `HOSTILE-BOUNDARY-REGISTER` validates data, so neither is declared and no declaration is generated
  for them; their evidence is the court table, the register and the footprint bounds.
- **The chain's objects are on disk.** `.frf/receipts/` carries three Phase-18 receipts, one per
  declarable court. `.frf/challenges/` carries six adjudicated challenge records — both declared
  axes (`stdout-first-line`, `exit-class`) on all three courts, every one `saw_defect` and
  `specificity_clean` — which is what makes the claim `sensitivity-backed` rather than merely green
  (D13). `.frf/claims/` carries the compiled claim
  `505ceaf418cb458554c3c7ac23922a2835a847ddc6b79c1291086878460af575`, compiled at
  `--policy sensitivity-backed` over the three receipts, binding authority `openssl-rt-3.6.4-r2` to
  candidate `openssl-rs 0.0.25` (`identity_hash e4f60d8b`) with zero blockers. **The identity is the
  current 0.0.25 release**: the claim records the candidate the tree is
  (`gen_frf_courts.CANDIDATE_VERSION`), which is what the fix-4 identity clause requires. Two
  premises — `rt-hostile-tls` and `rt-mem-hardening` — are narrowed to the exit class because the
  hostile transcripts' raw digest differs on the harness's first-line digest; §4 records why leaving
  the residual open is the honest reading. The store verifies at **1184 objects** across six
  namespaces (`authorities` 5, `captures` 432, `challenges` 288, `claims` 20, `receipts` 144,
  `residuals` 295) with `graph_verified: yes` and `object_closure: complete`.
- **The Gemel change and checkpoint are this stratum's.** The change `C110`
  (`change.4f91d4ccf5b9fa9acdca24ac4c464cd038f795ff6b2e91fbcbb24214c8baf28a`) names Phase 18, its
  three declarable courts, the six adjudicated challenges, the claim and the five contract units;
  the checkpoint `K63`
  (`checkpoint.b64e46d7d62f37035f586a7bdeddfafc39751738649c804c31ab4f5ecb306cff`) closes it. The
  projection `forensics/GEMEL_TRAJECTORY.md` carries both, and the checkpoint's summary names Phase
  18 and the FRF chain. Items 6, 8 and 10 of §7 retired with that entry, exactly as they did for
  Phase 8's `C74`, Phase 9's `C94`, Phase 10's `C95`, Phase 11's `C97`, Phase 12's `C98`, Phase 13's
  `C99`, Phase 14's `C101`, Phase 15's `C103`, Phase 16's `C106` and Phase 17's `C108`.

**The declarations are produced by `gen_frf_courts.py`; the receipts, challenges, claim and
checkpoint were produced by running the chain in the FRF tooling container, never on the host.**
`forensics/GEMEL_TRAJECTORY.md` is the generated projection of a store Gemel keeps untracked (D17).
This section records the objects that are on disk.

## 9. What happens next

**Nothing is handed from this stratum to a later one.** `forensics/phase18-obligations.json`'s
`deferred` list is empty and its `deferred_to_later_phase` reads 0; every row this stratum owns is
implemented, and it received no unit or symbol deferral from an earlier stratum. The reduced flight,
the `tls13_encrypt_record` contract, the fixed-buffer divergences and the Miri-refused surface are
not rows this stratum's ledger owns — they are named boundaries rather than deferrals (§5) — so
nothing moves forward.

**The immediate next actions this seal's own state points at**, recorded so they are not lost:

- **The FRF/Gemel chain entry has landed.** §8's subject is now the objects on disk: the three
  declarations, three receipts, six adjudicated challenges, the claim
  `505ceaf418cb458554c3c7ac23922a2835a847ddc6b79c1291086878460af575` and the checkpoint `K63`. This
  stratum registers no `CT-*` court in the FRF registry and no data-validation court, so the entry
  covers the three behavioural differential courts and records the other two as not declarable.
  Items 6, 8 and 10 of §7 retired with it, and `phase_state.py` derives `complete`.
- **The register and the instrumented checks are the seal's live dependencies.** The authored
  register, the `UNSAFE-FOOTPRINT` ceilings and the provenance guard are data and guards, not
  assertions: a classification, capacity or count that drifts, a core module whose unsafe count
  rises above its ceiling, or a reappearing integer->callable-pointer reconstruction turns
  `HOSTILE-BOUNDARY-REGISTER` to `fail` and blocks the stratum.
- **`forensics/phase18-obligations.json` is the place a reader should look before believing any
  figure in this document**, because this document types no census figure of its own: §3's table and
  the head matter's court and row figures each name the artefact they were read from.

## 10. Corrections this seal records

Appended rather than folded into the sections above, for the reason the Phase 9 seal's §10 gives: a
correction that has been merged into the prose it corrects cannot be checked against the prose it
replaced. These are the corrections this seal makes to the evidence and the tools, and the
corrections the evidence forced rather than the ones a reviewer might have preferred.

1. **The FRF declaration table learned a third non-declarable court class and the manifest count
   moved with it.** `gen_frf_courts.py`'s `COURTS` table gained `rt-hostile-tls`, `rt-hostile-x509`
   and `rt-mem-hardening`, so `--check` moved from `274 file(s) (137 courts)` to
   `280 file(s) (140 courts)`, and `forensics/frf/README.md` and `docs/RELEASE_GATES.md`'s
   manifest-count sentence were moved with it, because `docs_consistency.py` binds both to the
   registry. `CT-PRIMITIVES` and `HOSTILE-BOUNDARY-REGISTER` take no declaration, and the table's
   Phase-18 block records each omission with its reason.
2. **The two hostile premises are correctly narrowed, and the seal records it rather than disposing
   the residuals.** The FRF venue's first stdout line is a digest of the whole transcript, so the
   hostile courts' recorded divergences raise an `open` first-line residual on `rt-hostile-tls` and
   `rt-mem-hardening`. Disposing it would have let the claim assert a first stdout line it does not
   have; leaving it open narrows those two premises to the exit class and keeps the claim honest.
   §4 and §8 record the reading.
3. **The sanitizer venue is separate from the forensic court, and the seal says so.** The court's
   hard 4 GiB `RLIMIT_DATA` is kept for the hostile courts; ASan is given
   `docker/openssl-rs-asan.{Dockerfile,sh}` and an ASan sibling build prefix (`/asan/install`), and
   it does not rebuild the authority. `docs/UNSAFE.md` §4 records the venue, its envelope and the
   six defects; §4 above records that OpenSSH is envelope-limited by its own seccomp sandbox.
4. **`atlas_common.SEAL_DOCS` gained `18: docs/PHASE-18-HARDENING-SEAL.md`**, so
   `render_seal_census.py` and `phase_state.py` recompute this document's `seal_sha256`, exactly as
   Phase 16's and Phase 17's seals are recorded.
5. **The FRF/Gemel chain entry landed, and §7 and §8 record it.** The seal's §8 records the three
   declarations, three receipts, six adjudicated challenges, the `sensitivity-backed` claim
   `505ceaf418cb458554c3c7ac23922a2835a847ddc6b79c1291086878460af575` and the Gemel change `C110`
   / checkpoint `K63`
   (`checkpoint.b64e46d7d62f37035f586a7bdeddfafc39751738649c804c31ab4f5ecb306cff`), so items 6, 8
   and 10 retired and `phase_state.py` derives `complete`. `seal_sha256` is recomputed from the
   document's new bytes.
