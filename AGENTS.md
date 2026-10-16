# AGENTS.md — memory-safety conversion guideline (local, gitignored)

Local working instructions for the `openssl-rs` unsafe→safe conversion campaign
(`integrate/safe-c33`). Not evidence, not shipped: excluded via `.gitignore`.

**Load this file at the start of every fresh session.** It is deliberately local,
so it can silently disappear after a clone or context reset unless the
orchestrator re-reads it explicitly.

The goal is not "uses Rust". The goal is **sound abstractions with genuinely safe
interiors**: every unsafe assumption either eliminated (made inexpressible) or
confined to a narrow, auditable abstraction with a sound interface.

Compatibility is preserved, but compatibility is never an excuse to reproduce a
known-unsafe operation: preserve OpenSSL behaviour where required, and **record**
any deliberate safety improvement that deviates from it.

---

## 0. The standard to hold (good ≠ exceptional)

| | pattern | what it guarantees |
|---|---------|--------------------|
| good (foundation) | `*mut T → NonNull<T> → Drop` | consolidates cleanup; provenance/uniqueness still caller obligations |
| **exceptional (target)** | `validated ownership boundary → borrowed/owned Rust state → safe internal algorithms` | unsafe assumptions live only at auditable boundaries; types, lifetimes and borrow rules enforce the interior |

We are moving from the first to the second. Every conversion must state which
unsafe assumptions were **eliminated** (became inexpressible), which were merely
**relocated** (into one documented boundary), and which remain **hidden**
(unreported obligations). Hidden must be zero; if you find a hidden obligation,
report it and block graduation — never reclassify it to satisfy the target.

**On "the C ABI edge".** Unsafe code cannot always be confined to the C ABI edge
alone. Allocators, operating-system interfaces, CPU intrinsics, and specialized
internal representations each require their own unsafe operations. The real
requirement is that every such operation live inside an appropriately narrow,
auditable abstraction with a sound interface — not that unsafe appears in
exactly one place.

---

## 1. Ownership adoption is a proof obligation, not a function call

An ownership-adoption constructor turns a caller-supplied raw pointer into an
owning handle whose `Drop` frees it. Such a constructor MUST be `unsafe fn` with
a `# Safety` contract.

The contract must establish, at minimum:

- **provenance** (which allocator seam produced it);
- **allocation identity and extent** (the whole block, not a sub-range);
- **alignment**;
- **initialization state** valid for every operation the owner performs
  (including the cleansing length, which must be valid for that allocation);
- **exclusive ownership** (no other owner will release it);
- **the exact release mechanism** (plain vs cleansed vs secure).

> An `unsafe fn` declaration **transfers** a proof obligation to its caller; it
> does **not** discharge it. Marking a constructor `unsafe` without making its
> callers establish the preconditions is not a fix.

- A **safe** `fn` whose body can trigger an invalid free is a soundness bug even
  if today's call sites are correct.
- Prefer *design* over documentation where cheap: when a block comes from a
  known allocator call in the same function, construct the owner directly from
  that call (`new`/`new_zeroed`) so provenance is not re-asserted by hand.
  Reserve `adopt`/`take` for genuine helper-allocated blocks and justify each.
- Never add a new `unsafe fn` with a safe-looking signature that hides raw work.

Audited constructors (fix any regression): `OwnedBlock::take`, `OwnedBuf::take`,
`OwnedStr::take`, `OwnedRaw::adopt`, `adopt`/`adopt_cleansed`, `from_raw`, across
`runtime/bio/owned.rs`, `store/store_lib.rs`, `evp/{pkey_ctx,digest,e_aes}.rs`,
`pem/pvkfmt.rs`, `ui/ui_lib.rs`, `hpke/mod.rs`, `ssl/{ssl_lib.rs,statem/statem_srvr.rs}`,
`x509/v3_utl.rs`, `ec/smpl.rs`, `provider/{cipher,kdf}.rs`.

## 2. Valid Rust values are an explicit invariant

**Allocated storage and initialized Rust values are separate states.**
`CRYPTO_zalloc` returning zeroed bytes does not, by itself, establish that those
bytes represent a valid initialized `T`; validity must be established for the
actual type and for every subsequent operation. (Zero initialization *may* be a
valid value for some types — that must be justified per type, not assumed.)

- An owner may hold `NonNull<MaybeUninit<T>>` while constructing an object.
- **No `&T`, `&mut T`, initialized read, or full destructor is permitted before
  the required initialization invariants hold.** Zeroing does not make a value
  valid when `T` contains references, `NonNull`, valid-range-restricted enums, or
  other fields with validity requirements.
- Partially initialized objects must release **only the resources actually
  acquired** — never run a complete destructor on a partially constructed value
  (this is the `OwnedRaw<T>` vs `OwnedCtx<T>` distinction; keep it).

### Borrowing
- Prefer owner-derived borrowing: `&mut OwnedTree`, `&mut OwnedNode`,
  `split_at_mut`/`get_mut` partitioning — instead of raw `from_raw_parts_mut`.
- `from_raw_parts_mut` requires exclusive access to the whole range for the
  entire returned borrow; derive that from an owner rather than asserting it.
- Audit: `unsafe fn tree_levels<'a>(tree) -> &'a mut [...]` (caller-chosen
  lifetime; no tie to the tree's owner) and `Node::parent_mut(&self)` (uniqueness
  the type system does not establish).

## 3. Fallible arithmetic and allocation

- Any `count * size_of::<T>()`, length/size sum, or offset used for allocation
  MUST use `checked_mul`/`checked_add` and translate overflow to the OpenSSL
  failure semantics (`None`/error), **not** rely on a panic boundary.
  Audit: the generic alloc helper in `src/asn1/owned.rs`.
- Make allocation failure, overflow and partial initialisation explicit through
  `Option`/`Result` (or the module's established outcome type).

## 4. Panic safety across the C ABI

- `guard_ffi` catches unwinding, but uses `AssertUnwindSafe`; catching a panic
  does not repair partially mutated state.
- For stateful contexts require one of: failure-atomic mutation, explicit
  rollback, or a **poisoned** state that forbids reuse after an interrupted
  operation. An error code alone is not sufficient.

## 5. Secret-bearing memory is a distinct category

Classify memory by *security* requirement, not only by allocation mechanism and
destructor — and distinguish **secret contents**, **public metadata**, and
**sensitive state**. (IVs/nonces are often public, yet their uniqueness and
lifecycle can be security-critical.)

1. **Lifetime + cleansing.** Cleansing must cover the *actual secret-bearing
   storage*, including copies, temporary representations, partially initialized
   states and **failure paths**. **Release and cleansing are separate
   obligations**: a destructor that merely frees memory is not a secret-safe
   destructor. Keep every `OPENSSL_clear_free` arm through conversion.
2. **Constant-time.** Separate secret-dependent operations from public-data
   parsing; keep the full-length `CRYPTO_memcmp` accumulation; never introduce
   secret-dependent branches or early exits. Source-level intent is **not**
   constant-time behaviour after optimization: for secret-dependent operations,
   preserve the intended timing discipline under optimisation and review
   generated code or use leakage-testing methods where the change warrants it.
   Never claim constant-time behaviour from source inspection alone.
3. **Initialised vs uninitialised.** `MaybeUninit<T>` + initialisation state.
4. **Reference/alias ownership.** Express shared/exclusive access through types;
   minimise unconstrained pointer→reference conversions.

No third-party crypto implementations: RustCrypto `zeroize`/`subtle` and similar
are **references for technique only**.

## 6. Per-batch execution contract

- One bounded task at a time; a subagent does not commit or push; the
  orchestrator commits, verifies and merges.
- Everything runs in the court container (`docker/openssl-rs-court.sh`), never on
  the host. `CARGO_BUILD_JOBS=6`, one heavy command at a time (OOM safety).
- Local gate per batch: `cargo fmt --all -- --check`,
  `cargo clippy --all-targets -- -D warnings`,
  **all current library tests pass**. The established baseline is **1183** library
  tests; it will grow, so the rule is *no unexplained removals and no newly
  ignored tests* — not a frozen literal.
- Preserve the `CRYPTO_*` allocator seam at the authority's exact size/`file`/
  `line`; preserve `#[repr(C)]` layouts and every exported symbol/signature;
  never weaken `unsafe_op_in_unsafe_fn` / `undocumented_unsafe_blocks` /
  `missing_safety_doc`.
- **`docker/` is out of scope for conversion agents.** This is a scope boundary,
  not an endorsement of the current launcher: the known isolation defect (host
  checkout bind-mounted read-write at `/work`) is a **standing infrastructure
  task** that must be tracked and fixed deliberately, never silently forgotten.
- Report per batch: mechanism eliminated / relocated / hidden (must be 0),
  unsafe ops removed vs relocated, boundary size, obligations discharged /
  retained / **newly introduced**, compatibility tested, and whether every
  remaining unsafe op has an explicit validity contract.
- Defer full Phase-25 forensic regeneration to seal points; keep the local gate.

## 7. Graduation states

- `OWNERSHIP_RECONSTRUCTED` — a safe ownership model exists and its residual
  boundary is identified.
- `SAFETY_DISCHARGED` — **materially harder.** A mechanism is `SAFETY_DISCHARGED`
  only when, within its defined scope:
  1. every remaining unsafe operation has an explicit validity contract;
  2. every required precondition is established by its callers or by an external
     ABI contract; and
  3. no safe-Rust caller can cause undefined behaviour through the safe
     interfaces.
  All retained, introduced and unresolved obligations must be enumerated.
  **Documentation alone does not discharge an obligation.**
- `SAFE_COMPATIBLE` — the only graduation state for a consumer family. A family
  graduates only when **every applicable mechanism in its conservatively
  established dependency closure is `SAFETY_DISCHARGED`**, unresolved
  dependencies are accounted for, and compatibility is confirmed against the
  **exact converted implementation**. L4 build/link and L7 functional evidence
  remain separate (an L4 pass is not an L7 pass). An unresolved or unknown
  safety-relevant dependency **blocks** `SAFE_COMPATIBLE` graduation until its
  applicability is excluded with evidence or its safety obligations are
  discharged: recording an unknown is necessary, but recording it does not
  establish safety. No family inherits safety graduation solely from a shared
  mechanism's successful conversion: a consumer like curl depends on many
  mechanisms, and discharging one does not make the whole consumer safe.

An unproven raw-pointer boundary never becomes `SAFETY_DISCHARGED` merely because
a `Drop` wrapper exists, and `hidden = 0` is a target, never a reporting
incentive.
