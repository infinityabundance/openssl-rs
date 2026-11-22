# ETP-4 — Verification receipt

**Item:** foundational verification pilot on production code: `SecretBuf`
whole-allocation cleansing and fixed-width Montgomery arithmetic, bound to
source, with the missing binary bridge recorded.

**Status:** `BOUNDED_MECHANICALLY_CHECKED`. This is a source-level test result
over declared finite domains. It is **not** a binary result and **not** a
theorem-prover proof.

**Machine-readable companion:** `evidence/etp4/results.json`, validated with
`python3 -m json.tool` (exit 0).

---

## 1. Source identity at the start

| property | value |
|---|---|
| branch | `staging` |
| HEAD | `85583cd9ae6cf4fc163fcb5d247dd36be6cc1c12` |
| worktree | clean (`git status --porcelain` empty) |
| pinned compiler | `rustc 1.98.1 (48a229cea 2026-09-01)`, `cargo 1.98.1 (797e8a9bc 2026-08-05)` |

The delivered change is test-only: two `#[cfg(test)]` verification modules
appended to `src/runtime/secret.rs` and `src/bn/mont.rs`. No production path,
signature, `#[repr(C)]` layout, `CRYPTO_*` seam or lint attribute was changed.
The REDC kernel file `src/bn/arith.rs` is byte-identical to HEAD.

### Delivered file digests (SHA-256)

| file | digest |
|---|---|
| `src/runtime/secret.rs` | `9174a878e9f4d05960e7780c1e4ea39039646d1f44982275991e5839949d887d` |
| `src/bn/mont.rs` | `ed6d9738c8ae4afaf2870b825a5de18849f41bbd0a1615d8aa3166b8d7484f3c` |
| `src/bn/arith.rs` | `edf456e6b38ee48c43bf42e2b7c167906d2675a2b18820358f9dcc04779dafdc` |
| `Cargo.toml` | `1bb7439f60d126d414fd3a67e87e029bb6bfac570ce2d19a05e075c4b3d09c60` |
| `rust-toolchain.toml` | `51b89aac2174179a4470434e6666f9f54d52309005332324154cdeeb1f66dd58` |
| `evidence/etp4/kani/kani_admission.rs` | `ecd3503b0a59c5c75cf1c714de6f7573fc950679ab553885f2a5590040caa38f` |

`src/bn/arith.rs` (the `mont_mul_into` REDC kernel) digest equals the HEAD blob
digest. The test files' digests include only the appended harness modules.

---

## 2. Venue and resource guard

| property | value |
|---|---|
| court | `docker/openssl-rs-court.sh exec`, image `openssl-rs-court-tools:1` |
| cap | `OPENSSL_RS_COURT_MEM=6g OPENSSL_RS_COURT_MEMSWAP=6g` |
| host `available` before the first build | 27 GiB |
| host `available` before the full gate | 24 GiB |
| OOM | none observed |
| parallelism | `CARGO_BUILD_JOBS=4`; `--test-threads=4`, plus a serial run |
| sequencing | one heavy command at a time; the pre-existing `openssl-rs-court` container was the only one listed by `docker ps` |

`free(1)` is not present inside the court image. Availability was read on the
host before each build, which is the value the §6.1 guard needs. The court
container pre-existed this item (up 47 minutes); no concurrent heavy command was
observed.

---

## 3. What verification was actually available

### 3.1 Initial probe

Command, inside the court:

```
rustc --version; cargo --version
for t in verus kani cargo-kani creusot aeneas charon z3 cvc5 cbmci \
         smtinterpol boogie hax; do command -v "$t"; done
python3 --version
```

Observed:

- `rustc 1.98.1 (48a229cea 2026-09-01)`, `cargo 1.98.1 (797e8a9bc 2026-08-05)`
- every listed verifier/solver was **ABSENT**: `verus`, `kani`,
  `cargo-kani`, `creusot`, `aeneas`, `charon`, `z3`, `cvc5`, `cbmc`,
  `smtinterpol`, `boogie`, `hax`
- `Python 3.11.2`

### 3.2 Network is present, contrary to the ETP-3 register

Measured commands and results:

| command | result |
|---|---|
| `getent hosts crates.io` | resolved (IPv6 addresses returned) |
| `curl -sSI https://static.crates.io/` | `HTTP/2 404` (route reachable) |
| `curl -sSI https://github.com/` | `HTTP/2 200` |
| `curl -sSI https://static.rust-lang.org/dist/channel-rust-nightly.toml` | `HTTP/2 200` |
| `apt-get update` | exit 0, fetched 9417 kB from `deb.debian.org` |

`docs/INSTRUMENT-QUALIFICATION.md` §2 records `network | absent` for this venue.
This session contradicts that line. **The register was not edited**; the
discrepancy is reported here for the instrument owner to reconcile. The
consequence is that "no network" is not available as a blocker for any tool.

### 3.3 z3 (SMT solver)

```
apt-get install -y --no-install-recommends z3    # exit 0
z3 --version                                     # Z3 version 4.8.12 - 64 bit
```

`sha256 /usr/bin/z3 = 5def71f04f8df16e633c084f611a7cd9fbe633cd87d5016e980ee18949e769b5`.

**Admitted for nothing in this item.** An SMT solver has no Rust front-end. It
cannot establish a property of the crate without a separately verified encoding,
and no such encoding was built. Citing z3 for the Rust properties would be an
instrument/property mismatch.

### 3.4 Kani (admitted as an instrument, not used for a property)

```
CARGO_BUILD_JOBS=4 cargo install kani-verifier --locked   # exit 0, 3.78 s
kani setup                                                # exit 0
kani --version
```

Observed:

- driver `kani-verifier v0.68.0`
- `Kani Rust Verifier 0.68.0 (standalone)`
- backend `CBMC 6.11.0`
- bundled toolchain `nightly-2026-08-21-x86_64-unknown-linux-gnu`
  (`rustc 1.100.0-nightly (8925ea358 2026-08-20)`)

Driver digests:

- `/usr/local/cargo/bin/kani`: `1bbdab14d231b24474e7ccbc306d619cb4205601ac7db71eb9f3cd4bbe364ca0`
- `/usr/local/cargo/bin/cargo-kani`: `a262fbecf63abb280c87bbe5cb772b24786f58cb0dc2b0cce148c16a0214dcf6`

**Admission controls** (`evidence/etp4/kani/kani_admission.rs`):

| control | command | exit | observed |
|---|---|---|---|
| positive | `kani … --harness admission_positive` | 0 | `VERIFICATION:- SUCCESSFUL`; `Complete - 1 successfully verified harnesses, 0 failures, 1 total.` |
| negative | `kani … --harness admission_negative_must_fail` | 1 | `VERIFICATION:- FAILED`; `Status: FAILURE` at the assertion; `Complete - 0 successfully verified harnesses, 1 failures, 1 total.` |

The verifier is not fail-open on this control: a false assertion produces exit 1.

**Crate compatibility probe:** `cargo kani --lib` exited 0 after 15.05 s and
reported `No proof harnesses (functions with #[kani::proof]) were found to
verify.` Kani's compiler therefore accepts the crate source under its own
toolchain. This verified no property.

**Does Kani support the pinned rustc 1.98.1? No.** It runs on its own bundled
`nightly-2026-08-21` (`rustc 1.100.0-nightly`). A Kani proof would describe a
different compilation unit from the pinned candidate. Accordingly **no Kani
result is claimed for either property in this item**, and the instrument is not
used as evidence.

### 3.5 Verus, Creusot, Aeneas, Charon

Not installed (`command -v` ABSENT). No installation was attempted, so their
capability on this codebase was not measured and contributes nothing. The one
verifier that *was* installed already fails the pinned-toolchain requirement, so
the pinned-compiler bridge remains absent regardless of those tools.

### 3.6 Tool-install scope

The `apt`/`cargo install`/`rustup`/`kani setup` state exists only in the running
court container, not in the pinned `openssl-rs-court-tools:1` image. A fresh
court does not contain z3, Kani, CBMC or the extra nightlies; the install
commands above are the reproduction recipe. No `docker/` file was modified.

---

## 4. Domain 1 — `SecretBuf` whole-allocation cleansing

### 4.1 Property exercised

For a `SecretBuf<u64>` whose entire capacity has been initialised to a
non-zero pattern, after `Drop` every byte of

```
[as_ptr, as_ptr + capacity * size_of::<u64>())
```

must read zero. The test observes this from inside `Drop`, after `cleanse_now`
and before the backing `Vec` releases the block, which is the last point at
which the allocation is live and soundly readable. The pre-state is checked
twice: the initialised prefix through `nonzero_before`, and the spare capacity
through a test-side volatile byte count, so the wipe cannot pass vacuously on
never-written memory.

### 4.2 Exhausted domain

| test | domain | cases |
|---|---|---|
| `runtime::secret::tests::etp4_whole_allocation_cleanse_domain` | lengths `{0,1,2,3,4,7,8,15,16,17,64,65}` at exact fit (12) and with spare margins `{1,3,8}` (36) | **48** |
| `runtime::secret::tests::etp4_spare_capacity_cleansed_on_every_exit_path` | every length above with spare capacity, on normal return, early `?` return and unwind | **36** |
| `runtime::secret::tests::etp4_reallocated_buffer_cleanses_whole_allocation` | a vector that grew by reallocation, then shrank its logical length (capacity 68) | **1** |

Totals: **85 allocation observations**, 0 non-zero bytes after destruction.
`observed_bytes = 7616` for the first test (sum of the checked extents).

The zero-length cases include both the empty allocation (capacity 0) and an
allocation whose whole capacity is spare (length 0, capacity > 0). The exact-fit
cases include `len == capacity`; the spare cases include `len < capacity`. The
final-conditional-subtraction analogue for cleansing is not applicable; the
multiple-of-eight and non-multiple lengths exercise the byte-count arithmetic.

### 4.3 Exit paths and the destructor

The type provides no `Copy`, no `Clone`, no `into_inner` and no
`Default`-from-secret; a value leaves scope on normal return, early `?` return,
or unwind. All three are exercised with staged non-zero spare capacity.
`Drop` observed the armed allocation in every case; a removed `Drop` body
produces no observation at all (control C2).

**Scope.** Safe Rust's `mem::forget`, `ManuallyDrop`, process abort and
`std::process::exit` bypass `Drop` for every type; no Rust type can prevent
them. The claim is scoped to every ordinary scope exit the type's API reaches.

---

## 5. Domain 2 — fixed-width Montgomery arithmetic (REDC)

### 5.1 What is checked

Two production kernels:

- `mont_mul_fallible` / `mont_mul_into` (`src/bn/arith.rs`): schoolbook product
  plus word-wise REDC; the kernel behind `BN_to_montgomery`,
  `BN_mod_mul_montgomery`, `BN_MONT_CTX_set` and the constant-time ladder.
  Contract: `a, b < m`, `m` odd.
- `mont_reduce` (`src/bn/mont.rs`): the general reduction behind
  `BN_from_montgomery` and the wide-operand branches. Contract: `r < m * R`.

For each output the harness checks **both**:

1. the canonical bound `out < m`; and
2. the defining congruence `out * R == input (mod m)`, with `R = 2^(64n)`.

The oracle is an independent path through `limbs::{mul, rem}` (the variable-time
bignum reference), never REDC itself. The one-limb exhaustive population also
recomputes the congruence over `u128`, independent of `limbs`.

### 5.2 Domain and counts

| test | domain | cases |
|---|---|---|
| `…::etp4_mont_mul_one_limb_exhaustive` | every `(a,b)` for `m ∈ {3,5,7,9,11,13,15,17,31,33,63,65,127,129,255,257}` (the whole residue square) | **175 056** |
| `…::etp4_mont_mul_one_limb_boundary` | 7 boundary moduli, top bit set/clear/near-max/mixed, 32 operands each | **7 168** |
| `…::etp4_mont_reduce_one_limb` | 23 one-limb moduli × 31 inputs spanning `[0, m*R)`, including non-canonical `m`, `m+1`, `R`, `R+1`, `m*R-1` | **713** |
| `…::etp4_mont_mul_two_limb` | 6 normalised two-limb boundary moduli × 22 operands each | **2 904** |
| `…::etp4_mont_reduce_two_limb` | 6 two-limb moduli × 29 inputs, including `m`, `R`, `R+1`, `m*R-1` | **174** |

Total: **186 015 Montgomery cases**, all satisfying `out < m` and the defining
congruence.

Explicit values in the populations include `0`, `1`, `2`, `m-1`, `m-2`, `m>>1`,
`R-1`, `R`, `R+1`, `R+m-1`, `m*R-1`; the non-canonical inputs are admitted only
where the contract admits them (`mont_reduce`). The `m-1`/`m-2`/`m*R-1` cases
exercise the final conditional subtraction, and the top-bit-set moduli exercise
the carry-out above the top limb.

### 5.3 Exhausted versus sampled

- **Exhausted:** the whole residue square for 16 small one-limb moduli; every
  declared cleansing length at exact fit and at three spare margins; all three
  ordinary exit paths at every declared length.
- **Sampled:** one-limb boundary moduli; all two-limb moduli; the general
  reduction input range; lengths and capacities outside the enumerated set;
  widths above two limbs (untested).

### 5.4 Domain exclusion

A non-normalised two-limb modulus representation (zero top limb, for example
`[3, 0]`) is excluded from the two-limb domain: the reference
`limbs::divide_fallible` requires a non-zero top limb. Production `BIGNUM`s are
normalised, so this is a harness/oracle domain limit, not an implementation
finding.

---

## 6. Mutation controls

Each control applied one temporary patch, ran the named test, recorded the
failure, then restored the file from a byte-for-byte copy. The restored tree
passes the focused suite, `fmt`, `clippy` and the full library tests.

| id | mutation | test | exit | observed failure |
|---|---|---|---|---|
| **ETP4-C1** | `cleanse_allocation` counts `v.len()` instead of `v.capacity()` (spare capacity not wiped) | `runtime::secret::tests::etp4_whole_allocation_cleanse_domain` | 101 | `assertion \`left == right\` failed: automatic destruction left non-zero bytes in the allocation` |
| **ETP4-C2** | `Drop` no longer calls `cleanse_now()` (destructor skipped) | same | 101 | same failure |
| **ETP4-M1** | `mont_mul_into` sets `keep = 1`, omitting the final conditional subtraction | `bn::mont::etp4_verification::etp4_mont_mul_one_limb_exhaustive` | 101 | `mont_mul exhaustive: output is not canonical (out=[9] m=[9])` |
| **ETP4-M2** | `mont_mul_into` sets `keep = borrow`, ignoring the high limb (top-bit-set carry) | `bn::mont::etp4_verification::etp4_mont_mul_one_limb_boundary` | 101 | `mont_mul boundary: out * R != input (mod m); out=[18445618182392643584] input=[281474976710656, 18446181128051097599] m=[18446462598732840961]` |

C1 and C2 are the two requested cleansing controls (spare-capacity skip; the
length-only wipe is the same mechanism, and C2 additionally removes the
destructor entirely). M1 and M2 are the two requested arithmetic controls.

**Restored tree:** 8 focused tests passed, 0 failed.

---

## 7. Gate output (verbatim)

```
fmt_check_exit=0

clippy_exit=0
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 16.88s

serial_exit=0
test result: ok. 2422 passed; 0 failed; 54 ignored; 0 measured; 0 filtered out; finished in 497.78s

mt_exit=0
test result: ok. 2422 passed; 0 failed; 54 ignored; 0 measured; 0 filtered out; finished in 166.38s
```

Baseline was 2414 passed / 54 ignored. The eight new tests account for the
increase to 2422; no test was removed, renamed or newly ignored.

Focused run:

```
test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 2468 filtered out; finished in 0.28s
```

---

## 8. Source binding and test names

Every result above is bound to the file digests in §1 and to these test names:

- `runtime::secret::tests::etp4_whole_allocation_cleanse_domain`
- `runtime::secret::tests::etp4_spare_capacity_cleansed_on_every_exit_path`
- `runtime::secret::tests::etp4_reallocated_buffer_cleanses_whole_allocation`
- `bn::mont::etp4_verification::etp4_mont_mul_one_limb_exhaustive`
- `bn::mont::etp4_verification::etp4_mont_mul_one_limb_boundary`
- `bn::mont::etp4_verification::etp4_mont_reduce_one_limb`
- `bn::mont::etp4_verification::etp4_mont_mul_two_limb`
- `bn::mont::etp4_verification::etp4_mont_reduce_two_limb`

The base commit is `85583cd9a`; the orchestrator assigns the delivery commit.
Because the receipt and harnesses are committed together without further source
edits, the digests remain the binding identity.

---

## 9. What this item does **not** establish, and the missing bridge

1. **No binary result.** The harnesses run in the debug test profile
   (`cargo test`). No statement is made about the release DSO, about rustc
   1.98.1's emitted instructions, or about LLVM/linker behaviour. In particular,
   the volatile-write loop's machine-code shape was not inspected.
2. **No theorem-prover proof.** Kani was installed and admitted with a positive
   and a negative control, but it runs on `nightly-2026-08-21`, not the pinned
   `1.98.1`, so it cannot speak about the pinned candidate; it was not used for
   either property. z3 has no Rust front-end. Verus/Creusot/Aeneas/Charon were
   not installed and contribute nothing.
3. **Bounded exhaustion is not a universal statement.** Sixteen one-limb moduli
   have their whole residue square covered; two-limb moduli are sampled; widths
   above two limbs are untested; the cleansing lengths, capacities and exit-path
   combinations are an enumerated subset.
4. **`Drop` is not literally unavoidable.** Safe Rust permits `mem::forget` and
   `ManuallyDrop`, and the process can abort or exit. The claim is scoped to
   ordinary scope exits.
5. **Allocator metadata is outside the owner.** The probe observes the block
   before the `Vec` releases it; it does not prove that libc keeps no copy in
   allocator metadata or a free-list header.
6. **No timing or constant-time result.** No secret-dependent branch, index or
   length was added to production code; the harness code is `#[cfg(test)]`.
7. **Tool state is session-local.** z3, Kani/CBMC and the extra nightlies are in
   the running court container, not the pinned image.
8. **Register discrepancy reported, not edited.** The ETP-3 register records no
   network; this session measured network. The instrument owner must reconcile
   that before any register entry depends on it.

### Theorem shapes that would upgrade each bounded result

| bounded result | universal theorem shape | tool class that could discharge it |
|---|---|---|
| 85 cleansing observations | For every `T: SecretElement` and every `SecretBuf<T>` allocation, every ordinary scope exit leaves every byte of `capacity * size_of::<T>()` zero, and the `Drop` path is reached on normal return, early return and unwind. | Source-level separation logic with volatile-store semantics (RustBelt/RefinedRust class), or BMC for fixed `T`/capacity; then a compiler or binary check for the emitted write pattern. |
| 186 015 REDC cases | For every `n >= 1`, every odd `m` with `2^(64(n-1)) <= m < 2^(64n)`, and every `a,b < m` (or `r < m*R`), REDC returns the unique `x` with `x < m` and `x*R == input (mod m)`. | SMT-backed BMC (Kani class) for fixed `n`/width; a proof assistant with machine-integer semantics for all `n`. |
| none — the bridge is absent | The source theorems compose with semantics preservation for rustc 1.98.1 + LLVM + assembler + linker, keyed to the exact artefact hashes. | Translation validation or a verified-compiler chain for the exact toolchain. This is the FRC tool admission named in the item; this pilot does not assert it. |

---

## 10. Reproduction

```sh
cd /home/user/openssl-rs
COURT='OPENSSL_RS_COURT_IMAGE=openssl-rs-court-tools:1
       OPENSSL_RS_COURT_MEM=6g OPENSSL_RS_COURT_MEMSWAP=6g'

# focused harness (prints the case counts with --nocapture)
env $COURT bash docker/openssl-rs-court.sh exec sh -c \
  'CARGO_BUILD_JOBS=4 cargo test --lib etp4_ -- --nocapture --test-threads=4'

# gates
env $COURT bash docker/openssl-rs-court.sh exec sh -c 'cargo fmt --all -- --check'
env $COURT bash docker/openssl-rs-court.sh exec sh -c \
  'CARGO_BUILD_JOBS=4 cargo clippy --all-targets -- -D warnings'
env $COURT bash docker/openssl-rs-court.sh exec sh -c \
  'CARGO_BUILD_JOBS=4 cargo test --lib -- --test-threads=1'
env $COURT bash docker/openssl-rs-court.sh exec sh -c \
  'CARGO_BUILD_JOBS=4 cargo test --lib -- --test-threads=4'

# tool admission (session-local; not in the pinned image)
env $COURT bash docker/openssl-rs-court.sh exec sh -c '
  apt-get update && apt-get install -y --no-install-recommends z3
  CARGO_BUILD_JOBS=4 cargo install kani-verifier --locked
  kani setup
  kani evidence/etp4/kani/kani_admission.rs --harness admission_positive
  kani evidence/etp4/kani/kani_admission.rs --harness admission_negative_must_fail
  cargo kani --lib'
```
