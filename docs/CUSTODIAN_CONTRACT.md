# The openssl-rs Custodian Contract

Status: **constitution** (Phase 0). Changes require a recorded decision in
`docs/DECISIONS.md` and, where they affect a claim, a new receipt.

## 1. What this project is

`openssl-rs` is a native-Rust, custodian-level reconstruction of the externally
observable contract of a pinned OpenSSL distribution.

It is **not**:

- a TLS library inspired by OpenSSL;
- an OpenSSL wrapper, binding, or FFI shim;
- an OpenSSL-shaped compatibility façade over `rustls`, `aws-lc`, BoringSSL,
  LibreSSL, `ring`, or OpenSSL itself;
- a narrow subset sufficient for one consumer.

The objective is that **unmodified OpenSSL consumers can compile, link, load,
execute and behave correctly** with `openssl-rs` substituted for OpenSSL, for an
explicitly stated authority, build profile and platform.

## 2. The single-crate rule

The project is **one Cargo package with one first-party Rust implementation
crate**. There are no implementation workspaces and no component crates. Internal
modules may be arbitrarily numerous; that is expected.

The single implementation crate **must still emit the multiple runtime artifacts
that the distribution contract requires**:

```
libcrypto.so.3     libssl.so.3     static archives
provider loadable modules          the `openssl` executable
public headers     pkg-config metadata     symbol version scripts
```

`libcrypto` and `libssl` are never collapsed into one shared library with
aliases. They have separate symbol namespaces, SONAMEs, version nodes and
runtime dependency relationships; those separations are part of the contract.

Build, oracle and court tooling may use shell, Python, C probes and other
non-product machinery. Only the *product* is one crate.

## 3. What must not be used as an implementation

The product must not dynamically or statically use any of the following as a
substitute for the implementation being reconstructed:

`openssl`, `openssl-sys`, `rustls`, `rustls-ffi`, `aws-lc-rs`, AWS-LC,
BoringSSL, LibreSSL, `ring`, OpenSSL-compatible system libraries, or any foreign
cryptographic library used as a hidden implementation backend.

Independent implementations **may** be used as test authorities, interoperability
peers, or differential corroborators — never as the hidden product.

**Provenance rule.** OpenSSL source may be used for archaeology and
understanding where licensing permits (`LICENSE-*` records this). Provenance must
remain explicit, and implementation must be reasoned from *behavioural
obligations*, not mechanically transliterated function-by-function from C.

## 4. Unsafe Rust

Unsafe Rust is permitted **only** where required by:

- C ABI boundaries;
- raw ownership compatibility;
- platform syscalls;
- dynamic loading;
- CPU intrinsics;
- exact memory-layout requirements.

Unsafe code is confined to narrow modules. Every invariant an `unsafe` block
relies on is documented at the block, and those invariants are aggressively
tested. See `docs/UNSAFE.md`.

## 5. No fake success

A placeholder that returns a plausible value is **worse** than an honest
unimplemented obligation. Development scaffolds, if any, must be:

- explicitly classified `SCAFFOLDED`;
- unreachable in normal production builds;
- impossible to count as parity;
- rejected by release gates (`docs/RELEASE_GATES.md`).

There is no path by which a scaffold becomes `PARITY_VERIFIED`.

## 6. Definition: "custodian compatible"

> For a specified OpenSSL authority version, build profile, platform and
> observed surface, `openssl-rs` is **custodian-compatible** only where
> machine-verifiable evidence demonstrates source/API compatibility, binary ABI
> compatibility and externally observable semantic compatibility, with **no
> unresolved residual intersecting the claimed scope**.

Corollaries, all of which are enforced by the parity model rather than by prose:

- A function existing is not parity.
- A symbol linking is not parity.
- A TLS connection succeeding is not parity.
- Passing happy-path vectors is not parity.
- Passing OpenSSL's own test suite alone is not parity.
- No phase is complete because an implementation "looks plausible".

## 7. Definition: "the goal"

The goal is **not** to prove that `openssl-rs` resembles OpenSSL. It is to make
every compatibility assertion answerable by:

```
Which authority?   Which version?   Which build?   Which platform?
Which observable surface?   Which court?   Which raw capture?
Which residuals?   Which resolution?   Which receipt?   Which downstream witness?
```

If the project cannot answer those questions, the claim is too strong. Evidence,
not confidence, is the custodian.

## 8. Where claims live

`unresolved` and `UNKNOWN` are **honest results**, not failures to paper over.

- No headline completion percentage is ever typed by hand; it is derived from
  evidence-bearing obligations (`docs/PARITY_MODEL.md`).
- No claim of universality is made from finite tests. Claims name exact observed
  regions.
- README claims are generated or bounded by machine evidence; see
  `docs/NON_CLAIMS.md`.

## 9. Phase order is a hard constraint

Work proceeds in the dependency-ordered conservation strata of
`docs/RELEASE_GATES.md`. In particular, **algorithms come late**. OpenSSL 3 is
built around algorithm *selection* and *object machinery*; the context/provider/
fetch/EVP semantics must be correct before algorithms have somewhere faithful to
live. Beginning with AES, SHA, RSA and TLS is explicitly disallowed as a start.

## 10. Authorities

The initial authority set is:

| id | role | version |
|---|---|---|
| `openssl-3.6.4-production` | production | 3.6.4 (security-fix release) |
| `openssl-3.6.3-historical` | historical | 3.6.3 (observed by extant bind9-rs archaeology) |

Authority admission, build profiles and contamination policy are defined in
`docs/AUTHORITY_POLICY.md`. A candidate must never be pinned to known-vulnerable
historical behaviour; see `docs/SECURITY_DIVERGENCE_POLICY.md`.

## 11. The court is the only **authority-bearing** execution venue

No **authority-bearing** execution runs on the host. That means every
differential court, forensic probe, fuzz campaign, benchmark and authority build
executes inside the isolated, resource-capped court container defined by
`docker/openssl-rs-court.Dockerfile` and driven by `docker/openssl-rs-court.sh`.
The host is not a forensic venue; those runs need the pinned authority, the
pinned toolchain and the resource caps, and their results are what become
parity evidence. See `docs/REPRODUCIBILITY.md`.

The distinction matters because the earlier, blanket wording ("nothing runs on
the host") was not true of continuous integration and could not be made true
without forbidding cheap, useful checks. What CI may run in a non-authority
environment is precisely:

* **pure implementation-unit tests** that exercise this crate's own Rust with no
  authority present (`cargo test --lib`);
* **static checks** — formatting, compilation, linting, and the dependency gate;
* **derivation of evidence from already-committed inputs**, such as regenerating
  the obligation ledgers or the phase state.

None of those may contribute **forensic parity evidence**. A unit test passing on
a CI runner says nothing about the authority and is never cited as a court. Only
the court venue produces evidence, and every claim in `docs/` and `forensics/`
names the court that produced it.
