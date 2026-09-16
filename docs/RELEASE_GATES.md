# Release Gates

Status: **constitution** (Phase 0).

## 1. Conservation strata (dependency-ordered phases)

Work proceeds in this order. Nothing is permitted to masquerade as complete
before its evidence exists.

| Phase | Conservation stratum |
|---|---|
| 0 | Constitution, authorities, claim algebra |
| 1 | Complete archaeology / API / ABI atlas |
| 2 | Distribution / ABI shell |
| 3 | Core runtime (allocation, threads, ERR, refcounts, ex_data, stacks, objects) |
| 4 | BIO + CONF + object database |
| 5 | BN + ASN.1 + DER/PEM |
| 6 | `OSSL_LIB_CTX` + provider core |
| 7 | EVP framework |
| 8 | Native cryptographic primitives |
| 9 | RAND / DRBG + entropy |
| 10 | Key formats + PKCS + STORE |
| 11 | X.509 + verification |
| 12 | CMS / OCSP / CMP / CT / TS and remaining `libcrypto` families |
| 13 | Legacy / deprecated compatibility |
| 14 | TLS / DTLS (`libssl`) |
| 15 | QUIC / ECH and modern SSL surface |
| 16 | CLI / config / filesystem contract |
| 17 | Downstream replacement court |
| 18 | Hostile fuzz / security / side-channel hardening |
| 19 | Performance / CPU dispatch |
| 20 | 3.6.4 custodian seal |
| 21 | Maintenance delta machinery |

**Not** the start: AES, SHA, RSA, TLS. That feels productive and works against
the architecture.

## 2. Phase exit rule

A phase does **not** end on implementation presence. Each phase ends with:

```
1  authority identity
2  obligation inventory
3  court manifests
4  raw captures
5  residual set
6  mutation / sensitivity evidence
7  resolution runs
8  FRF receipts
9  generated parity projection
10 Gemel checkpoint
```

Any open residual intersecting the claim scope **blocks** the claim.

## 3. Maturity levels

Evidence-backed, machine-enforced exit criteria. These are not marketing names.

```
L0  archaeology complete
L1  source / API shell
L2  ABI-load compatible
L3  libcrypto core semantic parity
L4  provider / EVP parity
L5  complete libcrypto claimed surface
L6  libssl protocol parity
L7  CLI / distribution parity
L8  downstream custodian court
L9  high-assurance custodian seal
```

## 4. Court taxonomy

Stable court families. A court observes **only** dimensions it can actually
detect, and is challenged with seeded mutations:

```
API-HEADER  ABI-SYMBOL  ABI-VERSION  ABI-LAYOUT  ABI-LINK  ABI-LOAD
MEM-OWNERSHIP  ERR-QUEUE  THREAD-STATE  BIO-STATE  CONF  OBJ-NID
BN  ASN1  DER  PEM  PARAM  LIBCTX  PROVIDER-LOAD  PROVIDER-DISPATCH
FETCH-PROPERTY  EVP-DIGEST  EVP-CIPHER  EVP-MAC  EVP-KDF  EVP-RAND
EVP-KEYMGMT  EVP-SIGNATURE  EVP-KEX  EVP-KEM  ENCODER  DECODER  STORE
X509  X509-PATH  PKCS  CMS  OCSP  CMP  SSL-STATE  SSL-WIRE  SSL-CALLBACK
DTLS  QUIC  CONFIG  CLI  DOWNSTREAM  BUILD-MATRIX
libcrypto-contamination
```

## 5. Priority order when the project becomes large

1. fix evidence infrastructure if it cannot observe the required behaviour;
2. fix architectural residuals;
3. fix ownership / error / state / concurrency residuals;
4. complete missing foundational machinery;
5. complete dependent API families;
6. expand hostile cases;
7. expand downstream coverage;
8. optimise.

Trivial APIs are never chosen merely to improve a completion percentage.

## 6. Safety testing

Continuously run appropriate combinations of `Miri`, address/thread/UB sanitizers,
fuzzing, property tests, stress tests and model tests. The **authority may
contain C undefined behaviour; the candidate must not reproduce it** merely
because one observed run yielded a certain result. Such cases are recorded as
compatibility boundaries.

No Rust panic may unwind through a C ABI boundary. Every exported FFI function
establishes an unwind boundary or otherwise guarantees non-unwinding behaviour.

## 7. Security review gates

Before promoting cryptographic families, review for: integer overflow; length
conversions; bounds; parser recursion; secret-dependent behaviour; panic
reachability across FFI; use-after-free; double free; refcount overflow; null
handling; allocator mismatch; unchecked pointer arithmetic; concurrency;
invalid state-machine transitions; provider unload races.

## 8. Future version policy

Seal one authority before moving. For later 3.6.x:

```
admit new authority -> regenerate atlas -> oracle/oracle differential
-> identify added/removed/changed obligations -> implement delta
-> re-run affected courts -> re-run selected global downstream courts
-> emit new receipts
```

OpenSSL 4.x is a major-family transition and gets a **new compatibility
profile**. An OpenSSL 3 receipt is never silently reinterpreted as evidence for
OpenSSL 4.

### Cutting a release of this crate

A release is a **sequence**, and one step of it is not optional: the crate version
is an input to generated evidence. Written down here because the first 0.0.10
attempt skipped step 3 and the `static gates` job's
`gen_frf_courts.py --check` is what caught it — the gate working, and a reminder
that a gate is not a procedure.

1. Land the stratum on `main` with the pipeline green (`court/pipeline.sh`, or the
   two CI jobs, which run the same steps).
2. Bump `version` in `Cargo.toml` **and** regenerate `Cargo.lock`, which records the
   crate's own version. `cargo publish --dry-run` refuses a dirty tree, which is how
   the second file was found.
3. Re-run every generator whose output carries the version:
   `python3 forensics/tools/gen_frf_courts.py`. Each court's `version_or_commit` comes
   from `Cargo.toml` through this tool, deliberately — the alternative is 43 YAML
   files edited by hand at every release, and the tool's `--check` is the guard that
   makes skipping it a failure rather than a silent lie. `grep -rl "$(cargo metadata
   --format-version 1 --no-deps | python3 -c 'import json,sys;
   print(json.load(sys.stdin)["packages"][0]["version"])')" .` lists the carriers.
4. `python3 forensics/tools/gen_frf_courts.py --check` and `cargo fmt --all --
   --check` locally, so the release commit is green on its own account rather than
   on the strength of CI.
5. Push, and let `main` go green. A red `main` is not a state this project keeps, and since
   D138 it cannot be reached: `main` requires the three CI jobs, requires the branch to be up to
   date, requires a pull request, and enforces that for admins too. So a release lands by opening
   a pull request from the release branch and merging it once the three jobs report.
6. `cargo publish --dry-run`, then `cargo publish`, with `CARGO_TARGET_DIR` outside
   the repository so the packaging target directory does not collide with the
   crate's own.

OpenSSL 4.x is a major-family transition and gets a **new compatibility
profile**. An OpenSSL 3 receipt is never silently reinterpreted as evidence for
OpenSSL 4.

## 9. Definition of success

The project is successful when, for explicitly stated authority versions, build
profiles and platforms, all of `docs/CUSTODIAN_CONTRACT.md` §6 holds, including
binary substitution where the ABI contract allows, and FRF can compile the parity
claim from immutable receipts. Nothing less is a custodian seal.

When behaviour remains unknown, say `UNKNOWN` with precision. Unknown is a
research result. It is never traded for confidence theatre.
