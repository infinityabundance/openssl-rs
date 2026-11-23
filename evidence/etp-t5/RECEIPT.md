# ETP-T5 - independent cryptographic references and differential receipt

Status: `PARTIAL` for the item, `AGREEMENT` for this candidate identity.
A differential observation is bounded evidence, never a proof.

## 1. Source identity and venue

| field | value |
|---|---|
| branch | `staging` |
| HEAD at the start | `ecd01a20fb69dbee972521e94857ab5169b6472d` |
| worktree at the start | clean (`git status --porcelain` empty) |
| build-relevant worktree during the campaign | clean (`src`, `Cargo.toml`, `Cargo.lock`, `build.rs`, `rust-toolchain.toml`) |
| changes made | new `forensics/etp5_crypto/`, new `docs/CRYPTOGRAPHIC-REFERENCE.md`, new `evidence/etp-t5/`, ETP-T5 row of `docs/ETP-TODO.md`; no change to `src/`, `docker/` or another item's evidence |
| memory at the start | `available` 25 GiB |
| memory before the campaign | `MemAvailable` 24-26 GiB; the court was started with `OPENSSL_RS_COURT_MEM=6g OPENSSL_RS_COURT_MEMSWAP=6g` |
| court image | `openssl-rs-court-tools:1` |
| toolchain | `rustc 1.98.1 (48a229cea 2026-09-01)`, `cc (Debian 12.2.0-14+deb12u1) 12.2.0`, Python 3.11.2 |
| candidate DSO | distribution-shaped `libcrypto.so.3`, SHA-256 `e071ffeebecf326a77131105ba5bd7f56af19341861be78a6976e1b73a9d7ff7` |
| authority DSO | OpenSSL 3.6.4 production, SHA-256 `611e511db4273c4b6b522031fd171efce71b80661bb8310c2a21dfd18ec0efd2` |

The candidate was rebuilt from the named commit in a fresh `CARGO_TARGET_DIR`
inside the court, linked with the whole archive, the shell object and
`artifacts/phase2/libcrypto.ld`.  Nothing was compiled on the host.  The
authority is the pinned `openssl-3.6.4-production` DSO named in
`docs/AUTHORITY_POLICY.md`.

## 2. Delivered files

| path | SHA-256 |
|---|---|
| `forensics/etp5_crypto/ref_arith.py` | `dd2b73d89fa4a674a0db11247c64edb56dfdbbf1f3dcaed09fc93926728bd460` |
| `forensics/etp5_crypto/ref_ec.py` | `9b3436683b91b118fdbff38898be11d0d5071f39e8b8a2790bdd4cb1d2c89ea8` |
| `forensics/etp5_crypto/ref_ecdsa.py` | `502ce746a131cc262cefd2871211290382c5659af53ce6f8e5aac10cf8455284` |
| `forensics/etp5_crypto/ref_rsa.py` | `83d96fd703d42bf0dabe154d67ed835fec4a2e608bc00a2f9899c102d178d9d4` |
| `forensics/etp5_crypto/ref_symmetric.py` | `989a2d3cd1f513e50bf5765ab77206690bca43df5e300dcf24b7baac1cba5e7e` |
| `forensics/etp5_crypto/make_vectors.py` | `f544fc69120aa18cc3702d827192efc39759c4c16bde20910512a4385149bead` |
| `forensics/etp5_crypto/etp5_harness.c` | `946881578568be2a3d55252dcec053ee9821e40ef5ce47971b7c56d4afe0c4dd` |
| `forensics/etp5_crypto/driver.py` | `0302c1d700cce243937791ee29f15408c28d45ac98bd2f65aa45175a394f0638` |
| `forensics/etp5_crypto/run_etp5.sh` | `9e61aa9a5805abe84b8f46fd444919b8ce17c698616e88df4e2b7c152780b14b` |
| `forensics/etp5_crypto/README.md` | `3aeb028495008ffd26cf7c266441966c072a1da312dac720af3788d91786d1da` |
| `forensics/etp5_crypto/vectors/field_order.json` | `85e4c78901209c81f866e49e49ebb447dce8842e9fbcbaf6cbdbca7f718c46dd` |
| `forensics/etp5_crypto/vectors/scalarmul.json` | `9112c1000e9dc1288853cd2759ac4918a4fb95693aba41ff154128b5d444eef0` |
| `forensics/etp5_crypto/vectors/ecdsa.json` | `4dd5fb85c19db5cc9950c88b569ca34d968c4302cb3b87d111cb004b44e6068d` |
| `forensics/etp5_crypto/vectors/rsa_key.json` | `9de2dc230e2ac25478a39953f748b7079a7308d2344d39fb3d790112d7ff6b81` |
| `forensics/etp5_crypto/vectors/rsa.json` | `30e5a2a244387b2a996e17df4418eb19e1a1f1cb5bc1b746c965f39cc36d9f0b` |
| `forensics/etp5_crypto/vectors/sha256.json` | `ea9a2f7460641332c7e3bfa10a00ea773ea7c038cb0c866300604fb72e21486c` |
| `docs/CRYPTOGRAPHIC-REFERENCE.md` | `44e8031d697cbf49918295e7f5e804012778c79d265e6a5e533f07d01ebc7a1d` |
| `evidence/etp-t5/RESULTS.json` | `1b859ef426a286532bb7d540e59f164e5a294c9c9aa35bfb7097941fe4fdc971` |
| `docs/ETP-TODO.md` | `b435bcc274a8ec60f750d61c06a9227ae707342ccc0ab4d5f9c906cb6072a82b` |

`RESULTS.json` is validated with `python3 -m json.tool`.  The vector files are
reproduced byte for byte by `make_vectors.py --check`.

## 3. References and normative sources

| reference | document and section | claimed domain |
|---|---|---|
| modular add/sub/mul/inverse/exponentiation | P-256 parameters: SEC 2 v2.0 section 2.4.2, FIPS 186-4 Appendix D.1.2.3, SP 800-186 section 3.2.1.3; inverse and exponentiation are defined by their arithmetic properties | `p` and `n`; inverse only for coprime operands; non-negative exponents |
| affine and Jacobian P-256 point arithmetic | group and parameters from the documents above; formulas are not normative; chosen interpretation: Hankerson-Menezes-Vanstone, *Guide to ECC*, Algorithms 3.21 and 3.22; uncompressed encoding from SEC 1 v2.0 section 2.3.3 | points on the curve; non-negative scalars |
| ECDSA with a supplied nonce | FIPS 186-5 sections 6.4.1 and 6.4.2 | `d`, `k` in `[1, n-1]`; `Q = dG`; `r`, `s` in `[1, n-1]` |
| RSA CRT and plain private operation | PKCS #1 v2.2 / RFC 8017 sections 3.2 and 5.1.2; Garner recombination is an implementation choice equivalent to RSADP | one fixed 2048-bit key; representatives in `[0, n)`; no padding/keygen |
| SHA-256 control | FIPS 180-4 sections 4.1.3, 4.2.2, 5.1.1 and 6.2.2 | arbitrary byte strings |
| HMAC-SHA-256 cross-check | RFC 2104 section 2; RFC 4231 vectors | arbitrary keys and messages |
| RFC 6979 nonce cross-check | RFC 6979 section 3.2 | P-256 with SHA-256 |

The full ambiguity notes and non-claims are in
`docs/CRYPTOGRAPHIC-REFERENCE.md`.

## 4. Reference cross-checks (observed)

| check | population | observed |
|---|---|---|
| extended-Euclid inverse vs Fermat `a^(m-2) mod m` | 536 inverses over `p` and `n` | PASS |
| explicit square-and-multiply vs Python `pow` | 536 exponentiations | PASS |
| affine vs Jacobian scalar multiplication, and curve membership | 388 scalars | PASS |
| group law and order (`G` on curve, `nG = O`, `kG + (n-k)G = O`) | 10 sampled scalars plus the order | PASS |
| RSA Garner CRT vs `c^d mod n` vs `m^e mod n` | 39 representatives | PASS |
| FIPS 180-4 SHA-256 published vectors | 4 short vectors plus the 1,000,000-byte example | PASS |
| RFC 4231 HMAC-SHA-256 | 2 vectors | PASS |
| RFC 6979 A.2.5 `k`, `r`, `s` and verification | 1 published vector | PASS |
| fixed-key invariants (`n = p*q`, `e*d = 1 (mod lambda)`, probable primes) | the fixed key | PASS |

Observed values include `k = a6e3c57d...8aad60`, `r = efd48b2a...af3716` and
`s = f7cb1c94...3acda8` for RFC 6979 A.2.5, matching the published vector
exactly.

## 5. Differential populations

Seed: `0x45545035`.  The seed and every population are recorded in
`RESULTS.json`; `make_vectors.py --check` reproduces the files.

| population | cases | composition |
|---|---|---|
| field and order arithmetic | 3622 | add/sub/mul: 850 each; inverse: 536; exponentiation: 536; 1811 cases over `p` and 1811 over `n` |
| P-256 scalar multiplication | 388 | `0`, `1`, `2`, `3`, `n-2`, `n-1`; all `2^i`, `i = 0..255`; 128 pseudo-random scalars |
| ECDSA | 201 | 67 supplied-nonce signs, 67 reference-signature verifications, 67 tampered-signature rejections |
| RSA | 40 | 39 representatives plus `RSA_check_key` |
| SHA-256 control | 75 | 4 published vectors plus lengths `0..64`, `127`, `128`, `129`, `255`, `256`, `1000` |
| total | **4326** | |

The differential drives the candidate and the authority through the same C ABI:
`BN_mod_add`/`BN_mod_sub`/`BN_mod_mul`/`BN_mod_inverse`/`BN_mod_exp`,
`EC_POINT_mul`/`EC_POINT_point2oct`, `ECDSA_do_sign_ex(kinv, r)` and
`ECDSA_do_verify`, `RSA_private_encrypt(RSA_NO_PADDING)`/`RSA_check_key`, and
`SHA256`.  The supplied nonce enters as the OpenSSL ABI accepts it: `kinv` and
`r` are supplied, and the candidate returns `(r, s)`.

ECDSA verification is exercised in both directions.  The candidate and the
authority verify the reference signature (the `-verify` cases), and the
reference verifies the signature returned by the candidate and by the
authority (the `-sign` cases).  Observed: 67/67 reference signatures accepted
by the candidate, 67/67 by the authority, 67/67 candidate signatures and 67/67
authority signatures accepted by the reference, with 0 failures in all four
arms (`ecdsa_cross_direction` in `RESULTS.json`).

## 6. Disagreements

**Zero.**  `counts_by_class = {}` and `differences.items = []` in
`RESULTS.json`.  No `authority_deviation`, `candidate_defect`,
`reference_defect`, `normative_ambiguity`, `harness_artefact` or `UNKNOWN` was
observed.

The classifier was exercised on ten synthetic known differences before the
campaign (agreement, candidate defect, reference defect, authority deviation,
three-way `UNKNOWN`, harness artefact, and the verify-decision variants): 10/10
PASS.  A transport control asked the harness for `1 + 2 mod p`, observed the
correct value, and confirmed that an injected wrong expected value is rejected:
PASS.  The classifier is therefore sensitive to every class it claims to
distinguish; the green result is not a classifier that cannot fail.

The vectors were not changed after any observation.  Three instrument defects
found while bringing up the harness (a vector-key lookup, fixed-width
comparison of a short `s`, and odd-length RSA input encoding) were repaired
before the first differential observation; no population was added to, removed
from or adjusted.

## 7. What this establishes

For the named candidate DSO, authority DSO, build and sampled population:

- the candidate agrees with an independently written reference on every case;
- the reference agrees with the pinned authority on every case;
- the reference reproduces the published FIPS 180-4, RFC 4231 and RFC 6979
  vectors, and two independent formulations agree with each other;
- the observation instrument and the classifier are sensitive to a wrong
  value and to each class in the classification.

## 8. What this does not establish

- No proof of correctness or of equivalence between the normative text, the
  reference and the candidate; the result is a differential observation.
- No constant-time behaviour, side-channel resistance, memory safety,
  ownership, aliasing or panic safety.
- No binary-level refinement from the Rust source to the DSO.
- No coverage beyond P-256, the one fixed RSA key, the raw RSA private
  operation, and the sampled populations.
- No statement that the authority is normatively correct; the authority is a
  behavioural reference.
- No statement about another commit, DSO, build profile or platform.

The reference's own correctness depends on the reading of the normative
documents stated in `docs/CRYPTOGRAPHIC-REFERENCE.md`.  A misreading would make
a `reference_defect` look like an agreement; the published-vector and
independent-formulation cross-checks reduce, but do not remove, that risk.

## 9. Reproduction

From the repository root, inside the court:

```sh
OPENSSL_RS_COURT_IMAGE=openssl-rs-court-tools:1 \
OPENSSL_RS_COURT_MEM=6g OPENSSL_RS_COURT_MEMSWAP=6g \
  bash docker/openssl-rs-court.sh exec \
    env CARGO_BUILD_JOBS=4 bash forensics/etp5_crypto/run_etp5.sh
```

The run rebuilds the candidate from the current commit into a fresh target
directory, links the distribution DSO, rebuilds the harness, verifies the
tracked vectors, runs the classifier and transport controls, executes the
differential against the candidate and the authority, and rewrites
`evidence/etp-t5/RESULTS.json`.

## 10. Notes and deviations

- The candidate DSO used for the differential is the distribution-shaped DSO
  (whole archive, shell object and version script), matching the existing court
  harness model.  The measurement DSO is not used for this result.
- The candidate and authority are driven one per process with
  `dlopen(RTLD_NOW | RTLD_LOCAL)`; the harness prints the resolved library path.
- The authority digest `611e511d...` is the admitted
  `openssl-3.6.4-production` DSO.
- `RESULTS.json` records the path names used inside the court (`/work/...`),
  the candidate and authority digests, the harness digest, the source commit,
  the build-relevant dirty state and the population sizes.
- No `src/`, `docker/` or other item's evidence was modified.
