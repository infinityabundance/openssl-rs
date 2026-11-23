# Cryptographic reference and differential classification (ETP-T5)

Status: normative description of the ETP-T5 references, their domains, the
cross-checks and the differential classification rules.
Implementation: `forensics/etp5_crypto/`.
Observed result: `evidence/etp-t5/RESULTS.json` and
`evidence/etp-t5/RECEIPT.md`.

This document does not assert that the candidate is correct.  It defines what
was compared, over which population, under which reading of which normative
document, and how a difference is classified.  The result for one candidate
identity is bounded evidence: it is not a proof, and it does not transfer to
another commit, another DSO or another platform.

---

## 1. What is and is not established

The campaign establishes, for the named candidate DSO and the named authority
DSO:

- that an independently written reference agrees with the candidate and with
  the pinned OpenSSL authority on every case in the sampled populations;
- that the references agree with published test vectors where a document
  supplies them, and with a second independent formulation where one exists;
- that the observation instrument is sensitive to a wrong value and that the
  classifier is sensitive to each class it claims to distinguish.

It does **not** establish:

- correctness outside the sampled populations;
- any curve other than P-256, any RSA key other than the one fixed key, or any
  RSA padding scheme;
- constant-time behaviour, side-channel resistance, memory safety, ownership
  or aliasing properties;
- a binary-level refinement from the Rust source to the DSO;
- that the authority is normatively correct.  The authority is a behavioural
  reference.  The normative documents are the arbiter of a difference.

A green differential is therefore compatible with a shared defect in the
candidate, the authority and the reference.  The cross-checks reduce that risk;
they do not remove it.

---

## 2. Normative sources

| component | document | section | what is taken |
|---|---|---|---|
| P-256 domain parameters | SEC 2 v2.0 (2010) | 2.4.2 | `p`, `n`, `a`, `b`, `G`, cofactor |
| P-256 domain parameters | FIPS 186-4 (2013) | Appendix D.1.2.3 | the same parameters |
| P-256 domain parameters | NIST SP 800-186 (2023) | 3.2.1.3 | the same parameters |
| point encoding | SEC 1 v2.0 (2009) | 2.3.3 (point-to-octet) | uncompressed `04 || X || Y` |
| point decoding | SEC 1 v2.0 (2009) | 2.3.4 (octet-to-point) | used only to describe the harness input |
| ECDSA generation | FIPS 186-5 (2023) | 6.4.1 | `r`, `s` and the rejection rules |
| ECDSA verification | FIPS 186-5 (2023) | 6.4.2 | the defining equation |
| digest truncation | FIPS 186-5 (2023) | 6.4.1 and 6.4.2 | leftmost `min(bitlen(n), bitlen(digest))` bits |
| RSA key and CRT representation | PKCS #1 v2.2 / RFC 8017 (2016) | 3.2 | `n`, `e`, `d`, `p`, `q`, `dmp1`, `dmq1`, `iqmp` |
| RSA private operation | PKCS #1 v2.2 / RFC 8017 (2016) | 5.1.2 (RSADP) | `m = c^d mod n` |
| SHA-256 | FIPS 180-4 (2015) | 4.1.3, 4.2.2, 5.1.1, 6.2.2 | initial value, constants, padding, compression |
| HMAC-SHA-256 | RFC 2104 (1997) | 2 | the HMAC construction |
| HMAC test vectors | RFC 4231 (2005) | 4 | published vectors |
| deterministic ECDSA nonce | RFC 6979 (2013) | 3.2 | HMAC-DRBG nonce; cross-check only |

The point-addition, doubling and scalar-multiplication formulas are **not**
prescribed by the normative documents.  They define the group and the scalar
multiplication; the formulas are an implementation choice.  The reference uses
the affine chord-and-tangent law and the Jacobian formulas of Hankerson,
Menezes and Vanstone, *Guide to Elliptic Curve Cryptography* (2004),
Algorithms 3.21 (doubling) and 3.22 (addition), and checks the two
representations against each other.

The RSA CRT **recombination algorithm** is likewise not prescribed by
RFC 8017; the standard defines the CRT representation and the RSADP result.
The reference uses Garner's algorithm, which is algebraically equivalent to
`m = c^d mod n`.  The equivalence is checked on every RSA representative.

---

## 3. Reference implementations

All references are Python 3.11 standard library only.  They do not import a
cryptographic package and do not transcribe the candidate or OpenSSL source.

### 3.1 Modular arithmetic (`ref_arith.py`)

**Definition.**  Addition, subtraction and multiplication are the ordinary
integer operations followed by reduction into `[0, m)`.  A modular inverse is
defined by `a * inv(a) == 1 (mod m)`.  Exponentiation is repeated squaring.

**Domain claimed correct.**  Integers; `m` is the P-256 prime `p` or the group
order `n`; both are prime; the inverse is computed only for `a` coprime to `m`;
the exponent is non-negative.

**Ambiguity.**  The normative documents define the inverse property, not an
algorithm.  The reference uses the extended Euclidean algorithm; Fermat
inversion `a^(m-2) mod m` is the independent second formulation used by the
cross-check.  The result is unique modulo `m`, so there is no interpretive
freedom in the value.

**Implementation note.**  `mod_exp` deliberately does not call Python's
built-in `pow`; the built-in is used only in the cross-check.

### 3.2 P-256 point arithmetic (`ref_ec.py`)

**Affine representation.**  `(x, y)` with the point at infinity as `None`.
Addition is the chord-and-tangent law; doubling is the tangent case; a point
and its negation sum to infinity; `P + P` is doubling.

**Jacobian representation.**  `(X : Y : Z)` with `x = X/Z^2`, `y = Y/Z^3`; `Z
== 0` is infinity.  Doubling uses Algorithm 3.21 and addition Algorithm 3.22 of
Hankerson et al., with `a = p - 3`.

**Scalar multiplication.**  Left-to-right double-and-add, once over affine
points and once over Jacobian points.  Both are references, not constant-time
implementations.

**Domain claimed correct.**  Points on `y^2 = x^3 + a*x + b` over the P-256
field, non-negative integer scalars.  The point at infinity is represented
explicitly.

**Ambiguity.**  Coordinate system and formulas are not normative.  The chosen
interpretation is the standard affine and Jacobian formulation; the two are
independent and are required to agree on every sampled scalar.  The curve
equation, the generator and the order are the published parameters.

**Encoding.**  Uncompressed `04 || X || Y` per SEC 1 v2.0 section 2.3.3; the
point at infinity is encoded as the single byte `00`, matching
`EC_POINT_point2oct`.

### 3.3 ECDSA (`ref_ecdsa.py`)

**Generation with a supplied nonce.**

```
R  = k * G
r  = x(R) mod n                 reject r == 0
s  = k^-1 * (z + r * d) mod n   reject s == 0
```

**Verification (the defining equation).**

```
w  = s^-1 mod n
u1 = z * w mod n
u2 = r * w mod n
P  = u1 * G + u2 * Q
accept iff x(P) mod n == r
```

`z` is the leftmost `min(bitlen(n), bitlen(digest))` bits of the digest.  For
P-256 and SHA-256 both are 256 bits, so `z = int(digest)`; the reduction modulo
`n` happens inside the formulas.

**Domain claimed correct.**  `d` and `k` in `[1, n-1]`; `Q = d*G` on the curve;
verification rejects `r` or `s` outside `[1, n-1]` and the point at infinity.

**Ambiguity.**  FIPS 186-5 does not require a low-`s` normalisation, and the
reference does not apply one.  The authority does not apply one by default.
This is a stated interpretation, not a normative requirement.

**RFC 6979.**  The reference also implements the RFC 6979 section 3.2 nonce so
that the published A.2.5 P-256/SHA-256 vector can be reproduced.  The
differential campaign supplies the nonce directly; the RFC path is a reference
cross-check, not a candidate operation under test.

### 3.4 RSA (`ref_rsa.py`)

**Key.**  One fixed 2048-bit key generated deterministically from the campaign
seed.  A SHA-256 counter-mode stream selects 1024-bit candidates with the top
two bits set; candidates advance by two until a Miller-Rabin probable prime
coprime to `e = 65537` is found.  `d` is `e^-1 mod lambda(n)` with
`lambda(n) = lcm(p-1, q-1)` as in RFC 8017 section 3.2.  The key is validated
on load: `n = p*q`, `e*d = 1 (mod lambda)`, both CRT exponents, `iqmp`, and
both factors probable prime.

**CRT recombination (Garner).**

```
m1 = c^dmp1 mod p
m2 = c^dmq1 mod q
h  = iqmp * (m1 - m2) mod p
m  = m2 + h * q
```

**Plain private operation.**  `m = c^d mod n` (RFC 8017 section 5.1.2).

**Domain claimed correct.**  One fixed key; representatives `c` in `[0, n)`;
no signature padding and no key generation by the candidate.  The CRT and plain
results are required to agree on every representative.  The committed key is
test data for this campaign, not a secret, and must not be used for any real
key operation.

**Ambiguity.**  The recombination algorithm is not normative; Garner is
algebraically equivalent to RSADP.  The deterministic key-generation procedure
is an implementation choice; reproducibility is from the recorded seed, not
from a normative key-generation standard.

### 3.5 SHA-256 control (`ref_symmetric.py`)

SHA-256 is implemented from FIPS 180-4 and HMAC-SHA-256 from RFC 2104.  The
SHA-256 differential is the **control** for the harness: a symmetric digest
that does not depend on field or group arithmetic.  If the harness agrees on
SHA-256 but disagrees on a number-theoretic operation, the difference is not in
the hex transport, the DSO loading or the output formatting.

**Domain claimed correct.**  Arbitrary byte strings; the differential includes
lengths `0..64`, `127`, `128`, `129`, `255`, `256` and `1000`, and the reference
cross-check includes the 1,000,000-byte FIPS example.

---

## 4. Cross-checks

A reference that agrees only with itself is not independent.  The following
checks are recorded in `RESULTS.json` under `cross_checks`; each is required to
pass before a differential result is treated as complete.

| check | independent formulation | population | observed |
|---|---|---|---|
| `arith_inverse_extended_euclid_vs_fermat` | extended Euclid vs `a^(m-2) mod m` | 536 inverses over `p` and `n` | PASS |
| `arith_square_and_multiply_vs_pow` | explicit square-and-multiply vs Python `pow` | 536 exponentiations | PASS |
| `ec_affine_vs_jacobian_and_curve_membership` | affine vs Jacobian scalar multiplication, plus curve membership | 388 scalars | PASS |
| `ec_group_law_and_order` | `G` on curve, `n*G = O`, `k*G + (n-k)*G = O` | 10 sampled scalars plus the order | PASS |
| `rsa_crt_vs_plain_and_public_inverse` | Garner CRT vs `c^d mod n` vs `m^e mod n` | 39 representatives | PASS |
| `sha256_fips180_4_published_vectors` | FIPS 180-4 published digests | 4 short vectors plus the 1,000,000-byte vector | PASS |
| `hmac_sha256_rfc4231` | RFC 4231 test cases 1 and 2 | 2 vectors | PASS |
| `rfc6979_p256_sha256_sample` | published `k`, `r`, `s` and verification | RFC 6979 A.2.5, message `sample` | PASS |
| `rsa_fixed_key_invariants` | `n = p*q`, `e*d = 1 (mod lambda)`, probable primes | the fixed key | PASS |

The published vectors are the external anchor: the P-256 parameters, the
FIPS 180-4 digests, the RFC 4231 MACs and the RFC 6979 nonce/signature are not
produced by this reference.  The affine/Jacobian and Euclid/Fermat pairs are
the internal anchor.  Neither anchor alone is sufficient.

---

## 5. Differential populations

Seed: `0x45545035`.  Every pseudo-random value is derived from that seed;
`make_vectors.py --check` reproduces the tracked files byte for byte.

| population | cases | composition |
|---|---|---|
| field and order arithmetic | 3622 | add/sub/mul: 850 each (the 13 distinct boundary values form every pair, plus 256 pseudo-random pairs, for each of `p` and `n`); inverse: 536; exponentiation: 536 |
| P-256 scalar multiplication | 388 | `0`, `1`, `2`, `3`, `n-2`, `n-1`; all `2^i` for `i = 0..255`; 128 pseudo-random scalars; duplicates removed |
| ECDSA | 67 vectors / 201 harness cases | 67 supplied-nonce signatures, 67 verifications of the reference signature, 67 verifications of a tampered signature (`s + 1 mod n`); one vector is RFC 6979 A.2.5 |
| RSA | 39 + 1 | 39 representatives (including `0`, `1`, `2`, `n-2`, `n-1`, `2^2047 mod n`, `2^2048-1 mod n`) plus `RSA_check_key` |
| SHA-256 control | 75 | 4 published vectors, lengths `0..64`, `127`, `128`, `129`, `255`, `256`, `1000` |

Total harness cases: **4326**.

The field boundary set is `{0, 1, 2, 3, m-1, m-2, m//2, (m-1)//2,
2^255 mod m, (2^256-1) mod m, 2^128 mod m, 2^192 mod m, Gx mod m, Gy mod m}`,
with duplicate values removed.  The pseudo-random population is sampled, not
exhaustive.

**Population stability.**  The vectors were generated before the first
differential observation.  Driver and harness defects found while bringing up
the instrument (a vector-key lookup, fixed-width comparison of a short `s`
value, and an odd-length RSA input encoding) were repaired before any
observation was recorded; no population was added to, removed from or otherwise
adjusted after a disagreement.  If a future investigation extends a population,
the original result is retained and the extension is reported separately.

---

## 6. Driving the candidate

`etp5_harness.c` loads exactly one `libcrypto.so.3` with
`dlopen(RTLD_NOW | RTLD_LOCAL)` and resolves every entry point with `dlsym`.
The harness is not linked against libcrypto, so the same binary drives the
candidate and the pinned authority.

| operation | C ABI calls |
|---|---|
| field/order arithmetic | `BN_mod_add`, `BN_mod_sub`, `BN_mod_mul`, `BN_mod_inverse`, `BN_mod_exp` |
| scalar multiplication | `EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)`, `EC_POINT_mul`, `EC_POINT_point2oct` |
| ECDSA signing | `EC_KEY_set_private_key`, `EC_KEY_set_public_key`, `ECDSA_do_sign_ex(kinv, r)`, `ECDSA_SIG_get0`, `ECDSA_do_verify` |
| ECDSA verification | `EC_POINT_oct2point`, `EC_KEY_set_public_key`, `ECDSA_SIG_set0`, `ECDSA_do_verify` |
| RSA | `RSA_set0_key`, `RSA_set0_factors`, `RSA_set0_crt_params`, `RSA_private_encrypt(RSA_NO_PADDING)`, `RSA_check_key` |
| control | `SHA256` |

The supplied nonce enters through `ECDSA_do_sign_ex`: the caller supplies
`kinv = k^-1 mod n` and `r = x(k*G) mod n`, which is the supplied-nonce form of
the OpenSSL ABI.  The candidate returns `(r, s)`; `r` and `s` are compared
exactly.

Verification is exercised in both directions for both subjects: the candidate
and the authority verify the reference signature (the `-verify` cases), and the
reference verifies the signature returned by the candidate and by the authority
(the `-sign` cases).  The four counts and any failures are recorded as
`ecdsa_cross_direction` in `RESULTS.json`.

Candidate identity (this result): commit
`ecd01a20fb69dbee972521e94857ab5169b6472d`, clean build-relevant tree,
distribution-shaped `libcrypto.so.3` with SHA-256
`e071ffeebecf326a77131105ba5bd7f56af19341861be78a6976e1b73a9d7ff7`.
Authority identity: OpenSSL 3.6.4 production DSO with SHA-256
`611e511db4273c4b6b522031fd171efce71b80661bb8310c2a21dfd18ec0efd2`.

### Instrument sensitivity

Two controls are run before the campaign:

- **classifier self-test** — ten synthetic cases exercise every classifier
  class: agreement, candidate defect, reference defect, authority deviation,
  three-way `UNKNOWN`, harness artefact, and the verify-decision variants;
- **transport control** — the harness is asked for `1 + 2 mod p`; the correct
  value is observed, and a deliberately wrong expected value is rejected.  This
  proves the observation-and-comparison path, not only the classifier.

Both controls are reported in the receipt.  Neither is a claim about the
candidate.

---

## 7. Disagreement classification

Every case is compared three ways: candidate against reference, authority
against reference, and candidate against authority.  Let `R`, `C` and `A` be
the reference, candidate and authority observations.  Exactly one class is
assigned:

| condition | class | meaning |
|---|---|---|
| `C == R == A` | none | agreement |
| `C == R` and `A != R` | `authority_deviation` | the candidate differs from OpenSSL and the normative reference agrees with the candidate |
| `C != R` and `A == R` | `candidate_defect` | the candidate differs from the normative reference and the authority agrees with the reference |
| `C == A` and `C != R` | `reference_defect` | both implementations agree and the reference differs; the normative text is the arbiter |
| `C != A`, `C != R`, `A != R` | `UNKNOWN` | pairwise disagreement; the evidence that would settle it is a reading of the cited normative section, and the original observation is retained |
| any observation missing or malformed | `harness_artefact` | the harness or the DSO refused the call; nothing is concluded about the cryptographic result |

A disagreement is not resolved by preference, ordering or recency.  A
three-way difference is not labelled `reference_defect` merely because two
implementations agree: agreement between the candidate and the authority can
reproduce a shared non-normative interpretation.  `UNKNOWN` is the honest
classification until the normative text is read.

For ECDSA verification the comparison uses the accept/reject decision, because
FIPS 186-5 defines the decision, not the integer error code.  A difference in
the integer return value with the same decision is recorded as a note, not as a
cryptographic disagreement.  The raw values remain in the harness output.

Every difference is published in `RESULTS.json` with the case identifier, the
operation, the inputs, all three observations, the classification and the
evidence.  A difference where the candidate is right and the reference is wrong
is classified `reference_defect` and is published in the same way; it is not
suppressed.

---

## 8. Observed result

At the identity named in section 6:

- 4326 cases executed against both DSOs;
- 0 differences: `counts_by_class = {}`;
- 9/9 reference cross-checks PASS;
- ECDSA cross-direction: 67/67 reference signatures accepted by the candidate
  and 67/67 by the authority; 67/67 candidate signatures and 67/67 authority
  signatures verified by the reference, with 0 failures in all four arms;
- 10/10 classifier controls PASS;
- transport control PASS.

No authority deviation, candidate defect, reference defect, normative ambiguity,
harness artefact or `UNKNOWN` was observed.  This is an observation about this
candidate, this authority, this build and this sampled population.  It is not a
proof of correctness and it does not establish constant-time behaviour or
memory safety.

`RESULTS.json` is the authoritative record.  This section is a summary of it.

---

## 9. Non-claims

- The populations are sampled, not exhaustive.
- Only P-256 is covered; no other curve is compared.
- Only one fixed RSA key and the raw private operation are covered; RSA key
  generation, PKCS #1 v1.5, PSS and OAEP are not.
- ECDSA nonce generation is not under test; the RFC 6979 path is a reference
  cross-check.
- The differential does not establish constant-time behaviour, side-channel
  resistance, memory safety, ownership, aliasing or panic safety.
- The differential does not establish a binary-level refinement between the
  Rust source and the DSO, nor that the DSO was built from the named commit
  beyond the recorded build identity and digest.
- The reference's own correctness rests on the reading of the normative
  documents stated in section 2; a misreading would make a `reference_defect`
  look like an agreement.
- Agreement with the authority is not normative correctness.  The authority is
  a behavioural reference and may itself be wrong.
