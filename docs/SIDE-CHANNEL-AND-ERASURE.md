# Side-channel and erasure verification (ETP-T7)

**Status:** `REGISTERED` for the classification, `RECORDED_NOT_REPAIRED` for the
erasure gaps, and `INSTRUMENT_CONTROLS_PASS` for the small dudect control run
described below. No constant-time claim is made for any mechanism, and no
erasure obligation is promoted to discharged.

**Candidate:** `0eddfe839f552a6e22a8cf375ec308c8bf7c478b` (`staging`).
**Governing standard:** `AGENTS.md` §5 (secret-bearing memory is a distinct
category; release and cleansing are separate obligations; source-level intent is
not constant-time behaviour), §11 (instruments are not interchangeable), §12
(the classification vocabulary) and §16 (negative controls).
**Evidence:** `evidence/etp-t7/SECRETS.json`,
`evidence/etp-t7/PREREGISTRATION.json`,
`evidence/etp-t7/DUDECT-ETP-T7.json`,
`evidence/etp-t7/ERASURE-AUDIT.json` and `evidence/etp-t7/RECEIPT.md`.
**Validators:** `forensics/tools/side_channel_erasure.py` and
`forensics/tools/preregistration_check.py`.

---

## 0. What this item does

1. Classifies secret-bearing surfaces, including the items that are normally
   left implicit: lengths, capacities, allocation sizes, loop bounds, table
   indices and addressed memory, error paths selected by a secret, and the
   declassification points.
2. Preregisters a measurement plan before a measurement exists, and checks a
   receipt against it.
3. Refuses six kinds of over-claim by name.
4. Audits the erasure obligations of the classified buffers and records the
   gaps without repairing them.

## 1. Classification vocabulary

The five classes are used exactly as `AGENTS.md` §12 states, with one addition
made explicit here: a secret's **length, capacity and allocation size are
separate items**. A `SECRET_DATA` entry says nothing about whether the length is
public; the length is its own entry when it matters.

| class | meaning in this register |
|---|---|
| `PUBLIC_DATA` | Not secret; may be observed without a leakage consequence. |
| `SECRET_DATA` | Secret contents whose exposure is a confidentiality failure. |
| `SECRET_DEPENDENT_CONTROL` | A branch, loop bound, allocation size, table index or memory address that depends on secret data. |
| `CLEANSING_REQUIRED` | Storage that must be wiped before release, over the stated extent, on every exit path. |
| `DECLASSIFICATION_BOUNDARY` | The point where a secret becomes legitimately observable, with the justification recorded. |

## 2. The register

`evidence/etp-t7/SECRETS.json` holds 51 entries. The validator recomputes the
counts from the entries and refuses a mismatch.

| class | entries |
|---|---:|
| `PUBLIC_DATA` | 3 |
| `SECRET_DATA` | 29 |
| `SECRET_DEPENDENT_CONTROL` | 9 |
| `CLEANSING_REQUIRED` | 5 |
| `DECLASSIFICATION_BOUNDARY` | 5 |

The surfaces are the admitted ones named in the entries: `runtime::secret`
(`SecretBuf`, `SecretArray`, `SecretRef`, `SecretLimbs`), the BN limb storage,
the ECDH output buffer, the ECDSA nonce and private scalar, the RSA CRT private
operation, the TLS 1.3 and TLS 1.2 connection schedules and record keys, the
session master key, the HPKE key schedule, CMS content keys and KEKs and
passwords, the provider KDF Argon2 secret and password copies, the provider
private-key decoders, `apps/kdf` and `apps/mac` scratch, the digest pads, the BN
random draw buffer, the AES/SM4/ARIA/Camellia table lookups, the ECDSA and BN
declassification points, and the PKCS#12 plaintext handoff.

Every entry names its source path, line, symbol and a token checked within three
lines of the citation. A citation that does not resolve is a validator failure,
not a footnote.

### 2.1 Secret-dependent control with no evidence

The rule is direct: a `SECRET_DEPENDENT_CONTROL` entry whose evidence is `NONE`
**is** the finding. Six entries meet it.

| id | source | control |
|---|---|---|
| `AES-SBOX` | `src/aes.rs:107` | `AES_SBOX[state byte]` in the byte-oriented round |
| `SM4-SBOX` | `src/sm4.rs:190` | `SM4_SBOX_T0[state byte]` |
| `ARIA-SBOX` | `src/aria.rs:316` | four 256-entry tables indexed by state bytes |
| `CAMELLIA-SBOX` | `src/camellia.rs:95` | `CAMELLIA_SBOX[..][state byte]` |
| `LIMB-NORMALISE` | `src/bn/limbs.rs:41` | trim loop whose count is the number of trailing zero limbs |
| `PKEY-XLAT-BUFLEN` | `src/evp/pkey_ctx.rs:4547` | `buflen = ceil(BN_num_bits(p2)/8)`, where `p2` can carry a private scalar |

The four cipher entries are the classic cache-timing shape: a secret value
selects a cache line. No timing, taint or branch-audit evidence in this tree
covers those lookups, so no constant-time claim about them can pass §4 below.
`LIMB-NORMALISE` is the variable-time trim; the constant-time store uses
`normalise_consttime`, but no per-call-site audit proves that no secret value
reaches the variable-time helper. `PKEY-XLAT-BUFLEN` is an allocation size
derived from a secret length, and is also the subject of finding `ERA-04`.

### 2.2 Secret-dependent control with evidence that reports a finding

These entries carry ctgrind or test evidence, and the evidence is not a clean
result:

| id | source | recorded evidence |
|---|---|---|
| `STORE-CONSTTIME` | `src/bn/bignum.rs:443` | ctgrind `ctgrind_store_consttime_result_length`, 1 error / 1 context |
| `ECDSA-NONCE-LOOP` | `src/ec/ecdsa_ossl.rs:461` | ctgrind ECDSA signing, 812 959 errors / 128 contexts |
| `ECDSA-RETRY-LOOP` | `src/ec/ecdsa_ossl.rs:779` | the same ECDSA signing case |
| `RSA-CRT` (content) | `src/rsa/ossl.rs:2415` | ctgrind RSA CRT, 97 626 errors / 111 contexts |
| `ECDSA-NONCE` (content) | `src/ec/ecdsa_ossl.rs:443` | the same ECDSA signing case |

The numbers are quoted from `courts/phase18/timing/RECEIPT-timing-unified.json`.
The stable quantity is the context count; the raw error total varies because the
tests generate a key per run.

## 3. Lengths, capacities and allocation sizes

A secret's length is metadata and can leak even when the contents do not. The
register therefore records the extent, not only the class:

- `SB-CAPACITY` (`src/runtime/secret.rs:319`) cleanses `capacity * size_of::<T>()`.
  `SB-BUF`, `SB-ARRAY`, `SB-LIMBS` inherit that obligation.
- `LIMB-CAPACITY` (`src/bn/limbs.rs:60`) cleanses the whole limb capacity; the
  `Vec` length is only the normalised top, so a shorter length is not a smaller
  cleanse.
- `ASN1-EXTENT` (`src/asn1/string.rs:332`) is the opposite: it cleanses `length`,
  not the allocation extent. This is finding `ERA-07`.
- `STORE-CONSTTIME` trims the result with a fixed-width mask scan; the normalised
  result length remains a declassified residual.
- `PKEY-XLAT-BUFLEN` is an allocation size computed from `BN_num_bits` of a
  BIGNUM that can be a private scalar.
- `LADDER-WIDTH` and `LADDER-BIT` are explicitly public: the ladder runs
  `64 * width` iterations over a public width, and the secret bit becomes a mask,
  not an address.

## 4. Loop bounds, table indices and addressed memory

The fixed-width primitives are classified as they are written:

- The Montgomery ladder (`src/bn/arith.rs:1901`) has a public loop bound and no
  secret index; ctgrind `ctgrind_secret_base_fold_and_ladder` reports 0 errors
  over 0 contexts.
- `normalise_consttime` (`src/bn/limbs.rs:209`) adds a fixed pass over the public
  width; the variable-time `normalise` remains a separate entry with no evidence.
- `constant_time_select` is used to choose between candidates, not to index a
  table. `src/bn/arith.rs:1712` states the design: there is no secret index; a
  table would be indexed by a secret, whereas the ladder selects between two
  register-shaped candidates.
- The AEAD field multiply (`src/modes/gcm.rs:145`) avoids Shoup's
  secret-indexed table and runs a fixed 128-bit multiplication; that is a design
  statement and carries no timing evidence.
- The AES, SM4, ARIA and Camellia rounds are table lookups indexed by secret
  state bytes; those are the four `NONE` findings above.

## 5. Error paths and declassification points

An error path whose selection depends on a secret is a `SECRET_DEPENDENT_CONTROL`
entry even when it looks like ordinary failure handling. The ECDSA nonce redraw
loop and the signature retry loop are two such paths; the RSA/ECDSA failure
returns are inside mechanisms whose ctgrind cases already report contexts.

The declassification points recorded here are:

| id | source | justification |
|---|---|---|
| `ECDSA-SIG-DECLASS` | `src/ec/ecdsa_ossl.rs:1119` | a produced signature is public; declassifying it makes the signing interior measurable |
| `INVERSE-DECLASS` | `src/bn/limbs.rs:1323` | the invertibility mask is accumulated over the fixed width; only the final zero test is branched on |
| `MONT-DECLASS` | `src/bn/mont.rs:1313` | the equality decision is the authorised point; the early-exit comparator is the negative control |
| `ECDH-OUTPUT` | `src/ec/ecdh_ossl.rs:98` | the success edge hands the shared secret to the caller, which owns and clears it |
| `PKCS12-PLAINTEXT` | `src/pkcs12/p12_decr.rs:206` | the success path returns decrypted plaintext; failure paths cleanse |

A declassification point is not a free pass: it says where a secret may become
observable and why, not that anything before it is safe.

## 6. Preregistration

`evidence/etp-t7/PREREGISTRATION.json` contains a template (required fields and
field rules) and two instances.

### 6.1 Prospective instance

`ETP-T7-DUDECT-INSTRUMENT-CONTROLS-1` was written before its run. It fixes:

- **hypotheses:** the positive control fires and the negative control stays
  quiet at the registered geometry;
- **workloads:** `cmpnaive` (early-exit comparison) and `cmpcmp`
  (`CRYPTO_memcmp`), each over two 4096-byte pairs differing at the first and
  last byte;
- **instrument:** the pinned dudect commit, the harness source digest and the
  header digest, with the admissible use and the not-its-use list;
- **geometry:** 10 000 measurements per batch, at most 3 batches, one run,
  `taskset -c 1`, two modes;
- **statistic:** Welch t per batch, threshold 10 and 500, state 0 =
  `DUDECT_LEAKAGE_FOUND`, state 1 = `DUDECT_NO_LEAKAGE_EVIDENCE_YET`;
- **controls:** `cmpnaive` expected state 0, `cmpcmp` expected state 1;
- **exclusions:** five fixed rules (`EX-1`…`EX-5`);
- **stopping conditions:** state 0, the batch budget, build/harness failure, and
  an artefact-identity mismatch;
- **null meaning:** absence of evidence at the geometry, not constant-time.

The receipt `evidence/etp-t7/DUDECT-ETP-T7.json` quotes the SHA-256 of the
preregistration and records the run:

| mode | role | batches × per batch | total | state | max abs t |
|---|---|---:|---:|---:|---:|
| `cmpcmp` | negative control | 3 × 10 000 | 30 000 | 1 | 0.98 |
| `cmpnaive` | positive control | 3 × 10 000 | 30 000 | 0 | 208.01 |

The controls behaved as preregistered. The harness binary digest
(`627882a8…`), the harness source digest (`bd898f…`), the header digest
(`3fb3b2…`) and the loaded DSO digest (`fd25cc9e…`) are in the receipt, and the
DSO resolution was checked with `ldd`.

**Deviation `DEV-1`.** The preregistered stopping condition said to stop a mode
when the harness reports state 0. The pinned harness runs the full batch budget
and reports the state afterwards, so `cmpnaive` ran three batches rather than
one. No measurement was added, removed or replaced; the realised geometry is
inside the registered budget and matches `per_batch` and `max_batches`. The
inaccurate wording is recorded in the receipt and the preregistration is **not**
amended after the run.

### 6.2 Reconstructed instance

`ETP-T7-DUDECT-LEGACY-RECONSTRUCTED` is `RECONSTRUCTED_POST_HOC`. It types the
geometry of `courts/phase18/timing/RECEIPT-dudect-modes.json` (seven modes,
20 000 per batch, at most three batches) so the recorded numbers can be checked
against the recorded geometry rather than restated from prose. It is not
evidence of prospective registration and supports no constant-time claim. The
legacy receipt records the loaded DSO digest and build-id but not the harness
binary digest; that gap is recorded, not repaired.

## 7. Refusal rules

`forensics/tools/side_channel_erasure.py check-claims` refuses a typed claim by
name. `--self-test` runs one positive and one negative control per rule. When
the caller supplies the artefact under test with `--artefact FILE` (the expected
identity is derived as `sha256:<hex>`) or `--binary-identity VALUE`, a ctgrind
claim whose recorded `binary_identity` differs from it is also refused: a
present identity is not the identity of the binary the log came from.

| rule | code | refused when | control |
|---|---|---|---|
| 1 | `CT_T_WITHOUT_PREREGISTERED_GEOMETRY` | a constant-time claim cites a t statistic without a preregistration id, geometry and criterion | `NC-1` refused, `PC-1` accepted |
| 2 | `CTGRIND_WITHOUT_HARNESS_IDENTITY_TAINT` | a ctgrind claim lacks the harness, the binary identity or the tainted inputs | `NC-2` refused, `PC-2` accepted |
| 2 | `CTGRIND_BINARY_IDENTITY_MISMATCH` | a ctgrind claim's recorded binary identity differs from the identity the caller supplies for the artefact under test | `NC-2B` refused, `PC-2` accepted against the matching identity |
| 3 | `DEBUG_BINARY_GENERALISED_TO_RELEASE` | a debug/test artefact is generalised to the release artefact | `NC-3` refused, `PC-3` accepted |
| 4 | `SECRET_DEPENDENT_CONTROL_WITHOUT_EVIDENCE` | a mechanism with class `SECRET_DEPENDENT_CONTROL` and evidence `NONE` is claimed constant-time or safe | `NC-4` refused (`AES-SBOX`), `PC-4` accepted |
| 5 | `EXCLUSIONS_CHANGED_AFTER_RUN` | the exclusion set differs from the preregistration, or is marked changed after the run | `NC-5` refused, `PC-5` accepted |
| 6 | `DUDECT_STATE_1_TREATED_AS_PROOF` | dudect state 1 is presented as a constant-time or safe verdict instead of absence of evidence at the geometry | `NC-6` refused, `PC-6` accepted |

The checker `forensics/tools/preregistration_check.py` additionally refuses a
receipt that mismatches its preregistration:

| code | refused when |
|---|---|
| `PR_PREREG_DIGEST_MISMATCH` | the quoted preregistration digest is not the file's |
| `PR_CANDIDATE_MISMATCH` | the measured DSO digest is not the registered one |
| `PR_HARNESS_SOURCE_MISMATCH` / `PR_HARNESS_BINARY_MISSING` | the harness identity is absent or wrong |
| `PR_BATCH_BUDGET` / `PR_BATCH_MISMATCH` / `PR_TOTAL_NOT_MULTIPLE` | the run leaves the registered geometry |
| `PR_POSITIVE_CONTROL_DID_NOT_FIRE` / `PR_NEGATIVE_CONTROL_FIRED` | a control leaves its registered direction |
| `PR_MISSING_MODE` / `PR_UNDECLARED_MODE` | the mode set differs from the preregistration |
| `PR_EXCLUSIONS_CHANGED` | the exclusion set changed after the run |
| `PR_EARLY_STOP_WITHOUT_LEAK` | a mode stopped early without a leakage finding |

## 8. Erasure audit

`evidence/etp-t7/ERASURE-AUDIT.json` treats release and cleansing as separate
obligations. Fifteen cleansing release arms were checked and are recorded as
present. Seven gaps were found. **None is repaired in this item.**

| id | class | severity | source | impact | named repair |
|---|---|---|---|---|---|
| `ERA-01` | `FREED_WITHOUT_CLEANSING` | HIGH | `src/ssl/ssl_lib.rs:3728` | TLS 1.3 early/handshake/master/traffic secrets, `psk_secret`, record keys, TLS 1.2 master secret and key block are inline in the connection block and are not wiped before the block is released | cleanse the inline schedule in `destroy_body`, or use a cleansing release over `size_of::<Ssl>()` |
| `ERA-02` | `LOST_CLEAR_FREE_ARM` | MEDIUM | `src/apps/mac.rs:262` | the authority's `OPENSSL_clear_free(buf, BUFSIZE)` arm became a plain `CRYPTO_free`; the last input chunk and the MAC output remain | use the cleansing release, or cleanse `BUFSIZE` before drop |
| `ERA-03` | `FREED_WITHOUT_CLEANSING` | MEDIUM | `src/asn1/x_pkey.rs:105` | `X509_PKEY` decrypted private-key data is released with a plain free | cleanse the recorded extent, or use `CRYPTO_clear_free` |
| `ERA-04` | `FAILURE_PATH_WITHOUT_CLEANSING` | MEDIUM | `src/evp/pkey_ctx.rs:4559` | a partially written translated BIGNUM is freed plainly when `BN_bn2nativepad` fails | cleanse `buflen` bytes on the failure path |
| `ERA-05` | `FREED_WITHOUT_CLEANSING` | MEDIUM | `src/evp/pkey_ctx.rs:3597` | the translated BIGNUM buffer is freed plainly at normal cleanup | cleanse `buflen` bytes before the release |
| `ERA-06` | `FREED_WITHOUT_CLEANSING` | MEDIUM | `src/bn/blinding.rs:301` | RSA blinding factors `a` and `ai` are released with `BN_free`, which cleanses only `BN_FLG_SECURE` objects | release `a` and `ai` with `BN_clear_free`, or set `BN_FLG_SECURE` at creation |
| `ERA-07` | `LENGTH_ONLY_CLEANSE` | LOW | `src/asn1/string.rs:332` | `ASN1_STRING_clear_free` cleanses `length`, not the allocation extent; a later length shrink leaves residue | record and cleanse the allocation extent, or cleanse `length + 1` and document the shrink case |

Five observations are recorded rather than findings: `CMS-KEK` cleanses a
prefix of a zero-initialised array and never writes the tail; `EVP_CIPHER_CTX_free`
cleanses a non-zero `cipher_data` extent; the PKCS#12 success path hands
plaintext out; `SSL_SESSION` does cleanse its master key and session id; and
`SecretBuf`/limb storage cleanse capacity.

## 9. What this does not establish

- **No constant-time claim.** `cmpcmp` state 1 is absence of evidence at
  10 000 × 3 per mode, not a proof. No mechanism in the register is
  `SAFETY_DISCHARGED` or constant-time by this item.
- **No microarchitectural coverage.** The dudect controls exercise a
  statistical timing class; they do not measure cache sets, branch predictors,
  port contention or speculative effects.
- **No release-artefact result.** The measured DSO digest is recorded, but its
  source identity is `UNKNOWN` and no source-to-binary correspondence is
  claimed.
- **No completeness.** The register covers the admitted surfaces cited; it is
  not a census of every secret in the crate.
- **No erasure remediation.** Seven gaps are recorded. The audit does not decide
  which authority-faithful residues to conserve and which to diverge from.
- **No runtime freed-memory inspection.** The erasure findings are source
  audits. ASan, Miri and Valgrind do not report residual bytes in released
  memory by default, so their absence would not have been evidence of cleansing.
- **No inheritance.** The result belongs to this court container, target and
  build; it does not generalise to another profile or CPU.

## 10. Reproduction

Inside the court:

```sh
OPENSSL_RS_COURT_IMAGE=openssl-rs-court-tools:1 \
OPENSSL_RS_COURT_MEM=6g OPENSSL_RS_COURT_MEMSWAP=6g \
  bash docker/openssl-rs-court.sh exec sh -c '
    cd /work
    python3 -m json.tool evidence/etp-t7/SECRETS.json > /dev/null
    python3 forensics/tools/side_channel_erasure.py validate --repo-root .
    python3 forensics/tools/side_channel_erasure.py --self-test --repo-root .
    python3 forensics/tools/preregistration_check.py \
      --prereg evidence/etp-t7/PREREGISTRATION.json \
      --instance ETP-T7-DUDECT-INSTRUMENT-CONTROLS-1 \
      --receipt evidence/etp-t7/DUDECT-ETP-T7.json
    python3 forensics/tools/preregistration_check.py --self-test --repo-root .
    python3 forensics/tools/tests/test_side_channel_erasure.py
  '
```

The dudect control binary is built from the tracked harness and the recorded
DSO:

```sh
cc -O2 -g -D_GNU_SOURCE \
  -I courts/phase18/timing/third_party/dudect \
  -I artifacts/phase2/install/include \
  courts/phase18/timing/dudect_bn.c \
  -L artifacts/phase2/install/lib -lcrypto -lm \
  -Wl,-rpath,/work/artifacts/phase2/install/lib -o /tmp/dudect_etp7
LD_LIBRARY_PATH=/work/artifacts/phase2/install/lib \
  taskset -c 1 /tmp/dudect_etp7 cmpcmp 10000
LD_LIBRARY_PATH=/work/artifacts/phase2/install/lib \
  taskset -c 1 /tmp/dudect_etp7 cmpnaive 10000
```

## 11. Invalidation

The classification is bound to the cited source lines and the erasure audit to
those owners. A change to a cited owner, to `dudect_bn.c`, `dudect.h` or the
preregistration invalidates the corresponding evidence and requires a new run.
The prospective receipt is bound to the preregistration digest
`d28964cc…`; editing the preregistration after the run is a refused change, not
an amendment.
