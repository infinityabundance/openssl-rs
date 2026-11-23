# HAZ-15 — external-key PKCS#1 v1.5 padding oracle

Status: **partially corrected, not eliminated.** The direct observable
distinction was removed on the tested return-sign / output-buffer / error-queue
axes, but the initial KDK justification was invalid and is retracted below, and
the returned **length** remains a distinguisher. The hazard is
`CLAIMED_NO_EVIDENCE` in the register, not `EVIDENCED`. The finding is a
**demonstrated difference in the observable set on a contract-valid input**, not
an exploit: plaintext disclosure additionally requires the application
preconditions in section 5.

## 0. Correction to the KDK argument (2026-11-22)

Sections 1–9 are the original finding and its first repair. They are retained as
the record; this section supersedes the part of section 6 that justified the
synthetic-message secrecy.

**The withdrawn argument.** The first repair keyed the implicit-rejection PRF
with `SHA-256(decrypted block)`, arguing that the block is secret because the
attacker cannot compute `c^d mod n`. That argument is invalid. RSA encryption is
public: for an attacker-chosen representative `m` the attacker computes
`c = m^e mod n` and the private operation returns `m`. The attacker therefore
knows the decrypted block — and `SHA-256(m)` — for every ciphertext the attacker
constructed, and can compute the synthetic answer the repair returns. The
construction does not establish the keyed pseudorandomness implicit rejection
requires.

**Why that is an oracle.** The returned message for an invalid block is a
function of attacker-known data, so an attacker can predict it and compare it
with the answer for a chosen `m`, recovering exactly the padding-validity
distinction the repair was meant to remove. The test
`rsa::ossl::tests::the_external_synthetic_answer_is_not_attacker_computable`
computes the withdrawn construction's answer and compares it with the returned
message; it fails when the withdrawn construction is restored (observed
`the returned message must not be the SHA-256(block)-keyed synthetic one`).

**The replacement.** `src/rsa/ossl.rs` now derives the KDK from private key
material and the ciphertext, with explicit domain separation:

1. when the object holds `d`, the authority's own `derive_kdk` is unchanged;
2. when it holds `p` and `q` but no `d`, the PRF key is
   `SHA-256("openssl-rs/rsa/ext-kdk/crt-key/v1" || p || q)` and the KDK is
   `HMAC-SHA-256(key, "openssl-rs/rsa/ext-kdk/ciphertext/v1" || ciphertext)`;
3. when it holds no private material at all (the engine-backed `(n, e)` shape),
   a 32-byte secret is drawn with `RAND_priv_bytes` at first use, stored against
   the object, cleansed when the object is destroyed, and used as the HMAC key
   with the same label. RNG or allocation failure is the defined refusal; there
   is no fallback to a publicly-derivable value.

**The remaining channel.** The generic check still returns the implicit
rejection's synthetic *length*. On the pinned 2048-bit key, valid messages of
8/16/32/48 bytes return those lengths, while 64 invalid blocks returned 58
distinct synthetic lengths and none of the four valid lengths. An application
that exposes the returned length — a TLS server expecting a 48-byte pre-master
secret, for example — therefore still has a distinguisher. The authority's own
answer for TLS is the fixed-length `ossl_rsa_padding_check_PKCS1_type_2_TLS`;
the generic check cannot make the length uniform without changing its contract.
This is a finding, not a pass. **The 64-block sample is superseded:** the
2,048-block measurement in `evidence/haz-15/REENTRANCY-AND-LENGTH.md` §5 matched
every protocol-relevant length, at a per-ciphertext probability of order
`1/246`, so the earlier zero-collision outcome was a property of a small sample
rather than of the implementation. Full detail and gate output are in
`evidence/haz-15/KDK-CORRECTION.md`, and the re-entrancy repair in the same path
is in `evidence/haz-15/REENTRANCY-AND-LENGTH.md`.

## 1. Identity and venue

| field | value |
|---|---|
| branch | `staging` |
| HEAD at the start | `478bf17ec1aa9022a784009a999a10e4eb4c07c4` |
| worktree at the start | clean (`git status --porcelain` empty) |
| `available` at the start | 25 GiB; the build was permitted under `AGENTS.md` §6.1 and the court was run with `OPENSSL_RS_COURT_MEM=6g OPENSSL_RS_COURT_MEMSWAP=6g` |
| court | `openssl-rs-court-tools:1` |
| authority | `openssl-3.6.4-production`, DSO SHA-256 `611e511db4273c4b6b522031fd171efce71b80661bb8310c2a21dfd18ec0efd2` |
| candidate before the correction | release build of HEAD, DSO SHA-256 `c816b3d15a470cdb820426d78287fa0757649f016a46f634ca149c58195b8a76` |
| candidate after the correction | release build of HEAD plus the `src/rsa/ossl.rs` change, DSO SHA-256 `db7d63ef4c1b702bd86bbcdf4ba9e036c063de18be84db9e8eed2fc2d55948a2` |

The harness (`forensics/haz15/haz15_harness.c`) loads exactly one `libcrypto.so.3`
with `dlopen(RTLD_NOW | RTLD_LOCAL)` and resolves every entry point with
`dlsym`, so one binary drives the candidate and the authority. The driver
(`forensics/haz15/drive.py`) assembles `evidence/haz-15/observables.json` from
the two runs and refuses a disagreement between the pre and post authority runs.

## 2. The code path

`src/rsa/ossl.rs`, `rsa_ossl_private_decrypt`:

1. While the key carries `RSA_FLAG_EXT_PKEY` and the caller asked for
   `RSA_PKCS1_PADDING`, the authority rewrites the selector to
   `RSA_PKCS1_NO_IMPLICIT_REJECT_PADDING` before any operation
   (`crypto/rsa/rsa_ossl.c:538-541`). The stated reason is that the KDK for
   implicit rejection is derived from the private exponent, which an external
   key does not hold.
2. The rewritten selector selects `RSA_padding_check_PKCS1_type_2`
   (`rsa_ossl.c:669-670`, `rsa_pk1.c:387`), the refusing check. On invalid
   padding it answers `-1`, leaves the output buffer untouched and leaves
   `RSA_R_PADDING_CHECK_FAILED` on the error queue.
3. The internal-key path keeps `RSA_PKCS1_PADDING` and selects
   `ossl_rsa_padding_check_PKCS1_type_2`, which answers a synthetic message and
   leaves no error.

The pre-correction candidate transcribed the authority exactly; the differential
reproduces the authority row for row (section 4).

## 3. The experiment

One fixed 2048-bit key (`forensics/etp5_crypto/vectors/rsa_key.json`) in two
shapes:

- **external** — `n`, `e`, `p`, `q`, `dmp1`, `dmq1`, `iqmp`; `d` absent;
  `RSA_FLAG_EXT_PKEY` set. This is the shape an engine-backed key has: the
  library can perform the private operation through the CRT parameters but does
  not hold the private exponent.
- **internal** — the same key with `d` present.

Four ciphertexts are submitted through `RSA_private_decrypt(..., RSA_PKCS1_PADDING)`:

| case | block |
|---|---|
| `valid` | `00 02` + 245 nonzero octets + `00` + the 8-octet message `HAZ15VAL` |
| `bad_type` | `00 03` + nonzero octets (wrong block type) |
| `short_ps` | `00 02` + four nonzero octets + `00` (padding string below the eight-octet minimum) |
| `out_of_range` | the ciphertext is the modulus itself (`c` is not in `[0, n)`) |

Each case records the return value, whether the output buffer was touched (and a
64-bit FNV-1a over the whole buffer), and the drained error queue. Timing is not
measured.

## 4. Observables

`evidence/haz-15/observables.json` carries every row. The table below is the
readable form. "unchanged" means every byte of the output buffer still held the
`0xAA` sentinel after the call.

| implementation | key | case | return | output buffer | error queue |
|---|---|---|---:|---|---|
| authority 3.6.4 | external | valid | `8` | `48415a313556414c` (`HAZ15VAL`) | empty |
| authority 3.6.4 | external | bad_type | `-1` | unchanged | 2 records; last `error:02000072:rsa routines::padding check failed` |
| authority 3.6.4 | external | short_ps | `-1` | unchanged | 2 records; last `...padding check failed` |
| authority 3.6.4 | external | out_of_range | `-1` | unchanged | 1 record; `error:02000084:rsa routines::data too large for modulus` |
| authority 3.6.4 | internal | valid | `8` | `HAZ15VAL` | empty |
| authority 3.6.4 | internal | bad_type | `244` | synthetic | empty |
| authority 3.6.4 | internal | short_ps | `107` | synthetic | empty |
| authority 3.6.4 | internal | out_of_range | `-1` | unchanged | 1 record; `data too large for modulus` |
| candidate before | external | valid | `8` | `HAZ15VAL` | empty |
| candidate before | external | bad_type | `-1` | unchanged | 2 records; last `...padding check failed` |
| candidate before | external | short_ps | `-1` | unchanged | 2 records; last `...padding check failed` |
| candidate before | external | out_of_range | `-1` | unchanged | 2 records; last `...padding check failed` |
| candidate before | internal | valid | `8` | `HAZ15VAL` | empty |
| candidate before | internal | bad_type | `244` | synthetic | empty |
| candidate before | internal | short_ps | `107` | synthetic | empty |
| candidate before | internal | out_of_range | `-1` | unchanged | 2 records; last `...padding check failed` |
| candidate after | external | valid | `8` | `HAZ15VAL` | empty |
| candidate after | external | bad_type | `238` | synthetic | empty |
| candidate after | external | short_ps | `8` | synthetic | empty |
| candidate after | external | out_of_range | `-1` | unchanged | 2 records; last `...padding check failed` |
| candidate after | internal | valid | `8` | `HAZ15VAL` | empty |
| candidate after | internal | bad_type | `244` | synthetic | empty |
| candidate after | internal | short_ps | `107` | synthetic | empty |
| candidate after | internal | out_of_range | `-1` | unchanged | 2 records; last `...padding check failed` |

Three facts follow directly:

- **The oracle is demonstrated before the correction.** On the external key, a
  valid block answers `8` with the message and no error; an invalid block
  answers `-1`, leaves the buffer untouched and leaves a padding-check error.
  The return sign, the buffer state and the error queue all distinguish the two.
- **The authority behaves identically on the padding cases.** Every authority
external-key `valid`/`bad_type`/`short_ps` row equals the pre-correction candidate
row, including the synthetic lengths on the internal key (`244` and `107`), so the
candidate was a faithful transcription and the padding defect is the authority's
too. The `out_of_range` error queue is the one exception and is recorded below.
- **The correction removes the distinction on the external key.** After the
  change, `valid`, `bad_type` and `short_ps` all answer a positive length, write
  the buffer and leave the error queue empty. The internal-key rows are
  byte-identical to the pre-correction run.

One **unrelated** authority difference was observed: for `out_of_range` the
authority leaves one record (`data too large for modulus`) and the candidate
leaves two, with `padding check failed` last. The authority's `goto err`
(`rsa_ossl.c:606-608`) skips the trailing padding raise; the candidate's `break`
does not. The difference predates this correction, is independent of padding
validity (the ciphertext value is public), and is not changed here. It is
recorded, not repaired.

## 5. Threat boundary

The oracle is reachable only when all of the following hold:

1. the application decrypts **attacker-chosen** ciphertexts;
2. the application exposes a **distinguishable** failure (error text, a
   different HTTP status, a timing class, a distinct log path);
3. the **key is externally held** (`RSA_FLAG_EXT_PKEY`), so the library has no
   private exponent.

OpenSSL-RS controls (3): the library no longer turns padding validity into a
distinguishable failure on that path. It does not control (1) or (2): an
application that never exposes the failure, or never accepts chosen ciphertexts,
has no oracle even under the authority. The XML-encryption/ROBOT class of attack
operates precisely at (1)+(2), and applications that report "decryption failed"
to the peer remain exposed unless they use OAEP or a uniform failure response.
The correction removes the library's contribution; it cannot remove an
application's.

## 6. Decision and correction (superseded in part by section 0)

Per `AGENTS.md` §17, a demonstrated known-vulnerability mechanism is eliminated,
not reproduced. The change in `src/rsa/ossl.rs`:

- the selector substitution is **removed**: an external key keeps
  `RSA_PKCS1_PADDING` and takes `ossl_rsa_padding_check_PKCS1_type_2`;
- `derive_kdk` runs only when `d` is present;
- when `d` is absent, `derive_external_kdk` computes SHA-256 over the decrypted
  block, which ~~is secret (the attacker cannot compute `c^d mod n`),~~
  deterministic for one ciphertext and different for a different ciphertext. The
  synthetic answer is therefore ~~unpredictable~~ and a repeated query of one
  ciphertext answers the same bytes; per-call randomness would itself be a
  distinguisher. **This justification is withdrawn by section 0:** the block is
  attacker-known for a constructed ciphertext, so the synthetic answer is
  attacker-computable. The KDK now comes from private key material or a per-key
  RNG secret, and the returned length remains a channel.
- the explicit `RSA_PKCS1_NO_IMPLICIT_REJECT_PADDING` selector still selects the
  refusing check, so the authority's behaviour remains available as an opt-in.

Preserved: the private-encrypt and public-decrypt signature paths, OAEP,
`RSA_NO_PADDING`, `RSA_FLAG_NO_BLINDING`, the length and range refusals, the
allocator seam, every exported signature and every `#[repr(C)]` layout.

The compatibility consequence is recorded in
`docs/SECURITY_DIVERGENCE_POLICY.md` as `D-RSA-EXTKEY-ORACLE-1`: an application
that relied on distinguishing an invalid external-key PKCS#1 v1.5 padding can no
longer do so, and must use OAEP, the explicit opt-out selector, or a uniform
failure response.

Tests:

- `rsa::ossl::tests::external_key_pkcs1_decryption_does_not_distinguish_padding`
  fails on the authority's behaviour and passes on the correction; it also
  pins determinism of the synthetic answer.
- `rsa::ossl::tests::internal_key_pkcs1_decryption_is_unchanged` pins the
  internal-key path's exact message bytes and its pre-existing implicit
  rejection.

## 7. Gates

Run in the court, one heavy command at a time, with `CARGO_BUILD_JOBS=4`.

```
$ cargo fmt --all -- --check
FMT_OK

$ cargo clippy --all-targets --offline -- -D warnings
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 17.77s
CLIPPY_OK

$ cargo test --lib --offline -- --test-threads=4
test result: ok. 2425 passed; 0 failed; 54 ignored; 0 measured; 0 filtered out; finished in 133.99s

$ cargo test --lib --offline
test result: ok. 2425 passed; 0 failed; 54 ignored; 0 measured; 0 filtered out; finished in 85.94s

$ python3 forensics/tools/etp_t1_seed.py
wrote /work/evidence/etp-t1/TRACEABILITY.json: 358 nodes, 469 edges, 39 orphans

$ python3 forensics/tools/traceability.py validate
traceability graph at 21bea318819a56f641b3aa2f25027216b97a1c4d: 358 nodes ... 469 edges ...
orphans: 39 declared and reproduced (39 ids), 0 undeclared, 0 stale

$ python3 forensics/tools/hazard_register.py validate
hazard register /work/evidence/etp-t2/HAZARDS.json: 20 hazards, 8 fault trees, 30 FMEA rows, 12 UCAs, 7 attack graphs
barrier states: BARRIER_ABSENT=3, CLAIMED_NO_EVIDENCE=16, EVIDENCED=1; FMEA evidence: CLAIMED_NO_EVIDENCE=22, EVIDENCED=1, NONE=7
register and traceability graph agree

$ python3 forensics/tools/tests/test_traceability.py
Ran 26 tests in 13.906s
OK

$ python3 forensics/tools/tests/test_hazard_register.py
Ran 23 tests in 0.874s
OK

$ python3 forensics/tools/divergence_obligations.py --check
ok: 10 row(s) match the table (0 blocking)

$ python3 forensics/tools/docs_consistency.py
ok: 20 hand-written claim(s) agree with their generated sources

$ python3 -m json.tool evidence/haz-15/observables.json
HAZ15_JSON_OK
$ python3 -m json.tool evidence/etp-t2/HAZARDS.json
JSON_OK
$ python3 -m json.tool evidence/etp-t1/TRACEABILITY.json
TRACE_JSON_OK
```

The baseline was 2423 passed / 0 failed / 54 ignored; the correction adds two
tests and no test is removed or newly ignored.

## 8. What remains unestablished

- **No timing measurement.** The rows are return value, output bytes and
  error-queue contents. A timing oracle is not excluded by this evidence.
- **The synthetic message's secrecy is an argument, not a proof.** ~~It rests on
  the decrypted block being secret and on SHA-256 being one-way.~~ Section 0
  withdraws that argument. The replacement rests on the CRT primes or a per-key
  RNG secret being secret and HMAC-SHA-256 being a PRF. No constant-time or
  leakage test was run on the new derivation.
- **The returned length is a channel.** The 64-block population in section 0
  separates the classes by length; no fixed-length mitigation was added to the
  generic check.
- **No independent adjudication.** The report and the correction share an
  author. `HAZ-15`'s register barrier is `CLAIMED_NO_EVIDENCE` after section 0
  (the length channel blocks an `EVIDENCED` barrier and the withdrawal blocks
  reliance on the original receipt); it is not `SAFETY_DISCHARGED`.
- **The public-only shape is a residual.** A key with no `d`, `p` or `q` gets a
  per-object RNG secret. Two objects built from the same public-only material
  therefore answer different synthetic messages for the same ciphertext; an
  application that reconstructs the key object per query loses the
  per-ciphertext determinism. That is recorded rather than hidden.
- **The external-key shape is a stand-in.** It uses the CRT parameters with `d`
  removed and the flag set, not a real `ENGINE`/neverbleed remote operation.
- **No consumer replay.** No TLS server or XML-encryption consumer was run
  against the corrected DSO, and no downstream population was measured.
- **The unrelated `out_of_range` error-queue difference is not repaired.**
- **The other padding selectors and the signature paths are not re-measured**;
  the change does not touch them, and the tests exercise PKCS#1 v1.5
  decryption only.

## 9. Reproduction

From the repository root, inside the court:

```sh
OPENSSL_RS_COURT_IMAGE=openssl-rs-court-tools:1 \
OPENSSL_RS_COURT_MEM=6g OPENSSL_RS_COURT_MEMSWAP=6g \
  bash docker/openssl-rs-court.sh exec \
    env CARGO_BUILD_JOBS=4 HAZ15_BUILD_DIR=/work/court/tmp/haz15-build \
    bash forensics/haz15/run_haz15.sh court/tmp/haz15/post

python3 forensics/haz15/drive.py \
  --pre court/tmp/haz15/pre --post court/tmp/haz15/post \
  --authority-dso forensics/authorities/prefix/openssl-3.6.4-production/lib/libcrypto.so.3 \
  --prefix-dso court/tmp/haz15-build-pre/candidate.so \
  --postfix-dso court/tmp/haz15-build-post.so \
  --head 478bf17ec1aa9022a784009a999a10e4eb4c07c4 \
  --out evidence/haz-15/observables.json
```

The pre-correction DSO is built from the exact HEAD source with
`git checkout HEAD -- src/rsa/ossl.rs` into a separate `HAZ15_BUILD_DIR`; the
build is deterministic (the re-run reproduced `c816b3d1...`).
