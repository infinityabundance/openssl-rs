# Survivable key compromise: rotation, delegation, expiry, revocation, anti-rollback and anti-freeze

This is the normative document for A18. The implementation is
`forensics/tools/key_lifecycle.py`; the controls are
`forensics/tools/tests/test_key_lifecycle.py`; the records are `evidence/a18/`,
produced deterministically by `evidence/a18/build_evidence.py`.

## 1. The problem: a signature is not survivable by itself

A signature says that whoever holds a key approved some bytes. It does not say
what happens when that key is stolen, retired or replaced. Without a second
root, a metadata version, an expiry, a revocation record or a delegation, a
release signed before a compromise and a release signed after it are the same
shape of object, and nothing inside the evidence distinguishes them.

The survival properties are therefore not decorations on a signature scheme;
they are what makes a compromise *detectable* and *recoverable*. The rule this
item implements is:

> An old signature never authorises a stale release.

## 2. The metadata model

A repository is one object with four metadata records and two optional lists:

```
{metadata: {root, targets, snapshot, timestamp},
 delegations: [...], releases: [...], maxTimestampInterval: seconds}
```

Every metadata record is:

```
{role, version, expires, threshold, keys: [{keyid, role, notBefore, notAfter, revokedAt}],
 signatures: [{keyid, sig}], ...role-specific fields}
```

`threshold` is optional and defaults to 1. `snapshot` carries
`targets: {version, sha256}`; `timestamp` carries `snapshot: {version, sha256}`
and `issuedAt`. `targets` carries `delegations: [{name, sha256}]`. A delegation
record has the same shape with `role: delegation` and a `name`.

**The signature model is structural, not cryptographic.** A signature is
`"sha256:" + SHA-256(canonical signed body || 0x00 || keyid)`. It catches a
signature that was not produced over the bytes under test
(`TK_REFUSED_SIGNATURE`), and it lets the controls demonstrate a revoked key
whose signature verifies. It has no secret, anyone can compute it, and it
establishes no authenticity. Real signature verification is `NOT_RUN`.

## 3. The four roles and the delegation

| role | what it carries | what it authorises |
|---|---|---|
| `root` | the role keys and the root keys | its own rotation and the keys of the other roles |
| `targets` | the target names and the delegation declarations | which targets and delegated roles exist |
| `snapshot` | `targets: {version, sha256}` | exactly one targets metadata version |
| `timestamp` | `snapshot: {version, sha256}`, `issuedAt` | freshness of exactly one snapshot |
| `delegation` | its own keys, targets and expiry | the delegated targets declared by `targets` |

The root is the anchor: a role key is admitted only when the root lists that
keyid with that role. A delegation is different: the parent `targets` binds the
whole delegation record by digest, so the record's own keys are authoritative
for that delegated role.

## 4. The evaluation order

`evaluate(repository, now, previous)` applies the rules in this order, and
refuses with the first code that fires:

1. the repository is structurally valid (`TK_REFUSED_REPOSITORY_INVALID`);
2. root version, expiry, signatures and both thresholds;
3. targets version, expiry, declared keys and signatures;
4. snapshot version, expiry, declared keys and signatures;
5. timestamp version, expiry, declared keys and signatures;
6. the delegation set;
7. the release set;
8. the hash chain (`targets` → `snapshot` → `timestamp`) and the freeze check.

The hash chain is last because it compares records that must each be valid
first. `previous` is the last accepted metadata set, or `None` for an initial
root. No clock is read: `now` is supplied.

## 5. Anti-rollback

The root must be **version-greater** than the accepted root. An equal version is
not a rotation; it is a rollback (`TK_REFUSED_ROOT_ROLLBACK`; enforced by the
`root-rollback` control and `test_root_rollback`).

`targets`, `snapshot` and `timestamp` must be **greater than or equal to** the
accepted version. Equal is a refresh; strictly lower is a rollback:

* `TK_REFUSED_TARGETS_ROLLBACK` — enforced by `targets-rollback` and
  `test_each_rollback_role_individually`;
* `TK_REFUSED_SNAPSHOT_ROLLBACK` — enforced by `snapshot-rollback` and
  `test_each_rollback_role_individually`;
* `TK_REFUSED_TIMESTAMP_ROLLBACK` — enforced by `timestamp-rollback` and
  `test_each_rollback_role_individually`.

## 6. Anti-freeze

Expiry is necessary but not sufficient. An attacker who controls the repository
can stop updating it and serve a valid, unexpired timestamp forever. The
repository therefore declares `maxTimestampInterval` (seconds), and:

> freeze iff `now - timestamp.issuedAt > maxTimestampInterval`.

Exactly at the interval is still fresh; one unit past it is a freeze
(`TK_REFUSED_FREEZE`; enforced by the `freeze` control,
`test_freeze_exactly_at_the_interval_is_accepted` and
`test_freeze_one_unit_past_the_interval_is_refused`).

Metadata whose `expires` is not after `now` is refused
(`TK_REFUSED_EXPIRED_METADATA`; enforced by `expired-metadata` and
`test_expired_metadata`). Expiry and freeze are different: expiry stops
correctly-signed old metadata; freeze stops a *fresh-looking* metadata set that
is never refreshed.

## 7. The rotation rule

A new root must be version-greater and signed by **a threshold of both the old
and the new root keys**:

* if the new root's threshold is not met, `TK_REFUSED_METADATA_THRESHOLD`;
* if the old root's threshold is not met, the rotation is signed only by the new
  side and is refused (`TK_REFUSED_ROOT_ROTATION_UNSIGNED_BY_OLD`; enforced by
  the `rotation-unsigned-by-old` control and
  `test_rotation_signed_by_new_root_only_is_refused`).

The point is that the old root authorises its own replacement. A party holding
only the new key cannot replace the root; that is what makes rotation a recovery
mechanism rather than a second compromise.

## 8. The revocation rule

A key is refused when it is outside its validity window or revoked:

* `TK_REFUSED_KEY_EXPIRED` — `notAfter` is at or before `now`;
* `TK_REFUSED_KEY_NOT_YET_VALID` — `notBefore` is after `now`;
* `TK_REFUSED_KEY_REVOKED` — `revokedAt` is at or before `now`.

**A signature by a revoked key is refused even when it verifies.** Revocation is
a decision about the key, not about the bytes.
Enforced by `TK_REFUSED_KEY_REVOKED` through `key-revoked-verifying-signature`
and `test_revoked_key_with_a_verifying_signature`; `key-expired` and
`test_expired_key` cover expiry, `key-not-yet-valid` and
`test_key_not_yet_valid` cover the other edge.

A keyid no metadata declares is `TK_REFUSED_UNKNOWN_KEY` (enforced by
`unknown-key` and `test_unknown_key`). A key the root binds to another role is
`TK_REFUSED_ROLE_KEY_MISMATCH` (enforced by `role-key-mismatch` and
`test_role_key_mismatch`). One key counted once cannot meet a threshold of two
(`TK_REFUSED_METADATA_THRESHOLD`; enforced by `metadata-threshold` and
`test_metadata_threshold`).

## 9. The stale-release rule

A release record is `{id, version, time, keyid}` and is bound to the targets
metadata version it describes. It is refused as
`TK_REFUSED_STALE_RELEASE` when either:

* the accepted targets version is higher than the release's version; or
* the signing key was revoked at or before the release's recorded time.

Enforced by `TK_REFUSED_STALE_RELEASE` through the `stale-release-version` and
`stale-release-revoked-key` controls and `test_stale_release_by_version` /
`test_stale_release_by_revoked_key`.

The second clause is the rule in its sharpest form. A key can have produced a
perfectly valid signature and still not authorise the release, because the key
was already revoked when the release claims to have been made. A key revoked
*after* a release does not retroactively invalidate that release; the revision
time is what matters.

## 10. The hash chain

`snapshot` must name the `targets` version **and** digest, and `timestamp` must
name the `snapshot` version **and** digest. A reference to a different version or
different bytes is refused:

* `TK_REFUSED_TARGETS_HASH_MISMATCH` — the snapshot vouches for different
  targets; enforced by `targets-hash-mismatch` and
  `test_targets_hash_mismatch`;
* `TK_REFUSED_SNAPSHOT_HASH_MISMATCH` — the timestamp vouches for a different
  snapshot; enforced by `snapshot-hash-mismatch` and
  `test_snapshot_hash_mismatch`.

The digest is over the whole metadata record, signatures included. Roles are
names; the chain is what binds a name to bytes.

## 11. Delegation

Targets declares each delegated role as `{name, sha256}`. The supplied
delegation record must exist, hash to that digest, and be unexpired:

* a declaration with no record, or a record with no declaration, is
  `TK_REFUSED_DELEGATION_UNKNOWN` (enforced by `delegation-unknown` and
  `test_delegation_unknown`);
* a mismatch between the declared digest and the record is
  `TK_REFUSED_DELEGATION_HASH_MISMATCH` (enforced by
  `delegation-hash-mismatch` and `test_delegation_hash_mismatch`);
* an expired record is `TK_REFUSED_DELEGATION_EXPIRED` even when its hash binds
  (enforced by `delegation-expired` and `test_delegation_expired`).

## 12. The real inventory and the honest finding

`evidence/a18/INVENTORY.json` records the measured state:

* **one key**, `test-only:hmac-sha256:8e10a5a15d233d54`, `symmetric: true`,
  derived from a fixed public seed, with **no expiry**, **no revocation
  record**, **no metadata version** and **no delegation**;
* **0 repositories**, 0 metadata versions, 0 revocation records, 0 expiry
  records and 0 delegations.

The finding is not that the key is weak. It is that the key is a **single point
of compromise**: there is no second root to rotate to, no revocation list to
consult and no metadata version to distinguish a pre-compromise signature from a
post-compromise one. A bundle or envelope signed before a hypothetical
compromise is indistinguishable from one signed after it. Compromise of the one
key cannot be detected or recovered from within the evidence.

`evidence/a18/EVALUATION.json` evaluates every role against the absent
repository. Every role is `NOT_RUN` with `TK_NOT_RUN`, and the stale-release
check is `NOT_RUN` for the same reason. **0 repositories and nothing accepted**
(`test_absent_repository_is_not_run`). A repository that does not exist is never
`ACCEPTED`.

## 13. The controls and what the positive establishes

`evidence/a18/CONTROLS.json` holds **22** `control-only` controls over the **21**
refusal codes: one per code, a second direction for stale release
(`stale-release-revoked-key`), and one positive control. Every control is a
synthetic repository built in memory by the producer; a control that fires
proves the refusal works and is not a defect report.

The named controls required by the item are present:

| required control | id | code |
|---|---|---|
| root rotation signed only by the new root | `rotation-unsigned-by-old` | `TK_REFUSED_ROOT_ROTATION_UNSIGNED_BY_OLD` |
| targets version decrease | `targets-rollback` | `TK_REFUSED_TARGETS_ROLLBACK` |
| snapshot hash mismatch | `snapshot-hash-mismatch` | `TK_REFUSED_SNAPSHOT_HASH_MISMATCH` |
| expired timestamp | `expired-metadata` | `TK_REFUSED_EXPIRED_METADATA` |
| timestamp frozen past the interval | `freeze` | `TK_REFUSED_FREEZE` |
| signature by a revoked key that verifies | `key-revoked-verifying-signature` | `TK_REFUSED_KEY_REVOKED` |
| expired delegation | `delegation-expired` | `TK_REFUSED_DELEGATION_EXPIRED` |
| release behind the accepted version | `stale-release-version` | `TK_REFUSED_STALE_RELEASE` |

The positive control (`positive-accepted`) is a version-incremented root
rotation signed by both the old and the new root keys, with threshold-two
signing, a hash-bound unexpired delegation and unexpired metadata. It reaches
`ACCEPTED`.

What the positive control **establishes**: the decision procedure can accept a
consistent, monotonic, threshold-signed, hash-bound repository, so the refusals
are not vacuous. What it **does not establish**: that any such repository exists,
that its keys are honestly held, that a ceremony happened, or that an accepted
release is safe or authentic. It is a control, not a repository.

## 14. Refusal table

Every code is stable. The final column names the control and the test that fire
it.

| code | wrong conclusion it prevents | enforced by |
|---|---|---|
| `TK_REFUSED_REPOSITORY_INVALID` | a malformed metadata set read as a checked repository | `repository-invalid`; `test_repository_invalid` |
| `TK_REFUSED_ROOT_ROLLBACK` | restoring an old root and its old keys | `root-rollback`; `test_root_rollback` |
| `TK_REFUSED_ROOT_ROTATION_UNSIGNED_BY_OLD` | the new key replacing the root without the old root | `rotation-unsigned-by-old`; `test_rotation_signed_by_new_root_only_is_refused` |
| `TK_REFUSED_TARGETS_ROLLBACK` | an old targets set served as current | `targets-rollback`; `test_each_rollback_role_individually` |
| `TK_REFUSED_SNAPSHOT_ROLLBACK` | an old snapshot alongside newer targets | `snapshot-rollback`; `test_each_rollback_role_individually` |
| `TK_REFUSED_TIMESTAMP_ROLLBACK` | replaying an old timestamp as fresh | `timestamp-rollback`; `test_each_rollback_role_individually` |
| `TK_REFUSED_SNAPSHOT_HASH_MISMATCH` | a timestamp vouching for a different snapshot | `snapshot-hash-mismatch`; `test_snapshot_hash_mismatch` |
| `TK_REFUSED_TARGETS_HASH_MISMATCH` | a snapshot vouching for different targets | `targets-hash-mismatch`; `test_targets_hash_mismatch` |
| `TK_REFUSED_EXPIRED_METADATA` | expired metadata read as current | `expired-metadata`; `test_expired_metadata` |
| `TK_REFUSED_FREEZE` | a valid timestamp served forever without refresh | `freeze`; `test_freeze_one_unit_past_the_interval_is_refused` |
| `TK_REFUSED_KEY_EXPIRED` | a key past its window accepted because it verifies | `key-expired`; `test_expired_key` |
| `TK_REFUSED_KEY_NOT_YET_VALID` | a future key used before its rotation | `key-not-yet-valid`; `test_key_not_yet_valid` |
| `TK_REFUSED_KEY_REVOKED` | a revoked key's valid signature accepted | `key-revoked-verifying-signature`; `test_revoked_key_with_a_verifying_signature` |
| `TK_REFUSED_UNKNOWN_KEY` | an invented keyid supplying a signature | `unknown-key`; `test_unknown_key` |
| `TK_REFUSED_ROLE_KEY_MISMATCH` | one key acting outside its role | `role-key-mismatch`; `test_role_key_mismatch` |
| `TK_REFUSED_METADATA_THRESHOLD` | one key counted twice toward a threshold | `metadata-threshold`; `test_metadata_threshold` |
| `TK_REFUSED_DELEGATION_UNKNOWN` | an undeclared or absent delegated role | `delegation-unknown`; `test_delegation_unknown` |
| `TK_REFUSED_DELEGATION_EXPIRED` | an expired delegated role still authorising | `delegation-expired`; `test_delegation_expired` |
| `TK_REFUSED_DELEGATION_HASH_MISMATCH` | a delegation swapped while keeping its name | `delegation-hash-mismatch`; `test_delegation_hash_mismatch` |
| `TK_REFUSED_STALE_RELEASE` | an old signature authorising a stale release | `stale-release-version`, `stale-release-revoked-key`; `test_stale_release_by_version` |
| `TK_REFUSED_SIGNATURE` | a signature over different bytes counted | `signature`; `test_signature_not_over_the_bytes` |

## 15. Non-claims

* **An accepted repository is not a trusted key ceremony.** Acceptance means the
  supplied metadata is monotonic, unexpired, threshold-signed, hash-bound and
  not stale. It does not mean the keys were generated, distributed or held
  honestly. **No ceremony exists here.**
* **The signature model is not cryptography.** It is a deterministic digest
  used to demonstrate the decision procedure; it has no secret and no
  authenticity. Real verification is `NOT_RUN`.
* **A repository is not a release.** The release check binds a recorded release
  to an accepted metadata version; it does not sign, publish or verify the
  release artefact.
* **The times are declared.** `now` is supplied, never read. A producer that
  misstates its own time is outside this mechanism.
* **An accepted control is not an accepted repository.** Every control
  repository is synthetic and `control-only`.
* **The refusal table is not a threat model.** It names the conclusions the
  rules prevent; it does not enumerate every attack on a key or a repository.
* This is evidence bookkeeping, not a safety, compatibility, cryptographic or
  build result.

## `NOT_RUN`

* Any real repository, root, targets, snapshot or timestamp metadata set: there
  are 0 repositories.
* A root rotation, a delegation, an expiry record or a revocation record on real
  data: none exists.
* A real accepted release and any stale-release decision on real data: `NOT_RUN`.
* Real signature verification, a production key, a key ceremony, key
  distribution and revocation propagation: none exists.
* A second root or any external trust root: the only key is A10's test-only
  symmetric key.
* A wall-clock, RFC 3161 or transparency-log timestamp for any evaluation: no
  timestamp authority and no log are configured.
* An independent review, a BOUNDARY audit, a SEAL and the Rust suite: `src/`
  was not modified, so no rebuild and no `cargo test` is claimed.
