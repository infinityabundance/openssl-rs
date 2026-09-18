# PHASE 1 ARCHAEOLOGY SEAL

**Authority:** `openssl-3.6.4-production` (OpenSSL 3.6.4)
**Historical authority:** `openssl-3.6.3-historical` (OpenSSL 3.6.3)
**Build profile:** `linux-x86_64-default-shared-legacy-notests`
**Platform:** `linux-x86_64` (ELF)
**Scope:** archaeology only.

---

## 1. What this seal asserts

That the project has a **complete, content-addressed, reproducible picture of the
OpenSSL 3.6.4 contract surface** for the stated profile and platform, that the
movement from the historical authority has been *measured* rather than assumed,
and that every expected archaeology plane is either represented or explicitly
deferred.

## 2. What this seal does **not** assert

Nothing whatsoever about a candidate. In particular:

- **No compatibility claim of any kind.** No obligation is `PARITY_VERIFIED`.
  The 33,823 generated obligations are `DISCOVERED` or `ARCHAEOLOGICAL`.
- **No cryptographic-security claim.** Compatibility is not security, and no
  correctness vectors have been run.
- **Not FIPS validated.** See `docs/FIPS_CLAIMS.md`.
- **No claim beyond the stated authority, profile and platform.**

Phase 1 establishes *what must be proved*, and *what remains unknown*.

---

## 3. Admitted authorities

| id | role | version | archive sha256 | source tree root |
|---|---|---|---|---|
| `openssl-3.6.4-production` | production | 3.6.4 | `9bffaa1ad1e07b354c21bd3324ec02fa15579f45a7d0494b3e74bc449b7333ef` | `27d9917bd7c63d9bb056e674cc08c809b44cde50f9e474cd30041b8b66385432` |
| `openssl-3.6.3-historical` | historical | 3.6.3 | `243a86649cf6f23eeb6a2ff2456e09e5d77dd9018a54d3d96b0c6bdd6ba6c7f1` | `b996e7f0e239da1cafc8fd40c94e15032cc07dc5259303e0e5969e325b16d72d` |

Both archives were verified against their upstream-published digests; admission
fails closed (`forensics/tools/authority_acquire.py`).

## 4. The differential trajectory (measured, not asserted)

`forensics/atlas/differential/openssl-3.6.3-historical-vs-openssl-3.6.4-production.json`

| plane | movement |
|---|---|
| symbols (libcrypto + libssl) | **0** |
| declarations (functions, typedefs, structs, enums, variables) | **0** |
| ABI layout (sizeof/alignof/offsetof) | **0** |
| provider algorithms | **0** |
| CLI commands and options | **0** |
| macros | **2** |

The two added macros are `SSL_VALUE_QUIC_MAX_PENDING_CONNS` and
`X509_R_CRL_SIGNATURE_ALGORITHM_MISMATCH` — the latter consistent with the
3.6.4 CRL signature-algorithm security fix, and the reason
`docs/SECURITY_DIVERGENCE_POLICY.md` exists: the *behavioural* change has a
surface fingerprint, and a future divergence on that surface now has a known
explanation rather than being re-derived.

This independently corroborates the FRF oracle-vs-oracle courts, which observed
the same narrow movement *behaviourally* (version banner changed; digest,
disabled-feature set and cipher inventory unchanged).

## 5. Completeness

`forensics/atlas/phase1-completeness.json` — generated, and it fails if any
listed artefact is absent.

- **28** planes complete and content-addressed
- **0** missing
- **5** deliberately deferred, each naming its owning phase
- **2** residual classes dispositioned, each with its `why`
- **0** open unknowns

The five figures are `forensics/atlas/phase1-completeness.json`'s fields
(`complete_count`, `missing_count`, `deferred_count`, the length of
`residual_dispositions`, and `open_unknown_count`), not this seal's arithmetic:
the census grew with the atlas, so a numeral typed here in the 22/6/4 form went
stale while the file it summarised did not.

## 6. FRF evidence

`.frf/` (committed) plus portable bundles under `forensics/frf/bundles/`
(derived, reproducible, not duplicated in git).

| item | result |
|---|---|
| authorities admitted | `openssl-3.6.3`, `openssl-3.6.4` |
| courts | 4 trajectory courts (`version`, `dgst`, `list-disabled`, `list-cipher`) |
| receipts | 4 |
| sensitivity | `openssl-cli-dgst` **passed** both mutation operators |
| challenge refusals | 2 courts, disposed `harness` (see `docs/DECISIONS.md` D13) |
| disposition | 1 residual disposed `oracle_version` (version banner) |
| claims | 1 `baseline` (4 premises), 1 **`sensitivity-backed`** (dgst court) |
| evidence status | `graph_verified: yes`, `object_closure: complete`, `stream_closure: complete`, `replay_ready: yes` |
| replay | **reproduced** — sides byte-identical, `replay_verified: yes` |
| OpenReceipt bundles | `cli-dgst.frf` (130 files), `cli-version.frf` (66 files), verified |

The `sensitivity-backed` claim is the strongest claim the project currently
holds. It is deliberately restricted to the one court that can demonstrate it can
see its own declared defect classes.

## 7. Gemel

The native Gemel store is **not** Git-tracked. Gemel's own `.gemel/.gitignore`
contains `*` with explicit re-inclusions (`!.gitignore`, `!exchange/`,
`!exchange/**`), so what Git carries is:

- Gemel's Git-carried `exchange/` projection (the native sync namespace);
- the human-readable trajectory projection at `forensics/GEMEL_TRAJECTORY.md`;
- the change, trajectory and checkpoint identities recorded in
  `docs/DECISIONS.md` D17 and in this seal.

Recorded here rather than implied, because an earlier revision of this file
claimed `.gemel` was "committed", which is false; `docs/DECISIONS.md` D17
corrects it. This is the canonical wording:

> The native Gemel store is not Git-tracked. Gemel's Git-carried `exchange/`
> projection is tracked, along with the human-readable trajectory projection and
> the checkpoint identities.

- change `C1` — Phase 0 constitution and Phase 1 archaeology atlas
- change `C2` — Phase 1 foundation closure
- Gemel checkpoint at the Phase 1 → Phase 2 handoff
- open claims and open residuals carried forward

## 8. Open unknowns carried forward

Recorded rather than resolved. A seal that hides its unknowns is not a seal.

These four were the seal's carried unknowns. The generated census has since
dispositioned them: the first two are its two closed `residual_dispositions`
classes, the third was remedied by the fixture-driven `openssl-cli-inventory`
court (`forensics/frf/README.md` §"The courts"), and the fourth is the
`panic-payload-surfacing-at-ffi` plane deferred to Phase 3 and landed there
(`docs/DECISIONS.md` D16). The list is kept as the record of what was carried at
seal time, which is why the section is not retitled.

1. **11 symbols declared in public headers but absent from the ABI inventory.**
   Not defects, not yet explained; each needs a per-symbol disposition.
2. **26 exported symbols with no installed declaration** (the `DSO_*` family;
   `dso.h` is not installed). Whether the candidate must export them is an open
   contract question.
3. **FRF sensitivity coverage missing for the two non-fixture-driven courts**
   (D13). Remedy: make them fixture-driven. Blocks a sensitivity-backed claim for
   those courts; the baseline claim is unaffected.
4. **Panic payload not surfaced at the FFI boundary** (D16). Phase 3 surfaces the
   condition through the thread-local `ERR` queue.

## 9. Reproduction

```bash
# inside the court containers only; nothing executes on the host
bash docker/openssl-rs-court.sh exec bash forensics/tools/build_atlas.sh
bash docker/openssl-rs-court.sh exec python3 forensics/tools/atlas_receipt.py --verify
bash docker/openssl-rs-court.sh exec python3 forensics/tools/atlas_differential.py
bash docker/openssl-rs-court.sh exec python3 forensics/tools/atlas_phase1_completeness.py
bash docker/openssl-rs-frf-court.sh exec bash forensics/frf/run_courts.sh
```

## 10. Seal status

```
PHASE 1 ARCHAEOLOGY: SEALED
CANDIDATE PARITY:    NONE CLAIMED
OBLIGATIONS:         33,823 (0 PARITY_VERIFIED)
OPEN UNKNOWNS:       0
DISPOSITIONED:       2 residual classes
DEFERRED PLANES:     5
```

Issued under `docs/RELEASE_GATES.md` §2. Phase 2 (distribution / ABI shell) is
already under way; its exit rule is **not** yet satisfied, because FRF receipts
and a Gemel checkpoint for the ABI courts are still outstanding.
