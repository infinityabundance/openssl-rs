# openssl-rs — FRF integration

This directory holds the **declarations** for the FRF (Forensic Residual
Framework) courts: the authority/candidate reference wrappers and the court
manifests. The FRF **store** (`objects/`, `captures/`, `residuals/`,
`receipts/`, `claims/`) lives at `.frf/` in the repository root.

FRF is the authority of claims for this project. The chain is:

```
Authority -> Court -> Capture -> Residual -> Endoduction
          -> Route -> Disposition -> Receipt -> Claim
```

## Why these courts exist

`docs/SECURITY_DIVERGENCE_POLICY.md` §1 requires an **oracle-versus-oracle**
trajectory court *before* any candidate code is written. The 3.6.3 → 3.6.4
comparison teaches the system what legitimate upstream evolution looks like, so
that later effort is not spent reproducing a 3.6.3 quirk upstream itself removed.

In this project:

| role | authority |
|---|---|
| authority (the "before") | `openssl-3.6.3` (historical) |
| candidate (the "after") | OpenSSL 3.6.4 (production target) |

## Venue

Courts execute the authority binaries, so they must run inside a container —
never on the host. They run in the FRF tooling container:

```bash
bash docker/openssl-rs-frf-court.sh up
bash docker/openssl-rs-frf-court.sh exec bash forensics/frf/run_courts.sh
```

The tooling container is a *second*, separately-pinned container (Debian
trixie) because the FRF/Gemel binaries are built against glibc 2.39 while the
forensic court is pinned to bookworm/glibc 2.36. Changing the forensic court's
base would invalidate recorded evidence, so the venues are kept separate. See
`docker/openssl-rs-frf-court.sh` and `docs/REPRODUCIBILITY.md`.

## The reference wrappers

`refs/openssl-3.6.4.sh` and `refs/openssl-3.6.3.sh` are two-line wrappers that
bind `LD_LIBRARY_PATH` to the authority's own prefix and then `exec` the real
binary. They exist because running the installed binary without that binding
would silently resolve the **contaminating system OpenSSL**
(`docs/AUTHORITY_POLICY.md` §4.1), making the observation worthless. The real
dependencies are declared in each manifest's `execution_context`, so they are
snapshotted and content-addressed rather than hidden.

## The courts

| court | observable claim | expected |
|---|---|---|
| `openssl-cli-version` | `openssl version` stdout + exit | **diverges** (release identity) |
| `openssl-cli-dgst` | `openssl dgst -sha256 <fixture>` stdout + exit | agrees |
| `openssl-cli-inventory` | disabled-feature + cipher membership for a queried name list | agrees |

`openssl-cli-inventory` replaced `openssl-cli-list-disabled` and
`openssl-cli-list-cipher`, which were not fixture-driven and could not be
challenged (`docs/DECISIONS.md` D13). The observed surface is unchanged; only the
framing changed, so the sensitivity evidence became obtainable. The superseded
court directories are gone — they never held a manifest of their own after the
replacement, so nothing evidentiary was removed.

## Recorded Phase 1 result

Measured disposition of the 3.6.3 → 3.6.4 trajectory:

- **Version banner diverged** — `OpenSSL 3.6.3 9 Jun 2026` vs
  `OpenSSL 3.6.4 25 Aug 2026`. Disposed `oracle_version`: an intended upstream
  release-identity change, not a defect.
- **Digest, disabled-feature set and cipher inventory did not diverge** — which
  corroborates the atlas independently: the symbol inventories
  (`symbols-*.json`) and algorithm inventories (`provider-inventory.json`) are
  identical across the two authorities.

This is the useful kind of negative result: the trajectory is *narrow*, so any
later 3.6.3→3.6.4 divergence a consumer reports can be localised quickly.

The disposition and claim were performed with:

```bash
frf --root .frf residual dispose <residual-id> \
    --disposition oracle_version \
    --reason "OpenSSL version banner differs between the admitted historical \
authority 3.6.3 and the production target 3.6.4. This is an intended upstream \
release-identity change, not a candidate defect: it is the expected content of \
the oracle-version trajectory (docs/SECURITY_DIVERGENCE_POLICY.md, \
docs/DECISIONS.md D1). Retained as the baseline observation for the \
3.6.3 -> 3.6.4 movement."

frf --root .frf claim compile <version-receipt> <dgst-receipt> \
    <list-disabled-receipt> <list-cipher-receipt>
```

The compiled claim is honest about its own limits, and narrowed itself
automatically: because the version court's stdout residual was disposed as an
oracle-version trajectory, the claim covers only *exit class* for that court and
explicitly states that it "does not establish byte-identical stderr, full CLI
compatibility, or a drop-in replacement claim."

## Finishing a change: the controlled vocabularies

`gemel change finish` takes `--claim subject|predicate|kind`,
`--evidence subject|outcome|kind` and `--residual summary|severity|classification`, and
the last field of each is an **enum**, not free text. Gemel rejects a whole string there
with `invalid enum value`, which does not list what it wanted; the vocabularies below
were read out of the binary's own string tables
(`strings /usr/local/bin/gemel | grep -A2 ENUM_EVIDENCE_KIND`) and are recorded here so
the next change does not have to rediscover them.

| field | values |
|---|---|
| claim kind | `compatibility`, `correctness`, `performance`, `safety`, `invariant`, `other` |
| evidence kind | `court_receipt`, `oracle_comparison`, `runtime_trace`, `binary_comparison`, `test_result`, `compiler_result`, `fuzz_result`, `benchmark`, `static_analysis`, `formal_proof`, `replay`, `environment_manifest`, `artifact_hash`, `external_attestation` |
| evidence outcome | `pass`, `fail`, `inconclusive`, `unknown` |
| residual severity | `low`, `medium` |
| residual classification | `verification_gap`, `semantic_divergence`, `expected_mismatch`, `platform_divergence`, `performance_divergence`, `unexplained_divergence`, `contract_mismatch` |
| producer kind | `human`, `agent`, `automation`, `fuzzer`, `external_oracle`, `git_import` |

An evidence *outcome* is one word: `pass`, never `pass, 1306 observations`. The
measurement belongs in the summary, and putting it in the outcome is how the first
attempt at a change was rejected.

A second such rejection is the reason this paragraph exists. An earlier revision of the
table above listed `harness`, `reproduction` and `tool_identities` among the evidence
kinds, taken from the binary's own string blob rather than from an accepted invocation —
the blob holds them, but adjacent to this vocabulary rather than inside it. Gemel
refuses two of them in the `--evidence` kind position:

```
error: object error: invalid enum value "harness" for enum
error: object error: invalid enum value "reproduction" for enum
```

`tool_identities` was **not** measured — it is dropped from the row because it sits in the
same blob region as the two refusals, and a table that lists a value nobody has tried is
how this paragraph came to be written. The row above is the set that has either been
accepted in a committed change or read from the contiguous `ENUM_EVIDENCE_KIND` run in
the blob; nothing in it is guesswork. Anyone adding a kind should try it first, and a
refusal is a nine-word error rather than a lost change.

## Sensitivity (challenge) results

A court that cannot detect its own declared defect class may not supply release
evidence (`docs/PARITY_MODEL.md` §7). `frf court challenge` runs each court
against mutant candidates that alter exactly one observable dimension and
requires each mutation to be seen on its targeted axis **and on no other**.

| court | `stdout-first-line` | `exit-class` | consequence |
|---|---|---|---|
| `openssl-cli-dgst` | seen on stdout only | seen on exit only | **has** sensitivity evidence |
| `openssl-cli-inventory` | seen on stdout only | seen on exit only | **has** sensitivity evidence |
| `openssl-cli-version` | refused | refused | observations only |
| `openssl-rs-rt-*` (all 62 runtime courts) | seen on stdout only | seen on exit only | **have** sensitivity evidence |

The runtime count is 62 as of this revision: ten Phase 3 courts, seventeen Phase 4, nine
Phase 5, seven Phase 6, and nineteen Phase 7 (D200). The number is not asserted from
memory — it is the count of manifests `forensics/frf/courts/openssl-rs-rt-*` holds, which is also
what `forensics/frf/run_courts.sh` derives its court list from — so the *runner* cannot fall
behind a new court. This line can: it is prose rather than a projection, and it was wrong
before this revision (it said 25 while the store held 37, then 40 while it held 43). The
authoritative counts are `frf --root .frf evidence status` and `forensics/STATUS.md`; a
discrepancy here is a stale sentence, not a missing court.

### The cause of the refusals, and the remedy that was applied

The FRF 0.1.86 challenge mutant wrapper resolves the reference object by scanning
its own arguments for a path under the object store. That works only when the
court's declared arguments reference `{fixture}` — which is true for
`openssl-cli-dgst` and false for the old `list-*` courts. For those, the mutant
printed `FRF-MUTANT: cannot locate reference object …`, exited 2 with empty
stdout, and so perturbed **both** axes at once. FRF therefore refused, correctly,
and the four residuals this produced were disposed `harness` with that reason.

D13's concrete remedy — make every trajectory court fixture-driven — was applied
in Phase 3 by replacing the two `list-*` courts with `openssl-cli-inventory`,
whose fixture *is* the query list. That court now demonstrates axis isolation on
both axes. `docs/DECISIONS.md` D13 is retained as the record of the gap; the
remedy is superseding context, not a rewrite of it.

### `openssl-cli-version` remains uncovered

That court's mutants reproduce evidence that an existing run already holds, so
FRF refuses to re-capture and the challenge cannot be adjudicated. The court's
stdout still diverges by design (the release banner), so its axis cannot be
claimed anyway; its claim contribution is the **exit class** only, as the
Phase 1 prose already says.

### Why the obvious "fix" is refused

Declaring only `stdout` for an unchallengeable court would make the challenge
*pass* on a mutant that never ran the reference — a false sensitivity result. An
honestly refused court is strictly better than a falsely passing one. See
`docs/DECISIONS.md` D13.

### Effect on the compiled claim

The Phase 1 claim was compiled at `--policy baseline` (observation evidence
only). With the runtime courts, `openssl-cli-dgst` and `openssl-cli-inventory`
now both carry sensitivity evidence, and each was compiled at
`--policy sensitivity-backed` on its own — they bind different authority
references (`openssl-3.6.3` and `openssl-cli-3.6.3`), and a claim asserts parity
against one reference, so they cannot be premises of a single claim. The
`version`+`dgst` pair is compiled at `--policy baseline` because the version
court's axis is the release banner, which diverges by design.

## Phase 3 — runtime courts

The Phase 1 courts above compare two OpenSSL releases. The Phase 3 courts compare
the authority against **openssl-rs itself**, which is what makes them the first
courts in this repository that can bear a candidate claim.

| court | fixture family | subject |
|---|---|---|
| `openssl-rs-rt-mem` | `rt-mem` | allocation, sizing, cleansing, installable allocator |
| `openssl-rs-rt-exdata` | `rt-exdata` | `CRYPTO_*_ex_data` |
| `openssl-rs-rt-err` | `rt-err` | the thread-local error queue and its load-gated string tables |
| `openssl-rs-rt-stack` | `rt-stack` | `OPENSSL_sk_*` |
| `openssl-rs-rt-thread` | `rt-thread` | threads, atomics, thread-local storage |
| `openssl-rs-rt-secure` | `rt-secure` | the secure heap |
| `openssl-rs-rt-lhash` | `rt-lhash` | `OPENSSL_LH_*` |

Each court executes the same C probe source twice: once compiled against the
authority's headers and library, once against the candidate's. The probe prints
one `key=value` line per observation. The two binaries are staged by
`forensics/tools/phase3_courts.py` (this container has no compiler), and both
wrappers bind `LD_LIBRARY_PATH` for the probe invocation **only** — see below.

### The reference identity includes a harness revision

The runtime reference is admitted as `openssl-rt-3.6.4-r2`, not
`openssl-rt-3.6.4`. FRF refuses to run against an admitted reference whose file
has changed, and rightly so: the reference *is* the harness that produces the
observation. Revision `r1` compared only the first stdout line; `r2` makes the
first line a digest of the whole transcript, so the declared `stdout` axis covers
every observation rather than one of them. That is a change in the observation
method, hence a new reference identity, and the receipts from `r1` remain in the
store as the earlier method's record.

### The harness must not leak the library under test

`LD_LIBRARY_PATH` is applied per invocation, never exported. Debian's `sha256sum`
links `libcrypto.so.3`, so exporting the binding made the harness's own digest
tool load the candidate library: with the binding exported, `sha256sum` aborted
on the candidate's scaffolded `SHA256_Init`. That is a true statement about the
candidate — a real unmodified consumer really did stop working — but it is not a
statement this harness should be making about itself.

### Re-observing a rebuilt candidate

Run identities in FRF 0.1.86 do not vary with the hashes of the
`execution_context` artifacts. Measured: after rebuilding the candidate library
(which changed `artifacts/phase2/libcrypto.so.3`), every runtime court's run id
was unchanged, and FRF refused to re-capture — the stored captures still recorded
the previous library's hash. The declared `candidate.version_or_commit` is not
enough either, because it did not change.

The consequence is deliberate here: `run_courts.sh` **recreates the store from
clean**. Authority admission and run identities are content-addressed, so a fresh
store is the only way to take a fresh observation of a rebuilt candidate, and it
is what a release does. Evidence is therefore per-release and is never carried
forward between releases — which is what `docs/CUSTODIAN_CONTRACT.md` asks for
when it says a claim must not generalise across versions silently.

The recreation is a working-tree replacement, not a destruction of the record:
the previous release's tree is the previous commit. Anyone asking "what did the
store say before this release" reads it out of Git history, which is why the
store is committed at all.

### Sensitivity (challenge) results

Every runtime court is fixture-driven, so FRF's mutant wrapper can locate its reference
object and every challenge is adjudicated rather than refused. The full table is in the
court declarations and the `evidence status` output; the two courts this stratum rests on
are:

| court | `stdout-first-line` | `exit-class` |
|---|---|---|
| `openssl-rs-rt-bn` | seen on stdout only | seen on exit only |
| `openssl-rs-rt-asn1` | seen on stdout only | seen on exit only |

Both were re-taken at this release's store generation, so their identities in
`docs/PHASE-5-BN-ASN1-PEM-SEAL.md` §10 supersede the ones an earlier revision quoted.
The `local-*`/`list-*` trajectory courts are still refused rather than passed, because
FRF cannot isolate an axis on them (D13).

### Phase 3 claim

`forensics/frf/run_courts.sh` compiles the whole set. The Phase 3 runtime claim is

```
ffd0d7b3b15bf8fd97f70f023ace973577e4b79b723ce1fe23cfb2ef9a31d87d
```

from the seven runtime receipts, at `--policy sensitivity-backed`. The other
claims in the store are the Phase 2 ABI court
(`1d9f93df30b87fc87c2899abb74b014b5a9ccc21274b3af4ae8f865a8c04e4d7`), the two
Phase 1 trajectory courts compiled individually at `sensitivity-backed`
(`590ddff04c3480cd71b54487e9be9907f49912b0e2cc894056c82630a211f60e` for the
digest court and
`2be01424768b3a566baa7784fe25208948bb38acd73aff6bb9fc56a8a4543ac8` for the
inventory court), and the digest+version pair at `--policy baseline`
(`bdc8ab134293990afe9e4a002b0c0c95357e1add33fc2acc746d97f77ea10c3a`), because the
version court's axis is the release banner and diverges by design.

**Read the scope literally.** FRF extracts the `stdout` observable as
`stdout-first-line`, so the claim says "preserves `<family>` first stdout line and
`<family>` exit class". Because the first line of each transcript is a digest of
every line that follows it — see the harness note above — that is a statement
about the whole transcript. The claim's wording does not say so, which is why the
mapping is recorded here. The *atlas* court
(`artifacts/phase3/COURTS.json`) independently compares the transcripts line by
line with no digest involved, and the two agree.

The claim also does not cover `stderr` (both sides write none), and does not
extend beyond the fixtures, the platform, or the observations the probes make.

### A consumer observation, incidentally recorded

Running the candidate wrapper with `LD_LIBRARY_PATH` exported made Debian's
`sha256sum` fail against openssl-rs, because `sha256sum` links `libcrypto.so.3`
and calls `SHA256_Init`, which is still `SCAFFOLDED`. That is a genuine
Phase 17 signal — a real, unmodified downstream consumer — arriving early. It is
recorded here because it was observed, not because SHA-2 is in scope: Phase 8
owns the digest algorithms.

## Phase 7 — the EVP strata

The Phase 7 runtime courts (D200) are the first ones whose subject is `evp.h`'s object families
rather than a runtime substrate: the fetch core and the method store, the `EVP_MD`/`EVP_CIPHER`/
`EVP_MAC`/`EVP_KDF`/`EVP_RAND`/`EVP_SKEY`/`EVP_KEYMGMT` method objects and their contexts, the
`EVP_PKEY` layer, the PBE registry, the encode and PEM bridges, the legacy `HMAC`/`CMAC`/HPKE
headers, and the three D199 coverage courts (`RT-EVP-REF`, `RT-EVP-INTROSPECT`, `RT-EVP-CLASS`,
`RT-EVP-PKEY-OPS`) that reference or call the exports no behavioural probe reached. They are
declared the same way as the Phase 3–6 courts — nineteen rows in `gen_frf_courts.py`'s `COURTS`
table, whose one-line subject is each probe header's own opening line — and their declarations are
`forensics/frf/courts/openssl-rs-rt-{fetch,evp-*,hmac,cmac,hpke}`.

Their chain is complete and lives in `.frf/`: nineteen receipts (zero residuals each), thirty-eight
challenge records (both declared axes on every court, all adjudicated), and the claim compiled from
the nineteen receipts at `--policy sensitivity-backed`, whose id and per-court receipt ids are cited
in `docs/PHASE-7-EVP-SEAL.md` §8 and D200. The claim's scope is the runtime courts' usual narrow
one — it preserves each fixture family's first stdout line and exit class — and is subject to the
same harness note above about the first line being a digest of the whole transcript.

## Not yet represented

These courts exercise the CLI surface, the Phase 3 runtime substrate and the Phase 7 `EVP_*` object
families. They do **not** yet constitute a claim about `libcrypto`/`libssl` ABI or semantics beyond
the runtime families listed above — that requires the later strata, and Phase 3
expressly excludes cryptographic behaviour. The `.num`/version-script/DSO
reconciliation in `forensics/atlas/*/symbols-*.json` is the corresponding *atlas*
evidence, and `forensics/frf/courts/openssl-abi-surface` is its FRF counterpart.
