# Span-hash migration summary (b51b, reject-fixed)

- Migration candidate: `b51b`, verified source commit
  `cb9c4c64c4749b796603cddf0736049d37ea12b0` (`git rev-parse` verified).
- Full per-site record: `forensics/memory-safety/campaign/safe-c33/atlas-refresh/span-hash-migration.json`
  (sha256 `a7a1b27ede19678886bc897bcd7bbdc4988d138b2c93160ea1282ffe0e0a05db`,
  166 sites, 52 candidate blobs).
- Tool under test: `forensics/tools/consumer_closure.py`
  (sha256 `8284292d5a2bc13b2b779a9d3201ad8951ac46df472cd3e22b40c07fedd5e050`).
- Pre-change tool: literal `git show HEAD:forensics/tools/consumer_closure.py`
  (sha256 `22364c5b62ce35ab791c3a708b7479a1477272ea3fa3ffcadc5208c8b8321145`).
- Baseline closure: `court/tmp/span-hash-migration/closure-ssh-b51b-old-bodyfix.json`.
- Fixed closure: `court/tmp/span-hash-migration/closure-ssh-b51b-finalAB.json`.

## Acceptance predicate (fixed)

```
identity_match on the fully-qualified operation
AND the obligation is bound to the boundary's resolved span:
      obligation's qualified operation == boundary's qualified operation
   OR obligation's current census line lies inside [span.start, span.end]
AND recorded span_sha256 is present
AND recorded span_sha256 == current span sha256
```

A same-file sibling with the same last component is refused
(`ambiguous-identity`) when it resolves to a different definition. The
coordinate alone never accepts a site. For the 98/166 baseline obligations whose
`current_census_line` was unset, the binding used the obligation's retained
enumeration coordinate (the OLD tool's documented fallback); the map records
both fields per site.

## Hash binding (git blobs, not the worktree)

Every `span_sha256` is sha256 over the normalised span text read from
`git show <migration_candidate>:<file>`. The map records the 52 per-file
candidate blobs under `candidate_blobs` (each with `git_blob_sha1`,
`content_sha256`, and the exact `git show` source); a site is bound to
`candidate_blobs[site.file]`. The live worktree was not used for migration
hashes. The fixed closure also reads
`source_commit = inventory.identity.source_head` (`cb9c4c64…`) for span
hashing, so the comparison is candidate-blob-to-candidate-blob.

If `identity.source_head` is absent or unresolvable, `span_source_commit`
returns None and every content-addressed disposition is refused as
**`span-unbound`**; the worktree is not read. The only worktree path is the
explicit test-only `allow_worktree_span` opt-in, used by the control harness
and never set by a real closure run.

## Measured before/after (same inputs)

| quantity | old tool | fixed tool |
|---|---|---|
| DISCHARGED | 166 | 166 |
| BLOCKED | 146 | 146 |
| UNKNOWN | 0 | 0 |
| `stale_discharge_rejections` | 0 | 0 |
| discharged stable-ID set | 166 | 166, difference 0 |
| boundary attribution differences | — | **0** |
| discharge-receipt attribution differences | — | **0** |

The previously observed 24/166 attribution differences (e.g.
`src/provider/digest.rs:959`, old `OSSH-V1I-007` → new `OSSH-V1I-001`) no longer
occur: the fixed predicate binds the obligation to its own definition, so
`sha1::dupctx` cannot discharge `nullmd::dupctx`. The 24 sites remain
discharged by their original boundaries.

## Corrected record claim

The earlier summary asserted attribution equality without measuring the
boundary/site attribution. That claim was false. This record states the
measured result above: boundary attribution differences **0**, receipt
attribution differences **0**. `B49-I2R-009` (`src/x509/v3_ist.rs`,
`i2r_issuer_sign_tool`) remains `BLOCKED`.

## Span-parser cases (fixed; fixture-observed)

- **Bodyless trait method:** `_span_body_open` returns None at the first
  top-level `;`; the candidate is marked `has_body=False` and `_span_result`
  raises `span-unparsable`. Fixture
  `trait T { fn f(&self); } fn g() -> u8 { 7 }` → control `bodyless` observed
  `span-unparsable`; it never extends to `g`'s `{`.
- **Const-generic truncation:** `_span_body_open` ignores `{` while `(`/`[`
  depth is positive; the body is the first `{` at depth 0. Fixture
  `unsafe fn constgen<const N: usize>() -> [u8; {N}] { let _ = 1; 0 }` → span
  lines 1-4; editing the body → `span-hash-mismatch` (control `constgen`).
- **`<{` signature expression:** `_span_body_open` refuses with
  `span-unparsable` when it sees `<` immediately followed by `{` before the
  body brace (angle brackets are not depth-tracked). Fixture
  `unsafe fn angle<const N: usize>() -> W<{N}> { ... }` → control `anglebrace`
  observed `span-unparsable`.
- **No bound source:** missing/unresolvable `identity.source_head` →
  `span-unbound` (control `unbound`); no worktree read on the production path.
- **Residual ambiguity:** an unbalanced/missing body → `span-unparsable`; an
  unresolved collision → `ambiguous-identity`. No unparsable path accepts.
- Self-consistency: migration and runtime use the same span/masking rule and
  the same candidate blob, so the 166 recorded hashes reproduce exactly.

## Commands

```sh
git show HEAD:forensics/tools/consumer_closure.py > court/tmp/span-hash-migration/consumer_closure_old.py
OPENSSL_RS_COURT_DATA=6291456 bash docker/openssl-rs-court.sh exec sh -c \
  'cd /work && python3 court/tmp/span-hash-migration/consumer_closure_old.py --repo /work \
   --family openssh --artifact court/tmp/openssh-closure/client-b51b/openssh-9.9p1/ssh \
   --install artifacts/phase2/install --inventory court/freeze-b51b/census-b51b.json \
   --workdir court/tmp/span-hash-migration/work-old-bodyfix \
   --output court/tmp/span-hash-migration/closure-ssh-b51b-old-bodyfix.json --summary'

python3 forensics/tools/span_hash_migration.py \
  --baseline-closure court/tmp/span-hash-migration/closure-ssh-b51b-old-bodyfix.json \
  --migration-candidate cb9c4c64c4749b796603cddf0736049d37ea12b0 --candidate-tag b51b \
  --out forensics/memory-safety/campaign/safe-c33/atlas-refresh/span-hash-migration.json

OPENSSL_RS_COURT_DATA=6291456 bash docker/openssl-rs-court.sh exec sh -c \
  'cd /work && python3 forensics/tools/consumer_closure.py --family openssh \
   --artifact court/tmp/openssh-closure/client-b51b/openssh-9.9p1/ssh \
   --install artifacts/phase2/install --inventory court/freeze-b51b/census-b51b.json \
   --workdir court/tmp/span-hash-migration/work-finalAB \
   --output court/tmp/span-hash-migration/closure-ssh-b51b-finalAB.json --summary'
```

Execution note: the launcher's default 4 GiB `RLIMIT_DATA` raised `MemoryError`;
runs used the supported `OPENSSL_RS_COURT_DATA=6291456` override, one at a time,
with host `available` ≥ 85 GB. No `docker/` file was edited.
