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
| `openssl-cli-list-disabled` | `openssl list -disabled` stdout + exit | agrees |
| `openssl-cli-list-cipher` | `openssl list -cipher-algorithms -1` stdout + exit | agrees |

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

## Sensitivity (challenge) results

A court that cannot detect its own declared defect class may not supply release
evidence (`docs/PARITY_MODEL.md` §7). `frf court challenge` runs each court
against mutant candidates that alter exactly one observable dimension and
requires each mutation to be seen on its targeted axis **and on no other**.

| court | `stdout-first-line` | `exit-class` | consequence |
|---|---|---|---|
| `openssl-cli-dgst` | seen on stdout only | seen on exit only | **has** sensitivity evidence |
| `openssl-cli-list-disabled` | refused (also diverged on exit) | refused (also diverged on stdout) | observations only |
| `openssl-cli-list-cipher` | refused (same cause) | refused (same cause) | observations only |

### The cause, established by inspection

The FRF 0.1.86 challenge mutant wrapper resolves the reference object by scanning
its own arguments for a path under the object store. That works only when the
court's declared arguments reference `{fixture}` — which is true for
`openssl-cli-dgst` (the fixture is the hashed input) and false for the two
`list-*` courts (they take no input file). For those courts the mutant prints
`FRF-MUTANT: cannot locate reference object …`, exits 2 with empty stdout, and so
perturbs **both** axes at once. FRF therefore refuses, correctly.

The four residuals this produced are disposed `harness`, with that reason.

### Why the obvious "fix" is refused

Declaring only `stdout` for those courts would make the challenge *pass* on a
mutant that never ran the reference — a false sensitivity result. An honestly
refused court is strictly better than a falsely passing one. See
`docs/DECISIONS.md` D13.

### Effect on the compiled claim

The Phase 1 claim was compiled at `--policy baseline` (observation evidence
only), which does not require challenge coverage, and it re-verifies after the
harness dispositions. A stronger `--policy sensitivity-backed` claim is **not**
available until every claimed axis has demonstrated coverage — so the `list-*`
courts currently block it.

The concrete remedy is to make every trajectory court fixture-driven. That is
also better forensic practice: a court should be a statement about a *fixture
family*, not about an argument list.

## Not yet represented

These courts exercise the CLI surface. They do **not** yet constitute a claim
about `libcrypto`/`libssl` ABI or semantics — that requires a candidate, and
Phase 1 has none. The `.num`/version-script/DSO reconciliation in
`forensics/atlas/*/symbols-*.json` is the corresponding *atlas* evidence, not an
FRF claim.
