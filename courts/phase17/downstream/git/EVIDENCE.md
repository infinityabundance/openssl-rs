# Phase 17 downstream -- unmodified git against the candidate shell

Status: **build/link/start/functional all PROVEN** (PASS). This file is generated from `courts/phase17/downstream/git/result.json` by `forensics/tools/gen_downstream_evidence.py`; edit the record (or re-run the driver), never this file.

## Pinned upstream

- **git 2.56.0**, `https://mirrors.edge.kernel.org/pub/software/scm/git/git-2.56.0.tar.xz`
  sha256 `26c56c296b38c0695b26fa95f475f1d01704d2d38e73465ca30b0b2f5dc789d3` (parsed from `build.sh`).
- Candidate identity: `0.0.27` (the `RT-DOWNSTREAM-CORPUS` freshness key).
- Authority: `openssl-rt-3.6.4-r2`.

## Measured result

| field | result | detail |
|---|---|---|
| build | PASS | Git 2.56.0, SHA-1/SHA-256 via the candidate libcrypto |
| link | PASS | libcrypto.so.3 -> /work/artifacts/phase2/install/lib/libcrypto.so.3 |
| start | PASS | the candidate-linked git runs and hashes objects |
| functional | PASS | SHA-1/SHA-256 object hashing agrees with GNU coreutils; HTTPS push/clone/pull with both TLS endpoints on the candidate, unrelated CA rejected; bounded t/ subset green |
| concurrency | 16/16 | parallel operations completed |

Functional evidence (harness lines):

- `hash_check.sh: PASS`
- `HTTPS PUSH/PULL PASS`
- `concurrent_ok=16/16`

## Known residuals

- t5540-http-push-webdav is skipped: Git is built without expat (the court image ships no libexpat headers); it is a plain-HTTP path with no OpenSSL use

## Historical failures

| exposed at | defect | fixed by |
|---|---|---|
| `3e1c5313` | Git's HTTPS transport could not complete end to end because candidate-linked nginx (the test server) carried the five TLS defects above | 3e1c5313 (ssl: fix the nginx-exposed defects) |
| `bb5958a9` | the Git downstream had no reproducing harness: its own t/ subset and an HTTPS push/clone/pull were not yet exercised against the candidate | bb5958a9 (p17: the Git downstream passes its own tests and pushes/clones/pulls over HTTPS via the candidate) |

## How to reproduce

```sh
bash docker/openssl-rs-court.sh exec sh /work/courts/phase17/downstream/git/build.sh
bash docker/openssl-rs-court.sh exec sh /work/courts/phase17/downstream/run_all.sh
```

`run_all.sh` runs this program's harness, rewrites `result.json` from the transcript, re-aggregates `forensics/atlas/downstream-corpus.json` and regenerates this file.
