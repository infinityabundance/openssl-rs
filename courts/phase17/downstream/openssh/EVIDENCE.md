# Phase 17 downstream -- unmodified openssh against the candidate shell

Status: **build/link/start/functional all PROVEN** (PASS). This file is generated from `courts/phase17/downstream/openssh/result.json` by `forensics/tools/gen_downstream_evidence.py`; edit the record (or re-run the driver), never this file.

## Pinned upstream

- **openssh 10.5p1**, `https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-10.5p1.tar.gz`
  sha256 `d44d28a839ea9daf969cc69150fde59910b2b39361dad81a3bd6cbd19218db11` (parsed from `build.sh`).
- Candidate identity: `0.0.24` (the `RT-DOWNSTREAM-CORPUS` freshness key).
- Authority: `openssl-rt-3.6.4-r2`.

## Measured result

| field | result | detail |
|---|---|---|
| build | PASS | OpenSSH 10.5p1 (portable), libcrypto-only consumer |
| link | PASS | libcrypto.so.3 -> /work/artifacts/phase2/install/lib/libcrypto.so.3 (no libssl) |
| start | PASS | the candidate-linked sshd starts on a high port |
| functional | PASS | live sshd+ssh login, the forced kex/cipher/MAC/host-key matrix including RSA/ECDSA, ssh-keygen RSA/ECDSA/Ed25519 sign+verify, and the regress unit suite |
| concurrency | 16/16 | parallel operations completed |

Functional evidence (harness lines):

- `probe SUMMARY: 31 pass, 0 fail`
- `regress unit 12 pass, 1 fail`
- `concurrent_logins=16/16`

## Known residuals

- `regress/unittests/utf8` aborts on both the candidate and the authority: the court image ships only C/C.utf8/POSIX locales and the test setlocale()s en_US.UTF-8

## Historical failures

| exposed at | defect | fixed by |
|---|---|---|
| `45095bfe` | OpenSSH's RSA and ECDSA signing/verification and the parsing of native openssh-key-v1 RSA/ECDSA private keys failed with `error in libcrypto: initialization error`, so RSA/ECDSA host keys and user keys were rejected and the handshake fell back to Ed25519 | 52b61567 (evp: legacy-origin EVP_PKEY signs/verifies -- OpenSSH RSA/ECDSA fixed) |

## How to reproduce

```sh
bash docker/openssl-rs-court.sh exec sh /work/courts/phase17/downstream/openssh/build.sh
bash docker/openssl-rs-court.sh exec sh /work/courts/phase17/downstream/run_all.sh
```

`run_all.sh` runs this program's harness, rewrites `result.json` from the transcript, re-aggregates `forensics/atlas/downstream-corpus.json` and regenerates this file.
