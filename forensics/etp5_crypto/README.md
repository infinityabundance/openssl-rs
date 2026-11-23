# ETP-T5 cryptographic references and differential harness

This directory holds the independent reference implementations, the vector
populations, the C differential harness and the driver used by ETP-T5.  The
normative discussion, domains, ambiguity notes and classification rules are in
`docs/CRYPTOGRAPHIC-REFERENCE.md`; the observed result is in
`evidence/etp-t5/RESULTS.json` and `evidence/etp-t5/RECEIPT.md`.

Nothing here is imported by the crate.  The Python references use only the
Python 3.11 standard library and are written from the normative documents, not
from the candidate or from OpenSSL source.

## Files

| file | role |
|---|---|
| `ref_arith.py` | modular add/sub/mul/inverse/exponentiation over the P-256 prime `p` and order `n` |
| `ref_ec.py` | P-256 affine and Jacobian point arithmetic, scalar multiplication, uncompressed encoding |
| `ref_ecdsa.py` | ECDSA signing with a supplied nonce, verification, RFC 6979 nonce |
| `ref_rsa.py` | deterministic 2048-bit key, CRT recombination, plain private operation |
| `ref_symmetric.py` | SHA-256 and HMAC-SHA-256 control implementations |
| `make_vectors.py` | deterministic population generator; `--check` verifies the tracked files |
| `etp5_harness.c` | dlopen harness that drives one `libcrypto.so.3` through its C ABI |
| `driver.py` | computes reference expectations, runs the harness, classifies differences; `--self-test` exercises the classifier |
| `run_etp5.sh` | court entry point: build, link, harness, vectors, differential |
| `vectors/` | the tracked populations and the fixed RSA key |

## Reproduce

From the repository root, inside the court:

```sh
OPENSSL_RS_COURT_IMAGE=openssl-rs-court-tools:1 \
OPENSSL_RS_COURT_MEM=6g OPENSSL_RS_COURT_MEMSWAP=6g \
  bash docker/openssl-rs-court.sh exec \
    env CARGO_BUILD_JOBS=4 bash forensics/etp5_crypto/run_etp5.sh
```

The seed is `0x45545035`.  `make_vectors.py --check` reproduces every tracked
vector byte for byte and exits non-zero on drift.  The campaign never runs on
the host.

The committed RSA key in `vectors/rsa_key.json` is test data for this
differential campaign.  It is not secret and must not be used for any real
key operation.

## Non-claims

The populations are sampled.  A green differential is bounded evidence, not a
proof of correctness, constant-time behaviour or memory safety.  The
reference's own correctness rests on the reading of the normative documents
stated in `docs/CRYPTOGRAPHIC-REFERENCE.md`.
