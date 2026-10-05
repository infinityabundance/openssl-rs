# Phase 17 downstream -- the machine-owned corpus

Six real, unmodified downstream programs are built against the candidate distribution shell (`artifacts/phase2/install/{include,lib}`) and exercised by a harness. The result of each is one machine-readable record, `courts/phase17/downstream/<program>/result.json`, aggregated into `forensics/atlas/downstream-corpus.json`. This README and every `EVIDENCE.md` are generated FROM those records by `forensics/tools/gen_downstream_evidence.py`, so prose cannot drift from measurement.

## Records

| program | role | version | build | link | start | functional | concurrency | residuals |
|---|---|---|---|---|---|---|---|---|
| curl | TLS client (transfers over the candidate libssl/libcrypto) | 8.22.0 | PASS | PASS | PASS | PASS | 16/16 | 0 |
| git | object hashing through the candidate libcrypto and HTTPS via candidate libcurl | 2.56.0 | PASS | PASS | PASS | PASS | 16/16 | 1 |
| haproxy | TLS terminator / load balancer in front of a plain-HTTP backend | 3.0.29 | PASS | PASS | PASS | PASS | 16/16 | 0 |
| nginx | TLS server (terminates TLS 1.3 with the candidate) | 1.26.3 | PASS | PASS | PASS | PASS | 16/16 | 0 |
| openssh | libcrypto-only consumer (EVP/HMAC/KDF/BN/EC/RSA/Ed25519, never libssl) | 10.5p1 | PASS | PASS | PASS | PASS | 16/16 | 1 |
| python | CPython `ssl`/`hashlib` consumer (live TLS and its own `test_ssl`) | 3.12.15 | PASS | PASS | PASS | PASS | 16/16 | 0 |

## Refreshing the corpus

The records are data, not assertions: `run_all.sh` is the driver that re-runs every
harness and rewrites them. It does **not** run in the normal gate path -- the
harnesses include multi-minute builds and live TLS servers. The `RT-DOWNSTREAM-CORPUS`
court instead validates the recorded corpus: every program present, every required
field present, `functional` true, `candidate` equal to the current `Cargo.toml`
version, and each corpus record still equal to its per-program `result.json`.

```sh
bash docker/openssl-rs-court.sh exec sh /work/courts/phase17/downstream/run_all.sh
python3 forensics/tools/phase17_courts.py      # RT-DOWNSTREAM-CORPUS
```

