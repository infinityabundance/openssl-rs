# PFP-8 — constant-time taint (ctgrind)

No Rust source changed in this batch, so the taint instrument re-runs the
established test at the frozen source and DSO; the numbers are not inherited.

| item | value |
|---|---|
| source | `b2cca665…`, `src` tree `05a4a56b…`, `src/bn/arith.rs` `b548ee15…` |
| candidate DSO | `88c0c7e0…` |
| test | `bn::arith::tests::ctgrind_secret_exponent_window` |
| profile | debug test binary, `CARGO_PROFILE_TEST_DEBUG=0`, `--test-threads=1` |
| instrument | valgrind 3.19.0 memcheck; exponent limb bytes marked undefined |
| raw | `ctgrind/exponent_taint.log`, `ctgrind/negative_control.log`, `ctgrind/summary.txt` |

| case | errors | contexts | valgrind exit |
|---|---:|---:|---:|
| secret exponent tainted | **0** | **0** | 0 |
| negative control (`CTGRIND_CONTROL=1`) | 4 | 1 | 99 |

Origins: **none** (`ctgrind/origins.txt`). The control fires on a deliberate
branch on a tainted exponent limb, so the instrument is sensitive at this
artefact.

Coverage limit, stated: the test exercises a four-limb modulus, so it reaches the
width-4 specialised kernel. The other seven fixed widths rest on the branch
audit, which enumerates all of them because they are inlined into one carrier;
see `AUDIT.md`. This is a source-bound check of the exponent ladder, not a
DSO-bound taint and not a proof of constant-time behaviour. The batch adds no
new secret carrier: it changes no source and implements no prepared path.
