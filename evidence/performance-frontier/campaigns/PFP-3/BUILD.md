# PFP-3 — build and reproducibility

Source identity is now a **clean commit**:

* `staging` HEAD `289f111877ce7aa9a9a76d25bf76357f57ed6582`, tree `11a5d18f…`;
* `HEAD:src` = `11a5d18fe6d842736d39f2ecb6c22aa58697b406`, clean
  (`git status --porcelain -- src Cargo.toml Cargo.lock` empty);
* `src/**/*.rs` fingerprint
  `ca5cc146006b4d771fc4b9a9ffd8109199f25c61ef7de0d9e90160232bd2d46a`
  (887 files), unchanged before and after each build.

Recipe (`build/build_pfp3.sh`): `cargo build --release --lib --offline`
(`CARGO_BUILD_JOBS=4`, `x86_64-unknown-linux-gnu`, rustc 1.98.1), then the
Phase-2 distribution link (`rustc -O --emit=obj` shell + `cc -shared
--whole-archive libopenssl_rs.a --version-script artifacts/phase2/libcrypto.ld
-soname libcrypto.so.3`).

## Rebuild at `289f11187` (2026-11-27)

| build | archive sha256 | DSO sha256 | size | build-id |
|---|---|---|---|---|
| `pfp3-c` (fresh target) | `6c2133c07f8ec7363e09c192674008c4532dc606fbe317aaf7cd953abd6bea7b` | `04611380847a708a591a9786734915c4295cc0e164d94025dc937b797ffb15d4` | 17,128,536 | `5a70df9f12a1ada45b0a250fb97019afcb55ebe7` |

This reproduces the digest `04611380…` recorded by the earlier two independent
clean builds (`build/raw/build-inputs-a.txt`, `-b.txt`), so the measured,
differentially-tested, audited and timed artefact is the one this commit builds.
Record: `build/raw/build-inputs-c.txt`.

## Post-fix rebuild at `f8d5c4b33` + uncommitted admission (2026-11-27)

The branch-free admission changes only `src/ec/p256/fixed_base.rs` (uncommitted;
the campaign does not commit). Two fresh-target builds were made:

| build | archive sha256 | DSO sha256 | size | build-id |
|---|---|---|---|---|
| `pfp3-d` | `14f76179c517213a35c3c1d69e3dccb722e228f7e12a81efceecb15bdac12bf6` | `ecbefb7d4ecd05cb08f5ade57e64ce2cd81de24bcd68b0c236a8640a18559053` | 17,123,976 | `01b4e75402b7c299d8b10c6293d4159f2cd85f9f` |
| `pfp3-e` | `14f76179c517213a35c3c1d69e3dccb722e228f7e12a81efceecb15bdac12bf6` | `ecbefb7d4ecd05cb08f5ade57e64ce2cd81de24bcd68b0c236a8640a18559053` | 17,123,976 | `01b4e75402b7c299d8b10c6293d4159f2cd85f9f` |

Archive and DSO are byte-identical across the two builds. Source fingerprint
`52219f14f2402ffcb2b1ce5abcc843c168b79fb4798b9db66e50b5683c3b0aee` (887 files),
recorded before and after each build (`raw/build-inputs-{d,e}.txt`).

## Earlier two-build record (working tree at `b0ada60`)

| build | archive sha256 | DSO sha256 | size | build-id |
|---|---|---|---|---|
| A (`court/tmp/pfp3-a`) | `6c2133c0…` | `04611380…` | 17,128,536 | `5a70df9f…` |
| B (`court/tmp/pfp3-b`) | `6c2133c0…` | `04611380…` | 17,128,536 | `5a70df9f…` |

The archive and DSO were byte-identical across those two builds. The
fingerprint-locale note in the previous revision still applies: the recorded
`ca5cc146…` is the in-court container `sha256sum` of the ordered list; the
locale-stable per-file set is `6be2dde9…`.

## Caveat

A digest match is a reproducibility fact, not a source-to-binary refinement
claim. The commit now removes the `PFP2-DIRTY-CANDIDATE` limitation for this
candidate.
