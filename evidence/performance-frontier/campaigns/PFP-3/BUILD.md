# PFP-3 — build and reproducibility

Source identity (the campaign is forbidden to commit, so the candidate is a
working tree, not a commit):

* git HEAD `b0ada60ebd72432daaef68d8ee6d7cd5245f7895`, `HEAD:src` =
  `abb2c83abaf361cb86d7509d5ea8da1c11eef866`;
* modified: `src/ec/mult.rs`, `src/ec/p256.rs`; untracked:
  `src/ec/p256/fixed_base.rs`;
* `src/**/*.rs` fingerprint `ca5cc146006b4d771fc4b9a9ffd8109199f25c61ef7de0d9e90160232bd2d46a`
  (887 files, taken before and after each build; unchanged within each build).

Recipe (unchanged from PFP-2/PFP-21; script `build/build_pfp3.sh`):
`cargo build --release --lib --offline` (`CARGO_BUILD_JOBS=4`,
`x86_64-unknown-linux-gnu`, rustc 1.98.1), then the Phase-2 distribution link
(`rustc -O --emit=obj` shell + `cc -shared --whole-archive libopenssl_rs.a
--version-script artifacts/phase2/libcrypto.ld -soname libcrypto.so.3`).

## Two independent clean builds

| build | archive sha256 | DSO sha256 | size | build-id |
|---|---|---|---|---|
| A (`court/tmp/pfp3-a`) | `6c2133c07f8ec7363e09c192674008c4532dc606fbe317aaf7cd953abd6bea7b` | `04611380847a708a591a9786734915c4295cc0e164d94025dc937b797ffb15d4` | 17,128,536 | `5a70df9f12a1ada45b0a250fb97019afcb55ebe7` |
| B (`court/tmp/pfp3-b`) | `6c2133c07f8ec7363e09c192674008c4532dc606fbe317aaf7cd953abd6bea7b` | `04611380847a708a591a9786734915c4295cc0e164d94025dc937b797ffb15d4` | 17,128,536 | `5a70df9f12a1ada45b0a250fb97019afcb55ebe7` |

The archive **and** the DSO are byte-identical across two independent clean
builds into fresh `CARGO_TARGET_DIR`s from the same source fingerprint.

Records: `build/raw/build-inputs-a.txt`, `build/raw/build-inputs-b.txt`.

### Fingerprint-locale note

The recorded `ca5cc146…` is the sha256 of the ordered `sha256sum` list produced
inside the court container. `sort` collation differs between the host and the
container, so re-deriving it on the host without `LC_ALL=C` gives a different
value even though the files are identical. The per-file `sha256sum` sets are
exactly equal (887 files, verified with `LC_ALL=C sort`), and their
locale-stable fingerprint is
`6be2dde9ece8d52cbb9fdce53d304cb233519371f1efa03e5c29a4ed61dba584`.
Within each build the before/after fingerprint files `cmp` equal, so the source
did not change while the DSO was produced.

## Caveat

The DSO is reproducible from the **recorded working-tree fingerprint**, not from
a commit, because this campaign does not commit. This is the same limitation the
PFP-2 record names `PFP2-DIRTY-CANDIDATE`; it is recorded, not hidden.
