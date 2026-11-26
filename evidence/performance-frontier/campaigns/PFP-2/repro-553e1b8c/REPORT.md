# PFP-23 — reproducible candidate bytes at `553e1b8c`

Status: **DONE for the reproducibility acceptance** (two independent clean
rebuilds agree; build inputs recorded). A digest match is **not** a
source-to-binary refinement claim.

## What was built

Source: a detached git worktree at the declared commit
`c1d25e10d16bc197e03446619a5330842b411c5c`, path `court/tmp/pfp23-src`, working
tree clean, `HEAD:src` = `613b4eee1bdfad91e67e6810b7f59cd274c2e00c` =
`c1d25e10d:src`. `staging` HEAD `4d4979e26` differs from that commit in exactly
one source file (`src/bn/arith.rs`, PFP-6), so the clean worktree is the build
tree the PFP-21 campaign used (which swapped that file rather than checking out
the commit).

Recipe (identical to the PFP-21 build):

```
cargo build --release --lib --offline            (CARGO_BUILD_JOBS=4)
rustc --edition 2021 --emit=obj --crate-type lib -O \
      --crate-name libcrypto_shell -o .../libcrypto.shell.o  <shell.rs>
cc -shared --whole-archive target/release/libopenssl_rs.a --no-whole-archive \
      shell.o --version-script=libcrypto.ld -soname,libcrypto.so.3 \
      -lpthread -ldl -lm -lrt -lutil -o distribution/libcrypto.so.3
```

## Recorded build inputs (`raw/build-inputs.txt`)

| input | value |
|---|---|
| source commit | `c1d25e10d16bc197e03446619a5330842b411c5c` |
| `HEAD:src` tree | `613b4eee1bdfad91e67e6810b7f59cd274c2e00c` |
| source-tree fingerprint (886 `src/**/*.rs`, sorted `sha256sum` manifest) | `290ea3aa8587229bb8a8eb303fa2c90c68d40afb0881fead88d39f2c176dcfdb` |
| `Cargo.lock` sha256 | `95e8fd837792b69a69798c3884dfc4000bee28d87c58fd3bf4cd5f597e62c2d9` |
| rustc | 1.98.1 (48a229cea 2026-09-01) |
| cargo | 1.98.1 (797e8a9bc 2026-08-05) |
| cc | Debian 12.2.0-14+deb12u1 |
| target triple | `x86_64-unknown-linux-gnu` |
| profile / flags | release; `cargo build --release --lib --offline`; `CARGO_BUILD_JOBS=4` |
| shell source | `court/tmp/pfp2-fix/shell/libcrypto.shell.rs`, sha256 `efa0fbce5c0e96ab7ddd539f7b798f4ad893f5c120c99cb44077f7c74ea65606` |
| version script | `artifacts/phase2/libcrypto.ld`, sha256 `75fb6eff05e5cf7677f46f03fb8ed6e7bbaa24a96f1e20702f74c524e1b51275` |

## Result

| artefact | first build (PFP-21) | this rebuild | agreement |
|---|---|---|---|
| `libopenssl_rs.a` | `b7c22e863b4508423b4c4a7be8efad7790aff14a8ecf366c24ca59e8788ad3f9` | same | byte-identical |
| `libcrypto.so.3` | `553e1b8ce1eb7e03a0d92a5614b566b88e49e55d2c2a3f7ba28fc6d78eecc4e4` | same | byte-identical (`cmp`) |

Size 17,032,672 bytes; build-id `408dafd2f611bb8fa095ed760e7eaafc59ebb39e`.
The source fingerprint is re-taken after the build and must be identical; it is.

Two independent clean rebuilds from the same declared commit into different
fresh `CARGO_TARGET_DIR`s therefore reproduce the measured digest. The candidate
DSO bytes are still not committed (`PFP2-DIRTY-CANDIDATE`); what is established
is that the committed source plus the recorded inputs produce the measured
bytes.

## What this does not say

The digest agreement identifies the bytes; it does not prove the compiler
preserved any particular source property, and it is not a source-to-binary
refinement claim. The authority remains the source and its tests.

## Reproduce

```
bash docker/openssl-rs-court.sh exec sh -c \
  'cd /work && git worktree add --detach court/tmp/pfp23-src c1d25e10d16bc197e03446619a5330842b411c5c'
OPENSSL_RS_COURT_MEM=8g OPENSSL_RS_COURT_MEMSWAP=8g \
  bash docker/openssl-rs-court.sh exec env CARGO_BUILD_JOBS=4 \
  sh evidence/performance-frontier/campaigns/PFP-2/repro-553e1b8c/rebuild.sh
```
