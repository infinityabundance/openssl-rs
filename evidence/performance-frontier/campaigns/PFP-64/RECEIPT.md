# PFP-64 receipt — POLYVAL adjudicated at the shipped DSO

**Decision: POLYVAL is already table-free on the fast path and constant-pattern
on the portable path. No STOP fired, no source changed, no new unsafe.** This
closes the "POLYVAL remains TODO" half of the row; the portable `cmov` remains
observed rather than proved and no constant-time claim is made.

## 1. Identity

| field | value |
|---|---|
| branch / HEAD | `staging` `89490a1aa5c60a5eb602c409f4936608a5bd5e27` |
| source change | **none** (no `src/`, `Cargo.*`, `build.rs` edit) |
| shipped DSO | `court/tmp/pfp68/final/libcrypto.so.3` |
| DSO SHA-256 / size | `f53e2622112379f9a74b584a336b52cf282b7b38c83949efacb3a1a33c9ad926` / 17 185 416 B |
| binding | the PFP-68 final distribution-shaped DSO (`campaigns/PFP-68/raw/identity.txt`, same digest); HEAD 89490a1a is the PFP-68 commit |
| authority | `openssl-3.6.4-production`, DSO `611e511d…`, static archive `…/lib/libcrypto.a` |
| instrument | `audit_pfp64.py` (PFP-63 `nm -S` + `objdump -d -M intel` classifier) |

## 2. What exists

POLYVAL is `src/provider/cipher.rs`'s `polyval_ghash_init` / `polyval_ghash_hash`
(used by AES-GCM-SIV). `polyval_ghash_init` is inlined (with `mulx_ghash`);
`polyval_ghash_hash` is a symbol. The multiply is the shared
`src/modes/gcm.rs::gf_mul` → `gf_mul_clmul` or `gf_mul_portable`.

## 3. Adjudication (full detail in `ADJUDICATION.md`)

| carrier | jcc | setcc | cmov | indexed memory | notes |
|---|---:|---:|---:|---:|---|
| `polyval_ghash_hash` | 9 | 0 | 0 | 10 | all 9 public (length loop, CPU dispatch); indexed = input at public block index (9) + rodata jump table at public capability index (1) |
| `gf_mul_clmul` | 0 | 0 | 0 | 0 | four `pclmul` |
| `gf_mul_portable` | 1 | 0 | 4 | 0 | fixed 128-iteration back-edge; mask `cmov`s |
| `aes_gcm_siv_encrypt` | 6 | 3 | 0 | 0 | length/flag; `mulx_ghash` halving is `and` mask |
| `aes_gcm_siv_decrypt` | 7 | 2 | 0 | 0 | length/flag |

**Finding:** no indexed memory operand is indexed by secret state or by the key;
no secret-derived conditional transfer or address exists in the POLYVAL path at
this digest. `mulx_ghash`'s `x^-1` conditional compiles to
`and eax,0x1; movabs r8,0xe100000000000000; and r8,rax` — no branch, `setcc` or
`cmov`. The fast path is table-free; the portable path is constant-pattern
(fixed loop, mask selection).

## 4. Correctness (one mismatch would be a STOP; none fired)

| evidence | count | result |
|---|---:|---|
| POLYVAL KAT vs authority-oracle values (`the_polyval_helpers_match_the_authority_oracle`) | 3 checks | **pass** |
| authority static-archive oracle re-executed this batch (`raw/oracle-polyval.txt`) | 3 cases | **3/3 equal, 0 mismatches** |
| RFC 8452 AES-GCM-SIV vectors (`CT-CIPHER` `gcm_siv`) | 50 vectors | **50/50 pass, 0 failed** |

Raw: `raw/kat-unit-test.txt`, `raw/oracle-polyval.txt`,
`raw/ct-cipher-gcm-siv.json`, `raw/audit-after.json`,
`raw/audit-after.disasm.txt`.

## 5. Safety and compatibility

No source changed, so the exported surface, `#[repr(C)]` layouts, allocator seam
and existing acceptance criteria are untouched. No new unsafe. This is an
instruction observation, **not** a constant-time proof: the portable `cmov`
lowering is observed rather than proved, and no cache/dudect evidence was run.

## 6. Gate

* `cargo fmt --all -- --check`: clean.
* `cargo clippy --all-targets -- -D warnings`: clean.
* `cargo test --lib -- --test-threads=4`: **2564 passed, 0 failed, 56 ignored** (baseline; no test newly ignored).

## 7. Memory (court `openssl-rs-court`, `memory.max=4294967296`)

| command | host `available` | `Swap free` | cap |
|---|---:|---:|---:|
| `cargo fmt` / `cargo test --lib <KAT>` | 21 GiB | 8 GiB | 4 GiB |
| authority oracle build + run | 21 GiB | 8 GiB | 4 GiB |
| `cargo clippy --all-targets` | 21 GiB | 8 GiB | 4 GiB |
| `cargo test --lib -- --test-threads=4` | 21 GiB | 8 GiB | 4 GiB |

Cap = `min(4, available − 8) = 4 GiB` (floor 2); `CARGO_BUILD_JOBS=1`,
`CARGO_PROFILE_TEST_DEBUG=0`, one heavy command at a time, no release `--test`
build, `test_sigstore_bundle` never run. The court was already up and capped at
4 GiB (`memory.events oom=0 oom_kill=0`).
