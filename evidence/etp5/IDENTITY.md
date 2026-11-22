# ETP-5 — consumer identity reconstruction

**Item:** ETP-5 of `docs/ETP-TODO.md`.
**Source identity for this reconstruction:** `933d09189890bf2ba8a6096108c0b11f42c1e84b`
(`staging`, tracked worktree clean at start).
**Scope:** the two consumer families this item owns — OpenSSH (`ssh`/`sshd`) and
curl. The chain reconstructed here is: consumer commit and build → OpenSSL
authority identity → candidate DSO digest → loaded artefacts → script
population.

This document records only what the tracked tree supports. Where a link is
absent it is marked **not reconstructable** and the missing record is named.
No identity is inferred from a version string, a mapped path, or a later
session's working directory.

---

## 1. OpenSSH (cohort A — portable OpenSSH 9.9p1)

### 1.1 What a clean checkout reconstructs

| link | value | tracked source |
|---|---|---|
| consumer source | portable OpenSSH 9.9p1 tarball, sha256 `b343fbcdbff87f15b1986e6e15d6d4fc9a7d36066be6b7fb507087ba8f966c02` | `courts/phase18/interop/MANIFEST.json` pin; re-derived at O2 (`RECEIPT-o2.json`, 5 verified / 1 absent-recorded / 0 failed) |
| cohort rule | 9.9p1 is cohort A; 10.5p1 is cohort B and is never pooled | `docs/OPENSSH-COHORT.md` |
| authority source | OpenSSL 3.6.4 archive sha256 `9bffaa1ad1e07b354c21bd3324ec02fa15579f45a7d0494b3e74bc449b7333ef`, source-tree root hash `27d9917bd7c63d9bb056e674cc08c809b44cde50f9e474cd30041b8b66385432` | `forensics/authorities/AUTHORITIES.json` (`checksum_verified: true`) |
| authority built DSO (as recorded) | libcrypto `611e511db4273c4b6b522031fd171efce71b80661bb8310c2a21dfd18ec0efd2` | `RECEIPT-o4.json`, `RECEIPT-o5.json`, `RECEIPT-o7-*.json` |
| candidate DSO, first population | libcrypto `3c3a68c1baeb304adf2fc3af827e49b14529556008429bd11dda784a2c6cdfd1` (host build) | `RECEIPT-o4.json`, `RECEIPT-o5.json`, `MANIFEST-o11-B.json` |
| candidate DSO, second population | libcrypto `ee7fa27c79f5a679d5b229429d53dc7c3b510695db9c74d11b4b6783a735ebe9` (court rebuild) | `RECEIPT-o7-AB.json`, `RECEIPT-o7-BA.json`, `RECEIPT-o7-BB.json`; re-measured in this session |
| loaded library, per cell | client and server each map their own cell's `libcrypto.so.3`; the mapping is proven from inside the process by `map_probe.c`, not by `ldd` | `RECEIPT-o5.json` (20 live checks, 2 `no_crypto_dependency`, 0 failed); re-proven in `REEXECUTION.md` |
| harness scripts | `cell.sh`, `manifest.py`, `check_receipts.py`, `build_trees.sh`, `verify_runtime_identity.sh`, `publish_logs.py` are tracked; the deterministic `regress/*.sh` selection (`touch`) is in `cell.sh` | `courts/phase18/interop/` |
| script population, court runs | 96 `run test` lines per cell | O7 logs; re-derived in this session (96 for BB and BA) |
| script population, host runs | 73 `run test` lines per subject | `MANIFEST-o11-A.json`, `MANIFEST-o11-B.json` |

The two populations are **not** the same 96 scripts. The 73-script O11 manifests
were produced on the host with `make -k tests` on `tree-A`/`tree-B`; the 96-
script population is the court cell run after `cell.sh` began touching
`regress/*.sh`. The tracked O7 logs are the 96-script runs. The O11 manifests
are not the O7 cell logs and must not be cited as such.

### 1.2 What a clean checkout does **not** reconstruct

| missing link | why | what would resolve it |
|---|---|---|
| candidate source commit for either B DSO | `RECEIPT-o4.json` records `dso_from_archive: "/var/tmp/t29-target/release/libopenssl_rs.a"`; that path is absent from this working tree, is not tracked, and **no archive digest is recorded** | a tracked build record naming the source commit, the release archive sha256, the toolchain, and both DSO digests |
| relationship between `3c3a68c1` and `ee7fa27c` | no record states whether they are the same source and toolchain built twice or different configurations (ETP0-GAP-018 / GAP-031) | the same build record, or a rebuild of both in one venue from the O2 pins |
| authority built prefix | `forensics/authorities/prefix/openssl-3.6.4-production/` is **not tracked**; only the archive pin and the source-tree root hash are tracked | track the prefix build recipe (configure flags, compiler, target) and the built DSO digests, or rebuild it reproducibly |
| per-cell consumer binary digests at O7 time | the O4/O7 receipts record NEEDED/RUNPATH and the DSO digest, not the `ssh`/`sshd`/`sshd-session` digests | record the binary digests in each cell receipt |
| the `tree-A`/`tree-B` build trees | `court/tmp/` is untracked (1,929 tracked references, 0 tracked files) | a content-addressed build record or a rebuild recipe |

The measured binary digests in this session (not historical claims, and not a
substitute for the missing O7 record) are:

| binary | tree-B (candidate `ee7fa27c`) | tree-A (authority `611e511d`) |
|---|---|---|
| `ssh` | `a7d0c336aab6e88468ddf592a6f3c5ed66407b51c4ab5e3eb3ed67b3a05aa96f` | `a4c94d35126f6fc0a7bfa24afc4cf98edad9a1b2fb25307a97ad2487e1938157` |
| `sshd` | `c1a5a5a7c0fe530283d0e236637b88a7e5154bfdd98bcc277209b35180874eb8` | `7f13c40a577889901793c761c80f8d4f08d83cfa58d67097ef0285f3a3e947ca` |
| `sshd-session` | `ebe9d5ff285c8646b5be407bc23efc935807590364fa2e69ba1ac05d6a4fffe6` | `3c90a75c92b09b3ba10c93b8e61d51a34e8156d080542fc9949de4ded8240ec6` |
| `sftp-server` | `5269d6da6040962bc41b467d15ff4add3b46457e6f48f0a48c87002cc90c53ac` | — |

**The interop consumers are not the graduated consumers.** The b85c graduation
names `ssh` `c2db343dfa5135272f2be6960210b3b99af83b9ed181034e976e1c68e98fff8b`
and `sshd` `8af509523ed16f68fe74a75aef923b78e87b047c054ea30fc2aa6d9971485ae1`
(`FREEZE-b85c.json`), with libcrypto `06b5f338…`. The interop trees carry
different binaries and a different candidate DSO. No tracked record claims the
two are the same build, and this document does not equate them.

### 1.3 Identity traps confirmed in this session

* Both builds print `OpenSSH_9.9p1, OpenSSL 3.6.4 25 Aug 2026`, yet load
  different DSOs (build IDs `b49b4afcdaaab3171daf2ac0826807f63e0ae836` for
  `ee7fa27c`, `5b4871ce9d78edeafc96f143d7d6697d943ad804` for `611e511d`). **A
  version banner is not an identity.**
* The O7 aggregate receipt records mapped *paths*, not DSO digests. The digests
  exist only in the per-cell receipts. A consumer of the aggregate alone cannot
  identify build B.
* The O7 aggregate receipt's BB log digest is
  `1a23987ae2ea2bee94eb68f3946e7751c03322ea5d0586cb6ac154c349fdc317`; the
  current `RECEIPT-o7-BB.json` names
  `03dc64dfa4c95082584361e1a15f23dc05e26d7edbbd45f7385e1ab63825e3b7`. Both files
  are tracked, both are 196,302 bytes, and they differ on one line: the compiler
  temporary object name in an `ld` warning (`ccPLmUvk.o` vs `ccK6DPDJ.o`). Both
  carry 96 `run test` lines. The aggregate was generated at
  `2026-11-22T02:25:53Z`, before the current BB receipt (`02:43:52Z`).
* The aggregate receipt says it supersedes "the three per-cell receipts marked
  withdrawn", but the current AA/AB/BA files are **live**, regenerated after the
  fix. The withdrawn revisions exist only in Git history. The supersession
  sentence describes history, not the current file set.

### 1.4 Script population reconstructability

| population | reconstructable? | evidence |
|---|---|---|
| 96 court scripts | yes, from each tracked log, by the `manifest.py` rules | O7 logs and the two logs published by this item |
| 73 host scripts | yes, from the tracked O11 logs | `MANIFEST-o11-*.json` |
| per-cell script list for AA/AB/BA at O7 time | **partly**: the logs carry 96 `run test` lines each, but the per-cell receipts do not record the selection rule (ETP0-GAP-035). The current `cell.sh` touches `regress/*.sh`, which makes the selection maximal; that rule was not in the AA/AB/BA receipts | logs + current `cell.sh` |
| historical pre-fix cell scripts | **no**; the withdrawn revision records only what remains established (the O6/O9 AA and BB logs) | `RECEIPT-o7.json@cc2e5fa32` |

---

## 2. curl (candidate 0.0.49, curl 8.10.1)

### 2.1 What a clean checkout reconstructs

| link | value | tracked source |
|---|---|---|
| candidate source | head `17e45eec1a48a7a5e1679e1d29ee69451e9d59a1`, crate 0.0.49, src-content `ade50c7383cf567a57e6ee0f3b6587b6c6d17b3fe72b4da98320a7f22ba76a35` | `forensics/memory-safety/campaign/safe-c33/atlas-refresh/v1x-candidate-freeze.json` |
| candidate DSOs | libcrypto `fd25cc9e6424ea79aaaff05df22b3f6e1d46aa22d5666cfe7589dce95ffd88a9`, libssl `648f8caecda245d2186813fb67ceadedd798b9ce609c8b041a84f195946c5f68` | **tracked** under `artifacts/phase2/install/lib/` (155 tracked files); re-measured equal in this session |
| consumer recipe | `recipe:curl:8.10.1`, source sha256 `d15ebab765d793e2e96db090f0e172d127859d78ca6f6391d7eafecfd894bbc0`, source root hash `34735156e3978b653ea4ea6f1b073ca3ccd5bd8c493ec708160a2dc289598d08` | `closure-curl-049.json` `ledger_record` |
| loaded libraries | `ldd` under `LD_LIBRARY_PATH=<install>/lib` resolves `libssl.so.3` and `libcrypto.so.3` to `artifacts/phase2/install/lib`, with digests equal to the inventory | `closure-curl-049.json` `loader_resolution` |
| analysis tool | `consumer_closure.py` sha256 `141b8a0f7806780cd2100b13562fd3d9bd84a22c8122793cd9e232f8daa3caae`, which is exactly the blob at `17e45eec1` | `closure-curl-049.json` `tool`; `git show 17e45eec1:forensics/tools/consumer_closure.py` |
| symbol population | 227 imported symbols; 644 reachable files; 7 production obligations discharged | `closure-curl-049.json` `symbol_evidence`, `counts` |
| element-7 predicate | `established: false`, `status: FAIL`, 449 reachable unresolved, 219 target-bounded, 158 contract-bounded, 72 closed-target-set | `element7-curl-049-triage.json` `receipt.predicate_element_7` |

### 2.2 What a clean checkout does **not** reconstruct

| missing link | why | what would resolve it |
|---|---|---|
| the analysed `libcurl` binary | `court/tmp/curl-049/curl-8.10.1/lib/.libs/libcurl.so.4.8.0`, sha256 `7dfe9b54…`, `build_provenance: null`; untracked | record the binary digest and build provenance in a tracked artifact record |
| agreement between the ledger row and the closure | the ledger row records artifact `e13a4fbd06104fd99b895c030e8e3517625ca41162330c29ce4744f490a02767` and `recorded_candidate_install` `06b5f338…` (the b85c OpenSSH candidate), with `artifact_matches_this_build: false`; the closure uses libcurl `7dfe9b54…` and install `fd25cc9e…` | re-record or correct the ledger row against `fd25cc9e` and the actual libcurl build |
| authority counterpart | the curl closure is a consumer closure, not an interoperability court; no OpenSSL authority differential is recorded | an authority court if a compatibility claim is wanted; the safety closure does not need one |
| element-7 population after the repairs | the triage says 219 target-bounded; `element7-curl-049-last34-notes.md` says 27 named rows remain and the full closure is `NOT_RUN`; the running count carries the recorded ±1/±2 discrepancy (ETP-TODO C2) | one frozen census, one full closure run at one identity, and a machine-readable queue table whose rows sum to the running count |
| reproducibility of the recorded closure with the current tool | the closure used tool `141b8a0f` (blob at `17e45eec1`); the tracked tool at HEAD is `77cb49445fd0a08a7868d40aacf2cab8f1b5617b290402cda0ac9e143b5c0bb3`, changed by the element-7 repair commits | a closure re-run at a frozen identity with the recorded tool, or a record binding the new tool to a new closure |

### 2.3 Disposition of the element-7 refusing population

* `closure-curl-049.json` says `verdict.state: ACCEPTED` **and**
  `verdict.safe_compatible: false`. `ACCEPTED` is the closure predicate's
  result, not a graduation.
* The machine-readable element-7 predicate says `FAIL`.
* The repair batches reduce the queue (120 → 72 → 69 → 56 → 51 → 34 → 27 by the
  running count) but never run a full closure after the tool changes.
* The 27 is a count in checkpoint notes, not a machine-readable, per-row,
  digest-bound closure result. The 219 is the last machine predicate at the
  0.0.49 candidate.
* Therefore the population remains **FAIL**, and neither "27 remain" nor "219
  remain" is reported as closed.

---

## 3. Cross-consumer summary

| question | OpenSSH | curl |
|---|---|---|
| consumer commit reconstructable? | source tarball yes; the linked candidate source commit **no** | yes, `17e45eec1` + inventory |
| candidate DSO tracked? | **no** (`court/tmp`) | yes (`artifacts/phase2/install/lib`) |
| candidate DSO bound to a source commit? | **no** for either `3c3a68c1` or `ee7fa27c` | yes, via the tracked inventory |
| authority DSO reconstructable? | digest recorded, prefix **not tracked** | not applicable (no authority court) |
| loaded library proven per process? | yes, `map_probe.c` in-process; re-proven here | yes, `ldd` under a declared `LD_LIBRARY_PATH` |
| consumer binary digest recorded? | **no** in the interop receipts; differs from the b85c graduation binaries | **no** for libcurl (`build_provenance: null`) |
| execution population reconstructable? | yes from logs (96 court / 73 host), with a historical selection-rule gap | yes for symbols/files; **no** for the final element-7 row set |

**No identity in this table is upgraded.** Where the tree is silent, the entry
is not reconstructable; a later session's working directory (for example the
present `court/tmp/o4` and `court/tmp/curl-049`) is not evidence of what the
historical run loaded.
