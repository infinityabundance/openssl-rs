# ETP-5 — re-execution report

**Source identity:** `933d09189890bf2ba8a6096108c0b11f42c1e84b` (`staging`, tracked
worktree clean at start).
**Court:** `openssl-rs-court-tools:1`, running container `openssl-rs-court`.
**Result class:** functional interoperability at a named DSO digest. **Not a
safety result and not a graduation.**

---

## 1. Environment and resource guard

| item | observed |
|---|---|
| host `available` before the first heavy command | 27 GiB |
| §6.1 threshold | 24 GiB; guard satisfied |
| court memory cap | 8,589,934,592 B (8 GiB), `memory.max` read from the cgroup |
| court OOM events | `oom=0 oom_kill=0`; `docker OOMKilled=false` |
| running court `memory.current` after the runs | ≈ 0.8 GiB |
| `CARGO_BUILD_JOBS` | 4 (no Rust build was required; the court's existing candidate DSO and OpenSSH trees were reused) |
| requested cap | `OPENSSL_RS_COURT_MEM=6g`; the live court was created at 8g by an earlier session and `exec` does not recreate it. 8g is within `min(8g, 27-16=11g)`, so the run remained inside the budget. Recorded as a deviation from the literal command, not as an exception to the cap. |

One heavy command ran at a time. No other session's court was interrupted.

## 2. Venue prerequisites

The first BB attempt aborted at setup, before any test ran:

```
run test connect.sh ...
Privilege separation user sshd does not exist
FATAL: sshd_proxy broken
make[1]: *** [Makefile:254: t-exec] Error 1
```

* Receipt generated `2026-11-22T11:45:53Z`; the log carried 3 `run test` lines,
  0 `ok`, 0 `failed`; the run stopped in `t-exec`, `interop-tests` and
  `extra-tests` for the same reason. This is **not** a cell result and is not
  counted as one.
* Cause: the O7 venue prerequisites (`sshd` privilege-separation user,
  `/var/empty`) were not present in the recreated container. The O7 receipt
  itself names them (`venue.court_environment_requirements`).
* Remedy, inside the container only: `useradd -r -M -d /var/empty -s
  /usr/sbin/nologin sshd`, `mkdir /var/empty` mode 0755 owned by root.
* `/work/court/tmp` is mode 0777 in this checkout, so the harness's
  unsafe-permissions check would stop every cell. The upstream-supported bypass
  `TEST_SSH_UNSAFE_PERMISSIONS=1` was set for the cell runs. It bypasses a
  permissions check; it does not change a test. Recorded as a venue deviation.
* No OOM occurred (`memory.events oom=0`).

## 3. Candidate identity actually executed

The court's existing build was reused. It is the O7 build, not a build of the
current source HEAD:

| field | value |
|---|---|
| candidate DSO executed | `ee7fa27c79f5a679d5b229429d53dc7c3b510695db9c74d11b4b6783a735ebe9` |
| DSO path | `/work/court/tmp/o4/b-prefix/lib/libcrypto.so.3` (untracked) |
| DSO GNU build-id | `b49b4afcdaaab3171daf2ac0826807f63e0ae836` |
| authority DSO | `611e511db4273c4b6b522031fd171efce71b80661bb8310c2a21dfd18ec0efd2` |
| authority DSO build-id | `5b4871ce9d78edeafc96f143d7d6697d943ad804` |
| version banner | both builds print `OpenSSH_9.9p1, OpenSSL 3.6.4 25 Aug 2026`; the banner does not distinguish them |
| tracked binding of `ee7fa27c` to a source commit | **none** |

The current source HEAD was **not** built for this item: no tracked record binds
`ee7fa27c` to a commit, and rebuilding at HEAD would produce a third DSO
identity that no tracked record names. The re-execution is therefore **at the
O7 candidate digest**, and the identity gap is recorded in `IDENTITY.md`.

## 4. Cells run

Both cells used the tracked `courts/phase18/interop/cell.sh`, the tracked
`subreaper.c` and `openssl-shim.sh` venue aids, `SKIP_LTESTS=sftp-cmds`, and
the deterministic `touch regress/*.sh` selection. Each cell's client and server
processes were probed from inside the process by `map_probe.c`; the cell refuses
to run on an unexpected mapping.

### 4.1 Cell BB — candidate client ↔ candidate server

| field | value |
|---|---|
| receipt | `evidence/etp5/REEXECUTION-RECEIPT-o7-BB.json` (`37efaf60af9adba5002bee513a19fd46f277afad42185f1708c627f6e088e442`) |
| generated | `2026-11-22T12:01:16Z` |
| log (published, tracked) | `evidence/etp5/logs/etp5-cell-BB-aae8742cde7b0e63b9d615df685d49971fc92f4c7137a0fe2eb24e3e01b3124a.log`, 169,038 B, sha256 `aae8742c…3124a` |
| derived counts | `evidence/etp5/REEXECUTION-MANIFEST-o7-BB.json` (`a6ff5a681139079964799038b0af818e3f0d60a594c0338f76b296e7b4e7cb41`) |
| scripts announced | **96** (`run test` lines) |
| ok assertions | **87** |
| failed assertions | **1** |
| skipped assertions | **8** (7 `SKIPPED:` + 1 `Skipped:`) |
| blocked scripts | **0** |
| unit assertions | **410** |
| client DSO mapped | `/work/court/tmp/o4/b-prefix/lib/libcrypto.so.3` = `ee7fa27c…` |
| server DSO mapped | `/work/court/tmp/o4/b-prefix/lib/libcrypto.so.3` = `ee7fa27c…` |
| mapping status | `ok` (both sides) |
| `make -k tests` exit | 2 (the single failed script; `-k` is what makes the run full) |

### 4.2 Cell BA — candidate client ↔ authority server (cross cell)

| field | value |
|---|---|
| receipt | `evidence/etp5/REEXECUTION-RECEIPT-o7-BA.json` (`bfb2bd81c96c9046e53e2d099689f16f913d34e234227ab82a7fd76c3e1d0c87`) |
| generated | `2026-11-22T12:14:25Z` |
| log (published, tracked) | `evidence/etp5/logs/etp5-cell-BA-234629128b1fa281f59ac4ec52aa371479c4060072f0e50a1ed1a40fc6d1e651.log`, 171,054 B, sha256 `23462912…c6d1e651` |
| derived counts | `evidence/etp5/REEXECUTION-MANIFEST-o7-BA.json` (`ddd79a3e3e0b3769a164bbf3bd75cf42602e6610d5d688c405d90fbea9c88c27`) |
| scripts announced | **96** |
| ok assertions | **87** |
| failed assertions | **1** |
| skipped assertions | **8** |
| blocked scripts | **0** |
| unit assertions | **410** |
| client DSO mapped | `/work/court/tmp/o4/b-prefix/lib/libcrypto.so.3` = `ee7fa27c…` |
| server DSO mapped | `/work/forensics/authorities/prefix/openssl-3.6.4-production/lib/libcrypto.so.3` = `611e511d…` |
| mapping status | `ok` (both sides; `separate_library_paths: true`) |
| `make -k tests` exit | 2 |

## 5. Reproduction of the recorded failures and skips

Both cells produce exactly one failing script, `dropbear-kex.sh`, at
`diffie-hellman-group14-sha1`:

```
run test dropbear-kex.sh ...
diffie-hellman-group14-sha1
dropbear kex: kex curve25519-sha256
...
ssh cat .../regress/data failed
cmp: EOF on .../regress/copy which is empty
corrupted copy
failed dropbear kex
```

This is the same transcript and the same classification recorded at O7/O8:
Dropbear 2026.94 does not offer `diffie-hellman-group14-sha1`, which the harness
forces on the server, so it is **unsupported, not a candidate-specific
failure**; it remains counted as a failure in the upstream suite.

The eight skip lines in each cell are:

| line | skip reason |
|---|---|
| `SKIPPED: TEST_SSH_SSHFP_DOMAIN not set.` | missing optional test input |
| `SKIPPED: skipped (running as root)` | root environment |
| `Skipped: running as root` | third skip spelling, counted |
| `SKIPPED: TEST_SSH_HOSTBASED_AUTH not set.` | missing optional test input |
| `SKIPPED: No PKCS#11 library found` (×3) | no PKCS#11 library |
| `SKIPPED: conch interop tests not enabled` | conch not pinned |

This is the recorded set (O7 counts 7 `SKIPPED` plus the one `Skipped:` line,
i.e. 8 by the case-insensitive rule; 0 blocked).

Comparison with the recorded O7 BB cell: 96 scripts, 87 ok, 1 failure
(`dropbear kex`), 7+1 skips. **Reproduced exactly.** The BA counts are also the
recorded O7 BA counts. The logs are new bytes: absolute paths, timestamps and
the compiler's temporary object name differ, so the log digest differs from the
O7 log digest by construction.

## 6. Cells not run

| cell | status | blocker | what would remove it |
|---|---|---|---|
| AA (authority client ↔ authority server) | `NOT_RUN` | wall-clock budget. Measured cost of the two cells run: BB ≈ 15 min, BA ≈ 13 min (receipt timestamps `12:01:16Z` and `12:14:25Z`, after the setup repair). AA is the authority-only cell and carries no candidate-library coverage beyond the recorded O7 AA. | ≈ 15 min of court time |
| AB (authority client ↔ candidate server) | `NOT_RUN` | the same budget. It is the second cross direction; BB already exercises the candidate as server, but AB would run the authority client against it. | ≈ 15 min of court time |

Neither unrun cell is presented as passing, and no failure evidence is claimed
for them. The O7 record says all four cells ran with identical counts; this item
re-ran two and records the other two as `NOT_RUN`.

## 7. curl

No curl closure re-run was attempted. The cheap decisive checks performed were:

| check | result |
|---|---|
| closure instrument self-test at the tracked tool | `python3 forensics/tools/consumer_closure.py --self-test` → **rc=0**, `self-test ok`, one `PREMISE_UNAVAILABLE` (the pre-existing `e7core` loader-fetch arm), at tool sha256 `77cb49445fd0a08a7868d40aacf2cab8f1b5617b290402cda0ac9e143b5c0bb3` |
| recorded element-7 predicate | `evidence/element7-curl-049-triage.json`: `established: false`, `status: FAIL`, 449 reachable unresolved, 219 target-bounded |
| repair-batch state | `element7-curl-049-last34-notes.md`: 27 named rows remain refused; full closure `NOT_RUN` |
| closure re-run | **NOT_RUN**. The recorded closure was produced by tool `141b8a0f…` (the blob at `17e45eec1`); the tracked tool has since changed. A closure run needs a frozen census, the two DSO graphs and the sidecars, and no cheap decisive substitute exists. |

The self-test is an instrument check. It is **not** a closure result and it does
not move element 7. The element-7 population remains **FAIL**; see
`IDENTITY.md` §2.3 and `REFUSALS.json` `ETP5-R5`.

## 8. What these results mean

* The OpenSSH functional court reproduces at candidate DSO `ee7fa27c` for the
  same-library cell and one cross cell: the same single unsupported failure, the
  same skip set, the same assertion counts.
* The result is **functional compatibility at a named digest**. It says nothing
  about memory safety, constant time, cryptographic correctness, or
  `SAFE_COMPATIBLE` graduation. A green cell would not discharge any obligation,
  and one of the cells is not green at all.
* The executed DSO is the O7 rebuild, not a build of HEAD; the source identity
  behind it is not tracked. The re-execution therefore confirms that the O7
  measurements are reproducible from the surviving work tree, not that the
  current source tree produces them.
