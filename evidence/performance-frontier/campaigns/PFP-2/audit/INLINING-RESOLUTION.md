# Inline resolution for `mod_exp_core_consttime_from_parts` (2026-11-26)

Supersedes the branch-audit paragraph of `../ctgrind/POST-FIX.md` §4 (which
recorded exit 1, 8 of 9 resolved). The other sections of that note are
unchanged. This note records the inlining evidence, the inventory mapping the
audit now supports, and what remains before PFP-2 could be a candidate.

## 1. Identity

| field | value |
|---|---|
| DSO | `court/tmp/pfp2-fix/distribution/libcrypto.so.3` |
| SHA-256 | `83f67826e2ca53dd8e014fe5442d2e77ba96ee7af35eeb78a312112a4e0a7c4f` |
| build ID | `ef860b61ec716042c749d01e9e7a97884b19de97` |
| source | `staging` `790685a0aa` + the PFP-2 worktree fix; only `src/ec/p256.rs` changed |
| audit | `courts/phase18/timing/binary_branch_audit.py`, objdump 2.40 |
| run | `openssl-rs-court-tools:1`, 8 GiB cap, `--expect-sha256` bound |

Before this change the audit exited 1 with

```
REFUSED target="Constant-time ladder core" symbol="mod_exp_core_consttime_from_parts" reason=missing
binary_branch_audit: FAIL-CLOSED: 1 of 9 expected targets were refused; this report is not a gate result.
```

The target was **not** deleted from the inventory. Deleting it would have
reduced coverage, which is the failure the check exists to prevent.

## 2. The inlining, from the artefact

### 2.1 No out-of-line body of the simple form

```
$ nm -S --defined-only court/tmp/pfp2-fix/distribution/libcrypto.so.3 | grep -E 'mod_exp_core'
0000000000342f10 00000000000005bc t _RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn5arith12mod_exp_core
0000000000345360 0000000000000691 t _RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn5arith42mod_exp_core_consttime_from_parts_prepared

$ strings -a court/tmp/pfp2-fix/distribution/libcrypto.so.3 \
    | grep -o 'mod_exp_core_consttime_from_parts[a-z_]*' | sort -u
mod_exp_core_consttime_from_parts_prepared
```

There is no symbol — and no string — for the 33-character identifier. The
v0 length-prefix rule is why: `33mod_exp_core_consttime_from_parts` is not a
suffix of `42mod_exp_core_consttime_from_parts_prepared`, so the prepared
symbol cannot be mistaken for it.

### 2.2 The wrapper's body is at the prepared entry, at the wrapper's call site

The wrapper is `src/bn/arith.rs:1854-1861`:

```rust
pub(crate) fn mod_exp_core_consttime_from_parts(ad, pd, md, declared_limbs) -> Option<Vec<Limb>> {
    mod_exp_core_consttime_from_parts_prepared(ad, pd, md, declared_limbs, None)
}
```

Its only non-test caller is `BN_mod_exp` (`src/bn/arith.rs:1421`), and that
caller calls the carrier directly, supplying the wrapper's constant `None`
(the extra argument is a zero tag), with no intervening symbol:

```
$ objdump -d --no-show-raw-insn --start-address=0x32a00c --stop-address=0x32a02a \
    court/tmp/pfp2-fix/distribution/libcrypto.so.3
  32a00c: sub    $0x8,%rsp
  32a010: lea    0x20(%rsp),%rdi
  32a015: mov    %rbx,%rdx
  32a018: mov    %r12,%r9
  32a01b: push   $0x0
  32a01d: push   %r15
  32a01f: push   %r15
  32a021: call   345360 <...42mod_exp_core_consttime_from_parts_prepared>
  32a026: add    $0x20,%rsp
```

All direct calls to the carrier, and where they are:

```
$ objdump -d --no-show-raw-insn <DSO> | grep 'call.*345360'
  32a021: call 345360 <..._from_parts_prepared>     # inside BN_mod_exp            (wrap: None)
  32af34: call 345360 <..._from_parts_prepared>     # inside BN_mod_exp_mont       (prepared: Some)
  32b41c: call 345360 <..._from_parts_prepared>     # inside BN_mod_exp_mont_consttime (prepared: Some)
```

The compiler reports the producer in the DSO's DWARF (`strings -a` finds
`clang LLVM (rustc version 1.98.1 (48a229cea 2026-09-01))` twice), so the
inlining decision is bound to the compiler that produced this artefact.

**What this establishes:** the wrapper has no out-of-line body; its only
reachable call site calls the carrier directly with the wrapper's constant
argument; therefore the body audited for "the constant-time ladder core" is the
body its call path executes.

**What it does not establish:** that the source was *inlined* rather than the
wrapper deleted and `BN_mod_exp` edited to the same call. Those produce the
same instruction stream and are indistinguishable here. This residual is stated
in the audit's docstring and in the report's mapping section; it is not hidden.

## 3. The mapping the inventory now declares

`TARGETS` (and the `--targets-file` JSON) admit:

```json
{
  "family": "Constant-time ladder core",
  "symbol": "mod_exp_core_consttime_from_parts",
  "resolves_to": "mod_exp_core_consttime_from_parts_prepared",
  "inlining": {
    "suffix": "_prepared",
    "caller": "BN_mod_exp",
    "constant_argument": "push $0x0",
    "producer": "clang LLVM (rustc version 1.98.1 (48a229cea 2026-09-01))",
    "check": "mod_exp_core_consttime_from_parts(..) is a one-line forwarder to "
             "mod_exp_core_consttime_from_parts_prepared(.., None); its only "
             "non-test caller BN_mod_exp calls the prepared entry with the None tag"
  }
}
```

The mapping is **consulted only when the intended symbol has no out-of-line
body**, and it is admitted only when the audit re-establishes, from the
artefact: `resolves_to == symbol + suffix` under the v0 length-prefix rule; the
carrier's extent and byte coverage; a unique declared caller whose own
disassembly is complete and which contains a direct call to the carrier; the
recorded constant instruction between the previous control transfer and that
call; and the producer string's presence in the DSO. Every failure has its own
refusal (`inline-witness-inconsistent`, `inline-carrier-missing`,
`inline-carrier-ambiguous`, `inline-caller-unverified`,
`inline-call-witness-missing`, `inline-constant-argument-missing`,
`inline-producer-absent`). The branch-counting rules, thresholds and violation
definitions are unchanged; the carrier is audited by exactly the same code.

When the intended symbol **does** have an out-of-line body the mapping is not
used and that body is audited (verified on `court/tmp/t19/libcrypto.so.3`,
`aaa32f21…`, where the row is the 4373-byte wrapper with 72 `jcc` and the
mapping is reported as "not used (out-of-line body present)").

## 4. Is any other target an inlining victim?

Survey of the 48 distinct `libcrypto.so.3` artefacts under `court/tmp/` and
`artifacts/` (18 inlined form, 21 out-of-line form, 9 neither), matching each
inventory target by the audit's own rule:

- **`mod_exp_core_consttime_from_parts` is the only target for which the
  inlining is observable.** It has no out-of-line body, and the carrier is
  present with the `BN_mod_exp` call site, on 18 artefacts (the `pfp0-refreeze`,
  `pfp1-build`, `pfp2-build/*`, `pfp2-{dbgrel,fix,recheck,run}` and `haz16`
  builds). On 21 other artefacts it is out-of-line (e.g. `aaa32f21…`,
  `78dec1c2…`, `69710a29…`); on 9 stale pre-refactor installs neither form
  exists. So the same source target alternates between out-of-line and inlined
  across digests — which is why the mapping is a fallback, not a replacement.
- **`p256::wide_mul_x86` has a second, different artefact on four
  kernel-variant builds** (`pfp2-build/{arch,default,mont,solinas}`): it is
  emitted as `...12wide_mul_x86.llvm.<hash>`, an LLVM-local copy, which the
  exact identifier match does not accept. Its body is present, under a name the
  inventory does not declare; those digests refuse the target rather than
  guessing. No mapping was added for them.
- `p256::mont_reduce_into` and the other six targets are absent only from
  builds that predate the code they name (the P-256 engine lands with PFP-2);
  they are never absent from a build whose source contains them.

The mechanism generalises to "the body survives under a name that is
`symbol + suffix` and is reached from a named caller". It deliberately does not
cover a body merged into a differently named function, or an LLVM-local copy
with a build-varying suffix: for those the audit refuses rather than inventing
a carrier.

## 5. Result at the current digest

Report: `post-fix-binary-branch-audit-inline-resolved.md` (stderr beside it).

```
binary_branch_audit: 9 expected targets resolved uniquely with complete
disassembly; 1 resolved through a verified inline mapping;
candidate sha256=83f67826e2ca53dd8e014fe5442d2e77ba96ee7af35eeb78a312112a4e0a7c4f
$ echo $?    # 0
```

Per-target counts for the P-256 kernels (unchanged counting rules; identical to
`post-fix-binary-branch-audit.md`):

| target | extent | insns | jcc | div | cmov | setcc | calls | the jcc |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| `p256::mont_reduce_into` | 1086 B | 296 | 2 | 0 | 0 | 2 | 0 | `+0x2ed je` (`test %r8,%r8`) and `+0x415 jne` (`dec %r8`) — the public `subtractions` loop bounds |
| `p256::wide_mul_x86` | 396 B | 112 | 0 | 0 | 0 | 9 | 0 | none |
| carrier of the ladder core | 1681 B | 427 | 42 | 0 | 2 | 4 | 20 | — |

No `div`/`idiv`, no `loop`, no `cpuid` and no dispatch-looking direct call in
any audited range; whole-DSO `cpuid` count unchanged at 29, none in range.

## 6. Negative controls

`forensics/tools/tests/test_binary_branch_audit.py`, 11 controls (fixtures built
from assembly with `cc -shared -nostdlib`):

| control | refusal |
|---|---|
| verified mapping (positive) | exit 0, report shows carrier **and** `(carries wrap)` |
| `resolves_to` names a symbol that does not exist | exit 1 `reason=inline-carrier-missing` |
| no `resolves_to`, symbol missing | exit 1 `reason=missing` (as before) |
| `resolves_to` names an existing unrelated symbol | exit 1 `reason=inline-witness-inconsistent` |
| carrier exists but the declared caller never calls it | exit 1 `reason=inline-call-witness-missing` |
| caller reaches the carrier without the constant | exit 1 `reason=inline-constant-argument-missing` |
| producer not in the DSO | exit 1 `reason=inline-producer-absent` |
| out-of-line body present | mapping unused; that body audited |
| `resolves_to` without `inlining`, or an unknown field | exit 2 (usage) |

Detection of control (c) "an existing symbol that is not the body" is
structural, not a guess: the name derivation rejects any symbol that is not
`symbol + suffix` under the v0 length-prefix rule, and the call-site witness
rejects a derived symbol the declared caller never reaches or the wrong call
site. A carrier that satisfies both *is* the body the intended call path
executes; beyond that, the inlined-versus-edited residual is the one stated in
§2.

## 7. Consequence for PFP-2

Passing the audit removes **`PFP2-BRANCH-AUDIT-INCOMPLETE`**: there is now a
passing branch audit at `83f67826…`, with the ladder core reached through a
recorded, re-verified mapping rather than dropped from the inventory.

It does **not** make the arm a candidate. `CANDIDATE` still needs

1. a timing measurement **at this digest** (`PFP2-POST-FIX-TIMING` is open; the
   recorded `ecdsa256` 18.69× is pre-fix and is not claimed here), and
2. a differential court **at this digest** (`../kernels/summary.json` and
   `../differential.json` are source-bound to `2004ea243`, not to
   `83f67826…`), and

and `PFP2-WRITEBACK-NORMALISE` remains an open residual (the write-back
`normalise` branch on the secret top limb, 4 engine-on-path contexts).

PFP-2 stays **`EXPERIMENT`**.
