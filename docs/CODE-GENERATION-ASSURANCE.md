# Code-generation assurance policy

The crate's constant-time claims are claims about *emitted machine code*, not
about source text. Rust's documentation is explicit that `core::hint::black_box`
guarantees nothing about optimisation, and the compiler is free to turn a
branchless source expression into a branch. Every code-generation result
therefore has an identity, and that identity is what makes it evidence.

## What the evidence binds to

A code-generation result is valid only for the exact combination of:

| binding | current value |
|---|---|
| rustc | 1.98.1 |
| LLVM (via rustc) | as shipped with 1.98.1 |
| target triple | `x86_64-unknown-linux-gnu` |
| profile | release, `opt-level = 3` (default), `codegen-units = 16`, `lto = false`, `overflow-checks = true`, `panic = unwind` |
| linker and `cc` | `ld` / `gcc` 12.2.0 as recorded in the release receipts |
| the DSO measured | identified by SHA-256, never by version string |

`docs/ETP-TODO.md` T13 records the `-O3` machine-code test for the
`constant_time_select` family. `courts/phase18/timing/binary_branch_audit.py`
records per-function branch/division/cmov counts for a given DSO digest.

A result is not transferable to another target, another optimisation level,
another `codegen-units` value, or a build with LTO enabled.

## Invalidation rule

**Any change to any binding above invalidates every code-generation claim until
it is re-checked.** This includes:

- a rustc or LLVM update, including patch releases;
- changing `opt-level`, `codegen-units`, `lto`, `overflow-checks`, `panic` or
  `debug-assertions` in any profile that ships;
- a linker, `cc`, or system-library change that alters emitted code;
- enabling or disabling a target CPU feature that changes dispatch;
- any source change inside a function whose machine code was checked.

Invalidation is automatic and does not require a demonstration of impact. If
non-impact cannot be *proved*, the evidence is treated as invalid — the same rule
`AGENTS.md` §22 applies to candidate freezes.

## What re-checking means

1. Rebuild the release DSO and record its digest.
2. Run the machine-code test (`cargo test --lib runtime::constant_time`) at the
   shipping profile.
3. Run `python3 courts/phase18/timing/binary_branch_audit.py <dso>` and compare
   the per-function table against the last recorded one: a new conditional jump,
   a new division, or a lost `cmov` in a secret-bearing range is a finding until
   explained.
4. Re-run the dudect and ctgrind cases for any affected primitive.

## What this policy does not establish

It does not prove constant-time behaviour. A branch-free instruction stream can
still be variable-latency; division and memory accesses can depend on operands
without any branch at all; microarchitectural effects are outside it. It records
what was checked, for which binary, and what happens when the binary changes.

Post-LTO inlined callers, the curve448 and `bn/limbs` barrier sites, and callee
coverage have not been checked and are listed as open in `docs/ETP-TODO.md`.

## Binary-level extension (ETP-T6)

The binding and invalidation rules above cover emitted code for one artefact.
`docs/BINARY-ASSURANCE.md` extends them to the trusted computing base (compiler,
LLVM, assembler, linker, archiver, C library, loader, runtime, CPU dispatch and
venue) and to the per-target claim matrix. It adds the per-target fields this
document does not carry — target ABI, build profile and flags, artefact digest
and build id, artefact source identity, TCB digest and instrument-or-`NONE` —
and it refuses inheritance across targets or profiles. It does not weaken or
replace any rule here, and it does not turn reproducibility or instruction-shape
audits into a source-to-binary correspondence argument.
