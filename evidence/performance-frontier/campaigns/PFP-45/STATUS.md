# PFP-45 — STATUS: NOT LANDED, implementation lost

**This file supersedes the impression given by `RECEIPT.md` in this directory. Read
this before the receipt.**

## What happened

`PFP-45` (reduce the DH secret exponent modulo the subgroup order) was implemented
and measured during the 2026-11-27/28 session. The receipt in this directory
records a green gate at **2611 passed / 0 failed / 56 ignored** and lists the
landed files.

That implementation **never reached the object database**. While the work was
uncommitted, the host ran out of disk and memory, and `src/bn/limbs.rs` was
truncated to **0 bytes** in the working tree. Committing the surviving tree —
which had to be done to avoid losing the rest of the session's work — recorded
the truncation rather than the file.

## What is actually lost

| item | state |
|---|---|
| `limbs::rem_consttime` (fixed-iteration binary long division) | **lost**. `git log --all -S'rem_consttime'` is empty; a scan of unreachable blobs in the plausible size band found zero occurrences. It was never staged. |
| `src/bn/mont.rs` gaining `order` / `reduce` parameters | **lost.** Only the call sites survive, and they do not compile against the certified `mont.rs`. |
| `src/dh/key.rs::dh_reduction_order` and its two tests | **lost.** |
| the three `limbs` tests and the two `dh/key` tests | **lost**; they account for the 2611-versus-2606 difference the receipt claims. |
| `forensics/atlas/implemented-surface.json` artefact hash `705be2c5…` | **orphaned.** No build on any branch reproduces it. |

## What survives and is useful

`RECEIPT.md` documents the intended contract in enough detail to redo the work
without guessing: fixed-iteration binary long division with a secret dividend and
a public modulus, result `< m`, width `= len(m)`, `Option` on allocation failure,
plus the ctgrind and branch-audit evidence that was gathered.

**The evidence in `RECEIPT.md` is therefore a design record, not a landed result.**
It must not be cited as a performance or security finding about the shipped
library, and the queue row stays `TODO` until the work is redone and gated.

## Why it is recorded rather than quietly deleted

A lost result that leaves a receipt claiming success is worse than a lost result,
because the receipt is what a future session reads. The measurement method and the
contract are worth keeping; the claim is not.
