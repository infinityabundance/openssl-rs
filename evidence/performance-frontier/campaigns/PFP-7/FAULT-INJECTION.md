# PFP-7 — fault injection in each CRT half and in the recombination

**Digest:** `6d002db2…` (unchanged; no source change was made, so this is the
protection of the build the row is about, not of a proposed optimised build).
**Harness:** `harness/pfp7_fault.c` → `raw/fault/{candidate,authority,verdicts}.txt`.

## What is injected

A hardware fault in one CRT half lands in the value that half contributes to the
recombination. The harness injects it where it lands — in the key component that
half consumes — on a fresh `d2i` of the same key:

| tag | injection | what a fault there corrupts |
|---|---|---|
| `halfA` | `dmp1 + 1` | the mod-`p` exponentiation result `r1` |
| `halfB` | `dmq1 + 1` | the mod-`q` exponentiation result `m1` |
| `combine` | `iqmp + 1` | the recombination step |
| `halfA+badD`, `halfB+badD`, `combine+badD` | the half (or recombination) **and** `d + 1` | the fault plus a broken fallback |
| `badD` | `d + 1` only | nothing on the CRT path, which does not read `d` |

Each case is run with blinding on and with blinding off. The observable is the
256-byte signature. **With a correct `d`, the only way the operation can return
the correct signature after a corrupted half is for the result check to reject
the CRT answer and the tail to fall back to the unblinded `d` exponentiation.**
Returning the corrupted CRT value is an undetected fault.

## The matrix

| injection | blinding on | blinding off |
|---|---|---|
| `halfA` (`dmp1+1`) | **DETECTED** (== clean) | **DETECTED** |
| `halfB` (`dmq1+1`) | **DETECTED** | **DETECTED** |
| `combine` (`iqmp+1`) | **DETECTED** | **DETECTED** |
| `halfA+badD` | EXPECTED_WRONG (blinding-dependent bytes) | EXPECTED_WRONG (= `m^(d+1) mod n`) |
| `halfB+badD` | EXPECTED_WRONG | EXPECTED_WRONG |
| `combine+badD` | EXPECTED_WRONG | EXPECTED_WRONG |
| `badD` (CRT intact) | NO_FAULT_UNCHANGED (== clean) | NO_FAULT_UNCHANGED |

`VERDICT PASS`. No case is undetected.

The `+badD` controls are what makes the DETECTED rows meaningful: they show the
same corruption *is* observable, so "equals clean" cannot be an accident of the
`+1` being a no-op.

* With blinding **off**, all three `+badD` cases return the **same** wrong value,
  and it equals `m^(d+1) mod n` computed independently in Python
  (`faf85e8f3172c566`): the fallback really is the `d` exponentiation.
* With blinding **on**, the three wrong values differ from each other and from
  the authority's, because unblinding `(I·A)^(d+1)` leaves an `A^d` factor: the
  returned bytes carry the independent, random blinding factor. Those three
  cells are therefore **not comparable across implementations by construction**;
  every other cell is byte-identical to the authority (0 cross-implementation
  mismatches over the 15 comparable lines).

## What this establishes, and what it does not

Established: the result check catches a corrupted `p` half, a corrupted `q`
half and a corrupted recombination, with and without blinding, and the fallback
returns the correct value; a fault in `d` alone changes nothing on the CRT path,
as expected.

Not established: this is an injected *component* fault, not a hardware
bit-flip inside the multiply chain, and it does not test double faults that
agree modulo `n`. It is the row's acceptance dimension ("each half and the
recombination"), measured at the digest.
