# PFP-57 receipt — carry-chain vs throughput, reconciled as hypotheses

**Decision: both explanations are hypotheses, not findings, and neither may
bound `M-A3` to `M-A6` until hardware performance counters exist.** The original
sentences in both receipts remain visible; the corrections sit beside them as
dated supersedes.

## 1. The contradiction, stated plainly

| receipt | conclusion | counterpart |
|---|---|---|
| `PFP-48/RECEIPT.md` §5 | "the loop is bound by the single `add`/`adc` carry dependency chain"; the stream arms "must attack the carry chain" | `M-A7` |
| `M-A7/RECEIPT.md` §7 | "the CIOS carry chain is not the dominant cost … the throughput floor, not latency, binds" | `PFP-48` |

Both cannot be the cause, and neither fits the data cleanly: PFP-48 cut 13 % of
the instructions and every workload got slower; M-A7 reduced dependency depth
with a carry-save accumulator and got 2.5–2.8× slower.

## 2. Supersedes added (original text preserved)

* `evidence/performance-frontier/campaigns/PFP-48/RECEIPT.md` §5 — a
  `PFP-57 SUPERSEDE` block after the verdict paragraph, and a second block after
  the "Implication for M-A3..M-A7" paragraph.
* `evidence/performance-frontier/campaigns/M-A7/RECEIPT.md` §7 — a
  `PFP-57 SUPERSEDE` block after the verdict paragraph.

Each block states: the measurement stands; the explanation is a hypothesis, not
a finding; the contradiction is named with the other receipt as counterpart;
the discriminating evidence is hardware performance counters — **port
utilisation, a top-down stall breakdown, dependent-chain occupancy** — and this
venue has none, so the question is open; no bound in `M-A3` to `M-A6` may rest
on either explanation until counters exist.

## 3. Downstream one-line notes (no bound may rest on either)

Added where a bound or conclusion rests on one of the explanations:

* Queue `PFP-48` row — dependency-chain route is a hypothesis.
* Queue `M-A3` to `M-A6` row — the "bound carried in from M-A7" is one of two
  unresolved hypotheses.
* Queue `M-A7` row — throughput explanation is a hypothesis; counterpart PFP-48.
* Queue "Reordering rationale, recorded 2026-11-27" — the rationale may not be
  used as a bound until counters exist.
* `M-A2/RESULTS.md` §4, `M-A2/BOUND.md` §1, `M-A2/RECEIPT.md` §1 — the
  latency-bound/throughput-bound attribution is a hypothesis.
* `M-A7/BOUNDS.md` §2 and §4, `M-A7/RECEIPT.md` §1 and §3 — the throughput-floor
  bound, the predicted figure, and the "mechanism of the refusal" are
  hypotheses.

The queue `PFP-57` row is marked `DONE` with this reconciliation recorded.

## 4. What would discriminate them

Hardware performance counters at the same digest and workload:

1. **Port utilisation** — whether the multiplier/add ports are saturated
   (throughput) or idle waiting on a serial carry (latency).
2. **Top-down stall breakdown** — the fraction of slots lost to
   `dependency`/`latency` versus `core`/`ports`.
3. **Dependent-chain occupancy** — measured latency against the modelled
   `~4n`-cycle diagonal versus the modelled throughput floor.

This venue exposes no PMU in the campaign protocol (the M-A2 and M-A7 receipts
record PMU `NOT_RUN`), so the contradiction is unresolved here.

## 5. Gate

Documentation only; no source changed. The full gate still reads
`cargo test --lib -- --test-threads=4`: **2564 passed, 0 failed, 56 ignored**
(run in the 4 GiB court in this batch).
