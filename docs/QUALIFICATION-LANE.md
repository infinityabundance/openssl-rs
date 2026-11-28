# The qualification lane

`.github/workflows/ci.yml` is the development lane. It runs on every push to
every branch and sets `cancel-in-progress: true`, so on `staging` a fast stream
of pushes supersedes the previous run before its full acceptance suite has
finished. That is the right trade for development speed, and it is also why the
complete gate has not been observed finishing: the longest steps — the courts
and the re-derived regression guard — are the ones a later push interrupts.

A `BOUNDARY` or `SEAL` gate cannot run on a lane that may be superseded at any
moment. It needs a run keyed to a frozen source identity that is allowed to run
to completion.

`.github/workflows/qualification.yml` is that lane.

## Two lanes, two contracts

- **Development lane** (`ci.yml`, every push). Cheap regression checks, where a
  newer commit may supersede an older run. A green result here is development
  feedback, not a safety certificate.
- **Qualification lane** (`qualification.yml`, an explicit dispatch naming a
  full commit SHA, or a `qualif-*` tag). The full acceptance suite — the same
  commands `ci.yml` runs in its seal mode, verbatim — keyed to the qualified
  commit and never cancelled by a later commit.

The qualification lane's concurrency group is the qualified commit itself
(`qualification-<sha>`), and `cancel-in-progress` is `false`. A later commit has
a different SHA and therefore a different group, so it cannot cancel a frozen
candidate's run. The only way two runs share a group is re-qualifying the same
commit, and that queues rather than supersedes.

A candidate graduates only from the qualification lane. Its evidence is bound to
the exact commit that ran, not to a branch tip that has since moved.

## Frozen source identity, not evidence

Qualifying a commit checks out that commit and records the resolved SHA in the
job log and step summary. Committing evidence *about* a candidate — receipts,
atlases, ledger entries — does not change the candidate: an evidence commit is a
different commit with the same build-relevant inputs, and the candidate identity
the lane is keyed to is the source commit named at dispatch.

## Status

The lane has **not yet been exercised**. Its trigger, concurrency key and
checkout semantics are written to the contract above, but no run has been
observed completing, so no claim is made that it works until a frozen candidate
is dispatched and its run is seen to finish without cancellation.
