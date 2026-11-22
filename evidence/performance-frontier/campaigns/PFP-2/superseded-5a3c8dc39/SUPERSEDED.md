# Superseded PFP-2 evidence

This directory preserves the samples produced by the parked work on
`wip/pfp2-p256-engine` (commit `5a3c8dc39`, based on `a3f7b277c`).

They are **superseded** and are not evidence for the landed PFP-2 candidate.

Why they were replaced rather than reused:

- The samples were taken from a dirty worktree before formatting, clippy and the
  test suite had run. The parked commit itself records that the first attempt
  measured a 22% regression and that the reported numbers were not verified.
- The parked `ARCH` kernel used the nine-fold Solinas reduction, so it measured
  roughly 3× slower than `MONT`; the landed engine gives `ARCH` the
  architecture multiply with Montgomery/REDC, and the kernel-selection point now
  honours the `OPENSSL_ia32cap` mask. The parked selection hard-coded `MONT`.
- The parked campaign compared the candidate only with the before-control
  (`a3f7b277c`), not with the admitted authority, so its ratio was not
  comparable with the PFP-0 `ecdsa256` row.
- The parked harness used a different `ecdsa256` workload (generated key, 32-byte
  digest, 8×5 iterations) from PFP-0's fixed key/digest at 500×5.

The fresh evidence is in `../performance/` and `../ctgrind/`, at the digest of
the landed candidate. These files are retained only so the retired branch's
claims can still be inspected.

Nothing in this directory is a measurement of the landed candidate.
