# PFP-3 — timing at the new digest: **NOT_RUN**

No timing figure is reported for PFP-3. The reason is an identity constraint, not
an omitted measurement:

* the preregistered timing campaign (`courts/performance-frontier/baseline/`
  analyser + `make_build_identity.py`) refuses a subject whose build-relevant
  source is not a **clean committed** tree (`build_relevant_clean` and
  `HEAD:src == source_commit:src`);
* this campaign is forbidden to commit, so the candidate is an uncommitted
  working tree (`src/ec/mult.rs`, `src/ec/p256.rs` modified; `fixed_base.rs`
  untracked);
* running the campaign with the identity guard bypassed would produce a number
  whose source identity is not established, which is exactly the failure mode
  `PERFORMANCE-FRONTIER-TODO.md` §22 exists to prevent.

Therefore the 15-repetition / `taskset -c 1` / paired-ratio / bootstrap-CI
campaign was **not executed** at DSO `04611380…`. The previously reported figures
(`ecdsa256` 18.83×, `ecdh` 226 µs, and PFP-2's 19.22× at `553e1b8c`) are at
**different digests**; no comparison, trend or speedup is claimed.

The differential and the two-build reproduction above are at the same DSO digest
and stand on their own; they are correctness and identity evidence, not latency.

To make timing admissible: commit the three source changes (a `stage/PFP-3`
branch is the campaign's own convention), rebuild from the clean commit, and run
`run_timing.sh` bound to that digest. Until then the timing conjunct is
`NOT_RUN`, and the PFP-3 row cannot be `DONE`.
