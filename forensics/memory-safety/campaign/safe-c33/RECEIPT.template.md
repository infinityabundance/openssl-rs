# Conversion receipt template

Copy this into `forensics/memory-safety/campaign/safe-c33/receipts/<TASK_ID>.md`
for each landed conversion batch. Fill every field with observed facts; write
`none` rather than omitting a field. A receipt is written by the conversion
engineer and must be *checkable* against the commit it names (AGENTS.md §15:
the agent that writes a safety claim is not the sole authority on whether its
evidence proves it).

---

```yaml
task_id:            # e.g. P25-X509-004
title:
phase:              25
stage_branch:       # e.g. stage/p25/x509-lu
source_identity:
  parent_sha:       # integrate/safe-c33 before the merge
  result_sha:       # the batch commit on the stage branch
authority_contract: # exact OpenSSL function(s) / ABI / spec boundary reconstructed

ownership_before:   # allocator, owners, aliases, release paths (the C shape)
ownership_after:    # the Rust type + lifetime structure that replaces it

mechanisms:         # one row per ownership mechanism touched
  - name:
    eliminated:     # assumptions now inexpressible (list)
    relocated:      # assumptions moved into one auditable boundary (list)
    hidden:         # MUST be 0; a non-zero value blocks graduation
unsafe_ops:
  removed:          # count + sites
  retained:         # count + the boundary each lives in
  introduced:       # count + the obligation each carries (must be justified)

boundary:           # the remaining unsafe trusted boundary and why it must exist
obligations:
  discharged:       # preconditions now established by callers / ABI contract
  retained:         # preconditions still owed, and by whom
  introduced:       # new proof obligations created by this batch

compatibility_delta:  # focused differential result vs the authority at result_sha
safety_checks:        # tests, Miri (model + scope), sanitizer, Kani/vector result
graduation:           # OWNERSHIP_RECONSTRUCTED | SAFETY_DISCHARGED (scoped) 
residuals:            # open findings, each with an explicit disposition
```

## Rules

- Never claim a check ran unless its output was read.
- `hidden` must be `0`; if one hidden obligation is found, report it and **block**
  graduation — do not reclassify it.
- `SAFETY_DISCHARGED` requires all three conditions of AGENTS.md §7 for the
  scoped mechanism, and the receipt must enumerate retained/introduced/unknown
  obligations.
- `SAFE_COMPATIBLE` for a consumer family requires the whole conservatively
  established dependency closure (AGENTS.md §7), not one shared mechanism.
- Record divergences with the AGENTS.md §17 classification.
