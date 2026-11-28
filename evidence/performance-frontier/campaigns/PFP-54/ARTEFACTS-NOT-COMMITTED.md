# PFP-54 — why the binaries are not committed

The audit was performed against two artefacts produced from one compilation:

| artefact | sha256 | bytes |
|---|---|---|
| shipped `libcrypto.so.3` | `a535454753d8857e4c385689ea431b5a47a9686322e6f52b203971188a49359f` | 12,342,512 |
| detached `libcrypto.so.3.debug` | `cd64dd590a597116f8475f6db0c81cc94602d74d540d4b45b4b1bae1a0b7ed9b` | 27,318,296 |
| `.text` (identical pre-split and shipped) | `9bf370d46142f2de2c6f62a7ef028c1203ccc3f24d27de78d8750c76b9a842fa` | — |
| build-id (identical in both) | `83eccb95e79216e5b53b46389df55fda6f9a9dee` | — |

**They are not committed.** 39 MB of rebuildable binaries per release is exactly the
growth the assessment warned against, and a digest in a receipt is the durable
identity — the bytes are reproducible from the recorded commit and flags by the
scripts in this directory (`build.sh`, `correspondence.py`, `resolve_extent.py`).

What *is* committed is everything that makes the audit checkable without the
binaries: the correspondence report, the resolved inlined extent, the full audit
report at the digest, the gate logs before and after, and the audit record.

**Consequence, stated plainly:** anyone re-running the audit must rebuild the two
artefacts and confirm the four hashes above before trusting the committed audit
report. If the hashes differ, the report does not describe their build and must not
be inherited — which is the same no-inheritance rule the kernel register already
enforces across targets, profiles and toolchains.

**The production build does not change.** `CARGO_PROFILE_RELEASE_DEBUG=1` was set
only for this audited build so the crate carries inlined-subroutine DIEs; the
shipped artefact is stripped of all `.debug_*` sections and the debug companion is
held as evidence, never packaged (`cargo package --list` names neither file).
