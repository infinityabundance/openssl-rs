# OpenSSH cohorts — which version backs which claim

**Item:** O1 of the Earned Trust Protocol work queue (`docs/ETP-TODO.md`).
**Status:** decision made; the reconciliation of the two historical populations is
O12, and this document does not substitute for it.

## The rule

OpenSSH results are **cohort-bound**. A result names the portable-OpenSSH
version, the tarball digest, the candidate identity that was linked, and the
build recipe it came from. Two cohorts' results are never combined, averaged,
subtracted or carried forward into one another's verdicts, and a claim measured
on one cohort is not evidence for the other.

This is the same rule the campaign already applies to candidate freezes
(`AGENTS.md` §22): evidence is bound to an exact identity, and an identity
change invalidates it rather than transferring it.

## Cohort A — OpenSSH 9.9p1 (primary)

| field | value |
|---|---|
| version | `9.9p1` (portable) |
| source | `https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-9.9p1.tar.gz` |
| source sha256 | `b343fbcdbff87f15b1986e6e15d6d4fc9a7d36066be6b7fb507087ba8f966c02` |
| recipe | `recipe:openssh:9.9p1` (client `recipe:openssh-client:9.9p1`, server `recipe:openssh-server:9.9p1`) |

What it backs today:

* the `SAFE_COMPATIBLE` graduation of `ssh`/`sshd` and its element-7 closure —
  the closure receipts are `forensics/memory-safety/campaign/safe-c33/evidence/closure-ssh-*.json`,
  which name `recipe:openssh:9.9p1` and artifact paths under
  `court/tmp/openssh-closure/client-*/openssh-9.9p1/ssh` (`b48` and later);
* the `L7-functional` rows for `openssh`, `openssh-client` and `openssh-server`
  in `forensics/downstream/runtime-functional-atlas.json`, which carry
  `recipe:openssh:9.9p1` (and the `-client`/`-server` recipes);
* the authority baseline record in
  `forensics/downstream/authority-baselines.jsonl`
  (`specimen:openssh:9.9p1`, `OpenSSH_9.9p1, OpenSSL 3.6.4`).

**Decision:** cohort A is the primary cohort for the interoperability campaign
(O2–O11). The four-cell matrix, the upstream `make tests` runs, the third-party
client cells and the algorithm-coverage rows are executed on 9.9p1 and their
receipts name it.

**Why:** the claim those items exist to substantiate is the `ssh`/`sshd`
graduation, and that graduation is a statement about 9.9p1. Interoperability
evidence measured on a different version would not attach to the claim it is
offered for; it would create a third population and a third reconciliation debt.
Choosing the version the claim already names is also the only choice that keeps
the evidence monotone: nothing already discharged has to be re-attributed.

## Cohort B — OpenSSH 10.5p1 (separate)

| field | value |
|---|---|
| version | `10.5p1` (portable) |
| source | `https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-10.5p1.tar.gz` |
| source sha256 | `d44d28a839ea9daf969cc69150fde59910b2b39361dad81a3bd6cbd19218db11` |

What it backs today:

* the Phase-17 downstream driver record (`courts/phase17/downstream/openssh/`),
  which starts a candidate-linked `sshd` and exercises a live handshake;
* the `CVE-2026-123158` analysis court, whose subject is authentication code
  (`auth-passwd.c`), not a libcrypto mechanism;
* the probe/unit-probe rows that name 10.5p1.

Recorded residuals of that cohort, which must not be read as cohort A failures:

* `regress/unittests/utf8` aborts on **both** the candidate and the authority
  because the court image ships no `en_US.UTF-8` locale — a harness limitation,
  recorded in the 10.5p1 corpus record and in `courts/phase17/downstream/openssh/result.json`;
* 10.5p1 predates the upstream fix for the `crypt(3)` `*`-prefix authentication
  defect (fixed in 10.6p2), so it says nothing about the authentication code's
  security. That is a property of the *version*, not of the candidate.

**Correction (O12).** An earlier version of this document listed a second
residual — `openssh-key-v1` RSA/ECDSA private keys rejected with
`error in libcrypto: initialization error`. That text appears in
`forensics/atlas/downstream-corpus.json` but **not** in the 10.5p1 record's
`known_residuals`, and `courts/phase17/downstream/openssh/result.json` lists it
as a *historical* failure fixed by commit `52b61567` ("evp: legacy-origin
EVP_PKEY signs/verifies — OpenSSH RSA/ECDSA fixed"). It was therefore a
witnessed-and-repaired defect, not an open residual of either cohort, and it is
withdrawn here rather than carried forward.

**Decision:** cohort B stays a separate cohort. Its results are reported with
their own version and digest and are never pooled with cohort A's. It is not
re-run merely to make the numbers look uniform.

## The contradiction this item found

`forensics/memory-safety/campaign/safe-c33/PROGRESS.md` states, in the
CVE-2026-123158 paragraph, that *"the campaign's OpenSSH L7 evidence was measured
on **10.5p1**"*. The closure receipts and the runtime-functional atlas say 9.9p1:
every `closure-ssh-*` receipt names `recipe:openssh:9.9p1` and every openssh
`L7-functional` atlas row carries the 9.9p1 recipe.

Both statements cannot be true of the same evidence. The receipts are the
primary records (they name the artifact path and the recipe), so this document
treats 9.9p1 as the L7 cohort and records the PROGRESS.md sentence as a
**provenance contradiction** to be resolved by provenance rather than by choice:

* if the PROGRESS.md sentence is simply imprecise about which population it
  describes (the CVE court is 10.5p1, the L7 closure is 9.9p1), O12 corrects the
  sentence and keeps both receipts as they are;
* if there exists an L7 measurement that genuinely ran on 10.5p1, it is a third
  population and must appear as its own row, not as the closure's evidence.

Neither record is relabelled to remove the conflict, and no verdict changes
until O12 has read the artifacts the receipts point at.

## What this means for the following items

| item | consequence |
|---|---|
| O2 | pins 9.9p1 (cohort A) as the primary tarball, alongside PuTTY and Dropbear, each by digest; 10.5p1's digest stays recorded for cohort B |
| O3 | the third-party tools are installed and detected for the 9.9p1 builds |
| O4–O7 | both builds, both `make tests` runs and the four cells are 9.9p1 |
| O8 | third-party clients against the 9.9p1 server, and the 9.9p1 client where the harness supports it |
| O9–O11 | coverage, negative controls and manifests name cohort A throughout |
| O12 | reconciles the two populations in one receipt and resolves the contradiction above |
