# External verification package — A24

**Status:** the package is built and verified **in this venue**. No party outside
this project has run it. The external status is `EXTERNAL_REVIEW_PENDING`, which
is not a pass.

**Implementation:** `forensics/tools/package_external.py`.
**Producer:** `evidence/a24/build_evidence.py`.
**Package:** `evidence/a24/PACKAGE/` (`verify.sh`, `verify.py`,
`PACKAGE-MANIFEST.json`, `README.md`, `PIPELINE.json` and the verifier inputs).
**In-venue run:** `evidence/a24/RUN.json`.
**External status:** `evidence/a24/STATUS.json`.
**Controls:** `evidence/a24/CONTROLS.json`.
**Tests:** `forensics/tools/tests/test_package_external.py`.

---

## 1. The problem

A run on the project's own machine is not external evidence. It shares the
candidate, the author, the working tree, the network and every private path. If
a recipient is handed a procedure that says "run `verify.sh` in the checkout",
the recipient has been handed a claim about this checkout, not a reproducible
package: the procedure may read `court/tmp`, an environment variable, a
site-packages module, another commit, or the network, and nothing in the result
distinguishes that from a self-contained run.

The package therefore has to be a **closed set of files** with a declared
entry point, a declared minimum interpreter, and a run that is refused when any
input is outside the set. The claim it supports is narrow and exact: *from these
files alone, this interpreter reproduces these records byte-for-byte*.

An in-venue reproduction is a self-reproduction. It is necessary (a package that
cannot reproduce on the producing machine cannot reproduce anywhere) and it is
not sufficient (Earned Trust Article 1: the claim may not exceed the evidence;
Article 5: a reproduction in the same trust domain is not independent).

---

## 2. The package contract

`build(paths, out)` writes a directory plus `PACKAGE-MANIFEST.json`. The
manifest is the package's identity and its contract:

| field | meaning |
|---|---|
| `members` | every file, sorted by path, with `role`, byte count and SHA-256 |
| `entryPoint` | `verify.py`; the exact program the recipient runs |
| `entryShell` | `verify.sh`; a parameter-expansion wrapper, no external command |
| `minimumInterpreter` | `3.11`, the project's documented Python minimum |
| `exactCommands` | `python3 verify.py`, `sh verify.sh`, `python3 verify.py --records <dir>` |
| `strippedEnvironmentCommand` | the `env -i` form with a one-entry `PATH` |
| `declarations` | `network: false`, `privateState: none`, `absolutePaths: false`, `untrackedFiles: false` |
| `records` | the four records the entry point must reproduce |
| `exclusionRule` and `excluded` | the rule and the files it excludes, with reasons |
| `refusalCodes` | every code this tool can emit |
| `outcomes` | the four outcomes |
| `packageDigest` | SHA-256 over the canonical manifest body without this field |

The manifest binds the member table and its own body (`packageDigest`). It is
not self-authenticating: a recipient must obtain the digest through a channel
it trusts, because a rewritten package can carry a rewritten manifest. The tool
detects an accidental or casual edit, not a deliberate forgery with a
recomputed digest; that limit is stated in §9.

The entry point has one contract: with `--records DIR` it writes
`SPEC.json`, `DIFFERENTIAL.json`, `PROPERTIES.json` and `CONTROLS.json` into
`DIR`, prints one JSON line, and exits 0 only when every produced record is
byte-identical to the packaged expected record. Before it runs anything it
checks the package against its own manifest: the manifest body must hash to
`packageDigest` and every member must match its recorded size and SHA-256. A
missing record, a tampered member, a crash and a nonzero exit are all failures.

Enforced by `EV_REFUSED_MISSING_INPUT`, `EV_REFUSED_MANIFEST_MISMATCH`,
`EV_REFUSED_PACKAGE_MUTATED`, `EV_REFUSED_ENTRYPOINT_FAILED`, and
`test_manifest_records_every_member_with_size_and_digest`,
`test_manifest_names_the_entry_point_and_interpreter`,
`test_the_manifest_is_bound_by_its_own_digest`,
`test_the_entry_point_checks_the_manifest`.

---

## 3. The stripped-environment rule

`verify(package_dir)` does not run the entry point in the caller's environment.
For each of two runs it builds a fresh temporary root, copies the declared
members into it, and runs

```
<interpreter> -I -S -B <audit driver> <unpacked package> <records> <result> <allowed roots>
```

with an environment of exactly five variables:

| variable | value |
|---|---|
| `PATH` | the interpreter's own directory, one entry |
| `HOME` | a fresh temporary directory |
| `TMPDIR` | a fresh temporary directory |
| `LANG` | `C` |
| `LC_ALL` | `C` |

No inherited variable is passed. `PYTHONPATH` is absent, not emptied. `-I`
isolates the interpreter from the environment and user site-packages, `-S`
removes site-packages entirely, and `-B` writes no bytecode into the package.
The result records `stripped: true`, `inheritedVariables: false`,
`pythonpath: null`, `pathEntries: 1` and the isolation flags.

The audit driver installs `sys.addaudithook` **after** importing its own
standard-library modules and **before** running the entry point. It records every
`open`/`os.open` whose resolved path is outside the package, the interpreter's
own library directories and the temporary run root, and it records writes
separately. A read outside that set is `EV_REFUSED_UNDECLARED_DEPENDENCY`; a
network module loaded at run time is `EV_REFUSED_NETWORK`.

Enforced by `EV_REFUSED_UNDECLARED_DEPENDENCY`, `EV_REFUSED_UNDECLARED_TOOL`,
`test_the_run_environment_has_one_path_entry_and_no_pythonpath` and
`test_a_hostile_environment_does_not_reach_the_entry_point` (which sets a
poisoned `PYTHONPATH` and a poison variable in the parent and requires the entry
point to observe neither).

---

## 4. No network, no private state: the structural tests

Two rules are checked structurally, before the entry point runs, over every
member's bytes:

* **No network.** Each `.py` member is parsed with `ast`; an `import` or
  `from … import` whose top-level module is a known network client
  (`socket`, `ssl`, `urllib`, `http`, `requests`, `ftplib`, `smtplib`,
  `telnetlib`, `xmlrpc`, `asyncio`, `httpx`, `aiohttp`, …) is
  `EV_REFUSED_NETWORK`. After the run, the audit driver also refuses if a
  network module entered `sys.modules` without a static import.
* **No private state.** Every member is scanned for `court/tmp`, an absolute
  private path (`/work/`, `/home/…`, `/tmp/…`, `/root`, `/var/tmp/`, `/mnt/`,
  `/opt/`), an environment token (`OPENSSL_RS_*`, `CARGO_*`, `RUSTUP_*`,
  `PYTHONPATH`) and an environment read (`os.environ`, `os.getenv`). A match is
  `EV_REFUSED_PRIVATE_STATE`.
* **No undeclared program.** A `.py` member that imports `subprocess`, `ctypes`,
  `multiprocessing` or `pty`, or calls `os.system`, `os.exec*`, `os.spawn*`,
  `os.popen` or `pty.spawn`, is `EV_REFUSED_UNDECLARED_TOOL`.

The tests assert, over the delivered package, that no Python member imports a
network or process module: `test_every_packaged_python_member_has_no_network_import`,
`test_the_scan_fires_on_a_socket_member`,
`test_the_scan_fires_on_a_subprocess_member`,
`test_the_scan_fires_on_an_os_system_call`,
`test_the_scan_fires_on_private_state`.

The scan is a text and AST scan over the declared bytes. It does not prove that
a computed string is not a URL, and it does not replace the audit hook: the hook
is the run-time observation, the scan is the structural guard.

---

## 5. The exclusion rule

> **Exclusion rule.** A file is packaged only when every input it reads is in the
> package and every program it executes is the declared Python interpreter. A
> file that needs the court container, the Rust toolchain, a C compiler,
> binutils, a shell script, a network service or private state is excluded and
> named with the reason it cannot run offline.

The rule excluded, in particular, `forensics/tools/adversarial_qualification.py`
and its E1–E3 fixtures. They were considered and are **not** packaged, because
they do not run on constructed inputs alone: `harness_binsec_verdicts` and
`harness_binsec_population` execute `courts/phase18/timing/binsec_checkct.sh`
under `bash` and call `compile_elf`, and `harness_branch_audit` calls
`require_tool("objdump")` and `compile_asm`; `compile_elf` and `compile_asm` call
`require_tool("cc")`. A package containing them would depend on a shell, a C
compiler and binutils, none of which is the declared minimum interpreter. The
same rule excludes `forensics/tools/etp6_package.py` (it calls git, the Rust
toolchain and the court), the E4 timing harness and its recorded receipt (it
compiles C and re-reads evidence this package cannot produce), `docker/`, all of
`src/` (no Rust build is in scope) and every evidence record that no packaged
verifier reads.

The excluded list is in the manifest (`excluded`) with a rule identifier and a
reason for each entry, and it is not a silent omission: it is the reason the
package is smaller than the tree.

Enforced by `test_the_exclusion_rule_is_stated` and by the manifest field
`exclusionRule`.

---

## 6. The real package and the in-venue run

The delivered package is the smallest set that exercises the project's own
admission machinery end to end without the court and without a Rust build:

| member | role |
|---|---|
| `forensics/tools/verifier_formalisation.py` | the A23 verifier: reference evaluators, differential, properties |
| `forensics/tools/policy_engine.py`, `thresholds.py`, `authorisation.py`, `corrections.py`, `dsse.py` | the implementation adapters the verifier imports |
| `evidence/a23/build_evidence.py` | the A23 producer |
| `evidence/a23/SPEC.json` | the frozen specification |
| `evidence/a23/DIFFERENTIAL.json`, `PROPERTIES.json`, `CONTROLS.json` | the expected records |
| `verify.py`, `verify.sh`, `README.md`, `PIPELINE.json` | the generated entry point, wrapper, instructions and pipeline |

Fifteen members in total: eleven declared inputs and four generated files. The
entry point runs the producer with `-I -S -B`, which recomputes the specification
digest, the four differential domains (75,607 compared cases), the seven
invariants and the ten controls, and compares the four produced records with the
packaged expected records byte-for-byte.

The in-venue run (`evidence/a24/RUN.json`) was made by

```
python3 forensics/tools/package_external.py verify evidence/a24/PACKAGE
```

which unpacked the package into two fresh temporary directories, ran the entry
point in each, recorded no read outside the package, compared **four records**,
found them byte-identical, and reported `PACKAGE_VERIFIED_IN_VENUE` with
`externalStatus: EXTERNAL_REVIEW_PENDING` and `externalPartyRan: false`. The
package digest, the interpreter version and the four record digests are in that
record and in the manifest.

Enforced by `test_four_records_were_compared_and_all_equal`,
`test_two_runs_were_made`, `test_the_run_record_is_in_venue_not_external`.

---

## 7. The external status

`evidence/a24/STATUS.json` states:

* **no external party has run this package**;
* the in-venue run is **not** external reproduction;
* `EXTERNAL_REVIEW_PENDING` is the status, and `isPass: false`.

A genuine external reproduction would require a party outside this project to:

1. receive the package and its digest through a channel it trusts;
2. unpack it in its own environment, with no access to this checkout;
3. run the declared command with its own interpreter at or above the minimum;
4. publish **its own** record naming the package digest it received, the digest
   of every record it produced, the interpreter and operating system it used,
   the command line and environment it ran under, its exit status, and any
   refusal code it observed;
5. sign that record with an identity in a trust domain distinct from this
   project's, and state how that domain is established (Earned Trust
   Article 5).

Until such a record exists, no external review may be claimed, cited or implied.
A claim of external reproduction is refused with `EV_REFUSED_EXTERNAL_NOT_RUN`;
the tool has no code path that turns an in-venue run into one. Verified by
`test_the_external_status_is_never_verified`,
`test_status_is_pending_and_not_a_pass`, `test_an_external_claim_exits_one_and_stays_pending`.

---

## 8. Refusal table

Every code is stable, is listed in the manifest, and has a `controlOnly`
control in `evidence/a24/CONTROLS.json`.

| code | condition | prevents |
|---|---|---|
| `EV_REFUSED_PRIVATE_STATE` | a member or the metadata names `court/tmp`, a private scratch path or an environment token | a package that only verifies on the producing machine |
| `EV_REFUSED_MISSING_INPUT` | a declared input is absent at build time, or a manifest member is absent at verification time | a package that silently omits a file and still reports success |
| `EV_REFUSED_ABSOLUTE_PATH` | a path is absolute, contains `..`, or is a symlink resolving outside the tree | a member that is really a path on the producing machine |
| `EV_REFUSED_NETWORK` | a member imports a network client, or the entry point loads one at run time | an offline claim that hides a network read |
| `EV_REFUSED_UNDECLARED_DEPENDENCY` | the entry opens a file outside the package and the interpreter's library, or a build path is outside the declared set | a package that needs this checkout or an undeclared file |
| `EV_REFUSED_MANIFEST_MISMATCH` | a member's bytes differ from its recorded size and SHA-256, or a produced record is not the expected record | a package whose contents or result differ from the identity it binds |
| `EV_REFUSED_REPRODUCIBLE` | two runs in fresh directories produce different output or records | a one-shot result the recipient cannot reproduce |
| `EV_REFUSED_UNDECLARED_TOOL` | a member imports or calls a program, or the interpreter is below the declared minimum | a dependency on a compiler, a shell or an undeclared tool |
| `EV_REFUSED_PACKAGE_MUTATED` | an undeclared file is present, or the manifest body no longer matches its digest | a package changed after the manifest was written |
| `EV_REFUSED_EXTERNAL_NOT_RUN` | an external run is claimed and no external party has produced a verdict | an in-venue run reported as external reproduction |
| `EV_REFUSED_UNTRACKED_INPUT` | a declared input is not tracked by Git at the candidate | a dependency on a working-tree file the candidate does not contain |
| `EV_REFUSED_ENTRYPOINT_FAILED` | the entry exits nonzero or raises before writing its records | a crashed verification read as a pass |

Two conditions share `EV_REFUSED_MANIFEST_MISMATCH` (member bytes and produced
records); the controls exercise both. Two conditions share
`EV_REFUSED_UNDECLARED_DEPENDENCY` (build path and run-time read); both are
exercised.

Outcomes:

| outcome | meaning |
|---|---|
| `PACKAGE_VERIFIED_IN_VENUE` | every check passed in the venue that ran it |
| `PACKAGE_UNVERIFIED` | the package is intact but was not run here |
| `PACKAGE_INVALID` | a refusal fired; nothing is established |
| `EXTERNAL_REVIEW_PENDING` | no external party has run it; not a pass |

CLI exit status is 0 for success, 1 for a refusal, 2 for a usage error, and the
code and outcome are printed on every path. Verified by the `CommandLine` class.

---

## 9. Boundaries: A12 (trust domains) and A17 (omission)

**A12.** A12 establishes independent cryptographic verification of envelopes: the
root of trust must be outside the candidate and selected by policy, and a
symmetric signature can never establish independence. A24 does not verify
signatures and contains no trust root. It supplies the *object* an external
reproducer would run and the *record shape* that party would publish; it does not
supply the independent trust domain. `STATUS.json` names that dependency rather
than asserting it, and this package's own work is not an A12 verification.

**A17.** A17 freezes an expected evidence manifest before execution and closes
with a signed reconciliation; a producer cannot pass by omitting a failed
result. The A24 manifest is a **package** manifest, not an A17 freeze: it binds
which files exist and what they hash to, not what evidence an execution was
expected to produce. A24 writes no reconciliation and no DSSE envelope, and it
does not amend `evidence/a17/FREEZE-forward.json`; it satisfies only the
member that freeze declares for this item (`evidence/a24/RECEIPT.md`). An
external party that ran A17's machinery over this package would be doing a
different check from the one recorded here.

Enforced by `test_the_boundaries_are_stated`.

---

## 10. Non-claims

* A passing in-venue run is **not** external reproduction and **not** an
  independent verdict (Article 1, Article 5).
* The package is **not** authenticated. Its digest is a content identity, not a
  signature; a rewritten package with a recomputed digest is not detected by
  this tool (Article 2 binds the claim to an identity, it does not make the
  identity unforgeable).
* The A23 differential is **not** a machine-checked proof, and the package makes
  no claim that it is (Article 7). A24 packages A23; it does not re-establish it.
* The package does **not** establish that any claim in the A23 records is true,
  that the records are the latest ones, or that the A23 verifier is sound on
  inputs outside its declared domains.
* The package does **not** contain the full surface named in the A24 queue row's
  aim (frozen claim-set manifest, native evidence, reconciliation, envelopes,
  statements, bundles, policy, release controls). It contains the verifier and
  the frozen records it reads. The rest is `NOT_RUN` and is not claimed.
* The static scan is not a sandbox. It refuses a package that names or imports a
  forbidden construct; it cannot prove the absence of a computed network call.
  The run-time audit hook is the observation that closes that gap for one run.
* The interpreter minimum is declared, not exhaustively tested. The in-venue run
  used the interpreter recorded in `RUN.json`; other versions are not covered.

---

## 11. `NOT_RUN`

* An external run by any party, in any environment (this is
  `EXTERNAL_REVIEW_PENDING`).
* An independent trust domain, an external signature, and any A12-style
  verification of the package.
* An A17 freeze and reconciliation **over this package**, and any signed
  closure of it.
* Execution on an interpreter other than the one recorded in `RUN.json`, on any
  other architecture, or on any operating system other than the recorded one.
* A delivery channel with an authenticated digest (publication, transparency log,
  timestamp).
* The full A24 surface: frozen claim-set manifest, native evidence, SARIF,
  envelopes, in-toto statements, Sigstore bundles, release policy and its
  controls.
* A proof that the package contains no defective code, and a sandboxed execution
  of untrusted package content.

---

## 12. Where the evidence is

| claim | record |
|---|---|
| the package exists with these bytes | `evidence/a24/PACKAGE/PACKAGE-MANIFEST.json` |
| the in-venue run passed, with a stripped environment | `evidence/a24/RUN.json` |
| the external status is pending, not a pass | `evidence/a24/STATUS.json` |
| every refusal code fires on a constructed input | `evidence/a24/CONTROLS.json` |
| the rules above are enforced | `forensics/tools/tests/test_package_external.py` |
