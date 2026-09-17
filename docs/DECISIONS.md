# Decisions

Status: append-only. Each entry records a decision that changes the contract or
the evidence machinery, and why. Superseding an entry requires a new entry.

**Decisions never assert current status.** Where an entry quotes a count, a
census or an observation, that is a record of what was observed *at the time the
decision was made* — evidence of the reasoning, not a claim about the present.
Current counts are derived exclusively from `forensics/STATUS.md` and the atlas,
never from this file. See D15 for the worked example of why this matters.

---

## D1 — Authorities: 3.6.4 production, 3.6.3 historical

**Decision.** Admit `openssl-3.6.4-production` (production) and
`openssl-3.6.3-historical` (historical).

**Why.** 3.6.4 is a security-fix release in the 3.6 series and is the correct
production target. 3.6.3 is retained because extant downstream archaeology
(bind9-rs) observed it, and because a historical authority is what makes the
3.6.3 → 3.6.4 oracle-vs-oracle trajectory court possible
(`docs/SECURITY_DIVERGENCE_POLICY.md`). Shipping behaviour pinned to 3.6.3 would
mean shipping known-fixed defects.

**Consequence.** A claim never generalises across authorities silently.

---

## D2 — Authority acquisition fails closed, and guards non-archive responses

**Decision.** `authority_acquire.py` refuses admission on checksum mismatch, and
additionally rejects any artifact that is not a plausible gzip release archive
before checksum checking.

**Why (recorded incident).** The initially configured URL
`https://mirror.openssl-library.org/source/openssl-3.6.4.tar.gz` returned a
**31 KB HTML page**, not the 55 MB archive; the mirror's `/source/` index links
the real asset on the GitHub release host. The HTML page's digest naturally did
not match the published digest. Two guards now exist so a wrong-URL response is
reported as a *content* error rather than as a confusing checksum mismatch:
archive magic bytes (`1f 8b`) and a minimum-size sanity floor, in addition to the
authoritative checksum gate.

**Consequence.** `validate_archive()` runs before checksum verification; the
checksum remains the authoritative gate.

---

## D3 — One crate; `rlib` only until Phase 2

**Decision.** One Cargo package, one implementation crate, `crate-type = ["rlib"]`
for now.

**Why.** The distribution artifacts (`libcrypto.so.3`, `libssl.so.3`, static
archives, provider modules, headers, pkg-config metadata, `openssl` executable)
must be emitted from the single implementation, but emitting them requires
export/version-script machinery and ABI courts that do not exist yet. Producing
artifacts now would be a claim without evidence, which
`docs/CUSTODIAN_CONTRACT.md` §5 forbids.

---

## D4 — Court container with a known, guarded contaminant

**Decision.** All execution happens in `openssl-rs-court` (image
`openssl-rs-court:1`), with `--memory=8g --memory-swap=8g` (OOM kills inside the
container, not the host), `--pids-limit=2048`, `--cpus=8`, `--restart=no`.

**Why.** The requirement is that no test runs on the host. `libcurl4` (needed for
`curl`/`git`) links `libssl3` 3.0.x, so a Debian userspace cannot be free of a
non-authority OpenSSL runtime.

**Consequence.** The non-authority `openssl` CLI binaries are deleted and the
build asserts `! command -v openssl`. The package is *not* purged, because
`ca-certificates` depends on it for its trust-store trigger and purging would
remove the trust store. The remaining `libssl3`/`libcrypto3` objects are recorded
as a known contaminant and courts must prove non-contamination; a produced
artifact resolving to a non-authority OpenSSL is a hard failure.

---

## D5 — The atlas is scoped per authority

**Decision.** Atlas outputs live at `forensics/atlas/<authority>/...`, not flat.

**Why.** A claim is always a claim *of a specific authority*. A flat layout would
allow the last-generated authority to silently overwrite another's evidence.

---

## D6 — `.num` condition grammar is four fields

**Decision.** Parse a `.num` condition as `STATUS : PLATFORM : KIND : CONDS`.

**Why.** The earlier two-field reading (`STATUS::KIND:CONDS`) mis-parsed
platform-scoped entries such as `EXIST:VMS:FUNCTION:OCSP`, which then appeared as
unexplained absences. Modelling `status` and `platform` explicitly is what stops
a *correct* absence from being reported as a defect. `NOEXIST` entries (for
example `ERR_put_error`, `OPENSSL_memcmp`) are declared and deliberately not
exported.

---

## D7 — The generated version script is the exclusion-explaining plane

**Decision.** Reconcile `.num` (source promise) against the build-generated
`libcrypto.ld` / `libssl.ld` (profile-specific promise) against the DSO exports.

**Why.** Guessing build-profile exclusions from condition strings is fragile. The
generated version script is produced by `util/mkdef.pl` filtered through the
actual configuration, so `num \ version_script` is *exactly* the set of exclusions
this build made. Result for the production authority: `.ld` (5896) equals DSO
exports (5896) exactly; all 53 absences are explained; zero hard residuals.

---

## D8 — ELF version-definition ABS markers are not API symbols

**Decision.** Exclude `.dynsym` entries with `Ndx=ABS` named `OPENSSL_3.x.y` from
the exported-API plane; record them separately as the version namespace identity.

**Why.** The linker emits one absolute OBJECT symbol per version node. Treating
them as API symbols produced 10 phantom "exported but undeclared" residuals
(`nm` shows them as `A`).

---

## D9 — Clang location elision requires stateful reconstruction, and macro
declarations are attributed to their expansion site

**Decision.** Reconstruct source locations with a stateful tracker that absorbs
clang's printed locations in print order; attribute macro-generated declarations
to the expansion location.

**Why.** `clang -ast-dump=json` omits `file` when unchanged, so a stateless reader
saw only 30 functions instead of ~7,485. Macro-generated declarations (for example
`X509_it` via `DECLARE_ASN1_*`) have `spellingLoc = <scratch space>` and a real
`expansionLoc` in the public header; attributing to the invocation site is both
correct and necessary.

---

## D10 — Panic strategy is `unwind`, not `abort`

**Decision.** The release profile keeps the default `panic = "unwind"`.

**Why.** `openssl-rs` is a library. With `panic = "abort"` the FFI unwind boundary
could not catch anything, and an internal defect would abort the *caller's*
process rather than return the function's documented failure value. The boundary
in `src/ffi/mod.rs` converts a panic into that failure value, satisfying
`docs/UNSAFE.md` §3.

---

## D11 — Status is generated, never typed

**Decision.** `forensics/STATUS.md`, `PARITY_MATRIX.md` and every headline figure
are generated from the atlas and receipts.

**Why.** `docs/NON_CLAIMS.md` §1 forbids hand-written status and hand-typed
completion percentages. A figure that cannot be regenerated is not evidence.

---

## D12 — Clang AST is the declaration plane, not regexes

**Decision.** Mine the public API surface through Clang, not regular expressions.

**Why.** The Phase 1 requirement is to cross-check headers against the AST against
DSO exports against `.num`. Regexes cannot resolve typedefs, attribute placement,
macro-expanded declarations or nested records. Consequences discovered by doing
it properly: 1,001 of the 1,012 declared-but-not-exported functions are
`static ossl_inline` header helpers (correctly not exported), and 26 exported
symbols (`DSO_*`) have no declaration in any *installed* header because `dso.h`
is not installed.

## D13 — Phase 1 sensitivity evidence is partial, and the gap is recorded, not hidden

**Decision.** Phase 1's FRF courts are recorded as follows:

- `openssl-cli-dgst` — challenge **PASSED** for both `stdout-first-line` and
  `exit-class`: each seeded defect was observed on its declared axis and on no
  other. This court has sensitivity evidence and may supply release evidence.
- `openssl-cli-list-disabled`, `openssl-cli-list-cipher` — challenge **REFUSED**.
  Cause established by inspection, not guessed: the FRF 0.1.86 challenge mutant
  locates the reference object by scanning its own arguments for a path under
  the object store, which only works when the court's declared arguments
  reference `{fixture}`. For these courts the mutant cannot find the reference,
  exits 2 with empty stdout, and therefore perturbs **both** the stdout and exit
  axes at once. The court cannot demonstrate axis isolation, so FRF refuses.

  The four resulting residuals are disposed `harness` with that reason.

**Why not "fix" it by narrowing the declared observables.** Declaring only
`stdout` for these courts would make the challenge *pass* on a mutant that never
ran the reference — a false sensitivity result. A passing court that cannot see
its own defect class is worse than an honestly refused one
(`docs/PARITY_MODEL.md` §7).

**Consequence.** Phase 1's exit rule requires sensitivity evidence, so Phase 1 is
**not** marked complete. The concrete remedy is to make every trajectory court
fixture-driven (arguments that reference `{fixture}`), which is also better
forensic practice: a court should be a statement about a fixture family. Until
then, the `list-*` courts are retained as *observations* but may not contribute
sensitivity evidence to a claim.

---


---

## D14 — Exporting a versioned ABI from Rust requires a two-stage build

**Decision.** The Phase 2 DSOs are built as `rustc --crate-type staticlib`
followed by a `cc -shared` link with `--whole-archive` and the generated version
script — never as a `rustc --crate-type cdylib` in one step.

**Why (two separate linker traps, both of which produce a DSO that looks right
and resolves wrongly).**

1. rustc's default bundled linker is **rust-lld**. Given a version script it
does not fail; it warns:

   ```
   rust-lld: attempt to reassign symbol 'EVP_DigestInit_ex' of VER_NDX_GLOBAL
             to version 'OPENSSL_3.0.0'
   ```

   and emits an **unversioned** library that still exports all 5,896 names. A
   symbol-count check passes; only versioned resolution fails.

2. Switching to GNU ld via `-C linker=cc` exposes the second trap: for
   `--crate-type cdylib`, rustc injects its **own anonymous version script**, and
   GNU ld refuses to combine an anonymous tag with named ones:

   ```
   /usr/bin/ld.bfd: anonymous version tag cannot be combined with other version tags
   ```

**Consequence.** The build is two stages, and `local: *;` must be emitted into
the version script's final node. The authority's own script carries it; omitting
it leaks the Rust runtime's symbols, because a `--whole-archive` link pulls them
in.

These are recorded because they are exactly the class of defect the Phase 2
courts exist to catch: `ABI-SYMBOL` alone would have passed on the rust-lld
artifact. Only `ABI-LOAD`, which resolves each symbol *at its declared version*
with `dlvsym`, distinguishes the two.

---

## D15 — Supersedes D7's *observed census*; D7's methodological decision stands

**Decision.** D7's methodological decision is not changed and remains in force:

> the generated version script (`libcrypto.ld` / `libssl.ld`) is the
> build-profile-specific exclusion plane, and `num \ version_script` is exactly
> the set of exclusions this build made.

**What is superseded.** D7's *quoted counts* (`generated .ld = 5896`,
`DSO exports = 5896`, `53 absences`) were libcrypto-only figures captured at an
earlier point in the archaeology, and they are not current status. The generated
reconciliation reports per-plane totals across **both** libraries (5896 + 603 =
6499), so a reader comparing D7 against `forensics/STATUS.md` sees two different
numbers for what sounds like the same thing.

D7 is deliberately **not rewritten**: it records the reasoning and the state of
knowledge at the time, and that record is itself evidence. Instead:

* this entry marks the census as superseded;
* the file header now states that this file never asserts current status;
* current counts are derived from `forensics/STATUS.md` and the atlas only.

**Why this is recorded rather than fixed silently.** It is the epistemology the
project is built on, made visible:

```
decision  -> remains true (a choice, defended on its reasons)
observation -> evolves (a measurement, true at its time)
```

A decision log that quietly edits its own numbers to match the present destroys
the ability to tell which reasoning was based on which observation. The rule is
therefore: **decision remains true; observation evolves; neither is restated as
the other.**

---

## D16 — The FFI unwind boundary is unconditional

**Decision.** `guard_ffi` always catches a panic and never resumes it. Its
behaviour does not vary with `debug_assertions`, build profile, environment, or
whether a test is running.

**Supersedes** the earlier behaviour, described in the same file at D10-adjacent
prose, in which debug builds re-raised the panic so that a defect on the FFI path
would fail tests loudly.

**Why the earlier design was wrong.** The *want* was correct — a panic on the FFI
path should never pass unnoticed — but the *mechanism* was not: it meant the
control-flow edge "unwind into C" existed in exactly one configuration, so the
invariant `no Rust panic may unwind through a C ABI boundary` held only where the
stakes were lowest. A boundary whose unwind behaviour varies by configuration is
not a boundary.

**What replaces it.** The boundary always catches, increments a process-wide
counter (`openssl_rs::ffi::panics_caught`), writes a fixed diagnostic to `stderr`,
and returns the documented failure value. Tests assert that the counter moved and
that the call *returned* rather than unwound. A `#[cfg(test)]`-only
`propagate_for_test` helper preserves payload-level assertions for pure-Rust call
paths.

**Residual (recorded, not hidden).** The panic payload is dropped, because
`PanicHookInfo` payloads are not ABI-stable and cannot cross into C. Phase 3 will
surface the condition through the thread-local `ERR` queue, which is what an
OpenSSL caller expects to find after a failure. This is tracked as an open
obligation in `forensics/atlas/phase1-completeness.json`.

---

## D17 — The Gemel store is not committed to git, by Gemel's own design

**Decision.** `.gemel/` is left uncommitted. What is committed is the *projection*
(`forensics/GEMEL_TRAJECTORY.md`, generated from `gemel log` / `gemel status`)
plus the change, trajectory and checkpoint identities recorded in this file and
in `docs/PHASE-1-ARCHAEOLOGY-SEAL.md`.

**Why.** Gemel ships its own `.gemel/.gitignore` containing `*`. The store is
therefore excluded from git *by design*, not by oversight: it is meant to travel
through Gemel's own mechanisms (`gemel remote` / `push` / `exchange`) and to be
projected into git deterministically with `gemel export-git` (Phase 4). Forcing
it in with `git add -f` would mean committing ~95 MB of content-addressed blobs
and fighting the tool's interop design.

**Correction of the record.** The commit `d368245` message states that "the
Gemel store is now committed". That statement is **false** and was written before
the nested `.gemel/.gitignore` was discovered. It is corrected here rather than
by rewriting pushed history: the project's own rule is that an observation
evolves and the record of it stays.

**Consequence.** `docs/RELEASE_GATES.md` §2's "Gemel checkpoint" requirement is
satisfied by a checkpoint *existing* and being legible, not by the store being in
git. Whether the sealed evidence should also include a deterministic
`gemel export-git` projection is deferred to Phase 4, which owns that mechanism.

**Contrast with FRF.** `.frf` **is** committed, because FRF's receipts and claims
are the claim-bearing evidence and FRF expects them to travel. The two tools have
opposite interop models; this file records both rather than assuming consistency
between them.

---

## D18 — ERR string text comes from the compiled `*_err.c` arrays, not `openssl.txt`

**Decision.** `gen_err_strings.py` takes each library's reason **text** from the
checked-in `*_err.c` array the library actually compiles, and each reason's
**code** from the header (`include/openssl/*err.h`, `include/crypto/*err.h`, …)
that the array's macro expands against. `crypto/err/openssl.txt` is no longer an
input at all.

**Why.** `openssl.txt` is the *input* to `util/mkerr.pl`; the `*_err.c` files are
what ships compiled, and a released tree can have them out of sync. Measured with
the RT-ERR court against the admitted authority:

```
openssl.txt                     : BIO_R_LOCAL_ADDR_NOT_AVAILABLE:111:local addr not available
crypto/bio/bio_err.c            : { ERR_PACK(ERR_LIB_BIO, 0, BIO_R_LOCAL_ADDR_NOT_AVAILABLE),
                                    "local address not available" }
openssl.txt                     : BIO_R_PEER_ADDR_NOT_AVAILABLE:114:peer addr not available
include/openssl/bioerr.h        : #define BIO_R_PEER_ADDR_NOT_AVAILABLE 151
```

A caller sees the compiled text at the header's code. Taking either value from
`openssl.txt` produces a table that is wrong for 74 entries — 72 descriptions and
2 codes — which the court reports as residuals rather than hiding.

**Consequence.** The generator fails closed if an array references a symbol no
installed header declares. The array's file is found by content, not by filename,
because 3.6.4 spells three of them `pkcs7err.c`, `pk12err.c` and `v3err.c`.

---

## D19 — The ERR string registry is modelled as loaded state, not a compiled table

**Decision.** `ERR_lib_error_string` and `ERR_reason_error_string` consult a
per-process load state: a bit per library plus a flag for the generic tables.
Nothing is visible until a loader has run.

**Why.** The authority's `int_error_hash` starts empty. `ossl_err_get_state_int`
creates a thread's `ERR_STATE` and then calls
`OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS)` — with the comment
"Ignore failures from these" — which loads the generic tables and every library in
`ossl_err_load_crypto_strings`. Two further facts follow from the same code:

* `err_all.c` skips `ossl_err_load_SSL_strings` on purpose, so all 357 SSL reasons
  are NULL until `OPENSSL_INIT_LOAD_SSL_STRINGS` is processed;
* `OSSL_DECODER` and `OSSL_ENCODER` ship compiled arrays that **no** loader in the
  crypto set loads, so those 6 reasons are always NULL.

All three were measured, not inferred: before any ERR call on a thread,
`ERR_lib_error_string(ERR_PACK(3,0,0))` returns NULL even though BN's table is
compiled in, and `ERR_error_string` renders the numeric fallback. The RT-ERR
probe asserts the before/after state on both sides.

**Consequence.** `ERR_load_<LIB>_strings` stops being a no-op. It loads the generic
tables plus that library, which is what the authority does through
`ERR_load_strings_const` and `ossl_err_load_ERR_strings`. Those 31 entry points are
now generated rather than hand-written.

**Supersedes** the Phase 3 seal's earlier §5 note that the reason tables were
"not yet generated" and that `ERR_reason_error_string` returning NULL was a known
deviation. That note is removed, not softened.

---

## D20 — ERR records reproduce the authority's source coordinates exactly

**Decision.** Every error the runtime raises carries the authority's own
`OPENSSL_FILE`, `OPENSSL_LINE` and `OPENSSL_FUNC`, derived by
`forensics/tools/gen_err_raise_sites.py` from the pinned source and the admitted
build record.

**Why.** `ERR_raise` is a macro:
`(ERR_new(), ERR_set_debug(OPENSSL_FILE, OPENSSL_LINE, OPENSSL_FUNC), ERR_set_error)`.
`ERR_get_error_all` hands all three to the caller and `ERR_print_errors` prints
them, so they are observed contract. Two alternatives were considered and
rejected:

1. *Leave them empty.* That is a measurable divergence with no benefit, and the
   earlier code did exactly this for `ex_data.c` and `init.c`.
2. *Store the intrinsic path and normalize the build prefix away in the court.*
   This would make the court's verdict depend on a normalizer, when the value is
   reproducible exactly.

The `__FILE__` prefix is computed as `relpath(source_tree, build_dir)` from the
build record rather than typed, because the authority was built out of tree and
`__FILE__` is the source path as spelled on the compiler's command line. A
different admitted build therefore yields a different, still-correct prefix.

**Consequence.** The candidate's error records compare byte-for-byte with the
authority's, and the derivation is data-driven: 14 sites today, and the same
generator covers later phases by adding the files whose sites that phase
reconstructs. Two arms (`stack.c:212`, `stack.c:275`) need on the order of a
billion elements to reach; their conditions are reproduced and the probe records
the boundary rather than claiming them.

---

## D21 — Phase completion requires an obligation ledger with explicit deferrals

**Decision.** A stratum may only derive `complete` when every export in its
symbol families is either implemented or listed in a ledger with the phase that
owns it and a reason. For Phase 3 that ledger is
`forensics/phase3-obligations.json`, produced by
`forensics/tools/phase3_obligations.py`, which **fails closed**: an export in a
Phase 3 family that is neither implemented nor deferred makes the generator exit
non-zero, so `forensics/phase-state.json` cannot report `complete`.

**Why.** "Either the phase is finished or it is not" is not honest when a
subsystem genuinely depends on a later one. Eleven Phase 3 symbols need a `BIO *`
or a `FILE *` (`ERR_print_errors*`, `ERR_add_error_mem_bio`, the six
`OPENSSL_LH_*stats*`, `OBJ_create_objects`), and BIO is Phase 4 by the same
ordering that puts ERR in Phase 3. Left unstated, that would read as an oversight;
stated in a hand-written list, it would rot silently. A machine-checked list that
fails closed is the only version that stays true.

**Consequence.** `phase-state.json` now carries a `deferred` field per stratum and
`phase-state.md` prints it beside the status. A deferral is not a parity claim and
does not soften any obligation; the symbols stay `SCAFFOLDED` and abort.

---

## D22 — The `ABI-SYMBOL` court does not compare prototypes, and that gap is recorded

**Decision.** `ABI-SYMBOL` continues to compare name, ELF symbol version, type,
binding and visibility. It does **not** claim to compare C prototypes, and the
Phase 3 seal says so explicitly.

**Why.** The RT-ERR probe found a real defect of exactly this class: the legacy
error getters were defined through one five-parameter macro while the installed
headers declare one, two or four parameters. Every symbol involved had the right
name, version, type, binding and visibility, so `ABI-SYMBOL` passed while a caller
following the header would read and dereference garbage. The differential probe
caught it because it *called* the functions as declared; the symbol court
structurally cannot.

**Consequence.** The class is not claimed closed. A declaration-vs-definition
arity check is recorded as an open obligation for the phase that owns the header
generator. Until then the seal states the gap rather than letting "symbols match
exactly" be read as "signatures match exactly".

---

## D23 — Phase 4's ledger separates hand-offs from open work, and the phase stays `in-progress`

**Decision.** `forensics/tools/phase4_obligations.py` enumerates the Phase 4
families (`BIO_`, `BUF_MEM_`, `CONF_`, `NCONF_`, `OBJ_create_objects`, the
`OPENSSL_LH_*stats*` family, `ERR_print_errors*`, `ERR_add_error_mem_bio`) and
sorts every export it cannot find implemented into exactly one of two lists:

* **deferred** — a subsystem a later stratum owns, with the owning phase and the
  reason (`BIO_f_md` → Phase 7, `BIO_f_asn1` → Phase 5, `BIO_s_core` → Phase 6, …);
* **open** — a symbol of *this* stratum that is not built yet.

`complete` is true only when both lists are empty, and `phase_state.py` treats
`open_in_this_stratum > 0` as a blocker.

**Why.** Phase 3's ledger could defer its handful of BIO-coupled symbols and still
be complete, because the stratum that owned them existed. Phase 4 owns BIO, CONF
and the buffer object — a 256-symbol surface — and inherits fourteen hand-offs from
Phase 3. Collapsing "not built yet" into "deferred" would let a partial stratum
report as finished, which is the exact failure mode the constitution forbids.

**Consequence.** Phase 4 is recorded `in-progress` with its real count: 123 of 256
family exports implemented, 14 handed to later strata, 119 open. None of the 123 is
a parity claim; every one is at most `IMPLEMENTED`, and no Phase 4 court has been
run yet, which `phase_state.py` also reports. The alternative — a hand-written
summary in a seal document — was rejected for the same reason D21 rejected it for
Phase 3.

---

## D24 — BIO archaeology used the pinned source, and the Rust is reasoned from behaviour

**Decision.** The BIO core (`src/runtime/bio/`) reproduces the authority's
observable behaviour by reading the pinned authority source in
`forensics/authorities/src/openssl-3.6.4/` for *archaeology* — the dispatch
classes, the callback translation between the modern and deprecated forms, the
`init` gate, the two read/write contracts, the chain-walk shapes — and then writing
Rust reasoned from those behavioural obligations. It is not a transliteration: the
internal object graph differs deliberately (the reference count is a real atomic,
the method table is a Rust struct with the legacy and modern slots in the order the
*behaviour* requires, and the chain is raw pointers only because the C API hands
them out).

**Why.** `docs/CUSTODIAN_CONTRACT.md` §3 permits authority source for archaeology
with provenance, and requires implementation to follow from behaviour. Reading the
source is what turned up three otherwise-unguessable facts that a from-memory
implementation would have got wrong: `BIO_new_ex` sets `init = 1` when a method has
no `create`; `BIO_meth_set_read` stores the legacy pointer and installs a
conversion shim in the dispatch slot, so `BIO_meth_get_read` and
`BIO_meth_get_read_ex` return different things; and `BIO_free_all` **stops** when it
meets a shared BIO rather than freeing the rest of the chain.

**Consequence.** The generated raise-site table was extended to cover the Phase 4
source files so that BIO/CONF error records carry the authority's own
`file`/`line`/`function`, and it now distinguishes sites whose *reason* is computed
at run time (`ERR_LIB_SYS` with `errno`) from sites with a header constant. Those
dynamic sites are emitted with a `dynamic_reason` flag and raised through
`raise_site_dynamic`, so the coordinates stay exact without inventing a reason.

---

## D25 — Regression is enforced by a committed baseline, on every push

**Decision.** `forensics/tools/regression_guard.py` compares the current derived
evidence against `forensics/regression-baseline.json` and fails on any movement in
the wrong direction: implemented symbols must not decrease, open obligations must
not increase, a court that passed must not fail or disappear, a court's
observation count must not shrink, and a phase state must not go backwards.
`.github/workflows/ci.yml` runs it on every push to every branch.

**Why.** The project's claims are cumulative, and the failure mode that CI
normally misses is *subtraction*: a deleted implementation, a narrowed probe, or a
reopened obligation produces no failing test. The observation-count rule is the
one that earns its keep: a probe quietly narrowed to dodge a difficult case still
passes, and nothing else in the pipeline would notice.

**Consequence.** Two jobs are required. `static` needs no authority and, crucially,
re-derives every generated artefact and asserts the tree is byte-identical — stale
evidence is a hard failure, because a claim built on a stale artefact is
unverifiable. `courts` re-runs all 19 courts from scratch against a freshly built
authority and then runs the guard over the *re-derived* results, so the committed
numbers are reproduced rather than trusted. `--update` rewrites the baseline as a
reviewable diff.

The clippy job is present but not yet required: the Phase 4 BIO modules carry 201
`docs/UNSAFE.md` documentation diagnostics. It runs with `continue-on-error` so it
is visible rather than omitted, and removing that one line is the change that
makes it a hard gate. Suppressing the lint with an `allow` was rejected.

**Not tied to publishing.** The guard exists so that every pushed commit is not a
step backwards; releasing is a separate, deliberate act.

---

## D26 — The regression baseline is read through git, and absence is never completion

**Decision.** `regression_guard.py` takes the baseline it judges against from
`--baseline-ref` (the pre-push tip, or the merge base for a pull request), read
**through git**; the copy in the working tree is a *proposed* baseline and is
separately required (`--require-current`) to equal the observed evidence. In the
court container, which does not own its bind-mounted checkout, the runner extracts
the authority to `court/trusted-baseline.json` and passes `--baseline-file`.

**Why.** An earlier version compared the working tree against the working tree.
That is self-certifying: delete forty implementations, run `--update`, commit the
lower baseline, and the comparison passes while being arithmetically true. The
two-part check closes it — the authority is read from a ref the candidate cannot
edit, and the proposed baseline must stay current, so lowering it does not help and
letting it go stale does not either.

**Absence is never zero.** Every check is fail-closed. If the authority recorded an
obligation ledger and the candidate cannot produce it, that is a regression, not
zero open obligations. A *trimmed* authority — one whose `implemented`, `courts` or
`phases` maps have been emptied — is rejected as unfit to certify anything, because
a comparison that checks nothing always passes. A plane present now but absent from
the authority is reported as **UNCERTIFIED** rather than silently skipped, so a
legitimately new ledger is visible as a gap the authority cannot speak to.

**Verified by negative controls**, not by inspection: a baseline claiming more
implementations, a court with a larger observation count, and a phase that
regressed are all reported; a deleted ledger is reported as
"absence is not completion"; a baseline with its `courts` map removed is rejected.

---

## D27 — Determinism is checked on semantics, not on a build product's digest

**Decision.** `forensics/tools/evidence_determinism.py` regenerates every derived
artefact and compares it against the committed one, normalising exactly the digests
of build-product inputs (`crate-archive`, `extra-object`) and *reporting* what it
normalised. Everything else — every count, symbol name, phase state and obligation
— is compared exactly.

**Why.** `implemented-surface.json` records the digest of
`target/release/libopenssl_rs.a`, and every ledger that binds that manifest records
its digest in turn. A Rust static archive is not byte-reproducible across build
environments, so a plain `git diff` after regeneration failed on CI for a reason
that had nothing to do with staleness. A check that cries wolf is a check nobody
trusts, and the first CI run proved it. The fix is to compare what must be
reproducible and to name, in the output, the one field that need not be.

**Consequence.** The determinism step is portable, so it runs in the fast static
job rather than only in the court. It immediately caught a genuinely stale
`STATUS.md` and a stale `phase3-obligations.json`, which is the class of rot it
exists to find.

---

## D28 — "Nothing runs on the host" is refined to "nothing authority-bearing does"

**Decision.** `docs/CUSTODIAN_CONTRACT.md` §11 now scopes the venue rule to
**authority-bearing** execution: differential courts, forensic probes, fuzz
campaigns, benchmarks and authority builds run only in the court container.
Non-authority environments — including CI runners — may run pure implementation
unit tests, static analysis and formatting, and re-derivation of evidence from
already-committed inputs. None of it may contribute forensic parity evidence.

**Why.** The blanket wording was not true of continuous integration and could not be
made true without forbidding cheap, useful checks. The property that actually
matters is that no *claim* rests on a run that lacked the authority, and that is
what the refined wording preserves. A unit test passing on a runner says nothing
about the authority and is never cited as a court.

---

## D29 — The generated status derives its ranges instead of asserting them

**Decision.** `render_status.py` computes the unstarted strata from the phase-state
document and prints their actual range, detecting whether they are contiguous.

**Why.** The renderer hardcoded "Remaining strata 4-21 are `not-started`" while the
JSON beside it said Phase 4 was in progress and phases 5–21 were unstarted. The
derived state was right and the prose contradicted it — in a project whose premise
is that status must never lie. A renderer must not know any phase status, and that
includes the range of the unstarted ones.

---

## D30 — The implemented surface stops recording the toolchain's symbol soup

**Decision.** `implemented_surface.py` reads `nm` in POSIX format and accepts a line
as a symbol only when it has the POSIX record *shape* (3–4 fields, a one-character
symbol type, a hexadecimal value). A line of any other shape must be a known
diagnostic class — an archive-member announcement ending `]:`, or a `bfd plugin:`,
`plugin:` or `nm:` message — or the generator fails with `NmParseError`.

The artefact's `internal_symbols` is now a structured observation. The stable,
collision-relevant part — plain C identifiers that are not Rust manglings — is
recorded as `c_style` and **compared exactly** (39 names: the legacy error-string
loaders, the two `openssl_rs_err_*` adapters, and `compiler_builtins` intrinsics).
The compiler-emitted population is recorded only as `compiler_emitted_count`, and
`nm`'s diagnostic-line count as `nm_diagnostic_lines`; both are declared build
products which `evidence_determinism.py` normalises and reports. `body_hash` is
computed over the evidence subset of the body, and the obligation ledgers bind
that digest through a single shared `implemented_surface_input()` helper instead of
the artefact's file digest.

**Why.** CI reported three stale artefacts. The cause was not staleness.

1. **`nm` writes diagnostics to the symbol stream.** The old parse took the third
   whitespace-separated field of any line with three or more fields. `nm` emits
   `bfd plugin: LLVM gold plugin has failed to create LTO module: ...` on stdout,
   whose third field is the word `LLVM`, so a compiler diagnostic was recorded as a
   defined symbol. How many such lines appear depends on the host's binutils and
   its LTO plugin — this is why the court (Debian binutils 2.40) and CI (Ubuntu)
   disagreed about a crate that had not changed.

2. **Most of the recorded names were never names.** 3,942 of 4,493 entries were
   `anon.<hash>.<n>.llvm.<hash>`, LLVM-internalised anonymous data. Those hashes
   changed between two builds of the *same* source in the *same* container
   (`...llvm.14066615883699384174` became `...llvm.18337626635650182727` against the
   committed artefact at HEAD), so the field was not a function of committed inputs
   at all. Treating it as evidence was the design error.

3. **One build product propagated into three artefacts.** `body_hash` covered the
   volatile list, and both obligation ledgers bound the artefact's file digest, so
   the archive's non-reproducibility surfaced as `phase3-obligations.json` and
   `phase4-obligations.json` both "stale".

**Consequence.** The determinism step still compares everything that must be
reproducible and now names the three fields it does not, so the exception is
visible. `implemented` stayed at 345 across the change, which is the evidence that
the strict parser dropped no real symbol; had it dropped one, the shell would have
scaffolded a *defined* symbol and the link would have failed loudly rather than
silently.

**Rejected.** Normalising the whole `internal_symbols` list. That would have hidden
the parser defect in (1) — a difference normalised because it was inconvenient, not
because it was a build product. Separating the stable subset from the
toolchain-dependent remainder keeps the difference visible and still compares the
part a consumer could collide with.

**Non-claim.** Nothing here changes any parity claim. This is a defect in the
evidence plane's own reproducibility, and it affected `IMPLEMENTED` bookkeeping, not
any court.

---

## D31 — The court's CPU cap is clamped to the machine, not asserted

**Decision.** `docker/openssl-rs-court.sh` requests 8 CPUs and, when the machine has
fewer, clamps `--cpus` to `nproc` and prints the clamp. An explicit
`OPENSSL_RS_COURT_CPUS` is clamped identically; a non-integer is rejected with exit
code 2.

**Why.** The `courts` CI job failed at `Start court container` with
`docker: Error response from daemon: range of CPUs is from 0.01 to 4.00, as there
are only 4 CPUs available`: GitHub's `ubuntu-latest` has 4 CPUs and the cap was
hardcoded at 8. A resource cap is a *bound* on a runaway court, and a bound that
prevents the court from starting at all is the opposite of containment. The value
is therefore machine-derived rather than asserted.

**Consequence.** Verified, not assumed: with an `nproc` shim reporting 4 CPUs, the
container now starts and reports `nanocpus=4000000000` (4 CPUs); an explicit
request of 999 on a 16-CPU machine starts and reports 16; `OPENSSL_RS_COURT_CPUS=abc`
is rejected. `docs/REPRODUCIBILITY.md` §1.3 records the clamping in the cap table.

**Note.** D4's recorded cap of `--cpus=8` remains the intent; this decision makes
the *effective* value fit the machine. D4 is not rewritten.

---

## D32 — The Phase 2 install tree ships build products in git (observed, deferred)

**Observation.** `artifacts/phase2/install/` is Git-tracked in full, including the
non-reproducible build products `lib/libcrypto.so.3`, `lib/libcrypto.so`,
`lib/libcrypto.a`, `lib/libssl.a` and `lib/ossl-modules/legacy.so` (54 MB). They
change on every `build_phase2.sh` run, so every commit made after a rebuild carries
tens of megabytes of binary churn that no court reads: the courts regenerate the
tree themselves, and `ABI-INSTALL-LAYOUT` asserts *entry presence*, while
`SHELL_MANIFEST.json` records the layout. `.gitignore` already tries to exclude
`/artifacts/phase2/*.so` and `/artifacts/phase2/*.a`, but the patterns are shallow
and do not match the nested `install/lib/` paths.

**Decision.** Recorded, not acted on in this change. Fixing it means either making
those ignore patterns recursive and `git rm --cached`-ing the build products, or
keeping the tree as a demonstrable distribution and accepting the churn. Which is
correct depends on whether the committed bytes were intended as the Phase 2
distribution artifact or as an accident of a shallow ignore pattern, and that is
the project owner's call rather than an inference from the evidence plane.

**Why it is recorded anyway.** It is the same defect class as D30 — a build product
treated as though it were evidence — and D30's own remedy (normalise, report, and
compare only what must be reproducible) would apply here as "do not track it". Not
recording the observation would lose the finding; acting on it unasked would change
what the Phase 2 seal's `install/` row means.

---

## D33 — The symbol table is read in Python, because `nm` is machine-dependent

**Decision.** The implemented surface is derived by reading the **native ELF symbol
tables** directly (`forensics/tools/elf_symbols.py`), not by running `nm`. The
reader is deliberately narrow — ELFCLASS64, little-endian, `ar` archives and single
objects — and raises `ElfError` on anything else rather than guessing. `nm` is no
longer in the evidence path, and `internal_symbols.nm_diagnostic_lines` is gone
with it, leaving two normalised build-product fields instead of three.

**Why.** D30 fixed the *parse* of `nm`'s output; this fixes the choice of `nm`
itself. Rust objects carry LLVM bitcode beside their machine code, and binutils
reads that bitcode through a plugin whose availability depends on the host. Where
the plugin works, `nm` additionally reports symbols that exist only in the
bitcode; where it does not, `nm` reports the native table alone (and prints
`bfd plugin: LLVM gold plugin has failed to create LTO module: ...`). So the same
archive yields different answers on different machines. The evidence: CI reported
`internal_symbols.c_style: 39 entries vs 260` with the extra 221 being
`compiler_builtins` definitions (`__adddf3`, `__addhf3`, ...), and the court's `nm`
printed `nm: memchr-...rcgu.o: no symbols` for a member whose `.symtab` in fact
defines 29 external symbols.

**Evidence that the reader is right.**

1. The court's own `nm` is the lossy one: a member it calls "no symbols" carries 29
   defined external symbols.
2. Reading `.symtab` in Python yields **260** C-identifier internals — *exactly*
   the number the plugin-enabled `nm` on the CI runner produced. Two independent
   readers on two machines now agree.
3. The `ar` walk is correct: 346 payloads for 346 `ar t` entries, every payload a
   valid ELF object, and the reader agrees with `nm` byte-for-byte on both a single
   extracted object and the `.rlib`.
4. `implemented` did not move: 345 before and after, on every path.

**Consequence.** The reader's set is a superset of the court's old `nm` set, and the
new members are Rust-mangled dependency symbols plus `compiler_builtins` and
`math` intrinsics (`__adddf3`, `cbrt`, `fabs`, `sqrt`, ...). Those are real C
identifiers that a *static* link against `libcrypto.a` could collide with, and they
are now visible in `internal_symbols.c_style` instead of being hidden by the
reader — which is the kind of thing `local: *;` exists to contain for the shared
object (and `ABI-SYMBOL` verifies it does). The `c_style` list is compared exactly.

**Non-claim.** No parity claim changes. This makes the artefact a function of the
archive rather than of the machine that inspects it.

**Enforcement.** A fix that nothing tests is a fix that will be undone, and
`evidence_determinism.py` structurally cannot catch this defect class: on any single
machine the generator and the committed artefact both use that machine's `nm` and
agree. So `forensics/tools/check_evidence_portability.py` stubs `nm`, `objdump`,
`readelf`, `ar` and `file` out of `PATH`, re-runs the whole generator chain, and
requires all six compared artefacts to reproduce anyway. It then seeds two failing
cases and requires both to be reported: a generator that calls `nm`, and a
generator that edits an evidence field. The controls run on every invocation
rather than being asserted in prose. It is wired into the `static` CI job.

The gate's comparison shares `evidence_determinism.artefact_differences` rather
than re-implementing it, so the declared build-product fields are excluded
symmetrically in both tools. The first version compared bytes and therefore failed
on the CI runner for a legitimate reason — the runner's look of the crate archive
has a different digest from the court's — which is precisely the difference those
declarations exist to absorb, and precisely why a second, drifting comparison
policy is a place for a claim to hide.

---

## D34 — `BIO_ADDR` is implemented from measurement, because the documentation is wrong about it

**Decision.** `BIO_ADDR` (12 exports) is implemented in `src/runtime/bio/addr.rs`
and courted by a new differential court `RT-BIO-ADDR` (82 observations, passing).
The contract was established by two discovery probes and one fault probe, all
committed under `courts/phase4/`, **before** the Rust was written:

* `discover_bio_addr.c` — the value API, the string conversions, the rejection
  cases, and the null-argument cases the authority defines;
* `discover_bio_addr2.c` — two behaviours that needed pinning down separately;
* `bio_addr_null_calls.c` — one null-argument call per process, because a probe
  cannot compare a crash.

**Why measurement rather than the documentation.** Several measured behaviours
contradict what a reader would assume, and each one would have been a parity defect
if it had been implemented from the man page:

1. `BIO_ADDR_rawaddress(ap, p, &n)` treats `n` as an **out** parameter. A caller
   passing `n = 1` gets back `n = 4` and a 4-byte copy, not the documented
   length-check failure.
2. `BIO_ADDR_service_string()` reports the **byte-swapped** port: 80 prints as
   `20480`, 443 as `47873`, 1 as `256`. The model that reproduces every measured
   case — and also the `AF_UNIX` result, where glibc's `getnameinfo` returns
   `"localhost"` for the host and the path for the service — is that the address is
   rebuilt for `getnameinfo` with the **host-order** port in the port field, with no
   `htons`. Implemented that way, not corrected.
3. `BIO_ADDR_rawmake()` validates *before* clearing, so a rejected call leaves the
   previous address intact. Measured: after a successful `AF_INET` make and a
   rejected `AF_UNSPEC` make, the family is still `AF_INET` and the port still the
   earlier value. The candidate reproduces this, and the court asserts it.
4. `BIO_ADDR_path_string()` returns NULL for every family except `AF_UNIX`.
5. `BIO_ADDR_rawport()` returns a **host-order** port, which is the opposite
   convention to (2) and is what makes the pair so easy to get wrong.

**Divergences.** `BIO_ADDR_rawmake` with a NULL `where` and seven accessors with a
NULL `ap` fault in the authority; the candidate is total there. Both are recorded
as `D-BIO-ADDR-1` and `D-BIO-ADDR-2` in
`docs/SECURITY_DIVERGENCE_POLICY.md`, with the per-process SIGSEGV evidence.

**A method note worth keeping.** `RT-BIO-ADDR` failed on its first run with 25
residuals whose authority side was `None` — every observation from the NULL `where`
call onward. That signature is how a *fault* in a shared probe presents itself, and
it is indistinguishable from a candidate that emits extra lines unless the probe is
read in order. The fix is to not probe undefined behaviour, not to relax the
comparison.

**Non-claim.** `RT-BIO-ADDR` passing means the candidate matched the authority for
the behaviours this probe exercises: the value round-trips, the string conversions,
and the rejection cases. It is not a claim about `BIO_ADDRINFO`, `BIO_lookup` or the
connect/accept BIOs, which remain open Phase 4 obligations.

---

## D35 — The CI runner owns the shared scratch directory before the container does

**Decision.** The `courts` job creates `court/` immediately after checkout, before
building or starting the court container.

**Why.** The repository is bind-mounted at `/work` and the container runs as root,
so every file and directory it creates lands on host disk owned by root. `court/` is
shared between the two: the courts write evidence and staged probes into
`court/phase2/` and `court/phase4/`, and later the *runner* user writes
`court/trusted-baseline.json` there with `git show`. When the container created
`court/` itself, that last write failed:

    court/trusted-baseline.json: Permission denied

which is how the first `courts` run to get that far failed — the step is the last
one reached, so every earlier green run had hidden the problem. Creating the
directory on the runner first leaves it runner-owned; the container can still write
inside it (it runs as root), and its own subdirectories stay separate.

**Consequence.** With this and D31, the `courts` job runs end to end: image,
container, preconditions, authority acquisition and build, the 11 ABI courts, the 7
runtime courts, the 3 BIO courts, and the baseline extraction. `static` passes
independently. The remaining red job is `lint`, which is `continue-on-error` by
D-something recorded in `docs/PHASE-4-BIO-CONF-SEAL.md` and still carrying the
Phase 4 `# Safety` documentation debt.

---

## D36 — `BIO_ADDR`'s two port conventions are inverted, and `BIO_lookup` is where that becomes visible

**Finding, measured.** `BIO_ADDR` stores its port two different ways depending on
how it was built, and the two accessors therefore disagree in opposite directions:

| built by | stored port field | `BIO_ADDR_rawport()` | `BIO_ADDR_service_string()` |
|---|---|---|---|
| `BIO_ADDR_rawmake(…, 8080)` | `htons(8080)` | `8080` (correct) | `"36895"` (swapped) |
| `BIO_lookup(…, "8080")` | `8080` (host-order value) | `36895` (swapped) | `"8080"` (correct) |

Measured with `courts/phase4/discover_bio_lookup.c` against the authority, for port
8080 on IPv4, port 80 on IPv4, and port 443 on IPv6 — all three consistent. So the
lookup path hands `BIO_ADDR_rawmake` the *network-order field value* as though it
were a host-order port, and `rawmake` then `htons`es it, which un-swaps it. That is
an upstream inconsistency, not a documentation gap, and it is reproducible.

**Why this is recorded rather than implemented.** `BIO_ADDRINFO` and `BIO_lookup`
are *not* implemented; they remain open Phase 4 obligations. The finding is
recorded now because it is the kind of detail that is expensive to rediscover: it
is invisible from the headers, invisible from a single accessor, and it would
otherwise be "fixed" into a parity defect by anyone implementing `BIO_lookup` from
the `BIO_ADDR` code that already exists. `BIO_ADDR` itself is unaffected — D34's
implementation reproduces the `rawmake` column exactly, and `RT-BIO-ADDR` asserts
it.

**Consequence for the next step.** An implementation of `BIO_lookup_ex` must
convert each `getaddrinfo` result into a `BIO_ADDR` whose port field is set the way
the second row describes, then build the `BIO_ADDRINFO` chain around it. The probe
that established the table is committed so the conversion can be courted the same
way, and `discover_bio_lookup.c` also records the entry count and ordering for
those lookups (one entry each for the numeric cases probed, with `socktype` 1 and
`protocol` 6 filled in by the resolver).

---

## D37 — D34's and D36's *mechanism* for the port was wrong; the observations were right

**Correction.** `BIO_ADDR_rawmake` stores the port **verbatim** — `sin_port = port`,
with no `htons` — and `BIO_ADDR_rawport` returns the field **verbatim**, with no
`ntohs`. D34 described the observable correctly and attributed it to the wrong
cause ("the authority rebuilds the address for `getnameinfo` with the host-order
port"); D36 went further and described a lookup path that "un-swaps" the port,
which does not exist. The truth is simpler and worse: one function forgets to
convert, and a resolver-built address is not one of its outputs at all — it is
glibc's `struct sockaddr` seen through a cast, so *its* field holds `htons(port)`
and the two accessors report the opposite way round.

**Why the court did not catch it.** `RT-BIO-ADDR` compared what the public API
returns: `BIO_ADDR_rawport` and `BIO_ADDR_service_string` agree under both models,
because D34's implementation un-swapped the field on the way into `getnameinfo` and
so reproduced the same string. The two models differ only in **what is stored**, and
that is visible only where something else reads the address — a socket syscall. The
observations were correct and insufficient; the mechanism was wrong and undetected.
The court now also compares the error queue, which closes the adjacent gap, and
`RT-BIO-SOCK` (the socket-layer court) is where the stored bytes are pinned.

**Consequence.** `BIO_ADDR_rawmake` stores `port` directly; `BIO_ADDR_rawport`
returns the field directly; `addr_strings` calls `getnameinfo` on the stored address
with no reconstruction and falls back to `ntohs(BIO_ADDR_rawport(ap))` only when
`getnameinfo` left the service empty. A unit test asserts the stored field directly,
so the model cannot silently regress.

---

## D38 — The resolver surface is implemented, and the court found two Phase 3 defects

**Decision.** `BIO_ADDRINFO` (6 exports), `BIO_lookup`, `BIO_lookup_ex`,
`BIO_parse_hostserv`, `BIO_get_port`, `BIO_get_host_ip` and `BIO_gethostbyname` are
implemented and courted by a new `RT-BIO-RESOLVE` (501 observations, passing).
Phase 4 is now implemented 157 / deferred 14 / open 85 of 256 owned; the baseline is
22 courts and 5,085 observations.

**Behaviours the source confirmed and the probe pinned.**

* `AI_ADDRCONFIG` is set **only** when the host is non-NULL *and* the family is
  `AF_UNSPEC`; `AI_PASSIVE` only for `BIO_LOOKUP_SERVER`. A one-shot retry clears
  `AI_ADDRCONFIG`, sets `AI_NUMERICHOST` and reports the *first* `gai_strerror`.
* `BIO_lookup_ex` validates the family explicitly
  (`BIO_R_UNSUPPORTED_PROTOCOL_FAMILY` at `bio_addr.c:698`) before any resolver
  call, and raises `ERR_LIB_BIO`/`ERR_R_SYS_LIB` with `gai_strerror` as data
  otherwise — at three different coordinates (`:746`, `:751`, `:767`), all of which
  `ERR_get_error_line_data` exposes.
* **`*res` is written only on success**: probed with a sentinel, the authority
  leaves it untouched when the lookup fails.
* `BIO_get_port` and `BIO_get_host_ip` are thin wrappers over `BIO_lookup`, not
  string parsers, which is why `BIO_get_host_ip("1.2.3")` yields `1.2.0.3` (the
  resolver accepts `inet_aton` shorthands) and `BIO_get_port("70000")` yields `4464`
  (the resolver truncates to 16 bits and the result is un-swapped).
* On the Linux authority the `gethostbyname`/`getservbyname` fallback and the
  `AF_UNSPEC` string fallback are both compiled out, so neither is implemented.

**Two Phase 3 defects, found by the new court.** The first run produced exactly one
residual, in `BIO_get_host_ip(NULL, ip)`:

    ip.null.err.data: authority='Name or service not knownhost=<NULL>'
                      candidate='Name or service not knownhost='

The authority's `ERR_add_error_vdata` substitutes the literal `"<NULL>"` for a NULL
argument, and **grows** its buffer rather than truncating. This project's
`err_variadic.c` did neither: it skipped NULL arguments and capped the result at
1023 bytes. Both were observable through `ERR_get_error_data` — the truncation by
any long argument, which nothing had probed. Both are fixed, and the probe now
observes `ERR_add_error_data` directly (NULL argument, both-NULL, a 3 KB argument,
and `num == 0`) so the exported function is covered rather than only the helper that
happened to exercise it.

**Non-claim.** `RT-BIO-RESOLVE` passing means the candidate matched the authority for
the lookups, failure modes, error coordinates and helper behaviours the probe
exercises, in this container's resolver environment. It says nothing about a
container with different `/etc/hosts`, `/etc/services` or NSS configuration, and it
is not a claim about the socket layer, which is a separate court.

## D39 — The socket entry points are implemented, and RT-BIO-SOCK is the court that can see the port convention

**Decision.** `BIO_socket`, `BIO_bind`, `BIO_connect`, `BIO_listen`, `BIO_accept_ex`,
`BIO_accept`, `BIO_get_accept_socket`, `BIO_set_tcp_ndelay` and `BIO_sock_info` are
implemented (`src/runtime/bio/bio_sock2.rs`) and courted by a new `RT-BIO-SOCK`
(157 observations, passing, zero residuals). Phase 4 is now implemented 166 /
deferred 14 / open 76 of 256 owned; the baseline is 23 courts and 5,242
observations; `implemented` `libcrypto` exports move 369 -> 378.

**Why this court exists, and what it adds over `RT-BIO-ADDR`.** `BIO_ADDR` stores
its port *verbatim* (D37), so a single accessor cannot reveal the convention: an
implementation that stored `htons(port)` agrees with the authority on every
`BIO_ADDR_*` accessor. What separates the two models is a *syscall*. The probe binds
port 8080 through `BIO_ADDR_rawmake` and reads the address back with
`BIO_sock_info` (which is `getsockname`). The authority reports

    describe.rawmake8080.rawport   = 8080
    describe.rawmake8080.service   = 36895
    sock.bind8080.readback.rawport = 8080
    sock.bind8080.readback.service = 36895

which is exactly the verbatim-model signature: the kernel bound 36895 (the byte
pattern `8080` read as network order), wrote it back in network order, the verbatim
read yields 8080 and `service_string` yields its `bswap16`. A `htons`-storing
implementation produces `(36895, "8080")` on both lines and fails the court. This is
the observation D34/D36 could only describe, and D37's correction needed a court of
this shape to be *verifiable* rather than merely argued.

**Behaviours the source confirmed and the probe pinned.**

* A syscall failure raises **two** errors, and `BIO_accept` raises **four**: it calls
  `BIO_accept_ex` (which raises `ERR_LIB_SYS`/`get_last_socket_error` + `"calling
  accept()"`, then `BIO_LIB`/`BIO_R_ACCEPT_ERROR`) and then raises the same pair
  again at its own coordinates. `accept.badfd.count = 4` in the authority and 4 in
  the candidate; the probe compares the whole queue, which is why it can see this.
* The **invalid-descriptor guard raises one error and no syscall error**: `BIO_bind,
  BIO_connect, BIO_listen` with `-1` each produce exactly one `ERR_LIB_BIO` entry
  (count 1), because the `sock == INVALID_SOCKET` check precedes any syscall. An
  implementation that let the syscall fail would produce count 2 with a different
  reason.
* A **retryable** `connect`/`accept` **raises nothing** (`BIO_sock_should_retry` is
  consulted before any raise), and `BIO_accept` reports it as `-2`, not `-1`.
* `BIO_set_tcp_ndelay` **raises nothing on either path** — success and a bad
  descriptor both leave the queue empty; the return value is the only report.
* `BIO_sock_info` with an unknown `type` raises one `ERR_LIB_BIO`; with a bad
  descriptor it raises the `getsockname` pair.
* `BIO_get_accept_socket` parses with `BIO_PARSE_PRIO_SERV` (so `"127.0.0.1:0"`
  reads the host as `127.0.0.1`), and a bad service surfaces the resolver's own
  `gai_strerror` text (`"Servname not supported for ai_socktype"`) as one BIO
  error.
* `BIO_listen` reads `SO_TYPE` first, sets `IPV6_V6ONLY` only for `AF_INET6`, calls
  `BIO_bind` with the **same** options, then `listen(sock, SOMAXCONN)`. `SOMAXCONN`
  is **4096** in this container, not the 128 a reader assumes; the constant was read
  from the image's headers rather than assumed.
* The authority's TCP-Fast-Open branch and the `getaddrinfo` fallback in
  `BIO_socket` are FreeBSD/macOS-only and compiled out here, so neither is
  implemented.

**A probe defect, found first.** The initial probe declared `BIO_ADDR peer;` on the
stack and failed to compile against the *authority* headers, because `BIO_ADDR` is
an opaque type to every external caller. That is itself a finding: the authority's
`BIO_accept` is one of the few places a `BIO_ADDR` lives on the stack (in
`bio_sock.c`), and the candidate's `BIO_accept` matches it with a zeroed stack
`BioAddr`. The probe was corrected to allocate with `BIO_ADDR_new()`. The
implementation was not changed — the probe was wrong, as it has been before.

**Non-claim.** `RT-BIO-SOCK` passing means the candidate matched the authority for
the socket construction, bind/listen/accept/connect flows, error coordinates and
return classes the probe exercises, on the loopback interface of this container.
It is not a claim about datagram or memory-pair BIOs, about `BIO_s_connect`/
`BIO_s_accept`, or about behaviour under a non-loopback network. Those are separate
obligations in the Phase 4 ledger.

## D40 — The debug callback, the retry classifiers and the compression methods

**Decision.** Seven more exports are implemented and courted:
`BIO_debug_callback`, `BIO_debug_callback_ex`, `BIO_fd_non_fatal_error`,
`BIO_fd_should_retry`, `BIO_dgram_non_fatal_error`, `BIO_f_zlib`, `BIO_f_zstd`
and `BIO_f_brotli` — eight symbols across three new modules (`bio_cb.rs`,
`retry.rs`, `comp.rs`) and two new courts, `RT-BIO-DEBUG` (55 observations) and
`RT-BIO-COMP` (45 observations), both passing with zero residuals on their first
run. Phase 4 is now implemented 174 / deferred 14 / open 68 of 256 owned; the
baseline is 25 courts and 5,342 observations; `implemented` `libcrypto` exports
move 378 -> 386.

**The three compression methods are a build-profile result, not a stub.**
`OPENSSL_NO_ZLIB`, `OPENSSL_NO_ZSTD` and `OPENSSL_NO_BROTLI` are all defined in
the admitted authority's `configuration.h`, so each body reduces to `return NULL`
with its `RUN_ONCE` compiled out. `RT-BIO-COMP` observes the NULL *and* that the
error queue stayed empty. This is scoped to the profile: a zlib-enabled build
exposes a real filter BIO with its own controls and error strings, so these are
recorded as implemented *for `openssl-3.6.4-production`* rather than universally,
and the obligation is expected to reopen as three implementations if a
compression-enabled profile is ever admitted (`docs/BUILD_MATRIX.md`). A
`SCAFFOLDED` abstention would abort; returning the authority's value does not.

**The retry classifiers differ by exactly one errno.** `BIO_fd_non_fatal_error`
accepts `ENOTCONN` and `BIO_dgram_non_fatal_error` does not — measured over the
whole Linux set, not sampled: `fd_nonfatal.e107=1` with `dgram_nonfatal.e107=0`.
`BIO_fd_should_retry` consults `errno` **only** for `0` and `-1`; every other
input answers 0 without reading it, which the probe pins by setting a retryable
`errno` first (`fd_retry.eagain.1=0`, `..2=0`, `..m2=0`, `..m5=0`) so an
implementation that read `errno` unconditionally would answer 1 and fail.

**The debug callback's text is the contract, and two quirks are in it.**

* `BIO_debug_callback` forwards a **coerced** return to `_ex`
  (`ret > 0 ? 1 : (int)ret`) and then **discards** what `_ex` returns, answering
  its own `ret`. So the same command through the two entry points gives
  `wrapper.recvmmsg.ret=123` and `ex.recvmmsg.ret=4` — `_ex` rewrites its answer
  to `(long)len` in the two `sendmmsg`/`recvmmsg` completion arms and nowhere
  else.
* The completion ret is coerced to 1 for a positive result before the callback
  sees it, which is why `write.ret=5` is accompanied by `write return 1
  processed: 5`. That coercion lives in `bio_call_callback` and was already
  reproduced by `iolib.rs`; the new court observes it from the other side.
* A zero-length `BIO_write` fires **no callback at all** (`write0` shows only the
  `Free` line), because the length check precedes `bio_call_callback`.
* The descriptor branch (`… - socket fd=0`) is exercised **without doing I/O**, by
  calling the callback directly on a `BIO_s_socket` BIO whose `sock_new` leaves
  `num` at 0 and `init` at 0. Provoking it through `BIO_read` would have made the
  transcript depend on a real descriptor number, and would have read from
  descriptor 0.

**One normalisation, and why it is legitimate.** Every message begins
`BIO[0x…]: ` with the subject's address. The probe rewrites each `0x`-prefixed
hex run to the literal `<addr>` before printing, symmetrically on both sides and
confined to that token — no other field in any message is a hex run, so the
substitution cannot mask a divergence. The raw text remains re-derivable by
re-running the staged binaries in `artifacts/phase4/probes/`, which is what makes
this a comparison-surface transform rather than a loss of evidence
(`docs/PARITY_MODEL.md`).

**A court that would have passed blind, caught during review.** The first version
of the descriptor case passed because the text was being written to `stderr`, not
to the destination BIO: the debug callback writes to *its own* BIO's `cb_arg`,
and the probe had set the argument on the wrong BIO. The observation count did
not change, so the pass looked identical. The probe now sets the argument on the
socket BIO, and `desc.dstlen=190` with a populated `desc.text` is the evidence
that the branch is genuinely compared. This is the second time in Phase 4 that a
*differential* court needed checking for blindness rather than just for
residuals.

**Non-claim.** `RT-BIO-DEBUG` passing means the candidate emitted the same text,
return values and error queue as the authority for the commands the probe drives.
It is not a claim about the callbacks of the filter and method BIOs still open in
this stratum. `RT-BIO-COMP` passing is scoped to the admitted build profile.

## D41 — The BIO printf engine is not the C library's, and it was wrong

**Decision.** Eight further exports are implemented and courted — `BIO_s_file`,
`BIO_new_file`, `BIO_new_fp` (`bss_file.rs`), `BIO_s_fd`, `BIO_new_fd`
(`bss_fd.rs`) and `BIO_s_log` (`bss_log.rs`) — and, far more importantly, the
`BIO_snprintf`/`BIO_vsnprintf`/`BIO_printf`/`BIO_vprintf` engine was replaced.
Phase 4 is now implemented 180 / deferred 14 / open 62 of 256 owned; the baseline
is 27 courts and 5,689 observations; `implemented` `libcrypto` exports move
386 -> 392.

**The defect this fixes, and why it was not a corner case.** The previous
implementation of the printf surface called `vsnprintf`. The authority does not:
it carries its own engine, `_dopr` (`crypto/bio/bio_print.c`), and the dialects
differ in ways a caller can see. Measured directly against the authority's DSO
before the fix:

    BIO_snprintf(b, n, "[%s]", (char *)NULL)   authority "[<NULL>]"  vsnprintf "[(null)]"
    BIO_snprintf(b, n, "[%p]", (void *)NULL)   authority "[0]"       vsnprintf "[(nil)]"
    BIO_snprintf(b, n, "%q", 1)                authority 0, ""       vsnprintf -1, ""
    BIO_snprintf(b, n, "%e", 10.0)             authority "10.000000e+00"
                                               vsnprintf "1.000000e+01"

The last one is not a rounding difference: `_dopr`'s exponent loop steps only
while the mantissa is **strictly** greater than ten, so a mantissa of exactly ten
is never normalised. `BIO_snprintf` is a Phase 4 export that was already recorded
as implemented, so this was an incorrect obligation rather than an open one, and
leaving it would have closed the stratum with a knowingly wrong surface. It was
found while reading `bss_file.c`, whose `"calling fopen(%s, %s)"` error data is
formatted by this engine and therefore contains `<NULL>` where the C library
would write `(null)`.

**The engine.** `src/runtime/bio/print_engine.rs` implements the format state
machine, `fmtint`, `fmtstr` and `fmtfp` — including the strict exponent loop, the
nine-digit fraction clamp (`if (max > 9) max = 9`), the `?` sign that an infinity
or NaN acquires, the `<NULL>` substitution, the "unknown conversion is skipped"
rule, `%n`, and the truncation verdict. `LDOUBLE` is `double` in this build
(`HAVE_LONG_DOUBLE` is undefined), which is why there is no third argument class
and why `%Lf` was measured to behave exactly like `%f`.

**Argument extraction stays in C, and only that.** A C-variadic function cannot
be defined in stable Rust and `va_arg` needs the un-erased list, so
`src/runtime/bio/bio_va.c` exposes exactly two primitives — next
general-purpose argument, next floating-point argument — and nothing else.
The Rust engine drives the parse and decides which class to pull, so there is a
single format parser and no second one that could desynchronise the argument
stream. On x86-64 SysV the two argument classes advance independent `va_list`
cursors, which is exactly the model these two accessors express.

**Two surprises the engine had to reproduce.** `q` and `j` are *length
modifiers*, so `"<%q>"` renders as `<` and nothing else: `q` is consumed as a
modifier and `>` becomes the (unknown) conversion, which is then skipped.
`"%wX"` is worse — `w` skips the **following character** and produces nothing.
Both were measured, and both are in `RT-BIO-PRINT`.

**Three probe defects, found before the implementation was questioned.** The
first `RT-BIO-FILE` run crashed the *authority* because the probe passed a
`BIO_METHOD *` to `BIO_method_name`, which takes a `BIO *`. The second printed
`int`-returning macros (`BIO_tell`, `BIO_seek`, `BIO_flush`, `BIO_eof`) with
`%ld`, which reads undefined register contents. The third ordered the `%n` test's
arguments wrongly and wrote through address 7. In every case the implementation
was correct and the probe was not — the fourth, fifth and sixth time in Phase 4
that has been true.

**A process note.** `forensics/tools/build_phase2.sh` is not executable; it must
be invoked as `bash forensics/tools/build_phase2.sh`. Invoking it directly fails
with `Permission denied`, and because the shell in question is often run with its
output redirected, that failure is silent and the *previous* shell is then used
for the courts — which presents as "the candidate still scaffolds the new
symbols". This cost one diagnostic cycle and is recorded so it costs no more.

**Non-claim.** `RT-BIO-PRINT` passing means the candidate matched the authority
for the format/argument combinations the probe drives, on this platform's
argument-passing ABI. It is not a claim about a platform whose `long double` is
not `double`, nor about format strings outside the probe's matrix.
`RT-BIO-FILE` passing means the candidate matched the authority for the FILE,
descriptor and syslog state machines and error shapes the probe exercises; the
syslog text leaves the process and is deliberately not compared.

## D42 — The four filter families, and why `BIO_f_nbio_test` is not one of them

**Decision.** `BIO_f_buffer`, `BIO_f_linebuffer`, `BIO_f_readbuffer` and
`BIO_f_prefix` are implemented and courted by a new `RT-BIO-FILTER`
(114 observations, passing, zero residuals on its first run). `BIO_f_nbio_test`
is **deferred to Phase 9** and recorded as such in the Phase 4 ledger. Phase 4 is
now implemented 184 / deferred 15 / open 57 of 256 owned; the baseline is
28 courts and 5,803 observations; `implemented` `libcrypto` exports move
392 -> 396.

**Why `BIO_f_nbio_test` is not implemented here.** Its factory, `create`,
`destroy`, `gets`, `puts` and `ctrl` do not need anything this stratum lacks, but
its **read and write both call `RAND_priv_bytes`** to decide whether to report a
retry. The obligation ledger is per symbol, so marking the symbol implemented
while leaving the method's two data paths to abort would be exactly the
"scaffold counted as parity" failure the release gates exist to prevent. RAND is
Phase 9 (`docs/RELEASE_GATES.md`); the deferral carries that reason in
`forensics/tools/phase4_obligations.py` so the disposition travels with the
ledger rather than with a comment.

**What the new court established.** The four filters are all "a BIO in front of a
BIO", so the probe measures *when* bytes cross the boundary by observing the
destination memory BIO after each step, rather than only what the return value
was:

* `BIO_f_buffer` retains a short write (`buff.mem.small.n=0` while
  `BIO_ctrl(BIO_CTRL_INFO)` is 3) and releases it on `BIO_flush`; a write of ten
  bytes likewise stays retained, and only an overflow of the 4096-byte buffer
  would pass through directly.
* `BIO_f_buffer`'s `BIO_ctrl(BIO_CTRL_PEEK)` **forces a read first**: on a source
  at end of file the forced read returns the memory BIO's empty-buffer value
  (`-1`), the input buffer stays empty, and PEEK therefore returns **0** rather
  than failing. That interaction between PEEK and the memory BIO's `num` is
  measured, not predicted.
* `BIO_f_buffer`'s `BIO_gets` inherits the same value: with the source drained it
  returns `-1`, because the memory BIO reports `-1` for an empty buffer and the
  filter passes a negative result through.
* `BIO_f_linebuffer` flushes up to and including the newline and retains the tail
  (`line.mem.nl.v=abcdef\n` with `info` 3), and the retained tail is what a later
  flush emits.
* `BIO_f_readbuffer` reports its **consumed** offset from
  `BIO_C_FILE_TELL`/`BIO_CTRL_INFO` (9 after a nine-byte read), accepts a backward
  seek and refuses a forward or negative one, and answers `BIO_CTRL_EOF` from its
  own cache rather than from the source.
* `BIO_f_prefix` emits the prefix at each line start and emits **nothing** for an
  indent of 0, because the indent goes through a `"%*s"` field; a seek re-arms the
  line start, so the byte written after `BIO_C_FILE_SEEK` acquires the prefix
  again.

**Non-claim.** `RT-BIO-FILTER` passing means the candidate matched the authority
for the byte movements, retained counts, control returns and error queue the
probe exercises over memory sources. It is not a claim about the filters over a
socket or a FILE, nor about the buffer-size controls at sizes the probe does not
use.

## D43 — The in-process BIO pair, and `BIO_f_base64`'s real dependency

**Decision.** `BIO_s_bio` and `BIO_new_bio_pair` are implemented (`bss_bio.rs`)
and courted by a new `RT-BIO-PAIR` (111 observations, passing, zero residuals on
its first run). `BIO_f_base64` is **deferred to Phase 7**: its context embeds an
`EVP_ENCODE_CTX` and its read/write paths call the `EVP_Encode*`/`EVP_Decode*`
codec, so it is EVP surface in the same way `BIO_f_md` and `BIO_f_cipher` are.
Phase 4 is now implemented 186 / deferred 16 / open 54 of 256 owned; the baseline
is 29 courts and 5,914 observations; `implemented` `libcrypto` exports move
396 -> 398.

**What the pair court established.** A BIO pair is two ring buffers, and its
contract is the retry protocol rather than the bytes:

* an empty read returns `-1` with the read retry flag set **and records the
  requested size on the peer**; the request is clamped to the peer's buffer size,
  so `BIO_read(b, buf, 100000)` records `17408` (17 KiB, the default) while
  `BIO_read(b, buf, 32)` records `32`;
* a write into a nearly full ring is **partial, not refused**:
  `BIO_write(a, "ijklmn", 6)` into four free bytes returns **4**, and
  `BIO_ctrl(BIO_CTRL_WPENDING)` becomes 8. Only a completely full buffer returns
  `-1` with the write retry flag;
* the ring wraps: writing eight, reading four and writing six again makes the
  write head pass the end of the buffer, and reading everything back gives
  `efghijkl` — which a flat-buffer implementation would also produce, but only
  because it had silently reordered the copy. The two-step sequence is what makes
  the split observable;
* `BIO_ctrl(BIO_CTRL_PENDING)` reports the **peer's** length while
  `BIO_CTRL_WPENDING` reports this endpoint's own;
* a write after the peer shut down its send side raises `BIO_R_BROKEN_PIPE`
  (reason 92) and returns `-1`, while a **read** on a closed-and-empty peer
  returns `0` and raises nothing at all;
* `BIO_ctrl(BIO_C_SET_WRITE_BUF_SIZE)` refuses on a paired BIO
  (`BIO_R_IN_USE`) and refuses a zero size (`BIO_R_INVALID_ARGUMENT`), with the
  two different reasons at two different coordinates;
* an **unpaired** BIO is not initialised — `bio_new` allocates the context but
  never sets `init` — so `BIO_read` and `BIO_write` answer `-1` with
  `BIO_R_UNINITIALIZED` from the public wrappers, while its controls report the
  unpaired defaults (`EOF` 1, pending 0). That asymmetry between a method that
  returns early and a wrapper that raises first is why `ctl.raw.*` is in the
  probe.

**Non-claim.** `RT-BIO-PAIR` passing means the candidate matched the authority for
the buffer arithmetic, retry flags, request recording, control refusals and error
queue the probe exercises. It is not a claim about a pair used as an SSL channel,
nor about `BIO_nread`/`BIO_nwrite` beyond the sequences driven here.

## D44 — `OBJ_create_objects`, and two OBJ defects its court found

**Decision.** `OBJ_create_objects` is implemented and courted by a new
`RT-OBJ-STREAM` (91 observations, passing). Phase 4 is now implemented 187 /
deferred 16 / open 53 of 256 owned; the baseline is 30 courts and 6,005
observations; `implemented` `libcrypto` exports move 398 -> 399. The 53 open
obligations are the nine remaining BIO methods and the 44 CONF/NCONF symbols.

**The court found two real defects in already-implemented OBJ exports.** The
first `RT-OBJ-STREAM` run produced exactly one residual:

    name.collision.err0: authority='67108966' candidate='0'

`OBJ_create` was refusing a duplicate short or long name, and refusing an OID
that was already registered, **without raising**. The authority raises
`OBJ_R_OID_EXISTS` at `obj_dat.c:713` and `:734` respectively, and
`ERR_R_PASSED_INVALID_ARGUMENT` at `:706` for the all-NULL call. All three were
missing, and so was the follow-up: driving the malformed-OID cases showed that
`OBJ_txt2obj("no-such-name", 0)` must raise `OBJ_R_UNKNOWN_OBJECT_NAME`
(`obj_dat.c:362`), and that a malformed *numeric* OID raises an **ASN.1** error
because `OBJ_create` parses through `OBJ_txt2obj` and hence `a2d_ASN1_OBJECT`.

`parse_oid_text` returned `Option`: it modelled "rejected" as one state when the
authority has two. A rejection either raises — a first number outside `0..2`
(`ASN1_R_FIRST_NUM_TOO_LARGE`), a missing second number, a bad separator, a
non-digit component, a too-large second number — or is **silent**, when `a2d`
returns a length of zero and the caller's `i <= 0` test rejects it. The type is
now a three-way `OidParse`, and all six rejections plus the silent case are
courted.

**Why one ASN.1 file is now in the raise-site generator.** The malformed-OID
error's coordinate is `crypto/asn1/a_object.c`, which is Phase 5 — but it is
observable through the Phase 4 export `OBJ_create`, so the generator covers that
one file (and the reason-symbol header it needs) rather than deferring the
observation. Only the *error site* is taken from it; the ASN.1 parser itself
remains a Phase 5 obligation. This is the same reasoning that already put
`crypto/objects/obj_dat.c` in the covered list.

**What the stream reader itself established.** `OBJ_create_objects` parses
`OID [short [long]]` per line and stops at the first unusable line **without
raising**, returning the count. The stopping rules are all in the probe: a read
of zero or fewer bytes; a first character that is not alphanumeric (`#`, a
space, or a dot); a first field with no digits or dots at all; a blank line; and
an `OBJ_create` refusal. Two details are easy to get wrong and are pinned: a
short-but-no-long line creates an object whose *short* name is what was given,
and the reader clears the byte **before** the terminator, so a final line with no
newline loses its last character — `nl.at.eof.truncated.nid.ge0=1` with
`nl.at.eof.as.written.nid.ge0=0`.

**Non-claim.** `RT-OBJ-STREAM` passing means the candidate matched the authority
for the streams driven, the accepted objects and the error queue. It is not a
claim about object-database behaviour outside `OBJ_create_objects`, nor about the
ASN.1 parser beyond the `a2d_ASN1_OBJECT` rejections it exercises.

## D45 — The clippy debt this stratum added, and the remaining inventory

**Decision.** The new Phase 4 modules are clean under the crate's own lint
configuration (`undocumented_unsafe_blocks = "deny"`, `missing_safety_doc =
"deny"`), and the two sites the previous batch left in `bio_sock2.rs` are fixed
too. The number of clippy diagnostics in the crate falls from 298 to 251; the
remainder is pre-existing debt in the Phase 4 BIO modules written before this
session, which `docs/DECISIONS.md` already records as the reason the `lints` CI
job is still `continue-on-error`.

Three of the fixes were more than comments: `abs_val`'s two zero assignments
became one `is_nan()` test, the `G`-format style decision became a named
`e_style` predicate, and `BIO_new_bio_pair`'s one-shot `loop` became a labelled
block. Each is equivalent to what it replaced, and the court covers all three.

**The inventory at the end of this batch.** Phase 4 owns 256 exports and stands
at 187 implemented, 16 deferred to a named later phase, and 53 open:

    src/runtime/bio/   9   BIO_s_dgram_pair, BIO_s_dgram_mem, BIO_new_bio_dgram_pair,
                           BIO_s_datagram, BIO_new_dgram,
                           BIO_s_connect, BIO_new_connect, BIO_s_accept, BIO_new_accept
    src/runtime/conf/ 44   the CONF_* and NCONF_* families

The 44 CONF/NCONF symbols are one subsystem (`crypto/conf/`), not a scattering of
independent functions: `NCONF_new`/`NCONF_load`/`NCONF_get_*` are the parser and
its accessors, and the `CONF_modules_*`/`CONF_imodule_*` families are the
module-configuration layer above it. They should be taken as one piece with one
court, for the reason Phase 3 was: the observable contract is the parse, the
include and variable-expansion rules, the section and duplicate-key behaviour and
the error coordinates, none of which survives being split.

**What is verified as of this commit.** 30 courts pass, covering 6,005
observations; the last three batches alone added `RT-BIO-SOCK` (157),
`RT-BIO-COMP` (45), `RT-BIO-DEBUG` (55), `RT-BIO-PRINT` (213), `RT-BIO-FILE`
(134), `RT-BIO-FILTER` (114), `RT-BIO-PAIR` (111) and `RT-OBJ-STREAM` (91).
`implemented` `libcrypto` exports are 399 of 6,499. Phase 0-3 remain `complete`
and Phase 4 remains `in-progress`, which is what the derived phase state says and
what the seals say; nothing here claims otherwise.

**The four defects the courts found, three of them in code already recorded as
implemented.** `BIO_snprintf`'s engine was the C library's rather than `_dopr`
(D41); two `ERR_add_error_vdata` behaviours were wrong (D38, an earlier batch);
`OBJ_create` and `OBJ_txt2obj` were silent where the authority raises (D44); and
`ERR_add_error_vdata` aside, every one of these was found because a *new* court
observed a surface no existing court could see. That is the pattern this stratum
is built on, and it is the reason the remaining 53 symbols should not be
implemented without their courts.

## D46 — The in-memory datagram pair, and why its header size is evidence

**Decision.** `BIO_s_dgram_pair`, `BIO_s_dgram_mem` and `BIO_new_bio_dgram_pair`
are implemented in `src/runtime/bio/bss_dgram_pair.rs`, and `RT-BIO-DGRAM-PAIR`
(141 observations) compares them against the authority. Phase 4 moves from 53 to
50 open obligations; `implemented` `libcrypto` exports move from 399 to 402.

The authority's datagram pair is not a byte stream with framing on top. It is a
ring buffer of `sizeof(hdr) + payload` records plus a header that carries the
`BIO_ADDR` pair, and nearly every surprising observable follows from that shape:
`BIO_CTRL_PENDING` on a **pair** reports the length of the *next datagram's
header* (0 when empty) rather than the length of the next datagram, because the
control peeks the header instead of counting bytes; a read with a short buffer
discards the remainder unless `BIO_CTRL_DGRAM_SET_NO_TRUNC` is set, in which case
the ring cursor is restored and nothing is consumed; and a write that cannot fit
header plus whole payload rolls the ring back, so a reader never sees a fragment.

**The header size is derived, not guessed.** `dgram_hdr` is internal, but two
public controls expose it: `BIO_CTRL_GET_WRITE_BUF_SIZE` on a fresh BIO reports
`9 * (sizeof(hdr) + mtu)`, and `BIO_CTRL_DGRAM_GET_WRITE_GUARANTEE` reports
`size - count - sizeof(hdr)`. Measured against the authority those are **15336**
and **15104** with the default 1472-byte MTU, which fixes `sizeof(hdr)` at
**232** — a `size_t` length plus two 112-byte address slots. The module stores
the addresses as raw 112-byte slots rather than as `BioAddr` values precisely so
the size cannot drift with ours. This is the same discipline as D41's `sizeof`
derivations: an internal layout becomes a compatibility obligation the moment a
public control reports it.

**The distinctions the court had to be built to see.** `GET_EFFECTIVE_CAPS` is
intercepted by `dgram_pair_ctrl`, so on a pair it answers the *peer's*
capabilities while `dgram_mem_ctrl`'s combined arm answers its own. A fresh pair
reports `init=0`, `eof=1`, `guarantee=0`, `locaddr_cap=0`, where a fresh
`dgram_mem` reports `init=1`, `eof=0`, `guarantee=15104`. `dgram_pair_write`
raises on the non-fatal path where the reads do not.
`BIO_CTRL_DGRAM_GET_LOCAL_ADDR_ENABLE` reports through its pointer and still
returns 1 — passing NULL **segfaults the authority**, so the probe was corrected
and the fault recorded as a divergence rather than reproduced. `BIO_sendmmsg` and
`BIO_recvmmsg` agree on `stride`, on `num_msg == 0` (return 1, `*num_processed =
0`) and on partial success (return 1 with the count), and they raise only when
the *first* message fails.

**Non-claim.** `RT-BIO-DGRAM-PAIR` passing means the candidate matched the
authority for the controls, transfers, rollback and message-batch behaviour it
drove. It is not a claim about the kernel socket datagram BIO (`BIO_s_datagram`,
`BIO_new_dgram`), which is still open, nor about any other Phase 4 surface.

**The inventory after this batch.** Phase 4 owns 256 exports and stands at **190
implemented, 16 deferred to a named later phase, and 50 open**:

    src/runtime/bio/   6   BIO_s_datagram, BIO_new_dgram, BIO_s_connect,
                           BIO_new_connect, BIO_s_accept, BIO_new_accept
    src/runtime/conf/ 44   the CONF_* and NCONF_* families

Both remaining groups are subsystems rather than symbol sets, and both are taken
with their courts. The count of implemented `libcrypto` exports is 402 of 6,499;
31 courts pass over 6,146 observations. Phase 0–3 remain `complete` and Phase 4
remains `in-progress`.

## D47 — The kernel datagram BIO, and three defects its court found elsewhere

**Decision.** `BIO_s_datagram` and `BIO_new_dgram` are implemented in
`src/runtime/bio/bss_dgram.rs`, and `RT-BIO-DGRAM` (294 observations) compares
them against the authority over six sections: a fresh BIO's controls, an invalid
descriptor, the address controls against four peer families, a real loopback
transfer, the receive-timeout bracket, and the message batches. Phase 4 moves
from 50 to 48 open obligations; `implemented` `libcrypto` exports move from 402
to 404.

The SCTP half of `bss_dgram.c` is not part of this: `OPENSSL_NO_SCTP` is defined
in this build profile and the atlas records `BIO_s_datagram_sctp`,
`BIO_new_dgram_sctp`, `BIO_dgram_is_sctp` and the `BIO_dgram_sctp_*` family as
`excluded_by_build_profile`. Nothing was implemented for symbols the authority
does not export.

**The court found three defects, one of them in Phase 3's socket layer.**

1. `BIO_socket_ioctl` raised `BIO_SOCK_248` with `raise_site_dynamic`, i.e. with
   no error data. The authority raises the same site as `ERR_raise_data` with the
   text `"calling ioctlsocket()"` — the Windows spelling of the call, kept on
   every platform. The difference is visible in `ERR_get_error_line_data`: the
   data was empty and the flags were `1` (`ERR_TXT_MALLOCED`) instead of `3`
   (`ERR_TXT_MALLOCED | ERR_TXT_STRING`). It was found by a *new* court observing
   the queue after a `BIO_C_SET_NBIO` on a bad descriptor, and only because this
   probe drains the queue after that control; no earlier court exercised the
   failure path of `BIO_socket_ioctl`. Fixed in place.
2. `BIO_CTRL_DGRAM_GET_RECV_TIMEOUT` and `..._GET_SEND_TIMEOUT` returned `1` on a
   failed `getsockopt(2)` where the authority returns `-1`. The authority assigns
   the syscall's result to the return value *before* testing it, so the failure
   code survives to the end of the control and is then normalized to `-1`; the
   first draft of these two arms left `ret` at its initialised `1`. Both now
   assign the result first, as the source does.
3. `BIO_CTRL_DGRAM_SET_DONT_FRAG` for an IPv6 peer used the
   `IPV6_MTU_DISCOVER` branch. The authority guards that branch with
   `#elif`, behind `IPV6_DONTFRAG`, and this platform *does* define
   `IPV6_DONTFRAG`, so the authority takes the boolean-value branch
   (`sockopt_val = num ? 1 : 0`) and raises from `bss_dgram.c:961` rather than
   `:969`. The difference is a different socket option, a different value and a
   different recorded raise site — all three observable, and all three found by
   comparing the error queue rather than the return value alone.

**A size that is only observable through one control.** `BIO_ADDR` is a union of
`sockaddr`, `sockaddr_in`, `sockaddr_in6` and `sockaddr_un`, so
`BIO_ADDR_sockaddr_size` answers `sizeof(BIO_ADDR)` == 112 for a family it does
not know. Our storage is a whole `sockaddr_storage` (128 bytes) so a
`getsockname(2)`/`accept(2)` that writes the platform's full storage cannot
overflow it, and the first draft therefore reported 128 for `AF_UNSPEC`. That is
invisible everywhere except `BIO_CTRL_DGRAM_GET_PEER` on an unconnected BIO,
which reports the size and copies exactly that many bytes —
`fresh.getpeer.ret` is the observation that pins it. `addr.rs` now has an
explicit `AUTHORITY_ADDR_SIZE` constant for the reported value, with the
storage kept deliberately larger.

**Two internal layouts became evidence.** `dgram_hdr` was the first case (D46);
here it is the `OSSL_TIME` pair. Both timers are *absolute* wall-clock deadlines
rather than durations, because `ossl_time_now()` is the epoch clock, and the read
bracket shortens `SO_RCVTIMEO` to the deadline and then restores the socket's own
timeout. The probe measures the whole bracket on a real socket: it arms a
deadline 400 ms away under a 10-second socket timeout, blocks a read, observes
the read return before a much later bound, and reads `SO_RCVTIMEO` back to
confirm the socket's own timeout — not the deadline — was restored.

**Recorded divergence.** `BIO_CTRL_DGRAM_GET_LOCAL_ADDR_ENABLE` writes through
its pointer without checking it, so a NULL argument faults in the authority. That
is recorded under `docs/SECURITY_DIVERGENCE_POLICY.md` and is not reproduced: the
arm is total, does not write, and reports the value it would have written through
its return instead.

**Non-claim.** `RT-BIO-DGRAM` passing means the candidate matched the authority
for the controls, the syscalls, the error queues and the batch behaviour this
probe drove. It is not a claim about the DTLS pairing that `libssl` performs over
this BIO, nor about `BIO_s_connect`/`BIO_s_accept`, which remain open.

**The inventory after this batch.** Phase 4 owns 256 exports and stands at **192
implemented, 16 deferred to a named later phase, and 48 open**:

    src/runtime/bio/   4   BIO_s_connect, BIO_new_connect, BIO_s_accept, BIO_new_accept
    src/runtime/conf/ 44   the CONF_* and NCONF_* families

32 courts pass over 6,440 observations. Phase 0–3 remain `complete` and Phase 4
remains `in-progress`.

## D48 — The connect and accept BIOs, and three lessons the courts taught back

**Decision.** `BIO_s_connect`, `BIO_new_connect`, `BIO_s_accept` and
`BIO_new_accept` are implemented in `src/runtime/bio/bss_conn.rs` and
`src/runtime/bio/bss_acpt.rs`, and `RT-BIO-CONN` (296 observations) compares them
against the authority. Phase 4 moves from 48 to 44 open obligations; `implemented`
`libcrypto` exports move from 404 to 408. The connect BIO also required the
TCP-Fast-Open and kernel-TLS surfaces, which turned out to be a lesson in itself.

### Lesson 1 — the build record decides the profile, not the platform headers

The first draft inferred the conditional-compilation surface from what the
*container's* headers define. They define `TCP_FASTOPEN`, `TCP_FASTOPEN_CONNECT`,
`SOL_TLS`, `TLS_TX` and the rest, and a kernel-TLS module was written to match.
`RT-BIO-CONN` measured `BIO_C_SET_TFO` answering **0** — the `default` arm — where
the draft answered 1.

The authoritative source is `forensics/authorities/build/openssl-3.6.4-production/configdata.pm`:
the build was configured `no-tfo` **and** `no-ktls`, so every fast-open and
kernel-TLS branch is compiled out, in `bss_conn.c`, `bss_acpt.c`, `bss_sock.c`
and `bio_sock2.c` alike. The `src/runtime/bio/ktls.rs` module, the KTLS arms in
`sock_ctrl` and `conn_ctrl`, the `TCP_FASTOPEN*` constants and the `BIO_connect`/
`BIO_listen` fast-open branches were all deleted. What remains is the inert
`tfo_first` field (written by the connect-mode control, read by nothing) and the
two KTLS control numbers in `mod.rs`, documented as taken-but-unimplemented
because a profile with kernel TLS would need them.

This is the same discipline the SCTP exclusion already had: **read the build
record, then the source, then the headers** — and never the headers alone.

### Lesson 2 — a court that cannot see a crash accepts two of them

`RT-BIO-CONN`'s first run "passed" with 65 observations while **both** sides died
of `SIGSEGV` in the same place: the probe passed a `BIO_METHOD *` to
`BIO_method_name`. The verdict compared exit codes, and `-11 == -11` is equality.

Both court harnesses now take a signal — a negative exit code on either side — as
an explicit failure (`"crashed": true`), because a probe that dies compared
nothing beyond the prefix it printed. That change immediately found two more
identical-crash pairs in **Phase 3**'s own courts, which had been passing the same
way for the same reason:

* `RT-LHASH`'s probe captured a `FILE *` report with `open_memstream`, which
  `<stdio.h>` declares only under `_GNU_SOURCE` — and `phase3_courts.py` did not
  pass `-D_GNU_SOURCE`. The implicit declaration returned `int`, the `FILE *` was
  truncated, and the probe wrote through a bogus stream. With the flag added the
  probe gains the observation that had been lost (`stats.file`, 53 → 56
  observations, and the two NULL-boundary markers).
* `RT-THREAD`'s probe called the NULL-argument `CRYPTO_atomic_*` entry points,
  which fault in the authority — the behaviour divergence `D-MEM-ATOMIC-1` already
  recorded but which the probe still exercised. Those calls are now markers
  (36 → 40 observations).

Neither was a candidate defect. Both were courts that could not tell agreement from
a shared crash, which is the same failure mode as a court that cannot see the axis
it claims to test.

### Lesson 3 — the four defects `RT-BIO-CONN` found

1. **`BIO_sock_non_fatal_error`'s membership set was wrong.** It accepted
   `ECONNREFUSED`, `ECONNRESET` and `ENOBUFS`, which the authority's list does
   **not** — that list is `EWOULDBLOCK`, `ENOTCONN`, `EINTR`, `EAGAIN`, `EPROTO`,
   `EINPROGRESS`, `EALREADY`, identical to `BIO_fd_non_fatal_error`'s. The defect
   is visible only through a *refused* `connect(2)`: the authority raises the
   `BIO_connect` error pair and walks to its next address, where the candidate
   treated the refusal as retryable and raised only its own error. `retry.rs` was
   already right; `bss_sock.rs` now shares its predicate. The probe gained a
   direct classifier table over sixteen `errno` values so the sets are compared
   value for value.
2. **`conn_state`'s info callback must observe the arm's result.** The authority
   threads one `ret` variable through the state machine and hands it to the
   callback, so the callback sees the descriptor a `CREATE_SOCKET` arm just made
   and the 1-or-0 a `CONNECT` arm just returned. The first draft assigned the
   results to locals and left `ret` at its initialised `-1`, so every callback
   reported `-1` while the connection still succeeded — an observation only an
   installed callback can make.
3. **A C `switch` break is not a `goto exit_loop`.** `conn_state` uses `break` to
   re-enter the machine *through* the callback and `goto exit_loop` to leave it.
   The draft wrote both as one construct, which skipped the callback on one path —
   and that mattered: a callback returning 0 stops the machine, so the authority
   never reaches the terminal `CONNECT_ERROR` raise when a callback is installed,
   and the draft raised a fourth error the authority does not.
4. **`acpt_state` has two exits and the draft had one.** The authority's `goto end`
   skips the cleanup and `goto exit_loop` runs it; three arms deliberately leave a
   live descriptor parked in the BIO. Collapsing them closed the *accepted* socket
   on the way out, so every read and write on the connection failed with `EBADF`.
   The probe's round trip is what caught it: the client's write reported 4 bytes,
   and the server's read reported `-1` with `errno` 9.

### The two state machines, as reconstructed

`conn_state` and `acpt_state` are transcribed as record types plus a loop whose
arms reproduce the authority's `break`/`goto` structure exactly, including the
error *marks*: `BIO_connect`'s non-retryable failure pops the mark it set, keeps
the two errors it raised, and the terminal state raises again on the next pass —
which is why a refused connect leaves three queue entries and not one. The accept
machine's `LISTEN` arm returns success before accepting anything, `ACCEPT` with a
chain already present is a successful no-op, and `OK` with no chain returns to
`ACCEPT`, so one BIO serves a sequence of connections.

### Non-claim

`RT-BIO-CONN` passing means the candidate matched the authority for the controls,
the two state machines, the callback sequences, the error queues and the loopback
transfers it drove. It is not a claim about the datagram connect mode's DTLS use,
nor about the `AF_UNIX` or `AF_INET6` paths, which the probe does not drive.

**The inventory after this batch.** Phase 4 owns 256 exports and stands at **196
implemented, 16 deferred to a named later phase, and 44 open** — the whole CONF
subsystem, which is the last stratum of this phase:

    src/runtime/conf/ 44   the CONF_* and NCONF_* families

33 courts pass over 6,743 observations. Phase 0–3 remain `complete` and Phase 4
remains `in-progress`.

## D49 — Five exported symbols no phase owned, and the CONF stratum's floor

**Decision.** The `OPENSSL_INIT_SETTINGS` object — `OPENSSL_INIT_new`,
`OPENSSL_INIT_free`, `OPENSSL_INIT_set_config_filename`,
`OPENSSL_INIT_set_config_file_flags`, `OPENSSL_INIT_set_config_appname` — is
implemented in `src/runtime/conf/init_settings.rs`. Phase 4 now owns 261 exports
and stands at **201 implemented, 16 deferred and 44 open**;
`implemented` `libcrypto` exports move from 408 to 413.

**The gap this closes is in the obligation model, not the code.** The five symbols
were owned by *no* phase. They are defined in `crypto/conf/conf_lib.c`, while
Phase 3's `init.rs` family matches the prefix `OPENSSL_init` — lower case — which
does not match `OPENSSL_INIT_new`. The ledgers are prefix-driven, so those five
exports appeared in no `implemented` list, no `deferred` list and no `open` list:
they were silently scaffolded, and every phase could report itself complete with
them outstanding.

That is a worse failure mode than an over-broad deferral, because nothing in the
repository could observe it. The family list in
`forensics/tools/phase4_obligations.py` now carries `OPENSSL_INIT_`, which puts
them under accounting, and `src/runtime/conf/mod.rs` records why they belong to
this stratum rather than to `init.rs` (they are `conf_lib.c` exports, and they are
what carries a configuration filename and application name into
`OPENSSL_init_crypto`).

The lesson generalises: a phase-completeness claim is only as strong as the
*coverage* of its families, and nothing yet checks that every authority export is
owned by some phase. That check belongs with the phase-family tables and is
recorded here as the next thing the ledger tooling should grow.

**The CONF stratum's remaining floor.** The 44 open obligations are the
configuration reader. The data model (`conf_api.c`), the default method — parser,
dumper and the two character-class tables (`conf_def.c`) — and the public
accessor layer (`conf_lib.c`) are *unstarted*, and the module registry plus the
automatic loader are additionally **blocked**: `CONF_modules_load` begins with
`conf_diagnostics`, which reads and writes the `OSSL_LIB_CTX` diagnostics flag,
and `OSSL_LIB_CTX` is Phase 6. That part of the stratum cannot be reconstructed
faithfully before the provider core exists, so it is a genuine structural
dependency rather than a matter of effort, and the module docstring for
`src/runtime/conf/` records it.

Nothing in this batch is scaffolded into looking present: the shell still aborts
loudly on every one of the 44, and the ledger reports them.

**Recorded divergence.** `OPENSSL_INIT_new` and the two `set_config_*` routines
allocate with the C library's `malloc`/`strdup` and free with `free`, **not** with
`CRYPTO_malloc`/`CRYPTO_free`. That is the authority's own choice, made so a
settings object created before the library initialises is not allocated by a
function the caller later replaces with `CRYPTO_set_mem_functions`. It is
reproduced exactly, and it means these five are deliberately invisible to
`CRYPTO_set_mem_functions`. A unit test asserts the layout
(`filename`, `appname`, `flags`, 24 bytes) and the default flag word `0x32`,
because `OPENSSL_config` builds the object by value and passes its address on.

33 courts still pass over 6,743 observations. Phase 0–3 remain `complete` and
Phase 4 remains `in-progress`.

---

## D50 — The CONF reader: the stratum is closed but for a recorded hand-off

**Decision.** Implement the whole configuration reader — `crypto/conf/conf_api.c`,
`conf_def.c`, `conf_lib.c`, and the two `conf_mod.c` exports that do not need an
`OSSL_LIB_CTX` (`CONF_parse_list`, `CONF_get1_default_config_file`) — and hand the
fifteen **module-registry** symbols to Phase 6 as a recorded deferral rather than
approximating them.

**Why the registry cannot be built here.** `CONF_modules_load` begins with
`conf_diagnostics(cnf)`, which is:

```c
static int conf_diagnostics(const CONF *cnf)
{
    ERR_set_mark();
    status = NCONF_get_number_e(cnf, NULL, "config_diagnostics", &result);
    ERR_pop_to_mark();
    if (status > 0) {
        OSSL_LIB_CTX_set_conf_diagnostics(cnf->libctx, result > 0);
        return result > 0;
    }
    return OSSL_LIB_CTX_get_conf_diagnostics(cnf->libctx);
}
```

and its return value then masks the caller's flags:

```c
if (conf_diagnostics(cnf))
    flags &= ~(CONF_MFLAGS_IGNORE_ERRORS | CONF_MFLAGS_IGNORE_RETURN_CODES
               | CONF_MFLAGS_SILENT | CONF_MFLAGS_IGNORE_MISSING_FILE);
```

So the `OSSL_LIB_CTX` diagnostics flag is not a diagnostic detail: it changes which
failures `CONF_modules_load` and `CONF_modules_load_file*` propagate, and therefore
what they *return*. `OSSL_LIB_CTX` is Phase 6. The registry also reaches
`DSO_load`, `OPENSSL_load_builtin_modules` and `ENGINE_load_builtin_engines`, all
later strata. A registry that cannot read the flag would answer a real
configuration's question wrongly, which is worse than not answering it.

The hand-off is machine-checked, not silent: the fifteen symbols are in the
`DEFERRED` table of `forensics/tools/phase4_obligations.py` with `owning_phase = 6`
and a reason, and that tool refuses to run if any export of this stratum's families
is neither implemented nor listed. `docs/RELEASE_GATES.md`'s rule — a deferral
names the phase that owns the subsystem, a gap does not — is what keeps this from
being a way of not doing the work.

**What the reader is.** `src/runtime/conf/` now holds `types.rs` (`CONF`,
`CONF_VALUE`, `CONF_METHOD`), `api.rs` (`conf_api.c`: the model, its hash and
comparison functions, the lookups, the two-phase free walk), `def.rs`
(`conf_def.c`: both character-class tables, the parser, the dumper, the two method
tables), `lib.rs` (`conf_lib.c`: the classic-hash bridge, the `NCONF` accessors,
`NCONF_get_number_e`) and `modparse.rs` (`CONF_parse_list` and the default-config
path).

**The court is `RT-CONF`, 736 observations, zero residuals.** It drove a new
kind of requirement for this project: the grammar is *input that people write*, so
almost every rule has a plausible-but-wrong implementation, and the authority's own
source contains the traps — the BOM strip only on the first read, the `key > 127`
rejection in `is_keytype`, the "second last char is not `\`" continuation
condition, `;` being punctuation in the *default* table and a full-line comment in
the *WIN32* one, `#` being a comment in the default table and *nothing at all* in
the WIN32 one, and `buf->length` rather than the content length in the expansion
cap. Every one of those is observed on both sides rather than assumed.

**Correction to D18's and D49's method.** The module-registry deferral was first
described as a *blocked* stratum in prose. That is not enough on its own: prose
about a blocker cannot fail, so it cannot distinguish "blocked" from "forgotten".
The machine-checked part is the ledger entry, and that is what the release gates
read.

---

## D51 — Thirteen exports no phase owned, and the audit that finds the next ones

**Decision.** Add `src/runtime/str.rs` (`crypto/o_str.c`) and `src/runtime/dir.rs`
(`crypto/o_dir.c`) to the Phase 3 runtime stratum, and add
`forensics/tools/ownership_audit.py` — which fails the build if any *implemented*
export is claimed by no phase family at all.

**Why.** D49 recorded that five `OPENSSL_INIT_*` exports were invisible to every
ledger because no family's prefixes matched them, and closed with the observation
that "nothing yet checks that every authority export is owned by some phase" and
that the check "belongs with the phase-family tables". This is that check, and it
found the same defect a second time — larger, and in files the CONF reader needed.

`crypto/o_str.c` exports eleven symbols: `OPENSSL_strnlen`, `OPENSSL_strlcpy`,
`OPENSSL_strlcat`, `OPENSSL_strtoul`, `OPENSSL_hexchar2int`,
`OPENSSL_hexstr2buf[_ex]`, `OPENSSL_buf2hexstr[_ex]`, `OPENSSL_strcasecmp`,
`OPENSSL_strncasecmp`. `crypto/o_dir.c` exports two: `OPENSSL_DIR_read`,
`OPENSSL_DIR_end`. None matched any prefix any ledger listed. All thirteen are now
implemented and owned; the CONF reader is what forced the issue, because
`conf_def.c`'s `.include` handling uses `OPENSSL_strlcpy`, `OPENSSL_strlcat`,
`OPENSSL_strcasecmp`, `OPENSSL_DIR_read` and `OPENSSL_DIR_end`, and a private
duplicate of those would have been a hidden implementation of an exported ABI
surface — the thing the constraint list forbids.

**The invariant the audit enforces, and why it is scoped.** The full invariant
("every authority export is owned") cannot hold while phases 5-21 have no families;
5,410 of libcrypto's 5,896 exports are legitimately unclaimed today. What must
never be true is an export being *implemented* while owned by nobody, because that
is the state in which work is invisible to the accounting it is supposed to appear
in. So the audit:

* **fails** on an implemented-but-unowned export;
* **reports**, in full and with per-class counts, the unowned remainder — the
  scope no stratum has claimed, as a visible fact rather than an implied one;
* **reports** `handoffs` (a symbol two phases claim, which is the deliberate
  Phase 3 → Phase 4 mechanism) and `overlaps` (a symbol two prefixes of one family
  list both match, which is how an accident looks).

It is a CI gate and an entry in the determinism/portability artefact set, so its
output is reproducible evidence rather than a one-off report.

**Consequence for a closed phase.** Phase 3's family list grew after its seal, so
its ledger now reports 235 owned rather than 220. That is not a rewrite of the
seal: D13 established that a decision stays true while the *observation* it quotes
evolves, and current counts are derived from the ledgers and `STATUS.md`, never
from `DECISIONS.md`. The seal's prose is a census at seal time; the ledger is the
present tense.

**Also fixed by this audit.** Three implemented exports were unowned for the same
reason: `BUF_reverse` (Phase 4's family said `BUF_MEM_`, and `BUF_reverse` is not a
`BUF_MEM_` name), `CRYPTO_alloc_ex_data` and `OPENSSL_cleanse` (Phase 3's families
listed their neighbours explicitly rather than by prefix).

---

## D52 — `OPENSSL_LH_insert` appends at the tail, and the dump order proves it

**Decision.** `OPENSSL_LH_insert` links a new node at the **end** of its bucket's
chain, not the beginning. The comment in `src/runtime/lhash.rs` claiming the
opposite was wrong, and is replaced with the reason.

**Why.** The authority's `getrn` walks the whole chain and returns a pointer to the
*last* node's `next` slot on a miss:

```c
for (n1 = *ret; n1 != NULL; n1 = n1->next) {
    if (n1->hash != hash) { ret = &(n1->next); continue; }
    if (lh->compw(...) == 0) break;
    ret = &(n1->next);
}
return ret;
```

so `*rn = nn` appends. A bucket's head is therefore its **oldest** entry, and
`doall` — which walks head to tail — visits a bucket in *insertion* order.

**How it was found, and why nothing else could find it.** No existing court could:
`RT-LHASH` cannot measure the `doall` family at all, because the authority faults
at the NULL thunk on a table built by a bare `OPENSSL_LH_new` (D-LHASH-1). The
CONF court could, for a reason specific to this stratum: `def_dump` is
`lh_CONF_VALUE_doall_BIO`, so `NCONF_dump_bio` *is* a walk, and two keys that collide
in one bucket come out in chain order. `RT-CONF` reported nine
`dump.text` residuals, all permutations, which is what a wrong chain direction looks
like. Prepending was a plausible assumption, not a measurement, and it survived
three phases of courts because none of them could see it.

Fixed and pinned by a unit test that hashes every key into one bucket and asserts
the walk yields insertion order. Phase 4's courts are otherwise unchanged by it,
which is itself the point: the defect was invisible to every court that existed.

---

## D53 — `ERR_raise_data` is formatted by `BIO_vsnprintf`, not by libc

**Decision.** `ERR_vset_error` in `src/runtime/err_variadic.c` formats with this
crate's own `BIO_vsnprintf` (`_dopr`), over a buffer it grows to `ERR_MAX_DATA_SIZE`
and shrinks to the printed length, exactly as `crypto/err/err_blocks.c` does. The
queue's state stays in Rust; only the `va_list` and the buffer moves.

**Why.** The authority's implementation is:

```c
buf = es->err_data[i]; buf_size = es->err_data_size[i];
es->err_data[i] = NULL; es->err_data_flags[i] = 0;          /* reserve it */
if (buf_size < ERR_MAX_DATA_SIZE && (rbuf = OPENSSL_realloc(buf, ERR_MAX_DATA_SIZE)))
    { buf = rbuf; buf_size = ERR_MAX_DATA_SIZE; }
printed_len = BIO_vsnprintf(buf, buf_size, fmt, args);
if (printed_len < 0) printed_len = 0;                        /* truncation -> empty */
buf[printed_len] = '\0';
if ((rbuf = OPENSSL_realloc(buf, printed_len + 1))) { ... }
```

The engine matters for the bytes a caller reads back through `ERR_get_error_all`:
`_dopr` renders `%s` of NULL as `<NULL>` and `%p` of NULL as `0`, and libc's
`vsnprintf` renders neither. The step that matters most is the third: `_dopr`
reports *truncation* as failure, so a message longer than `ERR_MAX_DATA_SIZE`
becomes an **empty** string rather than a truncated one — a distinction a
caller cannot see from the length, only from the bytes.

**What was wrong.** The previous implementation used a 1024-byte stack buffer and
libc's `vsnprintf`, then handed the result to `openssl_rs_err_set_error`. That is
observably different in three ways: the `%s`-of-NULL rendering, the `%p` and `%e`
renderings, and the truncation case. It survived Phase 3's `RT-ERR` court because
that court's raise-site section exercises sites whose messages have no
substitutions and are short.

**How it was found.** Writing `NCONF_get_number_e` required knowing what
`ERR_raise_data(ERR_LIB_CONF, CONF_R_NO_VALUE, "group=%s name=%s", group ?: "",
name)` puts in the queue when `name` is NULL — a reachable call, since
`NCONF_get_number_e(conf, group, NULL, &res)` is one. The answer is
`name=<NULL>`, which libc's `vsnprintf` does not produce.

**New Rust surface.** `openssl_rs_err_take_data` and
`openssl_rs_err_finish_data`, which are the two points where the buffer crosses
between the formatter and the queue. They exist so that the *formatting* can happen
where `va_list` exists without moving the queue's state out of Rust.

---

## D54 — `get_next_file` clears its own out-parameter, and the CONF court crashed

**Decision.** After `OPENSSL_DIR_end(dirctx)` at the end of `get_next_file`, the
function sets `*dirctx = NULL`. `OPENSSL_DIR_end` itself continues to leave the
caller's pointer dangling, as the authority's does.

**Why the two are different.** The authority's `LP_find_file_end` frees the context
and does not clear the caller's pointer — `src/runtime/dir.rs` reproduces that
faithfully, and a unit test asserts it, because a caller who reuses the context
without resetting it gets whatever the authority gives it. But
`get_next_file` is the *owner* of that out-parameter, and it does clear it:

```c
if ((next = get_next_file(dirpath, &dirctx)) != NULL) { ... }
else { OPENSSL_free(dirpath); dirpath = NULL; }
...
OPENSSL_DIR_end(dirctx);
*dirctx = NULL;          /* <-- the line that was missing */
return NULL;
```

Without it, the parser's "am I still walking a directory?" test — the pointer
itself — stays true after the directory is exhausted, so the next end-of-file calls
back in with a `dirpath` that has already been freed. The candidate segfaulted;
the authority does not. Found by bisecting the CONF court's first crash with
temporary `eprintln!` instrumentation, which is also how its location was
established: the third `get_next_file` completed and then the process died on the
*fourth* entry into the same branch.

**Lesson.** A faithful copy of a destructor's *own* contract is not a faithful copy
of its *caller's* obligations. The authority's `get_next_file` had two statements
where the port had one, and the missing one was the difference between a working
directory include and a double-free.

---

## D55 — Phase 4 ledger: a hand-off is not a gap

**Decision.** `forensics/tools/phase4_obligations.py` computes `complete` as
`not open_rows`, rather than requiring the deferred list to be empty as well.

**Why.** The field's own note, and the phase-state rule, both say what completion
means: every export in the stratum's families is either implemented or *handed to a
later phase whose subsystem it needs*, with `open` being the list of recorded gaps.
The expression required both lists to be empty, which made `complete` permanently
false for any stratum that legitimately hands anything forward — and Phase 4 now
does, fifteen times. The field is advisory (phase-state derives the state from
`counts.open_in_this_stratum`), but a field in a committed evidence file that
contradicts the note beside it is exactly the kind of drift this project treats as a
defect.

---

## D56 — Two more recorded divergences, and the CONFIG default path

**Decision.** Record two safety divergences and one deliberate compatibility
divergence introduced by this stratum, in
`docs/SECURITY_DIVERGENCE_POLICY.md`:

1. **`CONF_parse_list` with a NULL callback.** The authority calls it and faults;
   the candidate treats a NULL callback as "nothing to deliver to" and returns 0.
   Same class as D-LHASH-1, and `RT-CONF` prints a label rather than the value.
2. **`_CONF_new_section`'s error path.** The authority frees `v->section` even when
   the allocation that would have initialised it failed. Reachable only under
   allocation failure; the candidate frees only what it allocated.
3. **`CONF_get1_default_config_file` with `OPENSSL_CONF` unset.** The authority
   answers with `X509_get_default_cert_area() + "/openssl.cnf"`, where the cert area
   is the build's `OPENSSLDIR` — for the admitted authority,
   `/work/forensics/authorities/prefix/openssl-3.6.4-production/ssl`. That path
   describes *the forensic build's installation directory*, and this implementation
   is not installed there. `src/runtime/init.rs` already made and recorded the same
   decision for the same constant (`OBL-INIT-VERSION-DIRS`, which answers
   `OPENSSLDIR: N/A`), so the candidate answers with the empty string — the
   authority's own idiom for "no such path", which `CONF_modules_load_file_ex`
   short-circuits as "do not load a file" without erroring. The open obligation is
   `OBL-CONF-DEFAULT-CONFIG-FILE`, owned by Phase 16, which fixes the
   distribution's install layout.

**Why the third is a divergence and not a bug.** Reproducing the authority's answer
byte for byte is what `ERR_get_error_all`'s `file` and `line` do (D41), and the
difference is that those coordinates are *provenance* — there is no other truthful
value — while this is a *functional path* a caller will try to open. Pointing a
caller at a directory that exists on no machine this crate ships to is a worse
answer than "there is none configured yet", and the divergence is recorded, named
and owned rather than silently smoothed over. The environment branch is implemented
exactly, and it is what `RT-CONF` compares.

## D57 — A hand-off is sticky, and the two ledgers are reconciled against each other

**Decision.** A symbol a stratum has handed to a later stratum stays that stratum's
to own, and the deferring ledger keeps recording it as `deferred` even after the
owning stratum implements it. The receiving stratum declares which hand-offs it
discharged, and `forensics/tools/ownership_audit.py` fails if the two lists differ
or if any symbol is counted as implemented by two strata at once.

**Why this was wrong before.** Phase 3 deferred eleven exports to Phase 4 —
`ERR_print_errors`, `ERR_print_errors_cb`, `ERR_print_errors_fp`,
`ERR_add_error_mem_bio`, the six `OPENSSL_LH_*stats*` and `OBJ_create_objects` —
because each needs a `BIO *` or a `FILE *` sink and BIO is Phase 4. The sealed
Phase 3 document records exactly that, and says they stay `SCAFFOLDED` and abort.
Once Phase 4 implemented them, `phase3_obligations.py`'s deferral table stopped
applying (it only consulted the table for symbols that were *not* implemented), so
Phase 3 silently reclaimed them: its ledger moved from `deferred: 11` to
`implemented: 235, deferred: 0` while `docs/PHASE-3-CORE-RUNTIME-SEAL.md` still
said the opposite. Both ledgers then counted the same eleven symbols as their own
implemented work, and their `owned` totals summed to eleven more than the number
of exports actually owned by any family (497 against 486).

Two strata coordinating on one symbol is the intended device — it is how Phase 4
itself hands `BIO_f_md` to Phase 7 — so the fix is not to forbid the overlap but to
define it: exactly one stratum *implements*, and the other *records the hand-off*.
The audit now proves that mechanically, which is the only reason a reader can trust
`STATUS.md`'s per-stratum figures.

**Consequence.** Phase 3 stands at 235 owned, 224 implemented, 11 deferred (all
marked `implemented_by_owner`, so the discharged hand-offs are visible rather than
inferred). Phase 4 stands at 262 owned, 231 implemented, 31 deferred, 0 open. The
distinct owned total is 486, which is what the audit reports.

**Also in this decision.** `phase_state.py`'s Phase 3 and Phase 4 evidence lists
named only a subset of the modules each stratum actually added — the Phase 4 list
stopped at the modules the stratum had when its seal was drafted, and neither list
named the discovery probes that `docs/DECISIONS.md` and
`docs/SECURITY_DIVERGENCE_POLICY.md` cite as the origin of recorded measurements. A
required-evidence list that omits the evidence is a weakened gate, so both lists are
now complete, and `ownership-audit.json` gained the two cross-ledger invariants.

## D58 — The FRF court declarations are generated from one table

**Decision.** `forensics/tools/gen_frf_courts.py` owns the runtime courts' manifests
and fixtures. `--check` re-derives every declaration and fails on any drift, and CI
runs it.

**Why.** A runtime court is nine-tenths boilerplate: nineteen manifests differed
only in the court id, the one-line description of the subsystem, the staging phase
of the probe binaries and the paths those imply. With the table spread across the
files, "which runtime surfaces have an FRF court?" had to be answered by `ls`, and
the `version_or_commit` the courts name had to be bumped by hand in each file at
every release — the kind of step that gets done for the files somebody remembered.
Phases 5-21 will add hundreds of courts.

**What changed in the sealed Phase 3 courts.** Regenerating them was not cosmetic
and is recorded here rather than glossed: each court's `fixture.arguments` gained an
explicit staging-phase argument (`["{fixture}", "phase3"]`), so one harness serves
every runtime stratum and the directory the probes are read from is a declared court
input instead of a constant inside the two reference wrappers. The wrappers now
validate that argument and refuse a staging directory that is absent, because a
missing directory would otherwise make a court "pass" by comparing two empty
transcripts. The Phase 3 wording was also made consistent with the id
(`the Phase 3 \`rt-mem\` runtime surface`), and `version_or_commit` moved to `0.0.7`
for every court at once. No court's question, falsifier, authority, fixture list or
observed axis changed.

## D59 — The lint gate is a hard gate now

**Decision.** `continue-on-error: true` is deleted from the `lints` job in
`.github/workflows/ci.yml`. `cargo clippy --all-targets -- -D warnings` must pass on
every pushed commit, like the other gates.

**What it took.** D45 recorded 251 diagnostics of pre-existing debt in the Phase 4
BIO modules and deferred the decision; by the time the CONF stratum landed the count
was 522, almost all of them the two unsafe-documentation lints
(`undocumented_unsafe_blocks`, `missing_safety_doc`). They were cleared by writing
the actual invariant at each site — the caller contract for the `extern "C"` entry
point, the validity and lifetime of the `BIO *` or `CONF *` being dereferenced, the
ownership of a descriptor or method table — and not by adding an `allow`, which
`docs/UNSAFE.md` forbids and which would have hidden precisely the unsafe code a
reader most needs annotated. The count is now zero crate-wide.

Two of the clearances changed code rather than comments: `bss_conn.rs`'s
`crosspointer_transmute` sites became `core::mem::transmute_copy(&cb)`, which copies
the same bits without the dereference clippy's suggestion would have introduced (the
stored value *is* the callback's code address, not the address of a function
pointer), and `lhash.rs`'s `checked_div`/`checked_rem` fallbacks are unreachable
under the enclosing `n_used != 0` guard. Everything else was comments, plus a
handful of provably equivalent style rewrites. All 34 differential courts were
re-run afterwards and none moved, which is the evidence that the equivalence claims
hold rather than a reason to believe them.

## D60 — The `doall` dispatch, and six ERR coordinates read from the wrong function

Two defects fixed with the CONF stratum that D52-D56 did not cover.

**`OPENSSL_LH_doall_arg_thunk`'s `thunk` argument is a per-node wrapper, not an
iteration entry point.** Its signature is
`void (*)(void *node, void *arg, OPENSSL_LH_DOALL_FUNCARG func)`: it is called once
per node with *that node* and dispatches to `func`. The implementation called
`t(lh, arg, func)` — handing the callback the table pointer and invoking the thunk
once for the whole table. Nothing failed loudly, because the only callback in reach
was `def_dump`, whose `lh_CONF_VALUE_doall_BIO` would have printed the table's
address as if it were a `CONF_VALUE` pointer. `doall` and `doall_arg` now dispatch
through `lh->daw`/`lh->daaw` per node, and `visit()` snapshots the item pointers
before walking so a callback may delete its own node — which `_CONF_free_data`
does, and which a live-walk would turn into a use-after-free. D52 is what exposed
this: it needed `doall` order to be correct, and a thunk that fired once could not
produce an order at all.

**`gen_err_raise_sites.py`'s `enclosing_function` mis-parsed six of 316 raise
sites.** These coordinates are not internal: `ERR_get_error_all` returns the `file`,
`line` and `func` of the raising site, so a wrong function name is observable
through a public API. The naive scan matched the first identifier that looked like a
definition, which produced `HASH_OF` for `CONF_load`, `TACK_OF` for
`NCONF_get_section`, `EFINE_RUN_ONCE_STATIC` for `do_init_module_list_lock` and
`dopr` for `_dopr` — the last four characters of `PEM_ASN1_write_bio`-style macros
and of the `DEFINE_*`/`IMPLEMENT_*` families. It is replaced with a paren-balancing
`definition_name()` that returns the parenthesis group **enclosing** what follows,
which is the only reading that does not depend on an identifier's first character.

**Also.** `COVERED_FILES` gains `crypto/o_str.c` (stem `O_STR`), adding seven raise
sites that the CONF reader had been pulling in through `OPENSSL_strlcpy` and friends
without any of them being in the coordinate table.

## D61 — One court's capture leaked an ASLR address, and the fix is measured by re-running it

**Decision.** The `RT-BIO-DEBUG` probe redirects descriptor 2 to a temporary file
for the duration of the single `BIO_debug_callback_ex` call whose destination is
NULL, then restores it and reports the scrubbed text as two further observations
(`stderr.ctrl.text`, `stderr.ctrl.textlen`). The court's transcript grows from 55
observations to 57.

**Why.** That call's documented behaviour is to fall back to stderr, and its message
begins with the subject's address. The court declares `stdout` and `exit` as its
axes, and its stdout was already correct — every address in the text it captures
from a destination BIO is masked to `<addr>` before printing, precisely because the
address is an allocator artefact rather than contract. But FRF's *capture* includes
stderr, and the run identity is derived from the capture, so the live address made
this one court's evidence identity differ on every run. Measured: three re-runs of
the court against one store produced three different run ids. Nothing else did — the
other twenty-two runtime courts produced identical run ids across three full
re-runs of `forensics/frf/run_courts.sh`, including after the candidate library was
rebuilt, which independently confirms the note in `forensics/frf/README.md` that the
run identity does not vary with `execution_context` artifact hashes. One court was
enough to make the *aggregate* runtime claim's identity unstable, which is what
first made this visible: the claim id changed between two runs whose sources were
identical.

**Why ASLR was not simply disabled.** `setarch -R` is refused in both court
containers — `failed to set personality to (null): Operation not permitted` — so
there is no container-level fix. Redirecting the whole harness's stderr, or
discarding it, was rejected: `phase4_courts.py` records the candidate's stderr tail
as evidence, and a genuine diagnostic on stderr is exactly what a reader needs when
a court fails. Capturing the bytes at the point of the call and masking only the
address keeps every byte and makes the identity reproducible.

**How it was checked.** Re-running the court against the same store now returns the
identical run id, and FRF *refuses to re-capture*: `already exists and verifies
(identical evidence was already captured)`. That refusal is the acceptance test, and
it is falsifiable in one command. The claim ids recorded in
`docs/PHASE-4-BIO-CONF-SEAL.md` §8 are the ones this fix produced.

## D62 — The court owns its build directory, and no committed artefact records an ASLR address

Two tooling defects found by re-running a verification step, both of which made
committed evidence depend on something that is not part of the observation.

**The court and the host were sharing `target/` across two glibc versions.**
`target/flycheck0` is rust-analyzer's footprint: the editor runs `cargo check` on
the *host*, linked against the host's glibc (measured: 2.44), while the court image
is pinned to 2.36. Because `target/` is inside the bind mount, a dev-profile build
in the court picked up a host-built build script and died with

```
/lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.39' not found
```

which reads exactly like a defect in the crate and is not one. The court now
removes host-owned entries under `target/debug` (and `target/flycheck0`) before it
runs anything, only when it is root, and only in the dev profile: the release
artifacts the distribution shell is built from are always the court's own and are
never touched.

Isolating the court's build directory with `CARGO_TARGET_DIR` was implemented first
and reverted. It fixes the collision, but it changes the archive path recorded in
`forensics/atlas/implemented-surface.json`, so the same artefact would be generated
with two different recorded paths depending on the environment that ran the
generator — and `evidence_determinism.py` compares every field except the declared
build-product digests. Reshaping a recorded evidence field to suit the tooling is
the wrong trade; purging debris that was never evidence is the right one.

**`ABI-SUBSTITUTION` and `libcrypto-contamination` recorded `ldd` load addresses.**
`ldd` prints each resolved object with its load address, which is an ASLR artifact of
the run, and those lines are committed. Measured: two runs of
`build_phase2.sh` produced different `dynamic_closure_under_substitution` entries.
Both courts' claim is *which file* each library resolved to, and their verdicts
compare paths, so the address is masked to `(0x<load-addr>)` and nothing else in the
line changes. Two consecutive runs now reproduce those two artefacts byte for byte.
This is the same defect class D61 found in the `RT-BIO-DEBUG` capture: a court whose
verdict is deterministic and whose *record* was not.

`evidence_determinism.py` did not catch either one, and the reason is worth stating:
court transcripts and staged binaries are deliberately outside its compared set,
because they are produced by the court venue rather than by the generators it
re-runs. That boundary is right — but it means a court's own output is only checked
by re-running the court, which is how both of these were found.

## D63 — A compared artefact's own hash is compared modulo its declared normalisation

**Decision.** When a compared artefact records the `sha256` of an input that is
*itself* a compared artefact, that recorded hash is normalised on both sides.
`evidence_determinism.py` gains the rule; `check_evidence_portability.py` shares it
because it imports the same `normalise`.

**Why.** CI failed on the first push of the Phase 4 seal, at `Evidence determinism`,
with:

```
STALE: forensics/atlas/ownership-audit.json: .inputs[0].sha256:
  committed '6ce78192…' vs regenerated '04ede079…'
```

`implemented-surface.json` is an input of `ownership-audit.json`, which records the
hash of the file it read. On the CI runner the crate archive is not byte-identical
to the court's, so `implemented-surface.json` is regenerated with a different
`crate-archive` sha256 and a different `internal_symbols.compiler_emitted_count` —
both of which the tool normalises *when comparing that artefact* — and therefore a
different file hash, which `ownership-audit.json` recorded and the tool compared
exactly. The gate was reporting a stale artefact for a reason that had nothing to do
with staleness: the inner artefact compared **equal** in the same run.

The rule is not a blanket exemption. The inner artefact is compared directly, so a
substantive change to it fails on its own account before any outer artefact's input
hash is reached; what is blanked is a binding that could only ever hold modulo a
normalisation the inner artefact already declares. Three inputs are affected today:
`implemented-surface.json` (read by `ownership_audit.py`) and the Phase 3 and Phase 4
obligation ledgers (read by `phase_state.py` and `ownership_audit.py`).

**Why it appeared now.** The latent defect needed a run in which the two environments
disagreed about the archive. The court and the runner had agreed until this push.
That is the second time in this stratum that a gate failed only because an
environment changed underneath it (D62 is the first), and both were found by CI
rather than by the court — which is the point of running the same gates in both.

## D64 — Phase 5's scope is derived from the atlas, and its families cannot be typed

**Decision.** Phase 5's symbol families are **generated** by
`forensics/tools/phase5_obligations.py` from the Phase 1 atlas, not written out as
`(module, prefixes)` pairs the way Phases 3 and 4 do. The rule is one sentence:

> A symbol belongs to the stratum that owns the header declaring it.

with one exception the header alone cannot express — `pem.h` declares both the
generic PEM machinery and the typed readers and writers for types owned elsewhere
(`PEM_read_bio_X509` is Phase 11's even though `pem.h` declares it), so those are
resolved by the type in the name, looked up in the atlas.

**Why the families cannot be typed.** Phase 5's candidate surface is 1,093 exports
spanning **270 distinct ASN.1 type names**. `d2i_X509` and `d2i_ASN1_INTEGER` look
alike and belong to different strata, and no prefix list can separate them. Prefix
lists are also how the D49/D51 defect class arose twice — an export matching no
listed prefix is invisible to every ledger at once — and a hand-maintained list of
1,093 names would be that defect with a larger blast radius.

**The measured scope.** Of the 1,093 candidates, **513 are Phase 5's** — 201
declared in `bn.h`, 274 in `asn1.h`/`asn1t.h`, and 38 generic PEM entry points —
and **580 are handed to later strata**, each with its declaring header recorded as
the reason: 23 to Phase 7 (`evp.h`), 58 to Phase 8 (`dsa.h`, `dh.h`, `rsa.h`,
`ec.h`), 12 to Phase 10 (`pkcs12.h`), 346 to Phase 11 (`x509.h`, `x509v3.h`,
`x509_acert.h`) and 141 to Phase 12 (`cms.h`, `ocsp.h`, `ts.h`, `pkcs7.h`,
`crmf.h`, `cmp.h`, `ess.h`, `ct.h`). The ledger fails closed: a header with no
entry in its `HEADER_PHASE` table, or a PEM type that will not resolve, stops the
run rather than defaulting to "probably Phase 5".

**A consequence worth stating.** Type → header resolution needs weighting, because
`types.h` forward-declares *every* type and `pem.h` declares a reader for most of
them; a naive lookup answers `pem.h` for `X509` and would assign 346 X.509 codecs
to Phase 5. The resolver therefore prefers the struct definition, then the
functions that take or return the type, then the typedef, and treats `types.h` and
`pem.h` as "no opinion".

**Not yet done, and how the ledger says so.** The ledger reports 0 implemented and
513 open, and `complete: false`. `phase_state.py` continues to report Phase 5 as
`not-started` because Phase 5 has no required-evidence list or courts yet; that
change lands when the stratum has something to gate.

**Where the work stands.** The `BN` substrate exists in the working tree —
`src/bn/limbs.rs` (Knuth algorithm D division, schoolbook multiplication, binary
GCD, extended-Euclid inverse, shifts and bit operations, with twelve unit tests
whose expectations were checked against an independent bignum), `src/bn/bignum.rs`
(the object, its lifetime, predicates, byte/MPI/hex/dec conversions and the
`BN_CTX` pool) and `src/bn/arith.rs` (the arithmetic entry points). It is **not
committed and not wired into the crate**, for two reasons that are both evidence
reasons rather than tidiness: it does not yet pass the crate's lint gate — making
the entry points `unsafe extern "C"` per `docs/UNSAFE.md` cascades into roughly
sixty internal calls that each need their own `SAFETY` comment — and it has **no
differential court**, so committing it would put symbols into the ABI shell as
"implemented" on the strength of unit tests alone. `docs/PARITY_MODEL.md` does not
allow that, and Phase 4's own history is the argument: the courts found defects in
code that already looked finished, five times in one stratum.

**Three expectations, not implementations, were wrong.** The first version of the
BN unit tests asserted three hex values that the implementation disagreed with;
all three were the test author's arithmetic, confirmed against an independent
bignum, and the implementation was right. The `mod_inverse` test then asserted an
inverse for operands sharing the factor 147, which correctly does not exist. This
is the same failure mode the courts guard against, and it is recorded because the
lesson generalises: in this project the expectation is the suspect, every time.

## D65 — `RT-BN` found nine behaviours, and one of them was an ABI-level signature

**Decision.** The `BIGNUM` stratum is committed with its differential court, and the
court's findings are the reason the stratum is trustworthy rather than the reason it
looks finished. `RT-BN` compiles `courts/phase5/rt_bn_probe.c` twice — against the
admitted authority and against the candidate shell — runs both and diffs the
transcripts line by line on `key=value`. It passes with **475 observations and 0
residuals**. It is not a parity percentage and it is not security evidence; it is a
differential result for the behaviours the probe exercises, on one build profile
(D2).

**The first run was a probe bug, and that is now the tenth time.** The probe died
with `SIGSEGV` on the *authority* side, at `stage=authority-run`. `BN_free` does not
clear the caller's pointer, and the probe reused a freed `BIGNUM` slot through
`BN_asc2bn(&a, ...)` after freeing it. Clearing the slot turned a crash into 45
residuals. The rule that produced that diagnosis is worth restating because it has
now paid ten times: when a court fails, the probe is the suspect before the
implementation is.

**What the 45 residuals were.** Every one was a plausible reading of the API that is
wrong:

- **`BN_bn2hex` is byte-oriented**, not nibble-oriented: the authority suppresses
  leading zero *bytes* and then writes both digits of every byte it keeps, so `2` is
  `"02"`. Thirty-two of the 45 residuals were exactly this, one nibble wide.
- **`BN_cmp` orders by sign before magnitude.** Negating the magnitude comparison
  whenever `a` is negative is right for two negatives and inverts the mixed-sign case;
  the probe's `a = -0xffffffffffffffff`, `b = 1` separates them.
- **`BN_asc2bn` answers 1 or 0**, not the digit count its radix-specific relatives
  return.
- **`BN_usub` reports only a limb-count shortfall** (`bn_add.c`), and at equal width it
  lets the final borrow escape, returning `a - b mod 2^(64*len)`. `BN_add(3)` calls
  that undefined; a precompiled caller sees the wrap, so the wrap is reproduced.
- **`BN_mask_bits` refuses a width the value does not have**:
  `ossl_bn_mask_bits_fixed_top` answers 0 when the width reaches past the top limb.
- **The `mod` family reduces last, not first.** `BN_mod_add`/`_sub`/`_mul` are the true
  signed operation followed by one `BN_nnmod`; reducing the operands first differs by
  exactly the modulus whenever an operand is negative.
- **The `_quick` variants are their own algorithms**, not aliases: `BN_mod_lshift_quick`
  reports `BN_R_INPUT_NOT_REDUCED` for an operand outside `[0, |m|)` rather than
  reducing it.
- **A negative exponent is not rejected.** `BN_exp` and `BN_mod_exp` are driven by
  `BN_num_bits`/`BN_is_bit_set`, which read the magnitude, so they compute `a^|p|`.
- **The error queue is part of the answer**, at the authority's own coordinates:
  `BN_R_DIV_BY_ZERO` inside `BN_div`, `BN_R_NO_INVERSE` after `BN_mod_inverse`'s
  internal helper reports through a flag, `BN_R_NOT_A_SQUARE` at `BN_mod_sqrt`'s
  verification step, `BN_R_P_IS_NOT_PRIME` before it does any work when `p` is even and
  not two. All nineteen `crypto/bn` translation units that raise are now in
  `gen_err_raise_sites.py`'s covered set, so those coordinates are generated from the
  authority rather than transcribed.

**The one that matters most.** `BN_signed_lebin2bn`, `BN_signed_bin2bn` and
`BN_signed_native2bn` were declared `-> c_int` in the crate while the atlas records
`BIGNUM *(...)`. Worse, they required a non-null `ret` and so *failed* for the
documented `NULL`-means-allocate form that `BN_bin2bn` and `BN_lebin2bn` already
implemented correctly three functions away. This is not a wrong value; it is a wrong
call convention, and no C caller could have compiled against it without a warning they
were entitled to ignore.

**The gap the atlas already knew about.** The Phase 1 atlas records every export's full
C prototype — return type and parameter list — and **nothing compared the candidate's
Rust declaration against it**. That is why a signature error of this size survived
until a probe happened to call one of the three functions. A `prototype` court that
derives both sides and compares return class and arity would have caught it before any
probe ran, and would catch the class anywhere in the 5,896 `libcrypto` exports. It is
recorded here as the next quality gate for this stratum rather than as a claim that it
exists.

**One residual was a panic, not a wrong value.** `BN_mod_inverse(a, 0)` reached
`limbs::rem`'s division-by-zero assertion; `guard_ffi` caught it and returned `NULL`
with no error raised, because the raise happens after the arithmetic. The fix is at the
root and is also the mathematically right answer: `limbs::mod_inverse` answers `None`
for a zero modulus instead of letting the assertion fire, so a misuse of a public entry
point is a reported failure rather than a panic at the ABI boundary.

**Why this is the argument for the whole method.** The BN code passed the lint gate,
the unit tests, and a reading of `BN_add(3)` before this court ran. Thirty-two of the
45 residuals were one hex digit wide. A stratum cannot be trusted because it looks
finished; it is trusted because something independent disagreed with it first and lost.

## D66 — A phase's ledger counts what its families *cover*, and Phase 5 is now in progress

**Decision.** A stratum's `owned` count is every export its families cover — including
the ones the declaring-header rule hands to a later phase — and `implemented`,
`deferred` and `open` partition it. Phase 3 and Phase 4 read naturally that way because
their families are prefix lists: `BIO_f_md` matches Phase 4's `BIO_` and is then handed
to Phase 7, so it is counted once and deferred once.

Phase 5's families are header-derived (D64) and a hand-off is decided by the *declaring
header*, not by the name, so its first ledger reported `owned = 513` while its
`deferred` list held 580 symbols. That is the same fact stated twice in two different
vocabularies, and `ownership_audit.py` — whose invariant is
`implemented + deferred + open == owned` — correctly refused it:

> phase 5 ledger accounts for 1099 of 519 family exports … so some export it owns is
> neither implemented, handed on, nor recorded as open

**The resolution, and why it is the right one.** A symbol the family's prefixes match is
*covered* by that stratum even when the stratum then hands it on: `d2i_X509` starts with
`d2i_`, which is why it needed a ledger to hand it on in the first place. So `owned`
becomes the covered set (1,099 = 1,093 candidates plus the six Phase 4 hand-offs), and
`open` becomes `owned − implemented − deferred` (414). The arithmetic now closes, and it
closes for the same reason it closes in Phases 3 and 4.

**Phase 5 is `in-progress`, and that is derived.** `phase_state.py` gained a Phase 5
branch with a required-evidence list (the seal, the four `src/bn` modules, the probe,
the two tools) and two derived gates: the court file's verdicts, and
`open_in_this_stratum`. It reports `in-progress` with the blocking count — 414 open
obligations (280 ASN.1, 96 BN, 38 PEM) — and it will report `complete` only when that
count reaches zero and the courts pass. No string in the renderer says either.

**The hand-off edges now reconcile in both directions.** Phase 4 hands six
BIO-to-ASN.1 symbols to Phase 5 (`BIO_f_asn1`, `BIO_new_NDEF`, the four
`BIO_asn1_{get,set}_{prefix,suffix}`), and Phase 5's ledger declares exactly those six
as discharged; `ownership_audit.py` reports `phase 4 -> 5: 6 discharged` and
`0 mismatched hand-off edge(s)`. Before that, the edge was recorded in one ledger only —
which is the failure mode the reconciliation exists to catch, and it caught it.

## D67 — The prototype court, and the two parameters the authority never had

**Decision.** `forensics/tools/prototype_court.py` compares every implemented
`libcrypto` export's Rust declaration against the prototype the Phase 1 atlas recorded
for it — **return class and arity** — and fails on a mismatch. It is registered in
`evidence_determinism.py`'s generator set (so its document is reproduced from committed
inputs on every run) and in CI's static gates, where it needs no authority venue
because the atlas already carries the prototypes.

**Why the class, and not the types.** The atlas gives C types and the source gives Rust
types, and a per-parameter mapping between them would be a transcription that ages
badly. Return class and arity are what a caller's compiler bakes into the call, and
they are exactly what D65's defect got wrong. Both sides are resolved through their own
typedef chains first — `CRYPTO_THREAD_ID` is `unsigned long`, `BIO_callback_fn` is a
function pointer, `BioRecvmmsgFn` is an alias of `BioSendmmsgFn` — so a difference in
*spelling* is never reported as a difference in *shape*.

**A symbol it cannot check is never a pass.** The report separates
`declaration_is_generated` (the crate declares 42 exports from a `macro_rules!`, so
there is no declaration to parse), `implementation_is_c` (the eight variadic and
syscall shims that stable Rust cannot express), `no_prototype_in_atlas` (the
`ABI_ONLY_EXPORTED` class from Phase 1 — `OPENSSL_DIR_read` and `OPENSSL_DIR_end` are
in the DSO and in no installed header), and `unclassified`. `mismatches == 0` is
therefore stated alongside `checked`, never instead of it: today 508 of 560 are
checked, and the remaining 52 are named by class.

**What it found on its first real run.** Two declarations, both in Phase 5's own new
code, and both a *phantom parameter*:

```
BN_CTX_new_ex        authority: BN_CTX *(OSSL_LIB_CTX *)          crate: 2 parameters
BN_CTX_secure_new_ex authority: BN_CTX *(OSSL_LIB_CTX *)          crate: 2 parameters
```

An earlier understanding had given them a `const char *propq` second argument that
OpenSSL's `BN_CTX_new_ex` does not have — that pattern belongs to the `EVP_*`
constructors. On this ABI the extra parameter is harmless at every call site: x86-64
SysV passes it in a register the callee never reads, and the crate's argument was
`_propq`. That is precisely why nothing else found it, and why a prototype comparison
is worth having: it is the only gate that reads the declaration *as a caller's compiler
would*. Both are now one-parameter, and the doc comments say so with the reason.

**The court's own first run was mostly its own bug, and that is recorded too.** The
first version reported seven mismatches and sixteen unclassifiable returns. Six of the
seven were its parser reading the `>` of `->` as closing a `<`, which truncated every
declaration whose parameter list contains a function-pointer type; the sixteen were
one wrong assumption about which parenthesised group in
`int (*(const BIO_METHOD *))(BIO *, char *, int)` is the outer function's parameter
list. A court that reports its own traversal order, or its own reading of C declarator
syntax, as a property of the code is worse than no court — it manufactures work — and
both are now handled explicitly and commented where the trap is.

## D68 — Twenty-three exports `bn.h` declares belong to Phase 9, and saying so is not deferring them

**Decision.** Twenty-three of the 201 `BN_*` exports are recorded as hand-offs to
Phase 9 in `phase5_obligations.py`'s `HANDED_ON` table, each with the dependency as its
reason: the `BN_rand*`/`BN_priv_rand*`/`BN_pseudo_rand*` family and `BN_bntest_rand`
(eleven), `BN_generate_prime{,_ex,_ex2}`, `BN_generate_dsa_nonce`,
`BN_BLINDING_create_param`, the three `BN_X931_*` generators, and
`BN_GF2m_mod_sqrt{,_arr}`/`BN_GF2m_mod_solve_quad{,_arr}`.

**Why a dependency and not a judgement.** D64's rule makes these Phase 5's: `bn.h`
declares them, so the stratum owns them and the ledger counts them as *covered*. What
they need is `RAND_bytes_ex`, which is Phase 9, and no RAND surface exists in this
crate. Each reason names that call, so each row is checkable against
`crypto/bn/bn_rand.c` and its callers rather than being a claim about difficulty —
which is the difference between a hand-off and a thing quietly moved out of view.

**The rule this keeps.** Phase 4 already established that a hand-off is not a gap
(`forensics/phase4-obligations.json`'s `complete` field says so, and D57 records why).
The complement matters just as much: **a hand-off is not parity either.** The Phase 5
seal states the count, the targets and the reason, and the ledger's
`deferred_by_phase` reports `9: 23`, so a reader can see exactly which stratum is
expected to absorb them. Nothing in this change moves a symbol from `open` to
"implemented".

**What it changed in the ledger's arithmetic.** `owned` stays 1,099 (the exports the
families cover) and `open` falls from 414 to 391 — 280 ASN.1, 73 BN, 38 PEM. The 23 are
now `deferred` with `owning_phase: 9`, which satisfies
`implemented + deferred + open == owned` and is reported by `ownership_audit.py` as a
forward hand-off ("no ledger yet"), informational rather than a mismatch.

## D69 — The rest of `BN`, and two claims the source only suggested until the court measured them

**Decision.** The remaining implementable `BN_*` surface is implemented, and the
stratum's court is extended over it rather than left to unit evidence. Six modules:
`mont`, `recp`, `primes`, `nist`, `kron` and `blinding`. The court goes from 475
observations to **577**, still with 0 residuals.

**The probe was the suspect again — the eleventh time.** The extended probe handed
`BN_mod_exp_mont` a `BN_MONT_CTX` that had been re-set to a *different* modulus, and
the authority answered 0 for every one of those calls. A context is bound to one
modulus; passing a mismatched one is out of contract, and reproducing the authority's
refusal to honour it would be reproducing undefined behaviour. With a matching context
every observation agreed on the first run.

**Two things the source implied and the court now measures.**

- **`BN_nist_mod_*` is `BN_nnmod` against a fixed prime.** The first line inside each
  reducer is `field = &ossl_bignum_nist_p_192; /* just to make sure */`: the caller's
  `field` argument is overwritten before it is used, and the small and negative cases
  are dispatched straight to `BN_nnmod` against that same static object. Implementing
  it as `BN_nnmod(r, a, <the generated prime>, ctx)` is therefore exact rather than
  approximate, and it is the version that cannot silently disagree with a carry chain
  somebody mistranscribed. The probe checks both halves — that `field` is ignored, and
  that the result equals the `BN_nnmod` the authority itself calls.
- **`BN_nist_mod_func` selects by value, not identity.** It compares `BN_ucmp` against
  each static prime, so any `BIGNUM` equal to one of the five selects its reducer and
  anything else selects nothing. That is a `BIGNUM` comparison, not a pointer
  comparison, and a caller passing its own copy of P-256 gets the reducer.

**Values are generated, not transcribed.** `forensics/tools/gen_bn_primes.py` compiles
a probe against the admitted prefix, calls each of the thirteen `BN_get0_nist_prime_*`
and `BN_get_rfc*_prime_*` entry points, and emits `src/bn/prime_data.rs` with each
value's SHA-256. A transcription error in an 8192-bit prime is invisible to everything
except a comparison with the authority itself, and `BN_get0_nist_prime_*` feeds
`BN_nist_mod_*`, so a wrong value would silently change every result downstream. The
probe prints the full hex of all thirteen, so the court compares the values
themselves.

**Thirty-one exports are Phase 9's, and the count is stated.** The RAND families, the
prime generators, the five Miller-Rabin primality tests (their witnesses come from
`BN_priv_rand_range`), the X931 generators, `BN_generate_dsa_nonce`, the GF2m
square-root and quadratic-solver pair, and the four blinding entry points that
re-create the blinding factor through `BN_BLINDING_create_param`. Each is a
*dependency*, and the ledger's `deferred_by_phase` reports `9: 31` so a reader can see
which stratum is expected to absorb them. Nothing here moves a symbol from `open` to
implemented.

**What is left in this stratum is GF(2^m).** Fifteen exports — `BN_GF2m_add`,
`arr2poly`, `poly2arr`, `mod`, `mod_arr`, `mod_mul`, `mod_mul_arr`, `mod_sqr`,
`mod_sqr_arr`, `mod_exp`, `mod_exp_arr`, `mod_inv`, `mod_inv_arr`, `mod_div`,
`mod_div_arr` — and nothing else. The stratum's ledger reports `open_in_this_stratum`
333: those fifteen, 280 ASN.1 and 38 PEM, and `phase-state.json` keeps the phase
`in-progress` on exactly that number.

## D70 — `GF(2^m)` closes `BN`, and the reduction loop bound the court caught

**Decision.** The fifteen `BN_GF2m_*` exports are implemented in `src/bn/gf2m.rs`, and
with them **every one of the 201 exports `bn.h` declares is implemented or handed to a
named later stratum**. `RT-BN` goes from 577 observations to **633**, still with 0
residuals, and the stratum's `open_in_this_stratum` falls from 333 to **318** — 280
ASN.1 and 38 PEM, which is the whole of what Phase 5 has left.

**The arithmetic is written as field arithmetic, not as the authority's carry chains.**
`GF(2)[x]/(p)` has exactly one canonical representative per element, so a shift-and-xor
reducer and the authority's unrolled chains must agree on every value; what they do not
agree on is the machine code. `poly_rem` clears the top set bit of the working value one
step at a time, `poly_divrem` is the polynomial long division, `poly_inv` is extended
Euclid over `GF(2)[x]` that reports "the gcd is not one" as *no inverse* rather than as a
wrong answer, and `poly_mul` is carry-less multiply. Recorded as divergence `D-GF2M-2`
with **no timing claim in either direction**.

**Two defects the court found, and this pass they were the implementation's.** Unlike
the eleven earlier passes in this stratum where the probe was the suspect, both of
`GF(2^m)`'s findings were real implementation errors that the probe surfaced:

- **The reduction loop tested the wrong bound.** `poly_rem` compared the value's bit
  length against the modulus's, which skips the reduction of a value exactly one bit
  longer than the field — and `0xa5 * 0x57` in the AES field is exactly that. The
  comparison belongs against the *degree*: a bit at index `>= n` is above the field
  whatever the modulus's own length happens to be. The first draft produced a plausible
  field element that was simply not reduced, which is the failure mode a
  "looks right" reducer keeps.
- **`BN_GF2m_mod_inv` did not raise.** The authority reaches an invalid modulus through
  `BN_GF2m_mod_mul`, so that function's `INVALID_LENGTH` coordinate is what a caller
  sees; the direct extended-Euclid route had no reason to notice. It now validates the
  array first and raises at that same coordinate. The probe found it because it compares
  the error queue after the failure, not only the return value.

**A raise the candidate owed.** `BN_GF2m_mod_inv` reaches an invalid modulus through
`BN_GF2m_mod_mul`, so a caller sees *that* function's `INVALID_LENGTH` coordinate, not
its own. The first draft raised nothing on that path. The probe compares the error queue
after the failure, not only the return value, which is what made the missing raise
visible.

**Both `_arr` and non-`_arr` spellings are implemented and compared to each other.** The
non-`_arr` entry points convert the modulus through `BN_GF2m_poly2arr` and call the
`_arr` one, so the two routes are not independent — but they are *separately observable*,
and the court drives both and checks they agree, checks the field identities
(`a * a^-1 == 1`, `(a / b) * b == a`), and checks the invalid-modulus failure coordinates
of each. `BN_GF2m_poly2arr`'s `OPENSSL_ECC_MAX_FIELD_BITS` bound and the `arr[6]`
smallest fixed-size wrapper are generated from the authority's own constants.

**`BN_GF2m_mod_inv` blinds in the authority and this does not.** `BN_priv_rand_ex` is
Phase 9, and a fixed "blinding" value is not blinding. The returned value is identical —
the inverse in a field is unique — so the court compares values, return classes and error
behaviour and **removes the timing claim**. Recorded as divergence `D-GF2M-1` with
obligation `OBL-GF2M-INV-BLINDING`, owned by Phase 9, which closes by adding the blinding
when RAND exists.

**What is left in this stratum is ASN.1 and PEM.** The 280 `src/asn1/` exports and the 38
`src/pem/` exports, and nothing else. `phase-state.json` keeps Phase 5 `in-progress` on
exactly that number, and the seal's open count is derived from the ledger rather than
typed anywhere.

## D71 — The ASN.1 raise-site set, and the twenty-nine exports no ledger could see

**Decision.** The Phase 5 raise-site cover set is extended from `crypto/bn` to the
`crypto/asn1` substrate, and the files that belong to *later* strata are listed in
the generator with the phase that owns each, so the exclusion is visible rather
than implied. `gen_err_raise_sites.py` gains thirty-one `crypto/asn1` entries
(`a_bitstr.c` … `x_long.c`) and a comment block naming the eleven files left out
and why. The reconstructed site count goes from **391 to 594** authority raise
sites: `crypto/asn1` joins the set that already covers `crypto/stack`,
`crypto/ex_data.c`, `crypto/init.c`, the BIO and CONF subsystems, the object
database, the buffer object and `crypto/o_str.c`, with no unattributed site in
any of them.

**What that exposed, and it is the D49/D51 defect class a third time.** Selecting
`crypto/asn1` as the next stratum's subsystem made the *ledger's* coverage
question unavoidable, and `phase5_obligations.py`'s candidate rule is a prefix
test:

```python
prefix = re.compile(r"^(BN_|ASN1_|d2i_|i2d_|PEM_)")
```

Twenty-nine exports that the declaring-header rule this tool documents as its
actual rule hands to Phase 5 match **none** of those prefixes, so they are
invisible to the Phase 5 ledger, to every other ledger, and to
`ownership_audit.py`'s invariant (which only requires that an *implemented* export
be claimed by someone). They are:

```text
BIGNUM_it  CBIGNUM_it                       crypto/asn1/x_bignum.c
INT32_it INT64_it UINT32_it UINT64_it       crypto/asn1/x_int64.c
ZINT32_it ZINT64_it ZUINT32_it ZUINT64_it   crypto/asn1/x_int64.c
LONG_it ZLONG_it                            crypto/asn1/x_long.c
DIRECTORYSTRING_new/_free/_it               crypto/asn1/tasn_typ.c
DISPLAYTEXT_new/_free/_it                   crypto/asn1/tasn_typ.c
UTF8_getc UTF8_putc                         crypto/asn1/a_utf8.c
a2d_ASN1_OBJECT  i2t_ASN1_OBJECT            crypto/asn1/a_object.c
i2a_ASN1_OBJECT i2a_ASN1_STRING             crypto/asn1/a_object.c, f_string.c
i2a_ASN1_INTEGER i2a_ASN1_ENUMERATED        crypto/asn1/a_int.c
a2i_ASN1_STRING  a2i_ASN1_INTEGER  a2i_ASN1_ENUMERATED
                                            crypto/asn1/f_string.c, f_int.c
```

`i2a_ASN1_OBJECT` is not a convenience: `ASN1_parse` calls it, so the stratum
cannot be completed without it however the ledger counts it. The correction was
written and validated — each entry checked to be exported by this build profile
*and* declared in a header `HEADER_PHASE` maps to Phase 5, with the sixteen
symbols the header rule would over-claim (`SMIME_*` → 12, `b2i_*`/`i2b_*` → 10)
recorded as explicit exclusions — and it moves the ledger from 1,093 candidates
and 318 open to 1,122 and 345.

**Why it is not landed in this commit.** The regression guard's invariant is that
`open_obligations` never increases, and an honest scope correction *does* increase
it: `owned` rises by the same twenty-nine, and `implemented` does not change at
all. The guard has no way to express that distinction, so landing the correction
would require either weakening the invariant (unacceptable) or teaching the guard
to accept an increase that is exactly accounted for by growth in `owned` for the
same ledger, with the newly-owned symbols and their reason recorded. That
mechanism is checkable and is the right fix; it is not written yet, and a
correction that cannot be landed green is not landed.

**No product code ships for ASN.1 in this change, deliberately.** The modules
begun for the substrate (`layout`, `utl`, `string`, `der`, `integer`, `obj`) were
not wired into `lib.rs` and have been withdrawn rather than committed unwired:
source that no build compiles and no CI checks is invisible to every gate, which
is the same failure this entry is about. The stratum still reports 280 open ASN.1
obligations, and the next change to touch it starts with the guard mechanism and
the ledger correction above, then the implementation.

**What is unchanged and re-verified.** The full chain was re-run: `cargo fmt`,
`cargo build --release`, `cargo test --lib` (146 passed), `cargo clippy
--all-targets -- -D warnings`, all 34 courts (7,481 observations), the Phase 5 and
Phase 3/4 ledgers, `ownership_audit.py`, `prototype_court.py`, `phase_state.py`,
`render_status.py`, `evidence_determinism.py`, `check_evidence_portability.py`,
`gen_frf_courts.py --check` and `regression_guard.py --baseline-ref HEAD
--require-current`. Phase 5 remains `in-progress` on 318 open obligations, and no
claim moves.

**A second, smaller defect found on the way, and fixed rather than worked
around.** `src/runtime/err_sites.rs` is generated, but the generator emitted two
fields per line and `rustfmt` wants one, so the committed file was only
`cargo fmt --all -- --check`-clean because whoever generated it last had run
`cargo fmt` afterwards. Nothing enforced that step: `err_sites.rs` is **not** in
`evidence_determinism.py`'s compared set (it is a `.rs` product, not a JSON
artefact), so regenerating it drifted from the committed file silently and only
`cargo fmt` in CI would have caught it. The generator now emits the formatted
shape, which removes the manual step rather than documenting it. The same class of
gap applies to the other `.rs` generator, `gen_bn_primes.py`, and is recorded here
rather than assumed away.

## D72 — One ownership atlas, because discovery was still prefix-derived

**Decision.** Scope discovery stops being per-phase and becomes global. A new
generated artifact, `forensics/atlas/symbol-ownership.json`, has **every export of
`libcrypto.so.3` and `libssl.so.3`** as its universe — 6,499 symbols — and assigns
each to exactly one stratum by one rule, stated once in
`forensics/tools/ownership_rules.py` and applied by
`forensics/tools/symbol_ownership.py`. Phase 5's ledger becomes a projection of it.

**The defect this closes.** Phase 5 had already documented the right rule — *a
symbol belongs to the stratum that owns the header declaring it* — and then chosen
its candidates with a prefix test:

```python
prefix = re.compile(r"^(BN_|ASN1_|d2i_|i2d_|PEM_)")
```

So discovery and assignment used different rules, which is the D49/D51 defect
class a third time. The concrete misses are the ones a reviewer found by reading:
`a2d_ASN1_OBJECT` and `a2i_ASN1_INTEGER` are declared in `asn1.h` and match no
prefix, so they were invisible to the Phase 5 ledger, to every other ledger, and to
`ownership_audit.py`, whose invariant was only *every **implemented** export has an
owner*. `i2a_ASN1_OBJECT`, `i2a_ASN1_STRING`, `i2a_ASN1_INTEGER`,
`i2a_ASN1_ENUMERATED`, `a2i_ASN1_STRING`, `a2i_ASN1_ENUMERATED`, `i2t_ASN1_OBJECT`,
`UTF8_getc`, `UTF8_putc`, `BIGNUM_it`, `CBIGNUM_it`, the eight `{Z,}{U,}INT{32,64}_it`
items, `LONG_it`, `ZLONG_it`, `DIRECTORYSTRING_{new,free,it}` and
`DISPLAYTEXT_{new,free,it}` were the rest: **29 exports**, all of them ASN.1's.
`i2a_ASN1_OBJECT` is not a convenience — `ASN1_parse` calls it.

The fix is not more prefixes. The atlas asserts what the prefix rule could only
approximate, and it asserts it over the whole authority:

```text
rows == 6,499      unknown == 0      multiply_owned == 0      unassigned_headers == 0
```

**Three rules, tried in order.** `abi-only` for the 26 exports the DSO exports and
no installed header declares (15 `DSO_*`, `OPENSSL_DIR_{read,end}`,
`err_free_strings_int`, the three `conf_ssl_*`, `asn1_d2i_read_bio`, and the four
`PEM_*_CMS`), each named in `ABI_ONLY_OWNER` with the stratum that owns it;
`declaring-header` for everything a header declares; and `pem-typed-object` for
`pem.h`'s typed names, where the type in the name is resolved through the Phase 1
atlas's type→header evidence and *that* header decides. An export the rules cannot
place stops the atlas run; it never defaults.

The result: `declaring-header` 6,376, `pem-typed-object` 97, `abi-only` 26, and
per-phase counts `{2: 15, 3: 304, 4: 256, 5: 561, 6: 112, 7: 924, 8: 759, 9: 25,
10: 272, 11: 1455, 12: 1024, 13: 189, 14: 600, 15: 3}`.

**Phase 5's numbers move, and that is the point.** Owned 1,099 → **565**; open
318 → **362**; implemented **unchanged at 170**. `owned` shrinks because the
exports its prefixes used to match but whose declaring header belongs to another
stratum are now owned by *that* stratum — the deferred rows that used to be counted
here are gone, because a symbol deferred out of a stratum it never belonged to was
never this stratum's. `open` grows because 29 exports that were invisible are now
visible, and because the ASN.1 surface it *does* own is larger than the prefix test
admitted. Nothing was undone and no implementation was lost, which is why
`implemented` is the field that must not move, and does not.

**A scope correction has to be recordable, or it is indistinguishable from a
regression.** The regression guard's invariant is that `open_obligations` never
increases, and an honest correction does increase it. Weakening the invariant was
not an option, so `forensics/ownership-transitions.json` records the approved move
with its before/after numbers, and the guard accepts an increase **only** when a
row matches the observed change exactly on *every* field — phase, `open_before`,
`open_after`, `owned_after`. A larger increase, a different owned count, or an
unrecorded phase all fail. The transition names the decision that recorded it and
the artifact that is the authority for the new universe, and removing the row makes
the same change fail the guard again.

**The guard's evidence inventory is now discovered, not listed.** It held
`phase3-obligations`, `phase4-obligations` and three `COURTS.json` paths by hand,
so adding a stratum meant remembering to update the guard — the same failure mode
this entry is about. It now globs `forensics/phase*-obligations.json` and
`artifacts/phase*/COURTS.json`, and a new `inventory_problems` check cross-reads
`phase-state.json` in both directions: a ledger or court directory for a phase the
state does not know, and a phase that is not `not-started` with no ledger, are both
failures. This was already load-bearing when it landed: **the guard had been
ignoring `RT-BN` entirely**, so the court count went 34 → 35 and the observation
count 7,481 → 8,114 without a single new observation being taken.

**`ownership_audit.py` consumes the atlas.** Its invariant is now the stronger one:
*every authority export has exactly one declared owner*, checked against the
atlas's own assertions, instead of *every implemented export is claimed by a phase
family*. The prefix families remain as a **cross-check** for the strata that still
declare them, and a new `ledger_agreement` plane reports, per phase, the symbols
the atlas gives it that its ledger does not list and vice versa — a disagreement is
reported, never resolved silently.

**Two consequences worth naming rather than discovering later.** First, the rule is
mechanical, so where it disagrees with intent the *table* must be changed: for
example `PKCS8_PRIV_KEY_INFO` is declared in `x509.h`, so
`PEM_read_bio_PKCS8_PRIV_KEY_INFO` resolves to Phase 11 rather than to the PKCS and
key-format stratum a reader might expect. That is a decision in
`HEADER_PHASE`/`ABI_ONLY_OWNER` and is visible in the atlas's `records`, not a
hidden consequence of a regex. Second, `HEADER_PHASE` is asserted to contain no
duplicate key by scanning the source text, because a dict literal keeps the last
value silently and a silently-overridden decision is the class of defect this
entry removes.

**Not yet done, and named.** `ABI-PROTOTYPE` — a build-time C-signature check over
every implemented export, generated from the Clang AST, so an arity or constness
error fails at compile time rather than when a probe happens to call the function.
The ERR getters' wrong arities are the precedent. It is the next structural
change, before the ASN.1 surface starts moving.

**Re-verified.** `symbol_ownership.py`, `implemented_surface.py`,
`ownership_audit.py`, `prototype_court.py`, the three ledgers, `phase_state.py`,
`render_status.py`, `evidence_determinism.py` (now **10** artefacts, the atlas
included), `check_evidence_portability.py`, `gen_frf_courts.py --check`,
`regression_guard.py --update` and `regression_guard.py --baseline-ref HEAD
--require-current` — all green. Phase 5 remains `in-progress`, and no claim moves.

## D73 — The ASN.1 primitive section: its boundary, and what reading it established

**Decision, and the honest state.** The Phase 5 surface is 362 open obligations:
314 ASN.1 and 48 PEM. It decomposes into three sections that can each be finished
and courted on their own, and this entry records the first one's *boundary* and the
authority facts that reading it established. The implementation of that section was
begun and is **not landed**: see "why not landed" below, which is the same reason
D71 withdrew the raise-site slice and D72 withdrew the substrate modules.

### The boundary of the first section

The 314 ASN.1 obligations split cleanly by *what they need*, not by prefix:

| | count | needs |
|---|---|---|
| the primitive types, the DER header codec and the text conversions | **199** | nothing but BIO and CONF, both Phase 4's |
| the template codec: `ASN1_item_*`, the 24 `d2i_` and 24 `i2d_` wrappers, the `_it` accessors | **115** | the template interpreter |

The second is the harder and structurally larger piece, and the first does not
depend on it *except* in four places, which is what makes the split real rather
than convenient. Those four are `ASN1_dup` (i2d then d2i), `ASN1_TYPE_pack_sequence`
and `ASN1_TYPE_unpack_sequence` (both `ASN1_item_i2d`), and `BIO_new_NDEF`
(`ASN1_item_ndef_i2d`). They stay open with the codec rather than being implemented
twice.

So the first section is **199 exports minus those four**, and it is completable and
court-able without the interpreter.

### What reading the authority established

These are the facts that cost the reading, recorded so the next attempt does not pay
for them again. Each is checkable against `crypto/asn1` and each is a place an
implementation written from the header would be wrong.

**The `_it` accessors are functions.** `asn1t.h` defines
`DECLARE_ASN1_ITEM_attr(attr, name)` as `attr const ASN1_ITEM *name##_it(void);`,
and `ASN1_ITEM_rptr(ref)` as `(ref##_it())`. So `ASN1_ANY_it` is a **function with
no arguments returning a pointer to a function-local static** — which is why the
authority exports it as `FUNC` with `size == 8` and not as an `OBJECT`. Two calls
compare equal, and the fields of the returned `ASN1_ITEM` are readable through it.
That makes the descriptors court-able: walk `itype`, `utype`, `tcount`, `size`,
`sname`, and each template's `flags`/`tag`/`offset`/`field_name`, recursing through
`ASN1_ITEM_ptr(t->item)`. An exported *data* symbol here would be an `ABI-SYMBOL`
failure, and a court that compared pointers across implementations would be
comparing nothing.

**`asn1_primitive_new`'s three sentinels** (`tasn_new.c:259`):

```text
V_ASN1_NULL     *pval = (ASN1_VALUE *)1;          /* not a heap pointer */
V_ASN1_OBJECT   *pval = OBJ_nid2obj(NID_undef);   /* the *static* object  */
V_ASN1_BOOLEAN  *(ASN1_BOOLEAN *)pval = it->size; /* 1 for TBOOLEAN, 0 for FBOOLEAN */
```

and the matching free path (`tasn_fre.c:150`) does nothing for `V_ASN1_NULL` and
calls `ASN1_OBJECT_free` for `V_ASN1_OBJECT`, which is a no-op for a static entry
because it carries no `ASN1_OBJECT_FLAG_DYNAMIC` bit. `ASN1_TYPE`'s union is eight
bytes of pointer with `ASN1_BOOLEAN` in the *first four*, so a `boolean` must be
written and read through the same memory a pointer occupies.

**`ASN1_INTEGER` stores a magnitude, and the DER encoding is not it.** `data` is
big-endian magnitude and `type & V_ASN1_NEG` is the sign. `i2c_ibuf` pads with
`00` for a positive value whose top bit is set, with `FF` for a negative one whose
magnitude is `> 0x80…`, and for a magnitude whose first octet is exactly `0x80`
pads **only if some later octet is non-zero** — so `-0x8000…00` gains no `FF` while
`-0x8000…01` does. `c2i_ibuf` is the inverse and rejects content whose first two
octets have matching sign bits as `ILLEGAL_PADDING`, with a distinct
`ILLEGAL_ZERO_CONTENT` for an empty content. `ossl_i2c_ASN1_INTEGER` returns 0 for a
null argument.

Two quirks worth courting directly: `bn_to_asn1_string` sets
`ret->type |= V_ASN1_NEG_INTEGER` *regardless of `atype`*, which is not a bug —
`V_ASN1_ENUMERATED | V_ASN1_NEG_INTEGER == V_ASN1_NEG_ENUMERATED` — and
`ASN1_ENUMERATED_get` answers `0xffffffffL` rather than `-1` when the content is
longer than a `long`, while `ASN1_INTEGER_get` answers `-1` for every failure.

**A bit string's unused-bit count lives in the low three flag bits.** `flags &
ASN1_STRING_FLAG_BITS_LEFT` says the count in `flags & 0x07` is authoritative;
clearing the flag says "recompute from the content", which is exactly what
`ASN1_BIT_STRING_set_bit` does first (`a->flags &= ~(ASN1_STRING_FLAG_BITS_LEFT |
0x07)`). `ossl_i2c_ASN1_BIT_STRING` recomputes by scanning back over trailing zero
octets and then `p[-1] &= (0xff << bits)` — the masking is what makes the encoding
canonical and is the difference a value-comparing court would see.
`ossl_c2i_ASN1_BIT_STRING` rejects a leading count above 7 and masks the last octet
the same way. `ASN1_BIT_STRING_set_asc` returns the **inverse** of what a caller
expects: `num_asc`'s `-1` becomes `1`, and a found bit answers
`set_bit`'s result.

**An OID decode answers the static table entry when it can.** `ossl_c2i_ASN1_OBJECT`
looks the content up through `OBJ_obj2nid` and, on a hit, returns
`OBJ_nid2obj(nid)` — the shared registered object — without allocating. Only an
unregistered OID becomes a dynamic object, and then the subidentifier check runs:
a `0x80` octet may not lead unless the previous octet also continued
(X.690 8.19.2). The last octet's top bit must be clear. `i2a_ASN1_OBJECT` writes the
four bytes `"NULL"` for an object with null `data` — **4, not 0** — and for an OID
whose text is empty writes `"<INVALID>"` followed by a `BIO_dump` of the content.

**`ASN1_STRING_set` allocates `length + 1` and writes a NUL at `data[length]`**,
one byte past the content the caller asked for; it grows only when
`(size_t)str->length <= len` or `data` is null, and on a failed realloc it restores
the original pointer so the string stays valid. `ASN1_STRING_cmp` compares length,
then content, then type. `ASN1_STRING_copy` preserves the *destination's* embed bit
and copies every other flag.

**`B_ASN1_PRINTABLE` contains bits that are not string types.**
`B_ASN1_BIT_STRING`, `B_ASN1_SEQUENCE` and `B_ASN1_UNKNOWN` are in the authority's
definition, which is what makes `ASN1_STRING_set_by_NID` accept a bit string or a
sequence for a NID whose mask is that. `B_ASN1_DIRECTORYSTRING` and
`B_ASN1_DISPLAYTEXT` both gained `B_ASN1_UTF8STRING` relative to the older
definitions a reader may remember.

### The hand-offs this section forces

Named with their phase and reason, because a section cannot be called complete
while these are merely unmentioned:

* `SMIME_crlf_copy`, `SMIME_read_ASN1`, `SMIME_read_ASN1_ex`, `SMIME_text`,
  `SMIME_write_ASN1`, `SMIME_write_ASN1_ex` → **Phase 12**. `asn1.h` declares them,
  so the atlas gives them to Phase 5; `asm_mime.c` implements them over CMS and
  PKCS#7, which is Phase 12's.
* `ASN1_item_sign_ex`, `ASN1_item_verify_ex` → **Phase 7**. They digest and sign
  through `EVP_PKEY`/`EVP_MD`, and the algorithm identifier is `X509_ALGOR`
  (Phase 11).
* `b2i_PVK_bio`, `b2i_PVK_bio_ex`, `b2i_PrivateKey`, `b2i_PrivateKey_bio`,
  `b2i_PublicKey`, `b2i_PublicKey_bio`, `i2b_PVK_bio`, `i2b_PVK_bio_ex`,
  `i2b_PrivateKey_bio`, `i2b_PublicKey_bio`, the typed `PEM_read_bio_PrivateKey`
  family and `d2i_PKCS8PrivateKey`/`i2d_PKCS8PrivateKey` → **Phase 7 and Phase 10**.
  Their names resolve to `pem.h`'s generic machinery because their type word is
  weak, but they read and write `EVP_PKEY`s and the PKCS#8 container.

### Why it is not landed

The modules for the first section were written — the layouts and their constants,
`ASN1_STRING` and its fifteen types, the integer family, the bit string, the object,
the two opaque context objects — and they are withdrawn rather than committed,
because they were not declared in `lib.rs` and the section is not courted. Source
that no build compiles and no CI checks is invisible to every gate, which is the
failure D71 and D72 are about; committing it would make this stratum's evidence
worse while looking like progress. Phase 5 still reports 362 open obligations and
314 of them are ASN.1.

The next change to touch this section starts from the boundary and the facts above,
wires the modules in behind `pub mod asn1;` in the same commit that adds the court,
and closes the section as `open in src/asn1/ == 199 - 4 - 6 - 2` with the hand-offs
recorded. `ABI-PROTOTYPE` (D72) is still the change that should land before it.

## D74 — `ABI-PROTOTYPE`: the prototype court now compares *types*, not just shape

D65 landed `prototype_court.py` to catch a wrong call convention — `BN_signed_lebin2bn`
declared `-> c_int` where the authority declares `BIGNUM *`. It compared the return
*class* and the *arity*, and its own docstring said so: "It does not compare parameter
types." D72 recorded `ABI-PROTOTYPE` as still outstanding.

That gap was real, and it sat exactly where Phase 5 is about to work. A `const` dropped,
an extra pointer level, an `int` widened to `long`, or a callback's return type changed
is invisible to a shape check and invisible to most probes — a probe has to call that
one function with an argument that exposes the difference. The ASN.1 surface is 314
functions of pointer-to-pointer mutation, `const`, `ASN1_ITEM *` and callback typedefs.
The court had to be able to see it before that surface moved, so this landed first.

### What the court now compares

Both sides are reduced to one grammar, and compared as strings:

```
void | int:<bytes>:<s|u> | float:<bytes>
ptr(<inner>) | const(<inner>) | fn(<ret>; <args>) | fptr(<ret>; <args>) | opaque
```

The authority's side is built from the atlas's own `params` records — the C is never
re-parsed, only classified. The crate's side is read from the declaration in `src/`.

Four decisions in that grammar are worth stating, because each is a line drawn on
purpose:

* **A struct pointee's name is discarded.** `*mut Asn1String` and `*mut c_void` are the
  same type to the ABI and the same to a caller passing its own pointer, so keeping the
  name would report a spelling difference as a defect. What is *kept* is the pointer
  **depth**, because `BIO **` is not `BIO *`, and the **integer width**, because
  `int *` is not `long *`. Those are the differences a caller can observe.
* **A top-level `const` on a value is dropped.** `const BN_ULONG w` and `BN_ULONG w`
  declare the same function in C. `const` survives only on a pointee, where a caller
  can observe it.
* **`fn(...)` is a function *type*; `fptr(...)` is a function pointer.** The atlas
  records `BIO_info_cb` as `int (BIO *, int, int)` — the authority's own header says
  `typedef int BIO_info_cb(BIO *, int, int);` — so `BIO_info_cb *` is a pointer to a
  function type, which in C is the function pointer itself. Collapsing
  `ptr(fn(...)) -> fptr(...)` exactly once is what makes `CRYPTO_malloc_fn **`
  distinguishable from `CRYPTO_malloc_fn *`; collapsing blindly lost a level and
  reported the authority's own `CRYPTO_get_mem_functions` as a mismatch.
* **A type the table cannot canonicalise is a failure, never a pass.** `type_unmapped`
  is a third heading beside `pass` and `mismatch`, and it fails the court.

### Two defects in the court itself, found by running it

The first run reported 497 of 565 symbols `unmapped`, then 340 `mismatch`. Both were
the court's fault, and both are recorded here because the pattern is the one this
project keeps meeting: **the instrument is the suspect before the code is.**

* The canonicaliser tried `uint64_t` against the platform table, but an earlier edit of
  mine had deleted the `intN_t`/`uintN_t` entries from `C_SYSTEM_TYPEDEFS`, so every
  fixed-width type became `opaque`. An edit that silently shrinks a declaration table
  is invisible until something compares against it.
* `const` was dropped at the hand-off from a typedef name to its underlying type:
  `const BIO_ADDRINFO` reaches `struct bio_addrinfo_st` only through the atlas's
  typedef record, and the qualifier was lost in between. That produced 340 false
  mismatches, every one of them the crate being *more* faithful than the court.

A third defect was in how aliases were resolved. `type FreeFn` is declared twice in
this crate — `src/runtime/stack.rs` has the one-argument `OPENSSL_sk_freefunc`,
`src/runtime/mem.rs` has the three-argument `CRYPTO_free_fn` — and a single global
table returned whichever file sorted first. That made `OPENSSL_sk_pop_free` look like
it took a three-argument destructor when the file it lives in says otherwise. Each
declaration is now resolved against its own file's aliases first, with a name defined
in exactly one file usable as a fallback; a name defined in more than one file and
absent from the declaring file is left unresolved so it is *reported*, not guessed.

### What the type plane found in the crate

Twelve declarations disagreed with the authority. All twelve are fixed here:

* `BIO_callback_ctrl`, `BIO_meth_get_callback_ctrl`, `BIO_meth_set_callback_ctrl`
  declared `BIO_info_cb *` as a pointer to a function *pointer*. It is one level, not
  two: the authority's `BIO_info_cb` is a function type. `bss_conn.c`'s
  `BIO_CONNECT.info_callback` was stored that way too and called through
  `transmute_copy`, reinterpreting a pointer-sized code address as a function pointer
  because dereferencing it would have read the function's own bytes. Both the extra
  level and both transmutes are gone; the callback is an `Option<BioInfoCb>` and is
  called directly.
* `BN_GENCB_set_old` declared its deprecated callback `int (*)(int, int, void *)`. The
  authority declares `void (*cb)(int, int, void *)`, and `BN_GENCB_call` answers `1`
  after invoking it rather than the callback's result.
* `BN_options` returned `const char *`; the authority returns `char *`.
* `BN_are_coprime` took `const BIGNUM *a`; the authority takes `BIGNUM *a`.
* `OPENSSL_sk_delete`, `sk_delete_ptr`, `sk_pop`, `sk_set`, `sk_shift` and `sk_value`
  returned `const void *`. The authority declares `void *` and casts at the boundary —
  `return (void *)st->data[i];` — because the stack stores `const void **data`. The
  internal representation stays `const void *`; the exported boundary now casts, in one
  place, in a function named `expose`.

Ten of the twelve are declaration-only, and every Phase 3 and Phase 4 court still
passes with the same residual set. The other two are **not** declaration-only.
`BN_GENCB_set_old`'s callback returns `void` and `BN_GENCB_call` answers `1` after
invoking it, so a candidate that returned the callback's result was answering a
function that has no result.

That correction could not be left to the prototype court, because no court called
`BN_GENCB_call` at all: the fix would have been a behaviour change with nothing
watching it. So `RT-BN` gained a `BN_GENCB` section in the same change — registration
through both functions, the answer from `BN_GENCB_call`, the arguments the callback is
handed, `BN_GENCB_get_arg` before and after, whether a later `set` replaces the other
kind, and `BN_GENCB_call(NULL, …)`. It is `17` new observations, and the first run
found a defect the signature change had not: **the authority answers `0`, not `1`, for
`BN_GENCB_call` on a freshly allocated object.**

That is the authority's `ver` word, and it is not inferable from the two function
pointers. `struct bn_gencb_st` carries `unsigned int ver`, and `BN_GENCB_call`
branches on it: `0` on a fresh object, `1` returned after an old-style callback (or
when `ver == 1` holds no callback), and the new-style callback's result when
`ver == 2`. A model that asks only "is a callback installed" cannot separate a fresh
object from an old-style object whose callback is NULL. `BnGencb` now carries `ver`
and branches on it. Two cases remain unreproducible and are recorded in
`docs/SECURITY_DIVERGENCE_POLICY.md` as `D-GENCB-1` and `D-GENCB-2`: a `ver == 2`
object whose callback is NULL, and `BN_GENCB_get_arg(NULL)`, both of which the
authority reaches by calling through or dereferencing a null pointer.

That is the point of the court — these are wrong *call conventions* and wrong
*declarations*, the class D65 exists for, and only a signature comparison finds them.
They are also, twice over, defects whose *behaviour* only a probe finds, which is why
fixing a signature is not by itself evidence that the behaviour is right.

### State

`565` of `625` implemented exports are checkable and all `565` agree on the canonical
signature; `0` mismatches, `0` unmapped. The remaining `60` are `2` with no prototype
in the atlas, `50` declared from a `macro_rules!` and `8` defined in C — reported
under their own headings, never counted as passes. `RT-BN` is `650` observations
across `35` courts and `8,131` in total. Phase 5 is still `in-progress` with `362`
open obligations, `314` of them ASN.1, and the next change to touch the stratum wires
`src/asn1/` in behind `pub mod asn1;` in the same commit that adds its court.

## D75 — Phase 5's remaining work is a sequence of courted sections, written down

D73 established the boundary of the ASN.1 primitive section and withdrew the modules
rather than commit uncounted source. That left the rest of the stratum — 314 ASN.1 and
48 PEM exports — planned in review messages rather than in the repository.

`docs/PHASE-5-SUBPHASES.md` now records it: ten subphases, each with the exports it owns,
what it depends on, the court that will observe it, and the criterion that closes it. The
rule that makes the list worth having is the one D73 paid for: **a subphase closes in the
commit that adds its court**, so `pub mod asn1;` and `courts/phase5/rt_asn1_probe.c`
land together or not at all.

Two orderings in it are deliberate and are the ones a reader would most likely get
wrong:

* **5.4 (the item machinery) before 5.3 (the `d2i_*`/`i2d_*` wrappers).** The wrappers
  are the familiar names and look like the natural starting point, but each is
  `ASN1_item_d2i` over the matching `_it`, and `asn1_d2i_ex_primitive` — whose branches
  are observable — is what actually runs. Implementing the wrappers directly would mean
  writing that path by hand, twice, and drifting. 5.3 depends on 5.4.
* **Not AES, not SHA, not TLS** — the same reason phase 5 does not start with them: the
  algorithms have nowhere faithful to live until the object and template machinery is
  right.

The document also carries the authority facts each subphase must honour, in one place,
with the file each was read from: the integer family's magnitude/`V_ASN1_NEG` split and
its `i2c_ibuf`/`c2i_ibuf` padding rules, the two integer quirks (`ASN1_ENUMERATED_get`'s
`0xffffffffL`, `bn_to_asn1_string`'s deliberate `V_ASN1_NEG_INTEGER`), the bit string's
`BITS_LEFT` flag and its `0xff << bits` masking on both sides, the object decoder's
static-table answer and its X.690 8.19.2 check, and the primitive decode path's
constructed/indefinite/`TYPE_NOT_PRIMITIVE` branches. Those were being re-read from the
authority source each time a section started; they are contract, and they belong in the
repository.

No claim in the document is a parity claim. It is a plan, and the ledger still reports
Phase 5 `in-progress` with 362 open obligations.

## D76 — The ASN.1 leaf surface lands, and the court corrects three things on the way in

D73 withdrew the ASN.1 modules rather than commit source no build compiled. This
lands them, and the rule D73 set is what made the landing honest: `pub mod asn1;` and
`courts/phase5/rt_asn1_probe.c` arrive in the same change, and the second of them
immediately corrected the first.

**What is implemented.** 109 exports: the DER header codec (`ASN1_get_object`,
`ASN1_put_object`, `ASN1_object_size`, `ASN1_tag2bit`, `ASN1_tag2str`, `ASN1_put_eoc`,
`ASN1_check_infinite_end` and its const form, `ASN1_parse`, `ASN1_parse_dump`),
`ASN1_STRING` and its fifteen types, the `ASN1_INTEGER`/`ASN1_ENUMERATED` family with
the two's-complement content codec, `ASN1_OBJECT` with its decoder and encoder, the
four `BIGNUM` bridges, `ASN1_PCTX` and `ASN1_SCTX`, the text writers
(`i2t_`/`i2a_ASN1_OBJECT`, `i2a_ASN1_STRING` and the two integer writers), and three
`d2i` readers.

`d2i.rs` is worth a note on its own. Each of those readers is, in the authority, one
call to `ASN1_item_d2i` over the matching item, and the template machinery is 5.4. So
`asn1_d2i_ex_primitive` is reproduced directly, restricted to what an
`ASN1_ITYPE_PRIMITIVE` item with a null `templates` and no `funcs` can reach — which
is a restriction that can be *stated*, not guessed: no selector, no optional field, no
`ANY`, no `MSTRING`, no `prim_c2i`. Everything a malformed encoding can reach is
still there, including the constructed-form collection into a `CRYPTO_*` buffer that
`ASN1_STRING_set0` then takes ownership of.

**The court found three defects.**

1. `get_length` tested its bound with a *pre*-decrement where the authority writes
   `if (max-- < 1)`. The authority's post-decrement tests the old value, so a length
   that is the last readable byte is legal. Every short-form object with `omax == 2`
   was rejected: `30 00`, `04 00` and the end-of-contents marker all failed, and the
   `ILLEGAL_ZERO_CONTENT` raise that follows from `02 00` was wrong as a consequence.
   A single character in the wrong place, invisible to every test that used a buffer
   longer than the object.

2. Two raise reasons had been **typed rather than read**.
   `ASN1_R_BAD_OBJECT_HEADER` is `102` and `ASN1_R_EXPECTING_AN_OBJECT` is `116`;
   `101` and `127` were used. The generated `err_sites` table could not have supplied
   them, because the site is *dynamic* — the authority accumulates the reason in a
   local before raising — so the table carries no reason for it. The court checks them
   behaviourally instead: `o.not_oid.err` and `o.bad_last.err` compare the packed
   reason an actual call produces. That is weaker than deriving them, and deriving
   them from `asn1err.h` is named in the source as the next change to that file.

3. `asn1_parse2` returned `1` for a *failed* parse. The authority reaches `ret = 1`
   only when its `while` loop ends by itself; every failure leaves through `goto end`
   carrying whatever `ret` already held, which is `0` unless an end-of-contents was
   seen. This crate set `ret = 1` at the end of each *iteration*, so a failure after
   one successful object answered `1`. The recursive caller in the constructed branch
   then believed the child had parsed its bytes, advanced past them, and parsed the
   same input again — which is why `ASN1_parse_dump` printed its diagnostic twice for
   a `SEQUENCE` whose last child overran the declared length. The loop is now a
   labelled loop whose normal exit carries `1`, whose end-of-contents exit carries
   `2`, and whose 22 failure exits carry `0`.

That third one had a **doc comment asserting the opposite** — "a failure later answers
1 — which is what the authority does" — and the comment is why the bug existed. It was
taken from a summary of the authority rather than from the authority, and the summary
was wrong. The lesson is the one this project keeps re-learning in both directions:
the probe is the suspect before the implementation, and a note about the authority is
the suspect before the authority.

**A fourth finding was about the court, not the crate.** With stdout redirected, a
fault loses the tail of the buffer, so the last visible line is a lie and a crashing
candidate produces a *nondeterministic* transcript. That is how the probe's own
use-after-free — freeing a `BIO` and then writing to it — presented as two "missing"
observations rather than as a crash. `RT-ASN1` now calls
`setvbuf(stdout, NULL, _IONBF, 0)`, and every court that can fault should.

**A fifth was in the prototype court.** Its *class* plane did not narrow a qualified
path to a scalar, so `core::ffi::c_ulong` fell through to `unclassified` and
`ASN1_tag2bit` was reported as unclassifiable. The type plane had already been
narrowed for exactly that; now both are.

**Where the stratum stands.** `implemented[libcrypto]` is `625 -> 734` and
`open_obligations[phase5]` is `362 -> 226`, the two moving together as they must. The
`226` is `199` ASN.1 and `27` PEM: D73's hand-offs are now in `HANDED_ON` rather than
only in prose, which moved `SMIME_*` to Phase 12, the PKCS#8 and `b2i_*`/`i2b_*`
readers to Phase 10 and the `EVP_PKEY`-shaped `PEM_read_bio_PrivateKey` family to
Phase 7. `RT-ASN1` is 644 observations with no residuals; 36 courts and 8,775
observations in total; phases 0–4 are complete and phase 5 is in progress.

**What is not done.** The remaining 226. The template machinery (`ASN1_item_*`, the
42 `*_it` accessors), the rest of the codec wrappers, `ASN1_BIT_STRING`, `ASN1_NULL`,
the time types, the string masks and printing, `ASN1_TYPE`, the NDEF BIO bridge and
all 48 PEM exports are unimplemented. No claim here covers them.


## D77 — The shared DER codec lands in both halves, and the court finds an ownership contract

D76 recorded what the ASN.1 leaf surface claimed and what the 226 did not. This lands
the next section: the shared decoder and encoder, the free path, the item descriptors the
primitive path names, the wrapper family of `tasn_typ.c`, `ASN1_BIT_STRING`, `ASN1_NULL`
and `d2i_ASN1_UINTEGER`. `open_obligations[phase5]` is `226 -> 155` and
`implemented[libcrypto]` is `734 -> 805`, moving together as they must. `RT-ASN1` is
`644 -> 1306` observations with no residuals; 36 courts and 9,437 observations in total.

**The wrappers were landed before the template machinery, and the plan was wrong, not the
work.** D73 and `docs/PHASE-5-SUBPHASES.md` both put 5.4 (templates) before 5.3 (the
codec wrappers), on the reasoning that a wrapper is a thin layer over `ASN1_item_d2i` and
implementing it directly would mean writing the item path twice. Reading `tasn_dec.c` and
`tasn_enc.c` whole shows the dependency points the other way: `ASN1_item_d2i` reaches the
*primitive* arms of the item machinery with no template involved, so the wrappers need
`asn1_d2i_ex_primitive` — which is 5.3's own work — and waiting would have meant writing
that path here and again inside 5.4. The subphase table is corrected rather than the
observation being kept to.

**Restructuring the decoder found two defects in the file D76 landed.** Neither was
reachable from the three wrappers D76 shipped, which is why the court had not seen them:

* `asn1_ex_c2i`'s string arm frees the value **unconditionally** and nulls the caller's
  slot on an allocation failure. The old code freed only a value it had just allocated,
  so a `d2i_*` into an existing string would have handed the caller back a slot pointing
  at a half-filled object the authority had destroyed.
* `asn1_item_embed_d2i` raises `ASN1_R_TOO_SMALL` for `len <= 0` **before any header is
  read**. The old code went on to the header reader and reported a different reason for
  the same failure — the same return value with the wrong queue entry, which is exactly
  what this court compares.

**The court found a third thing, and it is an ownership contract rather than a bug.**
`asn1_item_ex_d2i_intern` ends with `if (rv <= 0) ASN1_item_ex_free(pval, it);`. So a
failed decode **frees the caller's value and nulls the caller's slot**, and a caller that
decodes into an existing object and fails does not keep it. The first probe case to reuse
a string and fail showed `bsd.keepstate` as `authority=0 candidate=1`, and the reading
that followed is what produced `src/asn1/fre.rs`. It also explains a shape that had looked
redundant: `asn1_ex_c2i`'s string arm nulls the caller's slot after freeing, and that null
is what stops the item layer freeing the same string a second time. Neither the return
value nor the error code differs in that case — only the caller's pointer, which no
single-call probe of one symbol would have caught.

**The item descriptors are compared field by field, not through an encoding.** `ASN1_ITEM`
is declared with its fields in `asn1t.h`, so the probe reads every one of them for all 26
descriptors. That found the fact that `IMPLEMENT_ASN1_TYPE(x)` passes `0` — not `-1` — as
the item's `size`, which a note written earlier had recorded the other way. `size` is the
field that decides whether a `BOOLEAN` is omitted from its encoding, so the wrong value
would have changed bytes rather than failing.

**Reason codes are now generated, not typed.** `forensics/tools/gen_err_reasons.py` reads
every `<LIB>_R_<NAME>` decimal `#define` under the production authority's `include/`,
`crypto/`, `ssl/` and `providers/` trees and emits `src/runtime/err_reasons.rs`: 1,839
constants over 541 headers, each citing the header that declares it. It reads the headers
independently of `gen_err_strings.parse_reason_codes` and cross-checks against it, so two
readers of the same fact must agree before the file is written. D76 recorded that
`ASN1_R_BAD_OBJECT_HEADER` and `ASN1_R_EXPECTING_AN_OBJECT` had been typed as `101`/`127`
when they are `102`/`116`; both are now references into that table, and the class of
mistake is gone rather than fixed once.

**What is not done.** The remaining 155: 128 ASN.1 and 27 PEM. The template interpreter
(`ASN1_item_*`, `ASN1_item_ex_*`, `ASN1_ITEM_lookup`/`get`), the 14 remaining `*_it`
descriptors (the two `*_ANY` items and the twelve numeric ones, which need
`ASN1_PRIMITIVE_FUNCS` hooks), the time accessors, the string masks and printing,
`ASN1_TYPE`, the NDEF BIO bridge, `d2i_ASN1_read_bio` and all 27 PEM exports are
unimplemented. No claim here covers them, and the seal's §9a is rewritten to say so.

**The staging branch.** The process instruction for this stratum is to push work
frequently so that a long stretch does not have to be re-derived if a session ends.
`phase5-asn1` carries it: commits that compile and are fmt- and clippy-clean but are not
yet courted are staged there, and a section reaches `main` only with the court that
observes it (D73's rule). This section's court is `RT-ASN1` at 1,306 observations with no
residuals, so the branch merges with this decision rather than after it.


## D78 — The ownership audit must run after the ledgers, and the check that missed it

`evidence_determinism.py` regenerates every derived artefact and requires the committed
bytes back. Its generator list had `ownership_audit.py` **before** the three obligation
generators, and `ownership_audit.json` records each ledger's sha256 as an input. So the
audit was recording the hashes of the *previous* generation's ledgers, and the fixed
point the tool verified was not the one the pipeline produced.

The check could not see it, by construction: `COMPARED_INPUT_PATHS` normalises
`inputs[].sha256` for any path that is itself compared, and `forensics/phase3-obligations.json`
is compared — so a wrong recorded hash was blanked before the comparison. The ledger's
*content* is compared directly, which is why the normalisation is right for the case it
was written for (D30/D33: a hash that can only ever match modulo a normalisation the inner
artefact already declares); it is wrong for a hash that is simply computed from the wrong
generation.

It was found by running the audit alone, after the ledgers, and watching the recorded
hashes move — not by any gate. The fix is the order, recorded in the generator list's own
comment so the next person to add a generator has the reason in front of them. The
residual is that no gate covers "this artefact's recorded input hashes are the current
ones"; a court for it would have to distinguish "normalised because redundant" from
"stale", and nothing yet does.


## D79 — A staging commit must regenerate the derived evidence, and CI is what said so

The staging branch `phase5-asn1` was created so a long stratum could be pushed in pieces
without uncourted source reaching `main` (D73). Its first commit, `b1149f7`, was pushed
mid-flight and **failed CI**, on exactly one step: `evidence-determinism`. The court job
beside it passed, which is the useful part of the signal — the code was fine, the
*record* was stale.

`evidence-determinism` regenerates every derived artefact and requires the committed
bytes back. The commit moved the implemented surface from 734 to 805 exports while
`forensics/atlas/implemented-surface.json` still said 734, so the gate correctly refused
it. The generators are cheap and need no authority container, so the rule is now: run
them before **any** push, staging included. What a staging commit may legitimately leave
stale is the court evidence — running the courts is the expensive part, and an uncourted
transcript is honestly labelled by the ledger rather than hidden — not the derived counts,
which the gate settles in seconds.

Two documentation defects were found beside it and fixed in the same change:

* `docs/CI.md` described the `lint` job as running with `continue-on-error: true` and
  "not yet a required gate". The workflow had already dropped that line, so the document
  was describing a gate that no longer existed — and a reader deciding whether a clippy
  failure blocks a merge would have got the answer wrong. The doc now says it is a
  required gate, and records why suppressing it was rejected rather than forgetting that
  it was.
* `docs/CI.md`'s list of what determinism compares named `implemented-surface.json`, "the
  two obligation ledgers", `phase-state.json` and `STATUS.md`. There are three ledgers,
  and `symbol-ownership.json`, `ownership-audit.json` and `prototype-court.json` are
  compared too. The list is now the rule rather than a subset.


## D80 — `ASN1_ITEM_lookup` and `ASN1_ITEM_get` are a cross-phase dependency, measured

Both are declared in `asn1.h`, so the ownership atlas gives them to Phase 5 and both sat
in the stratum's `open` list as if implementing them were a matter of reading
`crypto/asn1/asn1_item_list.c` — which is 46 lines, two loops, and trivial. It is not.
The file's real content is the header it includes: the authority's **generated**
`asn1_item_list.h`, a 147-entry array of item accessors, and both functions' observable
behaviour is that array as a whole. `ASN1_ITEM_lookup("X509")` answering `NULL` is a
wrong function, and it is exactly the answer an implementation over the items that exist
today would give.

Measured against `forensics/atlas/symbol-ownership.json`: the `_it` accessors of those 147
names are owned by this stratum for **40** of them, by Phase 8 for 7, Phase 10 for 6,
Phase 11 for 64 and Phase 12 for 30. So **107 of 147** are items no stratum before Phase 12
will have. Both symbols are therefore handed to Phase 12 with that measurement as the
reason, which is the same shape as D73's hand-offs: a disposition by *behaviour*, recorded
with the evidence that makes it checkable rather than a judgement about difficulty.

The trap this closes is specific and would have been silent. An implementation over today's
40 items would pass any court that asked it about `ASN1_OCTET_STRING` and would fail on the
107 names whose codecs are later phases' — so a partially-correct `ASN1_ITEM_lookup` is
worse than an honest hand-off, because the ledger would have called it done.

Recording it also wrote down what reading `tasn_utl.c` whole established — the choice
selector being an `utype`-offset, `ossl_asn1_do_lock`'s three operations and its -1, the
`ASN1_ENCODING` save/restore rules including `inlen <= 0` being a *failure*, the
`ASN1_BOOLEAN` field pointer being the value, `ossl_asn1_do_adb`'s selector rewrite and
linear search — and the `CHOICE` and `SEQUENCE` arms of `asn1_item_embed_d2i`, which is
what the template interpreter is written against. That is in
`docs/PHASE-5-SUBPHASES.md`, so the next session starts from it rather than from the
source.

## D81 — The item dispatch lands, and three kinds of instrument were the suspect first

`src/asn1/d2i.rs` now carries the whole of `asn1_item_embed_d2i` — `PRIMITIVE` with and
without a template, `MSTRING`, `EXTERN`, `CHOICE`, `SEQUENCE` and `NDEF_SEQUENCE` — plus
`asn1_template_ex_d2i`, `asn1_template_noexp_d2i` and `asn1_find_end`; `src/asn1/i2d.rs`
carries the matching `ASN1_item_ex_i2d` dispatch, `asn1_template_ex_i2d`,
`asn1_set_seq_out` and the three public encode entry points; and two new modules hold the
`ASN1_TYPE` family (`src/asn1/a_type.rs`) and the pack/unpack pair
(`src/asn1/asn_pack.rs`). `implemented[libcrypto]` moved 805 → 829 and the stratum's open
list 155 → 129.

### A note about the authority is the suspect before the authority

The hand-off this session started from asserted three things about `crypto/asn1/tasn_dec.c`
that are not so, and each would have produced a wrong implementation:

* that `asn1_d2i_ex_primitive` and `asn1_ex_c2i` take `OSSL_LIB_CTX *libctx, const char
  *propq`. They take neither. `libctx`/`propq` stop at `asn1_item_embed_d2i` and reach the
  `EXTERN` hooks and the allocator; the primitive decoder's own argument list ends at
  `ASN1_TLC *ctx`. Adding two ignored parameters would have made an internal function's
  signature differ from the authority's for no observable reason.
* that `asn1_d2i_ex_primitive` should **drop** its `MSTRING` arm because it "moved to
  `embed_d2i`". The authority keeps `if (it->itype == ASN1_ITYPE_MSTRING) { utype = tag;
  tag = -1; }` in the decoder, and the `MSTRING` arm of the dispatch *relies* on it: the
  dispatch reads the tag from the encoding and passes it as `tag`, and the decoder is what
  turns it back into a `utype`. Dropping it would have decoded every `ASN1_PRINTABLE` and
  `ASN1_TIME` with `utype = 0`.
* that the `err:` tail of `asn1_ex_c2i` "reduces to a plain return" outside the `ANY` arm,
  which is what let a multi-exit `return 0` stand in for it. The tail frees the `ASN1_TYPE`
  this frame allocated **and** nulls the caller's slot on every failure path, so it is a
  labelled block with one exit, not a comment.

All three were checked against `forensics/authorities/src/openssl-3.6.4` before any code
was written, and the file's own prose now records the measurement rather than the claim.

### `ABI-PROTOTYPE` found two defects in the new code, which is what it is for

The court reported two type-plane mismatches, both in symbols this session added:

* `ASN1_item_ex_d2i` was declared `opt: c_int`. The installed header declares that
  parameter `char`. A caller compiled against the header passes one byte and leaves the
  upper bits of the register undefined, so a callee that reads four is reading
  unspecified bits — the defect class D76 recorded for the legacy `ERR` getters, caught
  this time before the court could have found it at runtime.
* `ASN1_item_ex_i2d` was declared `pval: *const *const c_void`. The header declares
  `const ASN1_VALUE **` — the slot is writable and it is the *pointee* that is const —
  so `*mut *const c_void` is the matching spelling. The stricter form would have compiled
  every internal caller and broken every external one.

Both are fixed and both planes are now clean: 673 declarations checked, 0 mismatches, 0
unmapped.

### The instrument was the suspect too, again

After those two fixes the arity plane reported `ASN1_item_ex_d2i` as having **ten**
parameters against the authority's eight. The declaration has eight. The court's Rust
parameter splitter splits on top-level commas, and the two-line comment that explains the
`char` sits *inside* the parameter list, so its comma was counted as a parameter
separator. The same naive scan would have mis-read any parenthesis inside a comment.

The fix is in the instrument, not in the comment: `blank_comments` replaces each comment's
body with spaces **in place**, preserving length and line breaks so that every offset and
line number derived from the text still means the same thing, and it skips string literals
so that a `//` inside one — and this crate writes `c"..."` literals throughout — is not
taken for a comment. The comment stays where it is; it is now a standing regression test
that the court reads declarations rather than text.

### One deliberate residual, recorded rather than smoothed

`asn1_set_seq_out` sorts a `SET OF` with `qsort` in the authority. `qsort` is not
specified to be stable, so for two elements whose encodings are byte-identical the emitted
bytes are the same under any ordering but the resulting *stack* order — which only the
`do_sort == 2` case (`ASN1_TFLG_SET_ORDER`) exposes to the caller — is tied to the
original order here. The implementation uses a stable sort and says so, because that
matches the authority's common path and because the alternative is an unprovable claim
about libc's internals. It is an evidence question for `RT-ASN1-TEMPLATE`, not a
normalisation applied to make a difference go away.

### `item_ex_free` is gone

`src/asn1/fre.rs` had a crate-internal `item_ex_free` — `ASN1_item_ex_free` through a
string-typed slot — whose only caller was the previous `item_d2i`. The new dispatch calls
the exported `ASN1_item_ex_free` directly, exactly as the authority's
`asn1_item_ex_d2i_intern` does, so the wrapper became dead code and the compiler said so.
It is deleted rather than kept behind an `allow`: a function with no caller is a function
whose contract cannot be checked.

### What this does and does not claim

`RT-ASN1-TEMPLATE` does not exist yet. That court is what drives a **caller-built**
`ASN1_SEQUENCE` and `ASN1_CHOICE` template through the decode/encode pair, and without it
the template interpreter is exercised only insofar as the items this stratum defines reach
it — which, for a template-bearing item, is not at all. Nothing in this session is
`PARITY_VERIFIED`; the stratum stays `in-progress`, and this is a staging commit.

## D82 — The stream layer lands, and the prototype court's C type parser was the last instrument at fault

`ASN1_dup`/`ASN1_item_dup` (`a_dup.c`), the encode-to-stream family
(`a_i2d_fp.c`: `ASN1_i2d_fp`, `ASN1_i2d_bio`, `ASN1_item_i2d_fp`,
`ASN1_item_i2d_bio`, `ASN1_item_i2d_mem_bio`) and the decode-from-stream family
(`a_d2i_fp.c`: `ASN1_d2i_fp`, `ASN1_d2i_bio`, `ASN1_item_d2i_bio_ex`,
`ASN1_item_d2i_bio`, `ASN1_item_d2i_fp_ex`, `ASN1_item_d2i_fp`,
`asn1_d2i_read_bio`) are implemented. `implemented[libcrypto]` moved 829 → 843 and the
stratum's open list 129 → 115.

### `ASN1_d2i_fp`'s `xnew` is dead, and stays

`xnew` is taken and **never called** — not by `ASN1_d2i_fp`, not by `ASN1_d2i_bio`, and
not by the authority either. It is in the signature because the 0.9.6-era API had one. It
is kept, bound to `_`, because a caller passing a function pointer is part of the
observable interface even when the pointer is ignored, and because dropping it would
change the symbol's arity.

### The two decisions `asn1_d2i_read_bio` actually consists of

Everything else in that function is buffer bookkeeping. Two things are not:

* **`ASN1_R_TOO_LONG` from `ASN1_get_object` is recoverable.** It means the buffer does
  not yet hold the bytes the declared length needs. The reason is popped with
  `ERR_pop_to_mark` and a fresh mark taken, so a stream arriving in pieces does not
  accumulate one error per read. Any *other* reason from that call is fatal.
* **A clean EOF at a top-level boundary is the normal end of input and raises nothing.**
  A read failure, an EOF with bytes already buffered, and an EOF still owing an
  end-of-contents marker are all `ASN1_R_NOT_ENOUGH_DATA`. The authority's own comment
  names the consumers that depend on the quiet case — callers looping over concatenated
  DER values, including CPython's `ssl` module — so getting this wrong is observable as a
  spurious error rather than as a missing one.

The multi-byte tag scan is transcribed as the authority writes it, including the detail
that `while (diff > 0 && *(q++) & 0x80)` consumes a byte only when `diff > 0`, which is
why the `diff == 0` branch afterwards reads a byte the loop did not consume. And `off`
advances by `slen`, **not** by the mutated `want` — the two diverge in the chunked-read
path, and conflating them would have made a short read advance the offset by too little.

### The instrument was the suspect once more, and twice over

`ABI-PROTOTYPE` reported `ASN1_dup` and `ASN1_d2i_fp` as `TYPE-UNMAPPED` on the
*authority* side. The declarations were fine. `canon_c_type` decided
function-pointer-versus-function-type with `"(*" in t`, and both `int (*)(BIO *, int)`
(a pointer to a function) and `void *(void **, long)` (a function returning `void *`)
contain that substring. `d2i_of_void` has the second shape, so it resolved to `None`;
`i2d_of_void` has the same shape with an `int` return, so it resolved — which is the
signature of an instrument defect rather than a declaration defect.

The test is now structural: the `*` must be the *declarator*, inside the first top-level
group. `int (*)(...)` has a group whose content begins with `*`; `void *(...)` has one
that does not, and its return type is what precedes the group. The regex branch below
could not have caught it either, because its return-type group admits only letters, digits
and spaces. Both planes are now clean over 686 checked declarations.

This is the fourth instrument defect this stratum has found — after the ERR source
coordinates, the evidence-regeneration ordering and the parameter-splitter comment — and
it was found the same way: by noticing that a *pass* and a *fail* shared a shape that the
declarations did not explain.

## D83 — `RT-ASN1-TEMPLATE` exists, and it found two defects the ledger could not have

The template interpreter landed in D81 with a stated hole: nothing drove `CHOICE`,
`SEQUENCE`, the `SEQUENCE OF`/`SET OF` content writer, the `EMBED` indirection or the
`OPTIONAL` absent answer through a **caller-built** descriptor, because no built-in item
has those shapes — a built-in item's shape *is* the thing under test. The court now exists
and closes the hole. It is 100 observations over an item the probe declares itself.

### Two real defects, and neither was reachable from a unit test

**`uint32_i2c` negated at the wrong width.** The authority's hook reads a `uint32_t`,
negates it **as a `uint32_t`**, and only then widens. This crate widened first and negated
in 64 bits, so `-5` became `0xffffffff00000005` and encoded as nine octets
(`02 09 ff 00 00 00 00 ff ff ff fb`) where the authority writes one (`02 01 fb`). The
decode of the candidate's own encoding then failed, so a value written by this crate could
not be read back by it. The court caught both halves in one observation.

**The `SEQUENCE` arm raised `FIELD_MISSING` on a field error.** The authority's
`if (!ret) { errtt = seqtt; goto err; }` is a jump to the tail that *names the field*: it
raises nothing further, because the field's own decode already raised. This crate treated
the same condition as "the field was missing" and raised `ASN1_R_FIELD_MISSING` on top, so
a decode that fails left five entries on the queue where the authority leaves four. The
`field_error` flag is gone: every case that set it was a `goto err`, and both are now
`return err_tail(...)`.

The second is the more interesting one, because the *count* of queue entries is not
something a reader of the code would think to check, and the first four entries were
identical on both sides. It was visible only because the probe prints the whole queue.

### Three instrument and probe defects on the way in

* The probe's own "wrong inner tag" case rewrote index 2 with the value already there — the
  tag byte it meant to corrupt is at index 8 — so that case tested an undisturbed decode and
  both sides agreed on nothing. A probe is the suspect before the crate.
* `drain` printed only the reason code. `ERR_GET_REASON` masks the library out, so a bare
  `121` cannot be told from `BIO_R_UNSUPPORTED_METHOD` or `DH_R_UNABLE_TO_CHECK_GENERATOR`.
  It now prints the library and the reason string as well, which is what made the extra
  queue entry legible.
* `run_courts.sh` listed its runtime courts **by name**. `RT-ASN1-TEMPLATE` was generated,
  its manifest was written, and the runner ran the previous set — so the court existed and
  produced no receipt. The list is now derived from `forensics/frf/courts/`, because a
  registry that has to be remembered is the failure mode this project keeps finding.

### What is claimed, and what is not

`RT-ASN1-TEMPLATE` passes with 100 observations, appears in its claim's receipt set, and
has challenge mutants on both of its declared axes — so the court is sensitivity-backed
rather than merely green. The stratum's open list is 93; nothing in it is
`PARITY_VERIFIED`; Phase 5 remains `in-progress`.

## D84 — The ASCII-form parsers land, and one of them found a defect that was my own invention

`a2d_ASN1_OBJECT` (`a_object.c`) and `a2i_ASN1_INTEGER` / `a2i_ASN1_ENUMERATED`
(`f_int.c`) and `a2i_ASN1_STRING` (`f_string.c`) are implemented, with
`crypto/ctype.c`'s two class predicates they need. `implemented[libcrypto]` moved
865 → 869, the stratum's open list 93 → 89, and `RT-ASN1` grew 1306 → 1366
observations.

### `crypto/ctype.c` is not a table here, and that is a decision

`ossl_ctype_check`, `ossl_isdigit` and `ossl_isxdigit` are in **no** `.num` file and the
ownership atlas has no record of them, so they are internal helpers with no ABI
obligation. The authority implements them over a 128-entry mask table. Transcribing that
table is what D33 forbids — a hand-copied constant nothing regenerates. The two classes
the parsers use are each an exact union of ASCII ranges (`xdigit` was read back out of the
authority's own table: `0x30`-`0x39`, `0x41`-`0x46`, `0x61`-`0x66`, 22 entries and no
more), so they are written as range tests with the equivalence stated and a test that
checks all 256 byte values against both.

The one subtlety kept deliberately is that `ossl_isdigit` is a bare range test while
`ossl_isxdigit` carries the authority's `0 <= c < 128` bounds check. A byte with the high
bit set arrives as a negative `int` from a signed `char` and fails both, but by different
routes, and collapsing them would lose that.

### The defect was a claim I made about the authority rather than read from it

`a2i_ASN1_STRING` writes each output octet as

```c
s[num + j] <<= 4;
s[num + j] |= m;
```

I wrote an assignment instead, and — worse — invented a reason: a comment asserting that
this reader "assigns each octet rather than shifting into it", which I then used to justify
why it can use plain `OPENSSL_realloc` where the INTEGER reader uses the clearing one. The
first digit was therefore overwritten by the second, and `414243` decoded as `010203`.
`RT-ASN1` caught it on the first run.

The shift-and-or is not incidental. Each octet is written twice, and the first pass reads
whatever the allocation held, shifts it into the high nibble, and the second pass shifts it
out of the byte entirely — so the result is the two digits and nothing else, and the
clearing-versus-plain `realloc` difference between the two readers is **not** observable.
That is now written down as the reason the two readers may differ, instead of the invented
one. The line the authority actually writes is quoted in the comment.

This is the fourth time this stratum has found a *note about the authority* that was the
suspect before the authority was, and the first where the note was one I had just written.

### What the round trip measured

I expected the `i2a` → `a2i` round trip to fail for values long enough to be broken across
lines, on the reasoning that the `00` prefix strip and the backslash removal would leave an
odd hex count. Rather than reason further, the probe now measures it: a 40-octet INTEGER is
written with `i2a_ASN1_INTEGER` into a memory BIO and read back with `a2i_ASN1_INTEGER`, and
the return, the length and the queue are compared. It round-trips on both sides. The
reasoning was wrong and the measurement is what settled it.

## D85 — The time family lands, and the printer defect only the public entry point could show

The 29 exports of `crypto/asn1/a_time.c`, `a_utctm.c` and `a_gentm.c` are implemented, with
the three `crypto/o_time.c` calendar symbols they stand on (`OPENSSL_gmtime`,
`OPENSSL_gmtime_adj`, `OPENSSL_gmtime_diff`, all Phase 3 by declaring header). A new
`src/runtime/time.rs` carries the glibc `struct tm` projection and the Fliegel & Van Flandern
Julian-day arithmetic; `src/asn1/time.rs` carries the family. `implemented[libcrypto]` moved
871 → 903 and the stratum's open list 87 → 58.

### The one defect, and why no unit test could have found it

`ASN1_TIME_print` in the authority is

```c
int ASN1_TIME_print(BIO *bp, const ASN1_TIME *tm)
{
    return ASN1_TIME_print_ex(bp, tm, ASN1_DTFLGS_RFC822);
}
```

— it goes through the *public* `ASN1_TIME_print_ex`, which is
`ossl_asn1_time_print_ex(...) > 0`. There are three internal answers (`1` success, `-1`
unparseable, `0` BIO write failure) and the public pair collapses them to two. I wrote
`ASN1_TIME_print` as a direct call to the internal printer, so an unparseable value returned
`-1` where the authority returns `0`.

The instrument was right and the reading was wrong: the two functions are four lines apart in
`a_time.c` and I read the second and skipped the indirection in the first. What makes it
worth recording is *why nothing else caught it*. A unit test on the internal printer would
confirm the three-valued behaviour I had already reasoned about. The difference exists only
at the public entry point, and only for an input the value-level tests do not use. `RT-ASN1-TIME`
found it on its first run, as one line of a 1071-line transcript — which is the strongest
argument this project has for measuring the *entry point* rather than the helper.

### Two asymmetries that are the authority's, not defects

Both are reproduced and courted rather than corrected:

- The `±hhmm` offset is applied with `OPENSSL_gmtime_adj` **only when the destination is
  non-null**. `ASN1_UTCTIME_set_string(NULL, "…+hhmm")` therefore validates a value that
  `ASN1_UTCTIME_check` also accepts and that a fill does not merely normalise but can
  *reject*, if the offset moves the Julian day number below zero. `ASN1_TIME_check` answers
  1 for a value `ASN1_TIME_to_tm` then refuses.
- `ASN1_UTCTIME_set` *requires* the 1950-2049 window — `ossl_asn1_time_from_tm` is reached
  with `V_ASN1_UTCTIME`, and a year outside it is a failure rather than a widening to
  GeneralizedTime. Only `ASN1_TIME_set`/`ASN1_TIME_adj`, which pass `V_ASN1_UNDEF`, choose
  the syntax from the year. 2050-01-01 therefore gives NULL from the first and a
  GeneralizedTime from the second.

### `struct tm` is declared here, and its layout is measured

`Tm` in `src/runtime/time.rs` is the crate's projection of a *platform* structure, not of an
OpenSSL one: four exported signatures take a `struct tm *`. The probe therefore prints
`sizeof` and all eleven `offsetof` values and the court compares them, rather than the crate
asserting a layout in a unit test that the same source defines. `tm_gmtoff` and `tm_zone` are
part of the comparison because `ossl_asn1_time_to_tm` zeroes its local copy and then copies
the whole structure out, and because `ASN1_TIME_to_tm(NULL, …)` leaves whatever `gmtime_r`
wrote there.

### Where the arithmetic was allowed to differ from the authority

`OPENSSL_gmtime_adj` and the two Julian helpers perform `long` and `int` arithmetic that a
caller can drive into overflow, which is undefined upstream. The crate builds with
`overflow-checks = true`, so the modules use `wrapping_*` operations throughout: a value at
the overflow boundary is *a* value rather than a panic that would abort the caller's process.
D-TIME-2 in `docs/SECURITY_DIVERGENCE_POLICY.md` records that, and the four calls that fault
upstream on a null argument (D-TIME-1) answer the documented failure value instead.

## D86 — The string surface lands, and a Phase-3 refusal turns out to be wrong

Subphase 5.6 is 14 exports in: `a_print.c` (3), `a_mbstr.c` (2), `a_strnid.c` (7) and
`t_pkey.c` (2). `implemented[libcrypto]` moved 903 → 917 and the stratum's open list
58 → 42. `RT-ASN1-STR` is new: 581 observations, and it found three things.

### The constant I recalled instead of reading

`ASN1_PRINT_MAX_INDENT` is **128**. I wrote `80`, taken from the ASCII line width
rather than from `t_pkey.c`, and the court found it on the first run: with an indent of
81 the authority writes 81 spaces where the candidate wrote 80, two octets short over a
two-line buffer. This is the transcription defect class D33 names, in its purest form —
a number that looked plausible, was never regenerated from anything, and had nothing to
notice it going stale. The constant now quotes the file it came from, and the probe
carries indent values on both sides of the clamp (80, 81) so the boundary is measured
rather than assumed.

### `MASK:` with nothing after it

`ASN1_STRING_set_default_mask_asc("MASK:")` is an argument error in the authority, and
the test is `if (*p == '\0') return 0;` immediately after the prefix is consumed. I
accepted it, reasoning that `strtoul("")` answers 0 and `*end` is then the NUL. Both of
those are true and neither is the point: the authority rejects the *empty remainder*
before `strtoul` runs. The general shape is worth recording — a check that exists to
exclude an input the subsequent parse would accept anyway looks redundant while you are
reading it and is invisible when you skip it.

### A Phase-3 decision, superseded

`OPENSSL_INIT_LOAD_CONFIG` was on the Phase-3 `INIT_UNSUPPORTED` list: "reads
`openssl.cnf` and applies it", which is not a no-op, so refusing it with
`ERR_R_INIT_FAIL` was the honest choice while nothing called it.

`ASN1_STRING_TABLE_get` calls it. Its first line after the NID check is
`OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL)`, guarded by
`#ifndef OPENSSL_NO_AUTOLOAD_CONFIG`, which is not defined on this profile — so the
call is made on *every* lookup. The court showed the whole string table raising
`init fail` on the candidate where the authority raises nothing.

The refusal's premise was incomplete rather than wrong. The authority's config step is

```c
ossl_config_int(NULL)  ->  CONF_modules_load_file_ex(global_default, NULL, NULL,
                                                     DEFAULT_CONF_MFLAGS)
```

and `DEFAULT_CONF_MFLAGS` is `CONF_MFLAGS_DEFAULT_SECTION | CONF_MFLAGS_IGNORE_MISSING_FILE`.
A missing config file is therefore **not** an error upstream; the step succeeds having
loaded nothing. That is the observable answer on any profile with no default config
file, and it is the answer the court measured. So the flag is now accepted and the step
is a no-op that succeeds, and the part that genuinely needs a subsystem that does not
exist — applying a config file that *does* exist, which needs `OSSL_LIB_CTX` and the
module registry, both Phase 6 — is recorded rather than pretended.

Two things about that are worth keeping:

* Refusal and silence are not the only two options. The third — accept, do the part that
  is provable, and record the remainder — is the one that matches the authority on the
  profiles actually observed, and it is the one this decision takes.
* The Phase-3 unit test that enumerated the refused options has been narrowed by exactly
  one case. It is the same shape as D7's supersession: the *decision* was sound for what
  it knew, an observation moved, and the observation lives in the derived evidence rather
  than in this file.

### Two exports handed on rather than written

`ASN1_add_oid_module` and `ASN1_add_stable_module` are each four lines that register a
CONF module. `CONF_module_add` is Phase 6 — Phase 4 handed it there on the ground that
only the module registry constructs a `CONF_MODULE` — so neither can be written before
that registry exists. They are handed to Phase 6 and Phase 11 respectively, by the same
mechanism as the eleven RAND-dependent `BN_*` exports: a *dependency*, named, with the
stratum that owns it.

### Where the stack lives

`stable` is an `AtomicPtr`, not the authority's bare `static` pointer. The authority's
own comment on the sort it performs is "Ideally, this would be done under lock", so its
thread-safety is not a property being reproduced either way; an `AtomicPtr` keeps the
observable contract (one process-global stack, sorted before each search) while avoiding
a mutable static. The comparator is the *typed-stack* form — its arguments are the
addresses of the slots, so it dereferences twice — which is why the standard table's
`bsearch` comparator is a separate function: it receives element addresses instead.

## D87 — The escaping printer lands, and a comparison that was invalid rather than failing

`a_strex.c`'s three exports are in: `ASN1_STRING_print_ex`,
`ASN1_STRING_print_ex_fp` and `ASN1_STRING_to_UTF8`. Subphase 5.6 is closed.
`implemented[libcrypto]` moved 917 → 920 and the stratum's open list 42 → 39 —
the remaining twelve `asn1.h` exports are `ASN1_str2mask` and `asn1_gen.c`,
`ASN1_item_print`, the six NDEF/filter BIO exports and the two streaming writers.

### One implementation, two sinks, and why the length is trustworthy

`do_print_ex` renders everything **twice**: once with a null sink, which makes
`do_buf` count, and once for real. The two passes are the same code, so the length
cannot disagree with the bytes — and a caller can get the length on its own by
passing a null BIO, which is not a documented feature but is what
`send_bio_chars` does with a null argument. The probe measures both and records
`same=1`, which is a property rather than an example.

### The generated table, and how it was checked

`char_type[]` is 128 numbers generated by `crypto/asn1/charmap.pl` into
`crypto/asn1/charmap.h`. It is reproduced as the *generated artifact*, not
re-derived from the generator's rules: re-deriving it would be a second
implementation of a generator, which is the D33 class with an extra step. What
makes that acceptable is that the probe pins the table behaviourally — every one of
the 256 byte values is printed under `RFC2253`, under `ESC_MSB` alone and under
`ESC_QUOTE`, so the table is observed through the only interface that uses it
rather than compared against a copy of itself.

`ESC_MSB` alone is the case worth having: a byte above `0x7f` is tested against
that bit **without consulting the table at all**, so `ESC_MSB` escapes high bytes
and `ESC_CTRL` does not, and the two look interchangeable until the table is
removed from one path.

### The residual is about the instrument, not the crate

`do_dump` builds a stack `ASN1_TYPE` whose `value.ptr` is the `ASN1_STRING` being
printed, and sets `type` from the string. With `ASN1_STRFLGS_DUMP_DER` the encoder
then reinterprets that pointer *as the type* — correctly for every character type,
where the union member really is the string, and not for `BOOLEAN`, where it reads
an `int`. The authority printed `#010150` and the candidate `#0101B0`: two low
bytes of two heap addresses.

The court reported that as a value residual, which is the right thing for it to do
and the wrong thing to have asked. There is nothing to fix in the crate; the
observation was never comparable, because the value it compares contains an
address. The probe now asks for `DUMP_DER` only on types where the union member is
the string, and the restriction is written where it is applied rather than applied
silently.

The general point is worth keeping: a *passing* court is not evidence that the
comparison was meaningful, and a failing one is not evidence that the crate is
wrong. Both readings need the observation to be a function of the contract and
nothing else, and an address is not.

### What this does not claim

`X509_NAME_print_ex` and `X509_NAME_print_ex_fp` are the other half of the same
translation unit — `do_name_ex` and its field-name handling — and are declared in
`x509.h`, so they belong to Phase 11. Nothing here is parsed as a name.

## D88 — `ASN1_str2mask` lands, and the two generators are handed on for one structure

`ASN1_str2mask` and the fifty-four-name `asn1_str2tag` table beneath it are in.
`implemented[libcrypto]` moved 920 → 921 and the stratum's open list 39 → 37.
Subphase 5.6 is closed.

### Why two of the three exports are handed to Phase 11

`asn1_gen.c` declares three exports and they look alike. They are not:

```c
ASN1_TYPE *ASN1_generate_nconf(const char *str, CONF *nconf);
ASN1_TYPE *ASN1_generate_v3(const char *str, X509V3_CTX *cnf);
int ASN1_str2mask(const char *str, unsigned long *pmask);
```

The first two take or build an `X509V3_CTX`, which is `x509v3.h`'s and belongs to
Phase 11. `ASN1_generate_nconf`'s null-`CONF` path looks like the escape — it calls
`ASN1_generate_v3(str, NULL)` — but the non-null path calls `X509V3_set_nconf`,
which is a *macro that writes six fields* of the structure, so even reaching the
function body requires the layout. That is the same shape as `CONF_module_add` in
D86 and it gets the same treatment: named, with the stratum that owns it, rather
than half-written.

`ASN1_str2mask` shares nothing with them but the file. Its dependencies are the
table, `ASN1_tag2bit` (5.1) and `CONF_parse_list` (Phase 4), all of which exist.

### One table, one module

`asn1_str2tag` is used by `ASN1_str2mask` now and by the two generators later, so
it lives in `src/asn1/asn1_gen.rs` rather than in a private helper beside the
generator. Fifty-four names is small enough to duplicate and large enough for a
duplicate to drift, and this project has already had one registry that had to be
remembered rather than derived.

The table's shape carries one piece of meaning worth naming: the six *modifier*
names — `EXP`, `IMP`, `OCTWRAP`, `SEQWRAP`, `SETWRAP`, `BITWRAP`, `FORMAT` — do not
have `V_ASN1_*` values but values at or above `ASN1_GEN_FLAG` (0x10000), and
`ASN1_str2mask` rejects a name whose tag is in that range with one test. So a mask
naming `EXP` is refused *by a range test on the shared table*, not by a second list
of names that must be kept in step with the first.

### The first module in this stratum to need no correction

`RT-ASN1-STR` grew to 5831 observations with thirty-eight `str2mask` cases, and
they all matched on the first run. Ten of the previous eleven translation units in
this stratum needed a correction after their court ran; this one did not, and the
difference is not care — it is that the whole behaviour fits on one screen and can
be read rather than reconstructed. `ASN1_PRINT_MAX_INDENT` (D86) was a number in a
file I did not open; `ASN1_str2mask` is six lines.

Worth noting as a caution rather than a virtue: the probe cases were written *from*
the source, so they encode its branches. Passing on the first run means the
branches were transcribed correctly, not that a branch is absent. What makes the
pass meaningful is that the same cases ran against the authority, which is the
whole point of the method.

### The partial mask, which is the authority's behaviour

`ASN1_str2mask` writes `*pmask = 0` once and then ORs each accepted name in place.
A refused name returns 0 from the callback and stops the parse *without* clearing
what the earlier names accumulated, so `"PRINTABLE|NOPE"` answers 0 with a mask
that still has the printable bit set. The probe checks the mask on both sides of
that failure, so the residual is measured rather than read.

## D89 — The ASN.1 filter BIO lands, and the three-call setup test I wrote as arithmetic

`bio_asn1.c` and the `BIO_new_NDEF` half of `bio_ndef.c` are in: six exports.
`implemented[libcrypto]` moved 921 → 927 and the stratum's open list 37 → 30 — the
remainder is `ASN1_item_print`, `PEM_write_bio_ASN1_stream`, `i2d_ASN1_bio_stream`
and the 27 `pem.h` exports.

### The defect, which crashed rather than diverged

The authority tests its three setup calls as

```c
if (BIO_asn1_set_prefix(...) <= 0
    || BIO_asn1_set_suffix(...) <= 0
    || BIO_ctrl(asn_bio, BIO_C_SET_EX_ARG, 0, ndef_aux) <= 0)
    goto err;
```

I wrote it as a product:

```rust
let setup = setup * (unsafe { BIO_ctrl(...) } <= 0) as c_int;
```

which multiplies by **zero on success**, so `BIO_new_NDEF` took its error path on
every call. That path releases the support block; but the setup had already handed
the block to the BIO with `BIO_C_SET_EX_ARG`, and the BIO's destroy callback
releases it too. glibc reported a double free in a tcache bin and the probe dumped
core before printing a single NDEF observation.

Two things about it are worth keeping. The first is that this is the *opposite* of
D86's defect: there a constant was recalled instead of read, here three lines were
read and then rewritten into something tidier, and the rewrite inverted the answer.
Six lines transcribed would have been right. The second is that the failure mode was
a crash, not a divergence, and only because the probe had been made line-buffered in
D86 could it say *where* — the transcript stopped between `ndef.mem_nonnull=1` and
the first `ndef.*` observation, which named the callee. An instrument that loses its
transcript to a crash cannot localise the crash that lost it.

### Gemel C39's summary is incomplete, and that is recorded here

The `gemel change finish` summary for this work quoted two fragments of C in
backticks. The command was run through a shell, so the backticked spans were
executed as commands and dropped from the recorded text. Gemel is append-only, so
C39's summary cannot be rewritten; this entry is the authoritative record of what it
was meant to say. The lesson is operational rather than architectural — a summary
that contains shell metacharacters must be quoted for the shell that carries it —
and it is recorded rather than quietly retried because the trajectory is evidence.

## D90 — `ASN1_item_print` lands, and the court finds a defect no unit test could

`ASN1_item_print` (`crypto/asn1/tasn_prn.c`) is the derivation counterpart of the
template decoder: the same `itype` switch over the same `tt->offset` arithmetic,
walking a decoded value instead of bytes. It is implemented in `src/asn1/tasn_prn.rs`
and observed by `RT-ASN1-PRINT`, 275 observations, no residual.

Three things about it are worth keeping.

The first is the one the court caught, and it is the kind of defect this project exists
to find. `asn1_template_print_ctx` re-addresses an `EMBED` field before printing it:
the field's own storage *is* the value, so the printer builds a pointer to a local
holding the field's address and passes *that* down. The authority declares that local
at function scope. My first version declared it inside the `if` block that fills it in,
which compiles, which reads plausibly, and which points at a stack slot Rust is entitled
to reuse the moment the block ends. The struct's first field printed as a stable
constant that was independent of its value — 1651470960 for 0, for 1 and for 0x1234567
alike — and no unit test could have noticed, because nothing in the crate's own items
is `EMBED` with a primitive-hook field. The probe now pins that property on purpose:
`d.caller_num1` and `d.caller_num0` print the same field at two values that cannot be
mistaken for an address, so a printer reading the wrong storage cannot pass by
coincidence, and `d2.simple_int` prints a *non*-embedded `INT32` so an `EMBED`-only
defect is distinguishable from a hook defect. The fix mirrors `i2d.rs`'s `tval`, which
had the pattern right from the start.

The second is `i2s_ASN1_INTEGER`. `asn1_print_integer` calls it, its definition is in
`crypto/x509/v3_utl.c` and its declaration is in `x509v3.h` — a Phase 11 symbol. Phase 5
needs the behaviour and does not own the export, so it is reproduced as
`pub(crate) i2s_asn1_integer` with no `#[no_mangle]`: exporting a second definition would
double-define the symbol and claim an obligation this stratum does not own. Its two
`ERR_raise` coordinates are a different question, and the answer follows `a_object.c`'s
precedent from Phase 4 (D49) — the coordinate is observable through a Phase 5 export, so
`crypto/x509/v3_utl.c` is added to `gen_err_raise_sites.py`'s covered files rather than
deferred with the rest of `crypto/x509`. That needed one generator fix of its own: the
reason resolver's include list had `x509err.h` but not `x509v3err.h`, so `X509V3_R_*` did
not resolve.

The third is the ownership reconciliation, which was **already failing at the previous
HEAD** and had been missed. `bio_asn1.c`'s six exports are declared by `bio.h`, so the
declaring-header rule makes them Phase 4's, but 5.8 implemented them here — and both
ledgers counted them, which `ownership_audit.py` fails on. The mechanism for this already
existed: a hand-off is *sticky*, Phase 3 established that (D57), and a deferred row may
carry `implemented_by_owner: true`. So Phase 4 now declares `HANDED_OFF_TO_PHASE5` and
excludes those six from its `implemented` list, Phase 5 keeps them, and the audit
reconciles the two. The lesson is not about these six symbols: it is that a green
pipeline is only green for the steps it runs, and an evidence tool that fails silently
because nobody looked at it is indistinguishable from one that passes.

## D91 — `ASN1_item_print`'s null-item contract is recorded, not reproduced

`ASN1_item_print` reads `it->sname` before any check and `asn1_item_print_ctx` reads
`it->funcs`, `it->itype` and `it->utype` immediately, so a null item faults in the
authority. The candidate takes the item as a documented non-null caller contract instead
of reproducing the fault, in the same way and for the same reason the time family does
(D-TIME-1). It is recorded as `D-PRINT-1` in `docs/SECURITY_DIVERGENCE_POLICY.md`
alongside the malformed-item class, and no compatibility claim covers it: a probe cannot
compare a crash, so the probe does not reach it.

## D92 — `asn_mime.c`'s copying half lands, and a hand-off reason turns out to be a file

`SMIME_crlf_copy` and `i2d_ASN1_bio_stream` are implemented in
`src/asn1/asn_mime.rs` and observed by `RT-ASN1-MIME` (188 observations, no
residual). Both are `asn1.h`'s, so the declaring-header rule always gave them to
this stratum; what was wrong was the *reason* they were handed to Phase 12.

That reason was "operates over CMS and PKCS#7, which is Phase 12; asm_mime.c" — a
statement about a translation unit. `SMIME_crlf_copy`'s dependencies are
`BIO_f_buffer`, which Phase 4 implemented, and `strip_eol`, which is seventeen lines
of the same translation unit. Nothing is missing. So the hand-off was not a
dependency at all, it was an inference from the file a function lives in, which is
exactly what D49 recorded as the error class that lets an obligation disappear:
`a2d_ASN1_OBJECT` was lost the same way, by being classified by prefix rather than
by declaring header, one level further out. The rule the ledger documents for
itself — "the reason is a *dependency*, not a difficulty, which is what makes the
hand-off checkable" — is what caught it, because a file name cannot be checked and
`BIO_f_buffer` can.

`SMIME_text` stays deferred, and for a reason that is now written down rather than
implied: it reads through `mime_parse_hdr`, `mime_hdr_find` and `mime_hdr_free`,
which are `asn_mime.c`'s MIME header reader and land with `SMIME_read_ASN1_ex`.
`SMIME_read_ASN1`, `SMIME_read_ASN1_ex`, `SMIME_write_ASN1` and `SMIME_write_ASN1_ex`
stay for the reason that *is* a dependency: the base64 filter `BIO_f_base64` is
Phase 4's deferral to Phase 7, and `asn1_write_micalg` reads the `X509_ALGOR` set
that Phase 11 owns.

`PEM_write_bio_ASN1_stream` is the third `asn1.h` export in this file and it is
separately dispositioned. `B64_write_ASN1` wraps its sink in
`BIO_new(BIO_f_base64())`, so the export needs the EVP base64 codec and is handed to
Phase 7 with that named as the dependency.

The court also found the authority's own liveness defect. `i2d_ASN1_bio_stream`
unwinds with `do { tbio = BIO_pop(bio); BIO_free(bio); bio = tbio; } while (bio !=
out);`, and an item whose `ASN1_OP_STREAM_PRE` answers a BIO that is not in the chain
back to `out` makes `bio` settle at NULL and the loop spin forever. The first version
of the probe did exactly that and the authority run had to be killed by the harness
timeout — which is how the defect was found rather than argued about. The candidate
stops at NULL and the divergence is recorded as `D-MIME-1`: an unbounded loop is a
fault, not behaviour to reproduce. The probe's item now answers `sarg->out`, which is
what `BIO_new_NDEF`'s contract invites, and the two sides agree byte for byte.

Phase-5 open obligations: 29 -> 27, all of them `pem.h`'s.
libcrypto implemented exports: 928 -> 930.

Divergence: D-MIME-1.

## D93 — Phase 5 closes, and the last two exports are the ones with no dependency

`PEM_proc_type` and `PEM_dek_info` are implemented in `src/pem/pem_lib.rs` and
observed by `RT-PEM` (37 observations, no residual). They are the only two exports of
`crypto/pem/pem_lib.c` that need nothing beyond `BIO_snprintf`, which is why they are
the ones this stratum can hold, and the court was written to reach the parts of them
that a hand-written expectation would not: the appended cursor (each *appends* at
`buf + strlen(buf)`), the `BAD-TYPE` fallback for every value including
`PEM_TYPE_CLEAR` which has no arm of its own, the `0xff &` mask that keeps a negative
`char` two digits wide, and the newline which is written only while more than one byte
of room remains.

The other 25 are handed on, and the reason each carries is a *dependency*: 26 of this
stratum's 91 hand-offs wait on `EVP_ENCODE_CTX` or another EVP codec, 31 on `RAND`, 10
on `X509`, 7 on `asn_mime.c`'s MIME reader and writer, and 1 on `OSSL_LIB_CTX`. That
the PEM reader and writer are an `EVP_ENCODE_CTX` pair is the fact that decides the
whole subphase, and it is visible in the source rather than inferred: `PEM_write_bio`
allocates one on its second line and `PEM_read_bio_ex` on its twelfth.

`open_in_this_stratum` is now zero, `forensics/phase-state.json` reads phase 5
`complete`, and the seal was rewritten from the ledgers rather than from the previous
seal. The seal's FRF section is the one place this project has repeatedly gone stale,
and the mechanism is now explicit rather than a note: the identities are read back
from the store at the revision that writes them, the receipt table is generated from
`.frf/receipts` instead of transcribed, and the section says that every identity in it
moves with the store generation. The store was recreated from clean and the whole
chain re-run after the last commit of the stratum, so the 301 objects, 36 receipts and
9 phase-5 court receipts quoted there are the ones on disk.

Two things are worth carrying into Phase 6. The first is that this stratum's most
expensive defects were not arithmetic: they were a constant recalled instead of read
(D86), an authority conditional rewritten into something tidier (D89), and a
function-scope local translated into Rust with a narrower scope (D90). All three are
reading failures, and only the third needed a court to find. The second is that the
ownership model has now paid for itself twice — once when `a2d_ASN1_OBJECT` and the
`crypto/o_str.c` exports were invisible to every prefix list (D49, D51), and once when
`SMIME_crlf_copy` was handed to a later phase on the strength of the file it lives in
(D92). Both were found by a rule that is checkable rather than by reading harder.

Phase-5 open obligations: 27 -> 0. libcrypto implemented exports: 930 -> 932.
Divergence: D-PEM-1.

## D94 — the court runner list was a registry nobody owned

CI's authority-court job is described in its own comments as re-running "every court
from scratch". It re-ran three of the four strata that had courts, because the
workflow named them:

    Phase 2 shell and 11 ABI courts   -> build_phase2.sh
    Phase 3 runtime courts            -> phase3_courts.py
    Phase 4 BIO court                 -> phase4_courts.py

`forensics/tools/phase5_courts.py` existed on disk and was never called. Nine courts
— `RT-BN`, `RT-ASN1`, `RT-ASN1-TEMPLATE`, `RT-ASN1-TIME`, `RT-ASN1-STR`,
`RT-ASN1-PRINT`, `RT-BIO-ASN1`, `RT-ASN1-MIME` and `RT-PEM` — were therefore never
reproduced by CI, and `artifacts/phase5/COURTS.json` was read as evidence by the
regression guard instead. The job was green throughout, and its greenness said
nothing whatever about the stratum that was being implemented.

This is the same defect as D49, D51 and D92 seen from a different angle. Those were
about a *symbol* being classified by a name instead of by a declaration; this is
about a *court* being enumerated by hand instead of by a registry. In each case the
mechanism is a second list that has to be remembered, and in each case the reason it
is dangerous is that nothing fails when it goes stale.

So the fix is not "add a Phase 5 step". It is `forensics/tools/run_courts.py`, which
derives the list from `forensics/phase-state.json` — the same derived registry
`forensics/STATUS.md` is rendered from — finds each runner by convention (the shell
builder if the phase has one, because it also produces the artefact the later courts
link against; otherwise `phase<N>_courts.py`), and *fails* when a phase that is not
`not-started` has no runner and is not exempted in `COURTLESS` with a reason. The
check is two-directional: a `phase<N>_courts.py` whose phase is `not-started` is
reported too. Phase 6 cannot repeat this mistake; it will either be run or be a
loud failure.

Two further properties were needed to make the rerun actually mean something, and
both came out of asking what a green job would be able to claim:

  * the committed `COURTS.json` is **deleted before regenerating**, so a file that is
    present but not reproduced cannot be read as evidence by whatever runs next;
  * the regenerated file's **verdicts must equal** the committed file's, in either
    direction. A committed file that claims a pass the run does not reproduce is the
    trust problem; one that claims a failure the run does not reproduce is a record
    nobody regenerated. An observation-count *increase* is allowed and reported,
    because recording more is what a commit is for, and shrinkage is the regression
    guard's business.

Both were verified rather than asserted. `run_courts.py` in the court reports "4
phase(s) re-derived from the authority" and regenerates
`artifacts/phase5/COURTS.json` byte-identical to the committed file. Tampering
RT-PEM's committed verdict to `fail` makes the run fail with `verdicts that moved:
['RT-PEM: fail -> pass']`. A stray `phase9_courts.py` fails with "phase 9 is
`not-started` but has a runner on disk", and a `phase 6` temporarily marked
`in-progress` fails with "phase 6 (in-progress) is `not-started` and has no runner".
And in CI, against an authority rebuilt from scratch, the run reports all four phases
re-derived with `RT-BN` at 650 observations and `RT-PEM` at 37 — which is the
observation that would have been absent before.

Two smaller things fell out of the same reading. `gen_frf_courts.py` carried
`CANDIDATE_VERSION = "0.0.7"` as a literal with the comment "one place, so a release
bumps every court rather than the ones somebody remembered" — one place is right, a
second place relative to `Cargo.toml` is not, and nothing held them together, so the
32 declarations would have gone on naming a version the crate no longer was. It now
reads `[package] version`. And a version bump was assumed to force a full FRF store
regeneration; it does not. `frf court run` on a runtime court reports the run already
exists and verifies, and `receipt emit` reports an identical evidence state, because
a run identity is content-addressed over the *captures* — the transcripts of the
candidate binary and the fixture — while `version_or_commit` is provenance metadata
in the declaration. What moves the store is a change to the candidate's *behaviour*,
which is the right sensitivity for it to have.

`docs/CI.md` and the workflow's job name were updated with the change, and
`.gitignore` gained `.*.tmp`: `git add -A` swept a commit-message scratch file into
the D94 commit itself, which is the accident the `.rs` splice-file rule already
records one directory down, so the shape is excluded rather than the name.

## D95 — the DSO surface belonged to a phase whose definition was structural

`forensics/tools/ownership_rules.py` assigned the fifteen ABI-only `DSO_*` exports to
Phase 2, on the reasoning that the dynamic-loader abstraction is what Phase 2's
distribution contract is about. Phase 2 does not have a semantic obligation ledger
and its seal does not mention `DSO` at all: it closed on the distribution seal, the
build machinery and the eleven ABI courts. So the global ownership model — the one
D93 and the review that prompted it were built on — was asserting that Phase 2 owned
semantic exports, while Phase 2's own definition said it had closed on structure.
Neither statement was false about work that had been done, and that is exactly what
made it worth correcting rather than explaining: a model whose purpose is to make
ownership checkable cannot contain a claim that its own other half contradicts.

They move to Phase 6, the earliest semantic stratum that needs them. Provider and
module loading is where the dynamic loader stops being a description and starts being
operational, and `DSO_load` is what an engine and a provider module are both loaded
through. Phase 2 is unchanged and needs no reopening. `by_phase[6]` moves 112 → 127,
and the atlas invariants hold: `unknown = 0`, `multiply_owned = 0`,
`unassigned_headers = 0`.

## D96 — the prototype gap for macro-generated exports, recorded rather than half-built

`prototype_court.py` checks every implemented export's Rust declaration against the
authority's recorded prototype, and reports three classes it cannot judge: 162
`declaration_is_generated` (the symbol appears in `src/**/*.rs` but its signature is
produced by a `macro_rules!`, so the source parser cannot read it), 8
`implementation_is_c`, and 3 with no prototype in the atlas. The 162 are
disproportionately ASN.1: the `d2i_*`/`i2d_*`/`*_it`/`*_new`/`*_free` families are
macro-generated in this crate for exactly the reason they are macro-generated in the
authority, so the gap grows with the stratum that is being worked on.

The way to close it is a generated compile-time assertion per symbol, sourced from the
Clang prototype atlas, which type-checks the *item* rather than its source text:

    const _: unsafe extern "C" fn(...) -> ... = <the item>;

The obstacle is that this needs the item's Rust *path*, which is what the parser
cannot produce. Two ways out were considered and neither is small:

  * generate a module that glob-imports every crate module (`use crate::asn1::typ::*;`
    …) and asserts each export by its **bare** name. Name resolution replaces the path,
    so the generator needs no knowledge of the macro; the cost is a generated file that
    glob-imports the whole crate, and a compile-error iteration cycle to settle
    ambiguities in a crate with 932 exports;
  * feed the existing parser macro-*expanded* source via `cargo rustc --
    -Zunpretty=expanded`, which keeps one parser and one canonical form, at the cost of
    a nightly toolchain in the court image, against a crate pinned to a release
    toolchain by `rust-version`.

Both are real work and both were judged too likely to leave the tree red within the
budget of the change that found them, so nothing was attempted: a half-built assertion
mechanism is worse than a measured gap, because the gap is reported by the tool and
would be reported by nothing once a broken mechanism stopped compiling. The gap stays
at 162, `prototype_court.py` keeps reporting it under its own heading and counting it
as neither a pass nor a failure, and this entry is the durable record of the design
and of why it was not done here. It is the next thing to do in the ASN.1 line.

The review that found this also suggested turning generator *sequencing* into an
explicit dependency graph, or running generation to a fixed point and requiring the
second pass to produce nothing. The specific instance is fixed — `run_courts.py` now
owns the court ordering that used to be a property of the workflow's step list — but
the general mechanism is not built, and for the same reason: it is a change to how
every generator is invoked, and it should not be bolted on at the end of a change
about something else.

## D97 — the atlas was reconciled in one direction, and the ledgers were wrong in the other

D72 built `forensics/atlas/symbol-ownership.json` and made each phase ledger a
*projection* of it, which fixed the defect class D49, D51 and D52 had each recorded in
a different guise: a symbol matching no prefix was invisible to every ledger at once.
Phase 5 was rewritten to project, and `ownership_audit.py` gained the invariant that
an export the atlas assigns a stratum where that stratum's ledger has no row is an
error.

That invariant was written for Phase 5 and **not applied to the strata that had
already sealed**. Phases 3 and 4 still chose their own universes with
`(module, prefixes)` family lists, and they failed closed *within* those lists — which
is not the same thing at all. A prefix that matches nothing reports nothing, so sixty-
nine Phase 3 exports and nineteen Phase 4 exports that the atlas assigns them were in
no ledger, in no evidence list and in no audit, while both seals called their strata
complete.

The Phase 3 sixty-nine were not obscure: every `ASYNC_*` (22), every
`OSSL_ERR_STATE_*` (5), every `OSSL_trace_*` (10), `OSSL_get_max_threads`,
`OSSL_set_max_threads`, `OSSL_get_thread_support_flags`, `OSSL_sleep`, `OPENSSL_atexit`,
`OPENSSL_die`, `OPENSSL_fork_prepare`/`_parent`/`_child`, `OPENSSL_isservice`,
`OPENSSL_issetugid`, `OPENSSL_thread_stop`, `OPENSSL_thread_stop_ex`,
`err_free_strings_int`, the five `OPENSSL_INIT_*` handle constructors, and
`OPENSSL_gmtime` with its two neighbours. The Phase 4 nineteen were the fourteen
`COMP_*` functions, the three ABI-only `conf_ssl_*` helpers, `OPENSSL_config` and
`OPENSSL_load_builtin_modules`.

Three of those classes had a second cause worth naming, because each is a different
way for a list to be wrong:

  * `src/runtime/time.rs` **was in neither list**. It is implemented
    (`OPENSSL_gmtime`, `OPENSSL_gmtime_adj`, `OPENSSL_gmtime_diff`), it lives in the
    Phase 3 directory, and its own module comment says it is Phase 3's — but it was in
    no `FAMILIES` entry and no `PHASE3_MODULES` entry, so three implemented exports
    belonged to no ledger and to no evidence set simultaneously. An implementation can
    be invisible in exactly the same way an obligation can.
  * a **case difference** hid ten exports. Phase 3's families listed
    `OPENSSL_init` and `OpenSSL_version`; the authority exports `OPENSSL_INIT_new` and
    `OPENSSL_version_major`. Prefix matching is case-sensitive, so `OPENSSL_INIT_*` and
    the five `OPENSSL_version_*` accessors matched nothing.
  * the ledger was **over-claiming** as well as under-claiming. Phase 4's list matched
    every `BIO_` name, so it carried nine deferral rows — `BIO_f_base64`, `BIO_f_md`,
    `BIO_f_cipher`, `BIO_f_reliable`, `BIO_set_cipher`, `BIO_new_CMS`, `BIO_new_PKCS7`,
    `BIO_f_asn1`, `BIO_new_NDEF` — for symbols declared in `evp.h`, `cms.h`, `pkcs7.h`
    and `asn1.h`. The atlas never gave Phase 4 any of them.

The audit was wrong in the same direction. `ownership_audit.py` read a ledger's row set
as `implemented | open` and **ignored `deferred`**, so Phase 5's 91 deferred rows read
as a 91-symbol ownership gap that did not exist. Reading a field that is absent as if
it were empty, and not reading a field that is there, are the same defect: an absence
of evidence resembling a satisfied plane.

### What changed

  * `ownership_audit.py` was rewritten. It now reads `implemented | open | deferred`,
    and enforces **both** directions, as hard failures: every export the atlas assigns
    a stratum must have a row in that stratum's ledger, and every row a ledger carries
    for another stratum's export must be a hand-off that stratum recorded. It also
    checks each ledger's own arithmetic (every row in exactly one list, and the three
    summing to `owned`), the cross-ledger `implemented` double-count, and the hand-off
    edges in both readings — the deferring stratum's `deferred` rows against the
    receiving stratum's `handoffs_discharged`.
  * `phase3_obligations.py` and `phase4_obligations.py` were rewritten as atlas
    projections, in the shape Phase 5 already had. The prefix tables survive only as
    *labels* naming the module expected to hold a symbol, and an unlabelled symbol is
    now a hard failure rather than a row filed under "other".
  * `ownership_rules.py` gained `SYMBOL_PHASE`, the third and last name-level
    exception, because `crypto.h` genuinely declares two strata: `OSSL_LIB_CTX_new`
    sits nine lines from `CRYPTO_malloc`, and nothing in the header separates them. The
    ten `OSSL_LIB_CTX_*` exports move to Phase 6, whose subject matter the library
    context is. The atlas now records a `symbol-override` rule with the reason, and
    `by_phase` moves from `{3: 304, 6: 127}` to `{3: 294, 6: 137}`.
  * `phase_state.py` now derives Phase 3's state from its ledger's `open` count, as it
    already did for Phases 4 and 5. Before this, adding honest `open` rows to Phase 3's
    ledger would not have moved its state at all.
  * `regression_guard.py` gained `phase_state_transitions`, because a state *downgrade*
    is a regression by default — and must stay one. A correction that lowers a derived
    state is now the same shape as an ownership transition: a row in
    `forensics/ownership-transitions.json` matching the phase and both states exactly,
    naming the decision and the artifact that is the authority for the new state.
  * `docs/SEAL-CENSUS.md` is new, and is generated by
    `forensics/tools/render_seal_census.py`. Seals were restating their arithmetic in
    prose, and the prose did not regenerate: the Phase 5 seal's census once disagreed
    with the generated status and with another section of itself. The arithmetic now
    lives in one generated document that the seals cite. Phase 3's and Phase 4's seals,
    and Phase 5's, gained appended correction sections rather than edits — the
    append-only rule applies to seals as much as to this file.
  * `render_status.py` now **discovers** the ledgers instead of naming Phases 3 and 4.
    Phase 5's ledger had never been rendered in `STATUS.md` at all, and no reader could
    tell whether that was a decision. `evidence_determinism.py` discovers the phase
    generators the same way, so a new stratum no longer has to be remembered in four
    registries.

### What was deliberately not done

The sixty-nine and nineteen are **not** deferred to make the states green again. Two
dispositions were refused for that reason:

  * `OSSL_LIB_CTX_*` are not "deferred to Phase 6"; they are **Phase 6's**, and moving
    them in the atlas is the correct statement rather than a deferral a reader would
    have to trust.
  * the twenty-nine open Phase 3 exports are not handed to a later stratum in a lump.
    They are recorded `open`, they block the stratum, and `docs/PHASE-6-SUBPHASES.md`
    6.2 names them as work. `OSSL_trace_*` and `OSSL_ERR_STATE_*` are core-runtime
    facilities with no later stratum to defer to; inventing one would be the same
    defect one level up.

`ASYNC_*` **is** deferred, to Phase 13, and the reason is a dependency rather than a
distance: `OPENSSL_NO_ASYNC` is not defined in the pinned profile, and the authority's
own tree shows every in-tree caller is either an asynchronous engine
(`engines/e_dasync.c`, `engines/e_afalg.c`) or the SSL async API (`ssl/ssl_lib.c`).
Phase 13 is the earliest stratum whose own obligations require the job framework.

Phases 3, 4 and 5 are `in-progress`, Phase 6 has its own ledger at 156 open exports,
and `implemented` is unchanged at 932: not one implementation was removed and not one
observation was invalidated. This is a correction to a completeness claim, which is
the cheapest kind of correction there is — and the only reason it was cheap is that
the evidence and the accounting were kept apart.

## D98 — the prototype gap was three instrument gaps, and every implemented export is now judged

D96 recorded a measured gap rather than building a mechanism for it: 162 exports whose
Rust declaration `prototype_court.py` could not read because it was produced by a
`macro_rules!`, 8 implemented in C, and 3 with no prototype in the atlas. Two designs
were considered and rejected as too large for the change that found them — a generated
module of compile-time `const _: fn(...) = item;` assertions, and macro-*
expanded*source from `cargo rustc -Zunpretty=expanded`, which needs a nightly
toolchain against a crate pinned to a release one.

The third option is the one that was taken, and it is smaller than either: **read the
macro, not its expansion.** The crate cannot build a `#[no_mangle]` symbol name from
another token, so every macro that exports a symbol writes both identifiers at every
use and its *body* holds a literal signature with `$param` where the name goes. The
signature was always readable; only the substitution was missing.
`macro_defs` parses a `macro_rules!` declared parameter list and the literal signature
inside its body, `expand_macro_invocations` substitutes each invocation's arguments
positionally, and the result goes through the same `rust_signature_canon` /
`c_signature_canon` pair as every other declaration. One parser, one canonical form,
one comparison policy — the property D96's rejected designs would each have broken in
a different way.

It is robust in the direction that matters because it refuses rather than guesses. A
macro whose body puts a `$param` in a *type* position is reported as unreadable instead
of being read as `opaque` (which would make every such symbol compare equal to
something); a repetition that is not the last matcher element is reported rather than
having its extent assumed; a macro with no `fn $param(` in its body (`bail!`, the
`conf/def.rs` helper) is skipped without needing to understand arbitrary macro syntax.

Reading the sources to build that mechanism then found that **two of the three gap
classes were the instrument, not the code**:

  * `DECL_RE` required `pub` and did not match `pub(crate)`. `src/runtime/err_loaders.rs`
    declares all twenty-six `ERR_load_<LIB>_strings` entry points as
    `pub(crate) extern "C" fn` with `#[no_mangle]` — the symbol must be exported while
    the Rust item stays crate-private — so twenty-six *plainly written* declarations
    were reported as "the symbol appears in src but not as a declaration this court can
    parse". One alternation.
  * `c_signature_canon` built the authority's parameter list from the atlas's `params`
    array, which records Clang's `ParmVarDecl`s and therefore **omits the varargs**:
    `int (BIO *, const char *, ...)` has two entries. So the eight C implementations
    compared a three-parameter definition against a two-parameter prototype and failed.
    The authority's own `type` string carries the `...`, and the record carries
    `variadic: true`; the canonical form now appends it. A third bug in the same code
    path read the definition's return type by removing its *prefix* where the name is a
    *suffix*, which is why all eight reported `opaque`.

That is the sixth time in this stratum's line of work that the instrument was the first
suspect, and the second time in this court alone. The pattern is worth naming: a
measurement mechanism is written once against a shape the author has in mind, and every
input that does not have that shape is silently miscounted rather than reported. The
fix each time is the same — make the tool refuse when it cannot read, and add a control
that proves it can read the defect it claims to cover.

So the court gained a **sensitivity block**: three controls over deliberately defective
synthetic inputs, parsed by the same functions as the real pass, each asserting both
that the defective input is detected and that the corrected one is not, and each
`all_detected` a failure condition. The first draft of the macro control was itself
wrong — it asserted an empty parameter list where the parser correctly returns the
parameters *with their names*, as the crate writes them — which is a fair illustration
of why a control that asserts only "a mismatch was found" would have been worthless.

Result, and it is the whole point of the change: of 932 implemented `libcrypto`
exports, **921 are checked as Rust declarations, 8 as C definitions, 0 are unreadable,
0 are ungenerated, 0 are not found, and every one of the 929 has zero mismatches on
both the class/arity plane and the full canonical type plane**. The remaining 3 are
documented as unjudgeable by *this* court for a reason that is not a gap in it:
`OPENSSL_DIR_read`, `OPENSSL_DIR_end` and `asn1_d2i_read_bio` are declared in
`crypto/o_dir.h` and `crypto/asn1/asn1_local.h`, which the authority does not install,
so the Phase 1 atlas has no prototype for them. The Phase 2 loader court still proves
their ABI, resolving each at its declared ELF version.

`declaration_is_generated` is now a **defect** rather than a gap, and the court fails
on it along with `not_found`, `unreadable_macros`, the C-plane mismatches and a
sensitivity control that does not fire.

## D99 — the 29 reopened obligations, 24 implemented and 5 handed on with a real dependency

D97 left Phase 3's ledger with twenty-nine `open` exports. This is what happened to
them, and the split is the interesting part: **five are not Phase 3's** once you read
past the declaring header, and each of the five names a dependency that can be checked
rather than an amount of work that cannot.

**Twenty-four implemented** (`docs/PHASE-6-SUBPHASES.md` 6.2), in three new modules
whose existence is itself the finding that Phase 3's prefix lists had hidden:

  * `src/runtime/trace.rs` — the ten `OSSL_trace_*` exports. The pinned profile is
    configured `no-trace`, so eight answer a constant; but the two category
    interrogators and `OSSL_trace_string` are outside every `#ifndef` and are fully
    live. `OSSL_TRACE_CATEGORY_NUM` is 21 and the name table is order-dependent, and
    `OSSL_trace_string` is where the interesting behaviour is: `full == 0` with
    `size > 80` writes a `[len N limited to 80]: ` prefix, `text == 0` masks control
    characters while preserving newlines and appends one if the input lacked it, and
    the output goes through `%.*s`, so an embedded NUL does not truncate it.
  * `src/runtime/err_state.rs` — the five `OSSL_ERR_STATE_*` exports, split out of
    `err.rs` the way `err_save.c` is split out of `err.c`, because they move whole
    state structures and transfer ownership of the attached data buffers.
  * `src/runtime/uid.rs` — `OPENSSL_isservice` and `OPENSSL_issetugid`. Both are
    platform predicates whose answer is decided entirely by which `#if` arm is
    selected, and `uid.c` has five. This profile takes the glibc one,
    `getauxval(AT_SECURE) != 0`; the `getuid() != geteuid()` fallback beside it is
    deliberately **not** transcribed, because a literal written from the source would
    be an unmeasured claim about a libc this crate has not observed, and the two
    disagree for a process that was merely given a group it did not ask for.

plus `OPENSSL_die`, the three `OPENSSL_fork_*` hooks (empty bodies on this profile,
which is the authority's own body), `err_free_strings_int` (the authority's body is
the comment `/* obsolete */`), `OSSL_get_thread_support_flags` (a compile-time
constant, `3` here) and `OSSL_sleep`.

**Five deferred, with the dependency named.** `OSSL_get_max_threads` and
`OSSL_set_max_threads` read and write the thread-tracking ex-data slot of an
`OSSL_LIB_CTX`; `OPENSSL_thread_stop_ex` calls `ossl_lib_ctx_get_concrete`;
`OPENSSL_thread_stop` is the other half of a pair whose first half is a later
stratum's, and `OPENSSL_cleanup` runs the handler list that `OPENSSL_atexit` builds;
and `OPENSSL_atexit` itself pins the handler's shared object with
`DSO_dsobyaddr`/`DSO_free`, a block the profile compiles in — `OPENSSL_USE_NODELETE`,
`OPENSSL_NO_PINSHARED` and `DSO_NONE` are all unset, which was measured in the court
rather than read off the configure line. Faking that pin would be a silent
behavioural substitution for a dependency that exists.

### The court found two real defects, and both were mine

`RT-RUNTIME-EXT` (94 observations) is the differential court for the
twenty-four, and the first run failed on two things that no amount of re-reading had
caught:

  * **`OSSL_ERR_STATE_save` released nothing.** The authority memsets the thread's
    state after copying it into the destination, so the ownership of the attached
    data buffers **moves**. The implementation called `clear_all(false)` — the
    authority's own *comment* says "just clear the thread state" — and that function's
    documented behaviour for an owned buffer is to keep the pointer and truncate it in
    place. So both states owned the same buffers, and a state reused across an
    `ERR_clear_error` double-freed. `ErrState::zeroed` exists because the code is what
    a caller observes and the comment is not.
  * **`ossl_iscntrl` was wrong above 0x7f.** `ossl_ctype_check` is
    `a >= 0 && a < max && (map[a] & mask) != 0` with `max == 128`, so a byte at or
    above 128 is **not** a control character. The first version assumed a
    `CTYPE_MASK_ascii` fallback and masked those bytes into spaces; the probe passes
    `0x80` through `OSSL_trace_string`, where the authority passes it through
    unchanged.

Neither was reachable by inspection and neither would have been found by the unit
tests, which is the same lesson D65, D76, D90 and D98 each record from a different
angle. The first is worth naming precisely because the *docstring* of the function
being misused described the correct behaviour, and the code that used it read
plausibly.

Phase 3's ledger is at zero open again and `forensics/phase-state.json` derives it
`complete`; its seal gains an appended §11 rather than an edit. `implemented` for
`libcrypto` moves 932 → 956 and `libcrypto`'s scaffolds fall to 4,940.

## D100 — `OPENSSL_info` answers NULL for the build-dependent codes, and that was unrecorded

Found by `RT-COMP`, whose subject is the eighteen exports 6.3 implemented and which
reaches `OPENSSL_info` only because `OPENSSL_config` is one of them and
`crypto/conf/conf_sap.c`'s loader is what the probe touches next.

`crypto/info.c` is a translation unit of its own, and `OPENSSL_info` splits its codes
into two kinds. The **build-independent** ones are compile-time platform facts —
`OPENSSL_INFO_DSO_EXTENSION` (`.so`), `OPENSSL_INFO_DIR_FILENAME_SEPARATOR` (`/`),
`OPENSSL_INFO_LIST_SEPARATOR` (`:`) — and both sides agree on all three; `RT-COMP`
now compares them. The **build-dependent** ones answer the authority's own
`--openssldir`, `--enginesdir` and `--modulesdir`, which are paths inside the
forensic build tree that no shipped library should reproduce.

`src/runtime/init.rs` answers NULL for the build-dependent codes. That is the *same*
divergence Phase 4's seal already records for `CONF_get1_default_config_file` under
`OBL-CONF-DEFAULT-CONFIG-FILE` (Phase 16) — the same underlying fact, reached by a
second route — and the reason it is worth a decision entry rather than a probe
comment is that **nothing had recorded that the second route existed**. `RT-CONF`
recorded one accessor; `OPENSSL_info` is a public entry point into the same fact, and
a consumer that asks it gets NULL instead of a path.

`RT-COMP` now prints the `RECORDED_DIVERGENCE_OBL_CONF_DEFAULT_CONFIG_FILE` label for
all three build-dependent codes, on both sides, which is the idiom `RT-CONF` and
`RT-LHASH` already use for a boundary they cannot compare. The divergence stays open
with Phase 16, and it is now recorded at two entry points rather than one.

This is the third time in two subphases that adding a court to a surface produced a
finding about a *different* surface: `RT-RUNTIME-EXT` found the `OSSL_ERR_STATE_save`
ownership defect (D99), and `RT-COMP` found this. Both were in code that had already
passed its own stratum's ledger arithmetic, which is the argument for courts over
ledgers rather than an argument against ledgers.



## D101 — `crypto/params.c` spells its refusals as macros, and the raise-site generator could not see a call site

Adding Phase 6's four parameter translation units to
`gen_err_raise_sites.py`'s covered set produced a number that could not be right:
`crypto/params.c` is 1,723 lines with forty-odd refusals in it, and the scanner
found none of them.

It found the *definitions*. `params.c` opens with

```c
#define err_out_of_range      \
    ERR_raise(ERR_LIB_CRYPTO, \
        CRYPTO_R_PARAM_VALUE_TOO_LARGE_FOR_DESTINATION)
```

and then invokes the macro bare — `err_out_of_range;` — at every site. The scanner
matches `ERR_raise`, `ERR_raise_data` and `<LIB>err`, so it matched the eight
definitions and none of the invocations. The eight definitions were worse than
useless as output: `ERR_raise_data` expands `OPENSSL_FILE`/`OPENSSL_LINE`/
`OPENSSL_FUNC` at the point of *expansion*, so the coordinates a caller reads back
through `ERR_get_error_all` are the invocation line and the enclosing function, and
the definition would have recorded `crypto/params.c:26` attributed to whatever
ename happened to precede the `#define`. `enclosing_function` refuses a line with no
preceding definition, so in fact the generator did not produce that answer; it
produced no answer, and the file looked as though it raised nothing at all.

The fix is in two parts, and the second is the one that needed care.

`local_raise_macros` reads the file's own `#define`s, joins backslash
continuations, parses the raise call out of the body and records the `lib`/`reason`
pair under the macro's name. The main scan then attributes each bare invocation to
the invocation's line and enclosing function. That is the whole mechanism.

The part that needed care is that the *definition's own body* is a line containing
`ERR_raise(` that does not start with `#`. The scanner's existing guard — "a raise
behind a preprocessor definition is a macro body, not a call" — skipped only the
`#define` line itself, so the continuation lines became candidates with no enclosing
function, which is an `SystemExit` rather than a wrong site. `local_raise_macros`
therefore also returns **every line the preprocessor owns**, each directive
together with its backslash continuations, and the main scan skips that set. That is
stronger than the original guard and it is what makes the macro plane safe to add at
all.

`via_macro` is written to the atlas **only** when a site came through a macro, and
the body carries a `via_macro_note` saying so. The first attempt wrote
`"via_macro": null` on all 632 existing sites, which turned a pure addition into a
632-record rewrite: the evidence diff said every previously recorded coordinate had
changed, when none had. Evidence diffs are read by humans under time pressure, and
"every record changed" is the worst possible false signal. The field is now absent
rather than null, and the check is part of the review: adding the four files changed
`added 135, removed 0, changed 0`.

Only 4 of the 135 are in `param_build.c`'s *definition* functions; the rest are the
invocations `params.c` had been hiding. `RT-PARAM` is what makes them evidence
rather than a table.

## D102 — the allocation family's default branch, which every existing court had stepped over

`src/runtime/mem.rs` documented three behaviours as *measured*, and one of them was
measured in the wrong branch of a dispatch.

`CRYPTO_malloc` is two functions wearing one name:

```c
if (malloc_impl != CRYPTO_malloc) {          /* a caller installed one */
    ptr = malloc_impl(num, file, line);
    if (ptr != NULL || num == 0) return ptr;
    goto err;
}
if (ossl_unlikely(num == 0)) return NULL;    /* <-- no error raised */
...
ptr = malloc(num);
if (ossl_likely(ptr != NULL)) return ptr;
err: ossl_report_alloc_err(file, line); return NULL;
```

`RT-MEM` measures the allocation family, and **every one of its size observations is
taken after it has installed its counting allocator**, because the counts are how it
observes the free/realloc asymmetry. Installing an allocator is not a neutral act:
it selects the first branch. So `RT-MEM` measured the installed branch on both sides,
agreed, and the file recorded that agreement as the authority's answer, in a doc
comment that read "matching the authority". The default branch — the one a consumer
who never calls `CRYPTO_set_mem_functions` is in, which is every consumer that does
not embed — was measured by nothing.

A new court, `RT-MEM-DEFAULT`, never installs anything. Its first run produced
**thirteen** divergences, all the same shape: the authority answers NULL to a
zero-length request and the candidate answered a live allocation. `malloc(0)`,
`zalloc(0)`, `calloc(0,16)`, `calloc(16,0)`, `malloc_array(0,4)`,
`malloc_array(4,0)`, `realloc(NULL,0)`, `realloc_array(NULL,0,4)`,
`clear_realloc(NULL,0,0)`, `clear_realloc_array(NULL,0,4,0)`, and the four
secure-heap forms, which reach the same place because `CRYPTO_secure_malloc`
forwards to `CRYPTO_malloc` while the heap is uninitialised. No error is raised on
any of them, so the return value is the only witness, and it was wrong in thirteen
places at once.

The same branch holds two more defects, and they needed instruments that did not
exist.

**A leak that a NULL return value hides.** The default branch of `CRYPTO_realloc`
is
```c
if (num == 0) {
    CRYPTO_free(str, file, line);
    return NULL;
}
```
and the crate returned NULL without releasing. `RT-MEM` could not see it for the
same reason it could not see the zero-length arms — under an installed allocator the
authority delegates the decision to the caller's `realloc_fn`, so the *authority*
does not free there either, and both sides agreed. The new probe interposes the four
libc allocator entry points and reports the **change** in the number of `free` calls
across the single operation, with a control (`CRYPTO_free`) that certainly releases
and a sibling (`CRYPTO_clear_realloc`) that already agreed. Forwarding goes to
glibc's `__libc_*` rather than through `dlsym(RTLD_NEXT, ...)`, because `dlsym`
itself allocates and would recurse before the real symbols are resolved. The
observation is a *delta*, not a total: the crate's own runtime allocations are not
part of it, and `phase3_courts.py`'s rule that internal allocation counts are not
diffed is unaffected.

**A crash.** `CRYPTO_memdup` refuses `siz >= INT_MAX` before allocating. The crate
omitted the check, so `RT-MEM-DEFAULT`'s `CRYPTO_memdup(buf, INT_MAX)` — a request
to copy two gigabytes out of a 32-byte buffer — returned a live pointer in the
candidate and read out of bounds; the candidate segfaulted, and the truncated
transcript was the evidence. The authority's refusal is not an optimisation: `siz`
is an `int` at the allocator boundary.

Two further gaps in the *dispatch* are recorded by a second new court,
`RT-MEM-INSTALL`, which measures the installation state machine instead of any one
allocation. `CRYPTO_set_mem_functions` accepted only an all-or-nothing install and
answered 1 unconditionally, where the authority replaces each slot whose argument is
non-NULL, leaves the rest alone, and **refuses with 0** once `allow_customize` is
clear — which the default branch of `CRYPTO_malloc` clears on the first non-zero
request. And `CRYPTO_get_mem_functions` reported private shims where the authority
reports the address of its own exported `CRYPTO_malloc`, `CRYPTO_realloc` and
`CRYPTO_free`; a caller may compare the returned pointer against `&CRYPTO_malloc` or
hand it straight back, so the crate now stores that identity as "not installed" and
reports it back. The latch is the reason the two new courts are two: the branch a
process is in is chosen once and is permanent, so no single probe can measure both,
and `RT-MEM-DEFAULT` closes with the latch observation — the only order in which
the 0 is reachable — while `RT-MEM-INSTALL` measures the accepted order.

One constant was renamed. The `*_array` helpers' overflow constant was called
`ERR_R_OVERFLOW` in this file, and OpenSSL has no such symbol: the packed code they
raise is `CRYPTO_R_INTEGER_OVERFLOW`. The value 127 was right and the name was an
invention, which is D33's class — recalled rather than read — and the check is that
compiling `ERR_R_OVERFLOW` against the authority's own headers fails to compile.

The unit tests for the zero-length arms and for `CRYPTO_realloc(addr, 0)` were
removed rather than repaired. Both depend on which branch the process is in, the
branch is chosen once per process, and Rust's test harness runs every test in one
process; an assertion there would be a claim about test ordering rather than about
the contract. The two courts measure each branch in a process that chose it, which is
the division of labour `phase3_courts.py` already describes. The allocator
installation test was rewritten to assert *which* outcome it got and that the
outcome is self-consistent, instead of assuming the state it starts in — it had been
passing by accident, because the old model could not tell the two branches apart.

One more divergence was found while building the instrument and is a *recorded*
divergence rather than a fix: both `CRYPTO_aligned_alloc` and
`CRYPTO_aligned_alloc_array` write through `*freeptr` with no NULL test, so the
authority segfaults and the candidate answers NULL. The candidate's doc comment had
described NULL as an accepted argument, which is where the guard came from; the code
was right and the documentation was wrong. It is now
`docs/SECURITY_DIVERGENCE_POLICY.md` D-MEM-ALIGNED-1, and both cases print the
`NOT_MEASURED_AUTHORITY_FAULTS` marker in the new probe so the boundary is visible
in the transcript.

Two courts were added to Phase 3, its observation count moves 4,358 → 4,410, and
`src/runtime/mem.rs` gains the two-branch model. Nothing about the *installed*
branch changed, which is why `RT-MEM` still reproduces its 82 committed
observations byte for byte: the finding is entirely about the branch no probe had
entered.

## D103 — the 81 parameter exports, and two more instrument gaps the prototype court had

Phase 6.5 implements the parameter surface: the 56 exports of `crypto/params.c`, the
three of `crypto/params_dup.c`, the two of `crypto/params_from_text.c` and the twenty
of `crypto/param_build.c`, across `src/params/{mod,dup,from_text,build}.rs`. The module
tree mirrors the authority's file boundaries, because those are what the ownership
atlas and the raise-site coordinates are keyed on.

Three things about this surface were worth writing down before the code, and each
turned out to matter:

* **`params.c` spells its eight refusals as file-local macros and invokes them bare.**
  D101 fixed the generator; this is the first stratum to *use* the fix, and the
  fifty-odd invocation coordinates are now carried as `err_sites::PARAMS_*`.
* **`return_size` is a state, not a length.** Every setter has an early `data == NULL`
  arm that records the size the caller would need and answers **success** — that is how
  a provider asks "how big is this?" without a buffer. A reimplementation that treated
  a NULL buffer as an error would break every size query in the library.
* **"Native order" is little-endian here, and the code never says so.** The integer
  buffers a parameter carries are in the host's byte order — the opposite of
  `ASN1_INTEGER` one stratum below — so `copy_integer`'s `IS_BIG_ENDIAN` branch is taken
  as the little-endian arm, and `is_negative` reads the last byte rather than the first.

Two behaviours were reproduced rather than tidied, because a court compares answers and
there is no way from outside to tell which internal path produced one:

* `OSSL_PARAM_get_int32` reads a four-byte `INTEGER` *directly* while the general path
  would reject the same bytes if their sign disagreed with the destination. Both paths
  are in the module, in the authority's order.
* `OSSL_PARAM_set_double`'s bounds are half-open — an unsigned destination accepts
  `0 <= v < 2^32` and a signed one `-2^31 <= v < 2^31` — so `2^31` is *rejected* for an
  `int32` destination, which is one off from a "fits in an int32" reading.

The internal helpers `params.c` defines for later strata — `ossl_param_get1_octet_string`,
`ossl_param_get1_octet_string_from_param`, `ossl_param_get1_concat_octet_string` and
`setbuf_fromparams` — are implemented although no Phase 6 export reaches them, since
they are part of the translation unit this module reconstructs. They carry an
`allow(dead_code)` with the reason, as `err_reasons.rs` does. `setbuf_fromparams` drives
`WPACKET` in the authority and `crypto/packet.c` is Phase 7's; it is reproduced as the
two operations actually used (refuse a non-`OCTET_STRING` element, refuse a copy that
does not fit), including `WPACKET_init_static_len`'s `len > 0` refusal by a direct test
rather than by an assertion. It is to be re-based on the real `WPACKET` when that
stratum lands, and that is a **residual**, not a claim.

Three smaller divergences are recorded rather than hidden. `prepare_from_text`'s
`switch` has no `default` in C, so an unhandled `data_type` leaves `buf_n` indeterminate;
every type the atlas's headers define is handled, and the unreachable arm answers 0
bytes rather than reading uninitialised memory. `param_build.c`'s `n < 0` arm cannot be
reached because `BN_num_bits` is never negative for a live `BIGNUM`, so the generated
site exists and is not called. `OSSL_PARAM_print_to_bio` dereferences a NULL array in
the authority and answers 0 here. And `OSSL_PARAM_merge`'s `qsort` is unspecified among
*equal* keys within one list, where this implementation is stable.

### Two more instrument gaps, and they were the same gap twice

The court reported `implemented=974 checked=... unclassified=15 unreadable=10`. Both
numbers were the instrument, not the code.

**`unclassified=15`: a struct returned by value.** `classify_c` does not follow
typedefs, so `OSSL_PARAM` — a typedef of `struct ossl_param_st` — has no class, and
`classify_c_return` answered `unclassified`. The class plane is a coarse filter (return
kind and arity) and the *type* plane canonicalises `opaque` on both sides correctly, so
the fix is not to teach `classify_c` about typedefs: it is that an `unclassified` symbol
`continue`d **before** the type plane, so those fifteen exports were checked by
**neither plane**. No export had ever returned a struct by value before, which is why
nothing had noticed. The symbol is now dropped only when the type plane cannot
canonicalise it either, and `unclassified` counts what genuinely could not be read by
either. That is the D96/`a2d_ASN1_OBJECT` class a fourth time: an obligation that
disappears between classification layers.

**`unreadable=10`: my own macro.** The twelve scalar pushes were written as one
`macro_rules!` so that the width and the `OSSL_PARAM_*` code could not drift apart. D98
established that the court refuses a macro body that puts a metavariable in a *type*
position — deliberately, because reading one would mean guessing what it expands to —
and this macro did exactly that. The ten functions are now written out literally. The
repetition is the price of being read, and it is the second time this phase has paid it.

After both fixes: `implemented=1054 checked=1023 mismatches=0 unclassified=0 generated=0
unreadable=0 not-found=0`, and `type plane: checked=1039 mismatches=0 unmapped=0`. The
difference between 1023 and 1039 is the C-definition and macro planes, which the type
plane covers separately.

### What is NOT claimed yet

`RT-PARAM` does not exist. By D73's rule a subphase closes only when its exports are
implemented **and** a differential court observes them *in the same commit*, so the
parameter surface is **implemented and uncourted**, `forensics/phase6-obligations.json`
moves from 161 open to 80 open (81 implemented), and 6.5 stays `IN PROGRESS`. The court is the next
commit, not this one, and this paragraph exists so that the ledger's arithmetic is not
mistaken for an exit criterion met.

## D104 — `RT-PARAM`, the first Phase 6 court, and the fit rule it found in Phase 5

Phase 6.5's parameter surface is 81 exports across four modules, and `RT-PARAM` is the
court that closes it. It is 1,161 observations on each side, zero residuals.

### The court is a matrix, because the surface is a data type

An `OSSL_PARAM` has no behaviour of its own: it is a descriptor whose answer is a
function of three independent axes a caller sets — the parameter's `data_type` (seven of
them), the width and signedness the *caller's* accessor uses (which need not match the
parameter's, and which for four types selects a fast path that is not the general
conversion path), and whether `data` is NULL (which turns a setter into a size query that
answers **success**).

So the probe is a matrix rather than a scenario list. Every accessor against every
source width, signedness and type; every setter against every destination shape,
recording the return code, the error queue, `return_size` and the bytes produced. The
reason is that the *refusals* are where a plausible implementation and the authority
differ, and the two refusals are not interchangeable: reading a negative
`UNSIGNED_INTEGER` and reading one that is merely too large are
`CRYPTO_R_PARAM_UNSIGNED_INTEGER_NEGATIVE_VALUE_UNSUPPORTED` and
`CRYPTO_R_PARAM_VALUE_TOO_LARGE_FOR_DESTINATION`, and a caller that exercises only the
happy path cannot tell the two implementations apart.

Three behaviours are reproduced rather than tidied, because the court compares answers
and there is no way from outside to tell which internal path produced one. `get_int32`
reads a four-byte `INTEGER` directly where the general path would reject the same bytes
if their sign disagreed with the destination. `set_double`'s bounds are half-open, so
`2^31` is *rejected* for an `int32` destination — one off from a "fits in an int32"
reading. And `OSSL_PARAM_print_to_bio` answers 0 for an **empty** array, because `ok`
starts at `-1` and the loop never runs.

### Three findings, and two of them were mine

The first run had 226 residuals and the candidate crashed at observation 939. Both
defects were in the crate, and both were the kind a unit test would not have found.

**`OSSL_PARAM_get_utf8_string` wrote its terminator through the wrong pointer.**
`**val.add(data_length) = 0` parses as `*(*(val.add(n)))`: pointer arithmetic on
`char **`, scaled by eight and dereferenced twice. The terminator belongs in the buffer
at index `data_length`. The observable was a segfault on the first call that reached it
with a caller-supplied `char **`.

**`set_double`'s exactness test used Rust's saturating cast where the authority uses the
platform's.** The authority's test is a round trip through a C cast — `val !=
(int64_t)val` — and a `double` outside `int64`'s range makes that cast undefined in C.
What the *comparison* observes is the conversion, which on x86-64 is `INT64_MIN` for
every out-of-range and NaN input. Rust's `as` saturates, so it reported such a value as
**exact** and fell through to the range check: a different error reason for a caller that
did nothing wrong. Reproduced as `to_i64_as_c`/`to_u64_as_c`, which specify the
conversion rather than the undefined behaviour, and document that the value is the one
the authority's own comparison compares against.

### The finding that belongs to another stratum

After those two, three residuals remained. Two were the probe's fault: the builder's
`_PTR` parameters hold a *pointer*, and `dump_params` printed the first `data_size` bytes
of that pointer — part of an address, differing between two runs of the same binary. It
prints the pointer's *target* now. The third was real.

`OSSL_PARAM_BLD_push_BN_pad` with a negative `BIGNUM` records `BN_num_bytes(bn)` bytes —
`sz` is ignored for a negative value, because the encoding must be exactly two's
complement — and `BN_signed_bn2native` **refuses** that width: it needs `n + ext`, with
`ext` 1 for a negative value whose magnitude does not fill its top byte. The authority's
buffer then held zeros only because a fresh mapping is zero-filled on first touch; that is
not a contract, and comparing it would have been comparing uninitialised memory. So the
probe records `NOT_COMPARABLE_AUTHORITY_UNINITIALISED` for that one parameter and keeps
the *push* result, which is deterministic.

The refusal itself is `bn.h`'s, and `bn.h` is **Phase 5's**. A sweep of nineteen values
against every `tolen` from 0 to 5 found **five** destinations the authority refuses and
this crate accepted — `-1` and `0x80` into one byte, `-0x0102` and `0xffff` into two, and
`0` into a zero-length destination, which was answered as a success. `signed_bytes` had
the fit rule as `BN_num_bytes(a) > tolen` and the authority's is `n + ext > tolen`.
Phase 5's seal gains §10 and `RT-BN` gains 860 observations; the stride is unchanged at
zero open, so the stratum stays `complete` and the section is a correction, not a
reopening. See D104's table in `docs/PHASE-5-BN-ASN1-PEM-SEAL.md`.

That is the third time a court has found a defect in a stratum other than the one it was
written for, and the first time the *input choice* was the whole of the gap: Phase 5's
court called these three functions with destinations that were obviously large enough,
which is exactly the case where the fit rule cannot be observed. A court's coverage is a
property of the inputs it chooses.

### Arithmetic

| | before | after |
|---|---|---|
| Phase 6 courts | 0 | 1 |
| Phase 6 observations | 0 | 1,161 |
| `RT-BN` observations | 650 | 1,510 |
| Phase 6 ledger | 81 implemented / 80 open | unchanged |
| all courts | 47 | 48 |
| all observations | 17,325 | 19,346 |

`forensics/tools/phase_state.py` gains a Phase 6 evidence registry, which is what makes
`run_courts.py` run this stratum's runner at all: the workflow derives the list of active
strata from `phase-state.json`, and Phase 6 was `not-started` there only because nothing
had told the registry about its modules. It is `in-progress` now, on its ledger's 80 open
obligations, and `run_courts.py` refuses to run a runner for a `not-started` phase — which
is the check that caught this.

---

## D105 — a probe read past its own buffer, and every probe is now held to a level-differential gate

**The observation that was wrong.** `courts/phase6/rt_param_probe.c` declared
`char buf[16]`, filled all sixteen bytes with `0xaa`, and handed the buffer to
`OSSL_PARAM_construct_utf8_string("k", buf, 0)`. A zero `bsize` with a non-NULL
buffer means "measure it", and the authority measures it with `strlen` — so the
terminator was left to whatever happened to follow the array on the stack. It was
reading past the array, and the court recorded the result:

| build of the *same* source | authority | candidate |
|---|---|---|
| the revision the capture `run-openssl-rs-rt-param-ccb0bc0e…` was taken from | 24 | 22 |
| the committed revision, `-O0` | 22 | 22 |
| the committed revision, `-O1`, `-O2`, `-O3` | 16 | 16 |

Those are three different answers from one probe. The residual
`a0eaeb5b2946497400a7b63f1d0d78efe4f90ae91ee24ef1e910c7ce19551a7` was therefore
**not a candidate divergence at all**: it was the optimizer's stack layout being
compared against itself. The `-O0` reading is what makes that unambiguous — the same
source, both sides, 22 — and the two sides differing at `-O1` while the *authority*
moves to 16 is only possible if at least one side is reading beyond its own object.

**Why it cost more than one line.** The probe was edited after the court had run, and
the FRF store was not recreated, so the store held transcripts from a probe source
that no longer existed. The visible symptom was `frf court challenge` refusing this
court's `stdout-first-line` mutant with

```
run 'run-openssl-rs-rt-param-…' already exists and verifies
(identical evidence was already captured); raw captures are immutable
```

which reads like an FRF limitation and is nothing of the kind: the mutant's run
identity is a function of the court's declared inputs, the store already held a run
for it, and re-capturing would have produced a *different* transcript. The rule this
stratum now applies is the one the README already states for a rebuilt candidate:

> a change to any probe source invalidates the whole store; `run_courts.sh` recreates
> it from clean, because a store that mixes revisions cannot be compared to itself.

**And it means D104's "three residuals remained" was two residuals.** The third was
this read. The decision D104 records — that `RT-PARAM` is the first Phase 6 court and
that the fit rule it found belongs to Phase 5 — is unaffected.

**Remedy, part one: the probe terminates its own buffer.** The observation now sets
the terminator itself and is taken at two declared lengths, so the court compares the
*rule* (`strlen` of the declared buffer, plus one) rather than one number that a frame
happened to produce:

```c
memset(buf, 0xaa, sizeof buf);
buf[12] = '\0';
p = OSSL_PARAM_construct_utf8_string("k", buf, 0);
sayn("str.utf8.size0_construct.is_measured", (long long) p.data_size);
buf[15] = '\0';
p = OSSL_PARAM_construct_utf8_string("k", buf, 0);
sayn("str.utf8.size0_construct.is_measured_long", (long long) p.data_size);
```

**Remedy, part two: `forensics/tools/probe_hygiene.py`.** A differential court compares
two transcripts, and that is only meaningful if the transcript is a function of the
library under test. The gate compiles every `courts/phase<N>/*_probe.c` against each
side at `-O0`, `-O1` and `-O2`, runs each twice, and fails on either signature:

* **level drift** — the answers differ between optimization levels, which is what a
  read of uninitialised or out-of-bounds memory looks like;
* **run drift** — two runs at the *same* level differ, which is nondeterminism no court
  can compare either.

It was falsified against the pre-fix probe text before being trusted, and it reports
both signatures on it — including a run-drift reading of `22` then `17` at `-O0`, from
two executions of the *same binary*.

**Why not a sanitizer.** `-fsanitize=address` is the natural tool and cannot be used
here: ASan reserves a terabyte-scale shadow mapping and aborts with
`AddressSanitizer failed to allocate 0xdfff0001000 bytes` under the court's own
`RLIMIT_DATA` cap. The cap stays — it is what keeps a runaway court off the host — so
the level-differential method is the substitute: it needs no runtime support, it uses
the compiler that is already there, and it detects precisely the class that bit.
`gcc-12`'s `libasan` is present in the image and is refused for the same reason.

**Also in this commit.** `forensics/tools/phase6_courts.py` declared
`GENERATOR = "forensics/tools/phase5_courts.py"`, so every
`artifacts/phase6/COURTS.json` this stratum produced named the wrong generator in its
envelope. A copy-paste, and exactly the kind of provenance error the envelope exists to
prevent; `evidence_determinism.py` does not compare `generator`, which is why it
survived a green CI run.

**The store, recreated.** `run_courts.sh` from clean: 41 receipts, 82 challenges, 5
claims, `graph_verified: yes`, `object_closure: complete`, `replay_ready: yes`. Every
runtime court's `stdout-first-line` and `exit-class` mutants are adjudicated on their
own axis and no other, including the three that could not adjudicate before
(`rt-param`, `rt-mem-default`, `rt-mem-install`). `openssl-cli-version` remains the one
honest refusal D13 records and is compiled at `--policy baseline` with `openssl-cli-dgst`.

**Supersedes D104's counts; D104's decision stands.** D104 recorded Phase 6 at 1,161
observations and all courts at 19,346. Both were that generation's readings, and this
project never asserts a current count from `DECISIONS.md` — it derives them. Current:

| | D104's reading | now |
|---|---|---|
| Phase 6 observations (`RT-PARAM`) | 1,161 | 1,162 |
| all courts | 48 | 48 |
| all observations | 19,346 | 19,347 |
| runtime courts in the FRF store | 25 (stated in prose; already stale, actually 37) | 37 |
| probes under a hygiene gate | 0 | 37 |
| FRF store objects | 333 | 341 |

---

## D106 — `OSSL_LIB_CTX`, and the index slots as an obligation of their own kind

**What landed.** Phase 6.6a: seven of the ten `OSSL_LIB_CTX_*` exports —
`new`, `free`, `get0_global_default`, `set0_default`, `get_data`,
`get_conf_diagnostics`, `set_conf_diagnostics` — in `src/context/mod.rs`, from
`crypto/context.c`. `RT-LIBCTX` observes all of it in 73 observations with zero
residuals, on the first run.

**The reconnaissance came first, and it changed the design.** The probe was run
against the authority before any Rust was written, and it answered a question the
source does not: the authority's `switch` in `ossl_lib_ctx_get_data` has arms for
eighteen indices, and the three it does *not* answer for — 7 and 8, which the
authority once used for other things; 9, which is `FIPS_PROV` in a build that is
not FIPS; and 13, which was `BIO_PROV` — answer NULL. The measurement also settled
one build question that no installed header answers: index 19 (`THREAD`) answers a
pointer, so this profile has the thread pool compiled in, and index 21
(`COMP_METHODS`) answers `&ctx->comp_methods`, the address of a field *inside* the
object, so it is non-NULL for a context whose compression stack is empty.

`COMP_METHODS` is the one slot this stratum fills, and it is filled by having the
field rather than by allocating anything: the answer is an interior address and is
therefore exact immediately. It is also the arm most likely to be "simplified" into
returning the field's *value*, which would answer NULL for every context — so it
has a unit test of its own, and `RT-LIBCTX` compares it against the authority.

**Three of the ten exports are not writable yet, and the split is by dependency
rather than by convenience.** `OSSL_LIB_CTX_new_from_dispatch` calls
`ossl_bio_init_core` (6.6c, the core BIO); `OSSL_LIB_CTX_new_child` calls
`ossl_provider_init_as_child` (6.8) and is what sets `ischild`;
`OSSL_LIB_CTX_load_config` is a one-line forward to `CONF_modules_load_file_ex`
(6.10). Writing any of them now would mean writing it against a stub, so 6.6 is
now 6.6a–6.6g in `docs/PHASE-6-SUBPHASES.md` with each dependency named, and this
commit is 6.6a.

**The index slots are obligations of their own kind, and this is the decision.**
Seventeen of the eighteen live slots belong to a later stratum, so the arms answer
NULL until their owner lands. That gap is invisible to every symbol ledger — a
*field* that was never filled is not a symbol — which is exactly the
`a2d_ASN1_OBJECT` defect class one layer down. Three things make it visible
instead of latent:

  * the per-slot owner table is in `docs/PHASE-6-SUBPHASES.md` **and** in the
    module documentation, with the closure rule stated in both: Phase 6 cannot be
    called complete while any row is unfilled;
  * the probe observes the dead indices and the filled slots, and prints
    `libctx.slots.live` (18), `.filled` (1) and `.deferred` (17), so the
    transcript states the scope of its own table rather than leaving a reader to
    infer it from an absent line;
  * nothing is filled with a placeholder. The value is a live object of a type a
    later stratum owns; a one-byte allocation that only made the pointer non-NULL
    would satisfy the observation while saying something false about the object.

An unfilled slot may not be *observed* either, and that follows the rule the later
probes already use: comparing a missing subsystem is the ledger's business, not a
court's. The probe observes what a divergence can be seen in.

**Two behaviours that a plausible reading gets wrong.** Both are in the probe and
both are in the module documentation because neither is documented anywhere else:

  * `OSSL_LIB_CTX_set0_default(OSSL_LIB_CTX_get0_global_default())` does not
    install the global default, it **clears** the thread's slot
    (`set_default_context` rewrites the global object to NULL). The NULL context
    still resolves to the same object, but a following
    `set0_default(NULL)` reports the global default rather than the pointer that
    was passed in.
  * `OSSL_LIB_CTX_free` is a no-op for two of the three values it accepts: NULL,
    and whatever the calling thread's default resolves to — which includes the
    global default in a thread that never changed its default, and includes a
    context the thread installed itself. Only a non-default context is released.
    The probe reads the context *after* that no-op free to tell the two apart, and
    the hazard that creates (a candidate that really freed it is reading released
    memory, which glibc does not fault on at this size) is stated in the probe
    rather than avoided, because avoiding it would remove the only observation
    that can see the behaviour.

**Two deferrals are named in the code rather than left as absences.**
`context_deinit` calls `ossl_ctx_thread_stop` in the authority; it cannot be
called until 6.6e registers threads against a context, and the line it goes on
says so. And `ossl_do_ex_data_init(ctx)` gives each context its own ex-data
registry, which `src/runtime/ex_data.rs` records as a process-global Phase 3
deferral; this module does not quietly change that.

### Arithmetic

| | before | after |
|---|---|---|
| Phase 6 implemented | 81 | 88 |
| Phase 6 open | 80 | 73 |
| `implemented[libcrypto]` | 1,055 | 1,062 |
| Phase 6 courts | 1 | 2 |
| all courts | 48 | 49 |
| all observations | 19,347 | 19,420 |
| runtime courts in the FRF store | 37 | 38 |

---

## D107 — the thread slot, and a counter that is per context rather than per process

**What landed.** Phase 6.6e: slot 19 of the library context, `OSSL_get_max_threads`
and `OSSL_set_max_threads`. The slot is `crypto/thread/internal.c`'s
`ossl_threads_ctx_new`/`_free` — two counters, a mutex and a condition variable —
and `src/context/mod.rs` now creates it in `context_init` (failing the context if
it cannot be built) and releases it in `context_deinit_objs`, in the authority's
`#ifndef OPENSSL_NO_THREAD_POOL` position between the two callback slots and
`child_provider`. `RT-THREADDATA` observes all of it in 39 observations with zero
residuals, first run; `RT-LIBCTX` grows from 73 to 75 as slot 19 joins its
`filled_slots` list, which is the mechanism 6.6a described.

**The two accessors look trivial and are not.** Everything about them is in the
plural, and all three are in the court:

  * the counter is per **context**, so `OSSL_set_max_threads(a, 7)` must not move
    `OSSL_get_max_threads(b)`, and the default context is one of the contexts
    rather than a special case;
  * a NULL context resolves through the library context default chain, so the same
    call answers differently once this thread installs a default — the probe
    installs one, reads through NULL, restores, and reads again;
  * the value is stored **verbatim**: no range check, so `UINT64_MAX` is legal to
    set and to read back, and zero is a value rather than "unset". A `uint64_t`
    that was clipped, or a setter that refused a large value, would be a plausible
    reading and a wrong one.

**Why the pool's primitives are in this commit.** `ossl_threads_ctx_new` allocates
a mutex and a condition variable and **fails** if either cannot be built, so they
are part of the slot's constructor and cannot be deferred with it.
`src/runtime/thread.rs` gains the authority's `ossl_crypto_mutex_*` and
`ossl_crypto_condvar_*` over the same primitives (`crypto/threads_pthread.c` uses
`pthread_mutex_t`/`pthread_cond_t` directly). Two design points are recorded
because both are places a shim is usually wrong:

  * the mutex is **not** recursive. `PTHREAD_MUTEX_DEFAULT` deadlocks on re-lock by
    the same thread, and `std::sync::Mutex` would instead error or panic, so this
    cannot be a thin wrapper over it; it parks on a flag and deadlocks as the
    authority does.
  * a condition variable is paired with one mutex and the pairing is made
    **explicit**. The C API creates the two independently and pairs them at each
    `wait` on the promise that release-and-wait is atomic; Rust's
    `Condvar::wait` needs the guard of the mutex it waits on, so the pairing is
    bound on first `wait` and a mismatched pair is reported rather than becoming a
    lost wakeup. Every use in the authority pairs one condvar with one mutex for
    its lifetime.

Nothing waits on the condition variable yet: it is created and released here
because the constructor creates and releases it, and the pool that signals it is
not a Phase 6 subsystem.

**6.6e is split, and the reason is a file rather than a distance.** The subphase
was to carry `OSSL_get/set_max_threads` *and* `OPENSSL_thread_stop`/`_ex`. The
counter pair needs only the slot, which is why it landed here; the stop pair needs
`crypto/initthread.c`'s per-thread event-handler table, and `OPENSSL_atexit` (the
fifth Phase 3 hand-off) needs `DSO_dsobyaddr` to pin the handler's object, so it
waits for 6.9. Those three are now 6.6e-ii with both dependencies named, and
`context_deinit`'s missing `ossl_ctx_thread_stop` call is the line 6.6e-ii
unblocks.

### Arithmetic

| | before | after |
|---|---|---|
| Phase 6 implemented | 88 | 90 |
| Phase 6 open | 73 | 71 |
| `implemented[libcrypto]` | 1,062 | 1,064 |
| Phase 6 courts | 2 | 3 |
| all courts | 49 | 50 |
| all observations | 19,420 | 19,461 |
| `RT-LIBCTX` observations | 73 | 75 |
| runtime courts in the FRF store | 38 | 39 |

---

## D108 — the self-test object aliases its own fields, and the prototype court earned its keep

**What landed.** Phase 6.11: all nine exports of `self_test.h` (seven) and
`indicator.h` (two), in `src/selftest/{mod,indicator}.rs`, from
`crypto/self_test_core.c` (160 lines) and `crypto/indicator_core.c` (54).
`RT-SELFTEST` observes them in 71 observations with zero residuals, first run, and
slots 12 and 22 join `RT-LIBCTX`'s `filled_slots` list, taking that court from 75
to 79 observations. Four slots of the eighteen are filled now; the other fourteen
are owed and named in `docs/PHASE-6-SUBPHASES.md`.

**The probe is the callback, because there is nothing else to be.** Both surfaces
are callback plumbing, so the only way to observe them is to register a callback
and record what the library passes it. Four things came out of that, and each is
somewhere a plausible transcription differs:

  * **the array's entries alias the object's own fields.**
    `self_test_setparams` builds `st-phase`, `st-type` and `st-desc` with
    `OSSL_PARAM_construct_utf8_string(key, st->field, 0)`, which stores the
    *address* of the field rather than a copy of the string.
    `OSSL_SELF_TEST_onend` reassigns all three fields to `"None"` **after** calling
    the callback and does **not** rebuild the array — so the same array reports
    `Pass` inside the callback and `None` afterwards, and there is no rebuild that
    could be observed either way. The probe stashes the array pointer inside the
    callback and reads through it again after the call; that is the only way a C
    caller can see the aliasing at all, and it is the reason this court is worth
    writing rather than unit-testing.
  * **`onend` treats anything other than 1 as a failure**, including 0 and
    negative values. "Failed" and "did not answer 1" are the same thing to the
    authority.
  * **`oncorrupt_byte`'s answer is the callback's, inverted**: the callback
    answering 0 flips the first byte and the call answers 1; answering 1 leaves the
    byte alone and answers 0.
  * **the object's callback is the one passed to `OSSL_SELF_TEST_new`, not the
    context's.** The context's pair is what other code invokes; an implementation
    that read the context's callback from inside `onbegin` would pass a probe that
    only ever set both to the same function, so the probe sets them to different
    things and checks which one ran.

**The prototype court found a real defect that the runtime court could not.** An
earlier revision of this landing declared

```rust
pub unsafe extern "C" fn OSSL_SELF_TEST_get_callback(
    libctx: *mut c_void, cb: *mut *mut c_void, cbarg: *mut *mut c_void)
```

The authority's second parameter is `OSSL_CALLBACK **` — a pointer to a **function
pointer**, not a `void **`. Both spellings work at run time for any caller that
passes correctly sized storage, so `RT-SELFTEST` passed 71 observations against the
wrong prototype; `ABI-PROTOTYPE` reported it as one of two type mismatches and
named the canonical form. The same was true of `OSSL_INDICATOR_get_callback`. That
is exactly the blind spot D98 and D103 each recorded from the other direction: a
runtime court compares *answers*, and a prototype that is wrong only in the
*shape* of an output parameter has no answer to compare.

**Two safety divergences, both recorded rather than reproduced.**

  * `OSSL_SELF_TEST_oncorrupt_byte` dereferences `bytes` only when its callback
    refuses the corruption. The authority faults on a NULL `bytes` in that case;
    this answers 0, because nothing was corrupted.
  * both setters store nothing and both getters answer NULL when the context's slot
    cannot be read, which the authority's own NULL guards already do.

**The indicator half is storage without a caller, and that is stated rather than
implied.** `OSSL_INDICATOR_set_callback`/`get_callback` are implemented and
courted; nothing invokes the callback, because the code that reports an indicator —
an operation with an approved or non-approved state — is provider-side. A subphase
that "implemented the indicator" by inventing a call site would be claiming
behaviour no consumer can reach.

### Arithmetic

| | before | after |
|---|---|---|
| Phase 6 implemented | 90 | 99 |
| Phase 6 open | 71 | 62 |
| `implemented[libcrypto]` | 1,064 | 1,073 |
| Phase 6 courts | 3 | 4 |
| all courts | 50 | 51 |
| all observations | 19,461 | 19,536 |
| `RT-LIBCTX` observations | 75 | 79 |
| index slots filled | 2 | 4 |
| runtime courts in the FRF store | 39 | 40 |

---

## D109 — the namemap: a bit-5 mask, an order-dependent refusal, and a pre-population deferred whole

**What landed.** Phase 6.6b: `crypto/core_namemap.c`, 584 lines, as
`src/context/namemap.rs` — all ten internal functions
(`ossl_namemap_new/free/empty/stored/name2num/name2num_n/num2name/doall_names/add_name/add_names`
plus the two context-slot constructors). It adds **no export**, so what moves is
slot 4: `RT-LIBCTX` goes from 79 to 81 observations, comparing the slot's presence,
stability, per-context distinctness and difference from the object's own address
against the authority. Five of the eighteen index slots are filled now.

**The comparison is a bit mask, not a case fold.** `name2num` keys its lookup
through `ossl_ht_strcase`, which is `tgt[i] = ~0x20 & src[i]`. For ASCII letters
that is a case fold, which is the documented intent. For every other byte it is
not: `'!'` (`0x21`) and `0x01` both map to `0x01`, so two names differing only by
bit 5 in a non-letter position are the same name to this map. Reproduced rather
than normalised, because a map that answered differently from the authority for
such a name is exactly the kind of divergence this project exists not to have.
The same macro caps the key at **63** bytes — two names sharing a 63-byte prefix
are one name — which is also reproduced and unit-tested. The explicit-length form
keys on a prefix instead, so `name2num_n(nm, "sha256", 3)` asks for `"sha"`.

**`NDEBUG` is defined in the admitted build, and that decides a branch.** The two
`ossl_assert`s in this file are `OPENSSL_die(...)` in a debug build and a plain
`(x) != 0` under `NDEBUG`; the admitted profile's `configdata.pm` lists `NDEBUG`,
so a NULL namemap **reaches the `ERR_R_PASSED_NULL_PARAMETER` raise** rather than
aborting the process. Read from the authority's own build record, not assumed:
the opposite assumption turns a raise into a process death, and the generator had
already recorded that site as an active raise.

**The conflict refusal is order-dependent, and the unit test found it.** The first
run of the test asserted the intuitive thing — that
`ossl_namemap_add_names(nm, 0, "fresh:known", ':')` is refused because `known`
belongs to another number — and failed, because it is **accepted**. The number
being built starts as the caller's (0 for "none") and a part only *sets* it when
that part resolves to an existing number, so `fresh` resolves to 0 (changing
nothing), `known` then resolves to its number, and no comparison against `fresh`
ever happens. The conflict is reachable only between a part that comes *after* one
that already resolved. Both halves are now asserted, and the behaviour is in the
module documentation, because it is the sort of thing a later reader would
otherwise "fix".

Also reproduced and tested: `max_number` is stored on **every** successful
addition, so appending an alias to an existing number can *lower* it — the only
reader is `ossl_namemap_empty`, which asks whether it is zero, so the oddity is
invisible and still reproduced; and `stored` makes `ossl_namemap_free` a no-op,
with the context's destructor clearing the flag first.

**The pre-population is deferred whole, and the reason is the guard.**
`ossl_namemap_stored` pilfers the legacy `OBJ_NAME` database and the
`EVP_PKEY_ASN1_METHOD` set on first use of an empty map, then adds four RSA-PSS
aliases — all inside `if (ossl_namemap_empty(namemap))`. Every one of those names
takes a number, so the numbering of everything registered later depends on them.
That population cannot be built before the legacy method database and
`OBJ_NAME_do_all` exist (Phase 13). Running the RSA-PSS block *alone* would be
worse than running none of it: the map would no longer be empty, so a later phase
adding the legacy load would find the guard false and skip it entirely, silently
leaving the legacy names out of a map that had already been numbered wrongly.
Deferring both together keeps the ordering decision in one place.

**The container is not the authority's table.** The authority's `name -> number`
map is `crypto/hashtable/hashtable.c`: open addressing over 512 neighbourhoods,
FNV-1a, with `collision_check` turning an excessive conflict rate into
`CRYPTO_R_TOO_MANY_NAMES`. This module uses a `HashMap` keyed on the transformed
bytes, so the *lookup* behaviour is identical and the collision failure is
unreachable. Recorded rather than papered over: the site constant
`CORE_NAMEMAP_288` exists with `dynamic_reason: true` and one function beside it
carries the `#[allow(dead_code)]` that says why a raise which cannot happen is
not called. Reproducing it would mean reproducing the hash function too, and no
observable depends on which of two names occupies which slot.

**The error coordinates are generated, and `crypto/core_namemap.c` is now covered.**
`gen_err_raise_sites.py` gained the file as part of this stratum's obligation set
by the same rule Phase 4 and Phase 5 used — every authority file in the subsystem
that raises belongs to it. Regeneration was **purely additive**: 767 sites to 772,
nothing removed, nothing changed. One of the five is the first site in the table
whose reason is chosen at run time; the generator classified it `dynamic_reason`
rather than guessing which of its two constants the call site means.

**A gap this exposed, recorded rather than fixed here.**
`src/runtime/err_sites.rs` and `forensics/atlas/err-raise-sites.json` are
generated but are **not** in `evidence_determinism.py`'s generator or comparison
lists, so CI would not notice if a future edit to the generator — or to
`COVERED_FILES` — left the committed coordinates stale. They are contract
(`ERR_get_error_all` reports them), so this is a real incompleteness in the
evidence machinery rather than a cosmetic one. The remedy is to add the generator
and both outputs to that tool and to `check_evidence_portability.py`'s exercised
set; the cost is that the tool would then need the authority source tree and
`configdata.pm` on the host runner, which are both committed.

### Arithmetic

| | before | after |
|---|---|---|
| Phase 6 implemented / open | 99 / 62 | 99 / 62 (no export) |
| `implemented[libcrypto]` | 1,073 | 1,073 |
| Phase 6 courts / observations | 4 / 1,353 | 4 / 1,355 |
| `RT-LIBCTX` observations | 79 | 81 |
| index slots filled | 4 | 5 |
| `err_sites.rs` coordinates | 767 | 772 |
| unit tests | 183 | 189 |

## D110 — the core BIO: a slot filled eagerly, a `libctx` resolved at use time, and three faults registered rather than reproduced

**What landed.** Phase 6.6c: `crypto/bio/bss_core.c` (188 lines) as
`src/context/core_bio.rs`, plus `src/context/dispatch.rs` for the `OSSL_DISPATCH`
walk, plus `OSSL_LIB_CTX_BIO_CORE_INDEX` (17) and the export it exists for. Three
exports are implemented — `BIO_s_core`, `BIO_new_from_core_bio` and
`OSSL_LIB_CTX_new_from_dispatch` — and **slot 17 is filled**, so six of the
eighteen index slots are live. `docs/PHASE-6-SUBPHASES.md` carried this subphase as
`crypto/bio/bio_core.c`; the authority's file is `bss_core.c`, corrected there.

**Phase 4's accepted-and-ignored argument is now honoured, in Phase 4's code.**
`BIO_new_ex` has always taken an `OSSL_LIB_CTX *` and discarded it, because nothing
in Phase 4 could read it; Phase 4's seal named this subphase as the obligation that
created. `src/runtime/bio/mod.rs`'s `Bio` therefore gains a `libctx` field here.
That is a change to a **sealed** stratum's source by a later one, which the seal
rules permit only when the earlier seal named the obligation and the later stratum
discharges it — which is why the field is recorded here rather than left as an
unexplained diff. The Phase 4 courts are unaffected (3,244 observations, unchanged),
because no Phase 4 behaviour depends on the field.

**The finding: slot 17 is filled eagerly, not on first use.** `context_init` calls
`ossl_bio_core_globals_new(ctx)` for every context, so
`OSSL_LIB_CTX_get_data(ctx, 17)` answers non-NULL for a context that has never seen a
dispatch table. The consequence is not cosmetic: `get_globals()` **cannot return
NULL through the public API**, so `BIO_new_from_core_bio`'s NULL answer comes from
the absent `BIO_read_ex`/`BIO_write_ex` callbacks and never from an absent globals
block, and the `if (bcgbl == NULL)` arms in all seven operations are unreachable from
a consumer. A candidate that created the globals lazily would answer every
constructor observation identically and still be wrong about the slot. `RT-LIBCTX`
now carries index 17 in its `filled_slots` array — the same fact observed from the
other end — and moves from 81 to 83 observations.

**`bio->libctx` is stored as given and resolved at *use* time.** The authority's
`BIO_new_ex` assigns the argument with no concretisation, and
`ossl_lib_ctx_get_concrete(NULL)` answers the **thread** default. So a core BIO built
with a NULL context reaches whatever this thread's default is *when the operation
runs*. `RT-BIO-CORE` proves it rather than asserting it: it builds one such BIO
before any default is installed and writes to it (`0`, no callbacks reachable), then
installs a context that has them and writes to **the same BIO** again (`18`, that
channel's answer). A candidate that resolved the context at construction would pass
every other observation in this court and fail exactly that one. Two contexts holding
two tables are named the same way — the callbacks answer `3 × channel`, so the
transcript says which channel ran without trusting a counter.

**The court is a matrix over deliberately incomplete tables.** `BIO_new_from_core_bio`
accepts a table carrying only one of `read_ex`/`write_ex`, so the probe builds a
write-only and a read-only table and observes the answer to each *missing* callback
separately: `read_ex` and `write_ex` answer `0`, `ctrl`, `gets` and `puts` answer `-1`,
and `destroy` answers `0`. A transcription that picked one of the two values and used
it everywhere passes a happy-path test and fails this one. The handler the callbacks
receive is compared against the constructor's argument and against NULL and only the
booleans are printed — an address would make the transcript a property of the loader.
108 observations, zero residuals, first run.

**Three authority fault boundaries, registered rather than reproduced.** Each calls a
stored function pointer with no NULL test. `D-BIOCORE-1`: a table with `read_ex` or
`write_ex` but no `BIO_up_ref` — the guard passes and the *next line* jumps to zero.
`D-BIOCORE-2`: `BIO_free` of a core BIO whose context has no `BIO_free` callback,
which is every BIO built as `BIO_new(BIO_s_core())`. `D-BIOCORE-3`:
`OSSL_LIB_CTX_new_from_dispatch(handle, NULL)`, which is **reachable from an export**
because the export forwards its table straight into the walk whose own loop condition
dereferences it. The candidate's slots are `Option<fn>` precisely so that absence is
representable, and each such path answers the documented failure instead. No caller
supplying a usable table can tell the two behaviours apart, because in the authority
every path that reaches the unguarded call dies there.

**The probe was the suspect twice before the crate was.** `BIO_method_type` and
`BIO_method_name` take a `const BIO *`, not a `BIO_METHOD *`, so the first draft
compiled against a type error it read as a warning and would have been comparing
whatever those two functions do with a method pointer; and a channel's seven
callbacks are defined whichever table it sits in, so the two deliberately incomplete
tables left four and five functions unreferenced. Both were the instrument rather
than the subject, which is the failure mode this project has recorded most often. The
second also produced a unit-test trap worth naming: `clippy` rejects a `// SAFETY:`
comment that is not **directly** above its `unsafe` block — an `assert_eq!` between
them does not count — and it rejects `panic!` in a `#[cfg(test)]` module too.

### Arithmetic

| | before | after |
|---|---|---|
| Phase 6 implemented / open | 99 / 62 | 102 / 59 |
| `implemented[libcrypto]` | 1,073 | 1,076 |
| Phase 6 courts / observations | 4 / 1,353 | 5 / 1,463 |
| `RT-LIBCTX` observations | 81 | 83 |
| index slots filled | 5 | 6 |
| all courts / observations | 51 / 19,538 | 52 / 19,648 |
| prototype court, class / type plane | 1,041 / 1,058 | 1,044 / 1,061 |
| `err_sites.rs` coordinates | 772 | 772 |
| FRF courts | 40 | 41 |
| unit tests | 189 | 193 |

## D111 — the property engine has no export, so its court is the slot table

**What landed.** Phase 6.7a: `crypto/property/property_string.c` as
`src/property/strings.rs`, plus `defn_cache.c`'s constructor and releaser, plus the two
global-property functions from `property.c`, plus `ossl_property_parse_init` from
`property_parse.c`. **Index slots 2, 3 and 14 are filled**, so nine of the eighteen are
live, and `context_init` now ends with the property pre-initialisation the authority
puts there. No export changes: the Phase 6 ledger stays at 102 implemented and 59 open.

**The correction, and it is to the plan rather than to the code.**
`docs/PHASE-6-SUBPHASES.md` recorded 6.7's exit criterion as "definition, parse, string
round-trip, matching, query parse and negative selection", with `RT-PROPERTY` as its
court. Measured against the authority, **the property engine has no exported symbol at
all**: all thirty-odd entry points are `ossl_property_*`, `ossl_ctx_global_properties*`
and `ossl_prop_defn_*`. A probe is compiled against *installed headers* and linked
against the library, so it cannot call one function of the grammar, and a court that
claimed to compare the parse would be claiming an observation no probe can make — which
is the failure mode this project has now recorded four times in other forms
(`a2d_ASN1_OBJECT`, the prefix-derived discovery of D49 and D51, the unread ledger of
D94). The criterion and the court are corrected in place, and the *behaviour* it named
is not dropped: it becomes observable at 6.8, where a provider fetch applies a query to
a candidate set, and is corroborated at 6.12 by an independently written provider. That
is exactly `docs/PROVIDER_MODEL.md` §5's gate item 4, "property-based fetch selection
matches, including negative selection", and it was always 6.8's, not 6.7's.

**What the three slots can witness, and the one thing that is a start-up contract.**
`RT-LIBCTX` gains slots 2, 3 and 14 and moves 83 → 89 observations: presence, stability,
per-context distinctness and difference from the object's own address, for each of the
three, on two independent contexts. The engine's *ordering* contract is not visible
through a slot, but it is asserted by the authority at every context construction and is
reproduced here for the same reason:

```c
if ((ossl_property_value(ctx, "yes", 1) != OSSL_PROPERTY_TRUE)
    || (ossl_property_value(ctx, "no", 1) != OSSL_PROPERTY_FALSE))
    goto err;
```

`OSSL_PROPERTY_TRUE` is 1 and `OSSL_PROPERTY_FALSE` is 2, and the value table's counter
is **separate** from the name table's, so the six predefined names take 1..6 in their own
space while "yes" and "no" are the *first two values*. One shared counter, or interning
the names as values, fails the authority's own check. The two `if`s are written as two
`if`s rather than one tuple comparison because the authority's `||` short-circuits: a
table that numbers "yes" wrongly also leaves "no" uninterned, and that state is part of
what is reproduced.

**Two slots are filled and empty, and that is the authority's own state.**
`ossl_property_defns_new` is one empty lhash and `ossl_ctx_global_properties_new` is one
`OPENSSL_zalloc`ed block with a NULL `list`. A zeroed holder is a *valid empty* holder,
not an uninitialised slot: the authority's own constructor produces exactly this, and
the reader that would distinguish them is `ossl_ctx_global_properties`, which returns
`&globp->list`. So filling these two asserts nothing about property behaviour, and the
releasers are written to handle a non-empty state because that is the state 6.7b will
create — a releaser that ignored the list would leak, so it does not.

**The element layout is reproduced, not approximated.** `PROPERTY_STRING` is
`{ const char *s; OSSL_PROPERTY_IDX idx; char body[1]; }` with `s` pointing at its own
`body`, so one allocation holds the header and the string and `property_free` is a bare
`OPENSSL_free`. On x86-64 that is `size_of` 16 with `body` at offset 12, and
`new_property_string` allocates `16 + l`. A Rust `#[repr(C)]` type with a trailing
`[c_char; 1]` gives the same offsets and the same `size_of`, so the arithmetic is the
authority's down to the slack byte. `defn_cache.c`'s element has the same shape and the
same treatment.

**`PROP_R_*` is the first reason family in this table that is not in an installed
header.** The error-coordinate resolver compiles a C probe against the authority's
headers and prints what each symbol evaluates to, and it had only ever needed the
installed ones — `ERR_R_*`, `CRYPTO_R_*`, `BIO_R_*`, `ASN1_R_*`. The property grammar
raises `PROP_R_*`, which lives in `include/internal/propertyerr.h`, present in the
committed source tree and **not installed**. The resolver therefore gained
`-I <authority source>/include` as a *second* include directory, after the built prefix,
so every `openssl/...` header still comes from the prefix the courts link against and
only `internal/...` falls through to the tree the build was made from. 23 coordinates
were added — `property_string.c`'s 3 and `property_parse.c`'s 20 — taking the table from
772 to 795. `property_parse.c`'s are 6.7b's implementation, and they are taken now
because the rule Phase 4 and Phase 5 established is the *subsystem* set rather than the
implemented subset: a site nobody calls yet is a coordinate, not a claim.

**A naming correction.** The file mirroring `property.c` was first written as
`src/property/property.rs`, which clippy refuses (`module_inception`) and which would
have needed an `#[allow]` — a suppression rather than a correction. It is
`src/property/globals.rs`, named for the object, and says in its header that everything
in it is `property.c`'s.

### Arithmetic

| | before | after |
|---|---|---|
| Phase 6 implemented / open | 102 / 59 | 102 / 59 (no export) |
| index slots filled | 6 | 9 |
| `RT-LIBCTX` observations | 83 | 89 |
| all courts / observations | 52 / 19,649 | 52 / 19,655 |
| `err_sites.rs` coordinates | 772 | 795 |
| unit tests | 193 | 196 |

**The ordering contract has a unit test because no court can see it.** Three tests were
added to `src/property/strings.rs`: the two Boolean values are 1 and 2 *and* the six
predefined names occupy their own 1..6; a repeat intern answers the same index and a
non-`create` miss answers 0, with index 0 naming nothing on both tables; and two contexts
have their own tables and their own counters. That is the same reasoning D109 applied to
the namemap's order-dependent refusal — when a behaviour is real and nothing observable
reaches it, the assertion has to live where it can be made, and the residual says so.

## D112 — the ctype table is generated, and a range test that was only ever asserted

**What landed (6.7b, in progress).** Four things, of which two are compiled and tested
and two are committed but deliberately not yet in the module tree:

| artefact | state |
|---|---|
| `src/runtime/bsearch.rs` — `crypto/bsearch.c` mirrored | in the tree, 4 unit tests |
| `forensics/tools/gen_ctype_table.py` + `src/runtime/ctype_table.rs` | in the tree, registered with `evidence_determinism.py` |
| `src/runtime/ctype.rs` — five more classes | in the tree, 3 more unit tests |
| `src/property/list.rs` — the list and definition types | committed, **not declared** |
| `src/property/query.rs` — `property_query.c` | committed, **not declared** |

`list.rs` and `query.rs` are held out of the module tree on purpose. Their only caller is
the grammar `property_parse.c`, which is the next step; declaring them today would mean
nine `allow(dead_code)` markers on interfaces rather than on obligations, and an interface
that nothing calls is a placeholder wearing a different hat. Committing the files while
leaving them undeclared keeps them from being lost and keeps the crate honest — the
compiler does not see them, so nothing about them is claimed.

**No Gemel checkpoint accompanies this commit, and that is deliberate.** The constitution
requires a checkpoint at a *phase boundary*. This is a mid-subphase commit on a staging
branch, made so that the work survives; the 6.7b checkpoint comes when the grammar is
complete and courted.

**The instrument was wrong again, and the way it was wrong is worth recording.** The first
version of `gen_ctype_table.py` read **one source line per table entry**. The authority's
entries span two lines — the sum is wrapped — so every mask after the first line was
dropped, and the generator reported:

```text
digit      10 byte(s)
xdigit      0 byte(s)      <-- the authority has 22
```

`xdigit` appearing empty is a *plausible authority finding* — "the table has no xdigit
bits" — and it is exactly the shape of a real one. It was not: `/* 30  0  */` begins the
entry and `| CTYPE_MASK_xdigit | CTYPE_MASK_base64 | CTYPE_MASK_asn1print,` continues it.
The parser now accumulates until the next comment and checks each comment against its
position, and the corrected counts are 10 / 22 / 6 / 52 / 62 / 95. This is the failure
mode the project has now recorded more times than any other: **the probe, the generator and
the note are suspects before the authority is.**

**The more useful result: a Phase 5 claim was an assertion, and is now a check.**
`src/runtime/ctype.rs` implemented five predicates as ASCII *range tests* and recorded in
its header that the sets "were read back out of the authority's own table rather than
recalled". That equivalence lived in a doc comment. Nothing compared the two. With the
table now generated, one test walks every value a signed `char` can produce — `-256..512`,
so the values either side of the 128-byte boundary are included — and asserts that
`ossl_isdigit`, `ossl_isxdigit`, `ossl_isspace`, `ossl_isalpha`, `ossl_isalnum`,
`ossl_isprint` and `ossl_isasn1print` each agree with the table. They do. The claim is
retired into evidence, at the cost of one test.

That also settles *why* the table is generated rather than written. Phase 5's header says
transcribing 128 masks by hand would be "exactly the kind of hand-copied constant D33
forbids: a transcription that nothing regenerates and that nothing would notice going
stale". A generated table is the opposite of that, and it gives every class at once instead
of five more reasoned-out range tests.

**`CTYPE_MASK_ascii` is `(~0)` and must be truncated, not negated.** The masks are
`unsigned int`, so `~0` is `0xFFFFFFFF`. The generator's first resolution left it as `-1`,
which produced `pub(crate) const MASK_ASCII: u32 = -0x1;` and a compile error. The
constants are now masked to 32 bits at resolution. The table itself stores `unsigned
short`, and the entry check rejects anything that does not fit — which is what caught the
class of mistake rather than the instance.

**`ossl_tolower` XORs `c`, not the ascii image.** `return ASCII_IS_UPPER(a) ? c ^
case_change : c;` with `case_change` `0x20` in this profile and `0x40` only under a real
EBCDIC build. `ossl_toascii` is the identity here so the two coincide, and the distinction
is kept because the authority keeps it. The test covers `-256..512` and asserts that an
out-of-range value comes back unchanged.

**One determinism gap closed, one left open on purpose.** `gen_ctype_table.py` and its two
outputs are in `evidence_determinism.py`'s generator and comparison lists, so a stale
committed table is now a failure rather than a silent divergence — the artefact count goes
from 12 to 14. The gap D109 recorded, that `gen_err_raise_sites.py` and
`err-raise-sites.json` are in neither list, is **still open**: fixing it means adding the
same tool to `check_evidence_portability.py`'s exercised set as well, so that the two agree
about which generators need the authority's source tree. Doing half of that now would
replace one silent gap with two.

### Arithmetic

| | before | after |
|---|---|---|
| Phase 6 implemented / open | 102 / 59 | 102 / 59 (no export) |
| index slots filled | 9 | 9 (unchanged) |
| courts / observations | 52 / 19,655 | 52 / 19,655 (no behaviour change) |
| determinism-checked artefacts | 12 | 14 |
| unit tests | 196 | 203 |

## D113 — 6.7b closes: a backwards printer, a four-shape cache, and a clippy verdict on `unsafe fn` bodies

**What landed.** The rest of the property engine's grammar, so **6.7b is complete**:
`ossl_property_list_to_string` with its `put_char`/`put_str`/`put_num` helpers, and all
of `defn_cache.c` — `ossl_prop_defn_get` and `ossl_prop_defn_set`. With D112's half, the
whole of `property_parse.c`, `property_query.c` and `defn_cache.c` is reconstructed. Unit
tests go 203 → **216**.

**The reverse printer walks the sorted array backwards, and that is a test rather than a
comment.** `ossl_property_list_to_string` starts at `properties[num_properties - 1]` and
decrements while the output cursor advances, so the string lists the clauses in
*descending* `name_idx` order even though the array it reads is sorted ascending. It looks
like a defect and is reproduced, because it is observable. The test does not assert the
oddity in the abstract — it uses `input=certificate,output=certificate`, where
`ossl_property_parse_init` interns `output` before `input`, so the *higher* index is
`input` and the printed string must therefore contain `input` first. A forward walk would
put `output` first and fail.

The same test covers the printer's other two obligations: `put_num` advances the cursor by
a length it computed itself, not by what it wrote, so a truncated number leaves the cursor
*past* the NUL that terminated it; and a buffer with exactly one byte of room becomes a
terminator rather than a character, which is the `*remain == 1` arm of `put_char`. A NULL
list answers **1** and writes a bare terminator, so a caller can pass NULL and get a valid
empty string rather than a failure.

**`put_str` reads its input twice.** The first pass decides only *which* quote — single,
or double when the string contains a single — and never whether the value will be
truncated; that is the second pass and the `remain` arithmetic. A restructured version that
decided both in one pass would agree on every short value and differ on a value that
contains an apostrophe *and* overflows the buffer.

**The definition cache has four shapes, not two.** `prop == NULL` answers **1** without
touching anything; `pl == NULL` **deletes** the entry and answers 1; an already-cached text
frees the caller's list and **overwrites `*pl` with the cache's own**, so both sides then
share one object; and otherwise the text and the list are copied into a single
self-referential block whose key lives inside it. Three tests cover all four plus the
per-context isolation. The third shape is the one with teeth: nothing may free a list it
obtained that way twice, and the test asserts the pointer identity that makes that true.

**`ossl_assert` is non-fatal here too.** `NDEBUG` is defined in the admitted build, so the
two asserts in `ossl_prop_defn_get` are `(x) != 0` and a NULL table answers NULL rather
than aborting. That is the same build fact D109 read from `configdata.pm`, applied to a
third file.

**A clippy verdict worth recording, because it corrects an assumption.** The crate's
convention — every pointer operation in its own `unsafe` block with a `SAFETY` line
directly above — does not mean every *call* in an `unsafe fn` needs one. `lib_ctx_get_data`,
`lib_ctx_read_lock`, `lib_ctx_write_lock`, `lib_ctx_unlock` and `CRYPTO_malloc` are all
**safe** functions in this crate, so wrapping them is an `unused_unsafe` error under
`-D warnings`. Eight such blocks were removed from `defn_cache.rs`, and one in
`parse.rs`'s `put_char` (a pointer *cast* needs no block either). The distinction is worth
having in the record because the opposite assumption is the natural one to make from the
handoff's summary of the convention.

Two smaller corrections of my own work, both caught by clippy rather than by a court:
`items_after_test_module` — the printer was appended after the `#[cfg(test)]` module, so
the module moved to the end of the file; and `expect_used` is denied crate-wide, so a
test's three `expect`s became `unwrap_or_default`/`unwrap_or` with assertions that carry
the printed transcript into the failure message.

### Arithmetic

| | before | after |
|---|---|---|
| Phase 6 implemented / open | 102 / 59 | 102 / 59 (no export) |
| index slots filled | 9 | 9 (unchanged) |
| courts / observations | 52 / 19,655 | 52 / 19,655 (no behaviour change) |
| determinism-checked artefacts | 14 | 14 |
| unit tests | 203 | 216 |

## D114 — 6.8 and 6.9 swap, and the DSO contract that made the swap obvious

**The dependency only runs one way, and the plan had it backwards.**
`docs/PHASE-6-SUBPHASES.md` recorded 6.8 (provider) before 6.9 (DSO), with 6.9 depending on
6.8. But `OSSL_PROVIDER_load`'s dynamic branch **is** a `DSO_load` call, and DSO depends on
nothing in the provider stack — so landing the provider registry first would mean writing
`load` against a loader that does not exist, or writing it without its dynamic branch and
then reopening it. The rows now record **6.9 before 6.8**: an order correction of exactly
the kind the 6.6 split made when reconnaissance found `new_from_dispatch` could not precede
the core BIO.

While correcting that, a second error in the same row: 6.9's dependency was written as
`6.6g`, which is itself downstream — `6.6g` is `OSSL_LIB_CTX_load_config`, which waits for
6.10, which waits for 6.8, which waits for 6.9. A cycle. DSO's only Phase 6 dependency is
the context, so the row now says `6.6a`. This is worth recording rather than quietly
fixing: a dependency column nobody re-derives is exactly where a cycle can hide, and the
`phase_state.py` rule ("a phase cannot be complete while an earlier one is not") would
never have caught it because it orders *phases*, not subphases.

**Four facts the reconnaissance established, which fix the shape of the work.**

1. **All fifteen `DSO_*` symbols are exported, and `openssl/dso.h` is not installed.**
   `forensics/authorities/prefix/.../include/openssl/dso.h` does not exist, so these are in
   the atlas's `abi-only` class: a consumer can link them but cannot *declare* them from an
   installed header. That is why `RT-DSO` must take its prototypes from the authority's
   committed source tree, exactly as the error-coordinate resolver takes
   `internal/propertyerr.h` — and it means this court's subject is the ABI and the
   behaviour, not a source-level contract. It also means the property engine's situation
   and DSO's are **not** the same: the property engine has no exported symbol at all, while
   DSO has fifteen that no header declares.
2. **The method is `dlfcn`, and the file that supplies it is chosen by configuration.**
   `dso_openssl.c` compiles to a null method under `DSO_NONE`; this profile's
   `build/.../include/crypto/dso_conf.h` defines `DSO_DLFCN`, `HAVE_DLFCN_H` and
   `DSO_EXTENSION ".so"`, and `configdata.pm` lists `dso_dlfcn.o` — so `DSO_METHOD_openssl`
   returns the `dlfcn` method and `DSO_DLFCN` is the branch to reproduce. `dso_dl.c`,
   `dso_vms.c` and `dso_win32.c` are not this profile.
3. **The method struct is eleven fields and its order is load-bearing.** From
   `dso_local.h`: `name`, `dso_load`, `dso_unload`, `dso_bind_func`, `dso_ctrl`,
   `dso_name_converter`, `dso_merger`, `init`, `finish`, `pathbyaddr`, `globallookup`.
   The `dlfcn` initialiser fills `ctrl`, `init` and `finish` with NULL, so those three
   paths in the generic layer are reachable only through the *method* being NULL — which is
   the `DSO_R_UNSUPPORTED` arm.
4. **`DSO_new_method` does not initialise `ex_data`.** It zeroes the struct and never calls
   `CRYPTO_new_ex_data`, and `DSO_free` never calls `CRYPTO_free_ex_data`. So the field is
   present for layout and is dead in both directions — reproduced as a field, not
   implemented as a subsystem.

**Three behaviours that will need care in the court, written down before the code.**

* `DSO_convert_filename` translates `"foo"` to `"libfoo.so"` and `"libfoo.so"` to
  **`"liblibfoo.so"`** — the transform is "no `/` in the name", not "not already
  translated". With `DSO_FLAG_NAME_TRANSLATION_EXT_ONLY` it is `"foo.so"`, and with
  `DSO_FLAG_NO_NAME_TRANSLATION` the name is returned **unchanged by a `strdup`**, not by
  the converter.
* `DSO_merge` has four shapes: a rooted first spec wins, a missing first spec yields the
  second, a missing second yields the first, and otherwise the two are joined with one `/`
  — with a trailing `/` on the second **removed first**, so `"/d/", "f"` is `/d/f` and not
  `/d//f`.
* `DSO_pathbyaddr` and `DSO_dsobyaddr` return the path of the library the *function* lives
  in, which is necessarily different on the two sides of a differential court. The
  comparable observations are therefore the **contract** and not the text: `sz <= 0`
  answers `len + 1`, otherwise `min(len, sz - 1) + 1`, so `sz` in `{1, 2, 4}` answers
  `{1, 2, 4}` on both sides and the buffer's terminator is at `sz - 1`. That the paths
  differ is a *platform* divergence to record, not a residual to chase.

### Arithmetic

| | before | after |
|---|---|---|
| Phase 6 implemented / open | 102 / 59 | 102 / 59 (documentation only) |
| subphase order | 6.8 then 6.9 | **6.9 then 6.8** |
| unit tests | 216 | 216 |

## D115 — 6.9 closes: the DSO layer, one corrected error site, and a probe bug that looked like agreement

**All fifteen exports land and the court is a real one.** `crypto/dso/dso_lib.c` (329
lines) becomes `src/dso/mod.rs` (983) and `crypto/dso/dso_dlfcn.c` (445) becomes
`src/dso/dlfcn.rs` (616). `dso_err.c`'s reason table joins the generated
error-coordinate plane (`err_sites.rs` 795 → **830** coordinates) and `dso_openssl.c` is
the one-line accessor that the `DSO_DLFCN` profile resolves to. Phase 6 moves from 102
implemented / 59 open to **117 / 44**, and `libcrypto` from 1076 to **1091** of 5896.
`RT-DSO` is the 53rd court and adds **145 observations** with **no residuals**; the five
phase court sets now total **53 courts and 19,800 observations**, every one re-derived
from the authority in this run. The FRF store is recreated around it: 373 → **381**
objects, 90 → **92** challenges, 45 → **46** receipts, 5 claims, `graph_verified`.

**A number in this entry was mis-summed on first writing, and the correction is
recorded rather than applied quietly.** The first draft of the Gemel change for this
subphase stated the five-phase total as 19,796 and the pre-6.9 total as 19,651. Both
were hand arithmetic over the court artefacts; the derived sum is **19,800** before and
**19,655** after, and `regression_guard` prints the same 19,800 from
`forensics/regression-baseline.json`. Nothing about the evidence changed — only my
addition. It is mentioned here because an evidence record that silently acquires the
right number is indistinguishable from one that was right all along, and this project
has already decided which of those it wants to be (D33). The four-observation
difference is not attributable to a court; it is simply a bad sum.

**The court's first failure was the probe's, not the library's — the same lesson as the
ctype table, in a different guise.** The first `RT-DSO` run failed on three keys:
`path.query`, `path.full` and `path.negative` differed by exactly the difference between
the two libraries' path lengths (79 against 38). That is not a divergence; it is the one
dimension a `DSO` court *cannot* compare, because a `DSO`'s subject is a shared library
and the two sides are different libraries at different paths. The probe was rewritten to
compare the **arithmetic** instead: that the size query is positive, that it agrees with
the full-size answer, that `sz` in `{1, 2, 4}` answers `{1, 2, 4}`, that a size one below
the length truncates to `len - 1` by the `min(len, sz - 1) + 1` rule, and that the
buffer is terminated at each size. `q` and `full` are now used only inside relations and
never printed. D114 predicted this divergence; the probe had to be built to not *measure*
it rather than merely to tolerate it.

**`ERR_add_error_data` appends. It does not replace, and the comment in the code said it
did.** `dlfcn_pathbyaddr`'s failure path was reproduced through `ERR_add_error_txt` with
two calls and a note claiming that the authority's `ERR_add_error_data` "*replaces* rather
than appends", which was written down as the reason for a recorded divergence
(`D-DSO-1`). Reading `crypto/err/err.c` settles it the other way: `ERR_add_error_vdata`
reuses the slot's existing `MALLOCED|STRING` buffer, `realloc`s it to fit and `strlcat`s
into it. So the two are *both* append, and the divergence did not exist. What did exist
is the next paragraph. A recalled constant presented as a measured one is D33's defect
class, and this is its second instance in this stratum.

**The `<NULL>` substitution is reachable at exactly one site in this subsystem, and it
was missing.** `ERR_add_error_vdata` does `if (arg == NULL) arg = "<NULL>";`, so a NULL
argument to `ERR_add_error_data` becomes the literal `"<NULL>"`. The candidate's
`c_str_bytes` answers an empty slice for NULL — invisible at the load and bind sites,
because those fail immediately after a `dlopen`/`dlsym` that just set `dlerror`'s state,
but **wrong at `pathbyaddr`**, which fails because `dladdr` did — and `dladdr` does not
touch `dlerror`. So a caller who drained the error queue gets
`dlfcn_pathbyaddr(): <NULL>` from the authority. `c_str_or_null_literal` now makes all
three sites match, and `RT-DSO` observes the text itself rather than asserting it:
`ERR_raise(ERR_LIB_USER, 1)` puts a code on the queue with *no data*, the failing
`DSO_pathbyaddr` appends to that slot, and `ERR_get_error_all` reads back
`dlfcn_pathbyaddr(): <NULL>` — identical on both sides. A mutation that removes the
substitution makes the court **fail** (`court/dso-sensitivity.py`), so this is a
sensitivity-backed observation rather than a claim.

**`DSO_merge` refuses a NULL first spec before it reads the flag, so the merger's own
both-NULL arm is unreachable.** The layer's test is
`if (dso == NULL || filespec1 == NULL)` and it comes first; the
`DSO_FLAG_NO_NAME_TRANSLATION` test comes second and can only suppress the *call*. The
merger therefore cannot be entered with a NULL first spec, so its
`filespec1 == NULL && filespec2 == NULL` branch is dead code in the authority — and dead
here by the same construction. The probe records it as two observations rather than one:
`merge.both.null` and `merge.notranslate.null.first` carry the *layer's* reason and not
the merger's, which is also why a NULL-first refusal is unaffected by the flag.

**`DSO_bind_func` asked the method twice.** The authority assigns and then tests
(`if ((ret = dso->meth->dso_bind_func(dso, symname)) == NULL)`), so the method is asked
**once**. The candidate called it in the test and again in the return. That is invisible
through the ABI — `dlsym` is idempotent and raises nothing OpenSSL-owned — so no court
could have found it; it was found by reading the authority's function beside the
candidate's, which is the reason that reading is part of the method. Fixed.

**`probe_hygiene` had to learn a probe's build definitions, and learned them by asking
the runner.** `RT-DSO` is the first probe that cannot be compiled without per-side
input: it needs the path of the library under test, because the only `DSO_load` both
sides can be expected to succeed at is a load of the library each is itself built as,
and that path differs per side. The hygiene tool compiles every probe independently at
three optimisation levels and reported `UNSTABLE` — correctly, via the probe's own
`#error`. The fix is not a definition table in the hygiene tool: it imports each
`phaseN_courts.py`, finds the one that lists this probe, and calls its `extra_defs`.
That follows `discover_probes`'s reasoning, and it means adding a Phase 7 court with a
definition does not require remembering a second place. The definition itself is never
printed by the probe: the observations around it are NULL-ness and `strcmp` against the
input, which are equal on both sides by construction.

**A probe bug that looked like agreement, and would have looked like a divergence next
time.** The first version of the `<NULL>` observation printed `data` through a helper
that ends with `ERR_clear_error()` — and `data` **aliases the slot's own buffer**, which
that clear releases. Both sides printed an empty string, which reads as "the two sides
agree" while actually being "the probe never observed anything". The text is copied
before any helper runs. This is the failure mode the project's whole evidence model
exists to prevent, and it happened *inside* the instrument: worth recording because the
symptom — identical on both sides — is the symptom of success.

**Two behaviours the code reproduces because they look like mistakes, and one that would
have been.** `DSO_ctrl` with `DSO_CTRL_SET_FLAGS` and `larg = -1` answers `0` and then
reads back `-1` with a **clean error queue**, so the authority's own "a negative answer
means an error" comment does not hold for the value a caller may have stored; the probe
records the write, the read-back and the empty queue separately. `DSO_convert_filename`
translates `"libfoo.so"` to **`"liblibfoo.so.so"`** (D114 predicted
`"liblibfoo.so"`; the extension is appended to what is already there), which the probe
observes directly. And `DSO_load`'s refusals are *ordered*: the already-loaded test comes
before the filename is even looked at, so a second load on a live object is
`DSO_R_DSO_ALREADY_LOADED` and leaves the caller's object untouched — observed by
binding through the object after the refusal and by reading its filename back.

### Arithmetic

| | before | after |
|---|---|---|
| Phase 6 implemented / open | 102 / 59 | **117 / 44** |
| `libcrypto` implemented / 5896 | 1076 | **1091** |
| phase courts | 52 | **53** |
| court observations | 19,655 | **19,800** |
| Phase 6 courts | 5 | **6** |
| `err_sites.rs` coordinates | 795 | **830** |
| unit tests | 216 | **226** |
| `probe_hygiene` | clean (41 probes) | clean (**42 probes**) |
| FRF objects / challenges / receipts | 373 / 90 / 45 | **381 / 92 / 46** |

## D116 — 6.8c's activation half: an arm on the wrong side of `if (ref == 0)`, five bridges that refuse to be stubs, and an activation order that is load-bearing

**A defect that no court could have found, because nothing could reach it yet.**
`ossl_provider_free`'s `flag_initialized` arm — the teardown, the error-string unload and
the `operation_bits` release — had been written **before** the `if (ref == 0)` test rather
than inside it, so a provider was torn down on *every* release instead of on the last
one. The authority's own comment is the whole argument against that: *"there may be other
structures hanging on to the provider after the last deactivation and may therefore need
full access to the provider's services. Therefore, we deinit late."* The arm was
unreachable when it was written (`ossl_provider_free` carried a dead-code allowance),
which is exactly why the reading mattered and why no differential court could have caught
it: 6.8c's exports are what make the function live, and the first thing 6.8c does is
declare them. Its two allocation coordinates — `OPENSSL_free(prov->error_strings)` at
**754** and `OPENSSL_free(prov->operation_bits)` at **759** — also replaced the
placeholders `0`s that part 1 left, so a failing allocation records what a consumer would
see from the authority and not a line that does not exist.

**Five store bridges, and the decision not to stub them.** `provider_flush_store_cache`,
`provider_remove_store_methods` and the two activation functions each end in a call into
one of five libctx slots — the four method stores and the decoder cache — none of which
this build has. Every one of those calls is guarded by a NULL test on the slot, and the
NULL answers are **not uniform**: seven of the nine delegate functions answer 1, the
decoder *cache* answers 0, and the two sums compare against `== 4`. So the part of each
that decides behaviour in this build is the read and the NULL test, and that part is
written verbatim in `src/provider/stores.rs`. The delegation body is not: the four stores
are `ossl_method_store_new(…)`'s (Phase 7 and 10), and `ossl_method_store_cache_flush_all`
and `_remove_all_provided` are 6.7c's, which 6.7 deferred to 6.8 and which has not landed.
Writing a plausible body there would be a stub that reads as evidence, which is the one
thing this project does not do; writing nothing would let a later stratum fill the slot
and silently flush nothing. What is written instead is the authority's branch guarded by
an `assert!` on the invariant, the same shape `create_provider_children` already uses, and
`the_five_slots_are_unfilled` turns the invariant into a unit test so a slot that moves
fails the test *before* the first activation reaches the assertion. `docs/PARITY_MODEL.md`
does not have a name for "a branch that is correct because it cannot be taken"; this is
the project's answer to it, and it is a *checked* construction rather than an assumed one.

**The authority's construction order is load-bearing, and the first version of the test
got it backwards.** `provider_init` runs from `provider_activate` **only while the
provider has no store**. A second activation of a storeless provider re-enters
`provider_init`, finds `flag_initialized` set, and is refused — non-fatally, because
`NDEBUG` makes `ossl_assert` `(x) != 0`, so the answer is 0 and not an abort. That means
`OSSL_PROVIDER_try_load_ex`'s order is not a detail: create storeless, activate **once**
while storeless (which is when init happens), *then* `ossl_provider_add_to_store`. The
test originally added the provider to the store first and then expected the count to
advance; it does not, and the failure was the test's, not the library's. The helper now
performs the authority's own sequence and says why, and the store is what makes a
*second* activation possible at all — so the same test pins both halves: storeless
activation counts once, and a stored provider's count runs 1, 2, 3.

**`ossl_provider_deactivate` is a deactivation, not a report.** The two functions one
wraps the other, and their conventions are **opposite and neither is `>= 1`**:
`provider_deactivate` answers the *resulting* activation count — so from four activations
the first call answers **3**, not 4 — and `-1` on failure, which is not a count and is why
its callers test `< 0`; `ossl_provider_deactivate` answers `count == 0 ? provider_remove_store_methods(prov) : 1`,
a boolean that on the transition to zero *is the store sweep's verdict*. The test asserted
`2` where the wrapper had already consumed one deactivation, which is the same class of
error as the load-order and address mistakes this project keeps finding: the instrument
before the subject. Both conventions are now pinned, including the `-1` edge.

**Three smaller things, each kept rather than tidied.** `assert(ref > 0)` in
`ossl_provider_doall_activated` is **compiled out** under this profile's `NDEBUG` — the
authority says so in a comment ("Not much we can do if this assert ever fails. So we don't
use `ossl_assert` here") — so emitting a live assertion would have been a divergence and
not a fidelity; the line is a comment where it would be. `provider_init`'s walk stores
eight provider-side dispatch pointers and every one is read back through a
`transmute::<*mut c_void, fn(…)>` whose signature is named beside it, which is the only
way a `dlsym`-shaped pointer can be called at all. And `(1u8 << (bitnum % 8)) & 0xFF` is
kept verbatim from the authority in both bitset functions with a `#[allow(clippy::identity_op)]`
naming the lint: the mask is redundant in both languages, and it is the line a reader
compares against `crypto/provider_core.c`.

**D113's rule applied twice more, and the first draft was wrong both times.**
`lib_ctx_get_data` is a **safe** function in this crate, so the nine `unsafe` blocks the
bridge module was written with were unnecessary — `unused_unsafe` said so, once per
bridge. And a raw-pointer *comparison* needs no block either: the eight
`unsafe { ctx == provctx_addr() }` markers in the test's own callbacks became plain
comparisons. The rule is not "unsafe functions are everywhere"; it is that a safe
function called from an `unsafe fn` needs nothing, and the compiler is the authority on
which is which.

**D115's arithmetic was right when it was written, and the total has moved twice since.**
D115's table records 19,800 observations at `1b850aa`. `RT-LIBCTX` moved 89 → 91 in
`7e97ed5` (6.8b-ii, when the core dispatch table landed) and the committed baseline has
read **19,802** from that commit onward. This commit does not move it: it adds no export,
so no court gains an observation and none loses one. Recorded because a number that
differs from the previous entry's table is otherwise indistinguishable from a regression,
and this project has decided it would rather explain a difference than have one that looks
like agreement (D33).

### Residuals this subphase makes observable, rather than closes

1. **The three predefined `init` pointers are NULL, so `default`, `base` and `null` cannot
   activate.** `provider_new` receives `None`, so `provider_init` takes the module branch,
   `DSO_load("libnull.so")` fails, and the activation fails. The consequence is measured
   rather than guessed — `a_builtin_without_an_entry_point_cannot_activate` pins `-1`, `0`
   and `0` for the three entry points — and it propagates: `ossl_provider_activate_fallbacks`
   answers 0, so `ossl_provider_doall_activated` answers 0 and `OSSL_PROVIDER_available`
   answers 0 for every name, where the authority answers 1 and 1. The test is written to
   **fail when 7/8 lands the pointers**, so the residual is retired deliberately instead of
   silently.
2. **The `random_bytes` guard pair is Phase 9's and is skipped.** The authority's
   `prov->random_bytes != NULL && !ossl_rand_check_random_provider_on_load(…)` is
   reachable for any provider that publishes `OSSL_FUNC_PROVIDER_RANDOM_BYTES`; the check
   is omitted in both activation functions and the omission is registered, not hidden.
   `ossl_provider_random_bytes` itself *is* written, because the pointer and the call are
   this stratum's — only its callers are Phase 9's.
3. **`create_provider_children` asserts the child-callback stack is empty.** 6.8e owns both
   the stack and the walk, so the authority's loop over an empty stack is what runs; the
   assertion is what makes "empty" a checked fact rather than an assumption, and
   `no_provider_child_callback_exists` checks it independently.
4. **`osl_decoder_cache_flush`'s absent-cache answer is 0, and both activation callers
   discard it.** That asymmetry with the other four bridges is deliberate and pinned by a
   unit test, because "make them all return 1" is the plausible simplification.

### Arithmetic

| | before | after |
|---|---|---|
| Phase 6 implemented / open | 117 / 44 | **117 / 44** (unchanged: no export declared yet) |
| `libcrypto` implemented / 5896 | 1091 | **1091** |
| phase courts / observations | 53 / 19,802 | **53 / 19,802** |
| unit tests | 250 | **257** |
| `err_sites.rs` coordinates | 830 | **830** |
| new internal modules | — | **`src/provider/activate.rs`, `src/provider/stores.rs`** |

## D117 — 6.8c closes: a nullable entry point the court caught, two aliases that named their parameters, and a shell that had not been rebuilt

**The twenty-two exports land with their court, and the registry stops being a slot sweep.**
`crypto/provider.c` whole plus the five `OSSL_PROVIDER_*` wrappers that live in
`provider_core.c` are declared in `src/provider/mod.rs`, in the same commit as
`RT-PROVIDER` — because the ledger counts a symbol as implemented the moment it is
defined, and declaring them a commit earlier would have moved twenty-two rows on evidence
that did not exist. Phase 6 moves from 117 implemented / 44 open to **139 / 22**;
`libcrypto` from 1091 to **1113** of 5896. `RT-PROVIDER` is the **54th** court and adds
**67 observations** with no residuals, so the five phase court sets total **54 courts and
19,869 observations**, all re-derived from the authority in this run. The FRF store is
recreated around it: 381 → **389** objects, 46 → **47** receipts, 92 → **94** challenges,
5 claims, `graph_verified`.

**A builtin provider is the one provider a probe can create on both sides, and that is what
makes this court possible.** The two libraries' own providers are each published by their own
`OSSL_provider_init`, so observing them would compare the probe's environment rather than the
registry. The probe instead declares its own entry point, registers it with
`OSSL_PROVIDER_add_builtin`, and drives the registry through the public API: register, load,
initialise, query, configure, enumerate, deactivate, unload, reload. The dispatch-table walk
inside `provider_init` is on that path and is therefore coursed by *using* it — the seven
`OSSL_FUNC_PROVIDER_*` entries the probe publishes are what the walk stores, and each is then
called back through the object. Two of them have an out-parameter (`query_operation`'s
`no_cache`) or a return the caller reads (`gettable_params`' table), so the pass-through is
visible in both directions and not only as NULL-ness.

**The court's one finding is a real one, and it is the kind no value-level probe of the
other twenty-one would have reached.** `add_builtin.null_init` answered **1** where the
authority answers **0**. The export had taken a bare `ProviderInitFn`, so a NULL entry point
became `Some(NULL)` and `ossl_provider_add_builtin`'s test — which the authority performs
*before* it allocates anything, so a refusal costs nothing — could not see it. A consumer
could register a builtin with no entry point and be told it succeeded. The parameter is now
`Option<ProviderInitFn>`: `ABI-PROTOTYPE` canonicalises `Option<F>` and `F` identically,
because a nullable function pointer and a bare one are the same type to a caller, so the
nullable spelling costs nothing and is the one the contract needs.

**`ABI-PROTOTYPE` then found a hole in itself, or rather in what it had been able to
reach.** It reported `type_unmapped: 2` for `OSSL_PROVIDER_add_builtin` and
`OSSL_PROVIDER_do_all`, and the failure was on the **Rust** side in both: the aliases
`ProviderInitFn` and `ProviderDoAllFn` named their parameters, and a named argument is not a
type, so the canonicaliser could not read them. Every function-pointer alias in this crate is
spelled unnamed for that reason; these two were not, and nothing noticed because neither had
ever appeared in an export's signature. The type plane went from 2 unmapped to **0**, with
`checked` 1044 → **1066** declarations and `type_checked` 1061 → **1083** types. The lesson is
sharper than "fix the aliases": an alias is unchecked until an export uses it, so the
*declaration* was never the thing that was verified — the *use* was.

**Four defects in the instrument, and one stale artefact that read as a divergence.** The
probe defined `_GNU_SOURCE` over the compiler's own `-D_GNU_SOURCE`; `OSSL_PARAM_construct_utf8_ptr`
takes `char **` and was handed a `char[64]`; `OSSL_PARAM_END` is a brace *initializer* and not
an expression, so assigning it needs `OSSL_PARAM_construct_end()`; and a label from an earlier
draft survived into the source. Then the court's first successful compile reported that the
**candidate** had called a `SCAFFOLDED` symbol — which reads exactly like the most serious
divergence there is, and was a stale shell: `implemented-surface.json` had been regenerated to
1113 but `build_phase2.sh` had not been re-run, so the DSO still carried the previous scaffold
list and exported a stub for `OSSL_PROVIDER_add_builtin`. The pipeline order documented in the
project's own notes has `implemented_surface` precede `build_phase2` for precisely this
reason, and this is what happens when it is not followed. Recorded because the *symptom* was a
candidate divergence and the *cause* was a build-order mistake: the probe, the generator and
the note are all suspects before the authority is, and here the suspect was the pipeline.

**The one thing `RT-PROVIDER` deliberately does not observe, and why that is a recorded
residual rather than a gap.** `provider_activate_fallbacks` loads the table's `is_fallback`
rows through their compiled-in entry points, and the candidate has none of them:
`ossl_default_provider_init` is 807 lines and belongs with the algorithm tables in Phases 7
and 8, so `provider_init` takes the *module* branch, the `DSO_load("libdefault.so")` fails, and
the walk answers 0 where the authority answers 1. Entered with the flag set, the walk would
make `ossl_provider_doall_activated` and `OSSL_PROVIDER_available` answer differently too.
The probe therefore **never puts the flag in its enabled state**: the first public call it
makes is `OSSL_PROVIDER_load`, which sets `store->use_fallbacks = 0` before it looks anything
up. From that point both sides take the walk's early return, and `available`, `do_all` and the
enumeration *are* compared — they would not be otherwise. So the disabled path is courted, the
enabled path is named rather than hidden, and a unit test pins the current failure so that the
day Phases 7 and 8 land the entry points the test fails and the residual is retired
deliberately instead of silently.

**One evidence-discipline finding, and it is the mechanism working.** `evidence_determinism`
and `check_evidence_portability` both went `STALE` on the **phase 3, 4 and 5** obligation
ledgers, because each records the sha256 of `forensics/atlas/implemented-surface.json` among
its inputs and that file had changed from 1091 to 1113 implemented symbols. The remedy is the
one the tools already prescribe — regenerate and commit, because the generators are the source
of truth — and all three were regenerated. A ledger that names its inputs is doing its job
when it goes stale; three of them going stale at once is the mechanism, not a defect.

### Arithmetic

| | before | after |
|---|---|---|
| Phase 6 implemented / open | 117 / 44 | **139 / 22** |
| `libcrypto` implemented / 5896 | 1091 | **1113** |
| phase courts / observations | 53 / 19,802 | **54 / 19,869** |
| Phase 6 courts | 6 | **7** |
| `ABI-PROTOTYPE` declarations / types checked | 1044 / 1061 | **1066 / 1083** |
| unit tests | 257 | **257** |
| `err_sites.rs` coordinates | 830 | **830** |
| FRF objects / receipts / challenges | 381 / 46 / 92 | **389 / 47 / 94** |

## D118 — 6.10 cannot precede 6.6e-ii: RCU's read path registers a thread-exit handler

**The documented order was 6.9, then 6.8a–6.8c, then 6.10. Re-deriving 6.10's dependency
set instead of trusting the column shows that order is wrong, and the correction moves
6.6e-ii onto the critical path ahead of it.** The measurement is a symbol sweep over the
four translation units 6.10 is made of — `conf_mod.c` (764), `conf_api.c` (214),
`conf_sap.c` (82), `conf_mall.c` (38) — against everything the crate defines. Of the 58
names that appear to be missing, most are naming rather than absence: `OPENSSL_malloc` is
`CRYPTO_malloc` here, `OPENSSL_free` is `CRYPTO_free`, and the fourteen `sk_CONF_*` /
`sk_CONF_VALUE_*` are the untyped `OPENSSL_sk_*` the crate already has. What is really
absent is three groups, and one of them is the finding.

**`ossl_rcu_read_lock` calls `ossl_init_thread_start`.** That is the whole of it. The RCU
implementation for this profile is `crypto/threads_pthread.c` — there is no `crypto/rcu.c` —
and its read path is not a counter bump: it allocates a per-thread `rcu_thr_data`, stores it
under `CRYPTO_THREAD_LOCAL_RCU_KEY` in the *lock's own context*, and then registers
`ossl_rcu_free_local_data` as a **thread-exit handler** so that data is released when the
thread stops. So RCU depends on the per-thread event-handler table, and the event-handler
table is 6.6e-ii. Since `CONF_modules_load` creates `module_list_lock` through
`ossl_rcu_lock_new(1, NULL)` and every `CONF_modules_*` entry point takes it, **6.10 cannot
be written before 6.6e-ii**. The order in this document is corrected to 6.9, 6.8a–6.8c,
**6.6e-ii**, 6.10, 6.8d–6.8f, 6.11, and 6.6e-ii's row no longer reads as an optional
remainder of the 6.6 series.

This is the third dependency cycle or inversion this planning pass has found in the same
column, after D114's 6.9/6.6g cycle and D97's 6.6f/6.8 siting, and it is the same lesson
each time: **a dependency column nobody re-derives is where they hide.** It is also worth
naming why this one was invisible. `conf_mod.c` names `ossl_rcu_*` and never names
`ossl_init_thread_start`; the dependency is one level down, inside `threads_pthread.c`. A
reader checking `conf_mod.c`'s own includes would not see it, and neither would a grep of
the file for thread-event machinery.

**The second group is the builtin-module fan-out, and it is why `OPENSSL_load_builtin_modules`
is not a list this stratum can complete.** `do_load_builtin_modules` runs once and calls
`OPENSSL_load_builtin_modules`, which registers one module per subsystem —
`ENGINE_add_conf_module`, `ASN1_add_oid_module`, the deprecated `EVP_add_alg_module`,
`ossl_provider_add_conf_module` (6.8d), `ossl_random_add_conf_module` (Phase 9) and
`ossl_config_add_ssl_module` (libssl). This profile has **ENGINE enabled** — `configdata.pm`
carries `engine` in its options and `"engine" => "1"` — so `ENGINE_load_builtin_engines` is
compiled in and called. Of the six, this stratum owns one (`ASN1_add_oid_module`), 6.8d owns
one, and four belong to later strata. So 6.10's registry is implementable, but
`OPENSSL_load_builtin_modules`'s *fan-out* is not, and a config file that names
`openssl_init` will observe the difference. That is a residual of the same shape as 6.8c's
predefined-provider one, and it is named rather than smoothed over: the honest construction
is a registry that registers the modules which exist and a recorded divergence for the ones
that do not, with a unit test that fails when each of them lands.

**The third group is small and fully this stratum's**: `CONF_modules_unload`'s
`sk_CONF_MODULE_pop_free(to_delete, module_free)` chain, `module_free`/`module_finish`'s
`DSO_free` and `finish` calls, and `ossl_config_modules_free`. Nothing missing there.

### Arithmetic

| | before | after |
|---|---|---|
| Phase 6 implemented / open | 139 / 22 | **139 / 22** (no source changed) |
| phase courts / observations | 54 / 19,869 | **54 / 19,869** |
| subphase order corrected | — | **6.6e-ii before 6.10** |

## D119 — 6.6e-ii's source lands: four call sites close, two divergences fall out of the tests, and the court follows

**The three exports are declared and Phase 6 moves 139/22 → 142/19**, `libcrypto`
1113 → **1116** of 5896. `crypto/initthread.c` becomes `src/runtime/thread_events.rs` — the
handler record, the global register of per-thread list heads, `destructor_key` as a sentinel
plus a key cell, `manage_thread_local` and its three spellings, the push/remove/destructor
trio, `init_thread_stop`, `init_thread_deregister`'s two modes, `ossl_init_thread`,
`ossl_cleanup_thread`, `ossl_init_thread_start`, `ossl_init_thread_deregister`,
`ossl_ctx_thread_stop` and both `OPENSSL_thread_stop` spellings — and `crypto/init.c`'s
`OPENSSL_atexit` joins `src/runtime/init.rs` with `stop_handlers` and the drain that
`OPENSSL_cleanup` now runs.

**`OPENSSL_USE_NODELETE` is defined in this profile, so `OPENSSL_atexit`'s DSO-pinning block
does not exist in the authority either.** `configdata.pm` records
`lib_cppflags => "-DOPENSSL_USE_NODELETE -DL_ENDIAN"`, and the block is guarded by
`#if !defined(OPENSSL_USE_NODELETE) && !defined(OPENSSL_NO_PINSHARED)`. So the Win32
`GetModuleHandleEx` route and the `DSO_dsobyaddr(handler, DSO_FLAG_NO_UNLOAD_ON_FREE)` route
are both compiled out and what remains is a three-line linked-list push. D118's plan called
for reading that profile fact rather than assuming it, and the answer removed the whole
supposed difficulty. The `DSO_dsobyaddr` that 6.9 landed is not needed here at all.

**Four call sites close.** `ossl_provider_free`'s `ossl_init_thread_deregister(prov)`, which
the provider module had carried as "the most important of the five named omissions" since
6.8a, and which the authority calls **unconditionally** because an init that *failed* may
still have registered a handler. `context_deinit`'s `ossl_ctx_thread_stop(ctx)`, named in
`src/context/mod.rs` since Phase 3. `CRYPTO_THREAD_init_local`'s `ossl_init_thread()`
preamble, whose absence the same function's doc comment recorded as "a later phase" — the
marker and the code are now the same paragraph. And `core_dispatch`'s
`OSSL_FUNC_CORE_THREAD_START`, published as id 3, which is the provider-facing spelling of
`ossl_init_thread_start` and the mechanism by which a third-party provider is told when a
thread stops.

**Two defects the unit tests found, and neither is a defect in the transcription.**

* **`D-TEVENT-REENTRANT-1`.** `init_thread_stop` calls the handler *while holding* the global
  register's write lock, so a handler that calls `ossl_init_thread_start` re-enters the lock.
  On the authority's pthread rwlock that is a **deadlock** — `pthread_rwlock_wrlock` on a
  same-thread write acquisition does not return — which the test discovered by observing that
  this crate's lock *refuses* it with 0. A hang inside thread teardown has no return value, no
  error-queue entry and no recovery, so it is recorded rather than reproduced, and the refusal
  is pinned.
* **`D-TEVENT-CTX-STOP-LEAK-1`.** `ossl_ctx_thread_stop` frees the list **head** after running
  only the handlers whose `arg` matches, so handler nodes registered for *other* contexts are
  left linked to a released block: leaked, and unreachable, because the thread local was
  cleared. A leak is defined behaviour rather than a fault, so this one **is** reproduced and
  claimed, and it is recorded so that a reader who finds it independently knows the candidate
  got it right rather than wrong.

**Two instrumentation lessons, both the same shape.** A `static CryptoOnce = 0` handed to
`pthread_once` **faults**: `pthread_once` writes through its argument and a bare `static`
lands in read-only storage. `OSSL_LIB_CTX_new()` segfaulted on the first run, and the crate's
own pattern (`AtomicI32` + `.as_ptr()`, as `context/mod.rs` already did) is the fix. And
`pthread_key_create` after a `pthread_key_delete` routinely returns the **same key number**,
and glibc does not clear the per-thread value array for it — so a re-created key can read the
old, freed value. That bit the tests that ran after the one test in this crate that calls
`OPENSSL_cleanup`, and it is why the test-only re-arm clears the thread local as well as the
two run-onces.

**`RT-THREADDATA` does not yet observe any of this, and 6.6e-ii is therefore not sealed.**
The three rows move because the ledger counts a symbol as implemented the moment it is
*defined* — that is the documented property of this project's arithmetic — while the *seal*
requires differential evidence, and the existing probe's 39 observations do not include the
handler table. The same commit that extends the probe will be the one that calls this row
complete, and the extension is named in `docs/PHASE-6-SUBPHASES.md`: a provider-mediated
`OSSL_FUNC_CORE_THREAD_START` registration, "the handler ran exactly once with its argument",
"a second stop is a no-op", and the `OPENSSL_atexit` drain observed around `OPENSSL_cleanup`.

### Arithmetic

| | before | after |
|---|---|---|
| Phase 6 implemented / open | 139 / 22 | **142 / 19** |
| `libcrypto` implemented / 5896 | 1113 | **1116** |
| `ABI-PROTOTYPE` declarations / types checked | 1066 / 1083 | **1069 / 1086** |
| unit tests | 257 | **262** |
| phase courts / observations | 54 / 19,869 | **54 / 19,869** (the probe is unchanged) |
| recorded divergences added | — | **`D-TEVENT-REENTRANT-1`, `D-TEVENT-CTX-STOP-LEAK-1`** |

## D120 — 6.6e-ii sealed: the probe that called the wrong dispatch entry, and `RT-THREADDATA`'s fifteen new observations

**`RT-THREADDATA` goes 39 → 54 observations with no residuals, and 6.6e-ii is complete.** The
five phases now total **54 courts and 19,884 observations**, all re-derived from the authority
in this run. The FRF store is rebuilt around it: 389 objects, **47 receipts**, **94
challenges**, 5 claims, 141 captures, 97 residuals, `graph_verified`.

**The first version of the extension failed on *both* sides, and the defect was the probe's.**
`OSSL_FUNC_core_thread_start(x)` is a **cast of the entry it is handed**, not a search:
`OSSL_CORE_MAKE_FUNC` expands to `return (OSSL_FUNC_##name##_fn *)opf->function;` with no loop
and no id test. Applied to `in` — the table's first entry — it asked `core_gettable_params` to
register a thread-stop handler and returned whatever the callee's `eax` happened to hold, so
the two sides printed two different large negative numbers. The fix is the walk the authority's
own providers do, and the lesson is already written down in `src/context/dispatch.rs`: *"a
plain cast of the given entry's function pointer, with no search."* It is worth recording that
the symptom pointed at the library and the cause was the instrument, for the third time in this
stratum — after D115's path-length comparison and D117's stale shell.

**What the fifteen observations actually establish.** That the core dispatch table publishes
**id 3** and the provider-facing accessor answers non-NULL — a compatibility fact, because a
provider compiled against a 3.x that has this entry would find NULL before 6.6e-ii. That the
registration answers the provider's own result rather than a value of the core's. That the
handler runs **exactly once** with the argument the *provider* registered, which is what proves
`core_thread_start`'s argument order (`handle, handfn, arg`) was not transposed against
`ossl_init_thread_start`'s (`index, arg, handfn`) — a transposition both are pointer-sized and
would compile. That a second `OPENSSL_thread_stop` runs nothing. And that `OPENSSL_cleanup`
drains two `OPENSSL_atexit` handlers in **LIFO** order *after* stopping this thread's handlers,
which is the authority's order inside that function.

**The record this closes, and the two it keeps.** `CRYPTO_THREAD_init_local`'s doc comment had
carried "the authority additionally initialises its global thread-event machinery here; that
machinery has no counterpart yet … a later phase" since Phase 3, and `src/provider/mod.rs` had
carried `ossl_init_thread_deregister(prov)` as "the most important of the five named omissions"
since 6.8a. Both are now calls. The two divergences D119 recorded —
`D-TEVENT-REENTRANT-1` and `D-TEVENT-CTX-STOP-LEAK-1` — stand, each with the unit test that
pins it; neither is exercised by this court, because neither is reachable from a probe that
behaves.

### Arithmetic

| | before | after |
|---|---|---|
| Phase 6 implemented / open | 142 / 19 | **142 / 19** (unchanged: the court observes, it does not implement) |
| `RT-THREADDATA` observations | 39 | **54** |
| phase courts / observations | 54 / 19,869 | **54 / 19,884** |
| probe_hygiene | clean (43 probes) | **clean (43 probes)** |
| FRF objects / receipts / challenges | 389 / 47 / 94 | **389 / 47 / 94** (rebuilt, same counts) |

## D121 — 6.10 splits four ways, and its first part is RCU

**Consequence of D118, written down because 6.10 is the largest remaining block in the
stratum and the next session should not re-derive its shape.** Phase 6 stands at **142
implemented / 19 open** with 6.6e-ii sealed; the nineteen are 6.10's seventeen and the two
`OSSL_LIB_CTX` exports of 6.6d/6.6g.

**6.10a — the RCU layer.** `ossl_rcu_lock_new`, `_lock_free`, `_read_lock`, `_read_unlock`,
`_write_lock`, `_write_unlock`, `synchronize_rcu`, `cb_item_new`, `cb_item_free`, `rcu_call`,
`uptr_deref` and `assign_uptr`, over `crypto/threads_pthread.c`. The structures are
`rcu_lock_st` (a callback list, the owning context, the quiescent-point array and its six
indices, three mutexes and two condition variables), `rcu_qp { uint64_t users; }`,
`thread_qp { qp, depth, lock }` and `rcu_thr_data { thread_qp[10] }` with `MAX_QPS 10`. The
read path stores that per-thread state under `CRYPTO_THREAD_LOCAL_RCU_KEY` **in the lock's
own context** and registers `ossl_rcu_free_local_data` as a thread-exit handler — which is
D118's finding, and the reason 6.6e-ii had to land first. `get_hold_current_qp` is a re-try
loop over `reader_idx`; `ossl_synchronize_rcu` waits for in-order retirement on
`prior_signal` and then for the reader count to reach zero.

**This part is a transcription rather than a design, because the primitives already exist.**
`src/runtime/thread.rs` carries `ossl_crypto_condvar_*` over `pthread_mutex_t` and
`pthread_cond_t`, which is what the authority's RCU is built on. The search that established
this is the same one that would have been made anyway; recording it here means the next
session starts by writing the file rather than by asking whether it can.

**6.10b — the registry.** `conf_mod.c`'s fifteen exports plus `ossl_config_modules_free`,
over `supported_modules` and `initialized_modules`: two `STACK_OF` pointers that are *copied,
modified and swapped* under the RCU write lock, which is why the two parts are not one.
`module_find`'s truncation at the last `.` is the behaviour worth its own observation — a
module named `modname.XXXX` matches `modname`, so the same module can be initialised more
than once.

**6.10c — `conf_sap.c` and `conf_mall.c`**, which is where `OPENSSL_config`/`OPENSSL_no_config`
and the default-method initialiser live, and therefore where the builtin-module fan-out is.

**6.10d — `ASN1_add_oid_module`**, the one of the six builtin modules this stratum owns.

**The fan-out is a recorded residual, measured rather than assumed.** `OPENSSL_load_builtin_modules`
registers six modules: `ENGINE_add_conf_module` and `ENGINE_load_builtin_engines` (ENGINE's,
and **ENGINE is enabled in this profile** — `configdata.pm` carries `engine` in its options
and `"engine" => "1"`), `ossl_provider_add_conf_module` (6.8d), `ossl_random_add_conf_module`
(Phase 9), the deprecated `EVP_add_alg_module` (Phase 7) and `ossl_config_add_ssl_module`
(libssl's). The registry registers the ones that exist and names the ones that do not, and a
config file naming `openssl_init` observes the difference. **`RT-CONF-MOD` is the court.**

### Arithmetic

| | before | after |
|---|---|---|
| Phase 6 implemented / open | 142 / 19 | **142 / 19** (no source changed) |
| subphases named | 6.10 | **6.10a–6.10d** |

## D122 — 6.10a is three units, not one: the `_ex` thread-local family and the sparse array underneath it

**D121 said 6.10a was "a transcription rather than a design", and it was right about the
nature of the work and wrong about its size, because it missed two units.** Following the RCU
read path to its ends lands on `CRYPTO_THREAD_get_local_ex(CRYPTO_THREAD_LOCAL_RCU_KEY,
lock->ctx)` — and that function is not in `crypto/threads_pthread.c`, which is where D121
looked. It is `crypto/threads_common.c`, **414 lines**, added upstream in 2025 and used by
`crypto/err/err.c`, `crypto/rand/rand_lib.c`, `crypto/rsa/rsa_ossl.c` and
`crypto/async/async.c` as well as by RCU. It is the *per-context* thread-local family: one
operating-system key per process, a fixed array indexed by an eight-value key id, and under
each of those a **sparse array indexed by the libctx pointer cast to `uintptr_t`** — a lookup
that is legitimate precisely because libctx pointers are unique. Its destructor is
`clean_master_key`, which releases every table and the fixed array.

The sparse array is `crypto/sparse_array.c`, **216 lines**, with `DEFINE_SPARSE_ARRAY_OF`
generating `new`/`get`/`set`/`free` per element type. The crate has **no** sparse array at
all, which is why this is a prerequisite rather than a detail: `threads_common.c` cannot be
written without it.

**So 6.10a splits three ways, and the order is forced:**

* **6.10a-i — the sparse array**, `crypto/sparse_array.c`. 216 lines, no dependencies beyond
  allocation, and the only thing in the chain that can be tested on its own.
* **6.10a-ii — the `_ex` thread-local family**, `crypto/threads_common.c`: `master_key` as a
  `CRYPTO_THREAD_LOCAL` with its own `RUN_ONCE`, `master_key_init` as the flag the destructor
  reads, `MASTER_KEY_ENTRY` as a one-field wrapper over the sparse array, `clean_master_key_id`,
  `clean_master_key`, `init_master_key`, `CRYPTO_THREAD_get_local_ex`,
  `CRYPTO_THREAD_set_local_ex` and `CRYPTO_THREAD_clean_local`. Note the two subtleties the
  file states in its own comments: `master_key_init` exists because an uninitialised key would
  otherwise return garbage in the destructor, and `CRYPTO_THREAD_run_once` is used rather than
  the `RUN_ONCE` macro because the same source is compiled into the FIPS provider, where
  `RUN_ONCE` is suppressed. `CRYPTO_THREAD_NO_CONTEXT` is `(void *)1`, not NULL, and is folded
  to NULL before the concrete-context resolution.
* **6.10a-iii — RCU**, `crypto/threads_pthread.c`'s section, as D121 described it.

**This is the fourth dependency the planning pass did not see, and the pattern is now
established**: D114's 6.9/6.6g cycle, D97's 6.6f/6.8 siting, D118's RCU-to-`ossl_init_thread_start`
edge, and this one — a chain that is invisible from the file that names its first link. Each
was found by following the *call* rather than the *include*, which is the only method that has
worked. It is also why the estimate for 6.10 has to be stated in units rather than in
subphases: 6.10a alone is roughly a thousand lines of C across three files.

**One thing this turns up that is not 6.10's business, and is worth naming so it is not
forgotten.** `crypto/err/err.c` uses `CRYPTO_THREAD_LOCAL_ERR_KEY` from this same family, and
Phase 3's ERR is complete — so either the crate's error queue keeps its thread-local a
different way, or there is a 2025-era upstream change that Phase 3's archaeology did not see
because it read `err.c` at a different moment. The Phase 3 seal's ERR section should be read
against the current `err.c` before Phase 7 depends on the error queue further. Recorded as an
open item rather than investigated here, because investigating it is not 6.10a-iii's job and
guessing at the answer would be worse than leaving the question.

### Arithmetic

| | before | after |
|---|---|---|
| Phase 6 implemented / open | 142 / 19 | **142 / 19** (no source changed) |
| 6.10a | one unit | **three units: `sparse_array.c` (216), `threads_common.c` (414), RCU (~380)** |

## D123 — the prerequisite gate, its first run's two findings, and the two defects the tool had itself

**D122 ended by naming a chain that had been invisible from the file that names its first
link, and by pointing at the general problem: four dependency inversions have now been found
in this stratum, every one by hand, and none by a tool.** This is the tool. It is what
"ensure item 4 is included" asked for, and it is the last piece of Phase 6 infrastructure
before 6.10a-iii.

### Why an export atlas cannot see a prerequisite

Every atlas this project had before this one is a projection of the authority's **exported**
surface: `symbol-ownership.json` over the 6,499 DSO exports, `functions.json` over the 7,485
functions the installed headers declare, `macros.json` over the 16,805 macros those same
headers define. That is the right universe for a compatibility claim and the wrong universe
for a prerequisite. `crypto/conf/conf_mod.c` cannot be written without `ossl_rcu_lock_new`,
and `ossl_rcu_lock_new` is not exported, is declared in no installed header, and therefore
appeared in no artefact at all.

So four artefacts were added, and each covers a family the others cannot:

| artefact | universe | source |
|---|---|---|
| `atlas/internal-symbols.json` | **4,547** non-exported functions, each with the translation unit that defines it | the authority's build tree: 2,201 objects, one per unit per link form |
| `atlas/macro-owners.json` | **19,839** macros and enum members, installed and internal | `macros.json` plus a `#define`/`enum` scan of the non-installed headers |
| `atlas/typedef-owners.json` | **1,568** type names | `typedefs.json` plus a `typedef` scan of the same headers |
| `atlas/transcription-edges.json` | which authority unit each of **120 crate modules** transcribes, and what that unit references | measured from the symbols the module defines, not read out of its prose |

`transcription-edges.json` is the one that had to be committed. The mapping it records — the
dominant authority translation unit among the symbols a module defines — is a measurement,
and the identifiers of that unit are exactly what direction B below needs; committing them is
what lets the gate run in the static CI job, where no authority tree exists. The court job
re-derives the file and requires `git diff --exit-code` over it, so the committed copy cannot
drift.

### What it checks

* **A — `undefined_prerequisite`.** A name the crate references, in the internal function,
  macro, enumerator or typedef universe, that the crate does not build and no record has
  agreed to build.
* **B — `unwired_function_in_the_current_stratum`.** An authority internal function a
  transcribed unit calls, that the crate has no module for, in a unit whose own stratum is
  still open.
* **C — the sealed census.** The same for a stratum that has already sealed: **59 names over
  21 defining units**. Reported and *not* a failure, because each is either modelled
  differently by the crate or is work a later stratum carried across the boundary, and which
  of the two is a decision rather than a repair. What keeps that from becoming a hiding place
  is that `regression_guard.py` now holds the count to non-increase.
* **D — the records.** `forensics/prerequisites.json` carries deferrals (work with a named
  owner stratum) and divergences (a difference the crate intends). A divergence's `covers`
  list is checked in **both** directions: a covered name the gate did not observe is a
  failure, and an observed name no record covers is a finding. Suppression cannot be silent,
  and a record cannot quietly widen — a record that kept covering a name the crate has since
  fixed would be hiding the next one.

The C **language** surface is counted and listed but never failed: the crate models C types,
macros and reason codes differently on purpose (`BIO_ADDR` is a Rust type with a private
layout, `ERR_R_CRYPTO_LIB` is an entry in a generated table), and a lexical scan cannot tell a
rename from a gap. 2,067 such names are recorded. Saying so is the point: a gate that guessed
here would either be noise or would legitimise a rename.

### The first run's findings, verbatim

The gate's first run reported two classes and nothing else.

```
[undefined_prerequisite] 16
    F, arg, cb_arg, in, inlen, libctx, now, out_len, outlen, src, stderr, type, u16, u32, u64, u8
[unwired_function_in_the_current_stratum] 82
    crypto/initthread.c -> CRYPTO_THREAD_clean_local (src/runtime/threads_common.rs, phase 6)
    crypto/threads_common.c -> CRYPTO_THREAD_clean_local (src/runtime/threads_common.rs, phase 6)
    ... and the libctx accessors, the method store, the child-provider link, the directories
        and the EVP fetch path
```

* **`CRYPTO_THREAD_clean_local` is the real one, and it is fixed here.** The crate defines the
  function — as `threads_common::clean_local` — and called it from nowhere. `crypto/initthread.c`'s
  `OPENSSL_thread_stop` ends with `CRYPTO_THREAD_clean_local()`, the crate's version did not, and
  no scan of the crate alone could have seen it: the crate's identifier and the authority's name
  are different and the call was simply absent. `OPENSSL_thread_stop` now calls it, and
  `a_thread_stop_drops_the_per_context_thread_locals` pins the *consequence* — a value stored
  under `CRYPTO_THREAD_LOCAL_ASYNC_CTX_KEY` is gone after the stop — rather than the call.
* **The 16 `undefined_prerequisite` names are a collision class, not 16 defects.** Each is a name
  the authority's *non-installed* headers introduce — `#define F(x)` in `md4_local.h`,
  `u8`/`u16`/`u32`/`u64` in `aes_local.h`, macro-body and parameter names in
  `include/internal/list.h` and `sha3.h` — and each also appears in this crate as an ordinary Rust
  identifier: a generic parameter, a local binding, a width alias. A lexical scan of either side
  cannot separate those two facts, so they are recorded as a class rather than matched away: a
  matcher tuned to drop `u8` would also drop a real collision. The list is held exact, so a new
  member has to be looked at.
* Every other name from that run now has a row: **45 deferrals** with a named owning stratum and
  a citation (the twelve RCU names to 6.10a-iii, four to 6.10b/c, the method store to 6.7c/6.8,
  the child-provider link to 6.8e, the directories to Phase 16, the EVP fetch path to Phase 7)
  and **five divergence rows** covering 31 names.

### The tool had two defects of its own, and both were the class it exists to find

Worth recording because D105's lesson is that **the probe, the generator and the note are all
suspects before the authority is**:

1. **The reference cleaner mis-paired an apostrophe and blanked 7 KB of `src/property/parse.rs`.**
   `strip_rust` treated `'` as the start of a character literal, so `// ... this module's
   comparator` opened a "string" that ran to the next real quote 7,000 characters later. The
   result was a definition reported as missing, i.e. a false prerequisite. Rust is unambiguous
   here — `'` opens a literal only as `'x'`, `'\n'` or `'\u{…}'`, and is a lifetime otherwise —
   and the cleaner now distinguishes them. It also **fails loudly** if any blanked span contains
   `\nfn `, `\npub `, `\nunsafe `, `\nimpl `, `\n}` or `\n#[`, which cannot appear inside a comment
   or a string: that is the signature of a mis-pairing, and a cleaner that hides a prerequisite is
   worse than no cleaner.
2. **The definition scan could not see `extern "C" fn name(`.** One lens was used for both
   questions, and blanking string literals — which the *reference* scan needs, so that a
   `c"ossl_parse_property"` reason-site table is not read as a use — also blanked the `"C"` in the
   definition form almost every export in this crate is written in. There are now two lenses: a
   reference is blind to comments and strings, a definition is blind only to comments.

A third defect was in the *artefact*, not the gate: `scan_typedefs` read `typedef` statements out
of macro **bodies**, and `include/internal/list.h`'s `DEFINE_LIST_OF(name, type)` therefore
contributed `name` and `type` to the type universe, from which they became missing prerequisites.
Macro bodies are now blanked before the typedef scan.

### Arithmetic

| | before | after |
|---|---|---|
| Phase 6 implemented / open | 142 / 19 | **142 / 19** (`clean_local` is an internal, so no ledger row moved) |
| atlas artefacts | 12 | **17** |
| prerequisite findings | — | **0** |
| sealed-stratum census / language census / planned | — | **59 / 2,067 / 71** |
| prerequisite divergence rows / names covered | — | **5 / 31** |
| CI gates | 13 | **15** (the gate, and the weak-tier atlas check) |

## D124 — 6.10a-iii lands: the RCU layer, four recorded divergences, and the defect the tests found

**6.10a is now complete**, and with it the last unit of Phase 6's infrastructure that stood
between the stratum and its seventeen remaining exports. `src/runtime/rcu.rs` transcribes
`crypto/threads_pthread.c`'s RCU section — 12 functions and 5 statics over 380 lines of C —
and brings `crypto/conf/conf_mod.c` within reach.

### What the file's own comments say, and why each is load-bearing

**A quiescent point is a counter.** `struct rcu_qp` is a `uint64_t` and nothing else, so the
read side's entire cost is one `Acquire` add. `get_hold_current_qp`'s retry loop is what makes
that race-free: it adds to the point `reader_idx` named, re-reads `reader_idx` with `Acquire`,
and if the index moved subtracts with `Relaxed` and starts again. **The atomics are
order-for-order the authority's** — `Relaxed` for the first load and the compensating
decrement, `Acquire` for the increment and the confirming re-read, `Release` for the reader's
final decrement, and `Release` for both the writer's `reader_idx` store and the zero-add that
follows it. `__atomic_add_fetch` answers the *new* value where Rust's `fetch_add` answers the
old, so the two sites that use it are written as `fetch_add` plus the macro's arithmetic,
marked `wrapping_*` because the C is unsigned and wraps.

**Retirement is in order, and the order is a counter rather than a queue.** `update_qp` hands
out `id_ctr`; `ossl_synchronize_rcu` waits on `prior_signal` until `next_to_retire` equals the
id it was given, *and only then* examines the reader count. So a slow writer cannot let a fast
one reclaim a point a reader has not left.

**The per-thread bookkeeping is collective.** `rcu_thr_data` holds ten `thread_qp` slots, each
naming its lock, and it lives under `CRYPTO_THREAD_LOCAL_RCU_KEY` in the lock's own context —
so a thread holding two locks from two contexts keeps two arrays — and it is released by a
thread-stop handler rather than by a key destructor of its own. That is D118's chain: this file
could not be written before 6.6e-ii's handler table and 6.10a-ii's `_ex` family, and the reason
6.10a was three units rather than one (D122).

### Four places the transcription is deliberately not literal

1. **The mutexes and condition variables are handles, not embedded objects.** The authority
   embeds three `pthread_mutex_t` and two `pthread_cond_t` in `struct rcu_lock_st`; this
   crate's equivalents are opaque heap handles, so the struct holds pointers and
   `ossl_rcu_lock_new` allocates five objects instead of one. Unobservable: `rcu_lock_st` is
   `typedef`d opaque in `include/internal/rcu.h`, RCU exports no symbol, and its only consumer
   is in this crate.
2. **`ossl_rcu_lock_new`'s unwind uses two arrays of what was created rather than reading the
   struct's fields back.** The C tracks the successful `pthread_*_init` calls in
   `mutexes[3]`/`conds[2]`; this keeps the same information in the same shape. **The failure it
   unwinds is unreachable here**, because this crate's constructors box and cannot fail; the
   unwind is written out anyway, for the day that stops being true.
3. **`get_hold_current_qp`'s first `Relaxed` load is a plain `AtomicU32` load rather than an
   `ATOMIC_LOAD_N` macro**, which is what the macro expands to on this profile — the file's
   fallback path exists for compilers without `__atomic_*`, and this profile has them.
4. **The drain loop is a `while` over the list rather than the same `while` with a `goto`-free
   local.** No behavioural difference; noted so a reader comparing the two does not look for
   one.

### Four divergences, recorded in `docs/SECURITY_DIVERGENCE_POLICY.md`

The three faults are all in `ossl_rcu_read_lock`/`_read_unlock`, and the interesting part is
that the authority behaves *differently* on three paths that look alike:

| entry | obligation | authority | candidate |
|---|---|---|---|
| `D-RCU-1` | an eleventh distinct lock held at once | `assert` compiled out under `NDEBUG`; writes through `thread_qps[-1]` | answers 0 |
| `D-RCU-2` | an unlock with no thread data | `assert` compiled out; dereferences NULL | returns |
| `D-RCU-3` | an over-unlock (count below zero) | `OPENSSL_assert` is **active** and calls `OPENSSL_die` | restores the count to zero and clears the slot |

`D-RCU-3` is the one worth reading: `OPENSSL_assert` in `crypto.h.in` is not `NDEBUG`-gated,
so the authority checks *this* case with a fatal abort and does not check the other two at all.
The candidate answers all three, because a library aborting its caller's process is what
`docs/UNSAFE.md` §3 says must not happen.

**`D-RCU-4` is not a divergence but a limitation, and it is recorded as one.** The whole family
is declared in a non-installed header, none of the 6,499 exports resolves to any of the twelve
names, and the only caller in the build is `crypto/conf/conf_mod.c`. **So there is no way to
write a differential court for RCU today**: a probe compares two libraries across the exported
surface, and RCU is not on it. What stands in its place is the transcription plus ten unit
tests, two of which spawn threads — one pinning that a reader on *another* thread holds
retirement off (the writer's completion is observed, never timed, and the 50 ms wait is in the
safe direction: a slower machine only widens the window the assertion inspects), the other that
the per-thread data survives an explicit thread stop and is rebuilt on the next hold. That is
**weaker than a court and it is stated as weaker**: RCU is `IMPLEMENTED` and not
`PARITY_VERIFIED`, and `RT-CONF-MOD` is the court that will exercise it end to end.

### The defect the tests found

`ossl_rcu_read_lock` allocated the thread data, stored it under the key, registered the
handler — and never bound it to the local the walk below used, so the walk ran against the NULL
the lookup had answered. `a_read_hold_counts_once_and_a_re_entrant_hold_counts_depth` caught it
on the first run as a null dereference. It is the third defect in two commits that a *unit test*
found before a court could exist, and the reason the module doc says what the tests can and
cannot pin: the retry loop and the two condition-variable waits only fire under contention, and
two tests exist solely because of that.

### The prerequisite gate did its job twice

Both directions fired, unprompted, on the first run after the change:

* Its `stale_deferral` class refused the twelve `ossl_rcu_*` names the moment the crate defined
  them, which is what retired those twelve rows from `forensics/prerequisites.json` — a
  deferral is a promise, and this is the mechanism that makes the promise come due.
* It reported one *new* `undefined_prerequisite`: `sleep`, because the threaded test says
  `thread::sleep` and the authority defines a `sleep` wrapper in `include/internal/e_os.h`. That
  is the class the row `shadowed_by_a_crate_identifier` exists for, and it now covers 18 names.

### Arithmetic

| | before | after |
|---|---|---|
| Phase 6 implemented / open | 142 / 19 | **142 / 19** (RCU exports nothing, so no ledger row moved) |
| 6.10a units landed | 2 of 3 | **3 of 3** |
| Phase 6 modules named as evidence | 7 | **40** |
| unit tests | 274 | **284** |
| prerequisite planned census | 71 | **52** |
| prerequisite blocking dependencies | 45 | **33** |
| prerequisite divergence names | 31 | **32** |
| recorded divergences in the policy | 32 | **36** (`D-RCU-1`..`D-RCU-4`) |
| courts / observations | 54 / 19,884 | **54 / 19,884** (unchanged) |

## D125 — 6.10b/c/d measured: the eleven facts the next session should not re-derive

**D121 split 6.10 into four parts and D122 split its first into three. This is the
reconnaissance for the remaining three, read out of the authority rather than assumed, so
that writing them is transcription rather than archaeology.** Phase 6 stands at **142
implemented / 19 open**: the 17 this block closes and the two `OSSL_LIB_CTX` exports.

### What each part is, confirmed line by line

* **6.10b — `crypto/conf/conf_mod.c`, 764 lines.** `supported_modules` and
  `initialized_modules` are two `STACK_OF` **pointers**, and every mutation is
  copy-modify-swap under the RCU write lock: `sk_CONF_*_dup(old)`, push, `ossl_rcu_assign_ptr`,
  `ossl_rcu_write_unlock`, `ossl_synchronize_rcu`, *then* `sk_CONF_*_free(old)`. The `sk_dup`
  is **shallow** — it copies the array of pointers and nothing behind them — which is why
  freeing the old handle after the synchronize is correct and not a double free.
* **6.10c — `crypto/conf/conf_sap.c` (82) and `conf_mall.c` (38).** `ossl_config_int` is
  gated by a file-static `openssl_configured` that **is set even on failure**, so the second
  call is a no-op regardless of the first's result. `ossl_no_config_int` sets the same flag
  and nothing else. `OPENSSL_config` and `OPENSSL_no_config` are already written in
  `src/runtime/conf/sap.rs` and already route through `OPENSSL_init_crypto`.
* **6.10d — `ASN1_add_oid_module`**, in `crypto/asn1/asn_moid.c`, is four lines over
  `CONF_module_add("oid_section", oid_module_init, oid_module_finish)`; its handler parses a
  section with `NCONF_get_section` and calls `OBJ_create` per entry, and its finish is
  `OBJ_cleanup`. **Both `OBJ_*` are Phase 3's and are implemented**, so once `CONF_module_add`
  exists this is a transcription, not a build.

### Eleven measured facts, each of which would otherwise be re-derived or got wrong

1. **The profile is `no-trace`.** `OSSL_TRACE1(CONF, ...)` at `conf_mod.c:157` and
   `OSSL_TRACE3` at `:177` are **compiled out** (`OPENSSL_NO_TRACE`, recorded in
   `src/runtime/trace.rs`). Three lines of the transcription do not exist; a reader comparing
   the two files should not go looking for them.
2. **`OPENSSL_strdup` is a macro, not a function.** `crypto.h.in` defines it as
   `CRYPTO_strdup(str, OPENSSL_FILE, OPENSSL_LINE)`, so each of `conf_mod.c`'s three call sites
   is `CRYPTO_strdup(s, "../../crypto/conf/conf_mod.c", <the line of the call>)` — lines 362,
   445 and 446 — and the coordinates are the *call site's*, not the macro's.
3. **The raise sites are already generated.** `src/runtime/err_sites.rs` carries sixteen
   entries for `conf_mod.c`, including the four this block needs: `CONF_R_OPENSSL_CONF_REFERENCES_MISSING_SECTION`
   at `:163`, `CONF_R_UNKNOWN_MODULE_NAME` at `:276`, `CONF_R_MODULE_INITIALIZATION_ERROR` at
   `:286`, and the `errcode`-driven pair (`CONF_R_ERROR_LOADING_DSO`, `CONF_R_MISSING_INIT_FUNCTION`)
   at `:331`. **Nothing here is typed by hand.**
4. **`ASN1_add_stable_module` is Phase 11's, not this block's.** Phase 5 deferred it to phase
   11 because its handler needs `X509V3_parse_list`; the phase-6 ledger does not list it, and
   that is correct rather than a hole — checked in both directions before writing this.
5. **`OPENSSL_load_builtin_modules` calls seven, and four of them are other phases'.** In
   order: `ASN1_add_oid_module` (6.10d), `ASN1_add_stable_module` (Phase 11),
   `ENGINE_add_conf_module` (Phase 13, and **ENGINE is enabled in this profile**),
   `EVP_add_alg_module` (Phase 7), `ossl_config_add_ssl_module` (libssl, Phase 14),
   `ossl_provider_add_conf_module` (6.8d) and `ossl_random_add_conf_module` (Phase 9). The
   function is written in this block and calls the ones that exist; each of the others is a
   **recorded divergence**, because a config file naming them registers nothing here — which
   D121 already recorded as the fan-out residual and which `RT-CONF-MOD` observes.
6. **`module_find` truncates at the *last* dot and compares with `strncmp` of that length.**
   `modname.XXXX` therefore matches `modname`, and a name of `.foo` has length **0**, so it
   matches the **first** registered module. That second case is worth a court observation
   rather than a comment: it is reachable through a config file and it is not obviously the
   intent.
7. **`module_init`'s failure arm calls `pmod->finish(imod)` only when `init_called`.**
   `links++` happens after the push and before the swap; `module_finish` does `links--`.
8. **`conf_modules_finish_int` returns 0 when `module_list_lock == NULL`** — the authority's
   own comment: *"If module_list_lock is NULL here it means we were already unloaded"*. So
   `CONF_modules_unload` after `ossl_config_modules_free` returns early rather than faulting.
9. **`ossl_config_modules_free` is `CONF_modules_unload(1)` followed by `module_lists_free()`**,
   which frees the RCU lock and NULLs both lists. It is called from `OPENSSL_cleanup`, so the
   teardown order there is fixed by it.
10. **`module_load_dso` reads the module section for `path` before falling back to the name**,
    and its error path raises with `errcode` set by which of three steps failed — so the
    reason code is a *variable*, which is what fact 3's "the `errcode`-driven pair" means.
11. **The RCU client is exactly two lists and one `1`.** `ossl_rcu_lock_new(1, NULL)` at
    `conf_mod.c:102` — the clamp to two is reached by the only caller in the build — and every
    read of a list goes through `ossl_rcu_deref` inside a read lock, so `D-RCU-4`'s
    consequence narrows to "courted only through this consumer" the moment `RT-CONF-MOD`
    exists.

### Order, and why it is this order

**6.10b, then 6.10d, then 6.10c, then `OPENSSL_load_builtin_modules`, then 6.8d.** The
registry is the prerequisite of everything else in the block: `ASN1_add_oid_module` needs
`CONF_module_add`, and `CONF_modules_load` is what 6.10c's `ossl_config_int` calls.
`OPENSSL_load_builtin_modules` needs 6.10d for one of its seven callees, so it follows 6.10d.
**6.8d (`provider_conf.c`) then closes 6.10's own residual**, because
`ossl_provider_add_conf_module` is one of the two functions `OPENSSL_load_builtin_modules`
calls and 6.8d is where it lives.

### The court

**`RT-CONF-MOD`**, and it is a differential court rather than a unit test, because every one
of these seventeen symbols is an export. The observations that matter, in the order they
become reachable:

* `OPENSSL_load_builtin_modules` twice registers each module once (`sk_*_dup` instead of a
  second add) — the authority's stack is append-only here, so the observable is the *count*;
* `CONF_module_add` with a name containing a dot, and `module_find`'s prefix match;
* `CONF_modules_load` with no `openssl_conf` key returns **1**, which is the "nothing to do"
  answer and not an error;
* `CONF_modules_load` with `config_diagnostics` set clears the four ignore flags, which is
  observable by loading a config that names an unknown module: the same file answers 1 with
  the flags and a negative with the setting;
* `CONF_modules_load_file` on a missing file answers 1 under `CONF_MFLAGS_IGNORE_MISSING_FILE`
  and 0 without it;
* `CONF_imodule_*`'s six accessors across a module that the init function set `usr_data` and
  `flags` on, including the `flags` round trip;
* `CONF_modules_unload(1)` twice, and `CONF_modules_finish` after `ossl_config_modules_free`,
  which is fact 8's early return;
* and the `oid_section` path end to end: a config with an `oid_section` naming a section whose
  entries are OIDs, `OPENSSL_load_builtin_modules`, `CONF_modules_load`, and
  `OBJ_txt2nid` answering the created NID afterwards.

### Arithmetic

| | before | after |
|---|---|---|
| Phase 6 implemented / open | 142 / 19 | **142 / 19** (no source changed) |
| the block's parts | 6.10a–6.10d named | **6.10a landed; b, c and d measured to the line, with the eleven facts above fixed** |
| facts that were going to be guessed | — | **11 recorded, of which 3 are build-profile facts and 1 was a suspected hole that is not one** |

## D126 — 6.10b's first attempt, discarded, and the four things it proved must be looked up first

**A first transcription of `conf_mod.c` was composed and then deleted rather than committed, and
that is the record.** It was ~1,000 lines of Rust covering the registry, the copy-modify-swap
discipline, the DSO path and all sixteen exports, and it referenced **ten identifiers that were
guessed rather than read**: six `err_sites::ERR_RAISE_SITES_*` constants, `str.rs::strncmp`,
`obj.rs::NID_undef`, `ctype.rs::ossl_isspace`, and two `ERR_*` spellings. Nine of the ten were
wrong or absent. The staging branch stayed green because nothing was pushed, and the attempt is
recorded here rather than in the tree because **a transcription whose error coordinates are
invented is not a transcription** — it is the shape of one, and it would have been reviewed as
if it were real.

**D125's eleven facts came out of reading the authority. These four came out of *trying to
write* it, and they are the ones that cost the attempt.**

1. **The raise-site constants are generated, and their names are `CONF_MOD_<line>`.**
   `src/runtime/err_sites.rs` has exactly four entries for `conf_mod.c` — `CONF_MOD_104`
   (`do_init_module_list_lock`, `ERR_R_CRYPTO_LIB`), `CONF_MOD_163`
   (`CONF_R_OPENSSL_CONF_REFERENCES_MISSING_SECTION`), `CONF_MOD_276`
   (`CONF_R_UNKNOWN_MODULE_NAME`) and `CONF_MOD_286`
   (`CONF_R_MODULE_INITIALIZATION_ERROR`) — each carrying `file`, `line`, `func`, `lib`,
   `reason` and `dynamic_reason`. The naming rule is the header stem and the line, so **a
   raise site is never typed and never guessed**: the generator's own name is looked up. That
   is D123's `err_sites` note applied, and it is the class of mistake that survives review
   because a plausible-looking constant name reads like evidence.
2. **`conf_mod.c:331`'s raise is the one with a variable reason**, `ERR_raise_data(ERR_LIB_CONF,
   errcode, ...)` where `errcode` is set by which of three steps failed. The artefact carries
   **79** sites with `dynamic_reason: true`, so the shape exists; whether this specific site is
   among them is the first thing to check, because if the generator emits a constant for it the
   transcription reads it and if it does not then the reason code is a *runtime* value and needs
   the dynamic-raise entry point rather than a site constant.
3. **Three helpers do not exist where the authority's names suggest.** `str.rs` has **no
   `strncmp`** — `module_find`'s comparison must be transcribed rather than forwarded, and it is
   the second place in this file (after the last-dot scan) where a libc call has to be written
   out. The `ERR_*` accessors are not spelled `ERR_peek_last_error` / `ERR_GET_REASON`:
   `err.rs` exports `ERR_peek_last_error_all` and the two halves of a packed error are reached
   another way, which is what `CONF_modules_load_file_ex`'s missing-file test needs. `ctype.rs`
   **does** have `ossl_isspace` and `obj.rs` **does** have `NID_undef`, and turning up two of
   the ten right is not a defence of the other eight.
4. **The module belongs in `src/runtime/confmod/`, not the ledger's `src/confmod/`.** The
   crate's CONF data model is `src/runtime/conf/` (`conf_api.c`, `conf_def.c`, `conf_lib.c`,
   `conf_sap.c`), so `conf_mod.c`'s transcription belongs beside it; `src/confmod/` at the crate
   root would be the only stratum module outside its stratum's directory. That means
   `phase6_obligations.py`'s `MODULE_PREFIXES` and `phase_state.py`'s `PHASE6_MODULES` are
   **updated to the real path in the same commit that creates it** — a ledger naming a module
   that does not exist is the defect the ownership audit exists to catch, and pointing it at
   itself is not a way to keep it quiet.

### What the next attempt starts from

D125's eleven facts, these four, and nothing else to derive: the registry's structures and the
copy-modify-swap are written out in D125; the raise sites are four named constants; the two
places a libc call must be transcribed by hand are known by name; and the module's home is
decided. The order is unchanged — **6.10b, then 6.10d, then 6.10c, then
`OPENSSL_load_builtin_modules`, then 6.8d** — and `RT-CONF-MOD` is its court.

### Arithmetic

| | before | after |
|---|---|---|
| Phase 6 implemented / open | 142 / 19 | **142 / 19** (nothing was committed) |
| lines composed and discarded | — | **~1,000, whose ten guessed identifiers are the reason** |
| identifiers that must be read rather than guessed | 10 | **2 left to check** (`conf_mod.c:331`'s site, and the `ERR_*` pair for the packed-error test) |
## D127 — 6.10b/c/d land, and the first thing the finished pipeline found was a defect in 6.6e-ii

6.10b (`conf_mod.c`'s registry, fifteen exports plus `ossl_config_modules_free`), 6.10c
(`conf_sap.c`'s `ossl_config_int`/`ossl_no_config_int` and the config step in
`OPENSSL_init_crypto`) and 6.10d (`asn_moid.c`'s `ASN1_add_oid_module`) are implemented, and
`RT-CONF-MOD` observes them differentially in 161 observations with zero residuals. Phase 6
goes from 19 open to **2**, `libcrypto` from 1116 to **1133** implemented exports, and the
prerequisite gate's blocking-dependency list from 33 to 30.

### The defect: `ossl_ctx_thread_stop` was written against the wrong helper

`docs/SECURITY_DIVERGENCE_POLICY.md` carried `D-TEVENT-CTX-STOP-LEAK-1`, which claimed that
the authority's `ossl_ctx_thread_stop` is

```c
hands = clear_thread_local(ctx); init_thread_stop(ctx, hands); OPENSSL_free(hands);
```

and that the head is therefore released while other contexts' handler nodes are still linked
to it. **The authority is not that.** It is:

```c
void ossl_ctx_thread_stop(OSSL_LIB_CTX *ctx)
{
    if (destructor_key.sane != -1) {
        THREAD_EVENT_HANDLER **hands = fetch_thread_local(ctx);
        init_thread_stop(ctx, hands);
    }
}
```

`fetch_thread_local` is `manage_thread_local(ctx, 0, 1)`: fetch without allocating and
**without clearing**. Nothing is freed, the head stays in the thread's slot, and the register
keeps pointing at it. The source marks `fetch_thread_local` `ossl_unused` because the FIPS
build does not call it; this profile is the non-FIPS build, which does — and that is exactly
how the misreading was available to make.

The crate had been written against `clear_thread_local` plus a `CRYPTO_free`, and the
divergence entry had been written **from the test rather than from the authority**. That is
the lesson: a divergence record derived from the candidate's own behaviour records nothing.

**What made it visible.** Freeing the head left its address in
`GLOBAL_TEVENT_REGISTER`'s `skhands`, so the walk in `init_thread_deregister(NULL, 1)` —
which `OPENSSL_cleanup` runs — dereferenced released memory. Rust refuses that dereference
instead of reading the corpse, so the observable was the unit-test binary **aborting at
process exit**. It had never been reachable before, because until this commit nothing made the
exit-time `OPENSSL_cleanup` actually run its teardown: `crate::runtime::init`'s test-only
`reset_for_test` cleared `BASE_INITED`, and `OPENSSL_cleanup` therefore returned early at
exit. Making `base_init` a faithful `RUN_ONCE` — which 6.10c needs, because the base step now
creates the configuration re-entrancy key and can fail — is what closed that hole.

Three corrections followed, and each is a correction rather than a patch:

* `fetch_thread_local` exists as its own helper, with the authority's `ossl_unused` note
  recorded and the reason it applies to a different build profile;
* `ossl_ctx_thread_stop` is the authority's two statements;
* `init::reset_for_test` restores `BASE_INITED` from a new `BASE_ONCE_RET` — the authority's
  own `base_ossl_ret_`, which is **not** `base_inited`: `OPENSSL_cleanup` clears the latter and
  a `CRYPTO_ONCE` cannot be un-run. Taking `base_init`'s answer from `base_inited` made a
  post-cleanup call report a base-initialisation failure instead of the terminal refusal.

`D-TEVENT-CTX-STOP-LEAK-1` is struck through in the policy document with the misreading, the
truth and the reason it survived written out. The tests that encoded it are replaced by
`the_context_stop_filters_on_the_argument` (a survivor is still reachable afterwards) and
`a_second_context_stop_for_the_same_argument_runs_nothing`, and the module's `reset()` now
drains with `OPENSSL_thread_stop` — a line that was only needed once the defect was gone,
which is its own evidence that the tests had been leaning on it.

### `D86` is superseded, and the refusal moved

D86 recorded that a configuration file which exists is not applied, because the loader did not
exist yet. It is applied now. Two consequences are worth naming:

* the config step needed `settings`, which `OPENSSL_init_crypto` was ignoring. It reads it
  now, through `OPENSSL_INIT_SET_*`'s three fields, and the `OSS_LIB_CTX`/module-registry
  call that the old comment named as the blocker is made: `CONF_modules_load_file_ex` against
  `OSSL_LIB_CTX_get0_global_default()`.
* **the refusal for the unsupported options moved.** The authority tests `ADD_ALL_CIPHERS`,
  `ADD_ALL_DIGESTS`, `ASYNC` and the `ENGINE_*` bits *before* its `LOAD_CONFIG` block, so a
  caller who asks for `ADD_ALL_CIPHERS | LOAD_CONFIG` is refused **without a configuration
  having been read**. The crate tested them after, which was unobservable while the config
  step loaded nothing and is observable now. It is at the authority's position.

Three details of the config step are transcribed and each is a test: the flag
`openssl_configured` is set **unconditionally**, so a *failed* load is permanent for the
process rather than retried; the re-entrancy thread-local is **set and never cleared**, so
after a failed load a second call on the same thread takes the skip branch and answers 1
while the same call on another thread answers the once's recorded 0; and
`NO_LOAD_CONFIG | LOAD_CONFIG` marks the process configured and loads nothing, because
`NO_LOAD_CONFIG` claims the *same* once. Those three are why `RT-CONF-MOD` re-executes itself
with a mode argument: a process can only observe its own first configuration load once, so
each scenario is a fresh process and the parent reports the child's exit code.

### `RT-CONF-MOD`'s observations, and the two it deliberately does not make

161 observations, zero residuals. The ones that carry the most weight:

* **the error coordinates are the authority's own**, read through `ERR_peek_last_error_all`:
  `../../src/openssl-3.6.4/crypto/conf/conf_mod.c:286`, function `module_run`, and the data
  string `module=rt-cm-fail, value=fv retcode=-1      ` — including the six spaces of
  `%-8d`'s left justification, which `format!` cannot express and which is therefore built
  with the authority's own `BIO_snprintf`;
* **`module_init` answers -1 on failure**, not the initialiser's own code: the module returns
  0, `CONF_modules_load` answers -1, and the data field says `retcode=-1`;
* **`module_add` pushes and never deduplicates**, so the first registration shadows the
  second — observed with two counters;
* **`module_find` truncates at the *last* dot**, which the probe exercises both ways:
  `rt-cm-a.alpha` and `rt-cm-a.beta` find `rt-cm-a`, and `rt-cm-a.gamma.delta` **does not**
  (it truncates to `rt-cm-a.gamma`), so a three-part name is an unknown module;
* **a name whose last dot is its first character truncates to zero bytes**, and
  `strncmp(x, y, 0)` is 0 for every `y` — so `.weird` lands on the **first entry in the
  registry**, which is the built-in `oid_section`, and the OID module's initialiser is called
  with `.weird`'s value and fails;
* **`config_diagnostics` is per-context and sticky**, and turning it on clears four ignore
  flags — so the same call that answered 1 answers -1 afterwards.

It does **not** observe the fan-out of `OPENSSL_load_builtin_modules` (six of its seven
registrations belong to later strata, which is D121's recorded divergence and would fail the
court for a reason the court is not about), and it does not read `CONF_imodule_get_flags`
before a module's initialiser has run, because the authority allocates `CONF_IMODULE` with
`OPENSSL_malloc` and never initialises that field. Both are stated in the probe's header, and
the second is recorded in the divergence policy.

### Phase 5's generator had one predicate missing

The pipeline's ownership audit caught `ASN1_add_oid_module` counted as implemented by **both**
Phase 5 and Phase 6. Phase 5's generator was the outlier: `phase3`, `phase4` and `phase6`
each compute `implemented_here = sorted(s for s in owned if s in done and s not in handed_on)`,
and `phase5_obligations.py` — rewritten when Phase 5 abandoned `FAMILIES` — had dropped the
`and s not in handed_on`. `implemented` means implemented **by this stratum**, and a hand-off
the receiving stratum has built is not this stratum's work. The change is one predicate and
one partition-identity assertion, the latter already present in the other three generators.

### Arithmetic

| | before | after |
|---|---|---|
| Phase 6 implemented / open | 142 / 19 | **159 / 2** |
| `libcrypto` implemented | 1116 | **1133** |
| courts / observations | 54 / 19,884 | **55 / 20,045** |
| unit tests | 284 | **285** |
| blocking dependencies | 33 | **30** |
| language census | 2066 | **2050** |
| the two that remain open | — | `OSSL_LIB_CTX_new_child` (6.6d), `OSSL_LIB_CTX_load_config` (6.6g) |

## D128 — `ossl_config_add_ssl_module` is this stratum's, not libssl's: the plan and the ledger disagreed and the ledger is right

`docs/PHASE-6-SUBPHASES.md`'s 6.10 row ends its fan-out paragraph by listing the six modules
`OPENSSL_load_builtin_modules` registers that this stratum does not: `ENGINE_add_conf_module`
and `ENGINE_load_builtin_engines` (ENGINE), `ossl_provider_add_conf_module` (6.8d),
`ossl_random_add_conf_module` (Phase 9), `EVP_add_alg_module` (Phase 7) — and
`ossl_config_add_ssl_module`, which the row calls **libssl's**. `forensics/prerequisites.json`
has carried a row assigning the same symbol to **Phase 6.10c** since before 6.10 began, and
`D123`'s gate checks that row on every run.

Two records, two owners, and only one can be right. The ledger's is:

* `ossl_config_add_ssl_module` is `crypto/conf/conf_ssl.c`'s, in the same translation unit as
  `conf_ssl_get`/`conf_ssl_name_find`/`conf_ssl_get_cmd`, which Phase 4 built as part of 6.3;
* its body is `CONF_module_add("ssl_conf", ssl_module_init, ssl_module_free)`, and its handler
  reads the module's value with `CONF_imodule_get_value` and walks a section with
  `NCONF_get_section` — `CONF_IMODULE` and `CONF_module_add` are both this stratum's, which is
  the same dependency that put `ASN1_add_oid_module` (6.10d) and `ASN1_add_stable_module`
  (Phase 11) where they are;
* nothing in it needs libssl. It *registers* a store that libssl later reads through
  `SSL_CONF`, and the store and the accessors are Phase 4's and Phase 6's.

So the plan's sentence is wrong and the deferral row is right, which is D123's point arriving
from the other direction: a prose assignment in a plan is an act of judgement that nothing
checks, and a row in `prerequisites.json` is an act of judgement that every pipeline run
checks. When they disagree, the checked one wins, and the unchecked one is corrected.

**Nothing is implemented by this entry.** It records the correction, moves the unit to 6.10e
in `docs/PHASE-6-SUBPHASES.md`, and leaves the work — `conf_ssl.c`'s `ssl_module_init`,
`ssl_module_free` and the registration, plus the `RT-CONF-MOD` observations for
`ssl_module_init`'s two raise sites — to be done as its own commit under the same
`all_pass` discipline every other unit in this stratum has met.

## D129 — 6.6g: `OSSL_LIB_CTX_load_config`, and the three details one line does not show

`int OSSL_LIB_CTX_load_config(OSSL_LIB_CTX *ctx, const char *config_file)` is
`return CONF_modules_load_file_ex(ctx, config_file, NULL, 0) > 0;` in `crypto/context.c:479`.
It was the last thing 6.6 was waiting for the CONF module registry to unlock, and it is
written now that 6.10 has landed. Phase 6 goes from **2 open to 1**, and `libcrypto` from 1133
to 1134 implemented exports.

The body is one line; its **contract** is three details, each of which a transcription that
copied the surrounding entry point would get wrong, and each of which `RT-LIBCTX` observes:

1. **The flag word is a literal zero, not `DEFAULT_CONF_MFLAGS`.** The automatic loader
   tolerates a missing file and a failing module; this call does not. Same file, two entry
   points, two answers — and that is what makes it a *different* loader rather than a second
   spelling of the same one.
2. **The answer is `> 0`, not `!= 0`.** `CONF_modules_load_file_ex` answers **-1** when a
   module fails, so a `!= 0` test would report success for exactly the failure a caller most
   needs to see. The probe pins this by calling the *same* file through
   `CONF_modules_load_file` (-1) and through this function (0), one line apart.
3. **`config_diagnostics` in the file is set on the context it was loaded into**, because
   `CONF_modules_load` writes `cnf->libctx`. The probe loads a diagnostics-bearing file into a
   fresh context and observes its flag go to 1 while the process default's stays 0 — which is
   also why the observation could be made at all without disturbing the default.

Two more were worth the observations:

* **`oid_section` is loadable once per process, and that is the OID database's rule rather than
  the loader's.** `OBJ_create` refuses a short name that already exists, so a second load of a
  file carrying an `oid_section` **fails** — with `OBJ_R_OID_EXISTS` underneath and
  `CONF_R_MODULE_INITIALIZATION_ERROR` on top. It is observed, and it is why the repeatability
  observations use a file naming `ssl_conf`, whose reader frees its store before rebuilding it
  and is therefore idempotent.
* **a NULL context resolves through the thread's default**, so a load with `ctx == NULL` lands
  on the global default object; two loads of the same `ssl_conf` file into it both answer 1,
  which shows the load is not tied to the context that made the call.

**One observation is deliberately absent**, and the probe's header says so: a NULL `config_file`
with `OPENSSL_CONF` unset reaches `CONF_get1_default_config_file`'s fallback, which is the
authority's own `OPENSSLDIR` string and this crate's empty string — a recorded divergence, since
claiming a path inside the authority's build tree would be a false statement about this build.
Observing it would fail the court for a reason the court is not about, exactly as the
`OPENSSL_load_builtin_modules` fan-out would in `RT-CONF-MOD`. The half that *is* in scope — a
default file that exists — is observed, with `OPENSSL_CONF` pointed at a file the probe wrote.

### Arithmetic

| | before | after |
|---|---|---|
| Phase 6 implemented / open | 159 / 2 | **160 / 1** |
| `libcrypto` implemented | 1133 | **1134** |
| `RT-LIBCTX` observations | 91 | **110** |
| courts / observations | 55 / 20,131 | **55 / 20,150** |
| language census | 2050 | **2049** |
| the one that remains open | — | `OSSL_LIB_CTX_new_child` (6.6d), which needs `ossl_provider_init_as_child` (6.8e) |

## D130 — 6.8d lands, and the language census needed to become per-unit to mean anything

`crypto/provider_conf.c` is transcribed whole into `src/provider/conf.rs`: the slot-16
`PROVIDER_CONF_GLOBAL` and its two halves, `skip_dot`, the recursive parameter walk,
`prov_already_activated`, `provider_conf_activate`, `provider_conf_parse_bool_setting`,
`provider_conf_load`, `provider_conf_init` and `ossl_provider_add_conf_module`. Slot 16 is
filled by `context_init` and released **first** among the slots by `context_deinit_objs` —
the authority's *P2* position, ahead of the provider store's *P1* — and `providers` becomes
the third of the seven `OPENSSL_load_builtin_modules` registrations this crate can make.

`RT-PROVIDER` goes 67 → 80 observations and the pipeline is green at 55 courts and 20,163
observations. The observations are the two entry-point paths, the exact fourteen-spelling
boolean grammar (`Yes` and `2` refused; `TRUE` and `on` accepted), the two section errors
carrying `CRYPTO_R_PROVIDER_SECTION_ERROR`, and the recursion refusal.

### Three transcriptions that a plausible version gets wrong

* **Recursion is detected by pointer identity, not by text.** `visited` holds the `const
  char *` the `CONF` owns and the test is `==`, so two sections with the same *content* are
  not recursive while the same section reached twice is. A `strcmp` version would refuse a
  legitimate configuration; no test at all would not terminate.
* **The buffer bound is `>=`, checked before the append.** `char buffer[512]` and
  `buffer_len + strlen(sectconf->name) >= sizeof(buffer)` refuses a name that would exactly
  fill it, and the refusal is **-1** (fatal) rather than 0.
* **A nested 0 is swallowed.** The loop propagates only `rc < 0`, so a section with one bad
  parameter and one good one answers 1. Only the fatal answers escape.

And one truncation of the module's own making: `provider_conf_load` answers `ok >= 0`, so a
**non-fatal** activation failure is reported as success. That is deliberate — a `soft_load`
provider that could not be loaded must not fail the configuration — and it is why
`cmod.activate.load` is 1 on the authority even though the provider it names is activated
by a different path.

### The observation the court caught, and why it is not 6.8d's

`OSSL_PROVIDER_available` after an `activate = 1` differed: authority 1, candidate 0.
`default`'s `OSSL_provider_init` is `ossl_default_provider_init`, which is 7/8's and does not
exist in this crate, so the activation succeeds at the registry level and the provider is not
activated. That is 6.8c's **recorded residual 1** arriving through a second door, and the
probe now states the exclusion where it applies rather than observing it — the same
discipline the fan-out and the default-config-file fallback already get. What 6.8d owns is
the configuration walk, and every walk observable is in scope and observed.

### The census invariant had to move from a total to a per-unit map

Landing this made the prerequisite gate's `language_census` rise from 2049 to 2076, and the
regression guard — whose rule for that plane was non-increase — failed. The rise is not a
regression: the census counts the identifiers of every **transcribed authority unit** that
the crate neither models nor references, so transcribing another file necessarily adds that
file's local identifiers (`pcgbl`, `sectconf`, `ecmd`, `cval`, …). The guard's own comment
says the invariant exists so the census cannot "become a place where real omissions hide",
and a total that grows for a legitimate reason is exactly a place where an omission *can*
hide.

So the invariant is now stated where it can be checked:

* `prerequisite_gate.py` publishes `census_by_unit` — the same census, grouped by the
  authority unit each name came from;
* `regression_guard.py` fails when a unit that was **already transcribed** gains censused
  names, and reports a unit that is **new** as a movement; the total is reported and never
  fails on its own.

The per-unit map is bootstrap-only on the commit that introduces it, because the authority
baseline at `origin/phase6-libctx` predates the field; from the next commit the guard
compares it. The proposed-baseline check was extended to cover `prerequisites` in the same
change — it compared only five planes, so the blocking-dependency count and the new census
map were evidence the authority certified against and nothing verified.

### Arithmetic

| | before | after |
|---|---|---|
| Phase 6 implemented / open | 160 / 1 | **160 / 1** (6.8d adds no export) |
| `RT-PROVIDER` observations | 67 | **80** |
| courts / observations | 55 / 20,150 | **55 / 20,163** |
| language census | 2049 | **2076**, now with a per-unit invariant |
| the one that remains open | — | `OSSL_LIB_CTX_new_child` (6.6d), which needs `ossl_provider_init_as_child` (6.8e) |

## D131 — Phase 6 closes: the child provider, `OSSL_LIB_CTX_new_child`, and the last obligation

`crypto/provider_child.c` is transcribed into `src/provider/child.rs` — the slot-18 globals,
`ossl_provider_init_as_child`, `ossl_provider_deinit_child`, the two parent-reference helpers,
`ossl_child_provider_init` and the three callbacks — and the three accessors
`provider_core.c` keeps beside the object (`ossl_provider_set_child`, `_is_child`,
`_get_parent`). The parent half lands in `provider_core.c`'s Rust home:
`ossl_provider_register_child_cb`, `ossl_provider_deregister_child_cb`, the `OSSL_PROVIDER_CHILD_CB`
record, and the two core-dispatch entries that publish them — ids 105 and 106, which were
*absent* in the table's own test until this commit.

`OSSL_LIB_CTX_new_child` — the **last open export of the stratum, and the last of the whole
ownership atlas's Phase 6 set** — is written in `src/context/mod.rs`, and `OSSL_LIB_CTX_free`
gains the `ischild` arm that calls `ossl_provider_deinit_child` before the slots are released.
Its order is the contract: `OSSL_LIB_CTX_new_from_dispatch` first, then
`ossl_provider_init_as_child`, and **`ischild` last** — so a failure anywhere above leaves a
context that the free tears down as an ordinary one, rather than one whose teardown calls
`ossl_provider_deinit_child` on globals whose upcalls are NULL.

`forensics/phase6-obligations.json` goes to **zero open**, `forensics/phase-state.json` derives
**complete** for Phase 6, and the seal is `docs/PHASE-6-PROVIDER-SEAL.md`.

### Five call sites that had been waiting for this

Each was a `// 6.8e` marker naming the exact line the authority writes, and each is now that
line:

1. `ossl_provider_up_ref`'s child arm — an **up-ref of the parent** whose failure *rolls back*
   the reference just taken before reporting 0.
2. `ossl_provider_free`'s child arm — a **down-ref of the parent** before the early return.
3. `provider_activate`'s guard and its two failure arms — before either lock, because the
   parent's upcall may want locks of its own and taking the store's first is a lock-order
   inversion the authority's file header calls out by name.
4. `provider_deactivate`'s `freeparent` flag — set inside the locks, spent **after** them, for
   the same reason.
5. `create_provider_children` — the walk that replaces a loud `assert!`. Its `ret &=` is
   deliberate: every registration is asked even after one has refused, because a parent that
   refuses is not entitled to stop the others being told.

Plus the `removechildren` walk in `provider_deactivate`, which is **inside** the locks and runs
before the unlocks — the authority's position — and the `else removechildren = 0` narrowing that
a provider with activations left cannot have its children removed.

### Three divergences, all recorded rather than reproduced

`D-CHILD-DEREGISTER-NULL-1` is the pair worth reading. `ossl_provider_init_as_child` stores
**eight** dispatch entries and validates **seven**; the eighth,
`c_provider_deregister_child_cb`, is not in the test, and `ossl_provider_deinit_child` calls it
**unguarded**. So a parent that omits that entry initialises successfully and jumps through NULL
at teardown. The candidate keeps the *initialisation* half exactly — seven validated, the eighth
stored unvalidated — and makes the teardown half check and return. Splitting the pair is the
point: the validation contract is observable and is claimed, and the fault is not. `RT-LIBCTX`
observes the success half (`child.no_deregister=nonnull` with `register_called=1`) and
**deliberately does not free that context**, because freeing it would crash the authority — so
the divergence's teardown half is stated in the probe's own comment rather than measured.

`D-CHILD-REGISTER-PROPS-1` and `D-CHILD-PROPS-CB-1` are one missing function in two places:
`evp_get_global_properties_str` and `evp_set_default_properties_int` are `evp_fetch.c`'s and
therefore Phase 7's, and both are recorded deferrals in `forensics/prerequisites.json`. So
`provider_global_props_cb` answers 0 and raises nothing, and
`ossl_provider_register_child_cb` omits the property-string step before its walk. Both halves
are unreachable until a provider can take the **parent** role, which needs a third-party
provider — 6.12 — and the entries say so instead of implying a court has seen them.

### The probe plays the parent

`RT-LIBCTX` goes 110 → 124 observations, and the new ones are the child mechanism end to end,
which needed the probe to *be* a parent: it publishes the eight dispatch entries a third-party
provider would, calls `OSSL_LIB_CTX_new_child`, and records what the core asked it for. The
observations are that the registration happens once with three non-NULL callbacks and the
**child context as `cbdata`**; that slot 18 exists for every context; that the free calls the
deregistration exactly once with the handle it was given — which is `context_deinit`'s `ischild`
arm, and it does not run for an ordinary context; and that a table missing any of the **seven**
validated entries answers NULL **without** registering, because the validation precedes the
registration.

### Arithmetic

| | before | after |
|---|---|---|
| Phase 6 open obligations | 1 | **0** |
| Phase 6 state | in-progress | **complete** |
| `libcrypto` implemented | 1134 | **1135** |
| `RT-LIBCTX` observations | 110 | **124** |
| courts / observations | 55 / 20,163 | **55 / 20,177** |
| blocking dependencies | 29 | **11**, and all of them Phase 7's and Phase 16's |
| unit tests | 287 | **287** |

## D132 — `core_algorithm.c` is Phase 7's prerequisite, and the reason it was invisible

With the stratum at zero open obligations, one item of the plan remained unbuilt: 6.6f/6.8f,
the algorithm dispatch walk, which are the same function — `crypto/core_algorithm.c`'s
`ossl_algorithm_do_all` — assigned to two rows. It is **not** built, and the honest disposition
is not "implement it now" but "say where it belongs".

Its **only** caller in the authority is `crypto/core_fetch.c`'s `ossl_method_construct`, which is
the fetch path and therefore Phase 7's. Nothing in this crate references it, so:

* no court could reach it, because a C probe cannot call an internal function that has no entry
  point and no caller; and
* no ledger could see it, because the symbol-ownership atlas classifies **exports** and this is
  not one; and
* the prerequisite gate did not report it, because the gate's rule is *"every
  authority-internal name a crate module **references** must be built or recorded with the
  stratum that owns it"* — and a name that nothing references is invisible to it.

That third point is the finding, and it is the `a2d_ASN1_OBJECT` failure class arriving from the
other direction. There, a census was too narrow because it looked at prefixes; here, a gate is
too narrow because it looks at references. A whole authority translation unit can therefore sit
unnamed while a stratum reports complete, and the only thing that caught it was reading the
plan against the crate rather than reading either alone.

The disposition is a **deferral with the owner named**, which is the mechanism the project
already has for exactly this: `ossl_algorithm_do_all` is now a row in
`forensics/prerequisites.json` owned by Phase 7, with the reason and the citation. The gate
accepts it, reports it as a blocking dependency, and the blocking list goes 11 → 12 — so the
function is now **visible** to the machinery whose job is to notice it, which it was not
before this entry.

What this does **not** change: Phase 6's own completion rule. That rule is *"every export it
owns is implemented or handed to a named later stratum"*, and it is satisfied — the stratum's
ledger is at zero open and every export the atlas assigns it is accounted for. The seal's §2 no
longer lists 6.8f among the built subphases, §6 names it, and
`docs/PHASE-6-SUBPHASES.md`'s two rows carry the disposition.

The lesson is recorded rather than the mechanism fixed: the gate cannot see a unit no crate
module transcribes, and a *plan-versus-crate* reconciliation — which subphase rows name work
that neither a ledger nor a reference reaches — is the check that would catch the next one. It
is named here as an open obligation rather than built, because building it is a change to the
gate's own contract and belongs in its own commit with its own evidence.

## D133 — 6.12: the core hosting a real third-party provider, and the five defects it found

6.12 is the court the plan calls the third-party-provider court, and it is the only probe in
this stratum that can see the *provider-facing* half of the core. Every other court drives the
registry from outside, through the public API, and observes the objects it creates.
`OSSL_PROVIDER_init` — what the core hands a provider, and what it does with what a provider
hands back — is passed to `OSSL_provider_init` and to nothing else, so a probe that is not a
provider has no way to reach it at all. `courts/phase6/rt_provider_3p_probe.c` compiles an
`OSSL_provider_init` into its own binary, registers it with `OSSL_PROVIDER_add_builtin`, loads
it with `OSSL_PROVIDER_load_ex`, and then everything it reports is what the core gave it.

It found five defects, and every one of them was invisible to the other fifty-five courts for
the same structural reason: **nothing had ever walked that table or taken that role.**

**1. `FUNC_CORE_OBJ_ADD_SIGID` and `FUNC_CORE_OBJ_CREATE` were 121 and 122. The header says 11
and 12.** The constant was only ever compared against itself, this build's own install header
says 11 and 12 so no compile could disagree, and nothing read the published table at runtime. A
third-party provider compiled against these headers asks for id 12 and was being answered NULL;
a build that published 121 would hand a provider whatever the core put there. The digest below
is what makes the class visible, and the unit test now asserts 11 and 12 by value.

**2. The published table was in numeric order, not `core_dispatch_`'s order.** Two groups
differ: the BIO family is published `40 41 42 43 49 48 50 44 45 46 47` (the header declares
`GETS` and `PUTS` before `UP_REF`, and `CTRL` after `PUTS`) where the candidate had sorted it,
and the `CRYPTO_*` group is published *before* the child-callback and provider-accessor ids
even though its own ids are lower. Neither order is reachable through a lookup — a provider
switches on `function_id` — which is exactly why nobody noticed. The authority's order is now
reproduced, and `in.ids_digest` is what measures it: an FNV-1a over the published id sequence
with the one deferred family skipped, so an entry added, dropped, substituted or reordered
changes it.

**3. `OSSL_FUNC_PROVIDER_UP_REF` (110) and `PROVIDER_FREE` (111) were absent from the table, and
`provider_up_ref_intern`/`provider_free_intern` were not written at all.** They are 110 and 111
of the eight entries `ossl_provider_init_as_child` requires, so **`OSSL_LIB_CTX_new_child`
could not succeed** — the seven-pointer validation rejected the table and answered 0. The
crate's own table carried the comment `// 110, 111: ... — absent, 6.8c` three commits after
6.8c was declared complete. This is the `a2d_ASN1_OBJECT` class again: a stub comment that
outlived the subphase it named, with nothing to notice that the subphase had closed.

**4. `ossl_provider_register_child_cb` answered `1`, not the push's result.** The authority
writes `ret = sk_OSSL_PROVIDER_CHILD_CB_push(...)` and returns `ret`, so the answer is the new
length of `store->child_cbs`: 1 for the first registration, 2 for the second. A literal `1` is
indistinguishable from a correct answer until a *second* parent registers — and the authority's
own child, registering during `ossl_provider_init_as_child`, is always the first. The probe is
the second, so `child.register_child_ret` is 2 on the authority.

**5. `ossl_provider_add_to_store` never called `create_provider_children`.** The crate carried
`// 6.8e: \`if (!create_provider_children(prov))\` goes here` — a stub that stated its own
removal condition and then was not removed when 6.8e landed. The consequence is not a missing
call in a corner: `create_provider_children` is how a registered parent is told that a provider
has become active, so the parent's `create_cb` was never called for any provider. That is the
whole mechanism 6.8e exists for, silently not firing, and only a probe holding the parent role
could see it.

The same commit removes a guard whose documentation had stopped being true:
`create_provider_children` carried a `prov->store == NULL` test whose comment claimed it would
"fail loudly" if a callback were ever registered. It answered 1 instead of failing, and both of
its callers guarantee a non-NULL store, so it could not fire either way. 6.8e landing made the
premise false, so it is gone and the module docs no longer claim it.

**What the court deliberately does not observe.** Two things, both stated in the probe's own
header rather than left to be inferred:

* the eight `rand_*` core ids (96-99, 101-104), which are Phase 9's. Their absence is pinned by
  `core_dispatch.rs`'s own table test and by the ledger; the court reports the count and the
  digest *excluding* that family, which is strictly stronger than a total because it still
  catches an entry added, dropped or reordered outside it. That is the arrangement `RT-PROVIDER`
  uses for `cmod.activate.available`.
* `global_props_cb`, because the step that would call it is `evp_fetch.c`'s and is the recorded
  `D-CHILD-REGISTER-PROPS-1` divergence. A probe that counted its calls would be counting the
  divergence rather than the contract. `D-CHILD-REGISTER-PROPS-1`'s entry is updated from "no
  court has observed either half" to what is now true: the registration half *is* observed and
  passes on both sides, the property-string step is still observed by nothing.

Two smaller corrections are in the same commit. The probe's `create_cb` observations were
assertions rather than measurements — `child.create_cb_got_a_callback` and
`child.cbdata_is_the_child` were literals — so they are replaced by real ones:
`create_cb_prov_is_the_loaded_provider` compares the handle the core passed against the
`OSSL_PROVIDER *` the probe's own load returned, and `create_cb_cbdata_is_the_child` compares
the `cbdata` against the child. `deregister_child_ret` becomes
`child.deregister_cb_returned` with the reason spelled out: the entry is `void` on the
authority, so there is no answer to compare and the observation is a liveness witness.

`RT-PROVIDER-3P` is 40 observations with no residuals against the authority, registered in
`forensics/tools/phase6_courts.py`'s `COURTS` and `forensics/tools/phase_state.py`'s
`PHASE6_MODULES`, so a stratum's court runner and its completion rule both know it exists.

SPDX-License-Identifier: Apache-2.0

## D134 — the plan-versus-crate reconciliation, so a promise that reaches nothing fails a check

D132 ended by naming its own open obligation rather than fixing it: `core_algorithm.c` was
invisible because `prerequisite_gate.py`'s universe is the set of names a crate module
*references*, and a name nothing references is invisible to a gate built that way. The
disposition was a deferral with the owner named, and the mechanism was left for a later commit
because building it changes the gate's own contract. This is that commit.

`forensics/tools/plan_reconciliation.py` reads the subphase plans and asks the other half of the
same question. Its universe is **what a stratum promises**, not what the crate mentions: every
authority translation unit and every authority-internal function named by a subphase row of a
stratum that is `complete` or `in-progress`. A `not-started` stratum's plan is not judged,
because nothing has claimed to have done it yet; a stratum that has sealed *is* claiming, and
that claim is what is reconciled.

Three findings, and each is a class rather than an instance:

* **P1 `plan_named_unit_not_reached`** — a unit a row names that no crate module transcribes,
  that defines no internal function the crate builds, whose identifier list the crate never
  references, and that no record names. This is the `core_algorithm.c` class exactly.
* **P2 `plan_named_symbol_not_reached`** — an authority-internal function a row names that the
  crate neither builds nor records nor covers by a divergence. The gate's direction A with the
  reference set replaced by the plan's name set.
* **P3 `plan_unit_record_is_stale`** — a record that names an authority unit no row mentions.
  The reverse direction, which is what keeps the mechanism from quietly widening.

Two smaller findings exist because the plan is prose and prose can be wrong: a row naming a
`.c` file the authority does not have, and a row naming a bare basename the authority repeats.
Neither is guessed at. `crypto/provider.c` is one of three `provider.c`s in the authority
(`fuzz/`, `test/testutil/`), and the tool reports the candidates rather than picking one,
because picking one is precisely the unexamined transcription this project exists to remove.
Both rows that did it were written with the path instead, which is a one-word discipline and
not a limitation.

**The reach test needed four signals, and the reason is worth recording.** A unit is reached if
a crate module's *dominant* unit is it; or if the crate builds one of the authority-internal
functions it defines; or if the crate references one of the identifiers the unit's own row in
`transcription-edges.json` lists; or if a record names it. The first signal alone is not enough
because `transcription-edges.json` maps each module to one dominant unit **on purpose** — a
module whose definitions are spread across units appears once — so `crypto/provider.c`, whose
twenty-two exports are thin wrappers and which has no internal function of its own, is invisible
to it while every one of its exports is implemented. That is not a gap in the crate; it is a gap
in the vocabulary, and it is closed by a record that names the construct instead:

**The `units` block.** `forensics/prerequisites.json` gains a third record kind, holding the
units that no symbol can stand for. Each row carries a class from a fixed set, and the class
names the fields the row must prove, so a row is a claim that can be **falsified** rather than a
sentence that can be believed:

| class | what it must prove |
|---|---|
| `reached_by_a_named_construct` | a `crate_module` that exists and a list of `names` every one of which the crate actually builds |
| `deferred_to_later_stratum` | an `owner_phase` whose stratum has not already sealed |
| `not_in_this_profile` | the `guard` that empties the file |
| `does_not_exist_in_this_authority` | nothing — because the tool checks the absence against the committed manifest itself |

Ten rows are recorded, and the triage found things a reader would not have. `crypto/dso/dso_openssl.c`
is **entirely** inside `#ifdef DSO_NONE` and compiles to nothing in this profile, while
`crypto/dso/build.info` lists it unconditionally — so the build file alone cannot settle it, and
the guard is the evidence. `crypto/property/property_err.c` has no public loader at all: the
authority's `err_all.c` calls `ossl_err_load_PROP_strings()` directly, and this crate models every
one of those direct calls as one generated `load_lib(<lib>)`. `crypto/rcu.c` **does not exist**,
and the plan names it only in order to say so — "there is no `crypto/rcu.c`" — so the row is
recorded rather than the sentence reworded, because the sentence is worth keeping and the check
must keep firing on any *other* row that invents a file.

**Three symbols and two units were genuinely unreached**, and they are the point of the exercise.
`ossl_method_construct` in `crypto/core_fetch.c` is the other half of D132 — rows 6.6f and 6.8f
name it as the caller that makes `ossl_algorithm_do_all` Phase 7's prerequisite, and nothing
recorded it. `ossl_random_add_conf_module` is one of the seven `OPENSSL_load_builtin_modules`
registrations, Phase 9's, named by row 6.10 as a fan-out residual but present in no machine-
readable record. `OSSL_provider_init` is `providers/legacy/legacyprov.c`'s, Phase 13's, and rows
6.8d and 6.12 name it because a third-party provider declares one. All three are now deferrals
with their authority units named; `crypto/core_fetch.c`, `crypto/rand/rand_lib.c` and
`providers/legacy/legacyprov.c` are reached through them.

**The counterfactual was measured, not asserted.** Removing the `authority_unit` field from
D132's own `ossl_algorithm_do_all` deferral and re-running the tool reports
`plan_named_unit_not_reached: crypto/core_algorithm.c (6.6, 6.6f, 6.8f)` — the file, and exactly
the three rows that promised it. So the check catches the class it was built for, on the instance
it was built from.

The blocking-dependency count rises 12 → 15 because three names became **visible**, which is the
same shape as D132's own 11 → 12 and D130's language census: an invariant that cannot tell a
legitimate change from a hidden omission. The transition is recorded in
`forensics/ownership-transitions.json` with its reason, and `regression_guard.py` reports it as
an approved movement rather than failing.

`plan_reconciliation.py` runs in `court/pipeline.sh` after `phase_state.py` (it reads the derived
states to decide which strata are claiming), is listed in `evidence_determinism.py`'s
`GENERATORS_AFTER_LEDGERS` and its `COMPARED` set, and is a step of the `static gates` job in
`.github/workflows/ci.yml`. The Phase 6 seal's §6 and its exit-criteria table name it, because
D132's obligation was Phase 6's and this is what discharges it.

SPDX-License-Identifier: Apache-2.0

## D135 — D109's two unlisted generators are listed, and the drift it predicted was real

D109 recorded an open gap and deliberately left it open: `gen_err_raise_sites.py`, its
`forensics/atlas/err-raise-sites.json` and `src/runtime/err_sites.rs` were in neither
`evidence_determinism.py`'s generator list nor its comparison list — and the same was true of
`gen_bn_primes.py` and `src/bn/prime_data.rs`. The note said why it was not fixed there and then:
"fixing it means adding the same tool to `check_evidence_portability.py`'s exercised set as well,
so that the two agree about which generators need the authority's source tree. Doing half of that
now would replace one silent gap with two."

Both halves are now in, and the reason they had to be done together is structural rather than
stylistic: `check_evidence_portability.py` imports `evidence_determinism.GENERATORS` and exercises
that one list, so listing a generator is what puts it in both gates at once. Doing half would have
meant a second, hand-maintained list — which is the failure mode this project keeps removing.

**The blocker was real, and it is why the gap needed a weak tier rather than a list entry.**
Both generators read the **authority**, and the authority is not committed: `gen_err_raise_sites.py`
scans the covered units' `ERR_raise*` sites and resolves their symbol values through the compiler,
and `gen_bn_primes.py` compiles a C probe against the admitted prefix and runs it to read the
primes back. `evidence_determinism.py` runs every listed generator with no arguments and fails on
a non-zero exit, so simply listing either one would have made the `static gates` job — which has no
authority — fail. That is the same constraint `gen_ctype_table.py` already solved, and the solution
is the same: **two tiers, with which one ran printed rather than implied.**

* authority present → re-derive from the authority (the strong tier, and the one the court and the
  pipeline use);
* authority absent → check the generated `.rs` against the committed JSON, which still catches a
  hand-edited generated file or a stale artefact, and cannot catch the authority itself having
  changed (the authority is pinned by archive hash elsewhere, and the court re-derives).

`gen_bn_primes.py` needed one more thing than the other two: the primes themselves are not in the
JSON, only their SHA-256, and storing 8192-bit primes twice would put two copies of the same data
in the repository and let them disagree. So the weak tier recovers the bytes **from the committed
Rust**, re-hashes them against the record, and only then rebuilds and compares the file. A byte
changed in `prime_data.rs` therefore fails twice over — once on the digest and once on the
rebuild — and neither check needs a second copy of the data. Both generators' rendering is now a
pure function factored out of `main` (`render_rust`), so the comparison is a difference in the
*inputs* and never in the rendering.

**And the drift D109 predicted had already happened.** `src/bn/prime_data.rs` was committed with
sixteen bytes to a line while `rust_array` had been changed to wrap at twelve, so the file was
stale relative to its own generator and nothing compared them. Regenerating it against the
authority changes the wrapping and **no value** — the per-prime SHA-256s in `bn-primes.json` are
byte-identical, which is what makes this a formatting repair rather than a data correction. The
same check on `err_sites.rs` and `err-raise-sites.json` found them in sync; that is the difference
between a gap that was theoretical and one that had already bitten, and it is the argument for
closing both at once rather than leaving D109's note as the record.

`evidence_determinism.py`'s artefact count goes 14 → 19 (two JSON artefacts and one more `.rs`
source, plus the two generators). `check_evidence_portability.py` exercises the same 19 and still
passes with `nm`, `objdump`, `readelf`, `ar` and `file` stubbed out — which is the property that
matters, because both new generators invoke `clang` on the strong tier and the point of that gate
is that no *stubbed* tool is needed either way. Both gates were also run with the authority
directory moved aside, which is exactly the CI environment, and the three weak tiers were observed
firing by name rather than inferred from a green exit.

Both `.rs` generators being unlisted was one gap with two instances; D109 recorded it as such, and
this is the commit that closes it rather than the one that documents it.

SPDX-License-Identifier: Apache-2.0

## D136 — the drift was in the generator, not the artefact, and CI said so

D135 closed D109's determinism gap for the two unlisted `.rs` generators and reported the drift
it found in `src/bn/prime_data.rs` as a stale artefact: sixteen bytes to a line in the committed
file against twelve in `rust_array`, so the file was regenerated against the authority. **That
direction was wrong, and the evidence for it was one push away.** `cargo fmt --all -- --check`
failed on the regenerated file immediately, because `rustfmt` packs the tokens sixteen to a line
and the committed file had been the `rustfmt`-clean one all along. The generator's wrapping was
the drifted half.

The distinction is worth keeping because the two directions mean different things. A stale
*artefact* is a data problem: the committed file disagrees with the authority. A drifted
*generator* is a tooling problem: the committed file agrees with the authority and the generator
no longer reproduces it. D135 asserted the first; this entry corrects it to the second, and the
correction is a demonstration of why the two gates have to be run together — the determinism
check found the divergence on its own, and nothing in it could say which side was wrong, because
"the file does not reproduce from the generator" is symmetric.

What was actually wrong is a crossed discipline rather than a wrong number. D72 recorded the same
class for `src/runtime/err_sites.rs`: *"the generator emitted two fields per line and `rustfmt`
wants one, so the committed file was only `cargo fmt --all -- --check`-clean because whoever
generated it last had run `cargo fmt` afterwards. Nothing enforced that step."* `gen_bn_primes.py`
had the same shape and its manual step had been performed when the file was last written, which
is exactly why the committed file was right and the generator was not.

The fix is in the generator, and the width is **derived rather than typed**:

```python
BYTES_PER_LINE = (100 - 4 + 1) // 6
```

A byte token is `0xNN,` — five columns — the items are joined by a space, and the literal is
indented four columns, so `n` items occupy `4 + 6n - 1` columns against `rustfmt`'s default
`max_width` of 100. Sixteen gives 99 columns and seventeen gives 105, so the answer is exactly 16.
Writing `16` would have been correct and would have left the next reader to re-derive why, which is
the shape of defect this entry exists to remove: the number that drifted was a literal nobody had
a reason to check. Nothing else depends on the width, because the weak tier recovers the bytes by
matching `0xNN` tokens rather than by counting lines — so a width changed deliberately still
leaves the check meaningful.

`src/bn/prime_data.rs` is now byte-identical to its pre-D135 content, verified against the commit
before the regeneration, and `cargo fmt --all -- --check` is clean. `forensics/atlas/bn-primes.json`
never changed at all: the per-prime SHA-256s were identical throughout, which is the strongest
available statement that no prime's value was ever in question and that the whole episode was
wrapping.

The lesson recorded rather than the mechanism changed: a generator whose output is a
`cargo`-visible file must emit what `rustfmt` emits, and the way to know is to have the artefact in
a determinism check **and** `cargo fmt --check` in CI — which is now the case. D135's claim that
the artefact was stale is superseded here and is not rewritten there, because an entry that was
wrong in a specific and instructive way is worth more as a record than as a correction.

SPDX-License-Identifier: Apache-2.0

## D137 — a release is a sequence, and the version is an input to generated evidence

The 0.0.10 release was pushed three times and `main` went red once, and the way it went red is
worth recording because it is D136's lesson arriving on a different artefact within the hour.

`gen_frf_courts.py` writes each of the 43 FRF court declarations, and each declaration's
`candidate.version_or_commit` is read from `Cargo.toml`. That is deliberate: the tool's own
docstring says "a release edits `Cargo.toml` alone", and it replaced a literal in the generator
precisely so that a release would not be "the ones somebody remembered". So bumping the version to
0.0.10 without re-running the generator left every declaration naming 0.0.9, and the `static
gates` job's `gen_frf_courts.py --check` step failed. **That is the gate working.** The
regeneration is 43 files and one line each.

Two smaller facts came out of the same sequence and both are in the release list now:

* **`Cargo.lock` records the crate's own version**, so a bump is two files. `cargo publish
  --dry-run` refuses a dirty working tree, which is how the second one was found — a gate, again,
  rather than a memory.
* **A red `main` is not a state this project keeps.** The merge commit and the two release commits
  were pushed before each was known green; the third is. The order in §8 of `docs/RELEASE_GATES.md`
  now puts the local `--check` runs before the push, so the release commit is green on its own
  account rather than on the strength of CI.

The disposition is not a new mechanism, because the guard already existed and fired. It is a
**procedure written down**, in `docs/RELEASE_GATES.md` §8, with the reasoning and the command that
lists the version's carriers. That is the right shape for this class: the failure was not a missing
check but a step somebody had to remember, and the project's answer to "somebody has to remember"
is to write the step down next to the gate that catches it and to say which gate catches it.

Recorded rather than left implicit because D136 said the same thing one commit earlier about
`src/bn/prime_data.rs` and `rustfmt`: a generated artefact whose generator and committed copy were
never run against each other drifts, and the drift is found by the *other* gate — the one that
checks formatting, or the one that checks a declaration's version — rather than by the determinism
check, which can only report that the two disagree.

SPDX-License-Identifier: Apache-2.0

## D138 — one reader for a court's observation count, and the committed record compared whole

Three defects, all in the machinery that *reads* court evidence rather than in the courts, and
one operational change that makes the invariant they support enforced rather than documented.

## 1. Two tools read a field that does not exist

The seal census read `row.get("observations", 0)` and the court runner read the same, so
`docs/SEAL-CENSUS.md` rendered **every runtime court with 0 observations** while the manifests
said 124, 1,162, 3,857. Phase 3's total was reported as 0 against an actual 4,412; Phase 5's as 0
against 10,529. A generated document understating its own evidence by three orders of magnitude,
and looking entirely plausible doing it, is the worst shape this class can take: a reader has no
reason to doubt a number that is rendered rather than typed.

The field is `authority_observations`, with `candidate_observations` as the other half of the
same fact. `regression_guard.py` had the field right and the other two did not, which is exactly
why there is now **one accessor** rather than three spellings:

```python
atlas_common.court_observations(row)   # the count, with the invariant
atlas_common.has_transcript(row)       # whether the court has a transcript at all
```

`court_observations` raises `EvidenceError` when only one of the two fields is present, and when
the two disagree — the comparison is line-wise over both transcripts, so a difference between
them is a record that cannot be true. The seal census, the regression guard and the court runner
all read through it, so the vocabulary is one word in one place.

**`has_transcript` exists because zero is two different things.** The Phase 2 ABI courts compare
ELF structure — symbol tables, dynamic tags, layouts — and produce no transcript at all, so they
carry no counts and their 0 is correct. Telling the two apart is what stops "this court has no
transcript" being read as "this court observed nothing", which is the mistake that produced the
bug. The census now prints `— (structural)` for those and says in a line above the table that the
others observe nothing line-wise *for that reason and not by default*.

## 2. The committed court record is now compared whole

`run_courts.py` re-derived every stratum's courts from the authority — that part was already
right — but its comparison was `verdicts(committed) == verdicts(fresh)`. Everything else in the
record was unguarded: a committed `COURTS.json` could have its probe path, exit code, crashed
flag, `residual_count`, `residuals`, staged-binary paths or input digests altered while its court
names and verdicts stayed put, and the runner would still print *"committed evidence reproduced"*.
`evidence_determinism.py` cannot catch it either, and deliberately: court results are excluded
from that tool because they are the authority venue's output rather than a generator's.

So the comparison is now `compare_records(committed, fresh)` over the **whole** record, structural
rather than textual so that every difference names its path:

```
phase 3: the committed evidence is not what this run reproduces
  .courts[0].authority_exit_code: committed 99, this run 0
  .courts[0].probe: committed 'courts/phase3/nowhere.c', this run 'court/phase3/…'
```

The only fields removed before comparison are those **proven** environment-dependent, and the list
is `CANONICAL_PATHS`, which is currently **empty** — so the comparison is byte-for-byte modulo key
order. Each entry in that list is a field the comparison stops seeing, so each needs its own
evidence, and none has been observed to be necessary yet.

**The change was tested against its own defect class**, because a check that cannot detect what it
claims to cover is not evidence: a committed `phase3/COURTS.json` was tampered with — the first
court's `authority_exit_code` set to 99 and its `probe` path changed, both fields the old
comparison never looked at — and the runner failed on it and named both. The runner's success line
now reports what was actually established:

```
all_pass, 10 court(s), 4412 observation(s) over 10 transcript court(s):
the committed record is exactly what this run wrote, in every field
```

## 3. A typed numeral in the Phase 6 seal

`docs/PHASE-6-PROVIDER-SEAL.md` said "8 courts" in two places while its manifest held 9 — in the
same document whose §10 states that every count is `docs/SEAL-CENSUS.md`'s. The numerals are
removed rather than corrected, because a corrected numeral is the same defect with the right value
this time, and the sentence now says where the count comes from.

## 4. `main` is protected, so the invariant is enforced and not merely written

D137 recorded the 0.0.10 release putting `main` red because the crate version moved without
regenerating the 43 FRF declarations. GitHub reported `protected = false`, so *"a red `main` is not
a state this project keeps"* was procedural. It is now enforced: `main` requires

```
lints (clippy)
static gates (build, tests, determinism, no-regression)
every active stratum's courts, and the re-derived guard
```

with `strict: true` (the branch must be up to date with `main`), a pull request, `enforce_admins:
true`, and no force pushes or deletions. `enforce_admins` is the load-bearing field: without it the
owner's own direct push bypasses every check, which is how the incident D137 documents happened.

The README's Status section is rewritten in the same commit, for the same reason the seal's
numeral was. It said "Phase 1 — in progress" and "no product subsystem is implemented" well past
six sealed strata and a thousand implemented exports, because a number written into prose has no
generator to correct it. It now types **no count**: it names the strata's subjects, which change
when the plan changes, and points at `forensics/STATUS.md` and `docs/SEAL-CENSUS.md` for every
quantity. `docs/RELEASE_GATES.md` §8's release sequence — written by D137 — now ends at a
protected `main` rather than at an instruction to push and watch: the last step of a release is no
longer something a person has to check.

**Numbering.** An entry's number is assigned when it lands on `main`, and this one was written
as `D140` on the `phase7-evp` staging branch where three Phase 7 entries had landed ahead of it.
It landed first, so it is `D138`, and the staging branch's own entries were renumbered onto it
when it merged `main` — `docs/DECISIONS.md` is append-only, so the collision had to be resolved
somewhere and the merge was the only place that could see both lines of history.

SPDX-License-Identifier: Apache-2.0

## D139 — Phase 7 opens: the plan, the ledger, and three registries turned into rules

Phase 7 owns 924 exports of `libcrypto` — the EVP framework, which is not the algorithms but the
machinery every one of them is reached through. `docs/PHASE-7-SUBPHASES.md` is its plan, and this
is 7.0: the ledger and the wiring, with the stratum's whole working set open, which is the honest
starting state.

**The plan rests on a measurement rather than on the export list.** The authority's build tree
holds one `.o` per translation unit per form, so listing every `libcrypto-shlib-*.o` and
intersecting each one's defined externals with the atlas's Phase 7 set **places 924 of 924** — no
export in this stratum is unaccounted for by a translation unit. That measurement is what the plan
groups: `crypto/evp/pmeth_lib.c` 98, `evp_lib.c` 97, `p_lib.c` 74, `evp_enc.c` 45, and forty-odd
units of one to seven. It also turned up two things a plan written from the export list would have
got wrong, and both are stated in the plan's §0 rather than left for a reader to be surprised by:
Phase 7 owns glue that lives in **other directories** (`crypto/asn1/ameth_lib.c`'s 26, `i2d_evp.c`,
`d2i_pr.c`, `d2i_param.c`, `d2i_pu.c`, `crypto/pem/pem_pkey.c`'s 8), because ownership follows the
header that promises the symbol and not the directory it was written in; and it owns the legacy
cipher and digest **wrappers** whose primitives are Phase 13's, which are hand-offs with the
dependency named rather than stubs.

Two deferrals discharge on arrival and the plan says so in the row that does it: `core_algorithm.c`'s
`ossl_algorithm_do_all` and `core_fetch.c`'s `ossl_method_construct` are 7.1's first work, because
nothing in the stratum can be written above the fetch path and they could not be written in Phase 6
because their only caller is Phase 7's own `evp_fetch.c`.

**`phase7_obligations.py` discovers its incoming edges rather than listing them.** Phase 6's
generator carries its hand-off set as a literal with the reasons attached, which is right for a
stratum that had one source of them and wrong as a pattern: the set is a fact about four *other*
files, and a fact maintained by hand in a fifth place is the class of defect this project keeps
removing. Here every row of every `phase*-obligations.json` whose `owning_phase` is 7 is read as an
edge, so a stratum that defers a symbol to this one is recorded on both sides by construction and
the reasons stay where they were written — which is what `ownership_audit.py` compares in both
directions. The measurement: 924 atlas-owned plus **26 handed in by Phase 5** (3 `asn1.h`, 23
`pem.h`), 950 owned, 0 open, 950 open, which is what the plan's §0 says.

**One module table, and the ordering in it is load-bearing.** `module_of` answers with the first
entry that matches, and `EVP_PKEY_` is a prefix of `EVP_PKEY_CTX_`, `EVP_PKEY_asn1_` and
`EVP_PKEY_meth_` — so a general entry placed before its own sub-families sends a reader of
`EVP_PKEY_CTX_new` to the file that holds `EVP_PKEY` itself, which is exactly the failure Phase 6's
own `MODULE_PREFIXES` comment names. The first run of this generator did precisely that (271
symbols filed under `src/evp/pkey.rs`); the split is now 132/141 and the comment says why the order
is part of the meaning.

### Three registries become rules

The reviewer asked twice for this, and this commit is where it was affordable because a new stratum
had to be added. Each of the three was a place where adding a stratum meant remembering something.

1. **`phase_state.py` derived five strata with five copies of the same thirty lines.** They differed
   only in the phase number and two paths. A stratum whose copy was forgotten would be derived
   `not-started` while its modules existed — which is the understatement the Phase 4, 5 and 6
   comments each record having happened once, and each having fixed *for the court item alone*. The
   rule is now one function over `STRATUM_EVIDENCE`, a new stratum is one table row, and the
   court-item fix is applied once to every evidence item.
2. **The same function's `elif absent: state = "not-started"` was wrong for the same reason.** A
   stratum whose plan and ledger have landed but whose modules have not was reported as never
   started. It is now `in-progress` with the missing files listed in `evidence_absent` and named in
   `blocking`, so the derived state is not weaker for the change — it is what a stratum with a
   ledger *is*. Phase 7 derives `in-progress` from its own evidence on the first run.
3. **`run_courts.py` refused a stratum with no runner.** That is right for a stratum with a
   committed courts file and it was impossible for one in its first subphase: a ledger and a probe
   cannot be one commit without writing the probe before the thing it probes. Phase 6 did exactly
   this — its modules landed before `RT-PARAM` did. The exemption is `NO_RUNNER_YET`, which is
   **conditional**: it applies only while `artifacts/phase<N>/COURTS.json` is absent, so the moment a
   stratum commits a courts file it must have a runner, and `phase_state.py` still blocks completion
   without one. The condition is printed rather than silently skipped, so a stratum's first subphase
   says out loud that it has no court instead of reading as one whose courts all passed.

Two checks were added in the same pass, each in the shape the project uses for "somebody must
remember": `phase_state.py` now fails when a stratum has **evidence on disk and no
`STRATUM_EVIDENCE` row**, discovered by looking at the filesystem rather than at the registry
(reading the registry would be tautological, since all twenty-two phases are in it from the day they
are planned); and `run_courts.py`'s refusal now names the exemption that would fix it.

### The plan reconciliation learned to tell a plan from a claim

`plan_reconciliation.py` (D134) judged `complete` and `in-progress` strata alike, so Phase 7's plan —
which names 128 units and has built none of them — failed the gate with 87 findings. That is the gate
being wrong: a plan names the work a stratum *will* do, and failing a stratum for having a plan is
not a check. The rule is now the one `prerequisite_gate.py` already uses for its sealed-stratum
census: a **`complete`** stratum's unreached names are findings, and an **`in-progress`** stratum's are
a published census — `census_by_stratum: {"7": 86}` — that is not a failure, with the stratum's own
`open_in_this_stratum` doing the holding to account. `docs/PHASE-7-SUBPHASES.md` is also corrected
where it wrote `names.c` bare, because the authority has two of them (`apps/lib/names.c` and
`crypto/evp/names.c`) and the tool reports candidates rather than guessing.

The regression guard reports the new ledger as **`UNCERTIFIED`** rather than as either a pass or a
regression: a sixth obligation ledger appears where the authority has five, and the guard's rule is
about a commit not undoing an earlier one's evidence, so there is nothing to compare. It says so,
which is the honest answer, and the phase movement `not-started -> in-progress` is reported beside it.

SPDX-License-Identifier: Apache-2.0

## D140 — 7.1's first half: the algorithm walk, and D132's deferral discharged

`crypto/core_algorithm.c` is transcribed whole in `src/evp/algorithm.rs`:
`ossl_algorithm_do_all`, `algorithm_do_this` and `algorithm_do_map`, in that order of nesting.

**This is the item Phase 6 could not build and could not see.** D132 recorded that
`ossl_algorithm_do_all`'s only authority caller is `crypto/core_fetch.c`'s `ossl_method_construct`,
which is this stratum's, and that nothing in the Phase 6 crate referenced it — so it was invisible
to the symbol atlas (it is not an export), to the prerequisite gate (whose universe is names the
crate *references*) and to every court (a C probe cannot call an internal function with no entry
point and no caller). D134 built the plan-versus-crate check that made it visible and recorded it
as a deferral owned by Phase 7. **The deferral is now discharged and its row is removed**, which
is what the mechanism is for: a deferral is retired by building the name, and the gate reports
`stale_deferral` until it is. The blocking list goes 15 → 14 and the plan reconciliation's Phase 7
census drops by two — decreases, so nothing had to record them, which is the point of the
direction the invariants point in.

**Three return conventions that read alike and are not.** `algorithm_do_map` answers **-1** to quit
the whole walk, **0** to record a failure and continue, and **1** for success, and
`algorithm_do_this` treats the first two differently: -1 returns immediately, 0 sets `ok = 0` and
keeps asking that provider for its remaining operations. The third is the one a transcription is
most likely to get wrong, because the code says what it does and the comment says why:

```c
if (ret == 0) {      /* pre-condition not fulfilled: another thread got to it first */
    ret = 1;         /* -- and the map is skipped, because that is *success* */
    goto end;
}
```

A refused precondition is a **success**, not a failure. An implementation that propagated the 0
would turn a benign race — two threads fetching the same name — into a fetch failure, and the
difference is invisible unless a test asserts the *answer* rather than the call. It does now:
`a_refused_precondition_is_success_and_skips_the_map`.

**`post` overwrites `ret` when it refuses, and `ret` does not survive it.** The authority is
`if (post == NULL) ret = 1; else if (!post(..., &ret)) ret = -1;`, so a post that writes 0 and
answers 1 leaves a soft failure while a post that answers **0** overwrites whatever it had written.
The first version of this file's test asserted the shape a hand-written implementation would have —
that an erroring post left `ret` alone — and the assertion is what found the difference. The test is
now named for the behaviour that is actually there.

Two smaller facts the file records because a reader would otherwise assume them away. The operation
range is `OSSL_OP_DIGEST` (1) through `OSSL_OP__HIGHEST` (**22**), not through `OSSL_OP_KEYEXCH`
(11): the reserved ids above the last named operation are real dispatch ids a provider may publish,
and `operation_id == 0` means "all of them" rather than being passed through. And
`ossl_algorithm_get1_first_name` splits on the **first** colon, copies rather than borrowing, and
answers NULL — not an empty string — for a NULL name list, which a caller can see under
`OPENSSL_free`.

**`OSSL_ALGORITHM` is completed, where Phase 6 declared it.** Phase 6 left it an opaque forward
declaration and recorded that the definition was this stratum's, because its four members are what
the fetch machinery walks. It now has them, with `implementation` typed `*const c_void` rather than
as the dispatch struct the authority declares: the only reader upcasts it immediately, and typing it
would invite a dereference the authority never performs. The type stays in `src/provider/activate.rs`
rather than moving to `src/evp/`: that is where the pointer crosses the provider boundary and where
the accessors that hand it out live, and where the *members* are written is not a fact any caller
can observe.

Six unit tests, and the four that matter are the three return conventions and the two `post`
behaviours — the branches that produce identical call sequences and different answers. `ossl_algorithm_do_all`'s
own two paths (the sweep, and the one named provider whose context is asserted equal) are **not**
unit-testable without a provider registry fixture and are `RT-FETCH`'s, which lands with the method
store: `ossl_method_construct` and the store are 7.1's other half and remain open.

SPDX-License-Identifier: Apache-2.0


## D141 — 7.1's second half: the walk's six callbacks, Phase 7's whole error-coordinate surface, and a store that a sealed stratum still owed

**What landed.** `src/evp/method_store.rs` is `crypto/core_fetch.c` transcribed whole:
`ossl_method_construct` and the five callbacks it hands to `ossl_algorithm_do_all` —
`reserve_store`, `unreserve_store`, `precondition`, `this` and `postcondition` — with
`ConstructData`, the opaque `OSSL_METHOD_STORE` and `OSSL_METHOD_CONSTRUCT_METHOD`, and seven unit
tests. The export is `#[no_mangle]`; the five callbacks are not, because the authority's are
`static`. With it, **both deferrals Phase 6 handed forward (D132, D134) are discharged**:
`ossl_algorithm_do_all` went in D140 and `ossl_method_construct` is this entry, so its row leaves
`forensics/prerequisites.json` and the gate's blocking list drops 15 to 14.

**The file is a callback host, and the shape follows from that rather than from taste.** The five
`ossl_method_construct_*` functions are not a call graph — they are entry points the walk reaches in
a fixed order (`reserve_store` → `precondition` → `this` → `postcondition` → `unreserve_store`), and
the policy lives in that order. Two of the arms read like errors and are not, which is D140's
lesson arriving one file later: a **refused precondition is success** (the authority negates the
provider's operation bit to turn "methods have been constructed" into "construction should happen",
and `algorithm_do_map` turns the resulting 0 into "skip this map, continue the walk"), and **a
refused construction is silence** (a provider may publish an algorithm this build cannot
instantiate). A transcription that "fixed" either one would fail in the direction that looks like a
performance problem and is a correctness one.

**The reference is dropped here and not by the store.** `this` constructs, puts and then calls
`mcm->destruct` on the method it just built, because the authority's own comment says the `put`
function is *expected* to increment the refcount: the sequence is construct (1) → put (2) →
destruct (1), and the store's reference is what survives. Skipping the destruct leaks one reference
per algorithm per fetch, and the memory courts would not catch it — nothing counts, because the
store holds them forever. Both halves are asserted, per arm.

## The transcription corrections, and one of them was mine

**I had invented two NULL checks that the authority does not have.** The first draft of this file
guarded `data->mcm` with `if (mcm.is_null()) return 0;` in three places. The authority dereferences
it unconditionally, and the sibling `algorithm.rs` transcribes `algorithm_do_map`'s
`reserve_store` call the same way with the contract stated in `# Safety`. The guards are gone: a
NULL `mcm` is a caller error on both sides, and converting it into a silent refusal would have been
a behaviour change in exactly the case the contract excludes. This is the same family as D140's
four defects and it was found the same way — by reading the two files against each other rather
than by running anything.

**Two of `ConstructData`'s six fields are never assigned by the authority.** `ossl_method_construct`
declares `struct construct_data_st cbdata;` as a stack local and sets four fields; `libctx` and
`operation_id` are indeterminate and **nothing in the file reads either**, because the walk takes
the operation from its own argument and the callbacks are never given the libctx at all. This
transcription assigns both from its parameters, which is a divergence in the crate's favour — the
struct is fully determined — and it is invisible because no reader exists on either side. Rust
cannot spell an undetermined field, and inventing a read to justify a write would be worse than the
write; the field docs now say so instead of claiming the authority sets them.

**And a unit I had wrong in the plan.** `src/evp/method_store.rs`'s first draft said the store type
"belongs to `evp_fetch.c`". Phase 7's own plan row said the same. Both are wrong:
`crypto/evp/evp_fetch.c` *calls* `ossl_method_store_new` and its eleven siblings, and
**`crypto/property/property.c` defines them** — alongside the three global-properties functions
6.7a left behind (`ossl_ctx_global_properties`, `ossl_global_properties_no_mirrored`,
`ossl_global_properties_stop_mirroring`). The plan row is corrected above the line, the module doc
with it, and the deferral rows below.

**D140 had exported two internal functions, and that is corrected here too.** `ossl_algorithm_do_all`
and `ossl_algorithm_get1_first_name` were landed `#[no_mangle] pub`. Neither is an authority export:
`forensics/atlas/symbol-ownership.json`'s universe is the 6,499 symbols the DSO *exports*, and both
names are hidden from the authority's `.so` by libcrypto's version script. The crate's own rule says
so — an `ossl_*` internal is `pub(crate)` with no `#[no_mangle]` — and the cost of getting it wrong
is exactly the one `implemented-surface.json` tracks: a crate-global name a consumer's own function
of the same name could collide with, for a symbol nothing outside the crate can call. Both are now
`pub(crate)`, with a dead-code allowance where nothing calls them yet and the note naming the
subphase that will (`ossl_algorithm_get1_first_name` is the eight `_meth.c` constructors' in 7.3 and
7.4; `ossl_method_construct` is `inner_evp_generic_fetch`'s in 7.2). `ossl_method_construct` is
`pub(crate)` from the start for the same reason.

## Phase 7's error coordinates, registered as a subsystem set

`crypto/core_fetch.c` raises from two sites, at lines 65 and 92 — the `ossl_assert(result != NULL)`
in the pre- and the postcondition, each followed by `ERR_raise(ERR_LIB_CRYPTO,
ERR_R_PASSED_NULL_PARAMETER)`. Registering only those two would have been the per-file habit that
Phase 5 and Phase 6 both rejected in favour of the *subsystem* set, and the reason is worth
restating: a site nobody calls yet is a coordinate, not a claim, and a file that lands later without
its coordinates is a gap that only a careful reader notices. So `gen_err_raise_sites.py` gains
**57 files and 767 sites** — every `crypto/evp/` translation unit that raises anything (49 of 84),
`crypto/hpke/hpke.c` (7.6's, and not in `crypto/evp/` at all), `crypto/core_fetch.c`, and the eight
per-symbol exceptions the plan's own 7.4 and 7.5 rows name (`crypto/asn1/ameth_lib.c`, `i2d_evp.c`,
`d2i_pr.c`, `d2i_param.c`, `d2i_pu.c`, and `crypto/pem/pem_pkey.c`, `pem_pk8.c`).

**The 37 that raise nothing are named rather than omitted.** `bio_enc.c`, `bio_md.c`, `bio_ok.c`,
`encode.c`, the twelve `legacy_*` wrappers, the legacy cipher wrappers whose primitives are Phase
13's, the five name/type helpers, the two algorithm tables, `cmeth_lib.c` and `evp_err.c` are all
absent on purpose, and `evp_err.c` is the one worth naming: it is the error *string* table for the
whole library and it raises nothing at all, so listing it would be an entry that can never change
and would read as coverage that does not exist. `crypto/hmac/hmac.c` and `crypto/cmac/cmac.c` look
as if they must raise and do not — both are façades over `EVP_MAC`, and every refusal a caller sees
comes from the provider's implementation.

**Seven authority sites pass a reason constant where the library argument belongs, and the
generator now attributes them.** `ERR_raise(ERR_R_EVP_LIB, ...)` appears four times in
`exchange.c` and once each in `kdf_lib.c` and twice in `mac_lib.c`. They were recorded as
*unattributed*, which was right about the shape — a library argument that is not a library constant
is usually a call spelled inside a macro body — and wrong about these seven, which are real,
reachable, observable sites in this stratum's surface. Emitting them is a transcription and not an
interpretation: `ERR_set_error` packs `(lib & ERR_LIB_MASK) << ERR_LIB_OFFSET` and the authority's
`ERR_LIB_MASK` is **`0xFF`**, so `ERR_R_EVP_LIB` = `(4|ERR_RFLAG_COMMON)` = `0x80004` contributes
exactly the `4` that `ERR_LIB_EVP` would. The resolved value is emitted rather than the low byte,
because the table records what the authority's argument evaluates to and the masking belongs to the
code that consumes it. Three reason families came with them and three headers are added to the
resolver — `evperr.h`, `pemerr.h`, `rsaerr.h`, all installed, so no `internal/` fallthrough was
needed for this stratum — and the atlas now reports **1,619 sites, 852 → 1,619, with zero
unattributed**.

## The tests, and one that was not testing what it said

Seven tests. Five are about the policy arms an implementation is most likely to get plausibly
wrong: the temporary-store predicate (`no_store && !force_store`, both halves), the store being
obtained **once** however many maps the walk visits, a permanent store never being asked for a
temporary one and being passed as NULL, the put/put-NULL split with the destruct on both arms, and
the refused construction that puts and destructs nothing.

Two are new and are about the coordinate rather than the refusal, because that is the observable:
**a NULL `result` refuses at `CORE_FETCH_65` and `CORE_FETCH_92`**, asserted against the recorded
file, line and function through `ERR_peek_last_error_all` rather than against the return code. The
first version of that helper compared the *first* queued error and failed on the second assertion —
which is the test doing its job.

**One test was deleted for claiming coverage it did not have.** The draft ended with
`the_lookup_prefers_the_temporary_store_and_then_the_global_one`, which called `mcm->get` twice by
hand and never entered `ossl_method_construct` at all; it would have passed against a transcription
with the two lookups in the wrong order. The two-lookup policy is *not* unit-testable: the branch
between the lookups is chosen by `cbdata.store`, which only the walk fills, so reaching it needs a
provider that can be queried — and a unit test that called `ossl_algorithm_do_all` for real would
sweep the default context, activate the three predefined providers and read `openssl.cnf` as a side
effect of `cargo test`. The sibling `algorithm.rs` draws the same line for the sweep. **`RT-FETCH`
is the observation**, and the module doc says so where a reader will meet it rather than leaving the
gap to be inferred.

## The record defect this turned up, which is the entry's most useful part

While reading where the store lives, the deferral rows for it turned out to be owned by **Phase 6**
— with the reason "Phase 6.7c/6.8: the method store" — and Phase 6 is **complete**. Fifteen names
(`ossl_method_store_new`, `_free`, `_add`, `_remove`, `_remove_all_provided`, `_fetch`, `_do_all`,
`_cache_flush_all`, `_cache_get`, `_cache_set`, `ossl_method_lock_store`,
`ossl_method_unlock_store`, `ossl_ctx_global_properties`, `ossl_global_properties_no_mirrored`,
`ossl_global_properties_stop_mirroring`) were therefore **neither blocking the gate nor reported as
stale**: `blocking` is computed from rows whose owner stratum is not complete, and `stale_deferral`
from rows the crate has since built. A name owed to a sealed stratum fell between the two readings.

Phase 6 knew. Its plan gives the work to subphase 6.7c (`docs/PHASE-6-SUBPHASES.md` row 6.7c), its
seal records that the four method stores are Phase 7's and Phase 10's, and D-6.8c's own text says
"`ossl_method_store_cache_flush_all` and `_remove_all_provided` are 6.7c's, which 6.7 deferred to 6.8
and which has not landed". What did not happen is the *retargeting*: 6.7c is a subphase of a stratum
that closed, and a row pointing at it is a row pointing backwards.

The fix is a measurement and not a preference. The owner of a shared internal is the earliest
stratum that calls it, and `crypto/evp/evp_fetch.c` is `ossl_method_store_new`'s first caller —
ahead of `crypto/encode_decode/decoder_meth.c`, `encoder_meth.c` and `crypto/store/store_meth.c`,
which share the same store object. All fifteen retarget to Phase 7, with the caller written into
each row so a reader can check the claim. The gate's blocking list goes **14 → 28**, which is the
*correct* direction and the reason this entry is not a quiet edit: fifteen obligations that were
invisible are now counted.

This is the `a2d_ASN1_OBJECT` failure class arriving through a third route. D49/D72 fixed discovery
by header; D134 fixed plan-versus-crate reconciliation; this one is a *stale phase field* in a
hand-maintained record, and the invariant that would have caught it — "a complete stratum has no
unbuilt deferrals attributed to it" — is not one the gate computes. It is computed now, by the
transition row in `forensics/ownership-transitions.json` and by a reason that has to be read.

### Arithmetic

| | before | after |
|---|---|---|
| Phase 7 implemented / open | 0 / 950 | 0 / 950 (no export) |
| discharged deferrals | 0 | 1 (`ossl_method_construct`) |
| gate blocking dependencies | 14 | 28 |
| recorded err sites / unattributed | 852 / 0 | 1,619 / 0 |
| covered authority files | 106 | 164 |
| crate-global non-authority symbols | 275 (D140) | 273, which is main's own count |
| unit tests | 295 | 302 |

SPDX-License-Identifier: Apache-2.0

## D142 — the method store's object layer, and the checked invariant that fired exactly as designed

**What landed.** `src/property/store.rs` is `crypto/property/property.c`'s remainder, first half: the
four types the store is made of (`METHOD`, `IMPLEMENTATION`, `QUERY`, `ALGORITHM`) and
`OSSL_METHOD_STORE` itself; `ossl_method_up_ref`/`_free`; the three property-lock helpers; the
`QUERY` hash and comparator; `impl_free`, `impl_cache_free`, `impl_cache_flush_alg` and
`alg_cleanup`; `ossl_method_store_new`, `_free`, `ossl_method_lock_store`, `_unlock_store`,
`_retrieve`, `_insert`; `ossl_method_store_add`, `_remove`, `_remove_all_provided` and
`_cache_flush_all`; and with them the two global-properties accessors 6.7a left plus the
`no_mirrored` field they need. Six unit tests. **The query path — `ossl_method_store_fetch`, the
cache's `_cache_get`/`_cache_set` and the stochastic half of the flush, and `_do_all` — is the other
half and lands with `RT-FETCH`**, which is what turns any of this from a transcription into evidence.

**`crypto/property/property.c`'s remainder is a `#!allow(dead_code)]` module, and that is a
statement rather than a convenience.** Every entry point here is called by a *client* stratum's
module — `_add`, `_remove`, `_remove_all_provided` and `_cache_flush_all` by `evp_fetch.c`'s
methods, `_lock_store`/`_unlock_store` by its `mcm`, `_fetch` and the cache pair by the fetch itself
— so at the moment the object lands, nothing in this crate calls six of them. The allowance is one
line with the condition that retires it (7.2) rather than eight per-item ones each restating the
same paragraph.

## The slot table, and the invariant that caught me

`ossl_method_store_new` is the constructor for **four** slots, not one: `evp_method_store` (0),
`decoder_store` (10), `encoder_store` (11) and `store_loader_store` (15), which is why D-6.8c's note
says "the four method stores are `ossl_method_store_new(…)`'s (Phase 7 and 10)". D142 fills **slot 0
only**, in the authority's own position in `context_init` — immediately after the context's lock and
before the provider-config object, because the authority marks it `P2` ("cleaned up before the
provider store") and it is the first `P2` object it builds — with the matching release first in
`context_deinit_objs`. The other three are read by `decoder_meth.c`, `encoder_meth.c` and
`store_meth.c`, which are Phase 10's, and `decoder_cache` (20) is `ossl_decoder_cache_new`'s, which
does not exist yet; filling a slot whose reader has not landed would be filling a slot for nobody.

**And that is exactly what Phase 6 predicted, down to the failure message.** `src/provider/stores.rs`
ends each of the nine store bridges in a call it could not make, and rather than write a plausible
body it wrote the authority's branch guarded by `assert_slot_unfilled`, whose text is *"reached with
its store slot filled, but Phase 7 has not landed the store method it delegates to"*. Filling slot 0
made `the_five_slots_are_unfilled` fail on the first `cargo test`, by design, and the answer it
pointed at is the one taken: `evp_method_store_cache_flush` and
`evp_method_store_remove_all_provided` now **delegate** — flush the store if the slot is filled,
answer 1 if it is not — which is the authority's own three lines. The invariant test is reframed
rather than deleted: slot 0 must now be filled and slots 10, 11, 15 and 20 must not, so it fires
again for the next stratum. Three tests in `src/provider/activate.rs` also failed and passed again
with the delegation written, which is the same fact seen from the activation path.

**My own test found a defect in my own transcription.** `ossl_method_store_remove_all_provided` was
documented and asserted as "always answers 1, including for a NULL store". It does not: the
authority's first statement is `if (!ossl_property_write_lock(store)) return 0;`, and a NULL store
cannot take a lock, so it is **refused before the provider is looked at**. The `1` belongs to the
*bridges*, which test the slot themselves and never reach the store with NULL. The test was wrong,
the doc comment was wrong, and the two had agreed with each other — which is the shape a made-up
contract takes when nothing independent checks it.

**And a layout residual is resolved rather than carried.** `src/property/globals.rs` recorded that
`OsslGlobalProperties` was the authority's struct *minus* the `no_mirrored` bit, with the four-byte
padding difference as a residual. The field is now there — a `u32` written through a named mask, for
`OsslProvider`'s flags' reason — because the two functions that read and write it landed with it, and
a pointer plus a one-bit field round to the same sixteen bytes on both sides.

### Arithmetic

| | before | after |
|---|---|---|
| Phase 7 implemented / open | 0 / 950 | 0 / 950 (no exported surface: the store is internal) |
| store/lifecycle entry points built | 0 | 11 |
| recorded deferrals discharged | 1 | 12 |
| gate blocking dependencies | 28 | 17 |
| channel slots filled, of 23 | 14 | 15 (slot 0) |
| unit tests | 302 | 308 |

SPDX-License-Identifier: Apache-2.0

## D143 — the store's query path, and a plan claim the authority's own build record contradicts

**What landed.** The rest of `crypto/property/property.c` in `src/property/store.rs`:
`ossl_method_store_fetch`, the match itself; `ossl_method_store_cache_get` and `_cache_set`, the two
entry points and the delete arm that `_cache_set` hides behind a NULL method; the stochastic flush —
`ImplCacheFlush`, `impl_cache_flush_cache`'s Marsaglia xorshift, `impl_cache_flush_one_alg` and
`ossl_method_cache_flush_some`; `ossl_method_store_do_all` with `alg_do_one`, `alg_copy` and
`del_tmpalg`; and `src/runtime/rdtsc.rs`, the `OPENSSL_rdtsc` the flush seeds from. Five more unit
tests, 308 → 313. **The store is now whole**: every function `crypto/property/property.c` defines
except `ossl_ctx_global_properties_new`/`_free` (6.7a's, already in `globals.rs`) is present.

Three shapes in the query path are worth naming, because each is a place a plausible implementation
differs from the authority:

* **the no-query and query paths are two loops, not one loop with a condition.** With no query the
  *first* implementation of a matching provider wins — provider preference is the order of the
  implementation stack — and with a query every implementation is scored by `ossl_property_match_count`
  and the best wins, **stopping early only when the query has no optional properties**;
* **the caller's query is merged with the context's global properties**, and the two merge cases are
  not symmetric: with no caller query, `pq` becomes an *alias* of the context's own list and must not
  be freed, which is why the free at the tail is of `p2`;
* **`_cache_set` with a NULL method is a delete**, and the entry point has a destructor parameter it
  does not use on that path.

**The stochastic flush's outcome is not reproducible on either side.** Its seed is the CPU timestamp
counter, so which cached entries survive is seed-dependent on the authority as well; the authority's
own comment calls the strategy a deliberate compromise. `RT-FETCH` therefore observes the
*threshold* — `cache_nelem` crossing `IMPL_CACHE_FLUSH_THRESHOLD` (500) sets `cache_need_flush` —
and not the flush's result, and the unit test for the threshold inserts 500 distinct query strings
rather than asserting anything about which of them the flush keeps.

**A signature of mine was wrong in a way Rust's type system then made visible.** `prov_rw` is the
authority's `const OSSL_PROVIDER **prov_rw` — a *writable* pointer to a `const OSSL_PROVIDER *`,
because the fetch writes the provider that answered back through it. D142 had spelled it
`*const *const` and used `cast_mut` internally, which clippy rejected as a mutable-reference-needing
const parameter. The corrected type is `*mut *const OsslProvider`, and the same correction went into
`src/evp/method_store.rs`'s `McmGetFn`, whose `mcm->get` writes `*prov` too. The `cast_mut` is gone.

**And the plan said `no-asm`, which is false.** `docs/PHASE-7-SUBPHASES.md` §3.5 recorded "`no-asm`
is set, so no `crypto/evp/*.s` or per-architecture `.pl` output is a dependency". The authority's own
build record contradicts it three times: `%disabled` in `configdata.pm` — the admitted profile's
actual disable list, 41 entries — contains `trace`, `fips`, `md2`, `rc5`, `ktls`, `asan`, `ubsan`,
`zlib` and their siblings, and **`asm` is not among them**; `"asm_arch" => "x86_64"` and
`"perlasm_scheme" => "elf"` are recorded; and the build tree holds `crypto/x86_64cpuid.s` **and**
`libcrypto-shlib-x86_64cpuid.o`, where the `.s` is perlasm output that a `no-asm` build does not
produce. That is the same class as D141's fifteen mislabelled rows — a recorded claim contradicted by
measurement — and it is corrected in the plan rather than worked around, because the *consequence* is
not local to this stratum: every `crypto/*.pl` and `crypto/*/*.pl` output is part of the authority
this crate reconstructs, hidden from the DSO by the version script and therefore never exported
surface, but reached all the same by any transcription that calls `aesni_encrypt` or
`sha256_block_data_order`. Phase 8 and Phase 9 are the strata that will meet it.

`OPENSSL_rdtsc` is this stratum's instance, and its value is the one thing here that no court can
assert: the perlasm body assembles the full 64-bit counter in `rax` and the declared return type is
`uint32_t`, so the transcription takes the low half; the `x86_64` arm is the `_rdtsc` intrinsic and
the non-`x86_64` arm answers **0**, which selects the caller's documented global-seed branch rather
than inventing a timestamp source the authority does not have on that target either. The admitted
profile is `linux-x86_64`, so that arm is outside the claims in the first place; it is recorded in
`docs/SECURITY_DIVERGENCE_POLICY.md`'s class list rather than left as an implied fallback.

**Six `#[allow(dead_code)]` rows in `src/runtime/sparse_array.rs` were stale and are gone.** Each
named `6.10a-ii` as the subphase that would reach it, and the store reaches four of them
(`doall_arg`, `num`, `get`, `set`) a stratum earlier; the two that remain are the `_ex` pair.

### Arithmetic

| | before | after |
|---|---|---|
| Phase 7 implemented / open | 0 / 950 | 0 / 950 (the store is internal) |
| store functions present, of `property.c`'s | 11 | 21 |
| recorded deferrals | 17 | 13 |
| unit tests | 308 | 313 |

SPDX-License-Identifier: Apache-2.0

## D145 — 7.2's first half: Phase 7 has exports, and a probe that lied to itself

**What landed.** `src/evp/fetch.rs` is `crypto/evp/evp_fetch.c`'s **default-property** half:
`evp_set_parsed_default_properties`, `evp_set_default_properties_int`,
`EVP_set_default_properties`, `evp_default_properties_merge`,
`evp_default_property_is_enabled`, `EVP_default_properties_is_fips_enabled`,
`evp_default_properties_enable_fips_int`, `EVP_default_properties_enable_fips`,
`evp_get_global_properties_str`, `EVP_get1_default_properties`, and `get_evp_method_store` —
the slot read that keeps the index number in one place. Four unit tests, and **Phase 7's first
four exports**: `implemented[libcrypto]` 1135 → **1139**, three of the ten remaining blocking
deferrals discharged (13 → 10 recorded), and `RT-FETCH` extended from 27 to **38** observations
and passing.

The split is by dependency rather than by file: `evp_fetch.c` is two stories in one translation
unit, and the boundary is a lock. The *fetch* story needs `EVP_MD`'s and `EVP_CIPHER`'s method
objects, which are 7.3's and 7.4's; the *default-properties* story needs the per-context
global-property list 6.7a holds, 6.7b's grammar, and the store's cache flush that D142/D143
landed. So this half is writable now and that half is not, and the file says so rather than
being one long scaffold.

**Three things in it are easy to get backwards, so they are recorded.** The properties are
stored as a list but **rendered back to text and handed to every activated provider**
(`ossl_provider_default_props_update`) before the list is swapped — a provider that rebuilds its
own tables needs the query as text. The old list is **freed and the new one adopted**, not
merged: merging happens one level up and only when the context already has something, and the
`loadconfig` that inner call passes is **0**, because the accessor two lines above already
loaded the file. And after the swap the store's query cache is flushed, because every cached
answer was computed under the old query.

**`mirrored` is a one-way flag.** A child context starts with its parent's properties mirrored;
an explicit update stops mirroring permanently and a mirroring update is refused outright once
that has happened. There is no call that turns it back on, which is why the refusal is the
feature rather than a bug.

**A measurement replaced a guess, in a test I wrote.** The first version of
`enabling_and_disabling_fips_merge_the_two_opposite_forms` asserted that the text after
enable-then-disable is `fips=yes,-fips` — the list *accumulating* both forms — and the run said
`-fips`. A merge gives the incoming query precedence over the list it merges into, so a
property cannot survive as both itself and its negation. The assertion is now the measurement,
with the reason written down, because a list holding both forms would select nothing and would
pass any test that only checked the return code.

**And `RT-FETCH` caught itself lying, which is the entry's most useful part.** The first version
of the extended probe forgot `#include <openssl/evp.h>`. In C11 an undeclared function is
assumed to return `int`, so `char *props = EVP_get1_default_properties(ctx)` truncated a pointer
to its low 32 bits and the probe **segfaulted on both sides after twenty observations** — with
`residual_count: 0`, because two sides dying at the same place produce identical transcripts.
The runner's `crashed` flag is what turned that into a failure rather than a pass; Phase 3 and
Phase 4 added it for exactly this reason and this is the first time it has earned its keep in
this stratum. The compile line now carries
**`-Werror=implicit-function-declaration`**, so the warning that was there all along is a build
failure instead of a mystery, and the probe's header records it.

### Arithmetic

| | before | after |
|---|---|---|
| Phase 7 implemented / open | 0 / 950 | **4 / 946** |
| `implemented[libcrypto]` | 1135 | 1139 |
| recorded deferrals | 13 | 10 |
| gate blocking dependencies | 13 | 10 |
| courts / RT-FETCH observations | 57 / 27 | 57 / 38 |
| unit tests | 313 | 317 |

SPDX-License-Identifier: Apache-2.0

## D146 — 7.2's fetch half: the `mcm` interface, and every Phase-7 blocker discharged

**What landed.** `src/evp/fetch.rs` gains `crypto/evp/evp_fetch.c`'s other half: `NAME_SEPARATOR`
and the four method-id masks with `evp_method_id`; `struct evp_method_data_st` and its three
function-pointer types; the six `mcm` callbacks (`get_tmp_evp_method_store`,
`dealloc_tmp_evp_method_store`, `reserve_evp_method_store`, `unreserve_evp_method_store`,
`get_evp_method_from_store`, `put_evp_method_in_store`, `construct_evp_method`,
`destruct_evp_method`); `inner_evp_generic_fetch`; `evp_generic_fetch` and
`evp_generic_fetch_from_prov`; `filter_on_operation_id`, `evp_generic_do_all`, `evp_is_a` and
`evp_names_do_all`. Plus `ossl_lib_ctx_get_descriptor` in `src/context/mod.rs`, which lands with
its first caller because the fetch path's error *data* carries it.

**All five remaining Phase-7 deferral rows are discharged** — recorded 10 → 5, and the gate's
blocking list goes **15 → 5**: the only names left are Phase 16's three `OPENSSL_info` strings,
Phase 9's `ossl_random_add_conf_module` and Phase 13's `OSSL_provider_init`. **No Phase-7
deferral blocks anything.**

Five things in this half are contract rather than detail:

  * **the id is 31 bits on purpose.** The composite is `(name_id << 8) | operation_id`, limited so
    bit 31 is never set: `filter_on_operation_id` masks the low byte back out of an `int`, and a
    value with bit 31 set would sign-extend on the way there, so the operation a `do_all` filters
    on would be wrong for exactly the names with the most aliases. The masks are the authority's
    four macros, not a `(a << 8) | b` with the widths left to the reader;
  * **the name is truncated at the first separator before a lookup**, but the whole alias list is
    handed to `ossl_namemap_add_names` on construction — which is why `inner_evp_generic_fetch`
    re-resolves the id **after** the walk. A fetch of `"sha256:sha2-256"` constructs a method and
    then fails to cache it, because the combined string is not a name. The authority calls this a
    corner case and the code keeps it;
  * **`flag_construct_error_occurred` is set in exactly one place** — the class constructor's
    refusal — and it is the whole of the difference between the two error reasons a failed fetch
    reports: `ERR_R_FETCH_FAILED` when the algorithm is known but could not be built,
    `ERR_R_UNSUPPORTED` when the name resolved to nothing. Setting it on the namemap failure too
    would make every fetch of an unknown name report a construction error;
  * **`properties` is used only in the error message.** The query the store is given is the
    caller's properties or the empty string; the difference between the two arguments is visible
    only in what `ERR_get_error_all` reports back — and both messages are `ERR_raise_data` with the
    authority's format string verbatim, so both are contract. They are formatted into a
    **1024-byte** buffer because that is `ERR_MAX_DATA_SIZE`, the size `ERR_vset_error` grows to
    before formatting and therefore the size it truncates at;
  * **`evp_generic_do_all` is a fetch with a NULL name first.** A `do_all` cannot enumerate what
    was never fetched, so it constructs every algorithm of every activated provider and then walks
    the temporary store (if one was made) before the context's own. The consequence is visible: a
    provider whose constructor refuses for one algorithm leaves it out of the enumeration.

**The site at `evp_fetch.c:376` is the one place this file raises a reason that is not its site's
constant.** The authority computes `code = unsupported ? ERR_R_UNSUPPORTED : ERR_R_FETCH_FAILED`,
and because that argument is an identifier the generator recorded the site with
`dynamic_reason: true` and reason `0` rather than guessing one — so the transcription uses
`raise_site_dynamic_data`, which keeps the *coordinates* (file, line, function are the authority's)
and takes the reason from the caller. `ERR_R_FETCH_FAILED`'s numeric value is read from the
generated `EVP_FETCH_352` site rather than typed.

**Two compile-level facts worth recording.** `strchr` is already declared twice in this crate
(`src/dso/dlfcn.rs`, `src/runtime/bio/sys.rs`) returning `*mut c_char`, so this module's
declaration matches that spelling and casts — a third spelling would be a
`clashing_extern_declarations` warning, which the deny-list turned into an error on the first
build. And the fetch half is `#![allow(dead_code)]` for the same reason the store is: its callers
are the class methods of 7.3 and 7.4, which is one paragraph rather than twenty allowances.

### Arithmetic

| | before | after |
|---|---|---|
| Phase 7 implemented / open | 4 / 946 | 4 / 946 (the fetch half is internal) |
| recorded deferrals | 10 | **5** |
| gate blocking dependencies | 10 | **5** |
| of which Phase 7 | 5 | **0** |
| unit tests | 317 | 317 |

SPDX-License-Identifier: Apache-2.0

## D147 — 7.2 closes, and its exit criterion is corrected rather than claimed

**7.2 is complete**: D145 landed the default-property half and D146 the fetch half, so every
function `crypto/evp/evp_fetch.c` defines is transcribed and all five of this stratum's remaining
deferrals are discharged. The gate's blocking list is **15 → 5**, and **no Phase-7 name blocks
anything**: what remains is Phase 16's three `OPENSSL_info` strings, Phase 9's
`ossl_random_add_conf_module` and Phase 13's `OSSL_provider_init`.

**One of the row's two exit criteria cannot be met in 7.2, and the correction says so.** The row
promised "a property query selects and rejects algorithms through the real fetch path, including
negative selection". That needs a *class* to fetch through: `evp_generic_fetch` is internal,
`libcrypto.ld` hides it, and a probe compiled against the installed headers reaches the fetch path
only through `EVP_MD_fetch` and its siblings — which are 7.3's, because they need the `EVP_MD`
object. So the resolver lands with 7.3's first slice, in the same commit that makes `EVP_MD_fetch`
exist, rather than as a claim this subphase cannot support. The other criterion — the property
*string* step that `D-CHILD-REGISTER-PROPS-1` and `D-CHILD-PROPS-CB-1` recorded as unreachable
becoming writable — is met: `EVP_set_default_properties` and the merge path are implemented, four
of them exports, and `RT-FETCH` observes the whole surface.

**And 7.3's first slice is named in the plan so it is not discovered.** `7.3a` is
`crypto/evp/digest.c`'s `evp_md_new`, `evp_md_from_algorithm` (the `OSSL_DISPATCH` walk,
`set_legacy_nid` and `evp_md_cache_constants`), `evp_md_up_ref`/`_free`, `evp_lib.c`'s
`evp_md_free_int`, `evp_utils.c`'s `evp_do_md_getparams`, the `EVP_MD` struct with its fifteen
`OSSL_FUNC_digest_*` types, and the three exports `EVP_MD_fetch`, `EVP_MD_free`, `EVP_MD_up_ref`.
It is the smallest slice that makes the generic fetch reachable.

One contract fact the plan now carries because it is not a probe detail: **a digest whose
`OSSL_FUNC_DIGEST_GET_PARAMS` does not answer `OSSL_DIGEST_PARAM_BLOCK_SIZE` and
`OSSL_DIGEST_PARAM_SIZE` fails its fetch with `EVP_R_CACHE_CONSTANTS_FAILED`** — so the court's
resolver provider must publish both, and a probe written without them would report the authority's
own refusal as a candidate divergence.

### Arithmetic

| | before | after |
|---|---|---|
| Phase 7 implemented / open | 4 / 946 | 4 / 946 |
| recorded deferrals / blocking dependencies | 5 / 5 | 5 / 5 |
| of which Phase 7 | 0 | 0 |
| RT-FETCH observations | 38 | 38 |
| unit tests | 317 | 317 |

SPDX-License-Identifier: Apache-2.0

## D148 — 7.3a: the `EVP_MD` object, and the first exports Phase 7 can be fetched through

**What landed.** `src/evp/digest.rs` is `crypto/evp/digest.c`'s fetch half plus the four accessors
of the same object that live in `crypto/evp/evp_lib.c` and one function of
`crypto/evp/evp_utils.c`:

* `evp_md_new`, `set_legacy_nid`, `evp_md_cache_constants`, `evp_md_from_algorithm` (the whole
  `OSSL_DISPATCH` walk), `evp_md_up_ref`, `evp_md_free`, `evp_md_free_int`, `evp_do_md_getparams`;
* the `EVP_MD` struct with the fifteen `OSSL_FUNC_digest_*` types and their ids;
* **seven new exports**: `EVP_MD_fetch`, `EVP_MD_free`, `EVP_MD_up_ref`, `EVP_MD_get_type`,
  `EVP_MD_get0_name`, `EVP_MD_get_size`, `EVP_MD_get_block_size`. **`implemented[libcrypto]` goes
  1139 → 1146 and Phase 7's ledger reads 11 implemented** (D145's four plus these seven), with
  `open` 946 → 939.

Four unit tests, and one small enabling change: `src/runtime/obj.rs`'s `use obj_table::*` became
`pub(crate) use obj_table::*`, because `NID_undef` is the fetch's legacy-NID sentinel and a caller
in another module has to be able to name it rather than copy the `0`.

**This is the slice that makes the generic fetch reachable, and it is why 7.2's exit criterion was
corrected rather than claimed** (D147): everything 7.1 and 7.2 built is internal and hidden from
the DSO, so until a *class* exists to fetch through there is no observation of the fetch path at
all. `EVP_MD` is the smallest class — no key, no ASN.1, no context parameters of its own beyond
two sizes — and `RT-FETCH`'s resolver lands next, in the same subphase as the object it needs.

**The object is two objects in one struct.** `struct evp_md_st` is the legacy method (NID, sizes,
the six `EVP_MD_CTX` function pointers, `pkey_type`) **followed by** the provider-side one
(`name_id`, `type_name`, `prov`, `refcnt` and the fifteen dispatch pointers). A fetched method
fills the second half and leaves the first at zero except for the two sizes; `origin` says which
half is live, and it is exactly why `EVP_MD_free` refuses anything that is not `EVP_ORIG_DYNAMIC` —
a method from the method table is a static and freeing it would be freeing a static.

**Four things in the constructor are contract rather than detail.** The dispatch walk fills each
field **only if it is still NULL**, so the *first* entry for an id wins and a provider that
publishes `UPDATE` twice is not an error. The structural count is checked against three values —
`fncnt != 0 && fncnt != 5 && fncnt != 6` — so a digest with `newctx/init/update/final/freectx` and
nothing else is legal, one with a squeeze and no update is not, and `digest` stands alone and is
not counted. The provider reference is taken **after** that check, so a refused method never holds
one. And `EVP_MD_free` is the error path, which is why the object's `origin` is zero from the start.

**And `evp_md_cache_constants` is why a provider must answer two parameters.** `md_size` and
`block_size` are not read from the dispatch table: they are asked through
`OSSL_FUNC_DIGEST_GET_PARAMS` at fetch time, and a provider that does not answer
`OSSL_DIGEST_PARAM_SIZE` and `OSSL_DIGEST_PARAM_BLOCK_SIZE` **fails its own fetch** with
`EVP_R_CACHE_CONSTANTS_FAILED`. An `int` overflow of either is a refusal rather than a truncation,
the four parameters are asked in **one** call, and the two `EVP_MD_FLAG_*` bits are **set, never
cleared**. `RT-FETCH`'s resolver provider has to publish both parameters or the court would report
the authority's own refusal as a candidate divergence.

**One measurement replaced a call I should not have made.** A test asserted `EVP_MD_get_type(NULL)`
was harmless. It is not: the authority dereferences the argument unconditionally, so a NULL there
is undefined behaviour on both sides — the test process died at that line. The call is gone and the
reason is written where it was: this crate does not reproduce an authority fault, and a "harmless"
NULL probe of a function that has no NULL arm is the same mistake in test clothing.

**The gate's forward signal, and the record that answers it.** Adding `evp_md_free_int` made
`gen_prerequisite_atlas.py` attribute `src/evp/digest.rs` to `crypto/evp/evp_lib.c` — the module →
unit map is a majority vote over the internal symbols a module *defines* — which made the gate ask
whether the names `evp_lib.c` calls are referenced anywhere. Seven are not: `evp_cipher_cache_constants`,
the four `evp_cipher_*_asn1_*` parameter helpers, `evp_md_get_number` and one more. They are the
*accessor* half of the same file, which is 7.3b's, and they are now seven deferral rows owned by
Phase 7 — the mechanism the gate documents for "planned work whose crate-side reference arrives
with the subphase that owns it" — rather than findings. Blocking dependencies 5 → 12, which is
still *below* the authority baseline of 15 and therefore needs no transition row.

### Arithmetic

| | before | after |
|---|---|---|
| Phase 7 implemented / open | 4 / 946 | **11 / 939** |
| `implemented[libcrypto]` | 1139 | **1146** |
| recorded deferrals | 5 | 12 (seven of them this unit's remainder) |
| gate blocking dependencies | 5 | 12 |
| unit tests | 317 | 321 |

SPDX-License-Identifier: Apache-2.0

---

## D149 — 7.3a's court: the resolver lands, and it finds the fetch's failure reason wrong

**`RT-FETCH` now observes the fetch path.** D147 corrected 7.2's exit criterion because the
criterion needed a *class* to fetch through, and the class arrived in D148; this is the resolver
that criterion named, landed in the same subphase as the object it needs. The court's provider
publishes **one digest under three names with one property definition** (`provider=court`), and
the observation count goes **38 → 60**. What the new half observes, in the order a consumer would
meet it: a plain fetch resolving (`nonnull`, name matches, size 32, block size 64, legacy NID 0);
the **cache** answering the same object a second time; an **alias** resolving to that same object
and reporting the canonical first name; the declared property **selecting**; a property that
contradicts it **rejecting**, with nothing to fall back to; a name nobody publishes; `up_ref`
surviving a free and leaving the object usable; and the context's own default properties doing the
reject-then-release from the other side. The provider's digest publishes only the one-shot
`OSSL_FUNC_DIGEST_DIGEST` plus `OSSL_FUNC_DIGEST_GET_PARAMS`, which is the smallest shape
`evp_md_from_algorithm` accepts, so the court exercises the *zero-structural-functions* arm rather
than the five-function one.

**The resolver found a real defect, and it is a class rather than a typo.** The authority chooses
between two reasons in one expression —

```c
int code = unsupported ? ERR_R_UNSUPPORTED : ERR_R_FETCH_FAILED;
ERR_raise_data(ERR_LIB_EVP, code, "%s, Algorithm (%s : %d), Properties (%s)", ...);
```

— and builds the **same message** for both. The crate's first revision used
`err_sites::EVP_FETCH_352.reason` for *both* arms: that site is the neighbouring `ERR_raise_data`
at `evp_fetch.c:352`, which belongs to the *other* arm and has a reason of its own, so every fetch
that found nothing raised `ERR_R_FETCH_FAILED` where the authority raises `ERR_R_UNSUPPORTED`.
Three observations expose it and nothing else in any transcript could have: `fetch.rejected.err`,
`fetch.unknown.err` and `fetch.unloaded.err` are the reason *codes*, and every other line the two
libraries agree on. A court that printed only `NULL` would have reported this path as passing
forever. `ERR_R_UNSUPPORTED` is now composed from `err.h`'s own `ERR_RFLAG_COMMON` the way
`src/runtime/init.rs` spells `ERR_R_INIT_FAIL`, and **a unit test pins it against
`err_sites::PARAM_BUILD_265`** — a generated site that raises the constant literally — so the
typed value and the authority-derived one cannot drift apart silently.

**The first wiring of the block was wrong, and the mistake was kept rather than deleted.** It was
placed after the two `OSSL_PROVIDER_unload` calls, so every fetch in it failed on both sides and the
block degenerated into one `else` arm. That accident is what exposed the reason code. So the
resequencing puts the resolver where the provider is **loaded** — where it observes resolution
rather than a refusal — and gives the unloaded case its own named block, with its own justification
for existing: it is the only place the reason is observable, and it is kept on purpose. The tail
observation `after.store.stable` now clears the queue first, so that line is about the *store*, as
it says, instead of about whichever block ran last.

**A second, smaller record defect is corrected in the same commit.** `src/runtime/bio/mod.rs`
documented five `ERR_R_*` constants as coming from `cryptoerr.h` with the values `1`, `154`, `106`,
`114` and `42`. `cryptoerr.h` declares no `ERR_R_*` name at all, and none of those five numbers is
a reason code in `err.h`; they were unreferenced, so nothing observable depended on them. They now
carry `err.h` as their provenance and are composed from the header's own `ERR_RFLAG_*` bits. This
is the same defect class as the reason code above — a record that names a source which does not
contain the fact — and it is fixed rather than noted because the fix is arithmetic a reader can
check.

**One thing the resolver confirms by measurement.** `EVP_MD_get_type` on a provider digest whose
name is in no legacy table answers **0** on both sides, which is `NID_undef`: the namemap's names
and the `OBJ` NID table are still separate, exactly as D148 recorded when `set_legacy_nid` found
nothing. The observation is an *id*, so unlike a pointer it is comparable across the two libraries,
and it is the cheapest standing proof that the separation holds as the stratum grows.

### Arithmetic

| | before | after |
|---|---|---|
| Phase 7 implemented / open | 11 / 939 | 11 / 939 |
| `implemented[libcrypto]` | 1146 | 1146 |
| RT-FETCH observations | 38 | **60** |
| recorded deferrals / blocking dependencies | 12 / 12 | 12 / 12 |
| language census | 2262 | 2256 |
| unit tests | 321 | **322** |

SPDX-License-Identifier: Apache-2.0

---

## D151 — 7.3b: the `EVP_CIPHER` method object, and a Phase-6 defect four phases of callers could not see

**What landed.** `src/evp/cipher.rs` is 7.3a's shape applied to the cipher class, and it is a
subphase of its own because a cipher's context is where its *operation* lives: `EVP_CIPHER_CTX`
and the `EVP_Encrypt*`/`EVP_Decrypt*`/`EVP_Cipher*` family are 7.3c's, so **forty-two exports** land
here and every `EVP_CIPHER_CTX_*` name is a parameter rather than an export. The units are
`crypto/evp/evp_enc.c`'s method half (`evp_cipher_new`, `evp_cipher_from_algorithm` with its
four-clause structural check, `evp_cipher_cache_constants`, the three `evp_do_ciph_*` parameter
helpers, `evp_cipher_up_ref`/`_free`/`_free_int`, `EVP_CIPHER_fetch`, `EVP_CIPHER_up_ref`,
`EVP_CIPHER_free`, `EVP_CIPHER_can_pipeline`, `EVP_CIPHER_do_all_provided` and the four
method-object parameter entry points), `evp_lib.c`'s thirteen method-object accessors,
`crypto/evp/cmeth_lib.c` whole (eighteen `EVP_CIPHER_meth_*`), and `crypto/evp/e_null.c`'s
`EVP_enc_null`.

**`EVP_enc_null` is here rather than with the wrappers it looks like it belongs to**, and the
reason is the same one that puts `EVP_md_null` in 7.3d: it is the only `e_*.c` static whose
primitive is nobody's. `e_aes.c` calls `AES_encrypt` — that is Phase 13's, named in that stratum's
ledger — and a court for a method class needs something to resolve through a real provider, so the
two null methods land with their classes. It is also the first read-only method global in this
crate, and it is where the `static` + `unsafe impl Sync` pattern enters: a `const` item would be
inlined at each use and `EVP_enc_null()` would answer a different address per call, which is the
one property a method object cannot lose.

**Five deferral rows are discharged and the gate's blocking list is 12 → 10.** The two that this
subphase's code actually references (`evp_cipher_cache_constants`, `evp_cipher_get_number`) were
reported `stale_deferral` on the first run after the implementation — which is the mechanism
working — and the five that remain are restated: four take an `EVP_CIPHER_CTX *` and are 7.3c's,
one takes an `EVP_MD *` and is 7.3d's.

**`RT-EVP-CIPHER` lands with it: ninety-one observations, zero residuals.** Four algorithms, each
chosen for one clause of the structural check rather than for coverage of a table: `court-one` is
the smallest legal shape (`newctx` + `freectx` + a standalone one-shot, so `fnciphcnt` is 0 and
`ccipher` carries it), `court-enc` is the three-function arm, `court-pipe` is a pipeline with
**no** decrypt init and is therefore the only shape that separates
`EVP_CIPHER_can_pipeline(c, 1)` from `(c, 0)`, and `court-bad` publishes `update` with no `final`.

**And `court-bad` is why the refusal is worth observing rather than annotating.** The two reasons
`inner_evp_generic_fetch` chooses between share one message and differ only in the code: a name
nothing publishes takes `ERR_R_UNSUPPORTED`, and a name whose constructor was *entered and
refused* takes `ERR_R_FETCH_FAILED`. `RT-FETCH` could only reach the first, because its provider
publishes nothing illegal; this court reaches the second, and it is the arm D149's fix had to be
right about in the opposite direction. The flags are the other observation that carries weight:
`evp_cipher_cache_constants` assigns `mode` and then ORs seven bits that the parameter cannot
express, and the observed mask is `0x11300016` — five of the seven set by this probe's provider,
one from `ccipher`'s presence, one from a name in a gettable list.

**The court found a real defect, and it is older than this stratum.** `ossl_namemap_doall_names`
— `crypto/core_namemap.c`, landed in Phase 6 — ended with `count`, the number of names walked. The
authority's last line is `return i > 0;`: the answer is a *presence* answer, 1 when the number has
any name at all. Every caller for four phases tested it for zero — `evp_md_from_algorithm` does —
so the two agreed everywhere they were observed, and the crate's own unit test had encoded the
wrong semantics (`assert_eq!(..., 4)`). The first caller that *returns the value to a consumer* is
`EVP_CIPHER_names_do_all`, which 7.3b makes reachable, and it read `2` against the authority's
`1`. This is the D49/D51 class at a level below the ownership model: not a symbol that went
unowned, but a return value that no court had ever read.

**One class of fault is not reproduced and is now recorded.** The authority calls the visitor
without a NULL test, so a NULL `fn` is an indirect call through a null pointer;
`EVP_CIPHER_names_do_all` and `EVP_MD_names_do_all` pass a consumer's pointer through unchanged,
which makes that reachable. The crate answers 0, and `D-NAMEMAP-DOALL-1` in
`docs/SECURITY_DIVERGENCE_POLICY.md` records it rather than the probe reproducing it.

### Arithmetic

| | before | after |
|---|---|---|
| Phase 7 implemented / open | 11 / 939 | **52 / 898** |
| `implemented[libcrypto]` | 1146 | **1187** |
| recorded deferrals / blocking dependencies | 12 / 12 | **10 / 10** |
| courts / observations | 57 / 20,277 | **58 / 20,368** |
| prototype court: implemented / mismatches | 1146 / 0 | **1187 / 0** |
| unit tests | 322 | **328** |

SPDX-License-Identifier: Apache-2.0

---

## D152 — 7.3c's dependency map, measured before the slice is attempted

**What happened.** 7.3c was started and then stopped on purpose, and the reason is the finding:
the slice is entangled with three *other strata* in ways that the plan's file list did not show,
and two of them are not visible from `crypto/evp/evp_enc.c` at all. The work in progress is
committed **unregistered** — `src/evp/cipher_ctx.rs` is in the tree, `src/evp/mod.rs` does not
name it, and the tree therefore still builds and still passes the gates. That is a checkpoint, not
a landed slice: the ledger moves zero, the courts move zero, and nothing here is a claim.

**The four dependencies, each read from the authority rather than assumed:**

1. **ENGINE is Phase 13's, and `OPENSSL_NO_ENGINE` is undefined.** `evp_cipher_init_internal`
   calls `ENGINE_get_cipher_engine`, `ENGINE_init`, `ENGINE_get_cipher` and `ENGINE_finish`;
   `EVP_CIPHER_CTX_reset` and `EVP_CIPHER_CTX_copy` call `ENGINE_finish` and `ENGINE_init`. The
   authority's 115 `ENGINE_*` exports are Phase 13's and none exists. **This one is not a
   blocker**, and saying why is the point: `tmpimpl` is only non-NULL when an engine has been
   registered, `ctx->engine` is only non-NULL when a caller passed one, and an engine can only be
   obtained from `ENGINE_new`, which is a scaffold in the candidate — so no court can construct
   the state in which the omitted calls do anything, and the omission is recorded rather than
   stubbed. The pattern is `src/runtime/confmod/mod.rs`'s, where `ENGINE_load_builtin_engines` is
   omitted for the same reason and documented in the module.
2. **`EVP_CIPHER_CTX_get_algor` needs `d2i_X509_ALGOR`, which is Phase 11's.** One export,
   `X509_ALGOR_it` and its two codecs. Its siblings `EVP_CIPHER_CTX_get_algor_params` and
   `_set_algor_params` need only the *layout*, so they stay in 7.3c — which is why the WIP file
   declares `struct x509_algor_st`'s two fields itself with the reason written down.
3. **`EVP_CIPHER_CTX_rand_key` needs `RAND_priv_bytes_ex`, which is Phase 9's.** One export, and
   the whole of its non-`EVP_CIPH_RAND_KEY` arm. `src/runtime/rand.rs` does not exist.
4. **`EVP_CipherInit_SKEY` needs `EVP_SKEY`'s layout and `EVP_SKEY_get0_raw_key`, which are
   `skeymgmt_meth.c`'s — 7.3f's.** That one is *inside* the stratum, so it is not a hand-off to a
   later phase; it is a symbol 7.3f implements, and the ledger keeps it `open` until then.

**And the plan's earlier note that 7.3c "does not split" was wrong, so it is corrected rather than
kept.** The note said a context slice would answer only its own error paths and that the accessor
half depends on the operation half through `EVP_CIPHER_CTX_ctrl`. The second half of that is
true — `EVP_CIPHER_CTX_get_iv_length` reaches `ctrl` for a legacy cipher with
`EVP_CIPH_CUSTOM_IV_LENGTH`, so `ctrl` belongs to the arming half — but the first half is not:
`EVP_CipherInit_ex` *is* the arming path, it is four lines and it lives in the same half, so a
context armed through it can be observed by every accessor, by `EVP_CIPHER_CTX_dup`, by
`EVP_CIPHER_CTX_copy` and by the parameter round trip. The split that is real is **arming versus
moving data**: 7.3c-i is the context, its parameters and initialisation (`EVP_CipherInit*`,
`EVP_EncryptInit*`, `EVP_DecryptInit*`, the two pipeline initialisers, `ctrl`, the flags, the
accessors, the ASN.1 bridge) and 7.3c-ii is the twelve exports that push bytes through an armed
context. The plan carries the corrected row.

**Arithmetic:** unchanged. Phase 7 stays at 52 implemented and 898 open; no court observation is
added and no ledger row moves. What this entry buys is that 7.3c's four external dependencies are
known *before* the slice is written rather than discovered four hundred lines in.

SPDX-License-Identifier: Apache-2.0

---

## D153 — 7.3c-i: the context, its parameters and initialisation, and two faults the court met

**What landed.** `src/evp/cipher_ctx.rs`, registered this time: the context object and its
lifecycle, the flag trio, the whole accessor set, the parameter entry points,
`EVP_CIPHER_CTX_ctrl`'s nineteen commands, the ASN.1 parameter bridge, `set_key_length`,
`set_padding`, and the init family — `evp_cipher_init_internal` with both halves, the two pipeline
initialisers and the six `EVP_EncryptInit*`/`EVP_DecryptInit*` spellings. **53 exports**:
`implemented[libcrypto]` 1187 → 1240, and the gate's blocking list 10 → 6, because four of the
five `evp_lib.c` deferral rows are discharged by the ASN.1 bridge. The fifth, `evp_md_get_number`,
is 7.3d's.

**`ABI-PROTOTYPE` caught a signature defect before anything ran.** The two pipeline initialisers'
`iv` went in as `*const *const c_uchar`; the authority's `const unsigned char **iv` is a
**mutable** pointer to a const pointer, because the provider may advance the caller's array. The
court reported the two types by name —
`ptr(ptr(const(int:1:u)))` against `ptr(const(ptr(const(int:1:u))))` — which is the plane D98
added and the reason it is checked at build time instead of being discovered by a probe that
happens to pass a writable array. This is the first defect that plane has caught.

**`RT-EVP-CIPHER` goes 91 → 154 observations**, and its extension is the other half of the
stratum: an unarmed context's every empty arm, the two copy refusals, the flag masks, an armed
context through `EVP_EncryptInit_ex`, the parameter pair, `dup` and `copy` of an armed context,
`EVP_DecryptInit_ex` re-arming in the other direction, `reset`, and both pipeline initialisers'
refusals.

**The court found an authority fault, and the probe steps around it.** `EVP_CIPHER_CTX_gettable_params`
and `_settable_params` test `cctx != NULL` and then dereference `cctx->cipher` — which is NULL on
a context that has never been armed, which is every caller's state before its first init. The
authority's probe **died** at the first of the two. The crate answers NULL, and
`D-CIPHERCTX-PARAMS-NULL` in `docs/SECURITY_DIVERGENCE_POLICY.md` records it; the probe observes
both calls on an *armed* context, where the authority's own test is satisfied and both answer.

**And one observation was removed because it measures another stratum.** `EVP_EncryptInit_ex(ctx,
EVP_enc_null(), ...)` succeeds in the authority and fails here, and the reason is not this slice:
a legacy method with no provider is replaced by `EVP_CIPHER_fetch(NULL, cipher->nid == NID_undef ?
"NULL" : OBJ_nid2sn(nid), "")` — the **literal string `"NULL"`** — and the authority's *default
provider* publishes a cipher by that name. This crate's does not; it is Phase 13's. The probe says
so where the call would have been, because an observation there would read a missing stratum as a
behavioural divergence.

### Arithmetic

| | before | after |
|---|---|---|
| Phase 7 implemented / open | 52 / 898 | **105 / 845** |
| `implemented[libcrypto]` | 1187 | **1240** |
| recorded deferrals / blocking dependencies | 10 / 10 | **6 / 6** |
| RT-EVP-CIPHER observations | 91 | **154** |
| courts / observations | 58 / 20,368 | 58 / **20,431** |
| unit tests | 328 | **334** |

SPDX-License-Identifier: Apache-2.0

---

## D154 — 7.3c closes: the data path, and 7.3c's twelve exports observed end to end

**What landed.** 7.3c-ii: `evp_EncryptDecryptUpdate`'s block-buffering loop with
`ossl_is_partially_overlapping` and the header's `safe_div_round_up_int` fast path,
`EVP_EncryptUpdate`/`EVP_DecryptUpdate`, the four `Final` spellings with the padding loop and the
padding check, `EVP_Cipher` with its `ccipher`-preferred arm and its answer mapping, the
`EVP_CipherUpdate`/`EVP_CipherFinal*` dispatchers, and the two pipeline update/final pairs with
their pre-emptive zeroing of `outl`. **Twelve exports**, and 7.3c is closed with them.

**`RT-EVP-CIPHER` goes 154 → 185 observations, zero residuals on the first run.** The extension
adds a fifth algorithm, `court-both`, and it exists for exactly one arm: `EVP_Cipher` prefers a
method's `ccipher` over `cupdate`/`cfinal`, and neither of the two shapes the probe already
published can show that preference, because each has one of the two and not both. It also
observes the two direction refusals (which is what stops a caller encrypting through a decrypting
context), the round trip in both directions, the `_ex`-less aliases, `EVP_Cipher`'s one-shot and
its NULL-input final, and the two pipeline calls on a context that was not armed for one.

**Three transcriptions in this slice are the kind that look right and are not**, and each is
written where it can be read against the authority's own comment:

* `safe_div_round_up_int`'s **slow path**. `(a + 7) / 8` overflows for the last eight values of
  `int`; the header takes it only while `a < INT_MAX - b` and otherwise uses `a / b + (a % b !=
  0)`, which adds nothing. The caller is a length a probe chooses.
* `ossl_is_partially_overlapping`'s **integer arithmetic**. Subtracting two pointers that need not
  be in the same object is undefined in C, so the function subtracts them as integers, wraps, and
  tests the wrapped difference in both directions — `|`-ed rather than short-circuited because
  both are computed.
* `EVP_DecryptUpdate`'s **held-back block**. A full block of the output is copied into `ctx->final`
  and subtracted from `*outl`, so `EVP_DecryptFinal_ex` can check padding before the caller is
  ever handed plaintext it might have to retract. `EVP_CIPH_NO_PADDING` skips both, and the
  authority's comment on the check itself is the security-relevant line in the file:
  *"The following assumes that the ciphertext has been authenticated. Otherwise it provides a
  padding oracle."*

### Arithmetic

| | before | after |
|---|---|---|
| Phase 7 implemented / open | 105 / 845 | **117 / 833** |
| `implemented[libcrypto]` | 1240 | **1252** |
| RT-EVP-CIPHER observations | 154 | **185** |
| courts / observations | 58 / 20,431 | 58 / **20,462** |
| unit tests | 334 | 334 |

SPDX-License-Identifier: Apache-2.0

---

## D155 — 7.3d's first half, and the prototype court refusing a macro-generated export

**What landed.** 7.3d-i: `evp_lib.c`'s eleven remaining `EVP_MD_*` accessors (`EVP_MD_is_a`,
`EVP_MD_get0_description`, `EVP_MD_names_do_all`, `EVP_MD_get0_provider`, `EVP_MD_get_pkey_type`,
`EVP_MD_xof`, `EVP_MD_get_flags` and the four parameter entry points `digest.c` owns),
`evp_md_get_number`, the whole `EVP_MD_meth_*` constructor family, and `crypto/evp/m_null.c`'s
`EVP_md_null`. **36 exports**, and **the last `crypto/evp/evp_lib.c` deferral row is discharged**:
the file that 7.3a opened for one releaser is now closed across three subphases.

`RT-FETCH` goes **60 → 103 observations**, with zero residuals on the first run: the accessors read
on a *fetched* method (the only kind whose provider half is live), the constructors exercised on a
method built by hand (the only kind whose legacy half is), and `EVP_md_null` as the one global with
neither. `EVP_MD_meth_new` is also where the digest class meets the two contracts the cipher
constructors taught in 7.3b: every setter refuses a second write, and the two functions that test
their subject are `meth_dup` and `meth_free`.

**The prototype court refused nineteen of these functions, and it was right.** The first pass
generated the ten `meth_set_*`/`meth_get_*` pairs with `macro_rules!`, which is compact and is what
the cipher class did not do. `ABI-PROTOTYPE` reported every one as `UNREADABLE`: *"its macro fills
a type position in the signature"*. That is not a limitation of the reader — it is the plane's
**own sensitivity case**, which its self-test states explicitly: a `macro_rules!` return type
perturbed from `c_int` to `c_long` must be **refused rather than read**, because a signature no
plane can see is a signature no plane can check, and nineteen unchecked signatures is exactly the
hole D98 added the plane to close. The generation is gone; all thirty functions are written out.
The reading is the lesson: **a macro-generated export is an export this crate cannot make a claim
about**, and the court says so at build time rather than leaving a silent gap.

**Nine of the eighty names 7.3d's row lists are not 7.3d's, and the plan now says so.** The
`EVP_DigestSign*` and `EVP_DigestVerify*` families take an `EVP_PKEY_CTX`, and their translation
unit is `crypto/evp/m_sigver.c` — which 7.4's row already names. The ledger assigns them here
because the atlas owns a symbol by its *header* and they are declared in `evp.h`, so the plan
records the move rather than the ledger being bent to match it.

### Arithmetic

| | before | after |
|---|---|---|
| Phase 7 implemented / open | 117 / 833 | **152 / 798** |
| `implemented[libcrypto]` | 1252 | **1287** |
| recorded deferrals | 6 | **5** |
| RT-FETCH observations | 60 | **103** |
| prototype court: checked / mismatches / unreadable | 1193 / 0 / 0 | **1240 / 0 / 0** |
| unit tests | 334 | 334 |

SPDX-License-Identifier: Apache-2.0

---

## D156 — 7.3d-ii: the `EVP_MD_CTX` object, and three NULL callback calls measured rather than guessed

**What landed.** The context half of `crypto/evp/digest.c` — `struct evp_md_ctx_st`, the release
path, the initialise decision tree with both its arms, the two finals, the squeeze, the three ways
a context is copied, `EVP_Digest`, `EVP_Q_digest`, the five parameter entry points,
`EVP_MD_CTX_ctrl` and `EVP_MD_do_all_provided` — plus the twelve `EVP_MD_CTX_*` accessors that sit
in `crypto/evp/evp_lib.c` beside them. **33 exports**, and with them the object every digest call is
actually made on is transcribed rather than deferred.

**The typing correction that came with it.** `EvpMd`'s six legacy function pointers were typed with
an opaque `*mut c_void` because `struct evp_md_ctx_st` did not exist. It does now, so they take
`*mut EvpMdCtx` and `m_null.c`'s three callbacks are declared the way the authority declares them.
`ABI-PROTOTYPE` canonicalises both spellings to `ptr(opaque)` and the ABI does not distinguish them,
so this is not an evidence change — but a declaration that no longer matches the struct it belongs
to is a defect waiting for a reader, and there was no reason to leave one behind now that the
struct exists.

**`EVP_PKEY_CTX` is 7.4's, and the seam is named rather than faked.** `struct evp_md_ctx_st` carries
an `EVP_PKEY_CTX *pctx`, and `digest.c` touches it in exactly three places: a reset releases it,
`EVP_MD_CTX_set_pkey_ctx` releases the old one and stores the new one, and `EVP_MD_CTX_copy_ex`
duplicates it. So the digest stratum needs exactly two operations on a type that is one hundred and
forty-one obligations wide. Transcribing `evp_pkey_ctx_st` here would have pulled a stratum into a
subphase that cannot court any of it; ignoring the field would have made the accessors wrong.
`src/evp/pkey_ctx.rs` therefore declares the type opaquely and gives the two operations the
internal spellings the digest stratum calls, with its own module documentation saying why. Every
constructor for an `EVP_PKEY_CTX` is 7.4's and is a scaffold that **aborts**, so no caller of this
crate can hold a non-NULL one: the NULL arm is the whole of the reachable contract and is
transcribed exactly, and the non-NULL arm **aborts with a diagnostic** rather than returning
quietly, because a quiet return would leak the block it was asked to release or hand back a second
reference to an object it cannot copy, and both of those are wrong answers no court could see. When
7.4 lands, `EVP_PKEY_CTX_free` and `EVP_PKEY_CTX_dup` become one-line wrappers over these two
functions rather than a second implementation.

**Two blocks are omitted because they are unreachable, at a named site each.** The
`EVP_PKEY_CTX_IS_SIGNATURE_OP` redirects into `EVP_DigestSignUpdate`/`EVP_DigestVerifyUpdate` at
`digest.c:163` and `:395` are skipped — `ctx->pctx` is NULL until 7.4, and the authority's own
comment says the redirect exists only for a context initialised for signing. The `ENGINE_*` arms
are skipped for the reason `src/evp/cipher_ctx.rs` records for the cipher half: `tmpimpl` is
omitted and therefore NULL, `ctx->engine` is always NULL, and every `ENGINE_init`/`ENGINE_get_digest`
/`ENGINE_finish` call is guarded by a test on one of the two. An `impl` argument that is **not**
NULL is a caller holding an ENGINE, which no caller can obtain here, and it is refused at the
authority's own raise site (`DIGEST_311`, which is `!ENGINE_init(impl)`'s own line).

**Three NULL callback calls are faults, and they were measured rather than inferred.** This is the
finding of the subphase. `evp_md_init_internal` ends its legacy arm with `return
ctx->digest->init(ctx)`, `EVP_DigestFinal_ex`'s legacy arm calls `ctx->digest->final(ctx, md)`, and
the provider arm calls `ctx->digest->newctx(...)` — none of the three tests its pointer, and all
three are reachable through documented entry points:

  * `EVP_MD_meth_new` produces a method with `init`, `final` and `copy` all NULL and `ctx_size`
    zero, and `EVP_DigestInit_ex(ctx, that_method, NULL)` takes the legacy arm because the origin is
    `EVP_ORIG_METH`;
  * a provider that publishes only the standalone `OSSL_FUNC_DIGEST_DIGEST` is **accepted** by
    `evp_md_from_algorithm` — a structural count of zero is legal when the one-shot is present —
    and such a method has a NULL `newctx`, so `EVP_DigestInit_ex` on a fetched one-shot-only digest
    takes the provider arm and calls through NULL.

Measured, each in a process of its own against the pinned authority: a hand-built method with no
`init` prints `built=1 ctx=1` and dies with **exit 139**; the same with `init` set prints
`set_init=1 init=1 cmp_final_is_null=1` and dies at `EVP_DigestFinal_ex`; the one-shot-only provider
prints `add_builtin=1 load=1 fetch=1` and dies at the initialise. All three are recorded as
`D-MD-NULL-CALLBACK-1` in `docs/SECURITY_DIVERGENCE_POLICY.md` with the measurements, and the crate
answers 0 for each — raising nothing, because the authority raises nothing: it does not return.
`EVP_MD_do_all_provided` with a **NULL visitor** is the fourth, measured the same way (`add_builtin=1
load=1` then exit 139) and recorded as `D-MD-DOALL-NULL-1`; the crate refuses the walk, which is a
real narrowing rather than an equivalence and is recorded as one. `RT-FETCH` prints
`NOT_MEASURED_AUTHORITY_FAULTS` at each boundary, so a reader of the transcript sees the edge rather
than a gap.

**Two smaller decisions inside the transcription.** `ctx->flags` is `unsigned long` and every entry
point takes or answers an `int`, so the three flag operations are transcribed with the authority's
own conversions — the mask-and-truncate on `test_flags`, the `~flags` taken on the `int` and then
widened on `clear_flags` — rather than with a boolean, because they differ and a caller can see
that they do. And `EVP_MD_CTX_ctrl`'s three commands are where a caller-visible asymmetry lives: two of them
(`XOF_LEN`, `SSL3_MASTER_SECRET`) *set* a parameter and one (`MICALG`) *gets* one, so the same
entry point reads and writes depending on the command. The scalar it builds its descriptor from is
a *local* `size_t`, whose address the provider may rewrite, so the array is built from that local
and the answer is read back out of it; and the `<= 0` test at the bottom is what turns a provider's
`EVP_CTRL_RET_UNSUPPORTED` into a plain 0 rather than letting it escape as a negative success.
`size_t` whose address the provider may rewrite, so the array is built from that local and the
answer is read back out of it afterwards; the authority's `<= 0` test at the bottom is what turns a
provider's `EVP_CTRL_RET_UNSUPPORTED` into a plain 0 rather than letting it escape as a negative
success.

### Arithmetic

| | before | after |
|---|---|---|
| Phase 7 implemented / open | 152 / 798 | **186 / 764** |
| `implemented[libcrypto]` | 1287 | **1321** |
| recorded deferrals | 5 | 5 |
| RT-FETCH observations | 103 | **217** |
| prototype court: checked / mismatch / unreadable | 1240 / 0 / 0 | **1274 / 0 / 0** |
| unit tests | 334 | **348** |

`RT-FETCH`'s 114 new observations passed **with zero residuals on the first run**, which is worth
saying plainly rather than as a boast: the context half is the largest surface this stratum has
transcribed, and the activity vectors are the kind of observation that fails loudly when a branch is
taken the other way. What they show, in the authority's own transcript, is the whole call path —
`ctx.activity.after_init=1,0,0,1,0,0,0,0,1` (one `newctx`, one `init`, one context-parameter read),
`after_destructive_final=1,1,0,2,2,2,0,0,4` (the reset released the algorithm context and the
re-initialise built a new one), `after_copy=2,1,1,...` (a copy *duplicates*), `after_dup=2,1,2,...`
(and so does a dup), `after_reset=2,2,2,...` (a reset releases). A transcription that shared an
algorithm context instead of duplicating it, or that reused one instead of releasing it, cannot
produce those vectors.

SPDX-License-Identifier: Apache-2.0

---

## D157 — 7.3e-i: the first class with no legacy half, and a fault found by transcribing `EVP_MAC_CTX_dup`

**What landed.** The MAC half of 7.3e: `crypto/evp/mac_meth.c` and `crypto/evp/mac_lib.c`, the
`EVP_MAC` method object and the `EVP_MAC_CTX` it is run through. **28 exports**, and the class that
proves the stratum's machinery generalises past the two classes it was built for.

**`EVP_MAC` is the first class with no legacy half**, and that is not a documentation detail — three
consequences follow from it and each is a place a reader who had internalised `EVP_MD` would guess
wrong. There is no `EVP_MAC_meth_new`, so a method cannot be built by hand and `EVP_MAC_free` has no
`origin` test to make; a method whose callbacks are missing is **refused at fetch time** rather than
tolerated, because there is no legacy arm to fall back to; and `EVP_MAC_CTX_get_mac_size` has no
cached constant to fall back on — it asks the *context* every time, which is why a MAC's size can
depend on parameters set after the fetch. `EVP_MAC_get_params` answers **1** for a missing callback
where `EVP_MD_get_params` answers 0, and the authority's own comment says why: a parameter list
nothing recognised and a list with no handler are the same answer to a caller.

**The structural check is an arithmetic, not a list.** `fnmaccnt == 3 && fnctxcnt == 2`, where the 3
counts `update`, `final`, and **either** `init` **or** `init_skey` through one `mac_init_found` flag,
and the 2 counts `newctx` and `freectx` and **not** `dupctx`. Both asymmetries are load-bearing and
both are observable from outside: a provider publishing only the symmetric-key initialiser is
fetchable, and a method with no duplicator is fetchable and usable right up to the moment it is
duplicated. `RT-EVP-MAC` publishes five algorithms, one for each arm, and the two negative ones are
the reason the court exists rather than a single happy-path probe.

**A fault found by transcribing, not guessed at.** `EVP_MAC_CTX_dup` reaches
`src->meth->dupctx(src->algctx)` with no test — and because `dupctx` is the callback the structural
check does not count, a method without one is perfectly legal right up to that call. Measured in a
process of its own against the pinned authority: a provider publishing a MAC without `dupctx`, a
fetch, a context, a duplicate — `add_builtin=1 load=1 fetch=1 ctx_new=1` then **exit 139**. It is
recorded as `D-MAC-DUPCTX-NULL-1` and the crate answers the NULL the authority's *own next
statement* would have produced, so the boundary is one step wide and the reference the duplicate
took on the method is given back on the way out. Two other boundaries are printed by the court
rather than executed: `EVP_MAC_do_all_provided` with a NULL visitor (D-MD-DOALL-NULL-1, the same
class) and `EVP_MAC_init_SKEY`, which is 7.3f's and is a scaffold today.

**The court's most interesting observation is the `do_all` count.** Five algorithms are published
and one cannot be constructed, so a walk that enumerated the *published* arrays would count five and
the authority counts four — which is `evp_generic_do_all`'s construct-then-enumerate order, visible
from outside the library for the first time. The provider also counts its own callbacks as one
vector, so the transcript says which of the thirteen ran and how many times:
`after_new=1,0,0,0,0,0,0,0,0` (the constructor only), `after_update=1,0,0,1,2,0,0,0,0`,
`after_final=1,0,0,1,2,2,1,7,0` (one `set_ctx_params` and seven `get_ctx_params`, of which four are
the size question asked four times), `after_ctx_free=1,1,0,1,2,2,3,8,0`. A transcription that took
the method-level `get_params` where the authority takes the context-level `get_ctx_params`, or that
skipped the `xof` parameter before an XOF final, cannot produce those vectors — and the XOF one is
visible in the *bytes* as well, because the provider writes the flag it was handed into `out[4]`.

**`OSSL_MAC_PARAM_BLOCK_SIZE` is `"block-size"`.** The digest and cipher classes both spell the same
notion `"blocksize"`; this one has a hyphen. A reader who pattern-matched would build a descriptor no
provider recognises, and `EVP_MAC_CTX_get_block_size` would answer 0 for every MAC in existence
without a single error anywhere. It is named in the code where its one reader is, with that reason.

### Arithmetic

| | before | after |
|---|---|---|
| Phase 7 implemented / open | 186 / 764 | **214 / 736** |
| `implemented[libcrypto]` | 1321 | **1349** |
| courts | 58 | **59** |
| RT-EVP-MAC observations | — | **96** |
| prototype court: checked / mismatch / unreadable | 1274 / 0 / 0 | **1302 / 0 / 0** |
| unit tests | 348 | **356** |

SPDX-License-Identifier: Apache-2.0

---

## D158 — 7.3e closes: the `EVP_KDF` class, and a reference leak in the MAC class that its twin found

**What landed.** `crypto/evp/kdf_meth.c` and `crypto/evp/kdf_lib.c`, and with them **7.3e is
complete**: 26 exports, 24 implemented here and two handed forward. The subphase's own arithmetic is
now closed — `EVP_MAC` and `EVP_KDF`, four translation units, 55 rows of the plan, two courts.

**The two classes are twins and are written out separately, and this subphase is the argument for
that.** Four differences matter, and each is one a shared helper would have had to be told about:

  * **`EVP_KDF_CTX_dup` tests its duplicator and `EVP_MAC_CTX_dup` does not.** The KDF form is
    `src == NULL || src->algctx == NULL || src->meth->dupctx == NULL`; the MAC form reaches
    `src->meth->dupctx(...)` and faults — measured, D-MAC-DUPCTX-NULL-1. `RT-EVP-KDF` observes the
    two methods that differ in that one entry and gets a NULL from one and a context from the other;
    `RT-EVP-MAC` prints the boundary it cannot enter.
  * **the structural check is `1` and `2` against the MAC class's `3` and `2`**, with no fold:
    `fnkdfcnt` counts `derive` alone. `RT-EVP-KDF` publishes a KDF with no `derive` and one with no
    `freectx`, and both fetches must fail.
  * **a KDF has a `reset` and a MAC has none**, and the KDF's is a provider callback rather than a
    re-initialise: `EVP_KDF_CTX_reset` answers `void`, does not touch `algctx`, and a method without
    one is a silent success.
  * **`EVP_KDF_CTX_new` refuses a NULL method up front**, where `EVP_MAC_CTX_new` dereferences it.

**The finding: a reference leak in `EVP_MAC_CTX_new`, found by its KDF twin.** Both constructors are
the same `||` chain, and in both the authority's short-circuit is load-bearing:

```c
if ((ctx->algctx = kdf->newctx(...)) == NULL || !EVP_KDF_up_ref(kdf)) { ... release ... }
```

A NULL from the provider's `newctx` means `EVP_KDF_up_ref` is **never called**. Transcribing the two
operands as two statements evaluates both, so a provider that refuses its own context had a
reference taken on its method and never given back — a leak, silent, on a path no court could reach
because every court's provider succeeds. It was written that way in `EVP_MAC_CTX_new`, shipped in
`c2d496ab`, and stayed invisible for a whole commit; the KDF class's copy of the same function was
given a unit test asserting the reference count on the refusal path, the test failed on the KDF copy,
and the same defect was then found in the MAC copy by reading it. Both now take the reference only
when the constructor succeeded, both carry the unit test, and the comment at each site says why the
shape is two statements rather than one expression. **This is the second time in this stratum that a
defect in a class already sealed was found by writing its sibling**, and it is the reason the plan
does not factor the symmetric classes into one helper.

**`RT-EVP-KDF` lands with 68 observations and zero residuals on the first run.** The derived key is a
function of the length asked for, the key set on the context and a fold of the salt, so the
transcript shows that the implementation ran and which of its inputs changed: the two derivations
around the reset differ in the salt's fold and agree in the key, which is the observation that the
reset is the provider's own and the context is the same object. The nine-callback activity vector
says which of the thirteen ran and how many times. The `do_all` counts **two** where four algorithms
are published, because two cannot be constructed — the same construct-then-enumerate observation the
MAC court makes with a different arithmetic.

**One more thing the probe learned the hard way.** `EVP_KDF_*` is declared in `<openssl/kdf.h>` and
**not** in `<openssl/evp.h>`, so a probe that included only `evp.h` read `EVP_KDF_fetch`'s pointer
return as an `int`. `-Werror=implicit-function-declaration` turned that into a compile failure rather
than a silent truncation, which is exactly why the flag is in the court's compile line — and the note
is in the probe's own include block so the next probe does not have to rediscover it.

### Arithmetic

| | before | after |
|---|---|---|
| Phase 7 implemented / open | 214 / 736 | **238 / 712** |
| `implemented[libcrypto]` | 1349 | **1373** |
| courts | 59 | **60** |
| RT-EVP-KDF observations | — | **68** |
| prototype court: checked / mismatch / unreadable | 1302 / 0 / 0 | **1326 / 0 / 0** |
| unit tests | 356 | **365** |

SPDX-License-Identifier: Apache-2.0

---

## D159 — 7.3f's first half: `EVP_RAND`, the class whose constructor has three arguments and whose release is a chain

**What landed.** `crypto/evp/evp_rand.c`, whole — `src/evp/rand.rs`, **30 exports**, the third of the
provider-only classes and the first that does not follow the shape `EVP_MAC` and `EVP_KDF`
established. `RT-EVP-RAND` lands with **168 observations and zero residuals on the first run**.

**Three structural breaks, each of which a reader who had internalised the other two classes would
get wrong.**

  * **The constructor takes three arguments and the third is a dispatch table.**
    `OSSL_FUNC_rand_newctx_fn` is `void *(*)(void *provctx, void *parent, const OSSL_DISPATCH
    *parent_calls)`. The authority hands the child the parent's **algorithm context** and the parent
    method's **own `OSSL_DISPATCH` table**, so that a child DRBG calls *through* its parent rather
    than through a copy — which is the whole mechanism by which one provider's DRBG chains onto
    another's. `EvpRand` therefore keeps a `dispatch` field that no other class in this stratum has.
    The probe pins all three relations without printing an address: with no parent, both are NULL;
    with a parent, the second is the algorithm context *this probe's own provider allocated* (so the
    probe can tell it apart from the `EVP_RAND_CTX`), and the third is a table whose entry count and
    first id are read, and whose pointer the second child is compared against the first. "The child
    was handed the parent's `EVP_RAND_CTX`" is a wrong answer that only this observation
    distinguishes.
  * **A context is reference counted and its release is recursive.** `EVP_RAND_CTX_new` takes a
    reference on the parent *before* the provider's constructor is called; `EVP_RAND_CTX_free` on the
    last reference releases the algorithm context, then the method, then the parent — which may be
    the last reference to *its* parent. A transcription that freed one level would leak an entire
    tree of provider contexts. The court's observation is the provider's own `freectx` vector across
    a chain of calls: freeing two children of a live parent leaves the count unchanged, and the
    parent's own release is the next increment.
  * **Every operation is wrapped in the provider's lock, and the lock is optional.** `EVP_RAND_CTX_get_params`
    and its eleven siblings each take a lock, call a `_locked` helper, and release; a method with no
    `lock` answers 1 for every acquisition, so the pair is free. `EVP_RAND_enable_locking` is the one
    entry point that is *not* wrapped, because it is the call that enables the thing — and the court
    observes the same call producing `lock=0,unlock=0` on the plain method and a lock pair on the
    locked one.

**The two locking counters are independent conditions, and that is observable.** The structural
check is

```c
if (fnrandcnt != 3
    || fnctxcnt != 3
    || (fnenablelockcnt != 0 && fnenablelockcnt != 1)
    || (fnlockcnt != 0 && fnlockcnt != 2)
```

— two separate disjunctions, not one. So a method that publishes `enable_locking` and **no** `lock`
is fetchable, while one that publishes `lock` and no `unlock` is refused. A transcription that folded
the pair into a single counter would refuse the first; nothing else in the API would notice, because
the only entry point that consults `enable_locking` does not consult `lock`. `RT-EVP-RAND`
publishes both and asserts the asymmetry: `court-rand-enableonly` is *constructed* and its callback
runs, `court-rand-nolockpair` is refused.

**`fnctxcnt` counting `get_ctx_params` is the same requirement as the runtime one.** The fetch-time
check counts `newctx`, `freectx` and `get_ctx_params` as the three context functions, which looks
arbitrary until `evp_rand_generate_locked` is read: it **asks** for `OSSL_RAND_PARAM_MAX_REQUEST` and
refuses the whole generation when the answer is missing or zero, because the loop it drives is
chunked by it. So a method that cannot report its own parameters is a method whose `generate` cannot
run, and the class says so at fetch time. The court observes all four arms of that: the chunked
generation (twenty bytes over a `max_request` of seven is three callbacks of 7, 7, 6, and *where*
each landed is in the bytes and in the advanced buffer), `outlen == 0` (a success with no callback at
all, because the loop's condition is checked before the body), `max_request == 0`, and a
`get_ctx_params` that refuses.

**Two NULL contracts that differ, both measured.** `EVP_RAND_CTX_new(NULL, NULL)` raises
`EVP_R_INVALID_NULL_ALGORITHM`; `EVP_RAND_up_ref(NULL)` answers **1** without raising, because the
authority's static helper guards and the exported wrapper is one line over it; and
`EVP_RAND_CTX_free(NULL)` returns. One class refuses a NULL, the other is a no-op for it, and the
court pins both because a transcription that made them consistent would be wrong in one direction or
the other.

**The deferral the gate found, and why a deferral is the honest answer.**
`evp_rand_can_seed`, `evp_rand_get_seed` and `evp_rand_clear_seed` are internal, are declared in
`include/crypto/evp.h` — which is not installed in this profile — and their only caller in the whole
authority is `crypto/rand/rand_lib.c`, which is Phase 9's. This file transcribes `evp_rand.c` and
deliberately stops at the dispatch walk that fills the `get_seed` and `clear_seed` **fields**: the
fields are this file's, the three callers are the stratum that needs the DRBG plumbing. The
`prerequisite_gate` fired the moment `src/evp/rand.rs` became a module of that authority unit and
reported exactly those three names as unwired in an open stratum. The three rows added to
`forensics/prerequisites.json` are the recorded answer, and the mechanism is worth noting: the gate
found an omission **because registering a module is what makes a unit's identifiers owed**, which is
the boundary being visible to a tool rather than only to a reader. Stubbing them was the alternative,
and it was rejected for the reason this project always rejects it — a stub would have made the three
names look built, and the gate would have stopped asking.

**Deliberately not measured.** `EVP_RAND_do_all_provided` with a NULL visitor faults the authority
(`D-MD-DOALL-NULL-1`); the probe prints the boundary rather than entering it. `EVP_RAND_get0_name` and
its siblings on a NULL method dereference, so they are not called either.

### Arithmetic

| | before | after |
|---|---|---|
| Phase 7 implemented / open | 238 / 712 | **268 / 682** |
| `implemented[libcrypto]` | 1373 | **1403** |
| courts | 60 | **61** |
| RT-EVP-RAND observations | — | **168** |
| prototype court: checked / mismatch / unreadable | 1326 / 0 / 0 | **1356 / 0 / 0** |
| unit tests | 365 | **374** |
| prerequisite deferrals | 5 | **8** |

SPDX-License-Identifier: Apache-2.0

---

## D160 — 7.3f closes: `EVP_SKEYMGMT` and `EVP_SKEY`, and the prototype court refusing a signature its own transcription read wrong

**What landed.** `crypto/evp/skeymgmt_meth.c` and `crypto/evp/s_lib.c`, both whole — **24 exports** —
plus the four entry points that were handed forward from 7.3e for want of the object they take:
`EVP_MAC_init_SKEY`, `EVP_KDF_CTX_set_SKEY`, `EVP_KDF_derive_SKEY` and `EVP_CipherInit_SKEY`. With
them **7.3f is complete**: 7.3f's last row, `EVP_PKEY_derive_SKEY`, is 7.4's and is recorded as such
with its module named. `RT-EVP-SKEY` lands with **97 observations and zero residuals on the first
run**.

**The fourth class, and the first whose object is not a context.** `EVP_MD`, `EVP_CIPHER`, `EVP_MAC`
and `EVP_KDF` are four names for one shape: a method that has a *context*, and the state lives in the
context. `EVP_SKEY` has none. It is **made** by an operation — `import` or `generate` — rather than by
a constructor, so there is no `EVP_SKEY_new`, and the object **owns a reference to its method**, where
an `EVP_MD_CTX` owns one only for the life of the context. `EVP_SKEY_free` therefore releases the
provider's key data, then the method, then the lock the object allocated at import time, then the
block — and the court's `free` counter across two `up_ref`s and three `free`s is the observation that
the chain runs exactly once, at the end.

**Three things this class does that no sibling does.**

  * **The structural check has no counter.** `EVP_MD`'s constructor weighs five functions against
    four, `EVP_MAC`'s three against two, `EVP_KDF`'s one against two. This one is three plain NULL
    tests — `free`, `import`, `export` — and the *absence* of an arithmetic is observable: a method
    that lists `import` **twice** is fetchable, because there is nothing counting entries to notice,
    and the first entry wins. `RT-EVP-SKEY` publishes such a method and three with one of the three
    mandatory callbacks missing, and the four transcripts together are the shape of the check.
  * **The two reference counts disagree.** `EVP_SKEYMGMT_up_ref` reads the count, discards the
    result, and answers the constant **1** — `CRYPTO_UP_REF` returns 1 on every platform it is
    defined for, so there is nothing to report. `EVP_SKEY_up_ref` computes, and computes the thing
    `EVP_MAC_up_ref` does not: `CRYPTO_UP_REF` writes the **new** count, so the answer is exactly
    `new > 1` and a key whose count reached zero is not brought back to life. Both are pinned.
  * **`names_do_all` answers 0 for a NULL method** where every sibling answers 1. That boundary is in
    the crate's unit tests rather than the court, because every other observation this probe makes
    needs a live method and mixing the two would make one line's failure ambiguous. Saying which plane
    holds which observation is the point.

**`EVP_SKEY_to_provider` is four arms and the first is a pointer identity.** Same method name *and*
same provider is an `up_ref` of the object the caller passed; the same name from a **different**
provider is a full round trip — export to parameters, import into the destination — because the two
providers' key data are different objects and there is no common representation. `RT-EVP-SKEY` loads
two providers that publish the same first name for the key type and prints, for each arm, whether the
result is the same pointer and what its provider name is; the round trip's result reports the
*destination's* provider, and its key id says which provider's data it is.

**`EVP_SKEY_import` falls back by name, and the fallback is a second fetch.** A key type nobody
publishes is not an error: the method is asked for again under `OSSL_SKEY_TYPE_GENERIC`
(`"GENERIC-SECRET"`), and only a second failure raises `ERR_R_FETCH_FAILED`. The court observes the
fallback with a key type the provider does not publish and a `GENERIC-SECRET` it does, and the
resulting key reports the generic method's name.

**The finding: `ABI-PROTOTYPE` refused `EVP_CipherInit_SKEY`, and it was right.** The header declares

```c
int EVP_CipherInit_SKEY(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher, EVP_SKEY *skey,
    const unsigned char *iv, size_t iv_len, int enc, const OSSL_PARAM params[]);
```

and the authority's *internal* helper it forwards to is
`evp_cipher_init_skey_internal(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher, const EVP_SKEY *skey,
...)` — **the two disagree about constness**, and the exported signature is the header's. The
transcription was written from the internal helper and carried `*const` outward, which is a defect no
runtime court in this project could see: a probe compiled against the header cannot tell the
difference at the ABI level, and `cargo build` cannot either. The prototype court compared the
canonical declaration and named the parameter:

```text
TYPE-MISMATCH EVP_CipherInit_SKEY: authority int:4:s (ptr(opaque), ptr(const(opaque)), ptr(opaque),
  ptr(const(int:1:u)), int:8:u, int:4:s, ptr(const(opaque))) != crate ... ptr(const(opaque)) ...
```

This is the first defect this stratum has found in a function **before** its court ever ran, and it is
the argument for the plane rather than an anecdote about it: the reading that produced the wrong
signature was the reading of a *faithful* transcription of a different function.

**The other finding of the same run was a test defect, not an implementation defect.** The unit test
that drives `transfer_cb` — the callback `EVP_SKEY_to_provider` installs — first passed it a
`RawKeyDetails`, which is a two-field structure, where the callback writes a three-field
`TransferCbCtx`. The write was out of bounds and the debug-assertion layer aborted the test on a null
dereference. The fix is not a smaller cast: it is a provider `import` that *refuses*, so the test
drives the callback on the path where its constant answer of 1 is observable, which is the only arm
where that constant is not masked by a successful import. The test says so.

**One more boundary is now measured rather than assumed.** `EVP_KDF_derive_SKEY`'s raw fallback
derives into a buffer and then **clears** it before releasing it — `OPENSSL_clear_free`, not
`OPENSSL_free` — and a transcription that used the plain free would lose nothing observable to a
court and would leave the only copy of a derived secret in the heap. It is transcribed as written and
called out here because it is the class of thing this project keeps for a decision record rather than
for a test.

### Arithmetic

| | before | after |
|---|---|---|
| Phase 7 implemented / open | 268 / 682 | **296 / 654** |
| `implemented[libcrypto]` | 1403 | **1431** |
| courts | 61 | **62** |
| RT-EVP-SKEY observations | — | **97** |
| prototype court: checked / mismatches | 1356 / 0 | **1384 / 0** |
| unit tests | 374 | **383** |
| 7.3f's open rows | 24 | **0** |

SPDX-License-Identifier: Apache-2.0

---

## D161 — `OPENSSL_INIT_ADD_ALL_CIPHERS` is accepted, not refused; found by a court reading the error queue

**Decision.** Take `OPENSSL_INIT_ADD_ALL_CIPHERS` and `OPENSSL_INIT_ADD_ALL_DIGESTS` **off**
`INIT_UNSUPPORTED` in `src/runtime/init.rs`. `OPENSSL_init_crypto` now accepts them, raises nothing,
answers 1, and records them so the second call takes the fast path. Their action is
`add_all_legacy_methods(opts)`, which is one expression and does nothing until Phase 13 supplies
`crypto/evp/c_allc.c`'s and `c_alld.c`'s bodies.

**Why the earlier decision was wrong, and in which direction.** The two bits were refused on the
reasoning that "the authority's action for them is observable, so refusing is the honest choice
because they are not no-ops". That reasoning is sound about the *table* and was wrong about the
*return value*. The authority's code is

```c
if (opts & OPENSSL_INIT_ADD_ALL_CIPHERS) {
    if (!RUN_ONCE(&add_all_ciphers, ossl_init_add_all_ciphers))
        return 0;
}
```

and the once-raiser answers 1 and raises nothing. So the crate was reporting a *failure the
authority does not have* — and `OpenSSL_add_all_algorithms_noconf()` is, in `crypto.h`, literally
`OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS, NULL)`. Every
caller that checks that answer — which is what the spelling is for — failed against this crate and
succeeded against the authority. The table staying empty is a contents divergence and is recorded;
the call *failing* was a behaviour divergence that **no record named**, in either direction, because
the decision was recorded as a decision and never measured.

**How it was found.** By writing `EVP_CIPHER_do_all`, whose first statement is one of these calls,
and having `RT-EVP-NAMES` read `ERR_peek_error()` after it. The probe reported
`out_of_order:0 err=126615813` against the authority's `out_of_order:0 err=0` — a five-minute
measurement of a three-year-old assumption, and the only reason the difference was visible is that
the court compares *executions* rather than assertions. A unit test written from the same
understanding would have asserted the refusal and passed.

**What changes observably.** Three things, and they are all new capabilities rather than repairs:
`OPENSSL_add_all_algorithms_noconf()` answers 1; `EVP_CIPHER_do_all`/`EVP_MD_do_all` and their
sorted twins no longer leave an error on the queue after a successful walk; and the crate's own
`EVP_get_cipherbyname`/`EVP_get_digestbyname` — which have the same call as their first statement —
become writable at all, because their guard was what made them look unimplementable.

**The unit test that encoded the old decision is rewritten rather than deleted.** It was
`unsupported_options_fail_with_init_fail_and_do_not_get_recorded` and it asserted `0x4` was refused;
it now lists only the ENGINE and ASYNC bits, and a new test,
`the_legacy_adder_bits_are_accepted_and_raise_nothing`, asserts the opposite for the two that
moved — including that the queue is empty and that the option is recorded. A test that had been
deleted would have taken the argument with it.

SPDX-License-Identifier: Apache-2.0

---

## D162 — 7.3g closes: the two walkers, the two adders, the two lookups, and one hundred and sixty-four hand-offs with a primitive named for each

**What landed.** `crypto/evp/names.c`'s implementable half — `EVP_CIPHER_do_all`,
`EVP_CIPHER_do_all_sorted`, `EVP_MD_do_all`, `EVP_MD_do_all_sorted`, `EVP_add_cipher`,
`EVP_add_digest`, `EVP_get_cipherbyname`, `EVP_get_digestbyname` and their two internal `_ex`
halves — **eight exports**, and with them 7.3g is closed. `RT-EVP-NAMES` lands with **25
observations and zero residuals**.

**The rest of 7.3g is a hand-off, and the plan predicted it.** One hundred and sixty-four legacy
method statics — the `EVP_aes_*`, `EVP_des*`, `EVP_sha*` and their families — are Phase 13's, and
each row now names the primitive unit whose functions the wrapper's callbacks call:
`crypto/aes/` for `e_aes.c` and `e_xcbc_d.c`, `crypto/sha/` for `legacy_sha.c` (which is where
`EVP_shake128` lives, not under a `shake` prefix), `crypto/md5/` for `legacy_md5_sha1.c`, and so
on. The table in `forensics/tools/phase7_obligations.py` is per-family rather than one `EVP_`
catch-all, because a row that named one primitive unit for all of them would be a row nobody could
check.

**The judgement that changed while writing it, and it is worth recording because the reasoning was
wrong rather than incomplete.** The first reading handed `EVP_get_cipherbyname` and
`EVP_get_digestbyname` to Phase 13 as well, on the argument that *their whole answer is a lookup in
the table the wrappers fill*, so a court could observe the function and not its result. Reading the
bodies again says otherwise, and three things follow:

  * the legacy lookup is only the **first** of three steps. A miss falls through to the namemap; a
    name the namemap does not know is **fetched** — with `ERR_set_mark` around the fetch, so that a
    failed resolution leaves the error queue exactly as it found it — and the namemap is asked
    again. Every piece of that is this stratum's or an earlier one's;
  * a caller who has added a method with `EVP_add_cipher` gets it back **by name**, which is the
    whole point of the pair, and it needs no Phase-13 primitive;
  * what Phase 13 changes is *which names the first step finds*. That is a contents divergence,
    already recorded; refusing to write a function because one of its **inputs** is another
    stratum's contents would be the same mistake as refusing to write `EVP_add_cipher`.

`RT-EVP-NAMES` settled it by calling both lookups: for the probe's own entry, and for a name nobody
publishes — the second of which answers NULL with the error queue unchanged, which is the mark/pop
pair doing its job and would be the first thing lost by a transcription that "simplified" the fetch
away.

**The court's central design problem, and its answer.** Most of what these six functions return is
another stratum's contents: `EVP_CIPHER_do_all` calls
`OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS, NULL)`, which in the authority populates the
table with those one hundred and sixty-four statics. A probe that printed the visit count would be
printing **how much of Phase 13 exists** — six hundred on one side and three on the other — and
reporting it as a behavioural residual. So the probe observes the walk's *shape*, which is
contents-independent: alias rows report a NULL cipher and their target in `to` while real rows report
the method in `from` and a NULL `to`; the sorted walk is sorted; and the one contents-dependent fact
it may state is *the entry it added itself*, because that entry is the probe's. Three invariant
counts and two pointer relations replace a count that would have been a lie.

**One of those invariants caught the probe, not the crate.** The first version checked sortedness on
*both* walks and reported `out_of_order:1` on the authority for the unsorted one — which is a correct
observation of the wrong contract: `OBJ_NAME_do_all` is a hash-order walk and never promised an
order. The check is now gated on the sorted walk and the comment at the site says why. A court is a
program too.

**What is not here, each with its reason.** `evp_cleanup_int` is `names.c`'s and is owed to **7.4**
inside this stratum: its body calls `EVP_PBE_cleanup`, which is `crypto/evp/evp_pbe.c`'s, so half of
it cannot be written; it is recorded in `forensics/prerequisites.json` with `owner_phase: 7`, which
is why it appears in the blocking census rather than in a hand-off edge.
`EVP_add_alg_module` is `evp_cnf.c`'s and is 7.4's, because the callback it registers reads the
configuration through `X509V3_get_value_bool`, which is Phase 11's.

### Arithmetic

| | before | after |
|---|---|---|
| Phase 7 implemented / open / deferred | 296 / 654 / 0 | **304 / 482 / 164** |
| `implemented[libcrypto]` | 1431 | **1439** |
| courts | 62 | **63** |
| RT-EVP-NAMES observations | — | **25** |
| prototype court: checked / mismatch | 1384 / 0 | **1392 / 0** |
| unit tests | 383 | **389** |
| prerequisite deferrals | 8 | **9** |

SPDX-License-Identifier: Apache-2.0

---

## D163 — 7.4's dependency set was wrong: its legacy registry half is Phase 8's, and the gate could not have said so

**The finding.** 7.4's plan row says it depends on 7.3. Reading its calls says otherwise. Two
translation units hold a table of **Phase 8's** method objects and nothing else of consequence:

```text
crypto/evp/pmeth_lib.c   standard_methods[]  ->  ten ossl_<alg>_pkey_method functions
                                                 (crypto/rsa/rsa_pmeth.c, dh/dh_pmeth.c,
                                                  dsa/dsa_pmeth.c, ec/ec_pmeth.c, ec/ecx_meth.c)
crypto/asn1/ameth_lib.c  standard_methods[]  ->  twelve ossl_<alg>_asn1_meth objects
  (via crypto/asn1/standard_methods.h)           (crypto/rsa/rsa_ameth.c, dh/dh_ameth.c,
                                                  dsa/dsa_ameth.c, ec/ec_ameth.c, ec/ecx_meth.c)
```

Both tables *are* the algorithm strata's method objects. The subtree of 7.4 reachable only through
them — `evp_pkey_type.c`, `p_lib.c`'s `pkey_set_type` and `find_ameth`, `pmeth_lib.c`'s whole
`EVP_PKEY_meth_*`/`EVP_PKEY_asn1_*` registry, `p_legacy.c`, `ec_support.c`, `dh_support.c` — cannot
be transcribed before Phase 8; and `evp_cnf.c` cannot be transcribed before Phase 11, whose
`X509V3_get_value_bool` its module callback reads. The profile defines no `OPENSSL_NO_DEPRECATED_3_6`
(`Configure linux-x86_64 --prefix=… --openssldir=… --libdir=lib shared enable-legacy no-tests`), so
`EVP_PKEY_type` compiles its ameth branch rather than the local `base_id_conversion` table.

**Why no tool said so, and it is the mirror image of `a2d_ASN1_OBJECT`.** The prerequisite gate fires
on a name only when the crate has a module for the unit that *defines* it. `ossl_rsa_pkey_method` is
defined by `crypto/rsa/rsa_pmeth.c`, which has no module and will not have one until Phase 8, so
`owners` is empty and the gate `continue`s. A D49-class omission is a name whose **owner has a
module** and is not recorded; this is a name whose owner has **no** module, which the gate is
designed to skip — correctly, since a stratum cannot owe what it has no file for. The information is
still there, in `forensics/atlas/transcription-edges.json`'s `identifiers` per unit, and reading two
tables by hand is what found it. D114, D118, D122, D132 and D134 were found that way too.

**The measurement that makes it actionable rather than blocking.** I had assumed a unit was atomic
for the gate — that implementing one of its exports makes every identifier of it owed. It is not.
Implementing one export of `p_lib.c` makes the gate owe exactly **seven** names, and they are the
seven `include/crypto/evp.h` declares:

```text
evp_pkey_copy_downgraded   evp_pkey_export_to_provider   evp_pkey_free_legacy
evp_pkey_get0_DH_int       evp_pkey_get_legacy           evp_pkey_name2type
evp_pkey_type2name
```

File-local statics are not owed. Six of the seven are the legacy half and are Phase 8's; the seventh
is `keymgmt_lib.c`'s and lands here. So the provider half of `p_lib.c` lands with **six recorded rows
naming Phase 8**, and the gate's blocking census *says* what is outstanding rather than hiding it —
the disposition 7.3g used for one hundred and sixty-four legacy statics, applied at the granularity
of the names a header promises. The experiment is worth recording as an experiment: the first
version of it suppressed `gen_prerequisite_atlas.py`'s output, the atlas stayed stale, the gate
reported nothing, and the wrong conclusion was drawn from a silent failure — which is why the
generator's output is not suppressed in this project's own pipeline.

**The consequence for the order.** 7.4 splits, and the split is in `docs/PHASE-7-SUBPHASES.md`: 7.4a
(the `EVP_PKEY` object's provider attributes and lifetime, plus `keymgmt_lib.c` whole), 7.4b (the
five method-object families, minus `keymgmt_meth.c`'s `legacy_alg` fill), 7.4c (the `EVP_PKEY_CTX`
object and its accessors, `pmeth_check.c`, `pmeth_gn.c`, `m_sigver.c`, the PBE and PKCS#5 units), then
**7.4l handed to Phase 8 with the dependency named** (the two registries, `evp_pkey_type.c`,
`p_legacy.c`, `ec_support.c`, `dh_support.c`, `ameth_lib.c`, `i2d_evp.c` and the three `d2i_*`) and
**7.4n held for Phase 11** (`evp_cnf.c`). 7.4l is the largest hand-off in the programme and it is not
a deferral of convenience: it is the same judgement 7.3g made when it sent the legacy `EVP_aes_*`
statics to Phase 13 with `crypto/aes/` named.

**One thing this changes for every future stratum.** The plan's dependency column was read from the
authority's calls by hand, and this is the fourth time it has been wrong in a way no gate could see.
The two `standard_methods[]` tables are the *first* entries that a mechanical check could have
found, because the atlas already records every unit's identifier list: a scan for identifiers whose
defining unit has no module, whose *phase owner* is later than the referencing unit's, is a few lines
and would have printed both tables. It is not written here — this entry records the finding and the
mechanism that would generalise it, rather than claiming a tool that does not exist.

SPDX-License-Identifier: Apache-2.0

## D164 — 7.4a's first slice lands `keymgmt_meth.c` whole, and the seven `p_lib.c` names are disposed of one at a time

D163 found that a unit is not atomic for the prerequisite gate — implementing one export of
`crypto/evp/p_lib.c` owes exactly the seven functions `include/crypto/evp.h` declares for it — and
predicted the disposition: six rows naming Phase 8. Executing it turned up three things the
prediction did not cover, and all three are the kind of thing that is cheap now and expensive once
the surface is bigger.

**One: two of the seven were already landed, and one of them is complete.** `evp_pkey_type2name`'s
authority body is a scan of `standard_name2type` followed by `return OBJ_nid2sn(type)`, and
`OBJ_nid2sn` is Phase 4's and safe to call, so it is finished and never needed a row.
`evp_pkey_name2type` is a scan of the same table followed by two `EVP_PKEY_type` calls, and
`EVP_PKEY_type` is `evp_pkey_type.c`'s — which the plan's row **7.4l already hands to Phase 8**,
because the profile defines no `OPENSSL_NO_DEPRECATED_3_6` and the ameth branch is therefore the one
compiled. So that name is *partially* landed: the table half answers, and the fallback answers
`NID_undef` where the authority answers through an ameth object. A deferral row cannot record it —
the gate refuses a row whose symbol the crate defines, which is the `stale_deferral` rule and it is
right — so the gap is recorded where it can be acted on: `src/evp/pkey.rs`'s module doc, its section
"What is not here", and the site comment on the fallback. **It is not observable through any
implemented export yet**, because the export that would expose it — `EVP_PKEY_is_a`, whose last
statement is `pkey->type == evp_pkey_name2type(name)` — is still open in the ledger. When it lands,
`RT-EVP-PKEY` will measure the difference against the authority and it will have to be either fixed
by Phase 8 or entered in `docs/SECURITY_DIVERGENCE_POLICY.md`. Saying that here is the point: a
latent gap with a named trigger is a different object from a latent gap.

**Two: `evp_pkey_export_to_provider` is not one of Phase 8's six.** D163 called it `keymgmt_lib.c`'s
and landed-with-7.4a; reading its body says its first blocker is `EVP_PKEY_CTX_new_from_pkey`, which
is `pmeth_lib.c`'s and lands in **7.4c** inside this stratum, and its second is `pk->ameth->export_to`
and `pk->ameth->dirty_cnt`, which are Phase 8's. So it is recorded with `owner_phase` **7** — the
`evp_cleanup_int` precedent for an internal owed to a later subphase of its own stratum — rather than
with the other four, and the row says which of its two blockers comes first. That is four rows
naming Phase 8, one row naming 7.4c, and two names already landed: seven accounted for, where D163
predicted six rows and no explanation for the other two.

**Three: `has` is a macro, and a struct field is not a use of it.** `include/internal/safe_math.h`
defines a function-like macro `has(func)`, and the gate's reference lens reads a bare `has`
identifier as a reference to it — a name in the universe, built nowhere, with no record agreeing to
build it, so it is an `undefined_prerequisite`. The reference came from `EvpKeyMgmt`'s field for
`OSSL_FUNC_keymgmt_has_fn *has`, which the authority's own `struct evp_keymgmt_st` spells the same
way. The authority cannot resolve this ambiguity and the crate can, so the field is spelled `has_`
here, beside `match_` which is spelled that way for a keyword, and the field's doc says why. The
gate's doc already admits a lexical scan cannot tell a rename from a gap; this is that admission
paying for itself, and the repair is to remove the ambiguity rather than to suppress the finding.

**What is outstanding, recorded rather than lived with.** `EVP_PKEY_type` appears in the Phase-7
ledger's `open` list, because the global ownership atlas assigns it to this stratum — it is declared
in `evp.h` — while the plan's row 7.4l hands `evp_pkey_type.c` to Phase 8. Both are true and they
disagree: the atlas decides *ownership* by the declaring header, and the plan decides *when the work
can be done*. The ledger has a `deferred` list with an `owning_phase` and a reason per row, and 7.4l
belongs in it. It is not in it yet, and this entry records that rather than leaving the next reader
to notice — the mechanical step is a second hand-off table in `phase7_obligations.py` beside
`LEGACY_HANDOFFS`, whose rows are the eleven units 7.4l names, and it must land before 7.4a can be
called done, because a stratum with an open symbol it can never build is a stratum that can never
close.

SPDX-License-Identifier: Apache-2.0

## D165 — 7.4l's deferral is per-symbol, and neither the source nor the relocations alone can compute it

D164 recorded that row 7.4l's hand-off was not in the ledger yet, and named the mechanical step: a
second hand-off table in `phase7_obligations.py` whose rows are the eleven units 7.4l names. Building
that table turned out to require three facts that do not exist, and the attempt is worth recording in
full because the same three will be met by every later stratum.

**One: the census now exists, and it is 144.** `forensics/atlas/export-defining-units.json` is a new
generated artefact — every DSO export of each admitted library with the translation unit that defines
it, measured from the authority's own object files rather than inferred from prose, joined with the
owning stratum and declaring header from `symbol-ownership.json`. It is the fifth artefact of
`gen_prerequisite_atlas.py` and it exists because D163's finding needed it: a rule that assigns a
symbol to the stratum owning its *header* cannot see a call, and a rule that assigns a unit to a
stratum cannot express "this unit's exports are half this stratum's". 6,499 exports over 624 units,
**zero without a defining unit**, 34 defined by two units. Phase 7 owns exports defined in 83 units;
the eleven 7.4l names 144 of them:

```text
crypto/evp/pmeth_lib.c       98    crypto/asn1/ameth_lib.c      26
crypto/evp/p_legacy.c         6    crypto/asn1/i2d_evp.c         5
crypto/asn1/d2i_pr.c          4    crypto/asn1/d2i_param.c       2
crypto/evp/evp_pkey_type.c    1    crypto/asn1/d2i_pu.c          1
crypto/evp/evp_cnf.c          1    crypto/evp/ec_support.c       0
crypto/evp/dh_support.c       0
```

`evp_cnf.c`'s one is `EVP_add_alg_module`, already a deferral row. `ec_support.c` and
`dh_support.c` have one export and none between them that this stratum owns — they are named in the
plan because the *functions they implement* are needed, not because they export anything.

**Two: the unit is not the granularity, and D163's "the whole `EVP_PKEY_meth_*` registry" is
over-broad.** By hand, `EVP_PKEY_meth_get_sign` is
`if (psign_init) *psign_init = pmeth->sign_init; if (psign) *psign = pmeth->sign;` — two field reads
of a method object the caller supplies, with no reference to any table. So is `EVP_PKEY_meth_new`
(`CRYPTO_zalloc` and two assignments), and so is every `EVP_PKEY_meth_get_*`/`set_*` accessor and
most of `ameth_lib.c`. What is genuinely blocked is the handful of functions that reach the
`standard_methods[]` tables, and the tables are what make unit-level deferral wrong in the *dangerous*
direction: it would hand ~134 exports that this stratum can and must implement to Phase 8, and the
stratum would then be unable to close for a reason that is not real.

**Three: a bag-of-identifiers scan over the C bodies cannot replace the judgement, and 100% of its
answer is false.** The obvious mechanical rule — a body is blocked if it mentions an identifier whose
defining unit has no crate module — flags **98 of 98** `pmeth_lib.c` exports, `EVP_PKEY_meth_get_sign`
among them, because short field and parameter names (`sign`, `copy`, `free`, `init`, `check`) collide
with authority symbol names. Without a compiler's scoping, the source is a bag of words, and the tool
this project builds on is a *lexical* scan that its own doc already says cannot tell a rename from a
gap. Adding a scanner would have produced a confident, complete, wrong census.

**The measurement that does work, and the three layers it needs.** Undefined symbols are a property of
the *object*, not of the source: `crypto/evp/libcrypto-lib-pmeth_lib.o` needs 84 names, 37 of which
live in units the crate has not transcribed, and ten of those 37 are exactly the
`ossl_{rsa,rsa_pss,dh,dhx,dsa,ec,ecx25519,ecx448,ed25519,ed448}_pkey_method` objects from
`crypto/rsa/rsa_pmeth.c`, `crypto/dh/dh_pmeth.c`, `crypto/dsa/dsa_pmeth.c`, `crypto/ec/ec_pmeth.c` and
`crypto/ec/ecx_meth.c`. `elf_symbols.elf_undefined_symbols` was added for this and is the complement
of the function beside it. The other 27 are this stratum's own units in a later subphase
(`asymcipher.c`, `kem.c`, `exchange.c`, `signature.c` are 7.4b's; `ctrl_params_translate.c` is 7.4's),
which is the same census the plan already carries one level up.

But the object is not the granularity either, and the reason is three layers deep — all three measured
on that one object:

* **Relocations in `.text` give per-function references, and they are right.** Pairing each `SHT_RELA`
  entry with the defined function whose `[st_value, st_value+st_size)` contains its `r_offset` answers
  `EVP_PKEY_meth_get_sign -> []`, `EVP_PKEY_meth_new -> {CRYPTO_zalloc}`, which is exactly the hand
  reading. OpenSSL's build does **not** use `-ffunction-sections` — the object has one `.text` — so
  this pairing is what supplies the granularity the section table does not.
* **The table's own references are in a data section, not in the function.** `EVP_PKEY_meth_find`'s
  relocations name `OPENSSL_sk_find`, `OPENSSL_sk_value` and one *unnamed* symbol — the section symbol
  for the section holding `standard_methods`, with the offset in the addend. The ten
  `ossl_*_pkey_method` names appear in *that* section's relocations. So the rule needs recursion
  through data objects, and identifying a static object from a relocation means resolving
  section-plus-addend rather than a name — the same "one layer outward" shape as the whole of D163.
* **`OSSL_NELEM(standard_methods)` is a compile-time constant and leaves no relocation at all.**
  `EVP_PKEY_meth_get_count`'s only undefined symbol is `OPENSSL_sk_num`, and it is nonetheless blocked:
  its answer is `sizeof(standard_methods)/sizeof(standard_methods[0])`, which is ten today and is
  *whatever the algorithm strata compile in*. A relocation-only rule reports it as free. A rule that
  reads the source for the table's name reports it as blocked for the right reason by accident.

So the durable rule is: build the dependency graph the *linker* would build — text relocations, data
relocations, and a macro expansion for the constants — and then a symbol is blocked exactly when its
node reaches a node the crate does not define. That is a real tool with three passes, not the few
lines D163 estimated, and writing it is the next step rather than this entry's conclusion. What this
entry concludes is negative and worth as much: **no deferral row was added for these 144**, because the
two rules available today give opposite answers on evidence I can check, and 7.4l as written would have
deferred work that belongs here. The plan's row 7.4l is corrected to say so, and the artefact that
makes the rule writable is landed.

## D166 — 7.4c-i's prerequisite movement is recorded once per compared ref, and the guard needed a row for the push baseline

The 7.4c-i commit (`e03d81e5`) was red on CI, and on the regression guard alone:

```text
REGRESSION: prerequisites[blocking_dependencies]: 14 -> 18 (+4)
```

The movement itself was already recorded. `forensics/ownership-transitions.json` carried two
rows for it, `8 -> 18` and `15 -> 18`, and `regression_guard.py`'s `prerequisite_transition_for`
matched the second of them for the comparison the *branch* makes locally. What failed was a third
comparison.

**Why three rows for one movement.** `prerequisite_transition_for` matches `before` and `after`
**exactly** -- a row blesses one described change and nothing else -- while the project compares
against more than one authority. `.github/workflows/ci.yml`'s two guarded jobs each resolve the
trusted ref as:

* `git merge-base HEAD FETCH_HEAD`, when `GITHUB_BASE_REF` is set (a pull request) -- the merge
  base with `main`;
* `github.event.before` otherwise (a push) -- the tip of the branch **before** the push;
* and locally, `--baseline-ref origin/main`, a third value again.

Those baselines sit at different points in the history of this one metric, so one movement
appears as `8 -> 18`, `14 -> 18` and `15 -> 18` depending on which is consulted. `14` is the
commit before `e03d81e5` on `phase7-evp` (`ee87f232`), which is exactly what a push compares
against, and it had no row. The commit therefore failed a comparison whose change had already
been approved, from a baseline the file had not been told about.

**What actually moved.** Four authority-internal names became visible to the prerequisite gate
when `crypto/evp/pmeth_lib.c` got a module. None of them is new work:

| name | defining unit | owed to |
|---|---|---|
| `evp_pkey_ctx_get_params_strict` | `crypto/evp/pmeth_lib.c` | 7.4c-ii, inside this stratum |
| `evp_pkey_ctx_set_params_strict` | `crypto/evp/pmeth_lib.c` | 7.4c-ii, inside this stratum |
| `evp_pkey_ctx_use_cached_data` | `crypto/evp/pmeth_lib.c` | 7.4c-ii, inside this stratum |
| `evp_app_cleanup_int` | `crypto/evp/pmeth_lib.c` | Phase 8 (D163, D165) |

All four are rows in `forensics/prerequisites.json` naming the stratum that will build them. The
count rose because the names became *visible* -- the class D132 (11 -> 12), D134 (12 -> 15) and
D141 already recorded -- and each row now states the arithmetic its own baseline implies.

**The record defect this exposed.** The two rows written before this one said "six names" and
"the movement is three" while naming baselines of `8` and `15`, neither of which is a movement of
three. `reason` is prose the guard never reads, so nothing failed -- but a number typed by hand
into a record, contradicting the arithmetic of the row it sits in, is the class this project's
generated artefacts exist to prevent. Both rows' prose is corrected, together with the honest
general statement the three rows now share: a baseline further back already counts fewer of the
names, so one visibility event is recorded once per compared ref rather than once.

**What did not change:** the metric, the ledger, and every `after` value. `after` is `18` on all
three rows because that is what the working tree measures.

## D167 — `ossl_assert` under `NDEBUG` is a live refusal, and six doc comments said the released authority proceeds

`src/evp/pkey_ctx.rs` cited a divergence register entry that did not exist,
`D-PKEYCTX-LEGACY-ALG-1`. Writing the entry required stating what the authority does, and stating
what the authority does falsified the premise the citation rested on. The entry is **withdrawn**
and the premise is corrected here, because the same premise appears at six sites.

**The macro.** `include/internal/common.h`:

```c
#ifdef NDEBUG
#define ossl_assert(x) ossl_likely((x) != 0)
#else
#define ossl_assert(x) ossl_assert_int((x) != 0, "Assertion failed: " #x, __FILE__, __LINE__)
#endif
```

Under `NDEBUG`, `ossl_likely((x) != 0)` is the identity on a boolean, so `ossl_assert(C)`
evaluates to `C`. The consequence that matters is that **`if (!ossl_assert(C))` is `if (!C)` -- a
guard that fires in every build.** What `NDEBUG` removes is the *abort*: `ossl_assert_int` calls
`OPENSSL_die` on a false expression and the released macro does not. It does not remove the
refusal. The crate states this correctly in `src/provider/init.rs` ("`ossl_assert` under NDEBUG is
an `if`"), in `src/property/store.rs`, in `src/evp/fetch.rs` and elsewhere.

**What six sites said instead.** Each asserted that in the released authority the guard does not
fire, and each used that to describe a deliberate divergence:

| site | the claim | what the authority does |
|---|---|---|
| `pkey.rs` `EVP_PKEY_set_bn_param` | an oversized `BIGNUM` "writes past the buffer" | returns 0 |
| `pkey.rs` `pkey_set_type` | a check "the authority refuses in a debug build and proceeds from in a released one" | `ERR_raise(ERR_LIB_EVP, ERR_R_INTERNAL_ERROR); return 0` |
| `pkey.rs` `evp_pkey_cmp_any` | the released build "does take the -2" | takes the -2 -- **this one is right** |
| `pkey_ctx.rs` `int_ctx_new` | a disagreement is "**accepted**" | raises `ERR_R_INTERNAL_ERROR`, frees the keymgmt, returns NULL |
| `pkey_ctx.rs` `EVP_PKEY_CTX_dup` | with `exchange` NULL the duplicator "cannot be reached" | `ossl_assert` false, `goto err` |
| `keymgmt_lib.rs` `evp_keymgmt_util_export_to_provider` | "the round trip proceeds" | returns NULL |

**Measured, not read.** Two of the six are reachable in the authority binary, and both were
disassembled rather than argued about.

`EVP_PKEY_set_bn_param` compares the bit count and branches to the return-0 path:

```text
228e79:	cmp    $0x4000,%eax        ; BN_num_bits(bn) vs 16384 = 2048 bytes
228e7e:	jg     228f2b
...
228f2b:	add    $0x880,%rsp
228f32:	xor    %eax,%eax
228f34:	ret
```

`int_ctx_new` raises the error the crate's site names, at the line that site names:

```text
22bcb5:	cmp    %r12d,%eax          ; tmp_id vs id
22bcb8:	jne    22c07d
...
22c07d:	call   ERR_new
22c089:	mov    $0x11c,%esi        ; 284 -- pmeth_lib.c's ERR_raise line
22c09c:	mov    $0xc0103,%esi      ; 0x6 = ERR_LIB_EVP, ERR_R_INTERNAL_ERROR
22c0a8:	call   ERR_set_error
22c0b2:	call   EVP_KEYMGMT_free
22c0b7:	jmp    22bfa0             ; the NULL-return epilogue
```

So the authority refuses when `tmp_id != id`, with `ERR_R_INTERNAL_ERROR`, after freeing the
method -- exactly what the crate does at `err_sites::PMETH_LIB_284`. There is no divergence at
that site, which is why `D-PKEYCTX-LEGACY-ALG-1` is withdrawn rather than written.

**The crate's code was right at all six sites.** Every one refuses where the authority refuses.
What was wrong was the *record*: each comment placed the crate further from the authority than it
is, and did so in the direction that makes not reproducing a fault look like a decision.
`D-GF2M-1` does record a real divergence of that shape, so the shape is not itself the error --
but a claim of divergence is a claim, and it has to survive the same measurement as any other.
Here one `objdump` was enough. The comments now state what the authority does.

**One reachability left as a documented simplification.** `pkey_set_type`'s guard is
`if (!ossl_assert(type == EVP_PKEY_NONE || keymgmt == NULL) || !ossl_assert(e == NULL ||
keymgmt == NULL))`. The crate's signature has no `ENGINE` and every one of its callers passes
`EVP_PKEY_NONE`, so both clauses are unsatisifiable here and the crate does not transcribe the
guard. The branch the crate *does* take on a NULL `keymgmt` is the authority's later `check`
(`ameth == NULL && keymgmt == NULL`), which raises `EVP_R_UNSUPPORTED_ALGORITHM` -- and since
this crate's `ameth` is always NULL, that pair collapses to `keymgmt == NULL` exactly. The
comment at that site said it was the assertion guard, which was both wrong and contradicted by
the error the site raises. It now says what it is.

**What this does not change:** no behaviour, no courtroom, no obligation. `D-GF2M-1`'s divergence
is unaffected -- it is about blinding, not about `ossl_assert`.

## D168 — 7.4b-iii's first unit: `asymcipher.c`'s operation half, and `evp_pkey_ctx_is_legacy` is a header macro

7.4b is the five method-object families *with their `EVP_PKEY_*` operations*, and the plan's row
already said so; the crate's `src/evp/asymcipher.rs` module doc disagreed, saying its operation half
"is `EVP_PKEY_CTX` work and lands with 7.4c's context". Both are now true at once and that is the
right shape: the operations *belong to* 7.4b and could not be *written* before 7.4c-i landed the
`EVP_PKEY_CTX` object they read. The doc now says that instead of the weaker thing.

**One macro decides whether a branch is dead, and it is not what its name says.**

```c
/* include/crypto/evp.h:35 */
#define evp_pkey_ctx_is_legacy(ctx) \
    ((ctx)->keymgmt == NULL)
```

`pkey == NULL`, `pmeth == NULL`, `engine != NULL` — none of those is the test. It is `keymgmt == NULL`,
and in this crate that is a *reachable* state: `EVP_PKEY_CTX_new_id`-style construction and a context
whose key has not been assigned both produce it. So the authority's

```c
if (evp_pkey_ctx_is_legacy(ctx))
    goto legacy;
```

is live here, and the label it jumps to is **not** dead code. A transcription that read the macro by
its name would have concluded the opposite, dropped the label, and let `EVP_PKEY_encrypt_init` fall
through to the provider path with `ctx->op.ciph.cipher` never set — a NULL method dereferenced at the
first operation. The name is the hazard, not the branch.

**The `legacy:` label is a refusal, and the reason is structural rather than chosen.** Its body tests
`ctx->pmeth == NULL || ctx->pmeth->encrypt == NULL`, and `pmeth` is `EVP_PKEY_METHOD`'s, which is
Phase 8's (D163, D165). So the condition is satisfied on all three ways in — the macro above, the
second fetch returning NULL, and the post-loop `provkey == NULL` — and the arm it guards is the one
that hands the operation to a legacy method, which this crate cannot represent. Three of the arrivals
have already dropped `cipher` and the fourth never took one, which is why the label frees no method
here; the authority does not free one there either.

**The two-iteration fetch is not a retry.** The first iteration asks `EVP_ASYM_CIPHER_fetch` by
*property query*; the second asks `evp_asym_cipher_fetch_from_prov` for the same name at the
**provider that owns the key**, which is the only way to reach an algorithm a property query would not
select. The key is then exported to whichever provider answered, and `tmp_keymgmt` is passed to
`evp_pkey_export_to_provider` **by address** because that call may replace it — which is also why the
copy taken before the call is what gets freed when the callee NULLs it. Neither half of that survives
being "simplified".

**`out == NULL` is not a query mode.** The authority passes the caller's length, or **0** when there is
no output buffer — it does not skip the operation and does not pass a NULL length. A provider that
sizes its answer from `*outlen` therefore sees a zero, and one that ignores it sees a NULL buffer. The
distinction is the provider's to make, so the crate makes neither choice.

**The mark discipline is three calls and they are contract.** `EVP_PKEY_encrypt` sets a mark, runs the
provider's callback, and raises `EVP_R_PROVIDER_ASYM_CIPHER_FAILURE` **only** when the callback failed
*silently* — `ret <= 0 && ERR_count_to_mark() == 0`. A provider that raised its own error keeps it, and
the mark is cleared either way. The raised message is `"%s <clause>:%s"` over the method's type name
and its description, which is what makes the failing clause identifiable from the queue alone.

**What landed:** `evp_pkey_asym_cipher_init` and its six exports — `EVP_PKEY_encrypt_init`,
`_encrypt_init_ex`, `EVP_PKEY_encrypt`, `EVP_PKEY_decrypt_init`, `_decrypt_init_ex`,
`EVP_PKEY_decrypt`. `implemented[libcrypto]` moves 1543 -> 1549, and the six names leave the shell's
scaffold list. `evp_asym_cipher_fetch_from_prov`'s `#[allow(dead_code)]` is retired: its first live
caller has arrived, which is what the comment on it said to wait for.

**Still open in 7.4b-iii:** `kem.c`'s six, `exchange.c`'s six, and `signature.c`'s eighteen — the last
of which is where `EVP_PKEY_CTX_set_signature` and the four `*_message_*` pairs live.

## D169 — `pmeth_check.c` lands early, because 7.4b-iii reaches into it

7.4b-iii's remaining unit is `exchange.c`, and `EVP_PKEY_derive_set_peer`'s `validate_peer` arm is

```c
check_ctx = EVP_PKEY_CTX_new_from_pkey(ctx->libctx, peer, ctx->propquery);
check = EVP_PKEY_public_check(check_ctx);
```

`EVP_PKEY_public_check` and its six siblings are `crypto/evp/pmeth_check.c`'s, and the plan puts that
unit in **7.4c-ii**. So the exchange family cannot be completed in the plan's order without one of the
later subphase's units. This is a **plan edge, not a reordering**: the owning subphase is unchanged,
its row is not moved, and 7.4c-ii will find the unit already landed. The module doc says so at the
top, so the edge is visible from the code rather than only from this entry.

**What the unit is.** One provider probe and six wrappers that differ only in a selection and a
checktype:

```text
try_provided_check(ctx, selection, checktype)
  1. ctx is legacy (keymgmt == NULL)   -> -1   "ask someone else"
  2. the key cannot be exported        -> 0    with EVP_R_INITIALIZATION_ERROR
  3. evp_keymgmt_validate(keymgmt, keydata, selection, checktype)
```

The `-1` is the only one of the three that is not an answer, and the distinction is load-bearing: a
transcription that returned **0** for a legacy context would turn "not mine to answer" into "the key
is invalid", and `EVP_PKEY_public_check` would report a valid provider key as bad. `-1` is produced
before anything is raised, so a caller that falls through leaves the error queue clean.

**`EVP_PKEY_check` is not a seventh behaviour.** It is `EVP_PKEY_pairwise_check` under another name —
no key test, no selection, no error of its own — and it is written as the call rather than as a copy
of the body so the two cannot drift.

**`EVP_PKEY_private_check` is the one wrapper with no legacy half at all.** After `try_provided_check`
answers `-1` the authority refuses without consulting `ameth`, because no legacy key type implements a
private-key check. So that refusal is the authority's own answer and not this crate's gap, and it is
transcribed as the authority writes it rather than folded into the other five.

**The `pkey->type == EVP_PKEY_NONE` test is written even though it is false for every provider key.**
A provider key is typed `EVP_PKEY_KEYMGMT`, so `try_provided_check` answers with a validation result or
a 0 and the test is never reached; a context that *would* reach it has `keymgmt == NULL`, which is the
case that returned `-1`, and a legacy context carries a `pmeth` this crate cannot represent. Reading
the test as dead because "there are no legacy keys here" would be D168's mistake seen from the other
side — dropping a live branch because its name suggested it could not fire. So the test stays, and the
legacy arm that follows it is transcribed as a refusal at the recorded `not_supported` site with the
reason it cannot be taken here.

**Cost:** seven exports, and one shared helper hoisted while landing them: `evp_pkey_ctx_is_legacy` is
the header macro `keymgmt == NULL` (D168), and it now lives on `EvpPkeyCtx` as `is_legacy()` rather
than as a private function in `asymcipher.rs`, because `pmeth_check.c` and `exchange.c` both need it
and neither is the cipher's.

## D170 — `exchange.c`: two wrong callback types in landed code, and the evidence plane that cannot see them

7.4b-iii's last unit is `exchange.c`'s operation half. Writing `EVP_PKEY_derive` and
`EVP_PKEY_derive_SKEY` required *reading* the two method-object fields they call, and both were
wrong — in code that has been on `phase7-evp` since 7.4b-ii and through four CI runs.

**The two defects, both against `include/openssl/core_dispatch.h`:**

```c
OSSL_CORE_MAKE_FUNC(int, keyexch_derive,
    (void *ctx, unsigned char *secret, size_t *secretlen, size_t outlen))
OSSL_CORE_MAKE_FUNC(void *, keyexch_derive_skey,
    (void *ctx, const char *key_type, void *provctx,
     OSSL_FUNC_skeymgmt_import_fn *import, size_t keylen, const OSSL_PARAM params[]))
```

* `KeyexchDeriveFn` declared **three** parameters. `keyexch_derive` has four, and
  `EVP_PKEY_derive` forwards `key != NULL ? *pkeylen : 0` into the fourth. A provider that sizes its
  output from `outlen` therefore read whatever happened to be in that register.
* `KeyexchDeriveSkeyFn` declared `-> c_int`. It returns `void *` — the key data the destination
  method builds, which `EVP_PKEY_derive_SKEY` stores into the new `EVP_SKEY`. That is a pointer
  truncated to 32 bits.

The second was found by comparison: the sibling class had it right. `KdfDeriveSkeyFn` in
`src/evp/kdf.rs` returns `*mut c_void`, and `OSSL_FUNC_kdf_derive_skey` is declared identically to
`OSSL_FUNC_keyexch_derive_skey` in the same header, a few dozen lines apart.

**Why nothing caught them.** These are *internal* function-pointer fields of `EvpKeyExch`, not
exports. `ABI-PROTOTYPE` verifies the shape of the crate's **exported** functions against the Clang
prototype atlas, so a wrong arity two levels down is outside its reach. And no runtime court has yet
called `EVP_PKEY_derive` against a provider that publishes `keyexch_derive` — the court that will is
`RT-EVP-PKEY`, which does not exist yet. So the defect was invisible to every evidence plane the
project has: the prototype court, all sixty-four courts, the prerequisite gate and the ownership
audit. It was found by reading the header while transcribing the caller, which is exactly the kind of
discovery that stops scaling once the surface is five thousand symbols.

**The gap this names, and the mechanism that would close it.** `include/openssl/core_dispatch.h` is a
machine-readable table: every `OSSL_CORE_MAKE_FUNC(ret, name, (args))` line states a return type, an
arity and a parameter list, and every dispatch entry the crate stores is a `*Fn` type in
`src/provider/dispatch/` or beside a method object. So the check is generable and cheap:

```text
for every OSSL_CORE_MAKE_FUNC in the authority's header:
    find the crate type with that name
    assert  arity, parameter types (by pointer depth and constness), and return type
            match, after the crate's documented rewrites
```

That is the internal-facing sibling of `ABI-PROTOTYPE`, it needs no compiled provider and no court,
and it would have failed on both of the types above on the day 7.4b-ii landed. It is **not written
here**: this entry names it as the next evidence plane rather than smuggling a tool into a
transcription commit. What is written here is the correction and the record.

**Two more things this unit is, both the authority's own shape and both reproduced:**

* **`evp_pkey_derive_init` builds a key when `ctx->pkey` is NULL** rather than refusing. A blank
  `EVP_PKEY_new`, typed by the context's own method, with `evp_keymgmt_newdata` key data allocated
  and empty — because the legacy KDFs select a key type with no key. That is what lets
  `EVP_PKEY_derive` be reached from a context built out of a KDF name, and it is the only place in
  the five operation families where a missing key is a construction rather than an error.
* **the `legacy:` label leaks `tmp_keymgmt`.** `exchange.c`'s label frees it *after* the `pmeth`
  test, and the refusal returns before that — so the reference is dropped on the refusal path. The
  cipher's label frees it *before* the test, so the two files differ. The crate reproduces the leak
  because nothing observable distinguishes the two, and a silent improvement is still a silent
  change; the site comment says so.

## D171 — `signature.c`'s operation half is blocked on `ctrl_params_translate.c`, and three accessors land instead

7.4b-iii's last unit is `signature.c`'s operation half — nineteen exports. Its init function ends at a
shared `end:` label whose last statement is

```c
/* crypto/evp/signature.c:889 */
end:
#ifndef FIPS_MODULE
    if (ret > 0)
        ret = evp_pkey_ctx_use_cached_data(ctx);
#endif
```

`evp_pkey_ctx_use_cached_data` is already a deferral row owed to 7.4c-ii (it is one of the four rows
7.4c-i created). It acts only when `ctx->cached_parameters.dist_id_set`, and when it acts it calls
`evp_pkey_ctx_ctrl_str_int` or `evp_pkey_ctx_ctrl_int`.
**Those two route a *provider* context — the only kind this crate can build — to
`evp_pkey_ctx_ctrl_str_to_param` and `evp_pkey_ctx_ctrl_to_param`, which are
`crypto/evp/ctrl_params_translate.c`'s**, and that file is **2,959 lines**. It is the plan's own 7.4c
row, not a prerequisite anyone can land in passing.

So the plan's order has 7.4b-iii depending on 7.4c. That is not an error in the plan: row 7.4b says
"the five method-object families … with their `EVP_PKEY_*` operations" and row 7.4c names
`m_sigver.c`, `pmeth_check.c`, `pmeth_gn.c` and the `p5_*`/`pbe_*` units — the translation is a
*shared internal*, and by the rule D141 already applied, its owner is the earliest stratum that calls
it. 7.4b calls it; 7.4c owns it.

**What landed instead, and why it is not a substitute.** Three exports in the same family have no
legacy arm and no ctrl dependency at all:

* `EVP_PKEY_CTX_gettable_params` and `EVP_PKEY_CTX_settable_params` — five blocks over the five
  method classes, and **no state test whatsoever**: a legacy context and an uninitialised one both
  get NULL rather than an error, because the only thing they consult is which operation's algorithm
  context is present. Each block passes `ossl_provider_ctx` of **the method's** provider, not the
  libctx, because the descriptor table is a property of the method and not of one context;
* `EVP_PKEY_CTX_is_a` — whose legacy arm is `ctx->pmeth->pkey_id == evp_pkey_name2type(keytype)`,
  reached only through `evp_pkey_ctx_is_legacy` (D168) and therefore only by a context whose
  `keymgmt` is NULL, which the legacy constructors never produce without a `pmeth`. The arm is
  unreachable here, and the provided arm is the whole function.

These three are exactly as complete as the authority's. `EVP_PKEY_CTX_set_params`,
`EVP_PKEY_CTX_get_params` and the `_strict` pair are **not** landed: their `EVP_PKEY_STATE_LEGACY`
arm *is* the params-to-ctrl translation, so transcribing them now would mean writing an answer for a
branch whose body is a file this crate does not have — a guess dressed as a transcription.

**Two small things copied rather than normalised.** The authority tries the five families in a
different order in the two accessors — key generation before KEM in `gettable_params`, after it in
`settable_params` — and nothing can observe the difference, because a context carries one operation
at a time. That is the reason to copy the order rather than sort it: a reader who "tidied" the two
would be editing the authority. And `EVP_PKEY_CTX_is_a` is the one accessor in `pmeth_lib.c` that
dereferences `ctx` **without a NULL test**, in both arms — so the crate does not invent an answer for
a NULL context, and the site says so.

**One verification done while here, in D170's class.** All six `*_gettable_ctx_params`,
`*_settable_ctx_params` and keymgmt-generator callback types were checked against their
`OSSL_CORE_MAKE_FUNC` lines: arity, parameter types and return type all agree. The two exchange
defects D170 records are the exception in this family, not the rule — which is worth stating, because
the useful conclusion from D170 is that the type plane needs a generator, not that every type in it
is suspect.

**What this means for the plan, stated plainly:** `signature.c`'s operation half (and therefore the
completion of 7.4b) is gated on `ctrl_params_translate.c`. The next stretch of work in plan order is
7.4c-ii's ctrl and params core, and finishing 7.4b-iii comes immediately after it.

## D172 — 7.4c-ii's dependency map, and a divergence between the vendored header source and the built one

This entry records reconnaissance rather than work: the next stretch of 7.4c-ii was scoped and the
scope is written down here so it is not repeated. Two of the three findings are dependencies; the
third is an observation about an input the project trusts.

**1. `pmeth_gn.c` is the next independently landable unit, and one of its fourteen exports is not.**
Four hundred and fifty-eight lines, fourteen exports, and — measured by listing every external call
its body makes — **no dependency on `ctrl_params_translate.c`**. It needs `evp_keymgmt_gen_init`,
`evp_keymgmt_gen_set_template`, `evp_keymgmt_util_gen`, `evp_keymgmt_import_types`,
`evp_keymgmt_util_export`, `evp_keymgmt_util_fromdata`, `evp_pkey_ctx_free_old_ops`,
`OSSL_PARAM_dup`, `BN_GENCB_set` and `BN_GENCB_get_arg`, all of which are landed. Thirteen of the
fourteen — the two `*gen_init`s, `EVP_PKEY_generate`, `EVP_PKEY_paramgen`, `EVP_PKEY_keygen`,
`EVP_PKEY_CTX_set_cb`, `EVP_PKEY_CTX_get_cb`, `EVP_PKEY_CTX_get_keygen_info`,
`EVP_PKEY_fromdata_init`, `EVP_PKEY_fromdata`, `EVP_PKEY_fromdata_settable`, `EVP_PKEY_todata` and
`EVP_PKEY_export` — are therefore landable together.

The fourteenth is `EVP_PKEY_new_mac_key`, and it is not: its body is
`EVP_PKEY_CTX_new_id(type, e)` then `EVP_PKEY_keygen_init` then
`EVP_PKEY_CTX_set_mac_key(mac_ctx, key, keylen)` then `EVP_PKEY_keygen`. The third call is
`ctrl_params_translate.c`'s and the first is `pmeth_lib.c`'s `EVP_PKEY_CTX_new_id`, which is 7.4c-ii's
and also unlanded. So it joins `signature.c`'s eighteen behind the same gate (D171).

**2. `EVP_PKEY_generate` calls `evp_pkey_free_legacy`, and that is compiled in.**
`crypto/evp/pmeth_gn.c:192-196` is guarded by `#if !defined(FIPS_MODULE) && !defined(OPENSSL_NO_DEPRECATED_3_6)`,
and the check that matters is whether the second is defined in the build. It is **not**:
`forensics/authorities/build/openssl-3.6.4-production/configdata.pm` defines `NDEBUG` and no
`OPENSSL_NO_DEPRECATED_*`. So the call is live, on the success path of every `EVP_PKEY_generate`,
and `evp_pkey_free_legacy` (`crypto/evp/p_lib.c:1777`, declared in `include/crypto/evp.h:780`) is a
**real pre-existing dependency** of that unit rather than a dead branch. It is the kind of thing that
is invisible to a source read that stops at the `#if`.

**3. The vendored `core_names.h.in` is not the generated `core_names.h`, and they differ by a lot.**

```text
forensics/authorities/src/openssl-3.6.4/include/openssl/core_names.h.in   75  `define OSSL_` lines
forensics/authorities/build/openssl-3.6.4-production/include/openssl/core_names.h
                                                                         532  `define OSSL_` lines
```

`OSSL_GEN_PARAM_POTENTIAL` and `OSSL_GEN_PARAM_ITERATION` — needed by `pmeth_gn.c`'s
`ossl_callback_to_pkey_gencb`, which locates them in the params its provider hands it — are in the
generated header and **not** in the `.in`. Their values are `"potential"` and `"iteration"`.

What this means depends on which plane is asking, and the two are worth separating rather than
lumping:

* for **symbols**, it should not matter. `symbol-ownership.json`'s `declaring_header` comes from the
  Clang AST over the build's own include path (which has the generated header), and every exported
  symbol's declaration is in a public header rather than a name-macro header. The atlas's
  `unassigned_headers = 0` and `multiply_owned = 0` are unaffected;
* for **name macros** — the `OSSL_*` string constants, which are what a provider and this crate's
  params code compare against — a lookup that reads the vendored `.in` will miss 457 of 532 of them.

So this is recorded as an observation with a named verification, not as a defect: the next stretch
should establish which inputs resolve `OSSL_*` **name macros** rather than symbols, and if any of
them reads the source tree, they need the generated header (or the build directory) added. It is
recorded now because the transcribing of `pmeth_gn.c` is the first work that *needs* one of these
constants, and because a difference of 457 constants between two files with the same name is the kind
of thing that should be found by reading rather than by being surprised.

## D173 — `pmeth_gn.c` lands, `evp_pkey_free_legacy` stops being a deferral, and a court's class label cannot tell a typedef from its expansion

Thirteen of `crypto/evp/pmeth_gn.c`'s fourteen exports land: the two `*gen_init`s, `EVP_PKEY_generate`,
`EVP_PKEY_paramgen`, `EVP_PKEY_keygen`, `EVP_PKEY_CTX_set_cb`, `EVP_PKEY_CTX_get_cb`,
`EVP_PKEY_CTX_get_keygen_info`, `EVP_PKEY_fromdata_init`, `EVP_PKEY_fromdata`,
`EVP_PKEY_fromdata_settable`, `EVP_PKEY_todata` and `EVP_PKEY_export`. The fourteenth,
`EVP_PKEY_new_mac_key`, is gated exactly as D172 predicted: its body reaches
`EVP_PKEY_CTX_set_mac_key` (`ctrl_params_translate.c`) and `EVP_PKEY_CTX_new_id` (7.4c-ii).

**The deferral that had to move rather than be discharged.** D172 established that
`EVP_PKEY_generate` calls `evp_pkey_free_legacy` on its success path and that the `#if` guarding the
call does not remove it in this build. The function is `crypto/evp/p_lib.c`'s and had a deferral row
naming Phase 8, because its body is `x->ameth`, `EVP_PKEY_asn1_find`, `ameth->pkey_free` and four
`ENGINE_finish` calls. The crate now **defines** the name — with an empty body, and a doc stating that
every statement the authority's version has is `ameth` or `ENGINE` work — which makes the row stale,
because the gate's rule is that a row's symbol must be a name the crate does **not** define.

So the row is retired and the Phase-8 record moves into the code and into this entry, which is the
`evp_pkey_name2type` precedent exactly (D163): a name the crate defines *partially* cannot carry a
deferral, and the honest record of its missing half is the site, not the ledger. The blocking-dependency
census therefore moves **down**, which needs no transition row.

**Two contract details of the unit worth naming, because a plausible transcription gets both wrong:**

* **`EVP_PKEY_CTX_get_keygen_info`'s two boundaries are not one test.** `idx == -1` answers the
  *count*; `idx < 0` answers 0 — so `-1` is a count query and every other negative is out of range.
  And the upper test is `idx > keygen_info_count`, **not** `>=`, so `idx == count` reads one past what
  the count reports. `>=` would be the natural thing to write and would refuse a call the authority
  answers.
* **`EVP_PKEY_generate` attaches a stack array to the context** (`ctx->keygen_info = gentmp;
  keygen_info_count = 2;`) and clears the pointer after the generator returns, because a provider is
  not allowed to reach into the `EVP_PKEY_CTX` and the two legacy-compatible counters it reports
  through need somewhere to land. Leaving the pointer set would hand a later
  `EVP_PKEY_CTX_get_keygen_info` a dangling array — which is why the clearing is a statement.

**And a defect in the court, found by the court.** `EVP_PKEY_CTX_get_cb` returns `EVP_PKEY_gen_cb *`,
and `typedef int EVP_PKEY_gen_cb(EVP_PKEY_CTX *ctx)` makes that `int (*)(EVP_PKEY_CTX *)`. The crate's
first spelling of it was an inline `Option<unsafe extern "C" fn(*mut EvpPkeyCtx) -> c_int>`, which the
Rust-side reader rendered as `fptr(void; ptr(opaque))` — a `void` return — and reported. The fix is the
crate's own precedent for a function-pointer return: a **named alias**, as `BIO_meth_get_read ->
Option<BioReadFn>` does. The alias is now `EvpPkeyGenCb` in `pkey_ctx.rs`, beside the field it types.

That left a mismatch the crate could not fix, and it is the more interesting half: `classify_c` named
the authority's `EVP_PKEY_gen_cb *` a **`pointer`** on the syntactic test `t.endswith("*")`, while the
crate's resolved alias is a **`function_pointer`** — the same C type spelled two ways, classified two
ways. The BIO accessors spell it `int (*(...))(...)` and hit the `(*` test, so the two spellings had
always disagreed and nothing had compared them before. `classify_c` now consults the canonicaliser and
answers `function_pointer` when the pointee resolves to `fptr(...)`, so one type has one class.

The lesson is the one D167 recorded from the other direction: a court's *own* classification is a
claim, and this one was doing a syntactic test where the type system was available. It was found
because the crate got a declaration right and the court called it wrong — which is the only direction
in which a false mismatch is visible.

## D174 — the rest of 7.4c-ii's row, scoped: `evp_pbe.c` is gated on Phase 12, and the p5 units on one ASN.1 item

`crypto/evp/pbe_scrypt.c` lands whole (its two exports), and this entry records the scope of what is
left in the row so the next stretch does not re-derive it. Three findings, all from reading rather
than from running.

**1. `evp_pbe.c` is gated on Phase 12, by a table.** The unit is 313 lines and eight exports and has
no ctrl dependency, which made it look like the next independent landable thing. It is not, and the
reason is its `builtin_pbe[]` table: thirty-eight entries whose `keygen`/`keygen_ex` fields are
**function pointers**, and the `EVP_PBE_TYPE_OUTER` block names `PKCS5_PBE_keyivgen`,
`PKCS12_PBE_keyivgen`, `PKCS5_v2_PBE_keyivgen` and `PKCS5_v2_PBKDF2_keyivgen` among others. The
`PKCS12_*` pair is `crypto/pkcs12/p12_crpt.c`'s and is declared in `include/openssl/pkcs12.h`, so the
ownership atlas assigns it to **Phase 12** — which means `evp_pbe.c`'s table cannot be built until a
Phase-12 unit lands, and the table's contents are observable through `EVP_PBE_find_ex`, so the
pointers cannot be stubbed. That is the D169 pattern again, one phase further out, and it is why this
entry exists: the *shape* of the gate is a table of function pointers, not a call.

**2. `p5_crpt.c`'s and `p5_crpt2.c`'s own dependencies, checked the way D172 checked `pmeth_gn.c`'s.**
Neither unit calls any ctrl entry point — established by listing every external call, not by reading
includes. What they need instead is `EVP_KDF_fetch` / `EVP_KDF_CTX_new` / `EVP_KDF_derive`
(`src/evp/kdf.rs`, landed), `EVP_CipherInit_ex` (`cipher_ctx.rs`, landed), the `EVP_CIPHER_get_*` and
`EVP_MD_get_*` accessors, and — the one item that is not a call at all — **`PBEPARAM`**, the ASN.1 item
`PKCS5_PBE_keyivgen_ex` unpacks its parameter with (`ASN1_TYPE_unpack_sequence(ASN1_ITEM_rptr(PBEPARAM),
param)`). `PBEPARAM` is an `ASN1_ITEM` whose definition and `ASN1_ITEM` table entry are Phase 5's
work; if it is not in the crate, that is the second gate on those two units and it is a *data* gate
rather than a call graph, so it would not show up in a call listing.

**3. `pbe_scrypt.c` is self-contained, and it landed.** `EVP_PBE_scrypt_ex` and `EVP_PBE_scrypt` need
nothing but the KDF layer, the param constructors and one error site, and they are transcribed whole
in `src/evp/pbe.rs` — including the two facts a plausible transcription gets wrong: the bound is on
`r` and `p` and **not** on `N`, and it is tested **before** the `pass`/`salt` NULL normalisation, so an
oversized `r` refuses even with no salt at all; and both NULL strings become the empty string with
length **0**, which is why the pair travels as `octet_string` parameters and not as C strings.

**One build fact recorded while here:** `SCRYPT_MAX_MEM` is a Configure option, and
`configdata.pm` for the production build does **not** define it — so the `#else` arm is live
(`1024 * 1024 * 32`) and the `SCRYPT_MAX_MEM == 0` arm, half of `SIZE_MAX`, is dead in this profile.
That is the same class as D172's `OPENSSL_NO_DEPRECATED_3_6` check: a `#ifdef` whose answer is in the
build record rather than in the source, and which changes what a unit's body is.

**Where the row stands.** Done: `pmeth_check.c`, `pmeth_gn.c` (thirteen of fourteen), the three
descriptor-table accessors, `pbe_scrypt.c`. Left: `p5_crpt.c` and `p5_crpt2.c` (pending the `PBEPARAM`
check above), `evp_pbe.c` (pending Phase 12's `p12_crpt.c`), `p_sign.c` / `p_verify.c` / `p_enc.c` /
`p_dec.c` / `p_seal.c` / `p_open.c` (each of which calls `EVP_PKEY_CTX_ctrl`, so they follow
`ctrl_params_translate.c`), the raw-key constructors, `EVP_PKEY_new_mac_key`, and the
params/ctrl core itself.

## D175 — two more gates on 7.4c-ii's row, and the two raw-key getters that have none

`EVP_PKEY_get_raw_private_key` and `EVP_PKEY_get_raw_public_key` land (`crypto/evp/p_lib.c:591` and
`:623`), and they are the row's **only** remaining pair with no cross-phase gate at all — which is
worth stating because everything else in the row has one, and this entry names them.

**What the two getters are.** A key with a `keymgmt` — every key this crate can build — exports through
`evp_keymgmt_util_export` with a callback that locates `OSSL_PKEY_PARAM_PRIV_KEY` or
`OSSL_PKEY_PARAM_PUB_KEY` and calls `OSSL_PARAM_get_octet_string` with a `max_len` of
**`raw_key->key == NULL ? 0 : *raw_key->len`**. That ternary is what makes a NULL buffer a *length
query* rather than an error, and it is the whole reason the parameter travels as an octet string: the
caller learns the size and the size travels back through the same pointer. The second path needs
`pkey->ameth` and `ameth->get_priv_key` — Phase 8's, always NULL here — and answers what the authority
answers for a key with no method: `EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE`. Two functions, four
error sites, and no gate.

**The gates on everything else in the row, re-verified by reading rather than assumed:**

* **`p5_crpt.c` and `p5_crpt2.c` are gated on Phase 10, by a *type*.** D174 named `PBEPARAM` as the
  thing to check, and it is a gate: `typedef struct PBEPARAM_st` is declared in
  **`include/openssl/x509.h.in:261`**, so the ownership atlas assigns it to the stratum owning
  `x509.h` — Phase 10 — and `PKCS5_PBE_keyivgen_ex` needs not just the struct but its `ASN1_ITEM`
  (`ASN1_ITEM_rptr(PBEPARAM)`). The crate has the ASN.1 mechanism Phase 5 built (`Asn1Item` in
  `src/asn1/layout.rs`, `ASN1_TYPE_unpack_sequence` in `src/asn1/a_type.rs`), so this is a missing
  *item definition*, not a missing capability — and it is a data gate, which no call listing finds.
* **The raw-key *constructors* are gated on Phase 8, and the gate is inside an `#ifndef`.** D174
  recorded the summary that `new_raw_key_int` "builds an `EVP_PKEY_CTX`" and inferred it followed
  `ctrl_params_translate.c`. Reading it changes the answer twice over. `EVP_PKEY_CTX_new_from_name`
  and `EVP_PKEY_fromdata_init` are both landed (7.4c-i and `pmeth_gn.c`), so the *provider* path is
  ready. What blocks it is the block above it: `#ifndef OPENSSL_NO_ENGINE` is compiled in, and inside
  it `strtype != NULL` calls **`EVP_PKEY_asn1_find_str`** — `crypto/asn1/ameth_lib.c`'s, whose body is
  a search of `standard_methods[]`, the table of twelve `ossl_<alg>_asn1_meth` objects that are Phase
  8's (D163, D165). So the constructors are gated the same way `pkey_set_type`'s ameth arm is and for
  the same reason — and the gate is two levels down from the call that looks like the blocker.
* **`p_sign.c`, `p_verify.c`, `p_enc.c`, `p_dec.c`, `p_seal.c` and `p_open.c`** each call
  `EVP_PKEY_CTX_ctrl`, so they follow `ctrl_params_translate.c`, as D174 recorded.

**So the row's remaining order is forced, and it is not a preference:** `ctrl_params_translate.c` first
(it unblocks `signature.c`'s eighteen, which closes 7.4b, and the six `p_*` units, and the params core);
then `EVP_PKEY_asn1_find_str` and its siblings once Phase 8's table exists — or landed *partially* with
the table empty, which is the `D-PKEY-AMETH-1` precedent and would unblock the raw-key constructors
today; then `p5_crpt.c`/`p5_crpt2.c` when Phase 10 declares `PBEPARAM`; then `evp_pbe.c` when Phase 12
declares `PKCS12_PBE_keyivgen`.

That last paragraph is the useful output of this entry: three of the row's gates are in *other phases*,
and only one of them — the `EVP_PKEY_asn1_find_str` pair — can be converted into landable work inside
Phase 7 by the partial-transcription precedent the project already uses.

## D176 — the `EVP_PKEY_asn1_*` family is landable inside Phase 7, and the crate's own doc says it is not

The next in-phase work after D175 was `EVP_PKEY_asn1_find_str` and its siblings, on the reasoning that
a partial transcription with an empty table would unblock the raw-key constructors. Reading the unit
shows the finding is bigger than that and that one of the crate's own statements is wrong.

**The family is twenty-three exports across `crypto/asn1/ameth_lib.c` (438 lines), and they are
`OSSL_DEPRECATEDIN_3_6`.** Three of them are already partially landed in spirit — the
`EVP_PKEY_set_type_by_keymgmt` ameth arm is `D-PKEY-AMETH-1` — but the family itself is untouched.
The deprecation is a warning attribute and not a removal: this build defines `NDEBUG` and no
`OPENSSL_NO_DEPRECATED_*` (D172), the symbols are exported, and the prototype court reports
`not-found=0` for them. So they are owed and they are reachable.

**The correction: `EVP_PKEY_ASN1_METHOD` is not "Phase 8's" as a type.** Three places in the crate say
so — `src/evp/pkey.rs`'s module doc, its `EvpPkey` field note, and `evp_pkey_free_legacy`'s doc — and
the shape of the claim is right about the *objects* and wrong about the *struct*:

```c
include/openssl/types.h:119   typedef struct evp_pkey_asn1_method_st EVP_PKEY_ASN1_METHOD;
include/crypto/asn1.h:23      struct evp_pkey_asn1_method_st { ... };
```

The **body** is in `include/crypto/asn1.h`, which is an *internal* header — not installed, and
therefore not a declaration the ownership atlas can see. What the atlas sees is `evp.h`, which
declares the twenty-three accessors, and that makes them Phase 7's. So Phase 7 must define the struct
in order to implement its own exports, exactly as it defines `EvpPkeyCtx` in order to implement
`pmeth_lib.c`'s. What is genuinely Phase 8's is the twelve `ossl_<alg>_asn1_meth` **objects** that
populate `standard_methods[]` (D163, D165) — and only two of the twenty-three touch that table.

**So the split inside the family is what matters, and it is not the obvious one:**

* **twenty of the twenty-three are gate-free**: `get_count`, `get0`, `get0_info`, `add0`,
  `add_alias`, `new`, `free`, `copy` and the fifteen `set_*` mutators. Their bodies are `app_methods`
  (a stack, `OPENSSL_sk_*`), `CRYPTO_zalloc`, `memcpy` and field assignment;
* **`EVP_PKEY_get0_asn1` is not**, and for a different reason: its body is `return pkey->ameth;`, and
  `EvpPkey` has no `ameth` field because the field's type is the struct above — so it lands with the
  struct and not with the accessors;
* **`EVP_PKEY_asn1_find` and `EVP_PKEY_asn1_find_str`** search `app_methods` **and then**
  `standard_methods[]`. They are the two that need Phase 8's table, and they are the pair that
  `new_raw_key_int` calls (D175).

**And one exception worth naming, because it is the same shape as `evp_pkey_free_legacy`:** the
`set_*` mutators and `get0_info` read and write the struct's **callback fields**, so the struct cannot
be transcribed as an opaque placeholder. Its ~40 members are function-pointer types, which puts this
family squarely in **D170's class** — the class where a wrong parameter list is invisible to
`ABI-PROTOTYPE` (the types are fields, not exports) and to every court until a caller drives that
particular callback. So the discipline for this unit is: transcribe `include/crypto/asn1.h`'s struct
by reading each member against the header, and write the generator D170 names *before* the family, not
after it.

**Ordering consequence.** Three things are now competing for the next stretch, and the honest ranking
is: the `OSSL_CORE_MAKE_FUNC` type-plane generator first (it is mechanical, needs no provider and no
court, and this family adds ~40 more types to the unverified set); then this family, which is entirely
in-phase and unblocks the raw-key constructors with a documented empty table; then
`ctrl_params_translate.c`, which is the single gate on `signature.c`'s eighteen and therefore on
closing 7.4b.

## D177 — `EVP_PKEY_ASN1_METHOD` transcribed: forty-one members, ten types to declare, and two exports that need none of it

D176 established that the twenty-three `EVP_PKEY_asn1_*` accessors are Phase 7's and that the struct
body is in the internal `include/crypto/asn1.h`. This entry records the struct itself, member by
member, so that the unit can be written without re-reading the header — and records the type inventory
that says what else has to exist first.

**The struct is forty-one members and the order is the ABI.** From `include/crypto/asn1.h:23-89`:

```text
 1  int         pkey_id
 2  int         pkey_base_id
 3  unsigned long pkey_flags
 4  char *      pem_str
 5  char *      info

    /* Decoding and encoding, public side */
 6  int  (*pub_decode)(EVP_PKEY *pk, const X509_PUBKEY *pub)
 7  int  (*pub_encode)(X509_PUBKEY *pub, const EVP_PKEY *pk)
 8  int  (*pub_cmp)(const EVP_PKEY *a, const EVP_PKEY *b)
 9  int  (*pub_print)(BIO *out, const EVP_PKEY *pkey, int indent, ASN1_PCTX *pctx)

    /* Private side */
10  int  (*priv_decode)(EVP_PKEY *pk, const PKCS8_PRIV_KEY_INFO *p8inf)
11  int  (*priv_encode)(PKCS8_PRIV_KEY_INFO *p8, const EVP_PKEY *pk)
12  int  (*priv_print)(BIO *out, const EVP_PKEY *pkey, int indent, ASN1_PCTX *pctx)

    /* Sizes */
13  int  (*pkey_size)(const EVP_PKEY *pk)
14  int  (*pkey_bits)(const EVP_PKEY *pk)
15  int  (*pkey_security_bits)(const EVP_PKEY *pk)

    /* Parameters */
16  int  (*param_decode)(EVP_PKEY *pkey, const unsigned char **pder, int derlen)
17  int  (*param_encode)(const EVP_PKEY *pkey, unsigned char **pder)
18  int  (*param_missing)(const EVP_PKEY *pk)
19  int  (*param_copy)(EVP_PKEY *to, const EVP_PKEY *from)
20  int  (*param_cmp)(const EVP_PKEY *a, const EVP_PKEY *b)
21  int  (*param_print)(BIO *out, const EVP_PKEY *pkey, int indent, ASN1_PCTX *pctx)

22  int  (*sig_print)(BIO *out, const X509_ALGOR *sigalg, const ASN1_STRING *sig,
                     int indent, ASN1_PCTX *pctx)
23  void (*pkey_free)(EVP_PKEY *pkey)
24  int  (*pkey_ctrl)(EVP_PKEY *pkey, int op, long arg1, void *arg2)

    /* Legacy functions for old PEM */
25  int  (*old_priv_decode)(EVP_PKEY *pkey, const unsigned char **pder, int derlen)
26  int  (*old_priv_encode)(const EVP_PKEY *pkey, unsigned char **pder)

    /* Custom ASN1 signature verification and generation */
27  int  (*item_verify)(EVP_MD_CTX *ctx, const ASN1_ITEM *it, const void *data,
                      const X509_ALGOR *a, const ASN1_BIT_STRING *sig, EVP_PKEY *pkey)
28  int  (*item_sign)(EVP_MD_CTX *ctx, const ASN1_ITEM *it, const void *data,
                    X509_ALGOR *alg1, X509_ALGOR *alg2, ASN1_BIT_STRING *sig)
29  int  (*siginf_set)(X509_SIG_INFO *siginf, const X509_ALGOR *alg, const ASN1_STRING *sig)

    /* Check */
30  int  (*pkey_check)(const EVP_PKEY *pk)
31  int  (*pkey_public_check)(const EVP_PKEY *pk)
32  int  (*pkey_param_check)(const EVP_PKEY *pk)

    /* Get/set raw private/public key data */
33  int  (*set_priv_key)(EVP_PKEY *pk, const unsigned char *priv, size_t len)
34  int  (*set_pub_key)(EVP_PKEY *pk, const unsigned char *pub, size_t len)
35  int  (*get_priv_key)(const EVP_PKEY *pk, unsigned char *priv, size_t *len)
36  int  (*get_pub_key)(const EVP_PKEY *pk, unsigned char *pub, size_t *len)

    /* Exports and imports to / from providers */
37  size_t (*dirty_cnt)(const EVP_PKEY *pk)
38  int  (*export_to)(const EVP_PKEY *pk, void *to_keydata,
                      OSSL_FUNC_keymgmt_import_fn *importer,
                      OSSL_LIB_CTX *libctx, const char *propq)
39  OSSL_CALLBACK *import_from
40  int  (*copy)(EVP_PKEY *to, EVP_PKEY *from)

41  int  (*priv_decode_ex)(EVP_PKEY *pk, const PKCS8_PRIV_KEY_INFO *p8inf,
                          OSSL_LIB_CTX *libctx, const char *propq)
```

**The type inventory, checked rather than assumed.** Ten pointee types appear in those signatures and
the crate has **three** of them:

| C type | crate | note |
|---|---|---|
| `ASN1_ITEM` | `crate::asn1::layout::Asn1Item` | exists |
| `ASN1_STRING` | `crate::asn1::layout::Asn1String` | exists |
| `ASN1_PCTX` | `crate::asn1::layout::Asn1Pctx` | exists |
| `EVP_PKEY` | `crate::evp::pkey::EvpPkey` | exists |
| `OSSL_LIB_CTX` | `*mut c_void` | the crate's convention |
| `OSSL_CALLBACK` | `Option<unsafe extern "C" fn(*const OsslParam, *mut c_void) -> c_int>` | exists as a shape |
| `OSSL_FUNC_keymgmt_import_fn` | `crate::evp::keymgmt::KeymgmtImportFn` | exists |
| `X509_PUBKEY` | **absent** | Phase 10's object |
| `PKCS8_PRIV_KEY_INFO` | **absent** | Phase 10's object |
| `X509_ALGOR` | **absent** | Phase 10's object |
| `ASN1_BIT_STRING` | **absent** | Phase 5's object, not yet transcribed |
| `X509_SIG_INFO` | **absent** | Phase 10's object |
| `EVP_MD_CTX` | **absent as a named type** | `src/evp/digest.rs` has the object; the Rust name needs checking |
| `BIO` | `crate::runtime::bio::Bio` | exists |

So six types need an **opaque declaration** first — `#[repr(C)] pub struct X { _private: [u8; 0] }`,
the crate's documented idiom for a type that appears in a signature before its body is transcribed.
That is honest here rather than a shortcut: the accessors store and return the struct and never call
through those members, and the ones that *do* read fields — `get0_info`, `copy`, the `set_*` family —
are the ones that must wait for the body. The opaque declarations are therefore the prerequisite of
the unit and not a substitute for it.

**Two conclusions for the next stretch.**

* **`EVP_PKEY_asn1_get_count` and `EVP_PKEY_asn1_get0` are the only two that need no struct body at
  all** — one returns a length, the other indexes `standard_methods[]` (empty until Phase 8) and then
  `app_methods`. Everything else in the family either allocates the struct, copies it, reads a
  member, or compares two of them with `ameth_cmp`, which reads `pkey_id`. So the family does not
  decompose into a small first slice; it is one unit whose prerequisite is the struct.
* **the risk is D170's class and the mitigation is not optional.** Thirty-six of the forty-one members
  are function-pointer types, none of which `ABI-PROTOTYPE` can see, and D170 records two real defects
  of exactly that shape. So the `OSSL_CORE_MAKE_FUNC` type-plane generator is not a nice-to-have before
  this family — it is the check that makes forty-one hand-transcribed types credible.

## D178 — the mutators' signatures need named aliases, and the type plane is why

The fifteen `EVP_PKEY_asn1_set_*` mutators were written and the pipeline refused them: `type plane:
mismatches=0 unmapped=5`, on exactly the five whose parameter lists are longest — `set_public`,
`set_private`, `set_param`, `set_item` and `set_siginf`. Everything else canonicalised, including the
four-parameter `set_ctrl` and the one-parameter `set_check`.

The lesson is D173's, restated for a *parameter* rather than a return: `ABI-PROTOTYPE`'s Rust-side
reader resolves a function-pointer type through a **named alias** it can look up, and an inline
`Option<unsafe extern "C" fn(...) -> c_int>` — however correct as Rust — has nothing to look up. In
7.4c-i the fix was `EvpPkeyGenCb` for a return; here it is seventeen aliases for parameters. The five
that failed are the five that name, between them, `*const X509Pubkey`, `*mut X509Pubkey`,
`*const/*mut Pkcs8PrivKeyInfo`, `*mut X509SigInfo`, `*const X509Algor`, `*const Asn1String`,
`*mut/*const Asn1BitString`, `*mut EvpMdCtx`, `*const Asn1Item`, and the double pointers
`*mut *const u8` and `*mut *mut u8`.

**A wrong hypothesis, recorded so it is not retried.** The first guess was that `cargo fmt` reflowing
the long signatures across lines was what broke the parse, and `#[rustfmt::skip]` was added to the
five. It changed nothing: the failure is the type, not the layout. The marker is left off the tree
because it was not the cause.

**The work is written and deliberately not landed.** The mutators are the rest of a unit that is
otherwise complete, and landing them behind a red type plane would have traded a green invariant for
fifteen exports — the trade this project's constitution exists to refuse. What was landed instead is
the finding, and the shape of the fix is exact: seventeen names for seventeen parameter types, each
declared beside the struct, and the same discipline D177 already imposed on the struct's
thirty-six function-pointer *members*.

## D179 — D178's diagnosis was wrong: the reader could not read `cargo fmt`'s trailing comma

D178 concluded that the five refused `EVP_PKEY_asn1_set_*` mutators needed seventeen named parameter
aliases, because `ABI-PROTOTYPE`'s Rust reader "resolves a function-pointer type through a named alias
it can look up, and an inline `Option<unsafe extern "C" fn(...)>` has nothing to look up". **That is
false, and the reader is the defect.** The aliases would have worked — they are a valid workaround —
but they would have been seventeen names created to dodge a parser bug, and the bug would have
remained for every future declaration of the same shape.

**What the instrument actually did.** The refused artifact carried `rust_signature: null`, not a wrong
canonical form: `canon_rust_param` returned `None`. The failing parameter in each of the five was the
one `cargo fmt` had wrapped across lines, and the wrap puts the *generic argument list's* trailing
comma inside the text:

```rust
    pub_print: Option<
        unsafe extern "C" fn(*mut Bio, *const EvpPkey, c_int, *mut Asn1Pctx) -> c_int,
    >,
```

`canon_rust_type` strips the `Option<`/`>` wrapper and hands `unsafe extern "C" fn(...) -> c_int, ` to
`canon_rust_fnptr`, which reads everything after the inner `->` as the return type. It therefore read
the return type as **`c_int,`**, which is not an identifier, not an integer width, and not a pointer —
so it canonicalised to `None`, and the symbol was reported `type_unmapped` with the authority's side
perfectly readable. `set_ctrl` (four parameters), `set_check`, `set_free` and the two `set_*_key`
families are written on one line and so carry no trailing comma, which is exactly why they passed and
why the failure looked like it tracked parameter *count*. It does not; it tracks line wrapping.

**The fix**, in `forensics/tools/prototype_court.py`: `canon_rust_type` drops a trailing comma at its
own top level before classifying. A type in a list position may carry the list's trailing comma in
Rust, so this is a normalisation of the same kind as the `Option<...>` unwrap beside it, not a
loosening of the comparison. `canon_rust_param` reads through it; the recursion that unwraps
`Option<...>` re-enters at the top and so handles both the wrapped `Option<\n ...,\n>` and the
single-line `Option<X,>` shape.

**Evidence that the fix is the fix, and not merely a green run.** `compare_all` now reports
`checked=15 type_checked=15 type_unmapped=0 type_mismatches=0` over the fifteen mutators with the
declarations **unmodified** — the aliases are not on the tree. The court's own sensitivity section
gains a fourth control, `generic-argument-trailing-comma`, which asserts both halves the existing
controls assert: that the wrapped and unwrapped spellings canonicalise to the *same* form, and that a
`*mut`→`*const` change inside the same text still canonicalises *differently*. A control that only
asserted the first half would pass for a court that ignored the text entirely.

**The generalisable lesson, which is the same one the project keeps relearning.** D178 was arrived at
by reading the failing counts (`unmapped=5`) and the shape that correlated with them (the longest
parameter lists), and then reasoning from the reader's documented alias behaviour to a plausible
mechanism. The correlation was real and the mechanism was invented. What settled it in one step was
not reasoning but **reproducing the exact input**: calling `canon_rust_param` on the captured parameter
text and reading `None`, and calling `canon_rust_type("c_int,")` and reading `None`. Before that, the
plausible mechanism had already been written into the append-only record as though it were established.
The remedy is the one D178's own subject matter keeps calling for: an instrument defect is a claim
about the instrument and needs the instrument's own input, not a correlation with its output.

**Consequence for the aliases.** They are not added. `D178`'s stated fix is superseded by this entry
and is retained unedited because this file is append-only. The fifteen mutators land with their
signatures written inline, transcribed against `include/openssl/evp.h:1642-1748` parameter by
parameter, which is what D177 already did for the struct's thirty-six function-pointer members.

`implemented[libcrypto]` moves 1596 → 1611. No behaviour changed.

## D180 — the dispatch plane exists, and its first run found the D170 class again

D170 recorded two wrong callback types in landed code — `KeyexchDeriveFn` with three parameters where
the header declares four, and `KeyexchDeriveSkeyFn` returning `c_int` where the header returns
`void *` — and named the generable `OSSL_CORE_MAKE_FUNC` type-plane check as **the highest-value
missing evidence plane**. D178 then reached for named aliases as a fix for an unrelated symptom.
`forensics/tools/dispatch_court.py` is that plane, and on its first run it found the class again:
thirteen declarations in landed code disagree with the authority, including four that would have
mis-called a provider.

**Why nothing else could see it.** `core_dispatch.h` declares the provider contract as a preprocessor
constant and a typedef'd *function type*:

```c
#define OSSL_FUNC_CIPHER_NEWCTX 1
OSSL_CORE_MAKE_FUNC(void *, cipher_newctx, (void *provctx))
```

Neither half is an exported symbol. `ABI-PROTOTYPE` compares exported declarations, so it sees
nothing here; the ABI courts resolve exported symbols at their ELF versions; a runtime court observes
values, so a wrong dispatch id is visible only if a probe happens to drive exactly that entry and a
wrong callback arity only if the wrong register is read in a way the probe can see. The Phase 6
third-party provider court found bad core dispatch *IDs* by driving a provider; nothing found the
*types*.

**Two planes, authority side from the Clang atlas.** Identities: all 277 `OSSL_FUNC_*` object-like
macros in `macros.json` against every `const OSSL_FUNC_X: c_int = n;` in the crate — 195 declared,
195 agree. Signatures: all 631 function-type typedefs in `typedefs.json` against every Rust
`type X = unsafe extern "C" fn(...) -> T;` — 298 declared, 216 linked and checked, 82 exempted with a
reason, 0 unlinked. The canonicaliser is `ABI-PROTOTYPE`'s, imported rather than copied, so the two
planes cannot drift.

**The link is data, not inference, where inference cannot carry it.** The names are usually the
authority's in Rust spelling (`OSSL_FUNC_BIO_read_ex_fn` → `OsslFuncBioReadEx`), so the squashed name
is the first rule — measurable and injective, and the injectivity is *required*: the tool reports two
authority typedefs that squash to one key rather than resolving them. But a convention cannot tell
`BIO_meth_set_read_ex`'s `char *` from the core dispatch's `void *`, and those two alias names
collide. So the order is `NOT_A_DISPATCH` (a declaration of what the alias is instead, with a
reason), then `LINKS` (an explicit link — `CipherInitFn` is one Rust type for two authority
typedefs), then the convention, then the crate's own doc comment (`ChildFreeFn` is
`OSSL_FUNC_provider_free_fn`). Every alias none of the four resolves is a **failure**, which is what
stops a typo'd name from silently acquiring no counterpart; that is `run_courts.py`'s `COURTLESS`
idiom. The tables accept `Name@src/path.rs`, because a crate may declare one name twice with
different types: `ConfInitFn` is `CONF_METHOD.init` in `src/runtime/conf/types.rs` and
`conf_init_func` in `src/runtime/confmod/mod.rs`.

**What it found, and every one is fixed in this commit.**

| declaration | the authority says | the crate said |
|---|---|---|
| `SignatureDigestSignFn` | `int (void *, unsigned char *, size_t *, size_t, const unsigned char *, size_t)` | nine parameters, with `mdname`/`provkey`/`params` folded in from the *init* form |
| `SignatureDigestSignInitFn` | `int (void *, const char *, void *, const OSSL_PARAM [])` | five, with an extra `void *` before `params` |
| `SignatureDigestVerifyFn` | `int (void *, const unsigned char *, size_t, const unsigned char *, size_t)` | eight, the same transposition |
| `SignatureDigestVerifyInitFn` | as the sign-init form | five, same extra parameter |
| `KeyexchDeriveSkeyFn` | `..., OSSL_FUNC_skeymgmt_import_fn *import, ...` | `*mut c_void` |
| `KdfDeriveSkeyFn` | same | `*mut c_void` |
| `CipherPipelineInitFn` | `const unsigned char **iv` | `*const *const u8` |
| `CipherPipelineUpdateFn` | `const unsigned char **in` | `*const *const u8` |
| `SignatureQueryKeyTypesFn` | returns `const char **` | `*const *const c_char` |
| `Asn1AuxConstCb` | `int (int, const ASN1_VALUE **, const ASN1_ITEM *, void *)` | `*const *const c_void` |

The four `SignatureDigest*` types are the serious ones: the crate's parameter *order* put `mdname` and
`provkey` where the authority puts the output buffer. **No caller existed yet** — the fields are
assigned from dispatch entries and read by callers that land later — which is the best possible time
for this to be found, and it is the whole argument for building the plane before Phase 7.5's EVP code
rather than after.

The remaining five are one systematic transcription error: where the authority writes
`const T **pval` the crate wrote `*const *const U`. The C form means the *outer* pointer is writable —
only the pointee's pointee is const — so the Rust is `*mut *const U`. The fix is that class
throughout `src/asn1/` (24 sites), not only the one the plane can reach: `prim_i2c`, `prim_print`,
`asn1_ex_i2d`, `asn1_ex_print`, `ASN1_aux_const_cb`, and the internal helpers that mirror them. Call
sites that took the address of a slot now bind it `mut` and use `addr_of_mut!`, which is the sound
form the authority's own signature licenses.

**Two corrections to the tables, both made because the run disagreed with me.** `FreeFn` linked by
bare name to `CRYPTO_free_fn` and so also claimed `stack.rs`'s `OPENSSL_sk_freefunc`-shaped
declaration; the link is now scoped to `FreeFn@src/runtime/mem.rs` and the `stack.rs` one is exempted.
And `ConfInitFn` was linked to `conf_init_func`, which is `int (CONF_IMODULE *, const CONF *)` — the
DSO module init, not `CONF_METHOD.init`; the link is now scoped to the `confmod` declaration and the
`conf/types.rs` one is a `conftypes.h` struct member. **A plane whose first output is a list of its
own author's mistakes is a plane that is measuring something.**

**One instrument fix, in `ABI-PROTOTYPE`'s reader.** `GetReasonStringsFn` was reported `unmapped` and
the reason was not the declaration: it is the crate's one function-pointer type whose argument carries
a binding name —

```rust
type GetReasonStringsFn = unsafe extern "C" fn(provctx: *mut c_void) -> *const OsslItem;
```

— which is legal Rust, and `canon_rust_fnptr` canonicalised the whole `provctx: *mut c_void` text. A
parameter of a *declaration* always has a name and `canon_rust_param` already stripped it; an argument
of a function *pointer* may have one and nothing did. Both now call one `strip_binding`, so they
cannot drift again, and `ABI-PROTOTYPE`'s sensitivity section gains a
`named-fn-pointer-argument` control asserting both halves: the named and unnamed forms canonicalise
identically, and a pointee-constness change still differs.

**What is deliberately not claimed.** `signatures_authority_only` is 415 of 631 and is *coverage*, not
a defect: the authority declares the dispatch contract for every stratum and the crate has reached
seven. Nor does the plane check the two other places the same authority types appear — `OSSL_DISPATCH`
tables' identity/type pairing, and struct members declared inline rather than through an alias. The
first needs a dispatch-table reader; the second needs `structs.json`, which does record
`struct conf_method_st` and its members. Both are named here so they are not rediscovered, and
`Asn1AuxConstCb`'s four inline siblings in `ASN1_PRIMITIVE_FUNCS`/`ASN1_EXTERN_FUNCS` were fixed by
hand in this commit for exactly that reason.

No behaviour changed. `implemented[libcrypto]` is unchanged at 1611. `cargo fmt`, clippy
`-D warnings`, 423 unit tests, the full ordered pipeline and the guard all pass; the dispatch court
reports `identities 195/195`, `signatures checked=216 mismatches=0 unmapped=0 unlinked=0
problems=0`, and the regression baseline gains its artefact.

## D181 — 7.4c-ii closes: the two `find` functions land, and `OPENSSL_NO_ENGINE` is undefined

The last three of `crypto/asn1/ameth_lib.c`'s twenty-six exports — `EVP_PKEY_asn1_find`,
`EVP_PKEY_asn1_find_str` and `EVP_PKEY_get0_asn1` — land, and the unit is complete.

**The reason two of them were held was the wrong reason.** The module's own doc said the two `find`
functions were held because `standard_methods[]` is Phase 8's twelve objects. But
`EVP_PKEY_asn1_get_count` and `_get0` were already landed *against that same empty table*, with the
divergence recorded — so the table was never the reason not to define a symbol. The project's rule is
the opposite of withholding: define the symbol, answer correctly for every state the crate can reach,
and record what differs. They are now defined, they answer correctly for every method an application
registers through `add0`/`add_alias`, and the twelve legacy types are
`docs/SECURITY_DIVERGENCE_POLICY.md` **D-PKEY-AMETH-2**. The doc has been corrected rather than left
standing, because a record that names the wrong reason is the defect this project keeps finding.

**`OPENSSL_NO_ENGINE` is undefined, and an earlier note said otherwise.** The consequence is not
cosmetic: with the macro undefined the authority's engine arms in both functions are compiled **in**,
calling `ENGINE_get_pkey_asn1_meth_engine` / `ENGINE_get_pkey_asn1_meth` /
`ENGINE_pkey_asn1_find_str` / `ENGINE_init` / `ENGINE_free`. `ENGINE` is Phase 13's, so this crate has
no engine type and no registry — a consumer calling `ENGINE_add` fails to link before it can reach the
state — and with no engine registered the authority's arm itself answers NULL and falls through to
`*pe = NULL`. The crate writes that `*pe = NULL` and nothing else, so the two answers are
**identical** and there is nothing to record as a divergence; what is recorded is the reason the call
is absent, at both sites. That is the same shape as `cipher_ctx.rs`'s `ENGINE_finish` note.

**`pkey_asn1_find` is transcribed as a linear search, deliberately.** The authority asks
`standard_methods[]` with `OBJ_bsearch_ameth`, a binary search over a table sorted by `pkey_id`. The
crate's table is empty, and a binary search over it is vacuous; the linear form is what a binary
search is *equivalent to* for a table whose keys are unique, which `add0`'s duplicate check enforces
for `app_methods` and which the twelve standard objects satisfy. Transcribing the mechanism rather
than the answer would have been a longer program that means the same thing in the only state that
exists, and the reason is at the site.

**`EVP_PKEY_get0_asn1` needed `EvpPkey.ameth`, and the field is declared rather than synthesised.**
`EvpPkey`'s doc said the whole legacy block was absent "because `EVP_PKEY_ASN1_METHOD` and `ENGINE`
are Phase 8's and Phase 13's". D176 established that the *type* is Phase 7's — the accessors are
declared in installed `evp.h`, so the ownership atlas assigns them here, and this stratum defines the
struct — so the first half of that sentence was wrong. The field is typed, added in the authority's
own position (after `save_type`), and the doc now says which of the legacy fields remain absent and
why. Nothing in this crate sets it, and the field's doc says so and names the writer that will;
declaring it is what lets the accessor be `return pkey->ameth` rather than a function that manufactures
a NULL from nowhere.

`EVP_PKEY` is opaque, so the field order is the crate's and adding a field is invisible to the ABI;
`EVP_PKEY_new` allocates with `CRYPTO_zalloc`, so the field is zero-initialised with no constructor
change. The two `find` functions take `ENGINE **`, which needed an opaque `Engine` declaration — the
crate's documented idiom for a type that appears in a signature before its body.

`implemented[libcrypto]` moves 1611 → 1614, phase 7 to 479 implemented and 307 open. `cargo fmt`,
clippy `-D warnings`, 423 unit tests, the full ordered pipeline, the determinism and portability gates
and the regression guard all pass.

## D182 — the seal must require the dispatch plane, and the plane is not a subphase

Two record corrections, both for the class the reviewer of `22bef991` named: a record that omits or
mislabels what the evidence actually requires.

**The plan's 7.7 exit criterion named three instruments and not the plane D180 added.** It said "zero
open obligations, every court passing, the prototype court clean, the prerequisite gate and the plan
reconciliation at zero findings". The dispatch plane is none of those — it is not a stratum, it has no
obligation rows and no court manifest — and it is the only instrument that reaches the `OSSL_FUNC_*`
dispatch identities and callback signatures at all. Its first run found thirteen disagreeing
declarations in landed code, four of them in the `SignatureDigest*` family with a parameter order that
would mis-call a provider. A seal that did not require it would be a seal that could be earned by a tree
this plane is red on. `docs/PHASE-7-SUBPHASES.md`'s 7.7 row now names it, with its path and D180.

**D180's commit was labelled `7.6a`, and the plan's 7.6 is something else.** `7.6` is "the MAC, KDF and
HPKE header surfaces" — `crypto/hmac/hmac.c`, `crypto/cmac/cmac.c`, `crypto/hpke/hpke.c` and the
`kdf.h` remainder. The dispatch plane is an *evidence plane* rather than a work unit: it adds no crate
source, no obligation row and no court manifest. It has no subphase number, and the commit subject's
`7.6a` was a scheduling label that reads as a plan reference. The label is recorded here rather than
rewritten, because the commit is pushed and this file is append-only; the plan document is the record
that matters and it does not carry the label. Its two correct names are
`forensics/tools/dispatch_court.py` and `forensics/atlas/dispatch-court.json`.

## D183 — the canonicaliser dropped pointer depth in `(**)(...)` declarators

`canon_c_fnptr` read the declarator inside the outermost group and returned `fptr(...)` whatever it
found there. So `int (*)(EVP_PKEY_CTX *)`, `int (**)(EVP_PKEY_CTX *)` and `int (***)(void)` all
canonicalised to the same string.

**Why that is a defect and not a simplification.** Only the first is a function pointer. The second is
a *pointer to* a function pointer and the third a pointer to that — and while all three are one
pointer in the call convention, the *declared* type is what a caller writes and what the callee may
write through. The branch immediately below this one already knew this: `canon_c_type`'s `T *` arm
returns `ptr(fn(...))` for a pointer to a function type only after a comment saying "A pointer to a
function *pointer* is a real second level and is left alone (`ptr(fptr(...))`)". The declarator path
never got the same treatment, so the same type read two ways was two types.

**What found it.** The forty `EVP_PKEY_meth_get_*` accessors. Their out-parameters are
`int (**pinit)(EVP_PKEY_CTX *)` — the whole point of the `get` family is that it writes a function
pointer *through* the caller's pointer, which is why every one of them is a double pointer. The crate
declares `*mut Option<PkeyMethInitFn>`, which is exactly that; `ABI-PROTOTYPE` reported twenty type
mismatches and the instrument was the suspect. It was: `canon_rust_type` on
`*mut Option<unsafe extern "C" fn(...) -> c_int>` has always produced `ptr(fptr(...))`, so the two
sides disagreed only because the C side lost a level.

**The fix** counts the leading `*`s in the declarator and wraps in `ptr(...)` once per level beyond
the first. The court's sensitivity section gains a fifth control,
`function-pointer-declarator-depth`, which asserts both halves: one star and two stars must
canonicalise *differently* (`fptr(...)` against `ptr(fptr(...))`), three stars must give
`ptr(ptr(fptr(...)))`, and the Rust `*mut Option<fn ...>` spelling must produce the same two levels
the C does — because a fix applied to one side only would leave the plane structurally unable to see
the defect it was written for.

**The generalisable note, which is now the fifth of its kind in this stratum.** D178 invented a
mechanism from a correlation; D179, D180 and this one were each found by *reproducing the input* —
calling the reader on the exact text and reading what it returned. In every case the declaration was
right and the instrument was wrong, and in every case the correlation (parameter count, line
wrapping, parameter count again, parameter count a third time) pointed somewhere else. The
project's rule is "the instrument is the suspect before the code is", and the operative half of that
rule is *reproduce the input*, not *read the instrument's output*.

`implemented[libcrypto]` unchanged at 1614 in this commit; the court's type plane reports
`checked=1630 mismatches=0 unmapped=0` and its sensitivity section six controls, all detected.

## D184 — the `EVP_PKEY_METHOD` registry lands, and the accessors are where the depth defect hid

Forty-six exports: `EVP_PKEY_meth_new`, `_free`, `_copy`, `_get0_info`, `_add0`, `_remove`, and the
twenty `EVP_PKEY_meth_set_*` / `EVP_PKEY_meth_get_*` pairs. `include/crypto/evp.h:145-192`'s
`struct evp_pkey_method_st` is transcribed with its thirty-two members in the header's order, and
`EVP_PKEY_FLAG_DYNAMIC` with it.

**Three ways this struct is not its ASN.1 sibling, and each is a place a transcription would go
wrong by analogy.** `EVP_PKEY_meth_add0` has **no validation at all** — no alias/null rule like
`EVP_PKEY_asn1_add0`'s pair, no duplicate-`pkey_id` check, and a duplicate is pushed and the stack
sorted with both present. `EVP_PKEY_meth_copy` restores **two** fields where the ASN.1 copy restores
five, because this struct has no owned strings. And `EVP_PKEY_meth_free` frees on `DYNAMIC` alone,
which is the same rule as the ASN.1 one but load-bearing for a different reason: Phase 8's ten
`ossl_<alg>_pkey_method` objects are `static const` and must survive it.

**`EVP_PKEY_meth_remove` is pointer identity, not `pkey_id`.** The authority calls
`sk_EVP_PKEY_METHOD_delete_ptr` with no NULL test on the stack, and `OPENSSL_sk_delete_ptr` answers
NULL for a NULL stack, so a caller that removes before adding gets 0 rather than a fault. That is
reproduced rather than guarded, and it is the opposite of what `EVP_PKEY_meth_find` does — which
compares `pkey_id` through the comparator. Two lookups over one table with two different notions of
identity, both copied.

**The forty accessors are where D183's instrument defect hid**, and the reason it hid is worth
recording: every one of them takes a **double** pointer for each output, because the `get` family
writes a function pointer through the caller's pointer. Sixteen of the forty take two outputs, so a
transcription that flattened one level would have been wrong in eight of them and the court would
have said so — but only after the flattening on the *authority* side was fixed first.

**Two spellings are copied rather than tidied.** `EVP_PKEY_meth_get_encrypt`'s second output is
`pencryptfn` while its member is `encrypt`; and `get_check`, `get_public_check` and `get_param_check`
all name their output `pcheck` while writing three different members. `get_digestsign` and
`get_digestverify` name theirs with no `p` prefix at all.

**The eighteen aliases are exempted in the dispatch plane, and the reason is the next plane to
build.** `EVP_PKEY_METHOD`'s callbacks are declared **inline** in an internal header, so the atlas
records no typedef and `ABI-PROTOTYPE` sees nothing; `structs.json` has a record for the struct but
with `complete: false` and no fields, because the body is in a header the atlas does not scan. So
these eighteen types are checked by nothing, which is the second concrete argument for the
struct-member plane D180 named — the first being `ASN1_PRIMITIVE_FUNCS`'s four inline members, which
were fixed by hand in D180's commit for exactly this reason. The exemption reason says so at the
site rather than leaving it implicit.

`evp_pkey_meth_find_added_by_application` lands as a `pub(crate)` internal with no caller, carrying
an `#[allow(dead_code)]` that names the two callers that will land — `EVP_PKEY_meth_find` (7.4l) and
`int_ctx_new`'s `app_pmeth` arm (7.4c).

`implemented[libcrypto]` moves 1614 → 1660 and phase 7 to 525 implemented and 261 open.

## D185 — the struct-member plane's real obstacle is the atlas's universe, not a missing consumer

D180 named "struct members declared inline rather than through an alias" as the half of D170's class it
did not claim, and pointed at `structs.json`, which does record `conf_method_st` and its members. D184
then found eighteen `EVP_PKEY_METHOD` callback types that nothing checks and named the same plane again.
**Measured, the plane is not the answer, and the measurement is worth more than the plane would have
been.**

`forensics/atlas/openssl-3.6.4-production/structs.json` holds 465 struct records. **307 of them have no
body at all** — `complete: false` with an empty `fields` list — because the atlas's universe is the
*installed public surface*, and the bodies of the structs that matter are in headers that are not
installed. Of the 158 complete records, **8** have a field whose type is a function pointer, and only
**4** of those eight overlap the crate by name at all (`ASN1_ADB_st`/`Asn1Adb`,
`conf_method_st`/`ConfMethod`, `ossl_dispatch_st`/`OsslDispatch`, and one more through the `_st` strip).

The six structs whose function-pointer members are actually worth checking are `EVP_PKEY_METHOD`,
`EVP_PKEY_ASN1_METHOD`, `ASN1_PRIMITIVE_FUNCS`, `ASN1_EXTERN_FUNCS`, `DSO_METHOD` and `COMP_METHOD` —
and the atlas records **no** body for any of them, because all six live in `include/internal/`,
`include/crypto/` or `crypto/evp/`. A consumer written against `structs.json` today would check four
structs and report the other six as `no_prototype_in_atlas`, which is the same shape of blind spot the
plane was supposed to close.

**The fix is therefore upstream**, and there are two honest forms of it. A **second Clang pass over the
internal headers** puts the six bodies into the atlas and the plane becomes worthwhile for them; it also
grows the atlas's universe deliberately rather than accidentally, which is a change to Phase 1's
definition of that universe and so needs its own record. A **generated C translation unit** that
`#include`s the authority's internal headers and asserts each struct's member offsets and types, then
compares the crate's transcription against the assertion output, gets the same answer without changing
the atlas — and it is closer to what item 4 of the review asked for (a compile-time assertion rather
than a source parser). Neither is attempted in this commit, and neither is claimed.

What lands instead is the measurement and this conclusion: `ABI-DISPATCH`'s exemption reason for the
eighteen `PkeyMeth*Fn` aliases says the struct-member plane is what will check them, and that sentence
is now known to be false as written. The exemption is still correct — it is the only honest state
available — but it now names the *internal-header* gap rather than a plane that would not have reached
them. The other half of D180's commit, `ASN1_PRIMITIVE_FUNCS`'s four inline members and
`ASN1_EXTERN_FUNCS`'s four, were fixed by hand there for exactly this reason, and they remain checked by
nothing.

## D186 — `EVP_PKEY_CTX_new` and `_new_id` land, and the engine parameter is read and discarded

`crypto/evp/pmeth_lib.c:442` and `:447`, the two legacy-typed constructors, which is the whole of the
file's remaining constructor surface: `int_ctx_new` has existed since 7.4a, and these are its two
`EVP_PKEY *` / `int` doors. Both pass `libctx = NULL`, two NULL strings, and an id of `-1` or the
caller's.

**Both take `ENGINE *e` and neither forwards it.** The authority's `int_ctx_new` takes one and the
crate's has no such parameter, because `ENGINE` is Phase 13's; and `EVP_PKEY_CTX_new`'s engine arm is
reachable in the authority only when an engine implements the key's type, which cannot happen here for
the reason D181 records at the two `asn1_find` sites. The parameter stays in the signature — that is the
ABI — and is bound to `_` with the reason stated at the site rather than dropped, so a reader sees the
authority's parameter list and the decision in one place.

`implemented[libcrypto]` moves 1660 → 1662 and phase 7 to 527 implemented and 259 open.

## D187 — `ctrl_params_translate.c` is one atomic unit, and that is measured rather than assumed

The plan's 7.4c row now carries the slicing, and this entry records why the slicing is *not* by size.

The file is 2,959 lines. Its last 400 hold every export. The type layer (`enum state`'s ten values,
`enum action`'s three, `struct translation_ctx_st`, `struct translation_st`) and the ~40 `fixup_args`
functions are unreachable until the two translation tables exist; the tables are ~520 lines of
designated initialisers that reference the fix functions by name; and the seven entry points read the
tables. So there is no prefix of the file that is observable, and transcribing a prefix as
`#[allow(dead_code)]` internals would add ~900 unexercised lines and no evidence.

That is the *opposite* of the unit D184 landed. `EVP_PKEY_METHOD`'s forty accessors each export on
their own — the struct and six registry functions are the only shared prerequisite — which is why that
unit was one commit of forty-six exports while this one is one commit of about thirty after five
slices of work that produce nothing observable until the last.

**Every helper the unit needs is already in the crate**, which is what makes it a transcription rather
than a dependency wait: the twelve `OSSL_PARAM_construct_*` / `get_*` / `set_*` functions from Phase 6,
`OSSL_PARAM_allocate_from_text` (`src/params/from_text.rs`), `BN_bn2nativepad` and a `BN_num_bytes`
equivalent, `EVP_PKEY_CTX_settable_params`, the six `EVP_PKEY_CTX_IS_*_OP` tests on `EvpPkeyCtx`, and
`raise_site_data` for the `ERR_raise_data` sites. That list was measured, not assumed: each name was
looked for before the slicing was written down, because the alternative — discovering halfway through
a 2,959-line transcription that `OSSL_PARAM_allocate_from_text` is Phase 12's — is the failure this
project keeps recording under a different name each time.

No code changed in this commit. `implemented[libcrypto]` stays 1662, phase 7 at 527 implemented and
259 open, and the full ordered pipeline passes with both static courts clean.

## D188 — the ctrl plane lands whole, and three of its four absences were found by reading the table

`crypto/evp/ctrl_params_translate.c` is finished, together with the twenty-nine `pmeth_lib.c` exports
that are its only callers. `src/evp/pkey_ctx.rs` goes from 4,138 to 10,644 lines: the nine remaining
`fix_*` functions, twenty-five payload getters, the three `IMPL_GET_RSA_PAYLOAD_*` macros expanded
into twenty-nine instantiations apiece, `lookup_translation` and its two wrappers, the seven entry
points, and **both** translation tables — 86 rows and 41 — transcribed positionally to named fields
with the authority's own comments kept above the rows they belong to. `implemented[libcrypto]` moves
1662 → 1691 and phase 7 to 556 implemented and 230 open.

**D187 said the unit was one commit because nothing in it is observable until the last slice. That
held.** The tables read the fixers, the lookups read the tables, and the exports read the lookups, so
the evidence for the whole thing is the exports exercising the chain; three unit tests were added for
the parts of it that *cannot* be reached that way, and they are named below.

**A wrong constant was in the crate and this slice is where it became observable.**
`EVP_PKEY_CTRL_SET1_ID` was `13`; `include/openssl/evp.h:1824` says `15`, and 13 is
`EVP_PKEY_CTRL_GET_MD`. It was invisible for as long as nothing compared a *caller's* ctrl number
against it — the only two readers were `decode_cmd`, which compared it with itself, and the tables,
which did not exist. `EVP_PKEY_CTX_ctrl` is the caller that makes it observable, and a C caller
passing the header's 15 would have been answered `EVP_R_COMMAND_NOT_SUPPORTED`. Fixed, with the note
at the declaration.

**The table facts were checked against the authority rather than assumed, and one of them was wrong
in the task's own summary.** The five `OSSL_ACTION_NONE` rows name three ctrls, not one or three
rows: `DH_KDF_TYPE`, `EC_ECDH_COFACTOR` and `EC_KDF_TYPE`, with the two EC ones appearing **twice**
because the SM2 block repeats the whole of the EC block and the repetition is real — an SM2 context
is a different key type. The first draft of `the_tables_are_the_authority_rows_and_only_its_shapes`
asserted three and the table was right; the assertion is now five, with the multiset of ctrl numbers
spelled out, because a count that is *checked* is worth more than a count that is quoted.

**Three of the four shape facts the task named were confirmed, and the fourth was sharpened.** All
127 rows carry an explicit `action_type`; `ctrl_num == -1` is exactly the four ECX rows and every
pkey row is `0`; exactly two rows are hex-only, and they are `rsa_oaep_label` and
`rsa_pkcs1_implicit_rejection`. The sharpened one is the `NONE` count above. A second test pins the
lookup itself — by ctrl number, by an unrelated operation bit, and by an unknown number — and a third
pins the string door's **return channel**: `lookup_translation` rewrites the template's two ctrl-string
fields to say which column matched, and `evp_pkey_ctx_ctrl_str_to_param` reads exactly that to set
`ctx.ishex`. A transcription that set both would make every `distid` value hex-decoded, and no runtime
court would have been able to say which of the two was wrong.

**The pkey half cannot be finished, and neither can two of the exports, and this is the measurement
that D187 did not make.** Every one of the twenty-five payload getters reads the *legacy key* out of
the `EVP_PKEY *` it is handed: `EVP_PKEY_get_base_id`, `EVP_PKEY_get0_DH`, `_get0_DSA`,
`_get0_EC_KEY`, `_get0_RSA`, and then `DH_get0_p`, `RSA_get0_n`, `EC_KEY_get0_group` and their
siblings. **None of those ten functions exists in the crate**, and none can: they read `pkey->pkey.dh`
and its union siblings from the legacy block of `struct evp_pkey_st`, which `src/evp/pkey.rs`
deliberately does not have. There is no honest stand-in — a helper answering NULL would be a
placeholder pretending to be an accessor — so each getter keeps the whole of its own logic around the
dispatch and the dispatch is the absence its site names. Every one of them is nevertheless correct as
written for every key this crate can hold, because the whole table is **unreachable here**: its only
reader is `evp_pkey_setget_params_to_ctrl`, whose only reader is `evp_pkey_get_params_to_ctrl`, whose
only caller is `EVP_PKEY_get_params`'s legacy arm, reached when
`evp_pkey_is_legacy(pk)` = `type != EVP_PKEY_NONE && keymgmt == NULL` — a state this crate cannot
enter, and the crate's own `EVP_PKEY_get_params` has no such arm.

That has a **nice consequence in the dead-code structure, and it is the reason the file carries one
allow for the chain instead of forty-five.** Keeping `#[allow(dead_code)]` on
`evp_pkey_get_params_to_ctrl` alone makes `EVP_PKEY_TRANSLATIONS`, the thirteen payload getters, the
thirty-two RSA payload functions and the thirty `OSSL_PKEY_PARAM_RSA_*` keys they name all reachable.
That was established by stripping *every* allow in the file, compiling, and looking at what the
compiler still called dead; the residual was five items, and every other allow that had accumulated
across the five slices was removed. The seven that remain each have a different reason, which is the
point: `EVP_PKEY_OP_ALL` and `EVP_PKEY_OP_TYPE_NOGEN` are read only by the unit test,
`EVP_PKEY_meth_find_added_by_application` waits on 7.4l, the `CleanupCtrlToParams` variant is
unconstructed **in the authority too**, the `CleanupArgsFn` alias is the authority's second typedef
for one signature that Rust cannot coerce across, `get_payload_int` has no caller at all — its would-be
caller is the EC arm whose accessors are absent — and the last is the chain root above.
**And one of the removed ones turned out to be load-bearing for a reason nobody had written down**: `evp_pkey_ctx_free_all_cached_data`'s allow said `EVP_PKEY_CTX_free` calls it, and
`EVP_PKEY_CTX_free` called `evp_pkey_ctx_free_cached_data` instead. The authority's line 399 is the
*all* variant. The two are behaviourally identical — the all-variant's body is one call to the other
— so nothing was observable, and the stale allow was the *only* evidence that a call site had been
transcribed against the wrong half of a pair. The call is the authority's now and the allow is gone.
An unnecessary `#[allow(dead_code)]` is therefore worth reading twice rather than deleting: its
comment is a claim about a call graph, and a claim no compiler checks.

**`EVP_PKEY_CTX_str2ctrl` and `_hex2ctrl` are the two exports that cannot be finished, and for the
same one-line reason.** Each ends with `ctx->pmeth->ctrl(...)` and **no NULL test on `ctx->pmeth`**,
beyond which `EVP_PKEY_CTX_ctrl_int` and `_ctrl_str_int` refuse. The crate's `EvpPkeyCtx` has no
`pmeth` at all, so every context it can build is in exactly the state the authority would fault in;
the decode and the `INT_MAX` test are transcribed whole and the answer is the value the authority
reserves for "the callback was not reached", `-1`. These are the only two exports in this slice whose
answer differs from the authority's for a context the authority *can* build, and both are recorded at
their sites rather than in the ledger alone.

**Four more divergences, all named at their sites.** `EVP_PKEY_CTX_set_params`/`get_params` answer
`0` for a NULL context where the authority dereferences it — the crate's `gettable_params` and
`settable_params`, landed earlier in this file, already do that, so this keeps the family consistent
rather than making one of the five the odd one out. `fix_dh_nid` and `fix_dh_nid5114`'s FFC lookup is
**not** transcribed at all: `ossl_ffc_uid_to_dh_named_group` is two functions over
`crypto/ffc/ffc_dh.c`'s `dh_named_groups[]`, whose entries carry each group's prime and generator,
and a partial copy of that table's name column is precisely the half-transcription that reads as
complete; the arm answers `EVP_R_INVALID_VALUE`, which is the authority's answer for a UID with no
group. `fix_dh_paramgen_type`'s table **is** transcribed, because `crypto/evp/dh_support.c`'s
`dhtype2id[]` is four integers and four printable names with no key material — the distinction between
the two is the principle, not the size.

**One authority fault is documented rather than reproduced.** `fix_rsa_padding_mode`'s second loop
calls `strcmp(ctx->p2, str_value_map[i].ptr)` for *every* entry, and the last entry's `ptr` is NULL:
`RSA_PKCS1_WITH_TLS_PADDING` has no name. A `pad-mode` string matching none of the six therefore
reaches `strcmp` with a NULL second argument, which is undefined and faults on the glibc build the
authority is pinned to. The crate treats `None` as "this entry does not match" and takes the loop's own
not-found exit: the caller gets the `RSA_R_UNKNOWN_PADDING_TYPE` data error and `-2`, which is what it
would get for any of the other five unmatched names. Recorded because it is a reachable authority
defect, not a transcription choice.

**`evp_pkey_ctx_set_params_strict` and `_get_params_strict` were owed to 7.4c-ii and both rows were
wrong twice over.** They were in `forensics/prerequisites.json`'s `deferrals`, so building them made
the prerequisite gate report two `stale_deferral` findings — which is the gate working. Removing the
rows is the discharge, and while removing them the second problem showed: the row's *reason* describes
a body the authority does not have. It says "a three-line guard over `evp_keymgmt_get_params` — it
refuses unless the context is an `EVP_PKEY_OP_FROMDATA` operation with a live algorithm context",
which is `EVP_PKEY_fromdata`'s guard in `crypto/evp/pmeth_gn.c`. `pmeth_lib.c:858` and `:883` are
instead a settable/gettable membership check in front of `EVP_PKEY_CTX_{set,get}_params`, and that is
what landed. A deferral whose reason names the wrong body cannot be falsified by the gate, which owes
*names*; the detail is recorded here because the row is gone.

**Three supporting helpers came with the exports and were not in the task's list.**
`evp_pkey_ctx_set_md`, `_set1_octet_string`, `_add1_octet_string` and `_set_uint64` are the shared
bodies of the twenty-three wrapper exports; `decode_cmd` and `evp_pkey_ctx_store_cached_data` are the
cached-data store whose *free* half 7.4c-i landed, and `evp_pkey_ctx_ctrl_int`/`_ctrl_str_int` are the
two dispatch helpers. `evp_pkey_ctx_use_cached_data`, the store's replay half, is **not** written: its
callers are the operation inits of 7.4c-ii and it has none here, so it stays a row of the prerequisite
table rather than code with no reader.

**One transcription liberty, and it is named in the table's own comment.** The authority's 127
initialisers are positional; every one is a named-field `XlatEntry` here. The values are identical and
the only thing given up is the authority's line-for-line diffability — which is the property the
positional form *loses* the moment a field is inserted, so the trade is one readability for another.
The tables are `static` rather than `const` so that a `*const XlatEntry` handed out by the lookup stays
valid, which needs `unsafe impl Sync for XlatEntry`: its fields are raw pointers and a function
pointer, the tables are never written after their initialiser runs, and every pointer in them points
at a `c"..."` literal or a `static` in this file.

`implemented[libcrypto]` moves 1662 → 1691 and phase 7 to 556 implemented and 230 open. The ordered
pipeline passes, both static courts are clean, and the three added tests are
`the_tables_are_the_authority_rows_and_only_its_shapes`,
`a_ctrl_number_finds_its_row_and_an_unknown_one_does_not` and
`the_distid_strings_match_their_own_columns_and_the_template_says_which`.

## D189 — the signature entry points land, and the `legacy:` label does not reset the operation

`crypto/evp/signature.c` lines 568–1247 are transcribed whole into `src/evp/signature.rs`, after the
method half that 7.4b-i landed: the static `evp_pkey_signature_init` with its two-iteration fetch
loop, both name fallbacks and all three labels, and the eighteen exported entry points —
`EVP_PKEY_sign_init`, `_init_ex`, `_init_ex2`, `EVP_PKEY_sign_message_init`, `_update`, `_final`,
`EVP_PKEY_sign`; the same seven on the verification side (`EVP_PKEY_verify_init`, `_init_ex`,
`_init_ex2`, `EVP_PKEY_verify_message_init`, `_update`, `_final`, `EVP_PKEY_verify`); and
`EVP_PKEY_verify_recover` with its three `_init` spellings. `evp_pkey_ctx_use_cached_data` —
`crypto/evp/pmeth_lib.c:1534`, the replay half of the cached-data trio whose store and free halves
7.4c landed — goes into the same section of `src/evp/pkey_ctx.rs` as its two siblings, and its row is
removed from `forensics/prerequisites.json`. `implemented[libcrypto]` moves **1691 → 1709** and phase
7 to **574 implemented and 212 open** (from 556 and 230), and the gate's blocking list falls
**15 → 14**: the cached-data replay row was the *only* entry in this slice's census that was
blocking anything, so discharging it is what removes the name rather than merely recording that it
landed. (This sentence said "holds at 14" when it was first written; the census was read rather than
assumed after the pipeline ran, and it had moved. Corrected here rather than left standing.)

**The finding, and it is a reading rather than a transcription.** `legacy:` **does not reset
`ctx->operation`.** The authority's `err:` label ends

```text
err:
    evp_pkey_ctx_free_old_ops(ctx);
    ctx->operation = EVP_PKEY_OP_UNDEFINED;
    EVP_KEYMGMT_free(tmp_keymgmt);
    return ret;
```

and its `legacy:` label ends in a bare `return -2` after the `ctx->pmeth == NULL` refusal, with no
reset and no `free_old_ops`. So an init that fell through to the legacy half leaves the context
**armed** — `operation` is the caller's operation and `op.sig.algctx` is NULL. The obvious reading is
the opposite one: every other failed init in this file takes `err:` and leaves the context
`UNDEFINED`, and `_init`'s contract is usually described in those terms. The consequence is that the
`if (ctx->op.sig.algctx == NULL) goto legacy;` arms of `EVP_PKEY_sign`, `EVP_PKEY_verify` and
`EVP_PKEY_verify_recover` — three `-2`s that a court could otherwise only reach by hand-building a
context — are reachable from the public API, and `RT-EVP-PKEY` reaches all three at
`signature.c:1029`, `:1182` and `:1243`. The same asymmetry is why the three *legacy entries* are
distinguishable in the court: the middle one is the second iteration's provider-specific fetch
(no signature under the key's preferred name), the last is the post-loop `provkey == NULL` test (a
key with a method and no key data), and the first, `evp_pkey_ctx_is_legacy`, is unreachable here
because no context this crate can build has a NULL `keymgmt`.

**The deferral row's reason was wrong, and it was wrong about its callers.** The
`evp_pkey_ctx_use_cached_data` row said its "three callers are `signature.c`, `exchange.c` and
`pmeth_gn.c`". The authority has exactly two, and neither of the two extra names calls it at all:
`crypto/evp/signature.c:891` and `crypto/evp/m_sigver.c:365` — and `m_sigver.c` is not one of the
three the row named. `exchange.c`'s derive init has no cached-data step, and `pmeth_gn.c` has none
either. This is the second deferral row in two slices whose *reason* described a body the authority
does not have (D188 found the first), and the same lesson: the gate owes *names* and cannot falsify a
reason, so the detail is recorded here because the row is gone. The new row's site comment in
`src/evp/pkey_ctx.rs` states the caller count and cites this entry.

**Four stream-entry sites are an authority fault on both sides, and that is a measurement rather
than an assumption.** `EVP_PKEY_sign_message_update`, `_final`, `EVP_PKEY_verify_message_update` and
`_final` read `ctx->op.sig.signature` with no test; on a context left armed by a `legacy:` refusal
that pointer is NULL, and `signature->description` dereferences it. Measured out of band: four
programs, each against the pinned authority and against the candidate shell, each printing its
markers line-buffered and then dying with **exit 139** — the same four, the same way, on both sides.
So there is **nothing to register** in `docs/SECURITY_DIVERGENCE_POLICY.md`: a divergence is a
behaviour the two sides do not share, and two sides faulting identically is worse evidence than
agreement but is not a divergence. `RT-EVP-PKEY` prints
`NOT_MEASURED_AUTHORITY_FAULTS` at the four sites so the boundary is visible in the transcript
instead of silently absent from it.

**One arm is written and cannot be driven, and one is a single statement that needs Phase 8.**
`EVP_PKEY_verify_recover`'s `verify_recover == NULL` arm is unreachable through this unit's exports:
an armed `EVP_PKEY_OP_VERIFYRECOVER` requires `verify_recover_init`, and
`evp_signature_from_algorithm` refuses a method that publishes an init without its operation
callback, so no fetched method can reach the operate entry point with the callback absent. The
`legacy:` label's `switch (operation)` — three `ctx->pmeth->*_init` calls and a `default:` — is not
written at all, because every arm reads `ctx->pmeth` and `EVP_PKEY_METHOD` is Phase 8's; the refusal
above it is written, and it is the whole of what this crate can reach. Both are named at their sites
rather than left for a reader to notice.

**Three transcription liberties, each with a cost stated.** (1) `signature_op_prelude` factors the
prologue the seven non-init entry points share — the NULL-context test, the operation test and the
`algctx == NULL` jump — because the authority writes the same seven statements seven times with four
different site constants and one `Option` that says whether the third test is present at all. What is
given up is line-for-line diffability of eleven short bodies; what is kept is that the *order* of the
three tests, which is observable, is written once. The authority's operation test has two spellings
(`a != X && a != Y` for the one-shot pair, `a != X` for the four stream entries) and the helper takes
a mask; the two agree for every value the exports can leave in the field, because each of the five
inits stores one constant and nothing else writes it. (2) `signature_init_err` does **not** duplicate
the authority's explicit `signature->freectx(ctx->op.sig.algctx)` on the way to `err:`:
`evp_pkey_ctx_free_old_ops` calls that same callback before it releases the method, so the provider
sees one `freectx` for one `newctx` either way, and the authority's unguarded call against the
crate's guarded release differs only for a state no `newctx` can produce. (3) two stores the
authority makes are dropped because they are dead in both: the loop's `signature = NULL` (both arms
of the `switch` below assign it first) and `supported_sig`'s initialiser in the pre-fetched branch
(it is assigned before its only read). Both are noted at the site.

`#[allow(dead_code)]` came off `evp_signature_fetch_from_prov`: its first live caller was
`evp_pkey_signature_init`, and this is that caller.

**The court is `RT-EVP-PKEY`, 178 observations, zero residuals.** It publishes one provider with one
key type and fifteen signature arms, one per way the code under test can behave, and every
observation is a return code, a reason and its message data, a counter vector or a relation between
two pointers the probe holds — no address is printed. Eight dispatch tables, one per *shape* the
structural check admits, because five of the arms exist only to be refused by `evp_pkey_signature_init`
and a court that published only well-formed methods would measure nothing. The arms cover the
eighteen NULL-context answers (where the *line* is what separates them), the operation guard in both
directions, the two `EVP_R_NO_KEY_SET` sites, every callback of the full method through both the
fetching and the pre-fetched spellings, the zero-length convention on the three output buffers, the
`PROVIDER_SIGNATURE_FAILURE` arm at 0, one arm per missing init callback and for the two operation
callbacks a message-only method leaves absent, the `query_key_types` walk with a match, a
non-matching entry and an empty array, both name fallbacks and the `query_operation_name`-answers-NULL
fallback *inside* `evp_keymgmt_util_query_operation_name`, and the three legacy entries with the
`algctx == NULL` arm each makes reachable. Two arms cover the pre-fetched branch's *other* exit — the
`goto end:` a key that cannot be exported takes with `ret` still 0 — which is the third place the
crate's answer is neither the authority's refusal nor its success, and which leaves the context
armed exactly as `legacy:` does.

**Two things `RT-EVP-PKEY` deliberately does not print, both found while building it.** A *failing*
`EVP_KEYMGMT_fetch` or `EVP_SIGNATURE_fetch` puts a **namemap id** in the message —
`crypto/evp/evp_fetch.c:376`'s `Algorithm (%s : %d)` — and that number is not reproducible between
the two sides: the authority answered `(COURT-SIGKEY : 119)` on the first run of the probe and the
candidate `(COURT-SIGKEY : 1)`, from the same statement, and a separate measurement on a libctx with
no activated provider answered `(NO-SUCH-ONE : 0)` on *both* sides. The number is which name the
library registered that spelling as, so it counts what else was registered first; the probe therefore
never prints the data of a fetch it expects to fail, and every failing fetch inside
`evp_pkey_signature_init` is popped by its own error mark anyway. That same separate measurement
found a real and **pre-existing** difference that this slice does not touch and does not excuse: with
no activated provider, the candidate attempts a **DSO** load of `default` and leaves three entries on
the queue where the authority leaves none — `no filename@DSO_convert_filename/274`,
`no filename@DSO_load/139` and `(null)@provider_init/1026[name=default]` — which is the candidate
distribution having no default-provider module, not a behaviour `signature.c` owns. It is recorded
notes`). It is recorded
here rather than registered as a divergence, because it is a distribution gap in the fetch plane's
territory (7.1–7.3) and not a safety-versus-compatibility choice; `RT-EVP-PKEY` passes because it
loads its own provider before its first fetch.

**Both of those are already-owned records, and naming the owner is the point. (Correction, added in
a follow-up commit for the reason `211ba2bb` gives.)** The namemap **number** is not a mystery and
not a new gap: `docs/DECISIONS.md` **D109** predicts it exactly — "Every one of those names takes a
number, so the numbering of everything registered later depends on them" — because the legacy
pre-population is deferred whole to Phase 13, and the number in `evp_fetch.c:376`'s message is
*which name the library registered that spelling as*. A reader who finds `119` against the
candidate's `1` should go to D109, not to this entry: this slice did not cause it, cannot fix it,
and its arrival in an error message's data is the only new thing about it. Likewise the three
`default`-provider DSO entries are the residual **D117** already records for `RT-PROVIDER` —
`ossl_default_provider_init` is the algorithm tables' and `provider_init` takes the module branch
until they land. Neither is registered in `docs/SECURITY_DIVERGENCE_POLICY.md` because neither is a
safety-versus-compatibility choice; both are *distribution* gaps with a named future owner. The
remaining question D189 first raised as uncertain — whether the namemap number is "a real gap or
expected ordering" — is answered here: expected ordering, per D109.

No new function-pointer type alias was added, so `forensics/tools/dispatch_court.py`'s
`NOT_A_DISPATCH` table is untouched and its `unlinked=N` stays zero; the pipeline's `PIPELINE OK`
covers that, the prototype court, the prerequisite gate at zero findings and the FRF declarations.
