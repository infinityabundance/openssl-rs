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
