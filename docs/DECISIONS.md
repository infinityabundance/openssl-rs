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
