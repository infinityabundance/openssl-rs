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
