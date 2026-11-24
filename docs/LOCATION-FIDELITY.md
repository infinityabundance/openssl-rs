# Location fidelity: one truthful location per finding class

This document is the normative description of how a native finding record becomes
an emitted location for the Rust, FFI and binary finding classes. The
implementation is `forensics/tools/location_fidelity.py`; the controls are
`forensics/tools/tests/test_location_fidelity.py`; the recorded evidence is
`evidence/a4/{CLASSES,INSTANCES}.json`, produced deterministically by
`evidence/a4/build_instances.py`.

`docs/FINDING-IDENTITY.md` is normative for *identity*, and
`docs/SARIF-PROFILE.md` §7 is normative for the emitted SARIF shape. This
document is normative for the *location of one finding*: which location a class
may emit, from which native field, at which precision, and which substitution is
refused. It neither changes an identity nor relaxes a profile rule.

## 1. Purpose and scope

An emitted location is a **claim**. A consumer will review, patch, suppress,
bisect or break on it. When the location is wrong, the work happens somewhere the
finding is not, and the finding is read as absent from the code that carries it.

The two items split the claim:

* **A3 owns identity.** Which finding this is, across runs, candidates and code
  motion, and whether an identity may be reused. Identity says nothing about
  where the occurrence is.
* **A4 owns the location of one finding.** Given a native record, which location
  may be emitted for it, at which precision, and what that location does *not*
  establish.

The rule is singular and it is enforced in code, not only stated here:

> No line, column, extent, address, symbol, call site or expansion origin is
> emitted unless the native record carries it.

The corollary is the one that costs something: when the record does not carry a
field, the vehicle records the **absence** and emits the coarser truthful
location. It does not recover the field from the compiler, from the source text,
from a neighbouring symbol, or from a plausible reconstruction. A location that
is more precise than the record is a fabrication even when it is likely to be
correct.

Scope is the eight registered location classes of §2. It is not a general
statement about every finding rule in the tree: a rule whose native record does
not fall into one of these classes is outside this document, and the tool
refuses a class it does not register rather than guessing (`LF_REFUSED_UNKNOWN_CLASS`).

The subjects are the three a record can name: a **source** path, a **binary**
artefact, or the **record** itself. A source subject must carry a path; a binary
subject must carry a digest with a declared scope and algorithm; a record subject
names no code location at all.

## 2. The eight classes

The registry `CLASSES` in the implementation is the single source of truth; this
table repeats it. A class id is a stable identifier cited verbatim by the tool,
the tests and a receipt.

| class id | subjects | truthful location form | precision it may reach | real instance |
|---|---|---|---|---|
| `inline-macro-expansion` | source, binary | the span the compiler assigned to the tokens that carry the finding: an invocation-site token belongs to the invocation line, a body token to the definition line, with an expansion origin only where the record carries one | `line`, `symbol-only`, `byte-offset-in-artifact`, `function-offset-and-extent` | `L1-cmp-ctx-cb-to-ptr` |
| `macro-rules-derive-output` | source, binary | for a `macro_rules!` body, the definition line the compiler attributes every generated token to; each invocation is a separate instantiation with its own generated name and no distinct source line; a derive-generated item has no source file or line of its own | `definition-site`, `symbol-only`, `byte-offset-in-artifact`, `function-offset-and-extent` | `L2-define-new-free` |
| `monomorphised-generic` | source, binary | for source, the shared generic definition line as background; for a binary finding, the mangled or demangled instantiation symbol and its recorded offset and extent | `generic-definition-body`, `symbol-only`, `byte-offset-in-artifact`, `function-offset-and-extent` | `L3-md32-update` |
| `dynamic-dispatch` | source, binary | the call site the record carries together with the static target set it establishes; a trait method definition is shared by every dynamic call and is not the call's location | `line`, `call-site-offset-in-artifact`, `symbol-only` | `L4-bsearch-dyn-call` |
| `no-mangle-export` | source, binary | for source, the Rust declaration line of the export; for a binary finding, the exported symbol name plus the DSO and address of the machine code | `line`, `function-offset-and-extent`, `byte-offset-in-artifact`, `symbol-only` | `L5-cmp-ctx-export` |
| `indirect-function-pointer-call` | source, binary | the DSO, the containing function's offset and the offset of the instruction that performs the indirect call, with recorded provenance verbatim where the record resolves the pointer | `call-site-offset-in-artifact`, `symbol-only` | `L6-store-loader-closefn` |
| `inlined-optimised-code` | source, binary | the enclosing out-of-line symbol and the offset of the inlined code inside it; the inlined body has no symbol and no call site of its own | `function-offset-and-extent`, `byte-offset-in-artifact`, `line` | `L7-store-close-it`, `L7-compress-staged` |
| `binary-symbol-only` | binary | the DSO, the exported symbol name and the recorded address or byte offset, plus a recorded extent where the record carries one | `symbol-only`, `function-offset-and-extent`, `byte-offset-in-artifact` | `L8-bn-mod-inverse` |

The precision vocabulary a projection can produce is closed:
`none`, `symbol-only`, `line`, `definition-site`, `generic-definition-body`,
`byte-offset-in-artifact`, `function-offset-and-extent`,
`call-site-offset-in-artifact`, `record-condition`.

## 3. Per-class detail

Each subsection states the truthful location form, what is unavailable, what is
never emitted, and the consequence of the wrong form. The subjects and the
reachable precisions are in §2.

### 3.1 `inline-macro-expansion`

*Truthful.* The span the compiler assigned to the tokens that carry the finding.
A block written at the invocation belongs to the invocation line; a token
written inside the macro body belongs to the definition line. When the record
carries an expansion origin, it is emitted as expansion metadata; the invocation
line alone is a complete source location for an invocation-site token.

*Unavailable.* The expansion call stack when the record does not carry it;
hygiene context; a token-level mapping between body and invocation tokens; a
binary address unless the record records one.

*Never emitted.* The macro definition line substituted for an invocation-site
finding; a synthesized expansion origin or line; a column as a SARIF column.

*Instance.* `L1-cmp-ctx-cb-to-ptr`: the unsafe block is written at the invocation
`src/cmp/cmp_ctx.rs:759`, while the cast `f as *const () as *mut c_void` belongs
to the macro body at `src/cmp/cmp_ctx.rs:738`. The record carries
`line: 759`, `lineOrigin: "invocation-span"` and `expansionOrigin: "cb_to_ptr!"`,
so the truthful location is line 759 with the recorded origin as metadata.

*Consequence of the wrong form.* Emitting 738 reports the finding at the shared
macro body, so a per-invocation defect is read at a line that only contains the
body, and a fix at that line is read as fixing the invocation. Emitting a
synthesized origin invents provenance the compiler record does not contain.

### 3.2 `macro-rules-derive-output`

*Truthful.* For a `macro_rules!` body the compiler attributes generated tokens to
the definition line, with an expansion origin only where the record supplies one.
Each invocation is a separate instantiation with its own generated name and no
distinct source line. A derive-generated item has no source file or line of its
own; the attribute's line locates the input, not the generated code.

*Unavailable.* A per-instantiation source line; the expansion origin when
unrecorded; the location of derive-generated items; the number of instantiations
unless the record counts them.

*Never emitted.* The definition line as each instantiation's own line; a line per
derived impl; a synthesized expansion stack; an extent over generated code the
record does not measure.

*Instance.* `L2-define-new-free`: `src/asn1/string.rs:562` is the macro
definition, and one lexical row stands for every generated `*_free` function.
There is no per-instantiation line in the record; the generated export is a
separate binary symbol.

*Consequence of the wrong form.* `properties.instantiationLineRecorded: true` on
a macro-definition record presents the definition line as an instantiation's own
line, so a per-instance defect is reported at a line that only contains the
shared body and fixing that line is read as fixing one instance.

*Preserved limit.* The class covers derive output, but **no derive-generated
finding occurs in the tracked tree**, so the derive half is stated as a rule
without an instance. That absence is recorded rather than filled with an example.

### 3.3 `monomorphised-generic`

*Truthful.* For source, the generic definition line is the shared body and is not
any instance's own line. For a binary finding, the mangled or demangled
instantiation symbol and its recorded offset and extent are the location; the
generic definition is background, never the instance's address.

*Unavailable.* A per-instantiation source line; the type arguments unless the
symbol is demangled; a distinct source extent for each instance.

*Never emitted.* The generic definition line as the instance's line; a
type-argument-specific line; a symbol the record does not name.

*Instance.* `L3-md32-update`: one source row at `src/digest/md32.rs:118` covers
the generic body, and the candidate DSO carries six separate `update` and six
`finalize` instantiations. The binary location of the Md4 instance is the mangled
symbol `openssl_rs::digest::md32::update::<openssl_rs::digest::md4::Md4Ctx>` at
`0x1b4d20` with its recorded extent `0x165` (357 bytes).

*Consequence of the wrong form.* The shared body is read as the instance, so a
fix at `md32.rs:118` is read as fixing, or as failing to fix, one particular
instantiation. Substituting the Md5 instance's address or the generic source name
for the mangled instance reports the wrong code as the occurrence.

### 3.4 `dynamic-dispatch`

*Truthful.* The call site the record carries, with the static target set it
establishes. A trait method's definition is shared by every dynamic call and is
not the call's location. In a binary, the containing function's offset plus the
call-site offset is the whole location.

*Unavailable.* The runtime target unless the record resolves it; the receiver's
concrete type; the callee's source line; the trait definition's applicability to
this call.

*Never emitted.* The trait method's definition line as the call's location; a
single resolved target the record does not establish; a call site the record does
not carry.

*Instance.* `L4-bsearch-dyn-call`: the call at `src/runtime/bsearch.rs:85`
(`c = cmp(i);`) goes through `&mut dyn FnMut`. The emitted code loads the method
pointer and performs `call *%r13` at `0x3f551c`, inside
`openssl_rs::runtime::bsearch::ossl_bsearch` (`0x3f54e0`). The location is the
containing function plus the call-site offset; reachability of the function is
not claimed.

*Consequence of the wrong form.* The trait definition line substituted for the
call places a breakpoint or patch at code that is not the call. A single target
presented as resolved reads a target set or an ABI contract as one function, so
the wrong callee is read as the call.

### 3.5 `no-mangle-export`

*Truthful.* For source, the Rust declaration line is truthful for the export
declaration. For a binary finding, the exported symbol name is the identity and
the DSO plus address is the location. The export declaration line is never the
address of the machine code.

*Unavailable.* A line or column for the machine-code occurrence; the caller,
unless the record records one; the export's Rust signature in the binary beyond
the symbol name.

*Never emitted.* A source line for a machine-code finding at the export; a symbol
the record does not name; a definition site substituted for an address.

*Instance.* `L5-cmp-ctx-export`: the export declaration is
`src/cmp/cmp_ctx.rs:748`; the machine code is `libcrypto.so.3+0x27abd0`, size
`0x77`. The declaration line is not the machine-code location.

*Consequence of the wrong form.* The declaration line read as the instruction's
line makes a fix at the declaration look like the place the instruction is
changed, and a review at that line look like a review of the emitted body.

### 3.6 `indirect-function-pointer-call`

*Truthful.* The DSO, the containing function's offset and the offset of the
instruction that performs the indirect call. If the record resolves the pointer's
provenance, the provenance is emitted verbatim; the callee is not a location the
record establishes unless it names one.

*Unavailable.* The callee when unresolved; a source line for the call site; the
callee's definition line; an instruction extent unless the record measures one.

*Never emitted.* A line or column; one target presented as resolved when the
record records a set or a contract; a definition site in place of the call-site
offset.

*Instance.* `L6-store-loader-closefn`: the closure record's residual row 109
names the DSO, the containing function `0x36eee0`, the call site `0x36f8d3`, the
instruction `call *%rax`, and the provenance `OsslStoreLoader.closefn`. The
emitted location is exactly that, with no line.

*Consequence of the wrong form.* A resolved callee invented from an ABI contract
converts a target set into one function. A source line places a breakpoint at
code that contains no indirect call.

### 3.7 `inlined-optimised-code`

*Truthful.* The enclosing out-of-line symbol and the offset of the inlined code
inside it. The inlined body has no symbol and no call site of its own. A source
line for the body is truthful as source text; it does not become a binary
location.

*Unavailable.* A symbol for the inlined function; a distinct call site; the
boundary between inlined body and caller; a per-copy source line from the binary.

*Never emitted.* An inlined result presented with a distinct call site; a symbol
that does not exist; a call-site offset that is not an instruction boundary; the
callee's source line as the binary location.

*Instances.* `L7-store-close-it`: `ossl_store_close_it` has no symbol in the
candidate DSO; its code is inside `OSSL_STORE_open_ex` (`0x36eee0`), and the
closure record attributes the call site to the caller. `L7-compress-staged`:
`compress_staged` is private and generic and has no symbol; its only callers are
the `finalize` instantiations, so its code is located only through the enclosing
`finalize` symbol. Neither instance has a call site, because none exists.

*Consequence of the wrong form.* A breakpoint, patch or suppression placed at an
invented call site points where no instruction calls the inlined body, and a fix
at the reported call site does not change the inlined code.

### 3.8 `binary-symbol-only`

*Truthful.* The DSO, the exported symbol name and the address or byte offset the
record carries. Where the record also carries an extent, both lengths are emitted
equally. A source definition may be cited as background but is not the binary
occurrence's location, and symbol presence establishes no reachability.

*Unavailable.* A source line for the binary occurrence; the call path;
reachability from an entry point, which symbol presence does not establish; an
extent when the record records none.

*Never emitted.* A source location presented as the binary finding's location; a
call site the record does not carry; a reachability claim derived from symbol
presence.

*Instance.* `L8-bn-mod-inverse`: the tracking record names the DSO digest, the
dynsym name `BN_mod_inverse@@OPENSSL_3.0.0`, the offset `0x3cf4a0`, the size
`1137` and the GOT slot `0x896880 (R_X86_64_GLOB_DAT)`. The source definition
exists but is not the binary occurrence's location.

*Consequence of the wrong form.* Citing the source definition as the occurrence's
location directs a patch at source with no validated link to the binary.
Reading a dynsym entry as reachability treats a function that symbol presence
alone does not establish as reachable.

## 4. Real instances and synthetic controls are different things

Two different objects in this item are easy to confuse, and confusing them would
be a false claim.

A **real instance** is a tracked native record with a provenance witness. It lives
in `evidence/a4/INSTANCES.json` under `instances[*]`, has `"status": "real"`, and
cites the exact bytes it was derived from: a record digest (`recordSha256`), a
native row or JSON pointer, and the fields that pointer must carry. The nine real
instances are the ones named in §2 and §3. Re-reading their provenance against
the tracked bytes is a check on the evidence, not a re-derivation of the finding.

A **synthetic control** is a test-only mutation applied to an *emission in
memory*: one field of a projected emission is changed (or deleted), and the tool
must refuse with a named code. A control is not a source change, not an edit to a
recorded instance, and **not a defect report**. A control that fires proves the
instrument detects the substitution; it does **not** demonstrate that the
substitution occurs anywhere in the tree, and it is never described as a
vulnerability.

The 34 controls in `INSTANCES.json` are synthetic in this sense. Each has an
`op` (`set` or `delete`), a `path` into the emitted document, a `value` where it
applies, the `refusal` code the tool must return, and a `why` stating the
substitution. `verify_instances` applies each one to the recorded emission and
refuses the instance if the wrong code fires or if the mutation is accepted.

## 5. The projection algorithm

`project(record)` builds the most precise location the native record supports.
`check(record, emission)` accepts an emission only if the record supports it
exactly. The order below is the implemented order; a test asserts a refusal by
its exact code, so the order is part of the contract.

### 5.1 `project`

1. **Class.** The record's `class` must be one of the eight; otherwise
   `LF_REFUSED_UNKNOWN_CLASS`.
2. **Subject.** The subject must be an object whose `kind` is `source`, `binary`
   or `record`; a source or binary subject must carry a `uri`; otherwise
   `LF_REFUSED_MISSING_SUBJECT`.
3. **Record condition.** When the subject kind is `record`, or the native record
   sets `recordCondition`, and the record also carries a `line`, `byteOffset`,
   `address` or `callSite`, the projection refuses
   `LF_REFUSED_RECORD_CONDITION_WITH_LOCATION`. Otherwise it emits no location
   and precision `record-condition`.
4. **Source.** A class not registered for a source subject is
   `LF_REFUSED_EMISSION_INVALID`. Then, in order:
   * the candidate file set must contain the subject `uri`, else
     `LF_REFUSED_FILE_NOT_IN_CANDIDATE`;
   * a missing line, or a line whose origin is `symbol`, projects to
     `symbol-only` (when a symbol is named) or `none` (when neither);
   * a present line projects to `line`, refined to `definition-site` for an
     inline-macro or `macro_rules!` definition origin and to
     `generic-definition-body` for a generic-definition origin;
   * `instantiationLineRecorded` is true only for the origins `direct`,
     `invocation-span` and `expanded-token`;
   * an expansion origin is emitted only when the record carries one; a recorded
     column is preserved as a native property with its recorded unit and is
     **not** emitted as a SARIF column.
5. **Binary.** A class not registered for a binary subject is
   `LF_REFUSED_EMISSION_INVALID`. Then, in order:
   * the candidate file set must contain the subject `uri`;
   * the artefact digest, its scope and its algorithm must be present, else
     `LF_REFUSED_MISSING_ARTIFACT_DIGEST`;
   * `addressKind` must be `function` or `instruction`, else
     `LF_REFUSED_EMISSION_INVALID`;
   * `binary-symbol-only` with neither address nor offset projects to
     `symbol-only`, or refuses `LF_REFUSED_MISSING_SYMBOL` when it names no
     symbol;
   * a missing address falls back to the byte offset and a missing offset to the
     address; when neither exists, `LF_REFUSED_MISSING_ADDRESS`;
   * `dynamic-dispatch` and `indirect-function-pointer-call` require a recorded
     call site, else `LF_REFUSED_UNRECORDED_CALL_SITE`; the region is the
     call-site offset and the call itself carries no extent;
   * `inlined-optimised-code` requires the enclosing symbol, else
     `LF_REFUSED_INLINED_CALL_SITE`, and refuses a recorded call site with the
     same code;
   * any other binary class refuses a function whose address and offset disagree
     as `LF_REFUSED_FABRICATED_ADDRESS`;
   * an extent is emitted only when `extentRecorded` is true and the record
     carries a byte length; then `address.length` and `region.byteLength` are
     emitted equally and the precision is `function-offset-and-extent`;
   * a symbol name is emitted only when the record names one.

### 5.2 `check`

`check` re-derives the projection and refuses an emission that is not it. Its
order:

1. **Class and subject**, as in `project`.
2. **Emission class** must equal the record's class, else
   `LF_REFUSED_EMISSION_INVALID`.
3. **Text policy.** A `startColumn` anywhere in the location is
   `LF_REFUSED_COLUMN_NOT_EMITTED`; an `endLine`, `endColumn`, `charOffset` or
   `charLength` is `LF_REFUSED_UNRECORDED_EXTENT`; a `startLine` on an emission
   whose `lineInfoAvailable` is false, or on a binary precision, is
   `LF_REFUSED_MACHINE_CODE_LINE`.
4. **Record condition.** A record-condition finding that carries a location is
   `LF_REFUSED_RECORD_CONDITION_WITH_LOCATION`.
5. **Source.** The candidate file must contain the URI; a record with a line must
   emit one; an emitted line must equal the recorded line, and a line equal to
   the recorded definition line is `LF_REFUSED_DEFINITION_AS_INSTANCE` while any
   other wrong line is `LF_REFUSED_FABRICATED_LINE`; an
   `instantiationLineRecorded: true` whose origin is not an instantiation origin
   is `LF_REFUSED_DEFINITION_AS_INSTANCE`.
6. **Binary.** The candidate file and the artefact digest must be the record's
   (`LF_REFUSED_FILE_NOT_IN_CANDIDATE`, `LF_REFUSED_MISSING_ARTIFACT_DIGEST`); the
   emitted address must equal the recorded one (`LF_REFUSED_FABRICATED_ADDRESS`)
   and must be present for an address-bearing record (`LF_REFUSED_MISSING_ADDRESS`);
   a byte length must be recorded and equal (`LF_REFUSED_UNRECORDED_EXTENT`); an
   emitted symbol must be the recorded one (`LF_REFUSED_FABRICATED_SYMBOL`);
   the call-site offset of an indirect or dynamic call must be recorded and equal
   (`LF_REFUSED_UNRECORDED_CALL_SITE`, `LF_REFUSED_FABRICATED_CALL_SITE`); an
   inlined finding must name the enclosing function and carry no call site
   (`LF_REFUSED_INLINED_CALL_SITE`).
7. **Canonical equality.** The emission must be **canonically equal** to
   `project(record)`, else `LF_REFUSED_EMISSION_INVALID`.

The canonical form is `json.dumps(value, sort_keys=True, separators=(",", ":"))`.
Equality is over the whole document, so an additional, missing or renamed field
is a refusal even when every field a narrower rule names is correct. The narrower
codes exist so a consumer can learn *which* substitution happened; the canonical
check is what makes "the emission is the projection" true rather than described.

## 6. Refusal codes

Every code below is stable and is cited verbatim by a test, a receipt or the
tool. The "prevents" column states the wrong conclusion the refusal stops.

| code | condition | prevents |
|---|---|---|
| `LF_REFUSED_UNKNOWN_CLASS` | the class is not one of the eight registered location classes | that an unregistered record has no rule, so any location it carries might be the truthful one |
| `LF_REFUSED_MISSING_SUBJECT` | the record names neither a source path nor a binary artefact | that a location was verified when no subject was verified |
| `LF_REFUSED_MISSING_ARTIFACT_DIGEST` | a binary finding names no artefact digest, scope or algorithm | that the bytes examined are the candidate's bytes (Article 2) |
| `LF_REFUSED_MISSING_SYMBOL` | a symbol-only finding names no symbol | that a symbol location exists when the record names none |
| `LF_REFUSED_MISSING_ADDRESS` | a binary finding records neither an address nor a byte offset | that a machine-code location exists when none was recorded |
| `LF_REFUSED_FABRICATED_LINE` | the emitted line is not the line the native record carries | that the defect is at a line no native record identifies, so the wrong code is reviewed, patched or suppressed, or the finding is read as absent because that line is unrelated |
| `LF_REFUSED_DEFINITION_AS_INSTANCE` | a definition site (macro body, generic body) is presented as an instantiation's own location | that each instantiation has its own line at the shared definition, so a per-instance defect is reported at a line that only contains the shared body and fixing that line is read as fixing one instance |
| `LF_REFUSED_MACHINE_CODE_LINE` | a machine-code finding carries a source line | that the emitted instruction has a source line when the record records an address only, so a reader marks up a line the compiler may not have emitted the instruction from, particularly after inlining |
| `LF_REFUSED_COLUMN_NOT_EMITTED` | a column is emitted as a SARIF column | a token-level precision the record does not state, with an unstated unit |
| `LF_REFUSED_UNRECORDED_EXTENT` | an end line, column, offset, length or byte extent not present in the native record is emitted | that the tool observed the whole range, statement or symbol, so a diff, suppression or patch is scoped to bytes nobody examined |
| `LF_REFUSED_FILE_NOT_IN_CANDIDATE` | the location names a file the candidate identity does not contain | that the finding applies to this candidate when the record came from another candidate or a path that no longer exists (Article 2) |
| `LF_REFUSED_INLINED_CALL_SITE` | an inlined finding is presented as if it had a distinct call site or callee symbol | that a call exists in the binary, so a breakpoint, patch or suppression is placed where no instruction calls the inlined body, and a fix at the reported call site does not change the inlined code |
| `LF_REFUSED_UNRECORDED_CALL_SITE` | a dynamic or indirect call has no recorded call-site offset | that the dispatch's location is known when only its target set or its containing function is known |
| `LF_REFUSED_FABRICATED_CALL_SITE` | the emitted call-site offset is not the one the record carries | that the instruction at an invented offset is the dispatch, so the wrong instruction is read as the call |
| `LF_REFUSED_FABRICATED_ADDRESS` | the emitted address is not the address the record carries | that a resolved target was observed when the record establishes no such target |
| `LF_REFUSED_FABRICATED_SYMBOL` | a symbol name is emitted although the record names none, or names a different one | that the binary has that symbol and that the finding is inside it |
| `LF_REFUSED_RECORD_CONDITION_WITH_LOCATION` | a record-level condition is given a code location | that the condition is a property of a file or instruction when it is a property of the record, so a reader hunts for code that carries no defect |
| `LF_REFUSED_EMISSION_INVALID` | the emission differs from the one the record supports in a way no narrower refusal names | that the emission is the projection of the record when it is not |
| `LF_REFUSED_INSTANCE` | a recorded A4 instance failed its own projection or control | that the instance supports the rule it is cited for |
| `LF_REFUSED_PROVENANCE` | the tracked provenance an instance cites cannot be read or does not carry the expected native fields | that the instance is bound to the native record it names |

The A1 emission scan has its own codes under a separate prefix
(`LF_SARIF_*`). They report a violation of `docs/SARIF-PROFILE.md` §7 in an
existing emission; they do not modify the profile and they are not refusals of a
projection.

## 7. Controls and measured figures

The controls are negative by construction: each changes one thing and requires
the named refusal. The figures below are the measured output of the commands in
this section, not estimates.

| quantity | measured |
|---|---|
| real instances | 9 over the 8 classes (`inlined-optimised-code` carries 2) |
| tracked provenance entries | 20, re-read against the tracked bytes |
| synthetic mutation controls | 34, each asserted by its exact refusal code |
| symbol and instruction observations | 13, re-read against the DSO where the artefact is present |
| A1 emission scan | 4 245 results in 6 runs, 0 violations |

The distribution is one instance each for `inline-macro-expansion`,
`macro-rules-derive-output`, `monomorphised-generic`, `dynamic-dispatch`,
`no-mangle-export`, `indirect-function-pointer-call` and `binary-symbol-only`,
and two for `inlined-optimised-code`.

**The observation control found a real transcription defect.** `L3-md32-update`
recorded the monomorphised `update::<Md4Ctx>` extent as `0xA5`, i.e. 165 bytes,
which is the `nm` posix size field `165` read as decimal instead of
hexadecimal. `readelf -sW` reports **357** bytes (0x165) for
`_RINvNtNtCsfBoMNNx3tZr_10openssl_rs6digest4md326updateNtNtB4_3md46Md4CtxEB6_`
at `0x1b4d20`, and the next instantiation begins at `0x1b4e90`, which is
consistent with 357 and not with 165. The record, its observation and the
one-byte-past control were corrected to `0x165` (357) and `0x166` (358). The old
value, the new value, the corroborating measurement and the repair commit
`5f868b04f` are recorded; the recorded history is preserved rather than
rewritten.

With the correction, `verify-instances --observe` re-reads **13 of 13**
observations against `artifacts/phase2/install/lib/libcrypto.so.3`
(SHA-256 `fd25cc9e6424ea79aaaff05df22b3f6e1d46aa22d5666cfe7589dce95ffd88a9`),
0 not run, over 9 instances, 20 provenance entries and 34 mutations.

**The A1 emission scan is clean but is not a safety result.** Over
`evidence/a1/SARIF.json`, the 4 245 results have the precision population 4 011
`line`, 200 `byte-offset-in-artifact`, 2 `function-offset-and-extent`, and 32
record-condition results with no precision property and no locations. The scan
returns zero violations. This says the existing emission obeys the location
policy; it says nothing about whether any finding is true.

**Determinism.** Two projections of the same record are byte-identical, and
`check(record, project(record))` accepts for every recorded instance.

## 8. Non-claims and limits

* **A truthful location is not a claim that the finding is true, reachable,
  severe or current.** It says the location the record supports is emitted and
  no other. Identity is not state, and location is not state either.
* **The nine instances are not a census.** They exercise every class; they do
  not enumerate every finding that could fall into one.
* **The derive half has no instance.** No derive-generated finding occurs in the
  tracked tree, so `macro-rules-derive-output` states the derive rule without an
  example. This is recorded as an absence, not filled.
* **Expansion origins are emitted only where recorded.** The tool does not
  reconstruct an expansion stack.
* **Instruction observations are a string check, not a decoder-level proof.**
  An instruction observation is matched against `objdump` text at a computed
  address range. That confirms the bytes and the mnemonic text appear in that
  range; it is not a proof that the instruction boundary is valid for every
  decoder, and it is not an aliasing or ownership result.
* **Observations are `NOT_RUN` where the artefact is absent.** The check is
  bound to the recorded DSO digest; without that artefact the observation is
  deferred, and deferred is never pass.
* **No profile rule is relaxed.** The A1 profile's location policy is unchanged;
  `a1PolicyChange` is `none`, and the scan holds an emission to the profile
  rather than amending it.
* **Control codes are instrument evidence, not defect reports.** A synthetic
  control that fires proves the refusal works. It does not show that the
  substituted form appears in any record, and it is never reported as a
  vulnerability.
* **The scan covers one population.** The zero-violation result describes the
  six runs in `evidence/a1/SARIF.json`, not every emission the project may
  produce.

## 9. `NOT_RUN`

The following were not run at this level and are not claimed as pass:

* **BOUNDARY.** No independent caller or dependency-closure audit, no targeted
  Miri or sanitizer run, and no negative-control canary outside the tool's own
  refusals.
* **SEAL.** No full forensic regeneration, no broad compatibility or
  cryptographic assurance against this candidate, and no held-out verification.
* **Independent review.** The author of these controls is not an independent
  reviewer, and no third party has reviewed the mapping from class to refusal.
* **Any other artefact or profile.** Only
  `artifacts/phase2/install/lib/libcrypto.so.3` was re-read for observations, and
  only `evidence/a1/SARIF.json` was scanned. Any other DSO, SARIF document or
  profile is out of scope for this record.
* **The Rust suite.** `src/` was not modified, so the Rust test suite was not
  rebuilt or rerun for this item. The Python gates are the item's evidence.
