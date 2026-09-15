# Phase 4 — BIO, CONF and the buffer object: seal

**STATUS: reopened, `in-progress` (docs/DECISIONS.md D97).** Phase 4's own surface
was sealed as closed, and all sixteen courts pass with no residual — that is
unchanged. What D97 found is that the ledger's *universe* was a prefix list, and a
prefix that matches nothing reports nothing: nineteen exports the global ownership
atlas assigns this stratum were in no ledger at all, eighteen of which are now
recorded `open`. `forensics/phase-state.json` therefore derives `in-progress`. See §10.

**For every count in this document, read `docs/SEAL-CENSUS.md`**, which is generated
from the ledgers and the court results and cannot go stale.

This is **not** a claim that openssl-rs is a usable OpenSSL. 932 of 5,896 `libcrypto`
exports are implemented and all 603 `libssl` exports are still `SCAFFOLDED` and abort
when called.

- Authority: `openssl-3.6.4-production`
- Court results: `artifacts/phase4/COURTS.json` (16 courts, 3,217 observations, 0 residuals)
- Obligation ledger: `forensics/phase4-obligations.json` — figures in
  `docs/SEAL-CENSUS.md`. At seal time it read 262 owned: 231 implemented, 31 handed to
  named later strata, 0 open; D97 changed the universe to 272 owned: 231 implemented,
  23 handed on, 18 open
- Derived state: `forensics/phase-state.json` (`in-progress`)

## 1. What this phase built

| subsystem | what it is |
|---|---|
| BIO core | methods and the method table, `BIO_new`/`_new_ex`/`_up_ref`/`_free`/`_vfree`, chains (`push`/`pop`/`next`/`find_type`), flags, retry type and reason, `BIO_get_retry_BIO`, the modern and deprecated callback pairs, `dup_chain`, `BIO_set_data`/`get_data`, `BIO_printf`/`BIO_snprintf`/`BIO_indent`/`BIO_dump*`/`BIO_hex_string`, `BIO_ADDR`/`BIO_ADDRINFO`, `BIO_lookup`, `BIO_parse_hostserv`, `BIO_socket_*`, `BIO_debug_callback`, `BIO_find_type`, `BIO_meth_*` |
| BIO methods | memory, secure-memory, null, null-filter, socket, fd, file, connect, accept, datagram, in-memory datagram pair, BIO pair, buffer, line-buffer, read-buffer, prefix and compression filters, and the `BIO_new_*` constructors over them |
| buffer object | `BUF_MEM_new`/`_new_ex`/`_grow`/`_grow_clean`/`_free`, `BUF_reverse` |
| CONF | the reader (`conf_def.c`: both character-class tables, the scanner, all three variable-expansion forms, `clear_comments`, include processing and directory walking), the `CONF` container and its hash (`conf_api.c`), the classic hash bridge and the `NCONF_*` accessors (`conf_lib.c`), and `CONF_parse_list`/`CONF_get1_default_config_file` (`conf_mod.c`'s helpers) |
| object database | `OBJ_create_objects` over a BIO description stream, on top of Phase 3's object/NID tables |

It also carries the fixes the courts forced into Phase 3 surface: `OPENSSL_LH_*`
insertion order (D52), `ERR_raise_data`'s formatter (D53) and the ERR raise-site
coordinates (D60).

## 2. The evidence

Every court is a C probe compiled twice — once against the admitted authority's
headers and library, once against the candidate's generated headers and
`artifacts/phase2` — run on the same machine, and diffed line by line. A crash on
either side is a `fail`, not a missing observation.

| court | observations | what it compares |
|---|---|---|
| `RT-BIO` | 212 | the BIO core over the memory, secure-memory, null and null-filter methods, plus the buffer object |
| `RT-ERR-BIO` | 17 | `ERR_print_errors`, `_cb`, `_fp` and `ERR_add_error_mem_bio` |
| `RT-BIO-ADDR` | 98 | the `BIO_ADDR` value API, its string conversions and its rejection cases |
| `RT-BIO-RESOLVE` | 501 | `BIO_lookup`, `BIO_ADDRINFO` iteration and the socket put/get controls |
| `RT-BIO-SOCK` | 157 | the socket BIO and the `BIO_socket_*` descriptor helpers |
| `RT-BIO-COMP` | 45 | the compression BIO and its name map |
| `RT-BIO-DEBUG` | 57 | `BIO_debug_callback` and its indentation, including the NULL-destination fallback's message |
| `RT-BIO-PRINT` | 213 | `BIO_printf`, `BIO_snprintf`, the shared formatter and `BIO_dump` |
| `RT-BIO-FILE` | 134 | the file BIO, descriptor ownership and its controls |
| `RT-BIO-FILTER` | 114 | the buffer, line-buffer, read-buffer and prefix filters |
| `RT-BIO-PAIR` | 111 | the BIO pair, its directions and its retry behaviour |
| `RT-BIO-DGRAM-PAIR` | 141 | the in-memory datagram pair |
| `RT-BIO-DGRAM` | 294 | the kernel datagram BIO and its peer/control surface |
| `RT-BIO-CONN` | 296 | the connect and accept BIOs |
| `RT-OBJ-STREAM` | 91 | `OBJ_create_objects` and the description stream behind it |
| `RT-CONF` | 736 | the CONF reader, the classic hash bridge and the `NCONF_*` accessors |

With Phase 3's seven courts re-verified in the same run, the derived totals are
**34 courts and 7,481 observations, all passing**. `implemented` `libcrypto` exports
are **455** of 6,499; 486 exports are owned by a phase family once the eleven Phase 3
hand-offs are counted on one side only; 132 unit tests pass; `cargo clippy
--all-targets -- -D warnings` is clean crate-wide (D59).

## 3. What the probes found that memory would have got wrong

The courts are the reason this stratum is worth reading. Reconstructing from headers
and intuition produced a plausible implementation that the courts then corrected in
the ways below — four defects from the first BIO court, two from the object court,
five from the CONF work and its two spill-overs, and the further ones D47 and D48
record.

### From `RT-BIO`

1. **`BIO_snprintf` returns −1 on truncation**, not the length that would have been
   written — unlike `snprintf(3)`, and unlike `BIO_printf`.
2. **`BIO_sock_error` returns the current socket error** on a failed `getsockopt`
   (measured: `9`, `EBADF`), not a generic `1`.
3. **`BIO_ctrl(b, BIO_C_GET_FD, …)` returns the descriptor**, and `-1` for an
   uninitialised BIO; `BIO_C_SET_NBIO` is absent from the socket control switch, so
   it reports `0` rather than doing anything.
4. **`sock_new` leaves `init == 0`.** A bare `BIO_new(BIO_s_socket())` therefore
   reports `-1` from `BIO_C_GET_FD`, and its destructor must **not** close
   descriptor 0. `BIO_new_socket` is `BIO_set_fd`, not two field writes; writing the
   fields directly leaves `init` at `0` and the BIO unusable.

### From `RT-BIO-PRINT`, `RT-OBJ-STREAM`, `RT-BIO-DGRAM` and `RT-BIO-CONN`

5. `BIO_snprintf`'s engine is not the C library's `vsnprintf`; it is `_dopr` (D41,
   D53).
6. `OBJ_create` and `OBJ_txt2obj` were silent where the authority raises (D44).
7. The kernel datagram BIO's court found three further defects in code already
   recorded as implemented (D47), and the connect/accept court found three more
   (D48).

### From `RT-CONF` and the work it forced

8. **`OPENSSL_LH_insert` appends at a bucket's tail, not its head.** The authority's
   `getrn` returns `&(last->next)` on a miss, so a bucket's head is its *oldest*
   entry and `doall` visits a bucket in insertion order. Found by nine `dump.text`
   residuals — all permutations of the same two colliding keys — because
   `NCONF_dump_bio` *is* a `doall` walk. No earlier court could see it: `RT-LHASH`
   cannot reach the `doall` family at all, since the authority faults at the NULL
   thunk on a table built by a bare `OPENSSL_LH_new`. Prepending had survived three
   phases as a plausible assumption (D52).
9. **`OPENSSL_LH_doall_arg_thunk`'s `thunk` argument is a per-node wrapper**, not an
   iteration entry point. The old code called it once for the whole table, which
   would have handed `def_dump` the table pointer instead of each `CONF_VALUE` (D60).
10. **`ERR_raise_data` is formatted by `BIO_vsnprintf` (`_dopr`), not by libc.** It
    renders `%s` of NULL as `<NULL>` — reachable through
    `NCONF_get_number_e(conf, group, NULL, &res)` — and reports truncation as
    failure, so an over-long message becomes **empty** rather than truncated.
    `RT-ERR` could not see this because its raise-site section exercises sites whose
    messages carry no substitutions (D53).
11. **`get_next_file` must clear its own out-parameter** after `OPENSSL_DIR_end`.
    `OPENSSL_DIR_end` faithfully leaves the caller's pointer dangling, and without the
    clear the parser's "still walking a directory?" test stays true and the next EOF
    calls in with a freed path. This was a **segfault in the court**, found by
    bisecting with temporary `eprintln!` (D54).
12. **Six of 316 ERR raise sites had the wrong enclosing function name** — observable,
    because `ERR_get_error_all` returns it. The parser matched the first
    definition-looking identifier, so `CONF_load` was reported as `HASH_OF` and
    `_dopr` as `dopr` (D60).
13. **`RT-BIO-DEBUG`'s capture was not reproducible.** The one call whose destination
    is NULL writes to stderr, and its message begins with the subject's address, so
    the recorded stderr — and therefore the court's evidence identity — differed on
    every run, even though the court's declared axis was stable. Found by noticing
    that the aggregate runtime claim's id changed between two runs of identical
    sources. `setarch -R` is refused in both containers, so the probe now captures and
    scrubs that message itself (D61); three re-runs now return one identity and FRF
    refuses to re-capture.

Thirteen numbered findings, and the pattern is the one this project is built on:
every one was found because a **new** court — or, in the last case, a **re-run** —
observed a surface no existing court could see, and several were in code already
recorded as `implemented`.

## 4. Fault boundaries — recorded, not reproduced

Three authority behaviours in this stratum fault or are deliberately not copied.
Each is recorded in `docs/SECURITY_DIVERGENCE_POLICY.md` with its own class, and
each is narrow: the parity claim is narrowed, not the fault copied.

| divergence | authority | candidate |
|---|---|---|
| `CONF_parse_list` with a NULL callback (D-CONF-1) | faults | treats NULL as "nothing to deliver to" and returns 0 |
| `_CONF_new_section`'s error path (D-CONF-2) | frees `v->section` even when the allocation that would have initialised it failed | frees only what it allocated |
| `CONF_get1_default_config_file` with `OPENSSL_CONF` unset (D-CONF-3) | answers the forensic build's `OPENSSLDIR` | answers `""`, the authority's own idiom for "no such path", owned by Phase 16 as `OBL-CONF-DEFAULT-CONFIG-FILE` |

`RT-CONF` records the first and the recursive-directory include case as
`NOT_MEASURED_AUTHORITY_FAULTS` rather than as values, and the third as
`RECORDED_DIVERGENCE_OBL_CONF_DEFAULT_CONFIG_FILE`. A court that cannot compare a
fault says so; it does not silently agree.

The third is the only one of the three that is a *compatibility* choice rather than a
safety one, and it is the kind of thing this project insists on labelling: the
authority's `file`/`line` coordinates are reproduced byte for byte because they are
provenance, but a functional path pointing at a directory that exists on no machine
this crate ships to is a worse answer than "there is none configured yet".

## 5. Deliberate scaffolding, and what it means

**Superseded by §10 in its arithmetic**: this section describes the hand-offs as they
stood at seal time — 31 exports to five later strata, and eleven received from
Phase 3. D97 changed both sides of that ledger (§10). The *policy* below is unchanged.

- **31 Phase 4 family exports are handed to five later strata**, each with a named
  owning phase and a stated reason, all in `forensics/phase4-obligations.json`:
  six to Phase 5 (the ASN.1 prefix/suffix hooks, `BIO_f_asn1`, `BIO_new_NDEF`),
  seventeen to Phase 6 (`BIO_s_core`, `BIO_new_from_core_bio` and the fifteen
  `CONF_modules_*`/`CONF_module_*`/`CONF_imodule_*` entry points, whose observable
  behaviour depends on the `OSSL_LIB_CTX` configuration-diagnostics flag), five to
  Phase 7 (the digest, cipher, reliable and base64 filters and `BIO_set_cipher`, all
  wrappers over EVP), one to Phase 9 (`BIO_f_nbio_test`, whose read and write call
  `RAND_priv_bytes`) and two to Phase 12 (`BIO_new_CMS`, `BIO_new_PKCS7`). They stay
  `SCAFFOLDED` and abort; none is a no-op.
- **Eleven exports Phase 3 handed to this stratum are discharged here**, and stay
  recorded as Phase 3's hand-off rather than being re-counted as Phase 3's work
  (D57). `ownership_audit.py` fails if the two ledgers disagree.
- `phase4_obligations.py` fails closed: an export in a Phase 4 family that is
  neither implemented, handed to a named later stratum, nor recorded as open makes
  the ledger refuse to generate, and `open_in_this_stratum > 0` keeps the derived
  phase state at `in-progress`.

## 6. What is explicitly NOT claimed

- **Not that BIO or CONF are done.** They are done *for the surfaces the sixteen
  courts observe*, on one platform, for one build profile. `RT-CONF` exercises a
  large part of the reader, but nothing here says a configuration file the probe does
  not construct parses correctly.
- **Not that any symbol is `PARITY_VERIFIED`.** The strongest state any of them
  carries is `IMPLEMENTED`, and the ledger's overall state stays below
  `PARITY_VERIFIED` until every applicable dimension — error queue, ownership,
  concurrency, downstream — is proved for it.
- **Not cryptographic or security evidence.** These are differential-compatibility
  courts. `BIO_f_md`, `BIO_f_cipher` and `BIO_f_base64` are not implemented at all,
  so nothing in this stratum has been measured against a cipher, digest or key.
- **Not that the CONF module registry works.** It is handed to Phase 6, and the
  reason is substantive rather than scheduling: `CONF_modules_load`'s result depends
  on a flag that lives in `OSSL_LIB_CTX`.
- **Not that signature/arity compatibility is courted.** `ABI-SYMBOL` compares name,
  version, ELF type, binding and visibility; it does **not** compare C prototypes.
  A declaration that disagrees with the definition and is never exercised by a probe
  would still pass. Carried forward from Phase 3 and recorded as a residual.
- **Not a portable result.** One authority, one build profile
  (`enable-shared enable-legacy no-tfo no-ktls no-sctp no-ssl3 …`), `x86_64-linux`,
  one `LC_ALL`/`TZ`. See `docs/NON_CLAIMS.md`.
- Not FIPS validated, and not FIPS-capable.

## 7. Exit criteria

| criterion | state |
|---|---|
| BIO, CONF, buffer-object and object-stream subsystems implemented | met, except the 31 recorded hand-offs |
| differential courts exist and pass | met: 16 courts, 3,217 observations, no residual |
| no export in the stratum's families is unaccounted for | met at seal time against the Phase 4 *families* (231 + 31 + 0 = 262). **Not met against the stratum's universe: D97 found nineteen atlas-owned exports with no row at all**, eighteen of which are now `open`, so the criterion is unmet and the state is `in-progress`. See §10 |
| every implemented export is owned by exactly one stratum | met, enforced by `ownership_audit.py` (D57) |
| faults recorded rather than reproduced | met: three divergences, each with a class and a narrowed claim |
| lint gate clean | met: `cargo clippy --all-targets -- -D warnings` passes crate-wide (D59) |
| FRF receipt and compiled claim | met, §8 |
| Gemel trajectory and checkpoint | met, §9 |
| seal written | this document |

## 8. FRF evidence

Twenty-three FRF courts now run against the candidate: the three trajectory courts,
the ABI surface court, and the twenty runtime courts (`openssl-rs-rt-mem` through
`openssl-rs-rt-conf`). Each admits the reference program `openssl-rt-3.6.4-r2`, runs
both sides over a fixture list, compares the transcripts, and is challenged on every
axis it declares.

The compiled runtime claim is

```
9422588fe4d733dd8e1ae5c76e3b1da784c8ca75b05829a241c9245e07f91c97
```

at `--policy sensitivity-backed`, over the receipts of all twenty-three runtime
courts. The other claims, one authority each:

| claim | policy |
|---|---|
| `4b17cc5ccbe9fafb1d7e5de37bd73aafa825c1a1156ab5acfc67062f40d8f15e` (ABI surface) | sensitivity-backed |
| `0988dff72217ae05e82d44e3830d3080e99acb408fff69508535766c41844f11` (CLI digest) | sensitivity-backed |
| `2c2395d5bc16de182fec54cb8fd9d475994fc49cfdd8aef49c40d3560bcdb8cf` (CLI inventory) | sensitivity-backed |
| `ebfd07e39828771160ff5052391c8b55237f0da7b49c180d404c9d5d93a329e7` (version + digest) | baseline |

Every runtime court demonstrated that each declared axis can see its own defect
class, on that axis and no other. The one exception is the release-banner court,
which diverges by design: `openssl-cli-version` **fails** its challenge and is
compiled under `--policy baseline` with the trajectory residual
`40a254aac9beb227c4486672caf329128cced5cb465d8048250b6578ce69cb3a` disposed
`oracle_version`. An honestly refused challenge is better evidence than a falsely
passing one (D13), and the whole chain ends with the store verifying:
`graph_verified: yes`, `object_closure: complete`, 81 captures, 57 residuals,
54 challenges, 27 receipts, 5 claims.

**Three things a reader must not infer.**

1. **These identities are content-addressed, and they are the identities this
   commit produced.** Getting there required fixing `RT-BIO-DEBUG` (D61): its
   capture had leaked an ASLR-dependent address to stderr through the
   NULL-destination fallback, so its run identity — and therefore the aggregate
   runtime claim's — changed on every run while every other court's did not. Three
   re-runs of the fixed court now return one run id and FRF refuses to re-capture.
   **They supersede the Phase 3 claim identity**: `docs/PHASE-3-CORE-RUNTIME-SEAL.md`
   names `ffd0b7b3…`, which is what the seven runtime courts compiled to at that
   boundary and which no longer exists as an object, because the store is recreated
   per release rather than carried forward.
2. **The claim's own wording is narrower than what was observed.** FRF extracts the
   `stdout` axis as `stdout-first-line`; the harness makes that line a digest of the
   entire transcript, so the claim does cover every observation — but the mapping is
   stated in `forensics/frf/README.md` rather than left to be assumed.
3. **The court declarations are generated.** `forensics/tools/gen_frf_courts.py` owns
   the twenty-three runtime manifests and fixtures, `--check` fails on drift, and CI
   runs it. Regenerating them added an explicit probe-staging-phase argument to every
   runtime court and moved `version_or_commit` to `0.0.7`; no court's question,
   falsifier, authority, fixture list or observed axis changed (D58).

## 9. Gemel

Change `C15`
(`change.c7209037d8afa7cbacfab88290b3d6b99c39d116e47437a338f28c1fb643e960`),
trajectory `T15`
(`trajectory.2260da6cf42eaaa35daa2297aa2f6751291dcc532a26dacb60a852edac99c3cb`),
state `S15`
(`state.6362a83c6c38c4083b7e282c2c06129d5e2c180c6f75f473b2f79f8cba98f7a5`),
checkpoint `K7`
(`checkpoint.0c5d62d5f78d2c4ebdc7174affd4464f04d1315708e5a87962cded63439818d3`),
and then the reproducibility fix as change `C18`
(`change.59255d208f03996c865d0c2302df8c41c9417b7bd497038240e52867df53e247`) on
trajectory `T18`, with the phase boundary checkpoint `K8`
(`checkpoint.7eb3dba97cbf20f2b34d14cce7e93bc2171ebd0d7ee66d1f7508cc6e199567de`).
Two correction changes follow `C15`, because the closure summary's hand-off count was
wrong twice and Gemel is append-only:
`C16` (`change.f04691608339fed40844e328dfe829fa8df3432416be11dc19e4db6e6076973a`)
and `C17` (`change.a5cad72145bbab24af1d0313ecd88f34830047b49a6481d33d2ba23eb9c73b10`),
which records the exact breakdown — six to Phase 5, seventeen to Phase 6, five to
Phase 7, one to Phase 9, two to Phase 12. Neither correction changed a file; the Git
commit is the authoritative record of the diff.

Projection in `forensics/GEMEL_TRAJECTORY.md`, rendered by
`forensics/tools/render_gemel_trajectory.sh`. The native store is not Git-tracked
(D17); only its `exchange/` namespace and this projection travel in Git.

Six residuals are recorded in the store at this boundary rather than left to be
rediscovered: the two authority faults `RT-CONF` cannot compare, the
`CONF_get1_default_config_file` divergence and its owning phase, the ABI court's
blindness to C prototypes, the fact that 31 exports of this stratum remain
scaffolded until later strata land, and the `RT-BIO-DEBUG` identity change that its
own reproducibility fix caused.

## 10. Correction: the stratum's universe was incomplete (D97)

Appended, not folded in. Everything above stands as the record of what was true when
this document was sealed; this section records what was missing from the premise.

### What was wrong

Like Phase 3's, this ledger chose its universe with `(module, prefixes)` entries and
failed closed *within* them. Five prefixes — `BIO_`, `BUF_`, `CONF_`, `NCONF_`,
`OPENSSL_INIT_` — plus four names. Nineteen exports the global ownership atlas
(`forensics/atlas/symbol-ownership.json`, D72) assigns this stratum matched no entry:

* the **fourteen `COMP_*` functions** of `crypto/comp/comp_lib.c` — `COMP_CTX_new`,
  `_free`, `_get_method`, `_get_type`, `COMP_get_type`, `COMP_get_name`,
  `COMP_compress_block`, `COMP_expand_block`, and the six factories
  `COMP_zlib`, `COMP_zlib_oneshot`, `COMP_zstd`, `COMP_zstd_oneshot`,
  `COMP_brotli`, `COMP_brotli_oneshot`;
* the three **`conf_ssl_*` helpers** of `crypto/conf/conf_ssl.c`, which are
  ABI-only — the DSO exports them and no installed header declares them;
* **`OPENSSL_config`**, `crypto/conf/conf_sap.c`;
* **`OPENSSL_load_builtin_modules`**, `crypto/conf/conf_mall.c`, whose whole body is
  a loop of `CONF_module_add` calls.

`src/runtime/bio/comp.rs` was in this phase's own evidence list the whole time, so
the BIO *compression filter* existed while the `COMP_*` public API it sits beside did
not. The file was evidence; the symbols had no ledger row; nothing compared them.

The atlas reconciliation also showed the ledger **over**-claiming nine rows: the
seven EVP/CMS/PKCS#7 filter names (`BIO_f_base64`, `BIO_f_md`, `BIO_f_cipher`,
`BIO_f_reliable`, `BIO_set_cipher`, `BIO_new_CMS`, `BIO_new_PKCS7`, declared in
`evp.h`, `cms.h` and `pkcs7.h`) plus `BIO_f_asn1` and `BIO_new_NDEF`, which are
declared in `asn1.h`. The old prefix list matched all of them on `BIO_` and deferred
them; the atlas never gave them to this stratum at all.

### What the authority actually does with `COMP_*` in this profile

The fourteen are implementable here with **no compression library**, and that was
measured rather than assumed. The pinned profile's configure options record
`no-zlib no-zstd no-brotli`; `OPENSSL_NO_ZLIB`, `OPENSSL_NO_ZSTD` and
`OPENSSL_NO_BROTLI` are all defined, and `courts/phase4/discover_comp.c` confirms
from the binary that all six factories answer `NULL`:

```
macro OPENSSL_NO_ZLIB=1   macro OPENSSL_NO_ZSTD=1   macro OPENSSL_NO_BROTLI=1
COMP_zlib=(nil)  COMP_zlib_oneshot=(nil)  COMP_zstd=(nil)  COMP_zstd_oneshot=(nil)
COMP_brotli=(nil)  COMP_brotli_oneshot=(nil)
COMP_get_type(NULL)=0 (NID_undef=0)   COMP_get_name(NULL)=<NULL>
COMP_CTX_new(NULL)=(nil)
```

The same probe found an authority **memory fault**: `COMP_CTX_get_type(NULL)`
dereferences `comp->meth` with no NULL check and dies with SIGSEGV. It is recorded in
`docs/SECURITY_DIVERGENCE_POLICY.md` and deliberately not reproduced.

### What was done

The ledger is now a projection of the ownership atlas plus the sixteen symbols Phase 3
hands it. Eighteen of the nineteen are recorded **`open`** and are Phase 6.3's
(`docs/PHASE-6-SUBPHASES.md`); the nineteenth, `OPENSSL_load_builtin_modules`, is
deferred to Phase 6 with its dependency named — the module registry. The four
`BIO_asn1_*` controls stay this stratum's by `bio.h` and stay deferred to Phase 5,
which had already built them, so both ledgers now record that edge and
`ownership_audit.py` checks the two readings against each other.

### What this does not change

Nothing in §2 through §9 is withdrawn. All sixteen courts still pass, all 3,217
observations stand, and every recorded authority fault is unchanged. No implementation
was removed and no evidence was invalidated: this corrects the *completeness* claim,
not the evidence.

### Why it was not caught earlier

The same reason as Phase 3's: the ledger's prefix list, the `PHASE4_MODULES` evidence
list and the ownership atlas are three statements of one scope, and nothing compared
them. `ownership_audit.py` now fails when a stratum the atlas assigns exports has no
ledger row for them, and when a ledger carries a row another stratum does not defer to
it. `docs/DECISIONS.md` D97 has the full account.
