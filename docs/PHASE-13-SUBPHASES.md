# Phase 13 — Legacy / deprecated compatibility, as subphases

## 0. What this stratum is, and what it is not

Phase 13 is the legacy/deprecated-compatibility stratum: the `ENGINE` framework, the `UI` dialog
framework, the `TXT_DB` text database the `ca` app reads, and the deprecated METHOD-era surface
the earlier strata hand it rather than transcribe. Its name in `docs/RELEASE_GATES.md` §1 is
"Legacy / deprecated compatibility", and `forensics/atlas/symbol-ownership.json` gives it every
export declared in `engine.h`, `ui.h` and `txt_db.h`, plus every symbol an earlier stratum's
ledger records as handed here.

It is **not** a header of its own, and §4.1 is why. Phase 13 owns the *deprecated API surface*,
and most of that surface is declared in headers that belong to the strata implementing the
underlying object or algorithm: the METHOD-era `EVP_CIPHER`/`EVP_MD` statics are `evp.h`'s, the
`PEM_read[_bio]_PrivateKey` spellings are `pem.h`'s, the `ASYNC_*` framework is `async.h`'s, and
the two `TS_CONF_*` ENGINE setters are `ts.h`'s. A header is not split between two phases by the
ownership table, so those names arrive here as *recorded hand-offs* rather than as atlas rows.
The atlas gives this stratum only the three headers whose subject matter is itself the legacy
surface. It is **not** the algorithms the legacy statics call: `AES_encrypt`,
`SHA256_Update` and `Camellia_EncryptBlock` are Phase 8's, and the statics reach them as
callers. Nor is it the `EVP` framework the statics register into -- the namemap, the fetch and
the property machinery are Phase 7's -- nor the CLI that consumes TXT_DB and UI, which is
Phase 16's.

**Why this stratum is being planned while Phase 12 has sealed.** `forensics/tools/phase_state.py`'s
`REQUIRES` derives `requires(13) == (12,)`, and Phase 12 is `complete`. As with Phases 11 and 12,
the measurement finds that **127 of this stratum's working set were already `implemented`**
before its first subphase: 123 atlas-owned exports -- most of the `ENGINE_*` object, accessor and
table surface and the whole `UI_*` framework -- that landed as substrate the earlier strata
needed, and the four Phase 7 -> 13 `PEM_read[_bio]_PrivateKey` spellings that Phase 8 landed
(D369). What remains open (250 names) is the ENGINE registry, table, control and dynamic-loading
surface, the `TXT_DB` codec, and the deprecated METHOD-era statics those landings did not cover.
This document is that scope, measured.

## 1. The measurement this plan rests on

Every number below is read from `forensics/atlas/`, not typed, and
`forensics/phase13-obligations.json` is authoritative for the present.

**Phase 13's atlas-owned universe is 189 exports, all `libcrypto`, over three headers.** Reading
`forensics/atlas/symbol-ownership.json` for `owner_phase == 13`:

| header | exports | what it declares |
|---|---|---|
| `engine.h` | 121 | the `ENGINE` object, the registry, the dynamic loader, the per-algorithm method tables (`tb_*`), the control-command surface and the built-in loader |
| `ui.h` | 62 | the `UI` object, the `UI_METHOD` callback table, the prompt constructor and the `UI_UTIL_*` and `UI_OpenSSL` helpers |
| `txt_db.h` | 6 | `TXT_DB`, the two-dimensional text database: read, write, insert, free and the two indexed accessors |

**It also receives 188 hand-offs**, discovered from the other ledgers (`phase*-obligations.json`
rows whose `owning_phase` is 13) rather than listed here:

| from phase | count | header | what it is |
|---|---|---|---|
| 3 | 22 | `async.h` | the `ASYNC_*` job framework the async engines and the SSL async API call |
| 7 | 163 | `evp.h` (148), `pem.h` (15) | the deprecated METHOD-era `EVP_CIPHER`/`EVP_MD` statics and the four `PEM_read[_bio]_PrivateKey` spellings with their `_ex` twins |
| 12 | 3 | `ts.h` (2), `srp.h` (1) | `TS_CONF_set_crypto_device`, `TS_CONF_set_default_engine` (blocked on `ENGINE_by_id`/`ENGINE_set_default`) and `SRP_VBASE_init` (blocked on `TXT_DB_read`/`TXT_DB_free`) |

That is a working set of **377 exports**. **At activation, 127 of them were already implemented**
and `forensics/atlas/implemented-surface.json` is where each is read from. So `open_in_this_stratum`
opened at **250**, not 377. **That split moves as this stratum lands its own units: the ledger's
`counts` is the live record and this section is the activation measurement.** The 123 atlas-owned
landings are 61 of the `ENGINE_*` names and the whole 62-name `UI_*` framework; the other four are
the `PEM_read[_bio]_PrivateKey` spellings Phase 8 landed.

**Open, by declaring header** (`forensics/phase13-obligations.json`'s `open` rows, counted from
their own `declaring_header`):

| header | open |
|---|---|
| `evp.h` | 148 |
| `engine.h` | 60 |
| `async.h` | 22 |
| `pem.h` | 11 |
| `txt_db.h` | 6 |
| `ts.h` | 2 |
| `srp.h` | 1 |

The `evp.h`, `pem.h`, `async.h`, `ts.h` and `srp.h` rows are the hand-offs, declared in another
stratum's header; the `engine.h` 60, `ui.h` 0 and `txt_db.h` 6 are the atlas projection. The
atlas projection's own open subset is 66; the 188 hand-offs account for the remaining 184 open
(4 of the 188 being already implemented).

**The 377 symbols are defined by 52 authority translation units**
(`forensics/atlas/export-defining-units.json`), under `crypto/engine/` (23 units), `crypto/ui/`
(4), `crypto/txt_db/` (1), `crypto/evp/` (21), `crypto/async/` (3) and `crypto/sm3/` (1).
**Forty-two of those units still have open symbols**, and they are the whole of §2's work:
`eng_pkey.c` (9 open), `e_aes.c` (38), `e_aria.c` (27), `e_camellia.c` (21), `e_des3.c` (13),
`async_wait.c` (11), `tb_cipher.c` (8), `async.c` (8), the five `tb_rsa`/`tb_dsa`/`tb_dh`/
`tb_eckey`/`tb_rand` tables (seven each), `pem_pkey.c` (7), `txt_db.c` (6), `e_des.c` (6),
`e_rc2.c` (6), `e_sm4.c` (5), `eng_fat.c` (4), `pem_pk8.c` (4), the four remaining `e_*` units
(four each), `ts_conf.c` (2), `srp_vfy.c` (1) and the narrower remainder.

**Phase 13 publishes no provider registration row, and the census records where the legacy rows went.** The 39
legacy digest and cipher rows (`MD4`, `MDC2`, `WHIRLPOOL`, `RIPEMD-160`, the `CAST5`, `BF`,
`IDEA`, `SEED`, `RC2`, `RC4`, `DES`/`DESX` ciphers, `PBKDF1`, `PVKKDF` and `GENERIC-SECRET`)
that `forensics/atlas/provider-algorithms.json` records for `providers/legacyprov.c` are the
loadable module the candidate ships as a scaffold `ossl-modules/legacy.so`
(`forensics/tools/build_phase2.sh`). This stratum owns the deprecated METHOD-era statics that
reach those algorithms and the `OSSL_provider_init` symbol (D-dependency), but its subphases
deliberately do not activate the legacy provider (§3.6: only the default provider is active), so
`forensics/atlas/provider-algorithm-plans.json` hands the module's rows to the distribution
stratum (Phase 16), which owns the installed `ossl-modules/` contract. The ledger's
`provider_rows_owned` is therefore `0` and `phase_state.py`'s provider-row rule has nothing to hold
against this stratum -- the mirror of Phase 12, whose census slice is empty for the same reason.

## 2. The subphases

| # | Subphase | Owns | Depends on | Courts |
|---|---|---|---|---|
| 13.0 | **The plan and the census** | `docs/PHASE-13-SUBPHASES.md` and the measurement in §1. The ledger (`forensics/phase13-obligations.json`) and its generator land with it. **The runner and the reference-basis probe land with it too, and §4.3 is why they cannot be deferred**: `run_courts.py` refuses a stratum in `in-progress` with no runner and `court_coverage.py` refuses the inherited `implemented` exports until a reference probe covers them, and neither can be satisfied by a later subphase without leaving the pipeline red in between. | 12 | — |
| 13.1 | **The ENGINE object, registry and dynamic loading** | `eng_lib.c` (0 open: the object and refcount already landed), `eng_init.c` (0), `eng_list.c` (1: `ENGINE_by_id`), `eng_all.c` (1: `ENGINE_load_builtin_engines`), `eng_cnf.c` (1). The object lifecycle, the registry walk, the built-in loader and the dynamic (`OPENSSL_ENGINES`) loader. **3 open rows over 5 units.** | 13.0 | `RT-ENGINE` |
| 13.2 | **The ENGINE table and method binding** | `eng_pkey.c` (9), `tb_cipher.c` (8), `tb_pkmeth.c` (1), `tb_digest.c` (0), `tb_asnmth.c` (0), `tb_rand.c` (7), `tb_rsa.c` (7), `tb_dsa.c` (7), `tb_dh.c` (7), `tb_eckey.c` (7). The per-algorithm method tables and the `ENGINE_set_default_*`/`ENGINE_register_*`/`ENGINE_get_*` binding surface. **53 open rows over 10 units.** | 13.1 | `RT-ENGINE-TABLE` |
| 13.3 | **The ENGINE control and command surface** | `eng_ctrl.c` (0), `eng_fat.c` (4). The control-command dispatcher and the `ENGINE_ctrl_cmd*` fat helpers. **4 open rows over 2 units.** | 13.1 | `RT-ENGINE-CTRL` |
| 13.4 | **The UI framework** | `ui_lib.c` (0), `ui_openssl.c` (0), `ui_util.c` (0), `ui_null.c` (0). The `UI` object, the `UI_METHOD` callback table, the prompt constructor and the `UI_UTIL_*` helpers. **0 open rows** — all 62 names landed before activation as substrate the earlier strata needed, so this subphase's act is to *drive* them through `RT-UI`. | 13.0 | `RT-UI` |
| 13.5 | **TXT_DB** | `txt_db.c` (6): `TXT_DB_read`/`TXT_DB_free`/`TXT_DB_write`/`TXT_DB_insert`/`TXT_DB_create_index`/`TXT_DB_get_by_index`. **6 open rows over 1 unit** — the whole of `txt_db.h`. | 13.0 | `RT-TXTDB` |
| 13.6 | **The legacy EVP method statics** | `e_aes.c` (38), `e_aria.c` (27), `e_camellia.c` (21), `e_des3.c` (13), `e_des.c` (6), `e_rc2.c` (6), `e_sm4.c` (5), `e_bf.c`/`e_cast.c`/`e_idea.c`/`e_seed.c` (4 each), `e_chacha20_poly1305.c`/`e_rc4.c`/`e_aes_cbc_hmac_sha1.c`/`e_aes_cbc_hmac_sha256.c` (2 each), `e_rc4_hmac_md5.c`/`e_xcbc_d.c` (1 each), `legacy_md4.c`/`legacy_mdc2.c`/`legacy_wp.c` (1 each), `p_lib.c` (2). The deprecated `EVP_CIPHER`/`EVP_MD` statics whose callbacks call the Phase 8 primitives, handed here by Phase 7. **148 open rows over 21 units** — the largest subphase. | 13.1 | `RT-EVP-LEGACY` |
| 13.7 | **The PEM private-key readers and the ASYNC framework** | `pem_pkey.c` (7), `pem_pk8.c` (4), `async.c` (8), `async_wait.c` (11), `crypto/async/arch/async_posix.c` (3). The `PEM_read[_bio]_PrivateKey` typed readers (four of the eleven already landed) and the `ASYNC_*` job-and-wait framework handed here by Phase 3. **33 open rows over 5 units.** | 13.6 | `RT-LEGACY-REMAINDER` |
| 13.8 | **The received TS_CONF and SRP hand-offs** | `ts_conf.c` (2: `TS_CONF_set_crypto_device`, `TS_CONF_set_default_engine`) and `srp_vfy.c` (1: `SRP_VBASE_init`). The three Phase 12 rows, now that the ENGINE registry (13.1) and TXT_DB (13.5) their bodies reach exist. **3 open rows over 2 units.** | 13.1, 13.5 | `RT-HANDOFF` |
| 13.9 | **The seal** | nothing in the crate — evidence: `docs/PHASE-13-LEGACY-SEAL.md` | 13.0–13.8 | — |

The eight rows above the seal partition the 250 open exports exactly, by defining unit: 3 + 53 +
4 + 0 + 6 + 148 + 33 + 3 = 250 (the activation partition, which moves as subphases land), and the
42 open units each appear in exactly one row. The partition is derived from
`forensics/atlas/export-defining-units.json` joined to the ledger's `open` list, not typed.

**2.1 The order, and the dependency it rests on.** 13.1 before 13.2, 13.3 and 13.6 because the
method tables, the control dispatch and the legacy statics' registration all bind to an `ENGINE`
object the registry hands out, and `ENGINE_by_id` is the entry point all three reach. 13.1 before
13.8 because `TS_CONF_set_default_engine`'s body is `ENGINE_by_id` and `ENGINE_set_default`, both
landed by 13.1 and 13.2. 13.5 before 13.8 because `SRP_VBASE_init`'s body reads and releases a
verifier file through `TXT_DB_read`/`TXT_DB_free`. 13.4 and 13.5 are independent of the ENGINE
chain -- the UI framework and TXT_DB use no `ENGINE` object -- and 13.4 is a subphase whose names
have all landed, so it exists to drive what is already there rather than to transcribe. 13.7 after
13.6 because the PEM private-key readers dispatch into the legacy statics 13.6 lands, and 13.7's
ASYNC framework is independent of both.

**The measurement that ordering rests on is unit-level, and it is honest about what it cannot
settle.** The 52 units' own internal call graph (which open `eng_lib.c` helper each open
`eng_pkey.c` entry needs, and in what order) is measured at each slice, the way D442 and D444
were. A slice that discovers its unit is somewhere else records that rather than forcing the row
(§5).

## 3. What each subphase must honour

**3.1 An ENGINE is an identity and a refcount, and the registry's order is observable.**
`ENGINE_new`/`ENGINE_free`/`ENGINE_up_ref`/`ENGINE_init`/`ENGINE_finish` are a lifecycle, and
`ENGINE_add`/`ENGINE_remove`/`ENGINE_get_first`/`ENGINE_get_next`/`ENGINE_get_prev` walk a list
whose order the authority fixes. The differential court compares the observed `ENGINE_get_id` and
`ENGINE_get_name` after each operation, the refcount's effect on `ENGINE_finish`, and the
`ENGINE_by_id` refusal for an unknown id, all read from the authority's own returns rather than
typed.

**3.2 A method table is a dispatch, and the `ENGINE_set_default_*` arm publishes it.** The `tb_*`
units are the per-algorithm tables an `ENGINE` registers into, so their evidence is the set of
methods the authority's `ENGINE_get_*` return once a fixed in-process `ENGINE` (built with the
authority's own `ENGINE_set_*` setters) has registered and defaulted. The court compares the
selected method's identity, the `ENGINE_get_digest_engine`/`_get_pkey_meth_engine` reverse lookup
and the `ENGINE_unregister_*`/`ENGINE_finish` cleanup, each named by its return.

**3.3 The control surface is a command dispatch with an error coordinate.**
`ENGINE_ctrl`/`ENGINE_ctrl_cmd`/`ENGINE_ctrl_cmd_string` and `eng_fat.c`'s
`ENGINE_cmd_is_executable`/`ENGINE_set_default_*` are a command dispatcher over a `ENGINE_CMD_DEFN`
table. A differential court compares the integer each returns, the string a custom command receives
and the error queue for an unknown command name, because a transcription that accepts a command
the authority refuses is a different library.

**3.4 The UI surface is a callback table, and its evidence is what the callbacks receive.**
`ui_lib.c` and `ui_openssl.c` build a `UI` over a caller-supplied `UI_METHOD`; the observable is
the sequence of `reader`/`writer`/`flusher`/`opener`/`closer` calls and the strings handed to a
fixed in-process method, compared line for line. `UI_process`'s return, `UI_get0_result_string`,
`UI_get_result_length` and the `UI_UTIL_read_pw*` refusal arms are read from the authority rather
than typed. This subphase's names have all landed, so the court's job is to *drive* them, and an
arm that cannot be made observable is named `pending` rather than counted as passing.

**3.5 TXT_DB is a text codec, and its bytes are the contract.** `TXT_DB_read` parses a fixed
database file whose rows and indexes the authority's parser accepts, `TXT_DB_write` re-emits it,
and `TXT_DB_insert`/`TXT_DB_create_index`/`TXT_DB_get_by_index` manipulate the in-memory rows. The
differential court compares the round-tripped bytes and the indexed lookup's result for a fixed
database, plus `TXT_DB_read`'s error coordinate for each malformed line arm, because a codec whose
writer emits bytes its own reader accepts is a different library.

**3.6 The legacy EVP statics are one `EVP_add_*` registration each, and the primitive is the
observable.** `EVP_aes_128_cbc` and its siblings return a method whose `do_cipher`/`update`/`final`
callbacks call the Phase 8 primitives. The court drives each static's method over fixed input and
compares the ciphertext, digest or key-derivation bytes the authority produces, and prints only
invariants where a value is not comparable. The fetched-identity divergence the later CPS/CMS/TS
and OCSP courts already name (a legacy lookup that resolves an `EVP_MD` through
`EVP_get_digestbyname`, whose table is this stratum's) leaves the name-dependent arms `pending`.
A deprecated `EVP_MD` static is handed to `EVP_DigestInit_ex`, which fetches the provider
counterpart by short name; `EVP_sm3` is the default provider's and digests for real, while the
legacy-provider-only `EVP_md4`, `EVP_mdc2` and `EVP_whirlpool` are refused identically on both
sides because only the default provider is activated.

**3.7 The PEM readers and the ASYNC framework are dispatch and a thread contract.**
`PEM_read[_bio]_PrivateKey(*)` are four spellings over the Phase 10 decoder chain, so the court
compares the decoded key's type and public coordinates for a fixed PKCS#8 fixture and the error
coordinate for each malformed arm. The `ASYNC_*` framework's `ASYNC_start_job`/`ASYNC_pause_job`/
`ASYNC_WAIT_CTX_*` are a job-and-wait contract; the observable is the sequence of callbacks and the
`ASYNC_WAIT_CTX` state each transition leaves, and a probe that only reads the `WAIT_CTX` would
measure half of it, so the transition sequence is printed.

**3.8 The received hand-offs are a lookup and a file parse, and their return values are the
contract.** `TS_CONF_set_default_engine`'s answer is `1` for the literal `"builtin"`, and
otherwise the `ENGINE_by_id`/`ENGINE_set_default` result; `TS_CONF_set_crypto_device`'s answer is
`1` when its NULL-or-section-supplied device installs no engine or one the default-engine
installer accepts, and `0` when it refuses. The court drives exactly those arms over a fixed
`CONF` -- a NULL device with no section entry, a NULL device with `crypto_device = builtin`, an
explicit `"builtin"`, and an unknown id -- and pins them to the authority's own integers.
`SRP_VBASE_init`'s answer is one of the `SRP_ERR_*` codes or `SRP_NO_ERROR`, and the observable is
both that code and the state the parse leaves (`vb->default_g`/`default_N`, and the user a
subsequent `SRP_VBASE_get_by_user` finds); the court drives the `I`/`V` records, the seed-key
path and the NULL-file, absent-file, wrong-field-count and undecodable-base64 refusals. It uses
no built-in engine id whose registration diverges and never reads the error queue.

**3.9 Nothing here is a parity claim about the meaning of an ENGINE registration or a prompt.** A
transcription that returns an `ENGINE` the authority also returns has not been shown to behave
like every ENGINE, and §3.4's prompt is only as good as the fixed method the court supplies. The
measured surface is the one above, and a name that cannot be driven is named `pending` rather than
counted as passing — the contract Phase 8's `PENDING_CORRECTNESS_COURTS` and every later
activation established.

## 4. Measured corrections, and the precondition

**4.1 The 188 hand-offs are this stratum's, and the ownership table is the reason.** Phase 13
owns the deprecated API surface, not any header of its own, and the surface is declared in
headers the stratum table assigns to the strata implementing the underlying object or algorithm
(`forensics/tools/ownership_rules.py`, the Phase-13 block). A header is not split between two
phases by that table, so the names arrive as *recorded edges*: Phase 7's `LEGACY_HANDOFFS` hands
163 `evp.h`/`pem.h` names here, Phase 3 hands 22 `async.h` names, and Phase 12 hands 3. The
ledger's `handoffs_discharged` block is the discovery, and `forensics/tools/ownership_audit.py`
reconciles the two sides. The 123 atlas-owned landings are not this stratum's own work either;
they were pulled forward by the earlier strata as substrate, and §1 names the split.

**4.2 This stratum ships no provider row, and the plan says where the legacy rows went.** Reading
`forensics/atlas/provider-algorithms.json` for `owning_phase == 13` yields nothing: the 39 legacy
digest and cipher rows `providers/legacyprov.c` publishes belong to the loadable module the
candidate ships as a scaffold `ossl-modules/legacy.so`, and `provider-algorithm-plans.json` hands
them to the distribution stratum (Phase 16). `phase_state.py`'s provider-row rule and
`provider_court_coverage.py` therefore have nothing to hold against this stratum, and
`forensics/phase13-obligations.json` carries `provider_rows_owned: 0`. A reader who expected the
last export stratum to publish rows would otherwise have to infer the count from the census,
which is why the hand-off is recorded rather than implied. This is the mirror of Phase 12's `0`.

**4.3 The precondition this plan places on 13.0, and it is not optional.** Two fail-closed
joiners refuse this stratum's activation as specified, and both are measured rather than argued:

* `run_courts.py` refuses a stratum that is not `not-started` and has no runner: "phase 13
  (in-progress) is not `not-started` and has no runner". Phase 12 satisfied this by landing
  `forensics/tools/phase12_courts.py` in the same commit; this stratum must land
  `forensics/tools/phase13_courts.py`, whose only runnable court until 13.1 is the reference basis.
* `court_coverage.py` refuses the inherited `implemented` exports: "`N` implemented export(s) of a
  stratum that has begun is in none of directly-courted, indirectly-courted or non-observable".
  **The 127 inherited exports are the number at activation**, and the ledger's landing is what
  moved them into scope, so the commit that lands it also lands a phase-13 reference-basis probe
  that references them by name, registered in `court-coverage-rows.json`'s `reference_probes` as
  `RT-RUNTIME-REF`, `RT-BIO-CONF-REF`, `RT-BN-ASN1-REF`, `RT-PROVIDER-REF`, `RT-EVP-REF`,
  `RT-KEYFORMAT-REF`, `RT-X509-REF` and `RT-PHASE12-REF` are for theirs. The probe references; it
  does not call, and the atlas records every name covered only by it at basis `referenced`, never
  `called`.

So the activation order is: the ledger, the plan, the runner and the reference probe land
**together**, or `forensics/tools/pipeline.sh` fails at `run_courts.py` and `court_coverage.py` and
the tree carries an activation whose two evidence joiners refuse it. This document states the
precondition; the runner is `forensics/tools/phase13_courts.py` and the probe is
`courts/phase13/rt_coverage_ref_probe.c`, and both are `courts/`-side work rather than this plan's
files.

**4.4 "Legacy / deprecated compatibility" here is the ENGINE, UI and TXT_DB surface and the
deprecated statics over it, not the algorithms or the CLI.** The `AES_encrypt` the legacy statics
call is Phase 8's, the `EVP_MD` the fetched lookup resolves is Phase 7's, and the `openssl ca`
command that reads a `TXT_DB` and prompts through a `UI` is Phase 16's. Measured,
`forensics/atlas/symbol-ownership.json` assigns the whole of `engine.h`, `ui.h` and `txt_db.h` to
phase 13 and every one of the 148 `evp.h` hand-off names is still `evp.h`'s in the atlas, so the
two readings are reconciled by the recorded edges rather than by widening the table.

## 5. Process

This stratum inherits Phases 8 through 12's process unchanged: a subphase lands its code, its court
and its regenerated artefacts in **one commit**; every export carries a court edge in
`forensics/atlas/court-coverage.json` on the commit that lands it (D236) — **and §4.3 is the
measurement of what that rule means for a stratum whose exports were landed by an earlier one**;
every provider row it publishes is named by a probe of a court that covers it (D245); and an
artefact that a source change moves is regenerated in the same commit. `docs/DECISIONS.md` is
append-only and this document is not a decision record.

**This plan's own boundaries are the census's, and the census will correct them.** The subphase
table above was written from the defining units in `forensics/atlas/export-defining-units.json` and
the 250-row measurement in §1. D283's equivalent table for Phase 8 was corrected twice by
measurement — by D285, which found most of a slice was another stratum's, and by D287, which found a
prerequisite the slice's name could not show — and Phases 10, 11 and 12 were each corrected inside
their own activation. The same is expected here and is not a defect in this document: the census is
the authority, and a subphase that discovers its unit is somewhere else records that rather than
forcing the row.

**Landed exports (checked against the ledger):**

Subphase 13.1 landed this stratum's own first slice: `ENGINE_by_id` (`eng_list.rs`),
`ENGINE_load_builtin_engines` (`eng_all.rs`) and `ENGINE_add_conf_module` (`eng_cnf.rs`), over the
ENGINE registry core. Before that slice every name below was a *pre-activation* landing that the
ledger's implemented list already carried, and the ledger is the record. The ENGINE object
and accessor surface was already in: `ENGINE_new`, `ENGINE_free`, `ENGINE_up_ref`, `ENGINE_init`,
`ENGINE_finish`, `ENGINE_add`, `ENGINE_remove`, `ENGINE_get_first`, `ENGINE_get_next`,
`ENGINE_get_prev`, `ENGINE_get_id`, `ENGINE_get_name`, `ENGINE_set_id`, `ENGINE_set_name`,
`ENGINE_ctrl`, `ENGINE_ctrl_cmd`, `ENGINE_ctrl_cmd_string`, `ENGINE_set_flags` and
`ENGINE_get_flags`. The whole `UI_*` framework was already in: `UI_new`, `UI_new_method`, `UI_free`,
`UI_process`, `UI_ctrl`, `UI_method_set_reader`, `UI_method_get_reader`, `UI_UTIL_read_pw` and
`UI_OpenSSL`. The four Phase 7 -> 13 spellings `PEM_read_PrivateKey`, `PEM_read_PrivateKey_ex`,
`PEM_read_bio_PrivateKey` and `PEM_read_bio_PrivateKey_ex` landed with Phase 8 (D369). The bulk of
that list was landed before this stratum's first slice as substrate the earlier strata needed; the
ledger is the record and this sentence names only what those landings left here. Subphase 13.3
later landed the control fat helpers `ENGINE_set_default`, `ENGINE_set_default_string`,
`ENGINE_register_complete` and `ENGINE_register_all_complete`. Subphase 13.5 later landed the
whole of `txt_db.h` -- `TXT_DB_read`, `TXT_DB_write`, `TXT_DB_insert`, `TXT_DB_create_index`,
`TXT_DB_get_by_index` and `TXT_DB_free` (`src/txt_db/txt_db.rs`).

Subphase 13.2 landed the ENGINE table and method-binding surface. The cipher table
(`src/engine/tb_cipher.rs`) contributes `ENGINE_set_ciphers`, `ENGINE_get_ciphers`,
`ENGINE_register_ciphers`, `ENGINE_register_all_ciphers`, `ENGINE_set_default_ciphers`,
`ENGINE_unregister_ciphers`, `ENGINE_get_cipher` and `ENGINE_get_cipher_engine`; `tb_pkmeth.rs`
contributes `ENGINE_get_pkey_meth`; the four legacy method tables and RAND contribute
`ENGINE_set_RSA`/`_DSA`/`_DH`/`_EC`/`_RAND`, the `ENGINE_get_RSA`/`_DSA`/`_DH`/`_EC`/`_RAND`
getters, the `ENGINE_register_*`/`ENGINE_register_all_*`/`ENGINE_set_default_*`/`ENGINE_unregister_*`
set and `ENGINE_get_default_RSA`/`_DSA`/`_DH`/`_EC`/`_RAND` (`src/engine/tb_rsa.rs`,
`tb_dsa.rs`, `tb_dh.rs`, `tb_eckey.rs` and `tb_rand.rs`); and `src/engine/eng_pkey.rs` contributes
the three `ENGINE_set_load_*_function`/`ENGINE_get_load_*_function` pairs and
`ENGINE_load_private_key`, `ENGINE_load_public_key` and `ENGINE_load_ssl_client_cert`. Those, with
the three names 13.1 landed, are the ledger's `implemented` additions.

Subphase 13.3 landed the control and command surface. `src/engine/eng_fat.rs` contributes the four
fat helpers: `ENGINE_set_default` and `ENGINE_set_default_string` (the `ENGINE_METHOD_*` mask
dispatch and its string spelling) and `ENGINE_register_complete`/`ENGINE_register_all_complete`
(the nine-arm bulk registration and its registry walk), all binding into the 13.2 tables.
`src/engine/eng_ctrl.rs`'s dispatcher (`ENGINE_ctrl`, `ENGINE_ctrl_cmd`,
`ENGINE_ctrl_cmd_string` and `ENGINE_cmd_is_executable`) was already in as pre-activation
substrate. The `ENGINE_set_default_string` forward declaration `eng_cnf.rs` carried is dropped
with this landing.

Subphase 13.5 landed the `TXT_DB` codec. `src/txt_db/txt_db.rs` contributes all six
`txt_db.h` exports — `TXT_DB_read` (`crypto/txt_db/txt_db.c:20-125`) and its inverse
`TXT_DB_write` (`:187-232`), `TXT_DB_insert` (`:234-277`), `TXT_DB_create_index` (`:147-185`)
and `TXT_DB_get_by_index` (`:127-145`) over the `LHASH_OF(OPENSSL_STRING)` indexes they drive,
and `TXT_DB_free` (`:279-314`) — and its court is `RT-TXTDB`. The module records that
`SRP_VBASE_init`'s blocker (its `TXT_DB_read`/`TXT_DB_free` dependency, §1's Phase 12 -> 13
hand-off) is now removable; the row itself is 13.8's and is not landed here.

Subphase 13.6a landed the AES slice of the legacy EVP method statics. `src/evp/e_aes.rs`
contributes the thirty-eight `EVP_aes_*` accessors of `crypto/evp/e_aes.c` -- the generic pack
(`cbc`/`ecb`/`ofb`/`cfb128`/`cfb1`/`cfb8`/`ctr`) for 128/192/256, GCM and CCM for 128/192/256, XTS
and OCB for 128/256, and wrap/wrap-pad for 128/192/256 -- as the deprecated `EVP_CIPHER` statics
whose callbacks call the Phase-8 primitives, and `src/evp/e_aes_cbc_hmac_sha1.rs` and
`_sha256.rs` contribute the four `EVP_aes_*_cbc_hmac_sha*` stitched statics, whose callbacks reuse
the provider construction (`src/provider/cipher.rs`, D274/D276) rather than keep a second
transcription. Its court is `RT-EVP-LEGACY`. The fetched-identity divergence the later courts name
leaves the `EVP_get_cipherbyname` arm `pending.` -- the legacy `OBJ_NAME` cipher table the
authority fills at `OPENSSL_init_crypto` is empty in this crate -- while the accessors, the object
sizes and the round trips are compared. The remaining legacy statics (`e_des3.c`, `e_des.c`,
`e_rc2.c`, `e_sm4.c`, the four remaining `e_*` units, `e_chacha20_poly1305.c`,
`e_rc4.c`, `e_rc4_hmac_md5.c`, `e_xcbc_d.c`, `legacy_md4.c`, `legacy_mdc2.c`, `legacy_wp.c` and
`p_lib.c`) stay 13.6's own work.

Subphase 13.6b landed the ARIA and Camellia slices of the same statics. `src/evp/e_aria.rs`
contributes the twenty-seven `EVP_aria_*` accessors of `crypto/evp/e_aria.c` -- the generic block
pack (`cbc`/`ecb`/`ofb`/`cfb128`/`cfb1`/`cfb8`) and CTR for 128/192/256, plus GCM and CCM for
128/192/256 -- and `src/evp/e_camellia.rs` contributes the twenty-one `EVP_camellia_*` accessors of
`crypto/evp/e_camellia.c` (the same seven generic modes per key length), as the deprecated
`EVP_CIPHER` statics whose callbacks call the Phase-8 `ossl_aria_*`/`Camellia_*` primitives. The
same `RT-EVP-LEGACY` court drives them beside the AES statics, with the same fetched-identity
`pending.` arm.

Subphase 13.6c landed the remaining fifty-two legacy EVP cipher statics: the six `EVP_des_*` of
`crypto/evp/e_des.c`, the thirteen `EVP_des_ede*` of `crypto/evp/e_des3.c` (including
`EVP_des_ede3_wrap`), the six `EVP_rc2_*` of `crypto/evp/e_rc2.c`, the five `EVP_sm4_*` of
`crypto/evp/e_sm4.c`, the four `EVP_bf_*`/`EVP_cast5_*`/`EVP_idea_*`/`EVP_seed_*` of their units,
the two `EVP_rc4*` of `crypto/evp/e_rc4.c`, the two `EVP_chacha20*` of
`crypto/evp/e_chacha20_poly1305.c`, `EVP_rc4_hmac_md5` and `EVP_desx_cbc`. `RT-EVP-LEGACY` drives
them beside the earlier slices. The former legacy-provider-only families (single DES, DESX,
Blowfish, CAST5, IDEA, SEED, RC2, RC4 and RC4-HMAC-MD5) are fetched by short name and refused
identically on both sides -- the default provider does not publish them and only it is activated --
so their round-trip arm reports `rt=0` with an empty ciphertext on both transcripts while their
fields are still compared; `EVP_des_ede3_wrap` draws a random IV, so its round-trip value is
`pending.` with that reason. The `EVP_MD` statics (`legacy_md4.c`, `legacy_mdc2.c`,
`legacy_wp.c`, `legacy_sm3.c`) and `p_lib.c` stay 13.6's own work.

Subphase 13.6d closed 13.6 with the last four deprecated `EVP_MD` statics and the `p_lib.c`
remainder. `src/evp/legacy_md4.rs`, `src/evp/legacy_mdc2.rs` and `src/evp/legacy_wp.rs` contribute
`EVP_md4` (`crypto/evp/legacy_md4.c`), `EVP_mdc2` (`crypto/evp/legacy_mdc2.c`) and `EVP_whirlpool`
(`crypto/evp/legacy_wp.c`), and `src/sm3/legacy_sm3.rs` contributes `EVP_sm3`
(`crypto/sm3/legacy_sm3.c`), each the deprecated `EVP_MD` static whose callback triple calls the
Phase-8 primitive (`MD4_Init`/`_Update`/`_Final`, `MDC2_*`, `WHIRLPOOL_*` and `ossl_sm3_*`) under
the authority's `IMPLEMENT_LEGACY_EVP_MD_METH`/`_LC` macros. `src/evp/p_lib.rs` contributes the two
`#ifndef OPENSSL_NO_ENGINE` names of `crypto/evp/p_lib.c`, `EVP_PKEY_set1_engine` and
`EVP_PKEY_get0_engine`, over the 13.1 engine framework. `RT-EVP-LEGACY` drives them beside the
cipher statics: each digest's `md_size`, `block_size`, `type` and `flags` and a fixed-input digest
are compared, `EVP_sm3` round-tripping through the default provider while the three
legacy-provider-only digests (`EVP_md4`, `EVP_mdc2`, `EVP_whirlpool`) are refused identically on
both sides, and the `p_lib.c` pair is driven over a fresh `EVP_PKEY` and the NULL engine this link
can hold.

Subphase 13.4 drove the UI framework rather than landing code: all 62 names -- the UI object
(`ui_lib.rs`), the built-in console method (`ui_openssl.rs`), the `UI_UTIL_*` helpers
(`ui_util.rs`) and the null method (`ui_null.rs`) -- had already landed as substrate the earlier
strata needed, so the subphase's act was `RT-UI`. `courts/phase13/rt_ui_probe.c` calls every one
of them over a deterministic in-process method so no terminal is opened: the object lifecycle and
method identity, the method setter/getter pairs and their NULL arms, the string-add and
`UI_dup_*` surface and its refusals, `UI_process`'s five phases over every string type, the result
and prompt-construction accessors, the ex-data accessors, `UI_UTIL_read_pw` and
`UI_UTIL_read_pw_string` and the PEM wrapper, and the null method's cancel. The court coverage
atlas therefore records those 62 names at basis called rather than the referenced the activation
probe left them at, and no name the ledger holds implemented is left referenced only by the
reference basis.

Subphase 13.7 closed the stratum's PEM private-key remainder and landed the ASYNC job-and-wait
framework. `src/pem/pem_pkey.rs` gained the five write spellings -- `PEM_write_bio_PrivateKey[_ex]`
and `PEM_write_PrivateKey[_ex]` with the `PEM_write_cb_*_fnsig` bodies, and
`PEM_write_bio_Parameters` -- and the two `PEM_read_bio_Parameters*` readers;
`src/pem/pem_pk8.rs` gained the four `PEM_write[_bio]_PKCS8PrivateKey[_nid]` wrappers their
`legacy:` fall-through reaches. The ASYNC framework landed whole, in the authority's own directory
layout: `src/async/async.rs` (8 exports), `src/async/async_wait.rs` (11) and
`src/async/arch/async_posix.rs` (3), with the platform's `ucontext_t` fibre primitives kept on the C
side of the ABI (`src/async/arch/async_ucontext.c`, the `src/runtime/dir_posix.c` pattern for a
platform struct). Because every `ASYNC_*` entry point reaches
`OPENSSL_init_crypto(OPENSSL_INIT_ASYNC)`, that bit left `INIT_UNSUPPORTED` in `src/runtime/init.rs`
and its step landed at the authority's position (`crypto/init.c:647`), with `async_deinit` in
`OPENSSL_cleanup`. Its court is `RT-LEGACY-REMAINDER`. The two `PEM_read_bio_Parameters*` readers
answer NULL where the authority answers a key for a written `DH PARAMETERS` block -- the
decoder-absence divergence `D-DECODER-ABSENT-1` already names -- so the court drives them over an
empty BIO and leaves the divergent arm undriven rather than compared.

Subphase 13.8 landed the three received hand-offs, the last open rows. `src/ts/ts_conf.rs` gained
`TS_CONF_set_crypto_device` and `TS_CONF_set_default_engine` (`crypto/ts/ts_conf.c`), the
`#ifndef OPENSSL_NO_ENGINE` pair 12.5 withheld: the device reader delegates to the default-engine
installer, whose body is `ENGINE_by_id` (`:188`) and `ENGINE_set_default(e, ENGINE_METHOD_ALL)`
(`:192`), landed by 13.1 and 13.2. `src/srp/srp_vfy.rs` gained `SRP_VBASE_init`
(`crypto/srp/srp_vfy.c:394-510`), the entry point 12.8 withheld on the `TXT_DB_read`/
`TXT_DB_free` that 13.5 landed; its five private helpers lost the item-level
`#[allow(dead_code)]` markers whose note named that withheld caller, since the caller now exists.
Its court is `RT-HANDOFF`. Because the three are Phase 13's by hand-off rather than by the atlas,
landing them leaves Phase 12's hand-off edges **retargeted** rather than retired, the move
`phase7_obligations.py`'s `ENGINE_get_pkey_meth` row made in 13.2: the two `BLOCKED_HANDOFFS` rows
of `forensics/tools/phase12_obligations.py` moved to its new `UNBLOCKED_HANDOFFS` table, so
`forensics/phase12-obligations.json` still records them as handed to Phase 13 and
`forensics/tools/ownership_audit.py` reconciles the two ledgers in both directions.

**Open exports (checked against the ledger):**

None. Subphase 13.8 landed the last three Phase 12 hand-offs, so this stratum's obligation ledger
reports an open count of zero and complete, and every name it holds is implemented and courted,
directly or by hand-off. Section 2's partition open counts are the activation measurement; the
ledger counts is the live record and it now has no open row.
