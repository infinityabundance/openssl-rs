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

**Phase 13 owns 39 provider registration rows**, and that is a measurement rather than an
omission: `forensics/atlas/provider-algorithms.json` records the 39 legacy digest and cipher rows
(`MD4`, `MDC2`, `WHIRLPOOL`, `RIPEMD-160`, the `CAST5`, `BF`, `IDEA`, `SEED`, `RC2`, `RC4`,
`DES`/`DESX` ciphers, `PBKDF1`, `PVKKDF` and `GENERIC-SECRET`) with `owning_phase == 13`, and all
39 are `unimplemented` at activation, so `forensics/phase13-obligations.json`'s
`provider_rows_owned` is `39` and `phase_state.py`'s provider-row rule holds the stratum open on
them. This is the opposite of Phase 12, whose census slice is empty.

## 2. The subphases

| # | Subphase | Owns | Depends on | Courts |
|---|---|---|---|---|
| 13.0 | **The plan and the census** | `docs/PHASE-13-SUBPHASES.md` and the measurement in §1. The ledger (`forensics/phase13-obligations.json`) and its generator land with it. **The runner and the reference-basis probe land with it too, and §4.3 is why they cannot be deferred**: `run_courts.py` refuses a stratum in `in-progress` with no runner and `court_coverage.py` refuses the inherited `implemented` exports until a reference probe covers them, and neither can be satisfied by a later subphase without leaving the pipeline red in between. | 12 | — |
| 13.1 | **The ENGINE object, registry and dynamic loading** | `eng_lib.c` (0 open: the object and refcount already landed), `eng_init.c` (0), `eng_list.c` (1: `ENGINE_by_id`), `eng_all.c` (1: `ENGINE_load_builtin_engines`), `eng_cnf.c` (1). The object lifecycle, the registry walk, the built-in loader and the dynamic (`OPENSSL_ENGINES`) loader. **3 open rows over 5 units.** | 13.0 | `RT-ENGINE` |
| 13.2 | **The ENGINE table and method binding** | `eng_pkey.c` (9), `tb_cipher.c` (8), `tb_pkmeth.c` (1), `tb_digest.c` (0), `tb_asnmth.c` (0), `tb_rand.c` (7), `tb_rsa.c` (7), `tb_dsa.c` (7), `tb_dh.c` (7), `tb_eckey.c` (7). The per-algorithm method tables and the `ENGINE_set_default_*`/`ENGINE_register_*`/`ENGINE_get_*` binding surface. **53 open rows over 10 units.** | 13.1 | `RT-ENGINE-TABLE` |
| 13.3 | **The ENGINE control and command surface** | `eng_ctrl.c` (0), `eng_fat.c` (4). The control-command dispatcher and the `ENGINE_ctrl_cmd*` fat helpers. **4 open rows over 2 units.** | 13.1 | `RT-ENGINE-CTRL` |
| 13.4 | **The UI framework** | `ui_lib.c` (0), `ui_openssl.c` (0), `ui_util.c` (0), `ui_null.c` (0). The `UI` object, the `UI_METHOD` callback table, the prompt constructor and the `UI_UTIL_*` helpers. **0 open rows** — all 62 names landed before activation as substrate the earlier strata needed, so this subphase's first act is to *drive* them. | 13.0 | `RT-UI` |
| 13.5 | **TXT_DB** | `txt_db.c` (6): `TXT_DB_read`/`TXT_DB_free`/`TXT_DB_write`/`TXT_DB_insert`/`TXT_DB_create_index`/`TXT_DB_get_by_index`. **6 open rows over 1 unit** — the whole of `txt_db.h`. | 13.0 | `RT-TXTDB` |
| 13.6 | **The legacy EVP method statics** | `e_aes.c` (38), `e_aria.c` (27), `e_camellia.c` (21), `e_des3.c` (13), `e_des.c` (6), `e_rc2.c` (6), `e_sm4.c` (5), `e_bf.c`/`e_cast.c`/`e_idea.c`/`e_seed.c` (4 each), `e_chacha20_poly1305.c`/`e_rc4.c`/`e_aes_cbc_hmac_sha1.c`/`e_aes_cbc_hmac_sha256.c` (2 each), `e_rc4_hmac_md5.c`/`e_xcbc_d.c` (1 each), `legacy_md4.c`/`legacy_mdc2.c`/`legacy_wp.c` (1 each), `p_lib.c` (2). The deprecated `EVP_CIPHER`/`EVP_MD` statics whose callbacks call the Phase 8 primitives, handed here by Phase 7. **148 open rows over 21 units** — the largest subphase. | 13.1 | `RT-EVP-LEGACY` |
| 13.7 | **The PEM private-key readers and the ASYNC framework** | `pem_pkey.c` (7), `pem_pk8.c` (4), `async.c` (8), `async_wait.c` (11), `arch/async_posix.c` (3). The `PEM_read[_bio]_PrivateKey` typed readers (four of the eleven already landed) and the `ASYNC_*` job-and-wait framework handed here by Phase 3. **33 open rows over 5 units.** | 13.6 | `RT-LEGACY-REMAINDER` |
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

**3.7 The PEM readers and the ASYNC framework are dispatch and a thread contract.**
`PEM_read[_bio]_PrivateKey(*)` are four spellings over the Phase 10 decoder chain, so the court
compares the decoded key's type and public coordinates for a fixed PKCS#8 fixture and the error
coordinate for each malformed arm. The `ASYNC_*` framework's `ASYNC_start_job`/`ASYNC_pause_job`/
`ASYNC_WAIT_CTX_*` are a job-and-wait contract; the observable is the sequence of callbacks and the
`ASYNC_WAIT_CTX` state each transition leaves, and a probe that only reads the `WAIT_CTX` would
measure half of it, so the transition sequence is printed.

**3.8 Nothing here is a parity claim about the meaning of an ENGINE registration or a prompt.** A
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

**4.2 This stratum owns provider rows, and the ledger says so rather than leaving it implied.**
Reading `forensics/atlas/provider-algorithms.json` for `owning_phase == 13` yields the 39 legacy
digest and cipher rows, all `unimplemented` at activation, so `phase_state.py`'s provider-row rule
and `provider_court_coverage.py` both hold the stratum open on them, and
`forensics/phase13-obligations.json` carries `provider_rows_owned: 39`. A reader who expected the
last export stratum to publish no rows would otherwise have to infer the count from the census.
This is the mirror of Phase 12's `0`.

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
ledger is the record and this sentence names only what those landings left here.

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

**Open exports (checked against the ledger):**

The open set is the ENGINE control surface, the TXT_DB
codec and the deprecated statics over them. Representative names are
`ENGINE_set_default`, `TXT_DB_read`, `TXT_DB_free`, `TXT_DB_write`,
`TXT_DB_insert`, `TXT_DB_create_index`, `TXT_DB_get_by_index`, `ASYNC_WAIT_CTX_new`,
`EVP_aes_128_cbc`, `PEM_write_bio_PrivateKey`, `TS_CONF_set_crypto_device`,
`TS_CONF_set_default_engine` and `SRP_VBASE_init`. Every one is open rather than implemented, and
each is assigned to a subphase by §2's partition.
