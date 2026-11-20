# E7 closed-set / unreachability batch — checkpoint notes

Branch `staging`, HEAD `377e66a85` (tree clean at start). No commit/push.
`src/`, `Cargo.toml`, `Cargo.lock` untouched. Tool under change:
`forensics/tools/consumer_closure.py`.

Scope: the 21-mode + 7-wrap "modes" family (21 sites) and the
engine/http/store/p12 local-copy family (15 sites) of the 65-site element-7
queue.  Court `openssl-rs-court` (16 GiB) reused, not recreated;
`OPENSSL_RS_COURT_DATA=12582912`; no full closure run.

(Entries appended per family below; this header is written first so a
transport failure cannot lose the index.)

## Family 1 — modes (21 sites: 14 exported-name copies + 7 wrap)

**Proof shape.** None of the 21 is a contract.  `nm -D libssl.so.3` defines
none of the six `CRYPTO_*128_encrypt` names nor `CRYPTO_128_wrap_pad`; the
static table gives them as local `t` symbols.  Their callback argument is
supplied only by in-image call sites, of which the image has three reference
forms: direct `call <fn>`, `call/jmp *<GOT slot>` whose slot is an
`R_X86_64_RELATIVE` relocation to the same copy, and `lea <fn>` + a single
indirect call on that register in the same function.  For each pinned site the
operand is the function's own parameter (verified 7/6/5/7/7/7 by the
`_param_of_operand`/`_param_chain` walk, including the frame-spill and
phi forms).

- **0x1232d6 `CRYPTO_128_wrap_pad` — BOUND, 1 target.** One GOT call site
  (`0x334e10`, `aes_wrap_cipher`) passes `lea aes_encrypt_block`; the target
  set is `{0x335cd0}`.
- **6 `wrap128` sites — REFUSED** `caller-value-escapes-into-an-object-field`.
  Four direct callers; two forward their parameter, of which
  `CRYPTO_128_wrap_pad` closes (one caller) and `CRYPTO_128_wrap` does not:
  its address is `lea`'d into a heap cipher context (`aes_wrap_init`, importer
  0x1ff071) and dispatched through a context field, so the dispatch site is not
  a call to the function.  `CRYPTO_128_wrap_pad`'s own lea (0x1ff062) escapes
  the same way but the site itself is reached from `aes_wrap_cipher`.
- **14 exported-name copies — REFUSED** `caller-supplies-an-object-field`.
  Every site is reached from in-image wrappers.  Some pass a link-time block
  function (`cipher_hw_seed_cfb128_cipher` passes `seed_block_encrypt`), but at
  least one passes the cipher context's `block` field
  (`ossl_cipher_hw_chunked_cfb128`: `mov 0x30(%r12),%r10` -> 8th argument;
  `ossl_cipher_hw_generic_ctr`, `aes_ctr_cipher`, `camellia_cfb1_cipher`, ...
  likewise).  The field's writer set is the provider cipher hw-table mechanism
  (S5), not a call-site value set; composing the two is not done here, so the
  set is **not closed by the call sites** and the site stays refused rather
  than claiming a union of fixed block functions.

**Controls.** `E7LCP_MUTATIONS`: `export-function` (refuses as
`local-not-private`), `address-taken`, `no-null-guard`, `new-target` (adds a
function start to the reported set), `open-caller` (refuses
`caller-set-not-closed`), `forwarded-open` (a forwarding caller's set is
opened).  Self-test status: **NOT RUN YET** (recorded again below).

## Family 2 — engine / http / store / p12 (14 sites, not 15)

The triage holds **14** sites for these four files (engine 4, http 4, store 3,
p12 3); the assigned "15" does not exist in `element7-curl-049-triage.json`
for these files and is recorded here rather than smoothed.

**Proof shape.** engine + store: *proved-empty slot with an exported-entry-
point account*.  Each pinned operand is a NULL-guarded load of a field whose
source writer set is exactly {zeroing constructor, clearer(s) writing `None`,
copier(s) propagating `(*src).field`, one installer storing its own
parameter}.  The installer is a local `t` function with **no** reference of
any kind in this image (no direct caller, no GOT slot, no code materialisation,
no dlsym literal, no admitted import, no production source caller), and the
module exports none of the type's constructors/registry/setters.

| site | field | installer | result |
|---|---|---|---|
| 0x42c297/0x42c2d8/0x42c3fa/0x42c43b | `Engine.ciphers`/`digests`/`pkey_meths`/`pkey_asn1_meths` at 0x38/0x40/0x48/0x50 | `ENGINE_set_ciphers`/`_digests`/`_pkey_meths`/`_pkey_asn1_meths` | BOUND (empty) |
| 0x329358/0x32944d/0x3298c3 | `OsslStoreLoader.open_ex`/`open`/`closefn` at 0x58/0x10/0x50 | `OSSL_STORE_LOADER_set_open_ex`/`_set_open`/`_set_close` | BOUND (empty) |
| 0x268526/0x268b2c | `PKCS12_create_ex2` parameter 12 (`cb`) | callers pass zeroed `%xmm0`/`%xmm1` | BOUND (empty) |
| 0x2686e8 | same, but the call is `call *0x110(%rsp)` | - | REFUSED `slot-not-null-guarded` (frame-slot operand) |
| 0x325d8d/0x325ec5/0x325fbe/0x3261d8 | `OsslHttpReqCtx.upd_fn` at 0x28 | `http_req_ctx_new` | REFUSED `installer-has-a-source-caller` (http_client.rs:2362, production) |

**Controls.** `E7LEW_MUTATIONS`: `installer-reachable`, `installer-addressed`,
`second-writer` (a foreign source writer), `wrong-offset`, `no-guard`,
`entry-point-exported`.  Self-test status: **NOT RUN YET**.

## Targeted re-resolution (this candidate)

libssl `DsoGraph` + `PrecisionResolver`, the 35 sites seeded and
`apply_evidence_classes` run with curl's 227 admitted imports.  **10 resolved,
25 refused**; every refusal is a named reason, none is PREMISE_UNAVAILABLE.
Full closure: **NOT_RUN**.  Self-test: **NOT RUN YET** — see below.

### FINAL (supersedes the line above)

A soundness gap was found and closed before the final run: a function whose
address is materialised (`lea`) but **not** consumed by a call in the same
function, or whose relocation slot nothing calls through, has an indirect
dispatch the scan cannot see.  `_e7lcp_callers` now returns those as
*escapes* and refuses.  Under the corrected rule the earlier
`CRYPTO_128_wrap_pad` result is **withdrawn** (the same copy's address is
`lea`'d into a cipher context at `aes_wrap_init` 0x1ff062), which is the
intended sensitivity: the set was not closed by the call sites.

| family | sites | bound | refused |
|---|---|---|---|
| modes (14 exported-name copies) | 14 | 0 | 14 × `caller-supplies-an-object-field` |
| modes (`wrap128` + `CRYPTO_128_wrap_pad`) | 7 | 0 | 7 × `caller-value-escapes-into-an-object-field` |
| engine `ENGINE_register_all_complete` | 4 | 4 (empty) | 0 |
| store `OSSL_STORE_open_ex` | 3 | 3 (empty) | 0 |
| p12 `PKCS12_create_ex2` | 3 | 2 (empty) | 1 × `slot-not-null-guarded` (frame-slot operand 0x2686e8) |
| http `OSSL_HTTP_get`/`_open` | 4 | 0 | 4 × `installer-has-a-source-caller` |
| **total** | **35** | **9** | **26** |

Artifacts: `court/tmp/closedset/{probe_shapes,probe_reach,probe_callers,
probe_refs,probe_dbg,reresolve}.py`, `reresolve.json`, `reresolve.log`,
`selftest.log`, `RECEIPT.json`.

### Self-test (final)

`python3 forensics/tools/consumer_closure.py --self-test` → **rc=0**,
`self-test ok`, no `FAIL` line, no PREMISE_UNAVAILABLE added.  New matrices:

- `E7LCP mutation matrix`: export-function, address-taken, no-null-guard,
  open-caller, forwarded-open, new-target — all six load-bearing; each
  restores the positive witness exactly.
- `E7LEW mutation matrix`: installer-reachable, installer-addressed,
  second-writer, wrong-offset, no-guard, entry-point-exported — all six
  load-bearing; each restores exactly.
- Fixture refusals (each a separate fixture, not a switch): a stored-away
  `lea`, an escaping forwarding caller, an exported copy, an unguarded Option
  parameter; for E7LEW: an address-taken installer, a foreign field writer, a
  wrong installer store offset, an exported registry constructor, an
  unguarded slot.

### Residuals (plainly)

1. The modes-14 refusal is a *composition* gap, not an absence of a proof
   idea: the cipher context's `block` field writer set is the provider hw-table
   (S5) mechanism.  Composing call-site enumeration with S5 was not attempted
   and would be a new boundary needing its own control.
2. E7-LEW's empty set is an in-image and admitted-closure claim.  An object
   constructed by another DSO and handed to this dispatcher would need an
   exported constructor/registry entry point; this DSO exports none of the
   listed ones, but that is the boundary of the claim.
3. `Engine.pkey_meths`/`pkey_asn1_meths` have no clearer and (asn1) no copier in
   the crate; the construction-time NULL rests on `RawEngine::new`'s
   `CRYPTO_zalloc`, which the witness binds textually, not on a type-level
   validity proof.
4. The p12 callback is an `Option`: the two resolved sites are empty because
   all three in-image callers pass zeroed `%xmm` stores; the third site is
   refused only because its operand is a frame slot.
5. No closure was run and no consumer graduates: element 7 remains FAIL.
