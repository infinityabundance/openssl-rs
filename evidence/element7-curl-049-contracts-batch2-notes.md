# E7 provider-entry / parent-up-ref batch — checkpoint notes

Branch `staging`, HEAD `50ac592e2` (tree clean at start). No commit/push.
`src/` untouched. Tool changed: `forensics/tools/consumer_closure.py`
(+598 / -1). Candidate: libcrypto `fd25cc9e6424ea79...`, libssl
`648f8caecda245d2...` (hashes confirmed from
`artifacts/phase2/install/lib`).

## Method and its limits

- Read the four receipts: `s1-got-slot`, `closed-method-tables`,
  `dso-and-method-table-contracts`, `proved-empty-gate`.
- Built the two `DsoGraph`s and `PrecisionResolver(g)` only (no `run()`,
  no closure). Re-ran the real `apply_evidence_classes` over exactly the
  triage's 82 `a_external_abi_contract` rows with curl's 227 admitted
  imports (`reresolve.py`). This is a targeted re-resolution, not a
  closure run; it does not move element 7 by itself.
- Full `--self-test`: exit 0, `self-test ok`, no PREMISE_UNAVAILABLE.
  One pre-existing `NOT_RUN` remains in the e7core loader-fetch wrapper
  arm (unchanged from the prior batch).

## Central finding: most of the triage's rows are local copies

`nm -D libssl.so.3` does not define `CRYPTO_cfb128_encrypt`,
`OSSL_HTTP_get`, `OSSL_STORE_open_ex`, `PKCS12_create_ex2`,
`ENGINE_register_all_complete`, `CONF_modules_load`, `RAND_bytes_ex`,
`OBJ_NAME_do_all`, `OPENSSL_sk_pop_free`, ... .  Those names are exported
by **libcrypto** at different addresses; libssl carries non-exported
local copies (Rust static-link duplication).  For those rows:

- the containing function is not in the DSO's `.dynsym`;
- it has no in-image direct caller in most cases (only address-taken /
  method-table slots);
- therefore the *external* ABI contract does not apply to that copy, and
  the parameter/slot writer cannot be established.  They stay refused.

This is a triage-shape error, not a missing witness: the same source
function's exported copy in libcrypto is the one the external ABI names.

## Bound in this batch (3 new sites)

| site | function | class | writer |
|---|---|---|---|
| libssl 0x51bed4 | `provider_init` | `ABI_CONTRACT_PROVIDER_ENTRY` | `provider_new` stores its `init_function` parameter (src/provider/mod.rs:1891); `provider_init` stores the `DSO_bind_func("OSSL_provider_init")` result or NULL (src/provider/init.rs:301-315) |
| libssl 0x3b0069 | `ossl_provider_up_ref_parent` | `ABI_CONTRACT_PROVIDER_PARENT_UP_REF` | `ossl_provider_init_as_child` stores `function_for::<ChildUpRefFn>(p, OSSL_FUNC_PROVIDER_UP_REF)` from the parent's `in` table (src/provider/child.rs:533-536) |
| libssl 0x40bbca | `dso_shared::err_state_ptr` | `ABI_CONTRACT_DSO_EXPORT` | same `ERR_GET_STATE` LazySymbol cell as the bound twin 0x40bbe1: the dlsym result is published into the cell and tail-called; the cell writer scan is unchanged |

Proof for 0x51bed4: operand `%rax` has exactly two reaching definitions —
`mov 0x40(%rdi),%rax` (the provider parameter's `init_function`) and the
`DSO_bind_func` call whose result the same arm stores at `0x40(%rbx)`;
both paths are `test %rax,%rax` + conditional-branch guarded.  The
source assignment scan finds exactly three stores: init.rs:307 (DSO
transmute), init.rs:312 (`None`), mod.rs:1891 (`init_function`).

Proof for 0x3b0069: tail-call operand is a single `mov 0x48(%rax),%rax`;
the base is `lib_ctx_get_data(..., 0x12)` (both reaching base definitions
pass `$0x12` and are the documented accessor); the slot is NULL-guarded;
the only source writer binds `OSSL_FUNC_PROVIDER_UP_REF` and the compiled
store is `mov %rdx,0x48(%rax)` in `ossl_provider_init_as_child`.

## Confirmed already bound (13, not new)

libcrypto: 0x28a500 PEM_PASSWORD_CB; 0x340f29/0x340fb4, 0x50dadd,
0x510ab3/0x510ad2 PROVIDER_ALGORITHM_SLOT; 0x421cb2 X509_CTX_CALLBACK.
libssl: 0x2faf19/0x2fafa4, 0x4c7acd, 0x4caaa3/0x4caac2
PROVIDER_ALGORITHM_SLOT; 0x40bbe1 DSO_EXPORT.
Also 0x346026 / 0x300016 are resolved as an internal closed method-table
comparator, not contract-bounded.

## Refused (65 unresolved + 2 resolved rows)

| family (rows) | reason |
|---|---|
| modes/mod.rs (14) | non-exported libssl copies; operand is the exported signature's callback parameter but the copy has no exported entry point and no direct caller |
| wrap.rs (7) | private `wrap128`; callers (`aes_wrap_cipher`, `AES_wrap_key`) pass non-parameter in-image values; finite closed set, not an external ABI |
| engine/eng_fat (4) | local copy, zero direct callers; the engine registry is libssl-local, so exported ENGINE setters do not write it |
| http_client (4) | local copies; slots load from in-image HTTP/BIO state; no exported entry point |
| store_lib (3) | local copy; the store-loader registry is libssl-local |
| p12_crt (3) | local copy; operand traces to parameter 12 but no exported root / no direct caller |
| ssl_mcnf (3) | local static `ssl_do_config`; multiple method-table definitions, in-image callers only |
| provider/rand (3) | parent EVP_RAND dispatch from an in-image provider method object |
| confmod (2) | local copy; module list is libssl-local |
| evp/evp_pbe (2) | local copy; built-in PBE registry is libssl-local |
| encoder_meth (2) | local copy; `do_all` callback parameter but no exported entry point/direct caller |
| dh/check (2) | local; multiple reaching definitions from in-image methods |
| rand_lib (2) | local copies; RAND method table is in-image closed |
| pem/pem_pk8, pem/pem_lib (2 libssl + 1 libcrypto) | libssl copies local; libcrypto `PEM_ASN1_write_bio_internal` is private and its 89-caller walk reaches an exported root (`OCSP_REQUEST_print`) that does not declare the callback at that index — parameter chain not established |
| obj, stack, ui_read (3 libssl) | local copies; callback parameter but no exported entry point/direct caller (address-taken only) |
| dso_shared 0x40bbca (1) | **bound** in this batch; the tail-call result shape is now admitted with its own switch. |
| x509_vfy check_crl libssl (1) | store setter is not exported by this DSO |
| cmp_vfy (1) | local; the cert-conf setter in this DSO is not exported |
| passphrase (1) | local `ossl_pw_set_ossl_passphrase_cb`; no exported root chain proven |
| store_result (1) | local; field load with no exported writer |
| SSL_CTX_new_ex (1) | exported, but the operand is a two-definition `SSL_METHOD` table slot — an in-image closed set, not an external contract |

## Controls added (each load-bearing)

- `e7pe-wrong-offset` → `operand-is-not-the-init-function-slot`.
- `e7pe-second-writer` → `field-has-a-writer-outside-the-enumerated-set`
  (a foreign writer installing a different target).
- `e7pe-non-parameter` → `provider_new-does-not-store-its-parameter`.
- `e7pe-unguarded` → guardless fixture (each `test %rax,%rax` replaced by
  `nop`, branches kept) refuses baseline with
  `init-slot-is-not-null-guarded` and is accepted only under the switch.
- `e7pu-wrong-offset` → `operand-is-not-the-child-up-ref-slot`.
- `e7pu-second-writer` → `field-has-a-writer-outside-the-init-as-child`.
- `e7pu-no-dispatch-id` → `base-is-not-the-child-globals`.
- `e7pu-unguarded` → guardless fixture refuses and flips under its switch.
- `e7dso-tail-call` → the tail-call twin refuses under the switch and is
  accepted only when the call-result shape is admitted.
- Negative: calls at 0x51be9b and 0x3b0027 in the same functions are not
  absorbed (witness returns None); unpinned offsets are ignored.

## Queue after

- Triage `a_external_abi_contract`: 82 rows.
- Bound now: 15 → 16 after the DSO tail-call twin (13 pre-existing + 3
  new).
- Resolved closed comparator (not contract): 2.
- Unresolved and refused: 64.
- Relative to the prior receipt's 68, this batch binds 3 ⇒ 65 remain.
  The 82/68 difference is the 14 rows the prior receipts already
  accounted for (13 witnesses + the comparator rows); one row's
  accounting is off by one between the triage and the receipt and is
  recorded here rather than smoothed.

## Residuals

- Raw field displacements (0x40, 0x48) are not image-wide unique; the
  writer set is the source assignment set cross-checked against the
  enumerated writer functions, not a raw-displacement scan.
- A runtime GOT interposer outside the image is not addressed.
- The E7DSO tail-call-result shape is now admitted for a call-result tail
  whose result is published into the same cell; the switch is
  `e7dso-tail-call`.
- This is a targeted re-resolution, not a closure run; element 7 remains
  FAIL and `safe_compatible_curl` is NOT ESTABLISHED.
