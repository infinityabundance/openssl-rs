#!/usr/bin/env python3
"""Build the review receipt: court/.../b78-review-mechanisms.json is written to
forensics/memory-safety/campaign/safe-c33/atlas-refresh/b78-review-mechanisms.json
by the caller.  This script only prints JSON.
"""

import hashlib
import json
from pathlib import Path

ROOT = Path(".")
REV = ROOT / "court/freeze-b78/review2"


def load(name):
    return json.load(open(REV / name))


surface = load("surface.json")
obls = load("obligations.json")
contracts = load("contracts.json")
baseline = load("controls-baseline.json")
mutants = load("mutants-report.json")


def sha256(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


# ---------------------------------------------------------------------------
# per-obligation adjudications (hand-written by the reviewer from the source)
# ---------------------------------------------------------------------------
A = {}

A["dynamic_data_ctx_free_func"] = dict(
    verdict="ACCEPT",
    contract_source="fn-level # Safety at the definition",
    contract_quote=(
        "`CRYPTO_EX_free`'s ex_data contract: `ptr` is NULL or the value currently stored at the "
        "index this hook was registered for ... and that value is a live `DynamicDataCtx` which the "
        "enclosing ENGINE owns through its own ex_data slot."
    ),
    callers_from_safe_code=(
        "none. The name occurs only at its definition (eng_dyn.rs:415) and in the "
        "`Some(dynamic_data_ctx_free_func)` argument of CRYPTO_get_ex_new_index (eng_dyn.rs:499-504), "
        "inside `dynamic_get_data_ctx` (private `unsafe fn`). Invocation is by "
        "`CRYPTO_free_ex_data` (public `unsafe extern \"C\"`) from `OwnedEngine::Drop`."
    ),
    q1_safe_caller_ub=(
        "No. A safe Rust caller cannot name or call a private `unsafe extern \"C\"` fn; the only "
        "in-crate path is an unsafe fn / unsafe block, and the registration path is unsafe."
    ),
    q2_unsafe_ops_covered=(
        "Yes. `OwnedCtx::<DynamicDataCtx>::from_raw_at` (which returns None for NULL/misaligned) is the "
        "single release; the index is created with this hook (eng_dyn.rs:499) and the only writer of "
        "the index stores `*mut DynamicDataCtx` (dynamic_set_data_ctx, eng_dyn.rs:467)."
    ),
    q3_hidden_obligation=(
        "None found. A repeated CRYPTO_free_ex_data on the same block is safe: the body zeroes the "
        "slot and OPENSSL_sk after the callbacks (runtime/ex_data.rs:514-525), so a second invocation "
        "passes NULL to the hook and from_raw_at answers None. The doc's cited lines have drifted "
        "(:481-488 -> :499-504, :453 -> :467) but the establishing witnesses are present."
    ),
    q4_load_bearing_control=(
        "Yes in principle: B56-C7 counts exactly one release of the context block on the real "
        "ENGINE path and mutation M5 (a second CRYPTO_free) makes it fail; not re-run here "
        "(no build). Source-level C7 confirms the hook is never called outside an unsafe context."
    ),
    discharge=(
        "Contract at the definition + construction witnesses + ex_data free-hook contract "
        "(runtime/ex_data.rs:503-513) + control C7 (PASS baseline)."
    ),
    residual="None for this operation.",
)

A["push_cstr_or_null"] = dict(
    verdict="ACCEPT",
    contract_source="fn-level # Safety at the definition (repaired in source after the bound receipt)",
    contract_quote=(
        "`p` must be NULL or point to a NUL-terminated C string that stays readable for the duration "
        "of the call. The argument names a string the caller lends to this frame; no ownership is taken."
    ),
    callers_from_safe_code=(
        "ENGINE_set_default_string (public `unsafe extern \"C\"`, eng_fat.rs:239) and unsafe internal "
        "callers alg_module_init (evp_cnf.rs:104/107), conf_err (v3_cpols.rs:778/781), "
        "int_engine_configure (eng_cnf.rs:275/277/279) and conf_add_error_name_value. No safe fn calls it; "
        "the app mains reach it only through unsafe blocks."
    ),
    q1_safe_caller_ub=(
        "No. Every direct caller is an `unsafe fn` or calls inside an `unsafe` block with a SAFETY "
        "comment, and each passes NULL or a NUL-terminated string from a static/config value."
    ),
    q2_unsafe_ops_covered=(
        "Yes. The only unsafe operation is `CStr::from_ptr(p)`, covered by the contract; the Vec write "
        "is safe. Allocation failure aborts (Rust's alloc-error handler), so no unwind crosses the ABI."
    ),
    q3_hidden_obligation=(
        "None in the code. Evidence defect: the bound receipt `openssh-v1l` REJECTS this site (F09: "
        "no `# Safety`), and the contract has since been added; the closure still binds the REJECT. "
        "A receipt at the candidate is required. Control C1 reproduces F09 when the # Safety is removed "
        "(mutant M4) and passes on the current source."
    ),
    q4_load_bearing_control=(
        "C1 (contract site present) fires on mutant M4; no runtime control was run."
    ),
    discharge=(
        "This review's source read at src-content c0bd61c9 + caller enumeration + control C1; the "
        "v1l receipt does NOT discharge it and must be re-issued."
    ),
    residual="Stale REJECT receipt bound to a repaired site.",
)

A["engine_list_cleanup"] = dict(
    verdict="ACCEPT",
    contract_source="fn-level # Safety at the definition",
    contract_quote=(
        "The engine lock must be initialised (non-NULL) and must not already be held by this thread: "
        "this body takes it. ... With a NULL lock, `lock()` answers false and this cleanup stops with "
        "the list intact."
    ),
    callers_from_safe_code=(
        "none in production. The only direct call is the cfg(test) canary at eng_list.rs:896 inside "
        "`unsafe { }`; the only registration is `engine_cleanup_add_last(Some(engine_list_cleanup))` "
        "at eng_list.rs:237 inside `engine_list_add` (private `unsafe fn`). Invocation would be "
        "OPENSSL_cleanup -> engine_cleanup_int, which this candidate withholds."
    ),
    q1_safe_caller_ub=(
        "No. A safe caller cannot reach it; the test caller holds the lock precondition explicitly."
    ),
    q2_unsafe_ops_covered=(
        "Yes. The body takes the lock before reading the head (the deliberate fix for the authority's "
        "TOCTOU) and removes it with the unlocked `engine_list_remove`; a panic unwinds to the "
        "`extern \"C\"` boundary and aborts, leaving no poisoned lock in a live process."
    ),
    q3_hidden_obligation=(
        "No new memory-safety obligation. The destroy/ex-data callbacks run under the lock, exactly as "
        "the authority's ENGINE_remove already does, so the rewrite adds no new reentrancy edge; a "
        "callback that calls a locked engine API could deadlock, which is liveness, not UB, and matches "
        "the authority's own lock scope."
    ),
    q4_load_bearing_control=(
        "Yes: C3 asserts lock() precedes the head load and the removal lies between lock() and the "
        "following unlock(); mutant M2 (the old TOCTOU order) fires it. The in-repo "
        "cleanup_order_probe is the runtime counterpart (not run)."
    ),
    discharge=(
        "Contract at the definition + construction (ENGINE_add -> engine_list_add after "
        "ENGINE_new's lock init) + control C3 (PASS; M2 fires)."
    ),
    residual=(
        "Evidence defect: the bound B56 row describes the PRE-REWRITE body (line_current 97; "
        "`ENGINE_remove` answers 0) which no longer exists; commit 0d39697ae (the lock-first rewrite) "
        "is not an ancestor of the B56 candidate. B56 cannot discharge this span; it was re-established "
        "here at source."
    ),
)

A["module_free_thunk"] = dict(
    verdict="REJECT",
    contract_source="receipt-only (no # Safety at the definition; only an inner SAFETY comment)",
    contract_quote=(
        "v1l recorded contract: `value` is NULL or a `ConfModule` entry from the registry list being "
        "freed. The list is built only by module_add under the module-list lock, and the thunk is "
        "passed only to OPENSSL_sk_pop_free(to_delete, Some(module_free_thunk))."
    ),
    callers_from_safe_code=(
        "none. It appears only at its definition (confmod/mod.rs:397) and as `Some(module_free_thunk)` "
        "in `OPENSSL_sk_pop_free(to_delete, ...)` at confmod/mod.rs:1369, inside CONF_modules_unload "
        "(a safe `pub extern \"C\"`, but the pop_free call itself is in an `unsafe` block)."
    ),
    q1_safe_caller_ub=(
        "No. The thunk is private and is only invoked by the stack destructor with elements of the "
        "internal `to_delete` stack; CONF_modules_unload establishes element provenance by construction."
    ),
    q2_unsafe_ops_covered=(
        "Yes. `OPENSSL_sk_pop_free`'s # Safety requires the destructor to be valid for every element; "
        "the registry constructs entries only in module_add (OwnedBuf::new_zeroed + CRYPTO_strdup), and "
        "module_free adopts each member once."
    ),
    q3_hidden_obligation=(
        "The obligation itself is not hidden, but the CONTRACT IS NOT AT THE INTERFACE (criterion 1 / "
        "AGENTS.md §21.2: a private SAFETY comment is not a contract). Control C1 FAILS on this site."
    ),
    q4_load_bearing_control=(
        "C1 fires (baseline FAIL); the v1l C06 provenance/double-release canaries cover the runtime "
        "shape but were not re-run."
    ),
    discharge="None at the site. Add a `# Safety` contract; then re-adjudicate.",
    residual="Contract placement defect (same class as v1l F09).",
)

A["ui_free_method_data"] = dict(
    verdict="REJECT",
    contract_source="receipt-only (no # Safety at the definition; only an inner SAFETY comment)",
    contract_quote=(
        "v1l recorded contract: `data` is the slot's data, allocated by `ui_dup_method_data` or the "
        "wrapper; it is NULL or this unit's own block and no other owner releases it."
    ),
    callers_from_safe_code=(
        "none. Only the definition (ui_util.rs:197) and the registration `Some(ui_free_method_data)` in "
        "`CRYPTO_get_ex_new_index` at ui_util.rs:216, inside `ui_method_data_index_init` (a safe "
        "`extern \"C\"` once body). Invocation is by the ex_data machinery (unsafe)."
    ),
    q1_safe_caller_ub=(
        "No. The index is private (UI_METHOD_DATA_INDEX); the slot is written by this unit and the hook "
        "releases it once through OwnedPwData."
    ),
    q2_unsafe_ops_covered=(
        "Yes as read: OwnedPwData::adopt is the single release; ui_dup_method_data allocates through "
        "CRYPTO_memdup and replaces the slot, so the freed value is the unit's own block."
    ),
    q3_hidden_obligation=(
        "Same as module_free_thunk: the contract is not at the interface. C1 FAILS on this site."
    ),
    q4_load_bearing_control=(
        "C1 fires; no runtime control re-run."
    ),
    discharge="None at the site. Add a `# Safety` contract; then re-adjudicate.",
    residual="Contract placement defect.",
)

for name in ("readbuffer_write", "readbuffer_puts"):
    A[name] = dict(
        verdict="ACCEPT",
        contract_source="none (vacuous precondition; `#[allow(clippy::missing_safety_doc)]`)",
        contract_quote=(
            "No precondition exists: the body is exactly `0`. Every argument value (NULL, dangling, "
            "unaligned, any length) yields 0 without a read."
        ),
        callers_from_safe_code=(
            "none directly. The only references are the static method-table slots "
            "READBUFFER_METHOD.bwrite_old / .bputs (bf_readbuff.rs:48/51); BIO_f_readbuffer "
            "(safe `pub extern \"C\"`) publishes the table, and BIO_write/BIO_puts dispatch to the slots."
        ),
        q1_safe_caller_ub=(
            "No. There is no dereference, no unsafe block in the body, no allocation, no global or "
            "thread state; the `unsafe` marker is vestigial."
        ),
        q2_unsafe_ops_covered=(
            "Yes, vacuously: the only unsafe operation is the declaration itself and it has no "
            "precondition. The declaration is kept to preserve the exact C signature."
        ),
        q3_hidden_obligation=(
            "None for these two operations. Mechanism-wide there IS a safe-surface defect: "
            "COMP_get_type/COMP_get_name in the same BIO directory are safe `pub extern \"C\"` fns that "
            "dereference a caller pointer (see findings F-BIO-1)."
        ),
        q4_load_bearing_control=(
            "C2 asserts both bodies are exactly `0` with no deref/unsafe/call; mutant M1 (a null-checked "
            "deref) fires it."
        ),
        discharge="This source read + control C2 (PASS; M1 fires). Site-scoped only.",
        residual=(
            "No fn-level contract; the two operations are the whole of the BIO closure, so this is not "
            "a mechanism-wide discharge (mechanism_state UNSAFE_OPEN and other BIO files exist)."
        ),
    )

SSL_ACCEPT = {
    "ssl_match_option": (
        "Only caller is ssl_set_option_list:526 (private `unsafe extern \"C\"`), which receives "
        "`elem`/`len` from CONF_parse_list. CONF_parse_list's # Safety states the callback must accept "
        "a NULL-or-string pointer and a length; len == -1 is never passed by this caller."
    ),
    "ssl_set_option_list": (
        "Registered only by parse_option_list:659 with usr = cctx, and CONF_parse_list invokes it "
        "synchronously and retains nothing. parse_option_list sets cctx.tbl/ntbl for the call and "
        "clears them on every path."
    ),
    "min_max_proto": (
        "Callers cmd_MinProtocol:956 / cmd_MaxProtocol:988; both invoked only from SSL_CONF_cmd via "
        "ssl_conf_cmd_inner beneath the InUseGuard. SSL_CONF_cmd refuses a NULL value for typed rows "
        "(:1490) and requires exclusive access to cctx and the wrapped SSL/SSL_CTX (:1489). "
        "set_ssl/set_ssl_ctx supply the live min/max_version targets."
    ),
}

for name in ("cmd_Protocol", "cmd_Options", "cmd_VerifyMode", "cmd_CipherString",
             "cmd_Ciphersuites", "cmd_MinProtocol", "cmd_MaxProtocol"):
    SSL_ACCEPT[name] = (
        "Only registration is `cmdstr(NAME, ...)` in `commands()` (ssl_conf.rs); invocation is "
        "`(row.cmd)(...)` from ssl_conf_cmd_inner beneath the SSL_CONF_cmd InUseGuard. SSL_CONF_cmd's "
        "# Safety requires exclusive access to cctx and to the wrapped SSL/SSL_CTX and refuses NULL "
        "cctx/value, so the handler's own contract is established."
    )
    if name in ("cmd_CipherString", "cmd_Ciphersuites"):
        SSL_ACCEPT[name] += (
            " Caveat: the underlying SSL_CTX_set_cipher_list/set_ciphersuites contracts omit the "
            "exclusive-access requirement (finding F-SSL-1), but the caller here is stronger."
        )

for name in ("serverinfoex_srv_parse_cb", "serverinfo_srv_parse_cb"):
    SSL_ACCEPT[name] = (
        "ABI-only: installed by serverinfo_process_buffer (ssl_rsa.rs:1176/1165) as an erased "
        "pointer in the custom_ext_method record; extensions_cust.rs records that this slice never "
        "invokes either callback (control C4 PASS; mutant M5 fires when a cast/invocation is added)."
    )

for name, caller in SSL_ACCEPT.items():
    A[name] = dict(
        verdict="ACCEPT",
        contract_source="fn-level # Safety at the definition",
        contract_quote=contracts[[k for k, v in contracts.items() if v["item"] == name][0]]["safety_doc"][:600],
        callers_from_safe_code=caller,
        q1_safe_caller_ub=(
            "No direct safe caller. All public entry points into the SSL_CONF/SSL code are "
            "`pub unsafe extern \"C\" fn`; in-crate safe app mains reach this path only through "
            "`unsafe` blocks that state the entry-point contract."
        ),
        q2_unsafe_ops_covered=(
            "Yes per operation: the pointer dereferences are covered by the quoted contract, and the "
            "exclusivity requirement is established by the SSL_CONF_cmd contract / the ABI-only status."
        ),
        q3_hidden_obligation=(
            "None in this operation's own chain. The mechanism-level findings are recorded in "
            "mechanism_verdicts.SSL_SESSION (F-SSL-1 cipher-list exclusivity, F-SSL-2 "
            "ssl_set_version_bound)."
        ),
        q4_load_bearing_control=(
            "C5 asserts every *mut SslConfCtx entry point calls enter_use; mutant M3 (guard removed "
            "from SSL_CONF_cmd) fires it. C4 covers the serverinfo ABI-only claim. The three runtime "
            "reentrancy controls named by sslconf-exclusivity were not re-run."
        ),
        discharge=(
            "Contract at the definition + the caller/registration witnesses above + C5/C4 at source; "
            "the sslconf-exclusivity runtime controls remain the only runtime evidence and are not "
            "re-run here."
        ),
        residual=None,
    )

for name in ("update_cipher_list_by_id", "set_ciphersuites"):
    A[name] = dict(
        verdict="REJECT",
        contract_source="fn-level # Safety at the definition",
        contract_quote=contracts[[k for k, v in contracts.items() if v["item"] == name][0]]["safety_doc"][:600],
        callers_from_safe_code=(
            "update_cipher_list_by_id: update_cipher_list:828 and ssl_create_cipher_list:1208 (both "
            "private/`pub(crate)` `unsafe fn`, reached from SSL_CTX_set_cipher_list / SSL_set_cipher_list). "
            "set_ciphersuites: SSL_CTX_set_ciphersuites:1632 and SSL_set_ciphersuites:1662 (public "
            "`unsafe extern \"C\"`)."
        ),
        q1_safe_caller_ub=(
            "Not directly: the public setters are unsafe. But the *precondition the callee requires* "
            "is not in the callers' stated contracts, so an unsafe caller following those contracts "
            "can still cause a use-after-free of the replaced stack."
        ),
        q2_unsafe_ops_covered=(
            "No. The operation requires exclusive access to the cipher-list slot and frees the old "
            "stack. The immediate caller contracts say only `ctx`/`c` live and the slots writable/owned; "
            "the public setters' # Safety says only `ctx`/`s` NULL or live, `str` NULL or "
            "NUL-terminated. None states exclusive access or the absence of a concurrent reader "
            "(e.g. SSL_CTX_get_ciphers). Control C6 FAILS on all four public setters."
        ),
        q3_hidden_obligation=(
            "Yes (F-SSL-1): the exclusive-access / no-concurrent-reader precondition is unreported at "
            "the public interface. The general OpenSSL rule that objects are not thread-safe may cover "
            "it for C consumers, but the crate's own # Safety does not state it, so it is hidden under "
            "AGENTS.md §0."
        ),
        q4_load_bearing_control=(
            "C6 is the control: it fails on the current source and passes on mutant M6, which adds the "
            "missing sentence to all four setters."
        ),
        discharge="Not discharged. Add the exclusive-access precondition to the public setters' # Safety "
        "and to the two callers, or establish it structurally (e.g. a guard).",
        residual="Hidden precondition at the public interface.",
    )

# ---------------------------------------------------------------------------
# mechanism verdicts
# ---------------------------------------------------------------------------
mech = {
    "C_ABI_CONTRACT": {
        "obligations": 5,
        "accept": 3,
        "reject": 2,
        "verdict": "NOT_ESTABLISHED",
        "criterion3_safe_surface": (
            "No external safe-Rust UB found in the five files. The files contain 35 safe fns reaching "
            "unsafe, 5 of them external safe `pub extern \"C\"` (ENGINE_get_first/last, "
            "CONF_modules_unload/finish, OPENSSL_load_builtin_modules); none takes a raw pointer, and "
            "none of the five obligations is reachable from a safe fn except through unsafe blocks."
        ),
        "blocking_residuals": [
            "module_free_thunk and ui_free_method_data have no fn-level # Safety (criterion 1; C1 FAIL).",
            "mechanism_state is UNSAFE_OPEN in the inventory.",
            "The v1l receipt bound to push_cstr_or_null is a REJECT (F09) for a site whose contract has since been added; a receipt at S is required.",
            "B56's engine_list_cleanup row describes the pre-rewrite body and is not evidence for the current 180-line rewrite.",
        ],
        "cheapest_route": (
            "Add the two # Safety contracts (mechanical), re-issue the v1l and B56 receipts at the "
            "frozen S, and re-adjudicate the three ACCEPT sites. No runtime control is needed for "
            "criterion 1/2; criterion 3 for this mechanism is already clean at the safe surface."
        ),
    },
    "BIO": {
        "obligations": 2,
        "accept": 2,
        "reject": 0,
        "verdict": "NOT_ESTABLISHED",
        "criterion3_safe_surface": (
            "POSITIVELY FAILS criterion 3. The BIO mechanism is the directory rule ^src/runtime/bio/, "
            "which contains src/runtime/bio/comp.rs: COMP_get_type and COMP_get_name are safe "
            "`pub extern \"C\" fn`s that dereference a caller-supplied `*const CompMethod` with only a "
            "`# Notes` precondition and an `#[allow(clippy::not_unsafe_ptr_arg_deref)]`; a safe Rust "
            "caller can pass a dangling pointer and cause UB. The two closure obligations "
            "(readbuffer_write/puts) are ACCEPT site-scoped and have no precondition, but they are the "
            "whole closure, not the whole mechanism."
        ),
        "blocking_residuals": [
            "F-BIO-1: safe pub extern C pointer-dereferencing functions COMP_get_type/COMP_get_name in the mechanism directory.",
            "mechanism_state UNSAFE_OPEN; only 2 of the mechanism's production operations are in the closure.",
            "No fn-level # Safety on the two closure operations (the precondition is vacuous, but the marker is vestigial).",
        ],
        "cheapest_route": (
            "Either make COMP_get_type/COMP_get_name `unsafe` (they are internal helpers exported for "
            "the ABI; check the ABI-prototype constraint) or add a safe wrapper and keep the raw export "
            "unsafe; then extend the closure to the rest of the directory. The two closure obligations "
            "need no further work."
        ),
    },
    "SSL_SESSION": {
        "obligations": 14,
        "accept": 12,
        "reject": 2,
        "verdict": "NOT_ESTABLISHED",
        "criterion3_safe_surface": (
            "Fails at the safe surface. (a) ssl_set_version_bound (ssl_conf.rs:567) is a safe "
            "`pub(crate) fn` that dereferences a raw `*mut c_int` with no `# Safety`: any in-crate safe "
            "caller can pass a dangling pointer and cause UB (AGENTS.md §1/§9). (b) SSL_COMP_get_name "
            "(ssl_ciph.rs:1800) is a safe `pub extern \"C\"` that dereferences a caller pointer under a "
            "`# Notes` precondition. (c) The two cipher-list operations depend on an exclusive-access "
            "precondition that the public setters' # Safety does not state."
        ),
        "blocking_residuals": [
            "F-SSL-1: SSL_CTX_set_cipher_list / SSL_set_cipher_list / SSL_CTX_set_ciphersuites / SSL_set_ciphersuites do not state the exclusive-access precondition required by update_cipher_list_by_id and set_ciphersuites (C6 FAIL).",
            "F-SSL-2: ssl_set_version_bound is a safe fn with an unchecked raw-pointer dereference (new hidden obligation; blocks graduation under §0).",
            "F-SSL-3: SSL_COMP_get_name is a safe pub extern C with a caller-pointer precondition.",
            "0/14 re-reviewed at b78 before this review; no TSan/Loom/runtime concurrency evidence.",
        ],
        "external_serialisation_adjudication": {
            "question": "Is the retained second-concurrent-free / release-race obligation a real precondition on a safe caller, or a documented C-ABI obligation?",
            "answer": (
                "It is a documented C-ABI (unsafe-caller) obligation, not a safe-caller obligation. "
                "SSL_CONF_CTX_free and every SSL_CONF entry point are `pub unsafe extern \"C\" fn`, so "
                "no safe Rust caller can invoke them. The requirement is stated verbatim in the "
                "function's # Safety ('The caller must externally serialise this call'), and it is the "
                "same object-lifetime rule the authority imposes: an OpenSSL object must not be freed "
                "or entered while another thread is inside it, and the C objects are not internally "
                "synchronised. Under §7 criterion 2 an external ABI contract can discharge a "
                "precondition, so the residual is classified as a retained external ABI contract, not "
                "an unestablished code precondition."
            ),
            "is_it_hidden": (
                "No. It is recorded in the receipt and stated at the interface. The b78 argument calls "
                "it a hidden obligation; this review disagrees with that label while agreeing that it "
                "is retained, not discharged by code."
            ),
            "does_it_block_criterion3": (
                "No, by itself: criterion 3 quantifies over safe Rust callers, and there is none for "
                "this entry point. It does not rescue the mechanism, which fails on F-SSL-1/2/3."
            ),
            "caveat": (
                "The candidate defers the release rather than refusing it; that is a recorded "
                "divergence and must not be described as making concurrent use safe."
            ),
        },
        "cheapest_route": (
            "Fix F-SSL-2 (make ssl_set_version_bound `unsafe fn` with a # Safety, or take `&mut c_int`), "
            "state / structurally enforce the exclusivity precondition for the four cipher-list setters "
            "(F-SSL-1), and make SSL_COMP_get_name's precondition a # Safety (F-SSL-3) or stop "
            "declaring it safe. Then re-adjudicate the 14 at the new S. The 12 ACCEPT sites need no "
            "re-read unless their contract changes."
        ),
    },
}

# ---------------------------------------------------------------------------
# task 3
# ---------------------------------------------------------------------------
task3 = {
    "outside_b78_cohort_by_mechanism": {
        "EVP_PKEY_PROVIDER": 73,
        "X509_VERIFY_POLICY": 117,
        "RAND_CMS_STORE_KEYFMT": 13,
        "RUNTIME_CONCURRENCY": 4,
        "total": 207,
        "source": "evidence/b78-safety-argument.json mechanism_partition[*].outside_b78_cohort",
    },
    "contract_gaps_in_those_mechanisms": {
        "EVP_PKEY_PROVIDER": "36 operation-level SAFETY only with no fn-level # Safety; the digest_impl! macro carries 5 unsafe extern C fns without # Safety outside the reviewed cohort.",
        "X509_VERIFY_POLICY": "5 operation-level only, 1 cabi_contract_record, 2 no_contract.",
        "RAND_CMS_STORE_KEYFMT": "0 no_contract reported; 13 outside the reviewed cohort.",
        "RUNTIME_CONCURRENCY": "B60's reviewer is the orchestrating agent, not independent; no TSan/Loom run.",
    },
    "cheapest_sound_route": (
        "Per-site review remains the sound route for criterion 1/2. The measured safe-pub surface does "
        "not replace it: only 30/290 obligations are reachable from an external safe pub fn, and "
        "criterion 3 for the other 260 still requires that each unsafe entry point's contract be "
        "complete and that its callers establish it. The cheapest order is: (1) fix the five confirmed "
        "safe-interface defects (F-BIO-1, F-SSL-2, F-SSL-3 and the two contract-placement rejects) "
        "because they block every mechanism and are mechanical; (2) re-issue the stale receipts "
        "(v1l F09, B56 engine_list_cleanup, the sslconf row) at the frozen S; (3) review the 207 with "
        "the b78 cohort method in dependency clusters, prioritising the 30 reachable from safe pub fns "
        "(criterion 3 first) and the mechanisms with contract-form gaps (EVP 36 operation-level-only, "
        "X509 2 no-contract); (4) only then run a BOUNDARY gate with TSan/Loom for RUNTIME_CONCURRENCY "
        "and a re-adjudication by a reviewer who is not the orchestrator."
    ),
    "why_not_a_source_only_argument": (
        "A safe-pub-surface argument can discharge criterion 3 (no safe caller can cause UB) but not "
        "criterion 1 (every unsafe op has an explicit validity contract) or criterion 2 (every "
        "precondition is established by its callers). The 260 unsafe-entry-only obligations are "
        "reached by C consumers, and their contracts are the ABI evidence that must be read. There is "
        "no sound shortcut that turns 207 unreviewed caller closures into a discharge."
    ),
}

receipt = {
    "schema": "openssl-rs/review/b78-review-mechanisms/v1",
    "kind": "independent-review-three-weakest-mechanisms",
    "generated_utc": "2026-11-14T00:00:00Z",
    "reviewer_role": (
        "independent reviewer; did not author the conversions, the b78 safety argument, or the "
        "discharge receipts"
    ),
    "candidate": {
        "branch": "stage/p25/b75-ocsp",
        "head": "c9652a2b2",
        "frozen_inventory_source_head": "bb7d5206acfbf6c3e0ba202a0a03e61b8bf13aac",
        "src_content_sha256": "c0bd61c94f5a8da2e08c105724d14750403fbfd53aa8d4b722672f9b11b0bd38",
        "src_files": 878,
        "src_content_hash_rule": "sha256('openssl-rs/src-rs/v1\\0' + sorted relpath\\0bytes\\0)",
        "identity_proof": (
            "the hash recomputed over src/**/*.rs at HEAD equals census-b78.json's identity, and "
            "`git diff --stat bb7d5206a..HEAD -- src Cargo.toml Cargo.lock build.rs` is empty; the "
            "review therefore binds to the same source as the b78c closures"
        ),
        "closure": "evidence/closure-ssh-b78c.json",
        "closure_sha256": sha256("evidence/closure-ssh-b78c.json"),
        "b78_argument": "evidence/b78-safety-argument.json",
        "b78_argument_sha256": sha256("evidence/b78-safety-argument.json"),
    },
    "memory_discipline": {
        "free_g": "total 31, used 22, available 8, swap 29/31 used",
        "builds_or_tests_run": 0,
        "reason": (
            "AGENTS.md §6.1: available < 24 GiB means no build and no test; the review is source-level "
            "and all controls are lexical. The in-repo runtime controls are recorded NOT_RUN."
        ),
    },
    "task1_safe_surface": {
        "question": (
            "how many pub safe fns can reach an unsafe operation, which are reachable from safe Rust "
            "outside the crate, and how many closure obligations are reachable only through unsafe exports"
        ),
        "method": surface["method"],
        "counts": surface["counts"],
        "sensitivity": {
            "stricter_external_rule": (
                "vis == pub, every enclosing inline mod pub, and for an impl method the type must be "
                "defined pub in the same file; excludes #[doc(hidden)]/#[cfg(test)]/tests"
            ),
            "external_safe_pub_defs_strict": 851,
            "external_safe_pub_defs_reaching_unsafe_strict": 467,
            "looser_rule_used_above": 879,
            "looser_rule_reaching_unsafe": 477,
            "note": "the difference (28) is impl methods whose type is not pub in the same file; the order of magnitude and every conclusion are unchanged",
        },
        "external_reachable_safe_pub_reaching_unsafe_non_apps": (
            len([x for x in surface["safe_pub_external_reaching_unsafe"] if not x.startswith("src/apps")])
        ),
        "records": {
            "safe_pub_external_reaching_unsafe": surface["safe_pub_external_reaching_unsafe"],
            "safe_pub_extern_c_raw_pointer_param_reaching_unsafe": surface[
                "safe_pub_extern_c_raw_pointer_param_reaching_unsafe"
            ],
            "safe_plain_fn_raw_pointer_param_reaching_unsafe": surface[
                "safe_plain_fn_raw_pointer_param_reaching_unsafe"
            ],
        },
        "verified_external_safe_pointer_functions": [
            {
                "fn": "src/runtime/bio/comp.rs::COMP_get_type",
                "abi": "safe pub extern \"C\"",
                "precondition": "# Notes absent; body dereferences `(*meth).type_` after a NULL check",
                "mechanism": "BIO",
            },
            {
                "fn": "src/runtime/bio/comp.rs::COMP_get_name",
                "abi": "safe pub extern \"C\"",
                "precondition": "# Notes absent; body dereferences `(*meth).name` after a NULL check",
                "mechanism": "BIO",
            },
            {
                "fn": "src/ssl/ssl_ciph.rs::SSL_COMP_get_name",
                "abi": "safe pub extern \"C\"",
                "precondition": "# Notes: `comp` NULL or a live COMP_METHOD; forwards to COMP_get_name",
                "mechanism": "SSL_SESSION",
            },
            {
                "fn": "src/runtime/obj.rs::OBJ_NAME_add",
                "abi": "safe pub extern \"C\"",
                "precondition": "# Notes: name/data valid NUL-terminated and outlive the entry",
                "mechanism": "unmapped (runtime)",
            },
            {
                "fn": "src/runtime/obj.rs::OBJ_NAME_get",
                "abi": "safe pub extern \"C\"",
                "precondition": "no # Safety; name compared through the registered comparator/strcmp",
                "mechanism": "unmapped (runtime)",
            },
            {
                "fn": "src/runtime/obj.rs::OBJ_NAME_remove",
                "abi": "safe pub extern \"C\"",
                "precondition": "no # Safety; name compared through the registered comparator/strcmp",
                "mechanism": "unmapped (runtime)",
            },
            {
                "fn": "src/ssl/ssl_conf.rs::ssl_set_version_bound",
                "abi": "safe pub(crate) fn (Rust ABI)",
                "precondition": "no # Safety; `unsafe { *bound = version }` on a caller pointer",
                "mechanism": "SSL_SESSION",
            },
        ],
        "quic_stub_note": (
            "33 of the 46 safe pub extern C raw-pointer functions are the QUIC/stream stubs in "
            "ssl_lib.rs; each body is `let _ = (args); <constant>` and the pointer is never used."
        ),
        "obligations_reachable_from_external_safe_pub": {
            "total": 290,
            "reached": obls["closure_wide"]["reached_by_external_safe_pub"],
            "unsafe_entry_only_measured": 290 - obls["closure_wide"]["reached_by_external_safe_pub"],
            "by_mechanism": {
                k: {kk: vv for kk, vv in v.items() if kk != "examples"}
                for k, v in obls["closure_wide"]["by_mechanism"].items()
            },
            "caveat": (
                "the lexical graph resolves calls by name and does not follow function-pointer tables "
                "or macro-expanded edges, so the reached count is a lower bound (the unsafe-entry-only "
                "count is an upper bound). The 21 reviewed obligations were adjudicated by direct "
                "caller reads instead."
            ),
        },
        "conclusion": (
            "The criterion-3 scope is the safe-pub surface, not the 290 obligations as a whole: 879 "
            "safe pub fn definitions (122 plain Rust ABI, 757 extern C) are reachable from safe Rust, "
            "and 477 of them reach an unsafe operation. The b78 argument's premise that 'the mechanism "
            "entry points are pub unsafe extern C, so a safe-Rust caller cannot invoke one without an "
            "unsafe block' is false for the 757 safe extern C exports, at least 6 of which dereference "
            "caller pointers. The recorded 'crate-wide safe pub fn count is 202' could not be "
            "reproduced: 202 is neither 879 nor the 122 plain-Rust-ABI count, and no tool is recorded "
            "for it (evidence defect)."
        ),
    },
    "task2_obligations": obls["obligations"],
    "task2_adjudication": A,
    "mechanism_verdicts": mech,
    "task3_remaining": task3,
    "controls": {
        "baseline": baseline,
        "mutants": mutants,
        "interpretation": (
            "C1, C6 fail on the current source and are the two findings they are built to detect; "
            "C2, C3, C4, C5, C7 pass. Every mutant fires its intended control (M6 is the negative "
            "control for C6 and passes once the missing precondition is stated)."
        ),
        "not_run": [
            "B56-C7 / V1L-C06 runtime controls",
            "sslconf-exclusivity three reentrancy/concurrency controls",
            "cleanup_order_probe test",
            "Miri / ASan / TSan / Loom",
            "cargo fmt / clippy / test (memory floor)",
        ],
    },
    "findings": [
        {
            "id": "F-BIO-1",
            "severity": "safe-interface-soundness",
            "statement": (
                "COMP_get_type (src/runtime/bio/comp.rs:237) and COMP_get_name (:252) are safe "
                "`pub extern \"C\" fn`s that dereference a caller-supplied `*const CompMethod`; the "
                "only guard is a NULL check and the pointer's contract is a comment plus "
                "`#[allow(clippy::not_unsafe_ptr_arg_deref)]`. Safe Rust can call them with a dangling "
                "pointer and cause UB. This is a criterion-3 counterexample inside the BIO mechanism "
                "directory and is not recorded in evidence/b78-safety-argument.json."
            ),
            "control": "source read; the pattern is the one the allow attribute documents",
        },
        {
            "id": "F-SSL-1",
            "severity": "hidden-obligation",
            "statement": (
                "update_cipher_list_by_id and set_ciphersuites require exclusive access to the cipher-list "
                "slot and free the previous stack, but SSL_CTX_set_cipher_list, SSL_set_cipher_list, "
                "SSL_CTX_set_ciphersuites and SSL_set_ciphersuites state only 'NULL or live; NULL or "
                "NUL-terminated'. A concurrent reader (e.g. SSL_CTX_get_ciphers) is not excluded by the "
                "stated contract."
            ),
            "control": "C6 FAIL baseline; M6 PASS (statement added)",
        },
        {
            "id": "F-SSL-2",
            "severity": "safe-interface-soundness",
            "statement": (
                "ssl_set_version_bound (src/ssl/ssl_conf.rs:567) is a safe `pub(crate) fn` with a raw "
                "`*mut c_int` parameter and an unchecked `unsafe { *bound = version }`. Any in-crate "
                "safe caller can pass a dangling pointer and cause UB (AGENTS.md §1: a safe fn that can "
                "trigger UB is a soundness bug even when today's call sites are correct)."
            ),
            "control": "source read; mech-surface.json lists it as the only plain-Rust-ABI safe fn with "
            "a raw pointer parameter in the three mechanisms",
        },
        {
            "id": "F-SSL-3",
            "severity": "safe-interface-soundness",
            "statement": (
                "SSL_COMP_get_name (src/ssl/ssl_ciph.rs:1800) is a safe `pub extern \"C\" fn` whose "
                "# Notes (not # Safety) require `comp` to be a live COMP_METHOD; it forwards to "
                "COMP_get_name, which dereferences it."
            ),
            "control": "source read",
        },
        {
            "id": "F-EVID-1",
            "severity": "evidence-identity",
            "statement": (
                "B56's engine_list_cleanup row describes a body that no longer exists: the lock-first "
                "rewrite (0d39697ae, 180 insertions) is not an ancestor of the B56 candidate, and the "
                "row's argument ('With a NULL lock the loop's ENGINE_remove answers 0') does not "
                "describe the current body. The span hash matches the current operation, so the "
                "closure accepts the obligation, but the receipt's reasoning is not evidence for it."
            ),
            "control": "C3 PASS; git ancestry check",
        },
        {
            "id": "F-EVID-2",
            "severity": "evidence-identity",
            "statement": (
                "The v1l receipt bound to push_cstr_or_null REJECTS it (F09, no # Safety) while the "
                "current source has the contract. The closure records DISCHARGED on a rejected receipt."
            ),
            "control": "C1 PASS on push_cstr_or_null; M4 reproduces F09 when the # Safety is removed",
        },
        {
            "id": "F-EVID-3",
            "severity": "evidence-unreproducible",
            "statement": (
                "The b78 argument's safe-surface numbers ('13 safe pub fn in mechanism files', "
                "'crate-wide safe pub fn count is 202') have no recorded tool and do not match the "
                "measurement (879 safe pub definitions; 477 reaching unsafe)."
            ),
            "control": "surface.py / surface.json",
        },
    ],
    "non_claims": [
        "No build, test, Miri, ASan, TSan or Loom run supports this review; all controls are source-level.",
        "The name-based call graph is not a rustc-level resolution; dynamic dispatch, trait objects and "
        "macro-expanded edges are under-approximated, and re-exports were not followed.",
        "This review does not re-adjudicate the 207 obligations outside the four remaining mechanisms' "
        "b78 cohort, nor any obligation outside the 21.",
        "The safe-pointer functions listed are the ones verified by reading the body; the count of 46 "
        "raw-pointer safe extern C functions is a lexical over-approximation that includes the 33 "
        "pointer-ignoring QUIC stubs.",
        "Accepting the SSL_CONF_CTX_free serialisation as an external ABI contract is a classification "
        "of the obligation, not evidence that any C consumer observes it.",
    ],
    "source_witnesses": {
        "review_scripts": [
            "court/freeze-b78/review2/surface.py",
            "court/freeze-b78/review2/obligations.py",
            "court/freeze-b78/review2/contracts.py",
            "court/freeze-b78/review2/mech_surface.py",
            "court/freeze-b78/review2/controls.py",
            "court/freeze-b78/review2/mutate.py",
        ],
        "outputs": [
            "court/freeze-b78/review2/surface.json",
            "court/freeze-b78/review2/obligations.json",
            "court/freeze-b78/review2/contracts.json",
            "court/freeze-b78/review2/mech-surface.json",
            "court/freeze-b78/review2/controls-baseline.json",
            "court/freeze-b78/review2/mutants-report.json",
        ],
        "receipt_sha256_note": "this file's sha256 is recorded by the orchestrator after writing",
    },
}

print(json.dumps(receipt, indent=1))
