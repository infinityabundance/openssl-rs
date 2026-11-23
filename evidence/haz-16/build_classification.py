#!/usr/bin/env python3
"""Build `CLASSIFICATION.json` for HAZ-16 from the enumerated candidate set.

The enumerator (`enumerate_ffi_mutation.py`) produces the crate-wide candidate
superset.  This script restricts it to the **covered population** (the nine
library-object owner files named in `docs/FFI-FAILURE-ATOMICITY.md`), requires a
disposition for every covered entry, and fails if a covered entry is unnamed.
That is what stops the classification from silently shrinking when the source
changes.

Run from the repository root:

    python3 evidence/haz-16/build_classification.py
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent

COVERED_FILES = [
    "src/runtime/stack.rs",
    "src/runtime/lhash.rs",
    "src/runtime/bio/mod.rs",
    "src/runtime/bio/iolib.rs",
    "src/bn/bignum.rs",
    "src/bn/ctx.rs",
    "src/bn/blinding.rs",
    "src/runtime/ex_data.rs",
    "src/runtime/obj.rs",
]

F = "FAILURE_ATOMIC"
R = "ROLLBACK"
P = "POISONED"
X = "PARTIAL_EXPOSED"

# (file, entry) -> (class, object_state_concern, basis, residual)
DISPOSITIONS: dict[tuple[str, str], tuple[str, str, str, str | None]] = {
    # ---- OPENSSL_STACK ---------------------------------------------------
    ("src/runtime/stack.rs", "OPENSSL_sk_new_reserve"): (
        F, "object_state",
        "the stack is built locally and returned only after `from_boxes` completes; no caller can see a partial object", None),
    ("src/runtime/stack.rs", "OPENSSL_sk_reserve"): (
        F, "object_state",
        "`try_reserve` precedes the `num_alloc` assignment; a refusal leaves the count and the element array unchanged", None),
    ("src/runtime/stack.rs", "OPENSSL_sk_free"): (
        F, "object_state",
        "one `Box::from_raw` release of the whole object; no intermediate publish", None),
    ("src/runtime/stack.rs", "OPENSSL_sk_pop_free"): (
        R, "object_state",
        "each element is removed from the `Vec` before its destructor runs; a panic leaves only the unreleased remainder, and a retry is legal (fixed in this batch)", None),
    ("src/runtime/stack.rs", "OPENSSL_sk_set"): (
        F, "object_state",
        "one element write plus the `sorted` flag; both are total operations after the index check", None),
    ("src/runtime/stack.rs", "OPENSSL_sk_insert"): (
        F, "object_state",
        "`sk_reserve` precedes the insertion; the length and `sorted` flag change only after the insert succeeds", None),
    ("src/runtime/stack.rs", "OPENSSL_sk_zero"): (
        F, "object_state",
        "one pass setting every slot to NULL, with no fallible step inside it", None),
    ("src/runtime/stack.rs", "OPENSSL_sk_deep_copy"): (
        R, "object_state",
        "a copy failure frees every element already produced and the unlinked candidate before returning NULL", None),

    # ---- OPENSSL_LHASH ---------------------------------------------------
    ("src/runtime/lhash.rs", "OPENSSL_LH_free"): (
        F, "object_state", "one release of the whole table", None),
    ("src/runtime/lhash.rs", "OPENSSL_LH_flush"): (
        F, "object_state", "an in-place clear under the table lock with no fallible step", None),
    ("src/runtime/lhash.rs", "OPENSSL_LH_insert"): (
        F, "object_state",
        "the growth step precedes the bucket push, and `num_items` increments only after that push", None),
    ("src/runtime/lhash.rs", "OPENSSL_LH_delete"): (
        F, "object_state",
        "the element is removed and the count decremented; the optional contraction cannot fail the operation", None),

    # ---- BIO (core) ------------------------------------------------------
    ("src/runtime/bio/mod.rs", "BIO_new_ex"): (
        F, "object_state",
        "the block is built locally; an `ex_data` or `create` failure tears the block down before it is published", None),
    ("src/runtime/bio/mod.rs", "BIO_up_ref"): (
        F, "object_state", "one atomic reference increment", None),
    ("src/runtime/bio/mod.rs", "BIO_free"): (
        P, "object_state",
        "the reference gate claims the last reference (the destroying sentinel) before any callback; a free-callback veto leaves the object retired, and both reuse and a retry of the release are refused", None),
    ("src/runtime/bio/mod.rs", "BIO_vfree"): (
        F, "object_state", "a forward to `BIO_free`, whose gate is the state transition", None),
    ("src/runtime/bio/mod.rs", "BIO_free_all"): (
        F, "object_state",
        "each element is released through the independently guarded `BIO_free`; a veto leaks that element and the walk continues, with no released element reachable from a surviving one", None),
    ("src/runtime/bio/mod.rs", "BIO_get_retry_BIO"): (
        F, "object_state",
        "the walk and the single `reason` write are total after the NULL checks", None),
    ("src/runtime/bio/mod.rs", "BIO_push"): (
        F, "object_state",
        "both chain links are written before the notification; the notification's result is ignored by the authority and the chain graph is complete", None),
    ("src/runtime/bio/mod.rs", "BIO_find_type"): (
        F, "object_state", "read-only walk with no mutation", None),
    ("src/runtime/bio/mod.rs", "BIO_dup_chain"): (
        R, "object_state",
        "a failure frees the unlinked new BIO and the partial head through `BIO_free_all`", None),

    # ---- BIO (I/O) -------------------------------------------------------
    ("src/runtime/bio/iolib.rs", "BIO_sendmmsg"): (
        F, "object_state",
        "`*msgs_processed` is zeroed before the method and the method's own result is the only later write", None),
    ("src/runtime/bio/iolib.rs", "BIO_recvmmsg"): (
        F, "object_state",
        "as `BIO_sendmmsg`: the out-count is zeroed first and written once after the method", None),
    ("src/runtime/bio/iolib.rs", "BIO_puts"): (
        F, "object_state",
        "the method performs the transfer and `num_write` follows it; a failure return reports the transfer's own outcome", None),
    ("src/runtime/bio/iolib.rs", "BIO_gets"): (
        F, "object_state",
        "the method fills the caller buffer and the return value reports the count; no library field changes before it", None),
    ("src/runtime/bio/iolib.rs", "BIO_get_line"): (
        F, "object_state",
        "the loop reads through the same method and returns its own count; no library field is published ahead of the transfer", None),
    ("src/runtime/bio/iolib.rs", "BIO_ctrl"): (
        F, "object_state",
        "the command arguments are read, the callback runs, and the result is written once; application mutation inside a callback is HAZ-06/HAZ-20, not this boundary", None),
    ("src/runtime/bio/iolib.rs", "BIO_callback_ctrl"): (
        F, "object_state",
        "the callback is installed by one field write after the NULL and type checks", None),
    ("src/runtime/bio/iolib.rs", "BIO_do_connect_retry"): (
        F, "object_state",
        "each retry re-reads the socket state and the loop's only carried state is the iteration budget", None),

    # ---- BIGNUM ----------------------------------------------------------
    ("src/bn/bignum.rs", "BN_secure_new"): (
        F, "object_state",
        "the value is allocated locally and the secure flag is set before the handle is returned", None),
    ("src/bn/bignum.rs", "BN_free"): (
        F, "object_state", "one release of the limbs and the object", None),
    ("src/bn/bignum.rs", "BN_clear_free"): (
        F, "object_state", "one cleansed release of the limbs and the object", None),
    ("src/bn/bignum.rs", "BN_clear"): (
        F, "object_state", "an in-place zeroing with no fallible step", None),
    ("src/bn/bignum.rs", "BN_copy"): (
        F, "object_state",
        "`try_assign_limbs` performs the only fallible step before the destination is changed; the sign write follows it", None),
    ("src/bn/bignum.rs", "BN_swap"): (
        F, "object_state", "two `mem::swap` operations on values; total", None),
    ("src/bn/bignum.rs", "BN_set_word"): (
        F, "object_state", "the limb vector is built locally and stored once", None),
    ("src/bn/bignum.rs", "BN_set_bit"): (
        F, "object_state", "the growth is performed before the bit is set", None),
    ("src/bn/bignum.rs", "BN_clear_bit"): (
        F, "object_state", "a single masked limb write", None),
    ("src/bn/bignum.rs", "BN_set_negative"): (
        F, "object_state", "one scalar write", None),
    ("src/bn/bignum.rs", "BN_set_flags"): (
        F, "object_state", "one flag write", None),
    ("src/bn/bignum.rs", "BN_with_flags"): (
        F, "object_state", "one flag write", None),
    ("src/bn/bignum.rs", "BN_consttime_swap"): (
        F, "object_state",
        "both operands are reserved before the loop, and every loop step is total; no fallible operation exists inside the swap", None),
    ("src/bn/bignum.rs", "BN_bin2bn"): (
        F, "object_state",
        "the limbs are decoded into a local vector and stored once", None),
    ("src/bn/bignum.rs", "BN_lebin2bn"): (
        F, "object_state",
        "as `BN_bin2bn`, with the byte order reversed before the single store", None),
    ("src/bn/bignum.rs", "BN_bn2bin"): (
        F, "object_state",
        "the magnitude is copied into the caller's buffer; the `BIGNUM` is read-only and no library field changes (the caller buffer residual is the §4 non-claim)", None),
    ("src/bn/bignum.rs", "BN_bn2mpi"): (
        F, "object_state",
        "the encoding is written into the caller's buffer or a fresh owned buffer; the `BIGNUM` is read-only", None),
    ("src/bn/bignum.rs", "BN_mpi2bn"): (
        F, "object_state",
        "the decoded limbs are built locally and stored once", None),

    # ---- BN_CTX / BN_GENCB ----------------------------------------------
    ("src/bn/ctx.rs", "BN_CTX_free"): (
        F, "object_state", "one release of the pool and the context", None),
    ("src/bn/ctx.rs", "BN_CTX_start"): (
        F, "object_state", "one mark pushed onto the context's stack", None),
    ("src/bn/ctx.rs", "BN_CTX_get"): (
        F, "object_state",
        "pool growth is fallible and precedes `used += 1`; a fresh value is cleared before it is handed out", None),
    ("src/bn/ctx.rs", "BN_GENCB_new"): (
        F, "object_state", "local construction, no publication before success", None),
    ("src/bn/ctx.rs", "BN_GENCB_free"): (
        F, "object_state", "one release", None),

    # ---- BN_BLINDING -----------------------------------------------------
    ("src/bn/blinding.rs", "BN_BLINDING_new"): (
        F, "object_state",
        "the handle owns the block from the start; every failure arm releases it through `Drop` without publishing it", None),
    ("src/bn/blinding.rs", "BN_BLINDING_free"): (
        F, "object_state", "one release of the block and its members", None),
    ("src/bn/blinding.rs", "BN_BLINDING_invert_ex"): (
        F, "object_state",
        "the multiply it delegates to computes into a local magnitude and stores the result only after all fallible work", None),
    ("src/bn/blinding.rs", "BN_BLINDING_update"): (
        F, "object_state",
        "both squares are computed into `TempBn`s and published, with the counter, only after both succeed (fixed in this batch)", None),
    ("src/bn/blinding.rs", "BN_BLINDING_convert_ex"): (
        F, "object_state",
        "the counter advance is a complete state, `r` receives the current inverse, and the `n` multiply is atomic in its callee", None),
    ("src/bn/blinding.rs", "BN_BLINDING_create_param"): (
        F, "object_state",
        "the factor, its inverse and the exponent are computed into temporaries and published only after every fallible step (fixed in this batch)", None),

    # ---- CRYPTO_EX_DATA --------------------------------------------------
    ("src/runtime/ex_data.rs", "CRYPTO_get_ex_new_index"): (
        F, "object_state",
        "a registry slot is appended under the lock; no caller object is touched", None),
    ("src/runtime/ex_data.rs", "CRYPTO_set_ex_data"): (
        F, "object_state",
        "padding pushes precede the single element write; a failed push leaves only NULL padding", None),
    ("src/runtime/ex_data.rs", "CRYPTO_get_ex_data"): (
        F, "object_state", "read-only lookup", None),
    ("src/runtime/ex_data.rs", "CRYPTO_new_ex_data"): (
        X, "callback_state",
        "the container is zeroed and then populated by application `new_func` callbacks; a callback that panics leaves the slots it had already filled",
        "generic extension container, not a cryptographic context; callback-driven; recorded, not fixed in this batch"),
    ("src/runtime/ex_data.rs", "CRYPTO_free_ex_data"): (
        X, "callback_state",
        "free callbacks run before the slot stack is released and the container zeroed; a callback that panics leaves the stack and the zeroing undone",
        "generic extension container; callback-driven; recorded, not fixed in this batch"),
    ("src/runtime/ex_data.rs", "CRYPTO_dup_ex_data"): (
        X, "callback_state",
        "the destination is filled slot by slot; a `dup_func` or allocation failure returns 0 with the earlier slots already written",
        "generic extension container; recorded, not fixed in this batch"),

    # ---- ASN1_OBJECT / OBJ_NAME registry --------------------------------
    ("src/runtime/obj.rs", "OBJ_nid2obj"): (
        F, "object_state", "read-only lookup of a cached object", None),
    ("src/runtime/obj.rs", "OBJ_nid2sn"): (
        F, "object_state", "read-only lookup", None),
    ("src/runtime/obj.rs", "OBJ_nid2ln"): (
        F, "object_state", "read-only lookup", None),
    ("src/runtime/obj.rs", "OBJ_txt2obj"): (
        F, "object_state", "the object is built locally and returned only on success", None),
    ("src/runtime/obj.rs", "OBJ_txt2nid"): (
        F, "object_state", "parse and lookup; no caller object is mutated", None),
    ("src/runtime/obj.rs", "OBJ_length"): (
        F, "object_state", "read-only accessor", None),
    ("src/runtime/obj.rs", "OBJ_get0_data"): (
        F, "object_state", "read-only accessor", None),
    ("src/runtime/obj.rs", "OBJ_create"): (
        F, "object_state",
        "the record is built locally and inserted under the registry lock; a consumed NID is the authority's own observable", None),
    ("src/runtime/obj.rs", "OBJ_add_object"): (
        F, "object_state", "the record is built locally and inserted under the registry lock", None),
    ("src/runtime/obj.rs", "OBJ_add_sigid"): (
        F, "object_state", "a registry append under the lock", None),
    ("src/runtime/obj.rs", "OBJ_sigid_free"): (
        F, "object_state", "the registry is cleared under the lock", None),
    ("src/runtime/obj.rs", "OBJ_NAME_new_index"): (
        F, "object_state", "a comparator/destructor slot is appended under the lock", None),
    ("src/runtime/obj.rs", "OBJ_NAME_add"): (
        F, "object_state",
        "the entry is published under the lock before the replaced record is retired; a deferred destructor's failure cannot leave the registry inconsistent", None),
    ("src/runtime/obj.rs", "OBJ_NAME_remove"): (
        F, "object_state", "the entry is removed under the lock before its deferred release", None),
    ("src/runtime/obj.rs", "OBJ_NAME_cleanup"): (
        F, "object_state", "the registry is cleared under the lock", None),
}


def load_enumerator():
    spec = importlib.util.spec_from_file_location(
        "haz16_enumerate", HERE / "enumerate_ffi_mutation.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    enum = load_enumerator()
    # Re-run the enumerator in-process so the counts and the covered set come
    # from the current source tree.
    import io
    import contextlib

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        enum.main()
    census = json.loads(buf.getvalue())

    candidates = [
        r for r in census["candidates"] if r["file"] in COVERED_FILES
    ]
    covered = {(r["file"], r["name"]) for r in candidates}
    missing = sorted(covered - set(DISPOSITIONS))
    extra = sorted(set(DISPOSITIONS) - covered)
    if missing:
        sys.stderr.write(
            "covered entries without a disposition: "
            + ", ".join(f"{f}:{n}" for f, n in missing)
            + "\n"
        )
        return 2
    if extra:
        sys.stderr.write(
            "dispositions for entries no longer in the covered set: "
            + ", ".join(f"{f}:{n}" for f, n in extra)
            + "\n"
        )
        return 2

    rows = []
    for r in candidates:
        key = (r["file"], r["name"])
        cls, concern, basis, residual = DISPOSITIONS[key]
        rows.append(
            {
                "file": r["file"],
                "entry": r["name"],
                "class": cls,
                "concern": concern,
                "basis": basis,
                "residual": residual,
            }
        )
    rows.sort(key=lambda row: (row["file"], row["entry"]))

    counts = {F: 0, R: 0, P: 0, X: 0}
    for row in rows:
        counts[row["class"]] += 1

    try:
        head = subprocess.check_output(
            ["git", "rev-parse", "--short=9", "HEAD"], cwd=ROOT, text=True
        ).strip()
        branch = subprocess.check_output(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=ROOT, text=True
        ).strip()
        status = subprocess.check_output(
            ["git", "status", "--porcelain"], cwd=ROOT, text=True
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        head, branch, status = "UNKNOWN", "UNKNOWN", "UNKNOWN"

    doc = {
        "schema": "openssl-rs/etp/haz-16-classification/1",
        "kind": "ffi_failure_atomicity_classification",
        "hazard": "HAZ-16",
        "identity": {
            "repository": "openssl-rs",
            "head": head,
            "branch": branch,
            "worktree": "clean" if not status else "dirty at generation time",
            "note": "generated by evidence/haz-16/build_classification.py from the current tree",
        },
        "enumeration": {
            "script": "evidence/haz-16/enumerate_ffi_mutation.py",
            "method": census["method"],
            "scripts_scanned": census["scripts_scanned"],
            "exported_functions_found": census["exported_functions_found"],
            "guard_ffi_wrapped": census["guard_ffi_wrapped"],
            "mutation_candidates": census["mutation_candidates"],
            "covered_files": COVERED_FILES,
            "covered_population": len(rows),
            "excluded_reason": (
                "The remaining mutation candidates are in consumers (ssl, asn1, params, engine, "
                "async, dso, selftest, context, txt_db, provider) that do not own a "
                "security-relevant context in the HAZ-16 object list, or in evp/rsa/ec/x509, "
                "which do not use guard_ffi (a panic there aborts at the extern \"C\" boundary "
                "rather than leaving a caught partial state). They are NOT_AUDITED here and are "
                "not claimed atomic."
            ),
        },
        "classes": {
            "definition": {
                F: "no observable partial object state is possible",
                R: "an explicit compensating action restores a consistent prior or prefix state",
                P: "the object refuses further use with a defined outcome",
                X: "a caller can observe or use inconsistent state",
            },
            "counts": counts,
            "total": len(rows),
        },
        "fixed_in_this_batch": [
            {
                "entry": "BN_BLINDING_update",
                "file": "src/bn/blinding.rs",
                "pre_fix_class": X,
                "mechanism": "failure-atomic publication of two squarings plus counter commit/rollback",
                "test": "bn::blinding::tests::a_panic_between_the_blinding_squares_leaves_the_factor_pair_usable",
                "revert_control": "the same test fails on `round_trip_cancels` when the inverse square is published before the factor square is computed",
            },
            {
                "entry": "BN_BLINDING_create_param",
                "file": "src/bn/blinding.rs",
                "pre_fix_class": X,
                "mechanism": "failure-atomic publication of the factor, its inverse and the exponent",
                "test": "bn::blinding::tests::a_panic_after_the_blinding_draw_does_not_publish_the_new_factor",
                "revert_control": "the same test fails on `round_trip_cancels` when the fresh factor is copied into the context before its inverse is computed",
            },
            {
                "entry": "OPENSSL_sk_pop_free",
                "file": "src/runtime/stack.rs",
                "pre_fix_class": X,
                "mechanism": "remove-before-release, so a released element is never reachable from the stack",
                "test": "runtime::stack::tests::a_panic_during_pop_free_leaves_only_unreleased_elements_reachable",
                "revert_control": "the same test fails with `sk_num(st) == 2` when the in-place iteration is restored",
            },
        ],
        "rows": rows,
        "non_claims": [
            "Not a claim of universal failure atomicity: the covered population is the nine object-owner files above, and the rest of the guard_ffi surface is NOT_AUDITED.",
            "Not a claim that evp/rsa/ec/x509 entry points are panic-atomic: they do not call guard_ffi, so a panic there aborts at Rust's extern \"C\" boundary instead of being caught with a partially mutated object. That is a different defect class and was not changed here.",
            "A caller-supplied output buffer can be partially written if a defect panics mid-copy (BN_bn2bin, BN_bn2mpi, BIO_gets/get_line). The return value remains the documented failure signal and no library object is inconsistent; this is a non-claim, not an atomicity result.",
            "The three PARTIAL_EXPOSED rows are CRYPTO_EX_DATA callback-driven container state. They are recorded rather than fixed because the object is a generic extension slot container, not a key/nonce/plaintext/digest/verified-chain context, and the partial population is produced by application callbacks.",
            "No timing, Miri or sanitizer result is claimed here; the evidence is the unit suite and the revert controls recorded in RECEIPT.md.",
        ],
    }

    (HERE / "CLASSIFICATION.json").write_text(
        json.dumps(doc, indent=2, sort_keys=False) + "\n", encoding="utf-8"
    )
    sys.stdout.write(
        f"wrote CLASSIFICATION.json: {len(rows)} covered entries; "
        f"{F}={counts[F]}, {R}={counts[R]}, {P}={counts[P]}, {X}={counts[X]}\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
