#!/usr/bin/env python3
"""Mutation driver: show each external control fires.

For each mutant, copy `src/` to court/freeze-b78/review2/mutants/<id>/src,
apply exactly one textual mutation, run the chosen check, and report
PASS/FAIL.  A control "fires" when the mutant turns it FAIL (or, for the
negative control C6, when restoring the missing statement turns it PASS).

Nothing outside court/freeze-b78/review2/ is written.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(".").resolve()
BASE = ROOT / "court/freeze-b78/review2/mutants"
SRC = ROOT / "src"
CTRL = ROOT / "court/freeze-b78/review2/controls.py"

MUTANTS = [
    {
        "id": "M1_bio_deref",
        "check": "C2_bio_empty_body",
        "file": "src/runtime/bio/bf_readbuff.rs",
        "old": "unsafe extern \"C\" fn readbuffer_write(_b: *mut Bio, _in: *const c_char, _inl: c_int) -> c_int {\n    0\n}",
        "new": "unsafe extern \"C\" fn readbuffer_write(b: *mut Bio, _in: *const c_char, _inl: c_int) -> c_int {\n    if b.is_null() { return 0; }\n    unsafe { (*b).shutdown } as c_int\n}",
    },
    {
        "id": "M2_engine_toctou",
        "check": "C3_engine_cleanup_lock_order",
        "file": "src/engine/eng_list.rs",
        "old": "        if !lock() {\n            return;\n        }\n        let head = ENGINE_LIST_HEAD.load(Ordering::Acquire);",
        "new": "        let head = ENGINE_LIST_HEAD.load(Ordering::Acquire);\n        if !lock() {\n            return;\n        }",
    },
    {
        "id": "M3_sslconf_no_guard",
        "check": "C5_sslconf_entry_guard",
        "file": "src/ssl/ssl_conf.rs",
        "old": "        let Some(_in_use) = (unsafe { enter_use(cctx) }) else {\n            return 0;\n        };\n        // SAFETY: `cctx`/`cmd`/`value` are per the caller's contract; `_in_use` holds the",
        "new": "        // SAFETY: `cctx`/`cmd`/`value` are per the caller's contract; `_in_use` holds the",
    },
    {
        "id": "M4_contract_removed",
        "check": "C1_contract_site_present",
        "file": "src/engine/eng_fat.rs",
        "old": "/// # Safety\n/// `p` must be NULL or point to a NUL-terminated C string that stays readable for the duration of\n/// the call.",
        "new": "/// The string is rendered.",
    },
    {
        "id": "M5_callback_invoked",
        "check": "C4_callbacks_never_invoked",
        "file": "src/ssl/statem/extensions_cust.rs",
        "old": "pub(crate) fn custom_exts_copy(dst: &mut Vec<CustomExtMethod>, src: &[CustomExtMethod]) -> c_int {\n    if !src.is_empty() {\n        dst.clear();\n        dst.extend_from_slice(src);\n    }\n    1\n}",
        "new": "pub(crate) fn custom_exts_copy(dst: &mut Vec<CustomExtMethod>, src: &[CustomExtMethod]) -> c_int {\n    if !src.is_empty() {\n        dst.clear();\n        dst.extend_from_slice(src);\n    }\n    for m in src.iter() {\n        if !m.parse_cb.is_null() {\n            let f: CustomExtParseCb = unsafe { core::mem::transmute(m.parse_cb) };\n            let _ = f;\n        }\n    }\n    1\n}",
    },
    {
        "id": "M6_exclusivity_stated",
        "check": "C6_cipher_list_exclusivity_stated",
        "edits": [
            (
                "src/ssl/ssl_lib.rs",
                "/// `ctx` must be NULL or live; `str` NULL or NUL-terminated.\n#[no_mangle]\npub unsafe extern \"C\" fn SSL_CTX_set_cipher_list",
                "/// `ctx` must be NULL or live; `str` NULL or NUL-terminated; the caller must have exclusive\n/// access to `ctx` and no other reference to its cipher-list slots may be live.\n#[no_mangle]\npub unsafe extern \"C\" fn SSL_CTX_set_cipher_list",
            ),
            (
                "src/ssl/ssl_lib.rs",
                "/// `s` must be NULL or live; `str` NULL or NUL-terminated.\n#[no_mangle]\npub unsafe extern \"C\" fn SSL_set_cipher_list",
                "/// `s` must be NULL or live; `str` NULL or NUL-terminated; the caller must have exclusive\n/// access to `s` and no other reference to its cipher-list slots may be live.\n#[no_mangle]\npub unsafe extern \"C\" fn SSL_set_cipher_list",
            ),
            (
                "src/ssl/ssl_ciph.rs",
                "/// `ctx` must be NULL or live; `str` NULL or NUL-terminated.\n#[no_mangle]\npub unsafe extern \"C\" fn SSL_CTX_set_ciphersuites",
                "/// `ctx` must be NULL or live; `str` NULL or NUL-terminated; the caller must have exclusive\n/// access to `ctx` and no other reference to its cipher-list slots may be live.\n#[no_mangle]\npub unsafe extern \"C\" fn SSL_CTX_set_ciphersuites",
            ),
            (
                "src/ssl/ssl_ciph.rs",
                "/// `s` must be NULL or live; `str` NULL or NUL-terminated.\n#[no_mangle]\npub unsafe extern \"C\" fn SSL_set_ciphersuites",
                "/// `s` must be NULL or live; `str` NULL or NUL-terminated; the caller must have exclusive\n/// access to `s` and no other reference to its cipher-list slots may be live.\n#[no_mangle]\npub unsafe extern \"C\" fn SSL_set_ciphersuites",
            ),
        ],
    },
    {
        "id": "M7_safe_freehook_call",
        "check": "C7_freehooks_not_safely_called",
        "file": "src/runtime/confmod/mod.rs",
        "old": "pub extern \"C\" fn CONF_modules_unload(all: c_int) {\n    guard_ffi((), || {\n        if !conf_modules_finish_int() {\n            return;\n        }",
        "new": "pub extern \"C\" fn CONF_modules_unload(all: c_int) {\n    guard_ffi((), || {\n        module_free_thunk(core::ptr::null_mut());\n        if !conf_modules_finish_int() {\n            return;\n        }",
    },
]


def run_one(mid: str, check: str) -> dict:
    root = BASE / mid
    proc = subprocess.run(
        [sys.executable, str(CTRL), str(root), check],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        return {"result": "ERROR", "detail": [proc.stderr.strip()[-400:]]}
    return json.loads(proc.stdout)[check]


def main():
    BASE.mkdir(parents=True, exist_ok=True)
    report = {}
    for mu in MUTANTS:
        dest = BASE / mu["id"]
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(SRC, dest / "src")
        edits = mu.get("edits") or [(mu["file"], mu["old"], mu["new"])]
        apply_fail = None
        for rel, old, new in edits:
            target = dest / rel
            text = target.read_text(encoding="utf-8")
            if old not in text:
                apply_fail = f"mutation anchor not found in {rel}"
                break
            target.write_text(text.replace(old, new, 1), encoding="utf-8")
        if apply_fail:
            report[mu["id"]] = {"applied": False, "reason": apply_fail}
            shutil.rmtree(dest)
            continue
        res = run_one(mu["id"], mu["check"])
        # For every control except the negative control C6, a mutant must FAIL
        # (fire).  C6 is a negative control: the mutant restores the missing
        # statement, so it must PASS.
        expect = "PASS" if mu["check"] == "C6_cipher_list_exclusivity_stated" else "FAIL"
        report[mu["id"]] = {
            "applied": True,
            "check": mu["check"],
            "mutant_result": res["result"],
            "detail": res["detail"],
            "expected": expect,
            "fired": res["result"] == expect,
        }
        shutil.rmtree(dest)
    print(json.dumps(report, indent=1))


if __name__ == "__main__":
    main()
