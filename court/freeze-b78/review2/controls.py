#!/usr/bin/env python3
"""External source-level controls for the 21-obligation review.

Not a substitute for the in-repo runtime controls (which cannot be run under the
current memory floor); these are independent, load-bearing source checks that
detect the defect each obligation's argument depends on.  Each check returns
PASS/FAIL and a short detail.  The driver (`mutate.py`) applies one mutation to
a copy of the tree and shows the corresponding check turning FAIL, i.e. firing.

Usage:
  python3 controls.py <src-root>        # default: ./src
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path


def strip(text: str) -> str:
    root = Path(__file__).resolve().parents[3]
    sys.path.insert(0, str(root / "forensics/memory-safety/campaign/safe-c33"))
    import atlas_refresh as atlas

    return atlas.strip_comments_and_literals(text)


def read(root: Path, rel: str) -> str:
    return (root / rel).read_text(encoding="utf-8", errors="replace")


def body_of(text: str, name: str) -> str | None:
    m = re.search(r"\bfn\s+" + re.escape(name) + r"\b", text)
    if not m:
        return None
    p = text.find("{", m.end())
    if p < 0:
        return None
    depth = 0
    i = p
    while i < len(text):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[p + 1 : i]
        i += 1
    return None


def doc_block_above(text: str, name: str):
    """Return the contiguous /// doc block above the item, skipping attributes."""
    m = re.search(r"\bfn\s+" + re.escape(name) + r"\b", text)
    if not m:
        return None
    lines = text[: m.start()].split("\n")
    j = len(lines) - 1
    # the partial line holding the item qualifiers (`pub unsafe extern "C" `)
    if not lines[j].lstrip().startswith("#[") and not lines[j].lstrip().startswith("///"):
        j -= 1
    while j >= 0 and lines[j].lstrip().startswith("#["):
        j -= 1
    doc = []
    while j >= 0 and lines[j].lstrip().startswith("///"):
        doc.insert(0, lines[j])
        j -= 1
    return doc


def c1_contract_site(root: Path):
    """Every obligation needs a # Safety at the definition, or an explicit
    vacuous-precondition marker (the empty BIO callbacks)."""
    targets = [
        ("src/engine/eng_dyn.rs", "dynamic_data_ctx_free_func", True),
        ("src/engine/eng_fat.rs", "push_cstr_or_null", True),
        ("src/engine/eng_list.rs", "engine_list_cleanup", True),
        ("src/runtime/bio/bf_readbuff.rs", "readbuffer_write", False),
        ("src/runtime/bio/bf_readbuff.rs", "readbuffer_puts", False),
        ("src/runtime/confmod/mod.rs", "module_free_thunk", True),
        ("src/ui/ui_util.rs", "ui_free_method_data", True),
        ("src/ssl/ssl_ciph.rs", "update_cipher_list_by_id", True),
        ("src/ssl/ssl_ciph.rs", "set_ciphersuites", True),
        ("src/ssl/ssl_conf.rs", "ssl_match_option", True),
        ("src/ssl/ssl_conf.rs", "ssl_set_option_list", True),
        ("src/ssl/ssl_conf.rs", "min_max_proto", True),
        ("src/ssl/ssl_conf.rs", "cmd_Protocol", True),
        ("src/ssl/ssl_conf.rs", "cmd_Options", True),
        ("src/ssl/ssl_conf.rs", "cmd_VerifyMode", True),
        ("src/ssl/ssl_conf.rs", "cmd_CipherString", True),
        ("src/ssl/ssl_conf.rs", "cmd_Ciphersuites", True),
        ("src/ssl/ssl_conf.rs", "cmd_MinProtocol", True),
        ("src/ssl/ssl_conf.rs", "cmd_MaxProtocol", True),
        ("src/ssl/ssl_rsa.rs", "serverinfoex_srv_parse_cb", True),
        ("src/ssl/ssl_rsa.rs", "serverinfo_srv_parse_cb", True),
    ]
    failures = []
    for rel, name, needs in targets:
        text = read(root, rel)
        m = re.search(r"\bfn\s+" + re.escape(name) + r"\b", text)
        if not m:
            failures.append(f"{name}: definition not found")
            continue
        head = text[: m.start()]
        doc = doc_block_above(text, name) or []
        has_safety = any(re.search(r"#\s*Safety", d) for d in doc)
        if needs and not has_safety:
            failures.append(f"{name}: no # Safety at definition ({rel})")
        if not needs:
            body = body_of(text, name)
            if body is None or not re.fullmatch(r"\s*0\s*", body):
                failures.append(f"{name}: expected a vacuous `0` body, got {body!r}")
    return not failures, failures


def c2_bio_empty_body(root: Path):
    failures = []
    text = read(root, "src/runtime/bio/bf_readbuff.rs")
    for name in ("readbuffer_write", "readbuffer_puts"):
        body = body_of(text, name)
        if body is None or not re.fullmatch(r"\s*0\s*", body):
            failures.append(f"{name}: body is not exactly `0`: {body!r}")
            continue
        stripped = strip(body)
        for bad in ("*", "unsafe", "(", "let ", "static", "CStr"):
            if bad in stripped:
                failures.append(f"{name}: body contains {bad!r}")
    return not failures, failures


def c3_engine_cleanup_lock_order(root: Path):
    failures = []
    text = read(root, "src/engine/eng_list.rs")
    body = body_of(text, "engine_list_cleanup")
    if body is None:
        return False, ["engine_list_cleanup: body not found"]
    b = strip(body)
    i_lock = b.find("lock()")
    i_head = b.find("ENGINE_LIST_HEAD")
    i_remove = b.find("engine_list_remove")
    if i_lock < 0:
        failures.append("no lock() in the body")
    if i_head < 0:
        failures.append("no head load in the body")
    if i_remove < 0:
        failures.append("no engine_list_remove in the body")
    if i_lock >= 0 and i_head >= 0 and not (i_lock < i_head):
        failures.append("the head is read before the lock is taken (TOCTOU shape)")
    if i_head >= 0 and i_remove >= 0 and not (i_head < i_remove):
        failures.append("the head is not read before the removal")
    # the removal must be inside the lock-held region: after the removal the
    # body must unlock before the next iteration.
    i_unlock = b.find("unlock()", i_remove + 1) if i_remove >= 0 else -1
    if i_unlock >= 0 and i_remove >= 0 and not (i_lock < i_remove < i_unlock):
        failures.append("engine_list_remove is not between lock() and the following unlock()")
    return not failures, failures


def c4_callbacks_never_invoked(root: Path):
    failures = []
    for rel in ("src/ssl/statem/extensions_cust.rs", "src/ssl/ssl_rsa.rs"):
        text = strip(read(root, rel))
        for slot in ("parse_cb", "add_cb"):
            for m in re.finditer(r"\b" + slot + r"\b", text):
                tail = text[m.end() : m.end() + 120]
                if re.search(r"\bas\s+(?:unsafe\s+)?extern|transmute|\(.*\)\s*\(", tail):
                    failures.append(f"{rel}:{text.count(chr(10), 0, m.start())+1}: {slot} appears to be cast/invoked")
    cust = read(root, "src/ssl/statem/extensions_cust.rs")
    if "never invoked" not in cust and "never calls either" not in cust:
        failures.append("extensions_cust.rs no longer records the non-invocation fact")
    return not failures, failures


def c5_sslconf_entry_guard(root: Path):
    failures = []
    text = read(root, "src/ssl/ssl_conf.rs")
    for m in re.finditer(r'pub\s+unsafe\s+extern\s+"C"\s+fn\s+([A-Za-z_][A-Za-z0-9_]*)', text):
        name = m.group(1)
        # parameter list
        p = text.find("(", m.end())
        depth = 0
        q = p
        while q < len(text):
            if text[q] == "(":
                depth += 1
            elif text[q] == ")":
                depth -= 1
                if depth == 0:
                    break
            q += 1
        params = text[p : q + 1]
        if "SslConfCtx" not in params:
            continue
        body = body_of(text, name)
        if body is None:
            continue
        if "enter_use" not in body:
            failures.append(f"{name}: takes *mut SslConfCtx but never calls enter_use")
    return not failures, failures


def c6_cipher_list_exclusivity_stated(root: Path):
    """Negative control: the public setters must state the exclusive-access
    precondition that update_cipher_list_by_id/set_ciphersuites require."""
    failures = []
    targets = [
        ("src/ssl/ssl_lib.rs", "SSL_CTX_set_cipher_list"),
        ("src/ssl/ssl_lib.rs", "SSL_set_cipher_list"),
        ("src/ssl/ssl_ciph.rs", "SSL_CTX_set_ciphersuites"),
        ("src/ssl/ssl_ciph.rs", "SSL_set_ciphersuites"),
    ]
    for rel, name in targets:
        text = read(root, rel)
        m = re.search(r"\bfn\s+" + re.escape(name) + r"\b", text)
        if not m:
            failures.append(f"{name}: not found")
            continue
        doc = doc_block_above(text, name) or []
        d = " ".join(x.lower() for x in doc)
        if not re.search(r"exclusive|no other (shared|reference)|not concurrently|concurrent", d):
            failures.append(f"{name}: # Safety does not state the exclusive-access precondition")
    return not failures, failures


def inside_unsafe_block(text: str, pos: int) -> bool:
    """Approximate lexical test: is `pos` inside an `unsafe { ... }` block?"""
    depth = 0
    i = pos
    while i > 0:
        i -= 1
        c = text[i]
        if c == "}":
            depth += 1
        elif c == "{":
            if depth == 0:
                head = text[max(0, i - 16) : i]
                return bool(re.search(r"unsafe\s*$", head))
            depth -= 1
    return False


def c7_freehooks_not_safely_called(root: Path):
    """Each free hook may appear only at its definition and in a registration
    (`Some(NAME)`), or in a call from an unsafe fn."""
    import io
    import contextlib

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import surface

    failures = []
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        records, files, by_name = surface.build_records()
    hooks = {
        ("src/engine/eng_dyn.rs", "dynamic_data_ctx_free_func"),
        ("src/runtime/confmod/mod.rs", "module_free_thunk"),
        ("src/ui/ui_util.rs", "ui_free_method_data"),
        ("src/engine/eng_list.rs", "engine_list_cleanup"),
        ("src/runtime/bio/bf_readbuff.rs", "readbuffer_write"),
        ("src/runtime/bio/bf_readbuff.rs", "readbuffer_puts"),
    }
    for rel, name in hooks:
        text = strip(read(root, rel))
        dm = re.search(r"\bfn\s+" + name + r"\b", text)
        def_name_pos = dm.end() - len(name) if dm else None
        for mm in re.finditer(r"\b" + name + r"\b", text):
            if def_name_pos is not None and mm.start() == def_name_pos:
                continue  # the definition itself
            before = text[max(0, mm.start() - 16) : mm.start()]
            after = text[mm.end() : mm.end() + 3]
            if re.search(r"Some\(\s*$", before):
                continue  # registration: Some(NAME)
            if after.lstrip().startswith("("):
                enc = None
                for r in records:
                    if r["file"] != rel or r["body_start"] is None:
                        continue
                    if r["body_start"] < mm.start() < r["body_end"]:
                        enc = r
                if enc is None:
                    # outside any function body: a static initialiser, allow
                    continue
                if inside_unsafe_block(text, mm.start()):
                    continue
                if not enc["unsafe"]:
                    failures.append(
                        f"{name}: direct call from safe fn {enc['name']} outside an unsafe block ({rel}:{text.count(chr(10), 0, mm.start())+1})"
                    )
    return not failures, failures


CHECKS = [
    ("C1_contract_site_present", c1_contract_site),
    ("C2_bio_empty_body", c2_bio_empty_body),
    ("C3_engine_cleanup_lock_order", c3_engine_cleanup_lock_order),
    ("C4_callbacks_never_invoked", c4_callbacks_never_invoked),
    ("C5_sslconf_entry_guard", c5_sslconf_entry_guard),
    ("C6_cipher_list_exclusivity_stated", c6_cipher_list_exclusivity_stated),
    ("C7_freehooks_not_safely_called", c7_freehooks_not_safely_called),
]


def run(root: Path, only=None):
    out = {}
    for name, fn in CHECKS:
        if only and name not in only:
            continue
        try:
            ok, detail = fn(root)
        except Exception as e:  # noqa: BLE001 - a control error is a failure
            ok, detail = False, [f"control error: {e!r}"]
        out[name] = {"result": "PASS" if ok else "FAIL", "detail": detail}
    return out


if __name__ == "__main__":
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("src")
    print(json.dumps(run(root), indent=1))
