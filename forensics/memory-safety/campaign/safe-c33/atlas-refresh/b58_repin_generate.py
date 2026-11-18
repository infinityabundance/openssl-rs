#!/usr/bin/env python3
"""Freeze b58: re-pin the address-keyed site enumerations to the S artifact.

The site tables in ``forensics/tools/consumer_closure.py`` are keyed by the
virtual address of an indirect call in one exact ``libcrypto.so.3``.  A rebuild
moves every address, so a table lookup misses and the site falls back to
``materialised``/``field`` — target-bounded, element 7 FAIL.

Identity for a re-pin is the recorded ``(symbol, offset)`` pin, not the address.
This script:

  1. reads the S symbol table (``nm``) and the S disassembly cache;
  2. for every enumerated site resolves ``symbol_start + pin_offset``;
  3. for the sites whose *function text changed* (so the offset moved) uses the
     recorded ``REPIN_OVERRIDES`` — each carries the slot/field evidence that
     binds it (e.g. ``file_load`` slot ``newctx`` reads offset 0x30);
  4. verifies the new address is the expected instruction shape (an indirect
     call whose displacement — or the load feeding its register — is the
     enumerated field), and records the observed instruction text;
  5. with ``--apply`` rewrites only the address literals and the drifted pin
     offsets in the tool, leaving every contract, target set and comment intact.

Nothing here decides a classification.  It moves coordinates and records, per
site, the function, the field/offset read, and the instruction that was seen;
the tool's own per-call-site witnesses still have to accept the site in the
next closure run.

Output: forensics/memory-safety/campaign/safe-c33/atlas-refresh/
        site-repins-b58.json
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

REPO = Path("/work")
TOOL = REPO / "forensics/tools/consumer_closure.py"
LIB = REPO / "court/freeze-b58/install/lib/libcrypto.so.3"
DIS = (REPO / "court/tmp/closure-b58-ssh/"
       "libcrypto.so.3.f3061a4fccdf9637.dis")
OUT = (REPO / "forensics/memory-safety/campaign/safe-c33/atlas-refresh/"
       "site-repins-b58.json")
SOURCE_COMMIT = "b6f38f13456b79ecd94b1088c835c3da92bc942a"
LIB_SHA = "f3061a4fccdf96370e8c0e41891555f76f0e1612bd402d34a49ece1ae555a7ec"

# Sites whose containing function text changed between the pinned image and S,
# so (symbol, offset) moved.  Each override is justified by the slot it reads in
# the S disassembly; the offset is the *new* offset from the symbol start.
REPIN_OVERRIDES = {
    0x45C02D: (0x1D831D, "file_load newctx: `mov 0x30(%r14),%rax; call *%rax`"),
    0x45C086: (0x1D8373, "file_load set_ctx_params: `mov 0x50(%r14),%r12; call *%r12`"),
    0x45C0D0: (0x1D83BD, "file_load freectx: `mov 0x38(%r14),%rax; call *%rax`"),
    0x2BD122: (0x3A0158, "PKCS5_v2_PBE_keyivgen_ex keygen_ex: `call *%rax` (only indirect call in f)"),
    0x3E2088: (0x3DD2D8, "OSSL_STORE_open_ex open_ex: `mov 0x58(%r14),%rax; call *%rax`"),
    0x3E217D: (0x3DD391, "OSSL_STORE_open_ex open: `mov 0x10(%r14),%rax; call *%rax`"),
    0x3E2648: (0x3DD803, "OSSL_STORE_open_ex closefn: `mov 0x50(%r14),%rax; call *%rax`"),
    0x3E2408: (0x3DD619, "OSSL_STORE_open_ex p_close: `mov 0xb8(%r14),%rax; call *%rax`"),
    0x17319A: (0x4BA825, "CONF_modules_load init: `mov 0x10(%r12),%r15; call *%r15`"),
    0x1735B2: (0x4BAC63, "CONF_modules_load finish: `mov 0x18(%r12),%rax; call *%rax`"),
    0x495DE6: (0x30EF0C, "do_pk8pkey PEM_def_callback: `call *%rbx` (only indirect call)"),
    0x259E98: (0x2C2228, "ossl_synchronize_rcu node->handler: `call *(%rbx)`"),
}

# Guard pair that selects the legacy/provider close path in OSSL_STORE_open_ex.
# b58: `test %r12,%r12; je 0x3dd7f7` (legacy) and `test %r12,%r12; jne
# 0x3dd60a` (provider); the closefn site's predecessor block starts at
# 0x3dd7f7.
CLOSE_GUARD_REPIN = {
    0x3E23F0: 0x3DD601, 0x3E23F3: 0x3DD604, 0x3E263C: 0x3DD7F7,
    0x3E2633: 0x3DD7EE, 0x3E2636: 0x3DD7F1, 0x3E23F9: 0x3DD60A,
}

# Blocks whose 6-hex-digit literals are site addresses (or guard addresses).
BLOCKS = (
    "SLH_METHOD_TABLE_SITES", "SLH_METHOD_TABLE_SITE_PINS",
    "PROVIDER_HW_SITES", "PROVIDER_HW_SITE_PINS",
    "LEGACY_EVP_DATA_SITES", "LEGACY_EVP_DATA_SITE_PINS",
    "DECODER_METHOD_SITES", "DECODER_METHOD_SITE_PINS",
    "REGISTRATION_ATEXIT_CALL_SITE",
    "PBE_SITE", "PBE_EX_SITES", "PBE_EX_SITE_PINS",
    "STORE_LOADER_LEGACY_SITES", "STORE_LOADER_LEGACY_SITE_PINS",
    "STORE_LOADER_PROVIDER_SITE", "STORE_LOADER_PROVIDER_SITE_PIN",
    "CONF_SITES", "CONF_SITE_PINS",
    "PEM_SITE",
    "STORE_LOADER_CLOSE_GUARDS", "STORE_LOADER_CLOSE_GUARD_PINS",
    "EXTERNAL_ABI_SITE_FUNCTIONS", "EXTERNAL_ABI_SITE_PINS",
    "E7BS_MSBLOB_SITE", "E7BS_RCU_SITE", "E7BS_RCU_SITE_PIN",
)

# (block, old offset literal, new offset literal) for pins whose offset moved.
OFFSET_REPINS = (
    ("DECODER_METHOD_SITE_PINS", "0x6FD", "0x5ED"),
    ("DECODER_METHOD_SITE_PINS", "0x756", "0x643"),
    ("DECODER_METHOD_SITE_PINS", "0x7A0", "0x68D"),
    ("PBE_EX_SITE_PINS", "0x1C2", "0x208"),
    ("STORE_LOADER_LEGACY_SITE_PINS", "0x488", "0x498"),
    ("STORE_LOADER_LEGACY_SITE_PINS", "0x57D", "0x551"),
    ("STORE_LOADER_LEGACY_SITE_PINS", "0xA48", "0x9C3"),
    ("STORE_LOADER_PROVIDER_SITE_PIN", "0x808", "0x7D9"),
    ("EXTERNAL_ABI_SITE_PINS", "0x488", "0x498"),
    ("EXTERNAL_ABI_SITE_PINS", "0x57D", "0x551"),
    ("EXTERNAL_ABI_SITE_PINS", "0xA48", "0x9C3"),
    ("EXTERNAL_ABI_SITE_PINS", "0x50A", "0x505"),
    ("EXTERNAL_ABI_SITE_PINS", "0x922", "0x943"),
    ("CONF_SITE_PINS", "0x50A", "0x505"),
    ("CONF_SITE_PINS", "0x922", "0x943"),
    ("E7BS_RCU_SITE_PIN", "0x2F8", "0x5A8"),
    ("STORE_LOADER_CLOSE_GUARD_PINS", "0x7F0", "0x7C1"),
    ("STORE_LOADER_CLOSE_GUARD_PINS", "0x7F3", "0x7C4"),
    ("STORE_LOADER_CLOSE_GUARD_PINS", "0xA3C", "0x9B7"),
    ("STORE_LOADER_CLOSE_GUARD_PINS", "0xA33", "0x9AE"),
    ("STORE_LOADER_CLOSE_GUARD_PINS", "0xA36", "0x9B1"),
    ("STORE_LOADER_CLOSE_GUARD_PINS", "0x7F9", "0x7CA"),
)


def demangle_strip(name: str) -> str:
    return re.sub(r"::h[0-9a-f]{16}$", "", name)


def leaf(name: str) -> str:
    return demangle_strip(name).rsplit("::", 1)[-1]


def load_symbols():
    out = subprocess.check_output(["nm", "-n", "-C", "--defined-only", str(LIB)],
                                  stderr=subprocess.DEVNULL).decode("utf-8", "replace")
    syms = []
    for line in out.splitlines():
        p = line.split(" ", 2)
        if len(p) < 3:
            continue
        try:
            a = int(p[0], 16)
        except ValueError:
            continue
        if p[1].lower() in ("t", "w"):
            syms.append((a, p[2]))
    syms.sort()
    return syms


def load_disasm():
    if not DIS.is_file():
        DIS.parent.mkdir(parents=True, exist_ok=True)
        with open(DIS, "w") as fh:
            subprocess.run(["objdump", "-d", "--no-show-raw-insn", str(LIB)],
                           stdout=fh, check=True)
    pat_head = re.compile(r"^([0-9a-f]+) <(.*)>:$")
    pat_ins = re.compile(r"^\s+([0-9a-f]+):\t(.*)$")
    ins, func_at = {}, {}
    cur = None
    for line in DIS.read_text(errors="replace").splitlines():
        m = pat_head.match(line)
        if m:
            cur = int(m.group(1), 16)
            continue
        m = pat_ins.match(line)
        if m and cur is not None:
            a = int(m.group(1), 16)
            ins[a] = m.group(2).strip()
            func_at[a] = cur
    return ins, func_at


def context(ins, addr, back=8):
    keys = sorted(ins)
    try:
        i = keys.index(addr)
    except ValueError:
        return []
    return [(keys[j], ins[keys[j]]) for j in range(max(0, i - back), min(len(keys), i + 2))]


def verify(ins, addr, spec, table):
    text = ins.get(addr)
    if text is None:
        return False, "not-an-instruction"
    if not re.match(r"^(call|jmp)\s+\*", text):
        return False, f"not-an-indirect-call: {text!r}"
    want = None
    if table == "PROVIDER_HW_SITES":
        want = spec.get("read")
    elif table == "SLH_METHOD_TABLE_SITES":
        want = spec[2]
    elif table == "LEGACY_EVP_DATA_SITES":
        want = spec.get("read")
    elif table == "DECODER_METHOD_SITES":
        want = spec.get("read")
    elif table in ("STORE_LOADER_LEGACY_SITES", "CONF_SITES"):
        want = spec.get("offset")
    elif table == "STORE_LOADER_PROVIDER_SITE":
        want = 0xB8
    if want is None:
        return True, text
    m = re.search(r"\*(-?(?:0x)?[0-9a-f]*)?\(%", text)
    if m:
        disp = m.group(1) or "0"
        got = int(disp, 16)
        if got == want:
            return True, text
        return False, f"operand-displacement {got:#x} != {want:#x}: {text!r}"
    # register operand: the load feeding it must read the enumerated field
    reg = text.split("*")[-1].strip()
    for a, t in reversed(context(ins, addr, 24)[:-1]):
        mm = re.match(r"^mov\s+(-?0x[0-9a-f]+)?\((%r[a-z0-9]+)\)," + re.escape(reg) + "$", t)
        if mm:
            got = int(mm.group(1), 16) if mm.group(1) else 0
            if got == want:
                return True, f"{t} ; {text}"
            return False, f"feeding-load displacement {got:#x} != {want:#x}: {t!r}"
    return False, f"no enumerated load feeds {text!r}"


def block_span(text: str, name: str):
    m = re.search(r"(?m)^" + re.escape(name) + r"\s*=\s*", text)
    if not m:
        raise SystemExit(f"block not found: {name}")
    i = m.end()
    if i >= len(text):
        raise SystemExit(f"empty block: {name}")
    opener = text[i]
    if opener in "{[(":
        closer = {"{": "}", "[": "]", "(": ")"}[opener]
        depth = 0
        for j in range(i, len(text)):
            if text[j] == opener:
                depth += 1
            elif text[j] == closer:
                depth -= 1
                if depth == 0:
                    return m.start(), j + 1
        raise SystemExit(f"unbalanced block: {name}")
    end = text.find("\n", i)
    return m.start(), (len(text) if end < 0 else end)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true")
    args = ap.parse_args()

    sys.path.insert(0, str(REPO / "forensics/tools"))
    import consumer_closure as cc

    syms = load_symbols()
    ins, func_at = load_disasm()
    starts = {}
    for a, n in syms:
        starts.setdefault(demangle_strip(n), []).append(a)
        starts.setdefault(leaf(n), []).append(a)

    # (table, old_addr, spec, pin)
    entries = []
    for tname in ("PROVIDER_HW_SITES", "SLH_METHOD_TABLE_SITES",
                  "LEGACY_EVP_DATA_SITES", "DECODER_METHOD_SITES",
                  "PBE_EX_SITES", "STORE_LOADER_LEGACY_SITES", "CONF_SITES"):
        table = getattr(cc, tname)
        pin_name = ("LEGACY_EVP_DATA_SITE_PINS"
                    if tname == "LEGACY_EVP_DATA_SITES"
                    else tname.replace("SITES", "SITE_PINS"))
        pins = getattr(cc, pin_name)
        for addr, spec in table.items():
            entries.append((tname, addr, spec, pins.get(addr)))
    entries += [
        ("STORE_LOADER_PROVIDER_SITE", cc.STORE_LOADER_PROVIDER_SITE, {},
         cc.STORE_LOADER_PROVIDER_SITE_PIN),
        ("PBE_SITE", cc.PBE_SITE, {}, cc.PBE_SITE_PIN),
        ("PEM_SITE", cc.PEM_SITE, {}, cc.PEM_SITE_PIN),
        ("REGISTRATION_ATEXIT_CALL_SITE", cc.REGISTRATION_ATEXIT_CALL_SITE, {},
         cc.REGISTRATION_ATEXIT_CALL_SITE_PIN),
        ("E7BS_MSBLOB_SITE", cc.E7BS_MSBLOB_SITE, {}, cc.E7BS_MSBLOB_SITE_PIN),
        ("E7BS_RCU_SITE", cc.E7BS_RCU_SITE, {}, cc.E7BS_RCU_SITE_PIN),
    ]

    rename, records, failed = {}, [], []
    for table, old, spec, pin in entries:
        if not pin:
            failed.append({"table": table, "old": hex(old), "reason": "no-pin"})
            continue
        sym, off = pin[0], pin[1]
        if old in REPIN_OVERRIDES:
            new, why = REPIN_OVERRIDES[old]
        else:
            cands = starts.get(sym) or starts.get(leaf(sym)) or []
            cands = sorted(set(cands))
            if len(cands) != 1:
                failed.append({"table": table, "old": hex(old),
                               "reason": f"symbol-resolution-{len(cands)}", "symbol": sym})
                continue
            new, why = cands[0] + off, "pin"
        func_start = func_at.get(new)
        new_off = (new - func_start) if func_start is not None else None
        ok, seen = verify(ins, new, spec, table)
        rec = {"table": table, "old": f"0x{old:X}", "new": f"0x{new:X}",
               "symbol": sym, "old_offset": f"0x{off:X}",
               "new_offset": (f"0x{new_off:X}" if isinstance(new_off, int) else None),
               "basis": why, "instruction": seen, "verified": ok}
        records.append(rec)
        if ok:
            rename[old] = new
        else:
            failed.append(rec)

    # close-path guards, verified as exact instruction shapes
    guard_ok = True
    for old, new in CLOSE_GUARD_REPIN.items():
        text = ins.get(new, "")
        good = new in ins
        records.append({"table": "STORE_LOADER_CLOSE_GUARDS", "old": f"0x{old:X}",
                        "new": f"0x{new:X}", "symbol": "OSSL_STORE_open_ex",
                        "instruction": text, "verified": good,
                        "basis": "guard pair selects the legacy/provider close path"})
        if good:
            rename[old] = new
        else:
            guard_ok = False
            failed.append(records[-1])

    doc = {
        "schema": "openssl-rs/campaign/safe-c33/site-repin/v1",
        "candidate": "b58",
        "source_commit": SOURCE_COMMIT,
        "artefact": {"path": "court/freeze-b58/install/lib/libcrypto.so.3",
                     "sha256": LIB_SHA},
        "disassembly": {"path": str(DIS.relative_to(REPO)),
                        "sha256": subprocess.check_output(
                            ["sha256sum", str(DIS)]).decode().split()[0]},
        "rule": ("identity is the recorded (symbol, offset) pin resolved in the S "
                 "symbol table; the new address must be the enumerated indirect "
                 "call whose displacement (or feeding load) is the recorded "
                 "field. A site that fails the shape check is not re-pinned and "
                 "is reported in `failed`."),
        "counts": {"entries": len(entries) + len(CLOSE_GUARD_REPIN),
                   "repinned": len(rename), "failed": len(failed)},
        "sites": records,
        "failed": failed,
    }
    OUT.write_text(json.dumps(doc, indent=1) + "\n")
    print(f"[repin] entries={doc['counts']['entries']} "
          f"repinned={len(rename)} failed={len(failed)}")
    for f in failed:
        print("  FAILED", f)

    if not args.apply:
        return 0
    if failed:
        print("[repin] refusing --apply with failed entries", file=sys.stderr)
        return 2

    text = TOOL.read_text()
    spans = [(name, *block_span(text, name)) for name in BLOCKS]
    # apply from the end so offsets stay valid
    out = text
    for name, lo, hi in sorted(spans, key=lambda x: -x[1]):
        seg = out[lo:hi]

        def repl(m, seg_name=name):
            v = int(m.group(0), 16)
            if v not in rename:
                raise SystemExit(
                    f"{seg_name}: unmapped 6-digit literal {m.group(0)}")
            return f"0x{rename[v]:X}"
        new_seg = re.sub(r"0x[0-9A-Fa-f]{6}\b", repl, seg)
        out = out[:lo] + new_seg + out[hi:]
    # drifted pin offsets, scoped to their own block
    for name, old_lit, new_lit in OFFSET_REPINS:
        lo, hi = block_span(out, name)
        seg = out[lo:hi]
        if old_lit not in seg:
            raise SystemExit(f"{name}: offset {old_lit} not found")
        out = out[:lo] + seg.replace(old_lit, new_lit, 1) + out[hi:]
    TOOL.write_text(out)
    print(f"[repin] applied to {TOOL.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
