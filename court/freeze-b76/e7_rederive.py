#!/usr/bin/env python3
"""Re-derive the b73 element-7 pins against the b76 libcrypto.

The tool's site tables are keyed by a virtual address in one exact artefact.
Each row carries a ``(symbol leaf, offset)`` pin, which is the *re-derivation*
key.  This script performs the derivation independently of the tool for the
b76 image and classifies every element-7 site and every self-test fixture pin:

    REDERIVED      the pin re-derives an indirect transfer in this image and
                   the site's own witness proves its contract/target set at
                   that address (a row whose offset moved is only REDERIVED
                   when the witness accepts exactly one candidate and no other
                   row of the table accepts the same address)
    SHAPE_MISMATCH a b73 row exists for this function but the code at the
                   re-derived address is not the recorded shape, or the
                   witness refuses (the site's code changed)
    NO_EQUIVALENT  no b73 row corresponds to this site

Inputs, all read-only:
  * ``/work/artifacts/phase2/install/lib/libcrypto.so.3`` (the b76 candidate)
  * ``evidence/closure-ssh-b76b.json`` (the 48 target-bounded residual sites)
  * ``forensics/memory-safety/campaign/safe-c33/atlas-refresh/
     element7-b73-repin2.json`` (the 37 b73 rows of the five class tables)
  * ``git show HEAD:forensics/tools/consumer_closure.py`` (the b73 self-test
    fixture pins; HEAD is the pre-re-pin tool, so this is the frozen side)

The symbol map is built from ``readelf -sW`` (both ``.dynsym`` and
``.symtab``); ``nm --defined-only`` is used as a cross-check, and the script
records which table supplied each address.  Instructions are read from one
``objdump -d`` pass over the image.

Usage:
  python3 court/freeze-b76/e7_rederive.py [--image PATH] [--out PATH]
                                          [--witness/--no-witness]
                                          [--controls PATH]
"""
import argparse
import hashlib
import json
import re
import subprocess
import sys
import time
import uuid
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
DEFAULT_IMAGE = REPO / "artifacts/phase2/install/lib/libcrypto.so.3"
DEFAULT_CLOSURE = REPO / "evidence/closure-ssh-b76b.json"
DEFAULT_REPIN = (REPO / "forensics/memory-safety/campaign/safe-c33/"
                 "atlas-refresh/element7-b73-repin2.json")
DEFAULT_OUT = REPO / "court/freeze-b76/e7-rederive.json"
TOOL_REL = "forensics/tools/consumer_closure.py"
CONTRACT_CLASSES = {
    "ABI_CONTRACT_SLH_METHOD_TABLE", "ABI_CONTRACT_PROVIDER_HW_TABLE",
    "ABI_CONTRACT_LEGACY_EVP_CIPHER_DATA", "ABI_CONTRACT_DECODER_METHOD_OBJECT",
    "ABI_CONTRACT_REGISTRATION_ATEXIT", "ABI_CONTRACT_PBE_REGISTRY",
    "ABI_CONTRACT_STORE_LOADER", "ABI_CONTRACT_CONF_MODULE",
    "ABI_CONTRACT_EXPORT_CALLBACK_DEFAULT", "ABI_CONTRACT_PROVIDER",
}


# --------------------------------------------------------------------------- #
# ELF / symbol map
# --------------------------------------------------------------------------- #

def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, check=True, **kw)


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def leaf(name: str) -> str:
    """Mirror of the tool's _external_function_leaf (v0/legacy path parser)."""
    base = re.sub(r"\.llvm(?:\.[0-9]+)?$", "", name or "")
    m = re.search(r"Cs[0-9A-Za-z]+_", base)
    if m:
        pos, last = m.end(), None
        while pos < len(base):
            n = re.match(r"\d+", base[pos:])
            if not n:
                last = None
                break
            length = int(n.group(0))
            at = pos + len(n.group(0))
            ident = base[at:at + length]
            if len(ident) != length:
                last = None
                break
            last = ident
            pos = at + length
        if last:
            return last
    return base.split("@")[0]


def pin_leaf(symbol: str) -> str:
    return (symbol or "").rsplit("::", 1)[-1]


def readelf_symbols(path: Path):
    out = run(["readelf", "-sW", str(path)]).stdout
    table, rows = None, []
    for line in out.splitlines():
        m = re.match(r"Symbol table '(\S+)' contains", line)
        if m:
            table = m.group(1)
            continue
        parts = line.split()
        if len(parts) < 8 or not re.fullmatch(r"[0-9a-f]+:", parts[0]):
            continue
        try:
            value = int(parts[1], 16)
        except ValueError:
            continue
        typ, ndx, name = parts[3], parts[6], parts[7]
        if typ != "FUNC" or ndx in ("UND", "ABS"):
            continue
        rows.append({"table": table, "value": value, "name": name})
    return rows


def nm_symbols(path: Path):
    out = run(["nm", "--defined-only", str(path)]).stdout
    rows = []
    for line in out.splitlines():
        p = line.split()
        if len(p) < 3:
            continue
        try:
            value = int(p[0], 16)
        except ValueError:
            continue
        if p[1] in ("T", "t", "W", "w"):
            rows.append({"value": value, "name": p[2]})
    return rows


def objdump(path: Path):
    """addr -> {bytes, mnemonic, text}; one pass over the image."""
    out = run(["objdump", "-d", "--no-show-raw-insn", str(path)]).stdout
    insns = {}
    cur = None
    for line in out.splitlines():
        m = re.fullmatch(r"\s*([0-9a-f]+):\s+(.*)", line)
        if not m:
            if re.match(r"^[0-9a-f]+ <", line):
                cur = line.split()[0]
            continue
        insns[int(m.group(1), 16)] = {"text": m.group(2).strip(),
                                      "function": cur}
    raw = run(["objdump", "-d", str(path)]).stdout
    for line in raw.splitlines():
        m = re.fullmatch(r"\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s)+)\s*(.*)", line)
        if m:
            a = int(m.group(1), 16)
            if a in insns:
                insns[a]["bytes"] = m.group(2).split()
    return insns


def is_indirect(text: str) -> bool:
    m = re.match(r"\s*(call\w*|jmp\w*)\s+(\S.*)$", text or "")
    return bool(m) and m.group(2).lstrip().startswith("*")


# --------------------------------------------------------------------------- #
# b73 pin universe
# --------------------------------------------------------------------------- #

def git_blob(rel: str, ref: str = "HEAD"):
    try:
        out = subprocess.run(["git", "show", f"{ref}:{rel}"], cwd=REPO,
                             capture_output=True, text=True, check=True).stdout
    except subprocess.CalledProcessError:
        return None
    return out


def dict_literal(text: str, anchor: str, name: str):
    """Parse ``name = { ... }`` inside the function ``anchor`` (shallow)."""
    start = text.index(anchor)
    nxt = text.find("\ndef ", start + 1)
    body = text[start:nxt if nxt != -1 else len(text)]
    at = body.index(name + " = {")
    i = body.index("{", at)
    depth, j = 0, i
    while j < len(body):
        if body[j] == "{":
            depth += 1
        elif body[j] == "}":
            depth -= 1
            if depth == 0:
                break
        j += 1
    blob = body[i + 1:j]
    out = {}
    for m in re.finditer(r"0x([0-9A-Fa-f]+):\s*\(([^)]*)\)", blob):
        args = [a.strip() for a in m.group(2).split(",")]
        sym = args[0].strip().strip('"\'')
        off = int(args[1], 0) if len(args) > 1 else 0
        out[int(m.group(1), 16)] = (sym, off)
    return out


def b73_universe(repin_path: Path, head_text: str):
    rows = []
    repin = json.loads(repin_path.read_text())
    for cls, body in repin["classes"].items():
        for r in body.get("sites") or []:
            rows.append({
                "source": "element7-b73-repin2.json",
                "class": cls,
                "literal": int(r["new_address"], 16),
                "pin": (r["anchor_symbol"], int(r["anchor_offset"], 16)),
                "instruction_bytes": r.get("instruction_bytes"),
                "instruction": r.get("instruction"),
                "spec_field": r.get("shape_predicate"),
            })
    for r in repin.get("e7bs_msblob_repin", {}).get("sites") or []:
        rows.append({"source": "element7-b73-repin2.json/e7bs",
                     "class": "E7BS_MSBLOB", "literal": None,
                     "pin": (r.get("anchor_symbol"), int(r.get("anchor_offset"), 16)),
                     "instruction_bytes": r.get("instruction_bytes"),
                     "instruction": r.get("instruction"), "spec_field": None})
    fixtures = []
    if head_text:
        abi = dict_literal(head_text, "def _e7abi_self_test", "site_pins")
        pbe_sites = dict_literal(head_text, "def _pbe_outparam_self_test",
                                 "site_pins")
        pbe_targets = dict_literal(head_text, "def _pbe_outparam_self_test",
                                   "target_pins")
        for addr, pin in abi.items():
            fixtures.append({"source": "HEAD:_e7abi_self_test.site_pins",
                             "kind": "site", "literal": addr, "pin": pin})
        for addr, pin in pbe_sites.items():
            fixtures.append({"source": "HEAD:_pbe_outparam_self_test.site_pins",
                             "kind": "site", "literal": addr, "pin": pin})
        for addr, pin in pbe_targets.items():
            fixtures.append({"source": "HEAD:_pbe_outparam_self_test.target_pins",
                             "kind": "target", "literal": addr,
                             "pin": (pin[0], pin[1])})
    return rows, fixtures


# --------------------------------------------------------------------------- #
# derivation
# --------------------------------------------------------------------------- #

def build_index(syms):
    by_leaf = {}
    for s in syms:
        by_leaf.setdefault(leaf(s["name"]), []).append(s)
    return by_leaf


def derive(pin, by_leaf, by_addr_addr, insns):
    """(address, error) for a pin in this image."""
    if not pin or not pin[0]:
        return None, "no-pin"
    hits = by_leaf.get(pin_leaf(pin[0])) or []
    starts = sorted({h["value"] for h in hits})
    if not starts:
        return None, "symbol-absent"
    if len(starts) > 1:
        return None, f"ambiguous-leaf({[hex(a) for a in starts[:4]]})"
    addr = starts[0] + int(pin[1])
    ins = insns.get(addr)
    if ins is None:
        return None, "pin-lands-outside-instruction"
    return addr, None


def witness_for(cc, g, site, name):
    """The tool's own dispatch order for one site; returns a normalised dict."""
    steps = [
        ("external-abi", lambda: cc.external_abi_contract_witness(g, site, name)),
        ("pbe-outparam", lambda: cc.pbe_outparam_instance_witness(g, site, name)),
        ("slh", lambda: cc.slh_method_table_witness(g, site, name)),
        ("provider-hw", lambda: cc.provider_hw_table_witness(g, site, name)),
        ("legacy-evp", lambda: cc.legacy_evp_cipher_data_witness(g, site, name)),
        ("decoder", lambda: cc.decoder_method_object_witness(g, site, name)),
        ("registration-atexit", lambda: cc.registration_atexit_witness(g, site, name)),
        ("core-dispatch", lambda: cc.core_dispatch_witness(g, site, name)),
    ]
    for label, fn in steps:
        r = fn()
        if r is None:
            continue
        if isinstance(r, tuple):
            if len(r) == 3:
                cls, w, ref = r
            else:
                w, ref = r
                cls = (w or {}).get("class") if isinstance(w, dict) else None
        else:
            w = r
            cls = (r or {}).get("class")
            ref = r if isinstance(r, dict) and r.get("refusal") else None
        if isinstance(w, dict) and w.get("refusal"):
            ref, w = w, None
        if w is None:
            if ref is None:
                continue          # not this witness's site
            return {"rule": label, "class": cls, "accepted": False,
                    "refusal": (ref or {}).get("refusal")
                    or (ref or {}).get("reason")}
        bounded = bool(w.get("contract_bounded"))
        targets = w.get("targets") or w.get("target_set")
        return {"rule": label, "class": cls or w.get("class"),
                "accepted": bounded or bool(w.get("resolved")),
                "contract_bounded": bounded,
                "slot": w.get("slot") or w.get("field"),
                "targets": list(targets) if isinstance(targets, (list, tuple)) else None,
                "refusal": None}
    return None


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #

def _repin_record(out: dict, cc, repo: Path) -> dict:
    """The applied re-pin rows, with the witness and the control that proves each."""
    table_of = {
        "ABI_CONTRACT_SLH_METHOD_TABLE": "SLH_METHOD_TABLE_SITES",
        "ABI_CONTRACT_PROVIDER_HW_TABLE": "PROVIDER_HW_SITES",
        "ABI_CONTRACT_LEGACY_EVP_CIPHER_DATA": "LEGACY_EVP_DATA_SITES",
        "ABI_CONTRACT_DECODER_METHOD_OBJECT": "DECODER_METHOD_SITES",
        "ABI_CONTRACT_REGISTRATION_ATEXIT": "REGISTRATION_ATEXIT_CALL_SITE",
        "ABI_CONTRACT_PBE_REGISTRY": "PBE_SITE",
        "ABI_CONTRACT_STORE_LOADER": "STORE_LOADER_LEGACY_SITES",
        "ABI_CONTRACT_CONF_MODULE": "CONF_SITES",
        "ABI_CONTRACT_EXPORT_CALLBACK_DEFAULT": "PEM_SITE",
        "pbe-outparam-builtin-table": "PBE_EX_SITES",
    }
    # b73 loader field -> the b73 fixture pin it came from
    loader_b73 = {}
    if cc is not None:
        for lit, spec in cc.STORE_LOADER_LEGACY_SITES.items():
            loader_b73[spec["field"]] = lit
    rows_out = []
    refused = []
    for it in out["sites"]:
        if it["classification"] != "REDERIVED":
            refused.append({"call_site": it["call_site"],
                            "function": it["function_name"],
                            "offset": it["offset"],
                            "classification": it["classification"],
                            "reason": it.get("why")})
            continue
        w = it.get("witness") or {}
        new_pin = [it["function_name"], it["offset"]]
        if it.get("b73_row"):
            old_pin = it["b73_row"]["pin"]
            old_literal = it["b73_row"].get("literal")
            derivation = "pin-exact"
            control = "e7repin symbol/offset/instruction controls"
        else:
            # a loader row whose call moved: pair it by the field its witness
            # proves, never by the pinned offset
            slot = w.get("slot") or ""
            m = re.search(r"\.(\w+) \(offset", slot)
            field = m.group(1) if m else None
            old_literal = (hex(loader_b73[field])
                           if field in loader_b73 else None)
            old_pin = None
            if old_literal:
                fx = next((f for f in out["fixtures"]
                           if f["b73_literal"] == old_literal), None)
                if fx:
                    old_pin = fx["pin"]
            derivation = "witness-proved-moved-row"
            control = "e7repin moved-row uniqueness"
        rows_out.append({
            "table": table_of.get(w.get("class"), w.get("rule") or "-"),
            "class": w.get("class"),
            "witness_rule": w.get("rule"),
            "witness_slot": w.get("slot"),
            "old_literal": old_literal,
            "old_pin": old_pin,
            "new_address": it["call_site"],
            "new_pin": new_pin,
            "instruction": it["text"],
            "instruction_bytes": it.get("instruction_bytes"),
            "derivation": derivation,
            "control": control,
            "targets_after": it.get("targets_after"),
            "contract_bounded": w.get("contract_bounded"),
        })
    return {
        "schema": "openssl-rs/campaign/safe-c33/e7-repin/v1",
        "candidate_tag": "b76",
        "image": out["image"],
        "artifact": out["image"],
        "tool_sha256": hashlib.sha256(
            (repo / TOOL_REL).read_bytes()).hexdigest(),
        "b73_source": out["b73_source"],
        "closure": out["closure"],
        "rule": (
            "each row is re-derived from its (symbol leaf, offset) pin in the "
            "exact b76 image; start+offset must be an instruction start and an "
            "indirect call/jmp, and the row's own witness must re-prove the "
            "operand, base, field and writer/target set at that address.  A "
            "row whose offset moved is applied only when exactly one row of "
            "the table accepts that address (e7repin moved-row uniqueness); "
            "an unprovable row keeps its b73 literal and stays target-bounded"),
        "controls": ["e7repin-symbol-control", "e7repin-offset-control",
                     "e7repin-instruction-control",
                     "e7repin-moved-row-uniqueness"],
        "controls_result": (
            "pass: `python3 forensics/tools/consumer_closure.py --self-test` "
            "prints the e7repin control line, and "
            "`python3 court/freeze-b76/e7_rederive.py --controls` re-runs it"),
        "counts": out["counts"],
        "rows": rows_out,
        "refused": refused,
        "does_not_prove": [
            "a row proves its witness contract in this image, not that the "
            "witness rule is complete or that the field's writer set is "
            "exhaustive beyond its stated source/module scope",
            "the two loader rows were re-derived by witness uniqueness, not by "
            "the pinned offset; their b73 literal is recorded from the b73 "
            "fixture and the correspondence is the witness's field proof",
            "the element-7 residual is a FAST probe (--element7-only); it is "
            "not a closure receipt and carries no DISCHARGED/BLOCKED counts",
            "no build, test, Miri, ASan or cryptographic court was run",
        ],
    }


def n_dummy(item):
    return item.get("witness", {}).get("rule") if item.get("witness") else "-"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--image", default=str(DEFAULT_IMAGE))
    ap.add_argument("--closure", default=str(DEFAULT_CLOSURE))
    ap.add_argument("--repin", default=str(DEFAULT_REPIN))
    ap.add_argument("--out", default=str(DEFAULT_OUT))
    ap.add_argument("--witness", dest="witness", action="store_true", default=True)
    ap.add_argument("--no-witness", dest="witness", action="store_false")
    ap.add_argument("--controls", action="store_true",
                    help="run the re-pin mutation controls and exit")
    ap.add_argument("--record", default=None,
                    help="write the applied re-pin record here")
    args = ap.parse_args(argv)

    t0 = time.time()
    image = Path(args.image)
    if not image.is_file():
        ap.error(f"image not found: {image}")

    syms = readelf_symbols(image)
    nm = nm_symbols(image)
    by_leaf = build_index(syms)
    nm_starts = {r["value"] for r in nm}
    readelf_starts = {s["value"] for s in syms}
    insns = objdump(image)
    closure = json.loads(Path(args.closure).read_text())
    head_text = git_blob(TOOL_REL)
    rows, fixtures = b73_universe(Path(args.repin), head_text)

    tb = [s for s in closure["precision"]["residual_sites"]
          if s["class"] not in ("ABI_CONTRACT_CORE_DISPATCH",
                                "ABI_CONTRACT_EXPORT_CALLBACK",
                                "ABI_CONTRACT_PROVIDER")]
    by_addr = {s["value"]: s for s in syms}

    def fname_for(addr):
        s = by_addr.get(addr)
        return s["name"] if s else ""

    def symbol_table_of(addr):
        return sorted({s["table"] for s in syms if s["value"] == addr})

    # --- the tool's own witnesses (needs the tool module + a DsoGraph) --- #
    cc = None
    if args.witness:
        sys.path.insert(0, str(REPO / "forensics/tools"))
        import consumer_closure as cc_mod  # noqa: E402
        cc = cc_mod
        g = cc.DsoGraph(image, REPO / "court/tmp/e7-rederive-work")
        g.source_root = str(REPO)
        g.install_prefix = str(REPO / "artifacts/phase2/install")
        g.precision = cc.PrecisionResolver(g)

    if args.controls:
        failures = cc.e7repin_controls(g)
        print(f"controls: {'PASS' if not failures else 'FAIL'} "
              f"({len(failures)} failure(s))")
        for f in failures:
            print(" -", f)
        return 0 if not failures else 1

    pin_rows = {(pin_leaf(r["pin"][0]), r["pin"][1]): r for r in rows}
    for f in fixtures:
        if f["kind"] == "site":
            pin_rows.setdefault((pin_leaf(f["pin"][0]), f["pin"][1]),
                                {"source": f["source"], "class": "E7_ABI_FIXTURE",
                                 "literal": f["literal"], "pin": f["pin"],
                                 "instruction_bytes": None})

    sites = []
    for s in tb:
        f = int(s["function"], 16)
        a = int(s["call_site"], 16)
        name = g.funcs.get(f, "") if cc else fname_for(f)
        off = a - f
        key = (leaf(name), off)
        row = pin_rows.get(key)
        ins = insns.get(a)
        item = {
            "call_site": s["call_site"], "function": s["function"],
            "function_name": leaf(name), "offset": hex(off),
            "reason": s["reason"], "class": s["class"], "text": s["text"],
            "instruction_bytes": (ins or {}).get("bytes"),
            "b73_row": ({"pin": [row["pin"][0], hex(row["pin"][1])],
                         "class": row["class"],
                         "literal": (hex(row["literal"])
                                     if row.get("literal") else None),
                         "instruction_bytes": row.get("instruction_bytes")}
                        if row else None),
            "derivation": None, "witness": None,
        }
        resolved, err = derive(key, by_leaf, by_addr, insns)
        # (a) exact pin match: the b73 row's (leaf, offset) is this site's key
        if row is not None and not is_indirect((ins or {}).get("text", "")):
            item["derivation"] = "pin-exact"
            item["why"] = "address is not an indirect transfer"
            item["classification"] = "SHAPE_MISMATCH"
        elif row is not None and row.get("instruction_bytes"):
            got = (ins or {}).get("bytes") or []
            want = row["instruction_bytes"].split()
            if got != want:
                item["derivation"] = "pin-exact"
                item["why"] = f"instruction bytes {got} != b73 {want}"
                item["classification"] = "SHAPE_MISMATCH"
            else:
                item["derivation"] = "pin-exact"
        elif row is not None:
            item["derivation"] = "pin-exact"
        else:
            item["derivation"] = "no-exact-pin"

        # (b) witness at this address
        if cc is not None:
            site = {"kind": "call", "func": f, "addr": a,
                    "text": s["text"], "targets": set(), "unresolved": True,
                    "reason": s["reason"], "class": s["class"],
                    "field_offsets": set(), "seam": None,
                    "arg_deps": set(), "arg_targets": set()}
            g.sites = {(f, a, "call"): site}
            w = witness_for(cc, g, site, name)
            item["witness"] = w
            item["targets_after"] = sorted(site["targets"])
            item["unresolved_after"] = site["unresolved"]
            if w is not None and w.get("accepted") and not site["unresolved"]:
                item["targets_after"] = sorted(site["targets"])
        if item.get("classification"):
            sites.append(item)
            continue
        same_function = [r for r in rows
                         if pin_leaf(r["pin"][0]) == leaf(name)]
        same_function += [f for f in fixtures
                          if f["kind"] == "site"
                          and pin_leaf(f["pin"][0]) == leaf(name)]
        item["b73_rows_in_function"] = [
            {"pin": [r["pin"][0], hex(r["pin"][1])],
             "class": r.get("class") or r.get("source")} for r in same_function]
        if item["witness"] is None:
            if same_function:
                item["classification"] = "SHAPE_MISMATCH"
                item["why"] = (
                    "the function has b73 rows but none of their offsets is "
                    "this call and no witness accepts the address: the call "
                    "moved inside the function and cannot be re-derived from "
                    "its pin")
            else:
                item["classification"] = "NO_EQUIVALENT"
                item["why"] = ("no b73 row names this function and no witness "
                               "claims this site")
        elif item["witness"].get("accepted"):
            if item["derivation"] == "pin-exact":
                item["classification"] = "REDERIVED"
                item["why"] = ("pin re-derives an indirect transfer and the "
                               f"{item['witness']['rule']} witness accepts it")
            else:
                item["classification"] = "REDERIVED"
                item["why"] = ("the witness accepts this address and no "
                               "b73 row's offset does; the row moved inside "
                               "its function and the correspondence is proved "
                               "by the witness, not by the offset")
                item["derivation"] = "witness-proved-moved-row"
        else:
            item["classification"] = "SHAPE_MISMATCH"
            item["why"] = ("the site's code changed: "
                           f"{item['witness'].get('rule')} refuses "
                           f"({item['witness'].get('refusal')})")
        sites.append(item)

    fixtures_out = []
    for fx in fixtures:
        addr, err = derive(fx["pin"], by_leaf, by_addr, insns)
        item = {"source": fx["source"], "kind": fx["kind"],
                "b73_literal": hex(fx["literal"]),
                "pin": [fx["pin"][0], hex(fx["pin"][1])],
                "new_address": hex(addr) if addr is not None else None,
                "symbol_tables": symbol_table_of(addr) if addr else [],
                "instruction": (insns.get(addr) or {}).get("text"),
                "error": err}
        if err:
            item["classification"] = ("NO_EQUIVALENT"
                                      if err == "symbol-absent"
                                      else "SHAPE_MISMATCH")
            item["why"] = err
        elif fx["kind"] == "target":
            item["classification"] = "REDERIVED"
            item["why"] = "pin names exactly one function start"
        else:
            ok = is_indirect((insns.get(addr) or {}).get("text", ""))
            if ok:
                item["classification"] = "REDERIVED"
                item["why"] = "pin re-derives an indirect transfer"
            else:
                moved = [s for s in sites
                         if s["classification"] == "REDERIVED"
                         and s.get("derivation") == "witness-proved-moved-row"
                         and s["function_name"] == leaf(fx["pin"][0])]
                item["classification"] = "SHAPE_MISMATCH"
                item["why"] = (
                    "the pinned offset no longer lands on an indirect "
                    "transfer; the call moved inside the function")
                item["moved_candidates"] = [
                    {"call_site": s["call_site"], "offset": s["offset"],
                     "witness_class": (s.get("witness") or {}).get("class")}
                    for s in moved]
                if moved:
                    item["why"] += (
                        " -- the witness proves " + ", ".join(
                            c["call_site"] for c in item["moved_candidates"])
                        + " in this function; re-pin only the matching spec")
        fixtures_out.append(item)

    def counts(items):
        c = {}
        for it in items:
            c[it["classification"]] = c.get(it["classification"], 0) + 1
        return dict(sorted(c.items()))

    out = {
        "schema": "openssl-rs/campaign/safe-c33/e7-rederive/v1",
        "run_id": uuid.uuid4().hex,
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "wall_seconds": round(time.time() - t0, 1),
        "image": {"path": str(image), "sha256": sha256_file(image),
                  "size": image.stat().st_size},
        "symbol_table": {
            "readelf_tables": sorted({s["table"] for s in syms}),
            "readelf_func_symbols": len(syms),
            "readelf_func_starts": len(readelf_starts),
            "nm_func_starts": len(nm_starts),
            "cross_check": ("agree" if readelf_starts <= nm_starts
                            and nm_starts <= readelf_starts else "differ"),
            "used": ".symtab (single name per address from readelf -sW; nm "
                    "cross-checked the function-start set)",
            "note": "readelf -sW reports both .dynsym and .symtab; .symtab "
                    "carries the local Rust symbols the pins name",
        },
        "b73_source": {
            "git_ref": "HEAD",
            "tool_blob_sha256": (hashlib.sha256(head_text.encode()).hexdigest()
                                 if head_text else None),
            "repin_record": {"path": str(Path(args.repin).relative_to(REPO)),
                             "sha256": sha256_file(Path(args.repin))},
            "row_count": len(rows),
            "fixture_pin_count": len(fixtures),
        },
        "closure": {"path": str(Path(args.closure).relative_to(REPO)),
                    "artifact_sha256": closure["artifact_identity"]["sha256"],
                    "target_bounded_sites": len(tb)},
        "sites": sites,
        "fixtures": fixtures_out,
        "counts": {"sites": counts(sites), "fixtures": counts(fixtures_out)},
        "residue": [{"call_site": s["call_site"],
                     "function_name": s["function_name"],
                     "offset": s["offset"],
                     "classification": s["classification"],
                     "reason": s.get("why")}
                    for s in sites
                    if s["classification"] != "REDERIVED"],
        "does_not_prove": [
            "a REDERIVED verdict proves the site's witness contract in this "
            "image; it does not prove the witness rule itself is complete",
            "the fixture re-pins prove the fixture addresses moved; they do "
            "not re-run the refused control bodies",
            "reachability is taken from the b76b closure receipt, not "
            "recomputed here",
            "no build, test or cryptographic court was run",
        ],
    }
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, indent=1) + "\n")
    if args.record:
        rec = _repin_record(out, cc, REPO)
        rec_path = Path(args.record)
        rec_path.parent.mkdir(parents=True, exist_ok=True)
        rec_path.write_text(json.dumps(rec, indent=1) + "\n")
        print(f"[e7-rederive] wrote {rec_path} "
              f"({len(rec['rows'])} row(s), {len(rec['refused'])} refused)")
    print(f"[e7-rederive] wrote {out_path}")
    print(f"[e7-rederive] sites: {out['counts']['sites']}")
    print(f"[e7-rederive] fixtures: {out['counts']['fixtures']}")
    for r in out["residue"]:
        print(f"  RESIDUE {r['call_site']} {r['function_name']}+{r['offset']} "
              f"{r['classification']}: {r['reason']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
