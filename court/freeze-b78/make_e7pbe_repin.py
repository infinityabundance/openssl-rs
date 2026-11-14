"""Reproducible b78 record for the re-pinned E7-PBE fixture.

Derives the two sites and the five target leaves with the tool's own re-pin
engine (never a literal address) and writes court/freeze-b78/e7pbe-repin-b78.json.
"""
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path("/work")
spec = importlib.util.spec_from_file_location(
    "cc", ROOT / "forensics/tools/consumer_closure.py")
cc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cc)

dso = ROOT / "artifacts/phase2/install/lib/libcrypto.so.3"
work = ROOT / "court/tmp/e7pbe-repin-work"
work.mkdir(parents=True, exist_ok=True)
g = cc.DsoGraph(dso, work)
g.source_root = str(ROOT)
g.install_prefix = str(ROOT / "artifacts/phase2/install")
g.precision = cc.PrecisionResolver(g)

LEAVES = ("PKCS12_PBE_keyivgen_ex", "PKCS5_v2_PBE_keyivgen_ex",
          "PKCS5_v2_PBKDF2_keyivgen_ex", "PKCS5_PBE_keyivgen_ex",
          "PKCS5_v2_scrypt_keyivgen_ex")

sites = {}
for literal, site_spec in cc.PBE_EX_SITES.items():
    pin = cc.PBE_EX_SITE_PINS[literal]
    addr, how = cc._pin_effective("PBE_EX_SITES", literal, g)
    start = cc._pin_start(g, pin)
    text = next((t for a, t in cc._pin_insns(g, start) if a == addr), None)
    sites[site_spec["function"]] = {
        "stable_case_id": hex(literal),
        "pin": [pin[0], hex(pin[1])],
        "symbol_start": hex(start),
        "site_address": hex(addr),
        "resolved_offset": hex(addr - start),
        "how": how,
        "instruction": (text or "").strip(),
        "is_indirect_transfer": cc._is_indirect_transfer_strict(g, addr),
    }

targets = {}
for leaf in LEAVES:
    starts = sorted(a for a, names in g.names_at.items()
                    if a in g.start_set
                    and any(cc._external_function_leaf(n) == leaf
                            for n in names))
    targets[leaf] = [hex(a) for a in starts]

table = [a for a, names in g.names_at.items()
         if any("BUILTIN_PBE" in n for n in names)]
base = table[0]
got = sorted({r[0] for r in g.relocs
              if (r[2] or "").split("@")[0] == cc.PBE_FIND})

record = {
    "schema": "openssl-rs/safe-c33/e7pbe-fixture-repin/v1",
    "purpose": ("re-pin the E7-PBE self-test fixture by symbol for the b78 "
                "image; the fixture's literal keys are stable case ids only"),
    "image": {"path": "artifacts/phase2/install/lib/libcrypto.so.3",
              "sha256": g.sha256},
    "sites": sites,
    "target_leaves": targets,
    "builtin_table": {"base": hex(base),
                      "keygen_ex_member_offset": hex(cc.PBE_EX_FIELD_OFFSET),
                      "row_stride": 0x20, "selected_rows": [32, 33]},
    "find_ex_got_slot": [hex(x) for x in got],
    "derivation": {
        "site_2_moved_from_pin": "the recorded +0x208 no longer lands; the "
                                 "in-symbol witness search accepts exactly one "
                                 "of the symbol's indirect transfers",
        "uniqueness": "see pin_resolution_report()['moved'] for the b78 run",
    },
    "controls_added": [
        "a target leaf that disappears or is ambiguous fails the fixture",
        "a site that is not an indirect transfer in its pinned symbol fails",
        "a moved site is accepted only with a unique witness acceptance",
        "the mutation anchors (zero store, address escape, reloads) are read "
        "from the witness and their shapes are asserted",
    ],
    "not_proved": ["the fixture proves the target set and the refusal "
                   "controls; it is not a family discharge"],
}
out = ROOT / "court/freeze-b78/e7pbe-repin-b78.json"
out.write_text(json.dumps(record, indent=2) + "\n")
print("wrote", out)
print("sha256", hashlib.sha256(out.read_bytes()).hexdigest())
for f, s in sites.items():
    print(f, s["site_address"], "resolved", s["resolved_offset"],
          "how", s["how"], "|", s["instruction"][:28])
for leaf, starts in targets.items():
    print("target", leaf, starts)
print("BUILTIN_PBE", hex(base), "got", [hex(x) for x in got])
