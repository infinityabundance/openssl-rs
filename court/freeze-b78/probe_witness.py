"""Probe 3: exercise the new CONF-default-method witness on the b78 image."""
import importlib.util
from pathlib import Path

ROOT = Path("/work")
spec = importlib.util.spec_from_file_location(
    "cc", ROOT / "forensics/tools/consumer_closure.py")
cc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cc)

dso = ROOT / "artifacts/phase2/install/lib/libcrypto.so.3"
g = cc.DsoGraph(dso, ROOT / "court/tmp/claude-probe-work")
g.source_root = str(ROOT)
g.install_prefix = str(ROOT / "artifacts/phase2/install")
g.precision = cc.PrecisionResolver(g)

site_addr = cc._pinned_site("CONF_METHOD_SITE", g)
fstart = next(a for a, names in g.names_at.items()
              if a in g.start_set
              and any(cc._external_function_leaf(n) == "X509V3_EXT_REQ_add_conf"
                      for n in names))
text = next(t for a, t in g.precision.insns_by_func[fstart] if a == site_addr)
site = {"kind": "call", "func": fstart, "addr": site_addr, "text": text,
        "unresolved": True, "reason": "reg-value-partial[int]"}
print("site", hex(site_addr), g.funcs.get(fstart), "|", text.strip())
cls, wit, refusal = cc.conf_default_method_witness(g, site, g.funcs[fstart])
print("class:", cls)
print("refusal:", refusal)
if wit:
    import json
    print(json.dumps(wit, indent=1, default=str)[:3000])
    e7 = cc.evaluate_predicate_element_7([("control.so", site_addr, {
        "class": cls, "unresolved": True, "reason": site["reason"]})], [])
    print("element7:", e7["status"], e7["target_bounded_unresolved_sites"],
          e7["contract_bounded_by_class"])
# registration through the external ABI index
w2 = cc.external_abi_contract_witness(g, site, g.funcs[fstart])
print("indexed:", None if w2 is None else w2[0])
print("site functions map:", cc.EXTERNAL_ABI_SITE_FUNCTIONS.get(site_addr))
print("index entry:", cc._external_abi_index(g).get(site_addr))
