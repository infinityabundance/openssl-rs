#!/usr/bin/env python3
"""Per-file safe-surface detail for the three reviewed mechanisms."""

import contextlib
import io
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import surface

FILES = {
    "C_ABI_CONTRACT": [
        "src/engine/eng_dyn.rs",
        "src/engine/eng_fat.rs",
        "src/engine/eng_list.rs",
        "src/runtime/confmod/mod.rs",
        "src/ui/ui_util.rs",
    ],
    "BIO": ["src/runtime/bio/bf_readbuff.rs"],
    "SSL_SESSION": ["src/ssl/ssl_ciph.rs", "src/ssl/ssl_conf.rs", "src/ssl/ssl_rsa.rs"],
}


def main():
    records, files, by_name = surface.build_records()
    with contextlib.redirect_stdout(io.StringIO()):
        surface.analyze(records, files, by_name)
    out = {}
    for mech, rels in FILES.items():
        rows = []
        for r in records:
            if r["file"] not in rels or not r["definition"]:
                continue
            if r["safe"] and r["direct_unsafe"]:
                rows.append(
                    {
                        "file": r["file"],
                        "name": r["name"],
                        "line": r["line"],
                        "vis": r["vis"],
                        "extern": r["extern"],
                        "raw_pointer_param": r["raw_pointer_param"],
                        "external": r["external"],
                    }
                )
        out[mech] = {
            "files": rels,
            "safe_fns_reaching_unsafe": len(rows),
            "safe_pub_external_reaching_unsafe": sum(1 for r in rows if r["external"] and r["vis"] == "pub"),
            "safe_plain_rust_abi_rawptr": sorted(
                r["file"] + "::" + r["name"] + ":" + str(r["line"])
                for r in rows
                if not r["extern"] and r["raw_pointer_param"]
            ),
            "rows": rows,
        }
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
