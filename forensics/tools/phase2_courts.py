#!/usr/bin/env python3
"""openssl-rs — Phase 2 courts: the distribution / ABI shell.

Runs the Phase 2 court families against the generated shell and emits
`artifacts/phase2/COURTS.json` plus one detail file per court under
`artifacts/phase2/courts/`.

    ABI-SYMBOL          candidate DSO exported symbols vs the authority, exactly
    ABI-VERSION         version definition nodes and per-node symbol bindings
    ABI-LAYOUT          layout probe compiled against the *header shell* vs the
                        authority's measured layout
    ABI-LINK            a trivial C consumer, compiled against the header shell,
                        links against the candidate DSO
    ABI-LOAD            dlopen + dlvsym resolution of versioned symbols
    libcrypto-contamination  the candidate DSO's dynamic closure must not
                        resolve to a non-authority OpenSSL

What these courts do and do not establish
-----------------------------------------
They establish that the *distribution shell* is structurally correct: the right
symbols exist, under the right version nodes, with the right SONAME, that a
consumer can link and load, and that no contaminating OpenSSL is pulled in.

They establish **nothing** about semantics. Every symbol in the shell is
SCAFFOLDED and aborts when called, so passing these courts is not parity and is
never recorded as such.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import (  # noqa: E402
    PRODUCTION_AUTHORITY,
    authority_atlas_dir,
    content_hash,
    envelope,
    read_dynsyms,
    read_version_definition_names,
    rel,
    resolve_authority,
    run,
    sha256_file,
    write_json,
    write_text,
    REPO_ROOT,
)

PHASE2 = REPO_ROOT / "artifacts" / "phase2"
COURT_DIR = PHASE2 / "courts"
LIBS = {"libcrypto": "libcrypto.so.3", "libssl": "libssl.so.3"}

LINK_PROBE = r"""
/* Trivial external consumer: compiled against the header shell, linked against
 * the candidate DSO. It takes addresses of versioned symbols (forcing link-time
 * resolution) but CALLS none of them, because every shell symbol is scaffolded
 * and aborts on call. The point of Phase 2 is build+load, not execution. */
#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>

int main(void) {
    const void *probe[] = {
        (const void *)&EVP_DigestInit_ex,
        (const void *)&EVP_CipherInit_ex,
        (const void *)&EVP_PKEY_new,
        (const void *)&X509_new,
        (const void *)&SSL_CTX_new,
        (const void *)&SSL_new,
    };
    unsigned nonzero = 0;
    for (unsigned i = 0; i < sizeof(probe) / sizeof(probe[0]); i++)
        if (probe[i]) nonzero++;
    printf("link-probe: %u/%zu versioned symbols resolved by the dynamic linker\n",
           nonzero, sizeof(probe) / sizeof(probe[0]));
    return 0;
}
"""

LOAD_PROBE = ""  # superseded: replaced by a version-parameterised probe


def candidate_export(dso: Path) -> dict:
    """Exported API symbols of a candidate DSO: name -> (type, bind, version)."""
    out = {}
    for s in read_dynsyms(dso):
        if s.defined and s.bind in ("GLOBAL", "WEAK") and s.ndx != "ABS":
            out[s.name] = {"type": s.stype, "bind": s.bind, "version": s.version}
    return out


def court_abi_symbol(auth, atlas: dict) -> dict:
    result = {"court": "ABI-SYMBOL", "libraries": {}}
    for lib, soname in sorted(LIBS.items()):
        doc = json.loads((authority_atlas_dir(auth.id) / f"symbols-{lib}.json").read_text())
        expected = {
            r["symbol"]: {"type": (r["dso"] or {}).get("type"),
                          "version": (r["dso"] or {}).get("version")}
            for r in doc["body"]["records"] if (r.get("dso") or {}).get("present")
        }
        actual = candidate_export(PHASE2 / soname)
        missing = sorted(set(expected) - set(actual))
        extra = sorted(set(actual) - set(expected))
        version_diff = sorted(
            s for s in set(expected) & set(actual)
            if expected[s]["version"] != actual[s]["version"]
        )
        result["libraries"][lib] = {
            "authority_exported": len(expected),
            "candidate_exported": len(actual),
            "missing": missing, "extra": extra,
            "version_mismatch": version_diff,
            "verdict": "pass" if not (missing or extra or version_diff) else "fail",
        }
    result["verdict"] = "pass" if all(
        v["verdict"] == "pass" for v in result["libraries"].values()) else "fail"
    return result


def court_abi_version(auth, atlas: dict) -> dict:
    result = {"court": "ABI-VERSION", "libraries": {}}
    for lib, soname in sorted(LIBS.items()):
        doc = json.loads((authority_atlas_dir(auth.id) / f"symbols-{lib}.json").read_text())
        auth_defs = read_version_definition_names(auth.dso(lib))
        cand_defs = read_version_definition_names(PHASE2 / soname)
        per_node: dict[str, int] = {}
        for s in read_dynsyms(PHASE2 / soname):
            if s.defined and s.bind in ("GLOBAL", "WEAK") and s.ndx != "ABS":
                per_node[s.version or "(unversioned)"] = per_node.get(s.version or "(unversioned)", 0) + 1
        result["libraries"][lib] = {
            "authority_nodes": auth_defs,
            "candidate_nodes": cand_defs,
            "nodes_match": auth_defs == cand_defs,
            "candidate_symbols_by_node": dict(sorted(per_node.items())),
            "verdict": "pass" if auth_defs == cand_defs else "fail",
        }
    result["verdict"] = "pass" if all(
        v["verdict"] == "pass" for v in result["libraries"].values()) else "fail"
    return result


def court_abi_layout(auth) -> dict:
    """Compile a layout probe for EVERY aggregate in the authority's layout
    atlas against the header shell, and compare every measurement.

    The shell's headers are byte-identical to the authority's, so this court is
    expected to pass; its value is that it *would* catch a shell that had been
    regenerated, subsetted, or edited, and it proves the shell actually compiles
    as public headers (an opaque type cannot be probed, which is itself a fact).
    """
    doc = json.loads((authority_atlas_dir(auth.id) / "abi-layout.json").read_text())
    records = [r for r in doc["body"]["records"] if r.get("probe_status") == "ok"]
    if not records:
        return {"court": "ABI-LAYOUT", "verdict": "fail",
                "detail": {"reason": "no authority layout records"}}

    inc_text = "\n".join(
        f"#include <openssl/{p.name}>"
        for p in sorted((PHASE2 / "include" / "openssl").glob("*.h"))
    )
    aggs = sorted({r["aggregate"] for r in records})
    probes: list[str] = []
    for a in aggs:
        probes.append('    printf("sizeof\\t%s\\t%zu\\n", "' + a + '", sizeof(' + a + '));')
        probes.append('    printf("alignof\\t%s\\t%zu\\n", "' + a + '", _Alignof(' + a + '));')
    for r in records:
        a = r["aggregate"]
        for f in r["field_offsetof"]:
            probes.append(
                '    printf("offsetof\\t%s\\t%zu\\n", "' + a + '.' + f
                + '", offsetof(' + a + ', ' + f + '));'
            )
    src = ("/* Generated by forensics/tools/phase2_courts.py — layout probe "
           "against the header shell. */\n#include <stddef.h>\n#include <stdio.h>\n"
           + inc_text + "\n\nint main(void) {\n" + "\n".join(probes)
           + "\n    return 0;\n}\n")
    csrc = COURT_DIR / "layout_probe.c"
    write_text(csrc, src)
    binp = COURT_DIR / "layout_probe"
    res = run(["clang", "-std=c11", "-I", str(PHASE2 / "include"),
               "-o", str(binp), str(csrc)])
    if not res.ok:
        return {"court": "ABI-LAYOUT", "verdict": "fail",
                "detail": {"compile_failed": res.stderr.strip().splitlines()[:8]}}
    ex = run([str(binp)])
    if not ex.ok:
        return {"court": "ABI-LAYOUT", "verdict": "fail",
                "detail": {"run_failed": ex.stderr.strip().splitlines()[:8]}}

    measured: dict[str, int] = {}
    for line in ex.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) == 3:
            measured[f"{parts[0]}\t{parts[1]}"] = int(parts[2])

    expected: dict[str, int] = {}
    for r in records:
        a = r["aggregate"]
        expected[f"sizeof\t{a}"] = r["sizeof"]
        expected[f"alignof\t{a}"] = r["alignof"]
        for f, off in r["field_offsetof"].items():
            expected[f"offsetof\t{a}.{f}"] = off

    missing = sorted(set(expected) - set(measured))
    differing = sorted(k for k in set(expected) & set(measured)
                       if expected[k] != measured[k])
    return {
        "court": "ABI-LAYOUT",
        "aggregates": len({r["aggregate"] for r in records}),
        "measurements": len(measured),
        "expected_measurements": len(expected),
        "missing_count": len(missing), "missing": missing[:20],
        "differing_count": len(differing),
        "differing": [{"key": k, "authority": expected[k], "candidate": measured[k]}
                      for k in differing[:20]],
        "verdict": "pass" if not (missing or differing) else "fail",
    }


def court_abi_link(auth) -> dict:
    src = COURT_DIR / "link_probe.c"
    write_text(src, LINK_PROBE)
    binp = COURT_DIR / "link_probe"
    res = run(["clang", "-std=c11", "-I", str(PHASE2 / "include"), "-o", str(binp), str(src),
               "-L", str(PHASE2), "-lssl", "-lcrypto",
               f"-Wl,-rpath,{PHASE2}"])
    if not res.ok:
        return {"court": "ABI-LINK", "verdict": "fail",
                "detail": {"link_failed": res.stderr.strip().splitlines()[:8]}}
    ex = run([str(binp)])
    return {"court": "ABI-LINK", "verdict": "pass" if ex.ok else "fail",
            "detail": {"output": ex.stdout.strip().splitlines()[:4],
                       "exit": ex.returncode}}


def court_abi_load(auth) -> dict:
    """Demand-load each candidate DSO and resolve EVERY exported symbol at its
    own declared version with dlvsym.

    This is the court that distinguishes a real versioned ABI from one that
    merely exports the right names. An application that binds
    `EVP_DigestInit_ex@OPENSSL_3.0.0` must resolve; so must
    `CRYPTO_secure_calloc@OPENSSL_3.6.0`. Binding to an unversioned substitute
    would be a silent ABI substitution and is exactly what this catches.
    """
    results = {}
    for lib, soname in sorted(LIBS.items()):
        doc = json.loads((authority_atlas_dir(auth.id) / f"symbols-{lib}.json").read_text())
        pairs = sorted(
            (r["symbol"], (r["dso"] or {}).get("version"))
            for r in doc["body"]["records"]
            if (r.get("dso") or {}).get("present") and (r.get("dso") or {}).get("version")
        )
        rows = "\n".join(
            '    {"' + s + '", "' + v + '"},' for s, v in pairs
        )
        src = (
            '#include <dlfcn.h>\n#include <stdio.h>\n\n'
            'static const struct { const char *name; const char *ver; } syms[] = {\n'
            + rows + '\n};\n\n'
            'int main(int argc, char **argv) {\n'
            '    if (argc < 2) return 2;\n'
            '    void *h = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);\n'
            '    if (!h) { fprintf(stderr, "dlopen failed: %s\\n", dlerror()); return 1; }\n'
            '    unsigned n = sizeof(syms) / sizeof(syms[0]), ok = 0, bad = 0;\n'
            '    for (unsigned i = 0; i < n; i++) {\n'
            '        if (dlvsym(h, syms[i].name, syms[i].ver)) ok++;\n'
            '        else { if (bad < 10) printf("  unresolved %s@%s\\n", syms[i].name, syms[i].ver); bad++; }\n'
            '    }\n'
            '    printf("load-probe %s: %u/%u resolved at declared versions, %u unresolved\\n",\n'
            '           argv[1], ok, n, bad);\n'
            '    dlclose(h);\n'
            '    return bad == 0 ? 0 : 3;\n'
            '}\n'
        )
        csrc = COURT_DIR / f"load_probe_{lib}.c"
        write_text(csrc, src)
        binp = COURT_DIR / f"load_probe_{lib}"
        res = run(["clang", "-std=c11", "-o", str(binp), str(csrc), "-ldl"])
        if not res.ok:
            results[lib] = {"verdict": "fail",
                            "detail": {"compile_failed": res.stderr.strip().splitlines()[:6]}}
            continue
        ex = run([str(binp), str(PHASE2 / soname)])
        results[lib] = {
            "verdict": "pass" if ex.ok else "fail",
            "symbols_tested": len(pairs),
            "output": ex.stdout.strip().splitlines()[:12],
            "exit": ex.returncode,
        }
    return {"court": "ABI-LOAD", "libraries": results,
            "verdict": "pass" if all(v["verdict"] == "pass" for v in results.values()) else "fail"}


def court_contamination(auth) -> dict:
    """The candidate DSO must not pull in a non-authority OpenSSL at runtime."""
    findings = {}
    for lib, soname in sorted(LIBS.items()):
        dso = PHASE2 / soname
        res = run(["readelf", "-d", "--wide", str(dso)])
        needed = []
        for line in res.stdout.splitlines():
            if "(NEEDED)" in line:
                needed.append(line.split("[")[-1].rstrip("]"))
        bad = [n for n in needed if "crypto" in n or n.startswith("libssl")]
        findings[lib] = {
            "needed": sorted(needed),
            "contaminating": sorted(bad),
            "note": "libssl.so.3 in the authority has NEEDED libcrypto.so.3; the "
                    "shell's stubs never call libcrypto, so it does not. That is a "
                    "recorded ABI difference, not a contamination finding.",
        }
    return {"court": "libcrypto-contamination", "libraries": findings,
            "verdict": "pass" if all(not f["contaminating"] for f in findings.values()) else "fail"}




def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Run the Phase 2 ABI shell courts.")
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    args = ap.parse_args(argv)
    auth = resolve_authority(args.authority)
    COURT_DIR.mkdir(parents=True, exist_ok=True)
    print(f"[phase2-courts] authority={auth.id}")

    courts = [
        court_abi_symbol(auth, {}),
        court_abi_version(auth, {}),
        court_abi_layout(auth),
        court_abi_link(auth),
        court_abi_load(auth),
        court_contamination(auth),
    ]

    summary = []
    for c in courts:
        name = c["court"]
        write_json(COURT_DIR / f"{name}.json", c)
        verdict = c.get("verdict", "unknown")
        summary.append({"court": name, "verdict": verdict})
        print(f"  {name:<26} {verdict}")

    body = {
        "authority": auth.id,
        "scaffold_warning": (
            "PASSING THESE COURTS IS NOT PARITY. Every symbol in the shell is "
            "SCAFFOLDED and aborts when called; these courts establish the "
            "structural distribution shell only (docs/CUSTODIAN_CONTRACT.md §5)."
        ),
        "courts": summary,
        "all_pass": all(s["verdict"] == "pass" for s in summary),
    }
    doc = envelope("phase2-courts", "forensics/tools/phase2_courts.py", [], body,
                   authority=auth.id)
    doc["body_hash"] = content_hash(body)
    write_json(PHASE2 / "COURTS.json", doc)
    print(f"  -> {rel(PHASE2 / 'COURTS.json')} all_pass={body['all_pass']}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
