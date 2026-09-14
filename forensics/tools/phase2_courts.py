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
import os
import subprocess
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
    """Exported API symbols of a candidate DSO.

    Records type, binding, visibility AND version, because ABI-SYMBOL compares
    all four: a symbol that is `OBJECT/WEAK` in the authority and
    `FUNC/GLOBAL` in the candidate is a different ABI, not a match.
    """
    out = {}
    for s in read_dynsyms(dso):
        if s.defined and s.bind in ("GLOBAL", "WEAK") and s.ndx != "ABS":
            out[s.name] = {"type": s.stype, "bind": s.bind,
                           "visibility": s.vis, "version": s.version}
    return out


def court_abi_symbol(auth, atlas: dict) -> dict:
    """The exported symbol surface, compared on name, ELF type, binding,
    visibility AND version node.

    Comparing only name+version would accept a symbol that is `OBJECT/WEAK` in
    the authority and `FUNC/GLOBAL` in the candidate. That is a real ABI
    difference: a consumer taking the address of a data object and the dynamic
    linker binding a function are not interchangeable. The shell generates every
    scaffold as `extern "C" fn`, so this court is specifically what proves that
    choice did not silently change any symbol's ELF type.
    """
    result = {"court": "ABI-SYMBOL", "libraries": {}}
    for lib, soname in sorted(LIBS.items()):
        doc = json.loads((authority_atlas_dir(auth.id) / f"symbols-{lib}.json").read_text())
        expected = {
            r["symbol"]: {
                "type": (r["dso"] or {}).get("type"),
                "bind": (r["dso"] or {}).get("bind"),
                "visibility": (r["dso"] or {}).get("visibility"),
                "version": (r["dso"] or {}).get("version"),
            }
            for r in doc["body"]["records"] if (r.get("dso") or {}).get("present")
        }
        actual = candidate_export(PHASE2 / soname)
        common = set(expected) & set(actual)
        missing = sorted(set(expected) - set(actual))
        extra = sorted(set(actual) - set(expected))

        def mismatch(field: str) -> list[dict]:
            return [
                {"symbol": s, "authority": expected[s].get(field),
                 "candidate": actual[s].get(field)}
                for s in sorted(common)
                if expected[s].get(field) != actual[s].get(field)
            ]

        version_mismatch = mismatch("version")
        type_mismatch = mismatch("type")
        bind_mismatch = mismatch("bind")
        visibility_mismatch = mismatch("visibility")
        result["libraries"][lib] = {
            "authority_exported": len(expected),
            "candidate_exported": len(actual),
            "missing": missing, "extra": extra,
            "version_mismatch": version_mismatch,
            "type_mismatch": type_mismatch,
            "bind_mismatch": bind_mismatch,
            "visibility_mismatch": visibility_mismatch,
            "fields_compared": ["name", "version", "type", "bind", "visibility"],
            "verdict": "pass" if not (missing or extra or version_mismatch
                                      or type_mismatch or bind_mismatch
                                      or visibility_mismatch) else "fail",
        }
    result["verdict"] = "pass" if all(
        v["verdict"] == "pass" for v in result["libraries"].values()) else "fail"
    return result


# The dynamic contract: the tags a downstream loader and a packaging system act
# on. Only the REQUIRED subset can be equal in full, because a Rust-linked
# artifact necessarily carries toolchain runtime dependencies the C authority
# does not; that is why the court distinguishes required from extra rather than
# pretending a set equality it cannot have.
REQUIRED_DYNAMIC = ["DT_SONAME"]


def _dynamic_tags(dso: Path) -> dict:
    res = run(["readelf", "-d", "--wide", str(dso)])
    needed, soname = [], None
    for line in res.stdout.splitlines():
        if "(NEEDED)" in line:
            needed.append(line.split("[")[-1].rstrip("]"))
        elif "(SONAME)" in line:
            soname = line.split("[")[-1].rstrip("]")
    hdr = run(["readelf", "-h", str(dso)])
    klass = typ = machine = None
    for line in hdr.stdout.splitlines():
        s = line.strip()
        if s.startswith("Class:"):
            klass = s.split(":", 1)[1].strip()
        elif s.startswith("Type:"):
            typ = s.split(":", 1)[1].strip()
        elif s.startswith("Machine:"):
            machine = s.split(":", 1)[1].strip()
    return {"soname": soname, "needed": sorted(needed),
            "class": klass, "type": typ, "machine": machine}


def court_abi_dynamic(auth) -> dict:
    """ABI-DYNAMIC: SONAME, DT_NEEDED, ELF class/type/machine.

    Required: identical SONAME and ELF identity, and every dependency the
    authority declares must be present in the candidate. Found by review: the
    candidate libssl.so.3 was missing `DT_NEEDED libcrypto.so.3`, which the
    authority declares and which `docs/CUSTODIAN_CONTRACT.md` §2 names as part
    of the contract (separate runtime dependency relationships).

    Extra dependencies (the toolchain runtime) are recorded, not ignored, and do
    not fail the court: they cannot be removed from a Rust-linked artifact and
    are visible to any consumer who looks.
    """
    result = {"court": "ABI-DYNAMIC", "libraries": {}}
    for lib, soname in sorted(LIBS.items()):
        a = _dynamic_tags(auth.dso(lib))
        c = _dynamic_tags(PHASE2 / soname)
        required_missing = sorted(set(a["needed"]) - set(c["needed"]))
        extra = sorted(set(c["needed"]) - set(a["needed"]))
        identity_ok = (a["class"] == c["class"] and a["machine"] == c["machine"]
                       and a["type"] == c["type"])
        soname_ok = a["soname"] == c["soname"]
        result["libraries"][lib] = {
            "authority": a, "candidate": c,
            "soname_match": soname_ok,
            "elf_identity_match": identity_ok,
            "required_needed_missing": required_missing,
            "extra_needed_recorded": extra,
            # TWO VERDICTS, deliberately. The required contract must hold; full
            # DT_NEEDED set equality cannot, because a Rust-linked artifact
            # necessarily carries toolchain runtime dependencies the C authority
            # does not (libgcc_s.so.1, ld-linux-x86-64.so.2). One clean "pass"
            # would hide a structural residual; one "fail" would block on
            # something that is not a defect.
            "required_verdict": "pass" if (soname_ok and identity_ok and not required_missing)
                               else "fail",
            "exact_verdict": "pass" if not extra else "residual",
            "exact_residual_note": (
                "authority DT_NEEDED is a strict subset of the candidate's; "
                + str(len(extra)) + " extra runtime dependency/ies: "
                + ", ".join(extra)
            ) if extra else "",
        }
    result["required_verdict"] = "pass" if all(
        v["required_verdict"] == "pass" for v in result["libraries"].values()) else "fail"
    result["exact_verdict"] = "pass" if all(
        v["exact_verdict"] == "pass" for v in result["libraries"].values()) else "residual"
    result["verdict"] = result["required_verdict"]
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
    """No non-authority OpenSSL may appear in the candidate's RUNTIME CLOSURE.

    The question is not "does the candidate depend on a library called
    libcrypto" -- `libssl.so.3` SHOULD declare `NEEDED libcrypto.so.3`, the
    authority does, and `docs/CUSTODIAN_CONTRACT.md` §2 names that dependency as
    part of the contract. The question is whether anything resolves to an OpenSSL
    that is not ours.

    An earlier revision of this court conflated the two and flagged the correct
    dependency as contamination. That was a defect in the court, found when
    libssl's dependency was restored; the corrected form below resolves the
    closure and requires every OpenSSL it finds to live inside the candidate's
    own install tree.
    """
    libdir = PHASE2 / "install" / "lib"
    env = dict(os.environ)
    env["LD_LIBRARY_PATH"] = str(libdir)
    findings = {}
    for lib, soname in sorted(LIBS.items()):
        dso = PHASE2 / soname
        res = run(["readelf", "-d", "--wide", str(dso)])
        needed = sorted(
            l.split("[")[-1].rstrip("]") for l in res.stdout.splitlines()
            if "(NEEDED)" in l
        )
        ex = subprocess.run(["ldd", str(dso)], capture_output=True, text=True,
                            env=env, check=False)
        resolved = [l.strip() for l in ex.stdout.splitlines()
                    if "libcrypto" in l or "libssl" in l]
        outside = [l for l in resolved if str(PHASE2) not in l]
        findings[lib] = {
            "needed": needed,
            "resolved_openssl_closure": resolved,
            "resolved_outside_candidate": outside,
            "verdict": "pass" if not outside else "fail",
        }
    return {"court": "libcrypto-contamination", "libraries": findings,
            "note": "necessity of libcrypto.so.3 for libssl is asserted by "
                    "ABI-DYNAMIC, not here; this court asserts the RESOLVED PATH",
            "verdict": "pass" if all(f["verdict"] == "pass" for f in findings.values())
                       else "fail"}




def _compile_consumer(include_dir: Path, lib_dir: Path, out: Path,
                      src: Path, rpath: Path) -> tuple[bool, str]:
    res = run(["clang", "-std=c11", "-I", str(include_dir), "-o", str(out), str(src),
               "-L", str(lib_dir), "-lssl", "-lcrypto", f"-Wl,-rpath,{rpath}"])
    return res.ok, res.stderr.strip()


def court_abi_matrix(auth) -> dict:
    """The four oracle/candidate combinations.

    `docs/ABI_POLICY.md` §1 requires all four, because the cross combinations are
    what separate SOURCE compatibility from BINARY compatibility:

        authority headers + authority libs   (baseline)
        candidate headers + candidate libs   (self-consistent)
        authority headers + candidate libs   <- binary compatibility
        candidate headers + authority libs   <- reverse direction
    """
    src = COURT_DIR / "matrix_probe.c"
    write_text(src, LINK_PROBE)
    combos = [
        ("authority-headers+authority-libs", auth.prefix / "include", auth.prefix / "lib"),
        ("candidate-headers+candidate-libs", PHASE2 / "install" / "include",
         PHASE2 / "install" / "lib"),
        ("authority-headers+candidate-libs", auth.prefix / "include",
         PHASE2 / "install" / "lib"),
        ("candidate-headers+authority-libs", PHASE2 / "install" / "include",
         auth.prefix / "lib"),
    ]
    results = {}
    for name, inc, lib in combos:
        out = COURT_DIR / f"matrix_{name.replace('+', '_').replace('-', '_')}"
        ok, err = _compile_consumer(inc, lib, out, src, lib)
        if not ok:
            results[name] = {"verdict": "fail", "stage": "compile_or_link",
                             "diagnostic": err.splitlines()[:5]}
            continue
        ex = run([str(out)])
        results[name] = {"verdict": "pass" if ex.ok else "fail", "stage": "run",
                         "output": ex.stdout.strip().splitlines()[:2],
                         "exit": ex.returncode}
    return {"court": "ABI-MATRIX", "combinations": results,
            "verdict": "pass" if all(v["verdict"] == "pass" for v in results.values()) else "fail"}


def court_abi_substitution(auth) -> dict:
    """Binary substitution: one executable, two library providers.

    Build ONCE against the authority's headers and libraries, run it against the
    authority, then run the SAME binary with `LD_LIBRARY_PATH` pointing at the
    candidate install -- no recompilation. This is the strongest structural ABI
    proof available while the implementation is still a scaffold, because nothing
    about the executable changes between the two runs.

    `-Wl,-rpath` emits `DT_RUNPATH`, which `LD_LIBRARY_PATH` legitimately
    overrides; that is the mechanism, and it is asserted rather than assumed.
    """
    src = COURT_DIR / "subst_probe.c"
    write_text(src, LINK_PROBE)
    out = COURT_DIR / "subst_probe"
    ok, err = _compile_consumer(auth.prefix / "include", auth.prefix / "lib", out, src,
                                auth.prefix / "lib")
    if not ok:
        return {"court": "ABI-SUBSTITUTION", "verdict": "fail",
                "detail": {"build_failed": err.splitlines()[:5]}}
    # run 1: against the authority it was built against
    ex1 = run([str(out)])
    # run 2: the SAME binary, candidate libraries injected
    env = dict(os.environ)
    env["LD_LIBRARY_PATH"] = str(PHASE2 / "install" / "lib")
    p2 = subprocess.run([str(out)], capture_output=True, text=True, env=env, check=False)
    p2 = subprocess.run([str(out)], capture_output=True, text=True, env=env, check=False)
    ldd = subprocess.run(
        ["sh", "-c", f"LD_LIBRARY_PATH={PHASE2 / 'install' / 'lib'} ldd {out}"],
        capture_output=True, text=True, check=False,
    )
    lines = [l.strip() for l in ldd.stdout.splitlines() if "libcrypto" in l or "libssl" in l]
    substituted = all(str(PHASE2 / "install" / "lib") in l for l in lines) and bool(lines)
    return {
        "court": "ABI-SUBSTITUTION",
        "authority_run_exit": ex1.returncode,
        "authority_run_output": ex1.stdout.strip().splitlines()[:2],
        "candidate_run_exit": p2.returncode,
        "candidate_run_output": p2.stdout.strip().splitlines()[:2],
        "dynamic_closure_under_substitution": lines,
        "substitution_took_effect": substituted,
        "verdict": "pass" if (ex1.returncode == 0 and p2.returncode == 0 and substituted)
                   else "fail",
    }


CONSTANTS_PROBE = r"""
#include <stdio.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/objects.h>
#include <openssl/opensslv.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/x509_vfy.h>

#define P(x) printf("%s\t%lld\n", #x, (long long)(x))

int main(void) {
    P(OPENSSL_VERSION_NUMBER);
    P(OPENSSL_VERSION_MAJOR); P(OPENSSL_VERSION_MINOR); P(OPENSSL_VERSION_PATCH);
    P(EVP_MAX_MD_SIZE); P(EVP_MAX_KEY_LENGTH); P(EVP_MAX_IV_LENGTH);
    P(EVP_MAX_BLOCK_LENGTH);
    P(SHA256_DIGEST_LENGTH); P(SHA512_DIGEST_LENGTH); P(MD5_DIGEST_LENGTH);
    P(AES_BLOCK_SIZE);
    P(TLS1_2_VERSION); P(TLS1_3_VERSION); P(DTLS1_2_VERSION);
    P(X509_V_OK); P(X509_V_ERR_CERT_HAS_EXPIRED);
    P(NID_sha256); P(NID_sha512); P(NID_X9_62_prime256v1);
    P(EVP_PKEY_RSA); P(EVP_PKEY_EC); P(EVP_PKEY_ED25519); P(EVP_PKEY_X25519);
    P(SSL_VERIFY_NONE); P(SSL_VERIFY_PEER); P(SSL_VERIFY_FAIL_IF_NO_PEER_CERT);
    return 0;
}
"""


def court_abi_constants(auth) -> dict:
    """Compile the SAME constants probe against both header sets and compare.

    Constants are part of source compatibility: a consumer branches on
    `TLS1_3_VERSION` or `EVP_MAX_MD_SIZE` at compile time, so a value that differs
    is a silent behavioural divergence with no runtime symptom.
    """
    src = COURT_DIR / "constants_probe.c"
    write_text(src, CONSTANTS_PROBE)
    outs = {}
    for label, inc in (("authority", auth.prefix / "include"),
                       ("candidate", PHASE2 / "install" / "include")):
        binp = COURT_DIR / f"constants_{label}"
        res = run(["clang", "-std=c11", "-I", str(inc), "-o", str(binp), str(src)])
        if not res.ok:
            return {"court": "ABI-CONSTANTS", "verdict": "fail",
                    "detail": {f"{label}_compile_failed": res.stderr.strip().splitlines()[:6]}}
        ex = run([str(binp)])
        outs[label] = {l.split("\t")[0]: l.split("\t")[1]
                       for l in ex.stdout.splitlines() if "\t" in l}
    keys = sorted(set(outs["authority"]) | set(outs["candidate"]))
    differing = [{"constant": k, "authority": outs["authority"].get(k),
                  "candidate": outs["candidate"].get(k)}
                 for k in keys if outs["authority"].get(k) != outs["candidate"].get(k)]
    return {"court": "ABI-CONSTANTS", "constants_compared": len(keys),
            "differing_count": len(differing), "differing": differing[:20],
            "values": {k: outs["authority"].get(k) for k in keys},
            "verdict": "pass" if not differing else "fail"}


# Required install-layout entries: what a consumer's build system, pkg-config
# and the provider loader actually need. Anything else the authority installs
# (cmake config, engines-3) is reported as an optional difference, not a failure.
REQUIRED_INSTALL = [
    "bin/openssl", "bin/c_rehash",
    "include/openssl/opensslv.h", "include/openssl/evp.h", "include/openssl/ssl.h",
    "lib/libcrypto.so.3", "lib/libssl.so.3",
    "lib/libcrypto.so", "lib/libssl.so",
    "lib/libcrypto.a", "lib/libssl.a",
    "lib/ossl-modules/legacy.so",
    "lib/pkgconfig/libcrypto.pc", "lib/pkgconfig/libssl.pc",
]


def court_install_layout(auth) -> dict:
    """The install layout is an observable contract.

    Also asserts the provider module carries `NEEDED libcrypto.so.3`, because a
    module that loads without the dependency the authority declares is a
    different contract even if it loads successfully.
    """
    root = PHASE2 / "install"
    present, missing = [], []
    for relp in REQUIRED_INSTALL:
        p = root / relp
        (present if (p.exists() or p.is_symlink()) else missing).append(relp)
    # the provider module's declared dependency
    res = run(["readelf", "-d", "--wide", str(root / "lib/ossl-modules/legacy.so")])
    needed = [l.split("[")[-1].rstrip("]") for l in res.stdout.splitlines() if "(NEEDED)" in l]
    provider_ok = "libcrypto.so.3" in needed
    # optional differences vs the authority
    optional = {}
    for relp in ("lib/cmake", "lib/engines-3"):
        optional[relp] = (auth.prefix / relp).exists() and not (root / relp).exists()
    return {
        "court": "ABI-INSTALL-LAYOUT",
        "required_present": present, "required_missing": missing,
        "provider_module_needed": sorted(needed),
        "provider_declares_libcrypto": provider_ok,
        "optional_absent_vs_authority": {k: v for k, v in optional.items() if v},
        "verdict": "pass" if (not missing and provider_ok) else "fail",
    }


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
        court_abi_dynamic(auth),
        court_abi_layout(auth),
        court_abi_link(auth),
        court_abi_load(auth),
        court_abi_constants(auth),
        court_abi_matrix(auth),
        court_abi_substitution(auth),
        court_install_layout(auth),
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
