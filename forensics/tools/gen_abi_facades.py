#!/usr/bin/env python3
"""openssl-rs — the historical ABI/history façades' evidence and generated Rust.

Phase 23.7 is the compatibility-policy layer and the historical ABI façades
(`docs/PHASE-23-MULTITRACK-SUBPHASES.md` section 2, row 23.7). The façades are **narrow
typed adapters over the shared implementation**, never per-version forks and never a blind
cast of an old layout to a modern Rust object. This tool is their evidence half.

Two tiers, deliberately
-----------------------
The compatibility generation 23.7 establishes is the one that **predates the 1.1.0 opacity
transition**: in OpenSSL 0.9.8zh a public header defines `struct evp_md_ctx_st` and
`struct hmac_ctx_st` in full (transparent), while in the 3.6.4 production authority both are
opaque (`types.h` forward declarations, `complete = false` in the committed atlas). The
façade layouts are the historical ones, and they can only be measured by compiling a probe
against the historical release's own headers.

  * **`--measure`** runs *only* in the historical venue, where the acquired 0.9.8zh source
    tree is present: it configures a copy of the pristine tree, compiles a probe against the
    release's own header view, runs it, and writes `forensics/multitrack/abi-facades.json`
    with the measured `sizeof` / `alignof` / `offsetof` / field width for each façade, the
    prototype differences across eras, and the ENGINE/Provider and init/thread epochs. Every
    layout record cites the header it was measured from and that header's SHA-256 in the
    committed source manifest, so the measurement is bound to committed authority evidence
    rather than to a mutable tree.

  * **the default run** is the *materialisation* the court and `regen_all.sh` drive: it reads
    the committed `abi-facades.json`, re-checks every provenance link against the committed
    source manifest, and regenerates `src/compat/layout_generated.rs` — the `#[repr(C)]`
    façade structs and the compile-time `const _: () = assert!(...)` set that pins each
    struct's size, alignment, field offset and field width to the measurement. It needs no
    compiler and no authority source, so it is reproducible in the court container and the
    generated `.rs` cannot drift from the committed measurement.

What this tool refuses to invent
--------------------------------
A layout it cannot measure is recorded `not established` with its reason rather than guessed
at: the released 1.0.x epoch is not admitted as an authority here (no acquired source tree),
so no 1.0.x façade is claimed. The coverage boundary is written into the artefact body.

Outputs
-------
  forensics/multitrack/abi-facades.json      (committed: the measurement + the prototype,
                                              architecture and init/thread epoch records)
  src/compat/layout_generated.rs             (committed: generated repr(C) façades + asserts)

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import (  # noqa: E402
    PRODUCTION_AUTHORITY,
    REPO_ROOT,
    InputRef,
    envelope,
    rel,
    run,
    sha256_file,
    write_json,
)

GENERATOR = "forensics/tools/gen_abi_facades.py"
OUT_JSON = REPO_ROOT / "forensics" / "multitrack" / "abi-facades.json"
OUT_RUST = REPO_ROOT / "src" / "compat" / "layout_generated.rs"

HISTORICAL_AUTHORITY = "openssl-0.9.8zh-historical"
HISTORICAL_RELEASE = "openssl-0.9.8zh"
HISTORICAL_EPOCH = "0.9.8zh"

ACQUISITION = REPO_ROOT / "forensics" / "multitrack" / "historical-acquisition.json"

# The venue marker docker/openssl-rs-historical.Dockerfile creates. `--measure` refuses
# without it, exactly as `historical_build.py` does: a layout measured with the court's
# compiler would not bind the historical venue the build receipt records.
VENUE_MARKER = Path("/historical/toolchain.txt")

# The source-manifest name the acquisition record names, and the header directory the
# configured tree materialises (`Configure` symlinks the public headers into `include/openssl`).
MANIFEST_NAME = "SOURCE_MANIFEST.0.9.8zh.json"

# --------------------------------------------------------------------------------------------
# The façades. Each struct is declared here with the fields the 0.9.8zh header defines, in the
# header's order; the measurement supplies the offsets and widths. `c_type` is transcribed from
# the header and re-checked against the header text by `--measure`.
# --------------------------------------------------------------------------------------------

# A `STRUCTS` row's `c_type` strings are mapped to Rust by RUST_TYPE below; a type with no
# mapping is a hard failure rather than a guessed representation.
RUST_TYPE = {
    "const EVP_MD *": "*const crate::evp::digest::EvpMd",
    "ENGINE *": "*mut c_void",
    "unsigned long": "c_ulong",
    "void *": "*mut c_void",
    "unsigned int": "c_uint",
}

# C scalar widths and their Rust primitive, materialised in the generated assertions.
SCALAR_RUST = {
    "unsigned char": "c_uchar",
    "unsigned long": "c_ulong",
    "unsigned int": "c_uint",
    "int": "c_int",
}

STRUCTS: list[dict] = [
    {
        "facade_id": "F-EVP_MD_CTX-0.9.8zh",
        "struct_name": "EVP_MD_CTX",
        "c_tag": "env_md_ctx_st",
        "canonical_c_tag": "evp_md_ctx_st",
        "rust_type": "FacadeEvpMdCtx",
        "header": "crypto/evp/evp.h",
        "installed_header": "openssl/evp.h",
        "fields": [
            ("digest", "const EVP_MD *"),
            ("engine", "ENGINE *"),
            ("flags", "unsigned long"),
            ("md_data", "void *"),
        ],
        "canonical_type": "crate::evp::digest::EvpMdCtx",
        "adapter": "compat::adapters::evp_md_ctx_from_pre_1_1_0",
        "canonical_authority": PRODUCTION_AUTHORITY,
    },
    {
        "facade_id": "F-HMAC_CTX-0.9.8zh",
        "struct_name": "HMAC_CTX",
        "c_tag": "hmac_ctx_st",
        "canonical_c_tag": "hmac_ctx_st",
        "rust_type": "FacadeHmacCtx",
        "header": "crypto/hmac/hmac.h",
        "installed_header": "openssl/hmac.h",
        "fields": [
            ("md", "const EVP_MD *"),
            ("md_ctx", "EVP_MD_CTX"),
            ("i_ctx", "EVP_MD_CTX"),
            ("o_ctx", "EVP_MD_CTX"),
            ("key_length", "unsigned int"),
            ("key", "unsigned char []"),
        ],
        "canonical_type": "crate::mac::hmac::HmacCtx",
        "adapter": "compat::adapters::hmac_state_from_pre_1_1_0",
        "canonical_authority": PRODUCTION_AUTHORITY,
    },
]

# The same exported name with a different declaration across eras. `function` and `macro` are
# the two shapes a C symbol's contract takes; a macro contract has no runtime signature at all,
# which is exactly why the selected distribution must export the authority-specific prototype.
PROTOTYPES: list[dict] = [
    {
        "facade_id": "P-EVP_MD_CTX_init",
        "symbol": "EVP_MD_CTX_init",
        "historical": {
            "declaration": "void (EVP_MD_CTX *)",
            "kind": "function",
            "header": "crypto/evp/evp.h",
            "line": 550,
        },
        "canonical": {"declaration": "EVP_MD_CTX_reset((ctx))", "kind": "macro", "header": "evp.h"},
        "adapter": "compat::prototypes::evp_md_ctx_init",
    },
    {
        "facade_id": "P-EVP_MD_CTX_create",
        "symbol": "EVP_MD_CTX_create",
        "historical": {
            "declaration": "EVP_MD_CTX *(void)",
            "kind": "function",
            "header": "crypto/evp/evp.h",
            "line": 552,
        },
        "canonical": {"declaration": "EVP_MD_CTX_new()", "kind": "macro", "header": "evp.h"},
        "adapter": "compat::prototypes::evp_md_ctx_create",
    },
    {
        "facade_id": "P-EVP_MD_CTX_destroy",
        "symbol": "EVP_MD_CTX_destroy",
        "historical": {
            "declaration": "void (EVP_MD_CTX *)",
            "kind": "function",
            "header": "crypto/evp/evp.h",
            "line": 553,
        },
        "canonical": {"declaration": "EVP_MD_CTX_free((ctx))", "kind": "macro", "header": "evp.h"},
        "adapter": "compat::prototypes::evp_md_ctx_destroy",
    },
    {
        "facade_id": "P-HMAC_Init_ex",
        "symbol": "HMAC_Init_ex",
        "historical": {
            "declaration": "void (HMAC_CTX *, const void *, int, const EVP_MD *, ENGINE *)",
            "kind": "function",
            "header": "crypto/hmac/hmac.h",
            "line": 89,
        },
        "canonical": {
            "declaration": "int (HMAC_CTX *, const void *, int, const EVP_MD *, ENGINE *)",
            "kind": "function",
            "header": "hmac.h",
        },
        "adapter": "compat::prototypes::hmac_init_ex",
    },
    {
        "facade_id": "P-HMAC_Update",
        "symbol": "HMAC_Update",
        "historical": {
            "declaration": "void (HMAC_CTX *, const unsigned char *, size_t)",
            "kind": "function",
            "header": "crypto/hmac/hmac.h",
            "line": 90,
        },
        "canonical": {
            "declaration": "int (HMAC_CTX *, const unsigned char *, size_t)",
            "kind": "function",
            "header": "hmac.h",
        },
        "adapter": "compat::prototypes::hmac_update",
    },
    {
        "facade_id": "P-HMAC_Final",
        "symbol": "HMAC_Final",
        "historical": {
            "declaration": "void (HMAC_CTX *, unsigned char *, unsigned int *)",
            "kind": "function",
            "header": "crypto/hmac/hmac.h",
            "line": 91,
        },
        "canonical": {
            "declaration": "int (HMAC_CTX *, unsigned char *, unsigned int *)",
            "kind": "function",
            "header": "hmac.h",
        },
        "adapter": "compat::prototypes::hmac_final",
    },
    {
        "facade_id": "P-CRYPTO_set_locking_callback",
        "symbol": "CRYPTO_set_locking_callback",
        "historical": {
            "declaration": "void (void (*)(int, int, const char *, int))",
            "kind": "function",
            "header": "crypto/crypto.h",
            "line": 433,
        },
        "canonical": {"declaration": "", "kind": "macro", "header": "crypto.h"},
        "adapter": "compat::prototypes::crypto_set_locking_callback",
    },
]

# The architecture and init/thread epochs, each read from committed evidence. The historical
# side's epoch facts come from the plane census; the canonical side's from the production
# atlas and the parameterization receipt.
NOT_ESTABLISHED = [
    {
        "claim": "the released 1.0.x public layouts (1.0.0-1.0.2)",
        "reason": (
            "no 1.0.x authority is admitted with an acquired source tree in this subphase, so "
            "its headers cannot be measured; the 1.0.x epoch is left uncovered rather than "
            "inferred from the 0.9.8zh layouts"
        ),
    },
    {
        "claim": "the pre-1.1.0 layouts of BIO, RSA, X509, SSL, SSL_CTX, SSL_SESSION and BIGNUM",
        "reason": (
            "the subphase establishes a small, provable epoch (EVP_MD_CTX and the HMAC_CTX that "
            "embeds it) rather than a broad unproven claim; each additional struct needs its own "
            "measured layout, and none is inferred from a sibling"
        ),
    },
]

BOUNDARY = (
    "This plane covers the 0.9.8zh -> 3.6.4 epoch transition only, and only the aggregates and "
    "prototypes it names. The historical layout side is measured from the 0.9.8zh headers in the "
    "historical venue; the 3.6.4 side is the committed production atlas. A 1.0.x layout, or a "
    "pre-1.1.0 aggregate not named here, is recorded `not established` with its reason rather "
    "than inferred (docs/PHASE-23-MULTITRACK-SUBPHASES.md section 4.10)."
)

PROBE_TEMPLATE = """\
/* Generated by forensics/tools/gen_abi_facades.py -- do not edit. */
#include <stddef.h>
#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

int main(void) {{
{probes}
    return 0;
}}
"""


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _probe_source() -> str:
    probes: list[str] = []
    for s in STRUCTS:
        t = s["struct_name"]
        probes.append(f'    printf("sizeof\\t{t}\\t%zu\\n", sizeof({t}));')
        probes.append(f'    printf("alignof\\t{t}\\t%zu\\n", _Alignof({t}));')
        for name, _c in s["fields"]:
            probes.append(
                f'    printf("offsetof\\t{t}\\t{name}\\t%zu\\n", offsetof({t}, {name}));'
            )
            probes.append(
                f'    printf("fieldsize\\t{t}\\t{name}\\t%zu\\n", '
                f"sizeof((({t} *)0)->{name}));"
            )
    probes.append('    printf("macro\\tHMAC_MAX_MD_CBLOCK\\t%d\\n", HMAC_MAX_MD_CBLOCK);')
    return PROBE_TEMPLATE.format(probes="\n".join(probes))


def _parse_probe(stdout: str) -> dict:
    sizes: dict[str, int] = {}
    aligns: dict[str, int] = {}
    offsets: dict[str, dict[str, int]] = {}
    widths: dict[str, dict[str, int]] = {}
    macros: dict[str, int] = {}
    for line in stdout.splitlines():
        parts = line.split("\t")
        if parts[0] == "sizeof" and len(parts) == 3:
            sizes[parts[1]] = int(parts[2])
        elif parts[0] == "alignof" and len(parts) == 3:
            aligns[parts[1]] = int(parts[2])
        elif parts[0] == "offsetof" and len(parts) == 4:
            offsets.setdefault(parts[1], {})[parts[2]] = int(parts[3])
        elif parts[0] == "fieldsize" and len(parts) == 4:
            widths.setdefault(parts[1], {})[parts[2]] = int(parts[3])
        elif parts[0] == "macro" and len(parts) == 3:
            macros[parts[1]] = int(parts[2])
    return {"sizeof": sizes, "alignof": aligns, "offsetof": offsets,
            "fieldsize": widths, "macro": macros}


def _configure_tree(acq: dict) -> Path:
    """A configured copy of the pristine 0.9.8zh source; the pristine tree is never edited."""
    aid = acq["id"]
    pristine = REPO_ROOT / acq["source_tree"]["path"]
    root = REPO_ROOT / "forensics" / "authorities" / "build" / f"{aid}-abi-facades"
    src = root / "src"
    if not pristine.is_dir():
        raise SystemExit(
            f"[abi-facades] the acquired source tree is absent: {rel(pristine)}; run "
            f"`authority_acquire.py --historical {HISTORICAL_RELEASE}` in the historical venue"
        )
    if not (src / "Makefile").is_file():
        if src.exists():
            shutil.rmtree(src)
        shutil.copytree(pristine, src, symlinks=True)
        res = run(["perl", "Configure", "linux-x86_64",
                   f"--prefix={root / 'prefix'}", "shared"], cwd=src)
        if not res.ok:
            raise SystemExit(f"[abi-facades] Configure failed: {res.stderr.strip()[:400]}")
    return src


def measure() -> dict:
    """Measure every façade layout against the 0.9.8zh release's own configured headers."""
    if not VENUE_MARKER.is_file():
        raise SystemExit(
            "[abi-facades] --measure runs only in the historical venue (no /historical marker); "
            "run it through `bash docker/openssl-rs-historical.sh exec ...`"
        )
    acquisitions = {a["release_id"]: a for a in read_json(ACQUISITION)["acquisitions"]}
    acq = acquisitions.get(HISTORICAL_RELEASE)
    if acq is None:
        raise SystemExit(f"[abi-facades] {HISTORICAL_RELEASE} is not acquired")
    src = _configure_tree(acq)

    manifest = read_json(REPO_ROOT / "forensics" / "authorities" / MANIFEST_NAME)
    by_path = {f["path"]: f["sha256"] for f in manifest["files"]}

    probe = _probe_source()
    probe_path = src / "abi_facades_probe.c"
    bin_path = src / "abi_facades_probe"
    probe_path.write_text(probe, encoding="utf-8")
    try:
        comp = run(["cc", "-std=c11", "-Iinclude", "-o", str(bin_path), str(probe_path)], cwd=src)
        if not comp.ok:
            raise SystemExit(
                f"[abi-facades] probe did not compile: {comp.stderr.strip()[:600]}"
            )
        res = run([str(bin_path)], cwd=src)
        if not res.ok:
            raise SystemExit(f"[abi-facades] probe did not run: {res.stderr.strip()[:400]}")
        measured = _parse_probe(res.stdout)
    finally:
        probe_path.unlink(missing_ok=True)
        bin_path.unlink(missing_ok=True)

    def verify_field_list(header_text: str, s: dict) -> None:
        flat = "".join(header_text.split())
        for name, _c in s["fields"]:
            if name not in flat:
                raise SystemExit(
                    f"[abi-facades] field {name!r} is not in the {s['header']} text; the "
                    f"declared field list has drifted from the authority header"
                )

    facades: list[dict] = []
    for s in STRUCTS:
        header = s["header"]
        if header not in by_path:
            raise SystemExit(f"[abi-facades] {header} is not in {MANIFEST_NAME}")
        verify_field_list((src / header).read_text(encoding="utf-8", errors="replace"), s)
        t = s["struct_name"]
        fields = [
            {
                "name": name,
                "c_type": c_type,
                "offset": measured["offsetof"][t][name],
                "size": measured["fieldsize"][t][name],
            }
            for name, c_type in s["fields"]
        ]
        for a, b in zip(fields, fields[1:]):
            if a["offset"] + a["size"] > b["offset"]:
                raise SystemExit(
                    f"[abi-facades] {t}: field {a['name']} overlaps {b['name']}; the probe "
                    f"output is not a valid layout"
                )
        if fields and fields[-1]["offset"] + fields[-1]["size"] > measured["sizeof"][t]:
            raise SystemExit(f"[abi-facades] {t}: the last field runs past sizeof")
        facades.append({
            "facade_id": s["facade_id"],
            "facade_kind": "public_layout",
            "authority_id": acq["id"],
            "release_id": HISTORICAL_RELEASE,
            "epoch": HISTORICAL_EPOCH,
            "struct_name": t,
            "c_tag": s["c_tag"],
            "canonical_c_tag": s["canonical_c_tag"],
            "rust_type": s["rust_type"],
            "header": header,
            "installed_header": s["installed_header"],
            "header_sha256": by_path[header],
            "public_layout_epoch": "transparent_pre_1_1_0",
            "sizeof": measured["sizeof"][t],
            "alignof": measured["alignof"][t],
            "fields": fields,
            "canonical_type": s["canonical_type"],
            "canonical_authority_id": s["canonical_authority"],
            "canonical_public_layout_epoch": "opaque_post_1_1_0",
            "adapter": s["adapter"],
            "layout_check": f"compat::layout_generated::{s['rust_type']}",
            "not_established": [],
            "evidence": [
                f"forensics/authorities/{MANIFEST_NAME}#{header}",
                f"forensics/atlas/{PRODUCTION_AUTHORITY}/structs.json#{s['canonical_c_tag']}",
            ],
        })

    # Prototype records: the historical declaration is re-checked against the header text; the
    # canonical declaration comes from the committed production atlas.
    functions = {
        r["name"]: r
        for r in read_json(REPO_ROOT / "forensics" / "atlas" / PRODUCTION_AUTHORITY
                           / "functions.json")["body"]["records"]
    }
    macros = {
        r["name"]: r
        for r in read_json(REPO_ROOT / "forensics" / "atlas" / PRODUCTION_AUTHORITY
                           / "macros.json")["body"]["records"]
    }
    for p in PROTOTYPES:
        h = p["historical"]
        flat = "".join((src / h["header"]).read_text(encoding="utf-8",
                                                      errors="replace").split())
        symbol = p["symbol"]
        decl = h["declaration"]
        # The era's declaration is present, up to whitespace: the return type immediately
        # precedes the symbol name in the header.
        ret = decl.split("(")[0].strip()
        if symbol not in flat or (ret + symbol).replace(" ", "") not in flat:
            raise SystemExit(
                f"[abi-facades] {symbol}: the era declaration {decl!r} is not in {h['header']}"
            )
        canonical = p["canonical"]
        if canonical["kind"] == "function":
            rec = functions.get(symbol)
            if rec is None or rec["type"].split(" (")[0].strip() != canonical["declaration"].split(" (")[0].strip():
                raise SystemExit(
                    f"[abi-facades] {symbol}: canonical declaration {canonical['declaration']!r} "
                    f"is not the production atlas's {rec and rec['type']!r}"
                )
            evidence = [
                f"forensics/atlas/{PRODUCTION_AUTHORITY}/functions.json#{symbol}",
            ]
        else:
            if symbol not in macros:
                raise SystemExit(f"[abi-facades] {symbol}: no canonical macro record")
            evidence = [f"forensics/atlas/{PRODUCTION_AUTHORITY}/macros.json#{symbol}"]
        facades.append({
            "facade_id": p["facade_id"],
            "facade_kind": "prototype",
            "authority_id": acq["id"],
            "release_id": HISTORICAL_RELEASE,
            "epoch": HISTORICAL_EPOCH,
            "symbol": symbol,
            "eras": [
                {"era": HISTORICAL_EPOCH, "authority_id": acq["id"], "role": "historical",
                 "declaration": decl, "kind": h["kind"], "header": h["header"],
                 "header_sha256": by_path.get(h["header"], "unknown"), "line": h["line"]},
                {"era": "3.6.4", "authority_id": PRODUCTION_AUTHORITY, "role": "production",
                 "declaration": canonical["declaration"], "kind": canonical["kind"],
                 "header": canonical["header"], "header_sha256": "unknown", "line": 0},
            ],
            "authority_specific": True,
            "adapter": p["adapter"],
            "not_established": [],
            "evidence": [
                f"forensics/authorities/{MANIFEST_NAME}#{h['header']}",
                *evidence,
            ],
        })

    # The architecture epochs and the init/thread epochs. The historical facts are the plane
    # census's produced engines and measured-absence providers; the canonical ones are the
    # parameterization receipt's production census.
    census = read_json(REPO_ROOT / "forensics" / "atlas" / HISTORICAL_AUTHORITY
                       / "plane-census.json")["body"]
    census_planes = {row["plane"]: row for row in census["planes"]}
    receipt = read_json(REPO_ROOT / "forensics" / "atlas"
                        / "parameterization-receipt.json")["body"]
    prod_census = receipt["censuses"].get(PRODUCTION_AUTHORITY, {}).get("planes", [])
    prod_planes = {row["plane"]: row for row in prod_census}

    facades.append({
        "facade_id": "A-0.9.8zh",
        "facade_kind": "architecture",
        "authority_id": acq["id"],
        "release_id": HISTORICAL_RELEASE,
        "epoch": HISTORICAL_EPOCH,
        "engine_model": "engine",
        "provider_model": "no_provider",
        "adapter": "compat::arch::ArchitectureModel",
        "not_established": [],
        "evidence": [
            f"forensics/atlas/{HISTORICAL_AUTHORITY}/plane-census.json#engines",
            f"forensics/atlas/{HISTORICAL_AUTHORITY}/plane-census.json#providers",
        ],
    })
    facades.append({
        "facade_id": "A-3.6.4",
        "facade_kind": "architecture",
        "authority_id": PRODUCTION_AUTHORITY,
        "release_id": "openssl-3.6.4",
        "epoch": "3.6.4",
        "engine_model": "deprecated_engine",
        "provider_model": "provider_store",
        "adapter": "compat::arch::ArchitectureModel",
        "not_established": [],
        "evidence": [
            "forensics/atlas/parameterization-receipt.json#censuses",
            f"forensics/atlas/{PRODUCTION_AUTHORITY}/provider-inventory.json",
        ],
    })
    facades.append({
        "facade_id": "IT-0.9.8zh",
        "facade_kind": "init_thread",
        "authority_id": acq["id"],
        "release_id": HISTORICAL_RELEASE,
        "epoch": HISTORICAL_EPOCH,
        "init_model": "explicit_global_init",
        "thread_model": "application_locking_callbacks",
        "callbacks": ["CRYPTO_num_locks", "CRYPTO_set_locking_callback",
                      "CRYPTO_set_id_callback"],
        "adapter": "compat::arch::InitThreadModel",
        "not_established": [],
        "evidence": [
            "forensics/authorities/SOURCE_MANIFEST.0.9.8zh.json#crypto/crypto.h",
        ],
    })
    facades.append({
        "facade_id": "IT-3.6.4",
        "facade_kind": "init_thread",
        "authority_id": PRODUCTION_AUTHORITY,
        "release_id": "openssl-3.6.4",
        "epoch": "3.6.4",
        "init_model": "automatic_init",
        "thread_model": "internal_thread_support",
        "callbacks": [],
        "adapter": "compat::arch::InitThreadModel",
        "not_established": [],
        "evidence": [
            f"forensics/atlas/{PRODUCTION_AUTHORITY}/functions.json#OPENSSL_init_crypto",
            f"forensics/atlas/{PRODUCTION_AUTHORITY}/functions.json#OPENSSL_cleanup",
            f"forensics/atlas/{PRODUCTION_AUTHORITY}/macros.json#CRYPTO_set_locking_callback",
        ],
    })

    # A sanity cross-check of the epoch facts against the census rows so a hand-edit cannot
    # silently flip "engines present / providers absent" for 0.9.8zh.
    if census_planes.get("providers", {}).get("status") != "measured_absence":
        raise SystemExit("[abi-facades] the 0.9.8zh census no longer measures providers absent")
    if census_planes.get("engines", {}).get("status") != "produced":
        raise SystemExit("[abi-facades] the 0.9.8zh census no longer measures engines present")
    if prod_planes.get("providers", {}).get("status") != "produced":
        raise SystemExit("[abi-facades] the production census no longer measures providers present")

    toolchain = {}
    for key, argv in (("cc", ["cc", "--version"]), ("gcc", ["gcc", "--version"])):
        res = run(argv)
        if res.ok and res.stdout:
            toolchain[key] = res.stdout.splitlines()[0]

    return {
        "epoch_order": [HISTORICAL_AUTHORITY, PRODUCTION_AUTHORITY],
        "authorities": {
            HISTORICAL_AUTHORITY: {
                "release_id": HISTORICAL_RELEASE,
                "role": "historical",
                "source_manifest": f"forensics/authorities/{MANIFEST_NAME}",
                "manifest_root_hash": acq["source_tree"]["root_hash"],
                "venue": "openssl-rs-historical",
                "compiler": toolchain,
                "platform": {"system": platform.system(), "machine": platform.machine()},
                "probe": _probe_source(),
            },
            PRODUCTION_AUTHORITY: {
                "release_id": "openssl-3.6.4",
                "role": "production",
                "atlas": f"forensics/atlas/{PRODUCTION_AUTHORITY}",
            },
        },
        "facades": facades,
        "not_established": NOT_ESTABLISHED,
        "boundary": BOUNDARY,
    }


# --------------------------------------------------------------------------------------------
# Materialisation: the committed measurement -> the generated repr(C) Rust + compile-time checks
# --------------------------------------------------------------------------------------------

def _rust_field(s: dict, name: str, c_type: str) -> str:
    if c_type in RUST_TYPE:
        return RUST_TYPE[c_type]
    if c_type == "unsigned char []":
        # The array length is the measured element count, carried in the field's size.
        width = next(f["size"] for f in s["_fields"] if f["name"] == name)
        return f"[c_uchar; {width}]"
    if c_type in SCALAR_RUST:
        return SCALAR_RUST[c_type]
    for inner in STRUCTS:
        if inner["struct_name"] == c_type:
            return inner["rust_type"]
    raise SystemExit(f"[abi-facades] no Rust mapping for C type {c_type!r} (field {name})")


def render_rust(body: dict) -> str:
    layouts = [f for f in body["facades"] if f["facade_kind"] == "public_layout"]
    # Emit exactly the `core::ffi` scalar imports the generated fields use, so the generated file
    # is warning-clean under `-D warnings` without an `#[allow(unused_imports)]`.
    used: set[str] = set()
    for f in layouts:
        f = dict(f)
        f["_fields"] = f["fields"]
        for field in f["fields"]:
            rust = _rust_field(f, field["name"], field["c_type"])
            for token in ("c_uchar", "c_uint", "c_ulong", "c_int", "c_char", "c_void"):
                if token in rust:
                    used.add(token)
    imports = ", ".join(sorted(used))
    header = [
        "//! Generated by forensics/tools/gen_abi_facades.py -- do not edit.",
        "//!",
        "//! The pre-1.1.0 public layouts of the 0.9.8zh compatibility generation. Each struct",
        "//! is `#[repr(C)]` with the authority's own field order, and the `const _: ()`",
        "//! assertions pin its size, alignment, every field offset and every field width to the",
        "//! measurement in `forensics/multitrack/abi-facades.json`. A field reorder, width change",
        "//! or padding change therefore fails to compile rather than silently reinterpreting a",
        "//! historical object as a modern one.",
        "//!",
        "//! SPDX-License-Identifier: Apache-2.0",
        "#![allow(dead_code)]",
        "",
    ]
    if imports:
        header.append(f"use core::ffi::{{{imports}}};")
        header.append("")
    out: list[str] = list(header)
    for f in layouts:
        f = dict(f)
        f["_fields"] = f["fields"]
        out.append(f"/// `struct {f['c_tag']}` — `{f['struct_name']}`, `{f['header']}`, at the")
        out.append(f"/// 0.9.8zh layout (transparent; opaque in `{f['canonical_authority_id']}`).")
        out.append("#[repr(C)]")
        out.append(f"pub struct {f['rust_type']} {{")
        for field in f["fields"]:
            rust = _rust_field(f, field["name"], field["c_type"])
            out.append(f"    /// `{field['c_type']}` at offset {field['offset']}.")
            out.append(f"    pub(crate) {field['name']}: {rust},")
        out.append("}")
        out.append("")
        out.append("const _: () = {")
        out.append(f"    assert!(core::mem::size_of::<{f['rust_type']}>() == {f['sizeof']});")
        out.append(f"    assert!(core::mem::align_of::<{f['rust_type']}>() == {f['alignof']});")
        for field in f["fields"]:
            rust = _rust_field(f, field["name"], field["c_type"])
            out.append(
                f"    assert!(core::mem::offset_of!({f['rust_type']}, {field['name']}) "
                f"== {field['offset']});"
            )
            out.append(
                f"    assert!(core::mem::size_of::<{rust}>() == {field['size']});"
            )
        out.append("};")
        out.append("")
    return "\n".join(out).rstrip("\n") + "\n"


def _verify_provenance(body: dict) -> list[str]:
    """Every cited header must resolve in the committed source manifest with the same hash."""
    problems: list[str] = []
    manifest_path = REPO_ROOT / "forensics" / "authorities" / MANIFEST_NAME
    if not manifest_path.is_file():
        return [f"the source manifest {rel(manifest_path)} is absent"]
    by_path = {f["path"]: f["sha256"]
               for f in read_json(manifest_path)["files"]}
    for f in body["facades"]:
        if f["facade_kind"] != "public_layout":
            continue
        expected = by_path.get(f["header"])
        if expected != f["header_sha256"]:
            problems.append(
                f"{f['facade_id']}: header {f['header']} hash {f['header_sha256'][:12]}... does "
                f"not match the manifest's {expected and expected[:12]}..."
            )
    return problems


def materialise() -> int:
    if not OUT_JSON.is_file():
        raise SystemExit(f"[abi-facades] {rel(OUT_JSON)} is absent; run --measure first")
    doc = read_json(OUT_JSON)
    body = doc["body"]
    problems = _verify_provenance(body)
    if problems:
        for p in problems:
            print(f"[abi-facades] STALE: {p}")
        return 1
    OUT_RUST.parent.mkdir(parents=True, exist_ok=True)
    OUT_RUST.write_text(render_rust(body), encoding="utf-8")
    layouts = [f for f in body["facades"] if f["facade_kind"] == "public_layout"]
    prototypes = [f for f in body["facades"] if f["facade_kind"] == "prototype"]
    print(f"[abi-facades] materialised {len(layouts)} layout(s) and "
          f"{len(prototypes)} prototype(s) over {len(body['facades'])} record(s)")
    print(f"  -> {rel(OUT_RUST)}")
    return 0


def measure_and_write() -> int:
    body = measure()
    doc = envelope(
        "abi-facades",
        GENERATOR,
        [
            InputRef(name="historical-acquisition", path=ACQUISITION),
            InputRef(name="source-manifest",
                     path=REPO_ROOT / "forensics" / "authorities" / MANIFEST_NAME),
            InputRef(name="production-structs",
                     path=REPO_ROOT / "forensics" / "atlas" / PRODUCTION_AUTHORITY
                     / "structs.json"),
            InputRef(name="production-functions",
                     path=REPO_ROOT / "forensics" / "atlas" / PRODUCTION_AUTHORITY
                     / "functions.json"),
            InputRef(name="production-macros",
                     path=REPO_ROOT / "forensics" / "atlas" / PRODUCTION_AUTHORITY
                     / "macros.json"),
            InputRef(name="historical-plane-census",
                     path=REPO_ROOT / "forensics" / "atlas" / HISTORICAL_AUTHORITY
                     / "plane-census.json"),
            InputRef(name="parameterization-receipt",
                     path=REPO_ROOT / "forensics" / "atlas" / "parameterization-receipt.json"),
        ],
        body,
        authority=PRODUCTION_AUTHORITY,
    )
    write_json(OUT_JSON, doc)
    print(f"[abi-facades] measured {len(body['facades'])} record(s)")
    print(f"  -> {rel(OUT_JSON)}")
    return materialise()


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--measure", action="store_true",
                    help="measure the historical layouts in the historical venue and write "
                         "the artefact (requires the acquired 0.9.8zh source tree)")
    args = ap.parse_args(argv)
    if args.measure:
        return measure_and_write()
    return materialise()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
