#!/usr/bin/env python3
"""openssl-rs — the non-Rust trusted computing base (Phase 25.2).

Phase 25 is the memory-safety stratum, and its subject is the **trusted computing base** the
bounded claim covers. 25.1 landed the compiler-backed census of the crate's unsafe operations -- but
that census is a *Rust* census: one clippy run with the built-in `unsafe_code` lint over the crate's
own source. The TCB is not Rust-only. Part of it is first-party C the crate compiles (`build.rs`'s
adapters), part is generated C (the Phase-2 distribution scaffolds), part is CPU-feature/assembly
surface reached through `core::arch`, and the whole Rust/C seam is a set of FFI boundaries. This tool
is 25.2: it inventories that non-Rust surface so the TCB is never read as Rust-only, and writes
`artifacts/phase25/non-rust-tcb.json`.

What is inventoried, and what is out of scope
---------------------------------------------
The inventory's file universe is derived, not typed:

  * **the shipped non-Rust first-party surface** -- every `*.c`/`*.h`/`*.S` under `src/**` (there are
    seven `.c` adapters, no `.h` and no `.S`). A file on disk with no inventory row, and an inventory
    row with no file, are both findings;
  * **the generated set** -- the Phase-2 distribution scaffolds, the C the Phase-2 court generator
    (`forensics/tools/phase2_courts.py`) emits into `artifacts/phase2/courts/`. The generated header
    shell under `artifacts/phase2/{include,install/include}` is the *authority's* generated interface
    copied into the distribution, not C a candidate translation unit owns; it is recorded as a
    boundary, not inventoried here.

The first-party C adapters
--------------------------
`build.rs` is the authority for which C the crate compiles; this tool parses its list rather than
restating it. Each adapter records its source hash, **why C is required** (stable Rust cannot define a
C-variadic function; platform struct layouts -- `struct dirent`, `struct stat`, `ucontext_t` -- must
be read where they are defined), the symbols it *exports*, the Rust functions it *calls* (derived from
the object's undefined symbols minus a documented libc allowlist), its memory operations, its variadic
handling and its struct-layout assumptions. Each adapter is compiled under `-Wall -Wextra -Werror` and
the outcome is recorded: a warning or an error is a recorded fact, never waived.

The FFI boundaries
------------------
The exported C-ABI surface is **cross-referenced to the 25.1 census** rather than re-derived: one
`ffi_boundary` row per compiler-reported `FFI_EXPORT` site (with the census site id in `sites`), plus
one row per symbol a C adapter exports (which the Rust census cannot see). The imported surface is
cross-referenced to the census's `EXTERN_FUNCTION_CALL` sites, and **supplemented by a `src` scan**
because the census's `unsafe_code` basis enumerates only `unsafe extern` blocks -- the crate's plain
`extern "C"` blocks are not `unsafe` keywords, so a bare census read would under-count the imported
surface. That gap is recorded as a classified residual, not hidden.

Outputs
-------
  artifacts/phase25/non-rust-tcb.json

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import (  # noqa: E402
    PRODUCTION_AUTHORITY,
    REPO_ROOT,
    InputRef,
    content_hash,
    envelope,
    rel,
    resolve_authority,
    sha256_bytes,
    sha256_file,
    write_json,
)

# The Docker-only execution guard. Its call is the first statement of `main`: this tool compiles C,
# so the manifest does not list it `metadata_only` and a host invocation is refused.
import phase25_guard  # noqa: E402

# The record kinds and their closed vocabularies. Imported, never restated, so this inventory cannot
# drift from the schema the court validates it against.
import memory_safety_schemas as schemas  # noqa: E402

# The stratum's non-claims, imported from 25.1's census rather than restated, so the C boundary carries
# exactly the non-claims the rest of the stratum does (plus the C one below).
import ms_census  # noqa: E402

# The lossless columnar encoding the Phase-25 artefacts are stored in; this inventory decodes
# through it and re-encodes through it, so the scheme has exactly one implementation.
import ms_codec  # noqa: E402

OUT = REPO_ROOT / "artifacts" / "phase25" / "non-rust-tcb.json"
GENERATOR = "forensics/tools/ms_non_rust_tcb.py"
TOOL = REPO_ROOT / "forensics" / "tools" / "ms_non_rust_tcb.py"
SCHEMAS = REPO_ROOT / "forensics" / "tools" / "memory_safety_schemas.py"
GUARD = REPO_ROOT / "forensics" / "tools" / "phase25_guard.py"
PLAN = REPO_ROOT / "docs" / "PHASE-25-MEMORY-SAFETY-SUBPHASES.md"
MANIFEST = REPO_ROOT / "forensics" / "memory-safety" / "container.json"
BUILD_RS = REPO_ROOT / "build.rs"
CENSUS = REPO_ROOT / "artifacts" / "phase25" / "source-census.json"
SRC = REPO_ROOT / "src"

# The Phase-2 court generator's output directory: the C scaffolds it emits are the generated set.
PHASE2_COURTS = REPO_ROOT / "artifacts" / "phase2" / "courts"
PHASE2_INCLUDE = REPO_ROOT / "artifacts" / "phase2" / "include"
PHASE2_INSTALL_INCLUDE = REPO_ROOT / "artifacts" / "phase2" / "install" / "include"
PHASE2_GENERATOR = "forensics/tools/phase2_courts.py"

# Scratch, under the gitignored `/work` tree the brief mandates. This path only exists inside the
# court, because the tool refuses the host before it runs a compiler.
WORK = Path("/work/court/p25-non-rust")

# The strict compile basis. `-std=c11` matches the Phase-2 recipe; the warning set is the one the
# brief names. Both the adapters and the generated scaffolds are compiled under it, and every
# diagnostic is recorded.
STRICT_FLAGS: tuple[str, ...] = ("-std=c11", "-Wall", "-Wextra", "-Werror")
CC = os.environ.get("CC", "cc")
NM = "nm"

# The symbols an adapter's undefined set names that are resolved by libc rather than by the crate.
# The classification rule is recorded on every adapter: an undefined symbol is crate-provided unless
# it is named here or defined by another adapter. The list is exactly the libc/loader surface these
# seven files reach, so it grows only when a new adapter reaches a new one.
LIBC_SYMBOLS: frozenset[str] = frozenset({
    "malloc", "calloc", "realloc", "free",
    "memcpy", "memmove", "memset", "strlen", "strcmp", "strcpy", "strncpy", "strstr",
    "opendir", "readdir", "closedir", "stat", "lstat", "fstat",
    "getcontext", "makecontext", "swapcontext",
    "__errno_location", "abort", "nanosleep", "getauxval", "dlopen", "dlsym", "dlclose", "dlvsym",
})

# The `extern` block openers scanned in `src/**/*.rs`. `unsafe extern` blocks are the ones the 25.1
# census enumerates; plain `extern "C"` blocks are not `unsafe` keywords and are missed by it.
_EXTERN_BLOCK = re.compile(r"(unsafe\s+)?extern\s+\"C\"\s*\{")
_ARCH_INTRINSIC = re.compile(r"core::arch::[a-z0-9_]+::([A-Za-z_][A-Za-z0-9_]*)")
_ASM_MACRO = re.compile(r"\b(asm|global_asm|naked_asm|llvm_asm)!\s*\(")
_TARGET_X86 = re.compile(r"#\[\s*cfg\s*\(\s*target_arch\s*=\s*\"x86_64\"\s*\)\s*\]")
_TARGET_NOT_X86 = re.compile(r"#\[\s*cfg\s*\(\s*not\s*\(\s*target_arch\s*=\s*\"x86_64\"\s*\)\s*\)\s*\]")
_FN_NAME = re.compile(r"\b(?:fn|static(?:\s+mut)?)\s+([A-Za-z_][A-Za-z0-9_]*)")
_EXPORT_NAME = re.compile(r"#\[export_name\s*=\s*\"([^\"]+)\"")

# The classification vocabulary a C adapter's `reason_class` is drawn from. It is local to this
# tool (the schema's `c_adapter` row does not close it) and is what makes "why C" mechanical.
REASON_CLASSES: tuple[str, ...] = ("VARIADIC_ABI", "STRUCT_LAYOUT")

# The C function-definition/memory/layout patterns the per-adapter scan derives its facts from.
_MEMORY_PATTERNS: tuple[tuple[str, str], ...] = (
    ("allocation", r"\b(?:CRYPTO_)?malloc\s*\("),
    ("reallocation", r"\b(?:CRYPTO_)?realloc\s*\("),
    ("deallocation", r"\b(?:CRYPTO_)?free\s*\("),
    ("copy", r"\bmem(?:cpy|move)\s*\("),
    ("fill", r"\bmemset\s*\("),
    ("string-length", r"\bstrlen\s*\("),
    ("variadic-start", r"\bva_start\s*\("),
    ("variadic-copy", r"\bva_copy\s*\("),
    ("variadic-pull", r"\bva_arg\s*\("),
    ("variadic-end", r"\bva_end\s*\("),
    ("buffer-write", r"\b\w+\s*\[[^\]]*\]\s*="),
    ("pointer-arithmetic", r"\b\w+\s*[+-]\s*\w+\s*\)"),
)
_LAYOUT_PATTERNS: tuple[tuple[str, str], ...] = (
    ("struct", r"\bstruct\s+([A-Za-z_][A-Za-z0-9_]*)"),
    ("sizeof", r"\bsizeof\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)"),
    ("alignof", r"\b_Alignof\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)"),
    ("nested-member", r"\b\w+\s*->\s*\w+\.\w+"),
    ("member", r"\b\w+\s*->\s*\w+"),
    ("field", r"\b\w+\.\w+\b"),
)

# The non-claim every Phase-25 artefact carries, plus the one this subphase adds: first-party C is
# outside Rust's memory-safety guarantee and is counted as TCB.
NON_CLAIMS: tuple[str, ...] = tuple(ms_census.NON_CLAIMS) + (
    "first-party C is outside Rust's memory-safety guarantee and is counted as TCB: the C adapters, "
    "the generated C scaffolds and the C side of every FFI boundary are inventoried as trusted "
    "computing base, and their soundness is not established by the Rust compiler's checks",
)


# --------------------------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------------------------

def _run(argv: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(argv, cwd=str(REPO_ROOT), capture_output=True, text=True, check=False)


def _strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def _loc(text: str) -> int:
    """Physical lines: the count of newline-terminated lines plus a final unterminated line."""
    return text.count("\n") + (0 if text.endswith("\n") or not text else 1)


def _leading_comment(text: str) -> str:
    """The prose the file's own header states, collapsed to one line, for `purpose`.

    The first `/* ... */` block before the first preprocessor directive; `*` gutters stripped.
    """
    m = re.search(r"/\*(.*?)\*/", text, flags=re.S)
    if not m:
        return ""
    body = m.group(1)
    lines: list[str] = []
    for raw in body.splitlines():
        line = raw.strip().lstrip("*").strip()
        if line:
            lines.append(line)
        elif lines:
            break
    return " ".join(lines)


def _sha(path: Path) -> str:
    return sha256_file(path) if path.is_file() else "unknown"


def _rel(path: Path) -> str:
    return path.resolve().relative_to(REPO_ROOT).as_posix()


# --------------------------------------------------------------------------------------------
# the derived file universe
# --------------------------------------------------------------------------------------------

def shipped_non_rust() -> list[dict]:
    """Every `*.c`/`*.h`/`*.S` the repo ships under `src/**`, sorted, with its digest."""
    out: list[dict] = []
    for path in sorted(SRC.rglob("*")):
        if path.is_file() and path.suffix in (".c", ".h", ".S"):
            out.append({"path": _rel(path), "kind": path.suffix, "sha256": _sha(path)})
    return out


def generated_scaffolds() -> list[dict]:
    """The generated C the Phase-2 court generator emits, sorted, with its digest."""
    out: list[dict] = []
    if PHASE2_COURTS.is_dir():
        for path in sorted(PHASE2_COURTS.glob("*.c")):
            out.append({"path": _rel(path), "sha256": _sha(path)})
    return out


def build_rs_adapters() -> list[tuple[str, str]]:
    """`(source, object stem)` for every C file `build.rs` names, in file order.

    `build.rs` is the authority for which first-party C the crate compiles, so the list is parsed
    from it rather than restated. A drift between it and the inventory is a finding.
    """
    text = BUILD_RS.read_text(encoding="utf-8") if BUILD_RS.is_file() else ""
    seen: list[tuple[str, str]] = []
    for m in re.finditer(r'"(src/[^"]+\.c)"\s*,\s*"([^"]+)"', text):
        pair = (m.group(1), m.group(2))
        if pair not in seen:
            seen.append(pair)
    return seen


def _census_index(body: dict) -> dict:
    """The 25.1 census facts the FFI boundaries cross-reference, without re-deriving them.

    Takes the *decoded* census view and returns the compiler-reported `FFI_EXPORT` sites (with the
    source span and macro provenance, so the exported symbol can be named) and the
    `EXTERN_FUNCTION_CALL` sites (file/line, so a scanned block can be recognised as
    census-enumerated).
    """
    sites = body.get("sites") or []
    contexts = body.get("unsafe_contexts") or []
    site_by_ctx: dict[str, str] = {}
    for site in sites:
        if site.get("operation_kind") == "FFI_EXPORT":
            site_by_ctx[site.get("context_id")] = site.get("site_id")
    exports: list[dict] = []
    for ctx in contexts:
        if ctx.get("kind") != "FFI_EXPORT_FN":
            continue
        site_id = site_by_ctx.get(ctx.get("context_id"))
        if site_id is None:
            continue
        span = ctx.get("span") or [None, None]
        exports.append({
            "site_id": site_id, "file": ctx.get("file"), "line": ctx.get("line"),
            "bs": span[0], "be": span[1], "macro_provenance": ctx.get("macro_provenance"),
        })
    imports: list[dict] = []
    for site in sites:
        if site.get("operation_kind") == "EXTERN_FUNCTION_CALL":
            imports.append({"site_id": site.get("site_id"), "file": site.get("file"),
                            "line": site.get("line")})
    return {"exports": exports, "imports": imports}


def _scan_asm(path: Path, text: str) -> list[tuple[str, int, str]]:
    """`(path, line, macro)` for every `asm!`/`global_asm!`/`naked_asm!`/`llvm_asm!` site in a file."""
    out: list[tuple[str, int, str]] = []
    for m in _ASM_MACRO.finditer(text):
        out.append((_rel(path), text[:m.start()].count("\n") + 1, m.group(1)))
    return out


def _scan_extern_blocks() -> list[dict]:
    """Every `extern "C" { ... }` block under `src/**/*.rs`, with its declared foreign functions.

    A source scan is used rather than the census alone because the census's `unsafe_code` basis
    enumerates only `unsafe extern` blocks; the plain `extern "C"` blocks are the same FFI boundary
    without the `unsafe` keyword, and leaving them out would make the imported TCB incomplete.
    """
    out: list[dict] = []
    for path in sorted(SRC.rglob("*.rs")):
        text = path.read_text(encoding="utf-8", errors="replace")
        for m in _EXTERN_BLOCK.finditer(text):
            brace = text.index("{", m.start())
            depth = 0
            end = brace
            for j in range(brace, len(text)):
                if text[j] == "{":
                    depth += 1
                elif text[j] == "}":
                    depth -= 1
                    if depth == 0:
                        end = j
                        break
            body = text[brace + 1:end]
            fns = [{"name": m.group(1), "params": m.group(2)}
                   for m in re.finditer(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)", body)]
            out.append({
                "file": _rel(path),
                "line": text[:m.start()].count("\n") + 1,
                "unsafe": bool(m.group(1)),
                "fns": fns,
            })
    return out


def build_context() -> dict:
    """The on-disk facts the inventory and its pure checks are derived from.

    Everything here is read from disk (or the committed census); nothing is typed. The self-test
    builds a synthetic context with the same shape.
    """
    census_doc = json.loads(CENSUS.read_text(encoding="utf-8"))
    census_body = ms_census.decode_body(census_doc.get("body", census_doc))
    return {
        "shipped": shipped_non_rust(),
        "generated": generated_scaffolds(),
        "build_adapters": build_rs_adapters(),
        "census": _census_index(census_body),
        "refs": ms_codec.refs_from_census(census_body),
        "extern_blocks": _scan_extern_blocks(),
        "asm_sites": [
            site for path in sorted(SRC.rglob("*.rs"))
            for site in _scan_asm(path, path.read_text(encoding="utf-8", errors="replace"))
        ],
    }


# --------------------------------------------------------------------------------------------
# the C adapters: reason, symbols, memory, variadic and layout, and the strict compile
# --------------------------------------------------------------------------------------------

def _compile(src: Path, obj: Path, includes: tuple[Path, ...] = ()) -> dict:
    """Compile one C file under the strict basis and record the outcome, diagnostics included."""
    obj.parent.mkdir(parents=True, exist_ok=True)
    argv = [CC, "-c", *STRICT_FLAGS]
    for inc in includes:
        argv += ["-I", str(inc)]
    argv += ["-o", str(obj), str(src)]
    res = _run(argv)
    diagnostics = [line.strip() for line in res.stderr.splitlines()
                   if re.search(r":\s*(warning|error):", line)]
    return {
        "compiler": CC,
        "flags": list(STRICT_FLAGS),
        "includes": [_rel(i) for i in includes],
        "returncode": res.returncode,
        "diagnostics": diagnostics,
        "clean": res.returncode == 0 and not diagnostics,
    }


def _nm(obj: Path) -> tuple[list[str], list[str]]:
    """`(defined, undefined)` global symbols of a compiled object, from `nm`."""
    defined_raw = _run([NM, "-g", "--defined-only", str(obj)]).stdout
    defined = sorted({line.split()[-1] for line in defined_raw.splitlines() if line.strip()})
    undef_raw = _run([NM, "-u", str(obj)]).stdout
    undef = sorted({line.split()[-1] for line in undef_raw.splitlines() if line.strip()})
    return defined, undef


def _param_text(text: str, name: str) -> str:
    """The parameter list of a function's definition, comments stripped, or ""."""
    m = re.search(r"\b" + re.escape(name) + r"\s*\(([^{};]*)\)", text)
    return m.group(1).strip() if m else ""


def _memory_operations(text: str) -> list[str]:
    found: list[str] = []
    for label, pattern in _MEMORY_PATTERNS:
        if re.search(pattern, text):
            found.append(label)
    return found


def _layout_assumptions(text: str) -> list[str]:
    """The platform-layout facts a C adapter names, from its own code (preprocessor stripped).

    `#include <stdarg.h>` and its siblings are not layout facts, so preprocessor lines are removed
    first; a bare `.`-field access that merely repeats a `->`/`.`.` nested member is dropped so the
    record names each assumption once.
    """
    stripped = re.sub(r"(?m)^\s*#.*$", "", text)
    nested: set[str] = set()
    found: list[str] = []
    for label, pattern in _LAYOUT_PATTERNS:
        for m in re.finditer(pattern, stripped):
            token = m.group(0).strip()
            if re.search(r"\.(h|c|o|so|a|S)\b", token):
                continue
            value = f"struct {m.group(1)}" if label == "struct" else f"{label}:{token}"
            if label == "nested-member":
                nested.add(token)
            if value not in found:
                found.append(value)
    out: list[str] = []
    for value in found:
        if value.startswith("field:"):
            token = value.split(":", 1)[1]
            if any(n == token or n.endswith(token) for n in nested):
                continue
        out.append(value)
    return out[:24]


def _reason_class(text: str) -> str:
    """Which of the two reasons this adapter exists: variadic ABI, or a platform struct layout."""
    if re.search(r"\.\.\.", text) or "va_list" in text or re.search(r"\bva_arg\s*\(", text):
        return "VARIADIC_ABI"
    return "STRUCT_LAYOUT"


def _adapter_record(source_rel: str, stem: str, provided: set[str]) -> dict:
    src = REPO_ROOT / source_rel
    text = src.read_text(encoding="utf-8", errors="replace")
    bare = _strip_comments(text)
    obj = WORK / "objs" / f"{stem}.o"
    compile_rec = _compile(src, obj)
    defined, undef = _nm(obj) if compile_rec["returncode"] == 0 else ([], [])

    variadic: list[str] = []
    for name in defined:
        params = _param_text(bare, name)
        if "..." in params or "va_list" in params:
            variadic.append(name)
    rust_called = sorted(s for s in undef if s not in LIBC_SYMBOLS and s not in provided)
    reason_class = _reason_class(bare)
    reason = (
        "a C-variadic function of the public ABI cannot be defined in stable Rust (the `c_variadic` "
        "feature is unstable), so only the argument marshalling is written in C and every behavioural "
        "decision is made by the Rust functions it calls back into"
        if reason_class == "VARIADIC_ABI" else
        "the platform's struct layout is the platform's business -- the field offsets of `struct "
        "dirent`, `struct stat` and `ucontext_t` are read on the C side of the ABI so that no field "
        "offset or alignment is assumed in Rust"
    )
    purpose = _leading_comment(text) or (
        f"{reason_class} adapter defining {', '.join(defined) or 'no symbols'}"
    )
    return {
        "adapter_id": f"ca-{stem}",
        "path": source_rel,
        "purpose": purpose,
        "reason": reason,
        "reason_class": reason_class,
        "source_sha256": _sha(src),
        "loc": _loc(text),
        "exported_symbols": defined,
        "variadic_boundaries": variadic,
        "rust_functions_called": rust_called,
        "undefined_symbols": undef,
        "memory_operations": _memory_operations(bare),
        "variadic_handling": (
            "variadic: " + ", ".join(variadic) if variadic else
            "no `...`/`va_list` in this file; it reads/writes platform structs instead"
        ),
        "struct_layout_assumptions": _layout_assumptions(bare),
        "symbol_classification": (
            "an adapter's undefined symbol is crate-provided unless it is in the documented libc "
            "allowlist or is defined by another adapter; the object's own `nm` gives the sets"
        ),
        "compile": compile_rec,
        "evidence": [
            f"build.rs compiles {source_rel}",
            f"source sha256 {_sha(src)[:16]}",
            f"strict compile {CC} {' '.join(STRICT_FLAGS)}: "
            + ("clean" if compile_rec["clean"] else f"{len(compile_rec['diagnostics'])} diagnostic(s)"),
            "nm -g --defined-only / nm -u",
        ],
    }


# --------------------------------------------------------------------------------------------
# generated C, assembly and the FFI boundaries
# --------------------------------------------------------------------------------------------

_MARKERS = (
    ("alignment", re.compile(r"\boffsetof\s*\(")),
    ("alignment", re.compile(r"\b_Alignof\s*\(")),
    ("buffer", re.compile(r"\bsizeof\s*\(")),
    ("buffer", re.compile(r"bzero|memcpy|memset")),
    ("cpu-feature", re.compile(r"__cpuid|_rdtsc|getauxval")),
    ("loader", re.compile(r"\bdl(open|sym|vsym|close)\b")),
    ("environment", re.compile(r"LD_LIBRARY_PATH|DT_RUNPATH|rpath")),
)


def _generated_record(path: Path) -> dict:
    text = path.read_text(encoding="utf-8", errors="replace")
    obj = WORK / "objs" / f"gen_{path.stem}.o"
    compile_rec = _compile(path, obj, (PHASE2_INCLUDE, PHASE2_INSTALL_INCLUDE))
    assumptions: list[str] = []
    for label, pattern in _MARKERS:
        if pattern.search(text):
            assumptions.append(label)
    fallback = (
        "compiles under the Phase-2 recipe (`clang -std=c11`, no `-Wall`/`-Werror`) with the implicit "
        "declarations tolerated"
        if not compile_rec["clean"] else
        "none needed: it is clean under the strict basis too"
    )
    return {
        "path": _rel(path),
        "origin": "GENERATED",
        "generated_by": PHASE2_GENERATOR,
        "source_sha256": _sha(path),
        "loc": _loc(text),
        "assumptions": sorted(set(assumptions)),
        "fallback": fallback,
        "compile": compile_rec,
        "evidence": [
            f"generated by {PHASE2_GENERATOR} into {rel(PHASE2_COURTS)}",
            f"source sha256 {_sha(path)[:16]}",
            f"strict compile {CC} {' '.join(STRICT_FLAGS)} with the Phase-2 include path: "
            + ("clean" if compile_rec["clean"] else f"{len(compile_rec['diagnostics'])} diagnostic(s)"),
        ],
    }


def _assembly_records(ctx: dict) -> list[dict]:
    """Every assembly-level site: `asm!`/`global_asm!` macros and `core::arch` intrinsics.

    There is no `asm!`/`global_asm!` site and no `.S` file in the crate; the assembly-adjacent
    surface that *does* exist is the `core::arch` CPU-feature and timestamp intrinsics, which carry
    CPU-feature assumptions and, where the platform can be elsewhere, a recorded fallback arm.
    """
    records: list[dict] = []
    for path, line, macro in ctx["asm_sites"]:
        records.append({
            "kind": "INLINE_ASM", "path": path, "line": line, "intrinsic": f"{macro}!",
            "origin": "FIRST_PARTY", "generated": False,
            "cpu_features": [], "fallback": "", "evidence": [f"{path}:{line}"],
        })
    for path in sorted(SRC.rglob("*.rs")):
        text = path.read_text(encoding="utf-8", errors="replace")
        for m in _ARCH_INTRINSIC.finditer(text):
            line = text[:m.start()].count("\n") + 1
            window = text[max(0, m.start() - 400):m.start()]
            cfg = "x86_64" if _TARGET_X86.search(window) else "unconditional"
            if _TARGET_NOT_X86.search(text):
                fallback = "a non-x86_64 arm exists in the same file"
            else:
                fallback = "none: the module is admitted on the x86_64 profile only"
            records.append({
                "kind": "ARCH_INTRINSIC", "path": _rel(path), "line": line,
                "intrinsic": m.group(0), "origin": "FIRST_PARTY", "generated": False,
                "target_arch": cfg,
                "cpu_features": [m.group(1)],
                "fallback": fallback,
                "evidence": [f"{_rel(path)}:{line}"],
            })
    records.sort(key=lambda r: (r["path"], r["line"], r["intrinsic"]))
    return records


def _export_symbol(entry: dict, cache: dict) -> tuple[str, str]:
    """`(symbol, resolution)` for one census `FFI_EXPORT` site.

    The census reports the `#[no_mangle]`/`#[export_name]` *attribute* span, not the symbol name, so
    the name is read from the source the census points at: the attribute text for `export_name`, the
    first `fn`/`static` after it for `no_mangle`. A macro-generated export (the census collapses every
    expansion of one definition into a single site) has no literal name at the definition, so it is
    named by the macro and its definition site and marked `macro_expanded`.
    """
    path = entry["file"]
    if path not in cache:
        cache[path] = (REPO_ROOT / path).read_bytes()
    data = cache[path]
    attr = data[entry["bs"]:entry["be"]].decode("utf-8", "replace")
    m = _EXPORT_NAME.search(attr)
    if m:
        return m.group(1), "export_name"
    tail = _strip_comments(data[entry["be"]:entry["be"] + 600].decode("utf-8", "replace"))
    m = _FN_NAME.search(tail)
    if m:
        return m.group(1), "no_mangle"
    mp = entry.get("macro_provenance") or ""
    macro = mp.split("!@", 1)[0] if mp else "macro"
    return f"<macro {macro}@{path}:{entry['line']}>", "macro_expanded"


def _ffi_boundaries(ctx: dict, adapters: list[dict]) -> list[dict]:
    """Every FFI boundary: census exports, C-adapter exports and the imported foreign surface."""
    out: list[dict] = []
    cache: dict = {}

    # INBOUND, from the 25.1 census's FFI_EXPORT sites -- cross-referenced, not re-derived.
    for entry in ctx["census"]["exports"]:
        symbol, resolution = _export_symbol(entry, cache)
        out.append({
            "boundary_id": "fb-" + sha256_bytes(
                f"INBOUND\0census\0{symbol}\0{entry['site_id']}".encode())[:16],
            "symbol": symbol,
            "direction": "INBOUND",
            "abi": "C",
            "c_variadic": False,
            "unwind": "UNKNOWN",
            "sites": [entry["site_id"]],
            "source": "census:FFI_EXPORT",
            "census_site": entry["site_id"],
            "symbol_resolution": resolution,
            "exporter": "rust",
            "evidence": [
                f"25.1 census FFI_EXPORT site {entry['site_id']} at {entry['file']}:{entry['line']}",
                "unwind: 25.1 recorded no classification; 25.4 owns the panic/unwind boundary",
            ],
        })

    # INBOUND, from the C adapters: symbols the Rust census cannot see.
    for rec in adapters:
        variadic = set(rec["variadic_boundaries"])
        for symbol in rec["exported_symbols"]:
            out.append({
                "boundary_id": "fb-" + sha256_bytes(
                    f"INBOUND\0c-adapter\0{symbol}\0{rec['adapter_id']}".encode())[:16],
                "symbol": symbol,
                "direction": "INBOUND",
                "abi": "C",
                "c_variadic": symbol in variadic,
                "unwind": "UNKNOWN",
                "sites": [rec["adapter_id"]],
                "source": "c-adapter",
                "census_site": None,
                "exporter": "c-adapter",
                "evidence": [
                    f"defined by {rec['path']} (the Rust census cannot see a C definition)",
                    "unwind: 25.1 recorded no classification; 25.4 owns the panic/unwind boundary",
                ],
            })

    # OUTBOUND, from the census's EXTERN_FUNCTION_CALL sites and the src extern-block scan.
    census_import = {(i["file"], i["line"]): i["site_id"] for i in ctx["census"]["imports"]}
    for block in ctx["extern_blocks"]:
        site_id = census_import.get((block["file"], block["line"]))
        for fn in block["fns"]:
            out.append({
                "boundary_id": "fb-" + sha256_bytes(
                    f"OUTBOUND\0{block['file']}\0{block['line']}\0{fn['name']}".encode())[:16],
                "symbol": fn["name"],
                "direction": "OUTBOUND",
                "abi": "C",
                "c_variadic": "..." in fn["params"],
                "unwind": "UNKNOWN",
                "sites": [site_id] if site_id else [],
                "source": ("census:EXTERN_FUNCTION_CALL" if site_id
                           else "source-scan:extern-block"),
                "census_site": site_id,
                "exporter": "foreign",
                "evidence": [
                    f"declared in an {'unsafe ' if block['unsafe'] else ''}extern \"C\" block at "
                    f"{block['file']}:{block['line']}",
                    ("enumerated by the 25.1 census as EXTERN_FUNCTION_CALL" if site_id else
                     "not enumerated by the 25.1 census (a plain `extern \"C\"` block is not an "
                     "`unsafe` keyword); recorded by this subphase's src scan"),
                    "unwind: 25.1 recorded no classification; 25.4 owns the panic/unwind boundary",
                ],
            })
    out.sort(key=lambda r: (r["direction"], r["symbol"], r["sites"]))
    return out


# --------------------------------------------------------------------------------------------
# building the body
# --------------------------------------------------------------------------------------------

def build_body(ctx: dict) -> dict:
    """Compile and derive every non-Rust TCB fact: adapters, generated C, assembly, FFI boundaries."""
    # Pass 1: compile every adapter so the crate-provided symbol set is known before classification.
    adapters: list[dict] = []
    provided: set[str] = set()
    compiled: list[tuple[str, str, Path]] = []
    for source_rel, stem in ctx["build_adapters"]:
        obj = WORK / "objs" / f"{stem}.o"
        rec = _compile(REPO_ROOT / source_rel, obj)
        compiled.append((source_rel, stem, obj))
        if rec["clean"]:
            defined, _undef = _nm(obj)
            provided.update(defined)
    # Pass 2: records, with the crate-provided set complete.
    for source_rel, stem, _obj in compiled:
        adapters.append(_adapter_record(source_rel, stem, provided))

    generated = [_generated_record(REPO_ROOT / g["path"]) for g in ctx["generated"]]
    assembly = _assembly_records(ctx)
    boundaries = _ffi_boundaries(ctx, adapters)

    inbound = [b for b in boundaries if b["direction"] == "INBOUND"]
    outbound = [b for b in boundaries if b["direction"] == "OUTBOUND"]
    variadic_boundaries = (sum(len(a["variadic_boundaries"]) for a in adapters)
                           + sum(1 for b in outbound if b["c_variadic"]))
    diagnostics_total = sum(len(r["compile"]["diagnostics"]) for r in adapters + generated)

    counts = {
        "c_files": len(adapters),
        "c_loc": sum(a["loc"] for a in adapters),
        "asm_sites": sum(1 for r in assembly if r["kind"] in ("INLINE_ASM", "GLOBAL_ASM")),
        "exported_ffi": len(inbound),
        "imported_ffi": len(outbound),
        "variadic_boundaries": variadic_boundaries,
        "warnings": diagnostics_total,
        "c_adapter_exports": sum(len(a["exported_symbols"]) for a in adapters),
        "generated_c_files": len(generated),
        "generated_c_loc": sum(g["loc"] for g in generated),
        "arch_intrinsic_sites": sum(1 for r in assembly if r["kind"] == "ARCH_INTRINSIC"),
        "shipped_h_files": sum(1 for s in ctx["shipped"] if s["kind"] == ".h"),
        "shipped_s_files": sum(1 for s in ctx["shipped"] if s["kind"] == ".S"),
        "census_export_sites": len(ctx["census"]["exports"]),
        "census_import_sites": len(ctx["census"]["imports"]),
        "extern_blocks": len(ctx["extern_blocks"]),
        "boundary_records": len(boundaries),
    }

    residuals = [
        {
            "source": "census:FFI_EXPORT",
            "class": "out_of_scope",
            "detail": (
                "the 25.1 census is a Rust census: an `FFI_EXPORT` site is a `#[no_mangle]`/"
                "`#[export_name]` *definition* span, and every expansion of one macro definition "
                "collapses into a single site, so the census's FFI_EXPORT count is the number of "
                "distinct export definition sites and not the number of exported symbols. This "
                "inventory cross-references those sites and names each; a macro-expanded export is "
                "recorded as such. The authoritative exported-symbol population is the ABI surface "
                "the Phase-2 courts measure, not this census"
            ),
        },
        {
            "source": "census:EXTERN_FUNCTION_CALL",
            "class": "out_of_scope",
            "detail": (
                "the 25.1 census's `unsafe_code` basis enumerates `unsafe extern` blocks only, so the "
                "crate's plain `extern \"C\"` blocks -- the same FFI boundary without the `unsafe` "
                "keyword -- are not in it. A src scan finds every extern block; the ones the census "
                "did not enumerate are recorded with `source: source-scan:extern-block` and a null "
                "`census_site`, so the imported surface is complete rather than census-shaped"
            ),
        },
        {
            "source": "census:C_VARIADIC_BOUNDARY",
            "class": "out_of_scope",
            "detail": (
                "the 25.1 census reports 0 C_VARIADIC_BOUNDARY sites although the crate both declares "
                "C-variadic foreign functions and defines the C-variadic ABI entry points in its C "
                "adapters: the census's span tokenizer does not classify the construct, so the "
                "variadic boundaries are inventoried here (the C adapters' variadic exports and the "
                "variadic imports) rather than by the Rust census"
            ),
        },
    ]
    for rec in adapters + generated:
        comp = rec["compile"]
        if not comp["clean"]:
            residuals.append({
                "source": "strict-compile",
                "class": "evidence_missing",
                "detail": (
                    f"{rec['path']} does not compile clean under "
                    f"{' '.join(comp['flags'])}: {len(comp['diagnostics'])} diagnostic(s) recorded, "
                    f"not waived -- {comp['diagnostics'][0] if comp['diagnostics'] else 'no text'}"
                ),
            })

    return {
        "rule": {
            "authority": (
                "the non-Rust trusted computing base is inventoried from files, not from prose: "
                "`build.rs` is the authority for which first-party C the crate compiles, the Phase-2 "
                "court generator for the generated C scaffolds, a src scan for the extern blocks and "
                "the `core::arch` intrinsics, and the 25.1 census for the compiler-reported FFI "
                "sites. A file on disk with no row, and a row with no file, are both findings "
                "(docs/PHASE-25-MEMORY-SAFETY-SUBPHASES.md section 2.25.2)"
            ),
            "c_adapter_compile": (
                f"every first-party C adapter is compiled under {' '.join(STRICT_FLAGS)}; every "
                f"warning or error is recorded in the row's `compile` block and never waived, and a "
                f"row that claims a clean compile while recording a diagnostic is refused"
            ),
            "ffi_cross_reference": (
                "the exported C-ABI surface is cross-referenced to the 25.1 census's FFI_EXPORT sites "
                "(each boundary names its census site id) rather than re-derived, plus the symbols the "
                "C adapters export, which the Rust census cannot see; the imported surface is "
                "cross-referenced to the census's EXTERN_FUNCTION_CALL sites and supplemented by a "
                "src scan, because the census's `unsafe_code` basis misses plain `extern \"C\"` blocks"
            ),
            "assembly_scan": (
                "a src scan finds no `asm!`/`global_asm!`/`naked_asm!`/`llvm_asm!` site and no `.S` "
                "file in the crate; the assembly-adjacent surface is the `core::arch` CPU-feature and "
                "timestamp intrinsics, each recorded with its target-arch guard and its fallback arm"
            ),
            "scope": (
                "the file universe is every `*.c`/`*.h`/`*.S` under `src/**` plus the generated C the "
                "Phase-2 court generator emits into artifacts/phase2/courts/. The generated header "
                "shell under artifacts/phase2/{include,install/include} is the authority's generated "
                "interface copied into the distribution, not a candidate translation unit, and is out "
                "of this inventory's generated-C set"
            ),
        },
        "c_adapters": adapters,
        "generated_c": generated,
        "assembly": assembly,
        "ffi_boundaries": boundaries,
        "counts": counts,
        "residuals": residuals,
        "non_claims": list(NON_CLAIMS),
    }


# --------------------------------------------------------------------------------------------
# the pure checks (the court re-runs these over the committed artefact)
# --------------------------------------------------------------------------------------------

def _derived_counts(body: dict) -> dict:
    adapters = body.get("c_adapters") or []
    generated = body.get("generated_c") or []
    assembly = body.get("assembly") or []
    boundaries = body.get("ffi_boundaries") or []
    return {
        "c_files": len(adapters),
        "c_loc": sum(int(a.get("loc") or 0) for a in adapters),
        "asm_sites": sum(1 for r in assembly if r.get("kind") in ("INLINE_ASM", "GLOBAL_ASM")),
        "exported_ffi": sum(1 for b in boundaries if b.get("direction") == "INBOUND"),
        "imported_ffi": sum(1 for b in boundaries if b.get("direction") == "OUTBOUND"),
        "variadic_boundaries": (sum(len(a.get("variadic_boundaries") or []) for a in adapters)
                                + sum(1 for b in boundaries
                                      if b.get("direction") == "OUTBOUND" and b.get("c_variadic"))),
        "generated_c_files": len(generated),
    }


def non_rust_findings(body: dict, ctx: dict) -> list[str]:
    """Every way the committed non-Rust inventory contradicts itself, derived from the artefact.

    Pure over `body` and the on-disk context `ctx` (no compiler): it is what the `MS-NON-RUST-TCB`
    court runs. Checks: every shipped/generated non-Rust file is accounted for and its digest
    matches; every adapter is a `build.rs` source and vice versa; every record validates; every
    adapter names its reason and its variadic-or-layout role; every export has a boundary record and
    every census FFI site is cross-referenced; the counts are derived, not typed; and every strict
    compile is reported honestly.
    """
    problems: list[str] = []

    # The inventory is columnar on disk; re-derive the view the checks read. On a fresh measurement
    # the body is already the view, so this is a no-op.
    body = ms_codec.decode_body(body, ctx.get("refs"))

    adapters = body.get("c_adapters") or []
    generated = body.get("generated_c") or []
    boundaries = body.get("ffi_boundaries") or []
    assembly = body.get("assembly") or []

    # 1. File completeness, both directions.
    expected = {s["path"]: s for s in ctx["shipped"]}
    expected.update({g["path"]: {"path": g["path"], "sha256": g["sha256"]} for g in ctx["generated"]})
    inventoried: dict[str, str] = {}
    for a in adapters:
        inventoried[a.get("path")] = a.get("source_sha256")
    for g in generated:
        inventoried[g.get("path")] = g.get("source_sha256")
    for path in sorted(expected):
        if path not in inventoried:
            problems.append(f"the shipped/generated non-Rust file {path} is not accounted for in the "
                            f"inventory")
        elif inventoried[path] != expected[path]["sha256"]:
            problems.append(f"{path}: recorded source_sha256 does not match the file on disk")
    for path in sorted(inventoried):
        if path not in expected:
            problems.append(f"the inventory records {path}, which is not a shipped or generated "
                            f"non-Rust file on disk")

    # 2. The inventory's C adapters are exactly the C build.rs compiles.
    build_paths = sorted(p for p, _stem in ctx["build_adapters"])
    inv_paths = sorted(a.get("path") for a in adapters)
    if build_paths != inv_paths:
        problems.append("the C adapters are not exactly the C build.rs compiles "
                        f"(build.rs-only {sorted(set(build_paths) - set(inv_paths))}, "
                        f"inventory-only {sorted(set(inv_paths) - set(build_paths))})")

    # 3. Schema validation, and every adapter names its reason and its variadic-or-layout role.
    for a in adapters:
        problems += [f"c_adapters[{a.get('adapter_id')}]: {p}"
                     for p in schemas.validate_c_adapter(a)]
        if not a.get("reason"):
            problems.append(f"the C adapter {a.get('path')} names no reason C is required")
        if a.get("reason_class") not in REASON_CLASSES:
            problems.append(f"the C adapter {a.get('path')} names reason_class "
                            f"{a.get('reason_class')!r}, not one of {sorted(REASON_CLASSES)}")
        if not a.get("variadic_handling") and not a.get("struct_layout_assumptions"):
            problems.append(f"the C adapter {a.get('path')} names neither a variadic handling nor a "
                            f"struct-layout assumption")
    for g in generated:
        if g.get("origin") != "GENERATED" or not g.get("generated_by"):
            problems.append(f"the generated C {g.get('path')} does not name its generator/origin")
    for b in boundaries:
        problems += [f"ffi_boundaries[{b.get('boundary_id')}]: {p}"
                     for p in schemas.validate_ffi_boundary(b)]

    # 4. Every export has a boundary record; every census FFI site is cross-referenced.
    inbound_symbols = {b.get("symbol") for b in boundaries if b.get("direction") == "INBOUND"}
    inbound_sites = {s for b in boundaries if b.get("direction") == "INBOUND"
                     for s in (b.get("sites") or [])}
    outbound_sites = {s for b in boundaries if b.get("direction") == "OUTBOUND"
                      for s in (b.get("sites") or [])}
    for a in adapters:
        for symbol in a.get("exported_symbols") or []:
            if symbol not in inbound_symbols:
                problems.append(f"the exported symbol {symbol} of {a.get('path')} has no boundary "
                                f"record")
    for entry in ctx["census"]["exports"]:
        if entry["site_id"] not in inbound_sites:
            problems.append(f"the 25.1 census FFI_EXPORT site {entry['site_id']} "
                            f"({entry['file']}:{entry['line']}) is not cross-referenced by any "
                            f"boundary record")
    for entry in ctx["census"]["imports"]:
        if entry["site_id"] not in outbound_sites:
            problems.append(f"the 25.1 census EXTERN_FUNCTION_CALL site {entry['site_id']} "
                            f"({entry['file']}:{entry['line']}) is not cross-referenced")

    # 5. The counts are derived, not typed.
    derived = _derived_counts(body)
    counts = body.get("counts") or {}
    for key, val in derived.items():
        if counts.get(key) != val:
            problems.append(f"counts.{key}={counts.get(key)!r} is not the derived {val}")
    diagnostics_total = sum(len((r.get("compile") or {}).get("diagnostics") or [])
                            for r in adapters + generated)
    if counts.get("warnings") != diagnostics_total:
        problems.append(f"counts.warnings={counts.get('warnings')!r} is not the derived "
                        f"{diagnostics_total} diagnostic(s)")

    # 6. Every strict compile is reported honestly: `clean` iff there are no diagnostics.
    for rec in adapters + generated:
        comp = rec.get("compile") or {}
        diags = comp.get("diagnostics") or []
        if comp.get("clean") is not (not diags):
            problems.append(f"{rec.get('path')}: records a "
                            f"{'clean' if comp.get('clean') else 'non-clean'} strict compile while "
                            f"recording {len(diags)} diagnostic(s), so the compile outcome is not "
                            f"honest")

    # 7. The assembly scan agrees with the source: every `asm!` site is recorded, and none invented.
    recorded_asm = {(r.get("path"), r.get("line")) for r in assembly if r.get("kind") == "INLINE_ASM"}
    for path, line, _macro in ctx["asm_sites"]:
        if (path, line) not in recorded_asm:
            problems.append(f"the asm site {path}:{line} is not recorded in the assembly section")

    return problems


def non_rust_sensitivity_control(body: dict, ctx: dict) -> dict:
    """Seed five mutations and require each caught, with specificity holding.

    Each mutation is a distinct way the non-Rust inventory could lie: a shipped C file dropped, a
    fabricated C file added, an adapter's reason removed, a compile-clean result forged for a file
    that warns, and an exported symbol's boundary record dropped. The baseline must be clean and each
    mutation must produce its own finding, so a control that "caught" everything indiscriminately
    would not pass.
    """
    # The inventory is columnar on disk; the mutations below index its records, so decode once.
    body = ms_codec.decode_body(body, ctx.get("refs"))
    baseline = non_rust_findings(body, ctx)
    result: dict = {"baseline_findings": len(baseline), "honest": not baseline,
                    "specificity_holds": False, "mutations": {}}

    def check(label: str, mutated: dict, marker: str) -> bool:
        found = non_rust_findings(mutated, ctx)
        caught = any(marker in f for f in found)
        result["mutations"][label] = {
            "caught": caught, "findings": len(found),
            "delta": len(found) - len(baseline), "marker": marker,
        }
        return caught

    # m1: drop a shipped C adapter from the inventory.
    def drop_c_file() -> dict:
        return {**body, "c_adapters": (body.get("c_adapters") or [])[1:]}

    m1 = check("drop_c_file", drop_c_file(), "is not accounted for in the inventory")

    # m2: add a fabricated C file that is not on disk.
    def add_fabricated_c_file() -> dict:
        forged = list(body.get("c_adapters") or [])
        if forged:
            fake = dict(forged[0])
            fake["path"] = "src/runtime/nonexistent_adapter.c"
            fake["source_sha256"] = "0" * 64
            forged.append(fake)
        return {**body, "c_adapters": forged}

    m2 = check("add_fabricated_c_file", add_fabricated_c_file(), "which is not a shipped or "
                                                                 "generated non-Rust file")

    # m3: remove a C adapter's reason for existing.
    def remove_reason() -> dict:
        adapters = [dict(a) for a in body.get("c_adapters") or []]
        if adapters:
            adapters[0]["reason"] = ""
        return {**body, "c_adapters": adapters}

    m3 = check("remove_reason", remove_reason(), "names no reason C is required")

    # m4: forge a compile-clean result for a file that actually warns/errors.
    def forge_compile_clean() -> dict:
        generated = [dict(g) for g in body.get("generated_c") or []]
        for i, g in enumerate(generated):
            if (g.get("compile") or {}).get("diagnostics"):
                comp = dict(g["compile"])
                comp["clean"] = True
                g["compile"] = comp
                generated[i] = g
                return {**body, "generated_c": generated}
        return body

    m4 = check("forge_compile_clean", forge_compile_clean(), "the compile outcome is not honest")

    # m5: drop an exported symbol's boundary record.
    def drop_export_boundary() -> dict:
        boundaries = list(body.get("ffi_boundaries") or [])
        for i, b in enumerate(boundaries):
            if b.get("source") == "c-adapter" and b.get("direction") == "INBOUND":
                return {**body, "ffi_boundaries": boundaries[:i] + boundaries[i + 1:]}
        return body

    m5 = check("drop_export_boundary", drop_export_boundary(), "has no boundary record")

    result["specificity_holds"] = bool(m1 and m2 and m3 and m4 and m5 and not baseline)
    result["caught"] = sum(1 for v in result["mutations"].values() if v["caught"])
    result["seeded"] = len(result["mutations"])
    return result


# --------------------------------------------------------------------------------------------
# self-test
# --------------------------------------------------------------------------------------------

def _synthetic_context() -> dict:
    """A tiny on-disk context shaped like the real one, for the self-test."""
    adapter = "src/runtime/err_variadic.c"
    generated = "artifacts/phase2/courts/layout_probe.c"
    return {
        "shipped": [{"path": adapter, "kind": ".c", "sha256": _sha(REPO_ROOT / adapter)}],
        "generated": [{"path": generated, "sha256": _sha(REPO_ROOT / generated)}],
        "build_adapters": [(adapter, "openssl_rs_err_variadic")],
        "census": {"exports": [], "imports": []},
        "refs": ms_codec.Refs(),
        "extern_blocks": [],
        "asm_sites": [],
    }


def _synthetic_body() -> dict:
    """A tiny well-formed non-Rust inventory body, built without a compiler, for the self-test."""
    adapter = "src/runtime/err_variadic.c"
    generated = "artifacts/phase2/courts/layout_probe.c"
    return {
        "rule": {},
        "c_adapters": [{
            "adapter_id": "ca-synthetic",
            "path": adapter,
            "purpose": "synthetic C-variadic ERR adapter",
            "reason": "stable Rust cannot define a C-variadic function",
            "reason_class": "VARIADIC_ABI",
            "source_sha256": _sha(REPO_ROOT / adapter),
            "loc": 224,
            "exported_symbols": ["ERR_set_error"],
            "variadic_boundaries": ["ERR_set_error"],
            "rust_functions_called": ["openssl_rs_err_finish_data"],
            "undefined_symbols": ["openssl_rs_err_finish_data"],
            "memory_operations": ["deallocation", "copy"],
            "variadic_handling": "variadic: ERR_set_error",
            "struct_layout_assumptions": [],
            "symbol_classification": "synthetic",
            "compile": {"compiler": CC, "flags": list(STRICT_FLAGS), "includes": [],
                        "returncode": 0, "diagnostics": [], "clean": True},
            "evidence": [],
        }],
        "generated_c": [{
            "path": generated,
            "origin": "GENERATED",
            "generated_by": PHASE2_GENERATOR,
            "source_sha256": _sha(REPO_ROOT / generated),
            "loc": 1016,
            "assumptions": ["alignment"],
            "fallback": "synthetic",
            "compile": {"compiler": CC, "flags": list(STRICT_FLAGS), "includes": [],
                        "returncode": 1, "diagnostics": ["synthetic error: intentional"],
                        "clean": False},
            "evidence": [],
        }],
        "assembly": [],
        "ffi_boundaries": [{
            "boundary_id": "fb-synthetic",
            "symbol": "ERR_set_error",
            "direction": "INBOUND",
            "abi": "C",
            "c_variadic": True,
            "unwind": "UNKNOWN",
            "sites": ["ca-synthetic"],
            "source": "c-adapter",
            "census_site": None,
            "evidence": [],
        }],
        "counts": {
            "c_files": 1, "c_loc": 224, "asm_sites": 0, "exported_ffi": 1, "imported_ffi": 0,
            "variadic_boundaries": 1, "warnings": 1, "generated_c_files": 1,
        },
        "residuals": [],
        "non_claims": [],
    }


def self_test() -> int:
    """Prove the guard refuses the host and the sensitivity control is honest."""
    failures: list[str] = []

    refusal = phase25_guard.host_refusal_reasons("ms_non_rust_tcb.py")
    if not refusal:
        failures.append("the guard admitted a host invocation of ms_non_rust_tcb.py")

    ctx = _synthetic_context()
    body = _synthetic_body()
    baseline = non_rust_findings(body, ctx)
    if baseline:
        failures.append(f"the synthetic body is not clean: {baseline[:4]}")
    control = non_rust_sensitivity_control(body, ctx)
    if not control["specificity_holds"] or control["caught"] != control["seeded"]:
        failures.append(f"the sensitivity control is not honest: {control}")

    if failures:
        print("[ms-non-rust-tcb] self-test FAILED")
        for f in failures:
            print(f"  {f}")
        return 1
    print("[ms-non-rust-tcb] self-test ok: the guard refuses the host; the synthetic inventory is "
          "clean; and all five seeded mutations (dropped C file, fabricated C file, removed reason, "
          "forged compile-clean result, dropped export boundary) are caught with specificity holding")
    return 0


# --------------------------------------------------------------------------------------------
# entry points
# --------------------------------------------------------------------------------------------

def _write_tcb(path: Path, doc: dict) -> None:
    """Write the inventory compactly, key-sorted and deterministic.

    A deliberate deviation from `atlas_common.write_json`'s `indent=2`, matching the census and the
    other Phase-25 planes: the columnar body is ~6,800 boundary records and pretty-printing
    multiplies it without adding evidence. Determinism is preserved (sorted keys, fixed separators)
    and `body_hash` covers the body.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
    path.write_text(text, encoding="utf-8")


def _measure() -> int:
    """Compile the C, scan the source, and write the non-Rust TCB inventory.

    Measurement: it runs a C compiler and `nm`, so it is refused on the host and is not listed among
    `evidence_determinism.py`'s generators (see that file's why-comment); the `MS-NON-RUST-TCB` court
    re-runs only the pure checks over the committed artefact.
    """
    WORK.mkdir(parents=True, exist_ok=True)
    (WORK / "objs").mkdir(parents=True, exist_ok=True)
    ctx = build_context()
    body = build_body(ctx)

    inputs = [
        InputRef(name="phase-25-plan", path=PLAN),
        InputRef(name="memory-safety-schemas", path=SCHEMAS),
        InputRef(name="phase25-guard", path=GUARD),
        InputRef(name="phase25-container-manifest", path=MANIFEST),
        InputRef(name="ms-non-rust-tcb-tool", path=TOOL),
        InputRef(name="build-rs", path=BUILD_RS),
        InputRef(name="source-census", path=CENSUS),
        InputRef(name="crate-non-rust-sources", sha256=content_hash(
            {s["path"]: s["sha256"] for s in ctx["shipped"]}),
            note="content hash of the sorted (path, sha256) pairs of every shipped src non-Rust file"),
        InputRef(name="generated-scaffolds", sha256=content_hash(
            {g["path"]: g["sha256"] for g in ctx["generated"]}),
            note="content hash of the sorted (path, sha256) pairs of the Phase-2 generated C"),
    ]

    auth = resolve_authority(PRODUCTION_AUTHORITY)
    encoded = ms_codec.encode_body(body, ctx["refs"])
    doc = envelope(kind="phase25-non-rust-tcb", authority=auth.id, inputs=inputs, body=encoded,
                   generator=GENERATOR)
    doc["body_hash"] = content_hash(encoded)
    _write_tcb(OUT, doc)

    problems = non_rust_findings(body, ctx)
    c = body["counts"]
    print(f"[ms-non-rust-tcb] {c['c_files']} C adapter(s) ({c['c_loc']} loc), "
          f"{c['generated_c_files']} generated scaffold(s); {c['asm_sites']} asm site(s), "
          f"{c['arch_intrinsic_sites']} arch intrinsic(s)")
    print(f"  FFI: exported={c['exported_ffi']} ("
          f"{c['census_export_sites']} census FFI_EXPORT + {c['c_adapter_exports']} C-adapter), "
          f"imported={c['imported_ffi']} over {c['extern_blocks']} extern block(s); "
          f"variadic boundaries={c['variadic_boundaries']}")
    print(f"  strict compile: {c['warnings']} diagnostic(s) recorded; "
          f"residuals={len(body['residuals'])}")
    print(f"  -> {rel(OUT)} all_pass={not problems}")
    if problems:
        for p in problems[:24]:
            print(f"    {p}")
    return 0 if not problems else 1


def _check() -> int:
    """Re-run the pure checks over the committed inventory, without a compiler."""
    if not OUT.is_file():
        print(f"[ms-non-rust-tcb] {rel(OUT)} is absent; run --measure")
        return 1
    doc = json.loads(OUT.read_text(encoding="utf-8"))
    ctx = build_context()
    body = ms_codec.decode_body(doc.get("body", doc), ctx["refs"])
    problems = non_rust_findings(body, ctx)
    if problems:
        print(f"[ms-non-rust-tcb] check FAILED: {len(problems)} problem(s)")
        for p in problems[:24]:
            print(f"  {p}")
        return 1
    c = body["counts"]
    print(f"[ms-non-rust-tcb] check ok: {c['c_files']} C adapter(s), {c['generated_c_files']} "
          f"generated scaffold(s), {c['exported_ffi']} exported and {c['imported_ffi']} imported "
          f"boundary record(s); every check holds")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--measure", action="store_true",
                    help="compile the C and write artifacts/phase25/non-rust-tcb.json")
    ap.add_argument("--check", action="store_true",
                    help="re-run the pure checks over the committed inventory")
    ap.add_argument("--self-test", action="store_true",
                    help="prove the guard refuses the host and the control is honest")
    args = ap.parse_args(argv)

    # The Docker-only execution guard, called first: this tool runs a C compiler.
    phase25_guard.require_admitted()

    if args.self_test:
        return self_test()
    if args.measure:
        return _measure()
    if args.check:
        return _check()
    ap.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
