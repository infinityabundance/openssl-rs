#!/usr/bin/env python3
"""openssl-rs — the prerequisite atlases: the authority surface no export atlas can see.

Why these files exist
---------------------
Every atlas this project had before this one is a projection of the authority's
**exported** surface: `symbol-ownership.json` over the 6,499 DSO exports,
`functions.json` over the 7,485 functions the *installed* headers declare,
`macros.json` over the 16,805 macros those same headers define. That surface is
what a consumer can see, so it is the right universe for a compatibility claim.

It is the wrong universe for a **prerequisite**. `crypto/conf/conf_mod.c` cannot be
written without `ossl_rcu_lock_new`, and `ossl_rcu_lock_new` is not exported,
declared in no installed header, and therefore invisible to every atlas the project
had. Four dependency inversions have now been found in Phase 6 alone, every one by
hand and none by a tool:

* D114 — `dso_win32.c`'s stratum and `OSSL_LIB_CTX_load_config`'s were circular;
* D97 — `6.6f`'s property engine was sited in the wrong stratum;
* D118 — RCU's read path calls `ossl_init_thread_start`, so `6.10` cannot precede
  `6.6e-ii`;
* D122 — `threads_common.c` stands on `crypto/sparse_array.c`, which stood in no
  unit plan at all.

Each was found by following the *call*, which is the only method that has worked and
the method this tool mechanises.

The four artefacts
------------------
`forensics/atlas/internal-symbols.json`
    The **function** universe: every symbol the authority's objects define that is
    *not* a DSO export — 4,923 of them — with the translation unit that defines it.
    Source: the authority's build tree, which has one `.o` per translation unit per
    form, so the defining unit is a measurement rather than an inference.

`forensics/atlas/macro-owners.json`, `forensics/atlas/typedef-owners.json`
    The **macro/enumerator** and **type** universes, installed *and* internal. The
    installed half is a projection of the Phase-1 `macros.json` / `typedefs.json`;
    the internal half is a `#define`/`enum`/`typedef` scan of the non-installed
    headers under `include/internal/`, `crypto/`, `providers/`, `ssl/` and
    `engines/`. `CRYPTO_THREAD_LOCAL_ERR_KEY` — D122's open question about
    `crypto/err/err.c` — is a member of the latter, which is exactly why
    `macro-owners.json` has to exist before the question can be asked mechanically.

`forensics/atlas/transcription-edges.json`
    Which authority translation unit each crate module transcribes, derived from the
    authority symbols the module *defines* rather than from its prose, and for each
    of those units the internal symbols and macros it references. This is the half of
    the gate that can only be computed where the authority is: it is committed so the
    gate itself needs no authority tree and can therefore run in the static job.

The two tiers
-------------
The authority's source tree and build tree are **not committed**, so this generator
has the same two-tier shape as `gen_ctype_table.py`, and which tier ran is printed
rather than implied:

* authority present  -> the artefacts are re-derived from it and written;
* authority absent   -> `--check` validates the committed artefacts' structure and
  their own recorded arithmetic, and the court job re-derives and requires
  `git diff --exit-code` over them.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import (  # noqa: E402
    ATLAS,
    PRODUCTION_AUTHORITY,
    REPO_ROOT,
    InputRef,
    authority_build_dir,
    authority_source,
    envelope,
    rel,
    write_json,
)

GENERATOR = "forensics/tools/gen_prerequisite_atlas.py"

OUT_INTERNAL = ATLAS / "internal-symbols.json"
OUT_MACROS = ATLAS / "macro-owners.json"
OUT_TYPEDEFS = ATLAS / "typedef-owners.json"
OUT_EDGES = ATLAS / "transcription-edges.json"

SRC = REPO_ROOT / "src"

# The authority's build tree names each object after its library form and its source
# basename: `crypto/libcrypto-lib-threads_common.o` is the archive copy of
# `crypto/threads_common.c`, and `crypto/libcrypto-shlib-threads_common.o` is the
# shared-object copy of the *same* file. Both are read, and the prefix is stripped so
# the two agree on one translation unit rather than looking like a duplicate
# definition.
_OBJ_PREFIX = re.compile(r"^lib(?:crypto|ssl)-(?:lib|shlib)-")

# The source areas that make up the two libraries and their provider/engine modules.
# `apps/` and `test/` are excluded: they are consumers of the libraries rather than
# part of them, and a symbol defined only in a test is not a prerequisite of anything.
SOURCE_AREAS = ("crypto", "providers", "ssl", "engines")

# The non-installed headers, by area. `include/internal/` carries the internal
# declarations (`include/internal/threads_common.h` defines the key-id enumerators);
# the rest are per-area private headers.
INTERNAL_HEADER_ROOTS = ("include/internal", "crypto", "providers", "ssl", "engines")


# ---------------------------------------------------------------------------
# Lexical scanning
#
# Every scan here is lexical, and each artefact says so. A C parser is not needed
# for any question this tool asks — "does this unit mention this name?" — and using
# one would make the tool depend on the authority's build configuration, which is a
# larger coupling than the question deserves.
# ---------------------------------------------------------------------------


def blank_out(text: str, spans: list[tuple[int, int]]) -> str:
    """Replace each span with spaces, preserving newlines so lines still count."""
    out = list(text)
    for start, end in spans:
        for i in range(start, min(end, len(out))):
            if out[i] != "\n":
                out[i] = " "
    return "".join(out)


def strip_c(text: str) -> str:
    """Blank comments, string literals and character literals in C source."""
    spans: list[tuple[int, int]] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            end = text.find("*/", i + 2)
            end = n if end < 0 else end + 2
            spans.append((i, end))
            i = end
        elif c == "/" and i + 1 < n and text[i + 1] == "/":
            end = text.find("\n", i)
            end = n if end < 0 else end
            spans.append((i, end))
            i = end
        elif c == '"':
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == '"':
                    j += 1
                    break
                j += 1
            spans.append((i, j))
            i = j
        elif c == "'":
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == "'":
                    j += 1
                    break
                j += 1
            spans.append((i, j))
            i = j
        else:
            i += 1
    return blank_out(text, spans) if spans else text


_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def identifiers(text: str) -> set[str]:
    return set(_IDENT.findall(text))


# ---------------------------------------------------------------------------
# The authority's object files: symbol -> defining translation unit
# ---------------------------------------------------------------------------


def translation_unit(relpath: str) -> str:
    """`crypto/libcrypto-lib-threads_common.o` -> `crypto/threads_common.c`."""
    d, _, base = relpath.rpartition("/")
    base = _OBJ_PREFIX.sub("", base)
    base = base[:-2] if base.endswith(".o") else base
    return f"{d}/{base}.c" if d else f"{base}.c"


def authority_objects(build: Path):
    """Yield (translation_unit, area, defined-symbols) for every library object."""
    import elf_symbols  # local import: keeps this module importable without it

    for area in SOURCE_AREAS:
        root = build / area
        if not root.is_dir():
            continue
        for obj in sorted(root.rglob("*.o")):
            # `providers/legacy/legacy-dso-cpuid.o` and friends do not carry the
            # per-library prefix because they are linked into a DSO of their own;
            # the path is still the translation unit's own.
            tu = translation_unit(obj.relative_to(build).as_posix())
            try:
                syms = elf_symbols.elf_defined_external_symbols(obj.read_bytes())
            except elf_symbols.ElfError:
                continue
            if syms:
                yield tu, area, syms


def authority_exports(authority_id: str) -> set[str]:
    out: set[str] = set()
    for lib in ("libcrypto", "libssl"):
        doc = json.loads(
            (ATLAS / authority_id / f"symbols-{lib}.json").read_text(encoding="utf-8")
        )
        for rec in doc["body"]["records"]:
            if (rec.get("dso") or {}).get("present"):
                out.add(rec["symbol"])
    return out


def build_internal_symbols(authority_id: str) -> tuple[dict, dict[str, str]]:
    """Return (body, symbol -> translation unit) for the internal function universe."""
    build = authority_build_dir(authority_id)
    exports = authority_exports(authority_id)

    sym_tu: dict[str, str] = {}
    sym_area: dict[str, str] = {}
    tu_syms: dict[str, set[str]] = defaultdict(set)
    conflicts: list[str] = []
    for tu, area, syms in authority_objects(build):
        tu_syms[tu] |= syms
        for s in sorted(syms):
            if s in sym_tu and sym_tu[s] != tu:
                conflicts.append(f"{s}: {sym_tu[s]} and {tu}")
            sym_tu.setdefault(s, tu)
            sym_area.setdefault(s, area)

    internal = {s: t for s, t in sym_tu.items() if s not in exports}

    # Which internal headers declare each symbol, lexically. A header that merely
    # calls the name inside an inline body would also match; the field is named
    # `declared_in` and this note is the reason it is a lexical index rather than a
    # claim about the C grammar.
    headers = internal_headers(authority_source(authority_id))
    decl: dict[str, list[str]] = defaultdict(list)
    for header, text in headers.items():
        for name in identifiers(strip_c(text)):
            if name in internal:
                decl[name].append(header)

    records = [
        {
            "symbol": s,
            "translation_unit": internal[s],
            "area": sym_area[s],
            "declared_in": sorted(decl.get(s, [])),
        }
        for s in sorted(internal)
    ]
    body = {
        "definition": (
            "every symbol the authority's library objects define that is not a DSO "
            "export, with the translation unit that defines it; the universe a "
            "prerequisite is drawn from, and invisible to every export-based atlas"
        ),
        "universe": {
            "authority_defined_symbols": len(sym_tu),
            "exports": len(exports),
            "internal": len(internal),
            "translation_units": len(tu_syms),
        },
        "invariants": {
            "undefined_symbol": 0,
            "conflicting_definitions": len(conflicts),
            "records_without_a_translation_unit": sum(1 for r in records if not r["translation_unit"]),
        },
        "conflicts": sorted(conflicts),
        "records": records,
    }
    return body, sym_tu


# ---------------------------------------------------------------------------
# Macros, enumerators and typedefs, installed and internal
# ---------------------------------------------------------------------------

_DEFINE = re.compile(r"^[ \t]*#[ \t]*define[ \t]+([A-Za-z_][A-Za-z0-9_]*)", re.M)


def scan_macros(text: str) -> set[str]:
    return set(_DEFINE.findall(strip_c(text)))


def _matching_brace(text: str, open_idx: int) -> int:
    depth = 0
    for i in range(open_idx, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return i
    return -1


def scan_enumerators(text: str) -> set[str]:
    """Identifiers introduced at the head of an `enum` member."""
    clean = strip_c(text)
    out: set[str] = set()
    for m in re.finditer(r"\benum\b[^{;]*\{", clean):
        close = _matching_brace(clean, m.end() - 1)
        if close < 0:
            continue
        body = clean[m.end() : close]
        depth = 0
        member = ""
        parts: list[str] = []
        for ch in body:
            if ch in "([{":
                depth += 1
            elif ch in ")]}":
                depth -= 1
            if ch == "," and depth == 0:
                parts.append(member)
                member = ""
                continue
            member += ch
        parts.append(member)
        for part in parts:
            mm = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:=[^,]*)?$", part, re.S)
            if mm:
                out.add(mm.group(1))
    return out


_TYPEDEF = re.compile(r"\btypedef\b", re.M)


def _blank_macro_bodies(clean: str) -> str:
    """Blank every `#define`, including its backslash continuations.

    Used only by the typedef scan. A macro's body is a token soup that introduces no
    type until it is instantiated, and `include/internal/list.h`'s
    `DEFINE_LIST_OF(name, type)` is why this exists: reading a `typedef` out of a
    macro body is how the first version of this artefact put `name` and `type` into
    the type universe, from which they were then read as missing prerequisites.
    """
    lines = clean.split("\n")
    in_macro = False
    for i, line in enumerate(lines):
        if in_macro or line.lstrip().startswith("#"):
            in_macro = line.rstrip().endswith("\\")
            lines[i] = " " * len(line)
    return "\n".join(lines)


def scan_typedefs(text: str) -> set[str]:
    """Type names introduced by `typedef`, function-pointer form included."""
    out: set[str] = set()
    guarded = _blank_macro_bodies(strip_c(text))
    for m in _TYPEDEF.finditer(guarded):
        depth = 0
        end = -1
        for i in range(m.end(), len(guarded)):
            c = guarded[i]
            if c in "([{":
                depth += 1
            elif c in ")]}":
                depth -= 1
            elif c == ";" and depth == 0:
                end = i
                break
        if end < 0:
            continue
        decl = guarded[m.end() : end]
        fp = re.search(r"\(\s*\*\s*([A-Za-z_][A-Za-z0-9_]*)", decl)
        if fp:
            out.add(fp.group(1))
            continue
        names = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", decl)
        if names:
            out.add(names[-1])
    return out


def internal_headers(source: Path) -> dict[str, str]:
    """Every non-installed header, by its repo-relative path within the tree."""
    out: dict[str, str] = {}
    for root in INTERNAL_HEADER_ROOTS:
        base = source / root
        if not base.is_dir():
            continue
        for h in sorted(base.rglob("*.h")):
            out[h.relative_to(source).as_posix()] = h.read_text(encoding="utf-8", errors="replace")
    return out


def authority_version(authority_id: str) -> str:
    reg = json.loads(
        (REPO_ROOT / "forensics" / "authorities" / "AUTHORITIES.json").read_text(encoding="utf-8")
    )
    for a in reg["authorities"]:
        if a["id"] == authority_id:
            return a["version"]
    raise KeyError(authority_id)


def load_build_record(authority_id: str) -> dict:
    """The stable fields of this authority's build record.

    The toolchain and artifact sizes are deliberately dropped: they are properties of the
    machine that ran the build, and this artefact is compared byte for byte on a different one.
    The build *directory* and the *profile* are what a reader needs, and both are stable.
    """
    doc = json.loads((ATLAS / "BUILD_RECORDS.json").read_text(encoding="utf-8"))
    for b in doc.get("builds", []):
        if b["id"] == authority_id:
            return {
                "profile": b["profile"],
                "profile_args": b["profile_args"],
                "version": b["version"],
                "configure_argv": b["configure_argv"],
                "build_dir": b["build_dir"],
                "prefix": b["prefix"],
            }
    raise KeyError(authority_id)


def owner_phase_for_header(header: str, installed: dict[str, int], tu_of_module: dict[str, str],
                           module_phase: dict[str, int]) -> int | None:
    """The stratum that owns a header.

    Installed headers are answered by `symbol-ownership.json`, which already assigns
    every one of them. An internal header is answered by its own name: an internal
    header conventionally pairs with a translation unit of the same basename
    (`include/internal/threads_common.h` with `crypto/threads_common.c`), and that
    unit's transcriber's phase is the answer. A header that pairs with nothing is
    `null` and is reported rather than guessed.
    """
    name = header.rsplit("/", 1)[-1]
    if name in installed:
        return installed[name]
    stem = name[:-2] if name.endswith(".h") else name
    phases: list[int] = []
    for module, tu in tu_of_module.items():
        if tu.rsplit("/", 1)[-1] == f"{stem}.c":
            p = module_phase.get(module)
            if p is not None:
                phases.append(p)
    if not phases:
        return None
    return Counter(phases).most_common(1)[0][0]


def build_language_universe(authority_id: str, module_phase: dict[str, int],
                            tu_of_module: dict[str, str]) -> tuple[dict, dict]:
    """Return (macro-and-enumerator body, typedef body)."""
    installed_doc = json.loads(
        (ATLAS / "symbol-ownership.json").read_text(encoding="utf-8")
    )["body"]
    phased: dict[str, int] = {k: int(v) for k, v in installed_doc["headers"].items()}

    macros: dict[str, dict] = {}
    typedefs: dict[str, dict] = {}
    # The installed header set is the union of the headers the Phase-1 archaeology
    # parsed out of the installed tree. It is deliberately *not* the ownership atlas's
    # header map, which carries only the 81 headers that declare an export: a macro
    # installed in `opensslv.h` is installed even though no export is declared there,
    # and calling it internal would be a category error.
    installed: set[str] = set()

    def note(store: dict[str, dict], name: str, kind: str, where: str) -> None:
        row = store.setdefault(
            name,
            {
                "name": name,
                "kind": kind,
                "defined_in": [],
                "owner_phase": None,
            },
        )
        base = where.rsplit("/", 1)[-1]
        if base in installed:
            # An installed header's phase is the ownership atlas's answer or nothing:
            # falling through to the basename rule would look for a translation unit
            # named after an installed header, which does not exist.
            row["owner_phase"] = phased.get(base)
        elif row["owner_phase"] is None:
            row["owner_phase"] = owner_phase_for_header(where, {}, tu_of_module, module_phase)
        if where not in row["defined_in"]:
            row["defined_in"].append(where)
            row["defined_in"].sort()

    # The installed half, from the Phase-1 atlases rather than re-scanned: the
    # installed headers are what a consumer sees, and the archaeology has already
    # parsed them.
    macro_doc = json.loads((ATLAS / authority_id / "macros.json").read_text(encoding="utf-8"))
    typedef_doc = json.loads((ATLAS / authority_id / "typedefs.json").read_text(encoding="utf-8"))
    function_doc = json.loads((ATLAS / authority_id / "functions.json").read_text(encoding="utf-8"))
    for rec in macro_doc["body"]["records"]:
        installed.update(rec.get("defined_in") or [])
    for rec in typedef_doc["body"]["records"]:
        if rec.get("header"):
            installed.add(rec["header"])
    for rec in function_doc["body"]["records"]:
        if rec.get("header"):
            installed.add(rec["header"])

    for rec in macro_doc["body"]["records"]:
        k = rec.get("kind") or "macro"
        for header in rec.get("defined_in") or []:
            note(macros, rec["name"], k, header)
    for rec in typedef_doc["body"]["records"]:
        note(typedefs, rec["name"], "typedef", rec.get("header") or "")

    for header, text in internal_headers(authority_source(authority_id)).items():
        for name in sorted(scan_macros(text)):
            note(macros, name, "macro", header)
        for name in sorted(scan_enumerators(text)):
            note(macros, name, "enumerator", header)
        for name in sorted(scan_typedefs(text)):
            note(typedefs, name, "typedef", header)

    def counts_for(store: dict[str, dict]) -> dict:
        rows = list(store.values())
        unowned = [r["name"] for r in rows if r["owner_phase"] is None]
        internal_only = [
            r["name"] for r in rows
            if r["defined_in"] and not any(
                h.rsplit("/", 1)[-1] in installed for h in r["defined_in"]
            )
        ]
        return {
            "records": len(rows),
            "owned": len(rows) - len(unowned),
            "unowned": len(unowned),
            "internal_only": len(internal_only),
            "installed_headers": len(installed),
        }

    def body_of(store: dict[str, dict], definition: str) -> dict:
        rows = [store[k] for k in sorted(store)]
        unowned = [r["name"] for r in rows if r["owner_phase"] is None]
        return {
            "definition": definition,
            "counts": counts_for(store),
            "rule": (
                "an installed header's phase comes from forensics/atlas/"
                "symbol-ownership.json when that header declares an export, and is "
                "null otherwise; an internal header's comes from the translation "
                "unit of the same basename, via the module that transcribes it"
            ),
            "installed_headers": sorted(installed),
            "unowned_sample": unowned[:512],
            "records": rows,
        }

    return (
        body_of(
            macros,
            "every macro and enum member the authority's installed and internal "
            "headers define, with the header that defines it and that header's "
            "owning stratum",
        ),
        body_of(
            typedefs,
            "every typedef name the authority's installed and internal headers "
            "introduce, with the header that introduces it and that header's "
            "owning stratum",
        ),
    )


# ---------------------------------------------------------------------------
# Which translation unit each crate module transcribes, and what that unit needs
# ---------------------------------------------------------------------------

_RUST_FN = re.compile(
    r"^[ \t]*(?:pub(?:\([^)]*\))?[ \t]+)?(?:unsafe[ \t]+)?"
    r"(?:extern[ \t]+\"C\"[ \t]+)?fn[ \t]+([A-Za-z_][A-Za-z0-9_]*)[ \t]*[(<]",
    re.M,
)


def declared_phase(text: str) -> int | None:
    """The stratum a module declares for itself, from the first line of its doc header.

    The convention is `//! Phase <n>...` and it is machine-readable on purpose. It is
    the *second* source for a module's stratum: the first is the ownership of the
    exports the module defines, which is a measurement rather than a declaration.
    Where the two exist they are compared, because a module that transcribes Phase 6
    source while declaring itself Phase 3 is exactly the siting question D97 and D122
    each had to settle by hand.
    """
    for line in text.split("\n"):
        s = line.rstrip()
        if s.startswith("//!"):
            m = re.match(r"//!\s*Phase\s+(\d+)", s)
            return int(m.group(1)) if m else None
        if s.strip():
            return None
    return None


def crate_definitions() -> tuple[dict[str, list[str]], dict[str, int | None]]:
    """name -> the crate modules that define it, and module -> its declared stratum."""
    out: dict[str, list[str]] = defaultdict(list)
    declared: dict[str, int | None] = {}
    for path in sorted(SRC.rglob("*.rs")):
        text = path.read_text(encoding="utf-8")
        relp = rel(path)
        declared[relp] = declared_phase(text)
        for name in sorted(set(_RUST_FN.findall(text))):
            out[name].append(relp)
    return out, declared


def module_phases(crate_defs: dict[str, list[str]],
                  declared: dict[str, int | None]) -> tuple[dict[str, int], list[str], list[str], dict[str, str]]:
    """module -> the stratum it belongs to, and the sources that disagree.

    Derived first from the authority exports each module defines, resolved through
    `symbol-ownership.json`, and then from the module's own `//! Phase <n>`
    declaration where it defines no export at all (`crypto/threads_common.c`'s
    module defines none, and it is the module D122's chain runs through). Where both
    answers exist they must agree; a module where they do not is reported, because a
    disagreement is a question about the stratum's own boundary rather than something
    a tool should settle silently.
    """
    ownership = json.loads((ATLAS / "symbol-ownership.json").read_text(encoding="utf-8"))["body"]
    export_phase = {r["symbol"]: int(r["owner_phase"]) for r in ownership["records"] if r["owner_phase"] is not None}

    per_module: dict[str, Counter] = defaultdict(Counter)
    for symbol, modules in crate_defs.items():
        if symbol not in export_phase:
            continue
        for m in modules:
            per_module[m][export_phase[symbol]] += 1

    phases: dict[str, int] = {}
    source: dict[str, str] = {}
    mixed: list[str] = []
    disagree: list[str] = []
    for module, counter in sorted(per_module.items()):
        top, count = counter.most_common(1)[0]
        if count != sum(counter.values()):
            mixed.append(f"{module}: {dict(counter)}")
            source[module] = "dominant-export-ownership"
        else:
            source[module] = "export-ownership"
        d = declared.get(module)
        # Siting beats accounting. A module's stratum is where the project put it,
        # which its own declaration states; the export-ownership answer says which
        # stratum's *ledger* accounts for the exports it defines, and the two
        # legitimately differ wherever a module received a hand-off (Phase 6's
        # `thread_events.rs` declares Phase 6 and defines two exports Phase 3's ledger
        # accounts for). The difference is recorded rather than resolved away, and it
        # is checked against the ledgers' own `handoffs_discharged` records.
        if d is not None:
            phases[module] = d
            source[module] = "module-declaration"
            if d != top:
                disagree.append(
                    f"{module}: declared Phase {d}, defines exports owned by phase {top}"
                )
        else:
            phases[module] = top

    for module, d in sorted(declared.items()):
        if module in phases or d is None:
            continue
        phases[module] = d
        source[module] = "module-declaration"

    return phases, mixed, disagree, source


def build_edges(authority_id: str, crate_defs: dict[str, list[str]], sym_tu: dict[str, str],
                module_phase: dict[str, int], phase_source: dict[str, str]
                ) -> tuple[dict, dict[str, str], list[str]]:
    """The module -> translation unit map and each unit's internal references."""
    # `crate_defs` is symbol -> modules; this direction is module -> symbols.
    by_module: dict[str, list[str]] = defaultdict(list)
    for symbol, modules in crate_defs.items():
        for m in modules:
            by_module[m].append(symbol)

    tu_of_module: dict[str, str] = {}
    share: dict[str, str] = {}
    for module, names in sorted(by_module.items()):
        known = [n for n in names if n in sym_tu]
        if not known:
            continue
        counter = Counter(sym_tu[n] for n in known)
        top, count = counter.most_common(1)[0]
        tu_of_module[module] = top
        share[module] = f"{count}/{len(known)}"

    source = authority_source(authority_id)
    edges: dict[str, dict] = {}
    missing_units: list[str] = []
    for module, tu in sorted(tu_of_module.items()):
        path = source / tu
        if not path.is_file():
            missing_units.append(f"{module}: {tu}")
            continue
        if tu not in edges:
            clean = strip_c(path.read_text(encoding="utf-8", errors="replace"))
            edges[tu] = {"tu": tu, "modules": [], "identifiers": sorted(identifiers(clean))}
        edges[tu]["modules"].append(module)

    for tu in sorted(edges):
        edges[tu]["modules"].sort()

    body = {
        "definition": (
            "for each authority translation unit a crate module transcribes, the "
            "identifiers that unit references, and the module-to-unit map itself"
        ),
        "rule": (
            "the unit is the dominant authority translation unit among the symbols "
            "the module defines, so the map is measured from the code rather than "
            "read out of a doc comment; `share` is the dominance fraction and a "
            "module whose definitions are spread across units is expected"
        ),
        "modules": [
            {
                "module": m,
                "phase": module_phase.get(m),
                "phase_source": phase_source.get(m),
                "translation_unit": tu,
                "share": share[m],
            }
            for m, tu in sorted(tu_of_module.items())
        ],
        "units": [edges[tu] for tu in sorted(edges)],
    }
    return body, tu_of_module, missing_units


# ---------------------------------------------------------------------------
# Tiers
# ---------------------------------------------------------------------------


def write_all(authority_id: str) -> int:
    crate_defs, declared = crate_definitions()
    module_phase, mixed, disagree, phase_source = module_phases(crate_defs, declared)

    internal_body, sym_tu = build_internal_symbols(authority_id)
    edges_body, tu_of_module, missing_units = build_edges(
        authority_id, crate_defs, sym_tu, module_phase, phase_source
    )
    # The header-owner rule for an internal header needs the module-to-unit map,
    # which needs the symbol universe, so the language universes are built after the
    # edges rather than beside them. That is the same ordering argument D96 records
    # for generator sequencing, applied locally where the dependency is one call
    # deep and cheap to respect.
    macro_body, typedef_body = build_language_universe(authority_id, module_phase, tu_of_module)

    auth_atlas = ATLAS / authority_id
    # The two authority **trees** are not committed, and two of the four `inputs` this
    # document would like to name are not stable either, so neither is hashed here.
    #
    # `BUILD_RECORDS.json` is rewritten by `authority_build.py`, which the court job runs
    # before this generator: its `build_toolchain` and artifact sizes make its hash a property
    # of the machine that just built the authority. `implemented-surface.json` records the
    # crate archive's hash, which is a property of the machine that just built the *crate*.
    # A committed artefact that hashes either of those can never satisfy a byte comparison on
    # a runner it was not generated on -- and the court job compares these byte for byte with
    # `git diff --exit-code`. The stable facts each one carries are recorded as body fields
    # and as notes instead, which is what provenance needs; a hash that changes for a reason
    # unrelated to the evidence is not provenance, it is a false positive that a reviewer
    # learns to skip.
    build_records = load_build_record(authority_id)
    inputs = [
        InputRef(
            name="authority-source-manifest",
            path=REPO_ROOT / "forensics" / "authorities" / f"SOURCE_MANIFEST.{authority_version(authority_id)}.json",
        ),
        InputRef(name="authority-exports-libcrypto", path=auth_atlas / "symbols-libcrypto.json"),
        InputRef(name="authority-exports-libssl", path=auth_atlas / "symbols-libssl.json"),
        InputRef(name="authority-macros", path=auth_atlas / "macros.json"),
        InputRef(name="authority-typedefs", path=auth_atlas / "typedefs.json"),
        InputRef(name="authority-functions", path=auth_atlas / "functions.json"),
        InputRef(name="symbol-ownership", path=ATLAS / "symbol-ownership.json"),
        InputRef(
            name="authority-build-record",
            note=(
                "read for the build directory, the profile and the source area; its hash is "
                "deliberately not recorded, see this list's comment -- the fields are in "
                "body.authority_build"
            ),
        ),
        InputRef(
            name="implemented-surface",
            note=(
                "deliberately **not** read: the module-to-stratum map comes from "
                "symbol-ownership.json, which is committed and machine-independent, where "
                "I implemented-surface.json carries a build product's hash. Naming it as an input "
                "at all would be a claim about a file this generator does not open."
            ),
        ),
        InputRef(
            name="crate-source-tree",
            note=(
                "every .rs under src/ was read; a module that produces no export "
                "still contributes to the module-to-unit map"
            ),
        ),
    ]
    internal_body["authority_build"] = build_records
    edges_body["authority_build"] = build_records

    internal_body["modules_with_mixed_ownership"] = sorted(mixed)
    # Not a defect list: a module whose declaration disagrees with the ownership of
    # the exports it defines has almost always *received a hand-off*, which is a
    # recorded, legal pattern (`handoffs_discharged` in the phase ledgers). It is
    # recorded here because the siting question is exactly the one D97 and D122 each
    # had to settle by hand, and because a disagreement that is *not* a hand-off is
    # the next one that would have to be.
    internal_body["declaration_and_export_ownership_disagree"] = sorted(disagree)
    internal_body["modules_without_a_stratum"] = sorted(
        rel(p) for p in sorted(SRC.rglob("*.rs")) if rel(p) not in module_phase
    )
    internal_body["translation_units_without_a_source_file"] = sorted(missing_units)
    internal_body["not_checked"] = (
        "authority symbols defined only by an area outside crypto/ssl/providers/"
        "engines, and C constructs this tool's lexical scans do not model"
    )

    write_json(
        OUT_INTERNAL,
        envelope("internal-symbols", GENERATOR, inputs, internal_body, authority=authority_id),
    )
    write_json(
        OUT_MACROS,
        envelope("macro-owners", GENERATOR, inputs, macro_body, authority=authority_id),
    )
    write_json(
        OUT_TYPEDEFS,
        envelope("typedef-owners", GENERATOR, inputs, typedef_body, authority=authority_id),
    )
    write_json(
        OUT_EDGES,
        envelope("transcription-edges", GENERATOR, inputs, edges_body, authority=authority_id),
    )

    print(f"[prerequisite-atlas] internal symbols: {internal_body['universe']['internal']}"
          f" of {internal_body['universe']['authority_defined_symbols']} defined")
    print(f"[prerequisite-atlas] macros/enumerators: {macro_body['counts']}")
    print(f"[prerequisite-atlas] typedefs: {typedef_body['counts']}")
    print(f"[prerequisite-atlas] edges: {len(edges_body['modules'])} modules over "
          f"{len(edges_body['units'])} translation units")
    if mixed:
        print(f"[prerequisite-atlas] modules with mixed export ownership: {len(mixed)}",
              file=sys.stderr)
    for m in mixed:
        print(f"    {m}", file=sys.stderr)
    if disagree:
        print(f"[prerequisite-atlas] modules whose declaration disagrees with their "
              f"exports: {len(disagree)}", file=sys.stderr)
        for m in disagree:
            print(f"    {m}", file=sys.stderr)
    if missing_units:
        print(f"[prerequisite-atlas] units with no source file: {len(missing_units)}",
              file=sys.stderr)
        for m in missing_units:
            print(f"    {m}", file=sys.stderr)
    for out in (OUT_INTERNAL, OUT_MACROS, OUT_TYPEDEFS, OUT_EDGES):
        print(f"  -> {rel(out)}")
    return 0


def check_committed(check_only: bool) -> int:
    """The weak tier: validate the committed artefacts without the authority.

    It catches a hand-edited artefact and a truncated one. It cannot catch the
    authority having changed — the authority is pinned by archive hash elsewhere, and
    the court job, which has the tree, re-derives and requires no diff.
    """
    problems: list[str] = []
    for path, kind in (
        (OUT_INTERNAL, "internal-symbols"),
        (OUT_MACROS, "macro-owners"),
        (OUT_TYPEDEFS, "typedef-owners"),
        (OUT_EDGES, "transcription-edges"),
    ):
        if not path.is_file():
            problems.append(f"{rel(path)} is absent")
            continue
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            problems.append(f"{rel(path)} is not JSON: {exc}")
            continue
        if doc.get("kind") != kind:
            problems.append(f"{rel(path)} has kind {doc.get('kind')!r}, expected {kind!r}")
            continue
        body = doc["body"]
        records = body.get("records") or []
        if kind == "internal-symbols":
            if len(records) != body["universe"]["internal"]:
                problems.append(
                    f"{rel(path)}: {len(records)} records, universe says "
                    f"{body['universe']['internal']}"
                )
            if body["invariants"]["conflicting_definitions"] != len(body["conflicts"]):
                # A conflict is *recorded*, not forbidden: 144 symbols in this authority are
                # defined by two different translation units (a library copy and a provider
                # copy of the same source, among others), and the first definition wins. What
                # the check can require is that the count and the list agree, so that the
                # number in `invariants` is the number of entries `conflicts` holds.
                problems.append(
                    f"{rel(path)}: {body['invariants']['conflicting_definitions']} conflicting "
                    f"definitions recorded but {len(body['conflicts'])} listed"
                )
            for r in records:
                if not r.get("translation_unit"):
                    problems.append(f"{rel(path)}: {r['symbol']} has no translation unit")
                    break
        elif kind in ("macro-owners", "typedef-owners"):
            if len(records) != body["counts"]["records"]:
                problems.append(
                    f"{rel(path)}: {len(records)} records, counts says "
                    f"{body['counts']['records']}"
                )
            # `unowned_sample` is a *sample*, not the list: there are ten thousand unowned
            # macro names and listing them all would double the artefact to say one thing. The
            # check is therefore on the sample's length and on the count agreeing with the
            # records, which is what makes the sample's truncation a fact rather than a hole.
            expected = min(512, body["counts"]["unowned"])
            if len(body["unowned_sample"]) != expected:
                problems.append(
                    f"{rel(path)}: unowned_sample has {len(body['unowned_sample'])} entries, "
                    f"expected {expected} for {body['counts']['unowned']} unowned records"
                )
            unowned_here = sum(1 for r in records if r["owner_phase"] is None)
            if unowned_here != body["counts"]["unowned"]:
                problems.append(
                    f"{rel(path)}: {unowned_here} unowned records, counts says "
                    f"{body['counts']['unowned']}"
                )
        else:
            if not body.get("modules") or not body.get("units"):
                problems.append(f"{rel(path)}: empty module or unit list")
        names = [r.get("symbol") or r.get("name") for r in records]
        if names != sorted(names):
            problems.append(f"{rel(path)}: records are not in sorted order")

    if problems:
        for p in problems:
            print(f"[{GENERATOR}] {p}", file=sys.stderr)
        return 1
    if check_only:
        print(
            f"[prerequisite-atlas] ok (weak tier, authority absent): "
            f"{rel(OUT_INTERNAL)}, {rel(OUT_MACROS)}, {rel(OUT_TYPEDEFS)} and "
            f"{rel(OUT_EDGES)} are structurally consistent"
        )
    else:
        print(
            f"[prerequisite-atlas] weak tier: the authority's trees are absent, so "
            f"the committed artefacts were checked and not re-derived"
        )
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    ap.add_argument("--check", action="store_true", help="do not write; fail on drift")
    args = ap.parse_args(argv)

    if args.check:
        return check_committed(check_only=True)

    try:
        source = authority_source(args.authority)
        build = authority_build_dir(args.authority)
    except Exception as exc:  # noqa: BLE001 - any resolution failure means the weak tier
        print(f"[{GENERATOR}] authority unavailable ({exc}); weak tier", file=sys.stderr)
        return check_committed(check_only=False)

    if not source.is_dir() or not build.is_dir():
        print(f"[{GENERATOR}] authority trees absent; weak tier", file=sys.stderr)
        return check_committed(check_only=False)

    return write_all(args.authority)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
