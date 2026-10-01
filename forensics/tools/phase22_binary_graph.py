#!/usr/bin/env python3
"""openssl-rs -- Phase 22.6: the object, archive, DSO and provider-module graph.

`docs/PHASE-22-SUBPHASES.md` section 6 gives this subphase its reason to exist: "22.6 exists
because assembly and perlasm are invisible to Clang, and because link-time resolution is where the
real dependency graph is confirmed." This tool therefore reads the *binaries* the admitted
`openssl-3.6.4-production` build produced, not the source:

    forensics/authorities/build/openssl-3.6.4-production/
        libcrypto.so.3   libssl.so.3   libcrypto.a   libssl.a
        apps/openssl
        providers/*.so   engines/*.so

It extracts, per artefact, the defined symbols (with linkage global/local/weak and type
FUNC/OBJECT/TLS/NOTYPE), the undefined symbols, the TLS objects, the aliases, the sections of
interest, the archive membership (which `.o` is in which `.a`), the dynamic dependencies
(DT_NEEDED) and the versioned symbols; and it builds the **typed edge graph**: for every object,
its `RELOCATION_REFERENCE` edges (relocation -> symbol), each resolved to the object that defines
that symbol where the set defines it at all. That is the binary corroboration of the source
dependency graph, and -- because the `.s` objects are archive members with their own symbol and
relocation tables -- it is the one plane that sees the perlasm units Clang never parses (the
`perlasm_objects` census is derived by joining this plane against 22.1's `compile-commands.json`).

Reading
-------
Pure Python, deliberately. `forensics/tools/elf_symbols.py` already establishes that the native
`.symtab` is the surface this project needs and that binutils' LLVM-bitcode plugin makes the same
archive yield *different symbol sets on different machines* (`docs/DECISIONS.md` D30, D33). A
relocation graph read through `objdump` would inherit that non-determinism, so this tool parses
ELF64 / `ar` with `struct`, importing `elf_symbols`' constants and string helper rather than
reimplementing them. Binutils is not invoked at all.

Determinism and reduction
-------------------------
The document is a pure function of the artefacts it names: sorted everywhere, no timestamp, no PID
and no scratch path. Relocation entries are collapsed to one `RELOCATION_REFERENCE` edge per
`(object, symbol)` with the sorted set of relocation types seen; the per-entry offset and addend
are not retained, because a libcrypto archive carries ~134,000 relocation entries and inlining
them would be the "whole `.text`" this plane is told not to inline. The collapse is recorded
explicitly in `body.reduction` rather than done silently, and the raw form is recoverable by
re-running the parser over the same pinned build.

Output
------
    forensics/atlas/phase22/binary-reference-graph.json

`forensics/tools/phase22_courts.py` discovers this module and calls `courts()`, which drives the
pure `derive_body` over the committed artefact and over controlled in-memory mutations of it. See
`RT-PHASE22-BINARY` below.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import (  # noqa: E402
    PRODUCTION_AUTHORITY,
    REPO_ROOT,
    InputRef,
    authority_build_dir,
    envelope,
    rel,
    resolve_authority,
    sha256_file,
    write_json,
)

import elf_symbols as es  # noqa: E402  -- reuse the pinned ELF64 constants and reader helpers
import phase22_build_commands as pbc  # noqa: E402  -- the 22.1 map, for perlasm attribution

GENERATOR = "forensics/tools/phase22_binary_graph.py"
ARTEFACT_REL = "forensics/atlas/phase22/binary-reference-graph.json"
COURT = "RT-PHASE22-BINARY"

# ELF constants this reader needs, beyond those `elf_symbols` already names.
SHT_RELA = 4
SHT_DYNAMIC = 6
SHT_REL = 9
SHT_GNU_VERDEF = 0x6FFFFFFD
SHT_GNU_VERNEED = 0x6FFFFFFE
SHT_GNU_VERSYM = 0x6FFFFFFF
SYMENT = 24
SHN_XINDEX = 0xFFFF

STT_NOTYPE, STT_OBJECT, STT_FUNC, STT_SECTION, STT_FILE = 0, 1, 2, 3, 4
STT_COMMON, STT_TLS, STT_GNU_IFUNC = 5, 6, 10
STB_LOCAL, STB_GLOBAL, STB_WEAK, STB_GNU_UNIQUE = 0, 1, 2, 10

_TYPE_NAMES = {STT_NOTYPE: "NOTYPE", STT_OBJECT: "OBJECT", STT_FUNC: "FUNC",
               STT_COMMON: "COMMON", STT_TLS: "TLS", STT_GNU_IFUNC: "IFUNC"}
_BIND_NAMES = {STB_LOCAL: "local", STB_GLOBAL: "global", STB_WEAK: "weak",
               STB_GNU_UNIQUE: "unique"}

# Sections this plane considers "of interest". Exact names only: a `.text.*` glob would re-inline
# the whole code size this plane is told to keep out, and the named sections are the ones a
# compatibility reader asks about (where code, read-only data, TLS and the dynamic machinery live).
INTEREST_SECTIONS = frozenset({
    ".text", ".rodata", ".data", ".bss", ".data.rel.ro", ".init_array", ".fini_array",
    ".tdata", ".tbss", ".plt", ".plt.got", ".plt.sec", ".got", ".got.plt",
    ".eh_frame", ".eh_frame_hdr", ".init", ".fini", ".dynamic", ".dynsym", ".dynstr",
    ".symtab", ".strtab", ".gnu.version", ".gnu.version_d", ".gnu.version_r", ".interp",
    ".comment",
})

_FLAG_BITS = ((0x1, "W"), (0x2, "A"), (0x4, "X"), (0x10, "M"), (0x20, "S"), (0x40, "I"),
              (0x80, "L"), (0x100, "O"), (0x200, "G"), (0x400, "T"), (0x800, "C"))

# x86-64 relocation type names (the psABI subset the authority's objects actually emit).
R_X86_64 = {
    0: "R_X86_64_NONE", 1: "R_X86_64_64", 2: "R_X86_64_PC32", 3: "R_X86_64_GOT32",
    4: "R_X86_64_PLT32", 5: "R_X86_64_COPY", 6: "R_X86_64_GLOB_DAT",
    7: "R_X86_64_JUMP_SLOT", 8: "R_X86_64_RELATIVE", 9: "R_X86_64_GOTPCREL",
    10: "R_X86_64_32", 11: "R_X86_64_32S", 12: "R_X86_64_16", 13: "R_X86_64_PC16",
    14: "R_X86_64_8", 15: "R_X86_64_PC8", 16: "R_X86_64_DTPMOD64",
    17: "R_X86_64_DTPOFF64", 18: "R_X86_64_TPOFF64", 19: "R_X86_64_TLSGD",
    20: "R_X86_64_TLSLD", 21: "R_X86_64_DTPOFF32", 22: "R_X86_64_GOTTPOFF",
    23: "R_X86_64_TPOFF32", 24: "R_X86_64_PC64", 25: "R_X86_64_GOTOFF64",
    26: "R_X86_64_GOTPC32", 27: "R_X86_64_GOT64", 28: "R_X86_64_GOTPCREL64",
    29: "R_X86_64_GOTPC64", 30: "R_X86_64_GOTPLT64", 31: "R_X86_64_PLTOFF64",
    32: "R_X86_64_SIZE32", 33: "R_X86_64_SIZE64", 34: "R_X86_64_GOTPC32_TLSDESC",
    35: "R_X86_64_TLSDESC_CALL", 36: "R_X86_64_TLSDESC", 37: "R_X86_64_IRELATIVE",
    38: "R_X86_64_RELATIVE64", 41: "R_X86_64_GOTPCRELX", 42: "R_X86_64_REX_GOTPCRELX",
}


def _r_type_name(t: int) -> str:
    return R_X86_64.get(t, f"R_X86_64_UNKNOWN_0x{t:x}")


def _flags_str(flags: int) -> str:
    return "".join(s for bit, s in _FLAG_BITS if flags & bit)


# ---------------------------------------------------------------------------
# raw ELF64 reading
# ---------------------------------------------------------------------------

def read_sections(data: bytes) -> list[dict]:
    """Every section header of an ELF64 little-endian object, with its name resolved."""
    if len(data) < 64 or not data.startswith(es.ELF_MAGIC):
        raise es.ElfError("not an ELF object")
    if data[4] != es.ELFCLASS64:
        raise es.ElfError("only ELFCLASS64 is supported")
    if data[5] != es.ELFDATA2LSB:
        raise es.ElfError("only little-endian ELF objects are supported")
    (e_shoff,) = struct.unpack_from("<Q", data, 0x28)
    (e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from("<HHH", data, 0x3A)
    if e_shoff == 0 or e_shentsize != es.SHEntSize:
        raise es.ElfError(f"unusable section table (off={e_shoff})")
    if e_shnum == 0:
        # ELF extended numbering: the real count lives in section 0's sh_size.
        (e_shnum,) = struct.unpack_from("<Q", data, e_shoff + 0x20)
    if e_shnum == 0:
        raise es.ElfError("section table declares no sections")
    out: list[dict] = []
    for i in range(e_shnum):
        b = e_shoff + i * es.SHEntSize
        if b + es.SHEntSize > len(data):
            raise es.ElfError("section table runs past the end of the object")
        (sh_name, sh_type, sh_flags) = struct.unpack_from("<IIQ", data, b)
        (sh_addr, sh_offset, sh_size) = struct.unpack_from("<QQQ", data, b + 0x10)
        (sh_link, sh_info) = struct.unpack_from("<II", data, b + 0x28)
        (sh_entsize,) = struct.unpack_from("<Q", data, b + 0x38)
        out.append({"name": sh_name, "type": sh_type, "flags": sh_flags, "addr": sh_addr,
                    "offset": sh_offset, "size": sh_size, "link": sh_link, "info": sh_info,
                    "entsize": sh_entsize, "sname": ""})
    if e_shstrndx >= len(out):
        raise es.ElfError("section-name string table index is out of range")
    shstr = out[e_shstrndx]
    blob = data[shstr["offset"]:shstr["offset"] + shstr["size"]]
    for s in out:
        s["sname"] = es._cstring(blob, s["name"])
    return out


def _section_name(shndx: int, sections: list[dict]) -> str | None:
    if shndx == es.SHN_UNDEF:
        return None
    if shndx == 0xFFF1:
        return "ABS"
    if shndx == 0xFFF2:
        return "COMMON"
    if shndx < len(sections):
        return sections[shndx]["sname"]
    return f"SHN_0x{shndx:x}"


def _strtab_for(data: bytes, sections: list[dict], link: int) -> bytes:
    if link >= len(sections):
        raise es.ElfError("symbol table links to a missing string table")
    s = sections[link]
    return data[s["offset"]:s["offset"] + s["size"]]


def _read_symlist(data: bytes, sections: list[dict], tables: list[dict], want_defined: bool,
                  namever: dict[str, str]) -> list[dict]:
    """Defined or undefined symbols from one or more symbol-table sections."""
    out: list[dict] = []
    seen: set[tuple] = set()
    for tab in tables:
        if tab["entsize"] != SYMENT:
            raise es.ElfError(f"unexpected symbol entry size {tab['entsize']}")
        strtab = _strtab_for(data, sections, tab["link"])
        for j in range(tab["size"] // SYMENT):
            ent = tab["offset"] + j * SYMENT
            (st_name, st_info, _st_other, shndx) = struct.unpack_from("<IBBH", data, ent)
            (st_value, st_size) = struct.unpack_from("<QQ", data, ent + 8)
            if shndx == SHN_XINDEX:
                shndx = 0
            defined = shndx != es.SHN_UNDEF
            if defined != want_defined:
                continue
            stype = st_info & 0xF
            if stype in (STT_SECTION, STT_FILE):
                continue
            name = es._cstring(strtab, st_name)
            if not name:
                continue
            binding = _BIND_NAMES.get(st_info >> 4, f"bind{st_info >> 4}")
            type_name = _TYPE_NAMES.get(stype, f"type{stype}")
            section = _section_name(shndx, sections) if defined else None
            key = (name, binding, type_name, section, st_value if defined else 0)
            if key in seen:
                continue
            seen.add(key)
            rec = {"name": name, "binding": binding, "type": type_name,
                   "section": section, "value": st_value, "size": st_size}
            if name in namever:
                rec["version"] = namever[name]
            out.append(rec)
    out.sort(key=lambda r: (r["name"], r["binding"], r["type"], r["section"] or ""))
    return out


def _read_relocations(data: bytes, sections: list[dict]) -> tuple[list[dict], int]:
    """Collapsed RELOCATION_REFERENCE edges: one per (symbol) with its relocation-type set.

    Returns `(edges, raw_entries)` where `raw_entries` is the number of relocation entries that
    named a symbol (entries with symbol index 0 -- e.g. `R_X86_64_RELATIVE` -- name none and are
    not `relocation -> symbol` edges).
    """
    names_cache: dict[int, list[str]] = {}
    edges: dict[str, set[str]] = {}
    raw = 0
    for s in sections:
        if s["type"] not in (SHT_RELA, SHT_REL):
            continue
        step = 24 if s["type"] == SHT_RELA else 16
        if s["entsize"] not in (0, step):
            raise es.ElfError(f"unexpected relocation entry size {s['entsize']}")
        link = s["link"]
        if link not in names_cache:
            if link >= len(sections):
                raise es.ElfError("relocation section links to a missing symbol table")
            names_cache[link] = _symtab_names(data, sections, sections[link])
        names = names_cache[link]
        for j in range(s["size"] // step):
            ent = s["offset"] + j * step
            (_r_offset, r_info) = struct.unpack_from("<QQ", data, ent)
            sym_idx = r_info >> 32
            r_type = r_info & 0xFFFFFFFF
            if sym_idx == 0:
                continue
            raw += 1
            if sym_idx >= len(names):
                continue
            name = names[sym_idx]
            if not name:
                continue
            edges.setdefault(name, set()).add(_r_type_name(r_type))
    out = [{"symbol": k, "types": sorted(v)} for k, v in edges.items()]
    out.sort(key=lambda e: e["symbol"])
    return out, raw


def _symtab_names(data: bytes, sections: list[dict], tab: dict) -> list[str]:
    names: list[str] = []
    if tab["type"] not in (es.SHT_SYMTAB, es.SHT_DYNSYM) or tab["entsize"] != SYMENT:
        return names
    strtab = _strtab_for(data, sections, tab["link"])
    for j in range(tab["size"] // SYMENT):
        (st_name,) = struct.unpack_from("<I", data, tab["offset"] + j * SYMENT)
        names.append(es._cstring(strtab, st_name))
    return names


def _read_dynamic(data: bytes, sections: list[dict]) -> tuple[str | None, list[str]]:
    dyn = next((s for s in sections if s["type"] == SHT_DYNAMIC), None)
    if dyn is None or dyn["link"] >= len(sections):
        return None, []
    strtab = _strtab_for(data, sections, dyn["link"])
    soname: str | None = None
    needed: list[str] = []
    for j in range(dyn["size"] // 16):
        (d_tag, d_val) = struct.unpack_from("<qQ", data, dyn["offset"] + j * 16)
        if d_tag == 1:  # DT_NEEDED
            needed.append(es._cstring(strtab, d_val))
        elif d_tag == 14:  # DT_SONAME
            soname = es._cstring(strtab, d_val)
    return soname, sorted(set(needed))


def _read_versions(data: bytes, sections: list[dict]) -> tuple[dict[str, str], list[str]]:
    """`(symbol name -> version, sorted OPENSSL_* version-definition nodes)`."""
    dynsym = next((s for s in sections if s["type"] == es.SHT_DYNSYM), None)
    versym = next((s for s in sections if s["type"] == SHT_GNU_VERSYM), None)
    if dynsym is None or versym is None:
        return {}, []
    idxmap: dict[int, str] = {}
    defined_nodes: set[str] = set()
    verdef = next((s for s in sections if s["type"] == SHT_GNU_VERDEF), None)
    if verdef is not None and verdef["link"] < len(sections):
        strtab = _strtab_for(data, sections, verdef["link"])
        o = 0
        while o < verdef["size"]:
            base = verdef["offset"] + o
            (_vd_version, _vd_flags, vd_ndx, _vd_cnt, _vd_hash, vd_aux, vd_next) = \
                struct.unpack_from("<HHHHIII", data, base)
            (vda_name,) = struct.unpack_from("<I", data, base + vd_aux)
            name = es._cstring(strtab, vda_name)
            if vd_ndx >= 2:
                idxmap[vd_ndx] = name
                defined_nodes.add(name)
            if vd_next == 0:
                break
            o += vd_next
    verneed = next((s for s in sections if s["type"] == SHT_GNU_VERNEED), None)
    if verneed is not None and verneed["link"] < len(sections):
        strtab = _strtab_for(data, sections, verneed["link"])
        o = 0
        while o < verneed["size"]:
            base = verneed["offset"] + o
            (_vn_version, vn_cnt, _vn_file, vn_aux, vn_next) = \
                struct.unpack_from("<HHIII", data, base)
            aoff = base + vn_aux
            for _ in range(vn_cnt):
                (_vna_hash, _vna_flags, vna_other, vna_name, vna_next) = \
                    struct.unpack_from("<IHHII", data, aoff)
                idxmap[vna_other & 0x7FFF] = es._cstring(strtab, vna_name)
                if vna_next == 0:
                    break
                aoff += vna_next
            if vn_next == 0:
                break
            o += vn_next
    namever: dict[str, str] = {}
    strtab = _strtab_for(data, sections, dynsym["link"])
    for i in range(dynsym["size"] // SYMENT):
        if i * 2 + 2 > versym["size"]:
            break
        (vi,) = struct.unpack_from("<H", data, versym["offset"] + i * 2)
        if vi < 2 or vi not in idxmap:
            continue
        (st_name,) = struct.unpack_from("<I", data, dynsym["offset"] + i * SYMENT)
        name = es._cstring(strtab, st_name)
        if name:
            namever[name] = idxmap[vi]
    nodes = sorted(n for n in defined_nodes if n.startswith("OPENSSL_"))
    return namever, nodes


def read_object(data: bytes) -> dict:
    """Parse one ELF64 object into this plane's raw model fields."""
    sections = read_sections(data)
    symtab = [s for s in sections if s["type"] == es.SHT_SYMTAB]
    dynsym = [s for s in sections if s["type"] == es.SHT_DYNSYM]
    namever, versions_defined = _read_versions(data, sections)
    # Defined symbols come from `.symtab` when it survives (it keeps the *static* functions, which
    # are exactly the surface a public-header atlas cannot see); undefined symbols come from
    # `.dynsym`, because a linked DSO's `.symtab` does not carry its imports.
    defined = _read_symlist(data, sections, symtab or dynsym, True, namever)
    undefined = _read_symlist(data, sections, dynsym or symtab, False, namever)
    relocations, raw_relocs = _read_relocations(data, sections)
    soname, dt_needed = _read_dynamic(data, sections)
    interest = {}
    for s in sections:
        if s["sname"] in INTEREST_SECTIONS:
            interest[s["sname"]] = {"type": s["type"], "flags": _flags_str(s["flags"]),
                                    "size": s["size"], "entsize": s["entsize"]}
    return {
        "symbols": defined + undefined,
        "relocations": relocations,
        "sections": interest,
        "soname": soname,
        "dt_needed": dt_needed,
        "versions_defined": versions_defined,
        "raw_relocations": raw_relocs,
    }


# ---------------------------------------------------------------------------
# ar reading (with long-name resolution, which `elf_symbols` does not do)
# ---------------------------------------------------------------------------

def ar_members(data: bytes) -> list[tuple[str, bytes]]:
    """`(member_name, payload)` for every object member of a GNU `ar` archive."""
    if not data.startswith(es.AR_MAGIC):
        raise es.ElfError("not an ar archive")
    raw: list[tuple[str, bytes]] = []
    longnames: bytes | None = None
    off = len(es.AR_MAGIC)
    while off < len(data):
        if off + 60 > len(data):
            raise es.ElfError("truncated ar header")
        header = data[off:off + 60]
        if header[58:60] != b"\x60\n":
            raise es.ElfError("bad ar member magic")
        raw_size = header[48:58].decode("ascii", "replace").strip()
        try:
            size = int(raw_size)
        except ValueError as exc:
            raise es.ElfError(f"malformed ar member size {raw_size!r}") from exc
        body = data[off + 60:off + 60 + size]
        if len(body) != size:
            raise es.ElfError("truncated ar member")
        name = header[0:16].decode("latin1")
        off += 60 + size + (size & 1)
        if name.rstrip() == "//":
            longnames = body
            continue
        raw.append((name, body))
    out: list[tuple[str, bytes]] = []
    for name_field, body in raw:
        if name_field.rstrip() in ("/", "/SYM64/"):
            continue
        name = name_field.rstrip()
        if name.startswith("/") and longnames is not None:
            try:
                idx = int(name[1:].split("/")[0])
            except ValueError:
                idx = -1
            if 0 <= idx < len(longnames):
                end = longnames.find(b"\n", idx)
                if end < 0:
                    end = len(longnames)
                name = longnames[idx:end].decode("utf-8", "replace").strip().rstrip("/")
        elif name.endswith("/"):
            name = name[:-1]
        out.append((name, body))
    return out


# ---------------------------------------------------------------------------
# the pure classifier / resolver
# ---------------------------------------------------------------------------

ARTIFACT_RAW_KEYS = ("path", "sha256", "kind", "role", "format")


def derive_body(model: dict, meta: dict) -> dict:
    """The whole artefact body, as a pure function of the extracted model.

    `model` is `{"artifacts": [...], "objects": [...]}` where every object carries its raw
    `symbols` and `relocations` and nothing derived. Everything a reader consumes -- the
    per-object classified symbol lists, the aliases, the resolution of each relocation edge to the
    object that defines its symbol, the per-artefact membership, and every count -- is computed
    here. The sensitivity court mutates `model` and re-derives, which is only meaningful because
    this function holds no state between calls.
    """
    objects = sorted(model["objects"], key=lambda o: o["id"])
    artifacts = sorted(model["artifacts"], key=lambda a: a["path"])

    # The definition index: symbol name -> the sorted ids of every object that defines it with
    # *link* binding. Only global/weak/unique definitions can satisfy a reference from another
    # object, and only they are indexed: a `static` name such as `init` is file-local and is
    # defined in hundreds of objects, so indexing locals here would make a single reference
    # "resolve" to every file that happens to reuse the name. A reference to a local symbol is
    # resolved to its own object instead, below.
    definitions: dict[str, set[str]] = {}
    object_defines: dict[str, set[str]] = {}
    for obj in objects:
        names = object_defines.setdefault(obj["id"], set())
        for sym in obj["symbols"]:
            if sym["section"] is None:
                continue
            names.add(sym["name"])
            if sym["binding"] in ("global", "weak", "unique"):
                definitions.setdefault(sym["name"], set()).add(obj["id"])

    out_objects: list[dict] = []
    counts = {
        "artifacts": len(artifacts), "objects": len(objects), "defined": 0, "undefined": 0,
        "defined_global": 0, "defined_local": 0, "defined_weak": 0, "tls": 0, "aliases": 0,
        "relocation_edges": 0, "resolved_edges": 0, "archive_members": 0, "perlasm_objects": 0,
        "versioned_symbols": 0, "dt_needed": 0, "objects_with_relocations": 0,
    }
    per_artifact: dict[str, dict] = {a["path"]: {"members": [], "counts": {
        "objects": 0, "defined": 0, "undefined": 0, "relocation_edges": 0, "resolved_edges": 0,
        "tls": 0, "aliases": 0}} for a in artifacts}

    for obj in objects:
        defined = [s for s in obj["symbols"] if s["section"] is not None]
        undefined = [s for s in obj["symbols"] if s["section"] is None]

        alias_groups: dict[tuple, set[str]] = {}
        for s in defined:
            if s["value"]:
                alias_groups.setdefault((s["section"], s["value"], s["type"]), set()).add(s["name"])
        aliases = sorted(sorted(names) for names in alias_groups.values() if len(names) > 1)

        tls = sorted(s["name"] for s in defined if s["type"] == "TLS")

        relocs = []
        src_defines = object_defines[obj["id"]]
        for r in obj["relocations"]:
            resolvers = sorted(definitions.get(r["symbol"], ()))
            if not resolvers and r["symbol"] in src_defines:
                # A relocation against a file-local symbol is satisfied by the object that
                # issues it, which is the only object the linker lets define it.
                resolvers = [obj["id"]]
            relocs.append({"kind": "RELOCATION_REFERENCE", "symbol": r["symbol"],
                           "types": sorted(r["types"]), "resolved_to": resolvers})
        relocs.sort(key=lambda e: e["symbol"])
        resolved = sum(1 for e in relocs if e["resolved_to"])

        out = {
            "id": obj["id"], "artifact": obj["artifact"], "member": obj["member"],
            "source": obj["source"], "source_kind": obj["source_kind"],
            "defined": defined, "undefined": undefined, "tls": tls, "aliases": aliases,
            "relocations": relocs,
            "sections": obj["sections"], "soname": obj["soname"], "dt_needed": obj["dt_needed"],
            "versions_defined": obj["versions_defined"],
        }
        out_objects.append(out)

        counts["defined"] += len(defined)
        counts["undefined"] += len(undefined)
        counts["defined_global"] += sum(1 for s in defined if s["binding"] == "global")
        counts["defined_local"] += sum(1 for s in defined if s["binding"] == "local")
        counts["defined_weak"] += sum(1 for s in defined if s["binding"] == "weak")
        counts["tls"] += len(tls)
        counts["aliases"] += len(aliases)
        counts["relocation_edges"] += len(relocs)
        counts["resolved_edges"] += resolved
        if relocs:
            counts["objects_with_relocations"] += 1
        counts["versioned_symbols"] += sum(1 for s in defined + undefined if "version" in s)
        if obj["source_kind"] == "asm":
            counts["perlasm_objects"] += 1
        if obj["member"] is not None:
            counts["archive_members"] += 1

        agg = per_artifact.get(obj["artifact"])
        if agg is not None:
            agg["counts"]["objects"] += 1
            agg["counts"]["defined"] += len(defined)
            agg["counts"]["undefined"] += len(undefined)
            agg["counts"]["relocation_edges"] += len(relocs)
            agg["counts"]["resolved_edges"] += resolved
            agg["counts"]["tls"] += len(tls)
            agg["counts"]["aliases"] += len(aliases)
            if obj["member"] is not None:
                agg["members"].append(obj["id"])

    counts["dt_needed"] = sum(len(o["dt_needed"]) for o in out_objects)

    out_artifacts = []
    for a in artifacts:
        agg = per_artifact[a["path"]]
        rec = {k: a[k] for k in ARTIFACT_RAW_KEYS}
        rec["members"] = sorted(agg["members"])
        rec["member_count"] = len(agg["members"])
        rec["counts"] = agg["counts"]
        out_artifacts.append(rec)

    body = dict(meta)
    body["edge_kinds"] = ["RELOCATION_REFERENCE"]
    body["artifacts"] = out_artifacts
    body["objects"] = out_objects
    body["definitions"] = {k: sorted(v) for k, v in sorted(definitions.items())}
    body["counts"] = counts
    return body


def model_from_body(body: dict) -> dict:
    """Rebuild the raw model from a derived body, so the court can re-derive and compare.

    Only the raw facts are taken back: a defined symbol's section/value/size and an undefined
    symbol's lack of one, and a relocation's symbol and types without its `resolved_to`. Every
    classified field (`defined`/`undefined`/`tls`/`aliases`/resolution) is discarded and must be
    reproduced by `derive_body`.
    """
    objects = []
    for o in body["objects"]:
        symbols = []
        for d in o["defined"]:
            rec = {"name": d["name"], "binding": d["binding"], "type": d["type"],
                   "section": d["section"], "value": d["value"], "size": d["size"]}
            if "version" in d:
                rec["version"] = d["version"]
            symbols.append(rec)
        for u in o["undefined"]:
            rec = {"name": u["name"], "binding": u["binding"], "type": u["type"],
                   "section": None, "value": 0, "size": 0}
            if "version" in u:
                rec["version"] = u["version"]
            symbols.append(rec)
        relocations = [{"symbol": r["symbol"], "types": list(r["types"])}
                       for r in o["relocations"]]
        objects.append({
            "id": o["id"], "artifact": o["artifact"], "member": o["member"],
            "source": o["source"], "source_kind": o["source_kind"],
            "symbols": symbols, "relocations": relocations, "sections": o["sections"],
            "soname": o["soname"], "dt_needed": o["dt_needed"],
            "versions_defined": o["versions_defined"],
        })
    artifacts = [{k: a[k] for k in ARTIFACT_RAW_KEYS} for a in body["artifacts"]]
    return {"artifacts": artifacts, "objects": objects}


META_KEYS = ("build_dir", "producer", "profile", "toolchain", "reading", "compile_commands",
             "reduction", "relocation_type_names")


def meta_from_body(body: dict) -> dict:
    return {k: body[k] for k in META_KEYS if k in body}


# ---------------------------------------------------------------------------
# collection from the pinned build
# ---------------------------------------------------------------------------

# (relative path under the build dir, kind, role). Providers and engines are discovered by glob,
# so "every provider module the authority built" is a property of the tree rather than a list.
FIXED_ARTIFACTS = (
    ("libcrypto.so.3", "shared-object", "libcrypto"),
    ("libssl.so.3", "shared-object", "libssl"),
    ("libcrypto.a", "static-archive", "libcrypto"),
    ("libssl.a", "static-archive", "libssl"),
    ("apps/openssl", "executable", "app"),
)


def _artifact_specs(build_dir: Path) -> list[tuple[str, str, str]]:
    specs = list(FIXED_ARTIFACTS)
    for relp in sorted(p.name for p in (build_dir / "providers").glob("*.so")):
        specs.append((f"providers/{relp}", "provider-module", "provider"))
    for relp in sorted(p.name for p in (build_dir / "engines").glob("*.so")):
        specs.append((f"engines/{relp}", "engine-module", "engine"))
    return specs


def _source_map(compile_commands: Path | None) -> dict[str, tuple[str, str]]:
    """Output basename -> (source path, 'asm'|'c'), from 22.1's captured commands."""
    if compile_commands is None or not compile_commands.is_file():
        return {}
    doc = json.loads(compile_commands.read_text(encoding="utf-8"))
    out: dict[str, tuple[str, str]] = {}
    for cmd in doc.get("body", {}).get("commands", []):
        src = cmd.get("source") or ""
        out_name = (cmd.get("output") or "").rsplit("/", 1)[-1]
        if not out_name or not src:
            continue
        kind = "asm" if src.endswith((".s", ".S")) else "c"
        # A basename collision would make the join ambiguous; keep the first in sorted source
        # order and never overwrite, so the map is a function of the file set.
        out.setdefault(out_name, (src, kind))
    return out


def collect_model(build_dir: Path, compile_commands: Path | None) -> dict:
    """Parse every artefact the authority built into the raw model."""
    src_map = _source_map(compile_commands)
    artifacts: list[dict] = []
    objects: list[dict] = []
    raw_reloc_total = 0
    for relp, kind, role in _artifact_specs(build_dir):
        path = build_dir / relp
        data = path.read_bytes()
        repo_rel = rel(path)
        fmt = "ar" if data.startswith(es.AR_MAGIC) else "elf"
        artifacts.append({"path": repo_rel, "sha256": sha256_file(path), "kind": kind,
                          "role": role, "format": fmt})
        if fmt == "ar":
            for member_name, payload in ar_members(data):
                src, skind = src_map.get(member_name, (None, None))
                parsed = read_object(payload)
                raw_reloc_total += parsed.pop("raw_relocations")
                objects.append({
                    "id": f"{repo_rel}({member_name})", "artifact": repo_rel,
                    "member": member_name, "source": src, "source_kind": skind, **parsed})
        else:
            parsed = read_object(data)
            raw_reloc_total += parsed.pop("raw_relocations")
            objects.append({
                "id": repo_rel, "artifact": repo_rel, "member": None,
                "source": None, "source_kind": None, **parsed})
    model: dict = {"artifacts": artifacts, "objects": objects}
    model["raw_relocations"] = raw_reloc_total
    return model


def build_meta(auth, build_dir: Path, compile_commands: Path | None,
               raw_relocations: int) -> dict:
    from atlas_common import load_build_records
    record = load_build_records().get(auth.id, {})
    producer = "unknown"
    configdata = build_dir / "configdata.pm"
    if configdata.is_file():
        producer = pbc.read_producer(configdata)
    return {
        "build_dir": rel(build_dir),
        "producer": producer,
        "profile": record.get("profile"),
        "toolchain": record.get("build_toolchain", {}).get("cc"),
        "reading": (
            "pure-python ELF64/ar reader (forensics/tools/elf_symbols.py constants and string "
            "helper reused); binutils is never invoked, because its LLVM-bitcode plugin makes the "
            "same archive yield different symbol sets on different machines (D30, D33)"
        ),
        "compile_commands": rel(compile_commands) if compile_commands and \
            compile_commands.is_file() else None,
        "relocation_type_names": "x86-64 psABI subset; unknown types are R_X86_64_UNKNOWN_0x<hex>",
        "reduction": {
            "relocation_edges": (
                f"collapsed from {raw_relocations} raw relocation entries that name a symbol to "
                "one RELOCATION_REFERENCE edge per (object, symbol), carrying the sorted set of "
                "relocation types seen; the per-entry offset and addend are not retained, and "
                "entries with symbol index 0 (R_X86_64_RELATIVE and friends) are not "
                "relocation->symbol edges and are excluded from both numbers"
            ),
            "sections": (
                "only the named sections in INTEREST_SECTIONS are recorded, with size and flags; "
                "section contents are never inlined"
            ),
            "dsos": (
                "a DSO/executable is one object: per-translation-unit perlasm provenance is "
                "resolvable for archive members (joined against 22.1's compile-commands.json) but "
                "not for the linked shared objects, whose inputs are not enumerated here"
            ),
        },
    }


# ---------------------------------------------------------------------------
# the court
# ---------------------------------------------------------------------------

def _model_for_court(body: dict) -> dict:
    return model_from_body(body)


def courts() -> list[dict]:
    """`RT-PHASE22-BINARY`: an FRF-style sensitivity challenge over `derive_body`.

    Driven over the committed artefact (round trip: reconstruct the raw model from the artefact's
    own rows and re-derive the whole body, requiring equality) and over controlled in-memory
    mutations of that model. It fails if the classifier/resolver is insensitive to any of:
    adding a defined symbol, adding an undefined symbol, adding a relocation that resolves,
    adding a relocation that does not, removing an archive member, flipping a linkage bit, or
    removing a definition that a live edge resolved to.
    """
    path = REPO_ROOT / ARTEFACT_REL
    if not path.is_file():
        return []
    doc = json.loads(path.read_text(encoding="utf-8"))
    committed = doc["body"]
    model = _model_for_court(committed)
    meta = meta_from_body(committed)

    checks: list[tuple[str, bool]] = []
    derived = derive_body(model, meta)

    base_counts = derived["counts"]
    checks.append(("baseline: the graph has objects and artefacts",
                   base_counts["objects"] > 0 and base_counts["artifacts"] > 0))
    checks.append(("baseline: relocation edges exist and some resolve",
                   base_counts["relocation_edges"] > 0 and base_counts["resolved_edges"] > 0))
    # Round trip: the artefact must be exactly what this logic derives from its own model.
    checks.append(("round-trip: re-deriving the committed body from its own model reproduces it",
                   derived == committed))

    def fresh() -> dict:
        return json.loads(json.dumps(model))

    def first_object(m: dict) -> dict:
        return m["objects"][0]

    # -- add a defined symbol -------------------------------------------------------------------
    m = fresh()
    obj = first_object(m)
    obj["symbols"].append({"name": "__phase22_probe_defined", "binding": "global", "type": "FUNC",
                           "section": ".text", "value": 0x7FFFFFF0, "size": 16})
    d = derive_body(m, meta)
    checks.append(("mutation add-defined-symbol: `defined` rises by exactly one",
                   d["counts"]["defined"] == base_counts["defined"] + 1))
    checks.append(("mutation add-defined-symbol: the definition index gains the name",
                   d["definitions"].get("__phase22_probe_defined") == [obj["id"]]))
    checks.append(("mutation add-defined-symbol: `defined_global` follows",
                   d["counts"]["defined_global"] == base_counts["defined_global"] + 1))

    # -- add an undefined symbol ----------------------------------------------------------------
    m = fresh()
    obj = first_object(m)
    obj["symbols"].append({"name": "__phase22_probe_undefined", "binding": "global", "type": "FUNC",
                           "section": None, "value": 0, "size": 0})
    d = derive_body(m, meta)
    checks.append(("mutation add-undefined-symbol: `undefined` rises by exactly one",
                   d["counts"]["undefined"] == base_counts["undefined"] + 1))
    checks.append(("mutation add-undefined-symbol: the definition index does not gain it",
                   "__phase22_probe_undefined" not in d["definitions"]))

    # -- add a relocation that resolves -----------------------------------------------------------
    m = fresh()
    global_defs = sorted(derived["definitions"])
    checks.append(("add-resolved-edge: a global definition exists to reference", bool(global_defs)))
    if global_defs:
        defined_target = global_defs[0]
        obj = next(o for o in m["objects"]
                   if defined_target not in {r["symbol"] for r in o["relocations"]})
        obj["relocations"].append({"symbol": defined_target, "types": ["R_X86_64_PLT32"]})
        d = derive_body(m, meta)
        edge = next((e for o in d["objects"] for e in o["relocations"]
                     if e["symbol"] == defined_target and o["id"] == obj["id"]
                     and e["types"] == ["R_X86_64_PLT32"]), None)
        checks.append(("mutation add-resolved-edge: the edge exists and resolves",
                       edge is not None
                       and edge["resolved_to"] == derived["definitions"][defined_target]))
        checks.append(("mutation add-resolved-edge: `relocation_edges` and `resolved_edges` both rise",
                       d["counts"]["relocation_edges"] == base_counts["relocation_edges"] + 1
                       and d["counts"]["resolved_edges"] == base_counts["resolved_edges"] + 1))

    # -- add a relocation that does not resolve ---------------------------------------------------
    m = fresh()
    obj = first_object(m)
    missing = "__phase22_probe_missing_symbol__"
    obj["relocations"].append({"symbol": missing, "types": ["R_X86_64_PC32"]})
    d = derive_body(m, meta)
    edge = next((e for o in d["objects"] for e in o["relocations"]
                 if e["symbol"] == missing and o["id"] == obj["id"]), None)
    checks.append(("mutation add-unresolved-edge: the edge exists but resolves to nothing",
                   edge is not None and edge["resolved_to"] == []))
    checks.append((("mutation add-unresolved-edge: `relocation_edges` rises by one and "
                    "`resolved_edges` does not move"),
                   d["counts"]["relocation_edges"] == base_counts["relocation_edges"] + 1
                   and d["counts"]["resolved_edges"] == base_counts["resolved_edges"]))

    # -- remove an archive member -----------------------------------------------------------------
    m = fresh()
    victim = next(o for o in m["objects"] if o["member"] is not None)
    victim_def = sum(1 for s in victim["symbols"] if s["section"] is not None)
    victim_art = victim["artifact"]
    m["objects"] = [o for o in m["objects"] if o["id"] != victim["id"]]
    d = derive_body(m, meta)
    art = next(a for a in d["artifacts"] if a["path"] == victim_art)
    checks.append(("mutation remove-archive-member: `objects` and `archive_members` fall by one",
                   d["counts"]["objects"] == base_counts["objects"] - 1
                   and d["counts"]["archive_members"] == base_counts["archive_members"] - 1))
    checks.append(("mutation remove-archive-member: the artefact loses the member",
                   victim["id"] not in art["members"] and art["member_count"] == len(art["members"])))
    checks.append(("mutation remove-archive-member: `defined` falls by the member's own count",
                   d["counts"]["defined"] == base_counts["defined"] - victim_def))

    # -- flip a linkage bit -----------------------------------------------------------------------
    m = fresh()
    obj = next(o for o in m["objects"]
               if any(s["section"] is not None and s["binding"] == "global" for s in o["symbols"]))
    sym = next(s for s in obj["symbols"]
               if s["section"] is not None and s["binding"] == "global")
    sym["binding"] = "local"
    d = derive_body(m, meta)
    checks.append(("mutation flip-linkage: `defined_global` falls and `defined_local` rises",
                   d["counts"]["defined_global"] == base_counts["defined_global"] - 1
                   and d["counts"]["defined_local"] == base_counts["defined_local"] + 1))
    checks.append(("mutation flip-linkage: the total `defined` does not move",
                   d["counts"]["defined"] == base_counts["defined"]))

    # -- remove a definition a live edge resolved to ----------------------------------------------
    m = fresh()
    single_definer = {n for n, ids in derived["definitions"].items() if len(ids) == 1}
    referenced = sorted(
        {e["symbol"] for o in m["objects"] for e in o["relocations"]
         if e["symbol"] in single_definer})
    checks.append(("remove-definition: a referenced symbol has a single definer to remove",
                   bool(referenced)))
    if referenced:
        target = referenced[0]
        affected = sum(1 for o in m["objects"] for e in o["relocations"]
                       if e["symbol"] == target)
        for o in m["objects"]:
            o["symbols"] = [s for s in o["symbols"]
                            if not (s["name"] == target and s["section"] is not None)]
        d = derive_body(m, meta)
        checks.append(("remove-definition: the name leaves the definition index",
                       target not in d["definitions"]))
        checks.append(("remove-definition: exactly its live edges stop resolving",
                       d["counts"]["resolved_edges"] == base_counts["resolved_edges"] - affected))

    failures = [desc for desc, ok in checks if not ok]
    return [{
        "court": COURT,
        "artefact": ARTEFACT_REL,
        "artefacts": base_counts["artifacts"],
        "objects": base_counts["objects"],
        "relocation_edges": base_counts["relocation_edges"],
        "resolved_edges": base_counts["resolved_edges"],
        "archive_members": base_counts["archive_members"],
        "perlasm_objects": base_counts["perlasm_objects"],
        "mutations": ["round-trip", "add-defined-symbol", "add-undefined-symbol",
                      "add-resolved-edge", "add-unresolved-edge", "remove-archive-member",
                      "flip-linkage", "remove-definition"],
        "summary": (f"{base_counts['objects']} objects, {base_counts['defined']} defined, "
                    f"{base_counts['relocation_edges']} relocation edges "
                    f"({base_counts['resolved_edges']} resolved)"),
        "observations": len(checks),
        "failures": failures,
        "verdict": "pass" if not failures else "fail",
    }]


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    args = ap.parse_args(argv)

    auth = resolve_authority(args.authority)
    build_dir = authority_build_dir(auth.id)
    if not build_dir.is_dir():
        raise SystemExit(f"phase22-binary-graph: build dir missing: {build_dir}")
    compile_commands = REPO_ROOT / pbc.OUT_REL
    if not compile_commands.is_file():
        compile_commands = None

    model = collect_model(build_dir, compile_commands)
    meta = build_meta(auth, build_dir, compile_commands, model["raw_relocations"])
    body = derive_body({"artifacts": model["artifacts"], "objects": model["objects"]}, meta)

    inputs = [InputRef(name=f"built-artefact:{a['role']}:{Path(a['path']).name}",
                       path=REPO_ROOT / a["path"]) for a in body["artifacts"]]
    if compile_commands is not None:
        inputs.append(InputRef(name="compile-commands", path=compile_commands))
    doc = envelope(kind="phase22-binary-reference-graph", authority=auth.id, inputs=inputs,
                   body=body, generator=GENERATOR)
    write_json(REPO_ROOT / ARTEFACT_REL, doc)

    c = body["counts"]
    print(f"[phase22-binary-graph] producer={body['producer']!r} "
          f"reading=pure-python")
    print(f"  artifacts={c['artifacts']} objects={c['objects']} archive_members={c['archive_members']} "
          f"perlasm_objects={c['perlasm_objects']}")
    print(f"  defined={c['defined']} (global={c['defined_global']} local={c['defined_local']} "
          f"weak={c['defined_weak']}) undefined={c['undefined']} tls={c['tls']} aliases={c['aliases']}")
    print(f"  relocation_edges={c['relocation_edges']} resolved_edges={c['resolved_edges']} "
          f"versioned_symbols={c['versioned_symbols']} dt_needed={c['dt_needed']}")
    print(f"  -> {rel(REPO_ROOT / ARTEFACT_REL)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
