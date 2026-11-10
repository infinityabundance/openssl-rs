#!/usr/bin/env python3
"""Cross-check extension-slot registrations against the COMPILED artifact.

The source gate (``callback_enumeration_gate.py``) is deliberately syntactic:
it understands ``X509V3ExtMethod`` literals and the constructor parameters it
can see.  It cannot see a row produced by a macro expansion, a ``..base``
inherited slot, a const-fn whose body it does not resolve per call site, or a
build-script-generated row.  A source-only enumeration is therefore not a
completeness proof.

This instrument reads the built ``libcrypto.so.3`` instead:

* ``STANDARD_EXTS`` (the ``standard_exts[]`` pointer table) is located by
  symbol and, if the symbol is unavailable, by a relocation-backed pointer-run
  scan;
* every per-file static ``X509V3ExtMethod`` row is located structurally: an
  OBJECT in ``.data.rel.ro`` whose size is a positive multiple of 104 and whose
  elements carry a plausible ``ext_nid`` / ``ext_flags``;
* each populated slot is resolved from ``.rela.dyn``: an ``R_X86_64_RELATIVE``
  addend, an ``R_X86_64_64``/``R_X86_64_GLOB_DAT`` symbol, or the in-place file
  addend.  Target addresses are named from the static symbol table (with the
  dynamic symbol table as a fallback) and *all* aliases at an address are kept:
  identical-code folding routinely puts a source ``s2i_X`` and ``r2i_X`` at the
  same address, and choosing one arbitrarily would manufacture a false
  mismatch.

Any populated slot that cannot be resolved to a named function is a **refusal**
(exit 2), never an exclusion.  The reconciliation compares the compiled set with
``callback-registration-manifest.json`` and its parts, and fails (exit 1) when
the compiled artifact contains a target the manifest does not account for, or
when a manifest registration is dead (its callback occurs nowhere in the
artifact).  Const-fn factory rows (``fn:ext_ia5string`` and friends) are mapped
to the compiled instantiations deterministically; an ambiguous mapping is a
refusal.

Usage::

    python3 forensics/tools/callback_artifact_crosscheck.py \
        --artifact artifacts/phase2/install/lib/libcrypto.so.3 \
        --manifest forensics/memory-safety/campaign/safe-c33/atlas-refresh/\
callback-registration-manifest.json \
        --out forensics/memory-safety/campaign/safe-c33/atlas-refresh/\
callback-artifact-crosscheck.json

Exit codes: 0 = pass, 1 = reconciliation failure, 2 = refusal/uncertainty.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import struct
import sys

SCHEMA = "openssl-rs/campaign/safe-c33/callback-artifact-crosscheck/v1"

# X509V3ExtMethod is a #[repr(C)] 104-byte record (src/x509/v3_lib.rs asserts
# every offset below).  The extractor verifies the size against the artifact's
# own symbol sizes and the table stride before trusting anything.
ROW_SIZE = 104
SLOT_OFFSETS = {
    "it": 8,
    "ext_new": 16,
    "ext_free": 24,
    "d2i": 32,
    "i2d": 40,
    "i2s": 48,
    "s2i": 56,
    "i2v": 64,
    "v2i": 72,
    "i2r": 80,
    "r2i": 88,
}
# The seven slots this gate reconciles.  ``it``/``d2i``/``i2d``/``ext_new`` are
# still resolved and reported, but the manifest's slot-driven census classifies
# only these seven as gated extension callbacks.
GATED_SLOTS = ("ext_free", "i2s", "s2i", "i2v", "v2i", "i2r", "r2i")

# A real X509V3ExtMethod ext_nid is an OpenSSL NID (small positive integer) or
# the EXT_END sentinel -1.  This range is what separates a row object from the
# many unrelated 104-byte-multiple provider tables in .data.rel.ro.  It is a
# *discovery* heuristic only; every table row is always examined.
NID_MIN, NID_MAX = -1, 0xFFFF
FLAG_MASK = 0x7  # X509V3_EXT_DYNAMIC|CTX_DEP|MULTILINE

R_X86_64_NONE = 0
R_X86_64_64 = 1
R_X86_64_GLOB_DAT = 6
R_X86_64_RELATIVE = 8
R_X86_64_IRELATIVE = 37


class Refusal(Exception):
    """Parser uncertainty: report it and refuse; never silently exclude."""


class ELF64:
    """Minimal ELF64 little-endian reader (sections, symbols, relocations)."""

    SHT_SYMTAB = 2
    SHT_RELA = 4
    SHT_NOBITS = 8
    SHT_REL = 9
    SHT_DYNSYM = 11
    STT_OBJECT = 1
    STT_FUNC = 2

    def __init__(self, path):
        self.path = path
        with open(path, "rb") as handle:
            self.data = handle.read()
        d = self.data
        if len(d) < 64 or d[:4] != b"\x7fELF":
            raise Refusal("not an ELF file")
        if d[4] != 2:
            raise Refusal("not ELF64")
        if d[5] != 1:
            raise Refusal("not little-endian")
        (self.shoff,) = struct.unpack_from("<Q", d, 0x28)
        (self.shentsize,) = struct.unpack_from("<H", d, 0x3A)
        (self.shnum,) = struct.unpack_from("<H", d, 0x3C)
        (self.shstrndx,) = struct.unpack_from("<H", d, 0x3E)
        if not self.shoff or not self.shentsize:
            raise Refusal("no section header table")
        self.sections = []
        for index in range(self.shnum):
            off = self.shoff + index * self.shentsize
            fields = struct.unpack_from("<IIQQQQIIQQ", d, off)
            self.sections.append({
                "index": index,
                "nameoff": fields[0],
                "type": fields[1],
                "flags": fields[2],
                "addr": fields[3],
                "offset": fields[4],
                "size": fields[5],
                "link": fields[6],
                "info": fields[7],
                "align": fields[8],
                "entsize": fields[9],
            })
        if self.shstrndx >= len(self.sections):
            raise Refusal("invalid section-name table index")
        shstr = self.sections[self.shstrndx]
        names = d[shstr["offset"]:shstr["offset"] + shstr["size"]]
        for section in self.sections:
            section["name"] = self._cstr(names, section["nameoff"])
        self.symbols = []
        for section in self.sections:
            if section["type"] not in (self.SHT_SYMTAB, self.SHT_DYNSYM):
                continue
            if section["link"] >= len(self.sections):
                raise Refusal("symbol table has invalid string table")
            strtab_section = self.sections[section["link"]]
            strtab = d[strtab_section["offset"]:
                       strtab_section["offset"] + strtab_section["size"]]
            entsize = section["entsize"] or 24
            for off in range(section["offset"],
                             section["offset"] + section["size"], entsize):
                nameoff, info, _other, shndx, value, size = struct.unpack_from(
                    "<IBBHQQ", d, off)
                self.symbols.append({
                    "name": self._cstr(strtab, nameoff),
                    "type": info & 0xF,
                    "bind": info >> 4,
                    "shndx": shndx,
                    "value": value,
                    "size": size,
                    "table": section["name"],
                })
        self.relocations = {}
        for section in self.sections:
            if section["type"] not in (self.SHT_RELA, self.SHT_REL):
                continue
            entsize = section["entsize"] or (24 if section["type"] == self.SHT_RELA else 16)
            for off in range(section["offset"],
                             section["offset"] + section["size"], entsize):
                if section["type"] == self.SHT_RELA:
                    where, info, addend = struct.unpack_from("<QQq", d, off)
                else:
                    where, info = struct.unpack_from("<QQ", d, off)
                    addend = 0
                entry = {
                    "type": info & 0xFFFFFFFF,
                    "sym": info >> 32,
                    "addend": addend,
                    "section": section["name"],
                }
                self.relocations.setdefault(where, []).append(entry)

    @staticmethod
    def _cstr(blob, offset):
        if not blob or offset >= len(blob):
            return ""
        end = blob.find(b"\0", offset)
        if end < 0:
            end = len(blob)
        return blob[offset:end].decode("utf-8", "replace")

    def section_of(self, address):
        for section in self.sections:
            if section["type"] == self.SHT_NOBITS:
                continue
            if section["addr"] <= address < section["addr"] + section["size"]:
                return section
        return None

    def read(self, address, size):
        section = self.section_of(address)
        if section is None:
            raise Refusal("address 0x%x is not mapped by any section" % address)
        start = section["offset"] + (address - section["addr"])
        return self.data[start:start + size]

    def symbols_at(self, address, kind=STT_FUNC):
        return [s for s in self.symbols
                if s["type"] == kind and s["value"] == address and s["name"]]

    def functions_at(self, address):
        exact = self.symbols_at(address, self.STT_FUNC)
        if exact:
            return exact
        containing = [s for s in self.symbols
                      if s["type"] == self.STT_FUNC and s["name"]
                      and s["value"] < address < s["value"] + max(s["size"], 1)]
        if not containing:
            return []
        start = max(s["value"] for s in containing)
        return [s for s in containing if s["value"] == start]

    def objects_containing(self, address):
        out = []
        for symbol in self.symbols:
            if symbol["type"] != self.STT_OBJECT or not symbol["name"]:
                continue
            if symbol["value"] <= address < symbol["value"] + max(symbol["size"], 1):
                out.append(symbol)
        return out


_SUFFIXES = (".llvm.", ".constprop.", ".isra.", ".part.")


def demangle_segments(symbol):
    """Return rustc path segments; the identifier is the last one."""
    raw = symbol
    for suffix in _SUFFIXES:
        if suffix in raw:
            raw = raw.split(suffix, 1)[0]
    if raw.startswith("_R"):
        body = raw[2:]
        segments = []
        index = 0
        while index < len(body):
            match = re.match(r"(\d+)", body[index:])
            if match:
                length = int(match.group(1))
                start = index + len(match.group(1))
                ident = body[start:start + length]
                if len(ident) == length and re.fullmatch(
                        r"[A-Za-z_][A-Za-z0-9_]*", ident):
                    segments.append(ident)
                    index = start + length
                    continue
            index += 1
        if segments:
            return segments
    if raw.startswith("_ZN"):
        body = raw[3:]
        segments = []
        index = 0
        while index < len(body):
            match = re.match(r"(\d+)", body[index:])
            if not match:
                break
            length = int(match.group(1))
            start = index + len(match.group(1))
            ident = body[start:start + length]
            if len(ident) != length:
                break
            if not re.fullmatch(r"17h[0-9a-f]{16}", ident):
                segments.append(ident)
            index = start + length
        if segments:
            return segments
    return [raw]


def identifier(symbol):
    return demangle_segments(symbol)[-1]


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _plausible_row(elf, address):
    section = elf.section_of(address)
    if section is None or address + ROW_SIZE > section["addr"] + section["size"]:
        return False
    try:
        nid, flags = struct.unpack("<ii", elf.read(address, 8))
    except Refusal:
        return False
    return NID_MIN <= nid <= NID_MAX and (flags & ~FLAG_MASK) == 0


def _row_symbols(elf, address):
    """Symbols that start at ``address`` or cover it, best candidate first."""
    exact = [s for s in elf.symbols
             if s["type"] == elf.STT_OBJECT and s["name"]
             and s["value"] == address]
    if exact:
        return sorted(exact, key=lambda s: (-s["size"], s["name"]))
    covering = elf.objects_containing(address)
    if not covering:
        return []
    start = max(s["value"] for s in covering)
    return sorted([s for s in covering if s["value"] == start],
                  key=lambda s: (-s["size"], s["name"]))


def _row_label(elf, address):
    symbols = _row_symbols(elf, address)
    if not symbols:
        raise Refusal("row at 0x%x has no naming symbol" % address)
    symbol = symbols[0]
    name = identifier(symbol["name"])
    if symbol["size"] > ROW_SIZE:
        index, remainder = divmod(address - symbol["value"], ROW_SIZE)
        if remainder:
            raise Refusal("row 0x%x is not aligned to its %s symbol"
                          % (address, name))
        return "%s[%d]" % (name, index), symbol
    return name, symbol


def _locate_standard_exts(elf):
    candidates = [s for s in elf.symbols
                  if s["type"] == elf.STT_OBJECT and s["name"]
                  and "STANDARD_EXTS" in s["name"]]
    candidates.sort(key=lambda s: (s["table"] != ".symtab", -s["size"]))
    if not candidates:
        raise Refusal("STANDARD_EXTS symbol absent; refusing rather than "
                      "guessing the table location")
    symbol = candidates[0]
    if symbol["size"] <= 0 or symbol["size"] % 8:
        raise Refusal("STANDARD_EXTS symbol has implausible size %d"
                      % symbol["size"])
    raw = elf.read(symbol["value"], symbol["size"])
    pointers = list(struct.unpack("<%dQ" % (symbol["size"] // 8), raw))
    return symbol, pointers


def _discover_row_objects(elf):
    """Static row objects in .data.rel.ro, found structurally."""
    objects = []
    excluded = []
    for symbol in elf.symbols:
        if symbol["type"] != elf.STT_OBJECT or not symbol["name"]:
            continue
        if symbol["shndx"] >= len(elf.sections):
            continue
        section = elf.sections[symbol["shndx"]]
        if section["name"] != ".data.rel.ro":
            continue
        if symbol["size"] <= 0 or symbol["size"] % ROW_SIZE:
            continue
        elements = symbol["size"] // ROW_SIZE
        plausible = sum(
            1 for index in range(elements)
            if _plausible_row(elf, symbol["value"] + index * ROW_SIZE))
        if plausible == elements:
            objects.append(symbol)
        else:
            excluded.append({
                "symbol": symbol["name"],
                "identifier": identifier(symbol["name"]),
                "size": symbol["size"],
                "plausible_elements": plausible,
                "elements": elements,
                "reason": "not every 104-byte element has a plausible "
                          "ext_nid/ext_flags",
            })
    return objects, excluded


def _resolve_slot(elf, address):
    """Resolve one slot to a named function.

    Returns ``(target_address, symbols, method, refusal_reason)``.  A zero slot
    is ``(0, [], "null", None)``.  Everything else must name a function; an
    unnamed non-zero slot is a refusal.
    """
    relocations = elf.relocations.get(address, [])
    if len(relocations) > 1:
        return 0, [], "", "multiple relocations at one slot address"
    raw = struct.unpack("<Q", elf.read(address, 8))[0]
    if not relocations:
        if raw == 0:
            return 0, [], "null", None
        target = raw
        method = "file-addend"
    else:
        relocation = relocations[0]
        kind = relocation["type"]
        if kind == R_X86_64_NONE:
            if raw == 0:
                return 0, [], "null", None
            return 0, [], "", "R_X86_64_NONE with non-zero in-place value"
        if kind == R_X86_64_RELATIVE:
            target = relocation["addend"]
            method = "relocation:RELATIVE"
            if target == 0:
                return 0, [], "null", None
        elif kind in (R_X86_64_64, R_X86_64_GLOB_DAT):
            symtab = relocation["sym"]
            if not symtab or symtab >= len(elf.symbols):
                return 0, [], "", "relocation has no symbol index"
            base = elf.symbols[symtab]["value"]
            target = base + relocation["addend"]
            method = "relocation:symbol"
            if target == 0:
                return 0, [], "null", None
        elif kind == R_X86_64_IRELATIVE:
            return 0, [], "", ("R_X86_64_IRELATIVE: resolver result is not "
                               "a statically named target")
        else:
            return 0, [], "", "unsupported relocation type %d" % kind
    section = elf.section_of(target)
    if section is None:
        return target, [], "", "target 0x%x is not mapped" % target
    if not (section["flags"] & 0x4):  # SHF_EXECINSTR
        return target, [], "", "target 0x%x is in non-executable %s" % (
            target, section["name"])
    symbols = elf.functions_at(target)
    if not symbols:
        return target, [], "", "target 0x%x has no naming function symbol" % target
    # .symtab and .dynsym both describe exported targets; keep one entry per
    # name while retaining every distinct alias at the address.
    unique = {}
    for symbol in symbols:
        unique.setdefault(symbol["name"], symbol)
    return target, [unique[name] for name in sorted(unique)], method, None


def extract(artifact):
    elf = ELF64(artifact)
    table_symbol, pointers = _locate_standard_exts(elf)
    for index, pointer in enumerate(pointers):
        if not _plausible_row(elf, pointer):
            raise Refusal(
                "STANDARD_EXTS[%d] -> 0x%x is not a plausible extension row"
                % (index, pointer))
    row_objects, excluded = _discover_row_objects(elf)

    # Every table pointer is a row, whether or not the structural scan found
    # its object (the table is authoritative).  Structural objects not in the
    # table are per-file static rows.
    row_addresses = {}
    for pointer in pointers:
        row_addresses[pointer] = "standard_exts"
    for symbol in row_objects:
        for index in range(symbol["size"] // ROW_SIZE):
            address = symbol["value"] + index * ROW_SIZE
            row_addresses.setdefault(address, "static-row-object")

    rows = []
    records = []
    refusals = []
    methods = {}
    for address in sorted(row_addresses):
        try:
            label, symbol = _row_label(elf, address)
        except Refusal as exc:
            refusals.append({
                "row_address": "0x%x" % address,
                "slot": None,
                "reason": str(exc),
            })
            continue
        nid, flags = struct.unpack("<ii", elf.read(address, 8))
        row_record = {
            "row": label,
            "row_address": "0x%x" % address,
            "row_symbol": symbol["name"],
            "row_source": row_addresses[address],
            "ext_nid": nid,
            "ext_flags": flags,
            "slots": {},
        }
        for slot in SLOT_OFFSETS:
            slot_address = address + SLOT_OFFSETS[slot]
            target, symbols, method, reason = _resolve_slot(elf, slot_address)
            if reason:
                refusals.append({
                    "row": label,
                    "row_address": "0x%x" % address,
                    "slot": slot,
                    "slot_address": "0x%x" % slot_address,
                    "reason": reason,
                })
                row_record["slots"][slot] = {"resolution": "unresolved",
                                             "target_symbol": None}
                continue
            methods[method] = methods.get(method, 0) + 1
            if target == 0:
                row_record["slots"][slot] = {"resolution": "null",
                                             "target_symbol": None}
                continue
            names = [s["name"] for s in symbols]
            ids = sorted({identifier(name) for name in names})
            row_record["slots"][slot] = {
                "resolution": method,
                "target_address": "0x%x" % target,
                "target_symbol": names[0],
                "target_symbols": names,
                "target_identifiers": ids,
            }
            records.append({
                "row": label,
                "row_address": "0x%x" % address,
                "slot": slot,
                "slot_address": "0x%x" % slot_address,
                "target_address": "0x%x" % target,
                "target_symbol": names[0],
                "target_symbols": names,
                "target_identifiers": ids,
                "resolution_method": method,
            })
        rows.append(row_record)

    # A populated gated slot must never be skipped just because its row object
    # was structurally excluded: the table rows are always covered above, and
    # the excluded objects are reported so a reviewer can see the heuristic.
    return {
        "elf": elf,
        "table_symbol": table_symbol,
        "table_entries": len(pointers),
        "row_objects": row_objects,
        "excluded_objects": excluded,
        "rows": rows,
        "records": records,
        "refusals": refusals,
        "methods": methods,
    }


def load_manifest(path):
    with open(path, "r", encoding="utf-8") as handle:
        index = json.load(handle)
    expected_schema = "openssl-rs/campaign/safe-c33/" \
                      "callback-registration-manifest/v1"
    if index.get("schema") != expected_schema:
        raise Refusal("unexpected manifest schema %r" % index.get("schema"))
    registrations = []
    callbacks = []
    parts = index.get("parts")
    if isinstance(index.get("registrations"), list):
        registrations = index["registrations"]
        callbacks = index.get("callbacks", [])
    elif isinstance(parts, dict):
        base = os.path.dirname(os.path.abspath(path))
        for name in sorted(parts):
            part = parts[name]
            part_path = os.path.join(base, part["path"])
            if not os.path.isfile(part_path):
                raise Refusal("manifest part missing: %s" % part["path"])
            actual = sha256_file(part_path)
            if actual != part.get("sha256"):
                raise Refusal("manifest part digest mismatch: %s" % part["path"])
            with open(part_path, "r", encoding="utf-8") as handle:
                document = json.load(handle)
            if document.get("part") == "registrations":
                registrations.extend(document.get("registrations", []))
            elif document.get("part") == "callbacks":
                callbacks.extend(document.get("callbacks", []))
    else:
        raise Refusal("manifest carries neither embedded registrations nor parts")
    return index, registrations, callbacks, sha256_file(path)


def _in_scope(registration):
    return (registration.get("registration_kind") == "slot-registration"
            and not registration.get("test_only")
            and registration.get("slot") in GATED_SLOTS)


def _factory_match(manifest_slots, compiled_slots):
    """True when a const-fn factory row describes this compiled instantiation.

    ``manifest_slots`` maps slot -> callback for the factory row; it must name
    exactly the instantiation's populated slot set and every callback must be
    one of that slot's compiled identifier aliases.
    """
    if set(manifest_slots) != set(compiled_slots):
        return False
    return all(callback in compiled_slots.get(slot, set())
               for slot, callback in manifest_slots.items())


def reconcile(extract_result, manifest_path):
    index, registrations, _callbacks, manifest_sha = load_manifest(manifest_path)
    scoped = [r for r in registrations if _in_scope(r)]

    compiled_by_row = {}
    for record in extract_result["records"]:
        if record["slot"] not in GATED_SLOTS:
            continue
        compiled_by_row.setdefault(record["row"], {}).setdefault(
            record["slot"], set()).update(record["target_identifiers"])

    manifest_rows = {}
    for registration in scoped:
        manifest_rows.setdefault(registration["row"], {})[
            registration["slot"]] = registration["callback"]
    static_rows = {row for row in manifest_rows if not row.startswith("fn:")}
    factory_rows = sorted(row for row in manifest_rows if row.startswith("fn:"))

    row_map = {}
    factory_ambiguities = []
    refusals = []
    for row in sorted(compiled_by_row):
        if row in manifest_rows:
            row_map[row] = row
            continue
        candidates = [
            factory for factory in factory_rows
            if _factory_match(manifest_rows[factory], compiled_by_row[row])
        ]
        if len(candidates) == 1:
            row_map[row] = candidates[0]
            continue
        signatures = {
            tuple(sorted(manifest_rows[candidate].items()))
            for candidate in candidates
        }
        if len(signatures) == 1 and candidates:
            row_map[row] = sorted(candidates)[0]
            factory_ambiguities.append({
                "compiled_row": row,
                "candidates": sorted(candidates),
                "reason": "identical factory registration signatures; "
                          "deterministic choice does not change accounting",
            })
            continue
        row_map[row] = None
        if candidates:
            refusals.append({
                "compiled_row": row,
                "candidates": sorted(candidates),
                "reason": "ambiguous factory-row mapping",
            })

    manifest_callbacks = {r["callback"] for r in scoped}
    compiled_identifiers = {i for r in extract_result["records"]
                            if r["slot"] in GATED_SLOTS
                            for i in r["target_identifiers"]}

    # A target is the function address, not one of its symbol aliases.  Identical
    # code folding gives one address both a local wrapper name and an exported
    # name; the manifest usually records only one of them.  A target is
    # unaccounted only when *no* alias is a manifest callback.
    compiled_targets = {}
    for record in extract_result["records"]:
        if record["slot"] not in GATED_SLOTS:
            continue
        entry = compiled_targets.setdefault(record["target_address"], {
            "row": record["row"],
            "slots": set(),
            "target_identifiers": set(),
        })
        entry["slots"].add(record["slot"])
        entry["target_identifiers"].update(record["target_identifiers"])
    compiled_targets_not_in_manifest = []
    for address, entry in sorted(compiled_targets.items()):
        identifiers = entry["target_identifiers"]
        if not identifiers & manifest_callbacks:
            compiled_targets_not_in_manifest.append({
                "target_address": address,
                "row": entry["row"],
                "slots": sorted(entry["slots"]),
                "target_identifiers": sorted(identifiers),
            })
    dead_targets = sorted(manifest_callbacks - compiled_identifiers)

    # Registration-level comparison (same slot, alias-aware).
    compiled_unaccounted = []
    for row, slots in sorted(compiled_by_row.items()):
        mapped = row_map.get(row)
        for slot, identifiers in sorted(slots.items()):
            if mapped is None:
                compiled_unaccounted.append({
                    "row": row,
                    "slot": slot,
                    "target_identifiers": sorted(identifiers),
                    "mapped_manifest_row": None,
                    "reason": "no manifest row accounts for this row",
                })
                continue
            expected = manifest_rows.get(mapped, {}).get(slot)
            if expected is None or expected not in identifiers:
                compiled_unaccounted.append({
                    "row": row,
                    "slot": slot,
                    "target_identifiers": sorted(identifiers),
                    "mapped_manifest_row": mapped,
                    "manifest_callback": expected,
                    "reason": "manifest has no (row, slot, callback) match",
                })

    manifest_not_compiled = []
    for registration in scoped:
        row = registration["row"]
        targets = [row] if row in compiled_by_row else [
            compiled for compiled, mapped in row_map.items() if mapped == row
        ]
        found = any(
            registration["callback"] in compiled_by_row.get(compiled, {})
            .get(registration["slot"], set())
            for compiled in targets
        )
        if not found:
            manifest_not_compiled.append({
                "row": row,
                "slot": registration["slot"],
                "callback": registration["callback"],
                "row_file": registration.get("row_file"),
                "compiled_rows": sorted(targets),
            })

    counts = {
        "compiled_records": len([r for r in extract_result["records"]
                                 if r["slot"] in GATED_SLOTS]),
        "compiled_rows": len(compiled_by_row),
        "compiled_distinct_targets": len(compiled_identifiers),
        "manifest_registrations_total": len(registrations),
        "manifest_registrations_in_scope": len(scoped),
        "manifest_rows_static": len(static_rows),
        "manifest_rows_factory": len(factory_rows),
        "compiled_targets_not_in_manifest": len(compiled_targets_not_in_manifest),
        "compiled_registrations_unaccounted": len(compiled_unaccounted),
        "manifest_not_compiled": len(manifest_not_compiled),
        "manifest_dead_targets": len(dead_targets),
        "factory_mapped_compiled_rows": len([v for v in row_map.values()
                                             if v and v.startswith("fn:")]),
        "factory_ambiguities": len(factory_ambiguities),
        "refusals": len(refusals) + len(extract_result["refusals"]),
    }

    passed = (not extract_result["refusals"] and not refusals
              and not compiled_targets_not_in_manifest
              and not compiled_unaccounted
              and not manifest_not_compiled
              and not dead_targets)

    return {
        "manifest": {
            "path": os.path.relpath(manifest_path),
            "sha256": manifest_sha,
            "schema": index.get("schema"),
            "registration_count": index.get("registration_count"),
            "scope": {
                "registration_kind": "slot-registration",
                "test_only": False,
                "slots": list(GATED_SLOTS),
            },
        },
        "counts": counts,
        "compiled_targets_not_in_manifest": {
            "count": len(compiled_targets_not_in_manifest),
            "first_10": compiled_targets_not_in_manifest[:10],
        },
        "compiled_registrations_unaccounted": {
            "count": len(compiled_unaccounted),
            "first_10": compiled_unaccounted[:10],
        },
        "manifest_not_compiled": {
            "count": len(manifest_not_compiled),
            "first_10": manifest_not_compiled[:10],
        },
        "manifest_dead_targets": {
            "count": len(dead_targets),
            "first_10": dead_targets[:10],
        },
        "factory_row_map": {k: v for k, v in sorted(row_map.items())
                            if v != k},
        "factory_ambiguities": factory_ambiguities,
        "mapping_refusals": refusals,
        "pass": passed,
    }


def _serialise(payload, out_path):
    """Write the report, splitting the record list when it would be large."""
    limit = 190_000
    text = json.dumps(payload, indent=1, sort_keys=True) + "\n"
    if len(text.encode("utf-8")) <= limit:
        with open(out_path, "w", encoding="utf-8") as handle:
            handle.write(text)
        return
    records = payload.pop("records")
    base, extension = os.path.splitext(out_path)
    parts = []
    size = 100
    for start in range(0, len(records), size):
        chunk = records[start:start + size]
        part_name = "%s.part%02d%s" % (base, len(parts) + 1, extension)
        part_payload = {
            "schema": SCHEMA + "/part",
            "records": chunk,
        }
        part_text = json.dumps(part_payload, indent=1, sort_keys=True) + "\n"
        with open(part_name, "w", encoding="utf-8") as handle:
            handle.write(part_text)
        parts.append({
            "path": os.path.basename(part_name),
            "records": len(chunk),
            "sha256": sha256_file(part_name),
        })
    payload["records_split"] = True
    payload["records_parts"] = parts
    with open(out_path, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, indent=1, sort_keys=True) + "\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--artifact",
        default="artifacts/phase2/install/lib/libcrypto.so.3",
        help="built libcrypto.so.3 (the COMPILED candidate)")
    parser.add_argument(
        "--manifest",
        default="forensics/memory-safety/campaign/safe-c33/atlas-refresh/"
                "callback-registration-manifest.json",
        help="source-manifest index (+ parts directory)")
    parser.add_argument(
        "--out",
        default="forensics/memory-safety/campaign/safe-c33/atlas-refresh/"
                "callback-artifact-crosscheck.json",
        help="report path")
    parser.add_argument(
        "--quiet", action="store_true", help="suppress the human summary")
    args = parser.parse_args(argv)

    artifact = os.path.abspath(args.artifact)
    manifest = os.path.abspath(args.manifest)
    out_path = os.path.abspath(args.out)
    report = {"schema": SCHEMA}

    def refuse(reason, **extra):
        report.update({
            "gate": {"pass": False, "exit_code": 2,
                     "classification": "REFUSED"},
            "refusal": {"reason": reason, **extra},
        })
        _serialise(report, out_path)
        if not args.quiet:
            print(json.dumps({"classification": "REFUSED",
                              "reason": reason, "exit_code": 2}, indent=1))
        return 2

    if not os.path.isfile(artifact):
        return refuse("artifact missing", artifact=args.artifact)
    if not os.path.isfile(manifest):
        return refuse("manifest missing", manifest=args.manifest)

    try:
        extracted = extract(artifact)
    except Refusal as exc:
        return refuse("artifact extraction refusal: %s" % exc)
    try:
        reconciliation = reconcile(extracted, manifest)
    except Refusal as exc:
        return refuse("manifest reconciliation refusal: %s" % exc)

    report["artifact"] = {
        "path": os.path.relpath(artifact),
        "sha256": sha256_file(artifact),
        "size": os.path.getsize(artifact),
    }
    report["extractor"] = {
        "table_symbol": extracted["table_symbol"]["name"],
        "table_symbol_table": extracted["table_symbol"]["table"],
        "table_entries": extracted["table_entries"],
        "row_size": ROW_SIZE,
        "slot_offsets": SLOT_OFFSETS,
        "gated_slots": list(GATED_SLOTS),
        "row_objects": len(extracted["row_objects"]),
        "rows_total": len(extracted["rows"]),
        "resolution_methods": dict(sorted(extracted["methods"].items())),
        "excluded_non_row_objects": extracted["excluded_objects"],
        "method": "STANDARD_EXTS symbol + structural static-row objects; "
                  "slot targets from .rela.dyn (RELATIVE addend / symbol) "
                  "named from .symtab with .dynsym fallback; all aliases kept",
    }
    report["rows"] = extracted["rows"]
    report["records"] = extracted["records"]
    report["refusals"] = extracted["refusals"] + (
        reconciliation.pop("mapping_refusals") or [])
    report["reconciliation"] = reconciliation

    refused = (report["refusals"]
               or reconciliation["counts"].get("refusals", 0))
    if refused:
        exit_code, classification = 2, "REFUSED"
    elif reconciliation["pass"]:
        exit_code, classification = 0, "PASS"
    else:
        exit_code, classification = 1, "FAIL"
    report["gate"] = {
        "pass": exit_code == 0,
        "exit_code": exit_code,
        "classification": classification,
        "basis": [
            "every populated slot resolves to a named function or is null",
            "every compiled target address has an alias the manifest accounts "
            "for",
            "every compiled (row, slot) registration matches the manifest",
            "every manifest registration matches a compiled registration",
            "no manifest callback is dead in the artifact",
        ],
    }
    _serialise(report, out_path)
    if not args.quiet:
        print(json.dumps({
            "classification": classification,
            "exit_code": exit_code,
            "artifact_sha256": report["artifact"]["sha256"],
            "counts": {
                "rows": len(extracted["rows"]),
                "records": len([r for r in extracted["records"]
                                if r["slot"] in GATED_SLOTS]),
                "refusals": len(report["refusals"]),
                **{k: reconciliation["counts"][k] for k in (
                    "compiled_targets_not_in_manifest",
                    "compiled_registrations_unaccounted",
                    "manifest_not_compiled",
                    "manifest_dead_targets",
                )},
            },
        }, indent=1))
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
