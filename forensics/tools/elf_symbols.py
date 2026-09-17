#!/usr/bin/env python3
"""openssl-rs — read the native symbol tables of an ELF64 object or `ar` archive.

Why this exists instead of shelling out to `nm`
-----------------------------------------------
Rust objects carry LLVM bitcode alongside their machine code, and binutils reads
that bitcode through a plugin whose availability depends on the host. Where the
plugin works, `nm` reports symbols that exist **only in the bitcode**; where it
does not, `nm` prints

    bfd plugin: LLVM gold plugin has failed to create LTO module: ...

and reports the native table alone. The same archive therefore yields *different
symbol sets on different machines*, which is not a property an evidence artefact
may have -- CI (Ubuntu) saw 260 C-identifier internal symbols where the court
(Debian) saw 39, the difference being 221 `compiler_builtins` bitcode definitions
such as `__adddf3`.

The native `.symtab` is what this project actually needs. A `#[no_mangle]
extern "C"` definition is a real symbol in the object's native table, and those
are exactly the definitions the ABI shell must not scaffold. Reading the table
directly makes the derived surface a function of the archive alone rather than of
the reader. See docs/DECISIONS.md D30 and D33.

Scope
-----
Deliberately narrow: **ELFCLASS64, little-endian, `ar` archives and single
objects.** Anything else raises rather than being guessed at, because a silently
mis-read symbol table would make the shell scaffold a defined symbol (a link
failure) or omit a scaffold (a missing export). Both are loud; a wrong guess that
happens to look plausible is not.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import struct
from pathlib import Path

AR_MAGIC = b"!<arch>\n"
ELF_MAGIC = b"\x7fELF"

# ELF constants (the subset this reader needs).
ELFCLASS64 = 2
ELFDATA2LSB = 1
SHT_SYMTAB = 2
SHN_UNDEF = 0
STB_GLOBAL = 1
STB_WEAK = 2
STB_GNU_UNIQUE = 10
SYMENT_SIZE = 24
SHEntSize = 64

# `ar` members that are not objects: the symbol index and the long-name table.
AR_INDEX_NAMES = {b"/", b"/SYM64/", b"//"}


class ElfError(ValueError):
    """The input is not a format this reader understands."""


def _cstring(buf: bytes, off: int) -> str:
    end = buf.find(b"\x00", off)
    if end < 0:
        raise ElfError("unterminated string in .strtab")
    return buf[off:end].decode("utf-8", "replace")


def elf_defined_external_symbols(data: bytes) -> set[str]:
    """Global/weak symbols a single ELF64 object *defines*, by name.

    Mirrors `nm --defined-only --extern-only`: undefined entries are excluded, and
    so is every local binding. Absolute, common and extended-index section
    references count as defined, as they do for `nm`.
    """
    if len(data) < 64 or not data.startswith(ELF_MAGIC):
        raise ElfError("not an ELF object")
    if data[4] != ELFCLASS64:
        raise ElfError("only ELFCLASS64 is supported")
    if data[5] != ELFDATA2LSB:
        raise ElfError("only little-endian ELF objects are supported")

    (e_shoff,) = struct.unpack_from("<Q", data, 0x28)
    (e_shentsize, e_shnum, _e_shstrndx) = struct.unpack_from("<HHH", data, 0x3A)
    if e_shoff == 0 or e_shnum == 0 or e_shentsize != SHEntSize:
        raise ElfError(f"unusable section table (off={e_shoff} num={e_shnum})")

    sections = []
    for i in range(e_shnum):
        base = e_shoff + i * e_shentsize
        if base + SHEntSize > len(data):
            raise ElfError("section table runs past the end of the object")
        (sh_type,) = struct.unpack_from("<I", data, base + 0x04)
        (sh_offset, sh_size) = struct.unpack_from("<QQ", data, base + 0x18)
        (sh_link,) = struct.unpack_from("<I", data, base + 0x28)
        (sh_entsize,) = struct.unpack_from("<Q", data, base + 0x38)
        sections.append((sh_type, sh_offset, sh_size, sh_link, sh_entsize))

    names: set[str] = set()
    for sh_type, sh_offset, sh_size, sh_link, sh_entsize in sections:
        if sh_type != SHT_SYMTAB:
            continue
        if sh_entsize != SYMENT_SIZE:
            raise ElfError(f"unexpected symbol entry size {sh_entsize}")
        if sh_link >= len(sections):
            raise ElfError("symbol table links to a missing string table")
        _, str_off, str_size = sections[sh_link][:3]
        strtab = data[str_off : str_off + str_size]
        for j in range(sh_size // SYMENT_SIZE):
            ent = sh_offset + j * SYMENT_SIZE
            (st_name, st_info, _st_other, st_shndx) = struct.unpack_from("<IBBH", data, ent)
            if st_shndx == SHN_UNDEF:
                continue
            if (st_info >> 4) not in (STB_GLOBAL, STB_WEAK, STB_GNU_UNIQUE):
                continue
            names.add(_cstring(strtab, st_name))
    return names


def elf_undefined_symbols(data: bytes) -> set[str]:
    """Global/weak symbols a single ELF64 object *references and does not define*.

    Mirrors `nm --undefined-only`: the complement of `elf_defined_external_symbols`
    over the same two filters, and the reason it exists rather than being derived from
    the defined set is that the two are read from different sides of different files.
    A translation unit's undefined set is the exact list of names its object needs from
    elsewhere in the link, which is a property of the *object* and not of the source: a
    C body that mentions `standard_methods` has not thereby referenced anything outside
    its own unit, whereas the table's initialiser has.

    This is the measurement D165 specifies for the D163 class -- "does this unit's
    object need a symbol that lives in a unit the crate has not transcribed" -- and it
    is a measurement rather than an inference because the linker's own view of the
    dependency is what the link will actually require.
    """
    if len(data) < 64 or not data.startswith(ELF_MAGIC):
        raise ElfError("not an ELF object")
    if data[4] != ELFCLASS64:
        raise ElfError("only ELFCLASS64 is supported")
    if data[5] != ELFDATA2LSB:
        raise ElfError("only little-endian ELF objects are supported")

    (e_shoff,) = struct.unpack_from("<Q", data, 0x28)
    (e_shentsize, e_shnum, _e_shstrndx) = struct.unpack_from("<HHH", data, 0x3A)
    if e_shoff == 0 or e_shnum == 0 or e_shentsize != SHEntSize:
        raise ElfError(f"unusable section table (off={e_shoff} num={e_shnum})")

    sections = []
    for i in range(e_shnum):
        base = e_shoff + i * e_shentsize
        if base + SHEntSize > len(data):
            raise ElfError("section table runs past the end of the object")
        (sh_type,) = struct.unpack_from("<I", data, base + 0x04)
        (sh_offset, sh_size) = struct.unpack_from("<QQ", data, base + 0x18)
        (sh_link,) = struct.unpack_from("<I", data, base + 0x28)
        (sh_entsize,) = struct.unpack_from("<Q", data, base + 0x38)
        sections.append((sh_type, sh_offset, sh_size, sh_link, sh_entsize))

    names: set[str] = set()
    for sh_type, sh_offset, sh_size, sh_link, sh_entsize in sections:
        if sh_type != SHT_SYMTAB:
            continue
        if sh_entsize != SYMENT_SIZE:
            raise ElfError(f"unexpected symbol entry size {sh_entsize}")
        if sh_link >= len(sections):
            raise ElfError("symbol table links to a missing string table")
        _, str_off, str_size = sections[sh_link][:3]
        strtab = data[str_off : str_off + str_size]
        for j in range(sh_size // SYMENT_SIZE):
            ent = sh_offset + j * SYMENT_SIZE
            (st_name, st_info, _st_other, st_shndx) = struct.unpack_from("<IBBH", data, ent)
            if st_shndx != SHN_UNDEF:
                continue
            if (st_info >> 4) not in (STB_GLOBAL, STB_WEAK, STB_GNU_UNIQUE):
                continue
            name = _cstring(strtab, st_name)
            # A weak reference is a *permitted* absence and the link does not require
            # it; `nm -u` lists it, so it is listed here, and the caller decides.
            if name:
                names.add(name)
    return names


def _ar_member_payloads(data: bytes):
    """Yield the payload of each object member of an `ar` archive."""
    off = len(AR_MAGIC)
    while off < len(data):
        if off + 60 > len(data):
            raise ElfError("truncated ar header")
        header = data[off : off + 60]
        if header[58:60] != b"\x60\n":
            raise ElfError("bad ar member magic")
        raw_size = header[48:58].decode("ascii", "replace").strip()
        try:
            size = int(raw_size)
        except ValueError as exc:
            raise ElfError(f"malformed ar member size {raw_size!r}") from exc
        body = data[off + 60 : off + 60 + size]
        if len(body) != size:
            raise ElfError("truncated ar member")
        off += 60 + size + (size & 1)  # members are padded to an even offset
        if header[0:16].rstrip() in AR_INDEX_NAMES:
            continue
        yield body


def defined_external_symbols(path: Path | str) -> set[str]:
    """Global/weak symbols defined by an ELF64 object or an `ar` archive of them."""
    data = Path(path).read_bytes() if not isinstance(path, bytes) else path
    if data.startswith(AR_MAGIC):
        names: set[str] = set()
        for payload in _ar_member_payloads(data):
            names |= elf_defined_external_symbols(payload)
        return names
    return elf_defined_external_symbols(data)
