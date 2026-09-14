#!/usr/bin/env python3
"""openssl-rs — generate the ERR string tables from the authority's own sources.

`ERR_lib_error_string` and `ERR_reason_error_string` return text that a caller
prints, so the text is part of the contract. The authority compiles those tables
in (`crypto/err/` plus one generated `*_err.c` per library); this tool rebuilds
them from the *inputs* to that generation, so the result is derived rather than
transcribed:

    include/openssl/err.h            `ERR_LIB_*` codes and `ERR_R_*` values
    crypto/err/err.c                 `ERR_str_libraries` + the generic reasons
    crypto/err/err_all.c             which libraries the crypto step loads
    crypto/**/*_err.c, providers/**  the compiled `*_str_reasons[]` arrays
    crypto/ssl_err.c                 the SSL reasons, loaded only on request
    crypto/err/openssl.txt           `LIB_R_REASON:code:...` symbol -> code

Why the `*_err.c` files and not `openssl.txt`
---------------------------------------------
`openssl.txt` is the *input* to mkerr.pl; the checked-in `*_err.c` files are what
the library actually compiles. They are not always in sync in a released tree:
measured with the RT-ERR court, `BIO_R_LOCAL_ADDR_NOT_AVAILABLE` is
"local addr not available" in `openssl.txt` and "local address not available" in
`bio_err.c`, and the compiled string is what a caller sees. So the description
comes from `*_err.c` and `openssl.txt` supplies only the symbol -> code mapping,
with a hard failure if a symbol in the C array is absent from the text file.

Why the load sets matter
------------------------
The authority's string registry is **not** a compiled-in constant table that is
always visible. `int_error_hash` starts empty and is populated by explicit
loaders, and the loaders are driven by initialisation:

  * first ERR-state creation for a thread runs
    `OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS)`
    (`crypto/err/err.c`, `ossl_err_get_state_int`), which calls
    `ossl_err_load_crypto_strings()` in `crypto/err/err_all.c`;
  * `OPENSSL_INIT_LOAD_SSL_STRINGS` runs `ossl_err_load_SSL_strings()`
    (`crypto/ssl_err.c`), which `err_all.c` deliberately skips;
  * `ERR_load_<LIB>_strings()` loads the generic tables plus that one library.

All three are observable through `ERR_reason_error_string`, so this tool records
which libraries belong to which set and emits them as separate case lists that
the RT-ERR court checks.

Correctness is not asserted here: the generated table is verified against the
authority for every pair by the RT-ERR court, which is the only thing that makes
it evidence. This tool also emits the case lists that court iterates.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import (  # noqa: E402
    PRODUCTION_AUTHORITY,
    REPO_ROOT,
    resolve_authority,
    sha256_file,
)

OUT_RS = REPO_ROOT / "src" / "runtime" / "err_strings.rs"
OUT_LOADERS = REPO_ROOT / "src" / "runtime" / "err_loaders.rs"
OUT_CASES = REPO_ROOT / "courts" / "phase3" / "rt_err_strings_cases.h"

GENERATOR = "forensics/tools/gen_err_strings.py"

# `ERR_load_<NAME>_strings` in libcrypto does not always map to a library called
# `NAME`; these are the exceptions, each measured from the authority's headers.
LOADER_LIB_OVERRIDES = {
    "CRYPTOlib": "CRYPTO",
    "ERR": None,  # loads only the generic tables
}


def parse_err_h(text: str) -> tuple[dict[str, int], dict[str, int]]:
    """Return (ERR_LIB_* name -> code, ERR_R_* name -> value).

    The `ERR_R_*` values are small expressions over `ERR_LIB_*` and the two
    `ERR_RFLAG_*` constants (which are themselves shifts over
    `ERR_RFLAGS_OFFSET`), so they are evaluated rather than pattern-matched: a
    wrong flags offset would silently produce keys that never match, and the
    symptom would be a NULL string at runtime rather than a build error.
    """
    raw: dict[str, str] = {}
    for m in re.finditer(r"^#\s*define\s+(ERR_[A-Z0-9_]+)\s+(.+?)\s*$", text, re.M):
        expr = re.sub(r"/\*.*?\*/", " ", m.group(2)).strip()
        # Strip C integer suffixes (`18L`, `0x1UL`, ...) which Python's `int` and
        # `eval` reject. Without this the shift constants never resolve and every
        # ERR_R_* value fails with them.
        expr = re.sub(r"\b(0[xX][0-9a-fA-F]+|\d+)[uUlL]+\b", r"\1", expr)
        raw[m.group(1)] = expr

    env: dict[str, int] = {"__builtins__": {}}

    def resolve(name: str) -> int | None:
        expr = raw.get(name)
        if expr is None:
            return None
        try:
            return int(eval(expr, env))  # noqa: S307
        except Exception:
            return None

    # Resolve in passes so a definition may refer to one that appears later.
    pending = set(raw)
    for _ in range(8):
        progressed = False
        for name in sorted(pending):
            value = resolve(name)
            if value is not None:
                env[name] = value
                pending.discard(name)
                progressed = True
        if not progressed:
            break

    libs = {
        name.removeprefix("ERR_LIB_"): env[name]
        for name in env
        if name.startswith("ERR_LIB_") and not name.endswith(("OFFSET", "MASK"))
    }
    # Every `ERR_R_*` value is a usable key: the generic reason table in `err.c`
    # includes the flag combinations too (notably `ERR_R_FATAL`), and a caller can
    # observe the string for any of them. `ERR_RFLAG_*` names cannot collide here
    # because `ERR_RFLAG_` does not have the `ERR_R_` prefix.
    reasons = {
        name.removeprefix("ERR_R_"): env[name]
        for name in env
        if name.startswith("ERR_R_")
    }

    if not libs or not reasons:
        unresolved = sorted(p for p in pending if p.startswith("ERR_"))[:8]
        raise SystemExit(
            "gen_err_strings: err.h parsing produced nothing; "
            f"inputs changed (unresolved: {unresolved})"
        )
    return libs, reasons


def parse_err_c(text: str, libs: dict[str, int], reasons: dict[str, int],
                ) -> tuple[dict[int, str], dict[int, str]]:
    """Return (library code -> name, generic reason value -> text)."""
    lib_table: dict[int, str] = {}
    reason_table: dict[int, str] = {}

    block = re.search(r"ERR_str_libraries\[\]\s*=\s*\{(.*?)\n\};", text, re.S)
    if not block:
        raise SystemExit("gen_err_strings: ERR_str_libraries not found")
    for m in re.finditer(r"\{\s*ERR_PACK\(\s*ERR_LIB_([A-Z0-9_]+)\s*,\s*0\s*,\s*0\s*\)\s*,"
                         r'\s*"(.*?)"\s*\}', block.group(1)):
        name, text_ = m.group(1), m.group(2)
        if name not in libs:
            raise SystemExit(f"gen_err_strings: no ERR_LIB_{name} in err.h")
        lib_table[libs[name]] = text_

    block = re.search(r"ERR_str_reasons\[\]\s*=\s*\{(.*?)\n\};", text, re.S)
    if not block:
        raise SystemExit("gen_err_strings: ERR_str_reasons not found")
    for m in re.finditer(r"\{\s*ERR_R_([A-Z0-9_]+)\s*,\s*(.*?)\s*\},", block.group(1), re.S):
        name = m.group(1)
        if name not in reasons:
            raise SystemExit(f"gen_err_strings: no ERR_R_{name} in err.h")
        # The text may be split across lines by the authority's formatter.
        text_ = re.sub(r"\s+", " ", m.group(2)).strip()
        if not (text_.startswith('"') and text_.endswith('"')):
            raise SystemExit(f"gen_err_strings: unparsed ERR_R_{name} text: {text_!r}")
        value = reasons[name]
        # Generic reasons are looked up as ERR_PACK(0, 0, r), i.e. the bare value.
        reason_table[value & 0x7FFFFF] = text_[1:-1]

    if not lib_table or not reason_table:
        raise SystemExit("gen_err_strings: err.c parsing produced nothing")
    return lib_table, reason_table


def parse_err_all(text: str) -> list[str]:
    """The libraries `ossl_err_load_crypto_strings` loads, in source order.

    Comments are stripped first: `err_all.c` mentions `ossl_err_load_SSL_strings`
    in a comment to record that it deliberately skips it, and a naive scan would
    treat that mention as a load.
    """
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    text = re.sub(r"//[^\n]*", " ", text)
    order: list[str] = []
    for m in re.finditer(r"ossl_err_load_([A-Za-z0-9_]+?)_strings\s*\(\s*\)", text):
        name = m.group(1)
        if name == "ERR":
            continue
        if name not in order:
            order.append(name)
    if not order:
        raise SystemExit("gen_err_strings: err_all.c lists no loaders")
    if "SSL" in order:
        raise SystemExit("gen_err_strings: err_all.c must not load SSL strings")
    return order


def parse_reason_codes(source: Path) -> dict[str, int]:
    """`<LIB>_R_<NAME> -> code`, taken from the headers the arrays compile against.

    `crypto/err/openssl.txt` is *not* usable for this: it is the input to the
    generator that produced the arrays, and a released tree can have them out of
    sync. Measured: `openssl.txt` says `BIO_R_PEER_ADDR_NOT_AVAILABLE:114` while
    `include/openssl/bioerr.h` says `151`, and the compiled array — and therefore
    the code a caller can look up — uses the header's 151. So the headers are the
    authority for both the code and the existence of the symbol.
    """
    out: dict[str, int] = {}
    pattern = re.compile(r"^#\s*define\s+([A-Z0-9_]+_R_[A-Za-z0-9_]+)\s+(\d+)\s*$", re.M)
    roots = [source / "include", source / "crypto", source / "ssl", source / "providers"]
    for root in roots:
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*.h")) + sorted(root.rglob("*.h.in")):
            text = path.read_text(encoding="utf-8", errors="replace")
            for m in pattern.finditer(text):
                name, value = m.group(1), int(m.group(2))
                previous = out.get(name)
                if previous is not None and previous != value:
                    raise SystemExit(
                        f"gen_err_strings: {name} is {previous} and {value} in different headers"
                    )
                out[name] = value
    if not out:
        raise SystemExit("gen_err_strings: no <LIB>_R_<NAME> declares found")
    return out


def c_strings_unescape(text: str) -> str:
    """Decode a run of C string literals into the bytes the compiler would store."""
    out = bytearray()
    for literal in re.findall(r'"((?:\\.|[^"\\])*)"', text, re.S):
        j = 0
        while j < len(literal):
            ch = literal[j]
            if ch != "\\":
                out.extend(ch.encode("utf-8"))
                j += 1
                continue
            j += 1
            esc = literal[j]
            simple = {"n": 10, "t": 9, "r": 13, "\\": 92, '"': 34, "'": 39,
                      "0": 0, "a": 7, "b": 8, "f": 12, "v": 11, "?": 63}
            if esc in simple:
                out.append(simple[esc])
                j += 1
            elif esc == "x":
                j += 1
                start = j
                while j < len(literal) and literal[j] in "0123456789abcdefABCDEF":
                    j += 1
                out.append(int(literal[start:j], 16))
            elif esc.isdigit():
                start = j
                while j < len(literal) and literal[j].isdigit():
                    j += 1
                out.append(int(literal[start:j], 8))
            else:
                raise SystemExit(f"gen_err_strings: unknown escape \\{esc}")
    return out.decode("utf-8", errors="strict")


REASON_ENTRY = re.compile(
    r"\{\s*ERR_PACK\(\s*ERR_LIB_([A-Z0-9_]+)\s*,\s*0\s*,\s*([A-Z0-9_]+)\s*\)\s*,\s*"
    r'((?:"(?:\\.|[^"\\])*"\s*)+)\s*\}',
    re.S,
)


def find_reason_arrays(source: Path) -> dict[str, tuple[Path, list[tuple[str, str, str]]]]:
    """Map `<LIB>_str_reasons` prefix -> (file, [(lib_symbol, reason_symbol, text)]).

    The file is not always named `<lib>_err.c`: 3.6.4 spells the PKCS#7, PKCS#12
    and X509v3 tables `pkcs7err.c`, `pk12err.c` and `v3err.c`. So the search is by
    content over every error-table translation unit, not by filename.
    """
    arrays: dict[str, tuple[Path, list[tuple[str, str, str]]]] = {}
    candidates = [
        p
        for root in (source / "crypto", source / "providers")
        for p in sorted(root.rglob("*.c"))
        if "err" in p.name
    ]
    for path in candidates:
        text = path.read_text(encoding="utf-8", errors="replace")
        for m in re.finditer(
            r"static const ERR_STRING_DATA ([A-Za-z0-9_]+)_str_reasons\[\]\s*=\s*\{(.*?)\n\};",
            text,
            re.S,
        ):
            prefix, body = m.group(1), m.group(2)
            entries: list[tuple[str, str, str]] = []
            for e in REASON_ENTRY.finditer(body):
                lib_symbol, reason_symbol, literals = e.group(1), e.group(2), e.group(3)
                if not reason_symbol.startswith(prefix + "_R_"):
                    raise SystemExit(
                        f"gen_err_strings: {path}: {reason_symbol} not in {prefix}_str_reasons"
                    )
                entries.append((lib_symbol, reason_symbol, c_strings_unescape(literals)))
            # An empty array is meaningful, not a parse failure: `BUF_str_reasons`
            # is literally `{ 0, NULL }` in 3.6.4, because that library no longer
            # has any reason codes of its own.
            arrays[prefix] = (path, entries)
    if not arrays:
        raise SystemExit("gen_err_strings: no *_str_reasons arrays found")
    return arrays


def find_loader_symbols(symbols_path: Path) -> list[str]:
    """The `ERR_load_<X>_strings` symbols the authority exports from libcrypto."""
    doc = json.loads(symbols_path.read_text(encoding="utf-8"))
    names = [
        r["symbol"]
        for r in doc["body"]["records"]
        if re.fullmatch(r"ERR_load_[A-Za-z0-9_]+_strings", r["symbol"])
    ]
    if not names:
        raise SystemExit("gen_err_strings: no ERR_load_*_strings exports found")
    return sorted(names)


def rust_bytes(s: str) -> str:
    """A NUL-terminated Rust byte-string literal, escaped for arbitrary text.

    The trailing NUL is part of the table: these strings are handed straight to C
    callers through `const char *`, so the terminator belongs in the data rather
    than being added (and leaked) at each call site.
    """
    out = s.encode("utf-8") + b"\x00"
    body = "".join(
        chr(ch) if (0x20 <= ch < 0x7F and ch not in (0x22, 0x5C)) else f"\\x{ch:02x}"
        for ch in out
    )
    return f'b"{body}"'


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Generate the ERR string tables.")
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    args = ap.parse_args(argv)

    auth = resolve_authority(args.authority)
    src = auth.source
    err_h = auth.prefix / "include" / "openssl" / "err.h"
    err_c = src / "crypto" / "err" / "err.c"
    err_all = src / "crypto" / "err" / "err_all.c"
    symbols = REPO_ROOT / "forensics" / "atlas" / auth.id / "symbols-libcrypto.json"
    for p in (err_h, err_c, err_all, symbols):
        if not p.is_file():
            raise SystemExit(f"gen_err_strings: missing input {p}")

    libs, reason_values = parse_err_h(err_h.read_text(encoding="utf-8", errors="replace"))
    lib_table, generic = parse_err_c(
        err_c.read_text(encoding="utf-8", errors="replace"), libs, reason_values
    )
    crypto_order = parse_err_all(err_all.read_text(encoding="utf-8", errors="replace"))
    codes = parse_reason_codes(src)
    arrays = find_reason_arrays(src)
    loader_symbols = find_loader_symbols(symbols)

    missing = [name for name in crypto_order if name not in arrays]
    if missing:
        raise SystemExit(f"gen_err_strings: loader has no reason array: {missing}")

    # (lib_code << 23) | reason_code -> text, for the libraries that are loaded.
    per_reason: dict[tuple[int, int], str] = {}
    ssl_entries: list[tuple[int, int]] = []

    # The library of an array is named by its prefix, which matches the
    # `ERR_LIB_*` symbol; the entries' own `ERR_LIB_*` is cross-checked against it.
    array_lib: dict[str, int] = {}
    for prefix in arrays:
        if prefix not in libs:
            raise SystemExit(f"gen_err_strings: reason array {prefix}_str_reasons has no ERR_LIB_{prefix}")
        array_lib[prefix] = libs[prefix]

    def absorb(prefix: str) -> None:
        path, entries = arrays[prefix]
        for lib_symbol, reason_symbol, text in entries:
            if lib_symbol not in libs:
                raise SystemExit(f"gen_err_strings: {path}: no ERR_LIB_{lib_symbol}")
            if libs[lib_symbol] != array_lib[prefix]:
                raise SystemExit(
                    f"gen_err_strings: {path}: {reason_symbol} packs ERR_LIB_{lib_symbol} "
                    f"but the array is {prefix}_str_reasons"
                )
            if reason_symbol not in codes:
                raise SystemExit(
                    f"gen_err_strings: {path}: {reason_symbol} has no numeric define "
                    "in any header; the compiled array references a symbol the "
                    "installed headers do not declare"
                )
            lib = libs[lib_symbol]
            reason = codes[reason_symbol]
            if lib == libs["SSL"]:
                # Recorded separately for the court, but stored in the same table:
                # visibility is decided by the per-library load bit, not by which
                # table the text lives in.
                ssl_entries.append((lib, reason))
            per_reason.setdefault((lib, reason), text)

    for name in crypto_order:
        absorb(name)
    # Providers' own error table lives under `providers/`, and `err_all.c` loads
    # it, so it must be present in the array index.
    if "PROV" in crypto_order and "PROV" not in arrays:
        raise SystemExit("gen_err_strings: PROV loader present but no array found")

    # The SSL set is deliberately outside the crypto set: `err_all.c` skips it.
    if "SSL" not in arrays:
        raise SystemExit("gen_err_strings: no SSL reason array")
    absorb("SSL")

    # Libraries that have a compiled table but are loaded by neither set. They are
    # observable as always-NULL, so the court checks for exactly that.
    loaded_libs = {libs[name] for name in crypto_order} | {libs["SSL"]}
    unloaded: list[tuple[int, int]] = []
    for prefix, (_path, entries) in arrays.items():
        if array_lib[prefix] in loaded_libs:
            continue
        for _ls, reason_symbol, _t in entries:
            unloaded.append((array_lib[prefix], codes[reason_symbol]))

    crypto_libs = sorted({libs[name] for name in crypto_order})

    lines = [
        "//! GENERATED by forensics/tools/gen_err_strings.py — do not edit by hand.",
        "//!",
        "//! The authority's `ERR` string tables, rebuilt from the files its own build",
        "//! generates them from. See the generator docstring for the lookup semantics",
        "//! and for why the compiled `*_err.c` files — not `openssl.txt` — decide the",
        "//! text.",
        "//!",
        "//! Inputs (content-addressed):",
        f"//!   - `{err_h.relative_to(REPO_ROOT).as_posix()}` sha256 `{sha256_file(err_h)}`",
        f"//!   - `{err_c.relative_to(REPO_ROOT).as_posix()}` sha256 `{sha256_file(err_c)}`",
        f"//!   - `{err_all.relative_to(REPO_ROOT).as_posix()}` sha256 `{sha256_file(err_all)}`",
        f"//!   - `{symbols.relative_to(REPO_ROOT).as_posix()}` sha256 `{sha256_file(symbols)}`",
        "//!",
        f"//! Generator `{GENERATOR}` sha256 `{sha256_file(REPO_ROOT / GENERATOR)}`",
        "",
        "/// `(library code, name)`, sorted by code. Each name is NUL-terminated.",
        "pub(crate) static LIBS: &[(u8, &[u8])] = &[",
    ]
    lib_rows = sorted(lib_table.items())
    for code, name in lib_rows:
        lines.append(f"    ({code}u8, {rust_bytes(name)}),")
    lines += [
        "];",
        "",
        "/// The number of library names; asserted against the table by a unit test.",
        "#[cfg(test)]",
        f"pub(crate) const LIB_COUNT: usize = {len(lib_rows)};",
        "",
        "/// `(packed-or-bare key, text)`, sorted by key. Each text is NUL-terminated.",
        "///",
        "/// A per-library entry is keyed by `ERR_PACK(lib, 0, reason)`; a generic entry",
        "/// by the bare reason value, which is what `ERR_PACK(0, 0, reason)` produces.",
        "/// Every key here belongs to a library the crypto or SSL step loads, or to",
        "/// the generic tables.",
        "pub(crate) static REASONS: &[(u32, &[u8])] = &[",
    ]
    reason_rows: list[tuple[int, str]] = []
    for (lib, code), desc in per_reason.items():
        reason_rows.append(((lib << 23) | (code & 0x7FFFFF), desc))
    for value, desc in generic.items():
        reason_rows.append((value & 0x7FFFFF, desc))
    seen: dict[int, str] = {}
    for key, desc in sorted(reason_rows, key=lambda r: r[0]):
        seen.setdefault(key, desc)
    reason_rows = sorted(seen.items())
    for key, desc in reason_rows:
        lines.append(f"    ({key}u32, {rust_bytes(desc)}),")
    lines += [
        "];",
        "",
        "/// The number of reason strings; asserted against the table by a unit test.",
        "#[cfg(test)]",
        f"pub(crate) const REASON_COUNT: usize = {len(reason_rows)};",
        "",
        "/// Library codes the crypto-strings step loads, in `err_all.c` order.",
        "///",
        "/// SSL is deliberately absent; its table is loaded only by",
        "/// `OPENSSL_INIT_LOAD_SSL_STRINGS`.",
        "pub(crate) static CRYPTO_LIBS: &[u8] = &[",
    ]
    for lib in crypto_libs:
        lines.append(f"    {lib}u8,")
    lines += ["];", ""]

    OUT_RS.parent.mkdir(parents=True, exist_ok=True)
    OUT_RS.write_text("\n".join(lines), encoding="utf-8")

    # The per-library `ERR_load_<X>_strings` entry points. They are not no-ops:
    # each one loads the generic tables plus that library, which is observable.
    loader_lines = [
        "//! GENERATED by forensics/tools/gen_err_strings.py — do not edit by hand.",
        "//!",
        "//! The `ERR_load_<LIB>_strings` entry points libcrypto exports. Each loads the",
        "//! generic tables plus one library, which is observable through",
        "//! `ERR_reason_error_string`; see the generator docstring.",
        "",
        "use core::ffi::c_int;",
        "",
        "use super::{load_generic, load_lib};",
        "",
    ]
    loader_map: list[tuple[str, int | None]] = []
    for symbol in loader_symbols:
        middle = symbol[len("ERR_load_"):-len("_strings")]
        if middle in LOADER_LIB_OVERRIDES:
            override = LOADER_LIB_OVERRIDES[middle]
            lib = None if override is None else libs[override]
        else:
            lib = libs.get(middle)
            if lib is None:
                raise SystemExit(
                    f"gen_err_strings: cannot map {symbol} to an ERR_LIB_*; "
                    "add it to LOADER_LIB_OVERRIDES"
                )
        loader_map.append((symbol, lib))
        if lib is None:
            body = "load_generic();\n    1"
            note = "the generic tables only"
        elif lib in loaded_libs:
            body = f"load_lib({lib});\n    1"
            note = f"the generic tables and library {lib}"
        else:
            body = "load_generic();\n    1"
            note = "the generic tables; this library has no compiled reason table"
        loader_lines += [
            f"/// `int {symbol}(void)` — loads {note}.",
            "#[no_mangle]",
            f"pub(crate) extern \"C\" fn {symbol}() -> c_int {{",
            "    " + body,
            "}",
            "",
        ]
    OUT_LOADERS.parent.mkdir(parents=True, exist_ok=True)
    OUT_LOADERS.write_text("\n".join(loader_lines), encoding="utf-8")

    # The case lists the RT-ERR court iterates: every pair the authority can
    # answer, split by load set so the court checks the gating too.
    crypto_cases = sorted((lib, code) for (lib, code) in per_reason if lib != libs["SSL"])
    case_lines = [
        "/* GENERATED by forensics/tools/gen_err_strings.py — do not edit by hand.",
        " * Every (library, reason) pair the authority's crypto load set defines, so",
        " * the RT-ERR court can check the candidate's tables exhaustively rather",
        " * than by sampling. The three lists are separate because the authority's",
        " * visibility depends on which loader has run. */",
        "#define ERR_CASE_COUNT " + str(len(crypto_cases)),
        "static const struct { unsigned lib; unsigned reason; } ERR_CASES[] = {",
    ]
    for lib, code in crypto_cases:
        case_lines.append(f"    {{{lib}u, {code}u}},")
    case_lines += [
        "};",
        "",
        "/* The generic (library-independent) reasons. The authority tries",
        " * `ERR_PACK(0, 0, reason)` second, so these are keyed by the bare reason",
        " * value, `ERR_RFLAG_*` bits included. */",
        "#define ERR_GENERIC_CASE_COUNT " + str(len(generic)),
        "static const struct { unsigned reason; } ERR_GENERIC_CASES[] = {",
    ]
    for value in sorted(generic):
        case_lines.append(f"    {{{value & 0x7FFFFF}u}},")
    case_lines += [
        "};",
        "",
        "/* SSL reasons: NULL until `OPENSSL_INIT_LOAD_SSL_STRINGS` has run.",
        " * `err_all.c` skips the SSL loader on purpose. */",
        "#define ERR_SSL_CASE_COUNT " + str(len(ssl_entries)),
        "static const struct { unsigned lib; unsigned reason; } ERR_SSL_CASES[] = {",
    ]
    for lib, code in sorted(set(ssl_entries)):
        case_lines.append(f"    {{{lib}u, {code}u}},")
    case_lines += [
        "};",
        "",
        "/* Libraries with a compiled table that no loader in the crypto set loads.",
        " * The authority answers NULL for these, always. */",
        "#define ERR_UNLOADED_CASE_COUNT " + str(len(unloaded)),
        "static const struct { unsigned lib; unsigned reason; } ERR_UNLOADED_CASES[] = {",
    ]
    for lib, code in sorted(set(unloaded)):
        case_lines.append(f"    {{{lib}u, {code}u}},")
    case_lines += ["};", ""]
    OUT_CASES.parent.mkdir(parents=True, exist_ok=True)
    OUT_CASES.write_text("\n".join(case_lines) + "\n", encoding="utf-8")

    print(f"[gen_err_strings] libs={len(lib_rows)} crypto_reasons={len(crypto_cases)} "
          f"generic={len(generic)} ssl={len(set(ssl_entries))} "
          f"unloaded={len(set(unloaded))} loaders={len(loader_map)}")
    print(f"  crypto load set: {sorted(crypto_order)}")
    print(f"  -> {OUT_RS.relative_to(REPO_ROOT)} sha256={sha256_file(OUT_RS)}")
    print(f"  -> {OUT_LOADERS.relative_to(REPO_ROOT)} sha256={sha256_file(OUT_LOADERS)}")
    print(f"  -> {OUT_CASES.relative_to(REPO_ROOT)}")
    (REPO_ROOT / "forensics" / "atlas" / "err-strings.json").write_text(
        json.dumps({
            "generator": GENERATOR,
            "authority": auth.id,
            "lib_count": len(lib_rows),
            "crypto_reason_count": len(crypto_cases),
            "generic_reason_count": len(generic),
            "ssl_reason_count": len(set(ssl_entries)),
            "unloaded_reason_count": len(set(unloaded)),
            "crypto_load_set": sorted(crypto_order),
            "loaders": [sym for sym, _ in loader_map],
            "outputs": {
                OUT_RS.relative_to(REPO_ROOT).as_posix(): sha256_file(OUT_RS),
                OUT_LOADERS.relative_to(REPO_ROOT).as_posix(): sha256_file(OUT_LOADERS),
                OUT_CASES.relative_to(REPO_ROOT).as_posix(): sha256_file(OUT_CASES),
            },
        }, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
