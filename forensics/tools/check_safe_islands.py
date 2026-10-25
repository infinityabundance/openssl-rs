#!/usr/bin/env python3
"""openssl-rs — the enforcement court for the compiler-forbidden safe islands.

What this court decides
-----------------------
The safe-islands claim is a *structural* claim: five named module trees are
declared under `#[forbid(unsafe_code)]`, so the compiler — not a review
checklist — rejects unsafe syntax anywhere inside them. That claim has exactly
one authoritative test, and it is not a regular expression: the compiler must
be observed (a) accepting the pristine subtrees and (b) rejecting a deliberately
inserted unsafe construct in each one, at the registered attribute.

So this gate is split in two, and the split is printed rather than implied:

  * **Integrity guards** (this file, stdlib only) re-establish *scope* on the
    current tree: that the declaration is still where the registry says, that
    the attribute is an unconditional `#[forbid(unsafe_code)]` immediately
    preceding it, that no `#[path]`/`include!`/`cfg` has appeared that could
    move or remove the guarantee, and that a generated island still matches its
    generator. These checks are tamper detection. They are *not* the proof: a
    lexical check cannot see macro expansion, and a regex is not a compiler.

  * **The authoritative check** reads a compiler transcript recorded in the
    court (`s69-safe-island-compiler-evidence.json`) and refuses to certify
    unless the transcript is bound to the exact current sources and toolchain
    and the compiler actually rejected every island. This gate never invokes
    cargo itself; it validates evidence produced by
    `forensics/tools/safe_islands_court_record.py` in the court.

A green run therefore means exactly one thing: **the five named subtrees cannot
contain unsafe syntax under the recorded toolchain and profiles.** It does not
discharge transitive obligations, prove the algorithms, or establish
constant-time behaviour. `COMPILER_FORBID_CONFIRMED` and `SAFETY_DISCHARGED`
are separate fields and this gate can only ever set the first.

Fail-closed conditions
----------------------
Every condition below aborts certification with a named finding. "I cannot
establish the scope" is a failure, never an implicit pass:

  * the module is not declared from the registered parent, or is declared twice;
  * the declaration is inline, or the module resolved to a different file;
  * the attribute is missing, not immediately adjacent, not
    `#[forbid(unsafe_code)]`, or accompanied by any other attribute;
  * `#[path]`, `include!`, `cfg`/`cfg_attr`, or a symlinked source appeared on
    the declaration chain;
  * a generated island no longer matches its generator (token identity is the
    minimum; a byte mismatch that is token identity is reported as formatting);
  * the compiler evidence is missing, stale, for another toolchain/crate, or
    was produced by a capped build (`--cap-lints`, `RUSTFLAGS`,
    `CARGO_ENCODED_RUSTFLAGS`, `CARGO_BUILD_RUSTFLAGS`, a rustc wrapper, or any
    cargo invocation other than the recorded `check`/`test` on this crate).

Usage
-----
    python3 forensics/tools/check_safe_islands.py
    python3 forensics/tools/check_safe_islands.py --json
    python3 forensics/tools/check_safe_islands.py --repo-root /work/court/copy

Exit codes: 0 = integrity guards and the authoritative check both pass;
1 = an integrity guard failed; 2 = the authoritative check could not be
established; 3 = the registry itself is unusable.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

REGISTRY_SCHEMA = "openssl-rs/safe-islands/v1"
EVIDENCE_SCHEMA = "openssl-rs/safe-islands-compiler-evidence/v1"
FORBID = "#[forbid(unsafe_code)]"
REGISTRY_DEFAULT = "forensics/tools/safe_islands.json"

# Lint caps and wrappers that make a `forbid` diagnostic disappear or bypass it.
# The court refuses to certify when the recorded transcript shows any of them.
CAP_FLAGS = ("--cap-lints", "-cap-lints", "--force-warn")
CAP_ENV_KEYS = (
    "RUSTFLAGS",
    "CARGO_ENCODED_RUSTFLAGS",
    "CARGO_BUILD_RUSTFLAGS",
    "RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER",
)
ALLOWED_ENV_VALUES = {"", None}


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    axis: str          # "integrity" or "authoritative"
    check: str         # stable identifier
    ok: bool
    message: str
    target: str | None = None
    detail: str | None = None


@dataclass
class Report:
    findings: list[Finding] = field(default_factory=list)
    targets: list[dict] = field(default_factory=list)
    claim_scope: dict = field(default_factory=dict)

    def add(self, axis: str, check: str, ok: bool, message: str,
            target: str | None = None, detail: str | None = None) -> None:
        self.findings.append(Finding(axis, check, ok, message, target, detail))

    # -- queries ---------------------------------------------------------
    def failures(self, axis: str | None = None) -> list[Finding]:
        return [f for f in self.findings
                if not f.ok and (axis is None or f.axis == axis)]

    def guards_ok(self) -> bool:
        return not self.failures("integrity")

    def authoritative_ok(self) -> bool:
        return not self.failures("authoritative")


# ---------------------------------------------------------------------------
# Rust token stream (comments and whitespace removed)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Tok:
    text: str
    line: int


_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_NUM_RE = re.compile(
    r"0[xX][0-9A-Fa-f_]+(?:[iu](?:8|16|32|64|128|size))?"
    r"|0[bB][01_]+(?:[iu](?:8|16|32|64|128|size))?"
    r"|0[oO][0-7_]+(?:[iu](?:8|16|32|64|128|size))?"
    r"|[0-9][0-9_]*(?:\.[0-9][0-9_]*)?(?:[eE][+-]?[0-9_]+)?"
    r"(?:[iu](?:8|16|32|64|128|size)|f(?:32|64))?"
)
_RAW_RE = re.compile(r"(?:b|c)?r(#*)\"")
_PUNCT = (
    "::", "->", "=>", "==", "!=", "<=", ">=", "&&", "||", "+=", "-=", "*=",
    "/=", "%=", "&=", "|=", "^=", "<<", ">>", "..", "..=", "#!",
)


def rust_tokens(text: str) -> list[Tok]:
    """Lex enough Rust to compare generated output and to read declarations.

    Comments (line, block, nested block, doc) are dropped; whitespace is
    dropped; string/char literals are single tokens. Lifetimes are kept as a
    `'` token plus an identifier so a stray `'` cannot swallow the file.
    """
    toks: list[Tok] = []
    i, n, line = 0, len(text), 1
    while i < n:
        c = text[i]
        if c == "\n":
            line += 1
            i += 1
            continue
        if c in " \t\r\f\v":
            i += 1
            continue
        if text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        if text.startswith("/*", i):
            depth, j = 0, i
            while j < n:
                if text.startswith("/*", j):
                    depth += 1
                    j += 2
                elif text.startswith("*/", j):
                    depth -= 1
                    j += 2
                    if depth == 0:
                        break
                else:
                    if text[j] == "\n":
                        line += 1
                    j += 1
            if depth != 0:
                raise ValueError("unterminated block comment")
            i = j
            continue

        start_line = line

        m = _RAW_RE.match(text, i)
        if m:
            hashes = m.group(1)
            term = '"' + hashes
            j = text.find(term, m.end())
            if j < 0:
                raise ValueError("unterminated raw string")
            body = text[m.end():j]
            line += body.count("\n")
            toks.append(Tok(text[i:j + len(term)], start_line))
            i = j + len(term)
            continue

        # String / byte string / C string with escapes.
        if c in ("b", "c") and i + 1 < n and text[i + 1] == '"':
            c = '"'
            i += 1
        if c == '"':
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == '"':
                    j += 1
                    break
                if text[j] == "\n":
                    line += 1
                j += 1
            toks.append(Tok(text[i:j], start_line))
            i = j
            continue

        if c == "'":
            # A char literal is `'x'`, `'\n'`, `'\u{...}'`. Anything else is a
            # lifetime; keep the quote as a token so it cannot hide structure.
            j = i + 1
            if j < n and text[j] == "\\":
                j += 2
                if j < n and text[j] == "u":
                    close = text.find("'", j)
                    j = (close + 1) if close >= 0 else j
                else:
                    close = text.find("'", j)
                    j = (close + 1) if close >= 0 else j
            elif j < n and j + 1 < n and text[j + 1] == "'":
                j += 2
            else:
                j = i + 1
            if j > i + 1 and text[j - 1] == "'":
                toks.append(Tok(text[i:j], start_line))
                i = j
                continue
            toks.append(Tok("'", start_line))
            i += 1
            continue

        m = _IDENT_RE.match(text, i)
        if m:
            toks.append(Tok(m.group(0), start_line))
            i = m.end()
            continue
        m = _NUM_RE.match(text, i)
        if m:
            toks.append(Tok(m.group(0), start_line))
            i = m.end()
            continue
        for p in _PUNCT:
            if text.startswith(p, i):
                toks.append(Tok(p, start_line))
                i += len(p)
                break
        else:
            toks.append(Tok(c, start_line))
            i += 1
    return toks


def token_digest(tokens: list[Tok]) -> str:
    """Hash of the token stream: formatting-insensitive source identity."""
    h = hashlib.sha256()
    for t in tokens:
        h.update(t.text.encode("utf-8"))
        h.update(b"\x00")
    return h.hexdigest()


def canonical_token_digest(tokens: list[Tok]) -> str:
    """Token identity with the two transformations rustfmt performs normalized.

    `cargo fmt` rewraps lines, and it *adds a trailing comma* before `]`/`}` in a
    multi-line literal. Neither changes the program. Dropping a comma directly
    before a closing bracket therefore makes the comparison formatting-only in
    the same sense rustfmt is: every identifier, number, literal and other
    punctuation still has to match exactly, so a hand-inserted item or value
    still changes the digest.
    """
    kept: list[Tok] = []
    for i, t in enumerate(tokens):
        if t.text == "," and i + 1 < len(tokens) and tokens[i + 1].text in ("]", "}"):
            continue
        kept.append(t)
    return token_digest(kept)


# ---------------------------------------------------------------------------
# Declaration scanning
# ---------------------------------------------------------------------------

@dataclass
class Attribute:
    inner: bool
    tokens: list[str]
    line: int
    text: str

    def has(self, word: str) -> bool:
        return word in self.tokens


@dataclass
class Declaration:
    name: str
    line: int
    inline: bool
    attributes: list[Attribute]
    source_file: Path | None = None
    source_candidates: list[Path] = field(default_factory=list)


class ScopeError(Exception):
    """The scope could not be established; the caller must fail closed."""


def _match_bracket_backwards(toks: list[Tok], close_idx: int,
                             open_ch: str = "[", close_ch: str = "]") -> int:
    depth = 0
    k = close_idx
    while k >= 0:
        if toks[k].text == close_ch:
            depth += 1
        elif toks[k].text == open_ch:
            depth -= 1
            if depth == 0:
                return k
        k -= 1
    raise ScopeError(f"unbalanced {open_ch}{close_ch}")


def _declaration_start(toks: list[Tok], mod_idx: int) -> int:
    """Index of the first token of the item (its visibility), for attributes."""
    j = mod_idx - 1
    if j >= 0 and toks[j].text == ")":
        open_idx = _match_bracket_backwards(toks, j, "(", ")")
        if open_idx >= 1 and toks[open_idx - 1].text == "pub":
            return open_idx - 1
        return mod_idx
    if j >= 0 and toks[j].text == "pub":
        return j
    return mod_idx


def attributes_before(toks: list[Tok], idx: int) -> list[Attribute]:
    """The attribute groups immediately preceding token `idx`, in source order."""
    groups: list[Attribute] = []
    j = idx - 1
    while j >= 0 and toks[j].text == "]":
        open_idx = _match_bracket_backwards(toks, j)
        inner = False
        prefix = open_idx
        if open_idx >= 2 and toks[open_idx - 2].text == "#" and toks[open_idx - 1].text == "!":
            inner = True
            prefix = open_idx - 2
        elif open_idx >= 1 and toks[open_idx - 1].text == "#":
            prefix = open_idx - 1
        else:
            break
        inner_toks = [t.text for t in toks[open_idx:j + 1]]
        text = "".join(t.text for t in toks[prefix:j + 1])
        groups.append(Attribute(inner, inner_toks, toks[prefix].line, text))
        j = prefix - 1
    groups.reverse()
    return groups


def _depth_at(toks: list[Tok]) -> list[int]:
    depths: list[int] = []
    depth = 0
    for t in toks:
        depths.append(depth)
        if t.text == "{":
            depth += 1
        elif t.text == "}":
            depth = max(0, depth - 1)
    return depths


def find_declaration(parent: Path, name: str, crate_root: Path) -> Declaration:
    """Find `mod <name>;` at the top level of `parent`, with its attributes."""
    try:
        text = parent.read_text(encoding="utf-8")
    except OSError as exc:
        raise ScopeError(f"cannot read parent {parent}: {exc}") from exc
    toks = rust_tokens(text)
    depths = _depth_at(toks)
    hits: list[int] = []
    for idx, t in enumerate(toks):
        if t.text != "mod" or depths[idx] != 0:
            continue
        if idx + 1 >= len(toks) or toks[idx + 1].text != name:
            continue
        if idx + 2 >= len(toks):
            continue
        follower = toks[idx + 2].text
        if follower in (";", "{"):
            hits.append(idx)
    if not hits:
        raise ScopeError(
            f"module `{name}` is not declared at the top level of {parent.name}; "
            "the declaration moved or was deleted"
        )
    if len(hits) > 1:
        raise ScopeError(f"module `{name}` is declared {len(hits)} times in {parent.name}")
    idx = hits[0]
    inline = toks[idx + 2].text == "{"
    attrs = attributes_before(toks, _declaration_start(toks, idx))
    decl = Declaration(name=name, line=toks[idx].line, inline=inline, attributes=attrs)
    if inline:
        return decl

    # Rust's file-module resolution rules, made explicit.
    if parent.name == "mod.rs":
        base = parent.parent
    elif parent.resolve() == crate_root.resolve():
        base = parent.parent
    else:
        base = parent.parent / parent.stem
    candidates = [base / f"{name}.rs", base / name / "mod.rs"]
    decl.source_candidates = [c for c in candidates if c.is_file()]
    if len(decl.source_candidates) > 1:
        raise ScopeError(
            f"module `{name}` is ambiguous: both "
            f"{decl.source_candidates[0].name} and "
            f"{decl.source_candidates[1].name} exist"
        )
    if not decl.source_candidates:
        raise ScopeError(
            f"module `{name}` is declared but neither {candidates[0]} nor "
            f"{candidates[1]} exists"
        )
    decl.source_file = decl.source_candidates[0]
    return decl


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def rel(repo: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(repo.resolve()).as_posix()
    except ValueError:
        return str(path)


def read_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ScopeError(f"cannot read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ScopeError(f"{path} is not valid JSON: {exc}") from exc


def parse_lib_path(cargo_toml: Path) -> tuple[str | None, str | None, list[str]]:
    """Return ([lib].path, package name, feature keys) from Cargo.toml."""
    text = cargo_toml.read_text(encoding="utf-8")
    section = None
    lib_path = None
    package_name = None
    features: list[str] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip()
            continue
        if "=" not in line:
            continue
        key, value = (part.strip() for part in line.split("=", 1))
        value = value.strip().strip('"')
        if section == "lib" and key == "path":
            lib_path = value
        elif section == "package" and key == "name":
            package_name = value
        elif section == "features":
            features.append(key)
    return lib_path, package_name, features


def parse_toolchain_channel(pin: Path) -> str | None:
    if not pin.is_file():
        return None
    for raw in pin.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        m = re.match(r'channel\s*=\s*"([^"]+)"', line)
        if m:
            return m.group(1)
    return None


def is_within(base: Path, path: Path) -> bool:
    try:
        path.resolve().relative_to(base.resolve())
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Integrity guards
# ---------------------------------------------------------------------------

def check_registry_shape(registry: dict, report: Report) -> None:
    if registry.get("schema") != REGISTRY_SCHEMA:
        raise ScopeError(
            f"registry schema is {registry.get('schema')!r}, expected {REGISTRY_SCHEMA!r}"
        )
    if not isinstance(registry.get("targets"), list) or not registry["targets"]:
        raise ScopeError("registry has no targets")
    seen: set[str] = set()
    for target in registry["targets"]:
        module = target.get("module")
        if not module or not module.startswith("crate::"):
            raise ScopeError(f"target module {module!r} is not a `crate::…` path")
        if module in seen:
            raise ScopeError(f"duplicate target {module}")
        seen.add(module)
        for key in ("declaration_file", "attribute_file", "source_path",
                    "attribute_form", "attribute", "generated", "checked_profiles"):
            if key not in target:
                raise ScopeError(f"{module}: missing registry field {key!r}")


def check_crate_identity(repo: Path, registry: dict, report: Report) -> None:
    crate_root = repo / registry["crate_root"]
    cargo = repo / "Cargo.toml"
    lib_path, package_name, features = parse_lib_path(cargo)

    report.add("integrity", "crate-root-file",
               crate_root.is_file() and not crate_root.is_symlink(),
               f"crate root {registry['crate_root']} is a regular file, not a symlink")
    if lib_path != registry["crate_root"]:
        report.add("integrity", "crate-root-declared", False,
                   f"Cargo.toml [lib].path is {lib_path!r}, registry says "
                   f"{registry['crate_root']!r}")
    else:
        report.add("integrity", "crate-root-declared", True,
                   f"Cargo.toml [lib].path = {lib_path}")

    if package_name != registry["crate"]:
        report.add("integrity", "crate-name", False,
                   f"Cargo.toml package.name is {package_name!r}, registry says "
                   f"{registry['crate']!r}")
    else:
        report.add("integrity", "crate-name", True,
                   f"package name = {package_name}")

    expected_features = sorted(registry.get("features", []))
    if sorted(features) != expected_features:
        report.add("integrity", "features", False,
                   "Cargo.toml [features] = " + repr(sorted(features))
                   + " but the registry records " + repr(expected_features)
                   + "; the cfg surface changed, so the recorded profiles do not "
                     "establish the scope (re-record the registry and evidence)")
    else:
        report.add("integrity", "features", True,
                   "Cargo.toml [features] matches the recorded (empty) cfg surface")

    pin = repo / registry["toolchain"]["pin"]
    channel = parse_toolchain_channel(pin)
    if channel != registry["toolchain"]["channel"]:
        report.add("integrity", "toolchain-pin", False,
                   f"{registry['toolchain']['pin']} channel is {channel!r}, "
                   f"registry says {registry['toolchain']['channel']!r}")
    else:
        report.add("integrity", "toolchain-pin", True,
                   f"toolchain pinned to {channel}")

    root_tokens = rust_tokens(crate_root.read_text(encoding="utf-8"))
    root_texts = [t.text for t in root_tokens]
    guarded = False
    i = 0
    while i + 1 < len(root_texts) and root_texts[i] == "#!" and root_texts[i + 1] == "[":
        close = i + 1
        depth = 0
        while close < len(root_texts):
            if root_texts[close] == "[":
                depth += 1
            elif root_texts[close] == "]":
                depth -= 1
                if depth == 0:
                    break
            close += 1
        group = root_texts[i:close + 1]
        if "cfg" in group or "cfg_attr" in group:
            guarded = True
            break
        i = close + 1
    if guarded:
        report.add("integrity", "crate-root-cfg", False,
                   "crate-root inner attributes contain a cfg guard; a profile "
                   "could remove the whole crate")
    else:
        report.add("integrity", "crate-root-cfg", True,
                   "no crate-root cfg guard")


def _scan_island_source(path: Path, repo: Path, module: str, report: Report) -> None:
    if path.is_symlink():
        report.add("integrity", "island-symlink", False,
                   f"{module}: {rel(repo, path)} is a symlink; scope cannot be "
                   "established from a link", target=module)
        return
    if not is_within(repo / "src", path):
        report.add("integrity", "island-outside-src", False,
                   f"{module}: {rel(repo, path)} escapes src/", target=module)
        return
    toks = rust_tokens(path.read_text(encoding="utf-8"))
    texts = [t.text for t in toks]

    include_at = [i for i in range(len(texts) - 1)
                  if texts[i] == "include" and texts[i + 1] == "!"]
    if include_at:
        report.add("integrity", "island-include", False,
                   f"{module}: bare `include!` in {rel(repo, path)} at line "
                   f"{toks[include_at[0]].line}; the source tree is no longer "
                   "self-describing", target=module)
    else:
        report.add("integrity", "island-include", True,
                   f"{module}: no bare `include!`", target=module)

    # A `#[path]` anywhere in the island is a fail-closed condition: it moves
    # source in or out of the registered file. A `#[cfg]` on a *nested item*
    # (e.g. `#[cfg(test)] mod tests`) does not weaken the outer forbid, so it is
    # allowed; only an inner `#![cfg]` on the island itself could make the whole
    # module conditional, and that is rejected.
    path_at = [i for i in range(len(texts) - 1)
               if texts[i] == "path" and i > 0 and texts[i - 1] == "#"]
    inner_cfg = False
    i = 0
    while i + 1 < len(texts) and texts[i] == "#!" and texts[i + 1] == "[":
        close = i + 1
        depth = 0
        while close < len(texts):
            if texts[close] == "[":
                depth += 1
            elif texts[close] == "]":
                depth -= 1
                if depth == 0:
                    break
            close += 1
        group = texts[i:close + 1]
        if "cfg" in group or "cfg_attr" in group:
            inner_cfg = True
            break
        i = close + 1
    if path_at:
        report.add("integrity", "island-attributes", False,
                   f"{module}: `#[path]` inside {rel(repo, path)} at line "
                   f"{toks[path_at[0] - 1].line}; the registered file is no longer "
                   "the whole source of the island", target=module)
    elif inner_cfg:
        report.add("integrity", "island-attributes", False,
                   f"{module}: an inner `#![cfg…]` in {rel(repo, path)} makes the "
                   "island's own contents conditional", target=module)
    else:
        report.add("integrity", "island-attributes", True,
                   f"{module}: no `#[path]` and no inner cfg guard inside the "
                   "island (nested `#[cfg(test)]` items are covered by the outer "
                   "forbid and are not a scope escape)", target=module)

    inner_allow = any(
        texts[i] == "allow" and any(t == "unsafe_code" for t in texts[i:i + 6])
        for i, t in enumerate(texts)
    )
    if inner_allow:
        report.add("integrity", "island-allow", False,
                   f"{module}: an `allow(unsafe_code)` inside the island would be "
                   "a direct contradiction (and E0453 in the compiler)", target=module)
    else:
        report.add("integrity", "island-allow", True,
                   f"{module}: no `allow(unsafe_code)` inside the island",
                   target=module)


def check_target(repo: Path, registry: dict, target: dict, report: Report) -> dict:
    module = target["module"]
    crate_root = repo / registry["crate_root"]
    segments = module.split("::")[1:]
    result: dict = {"module": module, "checks": []}

    try:
        parent = crate_root
        for seg in segments[:-1]:
            decl = find_declaration(parent, seg, crate_root)
            if decl.inline:
                raise ScopeError(
                    f"`{seg}` is declared inline in {parent.name}; the file scope "
                    "cannot be established"
                )
            for attr in decl.attributes:
                if attr.has("path"):
                    raise ScopeError(f"`#[path]` on ancestor `{seg}` in {parent.name}")
                if attr.has("cfg") or attr.has("cfg_attr"):
                    raise ScopeError(f"`#[cfg]` on ancestor `{seg}` in {parent.name}")
            parent = decl.source_file
            assert parent is not None

        final = find_declaration(parent, segments[-1], crate_root)
        if final.inline:
            raise ScopeError(
                f"`{module}` is now an inline module in {parent.name}; the "
                "registered declaration form is a file module"
            )

        for attr in final.attributes:
            if attr.has("path"):
                raise ScopeError(f"`#[path]` on `{module}` in {parent.name}")
            if attr.has("cfg") or attr.has("cfg_attr"):
                raise ScopeError(f"`#[cfg]` on `{module}` in {parent.name}")
            if attr.has("allow") or attr.has("deny") or attr.has("warn") \
                    or attr.has("expect"):
                raise ScopeError(
                    f"lint-level attribute {attr.text!r} on `{module}`; only "
                    "`#[forbid(unsafe_code)]` may precede an island"
                )

        if target["attribute_form"] == "outer":
            if not final.attributes:
                raise ScopeError(
                    f"`{module}` has no attribute immediately before its declaration"
                )
            last = final.attributes[-1]
            if last.inner or last.text != FORBID:
                raise ScopeError(
                    f"`{module}`: attribute immediately before the declaration is "
                    f"{last.text!r}, expected {FORBID!r}"
                )
            if len(final.attributes) != 1:
                earlier = ", ".join(a.text for a in final.attributes[:-1])
                raise ScopeError(
                    f"`{module}`: `{FORBID}` is not unconditional: it is preceded "
                    f"by {earlier}"
                )
            attribute_line = last.line
        else:
            # Inner form: `#![forbid(unsafe_code)]` in the island itself, with no
            # cfg guard anywhere in its inner attribute block.
            source = final.source_file
            toks = rust_tokens(source.read_text(encoding="utf-8")) if source else []
            texts = [t.text for t in toks]
            seen_inner = False
            i = 0
            while i + 2 < len(texts):
                if texts[i] == "#" and texts[i + 1] == "!":
                    close = i + 2
                    while close < len(texts) and texts[close] != "]":
                        close += 1
                    group = texts[i:close + 1]
                    if "cfg" in group or "cfg_attr" in group:
                        raise ScopeError(
                            f"`{module}`: cfg guard in an inner attribute")
                    if group == ["#", "!", "[", "forbid", "(", "unsafe_code", ")", "]"]:
                        seen_inner = True
                    i = close + 1
                    continue
                i += 1
            if not seen_inner:
                raise ScopeError(
                    f"`{module}`: no `#![forbid(unsafe_code)]` inner attribute")
            attribute_line = 0

        decl_file = rel(repo, parent)
        if decl_file != target["declaration_file"]:
            raise ScopeError(
                f"`{module}` is declared from {decl_file}, registry says "
                f"{target['declaration_file']}"
            )
        if target["attribute_file"] != target["declaration_file"] and \
                target["attribute_form"] == "outer":
            raise ScopeError(
                f"`{module}`: attribute file {target['attribute_file']} differs "
                f"from declaration file {target['declaration_file']}")
        if final.source_file is None:
            raise ScopeError(f"`{module}`: no source file resolved")
        source_rel = rel(repo, final.source_file)
        if source_rel != target["source_path"]:
            raise ScopeError(
                f"`{module}` resolves to {source_rel}, registry says "
                f"{target['source_path']}"
            )
        if target["attribute_form"] == "outer" and \
                attribute_line != target["attribute_line"]:
            report.add(
                "integrity", "attribute-coordinate", True,
                f"{module}: attribute is at {rel(repo, parent)}:{attribute_line}, "
                f"registry recorded :{target['attribute_line']} (coordinate drift; "
                "the authoritative evidence must still match the current line)",
                target=module, detail="COORDINATE_DRIFT")
        result["declaration_line"] = final.line
        result["attribute_line"] = attribute_line
        result["attribute_file"] = rel(repo, parent)
        result["source_path"] = source_rel
        result["attribute_form"] = target["attribute_form"]

        report.add("integrity", "declaration", True,
                   f"{module}: {FORBID} at {rel(repo, parent)}:{attribute_line} "
                   f"immediately precedes `mod {segments[-1]};` at line "
                   f"{final.line} (source {source_rel})", target=module)

    except ScopeError as exc:
        message = str(exc)
        if module not in message:
            message = f"{module}: {message}"
        report.add("integrity", "declaration", False, message, target=module)
        result["error"] = message
        return result

    _scan_island_source(repo / source_rel, repo, module, report)
    return result


def check_generated(repo: Path, registry: dict, target: dict, report: Report,
                    evidence: dict | None) -> None:
    module = target["module"]
    if not target["generated"]:
        report.add("integrity", "generated", True,
                   f"{module}: hand-written (no generator committed)", target=module)
        return

    gen = target.get("generator")
    if not gen or not gen.get("path"):
        report.add("integrity", "generated", False,
                   f"{module}: registry says generated but names no generator",
                   target=module)
        return
    gen_path = repo / gen["path"]
    if not gen_path.is_file():
        report.add("integrity", "generated", False,
                   f"{module}: generator {gen['path']} is missing", target=module)
        return

    argv = [sys.executable, str(gen_path), "--check"]
    try:
        proc = subprocess.run(argv, cwd=repo, capture_output=True, text=True,
                              timeout=600)
    except (OSError, subprocess.TimeoutExpired) as exc:
        report.add("integrity", "generated", False,
                   f"{module}: generator check could not run: {exc}", target=module)
        return

    if proc.returncode == 0:
        report.add("integrity", "generated", True,
                   f"{module}: generator --check is byte-identical "
                   f"({gen['path']} --check)", target=module)
        return

    # The generator's `--check` compares bytes; a formatted generated file is a
    # legitimate byte mismatch. It is only acceptable when a recorded render is
    # *token-identical* to the committed file, and when that record is bound to
    # the same generator source and to the current file. Byte drift is reported
    # explicitly rather than hidden.
    current = repo / target["source_path"]
    current_tokens = canonical_token_digest(
        rust_tokens(current.read_text(encoding="utf-8")))
    rec = (evidence or {}).get("generators", {}).get(module)
    if not rec:
        report.add("integrity", "generated", False,
                   f"{module}: generator --check failed (exit {proc.returncode}) "
                   "and the compiler evidence has no recorded render to compare "
                   f"against: {proc.stderr.strip() or proc.stdout.strip()}",
                   target=module)
        return
    if rec.get("generator_sha256") != sha256_file(gen_path):
        report.add("integrity", "generated", False,
                   f"{module}: the generator source changed since the render was "
                   "recorded; the recorded token comparison is stale", target=module)
        return
    if rec.get("rendered_token_sha256") != current_tokens:
        report.add("integrity", "generated", False,
                   f"{module}: the committed file's token stream no longer matches "
                   "a fresh generator render; it is not a formatting-only variant",
                   target=module)
        return
    if not rec.get("token_identical"):
        report.add("integrity", "generated", False,
                   f"{module}: recorded render is not token-identical", target=module)
        return
    report.add("integrity", "generated", True,
               f"{module}: generator --check is byte-different but token-identical "
               f"to a fresh render (whitespace/comments/trailing commas only; "
               f"recorded, not hidden)",
               target=module, detail="BYTE_DRIFT_FORMATTING_ONLY")


# ---------------------------------------------------------------------------
# Authoritative check: the compiler transcript
# ---------------------------------------------------------------------------

def _lint_cap_reasons(build: dict) -> list[str]:
    reasons: list[str] = []
    argv = build.get("argv") or []
    if not argv:
        reasons.append("no recorded argv")
        return reasons
    joined = " ".join(str(a) for a in argv)
    for flag in CAP_FLAGS:
        if flag in joined:
            reasons.append(f"argv contains {flag}")
    if argv[:1] != ["cargo"]:
        reasons.append(f"argv does not start with cargo (got {argv[:1]})")
    cmd = argv[1] if len(argv) > 1 else ""
    if cmd not in ("check", "test"):
        reasons.append(f"cargo subcommand {cmd!r} is not a product compilation")
    if not any(a.startswith("--lib") for a in argv):
        reasons.append("build is not the library target (`--lib`)")
    env = build.get("env")
    if not isinstance(env, dict):
        reasons.append("no environment snapshot (cannot establish uncapped)")
        return reasons
    for key in CAP_ENV_KEYS:
        value = env.get(key)
        if value in ALLOWED_ENV_VALUES:
            continue
        if key in ("RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER"):
            reasons.append(f"{key} is set ({value!r}): wrapper bypasses normal "
                           "product compilation")
            continue
        if any(flag in str(value) for flag in CAP_FLAGS) or "cap-lints" in str(value):
            reasons.append(f"{key} carries a lint cap ({value!r})")
        elif "unsafe_code" in str(value):
            reasons.append(f"{key} names the unsafe_code lint ({value!r})")
    if build.get("lint_cap", {}).get("capped") is True:
        reasons.append("the record itself marks the build capped")
    crate = build.get("crate") or {}
    if crate.get("name") != "openssl-rs":
        reasons.append(f"build crate is {crate.get('name')!r}, not openssl-rs")
    if crate.get("lib_path") != "src/lib.rs":
        reasons.append(f"build lib path is {crate.get('lib_path')!r}")
    return reasons


def check_evidence(repo: Path, registry: dict, report: Report,
                   evidence_path: Path) -> dict | None:
    if not evidence_path.is_file():
        report.add("authoritative", "evidence-present", False,
                   f"compiler evidence {rel(repo, evidence_path)} is missing; the "
                   "authoritative check is NOT_RUN and cannot be inferred from the "
                   "integrity guards")
        return None
    try:
        evidence = read_json(evidence_path)
    except ScopeError as exc:
        report.add("authoritative", "evidence-present", False, str(exc))
        return None

    if evidence.get("schema") != EVIDENCE_SCHEMA:
        report.add("authoritative", "evidence-schema", False,
                   f"evidence schema is {evidence.get('schema')!r}, expected "
                   f"{EVIDENCE_SCHEMA!r}")
        return None
    report.add("authoritative", "evidence-schema", True,
               f"evidence schema {EVIDENCE_SCHEMA}")

    # -- identity: exact sources, toolchain, crate --------------------------
    files = evidence.get("files")
    if not isinstance(files, dict) or not files:
        report.add("authoritative", "evidence-identity", False,
                   "evidence records no source hashes")
        return evidence
    required = {registry["crate_root"], "Cargo.toml", "Cargo.lock",
                "build.rs", registry["toolchain"]["pin"]}
    for target in registry["targets"]:
        required.update((target["declaration_file"], target["attribute_file"],
                         target["source_path"]))
    missing = sorted(required - set(files))
    unsafe_keys = sorted(k for k in files
                         if Path(k).is_absolute() or ".." in Path(k).parts)
    if missing or unsafe_keys:
        report.add("authoritative", "evidence-identity", False,
                   "the transcript does not bind every file the claim depends on "
                   f"(missing: {missing or 'none'}; unusable keys: "
                   f"{unsafe_keys or 'none'})")
        return evidence
    stale: list[str] = []
    for relpath, digest in sorted(files.items()):
        path = repo / relpath
        if not path.is_file() or sha256_file(path) != digest:
            stale.append(relpath)
    if stale:
        report.add("authoritative", "evidence-identity", False,
                   "evidence is stale: the following files changed since the "
                   "compiler transcript was recorded: " + ", ".join(stale))
        return evidence
    report.add("authoritative", "evidence-identity", True,
               f"transcript is bound to {len(files)} unchanged source files "
               f"(sha256), recorded at HEAD {evidence.get('source_head', '?')[:12]}")

    tool = evidence.get("toolchain") or {}
    for key in ("channel", "rustc", "cargo", "edition"):
        if tool.get(key) != registry["toolchain"].get(key):
            report.add("authoritative", "evidence-toolchain", False,
                       f"evidence toolchain {key} is {tool.get(key)!r}, registry "
                       f"says {registry['toolchain'].get(key)!r}")
            return evidence
    report.add("authoritative", "evidence-toolchain", True,
               f"toolchain {tool.get('rustc')} / {tool.get('cargo')}, edition "
               f"{tool.get('edition')}")

    crate = evidence.get("crate") or {}
    if crate.get("name") != registry["crate"] or crate.get("lib_path") != registry["crate_root"]:
        report.add("authoritative", "evidence-crate", False,
                   f"evidence crate identity is {crate!r}")
    else:
        report.add("authoritative", "evidence-crate", True,
                   f"crate {crate.get('name')} {crate.get('version')} "
                   f"(lib {crate.get('lib_path')})")

    # -- only uncapped product compilations --------------------------------
    builds = evidence.get("builds")
    if not isinstance(builds, list) or not builds:
        report.add("authoritative", "evidence-uncapped", False,
                   "evidence records no builds")
        return evidence
    capped = []
    for build in builds:
        reasons = _lint_cap_reasons(build)
        if reasons:
            capped.append(f"{build.get('id', '?')}: " + "; ".join(reasons))
    if capped:
        report.add("authoritative", "evidence-uncapped", False,
                   "a recorded build is capped or is not normal product "
                   "compilation, so the `forbid` diagnostic is not evidence: "
                   + " | ".join(capped))
    else:
        report.add("authoritative", "evidence-uncapped", True,
                   f"all {len(builds)} recorded builds are uncapped cargo "
                   "check/test --lib product compilations (no --cap-lints, no "
                   "RUSTFLAGS/CARGO_ENCODED_RUSTFLAGS cap, no rustc wrapper)")

    profiles = registry.get("checked_profiles", [])

    # -- baseline: the compiler accepts the pristine islands ---------------
    baselines = {b.get("profile"): b for b in builds if b.get("kind") == "baseline"}
    for profile in profiles:
        build = baselines.get(profile)
        if build is None:
            report.add("authoritative", "baseline", False,
                       f"no baseline compiler run recorded for profile {profile}",
                       detail=f"profile:{profile}")
            continue
        ok = (build.get("exit_code") == 0 and build.get("error_count") == 0
              and build.get("result") == "PASS")
        report.add("authoritative", "baseline", ok,
                   f"baseline [{profile}] {build.get('command')}: "
                   f"{build.get('error_count')} errors, exit {build.get('exit_code')}",
                   detail=f"profile:{profile}")

    # -- canary: the compiler rejects every island -------------------------
    canaries = {b.get("profile"): b for b in builds if b.get("kind") == "canary"}
    for profile in profiles:
        build = canaries.get(profile)
        if build is None:
            report.add("authoritative", "canary", False,
                   f"no canary compiler run recorded for profile {profile}",
                   detail=f"profile:{profile}")
            continue
        if build.get("result") != "REJECTED_AS_EXPECTED":
            report.add("authoritative", "canary", False,
                   f"canary build [{profile}] did not fail: {build.get('error_count')} "
                   "errors", detail=f"profile:{profile}")
            continue
        probes = {p.get("target"): p for p in build.get("probes", [])}
        computed = {t["module"]: t for t in report.targets}
        for target in registry["targets"]:
            module = target["module"]
            probe = probes.get(module)
            expected_line = computed.get(module, {}).get(
                "attribute_line", target.get("attribute_line"))
            if probe is None:
                report.add("authoritative", "canary", False,
                           f"canary build [{profile}] has no probe for {module}",
                           target=module, detail=f"profile:{profile}")
                continue
            diag = probe.get("diagnostic") or {}
            lint = diag.get("lint_source") or {}
            problems = []
            if probe.get("observed") != "REJECTED":
                problems.append(f"observed {probe.get('observed')!r}")
            if diag.get("code") not in ("unsafe_code", "E0453"):
                problems.append(f"diagnostic code {diag.get('code')!r}")
            if diag.get("file") != target["source_path"]:
                problems.append(f"error file {diag.get('file')!r}")
            if lint.get("file") != target["declaration_file"]:
                problems.append(f"lint source file {lint.get('file')!r}")
            if lint.get("line") != expected_line:
                problems.append(
                    f"lint source line {lint.get('line')!r}, current attribute is "
                    f"line {expected_line}")
            if (lint.get("text") or "").strip() != FORBID:
                problems.append(f"lint source text {lint.get('text')!r}")
            if problems:
                report.add("authoritative", "canary", False,
                           f"{module} [{profile}]: the compiler did not reject the "
                           "canary at the registered attribute: "
                           + "; ".join(problems),
                           target=module, detail=f"profile:{profile}")
            else:
                report.add("authoritative", "canary", True,
                           f"{module} [{profile}]: compiler rejected the unsafe "
                           f"canary ({diag.get('code')}) with the lint defined at "
                           f"{lint.get('file')}:{lint.get('line')}",
                           target=module, detail=f"profile:{profile}")

    # -- an allow() cannot override the forbid -----------------------------
    override = next((b for b in builds if b.get("kind") == "override"), None)
    computed = {t["module"]: t for t in report.targets}
    if override is None:
        report.add("authoritative", "override", False,
                   "no `#[allow(unsafe_code)]` override probe recorded; cannot show "
                   "that the forbid cannot be lifted locally")
    else:
        ok = False
        detail = "no matching E0453 diagnostic"
        for probe in override.get("probes") or []:
            diag = probe.get("diagnostic") or {}
            lint = diag.get("lint_source") or {}
            module = probe.get("target")
            wanted = computed.get(module, {})
            if (override.get("result") == "REJECTED_AS_EXPECTED"
                    and diag.get("code") == "E0453"
                    and diag.get("file") == wanted.get("source_path")
                    and lint.get("file") == wanted.get("attribute_file")
                    and lint.get("line") == wanted.get("attribute_line")
                    and (lint.get("text") or "").strip() == FORBID):
                ok = True
                break
            detail = (f"code={diag.get('code')} file={diag.get('file')} "
                      f"lint={lint or 'none'}")
        report.add("authoritative", "override", ok,
                   "an inserted `#[allow(unsafe_code)]` was rejected as E0453 with "
                   "the registered forbid named, so the attribute cannot be "
                   "overridden locally" if ok else
                   "the `#[allow(unsafe_code)]` override probe was not rejected as "
                   f"E0453 at the registered attribute ({detail})")

    # -- scope: the lint is not crate-wide ---------------------------------
    scope = next((b for b in builds if b.get("kind") == "scope"), None)
    if scope is None:
        report.add("authoritative", "scope-proof", False,
                   "no outside-islands scope proof recorded; cannot distinguish a "
                   "module attribute from a crate-wide forbid")
    else:
        ok = scope.get("result") == "PASS" and scope.get("error_count") == 0
        report.add("authoritative", "scope-proof", ok,
                   "outside-islands canary compiled cleanly, so the guarantee is "
                   "scoped to the five declarations, not crate-wide"
                   if ok else
                   f"outside-islands canary did not compile ({scope.get('error_count')} "
                   "errors); the lint may be crate-wide")

    return evidence


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def emit(report: Report, evidence_path: Path, as_json: bool) -> int:
    guards = report.guards_ok()
    authoritative = report.authoritative_ok()
    verdict = "PASS" if (guards and authoritative) else "FAIL"

    if as_json:
        payload = {
            "schema": "openssl-rs/safe-islands-court-result/v1",
            "verdict": verdict,
            "COMPILER_FORBID_CONFIRMED": bool(guards and authoritative),
            "SAFETY_DISCHARGED": False,
            "integrity_guards": {
                "role": "tamper detection; not the proof",
                "status": "PASS" if guards else "FAIL",
                "findings": [f.__dict__ for f in report.findings
                             if f.axis == "integrity"],
            },
            "authoritative": {
                "role": "compiler transcript; the verdict",
                "source": str(evidence_path),
                "status": "PASS" if authoritative else "FAIL",
                "findings": [f.__dict__ for f in report.findings
                             if f.axis == "authoritative"],
            },
            "targets": report.targets,
            "claim_scope": report.claim_scope,
        }
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        for axis, title in (
            ("integrity", "integrity guards (stdlib structural checks: tamper "
                          "detection, NOT the proof)"),
            ("authoritative", "authoritative check (compiler transcript: the verdict)"),
        ):
            print(f"== {title} ==")
            for f in report.findings:
                if f.axis != axis:
                    continue
                mark = "OK  " if f.ok else "FAIL"
                print(f"  {mark} [{f.check}] {f.message}")
            if not any(f.axis == axis for f in report.findings):
                print("  FAIL [none] no checks ran")
            print()
        print("claim scope: a green run means the five named subtrees cannot")
        print("contain unsafe syntax under the recorded toolchain and profiles.")
        print("It does not discharge transitive obligations, prove the algorithms,")
        print("or establish constant-time behaviour.")
        print()
        print(f"VERDICT: {verdict}")
        print(f"COMPILER_FORBID_CONFIRMED: {str(guards and authoritative).lower()}")
        print("SAFETY_DISCHARGED: false  (this gate cannot set it)")

    if not guards:
        return 1
    if not authoritative:
        return 2
    return 0


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(
        description="Enforcement court for the compiler-forbidden safe islands.")
    ap.add_argument("--repo-root", default=None,
                    help="repository root (default: two levels above this file)")
    ap.add_argument("--registry", default=REGISTRY_DEFAULT,
                    help=f"registry path relative to the repo root "
                         f"(default: {REGISTRY_DEFAULT})")
    ap.add_argument("--compiler-evidence", default=None,
                    help="compiler transcript (default: the registry's `evidence`)")
    ap.add_argument("--json", action="store_true", help="machine-readable result")
    args = ap.parse_args(argv)

    repo = Path(args.repo_root).resolve() if args.repo_root else \
        Path(__file__).resolve().parents[2]
    report = Report()
    report.claim_scope = {
        "means": "the five named module trees cannot contain unsafe syntax under "
                 "the recorded toolchain and profiles",
        "does_not_mean": [
            "transitive obligations are discharged",
            "the algorithms are correct",
            "constant-time behaviour is established",
            "SAFETY_DISCHARGED (a separate state; this gate cannot set it)",
        ],
        "not_checked_profiles": [
            "release/SEAL rebuild (NOT_RUN)",
            "any feature profile (the crate declares no features; a non-empty "
            "[features] table fails closed)",
        ],
    }

    registry_path = repo / args.registry
    if not registry_path.is_file():
        print(f"FAIL: registry {registry_path} is missing", file=sys.stderr)
        return 3
    try:
        registry = read_json(registry_path)
        check_registry_shape(registry, report)
    except ScopeError as exc:
        print(f"FAIL: registry unusable: {exc}", file=sys.stderr)
        return 3

    try:
        check_crate_identity(repo, registry, report)
    except (ScopeError, OSError) as exc:
        report.add("integrity", "crate-identity", False, str(exc))

    for target in registry["targets"]:
        entry = {
            "module": target["module"],
            "declaration_file": target["declaration_file"],
            "source_path": target["source_path"],
            "checked_profiles": target.get("checked_profiles", []),
        }
        report.targets.append(entry)
        entry.update({k: v for k, v in
                      check_target(repo, registry, target, report).items()
                      if k != "checks"})

    evidence_hint = repo / args.compiler_evidence \
        if args.compiler_evidence else repo / registry.get("evidence", "")

    # The generated-file guard needs the recorded render only for a byte-drifting
    # generator, so load the transcript once, before the per-target checks.
    evidence_preview = None
    if evidence_hint.is_file():
        try:
            evidence_preview = read_json(evidence_hint)
        except ScopeError:
            evidence_preview = None

    for target in registry["targets"]:
        check_generated(repo, registry, target, report, evidence_preview)

    evidence = check_evidence(repo, registry, report, evidence_hint)
    if evidence is not None:
        for target in registry["targets"]:
            record = next((t for t in report.targets
                           if t["module"] == target["module"]), None)
            if record is not None:
                record["compiler_probe"] = any(
                    f.ok and f.check == "canary" and f.target == target["module"]
                    for f in report.findings)

    return emit(report, evidence_hint, args.json)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
