#!/usr/bin/env python3
"""openssl-rs -- Phase 22.11 canonical POD contract oracle and POD<->runtime differential.

`docs/PHASE-22-SUBPHASES.md` section 6 gives this subphase its rule, verbatim:

    22.11 must use the exact 3.6.4 manual corpus from the admitted source tree, resolve
    `.pod.in` templates as the build does, run OpenSSL's own `util/find-doc-nits` as one
    instrument (and test that instrument's sensitivity), parse POD into a content-addressed
    claim graph, and turn every mechanically testable claim into a differential probe against
    the admitted authority. Undocumented is not nonexistent, and documented-but-divergent is
    evidence.

The four planes and the rule between them (section 1.1) are what make this plane a
*reconciliation* rather than a scrape: the canonical POD manuals say what OpenSSL claims, the
source/AST/build planes say what it contains, the objects/DSO plane says what it publishes, and
runtime observation says what it does. **No plane may silently overrule another**: this tool never
chooses the manual over the runtime or the reverse -- a disagreement becomes a residual with a
class and is recorded as the result.

What this plane does
--------------------
  1. **Inventory** every public manual page in `doc/man1`, `doc/man3`, `doc/man5`, `doc/man7` of
     the admitted `openssl-3.6.4` source -- path, section, canonical page, the `NAME` entries and
     aliases, the source digest, and, for the `.pod.in` templates, how the page was resolved and
     the digest of the resolved text.
  2. **Run OpenSSL's own `util/find-doc-nits`** against the admitted build and retain its complete
     raw output as **one instrument** -- and say so, because it is not the oracle (section 6, and
     the Doxygen rule of 22.2 it rhymes with).
  3. **Parse POD into a machine-readable claim graph.** Every assertion this plane extracts is a
     claim `PODCLAIM(section:page, kind, subject, normalized)` with a class drawn from the plan's
     vocabulary. Only mechanically defensible extraction becomes a claim: arbitrary English prose
     is **not** understood and is not turned into an assertion (`SEMANTIC_TEXT` /
     `EXPLANATORY_ONLY` claims carry the text as a quote, never an interpreted meaning).
  4. **Reconcile** the claim graph against the planes that exist: the header/API atlas
     (`forensics/atlas/openssl-3.6.4-production/{functions,macros,typedefs,enums,structs,variables}
     .json`), 22.2's `doxygen-entities.json`, 22.3's `tu-ast.json`, 22.8's `install-manifest.json`,
     22.9's `cli-surface.json`, 22.10's `config-surface.json`, the provider-algorithm inventory,
     and the `.num`/DSO symbol inventories. Every disagreement is classified with the plan's
     residual vocabulary and recorded -- a disagreement is the result, not a preference.
  5. **Classify testability.** Every claim class carries whether an authority probe exists and,
     where none does, the reason (`UNTESTABLE`), so "no disagreement" cannot be read as "verified".

Resolution of `.pod.in`
-----------------------
`.pod.in` pages are templates (`util/dofile.pl` + `doc/perlvars.pm` + the build's `configdata.pm`)
and 56 of the pages in the corpus are templates, so a plane that read the files as written would
read `{- $OpenSSL::safe::opt_provider_synopsis -}` instead of the option block the manual actually
publishes. This tool resolves them **the way the build does**: it invokes the authority's own
`util/dofile.pl` from the admitted build directory with the build's own relative input path, so the
resolved text is byte-identical to the page the build generated (`--keep` reuses whatever the build
already wrote, for a machine without `perl`). The provenance of every page -- template vs plain
`.pod`, which resolver produced the text, the resolved digest -- is recorded per page.

Determinism
-----------
The document is a pure function of the admitted corpus, the joined planes and the captured
`find-doc-nits` output: pages are sorted by `(section, page)`, names/options/claims by their
identity, no timestamp, PID or scratch path is written. The court (`RT-PHASE22-POD`) re-derives the
claim graph and the reconciliation from the artefact's own committed page model and index and
requires equality, then mutates that model in memory and requires each mutation to move the plane
it belongs to.

Outputs
-------
    forensics/atlas/phase22/pod-contract.json
    docs/POD-CENSUS.md

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import copy
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
    authority_atlas_dir,
    authority_build_dir,
    envelope,
    parse_num_file,
    rel,
    resolve_authority,
    sha256_file,
    write_json,
)

GENERATOR = "forensics/tools/phase22_pod.py"
ARTEFACT_REL = "forensics/atlas/phase22/pod-contract.json"
CENSUS_REL = "docs/POD-CENSUS.md"
OUT = REPO_ROOT / ARTEFACT_REL
CENSUS = REPO_ROOT / CENSUS_REL

# The four public manual sections the plan names, in the order they are joined and rendered.
SECTIONS = (1, 3, 5, 7)
SECTION_DIR = {1: "man1", 3: "man3", 5: "man5", 7: "man7"}

# Authority-relative source of the manual corpus, resolved against `auth.source`.
CORPUS_REL = "doc"

# Which joined plane supplies which reconciliation axis, and the artefact paths that are
# content-addressed into this document's `inputs`.
PLANE_PATHS = {
    "header-atlas-functions": "forensics/atlas/openssl-3.6.4-production/functions.json",
    "header-atlas-macros": "forensics/atlas/openssl-3.6.4-production/macros.json",
    "header-atlas-typedefs": "forensics/atlas/openssl-3.6.4-production/typedefs.json",
    "header-atlas-enums": "forensics/atlas/openssl-3.6.4-production/enums.json",
    "header-atlas-structs": "forensics/atlas/openssl-3.6.4-production/structs.json",
    "header-atlas-variables": "forensics/atlas/openssl-3.6.4-production/variables.json",
    "doxygen-entities": "forensics/atlas/phase22/doxygen-entities.json",
    "tu-ast": "forensics/atlas/phase22/tu-ast.json",
    "install-manifest": "forensics/atlas/phase22/install-manifest.json",
    "cli-surface": "forensics/atlas/phase22/cli-surface.json",
    "config-surface": "forensics/atlas/phase22/config-surface.json",
    "provider-algorithms": "forensics/atlas/provider-algorithms.json",
}

# The source inventories read directly for the ABI axis (`.num`), relative to the authority.
NUM_RELS = ("util/libcrypto.num", "util/libssl.num")

# Which claim class each extracted claim kind carries, and the authority probe that can test it.
# The plan's vocabulary is STRUCTURAL | EXECUTABLE_CLAIM | SEMANTIC_TEXT | EXPLANATORY_ONLY.
CLAIM_CLASS = {
    "NAME_ENTRY": "STRUCTURAL",
    "SYNOPSIS_DECL": "STRUCTURAL",
    "CLI_OPTION": "EXECUTABLE_CLAIM",
    "ENV_VAR": "EXECUTABLE_CLAIM",
    "CONFIG_DIRECTIVE": "EXECUTABLE_CLAIM",
    "DEFAULT_PATH": "EXECUTABLE_CLAIM",
    "DEPRECATION": "EXECUTABLE_CLAIM",
    "PROVIDER_ALGORITHM": "EXECUTABLE_CLAIM",
    "RETURN_VALUE": "SEMANTIC_TEXT",
    "CONCEPT": "EXPLANATORY_ONLY",
}

# The authority probe each claim kind is tested against, or None when no mechanical predicate
# exists. `probes.untestable` names the reason for every None.
CLAIM_PROBE = {
    "NAME_ENTRY": "header-atlas+num+tu-ast",
    "SYNOPSIS_DECL": "header-atlas+num+tu-ast",
    "CLI_OPTION": "cli-surface",
    "ENV_VAR": "config-surface",
    "CONFIG_DIRECTIVE": "config-surface",
    "DEFAULT_PATH": "config-surface(default_paths)",
    "DEPRECATION": "num(DEPRECATEDIN)+tu-ast(attributes)",
    "PROVIDER_ALGORITHM": "provider-algorithms",
    "RETURN_VALUE": None,
    "CONCEPT": None,
}

UNTESTABLE_REASON = {
    "RETURN_VALUE": (
        "the RETURN VALUES section is prose; whether a documented success value is the value the "
        "implementation returns is not decidable from the text without executing the function, so "
        "the claim is retained as a quote and no equality probe is asserted"
    ),
    "CONCEPT": (
        "man7 concept and provider-behaviour prose is explanatory; the mechanically defensible part "
        "(NAME, provider identities) is extracted and probed separately"
    ),
}

# Extra disagreement classes this plane adds to the plan's list. They are named, not silent:
# the plan's residual vocabulary ends with "...", and a plane that invented an unnamed class would
# hide it. Each is documented in `body.residual_vocabulary`.
EXTRA_CLASSES = {
    "POD_DEPRECATION_MISMATCH":
        "the manual says a name is deprecated and the ABI/AST planes do not mark it deprecated",
    "POD_PROVIDER_ALGORITHM_MISSING":
        "a man7 provider identity is not an alias of any provider-algorithm registration row",
    "POD_DEFAULT_PATH_MISMATCH":
        "a default pathname the manual states is not among the compiled-in/configured default paths",
    "POD_PAGE_NOT_INSTALLED":
        "a manual page in the corpus has no manpage file in 22.8's installed-distribution manifest",
    "INSTALLED_PAGE_NOT_IN_POD":
        "an installed manpage file is not a page in this corpus",
}

# ---------------------------------------------------------------------------
# POD text utilities
# ---------------------------------------------------------------------------

_HEAD = re.compile(r"^(=head[1-6])[ \t]+(.*\S)[ \t]*$")
_ITEM = re.compile(r"^=item[ \t]+(.*\S)[ \t]*$")
_WS = re.compile(r"\s+")

# B<>, I<>, C<>, F<>, and links. Sufficient for the OpenSSL POD corpus and deliberately shallow:
# this plane extracts names, not rendered prose.
_MARKUP = re.compile(r"[BICFEZX]<([^<>]*)>")
_LINK = re.compile(r"L<([^>|]*)\|([^>]*)>")
_LINK_PLAIN = re.compile(r"L<([^>]*)>")

# A POD item head that is a list of names: every comma/space-separated part is a bare token.
_BARE_NAME = re.compile(r"^[A-Za-z0-9_.][A-Za-z0-9_.\-]*$")


def _norm(text: str) -> str:
    """Whitespace-collapsed, stripped -- the normal form every claim identity uses."""
    return _WS.sub(" ", text).strip()


def strip_pod_markup(text: str) -> str:
    text = _LINK.sub(r"\1", text)
    text = _LINK_PLAIN.sub(r"\1", text)
    text = _MARKUP.sub(r"\1", text)
    for ent, ch in (("E<lt>", "<"), ("E<gt>", ">"), ("E<amp>", "&"), ("E<sol>", "/"),
                    ("E<verbar>", "|"), ("E<quot>", '"'), ("E<apos>", "'")):
        text = text.replace(ent, ch)
    return text


def split_head1(text: str) -> dict[str, list[str]]:
    """The page's `=head1` sections, in document order, as `{NAME: [lines, ...]}`.

    The value is the *first* occurrence's lines; a page that repeats a `=head1` name is not a
    corpus shape OpenSSL produces, and joining would silently merge unrelated blocks.
    """
    sections: dict[str, list[str]] = {}
    current: str | None = None
    for line in text.splitlines():
        m = _HEAD.match(line)
        if m and m.group(1) == "=head1":
            name = m.group(2).strip()
            current = name
            sections.setdefault(name, [])
        elif current is not None:
            sections[current].append(line)
    return sections


def _name_and_notation(head: str) -> list[str]:
    """Every bare name token in a POD item head, or `[]` when the head is prose."""
    toks = re.findall(r"[BICFE]<([^<>]+)>", head)
    candidates = toks if toks else [head]
    out: list[str] = []
    for cand in candidates:
        parts = [p.strip() for p in re.split(r",", strip_pod_markup(cand))]
        if parts and all(_BARE_NAME.match(p) for p in parts if p):
            out.extend(p for p in parts if p)
    return out


# ---------------------------------------------------------------------------
# page parsing (pure) -- the page model the claim graph is derived from
# ---------------------------------------------------------------------------

_RE_INCLUDE = re.compile(r"^#\s*(include|define|if|endif|ifdef|ifndef|else|pragma)\b")
# `=for openssl names: a b c` -- OpenSSL's alias directive inside a NAME block
# (`doc/man1/openssl-cmds.pod.in` writes one); its arguments are names, not prose.
_FOR_NAMES = re.compile(r"^=for\s+openssl\s+names:\s*(.*\S)\s*$")
_RE_DECL_SYM = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_RE_SYNOPSIS_OPT = re.compile(r"B<(-[A-Za-z0-9][A-Za-z0-9_?.\-]*)>")
_RE_ENV_TOKEN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_RE_PATH_IN_F = re.compile(r"F<([^<>]+)>")
_RE_DEPRECATED = re.compile(
    r"([A-Za-z_][A-Za-z0-9_]*)\s*(?:\(\s*\))?\s*"
    r"(?:function|macro|variable|type|method)?\s*"
    r"(?:is|are|was|were|has been|have been)\s+deprecated"
    r"(?:\s+(?:in|since)\s+(?:OpenSSL\s+|version\s+)?([0-9][0-9A-Za-z._]*))?",
    re.IGNORECASE,
)
# An installed manual page as 22.8's manifest names it: `share/man/manN/<page>.<N>ossl`.
_MANPAGE_PATH = re.compile(r"share/man/man([1357])/(.+)\.([1357])ossl$")
_RE_ALG_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]*$")


def _synopsis_declarations(lines: list[str]) -> list[str]:
    """The C declarations of a man3/man7 SYNOPSIS, collision-normalised.

    Lines beginning with `=` (a POD directive) and preprocessor lines are dropped; the rest are
    joined and split on `;`, so a declaration continued across lines is recovered whole. This is
    extraction, not comprehension: the semicolon is the authority's own statement separator.
    """
    code: list[str] = []
    for line in lines:
        t = line.strip()
        if not t or t.startswith("=") or _RE_INCLUDE.match(t):
            continue
        code.append(t)
    text = _norm(" ".join(code))
    out: list[str] = []
    for part in text.split(";"):
        decl = _norm(part)
        if decl:
            out.append(decl)
    return out


def decl_symbol(decl: str) -> str | None:
    """The declared name of a C declaration: the identifier before `(`, else the last one."""
    m = _RE_DECL_SYM.search(decl)
    if m:
        return m.group(1)
    ids = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", decl)
    return ids[-1] if ids else None


def _env_names(lines: list[str]) -> list[str]:
    """Environment-variable names from an env page's top-level `=item` heads only.

    A prose item is skipped: the rule is that the head be a bare list of names, which is how the
    `openssl-env(7)` and `config(5)` pages state theirs. `openssl-env` documents them under
    DESCRIPTION rather than ENVIRONMENT (`=head1 DESCRIPTION`, then `=item B<CTLOG_FILE>`), so the
    caller widens the section for that page. **Nested lists are skipped**: `OPENSSL_TRACE`'s trace
    categories (`ALL`, `BN_CTX`, ...) are a second-level `=over` under one item and are not
    environment variables, so only items at `=over` depth 1 are taken.
    """
    names: set[str] = set()
    depth = 0
    for line in lines:
        t = line.strip()
        if t.startswith("=over"):
            depth += 1
            continue
        if t.startswith("=back"):
            depth = max(0, depth - 1)
            continue
        if depth > 1:
            continue
        m = _ITEM.match(t)
        if not m:
            continue
        for name in _name_and_notation(m.group(1)):
            if _RE_ENV_TOKEN.match(name):
                names.add(name)
    return sorted(names)


def _directive_names(section: int, lines: list[str], text: str) -> list[str]:
    """Configuration directives/settings a man5 page states.

    The syntax directives (`.include`, `.pragma`) appear inline as `B<.include>`; module settings
    appear as `=item` heads (`B<activate>`, `fullname`, `onlyuser, onlyCA`). Only name-shaped
    tokens are taken -- prose item heads are skipped. `lines` is the whole page for a man5 page,
    because the settings live under different `head1` sections in `config(5)`, `fips_config(5)`
    and `x509v3_config(5)`.
    """
    if section != 5:
        return []
    names: set[str] = set(re.findall(r"B<(\.[a-z][a-z0-9]*)>", text))
    head1: str | None = None
    for line in lines:
        m = _HEAD.match(line.strip())
        if m and m.group(1) == "=head1":
            head1 = m.group(2).strip()
            continue
        if head1 == "ENVIRONMENT":
            # The ENVIRONMENT section's items are environment variables, not directives; the
            # environment axis is extracted separately and reconciles against the config plane.
            continue
        mi = _ITEM.match(line.strip())
        if mi:
            names.update(_name_and_notation(mi.group(1)))
    return sorted(n for n in names if not n.startswith("="))


def _default_paths(text: str) -> list[str]:
    """Pathnames the page states as a default.

    Mechanically defensible and deliberately narrow: a line that mentions a default and carries a
    POD `F<>` filename token. `F<>` is the corpus's own notation for a file/path, so the extraction
    is a mark of the source rather than a guess about prose.
    """
    out: set[str] = set()
    for line in text.splitlines():
        if "default" not in line.lower():
            continue
        for raw in _RE_PATH_IN_F.findall(line):
            path = strip_pod_markup(raw).strip()
            if "/" in path or path.endswith((".cnf", ".pem", ".conf")):
                out.add(path)
    return sorted(out)


def _returns(lines: list[str]) -> list[dict]:
    """The RETURN VALUES items, each a `(subject, text)` quote -- never an interpretation.

    An item's subject is the parenthesised call it heads (`=item EVP_MD_fetch()`), taken as the
    quote's key; the text is the item body, whitespace-collapsed. This is a SEMANTIC_TEXT claim:
    it is carried, not understood.
    """
    out: list[dict] = []
    subject: str | None = None
    body: list[str] = []
    for line in lines:
        m = _ITEM.match(line.strip())
        if m:
            if subject is not None:
                out.append({"subject": subject, "text": _norm(" ".join(body))})
            head = strip_pod_markup(m.group(1)).strip()
            subject = head or None
            body = []
        elif subject is not None:
            body.append(line)
    if subject is not None:
        out.append({"subject": subject, "text": _norm(" ".join(body))})
    # The `=over`/`=back` lines are structural, not text.
    for row in out:
        row["text"] = _norm(re.sub(r"^=?(over|back)\b", "", row["text"]))
    return [r for r in out if r["subject"] and r["text"]]


def _deprecations(text: str, known: set[str]) -> list[dict]:
    """Deprecation statements the page makes, as `(subject, since, replacement)`.

    The OpenSSL corpus states deprecation as `X() was deprecated in OpenSSL 3.0; use Y instead` or
    `X() is deprecated`. This extracts the subject and, when present, the version and the stated
    replacement. `known` is the page's own documented names/synopsis symbols: a subject is kept
    only when it is an API-shaped token (has an underscore, is all-caps, or is one of the page's
    own names), which is what keeps the English prose around a deprecation sentence (`This page
    was deprecated ...`) from becoming an assertion. It stays best-effort and is recorded as a
    reduction: a sentence naming several subjects yields the subject adjacent to the verb.
    """
    out: dict[tuple[str, str | None], dict] = {}
    for m in _RE_DEPRECATED.finditer(_norm(text)):
        subject, since = m.group(1), m.group(2)
        if not ("_" in subject or subject.isupper() or subject in known):
            continue
        tail = text[m.end():m.end() + 160]
        repl = re.search(r"use\s+([A-Za-z_][A-Za-z0-9_]*)\s+instead", tail)
        row = {"subject": subject, "since": since,
               "replacement": repl.group(1) if repl else None}
        out[(subject, since)] = row
    return [out[k] for k in sorted(out, key=lambda k: (k[0], k[1] or ""))]


def _identities(section: int, lines: list[str]) -> list[str]:
    """Provider algorithm identities a man7 page states under an `Identities` heading."""
    if section != 7:
        return []
    names: set[str] = set()
    inside = False
    for line in lines:
        m = _HEAD.match(line.strip())
        if m:
            inside = m.group(2).strip().lower() in ("identities", "identity")
            continue
        if not inside:
            continue
        mi = _ITEM.match(line.strip())
        if mi:
            head = strip_pod_markup(mi.group(1)).strip()
            if _RE_ALG_NAME.match(head):
                names.add(head)
        for quoted in re.findall(r'"([^"]+)"', line):
            if _RE_ALG_NAME.match(quoted):
                names.add(quoted)
    return sorted(names)


def parse_page(section: int, page: str, source: str, source_kind: str,
               source_sha256: str, resolved_sha256: str, resolution: str,
               text: str) -> dict:
    """The claim-relevant page model from a resolved page's text. A pure function.

    `text` is the page as the manual publishes it (the `.pod.in` resolved the way the build does);
    `source_sha256` digests the file on disk, `resolved_sha256` the text this model was built from.
    """
    heads = split_head1(text)
    title_names, name_description = parse_name(heads.get("NAME", []))
    synopsis_lines = heads.get("SYNOPSIS", [])
    option_lines = heads.get("OPTIONS", [])

    synopsis_decls: list[str] = []
    options: set[str] = set()
    if section == 3:
        synopsis_decls = _synopsis_declarations(synopsis_lines)
    if section == 1:
        for line in synopsis_lines:
            options.update(_RE_SYNOPSIS_OPT.findall(line))
        for line in option_lines:
            m = _ITEM.match(line.strip())
            if m:
                options.update(_RE_SYNOPSIS_OPT.findall(m.group(1)))

    env_lines = list(heads.get("ENVIRONMENT", []))
    if section == 7 and "environment variable" in name_description.lower():
        # `openssl-env(7)` states its items under DESCRIPTION; the page whose own description
        # says it is the environment-variable page is the one whose DESCRIPTION holds them.
        env_lines = list(heads.get("DESCRIPTION", [])) + env_lines
    environment = _env_names(env_lines)
    directives = _directive_names(section, text.splitlines(), text)

    command = None
    if section == 1 and page.startswith("openssl-"):
        command = page[len("openssl-"):]

    known = set(title_names)
    for decl in synopsis_decls:
        sym = decl_symbol(decl)
        if sym:
            known.add(sym)
    return {
        "page": page,
        "section": section,
        "source": source,
        "source_kind": source_kind,
        "source_sha256": source_sha256,
        "resolved_sha256": resolved_sha256,
        "resolution": resolution,
        "names": title_names,
        "name_description": name_description,
        "synopsis_decls": synopsis_decls,
        "command": command,
        "options": sorted(options),
        "environment": environment,
        "directives": directives,
        "default_paths": _default_paths(text),
        "returns": _returns(heads.get("RETURN VALUES", [])),
        "deprecations": _deprecations(text, known),
        "identities": _identities(section, text.splitlines()),
    }


def parse_name(lines: list[str]) -> tuple[list[str], str]:
    """The `NAME` block's names and description.

    The corpus writes `name1, name2, name3 - description` across lines; the first ` - ` separates
    the name list from the description. The canonical page is the *file* name, so the names here
    are all the symbols the page answers to.

    A `=for openssl names: a b c` directive may also sit in the block (OpenSSL writes one in
    `openssl-cmds.pod.in` to declare the page's extra names); its argument list is part of the
    name set, and the directive line itself must not leak into it. Any other POD directive line is
    dropped rather than joined, so a `=for`/`=begin` never becomes a name.
    """
    named: list[str] = []
    prose: list[str] = []
    for line in lines:
        stripped = line.strip()
        m = _FOR_NAMES.match(stripped)
        if m:
            named.extend(t for t in re.split(r"[\s,]+", m.group(1)) if t)
            continue
        if stripped.startswith("="):
            continue
        prose.append(line)
    text = _norm(" ".join(line.strip() for line in prose if line.strip()))
    if " - " in text:
        left, description = text.split(" - ", 1)
    else:
        left, description = text, ""
    names = [strip_pod_markup(n).strip() for n in left.split(",")]
    return [n for n in (names + named) if n], _norm(strip_pod_markup(description))


# ---------------------------------------------------------------------------
# the claim graph (pure)
# ---------------------------------------------------------------------------

def claim_id(section: int, page: str, kind: str, subject: str, normalized: str) -> str:
    """The stable identity of one extracted assertion, in the plan's own form."""
    return f"PODCLAIM({section}:{page}, {kind}, {subject}, {normalized})"


def extract_claims(pages: list[dict]) -> list[dict]:
    """The machine-readable claim graph from a page model. A pure function.

    Only mechanically defensible extraction becomes an assertion. Every claim is
    `{id, section, page, kind, subject, normalized, class, probe}` with the identity the plan
    prescribes; nothing in the graph asserts a meaning the tool did not extract.
    """
    claims: list[dict] = []

    def add(page: dict, kind: str, subject: str, normalized: str) -> None:
        claims.append({
            "id": claim_id(page["section"], page["page"], kind, subject, normalized),
            "section": page["section"],
            "page": page["page"],
            "kind": kind,
            "subject": subject,
            "normalized": normalized,
            "class": CLAIM_CLASS[kind],
            "probe": CLAIM_PROBE[kind],
        })

    for page in pages:
        for name in page["names"]:
            add(page, "NAME_ENTRY", name, name)
        for decl in page["synopsis_decls"]:
            sym = decl_symbol(decl)
            if sym:
                add(page, "SYNOPSIS_DECL", sym, decl)
        for opt in page["options"]:
            add(page, "CLI_OPTION", opt, opt)
        for name in page["environment"]:
            add(page, "ENV_VAR", name, name)
        for name in page["directives"]:
            add(page, "CONFIG_DIRECTIVE", name, name)
        for path in page["default_paths"]:
            add(page, "DEFAULT_PATH", path, path)
        for row in page["returns"]:
            add(page, "RETURN_VALUE", row["subject"], row["text"])
        for row in page["deprecations"]:
            normalized = "deprecated" + (f" in {row['since']}" if row["since"] else "")
            if row["replacement"]:
                normalized += f"; use {row['replacement']} instead"
            add(page, "DEPRECATION", row["subject"], normalized)
        for name in page["identities"]:
            add(page, "PROVIDER_ALGORITHM", name, name)
        if page["name_description"]:
            add(page, "CONCEPT", page["page"], page["name_description"])

    return sorted(claims, key=lambda c: (c["section"], c["page"], c["kind"], c["subject"],
                                         c["normalized"]))


# ---------------------------------------------------------------------------
# the joined index (I/O) -- the reduction of every plane this tool reconciles against
# ---------------------------------------------------------------------------

def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def load_index(auth) -> dict:
    """The name/option sets the reconciliation joins against, read from the planes on disk.

    Every set is sorted so the index -- and therefore the reconciliation -- is a pure function of
    the inputs. The index is stored inside the artefact (`body.reconciliation.index`) so the court
    re-derives the reconciliation from the committed evidence rather than re-reading the planes.
    """
    atlas_dir = authority_atlas_dir(auth.id)

    atlas_names: set[str] = set()
    atlas_deprecated: set[str] = set()
    header_not_pod_sources: list[str] = []
    for key, relpath in (("functions", "functions.json"), ("macros", "macros.json"),
                         ("typedefs", "typedefs.json"), ("enums", "enums.json"),
                         ("structs", "structs.json"), ("variables", "variables.json")):
        path = atlas_dir / relpath
        if not path.is_file():
            header_not_pod_sources.append(f"{key}:absent")
            continue
        body = _load_json(path)["body"]
        for rec in body.get("records", []):
            name = rec.get("name")
            if name:
                atlas_names.add(name)
                if rec.get("deprecated"):
                    atlas_deprecated.add(name)

    num_names: set[str] = set()
    deprecated_names: set[str] = set()
    for numrel in NUM_RELS:
        path = auth.source / numrel
        if not path.is_file():
            continue
        entries, _unparsed = parse_num_file(path)
        for e in entries:
            if e.declared_nonexistent or e.platform_scoped_away:
                continue
            num_names.add(e.symbol)
            if e.deprecated:
                deprecated_names.add(e.symbol)

    tu_names: set[str] = set()
    tu_path = REPO_ROOT / PLANE_PATHS["tu-ast"]
    if tu_path.is_file():
        body = _load_json(tu_path)["body"]
        for ent in body.get("entities", []):
            if ent.get("kind") in ("function", "variable", "typedef", "struct", "union", "enum"):
                tu_names.add(ent["name"])

    doxygen_names: set[str] = set()
    dox_path = REPO_ROOT / PLANE_PATHS["doxygen-entities"]
    if dox_path.is_file():
        body = _load_json(dox_path)["body"]
        for ent in body.get("entities", []):
            if ent.get("kind") in ("function", "macro", "typedef", "enum", "struct",
                                   "union", "variable"):
                doxygen_names.add(ent["name"])

    cli_commands: list[str] = []
    cli_options: dict[str, list[str]] = {}
    cli_path = REPO_ROOT / PLANE_PATHS["cli-surface"]
    if cli_path.is_file():
        body = _load_json(cli_path)["body"]
        for cmd in body.get("commands", []):
            cli_commands.append(cmd["name"])
            opts = sorted({o["name"] for o in cmd.get("options", [])})
            cli_options[cmd["name"]] = opts
        cli_commands = sorted(cli_commands)

    env_vars: list[str] = []
    directives: list[str] = []
    default_paths: list[str] = []
    config_path = REPO_ROOT / PLANE_PATHS["config-surface"]
    if config_path.is_file():
        body = _load_json(config_path)["body"]
        env_vars = sorted({e["name"] for e in body.get("env_vars", [])})
        directives = sorted({d["name"] for d in body.get("directives", [])})
        for d in body.get("default_paths", []):
            default_paths.append(d.get("name", ""))
            default_paths.append(str(d.get("value", "")))
        default_paths = sorted({p for p in default_paths if p})

    provider_aliases: set[str] = set()
    prov_path = REPO_ROOT / PLANE_PATHS["provider-algorithms"]
    if prov_path.is_file():
        body = _load_json(prov_path)["body"]
        for row in body.get("rows", []):
            for a in row.get("aliases", []):
                provider_aliases.add(a)
            if row.get("algorithm_names"):
                provider_aliases.add(row["algorithm_names"])
    provider_aliases.discard(None)

    # 22.8's installed distribution: the manpage files the authority's own `make install` wrote,
    # keyed `section:page`. The symlinks are the manual's aliases made concrete; they are counted
    # rather than reconciled per row, because the install target's naming is the authority's own.
    installed_pages: set[str] = set()
    installed_symlinks: int = 0
    manifest_path = REPO_ROOT / PLANE_PATHS["install-manifest"]
    if manifest_path.is_file():
        body = _load_json(manifest_path)["body"]
        for entry in body.get("entries", []):
            m = _MANPAGE_PATH.match(entry.get("path", ""))
            if not m:
                continue
            if entry.get("category") == "manpage":
                installed_pages.add(f"{m.group(1)}:{m.group(2)}")
            elif entry.get("category") == "symlink":
                installed_symlinks += 1

    return {
        "atlas_names": sorted(atlas_names),
        "atlas_deprecated": sorted(atlas_deprecated),
        "atlas_names_absent": sorted(header_not_pod_sources),
        "num_names": sorted(num_names),
        "deprecated_names": sorted(deprecated_names),
        "tu_names": sorted(tu_names),
        "doxygen_names": sorted(doxygen_names),
        "cli_commands": cli_commands,
        "cli_options": cli_options,
        "env_vars": env_vars,
        "directives": directives,
        "default_paths": default_paths,
        "provider_aliases": sorted(provider_aliases),
        "installed_pages": sorted(installed_pages),
        "installed_symlinks": installed_symlinks,
    }


# ---------------------------------------------------------------------------
# reconciliation (pure)
# ---------------------------------------------------------------------------

def reconcile(claims: list[dict], pages: list[dict], index: dict) -> dict:
    """Join the claim graph against the planes and classify every disagreement. A pure function.

    **A disagreement is the result, not a preference.** The manual is never silently preferred to
    the runtime, nor the reverse: each is attributed to its class. `index` is the reduction stored
    in the artefact, so this is re-derivable by the court without re-reading the planes.
    """
    atlas = set(index["atlas_names"])
    atlas_deprecated = set(index.get("atlas_deprecated", []))
    num = set(index["num_names"])
    deprecated = set(index["deprecated_names"])
    tu = set(index["tu_names"])
    doxygen = set(index["doxygen_names"])
    cli_commands = index["cli_commands"]
    cli_options = {k: set(v) for k, v in index["cli_options"].items()}
    env_vars = set(index["env_vars"])
    directives = set(index["directives"])
    default_paths = set(index["default_paths"])
    provider_aliases = set(index["provider_aliases"])

    disagreements: list[dict] = []

    def record(cls: str, page: str, subject: str, detail: str) -> None:
        disagreements.append({"class": cls, "page": page, "subject": subject, "detail": detail})

    # The documented-name set the reverse direction is measured against: every man3 NAME entry.
    documented: set[str] = set()
    name_pages: dict[str, list[str]] = {}
    for page in pages:
        if page["section"] != 3:
            continue
        for name in page["names"]:
            documented.add(name)
            name_pages.setdefault(name, []).append(page["page"])
    for name, pages_ in name_pages.items():
        if len(pages_) > 1:
            record("POD_AMBIGUOUS", pages_[0], name,
                   "documented by more than one man3 page: " + ", ".join(sorted(pages_)))

    cli_pages: dict[str, dict] = {p["command"]: p for p in pages
                                  if p["section"] == 1 and p["command"]}
    documented_options: dict[str, set[str]] = {}

    for claim in claims:
        kind, subject, page = claim["kind"], claim["subject"], claim["page"]
        if kind in ("NAME_ENTRY", "SYNOPSIS_DECL"):
            if subject not in atlas and subject not in num:
                where = [name for name, present in (("the whole-program AST", subject in tu),
                                                    ("the Doxygen entity graph",
                                                     subject in doxygen))
                         if present]
                detail = ("not in the public header/API atlas nor the .num ABI inventory"
                          + (("; present in " + " and ".join(where)) if where
                             else "; absent from the other joined planes as well"))
                record("POD_NAME_NOT_IN_ATLAS", page, subject, detail)
        elif kind == "CLI_OPTION":
            cmd = next((p["command"] for p in pages if p["page"] == page), None)
            if cmd is None:
                continue  # an option-group page (format-options, ...) has no runtime command
            norm = subject.lstrip("-")
            runtime = cli_options.get(cmd, set())
            documented_options.setdefault(cmd, set()).add(norm)
            if cmd in cli_commands and norm not in runtime:
                record("POD_CLI_OPTION_MISSING", page, subject,
                       f"documented for command {cmd!r} but absent from its runtime option set")
        elif kind == "ENV_VAR":
            if subject not in env_vars:
                record("POD_ENVIRONMENT_VARIABLE_MISSING", page, subject,
                       "documented in the manual but not read by the authority's config/env plane")
        elif kind == "CONFIG_DIRECTIVE":
            if subject not in directives:
                record("POD_CONFIG_DIRECTIVE_MISSING", page, subject,
                       "documented in the manual but absent from the config plane's directive set")
        elif kind == "DEFAULT_PATH":
            if not any(subject == p or subject in p or p.endswith(subject)
                       for p in default_paths):
                record("POD_DEFAULT_PATH_MISMATCH", page, subject,
                       "stated default path is not among the compiled-in/configured default paths")
        elif kind == "DEPRECATION":
            if subject not in deprecated and subject not in atlas_deprecated and subject not in tu:
                record("POD_DEPRECATION_MISMATCH", page, subject,
                       "manual states the name is deprecated; the ABI/AST planes do not mark it")
        elif kind == "PROVIDER_ALGORITHM" and subject not in provider_aliases:
            record("POD_PROVIDER_ALGORITHM_MISSING", page, subject,
                   "man7 provider identity is not an alias of any provider-algorithm row")

    # Reverse direction: a public runtime CLI option no man1 page documents.
    for cmd in sorted(cli_pages):
        if cmd not in cli_options:
            continue
        docs_for_cmd = documented_options.get(cmd, set())
        for opt in sorted(cli_options[cmd]):
            if opt not in docs_for_cmd:
                record("RUNTIME_CLI_OPTION_UNDOCUMENTED", cli_pages[cmd]["page"], "-" + opt,
                       f"runtime option of command {cmd!r} is not documented by its man1 page")

    # Reverse direction: a public ABI name no man3 page documents. `documented` is the man3 NAME
    # set; `num - documented` is directly comparable to `util/find-doc-nits`'s own figure.
    for name in sorted(num - documented):
        record("ATLAS_PUBLIC_NAME_NOT_IN_POD", "man3", name,
               "in the .num ABI inventory but no man3 NAME entry documents it")

    # Reverse direction: an installed manpage 22.8 wrote that is not a page in this corpus.
    installed = set(index.get("installed_pages", []))
    pod_pages = {f"{p['section']}:{p['page']}" for p in pages}
    for page in pages:
        if installed and f"{page['section']}:{page['page']}" not in installed:
            record("POD_PAGE_NOT_INSTALLED", page["page"], page["page"],
                   "corpus page has no manpage file in the installed-distribution manifest")
    for key in sorted(installed - pod_pages):
        section, _, name = key.partition(":")
        record("INSTALLED_PAGE_NOT_IN_POD", name, name,
               f"installed man{section} page is not in this corpus")

    # The header-atlas variant is a far larger set (the public headers name ~26k macros and
    # types); it is reported as a count rather than 26k rows, because the per-row list is
    # dominated by non-API macros and would bury the ABI-vs-manual figure the plan names.
    aux_counts = {
        "documented_man3_names": len(documented),
        "num_names_total": len(num),
        "atlas_header_names_total": len(atlas),
        "atlas_header_names_not_in_pod": len(atlas - documented),
        "installed_manpages": len(installed),
        "installed_manpage_symlinks": index.get("installed_symlinks", 0),
    }

    disagreements.sort(key=lambda d: (d["class"], d["page"], d["subject"], d["detail"]))
    counts: dict[str, int] = {}
    for d in disagreements:
        counts[d["class"]] = counts.get(d["class"], 0) + 1
    return {
        "disagreements": disagreements,
        "counts_by_class": dict(sorted(counts.items())),
        "aux_counts": aux_counts,
    }


# ---------------------------------------------------------------------------
# body assembly (pure)
# ---------------------------------------------------------------------------

def summarize(pages: list[dict], claims: list[dict], recon: dict) -> dict:
    """Every count this plane reports, derived from the model -- never typed."""
    by_kind: dict[str, int] = {}
    by_class: dict[str, int] = {}
    for c in claims:
        by_kind[c["kind"]] = by_kind.get(c["kind"], 0) + 1
        by_class[c["class"]] = by_class.get(c["class"], 0) + 1
    pages_by_section: dict[str, int] = {}
    for p in pages:
        pages_by_section[str(p["section"])] = pages_by_section.get(str(p["section"]), 0) + 1
    return {
        "pages": len(pages),
        "pages_by_section": dict(sorted(pages_by_section.items())),
        "pages_generated": sum(1 for p in pages if p["source_kind"] == "pod.in"),
        "names": sum(len(p["names"]) for p in pages),
        "synopsis_decls": sum(len(p["synopsis_decls"]) for p in pages),
        "cli_options": sum(len(p["options"]) for p in pages),
        "cli_command_pages": sum(1 for p in pages if p["command"]),
        "environment_variables": sum(len(p["environment"]) for p in pages),
        "config_directives": sum(len(p["directives"]) for p in pages),
        "default_paths": sum(len(p["default_paths"]) for p in pages),
        "return_values": sum(len(p["returns"]) for p in pages),
        "deprecations": sum(len(p["deprecations"]) for p in pages),
        "provider_algorithms": sum(len(p["identities"]) for p in pages),
        "claims": len(claims),
        "claims_by_kind": dict(sorted(by_kind.items())),
        "claims_by_class": dict(sorted(by_class.items())),
        "disagreements": len(recon["disagreements"]),
        "disagreements_by_class": recon["counts_by_class"],
        "atlas_header_names_not_in_pod": recon["aux_counts"]["atlas_header_names_not_in_pod"],
        "documented_man3_names": recon["aux_counts"]["documented_man3_names"],
        "num_names_total": recon["aux_counts"]["num_names_total"],
        "installed_manpages": recon["aux_counts"]["installed_manpages"],
        "installed_manpage_symlinks": recon["aux_counts"]["installed_manpage_symlinks"],
    }


def build_body(pages: list[dict], index: dict) -> dict:
    """The derived body: claim graph, reconciliation and counts. A pure function.

    `RT-PHASE22-POD` drives this on the committed artefact's own page model and index and on
    controlled in-memory mutations of the model, so it must stay free of I/O.
    """
    claims = extract_claims(pages)
    recon = reconcile(claims, pages, index)

    probes_true: dict[str, int] = {}
    probes_untestable: dict[str, dict] = {}
    for c in claims:
        if c["probe"]:
            probes_true[c["kind"]] = probes_true.get(c["kind"], 0) + 1
        else:
            slot = probes_untestable.setdefault(
                c["kind"], {"class": c["class"], "count": 0,
                            "reason": UNTESTABLE_REASON.get(c["kind"], "no probe exists")})
            slot["count"] += 1

    return {
        "claims": claims,
        "reconciliation": {
            "index": index,
            "disagreements": recon["disagreements"],
            "counts_by_class": recon["counts_by_class"],
            "aux_counts": recon["aux_counts"],
        },
        "counts": summarize(pages, claims, recon),
        "probes": {
            "testable_by_kind": dict(sorted(probes_true.items())),
            "untestable": [probes_untestable[k] for k in sorted(probes_untestable)],
        },
    }


# ---------------------------------------------------------------------------
# find-doc-nits -- one instrument, not the oracle
# ---------------------------------------------------------------------------

_FDN_CRYPTO = re.compile(r"^#\s+(\d+)\s+libcrypto names are not documented", re.MULTILINE)
_FDN_SSL = re.compile(r"^#\s+(\d+)\s+libssl names are not documented", re.MULTILINE)
_FDN_MACROS = re.compile(r"^#\s+(\d+)\s+macros undocumented", re.MULTILINE)
_FDN_LINK = re.compile(r"^(.*?):\d+:\s*reference to non-existing\s+(\S+)$", re.MULTILINE)


def run_find_doc_nits(auth, scratch: Path) -> dict:
    """Run the authority's own `util/find-doc-nits` and retain its complete raw output.

    It is run from the admitted **build** directory (so it reads the build's own `configdata.pm`)
    with every check enabled. Its output is one instrument's report -- it is deliberately **not**
    treated as the oracle: its selection includes `doc/internal`, it reads `include/openssl/*.h`
    and the `.num` inventory rather than this plane's corpus, and a clean run would not prove a
    manual correct. See `docs/PHASE-22-SUBPHASES.md` section 6.
    """
    build_dir = authority_build_dir(auth.id)
    script = auth.source / "util" / "find-doc-nits"
    docdir = auth.source / "doc"
    argv = ["perl", "-I.", f"-I{docdir}", "-Mconfigdata", "-Mperlvars", str(script),
            "-n", "-u", "-l", "-a", "-c"]
    proc = subprocess.run(argv, cwd=str(build_dir), capture_output=True, text=True, check=False)
    stdout, stderr = proc.stdout, proc.stderr
    # The invocation is recorded with the authority's own absolute paths folded to a placeholder,
    # so the document carries a repository-relative statement rather than the container's mount.
    recorded_argv = [t.replace(str(auth.source), "<AUTHORITY-SRC>").replace(str(build_dir),
                                                                          "<AUTHORITY-BUILD>")
                     for t in argv]
    links = [{"page": m.group(1), "target": m.group(2)} for m in _FDN_LINK.finditer(stdout)]
    summary = {
        "libcrypto_names_not_documented": _int_group(_FDN_CRYPTO.search(stdout)),
        "libssl_names_not_documented": _int_group(_FDN_SSL.search(stdout)),
        "macros_undocumented": _int_group(_FDN_MACROS.search(stdout)),
        "reference_to_nonexisting": len(links),
    }
    return {
        "instrument": "util/find-doc-nits",
        "role": "one instrument, not the oracle",
        "argv": recorded_argv,
        "cwd": rel(build_dir),
        "returncode": proc.returncode,
        "stdout": stdout,
        "stderr": stderr,
        "stdout_sha256": _sha_text(stdout),
        "stderr_sha256": _sha_text(stderr),
        "summary": summary,
        "reference_to_nonexisting": sorted(links, key=lambda d: (d["page"], d["target"])),
        "note": (
            "Retained complete and raw. find-doc-nits is OpenSSL's own documentation linter, run "
            "from the admitted build directory; it selects the public and internal manuals from "
            "configdata.pm, not from this plane's public corpus, so its figures are a cross-check "
            "and never the plane's oracle. Its stderr carries the instrument's own git-probe "
            "usage text (the pinned container's git does not implement `git config get`), which "
            "find-doc-nits handles with a fallback; the noise is retained rather than hidden."
        ),
    }


def _int_group(m) -> int | None:
    return int(m.group(1)) if m else None


def _sha_text(text: str) -> str:
    import hashlib
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# corpus resolution (I/O)
# ---------------------------------------------------------------------------

def corpus_pages(auth) -> list[tuple[int, str, Path, str]]:
    """Every public manual page in the four sections: `(section, page, path, kind)`."""
    out: list[tuple[int, str, Path, str]] = []
    for section in SECTIONS:
        directory = auth.source / CORPUS_REL / SECTION_DIR[section]
        if not directory.is_dir():
            continue
        for path in sorted(directory.iterdir()):
            if path.suffix == ".pod":
                out.append((section, path.stem, path, "pod"))
            elif path.name.endswith(".pod.in"):
                out.append((section, path.name[: -len(".pod.in")], path, "pod.in"))
    return sorted(out, key=lambda r: (r[0], r[1]))


def resolve_page(auth, path: Path, kind: str, scratch: Path, *, dofile: bool) -> tuple[str, str, str]:
    """The published text of one page, its resolver, and the resolver's provenance.

    A plain `.pod` is read as written. A `.pod.in` is a template: the authority's own
    `util/dofile.pl` is run from the admitted build directory with the build's own relative input
    path, so the resolved text equals the page the build generated. `dofile=False` (or a build
    without `perl`) falls back to the generated page if the build wrote one, else to the
    unresolved template -- and the returned resolution says which happened.
    """
    source_text = path.read_text(encoding="utf-8")
    if kind == "pod":
        return source_text, "as-written", "plain .pod, read as written"

    if dofile:
        build_dir = authority_build_dir(auth.id)
        relpath = os.path.relpath(path, build_dir)
        argv = ["perl", "-I.", f"-I{auth.source / 'doc'}", "-Mconfigdata", "-Mperlvars",
                str(auth.source / "util" / "dofile.pl"), "-oMakefile", relpath]
        try:
            proc = subprocess.run(argv, cwd=str(build_dir), capture_output=True, text=True,
                                  check=False)
        except OSError:
            proc = None
        if proc is not None and proc.returncode == 0 and proc.stdout:
            return proc.stdout, "dofile", f"util/dofile.pl, input {relpath}"

    # The build writes the generated page at `<build>/doc/manN/<page>.pod`.
    section = next((s for s in SECTIONS if path.parent.name == SECTION_DIR[s]), None)
    if section is not None:
        candidate = (authority_build_dir(auth.id) / CORPUS_REL
                     / SECTION_DIR[section] / (path.stem + ".pod"))
        if candidate.is_file():
            return candidate.read_text(encoding="utf-8"), "generated-pod", \
                f"the build's generated page {rel(candidate)}"

    return source_text, "unresolved", \
        "the template could not be resolved (no dofile.pl and no build-generated page)"


def build_pages(auth, scratch: Path, *, dofile: bool) -> list[dict]:
    pages: list[dict] = []
    for section, page, path, kind in corpus_pages(auth):
        text, resolution, provenance = resolve_page(auth, path, kind, scratch, dofile=dofile)
        model = parse_page(
            section, page, rel(path), kind, sha256_file(path), _sha_text(text), resolution, text)
        model["resolution_provenance"] = provenance
        pages.append(model)
    return sorted(pages, key=lambda p: (p["section"], p["page"]))


# ---------------------------------------------------------------------------
# census (generated from the artefact, never typed)
# ---------------------------------------------------------------------------

def render_census(body: dict) -> str:
    c = body["counts"]
    recon = body["reconciliation"]
    d = recon["counts_by_class"]
    fdn = body["find_doc_nits"]
    lines: list[str] = []
    lines.append("# The Phase-22 POD census")
    lines.append("")
    lines.append("Generated from `forensics/atlas/phase22/pod-contract.json` by")
    lines.append("`forensics/tools/phase22_pod.py`; every number below is derived, none is typed.")
    lines.append("")
    lines.append("## The corpus")
    lines.append("")
    lines.append(f"- manual pages: **{c['pages']}** "
                 f"(man1 {c['pages_by_section'].get('1', 0)}, "
                 f"man3 {c['pages_by_section'].get('3', 0)}, "
                 f"man5 {c['pages_by_section'].get('5', 0)}, "
                 f"man7 {c['pages_by_section'].get('7', 0)})")
    lines.append(f"- generated from a `.pod.in` template: **{c['pages_generated']}** "
                 f"(resolved the way the build does)")
    lines.append(f"- `NAME` entries: **{c['names']}**")
    lines.append(f"- SYNOPSIS declarations (man3): **{c['synopsis_decls']}**")
    lines.append(f"- man1 command pages: **{c['cli_command_pages']}**, documented CLI options: "
                 f"**{c['cli_options']}**")
    lines.append(f"- environment variables: **{c['environment_variables']}**")
    lines.append(f"- configuration directives: **{c['config_directives']}**")
    lines.append(f"- default pathnames: **{c['default_paths']}**")
    lines.append(f"- documented return values: **{c['return_values']}**")
    lines.append(f"- deprecation statements: **{c['deprecations']}**")
    lines.append(f"- provider algorithm identities (man7): **{c['provider_algorithms']}**")
    lines.append("")
    lines.append("## The claim graph")
    lines.append("")
    lines.append(f"- claims: **{c['claims']}**")
    lines.append("")
    lines.append("| kind | class | claims |")
    lines.append("|---|---|---|")
    for kind, n in c["claims_by_kind"].items():
        cls = CLAIM_CLASS.get(kind, "?")
        lines.append(f"| {kind} | {cls} | {n} |")
    lines.append("")
    lines.append("| class | claims |")
    lines.append("|---|---|")
    for cls, n in c["claims_by_class"].items():
        lines.append(f"| {cls} | {n} |")
    lines.append("")
    lines.append("## Testability")
    lines.append("")
    lines.append("| kind | probe | claims |")
    lines.append("|---|---|---|")
    for kind, n in body["probes"]["testable_by_kind"].items():
        lines.append(f"| {kind} | {CLAIM_PROBE[kind]} | {n} |")
    lines.append("")
    lines.append("`UNTESTABLE` -- claims with no mechanical predicate, and why:")
    lines.append("")
    for row in body["probes"]["untestable"]:
        lines.append(f"- **{row['class']}** ({row['count']} claims): {row['reason']}")
    lines.append("")
    lines.append("## The reconciliation")
    lines.append("")
    lines.append(f"- disagreements: **{c['disagreements']}**")
    lines.append(f"- man3 `NAME` entries documented: **{c['documented_man3_names']}**")
    lines.append(f"- `.num` ABI names in the admitted profile: **{c['num_names_total']}**")
    lines.append(f"- installed manpage files (22.8's manifest): **{c['installed_manpages']}** "
                 f"plus **{c['installed_manpage_symlinks']}** alias symlinks")
    lines.append(f"- public header/API atlas names not documented by any man3 `NAME` entry "
                 f"(combined count, per-row list not emitted): "
                 f"**{c['atlas_header_names_not_in_pod']}**")
    lines.append("")
    lines.append("| class | count |")
    lines.append("|---|---|")
    for cls, n in d.items():
        lines.append(f"| {cls} | {n} |")
    lines.append("")
    lines.append("## find-doc-nits (one instrument, not the oracle)")
    lines.append("")
    lines.append(f"- `util/find-doc-nits` exit code: {fdn['returncode']}")
    lines.append(f"- libcrypto names not documented: "
                 f"{fdn['summary']['libcrypto_names_not_documented']}")
    lines.append(f"- libssl names not documented: {fdn['summary']['libssl_names_not_documented']}")
    lines.append(f"- macros undocumented: {fdn['summary']['macros_undocumented']}")
    lines.append(f"- reference-to-non-existing links: "
                 f"{fdn['summary']['reference_to_nonexisting']}")
    lines.append("")
    if body.get("gaps"):
        lines.append("## Gaps and reductions, named")
        lines.append("")
        for gap in body["gaps"]:
            lines.append(f"- {gap}")
        lines.append("")
    lines.append("SPDX-License-Identifier: Apache-2.0")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    ap.add_argument("--scratch", default="/tmp/phase22-pod")
    ap.add_argument("--no-dofile", action="store_true",
                    help="do not invoke perl/dofile.pl; use the build's generated pages")
    ap.add_argument("--no-census", action="store_true")
    args = ap.parse_args(argv)

    auth = resolve_authority(args.authority)
    scratch = Path(args.scratch)
    scratch.mkdir(parents=True, exist_ok=True)

    print(f"[phase22-pod] resolving {len(corpus_pages(auth))} public manual pages ...")
    pages = build_pages(auth, scratch, dofile=not args.no_dofile)

    print("[phase22-pod] joining the header/API, doxygen, AST, CLI, config, provider planes ...")
    index = load_index(auth)

    print("[phase22-pod] running util/find-doc-nits ...")
    docnits = run_find_doc_nits(auth, scratch)

    derived = build_body(pages, index)
    corpus = {
        "authority": auth.id,
        "source_root": rel(auth.source),
        "corpus_relative": CORPUS_REL,
        "sections": list(SECTIONS),
        "pod_in_templates": sum(1 for p in pages if p["source_kind"] == "pod.in"),
        "resolution": "util/dofile.pl run from the admitted build directory, or the build's "
                      "generated page; per page in `pages[].resolution`",
        "page_identity": "the file name without its extension is the canonical page; `names` are "
                         "the NAME entries the page answers to",
    }

    body = {
        "corpus": corpus,
        "pages": pages,
        "find_doc_nits": docnits,
        "claims": derived["claims"],
        "reconciliation": derived["reconciliation"],
        "probes": derived["probes"],
        "counts": derived["counts"],
        "residual_vocabulary": {
            "plan": ["POD_NAME_NOT_IN_ATLAS", "ATLAS_PUBLIC_NAME_NOT_IN_POD",
                     "POD_CLI_OPTION_MISSING", "RUNTIME_CLI_OPTION_UNDOCUMENTED",
                     "POD_ENVIRONMENT_VARIABLE_MISSING", "POD_CONFIG_DIRECTIVE_MISSING",
                     "POD_AMBIGUOUS", "UNKNOWN"],
            "extensions": EXTRA_CLASSES,
        },
        "gaps": [
            ("man7 concept extraction is partial: the NAME description and the provider "
             "`Identities` lists are extracted and probed, but provider-behaviour prose is "
             "EXPLANATORY_ONLY and untestable -- it is not turned into an assertion"),
            ("RETURN VALUES quotes are SEMANTIC_TEXT: the text is retained but its "
             "success/failure semantics are not mechanically decided (UNTESTABLE)"),
            ("deprecation extraction is sentence-level and best-effort; a sentence naming several "
             "subjects yields the subject adjacent to the verb (recorded, not hidden)"),
            ("default-pathname extraction is narrow by construction: only a `F<>` token on a line "
             "mentioning a default, which is a mark of the corpus rather than a parse of prose"),
            ("`util/find-doc-nits` is one instrument and its stderr carries the pinned "
             "container's git-probe usage text; both are retained raw"),
            ("`docs/PHASE-22-SUBPHASES.md` section 5 lists a separate "
             "`pod-atlas-reconciliation.json`; this plane folds the reconciliation into "
             "`pod-contract.json` (the artefact this task names) rather than emitting a second "
             "document"),
        ],
    }

    doc = envelope(
        kind="phase22-pod-contract",
        authority=auth.id,
        inputs=_inputs(auth),
        body=body,
        generator=GENERATOR,
    )
    write_json(OUT, doc)
    if not args.no_census:
        from atlas_common import write_text
        write_text(CENSUS, render_census(body))

    c = body["counts"]
    print(f"[phase22-pod] pages={c['pages']} names={c['names']} syms={c['synopsis_decls']} "
          f"claims={c['claims']} disagreements={c['disagreements']}")
    print(f"[phase22-pod] find-doc-nits rc={docnits['returncode']} "
          f"crypto-undoc={docnits['summary']['libcrypto_names_not_documented']} "
          f"ssl-undoc={docnits['summary']['libssl_names_not_documented']}")
    print(f"[phase22-pod] disagreements by class: {c['disagreements_by_class']}")
    print(f"[phase22-pod] -> {rel(OUT)}")
    return 0


def _inputs(auth) -> list[InputRef]:
    # The manual corpus is not a single file: every page's own digest is recorded in
    # `body.pages[].source_sha256`, so the corpus is self-addressing rather than bound by a
    # directory digest (which the envelope cannot take).
    inputs: list[InputRef] = []
    for name, path in PLANE_PATHS.items():
        p = REPO_ROOT / path
        if p.is_file():
            inputs.append(InputRef(name=name, path=p))
    for numrel in NUM_RELS:
        p = auth.source / numrel
        if p.is_file():
            inputs.append(InputRef(name="num:" + numrel, path=p))
    fdn = auth.source / "util" / "find-doc-nits"
    if fdn.is_file():
        inputs.append(InputRef(name="find-doc-nits", path=fdn))
    return inputs


# ---------------------------------------------------------------------------
# the court -- RT-PHASE22-POD
# ---------------------------------------------------------------------------

def _by_claim_id(claims: list[dict]) -> dict[str, dict]:
    return {c["id"]: c for c in claims}


def _count_for_kind(claims: list[dict], kind: str) -> int:
    return sum(1 for c in claims if c["kind"] == kind)


def _class_counts(disagreements: list[dict]) -> dict[str, int]:
    out: dict[str, int] = {}
    for d in disagreements:
        out[d["class"]] = out.get(d["class"], 0) + 1
    return out


def _target(pages: list[dict], predicate):
    return next((i for i, p in enumerate(pages) if predicate(p)), None)


def _replace_page(pages: list[dict], idx: int, **changes) -> list[dict]:
    mutated = copy.deepcopy(pages)
    mutated[idx].update(changes)
    return mutated


def _run_checks(pages: list[dict], index: dict, base_claims: list[dict], base_recon: dict,
                extractor=extract_claims, reconciler=reconcile) -> list[tuple[str, bool]]:
    """Every RT-PHASE22-POD assertion, run against an injectable extractor/reconciler.

    The court runs these with the real functions and, for the sensitivity proof, with deliberately
    broken ones; the broken run must fail them or the court is not an instrument.
    """
    checks: list[tuple[str, bool]] = []

    def derive(pgs):
        cl = extractor(pgs)
        return cl, reconciler(cl, pgs, index)

    base = derive(pages)
    checks.append(("baseline: the corpus has pages", len(pages) > 0))
    checks.append(("baseline: the claim graph is non-empty", len(base_claims) > 0))
    checks.append(("baseline: the graph has a reconciliation", base_recon["disagreements"] is not None))
    checks.append(("baseline: some disagreements were classified",
                   len(base_recon["disagreements"]) > 0))

    # -- round trip -------------------------------------------------------
    checks.append(("round-trip: claims equal the committed graph",
                   base[0] == base_claims))
    checks.append(("round-trip: reconciliation equals the committed reconciliation",
                   base[1] == base_recon))

    # 1. delete a NAME alias
    idx = _target(pages, lambda p: len(p["names"]) >= 2)
    if idx is None:
        checks.append(("delete-name: a page with an alias was found", False))
    else:
        victim = pages[idx]["names"][-1]
        mutated = copy.deepcopy(pages)
        mutated[idx]["names"] = mutated[idx]["names"][:-1]
        cl, _ = derive(mutated)
        checks.append(("delete-name: NAME_ENTRY claims fell by one",
                       _count_for_kind(cl, "NAME_ENTRY")
                       == _count_for_kind(base_claims, "NAME_ENTRY") - 1))
        checks.append(("delete-name: the alias left the graph",
                       not any(c["kind"] == "NAME_ENTRY" and c["subject"] == victim
                               and c["page"] == pages[idx]["page"] for c in cl)))

    # 2. add a fake public function to a SYNOPSIS
    idx = _target(pages, lambda p: p["section"] == 3 and p["synopsis_decls"])
    if idx is None:
        checks.append(("add-synopsis: a man3 page with a SYNOPSIS was found", False))
    else:
        fake = "int PODPROBE_fake_function(PODPROBE_CTX *ctx, int flag);"
        mutated = _replace_page(pages, idx, synopsis_decls=pages[idx]["synopsis_decls"] + [fake])
        cl, recon = derive(mutated)
        checks.append(("add-synopsis: a SYNOPSIS_DECL claim was added",
                       _count_for_kind(cl, "SYNOPSIS_DECL")
                       == _count_for_kind(base_claims, "SYNOPSIS_DECL") + 1))
        checks.append(("add-synopsis: the fake name is reconciled as POD_NAME_NOT_IN_ATLAS",
                       any(d["class"] == "POD_NAME_NOT_IN_ATLAS"
                           and d["subject"] == "PODPROBE_fake_function"
                           for d in recon["disagreements"])))

    # 3. alter a parameter type
    idx = _target(pages, lambda p: any("(" in d and ")" in d for d in p["synopsis_decls"]))
    if idx is None:
        checks.append(("alter-param: a parameterised SYNOPSIS declaration was found", False))
    else:
        decls = list(pages[idx]["synopsis_decls"])
        j = next(i for i, d in enumerate(decls) if "(" in d)
        old = decls[j]
        decls[j] = re.sub(r"\bint\b", "long", old, count=1)
        if decls[j] == old:
            decls[j] = old.replace("(", "(PODPROBE_T ", 1)
        mutated = _replace_page(pages, idx, synopsis_decls=decls)
        cl, _ = derive(mutated)
        old_ids = {c["id"] for c in base_claims}
        new_ids = {c["id"] for c in cl}
        checks.append(("alter-param: the declaration's identity changed", old_ids != new_ids))
        checks.append(("alter-param: exactly one SYNOPSIS_DECL claim moved",
                       _count_for_kind(cl, "SYNOPSIS_DECL")
                       == _count_for_kind(base_claims, "SYNOPSIS_DECL")
                       and len(old_ids ^ new_ids) == 2))

    # 4. change a documented return value
    idx = _target(pages, lambda p: p["returns"])
    if idx is None:
        checks.append(("change-return: a page with a RETURN VALUES item was found", False))
    else:
        rets = copy.deepcopy(pages[idx]["returns"])
        rets[0]["text"] = "Returns PODPROBE_CHANGED for success or NULL for failure."
        mutated = _replace_page(pages, idx, returns=rets)
        cl, _ = derive(mutated)
        old_ids = {c["id"] for c in base_claims if c["kind"] == "RETURN_VALUE"}
        new_ids = {c["id"] for c in cl if c["kind"] == "RETURN_VALUE"}
        checks.append(("change-return: the RETURN_VALUE identity changed", old_ids != new_ids))
        checks.append(("change-return: the RETURN_VALUE count held",
                       len(new_ids) == len(old_ids)))

    # 5. add / remove a CLI option
    idx = _target(pages, lambda p: p["section"] == 1 and p["command"] and p["options"])
    if idx is None:
        checks.append(("cli-option: a command page with documented options was found", False))
    else:
        added = _replace_page(pages, idx,
                              options=sorted(pages[idx]["options"] + ["-podprobe-opt"]))
        cl, recon = derive(added)
        checks.append(("add-cli-option: a CLI_OPTION claim was added",
                       _count_for_kind(cl, "CLI_OPTION")
                       == _count_for_kind(base_claims, "CLI_OPTION") + 1))
        checks.append(("add-cli-option: the option is classified POD_CLI_OPTION_MISSING",
                       any(d["class"] == "POD_CLI_OPTION_MISSING"
                           and d["subject"] == "-podprobe-opt"
                           for d in recon["disagreements"])))
        removed = _replace_page(pages, idx, options=pages[idx]["options"][1:])
        cl2, recon2 = derive(removed)
        checks.append(("remove-cli-option: a CLI_OPTION claim was removed",
                       _count_for_kind(cl2, "CLI_OPTION")
                       == _count_for_kind(base_claims, "CLI_OPTION") - 1))
        checks.append(("remove-cli-option: RUNTIME_CLI_OPTION_UNDOCUMENTED rose",
                       _class_counts(recon2["disagreements"])
                       .get("RUNTIME_CLI_OPTION_UNDOCUMENTED", 0)
                       > _class_counts(base_recon["disagreements"])
                       .get("RUNTIME_CLI_OPTION_UNDOCUMENTED", 0)))

    # 6. add / remove an environment variable
    idx = _target(pages, lambda p: p["environment"])
    if idx is None:
        checks.append(("env-var: a page documenting an environment variable was found", False))
    else:
        added = _replace_page(pages, idx,
                              environment=sorted(pages[idx]["environment"] + ["PODPROBE_ENV"]))
        cl, recon = derive(added)
        checks.append(("add-env-var: an ENV_VAR claim was added",
                       _count_for_kind(cl, "ENV_VAR") == _count_for_kind(base_claims, "ENV_VAR") + 1))
        checks.append(("add-env-var: the variable is classified POD_ENVIRONMENT_VARIABLE_MISSING",
                       any(d["class"] == "POD_ENVIRONMENT_VARIABLE_MISSING"
                           and d["subject"] == "PODPROBE_ENV"
                           for d in recon["disagreements"])))
        removed = _replace_page(pages, idx, environment=pages[idx]["environment"][1:])
        cl2, _ = derive(removed)
        checks.append(("remove-env-var: an ENV_VAR claim was removed",
                       _count_for_kind(cl2, "ENV_VAR")
                       == _count_for_kind(base_claims, "ENV_VAR") - 1))

    # 7. add / remove a configuration directive
    idx = _target(pages, lambda p: p["section"] == 5 and p["directives"])
    if idx is None:
        checks.append(("config-directive: a man5 page with directives was found", False))
    else:
        added = _replace_page(pages, idx,
                              directives=sorted(pages[idx]["directives"] + [".podprobe"]))
        cl, recon = derive(added)
        checks.append(("add-directive: a CONFIG_DIRECTIVE claim was added",
                       _count_for_kind(cl, "CONFIG_DIRECTIVE")
                       == _count_for_kind(base_claims, "CONFIG_DIRECTIVE") + 1))
        checks.append(("add-directive: the directive is classified POD_CONFIG_DIRECTIVE_MISSING",
                       any(d["class"] == "POD_CONFIG_DIRECTIVE_MISSING"
                           and d["subject"] == ".podprobe"
                           for d in recon["disagreements"])))
        removed = _replace_page(pages, idx, directives=pages[idx]["directives"][1:])
        cl2, _ = derive(removed)
        checks.append(("remove-directive: a CONFIG_DIRECTIVE claim was removed",
                       _count_for_kind(cl2, "CONFIG_DIRECTIVE")
                       == _count_for_kind(base_claims, "CONFIG_DIRECTIVE") - 1))

    # 8. change a default pathname
    idx = _target(pages, lambda p: p["default_paths"])
    if idx is None:
        checks.append(("default-path: a page stating a default path was found", False))
    else:
        paths = list(pages[idx]["default_paths"])
        paths[0] = "/podprobe/changed/openssl.cnf"
        mutated = _replace_page(pages, idx, default_paths=paths)
        cl, _ = derive(mutated)
        old_ids = {c["id"] for c in base_claims if c["kind"] == "DEFAULT_PATH"}
        new_ids = {c["id"] for c in cl if c["kind"] == "DEFAULT_PATH"}
        checks.append(("default-path: the DEFAULT_PATH identity changed", old_ids != new_ids))
        checks.append(("default-path: the DEFAULT_PATH count held",
                       len(new_ids) == len(old_ids)))

    # 9. alter a deprecation statement
    idx = _target(pages, lambda p: p["deprecations"])
    if idx is None:
        checks.append(("deprecation: a page stating a deprecation was found", False))
    else:
        deps = copy.deepcopy(pages[idx]["deprecations"])
        deps[0]["since"] = "9.9.9"
        mutated = _replace_page(pages, idx, deprecations=deps)
        cl, _ = derive(mutated)
        old_ids = {c["id"] for c in base_claims if c["kind"] == "DEPRECATION"}
        new_ids = {c["id"] for c in cl if c["kind"] == "DEPRECATION"}
        checks.append(("deprecation: the DEPRECATION identity changed", old_ids != new_ids))
        checks.append(("deprecation: the DEPRECATION count held",
                       len(new_ids) == len(old_ids)))

    return checks


def _broken_extractor(pages: list[dict]) -> list[dict]:
    """A claim graph that extracts nothing -- the defect class this plane exists to prevent."""
    return []


def _broken_reconciler(claims: list[dict], pages: list[dict], index: dict) -> dict:
    """A reconciliation that reports no disagreement -- documented-but-divergent is invisible."""
    return {"disagreements": [], "counts_by_class": {},
            "aux_counts": {"documented_man3_names": 0, "num_names_total": 0,
                           "atlas_header_names_total": 0, "atlas_header_names_not_in_pod": 0,
                           "installed_manpages": 0, "installed_manpage_symlinks": 0}}


def court_pod(body: dict) -> dict:
    """`RT-PHASE22-POD`: the POD plane's own extraction and reconciliation sensitivity challenge."""
    pages = body["pages"]
    index = body["reconciliation"]["index"]
    base_claims = body["claims"]
    base_recon = {"disagreements": body["reconciliation"]["disagreements"],
                  "counts_by_class": body["reconciliation"]["counts_by_class"],
                  "aux_counts": body["reconciliation"]["aux_counts"]}

    checks = _run_checks(pages, index, base_claims, base_recon)

    # Sensitivity: the same checks with a broken extractor / reconciler must fail. If they pass,
    # this court is not an instrument (docs/PHASE-22-SUBPHASES.md section 6).
    broken_checks = _run_checks(pages, index, base_claims, base_recon,
                                extractor=_broken_extractor)
    broken_fails = [d for d, ok in broken_checks if not ok]
    checks.append(("sensitivity: the broken extractor fails the name deletion check",
                   any(d.startswith("delete-name:") and not ok for d, ok in broken_checks)))
    checks.append(("sensitivity: the broken extractor fails at least six checks",
                   len(broken_fails) >= 6))

    broken_recon_checks = _run_checks(pages, index, base_claims, base_recon,
                                      reconciler=_broken_reconciler)
    recon_fails = [d for d, ok in broken_recon_checks if not ok]
    checks.append(("sensitivity: the broken reconciler fails the add-synopsis check",
                   any(d.startswith("add-synopsis:") and not ok
                       for d, ok in broken_recon_checks)))
    checks.append(("sensitivity: the broken reconciler fails at least four checks",
                   len(recon_fails) >= 4))

    failures = [d for d, ok in checks if not ok]
    c = body["counts"]
    return {
        "court": "RT-PHASE22-POD",
        "artefact": ARTEFACT_REL,
        "pages": c["pages"],
        "claims": c["claims"],
        "disagreements": c["disagreements"],
        "mutations": ["delete-name-alias", "add-synopsis-function", "alter-param-type",
                      "change-return-value", "add-cli-option", "remove-cli-option",
                      "add-env-var", "remove-env-var", "add-directive", "remove-directive",
                      "change-default-path", "alter-deprecation",
                      "broken-extractor", "broken-reconciler"],
        "observations": len(checks),
        "failures": failures,
        "summary": f"{c['pages']} pages, {c['claims']} claims, {c['disagreements']} disagreements",
        "verdict": "pass" if not failures else "fail",
    }


def _load_body() -> dict | None:
    if not OUT.is_file():
        return None
    return json.loads(OUT.read_text(encoding="utf-8"))["body"]


def courts() -> list[dict]:
    """The courts this plane owns, or `[]` while its artefact has not landed."""
    try:
        body = _load_body()
    except Exception as exc:  # a court that cannot read its artefact is a failing court
        return [{"court": "RT-PHASE22-POD", "artefact": ARTEFACT_REL, "verdict": "fail",
                 "stage": "artefact-unreadable", "observations": 0, "failures": [str(exc)]}]
    if body is None:
        return []
    return [court_pod(body)]


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
