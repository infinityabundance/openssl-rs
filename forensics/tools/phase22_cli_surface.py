#!/usr/bin/env python3
"""openssl-rs -- Phase 22.9 CLI grammar, aliases and dynamic-command surface extractor.

Enumerates the whole command namespace from the **authority's own built binary** -- never the
system `openssl` (the court image deliberately removes it) and never the pinned authority's
installed prefix -- and normalizes it into the repository's standard atlas document at
`forensics/atlas/phase22/cli-surface.json`.

Why the CLI is not "the 55 standard commands"
---------------------------------------------
`docs/PHASE-22-SUBPHASES.md` section 6 is explicit:

    22.9 "must not model the CLI as 'the 55 standard commands'. The digest and cipher
    pseudo-commands (`openssl sha256 file`) and the `openssl list -digest-commands` /
    `-cipher-commands` surfaces are part of it."

So this plane enumerates four command kinds and keeps the pseudo-command sets as first-class
surfaces:

  * `standard`      -- a name in `openssl list -commands` (the authority's `FUNCTION` table);
  * `deprecated`    -- a standard name whose own `-help` announces deprecation
                       (`The command rsautl was deprecated in version 3.0. Use 'pkeyutl'
                       instead.`); `rsautl` is the only one in this profile;
  * `digest-alias`  -- a name in `openssl list -digest-commands`, dispatched to `dgst` by
                       `do_cmd` via `EVP_get_digestbyname` (apps/openssl.c), so `openssl
                       sha256 file` is a supported invocation;
  * `cipher-alias`  -- a name in `openssl list -cipher-commands`, dispatched to `enc` the same
                       way, so `openssl aes-128-cbc file` is a supported invocation.

The authority binary and the recorded defect
--------------------------------------------
The binary is `forensics/authorities/build/openssl-3.6.4-production/apps/openssl`, run with its
build directory on `LD_LIBRARY_PATH`; the system `openssl` is never consulted. The option
grammar is the authority's `openssl list -options <cmd>` output, whose real rows are
`name type` pairs (`help -`, `in <`, `provider s`). The earlier Phase-1 archaeology matched
those rows against a *help-text* shape (`-in val          Input file`) that the output never
produces, so every structured `option_count` was zero -- the deferral `cli_option_list_parse`
in `forensics/prerequisites.json`. That parser (`forensics/tools/atlas_runtime.py`,
`parse_option_list`) is repaired here, and this plane's own parser records both the structured
options **and** the rows it refuses, so a malformed row cannot silently vanish. See
`docs/DECISIONS.md` for the subphase entry that records what this discharged.

Determinism
-----------
The document is a pure function of the captured texts: commands are sorted by name, options by
name, digest/cipher alias lists sorted, and no timestamp, PID or scratch path is written. The
same binary produces byte-identical JSON, which is what lets `RT-PHASE22-CLI` mutate the
capture in memory and check that this tool's classification logic moves exactly as expected.

Non-claim
---------
`RT-PHASE22-CLI` ties the artefact to this tool's classification logic and to the command set
the binary produced, **not** to a fresh run of the binary: the binary is content-addressed in
the document's `inputs` (its sha256 is recorded), but a rebuilt binary of the same version
would leave the committed artefact stale until the tool is re-run, and no pipeline step
re-runs it. A reviewer re-deriving the surface must run this tool again. That is the same
shape as 22.2's Doxygen corpus and is recorded as a non-claim rather than hidden.

Output
------
    forensics/atlas/phase22/cli-surface.json

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
    authority_build_dir,
    envelope,
    rel,
    resolve_authority,
    write_json,
)

GENERATOR = "forensics/tools/phase22_cli_surface.py"
ARTEFACT_REL = "forensics/atlas/phase22/cli-surface.json"
OUT = REPO_ROOT / ARTEFACT_REL

# The binary this plane enumerates, relative to the authority's build directory. The court runs
# the tool from the container, where `/work` is the repository root.
BINARY_REL_TO_BUILD = "apps/openssl"

# The authority source that defines the option value-type vocabulary, so the grammar this plane
# records is citeable rather than guessed.
OPT_SOURCE_REL = "forensics/authorities/src/openssl-3.6.4/apps/include/opt.h"
LIST_SOURCE_REL = "forensics/authorities/src/openssl-3.6.4/apps/list.c"

# The authority's own option value-type characters (apps/include/opt.h, OPTIONS.valtype),
# mapped to the meaning `valtype2param()` gives them in apps/lib/opt.c.
VALTYPE_NAMES: dict[str, str] = {
    "-": "no-value",
    ":": "uri",
    "s": "string",
    "/": "directory",
    "<": "infile",
    ">": "outfile",
    "p": "positive-int",
    "n": "int",
    "N": "nonneg-int",
    "l": "long",
    "u": "ulong",
    "M": "intmax",
    "U": "uintmax",
    "E": "PEM|DER|ENGINE",
    "F": "PEM|DER",
    "f": "format",
    "A": "PEM|DER|BASE64",
    "a": "any-format",
    "c": "PEM|DER|SMIME",
    ".": "parameters",
}

# A real `list -options` name begins with an alphanumeric and may carry `_ * ? . -`
# (`crl_CA_compromise`, `no-CAfile`, `cert...`); it never begins with a dash.
_OPTION_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_*?.\-]*$")

_USAGE = re.compile(r"^Usage:\s*(.*)$", re.MULTILINE)
_DEPRECATED = re.compile(
    r"^The command (\S+) was deprecated in version (\S+)\.\s*Use '([^']+)' instead\.",
    re.MULTILINE,
)

# The `--` end-of-options marker the authority always prints last (`- -`). It is a documented
# marker, not an option, so it is neither structured as an option nor refused.
_MARKER = ("-", "-")


# ---------------------------------------------------------------------------
# pure classification -- the instrument the court challenges
# ---------------------------------------------------------------------------

def classify_option_rows(text: str) -> tuple[list[dict], list[str], bool]:
    """Structure a `openssl list -options <cmd>` capture.

    Returns `(options, refused, marker)`: the structured options sorted by name, the raw
    non-blank rows that do **not** match the real `name type` grammar (refused rather than
    silently dropped), and whether the authority's `- -` end-of-options marker was present.

    This is the repaired grammar, not the Phase-1 help-text guess: a row is exactly two
    whitespace-separated tokens, the second a single value-type character from
    `apps/include/opt.h`. `-in val  Input file` -- the shape the old parser expected and the
    real output never emits -- has three or more tokens and is therefore refused.
    """
    options: dict[str, dict] = {}
    refused: list[str] = []
    marker = False
    for raw in text.splitlines():
        row = raw.strip()
        if not row:
            continue
        parts = row.split()
        if tuple(parts) == _MARKER:
            marker = True
            continue
        if (
            len(parts) != 2
            or parts[1] not in VALTYPE_NAMES
            or not _OPTION_NAME.match(parts[0])
        ):
            refused.append(row)
            continue
        name, valtype = parts
        options[name] = {
            "name": name,
            "valtype": valtype,
            "value_type": VALTYPE_NAMES[valtype],
            "takes_value": valtype != "-",
        }
    return [options[k] for k in sorted(options)], refused, marker


def classify_help(text: str) -> tuple[str, dict | None]:
    """The command kind implied by its own `-help`, and any deprecation notice.

    `rsautl -help` opens with `The command rsautl was deprecated in version 3.0. Use
    'pkeyutl' instead.`; every other command opens with its `Usage:` line. The alternative
    is recovered from the authority's own words rather than from a hardcoded list.
    """
    m = _DEPRECATED.search(text)
    if m:
        return "deprecated", {"deprecated_in": m.group(2), "replacement": m.group(3)}
    return "standard", None


def _usage(text: str) -> str | None:
    m = _USAGE.search(text)
    return m.group(1).strip() if m else None


# ---------------------------------------------------------------------------
# body
# ---------------------------------------------------------------------------

def build_body(capture: dict, parser=classify_option_rows) -> dict:
    """The atlas body for a captured command namespace. A pure function.

    `parser` is injected so `RT-PHASE22-CLI` can drive the exact same classification over the
    committed capture and over controlled in-memory mutations -- and, with a deliberately
    broken parser, prove the court is sensitive to the defect class this plane repaired.

    Pseudo-commands are dispatched to `dgst` or `enc`, so they carry the dispatcher's option
    surface. The authority is asymmetric about how it exposes that (apps/progs.pl): a cipher
    entry is `{FT_cipher, name, enc_main, enc_options, NULL}`, so its own `list -options`
    prints enc's options, while a digest entry is `{FT_md, name, dgst_main, NULL, NULL}`, so
    its own listing is empty and the options are inherited from `dgst`. Each record says which
    via `options_source`; that is what makes `openssl sha256 file` a structured surface and
    keeps `commands_with_zero_options` at zero.
    """
    standard = list(capture["standard_commands"])
    digest = list(capture["digest_commands"])
    cipher = list(capture["cipher_commands"])
    options_text: dict[str, str] = capture["options_text"]
    help_text: dict[str, str] = capture["help_text"]

    def parsed(name: str) -> tuple[list[dict], list[str], bool]:
        return parser(options_text.get(name, ""))

    dgst_options, _, _ = parsed("dgst")
    enc_options, _, _ = parsed("enc")

    records: dict[str, dict] = {}

    def base_record(name: str, kind: str) -> dict:
        helpstr = help_text.get(name, "")
        return {
            "name": name,
            "kind": kind,
            "alias_of": None,
            "aliases": [],
            "usage": _usage(helpstr),
            "help": helpstr,
            "options_text": options_text.get(name, ""),
            "options": [],
            "options_refused": [],
            "options_marker": False,
            "options_source": "self",
            "deprecation": None,
        }

    for name in standard:
        rec = base_record(name, "standard")
        rec["kind"], rec["deprecation"] = classify_help(rec["help"])
        rec["options"], rec["options_refused"], rec["options_marker"] = parsed(name)
        records[name] = rec

    # The dispatchers name their pseudo-commands as aliases; that edge is the authority's own
    # (do_cmd -> dgst_main / enc_main), not a hand-written list.
    if "dgst" in records:
        records["dgst"]["aliases"] = sorted(digest)
    if "enc" in records:
        records["enc"]["aliases"] = sorted(cipher)

    for name in digest:
        rec = base_record(name, "digest-alias")
        rec["alias_of"] = "dgst"
        own, refused, marker = parsed(name)
        if own:
            rec["options"], rec["options_refused"], rec["options_marker"] = own, refused, marker
            rec["options_source"] = "self"
        else:
            rec["options"] = [dict(o) for o in dgst_options]
            rec["options_source"] = "dgst"
        records[name] = rec

    for name in cipher:
        rec = base_record(name, "cipher-alias")
        rec["alias_of"] = "enc"
        own, refused, marker = parsed(name)
        if own:
            rec["options"], rec["options_refused"], rec["options_marker"] = own, refused, marker
            rec["options_source"] = "self"
        else:
            rec["options"] = [dict(o) for o in enc_options]
            rec["options_source"] = "enc"
        records[name] = rec

    commands = [records[k] for k in sorted(records)]

    # The global options are derived, not typed: the option names every standard command
    # accepts. In this profile that is exactly `help`; the provider block
    # (`provider-path`/`provider`/`provparam`/`propquery`) is near-global -- carried by 46 of
    # the 55 standard commands -- but not global, so it is not claimed as such.
    standard_records = [records[n] for n in standard]
    common: set[str] | None = None
    lookup: dict[str, dict] = {}
    for rec in standard_records:
        names = {o["name"] for o in rec["options"]}
        common = names if common is None else (common & names)
        for o in rec["options"]:
            lookup.setdefault(o["name"], o)
    global_options = [lookup[n] for n in sorted(common or set())]

    counts = {
        "commands": len(commands),
        "standard": sum(1 for c in commands if c["kind"] == "standard"),
        "deprecated": sum(1 for c in commands if c["kind"] == "deprecated"),
        "digest_aliases": len(digest),
        "cipher_aliases": len(cipher),
        "options_structured": sum(len(c["options"]) for c in commands),
        "options_refused": sum(len(c["options_refused"]) for c in commands),
        "commands_with_zero_options": sum(1 for c in commands if not c["options"]),
        "global_options": len(global_options),
    }

    return {
        "binary": capture["binary"],
        "version": capture["version"],
        "capture_method": "execution-captured",
        "enumerated_via": [
            "list -commands -1",
            "list -digest-commands -1",
            "list -cipher-commands -1",
            "list -options <cmd> (every command)",
            "<cmd> -help (every command)",
            "openssl -help",
            "openssl list -help",
        ],
        "option_grammar": {
            "row": "<name> <type>",
            "valtypes": VALTYPE_NAMES,
            "source": OPT_SOURCE_REL,
            "note": (
                "The rows are `openssl list -options <cmd>` (apps/list.c "
                "list_options_for_command). Each is a name and the authority's own OPTIONS "
                "value-type character; the trailing `- -` row is the documented `--` "
                "end-of-options marker, not an option."
            ),
        },
        "global_options": global_options,
        "global_options_note": (
            "Derived as the option names accepted by every standard command, not typed. The "
            "provider block (provider-path/provider/provparam/propquery) is near-global but "
            "not global in this profile, so it is deliberately not claimed as such."
        ),
        "commands": commands,
        "digest_commands": sorted(digest),
        "cipher_commands": sorted(cipher),
        "top_level_help": capture["top_help"],
        "list_help": capture["list_help"],
        "counts": counts,
        "note": (
            "The command namespace is not the standard-command list: the digest and cipher "
            "pseudo-commands are first-class records with the dispatcher's options. A dynamic "
            "surface this plane does *not* enumerate is `openssl no-<cmd>` (apps/openssl.c, "
            "do_cmd's `no-` prefix probe), which reports whether a feature is unsupported; it "
            "is named here as a residual rather than silently counted."
        ),
        "sort_key": "(command name; options by name; alias lists sorted)",
    }


def capture_from_body(body: dict) -> dict:
    """Rebuild the capture a committed body was normalised from, for the round-trip court."""
    standard = [c["name"] for c in body["commands"]
                if c["kind"] in ("standard", "deprecated")]
    return {
        "binary": body["binary"],
        "version": body["version"],
        "standard_commands": standard,
        "digest_commands": list(body["digest_commands"]),
        "cipher_commands": list(body["cipher_commands"]),
        "options_text": {c["name"]: c["options_text"] for c in body["commands"]},
        "help_text": {c["name"]: c["help"] for c in body["commands"]},
        "top_help": body["top_level_help"],
        "list_help": body["list_help"],
    }


# ---------------------------------------------------------------------------
# capture -- the only part that runs the authority binary
# ---------------------------------------------------------------------------

def _run(binary: Path, argv: list[str], env: dict) -> str:
    proc = subprocess.run([str(binary)] + argv, capture_output=True, text=True, env=env,
                          check=False)
    # Every `-help` surface is written to stderr by opt_printf_stderr (apps/lib/opt.c), so the
    # two streams are combined and the text is the surface. This is an execution capture, not a
    # reconstruction from source.
    return proc.stdout + proc.stderr


def capture_authority(auth, binary: Path) -> dict:
    build_dir = authority_build_dir(auth.id)
    env = dict(os.environ)
    env["LD_LIBRARY_PATH"] = str(build_dir)
    modules = build_dir / "providers"
    if modules.is_dir():
        env["OPENSSL_MODULES"] = str(modules)
    env["OPENSSL_CONF"] = "/dev/null"
    env.pop("OPENSSL_CONF_INCLUDE", None)

    def norm(text: str) -> str:
        # No scratch or premainder path is written; this is the single symmetric substitution
        # the runtime atlas already applies, kept for the case a help string names the prefix.
        for prefix in (str(auth.prefix), str(build_dir), str(auth.source)):
            text = text.replace(prefix, "<AUTHORITY>")
        return text

    raw = _run(binary, ["list", "-commands", "-1"], env)
    standard = sorted({ln.strip() for ln in raw.splitlines() if ln.strip()})
    raw = _run(binary, ["list", "-digest-commands", "-1"], env)
    digest = sorted({ln.strip() for ln in raw.splitlines() if ln.strip()})
    raw = _run(binary, ["list", "-cipher-commands", "-1"], env)
    cipher = sorted({ln.strip() for ln in raw.splitlines() if ln.strip()})

    options_text: dict[str, str] = {}
    help_text: dict[str, str] = {}
    for name in standard + digest + cipher:
        options_text[name] = norm(_run(binary, ["list", "-options", name], env))
        help_text[name] = norm(_run(binary, [name, "-help"], env))

    top_help = norm(_run(binary, ["-help"], env))
    list_help = norm(_run(binary, ["list", "-help"], env))
    version = norm(_run(binary, ["version"], env)).strip()

    return {
        "binary": rel(binary),
        "version": version,
        "standard_commands": standard,
        "digest_commands": digest,
        "cipher_commands": cipher,
        "options_text": options_text,
        "help_text": help_text,
        "top_help": top_help,
        "list_help": list_help,
    }


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    args = ap.parse_args(argv)

    auth = resolve_authority(args.authority)
    build_dir = authority_build_dir(auth.id)
    binary = build_dir / BINARY_REL_TO_BUILD
    if not binary.is_file():
        raise SystemExit(
            f"phase22-cli-surface: the authority's built binary is missing: {binary}; build "
            "the authority (forensics/tools/authority_build.py) first"
        )

    capture = capture_authority(auth, binary)
    body = build_body(capture)

    inputs = [InputRef(name="openssl-binary", path=binary)]
    opt_source = REPO_ROOT / OPT_SOURCE_REL
    if opt_source.is_file():
        inputs.append(InputRef(name="opt-grammar-source", path=opt_source))
    list_source = REPO_ROOT / LIST_SOURCE_REL
    if list_source.is_file():
        inputs.append(InputRef(name="list-command-source", path=list_source))

    doc = envelope(
        kind="phase22-cli-surface",
        authority=auth.id,
        inputs=inputs,
        body=body,
        generator=GENERATOR,
    )
    write_json(OUT, doc)

    c = body["counts"]
    print(f"[phase22-cli-surface] {body['version']}")
    print(f"  commands={c['commands']} (standard={c['standard']} deprecated={c['deprecated']} "
          f"digest-alias={c['digest_aliases']} cipher-alias={c['cipher_aliases']})")
    print(f"  structured options={c['options_structured']} refused={c['options_refused']} "
          f"commands_with_zero_options={c['commands_with_zero_options']} "
          f"global_options={c['global_options']} -> {rel(OUT)}")
    return 0


# ---------------------------------------------------------------------------
# the court -- RT-PHASE22-CLI
# ---------------------------------------------------------------------------

def _broken_parser(text: str) -> tuple[list[dict], list[str], bool]:
    """The original Phase-1 defect: every row is silently dropped, nothing is refused.

    Running the court's checks with this parser must fail them; if it does not, the court is
    not sensitive to the defect class this plane exists to repair and the verdict is `fail`.
    """
    return [], [], False


def _by_name(body: dict) -> dict[str, dict]:
    return {c["name"]: c for c in body["commands"]}


def _stable(base: dict, new: dict, moved: set[str]) -> bool:
    """Every command except those named by `moved` is byte-for-byte identical."""
    a, b = _by_name(base), _by_name(new)
    return all(a.get(k) == b.get(k) for k in (set(a) | set(b)) - moved)


def _option_target(capture: dict) -> str | None:
    """A standard command whose *captured* option text is real (not the parsed base).

    Selecting from the capture rather than from a parsed body is what lets the sensitivity
    probe drive these mutations through the broken parser too, so the failure is `the row was
    not structured`, not `no target was found`.
    """
    for name in capture["standard_commands"]:
        if "help -" in capture["options_text"].get(name, ""):
            return name
    return None


def _mutation_add_command(capture: dict, base: dict, checks: list[tuple[str, bool]]) -> None:
    mut = copy.deepcopy(capture)
    mut["standard_commands"].append("phase22probe")
    mut["options_text"]["phase22probe"] = "help -\nprobe-opt s\n- -\n"
    mut["help_text"]["phase22probe"] = "Usage: phase22probe [options]\n"
    new = build_body(mut)
    row = _by_name(new).get("phase22probe")
    checks.append(("add-command: commands rose by one",
                   new["counts"]["commands"] == base["counts"]["commands"] + 1))
    checks.append(("add-command: standard rose by one",
                   new["counts"]["standard"] == base["counts"]["standard"] + 1))
    checks.append(("add-command: the command is present with its structured options",
                   row is not None and row["kind"] == "standard"
                   and [o["name"] for o in row["options"]] == ["help", "probe-opt"]))
    checks.append(("add-command: nothing else moved",
                   _stable(base, new, {"phase22probe"})))


def _mutation_add_alias(capture: dict, base: dict, checks: list[tuple[str, bool]]) -> None:
    mut = copy.deepcopy(capture)
    mut["digest_commands"].append("sha999")
    mut["help_text"]["sha999"] = "Usage: sha999 [options] [file...]\n"
    new = build_body(mut)
    row = _by_name(new).get("sha999")
    dgst = _by_name(new).get("dgst")
    checks.append(("add-alias: digest_aliases rose by one",
                   new["counts"]["digest_aliases"] == base["counts"]["digest_aliases"] + 1))
    checks.append(("add-alias: the alias is a digest-alias of dgst",
                   row is not None and row["kind"] == "digest-alias"
                   and row["alias_of"] == "dgst"))
    checks.append(("add-alias: it inherits the dispatcher's structured options",
                   row is not None and row["options"] == dgst["options"]
                   and row["options_source"] == "dgst"))
    checks.append(("add-alias: dgst's alias list gained it",
                   dgst is not None and "sha999" in dgst["aliases"]))


def _mutation_add_option_row(capture: dict, base: dict, checks: list[tuple[str, bool]]) -> None:
    target = _option_target(capture)
    if target is None:
        checks.append(("add-option-row: a standard command with options was found", False))
        return
    mut = copy.deepcopy(capture)
    mut["options_text"][target] += "phase22probeopt s\n"
    new = build_body(mut)
    row = _by_name(new)[target]
    base_row = _by_name(base)[target]
    checks.append(("add-option-row: a real-grammar row parses",
                   any(o["name"] == "phase22probeopt" and o["valtype"] == "s"
                       for o in row["options"])))
    checks.append(("add-option-row: the target's structured count rose by one",
                   len(row["options"]) == len(base_row["options"]) + 1))
    checks.append(("add-option-row: a real row is not refused", not row["options_refused"]))
    checks.append(("add-option-row: commands_with_zero_options unchanged",
                   new["counts"]["commands_with_zero_options"]
                   == base["counts"]["commands_with_zero_options"]))


def _malformed_check(capture: dict, base: dict) -> list[tuple[str, bool]]:
    """The malformed-row checks, separated so the sensitivity probe can reuse them."""
    checks: list[tuple[str, bool]] = []
    target = _option_target(capture)
    if target is None:
        return [("malformed-row: a standard command with options was found", False)]
    mut = copy.deepcopy(capture)
    old_shape = "-in val          Input file"
    bad_valtype = "phase22probeopt ??"
    mut["options_text"][target] += old_shape + "\n" + bad_valtype + "\n"
    new = build_body(mut)
    row = _by_name(new)[target]
    base_row = _by_name(base)[target]
    checks.append(("malformed-row: the help-text shape is refused, not dropped",
                   old_shape in row["options_refused"]))
    checks.append(("malformed-row: the unknown valtype is refused",
                   bad_valtype in row["options_refused"]))
    checks.append(("malformed-row: neither entered the structured list",
                   len(row["options"]) == len(base_row["options"])))
    checks.append(("malformed-row: the refused count rose by exactly two",
                   new["counts"]["options_refused"]
                   == base["counts"]["options_refused"] + 2))
    return checks


def _mutation_remove_pseudo(capture: dict, base: dict, checks: list[tuple[str, bool]]) -> None:
    victim = base["cipher_commands"][0] if base["cipher_commands"] else None
    if victim is None:
        checks.append(("remove-pseudo: a cipher alias was found", False))
        return
    mut = copy.deepcopy(capture)
    mut["cipher_commands"] = [c for c in mut["cipher_commands"] if c != victim]
    new = build_body(mut)
    enc = _by_name(new).get("enc")
    checks.append(("remove-pseudo: cipher_aliases fell by one",
                   new["counts"]["cipher_aliases"] == base["counts"]["cipher_aliases"] - 1))
    checks.append(("remove-pseudo: the command record disappeared",
                   victim not in _by_name(new)))
    checks.append(("remove-pseudo: enc's alias list lost it",
                   enc is not None and victim not in enc["aliases"]))
    checks.append(("remove-pseudo: nothing else moved",
                   _stable(base, new, {victim, "enc"})))


def _real_row_checks(capture: dict, parser) -> list[tuple[str, bool]]:
    """Prove the parser reads a real authority row -- the exact class that silently returned
    zero before."""
    target = next((n for n, t in capture["options_text"].items()
                   if "in <" in t or "help -" in t), None)
    if target is None:
        return [("real-row: a real option capture was found", False)]
    text = capture["options_text"][target]
    options, refused, marker = parser(text)
    names = {o["name"] for o in options}
    checks = [
        (f"real-row: {target}'s real capture is non-empty", len(options) > 0),
        ("real-row: the flag row `help -` parsed as a no-value option",
         any(o["name"] == "help" and o["valtype"] == "-" and not o["takes_value"]
             for o in options)),
        ("real-row: the end-of-options marker was seen", marker),
        ("real-row: a real capture refuses nothing", not refused),
    ]
    # The recorded archaeology defect is repaired at its own source: the Phase-16 parser must
    # now read the authority's real shape too. Calling it here is what makes a revert of
    # `parse_option_list` fail this court.
    try:
        import atlas_runtime as art
        fixed = art.parse_option_list(text)
        checks.append(("real-row: atlas_runtime.parse_option_list parses a real row non-empty",
                       len(fixed) > 0))
        checks.append(("real-row: the repaired Phase-16 parser agrees on the option names",
                       {o["name"] for o in fixed} == names))
    except Exception as exc:  # pragma: no cover - a broken/absent module is a failure
        checks.append((f"real-row: atlas_runtime.parse_option_list importable ({exc})", False))
    return checks


def _run_all(capture: dict, parser) -> tuple[dict, list[tuple[str, bool]]]:
    base = build_body(capture, parser=parser)
    checks: list[tuple[str, bool]] = []
    checks += _real_row_checks(capture, parser)
    checks.append(("baseline: the capture enumerates commands", base["counts"]["commands"] > 0))
    checks.append(("baseline: every command's options are non-empty",
                   base["counts"]["commands_with_zero_options"] == 0))
    checks.append(("baseline: some option rows were structured",
                   base["counts"]["options_structured"] > 0))
    checks.append(("baseline: every standard command has options",
                   all(c["options"] for c in base["commands"] if c["kind"] == "standard")))
    checks += _malformed_check(capture, base)
    _mutation_add_command(capture, base, checks)
    _mutation_add_alias(capture, base, checks)
    _mutation_add_option_row(capture, base, checks)
    _mutation_remove_pseudo(capture, base, checks)
    return base, checks


def court_cli(body: dict) -> dict:
    """`RT-PHASE22-CLI`: a sensitivity challenge over this plane's classification logic."""
    capture = capture_from_body(body)
    base, checks = _run_all(capture, classify_option_rows)

    # Round-trip: re-derive the committed body from its own capture and require equality.
    rebuilt = build_body(capture, parser=classify_option_rows)
    checks.append(("round-trip: the committed body equals its re-derivation", rebuilt == body))

    # Sensitivity: the *same* checks, run with the original defect restored, must fail. If the
    # broken parser still passes them, this court is not an instrument.
    _, broken_checks = _run_all(capture, _broken_parser)
    broken_failures = [d for d, ok in broken_checks if not ok]
    checks.append(("sensitivity: the broken parser fails the real-row parse",
                   any(d.startswith("real-row:") and not ok for d, ok in broken_checks)))
    checks.append(("sensitivity: the broken parser silently drops the malformed row",
                   any(d.startswith("malformed-row:") and not ok for d, ok in broken_checks)))
    checks.append(("sensitivity: the broken parser fails the structured-options baseline",
                   any("structured" in d and not ok for d, ok in broken_checks)))
    checks.append(("sensitivity: at least three checks flip under the broken parser",
                   len(broken_failures) >= 3))

    failures = [d for d, ok in checks if not ok]
    return {
        "court": "RT-PHASE22-CLI",
        "artefact": ARTEFACT_REL,
        "version": body.get("version"),
        "commands": base["counts"]["commands"],
        "standard": base["counts"]["standard"],
        "digest_aliases": base["counts"]["digest_aliases"],
        "cipher_aliases": base["counts"]["cipher_aliases"],
        "options_structured": base["counts"]["options_structured"],
        "commands_with_zero_options": base["counts"]["commands_with_zero_options"],
        "mutations": ["real-row-parse", "malformed-row-refusal", "add-command", "add-alias",
                      "add-option-row", "remove-pseudo-command", "broken-parser-sensitivity"],
        "observations": len(checks),
        "failures": failures,
        "verdict": "pass" if not failures else "fail",
    }


def courts() -> list[dict]:
    """The courts this plane owns, or `[]` while its artefact has not landed."""
    if not OUT.is_file():
        return []
    try:
        body = json.loads(OUT.read_text(encoding="utf-8"))["body"]
    except Exception as exc:  # a court that cannot read its artefact is a failing court
        return [{"court": "RT-PHASE22-CLI", "artefact": ARTEFACT_REL, "verdict": "fail",
                 "stage": "artefact-unreadable", "observations": 0, "failures": [str(exc)]}]
    return [court_cli(body)]


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
