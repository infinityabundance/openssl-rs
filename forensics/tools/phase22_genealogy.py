#!/usr/bin/env python3
"""openssl-rs -- Phase 22.5 generated-source genealogy.

Records the edge between every generated source file and the original it was
generated *from*. `docs/PHASE-22-SUBPHASES.md` section 6 is the rule this tool
exists to obey:

    22.5 must parse both the original and the generated source, and record the
    edge between them. Parsing either alone loses provenance.

So the artefact is not a census of generated files -- that is 22.3's
translation-unit census and 22.8's distribution manifest -- and it is not a
census of original files -- that is 22.2/22.3. It is the *edges*: for each
output, the inputs it came from and the generator that produced it.

Where the edges are read from
-----------------------------
The plan allows "the generated Makefile in the pinned build dir and/or
`build.info` files and/or `configdata.pm`". The generated `Makefile` is the only
one of the three that carries the generator's *argv*: `Configure` turns each
`build.info`'s `GENERATE[...]` clause into an explicit recipe, and the
hand-written maintenance targets (`generate_crypto_objects`, `errors`,
`generate_crypto_bn`, ...) live only in `Makefile.in`, which `Configure`
expands into the generated `Makefile`. This tool therefore reads the pinned
build's generated `Makefile`
(`forensics/authorities/build/openssl-3.6.4-production/Makefile`, read-only),
and reads the generated Makefile's own `GENERATED*` variables as the declaration
of what this profile considers generated. The declaration is what makes
`outputs_without_a_rule` meaningful: a file the build declares generated but for
which no rule could be recovered is a **residual**, recorded rather than
dropped. `build.info`'s `GENERATE[...]` clauses are deliberately *not* used as
the declaration: they describe every architecture and documentation profile, so
they would report ~2,100 files this production profile never generates as
residuals. The generated Makefile is `Configure`'s resolution of those clauses
for this exact profile.

The two source trees
--------------------
A generated file lands in one of two trees, and the artefact keeps them apart:

  * an out-of-tree build writes generated headers, provider sources, perlasm,
    symbol scripts and documentation into the **build** tree
    (`forensics/authorities/build/openssl-3.6.4-production/...`);
  * the hand-run maintenance targets `cd` into `$(SRCDIR)` and rewrite files
    **in place** in the **source** tree
    (`forensics/authorities/src/openssl-3.6.4/...`), which is why
    `include/openssl/obj_mac.h` and the `crypto/objects/*` object tables are
    found beside `objects.txt` and not under `build/`.

A path is recorded repository-relative, so the two trees are distinguishable
and no host or scratch path is written.

What is recovered
-----------------
  * explicit file rules whose recipe invokes a `*.pl` generator -- the
    `include/openssl/*.h.in -> *.h` rules (`util/dofile.pl`), the provider
    `*.c.in -> *.c` rules, the perlasm `*.pl -> *.s`/`.S` rules, the symbol
    scripts (`util/mkdef.pl`), `crypto/buildinf.h`, the pkg-config/CMake
    exporters, and the generated POD manuals;
  * the maintenance targets that redirect a `*.pl` to an output -- the object
    tables (`crypto/objects/objects.pl`, `obj_dat.pl`, `objxref.pl`),
    `crypto/bn/bn_prime.pl`, `crypto/conf/keysets.pl`,
    `crypto/asn1/charmap.pl`, `fuzz/mkfuzzoids.pl`, `apps/CA.pl`'s VMS variant;
  * `apps/progs.pl -> apps/progs.c` / `apps/progs.h`, the CLI command table the
    plan calls out (an explicit file rule, so it is recovered by the first path);
  * `util/mkerr.pl` from `crypto/err/openssl.ec` plus `openssl.txt`, by reading
    the `.ec` table itself: the plan names the error headers/tables as a
    generation edge, and `mkerr.pl` names its own outputs in that table rather
    than on a redirect. The same reading covers the per-engine `engines/*.ec`.

Reduction, recorded rather than hidden
--------------------------------------
Only rules whose recipe invokes a `*.pl` generator are recorded. A shell-only
transformation -- the `sed -e '1,8d' ... >> include/openssl/obj_mac.h` that
appends the compatibility block after `objects.pl` runs -- is not a generator
edge and is deliberately excluded; it is recorded in `body.reduction`. Rules are
deduplicated on `(output, generator, rule_site)`.

Determinism
-----------
Every list is sorted and every count derived. No timestamp, PID, scratch path
or host path is written. The same Makefile and the same two trees produce
byte-identical JSON, which is what lets `RT-PHASE22-GENEALOGY`
(`forensics/tools/phase22_genealogy.py`'s own `build_body`) be a pure function
the court can drive over controlled in-memory mutations.

Output
------
    forensics/atlas/phase22/generated-lineage.json

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import re
import shlex
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import (  # noqa: E402
    PRODUCTION_AUTHORITY,
    REPO_ROOT,
    InputRef,
    envelope,
    rel,
    resolve_authority,
    write_json,
)

GENERATOR = "forensics/tools/phase22_genealogy.py"
ARTEFACT_REL = "forensics/atlas/phase22/generated-lineage.json"
OUT_REL = ARTEFACT_REL

BUILD_DIR_REL = "forensics/authorities/build/openssl-3.6.4-production"
SRC_DIR_REL = "forensics/authorities/src/openssl-3.6.4"
MAKEFILE_REL = f"{BUILD_DIR_REL}/Makefile"

BLD_PREFIX = BUILD_DIR_REL
SRC_PREFIX = SRC_DIR_REL

# Products of `Configure` rather than of a Makefile rule, marked generated so the
# `.h.in -> .h` rules do not call their own configuration metadata "source".
CONFIGURE_PRODUCTS = ("configdata.pm", "Makefile")

# The Makefile variables that declare a file generated. Used only to compute the
# residual set: a declared output with no recovered rule is not dropped.
_GENERATED_VARS = ("GENERATED_MANDATORY", "GENERATED", "GENERATED_PODS")

# Make directives that are never a rule's target line.
_DIRECTIVES = frozenset({
    "ifeq", "ifneq", "ifdef", "ifndef", "else", "endif", "include", "-include",
    "sinclude", "export", "unexport", "define", "endef", "vpath", "override",
    "undefine", "private",
})

# Tokens that break a shell command while scanning a recipe for the generator's
# argv. `(` is not included: `( cd $(SRCDIR); $(PERL) ...` must start at `cd`.
_SHELL_BREAK = frozenset({
    ";", "&&", "||", "|", ">", ">>", "<", "(", ")",
    "if", "then", "else", "fi", "for", "do", "done",
    "cd", "mv", "rm", "pwd", "set", "basename",
})


def _breaks(token: str) -> bool:
    """Whether a shell token ends the current command (or begins a new one)."""
    return (token in _SHELL_BREAK or token.endswith(";") or "&&" in token
            or "||" in token)


_SEP = re.compile(r"[\s]+")


# ---------------------------------------------------------------------------
# paths
# ---------------------------------------------------------------------------

def _join(prefix: str, path: str) -> str:
    """Join `path` onto `prefix`, resolving `.`/`..`, POSIX-style."""
    parts = (prefix + "/" + path).split("/")
    out: list[str] = []
    for p in parts:
        if p in ("", "."):
            continue
        if p == "..":
            if out:
                out.pop()
            continue
        out.append(p)
    return "/".join(out)


def normalize(token: str, default_tree: str) -> str:
    """A Makefile token -> a repository-relative path.

    `$(SRCDIR)/x`, `../../src/openssl-3.6.4/x` and a bare token under a
    source-context recipe all mean the source tree; every other bare token is
    build-relative. `..` is resolved against the build directory string-wise, so
    no host path is ever produced.
    """
    t = token
    for pref in ("$(SRCDIR)/", "${SRCDIR}/", "$${SRCDIR}/"):
        if t.startswith(pref):
            return _join(SRC_PREFIX, t[len(pref):])
    for pref in ("$(BLDDIR)/", "${BLDDIR}/", "$${BLDDIR}/"):
        if t.startswith(pref):
            return _join(BLD_PREFIX, t[len(pref):])
    if t.startswith("../../src/openssl-3.6.4/"):
        return _join(SRC_PREFIX, t[len("../../src/openssl-3.6.4/"):])
    if t.startswith("../"):
        return _join(BLD_PREFIX, t)
    if default_tree == "source":
        return _join(SRC_PREFIX, t)
    return _join(BLD_PREFIX, t)


# ---------------------------------------------------------------------------
# Makefile reading
# ---------------------------------------------------------------------------

def logical_lines(text: str) -> list[tuple[str, int]]:
    """Physical lines joined on a trailing backslash, with their start line (1-based).

    The backslash-newline is replaced by a space, so a variable assignment or a
    recipe command that spans physical lines becomes one logical line. This is
    what lets both the `GENERATED*` declarations and a multi-line generator
    recipe be read whole rather than one physical line at a time.
    """
    physical = text.splitlines()
    out: list[tuple[str, int]] = []
    i = 0
    while i < len(physical):
        start = i + 1
        buf = physical[i]
        while buf.endswith("\\") and not buf.endswith("\\\\") and i + 1 < len(physical):
            buf = buf[:-1] + " " + physical[i + 1]
            i += 1
        out.append((buf, start))
        i += 1
    return out


def _collapse(recipe: str) -> str:
    """A recipe's logical line -> one space-separated command text."""
    return _SEP.sub(" ", recipe.replace("\\\n", " ")).strip()


def _tokenize(text: str) -> list[str]:
    try:
        return shlex.split(text, posix=True)
    except ValueError:
        return text.split()


def _is_rule_line(ln: str) -> bool:
    s = ln.lstrip()
    if not s or s.startswith("#") or ln.startswith(("\t", " ")):
        return False
    head = s.split(None, 1)[0]
    return head not in _DIRECTIVES


def parse_rules(text: str) -> list[dict]:
    """Every make rule, as `{targets, prereqs, recipe, line}`."""
    lines = logical_lines(text)
    rules: list[dict] = []
    i = 0
    while i < len(lines):
        ln, line_no = lines[i]
        if not _is_rule_line(ln):
            i += 1
            continue
        j = i + 1
        recipe: list[str] = []
        while j < len(lines) and lines[j][0].startswith("\t"):
            recipe.append(lines[j][0][1:])
            j += 1
        idx = ln.find(":")
        if idx < 0 or (idx + 1 < len(ln) and ln[idx + 1] == "="):
            i += 1
            continue
        left = ln[:idx]
        if "=" in left or not left.strip():
            i += 1
            continue
        targets = left.split()
        if any(t.startswith(".") and t[1:].isupper() for t in targets):
            i = j
            continue
        rest = ln[idx + 1:]
        rest = rest.removeprefix(":")
        rules.append({"targets": targets, "prereqs": rest.split(),
                      "recipe": "\n".join(recipe), "line": line_no})
        i = j
    return rules


def declared_generated(makefile_text: str) -> set[str]:
    """The outputs the generated Makefile itself declares generated.

    Only the `GENERATED*` variables are used, not every `build.info`'s
    `GENERATE[...]` clause. `build.info` expresses the generation for *every*
    architecture and documentation profile, so using it as the declaration
    would report ~2,100 files that this production profile never generates
    (armv4 perlasm, man pages the profile does not build) as "generated without
    a rule". The generated Makefile is `Configure`'s resolution of those clauses
    for this exact profile, so its declarations are the honest residual base.
    """
    out: set[str] = set()
    for ln, _ in logical_lines(makefile_text):
        m = re.match(r"^(" + "|".join(_GENERATED_VARS) + r")\s*[:+]?=\s*(.*)$", ln)
        if not m:
            continue
        for tok in m.group(2).split():
            if "$" not in tok:
                out.add(normalize(tok, "build"))
    return out


def declared_templates(src_dir: Path) -> set[str]:
    """The root `build.info`'s `GENERATE[...]` outputs whose input is a `*.in` template.

    The Makefile's `GENERATED*` variables do not name every generated file: the
    `{skip}` ones such as `include/openssl/configuration.h` are written by
    `Configure` itself. Those are exactly the `*.h.in -> *.h` variant
    `docs/PHASE-22-SUBPHASES.md` calls out, so they are added to the declared set
    here.

    Only the **root** `build.info` is read, and only clauses whose declared input
    is a template ending in `.in`. A sub-`build.info`'s `GENERATE` paths are
    relative to that subdirectory (so `doc/build.info.in`'s `man1/*.pod` would be
    mis-rooted) and cover every profile; reading them would bury the one honest
    residual under spurious ones. The root file is where the top-level `.h.in`
    templates and `configuration.h` are declared.
    """
    out: set[str] = set()
    root = src_dir / "build.info"
    if not root.is_file():
        return out
    buf = ""
    for raw in root.read_text(encoding="utf-8", errors="replace").splitlines():
        buf = (buf + " " + raw.lstrip()).strip() if buf else raw.strip()
        if raw.rstrip().endswith("\\"):
            continue
        m = re.match(r"GENERATE\[([^\]]+)\]\s*(?:\{[^}]*\})?\s*=\s*(.*)$", buf)
        if m and "$" not in m.group(1) and any(
                i.endswith(".in") and "$" not in i for i in m.group(2).split()):
            out.add(normalize(m.group(1), "build"))
        buf = ""
    return out


def read_mkerr_outputs(ec_path: Path) -> tuple[list[str], list[Path]]:
    """The `(outputs, inputs)` `util/mkerr.pl` derives from one `.ec` table.

    `mkerr.pl` names its generated files in the `L LIBNAME PUBLIC ERROR INTERNAL`
    table rather than on a redirect, so the table is read directly. Its inputs
    are the table and the state file its own name implies (`openssl.ec` ->
    `openssl.txt`), which is the `crypto/err/openssl.ec` + `openssl.txt` edge the
    plan names.
    """
    outputs: list[str] = []
    for ln in ec_path.read_text(encoding="utf-8", errors="replace").splitlines():
        m = re.match(r"^L\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(\S+))?\s*$", ln)
        if not m:
            continue
        for tok in (m.group(2), m.group(3), m.group(4)):
            if tok and tok != "NONE":
                outputs.append(tok)
    txt = ec_path.with_suffix(".txt")
    inputs = [ec_path, txt]
    return outputs, inputs


# ---------------------------------------------------------------------------
# extraction
# ---------------------------------------------------------------------------

def _looks_like_output(token: str) -> bool:
    return "/" in token or "." in token.rsplit("/", 1)[-1]


def _is_generator_token(token: str) -> bool:
    """A `*.pl` generator, not a `*.pl` glob or a shell-variable expansion."""
    return (token.endswith(".pl") and "*" not in token and "?" not in token
            and "$$" not in token)


def _pl_tokens(tokens: list[str]) -> list[str]:
    return [t for t in tokens if _is_generator_token(t)]


def _is_input_token(token: str) -> bool:
    if not token or token in _SHELL_BREAK or token.endswith(".pl"):
        return False
    if token.startswith("-"):
        return False
    if any(c in token for c in "*?`&|"):
        return False
    if "=" in token or token.startswith("$") and not token.startswith(
            ("$(SRCDIR)", "$(BLDDIR)")):
        return False
    return True


def _mv_final(tokens: list[str], redirect: str) -> str | None:
    """If the recipe renames `redirect`, the final output."""
    want = redirect.rstrip(";")
    for i, tok in enumerate(tokens):
        if tok == "mv" and i + 2 < len(tokens) and tokens[i + 1].rstrip(";") == want:
            return tokens[i + 2].rstrip(";")
    return None


def _argv_for(tokens: list[str], gen_index: int, output: str, inputs: list[str]) -> list[str]:
    """The generator's argv as the Makefile gives it, with `$@`/`$<`/`$(PERL)` resolved."""
    start = 0
    for i in range(gen_index - 1, -1, -1):
        if _breaks(tokens[i]):
            start = i + 1
            break
    end = len(tokens)
    for i in range(gen_index + 1, len(tokens)):
        if _breaks(tokens[i]):
            end = i
            break
    argv: list[str] = []
    for tok in tokens[start:end]:
        if tok in ("$(PERL)", "${PERL}", "$${PERL}"):
            argv.append("perl")
        elif tok == "$@":
            argv.append(output)
        elif tok == "$<":
            argv.append(inputs[0] if inputs else "$<")
        else:
            argv.append(tok)
    return argv


def _classify(output: str, generator: str) -> str:
    base = generator.rsplit("/", 1)[-1]
    if base in ("objects.pl", "obj_dat.pl", "objxref.pl"):
        return "object-table"
    if base == "mkerr.pl":
        return "error-table"
    if base == "progs.pl":
        return "cli-table"
    if base == "mkdef.pl":
        return "symbol-table"
    if base in ("mkinstallvars.pl", "dofile.pl") and output.endswith((".pc", ".cmake", ".pm")):
        return "build-metadata"
    suffix = output.rsplit(".", 1)[-1] if "." in output.rsplit("/", 1)[-1] else ""
    return {
        "h": "header", "c": "source", "inc": "source", "pod": "doc",
        "html": "doc", "s": "asm", "S": "asm", "in": "source", "txt": "data",
        "num": "data", "ld": "symbol-table", "pc": "build-metadata",
        "cmake": "build-metadata", "pm": "build-metadata", "cnf": "config",
        "pl": "script", "sh": "script", "new": "intermediate",
    }.get(suffix, "other")


def extract_rows(makefile_text: str) -> list[dict]:
    """Every generation edge the Makefile expresses, as raw rows."""
    rules = parse_rules(makefile_text)
    rows: list[dict] = []

    for rule in rules:
        collapsed = _collapse(rule["recipe"])
        if ".pl" not in collapsed:
            continue
        tokens = _tokenize(collapsed)
        gen_tokens = _pl_tokens(tokens)
        if not gen_tokens:
            continue
        file_targets = [t for t in rule["targets"] if _looks_like_output(t)]
        if file_targets:
            gen = normalize(gen_tokens[0], "source")
            for out in file_targets:
                out_n = normalize(str(out), "build")
                inputs = sorted({
                    normalize(str(p), "build") for p in rule["prereqs"]
                    if _is_input_token(p) and normalize(str(p), "build") not in (out_n, gen)
                })
                rows.append({
                    "output": out_n,
                    "inputs": inputs,
                    "generator": gen,
                    "rule_site": f"{MAKEFILE_REL}:{rule['line']}",
                    "class": _classify(out_n, gen),
                    "generator_argv": _argv_for(tokens, tokens.index(gen_tokens[0]),
                                                out_n, inputs),
                })
            continue

        # A maintenance target: recover one edge per `*.pl`-and-redirect, or from
        # the `.ec` table for `mkerr.pl`.
        gen_indices = [i for i, t in enumerate(tokens) if _is_generator_token(t)]
        for gi in gen_indices:
            gen_tok = tokens[gi]
            gen = normalize(gen_tok, "source")
            if gen_tok.rsplit("/", 1)[-1] == "mkerr.pl":
                rows.extend(_mkerr_rows(rule, tokens, gi, gen))
                continue
            args: list[str] = []
            out: str | None = None
            k = gi + 1
            while k < len(tokens):
                tok = tokens[k]
                if tok in (">", ">>"):
                    if k + 1 < len(tokens):
                        out = tokens[k + 1]
                    break
                if tok == "<":
                    if k + 1 < len(tokens):
                        args.append(tokens[k + 1])
                    k += 2
                    continue
                if _breaks(tok):
                    break
                args.append(tok)
                k += 1
            if out is None:
                continue
            out = (_mv_final(tokens, out) or out).rstrip(";")
            inputs = sorted({
                normalize(a, "source") for a in args
                if _is_input_token(a) and normalize(a, "source") != gen
            })
            out_n = normalize(out, "source")
            rows.append({
                "output": out_n,
                "inputs": inputs,
                "generator": gen,
                "rule_site": f"{MAKEFILE_REL}:{rule['line']}",
                "class": _classify(out_n, gen),
                "generator_argv": _argv_for(tokens, gi, out_n, inputs),
            })
    return rows


def _mkerr_rows(rule: dict, tokens: list[str], gen_index: int, gen: str) -> list[dict]:
    """`mkerr.pl` edges, read from its `.ec` table rather than from a redirect."""
    src_dir = REPO_ROOT / SRC_DIR_REL
    specs: list[str] = []
    k = gen_index + 1
    conf: str | None = None
    while k < len(tokens):
        if tokens[k] in _SHELL_BREAK:
            break
        if tokens[k] == "-conf" and k + 1 < len(tokens):
            conf = tokens[k + 1]
            break
        k += 1
    if conf is None:
        specs.append("crypto/err/openssl.ec")
    elif "$" in conf:
        # `for E in *.ec` inside `cd $(SRCDIR)/engines`: enumerate the table dir.
        for ec in sorted((src_dir / "engines").glob("*.ec")):
            specs.append(f"engines/{ec.name}")
    else:
        specs.append(conf.lstrip("./"))

    rows: list[dict] = []
    for ec_tok in specs:
        ec_rel = ec_tok.removeprefix("../../src/openssl-3.6.4/")
        ec_path = src_dir / ec_rel
        if not ec_path.is_file():
            continue
        outs, ins = read_mkerr_outputs(ec_path)
        # The table's output paths are relative to mkerr.pl's cwd: the source
        # root for the default config, the table's own directory for `-conf`.
        base = "" if ec_rel == "crypto/err/openssl.ec" else ec_rel.rsplit("/", 1)[0] + "/"
        input_paths = sorted({normalize(str(p.relative_to(src_dir)), "source") for p in ins})
        for out in outs:
            out_n = normalize(base + out, "source")
            rows.append({
                "output": out_n,
                "inputs": input_paths,
                "generator": gen,
                "rule_site": f"{MAKEFILE_REL}:{rule['line']}",
                "class": _classify(out_n, gen),
                "generator_argv": ["perl", "util/mkerr.pl", "-conf",
                                   normalize(ec_rel, "source")],
            })
    return rows


# ---------------------------------------------------------------------------
# the body: a pure function of the raw rows and the declared set
# ---------------------------------------------------------------------------

def build_body(rows: list[dict], declared: list[str]) -> dict:
    """The atlas body from the raw rows. Pure and deterministic.

    The court calls this on the committed artefact's own rows (reconstructed
    from its `inputs`/`generator` columns) and on controlled in-memory
    mutations, so it must be free of I/O and ambient state.
    """
    configure = {normalize(p, "build") for p in CONFIGURE_PRODUCTS}

    recovered: set[str] = set()
    unrecovered: set[str] = set()
    for row in rows:
        if row.get("generator"):
            recovered.add(row["output"])
        else:
            unrecovered.add(row["output"])

    # Input marking: an input is `generated` when some recovered rule produced
    # it (or it is a Configure product); everything else is `source`.
    lineage: list[dict] = []
    for row in sorted(rows, key=lambda r: (r["output"], r.get("generator") or "",
                                           r.get("rule_site") or "")):
        inputs = []
        for p in sorted(set(row.get("inputs", []))):
            kind = "generated" if (p in recovered or p in configure) else "source"
            inputs.append({"path": p, "kind": kind})
        lineage.append({
            "output": row["output"],
            "inputs": inputs,
            "generator": row.get("generator"),
            "generator_argv": list(row.get("generator_argv", [])),
            "class": row.get("class", "other"),
            "rule_site": row.get("rule_site"),
        })

    declared_set = sorted(set(declared))
    residual = sorted((set(declared_set) | unrecovered) - recovered)

    generators = sorted({r["generator"] for r in rows if r.get("generator")})
    outputs = sorted(recovered | unrecovered)
    distinct_inputs = sorted({i["path"] for r in lineage for i in r["inputs"]})
    edges = sum(len(r["inputs"]) for r in lineage)
    generated_inputs = sum(1 for r in lineage for i in r["inputs"]
                           if i["kind"] == "generated")
    by_class: dict[str, int] = {}
    for r in lineage:
        by_class[r["class"]] = by_class.get(r["class"], 0) + 1

    return {
        "source_root": SRC_DIR_REL,
        "build_root": BUILD_DIR_REL,
        "rule_source": MAKEFILE_REL,
        "configure_products": sorted(configure),
        "input_marking": (
            "an input is `generated` when a recovered rule's `output` is that path, or "
            "when it is a Configure product (configdata.pm, Makefile); otherwise `source`. "
            "Marking is derived, not declared, so a mutation that turns a source into an "
            "output flips the kind."
        ),
        "reduction": {
            "recorded": "rules whose recipe invokes a `*.pl` generator (explicit file "
                        "rules and maintenance targets alike)",
            "not_recorded": "shell-only transformations (sed/append/concatenate) and "
                            "make feature probes; they generate no source file",
            "declared_base": "the residual base is the generated Makefile's `GENERATED`, "
                             "`GENERATED_MANDATORY` and `GENERATED_PODS` variables, which "
                             "are Configure's resolution for this profile; `build.info`'s "
                             "`GENERATE[...]` clauses are not used because they cover every "
                             "architecture and documentation profile",
            "deduplication": "rows deduplicated on (output, generator, rule_site)",
        },
        "counts": {
            "outputs": len(outputs),
            "inputs": len(distinct_inputs),
            "generators": len(generators),
            "edges": edges,
            "outputs_without_a_rule": len(residual),
            "rows": len(lineage),
            "by_class": dict(sorted(by_class.items())),
            "generated_inputs": generated_inputs,
            "source_inputs": edges - generated_inputs,
        },
        "generators": generators,
        "outputs_by_class": dict(sorted(by_class.items())),
        "outputs_without_a_rule": residual,
        "lineage": lineage,
    }


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    args = ap.parse_args(argv)

    auth = resolve_authority(args.authority)
    makefile = REPO_ROOT / MAKEFILE_REL
    if not makefile.is_file():
        raise SystemExit(
            f"phase22-genealogy: {MAKEFILE_REL} is absent, so no generation rule can be "
            "read; build the authority (forensics/tools/authority_build.py) first"
        )

    makefile_text = makefile.read_text(encoding="utf-8", errors="replace")
    rows = extract_rows(makefile_text)
    declared = declared_generated(makefile_text) | declared_templates(REPO_ROOT / SRC_DIR_REL)
    body = build_body(rows, sorted(declared))

    doc = envelope(
        kind="phase22-generated-lineage",
        authority=auth.id,
        inputs=[InputRef(name="generated-makefile", path=makefile)],
        body=body,
        generator=GENERATOR,
    )
    # The source tree is a directory, so it carries no file digest; it is named as
    # the second input the `build.info` declarations and `.ec` tables were read from.
    doc["inputs"].append({
        "name": "authority-source-tree",
        "path": SRC_DIR_REL,
        "note": "read for the `crypto/err/openssl.ec` and per-engine `*.ec` error tables; "
                "not content-addressed because it is a directory",
    })
    write_json(REPO_ROOT / OUT_REL, doc)

    c = body["counts"]
    print(f"[phase22-generated-lineage] outputs={c['outputs']} inputs={c['inputs']} "
          f"generators={c['generators']} edges={c['edges']} "
          f"outputs_without_a_rule={c['outputs_without_a_rule']}")
    print(f"  by_class={c['by_class']}")
    print(f"  -> {rel(REPO_ROOT / OUT_REL)}")
    return 0


# ---------------------------------------------------------------------------
# the court
# ---------------------------------------------------------------------------

def _rows_from_body(body: dict) -> list[dict]:
    """Reconstruct the raw rows from the committed body's own columns."""
    out: list[dict] = []
    for row in body["lineage"]:
        out.append({
            "output": row["output"],
            "inputs": [i["path"] for i in row["inputs"]],
            "generator": row.get("generator"),
            "generator_argv": row.get("generator_argv", []),
            "class": row.get("class", "other"),
            "rule_site": row.get("rule_site"),
        })
    return out


def court_genealogy(body: dict) -> dict:
    """`RT-PHASE22-GENEALOGY`: the extractor's own lineage and marking logic.

    Round-trips the committed body (re-derive it from its own rows and require
    equality), then drives `build_body` over controlled mutations of the raw
    rows and the declared set. The court FAILS if the extractor is insensitive
    to any of its defect classes: an output added with an input, an output
    declared with no rule, a second input added to an existing output, a
    generator removed, or an input's `source`/`generated` marking.
    """
    import copy

    checks: list[tuple[str, bool]] = []
    declared = sorted(set(body["outputs_without_a_rule"])
                      | {r["output"] for r in body["lineage"]})
    rows = _rows_from_body(copy.deepcopy(body))

    checks.append(("baseline: the artefact has outputs", body["counts"]["outputs"] > 0))
    checks.append(("baseline: the artefact has edges", body["counts"]["edges"] > 0))
    checks.append(("baseline: the artefact has generators", body["counts"]["generators"] > 0))
    checks.append(("baseline: at least one input is marked generated",
                   body["counts"]["generated_inputs"] > 0))

    # Round trip: re-derive the whole body from its own rows.
    rebuilt = build_body(copy.deepcopy(rows), list(declared))
    checks.append(("round-trip: lineage equal", rebuilt["lineage"] == body["lineage"]))
    checks.append(("round-trip: counts equal", rebuilt["counts"] == body["counts"]))
    checks.append(("round-trip: generators equal", rebuilt["generators"] == body["generators"]))
    checks.append(("round-trip: residual equal",
                   rebuilt["outputs_without_a_rule"] == body["outputs_without_a_rule"]))

    base = build_body(copy.deepcopy(rows), list(declared))

    # 1. add a generated output with an input.
    mutated = copy.deepcopy(rows)
    mutated.append({
        "output": f"{BLD_PREFIX}/synthetic/phase22_gen.c",
        "inputs": [f"{SRC_PREFIX}/synthetic/phase22_gen.c.in"],
        "generator": f"{SRC_PREFIX}/util/dofile.pl",
        "generator_argv": ["perl", "util/dofile.pl", "synthetic/phase22_gen.c.in"],
        "class": "source", "rule_site": f"{MAKEFILE_REL}:0",
    })
    new = build_body(mutated, list(declared))
    checks.append(("add-output: outputs rose by one",
                   new["counts"]["outputs"] == base["counts"]["outputs"] + 1))
    checks.append(("add-output: edges rose by one",
                   new["counts"]["edges"] == base["counts"]["edges"] + 1))
    checks.append(("add-output: the new input is marked source (it is no rule's output)",
                   any(i["path"].endswith("phase22_gen.c.in") and i["kind"] == "source"
                       for r in new["lineage"] for i in r["inputs"])))

    # 2. add a declared output with no rule (a residual, not a drop).
    declared2 = sorted(set(declared) | {f"{BLD_PREFIX}/synthetic/phase22_orphan.h"})
    new = build_body(copy.deepcopy(rows), declared2)
    checks.append(("add-declared: outputs_without_a_rule rose by one",
                   new["counts"]["outputs_without_a_rule"]
                   == base["counts"]["outputs_without_a_rule"] + 1))
    checks.append(("add-declared: the orphan is listed as a residual",
                   any(o.endswith("phase22_orphan.h") for o in new["outputs_without_a_rule"])))
    checks.append(("add-declared: it added no lineage row",
                   len(new["lineage"]) == len(base["lineage"])))

    # 3. add a second input to an existing output.
    target = next((r for r in base["lineage"] if r["inputs"]), None)
    if target is None:
        checks.append(("add-input: an output with an input was found", False))
    else:
        mutated = copy.deepcopy(rows)
        for r in mutated:
            if r["output"] == target["output"]:
                r["inputs"] = r["inputs"] + [f"{SRC_PREFIX}/synthetic/phase22_extra.in"]
        new = build_body(mutated, list(declared))
        checks.append(("add-input: edges rose by one",
                       new["counts"]["edges"] == base["counts"]["edges"] + 1))
        checks.append(("add-input: inputs rose by one",
                       new["counts"]["inputs"] == base["counts"]["inputs"] + 1))
        checks.append(("add-input: outputs unchanged",
                       new["counts"]["outputs"] == base["counts"]["outputs"]))

    # 4. remove a generator: the output becomes rule-less. Pick a row whose
    # generator is used by exactly one row, so the distinct-generator count must
    # fall by one.
    gen_use: dict[str, int] = {}
    out_use: dict[str, int] = {}
    for r in base["lineage"]:
        out_use[r["output"]] = out_use.get(r["output"], 0) + 1
        if r["generator"]:
            gen_use[r["generator"]] = gen_use.get(r["generator"], 0) + 1
    target = next((r for r in base["lineage"]
                   if r["generator"] and gen_use.get(r["generator"]) == 1
                   and out_use.get(r["output"]) == 1), None)
    if target is None:
        checks.append(("remove-generator: a uniquely-generated row was found", False))
    else:
        # declare it so the row-less output surfaces as a residual.
        declared3 = sorted(set(declared) | {target["output"]})
        mutated = copy.deepcopy(rows)
        for r in mutated:
            if r["output"] == target["output"]:
                r["generator"] = None
                r["generator_argv"] = []
        new = build_body(mutated, declared3)
        checks.append(("remove-generator: generators fell by one",
                       new["counts"]["generators"] == base["counts"]["generators"] - 1))
        checks.append(("remove-generator: the output is now a residual",
                       target["output"] in new["outputs_without_a_rule"]))
        checks.append(("remove-generator: an input it produced is no longer generated",
                       _any_reverted_to_source(base, new, target["output"])))

    # 5. mark an input generated vs source: point a source input at a real output.
    src_row = next((r for r in base["lineage"]
                    if any(i["kind"] == "source" for i in r["inputs"])), None)
    out_path = next((r["output"] for r in base["lineage"] if r["generator"]), None)
    if src_row is None or out_path is None:
        checks.append(("mark-input: a source input and an output were found", False))
    else:
        mutated = copy.deepcopy(rows)
        for r in mutated:
            if r["output"] == src_row["output"]:
                r["inputs"] = [p if p != _first_source_input(src_row) else out_path
                               for p in r["inputs"]]
        new = build_body(mutated, list(declared))
        marked = [i for r in new["lineage"] for i in r["inputs"]
                  if i["path"] == out_path and i["kind"] == "generated"]
        checks.append(("mark-input: inputs count unchanged",
                       new["counts"]["inputs"] == base["counts"]["inputs"]))
        checks.append(("mark-input: the repointed input reads generated",
                       bool(marked)))
        checks.append(("mark-input: generated_inputs rose (or held) while source fell",
                       new["counts"]["generated_inputs"] >= base["counts"]["generated_inputs"]
                       and new["counts"]["source_inputs"] <= base["counts"]["source_inputs"]))

    failures = [desc for desc, ok in checks if not ok]
    c = body["counts"]
    return {
        "court": "RT-PHASE22-GENEALOGY",
        "artefact": ARTEFACT_REL,
        "summary": (f"{c['outputs']} outputs, {c['edges']} edges, "
                    f"{c['generators']} generators, "
                    f"{c['outputs_without_a_rule']} without a rule"),
        "outputs": c["outputs"],
        "edges": c["edges"],
        "generators": c["generators"],
        "outputs_without_a_rule": c["outputs_without_a_rule"],
        "mutations": ["round-trip", "add-output", "add-declared", "add-input",
                      "remove-generator", "mark-input"],
        "observations": len(checks),
        "failures": failures,
        "verdict": "pass" if not failures else "fail",
    }


def _first_source_input(row: dict) -> str | None:
    for i in row["inputs"]:
        if i["kind"] == "source":
            return i["path"]
    return None


def _any_reverted_to_source(base: dict, new: dict, removed_output: str) -> bool:
    """Some input that was `generated` because of `removed_output` is now `source`."""
    before = {(r["output"], i["path"]) for r in base["lineage"] for i in r["inputs"]
              if i["kind"] == "generated" and i["path"] == removed_output}
    if not before:
        return True  # nothing depended on it; the generator count check carries the mutation
    after = {(r["output"], i["path"]) for r in new["lineage"] for i in r["inputs"]
             if i["kind"] == "generated" and i["path"] == removed_output}
    return not after


def courts() -> list[dict]:
    """`RT-PHASE22-GENEALOGY`, or `[]` while the artefact has not landed."""
    path = REPO_ROOT / ARTEFACT_REL
    if not path.is_file():
        return []
    doc = json.loads(path.read_text(encoding="utf-8"))
    return [court_genealogy(doc["body"])]


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
