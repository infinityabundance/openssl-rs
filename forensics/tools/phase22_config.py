#!/usr/bin/env python3
"""openssl-rs -- Phase 22.10 configuration, environment and default-path surface.

Recovers the third of Phase 22's "CLI, configuration and environment" surfaces: every place the
admitted authority reads the process environment, every compiled-in default path, and every
configuration directive its loader, its configuration modules and its own sample `openssl.cnf`
name. The result is the repository's standard, content-addressed atlas document at
`forensics/atlas/phase22/config-surface.json`.

The plan's rule
---------------
`docs/PHASE-22-SUBPHASES.md` section 6 is this plane's contract:

    22.10 "must treat an environment variable and a configuration directive as contract items
    with a name, a default, a scope, a security filter and an effect."

So the document does not merely list `getenv` calls. It reconstructs, for each named variable and
each directive, five fields:

  * ``name``            -- the literal variable or directive name;
  * ``default``         -- what OpenSSL uses when the item is absent (a compiled-in path, an
                           environment fallback, or ``"unset"``);
  * ``scope``           -- ``library`` / ``command`` / ``engine`` / ``provider`` / ``test`` /
                           ``demo``, derived from the file that reads it or the section that
                           defines it;
  * ``security_filter`` -- for a variable, how the read is gated: ``safe`` (through
                           ``ossl_safe_getenv``, which returns NULL when the process is
                           ``setuid``/``setgid``), ``unsafe`` (raw ``getenv``), ``mixed`` when a
                           name is read both ways, or ``dynamic`` when the name is only known at
                           run time; for a directive, the gate that supplies the value
                           (``config-file`` / ``environment`` / ``include-path``);
  * ``effect``          -- a one-line statement of what the item changes.

The three recoveries
--------------------
**Environment.** Every ``getenv`` / ``ossl_safe_getenv`` / ``secure_getenv`` / ``ossl_getenv`` call
site in the authority tree, with the literal name (string literals in place, and the tree's own
``#define NAME "value"`` macros and the ``X509_get_default_cert_{dir,file}_env`` accessors resolved
to their literals), the file and line, the enclosing function, and the reader. A site whose name is
only known at run time -- ``getenv(arg)`` in the ``env:`` password source, ``ossl_safe_getenv(name)``
in the ``$ENV::`` substitution -- is recorded with ``name: null`` and ``resolved: false`` rather
than dropped, because the plan's rule is that a variable the source reads is a residual to record.

**Default paths.** From the pinned `configdata.pm` (``libdir``, ``openssldir``) and the authority's
own built `openssl` binary (``OPENSSLDIR`` / ``ENGINESDIR`` / ``MODULESDIR`` via
``openssl version -d/-e/-m``), plus the paths the source derives from ``OPENSSLDIR`` and the
cert-area macros (`include/internal/common.h`) and the default configuration file
(`crypto/conf/conf_mod.c:CONF_get1_default_config_file`). The compiled-in values come out of the
binary as absolute paths under the repository root (the court mounts the repo at `/work`); they are
rewritten repository-relative so the document carries no host-varying path.

**Directives.** The union of the keys the source looks up by a literal or macro-resolved name
(`NCONF_get_string`, `NCONF_get_number_e`, `NCONF_get_section`, `CONF_get_string`,
`CONF_get_section`, `_CONF_get_*`), the config-module names registered with `CONF_module_add`, the
directive names the engine/provider/serialisation configuration modules compare by literal
(`strcmp(confname, "identity")`, ...), the configuration parser's own keywords (`.include`,
`.pragma` and its sub-pragmas), and every active key the authority's own `apps/openssl.cnf` sample
defines. Each directive records the scope of the section/file that defines it and the effect its
reader gives it.

The document also carries the full **`config_dispatch`** list: every `NCONF_*` / `CONF_*` /
`_CONF_*` entry point declared in the authority's `conf.h.in` / `conf_api.h` and the extension
entry point `X509V3_EXT_nconf`/`_nid`, each with the call sites the source reaches it from.

Cross-referencing documentation, where it is cheap
--------------------------------------------------
OpenSSL maintains a canonical list of the environment variables its libraries and commands use,
and of which are treated as security-sensitive, in `doc/man7/openssl-env.pod`. This tool parses
that manual and records `documented` and `documented_security_sensitive` on every variable, so
`residuals` can name the variables the source reads that the manual omits, the security-sensitive
variables a site reads with the raw `getenv` (which is exactly the `openssl rehash` divergence the
manual itself calls out), and the documented variables no site in this profile reads.

Determinism
-----------
Every list is sorted and every count is derived. No timestamp, PID or scratch path is written. The
same pinned source, `configdata.pm` and built binary produce byte-identical JSON, which is what
lets `RT-PHASE22-CONFIG` reconstruct the raw model from the document's own rows, re-derive the body
and mutate it.

Non-claim
---------
`RT-PHASE22-CONFIG` ties the artefact to this tool's aggregation logic and to the rows the scan
produced, **not** to a fresh source scan: it reconstructs the raw model from the committed
document's own `env_sites`/`default_paths`/`directive_sites`/`config_dispatch` rows, re-derives
the body and requires equality, then mutates those rows. A reviewer re-deriving the surface from
the authority must run this tool again, which `pipeline.sh` does before the court.

The directive set is not claimed closed. The `ssl_conf` command vocabulary (`MinProtocol`,
`CipherString`, ...), which the SSL configuration module resolves at run time through
`SSL_CONF_cmd` from a named section, and the provider parameter namespace beyond the literal keys
`crypto/provider_conf.c` names, are not enumerable from these call sites; the `residuals` block
says so rather than implying the set is closed.

Output
------
    forensics/atlas/phase22/config-surface.json

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
    envelope,
    rel,
    resolve_authority,
    write_json,
)

GENERATOR = "forensics/tools/phase22_config.py"
ARTEFACT_REL = "forensics/atlas/phase22/config-surface.json"
OUT_REL = ARTEFACT_REL

SRC_REL = "forensics/authorities/src/openssl-3.6.4"
BUILD_DIR_REL = "forensics/authorities/build/openssl-3.6.4-production"
SAMPLE_CNF_REL = SRC_REL + "/apps/openssl.cnf"
ENV_POD_REL = SRC_REL + "/doc/man7/openssl-env.pod"
CONF_H_IN_REL = SRC_REL + "/include/openssl/conf.h.in"
CONF_API_H_REL = SRC_REL + "/include/openssl/conf_api.h"
COMMON_H_REL = SRC_REL + "/include/internal/common.h"
BINARY_REL_TO_BUILD = "apps/openssl"
PLAN_REL = "docs/PHASE-22-SUBPHASES.md"

# The source file kinds that can carry an environment read or a config lookup.
SOURCE_SUFFIXES = (".c", ".h", ".cc", ".c.in")

# The compiler directory scan is the whole admitted tree, so a provider's or a demo's read is
# recorded rather than narrowed away.
SCAN_TOP_DIRS = ("crypto", "ssl", "apps", "providers", "engines", "include", "test", "fuzz",
                 "demos", "util", "Configurations")

# ---------------------------------------------------------------------------
# scope from path
# ---------------------------------------------------------------------------

_SCOPE_BY_PREFIX = (
    ("forensics/authorities/src/openssl-3.6.4/providers/", "provider"),
    ("forensics/authorities/src/openssl-3.6.4/crypto/engine/", "engine"),
    ("forensics/authorities/src/openssl-3.6.4/apps/", "command"),
    ("forensics/authorities/src/openssl-3.6.4/test/", "test"),
    ("forensics/authorities/src/openssl-3.6.4/fuzz/", "test"),
    ("forensics/authorities/src/openssl-3.6.4/demos/", "demo"),
    ("forensics/authorities/src/openssl-3.6.4/util/", "tooling"),
    ("forensics/authorities/src/openssl-3.6.4/Configurations/", "tooling"),
)


def scope_of(path: Path) -> str:
    """The compatibility scope a source file belongs to, from its path under the authority."""
    posix = rel(path)
    for prefix, scope in _SCOPE_BY_PREFIX:
        if posix.startswith(prefix):
            return scope
    if "/crypto/" in posix or "/ssl/" in posix or "/include/" in posix:
        return "library"
    return "library"


def disposition_of(scope: str) -> str:
    """The plan's section-4 disposition for a contract item of this scope."""
    return {
        "library": "REQUIRED_COMPATIBILITY",
        "command": "REQUIRED_COMPATIBILITY",
        "engine": "REQUIRED_COMPATIBILITY",
        "provider": "REQUIRED_COMPATIBILITY",
        "test": "TEST_ONLY",
        "demo": "DEMO_ONLY",
        "tooling": "TOOLING_ONLY",
    }.get(scope, "UNKNOWN")


# ---------------------------------------------------------------------------
# environment reads
# ---------------------------------------------------------------------------

# The readers. `ossl_safe_getenv`/`secure_getenv` withhold the value when the process is
# setuid/setgid; raw `getenv` and the cpuid wrapper `ossl_getenv` do not.
_READERS = {
    "ossl_safe_getenv": "safe",
    "secure_getenv": "safe",
    "getenv": "unsafe",
    "ossl_getenv": "unsafe",
}
_READER_RE = re.compile(r"\b(ossl_safe_getenv|secure_getenv|ossl_getenv|getenv)\s*\(")

# A line that *declares* a reader rather than calling it (`char *ossl_safe_getenv(const char
# *name)`, `static variant_char *ossl_getenv(const char *name)`).
_READER_DECL_RE = re.compile(
    r"^\s*(?:static\s+)?(?:char|const\s+char|variant_char|WCHAR)\s*\*?\s*"
    r"(?:ossl_safe_getenv|ossl_getenv)\s*\("
)

# The two accessors whose whole body is the name of a documented variable.
_ENV_ACCESSORS = {
    "X509_get_default_cert_dir_env": "SSL_CERT_DIR",
    "X509_get_default_cert_file_env": "SSL_CERT_FILE",
}

_STRING_LITERAL_RE = re.compile(r'"([^"\\]*(?:\\.[^"\\]*)*)"')
_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
# A C parameter declaration is not a variable name (`const char *name`).
_PARAM_DECL_RE = re.compile(r"\b(?:char|const\s+char|WCHAR|variant_char)\s*\*?\s*$")


def build_macro_table(src_root: Path, files: list[Path]) -> dict[str, str]:
    """`#define NAME "value"` string macros across the scanned tree, for name resolution."""
    table: dict[str, str] = {}
    define_re = re.compile(r'^\s*#\s*define\s+([A-Za-z_][A-Za-z0-9_]*)\s+"([^"]*)"\s*$')
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            m = define_re.match(line)
            if m:
                table[m.group(1)] = m.group(2)
    return table


def _split_top_level_args(argtext: str) -> list[str]:
    """Split a call's argument text on top-level commas."""
    out: list[str] = []
    depth = 0
    cur = ""
    in_str = False
    esc = False
    for ch in argtext:
        if in_str:
            cur += ch
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
            cur += ch
        elif ch in "([":
            depth += 1
            cur += ch
        elif ch in ")]":
            depth -= 1
            cur += ch
        elif ch == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


def resolve_name_expr(expr: str, macros: dict[str, str]) -> list[str]:
    """The variable names a call argument denotes, or [] when it is only known at run time."""
    names: list[str] = list(_STRING_LITERAL_RE.findall(expr))
    if names:
        return names
    # No literal: try identifiers that are string macros or the two X509 accessors.
    for ident in _IDENT_RE.findall(expr):
        if ident in _ENV_ACCESSORS:
            names.append(_ENV_ACCESSORS[ident])
        elif ident in macros:
            names.append(macros[ident])
    return names


def function_ranges(text: str) -> list[tuple[str, int, int]]:
    """`(name, start_line, end_line)` for each top-level function definition, 1-based.",
    Pragmatic brace matching: a definition header starts at column zero, contains `(`, and reaches
    a `{` before any `;`; the body ends at the matching close brace.
    """
    header_re = re.compile(
        r"^[A-Za-z_][A-Za-z0-9_\s\*]*?\b([A-Za-z_][A-Za-z0-9_]*)\s*\([^;{]*$"
    )
    control = {"if", "for", "while", "switch", "return", "else", "do", "sizeof", "case"}
    lines = text.split("\n")
    ranges: list[tuple[str, int, int]] = []
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        if not line or line[0] in " \t#/*}":
            i += 1
            continue
        m = header_re.match(line)
        if not m:
            i += 1
            continue
        # Find the `{` that opens the body, before any `;` that would make it a declaration.
        brace_line = None
        j = i
        while j < n and j < i + 40:
            seg = lines[j]
            semi = seg.find(";")
            brace = seg.find("{")
            if brace != -1 and (semi == -1 or brace < semi):
                brace_line = j
                break
            if semi != -1:
                break
            j += 1
        if brace_line is None:
            i += 1
            continue
        depth = 0
        end = None
        for k in range(brace_line, n):
            for ch in lines[k]:
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        end = k
                        break
            if end is not None:
                break
        if end is None:
            i += 1
            continue
        name = m.group(1)
        if name in control:
            i += 1
            continue
        ranges.append((name, i + 1, end + 1))
        i = end + 1
    return ranges


def caller_at(ranges: list[tuple[str, int, int]], line: int) -> str | None:
    best = None
    for name, start, end in ranges:
        if start <= line <= end and (best is None or start > best[1]):
            best = (name, start)
    return best[0] if best else None


def scan_env_sites(src_root: Path, files: list[Path], macros: dict[str, str]) -> list[dict]:
    """Every environment read, one row per (name, file, line).

    ``crypto/getenv.c`` is skipped: it *is* the safe reader (``ossl_safe_getenv``), so its
    ``getenv(name)``/``secure_getenv(name)`` bodies read a run-time name, not a variable, and
    recording them would double the reader implementation as two phantom variables.
    """
    sites: list[dict] = []
    for path in files:
        if path.name == "getenv.c" and path.parent.name == "crypto":
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel_path = rel(path)
        ranges = None
        for lineno, line in enumerate(text.split("\n"), start=1):
            if _READER_DECL_RE.match(line):
                continue
            for m in _READER_RE.finditer(line):
                reader = m.group(1)
                # Find the matching close paren for this call.
                depth = 1
                idx = m.end()
                while idx < len(line) and depth:
                    if line[idx] == "(":
                        depth += 1
                    elif line[idx] == ")":
                        depth -= 1
                    idx += 1
                argtext = line[m.end():idx - 1] if depth == 0 else line[m.end():]
                if _PARAM_DECL_RE.search(argtext.strip()):
                    continue  # a parameter list, not a call
                names = resolve_name_expr(argtext, macros)
                if ranges is None:
                    ranges = function_ranges(text)
                caller = caller_at(ranges, lineno)
                scope = scope_of(path)
                if not names:
                    sites.append({
                        "name": None, "file": rel_path, "line": lineno, "caller": caller,
                        "reader": _READERS[reader], "resolved": False, "scope": scope,
                        "expression": argtext.strip(),
                    })
                else:
                    for name in names:
                        sites.append({
                            "name": name, "file": rel_path, "line": lineno, "caller": caller,
                            "reader": _READERS[reader], "resolved": True, "scope": scope,
                            "expression": argtext.strip(),
                        })
    sites.sort(key=lambda s: ((s["name"] or ""), s["file"], s["line"], s["reader"]))
    return sites


# ---------------------------------------------------------------------------
# the documented environment (doc/man7/openssl-env.pod)
# ---------------------------------------------------------------------------

_ITEM_RE = re.compile(r"^=item\s+(.*)$")
_B_TOKEN_RE = re.compile(r"B<([^>]+)>")


def parse_env_pod(text: str) -> dict[str, dict]:
    """Documented variable -> {security_sensitive, historical} from `openssl-env.pod`.

    The manual's items carry one or more ``B<NAME>`` tokens and a sentence stating whether the
    variable is "considered security-sensitive". The HISTORY section names variables the library
    no longer considers. The ``OPENSSL_TRACE`` item carries a nested ``=over`` list of trace
    *values* (``ALL``, ``TLS``, ...); those are not environment variable names, so only items at
    the manual's top level (``over`` depth 1) are collected.
    """
    out: dict[str, dict] = {}
    lines = text.split("\n")
    item_names: list[str] = []
    item_text: list[str] = []
    historical = False
    depth = 0

    def flush() -> None:
        if not item_names:
            return
        body = " ".join(item_text).lower()
        # An affirmative sentence is the signal; a negative one is phrased "is not considered
        # security-sensitive" and so does not match. This also handles the `SSL_CERT_DIR` item,
        # which is affirmative and *then* carves out `openssl rehash`: the general rule is
        # security-sensitive and the exception is a per-site fact the residual records.
        sensitive = bool(re.search(r"\b(?:is|are)\s+considered\s+(?:a\s+)?security-sensitive",
                                   body))
        for name in item_names:
            out[name] = {"security_sensitive": bool(sensitive), "historical": historical}

    for line in lines:
        if line.startswith("=head1"):
            flush()
            item_names, item_text = [], []
            historical = "HISTORY" in line.upper()
            continue
        if line.startswith("=over"):
            depth += 1
            continue
        if line.startswith("=back"):
            flush()
            item_names, item_text = [], []
            depth = max(0, depth - 1)
            continue
        m = _ITEM_RE.match(line)
        if m:
            flush()
            item_names, item_text = [], []
            if depth == 1:
                item_names = [n.strip() for n in _B_TOKEN_RE.findall(m.group(1))]
            continue
        if item_names and not line.startswith("="):
            item_text.append(line)
    flush()
    return out


# ---------------------------------------------------------------------------
# default paths
# ---------------------------------------------------------------------------

def configdata_paths(build_dir: Path) -> dict:
    """`libdir`, `openssldir`, `prefix` from the pinned `configdata.pm`."""
    path = build_dir / "configdata.pm"
    if not path.is_file():
        return {}
    text = path.read_text(encoding="utf-8", errors="replace")
    out: dict[str, str] = {}
    for key in ("libdir", "openssldir", "prefix", "sourcedir", "builddir"):
        m = re.search(rf'^\s*"{key}"\s*=>\s*"([^"]*)"', text, re.MULTILINE)
        if m:
            out[key] = m.group(1)
    return out


def normalize_path(value: str) -> str:
    """Rewrite the repository-root prefix out of a compiled-in absolute path."""
    root = REPO_ROOT.as_posix().rstrip("/")
    if value.startswith(root + "/"):
        return value[len(root) + 1:]
    return value


def binary_paths(build_dir: Path) -> dict:
    """The built binary's compiled-in directories, from `openssl version -d/-e/-m`."""
    binary = build_dir / BINARY_REL_TO_BUILD
    if not binary.is_file():
        return {}
    env = dict(os.environ)
    prev = env.get("LD_LIBRARY_PATH", "")
    env["LD_LIBRARY_PATH"] = (str(build_dir) + (":" + prev if prev else ""))
    out: dict[str, str] = {}
    for flag, key in (("-d", "OPENSSLDIR"), ("-e", "ENGINESDIR"), ("-m", "MODULESDIR")):
        try:
            res = subprocess.run([str(binary), "version", flag], cwd=str(build_dir), env=env,
                                 capture_output=True, text=True, check=False)
        except OSError:
            continue
        m = re.search(rf"{key}:\s*\"([^\"]*)\"", res.stdout)
        if m:
            out[key] = normalize_path(m.group(1))
    return out


def build_default_paths(bin_paths: dict, cd: dict) -> list[dict]:
    """The default-path contract items: compiled-in, configured and source-derived."""
    openssldir = bin_paths.get("OPENSSLDIR") or normalize_path(cd.get("openssldir", ""))
    rows: list[dict] = []

    def add(name, value, kind, source, scope, effect):
        rows.append({"name": name, "value": value, "kind": kind, "source": source,
                     "scope": scope, "effect": effect})

    if "OPENSSLDIR" in bin_paths:
        add("OPENSSLDIR", bin_paths["OPENSSLDIR"], "compiled-in",
            "openssl version -d", "library",
            "default certificate and configuration area compiled into the library")
    if "ENGINESDIR" in bin_paths:
        add("ENGINESDIR", bin_paths["ENGINESDIR"], "compiled-in",
            "openssl version -e", "engine",
            "default directory the dynamic engine loader searches")
    if "MODULESDIR" in bin_paths:
        add("MODULESDIR", bin_paths["MODULESDIR"], "compiled-in",
            "openssl version -m", "provider",
            "default directory the provider module loader searches")
    if cd.get("libdir"):
        add("libdir", cd["libdir"], "configured", "configdata.pm", "library",
            "library directory name below the install prefix")
    if cd.get("openssldir"):
        add("openssldir", normalize_path(cd["openssldir"]), "configured", "configdata.pm",
            "library", "the configured --openssldir, the configuration/certificate root")

    if openssldir:
        add("X509_CERT_AREA", openssldir, "derived", "include/internal/common.h:83", "library",
            "X509_get_default_cert_area(): the certificate area root")
        add("X509_CERT_DIR", openssldir + "/certs", "derived",
            "include/internal/common.h:84", "library",
            "X509_get_default_cert_dir(): the default CA directory")
        add("X509_CERT_FILE", openssldir + "/cert.pem", "derived",
            "include/internal/common.h:85", "library",
            "X509_get_default_cert_file(): the default CA bundle file")
        add("X509_PRIVATE_DIR", openssldir + "/private", "derived",
            "include/internal/common.h:86", "library",
            "X509_get_default_private_dir(): the default private-key directory")
        add("default_config_file", openssldir + "/openssl.cnf", "derived",
            "crypto/conf/conf_mod.c:CONF_get1_default_config_file", "library",
            "the configuration file loaded when OPENSSL_CONF is unset")

    rows.sort(key=lambda r: r["name"])
    return rows


# ---------------------------------------------------------------------------
# directives
# ---------------------------------------------------------------------------

# Config keys with a curated default and effect. Names not listed get a derived effect.
_DIRECTIVE_META = {
    "openssl_conf": ("unset", "library",
                     "names the section whose entries select the configuration modules to load"),
    "config_diagnostics": ("0", "library",
                           "non-zero makes the configuration loader report otherwise-silent errors"),
    "oid_section": ("unset", "library",
                    "names the section that adds user OBJECT IDENTIFIERs"),
    "oid_file": ("unset", "library", "a file of extra OBJECT IDENTIFIER definitions"),
    "providers": ("unset", "library",
                  "names the section listing the providers to load and activate"),
    "provider": ("unset", "provider", "names a provider and its section of parameters"),
    "activate": ("unset", "provider",
                 "a per-provider directive that loads and activates the provider"),
    "default_properties": ("unset", "provider",
                           "the default property query applied to algorithm fetches"),
    "ssl_conf": ("unset", "library",
                 "names the section of SSL configuration commands applied at context creation"),
    "system_default": ("unset", "library",
                       "a well-known ssl_conf section applied to every default SSL context"),
    "alg_section": ("unset", "library",
                    "names the section of global algorithm settings"),
    "identity": ("disabled", "provider",
                 "the identity a provider advertises when it is added"),
    "soft_load": ("0", "provider",
                  "a provider directive that tolerates a missing module instead of failing"),
    "module": ("unset", "provider", "the module file backing a provider"),
    "path": ("unset", "library", "the directory a dynamically loaded module is searched in"),
    "init": ("unset", "engine", "whether a configured engine is initialised at load time"),
    "engine_id": ("unset", "engine", "the ENGINE identifier a dynamic engine is loaded as"),
    "dynamic_path": ("unset", "engine", "the shared object a dynamic engine is loaded from"),
    "default_algorithms": ("unset", "engine",
                           "the set of algorithms a configured engine takes over"),
    "enabled_logs": ("unset", "library",
                     "the named CT log list sections the CT log store loads"),
    "description": ("unset", "library", "a CT log's human-readable description"),
    "key": ("unset", "library", "a CT log's base64-encoded public key"),
    "asn1": ("unset", "command",
             "an ASN.1 generation template section used by asn1parse and s_client"),
}

# The sample's sections and the scope of the subsystem that consumes them.
_SAMPLE_SECTION_SCOPE = {
    "openssl_init": "library", "provider_sect": "library", "default_sect": "library",
    "new_oids": "library", "default": "library",
}


def _section_scope(section: str) -> str:
    return _SAMPLE_SECTION_SCOPE.get(section, "command")


def parse_sample_cnf(text: str, rel_path: str) -> list[dict]:
    """Active (uncommented) keys the sample `openssl.cnf` defines, with their section."""
    rows: list[dict] = []
    section = "default"
    for lineno, raw in enumerate(text.split("\n"), start=1):
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        stripped = line.strip()
        m = re.match(r"^\[([^\]]+)\]\s*$", stripped)
        if m:
            section = m.group(1).strip()
            continue
        m = re.match(r"^([A-Za-z0-9_.]+)\s*=\s*(.*)$", stripped)
        if m:
            rows.append({
                "name": m.group(1), "scope": _section_scope(section), "source_kind": "sample",
                "defined_in": {"file": rel_path, "line": lineno, "section": section},
                "sample_value": m.group(2).strip(), "security_filter": "config-file",
            })
    return rows


# name-lookup entry points: (function, argument index carrying the name)
_KEY_LOOKUPS = {
    "NCONF_get_string": 2, "NCONF_get_number_e": 2, "CONF_get_string": 2,
    "_CONF_get_string": 2,
}
_SECTION_LOOKUPS = {
    "NCONF_get_section": 1, "CONF_get_section": 1, "_CONF_get_section": 1,
}
_LOOKUP_RE = re.compile(
    r"\b(NCONF_get_string|NCONF_get_number_e|CONF_get_string|_CONF_get_string|"
    r"NCONF_get_section|CONF_get_section|_CONF_get_section)\s*\("
)

# Config-module directive names registered with CONF_module_add.
_MODULE_ADD_RE = re.compile(r'\bCONF_module_add\s*\(\s*"([^"]+)"')

# Directives a configuration module compares a config-derived name against by literal. Restricted to
# the two modules that dispatch on a config key by `strcmp` -- `crypto/provider_conf.c` and
# `crypto/engine/eng_cnf.c` -- so a `strcmp(<name>, "secp192r1")` curve-name test is not mistaken
# for a directive.
_STRCMP_KEY_RE = re.compile(
    r'\bstrcmp\s*\(\s*([A-Za-z_]\w*(?:name|key))\s*,\s*"([a-z_][a-z0-9_]*(?:\.[a-z0-9_]+)*)"\s*\)'
)
_STRCMP_KEY_FILES = ("crypto/provider_conf.c", "crypto/engine/eng_cnf.c")

# The configuration parser's own keywords (crypto/conf/conf_def.c).
_CONF_KEYWORDS = (
    (".include", "include-path",
     ("includes another configuration file, resolved against the "
      "include directory or OPENSSL_CONF_INCLUDE")),
    (".pragma", "config-file", "sets configuration-loader behaviour for the current file"),
    ("dollarid", "config-file", "a .pragma that lets a `$`-prefixed bare word be an expansion"),
    ("abspath", "config-file", "a .pragma that makes .include paths absolute"),
    ("includedir", "config-file", "a .pragma that sets the directory searched by .include"),
    ("ENV", "environment",
     "sections and `$ENV::` references that read the process environment"),
)


def _directive_meta(name: str) -> tuple[str, str, str]:
    """`(default, effect, scope)` for a curated directive, or an empty tail when not curated."""
    if name in _DIRECTIVE_META:
        default, scope, effect = _DIRECTIVE_META[name]
        return default, effect, scope
    return "unset", "", ""


def scan_source_directives(src_root: Path, files: list[Path], macros: dict[str, str]) -> list[dict]:
    """Directive definitions the source names: lookups, module names, strcmp keys, keywords."""
    rows: list[dict] = []
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel_path = rel(path)
        scope = scope_of(path)
        strcmp_keys_here = any(rel_path.endswith(f) for f in _STRCMP_KEY_FILES)
        ranges = None
        for lineno, line in enumerate(text.split("\n"), start=1):
            matched = False
            for m in _LOOKUP_RE.finditer(line):
                func = m.group(1)
                idx = _KEY_LOOKUPS.get(func, _SECTION_LOOKUPS.get(func))
                role = "key" if func in _KEY_LOOKUPS else "section"
                if idx is None:
                    continue
                # Reconstruct the call's argument text.
                depth = 1
                k = m.end()
                while k < len(line) and depth:
                    if line[k] == "(":
                        depth += 1
                    elif line[k] == ")":
                        depth -= 1
                    k += 1
                argtext = line[m.end():k - 1] if depth == 0 else line[m.end():]
                args = _split_top_level_args(argtext)
                if idx >= len(args):
                    continue
                names = resolve_name_expr(args[idx], macros)
                if not names:
                    continue
                if ranges is None:
                    ranges = function_ranges(text)
                caller = caller_at(ranges, lineno)
                for name in names:
                    rows.append({"name": name, "scope": scope, "source_kind": "source-lookup",
                                 "defined_in": {"file": rel_path, "line": lineno,
                                                "caller": caller, "role": role,
                                                "lookup": func},
                                 "security_filter": "config-file"})
                matched = True
            for m in _MODULE_ADD_RE.finditer(line):
                if ranges is None:
                    ranges = function_ranges(text)
                rows.append({"name": m.group(1), "scope": "library",
                             "source_kind": "module-name",
                             "defined_in": {"file": rel_path, "line": lineno,
                                            "caller": caller_at(ranges, lineno)},
                             "security_filter": "config-file"})
                matched = True
            for m in _STRCMP_KEY_RE.finditer(line) if strcmp_keys_here else ():
                if ranges is None:
                    ranges = function_ranges(text)
                rows.append({"name": m.group(2), "scope": scope,
                             "source_kind": "module-key",
                             "defined_in": {"file": rel_path, "line": lineno,
                                            "caller": caller_at(ranges, lineno)},
                             "security_filter": "config-file"})
                matched = True
            if matched:
                continue
    # The parser keywords are not file calls; they are named here with their source site.
    conf_def = src_root / "crypto/conf/conf_def.c"
    conf_def_rel = rel(conf_def) if conf_def.is_file() else "crypto/conf/conf_def.c"
    for name, gate, effect in _CONF_KEYWORDS:
        rows.append({"name": name, "scope": "library", "source_kind": "parser-keyword",
                     "defined_in": {"file": conf_def_rel, "line": None, "role": "keyword"},
                     "security_filter": gate, "effect_hint": effect})
    rows.sort(key=lambda r: (r["name"], r["source_kind"],
                             r["defined_in"].get("file") or "",
                             r["defined_in"].get("line") or 0))
    return rows


def aggregate_directives(sites: list[dict]) -> list[dict]:
    """One directive per name: default, scope(s), security filter, effect, and its sites."""
    by_name: dict[str, dict] = {}
    for s in sites:
        entry = by_name.setdefault(s["name"], {
            "name": s["name"], "default": None, "scope": None, "security_filter": None,
            "effect": None, "defined_in": [], "source_kinds": [],
        })
        entry["defined_in"].append(s["defined_in"])
        if s["source_kind"] not in entry["source_kinds"]:
            entry["source_kinds"].append(s["source_kind"])
        if s.get("effect_hint") and not entry["effect"]:
            entry["effect"] = s["effect_hint"]
    out: list[dict] = []
    for name in sorted(by_name):
        entry = by_name[name]
        default, effect, curated_scope = _directive_meta(name)
        entry["default"] = default
        # Scope precedence: an explicit source-lookup scope beats the sample's section scope.
        scopes = sorted({s["scope"] for s in sites if s["name"] == name})
        entry["scope"] = curated_scope or (scopes[0] if scopes else "library")
        gates = sorted({s["security_filter"] for s in sites if s["name"] == name})
        entry["security_filter"] = gates[0] if len(gates) == 1 else (
            "mixed" if gates else "config-file")
        if not entry["effect"]:
            if effect:
                entry["effect"] = effect
            elif "sample" in entry["source_kinds"]:
                entry["effect"] = "a directive the authority's own openssl.cnf sample defines"
            else:
                entry["effect"] = "a configuration key read by the authority"
        entry["defined_in"].sort(key=lambda d: (d.get("file") or "", d.get("line") or 0,
                                                d.get("role") or ""))
        entry["source_kinds"].sort()
        entry["disposition"] = disposition_of(entry["scope"])
        out.append(entry)
    return out


# ---------------------------------------------------------------------------
# config dispatch entry points
# ---------------------------------------------------------------------------

_ENTRY_POINT_RE = re.compile(r"\b(NCONF_[A-Za-z0-9_]+|_CONF_[A-Za-z0-9_]+|CONF_[A-Za-z0-9_]+)\s*\(")
_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_LINE_COMMENT_RE = re.compile(r"//[^\n]*")


def declared_config_entry_points(src_root: Path) -> list[dict]:
    """Every `NCONF_*`/`CONF_*`/`_CONF_*` entry point declared in the public conf headers.

    The declarations are flattened first: several are split across two physical lines
    (`NCONF_get_section`, `NCONF_get_number_e`, `CONF_get_string`), and a line-at-a-time match
    would silently omit exactly those. Comments are removed so a mention in prose is not a
    declaration, and a nested-token check keeps `sk_CONF_VALUE_new` and friends out.
    """
    entries: dict[str, dict] = {}
    for rel_path in (CONF_H_IN_REL, CONF_API_H_REL):
        path = src_root / rel_path.split("src/openssl-3.6.4/", 1)[-1]
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        text = _BLOCK_COMMENT_RE.sub(" ", text)
        text = _LINE_COMMENT_RE.sub(" ", text)
        flat = re.sub(r"\s+", " ", text)
        for m in _ENTRY_POINT_RE.finditer(flat):
            name = m.group(1)
            # `#define CONF_modules_free()` and `OPENSSL_no_config` are aliases, not new names;
            # include the latter two only when they read as a call, which the regex already does.
            entries.setdefault(name, {"function": name, "declared_in": rel(path), "note": None})
    # The extension configuration entry points, declared in x509v3.h.in.
    for name in ("X509V3_EXT_nconf", "X509V3_EXT_nconf_nid"):
        x509v3 = src_root / "include/openssl/x509v3.h.in"
        entries.setdefault(name, {
            "function": name, "declared_in": rel(x509v3) if x509v3.is_file() else "",
            "note": "X.509 extension configuration lookup",
        })
    return [entries[k] for k in sorted(entries)]


def find_call_sites(src_root: Path, files: list[Path], names: list[str]) -> dict[str, list[dict]]:
    """For each named function, the sorted call sites across the scanned tree."""
    wanted = set(names)
    call_re = re.compile(r"\b(" + "|".join(re.escape(n) for n in sorted(wanted)) + r")\s*\(")
    decl_re = re.compile(r"^[A-Za-z_].*\b(" + "|".join(re.escape(n) for n in sorted(wanted))
                         + r")\s*\(")
    sites: dict[str, list[dict]] = {n: [] for n in names}
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel_path = rel(path)
        ranges = None
        for lineno, line in enumerate(text.split("\n"), start=1):
            for m in call_re.finditer(line):
                name = m.group(1)
                if decl_re.match(line) and line.rstrip().endswith(";"):
                    continue  # a prototype
                # Skip a definition header (`X509_EXTENSION *X509V3_EXT_nconf(CONF *conf, ...`).
                before = line[:m.start()].rstrip()
                type_prefix = (before and before[-1].rstrip() in "*" and not before.endswith("=")
                               and re.search(r"[A-Za-z_]\s*\*\s*$", before))
                if type_prefix:
                    continue
                if ranges is None:
                    ranges = function_ranges(text)
                sites[name].append({"file": rel_path, "line": lineno,
                                    "caller": caller_at(ranges, lineno)})
    for value in sites.values():
        value.sort(key=lambda s: (s["file"], s["line"]))
    return sites


def build_config_dispatch(src_root: Path, files: list[Path]) -> list[dict]:
    """The reached config entry points, each with its call sites."""
    declared = declared_config_entry_points(src_root)
    names = [d["function"] for d in declared]
    sites = find_call_sites(src_root, files, names)
    out: list[dict] = []
    for d in declared:
        s = sites.get(d["function"], [])
        out.append({
            "function": d["function"],
            "declared_in": d["declared_in"],
            "note": d["note"],
            "reached": bool(s),
            "call_sites": len(s),
            "callers": s,
        })
    out.sort(key=lambda r: r["function"])
    return out


# ---------------------------------------------------------------------------
# environment aggregation
# ---------------------------------------------------------------------------

def reader_filter(readers: list[str]) -> str:
    uniq = sorted(set(readers))
    if not uniq:
        return "dynamic"
    if uniq == ["safe"]:
        return "safe"
    if uniq == ["unsafe"]:
        return "unsafe"
    return "mixed"


def env_meta(name: str, defaults: dict) -> dict:
    """Curated default/scope/effect for the well-known environment variables."""
    m = {
        "OPENSSL_CONF": ("library", defaults.get("default_config_file", "unset"),
                         "overrides the path of the configuration file the library loads"),
        "OPENSSL_CONF_INCLUDE": ("library", "unset",
                                 "the directory the config loader resolves .include against"),
        "OPENSSL_ENGINES": ("engine", defaults.get("ENGINESDIR", "unset"),
                            "overrides the directory dynamic engines are loaded from"),
        "OPENSSL_MODULES": ("provider", defaults.get("MODULESDIR", "unset"),
                            "overrides the directory providers are loaded from"),
        "SSL_CERT_DIR": ("library", defaults.get("X509_CERT_DIR", "unset"),
                         "overrides the default directory of CA certificates"),
        "SSL_CERT_FILE": ("library", defaults.get("X509_CERT_FILE", "unset"),
                          "overrides the default CA certificate bundle file"),
        "RANDFILE": ("library", "$HOME/.rnd",
                     "the path of the random-seed state file"),
        "HOME": ("library", "unset",
                 "the directory RAND_file_name uses when RANDFILE is unset"),
        "CTLOG_FILE": ("library", "unset",
                       "the path of the certificate-transparency log list"),
        "LEGACY_GOST_PKCS12": ("library", "unset",
                               "selects the legacy GOST MAC algorithm for PKCS#12"),
        "SSLKEYLOGFILE": ("library", "unset",
                          "the file TLS secrets are logged to when built with enable-sslkeylog"),
        "QLOGDIR": ("library", "unset", "the QUIC qlog output directory"),
        "OSSL_QFILTER": ("library", "unset", "the QUIC qlog filter specification"),
        "OPENSSL_TRACE": ("command", "unset",
                          "enables named debug trace categories for the openssl command"),
        "OPENSSL_SEC_MEM": ("command", "unset",
                            "bytes of secure memory to reserve at command start"),
        "OPENSSL_SEC_MEM_MINSIZE": ("command", "0",
                                    "the minimum allocation size for the secure-memory arena"),
        "OPENSSL_TEST_LIBCTX": ("command", "unset",
                                "makes the openssl command create a non-default library context"),
        "SSL_CIPHER": ("command", "unset",
                       "the cipher list s_time uses when -cipher is absent"),
        "OPENSSL_ia32cap": ("library", "cpuid-derived",
                            "overrides the detected x86-64 CPU capabilities"),
        "OPENSSL_armcap": ("library", "cpuid-derived",
                           "overrides the detected ARM CPU capabilities"),
        "OPENSSL_ppccap": ("library", "cpuid-derived",
                           "overrides the detected PowerPC CPU capabilities"),
        "OPENSSL_s390xcap": ("library", "cpuid-derived",
                             "overrides the detected s390x CPU capabilities"),
        "OPENSSL_riscvcap": ("library", "cpuid-derived",
                             "overrides the detected RISC-V CPU capabilities"),
        "OPENSSL_sparcv9cap": ("library", "cpuid-derived",
                               "overrides the detected SPARCv9 CPU capabilities"),
        "OPENSSL_MALLOC_FAILURES": ("library", "unset",
                                    "a debug build's memory-failure injection spec"),
        "OPENSSL_MALLOC_FD": ("library", "unset",
                              "the file descriptor a debug build logs allocations to"),
        "OPENSSL_MALLOC_SEED": ("library", "unset",
                                "the seed for a debug build's failure-injection RNG"),
        "OPENSSL_DEBUG_DECC_INIT": ("command", "unset",
                                    "VMS only: verbose DECC$ logical-name parsing"),
        "TEMPLATEKEM": ("provider", "unset",
                        "selects the template KEM provider implementation"),
        "NO_PROXY": ("library", "unset", "hosts that bypass the configured proxy"),
        "HTTP_PROXY": ("library", "unset", "the proxy for http:// requests"),
        "HTTPS_PROXY": ("library", "unset", "the proxy for https:// requests"),
        "http_proxy": ("library", "unset", "the lower-case proxy for http:// requests"),
        "https_proxy": ("library", "unset", "the lower-case proxy for https:// requests"),
        "no_proxy": ("library", "unset", "the lower-case proxy bypass list"),
    }
    if name in m:
        scope, default, effect = m[name]
        return {"scope": scope, "default": default, "effect": effect}
    return {}


def aggregate_env_vars(sites: list[dict], documented: dict, defaults: dict) -> list[dict]:
    """One contract item per resolved variable name."""
    by_name: dict[str, list[dict]] = {}
    for s in sites:
        if s["name"] is None:
            continue
        by_name.setdefault(s["name"], []).append(s)
    out: list[dict] = []
    for name in sorted(by_name):
        rows = by_name[name]
        readers = [r["reader"] for r in rows]
        scopes = sorted({r["scope"] for r in rows})
        meta = env_meta(name, defaults)
        doc = documented.get(name)
        entry = {
            "name": name,
            "default": meta.get("default", "unset"),
            "scope": meta.get("scope") or (scopes[0] if scopes else "library"),
            "security_filter": reader_filter(readers),
            "effect": meta.get("effect") or f"read by {rows[0]['caller'] or 'unknown'}",
            "documented": bool(doc and not doc["historical"]),
            "documented_historical": bool(doc and doc["historical"]),
            "documented_security_sensitive": bool(doc and doc["security_sensitive"]),
            "site_count": len(rows),
            "readers": sorted(set(readers)),
            "scopes": scopes,
            "sites": [{"file": r["file"], "line": r["line"], "caller": r["caller"],
                       "reader": r["reader"]} for r in rows],
        }
        entry["disposition"] = disposition_of(entry["scope"])
        out.append(entry)
    return out


# ---------------------------------------------------------------------------
# body
# ---------------------------------------------------------------------------

def build_body(env_sites: list[dict], default_paths: list[dict], directive_sites: list[dict],
               config_dispatch: list[dict], documented: dict, defaults: dict,
               authority_meta: dict) -> dict:
    """The atlas body as a pure function of its raw inputs.

    The court reconstructs the raw inputs from the committed body, re-derives the body and
    requires equality, then mutates the raw inputs and checks the derivation moves as expected.
    """
    env_vars = aggregate_env_vars(env_sites, documented, defaults)
    directives = aggregate_directives(directive_sites)

    dynamic_sites = [s for s in env_sites if s["name"] is None]
    named_sites = [s for s in env_sites if s["name"] is not None]
    unsafe_sensitive = [
        {"name": v["name"], "file": site["file"], "line": site["line"],
         "documented_exception": "rehash" in site["file"]}
        for v in env_vars if v["documented_security_sensitive"]
        for site in v["sites"] if site["reader"] == "unsafe"
    ]
    read_names = {v["name"] for v in env_vars}
    documented_not_read = sorted(
        n for n, d in documented.items() if not d["historical"] and n not in read_names
    )
    residuals = {
        "undocumented_env_vars": sorted(
            v["name"] for v in env_vars if not v["documented"] and not v["documented_historical"]),
        "documented_not_read": documented_not_read,
        "dynamic_env_name_sites": [
            {"file": s["file"], "line": s["line"], "caller": s["caller"],
             "expression": s.get("expression", "")} for s in dynamic_sites],
        "unsafe_reader_of_security_sensitive": sorted(
            unsafe_sensitive, key=lambda r: (r["name"], r["file"], r["line"])),
        "unsafe_reader_note": (
            "a security-sensitive variable read with the raw getenv. The openssl-env manual "
            "itself carves out SSL_CERT_DIR in openssl rehash; `documented_exception` marks the "
            "sites the manual explains and the rest are divergences to reconcile (22.11/22.12)."
        ),
        "not_enumerable": [
            ("the ssl_conf command vocabulary (MinProtocol, CipherString, ...) resolved at "
             "run time through SSL_CONF_cmd from a named section"),
            "provider parameter names beyond the literal keys crypto/provider_conf.c names",
        ],
    }

    return {
        "plan_rule": (
            "docs/PHASE-22-SUBPHASES.md section 6: an environment variable and a configuration "
            "directive are contract items with a name, a default, a scope, a security filter and "
            "an effect."
        ),
        "authority": authority_meta,
        "counts": {
            "env_vars": len(env_vars),
            "env_sites": len(env_sites),
            "env_named_sites": len(named_sites),
            "env_dynamic_sites": len(dynamic_sites),
            "default_paths": len(default_paths),
            "directives": len(directives),
            "config_entry_points": len(config_dispatch),
            "config_entry_points_reached": sum(1 for d in config_dispatch if d["reached"]),
        },
        "env_vars": env_vars,
        "env_sites": env_sites,
        "default_paths": default_paths,
        "directives": directives,
        "directive_sites": directive_sites,
        "config_dispatch": config_dispatch,
        "residuals": residuals,
    }


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def collect_source_files(src_root: Path) -> list[Path]:
    files: list[Path] = []
    for top in SCAN_TOP_DIRS:
        base = src_root / top
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*")):
            if path.is_file() and path.name.endswith(SOURCE_SUFFIXES):
                files.append(path)
    # The public configuration headers live under include/, already covered.
    return files


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    args = ap.parse_args(argv)

    auth = resolve_authority(args.authority)
    src_root = REPO_ROOT / SRC_REL
    if not src_root.is_dir():
        raise SystemExit(
            f"phase22-config: the authority source tree is missing: {src_root}; acquire the "
            "authority (forensics/tools/authority_acquire.py) first"
        )
    build_dir = REPO_ROOT / BUILD_DIR_REL

    files = collect_source_files(src_root)
    macros = build_macro_table(src_root, files)

    env_sites = scan_env_sites(src_root, files, macros)

    cd = configdata_paths(build_dir)
    bpaths = binary_paths(build_dir)
    default_paths = build_default_paths(bpaths, cd)
    defaults = {row["name"]: row["value"] for row in default_paths}
    defaults["default_config_file"] = defaults.get("default_config_file", "unset")

    directive_sites = scan_source_directives(src_root, files, macros)
    sample = REPO_ROOT / SAMPLE_CNF_REL
    if sample.is_file():
        directive_sites.extend(parse_sample_cnf(
            sample.read_text(encoding="utf-8", errors="replace"), rel(sample)))
        directive_sites.sort(key=lambda r: (r["name"], r["source_kind"],
                                            r["defined_in"].get("file") or "",
                                            r["defined_in"].get("line") or 0))

    config_dispatch = build_config_dispatch(src_root, files)

    pod = REPO_ROOT / ENV_POD_REL
    documented = parse_env_pod(pod.read_text(encoding="utf-8", errors="replace")) \
        if pod.is_file() else {}

    authority_meta = {
        "id": auth.id,
        "version": auth.version,
        "source_tree": SRC_REL,
        "build_dir": BUILD_DIR_REL,
        "binary": BINARY_REL_TO_BUILD,
        "compiled_paths_source": "openssl version -d/-e/-m" if bpaths else "configdata.pm",
    }

    body = build_body(env_sites, default_paths, directive_sites, config_dispatch,
                      documented, defaults, authority_meta)

    inputs = [
        InputRef(name="authority-source-tree", path=src_root / "VERSION.dat"),
        InputRef(name="openssl-cnf-sample", path=sample),
        InputRef(name="openssl-env-manual", path=pod),
        InputRef(name="phase-22-plan", path=REPO_ROOT / PLAN_REL),
    ]
    if (build_dir / "configdata.pm").is_file():
        inputs.append(InputRef(name="pinned-configdata", path=build_dir / "configdata.pm"))
    binary = build_dir / BINARY_REL_TO_BUILD
    if binary.is_file():
        inputs.append(InputRef(name="openssl-binary", path=binary))

    doc = envelope(kind="phase22-config-surface", authority=auth.id, inputs=inputs,
                   body=body, generator=GENERATOR)
    write_json(REPO_ROOT / OUT_REL, doc)

    c = body["counts"]
    print(f"[phase22-config] env_vars={c['env_vars']} env_sites={c['env_sites']} "
          f"(named={c['env_named_sites']} dynamic={c['env_dynamic_sites']})")
    print(f"  default_paths={c['default_paths']} directives={c['directives']} "
          f"config_entry_points={c['config_entry_points']} "
          f"(reached={c['config_entry_points_reached']})")
    print(f"  residuals: undocumented={len(body['residuals']['undocumented_env_vars'])} "
          f"documented_not_read={len(body['residuals']['documented_not_read'])} "
          f"unsafe_sensitive={len(body['residuals']['unsafe_reader_of_security_sensitive'])}")
    print(f"  -> {rel(REPO_ROOT / OUT_REL)}")
    return 0


# ---------------------------------------------------------------------------
# the court -- RT-PHASE22-CONFIG
# ---------------------------------------------------------------------------

def _raw_from_body(body: dict) -> dict:
    """The raw model the body is a pure function of, reconstructed from the body's own rows."""
    return {
        "env_sites": [dict(s) for s in body["env_sites"]],
        "default_paths": [dict(p) for p in body["default_paths"]],
        "directive_sites": [dict(d) for d in body["directive_sites"]],
        "config_dispatch": [dict(d) for d in body["config_dispatch"]],
        "documented": body.get("_documented", {}),
        "defaults": {p["name"]: p["value"] for p in body["default_paths"]},
        "authority_meta": body["authority"],
    }


def _derive(raw: dict) -> dict:
    return build_body(raw["env_sites"], raw["default_paths"], raw["directive_sites"],
                      raw["config_dispatch"], raw["documented"], raw["defaults"],
                      raw["authority_meta"])


def _env_var(body: dict, name: str) -> dict | None:
    return next((v for v in body["env_vars"] if v["name"] == name), None)


def _directive(body: dict, name: str) -> dict | None:
    return next((d for d in body["directives"] if d["name"] == name), None)


def _broken_aggregate(env_sites, default_paths, directive_sites, config_dispatch,
                      documented, defaults, authority_meta):
    """An aggregator blind to its own defect classes: one variable, one site, no readers.

    Running the court's checks against this must fail them. If it does not, the court is not
    sensitive to the classes it claims to inventory and the verdict is `fail`.
    """
    body = build_body(env_sites, default_paths, directive_sites, config_dispatch,
                      documented, defaults, authority_meta)
    body["env_vars"] = [{
        "name": body["env_vars"][0]["name"] if body["env_vars"] else "x",
        "default": "unset", "scope": "library", "security_filter": "safe", "effect": "",
        "documented": True, "documented_historical": False,
        "documented_security_sensitive": True, "site_count": 1, "readers": ["safe"],
        "scopes": ["library"], "sites": [],
    }] if body["env_vars"] else []
    body["counts"] = dict(body["counts"])
    body["counts"]["env_vars"] = len(body["env_vars"])
    body["counts"]["env_sites"] = 1
    body["default_paths"] = []
    body["counts"]["default_paths"] = 0
    body["directives"] = []
    body["counts"]["directives"] = 0
    return body


def court_config(body: dict) -> dict:
    """`RT-PHASE22-CONFIG`: a sensitivity challenge over this plane's aggregation logic."""
    checks: list[tuple[str, bool]] = []
    raw = _raw_from_body(body)

    checks.append(("baseline: the artefact has environment variables",
                   body["counts"]["env_vars"] > 0))
    checks.append(("baseline: the artefact has environment read sites",
                   body["counts"]["env_sites"] > 0))
    checks.append(("baseline: the artefact has default paths",
                   body["counts"]["default_paths"] > 0))
    checks.append(("baseline: the artefact has directives", body["counts"]["directives"] > 0))
    checks.append(("baseline: some config entry point is reached",
                   body["counts"]["config_entry_points_reached"] > 0))

    # Round-trip: re-derive the committed body from its own rows and require equality. The
    # `_documented` key is not committed (it is re-read from the manual), so compare everything
    # except it.
    rebuilt = _derive(raw)
    committed = json.loads(json.dumps(body))
    committed.pop("_documented", None)
    rebuilt_cmp = json.loads(json.dumps(rebuilt))
    rebuilt_cmp.pop("_documented", None)
    checks.append(("round-trip: the committed body equals its re-derivation",
                   rebuilt_cmp == committed))

    # 1. add an environment variable -- env_vars and env_sites rise by one.
    mut = json.loads(json.dumps(raw))
    mut["env_sites"].append({
        "name": "PHASE22_PROBE", "file": "synthetic/phase22_probe.c", "line": 1,
        "caller": "phase22_probe", "reader": "safe", "resolved": True, "scope": "library",
        "expression": '"PHASE22_PROBE"',
    })
    new = _derive(mut)
    checks.append(("add-env-var: env_vars rose by one",
                   new["counts"]["env_vars"] == body["counts"]["env_vars"] + 1))
    checks.append(("add-env-var: env_sites rose by one",
                   new["counts"]["env_sites"] == body["counts"]["env_sites"] + 1))
    probe = _env_var(new, "PHASE22_PROBE")
    checks.append(("add-env-var: the new variable is present and documented-agnostic",
                   probe is not None and probe["site_count"] == 1))

    # 2. add a second read site for one existing variable -- env_vars holds, env_sites rises.
    target = next((v for v in body["env_vars"] if v["site_count"] >= 1), None)
    if target is None:
        checks.append(("add-site: a variable with a site was found", False))
    else:
        mut = json.loads(json.dumps(raw))
        # Add a read site with the *opposite* reader so the variable necessarily becomes mixed,
        # whatever its current filter.
        probe_reader = "unsafe" if target["security_filter"] == "safe" else "safe"
        mut["env_sites"].append({
            "name": target["name"], "file": "synthetic/phase22_probe.c", "line": 2,
            "caller": "phase22_probe", "reader": probe_reader, "resolved": True,
            "scope": "library", "expression": '"' + target["name"] + '"',
        })
        new = _derive(mut)
        checks.append(("add-site: env_sites rose by one",
                       new["counts"]["env_sites"] == body["counts"]["env_sites"] + 1))
        checks.append(("add-site: env_vars held",
                       new["counts"]["env_vars"] == body["counts"]["env_vars"]))
        moved = _env_var(new, target["name"])
        checks.append(("add-site: the variable's site_count rose by one",
                       moved is not None and moved["site_count"] == target["site_count"] + 1))
        checks.append(("add-site: the variable is now read both ways (mixed)",
                       moved is not None and moved["security_filter"] == "mixed"))

    # 3. flip a read from safe to unsafe -- the variable's security filter moves.
    safe_target = next((v for v in body["env_vars"]
                        if v["security_filter"] == "safe" and v["sites"]), None)
    if safe_target is None:
        checks.append(("flip-reader: a safe-read variable was found", False))
    else:
        mut = json.loads(json.dumps(raw))
        victim_file = safe_target["sites"][0]["file"]
        victim_line = safe_target["sites"][0]["line"]
        for s in mut["env_sites"]:
            if (s["name"] == safe_target["name"] and s["file"] == victim_file
                    and s["line"] == victim_line):
                s["reader"] = "unsafe"
                break
        new = _derive(mut)
        moved = _env_var(new, safe_target["name"])
        checks.append((f"flip-reader: {safe_target['name']}'s security_filter moved",
                       moved is not None and moved["security_filter"] != safe_target["security_filter"]
                       and "unsafe" in moved["readers"]))
        checks.append(("flip-reader: env_sites held",
                       new["counts"]["env_sites"] == body["counts"]["env_sites"]))
        checks.append((("flip-reader: on an unsafe read of a documented security-sensitive "
                        "variable the residual appears"),
                       not safe_target["documented_security_sensitive"]
                       or any(r["name"] == safe_target["name"]
                              for r in new["residuals"]["unsafe_reader_of_security_sensitive"])))

    # 4. add a default path -- default_paths rises by one.
    mut = json.loads(json.dumps(raw))
    mut["default_paths"] = mut["default_paths"] + [{
        "name": "PHASE22_PATH", "value": "/tmp/phase22-probe", "kind": "synthetic",
        "source": "synthetic", "scope": "library", "effect": "probe",
    }]
    mut["defaults"] = {p["name"]: p["value"] for p in mut["default_paths"]}
    new = _derive(mut)
    checks.append(("add-default-path: default_paths rose by one",
                   new["counts"]["default_paths"] == body["counts"]["default_paths"] + 1))
    checks.append(("add-default-path: the path is present",
                   any(p["name"] == "PHASE22_PATH" for p in new["default_paths"])))
    checks.append(("add-default-path: nothing else moved",
                   new["counts"]["env_vars"] == body["counts"]["env_vars"]
                   and new["counts"]["directives"] == body["counts"]["directives"]))

    # 5. add a directive with a scope -- directives rises by one and the scope is kept.
    mut = json.loads(json.dumps(raw))
    mut["directive_sites"].append({
        "name": "phase22_probe_directive", "scope": "provider", "source_kind": "synthetic",
        "defined_in": {"file": "synthetic/phase22_probe.cnf", "line": 1, "section": "probe"},
        "security_filter": "config-file",
    })
    new = _derive(mut)
    checks.append(("add-directive: directives rose by one",
                   new["counts"]["directives"] == body["counts"]["directives"] + 1))
    added = _directive(new, "phase22_probe_directive")
    checks.append(("add-directive: the directive carries its scope",
                   added is not None and added["scope"] == "provider"))
    checks.append(("add-directive: nothing else moved",
                   new["counts"]["env_vars"] == body["counts"]["env_vars"]
                   and new["counts"]["default_paths"] == body["counts"]["default_paths"]))

    # Sensitivity: the same defect classes, run through an aggregator blind to them, must fail.
    broken = _broken_aggregate(raw["env_sites"], raw["default_paths"], raw["directive_sites"],
                               raw["config_dispatch"], raw["documented"], raw["defaults"],
                               raw["authority_meta"])
    checks.append(("sensitivity: the blind aggregator loses the default paths",
                   broken["counts"]["default_paths"] != body["counts"]["default_paths"]))
    checks.append(("sensitivity: the blind aggregator loses the directives",
                   broken["counts"]["directives"] != body["counts"]["directives"]))
    checks.append(("sensitivity: the blind aggregator collapses the environment",
                   broken["counts"]["env_vars"] != body["counts"]["env_vars"]
                   or broken["counts"]["env_sites"] != body["counts"]["env_sites"]))

    # The documented cross-reference must not be empty: an empty manual parse would make every
    # `documented` flag False and every residual meaningless.
    checks.append(("cross-reference: the manual yielded documented variables",
                   any(v["documented"] for v in body["env_vars"])))

    failures = [d for d, ok in checks if not ok]
    c = body["counts"]
    return {
        "court": "RT-PHASE22-CONFIG",
        "artefact": ARTEFACT_REL,
        "summary": (f"{c['env_vars']} env vars / {c['env_sites']} sites, "
                    f"{c['default_paths']} default paths, {c['directives']} directives"),
        "env_vars": c["env_vars"],
        "env_sites": c["env_sites"],
        "default_paths": c["default_paths"],
        "directives": c["directives"],
        "config_entry_points": c["config_entry_points"],
        "mutations": ["round-trip", "add-env-var", "add-read-site", "flip-reader-safe-to-unsafe",
                      "add-default-path", "add-directive-scope", "blind-aggregator-sensitivity"],
        "observations": len(checks),
        "failures": failures,
        "verdict": "pass" if not failures else "fail",
    }


def courts() -> list[dict]:
    """`RT-PHASE22-CONFIG`, or `[]` while the artefact has not landed."""
    path = REPO_ROOT / ARTEFACT_REL
    if not path.is_file():
        return []
    try:
        body = json.loads(path.read_text(encoding="utf-8"))["body"]
    except Exception as exc:  # a court that cannot read its artefact is a failing court
        return [{"court": "RT-PHASE22-CONFIG", "artefact": ARTEFACT_REL, "verdict": "fail",
                 "stage": "artefact-unreadable", "observations": 0, "failures": [str(exc)]}]
    # The `documented` map is re-read from the manual so the round trip can rebuild every
    # `documented` flag without the body having to carry the whole manual.
    pod = REPO_ROOT / ENV_POD_REL
    body = dict(body)
    body["_documented"] = parse_env_pod(pod.read_text(encoding="utf-8", errors="replace")) \
        if pod.is_file() else {}
    return [court_config(body)]


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
