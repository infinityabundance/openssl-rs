#!/usr/bin/env python3
"""openssl-rs — atlas generator: runtime surface (providers, CLI, corpora).

Produces, per authority:

    provider-inventory.json   provider-algorithms.json
    cli-commands.json         configs.json
    corpus-inventory.json

These are the surfaces a *distribution consumer* observes, as distinct from the
linker-level surfaces in symbols-*.json and the declaration-level surfaces in
functions.json et al.

How they are obtained
---------------------
* Provider / algorithm inventories come from the authority's **own built
  `openssl` executable** (`openssl list ...`), not from a handwritten list.
  `docs/PROVIDER_MODEL.md` requires the algorithm inventory to be derived
  automatically from the authority.
* CLI commands and options come from `openssl list -commands` and each command's
  `-help`. The command set is *generated*, never hardcoded, so a command missing
  from a hardcoded list cannot silently narrow the contract.
* Corpora are the upstream test and fuzz trees, content-addressed.

Normalisation (explicit and symmetric)
--------------------------------------
The authority binary is installed under a prefix whose absolute path would leak
the build directory into the evidence and differ between runs. Raw outputs are
kept as captures; the *derived* atlas applies one explicit, symmetric
substitution: the prefix path becomes the token `<PREFIX>`. Both authorities are
normalised identically. No other rewriting is performed.

Everything runs inside the court; the authority binary is executed with
LD_LIBRARY_PATH and OPENSSL_MODULES pointing at its own prefix, so the
contaminating system OpenSSL can never be used (docs/AUTHORITY_POLICY.md §4.1).
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import (  # noqa: E402
    AUTH_ROOT,
    InputRef,
    all_authority_ids,
    authority_atlas_dir,
    content_hash,
    envelope,
    rel,
    resolve_authority,
    run,
    sha256_bytes,
    sha256_file,
    write_json,
    write_text,
)

# Algorithm and inspection classes exposed by `openssl list`. This set is taken
# from the authority's own `openssl list -help`, not guessed: an earlier draft
# used `-asym-cipher-algorithms`, which does not exist (the real selector is
# `-asymcipher-algorithms`). Deriving the vocabulary from the authority is the
# point — a guessed selector silently yields an empty class.
#
# `-disabled` is included deliberately: it is the authority's own statement of
# which features were compiled out, and it is what explains symbol/algorithm
# absences in the reconciliation (docs/PARITY_MODEL.md §4).
LIST_SELECTORS = [
    "providers",
    "digest-algorithms",
    "cipher-algorithms",
    "mac-algorithms",
    "kdf-algorithms",
    "key-exchange-algorithms",
    "kem-algorithms",
    "signature-algorithms",
    "tls-signature-algorithms",
    "asymcipher-algorithms",
    "public-key-algorithms",
    "public-key-methods",
    "key-managers",
    "skey-managers",
    "encoders",
    "decoders",
    "store-loaders",
    "random-instances",
    "random-generators",
    "tls-groups",
    "disabled",
    "engines",
]


def authority_env(auth) -> dict:
    env = dict(os.environ)
    env["LD_LIBRARY_PATH"] = str(auth.libdir)
    # Provider modules live beside the libraries in the authority prefix.
    env["OPENSSL_MODULES"] = str(auth.libdir / "ossl-modules")
    env["OPENSSL_CONF"] = "/dev/null"
    env.pop("OPENSSL_CONF_INCLUDE", None)
    return env


def openssl_bin(auth) -> Path:
    p = auth.prefix / "bin" / "openssl"
    if not p.exists():
        raise SystemExit(f"FATAL: authority {auth.id} has no built openssl binary")
    return p


def normalise(text: str, auth) -> str:
    """Apply the single documented, symmetric path substitution."""
    return text.replace(str(auth.prefix), "<PREFIX>").replace(str(auth.libdir), "<PREFIX>/lib")


def capture(auth, name: str, argv: list[str]) -> str:
    """Run the authority binary, store the raw output as a capture, return text."""
    proc = run_with_env(argv, authority_env(auth))
    capdir = AUTH_ROOT / "captures" / auth.id
    write_text(capdir / f"{name}.txt", proc.stdout + proc.stderr)
    return proc.stdout


def run_with_env(argv: list[str], env: dict):
    """Run a command with an explicit environment, returning a CmdResult."""
    import subprocess
    from atlas_common import CmdResult
    p = subprocess.run(argv, capture_output=True, text=True, env=env, check=False)
    return CmdResult(argv=argv, returncode=p.returncode, stdout=p.stdout, stderr=p.stderr)


# --- providers ---------------------------------------------------------------

_PROVIDER_LINE = re.compile(r"^\s*([A-Za-z0-9_.-]+)\s*$")


def build_provider_inventory(auth) -> dict:
    binp = openssl_bin(auth)
    raw = capture(auth, "list-providers", [str(binp), "list", "-providers", "-verbose"])
    providers = []
    current = None
    for line in normalise(raw, auth).splitlines():
        m = re.match(r"^\s{2}([A-Za-z0-9_.-]+)\s*$", line)
        if m:
            current = {"name": m.group(1), "fields": {}}
            providers.append(current)
            continue
        m = re.match(r"^\s{4}([A-Za-z ]+):\s*(.*)$", line)
        if m and current is not None:
            current["fields"][m.group(1).strip()] = m.group(2).strip()
    algs = {}
    for sel in LIST_SELECTORS:
        if sel == "providers":
            continue
        # `-1` requests a one-column listing, which is unambiguous to parse;
        # the authority supports it for every listing selector.
        res = run_with_env([str(binp), "list", "-" + sel, "-1"], authority_env(auth))
        if res.returncode != 0:
            algs[sel] = {"error": res.stderr.strip()[:200], "count": 0, "entries": []}
            continue
        text = normalise(res.stdout, auth)
        write_text(AUTH_ROOT / "captures" / auth.id / f"list-{sel}.txt", text)
        if sel == "disabled":
            entries = [ln.strip() for ln in text.splitlines() if ln.strip()]
            algs[sel] = {"count": len(entries), "entries": entries}
            continue
        entries = parse_list_entries(text)
        algs[sel] = {"count": len(entries), "entries": entries}
    return {
        "binary": rel(binp),
        "providers": sorted(providers, key=lambda p: p["name"]),
        "algorithm_classes": {k: algs[k] for k in sorted(algs)},
    }


_LIST_ENTRY = re.compile(r"^\s{2}([A-Za-z0-9_.-]+)(?:\s+@\s+([A-Za-z0-9_.-]+))?(?:\s+([0-9].*))?\s*$")


def parse_list_entries(text: str) -> list[dict]:
    """Parse `openssl list -<class> -1` output (one entry per line).

    Rows look like:

        AES-128-CBC @ default
        { 1.2.840.113549.1.1.1, RSA } @ default

    We keep the algorithm name and the provider it resolves to; deduplicate and
    sort for determinism.
    """
    out: dict[tuple[str, str], dict] = {}
    for line in text.splitlines():
        body = line.strip()
        if not body or body.startswith("---"):
            continue
        name, _, provider = body.partition(" @ ")
        name = name.strip()
        provider = provider.strip()
        if not name:
            continue
        out[(name, provider)] = {"name": name, "provider": provider or None}
    return [out[k] for k in sorted(out)]


# --- CLI ---------------------------------------------------------------------

def build_cli_inventory(auth) -> dict:
    binp = openssl_bin(auth)
    # `-1` forces one command per line; the default listing is columnar and
    # would be silently truncated by a whitespace-split parser.
    raw = capture(auth, "list-commands", [str(binp), "list", "-commands", "-1"])
    names = sorted({ln.strip() for ln in raw.splitlines() if ln.strip()})
    commands = []
    for name in names:
        res = run_with_env([str(binp), "list", "-options", name], authority_env(auth))
        text = normalise(res.stdout + res.stderr, auth)
        options = parse_option_list(text)
        commands.append({
            "name": name,
            "options_exit_status": res.returncode,
            "option_count": len(options),
            "options": options,
            "option_listing": text,
        })
    return {
        "binary": rel(binp),
        "command_count": len(commands),
        "commands": commands,
    }


# `openssl list -options <cmd>` rows look like:
#
#     -in val          Input file
#     -out val         Output file
_OPTION_ROW = re.compile(r"^(\s*)(-[A-Za-z0-9_*?\-]+)(\s+\S+)?(\s{2,}.*)?$")


def parse_option_list(text: str) -> list[dict]:
    out: dict[str, dict] = {}
    for line in text.splitlines():
        if not line.startswith(" "):
            continue
        m = _OPTION_ROW.match(line)
        if not m:
            continue
        name = m.group(2)
        takes_value = bool(m.group(3))
        description = (m.group(4) or "").strip()
        out[name] = {
            "name": name,
            "takes_value": takes_value,
            "description": description,
        }
    return [out[k] for k in sorted(out)]


# --- configs -----------------------------------------------------------------

def build_config_catalog(auth) -> dict:
    files = []
    for root in [auth.source / "apps", auth.source]:
        for pattern in ("*.cnf", "*.cnf.in"):
            for p in sorted(root.glob(pattern)):
                files.append({
                    "path": rel(p),
                    "sha256": sha256_file(p),
                    "size_bytes": p.stat().st_size,
                    "template": p.name.endswith(".in"),
                })
    # dedupe by path
    seen = {}
    for f in files:
        seen[f["path"]] = f
    return {"config_file_count": len(seen), "config_files": [seen[k] for k in sorted(seen)]}


# --- corpora -----------------------------------------------------------------

def build_corpus_inventory(auth) -> dict:
    """Per-file, content-addressed inventory of the upstream corpora.

    Counts alone are not evidence: a fixture count cannot substitute for
    surface coverage (`docs/PARITY_MODEL.md`), and a corpus that silently
    gained or lost a file would be invisible. Every file is therefore listed
    with its size and SHA-256, sorted, so the corpus has a reproducible
    identity and a future authority's corpus delta is a diff.
    """
    out = {}
    for label, sub in (("test", "test"), ("fuzz", "fuzz"), ("providers", "providers")):
        root = auth.source / sub
        if not root.is_dir():
            out[label] = {"present": False}
            continue
        files = [p for p in sorted(root.rglob("*")) if p.is_file()]
        entries = [
            {
                "path": p.relative_to(auth.source).as_posix(),
                "size_bytes": p.stat().st_size,
                "sha256": sha256_file(p),
            }
            for p in files
        ]
        lines = [f"{e['sha256']}  {e['path']}\n" for e in entries]
        out[label] = {
            "present": True,
            "file_count": len(files),
            "total_bytes": sum(e["size_bytes"] for e in entries),
            "root_hash_algorithm": "sha256(<sha256>  <path>\\n, lexicographic)",
            "root_hash": sha256_bytes("".join(lines).encode("utf-8")),
            "by_extension": _ext_histogram(files),
            "files": entries,
        }
    seeds = auth.source / "fuzz" / "corpora"
    out["fuzz_seed_corpora"] = {
        "present": seeds.is_dir(),
        "targets": sorted(p.name for p in seeds.iterdir()) if seeds.is_dir() else [],
    }
    return out


def _ext_histogram(files: list[Path]) -> dict:
    from collections import Counter
    c = Counter()
    for p in files:
        c[p.suffix or "(none)"] += 1
    return {k: c[k] for k in sorted(c)}


def generate(authority_id: str) -> None:
    auth = resolve_authority(authority_id)
    outdir = authority_atlas_dir(authority_id)
    print(f"[runtime] {auth.id}")

    prov = build_provider_inventory(auth)
    doc = envelope("provider-inventory", "forensics/tools/atlas_runtime.py",
                   [InputRef("openssl_binary", openssl_bin(auth))], prov, authority=auth.id)
    doc["body_hash"] = content_hash(prov)
    write_json(outdir / "provider-inventory.json", doc)
    print(f"  providers: {[p['name'] for p in prov['providers']]}")
    for cls, info in prov["algorithm_classes"].items():
        if info.get("count"):
            print(f"    {cls}: {info['count']}")

    cli = build_cli_inventory(auth)
    doc = envelope("cli-commands", "forensics/tools/atlas_runtime.py",
                   [InputRef("openssl_binary", openssl_bin(auth))], cli, authority=auth.id)
    doc["body_hash"] = content_hash(cli)
    write_json(outdir / "cli-commands.json", doc)
    print(f"  cli commands: {cli['command_count']}")

    cfg = build_config_catalog(auth)
    doc = envelope("configs", "forensics/tools/atlas_runtime.py", [], cfg, authority=auth.id)
    doc["body_hash"] = content_hash(cfg)
    write_json(outdir / "configs.json", doc)
    print(f"  config files: {cfg['config_file_count']}")

    corp = build_corpus_inventory(auth)
    doc = envelope("corpus-inventory", "forensics/tools/atlas_runtime.py", [], corp,
                   authority=auth.id)
    doc["body_hash"] = content_hash(corp)
    write_json(outdir / "corpus-inventory.json", doc)
    print(f"  corpora: {[(k, v.get('file_count')) for k, v in corp.items() if isinstance(v, dict) and 'file_count' in v]}")


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Generate the runtime surface atlas.")
    ap.add_argument("--authority", action="append", default=[])
    ap.add_argument("--all", action="store_true")
    args = ap.parse_args(argv)
    ids = all_authority_ids() if args.all else args.authority
    if not ids:
        ap.error("specify --all or --authority")
    for aid in ids:
        generate(aid)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
