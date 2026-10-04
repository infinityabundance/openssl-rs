#!/usr/bin/env python3
"""openssl-rs — Phase 16 courts: the CLI / config / filesystem contract.

Each court is a C probe in `courts/phase16/` compiled **twice** — once against the
admitted authority, once against the candidate distribution shell — and run. The two
transcripts are compared line by line, keyed on `key=value`, and every difference is a
residual. The method is Phases 3 through 15's, for the same reason: a probe measures
what the authority actually does, and the comparison is between two *executions* of the
same program, so the expectation cannot drift.

`RT-LEGACY-MODULE`, and what it compares
----------------------------------------
`RT-LEGACY-MODULE`, and what it compares
----------------------------------------
16.1's court, `courts/phase16/rt_legacy_module_probe.c`, loads the `legacy` provider
through the same `OSSL_PROVIDER_load` path the authority's own CLI uses — the module's
`OSSL_provider_init` on one side, the candidate's `ossl-modules/legacy.so` on the other,
with `OPENSSL_MODULES` pointed at each side's own module directory. It compares the
provider's `name` read through `OSSL_PROVIDER_get_params`, the **row count and first
row's alias sequence** the module's `OSSL_PROVIDER_query_operation` answers for all four
operations 16.1 publishes (`OSSL_OP_DIGEST`, `OSSL_OP_CIPHER`, `OSSL_OP_KDF`,
`OSSL_OP_SKEYMGMT`), a fixed `"abc"` digest for each of the four legacy digests fetched
by name and by OID through the `provider=legacy` property, a fixed-key/fixed-IV
encrypt-and-decrypt of each of the 32 `legacy_ciphers` rows, and a fixed
password/salt/iteration derive of each of the two `legacy_kdfs` rows. It closes with the
refusal arms: an unknown digest/cipher/KDF name, a legacy cipher asked of the `default`
provider, and two `PBKDF1` derives the row must refuse. It does **not** read the error
queue; every slice of 16.1 is landed, so `OSSL_OP_CIPHER` and `OSSL_OP_KDF` are queried
and the comparison measures the whole table. See docs/PHASE-16-SUBPHASES.md section 3.

`RT-ENGINE-DYN`, and what it compares
-------------------------------------
16.2's court, `courts/phase16/rt_engine_dyn_probe.c`, drives `ENGINE_by_id` over the
loader 16.2 lands (`crypto/engine/eng_dyn.c`): the NULL-id refusal, the
`OPENSSL_INIT_ENGINE_DYNAMIC` bit whose step registers the `dynamic` built-in, the
`dynamic` engine id/name read back (and a second lookup answering a second object,
because the engine carries `ENGINE_FLAGS_BY_ID_COPY`), the dynamic fallback itself
(`ENGINE_by_id`'s miss path recurses into `ENGINE_by_id("dynamic")` and runs the
`ID`/`DIR_LOAD`/`DIR_ADD`/`LIST_ADD`/`LOAD` control chain) with `OPENSSL_ENGINES`
pointed at a fixed object-free directory so the `LOAD` refuses, and the empty-id
refusal. A real `.so` load is not driven: the candidate shell installs no *engine*
module, and the distribution's engine-module contract is 16.4's `filesystem` unit,
so the probe records that rather than fabricating a fixture. The `rdrand` id is not
observed because it is `crypto/engine/eng_rdrand.c`'s separate unit. See
courts/phase16/rt_engine_dyn_probe.c and docs/PHASE-16-SUBPHASES.md section 4.

`RT-DEFAULTS`, and what it compares
-----------------------------------
16.3's court, `courts/phase16/rt_defaults_probe.c`, drives the two `crypto/defaults.c`
functions through the public surfaces that stand on them: `OPENSSL_info(1001)` is
`ossl_get_openssldir()`, as a `'static` C string equal to `X509_get_default_cert_area()`
on both sides (both are the same build-time `OPENSSLDIR`), the four
`X509_get_default_*` paths keep their `/certs`, `/cert.pem` and `/private` relationship to
that area, `OPENSSL_info(1009)` is `ossl_get_wininstallcontext()` (the literal
`"Undefined"`, equal on both sides), and the refusal arm (an unrecognised code is NULL;
the seed-source and CPU settings codes are a recorded divergence and are not observed). The
raw authority path
is deliberately not printed, because the candidate answers its own `OPENSSL_RS_OPENSSLDIR`
(empty when unset) and the difference is a *value* the stratum does not claim; the engines
and modules dirs are not observed for the same reason. See
courts/phase16/rt_defaults_probe.c and docs/PHASE-16-SUBPHASES.md section 4.

The pending courts
------------------
None. Every court the plan named -- `RT-LEGACY-MODULE`, `RT-ENGINE-DYN`,
`RT-DEFAULTS`, `RT-CLI`, `RT-CONFIG`, `RT-STATEM-REMAINDER` -- is registered and
passing.

`RT-STATEM-REMAINDER`, and what it compares
-------------------------------------------
16.5's court, `courts/phase16/rt_statem_remainder_probe.c`, drives the TLS message-layer units 16.5
lands at the boundary they expose: the `SSL_connect` client and `SSL_accept` server over an empty
memory-BIO peer, their return class, hand state, `SSL_want` and `SSL_in_*`, and the second
`SSL_do_handshake` re-entry. The message bodies the landed transitions select need the record
layer, the extension units and the key schedule, none of which is landed, so a full flight is not
driven; the state the fresh connection is left in is, and the boundary is recorded. See
`courts/phase16/rt_statem_remainder_probe.c`.

None is declared in `gen_frf_courts.py`: that registry is the stratum's seal, and a court
with no probe cannot carry a declaration.

`RT-CLI`, and what it compares
-------------------------------
16.4's court drives the two `openssl` executables — the admitted authority's own built
binary and the candidate distribution shell's — over a fixed argv and compares the
transcripts keyed on `key=value`: the dispatcher's global-`help`/`version`, unknown-command
and `no-<cmd>` arms, the three command bodies whose output is build-independent (`help`,
`list`, `version`), and every command's option table through `list -options <cmd>` (the
fixed option tables the regenerated Phase-1 capture structures). It then drives
`atlas_runtime.parse_option_list` over each captured `option_listing` and requires the
structured rows to round-trip. No wall clock and no network: every case is a pure function
of the two tables.

`RT-CONFIG`, and what it compares
---------------------------------
16.4's second court, `courts/phase16/rt_config_probe.c`, drives the config loader the CLI
stands on over a fixed in-memory configuration: `NCONF_load_bio` over a memory BIO, the
section/`get_string`/`get_number` reads, and the CLI's default configuration file
(`CONF_get1_default_config_file`). The unset-`OPENSSL_CONF` arm is a recorded divergence
(§3.2), not an observed value.

SPDX-License-Identifier: Apache-2.0"""

from __future__ import annotations

import argparse
import json
import os
import shutil
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
    run,
    write_json,
)

OUT = REPO_ROOT / "artifacts" / "phase16" / "COURTS.json"
GENERATOR = "forensics/tools/phase16_courts.py"
PROBE_DIR = REPO_ROOT / "courts" / "phase16"
PHASE2 = REPO_ROOT / "artifacts" / "phase2"
STAGED = REPO_ROOT / "artifacts" / "phase16" / "probes"
RUN_TIMEOUT_S = "60"

# The differential courts, in the order they land. `(name, probe filename)`, and the probe is
# declared in the same commit as the entry, so a runner that names a probe which does not exist
# cannot be committed.
COURTS: list[tuple[str, str]] = [
    ("RT-LEGACY-MODULE", "rt_legacy_module_probe.c"),
    ("RT-ENGINE-DYN", "rt_engine_dyn_probe.c"),
    ("RT-DEFAULTS", "rt_defaults_probe.c"),
    ("RT-CONFIG", "rt_config_probe.c"),
    ("RT-STATEM-REMAINDER", "rt_statem_remainder_probe.c"),
]

# The fixed argv `RT-CLI` drives on both sides. Each case is build-independent and
# deterministic: the dispatcher's arms and the three command bodies whose output is
# the authority's (`help`, `list`, `version`); every command's option table is added
# from the regenerated Phase-1 capture (`cli_argv_cases`). See docs/PHASE-16-SUBPHASES.md
# section 3.
CLI_ARGV: list[list[str]] = [
    ["version"],
    ["version", "-v"],
    ["help"],
    ["list", "-commands", "-1"],
    ["list", "-options", "bogus"],
    ["zzz-not-a-command"],
    ["no-version"],
    ["no-zzz-not-a-command"],
]

CLI_CAPTURE = REPO_ROOT / "forensics" / "atlas" / "openssl-3.6.4-production" / "cli-commands.json"

# A court the plan names and this stratum cannot run yet. Each entry names the subphase that
# lands the probe and what the court will drive, so "nothing registered" is a stated distance
# rather than a court quietly dropped.
PENDING_COURTS: dict[str, str] = {}


def side_env(libdir: Path, modulesdir: Path) -> dict[str, str]:
    """The environment a probe runs under on one side.

    `OPENSSL_MODULES` points at that side's own `ossl-modules/`, which is what makes the
    candidate load the candidate's `legacy.so` and the authority load its own. `LD_LIBRARY_PATH`
    fixes the DSO the probe resolves against, and `OPENSSL_CONF=/dev/null` keeps the host's
    configuration out of a deterministic transcript.
    """
    env = dict(os.environ)
    env["LD_LIBRARY_PATH"] = str(libdir)
    env["OPENSSL_MODULES"] = str(modulesdir)
    env["OPENSSL_CONF"] = "/dev/null"
    env.pop("OPENSSL_CONF_INCLUDE", None)
    return env


def compile_probe(src: Path, out: Path, include: Path, libdir: Path) -> tuple[bool, str]:
    res = run([
        "clang", "-std=c11", "-Wall", "-Werror=implicit-function-declaration", "-O1",
        "-D_GNU_SOURCE",
        "-I", str(include),
        "-o", str(out), str(src),
        "-L", str(libdir), "-lssl", "-lcrypto",
        f"-Wl,-rpath,{libdir}",
    ])
    return res.ok, res.stderr.strip()


def run_probe(binary: Path, env: dict[str, str]) -> tuple[str, str, int | None]:
    res = run(["timeout", RUN_TIMEOUT_S, str(binary)], env=env)
    code = res.returncode
    if code == 124:
        return res.stdout, res.stderr, None
    return res.stdout, res.stderr, code


def diff(authority: str, candidate: str) -> list[dict]:
    """Line-wise comparison keyed on `key=value`, so a missing or extra line produces exactly one
    residual instead of shifting every following line."""
    def parse(text: str) -> tuple[list[str], dict[str, str]]:
        order: list[str] = []
        values: dict[str, str] = {}
        for line in text.splitlines():
            if "=" not in line:
                continue
            key, _, value = line.partition("=")
            if key not in values:
                order.append(key)
                values[key] = value
            else:
                values[key] = f"{values[key]}|{value}"
        return order, values

    a_order, a = parse(authority)
    c_order, c = parse(candidate)
    residuals: list[dict] = []
    for key in a_order:
        if key not in c:
            residuals.append({"observation": key, "authority": a[key],
                              "candidate": None, "class": "missing"})
        elif a[key] != c[key]:
            residuals.append({"observation": key, "authority": a[key],
                              "candidate": c[key], "class": "value"})
    for key in c_order:
        if key not in a:
            residuals.append({"observation": key, "authority": None,
                              "candidate": c[key], "class": "extra"})
    return residuals


def escape(text: str) -> str:
    """One transcript line per observation: newline becomes `|`, CR becomes `^`."""
    return text.replace("\n", "|").replace("\r", "^")


def cli_argv_cases() -> list[list[str]]:
    """The fixed argv `RT-CLI` drives: the build-independent arms plus every captured
    command's option table (`list -options <cmd>`)."""
    cases = [list(a) for a in CLI_ARGV]
    body = json.loads(CLI_CAPTURE.read_text(encoding="utf-8"))["body"]
    for c in body["commands"]:
        cases.append(["list", "-options", c["name"]])
    return cases


def cli_transcript(binary: Path, env: dict[str, str], cases: list[list[str]]) -> str:
    """Run `binary` over every fixed argv case and render the transcripts keyed on
    `case.N.*`. Exit codes and both streams are observations."""
    lines: list[str] = []
    for i, argv in enumerate(cases):
        res = run([str(binary), *argv], env=env)
        lines.append(f"case.{i}.argv={' '.join(argv)}")
        lines.append(f"case.{i}.exit={res.returncode}")
        lines.append(f"case.{i}.stdout={escape(res.stdout)}")
        lines.append(f"case.{i}.stderr={escape(res.stderr)}")
    return "\n".join(lines) + "\n"


def cli_parser_checks() -> list[dict]:
    """Drive the option-list parser over every captured fixed option table and require the
    structured rows to round-trip. This is `cli_option_list_parse`'s closure, measured."""
    import atlas_runtime as art

    body = json.loads(CLI_CAPTURE.read_text(encoding="utf-8"))["body"]
    checks: list[dict] = []
    for c in body["commands"]:
        parsed = art.parse_option_list(c["option_listing"])
        checks.append({
            "command": c["name"],
            "options": len(parsed),
            "round_trip": bool(parsed) and parsed == c["options"],
        })
    return checks


def cli_court(name: str, auth, work: Path) -> dict:
    """`RT-CLI`: the CLI dispatch over fixed argv and the option tables, differentially."""
    auth_bin = auth.prefix / "bin" / "openssl"
    cand_bin = PHASE2 / "openssl"
    cases = cli_argv_cases()
    a_out = cli_transcript(auth_bin, side_env(auth.libdir, auth.libdir / "ossl-modules"), cases)
    c_out = cli_transcript(
        cand_bin, side_env(PHASE2, PHASE2 / "install" / "lib" / "ossl-modules"), cases
    )
    residuals = diff(a_out, c_out)
    checks = cli_parser_checks()
    failures = [c for c in checks if not c["round_trip"]]
    return {
        "court": name,
        "argv_cases": len(cases),
        "authority_observations": len([l for l in a_out.splitlines() if "=" in l]),
        "candidate_observations": len([l for l in c_out.splitlines() if "=" in l]),
        "residual_count": len(residuals),
        "residuals": residuals[:24],
        "parser_checks": len(checks),
        "parser_failures": failures,
        "verdict": "pass" if not residuals and not failures else "fail",
    }


def court(name: str, src: Path, auth, work: Path) -> dict:
    auth_lib = auth.libdir
    auth_inc = auth.prefix / "include"

    auth_bin = work / f"{src.stem}.authority"
    cand_bin = work / f"{src.stem}.candidate"

    ok, err = compile_probe(src, auth_bin, auth_inc, auth_lib)
    if not ok:
        return {"court": name, "verdict": "fail", "stage": "compile-authority",
                "detail": err.splitlines()[:12]}
    ok, err = compile_probe(src, cand_bin, PHASE2 / "include", PHASE2)
    if not ok:
        return {"court": name, "verdict": "fail", "stage": "compile-candidate",
                "detail": err.splitlines()[:12]}

    a_out, a_err, a_code = run_probe(auth_bin, side_env(auth_lib, auth_lib / "ossl-modules"))
    c_out, c_err, c_code = run_probe(
        cand_bin, side_env(PHASE2, PHASE2 / "install" / "lib" / "ossl-modules")
    )

    staged = {}
    STAGED.mkdir(parents=True, exist_ok=True)
    for side, srcbin in (("authority", auth_bin), ("candidate", cand_bin)):
        dst = STAGED / f"{srcbin.stem}.{side}"
        if srcbin.is_file():
            shutil.copyfile(srcbin, dst)
            dst.chmod(0o755)
            staged[side] = rel(dst)

    if not a_out.strip():
        return {"court": name, "verdict": "fail", "stage": "authority-run",
                "detail": {"exit_code": a_code,
                           "stderr": a_err.splitlines()[:12]}}

    residuals = diff(a_out, c_out)
    # A probe that died on a signal compared nothing beyond the prefix it managed to print, so two
    # sides dying the same way is not agreement.
    crashed = a_code is None or a_code < 0 or c_code is None or c_code < 0
    return {
        "court": name,
        "probe": rel(src),
        "authority_exit_code": a_code,
        "candidate_exit_code": c_code,
        "crashed": crashed,
        "authority_observations": len([l for l in a_out.splitlines() if "=" in l]),
        "candidate_observations": len([l for l in c_out.splitlines() if "=" in l]),
        "residual_count": len(residuals),
        "residuals": residuals,
        "verdict": (
            "pass" if not residuals and c_code == a_code and not crashed else "fail"
        ),
        "staged_binaries": staged,
        "candidate_stderr_tail": c_err.splitlines()[-3:],
    }


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    args = ap.parse_args(argv)
    del args

    auth = resolve_authority(PRODUCTION_AUTHORITY)
    work = REPO_ROOT / "court" / "phase16"
    work.mkdir(parents=True, exist_ok=True)

    records: list[dict] = []
    for name, filename in COURTS:
        src = PROBE_DIR / filename
        if not src.is_file():
            records.append({"court": name, "verdict": "fail",
                            "stage": "probe-missing", "detail": rel(src)})
            continue
        records.append(court(name, src, auth, work))

    # `RT-CLI` drives the two executables rather than a compiled probe; it is a court
    # for the same reason and its verdict enters the same summary.
    records.append(cli_court("RT-CLI", auth, work))

    passed = sum(1 for r in records if r["verdict"] == "pass")
    body = {
        "all_pass": passed == len(records),
        "authority": auth.id,
        "courts": records,
        "summary": {"total": len(records), "pass": passed,
                    "fail": len(records) - passed},
        "pending_courts": PENDING_COURTS,
        "claim": (
            "`RT-LEGACY-MODULE` is 16.1's behavioural court: it **loads** the `legacy` provider "
            "module through `OSSL_PROVIDER_load` with `OPENSSL_MODULES` pointed at each side's "
            "own module directory, **reads** the provider name through "
            "`OSSL_PROVIDER_get_params`, **queries** the module's "
            "`OSSL_PROVIDER_query_operation` for all four operations 16.1 publishes "
            "(`OSSL_OP_DIGEST`, `OSSL_OP_CIPHER`, `OSSL_OP_KDF`, `OSSL_OP_SKEYMGMT`) and "
            "compares each table's row count and first row's alias sequence, **fetches** the "
            "four `legacy_digests` rows by name and by OID through the `provider=legacy` "
            "property and compares a fixed `\"abc\"` digest for each, **fetches and drives** "
            "each of the 32 `legacy_ciphers` rows with a fixed key/IV encrypt-and-decrypt and "
            "each of the two `legacy_kdfs` rows with a fixed password/salt/iteration derive, "
            "and exercises the refusal arms (an unknown digest/cipher/KDF name, a legacy name "
            "asked of the `default` provider, and two `PBKDF1` derives the row must refuse) -- "
            "not the error queue. The 39-row table is fully published, so "
            "`forensics/atlas/provider-algorithms.json` records `provider_rows_open` 0. "
            "`RT-ENGINE-DYN` is 16.2's: it **initialises** the `OPENSSL_INIT_ENGINE_DYNAMIC` "
            "bit (whose step runs `engine_load_dynamic_int` and registers the `dynamic` "
            "built-in), **reads** the `dynamic` engine id and name back through "
            "`ENGINE_by_id`, **drives** the dynamic fallback (`ENGINE_by_id`'s miss path "
            "recurses into `ENGINE_by_id(\"dynamic\")` and runs the `ID`/`DIR_LOAD`/`DIR_ADD`/"
            "`LIST_ADD`/`LOAD` control chain) with `OPENSSL_ENGINES` pointed at a fixed "
            "object-free directory, and exercises the NULL-, absent- and empty-id refusals. "
            "`RT-DEFAULTS` is 16.3's: it **reads** `OPENSSL_info(OPENSSL_INFO_CONFIG_DIR)` "
            "(which is `ossl_get_openssldir()`) and checks it equals "
            "`X509_get_default_cert_area()`, **checks** the four `X509_get_default_*` paths' "
            "`/certs`/`/cert.pem`/`/private` relationship to that area, **reads** "
            "`OPENSSL_info(OPENSSL_INFO_WINDOWS_CONTEXT)` (which is "
            "`ossl_get_wininstallcontext()`, the literal `\"Undefined\"`) and exercises the "
            "refusal arm (an unrecognised code is NULL; the seed-source and CPU settings "
            "codes are a recorded divergence and are not observed). The raw "
            "authority `OPENSSLDIR` is not printed: the candidate answers its own build path "
            "and the difference is a value the stratum does not claim. `RT-CONFIG` is 16.4's "
            "config-loader court: it **loads** a fixed in-memory configuration through "
            "`NCONF_load_bio` over a memory BIO, **reads** its sections and "
            "`get_string`/`get_number` values, and **drives** the CLI's default configuration "
            "file (`CONF_get1_default_config_file`), recording the unset-`OPENSSL_CONF` arm "
            "as a divergence. `RT-CLI` is 16.4's CLI court: it **runs** the admitted "
            "authority's own built `openssl` and the candidate distribution shell's over a "
            "fixed argv -- the global-`help`/`version`, unknown-command and `no-<cmd>` "
            "dispatcher arms, the `help`/`list`/`version` bodies, and every command's option "
            "table through `list -options <cmd>` -- and **drives** `atlas_runtime."
            "parse_option_list` over each captured `option_listing`, requiring a structured "
            "round-trip. Only `RT-STATEM-REMAINDER` remains named in `pending_courts`. "
            "docs/PHASE-16-SUBPHASES.md sections 3 and 4 record what each court compares."
        ),
    }

    inputs = [
        InputRef(name="phase-16-plan", path=REPO_ROOT / "docs" / "PHASE-16-SUBPHASES.md"),
        InputRef(name="phase16-obligations",
                 path=REPO_ROOT / "forensics" / "phase16-obligations.json"),
        InputRef(name="cli-capture", path=CLI_CAPTURE),
    ]
    for _name, filename in COURTS:
        inputs.append(InputRef(name="probe", path=PROBE_DIR / filename))
    doc = envelope(kind="phase16-courts", authority=auth.id, inputs=inputs,
                   body=body, generator=GENERATOR)
    write_json(OUT, doc)

    for r in records:
        if r["verdict"] == "pass":
            print(f"  {r['court']:<18} pass   "
                  f"({r['authority_observations']} observations)")
        else:
            print(f"  {r['court']:<18} FAIL   stage={r.get('stage', 'compare')}")
            detail = r.get("detail")
            if isinstance(detail, dict):
                print(f"      exit_code={detail.get('exit_code')}")
                for line in detail.get("stderr", []):
                    print(f"      {line}")
            elif isinstance(detail, list):
                for line in detail[:8]:
                    print(f"      {line}")
            for res in r.get("residuals", [])[:12]:
                print(f"      {res['observation']}: authority={res['authority']!r} "
                      f"candidate={res['candidate']!r} ({res['class']})")
    for name, needs in PENDING_COURTS.items():
        print(f"  {name:<18} PENDING (not registered as passing) -- {needs}")
    print(f"  -> {rel(OUT)} all_pass={body['all_pass']} over {len(records)} court(s)")
    return 0 if body["all_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
