#!/usr/bin/env python3
"""openssl-rs — Phase 13 courts: legacy/deprecated compatibility — ENGINE, UI, TXT_DB.

Each court is a C probe in `courts/phase13/` compiled **twice** — once against the admitted
authority, once against the candidate distribution shell — and run. The two transcripts are
compared line by line, and every difference is a residual.

The method is Phases 3-12's, for the same reason: a unit test encodes what its author believes the
contract is, whereas a probe measures what the authority actually does, and the comparison is
between two *executions* of the same program, so the expectation cannot drift.

`RT-PHASE13-REF`, and what it claims
------------------------------------
This stratum landed its reference basis at activation, because 13.0 lands no unit of its own: the
127 exports the crate already defines were landed by earlier strata as substrate. 13.1 then lands
the ENGINE object, registry and dynamic-loading surface, and its court is `RT-ENGINE`.

`RT-PHASE13-REF`, `courts/phase13/rt_coverage_ref_probe.c`, is the activation basis: it
takes each of the stratum's inherited `implemented` exports into a `volatile` table, prints one
`coverage_ref.N=nonnull` line per symbol, and stops. **It does not call any of them and claims no
behaviour about them.** The court coverage
atlas records every symbol covered only by it at basis `referenced`, never `called`, because the
probe's name is in that atlas's `reference_probes` table; the atlas's `claim` is the weaker, true
statement, and the atlas's phase-13 slice is the live count of the names each basis covers. See
docs/DECISIONS.md D199 and docs/PHASE-13-SUBPHASES.md section 4.3, which is where this stratum's
activation required it.

`RT-ENGINE`, and what it compares
---------------------------------
13.1's court, `courts/phase13/rt_engine_probe.c`, drives the three exports the subphase lands --
`ENGINE_by_id` (`eng_list.c`), `ENGINE_load_builtin_engines` (`eng_all.c`) and
`ENGINE_add_conf_module` (`eng_cnf.c`) -- over the 10.9 registry core. It compares the observed
`id`/`name` a lookup answers, object identity across lookups, the two refusal arms (NULL and absent
id), the refcount's effect on `ENGINE_free`/`ENGINE_remove`, and the one arm of the built-in
loader's registry effect both sides share (an engine registered before the call survives it). It
does **not** observe the built-in registry directly, because the authority registers `rdrand` and
`dynamic` and this crate registers nothing -- the divergence `src/engine/eng_all.rs` records -- nor
does it read the error queue. See docs/PHASE-13-SUBPHASES.md section 3.1 for what the court is
required to compare.

`RT-ENGINE-TABLE`, and what it compares
---------------------------------------
13.2's court, `courts/phase13/rt_engine_table_probe.c`, drives the table and method-binding
surface the subphase lands over a synthetic ENGINE built with the landed `ENGINE_new`/
`ENGINE_set_id`/`ENGINE_set_name`/`ENGINE_add`. It compares the identity each setter binds and
each getter returns, the cipher table's register/select/fetch/unregister cycle, the
`ENGINE_register_all_*` walk and the `dummy_nid` default select for the cipher/RSA/DSA/DH/EC/RAND
tables, the `ENGINE_get_pkey_meth` fetch and its absent-NID refusal, the three key-loader
setter/getter pairs and the NULL/uninitialised/no-loader refusals of
`ENGINE_load_private_key`/`_public_key`/`_ssl_client_cert`, and the no-method registration no-op.
It does **not** pass a NULL engine to a method getter (the authority dereferences it), and it never
reads the error queue, so the refusal arms' `ENGINE_R_*` raises cannot leak into a comparison. See
docs/PHASE-13-SUBPHASES.md section 3.2 for what the court is required to compare.

`RT-ENGINE-CTRL`, and what it compares
--------------------------------------
13.3's court, `courts/phase13/rt_engine_ctrl_probe.c`, drives the four control fat helpers the
subphase lands -- `ENGINE_set_default` and `ENGINE_set_default_string` (`eng_fat.c`), and
`ENGINE_register_complete`/`ENGINE_register_all_complete` -- over a synthetic ENGINE and the
`ENGINE_METHOD_*` bit names. It compares the mask dispatch one bit at a time and with
`ENGINE_METHOD_ALL` and `0`, every string spelling `int_def_cb` recognises (`RSA`, `RSA,DSA`,
`CIPHERS,DIGESTS`, `PKEY`, `PKEY_CRYPTO`, `PKEY_ASN1`, `ALL`, and space-trimmed elements), the
nine-arm registration through each table's select, the registry walk and its
`ENGINE_FLAGS_NO_REGISTER_ALL` skip, and the four refusal arms (an unknown element, an unknown
element after a known one, the NULL list and the empty list) by their return values and the
absence of a partial default. It does **not** pass a NULL engine (both bodies dereference it) and
never reads the error queue. See docs/PHASE-13-SUBPHASES.md section 3.3 for what the court is
required to compare.

`RT-UI`, and what it compares
-----------------------------
13.4's court, `courts/phase13/rt_ui_probe.c`, drives the whole 62-name `ui.h` framework the earlier
strata landed as substrate -- it *calls* every name rather than taking its address, which is what
moves its court-coverage basis from `referenced` to `called`. It builds a deterministic in-process
`UI_METHOD` (so `UI_process` never opens the console) and compares: the object lifecycle and method
identity; the `UI_METHOD` setter/getter pairs and their NULL arms; the string-add and `UI_dup_*`
surface and its refusal arms (a NULL prompt, a NULL result buffer, a NULL `ok_chars`/`cancel_chars`,
and the overlapping `ok`/`cancel` arm, which raises but still allocates); `UI_process`'s five phases
over every string type, with the writer observing each `UI_STRING`'s type, flags,
output/action/test strings and bounds and the reader supplying fixed answers through
`UI_set_result`/`UI_set_result_ex`; the result accessors and their negative and past-the-end
refusals; `UI_construct_prompt` default and method-supplied; the ex-data accessors;
`UI_UTIL_read_pw`/`_read_pw_string` over the in-process method and the PEM wrapper; and the null
method's `-2` cancel and empty-queue `0`. It does **not** pass a NULL `UI` to an accessor that
dereferences it (`UI_set_ex_data`, `UI_get_ex_data`, `UI_get_method`, `UI_set_method`,
`UI_get0_user_data`, `UI_process`, `UI_method_set_ex_data`, `UI_method_get_ex_data`), does not call
`UI_create_method(NULL)`, and never reads the error queue, so the `UI_R_*` raises on the refusals
cannot leak into a comparison. See docs/PHASE-13-SUBPHASES.md section 3.4.

The behavioural courts the plan gives the later subphases
---------------------------------------------------------
A court the plan names and this stratum cannot run yet is NOT registered here. It is named in
`PENDING_COURTS` with the subphase that brings it, and every name is printed on each run, so "not
run yet" cannot be read as "passed" -- the contract Phase 8's `PENDING_CORRECTNESS_COURTS` and every
later activation established. `RT-TXTDB`, `RT-EVP-LEGACY`, `RT-LEGACY-REMAINDER` and
`RT-HANDOFF` are the remaining subphases' own courts: 13.5's TXT_DB database,
13.6's legacy EVP method statics, 13.7's PEM readers and ASYNC framework, and 13.8's received
TS_CONF and SRP hand-offs.

What the behavioural courts will compare, and what they will not
----------------------------------------------------------------
The ENGINE, UI and TXT_DB courts will compare the authority's *behaviour*: the object lifecycle
and refcount, the registry and dynamic-loading arms, the registered method tables, the control
command dispatch, the UI method callbacks driven through a fixed in-process method, and the
TXT_DB read/write/update codec over a fixed text database. The legacy EVP method statics will be
driven over the authority's own primitives where an observable exists, and named `pending` where
the fetched-identity divergence the later CPS/CMS/TS courts already name makes a value
un-comparable. Nothing here is a parity claim about the meaning of an ENGINE registration or a
prompt.

SPDX-License-Identifier: Apache-2.0"""

from __future__ import annotations

import argparse
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

OUT = REPO_ROOT / "artifacts" / "phase13" / "COURTS.json"
GENERATOR = "forensics/tools/phase13_courts.py"
PROBE_DIR = REPO_ROOT / "courts" / "phase13"
PHASE2 = REPO_ROOT / "artifacts" / "phase2"
STAGED = REPO_ROOT / "artifacts" / "phase13" / "probes"
RUN_TIMEOUT_S = "60"

# The differential courts, in the order they land. `(name, probe filename)`, and the probe is
# declared in the same commit as the entry, so a runner that names a probe which does not exist
# cannot be committed -- the check below fails instead.
# Rows are appended as each subphase lands its court; a court whose probe the stratum cannot yet
# link stays in `PENDING_COURTS` below, so "not run yet" is never read as "passed".
COURTS: list[tuple[str, str]] = [
    ("RT-PHASE13-REF", "rt_coverage_ref_probe.c"),
    ("RT-ENGINE", "rt_engine_probe.c"),
    ("RT-ENGINE-TABLE", "rt_engine_table_probe.c"),
    ("RT-ENGINE-CTRL", "rt_engine_ctrl_probe.c"),
    ("RT-UI", "rt_ui_probe.c"),
]

# A court the plan names and this stratum cannot run yet. Not a registered court: nothing here can
# pass, and each is printed with the subphase that brings it so that "not run yet" cannot be read
# as "passed". The court names are `docs/PHASE-13-SUBPHASES.md` section 2's, one per work
# subphase.
PENDING_COURTS: dict[str, str] = {
    "RT-TXTDB": "13.5 (the TXT_DB text database)",
    "RT-EVP-LEGACY": "13.6 (the legacy EVP method statics)",
    "RT-LEGACY-REMAINDER": "13.7 (the PEM private-key readers and the ASYNC framework)",
    "RT-HANDOFF": "13.8 (the received TS_CONF and SRP hand-offs)",
}


def extra_defs(name: str, libdir: Path) -> list[str]:
    """Per-side build definitions.

    **None.** `RT-PHASE13-REF` takes addresses and prints whether each is non-NULL; it is compiled
    identically on both sides, so a difference in either transcript can only be a difference in
    what the library does. `extra_defs` is kept because the runner's shape is Phase 8's through
    Phase 12's and a later court here may need one.
    """
    del name, libdir
    return []


def compile_probe(
    src: Path, out: Path, include: Path, libdir: Path, defs: list[str] | None = None
) -> tuple[bool, str]:
    res = run([
        # `-Werror=implicit-function-declaration` is not decoration: without a prototype, C
        # assumes a function returns `int`, so a probe that forgot an include reads a pointer
        # return as its low 32 bits and dereferences it. Phases 6 through 12 each paid a run to
        # learn that, so it is a compile failure here.
        "clang", "-std=c11", "-Wall", "-Werror=implicit-function-declaration", "-O1",
        "-D_GNU_SOURCE",
        *(defs or []),
        "-I", str(include),
        "-o", str(out), str(src),
        "-L", str(libdir), "-lcrypto",
        f"-Wl,-rpath,{libdir}",
    ])
    return res.ok, res.stderr.strip()


def run_probe(binary: Path) -> tuple[str, str, int | None]:
    res = run(["timeout", RUN_TIMEOUT_S, str(binary)])
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


def court(name: str, src: Path, auth, work: Path) -> dict:
    auth_lib = auth.prefix / "lib"
    auth_inc = auth.prefix / "include"

    auth_bin = work / f"{src.stem}.authority"
    cand_bin = work / f"{src.stem}.candidate"

    ok, err = compile_probe(src, auth_bin, auth_inc, auth_lib,
                            extra_defs(name, auth_lib))
    if not ok:
        return {"court": name, "verdict": "fail", "stage": "compile-authority",
                "detail": err.splitlines()[:12]}
    ok, err = compile_probe(src, cand_bin, PHASE2 / "include", PHASE2,
                            extra_defs(name, PHASE2))
    if not ok:
        return {"court": name, "verdict": "fail", "stage": "compile-candidate",
                "detail": err.splitlines()[:12]}

    a_out, a_err, a_code = run_probe(auth_bin)
    c_out, c_err, c_code = run_probe(cand_bin)

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
    work = REPO_ROOT / "court" / "phase13"
    work.mkdir(parents=True, exist_ok=True)

    records: list[dict] = []
    for name, filename in COURTS:
        src = PROBE_DIR / filename
        if not src.is_file():
            records.append({"court": name, "verdict": "fail",
                            "stage": "probe-missing", "detail": rel(src)})
            continue
        records.append(court(name, src, auth, work))

    passed = sum(1 for r in records if r["verdict"] == "pass")
    body = {
        "all_pass": passed == len(records),
        "authority": auth.id,
        "courts": records,
        "summary": {"total": len(records), "pass": passed,
                    "fail": len(records) - passed},
        "pending_courts": PENDING_COURTS,
        "claim": (
            "`RT-PHASE13-REF` is the activation **reference basis**: its probe takes the address "
            "of each of this stratum's inherited `implemented` exports -- the 61 `ENGINE_*` "
            "object, accessor and table names, the 62 `UI_*` names and the four "
            "`PEM_read[_bio]_PrivateKey` spellings -- and prints whether each is non-NULL. A "
            "symbol covered only by it means the candidate distribution defines the name -- "
            "which the link proves -- and NOT that any arm of it was driven; the court coverage "
            "atlas records those at basis `referenced`, never `called` (docs/DECISIONS.md "
            "D199). `RT-ENGINE` is 13.1's behavioural court: it **calls** `ENGINE_by_id`, "
            "`ENGINE_load_builtin_engines` and `ENGINE_add_conf_module` and compares the "
            "registry's observed `id`/`name`, object identity, the NULL/absent refusals, the "
            "refcount effect and the built-in loader's shared registry arm -- not the built-in "
            "registry itself, whose `rdrand`/`dynamic` divergence src/engine/eng_all.rs records, "
            "and not the error queue. `RT-ENGINE-TABLE` is 13.2's behavioural court: it **calls** "
            "the `tb_cipher`/`tb_rsa`/`tb_dsa`/`tb_dh`/`tb_eckey`/`tb_rand` table surface, "
            "`ENGINE_get_pkey_meth` and the `eng_pkey.c` key-loader entry points over a synthetic "
            "ENGINE and compares the bound method identities, the register/select/unregister "
            "cycle, the `ENGINE_register_all_*` walk, the `dummy_nid` default select and the "
            "NULL/uninitialised/no-loader refusals -- not a NULL engine handed to a method "
            "getter, and not the error queue. `RT-ENGINE-CTRL` is 13.3's behavioural court: it "
            "**calls** the four control fat helpers `eng_fat.c` lands and compares the "
            "`ENGINE_METHOD_*` mask dispatch, every `int_def_cb` string spelling, the nine-arm "
            "`ENGINE_register_complete` and the `ENGINE_register_all_complete` walk and its "
            "`ENGINE_register_all_complete` walk and its "
            "`ENGINE_FLAGS_NO_REGISTER_ALL` skip, and the unknown/partial/NULL/empty refusals "
            "-- not a NULL engine, and not the error queue. `RT-UI` is 13.4's behavioural "
            "court: it **calls** all 62 `ui.h` names -- the object lifecycle, the `UI_METHOD` "
            "setter/getter surface and its NULL arms, the string-add and `UI_dup_*` surface and "
            "refusals, `UI_process` over a deterministic in-process method with the writer "
            "observing every `UI_STRING` and the reader supplying fixed answers, the result and "
            "prompt-construction accessors, the ex-data accessors, `UI_UTIL_read_pw`/"
            "`_read_pw_string` and the PEM wrapper, and the null method's cancel -- so those "
            "names are `called` and not merely `referenced`; it passes no NULL that an accessor "
            "would dereference, does not call `UI_create_method(NULL)`, and never reads the "
            "error queue. Every other behavioural court the "
            "plan names is named in `pending_courts` with the subphase that brings it -- "
            "`RT-TXTDB`, `RT-EVP-LEGACY`, `RT-LEGACY-REMAINDER` and `RT-HANDOFF` -- and "
            "none is registered here, so 'not run yet' cannot be read as 'passed'. Nothing here "
            "is a parity claim: `referenced` is not `called`, and docs/PHASE-13-SUBPHASES.md "
            "section 3 records what the behavioural courts compare."
        ),
    }

    inputs = [
        InputRef(name="authority-symbols", path=REPO_ROOT / "forensics" / "atlas"
                 / auth.id / "symbols-libcrypto.json"),
    ]
    for _name, filename in COURTS:
        inputs.append(InputRef(name="probe", path=PROBE_DIR / filename))
    doc = envelope(kind="phase13-courts", authority=auth.id, inputs=inputs,
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
