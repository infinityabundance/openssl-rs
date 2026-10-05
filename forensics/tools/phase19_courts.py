#!/usr/bin/env python3
"""openssl-rs — Phase 19 courts: the performance / CPU dispatch courts.

Each court is an instrument over the finished implementation, not a differential probe over a
symbol set. This stratum owns no exported symbol: it measures the library the strata before it
completed, so its evidence is about *dispatch behaviour* and *deterministic work* — how the
candidate reports CPU capabilities and selects implementations, and how much work its primitive
paths perform — rather than a count of names. The method is Phases 3 through 18's where a
differential control is possible: the authority and the candidate are driven over the same
capability set or the same input and their observations compared, so the expectation cannot drift.
Where the subject is the *instrument's* sensitivity — can the work measure tell a deliberately
slowed path from a fast one — the court is candidate-only and carries a sensitivity control instead
(D13, D201), exactly as Phase 8's `CT-*` courts and Phase 18's `CT-PRIMITIVES` do.

`RT-CPU-CAPABILITY`, and what it drives
--------------------------------------
19.1's court. Its instrument is `courts/phase19/rt_cpu_capability_probe.c`, compiled twice: once
against the admitted authority and once against the candidate distribution shell. It reports the
CPU-capability surface deterministically — `OPENSSL_ia32cap_P[0..3]`, the effect of calling
`OPENSSL_cpuid_setup`, the raw vector `OPENSSL_ia32_cpuid` returns, and the capability-derived
selection observable through the public API (`OpenSSL_version(OPENSSL_CPU_INFO)`,
`OPENSSL_info(OPENSSL_INFO_CPU_SETTINGS)` and the four `EVP_aes_*_cbc_hmac_sha*` constructors, which
answer NULL when `AESNI_CAPABLE` is clear) — as `key=value` observations with no address, clock or
duration.

The three names are declared `weak`: `OPENSSL_ia32cap_P` is `.hidden` and `OPENSSL_cpuid_setup` /
`OPENSSL_ia32_cpuid` live only in the static archive, so a side that does not provide them answers
`probe.reachable.*=0` instead of failing to link. The authority's static archive provides all three;
**the candidate provides none of them** — this is the `symbols_not_reached` census
`docs/PHASE-19-SUBPHASES.md` section 4.2 records, and the court records it honestly (the candidate's
CPU-dispatch string is `CPUINFO: N/A` and `OPENSSL_info(1008)` is NULL) rather than substituting an
answer. Because a dynamic link never resolves the hidden symbol, the court links the authority
against `libcrypto.a` with `-Wl,-u,` forcing and the candidate against its distribution shell.

The *fixed and faulted CPUID facade* is the `OPENSSL_ia32cap` environment variable: the authority's
`OPENSSL_cpuid_setup` reads it in the ELF `.init` constructor and masks the capability vector with
it, so the court fixes the capability set by running the probe under a chosen value. The probe is
driven under three sets — the host set, an AES-NI-cleared set and a fully cleared set — and the
authority's report and selection move with the facade while the candidate's do not. Every
candidate-vs-authority difference is *recorded* in the court's `divergences` block, not failed: the
reduced engine deliberately does not model `OPENSSL_ia32cap` masking (`src/provider/cipher.rs`).
The verdict is `pass` when the authority's capability surface was actually driven (the
authority-linked differential control), both transcripts are complete, and every divergence was
recorded — **not** when nothing diverged. It is not a parity claim and not an
assembly-versus-Rust equivalence claim (section 3.6).

`RT-EVP-DISPATCH`, and what it drives
------------------------------------
19.2's court. Its instrument is `courts/phase19/rt_evp_dispatch_probe.c`, compiled twice against
the same two sides. It reports, for a fixed operation set (AES-128/256-CBC, AES-128/256-GCM,
ChaCha20-Poly1305, SHA-1, SHA-256 and the four `EVP_aes_*_cbc_hmac_sha*` constructors), which
implementation each *selection path* chooses -- the legacy constructor, the provider fetch, the
legacy name lookup and the cipher/digest context -- as the selected method's `name`, `NID`/`type`,
`flags`, block/key/IV sizes, whether it carries a provider, and, for a fetch, the provider's own
name. It is driven under the same three fixed capability sets via the `OPENSSL_ia32cap` facade as
19.1.

The authority's default provider filters its `AES-*-CBC-HMAC-*` rows through
`ossl_cipher_capable_aes_cbc_hmac_sha*` (`AESNI_CBC_HMAC_SHA_CAPABLE`, `OPENSSL_ia32cap_P[1] &
(1 << 25)`), and its legacy `EVP_aes_*_cbc_hmac_sha*` constructor reads the same bit, so masking
AES-NI off makes those fetch/legacy/lookup paths answer NULL and *moves the authority's
selection*. That movement is the authority-linked differential control. The candidate reads the
same bit from `CPUID.(EAX=1).ECX` directly (`src/provider/cipher.rs:10560`) and does not model the
mask, so its selection does not move; that disposition and every other candidate-vs-authority
difference is *recorded* in the court's `divergences` block, not failed. The verdict is `pass`
when the authority's selection surface was driven, the faulted facade moved it, both transcripts
are complete under every set, and every divergence was recorded -- **not** when nothing diverged.
The engine path is not driven: no engine is configured and the reduced engine does not export the
enumeration it would need. It is a bounded comparison of *selection*, not a parity claim and not
an assembly-versus-Rust equivalence claim (sections 3.4 and 3.6).

The pending courts
------------------
The other three courts the plan names are `pending` with the subphase that lands each:

  * `RT-PERFORMANCE-WORK` (19.3) — deterministic operation and block counts over the
    primitive-bearing paths (not wall-clock-only), driven on the authority and the candidate over
    the same inputs, recording every path whose work differs as a finding;
  * `RT-PERFORMANCE-SENSITIVITY` (19.4) — the instrument-sensitivity control: a deliberately slowed
    path must be caught, so a measure that cannot tell a slow path from a fast one is `fail` rather
    than `pass`; candidate-only;
  * `PERFORMANCE-BOUNDARY-REGISTER` (19.5) — the register that records what is measured, what is
    not, and the explicit non-claims (no benchmark-parity claim, no assembly-versus-Rust
    equivalence claim), and that fails the stratum if a recorded boundary drifts from its evidence.

There is no benchmark-parity claim and no assembly-versus-Rust equivalence claim anywhere in this
stratum, and no verdict is ever taken from wall-clock time alone.

The runner reads no obligations ledger: the ledger's contract-unit states are measured from this
registry, so the edge runs ledger -> courts and binding it back would form a digest cycle neither
artefact could reproduce. `docs/PHASE-19-SUBPHASES.md` section 4.2 is the precondition. No court is
registered in `gen_frf_courts.py`: that registry is the stratum's seal.

SPDX-License-Identifier: Apache-2.0"""

from __future__ import annotations

import argparse
import os
import shutil
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
    run,
    write_json,
)

OUT = REPO_ROOT / "artifacts" / "phase19" / "COURTS.json"
GENERATOR = "forensics/tools/phase19_courts.py"
PLAN = REPO_ROOT / "docs" / "PHASE-19-SUBPHASES.md"
PROBE_DIR = REPO_ROOT / "courts" / "phase19"
STAGED = REPO_ROOT / "artifacts" / "phase19" / "probes"
PHASE2 = REPO_ROOT / "artifacts" / "phase2"
RUN_TIMEOUT_S = "120"

# The courts, in the order they land. `(name, probe filename)`, and the probe is declared in the
# same commit as the entry, so a runner that names a probe which does not exist cannot be
# committed.
CPU_CAPABILITY = "RT-CPU-CAPABILITY"
EVP_DISPATCH = "RT-EVP-DISPATCH"
COURTS: list[tuple[str, str]] = [
    (CPU_CAPABILITY, "rt_cpu_capability_probe.c"),
    (EVP_DISPATCH, "rt_evp_dispatch_probe.c"),
]

# A court the plan names and this stratum cannot run yet. Each entry names the subphase that lands
# the instrument and what the court will drive, so "nothing registered" is a stated distance rather
# than a court quietly dropped.
PENDING_COURTS: dict[str, str] = {
    "RT-PERFORMANCE-WORK": (
        "19.3 lands the deterministic work court; it counts operations and blocks over the "
        "primitive-bearing paths (not wall-clock-only) on both sides and records every path whose "
        "work differs as a finding"
    ),
    "RT-PERFORMANCE-SENSITIVITY": (
        "19.4 lands the sensitivity control; it requires a deliberately slowed path to be caught, "
        "so the work measure is proven able to tell a slow path from a fast one"
    ),
    "PERFORMANCE-BOUNDARY-REGISTER": (
        "19.5 lands the register; it records what is measured, what is not, and the explicit "
        "non-claims (no benchmark-parity claim, no assembly-versus-Rust equivalence claim), and "
        "checks that every recorded boundary still matches the evidence that establishes it"
    ),
}

# The fixed capability sets the capability probe is driven under. `(set name, OPENSSL_ia32cap
# value or None)`. The first is the host's own CPU, the second clears the AES-NI bit (bit 25 of
# `OPENSSL_ia32cap_P[1]`, `1 << 25` of the high 64-bit word) and the third clears everything; the
# authority's `OPENSSL_cpuid_setup` masks the vector with the value at load, so the *court* fixes
# the capability set the surface reports and the selection is made over.
CAPABILITY_SETS: list[tuple[str, str | None]] = [
    ("host", None),
    ("aesni-off", "~0x0200000000000000"),
    ("cleared", "~0xffffffffffffffff"),
]

# The capability-derived selection the facade must move on the authority, as the section-3.2
# authority-linked differential control: `sel.aes128cbcsha1.null` is 0 under the host set and 1
# under the AES-NI-cleared set. The facade's job is to drive *the authority's* selection; a court
# whose facade cannot move it has not driven the surface.
FACADE_CONTROL_KEY = "sel.aes128cbcsha1.null"

# The three capability-surface names the plan's census records as `symbols_not_reached` for the
# candidate. The authority must reach all three or the court has no expectation to compare; the
# candidate's reachability is recorded (whatever it is) rather than required.
REACHABLE_KEYS = (
    "probe.reachable.ia32cap_p",
    "probe.reachable.cpuid_setup",
    "probe.reachable.ia32_cpuid",
)

# The fixed transcript schema. Both sides emit every key (an unreached numeric observation is
# `n/a`), so the two observation counts agree and `atlas_common.court_observations` holds.
PROBE_SCHEMA = (
    "probe.kind",
    "probe.arch",
    *REACHABLE_KEYS,
    "probe.setup.called",
    "probe.setup.stable",
    "probe.cpuid.called",
    "probe.cpuid.ret",
    "cap.word.0",
    "cap.word.1",
    "cap.word.2",
    "cap.word.3",
    "cap.after_setup.0",
    "cap.after_setup.1",
    "cap.after_setup.2",
    "cap.after_setup.3",
    "cap.raw.word.2",
    "cap.raw.word.3",
    "api.cpuinfo",
    "api.cpu_settings_null",
    "api.cpu_settings",
    "sel.aes128cbcsha1.null",
    "sel.aes256cbcsha1.null",
    "sel.aes128cbcsha256.null",
    "sel.aes256cbcsha256.null",
    "probe.done",
)

# --------------------------------------------------------------------------------------------
# `RT-EVP-DISPATCH` (19.2): the fixed operation set the selection probe drives. The op ids here
# are the key fragments `courts/phase19/rt_evp_dispatch_probe.c` prints, and the schema below is
# built from the same lists, so an operation added to the probe without the schema is caught as a
# missing key rather than compared unobserved.
# --------------------------------------------------------------------------------------------
EVP_CIPHER_OPS: tuple[tuple[str, str], ...] = (
    ("aes-128-cbc", "AES-128-CBC"),
    ("aes-256-cbc", "AES-256-CBC"),
    ("aes-128-gcm", "AES-128-GCM"),
    ("aes-256-gcm", "AES-256-GCM"),
    ("chacha20-poly1305", "CHACHA20-POLY1305"),
    ("aes-128-cbc-hmac-sha1", "AES-128-CBC-HMAC-SHA1"),
    ("aes-256-cbc-hmac-sha1", "AES-256-CBC-HMAC-SHA1"),
    ("aes-128-cbc-hmac-sha256", "AES-128-CBC-HMAC-SHA256"),
    ("aes-256-cbc-hmac-sha256", "AES-256-CBC-HMAC-SHA256"),
)
EVP_DIGEST_OPS: tuple[tuple[str, str], ...] = (
    ("sha1", "SHA1"),
    ("sha256", "SHA256"),
)
# The context-selection operations: the legacy constructor plus three provider fetches and the
# fetched digest. The names are the key fragments the probe prints, not fetch names.
EVP_CTX_OPS: tuple[str, ...] = (
    "aes-128-cbc",
    "aes-128-cbc-fetch",
    "aes-128-gcm-fetch",
    "chacha20-poly1305-fetch",
    "sha256-fetch",
)

# The per-path identity fields, mirroring the probe's emitters. The legacy and fetch cipher paths
# carry `prov_null` (the legacy static has no provider); the digest paths answer `size` instead of
# `keylen`/`ivlen`. A fetch adds the provider name and the canonical-alias resolution.
CIPHER_IDENTITY = ("null", "name", "nid", "flags", "type", "block", "keylen", "ivlen",
                   "prov_null")
DIGEST_IDENTITY = ("null", "name", "nid", "flags", "size", "block", "prov_null")
PROV_EXTRA = ("prov_name", "is_a")
CTX_FIELDS = ("init", "name", "nid", "prov_name")


# The capability sets `RT-EVP-DISPATCH` drives the selection probe under, shared with 19.1: the
# host set, an AES-NI-cleared set (the `OPENSSL_ia32cap` facade masks bit 25 of the high word) and
# a fully cleared set. The authority's provider capability filter and its legacy `AESNI_CAPABLE`
# predicate both read the masked vector, so its `AES-*-CBC-HMAC-*` selection moves with the facade;
# the candidate reads CPUID directly and does not.
#
# `EVP_DISPATCH_CONTROLS` is the section-3.2 authority-linked differential control: each row is
# `(key, host-value, aesni-off-value)`. The authority's selection must take the host value under
# the host set and the cleared value under the faulted set, or the facade did not drive it.
EVP_DISPATCH_CONTROLS: tuple[tuple[str, str, str], ...] = (
    ("fetch.aes-128-cbc-hmac-sha1.null", "0", "1"),
    ("legacy.aes-256-cbc-hmac-sha256.null", "0", "1"),
    ("lookup.aes-128-cbc-hmac-sha1.null", "0", "1"),
)


def evp_dispatch_schema() -> tuple[str, ...]:
    """The fixed transcript schema for `RT-EVP-DISPATCH`.

    Both sides emit every key (a NULL selection prints `n/a`-shaped placeholders), so the two
    observation counts agree and `atlas_common.court_observations` holds. The keys are built from
    the same operation lists the probe's C table carries, so a drift between them fails closed as
    a missing key rather than passing unobserved.
    """
    keys: list[str] = ["probe.kind", "prov.default.loaded", "prov.default.name",
                       "prov.default.unload"]
    for oid, _name in EVP_CIPHER_OPS:
        keys += [f"legacy.{oid}.{field}" for field in CIPHER_IDENTITY]
        keys += [f"lookup.{oid}.null", f"lookup.{oid}.nid"]
    for oid, _name in EVP_DIGEST_OPS:
        keys += [f"legacy.{oid}.{field}" for field in DIGEST_IDENTITY]
        keys += [f"lookup.{oid}.null", f"lookup.{oid}.nid"]
    for oid, _name in EVP_CIPHER_OPS:
        keys += [f"fetch.{oid}.{field}" for field in CIPHER_IDENTITY]
        keys += [f"fetch.{oid}.{field}" for field in PROV_EXTRA]
    for oid, _name in EVP_DIGEST_OPS:
        keys += [f"fetch.{oid}.{field}" for field in DIGEST_IDENTITY]
        keys += [f"fetch.{oid}.{field}" for field in PROV_EXTRA]
    for oid in EVP_CTX_OPS:
        keys += [f"ctx.{oid}.{field}" for field in CTX_FIELDS]
    keys.append("probe.done")
    return tuple(keys)


EVP_DISPATCH_PROBE_SCHEMA: tuple[str, ...] = evp_dispatch_schema()


def side_env(libdir: Path, modulesdir: Path, cap: str | None) -> dict[str, str]:
    """The environment one probe run sees on one side.

    `LD_LIBRARY_PATH` fixes the DSO the candidate probe resolves against, `OPENSSL_MODULES` points
    at that side's own `ossl-modules/`, and `OPENSSL_CONF=/dev/null` keeps the host's configuration
    out of a deterministic transcript. `cap`, when set, is the `OPENSSL_ia32cap` facade value the
    authority's `.init` constructor reads.
    """
    env = dict(os.environ)
    env["LD_LIBRARY_PATH"] = str(libdir)
    env["OPENSSL_MODULES"] = str(modulesdir)
    env["OPENSSL_CONF"] = "/dev/null"
    env.pop("OPENSSL_CONF_INCLUDE", None)
    if cap is None:
        env.pop("OPENSSL_ia32cap", None)
    else:
        env["OPENSSL_ia32cap"] = cap
    return env


def run_probe(binary: Path, env: dict[str, str]) -> tuple[str, str, int | None]:
    """Run one side's probe and decode its transcript, tolerating a signal or a timeout."""
    proc = subprocess.run(
        ["timeout", RUN_TIMEOUT_S, str(binary)],
        env=env,
        capture_output=True,
        check=False,
    )
    code = proc.returncode
    out = proc.stdout.decode("latin-1")
    err = proc.stderr.decode("latin-1")
    if code == 124:
        return out, err, None
    return out, err, code


def _clang(src: Path, out: Path, include: Path) -> list[str]:
    return [
        "clang", "-std=c11", "-Wall", "-Wno-deprecated-declarations",
        "-Werror=implicit-function-declaration", "-O1",
        "-D_GNU_SOURCE",
        "-I", str(include),
        "-o", str(out), str(src),
    ]


def compile_authority(src: Path, out: Path, auth) -> tuple[bool, str]:
    """Compile the probe against the authority and link it statically.

    The capability surface is `.hidden`/archive-only, so a dynamic link cannot reach it: the
    authority probe links its static `libcrypto.a`, and `-Wl,-u,` forces the archive members that
    define the three names to be pulled in even though the probe's references are weak.
    """
    res = run(_clang(src, out, auth.prefix / "include") + [
        str(auth.libdir / "libcrypto.a"),
        "-Wl,-u,OPENSSL_cpuid_setup",
        "-Wl,-u,OPENSSL_ia32_cpuid",
        "-Wl,-u,OPENSSL_ia32cap_P",
        "-ldl", "-lpthread",
    ])
    return res.ok, res.stderr.strip()


def compile_candidate(src: Path, out: Path) -> tuple[bool, str]:
    """Compile the probe against the candidate distribution shell.

    The candidate provides none of the three capability-surface names, so the probe's weak
    references resolve to NULL and it answers `probe.reachable.*=0`; the public-API observations
    are driven exactly as on the authority.
    """
    res = run(_clang(src, out, PHASE2 / "include") + [
        "-L", str(PHASE2), "-lssl", "-lcrypto",
        f"-Wl,-rpath,{PHASE2}",
    ])
    return res.ok, res.stderr.strip()


def keyed(text: str) -> dict[str, str]:
    """The `key=value` observations, keyed for a line-independent comparison."""
    values: dict[str, str] = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key] = value
    return values


def residual_rows(a: dict[str, str], c: dict[str, str]) -> list[dict]:
    """Every observation that differs between the two sides, classified by its kind."""
    rows: list[dict] = []
    for key in sorted(set(a) | set(c)):
        av, cv = a.get(key), c.get(key)
        if av == cv:
            continue
        if key not in c:
            cls = "missing"
        elif key not in a:
            cls = "extra"
        else:
            cls = "value"
        rows.append({"observation": key, "authority": av, "candidate": cv, "class": cls})
    return rows


def cpu_capability_court(name: str, src: Path, auth, work: Path) -> dict:
    """`RT-CPU-CAPABILITY`: the capability surface and its selection, under fixed CPUID facades.

    The verdict is `pass` when the authority's capability surface was actually driven (the
    authority linked and reached `OPENSSL_ia32cap_P`), the faulted facade moved the authority's
    capability-derived selection, both transcripts are complete under every set, and every
    candidate-vs-authority difference was recorded. The candidate's `symbols_not_reached`
    disposition is a recorded divergence, not a failure.
    """
    auth_bin = work / f"{src.stem}.authority"
    cand_bin = work / f"{src.stem}.candidate"
    ok, err = compile_authority(src, auth_bin, auth)
    if not ok:
        return {"court": name, "verdict": "fail", "stage": "compile-authority",
                "detail": err.splitlines()[:12]}
    ok, err = compile_candidate(src, cand_bin)
    if not ok:
        return {"court": name, "verdict": "fail", "stage": "compile-candidate",
                "detail": err.splitlines()[:12]}

    problems: list[str] = []
    sets: list[dict] = []
    divergences: list[dict] = []
    a_obs_total = 0
    c_obs_total = 0
    per_set: dict[str, dict[str, str]] = {"authority": {}, "candidate": {}}

    for scenario, cap in CAPABILITY_SETS:
        a_out, a_err, a_code = run_probe(
            auth_bin, side_env(auth.libdir, auth.libdir / "ossl-modules", cap))
        c_out, c_err, c_code = run_probe(
            cand_bin, side_env(PHASE2, PHASE2 / "install" / "lib" / "ossl-modules", cap))
        if not a_out.strip():
            problems.append(f"{scenario}: authority produced no transcript "
                            f"(exit={a_code})")
        if not c_out.strip():
            problems.append(f"{scenario}: candidate produced no transcript "
                            f"(exit={c_code})")

        a_keys = keyed(a_out)
        c_keys = keyed(c_out)
        a_ns = {f"{scenario}.{k}": v for k, v in a_keys.items()}
        c_ns = {f"{scenario}.{k}": v for k, v in c_keys.items()}
        per_set["authority"].update(a_ns)
        per_set["candidate"].update(c_ns)
        a_obs_total += len(a_keys)
        c_obs_total += len(c_keys)

        if a_keys.get("probe.done") != "1":
            problems.append(f"{scenario}: authority transcript did not complete")
        if c_keys.get("probe.done") != "1":
            problems.append(f"{scenario}: candidate transcript did not complete")
        for key in PROBE_SCHEMA:
            if key not in a_keys:
                problems.append(f"{scenario}: authority is missing {key}")
            if key not in c_keys:
                problems.append(f"{scenario}: candidate is missing {key}")

        set_div = residual_rows(a_ns, c_ns)
        for row in set_div:
            row["set"] = scenario
        divergences.extend(set_div)
        sets.append({
            "set": scenario,
            "OPENSSL_ia32cap": cap if cap is not None else "(unset)",
            "authority_exit_code": a_code,
            "candidate_exit_code": c_code,
            "authority_observations": len(a_keys),
            "candidate_observations": len(c_keys),
            "divergence_count": len(set_div),
        })

    # The authority-linked differential control: the authority must have reached its own
    # capability surface, and the faulted facade must have moved its capability-derived selection.
    host = per_set["authority"]
    reached = {key: host.get(f"host.{key}", "missing") for key in REACHABLE_KEYS}
    if host.get("host.probe.reachable.ia32cap_p") != "1":
        problems.append(
            "authority did not reach OPENSSL_ia32cap_P: the capability surface was not driven "
            f"({reached})")
    if host.get("host.probe.reachable.cpuid_setup") != "1":
        problems.append("authority did not reach OPENSSL_cpuid_setup")
    if host.get("host.probe.reachable.ia32_cpuid") != "1":
        problems.append("authority did not reach OPENSSL_ia32_cpuid")
    facade_before = host.get(f"host.{FACADE_CONTROL_KEY}")
    facade_after = host.get(f"aesni-off.{FACADE_CONTROL_KEY}")
    facade_ok = (facade_before == "0" and facade_after == "1")
    if not facade_ok:
        problems.append(
            f"the faulted facade did not move the authority's selection: "
            f"{FACADE_CONTROL_KEY} host={facade_before} aesni-off={facade_after}")

    candidate_reached = {key: per_set["candidate"].get(f"host.{key}", "missing")
                         for key in REACHABLE_KEYS}

    staged: dict[str, str] = {}
    STAGED.mkdir(parents=True, exist_ok=True)
    for side, srcbin in (("authority", auth_bin), ("candidate", cand_bin)):
        dst = STAGED / f"{src.stem}.{side}"
        if srcbin.is_file():
            shutil.copyfile(srcbin, dst)
            dst.chmod(0o755)
            staged[side] = rel(dst)

    verdict = "pass" if not problems else "fail"

    return {
        "court": name,
        "probe": rel(src),
        "method": (
            "the probe is compiled twice and its `key=value` transcript compared. It is driven "
            "under three fixed capability sets via the `OPENSSL_ia32cap` facade (the host set, an "
            "AES-NI-cleared set and a fully cleared set). The authority probe links its static "
            "`libcrypto.a` with `-Wl,-u,` forcing so the hidden `OPENSSL_ia32cap_P` and the "
            "archive-only `OPENSSL_cpuid_setup` / `OPENSSL_ia32_cpuid` are reachable; the "
            "candidate probe links its distribution shell, where the weak references resolve to "
            "NULL. No address, clock or duration is observed."),
        "capability_sets": sets,
        "observations_recorded": {"authority": a_obs_total, "candidate": c_obs_total},
        "authority_observations": a_obs_total,
        "candidate_observations": c_obs_total,
        "reached": {"authority": reached, "candidate": candidate_reached},
        "control": {
            "authority_surface_reached": host.get("host.probe.reachable.ia32cap_p") == "1",
            "facade_key": FACADE_CONTROL_KEY,
            "facade_host": facade_before,
            "facade_aesni_off": facade_after,
            "facade_moved_selection": facade_ok,
        },
        "divergences": divergences,
        "divergence_count": len(divergences),
        "problems": problems,
        "verdict": verdict,
        "staged_binaries": staged,
        "candidate_stderr_tail": c_err.splitlines()[-3:],
    }


COURT_IMPL = {
    CPU_CAPABILITY: cpu_capability_court,
}


def evp_dispatch_court(name: str, src: Path, auth, work: Path) -> dict:
    """`RT-EVP-DISPATCH`: which implementation each operation selects, under fixed facades.

    The verdict is `pass` when the authority's selection surface was actually driven (the probe
    linked and its transcript completed under every set), the faulted facade moved the authority's
    capability-derived selection (the `AES-*-CBC-HMAC-*` fetch/legacy/lookup paths answered NULL
    with AES-NI masked), every schema key is present on both sides, and every candidate-vs-authority
    difference was recorded. The candidate's not-modelling-the-mask disposition is a recorded
    divergence, not a failure.
    """
    auth_bin = work / f"{src.stem}.authority"
    cand_bin = work / f"{src.stem}.candidate"
    ok, err = compile_authority(src, auth_bin, auth)
    if not ok:
        return {"court": name, "verdict": "fail", "stage": "compile-authority",
                "detail": err.splitlines()[:12]}
    ok, err = compile_candidate(src, cand_bin)
    if not ok:
        return {"court": name, "verdict": "fail", "stage": "compile-candidate",
                "detail": err.splitlines()[:12]}

    problems: list[str] = []
    sets: list[dict] = []
    divergences: list[dict] = []
    a_obs_total = 0
    c_obs_total = 0
    per_set: dict[str, dict[str, str]] = {"authority": {}, "candidate": {}}

    for scenario, cap in CAPABILITY_SETS:
        a_out, a_err, a_code = run_probe(
            auth_bin, side_env(auth.libdir, auth.libdir / "ossl-modules", cap))
        c_out, c_err, c_code = run_probe(
            cand_bin, side_env(PHASE2, PHASE2 / "install" / "lib" / "ossl-modules", cap))
        if not a_out.strip():
            problems.append(f"{scenario}: authority produced no transcript (exit={a_code})")
        if not c_out.strip():
            problems.append(f"{scenario}: candidate produced no transcript (exit={c_code})")

        a_keys = keyed(a_out)
        c_keys = keyed(c_out)
        a_ns = {f"{scenario}.{k}": v for k, v in a_keys.items()}
        c_ns = {f"{scenario}.{k}": v for k, v in c_keys.items()}
        per_set["authority"].update(a_ns)
        per_set["candidate"].update(c_ns)
        a_obs_total += len(a_keys)
        c_obs_total += len(c_keys)

        if a_keys.get("probe.done") != "1":
            problems.append(f"{scenario}: authority transcript did not complete")
        if c_keys.get("probe.done") != "1":
            problems.append(f"{scenario}: candidate transcript did not complete")
        for key in EVP_DISPATCH_PROBE_SCHEMA:
            if key not in a_keys:
                problems.append(f"{scenario}: authority is missing {key}")
            if key not in c_keys:
                problems.append(f"{scenario}: candidate is missing {key}")

        set_div = residual_rows(a_ns, c_ns)
        for row in set_div:
            row["set"] = scenario
        divergences.extend(set_div)
        sets.append({
            "set": scenario,
            "OPENSSL_ia32cap": cap if cap is not None else "(unset)",
            "authority_exit_code": a_code,
            "candidate_exit_code": c_code,
            "authority_observations": len(a_keys),
            "candidate_observations": len(c_keys),
            "divergence_count": len(set_div),
        })

    # The authority-linked differential control: the authority must have reached its selection
    # surface and the faulted facade must have moved its capability-derived selection. A court
    # whose facade cannot move the authority has not driven the surface. `auth_all` carries every
    # capability set's keys, prefixed by the set name.
    auth_all = per_set["authority"]
    reached = {"authority_default_provider": auth_all.get("host.prov.default.loaded") == "1"}
    controls: list[dict] = []
    facade_moved = bool(EVP_DISPATCH_CONTROLS)
    for key, host_value, faulted_value in EVP_DISPATCH_CONTROLS:
        h = auth_all.get(f"host.{key}")
        f = auth_all.get(f"aesni-off.{key}")
        moved = (h == host_value and f == faulted_value)
        controls.append({"key": key, "host": h, "aesni_off": f,
                         "expected_host": host_value, "expected_aesni_off": faulted_value,
                         "moved": moved})
        facade_moved = facade_moved and moved
    if not facade_moved:
        problems.append(
            "the faulted facade did not move the authority's selection: not every "
            f"AES-*-CBC-HMAC-* control took its host/cleared value ({controls})")
    if not reached["authority_default_provider"]:
        problems.append("authority did not load its default provider")

    candidate_reached = {
        "candidate_default_provider": per_set["candidate"].get("host.prov.default.loaded") == "1",
    }

    # The `AES-*-CBC-HMAC-*` paths, which the facade is expected to move on the authority. Recorded
    # explicitly so the selection movement is visible without reading every residual row.
    hmac_ops = [oid for oid, _ in EVP_CIPHER_OPS if "cbc-hmac" in oid]
    hmac_selection: dict[str, dict[str, str | None]] = {}
    for oid in hmac_ops:
        for path in ("legacy", "fetch", "lookup"):
            hmac_selection[f"{path}.{oid}.null"] = {
                "host": auth_all.get(f"host.{path}.{oid}.null"),
                "aesni_off": auth_all.get(f"aesni-off.{path}.{oid}.null"),
            }

    staged: dict[str, str] = {}
    STAGED.mkdir(parents=True, exist_ok=True)
    for side, srcbin in (("authority", auth_bin), ("candidate", cand_bin)):
        dst = STAGED / f"{src.stem}.{side}"
        if srcbin.is_file():
            shutil.copyfile(srcbin, dst)
            dst.chmod(0o755)
            staged[side] = rel(dst)

    verdict = "pass" if not problems else "fail"

    return {
        "court": name,
        "probe": rel(src),
        "method": (
            "the probe is compiled twice and its `key=value` transcript compared. It reports, for "
            "a fixed operation set, which implementation each path selects -- the legacy "
            "constructor, the provider fetch, the legacy name lookup and the cipher/digest "
            "context -- as the selected method's name/NID/type/flags/sizes and, for a fetch, its "
            "provider name. It is driven under three fixed capability sets via the "
            "`OPENSSL_ia32cap` facade (the host set, an AES-NI-cleared set and a fully cleared "
            "set), exactly as `RT-CPU-CAPABILITY`. The authority probe links its static "
            "`libcrypto.a`; the candidate probe links its distribution shell. No address, clock "
            "or duration is observed."),
        "capability_sets": sets,
        "observations_recorded": {"authority": a_obs_total, "candidate": c_obs_total},
        "authority_observations": a_obs_total,
        "candidate_observations": c_obs_total,
        "reached": {"authority": reached, "candidate": candidate_reached},
        "control": {
            "authority_selection_driven": auth_all.get("host.prov.default.loaded") == "1",
            "controls": controls,
            "facade_moved_selection": facade_moved,
            "aes_cbc_hmac_selection": hmac_selection,
        },
        "divergences": divergences,
        "divergence_count": len(divergences),
        "problems": problems,
        "verdict": verdict,
        "staged_binaries": staged,
        "candidate_stderr_tail": c_err.splitlines()[-3:],
    }


COURT_IMPL = {
    CPU_CAPABILITY: cpu_capability_court,
    EVP_DISPATCH: evp_dispatch_court,
}


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    args = ap.parse_args(argv)
    del args

    auth = resolve_authority(PRODUCTION_AUTHORITY)
    work = REPO_ROOT / "court" / "phase19"
    work.mkdir(parents=True, exist_ok=True)

    records: list[dict] = []
    for name, filename in COURTS:
        src = PROBE_DIR / filename
        if not src.is_file():
            records.append({"court": name, "verdict": "fail",
                            "stage": "probe-missing", "detail": rel(src)})
            continue
        records.append(COURT_IMPL[name](name, src, auth, work))

    passed = sum(1 for r in records if r["verdict"] == "pass")
    failed = sum(1 for r in records if r["verdict"] == "fail")
    body = {
        "all_pass": failed == 0 and len(records) == len(COURTS),
        "authority": auth.id,
        "courts": records,
        "summary": {"total": len(records), "pass": passed, "fail": failed},
        "pending_courts": PENDING_COURTS,
        "claim": (
            "`RT-CPU-CAPABILITY` is 19.1's court: it compiles "
            "courts/phase19/rt_cpu_capability_probe.c twice (authority and candidate) and reports "
            "the CPU-capability surface deterministically -- `OPENSSL_ia32cap_P[0..3]`, the effect "
            "of `OPENSSL_cpuid_setup`, the raw vector `OPENSSL_ia32_cpuid` returns, and the "
            "capability-derived selection observable through the public API "
            "(`OpenSSL_version(OPENSSL_CPU_INFO)`, `OPENSSL_info(OPENSSL_INFO_CPU_SETTINGS)` and "
            "the four `EVP_aes_*_cbc_hmac_sha*` constructors, which answer NULL when "
            "`AESNI_CAPABLE` is clear). The probe is driven under three fixed capability sets via "
            "the `OPENSSL_ia32cap` facade: the host set, an AES-NI-cleared set and a fully cleared "
            "set. The three capability names are declared weak because `OPENSSL_ia32cap_P` is "
            "`.hidden` and `OPENSSL_cpuid_setup`/`OPENSSL_ia32_cpuid` live only in the static "
            "archive: the authority probe links its static `libcrypto.a` with `-Wl,-u,` forcing so "
            "the surface is reached, and the candidate provides none of the three, so it answers "
            "`probe.reachable.*=0` -- the `symbols_not_reached` census the plan records -- and its "
            "CPU-dispatch string is `CPUINFO: N/A` with `OPENSSL_info(1008)` NULL. That disposition "
            "and every other candidate-vs-authority difference is *recorded* in the court's "
            "`divergences` block, not failed: the reduced engine deliberately does not model "
            "`OPENSSL_ia32cap` masking, so under a cleared facade the authority's selection moves "
            "to the non-AES-NI arm and the candidate's does not. The court is `pass` when the "
            "authority's capability surface was actually driven, the faulted facade moved the "
            "authority's selection, both transcripts are complete under every set, and every "
            "divergence was recorded -- NOT when nothing diverged. It is a bounded audit of the "
            "capability surface at the sets it drives, not a parity claim and not an "
            "assembly-versus-Rust equivalence claim (sections 3.4 and 3.6). "
            "`RT-EVP-DISPATCH` is 19.2's court: it compiles "
            "courts/phase19/rt_evp_dispatch_probe.c twice and reports, for a fixed operation set "
            "(AES-128/256-CBC/GCM, ChaCha20-Poly1305, SHA-1/256 and the four "
            "`EVP_aes_*_cbc_hmac_sha*` constructors), which implementation each path selects -- "
            "the legacy constructor, the provider fetch, the legacy name lookup and the "
            "cipher/digest context -- as the selected method's name/NID/type/flags/sizes and, for "
            "a fetch, its provider name, under the same three fixed capability sets. The "
            "authority's default provider filters its `AES-*-CBC-HMAC-*` rows through "
            "`ossl_cipher_capable_aes_cbc_hmac_sha*` (`AESNI_CBC_HMAC_SHA_CAPABLE`), so masking "
            "the AES-NI bit makes those fetch/legacy/lookup paths answer NULL and moves the "
            "authority's selection; the candidate reads CPUID directly and does not model the "
            "mask, so its selection does not move. Every candidate-vs-authority difference is "
            "recorded in the court's `divergences` block. The court is `pass` when the "
            "authority's selection surface was driven, the faulted facade moved it, both "
            "transcripts are complete under every set, and every divergence was recorded -- NOT "
            "when nothing diverged. It is a bounded comparison of *selection* over the sets it "
            "drives, not a parity claim and not an assembly-versus-Rust equivalence claim "
            "(sections 3.4 and 3.6); the engine path is not driven because no engine is "
            "configured and the reduced engine does not export the enumeration it would need. "
            "`RT-PERFORMANCE-WORK` is 19.3's, `RT-PERFORMANCE-SENSITIVITY` 19.4's and "
            "`PERFORMANCE-BOUNDARY-REGISTER` 19.5's; those three are `pending` with the subphase "
            "that lands their instrument. This stratum owns "
            "no exported symbol, so no differential probe over a symbol set is its evidence: the "
            "subject is dispatch behaviour and deterministic work over a finished implementation, "
            "with no benchmark-parity claim and no assembly-versus-Rust equivalence claim. "
            "docs/PHASE-19-SUBPHASES.md sections 1, 3 and 4 record the measurement and the courts."
        ),
    }

    inputs = [
        InputRef(name="phase-19-plan", path=PLAN),
        InputRef(name="cpu-capability-probe", path=PROBE_DIR / "rt_cpu_capability_probe.c"),
        InputRef(name="evp-dispatch-probe", path=PROBE_DIR / "rt_evp_dispatch_probe.c"),
    ]
    doc = envelope(kind="phase19-courts", authority=auth.id, inputs=inputs,
                   body=body, generator=GENERATOR)
    write_json(OUT, doc)

    for r in records:
        if r["verdict"] == "pass" and r["court"] == CPU_CAPABILITY:
            c = r["control"]
            print(f"  {r['court']:<32} pass   ({r['authority_observations']} observations x "
                  f"{len(r['capability_sets'])} sets, {r['divergence_count']} recorded "
                  f"divergence(s), authority reached={c['authority_surface_reached']}, "
                  f"facade {c['facade_host']}->{c['facade_aesni_off']})")
        elif r["verdict"] == "pass" and r["court"] == EVP_DISPATCH:
            c = r["control"]
            print(f"  {r['court']:<32} pass   ({r['authority_observations']} observations x "
                  f"{len(r['capability_sets'])} sets, {r['divergence_count']} recorded "
                  f"divergence(s), authority selection driven="
                  f"{c['authority_selection_driven']}, facade moved={c['facade_moved_selection']})")
        elif r["verdict"] != "pass":
            print(f"  {r['court']:<32} FAIL   stage={r.get('stage', 'compare')}")
            for p in (r.get("detail") if isinstance(r.get("detail"), list)
                      else r.get("problems", []))[:12]:
                print(f"      {p}")
    for cname, needs in PENDING_COURTS.items():
        print(f"  {cname:<32} PENDING (not registered as passing) -- {needs}")
    print(f"  -> {rel(OUT)} all_pass={body['all_pass']} over {len(records)} court(s)")
    return 0 if body["all_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
