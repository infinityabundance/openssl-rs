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
CPU-capability surface deterministically — `OPENSSL_ia32cap_P[0..3]`, the synthetic words
`cap.synthetic.pair`/`.word.4`/`.word.5` the fixed literal's override derives, whether
`OPENSSL_cpuid_setup` and `OPENSSL_ia32_cpuid` were reachable and callable, and the
capability-derived selection observable through the public API (`OpenSSL_version(OPENSSL_CPU_INFO)`,
`OPENSSL_info(OPENSSL_INFO_CPU_SETTINGS)` and the four `EVP_aes_*_cbc_hmac_sha*` constructors, which
answer NULL when `AESNI_CAPABLE` is clear) — as `key=value` observations with no address, clock or
duration. The raw vector `OPENSSL_ia32_cpuid` returns is deliberately not recorded: it is the
runner's own CPUID and would make the record machine-specific (D213's class). The first version
printed it (`probe.cpuid.ret`, `cap.raw.word.2/3`); those host readouts are replaced one-for-one by
the three portable observations of the *synthetic* vector the facade derives, so no coverage is lost
and the transcript stays byte-reproducible on any runner.

The three names are declared `weak`: `OPENSSL_ia32cap_P` is `.hidden` and `OPENSSL_cpuid_setup` /
`OPENSSL_ia32_cpuid` live only in the static archive, so a side that does not provide them answers
`probe.reachable.*=0` instead of failing to link. The authority's static archive provides all three;
**the candidate provides none of them** — this is the `symbols_not_reached` census
`docs/PHASE-19-SUBPHASES.md` section 4.2 records, and the court records it honestly (the candidate's
CPU-dispatch string is `CPUINFO: N/A` and `OPENSSL_info(1008)` is NULL) rather than substituting an
answer. Because a dynamic link never resolves the hidden symbol, the court links the authority
against `libcrypto.a` with `-Wl,-u,` forcing and the candidate against its distribution shell.

The *fixed CPUID facade* is the `OPENSSL_ia32cap` environment variable: the authority's
`OPENSSL_cpuid_setup` reads it in the ELF `.init` constructor and sets the capability vector from
it, so the court fixes the capability set by running the probe under a chosen value. The probe is
driven under three fixed literals — a synthetic *reference* vector, that vector with the AES-NI bit
cleared and zero — so the authority reports the same fictional CPU on any runner, never the capture
host's; the authority's selection still moves with the facade while the candidate's does not (it
reads CPUID directly). Every candidate-vs-authority difference is *recorded* in the court's
`divergences` block, not failed: the reduced engine deliberately does not model `OPENSSL_ia32cap`
masking (`src/provider/cipher.rs`).
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

`RT-PERFORMANCE-WORK`, and what it drives
----------------------------------------
19.3's court. Its instrument is `courts/phase19/rt_performance_work_probe.c`, compiled twice
against the same two sides, and it reports the *deterministic work* a fixed operation set performs
-- not wall-clock, which on a shared host is not reproducible and would make the verdict a function
of the machine (section 3.3). The library exposes no total instruction or block counter, so the
instrument is two deterministic measures and the court says which is which:

  * a **counting `CRYPTO` allocator** the stratum introduces (`CRYPTO_set_mem_functions`, called
    before the library's first allocation). It observes the number of `malloc`/`realloc`
    operations and the total bytes the library requests while a fixed primitive runs -- a
    deterministic instruction-path proxy for the library's own memory work. It changes no library
    behaviour: the shims forward to the default allocator.
  * a **method-derived work vector**: the input bytes, the primitive blocks the fixed input implies
    (`ceil(in / block_size)` for a cipher, `ceil((in + 9) / block_size)` for a digest, the
    field/modulus degree for EC/RSA), the output bytes and the AEAD tag length, read from the
    method's public geometry. `calls` is the probe's own invocation count (driver-side), recorded
    as the denominator and never a finding.

The fixed operation set is AES-128/256-CBC, AES-128/256-GCM, ChaCha20-Poly1305, SHA-256, a P-256
scalar multiplication and an RSA-1024 private decrypt. Every path whose *library-side* work vector
differs from the authority's is a **finding** -- a divisor-of-work difference -- recorded, never
failed; the verdict is `pass` when the surface was driven (the authority installed the counting
hook and the paths ran), both transcripts are complete, every schema key is present on both sides,
and every divergence was recorded -- **not** when nothing diverged. A path the probe cannot drive
is named `pending` rather than counted as passing. The counting allocator observes heap operations,
not total CPU instructions, and the block counts are input-implied: the court makes **no
benchmark-parity claim** and **no assembly-versus-Rust equivalence claim** (sections 3.1, 3.6).

`RT-PERFORMANCE-SENSITIVITY`, and what it drives
---------------------------------------------
19.4's court. It is **candidate-only** — the deliberately slowed variant is a construction of the
harness, never product code, so there is no authority counterpart to drive — in the shape Phase
8's `CT-*` courts and Phase 18's `CT-PRIMITIVES` use (D13, D201). Its instrument is
`courts/phase19/rt_performance_sensitivity_probe.c`, compiled once against the candidate
distribution shell, and it drives two arms under exactly the 19.3 work instrument (the counting
`CRYPTO` allocator the stratum introduces, plus the method-derived geometry): a **reference** arm,
the real `aes-128-cbc` path, and a **slowed** arm (`control-extra-pass`), the same path with an
injected extra full pass over the primitive. Section 3.2's rule is mechanical here — a control that
cannot fail is not evidence — so the verdict is `pass` only when the slowed arm is caught, and the
catch must be on the work counter the stratum introduces (a library-side `allocs`/`reallocs`/`bytes`
difference), not merely on the driver-side `calls` that 19.3 excludes from its findings. The
reference arm is anchored to the authority: the court requires its work vector to equal the
authority's `aes-128-cbc` vector the 19.3 court already recorded, so a reference that is the real
path is distinguished from a broken instrument's answer. The verdict is about the *instrument's
resolution* and makes no throughput or benchmark-parity claim (sections 3.2 and 3.6); if the
instrument cannot be made to catch the slowed variant the court is `fail`, never a vacuous `pass`.

`PERFORMANCE-BOUNDARY-REGISTER`, and what it binds
-------------------------------------------------
19.5's court, and the stratum's own non-claims. It stages no probe: its subject is
`artifacts/phase19/performance-boundary-register.json`, the authored register that records, per
surface, whether it is *measured* (a passing court covers it), *not-measured* (a surface this
stratum names but no court reaches, so it is named `pending` rather than counted as passing) or
*not-claimed* (explicitly outside this stratum -- including benchmark parity and
assembly-versus-Rust equivalence). The court re-reads the live courts registry -- the four probe
courts above, computed ahead of it in the same run -- and fails the stratum if a `measured` row's
court no longer covers its surface, a `not-measured`/`not-claimed` row a passing court now covers,
or a stated count/evidence value has moved. A surface the courts do not reach is `not-measured` or
`not-claimed`, never `measured`; the register may not claim more than the courts above measured
(docs/PHASE-19-SUBPHASES.md sections 3.1, 3.5 and 3.6).

There is no benchmark-parity claim and no assembly-versus-Rust equivalence claim anywhere in this
stratum, and no verdict is ever taken from wall-clock time alone.

The runner reads no obligations ledger: the ledger's contract-unit states are measured from this
registry, so the edge runs ledger -> courts and binding it back would form a digest cycle neither
artefact could reproduce. `docs/PHASE-19-SUBPHASES.md` section 4.2 is the precondition. No court is
registered in `gen_frf_courts.py`: that registry is the stratum's seal.

SPDX-License-Identifier: Apache-2.0"""

from __future__ import annotations

import argparse
import json
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
    sha256_file,
    write_json,
)

OUT = REPO_ROOT / "artifacts" / "phase19" / "COURTS.json"
GENERATOR = "forensics/tools/phase19_courts.py"
PLAN = REPO_ROOT / "docs" / "PHASE-19-SUBPHASES.md"
PROBE_DIR = REPO_ROOT / "courts" / "phase19"
STAGED = REPO_ROOT / "artifacts" / "phase19" / "probes"
PHASE2 = REPO_ROOT / "artifacts" / "phase2"
RUN_TIMEOUT_S = "120"

REGISTER = REPO_ROOT / "artifacts" / "phase19" / "performance-boundary-register.json"
REGISTER_SCHEMA = "openssl-rs/performance-boundary-register/v1"

# The courts, in the order they land. `(name, probe filename or None)`, and the probe is declared
# in the same commit as the entry, so a runner that names a probe which does not exist cannot be
# committed. The register court has no probe: its subject is the authored register, and it reads
# the four probe courts' records computed ahead of it in the same run.
CPU_CAPABILITY = "RT-CPU-CAPABILITY"
EVP_DISPATCH = "RT-EVP-DISPATCH"
PERFORMANCE_WORK = "RT-PERFORMANCE-WORK"
PERFORMANCE_SENSITIVITY = "RT-PERFORMANCE-SENSITIVITY"
REGISTER_COURT = "PERFORMANCE-BOUNDARY-REGISTER"
COURTS: list[tuple[str, str | None]] = [
    (CPU_CAPABILITY, "rt_cpu_capability_probe.c"),
    (EVP_DISPATCH, "rt_evp_dispatch_probe.c"),
    (PERFORMANCE_WORK, "rt_performance_work_probe.c"),
    (PERFORMANCE_SENSITIVITY, "rt_performance_sensitivity_probe.c"),
    (REGISTER_COURT, None),
]

# The classifications the register may use. `measured` is a passing court that covers the surface;
# `not-measured` is a surface this stratum names but no court reaches (a `pending` name);
# `not-claimed` is explicitly outside the stratum. A surface the courts do not reach is never
# `measured`.
REGISTER_CLASSIFICATIONS = ("measured", "not-measured", "not-claimed")

# A court the plan names and this stratum cannot run yet. Empty since 19.5 landed the register;
# kept as the stated-distance mechanism, so a court the plan names but the runner cannot run is
# recorded here rather than quietly dropped.
PENDING_COURTS: dict[str, str] = {}

# The fixed capability sets the capability probe is driven under, as `(set name, OPENSSL_ia32cap
# value)` pairs. Every value is an explicit fixed literal -- never `None` (the capture host's own
# CPU) and never a `~` mask over it -- so the file the court records is identical on any runner.
# A literal with no leading `~` and no `:` is an *override*: `OPENSSL_cpuid_setup` sets
# `OPENSSL_ia32cap_P[0]`/`[1]` from its low/high 32-bit halves and zeroizes `[2..9]`, so the
# reported vector is this synthetic CPU and not the runner's. `OPENSSL_ia32cap_P[1] & (1 << 25)`
# is `AESNI_CAPABLE`, i.e. bit 25 of the high 32-bit half of the literal. `reference` sets AES-NI
# and SSE3 (bit 0 of word[1]); `aesni-off` clears exactly the AES-NI bit and so stays distinct
# from `cleared`, which is zero.
REFERENCE_IA32CAP = "0x0200000100000000"
AESNI_OFF_IA32CAP = "0x0000000100000000"
CLEARED_IA32CAP = "0x0000000000000000"
CAPABILITY_SETS: list[tuple[str, str]] = [
    ("reference", REFERENCE_IA32CAP),
    ("aesni-off", AESNI_OFF_IA32CAP),
    ("cleared", CLEARED_IA32CAP),
]

# The capability-derived selection the facade must move on the authority, as the section-3.2
# authority-linked differential control: `sel.aes128cbcsha1.null` is 0 under the reference set and
# 1 under the AES-NI-cleared set. The facade's job is to drive *the authority's* selection; a
# court whose facade cannot move it has not driven the surface.
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
    "cap.word.0",
    "cap.word.1",
    "cap.word.2",
    "cap.word.3",
    "cap.after_setup.0",
    "cap.after_setup.1",
    "cap.after_setup.2",
    "cap.after_setup.3",
    "cap.synthetic.pair",
    "cap.synthetic.word.4",
    "cap.synthetic.word.5",
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


# The capability sets `RT-EVP-DISPATCH` drives the selection probe under, shared with 19.1: a
# synthetic reference set, an AES-NI-cleared set (the fixed `OPENSSL_ia32cap` literal clears bit 25
# of the high word) and a fully cleared set. The authority's provider capability filter and its
# legacy `AESNI_CAPABLE` predicate both read the fixed vector, so its `AES-*-CBC-HMAC-*` selection
# moves with the facade; the candidate reads CPUID directly and does not.
#
# `EVP_DISPATCH_CONTROLS` is the section-3.2 authority-linked differential control: each row is
# `(key, reference-value, aesni-off-value)`. The authority's selection must take the reference
# value under the reference set and the cleared value under the faulted set, or the facade did not
# drive it.
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


# --------------------------------------------------------------------------------------------
# `RT-PERFORMANCE-WORK` (19.3): the deterministic work court. The path ids and per-path fields are
# the key fragments `courts/phase19/rt_performance_work_probe.c` prints, and the schema below is
# built from the same lists, so a path or field added to the probe without the schema is caught as a
# missing key rather than compared unobserved.
# --------------------------------------------------------------------------------------------
PERFORMANCE_WORK_PATHS: tuple[str, ...] = (
    "aes-128-cbc",
    "aes-256-cbc",
    "aes-128-gcm",
    "aes-256-gcm",
    "chacha20-poly1305",
    "sha256",
    "ec-p256-mul",
    "rsa-1024-private",
)
# The fields every path emits, in the probe's order. `ran` says whether the path completed; the rest
# are `n/a` when it did not.
WORK_VECTOR_FIELDS: tuple[str, ...] = (
    "ran", "in", "blocks", "calls", "out", "tag", "allocs", "reallocs", "bytes", "ret",
)
# The library-side work keys: a path on which one of these differs from the authority's is a
# divergent-work *finding*. `in` (the probe's fixed input) and `calls` (the probe's own invocation
# count) are driver-side, so they are recorded as the denominator but never make a finding.
WORK_FINDING_KEYS: tuple[str, ...] = (
    "blocks", "out", "tag", "allocs", "reallocs", "bytes", "ret",
)


def performance_work_schema() -> tuple[str, ...]:
    """The fixed transcript schema for `RT-PERFORMANCE-WORK`.

    Both sides emit every key (an unreached path prints `n/a` in every numeric field), so the two
    observation counts agree and `atlas_common.court_observations` holds. The keys are built from
    the same path and field lists the probe's emitters use, so a drift fails closed as a missing
    key rather than passing unobserved.
    """
    keys: list[str] = ["probe.kind", "work.hook.install", "work.default_provider"]
    for path in PERFORMANCE_WORK_PATHS:
        keys += [f"work.{path}.{field}" for field in WORK_VECTOR_FIELDS]
    keys.append("probe.done")
    return tuple(keys)


PERFORMANCE_WORK_PROBE_SCHEMA: tuple[str, ...] = performance_work_schema()


# --------------------------------------------------------------------------------------------
# `RT-PERFORMANCE-SENSITIVITY` (19.4): the instrument-sensitivity control. Candidate-only, so its
# transcript is one side's. The reference arm re-measures the 19.3 `aes-128-cbc` path with the same
# instrument and the court anchors it to the authority's recorded 19.3 vector; the slowed arm is
# `control-extra-pass`, the reference path with an injected extra full pass over the primitive.
# --------------------------------------------------------------------------------------------
SENSITIVITY_REFERENCE = "aes-128-cbc"
SENSITIVITY_CONTROL = "control-extra-pass"
SENSITIVITY_ARMS: tuple[str, ...] = ("reference", "slowed")
# The counting-allocator keys -- the work counter the stratum introduces. The catch must land on at
# least one of these, not merely on the driver-side `calls` 19.3 excludes from its findings: an
# extra pass the counter cannot see is exactly the dead instrument section 3.2 refuses.
SENSITIVITY_COUNTER_KEYS: tuple[str, ...] = ("allocs", "reallocs", "bytes")


def performance_sensitivity_schema() -> tuple[str, ...]:
    """The fixed transcript schema for `RT-PERFORMANCE-SENSITIVITY`.

    One side's transcript (the court is candidate-only) emits every key -- an arm that did not run
    prints `n/a` in every numeric field -- so the schema is closed over the same field list 19.3
    uses.
    """
    keys: list[str] = ["probe.kind", "work.hook.install", "work.default_provider",
                       "sens.reference.id", "sens.slowed.id"]
    for arm in SENSITIVITY_ARMS:
        keys += [f"sens.{arm}.{field}" for field in WORK_VECTOR_FIELDS]
    keys.append("probe.done")
    return tuple(keys)


PERFORMANCE_SENSITIVITY_PROBE_SCHEMA: tuple[str, ...] = performance_sensitivity_schema()


def side_env(libdir: Path, modulesdir: Path, cap: str | None) -> dict[str, str]:
    """The environment one probe run sees on one side.

    `LD_LIBRARY_PATH` fixes the DSO the candidate probe resolves against, `OPENSSL_MODULES` points
    at that side's own `ossl-modules/`, and `OPENSSL_CONF=/dev/null` keeps the host's configuration
    out of a deterministic transcript. `cap`, when given, is the fixed `OPENSSL_ia32cap` facade
    value the authority's `.init` constructor reads; the capability courts always pass one of the
    court's synthetic literals, so the ambient environment is never an input there. `None` removes
    the variable for the courts that do not drive the facade (the work and sensitivity courts).
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
            "OPENSSL_ia32cap": cap,
            "authority_exit_code": a_code,
            "candidate_exit_code": c_code,
            "authority_observations": len(a_keys),
            "candidate_observations": len(c_keys),
            "divergence_count": len(set_div),
        })

    # The authority-linked differential control: the authority must have reached its own
    # capability surface, and the faulted facade must have moved its capability-derived selection.
    reference = per_set["authority"]
    reached = {key: reference.get(f"reference.{key}", "missing") for key in REACHABLE_KEYS}
    if reference.get("reference.probe.reachable.ia32cap_p") != "1":
        problems.append(
            "authority did not reach OPENSSL_ia32cap_P: the capability surface was not driven "
            f"({reached})")
    if reference.get("reference.probe.reachable.cpuid_setup") != "1":
        problems.append("authority did not reach OPENSSL_cpuid_setup")
    if reference.get("reference.probe.reachable.ia32_cpuid") != "1":
        problems.append("authority did not reach OPENSSL_ia32_cpuid")
    facade_reference = reference.get(f"reference.{FACADE_CONTROL_KEY}")
    facade_after = reference.get(f"aesni-off.{FACADE_CONTROL_KEY}")
    facade_ok = (facade_reference == "0" and facade_after == "1")
    if not facade_ok:
        problems.append(
            f"the faulted facade did not move the authority's selection: "
            f"{FACADE_CONTROL_KEY} reference={facade_reference} aesni-off={facade_after}")

    candidate_reached = {key: per_set["candidate"].get(f"reference.{key}", "missing")
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
            "under three fixed capability sets via the `OPENSSL_ia32cap` facade (a synthetic "
            "reference set, an AES-NI-cleared set and a fully cleared set), each an explicit "
            "literal so the recorded vector is never the runner's own CPUID. The raw "
            "`OPENSSL_ia32_cpuid` return is not recorded; the three host readouts the first "
            "version printed are replaced by portable observations of the synthetic vector the "
            "literal derives (`cap.synthetic.pair`/`.word.4`/`.word.5`). The authority probe "
            "links its static `libcrypto.a` with `-Wl,-u,` forcing so the hidden "
            "`OPENSSL_ia32cap_P` and the archive-only `OPENSSL_cpuid_setup` / "
            "`OPENSSL_ia32_cpuid` are reachable; the candidate probe links its distribution "
            "shell, where the weak references resolve to NULL. No address, clock or duration is "
            "observed."),
        "capability_sets": sets,
        "observations_recorded": {"authority": a_obs_total, "candidate": c_obs_total},
        "authority_observations": a_obs_total,
        "candidate_observations": c_obs_total,
        "reached": {"authority": reached, "candidate": candidate_reached},
        "control": {
            "authority_surface_reached": reference.get("reference.probe.reachable.ia32cap_p") == "1",
            "facade_key": FACADE_CONTROL_KEY,
            "facade_reference": facade_reference,
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
            "OPENSSL_ia32cap": cap,
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
    reached = {"authority_default_provider": auth_all.get("reference.prov.default.loaded") == "1"}
    controls: list[dict] = []
    facade_moved = bool(EVP_DISPATCH_CONTROLS)
    for key, reference_value, faulted_value in EVP_DISPATCH_CONTROLS:
        h = auth_all.get(f"reference.{key}")
        f = auth_all.get(f"aesni-off.{key}")
        moved = (h == reference_value and f == faulted_value)
        controls.append({"key": key, "reference": h, "aesni_off": f,
                         "expected_reference": reference_value,
                         "expected_aesni_off": faulted_value,
                         "moved": moved})
        facade_moved = facade_moved and moved
    if not facade_moved:
        problems.append(
            "the faulted facade did not move the authority's selection: not every "
            f"AES-*-CBC-HMAC-* control took its reference/cleared value ({controls})")
    if not reached["authority_default_provider"]:
        problems.append("authority did not load its default provider")

    candidate_reached = {
        "candidate_default_provider": per_set["candidate"].get("reference.prov.default.loaded") == "1",
    }

    # The `AES-*-CBC-HMAC-*` paths, which the facade is expected to move on the authority. Recorded
    # explicitly so the selection movement is visible without reading every residual row.
    hmac_ops = [oid for oid, _ in EVP_CIPHER_OPS if "cbc-hmac" in oid]
    hmac_selection: dict[str, dict[str, str | None]] = {}
    for oid in hmac_ops:
        for path in ("legacy", "fetch", "lookup"):
            hmac_selection[f"{path}.{oid}.null"] = {
                "reference": auth_all.get(f"reference.{path}.{oid}.null"),
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
            "`OPENSSL_ia32cap` facade (a synthetic reference set, an AES-NI-cleared set and a "
            "fully cleared set), exactly as `RT-CPU-CAPABILITY`. The authority probe links its "
            "static `libcrypto.a`; the candidate probe links its distribution shell. No address, "
            "clock or duration is observed."),
        "capability_sets": sets,
        "observations_recorded": {"authority": a_obs_total, "candidate": c_obs_total},
        "authority_observations": a_obs_total,
        "candidate_observations": c_obs_total,
        "reached": {"authority": reached, "candidate": candidate_reached},
        "control": {
            "authority_selection_driven": auth_all.get("reference.prov.default.loaded") == "1",
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


def performance_work_court(name: str, src: Path, auth, work: Path) -> dict:
    """`RT-PERFORMANCE-WORK`: the deterministic work vector over the primitive-bearing paths.

    The verdict is `pass` when the authority actually drove the instrument (it installed the
    counting `CRYPTO` allocator the stratum introduces and at least one named path ran), both
    transcripts are complete, every schema key is present on both sides, and every
    candidate-vs-authority difference was recorded. A path whose library-side work vector differs
    is a **finding** (a divisor-of-work difference) and a path the probe cannot drive is `pending`;
    neither is a failure. It is a bounded differential measurement of deterministic work, not a
    parity claim and not an assembly-versus-Rust equivalence claim (sections 3.1, 3.3 and 3.6), and
    no verdict is taken from wall-clock time.
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
    a_out, a_err, a_code = run_probe(
        auth_bin, side_env(auth.libdir, auth.libdir / "ossl-modules", None))
    c_out, c_err, c_code = run_probe(
        cand_bin, side_env(PHASE2, PHASE2 / "install" / "lib" / "ossl-modules", None))
    if not a_out.strip():
        problems.append(f"authority produced no transcript (exit={a_code})")
    if not c_out.strip():
        problems.append(f"candidate produced no transcript (exit={c_code})")

    a_keys = keyed(a_out)
    c_keys = keyed(c_out)

    if a_keys.get("probe.done") != "1":
        problems.append("authority transcript did not complete")
    if c_keys.get("probe.done") != "1":
        problems.append("candidate transcript did not complete")
    for key in PERFORMANCE_WORK_PROBE_SCHEMA:
        if key not in a_keys:
            problems.append(f"authority is missing {key}")
        if key not in c_keys:
            problems.append(f"candidate is missing {key}")

    # The authority-linked differential control: the work counter is an instrument the stratum
    # introduces, so the authority must have installed the counting allocator and at least one
    # named path must have run. A court whose hook did not install has nothing to compare.
    hook_install = a_keys.get("work.hook.install") == "1"
    if not hook_install:
        problems.append(
            "authority did not install the counting hook "
            f"(work.hook.install={a_keys.get('work.hook.install')}): the work instrument was not "
            "driven")

    paths: list[dict] = []
    findings: list[str] = []
    pending: list[str] = []
    a_ran = 0
    c_ran = 0
    for path in PERFORMANCE_WORK_PATHS:
        a_vals = {f: a_keys.get(f"work.{path}.{f}") for f in WORK_VECTOR_FIELDS}
        c_vals = {f: c_keys.get(f"work.{path}.{f}") for f in WORK_VECTOR_FIELDS}
        if a_vals["ran"] == "1":
            a_ran += 1
        if c_vals["ran"] == "1":
            c_ran += 1
        if a_vals["ran"] != "1":
            pending.append(path)
        diffs = {f: (a_vals[f], c_vals[f]) for f in WORK_FINDING_KEYS
                 if a_vals[f] != c_vals[f]}
        if a_vals["ran"] == "1" and c_vals["ran"] == "1" and diffs:
            findings.append(
                f"{path}: deterministic work differs ("
                + "; ".join(f"{f} authority={av} candidate={cv}"
                             for f, (av, cv) in diffs.items()) + ")")
        paths.append({"path": path, "authority": a_vals, "candidate": c_vals,
                      "divergent_work_keys": sorted(diffs)})

    if hook_install and a_ran == 0:
        problems.append("authority installed the hook but no named path ran")

    divergences = residual_rows(a_keys, c_keys)

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
            "a fixed operation set (AES-128/256-CBC/GCM, ChaCha20-Poly1305, SHA-256, a P-256 "
            "scalar multiplication and an RSA-1024 private decrypt), a deterministic work vector "
            "per path: a counting `CRYPTO` allocator's malloc/realloc/byte counts (the "
            "instruction-path proxy the stratum introduces), plus the method-derived "
            "input/blocks/output/tag sizes. No address, clock or duration is observed. A path "
            "whose library-side work vector differs is recorded as a finding, not failed."),
        "operation_set": list(PERFORMANCE_WORK_PATHS),
        "work_fields": list(WORK_VECTOR_FIELDS),
        "finding_keys": list(WORK_FINDING_KEYS),
        "observations_recorded": {"authority": len(a_keys), "candidate": len(c_keys)},
        "authority_observations": len(a_keys),
        "candidate_observations": len(c_keys),
        "paths": paths,
        "control": {
            "authority_hook_installed": hook_install,
            "candidate_hook_installed": c_keys.get("work.hook.install") == "1",
            "authority_paths_ran": a_ran,
            "candidate_paths_ran": c_ran,
            "total_paths": len(PERFORMANCE_WORK_PATHS),
        },
        "divergences": divergences,
        "divergence_count": len(divergences),
        "findings": findings,
        "findings_count": len(findings),
        "pending_paths": pending,
        "problems": problems,
        "verdict": verdict,
        "staged_binaries": staged,
        "candidate_stderr_tail": c_err.splitlines()[-3:],
    }


COURT_IMPL = {
    CPU_CAPABILITY: cpu_capability_court,
    EVP_DISPATCH: evp_dispatch_court,
    PERFORMANCE_WORK: performance_work_court,
}


def performance_sensitivity_court(name: str, src: Path, auth, work: Path,
                                 work_row: dict) -> dict:
    """`RT-PERFORMANCE-SENSITIVITY`: the candidate-only instrument-sensitivity control.

    The court is candidate-only -- the deliberately slowed variant is a construction of the probe,
    so there is no authority transcript to diff -- and compiles its probe **once** against the
    candidate distribution shell. It drives two arms under the same 19.3 work instrument: the
    reference (`aes-128-cbc`, the real path) and `control-extra-pass` (the same path with an
    injected extra full pass over the primitive, never product code).

    The verdict follows section 3.2. It is `pass` only when the instrument ran (the counting hook
    installed and both arms completed), the reference arm's work vector **equals the authority's
    `aes-128-cbc` vector 19.3 recorded** (so the reference is the real path rather than a broken
    instrument's answer), and the slowed arm is **caught on the work counter the stratum
    introduces** -- a library-side `allocs`/`reallocs`/`bytes` difference -- not merely on the
    driver-side `calls` 19.3 excludes from its findings. If the instrument cannot tell the slowed
    path from the reference, the court is `fail`: a control that cannot fail is not evidence. The
    verdict is about the instrument's resolution and makes no throughput or benchmark-parity claim.
    """
    del auth  # candidate-only: the slowed variant is a harness construction, not a library path

    cand_bin = work / f"{src.stem}.candidate"
    ok, err = compile_candidate(src, cand_bin)
    if not ok:
        return {"court": name, "verdict": "fail", "stage": "compile-candidate",
                "detail": err.splitlines()[:12]}

    c_out, c_err, c_code = run_probe(
        cand_bin, side_env(PHASE2, PHASE2 / "install" / "lib" / "ossl-modules", None))
    if not c_out.strip():
        return {"court": name, "verdict": "fail", "stage": "candidate-run",
                "detail": {"exit_code": c_code, "stderr": c_err.splitlines()[:12]}}

    c_keys = keyed(c_out)
    problems: list[str] = []

    if c_keys.get("probe.done") != "1":
        problems.append("candidate transcript did not complete")
    for key in PERFORMANCE_SENSITIVITY_PROBE_SCHEMA:
        if key not in c_keys:
            problems.append(f"candidate is missing {key}")

    # The authority anchor: the reference arm must reproduce the vector the 19.3 court recorded for
    # `aes-128-cbc` on the authority, so the reference is the real measured path and not a broken
    # instrument's constant. The full vector is compared, including the driver-side `in`/`calls`
    # (the same driver over the same fixed input).
    authority_ref: dict[str, str | None] = {}
    for p in (work_row.get("paths") or []):
        if p.get("path") == SENSITIVITY_REFERENCE:
            authority_ref = dict(p.get("authority") or {})
            break

    def arm(which: str) -> dict[str, str | None]:
        return {f: c_keys.get(f"sens.{which}.{f}") for f in WORK_VECTOR_FIELDS}

    reference = arm("reference")
    slowed = arm("slowed")

    if not authority_ref:
        problems.append(
            f"the authority's {SENSITIVITY_REFERENCE} work vector was not available from "
            "`RT-PERFORMANCE-WORK`: the reference arm cannot be anchored")
    else:
        mismatched = {f: (authority_ref.get(f), reference.get(f)) for f in WORK_VECTOR_FIELDS
                      if authority_ref.get(f) != reference.get(f)}
        if mismatched:
            problems.append(
                f"the reference arm does not match the authority's {SENSITIVITY_REFERENCE} work "
                "vector: " + "; ".join(f"{f} authority={av} reference={rv}"
                                        for f, (av, rv) in sorted(mismatched.items())))

    if reference.get("ran") != "1":
        problems.append("the reference arm did not run")
    if slowed.get("ran") != "1":
        problems.append("the slowed arm did not run")

    # The instrument-sensitivity control: the slowed variant must differ from the reference on a
    # library-side work key in general, and on the counting allocator (the work counter the stratum
    # introduces) specifically. `calls` is driver-side -- a slowed path the counter cannot see,
    # differing only in `calls`, is exactly the dead instrument this court refuses to pass.
    diffs = {f: (reference.get(f), slowed.get(f)) for f in WORK_FINDING_KEYS
             if reference.get(f) != slowed.get(f)}
    counter_diffs = {f: diffs[f] for f in SENSITIVITY_COUNTER_KEYS if f in diffs}
    caught = bool(diffs)
    counter_caught = bool(counter_diffs)
    calls_differ = reference.get("calls") != slowed.get("calls")
    if not caught:
        problems.append(
            f"the instrument did not catch the deliberately slowed {SENSITIVITY_CONTROL}: its "
            f"work vector equals the reference's ({diffs}): the court is fail, not vacuous pass")
    elif not counter_caught:
        problems.append(
            f"the slowed {SENSITIVITY_CONTROL} moved only non-counter work keys "
            f"({sorted(diffs)}); the counting allocator the stratum introduces did not catch it")

    honest = (not problems) and caught and counter_caught

    staged: dict[str, str] = {}
    STAGED.mkdir(parents=True, exist_ok=True)
    dst = STAGED / f"{src.stem}.candidate"
    if cand_bin.is_file():
        shutil.copyfile(cand_bin, dst)
        dst.chmod(0o755)
        staged["candidate"] = rel(dst)

    verdict = "pass" if not problems else "fail"

    return {
        "court": name,
        "probe": rel(src),
        "candidate_only": True,
        "frf_declarable": False,
        "frf_exclusion": (
            "candidate-only instrument-sensitivity control: the deliberately slowed variant is a "
            "construction of the harness, so there is no authority transcript to diff and no "
            "artifacts/phase19/probes/<probe>.authority pair to stage, and the probe is compiled "
            "once against the candidate distribution shell (D13, D201)"),
        "method": (
            "candidate-only; the probe is compiled once against the candidate distribution shell "
            "and drives two arms under the same 19.3 work instrument (the counting `CRYPTO` "
            "allocator the stratum introduces plus the method-derived geometry): a reference arm, "
            "the real `aes-128-cbc` path, and a slowed arm, the same path with an injected extra "
            "full pass over the primitive. The reference must equal the authority's `aes-128-cbc` "
            "vector the 19.3 court recorded and the slowed arm must be caught on a library-side "
            "counter key. No address, clock or duration is observed. The verdict is about the "
            "instrument's resolution: it makes no throughput or benchmark-parity claim."),
        "reference": reference,
        "slowed": slowed,
        "authority_reference": authority_ref,
        "control": {
            "path": SENSITIVITY_CONTROL,
            "what": (
                "the reference `aes-128-cbc` path with an injected extra full pass over the "
                "primitive inside the measured region -- extra library work constructed in the "
                "harness, never product code -- so the counting allocator must register it"),
            "reference": SENSITIVITY_REFERENCE,
            "caught": caught,
            "counter_caught": counter_caught,
            "counter_keys": list(SENSITIVITY_COUNTER_KEYS),
            "library_side_keys_differing": sorted(diffs),
            "counter_keys_differing": sorted(counter_diffs),
            "driver_side_calls_differ": calls_differ,
            "honest": honest,
        },
        "observations_recorded": {"candidate": len(c_keys)},
        "candidate_exit_code": c_code,
        "problems": problems,
        "verdict": verdict,
        "staged_binaries": staged,
        "candidate_stderr_tail": c_err.splitlines()[-3:],
    }


# ---------------------------------------------------------------------------
# `PERFORMANCE-BOUNDARY-REGISTER` -- the stratum's own non-claims, bound to the courts
# ---------------------------------------------------------------------------

# 19.3's work court drives a fixed path set; a path is the register's `work.agree.*` surface when
# its library-side work vector equals the authority's and its `work.diverge.*` surface when it
# differs. The split is derived from the court row, so a path moving between the two becomes a key
# the register no longer covers rather than a silent re-labelling.
def _work_agreeing(record: dict) -> list[str]:
    return sorted(
        p["path"] for p in (record.get("paths") or [])
        if not p.get("divergent_work_keys") and (p.get("authority") or {}).get("ran") == "1"
    )


def _work_divergent(record: dict) -> list[str]:
    return sorted(
        p["path"] for p in (record.get("paths") or [])
        if p.get("divergent_work_keys")
    )


def court_coverage(record: dict) -> set[str]:
    """The surface keys a court covers, from its own record -- and only when it passed.

    A non-`pass` court covers nothing: its row is still in the registry but no surface may lean on
    it. That is what makes "a row marked measured whose court no longer covers it" detectable --
    the coverage set for that court goes empty (or loses the key).
    """
    if record.get("verdict") != "pass":
        return set()
    court = record.get("court")
    if court == CPU_CAPABILITY:
        keys: set[str] = set()
        reached = (record.get("reached") or {}).get("authority") or {}
        for key in REACHABLE_KEYS:
            if key in reached:
                keys.add("cpu.reach." + key.rsplit(".", 1)[-1])
        if (record.get("control") or {}).get("facade_moved_selection"):
            keys.add("cpu.masking")
        return keys
    if court == EVP_DISPATCH:
        keys = set()
        sets = record.get("capability_sets") or []
        reference = next((s for s in sets if s.get("set") == "reference"), None)
        if reference is not None and reference.get("divergence_count") == 0:
            keys.add("evp.reference")
        if any(s.get("divergence_count", 0) > 0 for s in sets if s.get("set") != "reference"):
            keys.add("evp.masked")
        return keys
    if court == PERFORMANCE_WORK:
        keys = set()
        for path in _work_agreeing(record):
            keys.add("work.agree." + path)
        for path in _work_divergent(record):
            keys.add("work.diverge." + path)
        return keys
    if court == PERFORMANCE_SENSITIVITY:
        if (record.get("control") or {}).get("honest"):
            return {"sens.control"}
        return set()
    return set()


def register_evidence(record: dict) -> dict:
    """The court record's classification evidence, as the flat vocabulary the register cites.

    The register's `evidence` block is a dict of `{key: expected}` over this view, and the court
    compares them exactly, so a stated count or evidence value that moves is a failure rather than
    a register that silently describes the previous generation.
    """
    court = record.get("court")
    ev: dict = {"verdict": record.get("verdict")}
    if court == CPU_CAPABILITY:
        reached = record.get("reached") or {}
        ev["authority_reached"] = reached.get("authority") or {}
        ev["candidate_reached"] = reached.get("candidate") or {}
        ev["divergence_count"] = record.get("divergence_count")
        ctrl = record.get("control") or {}
        ev["facade_reference"] = ctrl.get("facade_reference")
        ev["facade_aesni_off"] = ctrl.get("facade_aesni_off")
        ev["facade_moved_selection"] = ctrl.get("facade_moved_selection")
    elif court == EVP_DISPATCH:
        sets = record.get("capability_sets") or []
        ev["reference_divergence_count"] = next(
            (s.get("divergence_count") for s in sets if s.get("set") == "reference"), None)
        ev["masked_sets"] = sorted(s.get("set") for s in sets if s.get("set") != "reference")
        ev["masked_divergence_count"] = {
            s.get("set"): s.get("divergence_count")
            for s in sets if s.get("set") != "reference"
        }
    elif court == PERFORMANCE_WORK:
        ev["findings"] = sorted(str(f) for f in record.get("findings") or [])
        ev["findings_count"] = record.get("findings_count")
        ev["divergent_paths"] = _work_divergent(record)
        ev["agreeing_paths"] = _work_agreeing(record)
        ev["pending_paths"] = sorted(record.get("pending_paths") or [])
    elif court == PERFORMANCE_SENSITIVITY:
        ctrl = record.get("control") or {}
        ev["caught"] = ctrl.get("caught")
        ev["counter_caught"] = ctrl.get("counter_caught")
        ev["counter_keys_differing"] = sorted(ctrl.get("counter_keys_differing") or [])
        ev["reference"] = ctrl.get("reference")
    return ev


def verify_register_surface(row: dict, registry: dict[str, dict], coverage: dict[str, set[str]],
                            covered_any: set[str]) -> list[str]:
    """Every way one register row drifts from the courts it cites.

    The three named drift classes are checks here: a `measured` row whose court no longer covers
    its surface (the `not_covered` clause and the `verdict` clause), a `not-measured`/`not-claimed`
    row a passing court now covers (the `covered_any` clause), and a stated count/evidence value
    that moved (the `evidence` equality, plus the declared-count check in `register_court`).
    """
    problems: list[str] = []
    sid = row.get("id", "<unnamed>")
    cls = row.get("classification")
    keys = row.get("surface_keys") or []
    court = row.get("court")
    if cls not in REGISTER_CLASSIFICATIONS:
        problems.append(f"{sid}: classification {cls!r} is not one of "
                        f"{list(REGISTER_CLASSIFICATIONS)}")
        return problems
    if cls != "measured":
        if court is not None:
            problems.append(f"{sid}: a {cls} row must name no court (got {court!r})")
        for k in keys:
            if k in covered_any:
                problems.append(
                    f"{sid}: recorded {cls} but a passing court now covers {k!r}")
        return problems
    rec = registry.get(court)
    if rec is None:
        problems.append(f"{sid}: cites court {court!r} which is not registered")
        return problems
    if rec.get("verdict") != "pass":
        problems.append(f"{sid}: recorded {cls} but its court {court} is {rec.get('verdict')}")
    not_covered = sorted(k for k in keys if k not in coverage.get(court, set()))
    if not_covered:
        problems.append(f"{sid}: recorded {cls} but {court} does not cover {not_covered}")
    ev = register_evidence(rec)
    want = row.get("evidence") or {}
    for key, expected in want.items():
        if key not in ev:
            problems.append(f"{sid}: evidence key {key!r} has no value in the {court} record")
        elif ev[key] != expected:
            problems.append(
                f"{sid}: evidence {key} = {expected!r} but {court} shows {ev[key]!r}")
    return problems


def register_court(name: str, records: list[dict]) -> dict:
    """`PERFORMANCE-BOUNDARY-REGISTER`: bind the authored register to the live courts registry.

    Reads the four already-computed probe-court records and the authored register, re-derives each
    court's coverage and each row's expected evidence, and reports every drift. A non-empty
    `problems` is `fail`.
    """
    if not REGISTER.is_file():
        return {"court": name, "probe": "", "verdict": "fail", "stage": "register-missing",
                "frf_declarable": False,
                "frf_exclusion": "the register court re-reads the courts registry; it stages no "
                                  "probe pair",
                "detail": rel(REGISTER)}
    doc = json.loads(REGISTER.read_text(encoding="utf-8"))
    problems: list[str] = []
    if doc.get("schema") != REGISTER_SCHEMA:
        problems.append(f"schema {doc.get('schema')!r} != {REGISTER_SCHEMA!r}")
    surfaces = doc.get("surfaces") or []
    registry = {r.get("court"): r for r in records}
    coverage = {r.get("court"): court_coverage(r) for r in records}
    covered_any: set[str] = set()
    for keys in coverage.values():
        covered_any |= keys
    for row in surfaces:
        problems += verify_register_surface(row, registry, coverage, covered_any)
    # Completeness: every passing probe court that covers surfaces must be cited by at least one
    # measured row, so a new court cannot pass unregistered.
    cited = {r.get("court") for r in surfaces if r.get("classification") == "measured"}
    for court, keys in coverage.items():
        if keys and court not in cited:
            problems.append(
                f"court {court} passes and covers {len(keys)} surface(s) but no measured "
                f"register row cites it")
    counts = {cls: 0 for cls in REGISTER_CLASSIFICATIONS}
    for row in surfaces:
        if row.get("classification") in counts:
            counts[row["classification"]] += 1
    declared = doc.get("classifications") or {}
    for cls in REGISTER_CLASSIFICATIONS:
        if declared.get(cls) != counts[cls]:
            problems.append(
                f"declared {cls} count {declared.get(cls)!r} but the register has {counts[cls]} "
                f"row(s)")
    if declared.get("total") != len(surfaces):
        problems.append(f"declared total {declared.get('total')!r} but the register has "
                        f"{len(surfaces)} row(s)")
    verdict = "pass" if not problems else "fail"
    return {
        "court": name,
        "probe": "",
        "method": (
            "stages no probe: it re-reads the live courts registry (the four probe courts above) "
            "and the authored register artifacts/phase19/performance-boundary-register.json, and "
            "fails the stratum if any recorded measured/not-measured/not-claimed classification, "
            "surface key or stated count/evidence value has drifted from what the courts show "
            "(docs/PHASE-19-SUBPHASES.md sections 3.1, 3.5 and 3.6). A not-measured or "
            "not-claimed row that a passing court now covers, a measured row whose court no "
            "longer covers it, and a stated count that moved are all failures. It is the "
            "stratum's own non-claims: no benchmark-parity claim and no assembly-versus-Rust "
            "equivalence claim."),
        "frf_declarable": False,
        "frf_exclusion": (
            "the register re-reads the courts registry and stages no artifacts/phase19/probes/ "
            "pair, so it takes no transcript to diff and carries no FRF declaration"),
        "register": {
            "path": rel(REGISTER),
            "schema": doc.get("schema"),
            "sha256": sha256_file(REGISTER),
            "counts": counts,
            "total": len(surfaces),
        },
        "surfaces": [
            {"id": r.get("id"), "classification": r.get("classification"),
             "court": r.get("court"), "surface_keys": r.get("surface_keys") or []}
            for r in surfaces
        ],
        "problems": problems,
        "verdict": verdict,
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
    work_row: dict = {}
    for name, filename in COURTS:
        # 19.5's register court stages no probe: its subject is the authored register and the four
        # probe courts' records, computed above it in this one run, so the registry is not read back
        # from disk and no digest cycle forms.
        if name == REGISTER_COURT:
            records.append(register_court(name, records))
            continue
        src = PROBE_DIR / filename
        if not src.is_file():
            records.append({"court": name, "verdict": "fail",
                            "stage": "probe-missing", "detail": rel(src)})
            continue
        # 19.4's sensitivity court is candidate-only and anchors its reference arm to the
        # authority vector 19.3 records, so it is handed the work court's row. Both are produced
        # in this one run, so the registry is not read back from disk and no digest cycle forms.
        if name == PERFORMANCE_SENSITIVITY:
            rec = performance_sensitivity_court(name, src, auth, work, work_row)
        else:
            rec = COURT_IMPL[name](name, src, auth, work)
        if name == PERFORMANCE_WORK:
            work_row = rec
        records.append(rec)

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
            "the CPU-capability surface deterministically -- `OPENSSL_ia32cap_P[0..3]`, the "
            "synthetic words `cap.synthetic.pair`/`.word.4`/`.word.5` the fixed literal's "
            "override derives, whether "
            "`OPENSSL_cpuid_setup` and `OPENSSL_ia32_cpuid` were reachable and callable, and the "
            "capability-derived selection observable through the public API "
            "(`OpenSSL_version(OPENSSL_CPU_INFO)`, `OpenSSL_info(OPENSSL_INFO_CPU_SETTINGS)` and "
            "the four `EVP_aes_*_cbc_hmac_sha*` constructors, which answer NULL when "
            "`AESNI_CAPABLE` is clear). The raw vector `OPENSSL_ia32_cpuid` returns is not "
            "recorded: it is the runner's own CPUID and would make the record machine-specific. "
            "Three portable observations of the synthetic vector the fixed literal derives "
            "(`cap.synthetic.pair`/`.word.4`/`.word.5`) take the place of the host readouts the "
            "first version printed, so no coverage is lost. "
            "The probe is driven under three fixed capability sets via the `OPENSSL_ia32cap` "
            "facade: a synthetic reference set, an AES-NI-cleared set and a fully cleared set, "
            "each an explicit literal so the reported vector is never the runner's own CPU. The "
            "three capability names are declared weak because `OPENSSL_ia32cap_P` is "
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
            "`RT-PERFORMANCE-WORK` is 19.3's court: it compiles "
            "courts/phase19/rt_performance_work_probe.c twice and reports the deterministic work "
            "a fixed operation set performs -- AES-128/256-CBC/GCM, ChaCha20-Poly1305, SHA-256, a "
            "P-256 scalar multiplication and an RSA-1024 private decrypt. The library exposes no "
            "total instruction counter, so the instrument is a counting `CRYPTO` allocator the "
            "stratum introduces (the number of malloc/realloc operations and total bytes the "
            "library requests for a fixed primitive -- a deterministic instruction-path proxy for "
            "its memory work; the shims forward to the default allocator and change no behaviour) "
            "plus the method-derived input/blocks/output/tag sizes. No address, clock or duration "
            "is observed. Every path whose library-side work vector differs from the authority's "
            "is a *finding* recorded, not failed -- the reduced engine's allocations differ on the "
            "EC and RSA paths while the symmetric/digest paths agree -- and a path the probe "
            "cannot drive is `pending`. The court is `pass` when the authority installed the hook "
            "and the paths ran, both transcripts are complete, every schema key is present and "
            "every divergence was recorded -- NOT when nothing diverged. The counting allocator "
            "observes heap operations, not total CPU instructions, and the block counts are "
            "input-implied: no benchmark-parity claim and no assembly-versus-Rust equivalence "
            "claim (sections 3.1 and 3.6). `RT-PERFORMANCE-SENSITIVITY` is 19.4's court: it is "
            "candidate-only -- the deliberately slowed variant is a construction of the harness, "
            "never product code -- and compiles courts/phase19/rt_performance_sensitivity_probe.c "
            "once against the candidate distribution shell. It drives a reference arm (the real "
            "`aes-128-cbc` path, which must equal the authority vector 19.3 recorded) and a slowed "
            "arm (`control-extra-pass`, the same path with an injected extra full pass over the "
            "primitive) under the same 19.3 work instrument, and the court is `pass` only when the "
            "slowed arm is caught on the counting allocator the stratum introduces (a library-side "
            "`allocs`/`reallocs`/`bytes` difference), not merely on the driver-side `calls` 19.3 "
            "excludes from its findings. Section 3.2's rule is mechanical here: a control that "
            "cannot fail is not evidence, so if the instrument cannot tell the slowed path from "
            "the reference the verdict is `fail`, never a vacuous `pass`. It is evidence about the "
            "instrument's resolution and makes no throughput or benchmark-parity claim. "
            "`PERFORMANCE-BOUNDARY-REGISTER` is 19.5's court: it stages no probe and reads the "
            "authored register artifacts/phase19/performance-boundary-register.json against the "
            "four probe courts' records computed above it, failing the stratum if a measured "
            "row's court no longer covers its surface, a not-measured or not-claimed row a "
            "passing court now covers, or a stated count/evidence value has moved. It records "
            "the stratum's own non-claims -- no benchmark-parity claim and no assembly-versus-"
            "Rust equivalence claim, the ENGINE path not measured, the three capability names "
            "not reached, and the two divergent-work findings -- and may not claim more than "
            "the courts above measured. This stratum owns "
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
        InputRef(name="performance-work-probe", path=PROBE_DIR / "rt_performance_work_probe.c"),
        InputRef(name="performance-sensitivity-probe",
                 path=PROBE_DIR / "rt_performance_sensitivity_probe.c"),
        InputRef(name="performance-boundary-register", path=REGISTER),
        InputRef(name="performance-work-fixture",
                 path=PROBE_DIR / "fixtures" / "rsa-work.pem"),
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
                  f"facade {c['facade_reference']}->{c['facade_aesni_off']})")
        elif r["verdict"] == "pass" and r["court"] == EVP_DISPATCH:
            c = r["control"]
            print(f"  {r['court']:<32} pass   ({r['authority_observations']} observations x "
                  f"{len(r['capability_sets'])} sets, {r['divergence_count']} recorded "
                  f"divergence(s), authority selection driven="
                  f"{c['authority_selection_driven']}, facade moved={c['facade_moved_selection']})")
        elif r["verdict"] == "pass" and r["court"] == PERFORMANCE_WORK:
            c = r["control"]
            print(f"  {r['court']:<32} pass   ({r['authority_observations']} observations, "
                  f"{c['authority_paths_ran']}/{c['total_paths']} paths ran, "
                  f"{r['findings_count']} divergent-work finding(s), "
                  f"hook installed={c['authority_hook_installed']})")
            for f in r["findings"]:
                print(f"      finding: {f}")
        elif r["verdict"] == "pass" and r["court"] == PERFORMANCE_SENSITIVITY:
            c = r["control"]
            print(f"  {r['court']:<32} pass   (candidate-only, "
                  f"{r['observations_recorded']['candidate']} observations, control "
                  f"{c['path']} caught={c['caught']} on counter={c['counter_caught']} "
                  f"keys={c['counter_keys_differing']}, reference={c['reference']} matches "
                  f"authority)")
        elif r["verdict"] == "pass" and r["court"] == REGISTER_COURT:
            reg = r["register"]
            print(f"  {r['court']:<32} pass   (no probe, {reg['total']} surfaces: "
                  + ", ".join(f"{k}={v}" for k, v in sorted(reg['counts'].items()))
                  + f") ")
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
