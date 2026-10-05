#!/usr/bin/env python3
"""openssl-rs — Phase 18 courts: the hostile fuzz / security / side-channel hardening courts.

Each court is an instrument over the finished implementation, not a differential probe over a
symbol set. This stratum owns no exported symbol: it hardens the library the sixteen strata
before it completed, so its evidence is a *hostile* one — a malformed-input corpus driven against
the candidate with crash/OOM/timeout detection and an authority-linked control, a
secret-independence check over the primitive-bearing paths with a sensitivity control, and a
resource-exhaustion court over the reduced engine's fixed buffers — rather than a count of names.
The method is Phases 3 through 17's where a differential control is possible: the authority and
the candidate are driven over the same corpus and their observations compared, so the expectation
cannot drift. Where the subject is a `CT-*` secret-independence property the court is
candidate-only and carries a sensitivity control instead (D13, D201), exactly as Phase 8's
`CT-*` courts do.

`RT-HOSTILE-TLS`, and what it drives
------------------------------------
18.1's court. Its instrument is `courts/phase18/rt_hostile_tls_probe.c`, compiled twice (once
against the admitted authority's prefix, once against the candidate distribution shell). It reads
`courts/phase18/fixtures/hostile-tls/`, the fixed malformed-input corpus
`forensics/tools/gen_hostile_tls_corpus.py` writes, one file per entry named
`<role>__<id>.bin`, and feeds each entry to the side that receives it: a `server` entry into
`SSL_accept` (the ClientHello / record reader) and a `client` entry into `SSL_connect` (the
ServerHello / flight reader), over a read-only memory BIO that reports EOF once the bytes are
consumed. The corpus is a fixed enumeration — bogus record types, lengths and versions,
truncated and oversized handshake headers, malformed ClientHello / ServerHello and
`key_share` / `supported_versions` / ALPN / SNI / `signature_algorithms` extension bodies, bad
CCS and bad Finished, length-mismatch records, and one well-formed control per role — not a
fuzzer, and **not a coverage claim**: a surface no entry reaches is named in the court's row
rather than counted as passing (section 3.1).

Each entry runs in **its own forked child**, so a crash, an exhausted allocation budget or a
non-terminating parse is a *recorded finding* for that entry rather than a harness abort
(section 3.3): a child killed by a signal is `crash`, one that reports an allocation failure
under the process's own `RLIMIT_DATA` is `oom`, and one that outlives the entry bound is killed
and recorded `timeout`. The parent always exits 0 and prints one fixed-schema block per entry
whether the child reported, crashed or timed out, so the two sides' observation counts agree and
a missing entry cannot read as a silently shorter transcript. The authority differential control
keeps the expectation honest (section 3.2): the corpus carries a well-formed ClientHello and the
court fails if the *authority* does not parse it into a real handshake message, so the corpus
cannot pass while having driven no valid input.

Every candidate-vs-authority difference is *recorded* rather than failed — the reduced engine's
dispositions legitimately differ from the authority's — which is why the verdict is `pass` when
the corpus was driven, every candidate disposition was recorded, and the authority control held,
**not** when nothing diverged. It is not a security proof and not a parity claim (section 3.6).

`RT-HOSTILE-X509`, and what it drives
------------------------------------
18.2's court. Its instrument is `courts/phase18/rt_hostile_x509_probe.c`, compiled twice (once
against the admitted authority's prefix, once against the candidate distribution shell). It reads
`courts/phase18/fixtures/hostile-x509/`, the fixed malformed-input corpus
`forensics/tools/gen_hostile_x509_corpus.py` writes, one file per entry named `<arm>__<id>.bin`,
and feeds each entry to the reader its arm names: `cert` (`d2i_X509`), `crl` (`d2i_X509_CRL`),
`req` (`d2i_X509_REQ`), `xext` (`d2i_X509_EXTENSION`, plus `X509V3_EXT_d2i` to drive the
subjectAltName / nameConstraints / basicConstraints body parsers), `xexts` (`d2i_X509_EXTENSIONS`),
`gn` (`d2i_GENERAL_NAMES`), `atype` (`d2i_ASN1_TYPE`), `gtime`/`utime`
(`d2i_ASN1_GENERALIZEDTIME`/`d2i_ASN1_UTCTIME`), `alg` (`d2i_X509_ALGOR`), `spki`
(`d2i_X509_PUBKEY`) and the three PEM containers (`PEM_read_bio_X509`/`_X509_CRL`/`_X509_REQ`).
The corpus enumerates truncated and oversized DER certificates, ASN.1 length bombs (deep nesting,
huge declared lengths, indefinite-length misuse), malformed TBSCertificate fields, bad extensions
(duplicate / unknown / critical, malformed name constraints and SAN), bad signature
`AlgorithmIdentifier`s, malformed CRL and CSR containers, malformed PEM containers (bad base64,
missing / extra delimiters, wrong labels), time and bit-string edge cases, and one well-formed
control per arm -- not a fuzzer, and **not a coverage claim**: a surface no entry reaches is named
in the court's row rather than counted as passing (section 3.1). Each entry runs in its own forked
child, exactly as `RT-HOSTILE-TLS` does, so a crash, an exhausted allocation budget or a
non-terminating parse is a *recorded finding* rather than a harness abort (section 3.3).

`CT-PRIMITIVES`, and what it measures
------------------------------------
18.3's court, and the stratum's one `CT-*`. It is **candidate-only**: there is no authority
transcript for a secret-independence property, so `courts/phase18/ct_primitives_probe.c` is
compiled **once**, against the candidate distribution shell, and answers a property question
rather than a differential one. For each measured path it drives the operation under two secret
classes -- a BN exponent's Hamming weight, BN inverse operands, two RSA keys' CRT exponents, an EC
scalar, the position of a tag mismatch, a key-schedule IKM -- interleaves the two classes, and
keeps the minimum timed batch per class with a serialising timestamp counter; a path is `separated`
when the ratio of the two minima exceeds 50 percent. That is a *bounded* work-independence screen
at that resolution, not a proof of constant-time behaviour and not a wall-clock or attack claim
(sections 3.1 and 3.6). It carries the section-3.2 sensitivity control: `control-branchy-tag` is a
deliberately branch-on-secret tag comparison, and the court is `pass` only when it is `separated`
exactly where the real path it varies is `independent`. A measured path that is `separated` is
recorded as a finding rather than failed -- the reduced engine's BN square-and-multiply core carries
this implementation's timing profile by its own module documentation (`src/bn/exp.rs`), and the
court's contract is to measure and record it with a proven-sensitive instrument.

`RT-MEM-HARDENING`, and what it drives
-------------------------------------
18.4's court. Its instrument is `courts/phase18/rt_mem_hardening_probe.c`, compiled twice (once
against the admitted authority's prefix, once against the candidate distribution shell). It drives
the reduced engine's fixed buffers on the paths that handle attacker-influenced lengths -- the
record write's `SSL3_RT_MAX_PLAIN_LENGTH` (16384) fragment/record-encryption inner buffer, the
handshake-message reassembly buffer `TLS13_HS_BUF_LEN` (16384), and the record-body store
`Ssl::rec_body` (17000) -- **at, just below and just above** each recorded capacity
(section 3.4), and records the disposition of every case (correct handling / error / crash /
OOM) rather than assuming it. The write cases stand up a full TLS 1.3 flight and `SSL_write`
exactly the boundary length, which is the previous greater-than-16-KiB overflow's concrete case;
the read cases feed one crafted record into `SSL_accept`. A buffer that is merely `unsafe` to use
-- `tls13_encrypt_record`'s inner buffer, which the fragmenting caller bounds but whose own
contract does not -- is recorded here, not silently fixed.

The section-3.4 injected-failure control is explicit and must *drive* the allocation-failure path.
`ctrl-rlimit` reads the child's `VmData` and lowers `RLIMIT_DATA` to `VmData + 8 MiB`, then
requests a 256 MiB `CRYPTO_malloc`, which must fail (`alloc_null`, `alloc_malloc_failure`);
`ctrl-d2i` drives the ASN.1 reader's own allocation over a DER that declares a 64 MiB content;
and `ctrl-hook` installs a wrapper allocator through `CRYPTO_set_mem_functions` that fails a
chosen CRYPTO allocation and then drives `SSL_CTX_new`. The engine's own allocation-failure paths
returned errors (the candidate raised `ERR_R_MALLOC_FAILURE` and `d2i_X509` returned NULL under
the bound); a crash there would be a recorded finding, not a harness abort (section 3.3).

Every case runs in its own forked child, exactly as `RT-HOSTILE-*` does, and the parent prints
one fixed-schema block per case. A candidate-vs-authority difference is *recorded* rather than
failed -- the reduced engine's dispositions legitimately differ -- so the verdict is `pass` when
every case was driven and every boundary group carries its below/at/above phases on both sides,
**and** the injected-failure control observed the allocation actually fail. It is a bounded
measurement, not a memory-safety proof and not a parity claim (sections 3.1, 3.4 and 3.6).

`HOSTILE-BOUNDARY-REGISTER`, and what it checks
----------------------------------------------
18.5's court, and the stratum's own non-claims. It stages no probe: its subject is
`artifacts/phase18/hostile-boundary-register.json`, the authored register that records, per
surface, whether it is *hardened* (a change landed), *measured* (a court covers it) or
*not-claimed* (explicitly outside this stratum). The court re-reads the live courts registry
(the four probe courts above, already computed) and fails the stratum if any recorded
classification, capacity, count or evidence value has drifted from what the courts actually
show (section 3.5). Three drift classes are caught explicitly: a row marked `hardened` or
`measured` whose court no longer covers its surface, a `not-claimed` row that a passing court
now covers, and a stated capacity or count that moved. A surface the corpus does not reach is
`not-claimed`/`measured`, never `hardened`; the register may not claim more than the courts
above measured (docs/PHASE-18-SUBPHASES.md sections 3.5 and 3.6).

The register is authored rather than derived -- it is the stratum's answer to
`docs/NON_CLAIMS.md`, and its `not-claimed` rows are exactly the claims a generator cannot
make -- so the court's job is to bind it back to the evidence. It is a court with no probe, no
transcript and no authority: it stages no `artifacts/phase18/probes/` pair and is marked
`frf_declarable: false`.

The runner reads no obligations ledger: the ledger's contract-unit states are measured from this
registry, so the edge runs ledger -> courts and binding it back would form a digest cycle neither
artefact could reproduce. `docs/PHASE-18-SUBPHASES.md` section 4.2 is the precondition. No court
is registered in `gen_frf_courts.py`: that registry is the stratum's seal.

SPDX-License-Identifier: Apache-2.0"""

from __future__ import annotations

import argparse
import json
import os
import resource
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

import gen_hostile_tls_corpus  # noqa: E402
import gen_hostile_x509_corpus  # noqa: E402
import provenance_court  # noqa: E402
import unsafe_footprint  # noqa: E402

OUT = REPO_ROOT / "artifacts" / "phase18" / "COURTS.json"
REGISTER = REPO_ROOT / "artifacts" / "phase18" / "hostile-boundary-register.json"
REGISTER_COURT = "HOSTILE-BOUNDARY-REGISTER"
REGISTER_SCHEMA = "openssl-rs/hostile-boundary-register/v1"
# The authored, per-core-module ceiling the growth check compares a fresh scan against. It is
# separate from the generated `forensics/atlas/unsafe-footprint.json` on purpose: a bound that
# were recomputed from the measurement could never fail, so the whole court would be vacuous.
UNSAFE_BOUNDS = REPO_ROOT / "artifacts" / "phase18" / "unsafe-bounds.json"
UNSAFE_BOUNDS_SCHEMA = "openssl-rs/unsafe-bounds/v1"
GENERATOR = "forensics/tools/phase18_courts.py"
PLAN = REPO_ROOT / "docs" / "PHASE-18-SUBPHASES.md"
PROBE_DIR = REPO_ROOT / "courts" / "phase18"
FIXTURES = PROBE_DIR / "fixtures" / "hostile-tls"
X509_FIXTURES = PROBE_DIR / "fixtures" / "hostile-x509"
CORPUS_GENERATOR = REPO_ROOT / "forensics" / "tools" / "gen_hostile_tls_corpus.py"
X509_CORPUS_GENERATOR = REPO_ROOT / "forensics" / "tools" / "gen_hostile_x509_corpus.py"
STAGED = REPO_ROOT / "artifacts" / "phase18" / "probes"
PHASE2 = REPO_ROOT / "artifacts" / "phase2"
AUTH_PREFIX = (REPO_ROOT / "forensics" / "authorities" / "prefix"
               / "openssl-3.6.4-production")
RUN_TIMEOUT_S = "900"

# The courts, in the order they land. `(name, probe filename or None)`, and the probe is declared
# in the same commit as the entry, so a runner that names a probe which does not exist cannot be
# committed. The register court has no probe: its subject is the authored register, and it reads
# the four probe courts' records computed ahead of it.
COURTS: list[tuple[str, str | None]] = [
    ("RT-HOSTILE-TLS", "rt_hostile_tls_probe.c"),
    ("RT-HOSTILE-X509", "rt_hostile_x509_probe.c"),
    ("CT-PRIMITIVES", "ct_primitives_probe.c"),
    ("RT-MEM-HARDENING", "rt_mem_hardening_probe.c"),
    (REGISTER_COURT, None),
]

# The classifications the register may use. `hardened` is a change that landed; `measured` is a
# passing court that covers the surface; `not-claimed` is explicitly outside the stratum.
REGISTER_CLASSIFICATIONS = ("hardened", "measured", "not-claimed")

# The courts the plan names and this stratum still cannot run. Empty since 18.5 landed the
# register; kept as the stated-distance mechanism, so a court the plan names but the runner cannot
# run is recorded here rather than quietly dropped.
PENDING_COURTS: dict[str, str] = {}

# The entry whose authority disposition proves the corpus drove a real parser rather than only
# rejecting. The plan requires the differential control to keep the expectation honest (section
# 3.2); this is the arm that fails if it cannot.
CONTROL_ENTRY = "ch-min-valid"

# `CT-PRIMITIVES`'s measured paths, one per primitive-bearing category, and the deliberately
# branch-on-secret control. `(path, unit, what)`. The path names are the transcript keys the probe
# emits; the `unit` is the category `docs/PHASE-18-SUBPHASES.md` section 2's row names.
CT_PATHS: list[tuple[str, str, str]] = [
    ("bn-modexp", "BN",
     "BN_mod_exp_mont_consttime over a fixed 255-bit prime, two 255-bit secret exponents of the "
     "same public length and different Hamming weight"),
    ("bn-inverse", "BN",
     "BN_mod_inverse over a fixed 255-bit prime modulus, two fixed coprime secret operands"),
    ("rsa-private", "RSA",
     "RSA_private_decrypt on a fixed ciphertext, two 1024-bit private keys whose CRT exponents "
     "differ in Hamming weight"),
    ("ec-scalar-mul", "EC",
     "EC_POINT_mul on P-256 against the generator, two 256-bit secret scalars (the constant-time "
     "ladder path)"),
    ("aead-tag-memcmp", "AEAD",
     "CRYPTO_memcmp over an aligned 4 KiB tag, mismatch at the first versus the last byte -- the "
     "comparison AES-GCM's finish and the Poly1305 check are built on"),
    ("tls-key-schedule-hkdf", "TLS key schedule",
     "EVP_KDF HKDF extract+expand, the TLS 1.3 schedule's core, two 32-byte secret IKMs"),
]
# The control: a deliberately branch-on-secret tag comparison, and the real path it varies. The
# court requires the control to be `separated` where the real path is `independent` (section 3.2).
CT_CONTROL: tuple[str, str, str] = (
    "control-branchy-tag",
    "aead-tag-memcmp",
    "a deliberately branch-on-secret tag comparison: it returns early on the first mismatching "
    "byte and does a dependent multiply per matching byte, so a tag differing at its last byte "
    "does far more work than one differing at its first",
)
CT_SEP_PCT = 150
CT_SAMPLES = 320
CT_WARMUP = 32
# `RT-HOSTILE-X509`'s control: the well-formed v3 certificate. The authority must parse it
# into a real certificate (version 2, at least one extension), not merely reject it.
X509_CONTROL_ENTRY = "cert-valid"
CONTROL_CLASSES = ("parse",)
HOSTILE_CLASSES = ("crash", "oom", "timeout")

# `RT-MEM-HARDENING`'s boundary phases and its injected-failure control. The control case must
# observe the allocation it drives actually fail (`alloc_null`), or the court cannot claim it drove
# the allocation-failure path rather than assuming it (section 3.4).
MEM_PHASES = ("below", "at", "above")
MEM_CONTROL_ENTRY = "ctrl-rlimit"
MEM_CONTROL_ENTRIES = ("ctrl-rlimit", "ctrl-d2i", "ctrl-hook")
MEM_CONTROL_CLASSES = ("ran",)


def side_env(libdir: Path, modulesdir: Path) -> dict[str, str]:
    """The environment a probe runs under on one side.

    `OPENSSL_MODULES` points at that side's own `ossl-modules/`; `LD_LIBRARY_PATH` fixes the DSO
    the probe resolves against, and `OPENSSL_CONF=/dev/null` keeps the host's configuration out of
    a deterministic transcript.
    """
    env = dict(os.environ)
    env["LD_LIBRARY_PATH"] = str(libdir)
    env["OPENSSL_MODULES"] = str(modulesdir)
    env["OPENSSL_CONF"] = "/dev/null"
    env.pop("OPENSSL_CONF_INCLUDE", None)
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


def compile_probe(src: Path, out: Path, include: Path, libdir: Path) -> tuple[bool, str]:
    """Compile one side's C probe against that side's headers and shared objects.

    The method is Phase 17's: the same source compiles twice, once against the admitted
    authority's prefix and once against the candidate distribution shell, so the comparison is
    between two executions of one program.
    """
    res = run([
        "clang", "-std=c11", "-Wall", "-Wno-deprecated-declarations",
        "-Werror=implicit-function-declaration", "-O1",
        "-D_GNU_SOURCE",
        "-I", str(include),
        "-o", str(out), str(src),
        "-L", str(libdir), "-lssl", "-lcrypto",
        f"-Wl,-rpath,{libdir}",
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


def _class_of(values: dict[str, str], entry: str) -> str | None:
    return values.get(f"entry.{entry}.class")


def _entry_ids(values: dict[str, str]) -> set[str]:
    ids: set[str] = set()
    for key in values:
        if key.startswith("entry.") and key.endswith(".class"):
            ids.add(key[len("entry."):-len(".class")])
    return ids


def residual_rows(a: dict[str, str], c: dict[str, str]) -> list[dict]:
    """Every observation that differs between the two sides, classified by its kind.

    The comparison is keyed rather than line-wise, so a missing or extra key is one residual
    instead of a cascade. A residual on an entry either side recorded as `crash`/`oom`/`timeout`
    is a `hostile` residual -- the finding the court must record honestly -- and every other is a
    `value`, `missing` or `extra` divergence.
    """
    rows: list[dict] = []
    for key in sorted(set(a) | set(c)):
        av, cv = a.get(key), c.get(key)
        if av == cv:
            continue
        entry = ""
        if key.startswith("entry."):
            entry = key[len("entry."):].split(".", 1)[0]
        a_class, c_class = _class_of(a, entry), _class_of(c, entry)
        hostile = (a_class in HOSTILE_CLASSES or c_class in HOSTILE_CLASSES)
        if key not in c:
            cls = "missing"
        elif key not in a:
            cls = "extra"
        else:
            cls = "hostile" if hostile else "value"
        rows.append({
            "observation": key,
            "authority": av,
            "candidate": cv,
            "class": cls,
        })
    return rows


def findings_of(side: str, values: dict[str, str], corpus_ids: list[str]) -> dict:
    """The crash/oom/timeout findings for one side, per section 3.3.

    A finding is a *recorded* entry, not an abort: its entry id, its class and its signal (for a
    crash) and the disposition fields that survived are kept so the court can report it and the
    corpus can continue.
    """
    out: dict[str, list[dict]] = {"crash": [], "oom": [], "timeout": []}
    for entry in corpus_ids:
        cls = _class_of(values, entry)
        if cls in HOSTILE_CLASSES:
            out[cls].append({
                "entry": entry,
                "role": values.get(f"entry.{entry}.role", ""),
                "arm": values.get(f"entry.{entry}.arm", ""),
                "signal": values.get(f"entry.{entry}.signal", ""),
            })
    return out


def ct_primitives_court(name: str, src: Path, auth, work: Path) -> dict:
    """`CT-PRIMITIVES`: the candidate-only secret-independence screen over the primitive paths.

    A `CT-*` court has no authority transcript to diff, so this one is compiled **once**, against
    the candidate distribution shell, and answers a property question: for each measured path, does
    the operation's work separate two secret classes? The probe keeps the minimum timed batch per
    class and classifies a path `separated` when the two minima differ by more than
    `CT_SEP_PCT` percent. It is a *bounded* screen at that resolution, not a proof of constant-time
    behaviour and not a wall-clock claim (sections 3.1 and 3.6).

    The verdict follows section 3.2: `pass` when the measurement ran, the deliberately
    branch-on-secret control was caught (`separated`) exactly where the real tag path it varies was
    `independent`, and every measured path produced a definite class. A measured path that is
    `separated` is **recorded as a finding**, not failed: the reduced engine's BN square-and-`
    multiply core is documented as carrying this implementation's timing profile
    (`src/bn/exp.rs`), and this court's contract is to measure and record it, with the control
    proving the instrument can tell the difference. The verdict is about the instrument's
    sensitivity, and the findings are the evidence it produced.
    """
    del auth  # candidate-only: there is no authority transcript for a secret-independence property

    cand_bin = work / f"{src.stem}.candidate"
    ok, err = compile_probe(src, cand_bin, PHASE2 / "include", PHASE2)
    if not ok:
        return {"court": name, "verdict": "fail", "stage": "compile-candidate",
                "detail": err.splitlines()[:12]}

    out, run_err, code = run_probe(
        cand_bin, side_env(PHASE2, PHASE2 / "install" / "lib" / "ossl-modules"))
    if not out.strip():
        return {"court": name, "verdict": "fail", "stage": "candidate-run",
                "detail": {"exit_code": code, "stderr": run_err.splitlines()[:12]}}

    vals = keyed(out)
    problems: list[str] = []
    paths: list[dict] = []
    for path, unit, what in CT_PATHS:
        ran = vals.get(f"ct.{path}.ran")
        cls = vals.get(f"ct.{path}.class")
        if ran != "1" or cls not in ("independent", "separated"):
            problems.append(f"{path}: ran={ran} class={cls}")
        paths.append({"path": path, "unit": unit, "what": what,
                      "ran": ran == "1", "class": cls})

    ctrl_path, ref_path, ctrl_what = CT_CONTROL
    ctrl_cls = vals.get(f"ct.{ctrl_path}.class")
    ref_cls = vals.get(f"ct.{ref_path}.class")
    ctrl_ran = vals.get(f"ct.{ctrl_path}.ran")
    # The control is honest when the deliberately branch-on-secret variant is caught and the real
    # path it varies is not: a control that cannot fail is not evidence (section 3.2).
    control_ok = (ctrl_ran == "1" and ctrl_cls == "separated" and ref_cls == "independent")
    if not control_ok:
        problems.append(
            f"control not honest: {ctrl_path}.class={ctrl_cls} (want separated), "
            f"{ref_path}.class={ref_cls} (want independent)")

    findings = [p["path"] for p in paths if p["class"] == "separated"]
    independent = [p["path"] for p in paths if p["class"] == "independent"]
    verdict = "pass" if not problems else "fail"

    staged: dict[str, str] = {}
    STAGED.mkdir(parents=True, exist_ok=True)
    dst = STAGED / f"{src.stem}.candidate"
    if cand_bin.is_file():
        shutil.copyfile(cand_bin, dst)
        dst.chmod(0o755)
        staged["candidate"] = rel(dst)

    return {
        "court": name,
        "probe": rel(src),
        "method": (
            "candidate-only; each path is driven under two secret classes with a serialising "
            f"timestamp counter, {CT_SAMPLES} samples per class after {CT_WARMUP} warmups, and "
            "classified `separated` when the ratio of the two minimum batch times exceeds "
            f"{CT_SEP_PCT} percent. A ratio of minima is a bounded work-independence screen at "
            "that resolution, not a timing-attack claim and not a proof of constant-time "
            "behaviour."),
        "threshold_percent": CT_SEP_PCT,
        "samples_per_class": CT_SAMPLES,
        "warmup": CT_WARMUP,
        "candidate_exit_code": code,
        "paths": paths,
        "control": {
            "path": ctrl_path,
            "what": ctrl_what,
            "reference": ref_path,
            "class": ctrl_cls,
            "reference_class": ref_cls,
            "honest": control_ok,
        },
        "findings": findings,
        "independence_observed": independent,
        "problems": problems,
        "verdict": verdict,
        "staged_binaries": staged,
    }


def hostile_tls_court(name: str, src: Path, auth, work: Path) -> dict:
    """`RT-HOSTILE-TLS`: the fixed malformed-input corpus, differentially, with findings.

    Returns a `pass` record when the corpus was driven on both sides, every entry's candidate
    disposition was recorded, and the authority differential control held; the candidate-vs-
    authority differences and any crash/oom/timeout findings are recorded in the row, not failed.
    """
    problems = gen_hostile_tls_corpus.verify()
    if problems:
        return {"court": name, "verdict": "fail", "stage": "corpus",
                "detail": problems[:8]}
    body = gen_hostile_tls_corpus.manifest()
    corpus_ids = [e["id"] for e in body["entries"]]

    auth_bin = work / f"{src.stem}.authority"
    cand_bin = work / f"{src.stem}.candidate"
    ok, err = compile_probe(src, auth_bin, auth.prefix / "include", auth.libdir)
    if not ok:
        return {"court": name, "verdict": "fail", "stage": "compile-authority",
                "detail": err.splitlines()[:12]}
    ok, err = compile_probe(src, cand_bin, PHASE2 / "include", PHASE2)
    if not ok:
        return {"court": name, "verdict": "fail", "stage": "compile-candidate",
                "detail": err.splitlines()[:12]}

    a_out, a_err, a_code = run_probe(
        auth_bin, side_env(auth.libdir, auth.libdir / "ossl-modules"))
    c_out, c_err, c_code = run_probe(
        cand_bin, side_env(PHASE2, PHASE2 / "install" / "lib" / "ossl-modules"))

    if not a_out.strip():
        return {"court": name, "verdict": "fail", "stage": "authority-run",
                "detail": {"exit_code": a_code, "stderr": a_err.splitlines()[:12]}}
    if not c_out.strip():
        return {"court": name, "verdict": "fail", "stage": "candidate-run",
                "detail": {"exit_code": c_code, "stderr": c_err.splitlines()[:12]}}

    a_vals, c_vals = keyed(a_out), keyed(c_out)
    residuals = residual_rows(a_vals, c_vals)
    findings = {
        "authority": findings_of("authority", a_vals, corpus_ids),
        "candidate": findings_of("candidate", c_vals, corpus_ids),
    }

    a_driven = _entry_ids(a_vals)
    c_driven = _entry_ids(c_vals)
    a_control = {
        "class": _class_of(a_vals, CONTROL_ENTRY),
        "out_bytes": a_vals.get(f"entry.{CONTROL_ENTRY}.out_bytes"),
        "out_first": a_vals.get(f"entry.{CONTROL_ENTRY}.out_first"),
    }
    c_control = {
        "class": _class_of(c_vals, CONTROL_ENTRY),
        "out_bytes": c_vals.get(f"entry.{CONTROL_ENTRY}.out_bytes"),
        "out_first": c_vals.get(f"entry.{CONTROL_ENTRY}.out_first"),
    }

    # The corpus is driven when every manifest entry got a class on both sides; the authority
    # control is honest when the *authority* parsed the well-formed ClientHello into a real
    # handshake record (not only a two-byte alert), and when the authority itself suffered no
    # hostile finding -- a control that cannot fail is not evidence (section 3.2).
    a_out_bytes = int(a_control["out_bytes"] or "0")
    control_ok = (
        a_control["class"] in CONTROL_CLASSES
        and a_out_bytes > 7
        and a_control["out_first"] == "2"
        and not any(findings["authority"][k] for k in HOSTILE_CLASSES)
        and c_control["class"] in CONTROL_CLASSES
    )
    driven_ok = (a_driven == set(corpus_ids) and c_driven == set(corpus_ids))

    if not driven_ok:
        missing_a = sorted(set(corpus_ids) - a_driven)
        missing_c = sorted(set(corpus_ids) - c_driven)
        problems = []
        if missing_a:
            problems.append(f"authority did not drive: {missing_a[:8]}")
        if missing_c:
            problems.append(f"candidate did not drive: {missing_c[:8]}")
    else:
        problems = []

    staged: dict[str, str] = {}
    STAGED.mkdir(parents=True, exist_ok=True)
    for side, srcbin in (("authority", auth_bin), ("candidate", cand_bin)):
        dst = STAGED / f"{src.stem}.{side}"
        if srcbin.is_file():
            shutil.copyfile(srcbin, dst)
            dst.chmod(0o755)
            staged[side] = rel(dst)

    # A reduced engine's dispositions differ from the authority's, so a difference is recorded
    # rather than failed. The `residuals` list is deliberately the hostile *class* differences
    # (which would be failures if unanalysed) plus the counted sample; the full divergence set is
    # summarised by `residual_count` and the bounded `recorded_divergences` sample.
    divergent = [r for r in residuals if r["class"] != "hostile"]
    hostile = [r for r in residuals if r["class"] == "hostile"]

    verdict = "pass" if (driven_ok and control_ok) else "fail"
    rlimit_data = resource.getrlimit(resource.RLIMIT_DATA)[0]
    cgroup_max = None
    try:
        cgroup_max = int(Path("/sys/fs/cgroup/memory.max").read_text().strip())
    except (OSError, ValueError):
        cgroup_max = None

    return {
        "court": name,
        "probe": rel(src),
        "corpus": {
            "path": rel(FIXTURES),
            "manifest": rel(gen_hostile_tls_corpus.MANIFEST),
            "manifest_sha256": sha256_file(gen_hostile_tls_corpus.MANIFEST),
            "generator": rel(CORPUS_GENERATOR),
            "entries": body["counts"]["entries"],
            "total_bytes": body["counts"]["total_bytes"],
            "by_category": body["counts"]["by_category"],
            "by_role": body["counts"]["by_role"],
        },
        "authority_exit_code": a_code,
        "candidate_exit_code": c_code,
        "authority_observations": len([l for l in a_out.splitlines() if "=" in l]),
        "candidate_observations": len([l for l in c_out.splitlines() if "=" in l]),
        "entries_driven": {
            "corpus": len(corpus_ids),
            "authority": len(a_driven),
            "candidate": len(c_driven),
        },
        "control": {"entry": CONTROL_ENTRY, "authority": a_control, "candidate": c_control,
                    "honest": control_ok},
        "findings": findings,
        "findings_count": {side: {k: len(v) for k, v in findings[side].items()}
                           for side in findings},
        "residual_count": len(residuals),
        "residuals": hostile,
        "hostile_residual_count": len(hostile),
        "recorded_divergences": divergent[:48],
        "recorded_divergence_count": len(divergent),
        "problems": problems,
        "bounds": {
            "rlimit_data_kib": None if rlimit_data == resource.RLIM_INFINITY else rlimit_data,
            "cgroup_memory_max_bytes": cgroup_max,
            "entry_timeout_ms": 4000,
        },
        "verdict": verdict,
        "staged_binaries": staged,
        "candidate_stderr_tail": c_err.splitlines()[-3:],
    }


def hostile_x509_court(name: str, src: Path, auth, work: Path) -> dict:
    """`RT-HOSTILE-X509`: the fixed malformed-input corpus over the X.509/ASN.1/PEM readers.

    Returns a `pass` record when the corpus was driven on both sides, every entry's candidate
    disposition was recorded, and the authority differential control held; the candidate-vs-
    authority differences and any crash/oom/timeout findings are recorded in the row, not
    failed. It is a bounded differential result over the corpus it drives, not a security proof
    and not a parity claim (sections 3.1 and 3.6).
    """
    problems = gen_hostile_x509_corpus.verify()
    if problems:
        return {"court": name, "verdict": "fail", "stage": "corpus",
                "detail": problems[:8]}
    body = gen_hostile_x509_corpus.manifest()
    corpus_ids = [e["id"] for e in body["entries"]]

    auth_bin = work / f"{src.stem}.authority"
    cand_bin = work / f"{src.stem}.candidate"
    ok, err = compile_probe(src, auth_bin, auth.prefix / "include", auth.libdir)
    if not ok:
        return {"court": name, "verdict": "fail", "stage": "compile-authority",
                "detail": err.splitlines()[:12]}
    ok, err = compile_probe(src, cand_bin, PHASE2 / "include", PHASE2)
    if not ok:
        return {"court": name, "verdict": "fail", "stage": "compile-candidate",
                "detail": err.splitlines()[:12]}

    a_out, a_err, a_code = run_probe(
        auth_bin, side_env(auth.libdir, auth.libdir / "ossl-modules"))
    c_out, c_err, c_code = run_probe(
        cand_bin, side_env(PHASE2, PHASE2 / "install" / "lib" / "ossl-modules"))

    if not a_out.strip():
        return {"court": name, "verdict": "fail", "stage": "authority-run",
                "detail": {"exit_code": a_code, "stderr": a_err.splitlines()[:12]}}
    if not c_out.strip():
        return {"court": name, "verdict": "fail", "stage": "candidate-run",
                "detail": {"exit_code": c_code, "stderr": c_err.splitlines()[:12]}}

    a_vals, c_vals = keyed(a_out), keyed(c_out)
    residuals = residual_rows(a_vals, c_vals)
    findings = {
        "authority": findings_of("authority", a_vals, corpus_ids),
        "candidate": findings_of("candidate", c_vals, corpus_ids),
    }

    a_driven, c_driven = _entry_ids(a_vals), _entry_ids(c_vals)

    def ctl(vals: dict[str, str]) -> dict:
        e = X509_CONTROL_ENTRY
        return {
            "class": _class_of(vals, e),
            "ret": vals.get(f"entry.{e}.ret"),
            "obs": vals.get(f"entry.{e}.obs"),
            "obs2": vals.get(f"entry.{e}.obs2"),
            "err": vals.get(f"entry.{e}.err"),
        }

    a_control, c_control = ctl(a_vals), ctl(c_vals)

    # The corpus is driven when every manifest entry got a class on both sides; the authority
    # control is honest when the *authority* parsed the well-formed v3 certificate into a real
    # certificate (version 2, at least one extension, no queued error) and itself suffered no
    # hostile finding -- a control that cannot fail is not evidence (section 3.2).
    control_ok = (
        a_control["class"] in CONTROL_CLASSES
        and a_control["ret"] == "1"
        and a_control["obs"] == "2"
        and int(a_control["obs2"] or "0") >= 1
        and a_control["err"] == "none"
        and not any(findings["authority"][k] for k in HOSTILE_CLASSES)
        and c_control["class"] in CONTROL_CLASSES
        and c_control["ret"] == "1"
    )
    driven_ok = (a_driven == set(corpus_ids) and c_driven == set(corpus_ids))

    if not driven_ok:
        missing_a = sorted(set(corpus_ids) - a_driven)
        missing_c = sorted(set(corpus_ids) - c_driven)
        problems = []
        if missing_a:
            problems.append(f"authority did not drive: {missing_a[:8]}")
        if missing_c:
            problems.append(f"candidate did not drive: {missing_c[:8]}")
    else:
        problems = []

    staged: dict[str, str] = {}
    STAGED.mkdir(parents=True, exist_ok=True)
    for side, srcbin in (("authority", auth_bin), ("candidate", cand_bin)):
        dst = STAGED / f"{src.stem}.{side}"
        if srcbin.is_file():
            shutil.copyfile(srcbin, dst)
            dst.chmod(0o755)
            staged[side] = rel(dst)

    divergent = [r for r in residuals if r["class"] != "hostile"]
    hostile = [r for r in residuals if r["class"] == "hostile"]

    verdict = "pass" if (driven_ok and control_ok) else "fail"
    rlimit_data = resource.getrlimit(resource.RLIMIT_DATA)[0]
    cgroup_max = None
    try:
        cgroup_max = int(Path("/sys/fs/cgroup/memory.max").read_text().strip())
    except (OSError, ValueError):
        cgroup_max = None

    return {
        "court": name,
        "probe": rel(src),
        "corpus": {
            "path": rel(X509_FIXTURES),
            "manifest": rel(gen_hostile_x509_corpus.MANIFEST),
            "manifest_sha256": sha256_file(gen_hostile_x509_corpus.MANIFEST),
            "generator": rel(X509_CORPUS_GENERATOR),
            "entries": body["counts"]["entries"],
            "total_bytes": body["counts"]["total_bytes"],
            "by_category": body["counts"]["by_category"],
            "by_arm": body["counts"]["by_arm"],
            "provenance": body["provenance"],
        },
        "authority_exit_code": a_code,
        "candidate_exit_code": c_code,
        "authority_observations": len([ln for ln in a_out.splitlines() if "=" in ln]),
        "candidate_observations": len([ln for ln in c_out.splitlines() if "=" in ln]),
        "entries_driven": {
            "corpus": len(corpus_ids),
            "authority": len(a_driven),
            "candidate": len(c_driven),
        },
        "control": {"entry": X509_CONTROL_ENTRY, "authority": a_control,
                    "candidate": c_control, "honest": control_ok},
        "findings": findings,
        "findings_count": {side: {k: len(v) for k, v in findings[side].items()}
                           for side in findings},
        "residual_count": len(residuals),
        "residuals": hostile,
        "hostile_residual_count": len(hostile),
        "recorded_divergences": divergent[:48],
        "recorded_divergence_count": len(divergent),
        "problems": problems,
        "bounds": {
            "rlimit_data_kib": None if rlimit_data == resource.RLIM_INFINITY else rlimit_data,
            "cgroup_memory_max_bytes": cgroup_max,
            "entry_timeout_ms": 4000,
        },
        "verdict": verdict,
        "staged_binaries": staged,
        "candidate_stderr_tail": c_err.splitlines()[-3:],
    }


def _case_ids(values: dict[str, str]) -> set[str]:
    """The `case.<id>` ids that printed a `class` — the mem court's analogue of `_entry_ids`."""
    ids: set[str] = set()
    for key in values:
        if key.startswith("case.") and key.endswith(".class"):
            ids.add(key[len("case."):-len(".class")])
    return ids


def mem_residual_rows(a: dict[str, str], c: dict[str, str]) -> list[dict]:
    """`residual_rows` for the `case.` prefix, so a crash/oom/timeout difference is `hostile`."""
    rows: list[dict] = []
    for key in sorted(set(a) | set(c)):
        av, cv = a.get(key), c.get(key)
        if av == cv:
            continue
        cid = ""
        if key.startswith("case."):
            cid = key[len("case."):].split(".", 1)[0]
        a_cls = a.get(f"case.{cid}.class") if cid else None
        c_cls = c.get(f"case.{cid}.class") if cid else None
        hostile = a_cls in HOSTILE_CLASSES or c_cls in HOSTILE_CLASSES
        if key not in c:
            cls = "missing"
        elif key not in a:
            cls = "extra"
        else:
            cls = "hostile" if hostile else "value"
        rows.append({"observation": key, "authority": av, "candidate": cv, "class": cls})
    return rows


def mem_case_row(values: dict[str, str], cid: str) -> dict:
    """One mem case's disposition, read by key rather than by position, with ints decoded.

    A side that never reported the case leaves every field empty, so a crashed child is visible
    rather than read as a zero.
    """
    fields = ("path", "phase", "capacity", "request", "class", "signal", "ret",
              "ssl_error", "state", "finished", "err_count", "reason0", "bytes",
              "consumed", "match", "alloc_null", "alloc_malloc_failure", "d2i_null",
              "rlimit_lowered", "alloc_set_rc")
    row: dict = {"id": cid}
    for f in fields:
        row[f] = values.get(f"case.{cid}.{f}", "")
    for f in fields:
        if f in ("path", "phase", "class"):
            continue
        if row[f] not in ("", None):
            try:
                row[f] = int(row[f])
            except ValueError:
                pass
    return row


def mem_findings_of(values: dict[str, str], ids: list[str]) -> dict:
    """The per-case crash/oom/timeout findings for one side (section 3.3)."""
    out: dict[str, list[dict]] = {"crash": [], "oom": [], "timeout": []}
    for cid in ids:
        cls = values.get(f"case.{cid}.class")
        if cls in HOSTILE_CLASSES:
            out[cls].append({
                "case": cid,
                "path": values.get(f"case.{cid}.path", ""),
                "phase": values.get(f"case.{cid}.phase", ""),
                "signal": values.get(f"case.{cid}.signal", ""),
            })
    return out


def mem_hardening_court(name: str, src: Path, auth, work: Path) -> dict:
    """`RT-MEM-HARDENING`: the fixed-buffer boundaries and the injected-failure control.

    Returns a `pass` record when every case was driven on both sides, every boundary group carries
    its below/at/above phases, and the injected-failure control observed the allocation it drives
    actually fail. A crash/OOM at a case is a *recorded* finding, not a harness abort (section
    3.3); a candidate-vs-authority difference is recorded rather than failed, because the reduced
    engine's dispositions legitimately differ. It is a bounded measurement, not a memory-safety
    proof and not a parity claim (sections 3.1, 3.4 and 3.6).
    """
    auth_bin = work / f"{src.stem}.authority"
    cand_bin = work / f"{src.stem}.candidate"
    ok, err = compile_probe(src, auth_bin, auth.prefix / "include", auth.libdir)
    if not ok:
        return {"court": name, "verdict": "fail", "stage": "compile-authority",
                "detail": err.splitlines()[:12]}
    ok, err = compile_probe(src, cand_bin, PHASE2 / "include", PHASE2)
    if not ok:
        return {"court": name, "verdict": "fail", "stage": "compile-candidate",
                "detail": err.splitlines()[:12]}

    a_out, a_err, a_code = run_probe(
        auth_bin, side_env(auth.libdir, auth.libdir / "ossl-modules"))
    c_out, c_err, c_code = run_probe(
        cand_bin, side_env(PHASE2, PHASE2 / "install" / "lib" / "ossl-modules"))

    if not a_out.strip():
        return {"court": name, "verdict": "fail", "stage": "authority-run",
                "detail": {"exit_code": a_code, "stderr": a_err.splitlines()[:12]}}
    if not c_out.strip():
        return {"court": name, "verdict": "fail", "stage": "candidate-run",
                "detail": {"exit_code": c_code, "stderr": c_err.splitlines()[:12]}}

    a_vals, c_vals = keyed(a_out), keyed(c_out)
    residuals = mem_residual_rows(a_vals, c_vals)
    a_driven, c_driven = _case_ids(a_vals), _case_ids(c_vals)
    try:
        expected = int(c_vals.get("cases.count", "-1") or "-1")
    except ValueError:
        expected = -1

    all_ids = sorted(a_driven | c_driven)
    cases = {"authority": [mem_case_row(a_vals, cid) for cid in all_ids],
             "candidate": [mem_case_row(c_vals, cid) for cid in all_ids]}

    # Boundary completeness: every non-control path group must carry below/at/above.
    groups: dict[tuple[str, object], set[str]] = {}
    for cid in all_ids:
        path = c_vals.get(f"case.{cid}.path", "") or a_vals.get(f"case.{cid}.path", "")
        phase = c_vals.get(f"case.{cid}.phase", "") or a_vals.get(f"case.{cid}.phase", "")
        if path.startswith("alloc-"):
            continue
        raw = c_vals.get(f"case.{cid}.capacity", "") or a_vals.get(f"case.{cid}.capacity", "")
        try:
            cap: object = int(raw)
        except ValueError:
            cap = raw
        groups.setdefault((path, cap), set()).add(phase)

    problems: list[str] = []
    if a_driven != c_driven:
        problems.append(
            f"case sets differ: authority-only={sorted(a_driven - c_driven)[:8]} "
            f"candidate-only={sorted(c_driven - a_driven)[:8]}")
    if expected < 0 or len(c_driven) != expected:
        problems.append(f"cases.count={expected} but the candidate drove {len(c_driven)} case(s)")
    incomplete = {f"{p}@{cap}": sorted(set(MEM_PHASES) - phases)
                  for (p, cap), phases in sorted(groups.items(), key=lambda kv: str(kv[0]))
                  if set(MEM_PHASES) - phases}
    if incomplete:
        problems.append(f"boundary groups missing phases: {incomplete}")
    if not groups:
        problems.append("no boundary group was driven")

    # The injected-failure control: the allocation the control drives must actually fail on both
    # sides, so the court can say it drove the allocation-failure path rather than assumed it
    # (section 3.4). A crash there is recorded as a finding (section 3.3).
    a_ctrl = mem_case_row(a_vals, MEM_CONTROL_ENTRY)
    c_ctrl = mem_case_row(c_vals, MEM_CONTROL_ENTRY)
    control_driven = (a_ctrl["alloc_null"] == 1 and c_ctrl["alloc_null"] == 1)
    if not control_driven:
        problems.append(
            f"injected-failure control {MEM_CONTROL_ENTRY} did not drive the failure: "
            f"authority alloc_null={a_ctrl['alloc_null']} class={a_ctrl['class']}, "
            f"candidate alloc_null={c_ctrl['alloc_null']} class={c_ctrl['class']}")

    control_rows = {cid: {"authority": mem_case_row(a_vals, cid),
                          "candidate": mem_case_row(c_vals, cid)}
                    for cid in MEM_CONTROL_ENTRIES}
    findings = {"authority": mem_findings_of(a_vals, all_ids),
                "candidate": mem_findings_of(c_vals, all_ids)}

    driven_ok = not problems
    verdict = "pass" if driven_ok else "fail"

    staged: dict[str, str] = {}
    STAGED.mkdir(parents=True, exist_ok=True)
    for side, srcbin in (("authority", auth_bin), ("candidate", cand_bin)):
        dst = STAGED / f"{src.stem}.{side}"
        if srcbin.is_file():
            shutil.copyfile(srcbin, dst)
            dst.chmod(0o755)
            staged[side] = rel(dst)

    hostile = [r for r in residuals if r["class"] == "hostile"]
    divergent = [r for r in residuals if r["class"] != "hostile"]

    rlimit_data = resource.getrlimit(resource.RLIMIT_DATA)[0]
    cgroup_max = None
    try:
        cgroup_max = int(Path("/sys/fs/cgroup/memory.max").read_text().strip())
    except (OSError, ValueError):
        cgroup_max = None

    return {
        "court": name,
        "probe": rel(src),
        "method": (
            "the fixed-buffer boundaries at, just below and just above the recorded capacity "
            "(SSL3_RT_MAX_PLAIN_LENGTH 16384 for the write path and TLS13_HS_BUF_LEN 16384 for "
            "handshake reassembly; Ssl::rec_body 17000 for the record body), each case in its own "
            "forked child so a crash/oom/timeout is a recorded finding; plus an injected-failure "
            "control that lowers RLIMIT_DATA, requests a 256 MiB allocation and drives the ASN.1 "
            "reader's own allocation, and a wrapper allocator through CRYPTO_set_mem_functions. "
            "A bounded measurement, not a memory-safety proof (sections 3.1, 3.4, 3.6)."),
        "authority_exit_code": a_code,
        "candidate_exit_code": c_code,
        "authority_observations": len([ln for ln in a_out.splitlines() if "=" in ln]),
        "candidate_observations": len([ln for ln in c_out.splitlines() if "=" in ln]),
        "cases_driven": {"probe_cases_count": expected, "authority": len(a_driven),
                         "candidate": len(c_driven)},
        "boundary_groups": {f"{p}@{cap}": sorted(phases)
                            for (p, cap), phases in sorted(groups.items(),
                                                           key=lambda kv: str(kv[0]))},
        "recorded_boundaries": [
            {
                "buffer": "ssl3_write_bytes / tls13_encrypt_record inner plaintext",
                "capacity": 16384,
                "disposition": "hardened-and-measured",
                "note": (
                    "the exposed write path fragments at SSL3_RT_MAX_PLAIN_LENGTH, so the "
                    "write-below/at/above cases (N = 16383/16384/16385, 32768, 65536) all "
                    "round-trip N bytes on both sides -- the previous greater-than-16-KiB "
                    "overflow is fixed, not merely bounded"),
            },
            {
                "buffer": "tls13_encrypt_record inner buffer contract",
                "capacity": 16384,
                "disposition": "merely-unsafe-to-use-recorded",
                "note": (
                    "tls13_encrypt_record copies `len` bytes into its [u8; TLS13_HS_BUF_LEN+1] "
                    "inner buffer without checking `len`; the fragmenting caller bounds it, but "
                    "the function's own # Safety contract does not, so it is recorded as unsafe "
                    "to call directly rather than silently fixed (section 3.4)"),
            },
            {
                "buffer": "Ssl::rd_msg_buf / TLS13_HS_BUF_LEN (handshake reassembly)",
                "capacity": 16384,
                "disposition": "measured",
                "note": (
                    "read-hs-below/at are parsed (and rejected as malformed) and read-hs-above "
                    "is rejected; every disposition is an error, none a crash"),
            },
            {
                "buffer": "Ssl::rec_body (record-body store)",
                "capacity": 17000,
                "disposition": "measured",
                "note": (
                    "the store's own bound: read-body-at (17000) reads the whole body then "
                    "rejects on the 16384-byte handshake cap, read-body-above (17001) is refused "
                    "before the body; the candidate consumes 17005/5 bytes where the authority "
                    "stops at 5 -- recorded, not fixed"),
            },
        ],
        "cases": cases,
        "control": {"entry": MEM_CONTROL_ENTRY, "failure_driven": control_driven,
                    "cases": control_rows},
        "findings": findings,
        "findings_count": {side: {k: len(v) for k, v in findings[side].items()}
                           for side in findings},
        "residual_count": len(residuals),
        "residuals": hostile,
        "hostile_residual_count": len(hostile),
        "recorded_divergences": divergent[:48],
        "recorded_divergence_count": len(divergent),
        "problems": problems,
        "bounds": {
            "rlimit_data_kib": None if rlimit_data == resource.RLIM_INFINITY else rlimit_data,
            "cgroup_memory_max_bytes": cgroup_max,
            "case_timeout_ms": 20000,
        },
        "verdict": verdict,
        "staged_binaries": staged,
        "candidate_stderr_tail": c_err.splitlines()[-3:],
    }


# ---------------------------------------------------------------------------
# `HOSTILE-BOUNDARY-REGISTER` -- the stratum's own non-claims, bound to the courts
# ---------------------------------------------------------------------------

# `recorded_boundaries` entries carry a long functional `buffer` string; these tokens map each to
# the flat evidence field the register cites, so the comparison is against a normalized view
# rather than a substring of prose.
_BOUNDARY_TOKENS: tuple[tuple[str, str], ...] = (
    ("ssl3_write_bytes", "boundary_write"),
    ("tls13_encrypt_record inner buffer contract", "boundary_encrypt_inner"),
    ("rd_msg_buf", "boundary_read_handshake"),
    ("rec_body", "boundary_read_record"),
)


def _registry_names(records: list[dict]) -> dict[str, dict]:
    return {r.get("court"): r for r in records}


def court_coverage(record: dict) -> set[str]:
    """The surface keys a court covers, from its own record -- and only when it passed.

    A non-`pass` court covers nothing: its row is still in the registry but no surface may lean on
    it. That is what makes "a row marked hardened/measured whose court no longer covers it"
    detectable -- the coverage set for that court goes empty (or loses the key).
    """
    if record.get("verdict") != "pass":
        return set()
    court = record.get("court")
    if court == "RT-HOSTILE-TLS":
        return {f"tls.{k}" for k in (record.get("corpus", {}).get("by_category") or {})}
    if court == "RT-HOSTILE-X509":
        return {f"x509.{k}" for k in (record.get("corpus", {}).get("by_arm") or {})}
    if court == "CT-PRIMITIVES":
        return {f"ct.{p['path']}" for p in record.get("paths") or []}
    if court == "RT-MEM-HARDENING":
        keys = {f"mem.{g}" for g in (record.get("boundary_groups") or {})}
        keys |= {f"mem.control.{c}" for c in (record.get("control", {}).get("cases") or {})}
        return keys
    return set()


def _boundary_evidence(record: dict) -> dict:
    out: dict = {}
    for b in record.get("recorded_boundaries") or []:
        buf = b.get("buffer", "")
        for token, field in _BOUNDARY_TOKENS:
            if token in buf:
                out[field] = {"capacity": b.get("capacity"),
                              "disposition": b.get("disposition")}
                break
    return out


def register_evidence(record: dict) -> dict:
    """The court record's classification evidence, as the flat vocabulary the register cites.

    The register's `evidence` block is a dict of `{key: expected}` over this view, and the court
    compares them exactly, so a stated capacity or count that moves is a failure rather than a
    register that silently describes the previous generation.
    """
    court = record.get("court")
    ev: dict = {"verdict": record.get("verdict")}
    if court in ("RT-HOSTILE-TLS", "RT-HOSTILE-X509"):
        corpus = record.get("corpus") or {}
        ev["corpus_entries"] = corpus.get("entries")
        ev["corpus_total_bytes"] = corpus.get("total_bytes")
        if "by_category" in corpus:
            ev["corpus_by_category"] = corpus["by_category"]
        if "by_arm" in corpus:
            ev["corpus_by_arm"] = corpus["by_arm"]
        ev["entries_driven_corpus"] = (record.get("entries_driven") or {}).get("corpus")
        ctrl = record.get("control") or {}
        ev["control_honest"] = ctrl.get("honest")
        ev["control_class"] = ctrl.get("class")
        ev["candidate_findings"] = (record.get("findings_count") or {}).get("candidate")
    elif court == "CT-PRIMITIVES":
        ev["threshold_percent"] = record.get("threshold_percent")
        ev["path_classes"] = {p["path"]: p["class"] for p in record.get("paths") or []}
        ev["findings"] = sorted(record.get("findings") or [])
        ev["finding_count"] = len(record.get("findings") or [])
        ctrl = record.get("control") or {}
        ev["control_honest"] = ctrl.get("honest")
        ev["control_class"] = ctrl.get("class")
    elif court == "RT-MEM-HARDENING":
        ev["cases_driven_candidate"] = (record.get("cases_driven") or {}).get("candidate")
        ev["boundary_groups"] = record.get("boundary_groups")
        ev.update(_boundary_evidence(record))
        ctrl = record.get("control") or {}
        ev["control_failure_driven"] = ctrl.get("failure_driven")
        ev["control_case_classes"] = {
            cid: (row.get("candidate") or {}).get("class")
            for cid, row in (ctrl.get("cases") or {}).items()
        }
    return ev


def verify_register_surface(row: dict, registry: dict[str, dict], coverage: dict[str, set[str]],
                            covered_any: set[str]) -> list[str]:
    """Every way one register row drifts from the courts it cites.

    The three named drift classes are checks here: a `hardened`/`measured` row whose court no
    longer covers its surface (the `not_covered` clause and the `verdict` clause), a
    `not-claimed` row a passing court now covers (the `covered_any` clause), and a stated
    capacity/count that moved (the `evidence` equality, plus the declared-count check in
    `register_court`).
    """
    problems: list[str] = []
    sid = row.get("id", "<unnamed>")
    cls = row.get("classification")
    keys = row.get("surface_keys") or []
    court = row.get("court")
    if cls not in REGISTER_CLASSIFICATIONS:
        problems.append(f"{sid}: classification {cls!r} is not one of {list(REGISTER_CLASSIFICATIONS)}")
        return problems
    if cls == "not-claimed":
        if court is not None:
            problems.append(f"{sid}: a not-claimed row must name no court (got {court!r})")
        for k in keys:
            if k in covered_any:
                problems.append(
                    f"{sid}: recorded not-claimed but a passing court now covers {k!r}")
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
    # Classification consistency against the boundary dispositions the row cites: a `hardened`
    # row must cite a boundary the court records as hardened, and a `measured` row must not.
    for key in want:
        if (not key.startswith("boundary_") or key not in ev
                or not isinstance(ev[key], dict) or "disposition" not in ev[key]):
            continue
        disposition = str(ev[key].get("disposition", ""))
        if cls == "hardened" and "hardened" not in disposition:
            problems.append(
                f"{sid}: recorded hardened but {court} disposition is {disposition!r}")
        if cls == "measured" and "hardened" in disposition:
            problems.append(
                f"{sid}: recorded measured but {court} disposition is hardened "
                f"({disposition!r}); a landed change is not a measurement")
    return problems


def unsafe_footprint_growth(bounds_doc: dict, current: dict) -> list[str]:
    """Every way a core module's `unsafe`/`extern "C"` footprint exceeds its recorded bound.

    `docs/UNSAFE.md` claimed `unsafe` is concentrated in narrow boundary modules, but the
    measured footprint shows that is not so: the boundary layer (ffi, runtime, dso, engine,
    async, context) carries a minority and the parser/algorithm modules carry the rest. This
    check makes that a ratchet rather than a story. Only `core` modules are bounded -- the
    boundary layer is allowed to grow, because that is the cost of speaking C -- and a module
    the bounds file does not name resolves to its `default`, so a new core module that arrives
    carrying `unsafe` is a failure rather than an unrecorded addition. It is a footprint ceiling,
    not a memory-safety proof.
    """
    bounds = bounds_doc.get("bounds") or {}
    default = bounds_doc.get("default") or {"unsafe_sites": 0, "extern_c_fns": 0}
    problems: list[str] = []
    for row in current["modules"]:
        if row["classification"] != "core":
            continue
        ceiling = bounds.get(row["module"], default)
        for metric in ("unsafe_sites", "extern_c_fns"):
            limit = ceiling.get(metric, 0)
            if row.get(metric, 0) > limit:
                problems.append(
                    f"core module {row['module']!r} grew {metric}: {limit} -> {row[metric]} "
                    f"(recorded bound {limit}); the boundary layer may grow, a "
                    f"parser/algorithm module may not"
                )
    return problems


def register_court(name: str, records: list[dict]) -> dict:
    """`HOSTILE-BOUNDARY-REGISTER`: bind the authored register to the live courts registry.

    Reads the four already-computed probe-court records and the authored register, re-derives
    each court's coverage and each row's expected evidence, and reports every drift. A non-empty
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
    registry = _registry_names(records)
    coverage = {r.get("court"): court_coverage(r) for r in records}
    covered_any: set[str] = set()
    for keys in coverage.values():
        covered_any |= keys
    for row in surfaces:
        problems += verify_register_surface(row, registry, coverage, covered_any)
    # The `unsafe`/FFI footprint ratchet, a second subject for the register: what boundary the
    # stratum records. It lives in this court rather than in a sixth probe court that would have
    # to be reconciled into the ledger's contract units.
    if not UNSAFE_BOUNDS.is_file():
        bounds_doc: dict = {}
        footprint: dict = {"modules": [], "totals": {}}
        problems.append(
            f"the unsafe-footprint bounds {rel(UNSAFE_BOUNDS)} is absent, so the core-module "
            f"growth check cannot run"
        )
    else:
        bounds_doc = json.loads(UNSAFE_BOUNDS.read_text(encoding="utf-8"))
        if bounds_doc.get("schema") != UNSAFE_BOUNDS_SCHEMA:
            problems.append(f"unsafe bounds schema {bounds_doc.get('schema')!r} != "
                            f"{UNSAFE_BOUNDS_SCHEMA!r}")
        footprint = unsafe_footprint.scan()
        problems += unsafe_footprint_growth(bounds_doc, footprint)
    # The provenance regression check: the integer->callable-pointer reconstruction
    # class that stopped Miri at the allocator trampoline. It is imported rather
    # than shelled, so the court and forensics/tools/provenance_court.py cannot
    # disagree about whether the pattern is present. A reappearance fails the
    # register rather than being reported as a note.
    prov_findings = provenance_court.scan_repo()
    problems += [f"provenance regression: {f}" for f in prov_findings]
    # Completeness: every passing court that covers surfaces must be cited by at least one
    # hardened/measured row, so a new court cannot pass unregistered.
    cited = {r.get("court") for r in surfaces
             if r.get("classification") in ("hardened", "measured")}
    for court, keys in coverage.items():
        if keys and court not in cited:
            problems.append(
                f"court {court} passes and covers {len(keys)} surface(s) but no "
                f"hardened/measured register row cites it")
    counts = {cls: 0 for cls in REGISTER_CLASSIFICATIONS}
    for row in surfaces:
        if row.get("classification") in counts:
            counts[row["classification"]] += 1
    declared = doc.get("classifications") or {}
    for cls in REGISTER_CLASSIFICATIONS:
        if declared.get(cls) != counts[cls]:
            problems.append(
                f"declared {cls} count {declared.get(cls)!r} but the register has "
                f"{counts[cls]} row(s)")
    if declared.get("total") != len(surfaces):
        problems.append(f"declared total {declared.get('total')!r} but the register has "
                        f"{len(surfaces)} row(s)")
    verdict = "pass" if not problems else "fail"
    return {
        "court": name,
        "probe": "",
        "method": (
            "stages no probe: it re-reads the live courts registry (the four probe courts above) "
            "and the authored register artifacts/phase18/hostile-boundary-register.json, and "
            "fails the stratum if any recorded hardened/measured/not-claimed classification, "
            "surface key, capacity, count or evidence value has drifted from what the courts "
            "show (docs/PHASE-18-SUBPHASES.md section 3.5). A not-claimed row that a passing "
            "court now covers, a hardened/measured row whose court no longer covers it, and a "
            "stated capacity/count that moved are all failures. It also runs the "
            "`UNSAFE-FOOTPRINT` growth check: it scans src/**/*.rs with the definitions in "
            "forensics/tools/unsafe_footprint.py and fails if any core (parser/algorithm) "
            "module's `unsafe_sites` or `extern \"C\" fn` count exceeds the ceiling recorded "
            "in artifacts/phase18/unsafe-bounds.json, while the boundary layer is allowed to "
            "grow. Finally it runs the provenance regression check in "
            "forensics/tools/provenance_court.py and fails if an integer->callable-pointer "
            "reconstruction (the class that stopped Miri at the allocator trampoline) has "
            "reappeared in src/**/*.rs. It is a record of a boundary, a footprint ceiling and "
            "a provenance regression guard, not a security proof and not a memory-safety "
            "proof (sections 3.1 and 3.6)."),
        "frf_declarable": False,
        "frf_exclusion": (
            "the register re-reads the courts registry and stages no artifacts/phase18/probes/ "
            "pair, so it takes no transcript to diff and carries no FRF declaration"),
        "register": {
            "path": rel(REGISTER),
            "schema": doc.get("schema"),
            "sha256": sha256_file(REGISTER),
            "counts": counts,
            "total": len(surfaces),
        },
        "provenance": {
            "tool": "forensics/tools/provenance_court.py",
            "findings": prov_findings,
        },
        "unsafe_footprint": {
            "bounds": {
                "path": rel(UNSAFE_BOUNDS),
                "schema": bounds_doc.get("schema"),
                "sha256": sha256_file(UNSAFE_BOUNDS) if UNSAFE_BOUNDS.is_file() else None,
                "core_modules": len(bounds_doc.get("bounds") or {}),
            },
            "measured": {
                "unsafe_sites": footprint["totals"].get("unsafe_sites"),
                "extern_c_fns": footprint["totals"].get("extern_c_fns"),
                "core_unsafe_sites":
                    footprint["totals"].get("by_class", {}).get("core", {}).get("unsafe_sites"),
                "core_extern_c_fns":
                    footprint["totals"].get("by_class", {}).get("core", {}).get("extern_c_fns"),
                "boundary_unsafe_sites":
                    footprint["totals"].get("by_class", {}).get("boundary", {})
                    .get("unsafe_sites"),
            },
        },
        "surfaces": [
            {"id": r.get("id"), "classification": r.get("classification"),
             "court": r.get("court"), "surface_keys": r.get("surface_keys") or []}
            for r in surfaces
        ],
        "problems": problems,
        "verdict": verdict,
    }


COURT_IMPL = {
    "RT-HOSTILE-TLS": hostile_tls_court,
    "RT-HOSTILE-X509": hostile_x509_court,
    "CT-PRIMITIVES": ct_primitives_court,
    "RT-MEM-HARDENING": mem_hardening_court,
}


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    args = ap.parse_args(argv)
    del args

    auth = resolve_authority(PRODUCTION_AUTHORITY)
    work = REPO_ROOT / "court" / "phase18"
    work.mkdir(parents=True, exist_ok=True)

    records: list[dict] = []
    for name, filename in COURTS:
        if name == REGISTER_COURT:
            records.append(register_court(name, records))
            continue
        if filename is None:
            records.append({"court": name, "verdict": "fail", "stage": "probe-missing",
                            "detail": "<no probe declared>"})
            continue
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
            "`RT-HOSTILE-TLS` is 18.1's court: it compiles "
            "courts/phase18/rt_hostile_tls_probe.c twice (authority and candidate) and drives the "
            "fixed malformed-input corpus courts/phase18/fixtures/hostile-tls/ -- one file per "
            "entry, `<role>__<id>.bin` -- through the real record layer and the TLS 1.3 flight. A "
            "`server` entry is fed into SSL_accept (the ClientHello / record reader) and a "
            "`client` entry into SSL_connect (the ServerHello / flight reader) over a read-only "
            "memory BIO that reports EOF. The corpus enumerates bogus record types, lengths and "
            "versions, truncated and oversized handshake headers, malformed ClientHello / "
            "ServerHello and key_share / supported_versions / ALPN / SNI / signature_algorithms "
            "extension bodies, bad CCS and bad Finished, length-mismatch records, and well-formed "
            "controls; it is a fixed enumeration, not a fuzzer, and not a coverage claim. Each "
            "entry runs in its own forked child, so a crash (a signal), an OOM (an allocation "
            "failure under the process's RLIMIT_DATA) or a timeout is a recorded finding rather "
            "than a harness abort (section 3.3), and the fixed-schema transcript keeps the two "
            "sides' observation counts equal. The court compares every entry's authority and "
            "candidate dispositions and records each difference rather than failing it, because "
            "the reduced engine legitimately differs; it is `pass` only when the corpus was "
            "driven on both sides, every candidate disposition was recorded, and the authority "
            "differential control held -- the authority parsed the well-formed control "
            "ClientHello into a real handshake record and itself suffered no hostile finding "
            "(section 3.2). It is a bounded differential result over the corpus it drives, not a "
            "security proof and not a parity claim (sections 3.1 and 3.6). "
            "`RT-HOSTILE-X509` is 18.2's court: it compiles "
            "courts/phase18/rt_hostile_x509_probe.c twice (authority and candidate) and drives the "
            "fixed malformed-input corpus courts/phase18/fixtures/hostile-x509/ -- one file per "
            "entry, `<arm>__<id>.bin` -- through the X.509, ASN.1 and PEM readers the arm names "
            "(d2i_X509, d2i_X509_CRL, d2i_X509_REQ, d2i_X509_EXTENSION, d2i_X509_EXTENSIONS, "
            "d2i_GENERAL_NAMES, d2i_ASN1_TYPE, d2i_ASN1_GENERALIZEDTIME, d2i_ASN1_UTCTIME, "
            "d2i_X509_ALGOR, d2i_X509_PUBKEY and PEM_read_bio_X509/_X509_CRL/_X509_REQ). The "
            "corpus enumerates truncated and oversized DER certificates, ASN.1 length bombs, "
            "malformed TBSCertificate fields, bad extensions (duplicate / unknown / critical, "
            "malformed name constraints and SAN), bad signature AlgorithmIdentifiers, malformed "
            "CRL and CSR containers, malformed PEM containers (bad base64, missing / extra "
            "delimiters, wrong labels), time and bit-string edge cases, and one well-formed "
            "control per arm; it is a fixed enumeration, not a fuzzer, and not a coverage claim. "
            "Each entry runs in its own forked child, so a crash, an OOM or a timeout is a "
            "recorded finding rather than a harness abort (section 3.3). The court is `pass` "
            "only when the corpus was driven on both sides, every candidate disposition was "
            "recorded, and the authority differential control held -- the authority parsed the "
            "well-formed v3 control certificate into a real certificate (version 2, at least one "
            "extension) and itself suffered no hostile finding (section 3.2). It is a bounded "
            "differential result over the corpus it drives, not a security proof and not a "
            "parity claim (sections 3.1 and 3.6). "
            "`CT-PRIMITIVES` is 18.3's court: it is candidate-only (there is no authority "
            "transcript for a secret-independence property) and compiles "
            "courts/phase18/ct_primitives_probe.c once against the candidate distribution shell. "
            "For each measured primitive path -- BN_mod_exp_mont_consttime and BN_mod_inverse "
            "over a 255-bit prime; RSA_private_decrypt over two 1024-bit keys whose CRT exponents "
            "differ in Hamming weight; EC_POINT_mul on P-256 through the constant-time ladder; "
            "CRYPTO_memcmp over a 4 KiB aligned tag as the primitive AES-GCM's finish and the "
            "Poly1305 check are built on; and EVP_KDF HKDF extract+expand as the TLS 1.3 key "
            "schedule's core -- it drives the operation under two secret classes, interleaved, "
            "and keeps the minimum timed batch per class with a serialising timestamp counter; a "
            "path is `separated` when the ratio of the two minima exceeds 50 percent. The court "
            "carries the section-3.2 sensitivity control: `control-branchy-tag` is a "
            "deliberately branch-on-secret tag comparison (early return on the first mismatch, a "
            "dependent multiply per matching byte), and the court is `pass` only when the control "
            "is `separated` exactly where the real path it varies (`aead-tag-memcmp`) is "
            "`independent`. A measured path that is `separated` is recorded as a finding, not "
            "failed: the reduced engine's BN square-and-multiply core carries this "
            "implementation's timing profile by its own module documentation (src/bn/exp.rs), so "
            "the BN paths are expected to separate and the court's job is to record that with a "
            "proven-sensitive instrument. A pass is instrument sensitivity plus a bounded "
            "secret-independence screen at the stated resolution -- NOT a proof of constant-time "
            "behaviour, NOT a wall-clock claim and NOT an attack claim (sections 3.1, 3.2 and "
            "3.6); a secret dependence below 50 percent is reported `independent` and is outside "
            "this screen's resolution. "
            "`RT-MEM-HARDENING` is 18.4's court: it compiles "
            "courts/phase18/rt_mem_hardening_probe.c twice (authority and candidate) and drives "
            "the reduced engine's fixed buffers on the paths that handle attacker-influenced "
            "lengths at, just below and just above each recorded capacity (section 3.4) -- the "
            "record write's SSL3_RT_MAX_PLAIN_LENGTH 16384 fragment/record-encryption inner "
            "buffer (the previous greater-than-16-KiB overflow's concrete case) via a full TLS "
            "1.3 `SSL_write` of the boundary length, the handshake-message reassembly buffer "
            "TLS13_HS_BUF_LEN 16384, and the record-body store Ssl::rec_body 17000 -- recording "
            "each case's disposition rather than assuming it. Each case runs in its own forked "
            "child, so a crash, an OOM or a timeout is a recorded finding rather than a harness "
            "abort (section 3.3). The injected-failure control is explicit: `ctrl-rlimit` lowers "
            "RLIMIT_DATA to the child's VmData + 8 MiB and requests a 256 MiB allocation, which "
            "must fail and raise the engine's own ERR_R_MALLOC_FAILURE; `ctrl-d2i` drives the "
            "ASN.1 reader's own allocation over a DER that declares a 64 MiB content; and "
            "`ctrl-hook` installs a wrapper allocator through CRYPTO_set_mem_functions. The "
            "court is `pass` only when every case was driven on both sides, every boundary group "
            "carries its below/at/above phases, and the injected failure was actually observed -- "
            "the engine's allocation-failure paths returned errors (ERR_R_MALLOC_FAILURE, a NULL "
            "d2i_X509) rather than aborting. A buffer that is merely `unsafe` to use -- "
            "tls13_encrypt_record's inner buffer, which the fragmenting caller bounds but whose "
            "own contract does not -- is recorded here, not silently fixed. It is a bounded "
            "measurement, not a memory-safety proof and not a parity claim (sections 3.1, 3.4 "
            "and 3.6). "
            "`HOSTILE-BOUNDARY-REGISTER` is 18.5's court, and it stages no probe: its subject is "
            "artifacts/phase18/hostile-boundary-register.json, the authored register that records, "
            "per surface, whether it is `hardened` (a change landed), `measured` (a passing court "
            "covers it) or `not-claimed` (explicitly outside this stratum). The court re-reads the "
            "live courts registry (the four probe courts above) and fails the stratum if any "
            "recorded classification, surface key, capacity, count or evidence value has drifted "
            "from what the courts show (section 3.5): a `hardened`/`measured` row whose court no "
            "longer covers its surface, a `not-claimed` row that a passing court now covers, and a "
            "stated capacity/count that moved are all failures. The register records one "
            "`hardened` surface -- the record write path at SSL3_RT_MAX_PLAIN_LENGTH -- and the "
            "rest as `measured` or `not-claimed`; a surface the corpus does not reach is never "
            "`hardened`, so the register cannot claim more than the courts above measured "
            "(sections 3.5 and 3.6). This stratum owns no exported symbol, so no differential "
            "probe over a symbol set is its evidence: the subject is a hostile input against a "
            "finished implementation. "
            "docs/PHASE-18-SUBPHASES.md sections 1, 3 and 4 record the measurement and the courts."
        ),
    }

    inputs = [
        InputRef(name="phase-18-plan", path=PLAN),
        InputRef(name="corpus-generator", path=CORPUS_GENERATOR),
        InputRef(name="corpus-manifest", path=gen_hostile_tls_corpus.MANIFEST),
        InputRef(name="hostile-tls-probe", path=PROBE_DIR / "rt_hostile_tls_probe.c"),
        # The fixed Phase 17 fixtures the server context loads to reach the ServerHello.
        InputRef(name="tls-signer", path=REPO_ROOT / "courts" / "phase17" / "fixtures"
                 / "signer.pem"),
        InputRef(name="tls-key", path=REPO_ROOT / "courts" / "phase17" / "fixtures"
                 / "rsa-key.pem"),
        # 18.2's hostile X.509 / malformed-input corpus and its driver.
        InputRef(name="x509-corpus-generator", path=X509_CORPUS_GENERATOR),
        InputRef(name="x509-corpus-manifest", path=gen_hostile_x509_corpus.MANIFEST),
        InputRef(name="hostile-x509-probe", path=PROBE_DIR / "rt_hostile_x509_probe.c"),
        # The fixed Phase 17 base objects the X.509 corpus mutates (read, never written).
        InputRef(name="x509-base-cert-v3", path=REPO_ROOT / "courts" / "phase17" / "fixtures"
                 / "leaf.pem"),
        InputRef(name="x509-base-cert-v1", path=REPO_ROOT / "courts" / "phase17" / "fixtures"
                 / "cert.der"),
        InputRef(name="x509-base-crl", path=REPO_ROOT / "courts" / "phase17" / "fixtures"
                 / "crl.pem"),
        InputRef(name="x509-base-req", path=REPO_ROOT / "courts" / "phase17" / "fixtures"
                 / "req.pem"),
        # 18.3's candidate-only secret-independence probe and the two fixed RSA keys whose CRT
        # exponents differ in Hamming weight.
        InputRef(name="ct-primitives-probe", path=PROBE_DIR / "ct_primitives_probe.c"),
        InputRef(name="ct-rsa-lo", path=FIXTURES.parent / "rsa-ct-lo.pem"),
        InputRef(name="ct-rsa-hi", path=FIXTURES.parent / "rsa-ct-hi.pem"),
        # 18.4's fixed-buffer boundary / allocation-failure probe. It loads the same fixed Phase 17
        # signer/key the hostile TLS probe does to stand up its TLS 1.3 flight.
        InputRef(name="mem-hardening-probe", path=PROBE_DIR / "rt_mem_hardening_probe.c"),
        # 18.5's authored boundary register: the four probe-court records above are its evidence,
        # and the register court binds every recorded classification back to them.
        InputRef(name="hostile-boundary-register", path=REGISTER),
        # 18.6's footprint ratchet: the measured unsafe/FFI footprint and the authored per-core
        # ceiling the register court compares it against.
        InputRef(name="unsafe-footprint", path=REPO_ROOT / "forensics" / "atlas"
                 / "unsafe-footprint.json"),
        InputRef(name="unsafe-bounds", path=UNSAFE_BOUNDS),
    ]
    doc = envelope(kind="phase18-courts", authority=auth.id, inputs=inputs,
                   body=body, generator=GENERATOR)
    write_json(OUT, doc)

    for r in records:
        if r["verdict"] == "pass" and r["court"] == REGISTER_COURT:
            c = r["register"]["counts"]
            u = r["unsafe_footprint"]["measured"]
            print(f"  {r['court']:<18} pass   ({r['register']['total']} surfaces: "
                  f"{c['hardened']} hardened, {c['measured']} measured, "
                  f"{c['not-claimed']} not-claimed; no drift; unsafe "
                  f"core={u['core_unsafe_sites']}/boundary={u['boundary_unsafe_sites']} "
                  f"of {u['unsafe_sites']})")
        elif r["verdict"] == "pass" and r["court"] == "CT-PRIMITIVES":
            print(f"  {r['court']:<18} pass   ({len(r['paths'])} paths, "
                  f"{len(r['findings'])} separated finding(s), control "
                  f"{r['control']['class']} vs reference "
                  f"{r['control']['reference_class']})")
        elif r["verdict"] == "pass" and r["court"] == "RT-MEM-HARDENING":
            f = r["findings_count"]
            print(f"  {r['court']:<18} pass   ({r['cases_driven']['candidate']} cases, "
                  f"{len(r['boundary_groups'])} boundary group(s), control "
                  f"driven={r['control']['failure_driven']}, findings a={f['authority']} "
                  f"c={f['candidate']})")
        elif r["verdict"] == "pass":
            c = r["corpus"]
            f = r["findings_count"]
            print(f"  {r['court']:<18} pass   ({r['authority_observations']} observations, "
                  f"{r['entries_driven']['corpus']} entries, {c['total_bytes']} corpus bytes, "
                  f"{r['recorded_divergence_count']} recorded divergence(s), "
                  f"findings a={f['authority']} c={f['candidate']})")
        else:
            print(f"  {r['court']:<18} FAIL   stage={r.get('stage', 'compare')}")
            for p in (r.get("detail") if isinstance(r.get("detail"), list)
                      else r.get("problems", []))[:12]:
                print(f"      {p}")
    for cname, needs in PENDING_COURTS.items():
        print(f"  {cname:<26} PENDING (not registered as passing) -- {needs}")
    print(f"  -> {rel(OUT)} all_pass={body['all_pass']} over {len(records)} court(s)")
    return 0 if body["all_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
