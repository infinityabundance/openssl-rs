#!/usr/bin/env python3
"""openssl-rs — Phase 9 courts: RAND, the DRBGs and the entropy sources.

Each court is a C probe in `courts/phase9/` compiled **twice** — once against the admitted
authority, once against the candidate distribution shell — and run. The two transcripts are
compared line by line, and every difference is a residual.

The method is Phases 3-8's, for the same reason: a unit test encodes what its author believes
the contract is, whereas a probe measures what the authority actually does, and the comparison is
between two *executions* of the same program, so the expectation cannot drift.

What a differential court can establish here, and what it cannot
----------------------------------------------------------------
A probe can compare, byte for byte: the parameters a DRBG reports, the refusal reason and
coordinate for every invalid-parameter arm, the state transitions (`EVP_RAND_STATE_ERROR` after a
failed instantiate, `_READY` after a successful one), the reseed-interval boundary, the observable
refusal of the prediction-resistance path, and -- with a `TEST-RAND` row and a fixed seed -- the
exact bytes both sides produce. It **cannot** establish that either side's output is
unpredictable, because that is a property of the seeding pool rather than of a transcript.
`docs/PHASE-9-SUBPHASES.md` section 3.3 records that as not courted rather than leaving it
implied; a court that compared pool *contents* would be comparing two machines.

`RT-DRBG` and what its first run found
--------------------------------------
`rt_drbg_probe.c` drives the three default-provider DRBG rows through the public `EVP_RAND_*`
surface: fetch, name, the settable/gettable parameter lists, the algorithm set each row needs
before it will instantiate, the state machine, a generate, a re-instantiate, `verify_zeroization`,
`uninstantiate` and the refusal arms (generate before instantiate, instantiate an errored context,
an over-strong strength, an algorithm name no provider answers).

On its first run it produced **180 residual lines** and every one of them was the same defect:
the candidate refused every instantiation with `PROV_R_ERROR_RETRIEVING_NONCE` while the
authority succeeded. The cause was a chain of two missing links, both now landed:
`ossl_lib_ctx_get_data(NULL, OSSL_LIB_CTX_DRBG_NONCE_INDEX)` answered NULL because `context_init`
never built the slot, and the core published none of the eight seeding callbacks the provider
seeks entropy and nonces through. That is the shape this stratum's evidence is for: the failure
was invisible to source comparison and unambiguous to a transcript.

`RT-RAND` and why it is a separate court from `RT-DRBG`
-----------------------------------------------------
`rt_rand_probe.c` drives `rand.h`'s twenty-five exports: the legacy `RAND_METHOD` table and its
identity, the public/private byte sources, the per-`OSSL_LIB_CTX` DRBG handles, the configuration
setters, the mixing entry points and the seed-file helpers. It is not a subset of `RT-DRBG` and
`RT-DRBG` is not a subset of it: one courts the provider's DRBG *rows* through `EVP_RAND_*`, the
other courts the `RAND_*` *library front* those rows sit behind. Three of the front's entries
dispatch in both directions -- `RAND_bytes_ex` reaches a nominated randomness provider, and the
file helpers reach `RAND_status` -- so the two courts would still not overlap even if the probe
sources were merged. The order inside `rt_rand_probe.c` is load-bearing and is argued in its own
header: each setter is observed both before and after the object it guards exists, because
`RAND_set_DRBG_type` refuses with `RAND_R_ALREADY_INSTANTIATED` once the primary is built and a
probe that only called it late would measure the refusal on both sides and prove nothing.

`RT-BN-RAND` and why it observes properties rather than values
-------------------------------------------------------------
`rt_bn_rand_probe.c` drives three of Phase 5's hand-offs to this stratum: `crypto/bn/bn_rand.c`'s
public family -- the ten draw entry points, their `_ex` and deprecated spellings, and the range
family -- and, since D324, `crypto/bn/bn_blind.c`'s blinding family and `crypto/bn/bn_prime.c`'s
prime generators and primality tests. It **cannot** compare a drawn or generated value: the two
sides seed from different pools, so a byte comparison would compare two machines. It compares each
arm's *contract* instead -- the return code, the error queue, `BN_num_bits(rnd) <= bits`, the pinned
top/bottom bits, and `BN_cmp(rnd, range) < 0` for the range family -- and at `bits = 1` and
`bits = 2` the masks pin the value exactly, so those two arms observe the mask arithmetic itself
rather than a property of it. The same rule governs the two families D324 added: a generated prime
is observed by its width, its pinned bits, its primality answer and its X9.31 congruences, never by
its value, and a blinding pair by the identity it must satisfy rather than by the numbers in it.
Every draw is made twice, once with no `BN_CTX` and once with a live one, because `bnrand` reads its
context's library context through `ossl_bn_get_libctx` and hands it to `RAND_bytes_ex`; the refusal
arms are the other half, since a draw that silently answered zero where the authority raised looks
identical in a success-only transcript.

`RT-RAND-USERS` and why the random layer's callers are a separate court
----------------------------------------------------------------------
`rt_rand_users_probe.c` drives the first two names Phase 9 inherited from Phase 7 --
`EVP_CIPHER_CTX_rand_key` and `EVP_SealInit` -- which are not the RAND front but *callers* of it,
and the thing worth measuring is that they call it the way the authority does (right `libctx`,
right length, right refusal). The draws are unobservable, so it compares the contract: the key
and IV lengths the context reports before and after, whether a cipher is installed, and the error
queue. `EVP_SealInit`'s four early-return arms are all deterministic and none needs a public key
(`npubk <= 0` answers 1, `npubk < 0` answers 1, a NULL `type` answers 1, and a positive `npubk`
with a NULL `pubk` answers 1). **The `npubk > 0` path with a real key is not courted and is
recorded as owed**: it needs an `EVP_PKEY` with a public part, which the crate can build only once
RSA key construction and the ASN.1 public-key decoder land, and the authority's own
`EVP_PKEY_get_size(NULL)` on that path is a null dereference, so a probe must not reach it with a
NULL key either.

`OSSL_HPKE_get_grease_value` was transcribed and measured in D316 and **did not land**, and this
court is where that is visible: the probe prints a `NOT_MEASURED` line for it rather than staying
silent. Its success path calls `OSSL_HPKE_keygen`, which fetches a keymgmt **by name from the
library context**, and the default provider's `OSSL_OP_KEYMGMT X25519` row is unimplemented and
Phase 8's; `RT-HPKE` never sees that because it deliberately runs in a private `OSSL_LIB_CTX`
carrying its own test provider, so that court measures the HPKE *framework* and this one measures
the default provider's algorithm universe.

SPDX-License-Identifier: Apache-2.0"""

from __future__ import annotations

import argparse
import json
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

OUT = REPO_ROOT / "artifacts" / "phase9" / "COURTS.json"
GENERATOR = "forensics/tools/phase9_courts.py"
PROBE_DIR = REPO_ROOT / "courts" / "phase9"
PHASE2 = REPO_ROOT / "artifacts" / "phase2"
STAGED = REPO_ROOT / "artifacts" / "phase9" / "probes"
RUN_TIMEOUT_S = "60"

# The differential courts, in the order they land. `(name, probe filename)`, and the probe is
# declared in the same commit as the entry, so a runner that names a probe which does not exist
# cannot be committed -- the check below fails instead.
COURTS: list[tuple[str, str]] = [
    ("RT-DRBG", "rt_drbg_probe.c"),
    ("RT-RAND", "rt_rand_probe.c"),
    ("RT-BN-RAND", "rt_bn_rand_probe.c"),
    ("RT-RAND-USERS", "rt_rand_users_probe.c"),
]

# A court the plan names and this stratum cannot run yet. Not a registered court: nothing here
# can pass, and each is printed with the subphase that brings it so that "not run yet" cannot be
# read as "passed".
PENDING_COURTS: dict[str, str] = {
    "CT-DRBG": "9.4 -- the DRBGs' construction vectors, which the pinned tree already carries: "
               "`test/recipes/30-test_evp_data/evprand.txt` mirror the NIST CAVP "
               "`drbgtestvectors.zip` sets, with the URL written in the file, and "
               "`evpkdf_hmac_drbg.txt` carries the HMAC-DRBG KDF cases. No network fetch is "
               "needed and none is permitted (docs/AUTHORITY_POLICY.md).",
}


def extra_defs(name: str, libdir: Path) -> list[str]:
    """Per-side build definitions.

    **None.** Every observation RT-DRBG makes is a return code, a state, a name, a parameter
    key/type pair or an `ERR_GET_LIB`/`ERR_GET_REASON` pair, so the probe is compiled identically
    on both sides and a difference in the transcript can only be a difference in behaviour.
    `extra_defs` is kept because the runner's shape is Phase 8's and a later court here may need
    one.
    """
    del name, libdir
    return []


def compile_probe(
    src: Path, out: Path, include: Path, libdir: Path, defs: list[str] | None = None
) -> tuple[bool, str]:
    res = run([
        # `-Werror=implicit-function-declaration` is not decoration: without a prototype, C
        # assumes a function returns `int`, so a probe that forgot an include reads a pointer
        # return as its low 32 bits and dereferences it. Phases 6 and 7 both paid a run to learn
        # that, so it is a compile failure here.
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
    """Line-wise comparison keyed on `key=value`, so a missing or extra line
    produces exactly one residual instead of shifting every following line."""
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
    # A probe that died on a signal compared nothing beyond the prefix it managed
    # to print, so two sides dying the same way is not agreement.
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
    work = REPO_ROOT / "court" / "phase9"
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
            "A passing RT-* court means the candidate produced the same observable "
            "transcript as the authority for the behaviours that probe exercises "
            "-- differential compatibility, NOT that its output is unpredictable "
            "(docs/PARITY_MODEL.md, docs/PHASE-9-SUBPHASES.md section 3.3). "
            "`pending_courts` names the courts the plan gives this stratum that have "
            "not landed; each is printed on every run so that 'not run yet' cannot be "
            "read as 'passed'."
        ),
    }

    inputs = [
        InputRef(name="authority-symbols", path=REPO_ROOT / "forensics" / "atlas"
                 / auth.id / "symbols-libcrypto.json"),
    ]
    for _name, filename in COURTS:
        inputs.append(InputRef(name="probe", path=PROBE_DIR / filename))
    doc = envelope(kind="phase9-courts", authority=auth.id, inputs=inputs,
                   body=body, generator=GENERATOR)
    write_json(OUT, doc)

    for r in records:
        if r["verdict"] == "pass":
            print(f"  {r['court']:<14} pass   "
                  f"({r['authority_observations']} observations)")
        else:
            print(f"  {r['court']:<14} FAIL   stage={r.get('stage', 'compare')}")
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
        print(f"  {name:<14} PENDING (not registered as passing) -- {needs}")
    print(f"  -> {rel(OUT)} all_pass={body['all_pass']} over {len(records)} court(s)")
    return 0 if body["all_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
