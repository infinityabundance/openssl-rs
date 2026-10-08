#!/usr/bin/env python3
"""openssl-rs — the Phase-25 Docker-only execution guard.

Phase 25's whole subject is executing tools -- a compiler-backed census, Miri, ASan/MSan, TSan,
Kani, the CVE replays -- against the candidate. `docs/REPRODUCIBILITY.md` section 1 says nothing
executes on the host -- not a build, not a test, not a probe -- and for a stratum whose evidence
*is* the output of those tools that rule is load-bearing rather than procedural: a host invocation
would produce unreproducible evidence that looks entirely green. This module turns the rule into a
fact for the stratum: the Phase-25 entry points import it and call it **first**, and on a host it
refuses with a clear message rather than proceeding.

What "admitted" means
---------------------
The guard admits an invocation only when **all** of the following hold, and fails closed
otherwise:

  1. the container marker `/.dockerenv` is present -- the runtime's own marker, absent on the
     host, exactly as `forensics/tools/require_court.sh` uses it for the shell entry points;
  2. `PHASE25_CONTAINER` is `1` in the environment -- the explicit opt-in that this is the
     admitted Phase-25 venue, injected by `docker/openssl-rs-court.sh` for every `exec`;
  3. the environment records an **admitted image identity and platform** (`PHASE25_IMAGE`,
     `PHASE25_PLATFORM`) that match the committed manifest
     `forensics/memory-safety/container.json`, so an unadmitted image is refused even inside a
     container.

The detection is a pure function of `(environment, marker, manifest)`, exposed as `evaluate`, so
the self-test and the runner's self-test can hand it the shape of a host invocation and require it
to be refused without the check ever being a no-op on the machine that runs it.

The one admission that is not a container
-----------------------------------------
`metadata_only` in the manifest names the Phase-25 **generators that execute nothing** -- they read
committed atlases and write a ledger, exactly as every other stratum's obligation generator runs
host-side in CI's static job. The guard admits an invocation of one of those on any host, because
it runs no compiler, no tool and no probe; every **execution** entry point (the runner
`phase25_courts.py`, and every later subphase tool that compiles, instruments, proves or replays)
is absent from the list and is refused on the host. The set is committed, so widening it is a
reviewable act rather than a silent one.

Outputs
-------
  (none) — this module writes no artefact; it is imported by the Phase-25 ledger and runner, and
  run with `--self-test` / `--check`.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import REPO_ROOT, rel  # noqa: E402

MANIFEST = REPO_ROOT / "forensics" / "memory-safety" / "container.json"
DOCKERENV = Path("/.dockerenv")

# Defaults read from the manifest at runtime; these are the fallback names, never a second source
# of truth for the admitted values.
ENV_FLAG = "PHASE25_CONTAINER"
ENV_IMAGE = "PHASE25_IMAGE"
ENV_PLATFORM = "PHASE25_PLATFORM"

REFUSAL_EXIT = 97


class GuardError(RuntimeError):
    """A manifest that does not name an admitted venue, with the reason."""


def load_manifest() -> dict:
    """The committed container manifest, or a fail-closed error.

    An absent or malformed manifest is fatal rather than defaulted: a missing file would otherwise
    silently re-introduce "whatever container happens to be running", which is the second source
    of truth this file removes.
    """
    if not MANIFEST.is_file():
        raise GuardError(
            f"the Phase-25 container manifest {rel(MANIFEST)} is absent; the admitted venue is "
            f"unknown, so the guard fails closed"
        )
    try:
        body = json.loads(MANIFEST.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise GuardError(f"{rel(MANIFEST)} is not valid JSON: {exc}") from exc
    for field in ("image", "platform", "marker", "env_flag", "env_image", "env_platform"):
        if not body.get(field):
            raise GuardError(f"{rel(MANIFEST)} does not name {field!r}")
    return body


def _manifest_or_problems(manifest: dict | None) -> tuple[dict, list[str]]:
    if manifest is not None:
        return manifest, []
    try:
        return load_manifest(), []
    except GuardError as exc:
        return {}, [str(exc)]


def entry_point_name() -> str:
    """The basename of the entry point this process is running as."""
    return Path(sys.argv[0]).name


def evaluate(
    *,
    env: dict | None = None,
    dockerenv: bool | None = None,
    manifest: dict | None = None,
    entry_point: str | None = None,
) -> dict:
    """Decide whether this invocation is admitted, and why not when it is not.

    Pure over its arguments so a caller can hand in the shape of a host invocation and require the
    refusal deterministically. `dockerenv` defaults to the real marker, `env` to `os.environ`,
    `manifest` to the committed file, and `entry_point` to `sys.argv[0]`'s basename.
    """
    env = dict(os.environ if env is None else env)
    marker_present = DOCKERENV.is_file() if dockerenv is None else bool(dockerenv)
    man, problems = _manifest_or_problems(manifest)
    ep = entry_point or entry_point_name()

    reasons = list(problems)

    # The metadata-only admission. It is a property of the manifest, and it is named so an audit
    # can see exactly which entry points are admitted without an admitted container.
    metadata_only = list(man.get("metadata_only") or [])
    if ep in metadata_only:
        return {
            "admitted": True,
            "venue": "metadata-only",
            "entry_point": ep,
            "reasons": [],
            "identity": {"image": None, "platform": None, "marker": None, "flag": None},
            "note": (f"{ep} is listed `metadata_only` in {rel(MANIFEST)}: it executes nothing "
                     f"(no compiler, no tool, no probe), so it is admitted on any host exactly as "
                     f"the other strata's obligation generators are"),
        }

    flag = str(man.get("env_flag") or ENV_FLAG)
    image_var = str(man.get("env_image") or ENV_IMAGE)
    platform_var = str(man.get("env_platform") or ENV_PLATFORM)

    if not marker_present:
        reasons.append(
            f"the container marker {man.get('marker') or DOCKERENV} is absent, so this is a host "
            f"invocation"
        )
    if env.get(flag) != "1":
        reasons.append(
            f"{flag} is not `1` in the environment, so this venue is not an admitted Phase-25 "
            f"container"
        )
    image = env.get(image_var)
    if image is None:
        reasons.append(f"{image_var} is not recorded in the environment")
    elif image != man.get("image"):
        reasons.append(
            f"{image_var}={image!r} is not the admitted image {man.get('image')!r}"
        )
    platform = env.get(platform_var)
    if platform is None:
        reasons.append(f"{platform_var} is not recorded in the environment")
    elif platform != man.get("platform"):
        reasons.append(
            f"{platform_var}={platform!r} is not the admitted platform {man.get('platform')!r}"
        )

    return {
        "admitted": not reasons,
        "venue": "container" if not reasons else "refused",
        "entry_point": ep,
        "reasons": reasons,
        "identity": {
            "image": man.get("image"),
            "platform": man.get("platform"),
            "marker": man.get("marker") or str(DOCKERENV),
            "flag": flag,
        },
        "note": "",
    }


def admitted(**kwargs) -> bool:
    """Whether the invocation is admitted (the boolean form of `evaluate`)."""
    return bool(evaluate(**kwargs)["admitted"])


def reasons(**kwargs) -> list[str]:
    """The refusal reasons for an invocation, empty when it is admitted."""
    return list(evaluate(**kwargs)["reasons"])


def require_admitted(
    *,
    entry_point: str | None = None,
    env: dict | None = None,
    dockerenv: bool | None = None,
    manifest: dict | None = None,
) -> None:
    """Refuse the host with a clear message unless the venue is admitted.

    The exit code matches `forensics/tools/require_court.sh` (97), so a shell and a Python entry
    point refuse the host the same way.
    """
    result = evaluate(env=env, dockerenv=dockerenv, manifest=manifest, entry_point=entry_point)
    if result["admitted"]:
        return
    ep = result["entry_point"]
    lines = [
        f"REFUSED: Phase 25 entry point {ep} must run inside the admitted court container.",
        "",
        "  Nothing in this stratum executes on the host -- not a census, not a sanitizer, not a",
        "  proof, not a replay. See docs/REPRODUCIBILITY.md section 1.",
        "",
        "  Run it through the venue instead, from the repository root:",
        "",
        "    bash docker/openssl-rs-court.sh exec sh -c 'cd /work && <cmd>'",
        "",
        "  the guard refused because:",
    ]
    lines += [f"    - {r}" for r in result["reasons"]]
    print("\n".join(lines), file=sys.stderr)
    raise SystemExit(REFUSAL_EXIT)


def host_refusal_reasons(entry_point: str = "phase25_courts.py") -> list[str]:
    """The reasons a synthetic host invocation of an execution entry point is refused.

    Exposed so the runner's self-test proves a host invocation is refused without running on a
    host: `entry_point` defaults to the runner, which the manifest deliberately does not list as
    `metadata_only`.
    """
    return reasons(env={}, dockerenv=False,
                   manifest=load_manifest(), entry_point=entry_point)


def self_test() -> int:
    """Prove the guard refuses a host invocation and admits only the admitted venue."""
    failures: list[str] = []
    manifest = load_manifest()
    good_env = {
        str(manifest["env_flag"]): "1",
        str(manifest["env_image"]): str(manifest["image"]),
        str(manifest["env_platform"]): str(manifest["platform"]),
    }

    # 1. A host invocation of an execution entry point is refused, and the reasons name both the
    #    marker and the opt-in flag rather than passing silently.
    host = evaluate(env={}, dockerenv=False, manifest=manifest,
                    entry_point="phase25_courts.py")
    if host["admitted"]:
        failures.append("a host invocation of phase25_courts.py was admitted")
    joined = " ".join(host["reasons"])
    if str(manifest["marker"]) not in joined:
        failures.append("the host refusal does not name the container marker")
    if str(manifest["env_flag"]) not in joined:
        failures.append("the host refusal does not name the opt-in flag")

    # 2. The admitted venue is admitted.
    venue = evaluate(env=good_env, dockerenv=True, manifest=manifest,
                     entry_point="phase25_courts.py")
    if not venue["admitted"]:
        failures.append(f"the admitted venue was refused: {venue['reasons']}")

    # 3. A container with the flag but the wrong image is refused: the identity is checked, not
    #    merely the marker.
    wrong = dict(good_env, **{str(manifest["env_image"]): "some-other-image:1"})
    if evaluate(env=wrong, dockerenv=True, manifest=manifest,
                entry_point="phase25_courts.py")["admitted"]:
        failures.append("an unadmitted image was admitted")

    # 4. A container with the marker but no opt-in flag is refused.
    no_flag = {k: v for k, v in good_env.items() if k != manifest["env_flag"]}
    if evaluate(env=no_flag, dockerenv=True, manifest=manifest,
                entry_point="phase25_courts.py")["admitted"]:
        failures.append("a container without the opt-in flag was admitted")

    # 5. The metadata-only entry point is admitted on a host, and named as such.
    meta = evaluate(env={}, dockerenv=False, manifest=manifest,
                    entry_point="phase25_obligations.py")
    if not meta["admitted"] or meta["venue"] != "metadata-only":
        failures.append("the metadata-only ledger generator was not admitted as metadata-only")

    # 6. The guard's own default entry point is not metadata-only, so a host run of it refuses.
    if evaluate(env={}, dockerenv=False, manifest=manifest,
                entry_point="phase25_guard.py")["admitted"]:
        failures.append("a host run of phase25_guard.py was admitted")

    if failures:
        print("[phase25-guard] self-test FAILED")
        for f in failures:
            print(f"  {f}")
        return 1
    print("[phase25-guard] self-test ok: a host invocation of the runner is refused (marker and "
          "flag both named), the admitted venue is admitted, an unadmitted image and a missing "
          "opt-in flag are each refused, the metadata-only ledger generator is admitted as "
          "metadata-only, and a host run of the guard itself is refused")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--self-test", action="store_true",
                    help="prove a host invocation is refused and only the admitted venue passes")
    ap.add_argument("--check", action="store_true",
                    help="enforce the guard for this invocation (the default)")
    ap.add_argument("--entry-point", default=None,
                    help="the entry point name to evaluate (default: this process's basename)")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()

    # The default action is the enforcement (`--check`), so an entry point that runs the module
    # without a flag is guarded rather than silently doing nothing.
    result = evaluate(entry_point=args.entry_point)
    if result["admitted"]:
        print(f"[phase25-guard] admitted ({result['venue']}): entry point "
              f"{result['entry_point']}, image {result['identity']['image']}, "
              f"platform {result['identity']['platform']}")
        if result["note"]:
            print(f"  {result['note']}")
        return 0
    require_admitted(entry_point=args.entry_point)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
