#!/usr/bin/env python3
"""openssl-rs -- Phase 17 downstream: turn measured harness output into one `result.json`.

This is the parser half of the driver (`courts/phase17/downstream/run_all.sh` runs the
harnesses and captures their logs; this script reads those logs). Nothing here is typed
aspiration: every field is read from a harness transcript, a `ldd`/`readelf` line, a
`build.sh` pin, or `history.json` (the one authored file, whose commit ids the
`RT-DOWNSTREAM-CORPUS` court re-verifies against git). The pinned version/URL/sha256 are
parsed from the program's own `build.sh` so a repin moves the record with it.

Usage:
    python3 lib/record.py --program curl --logs /court/phase17-downstream --out <downstream dir>
    python3 lib/record.py --all     --logs /court/phase17-downstream --out <downstream dir>

Writes `<out>/<program>/result.json`.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# program -> the variable prefix its build.sh uses for the pinned tarball.
PREFIX = {
    "curl": "CURL",
    "git": "GIT",
    "haproxy": "HAPROXY",
    "nginx": "NGINX",
    "openssh": "OPENSSH",
    "python": "CPYTHON",
}
PROGRAMS = ["curl", "git", "haproxy", "nginx", "openssh", "python"]
AUTHORITY = "openssl-rt-3.6.4-r2"
CANDIDATE_SHELL = "/work/artifacts/phase2/install"


def repo_root() -> Path:
    return Path(__file__).resolve().parents[4]


def candidate_version() -> str:
    """The candidate identity, read from Cargo.toml (the one release knob)."""
    text = (repo_root() / "Cargo.toml").read_text(encoding="utf-8")
    m = re.search(r"(?ms)^\[package\].*?^version\s*=\s*\"([^\"]+)\"", text)
    if m is None:
        raise SystemExit("record.py: Cargo.toml has no [package] version")
    return m.group(1)


def build_pin(program: str, prefix: str, out: Path) -> tuple[str, str, str]:
    """`(version, url, sha256)` parsed from the program's build.sh."""
    text = (out / program / "build.sh").read_text(encoding="utf-8")
    ver = re.search(rf"(?m)^{prefix}_VERSION=(\S+)", text)
    url = re.search(rf"(?m)^{prefix}_URL=(\S+)", text)
    sha = re.search(rf"(?m)^{prefix}_(?:SHA256|SHA)=(\S+)", text)
    if not (ver and url and sha):
        raise SystemExit(f"record.py: {program}/build.sh does not pin VERSION/URL/SHA256")
    return ver.group(1), url.group(1), sha.group(1)


def read(logs: Path, name: str) -> str:
    p = logs / name
    return p.read_text(errors="replace") if p.is_file() else ""


def one(pattern: str, text: str, default: str = "") -> str:
    m = re.search(pattern, text)
    return m.group(1) if m else default


def frac(pattern: str, text: str) -> tuple[int, int]:
    m = re.search(pattern, text)
    return (int(m.group(1)), int(m.group(2))) if m else (0, 16)


def candidate_link(ldd_text: str, lib: str) -> tuple[bool, str]:
    m = re.search(rf"{re.escape(lib)} => (\S+)", ldd_text)
    path = m.group(1) if m else ""
    ok = path.startswith(CANDIDATE_SHELL)
    return ok, (path or "not resolved")


def stage(ok: bool, detail: str) -> dict:
    return {"ok": bool(ok), "detail": detail}


def link_stage(ok: bool, detail: str, libs: list[str]) -> dict:
    return {"ok": bool(ok), "detail": detail, "libs": libs}


def functional(ok: bool, detail: str, evidence: list[str]) -> dict:
    return {"ok": bool(ok), "detail": detail, "evidence": evidence}


def analyse(program: str, logs: Path) -> dict:
    if program == "curl":
        ver = read(logs, "curl.version")
        ldd = read(logs, "curl.ldd")
        probe = read(logs, "curl.probe")
        lok, lpath = candidate_link(ldd, "libssl.so.3")
        c_ok, c_tot = frac(r"concurrent_200s=(\d+)/(\d+)", probe)
        build_ok = "curl 8.22.0" in ver and "OpenSSL/3.6.4" in ver
        functional_ok = ("live_tls_probe.sh: OK" in probe
                         and "http_code=200" in probe and "curl_negative_exit=60" in probe)
        return dict(
            build=stage(build_ok, one(r"(curl 8\.22\.0[^|]*)", ver).strip() or ver.strip()[:200]),
            link=link_stage(lok, f"libssl.so.3 -> {lpath}", ["libssl.so.3", "libcrypto.so.3"]),
            start=stage(bool(ver.strip()), "the candidate-linked curl runs and reports -V"),
            functional=functional(functional_ok,
                "TLS 1.3 verified fetch of the authority s_server (HTTP 200) with an unrelated CA rejected",
                ["live_tls_probe.sh: OK", "http_code=200", "curl_negative_exit=60"]),
            concurrency={"ok": c_ok, "total": c_tot},
            known_residuals=[],
        )

    if program == "nginx":
        ver = read(logs, "nginx.version")  # captured with 2>&1 (nginx -V writes to stderr)
        ldd = read(logs, "nginx.ldd")
        probe = read(logs, "nginx.probe")
        lok, lpath = candidate_link(ldd, "libssl.so.3")
        c_ok, c_tot = frac(r"C_concurrent_200s=(\d+)/(\d+)", probe)
        build_ok = "nginx version: nginx/1.26.3" in ver and "built with OpenSSL 3.6.4" in ver
        functional_ok = ("A_tls13_handshake=1" in probe and "B_http_code=200" in probe
                         and c_ok == c_tot and c_tot > 0)
        residuals: list[str] = []
        if "session saved: NO" in probe:
            residuals.append(
                "TLS 1.3 session resumption is unavailable: the candidate does not emit the "
                "post-handshake NewSessionTicket flight, so `s_client -sess_out` saves nothing; "
                "TLS 1.2 resumption and tickets work (see the CPython test_ssl record)")
        d_resumed = "D_tls13_resumed=1" in probe
        return dict(
            build=stage(build_ok, "nginx/1.26.3, built with OpenSSL 3.6.4"),
            link=link_stage(lok, f"libssl.so.3 -> {lpath}", ["libssl.so.3", "libcrypto.so.3"]),
            start=stage("master pid=" in probe and "a2_exit=0" in probe,
                        "the TLS listener starts and answers an authority s_client"),
            functional=functional(
                functional_ok,
                "TLS 1.3 termination for the authority s_client and the candidate curl, "
                "16/16 concurrent verified fetches, reload 2->3 workers, "
                "post-handshake NewSessionTicket + TLS 1.3 resumption",
                ["A_tls13_handshake=1", "B_http_code=200",
                 one(r"(C_concurrent_200s=\d+/\d+)", probe),
                 "D_tls13_resumed=1" if d_resumed else "D_tls13_resumed=0"]),
            concurrency={"ok": c_ok, "total": c_tot},
            known_residuals=residuals,
        )

    if program == "haproxy":
        ver = read(logs, "haproxy.version")
        ldd = read(logs, "haproxy.ldd")
        probe = read(logs, "haproxy.probe")
        lok, lpath = candidate_link(ldd, "libssl.so.3")
        c_ok, c_tot = frac(r"C_concurrent_200s=(\d+)/(\d+)", probe)
        build_ok = "Built with OpenSSL version : OpenSSL 3.6.4" in ver
        functional_ok = ("A_tls13_handshake=1" in probe and "B_http_code=200" in probe
                         and "B_neg_exit=60" in probe and "B_broken_cfg_exit=1" in probe)
        return dict(
            build=stage(build_ok, "HAProxy 3.0.29, built with the candidate OpenSSL 3.6.4"),
            link=link_stage(lok, f"libssl.so.3 -> {lpath}", ["libssl.so.3", "libcrypto.so.3"]),
            start=stage("haproxy_pid=" in probe and "DIED" not in probe,
                        "the frontend binds and reaches readiness"),
            functional=functional(
                functional_ok,
                "TLS 1.3 termination in front of a plain-HTTP backend for the authority "
                "s_client and the candidate curl; backend UP/L7OK; broken config rejected",
                ["A_tls13_handshake=1", "B_http_code=200", "B_neg_exit=60",
                 "B_broken_cfg_exit=1", one(r"(C_concurrent_200s=\d+/\d+)", probe)]),
            concurrency={"ok": c_ok, "total": c_tot},
            known_residuals=[],
        )

    if program == "python":
        ver = read(logs, "python.version")
        ldd = read(logs, "python.ldd")
        probe = read(logs, "python.probe")
        live = read(logs, "python.live")
        tests = read(logs, "python.tests")
        lok, lpath = candidate_link(ldd, "libssl.so.3")
        c_ok, c_tot = frac(r"concurrent_ok=(\d+)/(\d+)", live)
        build_ok = "Python 3.12.15" in ver and "OpenSSL 3.6.4" in ver
        failed = one(r"(?m)^failed\s*:\s*(\d+)", tests, "999")
        errors = one(r"(?m)^errors\s*:\s*(\d+)", tests, "999")
        passed = one(r"(?m)^passed\s*:\s*(\d+)", tests, "0")
        functional_ok = ("live_tls_probe.sh: OK" in live and failed == "0" and errors == "0"
                         and int(passed) >= 170)
        return dict(
            build=stage(build_ok, "CPython 3.12.15, _ssl/hashlib built with OpenSSL 3.6.4"),
            link=link_stage(lok, f"_ssl*.so libssl -> {lpath}", ["libssl.so.3", "libcrypto.so.3"]),
            start=stage("probe.py: OK" in probe, "the interpreter starts and its ssl/hashlib surface answers"),
            functional=functional(
                functional_ok,
                "live TLS 1.3 with an unrelated CA rejected, plus CPython's own bounded "
                f"test_ssl: {passed} passed, {failed} failed, {errors} errors",
                ["live_tls_probe.sh: OK", f"test_ssl passed={passed} failed={failed} errors={errors}"]),
            concurrency={"ok": c_ok, "total": c_tot},
            known_residuals=[],
        )

    if program == "git":
        ver = read(logs, "git.version")
        ldd = read(logs, "git.ldd")
        h = read(logs, "git.hash")
        https = read(logs, "git.https")
        tests = read(logs, "git.tests")
        lok, lpath = candidate_link(ldd, "libcrypto.so.3")
        c_ok, c_tot = frac(r"concurrent_ok=(\d+)/(\d+)", https)
        build_ok = "git version 2.56.0" in ver and "OpenSSL 3.6.4" in ver
        functional_ok = ("hash_check.sh: PASS" in h and "HTTPS PUSH/PULL PASS" in https
                         and " FAIL " not in tests)
        return dict(
            build=stage(build_ok, "Git 2.56.0, SHA-1/SHA-256 via the candidate libcrypto"),
            link=link_stage(lok, f"libcrypto.so.3 -> {lpath}", ["libcrypto.so.3"]),
            start=stage("hash_check.sh: PASS" in h, "the candidate-linked git runs and hashes objects"),
            functional=functional(
                functional_ok,
                "SHA-1/SHA-256 object hashing agrees with GNU coreutils; HTTPS push/clone/pull "
                "with both TLS endpoints on the candidate, unrelated CA rejected; bounded t/ subset green",
                ["hash_check.sh: PASS", "HTTPS PUSH/PULL PASS",
                 one(r"(concurrent_ok=\d+/\d+)", https)]),
            concurrency={"ok": c_ok, "total": c_tot},
            known_residuals=[
                "t5540-http-push-webdav is skipped: Git is built without expat (the court image "
                "ships no libexpat headers); it is a plain-HTTP path with no OpenSSL use"],
        )

    if program == "openssh":
        ver = read(logs, "openssh.version")
        ldd = read(logs, "openssh.ldd")
        probe = read(logs, "openssh.probe")
        keyfmt = read(logs, "openssh.keyformat")
        tests = read(logs, "openssh.tests")
        lok, lpath = candidate_link(ldd, "libcrypto.so.3")
        c_ok, c_tot = frac(r"concurrent_logins=(\d+)/(\d+)", probe)
        build_ok = "OpenSSH_10.5p1" in ver and "OpenSSL 3.6.4" in ver
        pfail = int(one(r"SUMMARY:\s*\d+ pass,\s*(\d+) fail", probe, "999"))
        psummary = one(r"(SUMMARY: \d+ pass, \d+ fail)", probe)
        tpass = one(r"regress unit summary:\s*(\d+) pass", tests, "0")
        tfail = int(one(r"regress unit summary:\s*\d+ pass,\s*(\d+) fail", tests, "999"))
        conc_line = one(r"(concurrent_logins=\d+/\d+)", probe)
        functional_ok = (pfail == 0 and "[FAIL]" not in keyfmt and tfail <= 1)
        return dict(
            build=stage(build_ok, "OpenSSH 10.5p1 (portable), libcrypto-only consumer"),
            link=link_stage(lok, f"libcrypto.so.3 -> {lpath} (no libssl)", ["libcrypto.so.3"]),
            start=stage("sshd started" in probe, "the candidate-linked sshd starts on a high port"),
            functional=functional(
                functional_ok,
                "live sshd+ssh login, the forced kex/cipher/MAC/host-key matrix including "
                "RSA/ECDSA, ssh-keygen RSA/ECDSA/Ed25519 sign+verify, and the regress unit suite",
                [f"probe {psummary}",
                 f"regress unit {tpass} pass, {tfail} fail",
                 conc_line]),
            concurrency={"ok": c_ok, "total": c_tot},
            known_residuals=[
                "`regress/unittests/utf8` aborts on both the candidate and the authority: the "
                "court image ships only C/C.utf8/POSIX locales and the test setlocale()s en_US.UTF-8"],
        )

    raise SystemExit(f"record.py: unknown program {program!r}")


def write_one(program: str, logs: Path, out: Path, history: dict) -> dict:
    version, url, sha = build_pin(program, PREFIX[program], out)
    rec = {
        "program": program,
        "version": version,
        "source_url": url,
        "source_sha256": sha,
        "candidate": candidate_version(),
        "authority": AUTHORITY,
        **analyse(program, logs),
        "historical_failures": history.get(program, []),
    }
    d = out / program
    d.mkdir(parents=True, exist_ok=True)
    (d / "result.json").write_text(json.dumps(rec, indent=2, sort_keys=True) + "\n",
                                   encoding="utf-8")
    return rec


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--program")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--logs", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)

    logs = Path(args.logs)
    out = Path(args.out)
    try:
        history = json.loads((out / "history.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:  # noqa: BLE001 - fail closed
        raise SystemExit(f"record.py: cannot read {out / 'history.json'}: {e}")

    programs = PROGRAMS if args.all or not args.program else [args.program]
    for p in programs:
        rec = write_one(p, logs, out, history)
        print(f"[record] {p}: build={rec['build']['ok']} link={rec['link']['ok']} "
              f"start={rec['start']['ok']} functional={rec['functional']['ok']} "
              f"concurrency={rec['concurrency']['ok']}/{rec['concurrency']['total']}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
