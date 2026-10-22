#!/usr/bin/env python3
"""openssl-rs — declarative downstream template layer.

The P1000 build/runtime atlases historically admitted a family only when a
bespoke recipe *and* a bespoke workload had been written for it.  That does not
scale to the long tail: most remaining families fall into a small number of
observable buckets whose acquisition/build/workload shape is identical apart
from a handful of fields.

This module is the template layer.  A family entry in
``downstream_template_families.json`` names:

* the pristine release (URL + SHA-256 + archive kind);
* a declarative build (``autotools`` / ``configure`` / ``cmake`` / ``meson`` /
  ``make``), exactly the build vocabulary ``downstream_build_link`` already runs;
* the built program and its identity argv;
* a workload bucket from :data:`HARNESS_TEMPLATES`.

The tools import this module rather than growing another bespoke branch:

* ``downstream_build_link`` appends :func:`recipe_specs` to its shared
  catalogue and uses :func:`write_pkgconfig_shim` for prefixes that ship no
  ``openssl.pc``;
* ``downstream_runtime`` merges :func:`programs` / :func:`runners` and calls
  :func:`admit_binary` *before* a template family may claim L7.

The template layer is deliberately honest about what it does **not** do: a
bucket template is a local, deterministic exercise of the program's OpenSSL
path, not a security proof, and a family that never loads the subject
libssl/libcrypto is refused by :func:`admit_binary` rather than promoted.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
import zipfile
from functools import partial
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable

sys.path.insert(0, str(Path(__file__).resolve().parent))

import downstream_census as census  # noqa: E402

TEMPLATE_ROOT = Path(__file__).resolve().parent
CONFIG_PATH = TEMPLATE_ROOT / "downstream_template_families.json"

#: The workload buckets the registry implements.  ``library-only (needs C)`` is
#: intentionally absent: a library with no executable needs a *typed* consumer,
#: which is the one bucket this declarative layer cannot honestly template.
HARNESS_TEMPLATES: tuple[str, ...] = (
    "digest",
    "http_client",
    "http_bench",
    "http_mirror",
    "tls_server",
    "signature",
    "ssh_client",
)

_TEMPLATE_SCHEMA = "openssl-rs/downstream-template-families/1"


# --------------------------------------------------------------------------------------------
# declarative family config
# --------------------------------------------------------------------------------------------

def _load_document() -> dict:
    if not CONFIG_PATH.is_file():
        return {"schema": _TEMPLATE_SCHEMA, "families": []}
    doc = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    if doc.get("schema") != _TEMPLATE_SCHEMA:
        raise SystemExit(f"[downstream-templates] unsupported schema in {CONFIG_PATH}")
    return doc


def families() -> tuple[dict, ...]:
    """The configured template families, in file order (pure; reads one JSON file)."""
    return tuple(_load_document().get("families") or ())


_BY_FAMILY: dict[str, dict] = {str(e["family"]): e for e in families()}


def recipe_specs() -> tuple[dict, ...]:
    """The build/link recipe form of each entry, in the shared catalogue vocabulary.

    The same recipe is run against the authority and the candidate with only
    ``{prefix}`` substituted, so the identical-build-intent rule is preserved.
    """
    out: list[dict] = []
    for entry in families():
        rec = {
            "family": entry["family"],
            "version": entry["version"],
            "url": entry["url"],
            "archive": entry.get("archive", "tar.gz"),
            "sha256": entry["sha256"],
            "build_system": entry["build_system"],
            "configure": list(entry.get("configure") or []),
            "make": list(entry.get("make") or [census.MAKE_JOBS]),
            "artifact": entry["artifact"],
            "launch": list(entry.get("launch") or []),
            "env_extra": entry.get("env_extra"),
            "pre_build": entry.get("pre_build"),
            "pkgconfig_shim": bool(entry.get("pkgconfig_shim")),
            "template": True,
            "bucket": entry.get("bucket"),
            "note": (f"template recipe ({entry.get('bucket')}); pristine release built against "
                     "the subject prefix, with the workload supplied by the bucket template"),
        }
        out.append(rec)
    return tuple(out)


def programs() -> dict[str, dict]:
    """The runtime intent (program, launch argv, version pattern) for each family."""
    out: dict[str, dict] = {}
    for entry in families():
        prog = {
            "program": entry["program"],
            "launch": list(entry.get("launch") or []),
            "version_re": entry["version_re"],
            "template": True,
            "bucket": entry.get("bucket"),
        }
        if entry.get("lib_paths"):
            prog["lib_paths"] = list(entry["lib_paths"])
        if entry.get("env"):
            prog["env"] = dict(entry["env"])
        out[str(entry["family"])] = prog
    return out


def runners() -> dict[str, Callable[[dict], dict]]:
    """The bucket workload for each configured family."""
    return {str(e["family"]): partial(run_template, str(e["family"])) for e in families()}


# --------------------------------------------------------------------------------------------
# build helpers shared by every template
# --------------------------------------------------------------------------------------------

def write_pkgconfig_shim(work: Path, prefix: Path) -> Path:
    """Write ``libssl.pc`` / ``libcrypto.pc`` for a subject prefix that ships none.

    Several upstream ``configure`` scripts probe with ``pkg-config libssl``.
    The candidate drop-in install intentionally carries no ``openssl.pc``; this
    shim is a generated build input (never a source patch) pointing at exactly
    the subject prefix, and is identical for both subjects.
    """
    pc_dir = work / "pkgconfig"
    pc_dir.mkdir(parents=True, exist_ok=True)
    version = "3"
    for header in (prefix / "include" / "openssl" / "opensslv.h",):
        try:
            text = header.read_text(encoding="utf-8", errors="ignore")
            m = re.search(r"OPENSSL_VERSION_STR\s+\"([^\"]+)\"", text)
            if m:
                version = m.group(1)
        except OSError:
            pass
    for name, lib in (("libssl", "ssl"), ("libcrypto", "crypto")):
        (pc_dir / f"{name}.pc").write_text(
            "Description: subject-prefix shim for the openssl-rs template layer\n"
            f"prefix={prefix}\nlibdir={prefix}/lib\nincludedir={prefix}/include\n"
            f"Name: {name}\nVersion: {version}\n"
            f"Libs: -L{prefix}/lib -l{lib}\nCflags: -I{prefix}/include\n",
            encoding="utf-8")
    return pc_dir


def _run(argv: list[str], *, cwd: Path | None = None, env: dict | None = None,
         timeout: int = 120, input_text: str | None = None) -> dict:
    start = time.monotonic()
    try:
        proc = subprocess.run(argv, cwd=str(cwd) if cwd else None, env=env,
                              capture_output=True, text=True, timeout=timeout,
                              input=input_text, check=False)
        code, out, err = proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as exc:
        code = -1
        out = (exc.stdout or b"").decode("utf-8", "ignore") if isinstance(exc.stdout, bytes) \
            else (exc.stdout or "")
        err = f"TIMEOUT after {timeout}s"
    except (FileNotFoundError, OSError) as exc:
        code, out, err = 127, "", str(exc)
    return {"argv": argv, "exit_code": code, "ok": code == 0, "stdout": out, "stderr": err,
            "elapsed_seconds": round(time.monotonic() - start, 3)}


def _expand(value: Any, mapping: dict[str, Any]) -> Any:
    """Substitute only the named ``{placeholders}`` (regex braces are left alone)."""
    if isinstance(value, list):
        return [_expand(v, mapping) for v in value]
    if isinstance(value, dict):
        return {k: _expand(v, mapping) for k, v in value.items()}
    if isinstance(value, str):
        out = value
        for key, val in mapping.items():
            out = out.replace("{" + key + "}", str(val))
        return out
    return value


def _transcript(parts: list[tuple[str, dict]]) -> str:
    lines: list[str] = []
    for label, res in parts:
        lines.append(f"== {label} ==")
        lines.append(f"exit={res.get('exit_code')}")
        if res.get("stdout"):
            lines.append(str(res["stdout"]).rstrip())
        if res.get("stderr"):
            lines.append(str(res["stderr"]).rstrip())
    return "\n".join(lines)


# --------------------------------------------------------------------------------------------
# deterministic ports and TMPDIR isolation
# --------------------------------------------------------------------------------------------

def allocate_port(family: str, purpose: str, *, host: str = "127.0.0.1",
                  attempts: int = 64) -> int:
    """A deterministic loopback port derived from (family, purpose).

    The port is a function of the family and purpose, never of wall-clock or PID
    state.  A collision is resolved by walking forward deterministically; the
    chosen port is normalised out of the transcript by the runtime atlas.
    """
    digest = hashlib.sha256(f"{family}:{purpose}".encode("utf-8")).hexdigest()
    base = 21000 + (int(digest[:8], 16) % 20000)
    for i in range(attempts):
        port = 21000 + ((base - 21000 + i) % 20000)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind((host, port))
            except OSError:
                continue
        return port
    raise RuntimeError(f"no free deterministic port for {family}:{purpose}")


def isolated_tmpdir(workdir: Path) -> Path:
    """A per-run TMPDIR under the court scratch tree (never a shared /tmp)."""
    tmp = workdir / "tmp"
    tmp.mkdir(parents=True, exist_ok=True)
    return tmp


def _env_for(ctx: dict, *, tmpdir: Path | None = None) -> dict:
    env = dict(ctx.get("env") or os.environ)
    if tmpdir is not None:
        env["TMPDIR"] = str(tmpdir)
        env["TMP"] = str(tmpdir)
        env["TEMP"] = str(tmpdir)
    return env


# --------------------------------------------------------------------------------------------
# admission: refuse L7 for a binary that never loads the subject
# --------------------------------------------------------------------------------------------

def admit_binary(program: Path, prefix: Path, authority_prefix: Path | None = None,
                 env: dict | None = None) -> dict:
    """Read the loader's own resolution of libssl/libcrypto and decide admission.

    This is the generic admission gate: a family may not claim L6/L7 merely
    because its recipe built.  At least one OpenSSL soname must appear in the
    program's transitive ``ldd`` closure, every one that appears must resolve
    under the subject prefix, and a candidate prefix must not resolve any of
    them under the admitted authority.
    """
    run_env = dict(env or os.environ)
    ldd = _run(["ldd", str(program)], env=run_env, timeout=60)
    sonames: dict[str, dict] = {}
    under_all = True
    under_auth = False
    for line in (ldd.get("stdout") or "").splitlines():
        left = line.split("=>")[0].strip()
        if not (left == "libssl.so" or left.startswith("libssl.so.") or
                left == "libcrypto.so" or left.startswith("libcrypto.so.")):
            continue
        resolved = ""
        if "=>" in line:
            resolved = line.split("=>", 1)[1].strip().split(" (")[0].strip()
        under = bool(resolved) and _under(resolved, prefix)
        under_authority = bool(resolved) and authority_prefix is not None and \
            _under(resolved, authority_prefix)
        sonames[left] = {"resolved": resolved or "unresolved", "under_prefix": under,
                         "under_authority": under_authority}
        under_all = under_all and under
        under_auth = under_auth or under_authority
    is_authority = authority_prefix is None or _same_path(prefix, authority_prefix)
    admitted = bool(sonames) and under_all and (is_authority or not under_auth)
    reason = None
    if not sonames:
        reason = "the program's loader closure names no libssl/libcrypto"
    elif not under_all:
        reason = "an OpenSSL soname resolves outside the subject prefix"
    elif not is_authority and under_auth:
        reason = "a candidate OpenSSL soname resolves under the authority prefix"
    return {"admitted": admitted, "sonames": sonames, "reason": reason,
            "ldd_exit": ldd.get("exit_code"), "all_under_prefix": under_all,
            "resolved_under_authority": under_auth}


def _same_path(a: Path, b: Path) -> bool:
    try:
        return os.path.realpath(str(a)) == os.path.realpath(str(b))
    except OSError:
        return False


def _under(path: str, prefix: Path) -> bool:
    try:
        return os.path.realpath(path).startswith(os.path.realpath(str(prefix)) + os.sep)
    except OSError:
        return False


# --------------------------------------------------------------------------------------------
# fixtures: PKI, HTTPS, plaintext negative peer, Gemini/TLS peer
# --------------------------------------------------------------------------------------------

def _openssl(ctx: dict, argv: list[str], cwd: Path) -> dict:
    binary = ctx["authority_prefix"] / "bin" / "openssl"
    if not binary.is_file():
        binary = Path(shutil.which("openssl") or "openssl")
    env = _env_for(ctx)
    # The authority CLI resolves its own libssl/libcrypto from its prefix; a subject
    # LD_LIBRARY_PATH (the runtime's ctx env) would otherwise shadow them.  The prefix ships no
    # ssl/openssl.cnf, and the fixture supplies every distinguished name/extensions explicitly, so
    # an empty config is the honest input (the same choice the runtime's own PKI helper makes).
    env["LD_LIBRARY_PATH"] = os.pathsep.join(
        [str(ctx["authority_prefix"] / "lib"), env.get("LD_LIBRARY_PATH", "")]).rstrip(
            os.pathsep)
    env["OPENSSL_CONF"] = "/dev/null"
    return _run([str(binary), *argv], cwd=cwd, env=env, timeout=60)


def _generate_pki(ctx: dict) -> dict:
    d = ctx["workdir"] / "pki"
    d.mkdir(parents=True, exist_ok=True)
    ca_key, ca_crt = d / "ca.key", d / "ca.crt"
    srv_key, srv_crt = d / "server.key", d / "server.crt"
    wrong_key, wrong_crt = d / "wrong.key", d / "wrong.crt"
    steps = [
        ["req", "-x509", "-newkey", "rsa:2048", "-sha256", "-nodes", "-days", "2",
         "-subj", "/CN=template-ca", "-addext", "basicConstraints=critical,CA:TRUE",
         "-addext", "keyUsage=critical,keyCertSign,cRLSign",
         "-keyout", str(ca_key), "-out", str(ca_crt)],
        ["req", "-newkey", "rsa:2048", "-sha256", "-nodes", "-subj", "/CN=localhost",
         "-keyout", str(srv_key), "-out", str(d / "server.csr")],
        ["x509", "-req", "-sha256", "-days", "2", "-in", str(d / "server.csr"),
         "-CA", str(ca_crt), "-CAkey", str(ca_key), "-CAcreateserial",
         "-extfile", str(_write_san(d)), "-out", str(srv_crt)],
        ["req", "-x509", "-newkey", "rsa:2048", "-sha256", "-nodes", "-days", "2",
         "-subj", "/CN=wrong-ca", "-keyout", str(wrong_key), "-out", str(wrong_crt)],
    ]
    for argv in steps:
        res = _openssl(ctx, argv, d)
        if not res["ok"]:
            raise RuntimeError(f"PKI fixture failed: {census._error_line(res)}")
    return {"ca": ca_crt, "cert": srv_crt, "key": srv_key, "wrong_ca": wrong_crt}


def _write_san(d: Path) -> Path:
    path = d / "san.cnf"
    path.write_text("subjectAltName=DNS:localhost,IP:127.0.0.1\n"
                    "basicConstraints=CA:FALSE\n"
                    "keyUsage=digitalSignature,keyEncipherment\n"
                    "extendedKeyUsage=serverAuth\n", encoding="utf-8")
    return path


class _HTTPFixture:
    """A deterministic loopback HTTP peer; TLS-wrapped for the positive fixture."""

    def __init__(self, port: int, body: str, *, cert: Path | None = None,
                 key: Path | None = None):
        self.body = body.encode("utf-8") if isinstance(body, str) else body
        self.requests = 0
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802 - stdlib name
                outer.requests += 1
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(outer.body)))
                self.end_headers()
                self.wfile.write(outer.body)

            def log_message(self, *args):  # noqa: D401 - silence
                return

        self.server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
        self.server.daemon_threads = True
        if cert and key:
            sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            sctx.load_cert_chain(str(cert), str(key))
            self.server.socket = sctx.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()
        return False


def _wait_tcp(port: int, timeout: float = 20.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)
            try:
                sock.connect(("127.0.0.1", port))
                return True
            except OSError:
                time.sleep(0.1)
    return False


def _write_fixture_files(ctx: dict) -> dict:
    d = ctx["workdir"] / "fixtures"
    d.mkdir(parents=True, exist_ok=True)
    payload = d / "payload.bin"
    tampered = d / "tampered.bin"
    payload.write_bytes(b"template-payload\n")
    tampered.write_bytes(b"template-payloaX\n")
    text = d / "payload.txt"
    text.write_text("template-payload\n", encoding="utf-8")
    return {"payload": payload, "tampered": tampered, "payload_txt": text}


# --------------------------------------------------------------------------------------------
# bucket templates
# --------------------------------------------------------------------------------------------

def run_template(name: str, ctx: dict) -> dict:
    entry = _BY_FAMILY.get(name)
    if entry is None:
        return _fail("no template entry for this family", "harness-failure")
    wl = entry.get("workload") or {}
    kind = wl.get("template")
    tmpdir = isolated_tmpdir(ctx["workdir"])
    env = _env_for(ctx, tmpdir=tmpdir)
    env.setdefault("HOME", str(ctx["workdir"]))
    # The caller's env carries LD_LIBRARY_PATH; keep it and add the isolated TMPDIR.
    ctx = dict(ctx, env=env)
    handlers: dict[str, Callable[[dict, dict], dict]] = {
        "digest": _tpl_digest,
        "http_client": _tpl_http,
        "http_bench": _tpl_http,
        "http_mirror": _tpl_http,
        "tls_server": _tpl_tls_server,
        "signature": _tpl_signature,
        "ssh_client": _tpl_ssh_client,
    }
    handler = handlers.get(str(kind))
    if handler is None:
        return _fail(f"template {kind!r} is not implemented in this venue", "harness-failure")
    try:
        return handler(entry, ctx)
    except Exception as exc:  # noqa: BLE001 - a fixture failure is recorded, never raised
        return _fail(f"the {kind} template failed: {exc}", "harness-failure")


def _fail(reason: str, failure_class: str) -> dict:
    return {"runtime_ok": False, "functional_ok": False, "failure_class": failure_class,
            "residual": "out-of-scope", "reason": reason, "transcript": "",
            "workload": "template", "local_only": True}


def _base(entry: dict, ctx: dict, wl: dict) -> dict[str, Any]:
    files = _write_fixture_files(ctx)
    port = allocate_port(str(entry["family"]), "positive")
    return {"files": files, "port": port, "entry": entry, "ctx": ctx, "wl": wl,
            "workdir": ctx["workdir"], "root": ctx["root"], "program": ctx["program"]}


def _expand_wl(value: Any, body: dict, *, extra: dict | None = None) -> Any:
    mapping = {
        "payload": body["files"]["payload"],
        "tampered": body["files"]["tampered"],
        "payload_txt": body["files"]["payload_txt"],
        "workdir": body["workdir"],
        "root": body["root"],
        "port": body["port"],
        "ca": (body.get("ca") or ""),
        "cert": (body.get("cert") or ""),
        "key": (body.get("key") or ""),
        "pem": (body.get("pem") or ""),
        "wrong_ca": (body.get("wrong_ca") or ""),
        "url": (body.get("url") or ""),
        "config": (body.get("config") or ""),
    }
    if extra:
        mapping.update(extra)
    return _expand(value, mapping)


def _tpl_digest(entry: dict, ctx: dict) -> dict:
    wl = entry["workload"]
    b = _base(entry, ctx, wl)
    argv = _expand_wl(wl["argv"], b)
    pos = _run([str(ctx["program"]), *argv], cwd=ctx["workdir"], env=ctx["env"], timeout=120)
    expect = str(wl["expect"])
    pos_match = re.search(expect, pos["stdout"] + pos["stderr"], re.MULTILINE)
    neg_argv = _expand_wl(wl.get("negative_argv") or wl["argv"], b)
    neg = _run([str(ctx["program"]), *neg_argv], cwd=ctx["workdir"], env=ctx["env"], timeout=120)
    # The negative control compares the *expectation* the family declares, not an assumed
    # lowercase-hex shape: NSEC3 hashes are base32hex and would otherwise never be compared.
    different = bool(pos_match) and pos_match.group(0) not in (neg["stdout"] + neg["stderr"])
    functional = bool(pos["ok"] and pos_match and (different or neg["exit_code"] != 0))
    return {
        "runtime_ok": bool(pos["ok"]),
        "functional_ok": functional,
        "failure_class": None if functional else ("functional-failure" if pos["ok"] else
                                                  "runtime-failure"),
        "residual": "none" if functional else ("functional-divergence" if pos["ok"] else
                                               "runtime-failure"),
        "reason": None if functional else (
            "the digest tool did not produce the expected digest" if not pos_match else
            "a tampered input did not change the digest"),
        "transcript": _transcript([("digest", pos), ("tampered input", neg)]),
        "workload": f"{entry['family']}: digest bucket",
        "local_only": True,
    }


def _http_client_argv(entry: dict, body: dict, *, negative: bool) -> list[str]:
    wl = entry["workload"]
    argv = wl.get("negative_argv") if negative and wl.get("negative_argv") else wl["argv"]
    mode = str(wl.get("negative", "wrong_ca"))
    ca = body["ca"]
    url = body["url"]
    port = body["port"]
    if negative:
        if mode in ("plaintext", "closed_port"):
            url = f"https://127.0.0.1:{body['neg_port']}/"
            port = body["neg_port"]
            ca = body["ca"]
        else:
            ca = body["wrong_ca"]
    return _expand_wl(argv, body, extra={"url": url, "ca": ca, "port": port})


def _mirror_has(ctx: dict, needle: str, name: str = "mirror") -> bool:
    mirror = ctx["workdir"] / name
    return any(p.is_file() and needle.encode("utf-8") in p.read_bytes()
               for p in mirror.rglob("*")) if mirror.exists() else False


def _tpl_http(entry: dict, ctx: dict) -> dict:
    wl = entry["workload"]
    b = _base(entry, ctx, wl)
    pki = _generate_pki(ctx)
    b["ca"], b["wrong_ca"] = pki["ca"], pki["wrong_ca"]
    b["url"] = f"https://127.0.0.1:{b['port']}/"
    neg_port = allocate_port(str(entry["family"]), "negative")
    b["neg_port"] = neg_port
    body_text = str(wl.get("expect", "template-payload"))
    mode = str(wl.get("negative", "wrong_ca"))
    results: list[tuple[str, dict]] = []
    functional = False
    mirror_ok = False
    with _HTTPFixture(b["port"], body_text, cert=pki["cert"], key=pki["key"]) as good:
        if mode == "plaintext":
            with _HTTPFixture(neg_port, body_text) as plain:
                pos = _run([str(ctx["program"]), *_http_client_argv(entry, b, negative=False)],
                           cwd=ctx["workdir"], env=ctx["env"], timeout=120)
                neg = _run([str(ctx["program"]), *_http_client_argv(entry, b, negative=True)],
                           cwd=ctx["workdir"], env=ctx["env"], timeout=120)
                results += [("positive", pos), ("negative (plaintext peer)", neg)]
                good_requests, plain_requests = good.requests, plain.requests
        else:
            # ``closed_port`` is for a client that does not verify certificates (wrk): an
            # unrelated CA is not a rejection it can express, but a refused connection must
            # never be reported as a successful transaction.
            pos = _run([str(ctx["program"]), *_http_client_argv(entry, b, negative=False)],
                       cwd=ctx["workdir"], env=ctx["env"], timeout=120)
            neg = _run([str(ctx["program"]), *_http_client_argv(entry, b, negative=True)],
                       cwd=ctx["workdir"], env=ctx["env"], timeout=120)
            results += [("positive", pos), ("negative (no listener)", neg)]
            good_requests, plain_requests = good.requests, 0
    pos_match = re.search(str(wl["expect"]), pos["stdout"] + pos["stderr"], re.MULTILINE)
    if wl["template"] == "http_mirror":
        mirror_ok = _mirror_has(ctx, body_text)
        # httrack's own progress log is not the evidence; the mirrored payload is.
        pos_match = mirror_ok
    if mode == "closed_port":
        # The client must not report the refused connection as a completed transaction.
        neg_output = neg["stdout"] + neg["stderr"]
        neg_bad = (neg["exit_code"] != 0
                   and re.search(str(wl["expect"]), neg_output, re.MULTILINE) is None)
    else:
        neg_bad = (neg["exit_code"] != 0 or not re.search(
            str(wl["expect"]), neg["stdout"] + neg["stderr"], re.MULTILINE)) \
            and not (wl["template"] == "http_mirror"
                     and _mirror_has(ctx, body_text, "mirror-neg"))
    functional = bool(pos["ok"] and pos_match and good_requests >= 1 and neg_bad
                      and (mirror_ok if wl["template"] == "http_mirror" else True))
    return {
        "runtime_ok": bool(pos["ok"]),
        "functional_ok": functional,
        "failure_class": None if functional else ("functional-failure" if pos["ok"] else
                                                  "runtime-failure"),
        "residual": "none" if functional else ("functional-divergence" if pos["ok"] else
                                               "runtime-failure"),
        "reason": None if functional else (
            "the client did not complete the expected HTTPS exchange" if not pos_match else
            "the negative-control peer was not rejected" if not neg_bad else
            "the mirror did not contain the fixture payload"),
        "transcript": _transcript(results),
        "workload": f"{entry['family']}: {wl['template']} bucket",
        "local_only": True,
    }


def _tpl_tls_server(entry: dict, ctx: dict) -> dict:
    wl = entry["workload"]
    b = _base(entry, ctx, wl)
    workdir = ctx["workdir"]
    root = workdir / "root"
    root.mkdir(parents=True, exist_ok=True)
    (root / "index.gmi").write_text("template-payload\n", encoding="utf-8")
    # A family that does not mint its own certificate (lighttpd, h2o, httpd) is given the same
    # fixture PKI the HTTP bucket uses; the server certificate is CA-signed, so the positive
    # client verifies it and an unrelated CA must be rejected.  A family that generates its own
    # certificate on first use (gmnisrv) keeps `cert_path` and never references these names.
    pki = _generate_pki(ctx)
    pem = workdir / "pki" / "server.pem"
    pem.write_bytes(pki["cert"].read_bytes() + pki["key"].read_bytes())
    b["ca"], b["wrong_ca"] = pki["ca"], pki["wrong_ca"]
    b["cert"], b["key"], b["pem"] = pki["cert"], pki["key"], pem
    config_path = workdir / "server.conf"
    b["config"] = config_path
    config_path.write_text(str(_expand_wl(wl["config"], b)), encoding="utf-8")
    argv = [str(ctx["program"]), *_expand_wl(wl["server_argv"], b)]
    server = subprocess.Popen(argv, cwd=str(workdir), env=ctx["env"],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        if not _wait_tcp(b["port"], timeout=20):
            out, err = server.communicate(timeout=5)
            return _fail(f"the TLS server did not listen: {(err or out or '')[-300:]}",
                         "runtime-failure")
        cert_path = Path(str(_expand_wl(wl.get("cert_path", "{ca}"), b)))
        # gmnisrv creates its self-signed certificate on first use; trigger and wait.
        deadline = time.monotonic() + 5
        while not cert_path.is_file() and time.monotonic() < deadline:
            try:
                raw = ssl._create_unverified_context().wrap_socket(
                    socket.create_connection(("127.0.0.1", b["port"]), timeout=2),
                    server_hostname="localhost")
                raw.close()
            except OSError:
                pass
            time.sleep(0.1)
        good = _tls_exchange(b["port"], cert_path, str(wl.get("payload", "")), verify_host=True)
        wrong = _tls_exchange(b["port"], b["wrong_ca"],
                              str(wl.get("payload", "")), verify_host=True)
    finally:
        server.terminate()
        try:
            out, err = server.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
            out, err = server.communicate()
    expect = str(wl["expect"])
    pos_match = bool(good.get("data")) and re.search(expect, good.get("data", ""),
                                                     re.MULTILINE) is not None
    neg_rejected = not wrong.get("ok")
    functional = bool(pos_match and neg_rejected)
    return {
        "runtime_ok": pos_match,
        "functional_ok": functional,
        "failure_class": None if functional else ("functional-failure" if pos_match else
                                                  "runtime-failure"),
        "residual": "none" if functional else ("functional-divergence" if pos_match else
                                               "runtime-failure"),
        "reason": None if functional else (
            "the TLS server did not return the expected protocol response" if not pos_match else
            "a client trusting only an unrelated CA was not rejected"),
        "transcript": _transcript([("tls client", {"exit_code": 0 if good.get("ok") else 1,
                                                   "stdout": good.get("data", ""),
                                                   "stderr": good.get("error", "")}),
                                   ("unrelated CA (must fail)",
                                    {"exit_code": 0 if wrong.get("ok") else 1,
                                     "stdout": wrong.get("data", ""),
                                     "stderr": wrong.get("error", "")}),
                                   ("server", {"exit_code": server.returncode,
                                               "stdout": (out or "")[-1000:],
                                               "stderr": (err or "")[-1000:]})]),
        "workload": f"{entry['family']}: {wl.get('protocol', 'TLS')} server bucket",
        "local_only": True,
    }


def _tls_exchange(port: int, ca: Path, payload: str, *, verify_host: bool) -> dict:
    try:
        sctx = ssl.create_default_context(cafile=str(ca))
        sctx.check_hostname = verify_host
        with socket.create_connection(("127.0.0.1", port), timeout=10) as sock:
            with sctx.wrap_socket(sock, server_hostname="localhost") as tls:
                tls.sendall(payload.encode("utf-8"))
                chunks: list[bytes] = []
                while True:
                    chunk = tls.recv(4096)
                    if not chunk:
                        break
                    chunks.append(chunk)
                return {"ok": True, "data": b"".join(chunks).decode("utf-8", "replace"),
                        "error": ""}
    except (ssl.SSLError, OSError) as exc:
        return {"ok": False, "data": "", "error": str(exc)}


def _tpl_signature(entry: dict, ctx: dict) -> dict:
    wl = entry["workload"]
    b = _base(entry, ctx, wl)
    pos = _run([str(ctx["program"]), *_expand_wl(wl["argv"], b)], cwd=ctx["workdir"],
               env=ctx["env"], timeout=120)
    neg = _run([str(ctx["program"]), *_expand_wl(wl.get("negative_argv") or wl["argv"], b)],
               cwd=ctx["workdir"], env=ctx["env"], timeout=120)
    signed = Path(str(_expand_wl("{workdir}/signed.appx", b)))
    unsigned = Path(str(_expand_wl("{workdir}/unsigned.appx", b)))
    entry_name = str(wl["artifact_entry"])
    signed_ok = _zip_has_entry(signed, entry_name)
    unsigned_ok = unsigned.is_file() and not _zip_has_entry(unsigned, entry_name)
    functional = bool(pos["ok"] and signed_ok and neg["ok"] and unsigned_ok)
    return {
        "runtime_ok": bool(pos["ok"] and signed.is_file()),
        "functional_ok": functional,
        "failure_class": None if functional else ("functional-failure" if pos["ok"] else
                                                  "runtime-failure"),
        "residual": "none" if functional else ("functional-divergence" if pos["ok"] else
                                               "runtime-failure"),
        "reason": None if functional else (
            "the signed artifact did not contain the signature entry" if not signed_ok else
            "the unsigned control unexpectedly contained a signature entry"),
        "transcript": _transcript([("signed", pos), ("unsigned control", neg)]),
        "workload": f"{entry['family']}: signature bucket",
        "local_only": True,
    }


def _zip_has_entry(path: Path, name: str) -> bool:
    try:
        with zipfile.ZipFile(path) as zf:
            return any(info.filename == name and info.file_size > 0 for info in zf.infolist())
    except (OSError, zipfile.BadZipFile):
        return False


def _tpl_ssh_client(entry: dict, ctx: dict) -> dict:
    wl = entry["workload"]
    b = _base(entry, ctx, wl)
    d = ctx["workdir"]
    keygen = ctx["root"] / str(wl.get("keygen", "ssh-keygen"))
    server_bin = ctx["root"] / str(wl.get("server", "sshd"))
    session = ctx["root"] / str(wl.get("session", "sshd-session"))
    ssh = ctx["program"]
    if not (keygen.is_file() and server_bin.is_file() and ssh.is_file()):
        return _fail("the recipe built no ssh/sshd/ssh-keygen to drive", "harness-failure")
    # sshd refuses to start without its compiled privilege-separation directory.
    privsep = ctx["root"] / ".l7-privsep"
    privsep.mkdir(parents=True, exist_ok=True)
    os.chmod(privsep, 0o755)
    host_key, client_key, other_key = d / "hostkey", d / "clientkey", d / "otherhost"
    for key in (host_key, client_key, other_key):
        gen = _run([str(keygen), "-t", "ed25519", "-f", str(key), "-N", "", "-q",
                    "-C", "template"], cwd=d, env=ctx["env"], timeout=40)
        if not gen["ok"]:
            return _fail(f"ssh-keygen failed: {census._error_line(gen)}", "harness-failure")
    authorized = d / "authorized_keys"
    authorized.write_text((d / "clientkey.pub").read_text(encoding="utf-8"), encoding="utf-8")
    known_good, known_bad = d / "known_hosts", d / "known_bad"
    known_good.write_text(f"[127.0.0.1]:{b['port']} " + (d / "hostkey.pub").read_text(
        encoding="utf-8"), encoding="utf-8")
    known_bad.write_text(f"[127.0.0.1]:{b['port']} " + (d / "otherhost.pub").read_text(
        encoding="utf-8"), encoding="utf-8")
    conf = d / "sshd_config"
    conf.write_text(f"Port {b['port']}\nListenAddress 127.0.0.1\nHostKey {host_key}\n"
                    f"PidFile {d}/sshd.pid\nAuthorizedKeysFile {authorized}\n"
                    "StrictModes no\nPasswordAuthentication no\n"
                    "KbdInteractiveAuthentication no\nPubkeyAuthentication yes\n"
                    "PermitRootLogin yes\nLogLevel VERBOSE\n"
                    f"SshdSessionPath {session}\n", encoding="utf-8")
    server = subprocess.Popen([str(server_bin), "-D", "-e", "-f", str(conf)], cwd=str(d),
                              env=ctx["env"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              text=True)
    common = ["-F", "/dev/null", "-o", "StrictHostKeyChecking=yes", "-o", "BatchMode=yes",
              "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none",
              "-o", "ConnectTimeout=8", "-o", f"IdentityFile={client_key}",
              "-p", str(b["port"])]
    try:
        if not _wait_tcp(b["port"], timeout=20):
            out, err = server.communicate(timeout=5)
            return _fail(f"sshd did not listen: {(err or out or '')[-300:]}", "runtime-failure")
        pos = _run([str(ssh), *common, "-o", f"UserKnownHostsFile={known_good}",
                    "127.0.0.1", "echo ok"], cwd=d, env=ctx["env"], timeout=40)
        neg = _run([str(ssh), *common, "-o", f"UserKnownHostsFile={known_bad}",
                    "127.0.0.1", "echo ok"], cwd=d, env=ctx["env"], timeout=40)
    finally:
        server.terminate()
        try:
            out, err = server.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
            out, err = server.communicate()
    exec_ok = pos["ok"] and str(wl.get("expect", "ok")) in pos["stdout"]
    neg_rejected = neg["exit_code"] != 0 and "Host key verification failed" in (
        neg["stdout"] + neg["stderr"])
    functional = exec_ok and neg_rejected
    return {
        "runtime_ok": exec_ok,
        "functional_ok": functional,
        "failure_class": None if functional else ("functional-failure" if exec_ok else
                                                  "runtime-failure"),
        "residual": "none" if functional else ("functional-divergence" if exec_ok else
                                               "runtime-failure"),
        "reason": None if functional else (
            "the verified ssh command did not run" if not exec_ok else
            "a known_hosts entry for a different host key was not rejected"),
        "transcript": _transcript([("ssh exec", pos), ("ssh host-key mismatch (must fail)", neg),
                                   ("sshd", {"exit_code": server.returncode,
                                             "stdout": (out or "")[-1000:],
                                             "stderr": (err or "")[-1000:]})]),
        "workload": f"{entry['family']}: ssh client bucket",
        "local_only": True,
    }

