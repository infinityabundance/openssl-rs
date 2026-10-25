#!/usr/bin/env python3
"""openssl-rs — Phase-24.7 runtime/functional atlas: the load/run/behave measurement.

Phase 24 measures whether `openssl-rs` survives the ways real software depends on OpenSSL, over the
frozen P1000 (`forensics/downstream/family-freeze.json`). 24.6 built and linked a pristine-source
recipe for every family that had one and recorded how far each subject reached on `L0-catalogued`
through `L4-linked`. This module is the next rung: for every family whose build/link row reached
`L4-linked` it **loads** the built program against the subject's install and drives a **real,
deterministic, local** OpenSSL-exercising workload, recording the level reached up to `L7-functional`.

What is measured, and what is not
---------------------------------
Reaching `L5-loaded` is not read from a version banner alone: the program is launched with
`LD_LIBRARY_PATH=<subject>/lib` and the subject's `libssl`/`libcrypto` must be shown **loading** by
the dynamic loader -- the program's `ldd` resolution of those sonames must be under the subject
prefix (never the authority's), and the loader must actually initialise them (`LD_DEBUG=libs`
records the subject library being called). A banner is not a load proof.

`L6-runtime` and `L7-functional` are a **real** workload, run against **local peers only**: no run
touches the public internet. The fixtures are the admitted authority's own `openssl` CLI (its
`s_server`/`s_client`/`req`) and the subject-linked program, on loopback. Where a program's workload
needs a peer or dependency this venue does not admit (an IMAP server, an authenticated FTPS login),
the exclusion is recorded with a reason and the level reached is stated honestly rather than faked.

The authority-applicable baseline
---------------------------------
A family's **authority-applicable baseline** is the highest level its **authority** runtime rows
reached. A candidate run is `DROP_IN`-relevant only when it reaches at least that rank; the candidate
is judged against what the authority itself achieved, never a higher aspirational one. The baseline
is recorded on every candidate row (`authority_applicable_level`) and re-derived by the court from
the authority rows, so a candidate row that inflates its own baseline to justify a higher pass is a
finding, not a pass.

Every P1000 family is accounted for
-----------------------------------
The atlas accounts for **all 1000** frozen families under both subjects. A family with no admitted
recipe, or whose build/link row never reached `L4-linked`, gets an honest
`not_attempted`/`unavailable` runtime row with a reason rather than being omitted or fabricated into
a pass. A sparse-but-complete atlas is the correct outcome; a fabricated pass never is.

Deterministic transcript normalisation
--------------------------------------
Every measured row carries a `transcript_sha256` over its normalised transcript, and the **same**
normaliser is applied to both subjects. It normalises only genuinely nondeterministic and
contract-irrelevant values -- absolute paths, ports, PIDs, timestamps and addresses -- and **never**
a return code, an error class, a certificate decision, or a protocol/algorithm choice, which are the
evidence the workload exists to produce (the brief's section 46).

The candidate identity is a measurement, not a pure function of committed inputs
-------------------------------------------------------------------------------
This tool performs real builds and runs; the artefact it writes is **measurement**. It is therefore
**not** listed in `forensics/tools/evidence_determinism.py`'s `GENERATORS` or `COMPARED` -- exactly
as 24.6's build/link atlas and the Phase-17 measured corpus under `courts/phase17/downstream/*/
result.json` are not -- because the level a run reaches and the transcript it produces are a function
of the court's toolchain and of the network, not of committed inputs, and a host invocation is
refused by the Docker-only guard before it builds anything. The court `RT-RUNTIME-FUNCTIONAL-ATLAS`
re-runs only this module's **pure** functions over the committed artefact and never rebuilds.

The Docker-only guard is called first
-------------------------------------
This module fetches from the network, compiles real projects and runs them, so it is an **execution**
entry point: `phase24_guard.require_admitted()` is the first statement of `main`, and a host
invocation is refused rather than producing unreproducible evidence (`docs/REPRODUCIBILITY.md`
section 1).

What is reused, not re-implemented
----------------------------------
The pristine-source recipe catalogue, the ELF/linkage helpers, the resource limits, the specimen and
variant construction and the path normaliser are **imported from 24.6** (`downstream_build_link`), so
the build each runtime row loads is the exact build 24.6 linked, one code path rather than two that
can drift.

Outputs
-------
  forensics/downstream/runtime-functional-atlas.json   the runtime/functional runs, both subjects

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import copy
import glob
import hashlib
import http.server
import json
import os
import pty
import re
import select
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import (  # noqa: E402
    PRODUCTION_AUTHORITY,
    REPO_ROOT,
    InputRef,
    content_hash,
    envelope,
    rel,
    resolve_authority,
    sha256_bytes,
    sha256_file,
    write_json,
)

# The Docker-only execution guard. Its call is the first statement of `main`: this tool fetches,
# compiles and runs, so it is an execution entry point and a host invocation is refused.
import phase24_guard  # noqa: E402

# The record schemas the rows are validated against, imported rather than restated so the vocabulary
# cannot drift from the module the court checks it with.
import downstream_schemas  # noqa: E402

# The 24.3 census primitives (fetch/extract/run/ELF inspection/resource limits) are reused through
# 24.6, which re-exports none of them itself: importing both keeps one code path.
import downstream_census as census  # noqa: E402

# The 24.6 build/link atlas: its recipe catalogue, its ELF/linkage helpers, its resource-limit reader,
# its specimen/variant/run construction and its `_norm` path normalisation are **reused by importing
# it**, so the runtime atlas loads the exact build the build/link atlas linked (the brief's "no
# divergent predicate").
import downstream_build_link as bl  # noqa: E402

# The declarative template layer: its programs and bucket runners are merged into the runtime
# intent, and its loader-closure admission gate refuses L7 for a binary that never loads the
# subject.  The module executes nothing at import time.
import downstream_templates as templates  # noqa: E402

# The stratum's four non-claims, imported from 24.4 so the atlas and the freeze cannot drift.
from downstream_freeze import NON_CLAIMS as STRATUM_NON_CLAIMS  # noqa: E402

FAMILIES = REPO_ROOT / "forensics" / "downstream" / "families.json"
FAMILY_FREEZE = REPO_ROOT / "forensics" / "downstream" / "family-freeze.json"
BUILD_LINK_ATLAS = REPO_ROOT / "forensics" / "downstream" / "build-link-atlas.json"
OUT = REPO_ROOT / "forensics" / "downstream" / "runtime-functional-atlas.json"

CANDIDATE_PREFIX = bl.CANDIDATE_PREFIX

# Scratch is kept under `/work/court` (never `/tmp` or the container's `/`) and removed after the
# measurement; only the small committed artefact persists in the tree.
SCRATCH = REPO_ROOT / "court" / "phase24-runtime"

GENERATOR = "forensics/tools/downstream_runtime.py"
PARSER_VERSION = "downstream-runtime/1"

L0 = "L0-catalogued"
L4 = "L4-linked"
L5 = "L5-loaded"
L6 = "L6-runtime"
L7 = "L7-functional"
RANK = downstream_schemas.EXECUTION_LEVEL_RANK

STEP_TIMEOUT = census.STEP_TIMEOUT
FETCH_TIMEOUT = census.FETCH_TIMEOUT
LAUNCH_TIMEOUT = census.LAUNCH_TIMEOUT
MAKE_JOBS = census.MAKE_JOBS

SUBJECTS = ("authority", "candidate")

# The allowed normalisation categories: only genuinely nondeterministic and contract-irrelevant
# values. Everything else -- return codes, error classes, certificate decisions, protocol or
# algorithm choices -- is evidence and is never normalised (the brief's section 46).
NORMALISATION_TAG = "runtime-transcript-normalisation/1"
NORMALISATION_ALLOWED = ("absolute_paths", "ports", "pids", "timestamps", "addresses")
NORMALISATION_NEVER = (
    "return_codes", "error_classes", "certificate_decisions", "protocol_choices",
    "algorithm_choices",
)

# The stratum's four non-claims (imported from 24.4 so the two cannot drift) plus the one this
# subphase's measurement adds: a functional pass under a measured workload is not a security proof.
NON_CLAIMS: list[str] = list(STRATUM_NON_CLAIMS) + [
    "a functional pass under a measured workload is not a security proof and not a claim about "
    "unmeasured consumers: the workload is one deterministic local exercise of the program's "
    "OpenSSL path, not a statement that every consumer works or that the library is safe",
]


# --------------------------------------------------------------------------------------------
# the per-family runtime intent: the program to load, its version argv, and its local workload
# --------------------------------------------------------------------------------------------
#
# Each recipe-backed family names the program inside the built pristine tree that is loaded, the
# argv that makes it report its version/usage (L5), and a `version_re` the output must match -- a
# banner is not the load proof (the loader trace is), but a program that does not even print its
# identity did not start. The workload itself is a runner keyed by family below.

PROGRAMS: dict[str, dict] = {
    # curl's `src/curl` is a libtool wrapper script; the real binary is `src/.libs/curl`, which
    # needs the build tree's `lib/.libs` on its library path (as the wrapper would set) so libcurl
    # resolves to the build while libssl/libcrypto resolve to the subject prefix.
    "curl": {"program": "src/.libs/curl", "launch": ["-V"], "version_re": r"curl \d",
             "lib_paths": ["lib/.libs"]},
    "haproxy": {"program": "haproxy", "launch": ["-v"], "version_re": r"HAProxy version"},
    "monit": {"program": "monit", "launch": ["-V"], "version_re": r"monit"},
    "nginx": {"program": "objs/nginx", "launch": ["-v"], "version_re": r"nginx version"},
    "openssh": {"program": "ssh", "launch": ["-V"], "version_re": r"OpenSSH_"},
    "pure-ftpd": {"program": "src/pure-ftpd", "launch": ["--help"], "version_re": r"pure-ftpd"},
    "redis": {"program": "src/redis-server", "launch": ["--version"], "version_re": r"Redis server"},
    "isync": {"program": "src/mbsync", "launch": ["--version"], "version_re": r"mbsync|isync"},
    # The 24.20 L7-expansion batch: four executable consumers and one DNSSEC tool set whose
    # functional level is a real local TLS/crypto operation rather than a banner.
    "fossil": {"program": "fossil", "launch": ["version"],
               "version_re": r"fossil version"},
    "ldns": {"program": "examples/.libs/ldns-signzone", "launch": ["-h"],
             "version_re": r"ldns-signzone", "lib_paths": [".libs"],
             "make_targets": ["examples"],
             # `make -j8 examples` races on libtool's .loT temporary names (observed:
             # `mv: cannot stat examples/ldns-*.loT`); the workload target is built serially.
             "make_jobs": ["-j1"]},
    "rsync": {"program": "rsync", "launch": ["--version"],
              "version_re": r"rsync\s+version"},
    "socat": {"program": "socat", "launch": ["-V"], "version_re": r"socat version"},
    "squid": {"program": "src/squid", "launch": ["-v"],
              "version_re": r"Squid Cache: Version"},
    # The 24.21 L7-expansion batch: two TLS servers (stunnel/openvpn), a TLS scanner (sslscan), a
    # VPN key-exchange daemon (tinc) and a TLS Redis client (hiredis-ssl).
    "stunnel": {"program": "src/stunnel", "launch": ["-version"],
                "version_re": r"stunnel 5"},
    "sslscan": {"program": "sslscan", "launch": ["--version"],
                "version_re": r"OpenSSL \d"},
    "openvpn": {"program": "src/openvpn/openvpn", "launch": ["--version"],
                "version_re": r"OpenVPN 2"},
    "tinc": {"program": "src/tincd", "launch": ["--version"],
             "version_re": r"tinc version 1\.0"},
    # hiredis ships no TLS CLI; its own upstream example is the admitted program. The default
    # recipe make builds the libraries and the unit test but not the example, so the example target
    # is built here with the recipe's own OpenSSL environment (`USE_SSL=1`, `OPENSSL_PREFIX`).
    "hiredis-ssl": {"program": "examples/hiredis-example-ssl", "launch": ["--help"],
                    "version_re": r"Usage:",
                    "make_targets": ["hiredis-example-ssl"],
                    "make_env": {"OPENSSL_PREFIX": "{prefix}", "USE_SSL": "1"}},
    # The 24.22 L7-expansion batch: a CONNECT-tunnel client and a health checker whose TLS evidence
    # is a fetched-page digest rather than a banner.
    "proxytunnel": {"program": "proxytunnel", "launch": ["-h"],
                    "version_re": r"proxytunnel \d"},
    "keepalived": {"program": "keepalived/keepalived", "launch": ["-v"],
                   "version_re": r"Keepalived v\d"},
    # The 24.23 L7-expansion batch: an SMTP submitter that speaks STARTTLS and an FTP/HTTP client
    # whose HTTPS fetch path is its libssl consumer path.
    "ssmtp": {"program": "ssmtp", "launch": ["-V"],
              "version_re": r"sSMTP 2\.64"},
    "tnftp": {"program": "src/tnftp", "launch": ["-?"],
              "version_re": r"usage: tnftp"},
    # The Phase-25 L7-expansion batch: an IMAPS client (fetchmail), an RSA/SHA-256 authenticated
    # throughput tool (iperf3) and a module-signature parser (kmod). Each asserts the family's own
    # OpenSSL consumer path, not a banner.
    "fetchmail": {"program": "fetchmail", "launch": ["--version"],
                  "version_re": r"fetchmail release 6\.5"},
    # iperf3's recipe artifact is the shared library, but configure also links `src/iperf3`; the
    # libtool target binary under `.libs` is what the loader trace can resolve.
    "iperf3": {"program": "src/.libs/iperf3", "launch": ["--version"],
               "version_re": r"iperf 3", "lib_paths": ["src/.libs"]},
    # kmod dispatches its tools on argv[0]; `tools/modinfo` is the build tree's own symlink to the
    # single kmod binary, so launching it selects the modinfo command (and keeps the loader proof
    # on the ELF that libkmod links).
    "kmod": {"program": "tools/modinfo", "launch": ["--version"],
             "version_re": r"kmod version"},
    # The 24.24 L7-expansion batch: three LIBRARY-only families. They ship no executable of their
    # own, so the admitted workload is a small harness under forensics/tools/ built against the
    # rebuilt library and the subject prefix. `harness` compiles it into the source tree before the
    # launch/load proof, exactly as `make_targets` builds a workload target for an upstream tree.
    "libevent": {
        "program": ".l7-libevent-harness", "launch": ["--version"],
        "version_re": r"libevent-l7-harness", "lib_paths": [".libs"],
        "harness": {
            "source": "forensics/tools/l7_libevent.c",
            "cflags": ["-I{root}/include", "-I{prefix}/include"],
            "ldflags": ["-L{root}/.libs", "-L{prefix}/lib",
                        "-Wl,-rpath,{root}/.libs", "-Wl,-rpath,{prefix}/lib",
                        "-levent_openssl", "-levent", "-lssl", "-lcrypto", "-pthread"],
        },
        "note": ("libevent's own libevent_openssl consumer path: two bufferevents over a "
                 "socketpair negotiate TLS1.3, verify the peer against the fixture CA and carry "
                 "a payload round trip; an unrelated CA is rejected"),
    },
    "libretls": {
        # Known candidate blocker (2026-10-21): every libtls context calls
        # SSL_CTX_set_tlsext_status_cb, whose macro reaches
        # SSL_CTX_callback_ctrl(SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB); the candidate falls through to
        # `_ => 0` (src/ssl/ssl_lib.rs:5022), so tls_configure fails before the handshake. The
        # workload is recorded honestly at L5 until that control arm lands.
        "program": ".l7-libretls-harness", "launch": ["--version"],
        "version_re": r"libretls-l7-harness", "lib_paths": [".libs"],
        "harness": {
            "source": "forensics/tools/l7_libretls.c",
            "cflags": ["-I{root}/include", "-I{prefix}/include"],
            "ldflags": ["-L{root}/.libs", "-L{prefix}/lib",
                        "-Wl,-rpath,{root}/.libs", "-Wl,-rpath,{prefix}/lib",
                        "-ltls", "-lssl", "-lcrypto"],
        },
        "note": ("libtls (libretls) consumer path: client+server over a socketpair complete a "
                 "verified TLS1.3 handshake and a payload round trip; an unrelated CA is "
                 "rejected"),
    },
    "libarchive": {
        "program": ".l7-libarchive-harness", "launch": ["--version"],
        "version_re": r"libarchive-l7-harness", "lib_paths": [".libs"],
        "harness": {
            "source": "forensics/tools/l7_libarchive.c",
            "cflags": ["-I{root}/libarchive", "-I{prefix}/include"],
            "ldflags": ["-L{root}/.libs", "-L{prefix}/lib",
                        "-Wl,-rpath,{root}/.libs", "-Wl,-rpath,{prefix}/lib",
                        "-larchive", "-lcrypto", "-lz"],
        },
        "note": ("libarchive's own create/read path: an in-memory tar carries a payload and its "
                 "libcrypto SHA-256 digest, the read-back verifies it, and a tampered payload "
                 "byte is rejected"),
    },
    # The Phase-25 L7-expansion batch. mosquitto's recipe builds only lib/, so the broker and its
    # own clients are built here from the same pristine tree and prefix. cyrus-sasl ships no
    # executable: the harness drives its client/server SASL APIs with DIGEST-MD5. links is a
    # non-interactive HTTPS consumer (its interactive UI never terminates in a pipe).
    "mosquitto": {
        "program": "src/mosquitto", "launch": ["-h"],
        "version_re": r"mosquitto version 2\.0", "lib_paths": ["lib"],
        "make_steps": [
            ["-C", "client", "WITH_TLS=yes", "WITH_CJSON=no"],
            ["-C", "src", "WITH_TLS=yes", "WITH_BUNDLED_DEPS=yes"],
        ],
        "note": ("mosquitto's own broker and clients: TLS1.3 listener with the fixture CA, a "
                 "retained publish and a subscribe over TLS returning the payload, and a client "
                 "trusting only the unrelated CA rejected with `unknown ca`"),
    },
    "cyrus-sasl": {
        "program": ".l7-cyrus-sasl-harness", "launch": ["--version"],
        "version_re": r"cyrus-sasl-l7-harness", "lib_paths": ["lib/.libs"],
        "harness": {
            "source": "forensics/tools/l7_cyrus_sasl.c",
            "cflags": ["-I{root}/include", "-Wno-cast-function-type"],
            "ldflags": ["-L{root}/lib/.libs", "-L{prefix}/lib",
                        "-Wl,-rpath,{root}/lib/.libs", "-Wl,-rpath,{prefix}/lib",
                        "-Wl,--no-as-needed", "-lsasl2", "-lssl", "-lcrypto"],
        },
        "note": ("the cyrus-sasl client and server APIs over a socketpair authenticate with "
                 "DIGEST-MD5 (libcrypto MD5/HMAC), and a wrong password is rejected"),
    },
    # The Phase-25 template-layer continuation's bespoke-workload families.  Each program links
    # the subject OpenSSL directly; the harnesses drive the family's own OpenSSL surface.
    "git-crypt": {"program": "git-crypt", "launch": ["--version"],
                  "version_re": r"git-crypt \d"},
    "s2n-tls": {"program": "b/bin/s2nd", "launch": ["--help"],
                "version_re": r"s2nd is an s2n-tls"},
    "openldap": {"program": "servers/slapd/slapd", "launch": ["-VV"],
                 "version_re": r"slapd 2\.6"},
    "srt": {"program": "b/srt-live-transmit", "launch": ["-h"],
            "version_re": r"SRT Library version"},
    "slowhttptest": {"program": "src/slowhttptest", "launch": ["-h"],
                     "version_re": r"slowhttptest.*version"},
    "cyrus-sasl-scram": {
        "program": ".l7-sasl-scram-harness", "launch": ["--version"],
        "version_re": r"cyrus-sasl-l7-harness SCRAM-SHA-256", "lib_paths": ["lib/.libs"],
        "harness": {
            "source": "forensics/tools/l7_cyrus_sasl.c",
            "cflags": ["-I{root}/include", "-Wno-cast-function-type",
                       "-DL7_MECH=\"SCRAM-SHA-256\""],
            "ldflags": ["-L{root}/lib/.libs", "-L{prefix}/lib",
                        "-Wl,-rpath,{root}/lib/.libs", "-Wl,-rpath,{prefix}/lib",
                        "-Wl,--no-as-needed", "-lsasl2", "-lssl", "-lcrypto"],
        },
        "note": "SCRAM-SHA-256 client/server over a socketpair; wrong password rejected",
    },
    "sipsak": {"program": "sipsak", "launch": ["-V"],
              "version_re": r"sipsak \d"},
    "cyrus-sasl-digestmd5": {
        "program": ".l7-sasl-digestmd5-harness", "launch": ["--version"],
        "version_re": r"cyrus-sasl-l7-harness DIGEST-MD5", "lib_paths": ["lib/.libs"],
        "harness": {
            "source": "forensics/tools/l7_cyrus_sasl.c",
            "cflags": ["-I{root}/include", "-Wno-cast-function-type",
                       "-DL7_MECH=\"DIGEST-MD5\""],
            "ldflags": ["-L{root}/lib/.libs", "-L{prefix}/lib",
                        "-Wl,-rpath,{root}/lib/.libs", "-Wl,-rpath,{prefix}/lib",
                        "-Wl,--no-as-needed", "-lsasl2", "-lssl", "-lcrypto"],
        },
        "note": "DIGEST-MD5 client/server over a socketpair; wrong password rejected",
    },
    # The Phase-25 L7 onboarding batch (b14).  Five programs are the family's own
    # executable; four libraries ship none, so their admitted consumers are harnesses
    # compiled against the rebuilt library and the subject prefix.
    "nmap-ncat": {
        "program": "ncat/ncat", "launch": ["--version"],
        "version_re": r"Ncat: Version 7\.95",
        "note": ("Ncat's TLS client: a verified TLS exchange with a local peer carries the "
                 "payload and an unrelated CA is rejected"),
    },
    "unbound": {
        "program": "unbound", "launch": ["-V"],
        "version_re": r"Version 1\.22\.0",
        "note": ("Unbound's DoT forwarder: a forwarding resolver retrieves a fixture zone from "
                 "a local TLS resolver, and a resolver trusting only an unrelated CA cannot"),
    },
    "qpdf": {
        "program": "b/qpdf/qpdf", "launch": ["--version"],
        "version_re": r"qpdf version 11\.9",
        "note": ("qpdf's OpenSSL crypto provider encrypts a PDF with AES-256, reports R=6, "
                 "decrypts with the right password and rejects the wrong one"),
    },
    "nagios-plugins-smtp": {
        "program": "plugins/check_smtp", "launch": ["-V"],
        "version_re": r"check_smtp v2\.4\.0",
        "note": ("check_smtp's STARTTLS path: a local STARTTLS peer succeeds and a peer that "
                 "does not advertise STARTTLS is rejected"),
    },
    "nagios-plugins-ldap": {
        "program": "plugins/check_ldap", "launch": ["-V"],
        "version_re": r"check_ldap v2\.4\.0",
        "note": ("check_ldap's LDAPS path: a local LDAP peer accepts the TLS simple bind and "
                 "search, while the wrong password is rejected"),
    },
    "efitools": {
        "program": "sign-efi-sig-list", "launch": ["-h"],
        "version_re": r"sign-efi-sig-list",
        "note": ("efitools' EFI signature-list path: a certificate is encoded as an ESL and "
                 "signed into an authenticated variable update, while a mismatched key is "
                 "refused"),
    },
    "libpaho-mqtt": {
        "program": ".l7-paho-harness", "launch": ["--version"],
        "version_re": r"paho-mqtt-l7-harness", "lib_paths": ["b/src"],
        "harness": {
            "source": "forensics/tools/l7_paho.c",
            "cflags": ["-I{root}/src", "-I{prefix}/include"],
            "ldflags": ["-L{root}/b/src", "-L{prefix}/lib",
                        "-Wl,-rpath,{root}/b/src", "-Wl,-rpath,{prefix}/lib",
                        "-lpaho-mqtt3cs", "-lssl", "-lcrypto", "-lpthread"],
        },
        "note": "paho.mqtt.c TLS CONNECT/CONNACK; unrelated CA rejected",
    },
    "srtp": {
        "program": ".l7-libsrtp-harness", "launch": ["--version"],
        "version_re": r"libsrtp-l7-harness", "lib_paths": ["b"],
        "harness": {
            "source": "forensics/tools/l7_libsrtp.c",
            "cflags": ["-I{root}/include", "-I{prefix}/include"],
            "ldflags": ["-L{root}/b", "-L{prefix}/lib",
                        "-Wl,-rpath,{root}/b", "-Wl,-rpath,{prefix}/lib",
                        "-lsrtp2", "-lcrypto", "-lpthread", "-lm"],
        },
        "note": "libsrtp AES-CM/HMAC protect+unprotect; wrong key rejected",
    },
    "rabbitmq-c": {
        "program": ".l7-rabbitmq-harness", "launch": ["--version"],
        "version_re": r"rabbitmq-c-l7-harness", "lib_paths": ["b/librabbitmq"],
        "harness": {
            "source": "forensics/tools/l7_rabbitmq.c",
            "cflags": ["-I{root}/include", "-I{root}/b/include", "-I{prefix}/include"],
            "ldflags": ["-L{root}/b/librabbitmq", "-L{prefix}/lib",
                        "-Wl,-rpath,{root}/b/librabbitmq", "-Wl,-rpath,{prefix}/lib",
                        "-lrabbitmq", "-lssl", "-lcrypto", "-lpthread"],
        },
        "note": "rabbitmq-c SSL socket open; unrelated CA rejected",
    },
    "links": {
        "program": "links", "launch": ["-version"],
        "version_re": r"Links 2\.30",
        "note": ("links' non-interactive HTTPS consumer path: `-dump` of a local TLS server "
                 "verifies the fixture CA and renders the payload; the unrelated CA is rejected "
                 "with `Invalid certificate`"),
    },
    # The closing Phase-25 L7-expansion pair. dovecot's executables satisfy their SSL dependency
    # through a module loaded with dlopen (no `ldd` line names libssl), so the admitted program is
    # the dovecot-owned TLS client harness; the workload is the installed dovecot master serving
    # IMAPS. librdkafka is library-only: the harness drives its SSL transport against a local TLS
    # broker stub. `make_steps` installs dovecot into its own build tree (`DESTDIR`) before the
    # load proof, because the master needs its full libexec/module layout to start.
    "dovecot": {
        "program": ".l7-dovecot-harness", "launch": ["--version"],
        "version_re": r"dovecot-l7-harness",
        "harness": {
            "source": "forensics/tools/l7_dovecot.c",
            "cflags": ["-I{prefix}/include"],
            "ldflags": ["-L{prefix}/lib", "-Wl,-rpath,{prefix}/lib", "-lssl", "-lcrypto"],
        },
        "make_steps": [["install", "DESTDIR={root}/.l7-install"]],
        "note": ("dovecot's installed IMAPS listener: a dovecot-linked TLS client verifies the "
                 "fixture CA, logs in, APPENDs a message, SELECTs INBOX and FETCHes the exact "
                 "payload back; an unrelated CA fails with `certificate verify failed`"),
    },
    "librdkafka": {
        "program": ".l7-rdkafka-harness", "launch": ["--version"],
        "version_re": r"librdkafka-l7-harness", "lib_paths": ["src"],
        "harness": {
            "source": "forensics/tools/l7_rdkafka.c",
            "cflags": ["-I{root}/src", "-I{prefix}/include", "-Wno-ignored-qualifiers"],
            "ldflags": ["-L{root}/src", "-L{prefix}/lib", "-Wl,-rpath,{root}/src",
                        "-Wl,-rpath,{prefix}/lib", "-lrdkafka", "-lssl", "-lcrypto",
                        "-lpthread", "-lz", "-ldl", "-lrt", "-lm"],
        },
        "note": ("librdkafka's SSL transport: a producer with `security.protocol=ssl` completes "
                 "a TLS handshake with a local broker stub, reports the connection UP and sends "
                 "its Metadata request; an unrelated CA fails certificate verification"),
    },
    # The Phase-25 L7-expansion batch: five LIBRARY-only families. Each ships no executable, so
    # the admitted workload is a harness under forensics/tools/ built against the family library
    # rebuilt in this source tree and the subject prefix. The harnesses assert the family's own
    # crypto consumer path and a negative control (a tampered signature, wrong key/password, or a
    # mutated digest).
    "jwt": {
        "program": ".l7-jwt-harness", "launch": ["--version"],
        "version_re": r"jwt-l7-harness", "lib_paths": ["b/libjwt"],
        "harness": {
            "source": "forensics/tools/l7_jwt.c",
            "cflags": ["-I{root}/include", "-I{prefix}/include"],
            "ldflags": ["-L{root}/b/libjwt", "-L{prefix}/lib",
                        "-Wl,-rpath,{root}/b/libjwt", "-Wl,-rpath,{prefix}/lib",
                        "-Wl,--no-as-needed", "-ljwt", "-lssl", "-lcrypto"],
        },
        "note": ("libjwt's RS256 and ES256 sign/decode paths: a claims set is signed and decoded "
                 "with locally generated keys, and a tampered signature is rejected"),
    },
    "libjose": {
        "program": ".l7-jose-harness", "launch": ["--version"],
        "version_re": r"jose-l7-harness", "lib_paths": ["b/lib"],
        "harness": {
            "source": "forensics/tools/l7_jose.c",
            "cflags": ["-I{root}/b", "-I{root}", "-I{prefix}/include"],
            "ldflags": ["-L{root}/b/lib", "-L{prefix}/lib",
                        "-Wl,-rpath,{root}/b/lib", "-Wl,-rpath,{prefix}/lib",
                        "-Wl,--no-as-needed", "-ljose", "-ljansson", "-lssl", "-lcrypto"],
        },
        "note": ("jose's JWS path: an ES256 JWK signs a payload, the JWS verifies with the same "
                 "key, and a second key is rejected"),
    },
    "libzip": {
        "program": ".l7-libzip-harness", "launch": ["--version"],
        "version_re": r"libzip-l7-harness", "lib_paths": ["b/lib"],
        "harness": {
            "source": "forensics/tools/l7_libzip.c",
            "cflags": ["-I{root}/lib", "-I{root}/b", "-I{prefix}/include"],
            "ldflags": ["-L{root}/b/lib", "-L{prefix}/lib",
                        "-Wl,-rpath,{root}/b/lib", "-Wl,-rpath,{prefix}/lib",
                        "-Wl,--no-as-needed", "-lzip", "-lssl", "-lcrypto"],
        },
        "note": ("libzip's AES-256 encrypted archive path: write/read with the right password and "
                 "a wrong-password reject"),
    },
    "apr-util": {
        "program": ".l7-aprutil-harness", "launch": ["--version"],
        "version_re": r"apr-util-l7-harness", "lib_paths": [".libs"],
        "harness": {
            "source": "forensics/tools/l7_aprutil.c",
            "cflags": ["-I{root}/include", "-I/usr/include/apr-1.0", "-I{prefix}/include"],
            "ldflags": ["-L{root}/.libs", "-L{prefix}/lib",
                        "-Wl,-rpath,{root}/.libs", "-Wl,-rpath,{prefix}/lib",
                        "-Wl,--no-as-needed", "-laprutil-1", "-lapr-1", "-lssl", "-lcrypto",
                        "-lpthread"],
        },
        "note": ("apr-util's MD5 digest vector plus a real libssl handshake over an apr_socket to "
                 "a local server, with a mutated-digest mismatch control"),
    },
    "fido2": {
        "program": ".l7-fido2-harness", "launch": ["--version"],
        "version_re": r"fido2-l7-harness", "lib_paths": ["b/src"],
        "harness": {
            "source": "forensics/tools/l7_fido2.c",
            "cflags": ["-I{root}/src", "-I{prefix}/include"],
            "ldflags": ["-L{root}/b/src", "-L{prefix}/lib",
                        "-Wl,-rpath,{root}/b/src", "-Wl,-rpath,{prefix}/lib",
                        "-Wl,--no-as-needed", "-lfido2", "-lssl", "-lcrypto"],
        },
        "note": ("libfido2's ES256 key representation: a P-256 key round-trips through "
                 "es256_pk_from_EVP_PKEY/es256_pk_to_EVP_PKEY, the ES256 signature verifies, and "
                 "an altered signature is rejected"),
    },
    # The Phase-25 L7 expansion batch (b9): six LIBRARY-only families. Each ships no executable,
    # so the admitted workload is a harness under forensics/tools/ built against the family
    # library rebuilt in this source tree and the subject prefix. Every harness asserts the
    # family's own OpenSSL consumer path plus a negative control (an unrelated CA, a wrong
    # password, or a corrupted input).
    "libwebsockets": {
        "program": ".l7-libwebsockets-harness", "launch": ["--version"],
        "version_re": r"libwebsockets-l7-harness", "lib_paths": ["b/lib"],
        "harness": {
            "source": "forensics/tools/l7_libwebsockets.c",
            "cflags": ["-I{root}/include", "-I{root}/b", "-I{prefix}/include"],
            "ldflags": ["-L{root}/b/lib", "-L{prefix}/lib",
                        "-Wl,-rpath,{root}/b/lib", "-Wl,-rpath,{prefix}/lib",
                        "-Wl,--no-as-needed", "-lwebsockets", "-lssl", "-lcrypto", "-lpthread"],
        },
        "note": ("libwebsockets' wss client and server over loopback: a TLS1.3 handshake with the "
                 "fixture CA and an echo round trip; a client trusting only an unrelated CA is "
                 "rejected"),
    },
    "libstrophe": {
        "program": ".l7-libstrophe-harness", "launch": ["--version"],
        "version_re": r"libstrophe-l7-harness", "lib_paths": [".libs"],
        "harness": {
            "source": "forensics/tools/l7_libstrophe.c",
            "cflags": ["-I{root}", "-I{prefix}/include"],
            "ldflags": ["-L{root}/.libs", "-L{prefix}/lib",
                        "-Wl,-rpath,{root}/.libs", "-Wl,-rpath,{prefix}/lib",
                        "-Wl,--no-as-needed", "-lstrophe", "-lssl", "-lcrypto", "-lexpat"],
        },
        "note": ("libstrophe's XMPP-over-TLS client: mandatory STARTTLS against a local stub, "
                 "certificate verification against the fixture CA, SASL PLAIN and a message "
                 "stanza round trip; an unrelated CA is rejected"),
    },
    "libcoap": {
        "program": ".l7-libcoap-harness", "launch": ["--version"],
        "version_re": r"libcoap-l7-harness", "lib_paths": ["b"],
        "harness": {
            "source": "forensics/tools/l7_libcoap.c",
            "cflags": ["-I{root}/include", "-I{root}/b", "-I{prefix}/include"],
            "ldflags": ["-L{root}/b", "-L{prefix}/lib",
                        "-Wl,-rpath,{root}/b", "-Wl,-rpath,{prefix}/lib",
                        "-Wl,--no-as-needed", "-lcoap-3", "-lssl", "-lcrypto", "-lpthread"],
        },
        "note": ("libcoap's CoAP-over-TLS server and client: a GET on /l7 returns the exact "
                 "payload over a verified TLS session; a client trusting only an unrelated CA "
                 "receives no response"),
    },
    "libesmtp": {
        "program": ".l7-libesmtp-harness", "launch": ["--version"],
        "version_re": r"libesmtp-l7-harness", "lib_paths": ["b"],
        "harness": {
            "source": "forensics/tools/l7_libesmtp.c",
            "cflags": ["-I{root}", "-I{prefix}/include"],
            "ldflags": ["-L{root}/b", "-L{prefix}/lib",
                        "-Wl,-rpath,{root}/b", "-Wl,-rpath,{prefix}/lib",
                        "-Wl,--no-as-needed", "-lesmtp", "-lssl", "-lcrypto", "-lpthread"],
        },
        "note": ("libesmtp's SMTP submission over STARTTLS against a local stub: the message is "
                 "accepted over a TLS1.3 session verified against the fixture CA; an unrelated CA "
                 "never establishes TLS"),
    },
    "minizip-ng": {
        "program": ".l7-minizip-ng-harness", "launch": ["--version"],
        "version_re": r"minizip-ng-l7-harness", "lib_paths": ["b"],
        "harness": {
            "source": "forensics/tools/l7_minizip_ng.c",
            "cflags": ["-I{root}", "-I{prefix}/include"],
            "ldflags": ["-L{root}/b", "-L{prefix}/lib",
                        "-Wl,-rpath,{root}/b", "-Wl,-rpath,{prefix}/lib",
                        "-Wl,--no-as-needed", "-lminizip", "-lssl", "-lcrypto"],
        },
        "note": ("minizip-ng's WinZip AES-256 archive path through its OpenSSL crypto backend: "
                 "write/read with the right password and a wrong-password reject"),
    },
    "libtins": {
        "program": ".l7-libtins-harness", "launch": ["--version"],
        "version_re": r"libtins-l7-harness", "lib_paths": ["b/lib"],
        "harness": {
            "source": "forensics/tools/l7_libtins.cpp",
            "cflags": ["-I{root}/include", "-I{root}/b/include", "-I{prefix}/include"],
            "ldflags": ["-L{root}/b/lib", "-L{prefix}/lib",
                        "-Wl,-rpath,{root}/b/lib", "-Wl,-rpath,{prefix}/lib",
                        "-Wl,--no-as-needed", "-ltins", "-lstdc++", "-lcrypto"],
        },
        "note": ("libtins' WPA2 crypto path through libcrypto: the supplicant PMK derivation "
                 "reproduces the 802.11i vector and a corrupted passphrase derives a different "
                 "key"),
    },
    # The Phase-25 L7 expansion batch (b10): six more LIBRARY-only families. Each harness links
    # the rebuilt family library and the subject prefix with --no-as-needed, and asserts one
    # concrete observable plus a negative control.
    "getdns": {
        "program": ".l7-getdns-harness", "launch": ["--version"],
        "version_re": r"getdns-l7-harness", "lib_paths": ["b"],
        "harness": {
            "source": "forensics/tools/l7_getdns.c",
            "cflags": ["-I{root}/b", "-I{prefix}/include"],
            "ldflags": ["-L{root}/b", "-L{prefix}/lib",
                        "-Wl,-rpath,{root}/b", "-Wl,-rpath,{prefix}/lib",
                        "-Wl,--no-as-needed", "-lgetdns", "-lssl", "-lcrypto",
                        "-lpthread"],
        },
        "note": ("getdns' DNS-over-TLS client: a verified TLS query returns the fixture A record, "
                 "and an unrelated CA is rejected"),
    },
    "libu2f-server": {
        "program": ".l7-libu2f-server-harness", "launch": ["--version"],
        "version_re": r"libu2f-server-l7-harness", "lib_paths": ["u2f-server/.libs"],
        "harness": {
            "source": "forensics/tools/l7_libu2f_server.c",
            "cflags": ["-I{root}", "-I{prefix}/include"],
            "ldflags": ["-L{root}/u2f-server/.libs", "-L{prefix}/lib",
                        "-L{aux}/usr/lib/x86_64-linux-gnu",
                        "-Wl,-rpath,{root}/u2f-server/.libs", "-Wl,-rpath,{prefix}/lib",
                        "-Wl,-rpath,{aux}/usr/lib/x86_64-linux-gnu",
                        "-Wl,--no-as-needed", "-lu2f-server", "-ljson-c", "-lssl",
                        "-lcrypto"],
        },
        "note": ("libu2f-server's ES256 registration and authentication: both verify, and a "
                 "signature made with the wrong key is rejected"),
    },
    "lua-luaossl": {
        "program": ".l7-luaossl-harness", "launch": ["--version"],
        "version_re": r"luaossl-l7-harness", "lib_paths": ["src/5.4", "src"],
        "harness": {
            "source": "forensics/tools/l7_lua_runner.c",
            "cflags": ["-I{aux}/usr/include/lua5.4",
                       "-I{aux}/usr/include/x86_64-linux-gnu",
                       "-DL7_NAME=\"luaossl-l7-harness\"",
                       "-DL7_SCRIPT_PATH=\"{repo}/forensics/tools/l7_luaossl.lua\"",
                       "-DL7_LUA_PATH=\"{root}/.l7-install/share/lua/5.4/?.lua;"
                       "{root}/.l7-install/share/lua/5.4/?/init.lua\"",
                       "-DL7_LUA_CPATH=\"{root}/.l7-install/lib/lua/5.4/?.so\""],
            "ldflags": ["-L{root}/src/5.4", "-L{prefix}/lib",
                        "-L{aux}/usr/lib/x86_64-linux-gnu",
                        "-Wl,-rpath,{root}/src/5.4", "-Wl,-rpath,{prefix}/lib",
                        "-Wl,-rpath,{aux}/usr/lib/x86_64-linux-gnu",
                        "-Wl,--no-as-needed", "-l:openssl.so", "-lssl", "-lcrypto",
                        "-llua5.4", "-lm", "-ldl", "-lpthread"],
        },
        "note": ("lua-luaossl: SHA-256 and HMAC-SHA256 vectors through the Lua binding, and a "
                 "corrupted input produces a different HMAC"),
    },
    "lua-sec": {
        "program": ".l7-luasec-harness", "launch": ["--version"],
        "version_re": r"luasec-l7-harness", "lib_paths": ["src", "src/luasocket"],
        "harness": {
            "source": "forensics/tools/l7_luasec.c",
            "cflags": ["-I{aux}/usr/include/lua5.4",
                       "-I{aux}/usr/include/x86_64-linux-gnu",
                       "-I{prefix}/include",
                       "-DL7_SCRIPT_PATH=\"{repo}/forensics/tools/l7_luasec.lua\"",
                       "-DL7_LUA_PATH=\"{root}/src/?.lua;{aux}/usr/share/lua/5.4/?.lua;"
                       "{aux}/usr/share/lua/5.4/?/init.lua\"",
                       "-DL7_LUA_CPATH=\"{root}/src/?.so;"
                       "{aux}/usr/lib/x86_64-linux-gnu/lua/5.4/?.so\""],
            "ldflags": ["-L{root}/src", "-L{prefix}/lib",
                        "-L{aux}/usr/lib/x86_64-linux-gnu",
                        "-Wl,-rpath,{root}/src", "-Wl,-rpath,{prefix}/lib",
                        "-Wl,-rpath,{aux}/usr/lib/x86_64-linux-gnu",
                        "-Wl,--no-as-needed", "-l:ssl.so", "-lssl", "-lcrypto",
                        "-llua5.4", "-lm", "-ldl", "-lpthread"],
        },
        "note": ("LuaSec's TLS client against a local server: a TLS1.3 handshake and payload round "
                 "trip with peer verification, and an unrelated CA is rejected"),
    },
    "duo_unix": {
        "program": ".l7-duo-unix-harness", "launch": ["--version"],
        "version_re": r"duo_unix-l7-harness", "lib_paths": ["lib/.libs", "compat/.libs"],
        "harness": {
            "source": "forensics/tools/l7_duo_unix.c",
            "cflags": ["-I{root}/lib", "-I{prefix}/include"],
            "ldflags": ["-L{root}/lib/.libs", "-L{root}/compat/.libs", "-L{prefix}/lib",
                        "-Wl,-rpath,{root}/lib/.libs", "-Wl,-rpath,{prefix}/lib",
                        "-Wl,--no-as-needed", "-lduo", "-lcompat", "-lssl", "-lcrypto",
                        "-lpthread"],
        },
        "note": ("duo_unix's libduo HMAC-SHA1 request signing: a local HTTPS endpoint verifies the "
                 "signature and authenticates, while a corrupted secret is rejected"),
    },
    "dcap-tunnel-ssl": {
        "program": ".l7-dcap-tunnel-ssl-harness", "launch": ["--version"],
        "version_re": r"dcap-tunnel-ssl-l7-harness", "lib_paths": ["plugins/ssl/.libs"],
        "harness": {
            "source": "forensics/tools/l7_dcap_tunnel_ssl.c",
            "cflags": ["-I{prefix}/include"],
            "ldflags": ["-L{root}/plugins/ssl/.libs", "-L{prefix}/lib",
                        "-Wl,-rpath,{root}/plugins/ssl/.libs", "-Wl,-rpath,{prefix}/lib",
                        "-Wl,--no-as-needed", "-lsslTunnel", "-lssl", "-lcrypto",
                        "-lpthread"],
        },
        "note": ("dcap-tunnel-ssl's libsslTunnel plugin: a TLS tunnel carries the auth line and a "
                 "payload round trip, while a non-TLS peer is rejected"),
    },
    # The Phase-25 L7 expansion batch (b11): three more library-level OpenSSL consumers. gensio
    # and sofia-sip are driven by TLS harnesses; jimtcl's aio SSL extension is driven from a
    # Tcl script evaluated by libjim.
    "gensio": {
        "program": ".l7-gensio-harness", "launch": ["--version"],
        "version_re": r"gensio-l7-harness", "lib_paths": ["lib/.libs"],
        "harness": {
            "source": "forensics/tools/l7_gensio.c",
            "cflags": ["-I{root}/include", "-I{prefix}/include"],
            "ldflags": ["-L{root}/lib/.libs", "-L{prefix}/lib",
                        "-Wl,-rpath,{root}/lib/.libs", "-Wl,-rpath,{prefix}/lib",
                        "-Wl,--no-as-needed", "-lgensio", "-lgensioosh", "-lssl",
                        "-lcrypto", "-lpthread"],
        },
        "note": ("gensio's ssl gensio: a loopback TLS request/response round trip with the "
                 "fixture CA, and an unrelated CA rejected"),
    },
    "jimtcl": {
        "program": ".l7-jimtcl-harness", "launch": ["--version"],
        "version_re": r"jimtcl-l7-harness", "lib_paths": [""],
        "harness": {
            "source": "forensics/tools/l7_jimtcl.c",
            "cflags": ["-I{root}", "-I{prefix}/include",
                       "-DL7_SCRIPT_PATH=\"{repo}/forensics/tools/l7_jimtcl.tcl\""],
            "ldflags": ["-L{root}", "-L{prefix}/lib", "-Wl,-rpath,{root}",
                        "-Wl,-rpath,{prefix}/lib", "-Wl,--no-as-needed",
                        "-l:libjim.so.0.81", "-lssl", "-lcrypto", "-lm", "-ldl"],
        },
        "note": ("jimtcl's aio SSL extension: a TLS server accepts a request and writes the "
                 "exact response, and a mismatched private key is rejected"),
    },
    "sofia-sip": {
        "program": ".l7-sofia-sip-harness", "launch": ["--version"],
        "version_re": r"sofia-sip-l7-harness", "lib_paths": ["libsofia-sip-ua/.libs"],
        "harness": {
            "source": "forensics/tools/l7_sofia_sip.c",
            "cflags": ["-I{prefix}/include", "-I{root}/libsofia-sip-ua/su",
                       "-I{root}/libsofia-sip-ua/msg", "-I{root}/libsofia-sip-ua/sip",
                       "-I{root}/libsofia-sip-ua/tport", "-I{root}/libsofia-sip-ua/url",
                       "-I{root}/libsofia-sip-ua/nea", "-I{root}/libsofia-sip-ua/stun",
                       "-I{root}/libsofia-sip-ua/features", "-I{root}/libsofia-sip-ua"],
            "ldflags": ["-L{root}/libsofia-sip-ua/.libs", "-L{prefix}/lib",
                        "-Wl,-rpath,{root}/libsofia-sip-ua/.libs",
                        "-Wl,-rpath,{prefix}/lib", "-Wl,--no-as-needed",
                        "-lsofia-sip-ua", "-lssl", "-lcrypto", "-lpthread", "-lrt"],
        },
        "note": ("sofia-sip's tport TLS transport: a SIP MESSAGE over loopback TLS returns its "
                 "payload, and an unrelated CA is rejected"),
    },
    # The Phase-25 L7 expansion batch (b13): two text browsers, an FTP/HTTP client, a web server
    # and a library harness. Each program is built against the subject prefix by the shared recipe.
    "elinks": {
        "program": "src/elinks", "launch": ["-version"],
        "version_re": r"ELinks 0\.16\.1",
        "note": ("ELinks' HTTPS client dumps a local page with the fixture CA and rejects an "
                 "unrelated CA"),
    },
    "lynx": {
        "program": "src/lynx", "launch": ["-version"],
        "version_re": r"Lynx Version 2\.9\.2",
        "note": ("Lynx's HTTPS client dumps a local page with the fixture CA and rejects an "
                 "unrelated CA"),
    },
    "lftp": {
        "program": "src/lftp", "launch": ["--version"],
        "version_re": r"LFTP \| Version 4\.9\.3",
        "note": ("lftp's OpenSSL backend fetches a file over a verified local HTTPS session and "
                 "rejects an unrelated CA"),
    },
    "lighttpd": {
        "program": "src/lighttpd", "launch": ["-v"],
        "version_re": r"lighttpd/1\.4\.76",
        "note": ("lighttpd's mod_openssl serves a document over TLS, and a client trusting only "
                 "an unrelated CA rejects the server certificate"),
    },
    "swtpm": {
        "program": "src/swtpm/.libs/swtpm", "launch": ["--version"],
        "version_re": r"TPM emulator version 0\.7\.1", "lib_paths": ["src/swtpm/.libs"],
        "note": ("swtpm's TPM2 socket front end: TPM2_Startup and GetRandom over the TCP data "
                 "channel, and an unknown command code rejected"),
    },
    "httping": {
        "program": "httping", "launch": ["-V"],
        "version_re": r"HTTPing v2\.5",
        "note": ("httping's HTTPS ping succeeds only against a real TLS peer (200 OK), while a "
                 "plain-TCP listener fails the handshake"),
    },
    "libssh": {
        "program": ".l7-libssh-harness", "launch": ["--version"],
        "version_re": r"libssh-l7-harness", "lib_paths": ["b/lib"],
        "harness": {
            "source": "forensics/tools/l7_libssh.c",
            "cflags": ["-I{root}/include", "-I{root}/b/include", "-I{prefix}/include"],
            "ldflags": ["-L{root}/b/lib", "-L{prefix}/lib",
                        "-Wl,-rpath,{root}/b/lib", "-Wl,-rpath,{prefix}/lib",
                        "-Wl,--no-as-needed", "-lssh", "-lssl", "-lcrypto", "-lz",
                        "-lpthread"],
        },
        "note": ("libssh's RSA key path: a pinned private key imports to its exact public blob, "
                 "and a corrupted encoding is rejected"),
    },
    # The Phase-25 L7 expansion batch (b12): five library/toolkit consumers whose OpenSSL paths are
    # driven by harnesses (libtpms' TPM2 command interface, libre's tls/tcp backend, libnetconf2's
    # TLS session client, liboauth2's JOSE path); arm-trusted-firmware-tools uses its own tools.
    "libtpms": {
        "program": ".l7-libtpms-harness", "launch": ["--version"],
        "version_re": r"libtpms-l7-harness", "lib_paths": ["src/.libs"],
        "harness": {
            "source": "forensics/tools/l7_libtpms.c",
            "cflags": ["-I{root}/include", "-I{prefix}/include"],
            "ldflags": ["-L{root}/src/.libs", "-L{prefix}/lib",
                        "-Wl,-rpath,{root}/src/.libs", "-Wl,-rpath,{prefix}/lib",
                        "-ltpms", "-lssl", "-lcrypto", "-lpthread"],
        },
        "note": ("libtpms' TPM2 command interface: TPM2_Startup, GetCapability and GetRandom "
                 "return the concrete family/manufacturer and 32 random bytes, while an "
                 "unknown command code is rejected"),
    },
    "libre": {
        "program": ".l7-libre-harness", "launch": ["--version"],
        "version_re": r"libre-l7-harness", "lib_paths": [""],
        "harness": {
            "source": "forensics/tools/l7_libre.c",
            "cflags": ["-I{root}/include", "-I{prefix}/include",
                       "-DHAVE_INTTYPES_H", "-DHAVE_STDBOOL_H"],
            "ldflags": ["-L{root}", "-L{prefix}/lib", "-Wl,-rpath,{root}",
                        "-Wl,-rpath,{prefix}/lib", "-lre", "-lssl", "-lcrypto",
                        "-lpthread", "-lm"],
        },
        "note": ("libre's SRTP path: AES-CM/HMAC-SHA1 protects a fixed RTP packet, a fresh "
                 "context recovers the payload, and a flipped authentication-tag byte is "
                 "rejected"),
    },
    "arm-trusted-firmware-tools": {
        "program": "tools/cert_create/cert_create", "launch": ["--help"],
        "version_re": r"CoT Generation Tool",
        "note": ("TF-A's cert_create signs a certificate chain that openssl verifies, a tampered "
                 "certificate is rejected, and fiptool packages the chain into a FIP whose "
                 "corrupted copy is rejected"),
    },
    "libnetconf2": {
        "program": ".l7-libnetconf2-harness", "launch": ["--version"],
        "version_re": r"libnetconf2-l7-harness", "lib_paths": ["b"],
        "harness": {
            "source": "forensics/tools/l7_libnetconf2.c",
            "cflags": ["-I{root}/src", "-I{root}/b/src", "-I{root}/b",
                       "-I{prefix}/include", "-I{aux}/usr/include",
                       "-DNC_ENABLED_TLS", "-DNC_ENABLED_SSH"],
            "ldflags": ["-L{root}/b", "-L{aux}/usr/lib/x86_64-linux-gnu",
                        "-L{prefix}/lib", "-Wl,-rpath,{root}/b",
                        "-Wl,-rpath,{aux}/usr/lib/x86_64-linux-gnu",
                        "-Wl,-rpath,{prefix}/lib", "-lnetconf2", "-lssh", "-lyang",
                        "-lssl", "-lcrypto", "-lpthread", "-lcrypt"],
        },
        "note": ("libnetconf2's TLS session client: a verified loopback session completes the "
                 "NETCONF hello exchange, while a client trusting only an unrelated CA never "
                 "connects"),
    },
    "liboauth2": {
        "program": ".l7-liboauth2-harness", "launch": ["--version"],
        "version_re": r"liboauth2-l7-harness", "lib_paths": [".libs"],
        "harness": {
            "source": "forensics/tools/l7_liboauth2.c",
            "cflags": ["-I{root}/include", "-I{prefix}/include", "-I{aux}/usr/include"],
            "ldflags": ["-L{root}/.libs", "-L{aux}/usr/lib/x86_64-linux-gnu",
                        "-L{prefix}/lib", "-Wl,-rpath,{root}/.libs",
                        "-Wl,-rpath,{aux}/usr/lib/x86_64-linux-gnu",
                        "-Wl,-rpath,{prefix}/lib", "-loauth2", "-lcjose", "-ljansson",
                        "-lcurl", "-lssl", "-lcrypto"],
        },
        "note": ("liboauth2's JOSE path: the SHA-256 EVP digest matches its known vector and a "
                 "cjose JWE round trip returns the payload, while a flipped ciphertext byte is "
                 "rejected"),
    },
    # The Phase-25 L7 server batch: three TLS servers, an FTPS server and a TLS terminator. Each is
    # a real local exchange with a concrete observable and a negative control, not a banner.
    "memcached": {
        "program": "memcached", "launch": ["-h"], "version_re": r"memcached 1\.6\.",
        "note": ("memcached's TLS listener (-Z): a set/get over TLS returns the stored value, an "
                 "unrelated CA is rejected, and plaintext on the TLS port never answers a get"),
    },
    "icecast": {
        "program": "src/icecast", "launch": ["-v"], "version_re": r"Icecast 2\.4",
        "note": ("icecast's HTTPS listener: a verified GET of a fixture returns 200 with its "
                 "bytes, and an unrelated CA is rejected"),
    },
    # Batch c1: the icecast2 package row plus the two package-split library rows.  Each reuses
    # its parent family's admitted harness unchanged; the observable is the same upstream
    # mechanism, measured against this family's own recipe and build.
    "icecast2": {
        "program": "src/icecast", "launch": ["-v"], "version_re": r"Icecast 2\.4",
        "note": ("the icecast2 package row: verified HTTPS GET of a fixture plus an "
                 "unrelated-CA reject over the subject libssl"),
    },
    "libevent-openssl-2.1-7": {
        "program": ".l7-libevent-harness", "launch": ["--version"],
        "version_re": r"libevent-l7-harness", "lib_paths": [".libs"],
        "harness": {
            "source": "forensics/tools/l7_libevent.c",
            "cflags": ["-I{root}/include", "-I{prefix}/include"],
            "ldflags": ["-L{root}/.libs", "-L{prefix}/lib",
                        "-Wl,-rpath,{root}/.libs", "-Wl,-rpath,{prefix}/lib",
                        "-levent_openssl", "-levent", "-lssl", "-lcrypto", "-pthread"],
        },
        "note": ("the libevent-openssl package row: a TLS1.3 bufferevent round trip that "
                 "verifies the fixture CA and rejects an unrelated CA"),
    },
    "libaprutil1": {
        "program": ".l7-aprutil-harness", "launch": ["--version"],
        "version_re": r"apr-util-l7-harness", "lib_paths": [".libs"],
        "harness": {
            "source": "forensics/tools/l7_aprutil.c",
            "cflags": ["-I{root}/include", "-I/usr/include/apr-1.0", "-I{prefix}/include"],
            "ldflags": ["-L{root}/.libs", "-L{prefix}/lib",
                        "-Wl,-rpath,{root}/.libs", "-Wl,-rpath,{prefix}/lib",
                        "-Wl,--no-as-needed", "-laprutil-1", "-lapr-1", "-lssl", "-lcrypto",
                        "-lpthread"],
        },
        "note": ("the libaprutil1 package row: apr-util's OpenSSL crypto driver plus a libssl "
                 "handshake over an apr_socket, with a mutated-digest control"),
    },
    "proftpd": {
        "program": "proftpd", "launch": ["-v"], "version_re": r"ProFTPD Version 1\.3",
        "note": ("proftpd's explicit FTPS: AUTH TLS login, PWD and a LIST over a PROT P data "
                 "connection listing the fixture, plaintext USER refused with 550, unrelated CA "
                 "rejected"),
    },
    "mini-httpd": {
        "program": "mini_httpd", "launch": ["-h"],
        "version_re": r"usage:.*mini_httpd",
        "note": ("mini_httpd's HTTPS listener: a verified GET of a fixture returns 200 with its "
                 "bytes, and an unrelated CA is rejected"),
    },
    "hitch": {
        "program": "src/hitch", "launch": ["--version"], "version_re": r"hitch 1\.8",
        "note": ("hitch's TLS terminator: a verified client handshake is proxied to a local "
                 "backend stub and its payload returned; a client trusting only the unrelated CA "
                 "is rejected"),
    },
    # The Phase-25 L7 client/proxy batch: a RadSec proxy, an IRC bouncer, a STARTTLS mail client and
    # an HTTPS text browser. Each workload is a real local protocol exchange with a concrete
    # observable and a negative control.
    "radsecproxy": {
        "program": "radsecproxy", "launch": ["-v"],
        "version_re": r"radsecproxy revision 1\.[19]",
        "note": ("radsecproxy's RadSec listener: a TLS client presents a fixture-CA certificate, "
                 "the Access-Request is relayed to a local UDP RADIUS backend and its "
                 "Access-Accept with the fixture Reply-Message returns over TLS; a client "
                 "trusting only the unrelated CA is rejected"),
    },
    "znc": {
        "program": "b/src/znc", "launch": ["--version"],
        "version_re": r"ZNC 1\.10",
        "note": ("ZNC's IRC-over-TLS listener: a verified client registers (001) and a PING is "
                 "answered with PONG; a plaintext client on the TLS port never registers"),
    },
    "s-nail": {
        "program": ".obj/s-nail", "launch": ["-V"],
        "version_re": r"s-nail v14\.9",
        "note": ("s-nail's SMTP submit path over STARTTLS to a local stub: the message is accepted "
                 "(250) and the stub records the exact body; a run trusting only the unrelated CA "
                 "fails certificate verification and is never accepted"),
    },
    "w3m": {
        "program": "w3m", "launch": ["-version"],
        "version_re": r"w3m version w3m/0\.5",
        "note": ("w3m's HTTPS consumer path: `-dump` of a local page with the fixture CA renders "
                 "the page body; the same request with the unrelated CA fails certificate "
                 "verification"),
    },
    # The Phase-25 L7 utility batch: a TLS downloader, an HTTPS benchmark, an Authenticode
    # signer/verifier, a FIT signer/verifier, a TLS interception proxy and the DKIM engine.
    "axel": {
        "program": "axel", "launch": ["--version"],
        "version_re": r"Axel 2\.17\.14",
        "note": ("axel's HTTPS downloader: a fixture file is fetched with the fixture CA and "
                 "byte-compared; a run trusting only the unrelated CA fails verification"),
    },
    "apache2-utils": {
        "program": "support/ab", "launch": ["-V"],
        "version_re": r"ApacheBench",
        "note": ("apache2-utils' `ab`: 20 HTTPS requests complete with 0 failures against the "
                 "authority's TLS server; the same benchmark against a plaintext listener "
                 "reports an SSL handshake failure on every request"),
    },
    "osslsigncode": {
        "program": "b/osslsigncode", "launch": ["--version"],
        "version_re": r"osslsigncode 2\.9",
        "note": ("osslsigncode's Authenticode path: a pristine PE from the release's tests is "
                 "signed and verified with a code-signing certificate, and a modified PE is "
                 "rejected with a digest mismatch"),
    },
    "u-boot-tools": {
        "program": "tools/mkimage", "launch": ["-V"],
        "version_re": r"mkimage version 2025\.01",
        "note": ("u-boot's FIT signing: `mkimage -F` signs a FIT image with an RSA key and the "
                 "public-key dtb, `fit_check_sign` accepts it, and a tampered payload is "
                 "rejected"),
    },
    "sslsplit": {
        "program": "sslsplit", "launch": ["-V"],
        "version_re": r"SSLsplit 0\.5\.5",
        "note": ("sslsplit's TLS interception: a customer connection is terminated with a "
                 "forged certificate from the fixture CA and forwarded to a local TLS backend; "
                 "a client trusting only the unrelated CA is rejected"),
    },
    "opendkim": {
        # opendkim's filter is a milter client (needs a sendmail milter peer this venue does
        # not admit); its DKIM engine is libopendkim, so the admitted program is a harness over
        # the libopendkim built from the same pristine tree.
        "program": ".l7-opendkim-harness", "launch": ["--version"],
        "version_re": r"opendkim-l7-harness", "lib_paths": ["libopendkim/.libs"],
        "harness": {
            "source": "forensics/tools/l7_opendkim.c",
            "cflags": ["-I{root}/libopendkim", "-I{prefix}/include", "-Wno-pointer-sign"],
            "ldflags": ["-L{root}/libopendkim/.libs", "-L{prefix}/lib",
                        "-Wl,-rpath,{root}/libopendkim/.libs", "-Wl,-rpath,{prefix}/lib",
                        "-lopendkim", "-lcrypto", "-lssl"],
        },
        "note": ("libopendkim's DKIM path: a message is signed with an RSA key and verified "
                 "through the library's key-lookup callback; a modified body fails "
                 "verification"),
    },
    # The Phase-25 L7 expansion batch (b5): service detection, a VPN handshake, a TLS control
    # channel, a voice-control listener, XMPP-over-TLS and an image digest.
    "nmap": {
        "program": "nmap", "launch": ["--version"],
        "version_re": r"Nmap version 7\.95",
        "note": ("nmap's own service-detection path: NSE `ssl-cert` against the authority's local "
                 "TLS server reports the fixture certificate's subject and RSA key; with no "
                 "listener the port is closed and no certificate is reported"),
    },
    "fastd": {
        "program": "b/src/fastd", "launch": ["--version"],
        "version_re": r"fastd .*v22",
        "note": ("fastd's ec25519/FHMQVC handshake: two instances configured as peers over "
                 "loopback complete the handshake; a peer with the wrong key never completes"),
    },
    # Kea's libtool-linked daemons resolve the build tree's libkea-* shared objects; every
    # `src/lib/*/.libs` directory and the agent's own are on the runtime library path.
    "kea": {
        "program": "src/bin/agent/.libs/kea-ctrl-agent", "launch": ["-v"],
        "version_re": r"2\.6\.3",
        "lib_paths": ["src/lib/*/.libs", "src/bin/agent/.libs"],
        "note": ("Kea's HTTPS control channel: a client verifies the fixture CA, POSTs "
                 "list-commands over TLS and gets result 0; a client trusting only the unrelated "
                 "CA fails certificate verification"),
    },
    "mumble-server": {
        "program": "b/mumble-server", "launch": ["--version"],
        "version_re": r"1\.5\.735",
        "note": ("mumble-server's TLS listener: a verified client handshake returns the framed "
                 "Mumble Version message naming release 1.5.735; a client trusting only the "
                 "unrelated CA is rejected with `unknown ca`"),
    },
    "prosody": {
        # Prosody is Lua; the admitted program is the recipe's harness, which embeds Lua 5.4 and
        # runs prosody's own entry script. LuaSec (built against the subject prefix) is the
        # OpenSSL consumer the XMPP listener uses.
        "program": ".l7-prosody-harness", "launch": ["--version"],
        "version_re": r"prosody-l7-harness",
        "note": ("Prosody's XMPP-over-TLS listener (LuaSec against the subject libssl): a client "
                 "registers, authenticates and receives an IQ ping result; a client trusting "
                 "only the unrelated CA fails TLS verification"),
    },
    "partclone": {
        "program": "src/partclone.extfs", "launch": ["--version"],
        "version_re": r"partclone",
        "note": ("partclone.extfs's torrent_info path: the generated SHA-1 matches the block-file "
                 "digest, the restored filesystem payload matches, and a corrupted image block is "
                 "detected by the CRC"),
    },
    # The Phase-25 L7 expansion batch (b6): three TLS servers, two IRC clients and an SNMP agent.
    "exim": {
        "program": "build-Linux-x86_64/exim", "launch": ["--version"],
        "version_re": r"Exim version 4\.100\.1",
        "note": ("Exim's SMTP STARTTLS submission path: a message is submitted over a verified "
                 "TLS 1.3 session and queued (250 OK); a client trusting only the unrelated CA is "
                 "refused at certificate verification"),
    },
    "nsd": {
        "program": "nsd", "launch": ["-v"],
        "version_re": r"NSD version 4\.10\.1",
        "note": ("NSD's DNS-over-TLS listener: a length-framed A query for the fixture zone is "
                 "answered authoritatively over TLS; the same query sent as plaintext to the TLS "
                 "port yields no DNS answer"),
    },
    "net-snmp": {
        "program": "agent/snmpd", "launch": ["-v"],
        "version_re": r"NET-SNMP version:\s*5\.9\.4",
        "note": ("net-snmp's SNMPv3 USM authentication path (HMAC-SHA-1 through the subject "
                 "libcrypto): snmpget returns the fixture sysLocation; a wrong authentication "
                 "password is refused with `Authentication failure`"),
    },
    "eggdrop": {
        "program": "eggdrop", "launch": ["-v"],
        "version_re": r"Eggdrop v1\.9\.5",
        "note": ("eggdrop's IRC-over-TLS client: it registers and joins the fixture channel over "
                 "a verified TLS session against a local IRC stub; pointed at a plaintext "
                 "listener it never registers"),
    },
    "irssi": {
        "program": "src/fe-text/irssi", "launch": ["--version"],
        "version_re": r"irssi 1\.4\.5",
        # The recipe's single top-level `make` recurses into `src/fe-text`, but a re-measured
        # tree has been observed without the front-end program. Run the workload's own sub-make
        # explicitly so the artifact the load proof resolves is always built, and a failure here
        # is reported as a build-step failure rather than a misleading "no program".
        "make_steps": [["-C", "src/fe-text"]],
        "note": ("irssi's IRC-over-TLS client: it connects, registers, joins the fixture channel "
                 "and receives the fixture message over a verified TLS session; with only the "
                 "unrelated CA the TLS verification fails and it never registers"),
    },
    "openssh-server": {
        "program": "sshd", "launch": ["-V"],
        "version_re": r"OpenSSH_9\.9p1",
        "note": ("sshd 9.9p1's server direction: a host key and a fixture client key are "
                 "generated, sshd -D serves, and ssh with StrictHostKeyChecking=yes runs `echo "
                 "ok`; a known_hosts entry for a different host key is rejected with `Host key "
                 "verification failed`"),
    },
    # The Phase-25 L7 expansion batch (b7): a packet capture, an offline NNTP client, an IRC
    # client, a TLS banner grabber, an HTTPS benchmark and an OpenSSL-digest password tool.
    "tcpdump": {
        "program": "tcpdump", "launch": ["--version"],
        "version_re": r"tcpdump version 4\.99\.6",
        "note": ("tcpdump's capture path: a local TLS handshake is captured on loopback and its "
                 "handshake record bytes are printed from the pcap; a plaintext capture prints "
                 "no TLS record"),
    },
    "slrn": {
        "program": "src/objs/slrn", "launch": ["--version"],
        "version_re": r"slrn 1\.0\.3",
        "note": ("slrn's slrnpull NNTP-over-TLS client fetches a fixture article over a real "
                 "TLS session; a plaintext peer on the same port cannot complete the handshake "
                 "and fetches no article. slrn 1.0.3a's src/sltcp.c only calls SSL_CTX_new and "
                 "never sets a verify mode, so the workload does not claim peer authentication"),
    },
    "epic5": {
        "program": "source/epic5", "launch": ["-v"],
        "version_re": r"EPIC5-3\.0\.3",
        "note": ("epic5's IRC-over-TLS client registers and joins the fixture channel; a client "
                 "trusting only the unrelated CA is refused at certificate verification"),
    },
    "bannergrab": {
        "program": "bannergrab", "launch": ["--version"],
        "version_re": r"Version 3\.5",
        "note": ("bannergrab's TLS path against a local HTTPS fixture prints the negotiated "
                 "protocol, cipher and certificate; a closed port yields no banner"),
    },
    "httperf": {
        "program": "src/httperf", "launch": ["--version"],
        "version_re": r"httperf",
        "note": ("httperf's HTTPS path completes one request with one successful reply against a "
                 "local TLS server; the same --ssl run against a plaintext listener yields zero "
                 "successful replies"),
    },
    "makepasswd": {
        "program": "src/makepasswd", "launch": ["--help"],
        "version_re": r"Usage: makepasswd",
        "note": ("makepasswd's OpenSSL MD5 digest path: a fixed password and salt produce the "
                 "exact MD5 digest, repeated runs are identical, and a different salt differs"),
    },
    # The Phase-25 L7 expansion batch (b8): two WPA KDF tools (cowpatty's genpmk and
    # hcxtools' hcxpmktool), the aircrack-ng cracking path, NRPE over TLS and mktorrent's
    # SHA-1 piece hashing.  Each asserts a digest/KDF or protocol result, not a banner.
    "cowpatty": {
        "program": "genpmk", "launch": ["-V"],
        "version_re": r"genpmk 1\.3",
        "note": ("cowpatty 4.8's genpmk computes the WPA PMK with OpenSSL's SHA-1 through "
                 "PBKDF2-HMAC-SHA1 (4096 iterations); a fixed SSID/passphrase matches the "
                 "published vector and a different passphrase yields a different PMK"),
    },
    "hcxtools": {
        "program": "hcxpmktool", "launch": ["--version"],
        "version_re": r"hcxpmktool 6\.2\.7",
        "note": ("hcxtools 6.2.7's hcxpmktool derives the WPA PMK with OpenSSL EVP "
                 "PBKDF2-HMAC-SHA1; the exact PMK over the fixture is asserted and a corrupted "
                 "passphrase changes it"),
    },
    "aircrack-ng": {
        "program": ".libs/aircrack-ng", "launch": ["--help"],
        "version_re": r"Aircrack-ng 1\.7",
        "lib_paths": [".libs", ".l7-install/lib"],
        "note": ("aircrack-ng 1.7's WPA key-cracking path recovers the known key from the "
                 "upstream handshake fixture and the pinned word list; a wrong word list "
                 "leaves the key unfound"),
    },
    "nrpe": {
        "program": "src/nrpe", "launch": ["-V"],
        "version_re": r"Version: 4\.1\.0",
        "note": ("NRPE 4.1.0's daemon and check_nrpe plugin speak TLS over loopback; a fixture "
                 "command's result is returned and a client trusting only the unrelated CA is "
                 "refused at certificate verification"),
    },
    "mktorrent": {
        "program": "mktorrent", "launch": ["-h"],
        "version_re": r"mktorrent 1\.1",
        "note": ("mktorrent 1.1 built with USE_OPENSSL=1 hashes each piece with OpenSSL SHA-1; "
                 "a fixed fixture gives an exact info hash and a modified file changes it"),
    },
    # The Phase-25 L7 onboarding batch (b15).
    "vsftpd": {
        "program": "vsftpd", "launch": [],
        # vsftpd has no version/usage flag: the pinned release is the recipe digest, and the
        # load proof is the dynamic-loader resolution plus the admitted TLS workload.
        "version_re": r"(?s).*",
        "note": ("vsftpd's FTPS control/data path: anonymous login over AUTH TLS, PROT P data, "
                 "and an unrelated-CA client refused"),
    },
    "apache2-bin": {
        "program": "httpd", "launch": ["-v"],
        "version_re": r"Apache/2\.4\.62",
        "note": ("Apache httpd with static mod_ssl serves the fixture over verified TLS; an "
                 "unrelated CA is refused"),
    },
    "ssldump": {
        "program": "b/ssldump", "launch": ["-v"],
        "version_re": r"Version: 1\.8",
        "note": ("ssldump prints the ClientHello/ServerHello of a live loopback TLS handshake; a "
                 "plaintext exchange produces no handshake record"),
    },
    "yara": {
        "program": ".libs/yara", "lib_paths": [".libs"], "launch": ["--version"],
        "version_re": r"4\.5\.2",
        "note": ("YARA's hash module matches the fixture SHA-256 and a wrong digest does not"),
    },
    "bruteforce-salted-openssl": {
        "program": "bruteforce-salted-openssl", "launch": ["-h"],
        "version_re": r"bruteforce-salted-openssl 1\.4\.2",
        "note": ("recovers the fixture password through EVP; a word list without it yields no "
                 "candidate"),
    },
    "ircii": {
        "program": "irc", "launch": ["-v"],
        "version_re": r"ircII version 20240918",
        "note": ("ircII registers and joins the fixture channel over verified TLS; an "
                 "unrelated CA never registers"),
    },
    "neon": {
        "program": ".l7-neon-harness", "launch": ["--version"],
        "version_re": r"neon-l7-harness", "lib_paths": [],
        "harness": {
            "source": "forensics/tools/l7_neon.c",
            "cflags": ["-I{root}/src", "-I{prefix}/include"],
            "ldflags": ["-L{root}/src/.libs", "-L{prefix}/lib",
                        "-Wl,-rpath,{root}/src/.libs", "-Wl,-rpath,{prefix}/lib",
                        "-Wl,--no-as-needed", "-lneon", "-lssl", "-lcrypto", "-lexpat", "-lz"],
        },
        "note": ("libneon fetches the fixture over verified TLS; an unrelated CA is refused"),
    },
    "cjose": {
        "program": ".l7-cjose-harness", "launch": ["--version"],
        "version_re": r"cjose-l7-harness", "lib_paths": [],
        "harness": {
            "source": "forensics/tools/l7_cjose.c",
            "cflags": ["-I{root}/include", "-I{prefix}/include"],
            "ldflags": ["-L{root}/src/.libs", "-L{prefix}/lib",
                        "-Wl,-rpath,{root}/src/.libs", "-Wl,-rpath,{prefix}/lib",
                        "-Wl,--no-as-needed", "-lcjose", "-lssl", "-lcrypto", "-ljansson"],
        },
        "note": ("cjose signs and verifies an HS256 JWS and rejects a tampered signature and a "
                 "wrong key"),
    },
    "libevhtp": {
        "program": ".l7-evhtp-harness", "launch": ["--version"],
        "version_re": r"libevhtp-l7-harness", "lib_paths": [],
        "harness": {
            "source": "forensics/tools/l7_evhtp.c",
            "cflags": ["-I{root}/include", "-I{root}/b/include", "-I{prefix}/include",
                       "-I{aux}/usr/include"],
            "ldflags": ["{root}/b/libevhtp.so", "-L{root}/b", "-L{prefix}/lib",
                        "-Wl,-rpath,{root}/b",
                        "-L{aux}/usr/lib/x86_64-linux-gnu",
                        "-Wl,-rpath,{prefix}/lib",
                        "-Wl,-rpath,{aux}/usr/lib/x86_64-linux-gnu",
                        "-Wl,--no-as-needed", "-lssl", "-lcrypto", "-levent_openssl",
                        "-levent", "-lpthread"],
        },
        "note": ("libevhtp serves the fixture over verified TLS; an unrelated CA is refused"),
    },
    "libxmlsec1": {
        "program": "apps/.libs/xmlsec1",
        "lib_paths": ["src/.libs", "src/openssl/.libs"],
        "launch": ["--version"], "version_re": r"xmlsec1 1\.3\.12",
        "note": ("xmlsec1 signs a document with RSA-SHA256, verifies it, and rejects a tampered "
                 "document"),
    },

}

# The declarative template cohort: each entry is a config row in
# forensics/tools/downstream_template_families.json.  Merging (rather than growing another
# literal) keeps the template layer's family set and the build/link catalogue in one place.
PROGRAMS.update(templates.programs())

# The frozen runtime/functional rule, recorded verbatim in the artefact and re-derived by the court.
RULE: dict = {
    "id": "downstream-runtime-functional-atlas/1",
    "name": "the local-only runtime/functional atlas",
    "levels": [L5, L6, L7],
    "subjects": list(SUBJECTS),
    "ladder": (
        "L5-loaded: the built program starts under LD_LIBRARY_PATH=<subject>/lib and the subject's "
        "libssl/libcrypto are actually loaded -- the program's own ldd resolution of every OpenSSL "
        "soname is under the subject prefix (and never the authority's), and the loader initialises "
        "the subject library (an LD_DEBUG=libs dynamic-load trace); a version banner alone is not a "
        "load proof. L6-runtime: the program executes a real, local OpenSSL code path without "
        "failure (a TLS handshake, a key generation). L7-functional: the workload completes its "
        "intended effect -- a verified transfer, a verified TLS server response, a verified "
        "signature, a protocol round-trip over TLS"
    ),
    "authority_applicable_baseline": (
        "a specimen's authority-applicable baseline is the highest level its authority runtime rows "
        "reached; a candidate run is DROP_IN-relevant only when its own level rank is at least that "
        "rank, and the candidate is judged against what the authority itself achieved, never a "
        "higher aspirational level. The baseline is recorded on every candidate row and re-derived "
        "from the authority rows by the court"
    ),
    "local_only": (
        "every L6/L7 workload runs against local peers only -- the admitted authority's own openssl "
        "CLI and the subject-linked program, on loopback; no run touches the public internet. The "
        "network is used only to acquire a pristine source, exactly as 24.6 fetched it"
    ),
    "workload_policy": (
        "only a workload meaningful to the program is driven, never a manufactured one; where a "
        "program's workload needs a peer or dependency this venue does not admit, the exclusion is "
        "recorded with a reason and the level reached is stated honestly rather than faked"
    ),
    "normalisation": {
        "tag": NORMALISATION_TAG,
        "normalises": list(NORMALISATION_ALLOWED),
        "never": list(NORMALISATION_NEVER),
        "policy": (
            "the same normaliser is applied to both subjects; it replaces only absolute paths, "
            "ports, PIDs, timestamps and addresses, and never a return code, an error class, a "
            "certificate decision, or a protocol/algorithm choice"
        ),
    },
    "accounting": (
        "all 1000 frozen families are emitted under both subjects; a family with no admitted recipe, "
        "or whose build/link row never reached L4-linked, is `not_attempted` with a reason, never "
        "omitted and never fabricated into a pass"
    ),
    "permit": (
        "a runtime row may not reach a level above the level its build/link row reached: a subject "
        "that never linked cannot load"
    ),
    "confinement": (
        "each fetch, build and run runs inside the admitted court container under its cgroup caps "
        "and this tool's own wall-clock bounds; scratch is under /work/court and removed afterwards"
    ),
    "constants": {"make_jobs": MAKE_JOBS, "step_timeout_seconds": STEP_TIMEOUT,
                  "launch_timeout_seconds": LAUNCH_TIMEOUT},
}


# --------------------------------------------------------------------------------------------
# deterministic transcript normalisation (the same normaliser for both subjects)
# --------------------------------------------------------------------------------------------

_TS_ISO = re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?\b")
_TS_HUMAN = re.compile(r"\b[A-Z][a-z]{2} [A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2} \d{4}\b")
_TS_CLOCK = re.compile(r"\b\d{2}:\d{2}:\d{2}(?:\.\d+)?\b")
_PID = re.compile(r"\b(pid|PID|Pid|process|Process)\b[ =:]*\d+\b")
_HEXADDR = re.compile(r"\b0x[0-9a-fA-F]+\b")
_IPPORT = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}:\d+\b")
_IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


def normalise_transcript(text: str, prefix: Path, authority_prefix: Path, scratch: Path,
                         port: int | None = None) -> str:
    """The portable form of a transcript: paths/ports/PIDs/timestamps/addresses become tokens.

    Only genuinely nondeterministic and contract-irrelevant values are replaced. A return code, an
    error class, a certificate decision and a protocol/algorithm choice are **not** touched: they are
    the evidence the workload exists to produce.
    """
    if not text:
        return ""
    for p, token in ((str(prefix), "{prefix}"), (str(authority_prefix), "{authority}"),
                     (str(CANDIDATE_PREFIX), "{candidate}"), (str(scratch), "{scratch}"),
                     (str(REPO_ROOT), "{repo}")):
        if p and p != "/":
            text = text.replace(p, token)
    if port:
        text = re.sub(rf"(?<!\d){port}(?!\d)", "{port}", text)
    text = _TS_ISO.sub("{timestamp}", text)
    text = _TS_HUMAN.sub("{timestamp}", text)
    text = _TS_CLOCK.sub("{clock}", text)
    text = _PID.sub(lambda m: f"{m.group(1)} {{pid}}", text)
    text = _HEXADDR.sub("{addr}", text)
    text = _IPPORT.sub("{addr}", text)
    text = _IP.sub("{addr}", text)
    return text


# --------------------------------------------------------------------------------------------
# subprocess helpers (bounded; never raise on a non-zero exit)
# --------------------------------------------------------------------------------------------

def _run_captured(argv: list[str], *, cwd: Path | None = None, env: dict | None = None,
                  timeout: int = STEP_TIMEOUT, stdin_text: str | None = None) -> dict:
    start = time.monotonic()
    try:
        proc = subprocess.run([str(a) for a in argv], cwd=str(cwd) if cwd else None, env=env,
                              input=stdin_text, capture_output=True, text=True, timeout=timeout,
                              check=False)
        code, out, err = proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as exc:
        code = -1
        out = exc.stdout.decode("utf-8", "ignore") if isinstance(exc.stdout, bytes) \
            else (exc.stdout or "")
        err = (exc.stderr.decode("utf-8", "ignore") if isinstance(exc.stderr, bytes)
               else (exc.stderr or "")) + f"\nTIMEOUT after {timeout}s"
    except FileNotFoundError as exc:
        code, out, err = 127, "", str(exc)
    return {
        "argv": [os.path.basename(str(argv[0]))] + [str(a) for a in argv[1:]],
        "exit_code": code,
        "ok": code == 0,
        "stdout": out or "",
        "stderr": err or "",
        "elapsed_seconds": round(time.monotonic() - start, 3),
    }


def _spawn(argv: list[str], cwd: Path, env: dict, out_path: Path, err_path: Path,
           stdin_path: Path | None = None):
    outf = open(out_path, "w", encoding="utf-8")
    errf = open(err_path, "w", encoding="utf-8")
    inf = open(stdin_path, encoding="utf-8") if stdin_path else subprocess.DEVNULL
    try:
        proc = subprocess.Popen([str(a) for a in argv], cwd=str(cwd), env=env, stdout=outf,
                                stderr=errf, stdin=inf, text=True)
    finally:
        if stdin_path:
            inf.close()
    return proc, outf, errf


def _run_captured_bytes(argv: list[str], *, cwd: Path | None = None, env: dict | None = None,
                        timeout: int = STEP_TIMEOUT, stdin_bytes: bytes = b"") -> dict:
    """`_run_captured` for a protocol whose request is binary (a RADIUS packet over s_client)."""
    start = time.monotonic()
    try:
        proc = subprocess.run([str(a) for a in argv], cwd=str(cwd) if cwd else None, env=env,
                              input=stdin_bytes, capture_output=True, timeout=timeout,
                              check=False)
        code, out, err = proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as exc:
        code = -1
        out = exc.stdout or b""
        err = (exc.stderr or b"") + f"\nTIMEOUT after {timeout}s".encode()
    except FileNotFoundError as exc:
        code, out, err = 127, b"", str(exc).encode()
    return {
        "argv": [os.path.basename(str(argv[0]))] + [str(a) for a in argv[1:]],
        "exit_code": code,
        "ok": code == 0,
        # latin-1 is byte-transparent for the transcript; the RADIUS bytes are parsed from `raw`.
        "stdout": out.decode("latin-1"),
        "stderr": err.decode("latin-1"),
        "raw": out,
        "elapsed_seconds": round(time.monotonic() - start, 3),
    }


def _stop(proc) -> None:
    try:
        proc.terminate()
    except Exception:  # noqa: BLE001
        pass
    try:
        proc.wait(timeout=5)
    except Exception:  # noqa: BLE001
        try:
            proc.kill()
            proc.wait(timeout=5)
        except Exception:  # noqa: BLE001
            pass


def _kill_comm(name: str) -> None:
    """SIGKILL any leftover process whose comm is `name` (a daemonising server's child)."""
    for p in Path("/proc").glob("[0-9]*"):
        try:
            if (p / "comm").read_text(encoding="utf-8").strip() == name:
                os.kill(int(p.name), 9)
        except OSError:
            continue


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _wait_tcp(host: str, port: int, timeout: float = 25.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1.0):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def _wait_listen(port: int, timeout: float = 20.0, host: str = "127.0.0.1") -> bool:
    """Wait until `host:port` is in LISTEN state without opening a connection.

    A bare connect/close probe is not neutral for a protocol server: RELP's receiver writes its
    greeting as soon as it accepts, so a probe that closes immediately can raise SIGPIPE in the
    server before the real client arrives.  Reading `/proc/net/tcp` observes the listener without
    participating in the protocol.
    """
    want_ip = "0100007F" if host == "127.0.0.1" else None
    if want_ip is None:
        return _wait_tcp(host, port, timeout)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            lines = Path("/proc/net/tcp").read_text(encoding="utf-8").splitlines()[1:]
        except OSError:
            lines = []
        for line in lines:
            fields = line.split()
            if len(fields) < 4 or fields[3] != "0A":
                continue
            addr, _, port_hex = fields[1].partition(":")
            if addr == want_ip and int(port_hex, 16) == port:
                return True
        time.sleep(0.1)
    return False


def _wait_log(path: Path, needle: str, timeout: float = 25.0) -> bool:
    """Wait for a literal line/marker in a spawned program's log; the workload's own evidence."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if needle in _read(path):
            return True
        time.sleep(0.2)
    return False


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


# --------------------------------------------------------------------------------------------
# authority CLI helpers and a deterministic local PKI fixture
# --------------------------------------------------------------------------------------------

def _auth_ossl(authority_prefix: Path) -> Path:
    return authority_prefix / "bin" / "openssl"


def _auth_env(authority_prefix: Path) -> dict:
    return dict(os.environ, LD_LIBRARY_PATH=str(authority_prefix / "lib"), OPENSSL_CONF="/dev/null")


def _ossl(authority_prefix: Path, argv: list[str], *, cwd: Path | None = None,
          timeout: int = 60, stdin_text: str | None = None) -> dict:
    return _run_captured([str(_auth_ossl(authority_prefix))] + argv, cwd=cwd,
                         env=_auth_env(authority_prefix), timeout=timeout, stdin_text=stdin_text)


def _gen_pki(authority_prefix: Path, d: Path) -> dict:
    """A deterministic local PKI: a CA, a server cert with SAN IP:127.0.0.1, and an unrelated CA.

    The keys are freshly generated, so their bytes are nondeterministic -- but nothing hashes them:
    only the transcripts of the programs that consume the PKI are hashed, and those are normalised.
    """
    d.mkdir(parents=True, exist_ok=True)
    ca_key, ca_crt = d / "ca.key", d / "ca.crt"
    srv_key, srv_csr, srv_crt = d / "server.key", d / "server.csr", d / "server.crt"
    ext = d / "server.ext"
    other_key, other_crt = d / "other.key", d / "other-ca.crt"

    steps = [
        (["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(ca_key), "-out",
          str(ca_crt), "-days", "7", "-subj", "/CN=runtime test CA", "-addext",
          "basicConstraints=critical,CA:TRUE"], "CA"),
        (["req", "-newkey", "rsa:2048", "-nodes", "-keyout", str(srv_key), "-out", str(srv_csr),
          "-subj", "/CN=127.0.0.1"], "server csr"),
        (["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(other_key), "-out",
          str(other_crt), "-days", "7", "-subj", "/CN=runtime unrelated CA", "-addext",
          "basicConstraints=critical,CA:TRUE"], "unrelated CA"),
    ]
    for argv, what in steps:
        res = _ossl(authority_prefix, argv, timeout=60)
        if not res["ok"]:
            raise RuntimeError(f"generating the {what} failed: {census._error_line(res)}")
    ext.write_text("subjectAltName=IP:127.0.0.1,DNS:127.0.0.1,DNS:localhost\n"
                   "basicConstraints=CA:FALSE\n"
                   "keyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n",
                   encoding="utf-8")
    res = _ossl(authority_prefix, ["x509", "-req", "-in", str(srv_csr), "-CA", str(ca_crt),
                                   "-CAkey", str(ca_key), "-CAcreateserial", "-out", str(srv_crt),
                                   "-days", "7", "-extfile", str(ext)], timeout=60)
    if not res["ok"]:
        raise RuntimeError(f"signing the server certificate failed: {census._error_line(res)}")
    # A second server certificate with the same SAN but signed by the unrelated CA. It is an extra
    # fixture file used only by the getdns negative control, so a wrong-CA reject can be told apart
    # from a hostname mismatch.
    other_srv_key, other_srv_csr = d / "other-server.key", d / "other-server.csr"
    other_srv_crt = d / "other-server.crt"
    res = _ossl(authority_prefix, ["req", "-newkey", "rsa:2048", "-nodes", "-keyout",
                                   str(other_srv_key), "-out", str(other_srv_csr), "-subj",
                                   "/CN=127.0.0.1"], timeout=60)
    if not res["ok"]:
        raise RuntimeError(f"generating the unrelated server csr failed: "
                           f"{census._error_line(res)}")
    res = _ossl(authority_prefix, ["x509", "-req", "-in", str(other_srv_csr), "-CA",
                                   str(other_crt), "-CAkey", str(other_key), "-CAcreateserial",
                                   "-out", str(other_srv_crt), "-days", "7", "-extfile",
                                   str(ext)], timeout=60)
    if not res["ok"]:
        raise RuntimeError(f"signing the unrelated server certificate failed: "
                           f"{census._error_line(res)}")
    # the combined PEM a TLS server that takes cert+key in one file expects (nginx/haproxy/monit/
    # pure-ftpd/redis all accept separate files, but the combined form is portable)
    srv_pem = d / "server.pem"
    srv_pem.write_text(_read(srv_crt) + _read(srv_key), encoding="utf-8")
    # A client certificate from the same CA, for the workloads whose client authenticates to the
    # server with a certificate (hiredis-ssl's example, openvpn's client). It is an extra fixture
    # file only: it changes no workload that does not read it.
    cli_key, cli_csr, cli_crt = d / "client.key", d / "client.csr", d / "client.crt"
    cli_ext = d / "client.ext"
    res = _ossl(authority_prefix, ["req", "-newkey", "rsa:2048", "-nodes", "-keyout", str(cli_key),
                                   "-out", str(cli_csr), "-subj", "/CN=127.0.0.1"], timeout=60)
    if not res["ok"]:
        raise RuntimeError(f"generating the client csr failed: {census._error_line(res)}")
    cli_ext.write_text("subjectAltName=IP:127.0.0.1\nbasicConstraints=CA:FALSE\n"
                       "extendedKeyUsage=clientAuth\n", encoding="utf-8")
    res = _ossl(authority_prefix, ["x509", "-req", "-in", str(cli_csr), "-CA", str(ca_crt),
                                   "-CAkey", str(ca_key), "-CAcreateserial", "-out", str(cli_crt),
                                   "-days", "7", "-extfile", str(cli_ext)], timeout=60)
    if not res["ok"]:
        raise RuntimeError(f"signing the client certificate failed: {census._error_line(res)}")
    # A self-signed CA certificate that is also a server certificate. sofia-sip's tport TLS
    # client verifies the presented certificate against its cafile/CApath; tport's server side
    # presents exactly one certificate (SSL_CTX_use_certificate_file), so the fixture uses a
    # certificate that is its own issuer and the trust anchor. This is a fixture property.
    self_key, self_crt = d / "self.key", d / "self.crt"
    res = _ossl(authority_prefix, [
        "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(self_key), "-out",
        str(self_crt), "-days", "7", "-subj", "/CN=127.0.0.1", "-addext",
        "basicConstraints=critical,CA:TRUE", "-addext",
        "subjectAltName=IP:127.0.0.1,DNS:127.0.0.1,DNS:localhost", "-addext",
        "keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign", "-addext",
        "extendedKeyUsage=serverAuth"], timeout=60)
    if not res["ok"]:
        raise RuntimeError(f"generating the self-signed server certificate failed: "
                           f"{census._error_line(res)}")
    return {"ca_crt": ca_crt, "ca_key": ca_key, "srv_crt": srv_crt, "srv_key": srv_key,
            "srv_pem": srv_pem, "other_crt": other_crt, "other_key": other_key,
            "other_srv_crt": other_srv_crt, "other_srv_key": other_srv_key,
            "self_crt": self_crt, "self_key": self_key,
            "client_crt": cli_crt, "client_key": cli_key}


def _s_client(authority_prefix: Path, port: int, ca: Path, extra: list[str],
              stdin_text: str | None = "", timeout: int = 25) -> dict:
    argv = ["s_client", "-connect", f"127.0.0.1:{port}", "-CAfile", str(ca), "-servername",
            "127.0.0.1"] + extra
    return _ossl(authority_prefix, argv, timeout=timeout, stdin_text=stdin_text)


def _transcript(*parts: tuple[str, dict | None]) -> str:
    """A labelled transcript; exit codes are kept (they are evidence, never normalised)."""
    lines: list[str] = []
    for name, res in parts:
        if res is None:
            continue
        lines.append(f"== {name} ==")
        lines.append(f"exit={res.get('exit_code')}")
        for stream in ("stdout", "stderr"):
            blob = (res.get(stream) or "").strip("\n")
            if blob:
                lines.append(blob)
    return "\n".join(lines)


def _http_connect_proxy(port: int, stop: threading.Event) -> threading.Thread:
    """A minimal loopback HTTP CONNECT proxy on `port`, relaying bytes both ways.

    It answers `CONNECT host:port HTTP/1.x` with `200 Connection established` and then pipes the
    client and the origin until either side closes, exactly the one hop a CONNECT-tunnel workload
    needs. Every connection is handled on its own thread so a rejected tunnel cannot stall the next.
    """
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", port))
    listener.listen(8)
    listener.settimeout(0.5)

    def relay(src: socket.socket, dst: socket.socket) -> None:
        try:
            while True:
                chunk = src.recv(65536)
                if not chunk:
                    break
                dst.sendall(chunk)
        except OSError:
            pass
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass

    def handle(client: socket.socket) -> None:
        with client:
            client.settimeout(15.0)
            head = b""
            try:
                while b"\r\n\r\n" not in head:
                    chunk = client.recv(4096)
                    if not chunk:
                        return
                    head += chunk
                target = head.split(b"\r\n", 1)[0].decode("utf-8", "ignore").split()[1]
                host, _, num = target.rpartition(":")
                origin = socket.create_connection((host, int(num)), timeout=5.0)
            except (OSError, IndexError, ValueError):
                return
            with origin:
                client.sendall(b"HTTP/1.0 200 Connection established\r\n\r\n")
                upstream = threading.Thread(target=relay, args=(client, origin), daemon=True)
                upstream.start()
                relay(origin, client)
                upstream.join(timeout=2)

    def serve() -> None:
        while not stop.is_set():
            try:
                client, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=handle, args=(client,), daemon=True).start()
        listener.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return thread


# --------------------------------------------------------------------------------------------
# the workloads: real, deterministic, local OpenSSL exercises
# --------------------------------------------------------------------------------------------
#
# Each runner returns `{runtime_ok, functional_ok, failure_class, residual, reason, transcript,
# workload, local_only}`. `runtime_ok` means the L6 code path executed without failure; `functional_ok`
# means the workload produced its intended effect (L7). A runner that cannot be driven at all records
# the exclusion with a reason and `runtime_ok=False`.

def _wl_curl(ctx: dict) -> dict:
    """A verified TLS 1.3 client fetch from the subject-linked curl against the authority s_server."""
    ap, port, d = ctx["authority_prefix"], ctx["port"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    notes: list[str] = []
    srv, of, ef = _spawn([str(_auth_ossl(ap)), "s_server", "-accept", str(port), "-cert",
                          str(pki["srv_crt"]), "-key", str(pki["srv_key"]), "-tls1_3", "-www"],
                         d, _auth_env(ap), d / "srv.out", d / "srv.err")
    try:
        if not _wait_tcp("127.0.0.1", port):
            return _wl_fail(notes, "curl: the authority s_server did not listen", None, d)
        common = ["-sS", "--max-time", "15", "--tlsv1.3", "--tls-max", "1.3", "-o", "/dev/null",
                  "-w", "http_code=%{http_code}\\nssl_verify_result=%{ssl_verify_result}\\n"]
        ok = _run_captured([str(ctx["program"])] + common + ["--cacert", str(pki["ca_crt"]),
                           f"https://127.0.0.1:{port}/"], env=ctx["env"], timeout=40)
        neg = _run_captured([str(ctx["program"])] + common + ["--cacert", str(pki["other_crt"]),
                            f"https://127.0.0.1:{port}/"], env=ctx["env"], timeout=40)
    finally:
        _stop(srv)
        of.close()
        ef.close()
    runtime_ok = ok["ok"] and "http_code=200" in ok["stdout"]
    functional_ok = runtime_ok and not neg["ok"]
    transcript = _transcript(("curl-verify-fetch", ok), ("curl-unrelated-ca (must fail)", neg),
                             ("s_server", {"exit_code": 0, "stdout": _read(d / "srv.err")}))
    return {"runtime_ok": runtime_ok, "functional_ok": functional_ok,
            "failure_class": None if functional_ok else ("functional-failure" if runtime_ok else
                                                         "runtime-failure"),
            "residual": "none" if functional_ok else ("functional-divergence" if runtime_ok else
                                                      "runtime-failure"),
            "reason": None if functional_ok else
            ("the verified TLS 1.3 fetch did not return 200" if not runtime_ok else
             "the unrelated CA was not rejected, so the fetch does not verify"),
            "transcript": transcript, "workload": "curl: verified TLS1.3 fetch + unrelated-CA reject",
            "local_only": True}


def _wl_nginx(ctx: dict) -> dict:
    """A verified TLS 1.3 server response from the subject-linked nginx, read by authority s_client."""
    ap, port, d = ctx["authority_prefix"], ctx["port"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    serve = d / "serve"
    (serve / "docroot").mkdir(parents=True, exist_ok=True)
    (serve / "logs").mkdir(parents=True, exist_ok=True)
    (serve / "run").mkdir(parents=True, exist_ok=True)
    (serve / "conf").mkdir(parents=True, exist_ok=True)
    (serve / "docroot" / "index.html").write_text("phase24-runtime-nginx-ok\n", encoding="utf-8")
    conf = serve / "conf" / "nginx.conf"
    conf.write_text(f"""worker_processes 1;
pid {serve}/run/nginx.pid;
error_log {serve}/logs/error.log info;
events {{ worker_connections 128; }}
http {{
    access_log {serve}/logs/access.log;
    default_type text/plain;
    sendfile off;
    server {{
        listen 127.0.0.1:{port} ssl;
        server_name 127.0.0.1;
        ssl_certificate {pki['srv_crt']};
        ssl_certificate_key {pki['srv_key']};
        ssl_protocols TLSv1.3;
        root {serve}/docroot;
        location / {{ }}
    }}
}}
""", encoding="utf-8")
    t = _run_captured([str(ctx["program"]), "-t", "-p", str(serve), "-c", str(conf)],
                      env=ctx["env"], timeout=30)
    if not t["ok"]:
        return {"runtime_ok": False, "functional_ok": False, "failure_class": "runtime-failure",
                "residual": "runtime-failure",
                "reason": f"nginx rejected its SSL configuration: {census._error_line(t)}",
                "transcript": _transcript(("nginx -t", t)),
                "workload": "nginx: verified TLS1.3 server response", "local_only": True}
    srv, of, ef = _spawn([str(ctx["program"]), "-p", str(serve), "-c", str(conf), "-g",
                          "daemon off;"], serve, ctx["env"], d / "nginx.out", d / "nginx.err")
    try:
        if not _wait_tcp("127.0.0.1", port):
            return _wl_fail([("nginx -t", t)], "nginx did not listen", "runtime-failure", d)
        hs = _s_client(ap, port, pki["ca_crt"], ["-tls1_3", "-brief"], stdin_text="", timeout=25)
        get = _s_client(ap, port, pki["ca_crt"], ["-tls1_3", "-quiet"],
                        stdin_text="GET /index.html HTTP/1.0\r\nConnection: close\r\n\r\n",
                        timeout=25)
    finally:
        _stop(srv)
        _kill_comm("nginx")
        of.close()
        ef.close()
    runtime_ok = "Verification: OK" in hs["stderr"] and "Protocol version: TLSv1.3" in hs["stderr"]
    functional_ok = runtime_ok and "200 OK" in get["stdout"]
    return {"runtime_ok": runtime_ok, "functional_ok": functional_ok,
            "failure_class": None if functional_ok else ("functional-failure" if runtime_ok else
                                                         "runtime-failure"),
            "residual": "none" if functional_ok else ("functional-divergence" if runtime_ok else
                                                      "runtime-failure"),
            "reason": None if functional_ok else
            ("the TLS 1.3 handshake did not verify" if not runtime_ok else
             "the verified GET did not return 200"),
            "transcript": _transcript(("nginx -t", t), ("authority s_client -brief", hs),
                                      ("authority s_client GET", get)),
            "workload": "nginx: verified TLS1.3 server response", "local_only": True}


def _wl_haproxy(ctx: dict) -> dict:
    """A TLS-terminating haproxy proxy: authority s_client verifies and gets an HTTP 200."""
    ap, port, d = ctx["authority_prefix"], ctx["port"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    conf = d / "haproxy.cfg"
    conf.write_text(f"""global
    maxconn 100
    log stdout format raw local0
defaults
    mode http
    log global
    timeout connect 2s
    timeout client 5s
    timeout server 5s
frontend ft
    bind 127.0.0.1:{port} ssl crt {pki['srv_pem']}
    mode http
    http-request return status 200 content-type text/plain string phase24-runtime-haproxy-ok
""", encoding="utf-8")
    check = _run_captured([str(ctx["program"]), "-c", "-f", str(conf)], env=ctx["env"], timeout=30)
    if not check["ok"]:
        return {"runtime_ok": False, "functional_ok": False, "failure_class": "runtime-failure",
                "residual": "runtime-failure",
                "reason": f"haproxy rejected its TLS configuration: {census._error_line(check)}",
                "transcript": _transcript(("haproxy -c", check)),
                "workload": "haproxy: TLS terminator with a verified response", "local_only": True}
    srv, of, ef = _spawn([str(ctx["program"]), "-db", "-f", str(conf)], d, ctx["env"],
                         d / "haproxy.out", d / "haproxy.err")
    try:
        if not _wait_tcp("127.0.0.1", port):
            return _wl_fail([("haproxy -c", check)], "haproxy did not listen", "runtime-failure", d)
        hs = _s_client(ap, port, pki["ca_crt"], ["-tls1_3", "-brief"], stdin_text="", timeout=25)
        get = _s_client(ap, port, pki["ca_crt"], ["-tls1_3", "-quiet"],
                        stdin_text="GET / HTTP/1.0\r\nConnection: close\r\n\r\n", timeout=25)
    finally:
        _stop(srv)
        of.close()
        ef.close()
    runtime_ok = "Verification: OK" in hs["stderr"] and "Protocol version: TLSv1.3" in hs["stderr"]
    functional_ok = runtime_ok and "200 OK" in get["stdout"] and "phase24-runtime-haproxy-ok" in \
        get["stdout"]
    return {"runtime_ok": runtime_ok, "functional_ok": functional_ok,
            "failure_class": None if functional_ok else ("functional-failure" if runtime_ok else
                                                         "runtime-failure"),
            "residual": "none" if functional_ok else ("functional-divergence" if runtime_ok else
                                                      "runtime-failure"),
            "reason": None if functional_ok else
            ("the TLS 1.3 handshake did not verify" if not runtime_ok else
             "the proxied GET did not return the fixed 200"),
            "transcript": _transcript(("haproxy -c", check), ("authority s_client -brief", hs),
                                      ("authority s_client GET", get)),
            "workload": "haproxy: TLS terminator with a verified response", "local_only": True}


def _wl_openssh(ctx: dict) -> dict:
    """A libcrypto-only workload: ssh-keygen generates an Ed25519 key and signs/verifies a message."""
    ap, d, root = ctx["authority_prefix"], ctx["workdir"], ctx["root"]
    env = ctx["env"]
    mk = _run_captured(["make", MAKE_JOBS, "ssh-keygen"], cwd=root, env=ctx["build_env"],
                       timeout=STEP_TIMEOUT)
    keygen = root / "ssh-keygen"
    if not keygen.is_file():
        return {"runtime_ok": False, "functional_ok": False, "failure_class": "harness-failure",
                "residual": "out-of-scope",
                "reason": f"the libcrypto workload binary ssh-keygen was not built: "
                          f"{census._error_line(mk)}",
                "transcript": _transcript(("make ssh-keygen", mk)),
                "workload": "openssh: ssh-keygen sign/verify (libcrypto)", "local_only": True}
    key = d / "id_ed25519"
    msg = d / "msg"
    msg.write_text("phase24 runtime openssh fixture\n", encoding="utf-8")
    gen = _run_captured([str(keygen), "-t", "ed25519", "-f", str(key), "-N", "", "-q", "-C",
                         "runtime"], cwd=d, env=env, timeout=30)
    runtime_ok = gen["ok"] and key.is_file() and (d / "id_ed25519.pub").is_file()
    sign = verify = None
    functional_ok = False
    if runtime_ok:
        sign = _run_captured([str(keygen), "-Y", "sign", "-f", str(key), "-n", "file", "msg"],
                             cwd=d, env=env, timeout=30)
        sig = d / "msg.sig"
        allowed = d / "allowed_signers"
        allowed.write_text("runtime " + _read(d / "id_ed25519.pub").strip() + "\n",
                           encoding="utf-8")
        if sign["ok"] and sig.is_file():
            verify = _run_captured([str(keygen), "-Y", "verify", "-f", str(allowed), "-I",
                                    "runtime", "-n", "file", "-s", str(sig)], cwd=d, env=env,
                                   timeout=30, stdin_text="phase24 runtime openssh fixture\n")
            functional_ok = verify["ok"] and "Good" in (verify["stdout"] + verify["stderr"])
    return {"runtime_ok": runtime_ok, "functional_ok": functional_ok,
            "failure_class": None if functional_ok else ("functional-failure" if runtime_ok else
                                                         "runtime-failure"),
            "residual": "none" if functional_ok else ("functional-divergence" if runtime_ok else
                                                      "runtime-failure"),
            "reason": None if functional_ok else
            ("the Ed25519 key generation failed" if not runtime_ok else
             "the ssh-keygen signature did not verify"),
            "transcript": _transcript(("make ssh-keygen", mk), ("ssh-keygen keygen", gen),
                                      ("ssh-keygen -Y sign", sign), ("ssh-keygen -Y verify", verify)),
            "workload": "openssh: ssh-keygen Ed25519 sign/verify (libcrypto)", "local_only": True}


def _wl_redis(ctx: dict) -> dict:
    """A TLS redis: a verified handshake plus two independent encrypted paths.

    The PING path exercises a single command over TLS; the SET/GET path exercises two further
    record-layer round trips and asserts the returned value, so a broken record layer or a broken
    key space is distinguishable from a broken handshake. A client trusting only the unrelated CA
    must be rejected, so an unverifiable server certificate is a recorded failure rather than a
    silent pass.
    """
    ap, port, d = ctx["authority_prefix"], ctx["port"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    dbdir = d / "db"
    dbdir.mkdir(parents=True, exist_ok=True)
    argv = [str(ctx["program"]), "--bind", "127.0.0.1", "--port", "0", "--tls-port", str(port),
            "--tls-cert-file", str(pki["srv_crt"]), "--tls-key-file", str(pki["srv_key"]),
            "--tls-ca-cert-file", str(pki["ca_crt"]), "--tls-auth-clients", "no", "--save", "",
            "--protected-mode", "no", "--dir", str(dbdir)]
    srv, of, ef = _spawn(argv, d, ctx["env"], d / "redis.out", d / "redis.err")
    try:
        if not _wait_tcp("127.0.0.1", port):
            return _wl_fail([("redis-server", {"exit_code": 0, "stdout": _read(d / "redis.err")})],
                            "redis-server did not open its TLS port", "runtime-failure", d)
        hs = _s_client(ap, port, pki["ca_crt"], ["-tls1_3", "-brief"], stdin_text="", timeout=25)
        ping = _s_client(ap, port, pki["ca_crt"], ["-tls1_3", "-quiet"], stdin_text="PING\r\n",
                         timeout=25)
        kv = _s_client(ap, port, pki["ca_crt"], ["-tls1_3", "-quiet"],
                       stdin_text="SET phase24:probe phase24-value\r\nGET phase24:probe\r\n",
                       timeout=25)
        neg = _s_client(ap, port, pki["other_crt"],
                        ["-tls1_3", "-brief", "-verify_return_error"], stdin_text="", timeout=25)
    finally:
        _stop(srv)
        of.close()
        ef.close()
    runtime_ok = "Verification: OK" in hs["stderr"] and "Protocol version: TLSv1.3" in hs["stderr"]
    ping_ok = "+PONG" in ping["stdout"]
    kv_ok = "+OK" in kv["stdout"] and "phase24-value" in kv["stdout"]
    neg_rejected = (neg["exit_code"] != 0
                    and "certificate verify failed" in (neg["stderr"] + neg["stdout"]))
    functional_ok = runtime_ok and ping_ok and kv_ok and neg_rejected
    return {"runtime_ok": runtime_ok, "functional_ok": functional_ok,
            "failure_class": None if functional_ok else ("functional-failure" if runtime_ok else
                                                         "runtime-failure"),
            "residual": "none" if functional_ok else ("functional-divergence" if runtime_ok else
                                                      "runtime-failure"),
            "reason": None if functional_ok else
            ("the TLS 1.3 handshake did not verify" if not runtime_ok else
             "the encrypted PING did not return +PONG" if not ping_ok else
             "the SET/GET round trip did not return the stored value" if not kv_ok else
             "the unrelated CA was not rejected, so the server certificate does not verify"),
            "transcript": _transcript(("authority s_client -brief", hs),
                                      ("authority s_client PING", ping),
                                      ("authority s_client SET/GET", kv),
                                      ("authority s_client unrelated-ca (must fail)", neg),
                                      ("redis-server", {"exit_code": 0,
                                                        "stdout": _read(d / "redis.err")})),
            "workload": ("redis: TLS handshake + encrypted PING/+PONG + SET/GET round trip + "
                         "unrelated-CA reject"), "local_only": True}


def _wl_monit(ctx: dict) -> dict:
    """A TLS monit: verified TLS 1.3 and TLS 1.2 paths, each answering an HTTP request.

    TLS 1.2 and TLS 1.3 are separate handshake/record paths in the server's libssl, so both being
    exercised makes a version-specific regression visible. A client trusting only the unrelated CA
    must be rejected, so an unverifiable certificate is a recorded failure.
    """
    ap, port, d = ctx["authority_prefix"], ctx["port"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    # monit refuses a PEM or control file that is group/other readable: it validates the file mode
    # before it will use them, so the fixture tightens them the way a real deployment would.
    os.chmod(pki["srv_pem"], 0o600)
    conf = d / "monitrc"
    conf.write_text(f"""set daemon 5
set logfile {d}/monit.log
set httpd port {port} and
    use address 127.0.0.1
    ssl enable
    pemfile {pki['srv_pem']}
    allow runtime:runtime
""", encoding="utf-8")
    os.chmod(conf, 0o600)
    check = _run_captured([str(ctx["program"]), "-t", "-c", str(conf)], env=ctx["env"], timeout=30)
    if not check["ok"]:
        return {"runtime_ok": False, "functional_ok": False, "failure_class": "runtime-failure",
                "residual": "runtime-failure",
                "reason": f"monit rejected its SSL configuration: {census._error_line(check)}",
                "transcript": _transcript(("monit -t", check)),
                "workload": "monit: TLS httpd handshake + HTTP response", "local_only": True}
    srv, of, ef = _spawn([str(ctx["program"]), "-I", "-c", str(conf)], d, ctx["env"],
                         d / "monit.out", d / "monit.err")
    try:
        if not _wait_tcp("127.0.0.1", port):
            return _wl_fail([("monit -t", check)], "monit did not open its TLS httpd port",
                            "runtime-failure", d)
        hs = _s_client(ap, port, pki["ca_crt"], ["-tls1_3", "-brief"], stdin_text="", timeout=25)
        get = _s_client(ap, port, pki["ca_crt"], ["-tls1_3", "-quiet"],
                        stdin_text="GET / HTTP/1.0\r\nConnection: close\r\n\r\n", timeout=25)
        hs12 = _s_client(ap, port, pki["ca_crt"], ["-tls1_2", "-brief"], stdin_text="",
                         timeout=25)
        get12 = _s_client(ap, port, pki["ca_crt"], ["-tls1_2", "-quiet"],
                          stdin_text="GET / HTTP/1.0\r\nConnection: close\r\n\r\n", timeout=25)
        neg = _s_client(ap, port, pki["other_crt"],
                        ["-tls1_3", "-brief", "-verify_return_error"], stdin_text="", timeout=25)
    finally:
        _stop(srv)
        _kill_comm("monit")
        of.close()
        ef.close()
    runtime_ok = "Verification: OK" in hs["stderr"] and "Protocol version: TLSv1.3" in hs["stderr"]
    get_ok = "HTTP/" in get["stdout"]
    tls12_ok = ("Verification: OK" in hs12["stderr"]
                and "Protocol version: TLSv1.2" in hs12["stderr"]
                and "HTTP/" in get12["stdout"])
    neg_rejected = (neg["exit_code"] != 0
                    and "certificate verify failed" in (neg["stderr"] + neg["stdout"]))
    functional_ok = runtime_ok and get_ok and tls12_ok and neg_rejected
    return {"runtime_ok": runtime_ok, "functional_ok": functional_ok,
            "failure_class": None if functional_ok else ("functional-failure" if runtime_ok else
                                                         "runtime-failure"),
            "residual": "none" if functional_ok else ("functional-divergence" if runtime_ok else
                                                      "runtime-failure"),
            "reason": None if functional_ok else
            ("the TLS 1.3 handshake did not verify" if not runtime_ok else
             "the TLS httpd did not answer an HTTP request" if not get_ok else
             "the TLS 1.2 handshake or HTTP response failed" if not tls12_ok else
             "the unrelated CA was not rejected, so the server certificate does not verify"),
            "transcript": _transcript(("monit -t", check), ("authority s_client -brief", hs),
                                      ("authority s_client GET", get),
                                      ("authority s_client -brief tls1_2", hs12),
                                      ("authority s_client GET tls1_2", get12),
                                      ("authority s_client unrelated-ca (must fail)", neg)),
            "workload": ("monit: TLS httpd handshake + HTTP response over TLS 1.3 and TLS 1.2 + "
                         "unrelated-CA reject"), "local_only": True}


def _ftps_account(ctx: dict) -> tuple[str, str]:
    """The deterministic local FTPS account the venue creates in its own disposable container.

    A system account (home bound to the fixture dir) lets pure-ftpd's `-l unix` backend authenticate
    a real login; the account is created idempotently and never touches the image, only the running
    container's ephemeral /etc.
    """
    user, passwd = "p24ftps", "p24ftps-pw"
    who = _run_captured(["id", "-u", user], timeout=15)
    if who["exit_code"] != 0:
        _run_captured(["useradd", "-M", "-d", str(ctx["workdir"] / "ftphome"), "-s", "/bin/sh",
                       user], timeout=30)
        _run_captured(["chpasswd"], timeout=30, stdin_text=f"{user}:{passwd}\n")
    return user, passwd


def _wl_pureftpd(ctx: dict) -> dict:
    """An authenticated FTPS session: AUTH TLS, USER/PASS and PWD against the subject pure-ftpd.

    24.17 adds the missing deterministic local workload: a system FTP account the venue creates in
    its own disposable container, whose credentials the authority's own `openssl s_client -starttls
    ftp` uses. The session completes a real authenticated explicit-TLS login and a `PWD` round trip
    on loopback (no public network), so the family reaches the functional level the authority can.

    The second harness repeats the login over TLS 1.2 (a different handshake/record path from the
    default TLS 1.3 session) and a client trusting only the unrelated CA must be rejected, so a
    version-specific or certificate-chain defect is not masked by the single successful session.
    """
    ap, port, d = ctx["authority_prefix"], ctx["port"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    home = d / "ftphome"
    home.mkdir(parents=True, exist_ok=True)
    user, passwd = _ftps_account(ctx)
    argv = [str(ctx["program"]), "--tls=1", "--certfile", str(pki["srv_pem"]), "-S",
            f"127.0.0.1,{port}", "-E", "-j", "-l", "unix"]
    proc, of, ef = _spawn(argv, d, ctx["env"], d / "ftpd.out", d / "ftpd.err")
    try:
        if not _wait_tcp("127.0.0.1", port):
            return _wl_fail([("pure-ftpd", {"exit_code": 0, "stdout": _read(d / "ftpd.err")})],
                            "pure-ftpd did not open its control port", "runtime-failure", d)
        session = _ossl(ap, ["s_client", "-connect", f"127.0.0.1:{port}", "-starttls", "ftp",
                             "-CAfile", str(pki["ca_crt"]), "-servername", "127.0.0.1", "-brief",
                             "-ign_eof"],
                        timeout=25,
                        stdin_text=f"USER {user}\r\nPASS {passwd}\r\nPWD\r\nQUIT\r\n")
        session12 = _ossl(ap, ["s_client", "-connect", f"127.0.0.1:{port}", "-starttls", "ftp",
                               "-CAfile", str(pki["ca_crt"]), "-servername", "127.0.0.1",
                               "-tls1_2", "-ign_eof"],
                          timeout=25,
                          stdin_text=f"USER {user}\r\nPASS {passwd}\r\nPWD\r\nQUIT\r\n")
        neg = _ossl(ap, ["s_client", "-connect", f"127.0.0.1:{port}", "-starttls", "ftp",
                         "-CAfile", str(pki["other_crt"]), "-servername", "127.0.0.1",
                         "-verify_return_error", "-brief", "-ign_eof"],
                    timeout=25, stdin_text="")
    finally:
        _stop(proc)
        _kill_comm("pure-ftpd")
        of.close()
        ef.close()
    replies = (session["stdout"] or "") + (session["stderr"] or "")
    replies12 = (session12["stdout"] or "") + (session12["stderr"] or "")
    runtime_ok = "230" in replies or "331" in replies
    login_ok = runtime_ok and "230" in replies and "257" in replies
    tls12_ok = "230" in replies12 and "257" in replies12 and "TLSv1.2" in replies12
    neg_rejected = (neg["exit_code"] != 0
                    and "certificate verify failed" in (neg["stderr"] + neg["stdout"]))
    functional_ok = login_ok and tls12_ok and neg_rejected
    return {"runtime_ok": runtime_ok, "functional_ok": functional_ok,
            "failure_class": None if functional_ok else ("functional-failure" if runtime_ok else
                                                         "runtime-failure"),
            "residual": "none" if functional_ok else ("functional-divergence" if runtime_ok else
                                                      "runtime-failure"),
            "reason": None if functional_ok else
            ("the authenticated FTPS login did not complete" if not runtime_ok else
             "the FTPS session did not answer PWD" if not login_ok else
             "the FTPS login over TLS 1.2 did not complete" if not tls12_ok else
             "the unrelated CA was not rejected, so the server certificate does not verify"),
            "transcript": _transcript(("authority s_client -starttls ftp (USER/PASS/PWD/QUIT)",
                                       session),
                                      ("authority s_client -starttls ftp tls1_2", session12),
                                      ("authority s_client unrelated-ca (must fail)", neg),
                                      ("pure-ftpd", {"exit_code": 0, "stdout": _read(d / "ftpd.err")})),
            "workload": ("pure-ftpd: authenticated FTPS login + PWD over explicit TLS 1.3 and "
                         "TLS 1.2 + unrelated-CA reject"),
            "local_only": True}


# --------------------------------------------------------------------------------------------
# a deterministic local IMAP-over-TLS peer (24.17's isync fixture)
# --------------------------------------------------------------------------------------------

_IMAP_MESSAGE = (
    b"Message-ID: <phase24-runtime-1@127.0.0.1>\r\n"
    b"Date: Thu, 01 Jan 1970 00:00:00 +0000\r\n"
    b"From: runtime@127.0.0.1\r\n"
    b"To: isync@127.0.0.1\r\n"
    b"Subject: phase24 runtime isync fixture\r\n"
    b"\r\n"
    b"phase24 runtime isync fixture body\n"
)


def _imap_serve_one(tls, stop: threading.Event, log: list[str] | None = None) -> None:
    """Serve the one-mailbox IMAP4rev1 subset mbsync needs, over the already-TLS socket."""
    f = tls.makefile("rwb", buffering=0)
    f.write(b"* OK [CAPABILITY IMAP4rev1 AUTH=PLAIN UIDPLUS] phase24 isync fixture ready\r\n")
    while not stop.is_set():
        raw = f.readline()
        if not raw:
            break
        line = raw.decode("utf-8", "ignore").rstrip("\r\n")
        if log is not None:
            log.append(line)
        if not line:
            continue
        parts = line.split(" ", 2)
        if len(parts) < 2:
            continue
        tag = parts[0]
        cmd = parts[1].upper()
        rest = parts[2] if len(parts) > 2 else ""
        # IMAP literals: a command ending in {n} is answered with a continuation and the
        # client's next line is the literal (which may itself carry another {m}).
        while rest.endswith("}") and "{" in rest:
            f.write(b"+ \r\n")
            literal = f.readline().decode("utf-8", "ignore").rstrip("\r\n")
            if log is not None:
                log.append("<literal> " + literal)
            rest = rest[:rest.rfind("{")] + literal
        upper = rest.upper()
        if cmd in ("CAPABILITY",):
            f.write(b"* CAPABILITY IMAP4rev1 AUTH=PLAIN UIDPLUS\r\n")
            f.write(f"{tag} OK CAPABILITY completed\r\n".encode())
        elif cmd in ("LOGIN", "AUTHENTICATE"):
            if cmd == "AUTHENTICATE":
                f.write(b"+ \r\n")
                f.readline()
            f.write(f"{tag} OK LOGIN completed\r\n".encode())
        elif cmd == "NAMESPACE":
            f.write(b'* NAMESPACE (("" "/")) NIL NIL\r\n')
            f.write(f"{tag} OK NAMESPACE completed\r\n".encode())
        elif cmd in ("LIST", "LSUB"):
            f.write(b'* LIST (\\HasNoChildren) "/" "INBOX"\r\n')
            f.write(f"{tag} OK {cmd} completed\r\n".encode())
        elif cmd == "STATUS":
            f.write(b'* STATUS "INBOX" (MESSAGES 1 RECENT 0 UIDNEXT 2 UIDVALIDITY 1 UNSEEN 0)\r\n')
            f.write(f"{tag} OK STATUS completed\r\n".encode())
        elif cmd in ("SELECT", "EXAMINE"):
            f.write(b"* FLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft)\r\n")
            f.write(b"* 1 EXISTS\r\n")
            f.write(b"* 0 RECENT\r\n")
            f.write(b"* OK [UIDVALIDITY 1] UIDs valid\r\n")
            f.write(b"* OK [UIDNEXT 2] Predicted next UID\r\n")
            f.write(b"* OK [PERMANENTFLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft)] Flags\r\n")
            f.write(f"{tag} OK [READ-WRITE] {cmd} completed\r\n".encode())
        elif (cmd == "UID" and upper.startswith("FETCH")) or cmd == "FETCH":
            spec = rest[upper.index("FETCH") + 5:].strip()
            items = spec[spec.index("(") + 1:spec.rindex(")")] \
                if ("(" in spec and ")" in spec) else spec
            parts: list[str] = []
            literal: tuple[str, bytes] | None = None
            has_uid = False
            for tok in items.replace("(", " ").replace(")", " ").split():
                u = tok.upper()
                if u == "UID":
                    has_uid = True
                    parts.append("UID 1")
                elif u == "FLAGS":
                    parts.append("FLAGS ()")
                elif u == "RFC822.SIZE":
                    parts.append(f"RFC822.SIZE {len(_IMAP_MESSAGE)}")
                elif u == "INTERNALDATE":
                    parts.append('INTERNALDATE "01-Jan-1970 00:00:00 +0000"')
                elif u.startswith("BODY") or u.startswith("RFC822"):
                    name = tok.replace(".PEEK", "").replace(".peek", "")
                    literal = (name, _IMAP_MESSAGE)
                elif u == "ENVELOPE":
                    parts.append('ENVELOPE ("Thu, 01 Jan 1970 00:00:00 +0000" '
                                 '"phase24 runtime isync fixture" NIL NIL NIL NIL NIL NIL NIL)')
            # A `UID FETCH` response always carries the message UID, as a real server sends it.
            if cmd == "UID" and not has_uid:
                parts.insert(0, "UID 1")
            if literal is not None:
                n = len(literal[1])
                head = ("* 1 FETCH (" + " ".join(parts + [f"{literal[0]} {{{n}}}"]) +
                        "\r\n")
                f.write(head.encode())
                f.write(literal[1])
                f.write(b")\r\n")
            else:
                resp = "* 1 FETCH (" + " ".join(parts) + ")\r\n"
                f.write(resp.encode())
            f.write(f"{tag} OK {cmd} FETCH completed\r\n".encode())
        elif cmd == "UID" and upper.startswith("SEARCH"):
            f.write(b"* SEARCH 1\r\n")
            f.write(f"{tag} OK UID SEARCH completed\r\n".encode())
        elif cmd == "UID" and upper.startswith("STORE"):
            f.write(b"* 1 FETCH (UID 1 FLAGS (\\Seen))\r\n")
            f.write(f"{tag} OK UID STORE completed\r\n".encode())
        elif cmd in ("CREATE", "SUBSCRIBE", "UNSUBSCRIBE", "NOOP", "CHECK", "CLOSE",
                     "EXPUNGE", "STARTTLS", "ENABLE"):
            f.write(f"{tag} OK {cmd} completed\r\n".encode())
        elif cmd == "LOGOUT":
            f.write(b"* BYE phase24 fixture logging out\r\n")
            f.write(f"{tag} OK LOGOUT completed\r\n".encode())
            break
        else:
            f.write(f"{tag} OK {cmd} completed\r\n".encode())


def _imap_plain_readline(conn) -> bytes:
    """Read one CRLF-terminated line from the plaintext socket without over-reading into TLS."""
    buf = bytearray()
    while True:
        try:
            ch = conn.recv(1)
        except OSError:
            return bytes(buf)
        if not ch:
            return bytes(buf)
        buf += ch
        if ch == b"\n":
            return bytes(buf)


def _imap_serve_starttls(conn, sctx, stop: threading.Event) -> None:
    """Serve the plaintext greeting/CAPABILITY/STARTTLS exchange, then hand off to the TLS peer.

    A STARTTLS IMAP session is a different client path in mbsync from implicit IMAPS: the client
    reads the plaintext capability list, issues STARTTLS and upgrades the same connection. The
    plaintext reads are byte-at-a-time so no part of the following TLS ClientHello is consumed, and
    the same socket is wrapped in place so the handshake continues on that stream.
    """
    wrapped = False
    try:
        conn.sendall(b"* OK [CAPABILITY IMAP4rev1 AUTH=PLAIN UIDPLUS STARTTLS] phase24 isync "
                     b"fixture ready\r\n")
        while not stop.is_set():
            raw = _imap_plain_readline(conn)
            if not raw:
                break
            line = raw.decode("utf-8", "ignore").rstrip("\r\n")
            if not line:
                continue
            parts = line.split(" ", 2)
            if len(parts) < 2:
                continue
            tag, cmd = parts[0], parts[1].upper()
            if cmd == "CAPABILITY":
                conn.sendall(b"* CAPABILITY IMAP4rev1 AUTH=PLAIN UIDPLUS STARTTLS\r\n")
                conn.sendall(f"{tag} OK CAPABILITY completed\r\n".encode())
            elif cmd == "STARTTLS":
                conn.sendall(f"{tag} OK Begin TLS negotiation now\r\n".encode())
                tls = sctx.wrap_socket(conn, server_side=True)
                wrapped = True
                try:
                    _imap_serve_one(tls, stop)
                finally:
                    tls.close()
                break
            else:
                conn.sendall(f"{tag} BAD CAPABILITY or STARTTLS expected\r\n".encode())
    finally:
        if not wrapped:
            try:
                conn.close()
            except Exception:  # noqa: BLE001
                pass


def _imaps_server(cert_pem: Path, port: int, ready: threading.Event, stop: threading.Event,
                  starttls: bool = False, log: list[str] | None = None) -> None:
    """Accept IMAPS (or STARTTLS-upgraded IMAP) on loopback and serve the fixture until `stop`."""
    try:
        sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        sctx.load_cert_chain(str(cert_pem))
    except Exception:  # noqa: BLE001
        ready.set()
        return
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind(("127.0.0.1", port))
        srv.listen(8)
        srv.settimeout(1.0)
    except OSError:
        ready.set()
        srv.close()
        return
    ready.set()
    while not stop.is_set():
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        tls = None
        try:
            if starttls:
                _imap_serve_starttls(conn, sctx, stop)
            else:
                tls = sctx.wrap_socket(conn, server_side=True)
                _imap_serve_one(tls, stop, log)
        except Exception:  # noqa: BLE001
            pass
        finally:
            try:
                if tls is not None:
                    tls.close()
                elif starttls:
                    conn.close()
            except Exception:  # noqa: BLE001
                pass
    srv.close()


def _write_mbsync_conf(path: Path, port: int, cacert: Path, maildir: Path,
                       tlstype: str) -> None:
    """Write one mbsync channel over `port`, verifying against `cacert` and syncing `maildir`."""
    path.write_text(
        "IMAPAccount phase24\n"
        "Host 127.0.0.1\n"
        f"Port {port}\n"
        "User runtime\n"
        "Pass runtime\n"
        f"TLSType {tlstype}\n"
        f"CertificateFile {cacert}\n"
        "\n"
        "IMAPStore remote\n"
        "Account phase24\n"
        "\n"
        "MaildirStore local\n"
        f"Path {maildir}/\n"
        f"Inbox {maildir}/INBOX\n"
        "SubFolders Verbatim\n"
        "\n"
        "Channel phase24\n"
        "Far :remote:\n"
        "Near :local:\n"
        "Patterns *\n"
        "Create Both\n"
        "Expunge Both\n"
        "SyncState *\n", encoding="utf-8")


def _wl_isync(ctx: dict) -> dict:
    """A real IMAP-over-TLS sync: the subject mbsync pulls a message from a local IMAP peer.

    24.17 adds the missing deterministic local workload: a one-mailbox IMAP4rev1 peer served by the
    courtroom's own Python over TLS with the authority-generated certificate, on loopback only. The
    subject `mbsync` connects with IMAPS, authenticates, fetches the message and writes it to a local
    Maildir, so the family reaches the functional level the authority can.

    The second harness drives the STARTTLS upgrade path (a different client code path from implicit
    IMAPS) into a second Maildir, and a config trusting only the unrelated CA must abort the fetch
    with a non-zero exit and no delivered message. A certificate-verification or upgrade-path
    defect is therefore visible independently of the single successful IMAPS fetch.
    """
    ap, port, d, root = ctx["authority_prefix"], ctx["port"], ctx["workdir"], ctx["root"]
    pki = _gen_pki(ap, d)
    maildir = d / "maildir"
    for sub in ("cur", "new", "tmp"):
        (maildir / sub).mkdir(parents=True, exist_ok=True)
    conf = d / "mbsyncrc"
    conf.write_text(
        "IMAPAccount phase24\n"
        "Host 127.0.0.1\n"
        f"Port {port}\n"
        "User runtime\n"
        "Pass runtime\n"
        "TLSType IMAPS\n"
        f"CertificateFile {pki['ca_crt']}\n"
        "\n"
        "IMAPStore remote\n"
        "Account phase24\n"
        "\n"
        "MaildirStore local\n"
        f"Path {maildir}/\n"
        f"Inbox {maildir}/INBOX\n"
        "SubFolders Verbatim\n"
        "\n"
        "Channel phase24\n"
        "Far :remote:\n"
        "Near :local:\n"
        "Patterns *\n"
        "Create Both\n"
        "Expunge Both\n"
        "SyncState *\n", encoding="utf-8")
    stport = _free_port()
    negdir, stmdir = d / "maildir-neg", d / "maildir-starttls"
    for target in (negdir, stmdir):
        for sub in ("cur", "new", "tmp"):
            (target / sub).mkdir(parents=True, exist_ok=True)
    negconf, stconf = d / "mbsyncrc-neg", d / "mbsyncrc-starttls"
    _write_mbsync_conf(negconf, port, pki["other_crt"], negdir, "IMAPS")
    _write_mbsync_conf(stconf, stport, pki["ca_crt"], stmdir, "STARTTLS")
    ready, stop = threading.Event(), threading.Event()
    thr = threading.Thread(target=_imaps_server, args=(pki["srv_pem"], port, ready, stop),
                           daemon=True)
    thr.start()
    ready.wait(timeout=10)
    ready2, stop2 = threading.Event(), threading.Event()
    thr2 = threading.Thread(target=_imaps_server,
                            args=(pki["srv_pem"], stport, ready2, stop2, True), daemon=True)
    thr2.start()
    ready2.wait(timeout=10)
    try:
        if (not _wait_tcp("127.0.0.1", port, timeout=10)
                or not _wait_tcp("127.0.0.1", stport, timeout=10)):
            return _wl_fail([], "the local IMAP peer did not listen", "runtime-failure", d)
        sync = _run_captured([str(ctx["program"]), "-c", str(conf), "phase24"], cwd=d,
                             env=ctx["env"], timeout=60)
        negsync = _run_captured([str(ctx["program"]), "-c", str(negconf), "phase24"], cwd=d,
                                env=ctx["env"], timeout=60)
        stsync = _run_captured([str(ctx["program"]), "-c", str(stconf), "phase24"], cwd=d,
                               env=ctx["env"], timeout=60)
    finally:
        stop.set()
        stop2.set()
        thr.join(timeout=5)
        thr2.join(timeout=5)
        _kill_comm("mbsync")
    msgs = [p for p in maildir.rglob("*") if p.is_file() and p.parent.name in ("new", "cur")]
    negmsgs = [p for p in negdir.rglob("*") if p.is_file() and p.parent.name in ("new", "cur")]
    stmsgs = [p for p in stmdir.rglob("*") if p.is_file() and p.parent.name in ("new", "cur")]
    sync_ok = sync["exit_code"] == 0 and bool(msgs)
    neg_rejected = negsync["exit_code"] != 0 and not negmsgs
    starttls_ok = stsync["exit_code"] == 0 and bool(stmsgs)
    functional_ok = sync_ok and neg_rejected and starttls_ok
    runtime_ok = sync["exit_code"] == 0 or bool(msgs)
    return {"runtime_ok": runtime_ok, "functional_ok": functional_ok,
            "failure_class": None if functional_ok else ("functional-failure" if runtime_ok else
                                                         "runtime-failure"),
            "residual": "none" if functional_ok else ("functional-divergence" if runtime_ok else
                                                      "runtime-failure"),
            "reason": None if functional_ok else
            ("the local IMAP-over-TLS sync did not complete" if not runtime_ok else
             "the IMAPS sync did not deliver the fixture message" if not sync_ok else
             "the unrelated CA did not abort the IMAPS fetch" if not neg_rejected else
             "the STARTTLS sync did not deliver the fixture message"),
            "transcript": _transcript(("mbsync -c mbsyncrc phase24", sync),
                                      ("mbsync unrelated-ca (must abort)", negsync),
                                      ("mbsync -c mbsyncrc-starttls phase24", stsync)),
            "workload": ("isync: mbsync IMAPS fetch + STARTTLS fetch from a local IMAP peer + "
                         "unrelated-CA abort"),
            "local_only": True}


def _wl_socat(ctx: dict) -> dict:
    """A TLS socat: a verified TLS 1.3 session carries a round trip to an EXEC peer.

    `OPENSSL-LISTEN` is socat's own libssl server path; the authority's `s_client` verifies the
    certificate and sends a line that a one-shot shell peer answers. A client trusting only the
    unrelated CA must be rejected, so an unverifiable server certificate is a recorded failure.
    """
    ap, port, d = ctx["authority_prefix"], ctx["port"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    echo = d / "echo.sh"
    echo.write_text("#!/bin/sh\nread line\nprintf 'socat-echo:%s\\n' \"$line\"\n",
                    encoding="utf-8")
    os.chmod(echo, 0o755)
    argv = [str(ctx["program"]),
            (f"OPENSSL-LISTEN:{port},reuseaddr,fork,cert={pki['srv_crt']},"
             f"key={pki['srv_key']},verify=0"),
            f"EXEC:{echo}"]
    srv, of, ef = _spawn(argv, d, ctx["env"], d / "socat.out", d / "socat.err")
    try:
        if not _wait_tcp("127.0.0.1", port):
            return _wl_fail([], "socat did not open its TLS port", "runtime-failure", d)
        echo_res = _s_client(ap, port, pki["ca_crt"], ["-tls1_3", "-quiet"],
                             stdin_text="phase24-socat\n", timeout=25)
        neg = _s_client(ap, port, pki["other_crt"],
                        ["-tls1_3", "-brief", "-verify_return_error"], stdin_text="", timeout=25)
    finally:
        _stop(srv)
        of.close()
        ef.close()
    runtime_ok = "socat-echo:phase24-socat" in echo_res["stdout"]
    neg_rejected = (neg["exit_code"] != 0
                    and "certificate verify failed" in (neg["stderr"] + neg["stdout"]))
    functional_ok = runtime_ok and neg_rejected
    return {"runtime_ok": runtime_ok, "functional_ok": functional_ok,
            "failure_class": None if functional_ok else ("functional-failure" if runtime_ok else
                                                         "runtime-failure"),
            "residual": "none" if functional_ok else ("functional-divergence" if runtime_ok else
                                                      "runtime-failure"),
            "reason": None if functional_ok else
            ("the TLS session did not carry the peer's echo" if not runtime_ok else
             "the unrelated CA was not rejected, so the server certificate does not verify"),
            "transcript": _transcript(("authority s_client echo", echo_res),
                                      ("authority s_client unrelated-ca (must fail)", neg),
                                      ("socat", {"exit_code": 0,
                                                 "stdout": _read(d / "socat.err")})),
            "workload": ("socat: verified TLS1.3 session + encrypted echo round trip + "
                         "unrelated-CA reject"),
            "local_only": True}


def _wl_rsync(ctx: dict) -> dict:
    """A local rsync: a verified copy plus the checksum path (`-c`) that consumes OpenSSL MD5.

    `rsync -ac` compares file digests instead of sizes/mtimes. A same-content file whose mtime
    alone moved must not be transferred, while changed content must be. The pair distinguishes a
    working digest path from a copy that silently ignores it.
    """
    d, rs = ctx["workdir"], ctx["program"]
    src, dst = d / "src", d / "dst"
    src.mkdir(parents=True, exist_ok=True)
    dst.mkdir(parents=True, exist_ok=True)
    probe = src / "probe.txt"
    probe.write_text("phase24-rsync-payload\n", encoding="utf-8")
    copy = _run_captured([str(rs), "-a", f"{src}/", f"{dst}/"], env=ctx["env"], timeout=30)
    copied = (dst / "probe.txt").is_file() and (
        (dst / "probe.txt").read_text(encoding="utf-8") == probe.read_text(encoding="utf-8"))
    # Move only the mtime: a checksum comparison must see identical content and skip the file.
    stamp = time.time() + 300
    os.utime(probe, (stamp, stamp))
    skip = _run_captured([str(rs), "-ac", "--itemize-changes", f"{src}/", f"{dst}/"],
                         env=ctx["env"], timeout=30)
    skip_ok = skip["ok"] and not any(line.startswith(">f")
                                     for line in skip["stdout"].splitlines())
    # Change the content: the same checksum path must now transfer the file.
    probe.write_text("phase24-rsync-payload-changed\n", encoding="utf-8")
    changed = _run_captured([str(rs), "-ac", "--itemize-changes", f"{src}/", f"{dst}/"],
                            env=ctx["env"], timeout=30)
    change_ok = (changed["ok"]
                 and any(line.startswith(">f") for line in changed["stdout"].splitlines())
                 and (dst / "probe.txt").read_text(encoding="utf-8")
                 == probe.read_text(encoding="utf-8"))
    runtime_ok = copy["ok"] and copied
    functional_ok = runtime_ok and skip_ok and change_ok
    return {"runtime_ok": runtime_ok, "functional_ok": functional_ok,
            "failure_class": None if functional_ok else ("functional-failure" if runtime_ok else
                                                         "runtime-failure"),
            "residual": "none" if functional_ok else ("functional-divergence" if runtime_ok else
                                                      "runtime-failure"),
            "reason": None if functional_ok else
            ("the local copy did not complete" if not runtime_ok else
             "the checksum path transferred an unchanged file" if not skip_ok else
             "the checksum path did not transfer changed content"),
            "transcript": _transcript(("rsync -a copy", copy), ("rsync -ac unchanged", skip),
                                      ("rsync -ac changed", changed)),
            "workload": "rsync: local copy + OpenSSL-MD5 checksum skip/transfer",
            "local_only": True}


def _wl_fossil(ctx: dict) -> dict:
    """A TLS fossil server: a verified TLS 1.3 handshake and a real HTTP 200 from the SCM UI."""
    ap, port, d = ctx["authority_prefix"], ctx["port"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    env = dict(ctx["env"], USER="fossil", LOGNAME="fossil", HOME=str(d))
    repo = d / "repo.fossil"
    init = _run_captured([str(ctx["program"]), "init", "-A", "fossil", str(repo)], cwd=d,
                         env=env, timeout=30)
    if not init["ok"] or not repo.is_file():
        return _wl_fail([("fossil init", {"exit_code": init["exit_code"],
                                        "stdout": "repository created" if repo.is_file() else ""})],
                        f"fossil could not create its repository: {census._error_line(init)}",
                        "runtime-failure", d)
    srv, of, ef = _spawn([str(ctx["program"]), "server", "--localhost", "--nojail", "--port",
                          str(port), "--cert", str(pki["srv_crt"]), "--pkey",
                          str(pki["srv_key"]), str(repo)], d, env, d / "fossil.out",
                         d / "fossil.err")
    try:
        if not _wait_tcp("127.0.0.1", port):
            return _wl_fail([("fossil init", {"exit_code": init["exit_code"],
                                            "stdout": "repository created" if repo.is_file()
                                            else ""})],
                            "fossil did not open its TLS port", "runtime-failure", d)
        hs = _s_client(ap, port, pki["ca_crt"], ["-tls1_3", "-brief"], stdin_text="",
                       timeout=25)
        get = _s_client(ap, port, pki["ca_crt"], ["-tls1_3", "-quiet"],
                        stdin_text="GET /home HTTP/1.0\r\nHost: 127.0.0.1\r\n"
                                   "Connection: close\r\n\r\n", timeout=25)
        neg = _s_client(ap, port, pki["other_crt"],
                        ["-tls1_3", "-brief", "-verify_return_error"], stdin_text="", timeout=25)
    finally:
        _stop(srv)
        _kill_comm("fossil")
        of.close()
        ef.close()
    runtime_ok = ("Verification: OK" in hs["stderr"]
                  and "Protocol version: TLSv1.3" in hs["stderr"])
    page_ok = "HTTP/1.0 200 OK" in get["stdout"] and "Fossil" in get["stdout"]
    neg_rejected = (neg["exit_code"] != 0
                    and "certificate verify failed" in (neg["stderr"] + neg["stdout"]))
    functional_ok = runtime_ok and page_ok and neg_rejected
    # The SCM page carries server timestamps and generated identifiers; only the status and the
    # functional marker are evidence, so the transcript keeps exactly those.
    get_note = {"exit_code": get["exit_code"],
                "stdout": "\n".join(line for line in get["stdout"].splitlines()
                                     if line.startswith("HTTP/") or "Fossil" in line)[:400]}
    return {"runtime_ok": runtime_ok, "functional_ok": functional_ok,
            "failure_class": None if functional_ok else ("functional-failure" if runtime_ok else
                                                         "runtime-failure"),
            "residual": "none" if functional_ok else ("functional-divergence" if runtime_ok else
                                                      "runtime-failure"),
            "reason": None if functional_ok else
            ("the TLS 1.3 handshake did not verify" if not runtime_ok else
             "the SCM UI did not answer an HTTP request" if not page_ok else
             "the unrelated CA was not rejected, so the server certificate does not verify"),
            "transcript": _transcript(("fossil init", {"exit_code": init["exit_code"],
                                                       "stdout": "repository created"
                                                       if repo.is_file() else ""}),
                                      ("authority s_client -brief", hs),
                                      ("authority s_client GET /home", get_note),
                                      ("authority s_client unrelated-ca (must fail)", neg)),
            "workload": "fossil: verified TLS1.3 server + HTTP 200 + unrelated-CA reject",
            "local_only": True}


def _wl_squid(ctx: dict) -> dict:
    """A TLS squid: the authority client fetches through squid's `https_port` proxy.

    The proxy terminates TLS with its own libssl, forwards a plain HTTP request to a local origin,
    and returns the origin's body. A client trusting only the unrelated CA must be rejected.
    """
    ap, port, d = ctx["authority_prefix"], ctx["port"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    for stale in Path("/dev/shm").glob("squid-*"):
        try:
            stale.unlink()
        except OSError:
            pass
    docroot = d / "docroot"
    docroot.mkdir(parents=True, exist_ok=True)
    (docroot / "index.html").write_text("phase24-squid-ok\n", encoding="utf-8")
    origin_port = _free_port()
    origin, oof, oef = _spawn([sys.executable, "-m", "http.server", str(origin_port), "--bind",
                              "127.0.0.1"], docroot, ctx["env"], d / "origin.out",
                             d / "origin.err")
    srv = of = ef = None
    try:
        if not _wait_tcp("127.0.0.1", origin_port):
            return _wl_fail([], "the local HTTP origin did not listen", "runtime-failure", d)
        icons = d / "icons"
        icons.mkdir(parents=True, exist_ok=True)
        mime = d / "mime.conf"
        mime.write_text("text/plain txt\n", encoding="utf-8")
        for writable in (d, docroot, icons):
            os.chmod(writable, 0o777)
        for readable in (pki["srv_crt"], pki["srv_key"], mime):
            os.chmod(readable, 0o644)
        conf = d / "squid.conf"
        conf.write_text(
            f"http_port 127.0.0.1:{_free_port()}\n"
            f"https_port 127.0.0.1:{port} tls-cert={pki['srv_crt']} "
            f"tls-key={pki['srv_key']}\n"
            "acl all src all\n"
            "http_access allow all\n"
            "cache deny all\n"
            "cache_replacement_policy heap\n"
            "memory_replacement_policy heap\n"
            "unlinkd_program /bin/true\n"
            "cache_effective_user nobody\n"
            "cache_effective_group nogroup\n"
            f"pid_filename {d}/squid.pid\n"
            f"coredump_dir {d}\n"
            f"access_log stdio:{d}/access.log\n"
            f"cache_log {d}/cache.log\n"
            "cache_store_log none\n"
            f"mime_table {mime}\n"
            f"icon_directory {icons}\n"
            "visible_hostname phase24\n", encoding="utf-8")
        srv, of, ef = _spawn([str(ctx["program"]), "-N", "-f", str(conf)], d, ctx["env"],
                             d / "squid.out", d / "squid.err")
        if not _wait_tcp("127.0.0.1", port, timeout=25):
            return _wl_fail([], "squid did not open its TLS proxy port", "runtime-failure", d)
        get = _s_client(ap, port, pki["ca_crt"], ["-tls1_3", "-quiet"],
                        stdin_text=(f"GET http://127.0.0.1:{origin_port}/index.html HTTP/1.0\r\n"
                                    "Host: 127.0.0.1\r\nConnection: close\r\n\r\n"),
                        timeout=25)
        neg = _s_client(ap, port, pki["other_crt"],
                        ["-tls1_3", "-brief", "-verify_return_error"], stdin_text="", timeout=25)
    finally:
        if srv is not None:
            _stop(srv)
        _kill_comm("squid")
        _stop(origin)
        for handle in (of, ef, oof, oef):
            if handle is not None:
                handle.close()
    runtime_ok = "HTTP/1.1 200 OK" in get["stdout"] and "phase24-squid-ok" in get["stdout"]
    neg_rejected = (neg["exit_code"] != 0
                    and "certificate verify failed" in (neg["stderr"] + neg["stdout"]))
    functional_ok = runtime_ok and neg_rejected
    # Keep the status line and the origin's marker; the origin's Date/Last-Modified are not evidence.
    get_note = {"exit_code": get["exit_code"],
                "stdout": "\n".join(line for line in get["stdout"].splitlines()
                                     if line.startswith("HTTP/") or "phase24-squid-ok" in line)}
    return {"runtime_ok": runtime_ok, "functional_ok": functional_ok,
            "failure_class": None if functional_ok else ("functional-failure" if runtime_ok else
                                                         "runtime-failure"),
            "residual": "none" if functional_ok else ("functional-divergence" if runtime_ok else
                                                      "runtime-failure"),
            "reason": None if functional_ok else
            ("the proxied fetch did not return the origin's payload" if not runtime_ok else
             "the unrelated CA was not rejected, so the server certificate does not verify"),
            "transcript": _transcript(("authority s_client GET via https_port", get_note),
                                      ("authority s_client unrelated-ca (must fail)", neg)),
            "workload": "squid: verified TLS1.3 https_port proxy fetch + unrelated-CA reject",
            "local_only": True}


def _wl_ldns(ctx: dict) -> dict:
    """A DNSSEC workload: ldns generates a key, signs a zone, and verifies the signature.

    `ldns-keygen` and `ldns-signzone` consume the subject's libcrypto for RSA/SHA-256,
    `ldns-verify-zone` validates the RRSIGs, and a one-record tamper must be reported as a bogus
    signature. The random key tag is evidence only of key generation, so it is not transcribed.
    """
    d, root = ctx["workdir"], ctx["root"]
    keygen = root / "examples" / ".libs" / "ldns-keygen"
    verify = root / "examples" / ".libs" / "ldns-verify-zone"
    if not keygen.is_file() or not verify.is_file():
        return _wl_fail([], "the ldns tools were not built by the examples target",
                        "runtime-failure", d)
    zone = d / "example.com.zone"
    zone.write_text(
        "example.com. 3600 IN SOA ns.example.com. hostmaster.example.com. 1 3600 600 86400 3600\n"
        "example.com. 3600 IN NS ns.example.com.\n"
        "ns.example.com. 3600 IN A 127.0.0.1\n"
        "www.example.com. 3600 IN A 127.0.0.1\n", encoding="utf-8")
    gen = _run_captured([str(keygen), "-a", "RSASHA256", "-b", "2048", "example.com"], cwd=d,
                        env=ctx["env"], timeout=60)
    names = [line.strip() for line in gen["stdout"].splitlines() if line.strip().startswith("K")]
    base = names[-1] if names else ""
    signed = d / "signed.zone"
    sign = _run_captured([str(ctx["program"]), "-n", "-f", str(signed), str(zone), base], cwd=d,
                         env=ctx["env"], timeout=60) if base else None
    checked = _run_captured([str(verify), str(signed)], cwd=d, env=ctx["env"], timeout=60) \
        if signed.is_file() else None
    tampered = d / "tampered.zone"
    tamper_rejected = False
    tamper = None
    if signed.is_file():
        tampered.write_text(
            re.sub(r"(www\.example\.com\.\s+3600\s+IN\s+A\s+)127\.0\.0\.1", r"\g<1>127.0.0.2",
                   signed.read_text(encoding="utf-8"), count=1), encoding="utf-8")
        tamper = _run_captured([str(verify), str(tampered)], cwd=d, env=ctx["env"], timeout=60)
        tamper_rejected = (tamper["exit_code"] != 0
                           and "Bogus DNSSEC signature" in (tamper["stdout"] + tamper["stderr"]))
    runtime_ok = bool(gen["ok"] and base and sign and sign["ok"] and checked and checked["ok"])
    functional_ok = (runtime_ok and "verified" in (checked["stdout"] + checked["stderr"])
                     and tamper_rejected)
    return {"runtime_ok": runtime_ok, "functional_ok": functional_ok,
            "failure_class": None if functional_ok else ("functional-failure" if runtime_ok else
                                                         "runtime-failure"),
            "residual": "none" if functional_ok else ("functional-divergence" if runtime_ok else
                                                      "runtime-failure"),
            "reason": None if functional_ok else
            ("the zone could not be keyed and signed" if not runtime_ok else
             "the signed zone did not verify" if "verified" not in
             (checked["stdout"] + checked["stderr"]) else
             "a tampered record was not reported as a bogus signature"),
            "transcript": _transcript(
                ("ldns-keygen", {"exit_code": gen["exit_code"],
                                 "stdout": "key generated" if base else "no key"}),
                ("ldns-signzone", sign), ("ldns-verify-zone", checked),
                ("ldns-verify-zone tampered (must fail)", tamper)),
            "workload": ("ldns: DNSSEC RSASHA256 keygen + zone signing + verify + tamper reject"),
            "local_only": True}


def _wl_stunnel(ctx: dict) -> dict:
    """A TLS stunnel: a verified TLS 1.3 accept-forward round trip to a local plain peer.

    stunnel's `accept`/`connect` service is its own libssl server path: the authority's `s_client`
    verifies the certificate and sends a line that a one-shot loopback peer answers, so a broken
    accept path, record layer or forwarding path is distinguishable from a broken handshake. A
    client trusting only the unrelated CA must be rejected.
    """
    ap, port, d = ctx["authority_prefix"], ctx["port"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    back = _free_port()
    peer = socket.socket()
    peer.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    peer.bind(("127.0.0.1", back))
    peer.listen(5)
    done = threading.Event()

    def echo() -> None:
        while not done.is_set():
            try:
                conn, _ = peer.accept()
            except OSError:
                return
            with conn:
                data = conn.recv(4096)
                conn.sendall(b"stunnel-echo:" + data.strip() + b"\n")

    thread = threading.Thread(target=echo, daemon=True)
    thread.start()
    conf = d / "stunnel.conf"
    conf.write_text(
        "foreground = yes\n"
        f"pid = {d}/stunnel.pid\n"
        "debug = 4\n"
        "[probe]\n"
        f"accept = 127.0.0.1:{port}\n"
        f"connect = 127.0.0.1:{back}\n"
        f"cert = {pki['srv_crt']}\n"
        f"key = {pki['srv_key']}\n"
        "sslVersionMin = TLSv1.3\n", encoding="utf-8")
    srv, of, ef = _spawn([str(ctx["program"]), str(conf)], d, ctx["env"], d / "stunnel.out",
                         d / "stunnel.err")
    try:
        if not _wait_tcp("127.0.0.1", port):
            return _wl_fail([("stunnel", {"exit_code": 0, "stdout": _read(d / "stunnel.err")})],
                            "stunnel did not open its accept port", "runtime-failure", d)
        echo_res = _s_client(ap, port, pki["ca_crt"], ["-tls1_3", "-quiet"],
                             stdin_text="phase24-stunnel\n", timeout=25)
        neg = _s_client(ap, port, pki["other_crt"],
                        ["-tls1_3", "-brief", "-verify_return_error"], stdin_text="", timeout=25)
    finally:
        _stop(srv)
        done.set()
        peer.close()
        thread.join(timeout=2)
        of.close()
        ef.close()
    runtime_ok = "stunnel-echo:phase24-stunnel" in echo_res["stdout"]
    neg_rejected = (neg["exit_code"] != 0
                    and "certificate verify failed" in (neg["stderr"] + neg["stdout"]))
    functional_ok = runtime_ok and neg_rejected
    return {"runtime_ok": runtime_ok, "functional_ok": functional_ok,
            "failure_class": None if functional_ok else ("functional-failure" if runtime_ok else
                                                         "runtime-failure"),
            "residual": "none" if functional_ok else ("functional-divergence" if runtime_ok else
                                                      "runtime-failure"),
            "reason": None if functional_ok else
            ("the TLS session did not carry the peer's echo" if not runtime_ok else
             "the unrelated CA was not rejected, so the server certificate does not verify"),
            "transcript": _transcript(("authority s_client echo", echo_res),
                                      ("authority s_client unrelated-ca (must fail)", neg),
                                      ("stunnel", {"exit_code": 0, "stdout": _read(
                                          d / "stunnel.err")})),
            "workload": ("stunnel: verified TLS1.3 accept-forward round trip + unrelated-CA reject"),
            "local_only": True}


def _wl_sslscan(ctx: dict) -> dict:
    """A TLS scan of a local candidate server: the reported protocol and cipher are the evidence.

    sslscan's own libssl client probes the authority's `s_server` on loopback and must report the
    negotiated TLS 1.3 protocol and an accepted TLS 1.3 cipher. The negative control is a server
    with TLS 1.3 disabled: `--tls13` must then report `TLSv1.3 disabled` rather than a fabricated
    result. sslscan performs no certificate-chain verification of its own (its verify mode is NONE,
    so every private chain reports a missing issuer), so an unrelated-CA rejection is not a
    discriminating negative control for this program and is deliberately not claimed.
    """
    ap, port, d = ctx["authority_prefix"], ctx["port"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    neg_port = _free_port()
    srv, of, ef = _spawn([str(_auth_ossl(ap)), "s_server", "-accept", str(port), "-cert",
                          str(pki["srv_crt"]), "-key", str(pki["srv_key"]), "-tls1_3", "-www"],
                         d, _auth_env(ap), d / "srv.out", d / "srv.err")
    neg, nof, nef = _spawn([str(_auth_ossl(ap)), "s_server", "-accept", str(neg_port), "-cert",
                            str(pki["srv_crt"]), "-key", str(pki["srv_key"]), "-tls1_2", "-www"],
                           d, _auth_env(ap), d / "neg.out", d / "neg.err")
    try:
        if not (_wait_tcp("127.0.0.1", port) and _wait_tcp("127.0.0.1", neg_port)):
            return _wl_fail([], "a local authority TLS server did not listen", "runtime-failure", d)
        scan = _run_captured([str(ctx["program"]), "--tls13", "--no-colour",
                              f"127.0.0.1:{port}"], env=ctx["env"], timeout=90)
        neg_scan = _run_captured([str(ctx["program"]), "--tls13", "--no-colour",
                                  f"127.0.0.1:{neg_port}"], env=ctx["env"], timeout=90)
    finally:
        _stop(srv)
        _stop(neg)
        of.close()
        ef.close()
        nof.close()
        nef.close()
    runtime_ok = ("TLSv1.3   enabled" in scan["stdout"]
                  and "TLS_AES_256_GCM_SHA384" in scan["stdout"])
    neg_ok = ("TLSv1.3   disabled" in neg_scan["stdout"]
              and "TLSv1.3   enabled" not in neg_scan["stdout"])
    functional_ok = runtime_ok and neg_ok
    return {"runtime_ok": runtime_ok, "functional_ok": functional_ok,
            "failure_class": None if functional_ok else ("functional-failure" if runtime_ok else
                                                         "runtime-failure"),
            "residual": "none" if functional_ok else ("functional-divergence" if runtime_ok else
                                                      "runtime-failure"),
            "reason": None if functional_ok else
            ("sslscan did not report the local server's TLS1.3 protocol and cipher"
             if not runtime_ok else
             "sslscan did not report TLSv1.3 as disabled on a TLS1.2-only server"),
            "transcript": _transcript(("sslscan --tls13", scan),
                                      ("sslscan --tls13 tls1.2-only (must be disabled)", neg_scan)),
            "workload": ("sslscan: TLS1.3 protocol/cipher scan of a local server + TLS1.2-only "
                         "negative control"),
            "local_only": True}


def _wl_openvpn(ctx: dict) -> dict:
    """A local OpenVPN TLS session: peer certificate verification and a completed handshake.

    Two subject-linked daemons run point-to-point over TCP with `--dev null` (no kernel device is
    created or configured): the client verifies the server certificate against the CA, the control
    channel negotiates TLS 1.3, and both sides reach `Initialization Sequence Completed`. A client
    trusting only the unrelated CA must fail verification, so an unverifiable peer certificate is a
    recorded failure rather than a silent pass.
    """
    ap, port, d = ctx["authority_prefix"], ctx["port"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    prog = str(ctx["program"])
    common = ["--dev", "null", "--dev-type", "null", "--ifconfig-noexec", "--route-noexec",
              "--dh", "none", "--verb", "4", "--cipher", "AES-256-GCM",
              "--data-ciphers", "AES-256-GCM:AES-128-GCM", "--data-ciphers-fallback",
              "AES-256-GCM"]
    srv_log, cli_log, neg_log = d / "srv.log", d / "cli.log", d / "neg.log"
    srv, of, ef = _spawn([prog, "--tls-server", "--ifconfig", "10.8.0.1", "10.8.0.2", "--proto",
                          "tcp-server", "--local", "127.0.0.1", "--port", str(port), "--ca",
                          str(pki["ca_crt"]), "--cert", str(pki["srv_crt"]), "--key",
                          str(pki["srv_key"])] + common, d, ctx["env"], srv_log,
                         d / "srv.err")
    cli = neg = None
    cf = nf = cfe = nfe = None
    try:
        if not _wait_tcp("127.0.0.1", port):
            return _wl_fail([("openvpn server", {"exit_code": 0, "stdout": _read(srv_log)})],
                            "the openvpn server did not open its TCP port", "runtime-failure", d)
        cli, cf, cfe = _spawn([prog, "--tls-client", "--ifconfig", "10.8.0.2", "10.8.0.1",
                               "--proto", "tcp-client", "--remote", "127.0.0.1", str(port),
                               "--nobind", "--ca", str(pki["ca_crt"]), "--cert",
                               str(pki["client_crt"]), "--key", str(pki["client_key"]),
                               "--remote-cert-tls", "server"] + common, d, ctx["env"], cli_log,
                              d / "cli.err")
        connected = _wait_log(cli_log, "Initialization Sequence Completed", timeout=25)
        _stop(cli)
        time.sleep(1.0)
        neg, nf, nfe = _spawn([prog, "--tls-client", "--ifconfig", "10.8.0.2", "10.8.0.1",
                               "--proto", "tcp-client", "--remote", "127.0.0.1", str(port),
                               "--nobind", "--ca", str(pki["other_crt"]), "--cert",
                               str(pki["client_crt"]), "--key", str(pki["client_key"]),
                               "--remote-cert-tls", "server"] + common, d, ctx["env"], neg_log,
                              d / "neg.err")
        _wait_log(neg_log, "VERIFY ERROR", timeout=15)
    finally:
        for proc in (cli, neg, srv):
            if proc is not None:
                _stop(proc)
        for handle in (of, ef, cf, cfe, nf, nfe):
            if handle is not None:
                handle.close()
    cli_text, neg_text = _read(cli_log), _read(neg_log)
    runtime_ok = ("Control Channel: TLSv1.3, cipher TLSv1.3 TLS_AES_256_GCM_SHA384" in cli_text
                  and "Initialization Sequence Completed" in cli_text)
    neg_rejected = ("VERIFY ERROR" in neg_text
                    and "Initialization Sequence Completed" not in neg_text)
    functional_ok = runtime_ok and neg_rejected
    return {"runtime_ok": runtime_ok, "functional_ok": functional_ok,
            "failure_class": None if functional_ok else ("functional-failure" if runtime_ok else
                                                         "runtime-failure"),
            "residual": "none" if functional_ok else ("functional-divergence" if runtime_ok else
                                                      "runtime-failure"),
            "reason": None if functional_ok else
            ("the local TLS control channel did not verify and initialise" if not runtime_ok else
             "the unrelated CA was not rejected, so the peer certificate does not verify"),
            "transcript": _transcript(("openvpn client", {"exit_code": 0, "stdout": cli_text}),
                                      ("openvpn client unrelated-ca (must fail)",
                                       {"exit_code": 0, "stdout": neg_text}),
                                      ("openvpn server", {"exit_code": 0, "stdout": _read(
                                          srv_log)})),
            "workload": ("openvpn: mutual certificate verify + TLS1.3 control channel + "
                         "Initialization Sequence + unrelated-CA reject"),
            "local_only": True}


def _wl_tinc(ctx: dict) -> dict:
    """A two-node tinc meta connection: RSA key generation, key exchange and a data packet.

    Both subject-linked `tincd` daemons use `DeviceType = dummy` (no kernel device), generate their
    RSA keys through the subject's libcrypto, authenticate the meta connection with those keys and
    complete the symmetric key exchange; the peer then sends a data packet over the established
    connection. A tinc without a reachable peer must not report an exchange, so the negative control
    runs the same node with its peer absent.
    """
    d = ctx["workdir"]
    prog = str(ctx["program"])
    ports = {"n1": ctx["port"], "n2": _free_port()}
    subnets = {"n1": 1, "n2": 2}
    conf: dict[str, Path] = {}
    keys: dict[str, str] = {}
    for node in ("n1", "n2"):
        conf[node] = d / node
        (conf[node] / "hosts").mkdir(parents=True, exist_ok=True)
        text = (f"Name = {node}\nDeviceType = dummy\nAddressFamily = ipv4\n"
                f"ListenAddress = 127.0.0.1\nPort = {ports[node]}\n")
        if node == "n1":
            text += "ConnectTo = n2\n"
        (conf[node] / "tinc.conf").write_text(text, encoding="utf-8")
        keygen = _run_captured([prog, "-c", str(conf[node]), "-K", "2048"], env=ctx["env"],
                               timeout=60)
        if not keygen["ok"]:
            return _wl_fail([("tincd -K", keygen)],
                            f"tincd could not generate an RSA key: {census._error_line(keygen)}",
                            "runtime-failure", d)
        keys[node] = _read(conf[node] / "hosts" / node)
    if not all(keys.values()):
        return _wl_fail([], "tincd generated no public key", "runtime-failure", d)

    def address(node: str) -> str:
        return (f"Address = 127.0.0.1\nPort = {ports[node]}\n"
                f"Subnet = 10.9.0.{subnets[node]}/32\n")

    for node in ("n1", "n2"):
        for peer in ("n1", "n2"):
            (conf[node] / "hosts" / peer).write_text(keys[peer] + address(peer), encoding="utf-8")
    logs = {node: d / f"{node}.log" for node in ("n1", "n2")}
    procs: dict[str, subprocess.Popen] = {}
    handles: dict[str, list] = {}

    def start(node: str, log: Path) -> None:
        out = open(log, "w", encoding="utf-8")
        procs[node] = subprocess.Popen(
            [prog, "-c", str(conf[node]), "-D", "-d", "3", "--pidfile", str(d / f"{node}.pid")],
            cwd=str(d), env=ctx["env"], stdout=out, stderr=subprocess.STDOUT, text=True)
        handles[node] = [out]

    try:
        start("n2", logs["n2"])
        time.sleep(1.0)
        start("n1", logs["n1"])
        exchanged = _wait_log(logs["n1"], "Got ANS_KEY from n2", timeout=25)
        _wait_log(logs["n1"], "Got PACKET from n2", timeout=5)
        _stop(procs["n1"])
        _stop(procs["n2"])
        neg_log = d / "n1-absent-peer.log"
        start("n1", neg_log)
        _wait_log(neg_log, "Could not set up a meta connection", timeout=20)
    finally:
        for proc in procs.values():
            _stop(proc)
        for opened in handles.values():
            for handle in opened:
                handle.close()
    text = _read(logs["n1"])
    runtime_ok = exchanged and "Got PACKET from n2" in text
    neg_text = _read(d / "n1-absent-peer.log")
    neg_rejected = ("Could not set up a meta connection" in neg_text
                    and "ANS_KEY" not in neg_text)
    functional_ok = runtime_ok and neg_rejected
    return {"runtime_ok": runtime_ok, "functional_ok": functional_ok,
            "failure_class": None if functional_ok else ("functional-failure" if runtime_ok else
                                                         "runtime-failure"),
            "residual": "none" if functional_ok else ("functional-divergence" if runtime_ok else
                                                      "runtime-failure"),
            "reason": None if functional_ok else
            ("the two tinc nodes did not exchange keys and a data packet" if not runtime_ok else
             "a tinc without a reachable peer still reported an exchange"),
            "transcript": _transcript(("tincd n1 (peer n2)", {"exit_code": 0, "stdout": text}),
                                      ("tincd n1 absent-peer (must fail)",
                                       {"exit_code": 0, "stdout": neg_text})),
            "workload": ("tinc: RSA keygen + authenticated meta connection + key exchange + "
                         "data packet + absent-peer negative control"),
            "local_only": True}


def _wl_hiredis(ctx: dict) -> dict:
    """A TLS Redis session through hiredis: PING, SET and GET over a verified record layer.

    hiredis ships no TLS CLI, so its own upstream `example-ssl` is the admitted program. The local
    peer is the subject-linked `redis-server` the preceding redis family built in this same run
    (deterministically earlier in the frozen P1000 order), started with TLS on loopback; the example
    completes a verified TLS handshake and the PING/SET/GET round trips. A client trusting only the
    unrelated CA must be rejected.
    """
    ap, d = ctx["authority_prefix"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    peer_src = bl.SCRATCH / "redis" / ctx["subject"] / "src"
    peer_root = census._single_source_root(peer_src) if peer_src.is_dir() else None
    peer = (peer_root / "src" / "redis-server") if peer_root else None
    if peer is None or not peer.is_file():
        return _wl_fail([], "the subject-linked redis-server peer was not built by this run",
                        "runtime-failure", d)
    dbdir = d / "db"
    dbdir.mkdir(parents=True, exist_ok=True)
    srv, of, ef = _spawn([str(peer), "--port", "0", "--tls-port", str(ctx["port"]),
                          "--tls-cert-file", str(pki["srv_crt"]), "--tls-key-file",
                          str(pki["srv_key"]), "--tls-ca-cert-file", str(pki["ca_crt"]),
                          "--tls-auth-clients", "no", "--save", "", "--protected-mode", "no",
                          "--dir", str(dbdir)], d, ctx["env"], d / "redis.out",
                         d / "redis.err")
    try:
        if not _wait_tcp("127.0.0.1", ctx["port"]):
            return _wl_fail([("redis-server", {"exit_code": 0, "stdout": _read(
                d / "redis.err")})], "the redis TLS peer did not open its port", "runtime-failure",
                            d)
        args = [str(ctx["program"]), "127.0.0.1", str(ctx["port"]), str(pki["client_crt"]),
                str(pki["client_key"])]
        good = _run_captured(args + [str(pki["ca_crt"])], env=ctx["env"], timeout=40)
        neg = _run_captured(args + [str(pki["other_crt"])], env=ctx["env"], timeout=40)
    finally:
        _stop(srv)
        of.close()
        ef.close()
    runtime_ok = "PING: PONG" in good["stdout"]
    kv_ok = ("SET: OK" in good["stdout"] and "GET foo: hello world" in good["stdout"])
    neg_rejected = (neg["exit_code"] != 0
                    and "certificate verify failed" in (neg["stdout"] + neg["stderr"]))
    functional_ok = runtime_ok and kv_ok and neg_rejected
    return {"runtime_ok": runtime_ok, "functional_ok": functional_ok,
            "failure_class": None if functional_ok else ("functional-failure" if runtime_ok else
                                                         "runtime-failure"),
            "residual": "none" if functional_ok else ("functional-divergence" if runtime_ok else
                                                      "runtime-failure"),
            "reason": None if functional_ok else
            ("the TLS PING did not return PONG" if not runtime_ok else
             "the SET/GET round trip did not return the stored value" if not kv_ok else
             "the unrelated CA was not rejected, so the peer certificate does not verify"),
            "transcript": _transcript(("hiredis-example-ssl PING/SET/GET", good),
                                      ("hiredis-example-ssl unrelated-ca (must fail)", neg)),
            "workload": ("hiredis-ssl: verified TLS connect + PING + SET/GET + unrelated-CA reject"),
            "local_only": True}


def _wl_proxytunnel(ctx: dict) -> dict:
    """A CONNECT tunnel through a local HTTP proxy whose destination leg is TLS.

    proxytunnel's documented ProxyCommand mode is driven over a socketpair: it CONNECTs to a local
    proxy, wraps the tunnelled stream in TLS to the authority's `s_server` (`-e`) and forwards a
    real HTTP GET whose fixed page comes back through the tunnel. A destination certificate whose
    SAN names a different address must not tunnel. proxytunnel 1.12.2 never calls
    `SSL_CTX_set_verify`, so an unrelated CA would not be rejected by this build; the certificate
    decision it does enforce is the host/SAN match, and that is the control driven here.
    """
    ap, d = ctx["authority_prefix"], ctx["workdir"]
    prog = str(ctx["program"])
    pki = _gen_pki(ap, d)
    body = b"phase24-proxytunnel-tls-probe\n"
    (d / "probe.txt").write_bytes(body)

    bad_key, bad_csr, bad_crt = d / "bad.key", d / "bad.csr", d / "bad.crt"
    bad_ext = d / "bad.ext"
    csr = _ossl(ap, ["req", "-newkey", "rsa:2048", "-nodes", "-keyout", str(bad_key), "-out",
                     str(bad_csr), "-subj", "/CN=127.0.0.2"], timeout=60)
    bad_ext.write_text("subjectAltName=IP:127.0.0.2\nbasicConstraints=CA:FALSE\n"
                       "keyUsage=digitalSignature,keyEncipherment\n"
                       "extendedKeyUsage=serverAuth\n", encoding="utf-8")
    signed = _ossl(ap, ["x509", "-req", "-in", str(bad_csr), "-CA", str(pki["ca_crt"]),
                        "-CAkey", str(pki["ca_key"]), "-CAcreateserial", "-out", str(bad_crt),
                        "-days", "7", "-extfile", str(bad_ext)], timeout=60)
    if not (csr["ok"] and signed["ok"]):
        return _wl_fail([("mismatched-SAN certificate", signed if not signed["ok"] else csr)],
                        "the mismatched-SAN certificate fixture could not be generated",
                        "runtime-failure", d)

    tls_port, bad_port, proxy_port = _free_port(), _free_port(), _free_port()
    servers = []
    for port, crt, key, tag in ((tls_port, pki["srv_crt"], pki["srv_key"], "tls"),
                                (bad_port, bad_crt, bad_key, "mismatch")):
        servers.append(_spawn([str(_auth_ossl(ap)), "s_server", "-accept", str(port), "-cert",
                               str(crt), "-key", str(key), "-WWW", "-quiet"], d,
                              _auth_env(ap), d / f"{tag}.out", d / f"{tag}.err"))
    stop = threading.Event()
    proxy = _http_connect_proxy(proxy_port, stop)

    def tunnel(dest_port: int, tag: str) -> tuple[bytes, dict]:
        """Drive one proxytunnel worker over a socketpair and return its bytes and transcript."""
        local, peer = socket.socketpair()
        log = d / f"proxytunnel-{tag}.err"
        with open(log, "w", encoding="utf-8") as handle:
            proc = subprocess.Popen(
                [prog, "-p", f"127.0.0.1:{proxy_port}", "-d", f"127.0.0.1:{dest_port}",
                 "-e", "-C", str(pki["ca_crt"]), "-v"],
                stdin=peer.fileno(), stdout=peer.fileno(), stderr=handle,
                cwd=str(d), env=ctx["env"], text=True)
            peer.close()
            try:
                local.settimeout(20.0)
                local.sendall(b"GET /probe.txt HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
                data = b""
                while True:
                    chunk = local.recv(65536)
                    if not chunk:
                        break
                    data += chunk
            except OSError:
                data = b""
            finally:
                local.close()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    _stop(proc)
        return data, {"exit_code": proc.returncode or 0, "stdout": _read(log)}

    try:
        if not (_wait_tcp("127.0.0.1", tls_port) and _wait_tcp("127.0.0.1", bad_port)):
            return _wl_fail([("s_server", {"exit_code": 0, "stdout": _read(d / "tls.err")})],
                            "the TLS destinations did not open their ports",
                            "runtime-failure", d)
        good, good_log = tunnel(tls_port, "tunnel")
        bad, bad_log = tunnel(bad_port, "mismatched-san")
    finally:
        stop.set()
        proxy.join(timeout=2)
        for proc, out, err in servers:
            _stop(proc)
            out.close()
            err.close()

    tunnelled = body.strip() in good
    neg_rejected = (body.strip() not in bad
                    and "does not match certificate subject alternative names" in bad_log["stdout"])
    functional_ok = tunnelled and neg_rejected
    return {
        "runtime_ok": tunnelled,
        "functional_ok": functional_ok,
        "failure_class": None if functional_ok else ("functional-failure" if tunnelled else
                                                     "runtime-failure"),
        "residual": "none" if functional_ok else ("functional-divergence" if tunnelled else
                                                  "runtime-failure"),
        "reason": None if functional_ok else
        ("the GET did not come back through the CONNECT tunnel" if not tunnelled else
         "a destination certificate naming another address was still tunnelled to"),
        "transcript": _transcript(("proxytunnel CONNECT + TLS destination", good_log),
                                  ("proxytunnel mismatched-SAN destination (must fail)", bad_log)),
        "workload": ("proxytunnel: HTTP CONNECT through a local proxy + TLS 1.3 to the destination "
                     "+ GET round trip + mismatched-SAN reject"),
        "local_only": True}


def _wl_keepalived(ctx: dict) -> dict:
    """keepalived's HTTP/SSL check path against a local TLS server, in `-T` genhash mode.

    The daemon's IPVS virtual-server checkers cannot start in this venue (there is no
    `/proc/net/ip_vs`), so the admitted workload drives the same check implementation the checker
    uses: `-T` genhash fetches a fixed page over TLS through keepalived's own libssl client and
    prints the MD5 of the body, which must equal the served file's digest. A plaintext server
    serving the same bytes must not satisfy the SSL request. keepalived 2.3.1 sets no verify mode
    (`SSL_VERIFY_NONE`), so an unrelated CA is not a discriminator this build can be held to.

    The two legs must be provably distinct: `_free_port` closes its probe socket, so the kernel can
    return the same port twice, and a shared port would point the "plaintext" control at the TLS
    listener, whose correct digest then reads as "a plaintext server satisfied the SSL request".
    The plaintext listener therefore binds an ephemeral port *first* and holds it, and only then is
    the TLS port chosen -- the kernel cannot hand out a port that is already in LISTEN. Both
    endpoints are probed for their actual payload before either leg launches, and the negative leg
    is judged on content alone: any body digest returned for the SSL request aimed at the plaintext
    peer means cleartext was accepted, while the error text the TLS client prints is transcribed
    and never used as the predicate.
    """
    ap, d = ctx["authority_prefix"], ctx["workdir"]
    prog = str(ctx["program"])
    pki = _gen_pki(ap, d)
    body = b"phase24-keepalived-tls-probe\n"
    (d / "probe.txt").write_bytes(body)
    expected = hashlib.md5(body).hexdigest()

    plain_state: dict = {"ready": threading.Event(), "error": None, "port": None}
    stop = threading.Event()

    def plain() -> None:
        """Serve the same bytes without TLS: the SSL request must not be satisfied by it."""
        listener = socket.socket()
        try:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", 0))
            listener.listen(4)
            listener.settimeout(0.5)
        except OSError as exc:
            listener.close()
            plain_state["error"] = exc
            plain_state["ready"].set()
            return
        plain_state["port"] = int(listener.getsockname()[1])
        plain_state["ready"].set()
        while not stop.is_set():
            try:
                client, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with client:
                # Drain the request first. A TLS client sends a ClientHello this listener will not
                # understand; closing with those bytes still unread turns the close into a reset,
                # which makes the client's own error text depend on a race rather than on the
                # protocol. The close below is therefore preceded by a bounded drain and followed
                # by a half-close, so the peer's interpretation is not timing-dependent.
                deadline = time.monotonic() + 0.5
                client.settimeout(0.3)
                while time.monotonic() < deadline:
                    try:
                        if not client.recv(4096):
                            break
                    except OSError:
                        break
                try:
                    client.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: "
                                   + str(len(body)).encode() + b"\r\n\r\n" + body)
                    client.shutdown(socket.SHUT_WR)
                    client.settimeout(0.3)
                    while client.recv(4096):
                        pass
                except OSError:
                    pass
        listener.close()

    def plain_fetch(port: int) -> bytes:
        """A plaintext GET against `port`, returning its body (empty when the peer is not HTTP)."""
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=5.0) as client:
                client.settimeout(5.0)
                client.sendall(b"GET /probe.txt HTTP/1.0\r\n\r\n")
                chunks = []
                while True:
                    chunk = client.recv(4096)
                    if not chunk:
                        break
                    chunks.append(chunk)
        except OSError:
            return b""
        raw = b"".join(chunks)
        return raw.split(b"\r\n\r\n", 1)[-1] if b"\r\n\r\n" in raw else b""

    thread = threading.Thread(target=plain, daemon=True)
    thread.start()
    server = out = err = None
    try:
        if not plain_state["ready"].wait(timeout=10.0) or plain_state["error"] is not None:
            return _wl_fail([("plaintext control", {"exit_code": 0, "stdout": str(
                                plain_state["error"])})],
                            "the plaintext control could not bind its port",
                            "runtime-failure", d)
        plain_port = int(plain_state["port"])
        # Chosen only now, with the plaintext listener already in LISTEN, so the kernel cannot return
        # the same port and the two legs cannot silently become one endpoint.
        tls_port = _free_port()
        if tls_port == plain_port:
            return _wl_fail([("plaintext control", {"exit_code": 0,
                                                    "stdout": f"bound {plain_port}"})],
                            "the TLS and plaintext legs were not provably distinct",
                            "runtime-failure", d)
        server, out, err = _spawn([str(_auth_ossl(ap)), "s_server", "-accept", str(tls_port),
                                   "-cert", str(pki["srv_crt"]), "-key", str(pki["srv_key"]),
                                   "-WWW", "-quiet"], d, _auth_env(ap), d / "tls.out",
                                  d / "tls.err")
        if not _wait_tcp("127.0.0.1", tls_port):
            return _wl_fail([("s_server", {"exit_code": 0, "stdout": _read(d / "tls.err")})],
                            "the TLS destination did not open its port",
                            "runtime-failure", d)
        # Fixture integrity, asserted on content rather than on a connection: the plaintext leg
        # really serves the page over plain HTTP, and the TLS listener does not serve it in the
        # clear. A port collision or a dead plaintext listener fails here loudly instead of being
        # reported as a subject divergence.
        plain_body = plain_fetch(plain_port)
        tls_cleartext_body = plain_fetch(tls_port)
        if not (tls_port != plain_port and plain_body == body
                and tls_cleartext_body != body):
            return _wl_fail([("plaintext control", {
                                 "exit_code": 0,
                                 "stdout": plain_body.decode("utf-8", "replace")}),
                             ("tls listener cleartext probe", {
                                 "exit_code": 0,
                                 "stdout": tls_cleartext_body.decode("utf-8", "replace")})],
                            "the TLS and plaintext legs were not provably distinct",
                            "runtime-failure", d)
        base = [prog, "-T", "-S", "-s", "127.0.0.1", "-u", "/probe.txt", "-t", "5", "-p"]
        good = _run_captured(base + [str(tls_port)], env=ctx["env"], timeout=40)
        neg = _run_captured(base + [str(plain_port)], env=ctx["env"], timeout=40)
    finally:
        stop.set()
        thread.join(timeout=2)
        if server is not None:
            _stop(server)
        if out is not None:
            out.close()
        if err is not None:
            err.close()

    digest = good["stdout"].strip()
    fetched = re.fullmatch(r"[0-9a-f]{32}", digest) is not None
    # The control asserts on content, not on a connection or an error string: the plaintext peer is
    # proven alive and serving this exact payload above, so any body digest from the SSL request
    # aimed at it is a real acceptance of cleartext. Which error message the TLS client prints while
    # rejecting the peer is its own choice (a reset and a TLS alert are both rejections), so the
    # message is transcribed and never used as the predicate.
    neg_rejected = re.fullmatch(r"[0-9a-f]{32}", neg["stdout"].strip()) is None
    functional_ok = fetched and digest == expected and neg_rejected
    return {
        "runtime_ok": fetched,
        "functional_ok": functional_ok,
        "failure_class": None if functional_ok else ("functional-failure" if fetched else
                                                     "runtime-failure"),
        "residual": "none" if functional_ok else ("functional-divergence" if fetched else
                                                  "runtime-failure"),
        "reason": None if functional_ok else
        ("the TLS page fetch returned no body digest" if not fetched else
         "the fetched body digest did not match the served page" if digest != expected else
         "a plaintext server satisfied the SSL request"),
        "transcript": _transcript(("genhash TLS fetch", good),
                                  ("genhash SSL request to a plaintext server (must fail)", neg)),
        "workload": ("keepalived: TLS page fetch + body-digest match + plaintext-peer reject"),
        "local_only": True}


def _wl_ssmtp(ctx: dict) -> dict:
    """An end-to-end message submission over SMTP STARTTLS to a local stub.

    `s_server -starttls smtp` does not exist, so the stub is a tiny loopback SMTP server: `220`,
    `250-STARTTLS` on EHLO, then it answers STARTTLS and hands the accepted socket to a TLS server
    context using the fixture certificate. The message must be accepted (`250` after DATA) and its
    body must arrive intact over the TLS leg.

    ssmtp 2.64 calls no `SSL_CTX_set_verify` and only checks that `SSL_get_peer_certificate`
    returned a certificate, so the TLS leg is confidentiality without authentication. The fixture
    CA is freshly generated and is not in any default trust store; the accepted submission records
    that limitation explicitly (it is not claimed as certificate verification).
    """
    ap, d = ctx["authority_prefix"], ctx["workdir"]
    prog = str(ctx["program"])
    pki = _gen_pki(ap, d)
    body = b"phase24-ssmtp-starttls-payload\n"
    port = _free_port()
    conf = d / "ssmtp.conf"
    conf.write_text(f"mailhub=127.0.0.1:{port}\nUseSTARTTLS=YES\nFromLineOverride=YES\n"
                    f"hostname=localhost\nroot=root@example.test\n", encoding="utf-8")
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(str(pki["srv_pem"]))
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", port))
    listener.listen(1)
    listener.settimeout(40.0)
    peer: list[str] = []
    messages: list[bytes] = []
    tls_versions: list[str] = []

    def serve() -> None:
        """One SMTP submission: greeting, EHLO/STARTTLS, TLS handoff, DATA, QUIT."""
        try:
            client, _ = listener.accept()
        except OSError:
            return
        conn = client
        buffer = bytearray()

        def read_line() -> bytes | None:
            while b"\n" not in buffer:
                try:
                    chunk = conn.recv(4096)
                except OSError:
                    return None
                if not chunk:
                    return None
                buffer.extend(chunk)
            raw, _, rest = buffer.partition(b"\n")
            buffer[:] = rest
            return bytes(raw).rstrip(b"\r")

        def send(payload: bytes) -> None:
            peer.append("S: " + payload.decode("utf-8", "replace").strip())
            conn.sendall(payload)

        with client:
            client.settimeout(20.0)
            send(b"220 smtp-fixture ESMTP\r\n")
            while True:
                line = read_line()
                if line is None:
                    return
                peer.append("C: " + line.decode("utf-8", "replace"))
                verb = line.split(b" ", 1)[0].upper()
                if verb == b"EHLO":
                    send(b"250-smtp-fixture\r\n250 STARTTLS\r\n")
                elif verb == b"STARTTLS":
                    send(b"220 Ready to start TLS\r\n")
                    try:
                        conn = server_ctx.wrap_socket(client, server_side=True)
                    except ssl.SSLError as exc:
                        peer.append(f"TLS-FAILED {exc}")
                        return
                    tls_versions.append(conn.version() or "")
                    peer.append("TLS-ESTABLISHED " + (conn.version() or ""))
                    buffer.clear()
                elif verb == b"DATA":
                    send(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                    data = bytearray()
                    while True:
                        entry = read_line()
                        if entry is None:
                            return
                        if entry == b".":
                            break
                        data.extend(entry + b"\n")
                    messages.append(bytes(data))
                    send(b"250 OK queued\r\n")
                elif verb == b"QUIT":
                    send(b"221 Bye\r\n")
                    return
                else:
                    send(b"250 OK\r\n")

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        # No SSL_CERT_FILE/SSL_CERT_DIR is injected: the default trust store must be the one the
        # program uses, so acceptance records ssmtp's missing verification rather than assuming it.
        sent = _run_captured([prog, "-v", "root@example.test", "-C", str(conf)], cwd=d,
                             env=dict(ctx["env"]), timeout=60,
                             stdin_text="Subject: phase24 ssmtp probe\n\n" + body.decode())
    finally:
        thread.join(timeout=5)
        listener.close()

    delivered = bool(messages) and body.strip() in messages[0]
    starttls = any(line.startswith("C: STARTTLS") for line in peer) and bool(tls_versions)
    functional_ok = bool(delivered and starttls and sent["ok"])
    return {
        "runtime_ok": bool(delivered or (sent["ok"] and starttls)),
        "functional_ok": functional_ok,
        "failure_class": None if functional_ok else (
            "functional-failure" if delivered else "runtime-failure"),
        "residual": "none" if functional_ok else (
            "functional-divergence" if delivered else "runtime-failure"),
        "reason": None if functional_ok else (
            "the message was not accepted end to end" if not delivered else
            "the submission was accepted without a negotiated STARTTLS/TLS leg" if not starttls else
            "the submitting client exited non-zero"),
        "transcript": _transcript(("ssmtp submission", sent),
                                  ("SMTP STARTTLS stub", {"exit_code": 0,
                                                          "stdout": "\n".join(peer)})),
        "workload": ("ssmtp: SMTP submission through a local STARTTLS stub + TLS handoff + "
                     "end-to-end message acceptance"),
        "note": ("ssmtp 2.64 performs no certificate verification (no SSL_CTX_set_verify; only a "
                 "presence check on SSL_get_peer_certificate). The fixture CA is untrusted, so "
                 "acceptance records the upstream TODO; it is not a verification result."),
        "local_only": True,
    }


def _wl_tnftp(ctx: dict) -> dict:
    """tnftp's HTTPS fetch path against a local TLS server, with a plaintext negative control.

    tnftp is an FTP client that also fetches `http://`/`https://` URLs through its libssl client.
    A local `s_server -WWW` serves a fixed payload, tnftp is told to trust only the fixture CA (its
    `SSL_CTX_set_default_verify_paths` honours `SSL_CERT_FILE`), and the saved file must be
    byte-identical. The same `https://` URL aimed at a plaintext server must not yield the payload.
    """
    ap, d = ctx["authority_prefix"], ctx["workdir"]
    prog = str(ctx["program"])
    pki = _gen_pki(ap, d)
    body = b"phase24-tnftp-https-payload\n"
    (d / "probe.txt").write_bytes(body)
    tls_port = _free_port()
    plain_port = _free_port()
    # `_free_port` closes the probe socket, so the kernel may hand the same port back for the next
    # call; a shared port would silently point the "plaintext" control at the TLS server.
    while plain_port == tls_port:
        plain_port = _free_port()
    server, out, err = _spawn([str(_auth_ossl(ap)), "s_server", "-accept", str(tls_port),
                               "-cert", str(pki["srv_crt"]), "-key", str(pki["srv_key"]),
                               "-WWW", "-quiet"], d, _auth_env(ap), d / "tls.out", d / "tls.err")
    stop = threading.Event()

    def plain() -> None:
        """Accept and drop: a TLS client must not be satisfied by this plaintext peer."""
        listener = socket.socket()
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", plain_port))
        listener.listen(4)
        listener.settimeout(0.5)
        while not stop.is_set():
            try:
                client, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with client:
                client.settimeout(5.0)
                try:
                    client.recv(4096)
                except OSError:
                    pass
        listener.close()

    thread = threading.Thread(target=plain, daemon=True)
    thread.start()
    env = dict(ctx["env"], SSL_CERT_FILE=str(pki["ca_crt"]))
    fetched, rejected = d / "fetched.txt", d / "plain-fetched.txt"
    try:
        if not _wait_tcp("127.0.0.1", tls_port):
            return _wl_fail([("s_server", {"exit_code": 0, "stdout": _read(d / "tls.err")})],
                            "the TLS destination did not open its port", "runtime-failure", d)
        good = _run_captured([prog, "-V", "-o", str(fetched),
                              f"https://127.0.0.1:{tls_port}/probe.txt"], cwd=d, env=env,
                             timeout=60)
        neg = _run_captured([prog, "-V", "-o", str(rejected),
                             f"https://127.0.0.1:{plain_port}/probe.txt"], cwd=d, env=env,
                            timeout=60)
    finally:
        stop.set()
        thread.join(timeout=2)
        _stop(server)
        out.close()
        err.close()

    payload_ok = fetched.is_file() and fetched.read_bytes() == body
    neg_rejected = not rejected.is_file() or rejected.read_bytes() != body
    functional_ok = bool(good["ok"] and payload_ok and neg_rejected)
    return {
        "runtime_ok": payload_ok,
        "functional_ok": functional_ok,
        "failure_class": None if functional_ok else (
            "functional-failure" if payload_ok else "runtime-failure"),
        "residual": "none" if functional_ok else (
            "functional-divergence" if payload_ok else "runtime-failure"),
        "reason": None if functional_ok else (
            "the HTTPS fetch returned no saved payload" if not payload_ok else
            "a plaintext peer satisfied the HTTPS request"),
        "transcript": _transcript(("tnftp https fetch", good),
                                  ("tnftp https fetch from a plaintext peer (must fail)", neg)),
        "workload": ("tnftp: HTTPS GET over TLS to a local server + byte-identical payload match "
                     "+ plaintext-peer reject"),
        "note": ("tnftp verifies the peer against the default verify paths, narrowed here to the "
                 "fixture CA through SSL_CERT_FILE, and matches the URL host against the SAN."),
        "local_only": True,
    }


def _wl_fail(notes: list, reason: str, failure_class: str | None, d: Path) -> dict:
    return {"runtime_ok": False, "functional_ok": False,
            "failure_class": failure_class or "runtime-failure", "residual": "runtime-failure",
            "reason": reason, "transcript": _transcript(*notes),
            "workload": "unavailable", "local_only": True}


def _wl_libevent(ctx: dict) -> dict:
    """A libevent_openssl socketpair session: TLS1.3, verified peer, byte round trip.

    Both endpoints are bufferevents created with `bufferevent_openssl_socket_new`; the client
    verifies the server certificate against the fixture CA and the payload must return unchanged.
    A session whose client trusts only the unrelated CA must fail the handshake.
    """
    ap, d = ctx["authority_prefix"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    prog = str(ctx["program"])
    common = ["--cert", str(pki["srv_crt"]), "--key", str(pki["srv_key"])]
    good = _run_captured([prog] + common + ["--ca", str(pki["ca_crt"])], cwd=d,
                         env=ctx["env"], timeout=60)
    neg = _run_captured([prog, "--negative"] + common + ["--ca", str(pki["other_crt"])],
                        cwd=d, env=ctx["env"], timeout=60)
    text = good["stdout"] + good["stderr"]
    neg_text = neg["stdout"] + neg["stderr"]
    verified = "handshake=TLSv1.3" in text and "peer_verify=ok" in text
    runtime_ok = bool(good["ok"] and verified)
    payload_ok = "payload=ok" in text
    neg_rejected = bool(neg["ok"] and "negative=rejected" in neg_text)
    functional_ok = runtime_ok and payload_ok and neg_rejected
    return {
        "runtime_ok": runtime_ok, "functional_ok": functional_ok,
        "failure_class": None if functional_ok else (
            "functional-failure" if runtime_ok else "runtime-failure"),
        "residual": "none" if functional_ok else (
            "functional-divergence" if runtime_ok else "runtime-failure"),
        "reason": None if functional_ok else (
            "the bufferevent socketpair did not complete a verified TLS1.3 handshake"
            if not runtime_ok else
            "the encrypted round trip did not return the payload" if not payload_ok else
            "the unrelated CA was not rejected, so the peer certificate does not verify"),
        "transcript": _transcript(("libevent bufferevent TLS1.3 round trip", good),
                                  ("libevent unrelated-ca (must fail)", neg)),
        "workload": ("libevent: bufferevent_openssl client+server over a socketpair + TLS1.3 + "
                     "peer-certificate verify + payload round trip + unrelated-CA reject"),
        "local_only": True,
    }


def _wl_libretls(ctx: dict) -> dict:
    """A libtls (libretls) client/server session over a socketpair.

    The client configures the fixture CA, completes a TLS1.3 handshake, asserts the peer
    certificate was provided and verifies it, then exchanges a payload with a libtls server. A
    client configured with only the unrelated CA must fail the handshake.
    """
    ap, d = ctx["authority_prefix"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    prog = str(ctx["program"])
    common = ["--cert", str(pki["srv_crt"]), "--key", str(pki["srv_key"])]
    good = _run_captured([prog] + common + ["--ca", str(pki["ca_crt"])], cwd=d,
                         env=ctx["env"], timeout=60)
    neg = _run_captured([prog, "--negative"] + common + ["--ca", str(pki["other_crt"])],
                        cwd=d, env=ctx["env"], timeout=60)
    text = good["stdout"] + good["stderr"]
    neg_text = neg["stdout"] + neg["stderr"]
    verified = "handshake=TLSv1.3" in text and "peer_verify=ok" in text
    runtime_ok = bool(good["ok"] and verified)
    payload_ok = "payload=ok" in text
    neg_rejected = bool(neg["ok"] and "negative=rejected" in neg_text)
    functional_ok = runtime_ok and payload_ok and neg_rejected
    return {
        "runtime_ok": runtime_ok, "functional_ok": functional_ok,
        "failure_class": None if functional_ok else (
            "functional-failure" if runtime_ok else "runtime-failure"),
        "residual": "none" if functional_ok else (
            "functional-divergence" if runtime_ok else "runtime-failure"),
        "reason": None if functional_ok else (
            "the libtls socketpair session did not complete a verified TLS1.3 handshake"
            if not runtime_ok else
            "the libtls round trip did not return the payload" if not payload_ok else
            "the unrelated CA was not rejected, so the peer certificate does not verify"),
        "transcript": _transcript(("libtls client/server TLS1.3 round trip", good),
                                  ("libtls unrelated-ca (must fail)", neg)),
        "workload": ("libretls: libtls client+server over a socketpair + TLS1.3 + peer-certificate "
                     "verify + payload round trip + unrelated-CA reject"),
        "local_only": True,
    }


def _wl_libarchive(ctx: dict) -> dict:
    """A libarchive create/read cycle whose integrity is a libcrypto SHA-256 digest.

    The archive holds a payload and its SHA-256 digest (computed through EVP); reading it back
    must reproduce the payload and verify the digest. One payload byte flipped inside the archive
    must be rejected by the digest check, so a reader that ignores integrity is a recorded failure.
    """
    d = ctx["workdir"]
    prog = str(ctx["program"])
    good = _run_captured([prog], cwd=d, env=ctx["env"], timeout=60)
    tamper = _run_captured([prog, "--tamper"], cwd=d, env=ctx["env"], timeout=60)
    text = good["stdout"] + good["stderr"]
    tamper_text = tamper["stdout"] + tamper["stderr"]
    runtime_ok = bool(good["ok"] and "archive=read" in text and "digest=ok" in text)
    tamper_rejected = bool(tamper["ok"] and "tampered=rejected" in tamper_text)
    functional_ok = runtime_ok and tamper_rejected
    return {
        "runtime_ok": runtime_ok, "functional_ok": functional_ok,
        "failure_class": None if functional_ok else (
            "functional-failure" if runtime_ok else "runtime-failure"),
        "residual": "none" if functional_ok else (
            "functional-divergence" if runtime_ok else "runtime-failure"),
        "reason": None if functional_ok else (
            "libarchive did not create and read back the archive with a matching SHA-256 digest"
            if not runtime_ok else
            "the tampered payload byte was not rejected by the digest check"),
        "transcript": _transcript(("libarchive create/read + SHA-256", good),
                                  ("libarchive tampered payload (must reject)", tamper)),
        "workload": ("libarchive: in-memory tar create/read + libcrypto SHA-256 digest verify + "
                     "tampered-byte reject"),
        "local_only": True,
    }


def _wl_mosquitto(ctx: dict) -> dict:
    """The mosquitto broker and its own clients over TLS1.3, with a trust negative control.

    The broker listens on loopback with the fixture CA/cert/key, a retained publish is made by
    `mosquitto_pub`, and `mosquitto_sub -C 1` must receive the exact payload over its own TLS
    client. A publish whose client trusts only the unrelated CA must fail, and the broker's own
    transcript must show the rejected handshake (`unknown ca`).
    """
    ap, d = ctx["authority_prefix"], ctx["workdir"]
    root, prog = ctx["root"], str(ctx["program"])
    pki = _gen_pki(ap, d)
    payload = "phase25-mosquitto-payload"
    topic = "phase25/runtime"
    port = ctx["port"]
    conf = d / "mosquitto.conf"
    conf.write_text(
        f"listener {port} 127.0.0.1\n"
        "allow_anonymous true\n"
        "user root\n"
        f"cafile {pki['ca_crt']}\n"
        f"certfile {pki['srv_crt']}\n"
        f"keyfile {pki['srv_key']}\n"
        "log_dest stderr\n",
        encoding="utf-8")
    broker, out, err = _spawn([prog, "-c", str(conf), "-v"], d, ctx["env"],
                              d / "broker.out", d / "broker.err")
    pub = sub = neg = None
    try:
        if not _wait_tcp("127.0.0.1", port):
            return _wl_fail([("mosquitto", {"exit_code": 0, "stdout": _read(d / "broker.err")})],
                            "the mosquitto broker did not open its TLS listener",
                            "runtime-failure", d)
        common = ["-h", "127.0.0.1", "-p", str(port)]
        pub = _run_captured([str(root / "client/mosquitto_pub")] + common +
                            ["--cafile", str(pki["ca_crt"]), "-t", topic, "-m", payload,
                             "-r"], cwd=d, env=ctx["env"], timeout=30)
        sub = _run_captured([str(root / "client/mosquitto_sub")] + common +
                            ["--cafile", str(pki["ca_crt"]), "-t", topic, "-C", "1"],
                            cwd=d, env=ctx["env"], timeout=30)
        neg = _run_captured([str(root / "client/mosquitto_pub")] + common +
                            ["--cafile", str(pki["other_crt"]), "-t", topic, "-m", "x"],
                            cwd=d, env=ctx["env"], timeout=30)
    finally:
        _stop(broker)
        out.close()
        err.close()

    broker_log = _read(d / "broker.err")
    received = (sub["stdout"] or "").strip()
    payload_ok = bool(pub and pub["ok"] and sub and sub["ok"] and received == payload)
    neg_rejected = bool(neg and not neg["ok"] and "unknown ca" in broker_log)
    functional_ok = payload_ok and neg_rejected
    return {
        "runtime_ok": payload_ok,
        "functional_ok": functional_ok,
        "failure_class": None if functional_ok else (
            "functional-failure" if payload_ok else "runtime-failure"),
        "residual": "none" if functional_ok else (
            "functional-divergence" if payload_ok else "runtime-failure"),
        "reason": None if functional_ok else (
            "the retained publish/subscribe over TLS did not return the payload"
            if not payload_ok else
            "a client trusting only the unrelated CA was not rejected"),
        "transcript": _transcript(("mosquitto_pub over TLS", pub),
                                  ("mosquitto_sub over TLS", sub),
                                  ("mosquitto_pub unrelated-ca (must fail)", neg),
                                  ("mosquitto broker", {"exit_code": 0,
                                                        "stderr": broker_log})),
        "workload": ("mosquitto: broker TLS listener + retained publish + subscribe over TLS "
                     "+ exact payload match + unrelated-CA reject"),
        "local_only": True,
    }


def _wl_cyrus_sasl(ctx: dict) -> dict:
    """cyrus-sasl's client and server APIs authenticating with DIGEST-MD5.

    The harness runs both SASL roles in one process over a socketpair (the response is computed
    through the family's libcrypto MD5/HMAC path) and resolves the fixture user through an
    in-process auxprop plugin. A second session with the wrong password must be rejected.
    """
    d = ctx["workdir"]
    prog = str(ctx["program"])
    env = dict(ctx["env"], SASL_PATH=str(ctx["root"] / "plugins" / ".libs"))
    good = _run_captured([prog], cwd=d, env=env, timeout=60)
    text = good["stdout"] + good["stderr"]
    # The mechanism is selected at harness compile time (DIGEST-MD5, SCRAM-SHA-256 or
    # CRAM-MD5); the contract checked here is the same for each: the client/server
    # exchange authenticates and a wrong password is rejected.
    runtime_ok = bool(good["ok"] and "mech=" in text and "auth=ok" in text)
    rejected = "wrong-password=rejected" in text
    functional_ok = runtime_ok and rejected
    return {
        "runtime_ok": runtime_ok,
        "functional_ok": functional_ok,
        "failure_class": None if functional_ok else (
            "functional-failure" if runtime_ok else "runtime-failure"),
        "residual": "none" if functional_ok else (
            "functional-divergence" if runtime_ok else "runtime-failure"),
        "reason": None if functional_ok else (
            "the SASL client/server exchange did not authenticate" if not runtime_ok else
            "the wrong password was not rejected"),
        "transcript": _transcript((f"{ctx['family']} client/server", good)),
        "workload": (f"{ctx['family']}: client+server SASL over a socketpair + "
                     "authentication + wrong-password reject"),
        "local_only": True,
    }


def _wl_sipsak(ctx: dict) -> dict:
    """sipsak's SIP MD5 digest authentication against a local UDP peer."""
    d = ctx["workdir"]
    prog = str(ctx["program"])
    nonce = "fixture-nonce-123"
    # The peer's secret is fixed; `password` is what the client under test is told.  Using the
    # client-supplied value on both sides would make the negative arm vacuous.
    fixture_password = "password"

    def run(password: str) -> tuple[dict, dict]:
        port = _free_port()
        state = {"requests": 0, "verified": False, "challenged": False}
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", port))
        sock.settimeout(8)

        def md5(text: str) -> str:
            return hashlib.md5(text.encode("utf-8")).hexdigest()

        def serve() -> None:
            try:
                for _ in range(3):
                    data, addr = sock.recvfrom(65535)
                    state["requests"] += 1
                    msg = data.decode("utf-8", "replace")
                    lines = msg.split("\r\n")
                    headers: dict[str, str] = {}
                    for line in lines[1:]:
                        if not line:
                            break
                        if ":" in line:
                            key, value = line.split(":", 1)
                            headers.setdefault(key.lower(), value.strip())
                    auth_line = "\r\n".join(
                        line for line in lines if line.lower().startswith("authorization:"))
                    params = {key: (quoted or bare) for key, quoted, bare in re.findall(
                        r"(\w+)=(?:\"([^\"]*)\"|([^,\s]+))", auth_line)}
                    code = "401 Unauthorized"
                    extra = ""
                    if auth_line and "response" in params:
                        uri = params.get("uri", "")
                        qop = params.get("qop", "")
                        ha1 = md5(f"{params.get('username', '')}:{params.get('realm', '')}:"
                                  f"{fixture_password}")
                        ha2 = md5(f"OPTIONS:{uri}")
                        if qop:
                            expected = md5(f"{ha1}:{nonce}:{params.get('nc', '')}:"
                                           f"{params.get('cnonce', '')}:{qop}:{ha2}")
                        else:
                            expected = md5(f"{ha1}:{nonce}:{ha2}")
                        state["verified"] = expected == params.get("response")
                        code = "200 OK" if state["verified"] else "403 Forbidden"
                    else:
                        state["challenged"] = True
                        extra = (f"WWW-Authenticate: Digest realm=\"fixture\", "
                                 f"nonce=\"{nonce}\", algorithm=MD5, qop=\"auth\"\r\n")
                    reply = f"SIP/2.0 {code}\r\n"
                    for name in ("via", "from", "to", "call-id", "cseq"):
                        if name in headers:
                            canonical = {"via": "Via", "from": "From", "to": "To",
                                         "call-id": "Call-ID", "cseq": "CSeq"}[name]
                            reply += f"{canonical}: {headers[name]}\r\n"
                    reply += extra + "Content-Length: 0\r\n\r\n"
                    sock.sendto(reply.encode("utf-8"), addr)
            except OSError:
                return

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        try:
            res = _run_captured([prog, "-s", f"sip:fixture@127.0.0.1:{port}", "-u", "fixture",
                                 "-a", password, "-N"], cwd=d, env=ctx["env"], timeout=20)
        finally:
            thread.join(timeout=1)
            sock.close()
        return res, state

    good, good_state = run("password")
    neg, neg_state = run("wrong-password")
    pos_ok = bool(good["ok"] and "SIP ok" in good["stdout"] and good_state["verified"])
    # sipsak's Nagios mode treats any SIP response as reachability, so the negative
    # control is the peer's actual decision: the peer received the authenticated request
    # and its digest did not verify.  A verified second request would mean the wrong
    # password was accepted.
    neg_ok = bool(neg_state["challenged"] and not neg_state["verified"]
                  and neg_state["requests"] >= 2)
    functional = bool(pos_ok and neg_ok)
    return {
        "runtime_ok": pos_ok, "functional_ok": functional,
        "failure_class": None if functional else (
            "functional-failure" if pos_ok else "runtime-failure"),
        "residual": "none" if functional else (
            "functional-divergence" if pos_ok else "runtime-failure"),
        "reason": None if functional else (
            "the SIP digest exchange did not authenticate" if not pos_ok else
            "the wrong password was not rejected"),
        "transcript": _transcript(("sipsak MD5 digest auth", good),
                                  ("sipsak wrong password (must fail)", neg),
                                  ("peer decision on the wrong password", {
                                      "exit_code": 0,
                                      "stdout": (f"requests={neg_state['requests']} "
                                                 f"challenged={neg_state['challenged']} "
                                                 f"verified={neg_state['verified']}")})),
        "workload": "sipsak: SIP OPTIONS with MD5 digest auth + wrong-password reject",
        "local_only": True,
    }


def _wl_git_crypt(ctx: dict) -> dict:
    """git-crypt's symmetric encryption path in a local repository.

    The workload initialises a repository (libcrypto RNG/HMAC), encrypts a committed file,
    proves the locked worktree no longer contains the plaintext, unlocks it with the exported
    key, and requires a key exported from a different repository to be rejected.  Only the
    family's own binary and git's local object store are involved.
    """
    d = ctx["workdir"]
    prog = str(ctx["program"])
    env = ctx["env"]
    repo = d / "repo"
    other = d / "other"
    repo.mkdir(parents=True, exist_ok=True)
    other.mkdir(parents=True, exist_ok=True)

    def git(root: Path, *argv: str) -> dict:
        return _run_captured(["git", *argv], cwd=root, env=env, timeout=60)

    for root in (repo, other):
        git(root, "init", "-q")
        git(root, "config", "user.email", "fixture@example.invalid")
        git(root, "config", "user.name", "fixture")
    init = _run_captured([prog, "init"], cwd=repo, env=env, timeout=60)
    other_init = _run_captured([prog, "init"], cwd=other, env=env, timeout=60)
    key = d / "key"
    other_key = d / "other.key"
    export = _run_captured([prog, "export-key", str(key)], cwd=repo, env=env, timeout=60)
    export_other = _run_captured([prog, "export-key", str(other_key)], cwd=other, env=env,
                                 timeout=60)
    (repo / ".gitattributes").write_text(
        "secret.txt filter=git-crypt diff=git-crypt\n", encoding="utf-8")
    (repo / "secret.txt").write_text("template-payload\n", encoding="utf-8")
    add = git(repo, "add", ".gitattributes", "secret.txt")
    commit = git(repo, "commit", "-qm", "fixture")
    lock = _run_captured([prog, "lock"], cwd=repo, env=env, timeout=60)
    locked = (repo / "secret.txt").read_bytes() if (repo / "secret.txt").is_file() else b""
    encrypted = b"template-payload" not in locked
    bad = d / "bad"
    if repo.is_dir():
        shutil.copytree(repo, bad)
    wrong = _run_captured([prog, "unlock", str(other_key)], cwd=bad, env=env, timeout=60) \
        if bad.is_dir() else {"ok": True, "exit_code": 0, "stdout": "", "stderr": ""}
    wrong_secret = (bad / "secret.txt").read_bytes() if (bad / "secret.txt").is_file() else b""
    wrong_rejected = (not wrong["ok"]) and b"template-payload" not in wrong_secret
    unlock = _run_captured([prog, "unlock", str(key)], cwd=repo, env=env, timeout=60)
    # Materialise the worktree through the family's smudge filter.  `unlock` normally does this
    # itself; the explicit checkout makes the decrypt path observable even when the worktree is
    # already considered clean.
    checkout = git(repo, "checkout", "--", "secret.txt")
    restored = (repo / "secret.txt").read_bytes() if (repo / "secret.txt").is_file() else b""
    functional = bool(init["ok"] and other_init["ok"] and export["ok"] and export_other["ok"]
                      and add["ok"] and commit["ok"] and lock["ok"] and encrypted
                      and wrong_rejected and unlock["ok"] and checkout["ok"]
                      and b"template-payload" in restored)
    return {
        "runtime_ok": bool(init["ok"] and lock["ok"] and unlock["ok"]),
        "functional_ok": functional,
        "failure_class": None if functional else (
            "functional-failure" if (init["ok"] and lock["ok"]) else "runtime-failure"),
        "residual": "none" if functional else (
            "functional-divergence" if (init["ok"] and lock["ok"]) else "runtime-failure"),
        "reason": None if functional else (
            "the locked worktree still held the plaintext" if not encrypted else
            "a key from a different repository was accepted" if not wrong_rejected else
            "the exported key did not restore the plaintext"),
        "transcript": _transcript(
            ("git-crypt init", init), ("git-crypt export-key", export),
            ("git add", add), ("git commit", commit), ("git-crypt lock", lock),
            ("locked worktree (must not contain the payload)", {
                "exit_code": 0, "stdout": f"ciphertext-bytes={len(locked)}",
                "stderr": "payload-absent" if encrypted else "PLAINTEXT-PRESENT"}),
            ("git-crypt unlock with a foreign key (must fail)", wrong),
            ("git-crypt unlock with the exported key", unlock),
            ("git checkout through the smudge filter", checkout),
            ("restored worktree", {
                "exit_code": 0, "stdout": restored.decode("utf-8", "replace")[:64]})),
        "workload": ("git-crypt: init/export/lock over a local repository + ciphertext differs "
                     "from plaintext + foreign-key reject + exported-key restore"),
        "local_only": True,
    }


def _wl_s2n(ctx: dict) -> dict:
    """s2n-tls' s2nd server, driven by a verifying Python TLS client."""
    d = ctx["workdir"]
    pki = _gen_pki(ctx["authority_prefix"], d / "pki")
    port = ctx["port"]
    log_path = d / "s2nd.log"
    log = open(log_path, "w", encoding="utf-8")
    proc = subprocess.Popen(
        [str(ctx["program"]), "--cert", str(pki["srv_crt"]), "--key", str(pki["srv_key"]),
         "-X3", "127.0.0.1", str(port)], cwd=str(d), env=ctx["env"], text=True,
        stdin=subprocess.PIPE, stdout=log, stderr=log)
    payload = "template-payload\n"
    good: dict = {"exit_code": -1, "stdout": "", "stderr": "server did not listen"}
    neg: dict = {"exit_code": -1, "stdout": "", "stderr": "negative control not run"}
    try:
        if _wait_log(log_path, "Listening on", timeout=20) and proc.stdin is not None:
            proc.stdin.write(payload)
            proc.stdin.flush()
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=10) as sock:
                    with _tls_context(pki).wrap_socket(sock, server_hostname="localhost") as tls:
                        data = tls.recv(len(payload))
                good = {"exit_code": 0, "stdout": data.decode("utf-8", "replace"),
                        "stderr": ""}
            except (ssl.SSLError, OSError) as exc:
                good = {"exit_code": 1, "stdout": "", "stderr": str(exc)}
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=10) as sock:
                    with _tls_context(pki, ca=pki["other_crt"]).wrap_socket(
                            sock, server_hostname="localhost") as tls:
                        tls.recv(1)
                neg = {"exit_code": 0, "stdout": "unrelated CA accepted", "stderr": ""}
            except (ssl.SSLError, OSError) as exc:
                neg = {"exit_code": 1, "stdout": "", "stderr": str(exc)}
    finally:
        proc.kill()
        try:
            proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        log.close()
    pos_ok = good["exit_code"] == 0 and good["stdout"] == payload
    neg_ok = neg["exit_code"] != 0
    functional = bool(pos_ok and neg_ok)
    return {
        "runtime_ok": pos_ok, "functional_ok": functional,
        "failure_class": None if functional else (
            "functional-failure" if pos_ok else "runtime-failure"),
        "residual": "none" if functional else (
            "functional-divergence" if pos_ok else "runtime-failure"),
        "reason": None if functional else (
            "s2nd did not deliver the server payload" if not pos_ok else
            "an unrelated CA was accepted"),
        "transcript": _transcript(("s2nd verified TLS exchange", good),
                                  ("s2nd unrelated CA (must fail)", neg)),
        "workload": "s2n-tls: verified TLS server exchange + unrelated-CA reject",
        "local_only": True,
    }


def _wl_openldap(ctx: dict) -> dict:
    """OpenLDAP slapd over ldaps:// plus its own ldapmodify/ldapsearch clients."""
    d = ctx["workdir"]
    root = ctx["root"]
    pki = _gen_pki(ctx["authority_prefix"], d / "pki")
    db = d / "db"
    db.mkdir(parents=True, exist_ok=True)
    port = ctx["port"]
    conf = d / "slapd.conf"
    conf.write_text(
        f"include {root}/servers/slapd/schema/core.schema\n"
        f"pidfile {d}/slapd.pid\n"
        f"TLSCertificateFile {pki['srv_crt']}\n"
        f"TLSCertificateKeyFile {pki['srv_key']}\n"
        f"TLSCACertificateFile {pki['ca_crt']}\n"
        "database mdb\n"
        'suffix "dc=fixture,dc=test"\n'
        'rootdn "cn=admin,dc=fixture,dc=test"\n'
        "rootpw secret\n"
        f"directory {db}\n", encoding="utf-8")
    base = d / "base.ldif"
    base.write_text("dn: dc=fixture,dc=test\nobjectClass: top\nobjectClass: dcObject\n"
                    "objectClass: organization\ndc: fixture\no: fixture\n\n",
                    encoding="utf-8")
    proc = subprocess.Popen([str(ctx["program"]), "-f", str(conf), "-h",
                             f"ldaps://127.0.0.1:{port}/", "-d", "0"], cwd=str(d),
                            env=ctx["env"], stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    client_env = dict(ctx["env"], LDAPTLS_CACERT=str(pki["ca_crt"]),
                      LDAPTLS_REQCERT="demand")
    neg_env = dict(ctx["env"], LDAPTLS_CACERT=str(pki["other_crt"]),
                   LDAPTLS_REQCERT="demand")
    modify = str(root / "clients/tools/ldapmodify")
    search = str(root / "clients/tools/ldapsearch")
    good = {"exit_code": -1, "stdout": "", "stderr": "server did not listen"}
    neg = {"exit_code": -1, "stdout": "", "stderr": "negative control not run"}
    try:
        if _wait_tcp("127.0.0.1", port, timeout=20):
            add = _run_captured([modify, "-a", "-x", "-H", f"ldaps://127.0.0.1:{port}",
                                 "-D", "cn=admin,dc=fixture,dc=test", "-w", "secret", "-f",
                                 str(base)], cwd=d, env=client_env, timeout=60)
            good = _run_captured([search, "-x", "-H", f"ldaps://127.0.0.1:{port}", "-b",
                                  "dc=fixture,dc=test", "-s", "base", "dn"], cwd=d,
                                 env=client_env, timeout=60)
            neg = _run_captured([search, "-x", "-H", f"ldaps://127.0.0.1:{port}", "-b",
                                 "dc=fixture,dc=test"], cwd=d, env=neg_env, timeout=60)
            good["stdout"] = (add["stdout"] + add["stderr"] + "\n" + good["stdout"])
    finally:
        proc.terminate()
        try:
            proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
    pos_ok = good["exit_code"] == 0 and "dn: dc=fixture,dc=test" in good["stdout"]
    neg_ok = neg["exit_code"] != 0
    functional = bool(pos_ok and neg_ok)
    return {
        "runtime_ok": pos_ok, "functional_ok": functional,
        "failure_class": None if functional else (
            "functional-failure" if pos_ok else "runtime-failure"),
        "residual": "none" if functional else (
            "functional-divergence" if pos_ok else "runtime-failure"),
        "reason": None if functional else (
            "the ldaps:// add/search did not return the fixture entry" if not pos_ok else
            "an unrelated CA was accepted"),
        "transcript": _transcript(("slapd ldaps add/search", good),
                                  ("ldapsearch unrelated CA (must fail)", neg)),
        "workload": "openldap: ldaps:// add + base search + unrelated-CA reject",
        "local_only": True,
    }


def _wl_srt(ctx: dict) -> dict:
    """SRT's OpenSSL-encrypted transport over loopback, with a passphrase control."""
    d = ctx["workdir"]
    prog = str(ctx["program"])
    payload = b"template-payload\n"

    def round_trip(passphrase: str, listen_pass: str) -> tuple[bool, str]:
        srt_port, udp_in, udp_out = _free_port(), _free_port(), _free_port()
        rx = subprocess.Popen(
            [prog, "-t", "8", f"srt://:{srt_port}?mode=listener&passphrase={listen_pass}",
             f"udp://127.0.0.1:{udp_out}?mode=receiver"], cwd=str(d), env=ctx["env"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        tx = subprocess.Popen(
            [prog, "-t", "8", f"udp://127.0.0.1:{udp_in}?mode=receiver",
             f"srt://127.0.0.1:{srt_port}?passphrase={passphrase}"], cwd=str(d),
            env=ctx["env"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        got = b""
        try:
            time.sleep(1.5)
            sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sender.sendto(payload, ("127.0.0.1", udp_in))
            receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            receiver.bind(("127.0.0.1", udp_out))
            receiver.settimeout(5)
            try:
                got, _ = receiver.recvfrom(4096)
            except socket.timeout:
                got = b""
            finally:
                receiver.close()
                sender.close()
        finally:
            for proc in (tx, rx):
                proc.kill()
                try:
                    proc.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
        return got == payload, f"received={got!r}"

    pos_ok, pos_detail = round_trip("fixture-passphrase", "fixture-passphrase")
    neg_ok, neg_detail = round_trip("wrong-passphrase", "fixture-passphrase")
    # The negative arm must deliver nothing: `neg_ok` is True when the mismatch was rejected.
    rejected = not neg_ok
    functional = bool(pos_ok and rejected)
    return {
        "runtime_ok": pos_ok, "functional_ok": functional,
        "failure_class": None if functional else (
            "functional-failure" if pos_ok else "runtime-failure"),
        "residual": "none" if functional else (
            "functional-divergence" if pos_ok else "runtime-failure"),
        "reason": None if functional else (
            "the encrypted round trip did not deliver the payload" if not pos_ok else
            "a mismatched passphrase still delivered data"),
        "transcript": _transcript(
            ("srt encrypted round trip", {"exit_code": 0, "stdout": pos_detail}),
            ("srt mismatched passphrase (must deliver nothing)", {
                "exit_code": 0, "stdout": neg_detail})),
        "workload": "srt: encrypted sender/receiver round trip + mismatched-passphrase reject",
        "local_only": True,
    }


def _wl_slowhttptest(ctx: dict) -> dict:
    """slowhttptest's HTTPS slow-read client against a local TLS fixture."""
    d = ctx["workdir"]
    pki = _gen_pki(ctx["authority_prefix"], d / "pki")
    prog = str(ctx["program"])
    body = b"x" * 4096

    class Handler(http.server.BaseHTTPRequestHandler):
        hits = 0

        def do_GET(self) -> None:  # noqa: N802 - stdlib name
            type(self).hits += 1
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except OSError:
                pass

        def log_message(self, *args: object) -> None:
            return

    def drive(port: int, *, tls: bool) -> tuple[dict, int]:
        Handler.hits = 0
        server = http.server.HTTPServer(("127.0.0.1", port), Handler)
        if tls:
            sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            sctx.load_cert_chain(str(pki["srv_crt"]), str(pki["srv_key"]))
            server.socket = sctx.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            res = _run_captured([prog, "-X", "-c", "1", "-l", "2", "-i", "1", "-r", "1",
                                 "-u", f"https://127.0.0.1:{port}/"], cwd=d, env=ctx["env"],
                                timeout=30)
        finally:
            server.shutdown()
            server.server_close()
        return res, Handler.hits

    pos, pos_hits = drive(ctx["port"], tls=True)
    neg, neg_hits = drive(_free_port(), tls=False)
    pos_ok = bool(pos["ok"] and "Test ended" in (pos["stdout"] + pos["stderr"])
                  and pos_hits >= 1)
    neg_ok = neg_hits == 0
    functional = bool(pos_ok and neg_ok)
    return {
        "runtime_ok": pos_ok, "functional_ok": functional,
        "failure_class": None if functional else (
            "functional-failure" if pos_ok else "runtime-failure"),
        "residual": "none" if functional else (
            "functional-divergence" if pos_ok else "runtime-failure"),
        "reason": None if functional else (
            "the HTTPS slow-read exchange did not complete" if not pos_ok else
            "the plaintext peer was not rejected"),
        "transcript": _transcript(("slowhttptest TLS slow read", pos),
                                  ("slowhttptest plaintext peer (must fail)", neg)),
        "workload": "slowhttptest: HTTPS slow-read exchange + plaintext-peer reject",
        "local_only": True,
    }


def _wl_links(ctx: dict) -> dict:
    """links' non-interactive HTTPS consumer path against a local TLS server.

    `links -dump` fetches a page over TLS from a loopback HTTPS server, verifying the server
    certificate against the fixture CA (its OpenSSL client honours SSL_CERT_FILE), and the page
    body is the functional assertion. The same request trusting only the unrelated CA must be
    rejected with `Invalid certificate`. The workload is deliberately the `-dump` client path:
    links' interactive UI does not terminate when driven from a pipe.
    """
    ap, d = ctx["authority_prefix"], ctx["workdir"]
    prog = str(ctx["program"])
    pki = _gen_pki(ap, d)
    body = b"phase25-links-https-payload\n"
    port = ctx["port"]

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 — the base class names the verb
            if self.path != "/probe.txt":
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            self.wfile.flush()
            # A TLS close_notify is what makes links see a clean end of stream; without it the
            # body is still rendered but the client reports `SSL error` and exits non-zero.
            self.request.settimeout(0.3)
            try:
                self.request.unwrap()
            except OSError:
                pass
            self.close_connection = True

        def log_message(self, *args: object) -> None:
            return

    server = http.server.HTTPServer(("127.0.0.1", port), Handler)
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.load_cert_chain(str(pki["srv_crt"]), str(pki["srv_key"]))
    server.socket = sctx.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"https://127.0.0.1:{port}/probe.txt"
    try:
        good = _run_captured([prog, "-dump", url], cwd=d,
                             env=dict(ctx["env"], SSL_CERT_FILE=str(pki["ca_crt"])),
                             timeout=60)
        neg = _run_captured([prog, "-dump", url], cwd=d,
                            env=dict(ctx["env"], SSL_CERT_FILE=str(pki["other_crt"])),
                            timeout=60)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    good_text = good["stdout"] + good["stderr"]
    neg_text = neg["stdout"] + neg["stderr"]
    payload_ok = bool(good["ok"] and body.decode().strip() in good_text)
    neg_rejected = bool(not neg["ok"] and body.decode().strip() not in neg_text
                        and "Invalid certificate" in neg_text)
    functional_ok = payload_ok and neg_rejected
    return {
        "runtime_ok": payload_ok,
        "functional_ok": functional_ok,
        "failure_class": None if functional_ok else (
            "functional-failure" if payload_ok else "runtime-failure"),
        "residual": "none" if functional_ok else (
            "functional-divergence" if payload_ok else "runtime-failure"),
        "reason": None if functional_ok else (
            "links did not render the HTTPS page body" if not payload_ok else
            "the unrelated CA was not rejected with `Invalid certificate`"),
        "transcript": _transcript(("links -dump over HTTPS", good),
                                  ("links -dump unrelated-ca (must fail)", neg)),
        "workload": ("links: non-interactive `-dump` HTTPS fetch + fixture-CA verify + page "
                     "body match + unrelated-CA reject"),
        "local_only": True,
    }


def _dovecot_links(install: Path) -> list[tuple[Path, Path]]:
    """The two compile-time `/usr/local` paths dovecot's master re-execs and dlopens.

    The pristine build is configured with the upstream default prefix but installed with `DESTDIR`
    into its own tree, so `BINDIR/doveconf` and `MODULE_DIR/libssl_iostream_openssl.so` still name
    `/usr/local`. The two paths are linked to the installed tree for the duration of the run and
    restored afterwards; a pre-existing real path is never overwritten.
    """
    return [(Path("/usr/local/bin/doveconf"), install / "bin" / "doveconf"),
            (Path("/usr/local/lib/dovecot"), install / "lib" / "dovecot")]


def _wl_dovecot(ctx: dict) -> dict:
    """The installed dovecot master serving IMAPS, driven by a dovecot-linked TLS client.

    The client is the harness the load proof resolves: it links the subject's libssl directly and
    verifies the server certificate against the fixture CA. It logs in, APPENDs a message, SELECTs
    INBOX and FETCHes the message back, so the assertion covers the IMAP greeting, the mailbox
    write and the read path. A client trusting only the unrelated CA must fail certificate
    verification (and the server log must record the resulting `unknown ca` alert).
    """
    ap, d = ctx["authority_prefix"], ctx["workdir"]
    root, prog = ctx["root"], str(ctx["program"])
    prefix = ctx["prefix"]
    pki = _gen_pki(ap, d)
    install = root / ".l7-install" / "usr" / "local"
    master = install / "sbin" / "dovecot"
    base = d / "dovecot"
    for sub in ("run", "state", "maildir", "home"):
        (base / sub).mkdir(parents=True, exist_ok=True)
    for sub in ("maildir", "home"):
        try:
            os.chown(base / sub, 65534, 65534)
        except OSError:
            pass
    port = ctx["port"]
    conf = d / "dovecot.conf"
    conf.write_text(
        f"base_dir = {base}/run\n"
        f"state_dir = {base}/state\n"
        f"libexec_dir = {install}/libexec/dovecot\n"
        f"log_path = {base}/dovecot.log\n"
        "protocols = imap\n"
        "listen = 127.0.0.1\n"
        "ssl = yes\n"
        f"ssl_cert = <{pki['srv_crt']}\n"
        f"ssl_key = <{pki['srv_key']}\n"
        "ssl_min_protocol = TLSv1.2\n"
        "disable_plaintext_auth = no\n"
        "auth_mechanisms = plain login\n"
        f"mail_location = maildir:{base}/maildir\n"
        "mail_fsync = never\n"
        "default_internal_user = nobody\n"
        "default_internal_group = nogroup\n"
        "default_login_user = nobody\n"
        "first_valid_uid = 1\n"
        "service imap-login {\n"
        "  inet_listener imap {\n"
        "    port = 0\n"
        "  }\n"
        "  inet_listener imaps {\n"
        f"    port = {port}\n"
        "    ssl = yes\n"
        "  }\n"
        "}\n"
        "passdb {\n"
        "  driver = static\n"
        "  args = password=phase25pass\n"
        "}\n"
        "userdb {\n"
        "  driver = static\n"
        f"  args = uid=65534 gid=65534 home={base}/home\n"
        "}\n",
        encoding="utf-8")

    saved: list[tuple[Path, str | None, bool]] = []
    server = out = err = None
    good = neg = None
    try:
        for link, target in _dovecot_links(install):
            if link.is_symlink():
                saved.append((link, os.readlink(link), True))
                link.unlink()
            elif link.exists():
                raise RuntimeError(f"{link} exists and is not a symlink; refusing to replace it")
            else:
                saved.append((link, None, True))
            link.parent.mkdir(parents=True, exist_ok=True)
            link.symlink_to(target)

        env = dict(ctx["env"], LD_LIBRARY_PATH=os.pathsep.join(
            [str(prefix / "lib"), str(install / "lib" / "dovecot")]))
        server, out, err = _spawn([str(master), "-c", str(conf), "-F"], d, env,
                                  d / "dovecot.out", d / "dovecot.err")
        if not _wait_tcp("127.0.0.1", port):
            return _wl_fail([("dovecot master", {"exit_code": 0,
                                                 "stderr": _read(d / "dovecot.err")})],
                            "the dovecot master did not open its IMAPS listener",
                            "runtime-failure", d)
        common = ["--ca", str(pki["ca_crt"]), "--host", "127.0.0.1", "--port", str(port)]
        good = _run_captured([prog] + common + ["--message", "phase25-dovecot-payload"],
                             cwd=d, env=ctx["env"], timeout=90)
        neg = _run_captured([prog, "--negative", "--ca", str(pki["other_crt"]),
                             "--host", "127.0.0.1", "--port", str(port)],
                            cwd=d, env=ctx["env"], timeout=90)
    finally:
        if server is not None:
            _stop(server)
        if out is not None:
            out.close()
        if err is not None:
            err.close()
        for link, old, touched in saved:
            if not touched:
                continue
            if link.is_symlink():
                link.unlink()
            if old is not None:
                link.symlink_to(old)

    log = _read(d / "dovecot.log")
    text = (good["stdout"] + good["stderr"]) if good else ""
    neg_text = (neg["stdout"] + neg["stderr"]) if neg else ""
    handshake = "handshake=TLSv1.3" in text and "peer_verify=ok" in text
    runtime_ok = bool(good and good["ok"] and handshake)
    steps_ok = all(f"{step}=ok" in text
                   for step in ("greeting", "login", "append", "select", "payload"))
    neg_rejected = bool(neg and neg["ok"] and "negative=rejected" in neg_text
                        and "certificate verify failed" in neg_text)
    functional_ok = runtime_ok and steps_ok and neg_rejected
    return {
        "runtime_ok": runtime_ok,
        "functional_ok": functional_ok,
        "failure_class": None if functional_ok else (
            "functional-failure" if runtime_ok else "runtime-failure"),
        "residual": "none" if functional_ok else (
            "functional-divergence" if runtime_ok else "runtime-failure"),
        "reason": None if functional_ok else (
            "the dovecot IMAPS session did not complete a verified TLS1.3 handshake"
            if not runtime_ok else
            "the IMAP greeting/login/append/select/fetch sequence did not complete"
            if not steps_ok else
            "a client trusting only the unrelated CA was not rejected"),
        "transcript": _transcript(("dovecot IMAPS greeting + LOGIN + APPEND + SELECT + FETCH", good),
                                  ("dovecot unrelated-ca (must fail)", neg),
                                  ("dovecot master log", {"exit_code": 0, "stderr": log})),
        "workload": ("dovecot: installed master + IMAPS listener with the fixture CA + greeting "
                     "+ LOGIN + APPEND + SELECT INBOX + FETCH payload + unrelated-CA reject"),
        "local_only": True,
    }


def _wl_rdkafka(ctx: dict) -> dict:
    """librdkafka's SSL transport against a local broker stub.

    The harness creates a loopback TLS listener with the fixture certificate and configures a
    producer with `security.protocol=ssl`, the fixture CA and `api.version.request=false` (so the
    first bytes after the handshake are a Metadata request). A passing run requires the stub to
    record the handshake and the request bytes, the client's own log to report `CONNECTED`/UP, and
    no `SSL handshake failed`. With `--negative` the client trusts only the unrelated CA and must
    fail certificate verification without ever reporting the connection up.
    """
    ap, d = ctx["authority_prefix"], ctx["workdir"]
    prog = str(ctx["program"])
    pki = _gen_pki(ap, d)
    common = ["--cert", str(pki["srv_crt"]), "--key", str(pki["srv_key"])]
    good = _run_captured([prog] + common + ["--ca", str(pki["ca_crt"])], cwd=d,
                         env=ctx["env"], timeout=120)
    neg = _run_captured([prog, "--negative"] + common + ["--ca", str(pki["other_crt"])],
                        cwd=d, env=ctx["env"], timeout=120)
    text = good["stdout"] + good["stderr"]
    neg_text = neg["stdout"] + neg["stderr"]
    runtime_ok = bool(good["ok"] and "handshake=ok" in text
                      and "metadata_request=ok" in text and "connected=up" in text
                      and "ssl_error=none" in text)
    neg_rejected = bool(neg["ok"] and "negative=rejected" in neg_text
                        and "ssl_error=certificate verify failed" in neg_text
                        and "connected=down" in neg_text)
    functional_ok = runtime_ok and neg_rejected
    return {
        "runtime_ok": runtime_ok,
        "functional_ok": functional_ok,
        "failure_class": None if functional_ok else (
            "functional-failure" if runtime_ok else "runtime-failure"),
        "residual": "none" if functional_ok else (
            "functional-divergence" if runtime_ok else "runtime-failure"),
        "reason": None if functional_ok else (
            "librdkafka did not complete the SSL transport handshake and report the connection up"
            if not runtime_ok else
            "a producer trusting only the unrelated CA was not rejected"),
        "transcript": _transcript(("librdkafka security.protocol=ssl + broker stub", good),
                                  ("librdkafka unrelated-ca (must fail)", neg)),
        "workload": ("librdkafka: producer with security.protocol=ssl + fixture-CA verify + "
                     "TLS handshake + Metadata request + connection UP + unrelated-CA reject"),
        "local_only": True,
    }


def _wl_fetchmail(ctx: dict) -> dict:
    """fetchmail's IMAPS retrieve path against a local IMAP stub, with a trust negative control.

    fetchmail's IMAP client wraps the mailbox socket with libssl (`ssl` in the rc), verifies the
    peer chain against the fixture CA through `sslcertfile`, and hands the fetched message to its
    MDA. The stub speaks the minimum IMAP4rev1 needed for a one-message retrieve; the MDA appends
    what it receives, so the message body is the functional assertion. A second poll whose trust
    store holds only the unrelated CA must fail certificate verification before any IMAP command.

    fetchmail's reader calls `SSL_peek` before every `SSL_read` (`socket.c:SockRead`). A subject
    whose `SSL_peek` is unimplemented therefore completes the TLS handshake and then aborts the
    poll; that is recorded as L6 with the blocker named, never masked as a fixture failure.
    """
    ap, d = ctx["authority_prefix"], ctx["workdir"]
    prog = str(ctx["program"])
    pki = _gen_pki(ap, d)
    body = b"L7-FETCHMAIL-BODY-MARKER"
    message = (b"From: l7@example.test\r\nTo: l7@example.test\r\nSubject: l7-fetchmail\r\n"
               b"Date: Tue, 21 Oct 2026 00:00:00 +0000\r\nMessage-ID: <l7@example.test>\r\n"
               b"\r\n" + body + b"\r\n")
    port = ctx["port"]
    events: list[str] = []
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(str(pki["srv_crt"]), str(pki["srv_key"]))
    stop = threading.Event()
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", port))
    listener.listen(4)
    listener.settimeout(0.5)

    def session(raw: socket.socket) -> None:
        """One IMAPS session: greeting, LOGIN, SELECT, FETCH, STORE, LOGOUT."""
        try:
            conn = tls.wrap_socket(raw, server_side=True)
        except (ssl.SSLError, OSError) as exc:
            events.append(f"tls=failed ({exc.__class__.__name__})")
            raw.close()
            return
        events.append(f"handshake={conn.version()}")
        stream = conn.makefile("rwb")

        def reply(line: bytes) -> None:
            stream.write(line)
            stream.flush()

        try:
            reply(b"* OK [CAPABILITY IMAP4rev1] l7 stub ready\r\n")
            while True:
                line = stream.readline()
                if not line:
                    break
                text = line.decode("utf-8", "replace").rstrip("\r\n")
                tag, _, rest = text.partition(" ")
                upper = rest.upper()
                events.append("imap: " + rest)
                if upper.startswith("CAPABILITY"):
                    reply(b"* CAPABILITY IMAP4rev1\r\n" + tag.encode() + b" OK done\r\n")
                elif upper.startswith("LOGIN"):
                    reply(tag.encode() + b" OK LOGIN done\r\n")
                elif upper.startswith(("SELECT", "EXAMINE")):
                    reply(b"* 1 EXISTS\r\n* 0 RECENT\r\n* FLAGS (\\Seen)\r\n"
                          + tag.encode() + b" OK [READ-WRITE] done\r\n")
                elif upper.startswith("SEARCH"):
                    reply(b"* SEARCH 1\r\n" + tag.encode() + b" OK done\r\n")
                elif upper.startswith(("FETCH", "UID FETCH")):
                    bits = rest.split(None, 2)
                    items = (bits[1] if len(bits) > 1 else "") + (
                        " " + bits[2] if len(bits) > 2 else "")
                    spec = items.upper()
                    if "RFC822.SIZE" in spec and "BODY" not in spec and "HEADER" not in spec:
                        reply(b"* 1 FETCH (RFC822.SIZE " + str(len(message)).encode() + b")\r\n")
                    else:
                        if "HEADER" in spec:
                            data = message.split(b"\r\n\r\n", 1)[0] + b"\r\n\r\n"
                            item = b"RFC822.HEADER"
                        elif "TEXT" in spec:
                            data = message.split(b"\r\n\r\n", 1)[1]
                            item = b"RFC822.TEXT"
                        else:
                            data, item = message, b"BODY[]"
                        if "UID" in spec and "BODY" not in spec:
                            item = b"UID 1 " + item
                        reply(b"* 1 FETCH (" + item + b" {" + str(len(data)).encode() + b"}\r\n"
                              + data + b")\r\n")
                    reply(tag.encode() + b" OK done\r\n")
                elif upper.startswith("LOGOUT"):
                    reply(b"* BYE bye\r\n" + tag.encode() + b" OK done\r\n")
                    break
                else:
                    reply(tag.encode() + b" OK done\r\n")
        except (ssl.SSLError, OSError):
            events.append("imap: session ended by peer")
        finally:
            try:
                stream.close()
            except OSError:
                pass

    def serve() -> None:
        while not stop.is_set():
            try:
                raw, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=session, args=(raw,), daemon=True).start()
        listener.close()

    def poll(tag: str, ca: Path) -> dict:
        """One fetchmail run: an appending MDA and a one-message IMAP poll over implicit TLS."""
        out = d / f"{tag}.mbox"
        mda = d / f"{tag}-mda.sh"
        mda.write_text("#!/bin/sh\nexec cat >> " + str(out) + "\n", encoding="utf-8")
        mda.chmod(0o755)
        rc = d / f"{tag}.rc"
        rc.write_text(
            "set no syslog\nset daemon 0\nset postmaster l7\n"
            f"poll 127.0.0.1 protocol IMAP port {port}\n"
            '  user "l7" password "secret"\n'
            f'  ssl sslcertck sslcertfile "{ca}"\n'
            f'  keep fetchall\n  mda "{mda}"\n', encoding="utf-8")
        rc.chmod(0o600)
        return _run_captured([prog, "-f", str(rc), "-v", "--nosyslog"], cwd=d, env=ctx["env"],
                             timeout=60)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        good = poll("good", pki["ca_crt"])
        neg = poll("neg", pki["other_crt"])
    finally:
        stop.set()
        try:
            listener.close()
        except OSError:
            pass
        thread.join(timeout=2)

    delivered = d / "good.mbox"
    rejected = d / "neg.mbox"
    text = good["stdout"] + good["stderr"]
    tls_line = next((ln for ln in text.splitlines() if "SSL/TLS: using protocol" in ln), "")
    neg_text = neg["stdout"] + neg["stderr"]
    runtime_ok = bool(tls_line)
    payload_ok = delivered.is_file() and body in delivered.read_bytes()
    neg_rejected = not rejected.is_file() or body not in rejected.read_bytes()
    functional_ok = runtime_ok and payload_ok and neg_rejected
    return {
        "runtime_ok": runtime_ok, "functional_ok": functional_ok,
        "failure_class": None if functional_ok else (
            "functional-failure" if runtime_ok else "runtime-failure"),
        "residual": "none" if functional_ok else (
            "functional-divergence" if runtime_ok else "runtime-failure"),
        "reason": None if functional_ok else (
            "fetchmail did not complete the TLS handshake with the local IMAPS stub"
            if not runtime_ok else
            "fetchmail completed the verified TLS session but delivered no message body: its "
            "IMAP reader calls SSL_peek before every SSL_read, and ssl_peek_internal returns -1 "
            "for every call (src/ssl/ssl_lib.rs), which fetchmail reports as a socket error"
            if not payload_ok else
            "the poll trusting only the unrelated CA was not rejected"),
        "transcript": _transcript(
            ("fetchmail IMAPS poll", {"exit_code": good["exit_code"], "stdout": tls_line}),
            ("imap stub", {"exit_code": 0, "stdout": "\n".join(events)}),
            ("fetchmail unrelated-ca poll (must fail)", {
                "exit_code": neg["exit_code"],
                "stderr": "\n".join(ln for ln in neg_text.splitlines()
                                     if "verification error" in ln
                                     or "OpenSSL reported" in ln
                                     or "SSL connection failed" in ln)})),
        "workload": ("fetchmail: IMAPS poll to a local IMAP/TLS stub + message-body delivery "
                     "through the MDA + unrelated-CA reject"),
        "note": ("fetchmail verifies the peer against the fixture CA through sslcertfile and "
                 "checks the SAN IP; the IMAP exchange runs over TLSv1.3 / TLSv1.2 as negotiated"),
        "local_only": True,
    }


def _wl_iperf3(ctx: dict) -> dict:
    """iperf3's completed test plus its OpenSSL SHA-256/authorization decision.

    iperf3 3.17.1's authenticated mode encrypts the salted credentials with OpenSSL's RSA. Its
    `encrypt_rsa_message` passes an output length of 0 to `EVP_PKEY_encrypt`, so every OpenSSL 3
    build answers "output buffer too small" and the token is empty; the authority and the candidate
    fail identically, which is recorded as a venue/upstream limitation rather than a divergence.
    The assertions are therefore (a) a completed server/client throughput test and (b) the part of
    the same libiperf auth code that does work on both subjects: `sha256()` over the salted
    credential and `check_authentication()`'s authorized-users decision, driven by a small harness
    linked against the family's rebuilt libiperf and the subject's libcrypto.
    """
    ap, d = ctx["authority_prefix"], ctx["workdir"]
    root, prefix = ctx["root"], ctx["prefix"]
    prog = str(ctx["program"])
    pki = _gen_pki(ap, d)
    pub = d / "auth-pub.pem"
    keygen = _ossl(ap, ["pkey", "-in", str(pki["srv_key"]), "-pubout", "-out", str(pub)],
                   timeout=60)
    if not keygen["ok"]:
        return _wl_fail([("openssl pkey -pubout", keygen)],
                        "the authentication public key could not be derived", "harness-failure", d)
    users = d / "users.csv"
    users.write_text("l7," + hashlib.sha256(b"{l7}secret").hexdigest() + "\n", encoding="utf-8")

    def test(extra_server: list[str], extra_client: list[str], env_extra: dict,
             tag: str, port: int | None = None) -> tuple[dict, dict]:
        """Run one server and its client; the server stays up for the client's real test."""
        port = port or _free_port()
        server, out, err = _spawn([prog, "-s", "-p", str(port), *extra_server], d,
                                  ctx["env"], d / f"{tag}-server.out",
                                  d / f"{tag}-server.err")
        try:
            if not _wait_tcp("127.0.0.1", port):
                return ({"exit_code": -1, "ok": False, "stdout": "", "stderr": ""},
                        {"exit_code": -1, "ok": False, "stdout": "", "stderr": ""})
            client = _run_captured([prog, "-c", "127.0.0.1", "-p", str(port), "-t", "1",
                                    *extra_client], cwd=d,
                                   env=dict(ctx["env"], **env_extra), timeout=90)
        finally:
            _stop(server)
            out.close()
            err.close()
        srv = {"exit_code": server.returncode, "ok": server.returncode == 0,
               "stdout": _read(d / f"{tag}-server.out"),
               "stderr": _read(d / f"{tag}-server.err")}
        return client, srv

    plain, plain_srv = test([], [], {}, "plain", ctx["port"])
    auth, auth_srv = test(
        [f"--rsa-private-key-path={pki['srv_key']}", f"--authorized-users-path={users}"],
        ["--username", "l7", "--rsa-public-key-path", str(pub)], {"IPERF3_PASSWORD": "secret"},
        "auth")

    harness = d / "l7-iperf3-harness"
    build = census._run(
        ["cc", str(REPO_ROOT / "forensics/tools/l7_iperf3.c"), "-o", str(harness), "-O2",
         "-Wall", "-Wextra", f"-I{prefix / 'include'}", f"-L{root / 'src/.libs'}",
         f"-L{prefix / 'lib'}", f"-Wl,-rpath,{root / 'src/.libs'}",
         f"-Wl,-rpath,{prefix / 'lib'}", "-liperf", "-lssl", "-lcrypto"],
        cwd=root, env=ctx["build_env"])
    if not build["ok"]:
        return _wl_fail([("cc l7_iperf3.c", build)],
                        f"the iperf3 digest/auth harness did not compile: "
                        f"{census._error_line(build)}", "harness-failure", d)
    digest = _run_captured([str(harness), str(users)], cwd=d, env=ctx["env"], timeout=60)

    plain_text = plain["stdout"] + plain["stderr"]
    plain_ok = bool(plain["ok"] and "iperf Done." in plain_text
                    and "Server listening on" in (plain_srv["stdout"] + plain_srv["stderr"]))
    digest_text = digest["stdout"] + digest["stderr"]
    expected = "65e9c904a7f6c8e173a48c57a67ac6e25cf991a79ff87b53591b3f1c26616dcf"
    digest_ok = bool(
        digest["ok"] and f"sha256={expected}" in digest_text
        and "auth_ok=accepted" in digest_text and "auth_wrong=rejected" in digest_text
        and "auth_stale=rejected" in digest_text)
    auth_text = auth["stdout"] + auth["stderr"]
    runtime_ok = plain_ok
    functional_ok = plain_ok and digest_ok
    return {
        "runtime_ok": runtime_ok, "functional_ok": functional_ok,
        "failure_class": None if functional_ok else (
            "functional-failure" if runtime_ok else "runtime-failure"),
        "residual": "none" if functional_ok else (
            "functional-divergence" if runtime_ok else "runtime-failure"),
        "reason": None if functional_ok else (
            "the local iperf3 server/client test did not complete" if not plain_ok else
            "libiperf's SHA-256/authorized-users decision did not match the fixture"),
        "transcript": _transcript(
            ("iperf3 test", {"exit_code": plain["exit_code"], "stdout": "\n".join(
                ln for ln in plain_text.splitlines()
                if "Connecting to host" in ln or "iperf Done." in ln)}),
            ("iperf3 server", {"exit_code": plain_srv["exit_code"], "stdout": "\n".join(
                ln for ln in (plain_srv["stdout"] + plain_srv["stderr"]).splitlines()
                if "Server listening on" in ln)}),
            ("iperf3 digest/auth harness", digest),
            ("iperf3 rsa-auth attempt (same upstream OpenSSL 3 failure on both subjects)", {
                "exit_code": auth["exit_code"], "stderr": "\n".join(
                    ln for ln in auth_text.splitlines()
                    if "output buffer too small" in ln or "authorization failed" in ln)})),
        "workload": ("iperf3: local server/client throughput test + libiperf SHA-256 of the "
                     "salted credential + authorized-users accept/reject/stale decisions"),
        "note": ("iperf3 3.17.1's RSA auth transport cannot complete with OpenSSL 3 (it passes a "
                 "zero output length to EVP_PKEY_encrypt; the authority fails identically), so "
                 "the digest and authorization decision are the asserted OpenSSL observable"),
        "local_only": True,
    }


def _wl_kmod(ctx: dict) -> dict:
    """kmod's module-signature path: libkmod parses an appended PKCS#7 with libcrypto.

    kmod 33 is built `--with-openssl` (its version banner reports `+LIBCRYPTO`), and `modinfo`
    reads a module's appended signature through `kmod_module_signature_info`. For the PKCS#7 id
    type that runs `d2i_PKCS7_bio`, `PKCS7_get_signer_info`, `X509_NAME_*`, `ASN1_INTEGER_to_BN`
    and `OBJ_obj2txt` from the subject's libcrypto, and reports the signer, key id, digest name and
    id type. The fixture is an ELF relocatable with a `.modinfo` section plus a PKCS#7 produced by
    the authority's `smime -sign`, laid out exactly as the kernel's sign-file does (module,
    signature, the 12-byte module_signature, the magic). The certificate serial is fixed so the
    reported key id is deterministic. A flipped signature byte must yield no signature metadata
    while the module's own `.modinfo` fields still parse.
    """
    ap, d = ctx["authority_prefix"], ctx["workdir"]
    prog = str(ctx["program"])
    source = d / "module.c"
    source.write_text(
        'const char __modinfo[] __attribute__((section(".modinfo"),used)) =\n'
        '    "license=GPL\\0description=kmod l7 fixture\\0";\n', encoding="utf-8")
    module = d / "module.ko"
    compiled = census._run(["cc", "-c", "-o", str(module), "-x", "c", str(source)], cwd=d,
                           env=ctx["build_env"])
    if not compiled["ok"]:
        return _wl_fail([("cc module.c", compiled)],
                        f"the kmod module fixture did not compile: {census._error_line(compiled)}",
                        "harness-failure", d)
    signer_key, signer_crt = d / "signer.key", d / "signer.crt"
    der, tampered = d / "signature.der", d / "tampered.ko"
    steps = [
        (["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(signer_key),
          "-out", str(signer_crt), "-days", "7", "-subj", "/CN=kmod-l7-signer",
          "-set_serial", "0x6b6d6f64"], "signer certificate"),
        (["smime", "-sign", "-nocerts", "-noattr", "-binary", "-md", "sha256", "-in",
          str(module), "-signer", str(signer_crt), "-inkey", str(signer_key), "-outform",
          "DER", "-out", str(der)], "module signature"),
    ]
    for argv, what in steps:
        res = _ossl(ap, argv, cwd=d, timeout=60)
        if not res["ok"]:
            return _wl_fail([(f"openssl {argv[0]}", res)],
                            f"generating the {what} failed: {census._error_line(res)}",
                            "harness-failure", d)

    module_bytes, der_bytes = module.read_bytes(), der.read_bytes()
    magic = b"~Module signature appended~\n"
    # struct module_signature: algo=RSA(1), hash=SHA256(4), id_type=PKCS7(2), signer/key id
    # carried by the PKCS#7, sig_len big-endian.
    header = struct.pack(">BBBBBBBBI", 1, 4, 2, 0, 0, 0, 0, 0, len(der_bytes))
    (d / "signed.ko").write_bytes(module_bytes + der_bytes + header + magic)
    flipped = bytes([der_bytes[0] ^ 0xFF]) + der_bytes[1:]
    tampered.write_bytes(module_bytes + flipped + header + magic)

    def field(name: str, path: Path) -> dict:
        return _run_captured([prog, "-F", name, str(path)], cwd=d, env=ctx["env"], timeout=60)

    description = field("description", module)
    signer = field("signer", d / "signed.ko")
    key_id = field("sig_key", d / "signed.ko")
    hash_algo = field("sig_hashalgo", d / "signed.ko")
    id_type = field("sig_id", d / "signed.ko")
    unsigned_signer = field("signer", module)
    tampered_signer = field("signer", tampered)

    def text(res: dict) -> str:
        return (res["stdout"] + res["stderr"]).strip()
    runtime_ok = bool(description["ok"] and text(description) == "kmod l7 fixture"
                      and unsigned_signer["ok"] and text(unsigned_signer) == "")
    functional_ok = bool(
        runtime_ok and text(signer) == "kmod-l7-signer" and text(key_id) == "6B:6D:6F:64"
        and text(hash_algo) == "sha256" and text(id_type) == "PKCS#7"
        and tampered_signer["ok"] and text(tampered_signer) == "")
    return {
        "runtime_ok": runtime_ok, "functional_ok": functional_ok,
        "failure_class": None if functional_ok else (
            "functional-failure" if runtime_ok else "runtime-failure"),
        "residual": "none" if functional_ok else (
            "functional-divergence" if runtime_ok else "runtime-failure"),
        "reason": None if functional_ok else (
            "modinfo did not read the fixture's .modinfo section" if not runtime_ok else
            "libkmod did not report the PKCS#7 signer/key-id/digest the fixture carries, or "
            "reported it for a corrupted signature"),
        "transcript": _transcript(
            ("modinfo -F description module.ko", description),
            ("modinfo -F signer module.ko (unsigned)", unsigned_signer),
            ("modinfo -F signer signed.ko", signer),
            ("modinfo -F sig_key signed.ko", key_id),
            ("modinfo -F sig_hashalgo signed.ko", hash_algo),
            ("modinfo -F sig_id signed.ko", id_type),
            ("modinfo -F signer tampered.ko (must report nothing)", tampered_signer)),
        "workload": ("kmod: modinfo parses a signed module fixture's appended PKCS#7 through "
                     "libcrypto (signer, key id, digest name, id type) + corrupted-signature "
                     "reject"),
        "note": ("kmod 33 is built --with-openssl and reports +LIBCRYPTO; libkmod's signature "
                 "path uses d2i_PKCS7/PKCS7_get_signer_info/X509_NAME/OBJ_obj2txt"),
        "local_only": True,
    }


def _wl_markers(ctx: dict, markers: list[str], workload: str, timeout: int = 120) -> dict:
    """Run a library-only family's harness and require every named observable marker."""
    d = ctx["workdir"]
    res = _run_captured([str(ctx["program"])], cwd=d, env=ctx["env"], timeout=timeout)
    text = res["stdout"] + res["stderr"]
    missing = [m for m in markers if m not in text]
    ok = bool(res["ok"] and not missing)
    return {
        "runtime_ok": ok, "functional_ok": ok,
        "failure_class": None if ok else "functional-failure",
        "residual": "none" if ok else "functional-divergence",
        "reason": None if ok else (
            f"the workload did not report {', '.join(missing)}"),
        "transcript": _transcript((workload, res)),
        "workload": workload,
        "local_only": True,
    }


def _wl_markers_argv(ctx: dict, argv: list[str], markers: list[str], workload: str,
                     timeout: int = 180) -> dict:
    """Run a harness with explicit argv and require every named observable marker."""
    d = ctx["workdir"]
    res = _run_captured([str(ctx["program"])] + argv, cwd=d, env=ctx["env"], timeout=timeout)
    text = res["stdout"] + res["stderr"]
    missing = [m for m in markers if m not in text]
    ok = bool(res["ok"] and not missing)
    return {
        "runtime_ok": ok, "functional_ok": ok,
        "failure_class": None if ok else "functional-failure",
        "residual": "none" if ok else "functional-divergence",
        "reason": None if ok else (
            f"the workload did not report {', '.join(missing)}"),
        "transcript": _transcript((workload, res)),
        "workload": workload,
        "local_only": True,
    }


def _wl_php(ctx: dict) -> dict:
    """PHP 8.2's openssl extension: PKCS#12, CMS sign/verify/encrypt/decrypt, chain check."""
    ap, d = ctx["authority_prefix"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    script = REPO_ROOT / "forensics" / "tools" / "l7_php_openssl.php"
    return _wl_markers_argv(ctx, [str(script), str(pki["srv_crt"]), str(pki["srv_key"]),
                                  str(pki["ca_crt"]), str(pki["other_crt"])], [
        "php_pkcs12_export=ok", "php_pkcs12_read=ok", "php_cms_sign=ok",
        "php_cms_verify=ok", "php_cms_encrypt=ok", "php_cms_decrypt=ok",
        "php_x509_checkpurpose=ok", "php_unrelated_ca=rejected"],
        "PHP 8.2 openssl ext: PKCS#12 roundtrip, CMS sign/verify/encrypt/decrypt and "
        "X.509 purpose check + unrelated-CA reject")


def _wl_ruby(ctx: dict) -> dict:
    """Ruby 3.1 ext/openssl: PKCS#12, PKCS#7, OCSP, store verify and raw Ed25519 keys."""
    ap, d = ctx["authority_prefix"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    script = REPO_ROOT / "forensics" / "tools" / "l7_ruby_openssl.rb"
    return _wl_markers_argv(ctx, [str(script), str(pki["srv_crt"]), str(pki["srv_key"]),
                                  str(pki["ca_crt"]), str(pki["other_crt"])], [
        "ruby_store_verify=ok", "ruby_pkcs12_export=ok", "ruby_pkcs12_read=ok",
        "ruby_pkcs7_sign=ok", "ruby_pkcs7_verify=ok", "ruby_ocsp_request=ok",
        "ruby_ed25519_sign=ok", "ruby_ed25519_verify=ok",
        "ruby_unrelated_ca_rejected=rejected"],
        "Ruby 3.1 ext/openssl: store verify, PKCS#12, PKCS#7, OCSP request, Ed25519 raw key "
        "+ unrelated-CA reject")


def _wl_perl(ctx: dict) -> dict:
    """Run one Perl XS module's admitted script through the embedded-Perl harness."""
    ap, d = ctx["authority_prefix"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    prog = PROGRAMS[ctx["family"]]
    script = REPO_ROOT / "forensics" / "tools" / str(prog["script"])
    argv = [str(script), str(pki["srv_crt"]), str(pki["srv_key"]),
            str(pki["ca_crt"]), str(pki["other_crt"])]
    body = "s33-perl-tls-fixture"
    stop = threading.Event()
    state: dict = {}
    thread = None
    if prog.get("tls_fixture"):
        argv = [str(script), str(pki["ca_crt"]), str(pki["other_crt"]),
                str(ctx["port"]), body]
        thread = _https_fixture(ctx["port"], pki, body, state, stop,
                               ciphers="ECDHE-RSA-AES128-GCM-SHA256",
                               max_version=ssl.TLSVersion.TLSv1_2)
    try:
        if thread is not None and not _wait_tcp("127.0.0.1", ctx["port"]):
            return _wl_fail([("tls fixture", {"exit_code": 0, "stdout": ""})],
                            "the local TLS fixture did not open its port",
                            "runtime-failure", d)
        return _wl_markers_argv(ctx, argv, list(prog["markers"]), str(prog["note"]))
    finally:
        stop.set()
        state.get("listener", socket.socket()).close()
        if thread is not None:
            thread.join(timeout=2)


def _wl_httplib(ctx: dict) -> dict:
    """cpp-httplib's header-only SSLServer/SSLClient over verified TLS."""
    ap, d = ctx["authority_prefix"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    res = _run_captured([str(ctx["program"]), str(pki["srv_crt"]), str(pki["srv_key"]),
                         str(pki["ca_crt"]), str(pki["other_crt"])],
                        cwd=d, env=ctx["env"], timeout=120)
    text = res["stdout"] + res["stderr"]
    ok = bool(res["ok"] and "S23-PASS" in text)
    return {
        "runtime_ok": ok, "functional_ok": ok,
        "failure_class": None if ok else "functional-failure",
        "residual": "none" if ok else "functional-divergence",
        "reason": None if ok else "the httplib client did not complete the verified fetch",
        "transcript": _transcript(("cpp-httplib TLS", res)),
        "workload": ("cpp-httplib 0.11.4: SSLServer/SSLClient verified fetch + "
                     "unrelated-CA reject"),
        "local_only": True,
    }


def _wl_jwt(ctx: dict) -> dict:
    """libjwt's RS256 and ES256 sign/verify/decode with a tampered-signature control."""
    return _wl_markers(ctx, [
        "rs256_sign=ok", "rs256_verify=ok", "rs256_claims=phase25-l7-jwt",
        "rs256_tamper=rejected", "es256_sign=ok", "es256_verify=ok",
        "es256_claims=phase25-l7-jwt", "es256_tamper=rejected",
    ], ("libjwt: RS256 + ES256 sign/verify/claims decode + tampered-signature reject"))


def _wl_libjose(ctx: dict) -> dict:
    """jose's ES256 JWS sign/verify with a wrong-key reject."""
    return _wl_markers(ctx, ["jws_sign=ok", "jws_verify=ok", "wrong_key=rejected"],
                       "jose: ES256 JWS sign/verify round trip + wrong-key reject")


def _wl_libzip(ctx: dict) -> dict:
    """libzip's AES-256 archive write/read with a wrong-password reject."""
    return _wl_markers(ctx, ["aes256_write=ok", "aes256_read=ok", "wrong_password=rejected"],
                       "libzip: AES-256 archive write/read + wrong-password reject")


def _wl_fido2(ctx: dict) -> dict:
    """libfido2's ES256 key round trip with an altered-signature reject."""
    return _wl_markers(ctx, ["es256_sign=ok", "es256_verify=ok",
                             "altered_signature=rejected"],
                       "libfido2: ES256 key round trip + sign/verify + altered-signature reject")


def _wl_aprutil(ctx: dict) -> dict:
    """apr-util's digest vector plus a real TLS handshake to a local server."""
    ap, d = ctx["authority_prefix"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    port = _free_port()
    server, out, err = _spawn(
        [str(_auth_ossl(ap)), "s_server", "-accept", str(port),
         "-cert", str(pki["srv_crt"]), "-key", str(pki["srv_key"]), "-www", "-quiet"],
        d, _auth_env(ap), d / "s_server.out", d / "s_server.err")
    try:
        if not _wait_tcp("127.0.0.1", port):
            return _wl_fail([("openssl s_server", {"exit_code": -1, "stdout": "",
                                                    "stderr": "the local server did not start"})],
                            "the local TLS server did not start", "harness-failure", d)
        res = _run_captured([str(ctx["program"]), "--ca", str(pki["ca_crt"]),
                             "--port", str(port)], cwd=d, env=ctx["env"], timeout=120)
    finally:
        _stop(server)
        out.close()
        err.close()
    srv_rc = server.returncode if server.returncode is not None else -15
    text = res["stdout"] + res["stderr"]
    markers = ["digest=ok", "mutated_digest=mismatch", "tls_handshake=ok", "peer_verify=ok"]
    missing = [m for m in markers if m not in text]
    ok = bool(res["ok"] and not missing)
    return {
        "runtime_ok": ok, "functional_ok": ok,
        "failure_class": None if ok else "functional-failure",
        "residual": "none" if ok else "functional-divergence",
        "reason": None if ok else f"the workload did not report {', '.join(missing)}",
        "transcript": _transcript(
            ("apr-util digest + TLS handshake", res),
            ("openssl s_server", {"exit_code": srv_rc,
                                  "stdout": _read(d / "s_server.err")})),
        "workload": ("apr-util: MD5 digest vector + mutated-digest mismatch + libssl TLS "
                     "handshake over apr_socket to a local server"),
        "local_only": True,
    }


def _plain_probe(port: int, payload: bytes, timeout: float = 5.0,
                 needle: str | None = None) -> dict:
    """Send bytes in the clear to a TLS-only port and record everything that comes back.

    Reads until the peer closes, the read times out, or `needle` is seen. `exit_code` is 0 when
    the peer answered and 1 when it did not: the transcript keeps the literal bytes, so a silent
    close, a TLS alert and a protocol reply are distinguishable.
    """
    text = ""
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(payload)
            while True:
                try:
                    chunk = sock.recv(1024)
                except OSError:
                    break
                if not chunk:
                    break
                text += chunk.decode("utf-8", "replace")
                if needle is not None and needle in text:
                    break
    except OSError as exc:
        text = f"<connect failed: {type(exc).__name__}>"
    if not text:
        text = "<no reply>"
    return {"exit_code": 0 if not text.startswith("<") else 1,
            "stdout": text, "stderr": ""}


def _ftp_client_stream(ap: Path, port: int, ca: Path, *, starttls: bool = True):
    """A line-oriented authority `s_client` for the two proftpd control/data connections."""
    argv = [str(_auth_ossl(ap)), "s_client", "-connect", f"127.0.0.1:{port}"]
    if starttls:
        argv += ["-starttls", "ftp"]
    argv += ["-CAfile", str(ca), "-servername", "127.0.0.1", "-quiet", "-ign_eof"]
    return subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, bufsize=1, env=_auth_env(ap))


def _read_until(proc, needle: str, timeout: float = 20.0) -> str:
    deadline = time.monotonic() + timeout
    text = ""
    while time.monotonic() < deadline:
        ready, _, _ = select.select([proc.stdout], [], [], 0.5)
        if not ready:
            continue
        line = proc.stdout.readline()
        if not line:
            break
        text += line
        if needle in text:
            break
    return text


def _ftp_list(ap: Path, pki: dict, port: int, user: str, passwd: str) -> dict:
    """LIST over a PROT P data connection: the control PASV reply names the data port, and a
    second authority `s_client` negotiates TLS on that port to read the listing."""
    ctl = _ftp_client_stream(ap, port, pki["ca_crt"])
    dat = None
    try:
        _read_until(ctl, "331")
        ctl.stdin.write(f"USER {user}\r\nPASS {passwd}\r\nPBSZ 0\r\nPROT P\r\nPASV\r\n")
        ctl.stdin.flush()
        pasv = _read_until(ctl, "227")
        match = re.search(r"\((?:[0-9]+,){4}([0-9]+),([0-9]+)\)", pasv)
        if match is None:
            return {"ok": False, "text": pasv}
        data_port = int(match.group(1)) * 256 + int(match.group(2))
        dat = _ftp_client_stream(ap, data_port, pki["ca_crt"], starttls=False)
        ctl.stdin.write("LIST\r\n")
        ctl.stdin.flush()
        listing = _read_until(dat, "fixture.txt", timeout=25)
        ctl.stdin.write("QUIT\r\n")
        ctl.stdin.flush()
        return {"ok": "fixture.txt" in listing, "text": listing}
    finally:
        for proc in (ctl, dat):
            if proc is not None:
                try:
                    proc.kill()
                    proc.wait(timeout=5)
                except (OSError, subprocess.TimeoutExpired):
                    pass


def _wl_memcached(ctx: dict) -> dict:
    """memcached's TLS listener: set/get over TLS, plaintext refusal, unrelated-CA reject."""
    ap, port, d = ctx["authority_prefix"], ctx["port"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    argv = [str(ctx["program"]), "-Z", "-l", "127.0.0.1", "-p", str(port), "-U", "0",
            "-u", "root", "-m", "64",
            "-o", f"ssl_chain_cert={pki['srv_crt']},ssl_key={pki['srv_key']}"]
    proc, of, ef = _spawn(argv, d, ctx["env"], d / "memcached.out", d / "memcached.err")
    try:
        if not _wait_tcp("127.0.0.1", port):
            return _wl_fail([("memcached", {"exit_code": 0,
                                             "stdout": _read(d / "memcached.err")})],
                            "memcached did not open its TLS port", "runtime-failure", d)
        good = _ossl(ap, ["s_client", "-connect", f"127.0.0.1:{port}", "-CAfile",
                          str(pki["ca_crt"]), "-servername", "127.0.0.1", "-quiet",
                          "-ign_eof"], timeout=25,
                     stdin_text="set l7 0 0 5\r\nvalue\r\nget l7\r\nquit\r\n")
        neg = _ossl(ap, ["s_client", "-connect", f"127.0.0.1:{port}", "-CAfile",
                         str(pki["other_crt"]), "-servername", "127.0.0.1",
                         "-verify_return_error", "-quiet", "-ign_eof"], timeout=25,
                    stdin_text="get l7\r\n")
        plain = _plain_probe(port, b"get l7\r\n")
    finally:
        _stop(proc)
        of.close()
        ef.close()
    text = good["stdout"] + good["stderr"]
    stored = "STORED" in text
    round_trip = "VALUE l7 0 5" in text and "\nvalue\n" in text
    neg_rejected = (neg["exit_code"] != 0
                    and "certificate verify failed" in (neg["stderr"] + neg["stdout"]))
    plain_refused = "VALUE l7" not in plain["stdout"] and "STORED" not in plain["stdout"]
    functional_ok = round_trip and stored and plain_refused and neg_rejected
    return {"runtime_ok": round_trip, "functional_ok": functional_ok,
            "failure_class": None if functional_ok else ("functional-failure" if round_trip
                                                         else "runtime-failure"),
            "residual": "none" if functional_ok else ("functional-divergence" if round_trip
                                                      else "runtime-failure"),
            "reason": None if functional_ok else
            ("the TLS set/get did not return the stored value" if not round_trip else
             "the set command did not answer STORED" if not stored else
             "plaintext on the TLS port was answered" if not plain_refused else
             "the unrelated CA was not rejected, so the server certificate does not verify"),
            "transcript": _transcript(
                ("authority s_client set/get over TLS", good),
                ("plaintext get on the TLS port (must not answer)", plain),
                ("authority s_client unrelated CA (must fail)", neg),
                ("memcached", {"exit_code": 0, "stdout": _read(d / "memcached.err")})),
            "workload": ("memcached: TLS1.3 set/get round trip + plaintext refusal + "
                         "unrelated-CA reject"),
            "local_only": True}


def _wl_icecast(ctx: dict) -> dict:
    """icecast's HTTPS listener: a verified GET of a fixture, and an unrelated-CA reject."""
    ap, port, d = ctx["authority_prefix"], ctx["port"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    root = ctx["root"]
    web, admin, logs = d / "web", d / "admin", d / "logs"
    for path in (web, admin, logs):
        path.mkdir(parents=True, exist_ok=True)
    for sub, dest in (("web", web), ("admin", admin)):
        for entry in sorted((root / sub).iterdir()):
            if entry.is_file():
                shutil.copy(entry, dest / entry.name)
    (web / "phase25.txt").write_text("phase25-l7-icecast-fixture\n", encoding="utf-8")
    # icecast refuses to run as root without a changeowner target, and the listener then writes
    # its logs as that user.
    _run_captured(["chown", "-R", "nobody:nogroup", str(logs)], timeout=20)
    _run_captured(["chmod", "755", str(d), str(web), str(admin)], timeout=20)
    conf = d / "icecast.xml"
    conf.write_text(f"""<icecast>
 <location>phase25-l7</location>
 <admin>root@127.0.0.1</admin>
 <hostname>127.0.0.1</hostname>
 <limits><clients>10</clients><sources>2</sources><workers>2</workers>
  <queue-size>524288</queue-size><client-timeout>30</client-timeout>
  <header-timeout>15</header-timeout><source-timeout>10</source-timeout></limits>
 <authentication><source-password>l7source</source-password>
  <relay-password>l7relay</relay-password><admin-user>admin</admin-user>
  <admin-password>l7admin</admin-password></authentication>
 <paths><logdir>{logs}</logdir><webroot>{web}</webroot><adminroot>{admin}</adminroot>
  <ssl-certificate>{pki['srv_pem']}</ssl-certificate>
  <alias source="/" dest="/status.xsl"/></paths>
 <listen-socket><port>{port}</port><bind-address>127.0.0.1</bind-address><ssl>1</ssl>
  </listen-socket>
 <security><chroot>0</chroot><changeowner><user>nobody</user><group>nogroup</group>
  </changeowner></security>
 <background>0</background>
</icecast>
""", encoding="utf-8")
    proc, of, ef = _spawn([str(ctx["program"]), "-c", str(conf)], d, ctx["env"],
                          d / "icecast.out", d / "icecast.err")
    try:
        if not _wait_tcp("127.0.0.1", port):
            return _wl_fail([("icecast", {"exit_code": 0, "stdout": _read(d / "icecast.err")})],
                            "icecast did not open its TLS port", "runtime-failure", d)
        good = _ossl(ap, ["s_client", "-connect", f"127.0.0.1:{port}", "-CAfile",
                          str(pki["ca_crt"]), "-servername", "127.0.0.1", "-quiet",
                          "-ign_eof"], timeout=25,
                     stdin_text="GET /phase25.txt HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
        neg = _ossl(ap, ["s_client", "-connect", f"127.0.0.1:{port}", "-CAfile",
                         str(pki["other_crt"]), "-servername", "127.0.0.1",
                         "-verify_return_error", "-quiet", "-ign_eof"], timeout=25,
                    stdin_text="GET /phase25.txt HTTP/1.0\r\n\r\n")
    finally:
        _stop(proc)
        of.close()
        ef.close()
    text = good["stdout"] + good["stderr"]
    served = "200" in text and "phase25-l7-icecast-fixture" in text
    neg_rejected = (neg["exit_code"] != 0
                    and "certificate verify failed" in (neg["stderr"] + neg["stdout"]))
    functional_ok = served and neg_rejected
    return {"runtime_ok": served, "functional_ok": functional_ok,
            "failure_class": None if functional_ok else ("functional-failure" if served
                                                         else "runtime-failure"),
            "residual": "none" if functional_ok else ("functional-divergence" if served
                                                      else "runtime-failure"),
            "reason": None if functional_ok else
            ("the verified HTTPS GET did not return 200 with the fixture" if not served else
             "the unrelated CA was not rejected, so the server certificate does not verify"),
            "transcript": _transcript(
                ("authority s_client GET over TLS", good),
                ("authority s_client unrelated CA (must fail)", neg),
                ("icecast", {"exit_code": 0, "stdout": _read(d / "icecast.err")})),
            "workload": ("icecast: verified HTTPS GET of a fixture (200 + bytes) + "
                         "unrelated-CA reject"),
            "local_only": True}


def _wl_proftpd(ctx: dict) -> dict:
    """proftpd's explicit FTPS: AUTH TLS login, PWD, LIST over PROT P, plaintext and CA rejects."""
    ap, port, d = ctx["authority_prefix"], ctx["port"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    user, passwd = _ftps_account(ctx)
    _run_captured(["chpasswd"], timeout=20, stdin_text=f"{user}:{passwd}\n")
    home = d / "ftphome"
    home.mkdir(parents=True, exist_ok=True)
    (home / "fixture.txt").write_text("phase25-l7-proftpd-fixture\n", encoding="utf-8")
    _run_captured(["chown", "-R", user, str(home)], timeout=20)
    _run_captured(["chmod", "755", str(d)], timeout=20)
    conf = d / "proftpd.conf"
    conf.write_text(f"""ServerType standalone
ServerName "phase25-l7-proftpd"
Port {port}
User nobody
Group nogroup
DefaultRoot {home}
RequireValidShell off
PidFile {d}/proftpd.pid
ScoreboardFile {d}/proftpd.score
WtmpLog off
TransferLog {d}/transfer.log
AuthOrder mod_auth_unix.c
TLSEngine on
TLSRequired on
TLSRSACertificateFile {pki['srv_crt']}
TLSRSACertificateKeyFile {pki['srv_key']}
TLSOptions NoSessionReuseRequired
TLSVerifyClient off
<Limit LOGIN>
  AllowAll
</Limit>
""", encoding="utf-8")
    proc, of, ef = _spawn([str(ctx["program"]), "-n", "-c", str(conf)], d, ctx["env"],
                          d / "proftpd.out", d / "proftpd.err")
    try:
        if not _wait_tcp("127.0.0.1", port):
            return _wl_fail([("proftpd", {"exit_code": 0, "stdout": _read(d / "proftpd.err")})],
                            "proftpd did not open its control port", "runtime-failure", d)
        session = _ossl(ap, ["s_client", "-connect", f"127.0.0.1:{port}", "-starttls", "ftp",
                             "-CAfile", str(pki["ca_crt"]), "-servername", "127.0.0.1",
                             "-brief", "-ign_eof"], timeout=30,
                        stdin_text=(f"USER {user}\r\nPASS {passwd}\r\nPBSZ 0\r\nPROT P\r\n"
                                    "PWD\r\nQUIT\r\n"))
        listing = _ftp_list(ap, pki, port, user, passwd)
        neg = _ossl(ap, ["s_client", "-connect", f"127.0.0.1:{port}", "-starttls", "ftp",
                         "-CAfile", str(pki["other_crt"]), "-servername", "127.0.0.1",
                         "-verify_return_error", "-brief", "-ign_eof"], timeout=25,
                    stdin_text="")
        plain = _plain_probe(port, f"USER {user}\r\nPASS {passwd}\r\n".encode(), needle="550")
    finally:
        _stop(proc)
        of.close()
        ef.close()
    replies = session["stdout"] + session["stderr"]
    login_ok = "230" in replies and "257" in replies
    list_ok = bool(listing["ok"])
    neg_rejected = (neg["exit_code"] != 0
                    and "certificate verify failed" in (neg["stderr"] + neg["stdout"]))
    plain_refused = "550" in plain["stdout"] and "230" not in plain["stdout"]
    functional_ok = login_ok and list_ok and plain_refused and neg_rejected
    return {"runtime_ok": login_ok, "functional_ok": functional_ok,
            "failure_class": None if functional_ok else ("functional-failure" if login_ok
                                                         else "runtime-failure"),
            "residual": "none" if functional_ok else ("functional-divergence" if login_ok
                                                      else "runtime-failure"),
            "reason": None if functional_ok else
            ("the authenticated explicit-TLS login/PWD did not complete" if not login_ok else
             "LIST over the PROT P data connection did not list the fixture" if not list_ok else
             "plaintext USER was not refused with 550" if not plain_refused else
             "the unrelated CA was not rejected, so the server certificate does not verify"),
            "transcript": _transcript(
                ("authority s_client -starttls ftp (USER/PASS/PBSZ/PROT/PWD)", session),
                ("authority s_client LIST over PROT P data connection",
                 {"exit_code": 0 if list_ok else 1, "stdout": listing["text"]}),
                ("plaintext USER on the FTPS port (must be refused)", plain),
                ("authority s_client unrelated CA (must fail)", neg),
                ("proftpd", {"exit_code": 0, "stdout": _read(d / "proftpd.err")})),
            "workload": ("proftpd: explicit FTPS login + PWD + LIST over PROT P + plaintext "
                         "refusal + unrelated-CA reject"),
            "local_only": True}


def _wl_mini_httpd(ctx: dict) -> dict:
    """mini_httpd's HTTPS listener: a verified GET of a fixture and an unrelated-CA reject."""
    ap, port, d = ctx["authority_prefix"], ctx["port"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    docroot = d / "docroot"
    docroot.mkdir(parents=True, exist_ok=True)
    (docroot / "phase25.txt").write_text("phase25-l7-mini-httpd-fixture\n", encoding="utf-8")
    _run_captured(["chmod", "755", str(d), str(docroot)], timeout=20)
    argv = [str(ctx["program"]), "-D", "-S", "-E", str(pki["srv_pem"]), "-d", str(docroot),
            "-p", str(port), "-u", "nobody", "-i", str(d / "mini.pid"),
            "-l", str(d / "mini.log")]
    proc, of, ef = _spawn(argv, d, ctx["env"], d / "mini.out", d / "mini.err")
    try:
        if not _wait_tcp("127.0.0.1", port):
            return _wl_fail([("mini_httpd", {"exit_code": 0, "stdout": _read(d / "mini.err")})],
                            "mini_httpd did not open its TLS port", "runtime-failure", d)
        good = _ossl(ap, ["s_client", "-connect", f"127.0.0.1:{port}", "-CAfile",
                          str(pki["ca_crt"]), "-servername", "127.0.0.1", "-quiet",
                          "-ign_eof"], timeout=25,
                     stdin_text="GET /phase25.txt HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
        neg = _ossl(ap, ["s_client", "-connect", f"127.0.0.1:{port}", "-CAfile",
                         str(pki["other_crt"]), "-servername", "127.0.0.1",
                         "-verify_return_error", "-quiet", "-ign_eof"], timeout=25,
                    stdin_text="GET /phase25.txt HTTP/1.0\r\n\r\n")
    finally:
        _stop(proc)
        of.close()
        ef.close()
    text = good["stdout"] + good["stderr"]
    served = "200" in text and "phase25-l7-mini-httpd-fixture" in text
    neg_rejected = (neg["exit_code"] != 0
                    and "certificate verify failed" in (neg["stderr"] + neg["stdout"]))
    functional_ok = served and neg_rejected
    return {"runtime_ok": served, "functional_ok": functional_ok,
            "failure_class": None if functional_ok else ("functional-failure" if served
                                                         else "runtime-failure"),
            "residual": "none" if functional_ok else ("functional-divergence" if served
                                                      else "runtime-failure"),
            "reason": None if functional_ok else
            ("the verified HTTPS GET did not return 200 with the fixture" if not served else
             "the unrelated CA was not rejected, so the server certificate does not verify"),
            "transcript": _transcript(
                ("authority s_client GET over TLS", good),
                ("authority s_client unrelated CA (must fail)", neg),
                ("mini_httpd", {"exit_code": 0,
                                "stdout": _read(d / "mini.err") + _read(d / "mini.log")})),
            "workload": ("mini_httpd: verified HTTPS GET of a fixture (200 + bytes) + "
                         "unrelated-CA reject"),
            "local_only": True}


def _wl_hitch(ctx: dict) -> dict:
    """hitch terminating TLS in front of a local backend, with an unrelated-CA reject.

    hitch 1.8 aborts in `sni_try_lookup` when a ClientHello carries SNI and no SNI table was built,
    so this workload (and its control) connects without `-servername`; the fixture certificate's
    SAN IP still makes the verification meaningful. A bare TCP probe also trips hitch's accept-loop
    assertion, so readiness is the log line, not a socket connect.
    """
    ap, front, d = ctx["authority_prefix"], ctx["port"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    backend = _free_port()
    payload = b"phase25-l7-hitch-backend\n"
    stop = threading.Event()
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", backend))
    listener.listen(8)
    listener.settimeout(0.5)

    def serve() -> None:
        while not stop.is_set():
            try:
                client, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with client:
                try:
                    client.settimeout(5.0)
                    client.recv(4096)
                    client.sendall(payload)
                except OSError:
                    pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    conf = d / "hitch.conf"
    conf.write_text(f"""frontend = {{
    host = "127.0.0.1"
    port = "{front}"
}}
backend = "[127.0.0.1]:{backend}"
pem-file = "{pki['srv_pem']}"
workers = 1
daemon = off
user = "nobody"
group = "nogroup"
""", encoding="utf-8")
    proc, of, ef = _spawn([str(ctx["program"]), "--config", str(conf), "-q"], d, ctx["env"],
                          d / "hitch.out", d / "hitch.err")
    try:
        if not _wait_log(d / "hitch.err", "Process 0 online"):
            return _wl_fail([("hitch", {"exit_code": 0, "stdout": _read(d / "hitch.err")})],
                            "hitch did not come online", "runtime-failure", d)
        good = _ossl(ap, ["s_client", "-connect", f"127.0.0.1:{front}", "-CAfile",
                          str(pki["ca_crt"]), "-quiet", "-ign_eof"], timeout=25,
                     stdin_text="GET / HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
        neg = _ossl(ap, ["s_client", "-connect", f"127.0.0.1:{front}", "-CAfile",
                         str(pki["other_crt"]), "-verify_return_error", "-quiet",
                         "-ign_eof"], timeout=25, stdin_text="GET / HTTP/1.0\r\n\r\n")
    finally:
        _stop(proc)
        stop.set()
        listener.close()
        thread.join(timeout=2)
        of.close()
        ef.close()
    text = good["stdout"] + good["stderr"]
    proxied = "phase25-l7-hitch-backend" in text
    neg_rejected = (neg["exit_code"] != 0
                    and "certificate verify failed" in (neg["stderr"] + neg["stdout"]))
    functional_ok = proxied and neg_rejected
    return {"runtime_ok": proxied, "functional_ok": functional_ok,
            "failure_class": None if functional_ok else ("functional-failure" if proxied
                                                         else "runtime-failure"),
            "residual": "none" if functional_ok else ("functional-divergence" if proxied
                                                      else "runtime-failure"),
            "reason": None if functional_ok else
            ("the TLS-terminated request did not return the backend payload" if not proxied else
             "the unrelated CA was not rejected, so the server certificate does not verify"),
            "transcript": _transcript(
                ("authority s_client GET through hitch to the backend", good),
                ("authority s_client unrelated CA (must fail)", neg),
                ("hitch", {"exit_code": 0, "stdout": _read(d / "hitch.err")})),
            "workload": ("hitch: verified TLS termination + proxied backend payload + "
                         "unrelated-CA reject"),
            "local_only": True}


def _tls_context(pki: dict, *, client: bool = False, ca: Path | None = None) -> ssl.SSLContext:
    """A client TLS context that verifies the peer against the fixture CA (or the control CA)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(cafile=str(ca or pki["ca_crt"]))
    if client:
        ctx.load_cert_chain(certfile=str(pki["client_crt"]), keyfile=str(pki["client_key"]))
    return ctx


def _radius_packet(code: int, ident: int, attributes: bytes = b"") -> bytes:
    return struct.pack("!BBH", code, ident, 20 + len(attributes)) + b"\x00" * 16 + attributes


def _radius_attribute(kind: int, value: bytes) -> bytes:
    return bytes((kind, len(value) + 2)) + value


def _radius_reply_message(reply: bytes) -> bytes:
    """The Reply-Message (type 18) value of a RADIUS reply, or b'' if it carries none."""
    if len(reply) < 20:
        return b""
    pos = 20
    while pos + 2 <= len(reply):
        kind, length = reply[pos], reply[pos + 1]
        if length < 2 or pos + length > len(reply):
            return b""
        if kind == 18:
            return reply[pos + 2:pos + length]
        pos += length
    return b""


def _udp_radius_backend(port: int, reply_body: bytes, state: dict,
                        stop: threading.Event) -> threading.Thread:
    """A loopback UDP RADIUS server: one Access-Request in, one Access-Accept out."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", port))
    sock.settimeout(0.5)

    def serve() -> None:
        while not stop.is_set():
            try:
                data, peer = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                return
            state["request"] = data
            attributes = _radius_attribute(18, reply_body)
            ident = data[1] if len(data) > 1 else 0
            request_authenticator = data[4:20] if len(data) >= 20 else b"\x00" * 16
            header = struct.pack("!BBH", 2, ident, 20 + len(attributes))
            # RFC 2865 Response Authenticator: MD5(Code+ID+Length+RequestAuth+Attributes+Secret).
            authenticator = hashlib.md5(header + request_authenticator + attributes
                                        + b"phase25secret").digest()
            try:
                sock.sendto(header + authenticator + attributes, peer)
            except OSError:
                return

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    state["socket"] = sock
    return thread


def _wl_radsecproxy(ctx: dict) -> dict:
    """radsecproxy's RadSec listener relaying one Access-Request to a local UDP backend.

    radsecproxy always verifies the peer certificate in both directions, so the workload's client
    presents a certificate from the fixture CA and the server's own certificate is issued by it.
    The negative control is a client that trusts only the unrelated CA: the handshake must fail.
    """
    ap, port, d = ctx["authority_prefix"], ctx["port"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    backend_port = _free_port()
    body = b"phase25-l7-radsecproxy-accept"
    state: dict = {}
    stop = threading.Event()
    thread = _udp_radius_backend(backend_port, body, state, stop)
    conf = d / "radsecproxy.conf"
    conf.write_text(f"""LogLevel 5
ListenTLS 127.0.0.1:{port}
tls default {{
    CACertificateFile {pki['ca_crt']}
    CertificateFile {pki['srv_crt']}
    CertificateKeyFile {pki['srv_key']}
}}
client 127.0.0.1 {{
    type tls
}}
server 127.0.0.1 {{
    type udp
    port {backend_port}
    secret phase25secret
}}
realm * {{
    server 127.0.0.1
}}
""", encoding="utf-8")
    proc, of, ef = _spawn([str(ctx["program"]), "-f", "-d", "5", "-c", str(conf)], d,
                          ctx["env"], d / "radsecproxy.out", d / "radsecproxy.err")
    good: dict = {"exit_code": -1, "stdout": "", "stderr": ""}
    neg: dict = {"exit_code": -1, "stdout": "", "stderr": ""}
    reply = b""
    try:
        if not _wait_tcp("127.0.0.1", port):
            return _wl_fail([("radsecproxy", {"exit_code": 0,
                                              "stdout": _read(d / "radsecproxy.err")})],
                            "radsecproxy did not open its RadSec port", "runtime-failure", d)
        request = _radius_packet(1, 7, _radius_attribute(1, b"phase25"))
        cert_argv = ["s_client", "-connect", f"127.0.0.1:{port}", "-cert",
                     str(pki["client_crt"]), "-key", str(pki["client_key"]),
                     "-servername", "127.0.0.1", "-quiet", "-ign_eof"]
        good = _run_captured_bytes([str(_auth_ossl(ap)), *cert_argv, "-CAfile",
                                    str(pki["ca_crt"])],
                                   env=_auth_env(ap), timeout=15, stdin_bytes=request)
        # The socket is held open by -ign_eof, so the client is stopped by the timeout; the
        # bytes it read before that are the evidence, and the reply must parse as one.
        reply = good.get("raw") or b""
        if reply:
            good["exit_code"] = 0
        neg = _run_captured_bytes([str(_auth_ossl(ap)), *cert_argv, "-CAfile",
                                   str(pki["other_crt"]), "-verify_return_error"],
                                  env=_auth_env(ap), timeout=15, stdin_bytes=request)
        neg["raw"] = b""
    finally:
        _stop(proc)
        stop.set()
        state.get("socket", socket.socket()).close()
        thread.join(timeout=2)
        of.close()
        ef.close()
    accepted = (len(reply) >= 20 and reply[0] == 2
                and body in _radius_reply_message(reply))
    relayed = bool(state.get("request"))
    neg_rejected = (neg["exit_code"] != 0
                    and "certificate verify failed" in (neg["stderr"] + neg["stdout"]))
    functional_ok = accepted and relayed and neg_rejected
    return {"runtime_ok": relayed, "functional_ok": functional_ok,
            "failure_class": None if functional_ok else
            ("functional-failure" if relayed else "runtime-failure"),
            "residual": "none" if functional_ok else
            ("functional-divergence" if relayed else "runtime-failure"),
            "reason": None if functional_ok else
            ("the RadSec client did not receive the Access-Accept with the fixture Reply-Message"
             if not accepted else
             ("the Access-Request was not relayed to the UDP backend" if not relayed else
              "the unrelated CA was not rejected, so the peer certificate does not verify")),
            "transcript": _transcript(
                ("RadSec client (fixture CA) Access-Accept", good),
                ("RadSec client (unrelated CA, must fail)", neg),
                ("radsecproxy", {"exit_code": 0,
                                  "stdout": _read(d / "radsecproxy.err")})),
            "workload": ("radsecproxy: RadSec Access-Request relayed to a local UDP backend, "
                         "Access-Accept with the fixture Reply-Message returned over TLS + "
                         "unrelated-CA reject"),
            "local_only": True}


def _znc_readline(tls, buf: dict) -> str:
    while b"\r\n" not in buf["data"]:
        chunk = tls.recv(4096)
        if not chunk:
            break
        buf["data"] += chunk
    line, _, rest = buf["data"].partition(b"\r\n")
    buf["data"] = rest
    return line.decode("utf-8", "ignore")


def _wl_znc(ctx: dict) -> dict:
    """ZNC's IRC-over-TLS listener: a verified client registers and a PING is answered."""
    ap, port, d = ctx["authority_prefix"], ctx["port"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    datadir = d / "znc-data"
    (datadir / "configs").mkdir(parents=True, exist_ok=True)
    (datadir / "configs" / "znc.conf").write_text(f"""Version = 1.10.3
AnonIPLimit = 10
MaxBufferSize = 500
ConnectDelay = 5
ServerThrottle = 30
SSLCertFile = {pki['srv_pem']}
<Listener listener0>
\tPort = +{port}
\tIPv4 = true
\tSSL = true
</Listener>
<User phase25>
\tPass = plain#phase25secret
\tAdmin = true
\tNick = phase25
	Buffer = 50
</User>
""", encoding="utf-8")
    (d / "znc.stdin").write_text("yes\n", encoding="utf-8")
    proc, of, ef = _spawn([str(ctx["program"]), "-f", "-D", "-r", "-d", str(datadir)], d,
                          ctx["env"], d / "znc.out", d / "znc.err",
                          # ZNC asks whether to run without a system module directory; the
                          # build tree is not installed, so answer the documented prompt.
                          stdin_path=d / "znc.stdin")
    good: dict = {"exit_code": -1, "stdout": "", "stderr": ""}
    neg: dict = {"exit_code": -1, "stdout": "", "stderr": ""}
    registered = False
    pong = False
    plain_registered = False
    try:
        # ZNC warns for 30 s before it starts when run as root (the court runs as root); the
        # listener is opened only after that countdown.
        if not _wait_tcp("127.0.0.1", port, timeout=50):
            return _wl_fail([("znc", {"exit_code": 0, "stdout": _read(d / "znc.err")})],
                            "znc did not open its TLS listener", "runtime-failure", d)
        try:
            raw = socket.create_connection(("127.0.0.1", port), timeout=10)
            with _tls_context(pki).wrap_socket(raw, server_hostname="127.0.0.1") as tls:
                tls.settimeout(10)
                tls.sendall(b"PASS phase25:phase25secret\r\nNICK phase25\r\n"
                            b"USER phase25 0 * :phase25\r\n")
                buf = {"data": b""}
                banner: list[str] = []
                for _ in range(20):
                    line = _znc_readline(tls, buf)
                    if not line:
                        break
                    banner.append(line)
                    if " 001 " in line:
                        registered = True
                        break
                tls.sendall(b"PING phase25-l7\r\n")
                for _ in range(10):
                    line = _znc_readline(tls, buf)
                    if not line:
                        break
                    banner.append(line)
                    if "PONG" in line and "phase25-l7" in line:
                        pong = True
                        break
                good = {"exit_code": 0 if (registered and pong) else 1,
                        "stdout": "\n".join(banner), "stderr": ""}
        except OSError as exc:
            good = {"exit_code": 1, "stdout": "", "stderr": f"znc client failed: {exc}"}
        # The negative control: a plaintext client on the TLS port must never register.
        try:
            raw = socket.create_connection(("127.0.0.1", port), timeout=10)
            raw.settimeout(5)
            raw.sendall(b"PASS phase25:phase25secret\r\nNICK phase25\r\n"
                        b"USER phase25 0 * :phase25\r\n")
            seen = ""
            for _ in range(8):
                chunk = raw.recv(4096)
                if not chunk:
                    break
                seen += chunk.decode("utf-8", "ignore")
                if " 001 " in seen:
                    plain_registered = True
                    break
            raw.close()
            neg = {"exit_code": 0 if plain_registered else 1, "stdout": seen, "stderr": ""}
        except OSError as exc:
            neg = {"exit_code": 1, "stdout": "", "stderr": f"plaintext connection failed: {exc}"}
    finally:
        _stop(proc)
        of.close()
        ef.close()
    functional_ok = registered and pong and not plain_registered
    runtime_ok = registered and pong
    return {"runtime_ok": runtime_ok, "functional_ok": functional_ok,
            "failure_class": None if functional_ok else
            ("functional-failure" if runtime_ok else "runtime-failure"),
            "residual": "none" if functional_ok else
            ("functional-divergence" if runtime_ok else "runtime-failure"),
            "reason": None if functional_ok else
            ("the TLS client did not complete registration (001) and PING/PONG" if not runtime_ok
             else "a plaintext client registered on the TLS listener"),
            "transcript": _transcript(
                ("znc TLS client registration + PING", good),
                ("znc plaintext client (must not register)", neg),
                ("znc", {"exit_code": 0, "stdout": _read(d / "znc.err")})),
            "workload": ("znc: IRC-over-TLS registration (001) + PING/PONG with the fixture CA + "
                         "plaintext-on-TLS-port reject"),
            "local_only": True}


def _smtp_starttls_stub(port: int, pki: dict, state: dict,
                        stop: threading.Event) -> threading.Thread:
    """A loopback SMTP submission server that upgrades to TLS on STARTTLS."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=str(pki["srv_pem"]))
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", port))
    listener.listen(4)
    listener.settimeout(0.5)

    def read_line(conn, buf: dict) -> str:
        while b"\r\n" not in buf["data"]:
            chunk = conn.recv(4096)
            if not chunk:
                break
            buf["data"] += chunk
        line, _, rest = buf["data"].partition(b"\r\n")
        buf["data"] = rest
        return line.decode("utf-8", "ignore")

    def serve() -> None:
        while not stop.is_set():
            try:
                conn, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with conn:
                try:
                    conn.settimeout(15)
                    buf = {"data": b""}
                    conn.sendall(b"220 phase25-l7 ESMTP\r\n")
                    while True:
                        line = read_line(conn, buf)
                        if not line:
                            break
                        verb = line.split(" ", 1)[0].upper()
                        if verb in ("EHLO", "HELO"):
                            conn.sendall(b"250-phase25-l7\r\n250-STARTTLS\r\n250 8BITMIME\r\n")
                        elif verb == "STARTTLS":
                            conn.sendall(b"220 Ready to start TLS\r\n")
                            conn = context.wrap_socket(conn, server_side=True)
                            buf = {"data": b""}
                            state["tls"] = True
                        elif verb in ("MAIL", "RCPT"):
                            conn.sendall(b"250 2.1.0 Ok\r\n")
                        elif verb == "DATA":
                            conn.sendall(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                            data = b""
                            while b"\r\n.\r\n" not in data:
                                chunk = conn.recv(4096)
                                if not chunk:
                                    break
                                data += chunk
                            state["message"] = data.split(b"\r\n.\r\n")[0]
                            conn.sendall(b"250 2.0.0 Ok: queued as phase25\r\n")
                        elif verb == "QUIT":
                            conn.sendall(b"221 2.0.0 Bye\r\n")
                            break
                        elif verb == "RSET":
                            conn.sendall(b"250 2.0.0 Ok\r\n")
                        else:
                            conn.sendall(b"250 2.0.0 Ok\r\n")
                except (OSError, ssl.SSLError):
                    continue

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    state["listener"] = listener
    return thread


def _wl_s_nail(ctx: dict) -> dict:
    """s-nail submitting a message over STARTTLS to a local stub, with a wrong-CA control."""
    ap, port, d = ctx["authority_prefix"], ctx["port"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    body = "phase25-l7-s-nail-body"
    state: dict = {}
    stop = threading.Event()
    thread = _smtp_starttls_stub(port, pki, state, stop)
    message = d / "message.txt"
    message.write_text(f"Subject: phase25-l7\n\n{body}\n", encoding="utf-8")

    def submit(ca: Path, tag: str) -> dict:
        argv = [str(ctx["program"]), "-S", f"smtp=127.0.0.1:{port}",
                "-S", "smtp-use-starttls", "-S", "smtp-auth=none",
                "-S", "ssl-verify=strict", "-S", f"ssl-ca-file={ca}",
                "-S", "from=phase25@example.invalid",
                "-S", "hostname=phase25.invalid",
                "-s", "phase25-l7", "phase25@example.invalid"]
        run_env = {k: v for k, v in ctx["env"].items()
                   if k.lower() not in ("http_proxy", "https_proxy", "all_proxy")}
        run_env["HOME"] = str(d)
        return _run_captured(argv, cwd=d, env=run_env, timeout=60,
                             stdin_text=message.read_text(encoding="utf-8"))

    try:
        if not _wait_tcp("127.0.0.1", port):
            return _wl_fail([("smtp stub", {"exit_code": 0, "stdout": ""})],
                            "the SMTP STARTTLS stub did not open its port",
                            "runtime-failure", d)
        good = submit(pki["ca_crt"], "good")
        accepted = state.get("message") or b""
        state.pop("message", None)
        neg = submit(pki["other_crt"], "neg")
        rejected_after_neg = state.get("message") is None
    finally:
        stop.set()
        state.get("listener", socket.socket()).close()
        thread.join(timeout=2)
    delivered = body.encode() in accepted
    neg_rejected = (neg["exit_code"] != 0 and rejected_after_neg
                    and "certificate" in (neg["stdout"] + neg["stderr"]).lower())
    functional_ok = good["exit_code"] == 0 and delivered and neg_rejected
    return {"runtime_ok": good["exit_code"] == 0, "functional_ok": functional_ok,
            "failure_class": None if functional_ok else
            ("functional-failure" if good["exit_code"] == 0 else "runtime-failure"),
            "residual": "none" if functional_ok else
            ("functional-divergence" if good["exit_code"] == 0 else "runtime-failure"),
            "reason": None if functional_ok else
            ("the message was not accepted (or not delivered) over STARTTLS" if not delivered
             else "the unrelated CA was not rejected"),
            "transcript": _transcript(
                ("s-nail submission over STARTTLS (fixture CA)", good),
                ("s-nail submission (unrelated CA, must fail)", neg)),
            "workload": ("s-nail: SMTP submission over STARTTLS to a local stub, message body "
                         "recorded + unrelated-CA reject"),
            "local_only": True}


def _https_fixture(port: int, pki: dict, body: str, state: dict,
                   stop: threading.Event, *, ciphers: str | None = None,
                   max_version=None) -> threading.Thread:
    """A minimal loopback HTTPS/1.0 server presenting the fixture server certificate."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=str(pki["srv_pem"]))
    if ciphers is not None:
        context.set_ciphers(ciphers)
    if max_version is not None:
        context.maximum_version = max_version
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", port))
    listener.listen(8)
    listener.settimeout(0.5)
    payload = body.encode()

    def serve() -> None:
        while not stop.is_set():
            try:
                conn, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                with context.wrap_socket(conn, server_side=True) as tls:
                    tls.settimeout(10)
                    request = b""
                    while b"\r\n\r\n" not in request:
                        chunk = tls.recv(4096)
                        if not chunk:
                            break
                        request += chunk
                    state["request"] = request
                    tls.sendall(b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n"
                                b"Content-Length: " + str(len(payload)).encode() + b"\r\n"
                                b"Connection: close\r\n\r\n" + payload)
            except (OSError, ssl.SSLError):
                continue

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    state["listener"] = listener
    return thread


def _wl_w3m(ctx: dict) -> dict:
    """w3m dumping a local HTTPS page with the fixture CA, and the wrong-CA control."""
    ap, port, d = ctx["authority_prefix"], ctx["port"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    body = "phase25-l7-w3m-fixture"
    state: dict = {}
    stop = threading.Event()
    thread = _https_fixture(port, pki, body, state, stop)
    url = f"https://127.0.0.1:{port}/phase25.txt"
    run_env = {k: v for k, v in ctx["env"].items()
               if k.lower() not in ("http_proxy", "https_proxy", "all_proxy")}
    try:
        if not _wait_tcp("127.0.0.1", port):
            return _wl_fail([("https fixture", {"exit_code": 0, "stdout": ""})],
                            "the local HTTPS fixture did not open its port",
                            "runtime-failure", d)
        good = _run_captured([str(ctx["program"]), "-dump", "-o",
                              f"ssl_ca_file={pki['ca_crt']}", "-o", "ssl_verify_server=1",
                              "-o", "http_proxy=", "-o", "https_proxy=", url],
                             cwd=d, env=run_env, timeout=45)
        neg = _run_captured([str(ctx["program"]), "-dump", "-o",
                             f"ssl_ca_file={pki['other_crt']}", "-o", "ssl_verify_server=1",
                             "-o", "http_proxy=", "-o", "https_proxy=", url],
                            cwd=d, env=run_env, timeout=45)
    finally:
        stop.set()
        state.get("listener", socket.socket()).close()
        thread.join(timeout=2)
    text = good["stdout"] + good["stderr"]
    rendered = good["exit_code"] == 0 and body in text
    # w3m asks before accepting an unverifiable certificate and, with no terminal on `-dump`,
    # rejects it while still exiting 0; the rejection text and the absent body are the evidence.
    neg_text = neg["stdout"] + neg["stderr"]
    neg_rejected = (body not in neg_text
                    and ("SSL session was rejected" in neg_text
                         or "unable to get local issuer certificate" in neg_text))
    functional_ok = rendered and neg_rejected
    return {"runtime_ok": rendered, "functional_ok": functional_ok,
            "failure_class": None if functional_ok else
            ("functional-failure" if rendered else "runtime-failure"),
            "residual": "none" if functional_ok else
            ("functional-divergence" if rendered else "runtime-failure"),
            "reason": None if functional_ok else
            ("the HTTPS page body was not rendered" if not rendered
             else "the unrelated CA was not rejected, so the server certificate does not verify"),
            "transcript": _transcript(
                ("w3m -dump https (fixture CA)", good),
                ("w3m -dump https (unrelated CA, must fail)", neg)),
            "workload": ("w3m: `-dump` of a local HTTPS page with the fixture CA renders its "
                         "body + unrelated-CA reject"),
            "local_only": True}


def _wl_axel(ctx: dict) -> dict:
    """axel's HTTPS download path: a fixture file fetched with the fixture CA, byte-compared.

    axel verifies both the chain and the hostname (`SSL_CTX_set_default_verify_paths` honours
    `SSL_CERT_FILE`), so the fixture CA is the positive run's trust anchor and the unrelated CA
    must fail before any bytes are written.
    """
    ap, d, port = ctx["authority_prefix"], ctx["workdir"], ctx["port"]
    pki = _gen_pki(ap, d)
    body = b"phase25-axel-fixture-" + b"A" * 4096 + b"\n"
    out = d / "fixture.bin"

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 -- the base class names the verb
            if self.path != "/probe.bin":
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            self.wfile.flush()

        def log_message(self, *args: object) -> None:
            return

    server = http.server.HTTPServer(("127.0.0.1", port), Handler)
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.load_cert_chain(str(pki["srv_crt"]), str(pki["srv_key"]))
    server.socket = sctx.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"https://127.0.0.1:{port}/probe.bin"
    try:
        good = _run_captured([str(ctx["program"]), "-n", "1", "-o", str(out), url], cwd=d,
                             env=dict(ctx["env"], SSL_CERT_FILE=str(pki["ca_crt"])), timeout=60)
        good_bytes = out.read_bytes() if out.is_file() else b""
        out.unlink(missing_ok=True)
        neg = _run_captured([str(ctx["program"]), "-n", "1", "-o", str(out), url], cwd=d,
                            env=dict(ctx["env"], SSL_CERT_FILE=str(pki["other_crt"])), timeout=60)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    good_text = good["stdout"] + good["stderr"]
    neg_text = neg["stdout"] + neg["stderr"]
    downloaded = bool(good["ok"] and good_bytes == body and
                      "certificate verify failed" not in good_text)
    neg_rejected = (not neg["ok"] and not out.exists()
                    and "certificate verify failed" in neg_text)
    functional_ok = downloaded and neg_rejected
    return {
        "runtime_ok": downloaded,
        "functional_ok": functional_ok,
        "failure_class": None if functional_ok else (
            "functional-failure" if downloaded else "runtime-failure"),
        "residual": "none" if functional_ok else (
            "functional-divergence" if downloaded else "runtime-failure"),
        "reason": None if functional_ok else (
            "axel did not fetch the fixture file byte-for-byte" if not downloaded else
            "the unrelated CA was not rejected, so the download is not certificate-verified"),
        "transcript": _transcript(("axel download (fixture CA)", good),
                                  ("axel download (unrelated CA, must fail)", neg)),
        "workload": ("axel: HTTPS download of a local fixture with the fixture CA + byte match + "
                     "unrelated-CA reject"),
        "local_only": True,
    }


def _wl_apache2_utils(ctx: dict) -> dict:
    """apache2-utils' `ab`: a completed HTTPS benchmark and a plaintext-listener control.

    `ab` does not verify the peer certificate, so the negative control is a plaintext listener on
    the target port: a run that actually speaks TLS must fail its handshake on every request (and
    transfer zero bytes), which a run that silently fell back to cleartext could not do.
    """
    ap, d, port = ctx["authority_prefix"], ctx["workdir"], ctx["port"]
    pki = _gen_pki(ap, d)
    requests = 20
    plain_port = _free_port()
    srv, of, ef = _spawn([str(_auth_ossl(ap)), "s_server", "-accept", str(port), "-cert",
                          str(pki["srv_crt"]), "-key", str(pki["srv_key"]), "-www", "-quiet"],
                         d, _auth_env(ap), d / "srv.out", d / "srv.err")

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 -- the base class names the verb
            payload = b"phase25-ab-plaintext\n"
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args: object) -> None:
            return

    plain = http.server.HTTPServer(("127.0.0.1", plain_port), Handler)
    plain_thread = threading.Thread(target=plain.serve_forever, daemon=True)
    plain_thread.start()
    try:
        if not _wait_tcp("127.0.0.1", port):
            return _wl_fail([("openssl s_server", {"exit_code": 0,
                                                    "stdout": _read(d / "srv.err")})],
                            "the local TLS server did not open its port", "runtime-failure", d)
        good = _run_captured([str(ctx["program"]), "-n", str(requests), "-c", "1",
                              f"https://127.0.0.1:{port}/"], cwd=d, env=ctx["env"], timeout=90)
        neg = _run_captured([str(ctx["program"]), "-n", "5", "-c", "1",
                             f"https://127.0.0.1:{plain_port}/"], cwd=d, env=ctx["env"],
                            timeout=60)
    finally:
        _stop(srv)
        of.close()
        ef.close()
        plain.shutdown()
        plain.server_close()
        plain_thread.join(timeout=5)

    good_text = good["stdout"] + good["stderr"]
    neg_text = neg["stdout"] + neg["stderr"]
    completed = bool(good["ok"] and
                     re.search(rf"Complete requests:\s+{requests}\b", good_text) is not None and
                     re.search(r"Failed requests:\s+0\b", good_text) is not None and
                     "SSL handshake failed" not in good_text)
    neg_rejected = (neg_text.count("SSL handshake failed") == 5 and
                    re.search(r"Document Length:\s+0 bytes", neg_text) is not None)
    functional_ok = completed and neg_rejected
    return {
        "runtime_ok": completed,
        "functional_ok": functional_ok,
        "failure_class": None if functional_ok else (
            "functional-failure" if completed else "runtime-failure"),
        "residual": "none" if functional_ok else (
            "functional-divergence" if completed else "runtime-failure"),
        "reason": None if functional_ok else (
            "ab did not complete its HTTPS request count without failures" if not completed else
            "ab did not report a TLS handshake failure against the plaintext listener"),
        "transcript": _transcript((f"ab -n {requests} https (fixture TLS server)", good),
                                  ("ab https against a plaintext listener (must fail)", neg)),
        "workload": (f"apache2-utils ab: {requests} completed HTTPS requests, 0 failed, and a "
                     "plaintext listener rejected by the TLS handshake"),
        "local_only": True,
    }


def _wl_osslsigncode(ctx: dict) -> dict:
    """osslsigncode's Authenticode path: sign a pristine PE, verify it, reject a modified one.

    The PE fixture is the release's own `tests/files/unsigned.exe`; the signing certificate is a
    local code-signing certificate from the fixture PKI. A byte in the middle of the file (inside a
    section, not a header or the certificate table) makes the Authenticode digest disagree, which
    `verify` must report.
    """
    ap, d = ctx["authority_prefix"], ctx["workdir"]
    prog = str(ctx["program"])
    unsigned = ctx["root"] / "tests" / "files" / "unsigned.exe"
    if not unsigned.is_file():
        return _wl_fail([("osslsigncode", {"exit_code": 0, "stdout": ""})],
                        "the release's tests/files/unsigned.exe fixture is absent",
                        "runtime-failure", d)
    key, crt = d / "codesign.key", d / "codesign.crt"
    gen = _ossl(ap, ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
                     "-out", str(crt), "-days", "7", "-subj", "/CN=phase25-code-signing",
                     "-addext", "basicConstraints=critical,CA:FALSE",
                     "-addext", "extendedKeyUsage=codeSigning"], timeout=60)
    if not gen["ok"]:
        return _wl_fail([("openssl req", gen)], "generating the code-signing certificate failed",
                        "runtime-failure", d)
    signed, tampered = d / "signed.exe", d / "tampered.exe"
    sign = _run_captured([prog, "sign", "-certs", str(crt), "-key", str(key), "-h", "sha256",
                          "-in", str(unsigned), "-out", str(signed)], cwd=d, env=ctx["env"],
                         timeout=120)
    verify = _run_captured([prog, "verify", "-CAfile", str(crt), "-in", str(signed)], cwd=d,
                           env=ctx["env"], timeout=120)
    data = bytearray(signed.read_bytes()) if signed.is_file() else bytearray()
    if len(data) > 0x400:
        data[len(data) // 2] ^= 0xFF
        tampered.write_bytes(data)
    neg = _run_captured([prog, "verify", "-CAfile", str(crt), "-in", str(tampered)], cwd=d,
                        env=ctx["env"], timeout=120)

    signed_ok = bool(sign["ok"] and signed.is_file() and
                     verify["ok"] and "Succeeded" in (verify["stdout"] + verify["stderr"]))
    neg_text = neg["stdout"] + neg["stderr"]
    neg_rejected = (not neg["ok"] and ("MISMATCH" in neg_text or "Failed" in neg_text))
    functional_ok = signed_ok and neg_rejected
    return {
        "runtime_ok": signed_ok,
        "functional_ok": functional_ok,
        "failure_class": None if functional_ok else (
            "functional-failure" if signed_ok else "runtime-failure"),
        "residual": "none" if functional_ok else (
            "functional-divergence" if signed_ok else "runtime-failure"),
        "reason": None if functional_ok else (
            "osslsigncode did not sign and verify the pristine PE" if not signed_ok else
            "the modified PE was not rejected by signature verification"),
        "transcript": _transcript(("osslsigncode sign", sign),
                                  ("osslsigncode verify (signed PE)", verify),
                                  ("osslsigncode verify (modified PE, must fail)", neg)),
        "workload": ("osslsigncode: Authenticode sign of a pristine PE + verified signature + "
                     "digest mismatch on a modified PE"),
        "local_only": True,
    }


def _wl_u_boot_tools(ctx: dict) -> dict:
    """u-boot-tools' FIT signing: mkimage signs, fit_check_sign verifies, a tamper is rejected."""
    ap, d = ctx["authority_prefix"], ctx["workdir"]
    mkimage = str(ctx["program"])
    fit_check = ctx["program"].parent / "fit_check_sign"
    if not fit_check.is_file():
        return _wl_fail([("mkimage", {"exit_code": 0, "stdout": ""})],
                        "the host-tools build produced no fit_check_sign", "runtime-failure", d)
    payload = b"phase25-fit-payload\n"
    (d / "payload.bin").write_bytes(payload)
    (d / "image.its").write_text(
        "/dts-v1/;\n"
        "/ {\n"
        "\tdescription = \"phase25 L7 FIT\";\n"
        "\t#address-cells = <1>;\n"
        "\timages {\n"
        "\t\tpayload {\n"
        "\t\t\tdescription = \"phase25 payload\";\n"
        "\t\t\tdata = /incbin/(\"payload.bin\");\n"
        "\t\t\ttype = \"kernel\";\n"
        "\t\t\tarch = \"x86\";\n"
        "\t\t\tos = \"linux\";\n"
        "\t\t\tcompression = \"none\";\n"
        "\t\t\tload = <0x100000>;\n"
        "\t\t\tentry = <0x100000>;\n"
        "\t\t\thash-1 { algo = \"sha256\"; };\n"
        "\t\t};\n"
        "\t};\n"
        "\tconfigurations {\n"
        "\t\tdefault = \"conf-1\";\n"
        "\t\tconf-1 {\n"
        "\t\t\tkernel = \"payload\";\n"
        "\t\t\tsignature-1 {\n"
        "\t\t\t\talgo = \"sha256,rsa2048\";\n"
        "\t\t\t\tkey-name-hint = \"dev\";\n"
        "\t\t\t\tsign-images = \"kernel\";\n"
        "\t\t\t};\n"
        "\t\t};\n"
        "\t};\n"
        "};\n", encoding="utf-8")
    keys = d / "keys"
    keys.mkdir(exist_ok=True)
    gen = _ossl(ap, ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout",
                     str(keys / "dev.key"), "-out", str(keys / "dev.crt"), "-days", "7",
                     "-subj", "/CN=phase25 FIT key"], timeout=60)
    if not gen["ok"]:
        return _wl_fail([("openssl req", gen)], "generating the FIT key failed",
                        "runtime-failure", d)
    (d / "keys.dts").write_text("/dts-v1/;\n/ {\n};\n", encoding="utf-8")
    dtc = _run_captured(["dtc", "-I", "dts", "-O", "dtb", "-o", str(d / "keys.dtb"),
                         str(d / "keys.dts")], cwd=d, env=ctx["env"], timeout=60)
    itb, tampered = d / "image.itb", d / "tampered.itb"
    made = _run_captured([mkimage, "-f", str(d / "image.its"), str(itb)], cwd=d,
                         env=ctx["env"], timeout=120)
    signed = _run_captured([mkimage, "-F", "-k", str(keys), "-K", str(d / "keys.dtb"),
                            str(itb)], cwd=d, env=ctx["env"], timeout=120)
    verify = _run_captured([str(fit_check), "-f", str(itb), "-k", str(d / "keys.dtb")],
                           cwd=d, env=ctx["env"], timeout=120)
    data = bytearray(itb.read_bytes()) if itb.is_file() else bytearray()
    index = data.find(payload.strip())
    if index > 0:
        data[index] ^= 0x01
        tampered.write_bytes(data)
    neg = _run_captured([str(fit_check), "-f", str(tampered), "-k", str(d / "keys.dtb")],
                        cwd=d, env=ctx["env"], timeout=120)

    verify_text = verify["stdout"] + verify["stderr"]
    signed_ok = bool(dtc["ok"] and made["ok"] and signed["ok"] and itb.is_file() and
                     verify["ok"] and "Signature check OK" in verify_text)
    neg_text = neg["stdout"] + neg["stderr"]
    neg_rejected = (not neg["ok"] and "Signature check bad" in neg_text)
    functional_ok = signed_ok and neg_rejected
    return {
        "runtime_ok": signed_ok,
        "functional_ok": functional_ok,
        "failure_class": None if functional_ok else (
            "functional-failure" if signed_ok else "runtime-failure"),
        "residual": "none" if functional_ok else (
            "functional-divergence" if signed_ok else "runtime-failure"),
        "reason": None if functional_ok else (
            "mkimage did not sign a FIT image that fit_check_sign accepts" if not signed_ok else
            "the tampered FIT payload was not rejected by signature verification"),
        "transcript": _transcript(("dtc (public-key dtb)", dtc),
                                  ("mkimage -f (FIT)", made),
                                  ("mkimage -F (sign)", signed),
                                  ("fit_check_sign (signed)", verify),
                                  ("fit_check_sign (tampered, must fail)", neg)),
        "workload": ("u-boot-tools: RSA-signed FIT image (mkimage -F) verified by fit_check_sign "
                     "+ tampered payload rejected"),
        "local_only": True,
    }


def _wl_sslsplit(ctx: dict) -> dict:
    """sslsplit's TLS interception: forge with the fixture CA, forward to a local TLS backend."""
    ap, d, port = ctx["authority_prefix"], ctx["workdir"], ctx["port"]
    pki = _gen_pki(ap, d)
    body = b"phase25-sslsplit-backend-payload\n"
    backend_port = 443
    probe = socket.socket()
    try:
        probe.bind(("127.0.0.1", backend_port))
    except OSError:
        probe.close()
        return _wl_fail([("sslsplit", {"exit_code": 0, "stdout": ""})],
                        f"the local TLS backend port {backend_port} is not free",
                        "runtime-failure", d)
    probe.close()

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 -- the base class names the verb
            if self.path != "/probe":
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            self.wfile.flush()

        def log_message(self, *args: object) -> None:
            return

    backend = http.server.HTTPServer(("127.0.0.1", backend_port), Handler)
    bctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    bctx.load_cert_chain(str(pki["srv_crt"]), str(pki["srv_key"]))
    backend.socket = bctx.wrap_socket(backend.socket, server_side=True)
    thread = threading.Thread(target=backend.serve_forever, daemon=True)
    thread.start()
    conn_log = d / "connections.log"
    argv = [str(ctx["program"]), "-D", "-p", str(d / "sslsplit.pid"), "-l", str(conn_log),
            "-c", str(pki["ca_crt"]), "-k", str(pki["ca_key"])]
    if os.geteuid() == 0:
        argv += ["-u", "root"]
    argv += ["https", "127.0.0.1", str(port), "127.0.0.1", str(backend_port)]
    srv, of, ef = _spawn(argv, d, ctx["env"], d / "sslsplit.out", d / "sslsplit.err")
    request = "GET /probe HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n"
    try:
        if not _wait_tcp("127.0.0.1", port):
            return _wl_fail([("sslsplit", {"exit_code": 0, "stdout": _read(d / "sslsplit.err")})],
                            "sslsplit did not open its listening port", "runtime-failure", d)
        good = _s_client(ap, port, pki["ca_crt"], ["-quiet", "-verify_return_error"],
                         stdin_text=request, timeout=45)
        neg = _s_client(ap, port, pki["other_crt"],
                        ["-quiet", "-verify_return_error"], stdin_text=request, timeout=45)
    finally:
        _stop(srv)
        of.close()
        ef.close()
        backend.shutdown()
        backend.server_close()
        thread.join(timeout=5)

    good_text = good["stdout"] + good["stderr"]
    log_text = _read(conn_log)
    forwarded = bool(body.decode().strip() in good_text and "200 OK" in good_text and
                     re.search(r"GET /probe 200", log_text) is not None)
    neg_text = neg["stdout"] + neg["stderr"]
    neg_rejected = (body.decode().strip() not in neg_text
                    and "certificate verify failed" in neg_text)
    functional_ok = forwarded and neg_rejected
    return {
        "runtime_ok": forwarded,
        "functional_ok": functional_ok,
        "failure_class": None if functional_ok else (
            "functional-failure" if forwarded else "runtime-failure"),
        "residual": "none" if functional_ok else (
            "functional-divergence" if forwarded else "runtime-failure"),
        "reason": None if functional_ok else (
            "the intercepted request did not reach the TLS backend and return its body"
            if not forwarded else
            "the unrelated CA was not rejected, so the forged certificate does not verify"),
        "transcript": _transcript(("authority s_client through sslsplit", good),
                                  ("authority s_client unrelated CA (must fail)", neg),
                                  ("sslsplit connection log", {"exit_code": 0,
                                                               "stdout": log_text})),
        "workload": ("sslsplit: TLS interception with a fixture-CA forged certificate, "
                     "forwarded GET /probe 200 and body returned + unrelated-CA reject"),
        "local_only": True,
    }


def _wl_opendkim(ctx: dict) -> dict:
    """libopendkim's DKIM path: sign a message, verify it, reject a modified body."""
    ap, d = ctx["authority_prefix"], ctx["workdir"]
    prog = str(ctx["program"])
    key, pub = d / "dev.key", d / "dev.pub"
    gen = _ossl(ap, ["genrsa", "-out", str(key), "2048"], timeout=60)
    exported = _ossl(ap, ["rsa", "-in", str(key), "-pubout", "-out", str(pub)], timeout=60)
    if not gen["ok"] or not exported["ok"]:
        return _wl_fail([("openssl genrsa", gen), ("openssl rsa", exported)],
                        "generating the DKIM key failed", "runtime-failure", d)
    record = d / "dev.txt"
    b64 = "".join(line for line in _read(pub).splitlines() if not line.startswith("---"))
    record.write_text("v=DKIM1; k=rsa; p=" + b64, encoding="utf-8")
    msg, signed, tampered = d / "msg.txt", d / "signed.txt", d / "tampered.txt"
    message = ("From: a@example.test\r\nTo: b@example.test\r\nSubject: phase25 opendkim\r\n"
               "Date: Thu, 01 Jan 2026 00:00:00 +0000\r\nMessage-ID: <l7@example.test>\r\n"
               "\r\nphase25-opendkim-body\r\n")
    msg.write_bytes(message.encode("utf-8"))
    sign = _run_captured([prog, "sign", str(msg), str(key), "example.test", "l7sel",
                          str(signed)], cwd=d, env=ctx["env"], timeout=120)
    verify = _run_captured([prog, "verify", str(signed), str(record)], cwd=d, env=ctx["env"],
                           timeout=120)
    data = signed.read_bytes() if signed.is_file() else b""
    index = data.find(b"phase25-opendkim-body")
    if index > 0:
        altered = bytearray(data)
        altered[index] = ord("P")
        tampered.write_bytes(altered)
    neg = _run_captured([prog, "verify", str(tampered), str(record)], cwd=d, env=ctx["env"],
                        timeout=120)

    signed_ok = bool(sign["ok"] and data.startswith(b"DKIM-Signature:") and
                     verify["ok"] and "verify=ok" in verify["stdout"])
    neg_text = neg["stdout"] + neg["stderr"]
    neg_rejected = (not neg["ok"] and
                    ("verify=fail" in neg["stdout"] or "Bad signature" in neg_text))
    functional_ok = signed_ok and neg_rejected
    return {
        "runtime_ok": signed_ok,
        "functional_ok": functional_ok,
        "failure_class": None if functional_ok else (
            "functional-failure" if signed_ok else "runtime-failure"),
        "residual": "none" if functional_ok else (
            "functional-divergence" if signed_ok else "runtime-failure"),
        "reason": None if functional_ok else (
            "libopendkim did not sign and verify the message" if not signed_ok else
            "the modified message body was not rejected by DKIM verification"),
        "transcript": _transcript(("opendkim harness sign", sign),
                                  ("opendkim harness verify (signed)", verify),
                                  ("opendkim harness verify (modified body, must fail)", neg)),
        "workload": ("opendkim: libopendkim signs a message with RSA-SHA256 and verifies it via "
                     "its key-lookup callback + modified-body reject"),
        "local_only": True,
    }


def _aux_root(ctx: dict) -> Path:
    return ctx["root"].parents[1] / "aux" / "root"


def _wl_nmap(ctx: dict) -> dict:
    """nmap's service-detection path: NSE ssl-cert reads a local TLS server's certificate."""
    ap, d, prog = ctx["authority_prefix"], ctx["workdir"], str(ctx["program"])
    pki = _gen_pki(ap, d / "pki")
    srv_out, srv_err = d / "server.out", d / "server.err"
    proc, outf, errf = _spawn(
        [str(_auth_ossl(ap)), "s_server", "-accept", str(ctx["port"]),
         "-cert", str(pki["srv_crt"]), "-key", str(pki["srv_key"]), "-www", "-quiet"],
        d, _auth_env(ap), srv_out, srv_err)
    try:
        if not _wait_tcp("127.0.0.1", ctx["port"]):
            return _wl_fail([("nmap fixture server", {"stdout": _read(srv_out),
                                                     "stderr": _read(srv_err), "exit_code": 1})],
                            "the local TLS fixture server did not listen", "runtime-failure", d)
        scan = _run_captured([prog, "-sT", "-Pn", "-p", str(ctx["port"]), "--script",
                              "ssl-cert,ssl-enum-ciphers", "127.0.0.1"], cwd=d,
                             env=ctx["env"], timeout=180)
    finally:
        _stop(proc)
        outf.close()
        errf.close()
    text = scan["stdout"] + scan["stderr"]
    subject_ok = "Subject: commonName=127.0.0.1" in text
    protocol_ok = "TLSv1.3" in text
    # Negative control: with the server gone the same scan must report a closed port and no
    # certificate at all.
    neg = _run_captured([prog, "-sT", "-Pn", "-p", str(ctx["port"]), "--script", "ssl-cert",
                         "127.0.0.1"], cwd=d, env=ctx["env"], timeout=120)
    neg_text = neg["stdout"] + neg["stderr"]
    neg_ok = ("closed" in neg_text and "Subject:" not in neg_text)
    functional_ok = bool(scan["ok"] and subject_ok and protocol_ok and neg_ok)
    return {
        "runtime_ok": bool(scan["ok"] and subject_ok),
        "functional_ok": functional_ok,
        "failure_class": None if functional_ok else (
            "functional-failure" if scan["ok"] else "runtime-failure"),
        "residual": "none" if functional_ok else (
            "functional-divergence" if scan["ok"] else "runtime-failure"),
        "reason": None if functional_ok else (
            "nmap did not report the fixture certificate subject and TLSv1.3"
            if not (subject_ok and protocol_ok) else
            "nmap did not report the closed port once the listener was stopped"),
        "transcript": _transcript(("nmap ssl-cert over the local TLS server", scan),
                                  ("nmap ssl-cert with no listener (negative control)", neg)),
        "workload": "nmap: NSE ssl-cert + ssl-enum-ciphers against a local TLS server; no-listener "
                    "negative control",
        "local_only": True,
    }


def _wl_fastd(ctx: dict) -> dict:
    """fastd's handshake path: two peer instances over loopback, and a wrong-key rejection.

    The venue has no `/dev/net/tun` and no CAP_NET_ADMIN, so this workload can only check the
    daemon's startup path; the peer handshake itself is reported as the venue exclusion rather
    than fabricated.
    """
    d, prog = ctx["workdir"], str(ctx["program"])
    d.mkdir(parents=True, exist_ok=True)
    start = _run_captured([prog, "--version"], cwd=d, env=ctx["env"], timeout=30)
    tun = Path("/dev/net/tun")
    reason = ("fastd's data path requires a TUN interface; the court container has no "
              "/dev/net/tun device and no CAP_NET_ADMIN (TUNSETIFF is refused), so the two-peer "
              "handshake workload cannot run in this venue")
    return {
        "runtime_ok": True, "functional_ok": False, "failure_class": None,
        "residual": "out-of-scope", "reason": reason,
        "transcript": _transcript(("fastd --version", start)),
        "workload": "fastd: TUN-backed peer handshake unavailable (no /dev/net/tun)",
        "local_only": True, "note": ("the launcher exits at open_iface_linux with ENODEV; "
                                      "asserted absence: " + str(not tun.exists())),
    }


def _wl_kea(ctx: dict) -> dict:
    """Kea's HTTPS control channel: config-get over a verified TLS POST."""
    ap, d, root, prog = (ctx["authority_prefix"], ctx["workdir"], ctx["root"],
                         str(ctx["program"]))
    pki = _gen_pki(ap, d / "pki")
    for sub in ("run/kea", "log/kea"):
        (root / ".l7-state" / sub).mkdir(parents=True, exist_ok=True)
    cfg = d / "kea.json"
    cfg.write_text(json.dumps({
        "Control-agent": {
            "http-host": "127.0.0.1",
            "http-port": ctx["port"],
            "trust-anchor": str(pki["ca_crt"]),
            "cert-file": str(pki["srv_crt"]),
            "key-file": str(pki["srv_key"]),
            "cert-required": False,
            "loggers": [{"name": "kea-ctrl-agent", "severity": "INFO",
                         "output_options": [{"output": "stdout"}]}],
        },
    }, indent=1), encoding="utf-8")
    out, err = d / "agent.out", d / "agent.err"
    proc, outf, errf = _spawn([prog, "-c", str(cfg), "-d"], d, ctx["env"], out, err)
    body = json.dumps({"command": "list-commands"}).encode()

    def post(cafile: str) -> tuple[bool, str]:
        try:
            tls = ssl.create_default_context(cafile=cafile)
            sock = tls.wrap_socket(socket.create_connection(("127.0.0.1", ctx["port"]), 5),
                                   server_hostname="localhost")
            sock.sendall(b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n"
                         b"Content-Length: " + str(len(body)).encode() +
                         b"\r\nConnection: close\r\n\r\n" + body)
            data = b""
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                data += chunk
            sock.close()
            return True, data.decode("utf-8", "replace")
        except Exception as exc:  # noqa: BLE001 — a rejected control connection is evidence
            return False, f"{type(exc).__name__}: {exc}"

    try:
        ready = _wait_tcp("127.0.0.1", ctx["port"])
        ok, reply = post(str(pki["ca_crt"])) if ready else (False, "listener did not start")
        neg_ok, neg_reply = post(str(pki["other_crt"]))
    finally:
        _stop(proc)
        outf.close()
        errf.close()
    accepted = bool(ok and '"result":0' in reply.replace(" ", "") and "arguments" in reply)
    rejected = (not neg_ok and "CERTIFICATE_VERIFY_FAILED" in neg_reply)
    functional_ok = accepted and rejected
    return {
        "runtime_ok": accepted, "functional_ok": functional_ok,
        "failure_class": None if functional_ok else (
            "functional-failure" if accepted else "runtime-failure"),
        "residual": "none" if functional_ok else (
            "functional-divergence" if accepted else "runtime-failure"),
        "reason": None if functional_ok else (
            "the Kea HTTPS control channel did not answer list-commands with result 0"
            if not accepted else "a client trusting only the unrelated CA was not rejected"),
        "transcript": _transcript(
            ("kea HTTPS list-commands (fixture CA)",
             {"exit_code": 0 if ok else 1, "stdout": reply, "stderr": ""}),
            ("kea HTTPS list-commands (unrelated CA, must fail)",
             {"exit_code": 0 if neg_ok else 1, "stdout": neg_reply, "stderr": ""})),
        "workload": "kea: HTTPS control-channel list-commands with the fixture CA; "
                    "unrelated-CA client rejected",
        "local_only": True,
    }


def _wl_mumble(ctx: dict) -> dict:
    """mumble-server's TLS listener: the framed Version message over a verified TLS session."""
    ap, d, prog = ctx["authority_prefix"], ctx["workdir"], str(ctx["program"])
    pki = _gen_pki(ap, d / "pki")
    pem = d / "server.pem"
    pem.write_text(_read(pki["srv_crt"]) + _read(pki["srv_key"]), encoding="utf-8")
    ini = d / "murmur.ini"
    ini.write_text(
        f"database={d / 'murmur.sqlite'}\nport={ctx['port']}\nhost=127.0.0.1\n"
        f"sslCert={pem}\nsslKey={pki['srv_key']}\nsslCA={pki['ca_crt']}\n"
        f"certrequired=False\nbonjour=False\nlogfile={d / 'murmur.log'}\n"
        f"welcometext=phase25 l7\n", encoding="utf-8")
    env = dict(ctx["env"])
    plugins = _aux_root(ctx) / "usr/lib/x86_64-linux-gnu/qt5/plugins"
    if plugins.is_dir():
        env["QT_PLUGIN_PATH"] = str(plugins)
    out, err = d / "murmur.out", d / "murmur.err"
    proc, outf, errf = _spawn([prog, "-fg", "-ini", str(ini)], d, env, out, err)

    def session(cafile: str) -> tuple[bool, bytes | str, str]:
        try:
            tls = ssl.create_default_context(cafile=cafile)
            sock = tls.wrap_socket(socket.create_connection(("127.0.0.1", ctx["port"]), 5),
                                   server_hostname="localhost")
            sock.settimeout(3)
            # The Mumble control protocol opens with a Version message in each direction;
            # sending ours also makes the exchange deterministic if the peer waits for it.
            hello = b"\x08\xff\x8b\x04\x12\x071.5.735"
            sock.sendall(b"\x00\x00\x00\x00" + len(hello).to_bytes(4, "big") + hello)
            data = sock.recv(512)
            version = sock.version() or ""
            sock.close()
            return True, data, version
        except Exception as exc:  # noqa: BLE001
            return False, f"{type(exc).__name__}", ""

    try:
        ready = (_wait_tcp("127.0.0.1", ctx["port"])
                 and _wait_log(d / "murmur.err", "Server listening", 25))
        ok, data, tls_version = session(str(pki["ca_crt"])) if ready else (
            False, "listener did not start", "")
        neg_ok, neg_data, _ = session(str(pki["other_crt"]))
    finally:
        _stop(proc)
        outf.close()
        errf.close()
    blob = data if isinstance(data, bytes) else b""
    # Mumble frames a control message as <4-byte type><4-byte length><protobuf>.  Type 0 is
    # Version; its release field (field 3) must name the built release.
    framed = len(blob) >= 8 and blob[:4] == b"\x00\x00\x00\x00" and b"1.5.735" in blob
    rejected = (not neg_ok and neg_data == "SSLCertVerificationError")
    functional_ok = bool(ok and tls_version.startswith("TLS") and framed and rejected)
    return {
        "runtime_ok": bool(ok and framed), "functional_ok": functional_ok,
        "failure_class": None if functional_ok else (
            "functional-failure" if ok else "runtime-failure"),
        "residual": "none" if functional_ok else (
            "functional-divergence" if ok else "runtime-failure"),
        "reason": None if functional_ok else (
            "mumble-server did not return a framed Version message over the verified TLS session"
            if not framed else "a client trusting only the unrelated CA was not rejected"),
        "transcript": _transcript(
            ("murmur TLS session (fixture CA)",
             {"exit_code": 0 if ok else 1,
              "stdout": f"tls={tls_version} data={str(data)[:120]!r} framed=Version "
                        f"release=1.5.735",
              "stderr": ""}),
            ("murmur TLS session (unrelated CA, must fail)",
             {"exit_code": 0 if neg_ok else 1, "stdout": str(neg_data), "stderr": ""})),
        "workload": "mumble-server: TLS handshake + framed Version (release 1.5.735) over a "
                    "verified session; unrelated CA rejected",
        "local_only": True,
    }


def _wl_partclone(ctx: dict) -> dict:
    """partclone's digest path: torrent_info SHA-1, restored payload, and CRC detection."""
    d, prog = ctx["workdir"], str(ctx["program"])
    tree, src, img = d / "tree", d / "fs.img", d / "image.pcl"
    tree.mkdir(parents=True, exist_ok=True)
    (tree / "payload.txt").write_text("phase25-partclone-payload", encoding="utf-8")
    with open(src, "wb") as fh:
        fh.truncate(16 << 20)
    mke2fs = _run_captured(["mke2fs", "-q", "-t", "ext4", "-d", str(tree), str(src)], cwd=d,
                           env=ctx["env"], timeout=120)
    create = _run_captured([prog, "-c", "-s", str(src), "-o", str(img), "-a", "1", "-k", "1",
                            "-q"], cwd=d, env=ctx["env"], timeout=180)
    blocks = d / "blocks"
    blocks.mkdir(parents=True, exist_ok=True)
    bt = _run_captured([prog, "-r", "-C", "-T", "-s", str(img), "-o", str(blocks / "part"),
                        "-q"], cwd=d, env=ctx["env"], timeout=180)
    torrent = _read(blocks / "part" / "torrent.info")
    parts = sorted(p for p in (blocks / "part").glob("*") if p.name != "torrent.info")
    digest = hashlib.sha1()
    for part in parts:
        digest.update(part.read_bytes())
    sha1_line = next((line.split("sha1:", 1)[1].strip() for line in torrent.splitlines()
                      if line.startswith("sha1:")), "")
    restored = d / "restored.img"
    # `-O` (overwrite) rather than `-o`: partclone 0.3.27's open_target() tests
    # S_ISBLK() on an uninitialised struct stat when the target does not exist, so a
    # plain `-o` on a new path can spuriously fail with ENOENT (a consumer defect,
    # independent of the crypto library).  `-O` is the documented overwrite path and
    # is deterministic for both subjects.
    restore = _run_captured([prog, "-r", "-C", "-s", str(img), "-O", str(restored), "-q"],
                            cwd=d, env=ctx["env"], timeout=180)
    payload = _run_captured(["debugfs", "-R", "cat /payload.txt", str(restored)], cwd=d,
                            env=ctx["env"], timeout=60)
    payload_ok = payload["ok"] and "phase25-partclone-payload" in payload["stdout"]
    data = bytearray(img.read_bytes()) if img.is_file() else bytearray()
    corrupt, corrupt_out = d / "corrupt.pcl", d / "corrupt.img"
    if len(data) > 64:
        data[len(data) // 2] ^= 0xFF
    corrupt.write_bytes(bytes(data))
    bad = _run_captured([prog, "-r", "-C", "-s", str(corrupt), "-O", str(corrupt_out), "-q"],
                        cwd=d, env=ctx["env"], timeout=180)
    bad_text = bad["stdout"] + bad["stderr"]
    detected = (not bad["ok"] and ("CRC" in bad_text or "checksum" in bad_text.lower()))
    digest_ok = bool(sha1_line and sha1_line == digest.hexdigest())
    functional_ok = bool(mke2fs["ok"] and create["ok"] and bt["ok"] and restore["ok"]
                         and digest_ok and payload_ok and detected)
    return {
        "runtime_ok": bool(create["ok"] and restore["ok"]),
        "functional_ok": functional_ok,
        "failure_class": None if functional_ok else (
            "functional-failure" if create["ok"] else "runtime-failure"),
        "residual": "none" if functional_ok else (
            "functional-divergence" if create["ok"] else "runtime-failure"),
        "reason": None if functional_ok else (
            "partclone did not produce the expected torrent SHA-1 and restored payload"
            if not (digest_ok and payload_ok) else
            "partclone did not detect the corrupted image block"),
        "transcript": _transcript(("mke2fs fixture", mke2fs),
                                  ("partclone create (CRC32)", create),
                                  ("partclone restore to block files (torrent_info)", bt),
                                  ("partclone restore", restore),
                                  ("debugfs payload read", payload),
                                  ("partclone restore of a corrupted block (must fail)", bad)),
        "workload": "partclone.extfs: torrent_info SHA-1 equals the block-file digest, restored "
                    "payload matches, corrupted block detected",
        "local_only": True,
    }


def _xmpp_tls_session(port: int, cafile: str, user: str, password: str,
                      host: str = "localhost") -> tuple[bool, list[str]]:
    """A minimal XMPP c2s STARTTLS session: SASL PLAIN, resource bind, IQ ping."""
    import base64
    checks: list[bool] = []
    trace: list[str] = []
    ctx = ssl.create_default_context(cafile=cafile)
    sock = socket.create_connection(("127.0.0.1", port), 5)
    sock.settimeout(8)

    def send(text: str) -> None:
        sock.sendall(text.encode("utf-8"))

    def read_until(*markers: str) -> str:
        data = b""
        wanted = [m.encode() for m in markers]
        while not any(m in data for m in wanted):
            chunk = sock.recv(8192)
            if not chunk:
                break
            data += chunk
        return data.decode("utf-8", "replace")

    header = ("<?xml version='1.0'?><stream:stream to='%s' xmlns='jabber:client' "
              "xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>" % host)
    send(header)
    features = read_until("</stream:features>")
    checks.append("starttls" in features)
    trace.append("starttls-offered=%s" % checks[-1])
    send("<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
    proceed = read_until("<proceed", "<failure")
    checks.append("<proceed" in proceed)
    trace.append("proceed=%s" % checks[-1])
    sock = ctx.wrap_socket(sock, server_hostname=host)
    trace.append("tls=%s" % (sock.version() or ""))
    send(header)
    read_until("</stream:features>")
    token = base64.b64encode(("\x00%s\x00%s" % (user, password)).encode()).decode()
    send("<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>%s</auth>" % token)
    auth = read_until("<success", "<failure")
    checks.append("<success" in auth)
    trace.append("sasl-success=%s" % checks[-1])
    send(header)
    read_until("</stream:features>")
    send("<iq type='set' id='bind1'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'>"
         "<resource>l7</resource></bind></iq>")
    bound = read_until("bind1", "bind1\"")
    checks.append("bind1" in bound)
    trace.append("bind-result=%s" % checks[-1])
    send("<iq type='get' id='ping1' to='%s'><ping xmlns='urn:xmpp:ping'/></iq>" % host)
    pong = read_until("ping1")
    checks.append("type='result'" in pong or 'type="result"' in pong)
    trace.append("ping-result=%s" % checks[-1])
    sock.close()
    return all(checks), trace


def _wl_prosody(ctx: dict) -> dict:
    """Prosody's XMPP-over-TLS listener, driven through the recipe's Lua harness."""
    ap, d, root, prog = (ctx["authority_prefix"], ctx["workdir"], ctx["root"],
                         str(ctx["program"]))
    pki = _gen_pki(ap, d / "pki")
    for sub in ("data", "log"):
        (d / sub).mkdir(parents=True, exist_ok=True)
    cfg = d / "prosody.cfg.lua"
    cfg.write_text(
        "daemonize = false\n"
        f"pidfile = '{d}/prosody.pid'\n"
        f"data_path = '{d}/data'\n"
        "plugin_paths = { '" + str(root / "plugins") + "' }\n"
        f"c2s_ports = {{ {ctx['port']} }}\n"
        "s2s_ports = { }\n"
        "legacy_ssl_ports = { }\n"
        "http_ports = { }\nhttps_ports = { }\n"
        "log = { { levels = { min = 'debug' }, to = 'file', filename = '"
        + str(d / "log/prosody.log") + "' } }\n"
        # The venue runs as root. Without this, mod_posix calls prosody.shutdown() during
        # startup, before prosody.main_thread is set (startup.lua:357), and the fixture then
        # aborts on a nil index instead of serving the XMPP listener. The refusal is a
        # deployment guard, not a protocol behaviour under test; the container is disposable.
        "run_as_root = true\n"
        f"ssl = {{ certificate = '{pki['srv_crt']}'; key = '{pki['srv_key']}'; }}\n"
        "VirtualHost 'localhost'\n"
        "  modules_enabled = { 'tls', 'saslauth', 'disco', 'ping' }\n"
        "  authentication = 'internal_plain'\n"
        "  allow_registration = false\n"
        "  c2s_require_encryption = true\n"
        f"  ssl = {{ certificate = '{pki['srv_crt']}'; key = '{pki['srv_key']}'; }}\n",
        encoding="utf-8")
    lua_path = ";".join([
        f"{root}/?.lua", f"{root}/?/init.lua",
        f"{root}/.l7-lua/share/lua/5.4/?.lua",
        f"{_aux_root(ctx)}/usr/share/lua/5.4/?.lua",
        f"{_aux_root(ctx)}/usr/share/lua/5.4/?/init.lua", ""])
    lua_cpath = ";".join([
        f"{root}/.l7-lua/lib/lua/5.4/?.so",
        f"{_aux_root(ctx)}/usr/lib/x86_64-linux-gnu/lua/5.4/?.so", ""])
    env = dict(ctx["env"], PROSODY_SRCDIR=str(root), PROSODY_CFGDIR=str(d),
               PROSODY_PLUGINDIR=str(root / "plugins"), PROSODY_DATADIR=str(root),
               LUA_PATH=lua_path, LUA_CPATH=lua_cpath)
    reg_env = dict(env, PROSODY_ENTRY="prosodyctl")
    reg = _run_captured([prog, "register", "l7user", "localhost", "l7pass"], cwd=d,
                        env=reg_env, timeout=120)
    out, err = d / "prosody.out", d / "prosody.err"
    proc, outf, errf = _spawn([prog], d, dict(env, PROSODY_ENTRY="prosody"), out, err)
    session_ok, trace = False, []
    neg_ok, neg_trace = False, []
    try:
        if _wait_tcp("127.0.0.1", ctx["port"]):
            session_ok, trace = _xmpp_tls_session(ctx["port"], str(pki["ca_crt"]), "l7user",
                                                  "l7pass")
            try:
                _xmpp_tls_session(ctx["port"], str(pki["other_crt"]), "l7user", "l7pass")
                neg_ok = False
            except ssl.SSLCertVerificationError:
                neg_ok = True
    finally:
        _stop(proc)
        outf.close()
        errf.close()
    functional_ok = bool(reg["ok"] and session_ok and neg_ok)
    return {
        "runtime_ok": bool(reg["ok"] and session_ok),
        "functional_ok": functional_ok,
        "failure_class": None if functional_ok else (
            "functional-failure" if reg["ok"] else "runtime-failure"),
        "residual": "none" if functional_ok else (
            "functional-divergence" if reg["ok"] else "runtime-failure"),
        "reason": None if functional_ok else (
            "prosody did not register/authenticate and answer the XMPP ping"
            if not (reg["ok"] and session_ok) else
            "a client trusting only the unrelated CA was not rejected"),
        "transcript": _transcript(  # noqa: E128
            *([("prosodyctl register", reg),
               ("XMPP STARTTLS session", {"exit_code": 0 if session_ok else 1,
                                         "stdout": " ".join(trace), "stderr": ""}),
               ("XMPP session with the unrelated CA", {
                   "exit_code": 0 if neg_ok else 1,
                   "stdout": "rejected" if neg_ok else "accepted", "stderr": ""})]
              + ([("prosody stderr tail", {"exit_code": 0, "stderr": _read(err)[-2000:],
                                           "stdout": ""}),
                  ("prosody log tail", {
                      "exit_code": 0, "stdout": _read(d / "log" / "prosody.log")[-2500:],
                      "stderr": ""}),
                  ("prosody error lines", {
                      "exit_code": 0, "stdout": "\n".join(
                          line for line in _read(d / "log" / "prosody.log").splitlines()
                          if "error" in line.lower() or "fail" in line.lower()),
                      "stderr": ""})]
                 if not functional_ok else []))),
        "workload": "prosody: XMPP STARTTLS, SASL PLAIN, resource bind and IQ ping; unrelated CA "
                    "rejected",
        "local_only": True,
    }


def _spawn_as(argv: list[str], cwd: Path, env: dict, out_path: Path, err_path: Path,
              uid: int = 65534, gid: int = 65534):
    """Spawn a program as an unprivileged user (a client that refuses to run as root)."""
    outf = open(out_path, "w", encoding="utf-8")
    errf = open(err_path, "w", encoding="utf-8")

    def demote() -> None:
        try:
            os.setgroups([])
        except OSError:
            pass
        os.setgid(gid)
        os.setuid(uid)

    proc = subprocess.Popen([str(a) for a in argv], cwd=str(cwd), env=env, stdout=outf,
                            stderr=errf, stdin=subprocess.DEVNULL, preexec_fn=demote, text=True)
    return proc, outf, errf


def _chown_tree(root: Path, uid: int = 65534, gid: int = 65534) -> None:
    """Hand a fixture directory to the unprivileged user a client runs as."""
    for p in [root, *root.rglob("*")]:
        try:
            os.chown(p, uid, gid)
        except OSError:
            pass
    try:
        os.chmod(root, 0o755)
    except OSError:
        pass


def _l7_irc_stub(ctx: dict) -> tuple[Path, dict]:
    """Compile the local IRC peer harness against the *authority* prefix.

    The stub is a peer, not the subject under test: linking it to the admitted authority keeps the
    peer's OpenSSL independent of the program it drives, exactly as the s_server/s_client peers are.
    """
    ap = ctx["authority_prefix"]
    out = ctx["workdir"] / ".l7-irc-stub"
    res = _run_captured(["cc", str(REPO_ROOT / "forensics" / "tools" / "l7_irc_stub.c"),
                         "-o", str(out), "-O2", "-Wall", "-Wextra",
                         f"-I{ap / 'include'}", f"-L{ap / 'lib'}",
                         f"-Wl,-rpath,{ap / 'lib'}", "-lssl", "-lcrypto"],
                        env=_auth_env(ap), timeout=120)
    return out, res


def _wait_marker(path: Path, needle: str, timeout: float) -> bool:
    """Wait for a marker in a peer's log (a marker line, never a bare substring of evidence)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if any(line == needle or line.startswith(needle + " ") for line in _read(path).splitlines()):
            return True
        time.sleep(0.25)
    return False


# --------------------------------------------------------------------------------------------
# b6 workloads: exim STARTTLS submission, nsd DoT, net-snmp USM, eggdrop/irssi IRC-over-TLS and
# the sshd server direction
# --------------------------------------------------------------------------------------------

def _wl_exim(ctx: dict) -> dict:
    """An SMTP STARTTLS submission: a verified session queues a message; an unrelated CA is refused."""
    ap, port, d = ctx["authority_prefix"], ctx["port"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    spool, logd, confd = d / "spool", d / "log", d / "etc"
    for p in (spool, logd, confd):
        p.mkdir(parents=True, exist_ok=True)
    conf = confd / "exim.conf"
    conf.write_text(f"""primary_hostname = l7.test
domainlist local_domains = l7.test
spool_directory = {spool}
log_file_path = {logd}/%slog
queue_only = true
never_users =
acl_smtp_mail = accept
acl_smtp_rcpt = accept
acl_smtp_data = accept
tls_advertise_hosts = *
tls_certificate = {pki['srv_crt']}
tls_privatekey = {pki['srv_key']}
local_interfaces = 127.0.0.1
""", encoding="utf-8")
    # The daemon runs as root but each SMTP child runs as the compiled EXIM_USER; the fixture
    # certificate and the spool/log directories must therefore be usable by that user.
    for f in (pki["srv_crt"], pki["srv_key"], pki["ca_crt"], pki["other_crt"]):
        os.chmod(f, 0o644)
    for p in (spool, logd):
        os.chmod(p, 0o777)
    exchange = ("EHLO client\r\nMAIL FROM:<a@l7.test>\r\nRCPT TO:<b@l7.test>\r\nDATA\r\n"
                "Subject: fixture\r\n\r\nphase24 runtime exim fixture\r\n.\r\nQUIT\r\n")
    srv, of, ef = _spawn([str(ctx["program"]), "-bd", "-oX", str(port), "-C", str(conf)], d,
                         ctx["env"], d / "exim.out", d / "exim.err")
    try:
        if not _wait_tcp("127.0.0.1", port):
            return _wl_fail([("exim daemon", {"exit_code": 0, "stdout": _read(d / "exim.err")})],
                            "the exim daemon did not listen on its submission port",
                            "runtime-failure", d)
        ok = _s_client(ap, port, pki["ca_crt"],
                       ["-starttls", "smtp", "-verify_return_error", "-quiet"],
                       stdin_text=exchange, timeout=45)
        neg = _s_client(ap, port, pki["other_crt"],
                        ["-starttls", "smtp", "-verify_return_error", "-quiet"],
                        stdin_text="EHLO client\r\nQUIT\r\n", timeout=45)
    finally:
        _stop(srv)
        of.close()
        ef.close()
    accepted = "250 OK id=" in ok["stdout"]
    neg_rejected = (neg["exit_code"] != 0
                    and "certificate verify failed" in (neg["stdout"] + neg["stderr"]))
    runtime_ok = accepted
    functional_ok = accepted and neg_rejected
    return {"runtime_ok": runtime_ok, "functional_ok": functional_ok,
            "failure_class": None if functional_ok else ("functional-failure" if runtime_ok else
                                                         "runtime-failure"),
            "residual": "none" if functional_ok else ("functional-divergence" if runtime_ok else
                                                      "runtime-failure"),
            "reason": None if functional_ok else
            ("the message was not queued over STARTTLS (no `250 OK id=`)" if not accepted else
             "the unrelated CA was not rejected, so the submission does not verify"),
            "transcript": _transcript(("authority s_client STARTTLS submission", ok),
                                      ("authority s_client unrelated-ca (must fail)", neg),
                                      ("exim mainlog", {"exit_code": 0,
                                                        "stdout": _read(logd / "mainlog")[-2000:]})),
            "workload": "exim: SMTP STARTTLS submission queued; unrelated CA refused",
            "local_only": True}


_DOT_QUERY = (struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
              + b"\x03www\x07example\x04test\x00" + struct.pack(">HH", 1, 1))
_DOT_ANSWER = b"\xc0\x00\x02\x7b"  # 192.0.2.123, the fixture A record


def _dot_query(ap: Path, port: int, ca: Path, wire: bytes) -> tuple[bytes, dict]:
    """One DNS-over-TLS query through the authority s_client; the raw answer bytes are returned."""
    argv = [str(_auth_ossl(ap)), "s_client", "-connect", f"127.0.0.1:{port}", "-CAfile",
            str(ca), "-verify_return_error", "-quiet", "-tls1_3"]
    proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, env=_auth_env(ap))
    data = b""
    try:
        proc.stdin.write(wire)
        proc.stdin.flush()
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            ready, _, _ = select.select([proc.stdout], [], [], 0.5)
            if not ready:
                continue
            chunk = os.read(proc.stdout.fileno(), 4096)
            if not chunk:
                break
            data += chunk
            if len(data) >= 2 and len(data) >= struct.unpack(">H", data[:2])[0] + 2:
                break
    finally:
        _stop(proc)
        try:
            err = proc.stderr.read().decode("utf-8", "ignore")
        except Exception:  # noqa: BLE001
            err = ""
    return data, {"exit_code": proc.returncode, "stdout": "", "stderr": err}


def _plain_dns_query(port: int, wire: bytes) -> bytes:
    """The same length-framed query sent as plaintext to the TLS port; no DNS answer is expected."""
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
            s.settimeout(4)
            s.sendall(wire)
            try:
                return s.recv(512)
            except socket.timeout:
                return b""
    except OSError:
        return b""


def _wl_nsd(ctx: dict) -> dict:
    """An authoritative answer over DNS-over-TLS; plaintext on the TLS port gets no answer."""
    ap, port, d = ctx["authority_prefix"], ctx["port"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    zone = d / "fixture.zone"
    zone.write_text("$ORIGIN example.test.\n$TTL 300\n"
                    "@ IN SOA ns.example.test. hostmaster.example.test. 1 3600 600 86400 300\n"
                    "@ IN NS ns.example.test.\nns IN A 127.0.0.1\nwww IN A 192.0.2.123\n",
                    encoding="utf-8")
    conf = d / "nsd.conf"
    conf.write_text(f"""server:
  ip-address: 127.0.0.1@{port}
  tls-port: {port}
  tls-service-key: {pki['srv_key']}
  tls-service-pem: {pki['srv_crt']}
  do-ip6: no
  username: ""
  database: ""
  zonesdir: {d}
  pidfile: {d}/nsd.pid
  xfrdfile: {d}/xfrd.state
  xfrdir: {d}/xfrd
  zonelistfile: {d}/zone.list
  logfile: {d}/nsd.log
zone:
  name: example.test
  zonefile: {zone}
""", encoding="utf-8")
    for f in (pki["srv_crt"], pki["srv_key"], pki["ca_crt"]):
        os.chmod(f, 0o600)
    srv, of, ef = _spawn([str(ctx["program"]), "-c", str(conf), "-d"], d, ctx["env"],
                         d / "nsd.out", d / "nsd.err")
    try:
        if not _wait_tcp("127.0.0.1", port):
            return _wl_fail([("nsd", {"exit_code": 0, "stdout": _read(d / "nsd.err")})],
                            "nsd did not open its DNS-over-TLS listener", "runtime-failure", d)
        wire = struct.pack(">H", len(_DOT_QUERY)) + _DOT_QUERY
        answer, tls = _dot_query(ap, port, pki["ca_crt"], wire)
        plain = _plain_dns_query(port, wire)
    finally:
        _stop(srv)
        of.close()
        ef.close()
    tls_ok = _DOT_ANSWER in answer
    plain_failed = _DOT_ANSWER not in plain
    runtime_ok = bool(answer) and "verify return" in tls["stderr"]
    functional_ok = tls_ok and plain_failed
    return {"runtime_ok": runtime_ok, "functional_ok": functional_ok,
            "failure_class": None if functional_ok else ("functional-failure" if runtime_ok else
                                                         "runtime-failure"),
            "residual": "none" if functional_ok else ("functional-divergence" if runtime_ok else
                                                      "runtime-failure"),
            "reason": None if functional_ok else
            ("the DoT query was not answered over a verified TLS session" if not runtime_ok else
             "the fixture A record was not in the DoT answer" if not tls_ok else
             "plaintext on the TLS port produced a DNS answer"),
            "transcript": _transcript(("authority s_client DoT (raw)",
                                       {"exit_code": tls["exit_code"],
                                        "stdout": answer[:64].hex(),
                                        "stderr": tls["stderr"]}),
                                      ("plaintext on the TLS port (raw)",
                                       {"exit_code": 0, "stdout": plain[:64].hex()}),
                                      ("nsd log", {"exit_code": 0,
                                                    "stdout": _read(d / "nsd.log")[-1500:]})),
            "workload": "nsd: DNS-over-TLS authoritative answer; plaintext on the TLS port fails",
            "local_only": True}


def _wl_net_snmp(ctx: dict) -> dict:
    """SNMPv3 USM authentication through the subject libcrypto, with the OID value asserted."""
    ap, port, d, root = ctx["authority_prefix"], ctx["port"], ctx["workdir"], ctx["root"]
    del ap
    state = root / ".l7-state"
    state.mkdir(parents=True, exist_ok=True)
    conf = d / "snmpd.conf"
    conf.write_text(f"agentaddress 127.0.0.1:{port}\n"
                    "syslocation phase24-runtime-netsnmp-ok\n"
                    "syscontact nobody@l7.test\n"
                    "createUser l7user SHA \"l7authpass\"\n"
                    "rwuser l7user auth\n", encoding="utf-8")
    get = root / "apps" / "snmpget"
    if not get.is_file():
        return {"runtime_ok": False, "functional_ok": False,
                "failure_class": "harness-failure", "residual": "out-of-scope",
                "reason": f"the recipe built no snmpget at {get}",
                "transcript": "", "workload": "net-snmp: USM authenticated GET",
                "local_only": True}
    srv, of, ef = _spawn([str(ctx["program"]), "-f", "-C", "-c", str(conf), "-p",
                          str(d / "snmpd.pid"), "-Lo"], d, ctx["env"],
                         d / "snmpd.out", d / "snmpd.err")
    oid = ".1.3.6.1.2.1.1.6.0"
    try:
        # SNMP runs over UDP, so there is no TCP listener to wait for: the authenticated GET is
        # retried briefly while the agent completes its start-up.
        pos = {"exit_code": -1, "stdout": "", "stderr": "", "ok": False}
        for _ in range(10):
            pos = _run_captured([str(get), "-v3", "-l", "authNoPriv", "-u", "l7user", "-a",
                                 "SHA", "-A", "l7authpass", "-On", "-m", "", "-t", "4",
                                 "-r", "1", f"127.0.0.1:{port}", oid],
                                cwd=d, env=ctx["env"], timeout=40)
            if pos["exit_code"] == 0:
                break
            time.sleep(1)
        neg = _run_captured([str(get), "-v3", "-l", "authNoPriv", "-u", "l7user", "-a", "SHA",
                             "-A", "wrongpass", "-On", "-m", "", "-t", "2", "-r", "0",
                             f"127.0.0.1:{port}", oid],
                            cwd=d, env=ctx["env"], timeout=40)
    finally:
        _stop(srv)
        of.close()
        ef.close()
    value_ok = pos["exit_code"] == 0 and "phase24-runtime-netsnmp-ok" in pos["stdout"]
    neg_refused = (neg["exit_code"] != 0
                   and "Authentication failure" in (neg["stdout"] + neg["stderr"]))
    runtime_ok = pos["exit_code"] == 0
    functional_ok = value_ok and neg_refused
    return {"runtime_ok": runtime_ok, "functional_ok": functional_ok,
            "failure_class": None if functional_ok else ("functional-failure" if runtime_ok else
                                                         "runtime-failure"),
            "residual": "none" if functional_ok else ("functional-divergence" if runtime_ok else
                                                      "runtime-failure"),
            "reason": None if functional_ok else
            ("the authenticated GET did not return the fixture sysLocation" if not value_ok else
             "a wrong authentication password was not refused"),
            "transcript": _transcript(("snmpget v3 authNoPriv", pos),
                                      ("snmpget v3 wrong password (must fail)", neg),
                                      ("snmpd", {"exit_code": 0,
                                                  "stdout": _read(d / "snmpd.out")[-1200:]})),
            "workload": "net-snmp: SNMPv3 SHA-authenticated GET returns the fixture OID value",
            "local_only": True}


def _eggdrop_config(path: Path, root: Path, d: Path, port: int, cafile: Path,
                    userfile: Path, ssl: bool) -> None:
    path.write_text(f"""set username "l7bot"
set nick "l7bot"
set altnick "l7bot_"
set realname "l7 fixture"
set admin "l7 <l7@l7.test>"
set network "l7net"
set default-port 6667
set userfile "{userfile}"
set chanfile "{d}/l7bot.chan"
set motd "{d}/motd.txt"
set help-path "{root}/help/"
set text-path "{root}/text/"
set mod-path "{root}/"
set ssl-verify-server {'1' if ssl else '0'}
set ssl-cafile "{cafile}"
set ssl-capath ""
loadmodule pbkdf2
loadmodule blowfish
loadmodule channels
loadmodule server
loadmodule ctcp
loadmodule irc
loadmodule notes
loadmodule console
loadmodule uptime
server add 127.0.0.1 {'+' if ssl else ''}{port}
channel add #l7
""", encoding="utf-8")


def _wl_eggdrop(ctx: dict) -> dict:
    """IRC-over-TLS registration and join; the same client against plaintext never registers."""
    ap, port, d, root = ctx["authority_prefix"], ctx["port"], ctx["workdir"], ctx["root"]
    pki = _gen_pki(ap, d)
    (d / "motd.txt").write_text("l7 fixture motd\n", encoding="utf-8")
    stub, built = _l7_irc_stub(ctx)
    if not built["ok"] or not stub.is_file():
        return {"runtime_ok": False, "functional_ok": False, "failure_class": "harness-failure",
                "residual": "out-of-scope",
                "reason": f"the IRC stub harness did not compile: {census._error_line(built)}",
                "transcript": _transcript(("cc l7_irc_stub.c", built)),
                "workload": "eggdrop: IRC-over-TLS registration", "local_only": True}
    log = d / "stub.log"
    srv, of, ef = _spawn([str(stub), str(port), str(log), "tls", str(pki["srv_crt"]),
                          str(pki["srv_key"])], d, _auth_env(ap), d / "stub.out",
                         d / "stub.err")
    try:
        if not _wait_marker(log, "READY", 20):
            return _wl_fail([("irc stub", {"exit_code": 0, "stdout": _read(d / "stub.err")})],
                            "the local IRC stub did not listen", "harness-failure", d)
        conf = d / "egg.conf"
        _eggdrop_config(conf, root, d, port, pki["ca_crt"], d / "l7bot.user", ssl=True)
        _chown_tree(d)
        proc, of2, ef2 = _spawn_as([str(ctx["program"]), "-n", "-m", "-c", str(conf)], d,
                                   dict(ctx["env"], HOME=str(d)), d / "egg.out",
                                   d / "egg.err")
        try:
            joined = _wait_marker(log, "JOINED #l7", 30)
        finally:
            _stop(proc)
            of2.close()
            ef2.close()
        registered = any(line.startswith("REGISTERED ") for line in _read(log).splitlines())
    finally:
        _stop(srv)
        of.close()
        ef.close()
    # The plaintext control: the same client still asks for TLS, so a plaintext listener never
    # receives a registration.
    pport = _free_port()
    plainlog = d / "plain.log"
    stub2, of3, ef3 = _spawn([str(stub), str(pport), str(plainlog), "plain"], d, _auth_env(ap),
                             d / "plain.out", d / "plain.err")
    plain_conf = d / "egg-plain.conf"
    _eggdrop_config(plain_conf, root, d, pport, pki["ca_crt"], d / "l7bot-plain.user", ssl=True)
    _chown_tree(d)
    proc2, of4, ef4 = _spawn_as([str(ctx["program"]), "-n", "-m", "-c", str(plain_conf)], d,
                                dict(ctx["env"], HOME=str(d)), d / "egg-plain.out",
                                d / "egg-plain.err")
    try:
        time.sleep(8)
    finally:
        _stop(proc2)
        of4.close()
        ef4.close()
        _stop(stub2)
        of3.close()
        ef3.close()
    plain_text = _read(plainlog)
    plain_refused = "REGISTERED" not in plain_text and "USER " not in plain_text
    runtime_ok = registered
    functional_ok = registered and joined and plain_refused
    return {"runtime_ok": runtime_ok, "functional_ok": functional_ok,
            "failure_class": None if functional_ok else ("functional-failure" if runtime_ok else
                                                         "runtime-failure"),
            "residual": "none" if functional_ok else ("functional-divergence" if runtime_ok else
                                                      "runtime-failure"),
            "reason": None if functional_ok else
            ("the bot did not register over TLS" if not registered else
             "the bot registered but never joined the fixture channel" if not joined else
             "a plaintext listener received a registration, so TLS is not load-bearing"),
            "transcript": _transcript(("irc stub (TLS) log", {"exit_code": 0, "stdout": _read(log)}),
                                      ("irc stub (plaintext) log",
                                       {"exit_code": 0, "stdout": plain_text}),
                                      ("eggdrop", {"exit_code": 0,
                                                    "stdout": _read(d / "egg.out")[-1500:]})),
            "workload": "eggdrop: IRC-over-TLS registration and join; plaintext never registers",
            "local_only": True}


def _irssi_config(path: Path, d: Path, port: int, cafile: Path) -> None:
    path.write_text(f"""servers = (
  {{ address = "127.0.0.1"; port = "{port}"; chatnet = "l7net"; autoconnect = "yes";
     use_tls = "yes"; ssl_verify = "yes"; ssl_cafile = "{cafile}"; ssl_capath = ""; }}
);
chatnets = {{ l7net = {{ type = "IRC"; }}; }};
settings = {{ core = {{ nick = "l7irssi"; user_name = "l7user"; real_name = "l7 fixture"; }}; }};
""", encoding="utf-8")


def _run_irssi(ctx: dict, config: Path, log: Path, join: bool, timeout: float) -> tuple[bool, bool, bytes]:
    """Run irssi on a pty; return (registered, joined, screen bytes)."""
    master, slave = pty.openpty()
    env = dict(ctx["env"], TERM="xterm", HOME=str(config.parent))
    proc = subprocess.Popen([str(ctx["program"]), f"--home={config.parent}"],
                            stdin=slave, stdout=slave, stderr=slave, env=env,
                            cwd=str(ctx["workdir"]))
    os.close(slave)
    screen = b""
    sent = False
    joined = False
    registered = False
    try:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            ready, _, _ = select.select([master], [], [], 0.3)
            if ready:
                try:
                    chunk = os.read(master, 65536)
                except OSError:
                    chunk = b""
                if not chunk:
                    break
                screen += chunk
            text = _read(log)
            if "REGISTERED " in text:
                registered = True
                if join and not sent:
                    os.write(master, b"/join #l7\n")
                    sent = True
            if sent and "JOINED #l7" in text:
                joined = True
                # Drain the pty a little longer: the join is rendered asynchronously by the
                # client, and the screen assertion must not race the terminal write.
                drain = time.monotonic() + 3.0
                while time.monotonic() < drain:
                    ready, _, _ = select.select([master], [], [], 0.3)
                    if not ready:
                        continue
                    try:
                        chunk = os.read(master, 65536)
                    except OSError:
                        break
                    if not chunk:
                        break
                    screen += chunk
                break
    finally:
        _stop(proc)
        try:
            os.close(master)
        except OSError:
            pass
    return registered, joined, screen


def _wl_irssi(ctx: dict) -> dict:
    """IRC-over-TLS registration and a channel join; the unrelated CA is refused."""
    ap, port, d = ctx["authority_prefix"], ctx["port"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    stub, built = _l7_irc_stub(ctx)
    if not built["ok"] or not stub.is_file():
        return {"runtime_ok": False, "functional_ok": False, "failure_class": "harness-failure",
                "residual": "out-of-scope",
                "reason": f"the IRC stub harness did not compile: {census._error_line(built)}",
                "transcript": _transcript(("cc l7_irc_stub.c", built)),
                "workload": "irssi: IRC-over-TLS registration", "local_only": True}
    home = d / "home"
    home.mkdir(parents=True, exist_ok=True)
    log = d / "stub.log"
    srv, of, ef = _spawn([str(stub), str(port), str(log), "tls", str(pki["srv_crt"]),
                          str(pki["srv_key"])], d, _auth_env(ap), d / "stub.out",
                         d / "stub.err")
    try:
        if not _wait_marker(log, "READY", 20):
            return _wl_fail([("irc stub", {"exit_code": 0, "stdout": _read(d / "stub.err")})],
                            "the local IRC stub did not listen", "harness-failure", d)
        config = home / "config"
        _irssi_config(config, d, port, pki["ca_crt"])
        registered, joined, screen = _run_irssi(ctx, config, log, join=True, timeout=35)
    finally:
        _stop(srv)
        of.close()
        ef.close()
    # The control: a client trusting only the unrelated CA must never complete TLS, so it never
    # registers. A fresh stub and log isolate this from the positive run's evidence.
    nport = _free_port()
    nlog = d / "stub-neg.log"
    stub2, of3, ef3 = _spawn([str(stub), str(nport), str(nlog), "tls", str(pki["srv_crt"]),
                              str(pki["srv_key"])], d, _auth_env(ap), d / "stub-neg.out",
                             d / "stub-neg.err")
    nhome = d / "home-neg"
    nhome.mkdir(parents=True, exist_ok=True)
    nconfig = nhome / "config"
    _irssi_config(nconfig, d, nport, pki["other_crt"])
    try:
        if not _wait_marker(nlog, "READY", 20):
            nregistered = True
        else:
            nregistered, _njoined, _nscreen = _run_irssi(ctx, nconfig, nlog, join=False,
                                                         timeout=15)
    finally:
        _stop(stub2)
        of3.close()
        ef3.close()
    neg_text = _read(nlog)
    # irssi verifies the peer after the TLS handshake and closes before registering, so the
    # control asserts the absence of registration rather than the absence of a handshake.
    neg_refused = (not nregistered and "REGISTERED" not in neg_text
                   and "C: NICK" not in neg_text and "C: USER" not in neg_text)
    screen_text = screen.decode("utf-8", "ignore")
    screen_join = ("has joined #l7" in screen_text
                   or "phase24 runtime irc fixture" in screen_text)
    runtime_ok = registered
    functional_ok = registered and joined and screen_join and neg_refused
    return {"runtime_ok": runtime_ok, "functional_ok": functional_ok,
            "failure_class": None if functional_ok else ("functional-failure" if runtime_ok else
                                                         "runtime-failure"),
            "residual": "none" if functional_ok else ("functional-divergence" if runtime_ok else
                                                      "runtime-failure"),
            "reason": None if functional_ok else
            ("irssi did not register over TLS" if not registered else
             "irssi registered but did not join the fixture channel" if not joined else
             "the joined channel is not on irssi's screen" if not screen_join else
             "a client with only the unrelated CA was not refused"),
            "transcript": _transcript(("irc stub (TLS) log", {"exit_code": 0, "stdout": _read(log)}),
                                      ("irc stub (unrelated CA) log",
                                       {"exit_code": 0, "stdout": neg_text}),
                                      ("irssi screen (tail)",
                                       {"exit_code": 0, "stdout": screen_text[-1500:]})),
            "workload": "irssi: IRC-over-TLS registration and channel join; unrelated CA refused",
            "local_only": True}


def _wl_openssh_server(ctx: dict) -> dict:
    """The sshd server direction: a fixture host key, a verified exec, and a host-key mismatch."""
    ap, port, d, root = ctx["authority_prefix"], ctx["port"], ctx["workdir"], ctx["root"]
    del ap
    ssh = root / "ssh"
    keygen = root / "ssh-keygen"
    session = root / "sshd-session"
    if not (ssh.is_file() and keygen.is_file() and session.is_file()):
        return {"runtime_ok": False, "functional_ok": False,
                "failure_class": "harness-failure", "residual": "out-of-scope",
                "reason": "the recipe built no ssh/ssh-keygen/sshd-session to drive sshd",
                "transcript": "", "workload": "openssh-server: sshd server direction",
                "local_only": True}
    priv = root / ".l7-privsep"
    priv.mkdir(parents=True, exist_ok=True)
    os.chmod(priv, 0o755)
    host_key, client_key = d / "hostkey", d / "clientkey"
    other_key = d / "otherhost"
    for key in (host_key, client_key, other_key):
        gen = _run_captured([str(keygen), "-t", "ed25519", "-f", str(key), "-N", "", "-q",
                             "-C", "runtime"], cwd=d, env=ctx["env"], timeout=40)
        if not gen["ok"]:
            return {"runtime_ok": False, "functional_ok": False,
                    "failure_class": "harness-failure", "residual": "out-of-scope",
                    "reason": f"ssh-keygen failed: {census._error_line(gen)}",
                    "transcript": _transcript(("ssh-keygen", gen)),
                    "workload": "openssh-server: sshd server direction", "local_only": True}
    authorized = d / "authorized_keys"
    authorized.write_text(_read(d / "clientkey.pub"), encoding="utf-8")
    known_good, known_bad = d / "known_hosts", d / "known_bad"
    known_good.write_text(f"[127.0.0.1]:{port} " + _read(d / "hostkey.pub"), encoding="utf-8")
    known_bad.write_text(f"[127.0.0.1]:{port} " + _read(d / "otherhost.pub"), encoding="utf-8")
    conf = d / "sshd_config"
    conf.write_text(f"Port {port}\nListenAddress 127.0.0.1\nHostKey {host_key}\n"
                    f"PidFile {d}/sshd.pid\nAuthorizedKeysFile {authorized}\nStrictModes no\n"
                    "PasswordAuthentication no\nKbdInteractiveAuthentication no\n"
                    "PubkeyAuthentication yes\nPermitRootLogin yes\nLogLevel VERBOSE\n"
                    f"SshdSessionPath {session}\n", encoding="utf-8")
    srv, of, ef = _spawn([str(ctx["program"]), "-D", "-e", "-f", str(conf)], d, ctx["env"],
                         d / "sshd.out", d / "sshd.err")
    common = ["-F", "/dev/null", "-o", "StrictHostKeyChecking=yes", "-o", "BatchMode=yes",
              "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none",
              "-o", "ConnectTimeout=8", "-o", f"IdentityFile={client_key}",
              "-p", str(port)]
    try:
        if not _wait_tcp("127.0.0.1", port):
            return _wl_fail([("sshd", {"exit_code": 0, "stdout": _read(d / "sshd.err")})],
                            "sshd did not listen on its fixture port", "runtime-failure", d)
        pos = _run_captured([str(ssh)] + common + ["-o", f"UserKnownHostsFile={known_good}",
                                                   "127.0.0.1", "echo ok"],
                            cwd=d, env=ctx["env"], timeout=40)
        neg = _run_captured([str(ssh)] + common + ["-o", f"UserKnownHostsFile={known_bad}",
                                                   "127.0.0.1", "echo ok"],
                            cwd=d, env=ctx["env"], timeout=40)
    finally:
        _stop(srv)
        of.close()
        ef.close()
    exec_ok = pos["exit_code"] == 0 and "ok" in pos["stdout"]
    neg_rejected = (neg["exit_code"] != 0
                    and "Host key verification failed" in (neg["stdout"] + neg["stderr"]))
    runtime_ok = exec_ok
    functional_ok = exec_ok and neg_rejected
    return {"runtime_ok": runtime_ok, "functional_ok": functional_ok,
            "failure_class": None if functional_ok else ("functional-failure" if runtime_ok else
                                                         "runtime-failure"),
            "residual": "none" if functional_ok else ("functional-divergence" if runtime_ok else
                                                      "runtime-failure"),
            "reason": None if functional_ok else
            ("the verified `ssh ... echo ok` did not run on sshd" if not exec_ok else
             "a known_hosts entry for a different host key was not rejected"),
            "transcript": _transcript(("ssh exec over sshd", pos),
                                      ("ssh host-key mismatch (must fail)", neg),
                                      ("sshd", {"exit_code": 0,
                                                 "stdout": _read(d / "sshd.err")[-1500:]})),
            "workload": "openssh-server: sshd -D, verified exec, host-key mismatch rejected",
            "local_only": True}


def _plain_http_fixture(port: int, body: str, state: dict,
                        stop: threading.Event) -> threading.Thread:
    """A minimal loopback plaintext HTTP/1.0 server (the TLS negative-control peer)."""
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", port))
    listener.listen(8)
    listener.settimeout(0.5)
    payload = body.encode()

    def serve() -> None:
        while not stop.is_set():
            try:
                conn, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                with conn:
                    conn.settimeout(5)
                    try:
                        conn.recv(4096)
                    except OSError:
                        pass
                    conn.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: " +
                                 str(len(payload)).encode() +
                                 b"\r\nConnection: close\r\n\r\n" + payload)
            except OSError:
                continue

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    state["listener"] = listener
    return thread


def _nntp_tls_fixture(port: int, pki: dict, state: dict,
                      stop: threading.Event) -> threading.Thread:
    """A local NNTP-over-TLS peer serving one fixture article (RFC 3977 subset)."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=str(pki["srv_pem"]))
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", port))
    listener.listen(8)
    listener.settimeout(0.5)
    headers = (b"Path: l7.test\r\nFrom: l7@l7.test\r\nNewsgroups: l7.test\r\n"
               b"Subject: L7-FIXTURE-ARTICLE\r\nMessage-ID: <l7@l7.test>\r\n"
               b"Date: Mon, 01 Jan 2024 00:00:00 +0000\r\nXref: l7.test l7.test:1\r\n")
    body = b"phase24 runtime nntp fixture body\r\n"

    def send(tls, line: str) -> None:
        tls.sendall((line + "\r\n").encode())

    def handle(conn) -> None:
        try:
            with context.wrap_socket(conn, server_side=True) as tls:
                tls.settimeout(20)
                state["handshakes"] = int(state.get("handshakes", 0)) + 1
                send(tls, "200 l7 fixture ready")
                stream = tls.makefile("rb")
                for raw in stream:
                    command = raw.decode("utf-8", "ignore").strip()
                    state.setdefault("commands", []).append(command)
                    upper = command.upper()
                    if upper.startswith("CAPABILITIES"):
                        send(tls, "101 Capability list")
                        send(tls, "VERSION 2")
                        send(tls, "READER")
                        send(tls, ".")
                    elif upper.startswith("MODE READER"):
                        send(tls, "200 reader")
                    elif upper.startswith("DATE"):
                        send(tls, "111 20240101000000")
                    elif upper.startswith("LISTGROUP"):
                        send(tls, "211 1 1 1 l7.test")
                        send(tls, "1")
                        send(tls, ".")
                    elif upper.startswith("XHDR"):
                        send(tls, "221 header follows")
                        send(tls, "1 <l7@l7.test>")
                        send(tls, ".")
                    elif upper.startswith("LIST"):
                        send(tls, "215 list follows")
                        send(tls, "l7.test 1 1 y")
                        send(tls, ".")
                    elif upper.startswith("GROUP"):
                        send(tls, "211 1 1 1 l7.test")
                    elif upper.startswith("XOVER") or upper.startswith("OVER"):
                        send(tls, "224 overview")
                        send(tls, "1\tL7-FIXTURE-ARTICLE\tl7@l7.test\t"
                                   "Mon, 01 Jan 2024 00:00:00 +0000\t<l7@l7.test>\t\t1\t1")
                        send(tls, ".")
                    elif upper.startswith("HEAD"):
                        send(tls, "221 1 <l7@l7.test>")
                        tls.sendall(headers)
                        send(tls, ".")
                    elif upper.startswith("BODY"):
                        send(tls, "222 1 <l7@l7.test>")
                        tls.sendall(body)
                        send(tls, ".")
                    elif upper.startswith("ARTICLE"):
                        send(tls, "220 1 <l7@l7.test>")
                        tls.sendall(headers + b"\r\n" + body)
                        send(tls, ".")
                    elif upper.startswith("STAT"):
                        send(tls, "223 0 <l7@l7.test>")
                    elif upper.startswith("QUIT"):
                        send(tls, "205 bye")
                        break
                    else:
                        send(tls, "500 unknown")
        except (OSError, ssl.SSLError):
            pass

    def serve() -> None:
        while not stop.is_set():
            try:
                conn, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=handle, args=(conn,), daemon=True).start()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    state["listener"] = listener
    return thread


def _capture_hex(program: Path, pcap: Path, env: dict) -> str:
    """Read a pcap back through tcpdump's `-XX` dump and return a whitespace-free hex string."""
    res = _run_captured([str(program), "-nn", "-XX", "-r", str(pcap)], env=env, timeout=60)
    return re.sub(r"\s+", "", res["stdout"]).upper()


def _wl_tcpdump(ctx: dict) -> dict:
    """Capture a local TLS handshake; the plaintext control must carry no TLS record."""
    ap, d, program = ctx["authority_prefix"], ctx["workdir"], ctx["program"]
    pki = _gen_pki(ap, d)
    port = ctx["port"]
    cap = d / "tls.pcap"
    tc, of, ef = _spawn([str(program), "-i", "lo", "-n", "-s", "0", "-U", "-w", str(cap),
                         "tcp", "port", str(port)], d, ctx["env"], d / "tc.out", d / "tc.err")
    try:
        if not _wait_log(d / "tc.err", "listening on", 15):
            return _wl_fail([("tcpdump", {"exit_code": 0, "stdout": _read(d / "tc.err")})],
                            "tcpdump did not start its loopback capture", "harness-failure", d)
        srv, sof, sef = _spawn([str(_auth_ossl(ap)), "s_server", "-accept", str(port),
                                "-cert", str(pki["srv_crt"]), "-key", str(pki["srv_key"]),
                                "-www", "-quiet"], d, _auth_env(ap), d / "srv.out",
                               d / "srv.err")
        try:
            if not _wait_tcp("127.0.0.1", port, 15):
                return _wl_fail([("s_server", {"exit_code": 0, "stdout": _read(d / "srv.err")})],
                                "the local TLS server did not listen", "harness-failure", d)
            handshake = _s_client(ap, port, pki["ca_crt"], ["-quiet"], stdin_text="", timeout=25)
        finally:
            _stop(srv)
            sof.close()
            sef.close()
        time.sleep(1)
    finally:
        _stop(tc)
        of.close()
        ef.close()
    tls_hex = _capture_hex(program, cap, ctx["env"])
    tls_record = "160301" in tls_hex or "160303" in tls_hex
    handshake_record = "010000" in tls_hex or "020000" in tls_hex

    # The control: capture plaintext bytes only, on a second port, with the same reader.
    pport = _free_port()
    pcap = d / "plain.pcap"
    tc2, of2, ef2 = _spawn([str(program), "-i", "lo", "-n", "-s", "0", "-U", "-w", str(pcap),
                            "tcp", "port", str(pport)], d, ctx["env"], d / "tc2.out",
                           d / "tc2.err")
    try:
        if not _wait_log(d / "tc2.err", "listening on", 15):
            return _wl_fail([("tcpdump (control)",
                              {"exit_code": 0, "stdout": _read(d / "tc2.err")})],
                            "tcpdump did not start its control capture", "harness-failure", d)
        listener = socket.socket()
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", pport))
        listener.listen(1)
        conn = socket.create_connection(("127.0.0.1", pport), timeout=5)
        conn.sendall(b"PLAINTEXT-ONLY-FIXTURE")
        conn.close()
        listener.close()
        time.sleep(1)
    finally:
        _stop(tc2)
        of2.close()
        ef2.close()
    plain_hex = _capture_hex(program, pcap, ctx["env"])
    plain_tls = "160301" in plain_hex or "160303" in plain_hex
    runtime_ok = handshake.get("exit_code") != 127
    functional_ok = runtime_ok and tls_record and handshake_record and not plain_tls
    return {"runtime_ok": runtime_ok, "functional_ok": functional_ok,
            "failure_class": None if functional_ok else ("functional-failure" if runtime_ok else
                                                         "runtime-failure"),
            "residual": "none" if functional_ok else ("functional-divergence" if runtime_ok else
                                                      "runtime-failure"),
            "reason": None if functional_ok else
            ("the TLS capture carried no TLS handshake record" if runtime_ok else
             "the tcpdump/s_client fixture did not run"),
            "transcript": _transcript(("tls handshake", handshake),
                                      ("tcpdump TLS capture (hex)",
                                       {"exit_code": 0, "stdout": tls_hex[-2000:]}),
                                      ("tcpdump plaintext control (hex)",
                                       {"exit_code": 0, "stdout": plain_hex[-1000:]})),
            "workload": "tcpdump: local TLS handshake records; plaintext carries none",
            "local_only": True}


def _wl_bannergrab(ctx: dict) -> dict:
    """A TLS banner grab on 443, and a closed port that must yield no banner."""
    ap, d, program = ctx["authority_prefix"], ctx["workdir"], ctx["program"]
    pki = _gen_pki(ap, d)
    state: dict = {}
    stop = threading.Event()
    thread = None
    try:
        thread = _https_fixture(443, pki, "bannergrab fixture banner", state, stop)
        positive = _run_captured([str(program), "--verbose", "--conn-time=3", "--read-time=3",
                                  "127.0.0.1", "443"], cwd=d, env=ctx["env"], timeout=45)
    finally:
        stop.set()
        if thread is not None:
            thread.join(timeout=2)
        listener = state.get("listener")
        if listener is not None:
            listener.close()
    pos_text = positive["stdout"] + positive["stderr"]
    ssl_info = "SSL SERVICE INFORMATION" in pos_text
    protocol = "Protocol: TLSv1.3" in pos_text or "Protocol: TLSv1.2" in pos_text
    banner = "bannergrab fixture banner" in pos_text

    closed_port = _free_port()
    negative = _run_captured([str(program), "--verbose", "--conn-time=2", "--read-time=1",
                              "127.0.0.1", str(closed_port)], cwd=d, env=ctx["env"], timeout=20)
    neg_text = negative["stdout"] + negative["stderr"]
    closed_clean = "SSL SERVICE INFORMATION" not in neg_text and "Certificate:" not in neg_text
    runtime_ok = positive["exit_code"] == 0
    functional_ok = runtime_ok and ssl_info and protocol and banner and closed_clean
    return {"runtime_ok": runtime_ok, "functional_ok": functional_ok,
            "failure_class": None if functional_ok else ("functional-failure" if runtime_ok else
                                                         "runtime-failure"),
            "residual": "none" if functional_ok else ("functional-divergence" if runtime_ok else
                                                      "runtime-failure"),
            "reason": None if functional_ok else
            ("the TLS banner grab printed no SSL service information" if not ssl_info else
             "the TLS banner grab printed no protocol" if not protocol else
             "the fixture banner was not printed" if not banner else
             "the closed-port control produced a banner"),
            "transcript": _transcript(("bannergrab TLS", positive),
                                      ("bannergrab closed port", negative)),
            "workload": "bannergrab: TLS banner/protocol; closed port yields none",
            "local_only": True}


def _httperf_replies(text: str) -> int:
    m = re.search(r"Total:\s+connections\s+\d+\s+requests\s+\d+\s+replies\s+(\d+)", text)
    return int(m.group(1)) if m else 0


def _wl_httperf(ctx: dict) -> dict:
    """One HTTPS request with one successful reply; plaintext yields zero replies."""
    ap, d, program = ctx["authority_prefix"], ctx["workdir"], ctx["program"]
    pki = _gen_pki(ap, d)
    port = ctx["port"]
    state: dict = {}
    stop = threading.Event()
    thread = _https_fixture(port, pki, "httperf fixture body", state, stop)
    try:
        positive = _run_captured([str(program), "--server", "127.0.0.1", "--port", str(port),
                                  "--uri", "/", "--num-conns", "1", "--num-calls", "1",
                                  "--ssl", "--timeout", "5"], cwd=d, env=ctx["env"],
                                 timeout=45)
    finally:
        stop.set()
        thread.join(timeout=2)
        listener = state.get("listener")
        if listener is not None:
            listener.close()
    pos_text = positive["stdout"] + positive["stderr"]
    replies = _httperf_replies(pos_text)
    ok2xx = "2xx=1" in pos_text

    pport = _free_port()
    pstate: dict = {}
    pstop = threading.Event()
    pthread = _plain_http_fixture(pport, "plaintext fixture body", pstate, pstop)
    try:
        negative = _run_captured([str(program), "--server", "127.0.0.1", "--port", str(pport),
                                  "--uri", "/", "--num-conns", "1", "--num-calls", "1",
                                  "--ssl", "--timeout", "5"], cwd=d, env=ctx["env"],
                                 timeout=45)
    finally:
        pstop.set()
        pthread.join(timeout=2)
        listener = pstate.get("listener")
        if listener is not None:
            listener.close()
    neg_text = negative["stdout"] + negative["stderr"]
    neg_replies = _httperf_replies(neg_text)
    neg_refused = neg_replies == 0 and ("failed to connect to SSL server" in neg_text or
                                        neg_replies == 0)
    runtime_ok = positive["exit_code"] == 0
    functional_ok = runtime_ok and replies == 1 and ok2xx and neg_refused
    return {"runtime_ok": runtime_ok, "functional_ok": functional_ok,
            "failure_class": None if functional_ok else ("functional-failure" if runtime_ok else
                                                         "runtime-failure"),
            "residual": "none" if functional_ok else ("functional-divergence" if runtime_ok else
                                                      "runtime-failure"),
            "reason": None if functional_ok else
            ("the HTTPS run did not report one successful reply" if runtime_ok else
             "httperf did not run"),
            "transcript": _transcript(("httperf HTTPS", positive),
                                      ("httperf plaintext control", negative)),
            "workload": "httperf: one HTTPS reply; plaintext yields zero",
            "local_only": True}


def _wl_makepasswd(ctx: dict) -> dict:
    """The OpenSSL MD5 digest path: deterministic, and salt-sensitive."""
    d, program = ctx["workdir"], ctx["program"]
    one = _run_captured([str(program), "-e", "md5", "-p", "testing", "-s", "foobar"],
                        cwd=d, env=ctx["env"], timeout=20)
    two = _run_captured([str(program), "-e", "md5", "-p", "testing", "-s", "foobar"],
                        cwd=d, env=ctx["env"], timeout=20)
    other = _run_captured([str(program), "-e", "md5", "-p", "testing2", "-s", "foobar"],
                          cwd=d, env=ctx["env"], timeout=20)
    expected = "ae2b1fca515949e5d54fb22b8ed95575"
    first = one["stdout"].strip()
    deterministic = first == two["stdout"].strip()
    salt_sensitive = other["stdout"].strip() != first
    digest_ok = expected in first
    runtime_ok = one["exit_code"] == 0
    functional_ok = runtime_ok and digest_ok and deterministic and salt_sensitive
    return {"runtime_ok": runtime_ok, "functional_ok": functional_ok,
            "failure_class": None if functional_ok else ("functional-failure" if runtime_ok else
                                                         "runtime-failure"),
            "residual": "none" if functional_ok else ("functional-divergence" if runtime_ok else
                                                      "runtime-failure"),
            "reason": None if functional_ok else
            ("the MD5 digest did not match the OpenSSL value" if not digest_ok else
             "the same input produced different digests" if not deterministic else
             "the digest did not change with the password"),
            "transcript": _transcript(("makepasswd md5", one),
                                      ("makepasswd md5 repeat", two),
                                      ("makepasswd md5 other password", other)),
            "workload": "makepasswd: OpenSSL MD5 digest is exact and deterministic",
            "local_only": True}


def _epic5_script(path: Path, cafile: Path, join: bool) -> None:
    body = f"set ssl_root_certs_location {cafile}\n"
    if not join:
        body += "set accept_invalid_ssl_cert off\n"
    else:
        body += "on ^001 * { join #l7 }\n"
    body += "on ^*join* { echo EPIC_JOINED }\n"
    path.write_text(body, encoding="utf-8")


def _run_epic5(ctx: dict, script: Path, log: Path, timeout: float) -> tuple[bool, bool, bytes]:
    """Run epic5 on a pty; return (registered, joined, screen bytes)."""
    master, slave = pty.openpty()
    env = dict(ctx["env"], TERM="dumb", HOME=str(script.parent))
    proc = subprocess.Popen([str(ctx["program"]), "-B", "-d", "-l", str(script),
                             "-n", "l7epic",
                             f"type=irc-ssl:host=127.0.0.1:port={ctx['port']}"],
                            stdin=slave, stdout=slave, stderr=slave, env=env,
                            cwd=str(script.parent))
    os.close(slave)
    screen = b""
    registered = joined = False
    try:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            ready, _, _ = select.select([master], [], [], 0.3)
            if ready:
                try:
                    chunk = os.read(master, 65536)
                except OSError:
                    chunk = b""
                if not chunk:
                    break
                screen += chunk
            text = _read(log)
            registered = registered or "REGISTERED " in text
            joined = joined or "JOINED #l7" in text
            if registered and joined:
                time.sleep(1.5)
                break
    finally:
        _stop(proc)
        try:
            os.close(master)
        except OSError:
            pass
    return registered, joined, screen


def _wl_epic5(ctx: dict) -> dict:
    """IRC-over-TLS registration and join; a client with only the unrelated CA is refused."""
    ap, d = ctx["authority_prefix"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    stub, built = _l7_irc_stub(ctx)
    if not built["ok"] or not stub.is_file():
        return {"runtime_ok": False, "functional_ok": False, "failure_class": "harness-failure",
                "residual": "out-of-scope",
                "reason": f"the IRC stub harness did not compile: {census._error_line(built)}",
                "transcript": _transcript(("cc l7_irc_stub.c", built)),
                "workload": "epic5: IRC-over-TLS registration", "local_only": True}
    script = d / "epic.rc"
    _epic5_script(script, pki["ca_crt"], join=True)
    log = d / "stub.log"
    srv, of, ef = _spawn([str(stub), str(ctx["port"]), str(log), "tls", str(pki["srv_crt"]),
                          str(pki["srv_key"])], d, _auth_env(ap), d / "stub.out",
                         d / "stub.err")
    try:
        if not _wait_marker(log, "READY", 20):
            return _wl_fail([("irc stub", {"exit_code": 0, "stdout": _read(d / "stub.err")})],
                            "the local IRC stub did not listen", "harness-failure", d)
        registered, joined, screen = _run_epic5(ctx, script, log, timeout=35)
    finally:
        _stop(srv)
        of.close()
        ef.close()
    nctx = dict(ctx, port=_free_port())
    nlog = d / "stub-neg.log"
    nscript = d / "epic-neg.rc"
    _epic5_script(nscript, pki["other_crt"], join=False)
    stub2, of2, ef2 = _spawn([str(stub), str(nctx["port"]), str(nlog), "tls",
                              str(pki["srv_crt"]), str(pki["srv_key"])], d, _auth_env(ap),
                             d / "stub-neg.out", d / "stub-neg.err")
    try:
        nregistered = False
        if _wait_marker(nlog, "READY", 20):
            nregistered, _nj, nscreen = _run_epic5(nctx, nscript, nlog, timeout=20)
        else:
            nscreen = b""
            nregistered = True
    finally:
        _stop(stub2)
        of2.close()
        ef2.close()
    neg_text = _read(nlog)
    neg_refused = not nregistered and "REGISTERED" not in neg_text
    screen_text = screen.decode("utf-8", "ignore")
    screen_join = "has joined channel #l7" in screen_text or "phase24 runtime irc fixture" in screen_text
    runtime_ok = registered
    functional_ok = registered and joined and screen_join and neg_refused
    return {"runtime_ok": runtime_ok, "functional_ok": functional_ok,
            "failure_class": None if functional_ok else ("functional-failure" if runtime_ok else
                                                         "runtime-failure"),
            "residual": "none" if functional_ok else ("functional-divergence" if runtime_ok else
                                                      "runtime-failure"),
            "reason": None if functional_ok else
            ("epic5 did not register over TLS" if not registered else
             "epic5 registered but did not join the fixture channel" if not joined else
             "the joined channel is not on epic5's screen" if not screen_join else
             "a client trusting only the unrelated CA was not refused"),
            "transcript": _transcript(("irc stub (TLS) log", {"exit_code": 0, "stdout": _read(log)}),
                                      ("irc stub (unrelated CA) log",
                                       {"exit_code": 0, "stdout": neg_text}),
                                      ("epic5 screen (tail)",
                                       {"exit_code": 0, "stdout": screen_text[-1500:]})),
            "workload": "epic5: IRC-over-TLS registration and join; unrelated CA refused",
            "local_only": True}


def _plain_nntp_fixture(port: int, state: dict,
                       stop: threading.Event) -> threading.Thread:
    """A plaintext peer on a TLS port: it answers in cleartext and never serves an article."""
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", port))
    listener.listen(8)
    listener.settimeout(0.5)

    def handle(conn) -> None:
        try:
            conn.settimeout(10)
            first = conn.recv(4096)
            # A TLS ClientHello starts with 0x16 0x03; recording it proves the client really
            # attempted TLS against this plaintext peer rather than falling back to cleartext.
            if first[:2] == b"\x16\x03":
                state["tls_clienthello"] = True
            conn.sendall(b"200 plaintext fixture ready\r\n")
            conn.sendall(b"500 plaintext peer speaks no TLS\r\n")
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def serve() -> None:
        while not stop.is_set():
            try:
                conn, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=handle, args=(conn,), daemon=True).start()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    state["listener"] = listener
    return thread


def _wl_slrn(ctx: dict) -> dict:
    """slrnpull fetches an NNTP article over TLS; a plaintext peer on the port fetches none.

    slrn 1.0.3a's src/sltcp.c:alloc_ssl calls SSL_CTX_new(SSLv23_client_method()) and never
    sets a verify mode or loads trust anchors, so an unrelated-CA control cannot be established
    without changing the client.  The control is therefore the protocol itself: a plaintext
    peer on the TLS port cannot complete the handshake and no article is fetched, while the
    positive path must show both a TLS handshake and the article arriving through it.  The
    no-verification limitation is recorded in the transcript rather than claimed as a pass.
    """
    ap, d = ctx["authority_prefix"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    slrnpull = ctx["program"].parent / "slrnpull"
    if not slrnpull.is_file():
        return {"runtime_ok": False, "functional_ok": False, "failure_class": "harness-failure",
                "residual": "out-of-scope",
                "reason": "the recipe built no src/objs/slrnpull beside slrn",
                "transcript": "", "workload": "slrn: NNTP-over-TLS article fetch",
                "local_only": True}
    spool = d / "spool"
    spool.mkdir(parents=True, exist_ok=True)
    (spool / "slrnpull.conf").write_text("l7.test 20 0 0\n", encoding="utf-8")
    state: dict = {}
    stop = threading.Event()
    thread = _nntp_tls_fixture(ctx["port"], pki, state, stop)
    try:
        positive = _run_captured([str(slrnpull), "-d", str(spool), "-h",
                                  f"snews://127.0.0.1:{ctx['port']}", "--debug",
                                  str(d / "slrn-debug.log"), "--no-post"],
                                 cwd=d, env=ctx["env"], timeout=40)
    finally:
        stop.set()
        thread.join(timeout=2)
        listener = state.get("listener")
        if listener is not None:
            listener.close()
    article = ""
    for path in spool.rglob("*"):
        if path.is_file():
            article += _read(path)
    fetched = "phase24 runtime nntp fixture body" in article
    handshook = int(state.get("handshakes", 0)) >= 1
    commands = state.get("commands") or []
    carried = handshook and any(
        str(command).upper().split(" ", 1)[0] in
        {"ARTICLE", "HEAD", "BODY", "GROUP", "LISTGROUP", "XOVER", "OVER", "STAT"}
        for command in commands)

    # The control: a plaintext peer on the same TLS port.  The client must attempt a TLS
    # ClientHello (proving the TLS path is the one exercised) and fetch no article.
    nstate: dict = {}
    nstop = threading.Event()
    nthread = _plain_nntp_fixture(_free_port(), nstate, nstop)
    try:
        nport = nstate["listener"].getsockname()[1]
        nspool = d / "spool-plain"
        nspool.mkdir(parents=True, exist_ok=True)
        (nspool / "slrnpull.conf").write_text("l7.test 20 0 0\n", encoding="utf-8")
        _run_captured([str(slrnpull), "-d", str(nspool), "-h",
                       f"snews://127.0.0.1:{nport}", "--no-post"],
                      cwd=d, env=ctx["env"], timeout=40)
        plain_article = ""
        for path in nspool.rglob("*"):
            if path.is_file():
                plain_article += _read(path)
    finally:
        nstop.set()
        nthread.join(timeout=2)
        listener = nstate.get("listener")
        if listener is not None:
            listener.close()
    no_article = "phase24 runtime nntp fixture body" not in plain_article
    runtime_ok = handshook and fetched
    functional_ok = runtime_ok and carried and no_article
    return {"runtime_ok": runtime_ok, "functional_ok": functional_ok,
            "failure_class": None if functional_ok else ("functional-failure" if runtime_ok else
                                                         "runtime-failure"),
            "residual": "none" if functional_ok else ("functional-divergence" if runtime_ok else
                                                      "runtime-failure"),
            "reason": None if functional_ok else
            ("slrnpull did not complete the NNTP-over-TLS fetch" if not runtime_ok else
             "the fixture article was not requested through the TLS session" if not carried else
             "the plaintext peer on the TLS port served an article"),
            "transcript": _transcript(
                ("slrnpull TLS", positive),
                ("slrnpull TLS commands", {"exit_code": 0,
                                             "stdout": "\n".join(commands[-20:])}),
                ("slrnpull plaintext-peer control article",
                 {"exit_code": 0, "stdout": plain_article[-1000:]}),
                ("slrn verification limitation",
                 {"exit_code": 0,
                  "stdout": ("slrn 1.0.3a src/sltcp.c:alloc_ssl calls SSL_CTX_new with no "
                             "SSL_CTX_set_verify/load_verify_locations: the fixture CA is "
                             "untrusted and the session is confidentiality without peer "
                             "authentication; this is recorded, not claimed as verification")})),
            "workload": ("slrn: slrnpull NNTP-over-TLS article fetch carried by the TLS session; "
                         "plaintext peer on the TLS port fetches none"),
            "local_only": True}


def _cowpatty_pmk(path: Path) -> bytes | None:
    """Read the single PMK record from a genpmk hashdb file (40-byte head + records)."""
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if len(data) < 41:
        return None
    rec_size = data[40]
    if rec_size < 33 or len(data) < 40 + rec_size:
        return None
    return data[40 + rec_size - 32:40 + rec_size]


def _wl_cowpatty(ctx: dict) -> dict:
    """genpmk's PBKDF2-HMAC-SHA1 PMK against a known vector, and a wrong passphrase."""
    d, program = ctx["workdir"], ctx["program"]
    ssid, passphrase = "linksys", "dictionary"
    # PBKDF2-HMAC-SHA1(passphrase="dictionary", salt="linksys", 4096, 32).
    expected = bytes.fromhex(
        "5df920b5481ed70538dd5fd02423d7e2522205feeebb974cad08a52b5613ede2")
    good = d / "words.txt"
    good.write_text(passphrase + "\n", encoding="utf-8")
    bad = d / "words-bad.txt"
    bad.write_text("dictionary2\n", encoding="utf-8")
    one = _run_captured([str(program), "-v", "-f", str(good), "-d", str(d / "one.hash"),
                         "-s", ssid], cwd=d, env=ctx["env"], timeout=120)
    two = _run_captured([str(program), "-v", "-f", str(good), "-d", str(d / "two.hash"),
                         "-s", ssid], cwd=d, env=ctx["env"], timeout=120)
    wrong = _run_captured([str(program), "-v", "-f", str(bad), "-d", str(d / "bad.hash"),
                           "-s", ssid], cwd=d, env=ctx["env"], timeout=120)
    pmk_one = _cowpatty_pmk(d / "one.hash")
    pmk_two = _cowpatty_pmk(d / "two.hash")
    pmk_bad = _cowpatty_pmk(d / "bad.hash")
    vector_ok = pmk_one == expected
    deterministic = pmk_one is not None and pmk_one == pmk_two
    wrong_differs = pmk_bad is not None and pmk_bad != pmk_one
    runtime_ok = bool(one["ok"] and two["ok"] and wrong["ok"])
    functional_ok = runtime_ok and vector_ok and deterministic and wrong_differs
    return {"runtime_ok": runtime_ok, "functional_ok": functional_ok,
            "failure_class": None if functional_ok else ("functional-failure" if runtime_ok else
                                                         "runtime-failure"),
            "residual": "none" if functional_ok else ("functional-divergence" if runtime_ok else
                                                      "runtime-failure"),
            "reason": None if functional_ok else
            ("genpmk did not run" if not runtime_ok else
             "the PBKDF2 PMK did not match the known vector" if not vector_ok else
             "the same input produced different PMKs" if not deterministic else
             "a different passphrase produced the same PMK"),
            "transcript": _transcript(
                ("genpmk fixed vector", one),
                ("genpmk fixed vector (repeat)", two),
                ("genpmk wrong passphrase", wrong),
                ("PMK (fixed vector / repeat / wrong passphrase)",
                 {"exit_code": 0,
                  "stdout": "\n".join(
                      (pmk or b"").hex() + (" (expected)" if pmk == expected else "")
                      for pmk in (pmk_one, pmk_two, pmk_bad))})),
            "workload": ("cowpatty: genpmk PBKDF2-HMAC-SHA1 PMK for a fixed SSID/passphrase "
                         "matches the known vector; a wrong passphrase differs"),
            "local_only": True}


def _wl_hcxtools(ctx: dict) -> dict:
    """hcxpmktool's EVP PBKDF2 PMK against an exact value; a wrong passphrase differs."""
    d, program = ctx["workdir"], ctx["program"]
    expected = "5df920b5481ed70538dd5fd02423d7e2522205feeebb974cad08a52b5613ede2"
    good = _run_captured([str(program), "-e", "linksys", "-p", "dictionary"],
                         cwd=d, env=ctx["env"], timeout=30)
    wrong = _run_captured([str(program), "-e", "linksys", "-p", "dictionary2"],
                          cwd=d, env=ctx["env"], timeout=30)
    pat = re.compile(r"PMK(?:\.\.|\(calculated\)\.)?:\s*([0-9a-f]{64})")
    good_pmk = next((m.group(1) for m in pat.finditer(good["stdout"])), "")
    wrong_pmk = next((m.group(1) for m in pat.finditer(wrong["stdout"])), "")
    digest_ok = good_pmk == expected
    wrong_differs = bool(wrong_pmk) and wrong_pmk != good_pmk
    runtime_ok = bool(good["ok"] and wrong["ok"])
    functional_ok = runtime_ok and digest_ok and wrong_differs
    return {"runtime_ok": runtime_ok, "functional_ok": functional_ok,
            "failure_class": None if functional_ok else ("functional-failure" if runtime_ok else
                                                         "runtime-failure"),
            "residual": "none" if functional_ok else ("functional-divergence" if runtime_ok else
                                                      "runtime-failure"),
            "reason": None if functional_ok else
            ("hcxpmktool did not run" if not runtime_ok else
             "the PBKDF2 PMK did not match the known value" if not digest_ok else
             "a corrupted passphrase produced the same PMK"),
            "transcript": _transcript(("hcxpmktool fixed vector", good),
                                      ("hcxpmktool wrong passphrase", wrong)),
            "workload": ("hcxtools: hcxpmktool EVP PBKDF2-HMAC-SHA1 PMK matches the expected "
                         "value; a corrupted passphrase differs"),
            "local_only": True}


def _wl_aircrack(ctx: dict) -> dict:
    """aircrack-ng recovers the known WPA key from the upstream fixture; a wrong list does not."""
    d, program, root = ctx["workdir"], ctx["program"], ctx["root"]
    cap = root / "test" / "wpa2-psk-linksys.cap"
    words = root / "test" / "password.lst"
    if not cap.is_file() or not words.is_file():
        return _wl_fail([], "the pristine tree holds no WPA handshake fixture/word list",
                        "harness-failure", d)
    good = _run_captured([str(program), "-w", str(words), "-a", "2", "-e", "linksys",
                          "-q", str(cap)], cwd=d, env=ctx["env"], timeout=120)
    bad_words = d / "wrong.lst"
    bad_words.write_text("wrongpass\n", encoding="utf-8")
    wrong = _run_captured([str(program), "-w", str(bad_words), "-a", "2", "-e", "linksys",
                           "-q", str(cap)], cwd=d, env=ctx["env"], timeout=120)
    good_text = good["stdout"] + good["stderr"]
    wrong_text = wrong["stdout"] + wrong["stderr"]
    recovered = "KEY FOUND! [ dictionary ]" in good_text
    wrong_fails = "KEY FOUND" not in wrong_text and "KEY NOT FOUND" in wrong_text
    runtime_ok = bool(good["exit_code"] != 127 and wrong["exit_code"] != 127)
    functional_ok = runtime_ok and recovered and wrong_fails
    return {"runtime_ok": runtime_ok, "functional_ok": functional_ok,
            "failure_class": None if functional_ok else ("functional-failure" if runtime_ok else
                                                         "runtime-failure"),
            "residual": "none" if functional_ok else ("functional-divergence" if runtime_ok else
                                                      "runtime-failure"),
            "reason": None if functional_ok else
            ("aircrack-ng did not run" if not runtime_ok else
             "the known key was not recovered from the handshake fixture" if not recovered else
             "a wrong word list still reported the key"),
            "transcript": _transcript(("aircrack-ng fixture key", good),
                                      ("aircrack-ng wrong word list (must not find)", wrong)),
            "workload": ("aircrack-ng: WPA key-cracking path recovers the known key from a "
                         "fixture handshake; a wrong word list leaves it unfound"),
            "local_only": True}


def _wl_nrpe(ctx: dict) -> dict:
    """NRPE over TLS: a fixture command's result, and an unrelated CA refused."""
    ap, d = ctx["authority_prefix"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    program = ctx["program"]
    check_nrpe = program.parent / "check_nrpe"
    if not check_nrpe.is_file():
        return _wl_fail([], "the recipe built no check_nrpe beside nrpe", "harness-failure", d)
    port = ctx["port"]
    # The daemon drops to nobody, so the fixture directory and the certificates it reads must be
    # traversable/readable by that account; the fixture key is a throwaway test secret.
    os.chmod(d, 0o777)
    for name in ("ca_crt", "srv_crt", "srv_key", "other_crt"):
        os.chmod(pki[name], 0o644)
    conf = d / "nrpe.cfg"
    conf.write_text(
        f"server_port={port}\nallowed_hosts=127.0.0.1\nnrpe_user=nobody\n"
        f"nrpe_group=nogroup\npid_file={d / 'nrpe.pid'}\n"
        f"log_file={d / 'nrpe.daemon.log'}\ndisable_syslog=1\n"
        f"ssl_cert_file={pki['srv_crt']}\nssl_privatekey_file={pki['srv_key']}\n"
        f"command[fixture]=/bin/echo PHASE24-NRPE-OK\n", encoding="utf-8")
    os.chmod(conf, 0o644)
    proc, of, ef = _spawn([str(program), "-c", str(conf), "-f"], d, ctx["env"],
                          d / "nrpe.out", d / "nrpe.err")
    try:
        listening = _wait_tcp("127.0.0.1", port, 25)
        good = _run_captured([str(check_nrpe), "-H", "127.0.0.1", "-p", str(port),
                              "-A", str(pki["ca_crt"]), "-c", "fixture"],
                             cwd=d, env=ctx["env"], timeout=30)
        wrong = _run_captured([str(check_nrpe), "-H", "127.0.0.1", "-p", str(port),
                               "-A", str(pki["other_crt"]), "-c", "fixture"],
                              cwd=d, env=ctx["env"], timeout=30)
    finally:
        _stop(proc)
        of.close()
        ef.close()
    good_text = good["stdout"] + good["stderr"]
    wrong_text = wrong["stdout"] + wrong["stderr"]
    command_ok = good["ok"] and "PHASE24-NRPE-OK" in good_text
    refused = (not wrong["ok"]) and "PHASE24-NRPE-OK" not in wrong_text
    runtime_ok = listening and bool(good["exit_code"] != 127)
    functional_ok = runtime_ok and command_ok and refused
    return {"runtime_ok": runtime_ok, "functional_ok": functional_ok,
            "failure_class": None if functional_ok else ("functional-failure" if runtime_ok else
                                                         "runtime-failure"),
            "residual": "none" if functional_ok else ("functional-divergence" if runtime_ok else
                                                      "runtime-failure"),
            "reason": None if functional_ok else
            ("the NRPE daemon did not listen" if not runtime_ok else
             "the fixture command result was not returned over TLS" if not command_ok else
             "a client trusting only the unrelated CA was not refused"),
            "transcript": _transcript(("check_nrpe over TLS", good),
                                      ("check_nrpe with the unrelated CA (must fail)", wrong),
                                      ("nrpe daemon log",
                                       {"exit_code": 0,
                                        "stdout": _read(d / "nrpe.daemon.log")[-1500:]})),
            "workload": ("nrpe: NRPE command result over a verified local TLS session; a client "
                         "trusting only the unrelated CA is refused"),
            "local_only": True}


def _bdecode(data: bytes, index: int = 0):
    """A minimal bencode reader used to locate mktorrent's raw `info` dictionary."""
    kind = data[index:index + 1]
    if kind == b"d":
        index += 1
        value: dict = {}
        while data[index:index + 1] != b"e":
            key, index = _bdecode(data, index)
            value[key], index = _bdecode(data, index)
        return value, index + 1
    if kind == b"l":
        index += 1
        items: list = []
        while data[index:index + 1] != b"e":
            item, index = _bdecode(data, index)
            items.append(item)
        return items, index + 1
    if kind == b"i":
        end = data.index(b"e", index)
        return int(data[index + 1:end]), end + 1
    colon = data.index(b":", index)
    length = int(data[index:colon])
    start = colon + 1
    return data[start:start + length], start + length


def _torrent_info_span(data: bytes) -> bytes:
    """The raw bytes of the top-level `info` value (the SHA-1 preimage of the info hash)."""
    index = 1
    while data[index:index + 1] != b"e":
        key, index = _bdecode(data, index)
        start = index
        _, index = _bdecode(data, index)
        if key == b"info":
            return data[start:index]
    raise ValueError("no info dictionary")


def _wl_mktorrent(ctx: dict) -> dict:
    """mktorrent's OpenSSL SHA-1 piece hashing: exact info hash, changed by a modified file."""
    d, program = ctx["workdir"], ctx["program"]
    payload = bytes(range(256)) * 160
    # SHA-1 of the single 65536-byte piece, and the exact info hash of the fixed fixture.
    expected_piece = "f230d8e9f07f538b8cdc792219b0011d09a22209"
    expected_info = "16ba09b2a85d31f560e9f8179d43b23842454a46"
    (d / "fixture.bin").write_bytes(payload)
    one = _run_captured([str(program), "-a", "http://127.0.0.1/announce", "-l", "16",
                         "-o", str(d / "one.torrent"), "fixture.bin"],
                        cwd=d, env=ctx["env"], timeout=60)
    two = _run_captured([str(program), "-a", "http://127.0.0.1/announce", "-l", "16",
                         "-o", str(d / "two.torrent"), "fixture.bin"],
                        cwd=d, env=ctx["env"], timeout=60)
    mod = d / "mod"
    mod.mkdir(parents=True, exist_ok=True)
    (mod / "fixture.bin").write_bytes(payload[:-1] + bytes([payload[-1] ^ 0x01]))
    changed = _run_captured([str(program), "-a", "http://127.0.0.1/announce", "-l", "16",
                             "-o", str(mod / "changed.torrent"), "fixture.bin"],
                            cwd=mod, env=ctx["env"], timeout=60)
    info_one = _torrent_info_span((d / "one.torrent").read_bytes()) \
        if (d / "one.torrent").is_file() else b""
    info_two = _torrent_info_span((d / "two.torrent").read_bytes()) \
        if (d / "two.torrent").is_file() else b""
    info_changed = _torrent_info_span((mod / "changed.torrent").read_bytes()) \
        if (mod / "changed.torrent").is_file() else b""
    digest_one = hashlib.sha1(info_one).hexdigest() if info_one else ""
    digest_two = hashlib.sha1(info_two).hexdigest() if info_two else ""
    digest_changed = hashlib.sha1(info_changed).hexdigest() if info_changed else ""
    built = one["ok"] and two["ok"] and changed["ok"]
    exact = digest_one == expected_info and bytes.fromhex(expected_piece) in info_one
    deterministic = digest_one == digest_two and bool(digest_one)
    modified_differs = bool(digest_changed) and digest_changed != digest_one
    functional_ok = built and exact and deterministic and modified_differs
    return {"runtime_ok": built, "functional_ok": functional_ok,
            "failure_class": None if functional_ok else ("functional-failure" if built else
                                                         "runtime-failure"),
            "residual": "none" if functional_ok else ("functional-divergence" if built else
                                                      "runtime-failure"),
            "reason": None if functional_ok else
            ("mktorrent did not run" if not built else
             "the info hash/piece hash did not match the OpenSSL SHA-1 value" if not exact else
             "two identical runs produced different info hashes" if not deterministic else
             "a modified file did not change the info hash"),
            "transcript": _transcript(
                ("mktorrent fixed fixture", one),
                ("mktorrent fixed fixture (repeat)", two),
                ("mktorrent modified fixture", changed),
                ("info hashes (fixed / repeat / modified)",
                 {"exit_code": 0,
                  "stdout": f"{digest_one} (expected)\n{digest_two}\n{digest_changed}"})),
            "workload": ("mktorrent: OpenSSL SHA-1 piece hashes give an exact info hash for a "
                         "fixed file; a modified file changes it"),
            "local_only": True}



def _wl_libwebsockets(ctx: dict) -> dict:
    """A wss client+server loopback session with an echo and an unrelated-CA reject."""
    ap, d = ctx["authority_prefix"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    prog = str(ctx["program"])
    common = ["--cert", str(pki["srv_crt"]), "--key", str(pki["srv_key"]),
              "--other-ca", str(pki["other_crt"])]
    good = _run_captured([prog] + common + ["--ca", str(pki["ca_crt"])], cwd=d,
                         env=ctx["env"], timeout=60)
    neg = _run_captured([prog, "--negative"] + common + ["--ca", str(pki["ca_crt"])],
                        cwd=d, env=ctx["env"], timeout=60)
    text = good["stdout"] + good["stderr"]
    neg_text = neg["stdout"] + neg["stderr"]
    handshake_ok = ("handshake=TLSv1.3" in text and "echo=ok" in text)
    runtime_ok = bool(good["ok"] and handshake_ok)
    neg_rejected = bool(neg["ok"] and "negative=rejected" in neg_text)
    functional_ok = runtime_ok and neg_rejected
    return {
        "runtime_ok": runtime_ok, "functional_ok": functional_ok,
        "failure_class": None if functional_ok else (
            "functional-failure" if runtime_ok else "runtime-failure"),
        "residual": "none" if functional_ok else (
            "functional-divergence" if runtime_ok else "runtime-failure"),
        "reason": None if functional_ok else (
            "the wss loopback session did not complete a verified TLS1.3 handshake and echo"
            if not runtime_ok else "the unrelated CA completed the wss handshake"),
        "transcript": _transcript(("wss client+server", good), ("unrelated CA", neg)),
        "workload": ("libwebsockets: wss server+client over loopback (TLS1.3 handshake, "
                     "verified peer, echo round trip) + unrelated-CA reject"),
        "local_only": True,
    }


def _wl_libstrophe(ctx: dict) -> dict:
    """An XMPP STARTTLS session plus a stanza exchange, and an unrelated-CA reject."""
    ap, d = ctx["authority_prefix"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    prog = str(ctx["program"])
    common = ["--cert", str(pki["srv_crt"]), "--key", str(pki["srv_key"])]
    good = _run_captured([prog] + common + ["--ca", str(pki["ca_crt"])], cwd=d,
                         env=ctx["env"], timeout=60)
    neg = _run_captured([prog, "--negative"] + common + ["--ca", str(pki["other_crt"])],
                        cwd=d, env=ctx["env"], timeout=60)
    text = good["stdout"] + good["stderr"]
    neg_text = neg["stdout"] + neg["stderr"]
    handshake_ok = ("tls=TLSv1.3" in text and "stanza=ok" in text)
    runtime_ok = bool(good["ok"] and handshake_ok)
    neg_rejected = bool(neg["ok"] and "negative=rejected" in neg_text)
    functional_ok = runtime_ok and neg_rejected
    return {
        "runtime_ok": runtime_ok, "functional_ok": functional_ok,
        "failure_class": None if functional_ok else (
            "functional-failure" if runtime_ok else "runtime-failure"),
        "residual": "none" if functional_ok else (
            "functional-divergence" if runtime_ok else "runtime-failure"),
        "reason": None if functional_ok else (
            "the libstrophe client did not complete STARTTLS and the stanza exchange"
            if not runtime_ok else "the unrelated CA passed libstrophe's certificate check"),
        "transcript": _transcript(("STARTTLS + stanza", good), ("unrelated CA", neg)),
        "workload": ("libstrophe: XMPP STARTTLS against a local stub (verified TLS1.3, SASL "
                     "PLAIN, message stanza round trip) + unrelated-CA reject"),
        "local_only": True,
    }


def _wl_libcoap(ctx: dict) -> dict:
    """CoAP-over-TLS request/response with an exact payload and an unrelated-CA reject."""
    ap, d = ctx["authority_prefix"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    res = _run_captured([str(ctx["program"]), "--cert", str(pki["srv_crt"]),
                         "--key", str(pki["srv_key"]), "--ca", str(pki["ca_crt"]),
                         "--other-ca", str(pki["other_crt"])],
                        cwd=d, env=ctx["env"], timeout=60)
    text = res["stdout"] + res["stderr"]
    runtime_ok = bool(res["ok"] and "coap_tls=ok" in text)
    payload_ok = "payload=phase25-l7-coap-response" in text
    neg_rejected = "negative=rejected" in text
    functional_ok = runtime_ok and payload_ok and neg_rejected
    return {
        "runtime_ok": runtime_ok, "functional_ok": functional_ok,
        "failure_class": None if functional_ok else (
            "functional-failure" if runtime_ok else "runtime-failure"),
        "residual": "none" if functional_ok else (
            "functional-divergence" if runtime_ok else "runtime-failure"),
        "reason": None if functional_ok else (
            "the CoAP-over-TLS exchange did not complete" if not runtime_ok else
            ("the response payload differs" if not payload_ok else
             "the unrelated CA received a response")),
        "transcript": _transcript(("coap over TLS", res)),
        "workload": ("libcoap: CoAP-over-TLS GET /l7 with a verified session and an exact "
                     "payload, plus an unrelated-CA reject"),
        "local_only": True,
    }


def _wl_libesmtp(ctx: dict) -> dict:
    """An SMTP STARTTLS submission accepted by a local stub, and an unrelated-CA reject."""
    ap, d = ctx["authority_prefix"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    prog = str(ctx["program"])
    common = ["--cert", str(pki["srv_crt"]), "--key", str(pki["srv_key"])]
    good = _run_captured([prog] + common + ["--ca", str(pki["ca_crt"])], cwd=d,
                         env=ctx["env"], timeout=60)
    neg = _run_captured([prog, "--negative"] + common + ["--ca", str(pki["other_crt"])],
                        cwd=d, env=ctx["env"], timeout=60)
    text = good["stdout"] + good["stderr"]
    neg_text = neg["stdout"] + neg["stderr"]
    handshake_ok = ("tls=TLSv1.3" in text and "starttls=ok" in text
                    and "message=accepted" in text and "session=ok" in text)
    runtime_ok = bool(good["ok"] and handshake_ok)
    neg_rejected = bool(neg["ok"] and "negative=rejected" in neg_text)
    functional_ok = runtime_ok and neg_rejected
    return {
        "runtime_ok": runtime_ok, "functional_ok": functional_ok,
        "failure_class": None if functional_ok else (
            "functional-failure" if runtime_ok else "runtime-failure"),
        "residual": "none" if functional_ok else (
            "functional-divergence" if runtime_ok else "runtime-failure"),
        "reason": None if functional_ok else (
            "the STARTTLS submission did not complete" if not runtime_ok else
            "the unrelated CA completed the TLS handshake"),
        "transcript": _transcript(("STARTTLS submission", good), ("unrelated CA", neg)),
        "workload": ("libesmtp: SMTP submission over STARTTLS against a local stub (verified "
                     "TLS1.3, message accepted) + unrelated-CA reject"),
        "local_only": True,
    }


def _wl_minizip_ng(ctx: dict) -> dict:
    """minizip-ng's AES-256 archive write/read with a wrong-password reject."""
    return _wl_markers(ctx, ["aes256_write=ok", "aes256_read=ok", "wrong_password=rejected"],
                       "minizip-ng: WinZip AES-256 archive write/read + wrong-password reject")


def _wl_libtins(ctx: dict) -> dict:
    """libtins' WPA2 PMK derivation against the 802.11i vector and a corrupted input."""
    return _wl_markers(ctx, ["pmk_vector=ok", "corrupt_input_differs=ok"],
                       "libtins: WPA2 PMK derivation reproduces the 802.11i vector and a "
                       "corrupted passphrase differs")


def _wl_getdns(ctx: dict) -> dict:
    """A DNS-over-TLS query answered by a loopback resolver and an unrelated-CA reject."""
    ap, d = ctx["authority_prefix"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    prog = str(ctx["program"])
    common = ["--cert", str(pki["srv_crt"]), "--key", str(pki["srv_key"]),
              "--pin-cert", str(pki["srv_crt"])]
    good = _run_captured([prog] + common + ["--ca", str(pki["ca_crt"])],
                         cwd=d, env=ctx["env"], timeout=60)
    neg = _run_captured([prog, "--cert", str(pki["other_srv_crt"]), "--key",
                         str(pki["other_srv_key"]), "--pin-cert", str(pki["srv_crt"]),
                         "--ca", str(pki["ca_crt"])],
                        cwd=d, env=ctx["env"], timeout=60)
    text = good["stdout"] + good["stderr"]
    neg_text = neg["stdout"] + neg["stderr"]
    runtime_ok = bool(good["ok"] and "dot_query=answered" in text and
                      "answer=192.0.2.53" in text)
    neg_rejected = bool(neg["ok"] and "dot_query=rejected" in neg_text)
    functional_ok = runtime_ok and neg_rejected
    return {
        "runtime_ok": runtime_ok, "functional_ok": functional_ok,
        "failure_class": None if functional_ok else (
            "functional-failure" if runtime_ok else "runtime-failure"),
        "residual": "none" if functional_ok else (
            "functional-divergence" if runtime_ok else "runtime-failure"),
        "reason": None if functional_ok else (
            "the DoT query did not return the fixture answer" if not runtime_ok else
            "an unrelated CA completed the DoT session"),
        "transcript": _transcript(("DNS over TLS", good), ("unrelated CA", neg)),
        "workload": ("getdns: DNS-over-TLS query for the fixture zone answered with 192.0.2.53 "
                     "over a verified session + unrelated-CA reject"),
        "local_only": True,
    }


def _wl_librelp(ctx: dict) -> dict:
    """Two RELP consumers from the same tree carry a message over mutual TLS."""
    ap, d = ctx["authority_prefix"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    recv_prog = str(ctx["program"])
    send_prog = str(ctx["root"] / "tests" / ".libs" / "send")
    # The runtime PKI's server certificate is serverAuth-only, and librelp verifies each peer's
    # certificate purpose.  Mint a clientAuth certificate from the same CA for the sender: this is
    # a fixture input, not a candidate-specific adaptation.
    cli_key, cli_csr, cli_crt = d / "client.key", d / "client.csr", d / "client.crt"
    cli_ext = d / "client.ext"
    for argv in (
        ["req", "-newkey", "rsa:2048", "-nodes", "-keyout", str(cli_key), "-out",
         str(cli_csr), "-subj", "/CN=127.0.0.1"],
    ):
        if not _ossl(ap, argv, cwd=d)["ok"]:
            raise RuntimeError("minting the librelp client certificate failed")
    cli_ext.write_text("basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\n"
                       "extendedKeyUsage=clientAuth\n", encoding="utf-8")
    if not _ossl(ap, ["x509", "-req", "-in", str(cli_csr), "-CA", str(pki["ca_crt"]),
                       "-CAkey", str(pki["ca_key"]), "-CAcreateserial", "-out", str(cli_crt),
                       "-days", "7", "-extfile", str(cli_ext)], cwd=d)["ok"]:
        raise RuntimeError("signing the librelp client certificate failed")

    def common(ca: Path, cert: Path, key: Path) -> list[str]:
        return ["-l", "openssl", "-T", "-a", "name", "-x", str(ca),
                "-y", str(cert), "-z", str(key), "-P", "127.0.0.1"]

    def exchange(tag: str, sender_ca: Path) -> tuple[dict, str, str]:
        port = _free_port()
        out_path, err_path = d / f"recv-{tag}.out", d / f"recv-{tag}.err"
        sess, errlog = d / f"recv-{tag}.sess", d / f"recv-{tag}.log"
        # Line-buffer the receiver's stdout so the delivered message is readable even when a
        # bounded stop arrives immediately after the sender exits.
        argv = ["stdbuf", "-oL", recv_prog, "-p", str(port), "-W", "30",
                "-e", str(errlog), "-C", str(sess),
                *common(pki["ca_crt"], pki["srv_crt"], pki["srv_key"])]
        proc, outf, errf = _spawn(argv, d, ctx["env"], out_path, err_path)
        try:
            listening = _wait_listen(port, timeout=20)
            send = _run_captured(
                [send_prog, "-t", "127.0.0.1", "-p", str(port),
                 "-m", "template-payload", *common(sender_ca, cli_crt, cli_key)],
                cwd=d, env=ctx["env"], timeout=30)
            send["listening"] = listening
        finally:
            _stop(proc)
            outf.close()
            errf.close()
        time.sleep(0.2)
        return send, _read(out_path), _read(err_path)

    good, good_out, good_err = exchange("good", pki["ca_crt"])
    bad, bad_out, bad_err = exchange("wrong-ca", pki["other_crt"])
    delivered = "template-payload" in good_out
    runtime_ok = bool(good["ok"] and delivered)
    neg_rejected = not ("template-payload" in bad_out)
    functional = runtime_ok and neg_rejected
    return {
        "runtime_ok": runtime_ok, "functional_ok": functional,
        "failure_class": None if functional else (
            "functional-failure" if runtime_ok else "runtime-failure"),
        "residual": "none" if functional else (
            "functional-divergence" if runtime_ok else "runtime-failure"),
        "reason": None if functional else (
            "the RELP message was not delivered over the verified TLS session"
            if not runtime_ok else
            "a sender trusting an unrelated CA still delivered the message"),
        "transcript": _transcript(
            ("RELP sender", good),
            ("receiver stdout", {"exit_code": 0, "stdout": good_out[:400],
                                  "stderr": good_err[:400]}),
            ("unrelated CA (must fail)", bad),
            ("negative receiver stdout", {"exit_code": 0, "stdout": bad_out[:200],
                                           "stderr": bad_err[:200]})),
        "workload": ("librelp: the tree's own send/receive pair carries a message over mutual "
                     "TLS and an unrelated CA is refused"),
        "local_only": True,
    }


def _wl_hydra(ctx: dict) -> dict:
    """Hydra authenticates over TLS; the right credential is found and a wrong one is not."""
    import base64

    ap, d = ctx["authority_prefix"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    prog = str(ctx["program"])
    port = _free_port()
    expected = "Basic " + base64.b64encode(b"user:pass").decode()

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - stdlib name
            ok = self.headers.get("Authorization", "") == expected
            body = b"template-payload\n" if ok else b"denied\n"
            self.send_response(200 if ok else 401)
            if not ok:
                self.send_header("WWW-Authenticate", 'Basic realm="fixture"')
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):  # noqa: D401 - silence
            return

    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.daemon_threads = True
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.load_cert_chain(str(pki["srv_crt"]), str(pki["srv_key"]))
    server.socket = sctx.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        good = _run_captured(
            [prog, "-l", "user", "-p", "pass", "-s", str(port), "-t", "1",
             "-f", "127.0.0.1", "https-get", "/"], cwd=d, env=ctx["env"], timeout=60)
        bad = _run_captured(
            [prog, "-l", "user", "-p", "wrong", "-s", str(port), "-t", "1",
             "-f", "127.0.0.1", "https-get", "/"], cwd=d, env=ctx["env"], timeout=60)
    finally:
        server.shutdown()
        server.server_close()
    text = good["stdout"] + good["stderr"]
    neg_text = bad["stdout"] + bad["stderr"]
    runtime_ok = bool(good["ok"] and "login: user" in text and "password: pass" in text)
    neg_rejected = "0 valid password found" in neg_text
    functional = runtime_ok and neg_rejected
    return {
        "runtime_ok": runtime_ok, "functional_ok": functional,
        "failure_class": None if functional else (
            "functional-failure" if runtime_ok else "runtime-failure"),
        "residual": "none" if functional else (
            "functional-divergence" if runtime_ok else "runtime-failure"),
        "reason": None if functional else (
            "hydra did not find the fixture credential over TLS" if not runtime_ok else
            "a wrong password was reported as valid"),
        "transcript": _transcript(("https-get (right password)", good),
                                  ("https-get (wrong password)", bad)),
        "workload": ("hydra: https-get authenticates over a verified TLS session; the fixture "
                     "credential is found and a wrong password is not"),
        "local_only": True,
    }


def _wl_check_tcp(ctx: dict) -> dict:
    """check_tcp's --ssl completes a TLS handshake and refuses a plaintext peer."""
    ap, d = ctx["authority_prefix"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    prog = str(ctx["program"])
    state = {"tls_seen": False}

    def serve_tls(port: int) -> threading.Thread:
        def run() -> None:
            listener = socket.socket()
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", port))
            listener.listen(1)
            listener.settimeout(20)
            sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            sctx.load_cert_chain(str(pki["srv_crt"]), str(pki["srv_key"]))
            try:
                conn, _ = listener.accept()
                with sctx.wrap_socket(conn, server_side=True):
                    state["tls_seen"] = True
            except (OSError, ssl.SSLError):
                pass
            finally:
                listener.close()

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        return thread

    def serve_plain(port: int) -> threading.Thread:
        def run() -> None:
            listener = socket.socket()
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", port))
            listener.listen(1)
            listener.settimeout(20)
            try:
                conn, _ = listener.accept()
                conn.close()
            except OSError:
                pass
            finally:
                listener.close()

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        return thread

    tls_port, plain_port = _free_port(), _free_port()
    tls_thread = serve_tls(tls_port)
    plain_thread = serve_plain(plain_port)
    good = _run_captured([prog, "-S", "-H", "127.0.0.1", "-p", str(tls_port), "-t", "10"],
                         cwd=d, env=ctx["env"], timeout=40)
    bad = _run_captured([prog, "-S", "-H", "127.0.0.1", "-p", str(plain_port), "-t", "10"],
                        cwd=d, env=ctx["env"], timeout=40)
    tls_thread.join(timeout=20)
    plain_thread.join(timeout=20)
    good_text, bad_text = good["stdout"] + good["stderr"], bad["stdout"] + bad["stderr"]
    runtime_ok = bool(good["ok"] and "TCP OK" in good_text and state["tls_seen"])
    neg_rejected = bool(not bad["ok"] and "TCP OK" not in bad_text)
    functional = runtime_ok and neg_rejected
    return {
        "runtime_ok": runtime_ok, "functional_ok": functional,
        "failure_class": None if functional else (
            "functional-failure" if runtime_ok else "runtime-failure"),
        "residual": "none" if functional else (
            "functional-divergence" if runtime_ok else "runtime-failure"),
        "reason": None if functional else (
            "check_tcp --ssl did not complete the TLS handshake" if not runtime_ok else
            "a plaintext peer was reported as a successful TLS check"),
        "transcript": _transcript(("check_tcp --ssl (TLS peer)", good),
                                  ("check_tcp --ssl (plaintext peer, must fail)", bad)),
        "workload": ("nagios check_tcp --ssl: a TLS handshake is accepted and a plaintext "
                     "peer is refused"),
        "local_only": True,
    }


def _wl_ncrack(ctx: dict) -> dict:
    """ncrack's HTTPS module finds the fixture credential and misses a wrong one."""
    import base64

    ap, d = ctx["authority_prefix"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    prog = str(ctx["program"])
    port = _free_port()
    expected = "Basic " + base64.b64encode(b"user:pass").decode()

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - stdlib name
            ok = self.headers.get("Authorization", "") == expected
            body = b"template-payload\n" if ok else b"denied\n"
            self.send_response(200 if ok else 401)
            if not ok:
                self.send_header("WWW-Authenticate", 'Basic realm="fixture"')
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):  # noqa: D401 - silence
            return

    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.daemon_threads = True
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.load_cert_chain(str(pki["srv_crt"]), str(pki["srv_key"]))
    server.socket = sctx.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        target = f"https://127.0.0.1:{port}"
        good = _run_captured([prog, "-v", "--user", "user", "--pass", "pass", target],
                             cwd=d, env=ctx["env"], timeout=90)
        bad = _run_captured([prog, "-v", "--user", "user", "--pass", "wrong", target],
                            cwd=d, env=ctx["env"], timeout=90)
    finally:
        server.shutdown()
        server.server_close()
    text = good["stdout"] + good["stderr"]
    neg_text = bad["stdout"] + bad["stderr"]
    runtime_ok = bool(good["ok"] and "Discovered credentials" in text)
    neg_rejected = "Discovered credentials" not in neg_text
    functional = runtime_ok and neg_rejected
    return {
        "runtime_ok": runtime_ok, "functional_ok": functional,
        "failure_class": None if functional else (
            "functional-failure" if runtime_ok else "runtime-failure"),
        "residual": "none" if functional else (
            "functional-divergence" if runtime_ok else "runtime-failure"),
        "reason": None if functional else (
            "ncrack did not find the fixture credential over TLS" if not runtime_ok else
            "a wrong password was reported as discovered"),
        "transcript": _transcript(("ncrack https (right password)", good),
                                  ("ncrack https (wrong password)", bad)),
        "workload": ("ncrack: HTTPS authentication over a verified TLS session; the fixture "
                     "credential is found and a wrong password is not"),
        "local_only": True,
    }


def _wl_ircd_hybrid(ctx: dict) -> dict:
    """ircd-hybrid greets a verified loopback client over its TLS listener."""
    ap, d, root = ctx["authority_prefix"], ctx["workdir"], ctx["root"]
    pki = _gen_pki(ap, d)
    dh = d / "dh.pem"
    gen = _ossl(ap, ["dhparam", "-out", str(dh), "2048"], cwd=d, timeout=120)
    prefix = root / ".l7-install"
    for sub in ("etc", "var/lib", "var/run", "var/log"):
        (prefix / sub).mkdir(parents=True, exist_ok=True)
    port = _free_port()
    conf = d / "ircd.conf"
    conf.write_text(
        "serverinfo {\n  name = \"irc.fixture\";\n  sid = \"1AA\";\n"
        "  description = \"fixture\";\n  network_name = \"fixture\";\n"
        f"  tls_certificate_file = \"{pki['srv_crt']}\";\n"
        f"  rsa_private_key_file = \"{pki['srv_key']}\";\n"
        f"  tls_dh_param_file = \"{dh}\";\n}};\n"
        "admin { name = \"fixture\"; description = \"fixture\"; email = \"f@example\"; };\n"
        "class { name = \"users\"; ping_time = 90 seconds; number_per_ip_local = 2;\n"
        "        number_per_ip_global = 8; max_number = 100; };\n"
        # `flags` must precede `port`: the port item is added with the flags parsed so far.
        f"listen {{ flags = tls; host = \"127.0.0.1\"; port = {port}; }};\n"
        "auth { user = \"*@*\"; class = \"users\"; };\n", encoding="utf-8")
    rundir = d / "run"
    rundir.mkdir(parents=True, exist_ok=True)
    os.system(f"chown -R nobody:nogroup {d} {prefix} 2>/dev/null")
    os.system(f"chmod -R a+rX {d} {prefix}")
    os.system(f"chmod 777 {d} {prefix / 'var' / 'lib'} {prefix / 'var' / 'run'} "
              f"{prefix / 'var' / 'log'} {rundir}")
    argv = ["setpriv", "--reuid=nobody", "--regid=nogroup", "--clear-groups",
            str(ctx["program"]), "-c", str(conf), "-f", "-l", str(d / "ircd.log"),
            "-p", str(d / "ircd.pid")]
    server = subprocess.Popen(argv, cwd=str(rundir), env=ctx["env"], start_new_session=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        listening = _wait_listen(port, timeout=20)
        good = _ircd_greeting(port, pki["ca_crt"])
        wrong = _ircd_greeting(port, pki["other_crt"])
    finally:
        # The daemon does not complete a graceful SIGTERM teardown in this venue; the bounded
        # stop is a SIGKILL to its process group, which is evidence-neutral (the greeting was
        # already read).
        try:
            os.killpg(os.getpgid(server.pid), signal.SIGKILL)
        except OSError:
            pass
        try:
            out, err = server.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
            out, err = server.communicate()
    greeted = bool(good.get("ok")) and "NOTICE" in good.get("data", "")
    ok = bool(gen["ok"] and listening and greeted)
    functional = ok and not wrong.get("ok")
    return {
        "runtime_ok": ok, "functional_ok": functional,
        "failure_class": None if functional else (
            "functional-failure" if ok else "runtime-failure"),
        "residual": "none" if functional else (
            "functional-divergence" if ok else "runtime-failure"),
        "reason": None if functional else (
            "ircd-hybrid did not listen or greet over TLS" if not ok else
            "a client trusting the unrelated CA was not rejected"),
        "transcript": _transcript(
            ("dhparam", gen),
            ("server", {"exit_code": 0 if listening else 1, "stdout": "",
                        "stderr": (err or "")[-800:]}),
            ("client", {"exit_code": 0 if good.get("ok") else 1,
                        "stdout": good.get("data", "")[:600],
                        "stderr": good.get("error", "")}),
            ("unrelated CA (must fail)", {"exit_code": 0 if wrong.get("ok") else 1,
                                          "stdout": wrong.get("data", "")[:200],
                                          "stderr": wrong.get("error", "")})),
        "workload": ("ircd-hybrid: IRC greeting over a verified TLS session (setpriv euid drop), "
                     "with an unrelated-CA reject"),
        "local_only": True,
    }


def _ircd_greeting(port: int, ca: Path) -> dict:
    try:
        sctx = ssl.create_default_context(cafile=str(ca))
        with socket.create_connection(("127.0.0.1", port), timeout=10) as sock:
            with sctx.wrap_socket(sock, server_hostname="127.0.0.1") as tls:
                tls.settimeout(5)
                data = b""
                try:
                    while len(data) < 4096 and b"NOTICE" not in data:
                        chunk = tls.recv(1024)
                        if not chunk:
                            break
                        data += chunk
                except (socket.timeout, ssl.SSLError):
                    pass
                return {"ok": True, "data": data.decode("utf-8", "replace"), "error": ""}
    except (ssl.SSLError, OSError) as exc:
        return {"ok": False, "data": "", "error": str(exc)}


def _wl_medusa(ctx: dict) -> dict:
    """Medusa's HTTP module over TLS finds the fixture credential and misses a wrong one."""
    import base64

    ap, d = ctx["authority_prefix"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    prog = str(ctx["program"])
    port = _free_port()
    expected = "Basic " + base64.b64encode(b"user:pass").decode()

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - stdlib name
            ok = self.headers.get("Authorization", "") == expected
            body = b"template-payload\n" if ok else b"denied\n"
            self.send_response(200 if ok else 401)
            if not ok:
                self.send_header("WWW-Authenticate", 'Basic realm="fixture"')
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):  # noqa: D401 - silence
            return

    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.daemon_threads = True
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.load_cert_chain(str(pki["srv_crt"]), str(pki["srv_key"]))
    server.socket = sctx.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    env = dict(ctx["env"], MEDUSA_MODULE_PATH=str(ctx["root"] / "src" / "modsrc"))
    try:
        base = [prog, "-h", "127.0.0.1", "-n", str(port), "-M", "http", "-s", "-f", "-v", "6"]
        good = _run_captured([*base[:1], "-u", "user", "-p", "pass", *base[1:]],
                             cwd=d, env=env, timeout=60)
        bad = _run_captured([*base[:1], "-u", "user", "-p", "wrong", *base[1:]],
                            cwd=d, env=env, timeout=60)
    finally:
        server.shutdown()
        server.server_close()
    text = good["stdout"] + good["stderr"]
    neg_text = bad["stdout"] + bad["stderr"]
    runtime_ok = bool(good["ok"] and "ACCOUNT FOUND" in text)
    neg_rejected = "ACCOUNT FOUND" not in neg_text
    functional = runtime_ok and neg_rejected
    return {
        "runtime_ok": runtime_ok, "functional_ok": functional,
        "failure_class": None if functional else (
            "functional-failure" if runtime_ok else "runtime-failure"),
        "residual": "none" if functional else (
            "functional-divergence" if runtime_ok else "runtime-failure"),
        "reason": None if functional else (
            "medusa did not find the fixture credential over TLS" if not runtime_ok else
            "a wrong password was reported as found"),
        "transcript": _transcript(("medusa http (right password)", good),
                                  ("medusa http (wrong password)", bad)),
        "workload": ("medusa: HTTP authentication over a verified TLS session; the fixture "
                     "credential is found and a wrong password is not"),
        "local_only": True,
    }


def _wl_libu2f_server(ctx: dict) -> dict:
    """libu2f-server's ES256 registration/authentication plus an altered-signature reject."""
    return _wl_markers(ctx, ["u2f_register=ok", "u2f_authenticate=ok",
                             "altered_signature=rejected"],
                       "libu2f-server: ES256 U2F registration and authentication + "
                       "altered-signature reject")


def _wl_luaossl(ctx: dict) -> dict:
    """lua-luaossl's digest/HMAC vectors and a corrupted-input control."""
    return _wl_markers(ctx, ["sha256_vector=ok", "hmac_vector=ok", "wrong_input_differs=ok"],
                       "lua-luaossl: SHA-256 and HMAC-SHA256 vectors through the Lua binding + "
                       "corrupted-input difference")


def _wl_luasec(ctx: dict) -> dict:
    """LuaSec's TLS client handshake/payload and an unrelated-CA reject."""
    ap, d = ctx["authority_prefix"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    prog = str(ctx["program"])
    common = ["--cert", str(pki["srv_crt"]), "--key", str(pki["srv_key"])]
    good = _run_captured([prog] + common + ["--ca", str(pki["ca_crt"])],
                         cwd=d, env=ctx["env"], timeout=60)
    neg = _run_captured([prog] + common + ["--ca", str(pki["other_crt"])],
                        cwd=d, env=ctx["env"], timeout=60)
    text = good["stdout"] + good["stderr"]
    neg_text = neg["stdout"] + neg["stderr"]
    runtime_ok = bool(good["ok"] and "handshake=ok" in text and
                      "payload=phase25-l7-luasec-pong" in text)
    neg_rejected = bool(neg["ok"] and "negative=rejected" in neg_text)
    functional_ok = runtime_ok and neg_rejected
    return {
        "runtime_ok": runtime_ok, "functional_ok": functional_ok,
        "failure_class": None if functional_ok else (
            "functional-failure" if runtime_ok else "runtime-failure"),
        "residual": "none" if functional_ok else (
            "functional-divergence" if runtime_ok else "runtime-failure"),
        "reason": None if functional_ok else (
            "the LuaSec client did not complete the handshake and payload round trip"
            if not runtime_ok else "an unrelated CA completed the LuaSec handshake"),
        "transcript": _transcript(("LuaSec TLS client", good), ("unrelated CA", neg)),
        "workload": ("lua-sec: LuaSec TLS1.3 client handshake and payload round trip against a "
                     "local server with peer verification + unrelated-CA reject"),
        "local_only": True,
    }


def _wl_duo_unix(ctx: dict) -> dict:
    """libduo's HMAC-signed authentication and a corrupted-secret reject."""
    ap, d = ctx["authority_prefix"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    prog = str(ctx["program"])
    common = ["--cert", str(pki["srv_crt"]), "--key", str(pki["srv_key"]),
              "--ca", str(pki["ca_crt"])]
    good = _run_captured([prog] + common, cwd=d, env=ctx["env"], timeout=60)
    neg = _run_captured([prog, "--corrupt"] + common, cwd=d, env=ctx["env"], timeout=60)
    text = good["stdout"] + good["stderr"]
    neg_text = neg["stdout"] + neg["stderr"]
    runtime_ok = bool(good["ok"] and "hmac_vector=ok" in text and "duo_login=ok" in text)
    neg_rejected = bool(neg["ok"] and "corrupt_signature=rejected" in neg_text)
    functional_ok = runtime_ok and neg_rejected
    return {
        "runtime_ok": runtime_ok, "functional_ok": functional_ok,
        "failure_class": None if functional_ok else (
            "functional-failure" if runtime_ok else "runtime-failure"),
        "residual": "none" if functional_ok else (
            "functional-divergence" if runtime_ok else "runtime-failure"),
        "reason": None if functional_ok else (
            "libduo's signed authentication did not complete" if not runtime_ok else
            "a corrupted secret was accepted"),
        "transcript": _transcript(("signed Duo login", good), ("corrupted secret", neg)),
        "workload": ("duo_unix: libduo HMAC-SHA1-signed preauth and authentication verified by a "
                     "local endpoint, plus a corrupted-secret reject"),
        "local_only": True,
    }


def _wl_dcap_tunnel(ctx: dict) -> dict:
    """The dcap SSL tunnel's payload round trip and a non-TLS peer reject."""
    ap, d = ctx["authority_prefix"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    prog = str(ctx["program"])
    good = _run_captured([prog, "--cert", str(pki["srv_crt"]), "--key", str(pki["srv_key"])],
                         cwd=d, env=ctx["env"], timeout=60)
    neg = _run_captured([prog, "--plain"], cwd=d, env=ctx["env"], timeout=60)
    text = good["stdout"] + good["stderr"]
    neg_text = neg["stdout"] + neg["stderr"]
    runtime_ok = bool(good["ok"] and "tunnel=ok" in text and
                      "payload=phase25-l7-dcap-tunnel" in text)
    neg_rejected = bool(neg["ok"] and "tunnel_peer=rejected" in neg_text)
    functional_ok = runtime_ok and neg_rejected
    return {
        "runtime_ok": runtime_ok, "functional_ok": functional_ok,
        "failure_class": None if functional_ok else (
            "functional-failure" if runtime_ok else "runtime-failure"),
        "residual": "none" if functional_ok else (
            "functional-divergence" if runtime_ok else "runtime-failure"),
        "reason": None if functional_ok else (
            "the SSL tunnel did not carry the auth line and payload" if not runtime_ok else
            "a non-TLS peer was accepted as a tunnel"),
        "transcript": _transcript(("TLS tunnel", good), ("non-TLS peer", neg)),
        "workload": ("dcap-tunnel-ssl: libsslTunnel establishes a TLS tunnel, sends its auth line "
                     "and round-trips a payload, plus a non-TLS peer reject"),
        "local_only": True,
    }


def _wl_gensio(ctx: dict) -> dict:
    """gensio's ssl gensio request/response round trip and an unrelated-CA reject."""
    ap, d = ctx["authority_prefix"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    prog = str(ctx["program"])
    common = ["--cert", str(pki["srv_crt"]), "--key", str(pki["srv_key"]),
              "--ca", str(pki["ca_crt"]), "--other-ca", str(pki["other_crt"])]
    res = _run_captured([prog] + common, cwd=d, env=ctx["env"], timeout=120)
    text = res["stdout"] + res["stderr"]
    ok = bool(res["ok"] and "tls_session=ok" in text and
              "payload_round_trip=ok" in text and "wrong_ca=rejected" in text)
    return {
        "runtime_ok": ok, "functional_ok": ok,
        "failure_class": None if ok else "functional-failure",
        "residual": "none" if ok else "functional-divergence",
        "reason": None if ok else (
            "the ssl gensio did not complete the request/response round trip or accepted an "
            "unrelated CA"),
        "transcript": _transcript(("gensio TLS session", res)),
        "workload": ("gensio: ssl gensio over loopback TCP carries a request and response with "
                     "the fixture CA + unrelated-CA reject"),
        "local_only": True,
    }


def _wl_jimtcl(ctx: dict) -> dict:
    """jimtcl's aio SSL server response and a mismatched-key reject."""
    ap, d = ctx["authority_prefix"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    prog = str(ctx["program"])
    res = _run_captured([prog, "--cert", str(pki["srv_crt"]), "--key", str(pki["srv_key"]),
                         "--wrong-key", str(pki["other_key"])],
                        cwd=d, env=ctx["env"], timeout=120)
    text = res["stdout"] + res["stderr"]
    ok = bool(res["ok"] and "tls_session=ok" in text and
              "payload=jimtcl-l7-response" in text and "wrong_key=rejected" in text)
    return {
        "runtime_ok": ok, "functional_ok": ok,
        "failure_class": None if ok else "functional-failure",
        "residual": "none" if ok else "functional-divergence",
        "reason": None if ok else (
            "jimtcl's aio SSL server did not return the exact response or accepted a "
            "mismatched private key"),
        "transcript": _transcript(("jimtcl aio SSL server", res)),
        "workload": ("jimtcl: the aio extension's OpenSSL server accepts a TLS request and "
                     "writes the exact response + mismatched-key reject"),
        "local_only": True,
    }


def _wl_sofia_sip(ctx: dict) -> dict:
    """sofia-sip's tport TLS transport round trip and an unrelated-CA reject.

    tport presents `agent.pem` with SSL_CTX_use_certificate_file(), which sends only the first
    certificate, so the fixture's agent.pem is leaf + issuing CA + key and the client's trust
    anchor is the CA. This is the fixture shape tport expects; it is not a subject behaviour.
    """
    ap, d = ctx["authority_prefix"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    prog = str(ctx["program"])
    res = _run_captured([prog, "--cert", str(pki["srv_crt"]), "--key", str(pki["srv_key"]),
                         "--ca", str(pki["ca_crt"]), "--other-ca", str(pki["other_crt"]),
                         "--client-cert", str(pki["srv_crt"]),
                         "--client-key", str(pki["srv_key"])],
                        cwd=d, env=ctx["env"], timeout=120)
    text = res["stdout"] + res["stderr"]
    ok = bool(res["ok"] and "tls_session=ok" in text and
              "payload=sofia-sip-l7-payload" in text and "wrong_ca=rejected" in text)
    return {
        "runtime_ok": ok, "functional_ok": ok,
        "failure_class": None if ok else "functional-failure",
        "residual": "none" if ok else "functional-divergence",
        "reason": None if ok else (
            "the tport TLS session did not deliver the SIP payload or accepted an unrelated CA"),
        "transcript": _transcript(("sofia-sip tport TLS", res)),
        "workload": ("sofia-sip: a SIP MESSAGE over tport TLS carries its payload on loopback "
                     "+ unrelated-CA reject"),
        "local_only": True,
    }


def _wl_libtpms(ctx: dict) -> dict:
    """libtpms' TPM2 command interface: startup, fixed properties and a 32-byte random blob."""
    prog = str(ctx["program"])
    res = _run_captured([prog], cwd=ctx["workdir"], env=ctx["env"], timeout=120)
    text = res["stdout"] + res["stderr"]
    ok = bool(res["ok"] and "tpm2_startup=ok" in text and "family=2.0" in text and
              "manufacturer=IBM" in text and "random=32" in text and
              "unknown_cc=rejected" in text)
    return {
        "runtime_ok": ok, "functional_ok": ok,
        "failure_class": None if ok else "functional-failure",
        "residual": "none" if ok else "functional-divergence",
        "reason": None if ok else (
            "libtpms did not complete TPM2_Startup/GetCapability/GetRandom or accepted an "
            "unknown command code"),
        "transcript": _transcript(("libtpms TPM2 command interface", res)),
        "workload": ("libtpms: TPM2_Startup, GetCapability(PT_FIXED) and GetRandom over "
                     "TPMLIB_Process + unknown-command reject"),
        "local_only": True,
    }


def _wl_libre(ctx: dict) -> dict:
    """libre's SRTP AES-CM/HMAC-SHA1 round trip and an authentication-tag reject."""
    prog = str(ctx["program"])
    res = _run_captured([prog], cwd=ctx["workdir"], env=ctx["env"], timeout=120)
    text = res["stdout"] + res["stderr"]
    ok = bool(res["ok"] and "srtp_encrypt=ok" in text and
              "srtp_roundtrip=ok" in text and "tamper=rejected" in text)
    return {
        "runtime_ok": ok, "functional_ok": ok,
        "failure_class": None if ok else "functional-failure",
        "residual": "none" if ok else "functional-divergence",
        "reason": None if ok else (
            "libre's SRTP encrypt/decrypt did not recover the payload or accepted a tampered "
            "authentication tag"),
        "transcript": _transcript(("libre SRTP", res)),
        "workload": ("libre: an RTP packet protected with SRTP_AES_CM_128_HMAC_SHA1_80 is "
                     "recovered by a fresh context + a flipped tag byte rejected"),
        "local_only": True,
    }


def _wl_atf(ctx: dict) -> dict:
    """TF-A cert_create signs a chain that openssl verifies; tampering is rejected; fiptool packs."""
    d = ctx["workdir"]
    ap = ctx["authority_prefix"]
    cert_create = str(ctx["program"])
    fiptool = str(ctx["root"] / "tools" / "fiptool" / "fiptool")
    der = d / "trusted_key.crt"
    pem = d / "trusted_key.pem"
    fw = d / "soc-fw.bin"
    fip = d / "fip.bin"
    lines: list[str] = []
    ok = True

    fw.write_bytes(b"arm-trusted-firmware-l7-payload")
    made = _run_captured([cert_create, "-n", "-a", "rsa", "-s", "sha256", "--tfw-nvctr", "1",
                          "--trusted-key-cert", str(der)],
                         cwd=d, env=ctx["env"], timeout=120)
    lines.append(f"cert_create=exit{'-' if made['ok'] else '!'}{made['exit_code']}")
    ok = ok and made["ok"] and der.is_file()

    conv = _ossl(ap, ["x509", "-inform", "DER", "-in", str(der), "-out", str(pem)])
    verify = _ossl(ap, ["verify", "-ignore_critical", "-CAfile", str(pem), str(pem)])
    lines.append(f"sign_verify={'ok' if conv['ok'] and verify['ok'] else 'failed'}")
    ok = ok and conv["ok"] and verify["ok"]

    tampered = d / "tampered.crt"
    tampered_pem = d / "tampered.pem"
    raw = bytearray(der.read_bytes())
    if raw:
        raw[-1] ^= 0xff
    tampered.write_bytes(bytes(raw))
    tamper_parse = _ossl(ap, ["x509", "-inform", "DER", "-in", str(tampered),
                              "-out", str(tampered_pem)])
    tamper_verify = (_ossl(ap, ["verify", "-ignore_critical", "-CAfile", str(pem),
                                str(tampered_pem)])
                     if tamper_parse["ok"] else tamper_parse)
    lines.append(f"cert_tamper={'rejected' if not tamper_verify['ok'] else 'accepted'}")
    ok = ok and not tamper_verify["ok"]

    packed = _run_captured([fiptool, "create", "--soc-fw", str(fw),
                            "--trusted-key-cert", str(der), str(fip)],
                           cwd=d, env=ctx["env"], timeout=120)
    info = _run_captured([fiptool, "info", str(fip)], cwd=d, env=ctx["env"], timeout=120)
    info_text = info["stdout"] + info["stderr"]
    packed_ok = bool(packed["ok"] and info["ok"] and "soc-fw" in info_text and
                     "trusted-key-cert" in info_text)
    lines.append(f"fiptool={'ok' if packed_ok else 'failed'}")
    ok = ok and packed_ok

    bad_fip = d / "tampered.fip"
    fip_raw = bytearray(fip.read_bytes()) if fip.is_file() else bytearray()
    if fip_raw:
        fip_raw[0] ^= 0xff
    bad_fip.write_bytes(bytes(fip_raw))
    bad_info = _run_captured([fiptool, "info", str(bad_fip)], cwd=d, env=ctx["env"], timeout=120)
    lines.append(f"fip_tamper={'rejected' if not bad_info['ok'] else 'accepted'}")
    ok = ok and not bad_info["ok"]

    lines.append(f"result={'ok' if ok else 'fail'}")
    transcript = "\n".join(lines)
    res = {"ok": ok, "exit_code": 0 if ok else 1, "stdout": transcript, "stderr": "",
           "elapsed_seconds": 0}
    return {
        "runtime_ok": ok, "functional_ok": ok,
        "failure_class": None if ok else "functional-failure",
        "residual": "none" if ok else "functional-divergence",
        "reason": None if ok else (
            "cert_create/fiptool did not sign, verify and reject tampered inputs as expected"),
        "transcript": _transcript(("arm-trusted-firmware-tools", res)),
        "workload": ("TF-A: cert_create signs a chain, openssl verifies it, a tampered "
                     "certificate and FIP are rejected"),
        "local_only": True,
    }


def _wl_libnetconf2(ctx: dict) -> dict:
    """libnetconf2's TLS session client: verified connection + unrelated-CA reject."""
    ap, d = ctx["authority_prefix"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    prog = str(ctx["program"])
    aux_modules = (ctx["root"].parents[1] / "aux" / "root" / "usr/share/yang/modules")
    res = _run_captured([prog, "--cert", str(pki["srv_crt"]), "--key", str(pki["srv_key"]),
                         "--ca", str(pki["ca_crt"]), "--other-cert", str(pki["other_srv_crt"]),
                         "--other-key", str(pki["other_srv_key"]),
                         "--client-cert", str(pki["client_crt"]),
                         "--client-key", str(pki["client_key"]),
                         "--modules", str(aux_modules),
                         "--nc-modules", str(ctx["root"] / "modules")],
                        cwd=d, env=ctx["env"], timeout=120)
    text = res["stdout"] + res["stderr"]
    ok = bool(res["ok"] and "tls_session=ok" in text and "netconf_hello=ok" in text and
              "wrong_ca=rejected" in text)
    return {
        "runtime_ok": ok, "functional_ok": ok,
        "failure_class": None if ok else "functional-failure",
        "residual": "none" if ok else "functional-divergence",
        "reason": None if ok else (
            "libnetconf2's TLS client did not complete the NETCONF hello or accepted an "
            "unrelated CA"),
        "transcript": _transcript(("libnetconf2 TLS client", res)),
        "workload": ("libnetconf2: a verified TLS session completes the NETCONF hello "
                     "exchange + unrelated-CA reject"),
        "local_only": True,
    }


def _wl_liboauth2(ctx: dict) -> dict:
    """liboauth2's JOSE path: EVP digest vector, cjose JWE round trip, tamper reject."""
    prog = str(ctx["program"])
    res = _run_captured([prog], cwd=ctx["workdir"], env=ctx["env"], timeout=120)
    text = res["stdout"] + res["stderr"]
    ok = bool(res["ok"] and "sha256=ok" in text and "jwe_roundtrip=ok" in text and
              "tamper=rejected" in text)
    return {
        "runtime_ok": ok, "functional_ok": ok,
        "failure_class": None if ok else "functional-failure",
        "residual": "none" if ok else "functional-divergence",
        "reason": None if ok else (
            "liboauth2's EVP digest, cjose round trip or ciphertext-tamper reject did not hold"),
        "transcript": _transcript(("liboauth2 JOSE", res)),
        "workload": ("liboauth2: EVP SHA-256 vector, cjose JWE encrypt/decrypt round trip and "
                     "a flipped ciphertext byte rejected"),
        "local_only": True,
    }


def _https_client_fixture(ctx: dict, argv_of, env_of=None, timeout: int = 60) -> dict:
    """A local HTTPS page fetched by a browser/client with the fixture CA and the wrong CA.

    `argv_of(url)` builds the client argv, and `env_of(ca)` the environment. The good run must
    render the exact body; the unrelated-CA run must not, and must report a verification failure.
    This is the shared shape of the elinks/lynx/lftp workloads (each keeps its own flags).
    """
    ap, d = ctx["authority_prefix"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    body = f"phase25-l7-{ctx['family']}-fixture"
    state: dict = {}
    stop = threading.Event()
    thread = _https_fixture(ctx["port"], pki, body, state, stop)
    url = f"https://127.0.0.1:{ctx['port']}/phase25.txt"
    try:
        if not _wait_tcp("127.0.0.1", ctx["port"]):
            return _wl_fail([("https fixture", {"exit_code": 0, "stdout": ""})],
                            "the local HTTPS fixture did not open its port",
                            "runtime-failure", d)
        good = _run_captured(argv_of(url), cwd=d,
                             env=(env_of(pki["ca_crt"]) if env_of else ctx["env"]),
                             timeout=timeout)
        neg = _run_captured(argv_of(url), cwd=d,
                            env=(env_of(pki["other_crt"]) if env_of else ctx["env"]),
                            timeout=timeout)
    finally:
        stop.set()
        state.get("listener", socket.socket()).close()
        thread.join(timeout=2)
    good_text = good["stdout"] + good["stderr"]
    neg_text = neg["stdout"] + neg["stderr"]
    rendered = bool(good["ok"] and body in good_text)
    neg_rejected = bool(body not in neg_text and not neg["ok"])
    functional_ok = rendered and neg_rejected
    return {
        "runtime_ok": rendered, "functional_ok": functional_ok,
        "failure_class": None if functional_ok else (
            "functional-failure" if rendered else "runtime-failure"),
        "residual": "none" if functional_ok else (
            "functional-divergence" if rendered else "runtime-failure"),
        "reason": None if functional_ok else (
            "the local HTTPS page body was not rendered" if not rendered else
            "the unrelated CA was not rejected, so the fixture CA is not being verified"),
        "transcript": _transcript((f"{ctx['family']} HTTPS (fixture CA)", good),
                                  (f"{ctx['family']} HTTPS (unrelated CA, must fail)", neg)),
        "workload": (f"{ctx['family']}: a local HTTPS page rendered with the fixture CA + "
                     "unrelated-CA reject"),
        "local_only": True,
    }


def _wl_elinks(ctx: dict) -> dict:
    """ELinks' OpenSSL HTTPS client: `-dump` with the fixture CA, wrong-CA reject."""
    prog = str(ctx["program"])
    run_env = {k: v for k, v in ctx["env"].items()
               if k.lower() not in ("http_proxy", "https_proxy", "all_proxy")}

    def env_of(ca: Path) -> dict:
        return dict(run_env, SSL_CERT_FILE=str(ca))

    return _https_client_fixture(ctx, lambda url: [prog, "-dump", "-no-home", url], env_of)


def _wl_lynx(ctx: dict) -> dict:
    """Lynx's OpenSSL HTTPS client: `-dump` with the fixture CA, wrong-CA reject."""
    prog = str(ctx["program"])
    cfg = ctx["root"] / "lynx.cfg"
    run_env = {k: v for k, v in ctx["env"].items()
               if k.lower() not in ("http_proxy", "https_proxy", "all_proxy")}

    def env_of(ca: Path) -> dict:
        return dict(run_env, SSL_CERT_FILE=str(ca))

    argv = [prog]
    if cfg.is_file():
        argv.append(f"-cfg={cfg}")
    argv += ["-dump", "-nolist"]
    return _https_client_fixture(ctx, lambda url: argv + [url], env_of, timeout=90)


def _wl_lftp(ctx: dict) -> dict:
    """lftp's OpenSSL backend: `get` over HTTPS with the fixture CA, wrong-CA reject."""
    ap, d, prog = ctx["authority_prefix"], ctx["workdir"], str(ctx["program"])
    pki = _gen_pki(ap, d)
    body = "phase25-l7-lftp-fixture"
    state: dict = {}
    stop = threading.Event()
    thread = _https_fixture(ctx["port"], pki, body, state, stop)
    url = f"https://127.0.0.1:{ctx['port']}/phase25.txt"
    out_good, out_bad = d / "got.txt", d / "bad.txt"
    base = f"set net:timeout 10; set ssl:verify-certificate yes; set ssl:ca-file "
    try:
        if not _wait_tcp("127.0.0.1", ctx["port"]):
            return _wl_fail([("https fixture", {"exit_code": 0, "stdout": ""})],
                            "the local HTTPS fixture did not open its port",
                            "runtime-failure", d)
        good = _run_captured([prog, "-c", f"{base}{pki['ca_crt']}; get {url} -o {out_good}"],
                             cwd=d, env=ctx["env"], timeout=90)
        neg = _run_captured([prog, "-c",
                             f"{base}{pki['other_crt']}; get {url} -o {out_bad}"],
                            cwd=d, env=ctx["env"], timeout=90)
    finally:
        stop.set()
        state.get("listener", socket.socket()).close()
        thread.join(timeout=2)
    fetched = out_good.is_file() and body in out_good.read_text(encoding="utf-8",
                                                               errors="replace")
    neg_text = neg["stdout"] + neg["stderr"]
    neg_rejected = bool(not neg["ok"] and "Certificate verification" in neg_text
                        and not (out_bad.is_file() and body in out_bad.read_text(
                            encoding="utf-8", errors="replace")))
    functional_ok = fetched and neg_rejected
    return {
        "runtime_ok": fetched, "functional_ok": functional_ok,
        "failure_class": None if functional_ok else (
            "functional-failure" if fetched else "runtime-failure"),
        "residual": "none" if functional_ok else (
            "functional-divergence" if fetched else "runtime-failure"),
        "reason": None if functional_ok else (
            "lftp did not fetch the local HTTPS file" if not fetched else
            "lftp accepted the unrelated CA"),
        "transcript": _transcript(("lftp get (fixture CA)", good),
                                  ("lftp get (unrelated CA, must fail)", neg)),
        "workload": "lftp: `get` over verified local HTTPS + unrelated-CA reject",
        "local_only": True,
    }


def _wl_lighttpd(ctx: dict) -> dict:
    """lighttpd's mod_openssl: serves a document over TLS; an unrelated CA is rejected."""
    ap, d, prog = ctx["authority_prefix"], ctx["workdir"], str(ctx["program"])
    pki = _gen_pki(ap, d)
    body = "phase25-l7-lighttpd-fixture"
    www = d / "www"
    www.mkdir(parents=True, exist_ok=True)
    (www / "index.txt").write_text(body, encoding="utf-8")
    conf = d / "lighttpd.conf"
    conf.write_text(
        f'server.document-root = "{www}"\n'
        f'server.bind = "127.0.0.1"\nserver.port = {ctx["port"]}\n'
        'server.modules = ( "mod_openssl" )\n'
        'ssl.engine = "enable"\n'
        f'ssl.pemfile = "{pki["srv_pem"]}"\n'
        'mimetype.assign = ( ".txt" => "text/plain" )\n', encoding="utf-8")
    srv_out, srv_err = d / "server.out", d / "server.err"
    proc, outf, errf = _spawn([prog, "-D", "-f", str(conf)], d, ctx["env"], srv_out, srv_err)

    def get(ca: Path) -> tuple[bool, str]:
        ctx_ssl = ssl.create_default_context(cafile=str(ca))
        try:
            with socket.create_connection(("127.0.0.1", ctx["port"]), timeout=10) as raw:
                with ctx_ssl.wrap_socket(raw, server_hostname="127.0.0.1") as tls:
                    tls.sendall(b"GET /index.txt HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
                    data = b""
                    while True:
                        chunk = tls.recv(4096)
                        if not chunk:
                            break
                        data += chunk
            return True, data.decode("utf-8", "replace")
        except (ssl.SSLError, OSError) as exc:
            return False, str(exc)

    try:
        if not _wait_tcp("127.0.0.1", ctx["port"]):
            return _wl_fail([("lighttpd", {"stdout": _read(srv_out),
                                            "stderr": _read(srv_err), "exit_code": 1})],
                            "lighttpd did not listen on its TLS port", "runtime-failure", d)
        good_ok, good_text = get(pki["ca_crt"])
        neg_ok, neg_text = get(pki["other_crt"])
    finally:
        _stop(proc)
        outf.close()
        errf.close()
    rendered = bool(good_ok and body in good_text)
    neg_rejected = bool(not neg_ok and body not in neg_text
                        and ("CERTIFICATE_VERIFY_FAILED" in neg_text
                             or "certificate verify failed" in neg_text))
    functional_ok = rendered and neg_rejected
    res_good = {"ok": good_ok, "exit_code": 0 if good_ok else 1,
                "stdout": good_text, "stderr": "", "elapsed_seconds": 0}
    res_neg = {"ok": neg_ok, "exit_code": 0 if neg_ok else 1,
               "stdout": neg_text, "stderr": "" if neg_ok else neg_text,
               "elapsed_seconds": 0}
    return {
        "runtime_ok": rendered, "functional_ok": functional_ok,
        "failure_class": None if functional_ok else (
            "functional-failure" if rendered else "runtime-failure"),
        "residual": "none" if functional_ok else (
            "functional-divergence" if rendered else "runtime-failure"),
        "reason": None if functional_ok else (
            "lighttpd did not serve the TLS document" if not rendered else
            "the client trusting only the unrelated CA accepted lighttpd's certificate"),
        "transcript": _transcript(("lighttpd TLS + fixture CA", res_good),
                                  ("lighttpd TLS + unrelated CA (must fail)", res_neg)),
        "workload": "lighttpd: mod_openssl serves a local document + unrelated-CA reject",
        "local_only": True,
    }


def _tpm_recv(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            break
        data += chunk
    return data


def _tpm_exchange(sock: socket.socket, command: bytes) -> tuple[int, bytes]:
    sock.sendall(command)
    header = _tpm_recv(sock, 10)
    if len(header) != 10:
        return -1, b""
    _tag, size, rc = struct.unpack(">HII", header)
    return rc, _tpm_recv(sock, max(0, size - 10))


def _wl_swtpm(ctx: dict) -> dict:
    """swtpm's TPM2 command interface over its TCP data channel.

    `swtpm socket --tpm2` is started with `--flags not-need-init` so the TPM is ready to receive
    `TPM2_Startup(CLEAR)`. The workload then sends `TPM2_GetRandom(32)` and asserts the returned
    digest length, while an unknown command code must be rejected with TPM_RC_COMMAND_CODE.
    """
    d = ctx["workdir"]
    state = d / "tpmstate"
    state.mkdir(parents=True, exist_ok=True)
    ctrl = _free_port()
    log = d / "swtpm.log"
    out, err = d / "swtpm.out", d / "swtpm.err"
    prog = str(ctx["program"])
    proc, outf, errf = _spawn(
        [prog, "socket", "--tpm2", "--tpmstate", f"dir={state}",
         "--server", f"type=tcp,port={ctx['port']},bindaddr=127.0.0.1",
         "--ctrl", f"type=tcp,port={ctrl},bindaddr=127.0.0.1",
         "--flags", "not-need-init", "--log", f"file={log},level=1"],
        d, ctx["env"], out, err)
    try:
        if not _wait_tcp("127.0.0.1", ctx["port"]):
            return _wl_fail([("swtpm socket", {"stdout": _read(out), "stderr": _read(err),
                                                "exit_code": 1})],
                            "swtpm did not listen on its TCP data channel",
                            "runtime-failure", d)
        with socket.create_connection(("127.0.0.1", ctx["port"]), timeout=15) as sock:
            startup_rc, _ = _tpm_exchange(sock, bytes.fromhex("80010000000c000001440000"))
            random_rc, random_body = _tpm_exchange(
                sock, bytes.fromhex("80010000000c0000017b0020"))
            unknown_rc, _ = _tpm_exchange(sock, bytes.fromhex("80010000000a000001ff"))
    finally:
        _stop(proc)
        outf.close()
        errf.close()
    digest_len = len(random_body) - 2 if len(random_body) >= 2 else 0
    functional_ok = (startup_rc == 0 and random_rc == 0 and digest_len == 32
                     and unknown_rc == 0x143)
    transcript = "\n".join([
        f"tpm2_startup_rc=0x{startup_rc:x}",
        f"tpm2_getrandom_rc=0x{random_rc:x}",
        f"tpm2_getrandom_bytes={digest_len}",
        f"tpm2_unknown_rc=0x{unknown_rc:x}",
        f"result={'ok' if functional_ok else 'fail'}",
    ]) + "\n"
    res = {"ok": functional_ok, "exit_code": 0 if functional_ok else 1,
           "stdout": transcript, "stderr": "", "elapsed_seconds": 0}
    return {
        "runtime_ok": functional_ok, "functional_ok": functional_ok,
        "failure_class": None if functional_ok else "functional-failure",
        "residual": "none" if functional_ok else "functional-divergence",
        "reason": None if functional_ok else (
            "swtpm did not complete TPM2_Startup/GetRandom or accepted an unknown command code"),
        "transcript": _transcript(("swtpm TPM2 command interface", res)),
        "workload": ("swtpm: TPM2_Startup, TPM2_GetRandom(32) over the TCP data channel and an "
                     "unknown-command reject"),
        "local_only": True,
    }


def _wl_httping(ctx: dict) -> dict:
    """httping's HTTPS path: a real TLS peer succeeds, a plain-TCP peer fails the handshake."""
    ap, d, prog = ctx["authority_prefix"], ctx["workdir"], str(ctx["program"])
    pki = _gen_pki(ap, d)
    body = "phase25-l7-httping-fixture"
    state: dict = {}
    stop = threading.Event()
    thread = _https_fixture(ctx["port"], pki, body, state, stop)
    plain_port = _free_port()
    plain = socket.socket()
    plain.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    plain.bind(("127.0.0.1", plain_port))
    plain.listen(4)
    plain_stop = threading.Event()

    def plain_serve() -> None:
        plain.settimeout(0.5)
        while not plain_stop.is_set():
            try:
                conn, _ = plain.accept()
            except (socket.timeout, OSError):
                continue
            conn.close()

    plain_thread = threading.Thread(target=plain_serve, daemon=True)
    plain_thread.start()
    url = f"https://127.0.0.1:{ctx['port']}/phase25.txt"
    bad_url = f"https://127.0.0.1:{plain_port}/phase25.txt"
    try:
        if not _wait_tcp("127.0.0.1", ctx["port"]):
            return _wl_fail([("https fixture", {"exit_code": 0, "stdout": ""})],
                            "the local HTTPS fixture did not open its port",
                            "runtime-failure", d)
        good = _run_captured([prog, "-c", "1", "-t", "5", "-g", url, "-s"],
                             cwd=d, env=ctx["env"], timeout=45)
        neg = _run_captured([prog, "-c", "1", "-t", "3", "-g", bad_url, "-s"],
                            cwd=d, env=ctx["env"], timeout=45)
    finally:
        stop.set()
        plain_stop.set()
        state.get("listener", socket.socket()).close()
        plain.close()
        thread.join(timeout=2)
        plain_thread.join(timeout=2)
    good_text = good["stdout"] + good["stderr"]
    neg_text = neg["stdout"] + neg["stderr"]
    ok_good = bool("200 OK" in good_text and "1 connects, 1 ok" in good_text)
    ok_neg = bool("1 connects, 0 ok" in neg_text)
    functional_ok = ok_good and ok_neg
    return {
        "runtime_ok": ok_good, "functional_ok": functional_ok,
        "failure_class": None if functional_ok else (
            "functional-failure" if ok_good else "runtime-failure"),
        "residual": "none" if functional_ok else (
            "functional-divergence" if ok_good else "runtime-failure"),
        "reason": None if functional_ok else (
            "the HTTPS ping did not report 200 OK" if not ok_good else
            "a plain-TCP listener did not fail the TLS handshake"),
        "transcript": _transcript(("httping https (TLS fixture)", good),
                                  ("httping https (plain TCP, must fail)", neg)),
        "workload": ("httping: an HTTPS ping of a local page reports 200 OK + a plain-TCP peer "
                     "fails the TLS handshake"),
        "local_only": True,
    }


def _wl_libssh(ctx: dict) -> dict:
    """libssh's RSA key path: a pinned key's exact public blob, and a corrupted key reject."""
    res = _run_captured([str(ctx["program"])], cwd=ctx["workdir"], env=ctx["env"], timeout=120)
    text = res["stdout"] + res["stderr"]
    ok = bool(res["ok"] and "key_import=ok" in text and "pubkey_blob=ok" in text
              and "roundtrip=ok" in text and "tamper=rejected" in text)
    return {
        "runtime_ok": ok, "functional_ok": ok,
        "failure_class": None if ok else "functional-failure",
        "residual": "none" if ok else "functional-divergence",
        "reason": None if ok else (
            "libssh did not import the pinned RSA key to its exact public blob, or accepted a "
            "corrupted private-key encoding"),
        "transcript": _transcript(("libssh RSA key path", res)),
        "workload": ("libssh: import a pinned RSA key, compare its exported public blob and "
                     "reject a corrupted encoding"),
        "local_only": True,
    }



def _wl_ncat(ctx: dict) -> dict:
    """Ncat's TLS server against a verifying local client."""
    d = ctx["workdir"]
    prog = str(ctx["program"])
    pki = _gen_pki(ctx["authority_prefix"], d / "pki")
    payload = b"template-payload\n"

    def run(ca: Path) -> tuple[bool, str, str]:
        port = _free_port()
        server = subprocess.Popen(
            [prog, "--ssl", "--ssl-cert", str(pki["srv_crt"]), "--ssl-key",
             str(pki["srv_key"]), "-l", "127.0.0.1", str(port), "--sh-exec", "cat",
             "--keep-open"], cwd=str(d), env=ctx["env"], stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True)
        try:
            if not _wait_tcp("127.0.0.1", port, timeout=10):
                return False, "", "the TLS server did not listen"
            client = _tls_context(pki, ca=ca)
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=8) as sock:
                    with client.wrap_socket(sock, server_hostname="localhost") as tls:
                        tls.sendall(payload)
                        tls.settimeout(8)
                        data = tls.recv(4096)
                return data == payload, data.decode("latin-1", "replace"), ""
            except (OSError, ssl.SSLError) as exc:
                return False, "", f"{type(exc).__name__}: {exc}"
        finally:
            _stop(server)

    good, good_data, good_err = run(pki["ca_crt"])
    bad, _, bad_err = run(pki["other_crt"])
    functional = bool(good and not bad)
    return {
        "runtime_ok": good, "functional_ok": functional,
        "failure_class": None if functional else (
            "functional-failure" if good else "runtime-failure"),
        "residual": "none" if functional else (
            "functional-divergence" if good else "runtime-failure"),
        "reason": None if functional else (
            "the TLS server did not echo the payload" if not good else
            "a client trusting only the unrelated CA was not rejected"),
        "transcript": _transcript(("ncat TLS echo", {
            "exit_code": 0 if good else 1, "stdout": good_data, "stderr": good_err}),
            ("ncat unrelated CA (must fail)", {
                "exit_code": 0 if bad else 1, "stderr": bad_err})),
        "workload": "ncat: TLS echo + payload match + unrelated-CA reject",
        "local_only": True,
    }


def _wl_unbound(ctx: dict) -> dict:
    """Unbound's DNS-over-TLS forwarding path between two local resolvers."""
    d = ctx["workdir"]
    prog = str(ctx["program"])
    pki = _gen_pki(ctx["authority_prefix"], d / "pki")
    name = "fixture.example.com."
    answer = "192.0.2.1"

    def config(port: int, *, upstream: bool, ca: Path) -> Path:
        path = d / ("upstream.conf" if upstream else "downstream.conf")
        if upstream:
            text = (f'server:\n  verbosity: 0\n  interface: 127.0.0.1@{port}\n'
                    f'  tls-port: {port}\n  tls-service-key: "{pki["srv_key"]}"\n'
                    f'  tls-service-pem: "{pki["srv_crt"]}"\n'
                    f'  do-not-query-localhost: no\n  module-config: "iterator"\n'
                    f'  local-zone: "{name}" static\n'
                    f'  local-data: "{name} 60 IN A {answer}"\n'
                    f'  do-daemonize: no\n  directory: "{d}"\n  username: ""\n'
                    f'  chroot: ""\n  pidfile: ""\n  use-syslog: no\n  logfile: ""\n')
        else:
            text = (f'server:\n  verbosity: 4\n  interface: 127.0.0.1@{port}\n'
                    f'  do-not-query-localhost: no\n  module-config: "iterator"\n'
                    f'  tls-cert-bundle: "{ca}"\n  do-daemonize: no\n'
                    f'  directory: "{d}"\n  username: ""\n  chroot: ""\n'
                    f'  pidfile: ""\n  use-syslog: no\n  logfile: ""\n'
                    f'forward-zone:\n  name: "."\n'
                    f'  forward-addr: 127.0.0.1@{up_port}#localhost\n'
                    f'  forward-tls-upstream: yes\n')
        path.write_text(text, encoding="utf-8")
        return path

    def query(port: int) -> tuple[bool, str]:
        packet = struct.pack(">HHHHHH", 0x4c37, 0x0100, 1, 0, 0, 0)
        for part in name.rstrip(".").split("."):
            packet += bytes([len(part)]) + part.encode("ascii")
        packet += b"\x00" + struct.pack(">HH", 1, 1)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(8)
        try:
            sock.sendto(packet, ("127.0.0.1", port))
            reply, _ = sock.recvfrom(4096)
        except OSError as exc:
            return False, str(exc)
        finally:
            sock.close()
        rcode = reply[3] & 0x0F if len(reply) >= 4 else -1
        return (rcode == 0 and socket.inet_aton(answer) in reply,
                f"rcode={rcode} reply={reply.hex()}")

    up_port = _free_port()
    down_port = _free_port()
    up_conf = config(up_port, upstream=True, ca=pki["ca_crt"])
    down_conf = config(down_port, upstream=False, ca=pki["ca_crt"])
    up_log, down_log = d / "upstream.log", d / "downstream.log"
    up, up_out, up_err = _spawn([prog, "-c", str(up_conf)], d, ctx["env"], up_log,
                                d / "upstream.err")
    down, down_out, down_err = _spawn([prog, "-c", str(down_conf)], d, ctx["env"], down_log,
                                      d / "downstream.err")
    try:
        up_ready = _wait_tcp("127.0.0.1", up_port, timeout=10)
        time.sleep(0.5)
        down_ready = _wait_tcp("127.0.0.1", down_port, timeout=10)
        time.sleep(0.2)
        good_ok, good_rc = query(down_port)
        down_text = _read(down_log) + _read(d / "downstream.err")
        good_ok = bool(up_ready and down_ready and good_ok
                       and "using TLS encryption" in down_text)
    finally:
        _stop(up)
        _stop(down)

    bad_port = _free_port()
    bad_conf = config(bad_port, upstream=False, ca=pki["other_crt"])
    up2, up2_out, up2_err = _spawn([prog, "-c", str(up_conf)], d, ctx["env"],
                                    d / "upstream2.log", d / "upstream2.err")
    down2, down2_out, down2_err = _spawn([prog, "-c", str(bad_conf)], d, ctx["env"],
                                         d / "downstream2.log", d / "downstream2.err")
    try:
        _wait_tcp("127.0.0.1", up_port, timeout=10)
        _wait_tcp("127.0.0.1", bad_port, timeout=10)
        time.sleep(0.5)
        bad_ok, bad_rc = query(bad_port)
    finally:
        _stop(up2)
        _stop(down2)

    functional = bool(good_ok and not bad_ok)
    return {
        "runtime_ok": good_ok, "functional_ok": functional,
        "failure_class": None if functional else (
            "functional-failure" if good_ok else "runtime-failure"),
        "residual": "none" if functional else (
            "functional-divergence" if good_ok else "runtime-failure"),
        "reason": None if functional else (
            "the DoT forwarder did not resolve the fixture zone" if not good_ok else
            "a resolver trusting only the unrelated CA still resolved the zone"),
        "transcript": _transcript(("unbound DoT forwarder", {
            "exit_code": 0 if good_ok else 1, "stdout": f"answer={good_ok} {good_rc}"}),
            ("unbound unrelated CA", {
                "exit_code": 0 if bad_ok else 1, "stdout": f"answer={bad_ok} {bad_rc}"}),
            ("downstream log", {"exit_code": 0,
                                "stdout": (_read(down_log) + _read(d / "downstream.err"))[-800:]}),
            ("upstream log", {"exit_code": 0,
                              "stdout": (_read(up_log) + _read(d / "upstream.err"))[-400:]})),
        "workload": "unbound: DNS-over-TLS forward to a local TLS resolver + unrelated-CA reject",
        "local_only": True,
    }


def _wl_qpdf(ctx: dict) -> dict:
    """qpdf's OpenSSL crypto provider encrypting/decrypting a PDF."""
    d = ctx["workdir"]
    prog = str(ctx["program"])
    empty, encrypted, decrypted, rejected = (d / "empty.pdf", d / "enc.pdf",
                                             d / "dec.pdf", d / "bad.pdf")
    make = _run_captured([prog, "--empty", str(empty)], cwd=d, env=ctx["env"],
                         timeout=30)
    encrypt = _run_captured([prog, "--encrypt", "user", "owner", "256", "--",
                             str(empty), str(encrypted)], cwd=d, env=ctx["env"], timeout=30)
    show = _run_captured([prog, "--show-encryption", str(encrypted)], cwd=d, env=ctx["env"],
                         timeout=30)
    decrypt = _run_captured([prog, "--password=user", "--decrypt", str(encrypted),
                             str(decrypted)], cwd=d, env=ctx["env"], timeout=30)
    wrong = _run_captured([prog, "--password=wrong", "--decrypt", str(encrypted),
                           str(rejected)], cwd=d, env=ctx["env"], timeout=30)
    runtime_ok = bool(make["ok"] and encrypt["ok"] and show["ok"] and decrypt["ok"]
                      and decrypted.is_file())
    functional = bool(runtime_ok and "R = 6" in show["stdout"] and not wrong["ok"]
                      and not rejected.is_file())
    return {
        "runtime_ok": runtime_ok, "functional_ok": functional,
        "failure_class": None if functional else (
            "functional-failure" if runtime_ok else "runtime-failure"),
        "residual": "none" if functional else (
            "functional-divergence" if runtime_ok else "runtime-failure"),
        "reason": None if functional else (
            "qpdf did not encrypt/decrypt a PDF with its OpenSSL provider" if not runtime_ok else
            "the encryption parameters or wrong-password rejection were wrong"),
        "transcript": _transcript(("qpdf --empty", make), ("qpdf encrypt AES-256", encrypt),
                                  ("qpdf show-encryption", show),
                                  ("qpdf decrypt", decrypt),
                                  ("qpdf wrong password (must fail)", wrong)),
        "workload": "qpdf: AES-256 PDF encryption + R=6 + correct decrypt + wrong-password reject",
        "local_only": True,
    }


def _wl_efitools(ctx: dict) -> dict:
    """efitools' certificate-to-ESL and authenticated-variable signing path."""
    d = ctx["workdir"]
    prog = str(ctx["program"])
    cert_to_esl = Path(prog).with_name("cert-to-efi-sig-list")
    pki = _gen_pki(ctx["authority_prefix"], d / "pki")
    esl = d / "fixture.esl"
    good = d / "good.auth"
    bad = d / "bad.auth"
    encode = _run_captured([str(cert_to_esl), str(pki["srv_crt"]), str(esl)], cwd=d,
                           env=ctx["env"], timeout=30)
    sign = _run_captured([prog, "-k", str(pki["srv_key"]), "-c", str(pki["srv_crt"]),
                          "db", str(esl), str(good)], cwd=d, env=ctx["env"], timeout=30)
    mismatch = _run_captured([prog, "-k", str(pki["other_key"]), "-c", str(pki["srv_crt"]),
                              "db", str(esl), str(bad)], cwd=d, env=ctx["env"], timeout=30)
    runtime_ok = bool(encode["ok"] and sign["ok"] and good.is_file())
    functional = bool(runtime_ok and esl.stat().st_size > 0 and good.stat().st_size > 1000
                      and (not bad.is_file() or bad.stat().st_size < 1000))
    return {
        "runtime_ok": runtime_ok, "functional_ok": functional,
        "failure_class": None if functional else (
            "functional-failure" if runtime_ok else "runtime-failure"),
        "residual": "none" if functional else (
            "functional-divergence" if runtime_ok else "runtime-failure"),
        "reason": None if functional else (
            "the EFI signature list could not be encoded and signed" if not runtime_ok else
            "the mismatched key was not refused"),
        "transcript": _transcript(("cert-to-efi-sig-list", encode),
                                  ("sign-efi-sig-list", sign),
                                  ("mismatched key (must be refused)", mismatch),
                                  ("sizes", {"exit_code": 0, "stdout":
                                   f"esl={esl.stat().st_size if esl.is_file() else -1} "
                                   f"good={good.stat().st_size if good.is_file() else -1} "
                                   f"bad={bad.stat().st_size if bad.is_file() else -1}"})),
        "workload": "efitools: certificate -> ESL -> signed authenticated variable; mismatched key refused",
        "local_only": True,
    }


def _wl_nagios_smtp(ctx: dict) -> dict:
    """check_smtp's STARTTLS path against a local SMTP peer."""
    d = ctx["workdir"]
    prog = str(ctx["program"])
    pki = _gen_pki(ctx["authority_prefix"], d / "pki")

    def run(advertise: bool) -> dict:
        port = _free_port()
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", port))
        listener.listen(5)
        listener.settimeout(15)
        sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        sctx.load_cert_chain(str(pki["srv_crt"]), str(pki["srv_key"]))
        state = {"starttls": False, "error": ""}

        def handle(conn: socket.socket) -> None:
            try:
                stream = conn.makefile("rwb", buffering=0)
                stream.write(b"220 fixture ESMTP\r\n")
                tls = False
                while True:
                    line = stream.readline()
                    if not line:
                        break
                    cmd = line.strip().split(b" ")[0].upper()
                    if cmd == b"EHLO":
                        if advertise and not tls:
                            stream.write(b"250-fixture\r\n250-STARTTLS\r\n"
                                         b"250 SIZE 10240000\r\n")
                        else:
                            stream.write(b"250-fixture\r\n250 SIZE 10240000\r\n")
                    elif cmd == b"HELO":
                        stream.write(b"250 fixture\r\n")
                    elif cmd == b"STARTTLS":
                        if advertise:
                            stream.write(b"220 Ready to start TLS\r\n")
                            conn = sctx.wrap_socket(conn, server_side=True)
                            stream = conn.makefile("rwb", buffering=0)
                            tls = True
                            state["starttls"] = True
                        else:
                            stream.write(b"454 TLS not available\r\n")
                    elif cmd == b"QUIT":
                        stream.write(b"221 Bye\r\n")
                        break
                    else:
                        stream.write(b"250 OK\r\n")
                conn.close()
            except (OSError, ssl.SSLError) as exc:
                state["error"] = str(exc)

        def serve() -> None:
            try:
                conn, _ = listener.accept()
                handle(conn)
            except OSError as exc:
                state["error"] = str(exc)
            finally:
                listener.close()

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        res = _run_captured([prog, "-H", "127.0.0.1", "-p", str(port), "-S", "-e", "220",
                             "-t", "10"], cwd=d, env=ctx["env"], timeout=25)
        thread.join(timeout=2)
        return res

    good = run(True)
    bad = run(False)
    pos_ok = bool(good["ok"] and "SMTP OK" in good["stdout"])
    neg_ok = bool(not bad["ok"] and "TLS not supported" in (bad["stdout"] + bad["stderr"]))
    functional = bool(pos_ok and neg_ok)
    return {
        "runtime_ok": pos_ok, "functional_ok": functional,
        "failure_class": None if functional else (
            "functional-failure" if pos_ok else "runtime-failure"),
        "residual": "none" if functional else (
            "functional-divergence" if pos_ok else "runtime-failure"),
        "reason": None if functional else (
            "check_smtp did not complete STARTTLS" if not pos_ok else
            "a peer without STARTTLS was not rejected"),
        "transcript": _transcript(("check_smtp STARTTLS", good),
                                  ("check_smtp no STARTTLS (must fail)", bad)),
        "workload": "check_smtp: STARTTLS exchange + no-STARTTLS peer reject",
        "local_only": True,
    }


def _wl_nagios_ldap(ctx: dict) -> dict:
    """check_ldap's LDAPS path against a local LDAP peer."""
    d = ctx["workdir"]
    prog = str(ctx["program"])
    pki = _gen_pki(ctx["authority_prefix"], d / "pki")

    def tlv(tag: int, value: bytes) -> bytes:
        return bytes([tag, len(value)]) + value

    def response(mid: int, code: int, app: int) -> bytes:
        body = bytes([app, 7, 0x0a, 1, code, 0x04, 0, 0x04, 0])
        return tlv(0x30, tlv(0x02, bytes([mid])) + body)

    def run(password: str) -> tuple[dict, dict]:
        port = _free_port()
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", port))
        listener.listen(5)
        listener.settimeout(15)
        sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        sctx.load_cert_chain(str(pki["srv_crt"]), str(pki["srv_key"]))
        state = {"bound": False, "searched": False, "error": ""}

        def handle(conn: socket.socket) -> None:
            tls = sctx.wrap_socket(conn, server_side=True)
            tls.settimeout(10)
            data = b""

            def read_message():
                nonlocal data
                while len(data) < 2:
                    data += tls.recv(4096)
                if data[0] != 0x30:
                    return None
                length, head = data[1], 2
                if length & 0x80:
                    count = length & 0x7F
                    while len(data) < 2 + count:
                        data += tls.recv(4096)
                    length = int.from_bytes(data[2:2 + count], "big")
                    head = 2 + count
                while len(data) < head + length:
                    data += tls.recv(4096)
                message, data = data[:head + length], data[head + length:]
                return message

            while True:
                message = read_message()
                if not message:
                    break
                pos = 2 if message[1] < 0x80 else 2 + (message[1] & 0x7F)
                ident_len = message[pos + 1]
                mid = int.from_bytes(message[pos + 2:pos + 2 + ident_len], "big")
                q = pos + 2 + ident_len
                op, op_len = message[q], message[q + 1]
                body = message[q + 2:q + 2 + op_len]
                if op == 0x60:
                    r = 2 + body[1]
                    r += 2 + body[r + 1]
                    pw_len = body[r + 1]
                    presented = body[r + 2:r + 2 + pw_len].decode("latin-1")
                    ok = presented == "secret"
                    state["bound"] = ok
                    tls.sendall(response(mid, 0 if ok else 49, 0x61))
                elif op == 0x42:
                    break
                else:
                    state["searched"] = True
                    tls.sendall(response(mid, 0, 0x65))
            tls.close()

        def serve() -> None:
            try:
                conn, _ = listener.accept()
                handle(conn)
            except (OSError, ssl.SSLError) as exc:
                state["error"] = str(exc)
            finally:
                listener.close()

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        env = dict(ctx["env"], LDAPTLS_REQCERT="never")
        res = _run_captured([prog, "-H", "127.0.0.1", "-p", str(port), "-S",
                             "-D", "cn=admin", "-P", password, "-b", "dc=example,dc=com",
                             "-t", "8"], cwd=d, env=env, timeout=25)
        thread.join(timeout=2)
        return res, state

    good, good_state = run("secret")
    bad, bad_state = run("wrong")
    pos_ok = bool(good["ok"] and "LDAP OK" in good["stdout"] and good_state["bound"])
    neg_ok = bool(not bad["ok"] and not bad_state["bound"])
    functional = bool(pos_ok and neg_ok)
    return {
        "runtime_ok": pos_ok, "functional_ok": functional,
        "failure_class": None if functional else (
            "functional-failure" if pos_ok else "runtime-failure"),
        "residual": "none" if functional else (
            "functional-divergence" if pos_ok else "runtime-failure"),
        "reason": None if functional else (
            "check_ldap did not complete the LDAPS bind/search" if not pos_ok else
            "the wrong password was not rejected"),
        "transcript": _transcript(("check_ldap LDAPS", good),
                                  ("check_ldap wrong password (must fail)", bad)),
        "workload": "check_ldap: LDAPS simple bind + search + wrong-password reject",
        "local_only": True,
    }


def _wl_paho(ctx: dict) -> dict:
    """paho.mqtt.c's TLS CONNECT/CONNACK path against a local peer."""
    d = ctx["workdir"]
    prog = str(ctx["program"])
    pki = _gen_pki(ctx["authority_prefix"], d / "pki")

    def run(ca: Path) -> tuple[dict, dict]:
        port = _free_port()
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", port))
        listener.listen(5)
        listener.settimeout(15)
        sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        sctx.load_cert_chain(str(pki["srv_crt"]), str(pki["srv_key"]))
        state = {"connack": False, "error": ""}

        def serve() -> None:
            try:
                conn, _ = listener.accept()
                with sctx.wrap_socket(conn, server_side=True) as tls:
                    tls.settimeout(10)
                    header = tls.recv(1)
                    if header == b"\x10":
                        remaining, shift = 0, 0
                        while True:
                            byte = tls.recv(1)[0]
                            remaining += (byte & 0x7F) << shift
                            if not byte & 0x80:
                                break
                            shift += 7
                        body = b""
                        while len(body) < remaining:
                            body += tls.recv(remaining - len(body))
                        tls.sendall(b"\x20\x02\x00\x00")
                        state["connack"] = True
            except (OSError, ssl.SSLError) as exc:
                state["error"] = str(exc)
            finally:
                listener.close()

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        res = _run_captured([prog, str(ca), str(port)], cwd=d, env=ctx["env"], timeout=25)
        thread.join(timeout=2)
        return res, state

    good, good_state = run(pki["ca_crt"])
    bad, _ = run(pki["other_crt"])
    pos_ok = bool(good["ok"] and "connect=ok" in good["stdout"] and good_state["connack"])
    neg_ok = bool(not bad["ok"])
    functional = bool(pos_ok and neg_ok)
    return {
        "runtime_ok": pos_ok, "functional_ok": functional,
        "failure_class": None if functional else (
            "functional-failure" if pos_ok else "runtime-failure"),
        "residual": "none" if functional else (
            "functional-divergence" if pos_ok else "runtime-failure"),
        "reason": None if functional else (
            "the MQTT CONNECT did not reach CONNACK over TLS" if not pos_ok else
            "a client trusting only the unrelated CA was not rejected"),
        "transcript": _transcript(("paho TLS CONNECT", good),
                                  ("paho unrelated CA (must fail)", bad)),
        "workload": "paho.mqtt.c: TLS CONNECT/CONNACK + unrelated-CA reject",
        "local_only": True,
    }


def _wl_srtp(ctx: dict) -> dict:
    """libsrtp's OpenSSL protect/unprotect path."""
    res = _run_captured([str(ctx["program"])], cwd=ctx["workdir"], env=ctx["env"],
                        timeout=30)
    text = res["stdout"] + res["stderr"]
    runtime_ok = bool(res["ok"] and "protect=ok" in text and "unprotect=ok" in text)
    functional = bool(runtime_ok and "wrong-key=rejected" in text)
    return {
        "runtime_ok": runtime_ok, "functional_ok": functional,
        "failure_class": None if functional else (
            "functional-failure" if runtime_ok else "runtime-failure"),
        "residual": "none" if functional else (
            "functional-divergence" if runtime_ok else "runtime-failure"),
        "reason": None if functional else (
            "libsrtp did not protect/unprotect the RTP packet" if not runtime_ok else
            "a session with the wrong key was not rejected"),
        "transcript": _transcript(("libsrtp protect/unprotect", res)),
        "workload": "libsrtp: AES-CM-128/HMAC-SHA1 protect + unprotect + wrong-key reject",
        "local_only": True,
    }


def _wl_rabbitmq(ctx: dict) -> dict:
    """rabbitmq-c's TLS socket open against a local peer."""
    d = ctx["workdir"]
    prog = str(ctx["program"])
    pki = _gen_pki(ctx["authority_prefix"], d / "pki")

    def run(ca: Path) -> dict:
        port = _free_port()
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", port))
        listener.listen(5)
        listener.settimeout(15)
        sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        sctx.load_cert_chain(str(pki["srv_crt"]), str(pki["srv_key"]))

        def serve() -> None:
            try:
                conn, _ = listener.accept()
                with sctx.wrap_socket(conn, server_side=True) as tls:
                    tls.settimeout(8)
                    try:
                        tls.recv(64)
                    except OSError:
                        pass
            except (OSError, ssl.SSLError):
                pass
            finally:
                listener.close()

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        res = _run_captured([prog, str(ca), str(port)], cwd=d, env=ctx["env"], timeout=25)
        thread.join(timeout=2)
        return res

    good = run(pki["ca_crt"])
    bad = run(pki["other_crt"])
    pos_ok = bool(good["ok"] and "open=ok" in good["stdout"])
    neg_ok = bool(not bad["ok"])
    functional = bool(pos_ok and neg_ok)
    return {
        "runtime_ok": pos_ok, "functional_ok": functional,
        "failure_class": None if functional else (
            "functional-failure" if pos_ok else "runtime-failure"),
        "residual": "none" if functional else (
            "functional-divergence" if pos_ok else "runtime-failure"),
        "reason": None if functional else (
            "the AMQP SSL socket did not open" if not pos_ok else
            "a client trusting only the unrelated CA was not rejected"),
        "transcript": _transcript(("rabbitmq-c TLS open", good),
                                  ("rabbitmq-c unrelated CA (must fail)", bad)),
        "workload": "rabbitmq-c: verified TLS socket open + unrelated-CA reject",
        "local_only": True,
    }



# --------------------------------------------------------------------------------------------
# Phase-25 L7 onboarding batch (b15): ten deterministic local workloads.
# Each fixture is loopback-only and its negative control is a real protocol/CA/input decision.
# --------------------------------------------------------------------------------------------

def _wl_vsftpd(ctx: dict) -> dict:
    """vsftpd FTPS: anonymous AUTH TLS + PROT P retrieval; an unrelated CA is refused."""
    import ftplib
    import io
    ap, port, d = ctx["authority_prefix"], ctx["port"], ctx["workdir"]
    pki = _gen_pki(ap, d / "pki")
    docroot, empty = d / "docroot", d / "empty"
    docroot.mkdir(parents=True, exist_ok=True)
    empty.mkdir(parents=True, exist_ok=True)
    payload = "phase25-l7-vsftpd\n"
    (docroot / "payload.txt").write_text(payload, encoding="utf-8")
    pasv = _free_port()
    if pasv > 60000:
        pasv = 40000
    conf = d / "vsftpd.conf"
    conf.write_text("\n".join([
        "listen=YES", f"listen_port={port}", "background=NO",
        "anonymous_enable=YES", "local_enable=NO", "write_enable=NO",
        f"anon_root={docroot}", "ftp_username=daemon", "nopriv_user=daemon",
        f"secure_chroot_dir={empty}", "anon_world_readable_only=NO",
        "ssl_enable=YES", "allow_anon_ssl=YES", "force_local_logins_ssl=NO",
        "force_local_data_ssl=YES", "require_ssl_reuse=NO",
        f"rsa_cert_file={pki['srv_crt']}", f"rsa_private_key_file={pki['srv_key']}",
        "pasv_enable=YES", f"pasv_min_port={pasv}", f"pasv_max_port={pasv + 40}",
        "pasv_address=127.0.0.1", "seccomp_sandbox=NO",
    ]) + "\n", encoding="utf-8")
    proc, of, ef = _spawn([str(ctx["program"]), str(conf)], d, ctx["env"],
                          d / "vsftpd.out", d / "vsftpd.err")
    good = ""
    neg_text = ""
    try:
        if not _wait_tcp("127.0.0.1", port):
            return _wl_fail([("vsftpd", {"exit_code": 0, "stdout": _read(d / "vsftpd.err")})],
                            "vsftpd did not open its control port", "runtime-failure", d)
        session = ssl.create_default_context(cafile=str(pki["ca_crt"]))
        ftp = ftplib.FTP_TLS(context=session)
        ftp.connect("127.0.0.1", port, timeout=15)
        ftp.login("anonymous", "l7@example")
        ftp.prot_p()
        buf = io.BytesIO()
        ftp.retrbinary("RETR payload.txt", buf.write)
        ftp.quit()
        good = buf.getvalue().decode("utf-8", "ignore")
        try:
            bad = ssl.create_default_context(cafile=str(pki["other_crt"]))
            nftp = ftplib.FTP_TLS(context=bad)
            nftp.connect("127.0.0.1", port, timeout=15)
            nftp.login("anonymous", "l7@example")
            nftp.quit()
            neg_text = "accepted"
        except (ssl.SSLError, OSError) as exc:
            neg_text = f"rejected: {exc}"
    finally:
        _stop(proc)
        of.close()
        ef.close()
    ok = good == payload
    neg_ok = neg_text.startswith("rejected")
    functional = ok and neg_ok
    return {
        "runtime_ok": ok, "functional_ok": functional,
        "failure_class": None if functional else ("functional-failure" if ok else "runtime-failure"),
        "residual": "none" if functional else ("functional-divergence" if ok else "runtime-failure"),
        "reason": None if functional else (
            "the FTPS retrieval did not return the fixture" if not ok else
            "a client trusting an unrelated CA was not refused"),
        "transcript": _transcript(("vsftpd FTPS positive",
                                   {"exit_code": 0, "stdout": good}),
                                  ("vsftpd unrelated CA", {"exit_code": 0, "stdout": neg_text})),
        "workload": ("vsftpd: anonymous AUTH TLS login and PROT P retrieval with an "
                     "unrelated-CA reject"),
        "local_only": True,
    }


def _wl_apache(ctx: dict) -> dict:
    """httpd + static mod_ssl: verified GET; an unrelated CA is refused."""
    import http.client
    ap, port, d = ctx["authority_prefix"], ctx["port"], ctx["workdir"]
    pki = _gen_pki(ap, d / "pki")
    docroot, logs = d / "docroot", d / "logs"
    docroot.mkdir(parents=True, exist_ok=True)
    logs.mkdir(parents=True, exist_ok=True)
    payload = "phase25-l7-httpd\n"
    (docroot / "payload.txt").write_text(payload, encoding="utf-8")
    root = ctx["root"]
    lines = [
        f"ServerRoot {d}", f"Listen 127.0.0.1:{port}",
        f"LoadModule authz_core_module {root}/modules/aaa/.libs/mod_authz_core.so",
        f"LoadModule dir_module {root}/modules/mappers/.libs/mod_dir.so",
        f"LoadModule mime_module {root}/modules/http/.libs/mod_mime.so",
        f"LoadModule log_config_module {root}/modules/loggers/.libs/mod_log_config.so",
        f"LoadModule unixd_module {root}/modules/arch/unix/.libs/mod_unixd.so",
        "SSLEngine on", f"SSLCertificateFile {pki['srv_crt']}",
        f"SSLCertificateKeyFile {pki['srv_key']}",
        f"DocumentRoot {docroot}", f"ErrorLog {logs}/error.log",
        f"PidFile {d}/httpd.pid", f"TypesConfig {root}/docs/conf/mime.types",
        "LogLevel warn", "User daemon", "Group daemon",
    ]
    conf = d / "httpd.conf"
    conf.write_text("\n".join(lines) + "\n", encoding="utf-8")
    proc, of, ef = _spawn([str(ctx["program"]), "-f", str(conf), "-DFOREGROUND"], d, ctx["env"],
                          d / "httpd.out", d / "httpd.err")
    good = ""
    neg_text = ""
    try:
        if not _wait_tcp("127.0.0.1", port):
            return _wl_fail([("httpd", {"exit_code": 0, "stdout": _read(logs / "error.log")})],
                            "httpd did not open its TLS port", "runtime-failure", d)
        gctx = ssl.create_default_context(cafile=str(pki["ca_crt"]))
        conn = http.client.HTTPSConnection("127.0.0.1", port, context=gctx, timeout=15)
        conn.request("GET", "/payload.txt")
        resp = conn.getresponse()
        good = resp.read().decode("utf-8", "ignore")
        conn.close()
        try:
            bctx = ssl.create_default_context(cafile=str(pki["other_crt"]))
            bconn = http.client.HTTPSConnection("127.0.0.1", port, context=bctx, timeout=15)
            bconn.request("GET", "/payload.txt")
            bconn.getresponse().read()
            bconn.close()
            neg_text = "accepted"
        except (ssl.SSLError, OSError) as exc:
            neg_text = f"rejected: {exc}"
    finally:
        _stop(proc)
        of.close()
        ef.close()
    ok = good == payload
    neg_ok = neg_text.startswith("rejected")
    functional = ok and neg_ok
    return {
        "runtime_ok": ok, "functional_ok": functional,
        "failure_class": None if functional else ("functional-failure" if ok else "runtime-failure"),
        "residual": "none" if functional else ("functional-divergence" if ok else "runtime-failure"),
        "reason": None if functional else (
            "the TLS GET did not return the fixture" if not ok else
            "a client trusting an unrelated CA was not refused"),
        "transcript": _transcript(("httpd TLS positive", {"exit_code": 0, "stdout": good}),
                                  ("httpd unrelated CA", {"exit_code": 0, "stdout": neg_text})),
        "workload": "httpd static mod_ssl serves the fixture with an unrelated-CA reject",
        "local_only": True,
    }


def _wl_ssldump(ctx: dict) -> dict:
    """ssldump prints a live loopback TLS handshake; a plaintext exchange has no handshake."""
    ap, port, d = ctx["authority_prefix"], ctx["port"], ctx["workdir"]
    pki = _gen_pki(ap, d / "pki")
    cap = d / "cap.txt"
    plain_port = _free_port()

    def capture(kind: str, use_port: int, out: Path) -> str:
        proc = subprocess.Popen(
            ["stdbuf", "-oL", "-eL", str(ctx["program"]), "-i", "lo", "-a", "-A",
             f"tcp port {use_port}"],
            cwd=str(d), env=ctx["env"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True)
        time.sleep(0.8)
        try:
            if kind == "tls":
                server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                server_ctx.load_cert_chain(certfile=str(pki["srv_pem"]))
                listener = socket.socket()
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind(("127.0.0.1", use_port))
                listener.listen(2)

                def serve() -> None:
                    try:
                        conn, _ = listener.accept()
                        with server_ctx.wrap_socket(conn, server_side=True) as tls:
                            tls.recv(64)
                    except (OSError, ssl.SSLError):
                        pass

                thread = threading.Thread(target=serve, daemon=True)
                thread.start()
                cctx = ssl.create_default_context()
                cctx.check_hostname = False
                cctx.verify_mode = ssl.CERT_NONE
                cli = cctx.wrap_socket(socket.create_connection(("127.0.0.1", use_port),
                                                                timeout=10),
                                       server_hostname="127.0.0.1")
                cli.sendall(b"hello")
                cli.close()
                thread.join(timeout=3)
                listener.close()
            else:
                listener = socket.socket()
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind(("127.0.0.1", use_port))
                listener.listen(2)
                cli = socket.create_connection(("127.0.0.1", use_port), timeout=10)
                conn, _ = listener.accept()
                conn.sendall(b"phase25-l7-ssldump-plaintext\n")
                cli.recv(64)
                cli.close()
                conn.close()
                listener.close()
            time.sleep(1.2)
        finally:
            _stop(proc)
        try:
            data = proc.stdout.read() if proc.stdout else ""
        except (OSError, ValueError):
            data = ""
        out.write_text(data, encoding="utf-8")
        return data

    good = capture("tls", port, cap)
    neg = capture("plain", plain_port, d / "plain.txt")
    ok = "ClientHello" in good and "ServerHello" in good
    neg_ok = "Handshake" not in neg and "ClientHello" not in neg
    functional = ok and neg_ok
    return {
        "runtime_ok": ok, "functional_ok": functional,
        "failure_class": None if functional else ("functional-failure" if ok else "runtime-failure"),
        "residual": "none" if functional else ("functional-divergence" if ok else "runtime-failure"),
        "reason": None if functional else (
            "ssldump did not print both handshake messages" if not ok else
            "a plaintext exchange produced a handshake record"),
        "transcript": _transcript(("ssldump live TLS capture", {"exit_code": 0, "stdout": good[-3000:]}),
                                  ("ssldump plaintext capture", {"exit_code": 0, "stdout": neg[-1000:]})),
        "workload": ("ssldump: live loopback handshake parsed and plaintext control with no "
                     "handshake record"),
        "local_only": True,
    }


def _wl_yara(ctx: dict) -> dict:
    """YARA hash rule: the fixture's SHA-256 matches, a wrong digest does not."""
    d = ctx["workdir"]
    payload = d / "payload.bin"
    payload.write_bytes(b"phase25-l7-yara\n")
    digest = hashlib.sha256(payload.read_bytes()).hexdigest()
    ok_rule = d / "ok.yar"
    bad_rule = d / "bad.yar"
    ok_rule.write_text(
        'import "hash"\nrule l7_match { condition: hash.sha256(0, filesize) == '
        f'"{digest}" }}\n', encoding="utf-8")
    bad_rule.write_text(
        'import "hash"\nrule l7_match { condition: hash.sha256(0, filesize) == '
        f'"{("0" * 64)}" }}\n', encoding="utf-8")
    good = _run_captured([str(ctx["program"]), str(ok_rule), str(payload)], cwd=d,
                         env=ctx["env"], timeout=30)
    neg = _run_captured([str(ctx["program"]), str(bad_rule), str(payload)], cwd=d,
                        env=ctx["env"], timeout=30)
    good_text = good["stdout"] + good["stderr"]
    neg_text = neg["stdout"] + neg["stderr"]
    ok = "l7_match" in good_text
    neg_ok = "l7_match" not in neg_text
    functional = ok and neg_ok
    return {
        "runtime_ok": ok, "functional_ok": functional,
        "failure_class": None if functional else ("functional-failure" if ok else "runtime-failure"),
        "residual": "none" if functional else ("functional-divergence" if ok else "runtime-failure"),
        "reason": None if functional else (
            "the SHA-256 rule did not match the fixture" if not ok else
            "the wrong-digest rule matched"),
        "transcript": _transcript(("yara matching rule", good), ("yara wrong digest", neg)),
        "workload": "yara: hash.sha256 rule matches the fixture and a wrong digest does not",
        "local_only": True,
    }


def _wl_bruteforce(ctx: dict) -> dict:
    """bruteforce-salted-openssl recovers the fixture password; a word list without it does not."""
    d = ctx["workdir"]
    # The ciphertext is a peer fixture produced by the admitted authority's own `openssl enc`,
    # never by the subject: the family under test is the brute-force EVP consumer.
    ossl = ctx["authority_prefix"] / "bin" / "openssl"
    plain = d / "plain.bin"
    enc = d / "enc.bin"
    plain.write_bytes(b"phase25-l7-bruteforce\n")
    env = _auth_env(ctx["authority_prefix"])
    encres = _run_captured([str(ossl), "enc", "-aes-256-cbc", "-md", "sha256",
                            "-pass", "pass:phase25", "-in", str(plain), "-out", str(enc)],
                           cwd=d, env=env, timeout=30)
    words = d / "words.txt"
    words.write_text("alpha\nbeta\nphase25\n", encoding="utf-8")
    words_bad = d / "words-bad.txt"
    words_bad.write_text("alpha\nbeta\ngamma\n", encoding="utf-8")
    good = _run_captured([str(ctx["program"]), "-1", "-c", "aes-256-cbc", "-d", "sha256",
                          "-f", str(words), str(enc)], cwd=d, env=ctx["env"], timeout=30)
    neg = _run_captured([str(ctx["program"]), "-1", "-c", "aes-256-cbc", "-d", "sha256",
                         "-f", str(words_bad), str(enc)], cwd=d, env=ctx["env"], timeout=30)
    good_text = good["stdout"] + good["stderr"]
    neg_text = neg["stdout"] + neg["stderr"]
    ok = encres["ok"] and "Password candidate: phase25" in good_text
    neg_ok = "Password candidate" not in neg_text
    functional = ok and neg_ok
    return {
        "runtime_ok": ok, "functional_ok": functional,
        "failure_class": None if functional else ("functional-failure" if ok else "runtime-failure"),
        "residual": "none" if functional else ("functional-divergence" if ok else "runtime-failure"),
        "reason": None if functional else (
            "the fixture password was not recovered through EVP" if not ok else
            "a word list without the password produced a candidate"),
        "transcript": _transcript(("openssl enc fixture", encres),
                                  ("bruteforce-salted-openssl positive", good),
                                  ("bruteforce-salted-openssl negative", neg)),
        "workload": ("bruteforce-salted-openssl: recover the fixture password from a word list "
                     "and reject a list without it"),
        "local_only": True,
    }


def _wl_ircii(ctx: dict) -> dict:
    """ircII registers and joins the fixture channel over TLS; an unrelated CA never registers."""
    ap, d = ctx["authority_prefix"], ctx["workdir"]
    pki = _gen_pki(ap, d / "pki")
    stub, built = _l7_irc_stub(ctx)
    if not built["ok"] or not stub.is_file():
        return {"runtime_ok": False, "functional_ok": False, "failure_class": "harness-failure",
                "residual": "out-of-scope",
                "reason": f"the IRC stub harness did not compile: {census._error_line(built)}",
                "transcript": _transcript(("cc l7_irc_stub.c", built)),
                "workload": "ircii: IRC-over-TLS registration", "local_only": True}
    script = d / "ircii.rc"
    script.write_text(f"set SSL_CA_FILE {pki['ca_crt']}\n"
                      f"server -SSL 127.0.0.1:{ctx['port']}\n", encoding="utf-8")
    log = d / "stub.log"
    srv, of, ef = _spawn([str(stub), str(ctx["port"]), str(log), "tls", str(pki["srv_crt"]),
                          str(pki["srv_key"])], d, _auth_env(ap), d / "stub.out", d / "stub.err")
    registered = joined = False
    try:
        if not _wait_marker(log, "READY", 20):
            return _wl_fail([("irc stub", {"exit_code": 0, "stdout": _read(d / "stub.err")})],
                            "the local IRC stub did not listen", "harness-failure", d)
        master, slave = pty.openpty()
        env = dict(ctx["env"], TERM="dumb", HOME=str(d))
        proc = subprocess.Popen([str(ctx["program"]), "-b", "-d", "-l", str(script), "l7irc"],
                                stdin=slave, stdout=slave, stderr=slave, env=env, cwd=str(d))
        os.close(slave)
        try:
            deadline = time.monotonic() + 25
            while time.monotonic() < deadline:
                text = _read(log)
                registered = registered or "REGISTERED " in text
                joined = joined or "JOINED #l7" in text
                if registered and not joined:
                    os.write(master, b"/join #l7\n")
                if registered and joined:
                    try:
                        os.write(master, b"/quit\n")
                    except OSError:
                        pass
                    break
                ready, _, _ = select.select([master], [], [], 0.2)
                if ready:
                    try:
                        os.read(master, 65536)
                    except OSError:
                        pass
        finally:
            _stop(proc)
            try:
                os.close(master)
            except OSError:
                pass
    finally:
        _stop(srv)
        of.close()
        ef.close()
    nregistered = False
    nport = _free_port()
    nscript = d / "ircii-neg.rc"
    nscript.write_text(f"set SSL_CA_FILE {pki['other_crt']}\n"
                       f"server -SSL 127.0.0.1:{nport}\n", encoding="utf-8")
    nlog = d / "stub-neg.log"
    nsrv, nof, nef = _spawn([str(stub), str(nport), str(nlog), "tls", str(pki["srv_crt"]),
                             str(pki["srv_key"])], d, _auth_env(ap), d / "stub-neg.out",
                            d / "stub-neg.err")
    try:
        if _wait_marker(nlog, "READY", 20):
            master, slave = pty.openpty()
            nproc = subprocess.Popen([str(ctx["program"]), "-b", "-d", "-l", str(nscript), "l7irc"],
                                     stdin=slave, stdout=slave, stderr=slave,
                                     env=dict(ctx["env"], TERM="dumb", HOME=str(d)), cwd=str(d))
            os.close(slave)
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline:
                if "REGISTERED " in _read(nlog):
                    nregistered = True
                    break
                ready, _, _ = select.select([master], [], [], 0.2)
                if ready:
                    try:
                        os.read(master, 65536)
                    except OSError:
                        pass
            _stop(nproc)
            try:
                os.close(master)
            except OSError:
                pass
    finally:
        _stop(nsrv)
        nof.close()
        nef.close()
    neg_refused = not nregistered and "REGISTERED" not in _read(nlog)
    functional = registered and joined and neg_refused
    return {
        "runtime_ok": registered, "functional_ok": functional,
        "failure_class": None if functional else ("functional-failure" if registered else
                                                  "runtime-failure"),
        "residual": "none" if functional else ("functional-divergence" if registered else
                                              "runtime-failure"),
        "reason": None if functional else (
            "ircII did not register over TLS" if not registered else
            "ircII registered but did not join the fixture channel" if not joined else
            "a client trusting only the unrelated CA registered"),
        "transcript": _transcript(("irc stub (TLS) log", {"exit_code": 0, "stdout": _read(log)}),
                                  ("irc stub (unrelated CA) log",
                                   {"exit_code": 0, "stdout": _read(nlog)})),
        "workload": "ircii: IRC-over-TLS registration and join; unrelated CA refused",
        "local_only": True,
    }


def _wl_neon(ctx: dict) -> dict:
    """libneon fetches the fixture over verified TLS; an unrelated CA fails the handshake."""
    ap, port, d = ctx["authority_prefix"], ctx["port"], ctx["workdir"]
    pki = _gen_pki(ap, d / "pki")
    body = "phase25-l7-neon"
    state: dict = {}
    stop = threading.Event()
    thread = _https_fixture(port, pki, body, state, stop)
    try:
        if not _wait_tcp("127.0.0.1", port):
            return _wl_fail([("https fixture", {"exit_code": 0, "stdout": ""})],
                            "the local HTTPS fixture did not open its port",
                            "runtime-failure", d)
        good = _run_captured([str(ctx["program"]), str(pki["ca_crt"]), str(port),
                              "/payload.txt"], cwd=d, env=ctx["env"], timeout=30)
        neg = _run_captured([str(ctx["program"]), str(pki["other_crt"]), str(port),
                             "/payload.txt"], cwd=d, env=ctx["env"], timeout=30)
    finally:
        stop.set()
        state.get("listener", socket.socket()).close()
        thread.join(timeout=2)
    good_text = good["stdout"] + good["stderr"]
    neg_text = neg["stdout"] + neg["stderr"]
    ok = "status=200" in good_text and body in good_text
    neg_ok = "connect=failed" in neg_text or "status=0" in neg_text
    functional = ok and neg_ok
    return {
        "runtime_ok": ok, "functional_ok": functional,
        "failure_class": None if functional else ("functional-failure" if ok else "runtime-failure"),
        "residual": "none" if functional else ("functional-divergence" if ok else "runtime-failure"),
        "reason": None if functional else (
            "libneon did not fetch the fixture over TLS" if not ok else
            "an unrelated CA was not refused"),
        "transcript": _transcript(("neon TLS fetch", good), ("neon unrelated CA", neg)),
        "workload": "neon: verified HTTPS fetch of the fixture with an unrelated-CA reject",
        "local_only": True,
    }


def _wl_cjose(ctx: dict) -> dict:
    """cjose signs/verifies an HS256 JWS and rejects tampered and wrong-key inputs."""
    d = ctx["workdir"]
    res = _run_captured([str(ctx["program"])], cwd=d, env=ctx["env"], timeout=30)
    text = res["stdout"] + res["stderr"]
    ok = ("sign=ok" in text and "import=ok" in text and "verify=ok" in text
          and "tamper=rejected" in text and "wrongkey=rejected" in text)
    return {
        "runtime_ok": ok, "functional_ok": ok,
        "failure_class": None if ok else "functional-failure",
        "residual": "none" if ok else "functional-divergence",
        "reason": None if ok else (
            "cjose did not sign/verify the JWS or accepted a tampered/wrong-key input"),
        "transcript": _transcript(("cjose JWS", res)),
        "workload": "cjose: HS256 sign/import/verify with tamper and wrong-key rejects",
        "local_only": True,
    }


def _wl_evhtp(ctx: dict) -> dict:
    """libevhtp serves the fixture over verified TLS; an unrelated CA is refused."""
    import http.client
    ap, d = ctx["authority_prefix"], ctx["workdir"]
    pki = _gen_pki(ap, d / "pki")
    payload = "phase25-l7-libevhtp\n"

    def one(port: int, ca: Path) -> tuple[str, str]:
        proc, of, ef = _spawn([str(ctx["program"]), str(port), str(pki["srv_crt"]),
                               str(pki["srv_key"])], d, ctx["env"],
                              d / f"evhtp-{port}.out", d / f"evhtp-{port}.err")
        try:
            if not _wait_tcp("127.0.0.1", port):
                return "", "server did not open its port"
            gctx = ssl.create_default_context(cafile=str(ca))
            conn = http.client.HTTPSConnection("127.0.0.1", port, context=gctx, timeout=15)
            conn.request("GET", "/payload.txt")
            body = conn.getresponse().read().decode("utf-8", "ignore")
            conn.close()
            return body, ""
        except (ssl.SSLError, OSError) as exc:
            return "", f"rejected: {exc}"
        finally:
            _stop(proc)
            of.close()
            ef.close()

    good, good_err = one(ctx["port"], pki["ca_crt"])
    neg_body, neg_err = one(_free_port(), pki["other_crt"])
    ok = good == payload
    neg_ok = neg_err.startswith("rejected")
    functional = ok and neg_ok
    return {
        "runtime_ok": ok, "functional_ok": functional,
        "failure_class": None if functional else ("functional-failure" if ok else "runtime-failure"),
        "residual": "none" if functional else ("functional-divergence" if ok else "runtime-failure"),
        "reason": None if functional else (
            "libevhtp did not serve the fixture over TLS" if not ok else
            "an unrelated CA was not refused"),
        "transcript": _transcript(("libevhtp TLS server", {"exit_code": 0, "stdout": good}),
                                  ("libevhtp unrelated CA", {"exit_code": 0, "stdout": neg_err})),
        "workload": "libevhtp: TLS server serves the fixture with an unrelated-CA reject",
        "local_only": True,
    }


def _wl_xmlsec(ctx: dict) -> dict:
    """xmlsec1 signs with RSA-SHA256, verifies, and rejects a tampered document."""
    ap, d = ctx["authority_prefix"], ctx["workdir"]
    pki = _gen_pki(ap, d / "pki")
    key, cert = pki["srv_key"], pki["srv_crt"]
    template = d / "template.xml"
    template.write_text(
        "<Envelope>\n <Data>phase25-l7-xmlsec</Data>\n"
        ' <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">\n'
        "  <SignedInfo>\n"
        '   <CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>\n'
        '   <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>\n'
        '   <Reference URI="">\n'
        '    <Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></Transforms>\n'
        '    <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>\n'
        "    <DigestValue/>\n"
        "   </Reference>\n"
        "  </SignedInfo>\n"
        "  <SignatureValue/>\n"
        f"  <KeyInfo><KeyName>{Path(cert).name}</KeyName></KeyInfo>\n"
        " </Signature>\n"
        "</Envelope>\n", encoding="utf-8")
    signed = d / "signed.xml"
    sign = _run_captured([str(ctx["program"]), "--sign", f"--privkey-pem:{Path(cert).name}",
                          f"{key},{cert}", "--output", str(signed), str(template)],
                         cwd=d, env=ctx["env"], timeout=45)
    verify = _run_captured([str(ctx["program"]), "--verify", f"--privkey-pem:{Path(cert).name}",
                            f"{key},{cert}", str(signed)], cwd=d, env=ctx["env"], timeout=45)
    tampered = d / "tampered.xml"
    text = signed.read_text(encoding="utf-8") if signed.is_file() else ""
    tampered.write_text(text.replace("phase25-l7-xmlsec", "phase25-l7-TAMPERED"),
                        encoding="utf-8")
    neg = _run_captured([str(ctx["program"]), "--verify", f"--privkey-pem:{Path(cert).name}",
                         f"{key},{cert}", str(tampered)], cwd=d, env=ctx["env"], timeout=45)
    verify_text = verify["stdout"] + verify["stderr"]
    neg_text = neg["stdout"] + neg["stderr"]
    ok = sign["ok"] and "Verification status: OK" in verify_text
    neg_ok = "Verification status: FAILED" in neg_text or "Failure reason:" in neg_text
    functional = ok and neg_ok
    return {
        "runtime_ok": ok, "functional_ok": functional,
        "failure_class": None if functional else ("functional-failure" if ok else "runtime-failure"),
        "residual": "none" if functional else ("functional-divergence" if ok else "runtime-failure"),
        "reason": None if functional else (
            "xmlsec1 did not sign and verify the document" if not ok else
            "a tampered document verified"),
        "transcript": _transcript(("xmlsec1 sign", sign), ("xmlsec1 verify", verify),
                                  ("xmlsec1 tampered", neg)),
        "workload": "xmlsec1: RSA-SHA256 sign/verify and tampered-document reject",
        "local_only": True,
    }


def _wl_ima(ctx: dict) -> dict:
    """ima-evm-utils: sign a file's IMA digest and verify it, then tamper."""
    d = ctx["workdir"]
    key, cert = d / "ima.key", d / "ima.crt"
    payload, tampered = d / "ima.bin", d / "ima-bad.bin"
    payload.write_bytes(b"ima-fixture\n")
    tampered.write_bytes(b"ima-fixturf\n")
    gen = _ossl(ctx["authority_prefix"], [
        "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-nodes", "-days", "2",
        "-subj", "/CN=ima-l7", "-keyout", str(key), "-out", str(cert)], cwd=d)
    # evmctl 1.4 defaults to X.509 public keys and parses them with d2i_X509_fp
    # (DER), so the verification key is the certificate in DER form.
    der = d / "ima.der"
    der_res = _ossl(ctx["authority_prefix"], ["x509", "-in", str(cert), "-outform", "DER",
                                               "-out", str(der)], cwd=d)
    # `-n` keeps the signature out of the extended attribute (the court filesystem
    # does not permit setxattr); `-f` still writes the .sig file.  Without `-n`
    # evmctl exits 125 on the EPERM from lsetxattr even though it signed correctly.
    sign = _run_captured([str(ctx["program"]), "ima_sign", "-n", "-f", "--key", str(key),
                          str(payload)], cwd=d, env=ctx["env"], timeout=60)
    signed = Path(str(payload) + ".sig")
    # The negative control reuses the valid signature over modified bytes.
    if signed.is_file():
        Path(str(tampered) + ".sig").write_bytes(signed.read_bytes())
    verify = _run_captured([str(ctx["program"]), "ima_verify", "-f", "--key", str(der),
                            str(payload)], cwd=d, env=ctx["env"], timeout=60)
    neg = _run_captured([str(ctx["program"]), "ima_verify", "-f", "--key", str(der),
                         str(tampered)], cwd=d, env=ctx["env"], timeout=60)
    verify_text = verify["stdout"] + verify["stderr"]
    neg_text = neg["stdout"] + neg["stderr"]
    ok = bool(gen["ok"] and der_res["ok"] and sign["ok"] and verify["ok"]
              and signed.is_file())
    neg_ok = neg["exit_code"] != 0 or "verification failed" in neg_text.lower()
    functional = ok and neg_ok
    return {
        "runtime_ok": ok, "functional_ok": functional,
        "failure_class": None if functional else ("functional-failure" if ok else
                                                  "runtime-failure"),
        "residual": "none" if functional else ("functional-divergence" if ok else
                                               "runtime-failure"),
        "reason": None if functional else (
            "evmctl did not sign and verify the fixture" if not ok else
            "a modified file still verified"),
        "transcript": _transcript(("ima_sign", sign), ("ima_verify", verify),
                                   ("tampered verify (must fail)", neg)),
        "workload": "evmctl: IMA SHA-256 sign/verify and tampered-file reject",
        "local_only": True,
    }


def _b16_out(ok: bool, functional: bool, transcript: str, workload: str,
             good: str, bad: str) -> dict:
    """The common result shape for the b16 onboarding workloads."""
    return {
        "runtime_ok": ok, "functional_ok": functional,
        "failure_class": None if functional else (
            "functional-failure" if ok else "runtime-failure"),
        "residual": "none" if functional else (
            "functional-divergence" if ok else "runtime-failure"),
        "reason": None if functional else (bad if ok else good),
        "transcript": transcript, "workload": workload, "local_only": True,
    }


def _stop_workload_group(proc: subprocess.Popen) -> tuple[str, str]:
    """Stop a workload server and its whole process group, with bounded waits.

    A server that forks (shellinaboxd) leaves a child holding the inherited stdout/stderr
    pipes, so a bare `communicate()` after `kill()` can block forever. Signal the group and
    bound every wait: a transcript missing a forked child's last bytes is preferable to a
    hung court, and every result is still recorded honestly.
    """
    try:
        pgid = os.getpgid(proc.pid)
    except ProcessLookupError:
        pgid = None
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            if pgid is not None:
                os.killpg(pgid, sig)
            else:
                proc.send_signal(sig)
        except ProcessLookupError:
            pass
        try:
            out, err = proc.communicate(timeout=5)
            return out or "", err or ""
        except subprocess.TimeoutExpired:
            continue
    return "", ""


def _wl_sscg(ctx: dict) -> dict:
    """sscg mints a CA and a service certificate; the authority verifies the chain."""
    d, prog = ctx["workdir"], str(ctx["program"])
    pki = _gen_pki(ctx["authority_prefix"], d / "pki")
    ca, ca_key = d / "ca.crt", d / "ca.key"
    crt, key = d / "service.crt", d / "service.key"
    mint = _run_captured([prog, "--quiet", "--force", "--lifetime", "2", "--hostname",
                          "127.0.0.1", "--subject-alt-name", "IP:127.0.0.1",
                          "--ca-file", str(ca), "--ca-key-file", str(ca_key),
                          "--cert-file", str(crt), "--cert-key-file", str(key)],
                         cwd=d, env=ctx["env"], timeout=120)
    verify = _ossl(ctx["authority_prefix"], ["verify", "-CAfile", str(ca), str(crt)], cwd=d)
    neg = _ossl(ctx["authority_prefix"], ["verify", "-CAfile", str(pki["other_crt"]), str(crt)],
                cwd=d)
    ok = bool(mint["ok"] and crt.is_file() and key.is_file())
    verified = ": OK" in (verify["stdout"] + verify["stderr"])
    refused = neg["exit_code"] != 0
    functional = ok and verified and refused
    return _b16_out(ok, functional,
                    _transcript(("sscg", mint), ("verify", verify),
                                ("unrelated CA (must fail)", neg)),
                    "sscg: CA + service certificate minted and chain-verified",
                    "sscg did not mint the CA and service certificate",
                    "the unrelated CA did not reject the chain")


def _wl_shellinabox(ctx: dict) -> dict:
    """shellinaboxd serves its web terminal over the fixture TLS listener."""
    d = ctx["workdir"]
    pki = _gen_pki(ctx["authority_prefix"], d / "pki")
    certdir = d / "certs"
    certdir.mkdir(parents=True, exist_ok=True)
    (certdir / "certificate.pem").write_bytes(pki["srv_crt"].read_bytes()
                                                + pki["srv_key"].read_bytes())
    port = _free_port()
    argv = [str(ctx["program"]), "--localhost-only", "--disable-utmp-logging", "-q",
            "-p", str(port), "-c", str(certdir), "-s", "/:nobody:nogroup:/:/bin/true"]
    server = subprocess.Popen(argv, cwd=str(d), env=ctx["env"], start_new_session=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        listening = _wait_tcp("127.0.0.1", port, timeout=15)
        good = templates._tls_exchange(port, pki["ca_crt"], "GET / HTTP/1.0\r\n\r\n",
                                       verify_host=True, server_hostname="127.0.0.1")
        wrong = templates._tls_exchange(port, pki["other_crt"], "GET / HTTP/1.0\r\n\r\n",
                                        verify_host=True, server_hostname="127.0.0.1")
    finally:
        out, err = _stop_workload_group(server)
    served = bool(good.get("ok")) and "ShellInABox" in good.get("data", "")
    ok = bool(listening and served)
    functional = ok and not wrong.get("ok")
    return _b16_out(ok, functional,
                    _transcript(("server", {"exit_code": 0 if listening else 1,
                                            "stdout": "", "stderr": (err or "")[-1200:]}),
                                ("client", {"exit_code": 0 if good.get("ok") else 1,
                                             "stdout": good.get("data", "")[:600],
                                             "stderr": good.get("error", "")}),
                                ("unrelated CA (must fail)",
                                 {"exit_code": 0 if wrong.get("ok") else 1,
                                  "stdout": wrong.get("data", "")[:200],
                                  "stderr": wrong.get("error", "")})),
                    "shellinabox: web terminal served over verified TLS",
                    "shellinabox did not serve its page over TLS",
                    "a client trusting the unrelated CA was not rejected")


def _wl_charybdis(ctx: dict) -> dict:
    """charybdis completes its IRC greeting over the fixture TLS listener.

    charybdis refuses to run as root, so the workload drops to `nobody` with setpriv and
    stages the install layout the daemon expects under its compiled prefix (helpers and
    modules are built but the recipe does not run `make install`).  The staging is a
    fixture property, identical for both subjects; no capability is granted to the
    container.
    """
    d = ctx["workdir"]
    root = ctx["root"]
    pki = _gen_pki(ctx["authority_prefix"], d / "pki")
    dh = d / "dh.pem"
    gen = _ossl(ctx["authority_prefix"], ["dhparam", "-out", str(dh), "2048"], cwd=d,
                timeout=120)
    prefix = root / ".l7-install"
    for sub in ("bin", "etc", "logs", "modules", "modules/autoload"):
        (prefix / sub).mkdir(parents=True, exist_ok=True)
    for helper in ("authd", "bandb", "ssld", "wsockd"):
        real = root / helper / ".libs" / helper
        if real.is_file():
            link = prefix / "bin" / helper
            if link.exists() or link.is_symlink():
                link.unlink()
            link.symlink_to(real)
    module_dir = prefix / "modules"
    for mod in (root / "modules").rglob("*.so"):
        if mod.parent.name == ".libs" and mod.is_file():
            target = module_dir / mod.name
            if not target.exists():
                shutil.copy2(mod, target)
    if (root / "modules" / "core" / ".libs").is_dir():
        for mod in (root / "modules" / "core" / ".libs").glob("*.so"):
            target = module_dir / mod.name
            if not target.exists():
                shutil.copy2(mod, target)
    port = _free_port()
    conf = d / "ircd.conf"
    conf.write_text(
        "serverinfo {\n  name = \"irc.fixture\";\n  sid = \"1AA\";\n"
        "  description = \"fixture\";\n  network_name = \"fixture\";\n"
        f"  ssl_cert = \"{pki['srv_crt']}\";\n"
        f"  ssl_private_key = \"{pki['srv_key']}\";\n"
        f"  ssl_dh_params = \"{dh}\";\n}};\n"
        "admin { name = \"fixture\"; description = \"fixture\"; email = \"f@example\"; };\n"
        "class \"users\" { ping_time = 2 minutes; number_per_ip = 10; max_number = 100; };\n"
        f"listen {{ host = \"127.0.0.1\"; sslport = {port}; }};\n"
        "auth { user = \"*@*\"; class = \"users\"; };\n", encoding="utf-8")
    rundir = d / "run"
    rundir.mkdir(parents=True, exist_ok=True)
    # The daemon and its helpers must be able to read the workdir and write the staged
    # etc/logs trees after the privilege drop.
    os.system(f"chown -R nobody:nogroup {d} 2>/dev/null")
    os.system(f"chmod -R a+rX {d}")
    os.system(f"chmod 777 {prefix / 'etc'} {prefix / 'logs'} {rundir}")
    lib_paths = [str(prefix / "modules")]
    lib_paths += [p for p in (ctx["env"].get("LD_LIBRARY_PATH") or "").split(os.pathsep) if p]
    env = dict(ctx["env"], LD_LIBRARY_PATH=os.pathsep.join(lib_paths), HOME=str(d),
               TMPDIR=str(rundir))
    argv = ["setpriv", "--reuid=nobody", "--regid=nogroup", "--clear-groups",
            str(ctx["program"]), "-configfile", str(conf), "-foreground",
            "-logfile", str(d / "ircd.log"), "-pidfile", str(d / "ircd.pid")]
    server = subprocess.Popen(argv, cwd=str(rundir), env=env, start_new_session=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        listening = _wait_tcp("127.0.0.1", port, timeout=20)
        good = templates._tls_exchange(port, pki["ca_crt"],
                                      "NICK fixture\r\nUSER fixture 0 * :x\r\n",
                                      verify_host=True, read_once=True)
        wrong = templates._tls_exchange(port, pki["other_crt"], "NICK fixture\r\n",
                                       verify_host=True, read_once=True)
    finally:
        out, err = _stop_workload_group(server)
    greeted = bool(good.get("ok")) and bool(re.search(r"(NOTICE|020|AUTH|001)",
                                                      good.get("data", "")))
    ok = bool(gen["ok"] and listening and greeted)
    functional = ok and not wrong.get("ok")
    return _b16_out(ok, functional,
                    _transcript(("dhparam", gen),
                                ("server", {"exit_code": 0 if listening else 1,
                                            "stdout": "", "stderr": (err or "")[-1200:]}),
                                ("client", {"exit_code": 0 if good.get("ok") else 1,
                                             "stdout": good.get("data", "")[:600],
                                             "stderr": good.get("error", "")}),
                                ("unrelated CA (must fail)",
                                 {"exit_code": 0 if wrong.get("ok") else 1,
                                  "stdout": wrong.get("data", "")[:200],
                                  "stderr": wrong.get("error", "")})),
                    "charybdis: IRC greeting over verified TLS (setpriv euid drop)",
                    "charybdis did not listen or greet over TLS",
                    "a client trusting the unrelated CA was not rejected")


def _wl_afflib(ctx: dict) -> dict:
    """AFFLIB signs an AFF image and refuses a tampered one."""
    d, prog = ctx["workdir"], Path(str(ctx["program"]))
    convert, verify = prog.with_name("affconvert"), prog.with_name("affverify")
    # AFFLIB identifies raw input by extension (raw_identify_file accepts .raw/.iso),
    # so the source payload must carry a raw extension.
    payload, img = d / "payload.raw", d / "fixture.aff"
    payload.write_bytes(b"afflib-fixture-payload\n" * 32)
    key, crt = d / "sign.key", d / "sign.crt"
    gen = _ossl(ctx["authority_prefix"], ["req", "-x509", "-newkey", "rsa:2048", "-sha256",
                                          "-nodes", "-days", "2", "-subj", "/CN=afflib-fixture",
                                          "-keyout", str(key), "-out", str(crt)], cwd=d)
    made = _run_captured([str(convert), "-o", str(img), str(payload)], cwd=d, env=ctx["env"],
                         timeout=120)
    signed = _run_captured([str(prog), "-k", str(key), "-c", str(crt), str(img)], cwd=d,
                           env=ctx["env"], timeout=120)
    good = _run_captured([str(verify), str(img)], cwd=d, env=ctx["env"], timeout=120)
    tampered = d / "tampered.aff"
    if img.is_file():
        blob = bytearray(img.read_bytes())
        if blob:
            blob[len(blob) // 2] ^= 0xFF
        tampered.write_bytes(bytes(blob))
    bad = _run_captured([str(verify), str(tampered)], cwd=d, env=ctx["env"], timeout=120)
    ok = bool(gen["ok"] and made["ok"] and signed["ok"] and good["ok"])
    functional = ok and bad["exit_code"] != 0
    return _b16_out(ok, functional,
                    _transcript(("affconvert", made), ("affsign", signed),
                                ("affverify", good), ("tampered (must fail)", bad)),
                    "AFFLIB: affsign/affverify over a signed AFF image",
                    "AFFLIB could not create and sign the image",
                    "a tampered image still verified")


def _wl_httest(ctx: dict) -> dict:
    """httest performs an HTTPS request with its own CA option."""
    d, prog = ctx["workdir"], str(ctx["program"])
    pki = _gen_pki(ctx["authority_prefix"], d / "pki")
    port = _free_port()

    def run(ca: Path, name: str) -> dict:
        script = d / f"{name}.htt"
        script.write_text(
            "CLIENT\n"
            f"_SSL:SET_CA {ca}\n"
            f"_REQ 127.0.0.1 SSL:{port}\n"
            "_VERIFY_PEER\n"
            "__GET / HTTP/1.0\n"
            "__Host: 127.0.0.1\n"
            "__\n"
            "_EXPECT . \"template-payload\"\n"
            "_WAIT\n"
            "END\n", encoding="utf-8")
        return _run_captured([prog, str(script)], cwd=d, env=ctx["env"], timeout=60)

    with templates._HTTPFixture(port, "template-payload", cert=pki["srv_crt"],
                                 key=pki["srv_key"]):
        good = run(pki["ca_crt"], "good")
        bad = run(pki["other_crt"], "bad")
    ok = good["ok"]
    functional = ok and bad["exit_code"] != 0
    return _b16_out(ok, functional,
                    _transcript(("HTTPS request", good), ("unrelated CA (must fail)", bad)),
                    "httest: HTTPS request over verified TLS",
                    "httest did not complete the HTTPS request",
                    "a request trusting the unrelated CA was not rejected")


def _wl_sipp(ctx: dict) -> dict:
    """SIPp's own UAS and UAC complete a call over verified TLS."""
    d, prog = ctx["workdir"], str(ctx["program"])
    pki = _gen_pki(ctx["authority_prefix"], d / "pki")
    port = _free_port()

    def attempt(ca: Path, tag: str) -> tuple[dict, str, bool]:
        for stale in d.glob("uac_*_errors.log"):
            stale.unlink(missing_ok=True)
        uas = subprocess.Popen([prog, "-sn", "uas", "-t", "l1", "-i", "127.0.0.1",
                                "-p", str(port), "-m", "1", "-timeout", "15s",
                                "-tls_cert", str(pki["srv_crt"]),
                                "-tls_key", str(pki["srv_key"])],
                               cwd=str(d), env=ctx["env"], stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True, start_new_session=True)
        try:
            # Do not probe the TLS port: SIPp's -m 1 UAS accepts one call, and a
            # connect-and-close probe would consume it.  Wait briefly and require the
            # UAS process to still be alive instead.
            time.sleep(2.0)
            listening = uas.poll() is None
            # SIPp always loads a client certificate (default cacert.pem), so the UAC
            # presents the fixture client key as well as the CA it verifies against.
            call = _run_captured([prog, "127.0.0.1:{}".format(port), "-sn", "uac", "-t", "l1",
                                  "-m", "1", "-r", "1", "-timeout", "12s",
                                  "-tls_ca", str(ca),
                                  "-tls_cert", str(pki["client_crt"]),
                                  "-tls_key", str(pki["client_key"]), "-trace_err"],
                                 cwd=d, env=ctx["env"], timeout=45)
        finally:
            uout, uerr = _stop_workload_group(uas)
        logs = "\n".join(p.read_text(encoding="utf-8", errors="replace")
                          for p in d.glob("uac_*_errors.log"))
        successful = False
        for line in (call["stdout"] + call["stderr"]).splitlines():
            if "Successful call" in line:
                nums = re.findall(r"\b(\d+)\b", line)
                if nums and int(nums[-1]) > 0:
                    successful = True
        return call, logs, bool(listening and successful)

    good, good_log, good_ok = attempt(pki["ca_crt"], "good")
    bad, bad_log, bad_ok = attempt(pki["other_crt"], "bad")
    bad_rejected = (not bad_ok) and ("unable to get local issuer certificate" in bad_log
                                     or "verify error" in bad_log
                                     or "TLS verification error" in bad_log)
    functional = good_ok and bad_rejected
    return _b16_out(good_ok, functional,
                    _transcript(("UAC (fixture CA)", good),
                                ("UAC errors (fixture CA)", {"exit_code": 0,
                                                              "stdout": good_log[-800:],
                                                              "stderr": ""}),
                                ("UAC (unrelated CA, must fail)", bad),
                                ("UAC errors (unrelated CA)", {"exit_code": 0,
                                                                "stdout": bad_log[-800:],
                                                                "stderr": ""})),
                    "SIPp: a SIP call between its own UAS and UAC over verified TLS",
                    "SIPp did not complete the call over TLS",
                    "a UAC trusting the unrelated CA was not rejected")


def _wl_dma(ctx: dict) -> dict:
    """DMA submits a message to a local SMTPS peer over verified TLS."""
    d, prog = ctx["workdir"], str(ctx["program"])
    pki = _gen_pki(ctx["authority_prefix"], d / "pki")
    port = _free_port()
    spool = d / "spool"
    spool.mkdir(parents=True, exist_ok=True)
    # DMA 0.14 is compiled with CONF_PATH=/etc/dma and drops root to the `mail` user
    # before doing any work, so the configuration must be at that path and the spool
    # must be writable by mail.
    confdir = Path("/etc/dma")
    confdir.mkdir(parents=True, exist_ok=True)
    try:
        import grp as _grp
        import pwd as _pwd
        mail = _pwd.getpwnam("mail")
        grp = _grp.getgrnam("mail")
        os.chown(spool, mail.pw_uid, grp.gr_gid)
    except (KeyError, OSError):
        pass
    os.chmod(d, 0o755)
    os.chmod(d / "pki", 0o755)
    for entry in (d / "pki").glob("*"):
        os.chmod(entry, 0o644)

    def write_conf(ca: Path) -> None:
        (confdir / "dma.conf").write_text(
            f"SMARTHOST 127.0.0.1\nPORT {port}\nSECURETRANSFER\nVERIFYCERT\n"
            f"NULLCLIENT\nSPOOLDIR {spool}\n", encoding="utf-8")
        (confdir / "auth.conf").write_text("", encoding="utf-8")

    state = {"data": ""}

    def serve() -> None:
        listener = socket.socket()
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", port))
        listener.listen(1)
        listener.settimeout(20)
        sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        sctx.load_cert_chain(str(pki["srv_crt"]), str(pki["srv_key"]))
        try:
            conn, _ = listener.accept()
            with conn, sctx.wrap_socket(conn, server_side=True) as tls:
                stream = tls.makefile("rwb", buffering=0)
                stream.write(b"220 fixture ESMTP\r\n")
                while True:
                    line = stream.readline()
                    if not line:
                        break
                    cmd = line.strip().split(b" ")[0].upper()
                    if cmd in (b"EHLO", b"HELO"):
                        stream.write(b"250-fixture\r\n250 SIZE 10240000\r\n")
                    elif cmd == b"DATA":
                        stream.write(b"354 go\r\n")
                        body = b""
                        while True:
                            part = stream.readline()
                            if not part or part == b".\r\n":
                                break
                            body += part
                        state["data"] = body.decode("utf-8", "replace")
                        stream.write(b"250 queued\r\n")
                    elif cmd == b"QUIT":
                        stream.write(b"221 bye\r\n")
                        break
                    else:
                        stream.write(b"250 ok\r\n")
        except OSError:
            return
        finally:
            listener.close()

    def deliver(ca_name: str) -> tuple[dict, threading.Thread]:
        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        env = dict(ctx["env"], SSL_CERT_FILE=str(pki["ca_crt" if ca_name == "ca" else "other_crt"]))
        res = _run_captured([prog, "-f", "sender@example", "-t"], cwd=d, env=env, timeout=30,
                            stdin_text="To: fixture@example\nSubject: fixture\n\ntemplate-payload\n")
        thread.join(timeout=25)
        return res, thread

    write_conf(pki["ca_crt"])
    good, _ = deliver("ca")
    good_data = state["data"]
    # The negative control reuses the same peer with a CA file that did not sign its certificate.
    state["data"] = ""
    write_conf(pki["other_crt"])
    bad, _ = deliver("wrong_ca")
    ok = bool(good["ok"] and "template-payload" in good_data)
    functional = ok and not ("template-payload" in state["data"])
    return _b16_out(ok, functional,
                    _transcript(("SMTPS session", good),
                                ("delivered body", {"exit_code": 0, "stdout": good_data[:400],
                                                     "stderr": ""}),
                                ("unrelated CA (must fail)", bad),
                                ("negative delivered body", {"exit_code": 0,
                                                             "stdout": state["data"][:200],
                                                             "stderr": ""})),
                    "DMA: message submitted to a local SMTPS peer over verified TLS",
                    "DMA did not deliver the message over TLS",
                    "a message was delivered while trusting the unrelated CA")


def _wl_h2o(ctx: dict) -> dict:
    """h2o serves the fixture over verified TLS."""
    d, prog = ctx["workdir"], str(ctx["program"])
    pki = _gen_pki(ctx["authority_prefix"], d / "pki")
    root = d / "docroot"
    root.mkdir(parents=True, exist_ok=True)
    (root / "index.html").write_text("template-payload\n", encoding="utf-8")
    port = _free_port()
    conf = d / "h2o.conf"
    conf.write_text(
        f"listen:\n  port: {port}\n  ssl:\n    certificate-file: {pki['srv_crt']}\n"
        f"    key-file: {pki['srv_key']}\nhosts:\n  \"default\":\n    paths:\n"
        f"      \"/\":\n        file.dir: {root}\naccess-log: /dev/null\n"
        f"error-log: /dev/null\n", encoding="utf-8")
    server = subprocess.Popen([prog, "-c", str(conf)], cwd=str(d), env=ctx["env"],
                              start_new_session=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        listening = _wait_tcp("127.0.0.1", port, timeout=20)
        good = templates._tls_exchange(port, pki["ca_crt"], "GET / HTTP/1.0\r\n\r\n",
                                       verify_host=True)
        wrong = templates._tls_exchange(port, pki["other_crt"], "GET / HTTP/1.0\r\n\r\n",
                                        verify_host=True)
    finally:
        out, err = _stop_workload_group(server)
    served = bool(good.get("ok")) and "template-payload" in good.get("data", "")
    ok = bool(listening and served)
    functional = ok and not wrong.get("ok")
    return _b16_out(ok, functional,
                    _transcript(("server", {"exit_code": 0 if listening else 1, "stdout": "",
                                            "stderr": (err or "")[-800:]}),
                                ("client", {"exit_code": 0 if good.get("ok") else 1,
                                             "stdout": good.get("data", "")[:600],
                                             "stderr": good.get("error", "")}),
                                ("unrelated CA (must fail)",
                                 {"exit_code": 0 if wrong.get("ok") else 1,
                                  "stdout": wrong.get("data", "")[:200],
                                  "stderr": wrong.get("error", "")})),
                    "h2o: fixture served over verified TLS",
                    "h2o did not serve the fixture over TLS",
                    "a client trusting the unrelated CA was not rejected")


def _wl_libshout(ctx: dict) -> dict:
    """libshout streams to an Icecast source endpoint over verified TLS.

    libshout 2.4.6 sets SSL_VERIFY_NONE and performs its own check
    (SSL_get_verify_result + X509_check_host), so it verifies the peer *name*, not a
    certificate chain.  The honest negative control is therefore a server certificate
    that matches the fixture CA but not the connected host name; an unrelated CA is not
    rejected by this consumer by design.
    """
    d, prog = ctx["workdir"], str(ctx["program"])
    pki = _gen_pki(ctx["authority_prefix"], d / "pki")
    payload = "template-payload\n" * 64
    port = _free_port()
    ext = d / "wronghost.ext"
    ext.write_text("subjectAltName=DNS:fixture.invalid\nbasicConstraints=CA:FALSE\n"
                   "keyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n",
                   encoding="utf-8")
    wh_key, wh_csr, wh_crt = d / "wh.key", d / "wh.csr", d / "wh.crt"
    wh_req = _ossl(ctx["authority_prefix"], [
        "req", "-newkey", "rsa:2048", "-nodes", "-keyout", str(wh_key), "-out", str(wh_csr),
        "-subj", "/CN=fixture.invalid"], cwd=d)
    wh_sign = _ossl(ctx["authority_prefix"], [
        "x509", "-req", "-in", str(wh_csr), "-CA", str(pki["ca_crt"]), "-CAkey",
        str(pki["ca_key"]), "-CAcreateserial", "-out", str(wh_crt), "-days", "7",
        "-extfile", str(ext)], cwd=d)

    def stream(cert: Path, key: Path) -> tuple[dict, str, dict]:
        got = {"data": ""}
        listener = socket.socket()
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", port))
        listener.listen(4)
        listener.settimeout(20)
        sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        sctx.load_cert_chain(str(cert), str(key))

        def serve() -> None:
            try:
                # libshout's rfc2818 path probes with a Content-Length: 0 SOURCE, then (because
                # the fixture answers HTTP/1.0) opens a fresh connection for the authenticated
                # SOURCE and sends the stream body on that one. Serve each sequentially.
                deadline = time.monotonic() + 35
                while time.monotonic() < deadline and "body" not in got:
                    conn, _ = listener.accept()
                    got["conns"] = got.get("conns", 0) + 1
                    with conn, sctx.wrap_socket(conn, server_side=True) as tls:
                        tls.settimeout(15)
                        blob = b""
                        while b"\r\n\r\n" not in blob:
                            chunk = tls.recv(4096)
                            if not chunk:
                                break
                            blob += chunk
                        head, _, rest = blob.partition(b"\r\n\r\n")
                        got["data"] = got.get("data", "") + head.decode("utf-8", "replace")
                        tls.sendall(b"HTTP/1.0 200 OK\r\n\r\n")
                        if b"Content-Length: 0" in head:
                            # the capability probe: answer and let the client reconnect
                            continue
                        # The authenticated SOURCE is answered and the body may follow on this
                        # connection (keep-alive) or on a fresh one (HTTP/1.0).  Bound the wait
                        # so the server can accept the fresh connection instead of blocking.
                        tls.settimeout(8)
                        body = rest
                        try:
                            while True:
                                chunk = tls.recv(4096)
                                if not chunk:
                                    break
                                body += chunk
                        except socket.timeout:
                            if not body:
                                continue
                        if not body:
                            continue
                        got["body"] = body
                        got["data"] += body.decode("utf-8", "replace")
            except OSError as exc:
                got["error"] = repr(exc)
            finally:
                listener.close()

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        env = dict(ctx["env"], SSL_CERT_FILE=str(pki["ca_crt"]))
        res = _run_captured([prog, "--format", "ogg", "--usage", "audio", "--host",
                             "127.0.0.1", "--port", str(port), "--pass", "fixture",
                             "--mount", "/stream", "--tls-mode", "rfc2818"], cwd=d, env=env,
                            timeout=40, stdin_text=payload)
        thread.join(timeout=25)
        return res, got.get("data", ""), {"conns": got.get("conns", 0),
                                                    "error": got.get("error", "")}

    good, good_data, good_meta = stream(pki["srv_crt"], pki["srv_key"])
    bad, bad_data, _ = stream(wh_crt, wh_key)
    ok = bool(wh_req["ok"] and wh_sign["ok"] and good["ok"] and "SOURCE" in good_data.upper()
              and "template-payload" in good_data)
    functional = ok and not bad["ok"] and "bad certificate" in (bad["stderr"] + bad["stdout"])
    return _b16_out(ok, functional,
                    _transcript(("SOURCE over TLS", good),
                                ("peer transcript", {"exit_code": 0, "stdout": good_data[:600],
                                                       "stderr": str(good_meta.get("error", "")) +
                                                                 f" conns={good_meta.get('conns', 0)}"}),
                                ("wrong-host certificate (must fail)", bad),
                                ("negative transcript", {"exit_code": 0,
                                                          "stdout": bad_data[:200],
                                                          "stderr": ""})),
                    "libshout: SOURCE stream to an Icecast peer over verified TLS",
                    "libshout did not stream over TLS",
                    "a server certificate for the wrong host was accepted")


def _wl_nghttp2(ctx: dict) -> dict:
    """nghttp fetches from nghttpd over verified TLS."""
    d, prog = ctx["workdir"], Path(str(ctx["program"]))
    nghttpd = prog.with_name("nghttpd")
    pki = _gen_pki(ctx["authority_prefix"], d / "pki")
    root = d / "docroot"
    root.mkdir(parents=True, exist_ok=True)
    (root / "fixture.txt").write_text("template-payload\n", encoding="utf-8")
    dh = d / "dh.pem"
    gen = _ossl(ctx["authority_prefix"], ["dhparam", "-out", str(dh), "1024"], cwd=d,
                timeout=120)
    port = _free_port()
    server = subprocess.Popen([str(nghttpd), "-d", str(root), "-v", str(port), str(pki["srv_key"]),
                               str(pki["srv_crt"])], cwd=str(d), env=ctx["env"],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                              start_new_session=True)
    try:
        listening = _wait_tcp("127.0.0.1", port, timeout=20)
        env = dict(ctx["env"], SSL_CERT_FILE=str(pki["ca_crt"]))
        good = _run_captured([str(prog), "-v", "https://127.0.0.1:{}/fixture.txt".format(port)],
                             cwd=d, env=env, timeout=45)
        env_bad = dict(ctx["env"], SSL_CERT_FILE=str(pki["other_crt"]))
        bad = _run_captured([str(prog), "-v", "https://127.0.0.1:{}/fixture.txt".format(port)],
                            cwd=d, env=env_bad, timeout=30)
    finally:
        out, err = _stop_workload_group(server)
    good_text = good["stdout"] + good["stderr"]
    bad_text = bad["stdout"] + bad["stderr"]
    # nghttp 1.64 installs a verify callback that always returns 1 and reports a
    # failed chain only as `[WARNING] Certificate verification failed`; it does not
    # abort the request.  The contract the consumer actually implements is therefore
    # observable in the verify result, not in a refused connection.
    warned = "Certificate verification failed" in bad_text
    not_warned = "Certificate verification failed" not in good_text
    ok = bool(gen["ok"] and listening and "template-payload" in good_text and not_warned)
    functional = ok and warned
    return _b16_out(ok, functional,
                    _transcript(("dhparam", gen),
                                ("server", {"exit_code": 0 if listening else 1, "stdout": "",
                                            "stderr": (err or "")[-800:]}),
                                ("nghttp (fixture CA)", good),
                                ("nghttp (unrelated CA, warning expected)", bad)),
                    "nghttp2: nghttp fetch from nghttpd over TLS, chain result reported",
                    "nghttp did not fetch the fixture over TLS",
                    "the unrelated CA's verification failure was not reported")


def _wl_strongswan(ctx: dict) -> dict:
    """strongSwan pki: X.509 issue/verify, PKCS#10 and PKCS#12 through the OpenSSL plugin."""
    d, prog = ctx["workdir"], str(ctx["program"])
    # pki reads its plugin configuration from STRONGSWAN_CONF and loads plugins from the
    # compile-time PLUGINDIR; the recipe builds both but does not install them.
    prefix = ctx["root"] / ".l7-install"
    plugdir = prefix / "lib" / "ipsec" / "plugins"
    plugdir.mkdir(parents=True, exist_ok=True)
    for mod in (ctx["root"] / "src" / "libstrongswan" / "plugins").glob("*/.libs/*.so"):
        link = plugdir / mod.name
        if not (link.exists() or link.is_symlink()):
            link.symlink_to(mod)
    conf = ctx["root"] / "strongswan.conf"
    conf.write_text("", encoding="utf-8")
    env = dict(ctx["env"], STRONGSWAN_CONF=str(conf))

    def run(args: list[str], stdin_text: str | None = None, timeout: int = 90) -> dict:
        return _run_captured([prog] + args, cwd=d, env=env, timeout=timeout,
                             stdin_text=stdin_text)

    ca_key, ca_crt = d / "ca.key", d / "ca.crt"
    srv_key, srv_csr, srv_crt = d / "srv.key", d / "srv.csr", d / "srv.crt"
    other = _gen_pki(ctx["authority_prefix"], d / "other")
    gen_ca = run(["--gen", "--type", "rsa", "--size", "2048", "--outform", "pem"])
    ca_key.write_text(gen_ca["stdout"], encoding="utf-8")
    self_res = run(["--self", "--ca", "--lifetime", "2", "--in", str(ca_key),
                    "--dn", "CN=fixture CA", "--outform", "pem"])
    ca_crt.write_text(self_res["stdout"], encoding="utf-8")
    gen_srv = run(["--gen", "--type", "rsa", "--size", "2048", "--outform", "pem"])
    srv_key.write_text(gen_srv["stdout"], encoding="utf-8")
    req = run(["--req", "--in", str(srv_key), "--dn", "CN=127.0.0.1", "--outform",
               "pem"])
    srv_csr.write_text(req["stdout"], encoding="utf-8")
    issue = run(["--issue", "--cacert", str(ca_crt), "--cakey", str(ca_key), "--in",
                 str(srv_csr), "--type", "pkcs10", "--flag", "serverAuth", "--san",
                 "127.0.0.1", "--lifetime", "2", "--outform", "pem"])
    srv_crt.write_text(issue["stdout"], encoding="utf-8")
    verify = run(["--verify", "--cacert", str(ca_crt), "--in", str(srv_crt)])
    neg = run(["--verify", "--cacert", str(other["other_crt"]), "--in", str(srv_crt)])
    # pki cannot *create* a PKCS#12 container, but it parses one through the pkcs12 plugin.
    p12 = d / "srv.p12"
    p12_make = _ossl(ctx["authority_prefix"], [
        "pkcs12", "-export", "-in", str(srv_crt), "-inkey", str(srv_key), "-certfile",
        str(ca_crt), "-passout", "pass:fixture", "-out", str(p12)], cwd=d)
    p12_list = run(["--pkcs12", "--list", "--in", str(p12)], stdin_text="fixture\n")
    p12_bad = run(["--pkcs12", "--list", "--in", str(p12)], stdin_text="wrong\n")
    # pki prints the loaded plugin list on a usage error; require the OpenSSL plugin.
    usage = run(["--help"])
    usage_text = usage["stdout"] + usage["stderr"]
    plugin_ok = "openssl" in usage_text and "pkcs12" in usage_text
    chain_ok = ("certificate trusted" in (verify["stdout"] + verify["stderr"]).lower())
    neg_ok = neg["exit_code"] != 0
    p12_ok = "RSA 2048 bits" in p12_list["stdout"] and "CN=127.0.0.1" in p12_list["stdout"]
    p12_neg = p12_bad["exit_code"] != 0
    ok = bool(gen_ca["ok"] and self_res["ok"] and gen_srv["ok"] and req["ok"]
              and issue["ok"] and verify["ok"] and plugin_ok and p12_make["ok"] and p12_ok)
    functional = ok and chain_ok and neg_ok and p12_neg
    return _b16_out(ok, functional,
                    _transcript(("pki --gen (CA)", gen_ca), ("pki --self (CA)", self_res),
                                ("pki --gen (server)", gen_srv), ("pki --req", req),
                                ("pki --issue", issue), ("pki --verify", verify),
                                ("unrelated CA (must fail)", neg),
                                ("openssl pkcs12 -export", p12_make),
                                ("pki --pkcs12 --list", p12_list),
                                ("pki --pkcs12 wrong password (must fail)", p12_bad),
                                ("plugin list", {"exit_code": 0, "stdout": usage_text[:600],
                                                  "stderr": ""})),
                    "strongswan pki: RSA keygen, X.509 issue/verify, PKCS#12 parse via the "
                    "OpenSSL plugin",
                    "strongswan pki did not issue and verify the fixture credential",
                    "pki verified under the unrelated CA or accepted the wrong PKCS#12 password")


def _wl_dcmtk(ctx: dict) -> dict:
    """DCMTK dcmsign: CMS SignedData over a DICOM dataset, with tamper and wrong-CA controls."""
    d, prog = ctx["workdir"], str(ctx["program"])
    root = ctx["root"]
    env = dict(ctx["env"], DCMDICTPATH=str(root / "dcmdata" / "data" / "dicom.dic"))
    dump2dcm = Path(prog).with_name("dump2dcm")
    dcmodify = Path(prog).with_name("dcmodify")
    dump = d / "fixture.dump"
    dump.write_text(
        "(0008,0005) CS [ISO_IR 100] # 10, 1 SpecificCharacterSet\n"
        "(0008,0060) CS [OT] # 2, 1 Modality\n"
        "(0010,0010) PN [Fixture^Patient] # 16, 1 PatientName\n"
        "(0020,000D) UI [1.2.840.10008.5.1.4.1.1.7] # 26, 1 StudyInstanceUID\n",
        encoding="utf-8")
    src, signed = d / "fixture.dcm", d / "signed.dcm"
    key, crt = d / "sign.key", d / "sign.crt"
    other = _gen_pki(ctx["authority_prefix"], d / "other")
    gen = _ossl(ctx["authority_prefix"], [
        "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-nodes",
        "-not_before", "20200101000000Z", "-not_after", "20300101000000Z",
        "-subj", "/CN=dcmtk-fixture", "-keyout", str(key), "-out", str(crt)], cwd=d)
    made = _run_captured([str(dump2dcm), str(dump), str(src)], cwd=d, env=env, timeout=60)
    sign = _run_captured([str(prog), "+s", str(key), str(crt), "+m2", "-pw", str(src),
                          str(signed)], cwd=d, env=env, timeout=120)
    verify = _run_captured([str(prog), "--verify", "+rg", "+cf", str(crt), str(signed)],
                           cwd=d, env=env, timeout=120)
    neg_ca = _run_captured([str(prog), "--verify", "+rg", "+cf", str(other["other_crt"]),
                            str(signed)], cwd=d, env=env, timeout=120)
    tampered = d / "tampered.dcm"
    tamper_step = {"exit_code": 1, "stdout": "", "stderr": "signed file absent", "ok": False}
    if signed.is_file():
        shutil.copy2(signed, tampered)
        tamper_step = _run_captured([str(dcmodify), "-m", "PatientName=Changed^Patient",
                                     str(tampered)], cwd=d, env=env, timeout=60)
    neg_tamper = _run_captured([str(prog), "--verify", "+rg", "+cf", str(crt), str(tampered)],
                               cwd=d, env=env, timeout=120)
    verify_text = verify["stdout"] + verify["stderr"]
    neg_ca_text = neg_ca["stdout"] + neg_ca["stderr"]
    neg_tamper_text = neg_tamper["stdout"] + neg_tamper["stderr"]
    ok = bool(gen["ok"] and made["ok"] and sign["ok"] and verify["ok"]
              and "Signature Verification : OK" in verify_text)
    functional = bool(ok and neg_ca["exit_code"] != 0
                      and "certificate verification failed" in neg_ca_text
                      and neg_tamper["exit_code"] != 0
                      and "document corrupted" in neg_tamper_text)
    return _b16_out(ok, functional,
                    _transcript(("dump2dcm", made), ("dcmsign +s +m2", sign),
                                ("dcmsign --verify", verify),
                                ("unrelated CA (must fail)", neg_ca),
                                ("dcmodify tamper", tamper_step),
                                ("tampered dataset (must fail)", neg_tamper)),
                    "DCMTK dcmsign: CMS SignedData (SHA-256) over a DICOM dataset, with "
                    "tampered-dataset and unrelated-CA controls",
                    "dcmsign did not sign and verify the DICOM dataset",
                    "dcmsign accepted the tampered dataset or the unrelated CA")


def _wl_postfix(ctx: dict) -> dict:
    """postfix posttls-finger: TLS engine, chain verification and name matching."""
    d, prog = ctx["workdir"], str(ctx["program"])
    pki = _gen_pki(ctx["authority_prefix"], d / "pki")
    port = _free_port()
    confdir = d / "etc" / "postfix"
    confdir.mkdir(parents=True, exist_ok=True)
    (confdir / "main.cf").write_text(
        "mail_owner = daemon\ndefault_privs = mail\nsetgid_group = nogroup\n"
        "smtp_tls_security_level = verify\n", encoding="utf-8")
    env = dict(ctx["env"], MAIL_CONFIG=str(confdir))

    def serve() -> None:
        listener = socket.socket()
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", port))
        listener.listen(1)
        listener.settimeout(20)
        sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        sctx.load_cert_chain(str(pki["srv_crt"]), str(pki["srv_key"]))
        try:
            conn, _ = listener.accept()
            with conn, sctx.wrap_socket(conn, server_side=True) as tls:
                tls.sendall(b"220 fixture ESMTP\r\n")
                tls.settimeout(5)
                try:
                    while True:
                        line = tls.recv(4096)
                        if not line:
                            break
                        if line.startswith(b"QUIT"):
                            tls.sendall(b"221 bye\r\n")
                            break
                        if line.startswith(b"EHLO"):
                            tls.sendall(b"250-fixture\r\n250 STARTTLS\r\n")
                        else:
                            tls.sendall(b"250 ok\r\n")
                except OSError:
                    pass
        except OSError:
            return
        finally:
            listener.close()

    def finger(ca: Path) -> dict:
        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        res = _run_captured([prog, "-w", "-c", "-F", str(ca), "-p", "TLSv1.2",
                             "127.0.0.1:{}".format(port)], cwd=d, env=env, timeout=45)
        thread.join(timeout=25)
        return res

    good = finger(pki["ca_crt"])
    bad = finger(pki["other_crt"])
    good_text = good["stdout"] + good["stderr"]
    bad_text = bad["stdout"] + bad["stderr"]
    # Postfix passes the literal destination "127.0.0.1" to SSL_add1_host(); OpenSSL's
    # X509_check_host does not match IP literals against dNSName SANs, so the *name*
    # check fails (num=62) even though the chain verified.  The chain result is what
    # distinguishes the two subjects here: num=62 means trusted chain + name mismatch;
    # an unrelated CA yields "untrusted issuer".
    tls_ok = ("TLSv1.2" in good_text
              and "ECDHE-RSA-AES256-GCM-SHA384" in good_text
              and "hostname mismatch" in good_text
              and "untrusted issuer" not in good_text)
    neg_ok = "untrusted issuer" in bad_text
    functional = bool(good["exit_code"] == 0 and bad["exit_code"] == 0 and tls_ok and neg_ok)
    return _b16_out(bool(good["ok"] and bad["ok"]), functional,
                    _transcript(("SMTPS (fixture CA)", good),
                                ("SMTPS (unrelated CA)", bad)),
                    "Postfix posttls-finger: implicit-TLS (SMTPS) handshake, TLS1.2 cipher "
                    "and chain/name verification result",
                    "posttls-finger did not establish SMTPS",
                    "the unrelated CA was not reported as untrusted")


def _wl_mutt(ctx: dict) -> dict:
    """Mutt submits a message to a local SMTPS peer over a verified TLS session."""
    d, prog = ctx["workdir"], str(ctx["program"])
    pki = _gen_pki(ctx["authority_prefix"], d / "pki")
    port = _free_port()
    state = {"data": ""}

    def serve() -> None:
        listener = socket.socket()
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", port))
        listener.listen(1)
        listener.settimeout(20)
        sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        sctx.load_cert_chain(str(pki["srv_crt"]), str(pki["srv_key"]))
        try:
            conn, _ = listener.accept()
            with conn, sctx.wrap_socket(conn, server_side=True) as tls:
                stream = tls.makefile("rwb", buffering=0)
                stream.write(b"220 fixture ESMTP\r\n")
                while True:
                    line = stream.readline()
                    if not line:
                        break
                    cmd = line.strip().split(b" ")[0].upper()
                    if cmd in (b"EHLO", b"HELO"):
                        stream.write(b"250-fixture\r\n250 SIZE 10240000\r\n")
                    elif cmd == b"DATA":
                        stream.write(b"354 go\r\n")
                        body = b""
                        while True:
                            part = stream.readline()
                            if not part or part == b".\r\n":
                                break
                            body += part
                        state["data"] = body.decode("utf-8", "replace")
                        stream.write(b"250 queued\r\n")
                    elif cmd == b"QUIT":
                        stream.write(b"221 bye\r\n")
                        break
                    else:
                        stream.write(b"250 ok\r\n")
        except OSError:
            return
        finally:
            listener.close()

    conf = d / "muttrc"
    conf.write_text(
        'set smtp_url="smtps://fixture@127.0.0.1:%d/"\n'
        "set ssl_starttls=no\n"
        "set ssl_verify_host=yes\n"
        "set from=fixture@example\n"
        "set realname=fixture\n"
        "set use_from=yes\n"
        "set hostname=fixture.example\n"
        "set record=\"\"\n"
        "set copy=no\n"
        "set sendmail_wait=0\n" % port, encoding="utf-8")

    def submit(ca: Path) -> dict:
        state["data"] = ""
        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        env = dict(ctx["env"], HOME=str(d), SSL_CERT_FILE=str(ca))
        res = _run_captured([prog, "-F", str(conf), "-s", "fixture", "recipient@example"],
                            cwd=d, env=env, timeout=45,
                            stdin_text="mutt-fixture-body\n")
        thread.join(timeout=25)
        return res

    good = submit(pki["ca_crt"])
    good_data = state["data"]
    bad = submit(pki["other_crt"])
    bad_data = state["data"]
    ok = bool(good["ok"] and "mutt-fixture-body" in good_data)
    functional = bool(ok and "mutt-fixture-body" not in bad_data)
    return _b16_out(ok, functional,
                    _transcript(("SMTPS submission", good),
                                ("delivered body", {"exit_code": 0,
                                                    "stdout": good_data[:400],
                                                    "stderr": ""}),
                                ("unrelated CA (must fail)", bad),
                                ("negative delivered body", {"exit_code": 0,
                                                             "stdout": bad_data[:200],
                                                             "stderr": ""})),
                    "mutt: message submitted to a local SMTPS peer over verified TLS",
                    "mutt did not deliver the message over TLS",
                    "a message was delivered while trusting the unrelated CA")


RUNNERS = {
    "icecast2": _wl_icecast,
    "libevent-openssl-2.1-7": _wl_libevent,
    "libaprutil1": _wl_aprutil,
    "curl": _wl_curl,
    "nginx": _wl_nginx,
    "haproxy": _wl_haproxy,
    "openssh": _wl_openssh,
    "redis": _wl_redis,
    "monit": _wl_monit,
    "pure-ftpd": _wl_pureftpd,
    "isync": _wl_isync,
    "fossil": _wl_fossil,
    "ldns": _wl_ldns,
    "rsync": _wl_rsync,
    "socat": _wl_socat,
    "squid": _wl_squid,
    "stunnel": _wl_stunnel,
    "sslscan": _wl_sslscan,
    "openvpn": _wl_openvpn,
    "tinc": _wl_tinc,
    "hiredis-ssl": _wl_hiredis,
    "proxytunnel": _wl_proxytunnel,
    "keepalived": _wl_keepalived,
    "ssmtp": _wl_ssmtp,
    "tnftp": _wl_tnftp,
    "libevent": _wl_libevent,
    "libretls": _wl_libretls,
    "libarchive": _wl_libarchive,
    "mosquitto": _wl_mosquitto,
    "cyrus-sasl": _wl_cyrus_sasl,
    # The Phase-25 template-layer continuation's bespoke workloads.
    "git-crypt": _wl_git_crypt,
    "s2n-tls": _wl_s2n,
    "openldap": _wl_openldap,
    "srt": _wl_srt,
    "slowhttptest": _wl_slowhttptest,
    "cyrus-sasl-scram": _wl_cyrus_sasl,
    "cyrus-sasl-digestmd5": _wl_cyrus_sasl,
    # The Phase-25 L7 onboarding batch (b14).
    "nmap-ncat": _wl_ncat,
    "unbound": _wl_unbound,
    "qpdf": _wl_qpdf,
    "nagios-plugins-smtp": _wl_nagios_smtp,
    "nagios-plugins-ldap": _wl_nagios_ldap,
    "efitools": _wl_efitools,
    "libpaho-mqtt": _wl_paho,
    "srtp": _wl_srtp,
    "rabbitmq-c": _wl_rabbitmq,
    "sipsak": _wl_sipsak,
    "links": _wl_links,
    "dovecot": _wl_dovecot,
    "librdkafka": _wl_rdkafka,
    "fetchmail": _wl_fetchmail,
    "iperf3": _wl_iperf3,
    "kmod": _wl_kmod,
    "jwt": _wl_jwt,
    "libjose": _wl_libjose,
    "libzip": _wl_libzip,
    "apr-util": _wl_aprutil,
    "fido2": _wl_fido2,
    # The Phase-25 L7 server batch.
    "memcached": _wl_memcached,
    "icecast": _wl_icecast,
    "proftpd": _wl_proftpd,
    "mini-httpd": _wl_mini_httpd,
    "hitch": _wl_hitch,
    # The Phase-25 L7 client/proxy batch.
    "radsecproxy": _wl_radsecproxy,
    "znc": _wl_znc,
    "s-nail": _wl_s_nail,
    "w3m": _wl_w3m,
    # The Phase-25 L7 utility batch.
    "axel": _wl_axel,
    "apache2-utils": _wl_apache2_utils,
    "osslsigncode": _wl_osslsigncode,
    "u-boot-tools": _wl_u_boot_tools,
    "sslsplit": _wl_sslsplit,
    "opendkim": _wl_opendkim,
    # The Phase-25 L7 expansion batch (b5).
    "nmap": _wl_nmap,
    "fastd": _wl_fastd,
    "kea": _wl_kea,
    "mumble-server": _wl_mumble,
    "prosody": _wl_prosody,
    "partclone": _wl_partclone,
    # The Phase-25 L7 expansion batch (b6).
    "exim": _wl_exim,
    "nsd": _wl_nsd,
    "net-snmp": _wl_net_snmp,
    "eggdrop": _wl_eggdrop,
    "irssi": _wl_irssi,
    "openssh-server": _wl_openssh_server,
    # The Phase-25 L7 expansion batch (b7).
    "tcpdump": _wl_tcpdump,
    "slrn": _wl_slrn,
    "epic5": _wl_epic5,
    "bannergrab": _wl_bannergrab,
    "httperf": _wl_httperf,
    "makepasswd": _wl_makepasswd,
    # The Phase-25 L7 expansion batch (b8).
    "cowpatty": _wl_cowpatty,
    "hcxtools": _wl_hcxtools,
    "aircrack-ng": _wl_aircrack,
    "nrpe": _wl_nrpe,
    "mktorrent": _wl_mktorrent,
    # The Phase-25 L7 expansion batch (b9): six LIBRARY-only families.
    "libwebsockets": _wl_libwebsockets,
    "libstrophe": _wl_libstrophe,
    "libcoap": _wl_libcoap,
    "libesmtp": _wl_libesmtp,
    "minizip-ng": _wl_minizip_ng,
    "libtins": _wl_libtins,
    # The Phase-25 L7 expansion batch (b10).
    "getdns": _wl_getdns,
    "libu2f-server": _wl_libu2f_server,
    "lua-luaossl": _wl_luaossl,
    "lua-sec": _wl_luasec,
    "duo_unix": _wl_duo_unix,
    "dcap-tunnel-ssl": _wl_dcap_tunnel,
    # The Phase-25 L7 expansion batch (b11).
    "gensio": _wl_gensio,
    "jimtcl": _wl_jimtcl,
    "sofia-sip": _wl_sofia_sip,
    # The Phase-25 L7 expansion batch (b12).
    "libtpms": _wl_libtpms,
    "libre": _wl_libre,
    "arm-trusted-firmware-tools": _wl_atf,
    "libnetconf2": _wl_libnetconf2,
    "liboauth2": _wl_liboauth2,
    # The Phase-25 L7 expansion batch (b13).
    "elinks": _wl_elinks,
    "lynx": _wl_lynx,
    "lftp": _wl_lftp,
    "lighttpd": _wl_lighttpd,
    "swtpm": _wl_swtpm,
    "httping": _wl_httping,
    "libssh": _wl_libssh,
    # The Phase-25 L7 onboarding batch (b15).
    "vsftpd": _wl_vsftpd,
    "apache2-bin": _wl_apache,
    "ssldump": _wl_ssldump,
    "yara": _wl_yara,
    "bruteforce-salted-openssl": _wl_bruteforce,
    "ircii": _wl_ircii,
    "neon": _wl_neon,
    "cjose": _wl_cjose,
    "libevhtp": _wl_evhtp,
    "libxmlsec1": _wl_xmlsec,

}

# The declarative template cohort's bucket runners.  Each is the same parameterised Python
# fixture; only the family's config row (argv, expectation, negative control, CA/port policy)
# differs, so ten template families do not add ten bespoke runners.
RUNNERS.update(templates.runners())

# The Phase-25 c2 split rows: the same program intent and admitted workload as the parent, with
# only the package-specific artifact (and the cyrus-sasl mechanism) changed.
_SPLIT_RUNTIME: tuple[tuple[str, str, dict], ...] = (
    ("libcjose0", "cjose", {}),
    ("libgetdns10", "getdns", {}),
    ("asterisk-srtp", "srtp", {}),
    ("epic5-lite", "epic5", {}),
    ("httpd", "apache2-bin", {}),
    ("librabbitmq", "rabbitmq-c", {}),
)
for _new, _base, _overrides in _SPLIT_RUNTIME:
    PROGRAMS[_new] = copy.deepcopy(PROGRAMS[_base])
    PROGRAMS[_new].update(_overrides)
    RUNNERS[_new] = RUNNERS[_base]

PROGRAMS["ima-evm-utils"] = {
    "program": "src/.libs/evmctl", "launch": ["--version"], "version_re": r"evmctl",
    "lib_paths": ["src/.libs"],
    "note": ("evmctl signs a file's IMA digest with the subject libcrypto and verifies it; a "
             "modified file no longer verifies"),
}
RUNNERS["ima-evm-utils"] = _wl_ima

# The Phase-25 L7 onboarding batch (b16).  Each program is the family's own executable or, for
# AFFLIB and libshout, the library's admitted signer/streamer; the workload is the loopback
# exercise implemented by the `_wl_*` runner above.
_B16_PROGRAMS: dict[str, dict] = {
    "sscg": {"program": "b/sscg", "launch": ["--version"], "version_re": r"4\.0\.3",
             "lib_paths": []},
    "shellinabox": {"program": "shellinaboxd", "launch": ["--version"],
                    "version_re": r"shellinabox", "lib_paths": []},
    "charybdis": {"program": "ircd/.libs/charybdis", "launch": ["--version"],
                  "version_re": r"(?i)(charybdis|ircd)",
                  "lib_paths": ["ircd/.libs", "librb/src/.libs"]},
    "afflib": {"program": "tools/.libs/affsign", "launch": ["-v"],
               "version_re": r"affsign version", "lib_paths": ["lib/.libs"]},
    "httest": {"program": "src/httest", "launch": ["--version"],
               "version_re": r"httest", "lib_paths": []},
    "sipp": {"program": "b/sipp", "launch": ["-v"], "version_re": r"SIPp v",
             "lib_paths": []},
    # DMA 0.14 has no version/help banner that names itself (`-h` takes an argument and
    # is ignored), so the launch proof is an empty-output exit plus the loader closure;
    # the TLS workload below is the functional evidence.
    # DMA 0.14 has no version/help banner that names itself (`-h` takes an argument and
    # is ignored), so the launch proof is an empty-output exit plus the loader closure;
    # the TLS workload below is the functional evidence.  `-q` reads the configured spool
    # directory before any OpenSSL call, so the probe first makes the default spool exist and
    # removes any stale configuration left by an earlier workload run (S44).
    "dma": {"program": "dma", "launch": ["-q"], "version_re": r"^$", "lib_paths": [],
            "pre_launch": [["sh", "-c", "rm -f /etc/dma/dma.conf /etc/dma/auth.conf"],
                           ["mkdir", "-p", "/var/spool/dma"]]},
    "h2o": {"program": "b/h2o", "launch": ["--version"], "version_re": r"h2o version",
            "lib_paths": []},
    "libshout": {"program": "tools/.libs/shout", "launch": ["--help"],
                 "version_re": r"(?i)usage: .*shout", "lib_paths": ["src/.libs"]},
    "nghttp2": {"program": "src/.libs/nghttp", "launch": ["--version"],
                "version_re": r"nghttp2", "lib_paths": ["lib/.libs", "src/.libs"]},
}
PROGRAMS.update(_B16_PROGRAMS)
RUNNERS.update({
    "sscg": _wl_sscg,
    "shellinabox": _wl_shellinabox,
    "charybdis": _wl_charybdis,
    "afflib": _wl_afflib,
    "httest": _wl_httest,
    "sipp": _wl_sipp,
    "dma": _wl_dma,
    "h2o": _wl_h2o,
    "libshout": _wl_libshout,
    "nghttp2": _wl_nghttp2,
})


# The S33 corpus batch: CMS/S/MIME, PKCS#12, OCSP, X.509 verification, raw-key,
# legacy-ENGINE, DTLS and TLS-transport surface.  A Perl XS family runs its admitted
# script through the embedded-Perl harness linked against the module under test.
_S33_PERL_COMMON = {
    "program": ".l7-perl-harness", "launch": ["--version"],
    "version_re": r"perl-l7-harness", "lib_paths": [],
    "env": {"PERL5LIB": ("{root}/blib/lib:{root}/blib/arch:"
                        "{root}/.perl-deps/lib:{root}/.perl-deps/arch")},
}
_Perl_cflags = [
    "-I/usr/lib/x86_64-linux-gnu/perl/5.36/CORE", "-D_REENTRANT", "-D_GNU_SOURCE",
    "-DDEBIAN", "-fwrapv", "-fno-strict-aliasing", "-pipe", "-D_LARGEFILE_SOURCE",
    "-D_FILE_OFFSET_BITS=64", "-DL7_NAME=\"perl-l7-harness\"",
]


def _s33_perl_program(family: str, script: str, module_dir: str, module: str,
                      markers: list[str], note: str, *, tls: bool = False) -> dict:
    prog = copy.deepcopy(_S33_PERL_COMMON)
    prog.update({
        "script": script, "markers": markers, "note": note,
        "tls_fixture": tls,
        "harness": {
            "source": "forensics/tools/l7_perl_runner.c",
            "cflags": _Perl_cflags + [
                f"-DL7_SCRIPT_PATH=\"{{repo}}/forensics/tools/{script}\""],
            "ldflags": [
                f"-L{{root}}/blib/arch/auto/{module_dir}",
                f"-Wl,-rpath,{{root}}/blib/arch/auto/{module_dir}",
                "-Wl,--no-as-needed", f"-l:{module}",
                "-L/usr/lib/x86_64-linux-gnu",
                "-Wl,-rpath,/usr/lib/x86_64-linux-gnu",
                "-Wl,-E", "-l:libperl.so.5.36", "-ldl", "-lm", "-lpthread", "-lc",
                "-lcrypt"],
        },
    })
    return prog


_S33_PROGRAMS: dict[str, dict] = {
    "perl-net-ssleay": _s33_perl_program(
        "perl-net-ssleay", "l7_perl_net_ssleay.pl", "Net/SSLeay", "SSLeay.so",
        ["tls_connect=ok", "tls_payload=ok", "tls_session=ok",
         "tls_unrelated_ca=rejected"],
        "Net::SSLeay 1.92: verified TLS handshake, payload and session reuse + "
        "unrelated-CA reject", tls=True),
    "perl-crypt-smime": _s33_perl_program(
        "perl-crypt-smime", "l7_perl_crypt_smime.pl", "Crypt/SMIME", "SMIME.so",
        ["smime_sign=ok", "smime_check=ok", "smime_encrypt=ok", "smime_roundtrip=ok"],
        "Crypt::SMIME 0.28: CMS sign/check and encrypt/decrypt (S/MIME)"),
    "perl-crypt-openssl-x509": _s33_perl_program(
        "perl-crypt-openssl-x509", "l7_perl_crypt_openssl_x509.pl",
        "Crypt/OpenSSL/X509", "X509.so",
        ["x509_parse=ok", "x509_subject=ok", "x509_fingerprint=ok", "x509_pubkey=ok",
         "x509_checkend=ok", "x509_extensions=ok", "x509_issuer_matches_ca=ok",
         "x509_unrelated_differs=ok"],
        "Crypt::OpenSSL::X509 1.9.14: parse, fingerprint, extensions and issuer linkage"),
    "perl-crypt-openssl-rsa": _s33_perl_program(
        "perl-crypt-openssl-rsa", "l7_perl_crypt_openssl_rsa.pl",
        "Crypt/OpenSSL/RSA", "RSA.so",
        ["rsa_sign=ok", "rsa_verify=ok", "rsa_tamper_rejected=ok", "rsa_encrypt=ok",
         "rsa_decrypt=ok"],
        "Crypt::OpenSSL::RSA 0.33: RSA keygen, sign/verify and public encrypt/decrypt"),
    "libcrypt-openssl-ec-perl": _s33_perl_program(
        "libcrypt-openssl-ec-perl", "l7_perl_crypt_openssl_ec.pl",
        "Crypt/OpenSSL/EC", "EC.so",
        ["ec_group=ok", "ec_point_new=ok", "ec_point_infinity=ok"],
        "Crypt::OpenSSL::EC 1.32: P-256 group construction and point operations"),
    "libcrypt-openssl-pkcs10-perl": _s33_perl_program(
        "libcrypt-openssl-pkcs10-perl", "l7_perl_crypt_openssl_pkcs10.pl",
        "Crypt/OpenSSL/PKCS10", "PKCS10.so",
        ["pkcs10_sign=ok", "pkcs10_pubkey=ok", "pkcs10_pubkey_type=ok"],
        "Crypt::OpenSSL::PKCS10 0.19: CSR construction/signing and public-key export"),
    "perl-crypt-openssl-aes": _s33_perl_program(
        "perl-crypt-openssl-aes", "l7_perl_crypt_openssl_aes.pl",
        "Crypt/OpenSSL/AES", "AES.so",
        ["aes_encrypt=ok", "aes_roundtrip=ok", "aes_cbc_encrypt=ok",
         "aes_cbc_roundtrip=ok"],
        "Crypt::OpenSSL::AES 0.23: AES-256 ECB/CBC encrypt/decrypt roundtrip"),
    "perl-crypt-openssl-dsa": _s33_perl_program(
        "perl-crypt-openssl-dsa", "l7_perl_crypt_openssl_dsa.pl",
        "Crypt/OpenSSL/DSA", "DSA.so",
        ["dsa_sign=ok", "dsa_verify=ok", "dsa_tamper_rejected=ok",
         "dsa_pem_roundtrip=ok"],
        "Crypt::OpenSSL::DSA 0.20: DSA keygen, sign/verify and PEM roundtrip"),
    "perl-crypt-openssl-bignum": _s33_perl_program(
        "perl-crypt-openssl-bignum", "l7_perl_crypt_openssl_bignum.pl",
        "Crypt/OpenSSL/Bignum", "Bignum.so",
        ["bn_add=ok", "bn_mul=ok", "bn_modexp=ok", "bn_inverse=ok"],
        "Crypt::OpenSSL::Bignum 0.09: BN add/mul/mod_exp/mod_inverse"),
    "perl-crypt-openssl-random": _s33_perl_program(
        "perl-crypt-openssl-random", "l7_perl_crypt_openssl_random.pl",
        "Crypt/OpenSSL/Random", "Random.so",
        ["rand_bytes=ok", "rand_differs=ok", "rand_status=ok"],
        "Crypt::OpenSSL::Random 0.15: RAND_bytes and RAND_status"),
    "php": {
        "program": "sapi/cli/php", "launch": ["-v"], "version_re": r"PHP 8\.2",
        "lib_paths": [],
        "note": ("PHP 8.2.32 openssl ext: PKCS#12, CMS/PKCS#7, X.509 purpose check"),
    },
    "ruby": {
        "program": "ruby", "launch": ["-v"], "version_re": r"ruby 3\.1",
        "lib_paths": [],
        "note": ("Ruby 3.1.2 ext/openssl: PKCS#12, PKCS#7, OCSP, store verify, Ed25519"),
    },
    "libcpp-httplib0.11": {
        "program": ".l7-httplib-harness", "launch": ["--help"],
        "version_re": r"usage:", "lib_paths": [],
        "note": "cpp-httplib 0.11.4: SSLServer/SSLClient verified fetch + wrong-CA reject",
    },
}
PROGRAMS.update(_S33_PROGRAMS)
RUNNERS.update({
    "perl-net-ssleay": _wl_perl, "perl-crypt-smime": _wl_perl,
    "perl-crypt-openssl-x509": _wl_perl, "perl-crypt-openssl-rsa": _wl_perl,
    "libcrypt-openssl-ec-perl": _wl_perl, "libcrypt-openssl-pkcs10-perl": _wl_perl,
    "perl-crypt-openssl-aes": _wl_perl, "perl-crypt-openssl-dsa": _wl_perl,
    "perl-crypt-openssl-bignum": _wl_perl, "perl-crypt-openssl-random": _wl_perl,
    "php": _wl_php, "ruby": _wl_ruby, "libcpp-httplib0.11": _wl_httplib,
})

# S44 package rows: the corpus carries the distribution package name as a separate family from the
# CPAN-style recipe name.  The pristine archive, build intent and admitted Perl harness are the
# same module, so each row reuses the parent's program intent and workload verbatim.
for _row, _parent in (
    ("libcrypt-openssl-bignum-perl", "perl-crypt-openssl-bignum"),
    ("libcrypt-openssl-random-perl", "perl-crypt-openssl-random"),
    ("libcrypt-openssl-rsa-perl", "perl-crypt-openssl-rsa"),
    ("libcrypt-openssl-dsa-perl", "perl-crypt-openssl-dsa"),
    ("libcrypt-openssl-x509-perl", "perl-crypt-openssl-x509"),
    ("libcrypt-smime-perl", "perl-crypt-smime"),
    ("h2o-evloop0.13", "h2o"),
    ("libafflib0v5", "afflib"),
    ("apache2-ssl", "apache2-bin"),
    ("libduo3", "duo_unix"),
):
    PROGRAMS[_row] = copy.deepcopy(PROGRAMS[_parent])
    RUNNERS[_row] = RUNNERS[_parent]

# The S36 corpus/Phase-1 additions: consumers with an admitted local workload for a
# surface the earlier batches did not reach (strongSwan PKI/PKCS#12, DCMTK CMS
# SignedData, Postfix's TLS engine).
_S36_PROGRAMS = {
    "strongswan": {
        "program": ".l7-strongswan-harness", "launch": ["--version"],
        "version_re": r"strongswan-l7-harness",
        "lib_paths": ["src/libstrongswan/.libs", "src/libtls/.libs", "src/pki/.libs"],
        "harness": {
            "source": "forensics/tools/l7_strongswan.c",
            "cflags": ["-I{prefix}/include"],
            "ldflags": ["-L{prefix}/lib", "-Wl,-rpath,{prefix}/lib", "-lcrypto"],
        },
        "env": {"S36_PKI": "{root}/src/pki/.libs/pki",
                "STRONGSWAN_CONF": "{root}/strongswan.conf"},
        "note": ("strongSwan 5.9.8 pki through the openssl plugin: RSA keygen, "
                 "X.509 issue/verify, PKCS#10 and PKCS#12 parse"),
    },
    "dcmtk": {
        "program": "b/bin/dcmsign", "launch": ["--version"],
        "version_re": r"dcmsign v3\.6\.7", "lib_paths": [],
        "note": ("DCMTK 3.6.7 dcmsign: CMS SignedData over a DICOM dataset, with "
                 "tampered-dataset and unrelated-CA controls"),
    },
    "postfix": {
        "program": "src/posttls-finger/posttls-finger", "launch": [],
        "version_re": r"usage: posttls-finger", "lib_paths": [],
        "env": {"MAIL_CONFIG": "{root}/.s36-postfix"},
        "note": ("Postfix 3.7.11 posttls-finger: implicit TLS (SMTPS), TLS1.2 cipher "
                 "and chain verification"),
    },
    "mutt": {
        "program": "mutt", "launch": ["-v"], "version_re": r"Mutt 2\.2\.13",
        "lib_paths": [],
        "note": ("Mutt 2.2.13: SMTPS submission over verified TLS, with the classic "
                 "S/MIME PKCS#7/CMS implementation linked against the subject"),
    },
}
PROGRAMS.update(_S36_PROGRAMS)
RUNNERS.update({
    "strongswan": _wl_strongswan,
    "dcmtk": _wl_dcmtk,
    "postfix": _wl_postfix,
    "mutt": _wl_mutt,
})

def _wl_sqlcipher(ctx: dict) -> dict:
    """SQLCipher writes, reads and refuses a wrong key on a real database file."""
    d = ctx["workdir"]
    prog = str(ctx["program"])
    db = d / "s46-sqlcipher.db"
    try:
        db.unlink()
    except OSError:
        pass
    sql = ("PRAGMA key='phase25-l7-key'; CREATE TABLE t(v); "
           "INSERT INTO t VALUES('phase25-l7-sqlcipher'); SELECT v FROM t;")
    made = _run_captured([prog, str(db), sql], cwd=d, env=ctx["env"], timeout=60)
    read = _run_captured([prog, str(db), "PRAGMA key='phase25-l7-key'; SELECT v FROM t;"],
                         cwd=d, env=ctx["env"], timeout=60)
    wrong = _run_captured([prog, str(db), "PRAGMA key='wrong-key'; SELECT v FROM t;"],
                          cwd=d, env=ctx["env"], timeout=60)
    good_text = made["stdout"] + made["stderr"] + read["stdout"] + read["stderr"]
    wrong_text = wrong["stdout"] + wrong["stderr"]
    runtime_ok = bool(made["ok"] and read["ok"] and "phase25-l7-sqlcipher" in good_text)
    rejected = bool(not wrong["ok"] or "phase25-l7-sqlcipher" not in wrong_text)
    functional_ok = runtime_ok and rejected
    return {
        "runtime_ok": runtime_ok, "functional_ok": functional_ok,
        "failure_class": None if functional_ok else (
            "functional-failure" if runtime_ok else "runtime-failure"),
        "residual": "none" if functional_ok else (
            "functional-divergence" if runtime_ok else "runtime-failure"),
        "reason": None if functional_ok else (
            "the encrypted database did not round-trip" if not runtime_ok else
            "a wrong key still opened the database"),
        "transcript": _transcript(("sqlcipher create+select", made),
                                  ("sqlcipher reopen", read),
                                  ("sqlcipher wrong key", wrong)),
        "workload": ("sqlcipher: AES-256 page encryption round trip + wrong-key reject"),
        "local_only": True,
    }


def _wl_tcltls(ctx: dict) -> dict:
    """TclTLS's TLS client channel against a local server and an unrelated-CA reject."""
    ap, d = ctx["authority_prefix"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    port, neg_port = _free_port(), _free_port()
    good_srv = _spawn([str(_auth_ossl(ap)), "s_server", "-accept", str(port),
                       "-cert", str(pki["srv_crt"]), "-key", str(pki["srv_key"]),
                       "-www", "-quiet"], d, _auth_env(ap),
                      d / "tcl-good.out", d / "tcl-good.err")
    bad_srv = _spawn([str(_auth_ossl(ap)), "s_server", "-accept", str(neg_port),
                      "-cert", str(pki["other_srv_crt"]), "-key", str(pki["other_srv_key"]),
                      "-www", "-quiet"], d, _auth_env(ap),
                     d / "tcl-bad.out", d / "tcl-bad.err")
    try:
        if not (_wait_tcp("127.0.0.1", port) and _wait_tcp("127.0.0.1", neg_port)):
            return _wl_fail([("openssl s_server", {"exit_code": 0, "stdout": ""})],
                            "the local TLS servers did not start", "runtime-failure", d)
        argv = [str(ctx["root"]), str(port), str(neg_port), str(pki["ca_crt"]),
                str(pki["other_crt"])]
        return _wl_markers_argv(ctx, argv, ["tcltls_payload=ok",
                                            "tcltls_unrelated_ca=rejected"],
                                "TclTLS TLS client channel + unrelated-CA reject")
    finally:
        _stop(good_srv)
        _stop(bad_srv)


def _wl_davix(ctx: dict) -> dict:
    """davix-get fetches the fixture over verified HTTPS and rejects an unrelated CA."""
    ap, d = ctx["authority_prefix"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    body = "davix-l7-payload"
    port = _free_port()
    stop, state = threading.Event(), {}
    thread = _https_fixture(port, pki, body, state, stop)
    good_dir, bad_dir = d / "ca-good", d / "ca-bad"
    for directory, cert in ((good_dir, pki["ca_crt"]), (bad_dir, pki["other_crt"])):
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "ca.pem").write_bytes(Path(cert).read_bytes())
        _ossl(ap, ["rehash", str(directory)])
    out_good, out_bad = d / "out-good", d / "out-bad"
    try:
        if not _wait_tcp("127.0.0.1", port):
            return _wl_fail([("tls fixture", {"exit_code": 0, "stdout": ""})],
                            "the local TLS fixture did not open its port",
                            "runtime-failure", d)
        url = f"https://127.0.0.1:{port}/"
        good = _run_captured([str(ctx["program"]), "-q", "--capath", str(good_dir),
                              "-o", str(out_good), url], cwd=d, env=ctx["env"], timeout=60)
        neg = _run_captured([str(ctx["program"]), "-q", "--capath", str(bad_dir),
                             "-o", str(out_bad), url], cwd=d, env=ctx["env"], timeout=60)
    finally:
        stop.set()
        state.get("listener", socket.socket()).close()
        thread.join(timeout=2)
    got = out_good.read_bytes() if out_good.is_file() else b""
    runtime_ok = bool(good["ok"] and body.encode() in got)
    rejected = bool(not neg["ok"] or not (out_bad.is_file() and body.encode() in out_bad.read_bytes()))
    functional_ok = runtime_ok and rejected
    return {
        "runtime_ok": runtime_ok, "functional_ok": functional_ok,
        "failure_class": None if functional_ok else (
            "functional-failure" if runtime_ok else "runtime-failure"),
        "residual": "none" if functional_ok else (
            "functional-divergence" if runtime_ok else "runtime-failure"),
        "reason": None if functional_ok else (
            "davix-get did not fetch the verified fixture" if not runtime_ok else
            "an unrelated CA was accepted"),
        "transcript": _transcript(("davix-get verified", good), ("davix-get wrong CA", neg)),
        "workload": "davix-get: verified HTTPS fetch + unrelated-CA reject",
        "local_only": True,
    }


def _wl_pyscrypt(ctx: dict) -> dict:
    """py-scrypt's scrypt KDF through the rebuilt extension and the subject libcrypto."""
    ap, d = ctx["authority_prefix"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    return _wl_markers_argv(ctx, [str(ctx["root"]), str(pki["srv_key"])],
                            ["scrypt_hash=ok", "scrypt_differs=ok"],
                            "py-scrypt: scrypt KDF vector + different-salt control")


def _wl_pym2crypto(ctx: dict) -> dict:
    """M2Crypto's RSA sign/verify through the rebuilt SWIG binding."""
    ap, d = ctx["authority_prefix"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    return _wl_markers_argv(ctx, [str(ctx["root"]), str(pki["srv_key"])],
                            ["m2_sign=ok", "m2_verify=ok", "m2_tamper=rejected"],
                            "M2Crypto: RSA sign/verify + tampered-signature reject")


def _wl_ewftools(ctx: dict) -> dict:
    """ewfacquire/ewfverify: the image digest is computed and re-verified over the subject."""
    d = ctx["workdir"]
    src = d / "s46-ewf-data.bin"
    src.write_bytes(bytes(range(256)) * 16)
    img = d / "s46-ewf-img"
    acquire = str(ctx["root"] / "ewftools" / ".libs" / "ewfacquire")
    verify = str(ctx["root"] / "ewftools" / ".libs" / "ewfverify")
    acq = _run_captured([acquire, "-u", "-q", "-t", str(img), "-C", "s46-case",
                         "-D", "s46", "-e", "s46", "-E", "s46", "-N", "s46",
                         "-m", "fixed", "-M", "physical", "-c", "deflate:none",
                         "-S", "1GiB", "-b", "64", "-B", "4096", "-P", "512",
                         "-g", "0", "-d", "sha256", str(src)],
                        cwd=d, env=ctx["env"], timeout=120)
    ver = _run_captured([verify, "-q", "-d", "sha256", str(img) + ".E01"],
                        cwd=d, env=ctx["env"], timeout=120)
    tampered = d / "s46-ewf-tampered.E01"
    tampered.write_bytes((img.with_suffix(".E01")).read_bytes())
    blob = bytearray(tampered.read_bytes())
    if blob:
        blob[len(blob) // 2] ^= 0xFF
    tampered.write_bytes(bytes(blob))
    neg = _run_captured([verify, "-q", "-d", "sha256", str(tampered)],
                        cwd=d, env=ctx["env"], timeout=120)
    good_text = acq["stdout"] + acq["stderr"] + ver["stdout"] + ver["stderr"]
    runtime_ok = bool(acq["ok"] and ver["ok"] and "ewfacquire: SUCCESS" in good_text
                      and "ewfverify: SUCCESS" in good_text)
    rejected = bool(not neg["ok"] or "ewfverify: SUCCESS" not in (
        neg["stdout"] + neg["stderr"]))
    functional_ok = runtime_ok and rejected
    return {
        "runtime_ok": runtime_ok, "functional_ok": functional_ok,
        "failure_class": None if functional_ok else (
            "functional-failure" if runtime_ok else "runtime-failure"),
        "residual": "none" if functional_ok else (
            "functional-divergence" if runtime_ok else "runtime-failure"),
        "reason": None if functional_ok else (
            "the acquired image did not verify" if not runtime_ok else
            "a tampered image still verified"),
        "transcript": _transcript(("ewfacquire", acq), ("ewfverify", ver),
                                  ("tampered image", neg)),
        "workload": ("ewf-tools: MD5/SHA-256 acquisition and re-verification + "
                     "tampered-image reject"),
        "local_only": True,
    }


# S44 corpus batch: the pristine tree's own test consumers are the admitted programs.
_S44_PROGRAMS = {
    "librelp": {
        "program": "tests/.libs/receive", "launch": ["-h"],
        "version_re": r"Usage: .*receive", "lib_paths": ["src/.libs"],
        "make_steps": [["-C", "tests", "receive", "send"]],
        "note": ("librelp 1.13.0's own send/receive pair: mutual TLS through the subject "
                 "libssl carries a message, and an unrelated CA is refused"),
    },
    "hydra": {
        "program": "hydra", "launch": ["-h"], "version_re": r"Hydra v\d",
        "lib_paths": [],
        "note": ("hydra 9.5 https-get: authenticated TLS request against the fixture, plus "
                 "a wrong-password control"),
    },
    "nagios-plugins-tcp": {
        "program": "plugins/check_tcp", "launch": ["-V"], "version_re": r"check_tcp",
        "lib_paths": [],
        "note": ("monitoring-plugins 2.4.0 check_tcp --ssl: a TLS handshake is accepted and "
                 "a plaintext peer is refused"),
    },
    "ncrack": {
        "program": "ncrack", "launch": ["-h"], "version_re": r"Ncrack \d",
        "lib_paths": [], "env": {"NCRACKDIR": "{root}"},
        "note": ("ncrack 0.7 HTTPS: the fixture credential is found over TLS and a wrong one "
                 "is not"),
    },
    "ircd-hybrid": {
        "program": "src/ircd", "launch": ["-v"],
        "version_re": r"ircd-hybrid-8\.2", "lib_paths": [],
        # The daemon refuses root before it parses any option, so the version/load probe runs
        # under the same unprivileged identity the workload uses.
        "launch_prefix": ["setpriv", "--reuid=nobody", "--regid=nogroup", "--clear-groups"],
        # The daemon chdirs to its compiled PREFIX before parsing the command line; the install
        # layout must exist for the launch/version probe (the workload stages and chowns it).
        "pre_launch": [["mkdir", "-p", "{root}/.l7-install/etc",
                        "{root}/.l7-install/var/lib", "{root}/.l7-install/var/run",
                        "{root}/.l7-install/var/log"]],
        "note": ("ircd-hybrid 8.2.46: TLS listener greeting over a verified session, plus an "
                 "unrelated-CA reject"),
    },
    "medusa": {
        "program": "src/medusa", "launch": ["-V"], "version_re": r"Medusa",
        "lib_paths": [],
        "note": ("medusa 2.3 http over TLS: fixture credential found and a wrong one missed"),
    },
}
PROGRAMS.update(_S44_PROGRAMS)
RUNNERS.update({"librelp": _wl_librelp, "hydra": _wl_hydra,
                "nagios-plugins-tcp": _wl_check_tcp, "ncrack": _wl_ncrack,
                "ircd-hybrid": _wl_ircd_hybrid, "medusa": _wl_medusa})


# S46 corpus batch: the consumers with an admitted deterministic workload.  Families in the batch
# without an entry here keep their build/link row (`no-fixture`), not a fabricated workload.
_S46_PROGRAMS: dict[str, dict] = {
    "tcl-tls": {
        "program": ".l7-tcl-harness", "launch": ["--version"],
        "version_re": r"tcltls-l7-harness", "lib_paths": [],
        "harness": {
            "source": "forensics/tools/l7_tcl_runner.c",
            "cflags": ["-I{aux}/usr/include", "-I{aux}/usr/include/tcl8.6",
                       "-DL7_TCL_LIBRARY=\"{aux}/usr/share/tcltk/tcl8.6\"",
                       "-DL7_TCL_TMLIB=\"{aux}/usr/share/tcltk/tcl8.6/tcl8\"",
                       "-DL7_SCRIPT_PATH=\"{repo}/forensics/tools/l7_tcltls.tcl\""],
            "ldflags": ["-L{aux}/usr/lib/x86_64-linux-gnu",
                        "-Wl,-rpath,{aux}/usr/lib/x86_64-linux-gnu",
                        "-L{prefix}/lib", "-Wl,-rpath,{prefix}/lib",
                        "-Wl,--no-as-needed", "-ltcl8.6", "-lssl", "-lcrypto",
                        "-ldl", "-lm", "-lpthread"],
        },
        "note": "TclTLS TLS client channel + unrelated-CA reject",
    },
    "sqlcipher": {
        "program": "sqlcipher", "launch": ["--version"],
        "version_re": r"SQLCipher", "lib_paths": [],
        "note": "SQLCipher: AES-256 page encryption round trip + wrong-key reject",
    },
    "davix": {
        "program": "bin/davix-get", "launch": ["--version"],
        "version_re": r"davix", "lib_paths": [],
        "note": "davix-get: verified HTTPS fetch + unrelated-CA reject",
    },
    "python3-scrypt": {
        "program": ".l7-pyscrypt-harness", "launch": ["--version"],
        "version_re": r"pyscrypt-l7-harness", "lib_paths": [],
        "harness": {
            "source": "forensics/tools/l7_python_runner.c",
            "cflags": ["-I{aux}/usr/include", "-I{aux}/usr/include/python3.11",
                       "-I{aux}/usr/include/x86_64-linux-gnu",
                       "-DL7_SCRIPT_PATH=\"{repo}/forensics/tools/l7_pyscrypt.py\""],
            "ldflags": ["-L{aux}/usr/lib/x86_64-linux-gnu",
                        "-Wl,-rpath,{aux}/usr/lib/x86_64-linux-gnu",
                        "-L{prefix}/lib", "-Wl,-rpath,{prefix}/lib",
                        "-Wl,--no-as-needed",
                        "-L/usr/lib/x86_64-linux-gnu",
                        "-l:libpython3.11.so.1.0", "-lssl", "-lcrypto",
                        "-ldl", "-lm", "-lpthread"],
        },
        "note": "py-scrypt: scrypt KDF vector + different-salt control",
    },
    "python3-m2crypto": {
        "program": ".l7-pym2-harness", "launch": ["--version"],
        "version_re": r"pym2-l7-harness", "lib_paths": [],
        "harness": {
            "source": "forensics/tools/l7_python_runner.c",
            "cflags": ["-I{aux}/usr/include", "-I{aux}/usr/include/python3.11",
                       "-I{aux}/usr/include/x86_64-linux-gnu",
                       "-DL7_SCRIPT_PATH=\"{repo}/forensics/tools/l7_pym2crypto.py\""],
            "ldflags": ["-L{aux}/usr/lib/x86_64-linux-gnu",
                        "-Wl,-rpath,{aux}/usr/lib/x86_64-linux-gnu",
                        "-L{prefix}/lib", "-Wl,-rpath,{prefix}/lib",
                        "-Wl,--no-as-needed",
                        "-L/usr/lib/x86_64-linux-gnu",
                        "-l:libpython3.11.so.1.0", "-lssl", "-lcrypto",
                        "-ldl", "-lm", "-lpthread"],
        },
        "note": "M2Crypto: RSA sign/verify + tampered-signature reject",
    },
    "ewf-tools": {
        "program": "ewftools/.libs/ewfverify", "launch": ["-V"],
        "version_re": r"ewfverify", "lib_paths": ["libewf/.libs"],
        "note": "ewf-tools: MD5/SHA-256 acquisition and re-verification + tampered-image reject",
    },
}
_S46_PROGRAMS["perl-net-dns-sec"] = _s33_perl_program(
    "perl-net-dns-sec", "l7_perl_net_dns_sec.pl", "Net/DNS/SEC", "SEC.so",
    ["dnssec_key=ok", "dnssec_sign=ok", "dnssec_verify=ok", "dnssec_tamper=rejected"],
    "Net::DNS::SEC 1.20: DNSSEC sign/verify + tampered-RRset reject")
PROGRAMS.update(_S46_PROGRAMS)
RUNNERS.update({
    "tcl-tls": _wl_tcltls,
    "sqlcipher": _wl_sqlcipher,
    "davix": _wl_davix,
    "python3-scrypt": _wl_pyscrypt,
    "python3-m2crypto": _wl_pym2crypto,
    "perl-net-dns-sec": _wl_perl,
    "ewf-tools": _wl_ewftools,
})


# S53 corpus batch: consumers whose own executable can be launched deterministically.  The batch
# families without an entry keep their build/link row (`no-fixture`); no workload is fabricated.
_S53_PROGRAMS: dict[str, dict] = {
    "njs": {"program": "build/njs", "launch": ["-v"], "version_re": r"^\d+\.\d+",
            "lib_paths": []},
    "carbon-c-relay": {"program": "relay", "launch": ["-h"],
                       "version_re": r"carbon-c-relay|Usage|usage", "lib_paths": []},
    "dmg2img": {"program": "vfdecrypt", "launch": ["-h"],
                "version_re": r"vfdecrypt|Usage|usage", "lib_paths": []},
    "ike-scan": {"program": "ike-scan", "launch": ["--version"],
                 "version_re": r"ike-scan", "lib_paths": []},
    "gsocket": {"program": "tools/gs-netcat", "launch": ["--version"],
                "version_re": r"gsocket|gs-netcat", "lib_paths": []},
    "megatools": {"program": "megatools", "launch": ["--version"],
                  "version_re": r"megatools|Megatools", "lib_paths": []},
    "lastpass-cli": {"program": "b/lpass", "launch": ["--version"],
                     "version_re": r"lpass|LastPass", "lib_paths": []},
    "ipmiutil": {"program": "util/ipmiutil", "launch": ["-V"],
                 "version_re": r"ipmiutil|IPMIUTIL", "lib_paths": ["util"]},
    "yadifa": {"program": "sbin/yadifad/yadifad", "launch": ["--help"],
               "version_re": r"yadifad|Usage|usage", "lib_paths": ["lib"]},
    "mosh": {"program": "src/frontend/mosh-client", "launch": ["--version"],
             "version_re": r"mosh|Mosh", "lib_paths": []},
    "encfs": {"program": "b/encfs", "launch": ["--version"],
              "version_re": r"encfs|EncFS", "lib_paths": []},
    "casync": {"program": "b/casync", "launch": ["--version"],
               "version_re": r"casync", "lib_paths": []},
    "openfortivpn": {"program": "src/openfortivpn", "launch": ["--version"],
                     "version_re": r"openfortivpn", "lib_paths": []},
    "yapet": {"program": "src/yapet/yapet", "launch": ["--help"],
              "version_re": r"yapet|YAPET|Usage|usage", "lib_paths": []},
    "ftp-ssl": {"program": "ftp/ftp", "launch": ["-?"],
                "version_re": r"ftp|usage|Usage", "lib_paths": []},
    "ftpd-ssl": {"program": "ftpd/ftpd", "launch": ["-h"],
                 "version_re": r"ftpd|usage|Usage", "lib_paths": []},
    "hopm": {"program": "src/hopm", "launch": ["-v"],
             "version_re": r"hopm|HOPM", "lib_paths": []},
    "bip": {"program": "src/bip", "launch": ["-v"],
            "version_re": r"bip|BIP", "lib_paths": []},
    "bruteforce-wallet": {"program": "bruteforce-wallet", "launch": ["-h"],
                          "version_re": r"bruteforce-wallet|Usage|usage", "lib_paths": []},
    "gvpe": {"program": "src/gvpe", "launch": ["--version"],
             "version_re": r"gvpe|GVPE", "lib_paths": []},
    "imapfilter": {"program": "src/imapfilter", "launch": ["-v"],
                   "version_re": r"imapfilter|IMAPFilter", "lib_paths": []},
    "nmh": {"program": "uip/inc", "launch": ["-help"],
            "version_re": r"inc|usage|Usage", "lib_paths": ["sbr/.libs"]},
    "fdm": {"program": "fdm", "launch": ["-V"],
            "version_re": r"fdm|FDM", "lib_paths": []},
}
PROGRAMS.update(_S53_PROGRAMS)


def _wl_njs(ctx: dict) -> dict:
    """njs's crypto module: SHA-256/SHA-1 digests through the subject libcrypto."""
    script = ("var c = require('crypto');"
              "console.log('sha256='+c.createHash('sha256').update('abc').digest('hex'));"
              "console.log('sha1='+c.createHash('sha1').update('abc').digest('hex'));")
    return _wl_markers_argv(ctx, ["-c", script],
                            ["sha256=ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                             "sha1=a9993e364706816aba3e25717850c26c9cd0d89d"],
                            "njs: SHA-256 and SHA-1 vectors through the crypto module")


RUNNERS.update({"njs": _wl_njs})


def _wl_casync(ctx: dict) -> dict:
    """casync make/extract: the content digest is computed and re-verified over the subject."""
    d = ctx["workdir"]
    src = d / "casync-src"
    src.mkdir(parents=True, exist_ok=True)
    payload = b"s53-casync-payload\n" * 512
    (src / "payload.bin").write_bytes(payload)
    idx = d / "casync.caidx"
    out = d / "casync-out"
    mk = _run_captured([str(ctx["program"]), "make", str(idx), str(src)],
                       cwd=d, env=ctx["env"], timeout=120)
    ex = _run_captured([str(ctx["program"]), "extract", str(idx), str(out)],
                       cwd=d, env=ctx["env"], timeout=120)
    got = out / "payload.bin"
    roundtrip = bool(got.is_file() and got.read_bytes() == payload)
    ok = bool(mk["ok"] and ex["ok"] and roundtrip)
    return {
        "runtime_ok": ok, "functional_ok": ok,
        "failure_class": None if ok else "functional-failure",
        "residual": "none" if ok else "functional-divergence",
        "reason": None if ok else "casync did not round-trip the payload",
        "transcript": _transcript(("casync make", mk), ("casync extract", ex)),
        "workload": "casync: content digest make/extract round trip",
        "local_only": True,
    }


RUNNERS.update({"casync": _wl_casync})


# --------------------------------------------------------------------------------------------
# S60 corpus batch: recipe-backed families that reached L5 but had no admitted workload.
# Each workload is a deterministic local exercise of the family's own OpenSSL consumer path
# and is identical for both subjects.
# --------------------------------------------------------------------------------------------

def _wl_fdm(ctx: dict) -> dict:
    """fdm fetches a message from a local IMAPS peer over a verified session.

    The peer is the courtroom's own IMAP4rev1 fixture over TLS with the authority-generated
    certificate.  fdm verifies the chain through the OpenSSL default verify paths, so the
    fixture CA is supplied as SSL_CERT_FILE; a fetch trusting only the unrelated CA must
    abort without delivering a message.
    """
    ap, port, d = ctx["authority_prefix"], ctx["port"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    # fdm drops to its compiled-in unprivileged account (`_fdm`, fdm.h) even when the
    # delivery user is overridden; the venue does not ship that account.  Creating the
    # same system account for both subjects is fixture setup, not a source or policy change.
    if subprocess.run(["id", "-u", "_fdm"], capture_output=True).returncode != 0:
        _run_captured(["useradd", "-r", "-s", "/usr/sbin/nologin", "_fdm"], timeout=30)
    maildir = d / "maildir"
    for sub in ("cur", "new", "tmp"):
        (maildir / sub).mkdir(parents=True, exist_ok=True)
    conf = d / "fdm.conf"
    conf.write_text(
        f'set verify-certificates\nset timeout 30\nset lock-file "{d}/fdm.lock"\n'
        f'action "inbox" maildir "{maildir}"\n'
        f'account "phase" imaps server "127.0.0.1" port {port} '
        f'user "runtime" pass "runtime"\n'
        'match all action "inbox"\n', encoding="utf-8")
    ready, stop = threading.Event(), threading.Event()
    imap_log: list[str] = []
    thr = threading.Thread(target=_imaps_server,
                           args=(pki["srv_pem"], port, ready, stop, False, imap_log),
                           daemon=True)
    thr.start()
    ready.wait(timeout=10)
    try:
        if not _wait_tcp("127.0.0.1", port, timeout=10):
            return _wl_fail([], "the local IMAP peer did not listen", "runtime-failure", d)
        env = dict(ctx["env"], HOME=str(d), TMPDIR=str(d))
        # fdm drops to its unprivileged account before delivering, so the fixture tree must
        # be writable by that account (a fixture permission, not a subject difference).
        os.system(f"chmod -R a+rwX {d} 2>/dev/null")
        good = _run_captured([str(ctx["program"]), "-u", "nobody", "-v", "-f", str(conf),
                              "fetch"],
                             cwd=d, env=dict(env, SSL_CERT_FILE=str(pki["ca_crt"])), timeout=60)
        neg = _run_captured([str(ctx["program"]), "-u", "nobody", "-f", str(conf), "fetch"],
                            cwd=d, env=dict(env, SSL_CERT_FILE=str(pki["other_crt"])), timeout=60)
    finally:
        stop.set()
        thr.join(timeout=5)
        _kill_comm("fdm")
    msgs = [p for p in maildir.rglob("*") if p.is_file() and p.parent.name in ("new", "cur")]
    delivered = any(_IMAP_MESSAGE.split(b"\r\n\r\n", 1)[1].strip() in p.read_bytes()
                    for p in msgs)
    runtime_ok = good["exit_code"] == 0 and bool(msgs)
    # fdm exits 0 even when the fetch aborts, so the negative control is the absence of a
    # delivered message plus the certificate-verification failure in its own log.
    neg_text = neg["stdout"] + neg["stderr"]
    neg_rejected = (not [p for p in maildir.rglob("*")
                         if p.is_file() and p.parent.name in ("new", "cur")]
                    and "certificate verification failed" in neg_text)
    # The positive fetch has already delivered; remove it so the negative is measured alone.
    if runtime_ok:
        for p in msgs:
            p.unlink()
        neg = _run_captured([str(ctx["program"]), "-u", "nobody", "-f", str(conf), "fetch"],
                            cwd=d, env=dict(env, SSL_CERT_FILE=str(pki["other_crt"])), timeout=60)
        neg_text = neg["stdout"] + neg["stderr"]
        neg_rejected = (not [p for p in maildir.rglob("*")
                             if p.is_file() and p.parent.name in ("new", "cur")]
                        and "certificate verification failed" in neg_text)
    functional_ok = bool(runtime_ok and delivered and neg_rejected)
    return {"runtime_ok": runtime_ok, "functional_ok": functional_ok,
            "failure_class": None if functional_ok else
            ("functional-failure" if runtime_ok else "runtime-failure"),
            "residual": "none" if functional_ok else
            ("functional-divergence" if runtime_ok else "runtime-failure"),
            "reason": None if functional_ok else
            ("the IMAPS fetch did not deliver the fixture message" if not delivered else
             "the unrelated CA did not abort the IMAPS fetch"),
            "transcript": _transcript(("fdm fetch (fixture CA)", good),
                                      ("fdm fetch (unrelated CA, must fail)", neg),
                                      ("IMAP peer commands", {"exit_code": 0,
                                                              "stdout": "\n".join(imap_log[-40:])})),
            "workload": "fdm: IMAPS fetch from a local peer + unrelated-CA abort",
            "local_only": True}


def _wl_imapfilter(ctx: dict) -> dict:
    """imapfilter checks a mailbox's status over a verified IMAPS session."""
    ap, port, d = ctx["authority_prefix"], ctx["port"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    # imapfilter loads its Lua support modules from the compiled-in sharedir; the recipe
    # configures PREFIX under the extracted root but does not install, so stage them.
    share = ctx["root"] / ".l7-install" / "share" / "imapfilter"
    share.mkdir(parents=True, exist_ok=True)
    for lua in (ctx["root"] / "src").glob("*.lua"):
        shutil.copy2(lua, share / lua.name)
    conf = d / "imapfilter.lua"
    conf.write_text(
        "options.timeout = 20\n"
        f"account = IMAP {{ server = '127.0.0.1', port = {port}, username = 'runtime', "
        "password = 'runtime', ssl = 'auto' }\n"
        "exist, unread, unseen, uidnext = account.INBOX:check_status()\n"
        "print('exist=' .. tostring(exist) .. ' uidnext=' .. tostring(uidnext))\n",
        encoding="utf-8")
    ready, stop = threading.Event(), threading.Event()
    thr = threading.Thread(target=_imaps_server, args=(pki["srv_pem"], port, ready, stop),
                           daemon=True)
    thr.start()
    ready.wait(timeout=10)
    try:
        if not _wait_tcp("127.0.0.1", port, timeout=10):
            return _wl_fail([], "the local IMAP peer did not listen", "runtime-failure", d)
        env = dict(ctx["env"], HOME=str(d), TMPDIR=str(d))
        good = _run_captured([str(ctx["program"]), "-c", str(conf), "-t", str(pki["ca_crt"])],
                             cwd=d, env=env, timeout=60)
        neg = _run_captured([str(ctx["program"]), "-c", str(conf), "-t",
                             str(pki["other_crt"])], cwd=d, env=env, timeout=60)
    finally:
        stop.set()
        thr.join(timeout=5)
    text = good["stdout"] + good["stderr"]
    status_ok = good["exit_code"] == 0 and re.search(r"exist=1\b", text) is not None
    neg_rejected = neg["exit_code"] != 0 and "exist=" not in (neg["stdout"] + neg["stderr"])
    functional_ok = bool(status_ok and neg_rejected)
    return {"runtime_ok": good["exit_code"] == 0, "functional_ok": functional_ok,
            "failure_class": None if functional_ok else
            ("functional-failure" if good["exit_code"] == 0 else "runtime-failure"),
            "residual": "none" if functional_ok else
            ("functional-divergence" if good["exit_code"] == 0 else "runtime-failure"),
            "reason": None if functional_ok else
            ("imapfilter did not report the fixture mailbox status" if not status_ok else
             "the unrelated CA did not abort the IMAPS check"),
            "transcript": _transcript(("imapfilter status (fixture CA)", good),
                                      ("imapfilter status (unrelated CA, must fail)", neg)),
            "workload": "imapfilter: IMAPS STATUS of the fixture mailbox + unrelated-CA abort",
            "local_only": True}


def _wl_nmh(ctx: dict) -> dict:
    """nmh's send submits a draft over SMTP STARTTLS to a local stub."""
    ap, port, d = ctx["authority_prefix"], ctx["port"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    body = "phase60-nmh-body"
    state: dict = {}
    stop = threading.Event()
    thread = _smtp_starttls_stub(port, pki, state, stop)
    draft = d / "draft.txt"
    draft.write_text(
        "From: phase60@example.invalid\nTo: phase60@example.invalid\n"
        "Subject: phase60-nmh\n\n"
        f"{body}\n", encoding="utf-8")
    home = d / "home"
    home.mkdir(parents=True, exist_ok=True)
    # nmh's send reads its compiled-in mts.conf; the recipe builds but does not install, so
    # stage the file the same way the build layout expects it.
    etc = ctx["root"] / ".l7-install" / "etc" / "nmh"
    etc.mkdir(parents=True, exist_ok=True)
    (etc / "mts.conf").write_text("mts: smtp\nhostname: phase60.invalid\n",
                                  encoding="utf-8")
    bindir = ctx["root"] / ".l7-install" / "bin"
    bindir.mkdir(parents=True, exist_ok=True)
    libexec = ctx["root"] / ".l7-install" / "libexec" / "nmh"
    libexec.mkdir(parents=True, exist_ok=True)
    for helper in ("mhbuild", "post"):
        real = ctx["root"] / "uip" / helper
        for link in (bindir / helper, libexec / helper):
            if real.is_file() and not link.exists():
                link.symlink_to(real)
    init = _run_captured([str(ctx["root"] / "uip" / "install-mh"), "-auto"], cwd=d,
                         env=dict(ctx["env"], HOME=str(home)), timeout=30,
                         stdin_text="n\n")
    for sub in ("Mail", "Mail/drafts", "Mail/inbox"):
        (home / sub).mkdir(parents=True, exist_ok=True)

    def submit(ca: Path) -> dict:
        return _run_captured([str(ctx["root"] / "uip" / "send"), "-server", "127.0.0.1",
                              "-port", str(port), "-tls", "-certverify", "-mts", "smtp",
                              "-nodraftfolder", str(draft)],
                             cwd=d, env=dict(ctx["env"], HOME=str(home),
                                             SSL_CERT_FILE=str(ca)), timeout=60)

    try:
        if not _wait_tcp("127.0.0.1", port):
            return _wl_fail([("install-mh", init)],
                            "the SMTP STARTTLS stub did not open its port",
                            "runtime-failure", d)
        good = submit(pki["ca_crt"])
        accepted = state.get("message") or b""
        state.pop("message", None)
        # send removes the draft after a successful delivery; restore it for the negative.
        draft.write_text(
            "From: phase60@example.invalid\nTo: phase60@example.invalid\n"
            "Subject: phase60-nmh\n\n"
            f"{body}\n", encoding="utf-8")
        neg = submit(pki["other_crt"])
        rejected_after_neg = state.get("message") is None
    finally:
        stop.set()
        state.get("listener", socket.socket()).close()
        thread.join(timeout=2)
    delivered = body.encode() in accepted
    neg_rejected = (neg["exit_code"] != 0 and rejected_after_neg
                    and "certificate" in (neg["stdout"] + neg["stderr"]).lower())
    functional_ok = bool(good["exit_code"] == 0 and delivered and neg_rejected)
    return {"runtime_ok": good["exit_code"] == 0, "functional_ok": functional_ok,
            "failure_class": None if functional_ok else
            ("functional-failure" if good["exit_code"] == 0 else "runtime-failure"),
            "residual": "none" if functional_ok else
            ("functional-divergence" if good["exit_code"] == 0 else "runtime-failure"),
            "reason": None if functional_ok else
            ("the draft was not accepted over STARTTLS" if not delivered else
             "the unrelated CA was not rejected"),
            "transcript": _transcript(("install-mh", init),
                                      ("nmh send over STARTTLS (fixture CA)", good),
                                      ("nmh send (unrelated CA, must fail)", neg)),
            "workload": "nmh: send over SMTP STARTTLS + unrelated-CA reject",
            "local_only": True}


def _wl_carbon_c_relay(ctx: dict) -> dict:
    """carbon-c-relay forwards a metric to a TLS sink it verifies with the fixture CA."""
    ap, d = ctx["authority_prefix"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    sink_port = _free_port()
    received: dict = {}
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", sink_port))
    listener.listen(4)
    listener.settimeout(20)
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.load_cert_chain(str(pki["srv_pem"]))

    def serve() -> None:
        try:
            conn, _ = listener.accept()
            with conn, sctx.wrap_socket(conn, server_side=True) as tls:
                tls.settimeout(15)
                data = b""
                while b"phase60.metric" not in data:
                    chunk = tls.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                received["data"] = data
        except OSError as exc:
            received["error"] = repr(exc)
        finally:
            listener.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    conf = d / "relay.conf"
    conf.write_text(
        f'cluster "sink" forward 127.0.0.1:{sink_port} proto tcp transport plain ssl;\n'
        'match * send to sink;\n', encoding="utf-8")
    env = dict(ctx["env"], TMPDIR=str(d))

    def forward(ca: Path, tag: str) -> tuple[dict, str]:
        received.pop("data", None)
        received.pop("error", None)
        listen_port = _free_port()
        proc = subprocess.Popen([str(ctx["program"]), "-f", str(conf), "-p",
                                 str(listen_port), "-C", str(ca), "-s", "-w", "1"],
                                cwd=str(d), env=env, start_new_session=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            if not _wait_tcp("127.0.0.1", listen_port, timeout=15):
                return {"exit_code": 1, "stdout": "", "stderr": "relay did not listen"}, ""
            sent = _run_captured([
                sys.executable, "-c",
                "import socket; s=socket.create_connection(('127.0.0.1', "
                f"{listen_port}), timeout=5); "
                "s.sendall(b'phase60.metric 1 1700000000\\n'); s.close()"],
                cwd=d, env=env, timeout=15)
            deadline = time.monotonic() + 12
            while time.monotonic() < deadline and "data" not in received:
                time.sleep(0.1)
            return sent, (received.get("data") or b"").decode("utf-8", "replace")
        finally:
            out, err = _stop_workload_group(proc)
            received.setdefault("relay", (out or "") + (err or ""))

    good, good_data = forward(pki["ca_crt"], "good")
    bad, bad_data = forward(pki["other_crt"], "bad")
    delivered = "phase60.metric" in good_data
    neg_rejected = "phase60.metric" not in bad_data
    functional_ok = bool(good["exit_code"] == 0 and delivered and neg_rejected)
    return {"runtime_ok": good["exit_code"] == 0, "functional_ok": functional_ok,
            "failure_class": None if functional_ok else
            ("functional-failure" if good["exit_code"] == 0 else "runtime-failure"),
            "residual": "none" if functional_ok else
            ("functional-divergence" if good["exit_code"] == 0 else "runtime-failure"),
            "reason": None if functional_ok else
            ("the metric was not forwarded over verified TLS" if not delivered else
             "the unrelated CA did not stop the TLS forward"),
            "transcript": _transcript(("relay -> TLS sink (fixture CA)", good),
                                      ("sink transcript", {"exit_code": 0,
                                                           "stdout": good_data[:400]}),
                                      ("relay -> TLS sink (unrelated CA, must fail)", bad),
                                      ("sink transcript (negative)", {"exit_code": 0,
                                                                      "stdout": bad_data[:200]})),
            "workload": "carbon-c-relay: metric forwarded to a verified TLS sink + unrelated-CA reject",
            "local_only": True}


RUNNERS.update({
    "fdm": _wl_fdm,
    "imapfilter": _wl_imapfilter,
    "nmh": _wl_nmh,
    "carbon-c-relay": _wl_carbon_c_relay,
})


# S60 corpus batch: the program each new recipe builds. A family whose recipe reached L4 but
# whose program is not admitted here keeps its build/link row honestly.
_S60_PROGRAMS: dict[str, dict] = {
    "jabberd2": {"program": "jabberd/jabberd", "launch": ["-V"],
                 "version_re": r"jabberd", "lib_paths": []},
    "atheme-services": {"program": "src/services/.libs/services", "launch": ["--version"],
                        "version_re": r"atheme|services", "lib_paths": ["src/services/.libs"]},
    "epic4": {"program": "src/epic", "launch": ["-v"], "version_re": r"EPIC|epic",
              "lib_paths": []},
    "weex": {"program": "src/weex", "launch": ["--version"], "version_re": r"weex|WeeX",
             "lib_paths": []},
    "ipmitool": {"program": "src/ipmitool", "launch": ["-V"],
                 "version_re": r"ipmitool|IPMI", "lib_paths": []},
    "partimage": {"program": "src/partimage", "launch": ["--version"],
                  "version_re": r"partimage|Partimage", "lib_paths": []},
    "ophcrack": {"program": "src/ophcrack", "launch": ["--version"],
                 "version_re": r"ophcrack|Ophcrack", "lib_paths": []},
    "kannel": {"program": "gw/bearerbox", "launch": ["--version"],
               "version_re": r"bearerbox|Kannel", "lib_paths": ["gw"]},
    "xrdp": {"program": "xrdp/xrdp", "launch": ["--version"], "version_re": r"xrdp",
             "lib_paths": ["common/.libs"]},
    "bind9": {"program": "bin/named/named", "launch": ["-v"], "version_re": r"BIND 9",
              "lib_paths": ["lib/isc/.libs", "lib/dns/.libs", "lib/isccfg/.libs",
                            "lib/isccc/.libs", "lib/bind9/.libs"]},
    "dnsperf": {"program": "src/dnsperf", "launch": ["-h"],
                "version_re": r"dnsperf|DNS Performance", "lib_paths": []},
    "i2pd": {"program": "i2pd", "launch": ["--version"], "version_re": r"i2pd",
             "lib_paths": []},
    "trousers": {"program": "src/tcsd/tcsd", "launch": ["--version"],
                 "version_re": r"tcsd|TrouSerS", "lib_paths": ["src/tspi/.libs"]},
    "tpm2-tools": {"program": "tools/tpm2_getrandom", "launch": ["--version"],
                   "version_re": r"tpm2_getrandom", "lib_paths": ["tools/.libs"]},
    "galera-3": {"program": "garb/garbd", "launch": ["--version"],
                 "version_re": r"garbd|Galera", "lib_paths": ["garb"]},
    "galera-4": {"program": "garb/garbd", "launch": ["--version"],
                 "version_re": r"garbd|Galera", "lib_paths": ["garb"]},
    "vboot-utils": {"program": "build/futility/futility", "launch": ["--version"],
                    "version_re": r"futility|vboot", "lib_paths": []},
    "rspamd": {"program": "src/rspamd", "launch": ["--version"], "version_re": r"rspamd",
               "lib_paths": ["src"]},
}
PROGRAMS.update(_S60_PROGRAMS)


# S60 package rows: the same pristine source, program and workload as the admitted parent.
for _new, _base in (("afftools", "libafflib0v5"), ("ewftools", "ewf-tools"),
                    ("libdcmtk17", "dcmtk"), ("apache2-http2", "apache2-bin")):
    if _base in PROGRAMS:
        PROGRAMS[_new] = dict(PROGRAMS[_base])
    if _base in RUNNERS:
        RUNNERS[_new] = RUNNERS[_base]


# the load proof (L5): the subject's libssl/libcrypto are actually loaded
# --------------------------------------------------------------------------------------------

def load_proof(program: Path, prefix: Path, authority_prefix: Path, launch: list[str],
               env: dict, launch_prefix: list[str] | None = None) -> dict:
    """Prove the launched program loads the subject's libssl/libcrypto, not the authority's.

    Two readings: the program's own `ldd` resolution of every OpenSSL soname (under the subject
    prefix, and -- for a candidate row -- never the authority's), and the dynamic loader's recorded
    `LD_DEBUG=libs` initialisation of the subject library. The conclusive proof is the resolution
    (the loader picking the subject's file); a version banner alone would prove neither.
    """
    run_env = dict(env)
    is_authority = os.path.realpath(str(prefix)) == os.path.realpath(str(authority_prefix))
    ldd = _run_captured(["ldd", str(program)], env=run_env, timeout=60)
    sonames: dict[str, dict] = {}
    any_lib = False
    all_under = True
    under_authority = False
    for line in (ldd["stdout"] or "").splitlines():
        left = line.split("=>")[0].strip()
        if not (left == "libssl.so" or left.startswith("libssl.so.") or
                left == "libcrypto.so" or left.startswith("libcrypto.so.")):
            continue
        resolved = line.split("=>", 1)[1].strip().split(" (")[0].strip() if "=>" in line else ""
        under = bool(resolved) and census._under(resolved, prefix)
        under_auth = bool(resolved) and census._under(resolved, authority_prefix)
        sonames[left] = {
            "resolved": f"prefix:{left}" if under else (resolved or "unresolved"),
            "under_prefix": under, "under_authority": under_auth,
        }
        any_lib = True
        all_under = all_under and under
        under_authority = under_authority or under_auth

    trace = _run_captured([*(launch_prefix or []), str(program)] + list(launch),
                          env=dict(run_env, LD_DEBUG="libs"), timeout=LAUNCH_TIMEOUT)
    trace_lines = [ln.strip() for ln in ((trace["stderr"] or "") + "\n" +
                                         (trace["stdout"] or "")).splitlines()
                   if ("libssl" in ln or "libcrypto" in ln) and str(prefix) in ln]
    proven = any_lib and all_under and (is_authority or not under_authority)
    return {
        "proven": proven,
        "all_under_prefix": all_under,
        "resolved_under_authority": under_authority,
        "sonames": sonames,
        "dynamic_load_trace": trace_lines[:8],
        "ldd_exit": ldd["exit_code"],
        "trace_exit": trace["exit_code"],
    }


# --------------------------------------------------------------------------------------------
# measurement: every P1000 family, both subjects
# --------------------------------------------------------------------------------------------

def _runtime_row(fam: dict, recipe: dict | None, subject: str, *, level: str, outcome: str,
                 residual: str, failure_class: str | None, reason: str | None,
                 specimen_id: str | None, variant_id: str | None, source_sha256: str | None,
                 evidence: list[str], canvas: dict | None, limits: dict, prefix: Path,
                 source_root_hash: str | None, launch: list[str] | None, workload: str | None,
                 transcript: str, local_only: bool, extra: dict | None = None) -> dict:
    """One runtime run row: reuse 24.6's `run` construction and extend it with the runtime proof."""
    row = bl._subject_row(
        fam, recipe, subject, level=level, outcome=outcome, residual=residual,
        failure_class=failure_class, reason=reason, specimen_id=specimen_id, variant_id=variant_id,
        source_sha256=source_sha256, evidence=evidence, steps=None, canvas=canvas, limits=limits,
        prefix=prefix, source_root_hash=source_root_hash)
    row["run_id"] = f"run:runtime:{subject}:{fam.get('canonical_name')}"
    row["load_proof"] = (canvas or {}).get("load_proof")
    row["link"] = (canvas or {}).get("link")
    row["linkage_proven"] = bool((canvas or {}).get("linkage_proven"))
    row["resolved_under_authority"] = bool((canvas or {}).get("resolved_under_authority"))
    # Persist the template admission verdict with the row it gated: the L7 level is only
    # meaningful alongside the loader-closure evidence that admitted it.
    if (canvas or {}).get("template_admission") is not None:
        row["template_admission"] = (canvas or {})["template_admission"]
    row["launch"] = list(launch) if launch else None
    row["workload"] = workload
    row["local_only"] = bool(local_only)
    row["transcript_sha256"] = sha256_bytes(transcript.encode("utf-8")) if transcript else ""
    lines = transcript.splitlines()
    row["transcript_excerpt"] = lines[-40:]
    row["normalisation"] = {
        "tag": NORMALISATION_TAG, "normalises": list(NORMALISATION_ALLOWED),
        "never": list(NORMALISATION_NEVER),
    }
    # The registry's contribution to the launch root, recorded in the same
    # {capability, bundle_id, sha256} shape the build/link row uses. This is evidence for the
    # V5b repair: the runtime harness now resolves exactly the bundles the build extracted, so
    # a capability-migrated recipe's pinned runtime libraries are on LD_LIBRARY_PATH.
    if recipe and recipe.get("capabilities"):
        row["aux_bundles"] = [
            {"capability": b["capability"], "bundle_id": b["bundle_id"],
             "sha256": b["sha256"]}
            for b in bl.deps.resolve_recipe(recipe["capabilities"])
        ]
    if extra:
        row.update(extra)
    return row


def _build_harness(prog: dict, root: Path, prefix: Path, out: Path,
                   build_env: dict, aux: Path | None = None) -> dict:
    """Compile a library-only family's admitted workload harness against the rebuilt library.

    The harness is a test-only consumer of the family library (which was itself built against the
    subject prefix by the shared recipe), so the program the load proof resolves links both the
    rebuilt family library and the subject's libssl/libcrypto. `{aux}`, `{root}` and `{repo}` are
    substituted alongside `{prefix}` for harnesses whose dependency lives in the pinned packages.
    """
    spec = prog["harness"]
    source = REPO_ROOT / str(spec["source"])
    aux = aux or (root.parents[1] / "aux" / "root")
    # A C++ consumer library (Poco) needs a C++ driver; every existing harness is C.
    compiler = str(spec.get("compiler") or "cc")
    argv = [compiler, str(source), "-o", str(out), "-O2", "-Wall", "-Wextra"]
    body = {"root": root, "prefix": prefix, "aux": aux, "repo": REPO_ROOT}
    argv += [str(a).format(**body) for a in spec.get("cflags") or []]
    argv += [str(a).format(**body) for a in spec.get("ldflags") or []]
    return census._run(argv, cwd=root, env=build_env)


def _specimen_variant(recipe: dict, name: str) -> tuple[str, str]:
    return f"specimen:{name}:{recipe['version']}", f"variant:{name}:{recipe['version']}:pristine"


def _aux_runtime_specs(recipe: dict) -> list[dict]:
    """The auxiliary package specs a recipe's build materialised in `<work>/aux/root`.

    `bl._prepare_aux` accepts two expressions for the same thing: capability bundles
    (resolved from the S64 registry) and the legacy per-family `aux_sources` pins. Both are
    extracted into the one aux root and both expose `library_dirs`/`bin_dirs`. Reading only
    `aux_sources` here made every capability-migrated recipe's runtime launch miss its pinned
    libraries: V5b measured `libevent-2.1.so.7` and `libltdl.so.7` unresolved for memcached,
    nsd and charybdis under both subjects, dropping L7 to L4. The order matches
    `_prepare_aux` (capabilities first) so the launch root is deterministic.
    """
    specs = list(recipe.get("aux_sources") or [])
    requests = recipe.get("capabilities") or []
    if requests:
        specs = bl.deps.merge_specs(bl.deps.resolve_recipe(requests)) + specs
    return specs


def _aux_runtime_lib_dirs(recipe: dict, root: Path) -> list[str]:
    """The extracted auxiliary libraries the program needs at load time, in order, deduplicated.

    `bl._prepare_aux` extracts each pinned dependency under `<family work>/aux/root`; the source
    root is `<family work>/<subject>/src/<archive>`, so the auxiliary root is two directories above
    it. Only directories that exist are added, so a recipe with non-library auxiliary sources is
    unaffected. Capability bundles contribute exactly as legacy pins do (V5b).
    """
    specs = _aux_runtime_specs(recipe)
    if not specs:
        return []
    aux_root = root.parents[1] / "aux" / "root"
    dirs: list[str] = []
    for spec in specs:
        for entry in spec.get("library_dirs") or []:
            candidate = aux_root / entry
            if candidate.is_dir() and str(candidate) not in dirs:
                dirs.append(str(candidate))
    return dirs


def _aux_runtime_bin_dirs(recipe: dict, root: Path) -> list[str]:
    """The extracted auxiliary programs a workload invokes (u-boot-tools' mkimage runs dtc)."""
    specs = _aux_runtime_specs(recipe)
    if not specs:
        return []
    aux_root = root.parents[1] / "aux" / "root"
    dirs: list[str] = []
    for spec in specs:
        for entry in spec.get("bin_dirs") or []:
            candidate = aux_root / entry
            if candidate.is_dir() and str(candidate) not in dirs:
                dirs.append(str(candidate))
    return dirs


def _measure_subject_runtime(fam: dict, recipe: dict, subject: str, prefix: Path,
                             authority_prefix: Path, root: Path, source_sha256: str | None,
                             source_root_hash: str | None, limits: dict) -> dict:
    """Load and drive one subject's built program; return its runtime run row."""
    name = str(fam.get("canonical_name"))
    spec_id, variant_id = _specimen_variant(recipe, name)
    prog = PROGRAMS[name]
    program = root / prog["program"]
    workdir = SCRATCH / "run" / name / subject
    if workdir.exists():
        shutil.rmtree(workdir, ignore_errors=True)
    workdir.mkdir(parents=True, exist_ok=True)
    lib_paths = [str(prefix / "lib")] + [str(root / p) for p in prog.get("lib_paths", [])]
    # A libtool-built consumer (Kea) leaves its shared objects in `src/lib/*/.libs`; a recipe names
    # that pattern and the glob is expanded here to the directories that actually exist.
    expanded: list[str] = []
    for entry in lib_paths:
        if glob.has_magic(entry):
            expanded.extend(sorted(glob.glob(entry)))
        else:
            expanded.append(entry)
    lib_paths = expanded
    lib_paths += _aux_runtime_lib_dirs(recipe, root)
    env = dict(os.environ, LD_LIBRARY_PATH=os.pathsep.join(lib_paths))
    # The candidate distribution shell is not installed at a configure-time prefix, so
    # its compiled-in MODULESDIR is empty (the recorded Phase 16 divergence): without an
    # explicit path `OSSL_PROVIDER_load(NULL, "legacy")` cannot find
    # `<prefix>/lib/ossl-modules/legacy.so` and a provider-loading consumer (medusa) fails
    # at startup.  The authority side already finds its own module through its compiled-in
    # MODULESDIR; naming each subject's own directory is the same prefix substitution as
    # `LD_LIBRARY_PATH`, and is the mechanism every provider court's `side_env` uses.
    env["OPENSSL_MODULES"] = str(prefix / "lib" / "ossl-modules")
    # A template program may need a runtime environment variable (siege's SIEGERC is the released
    # configuration file).  The values are expanded from the same root/prefix tokens the recipe
    # uses, so they are not candidate-specific.
    for key, val in (prog.get("env") or {}).items():
        env[str(key)] = (str(val).replace("{root}", str(root))
                         .replace("{prefix}", str(prefix)))
    aux_bins = _aux_runtime_bin_dirs(recipe, root)
    if aux_bins:
        env["PATH"] = os.pathsep.join([*aux_bins, env.get("PATH", "")])
    evidence = [f"family:{fam.get('family_id')}", f"recipe:{recipe['recipe_id']}",
                f"artifact:{prog['program']}", "local_only:loopback"]
    aux_root = root.parents[1] / "aux" / "root"
    aux_specs = _aux_runtime_specs(recipe)
    build_env = dict(os.environ, PKG_CONFIG_PATH=f"{prefix}/lib/pkgconfig",
                     CPPFLAGS=f"-I{prefix}/include", LDFLAGS=f"-L{prefix}/lib")
    aux_include = [str(aux_root / d) for spec in aux_specs
                   for d in spec.get("include_dirs") or []]
    aux_lib = [str(aux_root / d) for spec in aux_specs
               for d in spec.get("library_dirs") or []]
    aux_pc = [str(aux_root / d) for spec in aux_specs
              for d in spec.get("pkgconfig_dirs") or []]
    if aux_include:
        build_env["CPPFLAGS"] += "".join(f" -I{d}" for d in aux_include)
    if aux_lib:
        build_env["LDFLAGS"] += "".join(f" -L{d}" for d in aux_lib)
        build_env["LD_LIBRARY_PATH"] = os.pathsep.join(
            [*aux_lib, *lib_paths, build_env.get("LD_LIBRARY_PATH", "")]).rstrip(os.pathsep)
    if aux_pc:
        build_env["PKG_CONFIG_PATH"] = os.pathsep.join([*aux_pc, build_env["PKG_CONFIG_PATH"]])
    if aux_bins:
        build_env["PATH"] = os.pathsep.join([*aux_bins, build_env.get("PATH", "")])

    # A few admitted programs live behind an upstream target the shared recipe's `make` does not
    # build (ldns's tools are `make examples`). The workload's own target is built here with the
    # identical prefix environment, so the program loaded is the program built against the subject.
    targets = list(prog.get("make_targets") or [])
    if targets:
        target_env = dict(build_env)
        for key, value in (prog.get("make_env") or {}).items():
            target_env[str(key)] = str(value).format(prefix=prefix)
        prep = census._run(["make", *(prog.get("make_jobs") or [MAKE_JOBS]), *targets], cwd=root,
                           env=target_env)
        if not prep["ok"]:
            return _runtime_row(
                fam, recipe, subject, level=L4, outcome="failed", residual="runtime-failure",
                failure_class="load-failure",
                reason=(f"the workload target {targets} did not build: "
                        f"{census._error_line(prep)}"),
                specimen_id=spec_id, variant_id=variant_id, source_sha256=source_sha256,
                evidence=evidence + [f"build:{','.join(targets)}"], canvas=None, limits=limits,
                prefix=prefix, source_root_hash=source_root_hash, launch=None, workload=None,
                transcript=_transcript(("make " + " ".join(targets), prep)), local_only=True)

    # Some trees need more than one make invocation to produce the workload program (mosquitto's
    # recipe builds lib/ only, while the broker and clients are separate sub-makes). Each step is
    # run with the same prefix environment and must succeed before the load proof is attempted.
    for step in prog.get("make_steps") or []:
        # A step may name the build tree or the subject prefix (dovecot's workload installs into
        # its own `DESTDIR`); substitute them exactly as the harness flags are substituted.
        step = [str(a).format(root=root, prefix=prefix, aux=aux_root, repo=REPO_ROOT)
                for a in step]
        prep = census._run(["make", *(prog.get("make_jobs") or [MAKE_JOBS]), *step], cwd=root,
                           env=build_env)
        if not prep["ok"]:
            return _runtime_row(
                fam, recipe, subject, level=L4, outcome="failed", residual="runtime-failure",
                failure_class="load-failure",
                reason=(f"the workload build step {step} did not build: "
                        f"{census._error_line(prep)}"),
                specimen_id=spec_id, variant_id=variant_id, source_sha256=source_sha256,
                evidence=evidence + ["build:" + ",".join(step)], canvas=None, limits=limits,
                prefix=prefix, source_root_hash=source_root_hash, launch=None, workload=None,
                transcript=_transcript(("make " + " ".join(step), prep)), local_only=True)

    # A library-only family has no program of its own: compile the admitted workload harness
    # against the library rebuilt in this source tree and the subject prefix. The harness is the
    # program the load proof then resolves, so the L5 evidence is the library's own load, not a
    # fabricated banner.
    if prog.get("harness"):
        built = _build_harness(prog, root, prefix, program, build_env, aux_root)
        if not built["ok"]:
            return _runtime_row(
                fam, recipe, subject, level=L4, outcome="failed", residual="runtime-failure",
                failure_class="load-failure",
                reason=(f"the L7 workload harness did not compile: {census._error_line(built)}"),
                specimen_id=spec_id, variant_id=variant_id, source_sha256=source_sha256,
                evidence=evidence + ["build:l7-harness"], canvas=None, limits=limits,
                prefix=prefix, source_root_hash=source_root_hash, launch=None, workload=None,
                transcript=_transcript(("cc " + prog["harness"]["source"], built)),
                local_only=True)

    if not program.is_file():
        return _runtime_row(
            fam, recipe, subject, level=L4, outcome="failed", residual="runtime-failure",
            failure_class="load-failure",
            reason=f"the rebuilt pristine tree holds no program at {prog['program']}",
            specimen_id=spec_id, variant_id=variant_id, source_sha256=source_sha256,
            evidence=evidence, canvas=None, limits=limits, prefix=prefix,
            source_root_hash=source_root_hash, launch=None, workload=None, transcript="",
            local_only=True)

    # Some launch probes need a deterministic venue-side precondition that is not part of the
    # program's own build (dma's `-q` queue run reads the default spool directory before it ever
    # reaches an OpenSSL call).  `pre_launch` is the narrow analogue of `make_steps`: the steps are
    # run with the same prefix/root substitutions, and a step that fails is not fatal here because
    # the launch proof that follows records the actual outcome.
    for step in prog.get("pre_launch") or []:
        prepared = [str(a).format(root=root, prefix=prefix, aux=aux_root, repo=REPO_ROOT)
                    for a in step]
        census._run(prepared, cwd=root, env=env)

    launch = _run_captured([*(prog.get("launch_prefix") or []), str(program)]
                           + list(prog["launch"]), cwd=program.parent, env=env,
                           timeout=LAUNCH_TIMEOUT)
    version_ok = (re.search(prog["version_re"], launch["stdout"] + launch["stderr"],
                            re.IGNORECASE) is not None
                  and "error while loading shared libraries" not in launch["stderr"])
    proof = load_proof(program, prefix, authority_prefix, prog["launch"], env,
                       launch_prefix=prog.get("launch_prefix"))
    # The generic admission gate: a template family must load the subject's libssl/libcrypto.  A
    # build that linked a different OpenSSL, or a program whose loader closure never names one, is
    # refused here and cannot reach L6/L7 on the strength of a version banner.
    template_admission = None
    if prog.get("template"):
        template_admission = templates.admit_binary(program, prefix, authority_prefix, env)

    base_canvas = {"load_proof": proof, "linkage_proven": proof["proven"],
                   "resolved_under_authority": proof["resolved_under_authority"],
                   "link": {"all_under_prefix": proof["all_under_prefix"],
                            "sonames": proof["sonames"]}}
    if template_admission is not None:
        base_canvas["template_admission"] = template_admission
        base_canvas["linkage_proven"] = (base_canvas["linkage_proven"]
                                         and template_admission["admitted"])

    if not version_ok or not proof["proven"]:
        reason = ("the program did not start and report its version" if not version_ok else
                  "the subject's libssl/libcrypto were not loaded by the dynamic loader")
        return _runtime_row(
            fam, recipe, subject, level=L4, outcome="failed", residual="runtime-failure",
            failure_class="load-failure", reason=reason, specimen_id=spec_id, variant_id=variant_id,
            source_sha256=source_sha256, evidence=evidence, canvas=base_canvas, limits=limits,
            prefix=prefix, source_root_hash=source_root_hash, launch=list(prog["launch"]),
            workload=None, transcript=_transcript(("launch", launch)), local_only=True)

    if template_admission is not None and not template_admission["admitted"]:
        return _runtime_row(
            fam, recipe, subject, level=L4, outcome="failed", residual="runtime-failure",
            failure_class="link-failure",
            reason=f"template admission refused: {template_admission['reason']}",
            specimen_id=spec_id, variant_id=variant_id, source_sha256=source_sha256,
            evidence=evidence + ["admission:template"], canvas=base_canvas, limits=limits,
            prefix=prefix, source_root_hash=source_root_hash, launch=list(prog["launch"]),
            workload=None, transcript=_transcript(("launch", launch)), local_only=True)

    runner = RUNNERS.get(name)
    if runner is None:
        # The program loads, but no local workload is admitted for it: state the exclusion honestly.
        return _runtime_row(
            fam, recipe, subject, level=L5, outcome="reached", residual="out-of-scope",
            failure_class=None,
            reason=("no admitted deterministic local workload exists for this program in this "
                    "venue; only L5-loaded is measured"),
            specimen_id=spec_id, variant_id=variant_id, source_sha256=source_sha256,
            evidence=evidence, canvas=base_canvas, limits=limits, prefix=prefix,
            source_root_hash=source_root_hash, launch=list(prog["launch"]), workload=None,
            transcript=_transcript(("launch", launch)), local_only=True)

    ctx = {"family": name, "subject": subject, "program": program, "root": root, "prefix": prefix,
           "authority_prefix": authority_prefix, "workdir": workdir, "port": _free_port(),
           "env": env, "build_env": build_env}
    try:
        result = runner(ctx)
    except Exception as exc:  # noqa: BLE001 — a fixture failure is recorded, never raised
        result = {"runtime_ok": False, "functional_ok": False, "failure_class": "harness-failure",
                  "residual": "out-of-scope", "reason": f"the local workload fixture failed: {exc}",
                  "transcript": "", "workload": "harness-failure", "local_only": True}

    raw = _transcript(("launch", launch), ("workload", {"exit_code": 0,
                                                        "stdout": result.get("transcript", "")}))
    normalised = normalise_transcript(raw, prefix, authority_prefix, workdir, ctx["port"])

    extra = {"workload_result": {"name": result.get("workload"), "runtime_ok": result["runtime_ok"],
                                 "functional_ok": result["functional_ok"],
                                 "local_only": result.get("local_only", True)}}
    if result.get("note"):
        extra["note"] = result["note"]
    # Persist the consumer-boundary proof beside the level it gated: an L7 row
    # without this evidence (for a mechanism template) would be a false L7.
    if result.get("consumer_evidence") is not None:
        extra["consumer_evidence"] = result["consumer_evidence"]

    if result["functional_ok"]:
        level, outcome, residual, failure_class, reason = L7, "reached", "none", None, None
    elif result["runtime_ok"]:
        level = L6
        outcome = "failed" if result.get("failure_class") else "reached"
        residual = result.get("residual") or "functional-divergence"
        failure_class = result.get("failure_class")
        reason = result.get("reason") or result.get("note") or (
            "the workload reached its runtime level but no functional level was driven")
    else:
        level, outcome = L5, "failed"
        residual = result.get("residual") or "runtime-failure"
        failure_class = result.get("failure_class") or "runtime-failure"
        reason = result.get("reason") or "the local workload did not complete"

    return _runtime_row(
        fam, recipe, subject, level=level, outcome=outcome, residual=residual,
        failure_class=failure_class, reason=reason, specimen_id=spec_id, variant_id=variant_id,
        source_sha256=source_sha256, evidence=evidence, canvas=base_canvas, limits=limits,
        prefix=prefix, source_root_hash=source_root_hash, launch=list(prog["launch"]),
        workload=str(result.get("workload")), transcript=normalised,
        local_only=bool(result.get("local_only", True)), extra=extra)


def _not_attempted(fam: dict, subject: str, *, level: str, failure_class: str, residual: str,
                   reason: str, recipe: dict | None, specimen_id: str | None,
                   variant_id: str | None, source_sha256: str | None, limits: dict,
                   prefix: Path) -> dict:
    return _runtime_row(
        fam, recipe, subject, level=level, outcome="not_attempted", residual=residual,
        failure_class=failure_class, reason=reason, specimen_id=specimen_id, variant_id=variant_id,
        source_sha256=source_sha256, evidence=[f"family:{fam.get('family_id')}"], canvas=None,
        limits=limits, prefix=prefix, source_root_hash=None, launch=None, workload=None,
        transcript="", local_only=True)


def derive_atlas(families_body: dict, freeze_body: dict, build_link_body: dict,
                 authority_id: str, *, only: set[str] | None = None,
                 reuse: dict | None = None,
                 allow_superseded: bool = False) -> dict:
    """Measure the whole P1000 under both subjects and return the atlas `body`.

    `only`/`reuse` are the evidence-reuse seam: with a committed runtime atlas whose candidate
    identity is byte-identical to the current candidate install, unchanged families keep their
    previously measured rows and only `only` is rebuilt. `allow_superseded` is the explicit
    escape hatch for a candidate rebuild (it never claims a match): the reused rows remain bound
    to the committed identity, which is recorded in `evidence_reuse.superseded_identity`.
    """
    del families_body
    auth_prefix = resolve_authority(authority_id).prefix
    if not (CANDIDATE_PREFIX / "lib" / "libssl.so.3").is_file():
        raise SystemExit(f"[downstream-runtime] the candidate install prefix "
                         f"{rel(CANDIDATE_PREFIX)} holds no lib/libssl.so.3")
    limits = census.resource_limits()
    auth_defined = census.authority_defined_symbols(auth_prefix)
    cand_defined = census.authority_defined_symbols(CANDIDATE_PREFIX)

    bl_rows: dict[tuple[str, str], dict] = {}
    for r in build_link_body.get("runs") or []:
        bl_rows[(str(r.get("family_id")), str(r.get("subject")))] = r

    p1000 = freeze_body.get("p1000") or []
    rows: list[dict] = []
    specimens: dict[str, dict] = {}
    variants: dict[str, dict] = {}
    reuse_runs: dict[tuple[str, str], dict] = {}
    reused_families: list[str] = []
    superseded: dict[str, dict] = {}
    committed_identity: dict = {}
    if reuse:
        current = bl.candidate_identity()
        committed = reuse.get("candidate_identity") or {}
        committed_identity = copy.deepcopy(committed)
        for field in ("libssl_so_3_sha256", "libcrypto_so_3_sha256", "install_prefix"):
            if str(current.get(field)) != str(committed.get(field)):
                if not allow_superseded:
                    raise SystemExit(
                        f"[downstream-runtime] --reuse-committed refuses the committed atlas: "
                        f"its candidate_identity.{field} is not the current candidate install")
                superseded[field] = {"committed": str(committed.get(field)),
                                     "current": str(current.get(field))}
        for r in reuse.get("runs") or []:
            reuse_runs[(str(r.get("family_id")), str(r.get("subject")))] = r
        for s in reuse.get("specimens") or []:
            specimens[str(s.get("specimen_id"))] = copy.deepcopy(s)
        for v in reuse.get("variants") or []:
            variants[str(v.get("variant_id"))] = copy.deepcopy(v)

    SCRATCH.mkdir(parents=True, exist_ok=True)
    try:
        for entry in p1000:
            name = str(entry.get("canonical_name"))
            fam = {
                "family_id": entry.get("family_id"),
                "canonical_name": name,
                "openssl_linkage": entry.get("openssl_linkage"),
                "directness_class": entry.get("directness_class"),
                "_rank": entry.get("p1000_rank"),
            }
            recipe = bl._RECIPE_BY_FAMILY.get(name)
            permits = {s: RANK.get(str((bl_rows.get((str(entry.get("family_id")), s)) or {})
                                        .get("level")), -1) for s in SUBJECTS}
            any_l4 = any(permits[s] >= RANK[L4] for s in SUBJECTS)

            if (recipe is not None and only is not None and name not in only
                    and (str(entry.get("family_id")), "authority") in reuse_runs
                    and (str(entry.get("family_id")), "candidate") in reuse_runs
                    and reuse_runs[(str(entry.get("family_id")), "authority")]
                    .get("recipe_id") == recipe["recipe_id"]
                    and reuse_runs[(str(entry.get("family_id")), "candidate")]
                    .get("recipe_id") == recipe["recipe_id"]):
                rows.append(copy.deepcopy(reuse_runs[(str(entry.get("family_id")),
                                                     "authority")]))
                rows.append(copy.deepcopy(reuse_runs[(str(entry.get("family_id")),
                                                     "candidate")]))
                if superseded:
                    for row in rows[-2:]:
                        row["reused_from_candidate_identity"] = committed_identity
                reused_families.append(name)
                continue

            if recipe is None:
                for subject in SUBJECTS:
                    rows.append(_not_attempted(
                        fam, subject, level=L0, failure_class="acquire-failure",
                        residual="unavailable",
                        reason=("no admitted pristine-source build recipe is recorded for this "
                                "family; the atlas does not manufacture a source URL"),
                        recipe=None, specimen_id=None, variant_id=None, source_sha256=None,
                        limits=limits, prefix=auth_prefix))
                continue

            if not any_l4:
                for subject in SUBJECTS:
                    blocked = str((bl_rows.get((str(entry.get("family_id")), subject)) or {})
                                  .get("level") or L0)
                    rows.append(_not_attempted(
                        fam, subject, level=blocked if RANK.get(blocked, -1) >= 0 else L0,
                        failure_class="link-failure", residual="unlinked",
                        reason=(f"the 24.6 build/link run reached {blocked}, below L4-linked, so "
                                f"there is no loaded program to run"),
                        recipe=recipe, specimen_id=_specimen_variant(recipe, name)[0],
                        variant_id=_specimen_variant(recipe, name)[1], source_sha256=None,
                        limits=limits, prefix=auth_prefix))
                continue

            # A recipe-backed family the venue admits no runtime workload for (no PROGRAMS entry)
            # reaches only its build/link level: the runtime atlas records that honestly rather than
            # rebuilding a program it will not load, so 24.17's admission batch (which links but has
            # no admitted local workload) is `no-fixture`, not a fabricated load.
            if name not in PROGRAMS:
                for subject in SUBJECTS:
                    blr = bl_rows.get((str(entry.get("family_id")), subject)) or {}
                    blocked = str(blr.get("level") or L0)
                    spec_id, variant_id = _specimen_variant(recipe, name)
                    if RANK.get(blocked, -1) < RANK[L4]:
                        rows.append(_not_attempted(
                            fam, subject,
                            level=blocked if RANK.get(blocked, -1) >= 0 else L0,
                            failure_class="link-failure", residual="unlinked",
                            reason=(f"the 24.6 build/link run for {subject} reached {blocked}, below "
                                    f"L4-linked, so there is no loaded program to run"),
                            recipe=recipe, specimen_id=spec_id, variant_id=variant_id,
                            source_sha256=blr.get("source_sha256"), limits=limits,
                            prefix=auth_prefix))
                    else:
                        rows.append(_runtime_row(
                            fam, recipe, subject, level=blocked, outcome="reached",
                            residual="out-of-scope", failure_class=None,
                            reason=("no admitted deterministic local workload exists for this "
                                    "program in this venue; only the build/link level is measured"),
                            specimen_id=spec_id, variant_id=variant_id,
                            source_sha256=blr.get("source_sha256"),
                            evidence=[f"family:{entry.get('family_id')}",
                                      f"recipe:{recipe['recipe_id']}"], canvas=None,
                            limits=limits, prefix=auth_prefix,
                            source_root_hash=blr.get("source_root_hash"), launch=None,
                            workload=None, transcript="", local_only=True))
                continue

            # At least one subject reached L4: rebuild the pristine source once (the exact build
            # intent 24.6 used) so the program that is loaded is the program that was linked.
            try:
                _bl_rows, specimen, variant = bl.measure_family(
                    fam, recipe, auth_prefix, CANDIDATE_PREFIX, auth_defined, cand_defined, limits)
            except Exception as exc:  # noqa: BLE001 - one family must not abort the court
                # Acquisition is a measured outcome, not a court abort: record every subject as
                # `acquire-failure` naming the source host, then continue with the next family.
                reason = (f"acquiring or rebuilding the pristine source from {recipe['url']} "
                          f"failed: {type(exc).__name__}: {exc}")
                for subject in SUBJECTS:
                    rows.append(_not_attempted(
                        fam, subject, level=L0, failure_class="acquire-failure",
                        residual="unavailable", reason=reason, recipe=recipe,
                        specimen_id=_specimen_variant(recipe, name)[0],
                        variant_id=_specimen_variant(recipe, name)[1], source_sha256=None,
                        limits=limits, prefix=auth_prefix))
                print(f"  [p1000 {entry.get('p1000_rank'):>4}] {name:<12} acquire-failure "
                      f"{reason[:70]}"[:150], flush=True)
                continue
            if specimen:
                specimens[specimen["specimen_id"]] = specimen
            if variant:
                variants[variant["variant_id"]] = variant
            source_sha256 = next((r.get("source_sha256") for r in _bl_rows
                                  if r.get("source_sha256")), None)
            source_root_hash = next((r.get("source_root_hash") for r in _bl_rows
                                     if r.get("source_root_hash")), None)

            # A failed acquisition returns rows without a source tree; the atlas records the
            # acquire failure itself instead of probing a directory that was never created.
            acquire_failure = next((r for r in _bl_rows
                                    if r.get("failure_class") == "acquire-failure"), None)
            if acquire_failure is not None:
                reason = str(acquire_failure.get("reason") or
                             f"the pristine source from {recipe['url']} was not acquired")
                for subject in SUBJECTS:
                    rows.append(_not_attempted(
                        fam, subject, level=str(acquire_failure.get("level") or L0),
                        failure_class="acquire-failure", residual="unavailable",
                        reason=reason, recipe=recipe,
                        specimen_id=_specimen_variant(recipe, name)[0],
                        variant_id=_specimen_variant(recipe, name)[1], source_sha256=None,
                        limits=limits, prefix=auth_prefix))
                print(f"  [p1000 {entry.get('p1000_rank'):>4}] {name:<12} acquire-failure "
                      f"{reason[:70]}"[:150], flush=True)
                continue

            for subject in SUBJECTS:
                if permits[subject] < RANK[L4]:
                    blocked = str((bl_rows.get((str(entry.get("family_id")), subject)) or {})
                                  .get("level") or L0)
                    rows.append(_not_attempted(
                        fam, subject, level=blocked if RANK.get(blocked, -1) >= 0 else L0,
                        failure_class="link-failure", residual="unlinked",
                        reason=(f"the 24.6 build/link run for {subject} reached {blocked}, below "
                                f"L4-linked, so there is no loaded program to run"),
                        recipe=recipe, specimen_id=_specimen_variant(recipe, name)[0],
                        variant_id=_specimen_variant(recipe, name)[1], source_sha256=source_sha256,
                        limits=limits, prefix=auth_prefix))
                    continue
                root = census._single_source_root(bl.SCRATCH / name / subject / "src")
                if root is None:
                    rows.append(_not_attempted(
                        fam, subject, level=L4, failure_class="acquire-failure",
                        residual="unavailable",
                        reason=(f"the rebuild of {recipe['url']} produced no source tree to "
                                f"load from"), recipe=recipe,
                        specimen_id=_specimen_variant(recipe, name)[0],
                        variant_id=_specimen_variant(recipe, name)[1], source_sha256=source_sha256,
                        limits=limits, prefix=auth_prefix))
                    continue
                rows.append(_measure_subject_runtime(
                    fam, recipe, subject,
                    auth_prefix if subject == "authority" else CANDIDATE_PREFIX, auth_prefix,
                    root, source_sha256, source_root_hash, limits))
                last = rows[-1]
                print(f"  [p1000 {entry.get('p1000_rank'):>4}] {name:<10} {subject:<9} "
                      f"{last['level']:<16} {str(last.get('reason') or '')[:60]}"[:150], flush=True)
    finally:
        census._cleanup(bl.SCRATCH)
        census._cleanup(SCRATCH)

    _apply_baseline(rows)
    rows.sort(key=lambda r: (str(r.get("family_id")), str(r.get("subject"))))
    counts = _counts(freeze_body, rows)
    current_identity = bl.candidate_identity()
    carried = {}
    for r in rows:
        marker = r.get("reused_from_candidate_identity")
        if marker and marker != current_identity:
            carried[tuple(sorted(marker.items()))] = marker
    body = {
        "rule": RULE,
        "authority": authority_id,
        "authority_prefix": rel(auth_prefix),
        "candidate_identity": bl.candidate_identity(),
        "recipe_catalogue": [
            {"family": r["family"], "version": r["version"], "recipe_id": r["recipe_id"],
             "program": PROGRAMS.get(r["family"], {}).get("program")}
            for r in bl.RECIPES
        ],
        "specimens": sorted(specimens.values(), key=lambda s: str(s["specimen_id"])),
        "variants": sorted(variants.values(), key=lambda v: str(v["variant_id"])),
        "runs": rows,
        "counts": counts,
        "resource_limits": limits,
        "non_claims": NON_CLAIMS,
        "evidence_reuse": ({
            "mode": ("committed-rows-carried-forward"
                     if (superseded or carried) else "committed-rows"),
            "families_reused": len(reused_families),
            "reused_families": sorted(reused_families),
            "candidate_identity_match": not (superseded or carried),
            "superseded_identity": superseded or (list(carried.values()) or None),
        } if reuse else None),
    }
    return body


def _apply_baseline(rows: list[dict]) -> None:
    """Record on every row the authority-applicable baseline its family's authority rows reached."""
    baseline: dict[str, str] = {}
    for r in rows:
        if r.get("subject") == "authority":
            fid = str(r.get("family_id"))
            lv = str(r.get("level"))
            if RANK.get(lv, -1) > RANK.get(baseline.get(fid, L0), -1):
                baseline[fid] = lv
    for r in rows:
        fid = str(r.get("family_id"))
        base = baseline.get(fid, L0)
        r["authority_applicable_level"] = base
        r["reaches_baseline"] = RANK.get(str(r.get("level")), -1) >= RANK.get(base, -1)
        r["beyond_baseline"] = RANK.get(str(r.get("level")), -1) > RANK.get(base, -1)


def _counts(freeze_body: dict, rows: list[dict]) -> dict:
    """The counts, derived from the rows and the frozen P1000, never typed."""
    p1000 = freeze_body.get("p1000") or []
    recipe_families = {r["family"] for r in bl.RECIPES}

    def levels(subject: str, rung: str) -> int:
        return sum(1 for r in rows if r.get("subject") == subject
                   and RANK.get(str(r.get("level")), -1) >= RANK[rung])

    def outcomes(subject: str, outcome: str) -> int:
        return sum(1 for r in rows if r.get("subject") == subject and r.get("outcome") == outcome)

    baseline = {}
    for r in rows:
        if r.get("subject") == "authority":
            fid = str(r.get("family_id"))
            if RANK.get(str(r.get("level")), -1) > RANK.get(baseline.get(fid, L0), -1):
                baseline[fid] = str(r.get("level"))

    # The authority-applicable level per specimen (the recipe-backed families), and the candidate's
    # reach of it. `candidate_reaches_baseline` is the literal rule (candidate rank >= authority
    # baseline rank) over every specimen; `candidate_reaches_linked_baseline` restricts it to the
    # specimens whose authority baseline actually linked (rank >= L4), which is the set a drop-in is
    # even meaningful for, and `candidate_baseline_not_linked` records the rest so the first count
    # cannot be misread as 'every specimen was a real drop-in baseline'.
    spec_baseline: dict[str, str] = {}
    reaches = below = reaches_linked = not_linked = 0
    by_name = {str(e.get("canonical_name")): str(e.get("family_id")) for e in p1000}
    for name in sorted(recipe_families):
        fid = by_name.get(name)
        if fid is None:
            continue
        base = baseline.get(fid, L0)
        spec_baseline[fid] = base
        base_rank = RANK.get(base, -1)
        cand = next((r for r in rows if r.get("family_id") == fid
                     and r.get("subject") == "candidate"), None)
        cand_rank = RANK.get(str(cand.get("level")), -1) if cand else -1
        if base_rank >= RANK[L4]:
            if cand_rank >= base_rank:
                reaches_linked += 1
            else:
                below += 1
        else:
            not_linked += 1
        if cand_rank >= base_rank:
            reaches += 1

    failure_histogram: dict[str, int] = {}
    for r in rows:
        if r.get("subject") == "candidate" and r.get("outcome") in ("failed", "not_attempted"):
            fc = r.get("failure_class")
            if fc:
                failure_histogram[fc] = failure_histogram.get(fc, 0) + 1

    return {
        "p1000": len(p1000),
        "rows": len(rows),
        "with_recipe": len([e for e in p1000 if str(e.get("canonical_name")) in recipe_families]),
        "no_recipe": len([e for e in p1000 if str(e.get("canonical_name")) not in recipe_families]),
        "by_subject": {
            subject: {
                "loaded": levels(subject, L5),
                "runtime": levels(subject, L6),
                "functional": levels(subject, L7),
                "failed": outcomes(subject, "failed"),
                "not_attempted": outcomes(subject, "not_attempted"),
            }
            for subject in SUBJECTS
        },
        "authority_applicable_level": spec_baseline,
        "candidate_reaches_baseline": reaches,
        "candidate_reaches_linked_baseline": reaches_linked,
        "candidate_below_baseline": below,
        "candidate_baseline_not_linked": not_linked,
        "candidate_failures": failure_histogram,
        "candidate_specific_patch_count": sum(
            int(r.get("candidate_specific_patch_count") or 0) for r in rows),
    }


def write_outputs(body: dict, authority_id: str) -> None:
    inputs = [
        InputRef(name="family-freeze", path=FAMILY_FREEZE),
        InputRef(name="families", path=FAMILIES),
        InputRef(name="build-link-atlas", path=BUILD_LINK_ATLAS),
        InputRef(name="downstream-build-link",
                 path=REPO_ROOT / "forensics" / "tools" / "downstream_build_link.py"),
        InputRef(name="downstream-census",
                 path=REPO_ROOT / "forensics" / "tools" / "downstream_census.py"),
        InputRef(name="downstream-schemas",
                 path=REPO_ROOT / "forensics" / "tools" / "downstream_schemas.py"),
        InputRef(name="phase24-guard",
                 path=REPO_ROOT / "forensics" / "tools" / "phase24_guard.py"),
        InputRef(name="phase-24-plan",
                 path=REPO_ROOT / "docs" / "PHASE-24-DOWNSTREAM-1000-SUBPHASES.md"),
    ]
    doc = envelope(kind="downstream-runtime-functional-atlas", authority=authority_id,
                   inputs=inputs, body=body, generator=GENERATOR)
    doc["body_hash"] = content_hash(body)
    write_json(OUT, doc)


# --------------------------------------------------------------------------------------------
# the checks the court re-runs over the committed artefact (pure; never rebuilding)
# --------------------------------------------------------------------------------------------

def _load_atlas() -> dict:
    if not OUT.is_file():
        return {}
    return json.loads(OUT.read_text(encoding="utf-8")).get("body", {})


def _load_build_link() -> dict:
    if not BUILD_LINK_ATLAS.is_file():
        return {}
    return json.loads(BUILD_LINK_ATLAS.read_text(encoding="utf-8")).get("body", {})


def runtime_findings(families_body: dict, freeze_body: dict, build_link_body: dict,
                     atlas_body: dict) -> list[str]:
    """Every way the recorded runtime/functional atlas fails its own subject.

    Pure over the committed frozen P1000, the committed 24.6 build/link atlas and the committed
    runtime atlas, so the court re-runs it without rebuilding and the sensitivity control can mutate
    an in-memory copy. Every check is a re-derivation from the recorded rows: the population is
    accounted for under both subjects, a runtime row never reaches above the level its build/link row
    reached, an `L5+` row is backed by a real load proof, an `L6`/`L7` row has a non-empty normalised
    transcript, the candidate's authority-applicable baseline is re-derived (never inflated to
    justify a pass), the normaliser never erases evidence, a non-measured row carries a reason and a
    schema-valid residual/failure class, and the counts are read rather than typed.
    """
    del families_body
    findings: list[str] = []
    p1000 = freeze_body.get("p1000") or []
    p1000_ids = [str(e.get("family_id")) for e in p1000]
    p1000_set = set(p1000_ids)
    recipe_families = {r["family"] for r in bl.RECIPES}

    bl_rows: dict[tuple[str, str], dict] = {}
    for r in build_link_body.get("runs") or []:
        bl_rows[(str(r.get("family_id")), str(r.get("subject")))] = r

    runs = atlas_body.get("runs") or []
    if not runs:
        return ["the atlas records no runtime/functional run"]

    by_family_subject: dict[tuple[str, str], dict] = {}
    seen_run_ids: set[str] = set()
    for row in runs:
        fid = str(row.get("family_id"))
        subject = str(row.get("subject"))
        findings += [f"{fid}/{subject}: {p}" for p in downstream_schemas.validate_run(row)]
        rid = str(row.get("run_id"))
        if rid in seen_run_ids:
            findings.append(f"two runtime rows share run_id {rid!r}")
        seen_run_ids.add(rid)
        if fid not in p1000_set:
            findings.append(f"{fid} is not a frozen P1000 family: the atlas must account for the "
                            f"frozen population")
        if subject not in SUBJECTS:
            findings.append(f"{fid}: a runtime row names subject {subject!r}, not "
                            f"`authority`/`candidate`")
        by_family_subject[(fid, subject)] = row

        if int(row.get("candidate_specific_patch_count") or 0) != 0:
            findings.append(f"{fid}/{subject}: candidate_specific_patch_count is "
                            f"{row.get('candidate_specific_patch_count')!r}, not 0")

        # The permit: a runtime row may exceed its build/link level only because the build/link
        # reached L4-linked. A subject whose build/link row never linked cannot load or run.
        blr = bl_rows.get((fid, subject)) or {}
        permit = RANK.get(str(blr.get("level")), -1)
        if permit < RANK[L4] and RANK.get(str(row.get("level")), -1) > permit:
            findings.append(f"{fid}/{subject}: the runtime row reached {row.get('level')}, above "
                            f"the build/link level {blr.get('level')!r} it may load: a subject that "
                            f"never linked cannot load")

        outcome = row.get("outcome")
        if outcome in ("failed", "not_attempted", "unavailable"):
            if not row.get("reason"):
                findings.append(f"{fid}/{subject}: a {outcome} row carries no reason")
            if not row.get("failure_class"):
                findings.append(f"{fid}/{subject}: a {outcome} row carries no failure class")
            elif row["failure_class"] not in downstream_schemas.FAILURE_CLASSES:
                findings.append(f"{fid}/{subject}: failure class {row['failure_class']!r} is outside "
                                f"the taxonomy")
            if row.get("residual_class") in (None, "none"):
                findings.append(f"{fid}/{subject}: a {outcome} row carries no residual class")
        if row.get("residual_class") not in (None, "none") and not row.get("reason"):
            findings.append(f"{fid}/{subject}: a row with residual {row.get('residual_class')!r} "
                            f"carries no reason")

        level_rank = RANK.get(str(row.get("level")), -1)
        if level_rank >= RANK[L5]:
            if not row.get("linkage_proven"):
                findings.append(f"{fid}/{subject}: claims {row.get('level')} but its load/linkage "
                                f"is not proven")
            proof = row.get("load_proof") or {}
            if proof.get("proven") is not True:
                findings.append(f"{fid}/{subject}: a {row.get('level')} row carries no proven load "
                                f"proof")
            link = row.get("link") or {}
            if link.get("all_under_prefix") is not True:
                findings.append(f"{fid}/{subject}: a {row.get('level')} row does not resolve every "
                                f"OpenSSL soname under the subject prefix")
            if subject == "candidate" and (row.get("resolved_under_authority")
                                           or link.get("resolved_under_authority")):
                findings.append(f"{fid}/{subject}: a candidate {row.get('level')} row resolves the "
                                f"authority prefix, so the load proves the authority, not the "
                                f"candidate")
        if level_rank >= RANK[L6]:
            ts = str(row.get("transcript_sha256") or "")
            if len(ts) != 64:
                findings.append(f"{fid}/{subject}: a {row.get('level')} row has no non-empty "
                                f"transcript hash")
            norm = row.get("normalisation") or {}
            if not norm.get("tag"):
                findings.append(f"{fid}/{subject}: a {row.get('level')} row carries no normalisation "
                                f"tag")
            normalises = list(norm.get("normalises") or [])
            bad = [c for c in normalises if c not in NORMALISATION_ALLOWED]
            if bad:
                findings.append(f"{fid}/{subject}: the normalisation erases evidence "
                                f"({sorted(bad)}): return codes, error classes, certificate "
                                f"decisions and protocol/algorithm choices are never normalised")
        if not row.get("local_only"):
            findings.append(f"{fid}/{subject}: a runtime row is not marked local-only")

    # Every frozen family is accounted for under both subjects.
    missing = [fid for fid in p1000_ids
               if (fid, "authority") not in by_family_subject
               or (fid, "candidate") not in by_family_subject]
    if missing:
        findings.append(f"{len(missing)} frozen P1000 family(ies) lack a runtime row under both "
                        f"subjects (e.g. {missing[:3]})")

    # A family that reached L4 in 24.6 has runtime rows under both subjects.
    for fid in p1000_ids:
        bl_levels = [bl_rows.get((fid, s)) for s in SUBJECTS]
        if any(RANK.get(str(r.get("level")) if r else None, -1) >= RANK[L4] for r in bl_levels):
            for subject in SUBJECTS:
                if (fid, subject) not in by_family_subject:
                    findings.append(f"{fid}: reached L4-linked in 24.6 but has no {subject} runtime "
                                    f"row")

    # The candidate's authority-applicable baseline is re-derived, never inflated.
    derived_baseline: dict[str, str] = {}
    for r in runs:
        if r.get("subject") == "authority":
            fid = str(r.get("family_id"))
            if RANK.get(str(r.get("level")), -1) > RANK.get(derived_baseline.get(fid, L0), -1):
                derived_baseline[fid] = str(r.get("level"))
    for row in runs:
        if row.get("subject") != "candidate":
            continue
        fid = str(row.get("family_id"))
        base = derived_baseline.get(fid, L0)
        if str(row.get("authority_applicable_level")) != base:
            findings.append(f"{fid}/candidate: records authority_applicable_level "
                            f"{row.get('authority_applicable_level')!r}, but the authority rows "
                            f"reached {base!r}: the baseline is re-derived, never inflated to "
                            f"justify a pass")
        want_reach = RANK.get(str(row.get("level")), -1) >= RANK.get(base, -1)
        if bool(row.get("reaches_baseline")) != want_reach:
            findings.append(f"{fid}/candidate: reaches_baseline is {row.get('reaches_baseline')!r}, "
                            f"but the level {row.get('level')!r} against baseline {base!r} is "
                            f"{want_reach}")
        want_beyond = RANK.get(str(row.get("level")), -1) > RANK.get(base, -1)
        if bool(row.get("beyond_baseline")) != want_beyond:
            findings.append(f"{fid}/candidate: beyond_baseline is {row.get('beyond_baseline')!r}, "
                            f"but the level {row.get('level')!r} against baseline {base!r} is "
                            f"{want_beyond}")

    # The recorded rule and non-claims are the frozen ones.
    if atlas_body.get("rule") != RULE:
        findings.append("the recorded runtime rule is not the frozen rule")
    if atlas_body.get("non_claims") != NON_CLAIMS:
        findings.append("the recorded non_claims are not the stratum's four plus the functional "
                        "non-claim")

    # Counts are read, not typed.
    derived = _counts(freeze_body, runs)
    recorded = atlas_body.get("counts") or {}
    for key in ("p1000", "rows", "with_recipe", "no_recipe", "candidate_reaches_baseline",
                "candidate_reaches_linked_baseline", "candidate_below_baseline",
                "candidate_baseline_not_linked", "candidate_specific_patch_count"):
        if recorded.get(key) != derived[key]:
            findings.append(f"counts.{key} {recorded.get(key)!r} disagrees with the derived "
                            f"{derived[key]!r}")
    for subject in SUBJECTS:
        for rung in ("loaded", "runtime", "functional", "failed", "not_attempted"):
            got = (recorded.get("by_subject") or {}).get(subject, {}).get(rung)
            want = derived["by_subject"][subject][rung]
            if got != want:
                findings.append(f"counts.by_subject.{subject}.{rung} {got!r} disagrees with the "
                                f"derived {want!r}")
    if recorded.get("authority_applicable_level") != derived["authority_applicable_level"]:
        findings.append("counts.authority_applicable_level disagrees with the derived baseline map")
    if (recorded.get("candidate_failures") or {}) != derived["candidate_failures"]:
        findings.append("counts.candidate_failures disagrees with the derived histogram")
    return findings


def _mutations(atlas_body: dict, freeze_body: dict) -> list[tuple[str, str, dict]]:
    """`(name, needle, mutated_atlas)` for each seeded mutation."""
    del freeze_body
    out: list[tuple[str, str, dict]] = []
    runs = atlas_body.get("runs") or []

    # a candidate row whose level passes only because its baseline was inflated (an aspirational
    # authority level the authority never reached). Any candidate row at or below its baseline is a
    # valid target: raising its recorded baseline above the level the authority rows reached is the
    # defect the re-derivation check exists to catch.
    m1 = copy.deepcopy(atlas_body)
    cand = next((r for r in m1["runs"] if r.get("subject") == "candidate"
                 and not r.get("beyond_baseline")
                 and str(r.get("authority_applicable_level")) not in ("", "None", L0)), None)
    if cand is not None:
        cand["authority_applicable_level"] = "L8-authority-equivalent"
        cand["reaches_baseline"] = True
    out.append(("candidate_level_above_authority_baseline", "authority_applicable_level", m1))

    # an L5+ row with no load proof.
    m2 = copy.deepcopy(atlas_body)
    loaded = next((r for r in m2["runs"] if RANK.get(str(r.get("level")), -1) >= RANK[L5]), None)
    if loaded is not None:
        loaded["linkage_proven"] = False
        loaded["load_proof"] = {"proven": False}
    out.append(("loaded_row_without_proof", "load/linkage is not proven", m2))

    # an L6+ row with an empty transcript hash.
    m3 = copy.deepcopy(atlas_body)
    runtime = next((r for r in m3["runs"] if RANK.get(str(r.get("level")), -1) >= RANK[L6]), None)
    if runtime is not None:
        runtime["transcript_sha256"] = ""
    out.append(("runtime_row_without_transcript", "no non-empty transcript hash", m3))

    # a missing authority runtime row for a family that reached L4 in 24.6.
    m4 = copy.deepcopy(atlas_body)
    auth_row = next((r for r in m4["runs"] if r.get("subject") == "authority"
                     and RANK.get(str(r.get("level")), -1) >= RANK[L5]), None)
    if auth_row is not None:
        m4["runs"] = [r for r in m4["runs"] if r.get("run_id") != auth_row.get("run_id")]
    out.append(("missing_authority_runtime_row", "has no authority runtime row", m4))

    # a normalisation that erases a return code (evidence the workload exists to produce).
    m5 = copy.deepcopy(atlas_body)
    row5 = next((r for r in m5["runs"] if RANK.get(str(r.get("level")), -1) >= RANK[L6]
                 and r.get("transcript_sha256")), None)
    if row5 is not None:
        row5["normalisation"] = {**(row5.get("normalisation") or {}),
                                 "normalises": ["absolute_paths", "ports", "return_codes"]}
    out.append(("normalisation_erases_return_code", "erases evidence", m5))

    # a runtime row reaching above its build/link permit.
    m6 = copy.deepcopy(atlas_body)
    blocked = next((r for r in m6["runs"] if r.get("subject") == "candidate"
                    and RANK.get(str(r.get("level")), -1) == RANK[L0]), None)
    if blocked is not None:
        blocked["level"] = L6
        blocked["authority_applicable_level"] = L6
    out.append(("runtime_above_build_link_permit", "above the build/link level", m6))
    return out


def runtime_sensitivity_control(families_body: dict, freeze_body: dict, build_link_body: dict,
                                atlas_body: dict) -> dict:
    """Prove the court can fail: seed six mutations and require each to be caught.

    The honest atlas must yield **zero** findings (specificity), and each seeded mutation -- a
    candidate row whose level passes only by inflating its authority baseline, an `L5+` row with no
    load proof, an `L6+` row with an empty transcript hash, a missing authority runtime row for a
    family that reached `L4`, a normalisation that erases a return code, and a runtime row reaching
    above its build/link permit -- must be caught with a finding that names what it is.
    """
    base = runtime_findings(families_body, freeze_body, build_link_body, atlas_body)
    specificity = not base
    control: dict = {"baseline_findings": len(base), "specificity_holds": specificity}
    honest = specificity
    for name, needle, mutated in _mutations(atlas_body, freeze_body):
        caught = any(needle in f for f in
                     runtime_findings(families_body, freeze_body, build_link_body, mutated))
        control[f"injected_{name}"] = name
        control[f"caught_{name}"] = caught
        honest = honest and caught
    control["honest"] = bool(honest)
    return control


# --------------------------------------------------------------------------------------------
# entry point
# --------------------------------------------------------------------------------------------

def _load_inputs() -> tuple[dict, dict, dict]:
    if not FAMILY_FREEZE.is_file():
        raise SystemExit(f"[downstream-runtime] {rel(FAMILY_FREEZE)} is absent; run 24.4 first")
    if not BUILD_LINK_ATLAS.is_file():
        raise SystemExit(f"[downstream-runtime] {rel(BUILD_LINK_ATLAS)} is absent; run 24.6 first")
    freeze_body = json.loads(FAMILY_FREEZE.read_text(encoding="utf-8"))["body"]
    families_body = (json.loads(FAMILIES.read_text(encoding="utf-8"))["body"]
                     if FAMILIES.is_file() else {})
    build_link_body = json.loads(BUILD_LINK_ATLAS.read_text(encoding="utf-8"))["body"]
    return freeze_body, families_body, build_link_body


def cmd_measure(authority_id: str, only: set[str] | None = None,
                reuse: dict | None = None, allow_superseded: bool = False) -> int:
    freeze_body, families_body, build_link_body = _load_inputs()
    if len(freeze_body.get("p1000") or []) != 1000:
        print(f"[downstream-runtime] the frozen P1000 carries "
              f"{len(freeze_body.get('p1000') or [])} family(ies), not 1000")
        return 1
    print(f"[downstream-runtime] loading and running the recipe-backed families against both "
          f"subjects (authority {authority_id} + candidate {rel(CANDIDATE_PREFIX)})")
    started = time.monotonic()
    body = derive_atlas(families_body, freeze_body, build_link_body, authority_id,
                        only=only, reuse=reuse, allow_superseded=allow_superseded)
    findings = runtime_findings(families_body, freeze_body, build_link_body, body)
    control = runtime_sensitivity_control(families_body, freeze_body, build_link_body, body)
    if findings or not control["honest"]:
        print("[downstream-runtime] the measured atlas fails its own checks:")
        for f in findings:
            print(f"  - {f}")
        if not control["honest"]:
            print(f"  - the sensitivity control is not honest: {control}")
        return 1
    write_outputs(body, authority_id)
    c = body["counts"]
    print(f"[downstream-runtime] elapsed={time.monotonic() - started:.0f}s "
          f"with_recipe={c['with_recipe']} no_recipe={c['no_recipe']}")
    for subject in SUBJECTS:
        s = c["by_subject"][subject]
        print(f"  {subject:<9} loaded={s['loaded']} runtime={s['runtime']} "
              f"functional={s['functional']} failed={s['failed']} "
              f"not_attempted={s['not_attempted']}")
    print(f"  candidate_reaches_baseline={c['candidate_reaches_baseline']} "
          f"reaches_linked_baseline={c['candidate_reaches_linked_baseline']} "
          f"below_baseline={c['candidate_below_baseline']} "
          f"baseline_not_linked={c['candidate_baseline_not_linked']} "
          f"candidate_failures={c['candidate_failures']}")
    print(f"  -> {rel(OUT)}")
    return 0


def cmd_check(authority_id: str) -> int:
    del authority_id
    if not (FAMILY_FREEZE.is_file() and BUILD_LINK_ATLAS.is_file() and OUT.is_file()):
        print(f"[downstream-runtime] {rel(FAMILY_FREEZE)}, {rel(BUILD_LINK_ATLAS)} or {rel(OUT)} "
              f"is absent")
        return 1
    freeze_body, families_body, build_link_body = _load_inputs()
    atlas_body = _load_atlas()
    findings = runtime_findings(families_body, freeze_body, build_link_body, atlas_body)
    control = runtime_sensitivity_control(families_body, freeze_body, build_link_body, atlas_body)
    if findings:
        print(f"[downstream-runtime] {len(findings)} finding(s):")
        for f in findings:
            print(f"  - {f}")
    c = atlas_body.get("counts") or {}
    by = c.get("by_subject") or {}
    print(f"[downstream-runtime] with_recipe={c.get('with_recipe')} "
          f"cand_loaded={(by.get('candidate') or {}).get('loaded')} "
          f"cand_functional={(by.get('candidate') or {}).get('functional')} "
          f"reaches_baseline={c.get('candidate_reaches_baseline')} findings={len(findings)} "
          f"control honest={control['honest']}")
    return 0 if (not findings and control["honest"]) else 1


def self_test() -> int:
    """Prove the guard refuses a host invocation and the pure functions behave over committed data."""
    failures: list[str] = []

    # 1. The guard refuses a host invocation of this tool, naming the marker and the opt-in flag.
    refusal = phase24_guard.host_refusal_reasons("downstream_runtime.py")
    if not refusal:
        failures.append("the guard admitted a host invocation of downstream_runtime.py")
    else:
        manifest = phase24_guard.load_manifest()
        joined = " ".join(refusal)
        if str(manifest.get("marker")) not in joined:
            failures.append("the host refusal does not name the container marker")
        if str(manifest.get("env_flag")) not in joined:
            failures.append("the host refusal does not name the opt-in flag")

    # 2. The workload intents are well-formed over the reused recipe catalogue.
    for r in bl.RECIPES:
        name = r["family"]
        if name in PROGRAMS:
            spec = PROGRAMS[name]
            if not (r["family"] and spec["program"] and spec["launch"] and spec["version_re"]):
                failures.append(f"the runtime intent for {name!r} is incomplete")

    # 3. The normaliser never erases evidence: a return code survives it.
    sample = "exit=1 error=verify failed return_code=0 TLSv1.3 ECDHE-RSA-AES256-GCM-SHA384"
    norm = normalise_transcript(sample, Path("/p"), Path("/a"), Path("/s"), 8443)
    for kept in ("exit=1", "return_code=0", "TLSv1.3", "ECDHE-RSA-AES256-GCM-SHA384",
                 "error=verify failed"):
        if kept not in norm:
            failures.append(f"the normaliser erased evidence: {kept!r} is not in {norm!r}")

    # 4. The pure functions behave over the committed evidence.
    if not (FAMILY_FREEZE.is_file() and BUILD_LINK_ATLAS.is_file()):
        failures.append(f"{rel(FAMILY_FREEZE)} or {rel(BUILD_LINK_ATLAS)} is absent")
    else:
        freeze_body, families_body, build_link_body = _load_inputs()
        if len(freeze_body.get("p1000") or []) != 1000:
            failures.append("the frozen P1000 does not carry 1000 family(ies)")
        if not OUT.is_file():
            failures.append(f"{rel(OUT)} is absent; run --measure")
        else:
            atlas_body = _load_atlas()
            findings = runtime_findings(families_body, freeze_body, build_link_body, atlas_body)
            if findings:
                failures.append(f"the committed atlas has findings: {findings[:3]}")
            control = runtime_sensitivity_control(families_body, freeze_body, build_link_body,
                                                  atlas_body)
            if not control["honest"]:
                failures.append(f"the sensitivity control is not honest: {control}")

    # 5. Acquisition failure is a measured outcome, not a court abort. A missing source tree is
    #    reported as `None` (never a `FileNotFoundError`), and the failure rows name the source
    #    host/URL while accounting for both subjects under the closed vocabulary.
    missing = Path("/nonexistent-acquire-self-test/src")
    if census._single_source_root(missing) is not None:
        failures.append("a missing source tree did not report `None`")
    recipe = {"family": "__selftest__", "version": "0", "recipe_id": "selftest",
              "url": "https://unreachable.invalid/__selftest__.tar.gz", "archive": "tar.gz"}
    fam = {"family_id": "__selftest__", "canonical_name": "__selftest__",
           "openssl_linkage": "direct", "directness_class": "direct", "_rank": 0}
    acquire_rows = bl._acquisition_failure_rows(
        fam, recipe, "fetching the pristine source from https://unreachable.invalid/ failed",
        {"memory_max": "?", "pids_max": "?"}, Path("/p"))
    if {r["subject"] for r in acquire_rows} != {"authority", "candidate"}:
        failures.append("an acquisition failure does not account for both subjects")
    for r in acquire_rows:
        if r.get("failure_class") != "acquire-failure" or "unreachable.invalid" not in str(
                r.get("reason")):
            failures.append("an acquisition failure neither names its class nor its source host")
        problems = downstream_schemas.validate_run(r)
        if problems:
            failures.append(f"an acquisition failure row is schema-invalid: {problems[:2]}")

    if failures:
        print("[downstream-runtime] self-test FAILED")
        for f in failures:
            print(f"  {f}")
        return 1
    print("[downstream-runtime] self-test ok: the guard refuses a host invocation of this tool "
          "(marker and flag both named), a missing source tree is an `acquire-failure` naming its "
          "host rather than a raised exception, the normaliser preserves every return code, error class, "
          "certificate decision and protocol/algorithm choice it must, the committed P1000 "
          "runtime/functional atlas reproduces with zero findings, and every seeded mutation "
          "(an inflated authority baseline, an L5 row with no load proof, an L6 row with an empty "
          "transcript, a missing authority runtime row, a normalisation that erases a return code, "
          "and a runtime row above its build/link permit) is caught with specificity holding")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    ap.add_argument("--measure", action="store_true",
                    help="run the real builds and workloads and write the atlas (in-container)")
    ap.add_argument("--only", default="",
                    help="comma-separated families to measure; the rest are reused")
    ap.add_argument("--reuse-committed", action="store_true",
                    help="reuse unchanged families' rows from the committed atlas")
    ap.add_argument("--reuse-previous-candidate", action="store_true",
                    help=("with --reuse-committed, allow rows bound to a different (previous) "
                          "candidate install and record the mismatch explicitly"))
    ap.add_argument("--check", action="store_true",
                    help="validate the committed atlas without rebuilding (in-container)")
    ap.add_argument("--self-test", action="store_true",
                    help="prove the pure functions over the committed evidence")
    args = ap.parse_args(argv)

    # The Docker-only execution guard, called first. This tool fetches, compiles and runs, so it is an
    # execution entry point and a host invocation is refused.
    phase24_guard.require_admitted()

    if args.self_test:
        return self_test()
    if args.check:
        return cmd_check(args.authority)
    only = {s.strip() for s in str(args.only).split(",") if s.strip()} or None
    reuse = _load_atlas() if args.reuse_committed and OUT.is_file() else None
    return cmd_measure(args.authority, only=only, reuse=reuse,
                       allow_superseded=bool(args.reuse_previous_candidate))


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
