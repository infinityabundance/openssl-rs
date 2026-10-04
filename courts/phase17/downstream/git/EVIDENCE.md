# Phase 17 downstream — unmodified Git against the candidate shell

Status: **build/link PROVEN; Git's own t/ suite passes a bounded meaningful subset; SHA-1
and SHA-256 object hashing is correct through the candidate's libcrypto; https push, clone
and pull succeed end-to-end with the candidate's libssl/libcrypto on both ends.** This is a
proof slice; nothing is wired into `forensics/tools/phase17_courts.py` yet.

## What was built

- Candidate distribution surface: `artifacts/phase2/install/{include,lib}` (libssl.so.3 /
  libcrypto.so.3 / libcrypto.a / libssl.a; `openssl` CLI present but only partly landed).
- Unmodified upstream: **Git 2.56.0**, `git-2.56.0.tar.xz`, sha256
  `26c56c296b38c0695b26fa95f475f1d01704d2d38e73465ca30b0b2f5dc789d3` — the published digest
  from the signed `https://mirrors.edge.kernel.org/pub/software/scm/git/sha256sums.asc`.
- A shared **libcurl 8.22.0** (same pin as the sibling `courts/phase17/downstream/curl`
  slice, sha256 `d54dd598bf05927a726deb38df31c6a255ba83ff1de57c5d1464dac3ed8f44a1`) built
  *shared* against the candidate, because that slice builds curl statically into the tool
  and installs no libcurl to link Git against.
- TLS server for the live test: the candidate-linked **nginx 1.26.3** from
  `courts/phase17/downstream/nginx`, running `git-http-backend` behind FastCGI.
- Fixture certificates minted with the admitted authority's `openssl` CLI (see caveats).

## Why the build flags

- `--with-openssl=$CANDIDATE` sets `OPENSSLDIR` so configure probes the candidate's
  libcrypto for `SHA1_Init` and never takes libssl from the system 3.0.x contaminant.
- `--with-curl=$DEPS` sets `CURLDIR` (Git derives `-L`/`-rpath` from it); the actual
  `-lcurl` is passed as `CURL_LDFLAGS=-lcurl`, since the court is deliberately curl-dev-free
  and has no `curl-config` for configure to read it from.
- `OPENSSL_SHA1=YesPlease OPENSSL_SHA256=YesPlease` on the make line is what actually routes
  Git's object hashing through OpenSSL (`-DSHA1_OPENSSL -DSHA256_OPENSSL` + candidate
  `-lcrypto`); `--with-openssl` alone only enables the presence check.
- `NO_TCLTK=1 NO_GETTEXT=1` skip gitk/git-gui and translations (neither is TLS related).

## Reproducible commands

```sh
# from the repository root, court container up:
bash docker/openssl-rs-court.sh exec sh /work/courts/phase17/downstream/git/build.sh
bash docker/openssl-rs-court.sh exec sh /work/courts/phase17/downstream/git/hash_check.sh
bash docker/openssl-rs-court.sh exec sh /work/courts/phase17/downstream/git/run_tests.sh
bash docker/openssl-rs-court.sh exec sh /work/courts/phase17/downstream/git/https_probe.sh
```

## Link evidence (PASS)

```
git version 2.56.0 … libcurl: 8.22.0  OpenSSL: OpenSSL 3.6.4 25 Aug 2026
SHA-1: SHA1_OPENSSL (No collision detection)   SHA-256: SHA256_OPENSSL

git                DT_NEEDED libcrypto.so.3; RUNPATH /work/artifacts/phase2/install/lib
                   U EVP_sha1@OPENSSL_3.0.0   U EVP_sha256@OPENSSL_3.0.0
                   libcrypto.so.3 => /work/artifacts/phase2/install/lib/libcrypto.so.3
git-remote-https   libcurl.so.4  => /court/git/deps/lib/libcurl.so.4
                   libcrypto.so.3 => /work/artifacts/phase2/install/lib/libcrypto.so.3
                   libssl.so.3    => /work/artifacts/phase2/install/lib/libssl.so.3
```

## Object hashing (PASS)

For the blob `hello world\n` (Git hashes `blob 12\0hello world\n`); expected digests
computed independently by GNU `sha1sum`/`sha256sum`, not by OpenSSL:

```
sha1   expected 3b18e512dba79e4c8300dd08aeb37f8e728b8dad   git 3b18e512dba79e4c8300dd08aeb37f8e728b8dad
sha256 expected 0bd69098bd9b9cc5934a610ab65da429b525361147faa7b5b922919e9a23143d
                git 0bd69098bd9b9cc5934a610ab65da429b525361147faa7b5b922919e9a23143d
```

Both agree; `git` imports `EVP_sha1`/`EVP_sha256` from the candidate libcrypto, so the
digests are genuinely computed through the candidate.

## Git's own test suite (bounded subset)

```
t0000-basic          PASS  ok=92   not-ok=0  todo=0  skipped=0
t0001-init           PASS  ok=103  not-ok=0  todo=0  skipped=5
t0002-gitfile        PASS  ok=14   not-ok=0  todo=0  skipped=0
t1006-cat-file       PASS  ok=421  not-ok=0  todo=2  skipped=0
t1007-hash-object    PASS  ok=37   not-ok=0  todo=0  skipped=4
t5540-http-push-webdav   SKIP  git built without expat support
t5551-http-fetch-smart   PASS  ok=57   not-ok=0  todo=0  skipped=2
```

`t1006`'s two `not ok … # TODO known breakage` are Git's own expected failures (the harness
exits 0 and counts them separately). `t5551` requires a non-root uid, so the runner
provisions Apache and a uid-1000 account (the repository's owner convention) and reruns it
there; it passes 57/57. `t5540` is a WebDAV dumb-HTTP-push test that needs libexpat headers
(absent from the court image); it has no OpenSSL path, so it is skipped with that reason.

## https push / clone / pull, both ends on the candidate (PASS)

```
client  git-remote-https -> candidate libcurl -> candidate libssl/libcrypto
server  nginx (candidate libssl/libcrypto) --FastCGI--> git-http-backend (candidate git)

push   ok   (SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384)
clone  HEAD 060aa753…  == pushed HEAD
pull   HEAD 034b64cf…  == new pushed HEAD
negative arm: unrelated CA rejected
  fatal: … SSL certificate OpenSSL verify result: unable to get local issuer certificate (20)
nginx:      libssl.so.3 / libcrypto.so.3 => /work/artifacts/phase2/install/lib
```

FastCGI glue is `fcgiwrap`/`spawn-fcgi` (no TLS in them). The certificate chain is verified
by the client (`verify result: 0`); the unrelated-CA arm shows verification is real.

## Caveats / what did not work

- The candidate's `openssl req` CLI is a Phase 16 boundary ("apps/req … is not landed"), so
  fixture certificates cannot be minted with it; they are minted with the admitted
  authority's real 3.6.4 CLI. All TLS *endpoints* remain the candidate's libssl/libcrypto.
- `t5540` cannot run without libexpat headers; skipped as above.
- The court image has no Apache; the runner installs `apache2` at run time for `t5551`
  (it links no OpenSSL for plain HTTP and does not disturb the candidate).
- None of this is wired into `forensics/tools/phase17_courts.py` (per the task).
