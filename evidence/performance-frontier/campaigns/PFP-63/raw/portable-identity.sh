#!/usr/bin/env bash
# Regenerates the PFP-63 portable-half identity record.
set -u
cd /work || exit 1
git diff > evidence/performance-frontier/campaigns/PFP-63/raw/portable-diff.patch
{
  echo "branch:"
  git rev-parse --abbrev-ref HEAD
  echo "HEAD:"
  git rev-parse HEAD
  echo
  echo "batch files (git status --porcelain, scoped to src/examples/evidence):"
  git --no-optional-locks status --porcelain -- src examples evidence/performance-frontier/campaigns/PFP-63
  echo
  echo "whole-working-tree diff digest (includes pre-existing uncommitted work):"
  sha256sum evidence/performance-frontier/campaigns/PFP-63/raw/portable-diff.patch
  echo
  echo "source hashes:"
  sha256sum src/aes.rs src/aes/portable.rs src/aes/reference.rs src/aes/research.rs \
    src/digest/tables.rs src/modes/gcm.rs forensics/tools/gen_phase8_tables.py \
    examples/pfp63_bench.rs
  echo
  echo "release audit artefact:"
  sha256sum target/release/examples/pfp63_bench
  echo "debug control artefact:"
  sha256sum target/debug/deps/openssl_rs-bcfdf4d0f51f39b5
} > evidence/performance-frontier/campaigns/PFP-63/raw/portable-identity.txt
cat evidence/performance-frontier/campaigns/PFP-63/raw/portable-identity.txt
