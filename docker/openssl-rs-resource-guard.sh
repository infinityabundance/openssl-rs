#!/usr/bin/env bash
# openssl-rs — shared host-side resource guard for the container lifecycle scripts
# (openssl-rs-court.sh, openssl-rs-frf-court.sh, openssl-rs-asan.sh).
#
# This file is SOURCED, never executed. It exists because each venue gets its own,
# independent cgroup memory cap, and independent caps add up: three containers that
# each declare 8g collectively declare 24g, and no per-container flag can see the
# other two. The host is a shared resource -- the editor, rust-analyzer and the
# user's other work live on it -- so the sum has to be checked in one place, against
# one budget, or the logic drifts between the three scripts. Everything here is that
# one place.
#
# It provides:
#
#   guard_is_positive_int          POSIX-style positive-integer validation
#   guard_mem_to_bytes             "8g" / "512m" / a bare byte count -> bytes
#   guard_host_memtotal_bytes      /proc/meminfo MemTotal, in bytes
#   guard_host_memavailable_bytes  /proc/meminfo MemAvailable, in bytes
#   guard_clamp_mem_to_host        clamp a single request above MemTotal, announced
#   guard_check_container_budget   collective budget for the running openssl-rs-* set
#   guard_cgroup_dir               the host cgroup v2 directory for a container
#   guard_report_oom               memory.current / memory.max / memory.events
#
# Nothing here is silent. A value that cannot be parsed, a host that cannot be
# measured, or a budget that would be exceeded all produce a message and, where
# safety is at stake, a non-zero exit.
#
# Shared env overrides:
#   OPENSSL_RS_CONTAINER_BUDGET    collective memory budget for all openssl-rs-*
#                                  containers at once, a memory size; default is the
#                                  host's MemTotal (see guard_check_container_budget)
#   OPENSSL_RS_CONTAINER_HEADROOM  headroom below which the MemAvailable warning
#                                  fires; default 2g (see guard_check_container_budget)
#   OPENSSL_RS_CONTAINER_PREFIX    container-name prefix the budget counts; default
#                                  "openssl-rs-"
#   OPENSSL_RS_HOST_MEMINFO        path to the meminfo file read for MemTotal /
#                                  MemAvailable; default /proc/meminfo. A test hook
#                                  for simulating a runner of a different size -- the
#                                  default is always the real /proc/meminfo.

# A memory size (or a budget) docker understands, translated to bytes on stdout.
# Docker accepts a plain byte count and the short / IEC / byte suffixes -- 8g,
# 512m, 512mb, 1gib -- and this accepts the same shapes in either case. A value
# this cannot parse is a hard error for the caller, never a default: silently
# treating an unparseable cap as "no cap" is the exact failure this file exists to
# prevent.
guard_mem_to_bytes() {
  local raw lower mult
  raw="${1:-}"
  [ -n "${raw}" ] || return 1
  lower="$(printf '%s' "${raw}" | tr 'A-Z' 'a-z')"
  # Peel off a trailing unit in short ("g"), byte ("gb") or IEC ("gib") form.
  case "${lower}" in
    *b) lower="${lower%b}" ;;
  esac
  case "${lower}" in
    *i) lower="${lower%i}" ;;
  esac
  mult=1
  case "${lower}" in
    *k) lower="${lower%k}"; mult=1024 ;;
    *m) lower="${lower%m}"; mult=1048576 ;;
    *g) lower="${lower%g}"; mult=1073741824 ;;
    *t) lower="${lower%t}"; mult=1099511627776 ;;
  esac
  case "${lower}" in
    '' | *[!0-9]*) return 1 ;;
  esac
  printf '%s' "$(( 10#${lower} * mult ))"
}

# Positive-integer validation in the same shape the venue scripts already use for
# their CPU cap: no suffix, no sign, and a zero is not positive.
guard_is_positive_int() {
  case "${1}" in
    '' | *[!0-9]*) return 1 ;;
  esac
  [ "${1}" -gt 0 ]
}

# Read one /proc/meminfo field (name without the colon) as bytes on stdout. The
# file defaults to the real /proc/meminfo; OPENSSL_RS_HOST_MEMINFO only exists so a
# runner of a different size can be simulated in a test.
guard_host_meminfo_bytes() {
  awk -v field="${1}:" '$1 == field { printf "%d", $2 * 1024; found = 1 }
                        END { exit(found ? 0 : 1) }' "${OPENSSL_RS_HOST_MEMINFO:-/proc/meminfo}"
}

guard_host_memtotal_bytes() { guard_host_meminfo_bytes MemTotal; }
guard_host_memavailable_bytes() { guard_host_meminfo_bytes MemAvailable; }

# Clamp a single requested memory size to the host's actual RAM, announcing the
# clamp on stderr (so a caller capturing stdout cannot hide it) and echoing the
# clamped value on stdout. This is the mem counterpart of the `--cpus` clamp the
# venue scripts already apply: docker happily accepts a `--memory` larger than the
# machine, and the request then stops bounding anything the host can feel, so it is
# reduced to what the host really has -- to MemTotal, which is also the default
# budget, so that a single clamped container is always admissible.
guard_clamp_mem_to_host() {
  local label="${1}" request="${2}" req_bytes host_bytes
  if ! req_bytes="$(guard_mem_to_bytes "${request}")"; then
    echo "${label}: memory size '${request}' is not a size docker understands" >&2
    exit 2
  fi
  if [ "${req_bytes}" -le 0 ]; then
    echo "${label}: memory size must be greater than zero (got '${request}')" >&2
    exit 2
  fi
  if ! host_bytes="$(guard_host_memtotal_bytes)"; then
    echo "${label}: WARNING: cannot read MemTotal from /proc/meminfo; skipping the host clamp" >&2
    printf '%s' "${request}"
    return 0
  fi
  if [ "${req_bytes}" -gt "${host_bytes}" ]; then
    echo "${label}: note: --memory=${request} requested, but this machine has ${host_bytes} bytes of RAM; clamping to ${host_bytes}" >&2
    printf '%s' "${host_bytes}"
  else
    printf '%s' "${request}"
  fi
}

# Enforce the collective budget at `up` time.
#
#   $1  label           the venue's name, for messages
#   $2  name            the container about to be started
#   $3  request         its requested docker memory size (already host-clamped)
#
# The budget is OPENSSL_RS_CONTAINER_BUDGET, or -- by default -- the host's own
# MemTotal. MemTotal (rather than a fraction) is the default because the clamping
# above already reduces a single over-large request to exactly MemTotal: with a
# fractional budget, one clamped container would then exceed its own budget and `up`
# would refuse on a machine where it used to work. The budget is a ceiling on what
# the containers *declare*, not on what they use; real usage is bounded independently
# by the cgroup and the per-process RLIMIT_DATA on the exec path.
#
# The sum is over the running containers whose names begin with
# OPENSSL_RS_CONTAINER_PREFIX (default "openssl-rs-"), so the three venues see each
# other. A running sibling that declares no memory cap at all (docker's `0`, i.e.
# unlimited) cannot be summed, so it is counted against the whole budget and the
# start is refused: an unbounded sibling is precisely what the guard cannot protect
# the host from.
#
# Exceeding the budget refuses `up` with a non-zero exit. A low MemAvailable -- a
# number that moves while the machine is in use -- only warns, never refuses, so
# that a busy host cannot make `up` flaky.
guard_check_container_budget() {
  local label="${1}" name="${2}" request="${3}"
  local req_bytes prefix budget budget_raw running sib sib_bytes siblings total
  local headroom headroom_raw avail_bytes

  if ! req_bytes="$(guard_mem_to_bytes "${request}")"; then
    echo "${label}: cannot parse requested memory '${request}'" >&2
    exit 2
  fi

  prefix="${OPENSSL_RS_CONTAINER_PREFIX:-openssl-rs-}"
  budget_raw="${OPENSSL_RS_CONTAINER_BUDGET:-}"
  if [ -n "${budget_raw}" ]; then
    if ! budget="$(guard_mem_to_bytes "${budget_raw}")"; then
      echo "${label}: OPENSSL_RS_CONTAINER_BUDGET must be a memory size like 64g (got '${budget_raw}')" >&2
      exit 2
    fi
    if [ "${budget}" -le 0 ]; then
      echo "${label}: OPENSSL_RS_CONTAINER_BUDGET must be greater than zero (got '${budget_raw}')" >&2
      exit 2
    fi
    echo "${label}: collective container budget: ${budget} bytes (OPENSSL_RS_CONTAINER_BUDGET)" >&2
  elif budget="$(guard_host_memtotal_bytes)"; then
    echo "${label}: collective container budget: ${budget} bytes (host MemTotal)" >&2
  else
    echo "${label}: WARNING: cannot read host MemTotal; skipping the collective container budget guard" >&2
    budget=""
  fi

  if [ -n "${budget}" ]; then
    if ! running="$(docker ps --format '{{.Names}}')"; then
      echo "${label}: cannot enumerate running containers (docker ps failed); refusing to start '${name}'" >&2
      exit 2
    fi
    siblings=0
    while IFS= read -r sib; do
      [ -n "${sib}" ] || continue
      case "${sib}" in
        "${prefix}"*) ;;
        *) continue ;;
      esac
      [ "${sib}" = "${name}" ] && continue
      sib_bytes="$(docker inspect --format '{{.HostConfig.Memory}}' "${sib}" 2>/dev/null || printf '0')"
      case "${sib_bytes}" in
        '' | *[!0-9]*) sib_bytes=0 ;;
      esac
      if [ "${sib_bytes}" -le 0 ]; then
        echo "${label}: WARNING: running '${sib}' declares no --memory cap (unlimited); counting it against the entire budget" >&2
        sib_bytes="${budget}"
      fi
      siblings=$(( siblings + sib_bytes ))
    done <<EOF
${running}
EOF
    total=$(( siblings + req_bytes ))
    if [ "${total}" -gt "${budget}" ]; then
      echo "${label}: refusing to start '${name}': the declared container memory would be ${total} bytes -- ${siblings} bytes already declared by running '${prefix}*' containers plus ${req_bytes} requested -- which exceeds the ${budget}-byte budget." >&2
      echo "${label}: stop another container first ('<script> down') or raise OPENSSL_RS_CONTAINER_BUDGET if this host can take it." >&2
      exit 2
    fi
  fi

  headroom_raw="${OPENSSL_RS_CONTAINER_HEADROOM:-2g}"
  if ! headroom="$(guard_mem_to_bytes "${headroom_raw}")"; then
    echo "${label}: OPENSSL_RS_CONTAINER_HEADROOM must be a memory size like 2g (got '${headroom_raw}')" >&2
    exit 2
  fi
  if [ "${headroom}" -le 0 ]; then
    echo "${label}: OPENSSL_RS_CONTAINER_HEADROOM must be greater than zero (got '${headroom_raw}')" >&2
    exit 2
  fi
  if avail_bytes="$(guard_host_memavailable_bytes)"; then
    if [ "${avail_bytes}" -lt "$(( req_bytes + headroom ))" ]; then
      echo "${label}: WARNING: host MemAvailable is ${avail_bytes} bytes, below the requested ${req_bytes}-byte cap plus ${headroom} bytes of headroom; starting this container may put the host under memory pressure." >&2
    fi
  else
    echo "${label}: WARNING: cannot read MemAvailable; skipping the headroom warning" >&2
  fi
}

# The host cgroup v2 directory for a container, on stdout, or a non-zero exit if it
# is gone (the container is stopped). Covers the systemd cgroup driver (docker's
# default on a systemd host) and the plain cgroupfs driver.
guard_cgroup_dir() {
  local name="${1}" id
  id="$(docker inspect --format '{{.Id}}' "${name}" 2>/dev/null)" || return 1
  [ -n "${id}" ] || return 1
  if [ -d "/sys/fs/cgroup/system.slice/docker-${id}.scope" ]; then
    printf '%s' "/sys/fs/cgroup/system.slice/docker-${id}.scope"
    return 0
  fi
  if [ -d "/sys/fs/cgroup/docker/${id}" ]; then
    printf '%s' "/sys/fs/cgroup/docker/${id}"
    return 0
  fi
  return 1
}

# Print the cgroup OOM evidence for a container, read from the host so it survives
# the container's death: memory.current (what it holds now), memory.max (its hard
# cap) and memory.events' oom / oom_kill counters (how many times the cgroup hit the
# cap, and how many processes were killed for it). These counters are cumulative for
# the life of the cgroup, so a runtime OOM kill stays visible until the container is
# recreated -- which is the point: a kill must be explainable after the fact, not
# mysterious. Absent files fall back to "n/a" rather than failing.
guard_report_oom() {
  local name="${1}" base current max_ oom oom_kill
  if ! base="$(guard_cgroup_dir "${name}")"; then
    echo "  cgroup OOM evidence: cgroup not found for '${name}' (container not running?)"
    return 0
  fi
  current="$(cat "${base}/memory.current" 2>/dev/null || printf 'n/a')"
  max_="$(cat "${base}/memory.max" 2>/dev/null || printf 'n/a')"
  if [ -r "${base}/memory.events" ]; then
    oom="$(awk '$1 == "oom" { print $2 }' "${base}/memory.events" 2>/dev/null || printf 'n/a')"
    oom_kill="$(awk '$1 == "oom_kill" { print $2 }' "${base}/memory.events" 2>/dev/null || printf 'n/a')"
  else
    oom="n/a"
    oom_kill="n/a"
  fi
  echo "  cgroup path:      ${base}"
  echo "  memory.current:   ${current}"
  echo "  memory.max:       ${max_}"
  echo "  memory.events:    oom=${oom:-n/a} oom_kill=${oom_kill:-n/a}"
  echo "  docker OOMKilled: $(docker inspect --format '{{.State.OOMKilled}}' "${name}" 2>/dev/null || printf 'n/a')"
}
