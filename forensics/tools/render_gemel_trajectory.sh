#!/bin/sh
# openssl-rs — render the Gemel trajectory projection that travels in Git.
#
# Runs in the FRF tooling container, which is where the Gemel store lives:
#
#     bash docker/openssl-rs-frf-court.sh exec sh forensics/tools/render_gemel_trajectory.sh
#
# Why this is a tool and not a pasted transcript: `docs/DECISIONS.md` D17 says the
# native `.gemel` store is not Git-tracked and this projection is. A projection
# that is transcribed by hand is a claim about the store rather than a read of it,
# and the store renumbers derived names (`C6` today is not necessarily `C6`
# tomorrow), so anything quoted from memory goes stale silently. Everything below
# that can be read from the store is read from it.
set -eu

. "$(dirname "$0")/require_court.sh"

cd "$(dirname "$0")/../.."

OUT=forensics/GEMEL_TRAJECTORY.md

render() {
    printf '%s\n' "# Gemel trajectory (generated projection)"
    printf '\n'
    printf '%s\n' "Generated from the local \`.gemel\` store by" \
        "\`forensics/tools/render_gemel_trajectory.sh\` inside the FRF tooling" \
        "container. Gemel's store is **not** Git-tracked (Gemel ships a" \
        "\`.gemel/.gitignore\` containing \`*\`), so this projection, Gemel's own" \
        "\`exchange/\` namespace, and the identities quoted below are what travel" \
        "in Git. See \`docs/DECISIONS.md\` D17."
    printf '\n'
    printf '%s\n' "## \`gemel log\`" "" '```'
    gemel log 2>&1
    printf '%s\n' '```' ""
    # Deliberately no `gemel status` section: status reports how far the working
    # tree has moved from the head state, and writing this very file moves it. A
    # projection that changes every time it is rendered is not a projection of the
    # store, it is a projection of the moment. The log and the checkpoints are
    # store-resident and therefore stable.
    printf '%s\n' "## Checkpoints" ""
    for ref in .gemel/refs/checkpoints/K*; do
        [ -f "$ref" ] || continue
        printf '* `%s` — `%s`\n' "$(basename "$ref")" "$(cat "$ref")"
    done
    printf '\n'
    if [ -f .gemel/refs/checkpoints/current ]; then
        printf 'current: `%s`\n' "$(cat .gemel/refs/checkpoints/current)"
        printf '\n'
    fi
    printf '%s\n' "## Note: derived names are not identities" ""
    cat <<'NOTE'
Gemel names changes by derived order, so a name quoted inside one change's
summary can be renumbered later. The Phase 3 closure change
(`change.0321160b791013c5904bb61fe65b4932da674bdbc7f1043b50e2e4369544c227`)
says it supersedes `C9`; that name no longer exists in the store. The change it
means is
`change.e58167ada98b43af520cd6b8c39c103a30560c406cfd91e6004019fd0b75f326`,
currently named `C11`: a placeholder created by a command-line probe of Gemel's
claim-kind enum, which — because it was created first — is also the change that
carries the Phase 3 working-tree operations. The correction
(`change.8423b2c8fe75201fb070e0b21df03d122c8675cde393c9b2d88d9ea1800ee5de`)
records that mapping in the store rather than only in prose. No file content
changed with it; the Git commit is the authoritative record of the diff.
NOTE
    printf '\n'
    printf '%s\n' "## Open residuals at this boundary" "" '```'
    gemel residuals 2>&1
    printf '%s\n' '```'
}

render > "$OUT"
printf '[render-gemel-trajectory] wrote %s (%s lines)\n' "$OUT" "$(wc -l < "$OUT")"
