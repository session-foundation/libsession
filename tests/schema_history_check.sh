#!/bin/bash
#
# Checks that a database created by any previously published version upgrades cleanly to the
# current schema.
#
# full_schema.sql is the only thing that creates a schema; the migrations beside it are deltas from
# an older full_schema.  There is therefore no way to build a database by replaying migrations from
# nothing, and the only starting points that exist are earlier versions of full_schema.sql — which
# exist solely in git history.  That is what this walks.
#
# Starting points are every tag, plus every commit since the most recent tag (so unreleased work in
# progress is covered too, not just published versions), and every revision after SCHEMA_FLOOR.
# Revisions whose schemas are byte-identical to one already checked are skipped: a version that
# changed no schema tells us nothing new, and without this every tag in a quiet period would re-run
# the same check.
#
# Usage: tests/schema_history_check.sh <path-to-schema-upgrade-check>

set -euo pipefail

CHECKER=${1:-}
if [[ -z "$CHECKER" || ! -x "$CHECKER" ]]; then
    echo "usage: $0 <path-to-schema-upgrade-check binary>" >&2
    exit 2
fi

cd "$(dirname "$0")/.."

CORE_DIR=src/core/schema
CLIENT_DIR=src/client/schema

# Exemptions, one revision per line with a reason, for commits known to carry a broken schema (a
# work-in-progress state that was never released).  Kept as a file so removing something from it is
# a reviewable change rather than a silent edit to the walk.
SKIPLIST=tests/schema_history_skip.txt

# The oldest revision that is *not* a usable starting point, and by extension neither is anything
# behind it.
#
# A schema is described by full_schema.sql alone, so a change to one that ships without a migration
# leaves no way to carry an existing database across it: the database has to be recreated.  Every
# revision before such a change therefore describes a database that cannot reach today's schema, and
# checking that it does is checking something we deliberately gave up.
#
# Bump this to the then-current HEAD each time that happens.  It is a single revision rather than a
# list because the property is a cutoff: once one database has to be recreated, so does every older
# one.  Everything after it is still walked, which is what keeps a development branch honest between
# cutoffs -- consecutive commits do have to upgrade cleanly.
SCHEMA_FLOOR=3df4ae5207714dbc7cbb31ea8541321a6d1589a0

revs=$(
    git tag
    last_tag=$(git describe --tags --abbrev=0 2>/dev/null || true)
    if [[ -n "$last_tag" ]]; then
        git rev-list "$last_tag..HEAD"
    else
        git rev-list HEAD
    fi
)

# An entry naming no commit in this history skips nothing while looking as though it does, which is
# how a rebase after the entries were written goes unnoticed.  Refused outright instead.
if [[ -f "$SKIPLIST" ]]; then
    while read -r entry _; do
        [[ -z "$entry" || "$entry" == \#* ]] && continue
        if ! git merge-base --is-ancestor "$entry" HEAD 2>/dev/null; then
            echo "$SKIPLIST: $entry is not a commit in this history" >&2
            exit 1
        fi
    done <"$SKIPLIST"
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

declare -A seen
checked=0
skipped=0

for rev in $revs; do
    if [[ -f "$SKIPLIST" ]] && grep -q "^$(git rev-parse --short "$rev")" "$SKIPLIST" 2>/dev/null; then
        continue
    fi

    # `--is-ancestor` counts a commit as its own ancestor, so this drops the floor itself too.
    if git merge-base --is-ancestor "$rev" "$SCHEMA_FLOOR" 2>/dev/null; then
        continue
    fi

    core_sql=$(git show "$rev:$CORE_DIR/full_schema.sql" 2>/dev/null || true)
    # A revision predating full_schema.sql has no starting point to offer.
    [[ -z "$core_sql" ]] && continue

    client_sql=$(git show "$rev:$CLIENT_DIR/full_schema.sql" 2>/dev/null || true)

    # Dedupe on the schemas themselves, not the revision: consecutive releases usually share one.
    key=$(printf '%s\0%s' "$core_sql" "$client_sql" | sha256sum | cut -d' ' -f1)
    if [[ -n "${seen[$key]:-}" ]]; then
        skipped=$((skipped + 1))
        continue
    fi
    seen[$key]=$rev

    printf '%s' "$core_sql" > "$tmp/core.sql"
    args=(--core-schema "$tmp/core.sql")
    if [[ -n "$client_sql" ]]; then
        printf '%s' "$client_sql" > "$tmp/client.sql"
        args+=(--client-schema "$tmp/client.sql")
    fi

    # The migrations that existed then are what a database of that era would have recorded; anything
    # added since is what must now run.
    while read -r f; do
        [[ -z "$f" ]] && continue
        args+=(--applied "$(basename "$f" | sed -E 's/\.(sql|cpp)$//')")
    done < <(git ls-tree --name-only "$rev" "$CORE_DIR/" | grep -E '/[0-9][^/]*\.(sql|cpp)$' || true)

    while read -r f; do
        [[ -z "$f" ]] && continue
        args+=(--applied "client:$(basename "$f" | sed -E 's/\.(sql|cpp)$//')")
    done < <(git ls-tree --name-only "$rev" "$CLIENT_DIR/" | grep -E '/[0-9][^/]*\.(sql|cpp)$' || true)

    echo "checking upgrade from $(git describe --tags --always "$rev")"
    if ! "$CHECKER" "${args[@]}"; then
        echo "FAILED: a database created at $rev does not upgrade to the current schema" >&2
        exit 1
    fi
    checked=$((checked + 1))
done

echo "schema history check: $checked starting point(s) verified, $skipped duplicate(s) skipped"
if (( checked == 0 )); then
    echo "note: no revision yet carries a full_schema.sql to upgrade from" >&2
fi
