#!/usr/bin/env bash
#
# Stand up an ephemeral, hermetic Session Pro backend and run the libsession [pro_live] integration
# tests against it, then tear everything down. No CTest, no Docker: this script IS the entry point.
#
#   run-dev-backend.sh <path-to-testAll> [catch2 args...]
#
# It:
#   1. generates an ephemeral Ed25519 signing key   (session-router-config -k)
#   2. spins up a throwaway PostgreSQL cluster       (initdb + pg_ctl, unix socket in a temp dir)
#   3. starts the backend                            (flask --app main, KEY_PATH, no dev mode)
#   4. polls /status until ready
#   5. runs testAll against it (default filter [pro_live])
#   6. tears it all down on exit
#
# Env overrides:
#   SESSION_PRO_BACKEND_DIR   backend repo         (default ~/src/session-pro-backend-itest)
#   PRO_BACKEND_PORT          flask + pg port      (default 5055)
#
# NB: SESSION_PRO_BACKEND_DIR should be our OWN tracking clone of the backend (with its own .venv),
# NOT the backend agent's live working repo -- that repo is actively edited and may be mid-change.
# Update the clone deliberately (git -C <clone> pull) when we want to track the backend's latest.
#
set -euo pipefail

# Force a UTF-8 locale for the ephemeral cluster and every DB client. Backend migration SQL contains
# non-ASCII bytes (e.g. an em-dash in a comment); psycopg encodes each query with the connection's
# client encoding, which follows the DB/locale. A minimal CI container often runs a C/POSIX locale ->
# ASCII client encoding -> `UnicodeEncodeError: 'ascii' codec can't encode '—'` while bootstrapping
# the DB. C.UTF-8 is always present in glibc (no locale-gen needed), so this makes initdb build a UTF8
# cluster and flask/seed/psql all speak UTF-8, matching production. Overrides any inherited C locale.
export LC_ALL=C.UTF-8 LANG=C.UTF-8

TESTALL="${1:?usage: run-dev-backend.sh <testAll binary> [catch2 args...]}"
shift || true
BACKEND_DIR="${SESSION_PRO_BACKEND_DIR:-$HOME/src/session-pro-backend-itest}"
PORT="${PRO_BACKEND_PORT:-5055}"
PGBIN="$(ls -d /usr/lib/postgresql/*/bin 2>/dev/null | sort -V | tail -1)"
VENV_PY="$BACKEND_DIR/.venv/bin/python"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

[ -x "$TESTALL" ] || { echo "!! testAll not executable: $TESTALL" >&2; exit 2; }
[ -x "$VENV_PY" ] || { echo "!! backend venv python missing: $VENV_PY" >&2; exit 2; }
[ -n "$PGBIN" ]   || { echo "!! postgres bin dir not found under /usr/lib/postgresql" >&2; exit 2; }
command -v session-router-config >/dev/null || { echo "!! session-router-config not on PATH" >&2; exit 2; }

WORK="$(mktemp -d)"
PGDATA="$WORK/pgdata"
KEYFILE="$WORK/backend.key"
FLASK_LOG="$WORK/flask.log"
PG_LOG="$WORK/pg.log"
FLASK_PID=""

cleanup() {
    rc=$?
    [ -n "$FLASK_PID" ] && kill "$FLASK_PID" 2>/dev/null || true
    [ -d "$PGDATA" ] && "$PGBIN/pg_ctl" -D "$PGDATA" -m immediate stop >/dev/null 2>&1 || true
    rm -rf "$WORK"
    exit $rc
}
trap cleanup EXIT INT TERM

echo ">> ephemeral signing key: $KEYFILE"
session-router-config -f -k "$KEYFILE" >/dev/null

echo ">> initdb: $PGDATA"
"$PGBIN/initdb" -D "$PGDATA" --encoding=UTF8 --auth-local=trust --no-instructions -U "$USER" >/dev/null

echo ">> start postgres (unix socket in $WORK, port $PORT)"
"$PGBIN/pg_ctl" -D "$PGDATA" -l "$PG_LOG" \
    -o "-c listen_addresses= -k $WORK -p $PORT" -w start >/dev/null
createdb -h "$WORK" -p "$PORT" -U "$USER" pro_backend

export SESH_PRO_BACKEND_DB_URL="postgresql:///pro_backend?host=$WORK&port=$PORT&user=$USER"
export SESH_PRO_BACKEND_KEY_PATH="$KEYFILE"
# Stub all payment-provider egress so a real add_pro_payment redeems (google/app_store/stf)
# without contacting Google/Apple. Landed backend-side (base.PROVIDER_DRY_RUN). No platform creds and
# no with_platform_* needed: the provider comes from the seeded row, not from platform config.
export SESH_PRO_BACKEND_PROVIDER_DRY_RUN=1

echo ">> start flask on 127.0.0.1:$PORT (log: $FLASK_LOG)"
( cd "$BACKEND_DIR" && exec "$VENV_PY" -m flask --app main run --port "$PORT" ) >"$FLASK_LOG" 2>&1 &
FLASK_PID=$!

echo ">> waiting for /status ..."
ready=""
for _ in $(seq 1 60); do
    if curl -fsS "http://127.0.0.1:$PORT/status" >/dev/null 2>&1; then ready=1; break; fi
    if ! kill -0 "$FLASK_PID" 2>/dev/null; then
        echo "!! flask exited during startup:" >&2; cat "$FLASK_LOG" >&2; exit 3
    fi
    sleep 0.5
done
[ "$ready" = 1 ] || { echo "!! backend not ready in time:" >&2; cat "$FLASK_LOG" >&2; exit 3; }
echo ">> backend ready"

# Expose the seeding helper to the test process (it shells out to inject witnessed payments /
# revocations directly into the DB). DB URL is already exported above and inherited by testAll.
export PRO_BACKEND_DIR="$BACKEND_DIR"
export PRO_SEED_PYTHON="$VENV_PY"
export PRO_SEED_SCRIPT="$SCRIPT_DIR/seed_payment.py"

echo ">> running: $TESTALL ${*:-[pro_live]}"
set +e
"$TESTALL" --pro-backend-dev-server-url="http://127.0.0.1:$PORT" "${@:-[pro_live]}"
rc=$?
set -e
echo ">> testAll exited $rc"
exit $rc
