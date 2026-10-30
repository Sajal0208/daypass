#!/usr/bin/env bash
# End-to-end check against a real Postgres. Used by CI; runs locally too:
#   OWNER_URL=postgres://postgres:postgres@localhost:5432/postgres scripts/ci-integration.sh
#
# 1. Create a table with a "secret" column, apply the generated role SQL hiding it.
# 2. Open a lease, run `daypass doctor` (login, read-only, write blocked).
# 3. Drive the MCP server: visible column OK, hidden column denied, writes blocked, expiry enforced.
# 4. `daypass hidden suggest|check` agree with the live catalog (as owner and as the read-only role).
set -euo pipefail
cd "$(dirname "$0")/.."
: "${OWNER_URL:?set OWNER_URL to a postgres:// URL with owner rights}"

export DAYPASS_HOME
DAYPASS_HOME="$(mktemp -d)"
DAYPASS=(node dist/cli/main.js)

psql "$OWNER_URL" -v ON_ERROR_STOP=1 -q <<'SQL'
DROP TABLE IF EXISTS customers;
CREATE TABLE customers (id serial primary key, name text, email text, secret text);
INSERT INTO customers (name, email, secret) VALUES ('Ada', 'ada@example.com', 'hunter2');
SQL

printf 'customers.email\ncustomers.secret\n' > "$DAYPASS_HOME/hidden.txt"
"${DAYPASS[@]}" sql --role daypass_ro --hide-file "$DAYPASS_HOME/hidden.txt" \
  | psql "$OWNER_URL" -v ON_ERROR_STOP=1 -q
# Non-RDS owners set a password once after the first run; re-runs must keep it.
psql "$OWNER_URL" -q -c "ALTER ROLE daypass_ro PASSWORD 'ro-pass';"

# `hidden --url` verifies TLS unless the URL says sslmode=disable; the CI Postgres has no TLS.
OWNER_NOSSL_URL="$(node -e "const u=new URL(process.argv[1]);u.searchParams.set('sslmode','disable');console.log(u.toString())" "$OWNER_URL")"
"${DAYPASS[@]}" hidden suggest --url "$OWNER_NOSSL_URL" | grep -q '^customers.email$'
"${DAYPASS[@]}" hidden suggest --url "$OWNER_NOSSL_URL" | grep -q '^customers.secret$'
"${DAYPASS[@]}" hidden check --file "$DAYPASS_HOME/hidden.txt" --url "$OWNER_NOSSL_URL"
printf 'customers.email\ncustomers.gone\n' > "$DAYPASS_HOME/hidden-bad.txt"
if "${DAYPASS[@]}" hidden check --file "$DAYPASS_HOME/hidden-bad.txt" --url "$OWNER_NOSSL_URL" >/dev/null; then
  echo "hidden check should exit 1 on a stale list"; exit 1
fi

RO_URL="$(node -e "const u=new URL(process.argv[1]);u.username='daypass_ro';u.password='ro-pass';u.searchParams.set('sslmode','disable');console.log(u.toString())" "$OWNER_URL")"

# A failed re-run must change nothing. A stale entry (customers.gone) stops the script after the
# bulk GRANT SELECT ON ALL TABLES; without a transaction that leaves the hidden column readable.
priv() { psql "$OWNER_URL" -tA -c "SELECT has_column_privilege('daypass_ro','customers','$1','SELECT')"; }
printf 'customers.email\ncustomers.secret\ncustomers.gone\n' > "$DAYPASS_HOME/hidden-stale.txt"
if "${DAYPASS[@]}" sql --role daypass_ro --hide-file "$DAYPASS_HOME/hidden-stale.txt" \
     | psql "$OWNER_URL" -v ON_ERROR_STOP=1 -q 2>"$DAYPASS_HOME/stale.err"; then
  echo "FAIL: setup with a stale hidden column must exit non-zero"; exit 1
fi
grep -q 'hidden column "customers.gone" does not exist' "$DAYPASS_HOME/stale.err" \
  || { echo "FAIL: expected stale-entry error"; cat "$DAYPASS_HOME/stale.err"; exit 1; }
echo "after failed re-run: secret=$(priv secret) name=$(priv name)"
[ "$(priv secret)" = f ] || { echo "FAIL: failed re-run exposed customers.secret"; exit 1; }
[ "$(priv name)" = t ]   || { echo "FAIL: failed re-run removed access to customers.name"; exit 1; }
psql "$RO_URL" -tA -c "select 1" >/dev/null || { echo "FAIL: failed re-run reset the role password"; exit 1; }
echo "after failed re-run: password still works"

# Even without ON_ERROR_STOP (psql keeps going, exit 0) the aborted transaction makes COMMIT a
# rollback, so privileges are still unchanged.
"${DAYPASS[@]}" sql --role daypass_ro --hide-file "$DAYPASS_HOME/hidden-stale.txt" \
  | psql "$OWNER_URL" -q >/dev/null 2>&1 || true
[ "$(priv secret)" = f ] && [ "$(priv name)" = t ] || { echo "FAIL: failed re-run without ON_ERROR_STOP changed privileges"; exit 1; }
psql "$RO_URL" -tA -c "select 1" >/dev/null || { echo "FAIL: failed re-run without ON_ERROR_STOP reset the password"; exit 1; }
echo "after failed re-run without ON_ERROR_STOP: secret=$(priv secret) name=$(priv name), password still works"

# A psqlrc with ON_ERROR_ROLLBACK=on would savepoint around the failing DO block and let COMMIT
# land the bulk GRANT; the script's own \set lines override it, so this still fails and changes nothing.
if "${DAYPASS[@]}" sql --role daypass_ro --hide-file "$DAYPASS_HOME/hidden-stale.txt" \
     | psql "$OWNER_URL" -v ON_ERROR_ROLLBACK=on -q >/dev/null 2>&1; then
  echo "FAIL: stale-list run with ON_ERROR_ROLLBACK=on must exit non-zero"; exit 1
fi
[ "$(priv secret)" = f ] && [ "$(priv name)" = t ] || { echo "FAIL: ON_ERROR_ROLLBACK=on let the failed re-run change privileges"; exit 1; }
echo "after failed re-run with ON_ERROR_ROLLBACK=on: secret=$(priv secret) name=$(priv name)"

# The transaction covers the DO blocks and the \gexec line too: a failed FIRST run under a new
# role name leaves no role behind (CREATE ROLE and GRANT CONNECT both rolled back).
"${DAYPASS[@]}" sql --role daypass_never --hide-file "$DAYPASS_HOME/hidden-stale.txt" \
  | psql "$OWNER_URL" -v ON_ERROR_STOP=1 -q >/dev/null 2>&1 || true
[ "$(psql "$OWNER_URL" -tA -c "select count(*) from pg_roles where rolname = 'daypass_never'")" = 0 ] \
  || { echo "FAIL: failed first run left the role behind (transaction does not cover CREATE ROLE)"; exit 1; }
echo "after failed first run: role daypass_never does not exist"

# A successful re-run keeps the password too.
"${DAYPASS[@]}" sql --role daypass_ro --hide-file "$DAYPASS_HOME/hidden.txt" \
  | psql "$OWNER_URL" -v ON_ERROR_STOP=1 -q
psql "$RO_URL" -tA -c "select 1" >/dev/null || { echo "FAIL: successful re-run reset the role password"; exit 1; }
echo "after successful re-run: secret=$(priv secret) name=$(priv name), password still works"

node -e "require('fs').writeFileSync(process.env.DAYPASS_HOME+'/config.json', JSON.stringify({targets:{ci:{url:process.argv[1]}}}))" "$RO_URL"

"${DAYPASS[@]}" open ci --no-network --reason "ci" --ttl 5m
"${DAYPASS[@]}" doctor ci
# pg_catalog lists hidden columns regardless of grants, so the read-only role sees the same picture.
"${DAYPASS[@]}" hidden check --file "$DAYPASS_HOME/hidden.txt" --live ci

node scripts/smoke.mjs
"${DAYPASS[@]}" log -n 20
"${DAYPASS[@]}" close
psql "$OWNER_URL" -q -c "DROP TABLE IF EXISTS customers;"
echo "integration: OK"
