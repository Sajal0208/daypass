#!/usr/bin/env bash
# End-to-end check against a real Postgres. Used by CI; runs locally too:
#   OWNER_URL=postgres://postgres:postgres@localhost:5432/postgres scripts/ci-integration.sh
#
# 1. Create a table with a "secret" column, apply the generated role SQL hiding it.
# 2. Open a lease, run `peephole doctor` (login, read-only, write blocked).
# 3. Drive the MCP server: visible column OK, hidden column denied, writes blocked, expiry enforced.
set -euo pipefail
cd "$(dirname "$0")/.."
: "${OWNER_URL:?set OWNER_URL to a postgres:// URL with owner rights}"

export PEEPHOLE_HOME
PEEPHOLE_HOME="$(mktemp -d)"
PEEPHOLE=(node dist/cli/main.js)

psql "$OWNER_URL" -v ON_ERROR_STOP=1 -q <<'SQL'
DROP TABLE IF EXISTS customers;
CREATE TABLE customers (id serial primary key, name text, email text, secret text);
INSERT INTO customers (name, email, secret) VALUES ('Ada', 'ada@example.com', 'hunter2');
SQL

printf 'customers.email\ncustomers.secret\n' > "$PEEPHOLE_HOME/hidden.txt"
"${PEEPHOLE[@]}" sql --role peephole_ro --hide-file "$PEEPHOLE_HOME/hidden.txt" \
  | psql "$OWNER_URL" -v ON_ERROR_STOP=1 -q
psql "$OWNER_URL" -q -c "ALTER ROLE peephole_ro PASSWORD 'ro-pass';"

RO_URL="$(node -e "const u=new URL(process.argv[1]);u.username='peephole_ro';u.password='ro-pass';u.searchParams.set('sslmode','disable');console.log(u.toString())" "$OWNER_URL")"
node -e "require('fs').writeFileSync(process.env.PEEPHOLE_HOME+'/config.json', JSON.stringify({targets:{ci:{url:process.argv[1]}}}))" "$RO_URL"

"${PEEPHOLE[@]}" open ci --no-network --reason "ci" --ttl 5m
"${PEEPHOLE[@]}" doctor ci

node scripts/smoke.mjs
"${PEEPHOLE[@]}" log -n 20
"${PEEPHOLE[@]}" close
psql "$OWNER_URL" -q -c "DROP TABLE IF EXISTS customers;"
echo "integration: OK"
