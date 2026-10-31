#!/usr/bin/env bash
# End-to-end check against a real Postgres. Used by CI; runs locally too:
#   OWNER_URL=postgres://postgres:postgres@localhost:5432/postgres scripts/ci-integration.sh
#
# 1. Create a table with a "secret" column, apply the generated role SQL hiding it.
# 2. Open a lease, run `daypass doctor` (login, role settings, write blocked, hidden columns).
# 3. Drive the MCP server: visible column OK, hidden column denied, writes blocked, expiry enforced.
# 4. `daypass hidden suggest|check` agree with the live catalog (as owner and as the read-only role).
# 5. Review 2026-10-30: views, matviews, partitions, inheritance children and SECURITY DEFINER
#    functions cannot leak a hidden column; a column added to a hidden table stops the re-run;
#    quoted identifiers and a second schema work end to end; doctor fails against the owner.
# 6. Round 2: whole-row views, definer functions outside --schemas, child-only hidden columns,
#    old default privileges, dropped schemas, views over unlisted schemas, per-database role
#    settings and CREATE on a schema.
#
# DAYPASS_CI_ROLE names the role (default daypass_ro); roles are cluster-wide, so use a unique
# name on a shared server.
set -euo pipefail
cd "$(dirname "$0")/.."
: "${OWNER_URL:?set OWNER_URL to a postgres:// URL with owner rights}"

export DAYPASS_HOME
DAYPASS_HOME="$(mktemp -d)"
DAYPASS=(node dist/cli/main.js)
# The read-only role under test. Roles are cluster-wide: on a shared server pick a unique name.
ROLE="${DAYPASS_CI_ROLE:-daypass_ro}"
[[ "$ROLE" =~ ^[a-z_][a-z0-9_]*$ ]] || { echo "DAYPASS_CI_ROLE must match ^[a-z_][a-z0-9_]*$"; exit 1; }

psql "$OWNER_URL" -v ON_ERROR_STOP=1 -q <<'SQL'
-- Postgres' default; an aborted earlier run of this script may have left it revoked.
SELECT format('GRANT TEMP ON DATABASE %I TO PUBLIC', current_database()) \gexec
DROP SCHEMA IF EXISTS analytics CASCADE;
DROP SCHEMA IF EXISTS ci_util CASCADE;
DROP TABLE IF EXISTS customers CASCADE;
DROP TABLE IF EXISTS "Order-Items", measurements, parent_t, later_t, later2_t, ruled_t, audit_t, parent2, derived_t, pub_w, seq_t, parent_p CASCADE;
DROP FUNCTION IF EXISTS public.secret_of(int) CASCADE;
DROP FUNCTION IF EXISTS public.run_it(text);
DROP VIEW IF EXISTS v_stat, v_auth, v_roles;
DROP MATERIALIZED VIEW IF EXISTS mv_xml, mv_plain_fn;
DROP SEQUENCE IF EXISTS seq_pub;
DROP SCHEMA IF EXISTS other_s CASCADE;
DROP SERVER IF EXISTS ci_files CASCADE;
DROP FUNCTION IF EXISTS leak_secret(int);
CREATE TABLE customers (id serial primary key, name text, email text, secret text);
INSERT INTO customers (name, email, secret) VALUES ('Ada', 'ada@example.com', 'hunter2');
-- Every other path a hidden column could leak through.
CREATE VIEW customer_secrets AS SELECT id, secret FROM customers;
CREATE VIEW customer_names AS SELECT id, name FROM customers;
CREATE VIEW customer_nested AS SELECT id FROM customer_secrets;
CREATE MATERIALIZED VIEW customer_mv AS SELECT id, email FROM customers;
CREATE MATERIALIZED VIEW customer_stats_mv AS SELECT id, length(name) AS name_len, 'x'::text AS city_code FROM customers;
CREATE TABLE measurements (id int, secret text, city text) PARTITION BY LIST (city);
CREATE TABLE measurements_a PARTITION OF measurements FOR VALUES IN ('a');
INSERT INTO measurements VALUES (1, 'partition-secret', 'a');
CREATE TABLE parent_t (id int, secret text);
CREATE TABLE child_t (extra int) INHERITS (parent_t);
INSERT INTO child_t VALUES (1, 'child-secret', 2);
CREATE TABLE "Order-Items" (id serial primary key, "ship.address" text, qty int);
INSERT INTO "Order-Items" ("ship.address", qty) VALUES ('1 Main St', 2);
CREATE SCHEMA analytics;
CREATE TABLE analytics.events (id serial primary key, kind text, user_email text);
INSERT INTO analytics.events (kind, user_email) VALUES ('signup', 'ada@example.com');
CREATE FUNCTION leak_secret(int) RETURNS text LANGUAGE sql SECURITY DEFINER AS $$ SELECT secret FROM customers WHERE id = $1 $$;
-- Review 2026-10-30 round 2.
-- C3: a whole-row reference records only a whole-relation dependency, yet returns every column.
CREATE VIEW customer_whole AS SELECT c FROM customers c;
CREATE VIEW customer_json AS SELECT row_to_json(c) AS j FROM customers c;
CREATE VIEW customer_count AS SELECT count(*) AS n FROM customers;
-- C4: a SECURITY DEFINER function in a schema that is not in --schemas, called through a view.
CREATE SCHEMA ci_util;
CREATE FUNCTION ci_util.leak2(int) RETURNS text LANGUAGE sql SECURITY DEFINER AS $$ SELECT secret FROM public.customers WHERE id = $1 $$;
CREATE VIEW customer_via_fn AS SELECT id, ci_util.leak2(id) AS s FROM customers;
-- I5: a view in public over a table in analytics; withheld when analytics is not in --schemas.
CREATE VIEW event_kinds AS SELECT kind FROM analytics.events;
-- M1: a non-SELECT rule that reads a hidden column does not make its table leak on SELECT.
CREATE TABLE audit_t (v text);
CREATE TABLE ruled_t (id int);
INSERT INTO ruled_t VALUES (7);
CREATE RULE ruled_log AS ON INSERT TO ruled_t DO ALSO INSERT INTO audit_t SELECT secret FROM customers;
SQL

cat > "$DAYPASS_HOME/hidden.txt" <<'EOF'
customers.email
customers.secret
measurements.secret
parent_t.secret
"Order-Items"."ship.address"
analytics.events.user_email
customer_stats_mv.city_code   # a matview column listed directly
EOF
SQLARGS=(sql --role $ROLE --schemas public,analytics)
# Fresh in CI; on a developer's database the role may survive an earlier run.
ROLE_EXISTED="$(psql "$OWNER_URL" -tA -c "select count(*) from pg_roles where rolname = '$ROLE'")"

# F2/F1(g): an executable SECURITY DEFINER function fails the self-check and names both remedies...
if "${DAYPASS[@]}" "${SQLARGS[@]}" --hide-file "$DAYPASS_HOME/hidden.txt" \
     | psql "$OWNER_URL" -v ON_ERROR_STOP=1 -q 2>"$DAYPASS_HOME/definer.err"; then
  echo "FAIL: setup must fail while leak_secret(int) is executable by the role"; exit 1
fi
grep -q 'leak_secret(integer)' "$DAYPASS_HOME/definer.err" || { echo "FAIL: definer error must name the function"; cat "$DAYPASS_HOME/definer.err"; exit 1; }
# C4: the check covers every schema, not only --schemas (a view in public can call ci_util.leak2).
grep -q 'ci_util.leak2(integer)' "$DAYPASS_HOME/definer.err" || { echo "FAIL: definer error must name ci_util.leak2 (outside --schemas)"; cat "$DAYPASS_HOME/definer.err"; exit 1; }
grep -q 'REVOKE EXECUTE ON FUNCTION' "$DAYPASS_HOME/definer.err" || { echo "FAIL: definer error must name the REVOKE remedy"; exit 1; }
grep -q -- '--allow-definer-functions' "$DAYPASS_HOME/definer.err" || { echo "FAIL: definer error must name the flag"; exit 1; }
[ "$ROLE_EXISTED" != 0 ] || [ "$(psql "$OWNER_URL" -tA -c "select count(*) from pg_roles where rolname = '$ROLE'")" = 0 ] \
  || { echo "FAIL: failed first run (definer) left the role behind"; exit 1; }
echo "definer function: setup refused, role not created"
# ...and passes once acknowledged.
"${DAYPASS[@]}" "${SQLARGS[@]}" --allow-definer-functions --hide-file "$DAYPASS_HOME/hidden.txt" \
  | psql "$OWNER_URL" -v ON_ERROR_STOP=1 -q 2>"$DAYPASS_HOME/definer-ack.err"
grep -q 'acknowledged (--allow-definer-functions)' "$DAYPASS_HOME/definer-ack.err" || { echo "FAIL: expected acknowledgement notice"; cat "$DAYPASS_HOME/definer-ack.err"; exit 1; }
echo "definer function: setup passes with --allow-definer-functions"
# The documented remedy: lock the function down, then the plain run passes.
psql "$OWNER_URL" -q -c "REVOKE EXECUTE ON FUNCTION leak_secret(int) FROM PUBLIC; REVOKE EXECUTE ON FUNCTION ci_util.leak2(int) FROM PUBLIC;"
"${DAYPASS[@]}" "${SQLARGS[@]}" --hide-file "$DAYPASS_HOME/hidden.txt" \
  | psql "$OWNER_URL" -v ON_ERROR_STOP=1 -q 2>"$DAYPASS_HOME/setup.err"
grep -q 'view public.customer_secrets exposes hidden column public.customers.secret' "$DAYPASS_HOME/setup.err" \
  || { echo "FAIL: expected a NOTICE naming the leaking view and column"; cat "$DAYPASS_HOME/setup.err"; exit 1; }
grep -q 'view public.customer_nested exposes hidden column public.customers.secret through view public.customer_secrets' "$DAYPASS_HOME/setup.err" \
  || { echo "FAIL: expected a NOTICE for the nested view"; cat "$DAYPASS_HOME/setup.err"; exit 1; }
grep -q 'view public.customer_mv exposes hidden column public.customers.email' "$DAYPASS_HOME/setup.err" \
  || { echo "FAIL: expected a NOTICE for the materialized view"; cat "$DAYPASS_HOME/setup.err"; exit 1; }
grep -q 'can create temp tables: yes' "$DAYPASS_HOME/setup.err" || { echo "FAIL: expected the TEMP report line"; exit 1; }
grep -q 'rds.restrict_password_commands' "$DAYPASS_HOME/setup.err" || { echo "FAIL: expected the RDS password note"; exit 1; }
echo "setup: OK (views withheld, TEMP and password notes printed)"
# Non-RDS owners set a password once after the first run; re-runs must keep it.
psql "$OWNER_URL" -q -c "ALTER ROLE $ROLE PASSWORD 'ro-pass';"

# `hidden --url` verifies TLS unless the URL says sslmode=disable; the CI Postgres has no TLS.
# A URL target needs a password even under trust auth; a dummy one is ignored by the server.
OWNER_NOSSL_URL="$(node -e "const u=new URL(process.argv[1]);if(!u.password)u.password='unused';u.searchParams.set('sslmode','disable');console.log(u.toString())" "$OWNER_URL")"
"${DAYPASS[@]}" hidden suggest --url "$OWNER_NOSSL_URL" --schemas public,analytics > "$DAYPASS_HOME/suggest.txt"
for want in '^customers.email$' '^customers.secret$' '^"Order-Items"."ship.address"$' '^analytics.events.user_email$' \
            '^measurements.secret$' '^parent_t.secret$'; do
  grep -q "$want" "$DAYPASS_HOME/suggest.txt" || { echo "FAIL: hidden suggest should print $want"; cat "$DAYPASS_HOME/suggest.txt"; exit 1; }
done
# The suggested list is minimal and directly applicable: partitions/children follow their parent,
# and a view over a listed column is withheld as a whole, so its columns are not listed.
for nope in '^measurements_a.secret$' '^child_t.secret$' '^customer_secrets.secret$' '^customer_mv.email$'; do
  if grep -q "$nope" "$DAYPASS_HOME/suggest.txt"; then echo "FAIL: hidden suggest should not print $nope"; cat "$DAYPASS_HOME/suggest.txt"; exit 1; fi
done
# ...and applying the suggestion as-is works.
grep -v '^#' "$DAYPASS_HOME/suggest.txt" > "$DAYPASS_HOME/hidden-suggested.txt"
"${DAYPASS[@]}" "${SQLARGS[@]}" --hide-file "$DAYPASS_HOME/hidden-suggested.txt" | psql "$OWNER_URL" -v ON_ERROR_STOP=1 -q 2>/dev/null
"${DAYPASS[@]}" "${SQLARGS[@]}" --hide-file "$DAYPASS_HOME/hidden.txt" | psql "$OWNER_URL" -v ON_ERROR_STOP=1 -q 2>/dev/null
echo "hidden suggest: canonical, minimal, directly applicable (quoted names, second schema, parents only)"
# F6: schema-qualified and quoted entries, F1(h): views over hidden columns are reported (informational).
"${DAYPASS[@]}" hidden check --file "$DAYPASS_HOME/hidden.txt" --url "$OWNER_NOSSL_URL" --schemas public,analytics > "$DAYPASS_HOME/check.out" 2>&1 \
  || { echo "FAIL: hidden check should pass on the applied list"; cat "$DAYPASS_HOME/check.out"; exit 1; }
grep -q 'view customer_secrets exposes hidden column customers.secret' "$DAYPASS_HOME/check.out" \
  || { echo "FAIL: hidden check should report the leaking view"; cat "$DAYPASS_HOME/check.out"; exit 1; }
grep -q 'view customer_nested exposes hidden column customers.secret through view customer_secrets' "$DAYPASS_HOME/check.out" \
  || { echo "FAIL: hidden check should follow nested views"; cat "$DAYPASS_HOME/check.out"; exit 1; }
grep -q 'hidden list matches the schema (7 hidden' "$DAYPASS_HOME/check.out" || { echo "FAIL: unexpected check summary"; cat "$DAYPASS_HOME/check.out"; exit 1; }
echo "hidden check: OK, view leaks reported"
printf 'customers.email\ncustomers.gone\n' > "$DAYPASS_HOME/hidden-bad.txt"
if "${DAYPASS[@]}" hidden check --file "$DAYPASS_HOME/hidden-bad.txt" --url "$OWNER_NOSSL_URL" >/dev/null; then
  echo "hidden check should exit 1 on a stale list"; exit 1
fi
printf 'customers.email\n!customers.email\n' > "$DAYPASS_HOME/hidden-conflict.txt"
if "${DAYPASS[@]}" hidden check --file "$DAYPASS_HOME/hidden-conflict.txt" --url "$OWNER_NOSSL_URL" > "$DAYPASS_HOME/conflict.out" 2>&1; then
  echo "FAIL: hidden check must exit 1 on a hidden+allowed conflict"; exit 1
fi
grep -q 'both hidden and !allowed' "$DAYPASS_HOME/conflict.out" && grep -q 'customers.email' "$DAYPASS_HOME/conflict.out" \
  || { echo "FAIL: hidden check should name the conflicting column"; cat "$DAYPASS_HOME/conflict.out"; exit 1; }
echo "hidden check: conflict reported"

RO_URL="$(node -e "const u=new URL(process.argv[1]);u.username='$ROLE';u.password='ro-pass';u.searchParams.set('sslmode','disable');console.log(u.toString())" "$OWNER_URL")"

# A failed re-run must change nothing. A stale entry (customers.gone) stops the script after the
# bulk GRANT SELECT ON ALL TABLES; without a transaction that leaves the hidden column readable.
priv() { psql "$OWNER_URL" -tA -c "SELECT has_column_privilege('$ROLE','customers','$1','SELECT')"; }
{ grep -v '^#' "$DAYPASS_HOME/hidden.txt"; echo 'customers.gone'; } > "$DAYPASS_HOME/hidden-stale.txt"
if "${DAYPASS[@]}" "${SQLARGS[@]}" --hide-file "$DAYPASS_HOME/hidden-stale.txt" \
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
"${DAYPASS[@]}" "${SQLARGS[@]}" --hide-file "$DAYPASS_HOME/hidden-stale.txt" \
  | psql "$OWNER_URL" -q >/dev/null 2>&1 || true
[ "$(priv secret)" = f ] && [ "$(priv name)" = t ] || { echo "FAIL: failed re-run without ON_ERROR_STOP changed privileges"; exit 1; }
psql "$RO_URL" -tA -c "select 1" >/dev/null || { echo "FAIL: failed re-run without ON_ERROR_STOP reset the password"; exit 1; }
echo "after failed re-run without ON_ERROR_STOP: secret=$(priv secret) name=$(priv name), password still works"

# A psqlrc with ON_ERROR_ROLLBACK=on would savepoint around the failing DO block and let COMMIT
# land the bulk GRANT; the script's own \set lines override it, so this still fails and changes nothing.
if "${DAYPASS[@]}" "${SQLARGS[@]}" --hide-file "$DAYPASS_HOME/hidden-stale.txt" \
     | psql "$OWNER_URL" -v ON_ERROR_ROLLBACK=on -q >/dev/null 2>&1; then
  echo "FAIL: stale-list run with ON_ERROR_ROLLBACK=on must exit non-zero"; exit 1
fi
[ "$(priv secret)" = f ] && [ "$(priv name)" = t ] || { echo "FAIL: ON_ERROR_ROLLBACK=on let the failed re-run change privileges"; exit 1; }
echo "after failed re-run with ON_ERROR_ROLLBACK=on: secret=$(priv secret) name=$(priv name)"

# The transaction covers the DO blocks and the \gexec line too: a failed FIRST run under a new
# role name leaves no role behind (CREATE ROLE and GRANT CONNECT both rolled back).
"${DAYPASS[@]}" sql --role ${ROLE}_never --schemas public,analytics --hide-file "$DAYPASS_HOME/hidden-stale.txt" \
  | psql "$OWNER_URL" -v ON_ERROR_STOP=1 -q >/dev/null 2>&1 || true
[ "$(psql "$OWNER_URL" -tA -c "select count(*) from pg_roles where rolname = '${ROLE}_never'")" = 0 ] \
  || { echo "FAIL: failed first run left the role behind (transaction does not cover CREATE ROLE)"; exit 1; }
echo "after failed first run: role ${ROLE}_never does not exist"

# A successful re-run keeps the password too.
"${DAYPASS[@]}" "${SQLARGS[@]}" --hide-file "$DAYPASS_HOME/hidden.txt" \
  | psql "$OWNER_URL" -v ON_ERROR_STOP=1 -q
psql "$RO_URL" -tA -c "select 1" >/dev/null || { echo "FAIL: successful re-run reset the role password"; exit 1; }
echo "after successful re-run: secret=$(priv secret) name=$(priv name), password still works"

# F1: as the role, every indirect path to a hidden column is denied; visible paths still work.
ro() { psql "$RO_URL" -tA -c "$1" 2>&1 || true; }
denied() { local out; out="$(ro "$1")"; grep -q 'permission denied' <<<"$out" || { echo "FAIL: role should be denied: $1"; echo "$out"; exit 1; }; }
allowed() { local out; out="$(ro "$1")"; grep -q "$2" <<<"$out" || { echo "FAIL: role should read '$2' from: $1"; echo "$out"; exit 1; }; }
denied "select secret from customer_secrets"            # view over a hidden column
denied "select id from customer_secrets"                # the whole view is withheld
denied "select id from customer_nested"                 # nested view
denied "select email from customer_mv"                  # materialized view over a hidden column
denied "select secret from measurements"                # partitioned parent
denied "select secret from measurements_a"              # partition
denied "select secret from parent_t"                    # inheritance parent
denied "select secret from child_t"                     # inheritance child
denied "select \"ship.address\" from \"Order-Items\""   # quoted identifiers
denied "select user_email from analytics.events"        # second schema
denied "select city_code from customer_stats_mv"        # matview column listed directly
denied "select leak_secret(1)"                          # SECURITY DEFINER function, locked down by the owner
allowed "select name from customer_names" Ada           # view over visible columns only
allowed "select name_len from customer_stats_mv" 3
allowed "select id from measurements_a" 1
allowed "select extra from child_t" 2
allowed "select qty from \"Order-Items\"" 2
allowed "select kind from analytics.events" signup
# C3: whole-row references (SELECT c, row_to_json(c)) reach every column; count(*) reaches none.
denied "select c from customer_whole"
denied "select j from customer_json"
allowed "select n from customer_count" 1
grep -q 'view public.customer_whole exposes' "$DAYPASS_HOME/setup.err" || { echo "FAIL: expected a NOTICE for the whole-row view"; cat "$DAYPASS_HOME/setup.err"; exit 1; }
# C4: the definer function outside --schemas is locked down, so the view calling it fails too.
denied "select s from customer_via_fn"
# M1: a table whose INSERT rule reads a hidden column is still an ordinary readable table.
allowed "select id from ruled_t" 7
# I5: with analytics in --schemas, a public view over it is granted...
allowed "select kind from event_kinds" signup
echo "role: views, matviews, partitions, children, quoted names, second schema and definer function all denied; visible paths readable"

# I4: dropping a schema from --schemas revokes what earlier runs granted there; I5: a view in a
# listed schema over a table in an unlisted one is withheld (its data is outside the listed schemas).
grep -v 'analytics\.' "$DAYPASS_HOME/hidden.txt" > "$DAYPASS_HOME/hidden-public.txt"
"${DAYPASS[@]}" sql --role $ROLE --schemas public --hide-file "$DAYPASS_HOME/hidden-public.txt" \
  | psql "$OWNER_URL" -v ON_ERROR_STOP=1 -q 2>"$DAYPASS_HOME/public-only.err"
denied "select kind from analytics.events"
denied "select kind from event_kinds"
grep -q 'view public.event_kinds reads analytics.events' "$DAYPASS_HOME/public-only.err" \
  || { echo "FAIL: expected a NOTICE naming the unlisted schema"; cat "$DAYPASS_HOME/public-only.err"; exit 1; }
[ "$(psql "$OWNER_URL" -tA -c "select has_schema_privilege('$ROLE','analytics','USAGE')")" = f ] \
  || { echo "FAIL: USAGE on analytics survived dropping it from --schemas"; exit 1; }
"${DAYPASS[@]}" "${SQLARGS[@]}" --hide-file "$DAYPASS_HOME/hidden.txt" | psql "$OWNER_URL" -v ON_ERROR_STOP=1 -q 2>/dev/null
allowed "select kind from analytics.events" signup
echo "schemas: dropping one from --schemas revokes it; views over unlisted schemas withheld"

# C2: hiding a column on a child/partition only would leave it readable through the parent
# (Postgres checks the parent's privileges for the child's rows), so the setup refuses it.
psql "$OWNER_URL" -q -c "CREATE TABLE parent2 (id int, secret text); CREATE TABLE child2 () INHERITS (parent2);"
{ grep -v '^#' "$DAYPASS_HOME/hidden.txt"; echo 'child2.secret'; } > "$DAYPASS_HOME/hidden-child.txt"
if "${DAYPASS[@]}" "${SQLARGS[@]}" --hide-file "$DAYPASS_HOME/hidden-child.txt" \
     | psql "$OWNER_URL" -v ON_ERROR_STOP=1 -q 2>"$DAYPASS_HOME/child.err"; then
  echo "FAIL: hiding only a child's column must fail"; exit 1
fi
grep -q 'parent2.secret' "$DAYPASS_HOME/child.err" || { echo "FAIL: expected the parent column to be named"; cat "$DAYPASS_HOME/child.err"; exit 1; }
psql "$OWNER_URL" -q -c "DROP TABLE parent2 CASCADE;"
echo "child-only hidden column: refused, parent named"

# F1(f): a table created after the run is invisible until the owner re-runs (no default privileges).
psql "$OWNER_URL" -q -c "CREATE TABLE later_t (id int); INSERT INTO later_t VALUES (1);"
denied "select id from later_t"
"${DAYPASS[@]}" "${SQLARGS[@]}" --hide-file "$DAYPASS_HOME/hidden.txt" | psql "$OWNER_URL" -v ON_ERROR_STOP=1 -q
allowed "select id from later_t" 1
echo "new table: invisible until re-run, visible after"

# C1: default privileges left by an older Daypass version (ALTER DEFAULT PRIVILEGES ... GRANT
# SELECT ON TABLES) are removed by a re-run, so a later table stays invisible.
psql "$OWNER_URL" -q -c "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO $ROLE;"
"${DAYPASS[@]}" "${SQLARGS[@]}" --hide-file "$DAYPASS_HOME/hidden.txt" | psql "$OWNER_URL" -v ON_ERROR_STOP=1 -q 2>/dev/null
[ "$(psql "$OWNER_URL" -tA -c "select count(*) from pg_default_acl d, aclexplode(d.defaclacl) a where a.grantee = (select oid from pg_roles where rolname = '$ROLE')")" = 0 ] \
  || { echo "FAIL: default privileges for the role survived a re-run"; exit 1; }
psql "$OWNER_URL" -q -c "CREATE TABLE later2_t (id int); INSERT INTO later2_t VALUES (1);"
denied "select id from later2_t"
psql "$OWNER_URL" -q -c "DROP TABLE later2_t;"
echo "old default privileges: removed by the re-run; a later table stays invisible"

# F5: a column added to a hidden table since the last run stops the re-run and names the column.
psql "$OWNER_URL" -q -c "ALTER TABLE customers ADD COLUMN newcol text;"
if "${DAYPASS[@]}" "${SQLARGS[@]}" --hide-file "$DAYPASS_HOME/hidden.txt" \
     | psql "$OWNER_URL" -v ON_ERROR_STOP=1 -q 2>"$DAYPASS_HOME/newcol.err"; then
  echo "FAIL: re-run must fail when a hidden table gained a column"; exit 1
fi
grep -q 'added since the last run' "$DAYPASS_HOME/newcol.err" && grep -q 'customers.newcol' "$DAYPASS_HOME/newcol.err" \
  || { echo "FAIL: expected the new column to be named"; cat "$DAYPASS_HOME/newcol.err"; exit 1; }
[ "$(priv newcol)" = f ] || { echo "FAIL: failed re-run exposed customers.newcol"; exit 1; }
echo "new column on a hidden table: re-run refused, column still hidden"
echo '!customers.newcol   # reviewed: nothing personal' >> "$DAYPASS_HOME/hidden.txt"
"${DAYPASS[@]}" "${SQLARGS[@]}" --hide-file "$DAYPASS_HOME/hidden.txt" | psql "$OWNER_URL" -v ON_ERROR_STOP=1 -q
[ "$(priv newcol)" = t ] || { echo "FAIL: !customers.newcol should make the column readable"; exit 1; }
[ "$(priv secret)" = f ] || { echo "FAIL: customers.secret must stay hidden"; exit 1; }
echo "after !customers.newcol: newcol=$(priv newcol) secret=$(priv secret)"

# F6: a PUBLIC grant on a hidden table is refused with the fix named.
psql "$OWNER_URL" -q -c "GRANT SELECT ON customers TO PUBLIC;"
if "${DAYPASS[@]}" "${SQLARGS[@]}" --hide-file "$DAYPASS_HOME/hidden.txt" \
     | psql "$OWNER_URL" -v ON_ERROR_STOP=1 -q 2>"$DAYPASS_HOME/public.err"; then
  echo "FAIL: setup must refuse a PUBLIC grant on a hidden table"; exit 1
fi
grep -q 'REVOKE SELECT ON public.customers FROM PUBLIC' "$DAYPASS_HOME/public.err" || { echo "FAIL: expected the REVOKE fix"; cat "$DAYPASS_HOME/public.err"; exit 1; }
psql "$OWNER_URL" -q -c "REVOKE SELECT ON customers FROM PUBLIC;"
echo "PUBLIC grant on a hidden table: refused with the fix named"

# F2: the role can switch its own session out of read-only and, with PUBLIC's TEMP, create temp
# tables; --revoke-public-temp removes that and the report says so.
# Separate -c flags: one session, one transaction each, so the SET applies to the CREATE.
TEMP_OUT="$(psql "$RO_URL" -tA -c "set default_transaction_read_only = off" -c "create temp table t_probe(x int)" -c "select 42" 2>&1 || true)"
grep -q '^42$' <<<"$TEMP_OUT" || { echo "FAIL: with PUBLIC's TEMP the role should be able to create a temp table"; echo "$TEMP_OUT"; exit 1; }
"${DAYPASS[@]}" "${SQLARGS[@]}" --revoke-public-temp --hide-file "$DAYPASS_HOME/hidden.txt" \
  | psql "$OWNER_URL" -v ON_ERROR_STOP=1 -q 2>"$DAYPASS_HOME/temp.err"
grep -q 'can create temp tables: no' "$DAYPASS_HOME/temp.err" || { echo "FAIL: expected TEMP=false after --revoke-public-temp"; cat "$DAYPASS_HOME/temp.err"; exit 1; }
TEMP_OUT="$(psql "$RO_URL" -tA -c "set default_transaction_read_only = off" -c "create temp table t_probe(x int)" 2>&1 || true)"
grep -q 'permission denied' <<<"$TEMP_OUT" || { echo "FAIL: role should not create temp tables now"; echo "$TEMP_OUT"; exit 1; }
psql "$OWNER_URL" -q -c "GRANT TEMP ON DATABASE $(psql "$OWNER_URL" -tA -c 'select quote_ident(current_database())') TO PUBLIC;"
echo "--revoke-public-temp: role cannot create temp tables"

# ---- Review 2026-10-30 round 3 -------------------------------------------------------------
setup_fails() { # setup_fails <errfile> <hidden file> [extra sql args...]: the run must exit non-zero
  local err="$1" list="$2"; shift 2
  if "${DAYPASS[@]}" "${SQLARGS[@]}" "$@" --hide-file "$list" | psql "$OWNER_URL" -v ON_ERROR_STOP=1 -q 2>"$err" >/dev/null; then
    echo "FAIL: setup should have failed ($err)"; cat "$err"; exit 1
  fi
}
setup_ok() { "${DAYPASS[@]}" "${SQLARGS[@]}" --hide-file "${1:-$DAYPASS_HOME/hidden.txt}" | psql "$OWNER_URL" -v ON_ERROR_STOP=1 -q 2>"${2:-/dev/null}" >/dev/null; }
need() { grep -q -- "$2" "$1" || { echo "FAIL: expected '$2' in $1"; cat "$1"; exit 1; }; }

# C1: search_path hijack. A role with CREATE on a schema in the owner's search_path plants an
# operator that the setup's own expressions would resolve to, running as the owner. The setup
# pins search_path to pg_catalog, so the plant never runs, and refuses a role that owns objects.
psql "$OWNER_URL" -q -c "GRANT CREATE ON SCHEMA public TO $ROLE;"
psql "$RO_URL" -q -c "set default_transaction_read_only = off" \
  -c "CREATE FUNCTION public.ro_cat(oid, text) RETURNS text LANGUAGE plpgsql AS \$\$BEGIN RAISE NOTICE 'HIJACKED as %', current_user; RETURN \$1::text || \$2; END\$\$;" \
  -c "CREATE OPERATOR public.|| (LEFTARG = oid, RIGHTARG = text, FUNCTION = public.ro_cat);"
setup_fails "$DAYPASS_HOME/hijack.err" "$DAYPASS_HOME/hidden.txt"
if grep -q HIJACKED "$DAYPASS_HOME/hijack.err"; then echo "FAIL: the planted operator ran as the owner"; cat "$DAYPASS_HOME/hijack.err"; exit 1; fi
need "$DAYPASS_HOME/hijack.err" "owns objects in this database"
need "$DAYPASS_HOME/hijack.err" "DROP OWNED BY"
psql "$OWNER_URL" -q -c "DROP OWNED BY $ROLE; REVOKE CREATE ON SCHEMA public FROM $ROLE;"
setup_ok
echo "search_path hijack: plant never ran, role-owned objects refused"

# C2: a generated column derived from a hidden column is refused until it is listed too;
# catalog text that mentions a hidden column (default, CHECK, partial index) is reported.
psql "$OWNER_URL" -q -c "CREATE TABLE derived_t (id int primary key, secret text DEFAULT 'zz-default' CHECK (secret <> 'hunter2'), hint text GENERATED ALWAYS AS (left(secret, 2)) STORED); CREATE INDEX derived_t_part ON derived_t (id) WHERE secret = 'x'; INSERT INTO derived_t (id, secret) VALUES (1, 'gen-secret'); CREATE VIEW derived_v AS SELECT id, hint FROM derived_t;"
{ grep -v '^#' "$DAYPASS_HOME/hidden.txt"; echo 'derived_t.secret'; } > "$DAYPASS_HOME/hidden-derived.txt"
setup_fails "$DAYPASS_HOME/derived.err" "$DAYPASS_HOME/hidden-derived.txt"
need "$DAYPASS_HOME/derived.err" "public.derived_t.hint (generated from public.derived_t.secret)"
if "${DAYPASS[@]}" hidden check --file "$DAYPASS_HOME/hidden-derived.txt" --url "$OWNER_NOSSL_URL" --schemas public,analytics > "$DAYPASS_HOME/derived-check.out" 2>&1; then
  echo "FAIL: hidden check must flag the generated column"; cat "$DAYPASS_HOME/derived-check.out"; exit 1
fi
need "$DAYPASS_HOME/derived-check.out" "derived_t.hint (generated from derived_t.secret)"
echo 'derived_t.hint' >> "$DAYPASS_HOME/hidden-derived.txt"
setup_ok "$DAYPASS_HOME/hidden-derived.txt" "$DAYPASS_HOME/derived2.err"
need "$DAYPASS_HOME/derived2.err" "catalog text: default value for column secret of table public.derived_t mentions hidden column public.derived_t.secret"
need "$DAYPASS_HOME/derived2.err" "catalog text: constraint derived_t_secret_check on table public.derived_t mentions hidden column"
need "$DAYPASS_HOME/derived2.err" "catalog text: index public.derived_t_part mentions hidden column"
denied "select hint from derived_t"
denied "select hint from derived_v"
allowed "select id from derived_t" 1
psql "$OWNER_URL" -q -c "DROP TABLE derived_t CASCADE;"
setup_ok
echo "generated column: refused until listed; catalog text reported"

# C3: membership in another role is refused (SET ROLE would use its privileges; NOINHERIT does not stop that).
psql "$OWNER_URL" -q -c "CREATE ROLE ${ROLE}_app NOLOGIN; GRANT SELECT ON customers TO ${ROLE}_app; GRANT ${ROLE}_app TO $ROLE;"
setup_fails "$DAYPASS_HOME/member.err" "$DAYPASS_HOME/hidden.txt"
need "$DAYPASS_HOME/member.err" "is a member of ${ROLE}_app"
psql "$OWNER_URL" -q -c "REVOKE ${ROLE}_app FROM $ROLE; DROP OWNED BY ${ROLE}_app; DROP ROLE ${ROLE}_app;"
echo "membership in another role: refused"

# C4: a PUBLIC grant in a schema that is not in --schemas is still readable: refused.
psql "$OWNER_URL" -q -c "CREATE SCHEMA other_s; GRANT USAGE ON SCHEMA other_s TO PUBLIC; CREATE TABLE other_s.leak (secret text); GRANT SELECT ON other_s.leak TO PUBLIC;"
setup_fails "$DAYPASS_HOME/other.err" "$DAYPASS_HOME/hidden.txt"
need "$DAYPASS_HOME/other.err" "other_s.leak"
psql "$OWNER_URL" -q -c "DROP SCHEMA other_s CASCADE;"
echo "PUBLIC grant outside --schemas: refused"

# Writes the role could make once it turns read-only off: a PUBLIC INSERT grant, nextval through
# PUBLIC USAGE on a sequence. Both refused.
psql "$OWNER_URL" -q -c "CREATE TABLE pub_w (id int); GRANT INSERT ON pub_w TO PUBLIC; CREATE SEQUENCE seq_pub; GRANT USAGE ON SEQUENCE seq_pub TO PUBLIC;"
setup_fails "$DAYPASS_HOME/writes.err" "$DAYPASS_HOME/hidden.txt"
need "$DAYPASS_HOME/writes.err" "public.pub_w"
need "$DAYPASS_HOME/writes.err" "public.seq_pub"
psql "$OWNER_URL" -q -c "DROP TABLE pub_w; DROP SEQUENCE seq_pub;"
echo "PUBLIC write grants: refused"

# C5: foreign tables. Their columns can be listed; they are never granted, and a view over one
# is withheld (it reads data the role is not granted, with the view owner's user mapping).
if psql "$OWNER_URL" -q -c "CREATE EXTENSION IF NOT EXISTS file_fdw;" 2>/dev/null; then
  psql "$OWNER_URL" -q -c "CREATE SERVER ci_files FOREIGN DATA WRAPPER file_fdw; CREATE FOREIGN TABLE ext_events (id int, label text) SERVER ci_files OPTIONS (filename '/dev/null', format 'csv'); CREATE VIEW ext_view AS SELECT id FROM ext_events;"
  { grep -v '^#' "$DAYPASS_HOME/hidden.txt"; echo 'ext_events.label'; } > "$DAYPASS_HOME/hidden-ft.txt"
  setup_ok "$DAYPASS_HOME/hidden-ft.txt" "$DAYPASS_HOME/ft.err"
  need "$DAYPASS_HOME/ft.err" "view public.ext_view reads foreign table public.ext_events"
  denied "select id from ext_events"
  denied "select id from ext_view"
  psql "$OWNER_URL" -q -c "DROP SERVER ci_files CASCADE; DROP EXTENSION file_fdw;"
  setup_ok
  echo "foreign tables: listable, never granted, views over them withheld"
else
  echo "SKIP: file_fdw not available, foreign-table case not run"
fi

# ---- Review 2026-10-30 round 4 -------------------------------------------------------------
# 1: a materialized view stores what its query returned when the OWNER refreshed it, so a
# function it calls (or a data-reading built-in such as query_to_xml) reads as the owner.
# Withheld; a matview calling only plain built-ins (upper) is fine.
psql "$OWNER_URL" -q -c "CREATE FUNCTION public.secret_of(int) RETURNS text LANGUAGE sql STABLE AS 'SELECT secret FROM public.customers WHERE id = \$1'; CREATE MATERIALIZED VIEW mv_fn AS SELECT id, public.secret_of(id) AS s FROM customers; CREATE MATERIALIZED VIEW mv_xml AS SELECT query_to_xml('select secret from public.customers', true, false, '') AS x; CREATE MATERIALIZED VIEW mv_plain_fn AS SELECT id, upper(name) AS n FROM customers;"
setup_ok "$DAYPASS_HOME/hidden.txt" "$DAYPASS_HOME/mvfn.err"
need "$DAYPASS_HOME/mvfn.err" "view public.mv_fn calls function public.secret_of(integer)"
need "$DAYPASS_HOME/mvfn.err" "view public.mv_xml calls function pg_catalog.query_to_xml("
denied "select s from mv_fn"
denied "select x from mv_xml"
allowed "select n from mv_plain_fn" ADA
"${DAYPASS[@]}" hidden check --file "$DAYPASS_HOME/hidden.txt" --url "$OWNER_NOSSL_URL" --schemas public,analytics > "$DAYPASS_HOME/mvfn-check.out" 2>&1 || true
need "$DAYPASS_HOME/mvfn-check.out" "view mv_fn calls function public.secret_of"
need "$DAYPASS_HOME/mvfn-check.out" "view mv_xml calls function pg_catalog.query_to_xml"
psql "$OWNER_URL" -q -c "DROP MATERIALIZED VIEW mv_fn, mv_xml, mv_plain_fn; DROP FUNCTION public.secret_of(int);"
echo "matviews calling functions: withheld"

# 2: a view over a catalog the role cannot read itself (pg_statistic holds column values,
# pg_authid password hashes) would read it with the owner's rights. Withheld; a view over a
# readable catalog view (pg_roles) is fine.
psql "$OWNER_URL" -q -c "CREATE VIEW v_stat AS SELECT starelid, stavalues1::text AS vals FROM pg_catalog.pg_statistic; CREATE VIEW v_auth AS SELECT rolname, rolpassword FROM pg_catalog.pg_authid; CREATE VIEW v_roles AS SELECT rolname FROM pg_catalog.pg_roles;"
setup_ok "$DAYPASS_HOME/hidden.txt" "$DAYPASS_HOME/cat.err"
need "$DAYPASS_HOME/cat.err" "view public.v_stat reads pg_catalog.pg_statistic, which the role cannot read itself"
need "$DAYPASS_HOME/cat.err" "view public.v_auth reads pg_catalog.pg_authid, which the role cannot read itself"
denied "select vals from v_stat"
denied "select rolpassword from v_auth"
allowed "select rolname from v_roles" "$ROLE"
"${DAYPASS[@]}" hidden check --file "$DAYPASS_HOME/hidden.txt" --url "$OWNER_NOSSL_URL" --schemas public,analytics > "$DAYPASS_HOME/cat-check.out" 2>&1 || true
need "$DAYPASS_HOME/cat-check.out" "view v_auth reads pg_catalog.pg_authid"
psql "$OWNER_URL" -q -c "DROP VIEW v_stat, v_auth, v_roles;"
echo "views over restricted catalogs: withheld"

# Sequences owned by a hidden column (serial / identity) are not granted: last_value would tell
# how many rows exist and the latest value.
psql "$OWNER_URL" -q -c "CREATE TABLE seq_t (id int, ticket serial); INSERT INTO seq_t (id) VALUES (1);"
{ grep -v '^#' "$DAYPASS_HOME/hidden.txt"; echo 'seq_t.ticket'; } > "$DAYPASS_HOME/hidden-seq.txt"
setup_ok "$DAYPASS_HOME/hidden-seq.txt"
denied "select last_value from seq_t_ticket_seq"
allowed "select id from seq_t" 1
psql "$OWNER_URL" -q -c "DROP TABLE seq_t;"
echo "sequence owned by a hidden column: not granted"

# A comment on the role that is not Daypass's own is reported before the setup replaces it.
psql "$OWNER_URL" -q -c "COMMENT ON ROLE $ROLE IS 'a human note';"
setup_ok "$DAYPASS_HOME/hidden.txt" "$DAYPASS_HOME/comment.err"
need "$DAYPASS_HOME/comment.err" "replacing the comment on role $ROLE"
echo "role comment: replacement reported"

node -e "require('fs').writeFileSync(process.env.DAYPASS_HOME+'/config.json', JSON.stringify({targets:{ci:{url:process.argv[1],schemas:['public','analytics']},owner:{url:process.argv[2],schemas:['public','analytics']}}}))" "$RO_URL" "$OWNER_NOSSL_URL"

# F3/F4: doctor against the owner (superuser, no role settings) must FAIL on role settings and write blocked.
"${DAYPASS[@]}" open owner --no-network --reason "ci owner" --ttl 5m
if "${DAYPASS[@]}" doctor owner > "$DAYPASS_HOME/doctor-owner.out" 2>&1; then
  echo "FAIL: doctor must exit 1 against the owner"; cat "$DAYPASS_HOME/doctor-owner.out"; exit 1
fi
grep -q '✖ role settings' "$DAYPASS_HOME/doctor-owner.out" || { echo "FAIL: doctor owner should fail 'role settings'"; cat "$DAYPASS_HOME/doctor-owner.out"; exit 1; }
grep -q '✖ write blocked' "$DAYPASS_HOME/doctor-owner.out" || { echo "FAIL: doctor owner should fail 'write blocked'"; cat "$DAYPASS_HOME/doctor-owner.out"; exit 1; }
# No hidden list stored on that role and none given: nothing proves the columns are hidden.
need "$DAYPASS_HOME/doctor-owner.out" "✖ hidden columns.*no hidden list"
cat "$DAYPASS_HOME/doctor-owner.out"
"${DAYPASS[@]}" close
echo "doctor owner: fails as it should"

# Drift: the role changed its own defaults; doctor names the setting.
# ...which the role can do for itself (F3), which is why doctor has to check.
psql "$RO_URL" -q -c "set default_transaction_read_only = off" -c "ALTER ROLE $ROLE SET statement_timeout = '1h';" -c "ALTER ROLE $ROLE SET search_path = public;"
"${DAYPASS[@]}" open ci --no-network --reason "ci" --ttl 5m
if "${DAYPASS[@]}" doctor ci > "$DAYPASS_HOME/doctor-drift.out" 2>&1; then
  echo "FAIL: doctor must exit 1 when a role setting drifted"; cat "$DAYPASS_HOME/doctor-drift.out"; exit 1
fi
grep -q '✖ role settings.*statement_timeout' "$DAYPASS_HOME/doctor-drift.out" || { echo "FAIL: doctor should name statement_timeout"; cat "$DAYPASS_HOME/doctor-drift.out"; exit 1; }
grep -q '✖ role settings.*search_path=public (not set by the setup)' "$DAYPASS_HOME/doctor-drift.out" || { echo "FAIL: doctor should flag an extra role setting"; cat "$DAYPASS_HOME/doctor-drift.out"; exit 1; }
"${DAYPASS[@]}" close
echo "doctor drift: statement_timeout named"

# I3: a per-database setting overrides the role-level one, the role can set it for itself, and
# pg_roles.rolconfig does not show it. Doctor reads pg_db_role_setting; a re-run resets it.
DBNAME="$(psql "$OWNER_URL" -tA -c 'select quote_ident(current_database())')"
psql "$RO_URL" -q -c "set default_transaction_read_only = off" -c "ALTER ROLE $ROLE IN DATABASE $DBNAME SET default_transaction_read_only = off;"
"${DAYPASS[@]}" open ci --no-network --reason "ci" --ttl 5m
if "${DAYPASS[@]}" doctor ci > "$DAYPASS_HOME/doctor-perdb.out" 2>&1; then
  echo "FAIL: doctor must exit 1 on a per-database role setting"; cat "$DAYPASS_HOME/doctor-perdb.out"; exit 1
fi
grep -q '✖ role settings.*default_transaction_read_only=off (in database' "$DAYPASS_HOME/doctor-perdb.out" \
  || { echo "FAIL: doctor should name the per-database setting"; cat "$DAYPASS_HOME/doctor-perdb.out"; exit 1; }
"${DAYPASS[@]}" close
"${DAYPASS[@]}" "${SQLARGS[@]}" --hide-file "$DAYPASS_HOME/hidden.txt" | psql "$OWNER_URL" -v ON_ERROR_STOP=1 -q
[ "$(psql "$OWNER_URL" -tA -c "select count(*) from pg_db_role_setting where setdatabase <> 0 and setrole = (select oid from pg_roles where rolname = '$ROLE')")" = 0 ] \
  || { echo "FAIL: re-run must reset per-database settings of the role"; exit 1; }
echo "per-database role setting: doctor names it, re-run resets it"

# I2: CREATE on a schema lets the role make tables, views and functions (PUBLIC holds it on
# public up to PG 14 and on databases upgraded from there). Doctor fails on it; the setup
# reports it and --revoke-public-create removes it.
PUBLIC_CREATE_BEFORE="$(psql "$OWNER_URL" -tA -c "select has_schema_privilege('public','public','CREATE')")"
psql "$OWNER_URL" -q -c "GRANT CREATE ON SCHEMA public TO PUBLIC;"
"${DAYPASS[@]}" "${SQLARGS[@]}" --hide-file "$DAYPASS_HOME/hidden.txt" | psql "$OWNER_URL" -v ON_ERROR_STOP=1 -q 2>"$DAYPASS_HOME/create.err"
grep -q 'can create objects in schema(s) public' "$DAYPASS_HOME/create.err" || { echo "FAIL: expected the CREATE report line"; cat "$DAYPASS_HOME/create.err"; exit 1; }
"${DAYPASS[@]}" open ci --no-network --reason "ci" --ttl 5m
if "${DAYPASS[@]}" doctor ci > "$DAYPASS_HOME/doctor-create.out" 2>&1; then
  echo "FAIL: doctor must exit 1 when the role can CREATE in a schema"; cat "$DAYPASS_HOME/doctor-create.out"; exit 1
fi
grep -q '✖ write blocked.*CREATE on schema public' "$DAYPASS_HOME/doctor-create.out" \
  || { echo "FAIL: doctor should name CREATE on public"; cat "$DAYPASS_HOME/doctor-create.out"; exit 1; }
"${DAYPASS[@]}" close
"${DAYPASS[@]}" "${SQLARGS[@]}" --revoke-public-create --hide-file "$DAYPASS_HOME/hidden.txt" | psql "$OWNER_URL" -v ON_ERROR_STOP=1 -q 2>"$DAYPASS_HOME/create2.err"
grep -q 'can create objects in schema(s): none' "$DAYPASS_HOME/create2.err" || { echo "FAIL: expected no CREATE after --revoke-public-create"; cat "$DAYPASS_HOME/create2.err"; exit 1; }
CREATE_OUT="$(psql "$RO_URL" -tA -c "set default_transaction_read_only = off" -c "create table public.ro_probe(x int)" 2>&1 || true)"
grep -q 'permission denied' <<<"$CREATE_OUT" || { echo "FAIL: role should not create tables in public now"; echo "$CREATE_OUT"; exit 1; }
echo "CREATE on schema: reported, doctor fails, --revoke-public-create removes it"

# Round 3: doctor knows the hidden list (the setup stores it on the role) and fails on a readable
# hidden column, an executable SECURITY DEFINER function and a write grant made after the setup.
psql "$OWNER_URL" -q -c "GRANT SELECT (secret) ON customers TO $ROLE; GRANT EXECUTE ON FUNCTION leak_secret(int) TO $ROLE; GRANT UPDATE ON ruled_t TO PUBLIC;"
# Round 4: a hidden table attached under a readable parent after the setup leaks through the parent.
psql "$OWNER_URL" -q -c "CREATE TABLE parent_p (secret text); GRANT SELECT ON parent_p TO $ROLE; ALTER TABLE customers INHERIT parent_p;"
"${DAYPASS[@]}" open ci --no-network --reason "ci" --ttl 5m
if "${DAYPASS[@]}" doctor ci > "$DAYPASS_HOME/doctor-leak.out" 2>&1; then
  echo "FAIL: doctor must exit 1 on a readable hidden column"; cat "$DAYPASS_HOME/doctor-leak.out"; exit 1
fi
need "$DAYPASS_HOME/doctor-leak.out" "✖ hidden columns.*customers.secret"
need "$DAYPASS_HOME/doctor-leak.out" "✖ definer functions.*leak_secret(integer)"
need "$DAYPASS_HOME/doctor-leak.out" "✖ write blocked.*ruled_t"
need "$DAYPASS_HOME/doctor-leak.out" "✖ hidden columns.*parent_p.secret (parent of customers)"
"${DAYPASS[@]}" close
psql "$OWNER_URL" -q -c "REVOKE EXECUTE ON FUNCTION leak_secret(int) FROM $ROLE; REVOKE UPDATE ON ruled_t FROM PUBLIC; ALTER TABLE customers NO INHERIT parent_p; DROP TABLE parent_p;"
"${DAYPASS[@]}" "${SQLARGS[@]}" --hide-file "$DAYPASS_HOME/hidden.txt" | psql "$OWNER_URL" -v ON_ERROR_STOP=1 -q 2>/dev/null
echo "doctor: readable hidden column, definer function and write grant all fail"

# Round 4: the role cannot fool doctor with look-alike catalog objects on its own search_path.
psql "$OWNER_URL" -q -c "GRANT CREATE ON SCHEMA public TO $ROLE;"
psql "$RO_URL" -q -c "set default_transaction_read_only = off" \
  -c "CREATE VIEW public.pg_roles AS SELECT r.oid, r.rolname, ARRAY['default_transaction_read_only=on','statement_timeout=10s','idle_in_transaction_session_timeout=30s','lock_timeout=1s','temp_file_limit=256MB']::text[] AS rolconfig, false AS rolsuper, false AS rolcreaterole, false AS rolcreatedb FROM pg_catalog.pg_roles r" \
  -c "CREATE VIEW public.pg_shdepend AS SELECT * FROM pg_catalog.pg_shdepend WHERE false" \
  -c "CREATE FUNCTION public.has_schema_privilege(name, oid, text) RETURNS boolean LANGUAGE sql AS 'select false'" \
  -c "ALTER ROLE $ROLE SET search_path = public, pg_catalog" -c "ALTER ROLE $ROLE SET statement_timeout = '1h'"
"${DAYPASS[@]}" open ci --no-network --reason "ci" --ttl 5m
if "${DAYPASS[@]}" doctor ci > "$DAYPASS_HOME/doctor-spoof.out" 2>&1; then
  echo "FAIL: doctor must see through spoofed catalog objects"; cat "$DAYPASS_HOME/doctor-spoof.out"; exit 1
fi
need "$DAYPASS_HOME/doctor-spoof.out" "✖ role settings.*statement_timeout=1h"
need "$DAYPASS_HOME/doctor-spoof.out" "✖ write blocked.*CREATE on schema public"
need "$DAYPASS_HOME/doctor-spoof.out" "✖ write blocked.*owns 3 object"
"${DAYPASS[@]}" close
psql "$OWNER_URL" -q -c "DROP OWNED BY $ROLE; REVOKE CREATE ON SCHEMA public FROM $ROLE;"
"${DAYPASS[@]}" "${SQLARGS[@]}" --hide-file "$DAYPASS_HOME/hidden.txt" | psql "$OWNER_URL" -v ON_ERROR_STOP=1 -q 2>/dev/null
echo "doctor: spoofed pg_roles / pg_shdepend / has_schema_privilege do not hide drift"

# Functions are EXECUTE-to-PUBLIC by default: one taking SQL text runs whatever it is handed,
# out of the guard's sight. Doctor lists them as a warning; the setup report counts them.
psql "$OWNER_URL" -q -c "CREATE FUNCTION public.run_it(query text) RETURNS int LANGUAGE plpgsql AS \$\$BEGIN RETURN 1; END\$\$;"
"${DAYPASS[@]}" "${SQLARGS[@]}" --hide-file "$DAYPASS_HOME/hidden.txt" | psql "$OWNER_URL" -v ON_ERROR_STOP=1 -q 2>"$DAYPASS_HOME/fns.err" >/dev/null
need "$DAYPASS_HOME/fns.err" "can execute 1 function(s) outside pg_catalog"
need "$DAYPASS_HOME/fns.err" "REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA"
"${DAYPASS[@]}" open ci --no-network --reason "ci" --ttl 5m
"${DAYPASS[@]}" doctor ci > "$DAYPASS_HOME/doctor-fns.out" 2>&1 || true
need "$DAYPASS_HOME/doctor-fns.out" "✔ functions.*runs SQL from a string: public.run_it(query text)"
"${DAYPASS[@]}" close
psql "$OWNER_URL" -q -c "DROP FUNCTION public.run_it(text);"
echo "functions taking SQL text: reported (warning)"

"${DAYPASS[@]}" open ci --no-network --reason "ci" --ttl 5m
"${DAYPASS[@]}" doctor ci | tee "$DAYPASS_HOME/doctor.out"
for want in '✔ role settings' '✔ write blocked' '✔ other schemas' '✔ hidden columns   7 listed' '✔ definer functions'; do
  grep -q "$want" "$DAYPASS_HOME/doctor.out" || { echo "FAIL: doctor should print '$want'"; exit 1; }
done
# pg_catalog lists hidden columns regardless of grants, so the read-only role sees the same picture.
"${DAYPASS[@]}" hidden check --file "$DAYPASS_HOME/hidden.txt" --live ci

node scripts/smoke.mjs
"${DAYPASS[@]}" log -n 20
"${DAYPASS[@]}" close
psql "$OWNER_URL" -q <<'SQL'
DROP SCHEMA IF EXISTS analytics CASCADE;
DROP SCHEMA IF EXISTS ci_util CASCADE;
DROP TABLE IF EXISTS customers CASCADE;
DROP TABLE IF EXISTS "Order-Items", measurements, parent_t, later_t, later2_t, ruled_t, audit_t, parent2, derived_t, pub_w, seq_t, parent_p CASCADE;
DROP FUNCTION IF EXISTS public.secret_of(int) CASCADE;
DROP FUNCTION IF EXISTS public.run_it(text);
DROP VIEW IF EXISTS v_stat, v_auth, v_roles;
DROP MATERIALIZED VIEW IF EXISTS mv_xml, mv_plain_fn;
DROP SEQUENCE IF EXISTS seq_pub;
DROP SCHEMA IF EXISTS other_s CASCADE;
DROP SERVER IF EXISTS ci_files CASCADE;
DROP FUNCTION IF EXISTS leak_secret(int);
SQL
# Put PUBLIC's CREATE on public back the way it was (the I2 case revoked it).
if [ "$PUBLIC_CREATE_BEFORE" = t ]; then psql "$OWNER_URL" -q -c "GRANT CREATE ON SCHEMA public TO PUBLIC;"; fi
echo "integration: OK"
