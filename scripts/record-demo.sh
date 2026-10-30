#!/usr/bin/env bash
# Records the README demo (docs/assets/demo.gif) with vhs against a throwaway Postgres in Docker.
#
#   scripts/record-demo.sh                 # record docs/assets/demo.gif from docs/assets/demo.tape
#   scripts/record-demo.sh --transcript    # run the same six commands and print their output instead
#                                          # (used for docs/assets/demo-output.txt, the reduced-motion
#                                          # and screen-reader fallback on the website)
#
# The scene is the one scripts/ci-integration.sh uses: a `customers` table whose `email` and
# `secret` columns are hidden from the daypass_ro role, exposed as a target named "prod" (URL
# form, password auth). Everything lives in a temp dir: an isolated DAYPASS_HOME, and a `daypass`
# wrapper on PATH so the recording shows the bare command. Nothing from ~/.daypass is read. The
# identity written to the lease is "dev@laptop" (USER from the environment; os.hostname() patched
# by a preload shim) so no real user or machine name lands in the GIF. Re-runnable: it replaces the
# container, and the EXIT trap removes the container and the temp dir.
#
# Needs: docker, psql/pg_isready, node (dist built), and vhs (`brew install vhs`) unless --transcript.
set -euo pipefail
cd "$(dirname "$0")/.."
REPO="$PWD"

MODE=record
[ "${1:-}" = "--transcript" ] && MODE=transcript

PORT="${DEMO_PG_PORT:-5439}"
CONTAINER=daypass-demo-pg
OWNER_URL="postgres://postgres:postgres@localhost:$PORT/postgres"

say() { echo "record-demo: $*" >&2; }

if [ "$MODE" = record ] && ! command -v vhs >/dev/null; then
  say "vhs not found (brew install vhs)"; exit 1
fi
[ -f dist/cli/main.js ] || { say "building dist"; npm run build >&2; }

DEMO_DIR="$(mktemp -d /tmp/daypass-demo.XXXXXX)"
cleanup() {
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  rm -rf "$DEMO_DIR"
}
trap cleanup EXIT

# --- database ---------------------------------------------------------------------------------
docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
say "starting $CONTAINER on port $PORT"
docker run --rm -d --name "$CONTAINER" -e POSTGRES_PASSWORD=postgres -p "$PORT:5432" postgres:16 >/dev/null
for _ in $(seq 1 60); do
  if pg_isready -h localhost -p "$PORT" -U postgres -q && psql "$OWNER_URL" -qAt -c 'select 1' >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
psql "$OWNER_URL" -qAt -c 'select 1' >/dev/null || { say "postgres did not come up"; exit 1; }

psql "$OWNER_URL" -v ON_ERROR_STOP=1 -q <<'SQL'
DROP TABLE IF EXISTS customers;
CREATE TABLE customers (id serial primary key, name text, email text, secret text, signed_up date);
INSERT INTO customers (name, email, secret, signed_up) VALUES
  ('Ada',      'ada@example.com',      'hunter2',       '2026-10-20'),
  ('Grace',    'grace@example.com',    'swordfish',     '2026-10-22'),
  ('Linus',    'linus@example.com',    'letmein',       '2026-10-24'),
  ('Margaret', 'margaret@example.com', 'correct-horse', '2026-10-26');
SQL

# --- isolated daypass home + `daypass` on PATH ---------------------------------------------
export DAYPASS_HOME="$DEMO_DIR/.daypass"
mkdir -p "$DAYPASS_HOME" "$DEMO_DIR/bin"
chmod 700 "$DAYPASS_HOME"

printf 'customers.email\ncustomers.secret\n' > "$DEMO_DIR/hidden.txt"
# The role script ends with a self-check that prints two result sets; keep stdout clean for --transcript.
node dist/cli/main.js sql --role daypass_ro --hide-file "$DEMO_DIR/hidden.txt" \
  | psql "$OWNER_URL" -v ON_ERROR_STOP=1 -q >/dev/null
psql "$OWNER_URL" -q -c "ALTER ROLE daypass_ro PASSWORD 'ro-pass';" >/dev/null

RO_URL="$(node -e "const u=new URL(process.argv[1]);u.username='daypass_ro';u.password='ro-pass';u.searchParams.set('sslmode','disable');console.log(u.toString())" "$OWNER_URL")"
node -e "require('fs').writeFileSync(process.env.DAYPASS_HOME+'/config.json', JSON.stringify({targets:{prod:{url:process.argv[1]}}}, null, 2))" "$RO_URL"

cat > "$DEMO_DIR/identity.cjs" <<'JS'
// Preloaded into the CLI so the lease identity reads "dev@laptop" instead of a real machine name.
const os = require('node:os');
os.hostname = () => 'laptop';
require('node:module').syncBuiltinESMExports();
JS
cat > "$DEMO_DIR/bin/daypass" <<SH
#!/usr/bin/env bash
exec node -r "$DEMO_DIR/identity.cjs" "$REPO/dist/cli/main.js" "\$@"
SH
chmod +x "$DEMO_DIR/bin/daypass"

export PATH="$DEMO_DIR/bin:$PATH"
export USER=dev
unset AWS_PROFILE AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN 2>/dev/null || true

# --- go ---------------------------------------------------------------------------------------
if [ "$MODE" = transcript ]; then
  # Same six lines the tape types, echoed with a plain "$ " prompt.
  run() { echo "\$ $1"; eval "$1" 2>&1; echo; }
  run 'daypass open prod --ttl 30m --reason "why did signups drop on Monday"'
  run 'daypass status'
  run 'daypass doctor prod'
  run 'DEMO=1 node scripts/smoke.mjs'
  run 'daypass log -n 3'
  run 'daypass close'
else
  say "recording docs/assets/demo.tape"
  vhs docs/assets/demo.tape >&2
  say "wrote docs/assets/demo.gif ($(du -h docs/assets/demo.gif | cut -f1))"
fi
