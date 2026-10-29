-- Peephole: one-time setup of the read-only role on the target database.
-- Run as the DB owner / master user, once per database:
--
--   peephole sql --hide-file hidden-columns.txt | psql -X "$OWNER_URL" -v ON_ERROR_STOP=1
--
-- (-X skips your psqlrc.)
--
-- `peephole sql --role NAME` changes the role name; `--hide table.col ...` / `--hide-file`
-- list columns the agent must never see. Needs psql (uses \gexec).
--
-- Safe to re-run. Nothing here touches data. The whole script is ONE transaction (BEGIN below,
-- COMMIT at the end): it stops at the first problem, and a failed run changes nothing. Without
-- the transaction a run that fails after the bulk GRANT SELECT ON ALL TABLES (e.g. on a stale
-- entry in the hidden list) would leave every hidden column readable. It ends with a self-check
-- that fails if any hidden column is still readable. Re-runs keep an existing password.

-- psql settings, restated in case a psqlrc overrides them: stop at the first error, and never
-- savepoint around a failing statement (ON_ERROR_ROLLBACK=on would let COMMIT land the bulk GRANT).
\set ON_ERROR_STOP on
\set ON_ERROR_ROLLBACK off

BEGIN;

-- 1. Role. Created with no password: on RDS it logs in only with a short-lived IAM token
--    (rds_iam below). On any other Postgres the owner sets one once, after the first run:
--    ALTER ROLE "__ROLE__" PASSWORD '...'. Re-runs do not touch the password.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '__ROLE__') THEN
    EXECUTE 'CREATE ROLE "__ROLE__" LOGIN PASSWORD NULL';
  END IF;
END $$;
-- SUPERUSER / REPLICATION / BYPASSRLS are not named here: a new role never has them, and on
-- RDS the master user is not a superuser, so even "NOSUPERUSER" is refused.
ALTER ROLE "__ROLE__" WITH LOGIN NOCREATEDB NOCREATEROLE NOINHERIT CONNECTION LIMIT 5;

-- RDS only. On plain Postgres (local dev) rds_iam does not exist and this is skipped.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rds_iam') THEN
    EXECUTE 'GRANT rds_iam TO "__ROLE__"';
  ELSE
    RAISE NOTICE 'rds_iam role not found (not RDS?) - IAM grant skipped';
  END IF;
END $$;

-- 2. Belt and braces at the role level (the client also sets these per session).
--    10s while Peephole reads the live instance; raise once it points at a read replica.
ALTER ROLE "__ROLE__" SET default_transaction_read_only = on;
ALTER ROLE "__ROLE__" SET statement_timeout = '10s';
ALTER ROLE "__ROLE__" SET idle_in_transaction_session_timeout = '30s';
ALTER ROLE "__ROLE__" SET lock_timeout = '1s';
ALTER ROLE "__ROLE__" SET temp_file_limit = '256MB';

-- 3. Read access to the public schema, now and for future tables.
SELECT format('GRANT CONNECT ON DATABASE %I TO "__ROLE__"', current_database()) \gexec
GRANT USAGE ON SCHEMA public TO "__ROLE__";
GRANT SELECT ON ALL TABLES IN SCHEMA public TO "__ROLE__";
GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO "__ROLE__";
-- Only covers tables created by the user running this script. The owner report at the end
-- shows whether another user (e.g. the one running Prisma migrations) owns tables.
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO "__ROLE__";

-- 4. Hide sensitive columns.
--    Postgres ignores a column-level REVOKE when the role holds table-level SELECT, so for each
--    table below we drop the table-level grant and grant only the visible columns instead.
--    Side effects: `SELECT *` on these tables fails (Claude must name columns), and a column
--    added later to one of these tables stays hidden until this script is re-run.
--    An entry that does not exist stops the script. If you use Prisma, `npm test` with
--    PEEPHOLE_HIDDEN_FILE and PEEPHOLE_PRISMA_SCHEMA set checks the list against your schema.
DO $$
DECLARE
  hidden text[] := __HIDDEN__;
  spec text;
  tbl  text;
  cols text;
BEGIN
  -- Every entry must exist; a typo would otherwise hide nothing.
  FOREACH spec IN ARRAY hidden LOOP
    IF NOT EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name = split_part(spec, '.', 1)
        AND column_name = split_part(spec, '.', 2)
    ) THEN
      RAISE EXCEPTION 'hidden column "%" does not exist in schema public - fix the list', spec;
    END IF;
  END LOOP;

  -- Per table: drop table-level SELECT (which also clears old column grants), then grant the visible columns.
  FOR tbl IN SELECT DISTINCT split_part(h, '.', 1) FROM unnest(hidden) AS h ORDER BY 1 LOOP
    EXECUTE format('REVOKE SELECT ON TABLE public.%I FROM "__ROLE__"', tbl);
    SELECT string_agg(format('%I', column_name), ', ' ORDER BY ordinal_position) INTO cols
      FROM information_schema.columns
     WHERE table_schema = 'public' AND table_name = tbl
       AND NOT ((tbl || '.' || column_name) = ANY (hidden));
    IF cols IS NOT NULL THEN
      EXECUTE format('GRANT SELECT (%s) ON TABLE public.%I TO "__ROLE__"', cols, tbl);
    END IF;
  END LOOP;

  -- Self-check: no hidden column may be readable, and a visible one must be.
  FOREACH spec IN ARRAY hidden LOOP
    IF has_column_privilege('__ROLE__', format('public.%I', split_part(spec, '.', 1)), split_part(spec, '.', 2), 'SELECT') THEN
      RAISE EXCEPTION 'self-check failed: __ROLE__ can still read %', spec;
    END IF;
  END LOOP;
  -- ...and the role must still be able to read something on each of those tables.
  FOR tbl IN SELECT DISTINCT split_part(h, '.', 1) FROM unnest(hidden) AS h LOOP
    IF NOT EXISTS (
      SELECT 1 FROM information_schema.columns c
      WHERE c.table_schema = 'public' AND c.table_name = tbl
        AND has_column_privilege('__ROLE__', format('public.%I', tbl), c.column_name, 'SELECT')
    ) THEN
      RAISE EXCEPTION 'self-check failed: __ROLE__ cannot read any column of %', tbl;
    END IF;
  END LOOP;
  RAISE NOTICE 'hidden columns verified: % columns across % tables',
    coalesce(array_length(hidden, 1), 0), (SELECT count(DISTINCT split_part(h, '.', 1)) FROM unnest(hidden) h);
END $$;

-- 5. Report
SELECT rolname, rolconnlimit, rolconfig FROM pg_roles WHERE rolname = '__ROLE__';
-- Tables owned by someone other than you are NOT covered by the default-privileges rule above.
SELECT tableowner, count(*) AS tables, (tableowner = current_user) AS covered_by_default_privileges
  FROM pg_tables WHERE schemaname = 'public' GROUP BY 1 ORDER BY 2 DESC;

COMMIT;
