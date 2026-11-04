-- Daypass: one-time setup of the read-only role on the target database.
-- Run as the DB owner / master user, once per database:
--
--   daypass sql --hide-file hidden-columns.txt | psql -X "$OWNER_URL" -v ON_ERROR_STOP=1
--
-- (-X skips your psqlrc.)
--
-- `daypass sql --role NAME` changes the role name; `--hide table.col ...` / `--hide-file` list
-- columns the agent must never see (also `schema.table.col` and "quoted"."identifiers");
-- `--schemas public,analytics` picks the schemas the role may read (default: public);
-- `--allow-definer-functions` acknowledges SECURITY DEFINER functions the role can execute;
-- `--revoke-public-temp` removes PUBLIC's TEMP privilege on the database;
-- `--revoke-public-create` removes PUBLIC's CREATE privilege on the listed schemas.
-- Needs psql (uses \gexec).
--
-- Safe to re-run. Nothing here touches data. The whole script is ONE transaction (BEGIN below,
-- COMMIT at the end): it stops at the first problem, and a failed run changes nothing. It ends
-- with a self-check that fails if any hidden column is still readable, if any readable view
-- depends on a hidden column, if the role can read anything outside --schemas or write anything
-- anywhere, owns an object or belongs to another role, or can execute a SECURITY DEFINER function
-- that was not acknowledged. Re-runs keep an existing password.
--
-- Fail closed: the role can read exactly what this run grants. There is no GRANT ... ON ALL
-- TABLES and no ALTER DEFAULT PRIVILEGES (default privileges an older Daypass version set up are
-- removed), so a table or view created after this run is invisible until the owner re-runs the
-- script (and reviews the hidden list first). Grants this role holds in schemas that are no
-- longer listed are revoked.
--
-- PostgreSQL 16+: only a superuser or a role holding ADMIN OPTION on the read-only role may alter
-- it. The user that created it holds that automatically; anyone else gets a clear error below.

-- psql settings, restated in case a psqlrc overrides them: stop at the first error, and never
-- savepoint around a failing statement (ON_ERROR_ROLLBACK=on would let COMMIT land partial grants).
\set ON_ERROR_STOP on
\set ON_ERROR_ROLLBACK off

BEGIN;

-- Pin the search path for this transaction. Every unqualified function and operator below
-- (||, =, ~, format, ...) then resolves in pg_catalog only: an object someone planted in a
-- schema on the owner's search_path (the read-only role itself may hold CREATE on public up to
-- PostgreSQL 14) can never run as the owner. pg_temp last: never searched for functions or
-- operators, and searched last for relations. Side effect: every regclass in a message is
-- schema-qualified.
SET LOCAL search_path = pg_catalog, pg_temp;

-- 1. Role. Created with no password: on RDS it logs in only with a short-lived IAM token
--    (rds_iam below). On any other Postgres the owner sets one once, after the first run:
--    ALTER ROLE "__ROLE__" PASSWORD '...'. Re-runs do not touch the password.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '__ROLE__') THEN
    EXECUTE 'CREATE ROLE "__ROLE__" LOGIN PASSWORD NULL';
  ELSIF current_setting('server_version_num')::int >= 160000
        AND NOT pg_has_role(current_user, '__ROLE__', 'MEMBER WITH ADMIN OPTION') THEN
    -- PG 16 changed CREATEROLE: altering an existing role needs ADMIN OPTION on it.
    RAISE EXCEPTION 'PostgreSQL 16+: % may not alter role "__ROLE__" (no ADMIN OPTION on it). Run this script as the user that created the role or as a superuser, or have one of them run: GRANT "__ROLE__" TO % WITH ADMIN OPTION;', current_user, quote_ident(current_user);
  END IF;
END $$;
-- SUPERUSER / REPLICATION / BYPASSRLS: removed on every run, but named only when set. Only a
-- superuser may change them (on RDS the master user is not one, so even a no-op "NOSUPERUSER" is
-- refused). REPLICATION reads every row through a logical replication slot; BYPASSRLS skips
-- row-level security. The last step before COMMIT verifies all five attributes.
DO $$
DECLARE
  attrs text;
BEGIN
  SELECT concat_ws(' ', CASE WHEN rolsuper THEN 'NOSUPERUSER' END, CASE WHEN rolreplication THEN 'NOREPLICATION' END,
                        CASE WHEN rolbypassrls THEN 'NOBYPASSRLS' END)
    INTO attrs FROM pg_roles WHERE rolname = '__ROLE__';
  IF attrs <> '' THEN
    BEGIN
      EXECUTE 'ALTER ROLE "__ROLE__" WITH ' || attrs;
    EXCEPTION WHEN insufficient_privilege THEN
      RAISE EXCEPTION 'role % has %, and only a superuser can remove that. Have one run: ALTER ROLE % WITH %; then re-run',
        '__ROLE__', replace(attrs, 'NO', ''), quote_ident('__ROLE__'), attrs;
    END;
  END IF;
END $$;
ALTER ROLE "__ROLE__" WITH LOGIN NOCREATEDB NOCREATEROLE NOINHERIT CONNECTION LIMIT 5;

-- The role must own nothing and belong to nothing. Owned objects are what it could have planted
-- while it held CREATE somewhere (a function, an operator, a trigger target, a large object);
-- membership in another role lets it SET ROLE to that role and use all of its privileges
-- (NOINHERIT does not stop SET ROLE). Checked before anything else runs.
DO $$
DECLARE
  role_oid oid := (SELECT oid FROM pg_roles WHERE rolname = '__ROLE__');
  msg text;
BEGIN
  SELECT string_agg(pg_describe_object(d.classid, d.objid, d.objsubid), '; ' ORDER BY pg_describe_object(d.classid, d.objid, d.objsubid)) INTO msg
    FROM pg_shdepend d
   WHERE d.refclassid = 'pg_authid'::regclass AND d.refobjid = role_oid AND d.deptype = 'o'
     AND d.dbid IN (0, (SELECT oid FROM pg_database WHERE datname = current_database()));
  IF msg IS NOT NULL THEN
    RAISE EXCEPTION 'role % owns objects in this database: %. A read-only role should own nothing (it can plant objects while it holds CREATE on a schema). Inspect them, then as the owner run: DROP OWNED BY %; and re-run this script (it re-grants what it needs).',
      '__ROLE__', msg, quote_ident('__ROLE__');
  END IF;
  IF EXISTS (SELECT 1 FROM pg_shdepend d WHERE d.refclassid = 'pg_authid'::regclass AND d.refobjid = role_oid AND d.deptype = 'o'
              AND d.dbid NOT IN (0, (SELECT oid FROM pg_database WHERE datname = current_database()))) THEN
    RAISE NOTICE 'role % owns objects in another database on this server: run this script there too, or DROP OWNED BY % in it', '__ROLE__', quote_ident('__ROLE__');
  END IF;
  SELECT string_agg(DISTINCT r.rolname, ', ') INTO msg
    FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.roleid
   WHERE m.member = role_oid AND r.rolname <> 'rds_iam';
  IF msg IS NOT NULL THEN
    RAISE EXCEPTION 'role % is a member of %: it can SET ROLE to them and use their privileges (NOINHERIT does not stop SET ROLE). Revoke it: REVOKE <role> FROM %; then re-run',
      '__ROLE__', msg, quote_ident('__ROLE__');
  END IF;
  -- CVE-2024-4317: pg_stats_ext / pg_stats_ext_exprs in clusters created before 14.12 / 15.7 /
  -- 16.3 show statistics (most common values, ...) of tables the caller cannot read. A minor
  -- upgrade does not fix the catalog: the fix SQL has to be run in every database.
  IF current_setting('server_version_num')::int >= 140000 AND (
       (to_regclass('pg_catalog.pg_stats_ext') IS NOT NULL AND pg_get_viewdef('pg_catalog.pg_stats_ext'::regclass) !~ 'pg_has_role')
    OR (to_regclass('pg_catalog.pg_stats_ext_exprs') IS NOT NULL AND pg_get_viewdef('pg_catalog.pg_stats_ext_exprs'::regclass) !~ 'pg_has_role')) THEN
    RAISE EXCEPTION 'this database has the unpatched pg_stats_ext / pg_stats_ext_exprs views of CVE-2024-4317: any role can read extended statistics (sample values) of hidden columns. Update to a fixed minor release and run share/fix-CVE-2024-4317.sql from it in this database (see https://www.postgresql.org/support/security/CVE-2024-4317/), then re-run';
  END IF;
END $$;

-- RDS only. On plain Postgres (local dev) rds_iam does not exist and this is skipped. IAM login
-- needs the membership only, never rds_iam's privileges. PostgreSQL 16+: granted WITH INHERIT
-- FALSE, SET FALSE, so the role can neither use nor SET ROLE to rds_iam (an older grant is
-- narrowed the same way). Before 16, SET ROLE rds_iam cannot be prevented: the last step before
-- COMMIT then refuses an rds_iam that holds anything. The GRANT runs only when needed (it needs
-- ADMIN OPTION on rds_iam from PG 16).
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rds_iam') THEN
    RAISE NOTICE 'rds_iam role not found (not RDS?) - IAM grant skipped';
  ELSIF current_setting('server_version_num')::int >= 160000 THEN
    IF NOT pg_has_role('__ROLE__', 'rds_iam', 'MEMBER')
       OR EXISTS (SELECT 1 FROM pg_auth_members m
                   WHERE m.roleid = (SELECT oid FROM pg_roles WHERE rolname = 'rds_iam')
                     AND m.member = (SELECT oid FROM pg_roles WHERE rolname = '__ROLE__')
                     AND (m.set_option OR m.inherit_option)) THEN
      BEGIN
        EXECUTE 'GRANT rds_iam TO "__ROLE__" WITH INHERIT FALSE, SET FALSE';
      EXCEPTION WHEN insufficient_privilege THEN
        RAISE EXCEPTION 'cannot grant rds_iam to % WITH INHERIT FALSE, SET FALSE: % has no ADMIN OPTION on rds_iam. Run this script as the RDS master user', '__ROLE__', current_user;
      END;
    END IF;
  ELSIF NOT pg_has_role('__ROLE__', 'rds_iam', 'MEMBER') THEN
    EXECUTE 'GRANT rds_iam TO "__ROLE__"';
  END IF;
END $$;

-- 2. Session defaults at the role level (the client also sets these per session).
--    These are DEFAULTS the role can change for itself (SET ..., ALTER ROLE ... RESET ALL,
--    ALTER ROLE ... IN DATABASE ... SET): they bound the agent through the MCP client, not
--    someone holding the role's password in psql. `daypass doctor` reports drift: it accepts a
--    statement_timeout from 1ms to 5min (10s while Daypass reads the live instance; raise it, e.g.
--    to 60s, once it points at a read replica) and wants the other four exactly as below.
--    RESET ALL first: any other setting (search_path, role, ...) was not put there by this script.
ALTER ROLE "__ROLE__" RESET ALL;
ALTER ROLE "__ROLE__" SET default_transaction_read_only = on;
ALTER ROLE "__ROLE__" SET statement_timeout = '10s';
ALTER ROLE "__ROLE__" SET idle_in_transaction_session_timeout = '30s';
ALTER ROLE "__ROLE__" SET lock_timeout = '1s';
ALTER ROLE "__ROLE__" SET temp_file_limit = '256MB';
-- Per-database settings (ALTER ROLE ... IN DATABASE ... SET) override the five above and do not
-- show in pg_roles.rolconfig. This script never sets any, so every one found is removed.
SELECT format('ALTER ROLE %I IN DATABASE %I RESET ALL', '__ROLE__', d.datname)
  FROM pg_db_role_setting s JOIN pg_database d ON d.oid = s.setdatabase
 WHERE s.setrole = (SELECT oid FROM pg_roles WHERE rolname = '__ROLE__') \gexec

-- 3. Database access. Schema and table grants are explicit, per relation, in step 4.
SELECT format('GRANT CONNECT ON DATABASE %I TO "__ROLE__"', current_database()) \gexec

-- 4. Grants and hidden columns, in one block so every decision sees the same catalog.
--    Postgres ignores a column-level REVOKE when the role holds table-level SELECT, so a table
--    with a hidden column gets SELECT on its visible columns only. Side effects: `SELECT *` on
--    these tables fails (the agent must name columns), and a column added later to one of them
--    stops the next run until it is listed (hidden) or marked `!table.column` (visible).
--    An entry that does not exist stops the script. `daypass hidden check` finds that first.
DO $$
DECLARE
  hidden_in     text[]  := __HIDDEN__;
  allow_in      text[]  := __ALLOW__;
  schemas       text[]  := __SCHEMAS__;
  allow_definer boolean := __ALLOW_DEFINER__;
  revoke_temp   boolean := __REVOKE_TEMP__;
  revoke_create boolean := __REVOKE_CREATE__;
  -- What this run hides, stored on the role (COMMENT ON ROLE) for `daypass doctor`.
  manifest_in   text    := __MANIFEST__;
  existing      jsonb;
  -- Write privileges: any of these makes a relation writable once the role turns read-only off.
  write_privs   constant text := 'INSERT, UPDATE, DELETE, TRUNCATE, TRIGGER'
                  || CASE WHEN current_setting('server_version_num')::int >= 170000 THEN ', MAINTAIN' ELSE '' END;
  role_name     constant text := '__ROLE__';
  role_oid      oid;
  -- Resolved sets. A column is 'relid.attnum'; labels are the canonical spelling from the list.
  hidden        text[] := '{}';   -- every hidden column, children and partitions included
  hidden_label  text[] := '{}';   -- parallel to hidden
  hidden_rels   oid[]  := '{}';   -- distinct relations carrying a hidden column
  allowed       text[] := '{}';   -- `!` columns, children and partitions included
  prev_readable text[] := '{}';   -- columns of hidden_rels the role could read BEFORE this run
  prev_rels     oid[]  := '{}';   -- hidden_rels the role could read at least one column of before
  tainted_rels  oid[]  := '{}';   -- views/matviews the role must not read
  taint_root    text[] := '{}';   -- parallel to tainted_rels: what it exposes ("exposes hidden column t.c")
  taint_why     text[] := '{}';   -- parallel to tainted_rels: taint_root plus the view it goes through
  spec   text;
  parts  text[];
  lbl    text;
  rel    oid;
  att    int2;
  r      record;
  cols   text;
  msg    text;
  idx    int;
  n_new  int;
  n_rel  int := 0;
  n_view int := 0;
BEGIN
  SELECT oid INTO role_oid FROM pg_roles WHERE rolname = role_name;

  -- Every entry must exist; a typo would otherwise hide nothing. Existence = pg_attribute on a
  -- relation of kind r/p/v/m (information_schema.columns omits materialized views). Same
  -- definition as `daypass hidden suggest|check`.
  FOREACH spec IN ARRAY hidden_in LOOP
    parts := string_to_array(spec, '|');
    IF coalesce(array_length(parts, 1), 0) <> 3 THEN
      RAISE EXCEPTION 'bad hidden entry "%" (expected schema|table|column from daypass sql)', spec;
    END IF;
    lbl := CASE WHEN parts[1] = 'public' THEN '' ELSE
             CASE WHEN parts[1] ~ '^[A-Za-z_][A-Za-z0-9_]*$' THEN parts[1] ELSE quote_ident(parts[1]) END || '.' END
        || CASE WHEN parts[2] ~ '^[A-Za-z_][A-Za-z0-9_]*$' THEN parts[2] ELSE quote_ident(parts[2]) END || '.'
        || CASE WHEN parts[3] ~ '^[A-Za-z_][A-Za-z0-9_]*$' THEN parts[3] ELSE quote_ident(parts[3]) END;
    IF NOT parts[1] = ANY (schemas) THEN
      RAISE EXCEPTION 'hidden column % is in schema "%", which is not in --schemas (%) - add it: daypass sql --schemas %',
        lbl, parts[1], array_to_string(schemas, ','), array_to_string(schemas || parts[1], ',');
    END IF;
    SELECT c.oid, a.attnum INTO rel, att
      FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
      JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
     WHERE n.nspname = parts[1] AND c.relname = parts[2] AND a.attname = parts[3]
       AND c.relkind IN ('r','p','v','m','f');
    IF NOT FOUND THEN
      RAISE EXCEPTION 'hidden column "%" does not exist (as a table, partitioned table, view, materialized view or foreign table column in schema %) - fix the list', lbl, parts[1];
    END IF;
    IF (rel || '.' || att) = ANY (hidden) THEN CONTINUE; END IF;
    hidden := hidden || (rel || '.' || att);
    hidden_label := hidden_label || lbl;
    hidden_rels := hidden_rels || rel;
    -- Partitions and inheritance children expose the same column: hide it there too, recursively.
    FOR r IN
      WITH RECURSIVE kids AS (
        SELECT inhrelid FROM pg_inherits WHERE inhparent = rel
        UNION
        SELECT i.inhrelid FROM pg_inherits i JOIN kids k ON i.inhparent = k.inhrelid
      )
      SELECT k.inhrelid AS child, a.attnum AS cattnum
        FROM kids k
        LEFT JOIN pg_attribute a ON a.attrelid = k.inhrelid AND a.attname = parts[3] AND a.attnum > 0 AND NOT a.attisdropped
    LOOP
      IF r.cattnum IS NULL THEN
        RAISE EXCEPTION 'hidden column %: partition/child % lacks column % - cannot hide it there', lbl, r.child::regclass, parts[3];
      END IF;
      IF NOT (r.child || '.' || r.cattnum) = ANY (hidden) THEN
        hidden := hidden || (r.child || '.' || r.cattnum);
        hidden_label := hidden_label || (r.child::regclass::text || '.' || quote_ident(parts[3]) || ' (via ' || lbl || ')');
        hidden_rels := hidden_rels || r.child;
      END IF;
    END LOOP;
  END LOOP;

  -- `!` allow entries: reviewed, intentionally visible. Must exist too; children inherit the mark.
  FOREACH spec IN ARRAY allow_in LOOP
    parts := string_to_array(spec, '|');
    IF coalesce(array_length(parts, 1), 0) <> 3 THEN
      RAISE EXCEPTION 'bad allow entry "%" (expected schema|table|column from daypass sql)', spec;
    END IF;
    SELECT c.oid, a.attnum INTO rel, att
      FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
      JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
     WHERE n.nspname = parts[1] AND c.relname = parts[2] AND a.attname = parts[3]
       AND c.relkind IN ('r','p','v','m','f');
    IF NOT FOUND THEN
      RAISE EXCEPTION 'allowed column "!%.%.%" does not exist - fix the list', parts[1], parts[2], parts[3];
    END IF;
    IF (rel || '.' || att) = ANY (hidden) THEN
      RAISE EXCEPTION 'column %.%.% is both hidden and !allowed - keep one line per column', parts[1], parts[2], parts[3];
    END IF;
    allowed := allowed || (rel || '.' || att);
    FOR r IN
      WITH RECURSIVE kids AS (
        SELECT inhrelid FROM pg_inherits WHERE inhparent = rel
        UNION
        SELECT i.inhrelid FROM pg_inherits i JOIN kids k ON i.inhparent = k.inhrelid
      )
      SELECT a.attrelid AS child, a.attnum AS cattnum
        FROM kids k JOIN pg_attribute a ON a.attrelid = k.inhrelid AND a.attname = parts[3] AND a.attnum > 0 AND NOT a.attisdropped
    LOOP
      allowed := allowed || (r.child || '.' || r.cattnum);
    END LOOP;
  END LOOP;
  hidden_rels := ARRAY(SELECT DISTINCT unnest(hidden_rels));

  -- A hidden column on a partition or inheritance child only: Postgres checks the PARENT's
  -- privileges when the parent is queried, and that returns the child's rows, so the column would
  -- still be readable through the parent. Hide it on the topmost ancestor instead.
  FOR r IN
    WITH RECURSIVE anc AS (
      SELECT i.inhrelid AS rel, i.inhparent AS parent FROM pg_inherits i WHERE i.inhrelid = ANY (hidden_rels)
      UNION
      SELECT a.rel, i.inhparent FROM anc a JOIN pg_inherits i ON i.inhrelid = a.parent
    )
    SELECT anc.rel, anc.parent, ca.attname
      FROM anc
      JOIN pg_attribute ca ON ca.attrelid = anc.rel AND ca.attnum > 0 AND NOT ca.attisdropped
                          AND (ca.attrelid || '.' || ca.attnum) = ANY (hidden)
      JOIN pg_attribute pa ON pa.attrelid = anc.parent AND pa.attname = ca.attname AND pa.attnum > 0 AND NOT pa.attisdropped
     WHERE NOT (pa.attrelid || '.' || pa.attnum) = ANY (hidden)
     ORDER BY 1, 2, 3
  LOOP
    RAISE EXCEPTION '%', format('hidden column %s.%I is on a partition/child of %s, whose column %I is not hidden: SELECT %I FROM %s would still return the child''s rows. List %s.%I instead (that hides it on every partition and child).',
      r.rel::regclass, r.attname, r.parent::regclass, r.attname, r.attname, r.parent::regclass, r.parent::regclass, r.attname);
  END LOOP;

  -- A generated column computed from a hidden column carries (part of) its value. Such a column
  -- must be listed too: say which. (`daypass hidden suggest` lists them; `hidden check` flags them.)
  -- Up to PG 15 the dependency runs column to column; from PG 16 it runs from the column's
  -- generation expression (pg_attrdef) to the source column. Check both.
  SELECT string_agg(DISTINCT format('%s.%I (generated from %s.%I)', g.relid::regclass, ga.attname, g.refrelid::regclass, ha.attname), ', ') INTO msg
    FROM (SELECT d.objid AS relid, d.objsubid AS attnum, d.refobjid AS refrelid, d.refobjsubid AS refattnum
            FROM pg_depend d
           WHERE d.classid = 'pg_class'::regclass AND d.refclassid = 'pg_class'::regclass
             AND d.objsubid > 0 AND d.refobjsubid > 0
          UNION
          SELECT ad.adrelid, ad.adnum, d.refobjid, d.refobjsubid
            FROM pg_depend d JOIN pg_attrdef ad ON ad.oid = d.objid
           WHERE d.classid = 'pg_attrdef'::regclass AND d.refclassid = 'pg_class'::regclass
             AND d.refobjsubid > 0 AND NOT (d.refobjid = ad.adrelid AND d.refobjsubid = ad.adnum)) g
    JOIN pg_attribute ga ON ga.attrelid = g.relid AND ga.attnum = g.attnum AND ga.attgenerated <> ''
    JOIN pg_attribute ha ON ha.attrelid = g.refrelid AND ha.attnum = g.refattnum
   WHERE (g.refrelid || '.' || g.refattnum) = ANY (hidden)
     AND NOT (g.relid || '.' || g.attnum) = ANY (hidden);
  IF msg IS NOT NULL THEN
    RAISE EXCEPTION 'column(s) derived from a hidden column would be readable: %. Add each to the hidden list too, then re-run.', msg;
  END IF;

  -- Catalog text the role can read anyway (pg_get_expr, pg_indexes, pg_constraint, pg_policy):
  -- a default, a CHECK constraint, a partial-index predicate or expression, a row-level policy or
  -- extended statistics that mention a hidden column show their constants. Not an error; review them.
  FOR r IN
    SELECT DISTINCT pg_describe_object(d.classid, d.objid, 0) AS obj, format('%s.%I', d.refobjid::regclass, a.attname) AS col,
           d.classid = 'pg_policy'::regclass AS is_policy
      FROM pg_depend d JOIN pg_attribute a ON a.attrelid = d.refobjid AND a.attnum = d.refobjsubid
     WHERE d.refclassid = 'pg_class'::regclass AND d.refobjsubid > 0
       AND (d.refobjid || '.' || d.refobjsubid) = ANY (hidden)
       AND (d.classid IN ('pg_attrdef'::regclass, 'pg_policy'::regclass, 'pg_statistic_ext'::regclass)
            OR (d.classid = 'pg_constraint'::regclass AND EXISTS (SELECT 1 FROM pg_constraint k WHERE k.oid = d.objid AND k.contype IN ('c', 'x')))
            OR (d.classid = 'pg_class'::regclass AND d.objsubid = 0
                AND EXISTS (SELECT 1 FROM pg_index i WHERE i.indexrelid = d.objid AND (i.indpred IS NOT NULL OR i.indexprs IS NOT NULL))))
     ORDER BY 2, 1
  LOOP
    RAISE NOTICE 'catalog text: % mentions hidden column %: the role can read its definition, constants included%', r.obj, r.col,
      CASE WHEN r.is_policy THEN ' (and a row-level policy on it reveals one bit per row: which rows pass)' ELSE '' END;
  END LOOP;

  -- A grant to PUBLIC on a hidden table would reach the role no matter what this script does.
  FOR r IN
    SELECT c.oid::regclass AS tbl, NULL::text AS col
      FROM pg_class c, aclexplode(c.relacl) a
     WHERE c.oid = ANY (hidden_rels) AND a.grantee = 0 AND a.privilege_type = 'SELECT'
    UNION ALL
    SELECT c.oid::regclass, pa.attname
      FROM pg_attribute pa JOIN pg_class c ON c.oid = pa.attrelid, aclexplode(pa.attacl) a
     WHERE (pa.attrelid || '.' || pa.attnum) = ANY (hidden) AND a.grantee = 0 AND a.privilege_type = 'SELECT'
  LOOP
    IF r.col IS NULL THEN
      RAISE EXCEPTION 'PUBLIC can read hidden table %: run REVOKE SELECT ON % FROM PUBLIC; then re-run', r.tbl, r.tbl;
    ELSE
      RAISE EXCEPTION 'PUBLIC can read hidden column %.%: run REVOKE SELECT (%) ON % FROM PUBLIC; then re-run', r.tbl, quote_ident(r.col), quote_ident(r.col), r.tbl;
    END IF;
  END LOOP;

  -- Snapshot BEFORE anything is revoked: which columns of the hidden tables could the role read?
  -- A column that appears on a previously processed table, is neither hidden nor !allowed, and
  -- was not readable before, was added since the last run. Granting it silently would leak it.
  SELECT coalesce(array_agg(a.attrelid || '.' || a.attnum), '{}') INTO prev_readable
    FROM pg_attribute a
   WHERE a.attrelid = ANY (hidden_rels) AND a.attnum > 0 AND NOT a.attisdropped
     AND has_column_privilege(role_name, a.attrelid, a.attnum, 'SELECT');
  prev_rels := ARRAY(SELECT DISTINCT split_part(p, '.', 1)::oid FROM unnest(prev_readable) p);
  SELECT string_agg(format('%s.%I', a.attrelid::regclass, a.attname), ', ' ORDER BY a.attrelid, a.attnum) INTO msg
    FROM pg_attribute a
   WHERE a.attrelid = ANY (prev_rels) AND a.attnum > 0 AND NOT a.attisdropped
     AND NOT (a.attrelid || '.' || a.attnum) = ANY (hidden)
     AND NOT (a.attrelid || '.' || a.attnum) = ANY (allowed)
     AND NOT (a.attrelid || '.' || a.attnum) = ANY (prev_readable);
  IF msg IS NOT NULL THEN
    RAISE EXCEPTION 'column(s) added since the last run on a table with hidden columns: %. Decide for each: add "table.column" to the hidden list, or mark it visible with "!table.column"; then re-run.', msg;
  END IF;

  FOREACH spec IN ARRAY schemas LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = spec) THEN
      RAISE EXCEPTION 'schema "%" does not exist', spec;
    END IF;
  END LOOP;

  -- Default privileges for this role (an older Daypass version set ALTER DEFAULT PRIVILEGES ...
  -- GRANT SELECT ON TABLES) would make every future table readable at once. Remove them all.
  FOR r IN
    SELECT DISTINCT d.defaclrole, d.defaclnamespace, d.defaclobjtype,
           (SELECT nspname FROM pg_namespace WHERE oid = d.defaclnamespace) AS nsp
      FROM pg_default_acl d, aclexplode(d.defaclacl) a
     WHERE a.grantee = role_oid
  LOOP
    IF NOT pg_has_role(current_user, r.defaclrole, 'MEMBER') THEN
      RAISE EXCEPTION 'role % has default privileges (set by %) that grant % every new %: run this script as % or a superuser, or as % run: ALTER DEFAULT PRIVILEGES FOR ROLE % % REVOKE ALL ON % FROM %;',
        role_name, pg_get_userbyid(r.defaclrole), role_name,
        CASE r.defaclobjtype WHEN 'r' THEN 'table' WHEN 'S' THEN 'sequence' WHEN 'f' THEN 'function' WHEN 'T' THEN 'type' ELSE 'schema' END,
        pg_get_userbyid(r.defaclrole), pg_get_userbyid(r.defaclrole), quote_ident(pg_get_userbyid(r.defaclrole)),
        CASE WHEN r.nsp IS NULL THEN '' ELSE 'IN SCHEMA ' || quote_ident(r.nsp) END,
        CASE r.defaclobjtype WHEN 'r' THEN 'TABLES' WHEN 'S' THEN 'SEQUENCES' WHEN 'f' THEN 'FUNCTIONS' WHEN 'T' THEN 'TYPES' ELSE 'SCHEMAS' END,
        quote_ident(role_name);
    END IF;
    EXECUTE format('ALTER DEFAULT PRIVILEGES FOR ROLE %I %s REVOKE ALL ON %s FROM %I',
      pg_get_userbyid(r.defaclrole),
      CASE WHEN r.nsp IS NULL THEN '' ELSE format('IN SCHEMA %I', r.nsp) END,
      CASE r.defaclobjtype WHEN 'r' THEN 'TABLES' WHEN 'S' THEN 'SEQUENCES' WHEN 'f' THEN 'FUNCTIONS' WHEN 'T' THEN 'TYPES' WHEN 'n' THEN 'SCHEMAS'
        ELSE NULL END,
      role_name);
  END LOOP;

  -- Start from nothing, in EVERY schema (not only the listed ones, so a schema dropped from
  -- --schemas loses what an earlier run granted there): revoke each relation and schema privilege
  -- the role holds directly. Only objects the role actually has an ACL entry on are touched.
  FOR r IN
    SELECT c.oid, c.relkind
      FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname !~ '^pg_(toast|temp)'
       AND (EXISTS (SELECT 1 FROM aclexplode(c.relacl) a WHERE a.grantee = role_oid)
            OR EXISTS (SELECT 1 FROM pg_attribute pa, aclexplode(pa.attacl) a WHERE pa.attrelid = c.oid AND a.grantee = role_oid))
     ORDER BY 1
  LOOP
    EXECUTE format('REVOKE ALL ON %s %s FROM %I', CASE WHEN r.relkind = 'S' THEN 'SEQUENCE' ELSE 'TABLE' END, r.oid::regclass, role_name);
  END LOOP;
  FOR r IN
    SELECT n.nspname FROM pg_namespace n
     WHERE EXISTS (SELECT 1 FROM aclexplode(n.nspacl) a WHERE a.grantee = role_oid)
     ORDER BY 1
  LOOP
    EXECUTE format('REVOKE ALL ON SCHEMA %I FROM %I', r.nspname, role_name);
  END LOOP;
  FOREACH spec IN ARRAY schemas LOOP
    EXECUTE format('GRANT USAGE ON SCHEMA %I TO %I', spec, role_name);
  END LOOP;
  -- Sequences: SELECT (currval, last_value), except one owned by a hidden column (serial /
  -- identity): its last_value tells the latest value and roughly how many rows exist.
  FOR r IN
    SELECT c.oid FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = ANY (schemas) AND c.relkind = 'S'
       AND NOT EXISTS (SELECT 1 FROM pg_depend d
                        WHERE d.classid = 'pg_class'::regclass AND d.objid = c.oid AND d.refclassid = 'pg_class'::regclass
                          AND d.deptype IN ('a', 'i') AND d.refobjsubid > 0 AND (d.refobjid || '.' || d.refobjsubid) = ANY (hidden))
     ORDER BY 1
  LOOP
    EXECUTE format('GRANT SELECT ON SEQUENCE %s TO %I', r.oid::regclass, role_name);
  END LOOP;

  -- Tables and partitioned tables (never views, foreign tables or anything else) without a
  -- hidden column: table-level SELECT. Partitions and children of a hidden table are in hidden_rels.
  FOR r IN
    SELECT c.oid, n.nspname, c.relname
      FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = ANY (schemas) AND c.relkind IN ('r','p') AND NOT c.oid = ANY (hidden_rels)
     ORDER BY 2, 3
  LOOP
    EXECUTE format('GRANT SELECT ON TABLE %I.%I TO %I', r.nspname, r.relname, role_name);
    n_rel := n_rel + 1;
  END LOOP;

  -- Views and materialized views: which must the role not read? pg_depend records, for each
  -- view's ON SELECT rule (ev_type '1'; other rules run on writes, which the role cannot do),
  -- every (relation, column) it reads, plus a whole-relation entry (column 0) per relation.
  --   a. it reads a hidden column;
  --   b. it reads the whole row of a relation with a hidden column (`SELECT t FROM t`,
  --      `row_to_json(t)`): that records only the column-0 entry, so look for a whole-row Var
  --      (`:varattno 0`) in the stored rule. Conservative: any whole-row Var in the rule counts;
  --   c. it reads a relation in a schema that is not listed (its data is outside --schemas, and
  --      hidden columns there cannot even be listed);
  --   d. it reads a view that is tainted (pg_depend does not say through which output column,
  --      so the whole view counts).
  FOR r IN
    SELECT DISTINCT ON (rw.ev_class) rw.ev_class AS v, format('exposes hidden column %s.%I', d.refobjid::regclass, a.attname) AS root
      FROM pg_depend d JOIN pg_rewrite rw ON rw.oid = d.objid
      JOIN pg_attribute a ON a.attrelid = d.refobjid AND a.attnum = d.refobjsubid
     WHERE d.classid = 'pg_rewrite'::regclass AND d.refclassid = 'pg_class'::regclass AND rw.ev_type = '1'
       AND d.refobjsubid > 0 AND rw.ev_class <> d.refobjid
       AND (d.refobjid || '.' || d.refobjsubid) = ANY (hidden)
     ORDER BY rw.ev_class, d.refobjid, d.refobjsubid
  LOOP
    tainted_rels := tainted_rels || r.v; taint_root := taint_root || r.root; taint_why := taint_why || r.root;
  END LOOP;
  FOR r IN
    SELECT DISTINCT ON (rw.ev_class) rw.ev_class AS v, format('exposes the whole row of %s, which has hidden columns', d.refobjid::regclass) AS root
      FROM pg_depend d JOIN pg_rewrite rw ON rw.oid = d.objid
     WHERE d.classid = 'pg_rewrite'::regclass AND d.refclassid = 'pg_class'::regclass AND rw.ev_type = '1'
       AND d.refobjsubid = 0 AND rw.ev_class <> d.refobjid AND d.refobjid = ANY (hidden_rels)
       AND rw.ev_action::text ~ ':varattno 0 ' AND NOT rw.ev_class = ANY (tainted_rels)
     ORDER BY rw.ev_class, d.refobjid
  LOOP
    tainted_rels := tainted_rels || r.v; taint_root := taint_root || r.root; taint_why := taint_why || r.root;
  END LOOP;
  FOR r IN
    SELECT DISTINCT ON (rw.ev_class) rw.ev_class AS v,
           format('reads %s, in schema %I, which is not in --schemas (add it: daypass sql --schemas %s)', d.refobjid::regclass, rn.nspname, array_to_string(schemas || rn.nspname::text, ',')) AS root
      FROM pg_depend d JOIN pg_rewrite rw ON rw.oid = d.objid
      JOIN pg_class t ON t.oid = d.refobjid JOIN pg_namespace rn ON rn.oid = t.relnamespace
     WHERE d.classid = 'pg_rewrite'::regclass AND d.refclassid = 'pg_class'::regclass AND rw.ev_type = '1'
       AND rw.ev_class <> d.refobjid AND NOT rw.ev_class = ANY (tainted_rels)
       AND rn.nspname NOT IN ('pg_catalog', 'information_schema') AND rn.nspname !~ '^pg_(toast|temp)'
       AND NOT rn.nspname = ANY (schemas)
     ORDER BY rw.ev_class, d.refobjid
  LOOP
    tainted_rels := tainted_rels || r.v; taint_root := taint_root || r.root; taint_why := taint_why || r.root;
  END LOOP;
  -- e. A materialized view stores what its query returned when the OWNER last refreshed it. Every
  --    function in it ran with the owner's rights, and so did every function in each view it
  --    reads, directly or through other views; a catalog view that filters rows by the caller
  --    (pg_stats, pg_stats_ext, pg_stat_activity, information_schema, ...) returned the owner's
  --    rows; a table with row-level security returned the rows the owner may see. Walk the whole
  --    tree. Catalogs and built-ins are pinned and pg_depend does not record them, so relations,
  --    functions and operators come from each stored rule. Fail closed: the matview is withheld
  --    when the tree reaches
  --      - a pg_catalog / information_schema relation, except a few plain catalog tables the role
  --        can read in full itself (every caller sees the same rows there);
  --      - a table with row-level security;
  --      - a function outside pg_catalog, a built-in that reads data by name, or any other
  --        built-in that is not immutable, except a short list of clock, date/time, formatting
  --        and JSON builders. Functions behind operators (also in row comparisons), behind a
  --        type conversion through text (the types' input/output functions), behind a subscript
  --        (the type's subscript handler) and in a domain's CHECK count too. Extension functions
  --        and operators (citext, pg_trgm, ...) are outside pg_catalog: such a matview is
  --        withheld too, since nothing tells what they read.
  --    A plain view's functions run as the caller, but it reads its tables with its OWNER's
  --    rights, row-level security included (an owner without FORCE ROW LEVEL SECURITY sees every
  --    row): a view whose tree reaches a table with row-level security is withheld too, unless it
  --    is security_invoker (PostgreSQL 15+). A security_invoker view over such a view is
  --    withheld through it (rule d).
  FOR r IN
    WITH RECURSIVE tree(mv, rel, via) AS (
      SELECT c.oid, c.oid, c.oid FROM pg_class c
       WHERE c.relkind = 'm'
          OR (c.relkind = 'v' AND NOT coalesce((SELECT bool_or(o ~* '^security_invoker=(t|tr|tru|true|y|ye|yes|on|1)$') FROM unnest(c.reloptions) o), false))
      UNION
      SELECT t.mv, f[1]::oid, t.rel
        FROM tree t
        JOIN pg_class c ON c.oid = t.rel AND c.relkind IN ('v','m')
        JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname NOT IN ('pg_catalog', 'information_schema')
        JOIN pg_rewrite rw ON rw.ev_class = c.oid AND rw.ev_type = '1',
        regexp_matches(rw.ev_action::text, ':relid ([0-9]+)', 'g') f
       WHERE f[1]::oid <> c.oid
    ), mvtree AS (
      SELECT t.* FROM tree t JOIN pg_class m ON m.oid = t.mv AND m.relkind = 'm'
    ), why AS (
      SELECT t.mv, t.via, 1 AS o, format('reads %I.%I', tn.nspname, tc.relname) AS what
        FROM mvtree t JOIN pg_class tc ON tc.oid = t.rel JOIN pg_namespace tn ON tn.oid = tc.relnamespace
       WHERE tn.nspname IN ('pg_catalog', 'information_schema')
         AND NOT (tn.nspname = 'pg_catalog' AND tc.relkind = 'r' AND has_table_privilege(role_name, tc.oid, 'SELECT')
                  AND tc.relname IN ('pg_namespace','pg_class','pg_attribute','pg_type','pg_index','pg_constraint','pg_inherits','pg_description','pg_enum'))
      UNION ALL
      SELECT t.mv, t.via, 2, format('reads %s, which has row-level security', tc.oid::regclass)
        FROM tree t JOIN pg_class tc ON tc.oid = t.rel
       WHERE tc.relkind IN ('r','p') AND tc.relrowsecurity
      UNION ALL
      SELECT t.mv, t.rel, 3, format('calls function %s', CASE WHEN pn.nspname = 'pg_catalog' THEN 'pg_catalog.' ELSE '' END || p.oid::regprocedure::text)
        FROM mvtree t
        JOIN pg_class c ON c.oid = t.rel AND c.relkind IN ('v','m')
        JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname NOT IN ('pg_catalog', 'information_schema')
        JOIN pg_rewrite rw ON rw.ev_class = c.oid AND rw.ev_type = '1',
        LATERAL (SELECT f[2]::oid AS fn FROM regexp_matches(rw.ev_action::text, ':(funcid|opfuncid|aggfnoid|winfnoid) ([0-9]+)', 'g') f
                 UNION
                 SELECT o.oprcode::oid FROM regexp_matches(rw.ev_action::text, ':(opno|sortop|eqop) ([0-9]+)', 'g') g
                   JOIN pg_operator o ON o.oid = g[2]::oid
                 UNION
                 SELECT o.oprcode::oid FROM regexp_matches(rw.ev_action::text, ':opnos [(]o ([0-9 ]+)[)]', 'g') l,
                   unnest(string_to_array(l[1], ' ')) u JOIN pg_operator o ON o.oid = u::oid
                 UNION
                 SELECT CASE WHEN k[1] IN ('opno', 'sortop', 'eqop') THEN (SELECT o.oprcode::oid FROM pg_operator o WHERE o.oid = k[2]::oid) ELSE k[2]::oid END
                   FROM regexp_matches(rw.ev_action::text, ':resulttype ([0-9]+)', 'g') dt
                   JOIN pg_constraint dc ON dc.contypid = dt[1]::oid AND dc.conbin IS NOT NULL,
                   regexp_matches(dc.conbin::text, ':(funcid|opfuncid|opno) ([0-9]+)', 'g') k
                  WHERE rw.ev_action::text ~ '[{]COERCETODOMAIN ') x
        JOIN pg_proc p ON p.oid = x.fn JOIN pg_namespace pn ON pn.oid = p.pronamespace
       WHERE pn.nspname <> 'pg_catalog'
          OR p.proname ~ '^((query|cursor|table|schema|database)_to_xml|ts_(stat|rewrite)$|lo_|pg_read_|pg_ls_|pg_stat_file$|pg_stat_get_activity$|current_setting$|dblink|crosstab|xpath_table$)'
          OR (p.provolatile <> 'i' AND p.proname !~ '^(now|transaction_timestamp|statement_timestamp|clock_timestamp|timeofday|random|gen_random_uuid|date_trunc|date_part|date_bin|extract|to_char|to_timestamp|to_date|age|timezone|generate_series|concat|concat_ws|format|array_to_string|to_json|to_jsonb|row_to_json|array_to_json|json_build_object|json_build_array|jsonb_build_object|jsonb_build_array|json_object_agg|jsonb_object_agg|json_agg|jsonb_agg|textanycat|anytextcat|date|timestamptz|timestamp|time|timetz|(timestamptz|timestamp|date|time|timetz|interval)_[a-z0-9_]+)$')
      UNION ALL
      -- A conversion through text (CoerceViaIO) runs the input/output functions of the types
      -- involved; the node does not say which, so every type the rule names counts (with its
      -- element, base, range subtype and column types).
      SELECT t.mv, t.rel, 4, format('converts values through text with type %s, whose input/output functions are outside pg_catalog', bt.top::regtype)
        FROM mvtree t
        JOIN pg_class c ON c.oid = t.rel AND c.relkind IN ('v','m')
        JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname NOT IN ('pg_catalog', 'information_schema')
        JOIN pg_rewrite rw ON rw.ev_class = c.oid AND rw.ev_type = '1' AND rw.ev_action::text ~ '[{]COERCEVIAIO ',
        LATERAL (WITH RECURSIVE ty(oid, top) AS (
                   SELECT m[1]::oid, m[1]::oid FROM regexp_matches(rw.ev_action::text, ':[a-z_]*type ([0-9]+)', 'g') m
                   UNION
                   SELECT x.oid, ty.top
                     FROM ty JOIN pg_type y ON y.oid = ty.oid,
                     LATERAL (SELECT y.typelem UNION SELECT y.typbasetype
                              UNION SELECT rg.rngsubtype FROM pg_range rg WHERE rg.rngtypid = y.oid
                              UNION SELECT a.atttypid FROM pg_attribute a WHERE a.attrelid = y.typrelid AND a.attnum > 0) x(oid)
                    WHERE x.oid <> 0)
                 SELECT DISTINCT ty.top FROM ty JOIN pg_type y ON y.oid = ty.oid
                  WHERE EXISTS (SELECT 1 FROM pg_namespace pn JOIN pg_proc tp ON tp.pronamespace = pn.oid
                                 WHERE tp.oid = ANY (ARRAY[y.typinput, y.typoutput, y.typreceive, y.typsend]::oid[])
                                   AND pn.nspname <> 'pg_catalog')) bt
      UNION ALL
      -- A subscript runs the container type's subscript handler (PostgreSQL 14+; regproc prints
      -- schema-qualified when the handler is outside pg_catalog, the pinned search_path).
      SELECT t.mv, t.rel, 5, format('subscripts type %s, whose subscript handler is outside pg_catalog', y.oid::regtype)
        FROM mvtree t
        JOIN pg_class c ON c.oid = t.rel AND c.relkind IN ('v','m')
        JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname NOT IN ('pg_catalog', 'information_schema')
        JOIN pg_rewrite rw ON rw.ev_class = c.oid AND rw.ev_type = '1',
        regexp_matches(rw.ev_action::text, ':refcontainertype ([0-9]+)', 'g') sr
        JOIN pg_type y ON y.oid = sr[1]::oid
       WHERE (to_jsonb(y) ->> 'typsubscript') ~ '[.]'
    )
    SELECT DISTINCT ON (w.mv) w.mv AS v,
           w.what || CASE WHEN w.via <> w.mv THEN ' through view ' || w.via::regclass::text ELSE '' END
             || CASE WHEN (SELECT relkind FROM pg_class WHERE oid = w.mv) = 'm'
                     THEN ' (a materialized view stores what it returned when the owner refreshed it'
                          || CASE WHEN w.o >= 3 THEN '; functions outside pg_catalog, extension ones included, may read anything the owner can' ELSE '' END || ')'
                     ELSE ' (a view reads its tables with its owner''s rights; only a security_invoker view, PostgreSQL 15+, reads them as the caller)' END AS root
      FROM why w
     WHERE NOT w.mv = ANY (tainted_rels)
     ORDER BY w.mv, w.o, w.what
  LOOP
    tainted_rels := tainted_rels || r.v; taint_root := taint_root || r.root; taint_why := taint_why || r.root;
  END LOOP;
  -- f. A view over a catalog the role cannot read itself (pg_statistic holds column values,
  --    pg_authid password hashes) reads it with the view owner's rights. Catalogs are pinned, so
  --    the relation oids come from the stored rule's range table.
  FOR r IN
    SELECT DISTINCT ON (rw.ev_class) rw.ev_class AS v, format('reads %I.%I, which the role cannot read itself', tn.nspname, t.relname) AS root
      FROM pg_rewrite rw JOIN pg_class v ON v.oid = rw.ev_class JOIN pg_namespace vn ON vn.oid = v.relnamespace,
           regexp_matches(rw.ev_action::text, ':relid ([0-9]+)', 'g') f
      JOIN pg_class t ON t.oid = f[1]::oid JOIN pg_namespace tn ON tn.oid = t.relnamespace
     WHERE rw.ev_type = '1' AND v.relkind IN ('v','m') AND t.oid <> rw.ev_class AND NOT rw.ev_class = ANY (tainted_rels)
       AND vn.nspname NOT IN ('pg_catalog', 'information_schema') AND vn.nspname !~ '^pg_(toast|temp)'
       AND tn.nspname IN ('pg_catalog', 'information_schema')
       AND NOT has_table_privilege(role_name, t.oid, 'SELECT')
     ORDER BY rw.ev_class, t.oid
  LOOP
    tainted_rels := tainted_rels || r.v; taint_root := taint_root || r.root; taint_why := taint_why || r.root;
  END LOOP;
  FOR r IN
    SELECT DISTINCT ON (rw.ev_class) rw.ev_class AS v, format('reads foreign table %s (foreign tables are never granted)', d.refobjid::regclass) AS root
      FROM pg_depend d JOIN pg_rewrite rw ON rw.oid = d.objid
      JOIN pg_class t ON t.oid = d.refobjid
     WHERE d.classid = 'pg_rewrite'::regclass AND d.refclassid = 'pg_class'::regclass AND rw.ev_type = '1'
       AND rw.ev_class <> d.refobjid AND t.relkind = 'f' AND NOT rw.ev_class = ANY (tainted_rels)
     ORDER BY rw.ev_class, d.refobjid
  LOOP
    tainted_rels := tainted_rels || r.v; taint_root := taint_root || r.root; taint_why := taint_why || r.root;
  END LOOP;
  -- g. A view reading a relation in a listed schema that the role is not granted (a sequence
  --    owned by a hidden column: its last_value tells the latest value) reads it with the view
  --    owner's rights. Tables with hidden columns (rules a, b), views (rule d) and foreign tables
  --    are handled apart; the grants for tables and sequences are already in place here.
  FOR r IN
    SELECT DISTINCT ON (rw.ev_class) rw.ev_class AS v,
           format('reads %s, which the role is not granted%s', d.refobjid::regclass,
                  CASE WHEN t.relkind = 'S' THEN ' (a sequence owned by a hidden column)' ELSE '' END) AS root
      FROM pg_depend d JOIN pg_rewrite rw ON rw.oid = d.objid
      JOIN pg_class t ON t.oid = d.refobjid JOIN pg_namespace tn ON tn.oid = t.relnamespace
     WHERE d.classid = 'pg_rewrite'::regclass AND d.refclassid = 'pg_class'::regclass AND rw.ev_type = '1'
       AND rw.ev_class <> d.refobjid AND NOT rw.ev_class = ANY (tainted_rels)
       AND tn.nspname = ANY (schemas) AND t.relkind IN ('r','p','S') AND NOT t.oid = ANY (hidden_rels)
       AND NOT CASE WHEN t.relkind = 'S' THEN has_sequence_privilege(role_name, t.oid, 'SELECT')
                    ELSE has_table_privilege(role_name, t.oid, 'SELECT') END
     ORDER BY rw.ev_class, d.refobjid
  LOOP
    tainted_rels := tainted_rels || r.v; taint_root := taint_root || r.root; taint_why := taint_why || r.root;
  END LOOP;
  LOOP
    n_new := 0;
    FOR r IN
      SELECT DISTINCT ON (rw.ev_class) rw.ev_class AS v, d.refobjid AS via
        FROM pg_depend d JOIN pg_rewrite rw ON rw.oid = d.objid
       WHERE d.classid = 'pg_rewrite'::regclass AND d.refclassid = 'pg_class'::regclass AND rw.ev_type = '1'
         AND d.refobjid = ANY (tainted_rels) AND rw.ev_class <> d.refobjid AND NOT rw.ev_class = ANY (tainted_rels)
       ORDER BY rw.ev_class, d.refobjid
    LOOP
      idx := array_position(tainted_rels, r.via);
      tainted_rels := tainted_rels || r.v;
      taint_root := taint_root || taint_root[idx];
      taint_why := taint_why || (taint_root[idx] || ' through view ' || r.via::regclass::text);
      n_new := n_new + 1;
    END LOOP;
    EXIT WHEN n_new = 0;
  END LOOP;

  -- A listed view or matview column makes sense only when the view is not already tainted.
  FOR r IN
    SELECT DISTINCT c.oid::regclass AS v FROM pg_class c WHERE c.oid = ANY (hidden_rels) AND c.oid = ANY (tainted_rels)
  LOOP
    RAISE EXCEPTION 'view % is in the hidden list but also %, so it gets no grant at all - remove its entries from the list',
      r.v, taint_why[array_position(tainted_rels, r.v::oid)];
  END LOOP;

  FOR r IN
    SELECT c.oid, n.nspname, c.relname, c.relkind
      FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = ANY (schemas) AND c.relkind IN ('v','m') AND NOT c.oid = ANY (hidden_rels)
     ORDER BY 2, 3
  LOOP
    idx := array_position(tainted_rels, r.oid);
    IF idx IS NOT NULL THEN
      RAISE NOTICE 'view % %: not granted', format('%I.%I', r.nspname, r.relname), taint_why[idx];
    ELSE
      EXECUTE format('GRANT SELECT ON TABLE %I.%I TO %I', r.nspname, r.relname, role_name);
      n_view := n_view + 1;
    END IF;
  END LOOP;

  -- Relations with a hidden column: SELECT on the visible columns only (foreign tables: nothing).
  FOR rel IN SELECT h FROM unnest(hidden_rels) h JOIN pg_class c ON c.oid = h WHERE c.relkind <> 'f' ORDER BY 1 LOOP
    SELECT string_agg(quote_ident(a.attname), ', ' ORDER BY a.attnum) INTO cols
      FROM pg_attribute a
     WHERE a.attrelid = rel AND a.attnum > 0 AND NOT a.attisdropped
       AND NOT (a.attrelid || '.' || a.attnum) = ANY (hidden);
    IF cols IS NOT NULL THEN
      EXECUTE format('GRANT SELECT (%s) ON TABLE %s TO %I', cols, rel::regclass, role_name);
    END IF;
  END LOOP;

  IF revoke_temp THEN
    EXECUTE format('REVOKE TEMP ON DATABASE %I FROM PUBLIC', current_database());
  END IF;
  IF revoke_create THEN
    FOREACH spec IN ARRAY schemas LOOP
      EXECUTE format('REVOKE CREATE ON SCHEMA %I FROM PUBLIC', spec);
      IF has_schema_privilege(role_name, spec, 'CREATE') THEN
        RAISE EXCEPTION 'REVOKE CREATE ON SCHEMA % FROM PUBLIC did not take effect (schema owned by %) - run this script as that owner or a superuser',
          quote_ident(spec), (SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname = spec);
      END IF;
    END LOOP;
  END IF;

  -- Self-check 1: no hidden column may be readable (children and partitions included).
  FOR i IN 1 .. coalesce(array_length(hidden, 1), 0) LOOP
    IF has_column_privilege(role_name, split_part(hidden[i], '.', 1)::oid, split_part(hidden[i], '.', 2)::int2, 'SELECT') THEN
      RAISE EXCEPTION 'self-check failed: % can still read % - another role may have granted it (REVOKE removes only your own grants): check \dp % and have that grantor revoke it',
        role_name, hidden_label[i], split_part(hidden[i], '.', 1)::oid::regclass;
    END IF;
  END LOOP;
  -- Self-check 2: the role must still read something on each relation with a hidden column.
  FOR r IN SELECT h AS rel FROM unnest(hidden_rels) h JOIN pg_class c ON c.oid = h WHERE c.relkind <> 'f' LOOP
    IF NOT has_any_column_privilege(role_name, r.rel, 'SELECT') THEN
      RAISE EXCEPTION 'self-check failed: % cannot read any column of % - leave at least one column (the primary key) visible', role_name, r.rel::regclass;
    END IF;
  END LOOP;
  -- Self-check 3: no tainted relation, anywhere in the database, may be readable.
  FOR i IN 1 .. coalesce(array_length(tainted_rels, 1), 0) LOOP
    IF has_any_column_privilege(role_name, tainted_rels[i], 'SELECT') THEN
      RAISE EXCEPTION 'self-check failed: % can read %, which %. It is granted by someone else or to PUBLIC: check \dp % and revoke it',
        role_name, tainted_rels[i]::regclass, taint_why[i], tainted_rels[i]::regclass;
    END IF;
  END LOOP;
  -- Self-check 4: every grant took effect (a GRANT by someone who does not own the table is a
  -- WARNING, not an error, and would leave the table unreadable).
  FOR r IN
    SELECT c.oid::regclass AS tbl, pg_get_userbyid(c.relowner) AS owner
      FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = ANY (schemas) AND c.relkind IN ('r','p') AND NOT c.oid = ANY (hidden_rels)
       AND NOT has_table_privilege(role_name, c.oid, 'SELECT')
  LOOP
    RAISE EXCEPTION 'self-check failed: GRANT on % did not take effect (owned by %) - run this script as that owner or a superuser', r.tbl, r.owner;
  END LOOP;
  -- Self-check 5: no default privileges and no direct grants outside the listed schemas remain
  -- (REVOKE removes only the grants of the user running it).
  IF EXISTS (SELECT 1 FROM pg_default_acl d, aclexplode(d.defaclacl) a WHERE a.grantee = role_oid) THEN
    RAISE EXCEPTION 'self-check failed: default privileges for % remain - see \ddp and run ALTER DEFAULT PRIVILEGES FOR ROLE <owner> REVOKE ALL ON TABLES FROM %', role_name, role_name;
  END IF;
  SELECT string_agg(format('%s (granted by %s)', c.oid::regclass, pg_get_userbyid(a.grantor)), ', ') INTO msg
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace, aclexplode(c.relacl) a
   WHERE a.grantee = role_oid AND NOT n.nspname = ANY (schemas)
     AND n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname !~ '^pg_(toast|temp)';
  IF msg IS NOT NULL THEN
    RAISE EXCEPTION 'self-check failed: % still holds privileges outside --schemas on: % - have that grantor revoke them, or add the schema to --schemas', role_name, msg;
  END IF;
  -- Self-check 5b: nothing outside --schemas is readable, whoever granted it (PUBLIC included).
  SELECT string_agg(c.oid::regclass::text, ', ' ORDER BY 1) INTO msg
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
   WHERE NOT n.nspname = ANY (schemas)
     AND n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname !~ '^pg_(toast|temp)'
     AND c.relkind IN ('r','p','v','m','f','S')
     AND has_schema_privilege(role_name, n.oid, 'USAGE')
     AND CASE WHEN c.relkind = 'S' THEN has_sequence_privilege(role_name, c.oid, 'SELECT, USAGE, UPDATE')
              ELSE has_any_column_privilege(role_name, c.oid, 'SELECT') END;
  IF msg IS NOT NULL THEN
    RAISE EXCEPTION 'self-check failed: % can read relation(s) outside --schemas (granted to PUBLIC or by another role): %. Revoke those grants (REVOKE ... FROM PUBLIC), or add the schema to --schemas and re-run', role_name, msg;
  END IF;
  -- Self-check 5c: no write privilege anywhere, whoever granted it. With read-only turned off the
  -- role could use any of them: INSERT/UPDATE/DELETE/TRUNCATE/TRIGGER (MAINTAIN on 17+) on a
  -- relation, INSERT/UPDATE on a single column (has_table_privilege does not see column grants),
  -- USAGE/UPDATE on a sequence (nextval, setval).
  SELECT string_agg(c.oid::regclass::text, ', ' ORDER BY 1) INTO msg
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
   WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname !~ '^pg_(toast|temp)'
     AND CASE WHEN c.relkind = 'S' THEN has_sequence_privilege(role_name, c.oid, 'USAGE, UPDATE')
              WHEN c.relkind IN ('r','p','v','m','f') THEN has_table_privilege(role_name, c.oid, write_privs)
                                                        OR has_any_column_privilege(role_name, c.oid, 'INSERT, UPDATE')
              ELSE false END;
  IF msg IS NOT NULL THEN
    RAISE EXCEPTION 'self-check failed: % could write (%, INSERT/UPDATE on a column, or USAGE/UPDATE on a sequence) to: %. These come from PUBLIC or another grantor: revoke them (REVOKE ... FROM PUBLIC; a column grant needs REVOKE INSERT (col), UPDATE (col) ON ... FROM PUBLIC), then re-run', role_name, write_privs, msg;
  END IF;
  -- Self-check 5d: large objects. SELECT on one is a read this script does not control.
  IF current_setting('lo_compat_privileges') = 'on' THEN
    RAISE EXCEPTION 'self-check failed: lo_compat_privileges is on, so % can read and write every large object - turn it off', role_name;
  END IF;
  SELECT count(*)::text INTO msg
    FROM pg_largeobject_metadata l, aclexplode(l.lomacl) a
   WHERE a.grantee IN (0, role_oid);
  IF msg <> '0' THEN
    RAISE EXCEPTION 'self-check failed: % large object privilege(s) are granted to PUBLIC or %: see SELECT oid, lomacl FROM pg_largeobject_metadata and revoke them', msg, role_name;
  END IF;
  -- Self-check 5e: foreign servers. USAGE on a server (or on a wrapper, to create one) and a user
  -- mapping for the role or PUBLIC let dblink / postgres_fdw connect with stored credentials and
  -- read whatever that login reads, hidden columns included.
  SELECT string_agg(x, '; ' ORDER BY x) INTO msg FROM (
    SELECT format('USAGE on foreign server %I', s.srvname) AS x FROM pg_foreign_server s WHERE has_server_privilege(role_name, s.oid, 'USAGE')
    UNION ALL
    SELECT format('USAGE on foreign-data wrapper %I', w.fdwname) FROM pg_foreign_data_wrapper w WHERE has_foreign_data_wrapper_privilege(role_name, w.oid, 'USAGE')
    UNION ALL
    SELECT format('user mapping for %s on server %I', CASE WHEN u.umuser = 0 THEN 'PUBLIC' ELSE quote_ident(role_name) END, u.srvname)
      FROM pg_user_mappings u WHERE u.umuser IN (0, role_oid)) q;
  IF msg IS NOT NULL THEN
    RAISE EXCEPTION 'self-check failed: % can reach foreign servers: %. Revoke it (REVOKE USAGE ON FOREIGN SERVER s FROM PUBLIC, %; DROP USER MAPPING FOR PUBLIC SERVER s), then re-run', role_name, msg, quote_ident(role_name);
  END IF;
  -- Self-check 5f: default privileges for PUBLIC. A table, sequence or schema created later would
  -- be readable (or writable) at once, before anyone reviews its columns. Functions and types are
  -- EXECUTE / USAGE to PUBLIC by Postgres' own default; only those two entries are expected.
  SELECT string_agg(DISTINCT format('%s on %s%s (set by %s)', a.privilege_type,
           CASE d.defaclobjtype WHEN 'r' THEN 'tables' WHEN 'S' THEN 'sequences' WHEN 'f' THEN 'functions' WHEN 'T' THEN 'types' WHEN 'n' THEN 'schemas' ELSE d.defaclobjtype::text END,
           CASE WHEN d.defaclnamespace = 0 THEN '' ELSE ' in schema ' || quote_ident((SELECT nspname FROM pg_namespace WHERE oid = d.defaclnamespace)) END,
           pg_get_userbyid(d.defaclrole)), '; ') INTO msg
    FROM pg_default_acl d, aclexplode(d.defaclacl) a
   WHERE a.grantee = 0
     AND NOT (d.defaclobjtype = 'f' AND a.privilege_type = 'EXECUTE')
     AND NOT (d.defaclobjtype = 'T' AND a.privilege_type = 'USAGE');
  IF msg IS NOT NULL THEN
    RAISE EXCEPTION 'self-check failed: default privileges grant PUBLIC (so %) access to every new object: %. See \ddp; as that owner run ALTER DEFAULT PRIVILEGES [IN SCHEMA s] REVOKE ALL ON TABLES FROM PUBLIC (or SEQUENCES / SCHEMAS), then re-run', role_name, msg;
  END IF;
  -- Self-check 5g: system catalogs as a fresh cluster set them up. pg_init_privs holds the
  -- privileges initdb gave each pg_catalog object (a NULL there means Postgres' default);
  -- information_schema relations are SELECT to PUBLIC. Any other grant to PUBLIC or the role
  -- (SELECT on pg_statistic, pg_authid or pg_largeobject, EXECUTE on pg_read_file, ...) opens
  -- what the hidden list and the grants above close.
  SELECT string_agg(DISTINCT x, ', ') INTO msg FROM (
    SELECT format('%s on %s.%I%s to %s', a.privilege_type, cn.nspname, c.relname,
                  CASE WHEN o.sub = 0 THEN '' ELSE format(' (%I)', (SELECT attname FROM pg_attribute WHERE attrelid = c.oid AND attnum = o.sub)) END,
                  CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE quote_ident(role_name) END) AS x
      FROM pg_class c JOIN pg_namespace cn ON cn.oid = c.relnamespace,
           LATERAL (SELECT 0::int2 AS sub, c.relacl AS acl, acldefault(CASE WHEN c.relkind = 'S' THEN 's' ELSE 'r' END::"char", c.relowner) AS dflt
                    UNION ALL
                    SELECT pa.attnum, pa.attacl, NULL::aclitem[] FROM pg_attribute pa WHERE pa.attrelid = c.oid AND pa.attnum > 0 AND pa.attacl IS NOT NULL) o,
           aclexplode(o.acl) a
     WHERE cn.nspname IN ('pg_catalog', 'information_schema') AND a.grantee IN (0, role_oid)
       AND NOT (cn.nspname = 'information_schema' AND a.grantee = 0 AND a.privilege_type = 'SELECT' AND o.sub = 0)
       AND NOT EXISTS (SELECT 1 FROM aclexplode(coalesce((SELECT i.initprivs FROM pg_init_privs i
                                                           WHERE i.classoid = 'pg_class'::regclass AND i.objoid = c.oid AND i.objsubid = o.sub), o.dflt)) b
                        WHERE b.grantee = a.grantee AND b.privilege_type = a.privilege_type)
    UNION ALL
    SELECT format('%s on function %s to %s', a.privilege_type, p.oid::regprocedure, CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE quote_ident(role_name) END)
      FROM pg_proc p JOIN pg_namespace pn ON pn.oid = p.pronamespace, aclexplode(p.proacl) a
     WHERE pn.nspname IN ('pg_catalog', 'information_schema') AND a.grantee IN (0, role_oid)
       AND NOT EXISTS (SELECT 1 FROM aclexplode(coalesce((SELECT i.initprivs FROM pg_init_privs i
                                                           WHERE i.classoid = 'pg_proc'::regclass AND i.objoid = p.oid AND i.objsubid = 0),
                                                          acldefault('f', p.proowner))) b
                        WHERE b.grantee = a.grantee AND b.privilege_type = a.privilege_type)) q;
  IF msg IS NOT NULL THEN
    RAISE EXCEPTION 'self-check failed: system catalog privileges beyond a fresh cluster''s: %. Revoke each (e.g. REVOKE SELECT ON pg_catalog.pg_statistic FROM PUBLIC), then re-run', msg;
  END IF;
  -- Self-check 6: SECURITY DEFINER functions run as their owner and bypass every grant above.
  -- PUBLIC can EXECUTE every function by default, so the role can call them too, in ANY schema:
  -- a view calls a function without the caller needing USAGE on the function's schema.
  SELECT string_agg(p.oid::regprocedure::text, ', ' ORDER BY p.oid::regprocedure::text) INTO msg
    FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
   WHERE p.prosecdef AND n.nspname NOT IN ('pg_catalog', 'information_schema')
     AND has_function_privilege(role_name, p.oid, 'EXECUTE');
  IF msg IS NOT NULL AND NOT allow_definer THEN
    RAISE EXCEPTION E'self-check failed: % can execute SECURITY DEFINER function(s): %.\nEither lock each one down:  REVOKE EXECUTE ON FUNCTION f(args) FROM PUBLIC; GRANT EXECUTE ON FUNCTION f(args) TO <app role>;\nor acknowledge the risk:    daypass sql --allow-definer-functions', role_name, msg;
  ELSIF msg IS NOT NULL THEN
    RAISE NOTICE 'acknowledged (--allow-definer-functions): % can execute SECURITY DEFINER function(s): %', role_name, msg;
  END IF;

  -- Store what this run hid on the role, per database, for `daypass doctor`. COMMENT ON ROLE
  -- needs CREATEROLE / ADMIN OPTION, which the read-only role does not have, so it cannot edit it.
  BEGIN
    existing := shobj_description(role_oid, 'pg_authid')::jsonb;
  EXCEPTION WHEN others THEN
    existing := NULL;
  END;
  IF existing IS NULL OR jsonb_typeof(existing) <> 'object' OR NOT existing ? 'daypass' THEN
    IF shobj_description(role_oid, 'pg_authid') IS NOT NULL THEN
      RAISE NOTICE 'replacing the comment on role % (it was not written by Daypass): %', role_name, shobj_description(role_oid, 'pg_authid');
    END IF;
    existing := '{}'::jsonb;
  END IF;
  EXECUTE format('COMMENT ON ROLE %I IS %L', role_name,
    jsonb_build_object('daypass', 1, 'databases',
      coalesce(existing -> 'databases', '{}'::jsonb) || jsonb_build_object(current_database(), manifest_in::jsonb))::text);

  RAISE NOTICE 'hidden columns verified: % columns across % relations (children and partitions included); % tables and % views granted in schema(s) %',
    coalesce(array_length(hidden, 1), 0), coalesce(array_length(hidden_rels, 1), 0), n_rel, n_view, array_to_string(schemas, ', ');
END $$;

-- 5. Report
DO $$
DECLARE
  role_name constant text := '__ROLE__';
  msg text;
  fn_schemas text;
BEGIN
  RAISE NOTICE 'role % can create temp tables: % (PUBLIC holds TEMP on most databases; daypass sql --revoke-public-temp removes it)',
    role_name, CASE WHEN has_database_privilege(role_name, current_database(), 'TEMP') THEN 'yes' ELSE 'no' END;
  SELECT string_agg(quote_ident(n.nspname), ', ' ORDER BY n.nspname) INTO msg
    FROM pg_namespace n
   WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname !~ '^pg_(toast|temp)'
     AND has_schema_privilege(role_name, n.oid, 'CREATE');
  IF msg IS NULL THEN
    RAISE NOTICE 'role % can create objects in schema(s): none', role_name;
  ELSE
    RAISE NOTICE 'role % can create objects in schema(s) % (PUBLIC holds CREATE on public up to PostgreSQL 14; daypass sql --revoke-public-create removes it on the listed schemas)', role_name, msg;
  END IF;
  IF has_database_privilege(role_name, current_database(), 'CREATE') THEN
    RAISE NOTICE 'warning: role % can create schemas in this database: REVOKE CREATE ON DATABASE % FROM PUBLIC, %', role_name, quote_ident(current_database()), quote_ident(role_name);
  END IF;
  RAISE NOTICE 'role settings (default_transaction_read_only, statement_timeout, idle_in_transaction_session_timeout, lock_timeout, temp_file_limit) are defaults the role can change for itself; they bound the agent through the MCP client, not a direct psql session. daypass doctor reports drift.';
  RAISE NOTICE 'the role can change its own password (core Postgres); on RDS, rds.restrict_password_commands = 1 in the parameter group blocks that.';
  -- Functions are EXECUTE-to-PUBLIC by default: extension and app functions are callable by the
  -- role, and one that takes SQL as text runs whatever it is handed. Guidance only, nothing revoked.
  SELECT count(*)::text, string_agg(DISTINCT quote_ident(n.nspname), ', ') INTO msg, fn_schemas
    FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
   WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname !~ '^pg_(toast|temp)'
     AND p.prokind IN ('f', 'p') AND has_function_privilege(role_name, p.oid, 'EXECUTE');
  IF msg <> '0' THEN
    RAISE NOTICE 'role % can execute % function(s) outside pg_catalog (schemas: %); the MCP guard cannot see what they do. daypass doctor lists them. To lock them down: REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA <s> FROM PUBLIC; then GRANT EXECUTE to the roles that need them (not done here).',
      role_name, msg, fn_schemas;
  END IF;
  IF has_function_privilege(role_name, 'pg_catalog.lo_create(oid)', 'EXECUTE') THEN
    RAISE NOTICE 'role % can create large objects once it turns read-only off (core Postgres needs no privilege for that; REVOKE EXECUTE ON FUNCTION lo_create(oid), lo_creat(integer), lo_from_bytea(oid, bytea) FROM PUBLIC blocks it for every role)', role_name;
  END IF;
END $$;
SELECT rolname, rolconnlimit, rolconfig FROM pg_roles WHERE rolname = '__ROLE__';
-- Relations per owner: a GRANT by someone who does not own the table does not take effect (the
-- self-check above fails in that case). Run this script as the owner of your tables.
SELECT n.nspname AS schema, pg_get_userbyid(c.relowner) AS owner, c.relkind AS kind, count(*) AS relations,
       (pg_get_userbyid(c.relowner) = current_user) AS owned_by_you
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE c.relkind IN ('r','p','v','m') AND n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg_toast%'
 GROUP BY 1, 2, 3 ORDER BY 1, 4 DESC;

-- 6. Once more, just before COMMIT: the role still owns nothing and belongs to nothing (it could
--    have created an object or been granted a role while this transaction ran), holds none of
--    the five dangerous attributes, and its rds_iam membership reaches nothing.
DO $$
DECLARE
  role_oid oid := (SELECT oid FROM pg_roles WHERE rolname = '__ROLE__');
  iam_oid  oid := (SELECT oid FROM pg_roles WHERE rolname = 'rds_iam');
  msg text;
BEGIN
  SELECT concat_ws(', ', CASE WHEN rolsuper THEN 'SUPERUSER' END, CASE WHEN rolreplication THEN 'REPLICATION' END,
                         CASE WHEN rolbypassrls THEN 'BYPASSRLS' END, CASE WHEN rolcreatedb THEN 'CREATEDB' END,
                         CASE WHEN rolcreaterole THEN 'CREATEROLE' END)
    INTO msg FROM pg_roles WHERE oid = role_oid;
  IF msg <> '' THEN
    RAISE EXCEPTION 'self-check failed: role % still has %: as a superuser run ALTER ROLE % WITH NOSUPERUSER NOREPLICATION NOBYPASSRLS NOCREATEDB NOCREATEROLE; then re-run',
      '__ROLE__', msg, quote_ident('__ROLE__');
  END IF;
  IF iam_oid IS NOT NULL AND pg_has_role('__ROLE__', 'rds_iam', 'MEMBER') THEN
    IF current_setting('server_version_num')::int >= 160000 THEN
      -- IAM login needs the membership only: no SET, INHERIT or ADMIN on any grant of it.
      SELECT string_agg(format('granted by %s with %s', pg_get_userbyid(m.grantor),
                               concat_ws(', ', CASE WHEN m.set_option THEN 'SET' END, CASE WHEN m.inherit_option THEN 'INHERIT' END,
                                               CASE WHEN m.admin_option THEN 'ADMIN' END)), '; ') INTO msg
        FROM pg_auth_members m WHERE m.roleid = iam_oid AND m.member = role_oid AND (m.set_option OR m.inherit_option OR m.admin_option);
      IF msg IS NOT NULL THEN
        RAISE EXCEPTION 'self-check failed: role % can use the privileges of rds_iam (%): IAM login needs only the membership. Have that grantor run: REVOKE rds_iam FROM %; then re-run (it grants rds_iam WITH INHERIT FALSE, SET FALSE)',
          '__ROLE__', msg, quote_ident('__ROLE__');
      END IF;
    ELSE
      -- Before PostgreSQL 16 a member can always SET ROLE rds_iam, so rds_iam itself must hold
      -- nothing: no privilege or default privilege on any object, no owned object or user
      -- mapping (pg_shdepend, every database), no membership in another role, no attribute.
      SELECT string_agg(x, '; ' ORDER BY x) INTO msg FROM (
        SELECT CASE WHEN d.dbid = (SELECT oid FROM pg_database WHERE datname = current_database()) OR d.dbid = 0
                    THEN CASE d.deptype WHEN 'o' THEN 'owns ' ELSE 'is named in the privileges of ' END || pg_describe_object(d.classid, d.objid, d.objsubid)
                    ELSE format('%s an object in database %s', CASE d.deptype WHEN 'o' THEN 'owns' ELSE 'has privileges on' END,
                                (SELECT quote_ident(datname) FROM pg_database WHERE oid = d.dbid)) END AS x
          FROM pg_shdepend d WHERE d.refclassid = 'pg_authid'::regclass AND d.refobjid = iam_oid
        UNION ALL
        SELECT 'is a member of ' || quote_ident(r.rolname) FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.roleid WHERE m.member = iam_oid
        UNION ALL
        SELECT 'has attribute ' || a FROM pg_roles r,
               unnest(ARRAY[CASE WHEN r.rolsuper THEN 'SUPERUSER' END, CASE WHEN r.rolreplication THEN 'REPLICATION' END,
                            CASE WHEN r.rolbypassrls THEN 'BYPASSRLS' END, CASE WHEN r.rolcreatedb THEN 'CREATEDB' END,
                            CASE WHEN r.rolcreaterole THEN 'CREATEROLE' END]) a
         WHERE r.oid = iam_oid AND a IS NOT NULL) q;
      IF msg IS NOT NULL THEN
        RAISE EXCEPTION 'self-check failed: role % is a member of rds_iam and, before PostgreSQL 16, can SET ROLE rds_iam; rds_iam must hold nothing, but it: %. Revoke those from rds_iam, then re-run',
          '__ROLE__', msg;
      END IF;
    END IF;
  END IF;
  SELECT string_agg(pg_describe_object(d.classid, d.objid, d.objsubid), '; ' ORDER BY pg_describe_object(d.classid, d.objid, d.objsubid)) INTO msg
    FROM pg_shdepend d
   WHERE d.refclassid = 'pg_authid'::regclass AND d.refobjid = role_oid AND d.deptype = 'o'
     AND d.dbid IN (0, (SELECT oid FROM pg_database WHERE datname = current_database()));
  IF msg IS NOT NULL THEN
    RAISE EXCEPTION 'role % owns objects in this database: %. A read-only role should own nothing (it can plant objects while it holds CREATE on a schema). Inspect them, then as the owner run: DROP OWNED BY %; and re-run this script (it re-grants what it needs).',
      '__ROLE__', msg, quote_ident('__ROLE__');
  END IF;
  IF EXISTS (SELECT 1 FROM pg_shdepend d WHERE d.refclassid = 'pg_authid'::regclass AND d.refobjid = role_oid AND d.deptype = 'o'
              AND d.dbid NOT IN (0, (SELECT oid FROM pg_database WHERE datname = current_database()))) THEN
    RAISE NOTICE 'role % owns objects in another database on this server: run this script there too, or DROP OWNED BY % in it', '__ROLE__', quote_ident('__ROLE__');
  END IF;
  SELECT string_agg(DISTINCT r.rolname, ', ') INTO msg
    FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.roleid
   WHERE m.member = role_oid AND r.rolname <> 'rds_iam';
  IF msg IS NOT NULL THEN
    RAISE EXCEPTION 'role % is a member of %: it can SET ROLE to them and use their privileges (NOINHERIT does not stop SET ROLE). Revoke it: REVOKE <role> FROM %; then re-run',
      '__ROLE__', msg, quote_ident('__ROLE__');
  END IF;
END $$;

COMMIT;
