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
-- SUPERUSER / REPLICATION / BYPASSRLS are not named here: a new role never has them, and on
-- RDS the master user is not a superuser, so even "NOSUPERUSER" is refused.
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

-- RDS only. On plain Postgres (local dev) rds_iam does not exist and this is skipped. A re-run
-- skips the GRANT when the role is already a member (PG 16 would need ADMIN OPTION on rds_iam).
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rds_iam') THEN
    RAISE NOTICE 'rds_iam role not found (not RDS?) - IAM grant skipped';
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
  SELECT string_agg(format('%s.%I (generated from %s.%I)', d.objid::regclass, ga.attname, d.refobjid::regclass, ha.attname), ', '
                    ORDER BY d.objid, d.objsubid) INTO msg
    FROM pg_depend d
    JOIN pg_attribute ga ON ga.attrelid = d.objid AND ga.attnum = d.objsubid
    JOIN pg_attribute ha ON ha.attrelid = d.refobjid AND ha.attnum = d.refobjsubid
   WHERE d.classid = 'pg_class'::regclass AND d.refclassid = 'pg_class'::regclass
     AND d.objsubid > 0 AND d.refobjsubid > 0
     AND (d.refobjid || '.' || d.refobjsubid) = ANY (hidden)
     AND NOT (d.objid || '.' || d.objsubid) = ANY (hidden);
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
  -- e. A materialized view stores what its query returned when the OWNER last refreshed it, so
  --    every function it calls ran with the owner's rights: one outside pg_catalog, or a
  --    built-in that reads data by name (query_to_xml, lo_get, ...), taints it. Built-ins are
  --    pinned and pg_depend does not record them, so the function oids come from the stored rule.
  --    Plain views are not affected: functions in them run as the caller.
  FOR r IN
    SELECT DISTINCT ON (rw.ev_class) rw.ev_class AS v,
           format('calls function %s (a materialized view stores what it returned when the owner refreshed it)', CASE WHEN pn.nspname = 'pg_catalog' THEN 'pg_catalog.' ELSE '' END || p.oid::regprocedure::text) AS root
      FROM pg_rewrite rw JOIN pg_class mv ON mv.oid = rw.ev_class,
           regexp_matches(rw.ev_action::text, ':(funcid|opfuncid|aggfnoid|winfnoid) ([0-9]+)', 'g') f
      JOIN pg_proc p ON p.oid = f[2]::oid JOIN pg_namespace pn ON pn.oid = p.pronamespace
     WHERE rw.ev_type = '1' AND mv.relkind = 'm' AND NOT rw.ev_class = ANY (tainted_rels)
       AND (pn.nspname <> 'pg_catalog' OR p.proname ~ '^((query|cursor|table|schema|database)_to_xml|ts_(stat|rewrite)$|lo_|pg_read_|pg_ls_|pg_stat_file$|pg_stat_get_activity$|current_setting$|dblink|crosstab|xpath_table$)')
     ORDER BY rw.ev_class, (pn.nspname = 'pg_catalog'), p.oid
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
  -- relation, USAGE/UPDATE on a sequence (nextval, setval).
  SELECT string_agg(c.oid::regclass::text, ', ' ORDER BY 1) INTO msg
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
   WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname !~ '^pg_(toast|temp)'
     AND CASE WHEN c.relkind = 'S' THEN has_sequence_privilege(role_name, c.oid, 'USAGE, UPDATE')
              WHEN c.relkind IN ('r','p','v','m','f') THEN has_table_privilege(role_name, c.oid, write_privs)
              ELSE false END;
  IF msg IS NOT NULL THEN
    RAISE EXCEPTION 'self-check failed: % could write (%, or USAGE/UPDATE on a sequence) to: %. These come from PUBLIC or another grantor: revoke them (REVOKE ... FROM PUBLIC), then re-run', role_name, write_privs, msg;
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
--    have created an object or been granted a role while this transaction ran).
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
END $$;

COMMIT;
