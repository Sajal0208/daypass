# Other Postgres

Peephole works with any Postgres you can reach over TCP: self-managed, Supabase, Neon, Railway, a Docker container on your laptop. Without AWS IAM there is no token login, so the read-only role gets a password and the target is a URL. The role setup, the guard, the caps and the audit are the same as on RDS; only the login and the TLS source differ.

## Target config

```json
{
  "targets": {
    "staging": {
      "url": "postgres://peephole_ro:CHANGE-ME@staging-db.example.com:5432/app"
    }
  }
}
```

The URL is parsed for host, port, database, user and password. Explicit fields (`host`, `port`, `database`, `user`, `password`, `ssl`, `sslCa`, `schemas`, `maxRows`, `maxCell`, `maxBytes`) override what the URL says. `postgresql://` is accepted as well. A target needs either `region` or a password; otherwise `doctor` reports `Target "staging" needs either "region" (RDS IAM auth) or a password`.

## The password role

`peephole sql` creates the role without a password. For a non-RDS target, set one once after the first run; re-runs keep it:

```bash
peephole sql --hide-file hidden-columns.txt | psql -X "$OWNER_URL" -v ON_ERROR_STOP=1
psql "$OWNER_URL" -c "ALTER ROLE peephole_ro PASSWORD 'CHANGE-ME'"
```

One thing to know:

- The password sits in `~/.peephole/config.json` (mode `0600`) on each developer's machine. It never goes to the agent: the MCP server reads the config itself and the tools expose no connection details. It does mean the password is a shared secret with no expiry; rotate it when someone leaves. If you want "leaving the company revokes access" without rotation, that is what RDS IAM gives you.

The role has `CONNECTION LIMIT 5`. Each running MCP server holds at most 2 connections, so two Claude Code sessions on two laptops fit; a third process can hit `too many connections for role "peephole_ro"`.

## TLS

TLS is always verified; the only way to turn it off is `sslmode=disable` in the URL or `"ssl": false` on the target. Other `sslmode` values are not interpreted: `sslmode=require` still results in full certificate verification, which is stricter than what `psql` does with the same word.

Verification uses the system CA store. If the server's certificate comes from the provider's own CA, `doctor` fails at `db login` with a certificate error (`self-signed certificate in certificate chain` or similar). Download the provider's CA bundle and point the target at it:

```json
{
  "targets": {
    "staging": {
      "url": "postgres://peephole_ro:CHANGE-ME@staging-db.example.com:5432/app",
      "sslCa": "/home/alice/.peephole/staging-ca.pem"
    }
  }
}
```

`sslCa` is a path to a PEM file; it is read on every pool creation. Do not disable verification to work around a certificate error: the password travels in the TLS session.

## Connection poolers

Peephole sends its session settings (`default_transaction_read_only`, `statement_timeout`, `idle_in_transaction_session_timeout`, `lock_timeout`) as a startup `options` parameter on every connection. Some poolers reject startup parameters they do not know. If `db login` fails with a message about an unsupported startup parameter, use the provider's direct (non-pooled) host and port. The role-level settings in `setup-role.sql` are the same values, so a pooler that does accept the connection still enforces them.

## Supabase

- The direct connection and the session-mode pooler expose Postgres on different hosts and ports; the dashboard shows both. Start with the direct connection.
- Run the role setup with the `postgres` user's URL as `$OWNER_URL`. Tables created by Supabase migrations may be owned by another role; the owner report at the end of the setup output tells you whether `ALTER DEFAULT PRIVILEGES` covers them.
- If `db login` reports a certificate error, the direct connection is using a certificate your system does not trust. Download the CA certificate from the project's database settings and set `sslCa`.
- For anything else, check Supabase's docs.

## Neon

- Neon requires TLS; its connection strings carry `sslmode=require`. Peephole verifies the certificate regardless. If `db login` reports a certificate error, set `sslCa` as above.
- Neon offers a pooled host (PgBouncer) and a direct host. Use the direct host for Peephole; see "Connection poolers" above.
- Role creation needs the owning role of the database; run the setup with that role's URL.
- For anything else, check Neon's docs.

## Railway

- Railway exposes Postgres through a public TCP proxy on a non-standard port; the URL in the service's variables has the right host and port.
- Whether TLS is offered on that proxy, and with which certificate, depends on the template and version. If `db login` fails with `The server does not support SSL connections`, the endpoint has no TLS; Peephole will not fall back to plaintext over the internet, so use a private network path or a different host. If it fails with a certificate error, see `sslCa` above. Check Railway's docs for the current behaviour.

## Local development

A Postgres on your own machine has no TLS, so disable it explicitly:

```json
{
  "targets": {
    "local": {
      "url": "postgres://peephole_ro:ro-pass@localhost:5432/app?sslmode=disable"
    }
  }
}
```

This is the only place `sslmode=disable` belongs. A quick end-to-end check against a throwaway container, close to what CI runs:

```bash
docker run --rm -d --name pg-peephole -e POSTGRES_PASSWORD=postgres -p 5432:5432 postgres:16
export OWNER_URL=postgres://postgres:postgres@localhost:5432/postgres
npm run build                  # from a checkout of the repo
scripts/ci-integration.sh
docker rm -f pg-peephole
```

The script creates a `customers` table with an `email` and a `secret` column, hides both, opens a lease, runs `doctor`, drives the MCP server through visible, hidden, write, multi-statement and expired cases, and prints `integration: OK`.
