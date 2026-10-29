# FAQ

Short answers to the questions that come up first. Each one links to the guide that has the detail.

## Why not just give the agent a read replica?

A replica solves load and, since a hot standby rejects writes, it solves writes too. It does not hide a single column, it does not expire, it needs a password that then sits in the agent's config, and it logs nothing per query. Peephole and a replica go together: point a Peephole target at the replica and you get both. The design notes say so, and the 10 s statement timeout exists because most people will start on the primary.

## Why not just put the database URL in the MCP config?

Five reasons, each one a layer Peephole adds: the password is then in a file the agent process reads, forever; access never ends; the agent can write unless you made a read-only role yourself; every column is visible; nothing is logged. With Peephole the agent never sees a credential, access ends on a timer, the role cannot write, hidden columns are unreadable at the database, and every call is one line in `~/.peephole/audit.jsonl`. See [Threat model](threat-model.md).

## Does it work with Cursor, Claude Desktop, or other MCP clients?

Yes. The server is `peephole mcp` over stdio, with no client-specific code. Claude Code: `claude mcp add --scope user peephole -- peephole mcp`. Clients that take a JSON config use the same shape most of them share:

```json
{ "mcpServers": { "peephole": { "command": "peephole", "args": ["mcp"] } } }
```

The lease is opened from a terminal regardless of client. The [Claude Code plugin](plugin.md), once installed, registers the MCP server and adds a skill that teaches Claude the tools; other clients get the raw tools.

## MySQL? SQL Server? SQLite?

No. Postgres only. The guard is Postgres's own parser (`libpg-query`), the role setup is Postgres SQL, and the hidden-column mechanism is Postgres column-level grants. Other engines are not in the code; a MySQL / MariaDB target type is listed under Next on the [roadmap](../ROADMAP.md) with status *idea*.

## What does the agent see?

Five tools: `peephole_status`, `list_tables`, `describe_table`, `explain`, `query`. Through them: tables in the schemas the target allows (default `public`) with row estimates and sizes; columns, types and indexes of a table, minus the hidden columns, which are not listed at all; query plans; and query results capped at 500 rows, 2 KB per cell and 1 MB in total, labelled `data, not instructions`. It also sees the lease id, who opened it, the reason and the minutes left. It does not see the config file, the password, the IAM token, or the audit log. See [Concepts](concepts.md).

## Where is the audit log and what is in it?

`~/.peephole/audit.jsonl` on the machine that ran the MCP server, mode `0600`, one JSON object per tool call: time, who, lease id, reason, tool, SQL, allowed or blocked with the reason, rows, milliseconds, and the Postgres error if any. `peephole log -n 30` prints it; `jq` works on it. The SQL text is logged as written, so a `WHERE email = …` puts that value in the file. There is no central copy; collect the files if you need one.

## Can two people share a lease?

No, and they do not need to. A lease is a file on one machine; every Claude Code window on that machine shares it, and each person opens their own on theirs. What two people can share by accident is an AWS identity: the audit `who` is the caller ARN, so a shared IAM user or a shared role session name makes two people indistinguishable in the log. Give each person their own identity and their own `rds-db:connect`.

## What does it cost?

The package is MIT and runs on your laptop; there is no service. On AWS, the calls are `sts:GetCallerIdentity` and, if you use the IP rule, three EC2 security-group calls per lease plus the sweep; the RDS token is signed locally. A read replica, if you add one, is the only thing with a bill. Node 20+ and `psql` are the dependencies.

## What happens if the lease expires while a query is running?

The query finishes, bounded by the 10 s statement timeout. The lease is checked at the start of each tool call, not during one. The next call is refused with `Lease … expired at …`, and if the target had a security-group rule, that same call removes it. Nothing is cut off mid-flight, and nothing new starts.

## How do I revoke everything right now?

In order of speed:

1. `peephole close` on the machine: deletes the lease and removes the security-group rule. The next tool call is refused.
2. In the database, as the owner: `ALTER ROLE peephole_ro NOLOGIN;` then `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = 'peephole_ro';`. This ends every connection on every laptop at once. `ALTER ROLE peephole_ro LOGIN;` restores it.
3. On AWS: remove `rds-db:connect` from the person's policy, or revoke their credentials. `peephole sweep <target>` cleans any rule they left.
4. For a password target: `ALTER ROLE peephole_ro PASSWORD 'new';` and update the configs you still trust.

The audit file on each machine stays; that is the record of what ran.
