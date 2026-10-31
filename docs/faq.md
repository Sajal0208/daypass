# FAQ

Short answers to the questions that come up first. Each one links to the guide that has the detail.

## Why not just give the agent a read replica?

A replica solves load and, since a hot standby rejects writes, it solves writes too. It does not hide a single column, it does not expire, it needs a password that then sits in the agent's config, and it logs nothing per query. Daypass and a replica go together: point a Daypass target at the replica and you get both. The design notes say so, and the 10 s statement timeout exists because most people will start on the primary.

## Why not just put the database URL in the MCP config?

Five reasons, each one a layer Daypass adds: the password is then in a file the agent process reads, forever; access never ends; the agent can write unless you made a read-only role yourself; every column is visible; nothing is logged. With Daypass the tools never hand the agent a credential, access ends on a timer, the role holds no write privilege and every call runs read-only, hidden columns are unreadable at the database, and every database call is logged in `~/.daypass/audit.jsonl` before it runs and when it ends. (An agent you also let run shell commands as you can still read the config file; see the [threat model](threat-model.md).) See [Threat model](threat-model.md).

## Does it work with Cursor, Claude Desktop, or other MCP clients?

Yes. The server is `daypass mcp` over stdio, with no client-specific code. Claude Code: `claude mcp add --scope user daypass -- daypass mcp`. Clients that take a JSON config use the same shape most of them share:

```json
{ "mcpServers": { "daypass": { "command": "daypass", "args": ["mcp"] } } }
```

The lease is opened from a terminal regardless of client. The [Claude Code plugin](plugin.md), once installed, registers the MCP server and adds a skill that teaches Claude the tools; other clients get the raw tools.

## MySQL? SQL Server? SQLite?

No. Postgres only. The guard is Postgres's own parser (`libpg-query`), the role setup is Postgres SQL, and the hidden-column mechanism is Postgres column-level grants. Other engines are not in the code; a MySQL / MariaDB target type is listed under Next on the [roadmap](../ROADMAP.md) with status *idea*.

## What does the agent see?

Five tools: `daypass_status`, `list_tables`, `describe_table`, `explain`, `query`. Through them: tables in the schemas the target allows (default `public`) with row estimates and sizes; columns, types and indexes of a table, minus the hidden columns and the indexes on them; query plans; and query results capped at 500 rows and 1 MB in total (cut in the database) and 2000 characters per cell, labelled `data, not instructions`. It also sees the lease id, who opened it, the reason and the minutes left. No tool returns the config file, the password, the IAM token, or the audit log. Two caveats: a query against the system catalog (`information_schema.columns`, `pg_indexes`) shows the *names* of hidden columns, never their values; and an agent that may also run shell commands or read files as you can read `~/.daypass` directly, which the tools do not control. See [Concepts](concepts.md) and the [threat model](threat-model.md).

## Where is the audit log and what is in it?

`~/.daypass/audit.jsonl` on the machine that ran the MCP server, mode `0600`. An allowed call writes a `start` line before the statement is sent and an `end` line when it finishes, paired by `callId`; a refusal writes one line with the reason. The fields: time, who, lease id, reason, tool, SQL, allowed or blocked with the reason, rows, milliseconds, and the Postgres error if any. `daypass log -n 30` prints the last 30 calls, one row each (a start with no end shows as `RUN … unfinished`); `jq` works on it. The SQL text is logged as written, so a `WHERE email = …` puts that value in the file. There is no central copy; collect the files if you need one.

## Can two people share a lease?

No, and they do not need to. A lease is a file on one machine; every Claude Code window on that machine shares it, and each person opens their own on theirs. What two people can share by accident is an AWS identity: the audit `who` is the caller ARN, so a shared IAM user or a shared role session name makes two people indistinguishable in the log. Give each person their own identity and their own `rds-db:connect`.

## What does it cost?

The package is MIT and runs on your laptop; there is no service. On AWS, the calls are `sts:GetCallerIdentity` and, if you use the IP rule, three EC2 security-group calls per lease plus the sweep; the RDS token is signed locally. With the IP rule, `daypass open` also fetches `https://checkip.amazonaws.com` to learn your public IP. A read replica, if you add one, is the only thing with a bill. Node 20+ and `psql` are the dependencies.

## What happens if the lease expires while a query is running?

It cannot outlive the lease. The lease is checked at the start of each tool call, and the statement timeout is 10 s or the time the lease has left once a connection is checked out, whichever is shorter, so Postgres cancels a query still running when the lease ends (`canceling statement due to statement timeout`). If the lease ran out while the call waited for a connection, it fails with `The lease expired before the query could start.` The next call is refused with `Lease … expired at …`, and if the target had a security-group rule, that same call removes it.

## How do I revoke everything right now?

In order of speed:

1. `daypass close` on the machine: deletes the lease and removes the security-group rule. The next tool call is refused.
2. In the database, as the owner: `ALTER ROLE daypass_ro NOLOGIN;` then `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = 'daypass_ro';`. This ends every connection on every laptop at once. `ALTER ROLE daypass_ro LOGIN;` restores it.
3. On AWS: remove `rds-db:connect` from the person's policy, or revoke their credentials. `daypass sweep <target>` cleans any rule they left.
4. For a password target: `ALTER ROLE daypass_ro PASSWORD 'new';` and update the configs you still trust.

The audit file on each machine stays; that is the record of what ran.
