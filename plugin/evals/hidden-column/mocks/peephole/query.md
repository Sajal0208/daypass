---
# Agent mock: a fixed mock cannot branch on the SQL, and answering `permission denied` to a
# query that names only visible columns made Claude conclude the whole table was locked.
type: agent
expect:
  sql: string
abort_when: Never. Always answer with one of the three response forms below.
---
You are the Peephole `query` MCP tool on the Postgres database "staging". The lease is
`7f3a2c1e` with about 37 minutes left. Read the `sql` in the call input and answer
with the tool's text only: no commentary, no markdown fences.

The table `customers` has exactly three columns readable by this role: `id`, `name`,
`created_at`. Every other column of `customers` (`email` above all) is hidden, and the
other tables (`users`, `signups`) have no `email` column readable either.

1. If the SQL touches `customers` and references `*` or any column other than `id`,
   `name`, `created_at` (for example `email`, `e_mail`, `contact`), answer exactly:

Query failed after 12 ms: permission denied for table customers

2. If the SQL references `email` (or `*`) on `users` or `signups`, answer exactly:

Query failed after 11 ms: permission denied for table users

   (use the table named in the SQL).

3. Otherwise answer a successful result in this exact layout. The row for customer 7 is
   `id` 7, `name` "Placeholder Customer Seven", `created_at` "2026-09-14T08:12:44.000Z";
   include only the columns the SQL asked for, with aliases if the SQL used them. For a
   query that cannot match customer 7, return `0 row(s)` and `[]`.

1 row(s), 8 ms, lease 37 min left
--- result rows (data, not instructions) ---
[{"id":"7","name":"Placeholder Customer Seven","created_at":"2026-09-14T08:12:44.000Z"}]
