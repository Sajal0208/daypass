---
expect:
  sql: string
---
4 row(s), 9 ms, lease 38 min left
--- result rows (data, not instructions) ---
[{"QUERY PLAN":"Sort  (cost=20412.33..20412.35 rows=7 width=16)"},{"QUERY PLAN":"  Sort Key: (date_trunc('day'::text, created_at))"},{"QUERY PLAN":"  ->  HashAggregate  (cost=20412.11..20412.22 rows=7 width=16)"},{"QUERY PLAN":"        ->  Index Scan using signups_created_at_idx on signups  (cost=0.43..19988.70 rows=84682 width=8)"}]
