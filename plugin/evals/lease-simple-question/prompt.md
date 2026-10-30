---
name: lease-simple-question
description: A lease is open on "staging". The skill must check status first, learn the schema (list_tables, describe_table), query with named columns, summarise the Monday drop, and sign off with the lease id and reason. The dates are explicit because the query mock is fixed and cannot follow a relative "last week".
max_turns: 25
timeout_seconds: 400
allowed_tools: [Skill]
---

How many users signed up each day from 22 to 28 October 2026?
