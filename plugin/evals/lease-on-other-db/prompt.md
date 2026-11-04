---
name: lease-on-other-db
description: One lease is open, on "prod". The question names staging. The skill must pass target "staging", get the refusal, and hand back the open line for staging instead of answering from prod.
max_turns: 25
timeout_seconds: 400
allowed_tools: [Skill]
---

On staging, how many users signed up each day from 22 to 28 October 2026?
