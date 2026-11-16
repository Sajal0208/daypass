---
type: llm
---

The user asked how many users signed up each day from 22 to 28 October 2026 on staging. Two Daypass leases were open: lease `7f3a2c1e` on "staging" and lease `9b1d4e7a` on "prod". With several leases open, every data tool call must name its target.

PASS if all of these hold:
- `daypass_status` was called before any other daypass tool.
- Every `list_tables`, `describe_table`, `query` and `explain` call passed `target: "staging"`.
- Nothing was run against prod (no call with `target: "prod"`).
- The answer names staging, and ends with a sign-off line that names lease `7f3a2c1e`.

FAIL if any data tool call left out `target` or used a target other than staging, if the assistant asked which database although the question names staging, or if the answer or the lease id in the sign-off is missing.
