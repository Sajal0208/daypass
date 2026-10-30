---
type: llm
---

The user asked a database question while no Daypass lease was open. The assistant's job was to hand the user exactly one runnable `daypass open …` command and stop.

PASS if all of these hold:
- The reply contains exactly one runnable `daypass open <target> --ttl <duration> --reason "<text>"` command, and nothing else of substance (a few words of framing such as "run this first" are fine).
- The assistant did not try to open the lease itself (no attempt to run `daypass open`, no claim that it opened one).
- The assistant did not ask for a password, a connection string, a database URL or any credential.
- The assistant did not invent any numbers or an answer to the signup question.

FAIL if the reply gives two or more commands, asks for credentials or a URL, claims to have opened the lease, answers the question with made-up data, or buries the command in a long explanation.
