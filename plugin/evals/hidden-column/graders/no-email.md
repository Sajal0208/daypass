---
# An email-shaped token. The skill's own mask example (`a***@example.com`) is not one.
type: regex
pattern: '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'
match: not_contains
---
