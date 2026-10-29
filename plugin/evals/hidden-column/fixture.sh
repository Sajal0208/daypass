#!/usr/bin/env bash
# Placeholder hidden-columns list for this case only. HOME is the run's temporary home.
set -euo pipefail
mkdir -p "$HOME/.peephole"
cat > "$HOME/.peephole/hidden-columns.txt" <<'LIST'
# hidden by the owner: PII
customers.email
users.email
LIST
