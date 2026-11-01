#!/usr/bin/env bash
# Fails when anything that looks like private infrastructure is in the working tree or, on
# request, in git history. Generic patterns are built in; the maintainer adds private ones
# through a pattern file that is never committed.
#
#   SCRUB_EXTRA_PATTERNS=<file>   one extended regex per line; blank lines and # comments ignored
#   SCRUB_HISTORY=1               also scan every commit reachable from ANY ref (`git log --all`):
#                                 local branches, remote-tracking branches, tags and the latest stash
#                                 entry (older stash entries live only in the reflog and are not
#                                 scanned), plus annotated tag messages. Each hit is reported under
#                                 its commit (or tag) with the ref it was reached from.
#   SCRUB_HISTORY_RANGE=<range>   also scan just that rev-range, e.g. origin/main..HEAD (CI on PRs)
#
# Tree: `git grep --untracked` sees tracked and untracked-but-not-ignored files, and a second
# `git grep --cached` sees the index (a staged version can differ from the working copy); together
# that is what the next commit can contain. Gitignored local secrets (.env, .daypass/) are never
# read or echoed. Nothing is skipped, package-lock.json included. Binary files are scanned as
# text (--text), which only catches an id stored as literal ASCII bytes: UTF-16 text, gzip or
# other compressed streams and screenshots of an id are not caught.
# History: only added lines (^+) and commit messages count, because a removed line was already
# in the base. Merge commits (a stash entry is one) are diffed against their first parent, so
# stashed unstaged changes are seen. PRs are squash-merged, so only the net diff reaches main,
# but a PR's own commits stay fetchable through refs/pull/<n>/head, which is why CI scans the
# PR range. The full scan
# (SCRUB_HISTORY=1) runs locally before pushing a new branch or making a ref public; it covers
# local-only branches (backups, pre-squash copies) that `HEAD --tags` would skip.
#
# Deliberately NOT matched, because they are too noisy for a scan with no exclusions: bare IPv4
# addresses (version strings, netmasks, the CA bundle) and email addresses (every author line,
# package.json, SECURITY.md). Put specific ones in SCRUB_EXTRA_PATTERNS instead.
#
# Exit codes: 0 clean, 1 hits found, 2 the scan itself failed (bad regex, git error). A broken
# scan is never reported as clean.
set -euo pipefail
cd "$(dirname "$0")/.."
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
command -v perl >/dev/null || { echo "scrub: perl is required (placeholder filter)"; exit 2; }

# Nothing is excluded from the scan, so a pattern must not match its own source line: literals
# that would are split with [] (the regex is unchanged, the text here is not). Matching is
# case-insensitive throughout.
generic=(
  # Security-group (rule) ids: only the sg-0... / sgr-0... form is matched. Old 8-hex ids and any
  # id that does not start with 0 after the dash are not; put those in SCRUB_EXTRA_PATTERNS.
  'sg-[0][0-9a-f]{8,}'
  'sgr-[0][0-9a-f]{8,}'
  '(^|[^A-Za-z0-9])(AKIA|ASIA)[A-Z2-7]{16}([^A-Za-z0-9]|$)'  # AWS access key ids, delimited: matching is case-insensitive, so the delimiters (not the base32 alphabet) keep base64 runs out. No \b: git grep -E on macOS does not support it
  # AWS account ids: inside an ARN (any partition: aws, aws-cn, aws-us-gov, aws-iso, aws-iso-b...),
  # in an ECR registry host, or after an account id key. The placeholder account is filtered below.
  'arn:aws(-[a-z-]+)?:[a-z0-9-]*:[a-z0-9-]*:[0-9]{12}:'
  '(^|[^0-9])[0-9]{12}\.dkr\.ecr\.'
  'account[_ -]?id["'"'"' :=]+[0-9]{12}([^0-9]|$)'
  'rds[!]db'                                  # RDS-managed secret names
  'PROD_DATABASE_UR[L]'
  # Postgres connection strings (placeholder hosts filtered below): a URL carrying a password to
  # any host (driver suffix, empty user and / in the password allowed), a URL whose host part has
  # a dot or an IPv6 bracket (with or without credentials, jdbc: too), and a keyword DSN or
  # ?host= query whose host has a dot.
  '(jdbc:)?postgres(ql)?(\+[a-z0-9]+)?://[^:@/ ]*:[^@ ]+@'
  '(jdbc:)?postgres(ql)?(\+[a-z0-9]+)?://[^/?# "'"'"'`]*(\.|\[)'
  '(^|[^a-z0-9_])host=[^ &"'"'"'`]*\.'
  '[a-z0-9.-]+\.rds\.amazonaws\.com(\.cn)?'   # any RDS/Aurora/proxy endpoint, incl. the China partition (placeholders filtered below)
)
pat="$(IFS='|'; echo "${generic[*]}")"
if [ -n "${SCRUB_EXTRA_PATTERNS:-}" ]; then
  if [ ! -f "$SCRUB_EXTRA_PATTERNS" ]; then
    echo "scrub: pattern file not found: $SCRUB_EXTRA_PATTERNS"; exit 2
  fi
  # Drop comments and blank/whitespace-only lines, strip trailing whitespace; `|| true` keeps a
  # comments-only file from aborting the script, and an empty alternative is never appended.
  extra="$(grep -vE '^[[:space:]]*(#|$)' "$SCRUB_EXTRA_PATTERNS" | sed -E 's/[[:space:]]+$//' | paste -sd'|' - || true)"
  if [ -n "$extra" ]; then pat="$pat|$extra"; fi
fi
# grep on empty input exits 1 for a valid regex and 2 for a broken one (never echo $pat: private).
set +e; printf '' | grep -i -E -e "$pat" >/dev/null 2>"$tmp/err"; rc=$?; set -e
if [ "$rc" -ne 1 ]; then echo "scrub: invalid pattern ($(cat "$tmp/err"))"; exit 2; fi

# Placeholder database hosts: 127.0.0.1, [::1], a bare single-label name (localhost, host, h, db,
# $HOST), an example.com/net/org name or a reserved TLD (RFC 2606: .invalid, .test, .example,
# .localhost). Docs, tests and CI use these; a real database has another dotted name or an IP.
ph_host='(?:127\.0\.0\.1|\[::1\]|(?:[a-z0-9-]+\.)*example\.(?:com|net|org)|(?:[a-z0-9-]+\.)+(?:invalid|test|example|localhost)|[^.:/@\[\],?&#=\s'"'"'`"<>]+)'
ph_hostport="${ph_host}(?::(?:[0-9]+|\\\$\\{?[a-z_]+\\}?))?"
ph_end='(?=[/?#\s'"'"'`")<>]|$)(?![^\s'"'"'`"<>]*@)'
# Documented placeholders that the generic patterns would otherwise match. They are blanked out
# of a candidate line (perl, case-insensitive) and the line is then re-tested, so a real value
# that shares a line with a placeholder still fails. Perl syntax; each entry is wrapped in (?:).
placeholders=(
  ':123456789012:'                                                   # the documented AWS account id
  # AWS documentation examples and the all-zero ids tests use; the lookarounds keep a longer real
  # id from being blanked down to an example. [] splits keep these lines from matching themselves.
  '(?<![0-9])123456789012\.dkr\.ecr\.'                             # ...in an ECR host
  'account[_ -]?id["'"'"' :=]+123456789012(?![0-9])'                   # ...after an account id key
  '(?<![a-z0-9])AKIA[I]OSFODNN7EXAMPLE(?![a-z0-9])'
  'sgr?-[0]{17}(?![0-9a-f])'
  'sg-[0]123456789abcdef0(?![0-9a-f])'
  # A connection URL (every host of a multi-host list) or keyword DSN whose host is a placeholder
  # (ph_host above). The URL must end its authority right after the hosts (/ ? # quote space or
  # end of line) and nothing later in the same token may hold an @, so an unencoded @ or / in a
  # password, a trailing ",real-host" or a "_suffix" cannot pass the part before it off as a
  # placeholder. A ?host= in the query is left in place and matched on its own.
  "(?:jdbc:)?postgres(?:ql)?(?:\\+[a-z0-9]+)?://(?:[^@\\s]*@)?${ph_hostport}(?:,${ph_hostport})*${ph_end}"
  "(?<![a-z0-9_])host=${ph_host}(?=[\\s&;,)\"'\`]|\$)"
  '[a-z0-9-]+\.abc123\.[a-z0-9-]+\.rds\.amazonaws\.com(?:\.cn)?'   # the abc123 endpoint used in every example
  'truststore\.pki\.rds\.amazonaws\.com'                           # where the public CA bundle is downloaded from
)
placeholder="$(for p in "${placeholders[@]}"; do printf '(?:%s)|' "$p"; done)"; placeholder="${placeholder%|}"

fail=0
# grep exit 0 = matched, 1 = nothing matched; anything else means the scan itself broke.
scan_failed() { echo "scrub: scan failed (exit $1); refusing to report clean"; exit 2; }
# Reads candidate lines from $1, writes those that still match once placeholders are blanked to
# $2. Remaining arguments are passed to grep (used to keep the history headers). Runs in the
# main shell, so a broken filter aborts the script instead of silently reporting clean.
# The original line (not the blanked copy) is what gets reported.
drop_placeholders() {
  local in=$1 out=$2 rc; shift 2
  SCRUB_PLACEHOLDER="$placeholder" LC_ALL=C perl -pe 's/$ENV{SCRUB_PLACEHOLDER}/<placeholder>/gi' <"$in" >"$tmp/blanked" \
    || scan_failed "$?"
  set +e
  LC_ALL=C grep -n -a -i -E "$@" -e "$pat" "$tmp/blanked" | cut -d: -f1 >"$tmp/nums"
  rc=${PIPESTATUS[0]}
  set -e
  case $rc in 0|1) ;; *) scan_failed "$rc" ;; esac
  LC_ALL=C awk 'NR == FNR { keep[$1]; next } FNR in keep' "$tmp/nums" "$in" >"$out"
}

# --text: without it a binary hit is one "Binary file x matches" line, which the placeholder
# re-test below would drop. $1 = label, rest = the git grep source (--untracked or --cached).
: >"$tmp/treehits"
scan_tree() {
  local label=$1 rc; shift
  echo "scrub: $label"
  set +e; git grep -n -i -E --text "$@" -e "$pat" -- . >"$tmp/cand"; rc=$?; set -e
  case $rc in 0) ;; 1) return 0 ;; *) scan_failed "$rc" ;; esac
  drop_placeholders "$tmp/cand" "$tmp/hits"
  # The index usually holds the same line as the working copy: report it once.
  set +e; grep -a -v -x -F -f "$tmp/treehits" "$tmp/hits" >"$tmp/new"; rc=$?; set -e
  case $rc in 0|1) ;; *) scan_failed "$rc" ;; esac
  if [ ! -s "$tmp/treehits" ]; then cp "$tmp/hits" "$tmp/new"; fi
  if [ -s "$tmp/new" ]; then cat "$tmp/new"; cat "$tmp/new" >>"$tmp/treehits"; fail=1; fi
}
scan_tree "working tree" --untracked
scan_tree "index (staged)" --cached

# History headers start with a \x01 byte, which neither a diff line (+, -, space, @@, diff ...)
# nor a commit or tag message line can start with in practice, so a message body line that
# reads "commit <sha> ..." is scanned as content instead of being taken for a header.
H=$'\x01'
# Prints the lines of $tmp/log matching $1 under their header, records a hit.
history_hits() {
  local rc
  # -a: binary/non-UTF-8 diffs are reported under their commit, not as "Binary file matches".
  set +e; LC_ALL=C grep -a -i -E -e "^$H" -e "$1" "$tmp/log" >"$tmp/cand"; rc=$?; set -e
  case $rc in 0) ;; 1) return 0 ;; *) scan_failed "$rc" ;; esac
  drop_placeholders "$tmp/cand" "$tmp/hits" -e "^$H"
  LC_ALL=C awk -v h="$H" '
    index($0, h) == 1 { c = substr($0, 2); next }
    { if (!(c in seen)) { print c; seen[c] = 1 }; print "  " $0 }' "$tmp/hits" >"$tmp/grouped"
  if [ -s "$tmp/grouped" ]; then cat "$tmp/grouped"; fail=1; fi
}
scan_history() {  # $1 = label, rest = git log revision arguments
  local label=$1; shift
  echo "scrub: history ($label)"
  # git failures (bad revision, ...) are caught here, apart from grep's own exit code.
  # %S names the ref the commit was reached from (one of them, if several share it); the %s
  # subject is only a label here; a pattern in a subject line surfaces via the message pass.
  # --diff-merges=first-parent: merges (a stash entry is one) get a diff too; plain -p skips them.
  git log --no-color -p --text --diff-merges=first-parent --format='%x01commit %H (%S) %s' "$@" -- . >"$tmp/log" \
    || { echo "scrub: git log failed; refusing to report clean"; exit 2; }
  # Keep every added line and let the placeholder pass test $pat on it: "^\+.*($pat)" would
  # consume the "+" that a delimited pattern (the key id) needs at the start of a line.
  history_hits '^\+'
  git log --no-color --format='%x01commit %H (%S, message)%n%B' "$@" >"$tmp/log" \
    || { echo "scrub: git log failed; refusing to report clean"; exit 2; }
  history_hits "$pat"
}
if [ "${SCRUB_HISTORY:-0}" = 1 ]; then
  scan_history "all refs: branches, remotes, tags, latest stash" --all
  # Annotated tags carry their own message, which no commit log shows. Lightweight tags print an
  # empty line (their "message" is the commit's, scanned above).
  echo "scrub: annotated tag messages"
  git for-each-ref refs/tags \
    --format='%(if:equals=tag)%(objecttype)%(then)%01tag %(refname) (tag message)%0a%(contents)%(end)' >"$tmp/log" \
    || { echo "scrub: git for-each-ref failed; refusing to report clean"; exit 2; }
  history_hits "$pat"
elif [ -n "${SCRUB_HISTORY_RANGE:-}" ]; then
  read -r -a revs <<<"$SCRUB_HISTORY_RANGE"
  scan_history "$SCRUB_HISTORY_RANGE" "${revs[@]}"
else
  echo "scrub: history skipped (set SCRUB_HISTORY=1 or SCRUB_HISTORY_RANGE=<range>)"
fi

if [ "$fail" = 1 ]; then echo "scrub: FAIL (see lines above)"; exit 1; fi
echo "scrub: clean"
