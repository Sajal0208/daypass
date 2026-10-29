#!/usr/bin/env bash
# Fails when anything that looks like private infrastructure is in the working tree or, on
# request, in git history. Generic patterns are built in; the maintainer adds private ones
# through a pattern file that is never committed.
#
#   SCRUB_EXTRA_PATTERNS=<file>   one extended regex per line; blank lines and # comments ignored
#   SCRUB_HISTORY=1               also scan every commit reachable from HEAD or any tag
#   SCRUB_HISTORY_RANGE=<range>   also scan just that rev-range, e.g. origin/main..HEAD (CI on PRs)
#
# Tree: `git grep --untracked` sees tracked and untracked-but-not-ignored files, exactly what can
# be committed; gitignored local secrets (.env, .peephole/) are never read or echoed. Binary
# files are scanned too, so an image with an id in it fails.
# History: only added lines (^+) and commit messages count, because a removed line was already
# in the base. PRs are squash-merged, so only the net diff reaches main, but a PR's own commits
# stay fetchable through refs/pull/<n>/head, which is why CI scans the PR range. The full scan
# (SCRUB_HISTORY=1) runs locally on main before the repo goes public.
#
# Exit codes: 0 clean, 1 hits found, 2 the scan itself failed (bad regex, git error). A broken
# scan is never reported as clean.
set -euo pipefail
cd "$(dirname "$0")/.."
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT

# Nothing is excluded from the scan, so a pattern must not match its own source line: literals
# that would are split with [] (the regex is unchanged, the text here is not).
generic=(
  'sg-[0][0-9a-f]{8,}'                        # real security-group ids (17-hex, 2018+; the old 8-hex form is not matched)
  'sgr-[0][0-9a-f]{8,}'                       # real security-group rule ids
  'arn:aws:[a-z0-9-]*:[a-z0-9-]*:[0-9]{12}:'  # ARNs with an account id (placeholder account filtered below)
  'rds[!]db'                                  # RDS-managed secret names
  'PROD_DATABASE_UR[L]'
  'postgres(ql)?://[^:@/ ]+:[^@/ ]+@[^ ]*\.rds\.amazonaws\.com'  # URL with password to an RDS host
  '\.(cluster-(ro-)?|proxy-)?[a-z0-9]{12}\.[a-z]{2}-[a-z]+-[0-9]\.rds\.amazonaws\.com'  # real RDS/Aurora/proxy endpoints (the abc123 placeholder is 6 chars)
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

fail=0
# grep exit 0 = matched, 1 = nothing matched; anything else means the scan itself broke.
scan_failed() { echo "scrub: scan failed (exit $1); refusing to report clean"; exit 2; }
# 123456789012 is the documented placeholder account, so ARN hits that carry it are not private;
# this drops every whole line that contains it.
not_placeholder() { grep -v ':123456789012:' || true; }

echo "scrub: working tree"
set +e; out="$(git grep -n -i -E --untracked -e "$pat" -- . ':!package-lock.json')"; rc=$?; set -e
case $rc in
  0) hits="$(printf '%s\n' "$out" | not_placeholder)"
     if [ -n "$hits" ]; then printf '%s\n' "$hits"; fail=1; fi ;;
  1) ;;
  *) scan_failed "$rc" ;;
esac

# Prints the lines of $tmp/log matching $1 under their "commit <sha> ..." header, records a hit.
history_hits() {
  local out rc hits
  # -a: binary/non-UTF-8 diffs are reported under their commit, not as "Binary file matches".
  set +e; out="$(grep -a -i -E -e '^commit [0-9a-f]+ ' -e "$1" "$tmp/log")"; rc=$?; set -e
  case $rc in 0) ;; 1) return 0 ;; *) scan_failed "$rc" ;; esac
  hits="$(printf '%s\n' "$out" | not_placeholder | awk '
    /^commit [0-9a-f]+ / { c = $0; next }
    { if (!(c in seen)) { print c; seen[c] = 1 }; print "  " $0 }')"
  if [ -n "$hits" ]; then printf '%s\n' "$hits"; fail=1; fi
}
scan_history() {  # $1 = label, rest = git log revision arguments
  local label=$1; shift
  echo "scrub: history ($label)"
  # git failures (bad revision, ...) are caught here, apart from grep's own exit code.
  # The %s header is only a label here; a pattern in a subject line surfaces via the message pass.
  git log --no-color -p --text --format='commit %H %s' "$@" -- . >"$tmp/log" \
    || { echo "scrub: git log failed; refusing to report clean"; exit 2; }
  history_hits "^\+.*($pat)"
  git log --no-color --format='commit %H (message)%n%B' "$@" >"$tmp/log" \
    || { echo "scrub: git log failed; refusing to report clean"; exit 2; }
  history_hits "$pat"
}
if [ "${SCRUB_HISTORY:-0}" = 1 ]; then
  scan_history "HEAD and all tags" HEAD --tags
elif [ -n "${SCRUB_HISTORY_RANGE:-}" ]; then
  read -r -a revs <<<"$SCRUB_HISTORY_RANGE"
  scan_history "$SCRUB_HISTORY_RANGE" "${revs[@]}"
else
  echo "scrub: history skipped (set SCRUB_HISTORY=1 or SCRUB_HISTORY_RANGE=<range>)"
fi

if [ "$fail" = 1 ]; then echo "scrub: FAIL (see lines above)"; exit 1; fi
echo "scrub: clean"
