#!/usr/bin/env bash
# Verify that every local link in site/ points at something that exists.
#
# The HTML pages are abridged summaries that link out to the full Markdown
# guides, so both sets are customer-facing and both can rot. This runs in CI
# before the Pages deploy; run it locally with:
#
#   .github/scripts/check-links.sh
#
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SITE="$ROOT/site"
fails=0

report() { echo "  BROKEN  $1 -> $2"; fails=$((fails + 1)); }

# Resolve a link target and check it exists.
#   $1 file the link appears in, $2 raw link target
check() {
  local src="$1" target="$2" dir base
  dir="$(dirname "$src")"

  # strip anchor and query string
  target="${target%%#*}"
  target="${target%%\?*}"
  [ -z "$target" ] && return 0

  case "$target" in
    http://*|https://*|mailto:*|tel:*|data:*|javascript:*) return 0 ;;
    /*) base="$SITE$target" ;;   # root-relative resolves against the site root
    *)  base="$dir/$target" ;;
  esac

  # a directory link is satisfied by the directory or its index page
  if [ -e "$base" ] || [ -e "${base%/}/index.html" ] || [ -e "${base%/}/README.md" ]; then
    return 0
  fi
  report "${src#$ROOT/}" "$target"
}

echo "Checking Markdown links..."
while IFS= read -r f; do
  while IFS= read -r t; do
    check "$f" "$t"
  done < <(grep -oE '\]\([^)]+\)' "$f" 2>/dev/null | sed 's/^](//; s/)$//' | awk '{print $1}')
done < <(find "$SITE" -name '*.md')

echo "Checking HTML href/src targets..."
while IFS= read -r f; do
  while IFS= read -r t; do
    check "$f" "$t"
  done < <(grep -oE '(href|src)="[^"]+"' "$f" 2>/dev/null | sed 's/^[a-z]*="//; s/"$//')
done < <(find "$SITE" -name '*.html')

if [ "$fails" -gt 0 ]; then
  echo
  echo "FAILED: $fails broken link(s)."
  exit 1
fi
echo "All local links resolve."
