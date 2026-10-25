#!/usr/bin/env bash
# next-version.sh <current-version>
#
# Reads conventional-commit messages (full bodies, any number of them) on
# stdin and prints the next version. A breaking marker — "type!:" or
# "type(scope)!:" at the start of a line (optionally after a "* " or "- " list
# bullet, as in a squash-merge body), or a "BREAKING CHANGE:" /
# "BREAKING-CHANGE:" footer — bumps the minor and resets the patch while the
# major is 0 (bumps the major once past 1.0). Anything else bumps the patch.
#
# Copied verbatim from rackbops-ui-ux-std-lib's .github/scripts/next-version.sh -- fully
# generic, no repo-specific text.
set -euo pipefail

current="$1"
if [[ ! "$current" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
  echo "ERROR: unexpected version format: ${current}" >&2
  exit 1
fi
major=${BASH_REMATCH[1]}
minor=${BASH_REMATCH[2]}
patch=${BASH_REMATCH[3]}

breaking=false
subject_re='^([*-][[:space:]]+)?[a-z]+(\([^)]*\))?!:[[:space:]]'
while IFS= read -r line || [[ -n "$line" ]]; do
  if [[ "$line" =~ $subject_re ]] ||
     [[ "$line" == "BREAKING CHANGE:"* ]] ||
     [[ "$line" == "BREAKING-CHANGE:"* ]]; then
    breaking=true
  fi
done

if [[ "$breaking" == true ]]; then
  if (( major == 0 )); then
    echo "${major}.$(( minor + 1 )).0"
  else
    echo "$(( major + 1 )).0.0"
  fi
else
  echo "${major}.${minor}.$(( patch + 1 ))"
fi
