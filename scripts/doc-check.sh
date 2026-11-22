#!/usr/bin/env bash
# Checks that the references moved out of CLAUDE.md stay complete:
#
#   1. every boot argument the kernel parses has a row in docs/boot-arguments.md
#      (a row starts with "| `name="), and every row names one it still parses;
#   2. every LAB_* variable the lab scripts read is described in the header
#      comment of scripts/lab-test.sh.
#
# Run from anywhere; exit code 0 = complete. CI runs it (host job).
# Negative control: delete a row from docs/boot-arguments.md (or a LAB_
# line from the header): the check names it and fails.
set -euo pipefail
cd "$(dirname "$0")/.."
export LC_ALL=C

fail=0
doc=docs/boot-arguments.md

# Boot arguments the kernel parses: arg(..., "x"), arg_u64(..., "x"),
# arg_of("x") and literal "x=value" matches (heap=list, panic=halt, ...).
parsed=$(
  {
    grep -rhoE '(^|[^a-z_])(arg|arg_u64)\([^,()]*(\([^)]*\))?[^,()]*, *"[a-z0-9_]+"' kernel/src \
      | grep -oE '"[a-z0-9_]+"$'
    grep -rhoE 'arg_of\("[a-z0-9_]+"' kernel/src | grep -oE '"[a-z0-9_]+"$'
    grep -rhoE '"[a-z][a-z0-9_]*=[a-z0-9_]*"' kernel/src --include='*.rs' | sed 's/=.*/"/'
  } | tr -d '"' | sort -u
)
if [[ -z "$parsed" ]]; then
  echo "doc-check: found no boot arguments in kernel/src (pattern broken?)"
  exit 1
fi

for a in $parsed; do
  if ! grep -qF "| \`$a=" "$doc"; then
    echo "doc-check: boot argument '$a=' is parsed by the kernel but has no row in $doc"
    fail=1
  fi
done

documented=$(grep -oE '^\| `[a-z0-9_]+=' "$doc" | sed 's/^| `//; s/=$//' | sort -u)
for a in $documented; do
  if ! printf '%s\n' "$parsed" | grep -qx "$a"; then
    echo "doc-check: $doc documents '$a=', which the kernel no longer parses"
    fail=1
  fi
done

# LAB_* variables: the header is the comment block before the first
# non-comment line of scripts/lab-test.sh.
lab=scripts/lab-test.sh
header=$(awk '!/^#/ { exit } { print }' "$lab")
vars=$(cat "$lab" scripts/lab/*.sh scripts/qemu-run.sh | grep -oE 'LAB_[A-Z0-9_]+' | sort -u)
for v in $vars; do
  if ! printf '%s\n' "$header" | grep -qE "(^|[^A-Z0-9_])$v([^A-Z0-9_]|$)"; then
    echo "doc-check: $v is read by the lab scripts but not described in the header of $lab"
    fail=1
  fi
done

if [[ "$fail" == 0 ]]; then
  echo "doc-check: $(printf '%s\n' "$parsed" | wc -l | tr -d ' ') boot arguments," \
    "$(printf '%s\n' "$vars" | wc -l | tr -d ' ') LAB_ variables: all documented"
fi
exit "$fail"
