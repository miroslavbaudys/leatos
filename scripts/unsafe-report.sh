#!/usr/bin/env bash
# Report the unsafe audit surface of the kernel and crates.
#  - modules allowed to contain unsafe (`#[allow(unsafe_code)]` + reason)
#  - unsafe constructs per file (blocks, fns, impls, extern blocks), comments excluded
#  - crates/* must be #![forbid(unsafe_code)]
# Exit code 1 if a crate lacks forbid(unsafe_code).
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== modules allowed to use unsafe"
find kernel/src -name '*.rs' | sort | while IFS= read -r f; do
  awk -v f="${f#kernel/src/}" '
    /^[[:space:]]*#\[allow\(unsafe_code\)\]/ { why=$0; sub(/.*\]/, "", why); sub(/^[[:space:]]*\/\/[[:space:]]*/, "", why); want=1; next }
    want && /mod [a-z0-9_]+/ { m=$0; sub(/.*mod /, "", m); sub(/[;{].*/, "", m); printf "  %-34s %s\n", f ": mod " m, why; want=0 }
  ' "$f"
done
echo
echo "== unsafe constructs per file (kernel/src; comments excluded)"
total=0
while IFS= read -r f; do
  n=$(grep -vE '^[[:space:]]*//' "$f" | grep -cE 'unsafe[[:space:]]*(\{|fn |impl |extern )' || true)
  if [[ "$n" -gt 0 ]]; then
    printf '  %4d  %s\n' "$n" "${f#kernel/src/}"
    total=$((total + n))
  fi
done < <(find kernel/src -name '*.rs' | sort)
printf '  ----\n  %4d  total\n\n' "$total"

echo "== crates/* (must be #![forbid(unsafe_code)])"
bad=0
for lib in crates/*/src/lib.rs; do
  if grep -q 'forbid(unsafe_code)' "$lib"; then
    echo "  ok    ${lib%/src/lib.rs}"
  else
    echo "  FAIL  ${lib%/src/lib.rs}: missing #![forbid(unsafe_code)]"
    bad=1
  fi
done
exit $bad
