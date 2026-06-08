#!/usr/bin/env bash
#
# Static Application Security Testing (SAST): builds each project with the .NET
# security analyzers + Security Code Scan enabled (see Directory.Build.props) and
# reports the CA*/SCS* security findings in OUR OWN CODE.
#
# Counterpart to check-vulnerable-packages.sh (which is SCA — third-party
# dependencies). SAST and SCA are ORTHOGONAL: this script finds weaknesses you
# wrote (SQLi, path traversal, weak crypto, ...); the SCA script finds packages
# with known advisories. A clean report from one says nothing about the other.
# (GitHub CodeQL in .github/workflows/codeql.yml is a second, deeper SAST engine.)
#
# Policy for this teaching repo:
#   - src/Vulnerable is SUPPOSED to have findings — that is the live demo that the
#     tooling catches each CWE. They are listed but do NOT fail this gate.
#   - Every other project (notably src/Fixed) MUST stay clean. A security finding
#     there fails the gate (exit non-zero), catching a real regression.
#
set -euo pipefail
cd "$(dirname "$0")/.."

# Projects to scan. Any path containing /Vulnerable/ is allowed to have findings.
projects=(
  "src/Vulnerable/Shop.Api"
  "src/Fixed/Shop.Api"
)

# Match Roslyn security rules (CAxxxx) and Security Code Scan rules (SCSxxxx).
pattern="warning (CA[0-9]+|SCS[0-9]+)"

fail=0
for proj in "${projects[@]}"; do
  # --no-incremental forces the analyzers to re-run so every finding is emitted.
  log=$(dotnet build "$proj" --no-incremental -nologo 2>&1 || true)
  # `|| true` covers the whole pipeline: grep exits non-zero on a clean project
  # (no matches), which would otherwise trip `set -e` on this assignment.
  count=$(printf '%s\n' "$log" | grep -aoE "$pattern" | wc -l | tr -d ' ' || true)

  echo "== ${proj} : ${count} security finding(s) =="
  if [ "$count" -gt 0 ]; then
    printf '%s\n' "$log" | grep -aoE "$pattern" | sort | uniq -c | sort -rn
  fi

  case "$proj" in
    */Vulnerable/*)
      echo "   (expected — deliberately vulnerable demo code; not a failure)"
      ;;
    *)
      if [ "$count" -gt 0 ]; then
        echo "   ERROR: security findings in code that must stay clean." >&2
        fail=1
      fi
      ;;
  esac
  echo ""
done

if [ "$fail" -ne 0 ]; then
  echo "SAST gate FAILED: security findings in code that must be clean." >&2
  exit 1
fi
echo "SAST gate passed: all non-Vulnerable projects are clean of security findings."
