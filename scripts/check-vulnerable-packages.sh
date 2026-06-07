#!/usr/bin/env bash
#
# Lists known-vulnerable NuGet packages (direct + transitive) for the solution.
# Used in the course coda (Day 2) to demonstrate dependency scanning offline.
# Exits non-zero if any vulnerable package is found.
#
set -euo pipefail
cd "$(dirname "$0")/.."

dotnet restore SecureCoding.NetBackend.sln >/dev/null
report=$(dotnet list SecureCoding.NetBackend.sln package --vulnerable --include-transitive 2>&1)
echo "$report"

if echo "$report" | grep -q "has the following vulnerable packages"; then
  echo "Vulnerable packages found." >&2
  exit 1
fi
echo "No vulnerable packages."
