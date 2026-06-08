#!/usr/bin/env bash
#
# Software Composition Analysis (SCA): lists known-vulnerable NuGet packages
# (direct + transitive) for the solution, by querying the advisory database.
# Exits non-zero if any vulnerable package is found.
#
# SCOPE — read this before concluding "the repo is secure":
#   This checks your DEPENDENCIES only. It does NOT look at the code we wrote.
#   The deliberate weaknesses in src/Vulnerable (SQLi, path traversal, command
#   injection, SSRF, weak crypto, ...) are OUR code, not packages — this script
#   will (correctly) report "No vulnerable packages" while that code is full of
#   holes. To find code weaknesses use the Static Application Security Testing
#   (SAST) tools instead: scripts/check-code-security.sh (the Roslyn security
#   analyzers + Security Code Scan), and GitHub CodeQL (.github/workflows/codeql.yml).
#   SCA and SAST are orthogonal: "no vulnerable dependencies" does NOT mean
#   "secure code".
#
# Used in the course coda (Day 2) to demonstrate dependency scanning.
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
