<!--
Thanks for contributing to the Secure Coding for .NET Backend Developers course!
Please read CONTRIBUTING.md first. Fill in the sections below and delete this comment.
-->

## Summary
<!-- What does this PR change, and why? -->


## Type of change
<!-- Tick all that apply. -->
- [ ] New chapter (vulnerable + fixed controller pair + exploit test)
- [ ] Remediation / change in the `Fixed/` project
- [ ] Course materials (speaker notes, cheat-sheet, checklist, slides, run-sheet)
- [ ] CI / tooling / dependencies
- [ ] Docs (README, CONTRIBUTING, etc.)
- [ ] Other:

**Chapter / CWE affected (if any):**

## The golden rule
- [ ] I did **not** "fix" the `Vulnerable/` project — its flaws are the teaching material.
      (Remediations belong in `Fixed/`; analyzer/CodeQL alerts on `Vulnerable/` are expected.)

## Checklist
- [ ] `dotnet test` passes locally (all green).
- [ ] Any new/changed weakness has a **differential** exploit test — it succeeds against
      `Vulnerable` and is blocked against `Fixed` (and would fail if the controller did nothing).
- [ ] Weaknesses are tagged in code with `// CWE-XXX`.
- [ ] New chapter only: speaker note added in `course/chapters/`, and `course/cheat-sheet.md`,
      `course/checklist.md`, `course/slides.md`, and `Test.md` updated.
- [ ] No new analyzer warnings on the `Fixed/` project — or they're suppressed *narrowly,
      with a justification* (never a solution-wide disable).
- [ ] `./scripts/check-vulnerable-packages.sh` reports no vulnerable dependencies.
- [ ] Commit messages use a conventional prefix (`feat(chN):`, `docs(course):`, `fix:`, `ci:`, `build:`).

## How to verify
<!-- Commands a reviewer can run, e.g. a specific test filter or a cheat-sheet curl. -->
```bash
dotnet test --filter FullyQualifiedName~<YourTest>
```

## Related issues
<!-- e.g. Closes #12 -->


<!--
Note on CI: the CodeQL workflow WILL report alerts on the Vulnerable/ project — that is
expected and should not be "fixed". New alerts on Fixed/ should be resolved or justified.
-->
