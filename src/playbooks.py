from core import RemediationClass

PLAYBOOKS: dict[RemediationClass, dict] = {
    RemediationClass.CVE: {
        "objective": "Remediate the vulnerability and resolve any breaking change the upgrade introduces.",
        "steps": [
            "Gather: read the advisory; locate the dependency in lockfiles and the import sites that use it.",
            "Study: check the changelog between current and fixed version for breaking changes.",
            "Requirements: pin to the lowest fixed version that the rest of the tree allows.",
            "Identify files: lockfile(s), manifest, and every call site touching the changed API.",
            "Document: note the breaking change (if any) and the migration in the PR body.",
            "Plan: bump -> adapt call sites -> reinstall -> run the affected suite.",
            "Review: confirm no other pinned dependency conflicts with the new version.",
            "Build & verify: clean install, run targeted tests, confirm the advisory no longer reports.",
        ],
        "acceptance": [
            "Vulnerable version no longer present in the resolved tree.",
            "All call sites adapted; no references to removed/changed APIs remain.",
            "Affected test suite passes on a clean install.",
        ],
        "verify": "pip-audit -r requirements/base.txt  # or: npm audit --prefix superset-frontend",
    },
    RemediationClass.BROAD_CATCH: {
        "objective": "Replace the broad `except Exception` with the specific exception(s) actually raised.",
        "steps": [
            "Gather: read the try-body and every function it calls to enumerate what can raise.",
            "Study: find how the same exceptions are handled elsewhere in the module for consistency.",
            "Requirements: catch only the specific types; let unexpected errors propagate.",
            "Identify files: the catch site plus any callers depending on the swallowed behavior.",
            "Document: list which exceptions are now caught and why the rest should propagate.",
            "Plan: narrow the catch -> preserve intended handling -> ensure logging/re-raise is correct.",
            "Review: confirm no real error path is now silently surfaced incorrectly.",
            "Build & verify: run the module's tests; add a case asserting unexpected errors propagate.",
        ],
        "acceptance": [
            "No bare `except Exception` remains at the target site.",
            "Only exceptions the try-body can actually raise are caught.",
            "Unexpected exceptions propagate; existing tests still pass.",
        ],
        "verify": "pytest tests/<affected_path> && rg 'except Exception' <file>  # expect no match",
    },
    RemediationClass.EXHAUSTIVE_DEPS: {
        "objective": "Remove the suppression and correctly resolve the dependency array — fixing the latent bug if real.",
        "steps": [
            "Gather: read the effect/callback and trace every value it closes over.",
            "Study: determine whether the missing dep is a real stale-closure bug or a deliberate omission.",
            "Requirements: either add the deps, or restructure (useCallback/ref) to make omission correct.",
            "Identify files: the component plus any consumers affected by changed effect timing.",
            "Document: state whether a latent bug existed and how the fix addresses it.",
            "Plan: remove suppression -> apply the correct dependency handling -> re-run the rule clean.",
            "Review: confirm no new infinite-render or missed-update is introduced.",
            "Build & verify: lint passes without the suppression; component tests pass.",
        ],
        "acceptance": [
            "The eslint-disable for exhaustive-deps is removed.",
            "react-hooks/exhaustive-deps passes cleanly on the file.",
            "No new render loop; component tests pass.",
        ],
        "verify": "cd superset-frontend && npx eslint <file> --rule 'react-hooks/exhaustive-deps: error'",
    },
    RemediationClass.ANY_TYPE: {
        "objective": "Replace `any` with precise types inferred from usage in this file.",
        "steps": [
            "Gather: for each `any`, read how the value is produced and consumed.",
            "Study: look for an existing interface/type that already models the shape.",
            "Requirements: prefer reusing existing types; introduce a narrow local type only if needed.",
            "Identify files: this file plus any module exporting the relevant shape.",
            "Document: note any newly introduced types and why.",
            "Plan: type bottom-up (leaf values first) -> let inference flow upward.",
            "Review: confirm no `unknown`-laundering or `as any` casts were used as an escape.",
            "Build & verify: type-check passes; no new `any` introduced.",
        ],
        "acceptance": [
            "No `any` remains in the file (no `as any` casts either).",
            "tsc type-check passes with no new errors.",
        ],
        "verify": "cd superset-frontend && npx tsc --noEmit && npx eslint <file> --rule '@typescript-eslint/no-explicit-any: error'",
    },
    RemediationClass.DESCRIBE_TO_TEST: {
        "objective": "Migrate `describe()` blocks to flat `test()` per project convention.",
        "steps": [
            "Gather: map the describe nesting and any shared beforeEach/afterEach setup.",
            "Study: check a migrated file for the project's preferred flat-test naming.",
            "Requirements: preserve setup/teardown semantics; keep test names traceable.",
            "Identify files: just this test file.",
            "Document: note any non-mechanical change (shared setup hoisted, dynamic names resolved).",
            "Plan: flatten -> re-attach setup -> rename tests for clarity.",
            "Review: confirm no test was dropped or silently skipped.",
            "Build & verify: the file's tests pass with the same count and assertions.",
        ],
        "acceptance": [
            "No `describe()` blocks remain.",
            "Same number of tests run and pass; no skips introduced.",
        ],
        "verify": "cd superset-frontend && npx jest <file> --verbose",
    },
}
