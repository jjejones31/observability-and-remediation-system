"""
Scanners that produce Finding objects from the Superset codebase.
Each scanner targets one RemediationClass and emits findings with stable natural_keys.
"""
from __future__ import annotations
import json
import os
import re
import subprocess
from core import Finding, RemediationClass

SCAN_RUN_ID = "scan-2026-06-12-01"
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def scan_cve() -> list[Finding]:
    """Known CVEs from pip-audit and npm audit."""
    findings = []

    # Python CVEs (from pip-audit results)
    python_cves = [
        {
            "package": "flask",
            "version": "2.3.3",
            "cve_id": "CVE-2026-27205",
            "fix_version": "3.1.3",
            "severity": "high",
            "detail": (
                "Flask 2.3.3 is vulnerable to CVE-2026-27205. "
                "Fix available: upgrade to flask>=3.1.3. "
                "File: `requirements/base.txt` line 109. "
                "Flask is the core web framework for Superset — this upgrade may involve "
                "breaking API changes between 2.x and 3.x."
            ),
        },
        {
            "package": "pyjwt",
            "version": "2.12.0",
            "cve_id": "PYSEC-2026-179",
            "fix_version": "2.13.0",
            "severity": "high",
            "detail": (
                "PyJWT 2.12.0 has 5 known vulnerabilities (PYSEC-2026-175 through 179). "
                "Fix: upgrade to pyjwt>=2.13.0. File: `requirements/base.txt` line 318. "
                "PyJWT is used for authentication token handling throughout Superset."
            ),
        },
        {
            "package": "paramiko",
            "version": "3.5.1",
            "cve_id": "CVE-2026-44405",
            "fix_version": "unknown",
            "severity": "medium",
            "detail": (
                "Paramiko 3.5.1 is vulnerable to CVE-2026-44405. "
                "Note: paramiko is already capped <4.0 per recent commit 74845eaf0b. "
                "File: `requirements/base.txt` line 277. "
                "Used for SSH tunneling to databases."
            ),
        },
    ]

    for cve in python_cves:
        findings.append(Finding(
            cls=RemediationClass.CVE,
            natural_key=f"{cve['package']}:{cve['cve_id']}",
            title=f"Upgrade {cve['package']} {cve['version']} → {cve['fix_version']} ({cve['cve_id']})",
            scan_run_id=SCAN_RUN_ID,
            severity=cve["severity"],
            package=cve["package"],
            cve_id=cve["cve_id"],
            file_path="requirements/base.txt",
            detail=cve["detail"],
            is_hero=(cve["package"] == "flask"),  # Flask upgrade is highest-impact demo
        ))

    # Frontend CVEs (from npm audit)
    npm_cves = [
        {
            "package": "esbuild",
            "version": "0.17.0-0.28.0",
            "cve_id": "GHSA-gv7w-rqvm-qjhr",
            "fix_version": ">0.28.0 (via storybook upgrade)",
            "severity": "high",
            "detail": (
                "esbuild 0.17.0–0.28.0 is missing binary integrity verification, enabling "
                "remote code execution via NPM_CONFIG_REGISTRY. Affects storybook and tsx. "
                "Fix requires upgrading storybook to >=8.7.0. "
                "This is a dev dependency only — does not affect production builds."
            ),
        },
        {
            "package": "joi",
            "version": "<17.13.4",
            "cve_id": "GHSA-q7cg-457f-vx79",
            "fix_version": "17.13.4",
            "severity": "medium",
            "detail": (
                "joi (via jest-process-manager) has an uncaught RangeError on deeply nested input "
                "through recursive link() schemas. Fix: `npm audit fix` or upgrade jest-process-manager. "
                "Dev dependency only — affects test infrastructure."
            ),
        },
    ]

    for cve in npm_cves:
        findings.append(Finding(
            cls=RemediationClass.CVE,
            natural_key=f"{cve['package']}:{cve['cve_id']}",
            title=f"Upgrade {cve['package']} ({cve['cve_id']})",
            scan_run_id=SCAN_RUN_ID,
            severity=cve["severity"],
            package=cve["package"],
            cve_id=cve["cve_id"],
            file_path="superset-frontend/package.json",
            detail=cve["detail"],
        ))

    return findings


def scan_broad_catch() -> list[Finding]:
    """Find `except Exception` with pylint disable in non-test, non-migration Python files."""
    findings = []
    result = subprocess.run(
        ["grep", "-rn", "# pylint: disable=broad-except", "--include=*.py", "superset/"],
        capture_output=True, text=True, cwd=REPO_ROOT
    )
    for line in result.stdout.strip().split("\n"):
        if not line or "__pycache__" in line or "/test" in line or "migration" in line:
            continue
        parts = line.split(":", 2)
        if len(parts) < 3:
            continue
        file_path, line_num = parts[0], int(parts[1])
        # natural key is file:line (stable as long as the code doesn't move)
        natural_key = f"{file_path}:{line_num}"
        # Extract a readable snippet
        snippet = parts[2].strip()[:80]
        findings.append(Finding(
            cls=RemediationClass.BROAD_CATCH,
            natural_key=natural_key,
            title=f"Narrow broad except in `{file_path.split('/')[-1]}` L{line_num}",
            scan_run_id=SCAN_RUN_ID,
            severity="low",
            file_path=file_path,
            line=line_num,
            detail=f"```python\n{snippet}\n```\nReplace broad `except Exception` with specific exception type(s).",
        ))

    # Mark a few heroes for live demo
    hero_files = ["superset/models/core.py", "superset/commands/report/execute.py"]
    for f in findings:
        if f.file_path and any(h in f.file_path for h in hero_files):
            f.is_hero = True
            break  # just one hero per class

    return findings


def scan_exhaustive_deps() -> list[Finding]:
    """Find suppressed react-hooks/exhaustive-deps in non-test source files."""
    findings = []
    result = subprocess.run(
        ["grep", "-rn", "eslint-disable.*react-hooks/exhaustive-deps",
         "--include=*.tsx", "--include=*.ts", "superset-frontend/src/"],
        capture_output=True, text=True, cwd=REPO_ROOT
    )
    for line in result.stdout.strip().split("\n"):
        if not line or ".test." in line:
            continue
        parts = line.split(":", 2)
        if len(parts) < 3:
            continue
        file_path, line_num = parts[0], int(parts[1])
        natural_key = f"{file_path}:{line_num}"
        findings.append(Finding(
            cls=RemediationClass.EXHAUSTIVE_DEPS,
            natural_key=natural_key,
            title=f"Fix exhaustive-deps in `{file_path.split('/')[-1]}` L{line_num}",
            scan_run_id=SCAN_RUN_ID,
            severity="medium",
            file_path=file_path,
            line=line_num,
            detail=(
                "Suppressed `react-hooks/exhaustive-deps` rule. This may indicate a stale closure bug "
                "or an effect that fires on the wrong dependency set. Remove the suppression and fix "
                "the underlying dependency issue."
            ),
        ))

    # Hero: ExploreViewContainer is a high-value target
    for f in findings:
        if f.file_path and "ExploreViewContainer" in f.file_path:
            f.is_hero = True
            break

    return findings


def scan_any_type() -> list[Finding]:
    """Find files with `: any` type annotations (non-test src files)."""
    findings = []
    result = subprocess.run(
        ["grep", "-rn", ": any", "--include=*.tsx", "--include=*.ts",
         "superset-frontend/src/"],
        capture_output=True, text=True, cwd=REPO_ROOT
    )

    # Group by file, count instances
    from collections import Counter
    file_counts: Counter[str] = Counter()
    for line in result.stdout.strip().split("\n"):
        if not line or ".test." in line or "node_modules" in line:
            continue
        file_path = line.split(":")[0]
        file_counts[file_path] += 1

    # Create one finding per file (top files by count, cap at 20 for the initial batch)
    for file_path, count in file_counts.most_common(20):
        natural_key = file_path
        findings.append(Finding(
            cls=RemediationClass.ANY_TYPE,
            natural_key=natural_key,
            title=f"Eliminate {count} `any` types in `{file_path.split('/')[-1]}`",
            scan_run_id=SCAN_RUN_ID,
            severity="low",
            file_path=file_path,
            detail=(
                f"This file contains **{count} instances** of `: any` type annotations. "
                f"Per project standards (CLAUDE.md): 'NO `any` types — Use proper TypeScript types.' "
                f"Replace all `any` with precise types inferred from usage context."
            ),
        ))

    # Hero: MetricsControl is the most impactful
    for f in findings:
        if f.file_path and "MetricsControl.tsx" in f.file_path:
            f.is_hero = True
            break

    return findings


def scan_describe_to_test() -> list[Finding]:
    """Find test files with describe() blocks marked for migration."""
    findings = []
    result = subprocess.run(
        ["grep", "-rln",
         "eslint-disable-next-line no-restricted-globals -- TODO: Migrate from describe",
         "--include=*.test.tsx", "--include=*.test.ts",
         "superset-frontend/src/"],
        capture_output=True, text=True, cwd=REPO_ROOT
    )

    for file_path in result.stdout.strip().split("\n"):
        if not file_path:
            continue
        file_path = file_path.strip()
        natural_key = file_path
        # Count suppressions in this file
        count_result = subprocess.run(
            ["grep", "-c", "eslint-disable-next-line no-restricted-globals -- TODO", file_path],
            capture_output=True, text=True, cwd=REPO_ROOT
        )
        count = int(count_result.stdout.strip()) if count_result.stdout.strip() else 1
        findings.append(Finding(
            cls=RemediationClass.DESCRIBE_TO_TEST,
            natural_key=natural_key,
            title=f"Migrate `{file_path.split('/')[-1]}` from describe() to test()",
            scan_run_id=SCAN_RUN_ID,
            severity="low",
            file_path=file_path,
            detail=(
                f"This test file has **{count} describe() block(s)** marked with "
                f"`// eslint-disable-next-line no-restricted-globals -- TODO: Migrate from describe blocks`. "
                f"Per project convention (AGENTS.md): 'Use `test()` instead of `describe()`.'"
            ),
        ))

    # Cap at 15 for the initial batch — pick variety across directories
    findings = findings[:15]
    if findings:
        findings[0].is_hero = True

    return findings


def run_all_scanners() -> list[Finding]:
    """Run all scanners and return combined findings."""
    all_findings: list[Finding] = []
    print("Running CVE scanner...")
    all_findings.extend(scan_cve())
    print(f"  → {len(all_findings)} findings")

    print("Running broad-catch scanner...")
    broad = scan_broad_catch()
    # Cap broad-catch at 10 most impactful for initial batch
    broad_heroes = [f for f in broad if f.is_hero]
    broad_others = [f for f in broad if not f.is_hero]
    broad = broad_heroes + broad_others[:9]
    all_findings.extend(broad)
    print(f"  → {len(broad)} findings (capped from full set)")

    print("Running exhaustive-deps scanner...")
    deps = scan_exhaustive_deps()
    all_findings.extend(deps[:10])  # Cap at 10
    print(f"  → {min(len(deps), 10)} findings")

    print("Running any-type scanner...")
    any_type = scan_any_type()
    all_findings.extend(any_type)
    print(f"  → {len(any_type)} findings")

    print("Running describe-to-test scanner...")
    desc = scan_describe_to_test()
    all_findings.extend(desc)
    print(f"  → {len(desc)} findings")

    print(f"\nTotal: {len(all_findings)} findings "
          f"({sum(1 for f in all_findings if f.is_hero)} heroes)")
    return all_findings


if __name__ == "__main__":
    findings = run_all_scanners()
    output = [f.model_dump() for f in findings]
    with open(os.path.join(os.path.dirname(__file__), "findings.json"), "w") as fp:
        json.dump(output, fp, indent=2)
    print(f"\nWritten to findings.json")
