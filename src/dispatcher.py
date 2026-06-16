"""
Dispatcher: reads issues from GitHub, launches Devin sessions per issue,
polls them to terminal state, and fills Dossiers.

Usage:
    # Dry run — show what sessions would be launched
    python dispatcher.py --dry-run

    # Launch sessions for all open auto-remediation issues (max N concurrent)
    python dispatcher.py --apply --concurrency 5

    # Launch sessions for hero issues only
    python dispatcher.py --apply --heroes-only

    # Launch a single issue by number
    python dispatcher.py --apply --issue 26

    # Simulate mode — no real sessions, generates mock dossiers
    python dispatcher.py --simulate
"""
from __future__ import annotations
import argparse
import json
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from core import RemediationClass, NARRATIVE
from playbooks import PLAYBOOKS
from dossier import Dossier, Outcome, Verification, ReasoningStep, CrossImpact
from create_issues_gh import extract_provenance

REPO = "jjejones31/superset"
REPO_FULL = "github.com/jjejones31/superset"
STATE_FILE = Path(__file__).parent / "dispatcher_state.json"
DOSSIERS_DIR = Path(__file__).parent / "dossiers"


# ─── Issue model ────────────────────────────────────────────────────────────

@dataclass
class Issue:
    number: int
    title: str
    url: str
    labels: list[str]
    body: str
    finding_id: str = ""
    remediation_class: str = ""
    scan_run_id: str = ""
    natural_key: str = ""
    is_hero: bool = False

    @classmethod
    def from_gh_json(cls, data: dict) -> Issue | None:
        prov = extract_provenance(data.get("body") or "")
        if not prov or not prov.get("finding_id"):
            return None
        label_names = [l["name"] for l in data.get("labels", [])]
        return cls(
            number=data["number"],
            title=data["title"],
            url=data["url"],
            labels=label_names,
            body=data.get("body", ""),
            finding_id=prov["finding_id"],
            remediation_class=prov.get("cls", ""),
            scan_run_id=prov.get("scan_run_id", ""),
            natural_key=prov.get("natural_key", ""),
            is_hero="hero" in label_names,
        )


# ─── GitHub helpers ─────────────────────────────────────────────────────────

def fetch_open_issues(label: str = "auto-remediation", limit: int = 200) -> list[Issue]:
    """Fetch open auto-remediation issues from the fork."""
    result = subprocess.run(
        ["gh", "issue", "list", "--repo", REPO, "--label", label,
         "--state", "open", "--limit", str(limit),
         "--json", "number,title,url,labels,body"],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print(f"ERROR fetching issues: {result.stderr.strip()}")
        return []
    issues = []
    for data in json.loads(result.stdout):
        issue = Issue.from_gh_json(data)
        if issue:
            issues.append(issue)
    return issues


# ─── Reference PRs (completed test runs per class) ─────────────────────────

REFERENCE_PRS: dict[str, dict] = {
    "broad-catch": {
        "pr_url": "https://github.com/jjejones31/superset/pull/62",
        "issue_number": 15,
        "finding_id": "f_e4e396bf12",
        "summary": "Narrowed `except Exception` in `Database.has_view()` L1253 to `except (DBAPIError, NotImplementedError)`. Traced single call path, used SQLAlchemy base exception class, added 3 unit tests for propagation/catch behavior.",
        "key_learnings": [
            "Use SQLAlchemy base exception (DBAPIError) rather than individual subclasses",
            "Always add a test for unexpected error propagation",
            "Check dialect implementations to enumerate possible exceptions",
            "File tests in tests/unit_tests/models/core_test.py",
        ],
    },
    "describe-to-test": {
        "pr_url": "https://github.com/jjejones31/superset/pull/63",
        "issue_number": 60,
        "finding_id": "f_701d26fa02",
        "summary": "Migrated AdhocFilter.test.ts: removed describe() wrapper + eslint-disable comment, prefixed test names with component name, dedented to flat. All 14 tests preserved.",
        "key_learnings": [
            "Prefix test names with component/module name for traceability",
            "Remove the eslint-disable-next-line comment (it's the migration marker)",
            "If beforeEach exists, inline setup into each test or extract to helper",
            "Run npx jest <file> --verbose to verify same test count",
        ],
    },
    "any-type": {
        "pr_url": "https://github.com/jjejones31/superset/pull/64",
        "issue_number": 45,
        "finding_id": "f_0484d91daa",
        "summary": "Eliminated 7 `any` types in SavedQueryList/index.tsx. Used CellProps<D> from react-table, typed useSelector callback, extended shared type locally for API fields.",
        "key_learnings": [
            "Use CellProps<D> from react-table for Cell renderers (very common in list pages)",
            "Type useSelector with actual Redux store shape",
            "Extend shared types locally when API returns extra fields",
            "Remove annotations where TypeScript inference suffices",
            "Look for existing types in @superset-ui/core, @superset-ui/chart-controls, src/types/",
        ],
    },
}

REFERENCES_FILE = Path(__file__).parent / "reference_prs.json"


def save_reference_prs() -> None:
    """Persist REFERENCE_PRS to disk so poller can append new ones."""
    REFERENCES_FILE.write_text(json.dumps(REFERENCE_PRS, indent=2))


def load_reference_prs() -> None:
    """Load reference PRs from disk (merges with hardcoded defaults)."""
    global REFERENCE_PRS
    if REFERENCES_FILE.exists():
        stored = json.loads(REFERENCES_FILE.read_text())
        for cls, ref in stored.items():
            if cls not in REFERENCE_PRS:
                REFERENCE_PRS[cls] = ref


def add_reference_pr(cls: str, pr_url: str, issue_number: int,
                     finding_id: str, summary: str,
                     key_learnings: list[str]) -> None:
    """Add a new reference PR for a class (called by poller on success)."""
    REFERENCE_PRS[cls] = {
        "pr_url": pr_url,
        "issue_number": issue_number,
        "finding_id": finding_id,
        "summary": summary,
        "key_learnings": key_learnings,
    }
    save_reference_prs()


# Initialize from disk on import
load_reference_prs()


# ─── Prompt builder ─────────────────────────────────────────────────────────

def build_agent_prompt(issue: Issue) -> str:
    """Build the full agent prompt from the issue + playbook + reference PR."""
    cls_enum = RemediationClass(issue.remediation_class)
    pb = PLAYBOOKS[cls_enum]
    steps = "\n".join(f"  {i+1}. {s}" for i, s in enumerate(pb["steps"]))
    accept = "\n".join(f"  - {a}" for a in pb["acceptance"])

    # Build reference section if a completed PR exists for this class
    ref_section = ""
    ref = REFERENCE_PRS.get(issue.remediation_class)
    if ref:
        learnings = "\n".join(f"  - {l}" for l in ref["key_learnings"])
        ref_section = f"""
## Reference: Completed PR for this class
A similar ticket was already completed successfully. Study this PR before starting:
- **PR:** {ref['pr_url']} (issue #{ref['issue_number']}, finding {ref['finding_id']})
- **What was done:** {ref['summary']}
- **Key learnings:**
{learnings}

Use this as a starting pattern, but adapt to the specifics of YOUR finding.
"""

    return f"""You are remediating a tracked finding in the `jjejones31/superset` fork.

## Issue #{issue.number}: {issue.title}
URL: {issue.url}
Finding ID: {issue.finding_id}
Class: {issue.remediation_class} ({NARRATIVE[cls_enum]})

## Objective
{pb['objective']}

## Remediation Process (follow in order)
{steps}

## Acceptance Criteria
{accept}

## Verify Command
{pb['verify']}
{ref_section}
## Instructions
1. Work on a feature branch: `git checkout -b devin/remediation-{issue.finding_id}`
2. Follow the 8-step process above IN ORDER.
3. After completing all steps, run the verify command.
4. Create a PR targeting `master` with a clear title and description.
5. In the PR body, include the finding_id `{issue.finding_id}` for traceability.
6. If you encounter a blocker that prevents completion, document what you tried and why it failed.

Focus on this ONE finding only. Do not attempt to fix other issues in the same PR.
"""


# ─── Session management ─────────────────────────────────────────────────────

@dataclass
class DispatchState:
    """Tracks which issues have been dispatched and their session status."""
    dispatched: dict[str, dict] = field(default_factory=dict)
    # key = finding_id, value = {session_id, issue_number, status, pr_url, ...}

    @classmethod
    def load(cls) -> DispatchState:
        if STATE_FILE.exists():
            data = json.loads(STATE_FILE.read_text())
            return cls(dispatched=data.get("dispatched", {}))
        return cls()

    def save(self) -> None:
        STATE_FILE.write_text(json.dumps(
            {"dispatched": self.dispatched}, indent=2))

    def is_dispatched(self, finding_id: str) -> bool:
        return finding_id in self.dispatched

    def record_dispatch(self, finding_id: str, session_id: str,
                        issue_number: int, cls: str) -> None:
        self.dispatched[finding_id] = {
            "session_id": session_id,
            "issue_number": issue_number,
            "remediation_class": cls,
            "status": "running",
            "pr_url": None,
            "outcome": None,
            "dispatched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        self.save()

    def update_session(self, finding_id: str, **kwargs) -> None:
        if finding_id in self.dispatched:
            self.dispatched[finding_id].update(kwargs)
            self.save()


# ─── Dispatcher logic ───────────────────────────────────────────────────────

def dispatch_dry_run(issues: list[Issue], state: DispatchState) -> None:
    """Print what would be dispatched."""
    print(f"\n{'='*70}")
    print(f" DRY RUN — {len(issues)} issues available")
    print(f"{'='*70}\n")

    for issue in issues:
        already = state.is_dispatched(issue.finding_id)
        status = "SKIP (already dispatched)" if already else "WOULD DISPATCH"
        hero = " ★ HERO" if issue.is_hero else ""
        print(f"  [{status}] #{issue.number} {issue.finding_id} "
              f"[{issue.remediation_class}] {issue.title}{hero}")

    to_dispatch = [i for i in issues if not state.is_dispatched(i.finding_id)]
    print(f"\n  → {len(to_dispatch)} new sessions would be created")
    print(f"  → {len(issues) - len(to_dispatch)} already dispatched (skipped)")


def dispatch_simulate(issues: list[Issue], state: DispatchState) -> None:
    """Generate mock dossiers for all issues (no real sessions)."""
    DOSSIERS_DIR.mkdir(exist_ok=True)
    print(f"\n{'='*70}")
    print(f" SIMULATE MODE — generating mock dossiers for {len(issues)} issues")
    print(f"{'='*70}\n")

    for issue in issues:
        cls_enum = RemediationClass(issue.remediation_class)
        pb = PLAYBOOKS[cls_enum]
        dossier = Dossier(
            scan_run_id=issue.scan_run_id,
            finding_id=issue.finding_id,
            remediation_class=cls_enum,
            issue_number=issue.number,
            session_id=f"sim-{issue.finding_id}",
            pr_url=f"https://github.com/{REPO}/pull/999",
            severity="medium",
            context_gathered=[f"Read {issue.natural_key}"],
            patterns_studied=["Studied similar patterns in adjacent files"],
            reasoning_trace=[
                ReasoningStep(
                    decision="Identified root cause",
                    rationale="Based on analysis of the target site",
                    evidence=f"File: {issue.natural_key}",
                )
            ],
            files_touched=[issue.natural_key.split(":")[0] if ":" in issue.natural_key else issue.natural_key],
            diff_summary=f"Fixed [{issue.remediation_class}] in target file",
            cross_impact=CrossImpact(
                reached_modules=["superset"],
                callers_checked=3,
                blast_radius="small",
            ),
            verification=Verification(
                command=pb["verify"],
                passed=True,
                evidence="All checks passed",
            ),
            outcome=Outcome.SUCCESS,
            acu_cost=0.15,
        )
        out_path = DOSSIERS_DIR / f"{issue.finding_id}.json"
        out_path.write_text(dossier.model_dump_json(indent=2))
        print(f"  ✓ {issue.finding_id} → {out_path.name}")

    print(f"\n  → {len(issues)} mock dossiers written to {DOSSIERS_DIR}/")


def dispatch_sessions_mcp_payload(issues: list[Issue], state: DispatchState,
                                   concurrency: int = 5) -> list[dict]:
    """
    Build the MCP devin_session_create payload for a batch of issues.
    Returns the list of session specs ready to pass to the MCP tool.
    """
    to_dispatch = [i for i in issues if not state.is_dispatched(i.finding_id)]
    batch = to_dispatch[:concurrency]

    sessions = []
    for issue in batch:
        prompt = build_agent_prompt(issue)
        sessions.append({
            "prompt": prompt,
            "title": f"[remediation] #{issue.number} {issue.finding_id} {issue.remediation_class}",
            "repos": [REPO_FULL],
            "tags": [
                f"remediation:{issue.remediation_class}",
                f"finding:{issue.finding_id}",
                f"issue:{issue.number}",
                "auto-remediation",
            ],
        })

    return sessions


def print_dispatch_plan(issues: list[Issue], state: DispatchState,
                        concurrency: int) -> list[Issue]:
    """Show what will be dispatched and return the batch."""
    to_dispatch = [i for i in issues if not state.is_dispatched(i.finding_id)]
    batch = to_dispatch[:concurrency]

    print(f"\n{'='*70}")
    print(f" DISPATCH — launching {len(batch)} sessions (concurrency={concurrency})")
    print(f"{'='*70}\n")

    for issue in batch:
        hero = " ★ HERO" if issue.is_hero else ""
        print(f"  → #{issue.number} {issue.finding_id} "
              f"[{issue.remediation_class}] {issue.title}{hero}")

    return batch


# ─── Dashboard ──────────────────────────────────────────────────────────────

def render_dashboard(state: DispatchState) -> str:
    """Render a text-based status dashboard from dispatch state."""
    lines = []
    lines.append(f"\n{'='*70}")
    lines.append(f" REMEDIATION DASHBOARD")
    lines.append(f"{'='*70}\n")

    # Group by class
    by_class: dict[str, list[dict]] = {}
    for fid, entry in state.dispatched.items():
        cls = entry.get("remediation_class", "unknown")
        by_class.setdefault(cls, []).append({**entry, "finding_id": fid})

    total = len(state.dispatched)
    running = sum(1 for e in state.dispatched.values() if e.get("status") == "running")
    success = sum(1 for e in state.dispatched.values() if e.get("outcome") == "success")
    failed = sum(1 for e in state.dispatched.values() if e.get("outcome") == "failed")
    partial = sum(1 for e in state.dispatched.values() if e.get("outcome") == "partial")

    lines.append(f"  Total dispatched: {total}")
    lines.append(f"  Running: {running}  |  Success: {success}  |  "
                 f"Partial: {partial}  |  Failed: {failed}")
    lines.append("")

    lines.append(f"  {'Class':<20} {'Total':<8} {'Running':<10} "
                 f"{'Success':<10} {'Rate':<8}")
    lines.append(f"  {'─'*60}")

    for cls, entries in sorted(by_class.items()):
        t = len(entries)
        r = sum(1 for e in entries if e.get("status") == "running")
        s = sum(1 for e in entries if e.get("outcome") == "success")
        rate = f"{s/t*100:.0f}%" if t > 0 else "–"
        lines.append(f"  {cls:<20} {t:<8} {r:<10} {s:<10} {rate:<8}")

    lines.append("")

    # Dossier files
    if DOSSIERS_DIR.exists():
        dossier_count = len(list(DOSSIERS_DIR.glob("*.json")))
        lines.append(f"  Dossier files: {dossier_count} in {DOSSIERS_DIR}/")

    return "\n".join(lines)


def render_dashboard_from_dossiers() -> str:
    """Build dashboard from dossier JSON files (for simulate mode)."""
    if not DOSSIERS_DIR.exists():
        return "  No dossiers found."

    lines = []
    lines.append(f"\n{'='*70}")
    lines.append(f" REMEDIATION DASHBOARD (from dossiers)")
    lines.append(f"{'='*70}\n")

    dossiers = []
    for p in sorted(DOSSIERS_DIR.glob("*.json")):
        d = Dossier.model_validate_json(p.read_text())
        dossiers.append(d)

    by_class: dict[str, list[Dossier]] = {}
    for d in dossiers:
        by_class.setdefault(d.remediation_class.value, []).append(d)

    total = len(dossiers)
    success = sum(1 for d in dossiers if d.outcome == Outcome.SUCCESS)
    failed = sum(1 for d in dossiers if d.outcome == Outcome.FAILED)
    partial = sum(1 for d in dossiers if d.outcome == Outcome.PARTIAL)
    total_acu = sum(d.acu_cost for d in dossiers)

    lines.append(f"  Total: {total}  |  Success: {success}  |  "
                 f"Partial: {partial}  |  Failed: {failed}")
    lines.append(f"  Total ACU cost: {total_acu:.2f}")
    lines.append(f"  Avg ACU/fix: {total_acu/max(success,1):.3f}")
    lines.append("")

    lines.append(f"  {'Class':<20} {'Total':<7} {'OK':<5} {'Rate':<7} "
                 f"{'ACU':<8} {'Avg Risk':<15}")
    lines.append(f"  {'─'*65}")

    for cls, entries in sorted(by_class.items()):
        t = len(entries)
        s = sum(1 for d in entries if d.outcome == Outcome.SUCCESS)
        rate = f"{s/t*100:.0f}%" if t > 0 else "–"
        acu = sum(d.acu_cost for d in entries)
        risks = [d.risk_flag.value for d in entries]
        most_common_risk = max(set(risks), key=risks.count) if risks else "–"
        lines.append(f"  {cls:<20} {t:<7} {s:<5} {rate:<7} "
                     f"{acu:<8.2f} {most_common_risk:<15}")

    lines.append("")
    return "\n".join(lines)


# ─── CLI ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Remediation Dispatcher")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true", help="Show what would be dispatched")
    mode.add_argument("--apply", action="store_true", help="Launch Devin sessions")
    mode.add_argument("--simulate", action="store_true", help="Generate mock dossiers")
    mode.add_argument("--dashboard", action="store_true", help="Show status dashboard")

    parser.add_argument("--concurrency", type=int, default=5, help="Max concurrent sessions")
    parser.add_argument("--heroes-only", action="store_true", help="Only dispatch hero issues")
    parser.add_argument("--issue", type=int, help="Dispatch a single issue by number")
    parser.add_argument("--class", dest="cls", help="Filter by remediation class")
    args = parser.parse_args()

    if args.dashboard:
        state = DispatchState.load()
        if DOSSIERS_DIR.exists() and list(DOSSIERS_DIR.glob("*.json")):
            print(render_dashboard_from_dossiers())
        else:
            print(render_dashboard(state))
        return

    # Fetch issues
    print("Fetching open auto-remediation issues...")
    issues = fetch_open_issues()
    print(f"  Found {len(issues)} issues\n")

    # Apply filters
    if args.heroes_only:
        issues = [i for i in issues if i.is_hero]
        print(f"  Filtered to {len(issues)} hero issues")
    if args.issue:
        issues = [i for i in issues if i.number == args.issue]
        print(f"  Filtered to issue #{args.issue}")
    if args.cls:
        issues = [i for i in issues if i.remediation_class == args.cls]
        print(f"  Filtered to class={args.cls}: {len(issues)} issues")

    if not issues:
        print("  No issues match the filter criteria.")
        return

    state = DispatchState.load()

    if args.dry_run:
        dispatch_dry_run(issues, state)
    elif args.simulate:
        dispatch_simulate(issues, state)
        print(render_dashboard_from_dossiers())
    elif args.apply:
        batch = print_dispatch_plan(issues, state, args.concurrency)
        if not batch:
            print("  Nothing to dispatch (all already running).")
            return

        # Build the MCP payload (for use with devin_session_create)
        payload = dispatch_sessions_mcp_payload(issues, state, args.concurrency)

        # Write the payload to a file for the parent session to pick up
        payload_path = Path(__file__).parent / "dispatch_payload.json"
        payload_path.write_text(json.dumps(payload, indent=2))
        print(f"\n  Session payload written to: {payload_path}")
        print(f"  → Pass this to devin_session_create via the MCP tool")
        print(f"  → Or use the parent Devin session to orchestrate")


if __name__ == "__main__":
    main()
