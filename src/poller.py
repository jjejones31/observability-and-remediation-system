"""
Poller: monitors dispatched Devin sessions, detects completion,
extracts PRs/outcomes, and writes Dossier JSON files.

This module provides functions for:
1. Checking session status via Devin MCP
2. Extracting PR URLs from session messages/attachments
3. Building Dossier objects from completed sessions
4. Writing dossiers to disk for the dashboard

Usage (as a library from the parent Devin session):
    from poller import poll_and_fill_dossiers
    results = poll_and_fill_dossiers(state)

Usage (standalone with MCP context — for the orchestrating session):
    python poller.py --check    # Print status of all dispatched sessions
    python poller.py --fill     # Fill dossiers for completed sessions
"""
from __future__ import annotations
import json
import re
import time
from pathlib import Path
from dataclasses import dataclass

from core import RemediationClass
from playbooks import PLAYBOOKS
from dossier import (
    Dossier, Outcome, Verification, ReasoningStep,
    CrossImpact, KnowledgeNote, distill_to_knowledge,
    friction_signal_for_playbook,
)
from dispatcher import DispatchState, DOSSIERS_DIR, REPO

PR_URL_PATTERN = re.compile(r"https://github\.com/[^/]+/[^/]+/pull/\d+")


@dataclass
class SessionResult:
    """Result extracted from a completed Devin session."""
    session_id: str
    finding_id: str
    status: str  # "exit", "error", "running", etc.
    status_detail: str  # "finished", "waiting_for_user", etc.
    pr_url: str | None = None
    outcome: Outcome = Outcome.FAILED
    messages_summary: str = ""
    files_touched: list[str] | None = None


def extract_pr_from_messages(messages: list[dict]) -> str | None:
    """Extract the first PR URL from session messages."""
    for msg in messages:
        content = msg.get("content", "") or msg.get("message", "") or ""
        match = PR_URL_PATTERN.search(content)
        if match:
            return match.group(0)
    return None


def determine_outcome(status: str, status_detail: str, pr_url: str | None) -> Outcome:
    """Determine the remediation outcome from session state."""
    if status == "error":
        return Outcome.FAILED
    if status == "exit" or status_detail == "finished":
        if pr_url:
            return Outcome.SUCCESS
        return Outcome.PARTIAL
    # Still running or waiting
    return Outcome.PARTIAL


def build_dossier_from_result(result: SessionResult, state_entry: dict) -> Dossier:
    """Convert a SessionResult + dispatch state entry into a Dossier."""
    cls_val = state_entry.get("remediation_class", "cve")
    try:
        cls_enum = RemediationClass(cls_val)
    except ValueError:
        cls_enum = RemediationClass.CVE

    pb = PLAYBOOKS[cls_enum]

    return Dossier(
        scan_run_id=state_entry.get("scan_run_id", "scan-2026-06-12-01"),
        finding_id=result.finding_id,
        remediation_class=cls_enum,
        issue_number=state_entry.get("issue_number"),
        session_id=result.session_id,
        pr_url=result.pr_url,
        severity=state_entry.get("severity", "medium"),
        context_gathered=[result.messages_summary[:200]] if result.messages_summary else [],
        reasoning_trace=[
            ReasoningStep(
                decision="Agent completed remediation",
                rationale=f"Session ended with status={result.status}, detail={result.status_detail}",
                evidence=result.pr_url or "no PR created",
            )
        ],
        files_touched=result.files_touched or [],
        verification=Verification(
            command=pb["verify"],
            passed=result.outcome == Outcome.SUCCESS,
            evidence=f"PR: {result.pr_url}" if result.pr_url else "No PR submitted",
        ),
        outcome=result.outcome,
        acu_cost=0.0,  # TODO: extract from session metadata when available
    )


def save_dossier(dossier: Dossier) -> Path:
    """Write a dossier to the dossiers directory."""
    DOSSIERS_DIR.mkdir(exist_ok=True)
    path = DOSSIERS_DIR / f"{dossier.finding_id}.json"
    path.write_text(dossier.model_dump_json(indent=2))
    return path


def process_completed_session(finding_id: str, session_data: dict,
                               state: DispatchState) -> Dossier | None:
    """
    Process a single completed session.
    session_data: the dict returned by devin_session_interact(action="get")
    """
    entry = state.dispatched.get(finding_id)
    if not entry:
        return None

    status = session_data.get("status", "unknown")
    status_detail = session_data.get("status_detail", "")

    # Check if settled
    settled_statuses = {"exit", "error"}
    settled_details = {"finished", "waiting_for_user", "waiting_for_approval"}
    if status not in settled_statuses and status_detail not in settled_details:
        return None  # still running

    # Extract PR from structured output or messages
    pr_url = None
    structured = session_data.get("structured_output")
    if structured and isinstance(structured, dict):
        pr_url = structured.get("pr_url")

    # If no structured output PR, try messages (would need MCP call)
    # For now, we check the state entry which can be updated by the orchestrator
    if not pr_url:
        pr_url = entry.get("pr_url")

    outcome = determine_outcome(status, status_detail, pr_url)

    result = SessionResult(
        session_id=entry.get("session_id", ""),
        finding_id=finding_id,
        status=status,
        status_detail=status_detail,
        pr_url=pr_url,
        outcome=outcome,
    )

    dossier = build_dossier_from_result(result, entry)

    # Update state
    state.update_session(finding_id,
                         status=status,
                         outcome=outcome.value,
                         pr_url=pr_url)

    # Write dossier
    save_dossier(dossier)

    # Knowledge distillation
    note = distill_to_knowledge(dossier)
    if note:
        # Write knowledge note to a file for the orchestrator to pick up
        knowledge_dir = DOSSIERS_DIR / "knowledge"
        knowledge_dir.mkdir(exist_ok=True)
        kpath = knowledge_dir / f"{finding_id}_knowledge.json"
        kpath.write_text(json.dumps(note.to_devin_payload(), indent=2))

    # Friction signals
    friction = friction_signal_for_playbook(dossier)
    if friction:
        friction_dir = DOSSIERS_DIR / "friction"
        friction_dir.mkdir(exist_ok=True)
        fpath = friction_dir / f"{finding_id}_friction.json"
        fpath.write_text(json.dumps(friction, indent=2))

    return dossier


def poll_summary(state: DispatchState) -> str:
    """Print summary of all dispatched sessions."""
    lines = []
    lines.append(f"\n{'='*70}")
    lines.append(f" SESSION STATUS SUMMARY")
    lines.append(f"{'='*70}\n")

    for fid, entry in sorted(state.dispatched.items()):
        status = entry.get("status", "unknown")
        outcome = entry.get("outcome", "–")
        pr = entry.get("pr_url", "–")
        lines.append(f"  {fid}  #{entry.get('issue_number','?'):<4}  "
                     f"[{entry.get('remediation_class','')}]  "
                     f"status={status}  outcome={outcome}  pr={pr}")

    return "\n".join(lines)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Session Poller")
    parser.add_argument("--check", action="store_true", help="Show status of dispatched sessions")
    parser.add_argument("--fill", action="store_true", help="Fill dossiers for completed sessions")
    args = parser.parse_args()

    state = DispatchState.load()

    if args.check:
        print(poll_summary(state))
    elif args.fill:
        print("Fill mode requires MCP context (run from orchestrating session)")
    else:
        parser.print_help()
