"""
Event-driven webhook server for the remediation system.

Listens for GitHub webhook events and triggers remediation sessions:
  1. issues.labeled — when an issue gets the `auto-remediation` label, dispatch a Devin session
  2. pull_request.closed — when a PR is merged, update dossier and close the issue
  3. Manual /scan endpoint — trigger a full scan + issue creation + dispatch cycle

Usage:
    python webhook_server.py              # Start server on port 8080
    python webhook_server.py --port 9000  # Custom port
    python webhook_server.py --simulate   # Simulate mode (no real Devin sessions)
"""
from __future__ import annotations
import argparse
import hashlib
import hmac
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, request, jsonify

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

from core import RemediationClass, Finding
from playbooks import PLAYBOOKS
from dispatcher import (
    Issue, build_agent_prompt, DispatchState, REFERENCE_PRS,
    fetch_open_issues, dispatch_dry_run, dispatch_sessions_mcp_payload,
    render_dashboard, render_dashboard_from_dossiers,
    DOSSIERS_DIR,
)
from monitor import (
    MonitorState, SessionTimeline, FailureCategory,
    render_status_dashboard, render_failure_taxonomy,
    render_stuck_sessions, render_learning_curve,
)
from create_issues_gh import extract_provenance

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("webhook")

app = Flask(__name__)

DEVIN_API_BASE = "https://api.devin.ai/v1"
DEVIN_API_KEY = os.environ.get("DEVIN_API_KEY", "")
GITHUB_WEBHOOK_SECRET = os.environ.get("GITHUB_WEBHOOK_SECRET", "")
REPO = os.environ.get("GITHUB_REPO", "jjejones31/superset")
SIMULATE = False


# ─── Devin API client ───────────────────────────────────────────────────────

def devin_create_session(prompt: str, title: str, tags: list[str]) -> dict | None:
    """Create a Devin session via the REST API."""
    import requests

    if SIMULATE:
        sim_id = hashlib.sha1(title.encode()).hexdigest()[:16]
        log.info(f"[SIMULATE] Would create session: {title} → sim-{sim_id}")
        return {"session_id": f"sim-{sim_id}", "url": f"https://app.devin.ai/sessions/sim-{sim_id}"}

    if not DEVIN_API_KEY:
        log.error("DEVIN_API_KEY not set — cannot create sessions")
        return None

    resp = requests.post(
        f"{DEVIN_API_BASE}/sessions",
        headers={"Authorization": f"Bearer {DEVIN_API_KEY}", "Content-Type": "application/json"},
        json={"prompt": prompt, "title": title, "tags": tags},
        timeout=30,
    )
    if resp.status_code not in (200, 201):
        log.error(f"Devin API error {resp.status_code}: {resp.text[:200]}")
        return None

    data = resp.json()
    log.info(f"Session created: {data.get('session_id')} → {data.get('url')}")
    return data


def devin_get_session(session_id: str) -> dict | None:
    """Get session status from the Devin API."""
    import requests

    if SIMULATE:
        return {"session_id": session_id, "status": "finished", "status_enum": "stopped"}

    if not DEVIN_API_KEY:
        return None

    resp = requests.get(
        f"{DEVIN_API_BASE}/sessions/{session_id}",
        headers={"Authorization": f"Bearer {DEVIN_API_KEY}"},
        timeout=30,
    )
    if resp.status_code != 200:
        return None
    return resp.json()


# ─── Webhook handlers ───────────────────────────────────────────────────────

def verify_github_signature(payload: bytes, signature: str) -> bool:
    """Verify GitHub webhook HMAC signature."""
    if not GITHUB_WEBHOOK_SECRET:
        return True  # No secret configured, skip verification
    expected = "sha256=" + hmac.new(
        GITHUB_WEBHOOK_SECRET.encode(), payload, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


def handle_issue_labeled(payload: dict) -> dict:
    """Handle issues.labeled event — dispatch remediation session."""
    issue_data = payload.get("issue", {})
    label = payload.get("label", {}).get("name", "")

    if label != "auto-remediation":
        return {"action": "ignored", "reason": f"label '{label}' is not auto-remediation"}

    # Extract provenance from issue body
    body = issue_data.get("body", "")
    prov = extract_provenance(body)
    if not prov:
        return {"action": "skipped", "reason": "no provenance found in issue body"}

    finding_id = prov.get("finding_id", "")
    cls = prov.get("cls", "")

    # Check if already dispatched
    state = DispatchState.load()
    if state.is_dispatched(finding_id):
        existing = state.dispatched[finding_id]
        return {"action": "skipped", "reason": "already dispatched",
                "session_id": existing.get("session_id")}

    # Build the Issue object
    label_names = [l["name"] for l in issue_data.get("labels", [])]
    issue = Issue(
        number=issue_data["number"],
        title=issue_data["title"],
        url=issue_data.get("html_url", ""),
        labels=label_names,
        body=body,
        finding_id=finding_id,
        remediation_class=cls,
        scan_run_id=prov.get("scan_run_id", ""),
        natural_key=prov.get("natural_key", ""),
        is_hero="hero" in label_names,
    )

    # Build prompt and dispatch
    prompt = build_agent_prompt(issue)
    tags = [
        f"remediation:{cls}",
        f"finding:{finding_id}",
        f"issue:{issue.number}",
        "auto-remediation",
    ]

    result = devin_create_session(prompt, f"[remediation] #{issue.number} {finding_id} {cls}", tags)
    if not result:
        return {"action": "error", "reason": "failed to create Devin session"}

    session_id = result["session_id"]

    # Record dispatch
    state.record_dispatch(finding_id, session_id, issue.number, cls)

    # Update monitor
    monitor = MonitorState.load()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    tl = SessionTimeline(
        finding_id=finding_id,
        session_id=session_id,
        remediation_class=cls,
        issue_number=issue.number,
        dispatched_at=now,
        status="running",
    )
    monitor.timelines[finding_id] = tl
    monitor.save()

    log.info(f"Dispatched session {session_id} for #{issue.number} [{cls}] {finding_id}")
    return {
        "action": "dispatched",
        "session_id": session_id,
        "session_url": result.get("url"),
        "issue_number": issue.number,
        "finding_id": finding_id,
        "remediation_class": cls,
    }


def handle_pr_merged(payload: dict) -> dict:
    """Handle pull_request.closed (merged) — update dossier, close issue."""
    pr = payload.get("pull_request", {})
    if not pr.get("merged"):
        return {"action": "ignored", "reason": "PR closed but not merged"}

    # Look for finding_id in PR body
    body = pr.get("body", "")
    state = DispatchState.load()

    # Find matching dispatched session by PR URL
    pr_url = pr.get("html_url", "")
    matched_finding = None
    for fid, entry in state.dispatched.items():
        if entry.get("pr_url") == pr_url:
            matched_finding = fid
            break

    # Also try to find finding_id directly in PR body
    if not matched_finding:
        for fid in state.dispatched:
            if fid in body:
                matched_finding = fid
                break

    if not matched_finding:
        return {"action": "ignored", "reason": "no matching finding for this PR"}

    # Update state
    state.update_session(matched_finding, outcome="success", status="completed", pr_url=pr_url)

    log.info(f"PR merged for {matched_finding}: {pr_url}")
    return {"action": "completed", "finding_id": matched_finding, "pr_url": pr_url}


# ─── Routes ─────────────────────────────────────────────────────────────────

@app.route("/webhook", methods=["POST"])
def webhook():
    """GitHub webhook endpoint."""
    payload_bytes = request.get_data()
    signature = request.headers.get("X-Hub-Signature-256", "")

    if not verify_github_signature(payload_bytes, signature):
        return jsonify({"error": "invalid signature"}), 403

    event = request.headers.get("X-GitHub-Event", "")
    payload = request.get_json(force=True)
    action = payload.get("action", "")

    log.info(f"Webhook received: {event}.{action}")

    if event == "issues" and action == "labeled":
        result = handle_issue_labeled(payload)
    elif event == "pull_request" and action == "closed":
        result = handle_pr_merged(payload)
    else:
        result = {"action": "ignored", "reason": f"unhandled event: {event}.{action}"}

    return jsonify(result)


@app.route("/scan", methods=["POST"])
def scan_and_dispatch():
    """
    Manual trigger: run scanners, create issues, and dispatch sessions.
    This simulates: scan results → issue creation → session dispatch.
    """
    from scanners import scan_cve, scan_broad_catch, scan_exhaustive_deps, scan_any_type, scan_describe_to_test
    from create_issues_gh import run as create_issues_run

    log.info("Manual scan triggered")

    # Run all scanners
    findings = []
    findings.extend(scan_cve())
    findings.extend(scan_broad_catch())
    findings.extend(scan_exhaustive_deps())
    findings.extend(scan_any_type())
    findings.extend(scan_describe_to_test())

    log.info(f"Scan complete: {len(findings)} findings")

    # Create issues (dry_run based on simulate mode)
    create_issues_run(findings, dry_run=SIMULATE)

    return jsonify({
        "action": "scan_complete",
        "findings": len(findings),
        "simulate": SIMULATE,
    })


@app.route("/dispatch", methods=["POST"])
def dispatch():
    """
    Manual trigger: dispatch sessions for all undispatched auto-remediation issues.
    Query params: ?heroes_only=true, ?concurrency=5
    """
    heroes_only = request.args.get("heroes_only", "false").lower() == "true"
    concurrency = int(request.args.get("concurrency", "5"))

    issues = fetch_open_issues()
    if heroes_only:
        issues = [i for i in issues if i.is_hero]

    state = DispatchState.load()
    to_dispatch = [i for i in issues if not state.is_dispatched(i.finding_id)]
    batch = to_dispatch[:concurrency]

    results = []
    for issue in batch:
        prompt = build_agent_prompt(issue)
        tags = [
            f"remediation:{issue.remediation_class}",
            f"finding:{issue.finding_id}",
            f"issue:{issue.number}",
            "auto-remediation",
        ]
        session = devin_create_session(
            prompt,
            f"[remediation] #{issue.number} {issue.finding_id} {issue.remediation_class}",
            tags,
        )
        if session:
            state.record_dispatch(issue.finding_id, session["session_id"],
                                  issue.number, issue.remediation_class)
            results.append({
                "issue_number": issue.number,
                "finding_id": issue.finding_id,
                "session_id": session["session_id"],
                "session_url": session.get("url"),
            })

    return jsonify({
        "action": "dispatched",
        "sessions_created": len(results),
        "sessions": results,
    })


@app.route("/dashboard", methods=["GET"])
def dashboard():
    """JSON dashboard with full observability data."""
    state = DispatchState.load()
    monitor = MonitorState.load()

    total = len(state.dispatched)
    running = sum(1 for e in state.dispatched.values() if e.get("status") == "running")
    success = sum(1 for e in state.dispatched.values() if e.get("outcome") == "success")
    failed = sum(1 for e in state.dispatched.values() if e.get("outcome") == "failed")

    # Per-class breakdown
    by_class: dict[str, dict] = {}
    for fid, entry in state.dispatched.items():
        cls = entry.get("remediation_class", "unknown")
        if cls not in by_class:
            by_class[cls] = {"total": 0, "running": 0, "success": 0, "failed": 0}
        by_class[cls]["total"] += 1
        if entry.get("status") == "running":
            by_class[cls]["running"] += 1
        if entry.get("outcome") == "success":
            by_class[cls]["success"] += 1
        if entry.get("outcome") == "failed":
            by_class[cls]["failed"] += 1

    # Stuck sessions
    stuck = [
        {"finding_id": fid, "session_id": tl.session_id,
         "class": tl.remediation_class, "dispatched_at": tl.dispatched_at}
        for fid, tl in monitor.timelines.items()
        if tl.is_stuck
    ]

    return jsonify({
        "summary": {"total": total, "running": running, "success": success, "failed": failed},
        "by_class": by_class,
        "stuck_sessions": stuck,
        "reference_prs": list(REFERENCE_PRS.keys()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


@app.route("/dashboard/text", methods=["GET"])
def dashboard_text():
    """Text-based dashboard for terminal/CLI viewing."""
    state = DispatchState.load()
    monitor = MonitorState.load()

    output = []
    output.append(render_status_dashboard(monitor))
    output.append(render_failure_taxonomy(monitor))
    output.append(render_stuck_sessions(monitor))
    output.append(render_learning_curve(monitor))

    return "\n".join(output), 200, {"Content-Type": "text/plain"}


@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint."""
    return jsonify({
        "status": "ok",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "simulate_mode": SIMULATE,
        "devin_api_configured": bool(DEVIN_API_KEY),
        "webhook_secret_configured": bool(GITHUB_WEBHOOK_SECRET),
    })


# ─── Main ───────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Remediation Webhook Server")
    parser.add_argument("--port", type=int, default=8080, help="Port to listen on")
    parser.add_argument("--simulate", action="store_true", help="Simulate mode (no real Devin sessions)")
    args = parser.parse_args()

    global SIMULATE
    SIMULATE = args.simulate

    log.info(f"Starting webhook server on port {args.port}")
    log.info(f"  Simulate mode: {SIMULATE}")
    log.info(f"  Devin API key: {'configured' if DEVIN_API_KEY else 'NOT SET'}")
    log.info(f"  Webhook secret: {'configured' if GITHUB_WEBHOOK_SECRET else 'NOT SET'}")
    log.info(f"  Target repo: {REPO}")
    log.info("")
    log.info("Endpoints:")
    log.info(f"  POST /webhook          — GitHub webhook receiver")
    log.info(f"  POST /scan             — Trigger scan + issue creation")
    log.info(f"  POST /dispatch         — Dispatch sessions for open issues")
    log.info(f"  GET  /dashboard        — JSON observability dashboard")
    log.info(f"  GET  /dashboard/text   — Text dashboard (terminal-friendly)")
    log.info(f"  GET  /health           — Health check")

    app.run(host="0.0.0.0", port=args.port, debug=False)


if __name__ == "__main__":
    main()
