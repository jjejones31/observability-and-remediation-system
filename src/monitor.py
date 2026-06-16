"""
Monitor: real-time observability for remediation sessions.

Capabilities:
  1. Poll active sessions via Devin MCP (by tag)
  2. Track timestamps: dispatched → first_commit → PR_created → CI_pass → settled
  3. Compute real ACU from session metadata
  4. Detect stuck/looping sessions (no progress for N minutes)
  5. Failure taxonomy: categorize WHY sessions fail
  6. Per-class learning curve: does success rate improve as knowledge distills?
  7. Rich dashboard with time-series, failure breakdown, burndown

Usage:
    python monitor.py --status          # One-shot status of all active sessions
    python monitor.py --dashboard       # Full observability dashboard
    python monitor.py --stuck           # Show stuck sessions only
    python monitor.py --failures        # Failure taxonomy breakdown
    python monitor.py --learning-curve  # Per-class success over batch order
"""
from __future__ import annotations
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from pathlib import Path
from typing import Any

from core import RemediationClass, NARRATIVE
from dossier import Dossier, Outcome, RiskFlag
from dispatcher import DispatchState, DOSSIERS_DIR, REPO

MONITOR_STATE_FILE = Path(__file__).parent / "monitor_state.json"
STUCK_THRESHOLD_MINUTES = 30
LOOP_DETECTION_THRESHOLD = 3  # same error N times = looping


# ─── Failure Taxonomy ───────────────────────────────────────────────────────

class FailureCategory(str, Enum):
    AUTH_BLOCKED = "auth_blocked"         # Blocked on credentials/permissions
    LINT_LOOP = "lint_loop"              # Stuck in lint fix → fail → fix cycle
    WRONG_FILE = "wrong_file"            # Agent edited wrong file or misidentified target
    TEST_FAILURE = "test_failure"        # Tests fail after changes
    TIMEOUT = "timeout"                  # Session hit time limit
    DEPENDENCY_CONFLICT = "dep_conflict" # Version resolution failure
    BUILD_FAILURE = "build_failure"      # TypeScript/Python build fails
    STUCK_IDLE = "stuck_idle"            # No progress for extended period
    UNKNOWN = "unknown"                  # Unclassified

    @classmethod
    def classify(cls, signals: list[str], messages: list[str] | None = None) -> FailureCategory:
        """Classify failure from friction signals and session messages."""
        text = " ".join(signals + (messages or [])).lower()

        if any(k in text for k in ["auth", "permission", "credentials", "token", "401", "403"]):
            return cls.AUTH_BLOCKED
        if any(k in text for k in ["lint", "eslint", "prettier", "pre-commit"]):
            if text.count("lint") >= LOOP_DETECTION_THRESHOLD or "loop" in text:
                return cls.LINT_LOOP
            return cls.BUILD_FAILURE
        if any(k in text for k in ["wrong file", "not found", "no such file"]):
            return cls.WRONG_FILE
        if any(k in text for k in ["test fail", "assertion", "expect(", "pytest"]):
            return cls.TEST_FAILURE
        if any(k in text for k in ["timeout", "timed out", "exceeded"]):
            return cls.TIMEOUT
        if any(k in text for k in ["conflict", "resolution", "incompatible", "version"]):
            return cls.DEPENDENCY_CONFLICT
        if any(k in text for k in ["tsc", "type error", "build fail", "compile"]):
            return cls.BUILD_FAILURE
        if any(k in text for k in ["idle", "no progress", "stuck"]):
            return cls.STUCK_IDLE
        return cls.UNKNOWN


# ─── Timestamps ─────────────────────────────────────────────────────────────

@dataclass
class SessionTimeline:
    """Tracks key timestamps for a remediation session lifecycle."""
    finding_id: str
    session_id: str
    remediation_class: str
    issue_number: int | None = None

    dispatched_at: str | None = None
    first_activity_at: str | None = None
    first_commit_at: str | None = None
    pr_created_at: str | None = None
    ci_started_at: str | None = None
    ci_passed_at: str | None = None
    settled_at: str | None = None

    status: str = "unknown"
    status_detail: str = ""
    pr_url: str | None = None
    outcome: str | None = None
    failure_category: str | None = None
    acu_cost: float = 0.0
    last_checked_at: str | None = None

    # Derived metrics
    @property
    def time_to_pr(self) -> float | None:
        """Minutes from dispatch to PR creation."""
        if self.dispatched_at and self.pr_created_at:
            d = _parse_iso(self.dispatched_at)
            p = _parse_iso(self.pr_created_at)
            return (p - d).total_seconds() / 60
        return None

    @property
    def time_to_settle(self) -> float | None:
        """Minutes from dispatch to terminal state."""
        if self.dispatched_at and self.settled_at:
            d = _parse_iso(self.dispatched_at)
            s = _parse_iso(self.settled_at)
            return (s - d).total_seconds() / 60
        return None

    @property
    def is_stuck(self) -> bool:
        """Session is still running with no progress past threshold."""
        if self.status not in ("running", "unknown"):
            return False
        if not self.dispatched_at:
            return False
        d = _parse_iso(self.dispatched_at)
        elapsed = (datetime.now(timezone.utc) - d).total_seconds() / 60
        # Stuck if: running > threshold AND no PR yet
        return elapsed > STUCK_THRESHOLD_MINUTES and not self.pr_url

    @property
    def is_settled(self) -> bool:
        return self.status in ("exit", "error") or self.status_detail in (
            "finished", "waiting_for_user", "waiting_for_approval")

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "session_id": self.session_id,
            "remediation_class": self.remediation_class,
            "issue_number": self.issue_number,
            "dispatched_at": self.dispatched_at,
            "first_activity_at": self.first_activity_at,
            "first_commit_at": self.first_commit_at,
            "pr_created_at": self.pr_created_at,
            "ci_started_at": self.ci_started_at,
            "ci_passed_at": self.ci_passed_at,
            "settled_at": self.settled_at,
            "status": self.status,
            "status_detail": self.status_detail,
            "pr_url": self.pr_url,
            "outcome": self.outcome,
            "failure_category": self.failure_category,
            "acu_cost": self.acu_cost,
            "last_checked_at": self.last_checked_at,
        }

    @classmethod
    def from_dict(cls, d: dict) -> SessionTimeline:
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


# ─── Monitor State ──────────────────────────────────────────────────────────

@dataclass
class MonitorState:
    """Persistent state for the monitor."""
    timelines: dict[str, SessionTimeline] = field(default_factory=dict)
    # key = finding_id

    @classmethod
    def load(cls) -> MonitorState:
        if MONITOR_STATE_FILE.exists():
            data = json.loads(MONITOR_STATE_FILE.read_text())
            state = cls()
            for fid, tl_data in data.get("timelines", {}).items():
                state.timelines[fid] = SessionTimeline.from_dict(tl_data)
            return state
        return cls()

    def save(self) -> None:
        data = {"timelines": {fid: tl.to_dict() for fid, tl in self.timelines.items()}}
        MONITOR_STATE_FILE.write_text(json.dumps(data, indent=2))

    def ensure_timeline(self, finding_id: str, dispatch_entry: dict) -> SessionTimeline:
        """Get or create a timeline for a finding."""
        if finding_id not in self.timelines:
            self.timelines[finding_id] = SessionTimeline(
                finding_id=finding_id,
                session_id=dispatch_entry.get("session_id", ""),
                remediation_class=dispatch_entry.get("remediation_class", ""),
                issue_number=dispatch_entry.get("issue_number"),
                dispatched_at=dispatch_entry.get("dispatched_at"),
                status=dispatch_entry.get("status", "unknown"),
            )
        return self.timelines[finding_id]

    def update_from_session_data(self, finding_id: str, session_data: dict) -> SessionTimeline:
        """Update a timeline with fresh session data from MCP."""
        tl = self.timelines.get(finding_id)
        if not tl:
            return None

        now = _utcnow()
        tl.last_checked_at = now
        tl.status = session_data.get("status", tl.status)
        tl.status_detail = session_data.get("status_detail", tl.status_detail)

        # Track first activity
        if not tl.first_activity_at and tl.status != "unknown":
            tl.first_activity_at = now

        # Check if settled
        if tl.is_settled and not tl.settled_at:
            tl.settled_at = now

        # Extract structured output
        structured = session_data.get("structured_output")
        if structured and isinstance(structured, dict):
            if structured.get("pr_url") and not tl.pr_url:
                tl.pr_url = structured["pr_url"]
                tl.pr_created_at = now
            if structured.get("acu_cost"):
                tl.acu_cost = float(structured["acu_cost"])

        self.save()
        return tl

    def update_from_dossier(self, dossier: Dossier) -> None:
        """Back-fill timeline from a dossier."""
        tl = self.timelines.get(dossier.finding_id)
        if not tl:
            return
        tl.outcome = dossier.outcome.value
        tl.pr_url = dossier.pr_url or tl.pr_url
        tl.acu_cost = dossier.acu_cost or tl.acu_cost
        if dossier.outcome != Outcome.SUCCESS and dossier.friction_signals:
            tl.failure_category = FailureCategory.classify(dossier.friction_signals).value
        self.save()


# ─── Sync from dispatch state / dossiers ────────────────────────────────────

def sync_from_dispatch_state(monitor: MonitorState, dispatch: DispatchState) -> None:
    """Populate monitor timelines from dispatcher state."""
    for fid, entry in dispatch.dispatched.items():
        tl = monitor.ensure_timeline(fid, entry)
        tl.status = entry.get("status", tl.status)
        tl.pr_url = entry.get("pr_url") or tl.pr_url
        tl.outcome = entry.get("outcome") or tl.outcome
    monitor.save()


def sync_from_dossiers(monitor: MonitorState) -> None:
    """Back-fill timelines from dossier files."""
    if not DOSSIERS_DIR.exists():
        return
    for p in DOSSIERS_DIR.glob("*.json"):
        try:
            d = Dossier.model_validate_json(p.read_text())
            monitor.update_from_dossier(d)
        except Exception:
            continue


# ─── Dashboard rendering ────────────────────────────────────────────────────

def render_status_dashboard(monitor: MonitorState) -> str:
    """Real-time status of all tracked sessions."""
    lines = []
    lines.append(f"\n{'═'*80}")
    lines.append(f" REAL-TIME REMEDIATION MONITOR")
    lines.append(f" Last refresh: {_utcnow()}")
    lines.append(f"{'═'*80}\n")

    tls = list(monitor.timelines.values())
    running = [t for t in tls if t.status == "running" and not t.is_settled]
    settled = [t for t in tls if t.is_settled]
    stuck = [t for t in tls if t.is_stuck]

    lines.append(f"  Active: {len(running)}  |  Settled: {len(settled)}  |  "
                 f"Stuck: {len(stuck)}  |  Total: {len(tls)}")
    lines.append("")

    # Active sessions
    if running:
        lines.append(f"  ┌─ ACTIVE SESSIONS {'─'*58}")
        for tl in running:
            elapsed = ""
            if tl.dispatched_at:
                d = _parse_iso(tl.dispatched_at)
                mins = (datetime.now(timezone.utc) - d).total_seconds() / 60
                elapsed = f" ({mins:.0f}m)"
            stuck_flag = " ⚠️ STUCK" if tl.is_stuck else ""
            lines.append(f"  │ {tl.finding_id}  #{tl.issue_number or '?':<4}  "
                         f"[{tl.remediation_class}]{elapsed}{stuck_flag}")
        lines.append(f"  └{'─'*78}")
        lines.append("")

    # Settled sessions summary
    if settled:
        success = sum(1 for t in settled if t.outcome == "success")
        failed = sum(1 for t in settled if t.outcome == "failed")
        partial = sum(1 for t in settled if t.outcome == "partial")
        lines.append(f"  ┌─ SETTLED {'─'*67}")
        lines.append(f"  │ Success: {success}  |  Partial: {partial}  |  Failed: {failed}")

        # Time-to-PR stats
        pr_times = [t.time_to_pr for t in settled if t.time_to_pr is not None]
        if pr_times:
            avg_pr = sum(pr_times) / len(pr_times)
            lines.append(f"  │ Avg time-to-PR: {avg_pr:.1f} min  "
                         f"(min: {min(pr_times):.1f}, max: {max(pr_times):.1f})")

        # ACU stats
        total_acu = sum(t.acu_cost for t in settled)
        if total_acu > 0:
            lines.append(f"  │ Total ACU: {total_acu:.2f}  |  "
                         f"Avg ACU/fix: {total_acu/max(success,1):.3f}")
        lines.append(f"  └{'─'*78}")
        lines.append("")

    return "\n".join(lines)


def render_failure_taxonomy(monitor: MonitorState) -> str:
    """Breakdown of failures by category."""
    lines = []
    lines.append(f"\n{'═'*80}")
    lines.append(f" FAILURE TAXONOMY")
    lines.append(f"{'═'*80}\n")

    tls = list(monitor.timelines.values())
    failed = [t for t in tls if t.outcome in ("failed", "partial")]

    if not failed:
        lines.append("  No failures recorded yet.")
        return "\n".join(lines)

    # Count by category
    cats: dict[str, list[SessionTimeline]] = {}
    for t in failed:
        cat = t.failure_category or "unknown"
        cats.setdefault(cat, []).append(t)

    lines.append(f"  {'Category':<22} {'Count':<8} {'% of failures':<15} Examples")
    lines.append(f"  {'─'*75}")

    total_f = len(failed)
    for cat, entries in sorted(cats.items(), key=lambda x: -len(x[1])):
        pct = f"{len(entries)/total_f*100:.0f}%"
        examples = ", ".join(f"#{e.issue_number}" for e in entries[:3])
        lines.append(f"  {cat:<22} {len(entries):<8} {pct:<15} {examples}")

    lines.append("")
    lines.append(f"  Total failures/partial: {total_f}")

    # Actionable recommendations
    lines.append("")
    lines.append("  ┌─ RECOMMENDATIONS")
    if "auth_blocked" in cats:
        lines.append("  │ • auth_blocked: Add missing credentials to Devin secrets")
    if "lint_loop" in cats:
        lines.append("  │ • lint_loop: Revise playbook to run lint ONCE at end, not iteratively")
    if "dep_conflict" in cats:
        lines.append("  │ • dep_conflict: Pre-resolve dependency tree before dispatching CVE tickets")
    if "stuck_idle" in cats:
        lines.append("  │ • stuck_idle: Reduce STUCK_THRESHOLD or add session timeout to dispatch")
    if "test_failure" in cats:
        lines.append("  │ • test_failure: Ensure playbook step 7 (review) catches test issues before step 8")
    lines.append("  └")

    return "\n".join(lines)


def render_stuck_sessions(monitor: MonitorState) -> str:
    """Show stuck sessions with details."""
    lines = []
    lines.append(f"\n{'═'*80}")
    lines.append(f" STUCK SESSION DETECTION (threshold: {STUCK_THRESHOLD_MINUTES}min)")
    lines.append(f"{'═'*80}\n")

    stuck = [t for t in monitor.timelines.values() if t.is_stuck]

    if not stuck:
        lines.append("  No stuck sessions detected.")
        return "\n".join(lines)

    for tl in stuck:
        d = _parse_iso(tl.dispatched_at) if tl.dispatched_at else None
        elapsed = (datetime.now(timezone.utc) - d).total_seconds() / 60 if d else 0
        lines.append(f"  ⚠️  {tl.finding_id}  #{tl.issue_number or '?'}")
        lines.append(f"      Class: {tl.remediation_class}  |  Running: {elapsed:.0f}min")
        lines.append(f"      Session: {tl.session_id}")
        lines.append(f"      Last check: {tl.last_checked_at or 'never'}")
        lines.append(f"      Action: terminate + re-queue recommended")
        lines.append("")

    lines.append(f"  Total stuck: {len(stuck)}")
    lines.append(f"  Suggested action: `python dispatcher.py --apply --issue <N>` to re-dispatch")

    return "\n".join(lines)


def render_learning_curve(monitor: MonitorState) -> str:
    """Per-class success rate over batch order (does knowledge improve outcomes?)."""
    lines = []
    lines.append(f"\n{'═'*80}")
    lines.append(f" LEARNING CURVE (per-class success rate over batch order)")
    lines.append(f"{'═'*80}\n")

    # Group settled sessions by class, ordered by dispatch time
    by_class: dict[str, list[SessionTimeline]] = {}
    for tl in monitor.timelines.values():
        if tl.is_settled:
            by_class.setdefault(tl.remediation_class, []).append(tl)

    if not by_class:
        lines.append("  No settled sessions yet — nothing to plot.")
        return "\n".join(lines)

    for cls, entries in sorted(by_class.items()):
        # Sort by dispatch time
        entries.sort(key=lambda t: t.dispatched_at or "")

        lines.append(f"  ┌─ {cls} ({len(entries)} sessions)")

        # Sliding window success rate (window=3)
        window = 3
        rates = []
        for i in range(len(entries)):
            window_slice = entries[max(0, i-window+1):i+1]
            successes = sum(1 for t in window_slice if t.outcome == "success")
            rates.append(successes / len(window_slice))

        # Render as ASCII sparkline
        if rates:
            first_rate = rates[0] * 100
            last_rate = rates[-1] * 100
            trend = "↑" if last_rate > first_rate else "↓" if last_rate < first_rate else "→"
            sparkline = _ascii_sparkline(rates)
            lines.append(f"  │ {sparkline}  {first_rate:.0f}% → {last_rate:.0f}% {trend}")
        else:
            lines.append(f"  │ (no data)")

        lines.append(f"  └")
        lines.append("")

    # Knowledge notes generated
    knowledge_dir = DOSSIERS_DIR / "knowledge"
    if knowledge_dir.exists():
        k_count = len(list(knowledge_dir.glob("*.json")))
        lines.append(f"  Knowledge notes distilled: {k_count}")
        lines.append(f"  (Each success writes back learnings for the next ticket of same class)")

    return "\n".join(lines)


def render_full_dashboard(monitor: MonitorState) -> str:
    """Combine all views into one comprehensive dashboard."""
    parts = [
        render_status_dashboard(monitor),
        render_failure_taxonomy(monitor),
        render_stuck_sessions(monitor),
        render_learning_curve(monitor),
    ]
    return "\n".join(parts)


# ─── MCP Integration Helpers ────────────────────────────────────────────────

def build_poll_request(monitor: MonitorState) -> list[str]:
    """Get session IDs that need polling (active, not yet settled)."""
    return [
        f"devin-{tl.session_id}" for tl in monitor.timelines.values()
        if not tl.is_settled and tl.session_id
    ]


def handle_gather_result(monitor: MonitorState, session_id: str,
                          result: dict) -> SessionTimeline | None:
    """Process a single session result from devin_session_gather/interact."""
    # Find timeline by session_id
    for tl in monitor.timelines.values():
        if tl.session_id == session_id:
            return monitor.update_from_session_data(tl.finding_id, result)
    return None


def get_terminate_candidates(monitor: MonitorState) -> list[SessionTimeline]:
    """Get sessions that should be terminated (stuck beyond threshold)."""
    return [tl for tl in monitor.timelines.values() if tl.is_stuck]


# ─── Utilities ──────────────────────────────────────────────────────────────

def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso(s: str) -> datetime:
    """Parse ISO datetime string."""
    # Handle both Z suffix and +00:00
    s = s.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        return datetime.now(timezone.utc)


def _ascii_sparkline(values: list[float], width: int = 20) -> str:
    """Render a list of 0-1 floats as an ASCII sparkline."""
    if not values:
        return ""
    chars = " ▁▂▃▄▅▆▇█"
    # Resample to width
    if len(values) > width:
        step = len(values) / width
        sampled = [values[int(i * step)] for i in range(width)]
    else:
        sampled = values

    return "".join(chars[min(int(v * (len(chars) - 1)), len(chars) - 1)] for v in sampled)


# ─── CLI ────────────────────────────────────────────────────────────────────

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Remediation Monitor")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--status", action="store_true", help="Real-time status dashboard")
    mode.add_argument("--dashboard", action="store_true", help="Full observability dashboard")
    mode.add_argument("--stuck", action="store_true", help="Show stuck sessions")
    mode.add_argument("--failures", action="store_true", help="Failure taxonomy")
    mode.add_argument("--learning-curve", action="store_true", help="Per-class success over time")
    mode.add_argument("--sync", action="store_true", help="Sync state from dispatcher + dossiers")
    args = parser.parse_args()

    monitor = MonitorState.load()

    if args.sync:
        dispatch = DispatchState.load()
        sync_from_dispatch_state(monitor, dispatch)
        sync_from_dossiers(monitor)
        print(f"  Synced {len(monitor.timelines)} timelines from dispatch state + dossiers.")
        return

    # Auto-sync from dossiers on every read
    sync_from_dossiers(monitor)
    dispatch = DispatchState.load()
    sync_from_dispatch_state(monitor, dispatch)

    if args.status:
        print(render_status_dashboard(monitor))
    elif args.dashboard:
        print(render_full_dashboard(monitor))
    elif args.stuck:
        print(render_stuck_sessions(monitor))
    elif args.failures:
        print(render_failure_taxonomy(monitor))
    elif args.learning_curve:
        print(render_learning_curve(monitor))


if __name__ == "__main__":
    main()
