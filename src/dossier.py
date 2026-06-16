from __future__ import annotations
from enum import Enum
from pydantic import BaseModel, Field
from core import RemediationClass, NARRATIVE, utcnow


class Outcome(str, Enum):
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"


class RiskFlag(str, Enum):
    AUTO_MERGEABLE = "auto_mergeable"
    NEEDS_REVIEW = "needs_review"
    NEEDS_CAREFUL_REVIEW = "needs_careful_review"


class ReasoningStep(BaseModel):
    decision: str
    rationale: str
    evidence: str = ""


class CrossImpact(BaseModel):
    reached_modules: list[str] = Field(default_factory=list)
    callers_checked: int = 0
    blast_radius: str = "small"


class Verification(BaseModel):
    command: str
    passed: bool
    evidence: str = ""


class Dossier(BaseModel):
    scan_run_id: str
    finding_id: str
    remediation_class: RemediationClass
    issue_number: int | None = None
    session_id: str | None = None
    pr_url: str | None = None

    severity: str = "medium"

    context_gathered: list[str] = Field(default_factory=list)
    patterns_studied: list[str] = Field(default_factory=list)
    reasoning_trace: list[ReasoningStep] = Field(default_factory=list)
    files_touched: list[str] = Field(default_factory=list)
    diff_summary: str = ""
    cross_impact: CrossImpact = Field(default_factory=CrossImpact)
    verification: Verification | None = None

    outcome: Outcome = Outcome.FAILED
    friction_signals: list[str] = Field(default_factory=list)
    acu_cost: float = 0.0
    started_at: str = Field(default_factory=utcnow)
    completed_at: str = Field(default_factory=utcnow)

    @property
    def narrative_role(self) -> str:
        return NARRATIVE[self.remediation_class]

    @property
    def risk_flag(self) -> RiskFlag:
        v_ok = bool(self.verification and self.verification.passed)
        if not v_ok or self.cross_impact.blast_radius == "large":
            return RiskFlag.NEEDS_CAREFUL_REVIEW
        if self.cross_impact.blast_radius == "medium" or self.friction_signals:
            return RiskFlag.NEEDS_REVIEW
        return RiskFlag.AUTO_MERGEABLE

    def pr_rationale(self) -> str:
        steps = "\n".join(f"- **{s.decision}** — {s.rationale}"
                          + (f" _( {s.evidence} )_" if s.evidence else "")
                          for s in self.reasoning_trace)
        v = self.verification
        return f"""### Why this change
Finding `{self.finding_id}` · class `{self.remediation_class.value}` · risk **{self.risk_flag.value}**

{steps or '- (no non-trivial decisions recorded)'}

**Cross-impact:** {self.cross_impact.blast_radius} — {self.cross_impact.callers_checked} caller(s) checked.
**Verification:** `{v.command if v else 'n/a'}` → {'PASS' if v and v.passed else 'FAIL'}{(' · ' + v.evidence) if v and v.evidence else ''}
"""


class KnowledgeNote(BaseModel):
    name: str
    trigger: str
    body: str
    pinned: bool = True

    def to_devin_payload(self) -> dict:
        return {"name": self.name, "trigger_description": self.trigger,
                "body": self.body, "pinned": self.pinned}


def distill_to_knowledge(d: Dossier) -> KnowledgeNote | None:
    if d.outcome is not Outcome.SUCCESS or not (d.verification and d.verification.passed):
        return None
    path = "\n".join(f"- {s.decision}: {s.rationale}" for s in d.reasoning_trace)
    return KnowledgeNote(
        name=f"Remediation path: {d.remediation_class.value}",
        trigger=f"Working on a {d.remediation_class.value} remediation ticket",
        body=f"""Proven path for `{d.remediation_class.value}` (from {d.finding_id}):

{path or '- (mechanical; follow the ticket playbook verbatim)'}

Verify with: `{d.verification.command}`
Typical blast radius: {d.cross_impact.blast_radius}.""",
    )


def friction_signal_for_playbook(d: Dossier) -> dict | None:
    if d.outcome is Outcome.SUCCESS and not d.friction_signals:
        return None
    return {"remediation_class": d.remediation_class.value,
            "finding_id": d.finding_id,
            "signals": d.friction_signals,
            "action": "review_playbook"}
