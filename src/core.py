from __future__ import annotations
import hashlib
from enum import Enum
from datetime import datetime, timezone
from pydantic import BaseModel


class RemediationClass(str, Enum):
    CVE = "cve"
    BROAD_CATCH = "broad-catch"
    EXHAUSTIVE_DEPS = "exhaustive-deps"
    ANY_TYPE = "any-type"
    DESCRIBE_TO_TEST = "describe-to-test"


NARRATIVE = {
    RemediationClass.CVE: "headline",
    RemediationClass.BROAD_CATCH: "autonomy",
    RemediationClass.EXHAUSTIVE_DEPS: "autonomy",
    RemediationClass.ANY_TYPE: "volume",
    RemediationClass.DESCRIBE_TO_TEST: "throughput",
}


def finding_id(cls: RemediationClass, natural_key: str) -> str:
    """Stable, content-addressed id. Same defect -> same id across re-scans."""
    digest = hashlib.sha1(f"{cls.value}:{natural_key}".encode()).hexdigest()[:10]
    return f"f_{digest}"


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class Finding(BaseModel):
    """One unit of remediable work emitted by a scanner."""
    cls: RemediationClass
    natural_key: str
    title: str
    scan_run_id: str
    severity: str = "medium"
    file_path: str | None = None
    line: int | None = None
    package: str | None = None
    cve_id: str | None = None
    detail: str = ""
    is_hero: bool = False

    @property
    def id(self) -> str:
        return finding_id(self.cls, self.natural_key)
