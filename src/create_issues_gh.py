"""
Create GitHub issues using `gh` CLI (already authenticated).
Idempotent: skips findings whose finding_id is already embedded in existing issues.
"""
from __future__ import annotations
import json
import subprocess
import sys
import time

from core import Finding, RemediationClass, NARRATIVE
from playbooks import PLAYBOOKS

PROV_BEGIN, PROV_END = "<!--prov:", "-->"
REPO = "jjejones31/superset"

LABEL_COLORS = {
    "remediation:cve": "b60205",
    "remediation:broad-catch": "d93f0b",
    "remediation:exhaustive-deps": "fbca04",
    "remediation:any-type": "0e8a16",
    "remediation:describe-to-test": "1d76db",
    "severity:critical": "b60205", "severity:high": "d93f0b",
    "severity:medium": "fbca04", "severity:low": "c2e0c6",
    "hero": "5319e7", "auto-remediation": "ededed",
}


def embed_provenance(meta: dict) -> str:
    return f"{PROV_BEGIN}{json.dumps(meta, separators=(',', ':'))}{PROV_END}"


def extract_provenance(body: str) -> dict | None:
    if PROV_BEGIN not in body:
        return None
    chunk = body.split(PROV_BEGIN, 1)[1].split(PROV_END, 1)[0]
    try:
        return json.loads(chunk)
    except json.JSONDecodeError:
        return None


def render_body(f: Finding) -> str:
    pb = PLAYBOOKS[f.cls]
    meta = {"finding_id": f.id, "cls": f.cls.value,
            "scan_run_id": f.scan_run_id, "natural_key": f.natural_key}
    loc = f" — `{f.file_path}`" + (f":{f.line}" if f.line else "") if f.file_path else ""
    steps = "\n".join(f"{i+1}. {s}" for i, s in enumerate(pb["steps"]))
    accept = "\n".join(f"- [ ] {a}" for a in pb["acceptance"])
    return f"""{embed_provenance(meta)}
**Provenance:** `{f.id}`  ·  **Class:** `{f.cls.value}` ({NARRATIVE[f.cls]})  ·  **Severity:** {f.severity}

## Finding{loc}
{f.detail or f.title}

## Objective
{pb['objective']}

## Remediation process
{steps}

## Acceptance criteria
{accept}

## Verify
```
{pb['verify']}
```
"""


def gh_run(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(["gh"] + args, capture_output=True, text=True)


def ensure_labels() -> None:
    """Create any missing labels in the repo."""
    result = gh_run(["label", "list", "--repo", REPO, "--limit", "200", "--json", "name"])
    existing = set()
    if result.returncode == 0:
        existing = {l["name"] for l in json.loads(result.stdout)}

    for name, color in LABEL_COLORS.items():
        if name not in existing:
            gh_run(["label", "create", name, "--repo", REPO,
                    "--color", color, "--force"])
            print(f"  label created: {name}")


def existing_finding_ids() -> set[str]:
    """Get finding_ids from all existing auto-remediation issues."""
    ids = set()
    result = gh_run(["issue", "list", "--repo", REPO, "--label", "auto-remediation",
                     "--state", "all", "--limit", "500", "--json", "body"])
    if result.returncode != 0:
        return ids
    for issue in json.loads(result.stdout):
        prov = extract_provenance(issue.get("body") or "")
        if prov and prov.get("finding_id"):
            ids.add(prov["finding_id"])
    return ids


def create_issue(f: Finding) -> int | None:
    """Create a single GitHub issue. Returns issue number or None on failure."""
    labels = [f"remediation:{f.cls.value}", f"severity:{f.severity}", "auto-remediation"]
    if f.is_hero:
        labels.append("hero")

    title = f"[{f.cls.value}] {f.title}"
    body = render_body(f)

    args = ["issue", "create", "--repo", REPO,
            "--title", title, "--body", body]
    for label in labels:
        args.extend(["--label", label])

    result = gh_run(args)
    if result.returncode != 0:
        print(f"  ERROR creating {f.id}: {result.stderr.strip()}")
        return None

    # Parse issue URL to get number
    url = result.stdout.strip()
    try:
        return int(url.rstrip("/").split("/")[-1])
    except (ValueError, IndexError):
        return None


def run(findings: list[Finding], dry_run: bool = True) -> None:
    print(f"{'[DRY RUN] ' if dry_run else ''}Processing {len(findings)} findings...")
    print()

    if not dry_run:
        print("Ensuring labels exist...")
        ensure_labels()
        print()

    already = set() if dry_run else existing_finding_ids()
    if already:
        print(f"Found {len(already)} existing finding(s), will skip duplicates.\n")

    created = skipped = 0
    for f in findings:
        if f.id in already:
            print(f"  SKIP {f.id} (already exists)")
            skipped += 1
            continue

        if dry_run:
            print(f"  [DRY] would create {f.id} [{f.cls.value}] {f.title}"
                  + ("  ★ HERO" if f.is_hero else ""))
            created += 1
            continue

        num = create_issue(f)
        if num:
            print(f"  ✓ #{num}  {f.id}  [{f.cls.value}] {f.title}"
                  + ("  ★ HERO" if f.is_hero else ""))
            created += 1
        else:
            print(f"  ✗ FAILED {f.id}")
        time.sleep(0.7)  # rate limit

    print(f"\n{'[DRY] ' if dry_run else ''}"
          f"{created} created, {skipped} skipped "
          f"({sum(1 for f in findings if f.is_hero)} heroes)")


if __name__ == "__main__":
    data = json.load(open(sys.argv[1]))
    fs = [Finding(**d) for d in data]
    dry = "--apply" not in sys.argv
    run(fs, dry_run=dry)
