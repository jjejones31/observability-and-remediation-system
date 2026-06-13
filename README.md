# Superset Auto-Remediation System

An event-driven automation that uses [Devin](https://devin.ai) to systematically identify, triage, and remediate code quality issues in [Apache Superset](https://github.com/apache/superset).

## What It Does

This system scans a Superset fork for batch-automatable issues across 5 categories, creates GitHub issues with structured playbooks, and dispatches Devin sessions to remediate them — all triggered by events (webhooks, scan results, or manual API calls).

### Issue Categories

| Category | Volume | Narrative | Example |
|----------|--------|-----------|---------|
| **CVE fixes** | 5 | headline | Flask 2.3→3.x cascade with 12-extension compatibility |
| **Broad exception handling** | 10 | autonomy | Narrowing polymorphic `except Exception` across 30+ DB engines |
| **React exhaustive-deps** | 10 | autonomy | Fixing real stale-closure bugs vs. deliberate omissions |
| **TypeScript `any` types** | 20 | volume | Replacing `any` with precise types inferred from usage |
| **`describe()` → `test()` migration** | 15 | throughput | Flattening test nesting per project convention |

### Architecture

```
┌──────────────┐     ┌─────────────┐     ┌──────────────┐
│ GitHub Event │────▶│  Webhook    │────▶│  Dispatcher  │
│ (issue.labeled)   │  Server     │     │  (prompt     │
│               │     │             │     │   builder)   │
└──────────────┘     └─────────────┘     └──────┬───────┘
                                                │
                     ┌─────────────┐            │ Devin API
Scan results ───────▶│  Scanners   │     ┌──────▼───────┐
(pip-audit,          │  (5 classes)│     │  Devin       │
 npm audit,          └──────┬──────┘     │  Sessions    │
 grep/rg)                   │            │  (parallel)  │
                     ┌──────▼──────┐     └──────┬───────┘
                     │  Issue      │            │
                     │  Creator    │     ┌──────▼───────┐
                     │  (gh CLI)   │     │  Poller /    │
                     └─────────────┘     │  Monitor     │
                                         └──────┬───────┘
                                                │
                                         ┌──────▼───────┐
                                         │  Dossier +   │
                                         │  Dashboard   │
                                         └──────────────┘
```

### Event-Driven Flow

1. **Scan trigger** (`POST /scan`) → scanners run against the codebase → findings emitted
2. **Issue creation** → each finding becomes a GitHub issue with provenance, playbook, and acceptance criteria
3. **Label event** → when `auto-remediation` label is applied, webhook fires
4. **Session dispatch** → Devin session created with structured prompt (playbook + reference PR from prior successes)
5. **Monitoring** → real-time dashboard tracks active sessions, stuck detection, failure taxonomy
6. **Completion** → PR merged → dossier filed → knowledge distilled for next batch

### Key Design Decisions

- **Content-addressed finding IDs**: `SHA1(class + natural_key)[:10]` → same defect always maps to same ID, enabling idempotent issue creation and deduplication across re-scans
- **Single source of truth**: Issue body and agent prompt both read from `PLAYBOOKS` dict — no drift
- **Reference-based learning**: Successful remediations are stored as reference PRs and injected into future agent prompts for the same class
- **Provenance embedding**: Invisible HTML comment in each issue body carries machine-readable JSON for traceability

## Quick Start

### Simulate Mode (no API keys needed)

```bash
docker compose --profile simulate up --build
```

This starts the server on port 8081 in simulate mode — all Devin session creation is mocked, but the full event-driven flow is exercised.

### Live Mode

```bash
# 1. Copy and fill in credentials
cp .env.example .env
# Edit .env with your DEVIN_API_KEY, GH_TOKEN, GITHUB_WEBHOOK_SECRET

# 2. Start the server
docker compose up --build

# 3. Configure GitHub webhook
#    Repo Settings → Webhooks → Add webhook
#    URL: https://your-server/webhook
#    Content type: application/json
#    Secret: (same as GITHUB_WEBHOOK_SECRET)
#    Events: Issues, Pull requests
```

### Manual API Usage

```bash
# Trigger a scan (creates issues from scan results)
curl -X POST http://localhost:8080/scan

# Dispatch sessions for all undispatched issues
curl -X POST http://localhost:8080/dispatch

# Dispatch hero issues only
curl -X POST "http://localhost:8080/dispatch?heroes_only=true&concurrency=3"

# View dashboard (JSON)
curl http://localhost:8080/dashboard

# View dashboard (terminal-friendly text)
curl http://localhost:8080/dashboard/text

# Health check
curl http://localhost:8080/health
```

## Observability

The system answers: "If I were an engineering leader, how would I know this is working?"

### Dashboard (`GET /dashboard`)
- **Summary**: total dispatched, running, success, failed counts
- **Per-class breakdown**: success rate, ACU cost per class
- **Stuck detection**: sessions running >30min with no PR flagged for intervention
- **Reference PRs**: which classes have proven methods from prior completions

### Monitor CLI
```bash
python src/monitor.py --status          # Real-time session status
python src/monitor.py --dashboard       # Full observability view
python src/monitor.py --stuck           # Stuck sessions needing intervention
python src/monitor.py --failures        # Failure taxonomy breakdown
python src/monitor.py --learning-curve  # Per-class success rate over time
```

### Failure Taxonomy
Sessions are classified into 9 failure categories with actionable recommendations:
| Category | Recommendation |
|----------|---------------|
| `auth_blocked` | Check credentials / permissions |
| `lint_loop` | Run lint once at end, not iteratively |
| `wrong_file` | Improve natural_key specificity |
| `test_failure` | Add test patterns to playbook |
| `timeout` | Break into smaller scope |
| `dep_conflict` | Pin version constraints |
| `build_failure` | Add build step to playbook |
| `stuck_idle` | Terminate + re-queue |

## Results

### Test Runs Completed
| Issue | Class | PR | Method |
|-------|-------|-----|--------|
| #60 | describe-to-test | [#63](https://github.com/jjejones31/superset/pull/63) | Removed `describe()`, prefixed test names, dedented to flat |
| #45 | any-type | [#64](https://github.com/jjejones31/superset/pull/64) | Used `CellProps<D>` from react-table, extended shared types |
| #15 | broad-catch | [#62](https://github.com/jjejones31/superset/pull/62) | Traced call path → `(DBAPIError, NotImplementedError)`, 3 unit tests |

### Issues Created
- **61 total issues** across 5 categories in [jjejones31/superset](https://github.com/jjejones31/superset/issues)
- **3 verified hero issues** for high-complexity demo:
  - [#1](https://github.com/jjejones31/superset/issues/1) — Flask CVE cascade (12-extension compatibility)
  - [#6](https://github.com/jjejones31/superset/issues/6) — Polymorphic exception handling (30+ DB engines)
  - [#61](https://github.com/jjejones31/superset/issues/61) — Real stale-closure bug (confirmed by TODO in source)

## Project Structure

```
src/
├── webhook_server.py    # Event-driven Flask server (webhook + API)
├── core.py              # Finding model, content-addressed IDs
├── playbooks.py         # 5 remediation playbooks (8-step ceremony)
├── scanners.py          # Codebase scanners (CVE, types, tests, etc.)
├── create_issues_gh.py  # Idempotent issue creator via gh CLI
├── dispatcher.py        # Issue → Devin session launcher
├── poller.py            # Session → dossier filler
├── dossier.py           # Output contract, knowledge distillation
├── monitor.py           # Real-time observability + failure taxonomy
├── findings.json        # Scan output (61 findings)
└── reference_prs.json   # Proven methods from completed runs
```

## Why Devin?

This system wouldn't be practical without an autonomous coding agent because:

1. **Each fix requires contextual reasoning** — not just find-and-replace. The broad-catch hero (#6) requires tracing 30+ database engine implementations to determine which exceptions are actually thrown.

2. **Scale demands parallelism** — 61 issues × 8-step ceremony × verification = hundreds of hours of manual work. Devin sessions run in parallel, each following the same structured process.

3. **Learning compounds** — successful remediations are distilled into knowledge notes and reference PRs that improve future sessions of the same class. The system gets better over time.

4. **End-to-end ownership** — from reading the code to creating the PR to running verification, each session handles the full lifecycle without human intervention.
