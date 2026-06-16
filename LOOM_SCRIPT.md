# Loom Recording Script (5 minutes)

## 1. WHAT — Problem Framing (60s)

> "Every large codebase accumulates technical debt in predictable patterns. In Apache Superset — a 4000-file project with a Flask backend and React frontend — we found 900+ instances across just 5 categories: unpatched CVEs, overly broad exception handling, React hooks with stale closures, TypeScript `any` types, and deprecated test patterns."
>
> "The problem isn't identifying these — tools like pip-audit and grep find them instantly. The problem is *remediating* them. Each fix requires reading context, understanding patterns, making judgment calls, running verification. At 20 minutes per fix for a human, that's 300 hours of mechanical-but-careful work."
>
> "This system turns that into a batch operation."

**SHOW:** GitHub issues list (https://github.com/jjejones31/superset/issues) — 61 structured issues across 5 categories.

---

## 2. HOW — Demo + Architecture (180s)

### 2a. The Event-Driven Flow (60s)

> "The system is fully event-driven — the primary trigger is a push to main."

**SHOW:** Architecture diagram from README (or draw on screen).

> "When anyone pushes to main — or a PR merges — a GitHub webhook fires. The server inspects which files changed and runs targeted scanners: Python files trigger the broad-catch scanner, TypeScript files trigger type and hooks scanners, dependency files trigger CVE scanning."
>
> "Each finding gets a content-addressed ID — `SHA1(class + natural_key)` — so re-scanning is idempotent. New findings become GitHub issues with an embedded 8-step playbook. Then Devin sessions are auto-dispatched with a structured prompt that includes the playbook AND a reference to a prior successful PR for the same class."
>
> "The whole cycle — push, scan, issue creation, session dispatch — happens without human intervention."

**SHOW:** Webhook server code (`webhook_server.py` — `handle_push` function, showing targeted scanner routing).

### 2b. Live Demo — Completed Test Runs (60s)

> "Let me show you three completed test runs — one per class."

**SHOW:** PR #62 (broad-catch): "Devin traced the try-body, identified that `get_view_names()` can throw `DBAPIError` or `NotImplementedError`, narrowed the catch, added 3 unit tests. This is the kind of fix that requires reading 30+ database engine implementations to reason about what exceptions are possible."

**SHOW:** PR #63 (describe-to-test): "Mechanical but careful — removed describe() wrapper, prefixed test names, preserved all 14 tests."

**SHOW:** PR #64 (any-type): "Replaced 7 `any` types with precise types inferred from the codebase — used `CellProps<D>` from react-table, extended the shared type locally."

### 2c. Key Architectural Decisions (60s)

> "Three design choices that make this work at scale:"
>
> "**One: Content-addressed IDs.** `SHA1(class + natural_key)[:10]`. Same bug → same ID across re-scans. This makes issue creation idempotent — you can re-run scanners freely."
>
> "**Two: Reference-based learning.** When a session succeeds, its method gets stored as a reference PR. The next session of the same class sees: 'Here's what worked on a similar ticket — study this PR before starting.' The system gets better with each batch."
>
> "**Three: Single source of truth.** The playbook dict drives both the issue body AND the agent prompt. No drift between what the human reads and what the agent follows."

---

## 3. WHY — Why Devin? (60s)

> "This wouldn't be practical without an autonomous coding agent, for three reasons:"
>
> "**Contextual reasoning at scale.** These aren't find-and-replace fixes. The broad-catch hero requires tracing a polymorphic call through 30+ database engine implementations. The Flask CVE upgrade cascades through 12 Flask extensions. Each fix needs real understanding of the code."
>
> "**Parallel execution.** 61 issues × 8-step ceremony. Devin sessions run in parallel — we dispatched 3 test sessions and got 3 PRs back in under 15 minutes. A human would take days."
>
> "**Compounding knowledge.** Each successful remediation teaches the next one. The reference PR system means batch N+1 is more likely to succeed than batch N. That's not possible with a stateless tool."

---

## 4. WHEN — Next Steps (60s)

> "For a real customer engagement, I'd extend this in three ways:"
>
> "**First: Broader scanner coverage.** We covered 5 categories. The system is designed to add new `RemediationClass` entries — just add a scanner function and a playbook entry. Security misconfigurations, accessibility violations, API deprecations — same pattern."
>
> "**Second: CI-gated dispatch.** Right now, sessions dispatch immediately on push. In production, you'd gate dispatch behind CI — only create sessions for findings that survive the full test suite. A nightly deep-scan mode could cover the full codebase, not just changed files."
>
> "**Third: Feedback loop closure.** Right now, reference PRs are manual. With the dossier system, successful PRs automatically distill into Devin Knowledge notes. After 5-10 batches, the success rate converges toward 100% for mechanical classes."
>
> "The key insight is that Devin isn't just a helper — it's the core primitive. The system wouldn't exist without it."

---

## Key Numbers to Mention
- 61 issues created across 5 categories
- 3 test runs completed → 3 PRs (100% success)
- ~10 min average per remediation (dispatch to PR)
- 900+ total automatable issues in the codebase
- 3 hero issues verified non-trivial (require real reasoning)
