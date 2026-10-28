# AegisOps — Safety-Governed Remediation Dataset

**IMPORTANT: ALL RECORDS ARE SYNTHETIC**, generated for a hackathon demonstration. They are not downloaded from Kaggle, not real incident evidence, and not organizer-provided runbooks or policies.

The runbooks and policy rules are **illustrative proposed examples**, NOT authorized production remediation policy. Replace them with the 10 organizer-supplied runbooks and written risk policy before claiming compliance. Do not run these actions on production systems.

## Files and relationships
- `incidents.csv` — 3,000 incident-level labeled examples (join key `incident_id`)
- `runbooks.csv` — 10 hypothetical predefined remediation procedures (join `runbook_id`)
- `policies.csv` — policy decisions and boundaries (`policy_id`, `runbook_id`)
- `metrics.csv` — synthetic detection measurements (`incident_id`)
- `approvals.csv` — human review records (`approval_id`, `incident_id`)
- `execution_actions.csv` — actual modeled remediation attempts (`incident_id`)
- `audit_events.csv` — chronological trace entries (`incident_id`, `correlation_id`)

## Outcome distribution
{
  "ROLLED_BACK": 309,
  "RESOLVED": 1682,
  "BLOCKED": 221,
  "REJECTED": 258,
  "ESCALATED": 357,
  "AWAITING_APPROVAL": 144,
  "ROLLBACK_FAILED": 29
}

## How to use
1. Read `incidents.csv` with Python pandas, or import into SQLite/PostgreSQL.
2. Use `data_split` to separate training / validation / test examples, if doing ML.
3. For incident classification use pre-decision columns (incident type, anomaly score, severity, and environment). **Do not train detection on final_status or post-execution labels: data leakage.**
4. Make the policy engine authoritative; data-driven or AI recommendations must not bypass the policy.
5. During demo, inject a real failure into disposable containers and validate remediation, escalation, rate limiting, stop-switch, rollback, and audit traces. Historical synthetic results do not prove real rollback or safety.

## Notes
- Low-risk examples may auto-execute; medium/high risk require approvals unless blocked or escalated. High-risk examples in production are blocked by sample policy.
- `auto_resolved` means no approval needed and verification passed.
- `rollback_status=completed` represents a simulated compensation path, NOT proof of real recovery.
- `audit_events.csv` logs all key modeled decisions but does not establish tamper-resistance.
- Values and scenario names are fictional; don't present as sourced external telemetry.
