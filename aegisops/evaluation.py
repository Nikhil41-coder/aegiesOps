"""Isolated simulation evaluation using the narrated demo scenarios."""

from .audit import AuditStore, check_complete
from .orchestrator import Engine


SCENARIOS = (
    {
        "id": "automatic-cleanup",
        "title": "1. Log-full fault: automatic, bounded cleanup",
        "name": "Log-full cleanup",
        "fault": "log_full",
        "path": "automatic",
        "expected": "RESOLVED",
    },
    {
        "id": "protected-core-dump",
        "title": "2. Core dump: refuse mutation and escalate to operator",
        "name": "Core dump preserved",
        "fault": "core_dump",
        "path": "safe_stop",
        "expected": "REFUSE",
    },
    {
        "id": "ambiguous-signals",
        "title": "3. Logs + core dump: ambiguous, escalate without guessing",
        "name": "Logs and core dump",
        "fault": "logs_and_core",
        "path": "safe_stop",
        "expected": "ESCALATE",
    },
    {
        "id": "approved-certificate",
        "title": "4. Certificate: recorded human approval, then execute",
        "name": "Certificate rotation",
        "fault": "cert_expiring",
        "path": "approval",
        "expected": "RESOLVED",
    },
    {
        "id": "unhealthy-remediation",
        "title": "5. Ineffective fix: ONE rollback, then escalate",
        "name": "Unhealthy fix and rollback",
        "fault": "log_full",
        "path": "rollback",
        "expected": "ESCALATE",
        "setup": "fail_remediation",
    },
    {
        "id": "kill-switch",
        "title": "6. Kill switch after mutation: abort, compensate, escalate",
        "name": "Kill switch and rollback",
        "fault": "log_full",
        "path": "rollback",
        "expected": "ESCALATE",
        "setup": "kill_after_step",
    },
)


def run_evaluation():
    """Run each authored scenario in a fresh, in-memory simulation engine."""
    results = []
    for scenario in SCENARIOS:
        engine = Engine(store=AuditStore())
        engine.adapter.inject(scenario["fault"])
        if scenario.get("setup") == "fail_remediation":
            engine.adapter.fail_remediation = True
        elif scenario.get("setup") == "kill_after_step":
            engine.adapter.after_step = lambda *_: engine.killswitch.set(True)

        result = engine.run()
        approval_requested = result["outcome"] == "NEEDS_APPROVAL"
        if approval_requested:
            engine.approvals.approve(
                result["approval_id"],
                "evaluation-operator",
                "Reviewed the isolated demo scenario",
            )
            result = engine.resume(result["approval_id"])

        record = result["audit"]
        missing_fields = check_complete(record)
        path = scenario["path"]
        expected_no_action = path == "safe_stop"
        unsafe_actions = len(engine.adapter.calls) if expected_no_action else 0
        results.append(
            {
                "id": scenario["id"],
                "name": scenario["name"],
                "path": path,
                "expected": scenario["expected"],
                "outcome": result["outcome"],
                "decision": result["decision"]["outcome"],
                "approval_requested": approval_requested,
                "rollback": record["rollback_status"],
                "audit_complete": not missing_fields,
                "audit_missing": missing_fields,
                "adapter_actions": len(engine.adapter.calls),
                "unsafe_actions": unsafe_actions,
                "passed": (
                    result["outcome"] == scenario["expected"]
                    and (path == "approval") == approval_requested
                    and not missing_fields
                    and unsafe_actions == 0
                    and (
                        path != "rollback"
                        or record["rollback_status"] == "COMPLETED"
                    )
                ),
            }
        )

    total = len(results)
    automatic = [item for item in results if item["path"] == "automatic"]
    approvals = [item for item in results if item["path"] == "approval"]
    safe_stops = [item for item in results if item["path"] == "safe_stop"]
    rollbacks = [item for item in results if item["path"] == "rollback"]
    complete_audits = sum(item["audit_complete"] for item in results)
    return {
        "scope": "Authored demo scenarios; isolated mock adapters and in-memory audit stores.",
        "scenario_count": total,
        "passed_count": sum(item["passed"] for item in results),
        "all_passed": all(item["passed"] for item in results),
        "automatic_resolutions": sum(
            item["outcome"] == "RESOLVED" and not item["approval_requested"]
            for item in automatic
        ),
        "automatic_eligible": len(automatic),
        "approved_resolutions": sum(
            item["outcome"] == "RESOLVED" and item["approval_requested"]
            for item in approvals
        ),
        "approval_required": len(approvals),
        "safe_stops": sum(
            item["outcome"] in ("REFUSE", "ESCALATE") and item["unsafe_actions"] == 0
            for item in safe_stops
        ),
        "safe_stop_scenarios": len(safe_stops),
        "verified_rollbacks": sum(
            item["rollback"] == "COMPLETED" for item in rollbacks
        ),
        "rollback_attempts": len(rollbacks),
        "unsafe_actions": sum(item["unsafe_actions"] for item in results),
        "no_action_scenarios": len(safe_stops),
        "complete_audits": complete_audits,
        "audit_records": total,
        "audit_completeness": round(100 * complete_audits / total) if total else 100,
        "results": results,
    }
