"""Document conversion layer for AegisOps Copilot semantic retrieval.

Transforms structured database models and raw CSV rows into semantically rich,
traceable documents with stable IDs and precise provenance metadata.
"""

from dataclasses import dataclass, field
import re
from typing import Any


@dataclass
class IndexableDocument:
    doc_id: str
    text: str
    metadata: dict[str, Any] = field(default_factory=dict)


def runbook_to_document(row: dict[str, Any], dataset_version: str = "2026.10.1") -> IndexableDocument:
    """Convert a runbook record into a searchable document."""
    rb_id = str(row.get("runbook_id", "")).strip()
    name = str(row.get("name", "")).strip()
    inc_type = str(row.get("incident_type", "")).strip()
    risk = str(row.get("risk_level", "")).strip()
    action = str(row.get("allowlisted_action", "")).strip()
    verification = str(row.get("verification_rule", "")).strip()
    comp = str(row.get("compensation_action", "")).strip()
    category = str(row.get("service_category", "")).strip()
    max_att = str(row.get("max_attempts", "1")).strip()
    timeout = str(row.get("timeout_seconds", "300")).strip()

    text = (
        f"Runbook {rb_id}: {name}\n"
        f"Applicable Incident Type: {inc_type}\n"
        f"Service Category: {category}\n"
        f"Risk Level: {risk}\n"
        f"Authorized Remediation Action: {action}\n"
        f"Verification Rule: {verification}\n"
        f"Automated Rollback / Compensation Action: {comp}\n"
        f"Execution Bounds: maximum {max_att} attempts, timeout {timeout} seconds."
    )

    metadata = {
        "source_type": "runbook",
        "source_filename": "runbooks.csv",
        "source_record_id": rb_id,
        "runbook_id": rb_id,
        "incident_type": inc_type,
        "risk_level": risk,
        "service_category": category,
        "allowlisted_action": action,
        "verification_rule": verification,
        "compensation_action": comp,
        "dataset_version": dataset_version,
    }

    return IndexableDocument(doc_id=f"runbook:{rb_id}", text=text, metadata=metadata)


def policy_to_document(row: dict[str, Any], dataset_version: str = "2026.10.1") -> IndexableDocument:
    """Convert a policy record into a searchable document."""
    pol_id = str(row.get("policy_id", "")).strip()
    rb_id = str(row.get("runbook_id", "")).strip()
    risk = str(row.get("risk_level", "")).strip()
    auto_exec = str(row.get("auto_execute", "")).strip()
    app_req = str(row.get("approval_required", "")).strip()
    role = str(row.get("approval_role", "none")).strip()
    allowed_env = str(row.get("allowed_environment", "")).strip()
    max_att = str(row.get("max_attempts", "")).strip()
    timeout = str(row.get("timeout_seconds", "")).strip()
    cooldown = str(row.get("cooldown_seconds", "")).strip()
    rollback_req = str(row.get("rollback_required", "")).strip()
    change_req = str(row.get("change_record_required", "")).strip()
    kill_switch = str(row.get("kill_switch_enforced", "")).strip()
    pol_ver = str(row.get("policy_version", dataset_version)).strip()

    text = (
        f"Policy {pol_id} governing Runbook {rb_id}:\n"
        f"Risk Classification: {risk}\n"
        f"Auto Execution: {auto_exec}\n"
        f"Approval Requirement: {app_req} (Authorized Role: {role})\n"
        f"Permitted Environments: {allowed_env}\n"
        f"Operational Constraints: max attempts {max_att}, timeout {timeout}s, cooldown {cooldown}s.\n"
        f"Safety Invariants: rollback required = {rollback_req}, change record required = {change_req}, kill switch enforced = {kill_switch}.\n"
        f"Policy Specification Version: {pol_ver}."
    )

    metadata = {
        "source_type": "policy",
        "source_filename": "policies.csv",
        "source_record_id": pol_id,
        "policy_id": pol_id,
        "runbook_id": rb_id,
        "risk_level": risk,
        "approval_role": role,
        "auto_execute": auto_exec,
        "approval_required": app_req,
        "allowed_environment": allowed_env,
        "policy_version": pol_ver,
        "dataset_version": dataset_version,
    }

    return IndexableDocument(doc_id=f"policy:{pol_id}", text=text, metadata=metadata)


def markdown_to_documents(
    content: str, filename: str = "README.md", dataset_version: str = "2026.10.1"
) -> list[IndexableDocument]:
    """Split markdown documentation into semantic chunks by header."""
    sections = re.split(r"\n(?=#{1,3}\s+)", content)
    docs: list[IndexableDocument] = []

    for idx, sec in enumerate(sections):
        cleaned = sec.strip()
        if not cleaned:
            continue
        first_line = cleaned.split("\n", 1)[0].strip("# \t")
        slug = re.sub(r"[^a-zA-Z0-9]+", "_", first_line.lower()).strip("_") or f"sec_{idx}"
        doc_id = f"doc:{filename}:{slug}"

        metadata = {
            "source_type": "documentation",
            "source_filename": filename,
            "source_record_id": doc_id,
            "title": first_line,
            "section": slug,
            "dataset_version": dataset_version,
        }
        docs.append(IndexableDocument(doc_id=doc_id, text=cleaned, metadata=metadata))

    return docs


def incident_to_summary_document(
    row: dict[str, Any], dataset_version: str = "2026.10.1"
) -> IndexableDocument:
    """Create a concise incident summary document for similarity retrieval."""
    inc_id = str(row.get("incident_id", "")).strip()
    env = str(row.get("environment", "")).strip()
    svc = str(row.get("service_id", "")).strip()
    inc_type = str(row.get("incident_type", "")).strip()
    sev = str(row.get("severity", "")).strip()
    risk = str(row.get("risk_level", "")).strip()
    score = str(row.get("anomaly_score", "")).strip()
    rb_id = str(row.get("runbook_id", "")).strip()
    pol_id = str(row.get("policy_id", "")).strip()
    decision = str(row.get("policy_decision", "")).strip()
    app_status = str(row.get("approval_status", "")).strip()
    exec_status = str(row.get("execution_status", "")).strip()
    ver_status = str(row.get("verification_status", "")).strip()
    roll_status = str(row.get("rollback_status", "")).strip()
    final_status = str(row.get("final_status", "")).strip()
    data_split = str(row.get("data_split", "")).strip()

    text = (
        f"Incident {inc_id} ({data_split} split): {inc_type} detected on {svc} ({env}).\n"
        f"Severity: {sev}, Risk: {risk}, Anomaly Score: {score}.\n"
        f"Matched Runbook: {rb_id}, Policy: {pol_id}.\n"
        f"Policy Decision: {decision}, Approval Status: {app_status}.\n"
        f"Execution Status: {exec_status}, Verification: {ver_status}, Rollback: {roll_status}.\n"
        f"Final Operational Status: {final_status}."
    )

    metadata = {
        "source_type": "incident_summary",
        "source_filename": "incidents.csv",
        "source_record_id": inc_id,
        "incident_id": inc_id,
        "incident_type": inc_type,
        "environment": env,
        "service_id": svc,
        "runbook_id": rb_id,
        "policy_id": pol_id,
        "risk_level": risk,
        "final_status": final_status,
        "data_split": data_split,
        "dataset_version": dataset_version,
    }

    return IndexableDocument(
        doc_id=f"incident:{inc_id}", text=text, metadata=metadata
    )

