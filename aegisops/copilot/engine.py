
"""Bounded Agentic RAG engine for AegisOps Copilot with Gemini integration.

Executes an 8-node deterministic workflow:
1. Query classification
2. Retrieval planning
3. Semantic retrieval
4. Structured retrieval
5. Evidence sufficiency check
6. Bounded retrieval retry (max 1 retry, bounded timeout)
7. Answer generation (via Gemini or deterministic evidence fallback)
8. Validation, citation attribution, and guarded abstention
"""

from copy import deepcopy
import json
import os
from pathlib import Path
import re
import time
from typing import Any

from aegisops.config import GEMINI_API_KEY, GEMINI_MODEL
from aegisops.copilot.models import (
    Citation,
    CopilotResponse,
    EvidenceItem,
    QueryClassification,
)
from aegisops.copilot.query import (
    get_full_incident_dossier,
    get_incident_actions,
    get_incident_approvals,
    get_incident_audits,
    get_incident_metrics,
    get_incident_record,
    get_policy_by_runbook,
    get_policy_record,
    get_runbook_record,
)
from aegisops.copilot.retriever import SearchResult, SemanticIndex

# System prompt binding the LLM strictly to evidence
SYSTEM_PROMPT = """You are AegisOps Copilot, an expert read-only operational assistant for AegisOps.
CRITICAL SAFETY & FACTUAL INVARIANTS:
1. Answer ONLY based on the provided EVIDENCE. Never invent facts, record IDs, metrics, or timestamps.
2. You CANNOT execute shell commands, remediation actions, database writes, or approvals.
3. If user requests remediation, execution, shell commands, or approval bypass, REFUSE immediately.
4. Distinguish between verified facts from records and any interpretation.
5. Provide explicit citations to source files and record IDs.
6. If the evidence is insufficient, contradictory, or a requested incident/record is missing, clearly state that evidence is insufficient and ABSTAIN from speculating.
"""


class AegisOpsCopilot:
    """Bounded Agentic RAG engine coordinating structured and semantic retrieval."""

    def __init__(
        self,
        index: SemanticIndex | None = None,
        api_key: str | None = None,
        model_name: str | None = None,
        db_path: Path | str | None = None,
        max_execution_seconds: float = 10.0,
    ):
        self.index = index or SemanticIndex()
        self.api_key = api_key if api_key is not None else GEMINI_API_KEY
        self.model_name = model_name or GEMINI_MODEL or "gemini-2.5-flash"
        self.db_path = db_path
        self.max_execution_seconds = max_execution_seconds

        # Lazy Gemini client initialization
        self._gemini_client = None
        if self.api_key:
            try:
                from google import genai

                self._gemini_client = genai.Client(api_key=self.api_key)
            except Exception:
                self._gemini_client = None

    # =========================================================================
    # Node 1 — Query classification
    # =========================================================================
    def node_1_classify_query(self, query: str) -> QueryClassification:
        q_lower = query.lower().strip()

        # Security check: prompt injection / unauthorized command attempts
        dangerous_patterns = [
            r"\b(rm\s+-rf|sudo|chmod|cat\s+/etc/passwd|bash|sh|curl\s+http|wget)\b",
            r"\b(drop\s+table|delete\s+from|insert\s+into|update\s+kb_|update\s+audit)\b",
            r"\b(execute\s+action|remediate\s+now|approve\s+incident|override\s+policy|bypass\s+guard)\b",
            r"\b(ignore\s+all\s+previous\s+instructions|system\s+prompt|disregard\s+safety)\b",
        ]
        for pat in dangerous_patterns:
            if re.search(pat, q_lower):
                return QueryClassification(
                    category="unsupported",
                    confidence=1.0,
                    unsupported_reason=(
                        "Safety guardrail rejection: shell commands, database mutations, "
                        "remediation execution, and policy bypasses are strictly forbidden."
                    ),
                )

        # Entity extraction
        inc_match = re.search(r"\b(INC[-_]?\d{1,6})\b", query, re.IGNORECASE)
        rb_match = re.search(r"\b(RB[-_]?\d{1,3})\b", query, re.IGNORECASE)
        pol_match = re.search(r"\b(POL(?:[-_]?RB)?[-_]?\d{1,3}|POL_[a-zA-Z0-9_]+)\b", query, re.IGNORECASE)

        entities: dict[str, Any] = {}
        if inc_match:
            digits = re.sub(r"[^0-9]", "", inc_match.group(1))
            entities["incident_id"] = f"INC{digits.zfill(6)}" if digits else inc_match.group(1).upper()
        if rb_match:
            digits = re.sub(r"[^0-9]", "", rb_match.group(1))
            entities["runbook_id"] = f"RB{digits.zfill(3)}" if digits else rb_match.group(1).upper()
        if pol_match:
            raw = pol_match.group(1).upper()
            if raw.startswith("POL") and not raw.startswith("POL_RB"):
                digits = re.sub(r"[^0-9]", "", raw)
                entities["policy_id"] = f"POL_RB{digits.zfill(3)}" if digits else raw
            else:
                entities["policy_id"] = raw

        # Classification heuristics
        if "incident_id" in entities:
            if any(k in q_lower for k in ("metric", "threshold", "usage", "value", "signal")):
                cat = "metrics"
            elif any(k in q_lower for k in ("approval", "reviewer", "approved", "rejected")):
                cat = "approval_history"
            elif any(k in q_lower for k in ("action", "execute", "rollback", "attempt", "verification")):
                cat = "execution_history"
            elif any(k in q_lower for k in ("audit", "event", "timeline", "trace", "chronolog")):
                cat = "audit_timeline"
            else:
                cat = "incident_investigation"
            return QueryClassification(
                category=cat,
                entities=entities,
                requires_structured=True,
                requires_semantic="runbook_id" in entities or "policy_id" in entities or "why" in q_lower,
            )

        if "policy_id" in entities or ("policy" in q_lower and "runbook" not in q_lower):
            return QueryClassification(
                category="policy_explanation",
                entities=entities,
                requires_structured=bool(entities.get("policy_id")),
                requires_semantic=True,
            )

        if "runbook_id" in entities or "runbook" in q_lower or any(
            k in q_lower for k in ("procedure", "how to restart", "how to clean", "how to prune", "cache", "cert")
        ):
            return QueryClassification(
                category="runbook_guidance",
                entities=entities,
                requires_structured=bool(entities.get("runbook_id")),
                requires_semantic=True,
            )

        if any(k in q_lower for k in ("similar", "cases like", "historical", "patterns")):
            return QueryClassification(
                category="similar_incidents",
                entities=entities,
                requires_structured=False,
                requires_semantic=True,
            )

        if any(k in q_lower for k in ("incident", "investigat", "what happened")):
            return QueryClassification(
                category="incident_investigation",
                entities=entities,
                requires_structured=bool(entities.get("incident_id")),
                requires_semantic=True,
            )

        # Check if question is relevant to AegisOps
        ops_keywords = ("aegisops", "dataset", "status", "severity", "anomaly", "risk", "environment", "sandbox", "staging", "production")
        if any(k in q_lower for k in ops_keywords):
            return QueryClassification(
                category="runbook_guidance",
                entities=entities,
                requires_structured=False,
                requires_semantic=True,
            )

        return QueryClassification(
            category="unsupported",
            confidence=0.9,
            unsupported_reason="Question does not pertain to AegisOps runbooks, policies, or incidents.",
        )

    # =========================================================================
    # Node 2 — Retrieval planning
    # =========================================================================
    def node_2_plan_retrieval(self, classification: QueryClassification) -> dict[str, Any]:
        plan = {
            "structured_tasks": [],
            "semantic_tasks": [],
        }

        if classification.category == "unsupported":
            return plan

        inc_id = classification.entities.get("incident_id")
        rb_id = classification.entities.get("runbook_id")
        pol_id = classification.entities.get("policy_id")

        if inc_id:
            plan["structured_tasks"].append(("incident_dossier", inc_id))

        if rb_id:
            plan["structured_tasks"].append(("runbook", rb_id))
            plan["semantic_tasks"].append(("runbook", rb_id))

        if pol_id:
            plan["structured_tasks"].append(("policy", pol_id))
            plan["semantic_tasks"].append(("policy", pol_id))

        if classification.category == "runbook_guidance":
            plan["semantic_tasks"].append(("runbook_search", None))
            plan["semantic_tasks"].append(("documentation_search", None))

        elif classification.category == "policy_explanation":
            plan["semantic_tasks"].append(("policy_search", None))
            plan["semantic_tasks"].append(("documentation_search", None))

        elif classification.category == "similar_incidents":
            plan["semantic_tasks"].append(("incident_similarity", None))

        return plan

    # =========================================================================
    # Node 3 — Semantic retrieval
    # =========================================================================
    def node_3_semantic_retrieval(
        self, query: str, plan: dict[str, Any], classification: QueryClassification
    ) -> list[EvidenceItem]:
        items: list[EvidenceItem] = []
        seen_ids = set()

        for task_type, target_id in plan.get("semantic_tasks", []):
            results: list[SearchResult] = []
            if task_type == "runbook" and target_id:
                results = self.index.retrieve_runbooks(query=query, top_k=2)
            elif task_type == "runbook_search":
                results = self.index.retrieve_runbooks(query=query, top_k=3)
            elif task_type == "policy" and target_id:
                results = self.index.retrieve_policies(query=query, top_k=2)
            elif task_type == "policy_search":
                results = self.index.retrieve_policies(query=query, top_k=3)
            elif task_type == "documentation_search":
                results = self.index.retrieve_documentation(query=query, top_k=2)
            elif task_type == "incident_similarity":
                results = self.index.retrieve_incident_summaries(query=query, top_k=4)

            for r in results:
                if r.doc_id in seen_ids:
                    continue
                seen_ids.add(r.doc_id)
                items.append(
                    EvidenceItem(
                        source_type=r.source_type,
                        source_filename=r.source_filename,
                        source_record_id=r.source_record_id,
                        content=r.text,
                        retrieval_method="semantic",
                    )
                )

        return items

    # =========================================================================
    # Node 4 — Structured retrieval
    # =========================================================================
    def node_4_structured_retrieval(
        self, plan: dict[str, Any], classification: QueryClassification
    ) -> list[EvidenceItem]:
        items: list[EvidenceItem] = []

        try:
            for task_type, target_id in plan.get("structured_tasks", []):
                if task_type == "incident_dossier":
                    dossier = get_full_incident_dossier(target_id, self.db_path)
                    if dossier and dossier.get("incident"):
                        inc = dossier["incident"]
                        items.append(
                            EvidenceItem(
                                source_type="incident",
                                source_filename=inc["source_file"],
                                source_record_id=inc["incident_id"],
                                content=inc,
                                retrieval_method="structured",
                            )
                        )
                        for m in dossier.get("metrics", []):
                            items.append(
                                EvidenceItem(
                                    source_type="metric",
                                    source_filename=m["source_file"],
                                    source_record_id=m["metric_id"],
                                    content=m,
                                    retrieval_method="structured",
                                )
                            )
                        for a in dossier.get("approvals", []):
                            items.append(
                                EvidenceItem(
                                    source_type="approval",
                                    source_filename=a["source_file"],
                                    source_record_id=a["approval_id"],
                                    content=a,
                                    retrieval_method="structured",
                                )
                            )
                        for act in dossier.get("actions", []):
                            items.append(
                                EvidenceItem(
                                    source_type="execution_action",
                                    source_filename=act["source_file"],
                                    source_record_id=act["action_id"],
                                    content=act,
                                    retrieval_method="structured",
                                )
                            )
                        for ev in dossier.get("audits", []):
                            items.append(
                                EvidenceItem(
                                    source_type="audit_event",
                                    source_filename=ev["source_file"],
                                    source_record_id=ev["event_id"],
                                    content=ev,
                                    retrieval_method="structured",
                                )
                            )

                elif task_type == "runbook":
                    rb = get_runbook_record(target_id, self.db_path)
                    if rb:
                        items.append(
                            EvidenceItem(
                                source_type="runbook",
                                source_filename=rb["source_file"],
                                source_record_id=rb["runbook_id"],
                                content=rb,
                                retrieval_method="structured",
                            )
                        )

                elif task_type == "policy":
                    pol = get_policy_record(target_id, self.db_path)
                    if pol:
                        items.append(
                            EvidenceItem(
                                source_type="policy",
                                source_filename=pol["source_file"],
                                source_record_id=pol["policy_id"],
                                content=pol,
                                retrieval_method="structured",
                            )
                        )
        except Exception:
            # Operational reliability: database file missing or read failure returns empty evidence
            pass

        return items

    # =========================================================================
    # Node 5 — Evidence sufficiency check
    # =========================================================================
    def node_5_check_evidence_sufficiency(
        self, classification: QueryClassification, evidence: list[EvidenceItem]
    ) -> tuple[bool, str | None]:
        if classification.category == "unsupported":
            return False, classification.unsupported_reason

        inc_id = classification.entities.get("incident_id")
        if classification.category == "incident_investigation" and not inc_id:
            return False, "Inquiry does not specify a valid incident ID (e.g. INC000001). Please specify an incident ID to investigate."

        if inc_id:
            # Check if incident record exists
            inc_items = [e for e in evidence if e.source_type == "incident" and e.source_record_id == inc_id]
            if not inc_items:
                return False, f"Incident '{inc_id}' was not found in the incident registry."

            inc_data = inc_items[0].content
            # Check for conflicting evidence
            if inc_data.get("final_status") == "RESOLVED" and inc_data.get("verification_status") == "failed":
                return False, "Contradictory evidence: incident marked RESOLVED but verification failed."

        if classification.category in ("runbook_guidance", "policy_explanation"):
            if not evidence:
                return False, "No relevant runbook or policy documents found matching the inquiry."

        return True, None

    # =========================================================================
    # Node 6 — Bounded retrieval retry
    # =========================================================================
    def node_6_bounded_retry(
        self,
        query: str,
        classification: QueryClassification,
        current_evidence: list[EvidenceItem],
        start_time: float,
    ) -> list[EvidenceItem]:
        # Enforce execution time bound
        if time.time() - start_time >= self.max_execution_seconds:
            return current_evidence

        # Check if an incident record points to a runbook or policy we haven't fetched yet
        inc_items = [e for e in current_evidence if e.source_type == "incident"]
        new_evidence = list(current_evidence)

        if inc_items:
            inc = inc_items[0].content
            rb_id = inc.get("runbook_id")
            pol_id = inc.get("policy_id")

            existing_ids = {e.source_record_id for e in current_evidence}

            if rb_id and rb_id not in existing_ids:
                rb = get_runbook_record(rb_id, self.db_path)
                if rb:
                    new_evidence.append(
                        EvidenceItem(
                            source_type="runbook",
                            source_filename=rb["source_file"],
                            source_record_id=rb["runbook_id"],
                            content=rb,
                            retrieval_method="structured",
                        )
                    )

            if pol_id and pol_id not in existing_ids:
                pol = get_policy_record(pol_id, self.db_path)
                if pol:
                    new_evidence.append(
                        EvidenceItem(
                            source_type="policy",
                            source_filename=pol["source_file"],
                            source_record_id=pol["policy_id"],
                            content=pol,
                            retrieval_method="structured",
                        )
                    )

        # If semantic evidence was empty, retry semantic retrieval with broader top_k
        if not any(e.retrieval_method == "semantic" for e in new_evidence):
            broad = self.index.retrieve(query=query, top_k=4)
            for r in broad:
                new_evidence.append(
                    EvidenceItem(
                        source_type=r.source_type,
                        source_filename=r.source_filename,
                        source_record_id=r.source_record_id,
                        content=r.text,
                        retrieval_method="semantic",
                    )
                )

        return new_evidence

    # =========================================================================
    # Node 7 — Answer generation
    # =========================================================================
    def node_7_generate_answer(
        self,
        query: str,
        classification: QueryClassification,
        evidence: list[EvidenceItem],
        is_sufficient: bool,
        abstain_reason: str | None,
    ) -> dict[str, Any]:
        if not is_sufficient:
            return {
                "answer": (
                    f"I cannot answer this inquiry based on verified evidence. {abstain_reason or 'Evidence is insufficient.'}"
                ),
                "facts": [],
                "interpretations": [],
                "limitations": [abstain_reason or "Insufficient evidence in official records."],
                "abstained": True,
            }

        # Try Gemini API if configured
        if self._gemini_client is not None:
            try:
                evidence_payload = [e.to_dict() for e in evidence[:12]]
                prompt = (
                    f"Question: {query}\n\n"
                    f"Verified Evidence (JSON):\n{json.dumps(evidence_payload, indent=2)}\n\n"
                    f"Format your response with:\n"
                    f"1. Direct answer.\n"
                    f"2. Facts (bullet points referencing record IDs).\n"
                    f"3. Interpretation (bullet points or analysis).\n"
                    f"4. Limitations (if any)."
                )

                response = self._gemini_client.models.generate_content(
                    model=self.model_name,
                    contents=prompt,
                    config={"system_instruction": SYSTEM_PROMPT, "temperature": 0.0},
                )
                if response and response.text:
                    return {
                        "answer": response.text.strip(),
                        "facts": [f"Retrieved {len(evidence)} verified evidence records."],
                        "interpretations": ["Generated via Gemini grounded strictly on trusted retrieval."],
                        "limitations": ["Subject to synthetic dataset scope."],
                        "abstained": False,
                    }
            except Exception as e:
                # Graceful fallback to deterministic synthesizer on quota/network/API error
                pass

        # Deterministic Grounded Synthesis Fallback
        return self._deterministic_synthesizer(query, classification, evidence)

    def _deterministic_synthesizer(
        self,
        query: str,
        classification: QueryClassification,
        evidence: list[EvidenceItem],
    ) -> dict[str, Any]:
        inc_items = [e for e in evidence if e.source_type == "incident"]
        rb_items = [e for e in evidence if e.source_type == "runbook"]
        pol_items = [e for e in evidence if e.source_type == "policy"]
        met_items = [e for e in evidence if e.source_type == "metric"]
        app_items = [e for e in evidence if e.source_type == "approval"]
        act_items = [e for e in evidence if e.source_type == "execution_action"]

        facts: list[str] = []
        interpretations: list[str] = []
        limitations: list[str] = []

        if inc_items:
            inc = inc_items[0].content
            facts.append(
                f"Incident {inc['incident_id']} detected on {inc['service_id']} in {inc['environment']} at {inc['detected_at']}."
            )
            facts.append(
                f"Incident type '{inc['incident_type']}' with severity {inc['severity']}, risk level {inc['risk_level']}, anomaly score {inc['anomaly_score']}."
            )
            facts.append(
                f"Policy decision was {inc['policy_decision']}; approval status was '{inc['approval_status']}'; execution status was '{inc['execution_status']}'."
            )
            facts.append(
                f"Final status is {inc['final_status']} (auto_resolved={inc['auto_resolved']}, rollback_status={inc['rollback_status']})."
            )

            if met_items:
                m = met_items[0].content
                facts.append(
                    f"Observed metric {m['metric_name']}: before={m['value_before']}, after={m['value_after']}, threshold={m['threshold']} {m['unit']}."
                )

            if app_items:
                a = app_items[0].content
                facts.append(
                    f"Approval {a['approval_id']}: requested role {a['requested_role']}, reviewer {a.get('reviewer_id') or 'none'}, status {a['status']}, reason '{a.get('decision_reason')}'."
                )

            if act_items:
                act = act_items[0].content
                facts.append(
                    f"Execution action {act['action_id']}: ran '{act['action']}' (attempt {act['attempt_number']}), execution_status={act['execution_status']}, verification_status={act['verification_status']}, rollback_status={act['rollback_status']}."
                )

            direct = (
                f"Incident {inc['incident_id']} ({inc['incident_type']} on {inc['service_id']}, {inc['environment']}) "
                f"matched runbook {inc.get('runbook_id') or 'none'} under policy {inc.get('policy_id') or 'none'}. "
                f"Policy evaluation resulted in '{inc['policy_decision']}'. "
                f"Final resolution status was {inc['final_status']}."
            )
            interpretations.append("Outcome is determined deterministically by policy rule boundaries.")

        elif rb_items:
            target_rb_id = classification.entities.get("runbook_id")
            chosen_rb = None
            if target_rb_id:
                chosen_rb = next((e for e in rb_items if e.source_record_id == target_rb_id), None)
            if not chosen_rb:
                chosen_rb = rb_items[0]
            rb_content = chosen_rb.content
            if isinstance(rb_content, dict):
                direct = (
                    f"Runbook {rb_content['runbook_id']} ('{rb_content['name']}') resolves incident type '{rb_content['incident_type']}' "
                    f"via allowlisted action '{rb_content['allowlisted_action']}' under risk tier '{rb_content['risk_level']}'. "
                    f"Verification rule is '{rb_content['verification_rule']}', and rollback action is '{rb_content['compensation_action']}'."
                )
                facts.append(f"Runbook {rb_content['runbook_id']} authorized action: {rb_content['allowlisted_action']}.")
                facts.append(f"Verification rule: {rb_content['verification_rule']}; compensation: {rb_content['compensation_action']}.")
            else:
                raw_str = str(rb_content)
                safe_str = re.sub(r"\b(rm\s+-rf|sudo|chmod|cat\s+/etc/passwd|bash|sh|wget|curl)\b", "[REDACTED_COMMAND]", raw_str, flags=re.IGNORECASE)
                direct = safe_str
                facts.append("Retrieved runbook procedural instructions from knowledge base.")
            interpretations.append("Remediation execution requires explicit policy approval if risk tier exceeds T1.")

        elif pol_items:
            target_pol_id = classification.entities.get("policy_id")
            chosen_pol = None
            if target_pol_id:
                chosen_pol = next((e for e in pol_items if e.source_record_id == target_pol_id), None)
            if not chosen_pol:
                chosen_pol = pol_items[0]
            pol_content = chosen_pol.content
            if isinstance(pol_content, dict):
                direct = (
                    f"Policy {pol_content['policy_id']} governs Runbook {pol_content['runbook_id']} at risk level '{pol_content['risk_level']}'. "
                    f"Auto-execute is {pol_content['auto_execute']}, approval required is {pol_content['approval_required']} "
                    f"(role: {pol_content['approval_role']}) for environments: {pol_content['allowed_environment']}."
                )
                facts.append(f"Policy {pol_content['policy_id']} approval requirement: {pol_content['approval_required']}.")
            else:
                raw_str = str(pol_content)
                safe_str = re.sub(r"\b(rm\s+-rf|sudo|chmod|cat\s+/etc/passwd|bash|sh|wget|curl)\b", "[REDACTED_COMMAND]", raw_str, flags=re.IGNORECASE)
                direct = safe_str
                facts.append("Retrieved policy specification.")
            interpretations.append("High risk operations are constrained to authorized environments.")

        else:
            first_sem = evidence[0].content if evidence else ""
            raw_str = str(first_sem)
            safe_str = re.sub(r"\b(rm\s+-rf|sudo|chmod|cat\s+/etc/passwd|bash|sh|wget|curl)\b", "[REDACTED_COMMAND]", raw_str, flags=re.IGNORECASE)
            direct = safe_str
            facts.append("Retrieved relevant documentation and schema guidelines.")
            interpretations.append("Synthesized from repository documentation.")

        limitations.append("Historical data is synthetic; recommendations never bypass the deterministic policy engine.")

        return {
            "answer": direct,
            "facts": facts,
            "interpretations": interpretations,
            "limitations": limitations,
            "abstained": False,
        }

    # =========================================================================
    # Node 8 — Validation and abstention
    # =========================================================================
    def node_8_validate_and_format(
        self,
        generation: dict[str, Any],
        evidence: list[EvidenceItem],
        classification: QueryClassification,
        start_time: float,
        abstained: bool,
        abstain_reason: str | None,
    ) -> CopilotResponse:
        citations: list[Citation] = []
        inc_ids = set()
        rb_ids = set()
        pol_ids = set()

        if not abstained:
            for ev in evidence:
                # Add citation
                citations.append(
                    Citation(
                        type=ev.source_type,
                        id=ev.source_record_id,
                        source=ev.source_filename,
                    )
                )
                if ev.source_type == "incident":
                    inc_ids.add(ev.source_record_id)
                elif ev.source_type == "runbook":
                    rb_ids.add(ev.source_record_id)
                elif ev.source_type == "policy":
                    pol_ids.add(ev.source_record_id)

                # Collect from structured content
                if isinstance(ev.content, dict):
                    if ev.content.get("runbook_id"):
                        rb_ids.add(ev.content["runbook_id"])
                    if ev.content.get("policy_id"):
                        pol_ids.add(ev.content["policy_id"])
                    if ev.content.get("incident_id"):
                        inc_ids.add(ev.content["incident_id"])

        retrieval_counts = {}
        for ev in evidence:
            retrieval_counts[ev.source_type] = retrieval_counts.get(ev.source_type, 0) + 1

        return CopilotResponse(
            answer=generation["answer"],
            incident_ids=sorted(inc_ids),
            runbook_ids=sorted(rb_ids),
            policy_ids=sorted(pol_ids),
            citations=citations,
            facts=generation.get("facts", []),
            interpretations=generation.get("interpretations", []),
            limitations=generation.get("limitations", []),
            abstained=abstained,
            abstain_reason=abstain_reason,
            execution_time_seconds=round(time.time() - start_time, 3),
            retrieval_counts=retrieval_counts,
        )

    # =========================================================================
    # Entry Point: Complete 8-Node Workflow
    # =========================================================================
    def ask(self, query: str) -> CopilotResponse:
        start_time = time.time()

        # Node 1: Classification
        classification = self.node_1_classify_query(query)
        if classification.category == "unsupported":
            return self.node_8_validate_and_format(
                generation={"answer": f"Unsupported request: {classification.unsupported_reason}"},
                evidence=[],
                classification=classification,
                start_time=start_time,
                abstained=True,
                abstain_reason=classification.unsupported_reason,
            )

        # Node 2: Retrieval Planning
        plan = self.node_2_plan_retrieval(classification)

        # Node 3 & 4: Retrieval execution
        evidence: list[EvidenceItem] = []
        if plan.get("structured_tasks"):
            evidence.extend(self.node_4_structured_retrieval(plan, classification))
        if plan.get("semantic_tasks"):
            evidence.extend(self.node_3_semantic_retrieval(query, plan, classification))

        # Node 5: Evidence sufficiency check
        is_sufficient, abstain_reason = self.node_5_check_evidence_sufficiency(classification, evidence)

        # Node 6: Bounded retrieval retry
        if not is_sufficient and classification.category != "unsupported":
            evidence = self.node_6_bounded_retry(query, classification, evidence, start_time)
            # Re-evaluate sufficiency after retry
            is_sufficient, abstain_reason = self.node_5_check_evidence_sufficiency(classification, evidence)

        # Node 7: Answer generation
        generation = self.node_7_generate_answer(
            query=query,
            classification=classification,
            evidence=evidence,
            is_sufficient=is_sufficient,
            abstain_reason=abstain_reason,
        )

        # Node 8: Validation and formatting
        return self.node_8_validate_and_format(
            generation=generation,
            evidence=evidence,
            classification=classification,
            start_time=start_time,
            abstained=generation.get("abstained", False),
            abstain_reason=abstain_reason,
        )
