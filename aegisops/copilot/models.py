"""Data models and response schemas for AegisOps Copilot Agentic RAG."""

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

QueryCategory = Literal[
    "runbook_guidance",
    "policy_explanation",
    "incident_investigation",
    "metrics",
    "approval_history",
    "execution_history",
    "audit_timeline",
    "similar_incidents",
    "unsupported",
]


@dataclass
class Citation:
    type: str
    id: str
    source: str
    details: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "id": self.id,
            "record_id": self.id,
            "source": self.source,
            "source_file": self.source,
            "details": self.details,
        }


@dataclass
class EvidenceItem:
    source_type: str
    source_filename: str
    source_record_id: str
    content: Any
    retrieval_method: Literal["structured", "semantic"]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class QueryClassification:
    category: QueryCategory
    entities: dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0
    requires_structured: bool = False
    requires_semantic: bool = False
    unsupported_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CopilotResponse:
    answer: str
    incident_ids: list[str] = field(default_factory=list)
    runbook_ids: list[str] = field(default_factory=list)
    policy_ids: list[str] = field(default_factory=list)
    citations: list[Citation] = field(default_factory=list)
    facts: list[str] = field(default_factory=list)
    interpretations: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    abstained: bool = False
    abstain_reason: str | None = None
    execution_time_seconds: float = 0.0
    retrieval_counts: dict[str, int] = field(default_factory=dict)

    @property
    def confidence(self) -> str:
        return "LOW" if self.abstained else "HIGH"

    def to_dict(self) -> dict[str, Any]:
        return {
            "answer": self.answer,
            "direct_answer": self.answer,
            "incident_ids": self.incident_ids,
            "relevant_incident_ids": self.incident_ids,
            "runbook_ids": self.runbook_ids,
            "relevant_runbook_ids": self.runbook_ids,
            "policy_ids": self.policy_ids,
            "relevant_policy_ids": self.policy_ids,
            "citations": [c.to_dict() for c in self.citations],
            "facts": self.facts,
            "interpretations": self.interpretations,
            "limitations": self.limitations,
            "abstained": self.abstained,
            "abstain": self.abstained,
            "evidence_status": "insufficient" if self.abstained else "sufficient",
            "confidence": "LOW" if self.abstained else "HIGH",
            "abstain_reason": self.abstain_reason,
            "execution_time_seconds": self.execution_time_seconds,
            "retrieval_counts": self.retrieval_counts,
        }

