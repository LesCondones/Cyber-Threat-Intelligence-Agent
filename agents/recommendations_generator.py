"""
Recommendations Generator

Extracts prioritized, actionable recommendations from research findings,
MITRE mappings, and enriched IOCs. Closes the "what do I do with this?"
gap by producing items with explicit priority, owner, and rationale —
not vague guidance like "patch your systems".
"""

import logging
from dataclasses import dataclass
from typing import List, Literal, Optional

from pydantic import BaseModel, Field
from langchain_core.prompts import ChatPromptTemplate

from config import get_llm

logger = logging.getLogger(__name__)


# ── Pydantic Models for Structured Output ──

class RecommendationModel(BaseModel):
    """A single prioritized recommendation."""
    priority: Literal["Critical", "High", "Medium", "Low"] = Field(
        description="Priority tier — Critical for active exploitation or "
                    "imminent risk, High for known exploited CVEs in scope, "
                    "Medium for hardening, Low for general hygiene."
    )
    action: str = Field(description=(
        "Imperative-verb action, specific enough to assign as a ticket. "
        "Example: 'Apply MOVEit patch 2023.0.4 to all internet-facing "
        "transfer servers' — not 'patch your systems'."
    ))
    target: str = Field(description=(
        "Team or system that owns this action. Examples: "
        "'Vulnerability Management', 'SOC Detection Engineering', "
        "'Network Operations', 'IAM Team'."
    ))
    rationale: str = Field(description=(
        "Why this matters now, tied to a specific finding or IOC. "
        "Cite CVEs, technique IDs, threat actors when relevant."
    ))
    references: List[str] = Field(
        default_factory=list,
        description="Related identifiers: CVE IDs, T-codes (e.g. T1566.001), "
                    "vendor advisories. Empty list is acceptable."
    )


class RecommendationsOutput(BaseModel):
    """List of prioritized recommendations."""
    recommendations: List[RecommendationModel] = Field(
        description="4-10 prioritized, specific recommendations. Mix priorities."
    )


# ── Plain Data Class for Downstream Consumers ──

@dataclass
class Recommendation:
    priority: str
    action: str
    target: str
    rationale: str
    references: List[str]


# ── Generator ──

class RecommendationsGenerator:
    """Produces prioritized, actionable recommendations from investigation data."""

    PRIORITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}

    def __init__(self, llm=None):
        self.llm = llm or get_llm()

        self.chain = (
            ChatPromptTemplate.from_messages([
                ("system", (
                    "You are a senior cyber threat intelligence analyst writing "
                    "the Recommendations section of a CTI report. Every "
                    "recommendation must be specific enough to assign as a "
                    "ticket. No generic advice like 'patch your systems' or "
                    "'follow defense in depth'. Cite the specific CVE, "
                    "technique ID, IOC, or actor that motivates each item."
                )),
                ("human", (
                    "Generate prioritized recommendations for this investigation.\n\n"
                    "Research Topic: {research_topic}\n\n"
                    "Findings Summary:\n{findings_text}\n\n"
                    "Observed MITRE Techniques:\n{mitre_text}\n\n"
                    "High-Risk Indicators:\n{ioc_text}\n\n"
                    "Produce 4-10 recommendations covering a mix of priorities. "
                    "Order them: Critical -> High -> Medium -> Low.\n\n"
                    "For each recommendation include:\n"
                    "- priority (Critical / High / Medium / Low)\n"
                    "- action (imperative verb, specific target system/version/config)\n"
                    "- target (owning team)\n"
                    "- rationale (why now, what evidence — cite CVE/T-code/actor)\n"
                    "- references (CVE-IDs, T-codes, advisory URLs)"
                )),
            ])
            | self.llm.with_structured_output(RecommendationsOutput)
        )

    def generate(
        self,
        research_topic: str,
        findings: list,
        mitre_mappings: Optional[list] = None,
        enrichment_summary: Optional[object] = None,
    ) -> List[Recommendation]:
        """Generate prioritized recommendations grounded in the investigation."""
        findings_text = "\n\n".join(
            f"[{f.topic}] (Severity: {f.severity})\n{f.analysis[:1500]}"
            for f in findings
        )

        if mitre_mappings:
            mitre_text = "\n".join(
                f"- {m.tactic}: {m.technique_id} {m.technique} "
                f"(confidence: {m.confidence})"
                for m in mitre_mappings[:25]
            )
        else:
            mitre_text = "None mapped."

        # High-risk IOCs from enrichment (if available)
        if enrichment_summary and getattr(enrichment_summary, "results", None):
            high = [r for r in enrichment_summary.results if r.risk_score >= 50]
            ioc_text = "\n".join(
                f"- {r.ioc_value} ({r.ioc_type}) — risk: {r.risk_score}"
                for r in high[:20]
            ) or "None over risk threshold."
        else:
            ioc_text = "No enrichment data."

        try:
            result = self.chain.invoke({
                "research_topic": research_topic,
                "findings_text": findings_text,
                "mitre_text": mitre_text,
                "ioc_text": ioc_text,
            })
        except Exception as e:
            logger.warning(f"Recommendations generation failed: {e}")
            return []

        recs = [
            Recommendation(
                priority=r.priority,
                action=r.action,
                target=r.target,
                rationale=r.rationale,
                references=r.references,
            )
            for r in result.recommendations
        ]
        recs.sort(key=lambda r: self.PRIORITY_ORDER.get(r.priority, 99))
        return recs
